//! Load pipeline fixtures → message inventory (M3.1). Offline only.

use crate::bap_pipeline::{BapOfflinePipeline, PipelineError};
use crate::byte_source::{chunk_stream, MockByteSource, DEFAULT_PIPELINE_CHUNK_SIZES};
use crate::crypto::NonceDirection;
use crate::message_inventory::{
    fmt_msg_id, to_safe_export, CaptureMessageInventory, CrossCaptureMessageComparison,
    EvidenceLabel, MessageObservation, Presence, SafeInventoryExport,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MessageInventoryError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("failed to read input file")]
    Io,
    #[error("invalid JSON structure")]
    BadJson,
    #[error("field '{0}' has invalid hex (length chars={1})")]
    BadHex(&'static str, usize),
    #[error("field '{0}' must be non-empty")]
    EmptyField(&'static str),
    #[error("field '{0}' unexpected length {1} (expected {2})")]
    BadFieldLen(&'static str, usize, usize),
    #[error("unsupported direction '{0}'")]
    BadDirection(String),
    #[error("no frames with wire material")]
    EmptyWire,
    #[error("pipeline: {0}")]
    Pipeline(#[from] PipelineError),
    #[error("need at least two captures for comparison")]
    NeedTwoCaptures,
}

#[derive(Debug, Deserialize)]
struct ManifestFile {
    captures: Vec<ManifestCapture>,
}

#[derive(Debug, Deserialize)]
struct ManifestCapture {
    capture_id: String,
    status: String,
    #[serde(default)]
    pipeline_fixture: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PipelineFixtureFile {
    #[serde(default)]
    capture: Option<String>,
    session_key_hex: String,
    session_nonce_hex: String,
    frames: Vec<PipelineFixtureFrame>,
}

#[derive(Debug, Deserialize)]
struct PipelineFixtureFrame {
    direction: String,
    #[serde(default)]
    frame_hex: Option<String>,
    #[serde(default)]
    frame_offset: Option<u64>,
    #[serde(default)]
    frame_order: Option<u64>,
    #[serde(default)]
    expected_msg_id: Option<u16>,
}

fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, MessageInventoryError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(MessageInventoryError::EmptyField(field));
    }
    if t.len() % 2 != 0 {
        return Err(MessageInventoryError::BadHex(field, t.len()));
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or(MessageInventoryError::BadHex(field, t.len()))?;
        let lo = hex_nibble(bytes[i + 1]).ok_or(MessageInventoryError::BadHex(field, t.len()))?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_direction(s: &str) -> Result<NonceDirection, MessageInventoryError> {
    match s.trim() {
        "client_to_server" | "c2s" => Ok(NonceDirection::ClientToServer),
        "server_to_client" | "s2c" => Ok(NonceDirection::ServerToClient),
        other => Err(MessageInventoryError::BadDirection(other.to_string())),
    }
}

/// Build inventory for one pipeline fixture via existing BapOfflinePipeline.
pub fn inventory_from_pipeline_fixture(
    path: impl AsRef<Path>,
) -> Result<CaptureMessageInventory, MessageInventoryError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(MessageInventoryError::FileNotFound(path.display().to_string()));
    }
    let text = std::fs::read_to_string(path).map_err(|_| MessageInventoryError::Io)?;
    inventory_from_pipeline_fixture_str(&text)
}

pub fn inventory_from_pipeline_fixture_str(
    text: &str,
) -> Result<CaptureMessageInventory, MessageInventoryError> {
    let file: PipelineFixtureFile =
        serde_json::from_str(text).map_err(|_| MessageInventoryError::BadJson)?;
    let key = decode_hex("session_key_hex", &file.session_key_hex)?;
    if key.len() != 16 {
        return Err(MessageInventoryError::BadFieldLen(
            "session_key_hex",
            key.len(),
            16,
        ));
    }
    let sn = decode_hex("session_nonce_hex", &file.session_nonce_hex)?;
    if sn.len() != 12 {
        return Err(MessageInventoryError::BadFieldLen(
            "session_nonce_hex",
            sn.len(),
            12,
        ));
    }

    let capture_id = file
        .capture
        .clone()
        .unwrap_or_else(|| "unknown".to_string());

    let mut stream = Vec::new();
    let mut directions = Vec::new();
    let mut meta: Vec<(Option<u64>, Option<u64>, Option<u16>)> = Vec::new();

    for fr in &file.frames {
        let hex = fr.frame_hex.as_deref().unwrap_or("").trim();
        if hex.is_empty() {
            continue;
        }
        let raw = decode_hex("frame_hex", hex)?;
        directions.push(parse_direction(&fr.direction)?);
        meta.push((fr.frame_offset, fr.frame_order, fr.expected_msg_id));
        stream.extend_from_slice(&raw);
    }
    if directions.is_empty() {
        return Err(MessageInventoryError::EmptyWire);
    }

    let chunks = chunk_stream(&stream, DEFAULT_PIPELINE_CHUNK_SIZES);
    let mut source = MockByteSource::new(chunks);
    let mut pipeline = BapOfflinePipeline::new(&key, &sn)?;
    let decoded = pipeline.run_directed(&mut source, &directions)?;

    let mut observations = Vec::new();
    for (i, ((frame, dir), (off, order, hint_id))) in decoded
        .iter()
        .zip(directions.iter())
        .zip(meta.iter())
        .enumerate()
    {
        if let Some(obs) = MessageObservation::from_decoded(
            &capture_id,
            i as u32,
            *dir,
            frame,
            *off,
            *order,
        ) {
            let _ = hint_id;
            observations.push(obs);
        }
    }

    Ok(CaptureMessageInventory::from_observations(
        &capture_id,
        observations,
    ))
}

pub struct InventoryRunReport {
    pub captures: Vec<CaptureMessageInventory>,
    pub comparison: CrossCaptureMessageComparison,
    pub safe_export: SafeInventoryExport,
}

impl std::fmt::Display for InventoryRunReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cmp = &self.comparison;
        writeln!(f, "M3.1 MESSAGE INVENTORY")?;
        writeln!(f)?;
        writeln!(f, "captures:")?;
        for c in &self.captures {
            writeln!(f, "  {}", c.capture_id)?;
        }
        writeln!(f)?;
        writeln!(f, "captures_processed: {}", self.captures.len())?;
        let all_ids: std::collections::BTreeSet<u16> = cmp.rows.iter().map(|r| r.message_id).collect();
        writeln!(f, "total unique message IDs: {}", all_ids.len())?;
        writeln!(f)?;
        writeln!(
            f,
            "{:<8} {:<5} {:<5} {:<22} {:<14} {:<14} {}",
            "ID", "A", "B", "directions", "contexts", "lengths", "status"
        )?;
        for r in &cmp.rows {
            let in_a = matches!(r.presence, Presence::Both | Presence::AOnly);
            let in_b = matches!(r.presence, Presence::Both | Presence::BOnly);
            let dir_status = match r.presence {
                Presence::Both => r.direction_status.as_str(),
                _ => "n/a",
            };
            let ctx_status = match r.presence {
                Presence::Both => r.context_status.as_str(),
                _ => "n/a",
            };
            let len_status = match r.presence {
                Presence::Both => r.length_status.as_str(),
                _ => "n/a",
            };
            let dirs = format_dirs(&r.directions_a, &r.directions_b, r.presence);
            let ctxs = format_ctx(&r.contexts_a, &r.contexts_b, r.presence);
            let lens = format_lens(&r.lengths_a, &r.lengths_b, r.presence);
            let status = format!("{dir_status}/{ctx_status}/{len_status}");
            writeln!(
                f,
                "{:<8} {:<5} {:<5} {:<22} {:<14} {:<14} {}",
                fmt_msg_id(r.message_id),
                if in_a { "yes" } else { "no" },
                if in_b { "yes" } else { "no" },
                truncate(&dirs, 22),
                truncate(&ctxs, 14),
                truncate(&lens, 14),
                status
            )?;
        }
        writeln!(f)?;
        writeln!(f, "CROSS-CAPTURE SUMMARY")?;
        writeln!(f)?;
        writeln!(
            f,
            "stable IDs (both, dir+ctx+len stable): {}",
            format_id_list(
                &cmp
                    .rows
                    .iter()
                    .filter(|r| {
                        r.presence == Presence::Both
                            && r.direction_status == EvidenceLabel::CrossCaptureStable
                            && r.context_status == EvidenceLabel::CrossCaptureStable
                            && r.length_status == EvidenceLabel::CrossCaptureStable
                    })
                    .map(|r| r.message_id)
                    .collect::<Vec<_>>()
            )
        )?;
        writeln!(f, "A-only IDs: {}", format_id_list(&cmp.a_only_ids()))?;
        writeln!(f, "B-only IDs: {}", format_id_list(&cmp.b_only_ids()))?;
        writeln!(
            f,
            "direction divergent: {}",
            format_id_list(
                &cmp.rows
                    .iter()
                    .filter(|r| r.direction_status == EvidenceLabel::Divergent)
                    .map(|r| r.message_id)
                    .collect::<Vec<_>>()
            )
        )?;
        writeln!(
            f,
            "context divergent: {}",
            format_id_list(
                &cmp.rows
                    .iter()
                    .filter(|r| r.context_status == EvidenceLabel::Divergent)
                    .map(|r| r.message_id)
                    .collect::<Vec<_>>()
            )
        )?;
        writeln!(
            f,
            "length divergent: {}",
            format_id_list(
                &cmp.rows
                    .iter()
                    .filter(|r| r.length_status == EvidenceLabel::Divergent)
                    .map(|r| r.message_id)
                    .collect::<Vec<_>>()
            )
        )?;
        writeln!(f)?;
        writeln!(f, "STARTUP SEQUENCES")?;
        writeln!(f)?;
        writeln!(f, "A:")?;
        writeln!(
            f,
            "  {}",
            cmp.startup_a
                .iter()
                .map(|id| fmt_msg_id(*id))
                .collect::<Vec<_>>()
                .join(" → ")
        )?;
        writeln!(f, "B:")?;
        writeln!(
            f,
            "  {}",
            cmp.startup_b
                .iter()
                .map(|id| fmt_msg_id(*id))
                .collect::<Vec<_>>()
                .join(" → ")
        )?;
        writeln!(f)?;
        writeln!(f, "status:")?;
        writeln!(f, "  {}", cmp.startup_status.as_str())?;
        writeln!(f)?;
        if !cmp.sequence_pairs.is_empty() {
            writeln!(f, "OBSERVED_SEQUENCE_PAIR (startup windows):")?;
            for p in &cmp.sequence_pairs {
                writeln!(
                    f,
                    "  {} ({}) → {} ({})  [{}]",
                    fmt_msg_id(p.first_id),
                    p.first_direction,
                    fmt_msg_id(p.second_id),
                    p.second_direction,
                    p.label.as_str()
                )?;
            }
            writeln!(f)?;
        }
        writeln!(f, "EXTERNAL_REFERENCE names from docs matrix (not semantic proof):")?;
        for r in &cmp.rows {
            if let Some(name) = r.external_name {
                writeln!(f, "  {} → {} [{}]", fmt_msg_id(r.message_id), name, EvidenceLabel::ExternalReference.as_str())?;
            }
        }
        Ok(())
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}

fn format_id_list(ids: &[u16]) -> String {
    if ids.is_empty() {
        "(none)".into()
    } else {
        ids.iter().map(|id| fmt_msg_id(*id)).collect::<Vec<_>>().join(", ")
    }
}

fn format_dirs(
    a: &std::collections::BTreeMap<String, u32>,
    b: &std::collections::BTreeMap<String, u32>,
    presence: Presence,
) -> String {
    match presence {
        Presence::Both => {
            let sa: std::collections::BTreeSet<_> = a.keys().collect();
            let sb: std::collections::BTreeSet<_> = b.keys().collect();
            if sa == sb {
                sa.into_iter()
                    .map(|d| short_dir(d))
                    .collect::<Vec<_>>()
                    .join(",")
            } else {
                format!(
                    "A:{}|B:{}",
                    a.keys().map(|d| short_dir(d)).collect::<Vec<_>>().join(","),
                    b.keys().map(|d| short_dir(d)).collect::<Vec<_>>().join(",")
                )
            }
        }
        Presence::AOnly => a.keys().map(|d| short_dir(d)).collect::<Vec<_>>().join(","),
        Presence::BOnly => b.keys().map(|d| short_dir(d)).collect::<Vec<_>>().join(","),
    }
}

fn short_dir(d: &str) -> &str {
    match d {
        "client_to_server" => "C→S",
        "server_to_client" => "S→C",
        other => other,
    }
}

fn format_ctx(
    a: &std::collections::BTreeMap<u32, u32>,
    b: &std::collections::BTreeMap<u32, u32>,
    presence: Presence,
) -> String {
    match presence {
        Presence::Both => {
            let sa: std::collections::BTreeSet<_> = a.keys().collect();
            let sb: std::collections::BTreeSet<_> = b.keys().collect();
            if sa == sb {
                sa.into_iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            } else {
                "div".into()
            }
        }
        Presence::AOnly => a.keys().map(|c| c.to_string()).collect::<Vec<_>>().join(","),
        Presence::BOnly => b.keys().map(|c| c.to_string()).collect::<Vec<_>>().join(","),
    }
}

fn format_lens(
    a: &std::collections::BTreeMap<usize, u32>,
    b: &std::collections::BTreeMap<usize, u32>,
    presence: Presence,
) -> String {
    match presence {
        Presence::Both => {
            let sa: std::collections::BTreeSet<_> = a.keys().collect();
            let sb: std::collections::BTreeSet<_> = b.keys().collect();
            if sa == sb {
                sa.into_iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            } else {
                "div".into()
            }
        }
        Presence::AOnly => a.keys().map(|c| c.to_string()).collect::<Vec<_>>().join(","),
        Presence::BOnly => b.keys().map(|c| c.to_string()).collect::<Vec<_>>().join(","),
    }
}

pub fn run_from_manifest(path: impl AsRef<Path>) -> Result<InventoryRunReport, MessageInventoryError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(MessageInventoryError::FileNotFound(path.display().to_string()));
    }
    let text = std::fs::read_to_string(path).map_err(|_| MessageInventoryError::Io)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let manifest: ManifestFile =
        serde_json::from_str(&text).map_err(|_| MessageInventoryError::BadJson)?;

    let mut captures = Vec::new();
    for entry in &manifest.captures {
        if entry.status != "pipeline_ready" {
            continue;
        }
        let rel = entry
            .pipeline_fixture
            .as_ref()
            .ok_or_else(|| MessageInventoryError::FileNotFound(entry.capture_id.clone()))?;
        let fixture = resolve(base, rel);
        let mut inv = inventory_from_pipeline_fixture(&fixture)?;
        if inv.capture_id == "unknown" {
            inv.capture_id = entry.capture_id.clone();
        }
        captures.push(inv);
    }
    if captures.len() < 2 {
        return Err(MessageInventoryError::NeedTwoCaptures);
    }
    let comparison = CrossCaptureMessageComparison::compare(&captures[0], &captures[1]);
    let safe_export = to_safe_export(&captures, Some(&comparison));
    Ok(InventoryRunReport {
        captures,
        comparison,
        safe_export,
    })
}

fn resolve(base: &Path, rel: &str) -> PathBuf {
    let p = Path::new(rel);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

pub fn write_safe_export(path: impl AsRef<Path>, export: &SafeInventoryExport) -> Result<(), MessageInventoryError> {
    let json = serde_json::to_string_pretty(export).map_err(|_| MessageInventoryError::BadJson)?;
    std::fs::write(path, json + "\n").map_err(|_| MessageInventoryError::Io)
}
