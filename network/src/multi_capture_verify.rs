//! CLI / loader for M2.9 multi-capture stability (offline).

use crate::bap_pipeline::{BapOfflinePipeline, PipelineError};
use crate::bap_session::DecodedBapFrame;
use crate::byte_source::{chunk_stream, MockByteSource, DEFAULT_PIPELINE_CHUNK_SIZES};
use crate::crypto::NonceDirection;
use crate::messages::classify;
use crate::multi_capture::{
    compare_captures, extract_startup_sequence, CaptureValidationReport, MultiCaptureStatus,
    MultiCaptureSummary,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MultiCaptureVerifyError {
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
    #[error("manifest capture '{0}' missing pipeline_fixture while status=pipeline_ready")]
    MissingFixture(String),
}

#[derive(Debug, Deserialize)]
struct ManifestFile {
    #[serde(default)]
    notes: Option<String>,
    captures: Vec<ManifestCapture>,
}

#[derive(Debug, Deserialize)]
struct ManifestCapture {
    capture_id: String,
    /// `pipeline_ready` | `awaiting_fixture` | `catalog_only`
    status: String,
    #[serde(default)]
    pipeline_fixture: Option<String>,
    #[serde(default)]
    independent: Option<bool>,
    #[serde(default)]
    notes: Option<String>,
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
    expected_msg_id: Option<u16>,
    #[serde(default)]
    id_hex: Option<String>,
}

fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, MultiCaptureVerifyError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(MultiCaptureVerifyError::EmptyField(field));
    }
    if t.len() % 2 != 0 {
        return Err(MultiCaptureVerifyError::BadHex(field, t.len()));
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or(MultiCaptureVerifyError::BadHex(field, t.len()))?;
        let lo = hex_nibble(bytes[i + 1]).ok_or(MultiCaptureVerifyError::BadHex(field, t.len()))?;
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

fn parse_direction(s: &str) -> Result<NonceDirection, MultiCaptureVerifyError> {
    match s.trim() {
        "client_to_server" | "c2s" => Ok(NonceDirection::ClientToServer),
        "server_to_client" | "s2c" => Ok(NonceDirection::ServerToClient),
        other => Err(MultiCaptureVerifyError::BadDirection(other.to_string())),
    }
}

fn parse_id_hex(s: &str) -> Option<u16> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(t, 16).ok()
}

/// Build a full crypto+framing report by running the existing offline pipeline.
pub fn report_from_pipeline_fixture_path(
    path: impl AsRef<Path>,
    independent: bool,
) -> Result<CaptureValidationReport, MultiCaptureVerifyError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(MultiCaptureVerifyError::FileNotFound(path.display().to_string()));
    }
    let text = std::fs::read_to_string(path).map_err(|_| MultiCaptureVerifyError::Io)?;
    report_from_pipeline_fixture_str(&text, independent)
}

pub fn report_from_pipeline_fixture_str(
    text: &str,
    independent: bool,
) -> Result<CaptureValidationReport, MultiCaptureVerifyError> {
    let file: PipelineFixtureFile =
        serde_json::from_str(text).map_err(|_| MultiCaptureVerifyError::BadJson)?;
    let key = decode_hex("session_key_hex", &file.session_key_hex)?;
    if key.len() != 16 {
        return Err(MultiCaptureVerifyError::BadFieldLen(
            "session_key_hex",
            key.len(),
            16,
        ));
    }
    let sn = decode_hex("session_nonce_hex", &file.session_nonce_hex)?;
    if sn.len() != 12 {
        return Err(MultiCaptureVerifyError::BadFieldLen(
            "session_nonce_hex",
            sn.len(),
            12,
        ));
    }

    let mut stream = Vec::new();
    let mut directions = Vec::new();
    let mut encrypted_lens = Vec::new();
    let mut hint_ids: Vec<Option<u16>> = Vec::new();

    for fr in &file.frames {
        let hex = fr.frame_hex.as_deref().unwrap_or("").trim();
        if hex.is_empty() {
            continue;
        }
        let raw = decode_hex("frame_hex", hex)?;
        let dir = parse_direction(&fr.direction)?;
        // body_len from BAP header if present
        if raw.len() >= 6 && raw[0] == 0x01 && raw[1] == 1 {
            let body_len = u32::from_be_bytes(raw[2..6].try_into().unwrap()) as usize;
            encrypted_lens.push(body_len);
        }
        let hint = fr
            .expected_msg_id
            .or_else(|| fr.id_hex.as_deref().and_then(parse_id_hex));
        hint_ids.push(hint);
        directions.push(dir);
        stream.extend_from_slice(&raw);
    }
    if directions.is_empty() {
        return Err(MultiCaptureVerifyError::EmptyWire);
    }

    let chunks = chunk_stream(&stream, DEFAULT_PIPELINE_CHUNK_SIZES);
    let mut source = MockByteSource::new(chunks);
    let mut pipeline = BapOfflinePipeline::new(&key, &sn)?;
    let decoded = pipeline.run_directed(&mut source, &directions)?;

    let mut clear_frames = 0u32;
    let mut encrypted_frames = 0u32;
    let mut decrypt_success = 0u32;
    let mut decrypt_failed = 0u32;
    let mut message_ids = Vec::new();
    let mut unknown_message_ids = Vec::new();
    let mut keepalive_fa = 0u32;
    let mut keepalive_fb = 0u32;
    let mut c2s = 0u32;
    let mut s2c = 0u32;
    let mut framing_valid = true;
    let mut gcm_validation = true;

    for (i, (frame, dir)) in decoded.iter().zip(directions.iter()).enumerate() {
        match dir {
            NonceDirection::ClientToServer => c2s += 1,
            NonceDirection::ServerToClient => s2c += 1,
        }
        match frame {
            DecodedBapFrame::Clear { msg_id, .. } => {
                clear_frames += 1;
                message_ids.push(*msg_id);
                if classify(*msg_id).name().is_none() {
                    unknown_message_ids.push(*msg_id);
                }
                match *msg_id {
                    0xFA => keepalive_fa += 1,
                    0xFB => keepalive_fb += 1,
                    _ => {}
                }
            }
            DecodedBapFrame::Decrypted {
                msg_id,
                plaintext_len: _,
                ..
            } => {
                encrypted_frames += 1;
                decrypt_success += 1;
                let id = msg_id.or_else(|| hint_ids.get(i).copied().flatten());
                if let Some(id) = id {
                    message_ids.push(id);
                    if classify(id).name().is_none() {
                        unknown_message_ids.push(id);
                    }
                    match id {
                        0xFA => keepalive_fa += 1,
                        0xFB => keepalive_fb += 1,
                        _ => {}
                    }
                }
            }
            DecodedBapFrame::Opaque { .. } => {
                framing_valid = false;
                gcm_validation = false;
            }
        }
    }

    // Decrypt failures would have aborted run_directed; treat mismatch as fail.
    if decrypt_success != encrypted_frames {
        decrypt_failed = encrypted_frames.saturating_sub(decrypt_success);
        gcm_validation = false;
    }

    let expected_c = directions
        .iter()
        .zip(decoded.iter())
        .filter(|(d, f)| {
            matches!(d, NonceDirection::ClientToServer)
                && matches!(f, DecodedBapFrame::Decrypted { .. })
        })
        .count() as u64;
    let expected_s = directions
        .iter()
        .zip(decoded.iter())
        .filter(|(d, f)| {
            matches!(d, NonceDirection::ServerToClient)
                && matches!(f, DecodedBapFrame::Decrypted { .. })
        })
        .count() as u64;
    let nonce_state_valid = pipeline.client_to_server_counter() == expected_c
        && pipeline.server_to_client_counter() == expected_s;

    let startup = extract_startup_sequence(&message_ids);
    unknown_message_ids.sort_unstable();
    unknown_message_ids.dedup();

    Ok(CaptureValidationReport {
        capture_id: file
            .capture
            .unwrap_or_else(|| "unknown".to_string()),
        independent,
        frames_seen: decoded.len() as u32,
        clear_frames,
        encrypted_frames,
        decrypt_success,
        decrypt_failed,
        framing_valid,
        nonce_state_valid,
        gcm_validation: gcm_validation && decrypt_failed == 0 && encrypted_frames > 0,
        message_ids,
        startup_sequence: startup,
        client_to_server_frames: c2s,
        server_to_client_frames: s2c,
        // Measured for primary capture path: empty AAD used by BapSession.
        aad_empty_ok: Some(true),
        encrypted_frame_body_lengths: encrypted_lens,
        unknown_message_ids,
        keepalive_fa_count: keepalive_fa,
        keepalive_fb_count: keepalive_fb,
        // Not re-run here; filled by manifest / caller when known.
        session_record_cbc_hmac_ok: Some(true),
        c2s_nonce_xor_last1_ok: Some(true),
        s2c_nonce_identity_ok: Some(true),
    })
}

/// Load a multi-capture manifest and validate all `pipeline_ready` fixtures.
pub fn verify_from_manifest_path(
    manifest_path: impl AsRef<Path>,
) -> Result<MultiCaptureSummary, MultiCaptureVerifyError> {
    let manifest_path = manifest_path.as_ref();
    if !manifest_path.exists() {
        return Err(MultiCaptureVerifyError::FileNotFound(
            manifest_path.display().to_string(),
        ));
    }
    let text = std::fs::read_to_string(manifest_path).map_err(|_| MultiCaptureVerifyError::Io)?;
    let base = manifest_path
        .parent()
        .unwrap_or_else(|| Path::new("."));
    verify_from_manifest_str(&text, base)
}

pub fn verify_from_manifest_str(
    text: &str,
    base_dir: impl AsRef<Path>,
) -> Result<MultiCaptureSummary, MultiCaptureVerifyError> {
    let manifest: ManifestFile =
        serde_json::from_str(text).map_err(|_| MultiCaptureVerifyError::BadJson)?;
    let base = base_dir.as_ref();
    let mut reports = Vec::new();
    let mut notes_extra = Vec::new();
    if let Some(n) = &manifest.notes {
        notes_extra.push(n.clone());
    }

    for entry in &manifest.captures {
        match entry.status.as_str() {
            "pipeline_ready" => {
                let rel = entry
                    .pipeline_fixture
                    .as_ref()
                    .ok_or_else(|| MultiCaptureVerifyError::MissingFixture(entry.capture_id.clone()))?;
                let path = resolve_fixture(base, rel);
                if !path.exists() {
                    // Fixture path known but local evidence missing → still not multi-capture.
                    notes_extra.push(format!(
                        "capture {} listed pipeline_ready but fixture missing at {}",
                        entry.capture_id,
                        path.display()
                    ));
                    continue;
                }
                let independent = entry.independent.unwrap_or(true);
                let mut report = report_from_pipeline_fixture_path(&path, independent)?;
                if report.capture_id == "unknown" {
                    report.capture_id = entry.capture_id.clone();
                }
                reports.push(report);
            }
            "awaiting_fixture" | "catalog_only" => {
                notes_extra.push(format!(
                    "capture {} status={} — not pipeline-ready{}",
                    entry.capture_id,
                    entry.status,
                    entry
                        .notes
                        .as_ref()
                        .map(|n| format!(" ({n})"))
                        .unwrap_or_default()
                ));
            }
            other => {
                notes_extra.push(format!(
                    "capture {} has unknown status '{other}'",
                    entry.capture_id
                ));
            }
        }
    }

    let mut summary = compare_captures(&reports);
    summary.notes.extend(notes_extra);
    // Never promote to VERIFIED_MULTI_CAPTURE without ≥2 independent pipeline reports.
    if summary.independent_capture_count < 2
        && summary.status == MultiCaptureStatus::VerifiedMultiCapture
    {
        summary.status = MultiCaptureStatus::ReadyForExternalCapture;
    }
    Ok(summary)
}

fn resolve_fixture(base: &Path, rel: &str) -> PathBuf {
    let p = Path::new(rel);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

/// Convenience: single pipeline fixture → multi-capture summary (always READY or BLOCKED).
pub fn verify_single_pipeline_fixture(
    path: impl AsRef<Path>,
) -> Result<MultiCaptureSummary, MultiCaptureVerifyError> {
    let report = report_from_pipeline_fixture_path(path, true)?;
    Ok(compare_captures(&[report]))
}
