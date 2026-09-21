//! CLI verify for M4.3 UDP evidence analysis (read-only / offline).

use crate::udp_analysis::{
    analyze_capture, cross_capture_compare, to_safe_export, CaptureUdpAnalysis, SafeUdpEvidenceExport,
    SAFE_VERSION,
};
use crate::udp_evidence::{parse_classic_pcap_udp, BapTimelineEvent, EvidenceClass};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum UdpEvidenceVerifyError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("io: {0}")]
    Io(String),
    #[error("json: {0}")]
    Json(String),
    #[error("pcap: {0}")]
    Pcap(String),
    #[error("need two captures in manifest")]
    NeedTwoCaptures,
    #[error("validation failed: {0}")]
    Failed(String),
}

#[derive(Debug, Deserialize)]
struct ManifestFile {
    captures: Vec<ManifestCapture>,
}

#[derive(Debug, Deserialize)]
struct ManifestCapture {
    capture_id: String,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Debug)]
pub struct UdpEvidenceRun {
    pub export: SafeUdpEvidenceExport,
    pub result: &'static str,
    pub udp_observed: bool,
    pub notes: Vec<String>,
    pub used_live_pcap: bool,
}

impl std::fmt::Display for UdpEvidenceRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "M4.3 UDP EVIDENCE ANALYSIS")?;
        writeln!(f)?;
        writeln!(f, "version: {}", self.export.version)?;
        writeln!(f, "UDP_OBSERVED: {}", if self.udp_observed { "YES" } else { "NO" })?;
        writeln!(
            f,
            "source: {}",
            if self.used_live_pcap {
                "live_pcap_offline_scan"
            } else {
                "safe_fixture"
            }
        )?;
        writeln!(f)?;
        writeln!(f, "captures:")?;
        for c in &self.export.captures {
            writeln!(
                f,
                "  {} udp_packets={} udp_flows={} observed={}",
                c.capture_id, c.udp_packets, c.udp_flows, c.udp_observed
            )?;
        }
        writeln!(f)?;
        writeln!(f, "cross-capture:")?;
        for p in &self.export.cross_capture.properties {
            writeln!(
                f,
                "  {}: A={} B={} → {}",
                p.name, p.present_a, p.present_b, p.stability
            )?;
        }
        writeln!(f)?;
        writeln!(f, "unknowns:")?;
        for u in &self.export.unknowns {
            writeln!(f, "  {u}")?;
        }
        writeln!(f)?;
        for n in &self.notes {
            writeln!(f, "note: {n}")?;
        }
        writeln!(f, "UDP_EVIDENCE_ANALYSIS: {}", self.result)?;
        Ok(())
    }
}

fn default_safe_path() -> PathBuf {
    PathBuf::from("fixtures/udp_evidence/udp_evidence_safe.json")
}

fn resolve_pcap(capture_id: &str, manifest_dir: &Path) -> Option<PathBuf> {
    let candidates = [
        manifest_dir.join(format!("../../../external/d1-re/captures/{capture_id}/traffic.pcap")),
        PathBuf::from(format!("../external/d1-re/captures/{capture_id}/traffic.pcap")),
        PathBuf::from(format!("external/d1-re/captures/{capture_id}/traffic.pcap")),
        PathBuf::from(format!(
            "../evidence/local/{capture_id}/traffic.pcap"
        )),
    ];
    candidates.into_iter().find(|p| p.exists())
}

fn resolve_bap_jsonl(capture_id: &str, manifest_dir: &Path) -> Option<PathBuf> {
    let candidates = [
        manifest_dir.join(format!(
            "../../../external/d1-re/captures/{capture_id}/decrypted/decrypted_bap.jsonl"
        )),
        PathBuf::from(format!(
            "../external/d1-re/captures/{capture_id}/decrypted/decrypted_bap.jsonl"
        )),
        PathBuf::from(format!(
            "external/d1-re/captures/{capture_id}/decrypted/decrypted_bap.jsonl"
        )),
    ];
    candidates.into_iter().find(|p| p.exists())
}

fn load_bap_timeline(path: &Path) -> Result<Vec<BapTimelineEvent>, UdpEvidenceVerifyError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| UdpEvidenceVerifyError::Io(e.to_string()))?;
    let mut out = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| UdpEvidenceVerifyError::Json(e.to_string()))?;
        if v.get("kind").and_then(|k| k.as_str()) != Some("bap_frame") {
            continue;
        }
        let msg_id = v
            .get("id")
            .and_then(|x| x.as_u64())
            .ok_or_else(|| UdpEvidenceVerifyError::Json("missing id".into()))?
            as u16;
        let timestamp = v
            .get("frame_ts")
            .and_then(|x| x.as_f64())
            .ok_or_else(|| UdpEvidenceVerifyError::Json("missing frame_ts".into()))?;
        let direction = v
            .get("direction")
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string();
        out.push(BapTimelineEvent {
            msg_id,
            timestamp,
            direction,
        });
    }
    Ok(out)
}

fn analyze_from_pcap(
    capture_id: &str,
    pcap_path: &Path,
    bap: &[BapTimelineEvent],
) -> Result<CaptureUdpAnalysis, UdpEvidenceVerifyError> {
    let bytes = std::fs::read(pcap_path).map_err(|e| UdpEvidenceVerifyError::Io(e.to_string()))?;
    let records = parse_classic_pcap_udp(&bytes)
        .map_err(UdpEvidenceVerifyError::Pcap)?;
    Ok(analyze_capture(capture_id, records, bap, 1))
}

fn validate_export(export: &SafeUdpEvidenceExport) -> Result<(), UdpEvidenceVerifyError> {
    if export.version != SAFE_VERSION {
        return Err(UdpEvidenceVerifyError::Failed(format!(
            "version {} != {SAFE_VERSION}",
            export.version
        )));
    }
    if export.captures.len() < 2 {
        return Err(UdpEvidenceVerifyError::NeedTwoCaptures);
    }
    for c in &export.captures {
        if c.external_address != "REDACTED" && !c.external_address.is_empty() {
            // Allow empty; require REDACTED when set.
            if c.external_address.contains('.') {
                return Err(UdpEvidenceVerifyError::Failed(
                    "external IP leakage in safe export".into(),
                ));
            }
        }
    }
    let blob = serde_json::to_string(export).map_err(|e| UdpEvidenceVerifyError::Json(e.to_string()))?;
    if blob.contains("payload_hex") || blob.contains("session_key") {
        return Err(UdpEvidenceVerifyError::Failed(
            "secrets-looking fields in safe export".into(),
        ));
    }
    // crude IP leakage check
    if blob.contains("192.168.") || blob.contains("172.97.") {
        return Err(UdpEvidenceVerifyError::Failed(
            "IP leakage in safe export".into(),
        ));
    }
    Ok(())
}

/// Preferred entry: multi-capture manifest. Uses live PCAPs when present; else safe fixture.
pub fn run_from_manifest(path: impl AsRef<Path>) -> Result<UdpEvidenceRun, UdpEvidenceVerifyError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(UdpEvidenceVerifyError::FileNotFound(
            path.display().to_string(),
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| UdpEvidenceVerifyError::Io(e.to_string()))?;
    let manifest: ManifestFile =
        serde_json::from_str(&text).map_err(|e| UdpEvidenceVerifyError::Json(e.to_string()))?;
    let ready: Vec<_> = manifest
        .captures
        .iter()
        .filter(|c| c.status.as_deref() != Some("catalog_only"))
        .collect();
    if ready.len() < 2 {
        return Err(UdpEvidenceVerifyError::NeedTwoCaptures);
    }
    let manifest_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let a_id = &ready[0].capture_id;
    let b_id = &ready[1].capture_id;

    let pcap_a = resolve_pcap(a_id, manifest_dir);
    let pcap_b = resolve_pcap(b_id, manifest_dir);

    let mut notes = Vec::new();
    let (export, used_live, udp_observed) = if let (Some(pa), Some(pb)) = (pcap_a, pcap_b) {
        notes.push(format!("scanned pcap {}", pa.display()));
        notes.push(format!("scanned pcap {}", pb.display()));
        let bap_a = resolve_bap_jsonl(a_id, manifest_dir)
            .map(|p| load_bap_timeline(&p))
            .transpose()?
            .unwrap_or_default();
        let bap_b = resolve_bap_jsonl(b_id, manifest_dir)
            .map(|p| load_bap_timeline(&p))
            .transpose()?
            .unwrap_or_default();
        let analysis_a = analyze_from_pcap(a_id, &pa, &bap_a)?;
        let analysis_b = analyze_from_pcap(b_id, &pb, &bap_b)?;
        let cross = cross_capture_compare(&analysis_a, &analysis_b);
        let export = to_safe_export(&[analysis_a, analysis_b], cross);
        let obs = export.udp_observed_any;
        if let Err(e) = write_safe_exports(&export) {
            notes.push(format!("safe export write skipped: {e}"));
        }
        (export, true, obs)
    } else {
        notes.push(
            "live PCAPs not found; validating committed safe fixture (captures were inspected offline)"
                .into(),
        );
        let safe = load_safe_fixture()?;
        let obs = safe.udp_observed_any;
        (safe, false, obs)
    };

    validate_export(&export)?;
    if !export.unknowns.iter().any(|u| u.starts_with("UNK-UDP")) {
        return Err(UdpEvidenceVerifyError::Failed(
            "UDP unknown registry entries missing".into(),
        ));
    }
    if !udp_observed {
        notes.push(EvidenceClass::UdpNotObservedInCapture.as_str().into());
    }
    notes.push("M4.3 is read-only offline evidence; no UDP send/bind".into());

    Ok(UdpEvidenceRun {
        export,
        result: "VERIFIED",
        udp_observed,
        notes,
        used_live_pcap: used_live,
    })
}

fn load_safe_fixture() -> Result<SafeUdpEvidenceExport, UdpEvidenceVerifyError> {
    let candidates = [
        default_safe_path(),
        PathBuf::from("network/fixtures/udp_evidence/udp_evidence_safe.json"),
        PathBuf::from("../network/fixtures/udp_evidence/udp_evidence_safe.json"),
    ];
    let path = candidates
        .into_iter()
        .find(|p| p.exists())
        .ok_or_else(|| {
            UdpEvidenceVerifyError::FileNotFound(
                "fixtures/udp_evidence/udp_evidence_safe.json".into(),
            )
        })?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| UdpEvidenceVerifyError::Io(e.to_string()))?;
    serde_json::from_str(&text).map_err(|e| UdpEvidenceVerifyError::Json(e.to_string()))
}

pub fn write_safe_exports(export: &SafeUdpEvidenceExport) -> Result<PathBuf, UdpEvidenceVerifyError> {
    let dir = PathBuf::from("fixtures/udp_evidence");
    std::fs::create_dir_all(&dir).map_err(|e| UdpEvidenceVerifyError::Io(e.to_string()))?;
    let main = dir.join("udp_evidence_safe.json");
    let cross = dir.join("cross_capture_safe.json");
    let main_json = serde_json::to_string_pretty(export)
        .map_err(|e| UdpEvidenceVerifyError::Json(e.to_string()))?;
    std::fs::write(&main, main_json).map_err(|e| UdpEvidenceVerifyError::Io(e.to_string()))?;
    let cross_json = serde_json::to_string_pretty(&export.cross_capture)
        .map_err(|e| UdpEvidenceVerifyError::Json(e.to_string()))?;
    std::fs::write(&cross, cross_json).map_err(|e| UdpEvidenceVerifyError::Io(e.to_string()))?;
    Ok(main)
}

pub fn default_export_path(_manifest: &Path) -> PathBuf {
    PathBuf::from("fixtures/udp_evidence/udp_evidence_safe.json")
}
