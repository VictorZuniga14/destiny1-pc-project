//! Run M4.1 protocol-spec-verify over pipeline-ready captures.

use crate::message_inventory_verify::{self, MessageInventoryError};
use crate::protocol_spec::{
    build_protocol_spec, to_safe_export, validate_spec, SafeProtocolSpecExport, SPEC_VERSION,
};
use std::path::{Path, PathBuf};

pub struct ProtocolSpecRun {
    pub export: SafeProtocolSpecExport,
    pub result: &'static str,
    pub notes: Vec<String>,
}

impl std::fmt::Display for ProtocolSpecRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "M4.1 PROTOCOL IMPLEMENTATION SPECIFICATION")?;
        writeln!(f)?;
        writeln!(f, "version: {}", self.export.version)?;
        writeln!(f, "captures:")?;
        for c in &self.export.captures {
            writeln!(f, "  {c}")?;
        }
        writeln!(f)?;
        writeln!(f, "captures_processed: {}", self.export.captures.len())?;
        writeln!(f, "messages: {}/28", self.export.message_count)?;
        writeln!(f)?;
        writeln!(f, "startup sequence:")?;
        writeln!(f, "  {}", self.export.startup_sequence.join("→"))?;
        writeln!(f)?;
        writeln!(f, "framing: {}", self.export.framing.classification.as_str())?;
        writeln!(
            f,
            "session-login 0x1A: {}",
            self.export.crypto.session_login_0x1a.classification.as_str()
        )?;
        writeln!(
            f,
            "AES-GCM: {}",
            self.export.crypto.aes_gcm.classification.as_str()
        )?;
        writeln!(
            f,
            "nonce model: {}",
            self.export.crypto.nonce_model.classification
        )?;
        writeln!(f)?;
        writeln!(f, "state machine nodes:")?;
        writeln!(f, "  {}", self.export.state_machine.nodes.join(", "))?;
        writeln!(f)?;
        writeln!(f, "implementation readiness (sample):")?;
        for r in self.export.implementation_readiness.iter().take(8) {
            writeln!(
                f,
                "  {} → {} (understood={})",
                r.component,
                r.readiness.as_str(),
                r.understood
            )?;
        }
        writeln!(f)?;
        writeln!(f, "high-priority unknowns:")?;
        for u in self
            .export
            .unknowns
            .iter()
            .filter(|u| u.priority.as_str() == "HIGH")
        {
            writeln!(f, "  {}: {}", u.id, u.description)?;
        }
        writeln!(f)?;
        for n in &self.notes {
            writeln!(f, "note: {n}")?;
        }
        writeln!(f, "result:")?;
        writeln!(f, "  {}", self.result)?;
        Ok(())
    }
}

pub fn run_from_manifest(path: impl AsRef<Path>) -> Result<ProtocolSpecRun, MessageInventoryError> {
    let inv = message_inventory_verify::run_from_manifest(path)?;
    if inv.captures.len() < 2 {
        return Err(MessageInventoryError::NeedTwoCaptures);
    }
    let spec = build_protocol_spec(&inv.captures[0], &inv.captures[1]);
    let mut notes = Vec::new();
    let result = match validate_spec(&spec) {
        Ok(()) => {
            notes.push(format!("schema ok; version {SPEC_VERSION}"));
            "VERIFIED_PROTOCOL_SPEC"
        }
        Err(e) => {
            notes.push(format!("validation failed: {e}"));
            "BLOCKED_PROTOCOL_SPEC"
        }
    };
    // Markdown consistency (repo docs next to network/).
    let md_candidates = [
        PathBuf::from("../docs/networking/protocol-spec-v0.1.md"),
        PathBuf::from("docs/networking/protocol-spec-v0.1.md"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/networking/protocol-spec-v0.1.md"),
    ];
    let mut md_ok = false;
    for md_path in &md_candidates {
        if let Ok(text) = std::fs::read_to_string(md_path) {
            if text.contains("v0.1")
                && text.contains("20260529-003132")
                && text.contains("20260608-231100")
            {
                md_ok = true;
                break;
            }
        }
    }
    if md_ok {
        notes.push("markdown protocol-spec-v0.1.md consistent".into());
    } else {
        notes.push("markdown consistency check skipped or failed".into());
    }
    Ok(ProtocolSpecRun {
        export: to_safe_export(&spec),
        result,
        notes,
    })
}

pub fn write_safe_export(
    path: impl AsRef<Path>,
    export: &SafeProtocolSpecExport,
) -> Result<(), MessageInventoryError> {
    let json = serde_json::to_string_pretty(export).map_err(|_| MessageInventoryError::BadJson)?;
    if let Some(parent) = path.as_ref().parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, json + "\n").map_err(|_| MessageInventoryError::Io)
}

pub fn default_export_path(manifest: &Path) -> PathBuf {
    if manifest
        .components()
        .any(|c| c.as_os_str() == "multi_capture" || c.as_os_str() == "fixtures")
    {
        PathBuf::from("fixtures/protocol_spec/protocol_spec_safe.json")
    } else {
        manifest
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("protocol_spec_safe.json")
    }
}
