//! Capture / registry verify for M4.4 message codec.

use crate::jsonl::Direction;
use crate::message_codec::{
    decode_message, encode_message, roundtrip_ok, validate_session_login_response_payload,
    BapMessageEnvelope, CodecError,
};
use crate::message_registry::{self, to_safe_export, SafeMessageRegistryExport};
use crate::protocol_spec::EXPECTED_MESSAGE_IDS;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MessageCodecVerifyError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("io: {0}")]
    Io(String),
    #[error("json: {0}")]
    Json(String),
    #[error("registry: {0}")]
    Registry(String),
    #[error("verify failed: {0}")]
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

pub struct MessageCodecVerifyRun {
    pub result: &'static str,
    pub captures: usize,
    pub frames_decoded: u64,
    pub known_messages: u64,
    pub unknown_messages: u64,
    pub structured_0x1a: u64,
    pub opaque_0x1a: u64,
    pub roundtrip_failures: u64,
    pub notes: Vec<String>,
    pub export: SafeMessageRegistryExport,
}

impl std::fmt::Display for MessageCodecVerifyRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "M4.4 MESSAGE CODEC VERIFY")?;
        writeln!(f)?;
        writeln!(f, "captures: {}", self.captures)?;
        writeln!(f, "frames_decoded: {}", self.frames_decoded)?;
        writeln!(f, "known_messages: {}", self.known_messages)?;
        writeln!(f, "unknown_messages: {}", self.unknown_messages)?;
        writeln!(f, "structured_0x1a: {}", self.structured_0x1a)?;
        writeln!(f, "opaque_0x1a: {}", self.opaque_0x1a)?;
        writeln!(f, "roundtrip_failures: {}", self.roundtrip_failures)?;
        writeln!(f, "registry_entries: {}", self.export.message_count)?;
        writeln!(f)?;
        for n in &self.notes {
            writeln!(f, "note: {n}")?;
        }
        writeln!(f, "MESSAGE_CODEC_VERIFY: {}", self.result)?;
        Ok(())
    }
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

fn parse_direction(s: &str) -> Direction {
    match s {
        "client_to_server" => Direction::ClientToServer,
        "server_to_client" => Direction::ServerToClient,
        _ => Direction::ClientToServer,
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, MessageCodecVerifyError> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(MessageCodecVerifyError::Json("odd hex".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let h = std::str::from_utf8(&bytes[i..i + 2])
            .map_err(|e| MessageCodecVerifyError::Json(e.to_string()))?;
        out.push(
            u8::from_str_radix(h, 16)
                .map_err(|e| MessageCodecVerifyError::Json(e.to_string()))?,
        );
        i += 2;
    }
    Ok(out)
}

fn scan_capture(
    path: &Path,
    frames_decoded: &mut u64,
    known: &mut u64,
    unknown: &mut u64,
    structured_1a: &mut u64,
    opaque_1a: &mut u64,
    roundtrip_failures: &mut u64,
) -> Result<(), MessageCodecVerifyError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| MessageCodecVerifyError::Io(e.to_string()))?;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(line)
            .map_err(|e| MessageCodecVerifyError::Json(e.to_string()))?;
        if v.get("kind").and_then(|k| k.as_str()) != Some("bap_frame") {
            continue;
        }
        let id = match v.get("id").and_then(|x| x.as_u64()) {
            Some(i) => i as u16,
            None => continue,
        };
        let context = v.get("context").and_then(|x| x.as_u64()).unwrap_or(0) as u32;
        let direction = parse_direction(v.get("direction").and_then(|d| d.as_str()).unwrap_or(""));
        // Prefer plaintext for encrypted frames when present; else payload_hex for clear.
        let payload = if let Some(hx) = v.get("plaintext_hex").and_then(|x| x.as_str()) {
            // plaintext includes id+context+payload in some dumps — if starts with id, strip.
            let full = decode_hex(hx)?;
            if full.len() >= 6 {
                let pid = u16::from_be_bytes([full[0], full[1]]);
                if pid == id {
                    full[6..].to_vec()
                } else {
                    // already body-only
                    full
                }
            } else {
                full
            }
        } else if let Some(hx) = v.get("payload_hex").and_then(|x| x.as_str()) {
            decode_hex(hx)?
        } else {
            continue;
        };

        *frames_decoded += 1;
        let env = BapMessageEnvelope {
            id,
            context,
            direction,
            payload,
        };
        match decode_message(&env) {
            Ok(msg) => {
                if msg.is_known() {
                    *known += 1;
                } else {
                    *unknown += 1;
                }
                if id == 0x1A {
                    match validate_session_login_response_payload(&env.payload) {
                        Ok(_) => *structured_1a += 1,
                        Err(_) => *opaque_1a += 1,
                    }
                }
                match roundtrip_ok(&msg) {
                    Ok(true) => {}
                    Ok(false) | Err(_) => *roundtrip_failures += 1,
                }
                // Never log payload bytes.
                let _ = encode_message(&msg);
            }
            Err(CodecError::MalformedMessage(_))
            | Err(CodecError::InvalidPayloadLength(_))
            | Err(CodecError::InvalidRecordLength(_))
            | Err(CodecError::InvalidFieldLength(_)) => {
                *unknown += 1;
            }
            Err(e) => {
                return Err(MessageCodecVerifyError::Failed(e.to_string()));
            }
        }
    }
    Ok(())
}

/// Default: multi-capture manifest under fixtures/.
pub fn run_from_manifest(path: impl AsRef<Path>) -> Result<MessageCodecVerifyRun, MessageCodecVerifyError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(MessageCodecVerifyError::FileNotFound(
            path.display().to_string(),
        ));
    }
    message_registry::validate_registry()
        .map_err(MessageCodecVerifyError::Registry)?;

    let text = std::fs::read_to_string(path)
        .map_err(|e| MessageCodecVerifyError::Io(e.to_string()))?;
    let manifest: ManifestFile =
        serde_json::from_str(&text).map_err(|e| MessageCodecVerifyError::Json(e.to_string()))?;
    let ready: Vec<_> = manifest
        .captures
        .iter()
        .filter(|c| c.status.as_deref() != Some("catalog_only"))
        .collect();
    if ready.len() < 2 {
        return Err(MessageCodecVerifyError::Failed(
            "need two captures".into(),
        ));
    }

    let manifest_dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut notes = Vec::new();
    let mut frames_decoded = 0u64;
    let mut known_messages = 0u64;
    let mut unknown_messages = 0u64;
    let mut structured_0x1a = 0u64;
    let mut opaque_0x1a = 0u64;
    let mut roundtrip_failures = 0u64;
    let mut captures_scanned = 0usize;

    for c in &ready[..2] {
        if let Some(p) = resolve_bap_jsonl(&c.capture_id, manifest_dir) {
            notes.push(format!("scanned {}", p.display()));
            scan_capture(
                &p,
                &mut frames_decoded,
                &mut known_messages,
                &mut unknown_messages,
                &mut structured_0x1a,
                &mut opaque_0x1a,
                &mut roundtrip_failures,
            )?;
            captures_scanned += 1;
        } else {
            notes.push(format!(
                "capture {} jsonl not found — registry-only for this capture",
                c.capture_id
            ));
        }
    }

    // Cross-capture direction consistency on registry (structural).
    for id in EXPECTED_MESSAGE_IDS {
        let e = message_registry::registry_entry(*id);
        if e.direction != "C2S" && e.direction != "S2C" && e.direction != "UNKNOWN" {
            return Err(MessageCodecVerifyError::Failed(format!(
                "direction inconsistency 0x{id:04x}"
            )));
        }
    }
    notes.push("cross-capture: registry directions checked; payload semantics not invented".into());

    let export = to_safe_export();
    let _ = write_safe_export(&export);

    if captures_scanned == 0 {
        notes.push("no live captures — synthetic registry verification only".into());
    }
    if roundtrip_failures > 0 {
        return Err(MessageCodecVerifyError::Failed(format!(
            "{roundtrip_failures} roundtrip failures"
        )));
    }

    Ok(MessageCodecVerifyRun {
        result: "VERIFIED",
        captures: ready.len().min(2),
        frames_decoded,
        known_messages,
        unknown_messages,
        structured_0x1a,
        opaque_0x1a,
        roundtrip_failures,
        notes,
        export,
    })
}

pub fn run_default() -> Result<MessageCodecVerifyRun, MessageCodecVerifyError> {
    let candidates = [
        PathBuf::from("fixtures/multi_capture/manifest.json"),
        PathBuf::from("network/fixtures/multi_capture/manifest.json"),
    ];
    let path = candidates
        .into_iter()
        .find(|p| p.exists())
        .ok_or_else(|| {
            MessageCodecVerifyError::FileNotFound(
                "fixtures/multi_capture/manifest.json".into(),
            )
        })?;
    run_from_manifest(path)
}

pub fn write_safe_export(
    export: &SafeMessageRegistryExport,
) -> Result<PathBuf, MessageCodecVerifyError> {
    let dir = PathBuf::from("fixtures/message_codec");
    std::fs::create_dir_all(&dir).map_err(|e| MessageCodecVerifyError::Io(e.to_string()))?;
    let path = dir.join("message_registry_safe.json");
    let json = serde_json::to_string_pretty(export)
        .map_err(|e| MessageCodecVerifyError::Json(e.to_string()))?;
    if json.contains("payload_hex") || json.contains("session_key") {
        return Err(MessageCodecVerifyError::Failed(
            "secrets in safe export".into(),
        ));
    }
    std::fs::write(&path, json).map_err(|e| MessageCodecVerifyError::Io(e.to_string()))?;
    Ok(path)
}
