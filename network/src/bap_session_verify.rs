//! Offline mass BAP session verify against a gitignored capture sequence JSON.

use crate::bap_session::{BapSession, BapSessionError, DecodedBapFrame};
use crate::crypto::NonceDirection;
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BapVerifyError {
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
    #[error("frames list empty")]
    EmptyFrames,
    #[error("session: {0}")]
    Session(#[from] BapSessionError),
}

#[derive(Debug, Deserialize)]
struct VerifyFile {
    #[serde(default)]
    capture: Option<String>,
    session_key_hex: String,
    session_nonce_hex: String,
    frames: Vec<VerifyFrame>,
}

#[derive(Debug, Deserialize)]
struct VerifyFrame {
    direction: String,
    /// Full raw BAP frame hex (header+body). Omit / empty → wire unavailable.
    #[serde(default)]
    frame_hex: Option<String>,
    /// Correlation metadata (PCAP / JSONL); retained for evidence linkage.
    #[serde(default)]
    #[allow(dead_code)]
    id_hex: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    frame_offset: Option<u64>,
    #[serde(default)]
    #[allow(dead_code)]
    frame_order: Option<u64>,
    #[serde(default)]
    expected_kind: Option<u8>,
    #[serde(default)]
    expected_msg_id: Option<u16>,
    #[serde(default)]
    expected_plaintext_len: Option<usize>,
}

fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, BapVerifyError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(BapVerifyError::EmptyField(field));
    }
    if t.len() % 2 != 0 {
        return Err(BapVerifyError::BadHex(field, t.len()));
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or(BapVerifyError::BadHex(field, t.len()))?;
        let lo = hex_nibble(bytes[i + 1]).ok_or(BapVerifyError::BadHex(field, t.len()))?;
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

fn parse_direction(s: &str) -> Result<NonceDirection, BapVerifyError> {
    match s.trim() {
        "client_to_server" | "c2s" => Ok(NonceDirection::ClientToServer),
        "server_to_client" | "s2c" => Ok(NonceDirection::ServerToClient),
        other => Err(BapVerifyError::BadDirection(other.to_string())),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BapSessionVerifyReport {
    pub capture: String,
    pub frames_seen: u32,
    pub clear_frames: u32,
    pub encrypted_frames: u32,
    pub opaque_frames: u32,
    pub framing_valid: bool,
    pub encrypted_frames_with_wire_material: u32,
    pub wire_material_unavailable: u32,
    pub encrypted_decrypt_success: u32,
    pub encrypted_decrypt_failed: u32,
    pub clear_parse_ok: u32,
    pub nonce_state_valid: bool,
}

impl BapSessionVerifyReport {
    pub fn verified(&self) -> bool {
        self.framing_valid
            && self.nonce_state_valid
            && self.encrypted_decrypt_failed == 0
            && self.frames_seen > 0
    }
}

impl std::fmt::Display for BapSessionVerifyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "BAP SESSION VERIFY")?;
        writeln!(f)?;
        writeln!(f, "capture: {}", self.capture)?;
        writeln!(f)?;
        writeln!(f, "frames_seen: {}", self.frames_seen)?;
        writeln!(f, "clear_frames: {}", self.clear_frames)?;
        writeln!(f, "encrypted_frames: {}", self.encrypted_frames)?;
        writeln!(f, "opaque_frames: {}", self.opaque_frames)?;
        writeln!(f)?;
        writeln!(f, "framing_valid: {}", self.framing_valid)?;
        writeln!(
            f,
            "encrypted_frames_with_wire_material: {}",
            self.encrypted_frames_with_wire_material
        )?;
        writeln!(
            f,
            "wire_material_unavailable: {}",
            self.wire_material_unavailable
        )?;
        writeln!(
            f,
            "encrypted_decrypt_success: {}",
            self.encrypted_decrypt_success
        )?;
        writeln!(
            f,
            "encrypted_decrypt_failed: {}",
            self.encrypted_decrypt_failed
        )?;
        writeln!(f, "clear_parse_ok: {}", self.clear_parse_ok)?;
        writeln!(f)?;
        writeln!(f, "nonce_state_valid: {}", self.nonce_state_valid)?;
        writeln!(f)?;
        writeln!(
            f,
            "result: {}",
            if self.verified() {
                "VERIFIED"
            } else {
                "FAILED"
            }
        )?;
        Ok(())
    }
}

pub fn verify_from_path(path: impl AsRef<Path>) -> Result<BapSessionVerifyReport, BapVerifyError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(BapVerifyError::FileNotFound(path.display().to_string()));
    }
    let text = std::fs::read_to_string(path).map_err(|_| BapVerifyError::Io)?;
    verify_from_json_str(&text)
}

pub fn verify_from_json_str(text: &str) -> Result<BapSessionVerifyReport, BapVerifyError> {
    let file: VerifyFile = serde_json::from_str(text).map_err(|_| BapVerifyError::BadJson)?;
    if file.frames.is_empty() {
        return Err(BapVerifyError::EmptyFrames);
    }

    let key = decode_hex("session_key_hex", &file.session_key_hex)?;
    if key.len() != 16 {
        return Err(BapVerifyError::BadFieldLen("session_key_hex", key.len(), 16));
    }
    let sn = decode_hex("session_nonce_hex", &file.session_nonce_hex)?;
    if sn.len() != 12 {
        return Err(BapVerifyError::BadFieldLen(
            "session_nonce_hex",
            sn.len(),
            12,
        ));
    }

    let mut session = BapSession::new(&key, &sn)?;
    let mut report = BapSessionVerifyReport {
        capture: file
            .capture
            .unwrap_or_else(|| "unknown".to_string()),
        frames_seen: 0,
        clear_frames: 0,
        encrypted_frames: 0,
        opaque_frames: 0,
        framing_valid: true,
        encrypted_frames_with_wire_material: 0,
        wire_material_unavailable: 0,
        encrypted_decrypt_success: 0,
        encrypted_decrypt_failed: 0,
        clear_parse_ok: 0,
        nonce_state_valid: true,
    };

    let mut expected_c = 0u64;
    let mut expected_s = 0u64;

    for fr in &file.frames {
        report.frames_seen += 1;
        let direction = parse_direction(&fr.direction)?;

        let frame_hex = fr.frame_hex.as_deref().unwrap_or("").trim();
        if frame_hex.is_empty() {
            // No wire — do not count as decrypt failure.
            if fr.expected_kind == Some(1) {
                report.encrypted_frames += 1;
                report.wire_material_unavailable += 1;
            } else if fr.expected_kind == Some(2) {
                report.clear_frames += 1;
                report.wire_material_unavailable += 1;
            }
            continue;
        }

        let raw = decode_hex("frame_hex", frame_hex)?;
        match session.decode_frame(direction, &raw) {
            Ok(DecodedBapFrame::Clear {
                msg_id,
                context: _,
                payload: _,
            }) => {
                report.clear_frames += 1;
                report.clear_parse_ok += 1;
                if let Some(exp) = fr.expected_msg_id {
                    if exp != msg_id {
                        report.framing_valid = false;
                    }
                }
                if let Some(k) = fr.expected_kind {
                    if k != 2 {
                        report.framing_valid = false;
                    }
                }
            }
            Ok(DecodedBapFrame::Decrypted {
                msg_id,
                plaintext_len,
                ..
            }) => {
                report.encrypted_frames += 1;
                report.encrypted_frames_with_wire_material += 1;
                report.encrypted_decrypt_success += 1;
                match direction {
                    NonceDirection::ClientToServer => expected_c += 1,
                    NonceDirection::ServerToClient => expected_s += 1,
                }
                if let Some(exp) = fr.expected_plaintext_len {
                    if exp != plaintext_len {
                        report.encrypted_decrypt_failed += 1;
                        report.encrypted_decrypt_success =
                            report.encrypted_decrypt_success.saturating_sub(1);
                    }
                }
                if let (Some(exp_id), Some(got)) = (fr.expected_msg_id, msg_id) {
                    if exp_id != got {
                        report.framing_valid = false;
                    }
                }
            }
            Ok(DecodedBapFrame::Opaque { .. }) => {
                report.opaque_frames += 1;
            }
            Err(BapSessionError::DecryptFailed) => {
                report.encrypted_frames += 1;
                report.encrypted_frames_with_wire_material += 1;
                report.encrypted_decrypt_failed += 1;
                match direction {
                    NonceDirection::ClientToServer => expected_c += 1,
                    NonceDirection::ServerToClient => expected_s += 1,
                }
            }
            Err(BapSessionError::Framing(_)) | Err(BapSessionError::TrailingBytes) => {
                report.framing_valid = false;
            }
            Err(BapSessionError::EmptyCiphertext) => {
                report.encrypted_frames += 1;
                report.encrypted_frames_with_wire_material += 1;
                report.encrypted_decrypt_failed += 1;
            }
            Err(e) => return Err(e.into()),
        }
    }

    if session.client_to_server_counter() != expected_c
        || session.server_to_client_counter() != expected_s
    {
        report.nonce_state_valid = false;
    }

    Ok(report)
}
