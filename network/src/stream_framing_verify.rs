//! Offline: concat capture wire → chunked `BapStreamDecoder` → `BapSession`.

use crate::bap_session::{BapSession, BapSessionError, DecodedBapFrame};
use crate::crypto::NonceDirection;
use crate::stream_framing::{BapStreamDecoder, StreamFramingError};
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StreamVerifyError {
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
    #[error("stream framing: {0}")]
    Stream(#[from] StreamFramingError),
    #[error("session: {0}")]
    Session(#[from] BapSessionError),
    #[error("recovered {got} frames, expected {expected}")]
    FrameCountMismatch { got: usize, expected: usize },
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
    #[serde(default)]
    frame_hex: Option<String>,
}

fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, StreamVerifyError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(StreamVerifyError::EmptyField(field));
    }
    if t.len() % 2 != 0 {
        return Err(StreamVerifyError::BadHex(field, t.len()));
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or(StreamVerifyError::BadHex(field, t.len()))?;
        let lo = hex_nibble(bytes[i + 1]).ok_or(StreamVerifyError::BadHex(field, t.len()))?;
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

fn parse_direction(s: &str) -> Result<NonceDirection, StreamVerifyError> {
    match s.trim() {
        "client_to_server" | "c2s" => Ok(NonceDirection::ClientToServer),
        "server_to_client" | "s2c" => Ok(NonceDirection::ServerToClient),
        other => Err(StreamVerifyError::BadDirection(other.to_string())),
    }
}

/// Default offline chunk schedule for capture replay (not a protocol claim).
pub const DEFAULT_CHUNK_SIZES: &[usize] = &[1, 7, 13, 31, 64, 17, 3, 128];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamFramingVerifyReport {
    pub capture: String,
    pub stream_bytes: usize,
    pub chunks_pushed: u32,
    pub frames_recovered: u32,
    pub frames_expected: u32,
    pub clear_frames: u32,
    pub encrypted_frames: u32,
    pub encrypted_decrypt_success: u32,
    pub encrypted_decrypt_failed: u32,
    pub stream_framing_ok: bool,
    pub nonce_state_valid: bool,
    pub buffer_empty_at_end: bool,
}

impl StreamFramingVerifyReport {
    pub fn verified(&self) -> bool {
        self.stream_framing_ok
            && self.buffer_empty_at_end
            && self.frames_recovered == self.frames_expected
            && self.encrypted_decrypt_failed == 0
            && self.nonce_state_valid
            && self.frames_recovered > 0
    }
}

impl std::fmt::Display for StreamFramingVerifyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "BAP STREAM FRAMING VERIFY")?;
        writeln!(f)?;
        writeln!(f, "capture: {}", self.capture)?;
        writeln!(f)?;
        writeln!(f, "stream_bytes: {}", self.stream_bytes)?;
        writeln!(f, "chunks_pushed: {}", self.chunks_pushed)?;
        writeln!(f, "frames_expected: {}", self.frames_expected)?;
        writeln!(f, "frames_recovered: {}", self.frames_recovered)?;
        writeln!(f)?;
        writeln!(f, "clear_frames: {}", self.clear_frames)?;
        writeln!(f, "encrypted_frames: {}", self.encrypted_frames)?;
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
        writeln!(f)?;
        writeln!(f, "stream_framing_ok: {}", self.stream_framing_ok)?;
        writeln!(f, "buffer_empty_at_end: {}", self.buffer_empty_at_end)?;
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

/// Concatenate wire frames, push through `BapStreamDecoder` in `chunk_sizes`,
/// then decode with `BapSession` using per-frame directions from the JSON.
pub fn verify_from_path(
    path: impl AsRef<Path>,
    chunk_sizes: &[usize],
) -> Result<StreamFramingVerifyReport, StreamVerifyError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(StreamVerifyError::FileNotFound(path.display().to_string()));
    }
    let text = std::fs::read_to_string(path).map_err(|_| StreamVerifyError::Io)?;
    verify_from_json_str(&text, chunk_sizes)
}

pub fn verify_from_json_str(
    text: &str,
    chunk_sizes: &[usize],
) -> Result<StreamFramingVerifyReport, StreamVerifyError> {
    let file: VerifyFile = serde_json::from_str(text).map_err(|_| StreamVerifyError::BadJson)?;
    let key = decode_hex("session_key_hex", &file.session_key_hex)?;
    if key.len() != 16 {
        return Err(StreamVerifyError::BadFieldLen(
            "session_key_hex",
            key.len(),
            16,
        ));
    }
    let sn = decode_hex("session_nonce_hex", &file.session_nonce_hex)?;
    if sn.len() != 12 {
        return Err(StreamVerifyError::BadFieldLen(
            "session_nonce_hex",
            sn.len(),
            12,
        ));
    }

    let mut stream = Vec::new();
    let mut directions = Vec::new();
    for fr in &file.frames {
        let hex = fr.frame_hex.as_deref().unwrap_or("").trim();
        if hex.is_empty() {
            continue;
        }
        let raw = decode_hex("frame_hex", hex)?;
        directions.push(parse_direction(&fr.direction)?);
        stream.extend_from_slice(&raw);
    }
    if directions.is_empty() {
        return Err(StreamVerifyError::EmptyWire);
    }

    let sizes: Vec<usize> = if chunk_sizes.is_empty() {
        DEFAULT_CHUNK_SIZES.to_vec()
    } else {
        chunk_sizes
            .iter()
            .copied()
            .filter(|&n| n > 0)
            .collect()
    };
    let sizes = if sizes.is_empty() {
        vec![1]
    } else {
        sizes
    };

    let mut decoder = BapStreamDecoder::new();
    let mut recovered = Vec::new();
    let mut chunks_pushed = 0u32;
    let mut offset = 0usize;
    let mut size_i = 0usize;
    while offset < stream.len() {
        let n = sizes[size_i % sizes.len()].min(stream.len() - offset);
        size_i += 1;
        let frames = decoder.push(&stream[offset..offset + n])?;
        recovered.extend(frames);
        chunks_pushed += 1;
        offset += n;
    }
    let buffer_empty = decoder.buffered_len() == 0;
    decoder.finish()?;

    if recovered.len() != directions.len() {
        return Err(StreamVerifyError::FrameCountMismatch {
            got: recovered.len(),
            expected: directions.len(),
        });
    }

    // Round-trip check: recovered raw bytes equal concatenated originals order.
    let mut rebuilt = Vec::new();
    for r in &recovered {
        rebuilt.extend_from_slice(&r.raw_bytes);
    }
    let stream_framing_ok = rebuilt == stream;

    let mut session = BapSession::new(&key, &sn)?;
    let mut report = StreamFramingVerifyReport {
        capture: file.capture.unwrap_or_else(|| "unknown".to_string()),
        stream_bytes: stream.len(),
        chunks_pushed,
        frames_recovered: recovered.len() as u32,
        frames_expected: directions.len() as u32,
        clear_frames: 0,
        encrypted_frames: 0,
        encrypted_decrypt_success: 0,
        encrypted_decrypt_failed: 0,
        stream_framing_ok,
        nonce_state_valid: true,
        buffer_empty_at_end: buffer_empty,
    };

    let mut expected_c = 0u64;
    let mut expected_s = 0u64;

    for (raw, dir) in recovered.iter().zip(directions.iter()) {
        match session.decode_frame(*dir, &raw.raw_bytes) {
            Ok(DecodedBapFrame::Clear { .. }) => {
                report.clear_frames += 1;
            }
            Ok(DecodedBapFrame::Decrypted { .. }) => {
                report.encrypted_frames += 1;
                report.encrypted_decrypt_success += 1;
                match dir {
                    NonceDirection::ClientToServer => expected_c += 1,
                    NonceDirection::ServerToClient => expected_s += 1,
                }
            }
            Ok(DecodedBapFrame::Opaque { .. }) => {
                report.stream_framing_ok = false;
            }
            Err(BapSessionError::DecryptFailed) => {
                report.encrypted_frames += 1;
                report.encrypted_decrypt_failed += 1;
                match dir {
                    NonceDirection::ClientToServer => expected_c += 1,
                    NonceDirection::ServerToClient => expected_s += 1,
                }
            }
            Err(_) => {
                report.stream_framing_ok = false;
            }
        }
    }

    if session.client_to_server_counter() != expected_c
        || session.server_to_client_counter() != expected_s
    {
        report.nonce_state_valid = false;
    }

    Ok(report)
}
