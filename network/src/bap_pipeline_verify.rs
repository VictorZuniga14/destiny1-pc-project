//! Offline: MockByteSource → BapOfflinePipeline against capture JSON (M2.8).

use crate::bap_pipeline::{BapOfflinePipeline, PipelineError};
use crate::bap_session::DecodedBapFrame;
use crate::byte_source::{chunk_stream, MockByteSource, DEFAULT_PIPELINE_CHUNK_SIZES};
use crate::crypto::NonceDirection;
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PipelineVerifyError {
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
    #[error("{0}")]
    Pipeline(#[from] PipelineError),
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

fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, PipelineVerifyError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(PipelineVerifyError::EmptyField(field));
    }
    if t.len() % 2 != 0 {
        return Err(PipelineVerifyError::BadHex(field, t.len()));
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or(PipelineVerifyError::BadHex(field, t.len()))?;
        let lo = hex_nibble(bytes[i + 1]).ok_or(PipelineVerifyError::BadHex(field, t.len()))?;
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

fn parse_direction(s: &str) -> Result<NonceDirection, PipelineVerifyError> {
    match s.trim() {
        "client_to_server" | "c2s" => Ok(NonceDirection::ClientToServer),
        "server_to_client" | "s2c" => Ok(NonceDirection::ServerToClient),
        other => Err(PipelineVerifyError::BadDirection(other.to_string())),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipelineVerifyReport {
    pub capture: String,
    pub frames_seen: u32,
    pub clear_frames: u32,
    pub encrypted_frames: u32,
    pub decrypt_success: u32,
    pub decrypt_failed: u32,
    pub chunks_fed: u32,
    pub nonce_state_valid: bool,
}

impl PipelineVerifyReport {
    pub fn verified(&self) -> bool {
        self.frames_seen > 0
            && self.decrypt_failed == 0
            && self.nonce_state_valid
            && self.encrypted_frames == self.decrypt_success
    }
}

impl std::fmt::Display for PipelineVerifyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "BAP PIPELINE VERIFY")?;
        writeln!(f)?;
        writeln!(f, "capture: {}", self.capture)?;
        writeln!(f)?;
        writeln!(f, "frames_seen: {}", self.frames_seen)?;
        writeln!(f, "clear_frames: {}", self.clear_frames)?;
        writeln!(f, "encrypted_frames: {}", self.encrypted_frames)?;
        writeln!(f, "decrypt_success: {}", self.decrypt_success)?;
        writeln!(f, "decrypt_failed: {}", self.decrypt_failed)?;
        writeln!(f, "chunks_fed: {}", self.chunks_fed)?;
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

pub fn verify_from_path(
    path: impl AsRef<Path>,
    chunk_sizes: &[usize],
) -> Result<PipelineVerifyReport, PipelineVerifyError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(PipelineVerifyError::FileNotFound(path.display().to_string()));
    }
    let text = std::fs::read_to_string(path).map_err(|_| PipelineVerifyError::Io)?;
    verify_from_json_str(&text, chunk_sizes)
}

pub fn verify_from_json_str(
    text: &str,
    chunk_sizes: &[usize],
) -> Result<PipelineVerifyReport, PipelineVerifyError> {
    let file: VerifyFile = serde_json::from_str(text).map_err(|_| PipelineVerifyError::BadJson)?;
    let key = decode_hex("session_key_hex", &file.session_key_hex)?;
    if key.len() != 16 {
        return Err(PipelineVerifyError::BadFieldLen(
            "session_key_hex",
            key.len(),
            16,
        ));
    }
    let sn = decode_hex("session_nonce_hex", &file.session_nonce_hex)?;
    if sn.len() != 12 {
        return Err(PipelineVerifyError::BadFieldLen(
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
        return Err(PipelineVerifyError::EmptyWire);
    }

    let sizes = if chunk_sizes.is_empty() {
        DEFAULT_PIPELINE_CHUNK_SIZES
    } else {
        chunk_sizes
    };
    let chunks = chunk_stream(&stream, sizes);
    let chunks_fed = chunks.len() as u32;
    let mut source = MockByteSource::new(chunks);
    let mut pipeline = BapOfflinePipeline::new(&key, &sn)?;
    let decoded = pipeline.run_directed(&mut source, &directions)?;

    let mut report = PipelineVerifyReport {
        capture: file.capture.unwrap_or_else(|| "unknown".to_string()),
        frames_seen: decoded.len() as u32,
        clear_frames: 0,
        encrypted_frames: 0,
        decrypt_success: 0,
        decrypt_failed: 0,
        chunks_fed,
        nonce_state_valid: true,
    };

    let mut expected_c = 0u64;
    let mut expected_s = 0u64;
    for (frame, dir) in decoded.iter().zip(directions.iter()) {
        match frame {
            DecodedBapFrame::Clear { .. } => {
                report.clear_frames += 1;
            }
            DecodedBapFrame::Decrypted { .. } => {
                report.encrypted_frames += 1;
                report.decrypt_success += 1;
                match dir {
                    NonceDirection::ClientToServer => expected_c += 1,
                    NonceDirection::ServerToClient => expected_s += 1,
                }
            }
            DecodedBapFrame::Opaque { .. } => {
                report.nonce_state_valid = false;
            }
        }
    }

    if pipeline.client_to_server_counter() != expected_c
        || pipeline.server_to_client_counter() != expected_s
    {
        report.nonce_state_valid = false;
    }

    Ok(report)
}
