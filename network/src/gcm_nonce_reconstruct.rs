//! Load gitignored nonce-reconstruction inputs and report safe metadata only.

use crate::crypto::{
    self, GCM_NONCE_LEN, NonceDirection, NonceReconstructReport, NonceTransform,
};
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NonceInputError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("failed to read input file")]
    Io,
    #[error("invalid JSON structure (expected gcm-nonce-reconstruct object)")]
    BadJson,
    #[error("field '{0}' has invalid hex (length chars={1})")]
    BadHex(&'static str, usize),
    #[error("field '{0}' has unexpected byte length {1} (expected {2})")]
    BadFieldLen(&'static str, usize, usize),
    #[error("field '{0}' must be non-empty")]
    EmptyField(&'static str),
    #[error("unsupported direction '{0}' (client_to_server | server_to_client)")]
    BadDirection(String),
    #[error(
        "unsupported transform '{0}' (Identity | XorLastByte1 | DefaultForDirection)"
    )]
    BadTransform(String),
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::GcmNonceError),
}

#[derive(Debug, Deserialize)]
struct NonceFile {
    /// 12-byte session nonce candidate (typically from 0x1A plaintext[0..12]).
    session_nonce_hex: String,
    /// `client_to_server` or `server_to_client`.
    direction: String,
    /// `Identity` | `XorLastByte1` | `DefaultForDirection`.
    transform: String,
    /// Optional: nonce recorded for the target frame (e.g. JSONL `nonce` on 0x79).
    #[serde(default)]
    expected_nonce_hex: Option<String>,
}

fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, NonceInputError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(NonceInputError::EmptyField(field));
    }
    if t.len() % 2 != 0 {
        return Err(NonceInputError::BadHex(field, t.len()));
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or(NonceInputError::BadHex(field, t.len()))?;
        let lo = hex_nibble(bytes[i + 1]).ok_or(NonceInputError::BadHex(field, t.len()))?;
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

fn parse_direction(s: &str) -> Result<NonceDirection, NonceInputError> {
    match s.trim() {
        "client_to_server" | "c2s" => Ok(NonceDirection::ClientToServer),
        "server_to_client" | "s2c" => Ok(NonceDirection::ServerToClient),
        other => Err(NonceInputError::BadDirection(other.to_string())),
    }
}

fn parse_transform(
    s: &str,
    direction: NonceDirection,
) -> Result<NonceTransform, NonceInputError> {
    match s.trim() {
        "Identity" => Ok(NonceTransform::Identity),
        "XorLastByte1" => Ok(NonceTransform::XorLastByte(1)),
        "DefaultForDirection" => Ok(crypto::default_transform_for(direction)),
        other => Err(NonceInputError::BadTransform(other.to_string())),
    }
}

pub fn reconstruct_from_path(
    path: impl AsRef<Path>,
) -> Result<NonceReconstructReport, NonceInputError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(NonceInputError::FileNotFound(path.display().to_string()));
    }
    let text = std::fs::read_to_string(path).map_err(|_| NonceInputError::Io)?;
    reconstruct_from_json_str(&text)
}

pub fn reconstruct_from_json_str(text: &str) -> Result<NonceReconstructReport, NonceInputError> {
    let file: NonceFile = serde_json::from_str(text).map_err(|_| NonceInputError::BadJson)?;
    let direction = parse_direction(&file.direction)?;
    let transform = parse_transform(&file.transform, direction)?;

    let session = decode_hex("session_nonce_hex", &file.session_nonce_hex)?;
    if session.len() != GCM_NONCE_LEN {
        return Err(NonceInputError::BadFieldLen(
            "session_nonce_hex",
            session.len(),
            GCM_NONCE_LEN,
        ));
    }

    let expected = match &file.expected_nonce_hex {
        Some(h) if !h.trim().is_empty() => {
            let e = decode_hex("expected_nonce_hex", h)?;
            if e.len() != GCM_NONCE_LEN {
                return Err(NonceInputError::BadFieldLen(
                    "expected_nonce_hex",
                    e.len(),
                    GCM_NONCE_LEN,
                ));
            }
            Some(e)
        }
        _ => None,
    };

    Ok(crypto::reconstruct_first_frame_nonce(
        &session,
        direction,
        transform,
        expected.as_deref(),
    )?)
}
