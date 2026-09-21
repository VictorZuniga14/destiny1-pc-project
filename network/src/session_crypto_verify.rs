//! Load gitignored offline session-record material and run CBC+HMAC verification.
//!
//! Never logs or returns secret bytes. Errors name fields and lengths only.
//!
//! M2.3 path: strict layout checks for capture `20260529-003132`, then a single
//! hypothesis via [`crypto::verify_session_record`] (no key truncation fallback).

use crate::crypto::{
    self, AES128_KEY_LEN, HMAC_SHA256_LEN, IV_LEN, HmacMessageKind, SessionRecordVerifyReport,
};
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

/// Expected `record_len` for capture `20260529-003132` session-login-response.
pub const EXPECTED_RECORD_LEN: u32 = 80;
/// Expected ciphertext length under that capture's layout (`record_len - 0x30`).
pub const EXPECTED_CIPHERTEXT_LEN: usize = 32;
/// Minimum HMAC key length accepted (d1-re requires ≥ 16).
pub const EXPECTED_HMAC_KEY_MIN_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum VerifyInputError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("failed to read input file")]
    Io,
    #[error("invalid JSON structure (expected session-crypto-verify object)")]
    BadJson,
    #[error("field '{0}' has invalid hex (length chars={1})")]
    BadHex(&'static str, usize),
    #[error("field '{0}' has unexpected byte length {1} (expected {2})")]
    BadFieldLen(&'static str, usize, usize),
    #[error("field 'record_len' has unexpected value {0} (expected {EXPECTED_RECORD_LEN})")]
    BadRecordLen(u32),
    #[error("field 'ciphertext_hex' length {0} (expected {EXPECTED_CIPHERTEXT_LEN})")]
    BadCiphertextLen(usize),
    #[error("field '{0}' must be non-empty")]
    EmptyField(&'static str),
    #[error("field 'hmac_key_hex' length {0} (expected >= {EXPECTED_HMAC_KEY_MIN_LEN})")]
    BadHmacKeyLen(usize),
    #[error("unsupported hmac_message_kind '{0}' (supported: LengthIvCiphertext)")]
    UnsupportedHmacKind(String),
    #[error("crypto: {0}")]
    Crypto(#[from] crypto::CbcHmacError),
}

/// On-disk input. All secret fields are hex-encoded strings.
///
/// Format only — real values live under `evidence/local/` (gitignored).
#[derive(Debug, Deserialize)]
struct VerifyFile {
    /// Must be `LengthIvCiphertext` (d1-re hypothesis). Explicit; not inferred.
    hmac_message_kind: String,
    /// Big-endian record length field (`u32`); must be 80 for this capture path.
    record_len: u32,
    iv_hex: String,
    ciphertext_hex: String,
    hmac_hex: String,
    aes_key_hex: String,
    hmac_key_hex: String,
}

fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, VerifyInputError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(VerifyInputError::EmptyField(field));
    }
    if t.len() % 2 != 0 {
        return Err(VerifyInputError::BadHex(field, t.len()));
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or(VerifyInputError::BadHex(field, t.len()))?;
        let lo = hex_nibble(bytes[i + 1]).ok_or(VerifyInputError::BadHex(field, t.len()))?;
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

fn parse_kind(s: &str) -> Result<HmacMessageKind, VerifyInputError> {
    match s.trim() {
        "LengthIvCiphertext" => Ok(HmacMessageKind::LengthIvCiphertext),
        other => Err(VerifyInputError::UnsupportedHmacKind(other.to_string())),
    }
}

/// Run verification from a local JSON file. Prints nothing; returns a safe report.
pub fn verify_from_path(path: impl AsRef<Path>) -> Result<SessionRecordVerifyReport, VerifyInputError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(VerifyInputError::FileNotFound(path.display().to_string()));
    }
    let text = std::fs::read_to_string(path).map_err(|_| VerifyInputError::Io)?;
    verify_from_json_str(&text)
}

pub fn verify_from_json_str(text: &str) -> Result<SessionRecordVerifyReport, VerifyInputError> {
    let file: VerifyFile = serde_json::from_str(text).map_err(|_| VerifyInputError::BadJson)?;
    let kind = parse_kind(&file.hmac_message_kind)?;

    if file.record_len != EXPECTED_RECORD_LEN {
        return Err(VerifyInputError::BadRecordLen(file.record_len));
    }

    let iv = decode_hex("iv_hex", &file.iv_hex)?;
    if iv.len() != IV_LEN {
        return Err(VerifyInputError::BadFieldLen("iv_hex", iv.len(), IV_LEN));
    }
    let ciphertext = decode_hex("ciphertext_hex", &file.ciphertext_hex)?;
    if ciphertext.len() != EXPECTED_CIPHERTEXT_LEN {
        return Err(VerifyInputError::BadCiphertextLen(ciphertext.len()));
    }
    let hmac_tag = decode_hex("hmac_hex", &file.hmac_hex)?;
    if hmac_tag.len() != HMAC_SHA256_LEN {
        return Err(VerifyInputError::BadFieldLen(
            "hmac_hex",
            hmac_tag.len(),
            HMAC_SHA256_LEN,
        ));
    }
    let aes_key = decode_hex("aes_key_hex", &file.aes_key_hex)?;
    if aes_key.len() != AES128_KEY_LEN {
        return Err(VerifyInputError::BadFieldLen(
            "aes_key_hex",
            aes_key.len(),
            AES128_KEY_LEN,
        ));
    }
    let hmac_key = decode_hex("hmac_key_hex", &file.hmac_key_hex)?;
    if hmac_key.len() < EXPECTED_HMAC_KEY_MIN_LEN {
        return Err(VerifyInputError::BadHmacKeyLen(hmac_key.len()));
    }

    // Single hypothesis — no automatic alternative inputs / key truncations.
    Ok(crypto::verify_session_record(
        kind,
        file.record_len,
        &iv,
        &ciphertext,
        &hmac_tag,
        &aes_key,
        &hmac_key,
    )?)
}
