//! Offline first-frame AES-GCM verify (real wire material from gitignored JSON).
//!
//! Uses [`crate::crypto::decrypt_aes_gcm`] unchanged. Never prints secret bytes.

use crate::crypto::{self, KEY_LEN, NONCE_LEN, TAG_LEN, CryptoError};
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FirstFrameError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("failed to read input file")]
    Io,
    #[error("invalid JSON structure (expected gcm-first-frame-verify object)")]
    BadJson,
    #[error("field '{0}' has invalid hex (length chars={1})")]
    BadHex(&'static str, usize),
    #[error("field '{0}' has unexpected byte length {1} (expected {2})")]
    BadFieldLen(&'static str, usize, usize),
    #[error("field '{0}' must be non-empty")]
    EmptyField(&'static str),
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
}

#[derive(Debug, Deserialize)]
struct FirstFrameFile {
    session_key_hex: String,
    nonce_hex: String,
    tag_hex: String,
    ciphertext_hex: String,
    /// Empty string means empty AAD (Case A).
    #[serde(default)]
    aad_hex: String,
    #[serde(default = "default_expected_pt_len")]
    expected_plaintext_len: usize,
}

fn default_expected_pt_len() -> usize {
    6
}

fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, FirstFrameError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(FirstFrameError::EmptyField(field));
    }
    if t.len() % 2 != 0 {
        return Err(FirstFrameError::BadHex(field, t.len()));
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or(FirstFrameError::BadHex(field, t.len()))?;
        let lo = hex_nibble(bytes[i + 1]).ok_or(FirstFrameError::BadHex(field, t.len()))?;
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

/// Safe report — lengths and booleans only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirstFrameReport {
    pub key_length: usize,
    pub nonce_length: usize,
    pub ciphertext_length: usize,
    pub tag_length: usize,
    pub aad_length: usize,
    pub decrypt_ok: bool,
    pub plaintext_length: Option<usize>,
    pub expected_plaintext_length: usize,
    pub plaintext_length_matches_expected: bool,
}

impl FirstFrameReport {
    pub fn verified(&self) -> bool {
        self.decrypt_ok && self.plaintext_length_matches_expected
    }
}

impl std::fmt::Display for FirstFrameReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "key_length: {}", self.key_length)?;
        writeln!(f, "nonce_length: {}", self.nonce_length)?;
        writeln!(f, "ciphertext_length: {}", self.ciphertext_length)?;
        writeln!(f, "tag_length: {}", self.tag_length)?;
        writeln!(f, "aad_length: {}", self.aad_length)?;
        writeln!(
            f,
            "aes_gcm_decrypt: {}",
            if self.decrypt_ok { "success" } else { "fail" }
        )?;
        match self.plaintext_length {
            Some(n) => writeln!(f, "plaintext_length: {n}")?,
            None => writeln!(f, "plaintext_length: n/a")?,
        }
        writeln!(
            f,
            "plaintext_expected_length: {}",
            self.expected_plaintext_length
        )?;
        writeln!(
            f,
            "plaintext_length_matches_expected: {}",
            self.plaintext_length_matches_expected
        )?;
        writeln!(
            f,
            "result: {}",
            if self.verified() {
                "VERIFIED FOR CAPTURE (lengths only; secrets not printed)"
            } else {
                "FAILED"
            }
        )?;
        Ok(())
    }
}

pub fn verify_from_path(path: impl AsRef<Path>) -> Result<FirstFrameReport, FirstFrameError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(FirstFrameError::FileNotFound(path.display().to_string()));
    }
    let text = std::fs::read_to_string(path).map_err(|_| FirstFrameError::Io)?;
    verify_from_json_str(&text)
}

pub fn verify_from_json_str(text: &str) -> Result<FirstFrameReport, FirstFrameError> {
    let file: FirstFrameFile = serde_json::from_str(text).map_err(|_| FirstFrameError::BadJson)?;

    let key = decode_hex("session_key_hex", &file.session_key_hex)?;
    if key.len() != KEY_LEN {
        return Err(FirstFrameError::BadFieldLen(
            "session_key_hex",
            key.len(),
            KEY_LEN,
        ));
    }
    let nonce = decode_hex("nonce_hex", &file.nonce_hex)?;
    if nonce.len() != NONCE_LEN {
        return Err(FirstFrameError::BadFieldLen(
            "nonce_hex",
            nonce.len(),
            NONCE_LEN,
        ));
    }
    let tag = decode_hex("tag_hex", &file.tag_hex)?;
    if tag.len() != TAG_LEN {
        return Err(FirstFrameError::BadFieldLen("tag_hex", tag.len(), TAG_LEN));
    }
    let ciphertext = decode_hex("ciphertext_hex", &file.ciphertext_hex)?;
    // ciphertext may be empty in theory; for 0x79 expect 6 — still allow any length

    let aad = if file.aad_hex.trim().is_empty() {
        Vec::new()
    } else {
        decode_hex("aad_hex", &file.aad_hex)?
    };

    let expected = file.expected_plaintext_len;
    let mut report = FirstFrameReport {
        key_length: key.len(),
        nonce_length: nonce.len(),
        ciphertext_length: ciphertext.len(),
        tag_length: tag.len(),
        aad_length: aad.len(),
        decrypt_ok: false,
        plaintext_length: None,
        expected_plaintext_length: expected,
        plaintext_length_matches_expected: false,
    };

    match crypto::decrypt_aes_gcm(&key, &nonce, &ciphertext, &tag, &aad) {
        Ok(plaintext) => {
            report.decrypt_ok = true;
            report.plaintext_length = Some(plaintext.len());
            report.plaintext_length_matches_expected = plaintext.len() == expected;
            // plaintext dropped
        }
        Err(CryptoError::DecryptFailed) => {
            report.decrypt_ok = false;
        }
        Err(e) => return Err(e.into()),
    }

    Ok(report)
}
