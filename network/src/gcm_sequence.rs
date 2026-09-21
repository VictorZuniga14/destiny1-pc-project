//! Offline multi-frame AES-GCM sequence verify via [`SessionCryptoContext`].
//!
//! Uses [`crate::crypto::decrypt_aes_gcm`] unchanged. Never prints secret bytes.

use crate::crypto::{
    self, KEY_LEN, NONCE_LEN, TAG_LEN, CryptoError, NonceDirection, SessionCryptoContext,
    nonces_equal,
};
use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SequenceError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("failed to read input file")]
    Io,
    #[error("invalid JSON structure (expected gcm-sequence-verify object)")]
    BadJson,
    #[error("field '{0}' has invalid hex (length chars={1})")]
    BadHex(&'static str, usize),
    #[error("field '{0}' has unexpected byte length {1} (expected {2})")]
    BadFieldLen(&'static str, usize, usize),
    #[error("field '{0}' must be non-empty")]
    EmptyField(&'static str),
    #[error("unsupported direction '{0}'")]
    BadDirection(String),
    #[error("frames list must be non-empty")]
    EmptyFrames,
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),
    #[error("session context: {0}")]
    Context(#[from] crypto::SessionContextError),
    #[error("nonce: {0}")]
    Nonce(#[from] crypto::GcmNonceError),
}

#[derive(Debug, Deserialize)]
struct SequenceFile {
    session_key_hex: String,
    session_nonce_hex: String,
    #[serde(default)]
    aad_hex: String,
    frames: Vec<SequenceFrameFile>,
}

#[derive(Debug, Deserialize)]
struct SequenceFrameFile {
    id_hex: String,
    direction: String,
    #[serde(default)]
    frame_offset: Option<u64>,
    #[serde(default)]
    frame_order: Option<u64>,
    tag_hex: String,
    ciphertext_hex: String,
    #[serde(default)]
    expected_plaintext_len: Option<usize>,
    #[serde(default)]
    expected_nonce_hex: Option<String>,
}

fn decode_hex(field: &'static str, s: &str) -> Result<Vec<u8>, SequenceError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(SequenceError::EmptyField(field));
    }
    if t.len() % 2 != 0 {
        return Err(SequenceError::BadHex(field, t.len()));
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]).ok_or(SequenceError::BadHex(field, t.len()))?;
        let lo = hex_nibble(bytes[i + 1]).ok_or(SequenceError::BadHex(field, t.len()))?;
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

fn parse_direction(s: &str) -> Result<NonceDirection, SequenceError> {
    match s.trim() {
        "client_to_server" | "c2s" => Ok(NonceDirection::ClientToServer),
        "server_to_client" | "s2c" => Ok(NonceDirection::ServerToClient),
        other => Err(SequenceError::BadDirection(other.to_string())),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceFrameReport {
    pub id_hex: String,
    pub direction: &'static str,
    pub frame_offset: Option<u64>,
    pub frame_order: Option<u64>,
    pub tag_length: usize,
    pub ciphertext_length: usize,
    pub aad_length: usize,
    pub decrypt_ok: bool,
    pub plaintext_length: Option<usize>,
    pub plaintext_len_matches_expected: Option<bool>,
    pub nonce_matches_expected: Option<bool>,
    pub direction_enc_ordinal: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequenceReport {
    pub key_length: usize,
    pub session_nonce_length: usize,
    pub aad_length: usize,
    pub frames: Vec<SequenceFrameReport>,
    pub client_to_server_frames: u32,
    pub server_to_client_frames: u32,
    pub nonce_sequence_valid: bool,
    pub gcm_validation: bool,
}

impl SequenceReport {
    pub fn all_verified(&self) -> bool {
        self.nonce_sequence_valid && self.gcm_validation && !self.frames.is_empty()
    }
}

impl std::fmt::Display for SequenceReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "SESSION CRYPTO CONTEXT")?;
        writeln!(f, "frames_checked: {}", self.frames.len())?;
        writeln!(f, "client_to_server_frames: {}", self.client_to_server_frames)?;
        writeln!(f, "server_to_client_frames: {}", self.server_to_client_frames)?;
        writeln!(f, "nonce_sequence_valid: {}", self.nonce_sequence_valid)?;
        writeln!(f, "gcm_validation: {}", self.gcm_validation)?;
        writeln!(f, "key_length: {}", self.key_length)?;
        writeln!(f, "session_nonce_length: {}", self.session_nonce_length)?;
        writeln!(f, "aad_length: {}", self.aad_length)?;
        for (i, fr) in self.frames.iter().enumerate() {
            writeln!(f, "--- frame[{i}] ---")?;
            writeln!(f, "id_hex: {}", fr.id_hex)?;
            writeln!(f, "direction: {}", fr.direction)?;
            if let Some(o) = fr.frame_offset {
                writeln!(f, "frame_offset: {o}")?;
            }
            if let Some(o) = fr.frame_order {
                writeln!(f, "frame_order: {o}")?;
            }
            writeln!(f, "direction_enc_ordinal: {}", fr.direction_enc_ordinal)?;
            writeln!(f, "tag_length: {}", fr.tag_length)?;
            writeln!(f, "ciphertext_length: {}", fr.ciphertext_length)?;
            writeln!(
                f,
                "aes_gcm_decrypt: {}",
                if fr.decrypt_ok { "success" } else { "fail" }
            )?;
            match fr.plaintext_length {
                Some(n) => writeln!(f, "plaintext_length: {n}")?,
                None => writeln!(f, "plaintext_length: n/a")?,
            }
            match fr.plaintext_len_matches_expected {
                Some(v) => writeln!(f, "plaintext_len_matches_expected: {v}")?,
                None => writeln!(f, "plaintext_len_matches_expected: n/a")?,
            }
            match fr.nonce_matches_expected {
                Some(v) => writeln!(f, "nonce_matches_expected: {v}")?,
                None => writeln!(f, "nonce_matches_expected: n/a")?,
            }
        }
        writeln!(
            f,
            "result: {}",
            if self.all_verified() {
                "VERIFIED"
            } else {
                "FAILED"
            }
        )?;
        Ok(())
    }
}

pub fn verify_from_path(path: impl AsRef<Path>) -> Result<SequenceReport, SequenceError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(SequenceError::FileNotFound(path.display().to_string()));
    }
    let text = std::fs::read_to_string(path).map_err(|_| SequenceError::Io)?;
    verify_from_json_str(&text)
}

pub fn verify_from_json_str(text: &str) -> Result<SequenceReport, SequenceError> {
    let file: SequenceFile = serde_json::from_str(text).map_err(|_| SequenceError::BadJson)?;
    if file.frames.is_empty() {
        return Err(SequenceError::EmptyFrames);
    }

    let key = decode_hex("session_key_hex", &file.session_key_hex)?;
    if key.len() != KEY_LEN {
        return Err(SequenceError::BadFieldLen(
            "session_key_hex",
            key.len(),
            KEY_LEN,
        ));
    }
    let session_nonce = decode_hex("session_nonce_hex", &file.session_nonce_hex)?;
    if session_nonce.len() != NONCE_LEN {
        return Err(SequenceError::BadFieldLen(
            "session_nonce_hex",
            session_nonce.len(),
            NONCE_LEN,
        ));
    }
    let aad = if file.aad_hex.trim().is_empty() {
        Vec::new()
    } else {
        decode_hex("aad_hex", &file.aad_hex)?
    };

    let mut ctx = SessionCryptoContext::new(&key, &session_nonce)?;
    let session_nonce_snapshot = *ctx.session_nonce();

    let mut frames = Vec::with_capacity(file.frames.len());
    let mut c2s = 0u32;
    let mut s2c = 0u32;
    let mut nonce_ok_all = true;
    let mut gcm_ok_all = true;

    for fr in &file.frames {
        let direction = parse_direction(&fr.direction)?;
        let tag = decode_hex("tag_hex", &fr.tag_hex)?;
        if tag.len() != TAG_LEN {
            return Err(SequenceError::BadFieldLen("tag_hex", tag.len(), TAG_LEN));
        }
        let ciphertext = decode_hex("ciphertext_hex", &fr.ciphertext_hex)?;

        let ord = match direction {
            NonceDirection::ClientToServer => c2s,
            NonceDirection::ServerToClient => s2c,
        };

        let nonce = ctx.next_nonce(direction);

        let nonce_matches = match &fr.expected_nonce_hex {
            Some(h) if !h.trim().is_empty() => {
                let exp = decode_hex("expected_nonce_hex", h)?;
                if exp.len() != NONCE_LEN {
                    return Err(SequenceError::BadFieldLen(
                        "expected_nonce_hex",
                        exp.len(),
                        NONCE_LEN,
                    ));
                }
                let m = nonces_equal(&nonce, &exp)?;
                if !m {
                    nonce_ok_all = false;
                }
                Some(m)
            }
            _ => None,
        };

        let mut report = SequenceFrameReport {
            id_hex: fr.id_hex.clone(),
            direction: match direction {
                NonceDirection::ClientToServer => "client_to_server",
                NonceDirection::ServerToClient => "server_to_client",
            },
            frame_offset: fr.frame_offset,
            frame_order: fr.frame_order,
            tag_length: tag.len(),
            ciphertext_length: ciphertext.len(),
            aad_length: aad.len(),
            decrypt_ok: false,
            plaintext_length: None,
            plaintext_len_matches_expected: fr.expected_plaintext_len.map(|_| false),
            nonce_matches_expected: nonce_matches,
            direction_enc_ordinal: ord,
        };

        match crypto::decrypt_aes_gcm(ctx.session_key(), &nonce, &ciphertext, &tag, &aad) {
            Ok(plaintext) => {
                report.decrypt_ok = true;
                report.plaintext_length = Some(plaintext.len());
                if let Some(exp) = fr.expected_plaintext_len {
                    let ok = plaintext.len() == exp;
                    report.plaintext_len_matches_expected = Some(ok);
                    if !ok {
                        gcm_ok_all = false;
                    }
                }
            }
            Err(CryptoError::DecryptFailed) => {
                report.decrypt_ok = false;
                gcm_ok_all = false;
            }
            Err(e) => return Err(e.into()),
        }

        if !report.decrypt_ok {
            gcm_ok_all = false;
        }

        match direction {
            NonceDirection::ClientToServer => c2s += 1,
            NonceDirection::ServerToClient => s2c += 1,
        }

        frames.push(report);
    }

    // Base session nonce must remain intact after the sequence.
    if ctx.session_nonce() != &session_nonce_snapshot {
        nonce_ok_all = false;
    }

    Ok(SequenceReport {
        key_length: key.len(),
        session_nonce_length: session_nonce.len(),
        aad_length: aad.len(),
        frames,
        client_to_server_frames: c2s,
        server_to_client_frames: s2c,
        nonce_sequence_valid: nonce_ok_all,
        gcm_validation: gcm_ok_all,
    })
}
