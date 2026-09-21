//! Offline AES-GCM primitive (AES-128-GCM).
//!
//! This is a generic AEAD helper for synthetic fixtures. It does **not**
//! implement Destiny session key derivation, SignOn tokens, server/client
//! nonce XOR rules, or per-frame nonce increment.
//!
//! Callers supply `key`, `nonce`, and `aad` explicitly.
//!
//! For the real Destiny wire protocol, AAD remains **UNKNOWN** (research);
//! pass whatever AAD your experiment needs (often empty for synthetic tests).
//!
//! Wire layout used with BAP `kind=1` bodies (`docs/networking/framing-bap.md`):
//!
//! ```text
//! [tag:16][ciphertext...]
//! ```
//!
//! The `aes-gcm` crate returns `ciphertext || tag`; this module splits/joins
//! so the BAP tag stays at the front.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use thiserror::Error;

/// AES-128 key length (matches documented session key size in research notes).
pub const KEY_LEN: usize = 16;

/// Standard AES-GCM nonce length.
pub const NONCE_LEN: usize = 12;

/// AES-GCM authentication tag length / BAP encrypted-body tag prefix.
pub const TAG_LEN: usize = 16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("key must be {KEY_LEN} bytes, got {0}")]
    BadKeyLength(usize),
    #[error("nonce must be {NONCE_LEN} bytes, got {0}")]
    BadNonceLength(usize),
    #[error("tag must be {TAG_LEN} bytes, got {0}")]
    BadTagLength(usize),
    #[error("AES-GCM decrypt failed (auth/ciphertext/nonce/key mismatch)")]
    DecryptFailed,
    #[error("AES-GCM encrypt failed")]
    EncryptFailed,
}

/// Separated tag + ciphertext matching BAP `kind=1` body layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesGcmBlob {
    pub tag: [u8; TAG_LEN],
    pub ciphertext: Vec<u8>,
}

impl AesGcmBlob {
    /// Pack as `[tag:16][ciphertext...]`.
    pub fn to_body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TAG_LEN + self.ciphertext.len());
        out.extend_from_slice(&self.tag);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    /// Parse `[tag:16][ciphertext...]`.
    pub fn from_body_bytes(body: &[u8]) -> Result<Self, CryptoError> {
        if body.len() < TAG_LEN {
            return Err(CryptoError::BadTagLength(body.len()));
        }
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(&body[..TAG_LEN]);
        Ok(Self {
            tag,
            ciphertext: body[TAG_LEN..].to_vec(),
        })
    }
}

/// Encrypt `plaintext` with AES-128-GCM.
///
/// `aad` is caller-supplied additional authenticated data. For Destiny wire
/// behavior this value is research-owned / often empty in synthetic tests —
/// do not treat a chosen test AAD as protocol fact.
pub fn encrypt_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<AesGcmBlob, CryptoError> {
    let cipher = cipher_from_key(key)?;
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::BadNonceLength(nonce.len()));
    }
    let nonce = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let sealed = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::EncryptFailed)?;
    if sealed.len() < TAG_LEN {
        return Err(CryptoError::EncryptFailed);
    }
    let split = sealed.len() - TAG_LEN;
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&sealed[split..]);
    Ok(AesGcmBlob {
        tag,
        ciphertext: sealed[..split].to_vec(),
    })
}

/// Decrypt AES-128-GCM given an explicit tag and ciphertext (BAP order).
pub fn decrypt_aes_gcm(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if tag.len() != TAG_LEN {
        return Err(CryptoError::BadTagLength(tag.len()));
    }
    let cipher = cipher_from_key(key)?;
    if nonce.len() != NONCE_LEN {
        return Err(CryptoError::BadNonceLength(nonce.len()));
    }
    let nonce = Nonce::from_slice(nonce);
    // aes-gcm expects ciphertext || tag
    let mut sealed = Vec::with_capacity(ciphertext.len() + TAG_LEN);
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(tag);
    let payload = Payload {
        msg: &sealed,
        aad,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::DecryptFailed)
}

fn cipher_from_key(key: &[u8]) -> Result<Aes128Gcm, CryptoError> {
    if key.len() != KEY_LEN {
        return Err(CryptoError::BadKeyLength(key.len()));
    }
    Ok(Aes128Gcm::new_from_slice(key).expect("length checked"))
}
