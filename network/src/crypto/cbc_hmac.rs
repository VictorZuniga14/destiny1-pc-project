//! Offline AES-CBC + HMAC-SHA256 primitives for session-record experiments.
//!
//! Isolated from [`crate::crypto::aead`] (AES-GCM). Not a full Destiny
//! `SessionCryptoContext` and not network-facing.
//!
//! ## HMAC input hypothesis (from kallsyms/d1-re)
//!
//! ```text
//! Fuente: kallsyms/d1-re/tools/ps3_decrypt_capture.py
//! función/script: decrypt_bap_session_record
//! ```
//!
//! The public decryptor authenticates:
//!
//! ```text
//! HMAC-SHA256(key,  record_len_be(4) || iv(16) || ciphertext )
//! ```
//!
//! i.e. `material[0 .. 20 + cipher_len]` where `material = record_len_be || iv || ciphertext || tag`.
//!
//! That choice is exposed explicitly via [`HmacMessageKind::LengthIvCiphertext`].
//! Do not treat other message compositions as verified for Destiny unless tested.

use aes::cipher::{
    block_padding::{NoPadding, Pkcs7},
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type HmacSha256 = Hmac<Sha256>;

pub const AES128_KEY_LEN: usize = 16;
pub const IV_LEN: usize = 16;
pub const HMAC_SHA256_LEN: usize = 32;
pub const SESSION_NONCE_LEN: usize = 12;
pub const SESSION_KEY_LEN: usize = 16;
/// Minimum plaintext bytes d1-re reads for nonce+key (`0x1C`).
pub const MIN_SESSION_PLAINTEXT: usize = SESSION_NONCE_LEN + SESSION_KEY_LEN;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CbcHmacError {
    #[error("AES key must be {AES128_KEY_LEN} bytes, got {0}")]
    BadAesKeyLength(usize),
    #[error("IV must be {IV_LEN} bytes, got {0}")]
    BadIvLength(usize),
    #[error("HMAC tag must be {HMAC_SHA256_LEN} bytes, got {0}")]
    BadHmacLength(usize),
    #[error("HMAC key must be non-empty")]
    EmptyHmacKey,
    #[error("ciphertext length must be a positive multiple of 16, got {0}")]
    BadCiphertextLength(usize),
    #[error("AES-CBC decrypt failed")]
    DecryptFailed,
    #[error("PKCS#7 padding invalid")]
    InvalidPadding,
}

/// Which bytes are fed into HMAC-SHA256. Must be chosen explicitly by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HmacMessageKind {
    /// d1-re hypothesis: `u32_be(record_len) || iv || ciphertext`
    LengthIvCiphertext,
}

/// Build the HMAC message for the documented d1-re hypothesis.
pub fn build_hmac_message(
    kind: HmacMessageKind,
    record_len_be: u32,
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CbcHmacError> {
    if iv.len() != IV_LEN {
        return Err(CbcHmacError::BadIvLength(iv.len()));
    }
    match kind {
        HmacMessageKind::LengthIvCiphertext => {
            let mut msg = Vec::with_capacity(4 + IV_LEN + ciphertext.len());
            msg.extend_from_slice(&record_len_be.to_be_bytes());
            msg.extend_from_slice(iv);
            msg.extend_from_slice(ciphertext);
            Ok(msg)
        }
    }
}

/// Constant-time HMAC-SHA256 verify. Returns `true` iff tag matches.
pub fn verify_hmac_sha256(hmac_key: &[u8], message: &[u8], tag: &[u8]) -> Result<bool, CbcHmacError> {
    if hmac_key.is_empty() {
        return Err(CbcHmacError::EmptyHmacKey);
    }
    if tag.len() != HMAC_SHA256_LEN {
        return Err(CbcHmacError::BadHmacLength(tag.len()));
    }
    let mut mac = HmacSha256::new_from_slice(hmac_key).map_err(|_| CbcHmacError::EmptyHmacKey)?;
    mac.update(message);
    let computed = mac.finalize().into_bytes();
    Ok(bool::from(computed.ct_eq(tag)))
}

/// Compute HMAC-SHA256 (for synthetic tests only; avoid logging the output).
pub fn compute_hmac_sha256(hmac_key: &[u8], message: &[u8]) -> Result<[u8; HMAC_SHA256_LEN], CbcHmacError> {
    if hmac_key.is_empty() {
        return Err(CbcHmacError::EmptyHmacKey);
    }
    let mut mac = HmacSha256::new_from_slice(hmac_key).map_err(|_| CbcHmacError::EmptyHmacKey)?;
    mac.update(message);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_SHA256_LEN];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// AES-128-CBC encrypt with PKCS#7 (synthetic vectors / tests only).
pub fn encrypt_aes128_cbc_pkcs7(
    aes_key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CbcHmacError> {
    if aes_key.len() != AES128_KEY_LEN {
        return Err(CbcHmacError::BadAesKeyLength(aes_key.len()));
    }
    if iv.len() != IV_LEN {
        return Err(CbcHmacError::BadIvLength(iv.len()));
    }
    let encryptor =
        Aes128CbcEnc::new_from_slices(aes_key, iv).map_err(|_| CbcHmacError::DecryptFailed)?;
    Ok(encryptor.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

/// AES-128-CBC decrypt **without** stripping padding (matches d1-re hazmat path).
pub fn decrypt_aes128_cbc_raw(
    aes_key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CbcHmacError> {
    if aes_key.len() != AES128_KEY_LEN {
        return Err(CbcHmacError::BadAesKeyLength(aes_key.len()));
    }
    if iv.len() != IV_LEN {
        return Err(CbcHmacError::BadIvLength(iv.len()));
    }
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(CbcHmacError::BadCiphertextLength(ciphertext.len()));
    }
    let mut buf = ciphertext.to_vec();
    let decryptor =
        Aes128CbcDec::new_from_slices(aes_key, iv).map_err(|_| CbcHmacError::DecryptFailed)?;
    let pt = decryptor
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| CbcHmacError::DecryptFailed)?;
    Ok(pt.to_vec())
}

/// Validate PKCS#7 padding in-place semantics on already-decrypted plaintext.
pub fn validate_pkcs7(plaintext: &[u8]) -> Result<usize, CbcHmacError> {
    if plaintext.is_empty() {
        return Err(CbcHmacError::InvalidPadding);
    }
    let pad = plaintext[plaintext.len() - 1] as usize;
    if pad == 0 || pad > 16 || pad > plaintext.len() {
        return Err(CbcHmacError::InvalidPadding);
    }
    let start = plaintext.len() - pad;
    if plaintext[start..].iter().any(|&b| b as usize != pad) {
        return Err(CbcHmacError::InvalidPadding);
    }
    Ok(plaintext.len() - pad)
}

/// Safe report — no secret material in fields or Display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecordVerifyReport {
    pub hmac_message_kind: &'static str,
    pub hmac_valid: bool,
    pub decrypt_ok: bool,
    pub plaintext_len: Option<usize>,
    pub pkcs7_valid: Option<bool>,
    pub pkcs7_unpadded_len: Option<usize>,
    /// Length-only: raw/unpadded plaintext can hold a 12-byte nonce region.
    pub nonce_region_len_ok: bool,
    /// Length-only: raw/unpadded plaintext can hold nonce(12)+key(16).
    pub session_key_region_len_ok: bool,
    /// Candidate offset for nonce (d1-re: 0). Set only when length-compatible; not semantic proof.
    pub candidate_nonce_offset: Option<usize>,
    /// Candidate offset for session key (d1-re: 12). Set only when length-compatible.
    pub candidate_session_key_offset: Option<usize>,
    /// True iff unpadded (or raw) length ≥ 28 under d1-re layout hypothesis.
    pub structure_length_compatible: bool,
}

/// CLI / research classification for real verification (M2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyClass {
    /// HMAC + CBC + PKCS#7 + length-compatible structure.
    Verified,
    /// Crypto checks passed but structure length not compatible.
    Partial,
    /// HMAC failed, or decrypt/padding failed.
    Failed,
}

impl SessionRecordVerifyReport {
    pub fn classification(&self) -> VerifyClass {
        if !self.hmac_valid {
            return VerifyClass::Failed;
        }
        if !self.decrypt_ok || self.pkcs7_valid != Some(true) {
            return VerifyClass::Failed;
        }
        if self.structure_length_compatible {
            VerifyClass::Verified
        } else {
            VerifyClass::Partial
        }
    }

    /// True when classification is [`VerifyClass::Verified`].
    pub fn success(&self) -> bool {
        self.classification() == VerifyClass::Verified
    }
}

impl std::fmt::Display for VerifyClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verified => write!(f, "VERIFIED"),
            Self::Partial => write!(f, "PARTIAL"),
            Self::Failed => write!(f, "FAILED"),
        }
    }
}

impl std::fmt::Display for SessionRecordVerifyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "hmac_message_kind: {}", self.hmac_message_kind)?;
        writeln!(f, "hmac_valid: {}", self.hmac_valid)?;
        writeln!(
            f,
            "aes_cbc_decrypt: {}",
            if self.decrypt_ok {
                "success"
            } else if self.hmac_valid {
                "failed"
            } else {
                "n/a"
            }
        )?;
        match self.plaintext_len {
            Some(n) => writeln!(f, "plaintext_length: {n}")?,
            None => writeln!(f, "plaintext_length: n/a")?,
        }
        match self.pkcs7_valid {
            Some(true) => {
                writeln!(f, "padding_valid: true")?;
                if let Some(n) = self.pkcs7_unpadded_len {
                    writeln!(f, "pkcs7_unpadded_length: {n}")?;
                }
            }
            Some(false) => writeln!(f, "padding_valid: false")?,
            None => writeln!(f, "padding_valid: n/a")?,
        }
        writeln!(f, "candidate_nonce_length: {SESSION_NONCE_LEN}")?;
        writeln!(f, "candidate_session_key_length: {SESSION_KEY_LEN}")?;
        match self.candidate_nonce_offset {
            Some(o) => writeln!(f, "candidate_nonce_offset: {o}")?,
            None => writeln!(f, "candidate_nonce_offset: n/a")?,
        }
        match self.candidate_session_key_offset {
            Some(o) => writeln!(f, "candidate_session_key_offset: {o}")?,
            None => writeln!(f, "candidate_session_key_offset: n/a")?,
        }
        writeln!(
            f,
            "structure_length_compatible: {}",
            self.structure_length_compatible
        )?;
        writeln!(
            f,
            "note: offsets/lengths are structural candidates only; not semantic proof"
        )?;
        writeln!(f, "result: {}", self.classification())?;
        Ok(())
    }
}

/// Verify session-record crypto offline. Plaintext stays in memory and is dropped.
///
/// Uses the caller-supplied [`HmacMessageKind`] exactly once — no automatic
/// alternative HMAC inputs and no HMAC-key truncation fallback.
pub fn verify_session_record(
    hmac_kind: HmacMessageKind,
    record_len_be: u32,
    iv: &[u8],
    ciphertext: &[u8],
    hmac_tag: &[u8],
    aes_key: &[u8],
    hmac_key: &[u8],
) -> Result<SessionRecordVerifyReport, CbcHmacError> {
    let kind_name = match hmac_kind {
        HmacMessageKind::LengthIvCiphertext => "LengthIvCiphertext (d1-re hypothesis)",
    };
    let message = build_hmac_message(hmac_kind, record_len_be, iv, ciphertext)?;
    let hmac_valid = verify_hmac_sha256(hmac_key, &message, hmac_tag)?;

    let mut report = SessionRecordVerifyReport {
        hmac_message_kind: kind_name,
        hmac_valid,
        decrypt_ok: false,
        plaintext_len: None,
        pkcs7_valid: None,
        pkcs7_unpadded_len: None,
        nonce_region_len_ok: false,
        session_key_region_len_ok: false,
        candidate_nonce_offset: None,
        candidate_session_key_offset: None,
        structure_length_compatible: false,
    };

    if !hmac_valid {
        return Ok(report);
    }

    match decrypt_aes128_cbc_raw(aes_key, iv, ciphertext) {
        Ok(plaintext) => {
            report.decrypt_ok = true;
            report.plaintext_len = Some(plaintext.len());
            match validate_pkcs7(&plaintext) {
                Ok(n) => {
                    report.pkcs7_valid = Some(true);
                    report.pkcs7_unpadded_len = Some(n);
                    report.nonce_region_len_ok = n >= SESSION_NONCE_LEN;
                    report.session_key_region_len_ok = n >= MIN_SESSION_PLAINTEXT;
                    report.structure_length_compatible = n >= MIN_SESSION_PLAINTEXT;
                    if report.structure_length_compatible {
                        // d1-re candidate layout only — length-backed, not semantic proof
                        report.candidate_nonce_offset = Some(0);
                        report.candidate_session_key_offset = Some(SESSION_NONCE_LEN);
                    }
                }
                Err(_) => {
                    report.pkcs7_valid = Some(false);
                }
            }
            // plaintext dropped here — never returned
        }
        Err(_) => {
            report.decrypt_ok = false;
        }
    }

    Ok(report)
}
