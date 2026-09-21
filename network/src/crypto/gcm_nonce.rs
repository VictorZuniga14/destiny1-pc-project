//! Offline GCM nonce candidate transforms (session → first-frame).
//!
//! Isolated from AES-GCM encrypt/decrypt ([`crate::crypto::aead`]).
//! Does not decrypt frames, does not implement full nonce progression,
//! and never returns or logs nonce bytes via Display helpers.

use subtle::ConstantTimeEq;
use thiserror::Error;

/// AES-GCM nonce length used by the documented PS3 BAP path.
pub const GCM_NONCE_LEN: usize = 12;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum GcmNonceError {
    #[error("session nonce must be {GCM_NONCE_LEN} bytes, got {0}")]
    BadSessionNonceLength(usize),
    #[error("expected nonce must be {GCM_NONCE_LEN} bytes, got {0}")]
    BadExpectedNonceLength(usize),
}

/// Traffic direction for the candidate transform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceDirection {
    /// Server → client: EXTERNAL EVIDENCE uses session nonce as-is for the first S→C enc frame.
    ServerToClient,
    /// Client → server: EXTERNAL EVIDENCE XORs the last byte with 1 before the first C→S enc frame.
    ClientToServer,
}

/// Explicit transform applied to the session nonce candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceTransform {
    /// No change (server base).
    Identity,
    /// `nonce[len-1] ^= value` (client base uses `value = 1` in d1-re).
    XorLastByte(u8),
}

impl NonceTransform {
    pub fn name(self) -> &'static str {
        match self {
            Self::Identity => "Identity",
            Self::XorLastByte(1) => "XorLastByte(1)",
            Self::XorLastByte(_) => "XorLastByte(n)",
        }
    }
}

/// Default transform hypothesized for a direction (d1-re first-frame rule).
pub fn default_transform_for(direction: NonceDirection) -> NonceTransform {
    match direction {
        NonceDirection::ServerToClient => NonceTransform::Identity,
        NonceDirection::ClientToServer => NonceTransform::XorLastByte(1),
    }
}

/// Apply one explicit transform to a 12-byte session nonce candidate.
///
/// This does **not** by itself implement per-frame progression; see [`increment_nonce`].
pub fn apply_nonce_transform(
    session_nonce: &[u8],
    transform: NonceTransform,
) -> Result<[u8; GCM_NONCE_LEN], GcmNonceError> {
    if session_nonce.len() != GCM_NONCE_LEN {
        return Err(GcmNonceError::BadSessionNonceLength(session_nonce.len()));
    }
    let mut out = [0u8; GCM_NONCE_LEN];
    out.copy_from_slice(session_nonce);
    match transform {
        NonceTransform::Identity => {}
        NonceTransform::XorLastByte(v) => {
            out[GCM_NONCE_LEN - 1] ^= v;
        }
    }
    Ok(out)
}

/// Per-direction nonce increment used after each `kind=1` attempt (d1-re `increment_nonce`).
///
/// Increments from index 0 upward with wrap (little-endian style over the byte array).
/// EXTERNAL EVIDENCE as algorithm; CONFIRMED for capture sequences when decrypts succeed.
pub fn increment_nonce(nonce: &mut [u8; GCM_NONCE_LEN]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

/// Initial per-direction nonce state after session establishment (first-frame bases).
pub fn initial_direction_nonce(
    session_nonce: &[u8],
    direction: NonceDirection,
) -> Result<[u8; GCM_NONCE_LEN], GcmNonceError> {
    apply_nonce_transform(session_nonce, default_transform_for(direction))
}

/// Constant-time equality of two nonces.
pub fn nonces_equal(a: &[u8], b: &[u8]) -> Result<bool, GcmNonceError> {
    if a.len() != GCM_NONCE_LEN {
        return Err(GcmNonceError::BadSessionNonceLength(a.len()));
    }
    if b.len() != GCM_NONCE_LEN {
        return Err(GcmNonceError::BadExpectedNonceLength(b.len()));
    }
    Ok(bool::from(a.ct_eq(b)))
}

/// Safe report — lengths, transform name, match boolean only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonceReconstructReport {
    pub direction: &'static str,
    pub transform: &'static str,
    pub session_nonce_length: usize,
    pub derived_nonce_length: usize,
    pub matches_expected: Option<bool>,
}

impl std::fmt::Display for NonceReconstructReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "direction: {}", self.direction)?;
        writeln!(f, "transform: {}", self.transform)?;
        writeln!(f, "session_nonce_length: {}", self.session_nonce_length)?;
        writeln!(f, "derived_nonce_length: {}", self.derived_nonce_length)?;
        match self.matches_expected {
            Some(true) => writeln!(f, "matches_expected: true")?,
            Some(false) => writeln!(f, "matches_expected: false")?,
            None => writeln!(f, "matches_expected: n/a")?,
        }
        writeln!(
            f,
            "note: nonce bytes are never printed; first-frame only (no increment)"
        )?;
        Ok(())
    }
}

/// Deterministic first-frame nonce reconstruction check.
pub fn reconstruct_first_frame_nonce(
    session_nonce: &[u8],
    direction: NonceDirection,
    transform: NonceTransform,
    expected: Option<&[u8]>,
) -> Result<NonceReconstructReport, GcmNonceError> {
    let derived = apply_nonce_transform(session_nonce, transform)?;
    let matches = match expected {
        Some(exp) => Some(nonces_equal(&derived, exp)?),
        None => None,
    };
    let dir_name = match direction {
        NonceDirection::ClientToServer => "client_to_server",
        NonceDirection::ServerToClient => "server_to_client",
    };
    Ok(NonceReconstructReport {
        direction: dir_name,
        transform: transform.name(),
        session_nonce_length: session_nonce.len(),
        derived_nonce_length: derived.len(),
        matches_expected: matches,
    })
}
