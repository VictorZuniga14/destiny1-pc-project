//! Offline cryptographic primitives.
//!
//! These helpers are for synthetic fixtures and local research only.
//! They are **not** a Destiny session/crypto protocol implementation.
//!
//! - [`aead`]: AES-128-GCM (synthetic / BAP kind=1 experiments)
//! - [`cbc_hmac`]: AES-128-CBC + HMAC-SHA256 (session-record / `0x1A` experiments)
//! - [`gcm_nonce`]: first-frame GCM nonce transforms + increment
//! - [`session_context`]: per-direction nonce state for a session

pub mod aead;
pub mod cbc_hmac;
pub mod gcm_nonce;
pub mod session_context;

pub use aead::{
    AesGcmBlob, KEY_LEN, NONCE_LEN, TAG_LEN, CryptoError, decrypt_aes_gcm, encrypt_aes_gcm,
};

pub use cbc_hmac::{
    AES128_KEY_LEN, HMAC_SHA256_LEN, IV_LEN, MIN_SESSION_PLAINTEXT, SESSION_KEY_LEN,
    SESSION_NONCE_LEN, CbcHmacError, HmacMessageKind, SessionRecordVerifyReport, VerifyClass,
    build_hmac_message, compute_hmac_sha256, decrypt_aes128_cbc_raw, encrypt_aes128_cbc_pkcs7,
    validate_pkcs7, verify_hmac_sha256, verify_session_record,
};

pub use gcm_nonce::{
    GCM_NONCE_LEN, GcmNonceError, NonceDirection, NonceReconstructReport, NonceTransform,
    apply_nonce_transform, default_transform_for, increment_nonce, initial_direction_nonce,
    nonces_equal, reconstruct_first_frame_nonce,
};

pub use session_context::{SessionContextError, SessionCryptoContext};
