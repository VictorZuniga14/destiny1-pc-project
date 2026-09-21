//! Offline BAP session: framing + [`SessionCryptoContext`] + AES-GCM.
//!
//! No sockets / TCP / UDP. Bytes in → decoded frames out.
//!
//! ## Nonce consumption
//!
//! - `kind = 2` (clear): does **not** advance crypto counters.
//! - `kind = 1` (encrypted): after a structurally valid encrypted body is
//!   parsed, [`SessionCryptoContext::next_nonce`] is called for the given
//!   direction **before** GCM decrypt. On decrypt failure the counter is
//!   **not** rolled back (matches d1-re / M2.4d sequencing semantics).
//! - Other kinds: opaque body; no nonce consumption.

use crate::crypto::{
    decrypt_aes_gcm, encrypt_aes_gcm, CryptoError, NonceDirection, SessionContextError,
    SessionCryptoContext,
};
use crate::framing::{self, BapFrame, EncryptedBody, FrameBody, FramingError};
use thiserror::Error;

/// Wire / crypto direction for encrypted frames (required; never inferred).
pub use crate::crypto::NonceDirection as Direction;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BapSessionError {
    #[error("framing: {0}")]
    Framing(#[from] FramingError),
    #[error("session crypto: {0}")]
    Session(#[from] SessionContextError),
    #[error("AES-GCM decrypt failed")]
    DecryptFailed,
    #[error("AES-GCM encrypt failed")]
    EncryptFailed,
    #[error("encrypted frame has empty ciphertext")]
    EmptyCiphertext,
    #[error("unexpected trailing bytes after complete frame")]
    TrailingBytes,
}

/// Decoded offline frame (no secret material in Display).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedBapFrame {
    Clear {
        msg_id: u16,
        context: u32,
        payload: Vec<u8>,
    },
    /// GCM plaintext interpreted as clear layout when ≥ 6 bytes.
    Decrypted {
        msg_id: Option<u16>,
        context: Option<u32>,
        payload: Vec<u8>,
        plaintext_len: usize,
    },
    Opaque {
        kind: u8,
        body_len: usize,
    },
}

impl DecodedBapFrame {
    pub fn is_clear(&self) -> bool {
        matches!(self, Self::Clear { .. })
    }

    pub fn is_decrypted(&self) -> bool {
        matches!(self, Self::Decrypted { .. })
    }

    pub fn plaintext_len(&self) -> Option<usize> {
        match self {
            Self::Decrypted { plaintext_len, .. } => Some(*plaintext_len),
            Self::Clear { payload, .. } => Some(6 + payload.len()),
            Self::Opaque { .. } => None,
        }
    }
}

/// Offline BAP session bound to one [`SessionCryptoContext`].
pub struct BapSession {
    crypto: SessionCryptoContext,
}

impl BapSession {
    pub fn new(session_key: &[u8], session_nonce: &[u8]) -> Result<Self, BapSessionError> {
        Ok(Self {
            crypto: SessionCryptoContext::new(session_key, session_nonce)?,
        })
    }

    /// Construct from an existing [`SessionCryptoContext`] (e.g. session-material provider).
    pub fn from_crypto(crypto: SessionCryptoContext) -> Self {
        Self { crypto }
    }

    pub fn crypto(&self) -> &SessionCryptoContext {
        &self.crypto
    }

    pub fn client_to_server_counter(&self) -> u64 {
        self.crypto.client_to_server_counter()
    }

    pub fn server_to_client_counter(&self) -> u64 {
        self.crypto.server_to_client_counter()
    }

    /// Encode a clear (kind=2) frame. Does **not** advance crypto counters.
    pub fn encode_clear(msg_id: u16, context: u32, payload: &[u8]) -> Vec<u8> {
        clear_raw(msg_id, context, payload)
    }

    /// Encrypt plaintext clear-layout body and wrap as kind=1, consuming the
    /// next nonce for `direction` (same sequencing as decrypt).
    pub fn encode_encrypted(
        &mut self,
        direction: NonceDirection,
        msg_id: u16,
        context: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>, BapSessionError> {
        let mut plaintext = Vec::with_capacity(6 + payload.len());
        plaintext.extend_from_slice(&msg_id.to_be_bytes());
        plaintext.extend_from_slice(&context.to_be_bytes());
        plaintext.extend_from_slice(payload);
        let nonce = self.crypto.next_nonce(direction);
        let blob = encrypt_aes_gcm(self.crypto.session_key(), &nonce, &plaintext, &[])
            .map_err(|_| BapSessionError::EncryptFailed)?;
        Ok(encrypted_raw(blob.tag, &blob.ciphertext))
    }

    /// Parse one raw BAP frame and, if encrypted, decrypt with the next nonce
    /// for `direction`.
    pub fn decode_frame(
        &mut self,
        direction: NonceDirection,
        raw_frame: &[u8],
    ) -> Result<DecodedBapFrame, BapSessionError> {
        let (frame, consumed) = BapFrame::parse(raw_frame)?;
        if consumed != raw_frame.len() {
            return Err(BapSessionError::TrailingBytes);
        }
        self.decode_parsed(direction, frame)
    }

    /// Decode an already-parsed [`BapFrame`].
    pub fn decode_parsed(
        &mut self,
        direction: NonceDirection,
        frame: BapFrame,
    ) -> Result<DecodedBapFrame, BapSessionError> {
        match frame.body {
            FrameBody::Clear(c) => Ok(DecodedBapFrame::Clear {
                msg_id: c.msg_id,
                context: c.context,
                payload: c.payload,
            }),
            FrameBody::Encrypted(enc) => self.decode_encrypted(direction, enc),
            FrameBody::Opaque(body) => Ok(DecodedBapFrame::Opaque {
                kind: frame.kind.as_u8(),
                body_len: body.len(),
            }),
        }
    }

    fn decode_encrypted(
        &mut self,
        direction: NonceDirection,
        enc: EncryptedBody,
    ) -> Result<DecodedBapFrame, BapSessionError> {
        if enc.ciphertext.is_empty() {
            // Still consume nonce? Structurally valid kind=1 with tag only.
            // Empty ciphertext is unusual; reject without consuming nonce so
            // callers can fix input — treat as structural error before crypto.
            return Err(BapSessionError::EmptyCiphertext);
        }

        let nonce = self.crypto.next_nonce(direction);
        match decrypt_aes_gcm(
            self.crypto.session_key(),
            &nonce,
            &enc.ciphertext,
            &enc.tag,
            &[],
        ) {
            Ok(plaintext) => Ok(decode_plaintext(plaintext)),
            Err(CryptoError::DecryptFailed) => Err(BapSessionError::DecryptFailed),
            Err(CryptoError::BadKeyLength(_))
            | Err(CryptoError::BadNonceLength(_))
            | Err(CryptoError::BadTagLength(_))
            | Err(CryptoError::EncryptFailed) => Err(BapSessionError::DecryptFailed),
        }
    }
}

fn decode_plaintext(plaintext: Vec<u8>) -> DecodedBapFrame {
    let plaintext_len = plaintext.len();
    if plaintext_len >= 6 {
        let msg_id = u16::from_be_bytes(plaintext[0..2].try_into().unwrap());
        let context = u32::from_be_bytes(plaintext[2..6].try_into().unwrap());
        let payload = plaintext[6..].to_vec();
        DecodedBapFrame::Decrypted {
            msg_id: Some(msg_id),
            context: Some(context),
            payload,
            plaintext_len,
        }
    } else {
        DecodedBapFrame::Decrypted {
            msg_id: None,
            context: None,
            payload: plaintext,
            plaintext_len,
        }
    }
}

/// Re-export helpers for tests.
pub use framing::{clear_frame, encrypted_frame};

/// Build encrypted wire frame from tag+ciphertext (for fixtures).
pub fn encrypted_raw(tag: [u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    encrypted_frame(tag, ciphertext)
        .serialize()
        .expect("serialize encrypted")
}

pub fn clear_raw(msg_id: u16, context: u32, payload: &[u8]) -> Vec<u8> {
    clear_frame(msg_id, context, payload)
        .serialize()
        .expect("serialize clear")
}
