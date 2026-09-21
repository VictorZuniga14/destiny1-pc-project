//! Minimal AES-GCM session crypto state (per-direction nonce counters).
//!
//! Formalizes rules CONFIRMED for capture `20260529-003132` (M2.4d):
//! - C→S base = `session_nonce` with last byte XOR `1`
//! - S→C base = `session_nonce` unchanged
//! - Independent counters; after each direction's frame, that direction's
//!   nonce advances via [`increment_nonce`]
//!
//! Does **not** open sockets, speak BAP framing, or claim universal Destiny rules.
//! Never prints key/nonce bytes via [`Display`].

use crate::crypto::aead::KEY_LEN;
use crate::crypto::gcm_nonce::{
    GCM_NONCE_LEN, NonceDirection, increment_nonce, initial_direction_nonce,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionContextError {
    #[error("session key must be {KEY_LEN} bytes, got {0}")]
    BadKeyLength(usize),
    #[error("session nonce must be {GCM_NONCE_LEN} bytes, got {0}")]
    BadNonceLength(usize),
}

/// Offline session AEAD state: one key, one base nonce, two direction counters.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionCryptoContext {
    session_key: [u8; KEY_LEN],
    /// Immutable base from `0x1A` plaintext `[0..12)` (M2.3).
    session_nonce: [u8; GCM_NONCE_LEN],
    /// Current C→S nonce (starts as XOR-last-1 base).
    client_to_server_nonce: [u8; GCM_NONCE_LEN],
    /// Current S→C nonce (starts as Identity base).
    server_to_client_nonce: [u8; GCM_NONCE_LEN],
    client_to_server_counter: u64,
    server_to_client_counter: u64,
}

impl SessionCryptoContext {
    /// Create context with both counters at 0 and direction bases applied.
    pub fn new(session_key: &[u8], session_nonce: &[u8]) -> Result<Self, SessionContextError> {
        if session_key.len() != KEY_LEN {
            return Err(SessionContextError::BadKeyLength(session_key.len()));
        }
        if session_nonce.len() != GCM_NONCE_LEN {
            return Err(SessionContextError::BadNonceLength(session_nonce.len()));
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(session_key);
        let mut sn = [0u8; GCM_NONCE_LEN];
        sn.copy_from_slice(session_nonce);

        let c2s = initial_direction_nonce(&sn, NonceDirection::ClientToServer)
            .map_err(|_| SessionContextError::BadNonceLength(session_nonce.len()))?;
        let s2c = initial_direction_nonce(&sn, NonceDirection::ServerToClient)
            .map_err(|_| SessionContextError::BadNonceLength(session_nonce.len()))?;

        Ok(Self {
            session_key: key,
            session_nonce: sn,
            client_to_server_nonce: c2s,
            server_to_client_nonce: s2c,
            client_to_server_counter: 0,
            server_to_client_counter: 0,
        })
    }

    pub fn session_key(&self) -> &[u8; KEY_LEN] {
        &self.session_key
    }

    /// Immutable session nonce base (never mutated by [`Self::next_nonce`]).
    pub fn session_nonce(&self) -> &[u8; GCM_NONCE_LEN] {
        &self.session_nonce
    }

    pub fn client_to_server_counter(&self) -> u64 {
        self.client_to_server_counter
    }

    pub fn server_to_client_counter(&self) -> u64 {
        self.server_to_client_counter
    }

    /// C→S base: copy of session nonce with last byte XOR 1 (does not mutate base).
    pub fn client_to_server_base(&self) -> [u8; GCM_NONCE_LEN] {
        initial_direction_nonce(&self.session_nonce, NonceDirection::ClientToServer)
            .expect("session_nonce length validated at construction")
    }

    /// S→C base: copy of session nonce (Identity).
    pub fn server_to_client_base(&self) -> [u8; GCM_NONCE_LEN] {
        initial_direction_nonce(&self.session_nonce, NonceDirection::ServerToClient)
            .expect("session_nonce length validated at construction")
    }

    /// Nonce for `counter` applications of [`increment_nonce`] starting from `base`.
    ///
    /// Documented progression (M2.4d): `counter=0` → base; `counter=1` → inc(base); …
    pub fn nonce_after_increments(base: &[u8; GCM_NONCE_LEN], counter: u64) -> [u8; GCM_NONCE_LEN] {
        let mut n = *base;
        for _ in 0..counter {
            increment_nonce(&mut n);
        }
        n
    }

    /// Return the current direction nonce, then advance only that direction's counter/nonce.
    pub fn next_nonce(&mut self, direction: NonceDirection) -> [u8; GCM_NONCE_LEN] {
        match direction {
            NonceDirection::ClientToServer => {
                let out = self.client_to_server_nonce;
                increment_nonce(&mut self.client_to_server_nonce);
                self.client_to_server_counter = self.client_to_server_counter.saturating_add(1);
                out
            }
            NonceDirection::ServerToClient => {
                let out = self.server_to_client_nonce;
                increment_nonce(&mut self.server_to_client_nonce);
                self.server_to_client_counter = self.server_to_client_counter.saturating_add(1);
                out
            }
        }
    }

    /// Peek current nonce without advancing (for tests / diagnostics).
    pub fn peek_nonce(&self, direction: NonceDirection) -> [u8; GCM_NONCE_LEN] {
        match direction {
            NonceDirection::ClientToServer => self.client_to_server_nonce,
            NonceDirection::ServerToClient => self.server_to_client_nonce,
        }
    }
}

impl std::fmt::Debug for SessionCryptoContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionCryptoContext")
            .field("session_key_len", &self.session_key.len())
            .field("session_nonce_len", &self.session_nonce.len())
            .field("client_to_server_counter", &self.client_to_server_counter)
            .field("server_to_client_counter", &self.server_to_client_counter)
            .finish_non_exhaustive()
    }
}

// Re-export direction for callers that import session context.
pub use crate::crypto::gcm_nonce::NonceDirection as Direction;
