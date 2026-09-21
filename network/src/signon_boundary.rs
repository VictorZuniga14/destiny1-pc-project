//! Session material boundary between SignOn knowledge and BAP crypto (M4.10).
//!
//! Separates HOW material was obtained from HOW BAP uses it.
//! BAP must not know HTTP, cookies, OAuth, credentials, or SignOn endpoints.

use crate::crypto::session_context::{SessionContextError, SessionCryptoContext};
use crate::signon::{
    validate_session_material_metadata, SignOnError, SignOnSessionMaterial, EXPECTED_AES_KEY_LEN,
    EXPECTED_SESSION_NONCE_LEN,
};
use crate::test_crypto_material::{
    SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE, SYNTHETIC_TEST_ONLY_LABEL,
};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignOnBoundaryError {
    #[error("{0}")]
    SignOn(#[from] SignOnError),
    #[error("session context: {0}")]
    SessionContext(#[from] SessionContextError),
    #[error("provider: {0}")]
    Provider(String),
    #[error("real SignOn provider is NOT_IMPLEMENTED")]
    RealProviderNotImplemented,
}

/// In-memory material for BAP only. Never Serialize (no secret export).
#[derive(Clone)]
pub struct ProvidedSessionMaterial {
    key: [u8; EXPECTED_AES_KEY_LEN],
    nonce: [u8; EXPECTED_SESSION_NONCE_LEN],
    metadata: SignOnSessionMaterial,
}

impl std::fmt::Debug for ProvidedSessionMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProvidedSessionMaterial")
            .field("key_len", &self.key.len())
            .field("nonce_len", &self.nonce.len())
            .field("metadata", &self.metadata)
            .field("key", &"<redacted>")
            .field("nonce", &"<redacted>")
            .finish()
    }
}

impl ProvidedSessionMaterial {
    pub fn metadata(&self) -> &SignOnSessionMaterial {
        &self.metadata
    }

    pub fn key_len(&self) -> usize {
        self.key.len()
    }

    pub fn nonce_len(&self) -> usize {
        self.nonce.len()
    }

    /// Build `SessionCryptoContext` without exposing key/nonce via Display/Serialize.
    pub fn into_session_crypto_context(self) -> Result<SessionCryptoContext, SignOnBoundaryError> {
        Ok(SessionCryptoContext::new(&self.key, &self.nonce)?)
    }

    pub fn to_session_crypto_context(&self) -> Result<SessionCryptoContext, SignOnBoundaryError> {
        Ok(SessionCryptoContext::new(&self.key, &self.nonce)?)
    }
}

/// Abstraction: obtain validated session material for BAP without SignOn knowledge in BAP.
pub trait SessionMaterialProvider {
    fn provide(&self) -> Result<ProvidedSessionMaterial, SignOnBoundaryError>;
    fn provider_kind(&self) -> &'static str;
}

/// Offline synthetic provider for tests/harnesses. Marked SYNTHETIC_TEST_ONLY.
#[derive(Debug, Default, Clone, Copy)]
pub struct OfflineSessionMaterialProvider;

impl SessionMaterialProvider for OfflineSessionMaterialProvider {
    fn provide(&self) -> Result<ProvidedSessionMaterial, SignOnBoundaryError> {
        let metadata = SignOnSessionMaterial::synthetic_expected();
        validate_session_material_metadata(&metadata)?;
        Ok(ProvidedSessionMaterial {
            key: SYNTHETIC_SESSION_KEY,
            nonce: SYNTHETIC_SESSION_NONCE,
            metadata,
        })
    }

    fn provider_kind(&self) -> &'static str {
        SYNTHETIC_TEST_ONLY_LABEL
    }
}

/// Placeholder for a future legitimate provider — always refuses.
#[derive(Debug, Default, Clone, Copy)]
pub struct RealSignOnProvider;

impl SessionMaterialProvider for RealSignOnProvider {
    fn provide(&self) -> Result<ProvidedSessionMaterial, SignOnBoundaryError> {
        Err(SignOnBoundaryError::RealProviderNotImplemented)
    }

    fn provider_kind(&self) -> &'static str {
        "REAL_SIGNON_NOT_IMPLEMENTED"
    }
}

/// Feed BAP from any provider (offline path used in tests).
pub fn initialize_session_crypto_from_provider<P: SessionMaterialProvider>(
    provider: &P,
) -> Result<SessionCryptoContext, SignOnBoundaryError> {
    let material = provider.provide()?;
    if provider.provider_kind() == SYNTHETIC_TEST_ONLY_LABEL
        && !material.metadata().synthetic_test_only
    {
        return Err(SignOnBoundaryError::Provider(
            "synthetic provider must mark SYNTHETIC_TEST_ONLY".into(),
        ));
    }
    material.into_session_crypto_context()
}
