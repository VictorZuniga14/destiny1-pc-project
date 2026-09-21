//! Boundary tests for M4.10 SessionMaterialProvider.

use destiny1_network::bap_session::BapSession;
use destiny1_network::crypto::NonceDirection;
use destiny1_network::signon_boundary::{
    initialize_session_crypto_from_provider, OfflineSessionMaterialProvider, RealSignOnProvider,
    SessionMaterialProvider,
};
use destiny1_network::test_crypto_material::SYNTHETIC_TEST_ONLY_LABEL;

#[test]
fn synthetic_provider_feeds_session_crypto_and_bap() {
    let provider = OfflineSessionMaterialProvider;
    assert_eq!(provider.provider_kind(), SYNTHETIC_TEST_ONLY_LABEL);
    let material = provider.provide().unwrap();
    assert!(material.metadata().synthetic_test_only);
    assert_eq!(material.key_len(), 16);
    assert_eq!(material.nonce_len(), 12);

    let ctx = initialize_session_crypto_from_provider(&provider).unwrap();
    let mut session = BapSession::from_crypto(ctx);
    let frame = session
        .encode_encrypted(NonceDirection::ClientToServer, 0x79, 1, b"TEST")
        .unwrap();
    assert!(!frame.is_empty());
    // frame must not contain ASCII password/credential shaped strings
    let s = String::from_utf8_lossy(&frame);
    assert!(!s.contains("password"));
}

#[test]
fn real_provider_not_implemented() {
    let err = RealSignOnProvider.provide().unwrap_err();
    assert!(matches!(
        err,
        destiny1_network::signon_boundary::SignOnBoundaryError::RealProviderNotImplemented
    ));
}

#[test]
fn boundary_separates_http_from_bap() {
    // Provider API has no HTTP/SignOn types — only material for BAP.
    let provider = OfflineSessionMaterialProvider;
    let _ctx = initialize_session_crypto_from_provider(&provider).unwrap();
    assert_eq!(provider.provider_kind(), SYNTHETIC_TEST_ONLY_LABEL);
}
