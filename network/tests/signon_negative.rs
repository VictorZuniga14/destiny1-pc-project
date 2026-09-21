//! Negative / sensitive-data tests for M4.10 SignOn.

use destiny1_network::signon::{is_signon_sensitive_key, SignOnError, SignOnEvidence};
use destiny1_network::signon_boundary::{OfflineSessionMaterialProvider, SessionMaterialProvider};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/signon")
        .join(name)
}

#[test]
fn reject_sensitive_fixture() {
    let err = SignOnEvidence::from_path(fixture("signon_negative_sensitive.json")).unwrap_err();
    assert!(matches!(err, SignOnError::SensitiveValue(_)));
}

#[test]
fn reject_inline_token_value() {
    let json = r#"{
      "capture_id":"x","transport":"HTTPS","request_observed":true,"response_observed":true,
      "field_names":[],"field_lengths":{},"field_classifications":{},"fields":[],
      "evidence_source":"t","classification":"OBSERVED",
      "token":"abc123"
    }"#;
    assert!(matches!(
        SignOnEvidence::from_json_str(json),
        Err(SignOnError::SensitiveValue(_))
    ));
}

#[test]
fn reject_authorization_header_value() {
    let json = r#"{
      "capture_id":"x","transport":"HTTPS","request_observed":true,"response_observed":true,
      "field_names":[],"field_lengths":{},"field_classifications":{},"fields":[],
      "evidence_source":"t","classification":"OBSERVED",
      "authorization":"Bearer fake"
    }"#;
    assert!(SignOnEvidence::from_json_str(json).is_err());
}

#[test]
fn sensitive_key_helper() {
    assert!(is_signon_sensitive_key("session_key"));
    assert!(is_signon_sensitive_key("PASSWORD"));
    assert!(is_signon_sensitive_key("aes_key_hex"));
    assert!(!is_signon_sensitive_key("capture_id"));
    assert!(!is_signon_sensitive_key("transport"));
}

#[test]
fn no_external_http_in_modules() {
    let kind = OfflineSessionMaterialProvider.provider_kind();
    assert_eq!(kind, "SYNTHETIC_TEST_ONLY");
    assert!(!kind.to_lowercase().contains("http"));
}
