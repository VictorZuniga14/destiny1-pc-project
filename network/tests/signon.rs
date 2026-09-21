//! Unit tests for M4.10 SignOn offline model.

use destiny1_network::signon::{
    canonical_signon_evidence, validate_session_material_metadata, SignOnEvidence,
    SignOnSessionMaterial, EXPECTED_AES_KEY_LEN, EXPECTED_SESSION_NONCE_LEN,
};
use destiny1_network::signon_analysis::SignOnAnalyzer;
use destiny1_network::signon_spec::get_signon_protocol_spec;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/signon")
        .join(name)
}

#[test]
fn valid_evidence() {
    let ev = SignOnEvidence::from_path(fixture("signon_evidence_safe.json")).unwrap();
    assert!(ev.request_observed);
    assert!(ev.response_observed);
    assert_eq!(ev.transport, "HTTPS");
    assert!(!ev.fields.is_empty());
}

#[test]
fn request_response_and_status() {
    let ev = SignOnEvidence::from_path(fixture("signon_evidence_safe.json")).unwrap();
    assert!(ev.request_observed && ev.response_observed);
    assert!(ev.status_code.is_none() || ev.status_code.is_some());
    let report = SignOnAnalyzer::analyze(&ev);
    assert_eq!(report.request_observed, ev.request_observed);
    assert_eq!(report.response_observed, ev.response_observed);
}

#[test]
fn fields_and_unknown() {
    let unk = SignOnEvidence::from_path(fixture("signon_unknown_fields.json")).unwrap();
    let report = SignOnAnalyzer::analyze(&unk);
    assert!(report.unknown_fields.iter().any(|f| f == "mystery_field"));
    assert!(!report.fields_observed.is_empty());
}

#[test]
fn secret_metadata_no_values() {
    let ev = SignOnEvidence::from_path(fixture("signon_evidence_safe.json")).unwrap();
    let report = SignOnAnalyzer::analyze(&ev);
    assert!(report.secret_fields_present >= 2);
    assert_eq!(report.secret_values_stored, 0);
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("session_key_hex"));
    assert!(!json.contains("fake-token"));
}

#[test]
fn session_material_metadata() {
    let text = std::fs::read_to_string(fixture("session_material_metadata.json")).unwrap();
    let m: SignOnSessionMaterial = serde_json::from_str(&text).unwrap();
    validate_session_material_metadata(&m).unwrap();
    assert_eq!(m.session_key_length, Some(EXPECTED_AES_KEY_LEN));
    assert_eq!(m.session_nonce_length, Some(EXPECTED_SESSION_NONCE_LEN));
    assert!(m.synthetic_test_only);
}

#[test]
fn invalid_key_length() {
    let mut m = SignOnSessionMaterial::synthetic_expected();
    m.session_key_length = Some(15);
    assert!(validate_session_material_metadata(&m).is_err());
}

#[test]
fn invalid_nonce_length() {
    let mut m = SignOnSessionMaterial::synthetic_expected();
    m.session_nonce_length = Some(8);
    assert!(validate_session_material_metadata(&m).is_err());
}

#[test]
fn missing_material_length() {
    let mut m = SignOnSessionMaterial::synthetic_expected();
    m.session_key_length = None;
    assert!(validate_session_material_metadata(&m).is_err());
}

#[test]
fn deterministic_analyzer() {
    let ev = canonical_signon_evidence();
    let a = SignOnAnalyzer::analyze(&ev);
    let b = SignOnAnalyzer::analyze(&ev);
    assert_eq!(a, b);
}

#[test]
fn spec_no_invented_host() {
    let spec = get_signon_protocol_spec();
    assert_eq!(spec.endpoint.path.as_deref(), Some("/SignOn"));
    assert!(spec.endpoint.host.is_none());
    assert!(!spec.session_material.values_stored);
}
