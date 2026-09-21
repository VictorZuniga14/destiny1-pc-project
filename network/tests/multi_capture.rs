//! Multi-capture comparator + M2.9 status tests (synthetic + optional local evidence).

use destiny1_network::multi_capture::{
    compare_captures, CaptureValidationReport, InvariantClass, MultiCaptureStatus,
};
use destiny1_network::multi_capture_verify;
use std::path::PathBuf;

fn base_report(id: &str, independent: bool) -> CaptureValidationReport {
    CaptureValidationReport {
        capture_id: id.into(),
        independent,
        frames_seen: 128,
        clear_frames: 4,
        encrypted_frames: 124,
        decrypt_success: 124,
        decrypt_failed: 0,
        framing_valid: true,
        nonce_state_valid: true,
        gcm_validation: true,
        message_ids: vec![0x1e, 0x1f, 0x19, 0x1a, 0x79, 0x7a],
        startup_sequence: vec![0x1e, 0x1f, 0x19, 0x1a, 0x79, 0x7a],
        client_to_server_frames: 60,
        server_to_client_frames: 68,
        aad_empty_ok: Some(true),
        encrypted_frame_body_lengths: vec![22, 24],
        unknown_message_ids: vec![],
        keepalive_fa_count: 10,
        keepalive_fb_count: 10,
        session_record_cbc_hmac_ok: Some(true),
        c2s_nonce_xor_last1_ok: Some(true),
        s2c_nonce_identity_ok: Some(true),
    }
}

#[test]
fn missing_second_capture_is_ready_not_verified() {
    let r = base_report("20260529-003132", true);
    let summary = compare_captures(&[r]);
    assert_eq!(summary.status, MultiCaptureStatus::ReadyForExternalCapture);
    assert_ne!(summary.status, MultiCaptureStatus::VerifiedMultiCapture);
    assert_eq!(summary.independent_capture_count, 1);
    let framing = summary
        .invariants
        .iter()
        .find(|i| i.name.starts_with("BAP framing"))
        .unwrap();
    assert_eq!(framing.class, InvariantClass::Observed);
}

#[test]
fn identical_fixture_repeat_run_is_not_multi_capture_evidence() {
    // Two executions of the SAME capture — second marked independent=false.
    let a = base_report("20260529-003132", true);
    let mut b = base_report("20260529-003132", false);
    b.frames_seen = 128;
    let summary = compare_captures(&[a, b]);
    assert_eq!(summary.status, MultiCaptureStatus::ReadyForExternalCapture);
    assert_eq!(summary.independent_capture_count, 1);
}

#[test]
fn identical_ids_both_marked_independent_still_one_unique() {
    let a = base_report("20260529-003132", true);
    let b = base_report("20260529-003132", true);
    let summary = compare_captures(&[a, b]);
    // Collapsed by capture_id → still not multi-capture.
    assert_eq!(summary.status, MultiCaptureStatus::ReadyForExternalCapture);
    assert_eq!(summary.independent_capture_count, 1);
}

#[test]
fn divergent_synthetic_metadata_detected() {
    let a = base_report("cap-A", true);
    let mut b = base_report("cap-B", true);
    b.aad_empty_ok = Some(false);
    b.startup_sequence = vec![0x1e, 0x1f, 0x19, 0x1a];
    let summary = compare_captures(&[a, b]);
    let aad = summary
        .invariants
        .iter()
        .find(|i| i.name.starts_with("AAD"))
        .unwrap();
    assert_eq!(aad.class, InvariantClass::Divergent);
    let startup = summary
        .invariants
        .iter()
        .find(|i| i.name.starts_with("startup"))
        .unwrap();
    assert_eq!(startup.class, InvariantClass::Divergent);
}

#[test]
fn two_matching_independent_captures_can_be_stable() {
    let a = base_report("cap-A", true);
    let b = base_report("cap-B", true);
    let summary = compare_captures(&[a, b]);
    assert_eq!(summary.status, MultiCaptureStatus::VerifiedMultiCapture);
    let framing = summary
        .invariants
        .iter()
        .find(|i| i.name.starts_with("BAP framing"))
        .unwrap();
    assert_eq!(framing.class, InvariantClass::Stable);
    let gcm = summary
        .invariants
        .iter()
        .find(|i| i.name.starts_with("AES-GCM"))
        .unwrap();
    assert_eq!(gcm.class, InvariantClass::Stable);
}

#[test]
fn invariant_unknown_when_unmeasured() {
    let mut a = base_report("cap-A", true);
    a.aad_empty_ok = None;
    let summary = compare_captures(&[a]);
    let aad = summary
        .invariants
        .iter()
        .find(|i| i.name.starts_with("AAD"))
        .unwrap();
    assert_eq!(aad.class, InvariantClass::Unknown);
}

#[test]
fn keepalive_timing_always_unknown_in_comparator() {
    let summary = compare_captures(&[base_report("x", true)]);
    let timing = summary
        .invariants
        .iter()
        .find(|i| i.name.contains("timing"))
        .unwrap();
    assert_eq!(timing.class, InvariantClass::Unknown);
}

#[test]
fn real_capture_pipeline_fixture_when_present() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../evidence/local/bap_session_verify.json");
    if !path.exists() {
        return;
    }
    let report = multi_capture_verify::report_from_pipeline_fixture_path(&path, true).unwrap();
    assert_eq!(report.capture_id, "20260529-003132");
    assert_eq!(report.frames_seen, 128);
    assert_eq!(report.clear_frames, 4);
    assert_eq!(report.encrypted_frames, 124);
    assert_eq!(report.decrypt_success, 124);
    assert_eq!(report.decrypt_failed, 0);
    assert!(report.nonce_state_valid);
    assert!(report.gcm_validation);
    assert!(report.pipeline_ok());

    let summary = compare_captures(&[report]);
    assert_eq!(summary.status, MultiCaptureStatus::ReadyForExternalCapture);
    assert!(!summary.to_string().contains("session_key"));
}

#[test]
fn manifest_with_two_pipeline_fixtures_verified() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/multi_capture/manifest.json");
    let evidence_a = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../evidence/local/bap_session_verify.json");
    let evidence_b = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../evidence/local/bap_session_verify_20260608-231100.json");
    if !evidence_a.exists() || !evidence_b.exists() {
        return;
    }
    let summary = multi_capture_verify::verify_from_manifest_path(&path).unwrap();
    assert_eq!(summary.status, MultiCaptureStatus::VerifiedMultiCapture);
    assert_eq!(summary.independent_capture_count, 2);
    let framing = summary
        .invariants
        .iter()
        .find(|i| i.name.starts_with("BAP framing"))
        .unwrap();
    assert_eq!(framing.class, InvariantClass::Stable);
}
