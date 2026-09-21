//! Unit tests for M4.8 observation harness.

use destiny1_network::observation::{ObservedFrame, SafeFingerprint};
use destiny1_network::observation_analyze::ObservationAnalyzer;
use destiny1_network::observation_trace::ObservationTrace;
use destiny1_network::protocol_observation::{classify_frame, ObservationClass};
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/observation")
        .join(name)
}

#[test]
fn empty_trace() {
    let t = ObservationTrace::new(vec![]);
    let r = ObservationAnalyzer::analyze_trace(&t);
    assert_eq!(r.total_frames, 0);
}

#[test]
fn valid_startup_trace() {
    let t = ObservationTrace::from_path(fixture("startup_observed.json")).unwrap();
    assert_eq!(t.message_id_sequence().len(), 8);
    let r = ObservationAnalyzer::analyze_trace(&t);
    assert_eq!(r.total_frames, 8);
    assert!(r.message_ids.iter().any(|s| s == "0x001E"));
}

#[test]
fn known_and_unknown_frames() {
    let t = ObservationTrace::from_path(fixture("unknown_message_observed.json")).unwrap();
    let r = ObservationAnalyzer::analyze_trace(&t);
    assert!(!r.unknown_frames.is_empty());
    let f = t.frames()[0];
    assert_eq!(classify_frame(f).class, ObservationClass::Unknown);
}

#[test]
fn fingerprint_stable_and_different() {
    let a = SafeFingerprint::from_bytes(b"abc");
    let b = SafeFingerprint::from_bytes(b"abc");
    let c = SafeFingerprint::from_bytes(b"abd");
    assert_eq!(a, b);
    assert_ne!(a, c);
}

#[test]
fn classification_confirmed_startup_id() {
    let f = ObservedFrame {
        connection_id: 1,
        frame_index: 0,
        direction: "C2S".into(),
        kind: 2,
        body_len: 6,
        message_id: Some(0x1E),
        protocol_state: None,
        relative_time_ms: None,
        fingerprint: None,
    };
    assert_eq!(classify_frame(&f).class, ObservationClass::Confirmed);
}

#[test]
fn classification_structural_without_id() {
    let f = ObservedFrame {
        connection_id: 1,
        frame_index: 0,
        direction: "C2S".into(),
        kind: 2,
        body_len: 6,
        message_id: None,
        protocol_state: None,
        relative_time_ms: None,
        fingerprint: None,
    };
    assert_eq!(classify_frame(&f).class, ObservationClass::Structural);
}

#[test]
fn classification_observed_registry_non_confirmed() {
    let f = ObservedFrame {
        connection_id: 1,
        frame_index: 0,
        direction: "C2S".into(),
        kind: 2,
        body_len: 2,
        message_id: Some(0x0A),
        protocol_state: None,
        relative_time_ms: None,
        fingerprint: None,
    };
    assert_eq!(classify_frame(&f).class, ObservationClass::Observed);
}

#[test]
fn classification_hypothesis_sequence() {
    use destiny1_network::observation_scenarios::ScenarioKind;
    use destiny1_network::protocol_observation::classify_sequence;
    // Registry IDs that diverge from confirmed startup → Hypothesis (not Confirmed).
    let ids = vec![0x0A, 0x0B, 0x0C];
    assert_eq!(
        classify_sequence(&ids, ScenarioKind::Startup),
        ObservationClass::Hypothesis
    );
}

#[test]
fn serialize_roundtrip() {
    let t = ObservationTrace::from_path(fixture("keepalive_observed.json")).unwrap();
    let json = t.to_json_pretty().unwrap();
    let t2 = ObservationTrace::from_json_str(&json).unwrap();
    assert_eq!(t.message_id_sequence(), t2.message_id_sequence());
}

#[test]
fn deterministic_analyze() {
    let t = ObservationTrace::from_path(fixture("startup_expected.json")).unwrap();
    let a = ObservationAnalyzer::analyze_trace(&t);
    let b = ObservationAnalyzer::analyze_trace(&t);
    assert_eq!(a.appearance_order, b.appearance_order);
    assert_eq!(a.classification_counts, b.classification_counts);
}
