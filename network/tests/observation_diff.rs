//! Diff engine tests for M4.8.

use destiny1_network::observation_analyze::ObservationAnalyzer;
use destiny1_network::observation_diff::{
    diff_directions, diff_id_sequences, diff_lengths, DiffCategory,
};
use destiny1_network::observation_scenarios::scenario_startup;
use destiny1_network::observation_trace::ObservationTrace;
use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/observation")
        .join(name)
}

#[test]
fn missing_and_additional_frames() {
    let expected = vec![0x1E, 0x1F, 0x19];
    let observed = vec![0x1E, 0x1F, 0x19, 0x1A];
    let d = diff_id_sequences(&expected, &observed);
    assert!(d
        .entries
        .iter()
        .any(|e| e.category == DiffCategory::UnexpectedFrame));
    let summary = d.format_summary();
    assert!(summary.contains("EXPECTED:"));
    assert!(summary.contains("OBSERVED:"));
    assert!(summary.contains("DIFF:"));
}

#[test]
fn order_mismatch_transition() {
    let expected = vec![0xFA, 0xFB];
    let observed = vec![0xFA, 0x12E];
    let d = diff_id_sequences(&expected, &observed);
    assert!(!d.is_empty());
    assert!(d.format_summary().contains("0x00FA") || d.format_summary().contains("0xFA"));
}

#[test]
fn divergence_fixture() {
    let t = ObservationTrace::from_path(fixture("divergence_example.json")).unwrap();
    let d = ObservationAnalyzer::diff_startup(&t);
    // divergence has only first 5 of startup — missing frames after
    assert!(!d.is_empty());
}

#[test]
fn direction_mismatch() {
    let t = ObservationTrace::from_path(fixture("startup_observed.json")).unwrap();
    let expected_dirs = [(0x1E, "S2C")]; // wrong on purpose
    let diffs = diff_directions(&expected_dirs, &t);
    assert!(diffs
        .iter()
        .any(|e| e.category == DiffCategory::DirectionMismatch));
}

#[test]
fn length_mismatch() {
    let t = ObservationTrace::from_path(fixture("startup_observed.json")).unwrap();
    let diffs = diff_lengths(&[(0x1E, 999)], &t);
    assert!(diffs
        .iter()
        .any(|e| e.category == DiffCategory::LengthMismatch));
}

#[test]
fn matching_startup_no_diff() {
    let t = ObservationTrace::from_path(fixture("startup_expected.json")).unwrap();
    let d = diff_id_sequences(&scenario_startup().expected_ids, &t.message_id_sequence());
    assert!(d.is_empty());
}

#[test]
fn deterministic_diff() {
    let a = diff_id_sequences(&[0x1E, 0x1F], &[0x1E, 0xAB]);
    let b = diff_id_sequences(&[0x1E, 0x1F], &[0x1E, 0xAB]);
    assert_eq!(a, b);
}
