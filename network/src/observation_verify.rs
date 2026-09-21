//! CLI verifier for M4.8 observation harness.

use crate::observation::{SafeFingerprint, ObservationEvent, ObservedFrame};
use crate::observation_analyze::ObservationAnalyzer;
use crate::observation_diff::diff_id_sequences;
use crate::observation_scenarios::{all_scenarios, scenario_startup};
use crate::observation_trace::ObservationTrace;
use crate::protocol_observation::{classify_frame, ObservationClass};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ObservationVerifyError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("fixture: {0}")]
    Fixture(String),
    #[error("verify failed: {0}")]
    Failed(String),
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/observation")
}

pub fn run_default() -> Result<(), ObservationVerifyError> {
    run_from_dir(fixture_dir())
}

pub fn run_from_dir(dir: impl AsRef<Path>) -> Result<(), ObservationVerifyError> {
    let dir = dir.as_ref();
    if !dir.exists() {
        return Err(ObservationVerifyError::FileNotFound(
            dir.display().to_string(),
        ));
    }

    println!("OBSERVATION_VERIFY: start dir={}", dir.display());

    let mut traces = 0u32;
    let mut frames = 0u64;
    let mut known_messages = 0u64;
    let mut unknown_messages = 0u64;
    let mut state_transitions = 0u64;
    let mut diffs = 0u64;
    let mut classification_counts: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();

    // Fingerprint stability
    let a = SafeFingerprint::from_bytes(b"SIM");
    let b = SafeFingerprint::from_bytes(b"SIM");
    let c = SafeFingerprint::from_bytes(b"SIM2");
    if a != b || a == c {
        return Err(ObservationVerifyError::Failed(
            "fingerprint stability".into(),
        ));
    }

    // Sensitive reject
    let bad = r#"{"frames":[{"connection_id":1,"frame_index":0,"direction":"C2S","kind":2,"body_len":1,"session_key":"dead"}]}"#;
    if ObservationTrace::from_json_str(bad).is_ok() {
        return Err(ObservationVerifyError::Failed(
            "sensitive field must be rejected".into(),
        ));
    }

    let files = [
        "startup_expected.json",
        "startup_observed.json",
        "keepalive_expected.json",
        "keepalive_observed.json",
        "unknown_message_observed.json",
        "divergence_example.json",
        "boundary_trace_safe.json",
    ];

    for name in files {
        let path = dir.join(name);
        if !path.exists() {
            return Err(ObservationVerifyError::FileNotFound(
                path.display().to_string(),
            ));
        }
        let trace = ObservationTrace::from_path(&path)
            .map_err(|e| ObservationVerifyError::Fixture(e.to_string()))?;
        traces += 1;
        let report = ObservationAnalyzer::analyze_trace(&trace);
        frames += report.total_frames;
        unknown_messages += report.unknown_frames.len() as u64;
        for id in &report.message_ids {
            if !report.unknown_frames.contains(id) {
                known_messages += 1;
            }
        }
        state_transitions += report.id_transitions.len() as u64;
        diffs += report.diffs.len() as u64;
        for (k, v) in report.classification_counts {
            *classification_counts.entry(k).or_insert(0) += v;
        }

        // Determinism
        let report2 = ObservationAnalyzer::analyze_trace(&trace);
        if report.appearance_order != report2.appearance_order {
            return Err(ObservationVerifyError::Failed(
                "non-deterministic report".into(),
            ));
        }
    }

    // Diff example: expected startup vs observed with extra non-registry ID
    let exp = scenario_startup().expected_ids;
    let obs = {
        let mut v = exp.clone();
        v.push(0xEE);
        v
    };
    let d = diff_id_sequences(&exp, &obs);
    if d.is_empty() {
        return Err(ObservationVerifyError::Failed(
            "expected divergence for 0xEE".into(),
        ));
    }
    diffs += d.entries.len() as u64;

    // Classification: non-registry ID stays Unknown (0xAB is registry-known)
    let unk = ObservedFrame {
        connection_id: 1,
        frame_index: 0,
        direction: "C2S".into(),
        kind: 2,
        body_len: 3,
        message_id: Some(0xEE),
        protocol_state: None,
        relative_time_ms: None,
        fingerprint: None,
    };
    let cl = classify_frame(&unk);
    if cl.class != ObservationClass::Unknown {
        return Err(ObservationVerifyError::Failed(
            "0xEE must remain Unknown".into(),
        ));
    }

    let _ = all_scenarios();
    let _ = ObservationEvent::ConnectionStarted { connection_id: 0 };

    println!("traces: {traces}");
    println!("frames: {frames}");
    println!("known_messages: {known_messages}");
    println!("unknown_messages: {unknown_messages}");
    println!("state_transitions: {state_transitions}");
    println!("diffs: {diffs}");
    println!("classification_counts:");
    for (k, v) in &classification_counts {
        println!("  {k}: {v}");
    }
    println!("OBSERVATION_VERIFY: VERIFIED");
    Ok(())
}

/// Diff CLI helper against two fixture paths.
pub fn run_diff(expected: &Path, observed: &Path) -> Result<(), ObservationVerifyError> {
    let exp = ObservationTrace::from_path(expected)
        .map_err(|e| ObservationVerifyError::Fixture(e.to_string()))?;
    let obs = ObservationTrace::from_path(observed)
        .map_err(|e| ObservationVerifyError::Fixture(e.to_string()))?;
    let d = diff_id_sequences(&exp.message_id_sequence(), &obs.message_id_sequence());
    println!("{}", d.format_summary());
    Ok(())
}
