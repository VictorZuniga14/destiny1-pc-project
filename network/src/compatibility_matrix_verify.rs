//! CLI verifier / report for M4.9 compatibility matrix.

use crate::compatibility_matrix::{
    compute_metrics, format_report, get_compatibility_matrix, matrix_from_json, matrix_to_json,
    validate_entry, validate_matrix, CompatibilityEntry, CompatibilityMatrix, CompatibilityScope,
    EvidenceStatus, ImplementationStatus, MatrixError, RealWorldClaim, VerificationStatus,
};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CompatibilityMatrixVerifyError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("fixture: {0}")]
    Fixture(String),
    #[error("verify failed: {0}")]
    Failed(String),
    #[error("{0}")]
    Matrix(#[from] MatrixError),
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/compatibility_matrix")
}

pub fn run_verify() -> Result<(), CompatibilityMatrixVerifyError> {
    run_verify_from_dir(fixture_dir())
}

pub fn run_verify_from_dir(dir: impl AsRef<Path>) -> Result<(), CompatibilityMatrixVerifyError> {
    let dir = dir.as_ref();
    let safe = dir.join("compatibility_matrix_safe.json");
    let negative = dir.join("compatibility_matrix_negative.json");
    println!(
        "COMPATIBILITY_MATRIX_VERIFY: start dir={}",
        dir.display()
    );

    // Canonical matrix
    let canonical = get_compatibility_matrix();
    validate_matrix(&canonical)?;

    // Ensure fixture directory + sync safe export from canonical (source of truth)
    std::fs::create_dir_all(dir).map_err(|e| CompatibilityMatrixVerifyError::Fixture(e.to_string()))?;
    let canonical_json =
        matrix_to_json(&canonical).map_err(CompatibilityMatrixVerifyError::Fixture)?;
    std::fs::write(&safe, &canonical_json)
        .map_err(|e| CompatibilityMatrixVerifyError::Fixture(e.to_string()))?;

    // Fixture must match canonical structure (same ids after load+validate)
    let fixture_text = std::fs::read_to_string(&safe)
        .map_err(|e| CompatibilityMatrixVerifyError::Fixture(e.to_string()))?;
    let fixture: CompatibilityMatrix = matrix_from_json(&fixture_text)
        .map_err(CompatibilityMatrixVerifyError::Fixture)?;
    validate_matrix(&fixture)?;

    if fixture.entries.len() != canonical.entries.len() {
        return Err(CompatibilityMatrixVerifyError::Failed(format!(
            "fixture entry count {} != canonical {}",
            fixture.entries.len(),
            canonical.entries.len()
        )));
    }
    let mut canon_ids: Vec<_> = canonical.entries.iter().map(|e| e.id.clone()).collect();
    let mut fix_ids: Vec<_> = fixture.entries.iter().map(|e| e.id.clone()).collect();
    canon_ids.sort();
    fix_ids.sort();
    if canon_ids != fix_ids {
        return Err(CompatibilityMatrixVerifyError::Failed(
            "fixture ids diverge from canonical matrix".into(),
        ));
    }

    // Determinism
    let a = get_compatibility_matrix();
    let b = get_compatibility_matrix();
    if a != b {
        return Err(CompatibilityMatrixVerifyError::Failed(
            "non-deterministic get_compatibility_matrix".into(),
        ));
    }

    // Negative fixture: each case must fail validation
    if negative.exists() {
        let neg_text = std::fs::read_to_string(&negative)
            .map_err(|e| CompatibilityMatrixVerifyError::Fixture(e.to_string()))?;
        let neg: serde_json::Value = serde_json::from_str(&neg_text)
            .map_err(|e| CompatibilityMatrixVerifyError::Fixture(e.to_string()))?;
        let cases = neg
            .get("invalid_entries")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                CompatibilityMatrixVerifyError::Fixture(
                    "negative fixture missing invalid_entries".into(),
                )
            })?;
        for (i, case) in cases.iter().enumerate() {
            let entry: CompatibilityEntry = serde_json::from_value(case.clone()).map_err(|e| {
                CompatibilityMatrixVerifyError::Fixture(format!("neg entry {i}: {e}"))
            })?;
            if validate_entry(&entry).is_ok() {
                return Err(CompatibilityMatrixVerifyError::Failed(format!(
                    "negative case {i} ({}) unexpectedly passed",
                    entry.id
                )));
            }
        }
    }

    let metrics = compute_metrics(&canonical);
    if metrics.real_client_verified != 0 {
        return Err(CompatibilityMatrixVerifyError::Failed(
            "real_client_verified must be 0".into(),
        ));
    }
    if metrics.real_server_verified != 0 {
        return Err(CompatibilityMatrixVerifyError::Failed(
            "real_server_verified must be 0".into(),
        ));
    }

    // Hard asserts on real-world claims
    for e in &canonical.entries {
        if e.real_client_compatibility != RealWorldClaim::NotProven {
            return Err(CompatibilityMatrixVerifyError::Failed(format!(
                "{} must be NOT_PROVEN for real client",
                e.id
            )));
        }
        if e.real_server_compatibility != RealWorldClaim::NotProven {
            return Err(CompatibilityMatrixVerifyError::Failed(format!(
                "{} must be NOT_PROVEN for real server",
                e.id
            )));
        }
        if e.verification == VerificationStatus::Verified
            && e.scopes.iter().any(|s| {
                matches!(
                    s,
                    CompatibilityScope::RealClient | CompatibilityScope::RealServer
                )
            })
        {
            return Err(CompatibilityMatrixVerifyError::Failed(format!(
                "{} VERIFIED with real scope",
                e.id
            )));
        }
        let _ = EvidenceStatus::Observed;
        let _ = ImplementationStatus::Implemented;
    }

    // Roundtrip JSON
    let json = matrix_to_json(&canonical).map_err(CompatibilityMatrixVerifyError::Fixture)?;
    let again = matrix_from_json(&json).map_err(CompatibilityMatrixVerifyError::Fixture)?;
    if again.entries.len() != canonical.entries.len() {
        return Err(CompatibilityMatrixVerifyError::Failed(
            "json roundtrip length mismatch".into(),
        ));
    }

    println!("entries: {}", metrics.entries);
    println!("confirmed: {}", metrics.confirmed);
    println!("observed: {}", metrics.observed);
    println!("structural: {}", metrics.structural);
    println!("hypothesis: {}", metrics.hypothesis);
    println!("implemented: {}", metrics.implemented);
    println!("verified: {}", metrics.verified);
    println!("blocked: {}", metrics.blocked);
    println!("unknown: {}", metrics.unknown);
    println!("offline_verified: {}", metrics.offline_verified);
    println!("real_client_verified: {}", metrics.real_client_verified);
    println!("real_server_verified: {}", metrics.real_server_verified);
    println!("COMPATIBILITY_MATRIX: VERIFIED");
    Ok(())
}

pub fn run_report() -> Result<(), CompatibilityMatrixVerifyError> {
    let matrix = get_compatibility_matrix();
    validate_matrix(&matrix)?;
    print!("{}", format_report(&matrix));
    Ok(())
}
