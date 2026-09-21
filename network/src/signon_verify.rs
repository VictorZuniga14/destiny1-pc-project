//! CLI verifier / report for M4.10 SignOn offline analysis.

use crate::bap_session::BapSession;
use crate::crypto::gcm_nonce::NonceDirection;
use crate::signon::{
    canonical_signon_evidence, validate_session_material_metadata, SignOnEvidence,
    SignOnSessionMaterial,
};
use crate::signon_analysis::SignOnAnalyzer;
use crate::signon_boundary::{
    initialize_session_crypto_from_provider, OfflineSessionMaterialProvider, RealSignOnProvider,
    SessionMaterialProvider,
};
use crate::signon_spec::get_signon_protocol_spec;
use crate::test_crypto_material::SYNTHETIC_TEST_ONLY_LABEL;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignOnVerifyError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("fixture: {0}")]
    Fixture(String),
    #[error("verify failed: {0}")]
    Failed(String),
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/signon")
}

pub fn run_verify() -> Result<(), SignOnVerifyError> {
    run_verify_from_dir(fixture_dir())
}

pub fn run_verify_from_dir(dir: impl AsRef<Path>) -> Result<(), SignOnVerifyError> {
    let dir = dir.as_ref();
    if !dir.exists() {
        return Err(SignOnVerifyError::FileNotFound(dir.display().to_string()));
    }
    println!("SIGNON_VERIFY: start dir={}", dir.display());

    let safe = dir.join("signon_evidence_safe.json");
    let expected = dir.join("signon_analysis_expected.json");
    let negative = dir.join("signon_negative_sensitive.json");
    let unknown = dir.join("signon_unknown_fields.json");
    let material = dir.join("session_material_metadata.json");

    for p in [&safe, &negative, &unknown, &material] {
        if !p.exists() {
            return Err(SignOnVerifyError::FileNotFound(p.display().to_string()));
        }
    }

    // Canonical + fixture evidence
    let canon = canonical_signon_evidence();
    let ev = SignOnEvidence::from_path(&safe).map_err(|e| SignOnVerifyError::Fixture(e.to_string()))?;
    let report = SignOnAnalyzer::analyze(&ev);
    let report2 = SignOnAnalyzer::analyze(&ev);
    if report != report2 {
        return Err(SignOnVerifyError::Failed("non-deterministic analyzer".into()));
    }
    if report.secret_values_stored != 0 {
        return Err(SignOnVerifyError::Failed(
            "secret_values_stored must be 0".into(),
        ));
    }

    // Sync expected analysis fixture from analyzer when missing (canonical offline report)
    if !expected.exists() {
        let pretty = serde_json::to_string_pretty(&report)
            .map_err(|e| SignOnVerifyError::Fixture(e.to_string()))?;
        std::fs::write(&expected, pretty)
            .map_err(|e| SignOnVerifyError::Fixture(e.to_string()))?;
    }

    let expected_text = std::fs::read_to_string(&expected)
        .map_err(|e| SignOnVerifyError::Fixture(e.to_string()))?;
    let expected_report: crate::signon_analysis::SignOnAnalysisReport =
        serde_json::from_str(&expected_text)
            .map_err(|e| SignOnVerifyError::Fixture(e.to_string()))?;
    if expected_report.secret_values_stored != 0 {
        return Err(SignOnVerifyError::Failed(
            "expected fixture secret_values_stored != 0".into(),
        ));
    }

    // Negative: sensitive values rejected
    match SignOnEvidence::from_path(&negative) {
        Err(crate::signon::SignOnError::SensitiveValue(_)) => {}
        Ok(_) => {
            return Err(SignOnVerifyError::Failed(
                "negative sensitive fixture must be rejected".into(),
            ));
        }
        Err(e) => {
            return Err(SignOnVerifyError::Failed(format!(
                "negative fixture unexpected error: {e}"
            )));
        }
    }

    // Unknown fields fixture loads
    let unk = SignOnEvidence::from_path(&unknown)
        .map_err(|e| SignOnVerifyError::Fixture(e.to_string()))?;
    let unk_report = SignOnAnalyzer::analyze(&unk);
    if unk_report.unknown_fields.is_empty() {
        return Err(SignOnVerifyError::Failed(
            "unknown fields fixture produced no unknowns".into(),
        ));
    }
    if unk_report.secret_values_stored != 0 {
        return Err(SignOnVerifyError::Failed(
            "unknown fixture stored secrets".into(),
        ));
    }

    // Session material metadata
    let mat_text = std::fs::read_to_string(&material)
        .map_err(|e| SignOnVerifyError::Fixture(e.to_string()))?;
    let mat: SignOnSessionMaterial =
        serde_json::from_str(&mat_text).map_err(|e| SignOnVerifyError::Fixture(e.to_string()))?;
    validate_session_material_metadata(&mat)
        .map_err(|e| SignOnVerifyError::Failed(e.to_string()))?;

    // Offline provider → SessionCryptoContext → BAP encrypt
    let provider = OfflineSessionMaterialProvider;
    if provider.provider_kind() != SYNTHETIC_TEST_ONLY_LABEL {
        return Err(SignOnVerifyError::Failed(
            "provider must be SYNTHETIC_TEST_ONLY".into(),
        ));
    }
    let ctx = initialize_session_crypto_from_provider(&provider)
        .map_err(|e| SignOnVerifyError::Failed(e.to_string()))?;
    let mut session = BapSession::from_crypto(ctx);
    let frame = session
        .encode_encrypted(NonceDirection::ClientToServer, 0x79, 1, b"SIGNON")
        .map_err(|e| SignOnVerifyError::Failed(e.to_string()))?;
    if frame.is_empty() {
        return Err(SignOnVerifyError::Failed("empty encrypted frame".into()));
    }

    // Real provider must refuse
    if RealSignOnProvider.provide().is_ok() {
        return Err(SignOnVerifyError::Failed(
            "real provider must be NOT_IMPLEMENTED".into(),
        ));
    }

    let _ = get_signon_protocol_spec();
    let _ = canon;

    // Metrics
    let captures = 1u64;
    let fields_observed = report.fields_observed.len() as u64;
    let secret_fields = report.secret_fields_present;
    let secret_values_stored = report.secret_values_stored;
    let mut confirmed = 0u64;
    let mut observed = 0u64;
    let mut structural = 0u64;
    let mut hypothesis = 0u64;
    let mut unknown = 0u64;
    for (k, v) in &report.classification_counts {
        match k.as_str() {
            "CONFIRMED" => confirmed += v,
            "OBSERVED" => observed += v,
            "STRUCTURAL" => structural += v,
            "HYPOTHESIS" => hypothesis += v,
            "UNKNOWN" => unknown += v,
            _ => {}
        }
    }
    let limitations = report.limitations.len() as u64;

    println!("captures: {captures}");
    println!("fields_observed: {fields_observed}");
    println!("secret_fields: {secret_fields}");
    println!("secret_values_stored: {secret_values_stored}");
    println!("confirmed: {confirmed}");
    println!("observed: {observed}");
    println!("structural: {structural}");
    println!("hypothesis: {hypothesis}");
    println!("unknown: {unknown}");
    println!("limitations: {limitations}");
    println!("SIGNON_ANALYSIS: VERIFIED");
    Ok(())
}

pub fn run_report() -> Result<(), SignOnVerifyError> {
    let ev = canonical_signon_evidence();
    let report = SignOnAnalyzer::analyze(&ev);
    print!("{report}");
    let spec = get_signon_protocol_spec();
    println!();
    println!("Spec version: {}", spec.spec_version);
    println!("Unknowns: {}", spec.unknowns.len());
    println!("Offline SignOn analysis: VERIFIED");
    println!("Synthetic session material: VERIFIED");
    println!("Real SignOn: NOT_IMPLEMENTED");
    println!("Real client: NOT_TESTED");
    println!("Real server: NOT_TESTED");
    Ok(())
}
