//! Unit tests for M4.9 compatibility matrix.

use destiny1_network::compatibility_matrix::{
    compute_metrics, get_compatibility_matrix, refuse_promote_hypothesis_to_confirmed,
    refuse_promote_implemented_to_real_client, refuse_promote_local_tcp_to_real_server,
    refuse_promote_observed_to_implemented, validate_entry, validate_matrix, CompatibilityArea,
    CompatibilityEntry, CompatibilityScope, EvidenceStatus, ImplementationStatus, MatrixError,
    RealWorldClaim, VerificationStatus,
};
use destiny1_network::protocol_spec::EXPECTED_MESSAGE_IDS;

fn base_entry(id: &str) -> CompatibilityEntry {
    CompatibilityEntry {
        id: id.into(),
        area: CompatibilityArea::BapFraming,
        name: "test".into(),
        evidence: EvidenceStatus::Confirmed,
        implementation: ImplementationStatus::Implemented,
        verification: VerificationStatus::Verified,
        scopes: vec![CompatibilityScope::SyntheticLocal],
        evidence_refs: vec!["capture:20260529-003132".into()],
        verification_refs: vec!["unit-test".into()],
        dependencies: vec![],
        notes: vec![],
        blocking_reason: None,
        semantic_claim: None,
        real_client_compatibility: RealWorldClaim::NotProven,
        real_server_compatibility: RealWorldClaim::NotProven,
        message_id: None,
    }
}

#[test]
fn matrix_valid() {
    let m = get_compatibility_matrix();
    assert!(validate_matrix(&m).is_ok());
    assert!(m.entries.len() >= 20 + 28);
}

#[test]
fn all_28_message_ids_present() {
    let m = get_compatibility_matrix();
    let ids: std::collections::BTreeSet<_> =
        m.entries.iter().filter_map(|e| e.message_id).collect();
    for id in EXPECTED_MESSAGE_IDS {
        assert!(ids.contains(id), "missing 0x{id:04X}");
    }
    assert_eq!(ids.len(), 28);
}

#[test]
fn all_areas_present() {
    let m = get_compatibility_matrix();
    for a in CompatibilityArea::all() {
        assert!(
            m.entries.iter().any(|e| e.area == *a),
            "missing area {}",
            a.as_str()
        );
    }
}

#[test]
fn duplicate_id_fails() {
    let mut m = get_compatibility_matrix();
    m.entries.push(m.entries[0].clone());
    assert!(matches!(
        validate_matrix(&m),
        Err(MatrixError::DuplicateId(_))
    ));
}

#[test]
fn verified_without_evidence_fails() {
    let mut e = base_entry("bad_verified");
    e.verification_refs.clear();
    assert!(matches!(
        validate_entry(&e),
        Err(MatrixError::VerifiedWithoutEvidence(_))
    ));
}

#[test]
fn verified_real_client_fails() {
    let mut e = base_entry("bad_rc");
    e.scopes = vec![CompatibilityScope::RealClient];
    assert!(matches!(
        validate_entry(&e),
        Err(MatrixError::VerifiedRealClient(_))
    ));
}

#[test]
fn verified_real_server_fails() {
    let mut e = base_entry("bad_rs");
    e.scopes = vec![CompatibilityScope::RealServer];
    assert!(matches!(
        validate_entry(&e),
        Err(MatrixError::VerifiedRealServer(_))
    ));
}

#[test]
fn hypothesis_auto_promote_fails() {
    assert!(refuse_promote_hypothesis_to_confirmed(EvidenceStatus::Hypothesis).is_err());
}

#[test]
fn observed_auto_implemented_fails() {
    assert!(refuse_promote_observed_to_implemented(EvidenceStatus::Observed).is_err());
}

#[test]
fn implemented_auto_real_client_fails() {
    assert!(
        refuse_promote_implemented_to_real_client(ImplementationStatus::Implemented).is_err()
    );
}

#[test]
fn local_tcp_auto_real_server_fails() {
    assert!(refuse_promote_local_tcp_to_real_server(CompatibilityScope::LocalTcp).is_err());
}

#[test]
fn blocked_without_reason_fails() {
    let mut e = base_entry("blocked_no_reason");
    e.implementation = ImplementationStatus::Blocked;
    e.verification = VerificationStatus::NotVerified;
    e.blocking_reason = None;
    assert!(matches!(
        validate_entry(&e),
        Err(MatrixError::BlockedWithoutReason(_))
    ));
}

#[test]
fn unknown_with_invented_semantics_fails() {
    let mut e = base_entry("unk_sem");
    e.evidence = EvidenceStatus::Unknown;
    e.verification = VerificationStatus::NotVerified;
    e.verification_refs.clear();
    e.evidence_refs.clear();
    e.semantic_claim = Some("this is gameplay keepalive".into());
    assert!(matches!(
        validate_entry(&e),
        Err(MatrixError::UnknownWithSemantics(_))
    ));
}

#[test]
fn valid_multi_status_entry() {
    let e = base_entry("multi");
    assert_eq!(e.evidence, EvidenceStatus::Confirmed);
    assert_eq!(e.implementation, ImplementationStatus::Implemented);
    assert_eq!(e.verification, VerificationStatus::Verified);
    assert!(validate_entry(&e).is_ok());
}

#[test]
fn scope_valid() {
    let mut e = base_entry("scope_ok");
    e.scopes = vec![
        CompatibilityScope::OfflineCapture,
        CompatibilityScope::LocalTcp,
    ];
    assert!(validate_entry(&e).is_ok());
}

#[test]
fn scope_invalid_empty() {
    let mut e = base_entry("scope_empty");
    e.scopes.clear();
    assert!(matches!(
        validate_entry(&e),
        Err(MatrixError::ImpossibleScope(_))
    ));
}

#[test]
fn determinism() {
    let a = get_compatibility_matrix();
    let b = get_compatibility_matrix();
    assert_eq!(a, b);
    let ma = compute_metrics(&a);
    let mb = compute_metrics(&b);
    assert_eq!(ma, mb);
}

#[test]
fn real_client_server_verified_zero() {
    let m = get_compatibility_matrix();
    let metrics = compute_metrics(&m);
    assert_eq!(metrics.real_client_verified, 0);
    assert_eq!(metrics.real_server_verified, 0);
    for e in &m.entries {
        assert_eq!(e.real_client_compatibility, RealWorldClaim::NotProven);
        assert_eq!(e.real_server_compatibility, RealWorldClaim::NotProven);
    }
}

#[test]
fn confirmed_without_evidence_fails() {
    let mut e = base_entry("no_ev");
    e.evidence_refs.clear();
    assert!(matches!(
        validate_entry(&e),
        Err(MatrixError::ConfirmedWithoutEvidence(_))
    ));
}
