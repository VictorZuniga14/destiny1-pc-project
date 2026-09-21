//! Offline SignOn analyzer (M4.10).

use crate::signon::{
    SignOnEvidence, SignOnEvidenceClass, SignOnFieldClass, SignOnSessionMaterial,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignOnAnalysisReport {
    pub fields_observed: Vec<String>,
    pub secret_fields_present: u64,
    pub secret_values_stored: u64,
    pub session_material_structure: SignOnSessionMaterial,
    pub classification_counts: BTreeMap<String, u64>,
    pub unknown_fields: Vec<String>,
    pub evidence_sources: Vec<String>,
    pub limitations: Vec<String>,
    pub transport: String,
    pub path_observed: Option<String>,
    pub request_observed: bool,
    pub response_observed: bool,
    pub status_code: Option<u16>,
}

pub struct SignOnAnalyzer;

impl SignOnAnalyzer {
    pub fn analyze(evidence: &SignOnEvidence) -> SignOnAnalysisReport {
        let mut classification_counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut secret_fields_present = 0u64;
        let mut unknown_fields = Vec::new();
        let mut fields_observed = Vec::new();

        for f in &evidence.fields {
            *classification_counts
                .entry(f.evidence_status.as_str().into())
                .or_insert(0) += 1;
            if f.present || f.evidence_status != SignOnEvidenceClass::Unknown {
                fields_observed.push(f.name.clone());
            }
            if f.classification.is_secret() {
                secret_fields_present += 1;
            }
            if f.classification == SignOnFieldClass::Unknown
                || f.evidence_status == SignOnEvidenceClass::Unknown
            {
                if !unknown_fields.contains(&f.name) {
                    unknown_fields.push(f.name.clone());
                }
            }
        }
        fields_observed.sort();
        fields_observed.dedup();
        unknown_fields.sort();

        let session_material_structure = SignOnSessionMaterial::from_evidence_docs();

        let mut limitations = vec![
            "SignOn analysis is offline.".into(),
            "Real SignOn is not implemented.".into(),
            "No external authentication is performed.".into(),
            "No credentials are stored.".into(),
            "No session secrets are stored.".into(),
            "Session material values are never serialized.".into(),
            "Complete SignOn wire schema remains UNKNOWN.".into(),
            "Real-client compatibility remains unverified.".into(),
            "Real-server compatibility remains unverified.".into(),
        ];
        limitations.extend(evidence.notes.clone());

        SignOnAnalysisReport {
            fields_observed,
            secret_fields_present,
            secret_values_stored: 0, // invariant: never store values
            session_material_structure,
            classification_counts,
            unknown_fields,
            evidence_sources: vec![evidence.evidence_source.clone(), evidence.capture_id.clone()],
            limitations,
            transport: evidence.transport.clone(),
            path_observed: evidence.path_observed.clone(),
            request_observed: evidence.request_observed,
            response_observed: evidence.response_observed,
            status_code: evidence.status_code,
        }
    }
}

impl std::fmt::Display for SignOnAnalysisReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "SignOn Protocol")?;
        writeln!(f, "Transport: {}", self.transport)?;
        writeln!(f, "Evidence: OBSERVED/CONFIRMED (offline docs)")?;
        writeln!(f, "Real connection: NOT_IMPLEMENTED")?;
        if let Some(p) = &self.path_observed {
            writeln!(f, "Path observed: {p}")?;
        }
        writeln!(f)?;
        writeln!(f, "Session material:")?;
        let sm = &self.session_material_structure;
        writeln!(
            f,
            "  AES key: {} / VALUE NOT STORED",
            if sm.session_key_present {
                "PRESENT IN EVIDENCE"
            } else {
                "ABSENT"
            }
        )?;
        if let Some(n) = sm.session_key_length {
            writeln!(f, "  Key length: {n}")?;
        }
        writeln!(
            f,
            "  Nonce: {} / VALUE NOT STORED",
            if sm.session_nonce_present {
                "PRESENT IN EVIDENCE"
            } else {
                "ABSENT"
            }
        )?;
        if let Some(n) = sm.session_nonce_length {
            writeln!(f, "  Nonce length: {n}")?;
        }
        writeln!(
            f,
            "  MAC material: {} / VALUE NOT STORED",
            if sm.mac_key_present {
                "PRESENT IN EVIDENCE"
            } else {
                "ABSENT"
            }
        )?;
        writeln!(f)?;
        writeln!(f, "BAP integration:")?;
        writeln!(f, "  SessionCryptoContext: READY_FOR_PROVIDER")?;
        writeln!(f, "  Real SignOn provider: NOT_IMPLEMENTED")?;
        writeln!(f, "secret_values_stored: {}", self.secret_values_stored)?;
        Ok(())
    }
}
