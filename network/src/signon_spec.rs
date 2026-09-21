//! Machine-readable SignOn protocol specification (M4.10).
//!
//! Only facts backed by existing project evidence. Unknown stays UNKNOWN.
//! No invented endpoints or field semantics.

use crate::signon::{
    SignOnEvidenceClass, SignOnField, SignOnFieldClass, SIGNON_PATH_OBSERVED,
    SIGNON_PLATFORM_QUERY_OBSERVED, EXPECTED_AES_KEY_LEN, EXPECTED_MAC_KEY_MIN_LEN,
    EXPECTED_SESSION_NONCE_LEN,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignOnTransportSpec {
    pub scheme: String,
    pub evidence_status: SignOnEvidenceClass,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignOnEndpointSpec {
    pub path: Option<String>,
    pub host: Option<String>,
    pub method: Option<String>,
    pub platform_query: Option<String>,
    pub evidence_status: SignOnEvidenceClass,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignOnMessageSpec {
    pub observed: bool,
    pub evidence_status: SignOnEvidenceClass,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignOnSessionMaterialSpec {
    pub aes_key_length: usize,
    pub session_nonce_length: usize,
    pub mac_key_min_length: usize,
    pub values_stored: bool,
    pub evidence_status: SignOnEvidenceClass,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignOnProtocolSpec {
    pub spec_version: String,
    pub transport: SignOnTransportSpec,
    pub endpoint: SignOnEndpointSpec,
    pub request: SignOnMessageSpec,
    pub response: SignOnMessageSpec,
    pub fields: Vec<SignOnField>,
    pub session_material: SignOnSessionMaterialSpec,
    pub evidence: Vec<String>,
    pub unknowns: Vec<String>,
}

pub fn get_signon_protocol_spec() -> SignOnProtocolSpec {
    SignOnProtocolSpec {
        spec_version: "0.1".into(),
        transport: SignOnTransportSpec {
            scheme: "HTTPS".into(),
            evidence_status: SignOnEvidenceClass::Confirmed,
            notes: vec![
                "TLS over TCP; MITM plaintext log used by d1-re decryptor workflow".into(),
                "This project does not perform TLS or HTTP.".into(),
            ],
        },
        endpoint: SignOnEndpointSpec {
            path: Some(SIGNON_PATH_OBSERVED.into()),
            host: None, // not reproduced; UNKNOWN for exact host in this repo
            method: Some("POST".into()),
            platform_query: Some(SIGNON_PLATFORM_QUERY_OBSERVED.into()),
            evidence_status: SignOnEvidenceClass::Confirmed,
            notes: vec![
                "Path /SignOn with platform=ps3_ppu CONFIRMED for PS3 evidence".into(),
                "Exact SignOn host not stored in this repo — UNKNOWN/omitted".into(),
                "No invented endpoints.".into(),
            ],
        },
        request: SignOnMessageSpec {
            observed: true,
            evidence_status: SignOnEvidenceClass::Observed,
            notes: vec!["Request observed in PS3 capture workflow; body schema UNKNOWN".into()],
        },
        response: SignOnMessageSpec {
            observed: true,
            evidence_status: SignOnEvidenceClass::Observed,
            notes: vec![
                "Response supplies AES/MAC token pairs and optional BAP endpoints".into(),
                "Wire schema (protobuf-like) not fully specified — UNKNOWN".into(),
            ],
        },
        fields: vec![
            SignOnField {
                name: "platform".into(),
                field_type: "query_string".into(),
                length: Some(SIGNON_PLATFORM_QUERY_OBSERVED.len()),
                classification: SignOnFieldClass::Identifier,
                required: true,
                evidence_status: SignOnEvidenceClass::Confirmed,
                present: true,
            },
            SignOnField {
                name: "build".into(),
                field_type: "query_string".into(),
                length: None,
                classification: SignOnFieldClass::Identifier,
                required: true,
                evidence_status: SignOnEvidenceClass::Observed,
                present: true,
            },
            SignOnField {
                name: "aes_key".into(),
                field_type: "bytes".into(),
                length: Some(EXPECTED_AES_KEY_LEN),
                classification: SignOnFieldClass::SecretMaterial,
                required: true,
                evidence_status: SignOnEvidenceClass::Confirmed,
                present: true,
            },
            SignOnField {
                name: "mac_key".into(),
                field_type: "bytes".into(),
                length: Some(EXPECTED_MAC_KEY_MIN_LEN),
                classification: SignOnFieldClass::SecretMaterial,
                required: true,
                evidence_status: SignOnEvidenceClass::Confirmed,
                present: true,
            },
            SignOnField {
                name: "bap_endpoints".into(),
                field_type: "ip_port_candidates".into(),
                length: None,
                classification: SignOnFieldClass::Public,
                required: false,
                evidence_status: SignOnEvidenceClass::Confirmed,
                present: true,
            },
        ],
        session_material: SignOnSessionMaterialSpec {
            aes_key_length: EXPECTED_AES_KEY_LEN,
            session_nonce_length: EXPECTED_SESSION_NONCE_LEN,
            mac_key_min_length: EXPECTED_MAC_KEY_MIN_LEN,
            values_stored: false,
            evidence_status: SignOnEvidenceClass::Confirmed,
            notes: vec![
                "AES key 16 B and MAC key from SignOn response (existence CONFIRMED)".into(),
                "Session key+nonce for GCM are derived after 0x1A decrypt — values not stored".into(),
                "Offline synthetic material uses SYNTHETIC_TEST_ONLY constants only".into(),
            ],
        },
        evidence: vec![
            "docs/networking/signon-https.md".into(),
            "docs/networking/session-crypto-key-material.md".into(),
            "capture:20260529-003132 (workflow reference)".into(),
            "kallsyms/d1-re collect_signon_secrets / derive_bap_session (external ref)".into(),
        ],
        unknowns: vec![
            "Complete SignOn request/response wire schema".into(),
            "Exhaustive field list and types".into(),
            "Platform auth tickets (PSN) byte layout".into(),
            "PS4/Xbox SignOn path/host/schema equivalence".into(),
            "Exact SignOn host for this repository (intentionally omitted)".into(),
            "MAC key length variant always used by Destiny".into(),
        ],
    }
}
