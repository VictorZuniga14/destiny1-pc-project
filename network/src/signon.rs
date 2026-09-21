//! Offline SignOn evidence model (M4.10).
//!
//! Metadata-only representation of SignOn HTTPS knowledge from project docs.
//! Never stores secret values. Never performs HTTP or live authentication.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

pub const SIGNON_PATH_OBSERVED: &str = "/SignOn";
pub const SIGNON_PLATFORM_QUERY_OBSERVED: &str = "ps3_ppu";
pub const EXPECTED_AES_KEY_LEN: usize = 16;
pub const EXPECTED_SESSION_NONCE_LEN: usize = 12;
pub const EXPECTED_MAC_KEY_MIN_LEN: usize = 16;

/// Field / material classification (no semantics invented from names alone).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignOnFieldClass {
    Public,
    Identifier,
    SessionSecret,
    AuthSecret,
    Unknown,
    /// Explicit secret material marker for evidence metadata.
    SecretMaterial,
}

impl SignOnFieldClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "PUBLIC",
            Self::Identifier => "IDENTIFIER",
            Self::SessionSecret => "SESSION_SECRET",
            Self::AuthSecret => "AUTH_SECRET",
            Self::Unknown => "UNKNOWN",
            Self::SecretMaterial => "SECRET_MATERIAL",
        }
    }

    pub fn is_secret(self) -> bool {
        matches!(
            self,
            Self::SessionSecret | Self::AuthSecret | Self::SecretMaterial
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SignOnEvidenceClass {
    Confirmed,
    Observed,
    Structural,
    Hypothesis,
    Unknown,
}

impl SignOnEvidenceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "CONFIRMED",
            Self::Observed => "OBSERVED",
            Self::Structural => "STRUCTURAL",
            Self::Hypothesis => "HYPOTHESIS",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Keys that must never carry values into the SignOn model.
pub const SIGNON_SENSITIVE_VALUE_KEYS: &[&str] = &[
    "token",
    "session_key",
    "session_key_hex",
    "mac_key",
    "mac_key_hex",
    "aes_key",
    "aes_key_hex",
    "hmac_key",
    "hmac_key_hex",
    "password",
    "authorization",
    "authorization_header",
    "cookie",
    "bearer",
    "bearer_token",
    "private_key",
    "credential",
    "credentials",
    "secret",
    "value",
    "value_hex",
    "body",
    "body_hex",
    "payload",
    "payload_hex",
];

pub fn is_signon_sensitive_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SIGNON_SENSITIVE_VALUE_KEYS.iter().any(|s| k == *s)
        || k.contains("password")
        || k.contains("credential")
        || k.ends_with("_hex") && (k.contains("key") || k.contains("token") || k.contains("secret"))
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SignOnError {
    #[error("sensitive value field rejected: {0}")]
    SensitiveValue(String),
    #[error("invalid session material: {0}")]
    InvalidMaterial(String),
    #[error("parse: {0}")]
    Parse(String),
    #[error("io: {0}")]
    Io(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignOnField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    pub length: Option<usize>,
    pub classification: SignOnFieldClass,
    pub required: bool,
    pub evidence_status: SignOnEvidenceClass,
    /// Safe presence flag only — never a secret value.
    #[serde(default)]
    pub present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignOnEvidence {
    pub capture_id: String,
    pub transport: String,
    pub request_observed: bool,
    pub response_observed: bool,
    pub status_code: Option<u16>,
    pub field_names: Vec<String>,
    pub field_lengths: BTreeMap<String, usize>,
    pub field_classifications: BTreeMap<String, SignOnFieldClass>,
    pub fields: Vec<SignOnField>,
    pub evidence_source: String,
    pub classification: SignOnEvidenceClass,
    #[serde(default)]
    pub notes: Vec<String>,
    /// Observed path when documented — never invented endpoints.
    #[serde(default)]
    pub path_observed: Option<String>,
    #[serde(default)]
    pub platform_query_observed: Option<String>,
}

impl SignOnEvidence {
    pub fn from_json_str(s: &str) -> Result<Self, SignOnError> {
        reject_sensitive_json(s)?;
        let mut ev: SignOnEvidence =
            serde_json::from_str(s).map_err(|e| SignOnError::Parse(e.to_string()))?;
        sanitize_evidence(&mut ev);
        Ok(ev)
    }

    pub fn from_path(path: impl AsRef<std::path::Path>) -> Result<Self, SignOnError> {
        let s = std::fs::read_to_string(path.as_ref()).map_err(|e| SignOnError::Io(e.to_string()))?;
        Self::from_json_str(&s)
    }
}

fn reject_sensitive_json(s: &str) -> Result<(), SignOnError> {
    let v: serde_json::Value =
        serde_json::from_str(s).map_err(|e| SignOnError::Parse(e.to_string()))?;
    walk_reject_sensitive(&v, "")
}

fn walk_reject_sensitive(v: &serde_json::Value, path: &str) -> Result<(), SignOnError> {
    match v {
        serde_json::Value::Object(map) => {
            // Map keys under these containers are field *names* (may look sensitive);
            // values are lengths/classifications — not secret payloads.
            let skip_key_value_check = path.ends_with("field_classifications")
                || path.ends_with("field_lengths")
                || path.ends_with("field_names");

            for (k, child) in map {
                if !skip_key_value_check && is_signon_sensitive_key(k) {
                    match child {
                        serde_json::Value::Null => {}
                        serde_json::Value::Object(meta) => {
                            for mk in meta.keys() {
                                let allowed = matches!(
                                    mk.as_str(),
                                    "present"
                                        | "length"
                                        | "classification"
                                        | "type"
                                        | "required"
                                        | "evidence_status"
                                        | "field_type"
                                );
                                if !allowed {
                                    return Err(SignOnError::SensitiveValue(format!(
                                        "{path}/{k}.{mk}"
                                    )));
                                }
                            }
                            if meta.contains_key("value")
                                || meta.contains_key("value_hex")
                                || meta.contains_key("hex")
                            {
                                return Err(SignOnError::SensitiveValue(format!(
                                    "{path}/{k} nested value"
                                )));
                            }
                        }
                        serde_json::Value::String(_)
                        | serde_json::Value::Number(_)
                        | serde_json::Value::Bool(_)
                        | serde_json::Value::Array(_) => {
                            return Err(SignOnError::SensitiveValue(format!("{path}/{k}")));
                        }
                    }
                }
                // Inside a field descriptor, reject explicit value carriers.
                if path.contains("/fields[") || path.ends_with("/fields") {
                    if matches!(k.as_str(), "value" | "value_hex" | "hex" | "bytes_hex") {
                        return Err(SignOnError::SensitiveValue(format!("{path}/{k}")));
                    }
                }
                walk_reject_sensitive(child, &format!("{path}/{k}"))?;
            }
            Ok(())
        }
        serde_json::Value::Array(arr) => {
            for (i, child) in arr.iter().enumerate() {
                walk_reject_sensitive(child, &format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn sanitize_evidence(ev: &mut SignOnEvidence) {
    // Drop any accidental value-shaped notes containing hex blobs is out of scope;
    // ensure classifications for known secret field names stay SECRET_MATERIAL.
    for f in &mut ev.fields {
        if is_signon_sensitive_key(&f.name) && !f.classification.is_secret() {
            f.classification = SignOnFieldClass::SecretMaterial;
        }
        f.present = f.present || f.length.is_some();
    }
}

/// Metadata-only session material for BAP handoff description.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignOnSessionMaterial {
    pub session_key_present: bool,
    pub session_key_length: Option<usize>,
    pub session_nonce_present: bool,
    pub session_nonce_length: Option<usize>,
    pub mac_key_present: bool,
    pub mac_key_length: Option<usize>,
    pub source: String,
    pub classification: SignOnEvidenceClass,
    /// Must be true for synthetic offline test material.
    #[serde(default)]
    pub synthetic_test_only: bool,
}

impl SignOnSessionMaterial {
    pub fn synthetic_expected() -> Self {
        Self {
            session_key_present: true,
            session_key_length: Some(EXPECTED_AES_KEY_LEN),
            session_nonce_present: true,
            session_nonce_length: Some(EXPECTED_SESSION_NONCE_LEN),
            mac_key_present: false,
            mac_key_length: None,
            source: crate::test_crypto_material::SYNTHETIC_TEST_ONLY_LABEL.into(),
            classification: SignOnEvidenceClass::Confirmed,
            synthetic_test_only: true,
        }
    }

    pub fn from_evidence_docs() -> Self {
        Self {
            session_key_present: true,
            session_key_length: Some(EXPECTED_AES_KEY_LEN),
            session_nonce_present: true,
            session_nonce_length: Some(EXPECTED_SESSION_NONCE_LEN),
            mac_key_present: true,
            mac_key_length: Some(EXPECTED_MAC_KEY_MIN_LEN),
            source: "offline_evidence_metadata".into(),
            classification: SignOnEvidenceClass::Confirmed,
            synthetic_test_only: false,
        }
    }
}

/// Validate metadata-only session material (no secret bytes).
pub fn validate_session_material_metadata(m: &SignOnSessionMaterial) -> Result<(), SignOnError> {
    if m.session_key_present {
        match m.session_key_length {
            Some(EXPECTED_AES_KEY_LEN) => {}
            Some(n) => {
                return Err(SignOnError::InvalidMaterial(format!(
                    "session_key_length must be {EXPECTED_AES_KEY_LEN}, got {n}"
                )));
            }
            None => {
                return Err(SignOnError::InvalidMaterial(
                    "session_key_present but length missing".into(),
                ));
            }
        }
    }
    if m.session_nonce_present {
        match m.session_nonce_length {
            Some(EXPECTED_SESSION_NONCE_LEN) => {}
            Some(n) => {
                return Err(SignOnError::InvalidMaterial(format!(
                    "session_nonce_length must be {EXPECTED_SESSION_NONCE_LEN}, got {n}"
                )));
            }
            None => {
                return Err(SignOnError::InvalidMaterial(
                    "session_nonce_present but length missing".into(),
                ));
            }
        }
    }
    if m.source.trim().is_empty() {
        return Err(SignOnError::InvalidMaterial("source required".into()));
    }
    if m.synthetic_test_only
        && m.source != crate::test_crypto_material::SYNTHETIC_TEST_ONLY_LABEL
    {
        return Err(SignOnError::InvalidMaterial(
            "synthetic material must declare SYNTHETIC_TEST_ONLY source".into(),
        ));
    }
    // Serialization safety: material struct has no secret value fields by design.
    let json = serde_json::to_string(m).map_err(|e| SignOnError::Parse(e.to_string()))?;
    if json.contains("session_key_hex")
        || json.contains("\"token\"")
        || json.contains("password")
    {
        return Err(SignOnError::SensitiveValue(
            "session material serialization leaked secret-shaped keys".into(),
        ));
    }
    Ok(())
}

/// Canonical offline evidence snapshot from documented project knowledge (no secrets).
pub fn canonical_signon_evidence() -> SignOnEvidence {
    let mut field_lengths = BTreeMap::new();
    field_lengths.insert("aes_key".into(), EXPECTED_AES_KEY_LEN);
    field_lengths.insert("mac_key".into(), EXPECTED_MAC_KEY_MIN_LEN);
    field_lengths.insert("platform".into(), SIGNON_PLATFORM_QUERY_OBSERVED.len());
    field_lengths.insert("build".into(), 0); // length unknown — structural presence only

    let mut field_classifications = BTreeMap::new();
    field_classifications.insert("aes_key".into(), SignOnFieldClass::SecretMaterial);
    field_classifications.insert("mac_key".into(), SignOnFieldClass::SecretMaterial);
    field_classifications.insert("platform".into(), SignOnFieldClass::Identifier);
    field_classifications.insert("build".into(), SignOnFieldClass::Identifier);
    field_classifications.insert("bap_endpoint_ip".into(), SignOnFieldClass::Public);
    field_classifications.insert("bap_endpoint_port".into(), SignOnFieldClass::Public);

    let fields = vec![
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
            name: "bap_endpoint_ip".into(),
            field_type: "varint_packed_ipv4".into(),
            length: None,
            classification: SignOnFieldClass::Public,
            required: false,
            evidence_status: SignOnEvidenceClass::Confirmed,
            present: true,
        },
        SignOnField {
            name: "bap_endpoint_port".into(),
            field_type: "varint".into(),
            length: None,
            classification: SignOnFieldClass::Public,
            required: false,
            evidence_status: SignOnEvidenceClass::Confirmed,
            present: true,
        },
        SignOnField {
            name: "response_wire_schema".into(),
            field_type: "unknown".into(),
            length: None,
            classification: SignOnFieldClass::Unknown,
            required: false,
            evidence_status: SignOnEvidenceClass::Unknown,
            present: false,
        },
    ];

    SignOnEvidence {
        capture_id: "20260529-003132".into(),
        transport: "HTTPS".into(),
        request_observed: true,
        response_observed: true,
        status_code: None, // not asserted in docs as a fixed CONFIRMED value
        field_names: fields.iter().map(|f| f.name.clone()).collect(),
        field_lengths,
        field_classifications,
        fields,
        evidence_source: "docs/networking/signon-https.md + d1-re workflow (offline)".into(),
        classification: SignOnEvidenceClass::Confirmed,
        notes: vec![
            "SignOn analysis is offline.".into(),
            "Real SignOn is not implemented.".into(),
            "No credentials or session secrets stored.".into(),
            "Host remains undocumented here; path /SignOn CONFIRMED for PS3 evidence.".into(),
        ],
        path_observed: Some(SIGNON_PATH_OBSERVED.into()),
        platform_query_observed: Some(SIGNON_PLATFORM_QUERY_OBSERVED.into()),
    }
}
