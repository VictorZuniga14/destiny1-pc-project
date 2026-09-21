//! Protocol Compatibility Test Matrix (M4.9).
//!
//! Single source of truth for capability status across separate dimensions:
//! evidence / implementation / verification / scope.
//!
//! Does **not** claim real Destiny client or server compatibility.
//! Does **not** invent message semantics. Does **not** contact external networks.

use crate::protocol_spec::EXPECTED_MESSAGE_IDS;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const MATRIX_VERSION: &str = "1.0";
pub const CAPTURE_A: &str = "20260529-003132";
pub const CAPTURE_B: &str = "20260608-231100";

/// High-level compatibility areas (M4.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompatibilityArea {
    BapFraming,
    TcpStream,
    ServiceHandshake,
    SessionLogin,
    SessionCrypto,
    EncryptedHandshake,
    NatReporting,
    Keepalive,
    MessageCodec,
    MessageDispatch,
    ProtocolState,
    LocalServer,
    CompatibilityClient,
    ExternalClientBoundary,
    ObservationHarness,
    UdpTransport,
    GameplayNetworking,
    Signon,
    RealDestinyClient,
    RealDestinyServer,
}

impl CompatibilityArea {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BapFraming => "BAP_FRAMING",
            Self::TcpStream => "TCP_STREAM",
            Self::ServiceHandshake => "SERVICE_HANDSHAKE",
            Self::SessionLogin => "SESSION_LOGIN",
            Self::SessionCrypto => "SESSION_CRYPTO",
            Self::EncryptedHandshake => "ENCRYPTED_HANDSHAKE",
            Self::NatReporting => "NAT_REPORTING",
            Self::Keepalive => "KEEPALIVE",
            Self::MessageCodec => "MESSAGE_CODEC",
            Self::MessageDispatch => "MESSAGE_DISPATCH",
            Self::ProtocolState => "PROTOCOL_STATE",
            Self::LocalServer => "LOCAL_SERVER",
            Self::CompatibilityClient => "COMPATIBILITY_CLIENT",
            Self::ExternalClientBoundary => "EXTERNAL_CLIENT_BOUNDARY",
            Self::ObservationHarness => "OBSERVATION_HARNESS",
            Self::UdpTransport => "UDP_TRANSPORT",
            Self::GameplayNetworking => "GAMEPLAY_NETWORKING",
            Self::Signon => "SIGNON",
            Self::RealDestinyClient => "REAL_DESTINY_CLIENT",
            Self::RealDestinyServer => "REAL_DESTINY_SERVER",
        }
    }

    pub fn all() -> &'static [Self] {
        &[
            Self::BapFraming,
            Self::TcpStream,
            Self::ServiceHandshake,
            Self::SessionLogin,
            Self::SessionCrypto,
            Self::EncryptedHandshake,
            Self::NatReporting,
            Self::Keepalive,
            Self::MessageCodec,
            Self::MessageDispatch,
            Self::ProtocolState,
            Self::LocalServer,
            Self::CompatibilityClient,
            Self::ExternalClientBoundary,
            Self::ObservationHarness,
            Self::UdpTransport,
            Self::GameplayNetworking,
            Self::Signon,
            Self::RealDestinyClient,
            Self::RealDestinyServer,
        ]
    }
}

/// Evidence dimension — never auto-promotes Observation/Hypothesis → Confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    Confirmed,
    Observed,
    Structural,
    Hypothesis,
    Unknown,
    Blocked,
}

impl EvidenceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "CONFIRMED",
            Self::Observed => "OBSERVED",
            Self::Structural => "STRUCTURAL",
            Self::Hypothesis => "HYPOTHESIS",
            Self::Unknown => "UNKNOWN",
            Self::Blocked => "BLOCKED",
        }
    }
}

/// Implementation dimension — local repo only; does not imply real-client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ImplementationStatus {
    Implemented,
    Partial,
    NotImplemented,
    Blocked,
}

impl ImplementationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Implemented => "IMPLEMENTED",
            Self::Partial => "PARTIAL",
            Self::NotImplemented => "NOT_IMPLEMENTED",
            Self::Blocked => "BLOCKED",
        }
    }
}

/// Verification dimension — automated tests within declared scope only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationStatus {
    Verified,
    NotVerified,
    Blocked,
}

impl VerificationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::NotVerified => "NOT_VERIFIED",
            Self::Blocked => "BLOCKED",
        }
    }
}

/// Where a capability has been exercised / claimed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompatibilityScope {
    OfflineCapture,
    SyntheticLocal,
    LocalTcp,
    ExternalBoundary,
    RealClient,
    RealServer,
}

impl CompatibilityScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OfflineCapture => "OFFLINE_CAPTURE",
            Self::SyntheticLocal => "SYNTHETIC_LOCAL",
            Self::LocalTcp => "LOCAL_TCP",
            Self::ExternalBoundary => "EXTERNAL_BOUNDARY",
            Self::RealClient => "REAL_CLIENT",
            Self::RealServer => "REAL_SERVER",
        }
    }

    pub fn is_real_world(self) -> bool {
        matches!(self, Self::RealClient | Self::RealServer)
    }
}

/// Real-world compatibility claim — never inferred from local/synthetic success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RealWorldClaim {
    NotProven,
    Proven,
}

impl RealWorldClaim {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotProven => "NOT_PROVEN",
            Self::Proven => "PROVEN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityEntry {
    pub id: String,
    pub area: CompatibilityArea,
    pub name: String,
    pub evidence: EvidenceStatus,
    pub implementation: ImplementationStatus,
    pub verification: VerificationStatus,
    pub scopes: Vec<CompatibilityScope>,
    /// Safe evidence references (capture IDs, test/fixture names) — no payloads/secrets.
    pub evidence_refs: Vec<String>,
    /// Automated verification refs (CLI/test names) — required when verification=Verified.
    pub verification_refs: Vec<String>,
    pub dependencies: Vec<String>,
    pub notes: Vec<String>,
    pub blocking_reason: Option<String>,
    /// Explicit semantic claim; must be empty/None when evidence is Unknown.
    pub semantic_claim: Option<String>,
    pub real_client_compatibility: RealWorldClaim,
    pub real_server_compatibility: RealWorldClaim,
    /// Optional message ID when this entry describes a specific BAP message.
    pub message_id: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityMatrix {
    pub matrix_version: String,
    pub entries: Vec<CompatibilityEntry>,
    pub evidence_sources: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixMetrics {
    pub entries: u64,
    pub confirmed: u64,
    pub observed: u64,
    pub structural: u64,
    pub hypothesis: u64,
    pub implemented: u64,
    pub verified: u64,
    pub blocked: u64,
    pub unknown: u64,
    pub offline_verified: u64,
    pub real_client_verified: u64,
    pub real_server_verified: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum MatrixError {
    #[error("duplicate entry id: {0}")]
    DuplicateId(String),
    #[error("VERIFIED without verification_refs: {0}")]
    VerifiedWithoutEvidence(String),
    #[error("CONFIRMED without evidence_refs: {0}")]
    ConfirmedWithoutEvidence(String),
    #[error("VERIFIED REAL_CLIENT without real-client evidence: {0}")]
    VerifiedRealClient(String),
    #[error("VERIFIED REAL_SERVER without real-server evidence: {0}")]
    VerifiedRealServer(String),
    #[error("BLOCKED without blocking_reason: {0}")]
    BlockedWithoutReason(String),
    #[error("UNKNOWN with invented semantic_claim: {0}")]
    UnknownWithSemantics(String),
    #[error("incompatible statuses: {0}")]
    IncompatibleStatuses(String),
    #[error("impossible scope combination: {0}")]
    ImpossibleScope(String),
    #[error("real-world claim Proven without evidence: {0}")]
    RealWorldProven(String),
    #[error("promotion refused: {0}")]
    PromotionRefused(String),
    #[error("missing required area: {0}")]
    MissingArea(String),
    #[error("missing message id entry: 0x{0:04X}")]
    MissingMessageId(u16),
    #[error("matrix: {0}")]
    Other(String),
}

fn src_captures() -> Vec<String> {
    vec![
        format!("capture:{CAPTURE_A}"),
        format!("capture:{CAPTURE_B}"),
    ]
}

fn src_local() -> Vec<String> {
    let mut v = src_captures();
    v.push("local_synthetic_tests".into());
    v.push("local_replay".into());
    v
}

fn entry(
    id: &str,
    area: CompatibilityArea,
    name: &str,
    evidence: EvidenceStatus,
    implementation: ImplementationStatus,
    verification: VerificationStatus,
    scopes: &[CompatibilityScope],
    evidence_refs: Vec<String>,
    verification_refs: Vec<String>,
    notes: &[&str],
    blocking_reason: Option<&str>,
    message_id: Option<u16>,
) -> CompatibilityEntry {
    CompatibilityEntry {
        id: id.into(),
        area,
        name: name.into(),
        evidence,
        implementation,
        verification,
        scopes: scopes.to_vec(),
        evidence_refs,
        verification_refs,
        dependencies: Vec::new(),
        notes: notes.iter().map(|s| (*s).to_string()).collect(),
        blocking_reason: blocking_reason.map(|s| s.into()),
        semantic_claim: None,
        real_client_compatibility: RealWorldClaim::NotProven,
        real_server_compatibility: RealWorldClaim::NotProven,
        message_id,
    }
}

fn message_entry(
    id: u16,
    area: CompatibilityArea,
    evidence: EvidenceStatus,
    implementation: ImplementationStatus,
    verification: VerificationStatus,
    scopes: &[CompatibilityScope],
    evidence_refs: Vec<String>,
    verification_refs: Vec<String>,
    notes: &[&str],
) -> CompatibilityEntry {
    let hex = format!("0x{id:04X}");
    entry(
        &format!("msg_{hex}"),
        area,
        &format!("Message {hex}"),
        evidence,
        implementation,
        verification,
        scopes,
        evidence_refs,
        verification_refs,
        notes,
        None,
        Some(id),
    )
}

/// Canonical compatibility matrix — single source of truth for M4.9.
pub fn get_compatibility_matrix() -> CompatibilityMatrix {
    let mut entries = Vec::new();

    // --- Area capabilities ---
    entries.push(entry(
        "bap_framing",
        CompatibilityArea::BapFraming,
        "BAP framing [0x01][kind][body_len BE][body]",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[
            CompatibilityScope::OfflineCapture,
            CompatibilityScope::SyntheticLocal,
            CompatibilityScope::LocalTcp,
        ],
        src_local(),
        vec![
            "bap-session-verify".into(),
            "bap-stream-verify".into(),
            "framing tests".into(),
        ],
        &[
            "kind 1 = encrypted; kind 2 = clear",
            "BapStreamDecoder implemented and capture-validated",
            "Local compatibility is not real-client compatibility.",
        ],
        None,
        None,
    ));

    entries.push(entry(
        "tcp_stream",
        CompatibilityArea::TcpStream,
        "TCP stream byte source + fragmentation",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[
            CompatibilityScope::SyntheticLocal,
            CompatibilityScope::LocalTcp,
        ],
        vec![
            "local_synthetic_tests".into(),
            "TcpByteSource".into(),
            "local_replay".into(),
        ],
        vec![
            "tcp_byte_source tests".into(),
            "local-server-e2e".into(),
            "bap-stream-verify".into(),
        ],
        &[
            "TcpByteSource; fragmentation; multiple frames per read; EOF/incomplete",
            "No external network connections",
            "LOCAL_TCP does not imply REAL_SERVER.",
        ],
        None,
        None,
    ));

    entries.push(entry(
        "service_handshake_pair",
        CompatibilityArea::ServiceHandshake,
        "0x1E/0x1F service handshake",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[
            CompatibilityScope::OfflineCapture,
            CompatibilityScope::SyntheticLocal,
            CompatibilityScope::LocalTcp,
        ],
        src_local(),
        vec![
            "local-replay".into(),
            "stateful-server-verify".into(),
            "compatibility-client-verify".into(),
        ],
        &[
            "Observed + codec + stateful server + local replay verified",
            "Real server compatibility NOT_PROVEN",
        ],
        None,
        None,
    ));

    entries.push(entry(
        "session_login_pair",
        CompatibilityArea::SessionLogin,
        "0x19/0x1A session login",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[
            CompatibilityScope::OfflineCapture,
            CompatibilityScope::SyntheticLocal,
            CompatibilityScope::LocalTcp,
        ],
        src_local(),
        vec![
            "session-crypto-verify".into(),
            "local-replay".into(),
            "bap-session-verify".into(),
        ],
        &[
            "Session login structure observed; CBC/HMAC validated for existing captures",
            "Record layout validated; full content semantics still limited",
            "Capture validation is not server compatibility.",
        ],
        None,
        None,
    ));

    entries.push(entry(
        "session_crypto_context",
        CompatibilityArea::SessionCrypto,
        "SessionCryptoContext AES-GCM",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[
            CompatibilityScope::OfflineCapture,
            CompatibilityScope::SyntheticLocal,
            CompatibilityScope::LocalTcp,
        ],
        src_local(),
        vec![
            "gcm-sequence-verify".into(),
            "session_context tests".into(),
            "bap-session-verify".into(),
        ],
        &[
            "AES-GCM; key 16; nonce 12",
            "C2S base = session_nonce XOR last_byte(1); S2C = identity",
            "Independent per-direction counters",
            "Scope limited to available capture evidence — not universal Destiny rules",
        ],
        None,
        None,
    ));

    entries.push(entry(
        "encrypted_handshake_pair",
        CompatibilityArea::EncryptedHandshake,
        "0x79/0x7A encrypted handshake",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[
            CompatibilityScope::OfflineCapture,
            CompatibilityScope::SyntheticLocal,
            CompatibilityScope::LocalTcp,
        ],
        src_local(),
        vec![
            "gcm-first-frame-verify".into(),
            "gcm-sequence-verify".into(),
            "local-replay".into(),
        ],
        &[
            "AES-GCM decrypt validated; AAD empty compatible with verified captures",
            "Real-client compatibility NOT_PROVEN",
        ],
        None,
        None,
    ));

    entries.push(entry(
        "nat_reporting_pair",
        CompatibilityArea::NatReporting,
        "0x12E/0x12F NAT reporting candidates",
        EvidenceStatus::Observed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[
            CompatibilityScope::OfflineCapture,
            CompatibilityScope::SyntheticLocal,
            CompatibilityScope::LocalTcp,
        ],
        src_captures(),
        vec![
            "message-correlation-verify".into(),
            "stateful-server-verify".into(),
            "message-codec-verify".into(),
        ],
        &[
            "Observed; structure/correlation available; dispatch implemented",
            "Full semantics still limited — Observed does not mean understood.",
        ],
        None,
        None,
    ));

    entries.push(entry(
        "keepalive_pair",
        CompatibilityArea::Keepalive,
        "0xFA/0xFB keepalive candidates",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[
            CompatibilityScope::OfflineCapture,
            CompatibilityScope::SyntheticLocal,
            CompatibilityScope::LocalTcp,
        ],
        src_local(),
        vec![
            "state-machine-verify".into(),
            "stateful-server-verify".into(),
            "observation-verify".into(),
        ],
        &[
            "Request/response candidate; local response policy; keepalive model",
            "Universal timing NOT confirmed — temporal intervals observational only",
        ],
        None,
        None,
    ));

    entries.push(entry(
        "message_codec_layer",
        CompatibilityArea::MessageCodec,
        "Message codec + registry",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[
            CompatibilityScope::OfflineCapture,
            CompatibilityScope::SyntheticLocal,
        ],
        src_local(),
        vec!["message-codec-verify".into()],
        &["Registry reuses EXPECTED_MESSAGE_IDS; opaque IDs preserve raw"],
        None,
        None,
    ));

    entries.push(entry(
        "message_dispatch_layer",
        CompatibilityArea::MessageDispatch,
        "Message dispatcher (observational)",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[CompatibilityScope::SyntheticLocal, CompatibilityScope::LocalTcp],
        vec!["local_synthetic_tests".into()],
        vec!["message_dispatcher tests".into(), "stateful-server-verify".into()],
        &["Does not invent handlers for unknown IDs"],
        None,
        None,
    ));

    entries.push(entry(
        "protocol_state_layer",
        CompatibilityArea::ProtocolState,
        "ProtocolState + observational SM",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[
            CompatibilityScope::OfflineCapture,
            CompatibilityScope::SyntheticLocal,
            CompatibilityScope::LocalTcp,
        ],
        src_local(),
        vec![
            "state-machine-verify".into(),
            "stateful-server-verify".into(),
        ],
        &[
            "M3.4 observational SM separate from M4.5 local ProtocolState",
            "Implemented does not mean compatible.",
        ],
        None,
        None,
    ));

    entries.push(entry(
        "local_server_layer",
        CompatibilityArea::LocalServer,
        "LocalBapServer + replay",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[CompatibilityScope::SyntheticLocal, CompatibilityScope::LocalTcp],
        vec!["local_synthetic_tests".into(), "local_replay".into()],
        vec![
            "local-server-verify".into(),
            "local-replay".into(),
            "local-server-e2e".into(),
        ],
        &[
            "SIMULATED_HANDSHAKE only; localhost",
            "Synthetic tests do not prove Destiny client interoperability.",
        ],
        None,
        None,
    ));

    entries.push(entry(
        "compatibility_client_layer",
        CompatibilityArea::CompatibilityClient,
        "BapCompatibilityClient",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[CompatibilityScope::SyntheticLocal, CompatibilityScope::LocalTcp],
        vec!["local_synthetic_tests".into()],
        vec!["compatibility-client-verify".into()],
        &["Localhost only; SYNTHETIC_TEST_ONLY crypto"],
        None,
        None,
    ));

    entries.push(entry(
        "external_boundary_layer",
        CompatibilityArea::ExternalClientBoundary,
        "ExternalClientBoundary",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[
            CompatibilityScope::SyntheticLocal,
            CompatibilityScope::LocalTcp,
            CompatibilityScope::ExternalBoundary,
        ],
        vec!["local_synthetic_tests".into(), "external_boundary".into()],
        vec!["external-boundary-verify".into()],
        &[
            "Localhost ingress only; safe events; reuses StatefulBapSession",
            "Does not prove real Destiny client attachment",
        ],
        None,
        None,
    ));

    entries.push(entry(
        "observation_harness_layer",
        CompatibilityArea::ObservationHarness,
        "Observation harness (M4.8)",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Implemented,
        VerificationStatus::Verified,
        &[
            CompatibilityScope::SyntheticLocal,
            CompatibilityScope::ExternalBoundary,
        ],
        vec!["observation_harness".into(), "local_synthetic_tests".into()],
        vec!["observation-verify".into()],
        &["Metadata-only traces; no auto-promotion of hypotheses"],
        None,
        None,
    ));

    entries.push(entry(
        "udp_transport_layer",
        CompatibilityArea::UdpTransport,
        "UDP transport evidence",
        EvidenceStatus::Observed,
        ImplementationStatus::NotImplemented,
        VerificationStatus::Verified,
        &[CompatibilityScope::OfflineCapture],
        src_captures(),
        vec!["udp-evidence-verify".into()],
        &[
            "Ambient UDP observed in captures; session gameplay UDP not confirmed",
            "Capture A had 3074/3075 traffic before session; Capture B showed no session UDP",
            "Ports 3074/3075 are NOT asserted as Destiny gameplay transport",
            "Unknown remains unknown until evidence changes it.",
        ],
        None,
        None,
    ));

    entries.push(entry(
        "gameplay_networking_layer",
        CompatibilityArea::GameplayNetworking,
        "Gameplay networking / UDP gameplay",
        EvidenceStatus::Unknown,
        ImplementationStatus::Blocked,
        VerificationStatus::Blocked,
        &[CompatibilityScope::OfflineCapture],
        vec![],
        vec![],
        &["Gameplay UDP remains UNKNOWN/BLOCKED"],
        Some("No confirmed session gameplay UDP protocol; no implementation without evidence"),
        None,
    ));

    entries.push(entry(
        "signon_layer",
        CompatibilityArea::Signon,
        "SignOn HTTPS offline analysis + session material boundary",
        EvidenceStatus::Confirmed,
        ImplementationStatus::Partial,
        VerificationStatus::Verified,
        &[
            CompatibilityScope::OfflineCapture,
            CompatibilityScope::SyntheticLocal,
        ],
        vec![
            "docs/networking/signon-https.md".into(),
            "capture:20260529-003132".into(),
            "signon-verify".into(),
        ],
        vec!["signon-verify".into(), "signon tests".into()],
        &[
            "Offline SignOn analysis VERIFIED; metadata-only; no secret values stored",
            "SessionMaterialProvider boundary + OfflineSessionMaterialProvider (SYNTHETIC_TEST_ONLY)",
            "Real SignOn / live auth remains NOT_IMPLEMENTED / BLOCKED",
            "Offline SignOn analysis is not real SignOn compatibility.",
        ],
        Some(
            "Real SignOn HTTP/auth not implemented; live Bungie/Destiny connection forbidden",
        ),
        None,
    ));

    entries.push(entry(
        "signon_real_provider",
        CompatibilityArea::Signon,
        "Real SignOn provider / live authentication",
        EvidenceStatus::Blocked,
        ImplementationStatus::Blocked,
        VerificationStatus::Blocked,
        &[CompatibilityScope::RealServer],
        vec![],
        vec![],
        &["No real SignOn implementation; no live auth; no credentials"],
        Some("No real SignOn implementation or live Destiny/Bungie connection"),
        None,
    ));

    entries.push(entry(
        "real_destiny_client",
        CompatibilityArea::RealDestinyClient,
        "Real Destiny client compatibility",
        EvidenceStatus::Unknown,
        ImplementationStatus::Blocked,
        VerificationStatus::NotVerified,
        &[CompatibilityScope::RealClient],
        vec![],
        vec![],
        &[
            "NOT_PROVEN — local/synthetic success is not real-client proof",
            "Local compatibility is not real-client compatibility.",
        ],
        Some("no real-client compatibility evidence"),
        None,
    ));

    entries.push(entry(
        "real_destiny_server",
        CompatibilityArea::RealDestinyServer,
        "Real Destiny server compatibility",
        EvidenceStatus::Unknown,
        ImplementationStatus::Blocked,
        VerificationStatus::NotVerified,
        &[CompatibilityScope::RealServer],
        vec![],
        vec![],
        &[
            "NOT_PROVEN — local TCP is not real-server proof",
            "Capture validation is not server compatibility.",
        ],
        Some("no real-server compatibility evidence"),
        None,
    ));

    // --- Per-message entries (28 IDs from EXPECTED_MESSAGE_IDS) ---
    for &id in EXPECTED_MESSAGE_IDS {
        entries.push(message_capability(id));
    }

    CompatibilityMatrix {
        matrix_version: MATRIX_VERSION.into(),
        entries,
        evidence_sources: vec![
            format!("capture:{CAPTURE_A}"),
            format!("capture:{CAPTURE_B}"),
            "local_synthetic_tests".into(),
            "local_replay".into(),
            "external_boundary".into(),
            "observation_harness".into(),
        ],
        notes: vec![
            "Local compatibility is not real-client compatibility.".into(),
            "Capture validation is not server compatibility.".into(),
            "Synthetic tests do not prove Destiny client interoperability.".into(),
            "Observed does not mean understood.".into(),
            "Implemented does not mean compatible.".into(),
            "Unknown remains unknown until evidence changes it.".into(),
        ],
    }
}

fn message_capability(id: u16) -> CompatibilityEntry {
    let captures = src_captures();
    let local = src_local();
    match id {
        0x1E | 0x1F => message_entry(
            id,
            CompatibilityArea::ServiceHandshake,
            EvidenceStatus::Confirmed,
            ImplementationStatus::Implemented,
            VerificationStatus::Verified,
            &[
                CompatibilityScope::OfflineCapture,
                CompatibilityScope::SyntheticLocal,
                CompatibilityScope::LocalTcp,
            ],
            local,
            vec![
                "local-replay".into(),
                "message-codec-verify".into(),
                "stateful-server-verify".into(),
            ],
            &[
                "Observed; codec implemented; stateful server; local replay verified",
                "Real server compatibility NOT_PROVEN",
            ],
        ),
        0x19 | 0x1A => message_entry(
            id,
            CompatibilityArea::SessionLogin,
            EvidenceStatus::Confirmed,
            ImplementationStatus::Implemented,
            VerificationStatus::Verified,
            &[
                CompatibilityScope::OfflineCapture,
                CompatibilityScope::SyntheticLocal,
                CompatibilityScope::LocalTcp,
            ],
            local,
            vec![
                "session-crypto-verify".into(),
                "bap-session-verify".into(),
                "local-replay".into(),
            ],
            &[
                "Structure observed; CBC/HMAC (0x1A path) capture-validated",
                "Full payload semantics still limited",
            ],
        ),
        0x79 | 0x7A => message_entry(
            id,
            CompatibilityArea::EncryptedHandshake,
            EvidenceStatus::Confirmed,
            ImplementationStatus::Implemented,
            VerificationStatus::Verified,
            &[
                CompatibilityScope::OfflineCapture,
                CompatibilityScope::SyntheticLocal,
                CompatibilityScope::LocalTcp,
            ],
            local,
            vec![
                "gcm-sequence-verify".into(),
                "gcm-first-frame-verify".into(),
                "local-replay".into(),
            ],
            &[
                "Encrypted handshake; AES-GCM validated; AAD empty on verified captures",
                "Real-client compatibility NOT_PROVEN",
            ],
        ),
        0x12E | 0x12F => message_entry(
            id,
            CompatibilityArea::NatReporting,
            EvidenceStatus::Observed,
            ImplementationStatus::Implemented,
            VerificationStatus::Verified,
            &[
                CompatibilityScope::OfflineCapture,
                CompatibilityScope::SyntheticLocal,
                CompatibilityScope::LocalTcp,
            ],
            captures,
            vec![
                "message-correlation-verify".into(),
                "message-codec-verify".into(),
            ],
            &[
                "Observed; correlation/structure available; dispatch implemented",
                "Complete semantics still limited",
            ],
        ),
        0xFA | 0xFB => message_entry(
            id,
            CompatibilityArea::Keepalive,
            EvidenceStatus::Confirmed,
            ImplementationStatus::Implemented,
            VerificationStatus::Verified,
            &[
                CompatibilityScope::OfflineCapture,
                CompatibilityScope::SyntheticLocal,
                CompatibilityScope::LocalTcp,
            ],
            local,
            vec![
                "state-machine-verify".into(),
                "stateful-server-verify".into(),
            ],
            &[
                "Keepalive candidate; local response policy",
                "Universal timing NOT confirmed",
            ],
        ),
        0x10 | 0x11 | 0x2A | 0x2B => message_entry(
            id,
            CompatibilityArea::MessageCodec,
            EvidenceStatus::Observed,
            ImplementationStatus::Partial,
            VerificationStatus::Verified,
            &[CompatibilityScope::OfflineCapture, CompatibilityScope::SyntheticLocal],
            captures,
            vec![
                "message-inventory".into(),
                "message-codec-verify".into(),
                "multi-capture-verify".into(),
            ],
            &[
                "Present in inventory; opaque codec; semantics remain limited/unknown",
                "Do not invent request/response/gameplay meaning",
            ],
        ),
        0x7B | 0xAB => message_entry(
            id,
            CompatibilityArea::MessageCodec,
            EvidenceStatus::Observed,
            ImplementationStatus::Partial,
            VerificationStatus::Verified,
            &[CompatibilityScope::OfflineCapture, CompatibilityScope::SyntheticLocal],
            captures,
            vec![
                "payload-structure-verify".into(),
                "message-codec-verify".into(),
            ],
            &[
                "Variable-length payloads observed; semantics remain limited/unknown",
                "Unknown remains unknown until evidence changes it.",
            ],
        ),
        // Other inventory IDs: observed structurally, opaque codec, no invented semantics
        _ => message_entry(
            id,
            CompatibilityArea::MessageCodec,
            EvidenceStatus::Observed,
            ImplementationStatus::Partial,
            VerificationStatus::Verified,
            &[CompatibilityScope::OfflineCapture, CompatibilityScope::SyntheticLocal],
            captures,
            vec![
                "message-inventory".into(),
                "message-codec-verify".into(),
                "multi-capture-verify".into(),
            ],
            &[
                "Inventory/registry presence; opaque or structural only",
                "Semantics not invented — Observed does not mean understood.",
            ],
        ),
    }
}

/// Validate matrix invariants (M4.9).
pub fn validate_matrix(matrix: &CompatibilityMatrix) -> Result<(), MatrixError> {
    let mut seen = BTreeSet::new();
    for e in &matrix.entries {
        if !seen.insert(e.id.clone()) {
            return Err(MatrixError::DuplicateId(e.id.clone()));
        }
        validate_entry(e)?;
    }

    // Required areas present
    let areas: BTreeSet<_> = matrix.entries.iter().map(|e| e.area).collect();
    for a in CompatibilityArea::all() {
        if !areas.contains(a) {
            return Err(MatrixError::MissingArea(a.as_str().into()));
        }
    }

    // All 28 message IDs represented
    let msg_ids: BTreeSet<u16> = matrix
        .entries
        .iter()
        .filter_map(|e| e.message_id)
        .collect();
    for &id in EXPECTED_MESSAGE_IDS {
        if !msg_ids.contains(&id) {
            return Err(MatrixError::MissingMessageId(id));
        }
    }

    Ok(())
}

pub fn validate_entry(e: &CompatibilityEntry) -> Result<(), MatrixError> {
    // BLOCKED must have reason
    let blocked = e.evidence == EvidenceStatus::Blocked
        || e.implementation == ImplementationStatus::Blocked
        || e.verification == VerificationStatus::Blocked;
    if blocked {
        match &e.blocking_reason {
            Some(r) if !r.trim().is_empty() => {}
            _ => return Err(MatrixError::BlockedWithoutReason(e.id.clone())),
        }
    }

    // CONFIRMED needs evidence refs
    if e.evidence == EvidenceStatus::Confirmed && e.evidence_refs.is_empty() {
        return Err(MatrixError::ConfirmedWithoutEvidence(e.id.clone()));
    }

    // VERIFIED needs verification refs
    if e.verification == VerificationStatus::Verified && e.verification_refs.is_empty() {
        return Err(MatrixError::VerifiedWithoutEvidence(e.id.clone()));
    }

    // UNKNOWN must not invent semantics
    if e.evidence == EvidenceStatus::Unknown {
        if let Some(s) = &e.semantic_claim {
            if !s.trim().is_empty() {
                return Err(MatrixError::UnknownWithSemantics(e.id.clone()));
            }
        }
    }

    // Real-world Proven requires evidence (never true in current matrix)
    if e.real_client_compatibility == RealWorldClaim::Proven {
        return Err(MatrixError::RealWorldProven(format!(
            "{} real_client",
            e.id
        )));
    }
    if e.real_server_compatibility == RealWorldClaim::Proven {
        return Err(MatrixError::RealWorldProven(format!(
            "{} real_server",
            e.id
        )));
    }

    // VERIFIED + REAL_CLIENT/SERVER scope forbidden without Proven claim (which we also forbid)
    if e.verification == VerificationStatus::Verified {
        if e.scopes.contains(&CompatibilityScope::RealClient) {
            return Err(MatrixError::VerifiedRealClient(e.id.clone()));
        }
        if e.scopes.contains(&CompatibilityScope::RealServer) {
            return Err(MatrixError::VerifiedRealServer(e.id.clone()));
        }
    }

    // Impossible: claim Verified on real scopes while NotProven
    if e.scopes.iter().any(|s| s.is_real_world())
        && e.verification == VerificationStatus::Verified
    {
        return Err(MatrixError::ImpossibleScope(e.id.clone()));
    }

    // Incompatible: Implemented does not allow claiming Proven real client (checked above)
    // Incompatible: Hypothesis evidence cannot be paired with Verified claiming Confirmed semantics
    if e.evidence == EvidenceStatus::Hypothesis
        && e.verification == VerificationStatus::Verified
        && e.semantic_claim.is_some()
    {
        return Err(MatrixError::IncompatibleStatuses(format!(
            "{}: HYPOTHESIS cannot be VERIFIED with semantic claim",
            e.id
        )));
    }

    // Empty scopes invalid for non-blocked area entries that claim verification
    if e.scopes.is_empty() {
        return Err(MatrixError::ImpossibleScope(format!(
            "{}: empty scopes",
            e.id
        )));
    }

    Ok(())
}

/// Explicitly refuse automatic promotions (tests assert these fail).
pub fn refuse_promote_hypothesis_to_confirmed(
    _from: EvidenceStatus,
) -> Result<EvidenceStatus, MatrixError> {
    Err(MatrixError::PromotionRefused(
        "HYPOTHESIS must not auto-promote to CONFIRMED".into(),
    ))
}

pub fn refuse_promote_observed_to_implemented(
    _from: EvidenceStatus,
) -> Result<ImplementationStatus, MatrixError> {
    Err(MatrixError::PromotionRefused(
        "OBSERVED must not auto-promote to IMPLEMENTED".into(),
    ))
}

pub fn refuse_promote_implemented_to_real_client(
    _from: ImplementationStatus,
) -> Result<RealWorldClaim, MatrixError> {
    Err(MatrixError::PromotionRefused(
        "IMPLEMENTED must not auto-promote to REAL_CLIENT".into(),
    ))
}

pub fn refuse_promote_local_tcp_to_real_server(
    _from: CompatibilityScope,
) -> Result<RealWorldClaim, MatrixError> {
    Err(MatrixError::PromotionRefused(
        "LOCAL_TCP must not auto-promote to REAL_SERVER".into(),
    ))
}

pub fn compute_metrics(matrix: &CompatibilityMatrix) -> MatrixMetrics {
    let mut m = MatrixMetrics {
        entries: matrix.entries.len() as u64,
        confirmed: 0,
        observed: 0,
        structural: 0,
        hypothesis: 0,
        implemented: 0,
        verified: 0,
        blocked: 0,
        unknown: 0,
        offline_verified: 0,
        real_client_verified: 0,
        real_server_verified: 0,
    };
    for e in &matrix.entries {
        match e.evidence {
            EvidenceStatus::Confirmed => m.confirmed += 1,
            EvidenceStatus::Observed => m.observed += 1,
            EvidenceStatus::Structural => m.structural += 1,
            EvidenceStatus::Hypothesis => m.hypothesis += 1,
            EvidenceStatus::Unknown => m.unknown += 1,
            EvidenceStatus::Blocked => m.blocked += 1,
        }
        if e.implementation == ImplementationStatus::Implemented {
            m.implemented += 1;
        }
        if e.implementation == ImplementationStatus::Blocked
            || e.verification == VerificationStatus::Blocked
        {
            // count blocked dimension once per entry if any blocked flag (evidence Blocked already counted)
            if e.implementation == ImplementationStatus::Blocked
                && e.evidence != EvidenceStatus::Blocked
            {
                m.blocked += 1;
            }
        }
        if e.verification == VerificationStatus::Verified {
            m.verified += 1;
            let offline = e.scopes.iter().any(|s| {
                matches!(
                    s,
                    CompatibilityScope::OfflineCapture
                        | CompatibilityScope::SyntheticLocal
                        | CompatibilityScope::LocalTcp
                        | CompatibilityScope::ExternalBoundary
                )
            });
            if offline {
                m.offline_verified += 1;
            }
            if e.scopes.contains(&CompatibilityScope::RealClient)
                && e.real_client_compatibility == RealWorldClaim::Proven
            {
                m.real_client_verified += 1;
            }
            if e.scopes.contains(&CompatibilityScope::RealServer)
                && e.real_server_compatibility == RealWorldClaim::Proven
            {
                m.real_server_verified += 1;
            }
        }
    }
    m
}

/// Human-readable report grouped by area.
pub fn format_report(matrix: &CompatibilityMatrix) -> String {
    let mut by_area: BTreeMap<CompatibilityArea, Vec<&CompatibilityEntry>> = BTreeMap::new();
    for e in &matrix.entries {
        by_area.entry(e.area).or_default().push(e);
    }
    let mut out = String::new();
    out.push_str("M4.9 PROTOCOL COMPATIBILITY MATRIX REPORT\n");
    out.push_str(&format!("matrix_version: {}\n\n", matrix.matrix_version));
    for area in CompatibilityArea::all() {
        let Some(list) = by_area.get(area) else {
            continue;
        };
        // Prefer area-level entry (no message_id) for summary header
        let primary = list
            .iter()
            .find(|e| e.message_id.is_none())
            .copied()
            .unwrap_or(list[0]);
        out.push_str(area.as_str());
        out.push('\n');
        out.push_str(&format!("Evidence: {}\n", primary.evidence.as_str()));
        out.push_str(&format!(
            "Implementation: {}\n",
            primary.implementation.as_str()
        ));
        out.push_str(&format!(
            "Verification: {}\n",
            primary.verification.as_str()
        ));
        let scopes: Vec<_> = primary.scopes.iter().map(|s| s.as_str()).collect();
        out.push_str(&format!("Scope: {}\n", scopes.join(" / ")));
        if let Some(r) = &primary.blocking_reason {
            out.push_str(&format!("Reason: {r}\n"));
        }
        out.push_str(&format!(
            "Real client: {}\n",
            primary.real_client_compatibility.as_str()
        ));
        out.push_str(&format!(
            "Real server: {}\n",
            primary.real_server_compatibility.as_str()
        ));
        for note in &primary.notes {
            out.push_str(&format!("  - {note}\n"));
        }
        out.push('\n');
    }
    for n in &matrix.notes {
        out.push_str(&format!("NOTE: {n}\n"));
    }
    out
}

pub fn matrix_to_json(matrix: &CompatibilityMatrix) -> Result<String, String> {
    serde_json::to_string_pretty(matrix).map_err(|e| e.to_string())
}

pub fn matrix_from_json(s: &str) -> Result<CompatibilityMatrix, String> {
    serde_json::from_str(s).map_err(|e| e.to_string())
}
