//! Protocol implementation specification v0.1 (M4.1).
//!
//! Structured evidence extraction from verified captures / offline stack.
//! Does **not** invent protocol facts beyond existing OBSERVED/CONFIRMED evidence.

use crate::message_inventory::{fmt_msg_id, CaptureMessageInventory, MessageObservation};
use crate::message_correlation::ordered_observations;
use crate::messages::lookup_name;
use crate::state_machine::{
    build_state_machine, startup_prefix_len, ProtocolStateMachine, STABLE_STARTUP_SEQUENCE,
    STATE_POST_STARTUP, STATE_REPEATING_CLUSTER_01, STATE_START, STATE_STARTUP_SEQUENCE,
};
use crate::stream_framing::MAX_BODY_LEN;
use serde::Serialize;
use std::collections::BTreeSet;

/// Canonical 28 message IDs from verified multi-capture inventory.
pub const EXPECTED_MESSAGE_IDS: &[u16] = &[
    0x0A, 0x0B, 0x0C, 0x0D, 0x10, 0x11, 0x12, 0x13, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1E,
    0x1F, 0x20, 0x21, 0x2A, 0x2B, 0x79, 0x7A, 0x7B, 0xAB, 0xFA, 0xFB, 0x12E, 0x12F,
];

pub const SPEC_VERSION: &str = "0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EvidenceClass {
    Confirmed,
    Observed,
    StructuralHypothesis,
    ExternalReference,
    Unknown,
}

impl EvidenceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "CONFIRMED",
            Self::Observed => "OBSERVED",
            Self::StructuralHypothesis => "STRUCTURAL_HYPOTHESIS",
            Self::ExternalReference => "EXTERNAL_REFERENCE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ImplStatus {
    Documented,
    OfflineImplemented,
    PartiallyUnderstood,
    Unknown,
}

impl ImplStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Documented => "DOCUMENTED",
            Self::OfflineImplemented => "OFFLINE_IMPLEMENTED",
            Self::PartiallyUnderstood => "PARTIALLY_UNDERSTOOD",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Readiness {
    ReadyOffline,
    ReadyForLocalTest,
    PartiallyReady,
    Blocked,
    Unknown,
}

impl Readiness {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadyOffline => "READY_OFFLINE",
            Self::ReadyForLocalTest => "READY_FOR_LOCAL_TEST",
            Self::PartiallyReady => "PARTIALLY_READY",
            Self::Blocked => "BLOCKED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum UnknownPriority {
    High,
    Medium,
    Low,
}

impl UnknownPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolEvidence {
    pub source: String,
    pub capture_id: Option<String>,
    pub message_id: Option<String>,
    pub direction: Option<String>,
    pub context: Option<u32>,
    pub wire_length: Option<usize>,
    pub payload_length: Option<usize>,
    pub observation: String,
    pub classification: EvidenceClass,
    pub confidence: EvidenceClass,
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageSpecification {
    pub message_id: String,
    pub directions: Vec<String>,
    pub contexts: Vec<u32>,
    pub payload_lengths: Vec<usize>,
    pub fixed_length: bool,
    pub cross_capture_present: String,
    pub known_fields: Vec<String>,
    pub unknown_regions: Vec<String>,
    pub state_machine_positions: Vec<String>,
    pub external_reference: Option<&'static str>,
    pub implementation_status: ImplStatus,
    pub confidence: EvidenceClass,
    pub payload_understanding: String,
    pub unknowns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImplementationReadiness {
    pub component: String,
    pub evidence_level: EvidenceClass,
    pub offline_status: ImplStatus,
    pub readiness: Readiness,
    pub understood: String,
    pub implementable_offline: String,
    pub server_compatible: String,
    pub blocked_by: Vec<String>,
    pub unknowns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnknownEntry {
    pub id: String,
    pub description: String,
    pub priority: UnknownPriority,
    pub blocks: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolSpec {
    pub version: String,
    pub evidence_policy: String,
    pub captures: Vec<String>,
    pub framing: FramingSpec,
    pub crypto: CryptoSpec,
    pub startup_sequence: Vec<String>,
    pub state_machine_summary: StateMachineSummary,
    pub messages: Vec<MessageSpecification>,
    pub evidence_samples: Vec<ProtocolEvidence>,
    pub implementation_readiness: Vec<ImplementationReadiness>,
    pub unknowns: Vec<UnknownEntry>,
    pub external_reference_note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FramingSpec {
    pub magic: String,
    pub kind_encrypted: u8,
    pub kind_clear: u8,
    pub body_len_endian: String,
    pub clear_layout: String,
    pub encrypted_note: String,
    pub max_body_len_impl: usize,
    pub max_body_len_class: String,
    pub classification: EvidenceClass,
}

#[derive(Debug, Clone, Serialize)]
pub struct CryptoSpec {
    pub session_login_0x1a: SessionLoginSpec,
    pub session_crypto_context: SessionCtxSpec,
    pub aes_gcm: AesGcmSpec,
    pub nonce_model: NonceSpec,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionLoginSpec {
    pub direction: String,
    pub kind: u8,
    pub context: u32,
    pub payload_len: usize,
    pub prefix_u16_be: u16,
    pub record_len_u32_be: u32,
    pub iv_len: usize,
    pub ciphertext_len: usize,
    pub hmac_len: usize,
    pub cipher: String,
    pub hmac: String,
    pub hmac_input: String,
    pub validated: String,
    pub nonce_key_layout: String,
    pub nonce_key_layout_class: EvidenceClass,
    pub classification: EvidenceClass,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionCtxSpec {
    pub session_key_len: usize,
    pub session_nonce_len: usize,
    pub c2s_base: String,
    pub s2c_base: String,
    pub counters: String,
    pub classification: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AesGcmSpec {
    pub algorithm: String,
    pub key: String,
    pub nonce_len: usize,
    pub aad_in_verified_captures: String,
    pub aad_general: String,
    pub first_frames: String,
    pub channel_validation: String,
    pub classification: EvidenceClass,
}

#[derive(Debug, Clone, Serialize)]
pub struct NonceSpec {
    pub model: String,
    pub classification: String,
    pub not_universal: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StateMachineSummary {
    pub nodes: Vec<String>,
    pub startup_label: String,
    pub divergence_index: Option<usize>,
    pub repeating_cluster: String,
    pub classification: EvidenceClass,
}

fn collect_for_id<'a>(obs: &'a [&'a MessageObservation], id: u16) -> Vec<&'a MessageObservation> {
    obs.iter().copied().filter(|o| o.message_id == id).collect()
}

fn state_positions_for_id(sm: &ProtocolStateMachine, id: u16) -> Vec<String> {
    let mut set = BTreeSet::new();
    for trace in sm.traces.values() {
        for e in trace {
            if e.message_id == id {
                set.insert(format!("{} → {}", e.from_state, e.to_state));
            }
        }
    }
    set.into_iter().collect()
}

fn impl_status_for_id(id: u16) -> ImplStatus {
    match id {
        0x1A | 0x19 | 0x1E | 0x1F => ImplStatus::OfflineImplemented,
        0x79 | 0x7A | 0x12E | 0x12F | 0xFA | 0xFB => ImplStatus::OfflineImplemented,
        0x0A | 0x0B | 0x0C | 0x0D => ImplStatus::PartiallyUnderstood,
        _ => ImplStatus::PartiallyUnderstood,
    }
}

fn confidence_for_id(id: u16, both: bool) -> EvidenceClass {
    if both {
        match id {
            0x1A | 0x19 | 0x1E | 0x1F | 0x79 | 0x7A | 0x12E | 0x12F | 0xFA | 0xFB => {
                EvidenceClass::Observed
            }
            _ => EvidenceClass::Observed,
        }
    } else {
        EvidenceClass::Observed
    }
}

fn known_fields_for_id(id: u16) -> Vec<String> {
    match id {
        0x1A => vec![
            "u16 BE prefix=200 (OBSERVED)".into(),
            "u32 BE record_len=80 (OBSERVED)".into(),
            "IV[16] || ciphertext[32] || HMAC[32] (OBSERVED)".into(),
        ],
        0x1E | 0x1F => vec!["clear body layout via framing (OBSERVED)".into()],
        _ => Vec::new(),
    }
}

fn message_spec(
    id: u16,
    all_a: &[&MessageObservation],
    all_b: &[&MessageObservation],
    sm: &ProtocolStateMachine,
) -> MessageSpecification {
    let oa = collect_for_id(all_a, id);
    let ob = collect_for_id(all_b, id);
    let both = !oa.is_empty() && !ob.is_empty();
    let a_only = !oa.is_empty() && ob.is_empty();
    let b_only = oa.is_empty() && !ob.is_empty();
    let present = if both {
        "both"
    } else if a_only {
        "A_only"
    } else if b_only {
        "B_only"
    } else {
        "absent"
    };

    let mut dirs = BTreeSet::new();
    let mut ctxs = BTreeSet::new();
    let mut lens = BTreeSet::new();
    for o in oa.iter().chain(ob.iter()) {
        dirs.insert(o.direction.clone());
        ctxs.insert(o.context);
        lens.insert(o.payload_len);
    }

    let fixed = lens.len() <= 1;
    let ext = lookup_name(id);
    let positions = state_positions_for_id(sm, id);
    let understanding = if id == 0x1A {
        "structure + CBC/HMAC offline validated; nonce/key split STRUCTURAL_HYPOTHESIS"
            .into()
    } else if matches!(id, 0x79 | 0x7A | 0x12E | 0x12F | 0xFA | 0xFB) {
        "encrypted/clear observed; GCM path offline for encrypted after session"
            .into()
    } else if positions.iter().any(|p| p.contains(STATE_STARTUP_SEQUENCE)) {
        "startup sequence member; payload fields largely UNKNOWN".into()
    } else {
        "lengths/directions OBSERVED; payload semantics UNKNOWN".into()
    };

    let mut unknowns = vec!["exact payload field semantics".into()];
    if !fixed {
        unknowns.push("variable length structure".into());
    }

    MessageSpecification {
        message_id: fmt_msg_id(id),
        directions: dirs.into_iter().collect(),
        contexts: ctxs.into_iter().collect(),
        payload_lengths: lens.into_iter().collect(),
        fixed_length: fixed,
        cross_capture_present: present.into(),
        known_fields: known_fields_for_id(id),
        unknown_regions: if known_fields_for_id(id).is_empty() {
            vec!["entire payload".into()]
        } else {
            vec!["unparsed residual / semantic meaning".into()]
        },
        state_machine_positions: positions,
        external_reference: ext,
        implementation_status: impl_status_for_id(id),
        confidence: confidence_for_id(id, both),
        payload_understanding: understanding,
        unknowns,
    }
}

fn readiness_table() -> Vec<ImplementationReadiness> {
    vec![
        ImplementationReadiness {
            component: "BAP framing".into(),
            evidence_level: EvidenceClass::Confirmed,
            offline_status: ImplStatus::OfflineImplemented,
            readiness: Readiness::ReadyOffline,
            understood: "HIGH".into(),
            implementable_offline: "YES".into(),
            server_compatible: "NOT YET VERIFIED".into(),
            blocked_by: vec![],
            unknowns: vec!["kinds beyond 1/2".into()],
        },
        ImplementationReadiness {
            component: "clear messages".into(),
            evidence_level: EvidenceClass::Observed,
            offline_status: ImplStatus::OfflineImplemented,
            readiness: Readiness::ReadyOffline,
            understood: "MEDIUM".into(),
            implementable_offline: "YES".into(),
            server_compatible: "NOT YET VERIFIED".into(),
            blocked_by: vec!["payload schemas".into()],
            unknowns: vec!["most clear payload fields".into()],
        },
        ImplementationReadiness {
            component: "session-login crypto".into(),
            evidence_level: EvidenceClass::Confirmed,
            offline_status: ImplStatus::OfflineImplemented,
            readiness: Readiness::ReadyOffline,
            understood: "HIGH (capture-validated)".into(),
            implementable_offline: "YES".into(),
            server_compatible: "NOT YET VERIFIED".into(),
            blocked_by: vec!["SignOn key acquisition in-repo".into()],
            unknowns: vec!["nonce/key layout semantic confirmation".into()],
        },
        ImplementationReadiness {
            component: "GCM channel".into(),
            evidence_level: EvidenceClass::Confirmed,
            offline_status: ImplStatus::OfflineImplemented,
            readiness: Readiness::ReadyOffline,
            understood: "HIGH".into(),
            implementable_offline: "YES".into(),
            server_compatible: "NOT YET VERIFIED".into(),
            blocked_by: vec![],
            unknowns: vec!["AAD beyond verified empty".into()],
        },
        ImplementationReadiness {
            component: "nonce handling".into(),
            evidence_level: EvidenceClass::Confirmed,
            offline_status: ImplStatus::OfflineImplemented,
            readiness: Readiness::ReadyOffline,
            understood: "HIGH for verified captures".into(),
            implementable_offline: "YES".into(),
            server_compatible: "NOT YET VERIFIED".into(),
            blocked_by: vec![],
            unknowns: vec!["rekey / other platforms".into()],
        },
        ImplementationReadiness {
            component: "stream decoder".into(),
            evidence_level: EvidenceClass::Confirmed,
            offline_status: ImplStatus::OfflineImplemented,
            readiness: Readiness::ReadyOffline,
            understood: "HIGH".into(),
            implementable_offline: "YES".into(),
            server_compatible: "N/A (local)".into(),
            blocked_by: vec![],
            unknowns: vec!["MAX_BODY_LEN is IMPLEMENTATION_LIMIT".into()],
        },
        ImplementationReadiness {
            component: "TCP byte source".into(),
            evidence_level: EvidenceClass::Observed,
            offline_status: ImplStatus::OfflineImplemented,
            readiness: Readiness::ReadyForLocalTest,
            understood: "MEDIUM".into(),
            implementable_offline: "YES (local loopback)".into(),
            server_compatible: "NOT IMPLEMENTED (no Bungie endpoint)".into(),
            blocked_by: vec!["no write path".into(), "no live endpoints".into()],
            unknowns: vec!["production TCP endpoint/port".into()],
        },
        ImplementationReadiness {
            component: "startup state machine".into(),
            evidence_level: EvidenceClass::Observed,
            offline_status: ImplStatus::OfflineImplemented,
            readiness: Readiness::ReadyOffline,
            understood: "MEDIUM".into(),
            implementable_offline: "YES".into(),
            server_compatible: "NOT YET VERIFIED".into(),
            blocked_by: vec![],
            unknowns: vec!["semantic names for states".into()],
        },
        ImplementationReadiness {
            component: "message dispatch".into(),
            evidence_level: EvidenceClass::Observed,
            offline_status: ImplStatus::PartiallyUnderstood,
            readiness: Readiness::PartiallyReady,
            understood: "LOW–MEDIUM".into(),
            implementable_offline: "PARTIAL".into(),
            server_compatible: "NO".into(),
            blocked_by: vec!["payload semantics".into()],
            unknowns: vec!["handlers for post-startup IDs".into()],
        },
        ImplementationReadiness {
            component: "SignOn".into(),
            evidence_level: EvidenceClass::ExternalReference,
            offline_status: ImplStatus::Documented,
            readiness: Readiness::Blocked,
            understood: "DOCUMENTED".into(),
            implementable_offline: "NO (client not implemented)".into(),
            server_compatible: "NOT IMPLEMENTED".into(),
            blocked_by: vec!["production SignOn client".into()],
            unknowns: vec!["token formats beyond docs".into()],
        },
        ImplementationReadiness {
            component: "authentication".into(),
            evidence_level: EvidenceClass::Unknown,
            offline_status: ImplStatus::Unknown,
            readiness: Readiness::Blocked,
            understood: "LOW".into(),
            implementable_offline: "NO".into(),
            server_compatible: "NO".into(),
            blocked_by: vec!["SignOn".into(), "account services".into()],
            unknowns: vec!["auth flow semantics".into()],
        },
        ImplementationReadiness {
            component: "UDP".into(),
            evidence_level: EvidenceClass::Unknown,
            offline_status: ImplStatus::Unknown,
            readiness: Readiness::Blocked,
            understood: "LOW".into(),
            implementable_offline: "NO".into(),
            server_compatible: "NO".into(),
            blocked_by: vec!["no UDP evidence pipeline".into()],
            unknowns: vec!["gameplay transport".into()],
        },
        ImplementationReadiness {
            component: "gameplay".into(),
            evidence_level: EvidenceClass::Unknown,
            offline_status: ImplStatus::Unknown,
            readiness: Readiness::Blocked,
            understood: "LOW".into(),
            implementable_offline: "NO".into(),
            server_compatible: "NO".into(),
            blocked_by: vec!["UDP".into(), "world state".into()],
            unknowns: vec!["activity/world messages".into()],
        },
    ]
}

fn unknown_registry() -> Vec<UnknownEntry> {
    vec![
        UnknownEntry {
            id: "UNK-UDP".into(),
            description: "UDP/gameplay transport mechanics".into(),
            priority: UnknownPriority::High,
            blocks: "gameplay / multiplayer".into(),
        },
        UnknownEntry {
            id: "UNK-PAYLOAD".into(),
            description: "Payload field semantics for critical post-session messages".into(),
            priority: UnknownPriority::High,
            blocks: "message dispatch / local server responses".into(),
        },
        UnknownEntry {
            id: "UNK-SERVER-STATE".into(),
            description: "Server-side state expectations after startup".into(),
            priority: UnknownPriority::High,
            blocks: "interoperable local server".into(),
        },
        UnknownEntry {
            id: "UNK-CONTEXT".into(),
            description: "Meaning of BAP context u32".into(),
            priority: UnknownPriority::Medium,
            blocks: "correct request correlation".into(),
        },
        UnknownEntry {
            id: "UNK-KEEPALIVE-MS".into(),
            description: "Keepalive wall-clock period (frame_order only today)".into(),
            priority: UnknownPriority::Medium,
            blocks: "timing-accurate keepalive emulation".into(),
        },
        UnknownEntry {
            id: "UNK-AAD".into(),
            description: "AAD behavior beyond empty-in-verified-captures".into(),
            priority: UnknownPriority::Medium,
            blocks: "general GCM claims".into(),
        },
        UnknownEntry {
            id: "UNK-VARIABLE".into(),
            description: "Variable-length payload structures (e.g. 0x7B, 0xAB)".into(),
            priority: UnknownPriority::Medium,
            blocks: "full payload parsers".into(),
        },
        UnknownEntry {
            id: "UNK-CAPTURE-SPECIFIC".into(),
            description: "Capture-specific IDs (0x10/0x11/0x2A/0x2B) roles".into(),
            priority: UnknownPriority::Low,
            blocks: "complete message coverage".into(),
        },
        UnknownEntry {
            id: "UNK-PLATFORM".into(),
            description: "PS4/Xbox/PC protocol equivalence".into(),
            priority: UnknownPriority::High,
            blocks: "cross-platform claims".into(),
        },
        UnknownEntry {
            id: "UNK-REKEY".into(),
            description: "AES-GCM rekey / resync rules".into(),
            priority: UnknownPriority::Medium,
            blocks: "long-lived sessions".into(),
        },
    ]
}

/// Build deterministic protocol spec from two verified capture inventories.
pub fn build_protocol_spec(
    a: &CaptureMessageInventory,
    b: &CaptureMessageInventory,
) -> ProtocolSpec {
    let sm = build_state_machine(a, b);
    let oa = ordered_observations(a);
    let ob = ordered_observations(b);

    let messages: Vec<MessageSpecification> = EXPECTED_MESSAGE_IDS
        .iter()
        .map(|id| message_spec(*id, &oa, &ob, &sm))
        .collect();

    let evidence_samples = vec![
        ProtocolEvidence {
            source: "framing-bap.md / stream_framing.rs".into(),
            capture_id: None,
            message_id: None,
            direction: None,
            context: None,
            wire_length: None,
            payload_length: None,
            observation: "BAP [0x01][kind][body_len BE][body]".into(),
            classification: EvidenceClass::Confirmed,
            confidence: EvidenceClass::Confirmed,
        },
        ProtocolEvidence {
            source: "session-login-response.md".into(),
            capture_id: Some("20260529-003132".into()),
            message_id: Some("0x1A".into()),
            direction: Some("server_to_client".into()),
            context: Some(1),
            wire_length: None,
            payload_length: Some(86),
            observation: "CBC+HMAC validate; plaintext 28 unpadded".into(),
            classification: EvidenceClass::Confirmed,
            confidence: EvidenceClass::Confirmed,
        },
        ProtocolEvidence {
            source: "gcm-channel-validation.md / multi-capture".into(),
            capture_id: Some("20260529-003132+20260608-231100".into()),
            message_id: None,
            direction: None,
            context: None,
            wire_length: None,
            payload_length: None,
            observation: "124/124 and 122/122 encrypted decrypt VERIFIED cross-capture".into(),
            classification: EvidenceClass::Confirmed,
            confidence: EvidenceClass::Confirmed,
        },
        ProtocolEvidence {
            source: "state-machine.md".into(),
            capture_id: None,
            message_id: None,
            direction: None,
            context: None,
            wire_length: None,
            payload_length: None,
            observation: format!(
                "startup {} OBSERVED both captures",
                sm.startup.sequence_key
            ),
            classification: EvidenceClass::Observed,
            confidence: EvidenceClass::Observed,
        },
    ];

    let ids_a: Vec<u16> = oa.iter().map(|o| o.message_id).collect();
    let _pref = startup_prefix_len(&ids_a);
    let _ = (STATE_START, STATE_POST_STARTUP, STATE_REPEATING_CLUSTER_01);

    ProtocolSpec {
        version: SPEC_VERSION.into(),
        evidence_policy: "v0.1 engineering spec from observed evidence; not an official Bungie specification. CONFIRMED/OBSERVED only for validated facts; STRUCTURAL_HYPOTHESIS and EXTERNAL_REFERENCE kept separate; UNKNOWN remains UNKNOWN.".into(),
        captures: vec![a.capture_id.clone(), b.capture_id.clone()],
        framing: FramingSpec {
            magic: "0x01".into(),
            kind_encrypted: 1,
            kind_clear: 2,
            body_len_endian: "big-endian u32".into(),
            clear_layout: "[msg_id:u16 BE][context:u32 BE][payload...]".into(),
            encrypted_note: "kind=1 body opaque on wire; offline decrypt via SessionCryptoContext+AES-GCM after session material available".into(),
            max_body_len_impl: MAX_BODY_LEN,
            max_body_len_class: "IMPLEMENTATION_LIMIT".into(),
            classification: EvidenceClass::Confirmed,
        },
        crypto: CryptoSpec {
            session_login_0x1a: SessionLoginSpec {
                direction: "S2C".into(),
                kind: 2,
                context: 1,
                payload_len: 86,
                prefix_u16_be: 200,
                record_len_u32_be: 80,
                iv_len: 16,
                ciphertext_len: 32,
                hmac_len: 32,
                cipher: "AES-CBC PKCS#7".into(),
                hmac: "HMAC-SHA256".into(),
                hmac_input: "u32_be(record_len)||IV||ciphertext".into(),
                validated: "HMAC valid; AES-CBC decrypt ok; padding ok; plaintext 32; unpadded 28".into(),
                nonce_key_layout: "nonce[12]||session_key[16] candidate split".into(),
                nonce_key_layout_class: EvidenceClass::StructuralHypothesis,
                classification: EvidenceClass::Confirmed,
            },
            session_crypto_context: SessionCtxSpec {
                session_key_len: 16,
                session_nonce_len: 12,
                c2s_base: "session_nonce with last byte XOR 1".into(),
                s2c_base: "session_nonce identity".into(),
                counters: "independent C2S and S2C counters; first=base then increment".into(),
                classification: "CONFIRMED_FOR_VERIFIED_CAPTURES".into(),
            },
            aes_gcm: AesGcmSpec {
                algorithm: "AES-128-GCM".into(),
                key: "session key".into(),
                nonce_len: 12,
                aad_in_verified_captures: "empty".into(),
                aad_general: "AAD was empty in all currently verified frames. General AAD behavior remains UNKNOWN.".into(),
                first_frames: "0x79 body_len=22 (tag16+ct6); 0x7A body_len=24 (tag16+ct8)".into(),
                channel_validation: "8-frame startup GCM ok; full sessions 124/124 and 122/122 VERIFIED".into(),
                classification: EvidenceClass::Confirmed,
            },
            nonce_model: NonceSpec {
                model: "per-direction base + independent counters".into(),
                classification: "CONFIRMED_FOR_VERIFIED_CAPTURES".into(),
                not_universal: "Not elevated to UNIVERSAL_PROTOCOL_RULE (platforms/rekey UNKNOWN)".into(),
            },
        },
        startup_sequence: STABLE_STARTUP_SEQUENCE
            .iter()
            .map(|id| fmt_msg_id(*id))
            .collect(),
        state_machine_summary: StateMachineSummary {
            nodes: sm.graph.nodes.clone(),
            startup_label: sm.startup.structural_label.to_string(),
            divergence_index: sm.branches.divergence_index,
            repeating_cluster: sm.repeating_cluster.state_id.clone(),
            classification: EvidenceClass::Observed,
        },
        messages,
        evidence_samples,
        implementation_readiness: readiness_table(),
        unknowns: unknown_registry(),
        external_reference_note: "Names from messages.rs / message-matrix.md / d1-re docs are EXTERNAL_REFERENCE only.".into(),
    }
}

/// Safe JSON export document.
#[derive(Debug, Clone, Serialize)]
pub struct SafeProtocolSpecExport {
    pub version: String,
    pub evidence_policy: String,
    pub captures: Vec<String>,
    pub framing: FramingSpec,
    pub crypto: CryptoSpec,
    pub startup_sequence: Vec<String>,
    pub state_machine: StateMachineSummary,
    pub messages: Vec<MessageSpecification>,
    pub implementation_readiness: Vec<ImplementationReadiness>,
    pub unknowns: Vec<UnknownEntry>,
    pub external_reference_note: String,
    pub message_count: usize,
}

pub fn to_safe_export(spec: &ProtocolSpec) -> SafeProtocolSpecExport {
    SafeProtocolSpecExport {
        version: spec.version.clone(),
        evidence_policy: spec.evidence_policy.clone(),
        captures: spec.captures.clone(),
        framing: spec.framing.clone(),
        crypto: spec.crypto.clone(),
        startup_sequence: spec.startup_sequence.clone(),
        state_machine: spec.state_machine_summary.clone(),
        messages: spec.messages.clone(),
        implementation_readiness: spec.implementation_readiness.clone(),
        unknowns: spec.unknowns.clone(),
        external_reference_note: spec.external_reference_note.clone(),
        message_count: spec.messages.len(),
    }
}

/// Validate structural consistency of a built spec.
pub fn validate_spec(spec: &ProtocolSpec) -> Result<(), String> {
    if spec.version != SPEC_VERSION {
        return Err(format!("version mismatch {}", spec.version));
    }
    if spec.captures.len() != 2 {
        return Err("expected 2 captures".into());
    }
    if spec.messages.len() != EXPECTED_MESSAGE_IDS.len() {
        return Err(format!(
            "expected {} messages, got {}",
            EXPECTED_MESSAGE_IDS.len(),
            spec.messages.len()
        ));
    }
    let ids: BTreeSet<_> = spec.messages.iter().map(|m| m.message_id.clone()).collect();
    for id in EXPECTED_MESSAGE_IDS {
        let s = fmt_msg_id(*id);
        if !ids.contains(&s) {
            return Err(format!("missing message {s}"));
        }
    }
    if spec.startup_sequence.len() != STABLE_STARTUP_SEQUENCE.len() {
        return Err("startup sequence length".into());
    }
    for (i, id) in STABLE_STARTUP_SEQUENCE.iter().enumerate() {
        if spec.startup_sequence[i] != fmt_msg_id(*id) {
            return Err("startup sequence mismatch".into());
        }
    }
    if spec.crypto.aes_gcm.aad_general.contains("always empty") {
        return Err("AAD must not claim always empty".into());
    }
    if !spec.crypto.aes_gcm.aad_general.contains("UNKNOWN") {
        return Err("AAD general must remain UNKNOWN".into());
    }
    if spec.crypto.session_login_0x1a.nonce_key_layout_class != EvidenceClass::StructuralHypothesis
    {
        return Err("0x1A nonce/key layout must stay STRUCTURAL_HYPOTHESIS".into());
    }
    if spec.unknowns.is_empty() {
        return Err("unknown registry empty".into());
    }
    if spec.implementation_readiness.is_empty() {
        return Err("readiness empty".into());
    }
    // No secret-looking long hex blobs in serialized fields we control.
    let blob = serde_json::to_string(spec).map_err(|e| e.to_string())?;
    for needle in ["session_key_hex", "mac_key", "signon_token", "password"] {
        if blob.to_lowercase().contains(needle) {
            return Err(format!("possible secret field {needle}"));
        }
    }
    Ok(())
}
