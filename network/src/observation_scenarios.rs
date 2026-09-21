//! Reference observation scenarios from confirmed project evidence (M4.8).

use crate::state_machine::STABLE_STARTUP_SEQUENCE;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScenarioKind {
    Startup,
    SessionEstablishment,
    EncryptedHandshake,
    ActiveKeepalive,
    UnknownMessage,
}

impl ScenarioKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::SessionEstablishment => "session_establishment",
            Self::EncryptedHandshake => "encrypted_handshake",
            Self::ActiveKeepalive => "active_keepalive",
            Self::UnknownMessage => "unknown_message",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceScenario {
    pub kind: ScenarioKind,
    pub name: String,
    /// Expected message ID sequence (C2S/S2C interleaved as observed historically).
    pub expected_ids: Vec<u16>,
    pub notes: Vec<String>,
}

pub fn confirmed_startup_ids() -> Vec<u16> {
    STABLE_STARTUP_SEQUENCE.to_vec()
}

pub fn scenario_startup() -> ReferenceScenario {
    ReferenceScenario {
        kind: ScenarioKind::Startup,
        name: "startup".into(),
        expected_ids: confirmed_startup_ids(),
        notes: vec![
            "STABLE_STARTUP_SEQUENCE from M2.9/M3.4 — local reference only.".into(),
            "Divergence does not automatically mean client error.".into(),
        ],
    }
}

pub fn scenario_session_establishment() -> ReferenceScenario {
    ReferenceScenario {
        kind: ScenarioKind::SessionEstablishment,
        name: "session_establishment".into(),
        expected_ids: vec![0x1E, 0x1F, 0x19, 0x1A],
        notes: vec!["Clear handshake portion of confirmed startup.".into()],
    }
}

pub fn scenario_encrypted_handshake() -> ReferenceScenario {
    ReferenceScenario {
        kind: ScenarioKind::EncryptedHandshake,
        name: "encrypted_handshake".into(),
        expected_ids: vec![0x79, 0x7A],
        notes: vec!["Encrypted handshake IDs from confirmed evidence.".into()],
    }
}

pub fn scenario_active_keepalive() -> ReferenceScenario {
    ReferenceScenario {
        kind: ScenarioKind::ActiveKeepalive,
        name: "active_keepalive".into(),
        expected_ids: vec![0xFA, 0xFB],
        notes: vec![
            "0xFA/0xFB observed; intervals are observational only — not universal.".into(),
        ],
    }
}

pub fn scenario_unknown_message() -> ReferenceScenario {
    ReferenceScenario {
        kind: ScenarioKind::UnknownMessage,
        name: "unknown_message".into(),
        expected_ids: vec![],
        notes: vec!["Any non-registry ID remains Unknown — no invented semantics.".into()],
    }
}

pub fn all_scenarios() -> Vec<ReferenceScenario> {
    vec![
        scenario_startup(),
        scenario_session_establishment(),
        scenario_encrypted_handshake(),
        scenario_active_keepalive(),
        scenario_unknown_message(),
    ]
}
