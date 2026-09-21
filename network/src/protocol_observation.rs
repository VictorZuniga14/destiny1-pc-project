//! Observation classification levels (M4.8).
//!
//! Never auto-promotes Observed/Structural/Hypothesis → Confirmed.

use crate::observation::{is_known_codec_id, is_registry_id, ObservedFrame};
use crate::observation_scenarios::{confirmed_startup_ids, ScenarioKind};
use crate::state_machine::STABLE_STARTUP_SEQUENCE;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ObservationClass {
    Observed,
    Structural,
    Hypothesis,
    Confirmed,
    Unknown,
}

impl ObservationClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "Observed",
            Self::Structural => "Structural",
            Self::Hypothesis => "Hypothesis",
            Self::Confirmed => "Confirmed",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifiedObservation {
    pub frame_index: u64,
    pub message_id: Option<u16>,
    pub class: ObservationClass,
    pub rationale: String,
}

/// Classify a single observed frame. Confirmed only for IDs in the stable
/// startup sequence (already confirmed by M2.9/M3.4 evidence) when appearing
/// in expected structural roles — never auto-promotes unknowns.
pub fn classify_frame(frame: &ObservedFrame) -> ClassifiedObservation {
    let Some(id) = frame.message_id else {
        return ClassifiedObservation {
            frame_index: frame.frame_index,
            message_id: None,
            class: ObservationClass::Structural,
            rationale: "frame without message_id — structural only".into(),
        };
    };

    if STABLE_STARTUP_SEQUENCE.contains(&id) || matches!(id, 0xFA | 0xFB) {
        // Confirmed IDs from documented evidence — classification Confirmed for ID identity only.
        return ClassifiedObservation {
            frame_index: frame.frame_index,
            message_id: Some(id),
            class: ObservationClass::Confirmed,
            rationale: "message ID confirmed in project evidence registry/startup".into(),
        };
    }

    if is_known_codec_id(id) {
        return ClassifiedObservation {
            frame_index: frame.frame_index,
            message_id: Some(id),
            class: ObservationClass::Structural,
            rationale: "known codec ID; semantics not invented".into(),
        };
    }

    if is_registry_id(id) {
        return ClassifiedObservation {
            frame_index: frame.frame_index,
            message_id: Some(id),
            class: ObservationClass::Observed,
            rationale: "registry ID observed; meaning UNKNOWN".into(),
        };
    }

    ClassifiedObservation {
        frame_index: frame.frame_index,
        message_id: Some(id),
        class: ObservationClass::Unknown,
        rationale: "ID not in registry — remains Unknown".into(),
    }
}

pub fn classify_sequence(ids: &[u16], scenario: ScenarioKind) -> ObservationClass {
    match scenario {
        ScenarioKind::Startup => {
            let expected = confirmed_startup_ids();
            if ids == expected.as_slice() {
                ObservationClass::Confirmed
            } else if ids
                .iter()
                .all(|id| expected.contains(id) || matches!(id, 0xFA | 0xFB))
            {
                ObservationClass::Structural
            } else if ids.iter().any(|id| !is_registry_id(*id) && !is_known_codec_id(*id))
            {
                ObservationClass::Unknown
            } else {
                ObservationClass::Hypothesis
            }
        }
        ScenarioKind::ActiveKeepalive => {
            if ids.iter().all(|id| matches!(id, 0xFA | 0xFB)) {
                ObservationClass::Confirmed
            } else {
                ObservationClass::Hypothesis
            }
        }
        ScenarioKind::UnknownMessage => ObservationClass::Unknown,
        _ => ObservationClass::Observed,
    }
}
