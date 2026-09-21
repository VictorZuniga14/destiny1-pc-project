//! Real client observation harness core types (M4.8).
//!
//! Metadata-only observation of BAP structural behaviour. Does **not** connect
//! to Bungie/Destiny, store secrets, or invent message semantics.

use crate::external_client_boundary::ExternalBoundaryEvent;
use crate::message_codec::has_known_codec;
use crate::messages::lookup_name;
use crate::protocol_spec::EXPECTED_MESSAGE_IDS;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const TRACE_VERSION: &str = "1";

/// Non-reversible payload fingerprint for correlation only.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SafeFingerprint(pub String);

impl SafeFingerprint {
    /// Hash of provided bytes — not recoverable to payload.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(b"destiny1-obs-fp-v1|");
        h.update(bytes);
        let out = h.finalize();
        Self(hex_encode(&out[..16])) // truncated hex for stable compact id
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedFrame {
    pub connection_id: u64,
    pub frame_index: u64,
    pub direction: String,
    pub kind: u8,
    pub body_len: usize,
    #[serde(default)]
    pub message_id: Option<u16>,
    #[serde(default)]
    pub protocol_state: Option<String>,
    #[serde(default)]
    pub relative_time_ms: Option<u64>,
    #[serde(default)]
    pub fingerprint: Option<SafeFingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObservationEvent {
    ConnectionStarted { connection_id: u64 },
    FrameObserved { frame: ObservedFrame },
    StateObserved {
        connection_id: u64,
        protocol_state: String,
    },
    ProtocolMismatch {
        connection_id: u64,
        detail: String,
    },
    ConnectionClosed {
        connection_id: u64,
        reason: String,
    },
    ObservationError {
        connection_id: Option<u64>,
        detail: String,
    },
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ObservationError {
    #[error("sensitive field rejected: {0}")]
    SensitiveField(String),
    #[error("invalid trace: {0}")]
    InvalidTrace(String),
    #[error("io: {0}")]
    Io(String),
    #[error("json: {0}")]
    Json(String),
}

/// Fields that must never enter the observation model.
pub const SENSITIVE_FIELD_NAMES: &[&str] = &[
    "key",
    "session_key",
    "session_key_hex",
    "token",
    "credential",
    "credentials",
    "password",
    "authorization",
    "private_key",
    "secret",
    "hmac",
    "ciphertext",
    "plaintext",
    "payload",
    "payload_hex",
    "nonce",
    "session_nonce",
    "session_nonce_hex",
];

pub fn is_sensitive_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    SENSITIVE_FIELD_NAMES
        .iter()
        .any(|s| k == *s || k.contains(s))
}

/// Source of observation events (fixtures / boundary — no external sockets).
pub trait ObservationSource {
    fn events(&self) -> Result<Vec<ObservationEvent>, ObservationError>;
}

/// Fixture-driven source: load a safe JSON observation list.
pub struct FixtureObservationSource {
    pub events: Vec<ObservationEvent>,
}

impl ObservationSource for FixtureObservationSource {
    fn events(&self) -> Result<Vec<ObservationEvent>, ObservationError> {
        Ok(self.events.clone())
    }
}

/// Convert M4.7 safe boundary events into observation events.
pub struct BoundaryEventSource {
    pub events: Vec<ExternalBoundaryEvent>,
}

impl ObservationSource for BoundaryEventSource {
    fn events(&self) -> Result<Vec<ObservationEvent>, ObservationError> {
        Ok(boundary_events_to_observation(&self.events))
    }
}

pub fn boundary_events_to_observation(events: &[ExternalBoundaryEvent]) -> Vec<ObservationEvent> {
    let mut out = Vec::new();
    for e in events {
        match e {
            ExternalBoundaryEvent::ConnectionAccepted { connection_id } => {
                out.push(ObservationEvent::ConnectionStarted {
                    connection_id: *connection_id,
                });
            }
            ExternalBoundaryEvent::FrameRecovered {
                connection_id,
                frame_index,
                direction,
                kind,
                body_len,
            } => {
                out.push(ObservationEvent::FrameObserved {
                    frame: ObservedFrame {
                        connection_id: *connection_id,
                        frame_index: *frame_index,
                        direction: direction.clone(),
                        kind: *kind,
                        body_len: *body_len,
                        message_id: None,
                        protocol_state: None,
                        relative_time_ms: None,
                        fingerprint: None,
                    },
                });
            }
            ExternalBoundaryEvent::ProtocolEvent {
                connection_id,
                protocol_state,
                label,
            } => {
                out.push(ObservationEvent::StateObserved {
                    connection_id: *connection_id,
                    protocol_state: protocol_state.clone(),
                });
                if label.contains("Rejected") || label.contains("Mismatch") {
                    out.push(ObservationEvent::ProtocolMismatch {
                        connection_id: *connection_id,
                        detail: label.clone(),
                    });
                }
            }
            ExternalBoundaryEvent::ConnectionClosed {
                connection_id,
                reason,
            } => {
                out.push(ObservationEvent::ConnectionClosed {
                    connection_id: *connection_id,
                    reason: reason.clone(),
                });
            }
            ExternalBoundaryEvent::FrameRejected {
                connection_id,
                category,
                detail,
            }
            | ExternalBoundaryEvent::ConnectionError {
                connection_id,
                category,
                detail,
            } => {
                out.push(ObservationEvent::ObservationError {
                    connection_id: Some(*connection_id),
                    detail: format!("{category}:{detail}"),
                });
            }
            ExternalBoundaryEvent::BytesReceived { .. } => {}
        }
    }
    out
}

pub fn message_id_label(id: u16) -> String {
    format!("0x{id:04X}")
}

pub fn is_registry_id(id: u16) -> bool {
    EXPECTED_MESSAGE_IDS.contains(&id)
}

pub fn is_known_codec_id(id: u16) -> bool {
    has_known_codec(id)
}

pub fn external_name(id: u16) -> Option<&'static str> {
    lookup_name(id)
}
