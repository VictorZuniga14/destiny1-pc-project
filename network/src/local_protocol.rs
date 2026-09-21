//! Simulated local BAP protocol for M4.2 interoperability harness.
//!
//! **SIMULATED_HANDSHAKE** — not Bungie/Destiny handshake semantics.
//! Uses synthetic keys, synthetic payloads, and a harness-only state machine
//! (`SimState`) separate from the M3.4 observational states.

use crate::bap_session::DecodedBapFrame;
use crate::test_crypto_material::{
    SYNTHETIC_SESSION_KEY as CENTRAL_KEY, SYNTHETIC_SESSION_NONCE as CENTRAL_NONCE,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Synthetic AES-128 session key (16 bytes). Never a real capture key.
/// Re-exported from [`crate::test_crypto_material`] (SYNTHETIC_TEST_ONLY).
pub const SYNTHETIC_SESSION_KEY: [u8; 16] = CENTRAL_KEY;

/// Synthetic GCM base nonce (12 bytes). Never a real capture nonce.
pub const SYNTHETIC_SESSION_NONCE: [u8; 12] = CENTRAL_NONCE;

/// Shared synthetic context field for clear/encrypted test messages.
pub const SIM_CONTEXT: u32 = 1;

pub const MSG_1E: u16 = 0x1E;
pub const MSG_1F: u16 = 0x1F;
pub const MSG_19: u16 = 0x19;
pub const MSG_1A: u16 = 0x1A;
pub const MSG_79: u16 = 0x79;
pub const MSG_7A: u16 = 0x7A;
pub const MSG_FA: u16 = 0xFA;
pub const MSG_FB: u16 = 0xFB;
pub const MSG_12E: u16 = 0x12E;
pub const MSG_12F: u16 = 0x12F;
/// Post-handshake synthetic encrypted request A.
pub const MSG_SYN_A: u16 = 0x0A0A;
/// Post-handshake synthetic encrypted response A.
pub const MSG_SYN_A_RSP: u16 = 0x0A0B;
/// Post-handshake synthetic encrypted request B.
pub const MSG_SYN_B: u16 = 0x0B0B;
/// Post-handshake synthetic encrypted response B.
pub const MSG_SYN_B_RSP: u16 = 0x0B0C;

pub const PAYLOAD_1E: &[u8] = b"SIM_1E";
pub const PAYLOAD_1F: &[u8] = b"SIM_1F";
pub const PAYLOAD_19: &[u8] = b"SIM_19";
pub const PAYLOAD_1A: &[u8] = b"SIM_1A";
pub const PAYLOAD_79: &[u8] = b"SIM_79";
pub const PAYLOAD_7A: &[u8] = b"SIM_7A";
pub const PAYLOAD_FA: &[u8] = b"SIM_FA";
pub const PAYLOAD_FB: &[u8] = b"SIM_FB";
pub const PAYLOAD_SYN_A: &[u8] = b"SYN_ENC_A";
pub const PAYLOAD_SYN_A_RSP: &[u8] = b"SYN_RSP_A";
pub const PAYLOAD_SYN_B: &[u8] = b"SYN_ENC_B";
pub const PAYLOAD_SYN_B_RSP: &[u8] = b"SYN_RSP_B";

/// Harness-only simulated handshake states (not M3.4 observational SM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SimState {
    SimStart,
    Sim1eSent,
    Sim1fSent,
    Sim19Sent,
    Sim1aSent,
    Sim79Sent,
    Sim7aSent,
    SimReady,
}

impl SimState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SimStart => "SIM_START",
            Self::Sim1eSent => "SIM_1E_SENT",
            Self::Sim1fSent => "SIM_1F_SENT",
            Self::Sim19Sent => "SIM_19_SENT",
            Self::Sim1aSent => "SIM_1A_SENT",
            Self::Sim79Sent => "SIM_79_SENT",
            Self::Sim7aSent => "SIM_7A_SENT",
            Self::SimReady => "SIM_READY",
        }
    }
}

impl Default for SimState {
    fn default() -> Self {
        Self::SimStart
    }
}

/// Wire direction relative to the local test harness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalDirection {
    C2S,
    S2C,
}

impl LocalDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::C2S => "C2S",
            Self::S2C => "S2C",
        }
    }
}

/// Dispatcher / server outcomes (no gameplay handlers).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerAction {
    SendClear {
        msg_id: u16,
        context: u32,
        payload: Vec<u8>,
    },
    SendEncrypted {
        msg_id: u16,
        context: u32,
        payload: Vec<u8>,
    },
    ChangeState(SimState),
    CloseConnection,
    Ignore,
    ProtocolError {
        kind: ProtocolErrorKind,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtocolErrorKind {
    UnexpectedMessage,
    AuthCryptoError,
    GcmDecryptFailure,
    ProtocolError,
    InvalidFrame,
}

impl ProtocolErrorKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::UnexpectedMessage => "UNEXPECTED_MESSAGE",
            Self::AuthCryptoError => "AUTH/CRYPTO ERROR",
            Self::GcmDecryptFailure => "GCM DECRYPT FAILURE",
            Self::ProtocolError => "PROTOCOL_ERROR",
            Self::InvalidFrame => "INVALID_FRAME",
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LocalProtocolError {
    #[error("{0}")]
    Protocol(String),
}

/// Structured observability event (timestamp optional; tests ignore it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerTraceEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
    pub connection_id: u64,
    pub direction: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<u32>,
    pub state: String,
    pub action: String,
}

impl ServerTraceEvent {
    pub fn without_timestamp(&self) -> Self {
        let mut c = self.clone();
        c.timestamp = None;
        c
    }
}

/// Local message dispatcher for the simulated handshake + post-ready synthetic msgs.
#[derive(Debug, Default)]
pub struct LocalMessageDispatcher {
    pub state: SimState,
    /// After `0x1A`, encrypted frames are expected.
    pub crypto_expected: bool,
}

impl LocalMessageDispatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> SimState {
        self.state
    }

    /// Dispatch one inbound (C2S) decoded frame; returns ordered actions.
    pub fn dispatch_inbound(&mut self, frame: &DecodedBapFrame) -> Vec<ServerAction> {
        match frame {
            DecodedBapFrame::Clear {
                msg_id,
                context: _,
                payload: _,
            } => self.dispatch_clear(*msg_id),
            DecodedBapFrame::Decrypted {
                msg_id,
                context: _,
                payload: _,
                plaintext_len: _,
            } => match msg_id {
                Some(id) => self.dispatch_encrypted(*id),
                None => vec![ServerAction::ProtocolError {
                    kind: ProtocolErrorKind::ProtocolError,
                    detail: "encrypted plaintext too short for msg_id".into(),
                }],
            },
            DecodedBapFrame::Opaque { kind, .. } => vec![ServerAction::ProtocolError {
                kind: ProtocolErrorKind::InvalidFrame,
                detail: format!("opaque/unsupported kind 0x{kind:02x}"),
            }],
        }
    }

    fn dispatch_clear(&mut self, msg_id: u16) -> Vec<ServerAction> {
        match (self.state, msg_id) {
            (SimState::SimStart, MSG_1E) => {
                self.state = SimState::Sim1fSent;
                vec![
                    ServerAction::ChangeState(SimState::Sim1eSent),
                    ServerAction::SendClear {
                        msg_id: MSG_1F,
                        context: SIM_CONTEXT,
                        payload: PAYLOAD_1F.to_vec(),
                    },
                    ServerAction::ChangeState(SimState::Sim1fSent),
                ]
            }
            (SimState::Sim1fSent, MSG_19) => {
                self.state = SimState::Sim1aSent;
                self.crypto_expected = true;
                vec![
                    ServerAction::ChangeState(SimState::Sim19Sent),
                    ServerAction::SendClear {
                        msg_id: MSG_1A,
                        context: SIM_CONTEXT,
                        payload: PAYLOAD_1A.to_vec(),
                    },
                    ServerAction::ChangeState(SimState::Sim1aSent),
                ]
            }
            _ => vec![ServerAction::ProtocolError {
                kind: ProtocolErrorKind::UnexpectedMessage,
                detail: format!(
                    "unexpected clear 0x{msg_id:04x} in {}",
                    self.state.as_str()
                ),
            }],
        }
    }

    fn dispatch_encrypted(&mut self, msg_id: u16) -> Vec<ServerAction> {
        match (self.state, msg_id) {
            (SimState::Sim1aSent, MSG_79) => {
                self.state = SimState::SimReady;
                vec![
                    ServerAction::ChangeState(SimState::Sim79Sent),
                    ServerAction::SendEncrypted {
                        msg_id: MSG_7A,
                        context: SIM_CONTEXT,
                        payload: PAYLOAD_7A.to_vec(),
                    },
                    ServerAction::ChangeState(SimState::Sim7aSent),
                    ServerAction::ChangeState(SimState::SimReady),
                ]
            }
            (SimState::SimReady, MSG_SYN_A) => {
                vec![ServerAction::SendEncrypted {
                    msg_id: MSG_SYN_A_RSP,
                    context: SIM_CONTEXT,
                    payload: PAYLOAD_SYN_A_RSP.to_vec(),
                }]
            }
            (SimState::SimReady, MSG_SYN_B) => {
                vec![ServerAction::SendEncrypted {
                    msg_id: MSG_SYN_B_RSP,
                    context: SIM_CONTEXT,
                    payload: PAYLOAD_SYN_B_RSP.to_vec(),
                }]
            }
            (_, MSG_7A) => vec![ServerAction::ProtocolError {
                kind: ProtocolErrorKind::UnexpectedMessage,
                detail: format!("0x7A before 0x79 (state {})", self.state.as_str()),
            }],
            _ => vec![ServerAction::ProtocolError {
                kind: ProtocolErrorKind::UnexpectedMessage,
                detail: format!(
                    "unexpected encrypted 0x{msg_id:04x} in {}",
                    self.state.as_str()
                ),
            }],
        }
    }
}

/// Replay fixture step (synthetic only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayStep {
    pub direction: String,
    pub id: String,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub payload_hex: Option<String>,
    #[serde(default)]
    pub context: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakeReplayFixture {
    pub name: String,
    pub protocol: String,
    pub steps: Vec<ReplayStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoFixture {
    pub name: String,
    pub session_key_hex: String,
    pub session_nonce_hex: String,
    pub note: String,
}

impl CryptoFixture {
    pub fn synthetic_default() -> Self {
        Self {
            name: "synthetic-local-server".into(),
            session_key_hex: hex_encode(&SYNTHETIC_SESSION_KEY),
            session_nonce_hex: hex_encode(&SYNTHETIC_SESSION_NONCE),
            note: "SYNTHETIC ONLY — not from captures; never print decoded key/nonce in logs"
                .into(),
        }
    }

    pub fn key_bytes(&self) -> Result<Vec<u8>, LocalProtocolError> {
        hex_decode(&self.session_key_hex)
    }

    pub fn nonce_bytes(&self) -> Result<Vec<u8>, LocalProtocolError> {
        hex_decode(&self.session_nonce_hex)
    }
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Result<Vec<u8>, LocalProtocolError> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(LocalProtocolError::Protocol(
            "odd hex length".into(),
        ));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let chars: Vec<char> = s.chars().collect();
    for i in (0..chars.len()).step_by(2) {
        let byte = u8::from_str_radix(&format!("{}{}", chars[i], chars[i + 1]), 16)
            .map_err(|e| LocalProtocolError::Protocol(e.to_string()))?;
        out.push(byte);
    }
    Ok(out)
}

pub fn parse_msg_id(s: &str) -> Result<u16, LocalProtocolError> {
    let t = s.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16).map_err(|e| LocalProtocolError::Protocol(e.to_string()))
    } else {
        t.parse::<u16>()
            .map_err(|e| LocalProtocolError::Protocol(e.to_string()))
    }
}

pub fn payload_for_msg(msg_id: u16) -> &'static [u8] {
    match msg_id {
        MSG_1E => PAYLOAD_1E,
        MSG_1F => PAYLOAD_1F,
        MSG_19 => PAYLOAD_19,
        MSG_1A => PAYLOAD_1A,
        MSG_79 => PAYLOAD_79,
        MSG_7A => PAYLOAD_7A,
        MSG_SYN_A => PAYLOAD_SYN_A,
        MSG_SYN_A_RSP => PAYLOAD_SYN_A_RSP,
        MSG_SYN_B => PAYLOAD_SYN_B,
        MSG_SYN_B_RSP => PAYLOAD_SYN_B_RSP,
        _ => b"SIM_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_key_lengths() {
        assert_eq!(SYNTHETIC_SESSION_KEY.len(), 16);
        assert_eq!(SYNTHETIC_SESSION_NONCE.len(), 12);
    }

    #[test]
    fn dispatcher_rejects_7a_before_79() {
        let mut d = LocalMessageDispatcher::new();
        // Force state past start without 79
        d.state = SimState::Sim1aSent;
        let frame = DecodedBapFrame::Decrypted {
            msg_id: Some(MSG_7A),
            context: Some(SIM_CONTEXT),
            payload: PAYLOAD_7A.to_vec(),
            plaintext_len: 6 + PAYLOAD_7A.len(),
        };
        let actions = d.dispatch_inbound(&frame);
        assert!(matches!(
            actions.first(),
            Some(ServerAction::ProtocolError {
                kind: ProtocolErrorKind::UnexpectedMessage,
                ..
            })
        ));
    }
}
