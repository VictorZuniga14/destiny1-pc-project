//! Local response policy (M4.5) — deterministic synthetic replies only.
//!
//! Does not invent responses for unknown messages. Not Bungie semantics.

use crate::local_protocol::{
    PAYLOAD_1A, PAYLOAD_1F, PAYLOAD_7A, PAYLOAD_FB, PAYLOAD_SYN_A_RSP, PAYLOAD_SYN_B_RSP,
    SIM_CONTEXT, MSG_1A, MSG_1F, MSG_7A, MSG_FB, MSG_SYN_A, MSG_SYN_A_RSP, MSG_SYN_B,
    MSG_SYN_B_RSP,
};
use crate::message_codec::BapMessage;
use crate::protocol_state::ProtocolState;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnknownPolicy {
    Observe,
    Reject,
}

impl Default for UnknownPolicy {
    fn default() -> Self {
        Self::Observe
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseAction {
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
    ObserveOnly,
    Reject,
    None,
}

#[derive(Debug, Clone)]
pub struct ResponsePolicy {
    pub unknown: UnknownPolicy,
    /// When true, reply to synthetic 0xFA with 0xFB (optional keepalive).
    pub keepalive_reply: bool,
}

impl Default for ResponsePolicy {
    fn default() -> Self {
        Self {
            unknown: UnknownPolicy::Observe,
            keepalive_reply: true,
        }
    }
}

impl ResponsePolicy {
    /// Decide response from **current state before transition** + inbound message.
    pub fn decide(&self, state: ProtocolState, message: &BapMessage) -> ResponseAction {
        let id = message.id();
        match (state, id) {
            (ProtocolState::WaitingForServiceHandshake, 0x1E) => ResponseAction::SendClear {
                msg_id: MSG_1F,
                context: SIM_CONTEXT,
                payload: PAYLOAD_1F.to_vec(),
            },
            (
                ProtocolState::ServiceHandshakeComplete | ProtocolState::WaitingForSessionLogin,
                0x19,
            ) => ResponseAction::SendClear {
                msg_id: MSG_1A,
                context: SIM_CONTEXT,
                payload: PAYLOAD_1A.to_vec(),
            },
            (ProtocolState::SessionEstablished, 0x79) => ResponseAction::SendEncrypted {
                msg_id: MSG_7A,
                context: SIM_CONTEXT,
                payload: PAYLOAD_7A.to_vec(),
            },
            (
                ProtocolState::EncryptedChannelEstablished | ProtocolState::Active,
                0xFA,
            ) if self.keepalive_reply => ResponseAction::SendClear {
                msg_id: MSG_FB,
                context: message.context(),
                payload: PAYLOAD_FB.to_vec(),
            },
            // M4.2 synthetic encrypted A/B after ready.
            (ProtocolState::EncryptedChannelEstablished | ProtocolState::Active, MSG_SYN_A) => {
                ResponseAction::SendEncrypted {
                    msg_id: MSG_SYN_A_RSP,
                    context: SIM_CONTEXT,
                    payload: PAYLOAD_SYN_A_RSP.to_vec(),
                }
            }
            (ProtocolState::EncryptedChannelEstablished | ProtocolState::Active, MSG_SYN_B) => {
                ResponseAction::SendEncrypted {
                    msg_id: MSG_SYN_B_RSP,
                    context: SIM_CONTEXT,
                    payload: PAYLOAD_SYN_B_RSP.to_vec(),
                }
            }
            (ProtocolState::EncryptedChannelEstablished | ProtocolState::Active, 0x12E | 0x12F) => {
                ResponseAction::ObserveOnly
            }
            (ProtocolState::EncryptedChannelEstablished | ProtocolState::Active, _) => {
                if message.is_known() {
                    ResponseAction::ObserveOnly
                } else {
                    match self.unknown {
                        UnknownPolicy::Observe => ResponseAction::ObserveOnly,
                        UnknownPolicy::Reject => ResponseAction::Reject,
                    }
                }
            }
            _ => {
                // Invalid sequence: policy does not invent a reply.
                ResponseAction::None
            }
        }
    }
}

/// Safe metadata for fixtures (no payloads with secrets — synthetic ASCII only labeled).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafePolicyStep {
    pub state: String,
    pub inbound_id: String,
    pub action: String,
    pub response_id: Option<String>,
}

pub fn describe_action(action: &ResponseAction) -> SafePolicyStep {
    match action {
        ResponseAction::SendClear { msg_id, .. } => SafePolicyStep {
            state: String::new(),
            inbound_id: String::new(),
            action: "SendClear".into(),
            response_id: Some(format!("0x{msg_id:04x}")),
        },
        ResponseAction::SendEncrypted { msg_id, .. } => SafePolicyStep {
            state: String::new(),
            inbound_id: String::new(),
            action: "SendEncrypted".into(),
            response_id: Some(format!("0x{msg_id:04x}")),
        },
        ResponseAction::ObserveOnly => SafePolicyStep {
            state: String::new(),
            inbound_id: String::new(),
            action: "ObserveOnly".into(),
            response_id: None,
        },
        ResponseAction::Reject => SafePolicyStep {
            state: String::new(),
            inbound_id: String::new(),
            action: "Reject".into(),
            response_id: None,
        },
        ResponseAction::None => SafePolicyStep {
            state: String::new(),
            inbound_id: String::new(),
            action: "None".into(),
            response_id: None,
        },
    }
}

/// Direction used when building synthetic outbound envelopes for codec.
pub fn outbound_direction() -> crate::jsonl::Direction {
    crate::jsonl::Direction::ServerToClient
}
