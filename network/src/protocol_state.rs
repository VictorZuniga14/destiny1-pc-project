//! Local server execution state machine (M4.5).
//!
//! This is a **local implementation policy** for deterministic localhost testing.
//! It is **NOT** claimed to represent Bungie's internal server state machine.
//! Separate from the M3.4 observational state machine (`state_machine.rs`).

use crate::jsonl::Direction;
use crate::message_codec::BapMessage;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Explicit local protocol execution states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProtocolState {
    Connected,
    WaitingForServiceHandshake,
    ServiceHandshakeComplete,
    WaitingForSessionLogin,
    SessionEstablished,
    WaitingForEncryptedHandshake,
    EncryptedChannelEstablished,
    Active,
    Closing,
    Closed,
}

impl ProtocolState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connected => "CONNECTED",
            Self::WaitingForServiceHandshake => "WAITING_FOR_SERVICE_HANDSHAKE",
            Self::ServiceHandshakeComplete => "SERVICE_HANDSHAKE_COMPLETE",
            Self::WaitingForSessionLogin => "WAITING_FOR_SESSION_LOGIN",
            Self::SessionEstablished => "SESSION_ESTABLISHED",
            Self::WaitingForEncryptedHandshake => "WAITING_FOR_ENCRYPTED_HANDSHAKE",
            Self::EncryptedChannelEstablished => "ENCRYPTED_CHANNEL_ESTABLISHED",
            Self::Active => "ACTIVE",
            Self::Closing => "CLOSING",
            Self::Closed => "CLOSED",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }

    pub fn crypto_expected(self) -> bool {
        matches!(
            self,
            Self::WaitingForEncryptedHandshake
                | Self::EncryptedChannelEstablished
                | Self::Active
        )
    }
}

impl Default for ProtocolState {
    fn default() -> Self {
        Self::Connected
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProtocolStateError {
    #[error("unexpected message 0x{0:04x}")]
    UnexpectedMessage(u16),
    #[error("invalid direction for message 0x{id:04x}")]
    InvalidDirection { id: u16 },
    #[error("invalid state {0}")]
    InvalidState(&'static str),
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    #[error("crypto not established")]
    CryptoNotEstablished,
    #[error("handshake incomplete")]
    HandshakeIncomplete,
    #[error("already closed")]
    AlreadyClosed,
    #[error("invalid transition: {0}")]
    InvalidTransition(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionResult {
    Advanced {
        from: ProtocolState,
        to: ProtocolState,
    },
    Observed {
        state: ProtocolState,
    },
    Rejected {
        reason: ProtocolStateError,
    },
}

impl TransitionResult {
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    pub fn as_event_label(&self) -> &'static str {
        match self {
            Self::Advanced { .. } => "StateTransition",
            Self::Observed { .. } => "MessageObserved",
            Self::Rejected { .. } => "MessageRejected",
        }
    }
}

/// Expected client→server direction for handshake IDs under local policy.
fn expected_c2s(id: u16) -> bool {
    matches!(id, 0x1E | 0x19 | 0x79 | 0x12E | 0xFA | 0x0A | 0x0C)
}

fn expected_s2c(id: u16) -> bool {
    matches!(id, 0x1F | 0x1A | 0x7A | 0x12F | 0xFB | 0x0B | 0x0D)
}

/// Central transition authority — only place that advances [`ProtocolState`].
pub fn transition(
    state: ProtocolState,
    message: &BapMessage,
) -> TransitionResult {
    if matches!(state, ProtocolState::Closed) {
        return TransitionResult::Rejected {
            reason: ProtocolStateError::AlreadyClosed,
        };
    }
    if matches!(state, ProtocolState::Closing) {
        return TransitionResult::Rejected {
            reason: ProtocolStateError::AlreadyClosed,
        };
    }

    let id = message.id();
    let dir = message.direction();

    // Direction checks for known handshake / keepalive IDs.
    if expected_c2s(id) && dir != Direction::ClientToServer {
        return TransitionResult::Rejected {
            reason: ProtocolStateError::InvalidDirection { id },
        };
    }
    if expected_s2c(id) && dir != Direction::ServerToClient {
        // Inbound on server is always C2S; S2C-only IDs as inbound are invalid.
        return TransitionResult::Rejected {
            reason: ProtocolStateError::InvalidDirection { id },
        };
    }

    match (state, id) {
        // Accept / connected → wait for 0x1E
        (ProtocolState::Connected, _) => {
            // Auto-enter waiting on first evaluation from Connected via begin().
            TransitionResult::Rejected {
                reason: ProtocolStateError::InvalidState(
                    "use begin_waiting_for_handshake first",
                ),
            }
        }

        (ProtocolState::WaitingForServiceHandshake, 0x1E) => TransitionResult::Advanced {
            from: state,
            to: ProtocolState::ServiceHandshakeComplete,
        },
        (ProtocolState::WaitingForServiceHandshake, id) if is_sequenced_id(id) => {
            TransitionResult::Rejected {
                reason: ProtocolStateError::UnexpectedMessage(id),
            }
        }
        (ProtocolState::WaitingForServiceHandshake, _) => TransitionResult::Observed { state },

        (ProtocolState::ServiceHandshakeComplete, 0x19)
        | (ProtocolState::WaitingForSessionLogin, 0x19) => TransitionResult::Advanced {
            from: state,
            to: ProtocolState::SessionEstablished,
        },
        (ProtocolState::ServiceHandshakeComplete, id)
        | (ProtocolState::WaitingForSessionLogin, id)
            if is_sequenced_id(id) =>
        {
            TransitionResult::Rejected {
                reason: ProtocolStateError::UnexpectedMessage(id),
            }
        }
        (ProtocolState::ServiceHandshakeComplete, _)
        | (ProtocolState::WaitingForSessionLogin, _) => TransitionResult::Observed { state },

        (ProtocolState::SessionEstablished, 0x79) => TransitionResult::Advanced {
            from: state,
            to: ProtocolState::WaitingForEncryptedHandshake,
        },
        (ProtocolState::SessionEstablished, id) if is_sequenced_id(id) => {
            TransitionResult::Rejected {
                reason: ProtocolStateError::UnexpectedMessage(id),
            }
        }
        (ProtocolState::SessionEstablished, _) => TransitionResult::Observed { state },

        (ProtocolState::WaitingForEncryptedHandshake, 0x7A) => TransitionResult::Rejected {
            reason: ProtocolStateError::UnexpectedMessage(0x7A),
        },
        (ProtocolState::WaitingForEncryptedHandshake, id) if is_sequenced_id(id) => {
            TransitionResult::Rejected {
                reason: ProtocolStateError::UnexpectedMessage(id),
            }
        }
        (ProtocolState::WaitingForEncryptedHandshake, _) => TransitionResult::Observed { state },

        (
            ProtocolState::EncryptedChannelEstablished | ProtocolState::Active,
            0x12E | 0x12F | 0xFA | 0xFB | 0x0A | 0x0B | 0x0C | 0x0D,
        ) => {
            let to = ProtocolState::Active;
            if state == to {
                TransitionResult::Observed { state }
            } else {
                TransitionResult::Advanced { from: state, to }
            }
        }
        (ProtocolState::EncryptedChannelEstablished | ProtocolState::Active, _) => {
            TransitionResult::Observed {
                state: ProtocolState::Active,
            }
        }

        _ => TransitionResult::Rejected {
            reason: ProtocolStateError::UnexpectedMessage(id),
        },
    }
}

/// IDs that participate in the local handshake sequence policy.
fn is_sequenced_id(id: u16) -> bool {
    matches!(
        id,
        0x1E | 0x1F | 0x19 | 0x1A | 0x79 | 0x7A | 0x12E | 0x12F | 0xFA | 0xFB
    )
}

/// Move Connected → WaitingForServiceHandshake (connection accept).
pub fn begin_waiting_for_handshake(state: ProtocolState) -> Result<ProtocolState, ProtocolStateError> {
    match state {
        ProtocolState::Connected => Ok(ProtocolState::WaitingForServiceHandshake),
        ProtocolState::WaitingForServiceHandshake => Ok(state),
        ProtocolState::Closed | ProtocolState::Closing => Err(ProtocolStateError::AlreadyClosed),
        _ => Err(ProtocolStateError::InvalidTransition(
            "handshake already started".into(),
        )),
    }
}

/// Server completed sending synthetic 0x7A.
pub fn complete_encrypted_handshake(
    state: ProtocolState,
) -> Result<ProtocolState, ProtocolStateError> {
    match state {
        ProtocolState::WaitingForEncryptedHandshake => {
            Ok(ProtocolState::EncryptedChannelEstablished)
        }
        ProtocolState::EncryptedChannelEstablished | ProtocolState::Active => Ok(state),
        _ => Err(ProtocolStateError::HandshakeIncomplete),
    }
}

pub fn begin_closing(state: ProtocolState) -> ProtocolState {
    if matches!(state, ProtocolState::Closed) {
        ProtocolState::Closed
    } else {
        ProtocolState::Closing
    }
}

pub fn close(_state: ProtocolState) -> ProtocolState {
    ProtocolState::Closed
}

/// Apply an Advanced transition; no-op for Observed; Err for Rejected.
pub fn apply_transition(
    _state: ProtocolState,
    result: &TransitionResult,
) -> Result<ProtocolState, ProtocolStateError> {
    match result {
        TransitionResult::Advanced { to, .. } => Ok(*to),
        TransitionResult::Observed { state: s } => Ok(*s),
        TransitionResult::Rejected { reason } => Err(reason.clone()),
    }
}
