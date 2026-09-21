//! Conservative BAP message dispatcher (M4.4).
//!
//! Emits observation events only — does **not** mutate the M3.4 state machine
//! and does **not** implement gameplay handlers.

use crate::message_codec::{BapMessage, KnownBapMessage};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DispatchResult {
    Handled,
    Observed,
    Unknown,
}

impl DispatchResult {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Handled => "Handled",
            Self::Observed => "Observed",
            Self::Unknown => "Unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DispatchEvent {
    MessageObserved { id: u16 },
    StartupMessageObserved { id: u16 },
    KeepAliveObserved { id: u16 },
    NatMessageObserved { id: u16 },
    SessionLoginObserved,
    EncryptedHandshakeObserved { id: u16 },
}

/// Minimal observation flags (not a second state machine).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DispatchObservationState {
    pub startup_sequence_seen: bool,
    pub session_login_observed: bool,
    pub encrypted_handshake_observed: bool,
    pub nat_messages_observed: bool,
    pub keepalive_observed: bool,
    pub last_ids: Vec<u16>,
}

pub struct MessageDispatcher {
    pub state: DispatchObservationState,
    pub events: Vec<DispatchEvent>,
}

impl Default for MessageDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl MessageDispatcher {
    pub fn new() -> Self {
        Self {
            state: DispatchObservationState::default(),
            events: Vec::new(),
        }
    }

    pub fn clear_events(&mut self) {
        self.events.clear();
    }

    pub fn dispatch(&mut self, message: &BapMessage) -> DispatchResult {
        let id = message.id();
        self.state.last_ids.push(id);
        self.events
            .push(DispatchEvent::MessageObserved { id });

        match message {
            BapMessage::Unknown(_) => DispatchResult::Unknown,
            BapMessage::Known(k) => {
                self.note_known(k);
                DispatchResult::Handled
            }
        }
    }

    /// Observe without claiming Handled (e.g. opaque post-startup traffic).
    pub fn observe(&mut self, message: &BapMessage) -> DispatchResult {
        let id = message.id();
        self.state.last_ids.push(id);
        self.events
            .push(DispatchEvent::MessageObserved { id });
        if matches!(
            id,
            0x1E | 0x1F | 0x19 | 0x1A | 0x79 | 0x7A | 0x12E | 0x12F
        ) {
            if let BapMessage::Known(k) = message {
                self.note_known(k);
            }
            DispatchResult::Observed
        } else if matches!(id, 0xFA | 0xFB) {
            self.state.keepalive_observed = true;
            self.events
                .push(DispatchEvent::KeepAliveObserved { id });
            DispatchResult::Observed
        } else {
            DispatchResult::Unknown
        }
    }

    fn note_known(&mut self, k: &KnownBapMessage) {
        let id = k.id();
        match k {
            KnownBapMessage::DestinyServiceHandshakeRequest(_)
            | KnownBapMessage::DestinyServiceHandshakeResponse(_)
            | KnownBapMessage::SessionLoginRequest(_)
            | KnownBapMessage::EncryptedHandshakeRequest(_)
            | KnownBapMessage::EncryptedHandshakeStatus(_) => {
                self.events
                    .push(DispatchEvent::StartupMessageObserved { id });
                self.state.startup_sequence_seen = true;
            }
            KnownBapMessage::SessionLoginResponse { .. } => {
                self.events
                    .push(DispatchEvent::StartupMessageObserved { id });
                self.events.push(DispatchEvent::SessionLoginObserved);
                self.state.startup_sequence_seen = true;
                self.state.session_login_observed = true;
            }
            KnownBapMessage::Message0x12E(_) | KnownBapMessage::Message0x12F(_) => {
                self.events.push(DispatchEvent::NatMessageObserved { id });
                self.state.nat_messages_observed = true;
            }
            KnownBapMessage::Message0xFA(_) | KnownBapMessage::Message0xFB(_) => {
                self.events.push(DispatchEvent::KeepAliveObserved { id });
                self.state.keepalive_observed = true;
            }
        }
        if matches!(id, 0x79 | 0x7A) {
            self.events
                .push(DispatchEvent::EncryptedHandshakeObserved { id });
            self.state.encrypted_handshake_observed = true;
        }
    }
}
