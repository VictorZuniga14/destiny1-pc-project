//! Per-connection stateful BAP session (M4.5).
//!
//! Encapsulates local [`ProtocolState`], synthetic crypto session, codec, and
//! observational dispatcher. Not a Bungie server emulator.

use crate::bap_session::{BapSession, BapSessionError, DecodedBapFrame};
use crate::crypto::NonceDirection;
use crate::jsonl::Direction;
use crate::local_protocol::{SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE};
use crate::message_codec::{decode_from_frame, BapMessage};
use crate::message_dispatcher::{DispatchResult, MessageDispatcher};
use crate::protocol_state::{
    apply_transition, begin_closing, begin_waiting_for_handshake, close,
    complete_encrypted_handshake, transition, ProtocolState, ProtocolStateError, TransitionResult,
};
use crate::response_policy::{ResponseAction, ResponsePolicy, UnknownPolicy};
use serde::Serialize;

/// Deterministic synthetic session material (tests only — never real secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntheticSessionMaterial {
    pub key: [u8; 16],
    pub nonce: [u8; 12],
}

impl Default for SyntheticSessionMaterial {
    fn default() -> Self {
        Self {
            key: SYNTHETIC_SESSION_KEY,
            nonce: SYNTHETIC_SESSION_NONCE,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ProtocolEvent {
    Connected { connection_id: u64 },
    MessageReceived { id: u16, direction: String },
    MessageDecoded { id: u16, known: bool },
    StateTransition { from: String, to: String },
    MessageRejected { id: u16, reason: String },
    ResponseSent { id: u16 },
    SessionClosed,
}

impl ProtocolEvent {
    /// Safe display — never includes keys or payloads.
    pub fn safe_label(&self) -> String {
        match self {
            Self::Connected { connection_id } => format!("Connected conn={connection_id}"),
            Self::MessageReceived { id, direction } => {
                format!("MessageReceived id=0x{id:04x} dir={direction}")
            }
            Self::MessageDecoded { id, known } => {
                format!("MessageDecoded id=0x{id:04x} known={known}")
            }
            Self::StateTransition { from, to } => {
                format!("StateTransition {from}→{to}")
            }
            Self::MessageRejected { id, reason } => {
                format!("MessageRejected id=0x{id:04x} reason={reason}")
            }
            Self::ResponseSent { id } => format!("ResponseSent id=0x{id:04x}"),
            Self::SessionClosed => "SessionClosed".into(),
        }
    }
}

#[derive(Debug)]
pub struct HandleResult {
    pub transition: TransitionResult,
    pub actions: Vec<ResponseAction>,
    pub dispatch: DispatchResult,
    pub message: BapMessage,
}

pub struct StatefulBapSession {
    pub connection_id: u64,
    protocol_state: ProtocolState,
    pub session: BapSession,
    pub material: SyntheticSessionMaterial,
    pub dispatcher: MessageDispatcher,
    pub policy: ResponsePolicy,
    pub events: Vec<ProtocolEvent>,
}

impl StatefulBapSession {
    pub fn new_synthetic(connection_id: u64) -> Result<Self, BapSessionError> {
        Self::with_material(connection_id, SyntheticSessionMaterial::default())
    }

    pub fn with_material(
        connection_id: u64,
        material: SyntheticSessionMaterial,
    ) -> Result<Self, BapSessionError> {
        let session = BapSession::new(&material.key, &material.nonce)?;
        let mut s = Self {
            connection_id,
            protocol_state: ProtocolState::Connected,
            session,
            material,
            dispatcher: MessageDispatcher::new(),
            policy: ResponsePolicy::default(),
            events: Vec::new(),
        };
        s.events.push(ProtocolEvent::Connected { connection_id });
        s.protocol_state = begin_waiting_for_handshake(s.protocol_state)
            .unwrap_or(ProtocolState::WaitingForServiceHandshake);
        Ok(s)
    }

    pub fn protocol_state(&self) -> ProtocolState {
        self.protocol_state
    }

    /// Sole mutation path for protocol state (besides close helpers).
    fn set_state(&mut self, to: ProtocolState) {
        let from = self.protocol_state;
        if from != to {
            self.events.push(ProtocolEvent::StateTransition {
                from: from.as_str().into(),
                to: to.as_str().into(),
            });
            self.protocol_state = to;
        }
    }

    pub fn set_unknown_policy(&mut self, p: UnknownPolicy) {
        self.policy.unknown = p;
    }

    pub fn handle_decoded_frame(
        &mut self,
        frame: &DecodedBapFrame,
        direction: Direction,
    ) -> Result<HandleResult, ProtocolStateError> {
        let message = decode_from_frame(frame, direction).map_err(|e| {
            ProtocolStateError::InvalidMessage(e.to_string())
        })?;
        self.handle_message(message)
    }

    pub fn handle_message(&mut self, message: BapMessage) -> Result<HandleResult, ProtocolStateError> {
        let id = message.id();
        self.events.push(ProtocolEvent::MessageReceived {
            id,
            direction: match message.direction() {
                Direction::ClientToServer => "C2S".into(),
                Direction::ServerToClient => "S2C".into(),
            },
        });
        self.events.push(ProtocolEvent::MessageDecoded {
            id,
            known: message.is_known(),
        });

        let state_before = self.protocol_state;
        let tr = transition(state_before, &message);
        let actions_pre = self.policy.decide(state_before, &message);

        match &tr {
            TransitionResult::Rejected { reason } => {
                self.events.push(ProtocolEvent::MessageRejected {
                    id,
                    reason: reason.to_string(),
                });
                let dispatch = self.dispatcher.dispatch(&message);
                return Ok(HandleResult {
                    transition: tr,
                    actions: vec![ResponseAction::None],
                    dispatch,
                    message,
                });
            }
            TransitionResult::Advanced { to, .. } | TransitionResult::Observed { state: to } => {
                let new_state = apply_transition(state_before, &tr)?;
                self.set_state(new_state);
                let _ = to;
            }
        }

        let actions = vec![actions_pre];
        // After accepting 0x79, policy already queued 0x7A; complete encrypted state.
        if matches!(
            (state_before, id),
            (ProtocolState::SessionEstablished, 0x79)
        ) {
            let next = complete_encrypted_handshake(self.protocol_state)?;
            self.set_state(next);
        }

        // Unknown reject policy
        if matches!(actions.first(), Some(ResponseAction::Reject)) {
            return Err(ProtocolStateError::UnexpectedMessage(id));
        }

        let dispatch = self.dispatcher.dispatch(&message);
        for a in &actions {
            if let ResponseAction::SendClear { msg_id, .. }
            | ResponseAction::SendEncrypted { msg_id, .. } = a
            {
                self.events.push(ProtocolEvent::ResponseSent { id: *msg_id });
            }
        }

        Ok(HandleResult {
            transition: tr,
            actions,
            dispatch,
            message,
        })
    }

    pub fn client_to_server_counter(&self) -> u64 {
        self.session.client_to_server_counter()
    }

    pub fn server_to_client_counter(&self) -> u64 {
        self.session.server_to_client_counter()
    }

    pub fn encode_clear(&self, msg_id: u16, context: u32, payload: &[u8]) -> Vec<u8> {
        crate::bap_session::BapSession::encode_clear(msg_id, context, payload)
    }

    pub fn encode_encrypted_s2c(
        &mut self,
        msg_id: u16,
        context: u32,
        payload: &[u8],
    ) -> Result<Vec<u8>, BapSessionError> {
        self.session.encode_encrypted(
            NonceDirection::ServerToClient,
            msg_id,
            context,
            payload,
        )
    }

    pub fn decode_c2s_frame(&mut self, raw: &[u8]) -> Result<DecodedBapFrame, BapSessionError> {
        self.session
            .decode_frame(NonceDirection::ClientToServer, raw)
    }

    pub fn begin_close(&mut self) {
        let s = begin_closing(self.protocol_state);
        self.set_state(s);
    }

    pub fn finish_close(&mut self) {
        self.set_state(close(self.protocol_state));
        self.events.push(ProtocolEvent::SessionClosed);
    }

    pub fn safe_event_log(&self) -> Vec<String> {
        self.events.iter().map(|e| e.safe_label()).collect()
    }
}
