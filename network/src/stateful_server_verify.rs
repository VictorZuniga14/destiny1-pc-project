//! Offline verifier for M4.5 stateful local BAP server.

use crate::bap_session::DecodedBapFrame;
use crate::jsonl::Direction;
use crate::local_protocol::{
    PAYLOAD_19, PAYLOAD_1E, PAYLOAD_79, PAYLOAD_FA, SIM_CONTEXT, MSG_12E, MSG_19, MSG_1E, MSG_79,
    MSG_FA,
};
use crate::message_codec::{BapMessage, KnownBapMessage, OpaquePayload, UnknownBapMessage};
use crate::protocol_state::{ProtocolState, ProtocolStateError, TransitionResult};
use crate::response_policy::{ResponseAction, ResponsePolicy, UnknownPolicy};
use crate::stateful_bap_session::StatefulBapSession;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StatefulServerVerifyError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("fixture: {0}")]
    Fixture(String),
    #[error("verify failed: {0}")]
    Failed(String),
}

#[derive(Debug, Deserialize)]
struct SyntheticTrace {
    name: String,
    #[serde(default)]
    notes: Vec<String>,
    steps: Vec<TraceStep>,
}

#[derive(Debug, Deserialize)]
struct TraceStep {
    event: String,
    #[serde(default)]
    message_id: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    direction: Option<String>,
    #[serde(default)]
    expected_state: Option<String>,
    #[serde(default)]
    response_id: Option<String>,
}

const PAYLOAD_12E: &[u8] = b"SIM_12E";

fn opaque_c2s(id: u16, payload: &[u8]) -> BapMessage {
    let o = OpaquePayload {
        context: SIM_CONTEXT,
        direction: Direction::ClientToServer,
        payload: payload.to_vec(),
    };
    let known = match id {
        0x1E => KnownBapMessage::DestinyServiceHandshakeRequest(o),
        0x19 => KnownBapMessage::SessionLoginRequest(o),
        0x79 => KnownBapMessage::EncryptedHandshakeRequest(o),
        0x12E => KnownBapMessage::Message0x12E(o),
        0xFA => KnownBapMessage::Message0xFA(o),
        _ => {
            return BapMessage::Unknown(UnknownBapMessage {
                id,
                context: SIM_CONTEXT,
                direction: Direction::ClientToServer,
                payload: payload.to_vec(),
            })
        }
    };
    BapMessage::Known(known)
}

fn parse_hex_id(s: &str) -> Result<u16, StatefulServerVerifyError> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(t, 16).map_err(|e| StatefulServerVerifyError::Fixture(e.to_string()))
}

fn default_fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/stateful_server/synthetic_trace.json")
}

/// Run full offline stateful-server verification.
pub fn run_default() -> Result<(), StatefulServerVerifyError> {
    run_from_path(default_fixture_path())
}

pub fn run_from_path(path: impl AsRef<Path>) -> Result<(), StatefulServerVerifyError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(StatefulServerVerifyError::FileNotFound(
            path.display().to_string(),
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| StatefulServerVerifyError::Fixture(e.to_string()))?;
    let trace: SyntheticTrace = serde_json::from_str(&text)
        .map_err(|e| StatefulServerVerifyError::Fixture(e.to_string()))?;

    println!("STATEFUL_SERVER_VERIFY: start fixture={}", trace.name);
    for n in &trace.notes {
        println!("note: {n}");
    }

    verify_valid_sequence(&trace)?;
    verify_invalid_sequences()?;
    verify_unknown_observe()?;
    verify_malformed()?;
    verify_multi_client_isolation()?;
    verify_reconnect()?;
    verify_determinism()?;
    verify_safe_events()?;

    println!("STATEFUL_SERVER_VERIFY: VERIFIED");
    Ok(())
}

fn verify_valid_sequence(trace: &SyntheticTrace) -> Result<(), StatefulServerVerifyError> {
    let mut session = StatefulBapSession::new_synthetic(1)
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    if session.protocol_state() != ProtocolState::WaitingForServiceHandshake {
        return Err(StatefulServerVerifyError::Failed(
            "initial state must be WAITING_FOR_SERVICE_HANDSHAKE".into(),
        ));
    }

    for step in &trace.steps {
        match step.event.as_str() {
            "CONNECTED" => {
                if let Some(s) = &step.expected_state {
                    if session.protocol_state().as_str() != s {
                        return Err(StatefulServerVerifyError::Failed(format!(
                            "CONNECTED expected state {s}, got {}",
                            session.protocol_state().as_str()
                        )));
                    }
                }
            }
            "C2S" => {
                let id_str = step.message_id.as_deref().ok_or_else(|| {
                    StatefulServerVerifyError::Fixture("C2S needs message_id".into())
                })?;
                let id = parse_hex_id(id_str)?;
                let payload: &[u8] = match id {
                    MSG_1E => PAYLOAD_1E,
                    MSG_19 => PAYLOAD_19,
                    MSG_79 => PAYLOAD_79,
                    MSG_12E => PAYLOAD_12E,
                    MSG_FA => PAYLOAD_FA,
                    _ => b"SIM_UNK",
                };
                let msg = opaque_c2s(id, payload);
                let handled = session
                    .handle_message(msg)
                    .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
                if handled.transition.is_rejected() {
                    return Err(StatefulServerVerifyError::Failed(format!(
                        "unexpected reject for 0x{id:04x}"
                    )));
                }
                if let Some(exp) = &step.expected_state {
                    if session.protocol_state().as_str() != exp {
                        return Err(StatefulServerVerifyError::Failed(format!(
                            "after 0x{id:04x} expected {exp}, got {}",
                            session.protocol_state().as_str()
                        )));
                    }
                }
                if let Some(rid) = &step.response_id {
                    let want = parse_hex_id(rid)?;
                    let sent = handled.actions.iter().any(|a| match a {
                        ResponseAction::SendClear { msg_id, .. }
                        | ResponseAction::SendEncrypted { msg_id, .. } => *msg_id == want,
                        _ => false,
                    });
                    if !sent {
                        return Err(StatefulServerVerifyError::Failed(format!(
                            "expected response 0x{want:04x} for inbound 0x{id:04x}"
                        )));
                    }
                    if matches!(
                        handled.actions.first(),
                        Some(ResponseAction::SendEncrypted { .. })
                    ) {
                        let _ = session
                            .encode_encrypted_s2c(want, SIM_CONTEXT, b"SIM")
                            .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
                    }
                } else if id != MSG_FA {
                    let auto = handled.actions.iter().any(|a| {
                        matches!(
                            a,
                            ResponseAction::SendClear { .. } | ResponseAction::SendEncrypted { .. }
                        )
                    });
                    if auto {
                        return Err(StatefulServerVerifyError::Failed(format!(
                            "unexpected auto-response for 0x{id:04x}"
                        )));
                    }
                }
            }
            "S2C" | "OBSERVED" => {}
            other => {
                return Err(StatefulServerVerifyError::Fixture(format!(
                    "unknown event {other}"
                )));
            }
        }
    }

    if !matches!(
        session.protocol_state(),
        ProtocolState::Active | ProtocolState::EncryptedChannelEstablished
    ) {
        return Err(StatefulServerVerifyError::Failed(format!(
            "final state not active: {}",
            session.protocol_state().as_str()
        )));
    }
    Ok(())
}

fn verify_invalid_sequences() -> Result<(), StatefulServerVerifyError> {
    let mut s = StatefulBapSession::new_synthetic(10)
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    let h = s
        .handle_message(opaque_c2s(MSG_19, PAYLOAD_19))
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    if !matches!(
        h.transition,
        TransitionResult::Rejected {
            reason: ProtocolStateError::UnexpectedMessage(0x19)
        }
    ) {
        return Err(StatefulServerVerifyError::Failed(
            "0x19-first should reject".into(),
        ));
    }

    let mut s = StatefulBapSession::new_synthetic(11)
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    let _ = s
        .handle_message(opaque_c2s(MSG_1E, PAYLOAD_1E))
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    let h = s
        .handle_message(opaque_c2s(MSG_79, PAYLOAD_79))
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    if !h.transition.is_rejected() {
        return Err(StatefulServerVerifyError::Failed(
            "0x79 early should reject".into(),
        ));
    }

    let mut s = StatefulBapSession::new_synthetic(12)
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    let _ = s.handle_message(opaque_c2s(MSG_1E, PAYLOAD_1E)).unwrap();
    let _ = s.handle_message(opaque_c2s(MSG_19, PAYLOAD_19)).unwrap();
    let h = s
        .handle_message(BapMessage::Known(
            KnownBapMessage::EncryptedHandshakeStatus(OpaquePayload {
                context: SIM_CONTEXT,
                direction: Direction::ClientToServer,
                payload: b"SIM_7A".to_vec(),
            }),
        ))
        .unwrap();
    if !h.transition.is_rejected() {
        return Err(StatefulServerVerifyError::Failed(
            "0x7A early should reject".into(),
        ));
    }

    let mut s = StatefulBapSession::new_synthetic(13)
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    let h = s
        .handle_message(opaque_c2s(MSG_12E, PAYLOAD_12E))
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    if !h.transition.is_rejected() {
        return Err(StatefulServerVerifyError::Failed(
            "0x12E early should reject".into(),
        ));
    }
    Ok(())
}

fn verify_unknown_observe() -> Result<(), StatefulServerVerifyError> {
    let mut s = StatefulBapSession::new_synthetic(20)
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    let unk = BapMessage::Unknown(UnknownBapMessage {
        id: 0xABCD,
        context: SIM_CONTEXT,
        direction: Direction::ClientToServer,
        payload: b"UNK".to_vec(),
    });
    let h = s
        .handle_message(unk)
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    if !matches!(h.transition, TransitionResult::Observed { .. }) {
        return Err(StatefulServerVerifyError::Failed(
            "unknown should be Observed".into(),
        ));
    }
    if matches!(
        h.actions.first(),
        Some(ResponseAction::SendClear { .. }) | Some(ResponseAction::SendEncrypted { .. })
    ) {
        return Err(StatefulServerVerifyError::Failed(
            "unknown must not auto-respond".into(),
        ));
    }
    Ok(())
}

fn verify_malformed() -> Result<(), StatefulServerVerifyError> {
    let mut s = StatefulBapSession::new_synthetic(30)
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    let frame = DecodedBapFrame::Opaque {
        kind: 0x03,
        body_len: 2,
    };
    match s.handle_decoded_frame(&frame, Direction::ClientToServer) {
        Err(ProtocolStateError::InvalidMessage(_)) => Ok(()),
        other => Err(StatefulServerVerifyError::Failed(format!(
            "expected InvalidMessage, got {other:?}"
        ))),
    }
}

fn verify_multi_client_isolation() -> Result<(), StatefulServerVerifyError> {
    let mut a = StatefulBapSession::new_synthetic(100)
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    let b = StatefulBapSession::new_synthetic(101)
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    let _ = a.handle_message(opaque_c2s(MSG_1E, PAYLOAD_1E)).unwrap();
    if a.protocol_state() == b.protocol_state() {
        return Err(StatefulServerVerifyError::Failed(
            "states should diverge".into(),
        ));
    }
    let _ = a.handle_message(opaque_c2s(MSG_19, PAYLOAD_19)).unwrap();
    let _ = a.handle_message(opaque_c2s(MSG_79, PAYLOAD_79)).unwrap();
    let _ = a
        .encode_encrypted_s2c(0x7A, SIM_CONTEXT, b"SIM_7A")
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    if a.server_to_client_counter() == b.server_to_client_counter() {
        return Err(StatefulServerVerifyError::Failed(
            "nonce counters must be independent".into(),
        ));
    }
    Ok(())
}

fn verify_reconnect() -> Result<(), StatefulServerVerifyError> {
    let mut s1 = StatefulBapSession::new_synthetic(200)
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    let _ = s1.handle_message(opaque_c2s(MSG_1E, PAYLOAD_1E)).unwrap();
    let _ = s1.handle_message(opaque_c2s(MSG_19, PAYLOAD_19)).unwrap();
    s1.finish_close();
    if s1.protocol_state() != ProtocolState::Closed {
        return Err(StatefulServerVerifyError::Failed(
            "first session not closed".into(),
        ));
    }
    let s2 = StatefulBapSession::new_synthetic(201)
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    if s2.protocol_state() != ProtocolState::WaitingForServiceHandshake {
        return Err(StatefulServerVerifyError::Failed(
            "reconnect must start WaitingForServiceHandshake".into(),
        ));
    }
    if s2.client_to_server_counter() != 0 || s2.server_to_client_counter() != 0 {
        return Err(StatefulServerVerifyError::Failed(
            "reconnect must reset counters".into(),
        ));
    }
    Ok(())
}

fn verify_determinism() -> Result<(), StatefulServerVerifyError> {
    let run = || -> Result<(ProtocolState, Vec<u16>), StatefulServerVerifyError> {
        let mut s = StatefulBapSession::new_synthetic(1)
            .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
        let mut responses = Vec::new();
        for (id, payload) in [
            (MSG_1E, PAYLOAD_1E),
            (MSG_19, PAYLOAD_19),
            (MSG_79, PAYLOAD_79),
        ] {
            let h = s
                .handle_message(opaque_c2s(id, payload))
                .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
            for a in &h.actions {
                if let ResponseAction::SendClear { msg_id, .. }
                | ResponseAction::SendEncrypted { msg_id, .. } = a
                {
                    responses.push(*msg_id);
                }
            }
        }
        Ok((s.protocol_state(), responses))
    };
    let a = run()?;
    let b = run()?;
    if a != b {
        return Err(StatefulServerVerifyError::Failed(
            "deterministic runs diverged".into(),
        ));
    }
    let policy = ResponsePolicy::default();
    let m = opaque_c2s(MSG_1E, PAYLOAD_1E);
    let a1 = policy.decide(ProtocolState::WaitingForServiceHandshake, &m);
    let a2 = policy.decide(ProtocolState::WaitingForServiceHandshake, &m);
    if a1 != a2 {
        return Err(StatefulServerVerifyError::Failed(
            "policy not deterministic".into(),
        ));
    }
    let _ = UnknownPolicy::Observe;
    Ok(())
}

fn verify_safe_events() -> Result<(), StatefulServerVerifyError> {
    let mut s = StatefulBapSession::new_synthetic(50)
        .map_err(|e| StatefulServerVerifyError::Failed(e.to_string()))?;
    let _ = s.handle_message(opaque_c2s(MSG_1E, PAYLOAD_1E)).unwrap();
    let log = s.safe_event_log();
    let joined = log.join("|");
    if joined.contains("LOCALSERVER_KEY")
        || joined.contains("LOCALNONCE")
        || joined.contains("SIM_1E")
    {
        return Err(StatefulServerVerifyError::Failed(
            "event log leaked secrets/payload".into(),
        ));
    }
    if !joined.contains("MessageReceived") || !joined.contains("StateTransition") {
        return Err(StatefulServerVerifyError::Failed(
            "event log missing expected events".into(),
        ));
    }
    Ok(())
}
