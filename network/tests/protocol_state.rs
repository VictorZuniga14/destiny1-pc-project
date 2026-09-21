//! Unit tests for local ProtocolState (M4.5).

use destiny1_network::jsonl::Direction;
use destiny1_network::local_protocol::{PAYLOAD_19, PAYLOAD_1E, PAYLOAD_79, SIM_CONTEXT};
use destiny1_network::message_codec::{BapMessage, KnownBapMessage, OpaquePayload, UnknownBapMessage};
use destiny1_network::protocol_state::{
    begin_waiting_for_handshake, complete_encrypted_handshake, transition, ProtocolState,
    ProtocolStateError, TransitionResult,
};

fn opaque(id: u16, dir: Direction, payload: &[u8]) -> BapMessage {
    let o = OpaquePayload {
        context: SIM_CONTEXT,
        direction: dir,
        payload: payload.to_vec(),
    };
    match id {
        0x1E => BapMessage::Known(KnownBapMessage::DestinyServiceHandshakeRequest(o)),
        0x19 => BapMessage::Known(KnownBapMessage::SessionLoginRequest(o)),
        0x79 => BapMessage::Known(KnownBapMessage::EncryptedHandshakeRequest(o)),
        0x7A => BapMessage::Known(KnownBapMessage::EncryptedHandshakeStatus(o)),
        0x12E => BapMessage::Known(KnownBapMessage::Message0x12E(o)),
        0xFA => BapMessage::Known(KnownBapMessage::Message0xFA(o)),
        _ => BapMessage::Unknown(UnknownBapMessage {
            id,
            context: SIM_CONTEXT,
            direction: dir,
            payload: payload.to_vec(),
        }),
    }
}

#[test]
fn initial_state_connected() {
    assert_eq!(ProtocolState::default(), ProtocolState::Connected);
}

#[test]
fn begin_waiting() {
    let s = begin_waiting_for_handshake(ProtocolState::Connected).unwrap();
    assert_eq!(s, ProtocolState::WaitingForServiceHandshake);
}

#[test]
fn valid_1e_transition() {
    let m = opaque(0x1E, Direction::ClientToServer, PAYLOAD_1E);
    let r = transition(ProtocolState::WaitingForServiceHandshake, &m);
    assert!(matches!(
        r,
        TransitionResult::Advanced {
            to: ProtocolState::ServiceHandshakeComplete,
            ..
        }
    ));
}

#[test]
fn valid_19_transition() {
    let m = opaque(0x19, Direction::ClientToServer, PAYLOAD_19);
    let r = transition(ProtocolState::ServiceHandshakeComplete, &m);
    assert!(matches!(
        r,
        TransitionResult::Advanced {
            to: ProtocolState::SessionEstablished,
            ..
        }
    ));
}

#[test]
fn valid_79_transition() {
    let m = opaque(0x79, Direction::ClientToServer, PAYLOAD_79);
    let r = transition(ProtocolState::SessionEstablished, &m);
    assert!(matches!(
        r,
        TransitionResult::Advanced {
            to: ProtocolState::WaitingForEncryptedHandshake,
            ..
        }
    ));
}

#[test]
fn valid_7a_complete() {
    let s = complete_encrypted_handshake(ProtocolState::WaitingForEncryptedHandshake).unwrap();
    assert_eq!(s, ProtocolState::EncryptedChannelEstablished);
}

#[test]
fn post_handshake_observation() {
    let m = opaque(0x12E, Direction::ClientToServer, b"SIM_12E");
    let r = transition(ProtocolState::EncryptedChannelEstablished, &m);
    assert!(matches!(
        r,
        TransitionResult::Advanced {
            to: ProtocolState::Active,
            ..
        }
    ));
}

#[test]
fn invalid_19_first() {
    let m = opaque(0x19, Direction::ClientToServer, PAYLOAD_19);
    let r = transition(ProtocolState::WaitingForServiceHandshake, &m);
    assert!(matches!(
        r,
        TransitionResult::Rejected {
            reason: ProtocolStateError::UnexpectedMessage(0x19)
        }
    ));
}

#[test]
fn invalid_79_early() {
    let m = opaque(0x79, Direction::ClientToServer, PAYLOAD_79);
    let r = transition(ProtocolState::ServiceHandshakeComplete, &m);
    assert!(r.is_rejected());
}

#[test]
fn invalid_7a_early() {
    let m = opaque(0x7A, Direction::ClientToServer, b"SIM_7A");
    let r = transition(ProtocolState::SessionEstablished, &m);
    assert!(r.is_rejected());
}

#[test]
fn invalid_direction_1e() {
    let m = opaque(0x1E, Direction::ServerToClient, PAYLOAD_1E);
    let r = transition(ProtocolState::WaitingForServiceHandshake, &m);
    assert!(matches!(
        r,
        TransitionResult::Rejected {
            reason: ProtocolStateError::InvalidDirection { id: 0x1E }
        }
    ));
}

#[test]
fn unknown_observed() {
    let m = opaque(0xABCD, Direction::ClientToServer, b"UNK");
    let r = transition(ProtocolState::WaitingForServiceHandshake, &m);
    assert!(matches!(r, TransitionResult::Observed { .. }));
}

#[test]
fn deterministic_transitions() {
    let m = opaque(0x1E, Direction::ClientToServer, PAYLOAD_1E);
    let a = transition(ProtocolState::WaitingForServiceHandshake, &m);
    let b = transition(ProtocolState::WaitingForServiceHandshake, &m);
    assert_eq!(a, b);
}
