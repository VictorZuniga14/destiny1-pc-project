//! Unit tests for ResponsePolicy (M4.5).

use destiny1_network::jsonl::Direction;
use destiny1_network::local_protocol::{PAYLOAD_1E, PAYLOAD_19, PAYLOAD_79, SIM_CONTEXT};
use destiny1_network::message_codec::{BapMessage, KnownBapMessage, OpaquePayload, UnknownBapMessage};
use destiny1_network::protocol_state::ProtocolState;
use destiny1_network::response_policy::{ResponseAction, ResponsePolicy, UnknownPolicy};

fn msg(id: u16) -> BapMessage {
    let o = OpaquePayload {
        context: SIM_CONTEXT,
        direction: Direction::ClientToServer,
        payload: match id {
            0x1E => PAYLOAD_1E.to_vec(),
            0x19 => PAYLOAD_19.to_vec(),
            0x79 => PAYLOAD_79.to_vec(),
            _ => b"X".to_vec(),
        },
    };
    match id {
        0x1E => BapMessage::Known(KnownBapMessage::DestinyServiceHandshakeRequest(o)),
        0x19 => BapMessage::Known(KnownBapMessage::SessionLoginRequest(o)),
        0x79 => BapMessage::Known(KnownBapMessage::EncryptedHandshakeRequest(o)),
        0x12E => BapMessage::Known(KnownBapMessage::Message0x12E(o)),
        0xFA => BapMessage::Known(KnownBapMessage::Message0xFA(o)),
        _ => BapMessage::Unknown(UnknownBapMessage {
            id,
            context: SIM_CONTEXT,
            direction: Direction::ClientToServer,
            payload: b"UNK".to_vec(),
        }),
    }
}

#[test]
fn policy_1e_to_1f() {
    let p = ResponsePolicy::default();
    let a = p.decide(ProtocolState::WaitingForServiceHandshake, &msg(0x1E));
    assert!(matches!(a, ResponseAction::SendClear { msg_id: 0x1F, .. }));
}

#[test]
fn policy_19_to_1a() {
    let p = ResponsePolicy::default();
    let a = p.decide(ProtocolState::ServiceHandshakeComplete, &msg(0x19));
    assert!(matches!(a, ResponseAction::SendClear { msg_id: 0x1A, .. }));
}

#[test]
fn policy_79_to_7a() {
    let p = ResponsePolicy::default();
    let a = p.decide(ProtocolState::SessionEstablished, &msg(0x79));
    assert!(matches!(
        a,
        ResponseAction::SendEncrypted { msg_id: 0x7A, .. }
    ));
}

#[test]
fn policy_12e_observe_only() {
    let p = ResponsePolicy::default();
    let a = p.decide(ProtocolState::Active, &msg(0x12E));
    assert_eq!(a, ResponseAction::ObserveOnly);
}

#[test]
fn policy_unknown_observe() {
    let p = ResponsePolicy::default();
    let a = p.decide(ProtocolState::Active, &msg(0xABCD));
    assert_eq!(a, ResponseAction::ObserveOnly);
}

#[test]
fn policy_unknown_reject_optional() {
    let mut p = ResponsePolicy::default();
    p.unknown = UnknownPolicy::Reject;
    let a = p.decide(ProtocolState::Active, &msg(0xABCD));
    assert_eq!(a, ResponseAction::Reject);
}

#[test]
fn policy_deterministic() {
    let p = ResponsePolicy::default();
    let a = p.decide(ProtocolState::WaitingForServiceHandshake, &msg(0x1E));
    let b = p.decide(ProtocolState::WaitingForServiceHandshake, &msg(0x1E));
    assert_eq!(a, b);
}

#[test]
fn policy_no_invent_on_invalid_state() {
    let p = ResponsePolicy::default();
    let a = p.decide(ProtocolState::WaitingForServiceHandshake, &msg(0x19));
    assert_eq!(a, ResponseAction::None);
}
