//! Message dispatcher tests (M4.4).

use destiny1_network::jsonl::Direction;
use destiny1_network::message_codec::{
    decode_message, envelope, BapMessage, KnownBapMessage, OpaquePayload, UnknownBapMessage,
};
use destiny1_network::message_dispatcher::{DispatchEvent, DispatchResult, MessageDispatcher};

fn known_1e() -> BapMessage {
    BapMessage::Known(KnownBapMessage::DestinyServiceHandshakeRequest(
        OpaquePayload {
            context: 1,
            direction: Direction::ClientToServer,
            payload: b"x".to_vec(),
        },
    ))
}

#[test]
fn known_message_handled() {
    let mut d = MessageDispatcher::new();
    let r = d.dispatch(&known_1e());
    assert_eq!(r, DispatchResult::Handled);
    assert!(d.state.startup_sequence_seen);
    assert!(d
        .events
        .iter()
        .any(|e| matches!(e, DispatchEvent::StartupMessageObserved { id: 0x1E })));
}

#[test]
fn unknown_observed() {
    let mut d = MessageDispatcher::new();
    let msg = BapMessage::Unknown(UnknownBapMessage {
        id: 0xAB,
        context: 1,
        direction: Direction::ClientToServer,
        payload: b"raw".to_vec(),
    });
    assert_eq!(d.dispatch(&msg), DispatchResult::Unknown);
}

#[test]
fn malformed_rejected_at_codec() {
    // Opaque frames are rejected by decode_from_frame; envelope decode of unknown id is Unknown.
    let msg = decode_message(&envelope(0xDEAD, 0, Direction::ClientToServer, b"")).unwrap();
    assert!(matches!(msg, BapMessage::Unknown(_)));
}

#[test]
fn startup_and_keepalive_events() {
    let mut d = MessageDispatcher::new();
    let login = BapMessage::Known(KnownBapMessage::SessionLoginResponse {
        context: 1,
        direction: Direction::ServerToClient,
        record: None,
        raw_payload: b"SIM_1A".to_vec(),
    });
    d.dispatch(&login);
    assert!(d.state.session_login_observed);
    assert!(d
        .events
        .iter()
        .any(|e| matches!(e, DispatchEvent::SessionLoginObserved)));

    let ka = BapMessage::Known(KnownBapMessage::Message0xFA(OpaquePayload {
        context: 1,
        direction: Direction::ClientToServer,
        payload: vec![],
    }));
    d.dispatch(&ka);
    assert!(d.state.keepalive_observed);
    assert!(d
        .events
        .iter()
        .any(|e| matches!(e, DispatchEvent::KeepAliveObserved { id: 0xFA })));
}

#[test]
fn nat_events() {
    let mut d = MessageDispatcher::new();
    let nat = BapMessage::Known(KnownBapMessage::Message0x12E(OpaquePayload {
        context: 1,
        direction: Direction::ClientToServer,
        payload: b"n".to_vec(),
    }));
    d.dispatch(&nat);
    assert!(d.state.nat_messages_observed);
}
