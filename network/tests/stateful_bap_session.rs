//! Unit tests for StatefulBapSession (M4.5).

use destiny1_network::bap_session::DecodedBapFrame;
use destiny1_network::jsonl::Direction;
use destiny1_network::local_protocol::{
    PAYLOAD_19, PAYLOAD_1E, PAYLOAD_79, SIM_CONTEXT, SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE,
};
use destiny1_network::message_codec::{BapMessage, KnownBapMessage, OpaquePayload, UnknownBapMessage};
use destiny1_network::protocol_state::{ProtocolState, ProtocolStateError, TransitionResult};
use destiny1_network::response_policy::ResponseAction;
use destiny1_network::stateful_bap_session::{StatefulBapSession, SyntheticSessionMaterial};

fn c2s(id: u16, payload: &[u8]) -> BapMessage {
    let o = OpaquePayload {
        context: SIM_CONTEXT,
        direction: Direction::ClientToServer,
        payload: payload.to_vec(),
    };
    match id {
        0x1E => BapMessage::Known(KnownBapMessage::DestinyServiceHandshakeRequest(o)),
        0x19 => BapMessage::Known(KnownBapMessage::SessionLoginRequest(o)),
        0x79 => BapMessage::Known(KnownBapMessage::EncryptedHandshakeRequest(o)),
        0x12E => BapMessage::Known(KnownBapMessage::Message0x12E(o)),
        _ => BapMessage::Unknown(UnknownBapMessage {
            id,
            context: SIM_CONTEXT,
            direction: Direction::ClientToServer,
            payload: payload.to_vec(),
        }),
    }
}

fn handshake(s: &mut StatefulBapSession) {
    let _ = s.handle_message(c2s(0x1E, PAYLOAD_1E)).unwrap();
    let _ = s.handle_message(c2s(0x19, PAYLOAD_19)).unwrap();
    let _ = s.handle_message(c2s(0x79, PAYLOAD_79)).unwrap();
}

#[test]
fn initial_waiting() {
    let s = StatefulBapSession::new_synthetic(1).unwrap();
    assert_eq!(
        s.protocol_state(),
        ProtocolState::WaitingForServiceHandshake
    );
}

#[test]
fn full_valid_sequence() {
    let mut s = StatefulBapSession::new_synthetic(1).unwrap();
    handshake(&mut s);
    assert_eq!(
        s.protocol_state(),
        ProtocolState::EncryptedChannelEstablished
    );
    let h = s.handle_message(c2s(0x12E, b"SIM_12E")).unwrap();
    assert!(!h.transition.is_rejected());
    assert_eq!(s.protocol_state(), ProtocolState::Active);
}

#[test]
fn malformed_no_panic() {
    let mut s = StatefulBapSession::new_synthetic(1).unwrap();
    let frame = DecodedBapFrame::Opaque {
        kind: 0x99,
        body_len: 0,
    };
    let err = s.handle_decoded_frame(&frame, Direction::ClientToServer);
    assert!(matches!(err, Err(ProtocolStateError::InvalidMessage(_))));
}

#[test]
fn unknown_observed_no_auto_reply() {
    let mut s = StatefulBapSession::new_synthetic(1).unwrap();
    let h = s.handle_message(c2s(0xABCD, b"UNK")).unwrap();
    assert!(matches!(h.transition, TransitionResult::Observed { .. }));
    assert!(!matches!(
        h.actions.first(),
        Some(ResponseAction::SendClear { .. }) | Some(ResponseAction::SendEncrypted { .. })
    ));
}

#[test]
fn safe_event_log() {
    let mut s = StatefulBapSession::new_synthetic(7).unwrap();
    let _ = s.handle_message(c2s(0x1E, PAYLOAD_1E)).unwrap();
    let log = s.safe_event_log().join("\n");
    assert!(!log.contains("LOCALSERVER_KEY"));
    assert!(!log.contains("LOCALNONCE"));
    assert!(!log.contains("SIM_1E"));
    assert!(log.contains("0x001e") || log.contains("0x1e") || log.contains("MessageReceived"));
}

#[test]
fn synthetic_material_default() {
    let m = SyntheticSessionMaterial::default();
    assert_eq!(m.key, SYNTHETIC_SESSION_KEY);
    assert_eq!(m.nonce, SYNTHETIC_SESSION_NONCE);
}

#[test]
fn eof_close_handling() {
    let mut s = StatefulBapSession::new_synthetic(1).unwrap();
    handshake(&mut s);
    s.begin_close();
    assert_eq!(s.protocol_state(), ProtocolState::Closing);
    s.finish_close();
    assert_eq!(s.protocol_state(), ProtocolState::Closed);
}
