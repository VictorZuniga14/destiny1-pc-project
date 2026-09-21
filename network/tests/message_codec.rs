//! Message codec tests (M4.4).

use destiny1_network::jsonl::Direction;
use destiny1_network::message_codec::{
    decode_message, encode_message, envelope, roundtrip_ok, validate_session_login_response_payload,
    BapMessage, CodecError, KnownBapMessage, OpaquePayload, SessionLoginResponseRecord,
    UnknownBapMessage,
};

fn opaque(id_payload: &[u8]) -> OpaquePayload {
    OpaquePayload {
        context: 1,
        direction: Direction::ClientToServer,
        payload: id_payload.to_vec(),
    }
}

fn decode_id(id: u16, payload: &[u8], dir: Direction) -> BapMessage {
    decode_message(&envelope(id, 1, dir, payload)).unwrap()
}

#[test]
fn decode_0x1e() {
    let m = decode_id(0x1E, b"hello", Direction::ClientToServer);
    assert!(matches!(
        m,
        BapMessage::Known(KnownBapMessage::DestinyServiceHandshakeRequest(_))
    ));
}

#[test]
fn decode_0x1f() {
    let m = decode_id(0x1F, b"hi", Direction::ServerToClient);
    assert!(matches!(
        m,
        BapMessage::Known(KnownBapMessage::DestinyServiceHandshakeResponse(_))
    ));
}

#[test]
fn decode_0x19() {
    let m = decode_id(0x19, b"login", Direction::ClientToServer);
    assert!(matches!(
        m,
        BapMessage::Known(KnownBapMessage::SessionLoginRequest(_))
    ));
}

#[test]
fn decode_0x1a_structured() {
    let mut payload = Vec::new();
    payload.extend_from_slice(&200u16.to_be_bytes());
    let cipher = vec![0xABu8; 16];
    let record_len = (0x30 + cipher.len()) as u32;
    payload.extend_from_slice(&record_len.to_be_bytes());
    payload.extend_from_slice(&[0x11u8; 16]); // IV
    payload.extend_from_slice(&cipher);
    payload.extend_from_slice(&[0x22u8; 32]); // HMAC
    let rec = validate_session_login_response_payload(&payload).unwrap();
    assert_eq!(rec.prefix, 200);
    assert_eq!(rec.ciphertext.len(), 16);
    let m = decode_id(0x1A, &payload, Direction::ServerToClient);
    match m {
        BapMessage::Known(KnownBapMessage::SessionLoginResponse {
            record: Some(_), ..
        }) => {}
        other => panic!("{other:?}"),
    }
}

#[test]
fn decode_0x1a_opaque_short() {
    let m = decode_id(0x1A, b"SIM_1A", Direction::ServerToClient);
    match m {
        BapMessage::Known(KnownBapMessage::SessionLoginResponse {
            record: None,
            raw_payload,
            ..
        }) => assert_eq!(raw_payload, b"SIM_1A"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn decode_0x79_0x7a() {
    assert!(matches!(
        decode_id(0x79, b"enc", Direction::ClientToServer),
        BapMessage::Known(KnownBapMessage::EncryptedHandshakeRequest(_))
    ));
    assert!(matches!(
        decode_id(0x7A, b"ok", Direction::ServerToClient),
        BapMessage::Known(KnownBapMessage::EncryptedHandshakeStatus(_))
    ));
}

#[test]
fn decode_nat_and_keepalive() {
    assert!(matches!(
        decode_id(0x12E, b"n", Direction::ClientToServer),
        BapMessage::Known(KnownBapMessage::Message0x12E(_))
    ));
    assert!(matches!(
        decode_id(0x12F, b"s", Direction::ServerToClient),
        BapMessage::Known(KnownBapMessage::Message0x12F(_))
    ));
    assert!(matches!(
        decode_id(0xFA, b"", Direction::ClientToServer),
        BapMessage::Known(KnownBapMessage::Message0xFA(_))
    ));
    assert!(matches!(
        decode_id(0xFB, b"", Direction::ServerToClient),
        BapMessage::Known(KnownBapMessage::Message0xFB(_))
    ));
}

#[test]
fn known_encode_decode_roundtrip() {
    let msg = BapMessage::Known(KnownBapMessage::DestinyServiceHandshakeRequest(opaque(
        b"SIM_1E",
    )));
    assert!(roundtrip_ok(&msg).unwrap());
    let enc = encode_message(&msg).unwrap();
    assert_eq!(enc, b"SIM_1E");
}

#[test]
fn unknown_message_byte_roundtrip() {
    let raw = b"\x00\x01\x02\xff proprietary".to_vec();
    let msg = BapMessage::Unknown(UnknownBapMessage {
        id: 0xAB,
        context: 7,
        direction: Direction::ClientToServer,
        payload: raw.clone(),
    });
    let enc = encode_message(&msg).unwrap();
    assert_eq!(enc, raw);
    let again = decode_message(&envelope(0xAB, 7, Direction::ClientToServer, &enc)).unwrap();
    match again {
        BapMessage::Unknown(u) => assert_eq!(u.payload, raw),
        other => panic!("{other:?}"),
    }
}

#[test]
fn empty_payload_valid_for_opaque() {
    let m = decode_id(0xFA, b"", Direction::ClientToServer);
    assert!(roundtrip_ok(&m).unwrap());
}

#[test]
fn malformed_0x1a_wrong_length() {
    let err = validate_session_login_response_payload(&[0, 1, 0, 0, 0, 10, 1, 2, 3]);
    assert!(matches!(
        err,
        Err(CodecError::InvalidPayloadLength(_))
            | Err(CodecError::InvalidRecordLength(_))
    ));
}

#[test]
fn truncated_0x1a() {
    let err = validate_session_login_response_payload(&[0, 200]);
    assert!(err.is_err());
}

#[test]
fn structured_0x1a_encode_decode() {
    let rec = SessionLoginResponseRecord {
        prefix: 200,
        record_len: 0x30,
        iv: [3u8; 16],
        ciphertext: vec![],
        hmac: [9u8; 32],
    };
    let payload = rec.encode_payload().unwrap();
    let again = SessionLoginResponseRecord::decode_payload(&payload).unwrap();
    assert_eq!(again, rec);
}
