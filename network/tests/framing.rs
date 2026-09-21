use destiny1_network::framing::{
    self, BapFrame, ClearBody, EncryptedBody, FrameBody, FrameKind, FramingError, BAP_MAGIC,
};
use destiny1_network::jsonl::{self, Direction};
use destiny1_network::messages::{self, MessageClass};
use destiny1_network::timeline::Timeline;

fn clear_bytes(msg_id: u16, context: u32, payload: &[u8]) -> Vec<u8> {
    framing::clear_frame(msg_id, context, payload)
        .serialize()
        .expect("serialize clear")
}

#[test]
fn parses_bap_header_magic_and_kind() {
    let bytes = clear_bytes(0x19, 0x01020304, b"\xde\xad");
    assert_eq!(bytes[0], BAP_MAGIC);
    assert_eq!(bytes[1], 2);
    let (frame, consumed) = BapFrame::parse(&bytes).unwrap();
    assert_eq!(consumed, bytes.len());
    assert_eq!(frame.kind, FrameKind::Clear);
}

#[test]
fn body_length_is_big_endian() {
    // Craft header manually: body_len = 8 (6 clear header + 2 payload)
    let mut raw = vec![0x01, 0x02, 0x00, 0x00, 0x00, 0x08];
    raw.extend_from_slice(&0x1Eu16.to_be_bytes());
    raw.extend_from_slice(&0x11u32.to_be_bytes());
    raw.extend_from_slice(&[0xAA, 0xBB]);
    let (frame, _) = BapFrame::parse(&raw).unwrap();
    match frame.body {
        FrameBody::Clear(c) => {
            assert_eq!(c.msg_id, 0x1E);
            assert_eq!(c.context, 0x11);
            assert_eq!(c.payload, vec![0xAA, 0xBB]);
        }
        other => panic!("expected clear, got {other:?}"),
    }
}

#[test]
fn kind2_extracts_msg_id_and_context() {
    let bytes = clear_bytes(0x1A, 0xAABBCCDD, b"payload");
    let (frame, _) = BapFrame::parse(&bytes).unwrap();
    assert_eq!(frame.message_id(), Some(0x1A));
    assert_eq!(frame.context(), Some(0xAABBCCDD));
    match frame.body {
        FrameBody::Clear(ClearBody { payload, .. }) => assert_eq!(payload, b"payload"),
        _ => panic!("expected clear"),
    }
}

#[test]
fn kind1_is_opaque_encrypted_no_crypto() {
    let tag = [0x11u8; 16];
    let ciphertext = vec![0xCA, 0xFE, 0xBA, 0xBE];
    let frame = framing::encrypted_frame(tag, &ciphertext);
    let bytes = frame.serialize().unwrap();
    let (parsed, _) = BapFrame::parse(&bytes).unwrap();
    assert_eq!(parsed.kind, FrameKind::Encrypted);
    assert!(parsed.message_id().is_none());
    match parsed.body {
        FrameBody::Encrypted(EncryptedBody {
            tag: t,
            ciphertext: c,
        }) => {
            assert_eq!(t, tag);
            assert_eq!(c, ciphertext);
        }
        _ => panic!("expected encrypted opaque body"),
    }
}

#[test]
fn rejects_bad_magic() {
    let err = BapFrame::parse(&[0x00, 0x02, 0, 0, 0, 0]).unwrap_err();
    assert_eq!(err, FramingError::BadMagic(0x00));
}

#[test]
fn serialize_parse_round_trip_clear() {
    let original = framing::clear_frame(0x19, 7, b"synthetic");
    let bytes = original.serialize().unwrap();
    let (parsed, n) = BapFrame::parse(&bytes).unwrap();
    assert_eq!(n, bytes.len());
    assert_eq!(parsed, original);
}

#[test]
fn serialize_parse_round_trip_encrypted() {
    let original = framing::encrypted_frame([0x42; 16], b"\x01\x02\x03");
    let bytes = original.serialize().unwrap();
    let (parsed, _) = BapFrame::parse(&bytes).unwrap();
    assert_eq!(parsed, original);
}

#[test]
fn classifies_known_and_unknown_messages() {
    assert!(matches!(
        messages::classify(0x19),
        MessageClass::Known(info) if info.name == "session-login-request"
    ));
    assert!(matches!(
        messages::classify(0x1E),
        MessageClass::Known(info) if info.name == "destiny-service-handshake-request"
    ));
    assert!(matches!(
        messages::classify(0x12D),
        MessageClass::Known(info) if info.name == "activity-state"
    ));
    assert!(matches!(
        messages::classify(0xDEAD),
        MessageClass::Unknown { id: 0xDEAD }
    ));
}

#[test]
fn jsonl_fixture_builds_ordered_timeline() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/synthetic_session.jsonl");
    let records = jsonl::parse_jsonl_path(path).expect("fixture jsonl");
    let timeline = Timeline::from_evidence(&records);
    let lines = timeline.format_lines();

    assert!(lines[0].contains("C → S"));
    assert!(lines[0].contains("0x1e"));
    assert!(lines[0].contains("destiny-service-handshake-request"));

    assert!(lines[1].contains("S → C"));
    assert!(lines[1].contains("0x1f"));

    assert!(lines[2].contains("0x19"));
    assert!(lines[2].contains("session-login-request"));

    assert!(lines[3].contains("0x1a"));
    assert!(lines[3].contains("session-login-response"));

    assert!(lines[4].contains("encrypted"));
    assert!(lines[5].contains("encrypted"));

    // Unknown synthetic id 0xDEAD
    assert!(lines[6].contains("0xdead"));
    assert!(!lines[6].contains("session-login"));

    // Ordering by timestamp_ms
    let stamps: Vec<_> = timeline.entries().iter().map(|e| e.timestamp_ms).collect();
    let mut sorted = stamps.clone();
    sorted.sort();
    assert_eq!(stamps, sorted);
}

#[test]
fn frame_hex_evidence_path() {
    let frame = framing::clear_frame(0xFA, 9, b"\x00");
    let hex = jsonl::encode_hex(&frame.serialize().unwrap());
    let line = format!(
        r#"{{"timestamp_ms":5,"direction":"client_to_server","frame_hex":"{hex}","extra_ignored":true}}"#
    );
    let records = jsonl::parse_jsonl_str(&line).unwrap();
    assert_eq!(records[0].direction, Direction::ClientToServer);
    assert_eq!(records[0].frame.message_id(), Some(0xFA));
    assert_eq!(
        messages::classify(0xFA).name(),
        Some("keepalive-request")
    );
}

#[test]
fn timeline_tie_break_prefers_client_first() {
    use destiny1_network::timeline::TimelineEntry;
    let mut tl = Timeline::new();
    let f = framing::clear_frame(0x1F, 0, b"");
    tl.push(TimelineEntry::from_parts(10, Direction::ServerToClient, &f));
    let f2 = framing::clear_frame(0x1E, 0, b"");
    tl.push(TimelineEntry::from_parts(10, Direction::ClientToServer, &f2));
    tl.sort();
    assert_eq!(tl.entries()[0].message_id, Some(0x1E));
    assert_eq!(tl.entries()[1].message_id, Some(0x1F));
}
