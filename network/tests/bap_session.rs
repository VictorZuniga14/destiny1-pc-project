//! Offline BapSession tests (synthetic material only).

use destiny1_network::bap_session::{
    clear_raw, encrypted_raw, BapSession, BapSessionError, DecodedBapFrame,
};
use destiny1_network::crypto::{encrypt_aes_gcm, NonceDirection, SessionCryptoContext};
use destiny1_network::framing::{BapFrame, FramingError};

fn synth_key() -> [u8; 16] {
    *b"SYNTH_BAP_KEY16!"
}
fn synth_nonce() -> [u8; 12] {
    *b"SYNTHBAPNONC"
}

fn enc_frame_for(
    session: &mut SessionCryptoContext,
    direction: NonceDirection,
    plaintext: &[u8],
) -> Vec<u8> {
    let nonce = session.next_nonce(direction);
    let blob = encrypt_aes_gcm(session.session_key(), &nonce, plaintext, b"").unwrap();
    encrypted_raw(blob.tag, &blob.ciphertext)
}

#[test]
fn clear_does_not_consume_nonce() {
    let mut s = BapSession::new(&synth_key(), &synth_nonce()).unwrap();
    let raw = clear_raw(0x1e, 0, b"hello");
    let d = s
        .decode_frame(NonceDirection::ClientToServer, &raw)
        .unwrap();
    assert!(matches!(
        d,
        DecodedBapFrame::Clear {
            msg_id: 0x1e,
            ..
        }
    ));
    assert_eq!(s.client_to_server_counter(), 0);
    assert_eq!(s.server_to_client_counter(), 0);
}

#[test]
fn mixed_sequence_independent_counters() {
    // C clear, C enc, S clear, S enc, C enc  → C:0,1  S:0,1
    let key = synth_key();
    let sn = synth_nonce();
    let mut maker = SessionCryptoContext::new(&key, &sn).unwrap();

    let c_clear = clear_raw(0x19, 1, b"c");
    let c_enc0 = enc_frame_for(
        &mut maker,
        NonceDirection::ClientToServer,
        b"\x00\x79\x00\x00\x00\x02AB",
    );
    let s_clear = clear_raw(0x1a, 2, b"s");
    let s_enc0 = enc_frame_for(
        &mut maker,
        NonceDirection::ServerToClient,
        b"\x00\x7a\x00\x00\x00\x03CD",
    );
    let c_enc1 = enc_frame_for(
        &mut maker,
        NonceDirection::ClientToServer,
        b"\x01\x2e\x00\x00\x00\x04EF",
    );

    let mut s = BapSession::new(&key, &sn).unwrap();
    assert!(s
        .decode_frame(NonceDirection::ClientToServer, &c_clear)
        .unwrap()
        .is_clear());
    assert_eq!(s.client_to_server_counter(), 0);

    let d1 = s
        .decode_frame(NonceDirection::ClientToServer, &c_enc0)
        .unwrap();
    assert!(d1.is_decrypted());
    assert_eq!(s.client_to_server_counter(), 1);
    assert_eq!(s.server_to_client_counter(), 0);

    assert!(s
        .decode_frame(NonceDirection::ServerToClient, &s_clear)
        .unwrap()
        .is_clear());
    assert_eq!(s.server_to_client_counter(), 0);

    let d2 = s
        .decode_frame(NonceDirection::ServerToClient, &s_enc0)
        .unwrap();
    assert!(d2.is_decrypted());
    assert_eq!(s.server_to_client_counter(), 1);
    assert_eq!(s.client_to_server_counter(), 1);

    let d3 = s
        .decode_frame(NonceDirection::ClientToServer, &c_enc1)
        .unwrap();
    assert!(d3.is_decrypted());
    assert_eq!(s.client_to_server_counter(), 2);
    assert_eq!(s.server_to_client_counter(), 1);
}

#[test]
fn gcm_auth_failure_still_advances_counter() {
    let key = synth_key();
    let sn = synth_nonce();
    let mut maker = SessionCryptoContext::new(&key, &sn).unwrap();
    let good = enc_frame_for(&mut maker, NonceDirection::ClientToServer, b"ABCDEF");

    // Tamper tag inside encrypted body (bytes 6..22 of raw frame).
    let mut bad = good.clone();
    bad[6] ^= 0xff;

    let mut s = BapSession::new(&key, &sn).unwrap();
    let err = s
        .decode_frame(NonceDirection::ClientToServer, &bad)
        .unwrap_err();
    assert_eq!(err, BapSessionError::DecryptFailed);
    assert_eq!(s.client_to_server_counter(), 1);

    // Next good frame must use counter=1 nonce (same as maker's second).
    let good2 = enc_frame_for(&mut maker, NonceDirection::ClientToServer, b"GHIJKL");
    let ok = s
        .decode_frame(NonceDirection::ClientToServer, &good2)
        .unwrap();
    assert!(ok.is_decrypted());
    assert_eq!(s.client_to_server_counter(), 2);
}

#[test]
fn bad_magic() {
    let mut s = BapSession::new(&synth_key(), &synth_nonce()).unwrap();
    let err = s
        .decode_frame(NonceDirection::ClientToServer, &[0x00, 0x02, 0, 0, 0, 0])
        .unwrap_err();
    assert!(matches!(
        err,
        BapSessionError::Framing(FramingError::BadMagic(0x00))
    ));
    assert_eq!(s.client_to_server_counter(), 0);
}

#[test]
fn truncated_body() {
    let mut s = BapSession::new(&synth_key(), &synth_nonce()).unwrap();
    // Declares body_len=10 but only provides 2 body bytes.
    let err = s
        .decode_frame(
            NonceDirection::ClientToServer,
            &[0x01, 0x02, 0, 0, 0, 10, 0x00, 0x19],
        )
        .unwrap_err();
    assert!(matches!(
        err,
        BapSessionError::Framing(FramingError::TruncatedBody)
    ));
}

#[test]
fn clear_too_short() {
    let mut s = BapSession::new(&synth_key(), &synth_nonce()).unwrap();
    // body_len=4 < 6 required for clear header
    let err = s
        .decode_frame(
            NonceDirection::ClientToServer,
            &[0x01, 0x02, 0, 0, 0, 4, 0, 0, 0, 0],
        )
        .unwrap_err();
    assert!(matches!(
        err,
        BapSessionError::Framing(FramingError::TruncatedClearBody)
    ));
}

#[test]
fn encrypted_without_tag() {
    let mut s = BapSession::new(&synth_key(), &synth_nonce()).unwrap();
    let err = s
        .decode_frame(
            NonceDirection::ClientToServer,
            &[0x01, 0x01, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8],
        )
        .unwrap_err();
    assert!(matches!(
        err,
        BapSessionError::Framing(FramingError::TruncatedEncryptedTag)
    ));
    assert_eq!(s.client_to_server_counter(), 0);
}

#[test]
fn empty_ciphertext_no_nonce_consume() {
    let mut s = BapSession::new(&synth_key(), &synth_nonce()).unwrap();
    // tag only, no ciphertext
    let mut raw = vec![0x01, 0x01, 0, 0, 0, 16];
    raw.extend_from_slice(&[0u8; 16]);
    let err = s
        .decode_frame(NonceDirection::ClientToServer, &raw)
        .unwrap_err();
    assert_eq!(err, BapSessionError::EmptyCiphertext);
    assert_eq!(s.client_to_server_counter(), 0);
}

#[test]
fn trailing_bytes_rejected() {
    let mut s = BapSession::new(&synth_key(), &synth_nonce()).unwrap();
    let mut raw = clear_raw(0x1e, 0, b"");
    raw.push(0xff);
    let err = s
        .decode_frame(NonceDirection::ClientToServer, &raw)
        .unwrap_err();
    assert_eq!(err, BapSessionError::TrailingBytes);
}

#[test]
fn opaque_kind_no_nonce() {
    let mut s = BapSession::new(&synth_key(), &synth_nonce()).unwrap();
    // kind=3 opaque with 2-byte body
    let raw = [0x01u8, 0x03, 0, 0, 0, 2, 0xaa, 0xbb];
    let d = s
        .decode_frame(NonceDirection::ClientToServer, &raw)
        .unwrap();
    assert!(matches!(
        d,
        DecodedBapFrame::Opaque {
            kind: 3,
            body_len: 2
        }
    ));
    assert_eq!(s.client_to_server_counter(), 0);
}

#[test]
fn clear_round_trip_bytes() {
    let frame = destiny1_network::framing::clear_frame(0x19, 7, b"xyz");
    let bytes = frame.serialize().unwrap();
    let (parsed, n) = BapFrame::parse(&bytes).unwrap();
    assert_eq!(n, bytes.len());
    assert_eq!(parsed.serialize().unwrap(), bytes);
}

#[test]
fn encrypted_round_trip_bytes() {
    let tag = [9u8; 16];
    let ct = b"cipher";
    let frame = destiny1_network::framing::encrypted_frame(tag, ct);
    let bytes = frame.serialize().unwrap();
    let (parsed, n) = BapFrame::parse(&bytes).unwrap();
    assert_eq!(n, bytes.len());
    assert_eq!(parsed.serialize().unwrap(), bytes);
}

#[test]
fn verify_report_synthetic_mixed() {
    use destiny1_network::bap_session_verify;

    let key = synth_key();
    let sn = synth_nonce();
    let mut maker = SessionCryptoContext::new(&key, &sn).unwrap();
    let c_clear = clear_raw(0x1e, 0, b"");
    let c_enc = enc_frame_for(&mut maker, NonceDirection::ClientToServer, b"ABCDEF");
    let s_enc = enc_frame_for(&mut maker, NonceDirection::ServerToClient, b"ABCDEFGH");

    let json = format!(
        r#"{{
          "capture":"synth",
          "session_key_hex":"{k}",
          "session_nonce_hex":"{sn}",
          "frames":[
            {{"direction":"client_to_server","frame_hex":"{cc}","expected_kind":2,"expected_msg_id":30}},
            {{"direction":"client_to_server","frame_hex":"{ce}","expected_kind":1,"expected_plaintext_len":6}},
            {{"direction":"server_to_client","frame_hex":"{se}","expected_kind":1,"expected_plaintext_len":8}},
            {{"direction":"client_to_server","expected_kind":1}}
          ]
        }}"#,
        k = hex(&key),
        sn = hex(&sn),
        cc = hex(&c_clear),
        ce = hex(&c_enc),
        se = hex(&s_enc),
    );
    let report = bap_session_verify::verify_from_json_str(&json).unwrap();
    assert!(report.verified());
    assert_eq!(report.clear_frames, 1);
    assert_eq!(report.encrypted_frames, 3); // 2 with wire + 1 unavailable
    assert_eq!(report.encrypted_decrypt_success, 2);
    assert_eq!(report.encrypted_decrypt_failed, 0);
    assert_eq!(report.wire_material_unavailable, 1);
    assert!(!report.to_string().contains("SYNTH"));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
