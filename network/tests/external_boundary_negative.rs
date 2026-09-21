//! Negative tests for M4.7 external boundary.

use destiny1_network::bap_session::BapSession;
use destiny1_network::external_client_boundary::{
    ExternalClientConnection, ExternalConnectionState,
};
use destiny1_network::local_protocol::{PAYLOAD_19, PAYLOAD_79, MSG_19, MSG_79};
use destiny1_network::protocol_state::ProtocolState;
use destiny1_network::stateful_bap_session::SyntheticSessionMaterial;
use destiny1_network::stream_framing::MAX_BODY_LEN;
use destiny1_network::test_crypto_material::{SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE};

#[test]
fn invalid_magic() {
    let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
    assert!(c
        .feed_bytes(&[0x00, 0x02, 0x00, 0x00, 0x00, 0x00])
        .is_err());
    assert_eq!(c.connection_state(), ExternalConnectionState::Closed);
}

#[test]
fn invalid_kind() {
    let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
    // magic 0x01, kind 0x99, body_len 0
    assert!(c
        .feed_bytes(&[0x01, 0x99, 0x00, 0x00, 0x00, 0x00])
        .is_err());
}

#[test]
fn oversized_frame() {
    let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
    let mut hdr = vec![0x01, 0x02];
    let huge = (MAX_BODY_LEN as u32).saturating_add(1).to_be_bytes();
    hdr.extend_from_slice(&huge);
    assert!(c.feed_bytes(&hdr).is_err());
}

#[test]
fn truncated_frame_waits() {
    let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
    assert_eq!(c.feed_bytes(&[0x01, 0x02]).unwrap(), 0);
    assert!(c.buffered_len() > 0);
    assert_ne!(c.connection_state(), ExternalConnectionState::Closed);
}

#[test]
fn invalid_order_19_first() {
    let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
    assert!(c
        .feed_bytes(&BapSession::encode_clear(MSG_19, 1, PAYLOAD_19))
        .is_err());
}

#[test]
fn invalid_order_79_early() {
    let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
    let _ = c.feed_bytes(&BapSession::encode_clear(0x1E, 1, b"SIM_1E"));
    let mut sess = BapSession::new(&SYNTHETIC_SESSION_KEY, &SYNTHETIC_SESSION_NONCE).unwrap();
    let f = sess
        .encode_encrypted(
            destiny1_network::crypto::NonceDirection::ClientToServer,
            MSG_79,
            1,
            PAYLOAD_79,
        )
        .unwrap();
    assert!(c.feed_bytes(&f).is_err());
}

#[test]
fn wrong_key() {
    let mut m = SyntheticSessionMaterial::default();
    m.key[0] ^= 0xff;
    let mut c = ExternalClientConnection::with_material(1, m).unwrap();
    let _ = c.feed_bytes(&BapSession::encode_clear(0x1E, 1, b"SIM_1E"));
    let _ = c.take_outbound();
    let _ = c.feed_bytes(&BapSession::encode_clear(MSG_19, 1, PAYLOAD_19));
    let _ = c.take_outbound();
    let mut sess = BapSession::new(&SYNTHETIC_SESSION_KEY, &SYNTHETIC_SESSION_NONCE).unwrap();
    let f = sess
        .encode_encrypted(
            destiny1_network::crypto::NonceDirection::ClientToServer,
            MSG_79,
            1,
            PAYLOAD_79,
        )
        .unwrap();
    assert!(c.feed_bytes(&f).is_err());
    assert_ne!(c.protocol_state(), ProtocolState::Active);
}

#[test]
fn wrong_nonce() {
    let mut m = SyntheticSessionMaterial::default();
    m.nonce[0] ^= 0xff;
    let mut c = ExternalClientConnection::with_material(1, m).unwrap();
    let _ = c.feed_bytes(&BapSession::encode_clear(0x1E, 1, b"SIM_1E"));
    let _ = c.take_outbound();
    let _ = c.feed_bytes(&BapSession::encode_clear(MSG_19, 1, PAYLOAD_19));
    let _ = c.take_outbound();
    let mut sess = BapSession::new(&SYNTHETIC_SESSION_KEY, &SYNTHETIC_SESSION_NONCE).unwrap();
    let f = sess
        .encode_encrypted(
            destiny1_network::crypto::NonceDirection::ClientToServer,
            MSG_79,
            1,
            PAYLOAD_79,
        )
        .unwrap();
    assert!(c.feed_bytes(&f).is_err());
}

#[test]
fn tampered_ciphertext() {
    let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
    let _ = c.feed_bytes(&BapSession::encode_clear(0x1E, 1, b"SIM_1E"));
    let _ = c.take_outbound();
    let _ = c.feed_bytes(&BapSession::encode_clear(MSG_19, 1, PAYLOAD_19));
    let _ = c.take_outbound();
    let mut sess = BapSession::new(&SYNTHETIC_SESSION_KEY, &SYNTHETIC_SESSION_NONCE).unwrap();
    let mut f = sess
        .encode_encrypted(
            destiny1_network::crypto::NonceDirection::ClientToServer,
            MSG_79,
            1,
            PAYLOAD_79,
        )
        .unwrap();
    let i = f.len() - 2;
    f[i] ^= 0xaa;
    assert!(c.feed_bytes(&f).is_err());
}

#[test]
fn eof_graceful() {
    let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
    c.notify_eof();
    assert_eq!(c.connection_state(), ExternalConnectionState::Closed);
}
