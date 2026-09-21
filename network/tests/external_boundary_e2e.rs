//! E2E tests for M4.7 external boundary.

use destiny1_network::bap_session::BapSession;
use destiny1_network::compatibility_client::BapCompatibilityClient;
use destiny1_network::external_boundary_verify;
use destiny1_network::external_client_boundary::{
    BoundaryTestClient, ExternalBoundaryEvent, ExternalBoundaryHarness, ExternalClientConnection,
    ExternalListenerConfig,
};
use destiny1_network::local_protocol::{
    PAYLOAD_19, PAYLOAD_1E, PAYLOAD_79, PAYLOAD_FA, MSG_19, MSG_1E, MSG_79,
};
use destiny1_network::protocol_state::ProtocolState;
use destiny1_network::test_crypto_material::{SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE};
use std::thread;
use std::time::Duration;

#[test]
fn e2e_compatibility_through_boundary() {
    let mut harness = ExternalBoundaryHarness::start(ExternalListenerConfig {
        read_timeout: Some(Duration::from_secs(3)),
        ..ExternalListenerConfig::loopback_ephemeral()
    })
    .unwrap();
    thread::sleep(Duration::from_millis(40));
    let mut client = BapCompatibilityClient::new_synthetic();
    client.connect(harness.addr()).unwrap();
    client.run_handshake().unwrap();
    client.send_nat_probe().unwrap();
    let _ = client.send_keepalive().unwrap();
    client.send_unknown(0xAB, b"UNK").unwrap();
    client.close().unwrap();
    thread::sleep(Duration::from_millis(100));
    let ev = harness.events();
    assert!(ev.iter().any(|e| matches!(
        e,
        ExternalBoundaryEvent::ConnectionAccepted { .. }
    )));
    assert!(ev.iter().any(|e| matches!(
        e,
        ExternalBoundaryEvent::FrameRecovered { .. }
    )));
    harness.shutdown();
}

#[test]
fn multiple_frames_one_write() {
    let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
    let _ = c.feed_bytes(&BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E));
    let _ = c.take_outbound();
    let _ = c.feed_bytes(&BapSession::encode_clear(MSG_19, 1, PAYLOAD_19));
    let _ = c.take_outbound();
    let mut sess = BapSession::new(&SYNTHETIC_SESSION_KEY, &SYNTHETIC_SESSION_NONCE).unwrap();
    let f79 = sess
        .encode_encrypted(
            destiny1_network::crypto::NonceDirection::ClientToServer,
            MSG_79,
            1,
            PAYLOAD_79,
        )
        .unwrap();
    let _ = c.feed_bytes(&f79);
    let _ = c.take_outbound();
    assert!(matches!(
        c.protocol_state(),
        ProtocolState::EncryptedChannelEstablished | ProtocolState::Active
    ));
    let a = BapSession::encode_clear(0x12E, 1, b"A");
    let b = BapSession::encode_clear(0xFA, 1, PAYLOAD_FA);
    let d = BapSession::encode_clear(0xAB, 1, b"U");
    let mut all = Vec::new();
    all.extend_from_slice(&a);
    all.extend_from_slice(&b);
    all.extend_from_slice(&d);
    assert_eq!(c.feed_bytes(&all).unwrap(), 3);
}

#[test]
fn two_and_three_clients_isolated() {
    let mut a = ExternalClientConnection::new_synthetic(1).unwrap();
    let b = ExternalClientConnection::new_synthetic(2).unwrap();
    let mut c = ExternalClientConnection::new_synthetic(3).unwrap();
    let _ = a.feed_bytes(&BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E));
    let _ = a.feed_bytes(&BapSession::encode_clear(MSG_19, 1, PAYLOAD_19));
    assert_eq!(a.protocol_state(), ProtocolState::SessionEstablished);
    assert_eq!(
        b.protocol_state(),
        ProtocolState::WaitingForServiceHandshake
    );
    let _ = c.feed_bytes(&BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E));
    assert_eq!(
        c.protocol_state(),
        ProtocolState::ServiceHandshakeComplete
    );
    assert_ne!(a.protocol_state(), b.protocol_state());
    assert_ne!(a.protocol_state(), c.protocol_state());
}

#[test]
fn boundary_test_client_fragmented() {
    let mut harness = ExternalBoundaryHarness::start(ExternalListenerConfig {
        read_timeout: Some(Duration::from_secs(3)),
        ..ExternalListenerConfig::loopback_ephemeral()
    })
    .unwrap();
    thread::sleep(Duration::from_millis(40));
    let mut client = BoundaryTestClient::with_synthetic().unwrap();
    client.connect(harness.addr()).unwrap();
    let frame = BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E);
    client.send_fragmented(&frame, 3).unwrap();
    thread::sleep(Duration::from_millis(100));
    let ev = harness.events();
    assert!(ev.iter().any(|e| matches!(
        e,
        ExternalBoundaryEvent::FrameRecovered { .. }
    )));
    client.close();
    harness.shutdown();
}

#[test]
fn verify_cli() {
    external_boundary_verify::run_default().expect("EXTERNAL_BOUNDARY_VERIFY: VERIFIED");
}
