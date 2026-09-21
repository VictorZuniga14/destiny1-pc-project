//! Unit tests for BapCompatibilityClient (M4.6).

use destiny1_network::bap_session::BapSession;
use destiny1_network::compatibility_client::{
    assert_localhost_only, BapCompatibilityClient, ClientProtocolState,
};
use destiny1_network::local_protocol::SIM_CONTEXT;
use destiny1_network::local_server::{LocalBapServer, LocalServerConfig};
use destiny1_network::test_crypto_material::{SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE};
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

fn boot() -> (LocalBapServer, SocketAddr) {
    let mut server = LocalBapServer::new(LocalServerConfig {
        read_timeout: Some(Duration::from_secs(3)),
        write_timeout: Some(Duration::from_secs(3)),
        ..LocalServerConfig::loopback_ephemeral()
    });
    let addr = server.bind().unwrap();
    server.start_background().unwrap();
    thread::sleep(Duration::from_millis(40));
    (server, addr)
}

#[test]
fn initial_state_disconnected() {
    let c = BapCompatibilityClient::new_synthetic();
    assert_eq!(c.state(), ClientProtocolState::Disconnected);
}

#[test]
fn localhost_connection() {
    let (mut server, addr) = boot();
    let mut c = BapCompatibilityClient::new_synthetic();
    c.connect(addr).unwrap();
    assert_eq!(c.state(), ClientProtocolState::Connected);
    assert!(c.is_connected());
    c.close().unwrap();
    server.shutdown();
}

#[test]
fn no_external_endpoint() {
    let addr = SocketAddr::from(([1, 2, 3, 4], 80));
    assert!(assert_localhost_only(addr).is_err());
    let mut c = BapCompatibilityClient::new_synthetic();
    assert!(c.connect(addr).is_err());
}

#[test]
fn full_handshake() {
    let (mut server, addr) = boot();
    let mut c = BapCompatibilityClient::new_synthetic();
    c.connect(addr).unwrap();
    c.run_handshake().unwrap();
    assert_eq!(c.state(), ClientProtocolState::Active);
    assert_eq!(c.client_to_server_counter(), 1);
    assert_eq!(c.server_to_client_counter(), 1);
    c.close().unwrap();
    server.shutdown();
}

#[test]
fn synthetic_crypto_bases_differ() {
    let (mut server, addr) = boot();
    let mut c = BapCompatibilityClient::new_synthetic();
    c.connect(addr).unwrap();
    c.run_handshake().unwrap();
    let crypto = c.session().unwrap().crypto();
    assert_ne!(
        crypto.client_to_server_base(),
        crypto.server_to_client_base()
    );
    assert_eq!(crypto.session_key(), &SYNTHETIC_SESSION_KEY);
    assert_eq!(crypto.session_nonce(), &SYNTHETIC_SESSION_NONCE);
    c.close().unwrap();
    server.shutdown();
}

#[test]
fn post_handshake_12e_and_keepalive() {
    let (mut server, addr) = boot();
    let mut c = BapCompatibilityClient::new_synthetic();
    c.connect(addr).unwrap();
    c.run_handshake().unwrap();
    c.send_nat_probe().unwrap();
    let _ = c.send_keepalive().unwrap();
    assert_eq!(c.state(), ClientProtocolState::Active);
    c.close().unwrap();
    server.shutdown();
}

#[test]
fn unknown_message_no_panic() {
    let (mut server, addr) = boot();
    let mut c = BapCompatibilityClient::new_synthetic();
    c.connect(addr).unwrap();
    c.run_handshake().unwrap();
    c.send_unknown(0xAB, b"UNK").unwrap();
    assert_eq!(c.state(), ClientProtocolState::Active);
    c.close().unwrap();
    server.shutdown();
}

#[test]
fn split_frame_feed() {
    let (mut server, addr) = boot();
    let mut c = BapCompatibilityClient::new_synthetic();
    c.connect(addr).unwrap();
    let frame = BapSession::encode_clear(0x1F, SIM_CONTEXT, b"SIM_1F");
    let mid = frame.len() / 3;
    assert!(c.feed_bytes(&frame[..mid]).unwrap().is_empty());
    assert!(c.feed_bytes(&frame[mid..mid * 2]).unwrap().is_empty());
    let got = c.feed_bytes(&frame[mid * 2..]).unwrap();
    assert_eq!(got.len(), 1);
    c.close().unwrap();
    server.shutdown();
}

#[test]
fn multiple_frames_one_feed() {
    let (mut server, addr) = boot();
    let mut c = BapCompatibilityClient::new_synthetic();
    c.connect(addr).unwrap();
    let a = BapSession::encode_clear(0x11, 1, b"A");
    let b = BapSession::encode_clear(0x22, 1, b"B");
    let cframe = BapSession::encode_clear(0x33, 1, b"C");
    let mut all = Vec::new();
    all.extend_from_slice(&a);
    all.extend_from_slice(&b);
    all.extend_from_slice(&cframe);
    assert_eq!(c.feed_bytes(&all).unwrap().len(), 3);
    c.close().unwrap();
    server.shutdown();
}

#[test]
fn safe_event_trace() {
    let (mut server, addr) = boot();
    let mut c = BapCompatibilityClient::new_synthetic();
    c.connect(addr).unwrap();
    c.run_handshake().unwrap();
    let log = c.safe_event_log().join("\n");
    assert!(log.contains("Connected"));
    assert!(log.contains("StateTransition"));
    assert!(!log.contains("00010203"));
    assert!(!log.contains("LOCALSERVER"));
    c.close().unwrap();
    server.shutdown();
}

#[test]
fn deterministic_handshake() {
    let (mut server, addr) = boot();
    let run = || {
        let mut c = BapCompatibilityClient::new_synthetic();
        c.connect(addr).unwrap();
        c.run_handshake().unwrap();
        let t = (
            c.state(),
            c.client_to_server_counter(),
            c.server_to_client_counter(),
        );
        c.close().unwrap();
        t
    };
    assert_eq!(run(), run());
    server.shutdown();
}
