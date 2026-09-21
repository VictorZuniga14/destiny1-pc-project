//! Negative tests for M4.6 compatibility client.

use destiny1_network::bap_session::BapSession;
use destiny1_network::compatibility_client::{
    BapCompatibilityClient, ClientProtocolState, CompatibilityClientError,
};
use destiny1_network::local_protocol::{SIM_CONTEXT, SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE};
use destiny1_network::local_server::{LocalBapServer, LocalServerConfig};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::thread;
use std::time::Duration;

fn boot() -> (LocalBapServer, std::net::SocketAddr) {
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
fn wrong_key_rejected() {
    let (mut server, addr) = boot();
    let mut key = SYNTHETIC_SESSION_KEY;
    key[0] ^= 0xff;
    let mut c = BapCompatibilityClient::with_material(key, SYNTHETIC_SESSION_NONCE);
    c.connect(addr).unwrap();
    let err = c.run_handshake();
    assert!(err.is_err(), "wrong key must fail");
    assert_ne!(c.state(), ClientProtocolState::Active);
    c.close().ok();
    server.shutdown();
}

#[test]
fn wrong_nonce_rejected() {
    let (mut server, addr) = boot();
    let mut nonce = SYNTHETIC_SESSION_NONCE;
    nonce[0] ^= 0xff;
    let mut c = BapCompatibilityClient::with_material(SYNTHETIC_SESSION_KEY, nonce);
    c.connect(addr).unwrap();
    assert!(c.run_handshake().is_err());
    assert_ne!(c.state(), ClientProtocolState::Active);
    c.close().ok();
    server.shutdown();
}

#[test]
fn tampered_ciphertext_rejected() {
    let mut client = BapCompatibilityClient::new_synthetic();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let h = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let _ = s.set_read_timeout(Some(Duration::from_millis(300)));
        let mut buf = [0u8; 16];
        let _ = s.read(&mut buf);
        let _ = s.shutdown(Shutdown::Both);
    });
    client.connect(addr).unwrap();
    let mut sess = BapSession::new(&SYNTHETIC_SESSION_KEY, &SYNTHETIC_SESSION_NONCE).unwrap();
    let mut frame = sess
        .encode_encrypted(
            destiny1_network::crypto::NonceDirection::ServerToClient,
            0x7A,
            SIM_CONTEXT,
            b"SIM_7A",
        )
        .unwrap();
    let i = frame.len() - 2;
    frame[i] ^= 0xaa;
    let err = client.feed_bytes(&frame);
    assert!(
        matches!(err, Err(CompatibilityClientError::Crypto(_))),
        "got {err:?}"
    );
    client.close().ok();
    let _ = h.join();
}

#[test]
fn invalid_order_1f_when_expecting_7a() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let h = thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let frame = BapSession::encode_clear(0x1F, SIM_CONTEXT, b"SIM_1F");
        let _ = s.write_all(&frame);
        thread::sleep(Duration::from_millis(40));
        let _ = s.shutdown(Shutdown::Both);
    });
    let mut c = BapCompatibilityClient::new_synthetic();
    c.connect(addr).unwrap();
    let f = c.read_frame().unwrap();
    let err = c.validate_expected_response(&f, 0x7A);
    assert!(matches!(
        err,
        Err(CompatibilityClientError::UnexpectedMessage(0x1F))
    ));
    assert_ne!(c.state(), ClientProtocolState::Active);
    c.close().ok();
    let _ = h.join();
}

#[test]
fn malformed_incomplete_frame_no_panic() {
    let (mut server, addr) = boot();
    let mut c = BapCompatibilityClient::new_synthetic();
    c.connect(addr).unwrap();
    let partial = [0x01u8, 0x02];
    let frames = c.feed_bytes(&partial).unwrap();
    assert!(frames.is_empty());
    c.close().ok();
    server.shutdown();
}

#[test]
fn encrypted_before_ready_rejected() {
    let (mut server, addr) = boot();
    let mut c = BapCompatibilityClient::new_synthetic();
    c.connect(addr).unwrap();
    let err = c.send_encrypted(0x79, b"SIM_79");
    assert!(matches!(
        err,
        Err(CompatibilityClientError::InvalidState(_))
    ));
    c.close().ok();
    server.shutdown();
}
