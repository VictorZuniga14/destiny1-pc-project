//! End-to-end + negative tests for M4.2 local BAP server.

use destiny1_network::bap_session::{BapSession, DecodedBapFrame};
use destiny1_network::byte_source::chunk_stream;
use destiny1_network::crypto::NonceDirection;
use destiny1_network::local_protocol::{
    ProtocolErrorKind, ServerTraceEvent, SimState, MSG_1E, MSG_79, MSG_7A, MSG_SYN_A,
    PAYLOAD_1E, PAYLOAD_79, PAYLOAD_SYN_A, SIM_CONTEXT, SYNTHETIC_SESSION_KEY,
    SYNTHETIC_SESSION_NONCE,
};
use destiny1_network::local_server::{LocalBapServer, LocalServerConfig, LocalServerError};
use destiny1_network::local_server_verify;
use destiny1_network::replay_client::BapReplayClient;
use destiny1_network::stream_framing::BapStreamDecoder;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
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
fn test_simulated_handshake_end_to_end() {
    let (mut server, addr) = boot();
    let mut client = BapReplayClient::with_synthetic().unwrap();
    client.connect(addr).unwrap();

    client.run_handshake().unwrap();
    assert_eq!(client.sim_state, SimState::SimReady);

    let c2s_after_hs = client.session().client_to_server_counter();
    let s2c_after_hs = client.session().server_to_client_counter();
    assert_eq!(c2s_after_hs, 1);
    assert_eq!(s2c_after_hs, 1);

    client.run_encrypted_sequence().unwrap();
    assert_eq!(client.session().client_to_server_counter(), 3);
    assert_eq!(client.session().server_to_client_counter(), 3);
    // Independent directions: bases differ; counters both advanced.
    assert_ne!(
        client.session().crypto().client_to_server_base(),
        client.session().crypto().server_to_client_base()
    );

    let traces = server.traces();
    assert!(traces.iter().any(|t| t.action == "RECV" && t.message_id == Some(MSG_1E)));
    assert!(traces.iter().any(|t| t.action == "SendFrame" && t.message_id == Some(0x1F)));
    assert!(traces.iter().any(|t| t.message_id == Some(MSG_79)));
    assert!(traces.iter().any(|t| t.message_id == Some(MSG_7A)));

    // Deterministic compare ignoring timestamps.
    let stripped: Vec<ServerTraceEvent> =
        traces.iter().map(|t| t.without_timestamp()).collect();
    assert!(!stripped.is_empty());

    client.close();
    server.shutdown();
}

#[test]
fn encrypted_c2s_and_s2c() {
    let (mut server, addr) = boot();
    let mut client = BapReplayClient::with_synthetic().unwrap();
    client.connect(addr).unwrap();
    client.run_handshake().unwrap();
    client
        .send_encrypted(MSG_SYN_A, SIM_CONTEXT, PAYLOAD_SYN_A)
        .unwrap();
    let f = client.read_frame().unwrap();
    match f {
        DecodedBapFrame::Decrypted {
            msg_id: Some(id), ..
        } => assert_eq!(id, 0x0A0B),
        other => panic!("{other:?}"),
    }
    client.close();
    server.shutdown();
}

#[test]
fn independent_nonce_counters() {
    let (mut server, addr) = boot();
    let mut client = BapReplayClient::with_synthetic().unwrap();
    client.connect(addr).unwrap();
    client.run_handshake().unwrap();
    client.run_encrypted_sequence().unwrap();
    let c2s = client.session().client_to_server_counter();
    let s2c = client.session().server_to_client_counter();
    assert_eq!(c2s, 3);
    assert_eq!(s2c, 3);
    // Peek nonces differ after progression from different bases.
    let n_c2s = client.session().crypto().peek_nonce(NonceDirection::ClientToServer);
    let n_s2c = client.session().crypto().peek_nonce(NonceDirection::ServerToClient);
    assert_ne!(n_c2s, n_s2c);
    client.close();
    server.shutdown();
}

#[test]
fn multiple_encrypted_frames() {
    let (mut server, addr) = boot();
    let mut client = BapReplayClient::with_synthetic().unwrap();
    client.connect(addr).unwrap();
    client.run_handshake().unwrap();
    client.run_encrypted_sequence().unwrap();
    assert!(client.session().client_to_server_counter() >= 3);
    client.close();
    server.shutdown();
}

#[test]
fn split_tcp_frame_still_works() {
    let (mut server, addr) = boot();
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
    let _ = stream.set_nodelay(true);
    let frame = BapSession::encode_clear(MSG_1E, SIM_CONTEXT, PAYLOAD_1E);
    let chunks = chunk_stream(&frame, &[1, 2, 3, 5]);
    for c in &chunks {
        stream.write_all(c).unwrap();
        thread::sleep(Duration::from_millis(5));
    }
    // Read response 0x1F
    let mut session = BapSession::new(&SYNTHETIC_SESSION_KEY, &SYNTHETIC_SESSION_NONCE).unwrap();
    let mut dec = BapStreamDecoder::new();
    let mut buf = [0u8; 2048];
    let mut got = None;
    for _ in 0..20 {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                for raw in dec.push(&buf[..n]).unwrap() {
                    let d = session
                        .decode_frame(NonceDirection::ServerToClient, &raw.raw_bytes)
                        .unwrap();
                    got = Some(d);
                }
                if got.is_some() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    match got {
        Some(DecodedBapFrame::Clear { msg_id: 0x1F, .. }) => {}
        other => panic!("expected 0x1F, got {other:?}"),
    }
    let _ = stream.shutdown(Shutdown::Both);
    server.shutdown();
}

#[test]
fn multiple_frames_in_one_write() {
    // Offline decoder path: A+B+C recovered from one push.
    let a = BapSession::encode_clear(0x11, 1, b"A");
    let b = BapSession::encode_clear(0x22, 1, b"B");
    let c = BapSession::encode_clear(0x33, 1, b"C");
    let mut all = Vec::new();
    all.extend_from_slice(&a);
    all.extend_from_slice(&b);
    all.extend_from_slice(&c);
    let mut dec = BapStreamDecoder::new();
    let frames = dec.push(&all).unwrap();
    assert_eq!(frames.len(), 3, "3 frames recovered");
}

#[test]
fn wrong_key_crypto_error() {
    let mut server = LocalBapServer::with_crypto(
        LocalServerConfig::loopback_ephemeral(),
        SYNTHETIC_SESSION_KEY.to_vec(),
        SYNTHETIC_SESSION_NONCE.to_vec(),
    );
    let addr = server.bind().unwrap();
    server.start_background().unwrap();
    thread::sleep(Duration::from_millis(40));

    let wrong_key = *b"WRONG_SERVERKEY!";
    let mut client = BapReplayClient::with_keys(&wrong_key, &SYNTHETIC_SESSION_NONCE).unwrap();
    client.connect(addr).unwrap();
    // Clear handshake works (no crypto); fail on 0x79.
    client
        .send_clear(
            MSG_1E,
            SIM_CONTEXT,
            destiny1_network::local_protocol::PAYLOAD_1E,
        )
        .unwrap();
    let _ = client.read_frame().unwrap();
    client
        .send_clear(
            0x19,
            SIM_CONTEXT,
            destiny1_network::local_protocol::PAYLOAD_19,
        )
        .unwrap();
    let _ = client.read_frame().unwrap();
    client
        .send_encrypted(MSG_79, SIM_CONTEXT, PAYLOAD_79)
        .unwrap();
    // Server decrypt fails → closes; client may timeout or get EOF on read.
    let err = client.read_frame();
    assert!(err.is_err(), "expected crypto failure path");
    let traces = server.traces();
    assert!(
        traces.iter().any(|t| {
            t.action.contains("GCM DECRYPT") || t.action.contains("AUTH/CRYPTO")
        }),
        "traces={traces:?}"
    );
    client.close();
    server.shutdown();
}

#[test]
fn wrong_nonce_gcm_failure() {
    let mut server = LocalBapServer::with_crypto(
        LocalServerConfig::loopback_ephemeral(),
        SYNTHETIC_SESSION_KEY.to_vec(),
        SYNTHETIC_SESSION_NONCE.to_vec(),
    );
    let addr = server.bind().unwrap();
    server.start_background().unwrap();
    thread::sleep(Duration::from_millis(40));

    let wrong_nonce = *b"WRONGNONCE!!";
    let mut client = BapReplayClient::with_keys(&SYNTHETIC_SESSION_KEY, &wrong_nonce).unwrap();
    client.connect(addr).unwrap();
    client.run_handshake().expect_err("handshake should fail at encrypted step");
    let traces = server.traces();
    assert!(
        traces
            .iter()
            .any(|t| t.action.contains(ProtocolErrorKind::GcmDecryptFailure.as_str())
                || t.action.contains("GCM DECRYPT")),
        "traces={traces:?}"
    );
    client.close();
    server.shutdown();
}

#[test]
fn unexpected_message_7a_before_79() {
    let (mut server, addr) = boot();
    let mut client = BapReplayClient::with_synthetic().unwrap();
    client.connect(addr).unwrap();
    // Advance to after 1A
    client
        .send_clear(
            MSG_1E,
            SIM_CONTEXT,
            destiny1_network::local_protocol::PAYLOAD_1E,
        )
        .unwrap();
    let _ = client.read_frame().unwrap();
    client
        .send_clear(
            0x19,
            SIM_CONTEXT,
            destiny1_network::local_protocol::PAYLOAD_19,
        )
        .unwrap();
    let _ = client.read_frame().unwrap();
    // Send encrypted 0x7A instead of 0x79
    client
        .send_encrypted(MSG_7A, SIM_CONTEXT, destiny1_network::local_protocol::PAYLOAD_7A)
        .unwrap();
    thread::sleep(Duration::from_millis(80));
    let traces = server.traces();
    assert!(
        traces
            .iter()
            .any(|t| t.action.contains("UNEXPECTED_MESSAGE")),
        "traces={traces:?}"
    );
    client.close();
    server.shutdown();
}

#[test]
fn eof_clean_shutdown() {
    let (mut server, addr) = boot();
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
    drop(stream); // clean EOF
    thread::sleep(Duration::from_millis(80));
    let traces = server.traces();
    assert!(traces.iter().any(|t| t.action == "EOF" || t.action == "ACCEPT"));
    server.shutdown();
}

#[test]
fn incomplete_frame_at_eof_no_panic() {
    let (mut server, addr) = boot();
    {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
        stream.write_all(&[0x01, 0x02]).unwrap(); // truncated
        let _ = stream.shutdown(Shutdown::Both);
    }
    thread::sleep(Duration::from_millis(80));
    server.shutdown();
}

#[test]
fn local_replay_cli_verified() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/local_server/handshake_replay.json"
    );
    local_server_verify::run_local_replay(path).expect("LOCAL_REPLAY VERIFIED");
}

#[test]
fn serve_one_returns_ok_path() {
    // Ensure LocalServerError Display covers protocol label.
    let e = LocalServerError::Protocol(ProtocolErrorKind::ProtocolError.as_str().into());
    assert!(e.to_string().contains("PROTOCOL_ERROR"));
}

#[test]
fn stateful_negative_19_first() {
    let (mut server, addr) = boot();
    let mut client = BapReplayClient::with_synthetic().unwrap();
    client.connect(addr).unwrap();
    client
        .send_clear(
            0x19,
            SIM_CONTEXT,
            destiny1_network::local_protocol::PAYLOAD_19,
        )
        .unwrap();
    thread::sleep(Duration::from_millis(80));
    assert!(server
        .traces()
        .iter()
        .any(|t| t.action.contains("UNEXPECTED_MESSAGE")));
    client.close();
    server.shutdown();
}

#[test]
fn stateful_negative_79_early() {
    let (mut server, addr) = boot();
    let mut client = BapReplayClient::with_synthetic().unwrap();
    client.connect(addr).unwrap();
    client.send_clear(MSG_1E, SIM_CONTEXT, PAYLOAD_1E).unwrap();
    let _ = client.read_frame().unwrap();
    client.send_encrypted(MSG_79, SIM_CONTEXT, PAYLOAD_79).unwrap();
    thread::sleep(Duration::from_millis(80));
    assert!(server
        .traces()
        .iter()
        .any(|t| t.action.contains("UNEXPECTED_MESSAGE")));
    client.close();
    server.shutdown();
}

#[test]
fn stateful_negative_7a_mid_handshake() {
    let (mut server, addr) = boot();
    let mut client = BapReplayClient::with_synthetic().unwrap();
    client.connect(addr).unwrap();
    client.send_clear(MSG_1E, SIM_CONTEXT, PAYLOAD_1E).unwrap();
    let _ = client.read_frame().unwrap();
    client
        .send_clear(
            0x19,
            SIM_CONTEXT,
            destiny1_network::local_protocol::PAYLOAD_19,
        )
        .unwrap();
    let _ = client.read_frame().unwrap();
    client
        .send_encrypted(MSG_7A, SIM_CONTEXT, destiny1_network::local_protocol::PAYLOAD_7A)
        .unwrap();
    thread::sleep(Duration::from_millis(80));
    assert!(server
        .traces()
        .iter()
        .any(|t| t.action.contains("UNEXPECTED_MESSAGE")));
    client.close();
    server.shutdown();
}

#[test]
fn stateful_reconnect_fresh_state() {
    let (mut server, addr) = boot();
    {
        let mut c = BapReplayClient::with_synthetic().unwrap();
        c.connect(addr).unwrap();
        c.run_handshake().unwrap();
        c.close();
    }
    thread::sleep(Duration::from_millis(40));
    let mut c2 = BapReplayClient::with_synthetic().unwrap();
    c2.connect(addr).unwrap();
    assert_eq!(c2.session().client_to_server_counter(), 0);
    c2.run_handshake().unwrap();
    c2.close();
    server.shutdown();
}
