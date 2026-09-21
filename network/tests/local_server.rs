//! Unit tests for LocalBapServer (M4.2).

use destiny1_network::local_protocol::{
    LocalMessageDispatcher, ProtocolErrorKind, ServerAction, SimState, MSG_1E, MSG_7A,
    PAYLOAD_7A, SIM_CONTEXT, SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE,
};
use destiny1_network::local_server::{LocalBapServer, LocalServerConfig};
use destiny1_network::bap_session::{BapSession, DecodedBapFrame};
use destiny1_network::stream_framing::BapStreamDecoder;
use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

#[test]
fn server_binds_ephemeral_port() {
    let mut server = LocalBapServer::new(LocalServerConfig::loopback_ephemeral());
    let addr = server.bind().expect("bind");
    assert_eq!(addr.ip().to_string(), "127.0.0.1");
    assert_ne!(addr.port(), 0);
    assert_eq!(server.port(), Some(addr.port()));
    let banner = server.status_banner();
    assert!(banner.contains("LOCAL_BAP_SERVER"));
    assert!(banner.contains("LISTENING"));
    assert!(banner.contains("key_present=true"));
    assert!(banner.contains("nonce_present=true"));
    // Must not dump raw key material.
    assert!(!banner.contains("LOCALSERVER_KEY"));
}

#[test]
fn server_accepts_connection() {
    let mut server = LocalBapServer::new(LocalServerConfig::loopback_ephemeral());
    let addr = server.bind().unwrap();
    server.start_background().unwrap();
    thread::sleep(Duration::from_millis(30));
    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).expect("connect");
    drop(stream);
    thread::sleep(Duration::from_millis(50));
    server.shutdown();
}

#[test]
fn clear_frame_c2s_gets_1f() {
    let mut server = LocalBapServer::new(LocalServerConfig::loopback_ephemeral());
    let addr = server.bind().unwrap();
    server.start_background().unwrap();
    thread::sleep(Duration::from_millis(30));

    let mut client = destiny1_network::BapReplayClient::with_synthetic().unwrap();
    client.connect(addr).unwrap();
    client
        .send_clear(
            MSG_1E,
            SIM_CONTEXT,
            destiny1_network::local_protocol::PAYLOAD_1E,
        )
        .unwrap();
    let frame = client.read_frame().unwrap();
    match frame {
        DecodedBapFrame::Clear { msg_id, .. } => assert_eq!(msg_id, 0x1F),
        other => panic!("unexpected {other:?}"),
    }
    client.close();
    server.shutdown();
}

#[test]
fn dispatcher_unexpected_7a() {
    let mut d = LocalMessageDispatcher::new();
    d.state = SimState::Sim1aSent;
    let frame = DecodedBapFrame::Decrypted {
        msg_id: Some(MSG_7A),
        context: Some(SIM_CONTEXT),
        payload: PAYLOAD_7A.to_vec(),
        plaintext_len: 6 + PAYLOAD_7A.len(),
    };
    let actions = d.dispatch_inbound(&frame);
    assert!(matches!(
        actions.first(),
        Some(ServerAction::ProtocolError {
            kind: ProtocolErrorKind::UnexpectedMessage,
            ..
        })
    ));
}

#[test]
fn truncated_frame_decoder_waits() {
    let mut dec = BapStreamDecoder::new();
    // Partial header only — must not error / panic.
    let partial = [0x01u8, 0x02];
    let frames = dec.push(&partial).expect("incomplete ok");
    assert!(frames.is_empty());
    assert!(dec.buffered_len() > 0);
}

#[test]
fn invalid_magic_rejected_by_server() {
    let mut server = LocalBapServer::new(LocalServerConfig::loopback_ephemeral());
    let addr = server.bind().unwrap();
    server.start_background().unwrap();
    thread::sleep(Duration::from_millis(30));

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
    stream.write_all(&[0xFF, 0x02, 0, 0, 0, 0]).unwrap();
    thread::sleep(Duration::from_millis(100));
    // Server should close; further write may fail eventually.
    let traces = server.traces();
    assert!(
        traces.iter().any(|t| t.action.contains("PROTOCOL_ERROR")),
        "traces={traces:?}"
    );
    server.shutdown();
}

#[test]
fn invalid_kind_rejected() {
    let mut server = LocalBapServer::new(LocalServerConfig::loopback_ephemeral());
    let addr = server.bind().unwrap();
    server.start_background().unwrap();
    thread::sleep(Duration::from_millis(30));

    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
    // magic=1, kind=0xFF, body_len=0
    stream.write_all(&[0x01, 0xFF, 0, 0, 0, 0]).unwrap();
    thread::sleep(Duration::from_millis(100));
    let traces = server.traces();
    assert!(
        traces.iter().any(|t| t.action.contains("PROTOCOL_ERROR")),
        "traces={traces:?}"
    );
    server.shutdown();
}

#[test]
fn synthetic_session_counters_start_zero() {
    let s = BapSession::new(&SYNTHETIC_SESSION_KEY, &SYNTHETIC_SESSION_NONCE).unwrap();
    assert_eq!(s.client_to_server_counter(), 0);
    assert_eq!(s.server_to_client_counter(), 0);
    let c2s = s.crypto().client_to_server_base();
    let s2c = s.crypto().server_to_client_base();
    assert_ne!(c2s, s2c);
}
