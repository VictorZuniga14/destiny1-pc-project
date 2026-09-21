//! Integration tests for M4.5 stateful local server.

use destiny1_network::bap_session::DecodedBapFrame;
use destiny1_network::local_protocol::{
    PAYLOAD_19, PAYLOAD_1E, PAYLOAD_79, SIM_CONTEXT, MSG_1E, MSG_19, MSG_79,
};
use destiny1_network::local_server::{LocalBapServer, LocalServerConfig};
use destiny1_network::protocol_state::ProtocolState;
use destiny1_network::replay_client::BapReplayClient;
use destiny1_network::stateful_bap_session::StatefulBapSession;
use destiny1_network::stateful_server_verify;
use std::io::{Read, Write};
use std::net::TcpStream;
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
fn two_simultaneous_sessions_isolated() {
    let mut a = StatefulBapSession::new_synthetic(1).unwrap();
    let mut b = StatefulBapSession::new_synthetic(2).unwrap();
    let _ = a
        .handle_message({
            use destiny1_network::jsonl::Direction;
            use destiny1_network::message_codec::{BapMessage, KnownBapMessage, OpaquePayload};
            BapMessage::Known(KnownBapMessage::DestinyServiceHandshakeRequest(
                OpaquePayload {
                    context: SIM_CONTEXT,
                    direction: Direction::ClientToServer,
                    payload: PAYLOAD_1E.to_vec(),
                },
            ))
        })
        .unwrap();
    assert_ne!(a.protocol_state(), b.protocol_state());
    let _ = a
        .handle_message({
            use destiny1_network::jsonl::Direction;
            use destiny1_network::message_codec::{BapMessage, KnownBapMessage, OpaquePayload};
            BapMessage::Known(KnownBapMessage::SessionLoginRequest(OpaquePayload {
                context: SIM_CONTEXT,
                direction: Direction::ClientToServer,
                payload: PAYLOAD_19.to_vec(),
            }))
        })
        .unwrap();
    let _ = a
        .handle_message({
            use destiny1_network::jsonl::Direction;
            use destiny1_network::message_codec::{BapMessage, KnownBapMessage, OpaquePayload};
            BapMessage::Known(KnownBapMessage::EncryptedHandshakeRequest(
                OpaquePayload {
                    context: SIM_CONTEXT,
                    direction: Direction::ClientToServer,
                    payload: PAYLOAD_79.to_vec(),
                },
            ))
        })
        .unwrap();
    let _ = a
        .encode_encrypted_s2c(0x7A, SIM_CONTEXT, b"SIM_7A")
        .unwrap();
    assert_ne!(
        a.server_to_client_counter(),
        b.server_to_client_counter()
    );
    assert_eq!(b.protocol_state(), ProtocolState::WaitingForServiceHandshake);
    assert_eq!(b.client_to_server_counter(), 0);
}

#[test]
fn two_tcp_clients_independent() {
    let (mut server, addr) = boot();
    let mut c1 = BapReplayClient::with_synthetic().unwrap();
    let mut c2 = BapReplayClient::with_synthetic().unwrap();
    c1.connect(addr).unwrap();
    c2.connect(addr).unwrap();
    c1.run_handshake().unwrap();
    // c2 still at start — only 1E so far would leave different crypto progression
    c2.send_clear(MSG_1E, SIM_CONTEXT, PAYLOAD_1E).unwrap();
    let f = c2.read_frame().unwrap();
    match f {
        DecodedBapFrame::Clear { msg_id: 0x1F, .. } => {}
        other => panic!("{other:?}"),
    }
    assert_eq!(c1.session().client_to_server_counter(), 1);
    assert_eq!(c2.session().client_to_server_counter(), 0);
    c1.close();
    c2.close();
    server.shutdown();
}

#[test]
fn reconnect_starts_fresh() {
    let (mut server, addr) = boot();
    {
        let mut c = BapReplayClient::with_synthetic().unwrap();
        c.connect(addr).unwrap();
        c.run_handshake().unwrap();
        c.close();
    }
    thread::sleep(Duration::from_millis(50));
    let mut c2 = BapReplayClient::with_synthetic().unwrap();
    c2.connect(addr).unwrap();
    assert_eq!(c2.session().client_to_server_counter(), 0);
    assert_eq!(c2.session().server_to_client_counter(), 0);
    c2.run_handshake().unwrap();
    c2.close();
    server.shutdown();
}

#[test]
fn negative_19_first_rejected() {
    let (mut server, addr) = boot();
    let mut c = BapReplayClient::with_synthetic().unwrap();
    c.connect(addr).unwrap();
    c.send_clear(MSG_19, SIM_CONTEXT, PAYLOAD_19).unwrap();
    thread::sleep(Duration::from_millis(80));
    let traces = server.traces();
    assert!(
        traces
            .iter()
            .any(|t| t.action.contains("UNEXPECTED_MESSAGE")),
        "traces={traces:?}"
    );
    c.close();
    server.shutdown();
}

#[test]
fn negative_79_after_1e_rejected() {
    let (mut server, addr) = boot();
    let mut c = BapReplayClient::with_synthetic().unwrap();
    c.connect(addr).unwrap();
    c.send_clear(MSG_1E, SIM_CONTEXT, PAYLOAD_1E).unwrap();
    let _ = c.read_frame().unwrap();
    c.send_encrypted(MSG_79, SIM_CONTEXT, PAYLOAD_79).unwrap();
    thread::sleep(Duration::from_millis(80));
    let traces = server.traces();
    assert!(
        traces
            .iter()
            .any(|t| t.action.contains("UNEXPECTED_MESSAGE")),
        "traces={traces:?}"
    );
    c.close();
    server.shutdown();
}

#[test]
fn negative_7a_before_79_rejected() {
    let (mut server, addr) = boot();
    let mut c = BapReplayClient::with_synthetic().unwrap();
    c.connect(addr).unwrap();
    c.send_clear(MSG_1E, SIM_CONTEXT, PAYLOAD_1E).unwrap();
    let _ = c.read_frame().unwrap();
    c.send_clear(MSG_19, SIM_CONTEXT, PAYLOAD_19).unwrap();
    let _ = c.read_frame().unwrap();
    c.send_encrypted(0x7A, SIM_CONTEXT, b"SIM_7A").unwrap();
    thread::sleep(Duration::from_millis(80));
    let traces = server.traces();
    assert!(
        traces
            .iter()
            .any(|t| t.action.contains("UNEXPECTED_MESSAGE")),
        "traces={traces:?}"
    );
    c.close();
    server.shutdown();
}

#[test]
fn unknown_message_observed_no_auto_reply() {
    let (mut server, addr) = boot();
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1)).unwrap();
    let _ = stream.set_nodelay(true);
    let frame = destiny1_network::BapSession::encode_clear(0xABCD, SIM_CONTEXT, b"UNK");
    stream.write_all(&frame).unwrap();
    thread::sleep(Duration::from_millis(100));
    // Server should not send a synthetic reply; read may timeout.
    let _ = stream.set_read_timeout(Some(Duration::from_millis(150)));
    let mut buf = [0u8; 64];
    let n = stream.read(&mut buf).unwrap_or(0);
    assert_eq!(n, 0, "unknown must not auto-respond");
    let traces = server.traces();
    assert!(
        traces
            .iter()
            .any(|t| t.message_id == Some(0xABCD) && t.action == "RECV"),
        "traces={traces:?}"
    );
    assert!(
        !traces
            .iter()
            .any(|t| t.action == "SendFrame" && t.message_id == Some(0xABCD)),
        "should not invent reply"
    );
    drop(stream);
    server.shutdown();
}

#[test]
fn full_stateful_handshake_e2e() {
    let (mut server, addr) = boot();
    let mut c = BapReplayClient::with_synthetic().unwrap();
    c.connect(addr).unwrap();
    c.run_handshake().unwrap();
    c.send_encrypted(0x12E, SIM_CONTEXT, b"SIM_12E").unwrap();
    thread::sleep(Duration::from_millis(50));
    let traces = server.traces();
    assert!(traces.iter().any(|t| t.message_id == Some(0x1E)));
    assert!(traces.iter().any(|t| t.message_id == Some(0x1F)));
    assert!(traces.iter().any(|t| t.message_id == Some(0x19)));
    assert!(traces.iter().any(|t| t.message_id == Some(0x1A)));
    assert!(traces.iter().any(|t| t.message_id == Some(0x79)));
    assert!(traces.iter().any(|t| t.message_id == Some(0x7A)));
    assert!(traces.iter().any(|t| t.message_id == Some(0x12E)));
    c.close();
    server.shutdown();
}

#[test]
fn stateful_server_verify_cli() {
    stateful_server_verify::run_default().expect("STATEFUL_SERVER_VERIFY: VERIFIED");
}
