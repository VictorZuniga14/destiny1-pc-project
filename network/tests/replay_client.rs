//! BapReplayClient unit tests (M4.2).

use destiny1_network::local_protocol::{
    HandshakeReplayFixture, SIM_CONTEXT, MSG_1E, PAYLOAD_1E,
};
use destiny1_network::local_server::{LocalBapServer, LocalServerConfig};
use destiny1_network::replay_client::BapReplayClient;
use destiny1_network::bap_session::DecodedBapFrame;
use std::thread;
use std::time::Duration;

fn start_server() -> (LocalBapServer, std::net::SocketAddr) {
    let mut server = LocalBapServer::new(LocalServerConfig::loopback_ephemeral());
    let addr = server.bind().unwrap();
    server.start_background().unwrap();
    thread::sleep(Duration::from_millis(30));
    (server, addr)
}

#[test]
fn replay_client_connect_send_read() {
    let (mut server, addr) = start_server();
    let mut client = BapReplayClient::with_synthetic().unwrap();
    client.connect(addr).unwrap();
    assert!(client.is_connected());
    client.send_clear(MSG_1E, SIM_CONTEXT, PAYLOAD_1E).unwrap();
    let f = client.read_frame().unwrap();
    assert!(matches!(f, DecodedBapFrame::Clear { msg_id: 0x1F, .. }));
    client.close();
    server.shutdown();
}

#[test]
fn run_handshake_reaches_ready() {
    let (mut server, addr) = start_server();
    let mut client = BapReplayClient::with_synthetic().unwrap();
    client.connect(addr).unwrap();
    client.run_handshake().unwrap();
    assert_eq!(
        client.sim_state,
        destiny1_network::local_protocol::SimState::SimReady
    );
    assert!(client.session().client_to_server_counter() >= 1);
    assert!(client.session().server_to_client_counter() >= 1);
    client.close();
    server.shutdown();
}

#[test]
fn run_fixture_from_json() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/local_server/handshake_replay.json"
    );
    let text = std::fs::read_to_string(path).unwrap();
    let fx: HandshakeReplayFixture = serde_json::from_str(&text).unwrap();
    assert_eq!(fx.protocol, "SIMULATED_HANDSHAKE");

    let (mut server, addr) = start_server();
    let mut client = BapReplayClient::with_synthetic().unwrap();
    client.connect(addr).unwrap();
    client.run_fixture(&fx).unwrap();
    client.close();
    server.shutdown();
}

#[test]
fn clean_close_no_hang() {
    let (mut server, addr) = start_server();
    let mut client = BapReplayClient::with_synthetic().unwrap();
    client.connect(addr).unwrap();
    client.close();
    server.shutdown();
}
