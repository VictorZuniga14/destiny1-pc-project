//! E2E tests for M4.6 compatibility client.

use destiny1_network::compatibility_client::{
    BapCompatibilityClient, ClientProtocolState, LocalCompatibilityScenario,
};
use destiny1_network::compatibility_client_verify;
use destiny1_network::local_server::{LocalBapServer, LocalServerConfig};
use std::net::SocketAddr;
use std::thread;
use std::time::Duration;

fn boot() -> (LocalBapServer, SocketAddr) {
    let mut server = LocalBapServer::new(LocalServerConfig {
        read_timeout: Some(Duration::from_secs(3)),
        write_timeout: Some(Duration::from_secs(3)),
        max_connections: 8,
        ..LocalServerConfig::loopback_ephemeral()
    });
    let addr = server.bind().unwrap();
    server.start_background().unwrap();
    thread::sleep(Duration::from_millis(40));
    (server, addr)
}

#[test]
fn compatibility_scenario_pass() {
    let (mut server, addr) = boot();
    let mut client = BapCompatibilityClient::new_synthetic();
    LocalCompatibilityScenario::run(&mut client, addr).unwrap();
    assert_eq!(client.state(), ClientProtocolState::Closed);
    server.shutdown();
}

#[test]
fn two_clients_independent() {
    let (mut server, addr) = boot();
    let mut a = BapCompatibilityClient::new_synthetic();
    let mut b = BapCompatibilityClient::new_synthetic();
    a.connect(addr).unwrap();
    b.connect(addr).unwrap();
    a.run_handshake().unwrap();
    assert_eq!(a.state(), ClientProtocolState::Active);
    assert_eq!(b.state(), ClientProtocolState::Connected);
    assert_eq!(b.client_to_server_counter(), 0);
    b.run_handshake().unwrap();
    assert_eq!(b.client_to_server_counter(), 1);
    a.send_nat_probe().unwrap();
    b.send_keepalive().unwrap();
    assert_eq!(a.state(), ClientProtocolState::Active);
    assert_eq!(b.state(), ClientProtocolState::Active);
    // Independent counters after interleaved ops
    assert!(a.client_to_server_counter() >= 2);
    assert!(b.server_to_client_counter() >= 1);
    a.close().unwrap();
    b.close().unwrap();
    server.shutdown();
}

#[test]
fn reconnect_fresh_state() {
    let (mut server, addr) = boot();
    {
        let mut c = BapCompatibilityClient::new_synthetic();
        c.connect(addr).unwrap();
        c.run_handshake().unwrap();
        c.close().unwrap();
        assert_eq!(c.state(), ClientProtocolState::Closed);
    }
    let mut c2 = BapCompatibilityClient::new_synthetic();
    assert_eq!(c2.state(), ClientProtocolState::Disconnected);
    c2.connect(addr).unwrap();
    assert_eq!(c2.state(), ClientProtocolState::Connected);
    assert_eq!(c2.client_to_server_counter(), 0);
    assert_eq!(c2.server_to_client_counter(), 0);
    c2.run_handshake().unwrap();
    c2.close().unwrap();
    server.shutdown();
}

#[test]
fn eof_clean() {
    let (mut server, addr) = boot();
    let mut c = BapCompatibilityClient::new_synthetic();
    c.connect(addr).unwrap();
    c.close().unwrap();
    assert_eq!(c.state(), ClientProtocolState::Closed);
    server.shutdown();
}

#[test]
fn verify_cli_path() {
    compatibility_client_verify::run_default().expect("COMPATIBILITY_CLIENT_VERIFY: VERIFIED");
}
