//! Unit tests for ExternalClientBoundary (M4.7).

use destiny1_network::bap_session::BapSession;
use destiny1_network::external_client_boundary::{
    assert_localhost_bind, ExternalClientConnection, ExternalClientListener,
    ExternalConnectionState, ExternalListenerConfig,
};
use destiny1_network::local_protocol::{PAYLOAD_1E, MSG_1E};
use destiny1_network::protocol_state::ProtocolState;
use std::net::SocketAddr;

#[test]
fn bind_localhost() {
    let l = ExternalClientListener::bind(ExternalListenerConfig::loopback_ephemeral()).unwrap();
    assert_eq!(l.addr().ip().to_string(), "127.0.0.1");
}

#[test]
fn reject_external_endpoint() {
    assert!(assert_localhost_bind(SocketAddr::from(([8, 8, 8, 8], 80))).is_err());
    let mut cfg = ExternalListenerConfig::default();
    cfg.host = "0.0.0.0".into();
    assert!(ExternalClientListener::bind(cfg).is_err());
}

#[test]
fn connection_lifecycle() {
    let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
    assert_eq!(c.connection_state(), ExternalConnectionState::Accepted);
    let frame = BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E);
    c.feed_bytes(&frame).unwrap();
    assert_eq!(c.connection_state(), ExternalConnectionState::ProtocolActive);
    assert_eq!(
        c.protocol_state(),
        ProtocolState::ServiceHandshakeComplete
    );
    c.close("test");
    assert_eq!(c.connection_state(), ExternalConnectionState::Closed);
}

#[test]
fn safe_event_trace() {
    let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
    let _ = c.feed_bytes(&BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E));
    let log = c.safe_event_log().join("\n");
    assert!(log.contains("ConnectionAccepted"));
    assert!(log.contains("FrameRecovered"));
    assert!(!log.contains("00010203"));
    assert!(!log.contains("SIM_1E"));
}

#[test]
fn single_frame() {
    let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
    assert_eq!(
        c.feed_bytes(&BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E))
            .unwrap(),
        1
    );
    assert!(!c.take_outbound().is_empty());
}

#[test]
fn fragmented_frame() {
    let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
    let frame = BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E);
    assert_eq!(c.feed_bytes(&frame[..3]).unwrap(), 0);
    assert_eq!(c.feed_bytes(&frame[3..]).unwrap(), 1);
}

#[test]
fn deterministic_trace() {
    let run = || {
        let mut c = ExternalClientConnection::new_synthetic(1).unwrap();
        let _ = c.feed_bytes(&BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E));
        c.safe_event_log()
    };
    assert_eq!(run(), run());
}
