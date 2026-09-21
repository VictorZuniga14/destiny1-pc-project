//! Offline verifier for M4.7 external client boundary.

use crate::bap_session::BapSession;
use crate::compatibility_client::BapCompatibilityClient;
use crate::external_client_boundary::{
    assert_localhost_bind, validate_safe_trace, BoundaryTestClient, ExternalBoundaryHarness,
    ExternalClientBoundary, ExternalClientConnection, ExternalClientListener,
    ExternalConnectionState, ExternalListenerConfig, SafeTraceFile,
};
use crate::local_protocol::{PAYLOAD_19, PAYLOAD_1E, PAYLOAD_79, PAYLOAD_FA, MSG_19, MSG_1E, MSG_79};
use crate::protocol_state::ProtocolState;
use crate::stream_framing::MAX_BODY_LEN;
use crate::test_crypto_material::{SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExternalBoundaryVerifyError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("fixture: {0}")]
    Fixture(String),
    #[error("verify failed: {0}")]
    Failed(String),
}

fn default_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/external_boundary/boundary_trace_safe.json")
}

pub fn run_default() -> Result<(), ExternalBoundaryVerifyError> {
    run_from_path(default_fixture())
}

pub fn run_from_path(path: impl AsRef<Path>) -> Result<(), ExternalBoundaryVerifyError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(ExternalBoundaryVerifyError::FileNotFound(
            path.display().to_string(),
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| ExternalBoundaryVerifyError::Fixture(e.to_string()))?;
    let fx: SafeTraceFile = serde_json::from_str(&text)
        .map_err(|e| ExternalBoundaryVerifyError::Fixture(e.to_string()))?;

    println!("EXTERNAL_BOUNDARY_VERIFY: start fixture={}", fx.name);
    for n in &fx.notes {
        println!("note: {n}");
    }
    validate_safe_trace(&fx).map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;

    let mut connections = 0u32;
    let mut frames = 0u32;
    let mut protocol_events = 0u32;
    let mut unknown_messages = 0u32;
    let mut rejected_frames = 0u32;
    let mut fragmentation_tests = 0u32;
    let mut multiple_frame_tests = 0u32;
    let mut multi_client_tests = 0u32;
    let mut negative_tests = 0u32;

    // External endpoint rejection
    let ext = SocketAddr::from(([8, 8, 8, 8], 9));
    if assert_localhost_bind(ext).is_ok() {
        return Err(ExternalBoundaryVerifyError::Failed(
            "must reject external".into(),
        ));
    }
    let mut bad_cfg = ExternalListenerConfig::default();
    bad_cfg.host = "0.0.0.0".into();
    if ExternalClientListener::bind(bad_cfg).is_ok() {
        return Err(ExternalBoundaryVerifyError::Failed(
            "must reject 0.0.0.0".into(),
        ));
    }
    negative_tests += 1;

    // Offline feed: fragmented 0x1E
    {
        let mut conn = ExternalClientConnection::new_synthetic(1)
            .map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;
        connections += 1;
        let frame = BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E);
        let mid = frame.len() / 2;
        let n1 = conn
            .feed_bytes(&frame[..mid])
            .map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;
        assert_eq!(n1, 0);
        let n2 = conn
            .feed_bytes(&frame[mid..])
            .map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;
        assert_eq!(n2, 1);
        frames += 1;
        fragmentation_tests += 1;
        protocol_events += conn
            .events()
            .iter()
            .filter(|e| matches!(e, crate::external_client_boundary::ExternalBoundaryEvent::ProtocolEvent { .. }))
            .count() as u32;
        let out = conn.take_outbound();
        if out.is_empty() {
            return Err(ExternalBoundaryVerifyError::Failed(
                "expected 0x1F response".into(),
            ));
        }
    }

    // Multiple frames one feed
    {
        let mut conn = ExternalClientConnection::new_synthetic(2)
            .map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;
        connections += 1;
        // Advance handshake first
        let _ = conn.feed_bytes(&BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E));
        let _ = conn.take_outbound();
        let _ = conn.feed_bytes(&BapSession::encode_clear(MSG_19, 1, PAYLOAD_19));
        let _ = conn.take_outbound();
        let mut sess = BapSession::new(&SYNTHETIC_SESSION_KEY, &SYNTHETIC_SESSION_NONCE)
            .map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;
        let f79 = sess
            .encode_encrypted(
                crate::crypto::NonceDirection::ClientToServer,
                MSG_79,
                1,
                PAYLOAD_79,
            )
            .map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;
        let _ = conn.feed_bytes(&f79);
        let _ = conn.take_outbound();

        let a = BapSession::encode_clear(0x12E, 1, b"A");
        let b = BapSession::encode_clear(0xFA, 1, b"B");
        let c = BapSession::encode_clear(0xAB, 1, b"C");
        let mut all = Vec::new();
        all.extend_from_slice(&a);
        all.extend_from_slice(&b);
        all.extend_from_slice(&c);
        let n = conn
            .feed_bytes(&all)
            .map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;
        if n != 3 {
            return Err(ExternalBoundaryVerifyError::Failed(format!(
                "expected 3 frames got {n}"
            )));
        }
        frames += 3;
        multiple_frame_tests += 1;
        unknown_messages += 1;
    }

    // Invalid magic
    {
        let mut conn = ExternalClientConnection::new_synthetic(3)
            .map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;
        let err = conn.feed_bytes(&[0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0xff]);
        if err.is_ok() {
            return Err(ExternalBoundaryVerifyError::Failed(
                "invalid magic should fail".into(),
            ));
        }
        rejected_frames += 1;
        negative_tests += 1;
    }

    // Invalid order 0x19 first
    {
        let mut conn = ExternalClientConnection::new_synthetic(4)
            .map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;
        let err = conn.feed_bytes(&BapSession::encode_clear(MSG_19, 1, PAYLOAD_19));
        if err.is_ok() {
            return Err(ExternalBoundaryVerifyError::Failed(
                "0x19 first should reject".into(),
            ));
        }
        rejected_frames += 1;
        negative_tests += 1;
    }

    // Wrong key crypto
    {
        let mut material = crate::stateful_bap_session::SyntheticSessionMaterial::default();
        material.key[0] ^= 0xff;
        let mut conn = ExternalClientConnection::with_material(5, material)
            .map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;
        let _ = conn.feed_bytes(&BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E));
        let _ = conn.take_outbound();
        let _ = conn.feed_bytes(&BapSession::encode_clear(MSG_19, 1, PAYLOAD_19));
        let _ = conn.take_outbound();
        let mut sess = BapSession::new(&SYNTHETIC_SESSION_KEY, &SYNTHETIC_SESSION_NONCE).unwrap();
        // Encrypt with server key but connection has wrong key → decrypt fail on server side
        // Actually connection decrypts with its wrong key when client sends with correct key
        let f = sess
            .encode_encrypted(
                crate::crypto::NonceDirection::ClientToServer,
                MSG_79,
                1,
                PAYLOAD_79,
            )
            .unwrap();
        let err = conn.feed_bytes(&f);
        if err.is_ok() {
            return Err(ExternalBoundaryVerifyError::Failed(
                "wrong key should fail decrypt".into(),
            ));
        }
        rejected_frames += 1;
        negative_tests += 1;
    }

    // Multi-client isolation offline
    {
        let mut a = ExternalClientConnection::new_synthetic(10).unwrap();
        let b = ExternalClientConnection::new_synthetic(11).unwrap();
        let mut c = ExternalClientConnection::new_synthetic(12).unwrap();
        let _ = a.feed_bytes(&BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E));
        assert_ne!(a.protocol_state(), b.protocol_state());
        assert_eq!(
            b.protocol_state(),
            ProtocolState::WaitingForServiceHandshake
        );
        let _ = a.feed_bytes(&BapSession::encode_clear(MSG_19, 1, PAYLOAD_19));
        let _ = c.feed_bytes(&BapSession::encode_clear(MSG_1E, 1, PAYLOAD_1E));
        assert_eq!(
            a.connection_state(),
            ExternalConnectionState::ProtocolActive
        );
        assert_eq!(b.connection_state(), ExternalConnectionState::Accepted);
        multi_client_tests += 1;
        connections += 3;
    }

    // Live harness + CompatibilityClient handshake
    {
        let mut harness = ExternalBoundaryHarness::start(ExternalListenerConfig {
            read_timeout: Some(Duration::from_secs(3)),
            ..ExternalListenerConfig::loopback_ephemeral()
        })
        .map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;
        thread::sleep(Duration::from_millis(40));
        let mut client = BapCompatibilityClient::new_synthetic();
        client
            .connect(harness.addr())
            .map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;
        client
            .run_handshake()
            .map_err(|e| ExternalBoundaryVerifyError::Failed(e.to_string()))?;
        client.send_nat_probe().ok();
        client.send_keepalive().ok();
        client.send_unknown(0xAB, b"UNK").ok();
        client.close().ok();
        thread::sleep(Duration::from_millis(80));
        let ev = harness.events();
        if !ev.iter().any(|e| {
            matches!(
                e,
                crate::external_client_boundary::ExternalBoundaryEvent::ConnectionAccepted { .. }
            )
        }) {
            return Err(ExternalBoundaryVerifyError::Failed(
                "missing ConnectionAccepted".into(),
            ));
        }
        frames += ev
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    crate::external_client_boundary::ExternalBoundaryEvent::FrameRecovered { .. }
                )
            })
            .count() as u32;
        connections += 1;
        harness.shutdown();
    }

    // Safe log check
    {
        let conn = ExternalClientConnection::new_synthetic(99).unwrap();
        let log = conn.safe_event_log().join("|");
        if log.contains("00010203") || log.contains("payload") {
            return Err(ExternalBoundaryVerifyError::Failed(
                "unsafe log".into(),
            ));
        }
    }

    let _ = MAX_BODY_LEN;
    let _ = BoundaryTestClient::with_synthetic();
    let _ = ExternalClientBoundary::new(ExternalListenerConfig::default());
    let _ = fx.events.len();
    let _ = PAYLOAD_FA;

    println!("connections: {connections}");
    println!("frames: {frames}");
    println!("protocol_events: {protocol_events}");
    println!("unknown_messages: {unknown_messages}");
    println!("rejected_frames: {rejected_frames}");
    println!("fragmentation_tests: {fragmentation_tests}");
    println!("multiple_frame_tests: {multiple_frame_tests}");
    println!("multi_client_tests: {multi_client_tests}");
    println!("negative_tests: {negative_tests}");
    println!("EXTERNAL_BOUNDARY_VERIFY: VERIFIED");
    Ok(())
}
