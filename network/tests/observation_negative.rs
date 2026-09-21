//! Negative / sensitive-data tests for M4.8.

use destiny1_network::observation::{is_sensitive_key, ObservationError};
use destiny1_network::observation_trace::ObservationTrace;
use destiny1_network::protocol_observation::{classify_frame, ObservationClass};
use destiny1_network::observation::ObservedFrame;

#[test]
fn reject_session_key_field() {
    let json = r#"{
      "trace_version":"1",
      "frames":[{
        "connection_id":1,"frame_index":0,"direction":"C2S","kind":2,
        "body_len":1,"message_id":"0x1E","session_key":"00"
      }]
    }"#;
    let err = ObservationTrace::from_json_str(json).unwrap_err();
    assert!(matches!(err, ObservationError::SensitiveField(_)));
}

#[test]
fn reject_token_field() {
    let json = r#"{"events":[{"token":"x","connection_id":1,"frame_index":0,"direction":"C2S","kind":2,"body_len":1}]}"#;
    assert!(ObservationTrace::from_json_str(json).is_err());
}

#[test]
fn reject_payload_hex() {
    let json = r#"{"frames":[{"connection_id":1,"frame_index":0,"direction":"C2S","kind":2,"body_len":1,"payload_hex":"dead"}]}"#;
    assert!(ObservationTrace::from_json_str(json).is_err());
}

#[test]
fn sensitive_key_helper() {
    assert!(is_sensitive_key("session_key"));
    assert!(is_sensitive_key("PASSWORD"));
    assert!(!is_sensitive_key("frame_index"));
}

#[test]
fn unknown_preserved() {
    let f = ObservedFrame {
        connection_id: 1,
        frame_index: 0,
        direction: "C2S".into(),
        kind: 2,
        body_len: 2,
        message_id: Some(0xEE),
        protocol_state: None,
        relative_time_ms: None,
        fingerprint: None,
    };
    assert_eq!(classify_frame(&f).class, ObservationClass::Unknown);
}

#[test]
fn no_auto_promote_hypothesis() {
    // Registry ID that is not startup/keepalive stays Observed, not Confirmed.
    let f = ObservedFrame {
        connection_id: 1,
        frame_index: 0,
        direction: "C2S".into(),
        kind: 2,
        body_len: 2,
        message_id: Some(0x0A),
        protocol_state: None,
        relative_time_ms: None,
        fingerprint: None,
    };
    let c = classify_frame(&f).class;
    assert_ne!(c, ObservationClass::Confirmed);
}
