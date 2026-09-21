//! Adapter tests use a synthetic JSONL that mirrors confirmed d1-re field names.
//! Values are invented — not a real capture sequence.

use destiny1_network::evidence_adapter::{adapt_jsonl_path, adapt_jsonl_str, adapt_line};
use destiny1_network::messages;
use destiny1_network::timeline::Timeline;
use std::path::PathBuf;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/external_schema_synthetic.jsonl")
}

#[test]
fn skips_bap_connection_and_failed_frames() {
    let records = adapt_jsonl_path(fixture()).expect("adapt fixture");
    // 8 usable frames; connection + decrypt_failed skipped
    assert_eq!(records.len(), 8);
}

#[test]
fn pipeline_external_to_timeline_classifies_known_ids() {
    let records = adapt_jsonl_path(fixture()).unwrap();
    let timeline = Timeline::from_evidence(&records);
    let ids: Vec<u16> = timeline
        .entries()
        .iter()
        .filter_map(|e| e.message_id)
        .collect();
    assert_eq!(
        ids,
        vec![0x1E, 0x1F, 0x19, 0x1A, 0x79, 0x7A, 0xFA, 0xFB]
    );
    for id in ids {
        assert!(
            messages::classify(id).is_known(),
            "0x{id:x} should be known"
        );
    }
    let lines = timeline.format_cli_lines();
    assert!(lines[0].contains("0x001e"));
    assert!(lines[0].contains("destiny-service-handshake-request"));
    assert!(lines[4].contains("0x0079"));
    assert!(lines[6].contains("0x00fa"));
    // Timestamps from frame_ts * 1000
    assert!(lines[0].starts_with("[001000ms]"));
    assert!(lines[1].starts_with("[001031ms]"));
}

#[test]
fn adapt_line_connection_is_none() {
    let line = r#"{"kind":"bap_connection","client":"a","server":"b"}"#;
    assert!(adapt_line(line).unwrap().is_none());
}

#[test]
fn timestamp_fallback_uses_frame_index() {
    let line = r#"{"kind":"bap_frame","direction":"client_to_server","frame_index":7,"frame_kind":2,"id":25,"context":0,"payload_hex":""}"#;
    let rec = adapt_line(line).unwrap().unwrap();
    assert_eq!(rec.timestamp_ms, 7);
    assert_eq!(rec.frame.message_id(), Some(0x19));
}

#[test]
fn invalid_json_errors() {
    let err = adapt_jsonl_str("{nope").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("JSON") || msg.contains("line"));
}
