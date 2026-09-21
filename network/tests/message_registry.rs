//! Message registry tests (M4.4).

use destiny1_network::message_registry::{full_registry, to_safe_export, validate_registry};
use destiny1_network::protocol_spec::EXPECTED_MESSAGE_IDS;
use std::collections::BTreeSet;

#[test]
fn all_28_ids_represented() {
    let reg = full_registry();
    assert_eq!(reg.len(), 28);
    assert_eq!(EXPECTED_MESSAGE_IDS.len(), 28);
    let ids: BTreeSet<_> = reg.iter().map(|e| e.id).collect();
    assert_eq!(ids.len(), 28);
}

#[test]
fn no_duplicate_ids() {
    validate_registry().unwrap();
    let reg = full_registry();
    let mut seen = BTreeSet::new();
    for e in &reg {
        assert!(seen.insert(e.id), "duplicate {}", e.id_hex);
    }
}

#[test]
fn direction_consistency() {
    for e in full_registry() {
        assert!(
            e.direction == "C2S" || e.direction == "S2C" || e.direction == "UNKNOWN",
            "{}",
            e.id_hex
        );
    }
}

#[test]
fn unknown_ids_preserved() {
    let ab = full_registry().into_iter().find(|e| e.id == 0xAB).unwrap();
    assert_eq!(ab.codec, "Unknown");
    assert_eq!(ab.status, "UNKNOWN");
}

#[test]
fn known_codecs_marked() {
    let e1a = full_registry().into_iter().find(|e| e.id == 0x1A).unwrap();
    assert_eq!(e1a.status, "CONFIRMED_STRUCTURE");
    let e1e = full_registry().into_iter().find(|e| e.id == 0x1E).unwrap();
    assert_eq!(e1e.status, "OPAQUE_KNOWN");
}

#[test]
fn safe_export_no_payloads() {
    let export = to_safe_export();
    let json = serde_json::to_string(&export).unwrap();
    assert!(!json.contains("payload_hex"));
    assert!(!json.contains("session_key"));
    assert_eq!(export.message_count, 28);
}
