//! M3.1 message inventory unit tests (synthetic + optional real fixtures).

use destiny1_network::bap_session::DecodedBapFrame;
use destiny1_network::crypto::NonceDirection;
use destiny1_network::message_inventory::{
    payload_byte_diff, payload_fingerprint, CaptureMessageInventory, CrossCaptureMessageComparison,
    EvidenceLabel, MessageInventory, MessageObservation, Presence,
};
use destiny1_network::message_inventory_verify;
use std::path::PathBuf;

fn obs(
    capture: &str,
    idx: u32,
    dir: NonceDirection,
    id: u16,
    context: u32,
    payload: &[u8],
) -> MessageObservation {
    MessageObservation::from_decoded(
        capture,
        idx,
        dir,
        &DecodedBapFrame::Clear {
            msg_id: id,
            context,
            payload: payload.to_vec(),
        },
        None,
        None,
    )
    .unwrap()
}

#[test]
fn builds_message_observation() {
    let o = obs(
        "cap",
        0,
        NonceDirection::ClientToServer,
        0x1e,
        1,
        b"abc",
    );
    assert_eq!(o.message_id, 0x1e);
    assert_eq!(o.context, 1);
    assert_eq!(o.payload_len, 3);
    assert_eq!(o.frame_kind, 2);
    assert_eq!(o.evidence, EvidenceLabel::Observed);
}

#[test]
fn groups_by_message_id() {
    let mut inv = MessageInventory::new();
    inv.add(obs("a", 0, NonceDirection::ClientToServer, 0xfa, 1, b""));
    inv.add(obs("a", 1, NonceDirection::ClientToServer, 0xfa, 1, b""));
    inv.add(obs("a", 2, NonceDirection::ServerToClient, 0xfb, 1, b""));
    assert_eq!(inv.groups[&0xfa].total_observations, 2);
    assert_eq!(inv.groups[&0xfb].total_observations, 1);
}

#[test]
fn counts_by_direction() {
    let mut inv = MessageInventory::new();
    inv.add(obs("a", 0, NonceDirection::ClientToServer, 0x12e, 0, b"x"));
    inv.add(obs("a", 1, NonceDirection::ClientToServer, 0x12e, 0, b"y"));
    inv.add(obs("a", 2, NonceDirection::ServerToClient, 0x12e, 0, b"z"));
    let g = &inv.groups[&0x12e];
    assert_eq!(g.directions["client_to_server"], 2);
    assert_eq!(g.directions["server_to_client"], 1);
}

#[test]
fn counts_by_context() {
    let mut inv = MessageInventory::new();
    inv.add(obs("a", 0, NonceDirection::ClientToServer, 1, 2, b""));
    inv.add(obs("a", 1, NonceDirection::ClientToServer, 1, 2, b""));
    inv.add(obs("a", 2, NonceDirection::ClientToServer, 1, 9, b""));
    assert_eq!(inv.groups[&1].contexts[&2], 2);
    assert_eq!(inv.groups[&1].contexts[&9], 1);
}

#[test]
fn counts_payload_lengths() {
    let mut inv = MessageInventory::new();
    inv.add(obs("a", 0, NonceDirection::ClientToServer, 1, 0, b"aa"));
    inv.add(obs("a", 1, NonceDirection::ClientToServer, 1, 0, b"bbbb"));
    inv.add(obs("a", 2, NonceDirection::ClientToServer, 1, 0, b"cc"));
    assert_eq!(inv.groups[&1].payload_lengths[&2], 2);
    assert_eq!(inv.groups[&1].payload_lengths[&4], 1);
}

#[test]
fn fingerprint_deterministic() {
    let h1 = payload_fingerprint(b"hello");
    let h2 = payload_fingerprint(b"hello");
    let h3 = payload_fingerprint(b"world");
    assert_eq!(h1, h2);
    assert_ne!(h1, h3);
    assert_eq!(h1.len(), 64);
}

#[test]
fn byte_diff_reports_prefix_and_offset() {
    let d = payload_byte_diff(b"AAAAAAAA", b"AAAABBBB");
    assert_eq!(d.length_a, 8);
    assert_eq!(d.length_b, 8);
    assert_eq!(d.same_bytes_prefix, 4);
    assert_eq!(d.first_difference_offset, Some(4));
    assert_eq!(d.different_byte_count, 4);
}

#[test]
fn cross_capture_presence() {
    let a = CaptureMessageInventory::from_observations(
        "A",
        vec![
            obs("A", 0, NonceDirection::ClientToServer, 0x1e, 1, b""),
            obs("A", 1, NonceDirection::ClientToServer, 0xaa, 0, b"x"),
        ],
    );
    let b = CaptureMessageInventory::from_observations(
        "B",
        vec![
            obs("B", 0, NonceDirection::ClientToServer, 0x1e, 1, b""),
            obs("B", 1, NonceDirection::ServerToClient, 0xbb, 0, b"y"),
        ],
    );
    let cmp = CrossCaptureMessageComparison::compare(&a, &b);
    assert_eq!(cmp.both_ids(), vec![0x1e]);
    assert_eq!(cmp.a_only_ids(), vec![0xaa]);
    assert_eq!(cmp.b_only_ids(), vec![0xbb]);
}

#[test]
fn detects_stable_and_divergent_direction_length() {
    let a = CaptureMessageInventory::from_observations(
        "A",
        vec![
            obs("A", 0, NonceDirection::ClientToServer, 0xfa, 1, b""),
            obs("A", 1, NonceDirection::ClientToServer, 0x10, 1, b"aaaa"),
        ],
    );
    let b = CaptureMessageInventory::from_observations(
        "B",
        vec![
            obs("B", 0, NonceDirection::ClientToServer, 0xfa, 1, b""),
            obs("B", 1, NonceDirection::ServerToClient, 0x10, 1, b"aa"),
        ],
    );
    let cmp = CrossCaptureMessageComparison::compare(&a, &b);
    let fa = cmp.rows.iter().find(|r| r.message_id == 0xfa).unwrap();
    assert_eq!(fa.direction_status, EvidenceLabel::CrossCaptureStable);
    assert_eq!(fa.length_status, EvidenceLabel::CrossCaptureStable);
    let x = cmp.rows.iter().find(|r| r.message_id == 0x10).unwrap();
    assert_eq!(x.direction_status, EvidenceLabel::Divergent);
    assert_eq!(x.length_status, EvidenceLabel::Divergent);
    assert_eq!(x.presence, Presence::Both);
}

#[test]
fn startup_sequence_comparison() {
    let a = CaptureMessageInventory::from_observations(
        "A",
        vec![
            obs("A", 0, NonceDirection::ClientToServer, 0x1e, 1, b""),
            obs("A", 1, NonceDirection::ServerToClient, 0x1f, 1, b""),
        ],
    );
    let b_same = CaptureMessageInventory::from_observations(
        "B",
        vec![
            obs("B", 0, NonceDirection::ClientToServer, 0x1e, 1, b""),
            obs("B", 1, NonceDirection::ServerToClient, 0x1f, 1, b""),
        ],
    );
    let cmp = CrossCaptureMessageComparison::compare(&a, &b_same);
    assert_eq!(cmp.startup_status, EvidenceLabel::CrossCaptureStable);

    let b_diff = CaptureMessageInventory::from_observations(
        "B",
        vec![
            obs("B", 0, NonceDirection::ClientToServer, 0x19, 1, b""),
            obs("B", 1, NonceDirection::ServerToClient, 0x1a, 1, b""),
        ],
    );
    let cmp2 = CrossCaptureMessageComparison::compare(&a, &b_diff);
    assert_eq!(cmp2.startup_status, EvidenceLabel::Divergent);
}

#[test]
fn real_manifest_inventory_when_evidence_present() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/multi_capture/manifest.json");
    let a = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../evidence/local/bap_session_verify.json");
    let b = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../evidence/local/bap_session_verify_20260608-231100.json");
    if !a.exists() || !b.exists() {
        return;
    }
    let report = message_inventory_verify::run_from_manifest(&path).unwrap();
    assert_eq!(report.captures.len(), 2);
    assert!(report.comparison.both_ids().len() >= 10);
    assert_eq!(
        report.comparison.startup_status,
        EvidenceLabel::CrossCaptureStable
    );
    // Safe export must not embed hex payloads that look like secrets blobs.
    let json = serde_json::to_string(&report.safe_export).unwrap();
    assert!(!json.contains("session_key"));
    assert!(!json.contains("payload_hex"));
}
