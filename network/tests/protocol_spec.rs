//! M4.1 protocol specification unit tests.

use destiny1_network::bap_session::DecodedBapFrame;
use destiny1_network::crypto::NonceDirection;
use destiny1_network::message_inventory::{CaptureMessageInventory, MessageObservation};
use destiny1_network::protocol_spec::{
    build_protocol_spec, to_safe_export, validate_spec, EvidenceClass, EXPECTED_MESSAGE_IDS,
    SPEC_VERSION,
};
use destiny1_network::state_machine::STABLE_STARTUP_SEQUENCE;

fn obs(cap: &str, idx: u32, dir: NonceDirection, id: u16, ctx: u32) -> MessageObservation {
    MessageObservation::from_decoded(
        cap,
        idx,
        dir,
        &DecodedBapFrame::Clear {
            msg_id: id,
            context: ctx,
            payload: vec![0u8; 4],
        },
        None,
        Some(idx as u64),
    )
    .unwrap()
}

fn two_startup_captures() -> (CaptureMessageInventory, CaptureMessageInventory) {
    let dirs = [
        NonceDirection::ClientToServer,
        NonceDirection::ServerToClient,
        NonceDirection::ClientToServer,
        NonceDirection::ServerToClient,
        NonceDirection::ClientToServer,
        NonceDirection::ServerToClient,
        NonceDirection::ClientToServer,
        NonceDirection::ServerToClient,
    ];
    let build = |cap: &str, tail: u16| {
        let mut v = Vec::new();
        for (i, id) in STABLE_STARTUP_SEQUENCE.iter().enumerate() {
            v.push(obs(cap, i as u32, dirs[i], *id, 1));
        }
        // Ensure all expected IDs appear at least once across A+B for matrix coverage in tests
        // that only check schema — real runs use full captures.
        v.push(obs(cap, 8, NonceDirection::ClientToServer, tail, 1));
        CaptureMessageInventory::from_observations(cap, v)
    };
    (build("A", 0x0a), build("B", 0xab))
}

#[test]
fn protocol_spec_schema_and_version() {
    let (a, b) = two_startup_captures();
    let spec = build_protocol_spec(&a, &b);
    assert_eq!(spec.version, SPEC_VERSION);
    validate_spec(&spec).unwrap();
}

#[test]
fn all_expected_ids_when_present_in_inventory() {
    // Build inventories containing every expected ID.
    let mut oa = Vec::new();
    let mut ob = Vec::new();
    for (i, id) in EXPECTED_MESSAGE_IDS.iter().enumerate() {
        oa.push(obs(
            "A",
            i as u32,
            NonceDirection::ClientToServer,
            *id,
            1,
        ));
        ob.push(obs(
            "B",
            i as u32,
            NonceDirection::ServerToClient,
            *id,
            1,
        ));
    }
    // Prefix with startup so state machine is happy.
    let mut a_obs = Vec::new();
    let mut b_obs = Vec::new();
    let dirs = [
        NonceDirection::ClientToServer,
        NonceDirection::ServerToClient,
        NonceDirection::ClientToServer,
        NonceDirection::ServerToClient,
        NonceDirection::ClientToServer,
        NonceDirection::ServerToClient,
        NonceDirection::ClientToServer,
        NonceDirection::ServerToClient,
    ];
    for (i, id) in STABLE_STARTUP_SEQUENCE.iter().enumerate() {
        a_obs.push(obs("A", i as u32, dirs[i], *id, 1));
        b_obs.push(obs("B", i as u32, dirs[i], *id, 1));
    }
    for (j, o) in oa.into_iter().enumerate() {
        let mut o2 = o;
        o2.frame_index = (8 + j) as u32;
        a_obs.push(o2);
    }
    for (j, o) in ob.into_iter().enumerate() {
        let mut o2 = o;
        o2.frame_index = (8 + j) as u32;
        b_obs.push(o2);
    }
    let a = CaptureMessageInventory::from_observations("A", a_obs);
    let b = CaptureMessageInventory::from_observations("B", b_obs);
    let spec = build_protocol_spec(&a, &b);
    assert_eq!(spec.messages.len(), 28);
    validate_spec(&spec).unwrap();
}

#[test]
fn startup_sequence_represented() {
    let (a, b) = two_startup_captures();
    let spec = build_protocol_spec(&a, &b);
    assert_eq!(spec.startup_sequence.len(), 8);
    assert_eq!(spec.startup_sequence[0], "0x1E");
    assert_eq!(spec.startup_sequence[7], "0x12F");
}

#[test]
fn both_captures_represented() {
    let (a, b) = two_startup_captures();
    let spec = build_protocol_spec(&a, &b);
    assert_eq!(spec.captures, vec!["A".to_string(), "B".to_string()]);
}

#[test]
fn crypto_and_gcm_classification() {
    let (a, b) = two_startup_captures();
    let spec = build_protocol_spec(&a, &b);
    assert_eq!(
        spec.crypto.session_login_0x1a.classification,
        EvidenceClass::Confirmed
    );
    assert_eq!(spec.crypto.aes_gcm.classification, EvidenceClass::Confirmed);
    assert_eq!(
        spec.crypto.session_login_0x1a.nonce_key_layout_class,
        EvidenceClass::StructuralHypothesis
    );
}

#[test]
fn aad_remains_unknown_beyond_captures() {
    let (a, b) = two_startup_captures();
    let spec = build_protocol_spec(&a, &b);
    assert!(spec.crypto.aes_gcm.aad_general.contains("UNKNOWN"));
    assert!(!spec.crypto.aes_gcm.aad_general.to_lowercase().contains("always empty"));
}

#[test]
fn nonce_classification() {
    let (a, b) = two_startup_captures();
    let spec = build_protocol_spec(&a, &b);
    assert!(spec
        .crypto
        .nonce_model
        .classification
        .contains("CONFIRMED_FOR_VERIFIED_CAPTURES"));
    assert!(spec.crypto.nonce_model.not_universal.contains("UNIVERSAL"));
}

#[test]
fn external_references_separated() {
    let (a, b) = two_startup_captures();
    let spec = build_protocol_spec(&a, &b);
    assert!(spec.external_reference_note.contains("EXTERNAL_REFERENCE"));
    let m1a = spec.messages.iter().find(|m| m.message_id == "0x1A").unwrap();
    assert_eq!(m1a.external_reference, Some("session-login-response"));
}

#[test]
fn unknown_registry_and_readiness() {
    let (a, b) = two_startup_captures();
    let spec = build_protocol_spec(&a, &b);
    assert!(spec.unknowns.iter().any(|u| u.priority.as_str() == "HIGH"));
    assert!(spec
        .implementation_readiness
        .iter()
        .any(|r| r.component == "UDP" && r.readiness.as_str() == "BLOCKED"));
    assert!(spec
        .implementation_readiness
        .iter()
        .any(|r| r.component == "BAP framing" && r.readiness.as_str() == "READY_OFFLINE"));
}

#[test]
fn no_secrets_in_export() {
    let (a, b) = two_startup_captures();
    let spec = build_protocol_spec(&a, &b);
    let export = to_safe_export(&spec);
    let json = serde_json::to_string(&export).unwrap();
    assert!(!json.contains("session_key_hex"));
    assert!(!json.to_lowercase().contains("password"));
}

#[test]
fn deterministic_spec_generation() {
    let (a, b) = two_startup_captures();
    let s1 = serde_json::to_string(&to_safe_export(&build_protocol_spec(&a, &b))).unwrap();
    let s2 = serde_json::to_string(&to_safe_export(&build_protocol_spec(&a, &b))).unwrap();
    assert_eq!(s1, s2);
}

#[test]
fn framing_max_body_is_implementation_limit() {
    let (a, b) = two_startup_captures();
    let spec = build_protocol_spec(&a, &b);
    assert_eq!(spec.framing.max_body_len_class, "IMPLEMENTATION_LIMIT");
}
