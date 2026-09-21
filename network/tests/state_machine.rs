//! M3.4 observational state machine unit tests.

use destiny1_network::bap_session::DecodedBapFrame;
use destiny1_network::crypto::NonceDirection;
use destiny1_network::message_inventory::{CaptureMessageInventory, MessageObservation};
use destiny1_network::state_machine::{
    build_state_machine, replay_state_trace, startup_prefix_len, StateClassification,
    STABLE_STARTUP_SEQUENCE, STATE_BRANCH_A, STATE_BRANCH_B, STATE_POST_STARTUP,
    STATE_REPEATING_CLUSTER_01, STATE_START, STATE_STARTUP_SEQUENCE,
};

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
        Some(idx as u64),
    )
    .unwrap()
}

fn inv(capture: &str, observations: Vec<MessageObservation>) -> CaptureMessageInventory {
    CaptureMessageInventory::from_observations(capture, observations)
}

fn startup_obs(cap: &str) -> Vec<MessageObservation> {
    let seq = STABLE_STARTUP_SEQUENCE;
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
    seq.iter()
        .enumerate()
        .map(|(i, id)| obs(cap, i as u32, dirs[i], *id, 1, b"x"))
        .collect()
}

#[test]
fn startup_sequence_detection() {
    let ids: Vec<u16> = STABLE_STARTUP_SEQUENCE.to_vec();
    assert_eq!(startup_prefix_len(&ids), 8);
    assert_eq!(startup_prefix_len(&[0x1e, 0x1f, 0x99]), 2);
}

#[test]
fn stable_state_and_transition() {
    let a = inv("A", startup_obs("A"));
    let b = inv("B", startup_obs("B"));
    let m = build_state_machine(&a, &b);
    assert!(m.startup.capture_a_observed && m.startup.capture_b_observed);
    assert_eq!(m.startup.classification, StateClassification::Observed);
    assert!(m.graph.nodes.iter().any(|n| n == STATE_STARTUP_SEQUENCE));
    assert!(m.graph.edges.iter().any(|e| {
        e.from_state == STATE_START
            && e.to_state == STATE_STARTUP_SEQUENCE
            && e.classification == StateClassification::StableCrossCapture
    }));
}

#[test]
fn capture_specific_branch() {
    let mut oa = startup_obs("A");
    let mut ob = startup_obs("B");
    oa.push(obs(
        "A",
        8,
        NonceDirection::ClientToServer,
        0x0a,
        1,
        b"a",
    ));
    ob.push(obs(
        "B",
        8,
        NonceDirection::ClientToServer,
        0xab,
        1,
        b"b",
    ));
    let m = build_state_machine(&inv("A", oa), &inv("B", ob));
    assert_eq!(m.branches.divergence_index, Some(8));
    assert_eq!(m.branches.message_a, Some(0x0a));
    assert_eq!(m.branches.message_b, Some(0xab));
    let ta = &m.traces["A"];
    assert_eq!(ta[8].to_state, STATE_BRANCH_A);
    let tb = &m.traces["B"];
    assert_eq!(tb[8].to_state, STATE_BRANCH_B);
}

#[test]
fn context_transition_preserved() {
    let mut oa = startup_obs("A");
    let mut ob = startup_obs("B");
    oa.push(obs("A", 8, NonceDirection::ClientToServer, 0x0c, 1, b"a"));
    oa.push(obs("A", 9, NonceDirection::ServerToClient, 0x0d, 2, b"b"));
    ob.push(obs("B", 8, NonceDirection::ClientToServer, 0x0c, 1, b"a"));
    ob.push(obs("B", 9, NonceDirection::ServerToClient, 0x0d, 2, b"b"));
    let m = build_state_machine(&inv("A", oa), &inv("B", ob));
    assert!(m
        .context_transitions
        .iter()
        .any(|t| t.context_before == 1 && t.context_after == 2));
}

#[test]
fn direction_transition_in_trace() {
    let a = inv("A", startup_obs("A"));
    let b = inv("B", startup_obs("B"));
    let m = build_state_machine(&a, &b);
    let t = &m.traces["A"];
    assert_eq!(t[0].direction, "client_to_server");
    assert_eq!(t[1].direction, "server_to_client");
}

#[test]
fn repeating_cluster() {
    let mut oa = startup_obs("A");
    let mut ob = startup_obs("B");
    for (i, id) in [0xfau16, 0xfb, 0xfa, 0xfb, 0xfa, 0xfb].iter().enumerate() {
        let dir = if *id == 0xfa {
            NonceDirection::ClientToServer
        } else {
            NonceDirection::ServerToClient
        };
        oa.push(obs("A", (8 + i) as u32, dir, *id, 0, &[]));
        ob.push(obs("B", (8 + i) as u32, dir, *id, 0, &[]));
    }
    let m = build_state_machine(&inv("A", oa), &inv("B", ob));
    assert!(m.repeating_cluster.repeating);
    assert_eq!(m.repeating_cluster.state_id, STATE_REPEATING_CLUSTER_01);
    assert!(m.traces["A"]
        .iter()
        .any(|e| e.to_state == STATE_REPEATING_CLUSTER_01));
    // External keepalive name separated.
    assert_eq!(
        m.repeating_cluster.external_reference,
        Some("keepalive-request")
    );
}

#[test]
fn request_response_candidate_preservation() {
    let mut oa = startup_obs("A");
    let mut ob = startup_obs("B");
    // Extra 0x79→0x7A already in startup; add FA/FB which are strong RR candidates.
    for (i, id) in [0xfau16, 0xfb, 0xfa, 0xfb].iter().enumerate() {
        let dir = if *id == 0xfa {
            NonceDirection::ClientToServer
        } else {
            NonceDirection::ServerToClient
        };
        oa.push(obs("A", (8 + i) as u32, dir, *id, 0, &[]));
        ob.push(obs("B", (8 + i) as u32, dir, *id, 0, &[]));
    }
    let m = build_state_machine(&inv("A", oa), &inv("B", ob));
    let rr = m
        .request_response_candidates
        .iter()
        .find(|r| r.request_id == 0xfa && r.response_id == 0xfb)
        .expect("FA→FB candidate");
    assert!(rr.request_response_candidate);
    assert_eq!(rr.semantic_status, StateClassification::Unknown);
}

#[test]
fn external_reference_separation() {
    let m = build_state_machine(&inv("A", startup_obs("A")), &inv("B", startup_obs("B")));
    assert!(m
        .external_semantics
        .iter()
        .any(|e| e.message_id == "0x19" && e.external_name.contains("session-login")));
    // Observed startup is not named LOGIN_STATE.
    assert!(!m.graph.nodes.iter().any(|n| n.contains("LOGIN")));
    assert!(!m.graph.nodes.iter().any(|n| n.contains("AUTH")));
}

#[test]
fn deterministic_replay() {
    let obs = startup_obs("A");
    let refs: Vec<&MessageObservation> = obs.iter().collect();
    let t1 = replay_state_trace(&refs, None);
    let t2 = replay_state_trace(&refs, None);
    assert_eq!(t1, t2);
    assert_eq!(t1[0].from_state, STATE_START);
    assert_eq!(t1[0].to_state, STATE_STARTUP_SEQUENCE);
    assert_eq!(t1[7].to_state, STATE_STARTUP_SEQUENCE);
}

#[test]
fn cross_capture_validation() {
    let m = build_state_machine(&inv("A", startup_obs("A")), &inv("B", startup_obs("B")));
    assert!(m
        .graph
        .edges
        .iter()
        .any(|e| e.classification == StateClassification::StableCrossCapture));
}

#[test]
fn divergence_detection() {
    let mut oa = startup_obs("A");
    let mut ob = startup_obs("B");
    oa.push(obs("A", 8, NonceDirection::ClientToServer, 0x10, 1, b"x"));
    ob.push(obs("B", 8, NonceDirection::ClientToServer, 0x11, 1, b"y"));
    let m = build_state_machine(&inv("A", oa), &inv("B", ob));
    assert_eq!(m.branches.classification, StateClassification::Observed);
    assert_eq!(m.branches.divergence_index, Some(8));
}

#[test]
fn unknown_semantic_preservation() {
    let m = build_state_machine(&inv("A", startup_obs("A")), &inv("B", startup_obs("B")));
    for r in &m.request_response_candidates {
        assert_eq!(r.semantic_status, StateClassification::Unknown);
    }
    assert!(!m.unknowns.is_empty());
}

#[test]
fn no_semantic_promotion() {
    let m = build_state_machine(&inv("A", startup_obs("A")), &inv("B", startup_obs("B")));
    assert_eq!(m.startup.structural_label, "STABLE_STARTUP_SEQUENCE");
    for n in &m.graph.nodes {
        assert!(!n.contains("AUTHENTICATED"));
        assert!(!n.contains("KEEPALIVE_STATE"));
        assert!(!n.contains("GAMEPLAY"));
    }
    for row in &m.semantic_matrix {
        if row.external_reference.is_some() {
            assert_eq!(
                row.semantic_confidence,
                StateClassification::ExternalReference
            );
        }
    }
}

#[test]
fn post_startup_after_sequence() {
    let mut o = startup_obs("A");
    o.push(obs("A", 8, NonceDirection::ClientToServer, 0x0a, 1, b"z"));
    let refs: Vec<&MessageObservation> = o.iter().collect();
    let t = replay_state_trace(&refs, None);
    assert_eq!(t[8].to_state, STATE_POST_STARTUP);
}
