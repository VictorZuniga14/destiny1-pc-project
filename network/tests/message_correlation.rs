//! M3.3 message correlation unit tests (synthetic observations).

use destiny1_network::bap_session::DecodedBapFrame;
use destiny1_network::crypto::NonceDirection;
use destiny1_network::message_correlation::{
    align_sequences, analyze_two_captures, build_sequence, compute_sequence_divergence,
    cross_message_value_correlations, ngrams_for_observations, timing_stats, CorrelationLabel,
    EdgeClass, MessageCorrelationObservation, SequenceStability,
};
use destiny1_network::message_inventory::{CaptureMessageInventory, MessageObservation};

fn obs(
    capture: &str,
    idx: u32,
    dir: NonceDirection,
    id: u16,
    context: u32,
    payload: &[u8],
    order: u64,
) -> MessageObservation {
    let mut o = MessageObservation::from_decoded(
        capture,
        idx,
        dir,
        &DecodedBapFrame::Clear {
            msg_id: id,
            context,
            payload: payload.to_vec(),
        },
        None,
        Some(order),
    )
    .unwrap();
    o.frame_order = Some(order);
    o
}

fn inv(capture: &str, observations: Vec<MessageObservation>) -> CaptureMessageInventory {
    CaptureMessageInventory::from_observations(capture, observations)
}

#[test]
fn ngram_generation() {
    let a = inv(
        "A",
        vec![
            obs("A", 0, NonceDirection::ClientToServer, 0x1e, 1, b"a", 10),
            obs("A", 1, NonceDirection::ServerToClient, 0x1f, 1, b"b", 11),
            obs("A", 2, NonceDirection::ClientToServer, 0x19, 1, b"c", 12),
        ],
    );
    let seq = build_sequence(&a);
    let grams = ngrams_for_observations(&seq.observations, 2);
    assert_eq!(grams.len(), 2);
    assert_eq!(grams[0].0, vec![0x1e, 0x1f]);
    assert_eq!(grams[1].0, vec![0x1f, 0x19]);
}

#[test]
fn repeated_sequence() {
    let a = inv(
        "A",
        vec![
            obs("A", 0, NonceDirection::ClientToServer, 0xfa, 0, &[], 1),
            obs("A", 1, NonceDirection::ServerToClient, 0xfb, 0, &[], 2),
            obs("A", 2, NonceDirection::ClientToServer, 0xfa, 0, &[], 3),
            obs("A", 3, NonceDirection::ServerToClient, 0xfb, 0, &[], 4),
        ],
    );
    let b = inv(
        "B",
        vec![
            obs("B", 0, NonceDirection::ClientToServer, 0xfa, 0, &[], 1),
            obs("B", 1, NonceDirection::ServerToClient, 0xfb, 0, &[], 2),
        ],
    );
    let r = analyze_two_captures(&a, &b);
    let pair = r
        .stable_sequences
        .iter()
        .find(|s| s.sequence == vec![0xfa, 0xfb])
        .expect("FA→FB stable");
    assert!(pair.occurrences_a >= 2);
    assert!(pair.occurrences_b >= 1);
}

#[test]
fn cross_capture_stable_sequence() {
    let startup = |cap: &str| {
        inv(
            cap,
            vec![
                obs(cap, 0, NonceDirection::ClientToServer, 0x1e, 1, b"x", 1),
                obs(cap, 1, NonceDirection::ServerToClient, 0x1f, 1, b"y", 2),
                obs(cap, 2, NonceDirection::ClientToServer, 0x19, 1, b"z", 3),
                obs(cap, 3, NonceDirection::ServerToClient, 0x1a, 1, b"w", 4),
            ],
        )
    };
    let r = analyze_two_captures(&startup("A"), &startup("B"));
    let g = r
        .ngrams
        .iter()
        .find(|g| g.sequence == vec![0x1e, 0x1f, 0x19, 0x1a])
        .expect("4-gram");
    assert_eq!(g.classification, SequenceStability::StableSequence);
    assert_eq!(g.captures_seen.len(), 2);
}

#[test]
fn capture_specific_sequence() {
    let a = inv(
        "A",
        vec![
            obs("A", 0, NonceDirection::ClientToServer, 0x10, 1, b"a", 1),
            obs("A", 1, NonceDirection::ClientToServer, 0x11, 1, b"b", 2),
        ],
    );
    let b = inv(
        "B",
        vec![
            obs("B", 0, NonceDirection::ClientToServer, 0x1e, 1, b"c", 1),
            obs("B", 1, NonceDirection::ServerToClient, 0x1f, 1, b"d", 2),
        ],
    );
    let r = analyze_two_captures(&a, &b);
    let g = r
        .ngrams
        .iter()
        .find(|g| g.sequence == vec![0x10, 0x11])
        .expect("A-only bigram");
    assert_eq!(g.classification, SequenceStability::CaptureSpecific);
}

#[test]
fn direction_transition() {
    let a = inv(
        "A",
        vec![
            obs("A", 0, NonceDirection::ClientToServer, 0x79, 1, b"q", 1),
            obs("A", 1, NonceDirection::ServerToClient, 0x7a, 1, b"r", 2),
        ],
    );
    let b = inv(
        "B",
        vec![
            obs("B", 0, NonceDirection::ClientToServer, 0x79, 1, b"q", 1),
            obs("B", 1, NonceDirection::ServerToClient, 0x7a, 1, b"r", 2),
        ],
    );
    let r = analyze_two_captures(&a, &b);
    let t = r
        .direction_transitions
        .iter()
        .find(|t| t.from_id == 0x79 && t.to_id == 0x7a)
        .expect("79→7A");
    assert_eq!(t.from_direction, "client_to_server");
    assert_eq!(t.to_direction, "server_to_client");
    assert_eq!(t.label, CorrelationLabel::Correlation);
}

#[test]
fn context_transition() {
    let a = inv(
        "A",
        vec![
            obs("A", 0, NonceDirection::ClientToServer, 0x19, 1, b"a", 1),
            obs("A", 1, NonceDirection::ServerToClient, 0x1a, 2, b"b", 2),
        ],
    );
    let b = inv(
        "B",
        vec![
            obs("B", 0, NonceDirection::ClientToServer, 0x19, 1, b"a", 1),
            obs("B", 1, NonceDirection::ServerToClient, 0x1a, 2, b"b", 2),
        ],
    );
    let r = analyze_two_captures(&a, &b);
    assert!(r
        .context_transitions
        .iter()
        .any(|t| t.context_before == 1 && t.context_after == 2 && t.message_id == 0x1a));
}

#[test]
fn request_response_candidate() {
    let mk = |cap: &str| {
        inv(
            cap,
            vec![
                obs(cap, 0, NonceDirection::ClientToServer, 0x79, 1, b"qq", 1),
                obs(cap, 1, NonceDirection::ServerToClient, 0x7a, 1, b"rr", 2),
                obs(cap, 2, NonceDirection::ClientToServer, 0x79, 1, b"qq", 10),
                obs(cap, 3, NonceDirection::ServerToClient, 0x7a, 1, b"rr", 11),
            ],
        )
    };
    let r = analyze_two_captures(&mk("A"), &mk("B"));
    let c = r
        .request_response_candidates
        .iter()
        .find(|c| c.request_id == 0x79 && c.response_id == 0x7a)
        .expect("RR candidate");
    assert_eq!(c.candidate_type, "REQUEST_RESPONSE_CANDIDATE");
    assert_eq!(c.confidence, CorrelationLabel::StructuralHypothesis);
    assert_eq!(c.semantic_confirmation, CorrelationLabel::Unknown);
    assert_ne!(c.candidate_type, "CONFIRMED_REQUEST_RESPONSE");
}

#[test]
fn timing_statistics() {
    let s = timing_stats(&[10, 20, 30, 40], "frame_order");
    assert_eq!(s.min, Some(10));
    assert_eq!(s.max, Some(40));
    assert_eq!(s.median, Some(25.0));
    assert!(s.mean.unwrap() > 24.0);
}

#[test]
fn periodicity() {
    // Regular intervals → approximately periodic.
    let a = inv(
        "A",
        vec![
            obs("A", 0, NonceDirection::ClientToServer, 0xfa, 0, &[], 100),
            obs("A", 1, NonceDirection::ClientToServer, 0xfa, 0, &[], 200),
            obs("A", 2, NonceDirection::ClientToServer, 0xfa, 0, &[], 300),
            obs("A", 3, NonceDirection::ClientToServer, 0xfa, 0, &[], 400),
        ],
    );
    let b = inv(
        "B",
        vec![
            obs("B", 0, NonceDirection::ClientToServer, 0xfa, 0, &[], 50),
            obs("B", 1, NonceDirection::ClientToServer, 0xfa, 0, &[], 150),
            obs("B", 2, NonceDirection::ClientToServer, 0xfa, 0, &[], 250),
        ],
    );
    let r = analyze_two_captures(&a, &b);
    let p = r
        .periodic_candidates
        .iter()
        .find(|p| p.message_id == 0xfa && p.paired_id.is_none())
        .expect("periodic FA");
    assert!(p.approximately_periodic);
    assert_eq!(p.label, CorrelationLabel::StructuralHypothesis);
}

#[test]
fn fingerprint_repetition() {
    let payload = b"SAME";
    let a = inv(
        "A",
        vec![
            obs("A", 0, NonceDirection::ClientToServer, 0x12, 1, payload, 1),
            obs("A", 1, NonceDirection::ClientToServer, 0x12, 1, payload, 2),
        ],
    );
    let b = inv(
        "B",
        vec![obs("B", 0, NonceDirection::ClientToServer, 0x12, 1, payload, 1)],
    );
    let r = analyze_two_captures(&a, &b);
    assert!(r
        .fingerprint_repeats
        .iter()
        .any(|f| f.message_id == 0x12 && f.repeat_count >= 2));
}

#[test]
fn payload_relationship() {
    let shared = [0x11u8, 0x22, 0x33, 0x44];
    let a_obs = obs(
        "A",
        0,
        NonceDirection::ClientToServer,
        0x12e,
        1,
        &shared,
        1,
    );
    let b_obs = obs(
        "A",
        1,
        NonceDirection::ServerToClient,
        0x12f,
        1,
        &shared,
        2,
    );
    let pairs = vec![(&a_obs, &b_obs), (&a_obs, &b_obs)];
    let corr = cross_message_value_correlations(&pairs);
    assert!(!corr.is_empty());
    assert!(corr.iter().all(|c| c.semantic_meaning == "UNKNOWN"));
    assert!(corr.iter().all(|c| c.label == CorrelationLabel::Correlation));
}

#[test]
fn sequence_alignment() {
    let segs = align_sequences(&[0x1e, 0x1f, 0x10, 0x19], &[0x1e, 0x1f, 0x19]);
    assert!(segs.iter().any(|s| s.kind == "COMMON" && s.message_ids.contains(&0x1e)));
    assert!(segs.iter().any(|s| s.kind == "A_ONLY" && s.message_ids.contains(&0x10)));
}

#[test]
fn stable_graph_edge() {
    let mk = |cap: &str| {
        inv(
            cap,
            vec![
                obs(cap, 0, NonceDirection::ClientToServer, 0x79, 1, b"a", 1),
                obs(cap, 1, NonceDirection::ServerToClient, 0x7a, 1, b"b", 2),
            ],
        )
    };
    let r = analyze_two_captures(&mk("A"), &mk("B"));
    let e = r
        .transition_edges
        .iter()
        .find(|e| e.from_id == 0x79 && e.to_id == 0x7a)
        .expect("edge");
    assert_eq!(e.edge_class, EdgeClass::StableEdge);
}

#[test]
fn divergent_graph_edge() {
    let a = inv(
        "A",
        vec![
            obs("A", 0, NonceDirection::ClientToServer, 0x0a, 1, b"a", 1),
            obs("A", 1, NonceDirection::ServerToClient, 0x0b, 1, b"b", 2),
        ],
    );
    let b = inv(
        "B",
        vec![
            obs("B", 0, NonceDirection::ServerToClient, 0x0a, 1, b"a", 1),
            obs("B", 1, NonceDirection::ClientToServer, 0x0b, 1, b"b", 2),
        ],
    );
    let r = analyze_two_captures(&a, &b);
    let e = r
        .transition_edges
        .iter()
        .find(|e| e.from_id == 0x0a && e.to_id == 0x0b)
        .expect("edge");
    assert_eq!(e.edge_class, EdgeClass::DivergentEdge);
}

#[test]
fn no_semantic_promotion() {
    let mk = |cap: &str| {
        inv(
            cap,
            vec![
                obs(cap, 0, NonceDirection::ClientToServer, 0x1e, 1, b"a", 1),
                obs(cap, 1, NonceDirection::ServerToClient, 0x1f, 1, b"b", 2),
            ],
        )
    };
    let r = analyze_two_captures(&mk("A"), &mk("B"));
    for c in &r.request_response_candidates {
        assert_eq!(c.candidate_type, "REQUEST_RESPONSE_CANDIDATE");
        assert_eq!(c.semantic_confirmation, CorrelationLabel::Unknown);
        assert_ne!(c.confidence.as_str(), "CONFIRMED_REQUEST");
        assert_ne!(c.confidence.as_str(), "CONFIRMED_RESPONSE");
    }
    let d = compute_sequence_divergence(&r.sequence_a.message_ids, &r.sequence_b.message_ids);
    assert_eq!(d.label, CorrelationLabel::Observed);
}

#[test]
fn correlation_observation_from_inventory() {
    let o = obs("A", 3, NonceDirection::ClientToServer, 0x19, 9, b"zz", 42);
    let c = MessageCorrelationObservation::from_message_observation(&o);
    assert_eq!(c.frame_index, 3);
    assert_eq!(c.timestamp, Some(42));
    assert_eq!(c.timing_basis, "frame_order");
    assert_eq!(c.message_id, 0x19);
}
