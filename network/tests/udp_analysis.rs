//! Synthetic tests for UDP analysis (M4.3).

use destiny1_network::udp_analysis::{
    analyze_capture, analyze_flows, analyze_lengths, analyze_prefixes, analyze_timing,
    correlate_with_bap, cross_capture_compare, detect_sequence_candidates, port_pair_key,
    relate_to_session, synth_record, to_safe_export,
};
use destiny1_network::udp_evidence::{BapTimelineEvent, UdpDirection, UdpFlow};
use destiny1_network::udp_evidence_verify;

#[test]
fn udp_flow_grouping_multiple_flows() {
    let recs = vec![
        synth_record(1, 1.0, 1000, 2000, b"a", UdpDirection::C2S),
        synth_record(2, 1.1, 2000, 1000, b"b", UdpDirection::S2C),
        synth_record(3, 2.0, 53, 53000, b"dns", UdpDirection::Unknown),
        synth_record(4, 2.1, 53000, 53, b"dns2", UdpDirection::Unknown),
    ];
    let flows = analyze_flows(&recs);
    assert_eq!(flows.len(), 2);
    assert!(flows.iter().any(|f| f.flow_id == "UDP_FLOW_01"));
    assert!(flows.iter().any(|f| f.flow_id == "UDP_FLOW_02"));
    assert_eq!(port_pair_key(1000, 2000), port_pair_key(2000, 1000));
}

#[test]
fn length_statistics() {
    let recs = vec![
        synth_record(1, 1.0, 1, 2, b"aa", UdpDirection::Unknown),
        synth_record(2, 1.1, 1, 2, b"bbbb", UdpDirection::Unknown),
        synth_record(3, 1.2, 1, 2, b"ccc", UdpDirection::Unknown),
    ];
    let s = analyze_lengths(&recs);
    assert_eq!(s.count, 3);
    assert_eq!(s.min, 2);
    assert_eq!(s.max, 4);
    assert!(s.observation.contains("STRUCTURAL_OBSERVATION"));
}

#[test]
fn timing_statistics_burst() {
    let recs = vec![
        synth_record(1, 1.000, 1, 2, b"a", UdpDirection::Unknown),
        synth_record(2, 1.010, 1, 2, b"b", UdpDirection::Unknown),
        synth_record(3, 1.020, 1, 2, b"c", UdpDirection::Unknown),
        synth_record(4, 2.000, 1, 2, b"d", UdpDirection::Unknown),
    ];
    let t = analyze_timing(&recs);
    assert_eq!(t.pattern, "BURST");
    assert!(t.burst_size >= 3);
}

#[test]
fn prefix_analysis_and_sequence_candidate() {
    let recs = vec![
        synth_record(1, 1.0, 3074, 3074, &[0x00, 0x01, 0x00, 0x01], UdpDirection::Unknown),
        synth_record(2, 1.1, 3074, 3074, &[0x00, 0x01, 0x00, 0x02], UdpDirection::Unknown),
        synth_record(3, 1.2, 3074, 3074, &[0x00, 0x01, 0x00, 0x03], UdpDirection::Unknown),
    ];
    let notes = analyze_prefixes(&recs);
    assert!(!notes.is_empty());
    let seq = detect_sequence_candidates(&recs);
    assert!(
        seq.iter()
            .any(|s| s.classification == "POSSIBLE_SEQUENCE_CANDIDATE"),
        "{seq:?}"
    );
}

#[test]
fn tcp_and_bap_correlation() {
    let recs = vec![synth_record(
        1,
        100.0,
        3074,
        3074,
        b"x",
        UdpDirection::Unknown,
    )];
    let mut flows = analyze_flows(&recs);
    let bap = vec![
        BapTimelineEvent {
            msg_id: 0x1E,
            timestamp: 200.0,
            direction: "C2S".into(),
        },
        BapTimelineEvent {
            msg_id: 0x12E,
            timestamp: 100.05,
            direction: "C2S".into(),
        },
        BapTimelineEvent {
            msg_id: 0x12F,
            timestamp: 100.10,
            direction: "S2C".into(),
        },
    ];
    for f in &mut flows {
        let rel = relate_to_session(f, &bap);
        assert_eq!(rel.as_str(), "BEFORE_SESSION");
    }
    let corr = correlate_with_bap("syn", &flows, &recs, &bap);
    assert!(corr.iter().any(|c| c.kind == "NAT_TEMPORAL"));
    assert!(corr.iter().any(|c| {
        c.classification == "TEMPORAL_CORRELATION_CANDIDATE" && c.bap_msg_id == Some(0x12E)
    }));
}

#[test]
fn cross_capture_and_safe_export_no_secrets() {
    let a_recs = vec![
        synth_record(1, 1.0, 3074, 3074, b"aa", UdpDirection::Unknown),
        synth_record(2, 1.1, 53, 53000, b"dns", UdpDirection::Unknown),
    ];
    let b_recs: Vec<_> = vec![];
    let bap = vec![BapTimelineEvent {
        msg_id: 0x1E,
        timestamp: 10.0,
        direction: "C2S".into(),
    }];
    let a = analyze_capture("A", a_recs, &bap, 1);
    let b = analyze_capture("B", b_recs, &bap, 1);
    assert!(!b.inventory.udp_observed);
    assert!(b
        .transport_observations
        .iter()
        .any(|t| t.note.contains("UDP_NOT_OBSERVED")));
    let cross = cross_capture_compare(&a, &b);
    assert!(cross.properties.iter().any(|p| p.stability == "divergent"
        || p.name.contains("3074")
        || p.name.contains("UDP observed")));
    let export = to_safe_export(&[a, b], cross);
    let json = serde_json::to_string(&export).unwrap();
    assert!(!json.contains("10.0.0."));
    assert!(!json.contains("session_key"));
    assert!(!json.contains("payload_hex"));
    assert_eq!(export.version, "0.1");
}

#[test]
fn deterministic_analysis() {
    let recs = vec![
        synth_record(1, 1.0, 9, 8, b"z", UdpDirection::Unknown),
        synth_record(2, 1.5, 8, 9, b"y", UdpDirection::Unknown),
    ];
    let f1 = analyze_flows(&recs);
    let f2 = analyze_flows(&recs);
    assert_eq!(f1, f2);
}

#[test]
fn fragmented_flow_single_port_pair() {
    // Multiple packets same ports → one flow
    let recs = vec![
        synth_record(1, 1.0, 4000, 5000, b"1", UdpDirection::C2S),
        synth_record(2, 1.2, 5000, 4000, b"2", UdpDirection::S2C),
        synth_record(3, 1.4, 4000, 5000, b"3", UdpDirection::C2S),
    ];
    let flows = analyze_flows(&recs);
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0].packet_count, 3);
}

#[test]
fn safe_fixture_loads_and_cli_verify() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/fixtures/multi_capture/manifest.json"
    );
    // Prefer live pcap if present; else safe fixture.
    let report = udp_evidence_verify::run_from_manifest(path).expect("verify");
    assert_eq!(report.result, "VERIFIED");
    let json = serde_json::to_string(&report.export).unwrap();
    assert!(!json.contains("192.168."));
    assert!(!json.contains("172.97."));
}

#[test]
fn flow_session_relation_post_startup() {
    let mut flow = UdpFlow {
        flow_id: "UDP_FLOW_01".into(),
        first_timestamp: 50.0,
        last_timestamp: 60.0,
        packet_count: 1,
        byte_count: 1,
        direction: "UNKNOWN".into(),
        port_pair: "1/2".into(),
        session_relation: "UNKNOWN".into(),
        classification: "OBSERVED".into(),
    };
    let bap = vec![
        BapTimelineEvent {
            msg_id: 0x1E,
            timestamp: 10.0,
            direction: "C2S".into(),
        },
        BapTimelineEvent {
            msg_id: 0x7A,
            timestamp: 20.0,
            direction: "S2C".into(),
        },
    ];
    let rel = relate_to_session(&mut flow, &bap);
    assert_eq!(rel.as_str(), "POST_STARTUP");
}
