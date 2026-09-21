//! Synthetic tests for UDP evidence model (M4.3).

use destiny1_network::udp_evidence::{
    byte_entropy, classify_direction, fingerprint, parse_classic_pcap_udp, payload_sha256,
    prefix_hex, to_packet_observation, UdpDirection, UdpEvidenceRecord,
};

fn rec(idx: u64, ts: f64, sport: u16, dport: u16, payload: &[u8]) -> UdpEvidenceRecord {
    UdpEvidenceRecord {
        packet_index: idx,
        timestamp: ts,
        direction: UdpDirection::Unknown,
        length: (8 + payload.len()) as u32,
        source_port: sport,
        destination_port: dport,
        payload_length: payload.len(),
        payload: payload.to_vec(),
        source_address: "10.0.0.2".into(),
        destination_address: "10.0.0.1".into(),
    }
}

#[test]
fn payload_fingerprint_deterministic() {
    let p = b"abcd";
    assert_eq!(payload_sha256(p), payload_sha256(p));
    let fp = fingerprint(p);
    assert_eq!(fp.length, 4);
    assert_eq!(fp.prefix_hex, "61626364");
    assert!(!fp.sha256.is_empty());
}

#[test]
fn direction_classification_uses_client_ip() {
    let mut r = rec(1, 1.0, 1000, 2000, b"x");
    classify_direction(&mut r, Some("10.0.0.2"), &[]);
    assert_eq!(r.direction, UdpDirection::C2S);
    classify_direction(&mut r, Some("10.0.0.1"), &[]);
    assert_eq!(r.direction, UdpDirection::S2C);
    classify_direction(&mut r, None, &[]);
    assert_eq!(r.direction, UdpDirection::Unknown);
}

#[test]
fn packet_observation_redacts_payload() {
    let r = rec(1, 1.0, 53, 53, b"secret-bytes");
    let obs = to_packet_observation(&r);
    let s = serde_json::to_string(&obs).unwrap();
    assert!(!s.contains("secret-bytes"));
    assert!(s.contains(&obs.payload_sha256));
}

#[test]
fn entropy_empty_and_nonzero() {
    assert_eq!(byte_entropy(b""), 0.0);
    assert!(byte_entropy(b"aaaa") < byte_entropy(b"abcd"));
}

#[test]
fn prefix_hex_truncates() {
    assert_eq!(prefix_hex(b"hello", 2), "6865");
}

#[test]
fn classic_pcap_udp_roundtrip_synthetic() {
    // Build minimal classic pcap (little-endian) with one Ethernet/IPv4/UDP packet.
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes()); // ethernet

    let mut frame = Vec::new();
    frame.extend_from_slice(&[0u8; 12]); // eth addrs
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    // IPv4 header
    let mut ip = vec![0u8; 20];
    ip[0] = 0x45;
    ip[9] = 17; // UDP
    ip[12..16].copy_from_slice(&[1, 2, 3, 4]);
    ip[16..20].copy_from_slice(&[5, 6, 7, 8]);
    let payload = b"PING";
    let udp_len = (8 + payload.len()) as u16;
    let mut udp = Vec::new();
    udp.extend_from_slice(&1234u16.to_be_bytes());
    udp.extend_from_slice(&5678u16.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
    udp.extend_from_slice(payload);
    let total_len = (20 + udp.len()) as u16;
    ip[2..4].copy_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);

    pcap.extend_from_slice(&10u32.to_le_bytes()); // ts_sec
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    pcap.extend_from_slice(&frame);

    let recs = parse_classic_pcap_udp(&pcap).expect("parse");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].source_port, 1234);
    assert_eq!(recs[0].destination_port, 5678);
    assert_eq!(recs[0].payload, b"PING");
}

#[test]
fn absent_udp_pcap_header_only() {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes());
    let recs = parse_classic_pcap_udp(&pcap).unwrap();
    assert!(recs.is_empty());
}
