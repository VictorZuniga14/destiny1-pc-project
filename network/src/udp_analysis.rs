//! Offline UDP analysis (M4.3) — no sockets, no sendto, no gameplay claims.

use crate::udp_evidence::{
    byte_entropy, fingerprint, prefix_hex, payload_sha256, BapTimelineEvent, CaptureTransportInventory,
    CorrelationRecord, EvidenceClass, SessionRelation, TimingPattern, TransportObservation,
    UdpDirection, UdpEvidenceRecord, UdpFlow, UdpLengthStats, UdpPayloadFingerprint, UdpTimingStats,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowAnalysis {
    pub flow: UdpFlow,
    pub length_stats: UdpLengthStats,
    pub timing_stats: UdpTimingStats,
    pub fingerprints: Vec<UdpPayloadFingerprint>,
    pub prefix_notes: Vec<String>,
    pub sequence_candidates: Vec<SequenceCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequenceCandidate {
    pub offset: usize,
    pub width: u8,
    pub endian: String,
    pub values: Vec<u64>,
    pub classification: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureUdpAnalysis {
    pub inventory: CaptureTransportInventory,
    pub flows: Vec<FlowAnalysis>,
    pub correlations: Vec<CorrelationRecord>,
    pub transport_observations: Vec<TransportObservation>,
    pub structural_hypotheses: Vec<String>,
    pub unknowns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossCaptureUdpComparison {
    pub capture_a: String,
    pub capture_b: String,
    pub properties: Vec<CrossProperty>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossProperty {
    pub name: String,
    pub present_a: String,
    pub present_b: String,
    pub stability: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeUdpEvidenceExport {
    pub version: String,
    pub captures: Vec<CaptureTransportInventory>,
    pub flows: Vec<UdpFlow>,
    pub correlations: Vec<CorrelationRecord>,
    pub structural_hypotheses: Vec<String>,
    pub unknowns: Vec<String>,
    pub cross_capture: CrossCaptureUdpComparison,
    pub udp_observed_any: bool,
}

pub const SAFE_VERSION: &str = "0.1";

/// Canonical port-pair key (unordered for flow grouping of bidirectional same ports).
pub fn port_pair_key(sport: u16, dport: u16) -> String {
    let (a, b) = if sport <= dport {
        (sport, dport)
    } else {
        (dport, sport)
    };
    format!("{a}/{b}")
}

pub fn analyze_flows(records: &[UdpEvidenceRecord]) -> Vec<UdpFlow> {
    let mut groups: BTreeMap<String, Vec<&UdpEvidenceRecord>> = BTreeMap::new();
    for r in records {
        let key = port_pair_key(r.source_port, r.destination_port);
        groups.entry(key).or_default().push(r);
    }
    let mut flows = Vec::new();
    for (i, (pair, pkts)) in groups.into_iter().enumerate() {
        let flow_id = format!("UDP_FLOW_{:02}", i + 1);
        let first = pkts.iter().map(|p| p.timestamp).fold(f64::INFINITY, f64::min);
        let last = pkts.iter().map(|p| p.timestamp).fold(f64::NEG_INFINITY, f64::max);
        let byte_count: u64 = pkts.iter().map(|p| p.payload_length as u64).sum();
        let dirs: BTreeSet<_> = pkts.iter().map(|p| p.direction.as_str()).collect();
        let direction = if dirs.len() == 1 {
            dirs.iter().next().unwrap().to_string()
        } else {
            "MIXED_OR_UNKNOWN".into()
        };
        flows.push(UdpFlow {
            flow_id,
            first_timestamp: if first.is_finite() { first } else { 0.0 },
            last_timestamp: if last.is_finite() { last } else { 0.0 },
            packet_count: pkts.len() as u64,
            byte_count,
            direction,
            port_pair: pair,
            session_relation: SessionRelation::Unknown.as_str().into(),
            classification: EvidenceClass::Observed.as_str().into(),
        });
    }
    flows
}

pub fn analyze_lengths(records: &[UdpEvidenceRecord]) -> UdpLengthStats {
    let mut lengths: Vec<u64> = records.iter().map(|r| r.payload_length as u64).collect();
    lengths.sort_unstable();
    let count = lengths.len() as u64;
    if count == 0 {
        return UdpLengthStats {
            count: 0,
            min: 0,
            max: 0,
            mean: 0.0,
            median: 0.0,
            unique_lengths: vec![],
            distribution: BTreeMap::new(),
            observation: EvidenceClass::UdpNotObservedInCapture.as_str().into(),
        };
    }
    let min = *lengths.first().unwrap();
    let max = *lengths.last().unwrap();
    let sum: u64 = lengths.iter().sum();
    let mean = sum as f64 / count as f64;
    let median = if count % 2 == 1 {
        lengths[count as usize / 2] as f64
    } else {
        let i = count as usize / 2;
        (lengths[i - 1] + lengths[i]) as f64 / 2.0
    };
    let mut distribution = BTreeMap::new();
    for &l in &lengths {
        *distribution.entry(l).or_insert(0) += 1;
    }
    let unique: Vec<u64> = distribution.keys().copied().collect();
    let observation = if unique.len() == 1 {
        "STRUCTURAL_OBSERVATION:fixed-size".into()
    } else if max - min <= 16 {
        "STRUCTURAL_OBSERVATION:small_variation".into()
    } else {
        "STRUCTURAL_OBSERVATION:high_variation".into()
    };
    UdpLengthStats {
        count,
        min,
        max,
        mean,
        median,
        unique_lengths: unique,
        distribution,
        observation,
    }
}

pub fn analyze_timing(records: &[UdpEvidenceRecord]) -> UdpTimingStats {
    let mut ts: Vec<f64> = records.iter().map(|r| r.timestamp).collect();
    ts.sort_by(|a, b| a.total_cmp(b));
    let mut deltas = Vec::new();
    for w in ts.windows(2) {
        deltas.push(w[1] - w[0]);
    }
    let (mean_delta, median_delta) = if deltas.is_empty() {
        (None, None)
    } else {
        let sum: f64 = deltas.iter().sum();
        let mean = sum / deltas.len() as f64;
        let mut sorted = deltas.clone();
        sorted.sort_by(|a, b| a.total_cmp(b));
        let med = if sorted.len() % 2 == 1 {
            sorted[sorted.len() / 2]
        } else {
            (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
        };
        (Some(mean), Some(med))
    };
    // Burst heuristic: consecutive deltas < 0.05s
    let mut burst_size = 1u64;
    let mut best_burst = 1u64;
    for &d in &deltas {
        if d < 0.05 {
            burst_size += 1;
            best_burst = best_burst.max(burst_size);
        } else {
            burst_size = 1;
        }
    }
    let pattern = if deltas.is_empty() {
        TimingPattern::Unknown
    } else if best_burst >= 3 {
        TimingPattern::Burst
    } else if mean_delta.map(|m| m > 1.0).unwrap_or(false) {
        TimingPattern::Idle
    } else {
        TimingPattern::Irregular
    };
    UdpTimingStats {
        inter_packet_deltas: deltas,
        mean_delta,
        median_delta,
        burst_size: best_burst,
        pattern: pattern.as_str().into(),
    }
}

pub fn analyze_prefixes(records: &[UdpEvidenceRecord]) -> Vec<String> {
    let mut notes = Vec::new();
    if records.is_empty() {
        return notes;
    }
    let prefixes: Vec<String> = records.iter().map(|r| prefix_hex(&r.payload, 4)).collect();
    let unique: BTreeSet<_> = prefixes.iter().cloned().collect();
    if unique.len() == 1 {
        notes.push(format!(
            "STRUCTURAL_HYPOTHESIS: constant 4-byte prefix {}",
            unique.iter().next().unwrap()
        ));
    } else {
        notes.push(format!(
            "STRUCTURAL_HYPOTHESIS: variable 4-byte prefixes ({} distinct)",
            unique.len()
        ));
    }
    // bit variation on first byte
    let first_bytes: BTreeSet<u8> = records
        .iter()
        .filter_map(|r| r.payload.first().copied())
        .collect();
    if first_bytes.len() > 1 {
        notes.push(format!(
            "STRUCTURAL_HYPOTHESIS: first-byte variation ({} values)",
            first_bytes.len()
        ));
    }
    notes
}

pub fn detect_sequence_candidates(records: &[UdpEvidenceRecord]) -> Vec<SequenceCandidate> {
    let mut out = Vec::new();
    if records.len() < 3 {
        return out;
    }
    // Try u16 BE at offset 2 (common after 2-byte magic-ish prefix in 3074 samples).
    for &(offset, width, be) in &[(0usize, 2u8, true), (2, 2, true), (0, 4, true)] {
        let mut values = Vec::new();
        let mut ok = true;
        for r in records {
            if r.payload.len() < offset + width as usize {
                ok = false;
                break;
            }
            let slice = &r.payload[offset..offset + width as usize];
            let v = if width == 2 {
                if be {
                    u16::from_be_bytes([slice[0], slice[1]]) as u64
                } else {
                    u16::from_le_bytes([slice[0], slice[1]]) as u64
                }
            } else if be {
                u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) as u64
            } else {
                u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]) as u64
            };
            values.push(v);
        }
        if !ok || values.len() < 3 {
            continue;
        }
        let monotonic = values.windows(2).all(|w| w[1] >= w[0]);
        let steps = values.windows(2).filter(|w| w[1] == w[0] + 1).count();
        if monotonic && steps >= 1 {
            out.push(SequenceCandidate {
                offset,
                width,
                endian: if be { "BE".into() } else { "LE".into() },
                values: values.clone(),
                classification: EvidenceClass::PossibleSequenceCandidate.as_str().into(),
            });
        }
    }
    out
}

pub fn relate_to_session(
    flow: &mut UdpFlow,
    bap: &[BapTimelineEvent],
) -> SessionRelation {
    let startup_end = bap
        .iter()
        .filter(|e| matches!(e.msg_id, 0x1E | 0x1F | 0x19 | 0x1A | 0x79 | 0x7A))
        .map(|e| e.timestamp)
        .fold(None, |acc: Option<f64>, t| {
            Some(acc.map_or(t, |a| a.max(t)))
        });
    let session_start = bap
        .iter()
        .find(|e| e.msg_id == 0x1E)
        .map(|e| e.timestamp);
    let rel = match (session_start, startup_end) {
        (Some(start), Some(end)) => {
            if flow.last_timestamp < start {
                SessionRelation::BeforeSession
            } else if flow.first_timestamp <= end {
                SessionRelation::DuringStartup
            } else {
                SessionRelation::PostStartup
            }
        }
        _ => SessionRelation::Unknown,
    };
    flow.session_relation = rel.as_str().into();
    rel
}

pub fn correlate_with_bap(
    capture_id: &str,
    flows: &[UdpFlow],
    records: &[UdpEvidenceRecord],
    bap: &[BapTimelineEvent],
) -> Vec<CorrelationRecord> {
    let mut out = Vec::new();
    let nat_ids = [0x12Eu16, 0x12F];
    let watch = [0x12E, 0x12F, 0x12D, 0x0A, 0x0B, 0x0C, 0x0D, 0xFA, 0xFB];

    for &mid in &watch {
        for ev in bap.iter().filter(|e| e.msg_id == mid) {
            // nearest UDP packet
            let mut best: Option<(&UdpEvidenceRecord, f64)> = None;
            for r in records {
                let d = (r.timestamp - ev.timestamp).abs();
                if best.map(|(_, bd)| d < bd).unwrap_or(true) {
                    best = Some((r, d));
                }
            }
            if let Some((r, d)) = best {
                let class = if d <= 0.5 {
                    EvidenceClass::TemporalCorrelationCandidate
                } else {
                    EvidenceClass::Unknown
                };
                let kind = if nat_ids.contains(&mid) {
                    "NAT_TEMPORAL"
                } else {
                    "BAP_TEMPORAL"
                };
                out.push(CorrelationRecord {
                    capture_id: capture_id.into(),
                    kind: kind.into(),
                    bap_msg_id: Some(mid),
                    flow_id: flows
                        .iter()
                        .find(|f| f.port_pair == port_pair_key(r.source_port, r.destination_port))
                        .map(|f| f.flow_id.clone()),
                    delta_seconds: Some(d),
                    classification: class.as_str().into(),
                    note: format!(
                        "nearest UDP ports {}→{} delta_s={d:.6}; correlation≠causality",
                        r.source_port, r.destination_port
                    ),
                });
            } else {
                out.push(CorrelationRecord {
                    capture_id: capture_id.into(),
                    kind: if nat_ids.contains(&mid) {
                        "NAT_TEMPORAL".into()
                    } else {
                        "BAP_TEMPORAL".into()
                    },
                    bap_msg_id: Some(mid),
                    flow_id: None,
                    delta_seconds: None,
                    classification: EvidenceClass::UdpNotObservedInCapture.as_str().into(),
                    note: "no UDP packets in capture to correlate".into(),
                });
            }
        }
    }

    for f in flows {
        out.push(CorrelationRecord {
            capture_id: capture_id.into(),
            kind: "TCP_SESSION_RELATION".into(),
            bap_msg_id: None,
            flow_id: Some(f.flow_id.clone()),
            delta_seconds: None,
            classification: f.session_relation.clone(),
            note: format!("flow {} ports {}", f.flow_id, f.port_pair),
        });
    }
    out
}

pub fn build_inventory(
    capture_id: &str,
    records: &[UdpEvidenceRecord],
    flows: &[UdpFlow],
    tcp_flows: u64,
) -> CaptureTransportInventory {
    let mut sports: BTreeSet<u16> = BTreeSet::new();
    let mut dports: BTreeSet<u16> = BTreeSet::new();
    let mut bytes = 0u64;
    for r in records {
        sports.insert(r.source_port);
        dports.insert(r.destination_port);
        bytes += r.payload_length as u64;
    }
    let timing_range = if records.is_empty() {
        None
    } else {
        let min = records.iter().map(|r| r.timestamp).fold(f64::INFINITY, f64::min);
        let max = records
            .iter()
            .map(|r| r.timestamp)
            .fold(f64::NEG_INFINITY, f64::max);
        Some([min, max])
    };
    let mut notes = Vec::new();
    if records.is_empty() {
        notes.push(EvidenceClass::UdpNotObservedInCapture.as_str().into());
    }
    CaptureTransportInventory {
        capture_id: capture_id.into(),
        tcp_flows,
        udp_flows: flows.len() as u64,
        udp_packets: records.len() as u64,
        udp_bytes: bytes,
        source_ports: sports.into_iter().collect(),
        destination_ports: dports.into_iter().collect(),
        timing_range,
        related_tcp_session: "UNKNOWN".into(),
        udp_observed: !records.is_empty(),
        external_address: "REDACTED".into(),
        notes,
    }
}

pub fn analyze_capture(
    capture_id: &str,
    records: Vec<UdpEvidenceRecord>,
    bap: &[BapTimelineEvent],
    tcp_flows: u64,
) -> CaptureUdpAnalysis {
    let mut flows = analyze_flows(&records);
    for f in &mut flows {
        relate_to_session(f, bap);
    }
    let mut flow_analyses = Vec::new();
    for f in &flows {
        let owned: Vec<UdpEvidenceRecord> = records
            .iter()
            .filter(|r| port_pair_key(r.source_port, r.destination_port) == f.port_pair)
            .cloned()
            .collect();
        flow_analyses.push(FlowAnalysis {
            flow: f.clone(),
            length_stats: analyze_lengths(&owned),
            timing_stats: analyze_timing(&owned),
            fingerprints: owned.iter().map(|r| fingerprint(&r.payload)).collect(),
            prefix_notes: analyze_prefixes(&owned),
            sequence_candidates: detect_sequence_candidates(&owned),
        });
    }
    let correlations = correlate_with_bap(capture_id, &flows, &records, bap);
    let inventory = build_inventory(capture_id, &records, &flows, tcp_flows);

    let mut transport_observations = Vec::new();
    let any_post = flows
        .iter()
        .any(|f| f.session_relation == SessionRelation::PostStartup.as_str());
    let any_before = flows
        .iter()
        .any(|f| f.session_relation == SessionRelation::BeforeSession.as_str());
    if any_post {
        transport_observations.push(TransportObservation {
            state_label: "POST_STARTUP".into(),
            udp_observed: true,
            note: "UDP observed after startup window (temporal only; not gameplay)".into(),
        });
    }
    if any_before {
        transport_observations.push(TransportObservation {
            state_label: "BEFORE_SESSION".into(),
            udp_observed: true,
            note: "UDP observed before BAP 0x1E".into(),
        });
    }
    if records.is_empty() {
        transport_observations.push(TransportObservation {
            state_label: "CAPTURE".into(),
            udp_observed: false,
            note: EvidenceClass::UdpNotObservedInCapture.as_str().into(),
        });
    }

    let mut structural_hypotheses = Vec::new();
    let unknowns = vec![
        "UNK-UDP-TRANSPORT".into(),
        "UNK-UDP-FRAMING".into(),
        "UNK-UDP-SESSION-BINDING".into(),
        "UNK-UDP-PAYLOAD".into(),
        "UNK-UDP-SEQUENCING".into(),
        "UNK-UDP-LOSS".into(),
        "UNK-UDP-REORDERING".into(),
        "UNK-UDP-NAT".into(),
    ];
    for fa in &flow_analyses {
        structural_hypotheses.extend(fa.prefix_notes.clone());
        for sc in &fa.sequence_candidates {
            structural_hypotheses.push(format!(
                "POSSIBLE_SEQUENCE_CANDIDATE offset={} width={} values={:?}",
                sc.offset, sc.width, sc.values
            ));
        }
    }

    CaptureUdpAnalysis {
        inventory,
        flows: flow_analyses,
        correlations,
        transport_observations,
        structural_hypotheses,
        unknowns,
    }
}

pub fn cross_capture_compare(
    a: &CaptureUdpAnalysis,
    b: &CaptureUdpAnalysis,
) -> CrossCaptureUdpComparison {
    let mut properties = Vec::new();
    properties.push(CrossProperty {
        name: "UDP observed".into(),
        present_a: if a.inventory.udp_observed {
            "yes".into()
        } else {
            "no".into()
        },
        present_b: if b.inventory.udp_observed {
            "yes".into()
        } else {
            "no".into()
        },
        stability: if a.inventory.udp_observed == b.inventory.udp_observed {
            "stable".into()
        } else {
            "divergent".into()
        },
        note: "Presence of any UDP datagrams".into(),
    });

    let a_3074 = a.inventory.source_ports.contains(&3074)
        || a.inventory.destination_ports.contains(&3074);
    let b_3074 = b.inventory.source_ports.contains(&3074)
        || b.inventory.destination_ports.contains(&3074);
    properties.push(CrossProperty {
        name: "UDP port 3074".into(),
        present_a: if a_3074 { "yes".into() } else { "no".into() },
        present_b: if b_3074 { "yes".into() } else { "no".into() },
        stability: if a_3074 == b_3074 {
            if a_3074 {
                "stable".into()
            } else {
                "unknown".into()
            }
        } else {
            "capture-specific".into()
        },
        note: "Port number alone is not a Destiny protocol claim".into(),
    });

    let a_dns = a.inventory.source_ports.contains(&53)
        || a.inventory.destination_ports.contains(&53);
    let b_dns = b.inventory.source_ports.contains(&53)
        || b.inventory.destination_ports.contains(&53);
    properties.push(CrossProperty {
        name: "UDP DNS (53)".into(),
        present_a: if a_dns { "yes".into() } else { "no".into() },
        present_b: if b_dns { "yes".into() } else { "no".into() },
        stability: if a_dns && b_dns {
            "stable".into()
        } else {
            "divergent".into()
        },
        note: "DNS is ambient; not BAP".into(),
    });

    let a_post = a
        .transport_observations
        .iter()
        .any(|t| t.state_label == "POST_STARTUP" && t.udp_observed);
    let b_post = b
        .transport_observations
        .iter()
        .any(|t| t.state_label == "POST_STARTUP" && t.udp_observed);
    properties.push(CrossProperty {
        name: "UDP during/after BAP session".into(),
        present_a: if a_post { "yes".into() } else { "no".into() },
        present_b: if b_post { "yes".into() } else { "no".into() },
        stability: if a_post == b_post {
            "stable".into()
        } else {
            "divergent".into()
        },
        note: "Based on timestamps vs 0x1E startup window only".into(),
    });

    CrossCaptureUdpComparison {
        capture_a: a.inventory.capture_id.clone(),
        capture_b: b.inventory.capture_id.clone(),
        properties,
    }
}

pub fn to_safe_export(
    analyses: &[CaptureUdpAnalysis],
    cross: CrossCaptureUdpComparison,
) -> SafeUdpEvidenceExport {
    let mut captures = Vec::new();
    let mut flows = Vec::new();
    let mut correlations = Vec::new();
    let mut structural_hypotheses = BTreeSet::new();
    let mut unknowns = BTreeSet::new();
    let mut udp_observed_any = false;
    for a in analyses {
        udp_observed_any |= a.inventory.udp_observed;
        captures.push(a.inventory.clone());
        for f in &a.flows {
            flows.push(f.flow.clone());
        }
        correlations.extend(a.correlations.clone());
        structural_hypotheses.extend(a.structural_hypotheses.iter().cloned());
        unknowns.extend(a.unknowns.iter().cloned());
    }
    // Scrub: ensure no IP-looking strings in hypotheses
    let structural_hypotheses: Vec<String> = structural_hypotheses
        .into_iter()
        .filter(|s| !s.contains("192.") && !s.contains("172."))
        .collect();
    SafeUdpEvidenceExport {
        version: SAFE_VERSION.into(),
        captures,
        flows,
        correlations,
        structural_hypotheses,
        unknowns: unknowns.into_iter().collect(),
        cross_capture: cross,
        udp_observed_any,
    }
}

/// Build a synthetic evidence record for tests.
pub fn synth_record(
    idx: u64,
    ts: f64,
    sport: u16,
    dport: u16,
    payload: &[u8],
    direction: UdpDirection,
) -> UdpEvidenceRecord {
    UdpEvidenceRecord {
        packet_index: idx,
        timestamp: ts,
        direction,
        length: (8 + payload.len()) as u32,
        source_port: sport,
        destination_port: dport,
        payload_length: payload.len(),
        payload: payload.to_vec(),
        source_address: "REDACTED".into(),
        destination_address: "REDACTED".into(),
    }
}

#[allow(dead_code)]
fn _entropy_touch(p: &[u8]) -> f64 {
    byte_entropy(p)
}

#[allow(dead_code)]
fn _sha_touch(p: &[u8]) -> String {
    payload_sha256(p)
}
