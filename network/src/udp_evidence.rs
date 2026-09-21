//! UDP evidence model (M4.3) — read-only offline observations.
//!
//! Does **not** implement UDP networking, gameplay, NAT traversal, or sockets.
//! Labels follow OBSERVED / STRUCTURAL_HYPOTHESIS / EXTERNAL_REFERENCE / UNKNOWN.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Evidence classification labels (never semantic gameplay claims).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceClass {
    Observed,
    StructuralHypothesis,
    StructuralObservation,
    ExternalReference,
    TemporalCorrelationCandidate,
    PossibleSequenceCandidate,
    Unknown,
    UdpNotObservedInCapture,
}

impl EvidenceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "OBSERVED",
            Self::StructuralHypothesis => "STRUCTURAL_HYPOTHESIS",
            Self::StructuralObservation => "STRUCTURAL_OBSERVATION",
            Self::ExternalReference => "EXTERNAL_REFERENCE",
            Self::TemporalCorrelationCandidate => "TEMPORAL_CORRELATION_CANDIDATE",
            Self::PossibleSequenceCandidate => "POSSIBLE_SEQUENCE_CANDIDATE",
            Self::Unknown => "UNKNOWN",
            Self::UdpNotObservedInCapture => "UDP_NOT_OBSERVED_IN_CAPTURE",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UdpDirection {
    C2S,
    S2C,
    Unknown,
}

impl UdpDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::C2S => "C2S",
            Self::S2C => "S2C",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Temporal relation of a UDP flow to the BAP session timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionRelation {
    BeforeSession,
    DuringStartup,
    PostStartup,
    Unknown,
}

impl SessionRelation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeforeSession => "BEFORE_SESSION",
            Self::DuringStartup => "DURING_STARTUP",
            Self::PostStartup => "POST_STARTUP",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingPattern {
    Burst,
    Idle,
    RepeatedBurst,
    Irregular,
    Unknown,
}

impl TimingPattern {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Burst => "BURST",
            Self::Idle => "IDLE",
            Self::RepeatedBurst => "REPEATED_BURST",
            Self::Irregular => "IRREGULAR",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// One UDP datagram observation (payload kept in memory only; never safe-exported).
#[derive(Debug, Clone, PartialEq)]
pub struct UdpEvidenceRecord {
    pub packet_index: u64,
    pub timestamp: f64,
    pub direction: UdpDirection,
    pub length: u32,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload_length: usize,
    /// In-memory only. Safe exports use fingerprints.
    pub payload: Vec<u8>,
    /// Redacted in safe exports.
    pub source_address: String,
    pub destination_address: String,
}

/// Packet-level observation without raw addresses/payload (safe-friendly).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UdpPacketObservation {
    pub packet_index: u64,
    pub timestamp: f64,
    pub direction: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub payload_length: usize,
    pub payload_sha256: String,
    pub prefix_hex: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UdpFlow {
    pub flow_id: String,
    pub first_timestamp: f64,
    pub last_timestamp: f64,
    pub packet_count: u64,
    pub byte_count: u64,
    pub direction: String,
    pub port_pair: String,
    pub session_relation: String,
    #[serde(default)]
    pub classification: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UdpLengthStats {
    pub count: u64,
    pub min: u64,
    pub max: u64,
    pub mean: f64,
    pub median: f64,
    pub unique_lengths: Vec<u64>,
    pub distribution: BTreeMap<u64, u64>,
    pub observation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UdpTimingStats {
    pub inter_packet_deltas: Vec<f64>,
    pub mean_delta: Option<f64>,
    pub median_delta: Option<f64>,
    pub burst_size: u64,
    pub pattern: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UdpPayloadFingerprint {
    pub sha256: String,
    pub length: usize,
    pub prefix_hex: String,
    pub suffix_hex: String,
    pub entropy_bits_per_byte: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CaptureTransportInventory {
    pub capture_id: String,
    pub tcp_flows: u64,
    pub udp_flows: u64,
    pub udp_packets: u64,
    pub udp_bytes: u64,
    pub source_ports: Vec<u16>,
    pub destination_ports: Vec<u16>,
    pub timing_range: Option<[f64; 2]>,
    pub related_tcp_session: String,
    pub udp_observed: bool,
    pub external_address: String,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransportObservation {
    pub state_label: String,
    pub udp_observed: bool,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BapTimelineEvent {
    pub msg_id: u16,
    pub timestamp: f64,
    pub direction: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorrelationRecord {
    pub capture_id: String,
    pub kind: String,
    pub bap_msg_id: Option<u16>,
    pub flow_id: Option<String>,
    pub delta_seconds: Option<f64>,
    pub classification: String,
    pub note: String,
}

pub fn payload_sha256(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hex_encode(&hasher.finalize())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn prefix_hex(payload: &[u8], n: usize) -> String {
    hex_encode(&payload[..payload.len().min(n)])
}

pub fn suffix_hex(payload: &[u8], n: usize) -> String {
    if payload.is_empty() {
        return String::new();
    }
    let start = payload.len().saturating_sub(n);
    hex_encode(&payload[start..])
}

/// Shannon entropy in bits/byte (structural only).
pub fn byte_entropy(payload: &[u8]) -> f64 {
    if payload.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in payload {
        counts[b as usize] += 1;
    }
    let n = payload.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f64 / n;
        h -= p * p.log2();
    }
    h
}

pub fn to_packet_observation(rec: &UdpEvidenceRecord) -> UdpPacketObservation {
    UdpPacketObservation {
        packet_index: rec.packet_index,
        timestamp: rec.timestamp,
        direction: rec.direction.as_str().into(),
        source_port: rec.source_port,
        destination_port: rec.destination_port,
        payload_length: rec.payload_length,
        payload_sha256: payload_sha256(&rec.payload),
        prefix_hex: prefix_hex(&rec.payload, 8),
    }
}

pub fn fingerprint(payload: &[u8]) -> UdpPayloadFingerprint {
    UdpPayloadFingerprint {
        sha256: payload_sha256(payload),
        length: payload.len(),
        prefix_hex: prefix_hex(payload, 8),
        suffix_hex: suffix_hex(payload, 4),
        entropy_bits_per_byte: byte_entropy(payload),
    }
}

/// Minimal classic PCAP (linktype Ethernet) → UDP evidence records.
/// Read-only; no sockets. Supports little-endian magic `d4 c3 b2 a1`.
pub fn parse_classic_pcap_udp(bytes: &[u8]) -> Result<Vec<UdpEvidenceRecord>, String> {
    if bytes.len() < 24 {
        return Err("pcap too short".into());
    }
    let magic = &bytes[0..4];
    let le = magic == [0xd4, 0xc3, 0xb2, 0xa1] || magic == [0x4d, 0x3c, 0xb2, 0xa1];
    let be = magic == [0xa1, 0xb2, 0xc3, 0xd4] || magic == [0xa1, 0xb2, 0x3c, 0x4d];
    if !le && !be {
        return Err(format!("unsupported pcap magic {:02x?}", magic));
    }
    let linktype = if le {
        u32::from_le_bytes(bytes[20..24].try_into().unwrap())
    } else {
        u32::from_be_bytes(bytes[20..24].try_into().unwrap())
    };
    if linktype != 1 {
        return Err(format!("unsupported linktype {linktype} (need Ethernet=1)"));
    }
    let mut off = 24usize;
    let mut out = Vec::new();
    let mut idx = 0u64;
    while off + 16 <= bytes.len() {
        let (ts_sec, ts_usec, incl_len) = if le {
            (
                u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap()),
                u32::from_le_bytes(bytes[off + 4..off + 8].try_into().unwrap()),
                u32::from_le_bytes(bytes[off + 8..off + 12].try_into().unwrap()),
            )
        } else {
            (
                u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()),
                u32::from_be_bytes(bytes[off + 4..off + 8].try_into().unwrap()),
                u32::from_be_bytes(bytes[off + 8..off + 12].try_into().unwrap()),
            )
        };
        off += 16;
        let end = off + incl_len as usize;
        if end > bytes.len() {
            break;
        }
        let pkt = &bytes[off..end];
        off = end;
        idx += 1;
        let ts = ts_sec as f64 + (ts_usec as f64) / 1_000_000.0;
        for rec in extract_udp_from_ethernet(idx, ts, pkt) {
            out.push(rec);
        }
    }
    Ok(out)
}

fn extract_udp_from_ethernet(
    packet_index: u64,
    timestamp: f64,
    pkt: &[u8],
) -> Vec<UdpEvidenceRecord> {
    let mut out = Vec::new();
    if pkt.len() < 14 {
        return out;
    }
    let ethertype = u16::from_be_bytes([pkt[12], pkt[13]]);
    if ethertype != 0x0800 {
        return out;
    }
    let ip = &pkt[14..];
    if ip.len() < 20 {
        return out;
    }
    let version = ip[0] >> 4;
    let ihl = ((ip[0] & 0x0f) as usize) * 4;
    if version != 4 || ip.len() < ihl {
        return out;
    }
    if ip[9] != 17 {
        return out;
    }
    let src = format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15]);
    let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
    let udp = &ip[ihl..];
    if udp.len() < 8 {
        return out;
    }
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    let ulen = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    let payload = if ulen >= 8 {
        udp[8..ulen.min(udp.len())].to_vec()
    } else {
        udp[8..].to_vec()
    };
    out.push(UdpEvidenceRecord {
        packet_index,
        timestamp,
        direction: UdpDirection::Unknown,
        length: (8 + payload.len()) as u32,
        source_port: sport,
        destination_port: dport,
        payload_length: payload.len(),
        payload,
        source_address: src,
        destination_address: dst,
    });
    out
}

/// Assign C2S/S2C when a local client endpoint is known; else UNKNOWN.
pub fn classify_direction(
    rec: &mut UdpEvidenceRecord,
    client_ip: Option<&str>,
    server_hint_ports: &[u16],
) {
    if let Some(cip) = client_ip {
        if rec.source_address == cip {
            rec.direction = UdpDirection::C2S;
            return;
        }
        if rec.destination_address == cip {
            rec.direction = UdpDirection::S2C;
            return;
        }
    }
    // Port-only is insufficient alone — only fill UNKNOWN unless both ends match hints weakly.
    let _ = server_hint_ports;
    rec.direction = UdpDirection::Unknown;
}
