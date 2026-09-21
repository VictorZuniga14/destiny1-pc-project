//! Offline message inventory from decoded BAP frames (M3.1).
//!
//! Consumes [`DecodedBapFrame`] / pipeline outputs. Does **not** re-implement
//! framing or crypto. Evidence labels: OBSERVED / CROSS_CAPTURE_STABLE /
//! DIVERGENT / UNKNOWN / EXTERNAL_REFERENCE.

use crate::bap_session::DecodedBapFrame;
use crate::crypto::NonceDirection;
use crate::messages::lookup_name;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

/// Evidence classification for inventory facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EvidenceLabel {
    Observed,
    CrossCaptureStable,
    Divergent,
    Unknown,
    ExternalReference,
}

impl EvidenceLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "OBSERVED",
            Self::CrossCaptureStable => "CROSS_CAPTURE_STABLE",
            Self::Divergent => "DIVERGENT",
            Self::Unknown => "UNKNOWN",
            Self::ExternalReference => "EXTERNAL_REFERENCE",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessageObservation {
    pub capture_id: String,
    pub frame_index: u32,
    pub direction: String,
    pub frame_kind: u8,
    pub message_id: u16,
    pub context: u32,
    pub payload_len: usize,
    /// Full payload bytes (in-memory). Prefer [`Self::payload_sha256`] for exports.
    #[serde(skip)]
    pub payload: Vec<u8>,
    pub payload_sha256: String,
    pub frame_offset: Option<u64>,
    pub frame_order: Option<u64>,
    pub evidence: EvidenceLabel,
}

impl MessageObservation {
    pub fn from_decoded(
        capture_id: &str,
        frame_index: u32,
        direction: NonceDirection,
        frame: &DecodedBapFrame,
        frame_offset: Option<u64>,
        frame_order: Option<u64>,
    ) -> Option<Self> {
        let dir = match direction {
            NonceDirection::ClientToServer => "client_to_server",
            NonceDirection::ServerToClient => "server_to_client",
        };
        let (frame_kind, message_id, context, payload) = match frame {
            DecodedBapFrame::Clear {
                msg_id,
                context,
                payload,
            } => (2u8, *msg_id, *context, payload.clone()),
            DecodedBapFrame::Decrypted {
                msg_id,
                context,
                payload,
                ..
            } => {
                let id = (*msg_id)?;
                let ctx = context.unwrap_or(0);
                (1u8, id, ctx, payload.clone())
            }
            DecodedBapFrame::Opaque { .. } => return None,
        };
        Some(Self {
            capture_id: capture_id.to_string(),
            frame_index,
            direction: dir.to_string(),
            frame_kind,
            message_id,
            context,
            payload_len: payload.len(),
            payload_sha256: payload_fingerprint(&payload),
            payload,
            frame_offset,
            frame_order,
            evidence: EvidenceLabel::Observed,
        })
    }
}

/// SHA-256 hex of payload bytes (deterministic).
pub fn payload_fingerprint(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessagePayloadDiff {
    pub length_a: usize,
    pub length_b: usize,
    pub same_bytes_prefix: usize,
    pub first_difference_offset: Option<usize>,
    pub different_byte_count: usize,
}

/// Positional byte diff; no semantic interpretation.
pub fn payload_byte_diff(a: &[u8], b: &[u8]) -> MessagePayloadDiff {
    let min_len = a.len().min(b.len());
    let mut prefix = 0usize;
    while prefix < min_len && a[prefix] == b[prefix] {
        prefix += 1;
    }
    let first = if prefix < a.len() || prefix < b.len() {
        Some(prefix)
    } else {
        None
    };
    let mut different = a.len().abs_diff(b.len());
    for i in prefix..min_len {
        if a[i] != b[i] {
            different += 1;
        }
    }
    MessagePayloadDiff {
        length_a: a.len(),
        length_b: b.len(),
        same_bytes_prefix: prefix,
        first_difference_offset: first,
        different_byte_count: different,
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MessageIdGroup {
    pub message_id: u16,
    pub total_observations: u32,
    pub captures_seen: BTreeSet<String>,
    pub directions: BTreeMap<String, u32>,
    pub contexts: BTreeMap<u32, u32>,
    pub payload_lengths: BTreeMap<usize, u32>,
    pub payload_hashes: BTreeMap<String, u32>,
    pub first_frame_index: Option<u32>,
    pub last_frame_index: Option<u32>,
    #[serde(skip)]
    pub observations: Vec<MessageObservation>,
}

impl MessageIdGroup {
    fn push(&mut self, obs: MessageObservation) {
        self.total_observations += 1;
        self.captures_seen.insert(obs.capture_id.clone());
        *self.directions.entry(obs.direction.clone()).or_insert(0) += 1;
        *self.contexts.entry(obs.context).or_insert(0) += 1;
        *self.payload_lengths.entry(obs.payload_len).or_insert(0) += 1;
        *self.payload_hashes.entry(obs.payload_sha256.clone()).or_insert(0) += 1;
        self.first_frame_index = Some(
            self.first_frame_index
                .map_or(obs.frame_index, |f| f.min(obs.frame_index)),
        );
        self.last_frame_index = Some(
            self.last_frame_index
                .map_or(obs.frame_index, |f| f.max(obs.frame_index)),
        );
        self.observations.push(obs);
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct MessageInventory {
    pub groups: BTreeMap<u16, MessageIdGroup>,
}

impl MessageInventory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, obs: MessageObservation) {
        let id = obs.message_id;
        self.groups
            .entry(id)
            .or_insert_with(|| MessageIdGroup {
                message_id: id,
                ..Default::default()
            })
            .push(obs);
    }

    pub fn unique_ids(&self) -> Vec<u16> {
        self.groups.keys().copied().collect()
    }

    pub fn total_observations(&self) -> u32 {
        self.groups.values().map(|g| g.total_observations).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureMessageSummary {
    pub message_id: u16,
    pub occurrences: u32,
    pub direction_counts: BTreeMap<String, u32>,
    pub context_counts: BTreeMap<u32, u32>,
    pub payload_length_counts: BTreeMap<usize, u32>,
    pub external_name: Option<&'static str>,
    pub external_name_label: EvidenceLabel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaptureMessageInventory {
    pub capture_id: String,
    pub total_frames: u32,
    pub message_count: u32,
    pub unique_message_ids: Vec<u16>,
    pub startup_sequence: Vec<u16>,
    pub messages: Vec<CaptureMessageSummary>,
    #[serde(skip)]
    pub inventory: MessageInventory,
}

impl CaptureMessageInventory {
    pub fn from_observations(capture_id: &str, observations: Vec<MessageObservation>) -> Self {
        let total_frames = observations.len() as u32;
        let mut inventory = MessageInventory::new();
        let mut startup = Vec::new();
        for obs in observations {
            if startup.len() < 8 {
                startup.push(obs.message_id);
            }
            inventory.add(obs);
        }
        let unique: Vec<u16> = inventory.unique_ids();
        let messages: Vec<CaptureMessageSummary> = unique
            .iter()
            .map(|id| {
                let g = &inventory.groups[id];
                let ext = lookup_name(*id);
                CaptureMessageSummary {
                    message_id: *id,
                    occurrences: g.total_observations,
                    direction_counts: g.directions.clone(),
                    context_counts: g.contexts.clone(),
                    payload_length_counts: g.payload_lengths.clone(),
                    external_name: ext,
                    external_name_label: if ext.is_some() {
                        EvidenceLabel::ExternalReference
                    } else {
                        EvidenceLabel::Unknown
                    },
                }
            })
            .collect();
        Self {
            capture_id: capture_id.to_string(),
            total_frames,
            message_count: inventory.total_observations(),
            unique_message_ids: unique,
            startup_sequence: startup,
            messages,
            inventory,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Presence {
    Both,
    AOnly,
    BOnly,
}

impl Presence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::AOnly => "A_only",
            Self::BOnly => "B_only",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrossCaptureMessageRow {
    pub message_id: u16,
    pub presence: Presence,
    pub directions_a: BTreeMap<String, u32>,
    pub directions_b: BTreeMap<String, u32>,
    pub contexts_a: BTreeMap<u32, u32>,
    pub contexts_b: BTreeMap<u32, u32>,
    pub lengths_a: BTreeMap<usize, u32>,
    pub lengths_b: BTreeMap<usize, u32>,
    pub direction_status: EvidenceLabel,
    pub context_status: EvidenceLabel,
    pub length_status: EvidenceLabel,
    pub external_name: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ObservedSequencePair {
    pub first_id: u16,
    pub second_id: u16,
    pub first_direction: String,
    pub second_direction: String,
    pub label: EvidenceLabel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CrossCaptureMessageComparison {
    pub capture_a: String,
    pub capture_b: String,
    pub rows: Vec<CrossCaptureMessageRow>,
    pub startup_a: Vec<u16>,
    pub startup_b: Vec<u16>,
    pub startup_status: EvidenceLabel,
    pub sequence_pairs: Vec<ObservedSequencePair>,
    pub sample_payload_diffs: Vec<(u16, MessagePayloadDiff)>,
}

impl CrossCaptureMessageComparison {
    pub fn compare(a: &CaptureMessageInventory, b: &CaptureMessageInventory) -> Self {
        let ids_a: BTreeSet<u16> = a.unique_message_ids.iter().copied().collect();
        let ids_b: BTreeSet<u16> = b.unique_message_ids.iter().copied().collect();
        let all: BTreeSet<u16> = ids_a.union(&ids_b).copied().collect();

        let mut rows = Vec::new();
        let mut sample_diffs = Vec::new();

        for id in all {
            let ga = a.inventory.groups.get(&id);
            let gb = b.inventory.groups.get(&id);
            let presence = match (ga.is_some(), gb.is_some()) {
                (true, true) => Presence::Both,
                (true, false) => Presence::AOnly,
                (false, true) => Presence::BOnly,
                (false, false) => unreachable!(),
            };
            let empty: BTreeMap<String, u32> = BTreeMap::new();
            let empty_c: BTreeMap<u32, u32> = BTreeMap::new();
            let empty_l: BTreeMap<usize, u32> = BTreeMap::new();
            let dirs_a = ga.map(|g| &g.directions).unwrap_or(&empty);
            let dirs_b = gb.map(|g| &g.directions).unwrap_or(&empty);
            let ctx_a = ga.map(|g| &g.contexts).unwrap_or(&empty_c);
            let ctx_b = gb.map(|g| &g.contexts).unwrap_or(&empty_c);
            let len_a = ga.map(|g| &g.payload_lengths).unwrap_or(&empty_l);
            let len_b = gb.map(|g| &g.payload_lengths).unwrap_or(&empty_l);

            let (direction_status, context_status, length_status) = match presence {
                Presence::Both => (
                    compare_key_sets(dirs_a, dirs_b),
                    compare_key_sets(ctx_a, ctx_b),
                    compare_key_sets(len_a, len_b),
                ),
                _ => (
                    EvidenceLabel::Unknown,
                    EvidenceLabel::Unknown,
                    EvidenceLabel::Unknown,
                ),
            };

            if presence == Presence::Both {
                if let (Some(ga), Some(gb)) = (ga, gb) {
                    if let (Some(oa), Some(ob)) = (ga.observations.first(), gb.observations.first())
                    {
                        sample_diffs.push((id, payload_byte_diff(&oa.payload, &ob.payload)));
                    }
                }
            }

            rows.push(CrossCaptureMessageRow {
                message_id: id,
                presence,
                directions_a: dirs_a.clone(),
                directions_b: dirs_b.clone(),
                contexts_a: ctx_a.clone(),
                contexts_b: ctx_b.clone(),
                lengths_a: len_a.clone(),
                lengths_b: len_b.clone(),
                direction_status,
                context_status,
                length_status,
                external_name: lookup_name(id),
            });
        }

        let startup_status = if a.startup_sequence == b.startup_sequence {
            EvidenceLabel::CrossCaptureStable
        } else {
            EvidenceLabel::Divergent
        };

        let sequence_pairs = {
            let mut seen = BTreeSet::new();
            let mut pairs = Vec::new();
            for seq in [&a.startup_sequence, &b.startup_sequence] {
                for (f, s) in observe_sequence_pairs(seq) {
                    if seen.insert((f, s)) {
                        pairs.push(ObservedSequencePair {
                            first_id: f,
                            second_id: s,
                            first_direction: "unknown".into(),
                            second_direction: "unknown".into(),
                            label: EvidenceLabel::Observed,
                        });
                    }
                }
            }
            enrich_pairs_with_dirs(pairs, a)
        };

        Self {
            capture_a: a.capture_id.clone(),
            capture_b: b.capture_id.clone(),
            rows,
            startup_a: a.startup_sequence.clone(),
            startup_b: b.startup_sequence.clone(),
            startup_status,
            sequence_pairs,
            sample_payload_diffs: sample_diffs,
        }
    }

    pub fn both_ids(&self) -> Vec<u16> {
        self.rows
            .iter()
            .filter(|r| r.presence == Presence::Both)
            .map(|r| r.message_id)
            .collect()
    }

    pub fn a_only_ids(&self) -> Vec<u16> {
        self.rows
            .iter()
            .filter(|r| r.presence == Presence::AOnly)
            .map(|r| r.message_id)
            .collect()
    }

    pub fn b_only_ids(&self) -> Vec<u16> {
        self.rows
            .iter()
            .filter(|r| r.presence == Presence::BOnly)
            .map(|r| r.message_id)
            .collect()
    }
}

fn compare_key_sets<K: Ord>(a: &BTreeMap<K, u32>, b: &BTreeMap<K, u32>) -> EvidenceLabel {
    let ka: BTreeSet<_> = a.keys().collect();
    let kb: BTreeSet<_> = b.keys().collect();
    if ka == kb {
        EvidenceLabel::CrossCaptureStable
    } else {
        EvidenceLabel::Divergent
    }
}

fn observe_sequence_pairs(seq: &[u16]) -> Vec<(u16, u16)> {
    let mut out = Vec::new();
    for w in seq.windows(2) {
        out.push((w[0], w[1]));
    }
    out
}

fn enrich_pairs_with_dirs(
    pairs: Vec<ObservedSequencePair>,
    a: &CaptureMessageInventory,
) -> Vec<ObservedSequencePair> {
    let mut by_index: BTreeMap<u32, &MessageObservation> = BTreeMap::new();
    for g in a.inventory.groups.values() {
        for o in &g.observations {
            by_index.insert(o.frame_index, o);
        }
    }
    let ordered: Vec<&MessageObservation> = by_index.values().copied().collect();
    pairs
        .into_iter()
        .map(|mut p| {
            for w in ordered.windows(2) {
                if w[0].message_id == p.first_id && w[1].message_id == p.second_id {
                    p.first_direction = w[0].direction.clone();
                    p.second_direction = w[1].direction.clone();
                    p.label = EvidenceLabel::Observed;
                    break;
                }
            }
            p
        })
        .collect()
}

/// Safe export (no raw payloads / secrets).
#[derive(Debug, Clone, Serialize)]
pub struct SafeInventoryExport {
    pub captures: Vec<SafeCaptureExport>,
    pub comparison: Option<SafeComparisonExport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeCaptureExport {
    pub capture_id: String,
    pub total_frames: u32,
    pub unique_message_ids: Vec<String>,
    pub startup_sequence: Vec<String>,
    pub messages: Vec<SafeMessageExport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeMessageExport {
    pub message_id: String,
    pub occurrences: u32,
    pub direction_counts: BTreeMap<String, u32>,
    pub context_counts: BTreeMap<String, u32>,
    pub payload_length_counts: BTreeMap<String, u32>,
    pub external_name: Option<&'static str>,
    pub external_name_label: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeComparisonExport {
    pub capture_a: String,
    pub capture_b: String,
    pub startup_a: Vec<String>,
    pub startup_b: Vec<String>,
    pub startup_status: &'static str,
    pub rows: Vec<SafeRowExport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeRowExport {
    pub message_id: String,
    pub presence: &'static str,
    pub direction_status: &'static str,
    pub context_status: &'static str,
    pub length_status: &'static str,
    pub external_name: Option<&'static str>,
}

pub fn fmt_msg_id(id: u16) -> String {
    format!("0x{id:02X}")
}

pub fn to_safe_export(
    captures: &[CaptureMessageInventory],
    comparison: Option<&CrossCaptureMessageComparison>,
) -> SafeInventoryExport {
    let captures = captures
        .iter()
        .map(|c| SafeCaptureExport {
            capture_id: c.capture_id.clone(),
            total_frames: c.total_frames,
            unique_message_ids: c.unique_message_ids.iter().copied().map(fmt_msg_id).collect(),
            startup_sequence: c.startup_sequence.iter().copied().map(fmt_msg_id).collect(),
            messages: c
                .messages
                .iter()
                .map(|m| SafeMessageExport {
                    message_id: fmt_msg_id(m.message_id),
                    occurrences: m.occurrences,
                    direction_counts: m.direction_counts.clone(),
                    context_counts: m
                        .context_counts
                        .iter()
                        .map(|(k, v)| (k.to_string(), *v))
                        .collect(),
                    payload_length_counts: m
                        .payload_length_counts
                        .iter()
                        .map(|(k, v)| (k.to_string(), *v))
                        .collect(),
                    external_name: m.external_name,
                    external_name_label: m.external_name_label.as_str(),
                })
                .collect(),
        })
        .collect();
    let comparison = comparison.map(|cmp| SafeComparisonExport {
        capture_a: cmp.capture_a.clone(),
        capture_b: cmp.capture_b.clone(),
        startup_a: cmp.startup_a.iter().copied().map(fmt_msg_id).collect(),
        startup_b: cmp.startup_b.iter().copied().map(fmt_msg_id).collect(),
        startup_status: cmp.startup_status.as_str(),
        rows: cmp
            .rows
            .iter()
            .map(|r| SafeRowExport {
                message_id: fmt_msg_id(r.message_id),
                presence: r.presence.as_str(),
                direction_status: r.direction_status.as_str(),
                context_status: r.context_status.as_str(),
                length_status: r.length_status.as_str(),
                external_name: r.external_name,
            })
            .collect(),
    });
    SafeInventoryExport {
        captures,
        comparison,
    }
}
