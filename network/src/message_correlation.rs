//! Offline message correlation & sequence analysis (M3.3).
//!
//! Labels: OBSERVED / STRUCTURAL_HYPOTHESIS / CORRELATION /
//! EXTERNAL_REFERENCE / UNKNOWN. Never promotes candidates to confirmed
//! request/response semantics.

use crate::message_inventory::{fmt_msg_id, CaptureMessageInventory, MessageObservation};
use crate::messages::lookup_name;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Evidence / hypothesis label for correlation facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CorrelationLabel {
    Observed,
    StructuralHypothesis,
    Correlation,
    ExternalReference,
    Unknown,
}

impl CorrelationLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "OBSERVED",
            Self::StructuralHypothesis => "STRUCTURAL_HYPOTHESIS",
            Self::Correlation => "CORRELATION",
            Self::ExternalReference => "EXTERNAL_REFERENCE",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SequenceStability {
    StableSequence,
    PartiallyStable,
    CaptureSpecific,
    Unknown,
}

impl SequenceStability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StableSequence => "STABLE_SEQUENCE",
            Self::PartiallyStable => "PARTIALLY_STABLE",
            Self::CaptureSpecific => "CAPTURE_SPECIFIC",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum EdgeClass {
    StableEdge,
    CaptureSpecificEdge,
    DivergentEdge,
}

impl EdgeClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StableEdge => "STABLE_EDGE",
            Self::CaptureSpecificEdge => "CAPTURE_SPECIFIC_EDGE",
            Self::DivergentEdge => "DIVERGENT_EDGE",
        }
    }
}

/// Temporal observation for correlation (reuses inventory fields).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessageCorrelationObservation {
    pub capture_id: String,
    pub frame_index: u32,
    pub frame_order: Option<u64>,
    /// Ordinal timing from `frame_order` when present (not wall-clock ms).
    pub timestamp: Option<u64>,
    pub timing_basis: &'static str,
    pub direction: String,
    pub message_id: u16,
    pub context: u32,
    pub payload_len: usize,
    pub payload_fingerprint: String,
}

impl MessageCorrelationObservation {
    pub fn from_message_observation(o: &MessageObservation) -> Self {
        let (timestamp, timing_basis) = match o.frame_order {
            Some(ord) => (Some(ord), "frame_order"),
            None => (None, "unknown"),
        };
        Self {
            capture_id: o.capture_id.clone(),
            frame_index: o.frame_index,
            frame_order: o.frame_order,
            timestamp,
            timing_basis,
            direction: o.direction.clone(),
            message_id: o.message_id,
            context: o.context,
            payload_len: o.payload_len,
            payload_fingerprint: o.payload_sha256.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MessageSequence {
    pub capture_id: String,
    pub message_ids: Vec<u16>,
    pub sequence_length: usize,
    pub unique_message_ids: Vec<u16>,
    pub direction_changes: u32,
    pub context_changes: u32,
    pub observations: Vec<MessageCorrelationObservation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NgramRecord {
    pub n: u8,
    pub sequence: Vec<u16>,
    pub sequence_key: String,
    pub occurrences: u32,
    pub captures_seen: BTreeSet<String>,
    pub direction_pattern: String,
    pub context_pattern: String,
    pub classification: SequenceStability,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimingStats {
    pub sample_count: u32,
    pub min: Option<u64>,
    pub max: Option<u64>,
    pub mean: Option<f64>,
    pub median: Option<f64>,
    pub unit: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirectionTransition {
    pub from_id: u16,
    pub to_id: u16,
    pub from_direction: String,
    pub to_direction: String,
    pub count: u32,
    pub captures_seen: BTreeSet<String>,
    pub label: CorrelationLabel,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestResponseCandidate {
    pub request_id: u16,
    pub response_id: u16,
    pub request_direction: String,
    pub response_direction: String,
    pub occurrences: u32,
    pub captures_seen: BTreeSet<String>,
    pub signals: Vec<&'static str>,
    pub candidate_type: &'static str,
    pub confidence: CorrelationLabel,
    pub semantic_confirmation: CorrelationLabel,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContextCorrelation {
    pub message_id: u16,
    pub contexts_seen: BTreeSet<u32>,
    pub by_context: Vec<ContextBucket>,
    pub classification: CorrelationLabel,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContextBucket {
    pub context: u32,
    pub captures: BTreeSet<String>,
    pub directions: BTreeMap<String, u32>,
    pub lengths: BTreeMap<usize, u32>,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContextTransition {
    pub context_before: u32,
    pub message_id: u16,
    pub context_after: u32,
    pub count: u32,
    pub captures_seen: BTreeSet<String>,
    pub label: CorrelationLabel,
}

#[derive(Debug, Clone, Serialize)]
pub struct FingerprintRepeat {
    pub message_id: u16,
    pub direction: String,
    pub context: u32,
    pub fingerprint: String,
    pub repeat_count: u32,
    pub positions: Vec<u32>,
    pub captures: BTreeSet<String>,
    pub label: CorrelationLabel,
}

#[derive(Debug, Clone, Serialize)]
pub struct PayloadVariation {
    pub message_id: u16,
    pub direction: String,
    pub context: u32,
    pub distinct_fingerprints: usize,
    pub captures_seen: BTreeSet<String>,
    pub label: CorrelationLabel,
}

#[derive(Debug, Clone, Serialize)]
pub struct CrossMessageValueCorrelation {
    pub from_id: u16,
    pub to_id: u16,
    pub from_offset: usize,
    pub to_offset: usize,
    pub width: usize,
    pub matching_pairs: u32,
    pub candidate_correlation: bool,
    pub semantic_meaning: &'static str,
    pub label: CorrelationLabel,
}

#[derive(Debug, Clone, Serialize)]
pub struct TemporalCluster {
    pub message_ids: Vec<u16>,
    pub cluster_size: usize,
    pub intervals: TimingStats,
    pub pattern_key: String,
    pub captures_seen: BTreeSet<String>,
    pub label: CorrelationLabel,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeriodicCandidate {
    pub message_id: u16,
    pub paired_id: Option<u16>,
    pub periodic_candidate: bool,
    pub approximately_periodic: bool,
    pub median_interval: Option<f64>,
    pub jitter: Option<f64>,
    pub sample_count: u32,
    pub unit: &'static str,
    pub label: CorrelationLabel,
    pub external_reference: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SequenceDivergence {
    pub common_prefix_length: usize,
    pub common_suffix_length: usize,
    pub divergence_index: Option<usize>,
    pub capture_a_message: Option<u16>,
    pub capture_b_message: Option<u16>,
    pub label: CorrelationLabel,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlignmentSegment {
    pub kind: &'static str,
    pub message_ids: Vec<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TransitionEdge {
    pub from_id: u16,
    pub to_id: u16,
    pub count: u32,
    pub captures_seen: BTreeSet<String>,
    pub direction_transition: String,
    pub context_transition: String,
    pub median_delta: Option<f64>,
    pub delta_unit: &'static str,
    pub edge_class: EdgeClass,
}

#[derive(Debug, Clone, Serialize)]
pub struct StableSubsequence {
    pub sequence: Vec<u16>,
    pub sequence_key: String,
    pub occurrences_a: u32,
    pub occurrences_b: u32,
    pub length: usize,
    pub classification: SequenceStability,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalNameRef {
    pub message_id: u16,
    pub external_reference: &'static str,
    pub source: &'static str,
    pub label: CorrelationLabel,
}

#[derive(Debug, Clone, Serialize)]
pub struct CorrelationAnalysis {
    pub capture_a: String,
    pub capture_b: String,
    pub sequence_a: MessageSequence,
    pub sequence_b: MessageSequence,
    pub unique_message_ids: Vec<u16>,
    pub ngrams: Vec<NgramRecord>,
    pub stable_sequences: Vec<StableSubsequence>,
    pub direction_transitions: Vec<DirectionTransition>,
    pub request_response_candidates: Vec<RequestResponseCandidate>,
    pub context_correlations: Vec<ContextCorrelation>,
    pub context_transitions: Vec<ContextTransition>,
    pub fingerprint_repeats: Vec<FingerprintRepeat>,
    pub payload_variations: Vec<PayloadVariation>,
    pub cross_message_correlations: Vec<CrossMessageValueCorrelation>,
    pub temporal_clusters: Vec<TemporalCluster>,
    pub periodic_candidates: Vec<PeriodicCandidate>,
    pub sequence_divergence: SequenceDivergence,
    pub alignment: Vec<AlignmentSegment>,
    pub transition_edges: Vec<TransitionEdge>,
    pub external_references: Vec<ExternalNameRef>,
    pub edge_timing: BTreeMap<String, TimingStats>,
}

/// Ordered observations from a capture inventory (by frame_index).
pub fn ordered_observations(inv: &CaptureMessageInventory) -> Vec<&MessageObservation> {
    let mut out: Vec<&MessageObservation> = inv
        .inventory
        .groups
        .values()
        .flat_map(|g| g.observations.iter())
        .collect();
    out.sort_by_key(|o| (o.frame_index, o.frame_order.unwrap_or(0)));
    out
}

pub fn build_sequence(inv: &CaptureMessageInventory) -> MessageSequence {
    let obs = ordered_observations(inv);
    let corr: Vec<MessageCorrelationObservation> = obs
        .iter()
        .map(|o| MessageCorrelationObservation::from_message_observation(o))
        .collect();
    let message_ids: Vec<u16> = corr.iter().map(|c| c.message_id).collect();
    let unique: BTreeSet<u16> = message_ids.iter().copied().collect();
    let mut direction_changes = 0u32;
    let mut context_changes = 0u32;
    for w in corr.windows(2) {
        if w[0].direction != w[1].direction {
            direction_changes += 1;
        }
        if w[0].context != w[1].context {
            context_changes += 1;
        }
    }
    MessageSequence {
        capture_id: inv.capture_id.clone(),
        sequence_length: message_ids.len(),
        unique_message_ids: unique.into_iter().collect(),
        message_ids,
        direction_changes,
        context_changes,
        observations: corr,
    }
}

fn sequence_key(ids: &[u16]) -> String {
    ids.iter()
        .map(|id| fmt_msg_id(*id))
        .collect::<Vec<_>>()
        .join("→")
}

/// Generate n-grams for one ordered sequence of observations.
pub fn ngrams_for_observations(
    obs: &[MessageCorrelationObservation],
    n: usize,
) -> Vec<(Vec<u16>, String, String)> {
    let mut out = Vec::new();
    if n == 0 || obs.len() < n {
        return out;
    }
    for window in obs.windows(n) {
        let ids: Vec<u16> = window.iter().map(|o| o.message_id).collect();
        let dirs: String = window
            .iter()
            .map(|o| dir_short(&o.direction))
            .collect::<Vec<_>>()
            .join("→");
        let ctxs: String = window
            .iter()
            .map(|o| o.context.to_string())
            .collect::<Vec<_>>()
            .join("→");
        out.push((ids, dirs, ctxs));
    }
    out
}

fn dir_short(d: &str) -> &str {
    match d {
        "client_to_server" => "C2S",
        "server_to_client" => "S2C",
        other => other,
    }
}

fn opposite_dir(a: &str, b: &str) -> bool {
    (a == "client_to_server" && b == "server_to_client")
        || (a == "server_to_client" && b == "client_to_server")
}

pub fn timing_stats(values: &[u64], unit: &'static str) -> TimingStats {
    if values.is_empty() {
        return TimingStats {
            sample_count: 0,
            min: None,
            max: None,
            mean: None,
            median: None,
            unit,
        };
    }
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    let min = Some(sorted[0]);
    let max = Some(sorted[n - 1]);
    let sum: u64 = sorted.iter().sum();
    let mean = Some(sum as f64 / n as f64);
    let median = Some(if n % 2 == 1 {
        sorted[n / 2] as f64
    } else {
        (sorted[n / 2 - 1] as f64 + sorted[n / 2] as f64) / 2.0
    });
    TimingStats {
        sample_count: n as u32,
        min,
        max,
        mean,
        median,
        unit,
    }
}

fn delta_between(
    a: &MessageCorrelationObservation,
    b: &MessageCorrelationObservation,
) -> Option<u64> {
    match (a.timestamp, b.timestamp) {
        (Some(x), Some(y)) if y >= x => Some(y - x),
        _ => None,
    }
}

/// Longest common subsequence of message IDs (classic DP).
pub fn lcs_ids(a: &[u16], b: &[u16]) -> Vec<u16> {
    let n = a.len();
    let m = b.len();
    let mut dp = vec![vec![0usize; m + 1]; n + 1];
    for i in 1..=n {
        for j in 1..=m {
            if a[i - 1] == b[j - 1] {
                dp[i][j] = dp[i - 1][j - 1] + 1;
            } else {
                dp[i][j] = dp[i - 1][j].max(dp[i][j - 1]);
            }
        }
    }
    let mut out = Vec::new();
    let mut i = n;
    let mut j = m;
    while i > 0 && j > 0 {
        if a[i - 1] == b[j - 1] {
            out.push(a[i - 1]);
            i -= 1;
            j -= 1;
        } else if dp[i - 1][j] >= dp[i][j - 1] {
            i -= 1;
        } else {
            j -= 1;
        }
    }
    out.reverse();
    out
}

/// Alignment segments: COMMON / A_ONLY / B_ONLY via LCS walk.
pub fn align_sequences(a: &[u16], b: &[u16]) -> Vec<AlignmentSegment> {
    let lcs = lcs_ids(a, b);
    let mut segments = Vec::new();
    let mut ia = 0usize;
    let mut ib = 0usize;
    let mut li = 0usize;

    let push = |segs: &mut Vec<AlignmentSegment>, kind: &'static str, ids: Vec<u16>| {
        if ids.is_empty() {
            return;
        }
        if let Some(last) = segs.last_mut() {
            if last.kind == kind {
                last.message_ids.extend(ids);
                return;
            }
        }
        segs.push(AlignmentSegment {
            kind,
            message_ids: ids,
        });
    };

    while li < lcs.len() {
        let target = lcs[li];
        let mut a_only = Vec::new();
        while ia < a.len() && a[ia] != target {
            a_only.push(a[ia]);
            ia += 1;
        }
        push(&mut segments, "A_ONLY", a_only);
        let mut b_only = Vec::new();
        while ib < b.len() && b[ib] != target {
            b_only.push(b[ib]);
            ib += 1;
        }
        push(&mut segments, "B_ONLY", b_only);
        if ia < a.len() && ib < b.len() && a[ia] == target && b[ib] == target {
            push(&mut segments, "COMMON", vec![target]);
            ia += 1;
            ib += 1;
            li += 1;
        } else {
            break;
        }
    }
    if ia < a.len() {
        push(&mut segments, "A_ONLY", a[ia..].to_vec());
    }
    if ib < b.len() {
        push(&mut segments, "B_ONLY", b[ib..].to_vec());
    }
    segments
}

pub fn compute_sequence_divergence(a: &[u16], b: &[u16]) -> SequenceDivergence {
    let mut prefix = 0usize;
    while prefix < a.len() && prefix < b.len() && a[prefix] == b[prefix] {
        prefix += 1;
    }
    let mut suffix = 0usize;
    while suffix < a.len().saturating_sub(prefix)
        && suffix < b.len().saturating_sub(prefix)
        && a[a.len() - 1 - suffix] == b[b.len() - 1 - suffix]
    {
        suffix += 1;
    }
    let (div_idx, ca, cb) = if prefix < a.len() || prefix < b.len() {
        (Some(prefix), a.get(prefix).copied(), b.get(prefix).copied())
    } else {
        (None, None, None)
    };
    SequenceDivergence {
        common_prefix_length: prefix,
        common_suffix_length: suffix,
        divergence_index: div_idx,
        capture_a_message: ca,
        capture_b_message: cb,
        label: CorrelationLabel::Observed,
    }
}

/// Compare consecutive observation payloads for identical value windows.
pub fn cross_message_value_correlations(
    pairs: &[(&MessageObservation, &MessageObservation)],
) -> Vec<CrossMessageValueCorrelation> {
    let mut hits: BTreeMap<(u16, u16, usize, usize, usize), u32> = BTreeMap::new();
    for (a, b) in pairs {
        if a.payload.is_empty() || b.payload.is_empty() {
            continue;
        }
        let max_w = 4.min(a.payload.len()).min(b.payload.len());
        for width in [2usize, 4] {
            if width > max_w {
                continue;
            }
            let starts_a = [0usize, a.payload.len().saturating_sub(width) / 2];
            let starts_b = [0usize, b.payload.len().saturating_sub(width) / 2];
            for &oa in &starts_a {
                if oa + width > a.payload.len() {
                    continue;
                }
                for &ob in &starts_b {
                    if ob + width > b.payload.len() {
                        continue;
                    }
                    if a.payload[oa..oa + width] == b.payload[ob..ob + width] {
                        *hits
                            .entry((a.message_id, b.message_id, oa, ob, width))
                            .or_insert(0) += 1;
                    }
                }
            }
        }
        if a.payload_len == b.payload_len && a.payload == b.payload && a.payload_len >= 2 {
            *hits
                .entry((a.message_id, b.message_id, 0, 0, a.payload_len.min(8)))
                .or_insert(0) += 1;
        }
    }
    hits.into_iter()
        .filter(|(_, c)| *c >= 2)
        .map(
            |((from_id, to_id, from_offset, to_offset, width), matching_pairs)| {
                CrossMessageValueCorrelation {
                    from_id,
                    to_id,
                    from_offset,
                    to_offset,
                    width,
                    matching_pairs,
                    candidate_correlation: true,
                    semantic_meaning: "UNKNOWN",
                    label: CorrelationLabel::Correlation,
                }
            },
        )
        .collect()
}

fn is_approximately_periodic(deltas: &[u64]) -> (bool, Option<f64>, Option<f64>) {
    if deltas.len() < 3 {
        return (false, None, None);
    }
    let stats = timing_stats(deltas, "frame_order");
    let median = stats.median.unwrap_or(0.0);
    if median <= 0.0 {
        return (false, Some(median), None);
    }
    let mut abs_dev = 0.0;
    for d in deltas {
        abs_dev += (*d as f64 - median).abs();
    }
    let jitter = abs_dev / deltas.len() as f64;
    let relative = jitter / median;
    let approx = relative <= 0.25;
    (approx, Some(median), Some(jitter))
}

/// Full cross-capture correlation analysis.
pub fn analyze_two_captures(
    a: &CaptureMessageInventory,
    b: &CaptureMessageInventory,
) -> CorrelationAnalysis {
    let seq_a = build_sequence(a);
    let seq_b = build_sequence(b);

    let mut all_ids: BTreeSet<u16> = BTreeSet::new();
    all_ids.extend(seq_a.unique_message_ids.iter().copied());
    all_ids.extend(seq_b.unique_message_ids.iter().copied());

    let mut ngram_map: BTreeMap<(u8, String), NgramRecord> = BTreeMap::new();
    for seq in [&seq_a, &seq_b] {
        for n in 1u8..=4 {
            for (ids, dirs, ctxs) in ngrams_for_observations(&seq.observations, n as usize) {
                let key = sequence_key(&ids);
                let entry = ngram_map
                    .entry((n, key.clone()))
                    .or_insert_with(|| NgramRecord {
                        n,
                        sequence: ids.clone(),
                        sequence_key: key,
                        occurrences: 0,
                        captures_seen: BTreeSet::new(),
                        direction_pattern: dirs.clone(),
                        context_pattern: ctxs.clone(),
                        classification: SequenceStability::Unknown,
                    });
                entry.occurrences += 1;
                entry.captures_seen.insert(seq.capture_id.clone());
                if entry.direction_pattern.is_empty() {
                    entry.direction_pattern = dirs;
                }
                if entry.context_pattern.is_empty() {
                    entry.context_pattern = ctxs;
                }
            }
        }
    }
    let mut ngrams: Vec<NgramRecord> = ngram_map.into_values().collect();
    for g in &mut ngrams {
        g.classification = match g.captures_seen.len() {
            2 if g.n >= 2 => SequenceStability::StableSequence,
            2 => SequenceStability::PartiallyStable,
            1 => SequenceStability::CaptureSpecific,
            _ => SequenceStability::Unknown,
        };
    }
    ngrams.sort_by(|x, y| {
        y.n.cmp(&x.n)
            .then(y.occurrences.cmp(&x.occurrences))
            .then(x.sequence_key.cmp(&y.sequence_key))
    });

    let mut stable_sequences: Vec<StableSubsequence> = ngrams
        .iter()
        .filter(|g| g.n >= 2 && g.captures_seen.len() == 2)
        .map(|g| {
            let occ_a = count_subsequence(&seq_a.message_ids, &g.sequence);
            let occ_b = count_subsequence(&seq_b.message_ids, &g.sequence);
            StableSubsequence {
                sequence: g.sequence.clone(),
                sequence_key: g.sequence_key.clone(),
                occurrences_a: occ_a,
                occurrences_b: occ_b,
                length: g.sequence.len(),
                classification: SequenceStability::StableSequence,
            }
        })
        .collect();
    stable_sequences
        .sort_by(|a, b| b.length.cmp(&a.length).then(a.sequence_key.cmp(&b.sequence_key)));
    stable_sequences.dedup_by(|a, b| a.sequence_key == b.sequence_key);

    let mut dir_map: BTreeMap<(u16, u16, String, String), DirectionTransition> = BTreeMap::new();
    let mut edge_deltas: BTreeMap<(u16, u16), Vec<u64>> = BTreeMap::new();
    let mut edge_meta: BTreeMap<
        (u16, u16),
        (
            BTreeSet<String>,
            BTreeMap<String, u32>,
            BTreeMap<String, u32>,
        ),
    > = BTreeMap::new();

    for seq in [&seq_a, &seq_b] {
        for w in seq.observations.windows(2) {
            let from = &w[0];
            let to = &w[1];
            let dk = (
                from.message_id,
                to.message_id,
                from.direction.clone(),
                to.direction.clone(),
            );
            let e = dir_map.entry(dk).or_insert_with(|| DirectionTransition {
                from_id: from.message_id,
                to_id: to.message_id,
                from_direction: from.direction.clone(),
                to_direction: to.direction.clone(),
                count: 0,
                captures_seen: BTreeSet::new(),
                label: CorrelationLabel::Correlation,
            });
            e.count += 1;
            e.captures_seen.insert(seq.capture_id.clone());

            let ek = (from.message_id, to.message_id);
            if let Some(d) = delta_between(from, to) {
                edge_deltas.entry(ek).or_default().push(d);
            }
            let meta = edge_meta
                .entry(ek)
                .or_insert_with(|| (BTreeSet::new(), BTreeMap::new(), BTreeMap::new()));
            meta.0.insert(seq.capture_id.clone());
            let dt = format!(
                "{}→{}",
                dir_short(&from.direction),
                dir_short(&to.direction)
            );
            *meta.1.entry(dt).or_insert(0) += 1;
            let ct = format!("{}→{}", from.context, to.context);
            *meta.2.entry(ct).or_insert(0) += 1;
        }
    }
    let mut direction_transitions: Vec<_> = dir_map.into_values().collect();
    direction_transitions.sort_by(|a, b| b.count.cmp(&a.count));

    let mut transition_edges = Vec::new();
    let mut edge_timing = BTreeMap::new();
    for ((from_id, to_id), (caps, dirs, ctxs)) in &edge_meta {
        let deltas = edge_deltas
            .get(&(*from_id, *to_id))
            .cloned()
            .unwrap_or_default();
        let stats = timing_stats(&deltas, "frame_order");
        let key = format!("{}→{}", fmt_msg_id(*from_id), fmt_msg_id(*to_id));
        edge_timing.insert(key, stats.clone());
        let dir_transition = dirs
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(k, _)| k.clone())
            .unwrap_or_default();
        let ctx_transition = ctxs
            .iter()
            .max_by_key(|(_, c)| *c)
            .map(|(k, _)| k.clone())
            .unwrap_or_default();
        let count: u32 = dirs.values().sum();
        let in_a = caps.contains(&seq_a.capture_id);
        let in_b = caps.contains(&seq_b.capture_id);
        let edge_class = classify_edge(*from_id, *to_id, &seq_a, &seq_b, in_a, in_b);
        transition_edges.push(TransitionEdge {
            from_id: *from_id,
            to_id: *to_id,
            count,
            captures_seen: caps.clone(),
            direction_transition: dir_transition,
            context_transition: ctx_transition,
            median_delta: stats.median,
            delta_unit: "frame_order",
            edge_class,
        });
    }
    transition_edges.sort_by(|a, b| b.count.cmp(&a.count).then(a.from_id.cmp(&b.from_id)));

    let request_response_candidates =
        build_rr_candidates(&direction_transitions, &transition_edges, &seq_a, &seq_b);

    let context_correlations = build_context_correlations(&seq_a, &seq_b);
    let context_transitions = build_context_transitions(&seq_a, &seq_b);
    let (fingerprint_repeats, payload_variations) = build_fingerprint_facts(&seq_a, &seq_b);

    let mut consec_pairs = Vec::new();
    for inv in [a, b] {
        let ordered = ordered_observations(inv);
        for w in ordered.windows(2) {
            consec_pairs.push((w[0], w[1]));
        }
    }
    let mut cross_message_correlations = cross_message_value_correlations(&consec_pairs);
    cross_message_correlations.sort_by(|x, y| y.matching_pairs.cmp(&x.matching_pairs));
    cross_message_correlations.truncate(64);

    let temporal_clusters = build_temporal_clusters(&seq_a, &seq_b);
    let periodic_candidates = build_periodic_candidates(&seq_a, &seq_b);
    let sequence_divergence = compute_sequence_divergence(&seq_a.message_ids, &seq_b.message_ids);
    let alignment = align_sequences(&seq_a.message_ids, &seq_b.message_ids);

    let external_references: Vec<ExternalNameRef> = all_ids
        .iter()
        .filter_map(|id| {
            lookup_name(*id).map(|name| ExternalNameRef {
                message_id: *id,
                external_reference: name,
                source: "messages.rs",
                label: CorrelationLabel::ExternalReference,
            })
        })
        .collect();

    CorrelationAnalysis {
        capture_a: seq_a.capture_id.clone(),
        capture_b: seq_b.capture_id.clone(),
        sequence_a: seq_a,
        sequence_b: seq_b,
        unique_message_ids: all_ids.into_iter().collect(),
        ngrams,
        stable_sequences,
        direction_transitions,
        request_response_candidates,
        context_correlations,
        context_transitions,
        fingerprint_repeats,
        payload_variations,
        cross_message_correlations,
        temporal_clusters,
        periodic_candidates,
        sequence_divergence,
        alignment,
        transition_edges,
        external_references,
        edge_timing,
    }
}

fn count_subsequence(hay: &[u16], needle: &[u16]) -> u32 {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    let mut c = 0u32;
    for w in hay.windows(needle.len()) {
        if w == needle {
            c += 1;
        }
    }
    c
}

fn classify_edge(
    from_id: u16,
    to_id: u16,
    seq_a: &MessageSequence,
    seq_b: &MessageSequence,
    in_a: bool,
    in_b: bool,
) -> EdgeClass {
    match (in_a, in_b) {
        (true, true) => {
            let dirs_a = majority_dir_pair(seq_a, from_id, to_id);
            let dirs_b = majority_dir_pair(seq_b, from_id, to_id);
            match (dirs_a, dirs_b) {
                (Some(da), Some(db)) if da == db => EdgeClass::StableEdge,
                (Some(_), Some(_)) => EdgeClass::DivergentEdge,
                _ => EdgeClass::StableEdge,
            }
        }
        _ => EdgeClass::CaptureSpecificEdge,
    }
}

fn majority_dir_pair(seq: &MessageSequence, from_id: u16, to_id: u16) -> Option<(String, String)> {
    let mut counts: BTreeMap<(String, String), u32> = BTreeMap::new();
    for w in seq.observations.windows(2) {
        if w[0].message_id == from_id && w[1].message_id == to_id {
            *counts
                .entry((w[0].direction.clone(), w[1].direction.clone()))
                .or_insert(0) += 1;
        }
    }
    counts.into_iter().max_by_key(|(_, c)| *c).map(|(k, _)| k)
}

fn build_rr_candidates(
    transitions: &[DirectionTransition],
    edges: &[TransitionEdge],
    seq_a: &MessageSequence,
    seq_b: &MessageSequence,
) -> Vec<RequestResponseCandidate> {
    let mut out = Vec::new();
    for t in transitions {
        if !opposite_dir(&t.from_direction, &t.to_direction) {
            continue;
        }
        let mut signals = Vec::new();
        signals.push("opposite_direction");
        if t.from_id.abs_diff(t.to_id) == 1 {
            signals.push("consecutive_ids");
        }
        if t.captures_seen.len() == 2 {
            signals.push("stable_across_captures");
        }
        if t.count >= 2 {
            signals.push("repeated");
        }
        let same_ctx = consecutive_same_context(seq_a, t.from_id, t.to_id)
            || consecutive_same_context(seq_b, t.from_id, t.to_id);
        if same_ctx {
            signals.push("compatible_context");
        }
        if length_consistent(seq_a, t.to_id) && length_consistent(seq_b, t.to_id) {
            signals.push("consistent_lengths");
        }
        let edge = edges
            .iter()
            .find(|e| e.from_id == t.from_id && e.to_id == t.to_id);
        if edge
            .map(|e| e.edge_class == EdgeClass::StableEdge)
            .unwrap_or(false)
        {
            signals.push("stable_edge");
        }
        if signals.len() < 3 {
            continue;
        }
        out.push(RequestResponseCandidate {
            request_id: t.from_id,
            response_id: t.to_id,
            request_direction: t.from_direction.clone(),
            response_direction: t.to_direction.clone(),
            occurrences: t.count,
            captures_seen: t.captures_seen.clone(),
            signals,
            candidate_type: "REQUEST_RESPONSE_CANDIDATE",
            confidence: CorrelationLabel::StructuralHypothesis,
            semantic_confirmation: CorrelationLabel::Unknown,
        });
    }
    out.sort_by(|a, b| b.occurrences.cmp(&a.occurrences));
    out.dedup_by(|a, b| a.request_id == b.request_id && a.response_id == b.response_id);
    out
}

fn consecutive_same_context(seq: &MessageSequence, from_id: u16, to_id: u16) -> bool {
    for w in seq.observations.windows(2) {
        if w[0].message_id == from_id && w[1].message_id == to_id && w[0].context == w[1].context
        {
            return true;
        }
    }
    false
}

fn length_consistent(seq: &MessageSequence, id: u16) -> bool {
    let lens: BTreeSet<usize> = seq
        .observations
        .iter()
        .filter(|o| o.message_id == id)
        .map(|o| o.payload_len)
        .collect();
    lens.len() <= 1
}

fn build_context_correlations(a: &MessageSequence, b: &MessageSequence) -> Vec<ContextCorrelation> {
    let mut map: BTreeMap<(u16, u32), ContextBucket> = BTreeMap::new();
    for seq in [a, b] {
        for o in &seq.observations {
            let e = map
                .entry((o.message_id, o.context))
                .or_insert_with(|| ContextBucket {
                    context: o.context,
                    captures: BTreeSet::new(),
                    directions: BTreeMap::new(),
                    lengths: BTreeMap::new(),
                    count: 0,
                });
            e.captures.insert(seq.capture_id.clone());
            *e.directions.entry(o.direction.clone()).or_insert(0) += 1;
            *e.lengths.entry(o.payload_len).or_insert(0) += 1;
            e.count += 1;
        }
    }
    let mut by_id: BTreeMap<u16, Vec<ContextBucket>> = BTreeMap::new();
    for ((id, _), bucket) in map {
        by_id.entry(id).or_default().push(bucket);
    }
    by_id
        .into_iter()
        .map(|(message_id, buckets)| {
            let contexts_seen: BTreeSet<u32> = buckets.iter().map(|b| b.context).collect();
            ContextCorrelation {
                message_id,
                contexts_seen,
                by_context: buckets,
                classification: CorrelationLabel::Observed,
            }
        })
        .collect()
}

fn build_context_transitions(a: &MessageSequence, b: &MessageSequence) -> Vec<ContextTransition> {
    let mut map: BTreeMap<(u32, u16, u32), ContextTransition> = BTreeMap::new();
    for seq in [a, b] {
        for w in seq.observations.windows(2) {
            if w[0].context == w[1].context {
                continue;
            }
            let key = (w[0].context, w[1].message_id, w[1].context);
            let e = map.entry(key).or_insert_with(|| ContextTransition {
                context_before: w[0].context,
                message_id: w[1].message_id,
                context_after: w[1].context,
                count: 0,
                captures_seen: BTreeSet::new(),
                label: CorrelationLabel::StructuralHypothesis,
            });
            e.count += 1;
            e.captures_seen.insert(seq.capture_id.clone());
        }
    }
    let mut v: Vec<_> = map.into_values().collect();
    v.sort_by(|a, b| b.count.cmp(&a.count));
    v.truncate(128);
    v
}

fn build_fingerprint_facts(
    a: &MessageSequence,
    b: &MessageSequence,
) -> (Vec<FingerprintRepeat>, Vec<PayloadVariation>) {
    let mut groups: BTreeMap<(u16, String, u32, String), FingerprintRepeat> = BTreeMap::new();
    for seq in [a, b] {
        for o in &seq.observations {
            let key = (
                o.message_id,
                o.direction.clone(),
                o.context,
                o.payload_fingerprint.clone(),
            );
            let e = groups.entry(key).or_insert_with(|| FingerprintRepeat {
                message_id: o.message_id,
                direction: o.direction.clone(),
                context: o.context,
                fingerprint: o.payload_fingerprint.clone(),
                repeat_count: 0,
                positions: Vec::new(),
                captures: BTreeSet::new(),
                label: CorrelationLabel::Observed,
            });
            e.repeat_count += 1;
            e.positions.push(o.frame_index);
            e.captures.insert(seq.capture_id.clone());
        }
    }
    let mut repeats: Vec<_> = groups
        .into_values()
        .filter(|r| r.repeat_count >= 2)
        .collect();
    repeats.sort_by(|a, b| b.repeat_count.cmp(&a.repeat_count));
    repeats.truncate(64);

    let mut var_map: BTreeMap<(u16, String, u32), BTreeSet<String>> = BTreeMap::new();
    let mut var_caps: BTreeMap<(u16, String, u32), BTreeSet<String>> = BTreeMap::new();
    for seq in [a, b] {
        for o in &seq.observations {
            let k = (o.message_id, o.direction.clone(), o.context);
            var_map
                .entry(k.clone())
                .or_default()
                .insert(o.payload_fingerprint.clone());
            var_caps
                .entry(k)
                .or_default()
                .insert(seq.capture_id.clone());
        }
    }
    let mut variations = Vec::new();
    for ((message_id, direction, context), fps) in var_map {
        if fps.len() > 1 {
            let caps = var_caps
                .get(&(message_id, direction.clone(), context))
                .cloned()
                .unwrap_or_default();
            variations.push(PayloadVariation {
                message_id,
                direction,
                context,
                distinct_fingerprints: fps.len(),
                captures_seen: caps,
                label: CorrelationLabel::Observed,
            });
        }
    }
    variations.sort_by(|a, b| b.distinct_fingerprints.cmp(&a.distinct_fingerprints));
    variations.truncate(64);
    (repeats, variations)
}

fn build_temporal_clusters(a: &MessageSequence, b: &MessageSequence) -> Vec<TemporalCluster> {
    let mut out = Vec::new();
    for seq in [a, b] {
        let ids = &seq.message_ids;
        let mut i = 0usize;
        while i + 3 < ids.len() {
            let x = ids[i];
            let y = ids[i + 1];
            if x == y {
                i += 1;
                continue;
            }
            let mut j = i;
            let mut count = 0usize;
            while j + 1 < ids.len() && ids[j] == x && ids[j + 1] == y {
                count += 1;
                j += 2;
            }
            if count >= 3 {
                let mut intervals = Vec::new();
                for k in 0..count.saturating_sub(1) {
                    let ia = i + k * 2;
                    let ib = i + (k + 1) * 2;
                    if let (Some(o0), Some(o1)) =
                        (seq.observations.get(ia), seq.observations.get(ib))
                    {
                        if let Some(d) = delta_between(o0, o1) {
                            intervals.push(d);
                        }
                    }
                }
                let mut caps = BTreeSet::new();
                caps.insert(seq.capture_id.clone());
                out.push(TemporalCluster {
                    message_ids: vec![x, y],
                    cluster_size: count,
                    intervals: timing_stats(&intervals, "frame_order"),
                    pattern_key: sequence_key(&[x, y]),
                    captures_seen: caps,
                    label: CorrelationLabel::Observed,
                });
                i = j;
            } else {
                i += 1;
            }
        }
    }
    let mut merged: BTreeMap<String, TemporalCluster> = BTreeMap::new();
    for c in out {
        let e = merged
            .entry(c.pattern_key.clone())
            .or_insert_with(|| TemporalCluster {
                message_ids: c.message_ids.clone(),
                cluster_size: 0,
                intervals: TimingStats {
                    sample_count: 0,
                    min: None,
                    max: None,
                    mean: None,
                    median: None,
                    unit: "frame_order",
                },
                pattern_key: c.pattern_key.clone(),
                captures_seen: BTreeSet::new(),
                label: CorrelationLabel::Observed,
            });
        e.cluster_size += c.cluster_size;
        e.captures_seen.extend(c.captures_seen);
    }
    merged.into_values().collect()
}

fn build_periodic_candidates(a: &MessageSequence, b: &MessageSequence) -> Vec<PeriodicCandidate> {
    let mut out = Vec::new();
    let ids_of_interest: BTreeSet<u16> = [0xFA, 0xFB, 0x79, 0x7A]
        .into_iter()
        .chain(a.unique_message_ids.iter().copied())
        .chain(b.unique_message_ids.iter().copied())
        .collect();

    for id in ids_of_interest {
        let mut deltas = Vec::new();
        for seq in [a, b] {
            let positions: Vec<&MessageCorrelationObservation> = seq
                .observations
                .iter()
                .filter(|o| o.message_id == id)
                .collect();
            for w in positions.windows(2) {
                if let Some(d) = delta_between(w[0], w[1]) {
                    deltas.push(d);
                }
            }
        }
        if deltas.len() < 3 {
            continue;
        }
        let (approx, median, jitter) = is_approximately_periodic(&deltas);
        if !approx && deltas.len() < 5 {
            continue;
        }
        out.push(PeriodicCandidate {
            message_id: id,
            paired_id: None,
            periodic_candidate: approx,
            approximately_periodic: approx,
            median_interval: median,
            jitter,
            sample_count: deltas.len() as u32,
            unit: "frame_order",
            label: if approx {
                CorrelationLabel::StructuralHypothesis
            } else {
                CorrelationLabel::Unknown
            },
            external_reference: lookup_name(id),
        });
    }

    let mut deltas = Vec::new();
    for seq in [a, b] {
        let starts: Vec<usize> = seq
            .observations
            .windows(2)
            .enumerate()
            .filter_map(|(i, w)| {
                if w[0].message_id == 0xFA && w[1].message_id == 0xFB {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();
        for w in starts.windows(2) {
            let o0 = &seq.observations[w[0]];
            let o1 = &seq.observations[w[1]];
            if let Some(d) = delta_between(o0, o1) {
                deltas.push(d);
            }
        }
    }
    if deltas.len() >= 3 {
        let (approx, median, jitter) = is_approximately_periodic(&deltas);
        out.push(PeriodicCandidate {
            message_id: 0xFA,
            paired_id: Some(0xFB),
            periodic_candidate: approx,
            approximately_periodic: approx,
            median_interval: median,
            jitter,
            sample_count: deltas.len() as u32,
            unit: "frame_order",
            label: CorrelationLabel::StructuralHypothesis,
            external_reference: lookup_name(0xFA),
        });
    }
    out
}

/// Safe export (no payload bytes / secrets).
#[derive(Debug, Clone, Serialize)]
pub struct SafeCorrelationExport {
    pub capture_a: String,
    pub capture_b: String,
    pub message_counts: BTreeMap<String, u32>,
    pub unique_message_ids: Vec<String>,
    pub sequence_lengths: BTreeMap<String, usize>,
    pub ngrams: Vec<SafeNgram>,
    pub stable_sequences: Vec<SafeSubseq>,
    pub transition_edges: Vec<SafeEdge>,
    pub stable_edges: Vec<String>,
    pub capture_specific_edges: Vec<String>,
    pub divergent_edges: Vec<String>,
    pub timing_statistics: BTreeMap<String, TimingStats>,
    pub context_transitions: Vec<SafeCtxTrans>,
    pub context_correlations: Vec<SafeCtxCorr>,
    pub request_response_candidates: Vec<SafeRr>,
    pub fingerprint_repeats: Vec<SafeFpRepeat>,
    pub payload_variations: Vec<SafePayloadVar>,
    pub cross_message_correlations: Vec<SafeCrossMsg>,
    pub periodic_candidates: Vec<SafePeriodic>,
    pub temporal_clusters: Vec<SafeCluster>,
    pub sequence_divergence: SequenceDivergence,
    pub alignment_summary: Vec<SafeAlign>,
    pub external_references: Vec<SafeExt>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeNgram {
    pub n: u8,
    pub sequence: String,
    pub occurrences: u32,
    pub captures: usize,
    pub classification: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeSubseq {
    pub sequence: String,
    pub occurrences_a: u32,
    pub occurrences_b: u32,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeEdge {
    pub edge: String,
    pub count: u32,
    pub captures: usize,
    pub direction_transition: String,
    pub median_delta: Option<f64>,
    pub edge_class: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeCtxTrans {
    pub context_before: u32,
    pub message_id: String,
    pub context_after: u32,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeCtxCorr {
    pub message_id: String,
    pub contexts: Vec<u32>,
    pub classification: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeRr {
    pub request_id: String,
    pub response_id: String,
    pub occurrences: u32,
    pub signals: Vec<&'static str>,
    pub candidate_type: &'static str,
    pub confidence: &'static str,
    pub semantic_confirmation: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeFpRepeat {
    pub message_id: String,
    pub direction: String,
    pub context: u32,
    pub fingerprint_prefix: String,
    pub repeat_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafePayloadVar {
    pub message_id: String,
    pub direction: String,
    pub context: u32,
    pub distinct_fingerprints: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeCrossMsg {
    pub from_id: String,
    pub to_id: String,
    pub from_offset: usize,
    pub to_offset: usize,
    pub width: usize,
    pub matching_pairs: u32,
    pub semantic_meaning: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafePeriodic {
    pub message_id: String,
    pub paired_id: Option<String>,
    pub approximately_periodic: bool,
    pub median_interval: Option<f64>,
    pub jitter: Option<f64>,
    pub unit: &'static str,
    pub external_reference: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeCluster {
    pub pattern: String,
    pub cluster_size: usize,
    pub captures: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeAlign {
    pub kind: &'static str,
    pub message_ids: String,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeExt {
    pub message_id: String,
    pub external_reference: &'static str,
    pub source: &'static str,
}

pub fn to_safe_export(a: &CorrelationAnalysis) -> SafeCorrelationExport {
    let mut message_counts = BTreeMap::new();
    message_counts.insert(a.capture_a.clone(), a.sequence_a.sequence_length as u32);
    message_counts.insert(a.capture_b.clone(), a.sequence_b.sequence_length as u32);

    let mut sequence_lengths = BTreeMap::new();
    sequence_lengths.insert(a.capture_a.clone(), a.sequence_a.sequence_length);
    sequence_lengths.insert(a.capture_b.clone(), a.sequence_b.sequence_length);

    let stable_edges: Vec<String> = a
        .transition_edges
        .iter()
        .filter(|e| e.edge_class == EdgeClass::StableEdge)
        .map(|e| format!("{}→{}", fmt_msg_id(e.from_id), fmt_msg_id(e.to_id)))
        .collect();
    let capture_specific_edges: Vec<String> = a
        .transition_edges
        .iter()
        .filter(|e| e.edge_class == EdgeClass::CaptureSpecificEdge)
        .map(|e| format!("{}→{}", fmt_msg_id(e.from_id), fmt_msg_id(e.to_id)))
        .collect();
    let divergent_edges: Vec<String> = a
        .transition_edges
        .iter()
        .filter(|e| e.edge_class == EdgeClass::DivergentEdge)
        .map(|e| format!("{}→{}", fmt_msg_id(e.from_id), fmt_msg_id(e.to_id)))
        .collect();

    // Cap timing map size for versioned export.
    let mut timing_statistics = BTreeMap::new();
    for (k, v) in a.edge_timing.iter().take(64) {
        timing_statistics.insert(k.clone(), v.clone());
    }

    SafeCorrelationExport {
        capture_a: a.capture_a.clone(),
        capture_b: a.capture_b.clone(),
        message_counts,
        unique_message_ids: a
            .unique_message_ids
            .iter()
            .map(|id| fmt_msg_id(*id))
            .collect(),
        sequence_lengths,
        ngrams: a
            .ngrams
            .iter()
            .filter(|g| g.n >= 2)
            .take(128)
            .map(|g| SafeNgram {
                n: g.n,
                sequence: g.sequence_key.clone(),
                occurrences: g.occurrences,
                captures: g.captures_seen.len(),
                classification: g.classification.as_str(),
            })
            .collect(),
        stable_sequences: a
            .stable_sequences
            .iter()
            .take(64)
            .map(|s| SafeSubseq {
                sequence: s.sequence_key.clone(),
                occurrences_a: s.occurrences_a,
                occurrences_b: s.occurrences_b,
                length: s.length,
            })
            .collect(),
        transition_edges: a
            .transition_edges
            .iter()
            .take(128)
            .map(|e| SafeEdge {
                edge: format!("{}→{}", fmt_msg_id(e.from_id), fmt_msg_id(e.to_id)),
                count: e.count,
                captures: e.captures_seen.len(),
                direction_transition: e.direction_transition.clone(),
                median_delta: e.median_delta,
                edge_class: e.edge_class.as_str(),
            })
            .collect(),
        stable_edges,
        capture_specific_edges,
        divergent_edges,
        timing_statistics,
        context_transitions: a
            .context_transitions
            .iter()
            .take(64)
            .map(|t| SafeCtxTrans {
                context_before: t.context_before,
                message_id: fmt_msg_id(t.message_id),
                context_after: t.context_after,
                count: t.count,
            })
            .collect(),
        context_correlations: a
            .context_correlations
            .iter()
            .map(|c| SafeCtxCorr {
                message_id: fmt_msg_id(c.message_id),
                contexts: c.contexts_seen.iter().copied().collect(),
                classification: c.classification.as_str(),
            })
            .collect(),
        request_response_candidates: a
            .request_response_candidates
            .iter()
            .map(|r| SafeRr {
                request_id: fmt_msg_id(r.request_id),
                response_id: fmt_msg_id(r.response_id),
                occurrences: r.occurrences,
                signals: r.signals.clone(),
                candidate_type: r.candidate_type,
                confidence: r.confidence.as_str(),
                semantic_confirmation: r.semantic_confirmation.as_str(),
            })
            .collect(),
        fingerprint_repeats: a
            .fingerprint_repeats
            .iter()
            .take(64)
            .map(|r| SafeFpRepeat {
                message_id: fmt_msg_id(r.message_id),
                direction: r.direction.clone(),
                context: r.context,
                fingerprint_prefix: r.fingerprint.chars().take(16).collect(),
                repeat_count: r.repeat_count,
            })
            .collect(),
        payload_variations: a
            .payload_variations
            .iter()
            .take(64)
            .map(|v| SafePayloadVar {
                message_id: fmt_msg_id(v.message_id),
                direction: v.direction.clone(),
                context: v.context,
                distinct_fingerprints: v.distinct_fingerprints,
            })
            .collect(),
        cross_message_correlations: a
            .cross_message_correlations
            .iter()
            .take(64)
            .map(|c| SafeCrossMsg {
                from_id: fmt_msg_id(c.from_id),
                to_id: fmt_msg_id(c.to_id),
                from_offset: c.from_offset,
                to_offset: c.to_offset,
                width: c.width,
                matching_pairs: c.matching_pairs,
                semantic_meaning: c.semantic_meaning,
            })
            .collect(),
        periodic_candidates: a
            .periodic_candidates
            .iter()
            .map(|p| SafePeriodic {
                message_id: fmt_msg_id(p.message_id),
                paired_id: p.paired_id.map(fmt_msg_id),
                approximately_periodic: p.approximately_periodic,
                median_interval: p.median_interval,
                jitter: p.jitter,
                unit: p.unit,
                external_reference: p.external_reference,
            })
            .collect(),
        temporal_clusters: a
            .temporal_clusters
            .iter()
            .map(|c| SafeCluster {
                pattern: c.pattern_key.clone(),
                cluster_size: c.cluster_size,
                captures: c.captures_seen.len(),
            })
            .collect(),
        sequence_divergence: a.sequence_divergence.clone(),
        alignment_summary: a
            .alignment
            .iter()
            .take(64)
            .map(|s| SafeAlign {
                kind: s.kind,
                message_ids: sequence_key(&s.message_ids),
                length: s.message_ids.len(),
            })
            .collect(),
        external_references: a
            .external_references
            .iter()
            .map(|e| SafeExt {
                message_id: fmt_msg_id(e.message_id),
                external_reference: e.external_reference,
                source: e.source,
            })
            .collect(),
    }
}
