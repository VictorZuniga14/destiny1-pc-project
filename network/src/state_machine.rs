//! Observational BAP protocol state machine (M3.4).
//!
//! Represents what captures demonstrate — not semantic guesses.
//! Labels: OBSERVED / STRUCTURAL_HYPOTHESIS / EXTERNAL_REFERENCE / UNKNOWN.

use crate::message_correlation::{
    analyze_two_captures, ordered_observations, CorrelationAnalysis,
};
use crate::message_inventory::{fmt_msg_id, CaptureMessageInventory, MessageObservation};
use crate::messages::lookup_name;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Stable startup message-ID sequence observed across verified captures.
pub const STABLE_STARTUP_SEQUENCE: &[u16] = &[
    0x1E, 0x1F, 0x19, 0x1A, 0x79, 0x7A, 0x12E, 0x12F,
];

pub const STATE_START: &str = "START";
pub const STATE_STARTUP_SEQUENCE: &str = "STARTUP_SEQUENCE";
pub const STATE_POST_STARTUP: &str = "POST_STARTUP";
pub const STATE_REPEATING_CLUSTER_01: &str = "REPEATING_CLUSTER_01";
pub const STATE_BRANCH_A: &str = "BRANCH_CAPTURE_A_01";
pub const STATE_BRANCH_B: &str = "BRANCH_CAPTURE_B_01";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StateClassification {
    Observed,
    StructuralHypothesis,
    ExternalReference,
    Unknown,
    StableCrossCapture,
    CaptureSpecific,
    Divergent,
}

impl StateClassification {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "OBSERVED",
            Self::StructuralHypothesis => "STRUCTURAL_HYPOTHESIS",
            Self::ExternalReference => "EXTERNAL_REFERENCE",
            Self::Unknown => "UNKNOWN",
            Self::StableCrossCapture => "STABLE_CROSS_CAPTURE",
            Self::CaptureSpecific => "CAPTURE_SPECIFIC",
            Self::Divergent => "DIVERGENT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StateObservation {
    pub capture_id: String,
    pub state_id: String,
    pub first_frame: u32,
    pub last_frame: u32,
    pub message_count: u32,
    pub repeating: bool,
    pub periodicity: &'static str,
    pub classification: StateClassification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StateTransition {
    pub from_state: String,
    pub to_state: String,
    pub message_id: u16,
    pub direction: String,
    pub context: u32,
    pub occurrences: u32,
    pub captures_seen: BTreeSet<String>,
    pub classification: StateClassification,
    pub request_response_candidate: bool,
    pub semantic_status: StateClassification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StateTraceEntry {
    pub frame_index: u32,
    pub message_id: u16,
    pub direction: String,
    pub context: u32,
    pub from_state: String,
    pub to_state: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StartupSequenceEvidence {
    pub sequence: Vec<u16>,
    pub sequence_key: String,
    pub capture_a_observed: bool,
    pub capture_b_observed: bool,
    pub common_prefix: bool,
    pub matched_prefix_len_a: usize,
    pub matched_prefix_len_b: usize,
    pub classification: StateClassification,
    pub structural_label: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct BranchEvidence {
    pub divergence_index: Option<usize>,
    pub message_a: Option<u16>,
    pub message_b: Option<u16>,
    pub branch_a_state: String,
    pub branch_b_state: String,
    pub classification: StateClassification,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepeatingClusterEvidence {
    pub state_id: String,
    pub message_ids: Vec<u16>,
    pub repeating: bool,
    pub periodicity: &'static str,
    pub captures_seen: BTreeSet<String>,
    pub classification: StateClassification,
    pub external_reference: Option<&'static str>,
    pub external_source: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemanticEvidenceRow {
    pub message_id: String,
    pub observed_behavior: String,
    pub structural_role: String,
    pub external_reference: Option<&'static str>,
    pub semantic_confidence: StateClassification,
    pub unknowns: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExternalSemantic {
    pub message_id: String,
    pub external_name: &'static str,
    pub source: &'static str,
    pub label: StateClassification,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolStateGraph {
    pub nodes: Vec<String>,
    pub edges: Vec<StateTransition>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolStateMachine {
    pub capture_a: String,
    pub capture_b: String,
    pub states: Vec<StateObservation>,
    pub graph: ProtocolStateGraph,
    pub startup: StartupSequenceEvidence,
    pub branches: BranchEvidence,
    pub repeating_cluster: RepeatingClusterEvidence,
    pub context_transitions: Vec<ContextTransitionNote>,
    pub request_response_candidates: Vec<RrNote>,
    pub semantic_matrix: Vec<SemanticEvidenceRow>,
    pub external_semantics: Vec<ExternalSemantic>,
    pub traces: BTreeMap<String, Vec<StateTraceEntry>>,
    pub unknowns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContextTransitionNote {
    pub context_before: u32,
    pub message_id: u16,
    pub context_after: u32,
    pub count: u32,
    pub classification: StateClassification,
}

#[derive(Debug, Clone, Serialize)]
pub struct RrNote {
    pub request_id: u16,
    pub response_id: u16,
    pub request_response_candidate: bool,
    pub confidence: &'static str,
    pub semantic_status: StateClassification,
}

fn sequence_key(ids: &[u16]) -> String {
    ids.iter()
        .map(|id| fmt_msg_id(*id))
        .collect::<Vec<_>>()
        .join("→")
}

/// How many leading IDs match [`STABLE_STARTUP_SEQUENCE`].
pub fn startup_prefix_len(ids: &[u16]) -> usize {
    let mut n = 0;
    while n < STABLE_STARTUP_SEQUENCE.len() && n < ids.len() && ids[n] == STABLE_STARTUP_SEQUENCE[n]
    {
        n += 1;
    }
    n
}

fn dir_short(d: &str) -> &str {
    match d {
        "client_to_server" => "C2S",
        "server_to_client" => "S2C",
        other => other,
    }
}

fn is_cluster_member(id: u16) -> bool {
    id == 0xFA || id == 0xFB
}

/// Deterministic per-capture state replay.
///
/// `branch_after`: if `Some(idx)`, frames with `frame_index >= idx` use the
/// capture-specific branch state instead of plain `POST_STARTUP` (when not in
/// the repeating cluster).
pub fn replay_state_trace(
    observations: &[&MessageObservation],
    branch_after: Option<(usize, &str)>,
) -> Vec<StateTraceEntry> {
    let ids: Vec<u16> = observations.iter().map(|o| o.message_id).collect();
    let startup_len = startup_prefix_len(&ids);
    let mut out = Vec::with_capacity(observations.len());
    let mut current = STATE_START.to_string();

    for (i, o) in observations.iter().enumerate() {
        let from = current.clone();
        let to = next_state(i, o.message_id, &from, startup_len, branch_after);
        out.push(StateTraceEntry {
            frame_index: o.frame_index,
            message_id: o.message_id,
            direction: o.direction.clone(),
            context: o.context,
            from_state: from,
            to_state: to.clone(),
        });
        current = to;
    }
    out
}

fn next_state(
    index: usize,
    message_id: u16,
    current: &str,
    startup_len: usize,
    branch_after: Option<(usize, &str)>,
) -> String {
    if index < startup_len {
        return STATE_STARTUP_SEQUENCE.to_string();
    }

    if is_cluster_member(message_id) {
        return STATE_REPEATING_CLUSTER_01.to_string();
    }

    if current == STATE_REPEATING_CLUSTER_01 && !is_cluster_member(message_id) {
        if let Some((div, branch)) = branch_after {
            if index >= div {
                return branch.to_string();
            }
        }
        return STATE_POST_STARTUP.to_string();
    }

    if let Some((div, branch)) = branch_after {
        if index >= div {
            return branch.to_string();
        }
    }

    if current == STATE_STARTUP_SEQUENCE || current == STATE_START {
        return STATE_POST_STARTUP.to_string();
    }
    current.to_string()
}

fn aggregate_states(capture_id: &str, trace: &[StateTraceEntry]) -> Vec<StateObservation> {
    let mut map: BTreeMap<String, (u32, u32, u32)> = BTreeMap::new();
    for e in trace {
        let entry = map
            .entry(e.to_state.clone())
            .or_insert((e.frame_index, e.frame_index, 0));
        entry.0 = entry.0.min(e.frame_index);
        entry.1 = entry.1.max(e.frame_index);
        entry.2 += 1;
    }
    map.into_iter()
        .map(|(state_id, (first, last, count))| {
            let repeating = state_id == STATE_REPEATING_CLUSTER_01;
            StateObservation {
                capture_id: capture_id.to_string(),
                state_id,
                first_frame: first,
                last_frame: last,
                message_count: count,
                repeating,
                periodicity: if repeating { "UNKNOWN" } else { "n/a" },
                classification: StateClassification::Observed,
            }
        })
        .collect()
}

fn collect_transitions(
    capture_id: &str,
    trace: &[StateTraceEntry],
    rr_pairs: &BTreeSet<(u16, u16)>,
) -> Vec<StateTransition> {
    let mut map: BTreeMap<(String, String, u16, String, u32), StateTransition> = BTreeMap::new();
    for e in trace {
        let key = (
            e.from_state.clone(),
            e.to_state.clone(),
            e.message_id,
            e.direction.clone(),
            e.context,
        );
        let entry = map.entry(key).or_insert_with(|| StateTransition {
            from_state: e.from_state.clone(),
            to_state: e.to_state.clone(),
            message_id: e.message_id,
            direction: e.direction.clone(),
            context: e.context,
            occurrences: 0,
            captures_seen: BTreeSet::new(),
            classification: StateClassification::Observed,
            request_response_candidate: false,
            semantic_status: StateClassification::Unknown,
        });
        entry.occurrences += 1;
        entry.captures_seen.insert(capture_id.to_string());
        entry.request_response_candidate = rr_pairs
            .iter()
            .any(|(req, resp)| e.message_id == *req || e.message_id == *resp);
        entry.semantic_status = StateClassification::Unknown;
    }
    map.into_values().collect()
}

fn merge_transitions(mut edges: Vec<StateTransition>) -> Vec<StateTransition> {
    let mut map: BTreeMap<(String, String, u16, String), StateTransition> = BTreeMap::new();
    for e in edges.drain(..) {
        let key = (
            e.from_state.clone(),
            e.to_state.clone(),
            e.message_id,
            e.direction.clone(),
        );
        let entry = map.entry(key).or_insert_with(|| StateTransition {
            from_state: e.from_state.clone(),
            to_state: e.to_state.clone(),
            message_id: e.message_id,
            direction: e.direction.clone(),
            context: e.context,
            occurrences: 0,
            captures_seen: BTreeSet::new(),
            classification: e.classification,
            request_response_candidate: e.request_response_candidate,
            semantic_status: StateClassification::Unknown,
        });
        entry.occurrences += e.occurrences;
        entry.captures_seen.extend(e.captures_seen);
        entry.request_response_candidate |= e.request_response_candidate;
    }
    let mut out: Vec<_> = map.into_values().collect();
    for e in &mut out {
        e.classification = match e.captures_seen.len() {
            2 => StateClassification::StableCrossCapture,
            1 => StateClassification::CaptureSpecific,
            _ => StateClassification::Unknown,
        };
    }
    out.sort_by(|a, b| {
        b.occurrences
            .cmp(&a.occurrences)
            .then(a.from_state.cmp(&b.from_state))
            .then(a.message_id.cmp(&b.message_id))
    });
    out
}

fn build_semantic_matrix(
    corr: &CorrelationAnalysis,
    startup_ids: &[u16],
) -> Vec<SemanticEvidenceRow> {
    let mut rows = Vec::new();
    let startup_set: BTreeSet<u16> = startup_ids.iter().copied().collect();
    for id in &corr.unique_message_ids {
        let ext = lookup_name(*id);
        let in_startup = startup_set.contains(id);
        let dirs: BTreeSet<String> = corr
            .sequence_a
            .observations
            .iter()
            .chain(corr.sequence_b.observations.iter())
            .filter(|o| o.message_id == *id)
            .map(|o| dir_short(&o.direction).to_string())
            .collect();
        let observed = format!(
            "dirs={}",
            dirs.into_iter().collect::<Vec<_>>().join(",")
        );
        let structural = if in_startup {
            "startup sequence member".to_string()
        } else if *id == 0xFA || *id == 0xFB {
            "repeating cluster member".to_string()
        } else {
            "post-startup / branch activity".to_string()
        };
        let semantic = if ext.is_some() {
            StateClassification::ExternalReference
        } else {
            StateClassification::Unknown
        };
        rows.push(SemanticEvidenceRow {
            message_id: fmt_msg_id(*id),
            observed_behavior: observed,
            structural_role: structural,
            external_reference: ext,
            semantic_confidence: semantic,
            unknowns: "exact payload semantics".into(),
        });
    }
    rows
}

/// Build observational state machine from two capture inventories.
pub fn build_state_machine(
    a: &CaptureMessageInventory,
    b: &CaptureMessageInventory,
) -> ProtocolStateMachine {
    let corr = analyze_two_captures(a, b);
    let obs_a = ordered_observations(a);
    let obs_b = ordered_observations(b);
    let ids_a: Vec<u16> = obs_a.iter().map(|o| o.message_id).collect();
    let ids_b: Vec<u16> = obs_b.iter().map(|o| o.message_id).collect();

    let pref_a = startup_prefix_len(&ids_a);
    let pref_b = startup_prefix_len(&ids_b);
    let full = STABLE_STARTUP_SEQUENCE.len();
    let startup = StartupSequenceEvidence {
        sequence: STABLE_STARTUP_SEQUENCE.to_vec(),
        sequence_key: sequence_key(STABLE_STARTUP_SEQUENCE),
        capture_a_observed: pref_a == full,
        capture_b_observed: pref_b == full,
        common_prefix: pref_a.min(pref_b) > 0,
        matched_prefix_len_a: pref_a,
        matched_prefix_len_b: pref_b,
        classification: if pref_a == full && pref_b == full {
            StateClassification::Observed
        } else if pref_a.min(pref_b) > 0 {
            StateClassification::StructuralHypothesis
        } else {
            StateClassification::Unknown
        },
        structural_label: "STABLE_STARTUP_SEQUENCE",
    };

    let div = &corr.sequence_divergence;
    let branches = BranchEvidence {
        divergence_index: div.divergence_index,
        message_a: div.capture_a_message,
        message_b: div.capture_b_message,
        branch_a_state: STATE_BRANCH_A.to_string(),
        branch_b_state: STATE_BRANCH_B.to_string(),
        classification: if div.divergence_index.is_some() {
            StateClassification::Observed
        } else {
            StateClassification::Unknown
        },
    };

    let rr_pairs: BTreeSet<(u16, u16)> = corr
        .request_response_candidates
        .iter()
        .map(|r| (r.request_id, r.response_id))
        .collect();

    let branch_a = div.divergence_index.map(|i| (i, STATE_BRANCH_A));
    let branch_b = div.divergence_index.map(|i| (i, STATE_BRANCH_B));

    let trace_a = replay_state_trace(&obs_a, branch_a);
    let trace_b = replay_state_trace(&obs_b, branch_b);

    let mut states = aggregate_states(&a.capture_id, &trace_a);
    states.extend(aggregate_states(&b.capture_id, &trace_b));

    let mut edges = collect_transitions(&a.capture_id, &trace_a, &rr_pairs);
    edges.extend(collect_transitions(&b.capture_id, &trace_b, &rr_pairs));
    let edges = merge_transitions(edges);

    let fa_ext = lookup_name(0xFA);
    let mut cluster_caps = BTreeSet::new();
    if trace_a
        .iter()
        .any(|e| e.to_state == STATE_REPEATING_CLUSTER_01)
    {
        cluster_caps.insert(a.capture_id.clone());
    }
    if trace_b
        .iter()
        .any(|e| e.to_state == STATE_REPEATING_CLUSTER_01)
    {
        cluster_caps.insert(b.capture_id.clone());
    }
    let approx = corr
        .periodic_candidates
        .iter()
        .any(|p| p.message_id == 0xFA && p.approximately_periodic);
    let repeating_cluster = RepeatingClusterEvidence {
        state_id: STATE_REPEATING_CLUSTER_01.to_string(),
        message_ids: vec![0xFA, 0xFB],
        repeating: true,
        periodicity: if approx { "APPROXIMATE" } else { "UNKNOWN" },
        captures_seen: cluster_caps,
        classification: StateClassification::Observed,
        external_reference: fa_ext,
        external_source: fa_ext.map(|_| "messages.rs"),
    };

    let context_transitions: Vec<ContextTransitionNote> = corr
        .context_transitions
        .iter()
        .take(64)
        .map(|t| ContextTransitionNote {
            context_before: t.context_before,
            message_id: t.message_id,
            context_after: t.context_after,
            count: t.count,
            classification: StateClassification::StructuralHypothesis,
        })
        .collect();

    let request_response_candidates: Vec<RrNote> = corr
        .request_response_candidates
        .iter()
        .map(|r| RrNote {
            request_id: r.request_id,
            response_id: r.response_id,
            request_response_candidate: true,
            confidence: r.confidence.as_str(),
            semantic_status: StateClassification::Unknown,
        })
        .collect();

    let external_semantics: Vec<ExternalSemantic> = corr
        .external_references
        .iter()
        .map(|e| ExternalSemantic {
            message_id: fmt_msg_id(e.message_id),
            external_name: e.external_reference,
            source: e.source,
            label: StateClassification::ExternalReference,
        })
        .collect();

    let semantic_matrix = build_semantic_matrix(&corr, STABLE_STARTUP_SEQUENCE);

    let mut nodes: BTreeSet<String> = BTreeSet::new();
    nodes.insert(STATE_START.to_string());
    nodes.insert(STATE_STARTUP_SEQUENCE.to_string());
    nodes.insert(STATE_POST_STARTUP.to_string());
    nodes.insert(STATE_REPEATING_CLUSTER_01.to_string());
    nodes.insert(STATE_BRANCH_A.to_string());
    nodes.insert(STATE_BRANCH_B.to_string());
    for e in &edges {
        nodes.insert(e.from_state.clone());
        nodes.insert(e.to_state.clone());
    }

    let mut traces = BTreeMap::new();
    traces.insert(a.capture_id.clone(), trace_a);
    traces.insert(b.capture_id.clone(), trace_b);

    let unknowns = vec![
        "exact payload field semantics".into(),
        "authenticated / login semantic confirmation".into(),
        "keepalive wall-clock period".into(),
        "meaning of context values".into(),
        "gameplay / activity / inventory role of post-startup messages".into(),
    ];

    ProtocolStateMachine {
        capture_a: a.capture_id.clone(),
        capture_b: b.capture_id.clone(),
        states,
        graph: ProtocolStateGraph {
            nodes: nodes.into_iter().collect(),
            edges,
        },
        startup,
        branches,
        repeating_cluster,
        context_transitions,
        request_response_candidates,
        semantic_matrix,
        external_semantics,
        traces,
        unknowns,
    }
}

/// Safe versioned export (no secrets / no payload bytes).
#[derive(Debug, Clone, Serialize)]
pub struct SafeStateMachineExport {
    pub capture_a: String,
    pub capture_b: String,
    pub nodes: Vec<String>,
    pub states: Vec<SafeStateObs>,
    pub transitions: Vec<SafeTransition>,
    pub startup: SafeStartup,
    pub branches: SafeBranch,
    pub repeating_cluster: SafeCluster,
    pub context_transitions: Vec<SafeCtx>,
    pub request_response_candidates: Vec<SafeRr>,
    pub semantic_matrix: Vec<SafeSem>,
    pub external_semantics: Vec<SafeExt>,
    pub unknowns: Vec<String>,
    pub trace_lengths: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeStateObs {
    pub capture_id: String,
    pub state_id: String,
    pub first_frame: u32,
    pub last_frame: u32,
    pub message_count: u32,
    pub repeating: bool,
    pub periodicity: &'static str,
    pub classification: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeTransition {
    pub from: String,
    pub to: String,
    pub message_id: String,
    pub direction: String,
    pub context: u32,
    pub count: u32,
    pub captures: usize,
    pub classification: &'static str,
    pub request_response_candidate: bool,
    pub semantic_status: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeStartup {
    pub sequence: String,
    pub capture_a_observed: bool,
    pub capture_b_observed: bool,
    pub common_prefix: bool,
    pub classification: &'static str,
    pub structural_label: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeBranch {
    pub divergence_index: Option<usize>,
    pub message_a: Option<String>,
    pub message_b: Option<String>,
    pub branch_a_state: String,
    pub branch_b_state: String,
    pub classification: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeCluster {
    pub state_id: String,
    pub message_ids: Vec<String>,
    pub repeating: bool,
    pub periodicity: &'static str,
    pub captures: usize,
    pub classification: &'static str,
    pub external_reference: Option<&'static str>,
    pub external_source: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeCtx {
    pub context_before: u32,
    pub message_id: String,
    pub context_after: u32,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeRr {
    pub request_id: String,
    pub response_id: String,
    pub request_response_candidate: bool,
    pub confidence: &'static str,
    pub semantic_status: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeSem {
    pub message_id: String,
    pub observed_behavior: String,
    pub structural_role: String,
    pub external_reference: Option<&'static str>,
    pub semantic_confidence: &'static str,
    pub unknowns: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeExt {
    pub message_id: String,
    pub external_name: &'static str,
    pub source: &'static str,
}

pub fn to_safe_export(m: &ProtocolStateMachine) -> SafeStateMachineExport {
    let mut trace_lengths = BTreeMap::new();
    for (k, v) in &m.traces {
        trace_lengths.insert(k.clone(), v.len());
    }
    SafeStateMachineExport {
        capture_a: m.capture_a.clone(),
        capture_b: m.capture_b.clone(),
        nodes: m.graph.nodes.clone(),
        states: m
            .states
            .iter()
            .map(|s| SafeStateObs {
                capture_id: s.capture_id.clone(),
                state_id: s.state_id.clone(),
                first_frame: s.first_frame,
                last_frame: s.last_frame,
                message_count: s.message_count,
                repeating: s.repeating,
                periodicity: s.periodicity,
                classification: s.classification.as_str(),
            })
            .collect(),
        transitions: m
            .graph
            .edges
            .iter()
            .take(128)
            .map(|e| SafeTransition {
                from: e.from_state.clone(),
                to: e.to_state.clone(),
                message_id: fmt_msg_id(e.message_id),
                direction: e.direction.clone(),
                context: e.context,
                count: e.occurrences,
                captures: e.captures_seen.len(),
                classification: e.classification.as_str(),
                request_response_candidate: e.request_response_candidate,
                semantic_status: e.semantic_status.as_str(),
            })
            .collect(),
        startup: SafeStartup {
            sequence: m.startup.sequence_key.clone(),
            capture_a_observed: m.startup.capture_a_observed,
            capture_b_observed: m.startup.capture_b_observed,
            common_prefix: m.startup.common_prefix,
            classification: m.startup.classification.as_str(),
            structural_label: m.startup.structural_label,
        },
        branches: SafeBranch {
            divergence_index: m.branches.divergence_index,
            message_a: m.branches.message_a.map(fmt_msg_id),
            message_b: m.branches.message_b.map(fmt_msg_id),
            branch_a_state: m.branches.branch_a_state.clone(),
            branch_b_state: m.branches.branch_b_state.clone(),
            classification: m.branches.classification.as_str(),
        },
        repeating_cluster: SafeCluster {
            state_id: m.repeating_cluster.state_id.clone(),
            message_ids: m
                .repeating_cluster
                .message_ids
                .iter()
                .map(|id| fmt_msg_id(*id))
                .collect(),
            repeating: m.repeating_cluster.repeating,
            periodicity: m.repeating_cluster.periodicity,
            captures: m.repeating_cluster.captures_seen.len(),
            classification: m.repeating_cluster.classification.as_str(),
            external_reference: m.repeating_cluster.external_reference,
            external_source: m.repeating_cluster.external_source,
        },
        context_transitions: m
            .context_transitions
            .iter()
            .take(64)
            .map(|t| SafeCtx {
                context_before: t.context_before,
                message_id: fmt_msg_id(t.message_id),
                context_after: t.context_after,
                count: t.count,
            })
            .collect(),
        request_response_candidates: m
            .request_response_candidates
            .iter()
            .map(|r| SafeRr {
                request_id: fmt_msg_id(r.request_id),
                response_id: fmt_msg_id(r.response_id),
                request_response_candidate: r.request_response_candidate,
                confidence: r.confidence,
                semantic_status: r.semantic_status.as_str(),
            })
            .collect(),
        semantic_matrix: m
            .semantic_matrix
            .iter()
            .map(|r| SafeSem {
                message_id: r.message_id.clone(),
                observed_behavior: r.observed_behavior.clone(),
                structural_role: r.structural_role.clone(),
                external_reference: r.external_reference,
                semantic_confidence: r.semantic_confidence.as_str(),
                unknowns: r.unknowns.clone(),
            })
            .collect(),
        external_semantics: m
            .external_semantics
            .iter()
            .map(|e| SafeExt {
                message_id: e.message_id.clone(),
                external_name: e.external_name,
                source: e.source,
            })
            .collect(),
        unknowns: m.unknowns.clone(),
        trace_lengths,
    }
}
