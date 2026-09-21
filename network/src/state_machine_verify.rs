//! Run M3.4 observational state machine over pipeline-ready captures.

use crate::message_inventory::fmt_msg_id;
use crate::message_inventory_verify::{self, MessageInventoryError};
use crate::state_machine::{
    build_state_machine, to_safe_export, ProtocolStateMachine, SafeStateMachineExport,
    StateClassification, STATE_REPEATING_CLUSTER_01, STATE_STARTUP_SEQUENCE,
};
use std::path::{Path, PathBuf};

pub struct StateMachineRun {
    pub machine: ProtocolStateMachine,
    pub safe_export: SafeStateMachineExport,
}

impl std::fmt::Display for StateMachineRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let m = &self.machine;
        writeln!(f, "M3.4 PROTOCOL STATE MACHINE")?;
        writeln!(f)?;
        writeln!(f, "captures:")?;
        writeln!(f, "  {}", m.capture_a)?;
        writeln!(f, "  {}", m.capture_b)?;
        writeln!(f)?;
        writeln!(f, "captures_processed: 2")?;
        writeln!(f, "nodes: {}", m.graph.nodes.join(", "))?;
        writeln!(f)?;

        writeln!(f, "startup sequence:")?;
        writeln!(f, "  {}", m.startup.sequence_key)?;
        writeln!(
            f,
            "  A observed={}  B observed={}  common_prefix={}",
            m.startup.capture_a_observed,
            m.startup.capture_b_observed,
            m.startup.common_prefix
        )?;
        writeln!(
            f,
            "  structural_label={}  classification={}",
            m.startup.structural_label,
            m.startup.classification.as_str()
        )?;
        writeln!(f)?;

        writeln!(f, "states (aggregated):")?;
        let mut seen = std::collections::BTreeSet::new();
        for s in &m.states {
            if seen.insert(s.state_id.clone()) {
                writeln!(
                    f,
                    "  {} repeating={} periodicity={}",
                    s.state_id, s.repeating, s.periodicity
                )?;
            }
        }
        writeln!(f)?;

        let stable: Vec<_> = m
            .graph
            .edges
            .iter()
            .filter(|e| e.classification == StateClassification::StableCrossCapture)
            .collect();
        let specific: Vec<_> = m
            .graph
            .edges
            .iter()
            .filter(|e| e.classification == StateClassification::CaptureSpecific)
            .collect();

        writeln!(f, "stable transitions:")?;
        for e in stable.iter().take(16) {
            writeln!(
                f,
                "  {} → {} via {} ({}) count={}",
                e.from_state,
                e.to_state,
                fmt_msg_id(e.message_id),
                e.direction,
                e.occurrences
            )?;
        }
        if stable.is_empty() {
            writeln!(f, "  (none)")?;
        }
        writeln!(f)?;

        writeln!(f, "capture-specific transitions:")?;
        for e in specific.iter().take(12) {
            writeln!(
                f,
                "  {} → {} via {} count={}",
                e.from_state,
                e.to_state,
                fmt_msg_id(e.message_id),
                e.occurrences
            )?;
        }
        if specific.is_empty() {
            writeln!(f, "  (none)")?;
        }
        writeln!(f)?;

        writeln!(f, "branches:")?;
        writeln!(
            f,
            "  divergence_index={:?} A={:?} B={:?}",
            m.branches.divergence_index,
            m.branches.message_a.map(fmt_msg_id),
            m.branches.message_b.map(fmt_msg_id)
        )?;
        writeln!(
            f,
            "  {} | {}",
            m.branches.branch_a_state, m.branches.branch_b_state
        )?;
        writeln!(f)?;

        writeln!(f, "repeating cluster:")?;
        writeln!(
            f,
            "  {} repeating={} periodicity={}",
            STATE_REPEATING_CLUSTER_01,
            m.repeating_cluster.repeating,
            m.repeating_cluster.periodicity
        )?;
        if let Some(ext) = m.repeating_cluster.external_reference {
            writeln!(
                f,
                "  EXTERNAL_REFERENCE: {} (messages.rs)",
                ext
            )?;
        }
        writeln!(f)?;

        writeln!(f, "request/response candidates (preserved):")?;
        for r in m.request_response_candidates.iter().take(10) {
            writeln!(
                f,
                "  {} → {} candidate=true semantic={}",
                fmt_msg_id(r.request_id),
                fmt_msg_id(r.response_id),
                r.semantic_status.as_str()
            )?;
        }
        writeln!(f)?;

        writeln!(f, "trace lengths:")?;
        for (cap, tr) in &m.traces {
            let startup_n = tr
                .iter()
                .filter(|e| e.to_state == STATE_STARTUP_SEQUENCE)
                .count();
            writeln!(
                f,
                "  {}: {} frames (startup_state_frames={})",
                cap,
                tr.len(),
                startup_n
            )?;
        }
        writeln!(f)?;

        writeln!(f, "result:")?;
        writeln!(f, "  VERIFIED_MULTI_CAPTURE")?;
        Ok(())
    }
}

pub fn run_from_manifest(path: impl AsRef<Path>) -> Result<StateMachineRun, MessageInventoryError> {
    let inv = message_inventory_verify::run_from_manifest(path)?;
    if inv.captures.len() < 2 {
        return Err(MessageInventoryError::NeedTwoCaptures);
    }
    let machine = build_state_machine(&inv.captures[0], &inv.captures[1]);
    let safe_export = to_safe_export(&machine);
    Ok(StateMachineRun {
        machine,
        safe_export,
    })
}

pub fn write_safe_export(
    path: impl AsRef<Path>,
    export: &SafeStateMachineExport,
) -> Result<(), MessageInventoryError> {
    let json = serde_json::to_string_pretty(export).map_err(|_| MessageInventoryError::BadJson)?;
    if let Some(parent) = path.as_ref().parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(path, json + "\n").map_err(|_| MessageInventoryError::Io)
}

pub fn default_export_path(manifest: &Path) -> PathBuf {
    if manifest
        .components()
        .any(|c| c.as_os_str() == "multi_capture" || c.as_os_str() == "fixtures")
    {
        PathBuf::from("fixtures/state_machine/cross_capture_safe.json")
    } else {
        manifest
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("state_machine_safe.json")
    }
}
