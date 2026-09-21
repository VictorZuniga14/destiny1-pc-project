//! Run M3.3 message correlation over pipeline-ready captures.

use crate::message_correlation::{
    analyze_two_captures, to_safe_export, CorrelationAnalysis, EdgeClass, SafeCorrelationExport,
};
use crate::message_inventory::fmt_msg_id;
use crate::message_inventory_verify::{self, MessageInventoryError};
use std::path::{Path, PathBuf};

pub struct CorrelationRun {
    pub analysis: CorrelationAnalysis,
    pub safe_export: SafeCorrelationExport,
}

impl std::fmt::Display for CorrelationRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let a = &self.analysis;
        writeln!(f, "M3.3 MESSAGE CORRELATION ANALYSIS")?;
        writeln!(f)?;
        writeln!(f, "captures:")?;
        writeln!(f, "  {}", a.capture_a)?;
        writeln!(f, "  {}", a.capture_b)?;
        writeln!(f)?;
        writeln!(f, "captures_processed: 2")?;
        writeln!(f, "messages: {}", a.unique_message_ids.len())?;
        writeln!(
            f,
            "sequence lengths: A={} B={}",
            a.sequence_a.sequence_length, a.sequence_b.sequence_length
        )?;
        writeln!(f)?;

        writeln!(f, "stable sequences:")?;
        for s in a.stable_sequences.iter().take(16) {
            writeln!(
                f,
                "  {} (A={}, B={}, len={})",
                s.sequence_key, s.occurrences_a, s.occurrences_b, s.length
            )?;
        }
        if a.stable_sequences.is_empty() {
            writeln!(f, "  (none)")?;
        }
        writeln!(f)?;

        let stable_edges: Vec<_> = a
            .transition_edges
            .iter()
            .filter(|e| e.edge_class == EdgeClass::StableEdge)
            .collect();
        let specific_edges: Vec<_> = a
            .transition_edges
            .iter()
            .filter(|e| e.edge_class == EdgeClass::CaptureSpecificEdge)
            .collect();

        writeln!(f, "stable edges:")?;
        for e in stable_edges.iter().take(20) {
            writeln!(
                f,
                "  {}→{} count={} dir={}",
                fmt_msg_id(e.from_id),
                fmt_msg_id(e.to_id),
                e.count,
                e.direction_transition
            )?;
        }
        if stable_edges.is_empty() {
            writeln!(f, "  (none)")?;
        }
        writeln!(f)?;

        writeln!(f, "capture-specific edges:")?;
        for e in specific_edges.iter().take(16) {
            writeln!(
                f,
                "  {}→{} count={}",
                fmt_msg_id(e.from_id),
                fmt_msg_id(e.to_id),
                e.count
            )?;
        }
        if specific_edges.is_empty() {
            writeln!(f, "  (none)")?;
        }
        writeln!(f)?;

        writeln!(f, "request/response candidates:")?;
        for r in a.request_response_candidates.iter().take(16) {
            writeln!(
                f,
                "  {} → {} [{}] confidence={} semantic={}",
                fmt_msg_id(r.request_id),
                fmt_msg_id(r.response_id),
                r.candidate_type,
                r.confidence.as_str(),
                r.semantic_confirmation.as_str()
            )?;
            writeln!(f, "    signals: {}", r.signals.join(", "))?;
        }
        if a.request_response_candidates.is_empty() {
            writeln!(f, "  (none)")?;
        }
        writeln!(f)?;

        writeln!(f, "periodic candidates:")?;
        for p in &a.periodic_candidates {
            writeln!(
                f,
                "  {} paired={:?} approx_periodic={} median={:?} jitter={:?} unit={}",
                fmt_msg_id(p.message_id),
                p.paired_id.map(fmt_msg_id),
                p.approximately_periodic,
                p.median_interval,
                p.jitter,
                p.unit
            )?;
            if let Some(ext) = p.external_reference {
                writeln!(
                    f,
                    "    external_reference: {} (messages.rs) [EXTERNAL_REFERENCE]",
                    ext
                )?;
            }
        }
        if a.periodic_candidates.is_empty() {
            writeln!(f, "  (none)")?;
        }
        writeln!(f)?;

        writeln!(f, "context transitions:")?;
        for t in a.context_transitions.iter().take(12) {
            writeln!(
                f,
                "  ctx {} → {} → ctx {} (count={})",
                t.context_before,
                fmt_msg_id(t.message_id),
                t.context_after,
                t.count
            )?;
        }
        if a.context_transitions.is_empty() {
            writeln!(f, "  (none)")?;
        }
        writeln!(f)?;

        writeln!(f, "first sequence divergence:")?;
        let d = &a.sequence_divergence;
        writeln!(f, "  common_prefix_length: {}", d.common_prefix_length)?;
        writeln!(f, "  common_suffix_length: {}", d.common_suffix_length)?;
        writeln!(f, "  divergence_index: {:?}", d.divergence_index)?;
        writeln!(
            f,
            "  A: {:?}  B: {:?}",
            d.capture_a_message.map(fmt_msg_id),
            d.capture_b_message.map(fmt_msg_id)
        )?;
        writeln!(f)?;

        writeln!(f, "alignment (first segments):")?;
        for seg in a.alignment.iter().take(12) {
            let ids = seg
                .message_ids
                .iter()
                .map(|id| fmt_msg_id(*id))
                .collect::<Vec<_>>()
                .join("→");
            writeln!(f, "  {}: {} (len={})", seg.kind, ids, seg.message_ids.len())?;
        }
        writeln!(f)?;

        writeln!(f, "result:")?;
        writeln!(f, "  VERIFIED_MULTI_CAPTURE")?;
        Ok(())
    }
}

pub fn run_from_manifest(path: impl AsRef<Path>) -> Result<CorrelationRun, MessageInventoryError> {
    let inv = message_inventory_verify::run_from_manifest(path)?;
    if inv.captures.len() < 2 {
        return Err(MessageInventoryError::NeedTwoCaptures);
    }
    let analysis = analyze_two_captures(&inv.captures[0], &inv.captures[1]);
    let safe_export = to_safe_export(&analysis);
    Ok(CorrelationRun {
        analysis,
        safe_export,
    })
}

pub fn write_safe_export(
    path: impl AsRef<Path>,
    export: &SafeCorrelationExport,
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
        PathBuf::from("fixtures/message_correlation/cross_capture_safe.json")
    } else {
        manifest
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("message_correlation_safe.json")
    }
}
