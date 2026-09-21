//! Run M3.2 payload structure analysis over pipeline-ready captures.

use crate::message_inventory::{fmt_msg_id, CaptureMessageInventory};
use crate::message_inventory_verify::{self, MessageInventoryError};
use crate::payload_structure::{
    analyze_message_id, flatten_observations, to_safe_report, LengthClass, OffsetStability,
    PRIORITY_MESSAGE_IDS, PayloadStructureReport, SafePayloadStructureExport,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct PayloadStructureRun {
    pub capture_a: String,
    pub capture_b: String,
    pub reports: Vec<PayloadStructureReport>,
    pub safe_exports: Vec<SafePayloadStructureExport>,
}

impl std::fmt::Display for PayloadStructureRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "M3.2 PAYLOAD STRUCTURE ANALYSIS")?;
        writeln!(f)?;
        writeln!(f, "captures:")?;
        writeln!(f, "  {}", self.capture_a)?;
        writeln!(f, "  {}", self.capture_b)?;
        writeln!(f)?;
        writeln!(f, "captures_processed: 2")?;
        writeln!(f, "message IDs analyzed: {}", self.reports.len())?;
        writeln!(f, "multi-capture-verify: VERIFIED_MULTI_CAPTURE")?;
        writeln!(f)?;
        writeln!(
            f,
            "{:<8} {:<16} {:<18} {:<18} {}",
            "ID", "lengths", "stable regions", "variable regions", "status"
        )?;

        let mut stable_ids = Vec::new();
        let mut divergent_ids = Vec::new();
        let mut capture_specific = Vec::new();
        let mut unknown_ids = Vec::new();

        for r in &self.reports {
            let lens = format_lengths(r);
            let stable_n = r
                .regions
                .iter()
                .filter(|reg| reg.cross_capture_stability == OffsetStability::Constant)
                .count();
            let var_n = r
                .regions
                .iter()
                .filter(|reg| reg.cross_capture_stability == OffsetStability::Variable)
                .count();
            let status = match r.length_class {
                LengthClass::CrossCaptureLengthDivergent => "LENGTH_DIVERGENT",
                LengthClass::CrossCaptureLengthStable
                    if stable_n > 0 && var_n == 0 && r.offsets.iter().all(|o| {
                        matches!(
                            o.cross_capture,
                            OffsetStability::Constant | OffsetStability::Unobserved
                        )
                    }) =>
                {
                    "STRUCTURAL_STABLE"
                }
                LengthClass::CrossCaptureLengthStable if var_n > 0 => "MIXED",
                LengthClass::FixedLength | LengthClass::VariableLength => "CAPTURE_SPECIFIC",
                _ => "UNKNOWN",
            };
            match status {
                "STRUCTURAL_STABLE" => stable_ids.push(r.message_id),
                "LENGTH_DIVERGENT" | "MIXED" => divergent_ids.push(r.message_id),
                "CAPTURE_SPECIFIC" => capture_specific.push(r.message_id),
                _ => unknown_ids.push(r.message_id),
            }
            writeln!(
                f,
                "{:<8} {:<16} {:<18} {:<18} {}",
                fmt_msg_id(r.message_id),
                truncate(&lens, 16),
                stable_n,
                var_n,
                status
            )?;
        }

        writeln!(f)?;
        writeln!(f, "STRUCTURAL SUMMARY")?;
        writeln!(f)?;
        writeln!(
            f,
            "cross-capture stable: {}",
            format_ids(&stable_ids)
        )?;
        writeln!(
            f,
            "cross-capture divergent: {}",
            format_ids(&divergent_ids)
        )?;
        writeln!(f, "capture-specific: {}", format_ids(&capture_specific))?;
        writeln!(f, "unknown: {}", format_ids(&unknown_ids))?;
        writeln!(f)?;

        // Detail priority messages first (capped region listing), then a few others.
        let mut shown = BTreeSet::new();
        for &pid in PRIORITY_MESSAGE_IDS {
            if let Some(r) = self.reports.iter().find(|r| r.message_id == pid) {
                write_detail(f, r)?;
                shown.insert(pid);
            }
        }
        let mut extra = 0usize;
        for r in &self.reports {
            if shown.contains(&r.message_id) {
                continue;
            }
            if extra >= 4 {
                break;
            }
            if r.regions.iter().any(|reg| {
                reg.text_candidate.is_some()
                    || reg.numeric_candidates.iter().any(|n| n.possible_monotonic)
            }) {
                write_detail(f, r)?;
                shown.insert(r.message_id);
                extra += 1;
            }
        }
        Ok(())
    }
}

fn write_detail(f: &mut std::fmt::Formatter<'_>, r: &PayloadStructureReport) -> std::fmt::Result {
    writeln!(f, "{}", fmt_msg_id(r.message_id))?;
    writeln!(f)?;
    writeln!(f, "lengths:")?;
    writeln!(f, "  A: {:?}", r.lengths_a.keys().collect::<Vec<_>>())?;
    writeln!(f, "  B: {:?}", r.lengths_b.keys().collect::<Vec<_>>())?;
    writeln!(f, "  class: {}", r.length_class.as_str())?;
    writeln!(f)?;
    writeln!(
        f,
        "candidate regions: {} total (showing up to {})",
        r.regions.len(),
        DETAIL_REGION_LIMIT
    )?;
    for reg in r.regions.iter().take(DETAIL_REGION_LIMIT) {
        writeln!(f, "  offset {}..{}", reg.start, reg.end)?;
        writeln!(
            f,
            "    within: {} / cross: {}",
            reg.within_capture_stability.as_str(),
            reg.cross_capture_stability.as_str()
        )?;
        writeln!(f, "    status: {}", reg.structural_status.as_str())?;
        for n in reg.numeric_candidates.iter().take(8) {
            writeln!(
                f,
                "    u{} {}: distinct={} monotonic={} [{}] semantic={}",
                n.width * 8,
                n.endian,
                n.distinct_values,
                n.possible_monotonic,
                n.classification.as_str(),
                n.semantic_meaning
            )?;
        }
        if reg.numeric_candidates.len() > 8 {
            writeln!(
                f,
                "    ... {} more numeric candidates",
                reg.numeric_candidates.len() - 8
            )?;
        }
        if let Some(b) = &reg.bit_variation {
            writeln!(
                f,
                "    bits variable={:?} constant={:?} [{}]",
                b.variable_bits,
                b.constant_bits,
                b.classification.as_str()
            )?;
        }
        if let Some(t) = &reg.text_candidate {
            writeln!(
                f,
                "    TEXT_CANDIDATE printable_ratio={}% [{}]",
                t.printable_ratio,
                t.classification.as_str()
            )?;
        }
        writeln!(f)?;
    }
    if r.regions.len() > DETAIL_REGION_LIMIT {
        writeln!(
            f,
            "  ... {} regions omitted",
            r.regions.len() - DETAIL_REGION_LIMIT
        )?;
        writeln!(f)?;
    }
    if !r.correlated_region_pairs.is_empty() {
        writeln!(f, "  OBSERVED_CORRELATION:")?;
        for (a0, a1, b0, b1) in r.correlated_region_pairs.iter().take(16) {
            writeln!(f, "    {a0}..{a1} <-> {b0}..{b1}")?;
        }
        if r.correlated_region_pairs.len() > 16 {
            writeln!(
                f,
                "    ... {} more pairs",
                r.correlated_region_pairs.len() - 16
            )?;
        }
        writeln!(f)?;
    }
    Ok(())
}

const DETAIL_REGION_LIMIT: usize = 24;

fn format_lengths(r: &PayloadStructureReport) -> String {
    let mut s = BTreeSet::new();
    s.extend(r.lengths_a.keys().copied());
    s.extend(r.lengths_b.keys().copied());
    s.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

fn format_ids(ids: &[u16]) -> String {
    if ids.is_empty() {
        "(none)".into()
    } else {
        ids.iter().map(|id| fmt_msg_id(*id)).collect::<Vec<_>>().join(", ")
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n.saturating_sub(1)])
    }
}

pub fn run_from_manifest(path: impl AsRef<Path>) -> Result<PayloadStructureRun, MessageInventoryError> {
    let inv = message_inventory_verify::run_from_manifest(path)?;
    if inv.captures.len() < 2 {
        return Err(MessageInventoryError::NeedTwoCaptures);
    }
    let a = &inv.captures[0];
    let b = &inv.captures[1];
    Ok(analyze_two_captures(a, b))
}

pub fn analyze_two_captures(
    a: &CaptureMessageInventory,
    b: &CaptureMessageInventory,
) -> PayloadStructureRun {
    let mut all = flatten_observations(&a.inventory.groups);
    all.extend(flatten_observations(&b.inventory.groups));

    let mut ids: BTreeSet<u16> = BTreeSet::new();
    ids.extend(a.unique_message_ids.iter().copied());
    ids.extend(b.unique_message_ids.iter().copied());

    // Priority order then remaining.
    let mut ordered = Vec::new();
    for &pid in PRIORITY_MESSAGE_IDS {
        if ids.remove(&pid) {
            ordered.push(pid);
        }
    }
    ordered.extend(ids.iter().copied());

    let reports: Vec<PayloadStructureReport> = ordered
        .iter()
        .map(|id| analyze_message_id(*id, &all, &a.capture_id, &b.capture_id))
        .filter(|r| r.observations_count > 0)
        .collect();
    let safe_exports: Vec<_> = reports.iter().map(to_safe_report).collect();

    PayloadStructureRun {
        capture_a: a.capture_id.clone(),
        capture_b: b.capture_id.clone(),
        reports,
        safe_exports,
    }
}

pub fn write_safe_export(
    path: impl AsRef<Path>,
    run: &PayloadStructureRun,
) -> Result<(), MessageInventoryError> {
    #[derive(Serialize)]
    struct Doc<'a> {
        capture_a: &'a str,
        capture_b: &'a str,
        message_ids_analyzed: usize,
        reports: &'a [SafePayloadStructureExport],
    }
    let doc = Doc {
        capture_a: &run.capture_a,
        capture_b: &run.capture_b,
        message_ids_analyzed: run.safe_exports.len(),
        reports: &run.safe_exports,
    };
    let json = serde_json::to_string_pretty(&doc).map_err(|_| MessageInventoryError::BadJson)?;
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
        PathBuf::from("fixtures/payload_structure/cross_capture_safe.json")
    } else {
        manifest
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("payload_structure_safe.json")
    }
}
