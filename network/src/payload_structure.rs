//! Offline payload structure analysis (M3.2).
//!
//! Separates OBSERVED facts from STRUCTURAL_HYPOTHESIS. Does not assign
//! semantic field names. Reuses [`MessageObservation`] payloads in memory.

use crate::message_inventory::{fmt_msg_id, EvidenceLabel, MessageObservation};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Structural classification (not semantic confirmation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum StructuralClass {
    Observed,
    StructuralHypothesis,
    StructuralStable,
    StructuralDivergent,
    CaptureSpecific,
    Unknown,
}

impl StructuralClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Observed => "OBSERVED",
            Self::StructuralHypothesis => "STRUCTURAL_HYPOTHESIS",
            Self::StructuralStable => "STRUCTURAL_STABLE",
            Self::StructuralDivergent => "STRUCTURAL_DIVERGENT",
            Self::CaptureSpecific => "CAPTURE_SPECIFIC",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OffsetStability {
    Constant,
    Variable,
    Unobserved,
    LengthDependent,
}

impl OffsetStability {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Constant => "CONSTANT",
            Self::Variable => "VARIABLE",
            Self::Unobserved => "UNOBSERVED",
            Self::LengthDependent => "LENGTH_DEPENDENT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum LengthClass {
    FixedLength,
    VariableLength,
    CrossCaptureLengthStable,
    CrossCaptureLengthDivergent,
}

impl LengthClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FixedLength => "FIXED_LENGTH",
            Self::VariableLength => "VARIABLE_LENGTH",
            Self::CrossCaptureLengthStable => "CROSS_CAPTURE_LENGTH_STABLE",
            Self::CrossCaptureLengthDivergent => "CROSS_CAPTURE_LENGTH_DIVERGENT",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NumericCandidate {
    pub width: u8,
    pub endian: &'static str,
    pub distinct_values: usize,
    pub sample_values: Vec<u64>,
    pub possible_monotonic: bool,
    pub classification: StructuralClass,
    pub semantic_meaning: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BitVariation {
    pub offset: usize,
    pub distinct_values: Vec<u8>,
    pub bitwise_or: u8,
    pub bitwise_and: u8,
    pub variable_bits: Vec<u8>,
    pub constant_bits: Vec<u8>,
    pub classification: StructuralClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TextCandidate {
    pub offset: usize,
    pub width: usize,
    pub printable_ratio: u32, // 0..=100
    pub classification: StructuralClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CandidateRegion {
    pub start: usize,
    pub end: usize, // exclusive
    pub within_capture_stability: OffsetStability,
    pub cross_capture_stability: OffsetStability,
    pub structural_status: StructuralClass,
    pub numeric_candidates: Vec<NumericCandidate>,
    pub bit_variation: Option<BitVariation>,
    pub text_candidate: Option<TextCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OffsetAnalysis {
    pub offset: usize,
    pub within_a: OffsetStability,
    pub within_b: OffsetStability,
    pub cross_capture: OffsetStability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PayloadStructureReport {
    pub message_id: u16,
    pub observations_count: u32,
    pub captures_seen: BTreeSet<String>,
    pub lengths_a: BTreeMap<usize, u32>,
    pub lengths_b: BTreeMap<usize, u32>,
    pub length_class: LengthClass,
    pub fingerprint_counts: BTreeMap<String, u32>,
    pub offsets: Vec<OffsetAnalysis>,
    pub regions: Vec<CandidateRegion>,
    pub correlated_region_pairs: Vec<(usize, usize, usize, usize)>, // a0,a1,b0,b1
}

/// Priority analysis order (documentation order; not semantic importance).
pub const PRIORITY_MESSAGE_IDS: &[u16] = &[
    0x19, 0x1A, 0x1E, 0x1F, 0x79, 0x7A, 0x12E, 0x12F, 0xFA, 0xFB, 0x0A, 0x0B, 0x0C, 0x0D, 0x12,
    0x13, 0x15, 0x16, 0x17, 0x18, 0x20, 0x21, 0x7B, 0xAB, 0x10, 0x11, 0x2A, 0x2B,
];

pub fn analyze_message_id(
    message_id: u16,
    observations: &[MessageObservation],
    capture_a: &str,
    capture_b: &str,
) -> PayloadStructureReport {
    let obs_a: Vec<&MessageObservation> = observations
        .iter()
        .filter(|o| o.capture_id == capture_a && o.message_id == message_id)
        .collect();
    let obs_b: Vec<&MessageObservation> = observations
        .iter()
        .filter(|o| o.capture_id == capture_b && o.message_id == message_id)
        .collect();

    let mut captures_seen = BTreeSet::new();
    if !obs_a.is_empty() {
        captures_seen.insert(capture_a.to_string());
    }
    if !obs_b.is_empty() {
        captures_seen.insert(capture_b.to_string());
    }

    let lengths_a = count_lengths(&obs_a);
    let lengths_b = count_lengths(&obs_b);
    let length_class = classify_lengths(&lengths_a, &lengths_b, !obs_a.is_empty(), !obs_b.is_empty());

    let mut fingerprint_counts = BTreeMap::new();
    for o in obs_a.iter().chain(obs_b.iter()) {
        *fingerprint_counts
            .entry(o.payload_sha256.clone())
            .or_insert(0) += 1;
    }

    let max_len = observations
        .iter()
        .filter(|o| o.message_id == message_id)
        .map(|o| o.payload_len)
        .max()
        .unwrap_or(0);

    let mut offsets = Vec::new();
    for off in 0..max_len {
        let within_a = offset_stability(&obs_a, off);
        let within_b = offset_stability(&obs_b, off);
        let cross = cross_offset_stability(&obs_a, &obs_b, off, within_a, within_b);
        offsets.push(OffsetAnalysis {
            offset: off,
            within_a,
            within_b,
            cross_capture: cross,
        });
    }

    let regions = build_regions(&offsets, &obs_a, &obs_b);
    let correlated = find_correlations(&obs_a, &obs_b, &regions);

    PayloadStructureReport {
        message_id,
        observations_count: (obs_a.len() + obs_b.len()) as u32,
        captures_seen,
        lengths_a,
        lengths_b,
        length_class,
        fingerprint_counts,
        offsets,
        regions,
        correlated_region_pairs: correlated,
    }
}

fn count_lengths(obs: &[&MessageObservation]) -> BTreeMap<usize, u32> {
    let mut m = BTreeMap::new();
    for o in obs {
        *m.entry(o.payload_len).or_insert(0) += 1;
    }
    m
}

fn classify_lengths(
    a: &BTreeMap<usize, u32>,
    b: &BTreeMap<usize, u32>,
    has_a: bool,
    has_b: bool,
) -> LengthClass {
    if !has_a || !has_b {
        let only = if has_a { a } else { b };
        if only.len() <= 1 {
            LengthClass::FixedLength
        } else {
            LengthClass::VariableLength
        }
    } else {
        let ka: BTreeSet<_> = a.keys().copied().collect();
        let kb: BTreeSet<_> = b.keys().copied().collect();
        if ka == kb {
            if ka.len() <= 1 {
                LengthClass::CrossCaptureLengthStable
            } else {
                // same variable set across captures
                LengthClass::CrossCaptureLengthStable
            }
        } else {
            LengthClass::CrossCaptureLengthDivergent
        }
    }
}

fn offset_stability(obs: &[&MessageObservation], offset: usize) -> OffsetStability {
    let mut values = BTreeSet::new();
    let mut seen = 0u32;
    let mut missing = 0u32;
    for o in obs {
        if offset < o.payload.len() {
            values.insert(o.payload[offset]);
            seen += 1;
        } else {
            missing += 1;
        }
    }
    if seen == 0 {
        return OffsetStability::Unobserved;
    }
    if missing > 0 && values.len() <= 1 {
        return OffsetStability::LengthDependent;
    }
    if values.len() <= 1 {
        OffsetStability::Constant
    } else {
        OffsetStability::Variable
    }
}

fn cross_offset_stability(
    a: &[&MessageObservation],
    b: &[&MessageObservation],
    offset: usize,
    within_a: OffsetStability,
    within_b: OffsetStability,
) -> OffsetStability {
    if a.is_empty() || b.is_empty() {
        return OffsetStability::Unobserved;
    }
    if matches!(
        within_a,
        OffsetStability::Unobserved | OffsetStability::LengthDependent
    ) || matches!(
        within_b,
        OffsetStability::Unobserved | OffsetStability::LengthDependent
    ) {
        return OffsetStability::LengthDependent;
    }
    // Collect values across both captures at this offset.
    let mut values = BTreeSet::new();
    for o in a.iter().chain(b.iter()) {
        if offset < o.payload.len() {
            values.insert(o.payload[offset]);
        }
    }
    if values.len() <= 1 {
        OffsetStability::Constant
    } else if within_a == OffsetStability::Constant && within_b == OffsetStability::Constant {
        // constant within each capture but differs across → session-specific constant
        OffsetStability::Variable
    } else {
        OffsetStability::Variable
    }
}

fn build_regions(
    offsets: &[OffsetAnalysis],
    obs_a: &[&MessageObservation],
    obs_b: &[&MessageObservation],
) -> Vec<CandidateRegion> {
    if offsets.is_empty() {
        return Vec::new();
    }
    let mut regions = Vec::new();
    let mut start = 0usize;
    let mut cur = offsets[0].cross_capture;
    for i in 1..=offsets.len() {
        let end_run = i == offsets.len() || offsets[i].cross_capture != cur;
        if end_run {
            let end = i;
            let within = if offsets[start].within_a == offsets[start].within_b {
                offsets[start].within_a
            } else {
                OffsetStability::Variable
            };
            let structural_status = match cur {
                OffsetStability::Constant => StructuralClass::StructuralStable,
                OffsetStability::Variable => StructuralClass::StructuralDivergent,
                OffsetStability::LengthDependent => StructuralClass::CaptureSpecific,
                OffsetStability::Unobserved => StructuralClass::Unknown,
            };
            let width = end - start;
            let mut numeric = Vec::new();
            if cur != OffsetStability::Unobserved {
                // Native width if classic integer size.
                if matches!(width, 1 | 2 | 4 | 8) {
                    numeric.extend(numeric_candidates(start, width as u8, obs_a, obs_b));
                }
                // Probe 2/4/8 from region start (may span following bytes).
                // Skip spanning from every single-byte VARIABLE run (noise / cost).
                let allow_span = width > 1 || cur == OffsetStability::Constant;
                if allow_span {
                    for w in [2u8, 4, 8] {
                        if w as usize == width {
                            continue;
                        }
                        if start + w as usize <= offsets.len() {
                            numeric.extend(numeric_candidates(start, w, obs_a, obs_b));
                        }
                    }
                }
            }
            let bit_variation = if width == 1 {
                Some(bit_variation_at(start, obs_a, obs_b))
            } else {
                None
            };
            let text_candidate = text_candidate_at(start, width, obs_a, obs_b);
            regions.push(CandidateRegion {
                start,
                end,
                within_capture_stability: within,
                cross_capture_stability: cur,
                structural_status,
                numeric_candidates: numeric,
                bit_variation,
                text_candidate,
            });
            if i < offsets.len() {
                start = i;
                cur = offsets[i].cross_capture;
            }
        }
    }
    regions
}

fn read_int(payload: &[u8], offset: usize, width: u8, be: bool) -> Option<u64> {
    let w = width as usize;
    if offset + w > payload.len() {
        return None;
    }
    let slice = &payload[offset..offset + w];
    let mut v = 0u64;
    if be {
        for b in slice {
            v = (v << 8) | u64::from(*b);
        }
    } else {
        for (i, b) in slice.iter().enumerate() {
            v |= u64::from(*b) << (8 * i);
        }
    }
    Some(v)
}

fn numeric_candidates(
    offset: usize,
    width: u8,
    obs_a: &[&MessageObservation],
    obs_b: &[&MessageObservation],
) -> Vec<NumericCandidate> {
    let mut out = Vec::new();
    for (endian, be) in [("BE", true), ("LE", false)] {
        if width == 1 && endian == "LE" {
            continue; // u8 identical
        }
        let mut values = Vec::new();
        for o in obs_a.iter().chain(obs_b.iter()) {
            if let Some(v) = read_int(&o.payload, offset, width, be) {
                values.push(v);
            }
        }
        if values.is_empty() {
            continue;
        }
        let distinct: BTreeSet<u64> = values.iter().copied().collect();
        let possible_monotonic = is_monotonic(&values);
        let mut sample: Vec<u64> = distinct.iter().copied().take(8).collect();
        sample.sort_unstable();
        out.push(NumericCandidate {
            width,
            endian,
            distinct_values: distinct.len(),
            sample_values: sample,
            possible_monotonic,
            classification: StructuralClass::StructuralHypothesis,
            semantic_meaning: "UNKNOWN",
        });
    }
    out
}

fn is_monotonic(values: &[u64]) -> bool {
    if values.len() < 3 {
        return false;
    }
    // Check non-decreasing in observation order (not sorted).
    let mut inc = true;
    let mut dec = true;
    for w in values.windows(2) {
        if w[1] < w[0] {
            inc = false;
        }
        if w[1] > w[0] {
            dec = false;
        }
    }
    (inc || dec) && values.iter().collect::<BTreeSet<_>>().len() >= 3
}

fn bit_variation_at(
    offset: usize,
    obs_a: &[&MessageObservation],
    obs_b: &[&MessageObservation],
) -> BitVariation {
    let mut set = BTreeSet::new();
    for o in obs_a.iter().chain(obs_b.iter()) {
        if offset < o.payload.len() {
            set.insert(o.payload[offset]);
        }
    }
    let values: Vec<u8> = set.iter().copied().collect();
    let mut bor = 0u8;
    let mut band = 0xffu8;
    for v in &values {
        bor |= *v;
        band &= *v;
    }
    if values.is_empty() {
        band = 0;
    }
    let mut variable_bits = Vec::new();
    let mut constant_bits = Vec::new();
    for bit in 0..8u8 {
        let mask = 1u8 << bit;
        if (bor ^ band) & mask != 0 {
            variable_bits.push(bit);
        } else {
            constant_bits.push(bit);
        }
    }
    BitVariation {
        offset,
        distinct_values: values,
        bitwise_or: bor,
        bitwise_and: band,
        variable_bits,
        constant_bits,
        classification: StructuralClass::StructuralHypothesis,
    }
}

fn text_candidate_at(
    offset: usize,
    width: usize,
    obs_a: &[&MessageObservation],
    obs_b: &[&MessageObservation],
) -> Option<TextCandidate> {
    if width < 3 {
        return None;
    }
    let mut ratios = Vec::new();
    for o in obs_a.iter().chain(obs_b.iter()) {
        if offset + width > o.payload.len() {
            continue;
        }
        let slice = &o.payload[offset..offset + width];
        let printable = slice
            .iter()
            .filter(|b| **b >= 0x20 && **b <= 0x7e)
            .count();
        ratios.push(((printable * 100) / width) as u32);
    }
    if ratios.is_empty() {
        return None;
    }
    let avg = ratios.iter().sum::<u32>() / ratios.len() as u32;
    if avg < 80 {
        return None;
    }
    Some(TextCandidate {
        offset,
        width,
        printable_ratio: avg,
        classification: StructuralClass::StructuralHypothesis,
    })
}

fn find_correlations(
    obs_a: &[&MessageObservation],
    obs_b: &[&MessageObservation],
    regions: &[CandidateRegion],
) -> Vec<(usize, usize, usize, usize)> {
    let variable: Vec<&CandidateRegion> = regions
        .iter()
        .filter(|r| r.cross_capture_stability == OffsetStability::Variable)
        .take(48)
        .collect();
    let mut pairs = Vec::new();
    for i in 0..variable.len() {
        for j in (i + 1)..variable.len() {
            let ra = variable[i];
            let rb = variable[j];
            if regions_change_together(obs_a, obs_b, ra, rb) {
                pairs.push((ra.start, ra.end, rb.start, rb.end));
                if pairs.len() >= 32 {
                    return pairs;
                }
            }
        }
    }
    pairs
}

fn regions_change_together(
    obs_a: &[&MessageObservation],
    obs_b: &[&MessageObservation],
    ra: &CandidateRegion,
    rb: &CandidateRegion,
) -> bool {
    let all: Vec<&MessageObservation> = obs_a.iter().chain(obs_b.iter()).copied().collect();
    if all.len() < 2 {
        return false;
    }
    // Compare each observation to the first: if one region differs, the other should too.
    let base = all[0];
    let mut linked = 0u32;
    let mut considered = 0u32;
    for o in &all[1..] {
        let da = slice_differs(base, o, ra.start, ra.end);
        let db = slice_differs(base, o, rb.start, rb.end);
        if da || db {
            considered += 1;
            if da == db {
                linked += 1;
            }
        }
    }
    considered >= 2 && linked == considered
}

fn slice_differs(a: &MessageObservation, b: &MessageObservation, start: usize, end: usize) -> bool {
    let wa = end.min(a.payload.len()).saturating_sub(start.min(a.payload.len()));
    let wb = end.min(b.payload.len()).saturating_sub(start.min(b.payload.len()));
    if wa != wb || start >= a.payload.len() || start >= b.payload.len() {
        return a.payload_len != b.payload_len;
    }
    a.payload[start..start + wa] != b.payload[start..start + wb]
}

/// Safe export row (no payload bytes).
#[derive(Debug, Clone, Serialize)]
pub struct SafePayloadStructureExport {
    pub message_id: String,
    pub observations_count: u32,
    pub captures_seen: Vec<String>,
    pub lengths_a: BTreeMap<String, u32>,
    pub lengths_b: BTreeMap<String, u32>,
    pub length_class: &'static str,
    pub fingerprint_counts: BTreeMap<String, u32>,
    pub regions_total: usize,
    pub regions_exported: usize,
    pub stable_region_count: usize,
    pub variable_region_count: usize,
    pub regions: Vec<SafeRegionExport>,
    pub correlated_region_pairs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeRegionExport {
    pub start: usize,
    pub end: usize,
    pub within_capture_stability: &'static str,
    pub cross_capture_stability: &'static str,
    pub structural_status: &'static str,
    pub numeric_candidates: Vec<SafeNumericExport>,
    pub bit_variation: Option<SafeBitExport>,
    pub text_candidate: Option<SafeTextExport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeNumericExport {
    pub width: u8,
    pub endian: &'static str,
    pub distinct_values: usize,
    pub sample_values: Vec<u64>,
    pub possible_monotonic: bool,
    pub classification: &'static str,
    pub semantic_meaning: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeBitExport {
    pub offset: usize,
    pub distinct_values: Vec<u8>,
    pub variable_bits: Vec<u8>,
    pub constant_bits: Vec<u8>,
    pub classification: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeTextExport {
    pub offset: usize,
    pub width: usize,
    pub printable_ratio: u32,
    pub classification: &'static str,
}

pub const SAFE_EXPORT_REGION_LIMIT: usize = 64;

pub fn to_safe_report(r: &PayloadStructureReport) -> SafePayloadStructureExport {
    let stable_region_count = r
        .regions
        .iter()
        .filter(|reg| reg.cross_capture_stability == OffsetStability::Constant)
        .count();
    let variable_region_count = r
        .regions
        .iter()
        .filter(|reg| reg.cross_capture_stability == OffsetStability::Variable)
        .count();
    // Prefer exporting constant / mixed regions first; then a sample of variable.
    let mut ordered: Vec<&CandidateRegion> = Vec::new();
    ordered.extend(
        r.regions
            .iter()
            .filter(|reg| reg.cross_capture_stability != OffsetStability::Variable),
    );
    ordered.extend(
        r.regions
            .iter()
            .filter(|reg| reg.cross_capture_stability == OffsetStability::Variable)
            .take(SAFE_EXPORT_REGION_LIMIT),
    );
    ordered.truncate(SAFE_EXPORT_REGION_LIMIT);

    SafePayloadStructureExport {
        message_id: fmt_msg_id(r.message_id),
        observations_count: r.observations_count,
        captures_seen: r.captures_seen.iter().cloned().collect(),
        lengths_a: r
            .lengths_a
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
        lengths_b: r
            .lengths_b
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
        length_class: r.length_class.as_str(),
        fingerprint_counts: r
            .fingerprint_counts
            .iter()
            .take(32)
            .map(|(k, v)| (k.clone(), *v))
            .collect(),
        regions_total: r.regions.len(),
        regions_exported: ordered.len(),
        stable_region_count,
        variable_region_count,
        regions: ordered
            .iter()
            .map(|reg| SafeRegionExport {
                start: reg.start,
                end: reg.end,
                within_capture_stability: reg.within_capture_stability.as_str(),
                cross_capture_stability: reg.cross_capture_stability.as_str(),
                structural_status: reg.structural_status.as_str(),
                numeric_candidates: reg
                    .numeric_candidates
                    .iter()
                    .take(8)
                    .map(|n| SafeNumericExport {
                        width: n.width,
                        endian: n.endian,
                        distinct_values: n.distinct_values,
                        sample_values: n.sample_values.clone(),
                        possible_monotonic: n.possible_monotonic,
                        classification: n.classification.as_str(),
                        semantic_meaning: n.semantic_meaning,
                    })
                    .collect(),
                bit_variation: reg.bit_variation.as_ref().map(|b| SafeBitExport {
                    offset: b.offset,
                    distinct_values: b.distinct_values.clone(),
                    variable_bits: b.variable_bits.clone(),
                    constant_bits: b.constant_bits.clone(),
                    classification: b.classification.as_str(),
                }),
                text_candidate: reg.text_candidate.as_ref().map(|t| SafeTextExport {
                    offset: t.offset,
                    width: t.width,
                    printable_ratio: t.printable_ratio,
                    classification: t.classification.as_str(),
                }),
            })
            .collect(),
        correlated_region_pairs: r
            .correlated_region_pairs
            .iter()
            .take(32)
            .map(|(a0, a1, b0, b1)| format!("{a0}..{a1}<->{b0}..{b1}"))
            .collect(),
    }
}

/// Collect all observations from inventory groups.
pub fn flatten_observations(
    groups: &BTreeMap<u16, crate::message_inventory::MessageIdGroup>,
) -> Vec<MessageObservation> {
    let mut out = Vec::new();
    for g in groups.values() {
        out.extend(g.observations.iter().cloned());
    }
    out
}

pub fn external_name_label(id: u16) -> Option<(&'static str, EvidenceLabel)> {
    crate::messages::lookup_name(id).map(|n| (n, EvidenceLabel::ExternalReference))
}
