//! Multi-capture stability comparison (M2.9) — offline only.
//!
//! Compares [`CaptureValidationReport`] values. Does **not** invent captures,
//! change crypto rules, or open sockets.
//!
//! `STABLE` requires ≥2 **independent** captures with matching observations.
//! A single capture yields `OBSERVED` / `READY_FOR_EXTERNAL_CAPTURE`, never
//! `VERIFIED_MULTI_CAPTURE`.

use std::collections::{BTreeMap, BTreeSet};

/// How an invariant is classified across the compared set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvariantClass {
    /// Same value in ≥2 independent captures.
    Stable,
    /// Seen in exactly one capture when ≥2 were compared.
    CaptureSpecific,
    /// Differing values across captures.
    Divergent,
    /// Seen, but only one independent capture is available (not Stable).
    Observed,
    /// Not measured / insufficient evidence.
    Unknown,
}

impl InvariantClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "STABLE",
            Self::CaptureSpecific => "CAPTURE_SPECIFIC",
            Self::Divergent => "DIVERGENT",
            Self::Observed => "OBSERVED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Overall M2.9 result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultiCaptureStatus {
    /// ≥2 independent pipeline-ready captures compared successfully.
    VerifiedMultiCapture,
    /// Infrastructure ready; need another independent fixture.
    ReadyForExternalCapture,
    /// Cannot run (missing material, failed validation, etc.).
    Blocked,
}

impl MultiCaptureStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedMultiCapture => "VERIFIED_MULTI_CAPTURE",
            Self::ReadyForExternalCapture => "READY_FOR_EXTERNAL_CAPTURE",
            Self::Blocked => "BLOCKED",
        }
    }
}

/// Per-capture offline validation snapshot (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureValidationReport {
    pub capture_id: String,
    /// True only for distinct independent sources (not a repeated run of the same id).
    pub independent: bool,
    pub frames_seen: u32,
    pub clear_frames: u32,
    pub encrypted_frames: u32,
    pub decrypt_success: u32,
    pub decrypt_failed: u32,
    pub framing_valid: bool,
    pub nonce_state_valid: bool,
    pub gcm_validation: bool,
    /// Ordered message ids observed (clear + post-decrypt when available).
    pub message_ids: Vec<u16>,
    /// Prefix matching handshake/login when present.
    pub startup_sequence: Vec<u16>,
    pub client_to_server_frames: u32,
    pub server_to_client_frames: u32,
    /// Empty AAD used successfully for GCM in this capture (if measured).
    pub aad_empty_ok: Option<bool>,
    pub encrypted_frame_body_lengths: Vec<usize>,
    pub unknown_message_ids: Vec<u16>,
    pub keepalive_fa_count: u32,
    pub keepalive_fb_count: u32,
    /// Session CBC/HMAC of 0x1A validated offline (if measured for this capture).
    pub session_record_cbc_hmac_ok: Option<bool>,
    /// C→S nonce base = session⊕last_byte(1) hypothesis held (if measured).
    pub c2s_nonce_xor_last1_ok: Option<bool>,
    /// S→C nonce base = Identity held (if measured).
    pub s2c_nonce_identity_ok: Option<bool>,
}

impl CaptureValidationReport {
    pub fn pipeline_ok(&self) -> bool {
        self.framing_valid
            && self.nonce_state_valid
            && self.gcm_validation
            && self.decrypt_failed == 0
            && self.frames_seen > 0
            && self.encrypted_frames == self.decrypt_success
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantRow {
    pub name: String,
    pub class: InvariantClass,
    pub detail: String,
    pub captures_contributing: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiCaptureSummary {
    pub status: MultiCaptureStatus,
    pub independent_capture_count: u32,
    pub capture_reports: Vec<CaptureValidationReport>,
    pub invariants: Vec<InvariantRow>,
    pub notes: Vec<String>,
}

impl MultiCaptureSummary {
    pub fn verified_multi_capture(&self) -> bool {
        self.status == MultiCaptureStatus::VerifiedMultiCapture
    }
}

/// Compare capture reports. Does not re-run crypto.
pub fn compare_captures(reports: &[CaptureValidationReport]) -> MultiCaptureSummary {
    let independent: Vec<&CaptureValidationReport> = reports.iter().filter(|r| r.independent).collect();

    let mut notes = Vec::new();
    if reports.is_empty() {
        return MultiCaptureSummary {
            status: MultiCaptureStatus::Blocked,
            independent_capture_count: 0,
            capture_reports: vec![],
            invariants: vec![],
            notes: vec!["no capture reports supplied".into()],
        };
    }

    // Repeated runs of the same capture_id must not inflate independence.
    let unique_ids: BTreeSet<&str> = independent.iter().map(|r| r.capture_id.as_str()).collect();
    let n_unique = unique_ids.len() as u32;
    if independent.len() > unique_ids.len() {
        notes.push(
            "duplicate independent=true reports with the same capture_id were collapsed for stability claims"
                .into(),
        );
    }

    // Prefer one report per unique id (first wins) for stability classification.
    let mut by_id: BTreeMap<String, &CaptureValidationReport> = BTreeMap::new();
    for r in &independent {
        by_id.entry(r.capture_id.clone()).or_insert(*r);
    }
    let uniq: Vec<&CaptureValidationReport> = by_id.values().copied().collect();
    let n = uniq.len() as u32;

    let mut invariants = Vec::new();

    invariants.push(classify_bool(
        "BAP framing valid",
        &uniq,
        |r| Some(r.framing_valid),
        n,
    ));
    invariants.push(classify_bool(
        "AES-GCM decrypt (all encrypted frames)",
        &uniq,
        |r| Some(r.gcm_validation && r.decrypt_failed == 0 && r.encrypted_frames == r.decrypt_success),
        n,
    ));
    invariants.push(classify_bool(
        "nonce state / direction counters",
        &uniq,
        |r| Some(r.nonce_state_valid),
        n,
    ));
    invariants.push(classify_bool(
        "AAD empty (GCM)",
        &uniq,
        |r| r.aad_empty_ok,
        n,
    ));
    invariants.push(classify_bool(
        "C->S nonce base XOR-last-1",
        &uniq,
        |r| r.c2s_nonce_xor_last1_ok,
        n,
    ));
    invariants.push(classify_bool(
        "S->C nonce base Identity",
        &uniq,
        |r| r.s2c_nonce_identity_ok,
        n,
    ));
    invariants.push(classify_bool(
        "0x1A AES-CBC/HMAC session record",
        &uniq,
        |r| r.session_record_cbc_hmac_ok,
        n,
    ));
    invariants.push(classify_sequence(
        "startup sequence (msg_id prefix)",
        &uniq,
        |r| {
            if r.startup_sequence.is_empty() {
                None
            } else {
                Some(r.startup_sequence.clone())
            }
        },
        n,
    ));
    invariants.push(classify_bool(
        "keepalive 0xFA present",
        &uniq,
        |r| Some(r.keepalive_fa_count > 0),
        n,
    ));
    invariants.push(classify_bool(
        "keepalive 0xFB present",
        &uniq,
        |r| Some(r.keepalive_fb_count > 0),
        n,
    ));
    // Timing of keepalive is never claimed Stable from counts alone.
    invariants.push(InvariantRow {
        name: "keepalive timing (~interval)".into(),
        class: InvariantClass::Unknown,
        detail: "timing not compared in M2.9; interval remains capture-local OBSERVED if documented elsewhere"
            .into(),
        captures_contributing: 0,
    });

    let all_pipeline_ok = uniq.iter().all(|r| r.pipeline_ok());
    let status = if n == 0 {
        notes.push("no independent captures".into());
        MultiCaptureStatus::Blocked
    } else if n == 1 {
        notes.push(
            "only one independent pipeline-ready capture; cannot claim multi-capture stability"
                .into(),
        );
        if all_pipeline_ok {
            MultiCaptureStatus::ReadyForExternalCapture
        } else {
            MultiCaptureStatus::Blocked
        }
    } else if all_pipeline_ok {
        // ≥2 independent — check whether critical crypto/framing invariants are Stable.
        let critical_stable = invariants.iter().any(|i| {
            i.name.starts_with("BAP framing") && i.class == InvariantClass::Stable
        }) && invariants.iter().any(|i| {
            i.name.starts_with("AES-GCM") && i.class == InvariantClass::Stable
        });
        if critical_stable {
            MultiCaptureStatus::VerifiedMultiCapture
        } else {
            notes.push(
                "≥2 captures present but critical framing/GCM invariants are not STABLE"
                    .into(),
            );
            MultiCaptureStatus::Blocked
        }
    } else {
        notes.push("one or more captures failed pipeline validation".into());
        MultiCaptureStatus::Blocked
    };

    MultiCaptureSummary {
        status,
        independent_capture_count: n_unique.max(n),
        capture_reports: reports.to_vec(),
        invariants,
        notes,
    }
}

fn classify_bool(
    name: &str,
    reports: &[&CaptureValidationReport],
    f: impl Fn(&CaptureValidationReport) -> Option<bool>,
    n: u32,
) -> InvariantRow {
    let values: Vec<(String, bool)> = reports
        .iter()
        .filter_map(|r| f(r).map(|v| (r.capture_id.clone(), v)))
        .collect();
    let contributing = values.len() as u32;
    if values.is_empty() {
        return InvariantRow {
            name: name.into(),
            class: InvariantClass::Unknown,
            detail: "not measured".into(),
            captures_contributing: 0,
        };
    }
    if n <= 1 {
        let v = values[0].1;
        return InvariantRow {
            name: name.into(),
            class: InvariantClass::Observed,
            detail: format!("value={v} (single capture; CONFIRMED_FOR_CAPTURE only)"),
            captures_contributing: contributing,
        };
    }
    let set: BTreeSet<bool> = values.iter().map(|(_, v)| *v).collect();
    if set.len() == 1 {
        let v = *set.iter().next().unwrap();
        if contributing == n {
            InvariantRow {
                name: name.into(),
                class: InvariantClass::Stable,
                detail: format!("value={v}"),
                captures_contributing: contributing,
            }
        } else {
            InvariantRow {
                name: name.into(),
                class: InvariantClass::CaptureSpecific,
                detail: format!("value={v} measured in {contributing}/{n} captures"),
                captures_contributing: contributing,
            }
        }
    } else {
        InvariantRow {
            name: name.into(),
            class: InvariantClass::Divergent,
            detail: format!("values differ across captures: {values:?}"),
            captures_contributing: contributing,
        }
    }
}

fn classify_sequence(
    name: &str,
    reports: &[&CaptureValidationReport],
    f: impl Fn(&CaptureValidationReport) -> Option<Vec<u16>>,
    n: u32,
) -> InvariantRow {
    let values: Vec<(String, Vec<u16>)> = reports
        .iter()
        .filter_map(|r| f(r).map(|v| (r.capture_id.clone(), v)))
        .collect();
    let contributing = values.len() as u32;
    if values.is_empty() {
        return InvariantRow {
            name: name.into(),
            class: InvariantClass::Unknown,
            detail: "not measured".into(),
            captures_contributing: 0,
        };
    }
    if n <= 1 {
        return InvariantRow {
            name: name.into(),
            class: InvariantClass::Observed,
            detail: format!("seq={:?}", values[0].1),
            captures_contributing: contributing,
        };
    }
    let first = &values[0].1;
    let all_eq = values.iter().all(|(_, s)| s == first);
    if all_eq && contributing == n {
        InvariantRow {
            name: name.into(),
            class: InvariantClass::Stable,
            detail: format!("seq={first:?}"),
            captures_contributing: contributing,
        }
    } else if all_eq {
        InvariantRow {
            name: name.into(),
            class: InvariantClass::CaptureSpecific,
            detail: format!("seq={first:?} in {contributing}/{n}"),
            captures_contributing: contributing,
        }
    } else {
        InvariantRow {
            name: name.into(),
            class: InvariantClass::Divergent,
            detail: format!("sequences differ: {values:?}"),
            captures_contributing: contributing,
        }
    }
}

impl std::fmt::Display for MultiCaptureSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "M2.9 MULTI-CAPTURE STABILITY")?;
        writeln!(f)?;
        writeln!(f, "captures: {}", self.independent_capture_count)?;
        writeln!(f)?;
        for r in &self.capture_reports {
            let indep = if r.independent { "independent" } else { "repeat-run" };
            writeln!(f, "capture: {} ({indep})", r.capture_id)?;
            writeln!(f, "  frames: {}", r.frames_seen)?;
            writeln!(f, "  clear: {}", r.clear_frames)?;
            writeln!(f, "  encrypted: {}", r.encrypted_frames)?;
            writeln!(f, "  decrypt success: {}", r.decrypt_success)?;
            writeln!(f, "  decrypt failed: {}", r.decrypt_failed)?;
            writeln!(
                f,
                "  framing: {}",
                if r.framing_valid { "VALID" } else { "INVALID" }
            )?;
            writeln!(
                f,
                "  nonce state: {}",
                if r.nonce_state_valid { "VALID" } else { "INVALID" }
            )?;
            writeln!(
                f,
                "  gcm: {}",
                if r.gcm_validation { "VALID" } else { "INVALID" }
            )?;
            if !r.startup_sequence.is_empty() {
                let seq: Vec<String> = r
                    .startup_sequence
                    .iter()
                    .map(|id| format!("0x{id:02x}"))
                    .collect();
                writeln!(f, "  startup: {}", seq.join(" → "))?;
            }
            writeln!(f)?;
        }
        writeln!(f, "INVARIANTS")?;
        writeln!(f)?;
        for inv in &self.invariants {
            writeln!(f, "{}:", inv.name)?;
            writeln!(f, "  status: {}", inv.class.as_str())?;
            writeln!(f, "  captures: {}", inv.captures_contributing)?;
            writeln!(f, "  detail: {}", inv.detail)?;
            writeln!(f)?;
        }
        for n in &self.notes {
            writeln!(f, "note: {n}")?;
        }
        if !self.notes.is_empty() {
            writeln!(f)?;
        }
        writeln!(f, "RESULT:")?;
        writeln!(f, "  {}", self.status.as_str())?;
        Ok(())
    }
}

/// Canonical startup ids we look for as a prefix (not required to be universal).
pub const EXPECTED_STARTUP_HINT: &[u16] = &[0x1e, 0x1f, 0x19, 0x1a, 0x79, 0x7a];

/// Extract leading startup-like sequence from ordered message ids.
pub fn extract_startup_sequence(message_ids: &[u16]) -> Vec<u16> {
    let mut matched = Vec::new();
    for (i, &expected) in EXPECTED_STARTUP_HINT.iter().enumerate() {
        match message_ids.get(i) {
            Some(&id) if id == expected => matched.push(id),
            _ => break,
        }
    }
    if !matched.is_empty() {
        matched
    } else {
        message_ids.iter().take(6).copied().collect()
    }
}
