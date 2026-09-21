//! Observation analyzer + report (M4.8).

use crate::observation::{
    is_known_codec_id, is_registry_id, message_id_label, ObservationEvent, ObservationSource,
};
use crate::observation_diff::{diff_against_scenario, ObservationDiff};
use crate::observation_scenarios::{scenario_startup, ScenarioKind};
use crate::observation_trace::ObservationTrace;
use crate::protocol_observation::{classify_frame, ObservationClass};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationReport {
    pub total_frames: u64,
    pub frames_by_direction: BTreeMap<String, u64>,
    pub frames_by_kind: BTreeMap<u8, u64>,
    pub message_ids: Vec<String>,
    pub lengths_by_message_id: BTreeMap<String, Vec<usize>>,
    pub appearance_order: Vec<String>,
    pub id_transitions: Vec<String>,
    pub states_observed: Vec<String>,
    pub unknown_frames: Vec<String>,
    pub classification_counts: BTreeMap<String, u64>,
    pub diffs: Vec<String>,
    pub notes: Vec<String>,
}

pub struct ObservationAnalyzer;

impl ObservationAnalyzer {
    pub fn analyze_trace(trace: &ObservationTrace) -> ObservationReport {
        let frames = trace.frames();
        let mut frames_by_direction: BTreeMap<String, u64> = BTreeMap::new();
        let mut frames_by_kind: BTreeMap<u8, u64> = BTreeMap::new();
        let mut lengths_by_message_id: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut appearance_order = Vec::new();
        let mut states_observed = Vec::new();
        let mut unknown_frames = Vec::new();
        let mut classification_counts: BTreeMap<String, u64> = BTreeMap::new();
        let mut prev_id: Option<u16> = None;
        let mut id_transitions = Vec::new();
        let mut message_ids_set: BTreeMap<u16, ()> = BTreeMap::new();

        for f in &frames {
            *frames_by_direction
                .entry(f.direction.clone())
                .or_insert(0) += 1;
            *frames_by_kind.entry(f.kind).or_insert(0) += 1;

            let classified = classify_frame(f);
            *classification_counts
                .entry(classified.class.as_str().into())
                .or_insert(0) += 1;

            if let Some(id) = f.message_id {
                message_ids_set.insert(id, ());
                let label = message_id_label(id);
                appearance_order.push(label.clone());
                lengths_by_message_id
                    .entry(label)
                    .or_default()
                    .push(f.body_len);
                if !is_registry_id(id) && !is_known_codec_id(id) {
                    unknown_frames.push(message_id_label(id));
                }
                if let Some(p) = prev_id {
                    id_transitions.push(format!(
                        "{}→{}",
                        message_id_label(p),
                        message_id_label(id)
                    ));
                }
                prev_id = Some(id);
            } else {
                appearance_order.push(format!("kind={}", f.kind));
            }

            if let Some(s) = &f.protocol_state {
                if !states_observed.contains(s) {
                    states_observed.push(s.clone());
                }
            }
        }

        for e in &trace.events {
            if let ObservationEvent::StateObserved { protocol_state, .. } = e {
                if !states_observed.contains(protocol_state) {
                    states_observed.push(protocol_state.clone());
                }
            }
        }

        let message_ids: Vec<String> = message_ids_set
            .keys()
            .copied()
            .map(message_id_label)
            .collect();

        let startup = scenario_startup();
        let diff = diff_against_scenario(&startup, trace);
        let diffs = if diff.is_empty() {
            Vec::new()
        } else {
            vec![diff.format_summary()]
        };

        let mut notes = vec![
            "Classification never auto-promotes Hypothesis→Confirmed.".into(),
            "Unknown IDs remain Unknown — no invented semantics.".into(),
        ];
        notes.extend(trace.notes.clone());

        let _ = ScenarioKind::Startup;
        let _ = ObservationClass::Observed;

        ObservationReport {
            total_frames: frames.len() as u64,
            frames_by_direction,
            frames_by_kind,
            message_ids,
            lengths_by_message_id,
            appearance_order,
            id_transitions,
            states_observed,
            unknown_frames,
            classification_counts,
            diffs,
            notes,
        }
    }

    pub fn analyze_source<S: ObservationSource>(
        source: &S,
    ) -> Result<(ObservationTrace, ObservationReport), crate::observation::ObservationError> {
        let events = source.events()?;
        let trace = ObservationTrace::new(events);
        let report = Self::analyze_trace(&trace);
        Ok((trace, report))
    }

    pub fn diff_startup(trace: &ObservationTrace) -> ObservationDiff {
        diff_against_scenario(&scenario_startup(), trace)
    }
}

impl std::fmt::Display for ObservationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "M4.8 OBSERVATION REPORT")?;
        writeln!(f, "total_frames: {}", self.total_frames)?;
        writeln!(f, "message_ids: {}", self.message_ids.join(", "))?;
        writeln!(f, "appearance_order: {}", self.appearance_order.join(" → "))?;
        writeln!(f, "unknown_frames: {}", self.unknown_frames.join(", "))?;
        writeln!(f, "classification_counts:")?;
        for (k, v) in &self.classification_counts {
            writeln!(f, "  {k}: {v}")?;
        }
        for d in &self.diffs {
            writeln!(f, "{d}")?;
        }
        Ok(())
    }
}
