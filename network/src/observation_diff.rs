//! Structural observation diff engine (M4.8).
//!
//! Compares expected vs observed sequences. Does not generate protocol code.

use crate::observation::message_id_label;
use crate::observation_scenarios::ReferenceScenario;
use crate::observation_trace::ObservationTrace;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiffCategory {
    MissingFrame,
    UnexpectedFrame,
    DirectionMismatch,
    LengthMismatch,
    OrderMismatch,
    StateMismatch,
    UnexpectedClose,
    UnknownMessage,
    CryptoProcessingFailure,
}

impl DiffCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MissingFrame => "MissingFrame",
            Self::UnexpectedFrame => "UnexpectedFrame",
            Self::DirectionMismatch => "DirectionMismatch",
            Self::LengthMismatch => "LengthMismatch",
            Self::OrderMismatch => "OrderMismatch",
            Self::StateMismatch => "StateMismatch",
            Self::UnexpectedClose => "UnexpectedClose",
            Self::UnknownMessage => "UnknownMessage",
            Self::CryptoProcessingFailure => "CryptoProcessingFailure",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffEntry {
    pub category: DiffCategory,
    pub detail: String,
    #[serde(default)]
    pub expected: Option<String>,
    #[serde(default)]
    pub observed: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationDiff {
    pub expected_label: String,
    pub observed_label: String,
    pub expected_sequence: Vec<String>,
    pub observed_sequence: Vec<String>,
    pub entries: Vec<DiffEntry>,
}

impl ObservationDiff {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn format_summary(&self) -> String {
        let exp = self.expected_sequence.join(" → ");
        let obs = self.observed_sequence.join(" → ");
        let mut lines = vec![
            format!("EXPECTED: {exp}"),
            format!("OBSERVED: {obs}"),
        ];
        if self.entries.is_empty() {
            lines.push("DIFF: (none)".into());
        } else {
            for e in &self.entries {
                lines.push(format!("DIFF: {} — {}", e.category.as_str(), e.detail));
            }
        }
        lines.join("\n")
    }
}

pub fn diff_id_sequences(expected: &[u16], observed: &[u16]) -> ObservationDiff {
    let expected_sequence: Vec<String> = expected.iter().copied().map(message_id_label).collect();
    let observed_sequence: Vec<String> = observed.iter().copied().map(message_id_label).collect();
    let mut entries = Vec::new();

    let mut ei = 0usize;
    let mut oi = 0usize;
    while ei < expected.len() && oi < observed.len() {
        if expected[ei] == observed[oi] {
            ei += 1;
            oi += 1;
            continue;
        }
        // Look ahead for order mismatch / unexpected / missing
        if let Some(pos) = observed[oi..].iter().position(|x| *x == expected[ei]) {
            for u in &observed[oi..oi + pos] {
                entries.push(DiffEntry {
                    category: DiffCategory::UnexpectedFrame,
                    detail: format!("additional frame {}", message_id_label(*u)),
                    expected: None,
                    observed: Some(message_id_label(*u)),
                });
            }
            oi += pos;
            continue;
        }
        if let Some(pos) = expected[ei..].iter().position(|x| *x == observed[oi]) {
            for m in &expected[ei..ei + pos] {
                entries.push(DiffEntry {
                    category: DiffCategory::MissingFrame,
                    detail: format!("missing frame {}", message_id_label(*m)),
                    expected: Some(message_id_label(*m)),
                    observed: None,
                });
            }
            ei += pos;
            continue;
        }
        entries.push(DiffEntry {
            category: DiffCategory::OrderMismatch,
            detail: format!(
                "unexpected transition {} → {}",
                message_id_label(expected[ei]),
                message_id_label(observed[oi])
            ),
            expected: Some(message_id_label(expected[ei])),
            observed: Some(message_id_label(observed[oi])),
        });
        ei += 1;
        oi += 1;
    }
    while ei < expected.len() {
        entries.push(DiffEntry {
            category: DiffCategory::MissingFrame,
            detail: format!("missing frame {}", message_id_label(expected[ei])),
            expected: Some(message_id_label(expected[ei])),
            observed: None,
        });
        ei += 1;
    }
    while oi < observed.len() {
        entries.push(DiffEntry {
            category: DiffCategory::UnexpectedFrame,
            detail: format!("additional frame {}", message_id_label(observed[oi])),
            expected: None,
            observed: Some(message_id_label(observed[oi])),
        });
        oi += 1;
    }

    ObservationDiff {
        expected_label: "EXPECTED".into(),
        observed_label: "OBSERVED".into(),
        expected_sequence,
        observed_sequence,
        entries,
    }
}

pub fn diff_against_scenario(
    scenario: &ReferenceScenario,
    observed: &ObservationTrace,
) -> ObservationDiff {
    let obs_ids = observed.message_id_sequence();
    let mut diff = diff_id_sequences(&scenario.expected_ids, &obs_ids);
    diff.expected_label = scenario.name.clone();

    // Direction / length / state mismatches when both sides have frames with metadata
    let frames = observed.frames();
    for (i, exp_id) in scenario.expected_ids.iter().enumerate() {
        if let Some(f) = frames.get(i) {
            if let Some(mid) = f.message_id {
                if mid != *exp_id {
                    // already covered by sequence diff
                    continue;
                }
            }
            if let Some(state) = &f.protocol_state {
                if state.is_empty() {
                    entries_push_state(&mut diff, "empty state");
                }
            }
        }
    }

    // Unknown messages in observed
    for f in &frames {
        if let Some(id) = f.message_id {
            if !crate::observation::is_registry_id(id)
                && !crate::observation::is_known_codec_id(id)
            {
                diff.entries.push(DiffEntry {
                    category: DiffCategory::UnknownMessage,
                    detail: format!("unknown message {}", message_id_label(id)),
                    expected: None,
                    observed: Some(message_id_label(id)),
                });
            }
        }
    }

    diff
}

fn entries_push_state(diff: &mut ObservationDiff, detail: &str) {
    diff.entries.push(DiffEntry {
        category: DiffCategory::StateMismatch,
        detail: detail.into(),
        expected: None,
        observed: None,
    });
}

pub fn diff_directions(
    expected_dirs: &[(u16, &str)],
    observed: &ObservationTrace,
) -> Vec<DiffEntry> {
    let mut out = Vec::new();
    let frames = observed.frames();
    for (i, (id, dir)) in expected_dirs.iter().enumerate() {
        if let Some(f) = frames.get(i) {
            if f.message_id == Some(*id) && f.direction != *dir {
                out.push(DiffEntry {
                    category: DiffCategory::DirectionMismatch,
                    detail: format!(
                        "id {} expected dir {dir} got {}",
                        message_id_label(*id),
                        f.direction
                    ),
                    expected: Some((*dir).into()),
                    observed: Some(f.direction.clone()),
                });
            }
        }
    }
    out
}

pub fn diff_lengths(
    expected_lens: &[(u16, usize)],
    observed: &ObservationTrace,
) -> Vec<DiffEntry> {
    let mut out = Vec::new();
    for f in observed.frames() {
        if let Some(id) = f.message_id {
            if let Some((_, elen)) = expected_lens.iter().find(|(i, _)| *i == id) {
                if f.body_len != *elen {
                    out.push(DiffEntry {
                        category: DiffCategory::LengthMismatch,
                        detail: format!(
                            "id {} expected len {elen} got {}",
                            message_id_label(id),
                            f.body_len
                        ),
                        expected: Some(elen.to_string()),
                        observed: Some(f.body_len.to_string()),
                    });
                }
            }
        }
    }
    out
}
