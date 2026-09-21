//! Safe observation trace serialize/deserialize (M4.8).
//!
//! Rejects or strips sensitive fields. Never stores secrets.

use crate::observation::{
    is_sensitive_key, ObservedFrame, ObservationError, ObservationEvent, SafeFingerprint,
    TRACE_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationTrace {
    pub trace_version: String,
    #[serde(default)]
    pub capture_id: Option<String>,
    #[serde(default)]
    pub notes: Vec<String>,
    pub events: Vec<ObservationEvent>,
}

impl ObservationTrace {
    pub fn new(events: Vec<ObservationEvent>) -> Self {
        Self {
            trace_version: TRACE_VERSION.into(),
            capture_id: None,
            notes: Vec::new(),
            events,
        }
    }

    pub fn frames(&self) -> Vec<&ObservedFrame> {
        self.events
            .iter()
            .filter_map(|e| match e {
                ObservationEvent::FrameObserved { frame } => Some(frame),
                _ => None,
            })
            .collect()
    }

    pub fn message_id_sequence(&self) -> Vec<u16> {
        self.frames().iter().filter_map(|f| f.message_id).collect()
    }
}

/// Compact frame row used in fixtures (metadata only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceFrameRow {
    pub connection_id: u64,
    pub frame_index: u64,
    pub direction: String,
    pub kind: u8,
    #[serde(default)]
    pub message_id: Option<String>,
    pub body_len: usize,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub relative_time_ms: Option<u64>,
    #[serde(default)]
    pub fingerprint: Option<String>,
    #[serde(default)]
    pub event: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TraceFileRaw {
    #[serde(default)]
    trace_version: Option<String>,
    #[serde(default)]
    capture_id: Option<String>,
    #[serde(default)]
    notes: Vec<String>,
    #[serde(default)]
    events: Vec<Value>,
    #[serde(default)]
    frames: Vec<Value>,
}

fn parse_msg_id(s: &str) -> Option<u16> {
    let t = s.trim().trim_start_matches("0x").trim_start_matches("0X");
    u16::from_str_radix(t, 16).ok()
}

fn reject_sensitive_object(v: &Value) -> Result<(), ObservationError> {
    match v {
        Value::Object(map) => {
            for (k, child) in map {
                if is_sensitive_key(k) {
                    return Err(ObservationError::SensitiveField(k.clone()));
                }
                reject_sensitive_object(child)?;
            }
            Ok(())
        }
        Value::Array(arr) => {
            for item in arr {
                reject_sensitive_object(item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn strip_sensitive_keys(v: &mut Value) {
    if let Value::Object(map) = v {
        let keys: Vec<String> = map.keys().cloned().collect();
        for k in keys {
            if is_sensitive_key(&k) {
                map.remove(&k);
            } else if let Some(child) = map.get_mut(&k) {
                strip_sensitive_keys(child);
            }
        }
    } else if let Value::Array(arr) = v {
        for item in arr {
            strip_sensitive_keys(item);
        }
    }
}

fn row_to_event(row: TraceFrameRow) -> ObservationEvent {
    let mid = row.message_id.as_deref().and_then(parse_msg_id);
    ObservationEvent::FrameObserved {
        frame: ObservedFrame {
            connection_id: row.connection_id,
            frame_index: row.frame_index,
            direction: row.direction,
            kind: row.kind,
            body_len: row.body_len,
            message_id: mid,
            protocol_state: row.state,
            relative_time_ms: row.relative_time_ms,
            fingerprint: row.fingerprint.map(SafeFingerprint),
        },
    }
}

fn value_to_event(mut v: Value) -> Result<ObservationEvent, ObservationError> {
    reject_sensitive_object(&v)?;
    strip_sensitive_keys(&mut v);
    // Prefer typed ObservationEvent JSON; else TraceFrameRow.
    if let Ok(ev) = serde_json::from_value::<ObservationEvent>(v.clone()) {
        return Ok(ev);
    }
    let row: TraceFrameRow = serde_json::from_value(v)
        .map_err(|e| ObservationError::Json(e.to_string()))?;
    Ok(row_to_event(row))
}

impl ObservationTrace {
    pub fn from_json_str(text: &str) -> Result<Self, ObservationError> {
        let mut root: Value =
            serde_json::from_str(text).map_err(|e| ObservationError::Json(e.to_string()))?;
        reject_sensitive_object(&root)?;
        strip_sensitive_keys(&mut root);
        let raw: TraceFileRaw =
            serde_json::from_value(root).map_err(|e| ObservationError::Json(e.to_string()))?;

        let mut events = Vec::new();
        for e in raw.events {
            events.push(value_to_event(e)?);
        }
        for f in raw.frames {
            events.push(value_to_event(f)?);
        }

        Ok(Self {
            trace_version: raw
                .trace_version
                .unwrap_or_else(|| TRACE_VERSION.into()),
            capture_id: raw.capture_id,
            notes: raw.notes,
            events,
        })
    }

    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, ObservationError> {
        let text = std::fs::read_to_string(path.as_ref())
            .map_err(|e| ObservationError::Io(e.to_string()))?;
        Self::from_json_str(&text)
    }

    pub fn to_json_pretty(&self) -> Result<String, ObservationError> {
        serde_json::to_string_pretty(self).map_err(|e| ObservationError::Json(e.to_string()))
    }
}
