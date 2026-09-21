//! Adapter from `kallsyms/d1-re` `decrypted_bap.jsonl` records to project
//! [`EvidenceRecord`] values.
//!
//! Schema reference: `docs/networking/evidence-jsonl.md`.
//!
//! This module does **not** decrypt, derive keys, or load real captures.
//! It only maps already-decoded JSON fields into our offline pipeline.

use crate::framing::{clear_frame, BapFrame};
use crate::jsonl::{Direction, EvidenceRecord};
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error on line {line}: {source}")]
    Json {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid direction '{0}'")]
    BadDirection(String),
    #[error("invalid hex in payload_hex: {0}")]
    BadHex(String),
    #[error("bap_frame missing message id (unusable for EvidenceRecord)")]
    MissingMessageId,
}

#[derive(Debug, Deserialize)]
struct ExternalLine {
    kind: String,
    #[serde(default)]
    direction: Option<String>,
    #[serde(default)]
    frame_kind: Option<u8>,
    #[serde(default)]
    frame_index: Option<u64>,
    #[serde(default)]
    frame_ts: Option<f64>,
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    context: Option<u64>,
    #[serde(default)]
    payload_hex: Option<String>,
    #[serde(default)]
    error: Option<String>,
    // Tolerate all other external fields.
}

/// Convert one JSONL line. Returns `Ok(None)` for skipped records
/// (`bap_connection`, failed frames without `id`, blanks, comments).
pub fn adapt_line(line: &str) -> Result<Option<EvidenceRecord>, AdapterError> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return Ok(None);
    }
    let raw: ExternalLine = serde_json::from_str(line).map_err(|source| AdapterError::Json {
        line: 0,
        source,
    })?;
    adapt_parsed(raw)
}

fn adapt_parsed(raw: ExternalLine) -> Result<Option<EvidenceRecord>, AdapterError> {
    match raw.kind.as_str() {
        "bap_connection" => Ok(None),
        "bap_frame" => adapt_bap_frame(raw).map(Some),
        // Unknown record kinds: skip rather than fail the whole file.
        _ => Ok(None),
    }
}

fn adapt_bap_frame(raw: ExternalLine) -> Result<EvidenceRecord, AdapterError> {
    let direction_raw = raw
        .direction
        .as_deref()
        .ok_or_else(|| AdapterError::BadDirection("<missing>".into()))?;
    let direction = Direction::parse(direction_raw)
        .map_err(|_| AdapterError::BadDirection(direction_raw.to_string()))?;

    // Prefer logical message fields from clear parse or successful decrypt.
    let id = match raw.id {
        Some(id) if id <= u64::from(u16::MAX) => id as u16,
        Some(_) => return Err(AdapterError::MissingMessageId),
        None => {
            // Failed encrypted frame or truncated clear — not timeline-ready.
            if raw.error.is_some() {
                return Err(AdapterError::MissingMessageId);
            }
            return Err(AdapterError::MissingMessageId);
        }
    };

    let context = raw.context.unwrap_or(0) as u32;
    let payload = match raw.payload_hex.as_deref() {
        Some(h) => decode_hex(h)?,
        None => Vec::new(),
    };

    // Original wire `frame_kind` (1 vs 2) is documented in evidence-jsonl.md;
    // after successful decrypt the JSONL already exposes logical message fields.
    let _ = raw.frame_kind;
    let frame: BapFrame = clear_frame(id, context, &payload);

    let timestamp_ms = timestamp_ms_from_external(raw.frame_ts, raw.frame_index);

    Ok(EvidenceRecord {
        timestamp_ms,
        direction,
        frame,
    })
}

fn timestamp_ms_from_external(frame_ts: Option<f64>, frame_index: Option<u64>) -> u64 {
    if let Some(ts) = frame_ts {
        if ts.is_finite() && ts >= 0.0 {
            return (ts * 1000.0).floor() as u64;
        }
    }
    // Fallback when timing spans were unavailable in the decryptor run.
    frame_index.unwrap_or(0)
}

/// Parse a full external JSONL document into project evidence records.
/// Lines that adapt to `None` are skipped. Hard errors abort.
pub fn adapt_jsonl_str(input: &str) -> Result<Vec<EvidenceRecord>, AdapterError> {
    let mut out = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Validate JSON even for skip kinds.
        let value: Value = serde_json::from_str(line).map_err(|source| AdapterError::Json {
            line: idx + 1,
            source,
        })?;
        let raw: ExternalLine =
            serde_json::from_value(value).map_err(|source| AdapterError::Json {
                line: idx + 1,
                source,
            })?;
        match adapt_parsed(raw) {
            Ok(Some(rec)) => out.push(rec),
            Ok(None) => {}
            Err(AdapterError::MissingMessageId) => {
                // Soft-skip unusable frames (e.g. decrypt_failed without id).
            }
            Err(e) => return Err(map_line(e, idx + 1)),
        }
    }
    Ok(out)
}

pub fn adapt_jsonl_path(path: impl AsRef<std::path::Path>) -> Result<Vec<EvidenceRecord>, AdapterError> {
    let text = std::fs::read_to_string(path)?;
    adapt_jsonl_str(&text)
}

fn map_line(err: AdapterError, line: usize) -> AdapterError {
    match err {
        AdapterError::Json { source, .. } => AdapterError::Json { line, source },
        other => other,
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, AdapterError> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.len() % 2 != 0 {
        return Err(AdapterError::BadHex(format!("odd length: {s}")));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| AdapterError::BadHex(s[i..i + 2].to_string()))
        })
        .collect()
}
