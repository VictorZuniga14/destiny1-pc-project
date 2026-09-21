//! Project-owned evidence JSONL format for the offline analyzer.
//!
//! The project-owned schema lives in this module. The third-party
//! `decrypted_bap.jsonl` layout is documented in
//! `docs/networking/evidence-jsonl.md` and converted via
//! [`crate::evidence_adapter`].
//!
//! ## Minimal fields
//!
//! | Field | Required | Meaning |
//! | ----- | -------- | ------- |
//! | `timestamp_ms` | yes | Ordering key (milliseconds, synthetic or local clock) |
//! | `direction` | yes | `client_to_server` or `server_to_client` |
//! | `frame_hex` | one of | Full BAP frame as hex (preferred for framing tests) |
//! | `kind` + clear/encrypted fields | one of | Pre-parsed structured fields without raw frame |
//!
//! Unknown JSON keys are ignored (tolerant reader).

use crate::framing::{
    BapFrame, ClearBody, EncryptedBody, FrameBody, FrameKind, FramingError, KIND_CLEAR,
    KIND_ENCRYPTED,
};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum JsonlError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error on line {line}: {source}")]
    Json {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("invalid direction '{0}' (expected client_to_server or server_to_client)")]
    BadDirection(String),
    #[error("invalid hex: {0}")]
    BadHex(String),
    #[error("record missing both frame_hex and structured body fields")]
    IncompleteRecord,
    #[error("framing error: {0}")]
    Framing(#[from] FramingError),
    #[error("encrypted tag must be exactly 16 bytes")]
    BadTagLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    ClientToServer,
    ServerToClient,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientToServer => "client_to_server",
            Self::ServerToClient => "server_to_client",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Self::ClientToServer => "C → S",
            Self::ServerToClient => "S → C",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, JsonlError> {
        match raw {
            "client_to_server" | "c2s" | "C→S" | "C -> S" => Ok(Self::ClientToServer),
            "server_to_client" | "s2c" | "S→C" | "S -> C" => Ok(Self::ServerToClient),
            other => Err(JsonlError::BadDirection(other.to_string())),
        }
    }
}

/// One evidence line after parsing (project-owned schema).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceRecord {
    pub timestamp_ms: u64,
    pub direction: Direction,
    pub frame: BapFrame,
}

#[derive(Debug, Deserialize)]
struct RawRecord {
    timestamp_ms: u64,
    direction: String,
    #[serde(default)]
    frame_hex: Option<String>,
    #[serde(default)]
    kind: Option<u8>,
    #[serde(default)]
    message_id: Option<u16>,
    #[serde(default)]
    context: Option<u32>,
    #[serde(default)]
    payload_hex: Option<String>,
    #[serde(default)]
    tag_hex: Option<String>,
    #[serde(default)]
    ciphertext_hex: Option<String>,
    // Tolerate unknown fields via serde's default ignore of extras — actually
    // serde denies unknown by default only with deny_unknown_fields. Default
    // is to ignore unknown fields. Good.
}

impl EvidenceRecord {
    pub fn from_raw_json(line: &str) -> Result<Self, JsonlError> {
        let raw: RawRecord = serde_json::from_str(line).map_err(|source| JsonlError::Json {
            line: 0,
            source,
        })?;
        Self::from_raw(raw)
    }

    fn from_raw(raw: RawRecord) -> Result<Self, JsonlError> {
        let direction = Direction::parse(&raw.direction)?;
        let frame = if let Some(hex) = raw.frame_hex.as_deref() {
            let bytes = decode_hex(hex)?;
            BapFrame::parse(&bytes)?.0
        } else {
            structured_frame(&raw)?
        };
        Ok(Self {
            timestamp_ms: raw.timestamp_ms,
            direction,
            frame,
        })
    }
}

fn structured_frame(raw: &RawRecord) -> Result<BapFrame, JsonlError> {
    let kind_byte = raw.kind.ok_or(JsonlError::IncompleteRecord)?;
    match FrameKind::from_u8(kind_byte) {
        FrameKind::Clear => {
            let msg_id = raw.message_id.ok_or(JsonlError::IncompleteRecord)?;
            let context = raw.context.unwrap_or(0);
            let payload = match &raw.payload_hex {
                Some(h) => decode_hex(h)?,
                None => Vec::new(),
            };
            Ok(BapFrame {
                kind: FrameKind::Clear,
                body: FrameBody::Clear(ClearBody {
                    msg_id,
                    context,
                    payload,
                }),
            })
        }
        FrameKind::Encrypted => {
            let tag_bytes = decode_hex(raw.tag_hex.as_deref().unwrap_or(""))?;
            if tag_bytes.len() != 16 {
                return Err(JsonlError::BadTagLength);
            }
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&tag_bytes);
            let ciphertext = match &raw.ciphertext_hex {
                Some(h) => decode_hex(h)?,
                None => Vec::new(),
            };
            Ok(BapFrame {
                kind: FrameKind::Encrypted,
                body: FrameBody::Encrypted(EncryptedBody { tag, ciphertext }),
            })
        }
        FrameKind::Other(k) => {
            let body = match &raw.payload_hex {
                Some(h) => decode_hex(h)?,
                None => Vec::new(),
            };
            Ok(BapFrame {
                kind: FrameKind::Other(k),
                body: FrameBody::Opaque(body),
            })
        }
    }
}

/// Read project-owned JSONL evidence from a string (one JSON object per line).
pub fn parse_jsonl_str(input: &str) -> Result<Vec<EvidenceRecord>, JsonlError> {
    let mut out = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let raw: RawRecord = serde_json::from_str(line).map_err(|source| JsonlError::Json {
            line: idx + 1,
            source,
        })?;
        out.push(EvidenceRecord::from_raw(raw)?);
    }
    Ok(out)
}

/// Read project-owned JSONL from a file path.
pub fn parse_jsonl_path(path: impl AsRef<std::path::Path>) -> Result<Vec<EvidenceRecord>, JsonlError> {
    let text = std::fs::read_to_string(path)?;
    parse_jsonl_str(&text)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, JsonlError> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.len() % 2 != 0 {
        return Err(JsonlError::BadHex(format!("odd length: {s}")));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| JsonlError::BadHex(s[i..i + 2].to_string()))
        })
        .collect()
}

/// Encode bytes as lowercase hex (for fixture helpers / tests).
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn kind_clear() -> u8 {
    KIND_CLEAR
}

pub fn kind_encrypted() -> u8 {
    KIND_ENCRYPTED
}
