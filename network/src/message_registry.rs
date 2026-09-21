//! Central BAP message registry (M4.4).
//!
//! Reuses [`crate::messages`] names and [`crate::protocol_spec::EXPECTED_MESSAGE_IDS`].
//! Does not duplicate M3.1 inventory observations.

use crate::jsonl::Direction;
use crate::message_codec::{has_known_codec, CODEC_KNOWN_IDS};
use crate::messages::{classify, lookup_name};
use crate::protocol_spec::EXPECTED_MESSAGE_IDS;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum CodecStatus {
    ConfirmedStructure,
    OpaqueKnown,
    Unknown,
}

impl CodecStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConfirmedStructure => "CONFIRMED_STRUCTURE",
            Self::OpaqueKnown => "OPAQUE_KNOWN",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RegistryEntry {
    pub id: u16,
    pub id_hex: String,
    pub direction: String,
    pub name: Option<&'static str>,
    pub codec: String,
    pub status: String,
    pub length_constraints: String,
    pub name_source: String,
}

/// Typical observed directions from startup / keepalive evidence (not exclusive).
fn typical_direction(id: u16) -> &'static str {
    match id {
        0x1E | 0x19 | 0x79 | 0x12E | 0xFA | 0x0A | 0x0C | 0x12 | 0x15 | 0x17 | 0x20 | 0x7B
        | 0xAB | 0x10 | 0x2A => "C2S",
        0x1F | 0x1A | 0x7A | 0x12F | 0xFB | 0x0B | 0x0D | 0x13 | 0x16 | 0x18 | 0x21 | 0x11
        | 0x2B => "S2C",
        _ => "UNKNOWN",
    }
}

fn codec_name(id: u16) -> &'static str {
    match id {
        0x1E => "DestinyServiceHandshakeRequest",
        0x1F => "DestinyServiceHandshakeResponse",
        0x19 => "SessionLoginRequest",
        0x1A => "SessionLoginResponse",
        0x79 => "EncryptedHandshakeRequest",
        0x7A => "EncryptedHandshakeStatus",
        0x12E => "Message0x12E",
        0x12F => "Message0x12F",
        0xFA => "Message0xFA",
        0xFB => "Message0xFB",
        _ => "Unknown",
    }
}

fn status_for(id: u16) -> CodecStatus {
    if id == 0x1A {
        CodecStatus::ConfirmedStructure
    } else if has_known_codec(id) {
        CodecStatus::OpaqueKnown
    } else {
        CodecStatus::Unknown
    }
}

fn length_constraints(id: u16) -> &'static str {
    match id {
        0x1A => "payload_len == 6 + record_len; record_len >= 0x30; IV=16; HMAC=32",
        _ if has_known_codec(id) => "opaque payload (any length including empty)",
        _ => "unknown / preserve raw",
    }
}

pub fn registry_entry(id: u16) -> RegistryEntry {
    let name = lookup_name(id);
    let status = status_for(id);
    RegistryEntry {
        id,
        id_hex: format!("0x{id:04x}"),
        direction: typical_direction(id).into(),
        name,
        codec: codec_name(id).into(),
        status: status.as_str().into(),
        length_constraints: length_constraints(id).into(),
        name_source: if name.is_some() {
            "EXTERNAL_REFERENCE".into()
        } else {
            "NONE".into()
        },
    }
}

pub fn full_registry() -> Vec<RegistryEntry> {
    EXPECTED_MESSAGE_IDS.iter().copied().map(registry_entry).collect()
}

pub fn validate_registry() -> Result<(), String> {
    let ids = EXPECTED_MESSAGE_IDS;
    if ids.len() != 28 {
        return Err(format!("expected 28 IDs, got {}", ids.len()));
    }
    let set: BTreeSet<_> = ids.iter().copied().collect();
    if set.len() != ids.len() {
        return Err("duplicate IDs in EXPECTED_MESSAGE_IDS".into());
    }
    for id in CODEC_KNOWN_IDS {
        if !set.contains(id) && *id != 0x12D {
            // all codec IDs except possibly extras should be in the 28
            if !EXPECTED_MESSAGE_IDS.contains(id) {
                return Err(format!("codec id 0x{id:04x} missing from expected set"));
            }
        }
    }
    for id in ids {
        let _ = classify(*id);
        let e = registry_entry(*id);
        if e.direction != "C2S" && e.direction != "S2C" && e.direction != "UNKNOWN" {
            return Err(format!("bad direction for 0x{id:04x}"));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeMessageRegistryExport {
    pub version: String,
    pub message_count: usize,
    pub entries: Vec<SafeRegistryEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeRegistryEntry {
    pub id: String,
    pub direction: String,
    pub known: bool,
    pub codec: String,
    pub length_constraints: String,
    pub status: String,
    pub name: Option<&'static str>,
    pub name_source: String,
}

pub fn to_safe_export() -> SafeMessageRegistryExport {
    let entries: Vec<_> = full_registry()
        .into_iter()
        .map(|e| SafeRegistryEntry {
            id: e.id_hex,
            direction: e.direction,
            known: e.status != CodecStatus::Unknown.as_str(),
            codec: e.codec,
            length_constraints: e.length_constraints,
            status: e.status,
            name: e.name,
            name_source: e.name_source,
        })
        .collect();
    SafeMessageRegistryExport {
        version: "0.1".into(),
        message_count: entries.len(),
        entries,
    }
}

/// Direction hint as [`Direction`] when typical is known.
pub fn typical_wire_direction(id: u16) -> Option<Direction> {
    match typical_direction(id) {
        "C2S" => Some(Direction::ClientToServer),
        "S2C" => Some(Direction::ServerToClient),
        _ => None,
    }
}
