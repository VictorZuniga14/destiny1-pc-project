//! BAP message codec (M4.4) — logical body encode/decode only.
//!
//! Operates on already-decoded `id` + `context` + `payload` (post-framing,
//! post-AES-GCM). Does **not** touch sockets, PCAP, or crypto primitives.
//!
//! Semantic discipline: field names are structural / external-reference only.
//! Never invents Destiny gameplay meaning.

use crate::jsonl::Direction;
use crate::messages::{classify, lookup_name};
use serde::Serialize;
use thiserror::Error;

/// Logical message envelope (no BAP outer framing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BapMessageEnvelope {
    pub id: u16,
    pub context: u32,
    pub direction: Direction,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("invalid payload length: {0}")]
    InvalidPayloadLength(String),
    #[error("invalid field length: {0}")]
    InvalidFieldLength(String),
    #[error("invalid record_len: {0}")]
    InvalidRecordLength(String),
    #[error("unexpected message id 0x{0:04x}")]
    UnexpectedMessageId(u16),
    #[error("malformed message: {0}")]
    MalformedMessage(String),
    #[error("unsupported message 0x{0:04x}")]
    UnsupportedMessage(u16),
}

/// Top-level decoded logical message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BapMessage {
    Known(KnownBapMessage),
    Unknown(UnknownBapMessage),
}

impl BapMessage {
    pub fn id(&self) -> u16 {
        match self {
            Self::Known(k) => k.id(),
            Self::Unknown(u) => u.id,
        }
    }

    pub fn context(&self) -> u32 {
        match self {
            Self::Known(k) => k.context(),
            Self::Unknown(u) => u.context,
        }
    }

    pub fn direction(&self) -> Direction {
        match self {
            Self::Known(k) => k.direction(),
            Self::Unknown(u) => u.direction,
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known(_))
    }
}

/// Unknown / not-yet-structured message — preserves raw payload in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownBapMessage {
    pub id: u16,
    pub context: u32,
    pub direction: Direction,
    pub payload: Vec<u8>,
}

impl std::fmt::Display for UnknownBapMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UnknownBapMessage{{id=0x{:04x}, context={}, dir={:?}, payload_len={}}}",
            self.id,
            self.context,
            self.direction,
            self.payload.len()
        )
    }
}

/// Opaque payload for messages with confirmed ID/direction but no safe field layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaquePayload {
    pub context: u32,
    pub direction: Direction,
    pub payload: Vec<u8>,
}

/// `0x1A` session-login-response structural body (M2.1–M2.3).
///
/// `prefix` meaning remains **UNKNOWN**. Does **not** decrypt CBC/HMAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionLoginResponseRecord {
    /// `u16` BE — meaning UNKNOWN.
    pub prefix: u16,
    pub record_len: u32,
    pub iv: [u8; 16],
    pub ciphertext: Vec<u8>,
    pub hmac: [u8; 32],
}

impl SessionLoginResponseRecord {
    pub const MIN_RECORD_LEN: u32 = 0x30; // IV(16) + HMAC(32) minimum; cipher may be 0

    pub fn validate_lengths(&self) -> Result<(), CodecError> {
        if self.record_len < Self::MIN_RECORD_LEN {
            return Err(CodecError::InvalidRecordLength(format!(
                "record_len {} < {}",
                self.record_len,
                Self::MIN_RECORD_LEN
            )));
        }
        let cipher_len = self.record_len as usize - 0x30;
        if self.ciphertext.len() != cipher_len {
            return Err(CodecError::InvalidFieldLength(format!(
                "ciphertext len {} != record_len-0x30 {}",
                self.ciphertext.len(),
                cipher_len
            )));
        }
        Ok(())
    }

    pub fn encode_payload(&self) -> Result<Vec<u8>, CodecError> {
        self.validate_lengths()?;
        let mut out = Vec::with_capacity(6 + self.record_len as usize);
        out.extend_from_slice(&self.prefix.to_be_bytes());
        out.extend_from_slice(&self.record_len.to_be_bytes());
        out.extend_from_slice(&self.iv);
        out.extend_from_slice(&self.ciphertext);
        out.extend_from_slice(&self.hmac);
        Ok(out)
    }

    pub fn decode_payload(payload: &[u8]) -> Result<Self, CodecError> {
        if payload.len() < 6 + Self::MIN_RECORD_LEN as usize {
            return Err(CodecError::InvalidPayloadLength(format!(
                "0x1A payload len {} too short",
                payload.len()
            )));
        }
        let prefix = u16::from_be_bytes([payload[0], payload[1]]);
        let record_len = u32::from_be_bytes([payload[2], payload[3], payload[4], payload[5]]);
        if record_len < Self::MIN_RECORD_LEN {
            return Err(CodecError::InvalidRecordLength(format!(
                "record_len {record_len} < {}",
                Self::MIN_RECORD_LEN
            )));
        }
        let need = 6 + record_len as usize;
        if payload.len() != need {
            return Err(CodecError::InvalidPayloadLength(format!(
                "payload len {} != 6+record_len {}",
                payload.len(),
                need
            )));
        }
        let material = &payload[6..];
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&material[0..16]);
        let cipher_len = record_len as usize - 0x30;
        let ciphertext = material[16..16 + cipher_len].to_vec();
        let mut hmac = [0u8; 32];
        hmac.copy_from_slice(&material[16 + cipher_len..16 + cipher_len + 32]);
        let rec = Self {
            prefix,
            record_len,
            iv,
            ciphertext,
            hmac,
        };
        rec.validate_lengths()?;
        Ok(rec)
    }
}

/// Known message variants — names from external matrix / neutral IDs.
///
/// External names (d1-re / message-matrix) are **EXTERNAL_REFERENCE** labels,
/// not additional Destiny semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KnownBapMessage {
    /// 0x1E — EXTERNAL_REFERENCE name: destiny-service-handshake-request
    DestinyServiceHandshakeRequest(OpaquePayload),
    /// 0x1F
    DestinyServiceHandshakeResponse(OpaquePayload),
    /// 0x19
    SessionLoginRequest(OpaquePayload),
    /// 0x1A — structured when payload matches M2.1 layout; else opaque.
    SessionLoginResponse {
        context: u32,
        direction: Direction,
        /// Structured parse when valid; always keep raw for roundtrip safety.
        record: Option<SessionLoginResponseRecord>,
        raw_payload: Vec<u8>,
    },
    /// 0x79 — plaintext body only (crypto already applied upstream)
    EncryptedHandshakeRequest(OpaquePayload),
    /// 0x7A
    EncryptedHandshakeStatus(OpaquePayload),
    /// 0x12E — neutral structural known ID
    Message0x12E(OpaquePayload),
    /// 0x12F
    Message0x12F(OpaquePayload),
    /// 0xFA
    Message0xFA(OpaquePayload),
    /// 0xFB
    Message0xFB(OpaquePayload),
}

impl KnownBapMessage {
    pub fn id(&self) -> u16 {
        match self {
            Self::DestinyServiceHandshakeRequest(_) => 0x1E,
            Self::DestinyServiceHandshakeResponse(_) => 0x1F,
            Self::SessionLoginRequest(_) => 0x19,
            Self::SessionLoginResponse { .. } => 0x1A,
            Self::EncryptedHandshakeRequest(_) => 0x79,
            Self::EncryptedHandshakeStatus(_) => 0x7A,
            Self::Message0x12E(_) => 0x12E,
            Self::Message0x12F(_) => 0x12F,
            Self::Message0xFA(_) => 0xFA,
            Self::Message0xFB(_) => 0xFB,
        }
    }

    pub fn context(&self) -> u32 {
        match self {
            Self::DestinyServiceHandshakeRequest(o)
            | Self::DestinyServiceHandshakeResponse(o)
            | Self::SessionLoginRequest(o)
            | Self::EncryptedHandshakeRequest(o)
            | Self::EncryptedHandshakeStatus(o)
            | Self::Message0x12E(o)
            | Self::Message0x12F(o)
            | Self::Message0xFA(o)
            | Self::Message0xFB(o) => o.context,
            Self::SessionLoginResponse { context, .. } => *context,
        }
    }

    pub fn direction(&self) -> Direction {
        match self {
            Self::DestinyServiceHandshakeRequest(o)
            | Self::DestinyServiceHandshakeResponse(o)
            | Self::SessionLoginRequest(o)
            | Self::EncryptedHandshakeRequest(o)
            | Self::EncryptedHandshakeStatus(o)
            | Self::Message0x12E(o)
            | Self::Message0x12F(o)
            | Self::Message0xFA(o)
            | Self::Message0xFB(o) => o.direction,
            Self::SessionLoginResponse { direction, .. } => *direction,
        }
    }

    pub fn external_name(&self) -> Option<&'static str> {
        lookup_name(self.id())
    }
}

/// IDs with dedicated known codecs (opaque or structured).
pub const CODEC_KNOWN_IDS: &[u16] = &[
    0x1E, 0x1F, 0x19, 0x1A, 0x79, 0x7A, 0x12E, 0x12F, 0xFA, 0xFB,
];

pub fn has_known_codec(id: u16) -> bool {
    CODEC_KNOWN_IDS.contains(&id)
}

fn opaque(env: &BapMessageEnvelope) -> OpaquePayload {
    OpaquePayload {
        context: env.context,
        direction: env.direction,
        payload: env.payload.clone(),
    }
}

/// Decode logical message from envelope (payload = body after id/context).
pub fn decode_message(env: &BapMessageEnvelope) -> Result<BapMessage, CodecError> {
    match env.id {
        0x1E => Ok(BapMessage::Known(KnownBapMessage::DestinyServiceHandshakeRequest(
            opaque(env),
        ))),
        0x1F => Ok(BapMessage::Known(
            KnownBapMessage::DestinyServiceHandshakeResponse(opaque(env)),
        )),
        0x19 => Ok(BapMessage::Known(KnownBapMessage::SessionLoginRequest(
            opaque(env),
        ))),
        0x1A => {
            let record = SessionLoginResponseRecord::decode_payload(&env.payload).ok();
            Ok(BapMessage::Known(KnownBapMessage::SessionLoginResponse {
                context: env.context,
                direction: env.direction,
                record,
                raw_payload: env.payload.clone(),
            }))
        }
        0x79 => Ok(BapMessage::Known(KnownBapMessage::EncryptedHandshakeRequest(
            opaque(env),
        ))),
        0x7A => Ok(BapMessage::Known(KnownBapMessage::EncryptedHandshakeStatus(
            opaque(env),
        ))),
        0x12E => Ok(BapMessage::Known(KnownBapMessage::Message0x12E(opaque(env)))),
        0x12F => Ok(BapMessage::Known(KnownBapMessage::Message0x12F(opaque(env)))),
        0xFA => Ok(BapMessage::Known(KnownBapMessage::Message0xFA(opaque(env)))),
        0xFB => Ok(BapMessage::Known(KnownBapMessage::Message0xFB(opaque(env)))),
        _ => Ok(BapMessage::Unknown(UnknownBapMessage {
            id: env.id,
            context: env.context,
            direction: env.direction,
            payload: env.payload.clone(),
        })),
    }
}

/// Encode logical body only (no magic/kind/body_len).
pub fn encode_message(message: &BapMessage) -> Result<Vec<u8>, CodecError> {
    match message {
        BapMessage::Unknown(u) => Ok(u.payload.clone()),
        BapMessage::Known(k) => match k {
            KnownBapMessage::DestinyServiceHandshakeRequest(o)
            | KnownBapMessage::DestinyServiceHandshakeResponse(o)
            | KnownBapMessage::SessionLoginRequest(o)
            | KnownBapMessage::EncryptedHandshakeRequest(o)
            | KnownBapMessage::EncryptedHandshakeStatus(o)
            | KnownBapMessage::Message0x12E(o)
            | KnownBapMessage::Message0x12F(o)
            | KnownBapMessage::Message0xFA(o)
            | KnownBapMessage::Message0xFB(o) => Ok(o.payload.clone()),
            KnownBapMessage::SessionLoginResponse {
                record,
                raw_payload,
                ..
            } => {
                if let Some(rec) = record {
                    rec.encode_payload()
                } else {
                    Ok(raw_payload.clone())
                }
            }
        },
    }
}

/// Decode from [`crate::bap_session::DecodedBapFrame`].
pub fn decode_from_frame(
    frame: &crate::bap_session::DecodedBapFrame,
    direction: Direction,
) -> Result<BapMessage, CodecError> {
    use crate::bap_session::DecodedBapFrame;
    match frame {
        DecodedBapFrame::Clear {
            msg_id,
            context,
            payload,
        } => decode_message(&BapMessageEnvelope {
            id: *msg_id,
            context: *context,
            direction,
            payload: payload.clone(),
        }),
        DecodedBapFrame::Decrypted {
            msg_id,
            context,
            payload,
            ..
        } => {
            let id = msg_id.ok_or_else(|| {
                CodecError::MalformedMessage("decrypted plaintext missing msg_id".into())
            })?;
            let ctx = context.ok_or_else(|| {
                CodecError::MalformedMessage("decrypted plaintext missing context".into())
            })?;
            decode_message(&BapMessageEnvelope {
                id,
                context: ctx,
                direction,
                payload: payload.clone(),
            })
        }
        DecodedBapFrame::Opaque { kind, .. } => Err(CodecError::MalformedMessage(format!(
            "opaque frame kind=0x{kind:02x} has no logical message"
        ))),
    }
}

/// Strict 0x1A structural validation (for capture verify / tests).
pub fn validate_session_login_response_payload(payload: &[u8]) -> Result<SessionLoginResponseRecord, CodecError> {
    SessionLoginResponseRecord::decode_payload(payload)
}

/// Build envelope helpers for tests / local server.
pub fn envelope(id: u16, context: u32, direction: Direction, payload: &[u8]) -> BapMessageEnvelope {
    BapMessageEnvelope {
        id,
        context,
        direction,
        payload: payload.to_vec(),
    }
}

/// Round-trip check for any message.
pub fn roundtrip_ok(message: &BapMessage) -> Result<bool, CodecError> {
    let encoded = encode_message(message)?;
    let again = decode_message(&BapMessageEnvelope {
        id: message.id(),
        context: message.context(),
        direction: message.direction(),
        payload: encoded,
    })?;
    // Compare by re-encoding (Unknown / opaque payloads are byte-identical).
    Ok(encode_message(&again)? == encode_message(message)?)
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeCodecMeta {
    pub id: String,
    pub known_codec: bool,
    pub matrix_name: Option<&'static str>,
    pub matrix_class: String,
}

pub fn safe_codec_meta(id: u16) -> SafeCodecMeta {
    let c = classify(id);
    SafeCodecMeta {
        id: format!("0x{id:04x}"),
        known_codec: has_known_codec(id),
        matrix_name: c.name(),
        matrix_class: if c.is_known() {
            "EXTERNAL_REFERENCE".into()
        } else {
            "UNKNOWN".into()
        },
    }
}
