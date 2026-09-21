//! BAP framing parser/serializer.
//!
//! Documented layout (`docs/networking/framing-bap.md`):
//!
//! ```text
//! [0x01][kind:u8][body_len:u32 BE][body...]
//! ```
//!
//! - `kind = 2`: `[msg_id:u16 BE][context:u32 BE][payload...]`
//! - `kind = 1`: `[tag:16][ciphertext...]` — opaque in framing; optional offline
//!   AES-GCM decrypt lives in `crypto::aead` (synthetic fixtures only)
//! - other kinds: opaque body bytes

use thiserror::Error;

/// Documented outer-frame magic / version byte.
pub const BAP_MAGIC: u8 = 0x01;

/// Cleartext frame kind.
pub const KIND_CLEAR: u8 = 2;

/// Encrypted frame kind (body is opaque in this crate).
pub const KIND_ENCRYPTED: u8 = 1;

const HEADER_LEN: usize = 6;
const CLEAR_HEADER_LEN: usize = 6;
const ENCRYPTED_TAG_LEN: usize = 16;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum FramingError {
    #[error("buffer too short for BAP header")]
    TruncatedHeader,
    #[error("expected BAP magic 0x01, found 0x{0:02x}")]
    BadMagic(u8),
    #[error("buffer too short for declared body length")]
    TruncatedBody,
    #[error("clear body shorter than msg_id+context (need {CLEAR_HEADER_LEN} bytes)")]
    TruncatedClearBody,
    #[error("encrypted body shorter than 16-byte tag")]
    TruncatedEncryptedTag,
    #[error("body length overflow")]
    LengthOverflow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Encrypted,
    Clear,
    Other(u8),
}

impl FrameKind {
    pub fn from_u8(value: u8) -> Self {
        match value {
            KIND_ENCRYPTED => Self::Encrypted,
            KIND_CLEAR => Self::Clear,
            other => Self::Other(other),
        }
    }

    pub fn as_u8(self) -> u8 {
        match self {
            Self::Encrypted => KIND_ENCRYPTED,
            Self::Clear => KIND_CLEAR,
            Self::Other(v) => v,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearBody {
    pub msg_id: u16,
    pub context: u32,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedBody {
    /// First 16 bytes of the encrypted body (AEAD tag in documented layout).
    pub tag: [u8; ENCRYPTED_TAG_LEN],
    /// Remaining ciphertext bytes — opaque; not decrypted by this crate.
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameBody {
    Clear(ClearBody),
    /// Encrypted body kept opaque (no crypto).
    Encrypted(EncryptedBody),
    /// Undocumented kind: raw body bytes.
    Opaque(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BapFrame {
    pub kind: FrameKind,
    pub body: FrameBody,
}

impl BapFrame {
    /// Parse one complete BAP frame from the start of `data`.
    /// Returns `(frame, bytes_consumed)`.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), FramingError> {
        if data.len() < HEADER_LEN {
            return Err(FramingError::TruncatedHeader);
        }
        let magic = data[0];
        if magic != BAP_MAGIC {
            return Err(FramingError::BadMagic(magic));
        }
        let kind_byte = data[1];
        let body_len = u32::from_be_bytes(data[2..6].try_into().unwrap()) as usize;
        let total = HEADER_LEN
            .checked_add(body_len)
            .ok_or(FramingError::LengthOverflow)?;
        if data.len() < total {
            return Err(FramingError::TruncatedBody);
        }
        let body_bytes = &data[HEADER_LEN..total];
        let kind = FrameKind::from_u8(kind_byte);
        let body = match kind {
            FrameKind::Clear => FrameBody::Clear(parse_clear_body(body_bytes)?),
            FrameKind::Encrypted => FrameBody::Encrypted(parse_encrypted_body(body_bytes)?),
            FrameKind::Other(_) => FrameBody::Opaque(body_bytes.to_vec()),
        };
        Ok((Self { kind, body }, total))
    }

    /// Parse consecutive frames until input is exhausted or magic breaks.
    pub fn parse_all(mut data: &[u8]) -> Result<Vec<Self>, FramingError> {
        let mut frames = Vec::new();
        while !data.is_empty() {
            if data[0] != BAP_MAGIC {
                break;
            }
            let (frame, consumed) = Self::parse(data)?;
            frames.push(frame);
            data = &data[consumed..];
        }
        Ok(frames)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, FramingError> {
        let body_bytes = serialize_body(&self.body)?;
        let body_len = u32::try_from(body_bytes.len()).map_err(|_| FramingError::LengthOverflow)?;
        let mut out = Vec::with_capacity(HEADER_LEN + body_bytes.len());
        out.push(BAP_MAGIC);
        out.push(self.kind.as_u8());
        out.extend_from_slice(&body_len.to_be_bytes());
        out.extend_from_slice(&body_bytes);
        Ok(out)
    }

    pub fn message_id(&self) -> Option<u16> {
        match &self.body {
            FrameBody::Clear(c) => Some(c.msg_id),
            _ => None,
        }
    }

    pub fn context(&self) -> Option<u32> {
        match &self.body {
            FrameBody::Clear(c) => Some(c.context),
            _ => None,
        }
    }

    pub fn payload_len(&self) -> usize {
        match &self.body {
            FrameBody::Clear(c) => c.payload.len(),
            FrameBody::Encrypted(e) => ENCRYPTED_TAG_LEN + e.ciphertext.len(),
            FrameBody::Opaque(b) => b.len(),
        }
    }
}

fn parse_clear_body(body: &[u8]) -> Result<ClearBody, FramingError> {
    if body.len() < CLEAR_HEADER_LEN {
        return Err(FramingError::TruncatedClearBody);
    }
    let msg_id = u16::from_be_bytes(body[0..2].try_into().unwrap());
    let context = u32::from_be_bytes(body[2..6].try_into().unwrap());
    let payload = body[CLEAR_HEADER_LEN..].to_vec();
    Ok(ClearBody {
        msg_id,
        context,
        payload,
    })
}

fn parse_encrypted_body(body: &[u8]) -> Result<EncryptedBody, FramingError> {
    if body.len() < ENCRYPTED_TAG_LEN {
        return Err(FramingError::TruncatedEncryptedTag);
    }
    let mut tag = [0u8; ENCRYPTED_TAG_LEN];
    tag.copy_from_slice(&body[..ENCRYPTED_TAG_LEN]);
    let ciphertext = body[ENCRYPTED_TAG_LEN..].to_vec();
    Ok(EncryptedBody { tag, ciphertext })
}

fn serialize_body(body: &FrameBody) -> Result<Vec<u8>, FramingError> {
    match body {
        FrameBody::Clear(c) => {
            let mut out = Vec::with_capacity(CLEAR_HEADER_LEN + c.payload.len());
            out.extend_from_slice(&c.msg_id.to_be_bytes());
            out.extend_from_slice(&c.context.to_be_bytes());
            out.extend_from_slice(&c.payload);
            Ok(out)
        }
        FrameBody::Encrypted(e) => {
            let mut out = Vec::with_capacity(ENCRYPTED_TAG_LEN + e.ciphertext.len());
            out.extend_from_slice(&e.tag);
            out.extend_from_slice(&e.ciphertext);
            Ok(out)
        }
        FrameBody::Opaque(b) => Ok(b.clone()),
    }
}

/// Helper to build a cleartext frame for tests/fixtures.
pub fn clear_frame(msg_id: u16, context: u32, payload: &[u8]) -> BapFrame {
    BapFrame {
        kind: FrameKind::Clear,
        body: FrameBody::Clear(ClearBody {
            msg_id,
            context,
            payload: payload.to_vec(),
        }),
    }
}

/// Helper to build an encrypted opaque frame for tests/fixtures.
pub fn encrypted_frame(tag: [u8; 16], ciphertext: &[u8]) -> BapFrame {
    BapFrame {
        kind: FrameKind::Encrypted,
        body: FrameBody::Encrypted(EncryptedBody {
            tag,
            ciphertext: ciphertext.to_vec(),
        }),
    }
}
