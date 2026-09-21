//! Offline incremental BAP framing over a byte stream (no sockets / TCP).
//!
//! ```text
//! chunks → BapStreamDecoder → complete raw frames → BapSession
//! ```
//!
//! Incomplete data is **not** an error: `push` returns an empty vec and keeps
//! bytes buffered. Invalid magic / kind / oversized body **are** errors.

use crate::framing::{BAP_MAGIC, KIND_CLEAR, KIND_ENCRYPTED};
use thiserror::Error;

/// BAP outer header length: magic + kind + body_len.
pub const STREAM_HEADER_LEN: usize = 6;

/// Maximum accepted `body_len` (bytes). Prevents huge allocations from corrupt input.
///
/// Largest observed body in capture `20260529-003132` is on the order of a few
/// KiB; 4 MiB is a generous offline research ceiling, not a Destiny protocol claim.
pub const MAX_BODY_LEN: usize = 4 * 1024 * 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StreamFramingError {
    #[error("expected BAP magic 0x01, found 0x{0:02x}")]
    InvalidMagic(u8),
    #[error("unsupported BAP kind 0x{0:02x} (only 1 and 2 accepted by stream decoder)")]
    InvalidKind(u8),
    #[error("body_len {0} exceeds max {MAX_BODY_LEN}")]
    FrameTooLarge(u32),
    #[error("stream ended with {0} buffered byte(s); frame incomplete")]
    IncompleteAtEnd(usize),
}

/// One complete BAP frame extracted from the stream (owned bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawBapFrame {
    pub kind: u8,
    pub body: Vec<u8>,
    /// Full wire frame: `[0x01][kind][body_len BE][body...]`.
    pub raw_bytes: Vec<u8>,
}

impl RawBapFrame {
    pub fn body_len(&self) -> usize {
        self.body.len()
    }
}

/// Incremental offline BAP frame boundary detector.
#[derive(Debug, Default)]
pub struct BapStreamDecoder {
    buf: Vec<u8>,
    max_body_len: usize,
}

impl BapStreamDecoder {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            max_body_len: MAX_BODY_LEN,
        }
    }

    pub fn with_max_body_len(max_body_len: usize) -> Self {
        Self {
            buf: Vec::new(),
            max_body_len,
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    pub fn max_body_len(&self) -> usize {
        self.max_body_len
    }

    pub fn reset(&mut self) {
        self.buf.clear();
    }

    /// Append `bytes` and return every complete frame that can be carved out.
    ///
    /// Returns `Ok(vec![])` when more data is needed (incomplete header/body).
    pub fn push(&mut self, bytes: &[u8]) -> Result<Vec<RawBapFrame>, StreamFramingError> {
        if !bytes.is_empty() {
            self.buf.extend_from_slice(bytes);
        }
        self.drain_complete()
    }

    /// After the producer has no more bytes: require an empty buffer.
    pub fn finish(&mut self) -> Result<(), StreamFramingError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(StreamFramingError::IncompleteAtEnd(self.buf.len()))
        }
    }

    fn drain_complete(&mut self) -> Result<Vec<RawBapFrame>, StreamFramingError> {
        let mut out = Vec::new();
        loop {
            if self.buf.len() < STREAM_HEADER_LEN {
                break;
            }
            let magic = self.buf[0];
            if magic != BAP_MAGIC {
                return Err(StreamFramingError::InvalidMagic(magic));
            }
            let kind = self.buf[1];
            if kind != KIND_ENCRYPTED && kind != KIND_CLEAR {
                return Err(StreamFramingError::InvalidKind(kind));
            }
            let body_len = u32::from_be_bytes(self.buf[2..6].try_into().unwrap());
            if body_len as usize > self.max_body_len {
                return Err(StreamFramingError::FrameTooLarge(body_len));
            }
            let total = STREAM_HEADER_LEN + body_len as usize;
            if self.buf.len() < total {
                // Incomplete body — wait for more bytes.
                break;
            }
            let raw_bytes: Vec<u8> = self.buf.drain(..total).collect();
            let body = raw_bytes[STREAM_HEADER_LEN..].to_vec();
            out.push(RawBapFrame {
                kind,
                body,
                raw_bytes,
            });
        }
        Ok(out)
    }
}
