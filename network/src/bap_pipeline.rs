//! Offline composition: [`ByteSource`] → [`BapStreamDecoder`] → [`BapSession`].
//!
//! Works with [`crate::byte_source::MockByteSource`] or
//! [`crate::tcp_byte_source::TcpByteSource`]. Layers stay separate.

use crate::bap_session::{BapSession, BapSessionError, DecodedBapFrame};
use crate::byte_source::{ByteSource, ByteSourceError};
use crate::crypto::NonceDirection;
use crate::stream_framing::{BapStreamDecoder, RawBapFrame, StreamFramingError};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PipelineError {
    #[error("byte source: {0}")]
    Source(#[from] ByteSourceError),
    #[error("stream framing: {0}")]
    Stream(#[from] StreamFramingError),
    #[error("session: {0}")]
    Session(#[from] BapSessionError),
    #[error("direction list length {dirs} does not match recovered frames {frames}")]
    DirectionCountMismatch { dirs: usize, frames: usize },
}

/// Connects byte ingress, incremental framing, and session decode.
pub struct BapOfflinePipeline {
    decoder: BapStreamDecoder,
    session: BapSession,
}

impl BapOfflinePipeline {
    pub fn new(session_key: &[u8], session_nonce: &[u8]) -> Result<Self, PipelineError> {
        Ok(Self {
            decoder: BapStreamDecoder::new(),
            session: BapSession::new(session_key, session_nonce)?,
        })
    }

    pub fn session(&self) -> &BapSession {
        &self.session
    }

    pub fn client_to_server_counter(&self) -> u64 {
        self.session.client_to_server_counter()
    }

    pub fn server_to_client_counter(&self) -> u64 {
        self.session.server_to_client_counter()
    }

    /// Drain `source` through the stream decoder; call [`BapStreamDecoder::finish`].
    pub fn collect_raw_frames<S: ByteSource>(
        &mut self,
        source: &mut S,
    ) -> Result<Vec<RawBapFrame>, PipelineError> {
        let mut out = Vec::new();
        loop {
            match source.read()? {
                Some(chunk) => {
                    out.extend(self.decoder.push(&chunk)?);
                }
                None => break,
            }
        }
        self.decoder.finish()?;
        Ok(out)
    }

    /// Decode one complete raw frame with an explicit direction.
    pub fn decode_raw(
        &mut self,
        direction: NonceDirection,
        raw: &RawBapFrame,
    ) -> Result<DecodedBapFrame, PipelineError> {
        Ok(self.session.decode_frame(direction, &raw.raw_bytes)?)
    }

    /// All recovered frames share the same `direction`.
    pub fn run_unidirectional<S: ByteSource>(
        &mut self,
        source: &mut S,
        direction: NonceDirection,
    ) -> Result<Vec<DecodedBapFrame>, PipelineError> {
        let raws = self.collect_raw_frames(source)?;
        let mut decoded = Vec::with_capacity(raws.len());
        for raw in &raws {
            decoded.push(self.decode_raw(direction, raw)?);
        }
        Ok(decoded)
    }

    /// `directions[i]` applies to the i-th recovered frame (interleaved C↔S).
    pub fn run_directed<S: ByteSource>(
        &mut self,
        source: &mut S,
        directions: &[NonceDirection],
    ) -> Result<Vec<DecodedBapFrame>, PipelineError> {
        let raws = self.collect_raw_frames(source)?;
        if raws.len() != directions.len() {
            return Err(PipelineError::DirectionCountMismatch {
                dirs: directions.len(),
                frames: raws.len(),
            });
        }
        let mut decoded = Vec::with_capacity(raws.len());
        for (raw, dir) in raws.iter().zip(directions.iter()) {
            decoded.push(self.decode_raw(*dir, raw)?);
        }
        Ok(decoded)
    }
}
