//! Offline byte ingress for the BAP pipeline.
//!
//! ```text
//! ByteSource → BapStreamDecoder → BapSession
//! ```
//!
//! Implementations: [`MockByteSource`] (offline) and
//! [`crate::tcp_byte_source::TcpByteSource`] (M2.10, local/research TCP read-only).

use std::collections::VecDeque;
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ByteSourceError {
    #[error("byte source failed: {0}")]
    Failed(String),
}

/// Sync offline source of byte chunks.
///
/// - `Ok(Some(bytes))` — data available
/// - `Ok(None)` — clean EOF
/// - `Err(_)` — source failure (must not be treated as EOF)
pub trait ByteSource {
    fn read(&mut self) -> Result<Option<Vec<u8>>, ByteSourceError>;
}

/// Deterministic in-memory chunk queue for tests and capture replay.
#[derive(Debug, Clone)]
pub struct MockByteSource {
    queue: VecDeque<Result<Vec<u8>, ByteSourceError>>,
}

impl MockByteSource {
    /// Queue of successful data chunks; after the last, `read` returns `Ok(None)`.
    pub fn new(chunks: impl IntoIterator<Item = Vec<u8>>) -> Self {
        Self {
            queue: chunks.into_iter().map(Ok).collect(),
        }
    }

    /// Queue of explicit results (data or intentional errors).
    pub fn from_results(
        items: impl IntoIterator<Item = Result<Vec<u8>, ByteSourceError>>,
    ) -> Self {
        Self {
            queue: items.into_iter().collect(),
        }
    }

    pub fn remaining(&self) -> usize {
        self.queue.len()
    }
}

impl ByteSource for MockByteSource {
    fn read(&mut self) -> Result<Option<Vec<u8>>, ByteSourceError> {
        match self.queue.pop_front() {
            None => Ok(None),
            Some(Ok(bytes)) => Ok(Some(bytes)),
            Some(Err(e)) => Err(e),
        }
    }
}

/// Split `stream` into chunks cycling through `sizes` (skips zero sizes).
pub fn chunk_stream(stream: &[u8], sizes: &[usize]) -> Vec<Vec<u8>> {
    let sizes: Vec<usize> = sizes.iter().copied().filter(|&n| n > 0).collect();
    let sizes = if sizes.is_empty() { vec![1] } else { sizes };
    let mut out = Vec::new();
    let mut offset = 0;
    let mut i = 0;
    while offset < stream.len() {
        let n = sizes[i % sizes.len()].min(stream.len() - offset);
        i += 1;
        out.push(stream[offset..offset + n].to_vec());
        offset += n;
    }
    out
}

/// Default chunk schedule for offline capture replay (same spirit as M2.7).
pub const DEFAULT_PIPELINE_CHUNK_SIZES: &[usize] =
    &[1, 2, 3, 7, 13, 31, 64, 127, 256, 17, 5];
