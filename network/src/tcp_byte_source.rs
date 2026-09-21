//! TCP transport as a [`ByteSource`] (M2.10).
//!
//! Read-only. Delivers raw socket bytes; does **not** parse BAP.
//! Framing remains [`crate::stream_framing::BapStreamDecoder`].
//!
//! Uses blocking `std::net` so [`crate::bap_pipeline::BapOfflinePipeline`]
//! keeps working unchanged. No Tokio / no write / no live Bungie endpoints.

use crate::byte_source::{ByteSource, ByteSourceError};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::time::Duration;
use thiserror::Error;

/// Generic TCP endpoint (no vendor defaults).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpEndpoint {
    pub host: String,
    pub port: u16,
    pub connect_timeout: Duration,
    pub read_timeout: Option<Duration>,
}

impl TcpEndpoint {
    /// Build an endpoint. Does **not** default to any game service host.
    pub fn new(
        host: impl Into<String>,
        port: u16,
        connect_timeout: Duration,
        read_timeout: Option<Duration>,
    ) -> Result<Self, TcpByteSourceError> {
        let host = host.into();
        if host.trim().is_empty() {
            return Err(TcpByteSourceError::InvalidAddress(
                "host must be non-empty".into(),
            ));
        }
        if port == 0 {
            return Err(TcpByteSourceError::InvalidAddress(
                "port must be non-zero".into(),
            ));
        }
        if connect_timeout.is_zero() {
            return Err(TcpByteSourceError::InvalidTimeout(
                "connect_timeout must be non-zero".into(),
            ));
        }
        if let Some(rt) = read_timeout {
            if rt.is_zero() {
                return Err(TcpByteSourceError::InvalidTimeout(
                    "read_timeout must be non-zero when set".into(),
                ));
            }
        }
        Ok(Self {
            host,
            port,
            connect_timeout,
            read_timeout,
        })
    }

    /// Convenience for local tests (`127.0.0.1`).
    pub fn loopback(port: u16, connect_timeout: Duration) -> Result<Self, TcpByteSourceError> {
        Self::new("127.0.0.1", port, connect_timeout, None)
    }

    pub fn socket_addr_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TcpByteSourceError {
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("invalid timeout: {0}")]
    InvalidTimeout(String),
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("read failed: {0}")]
    ReadFailed(String),
    #[error("connection closed")]
    Closed,
    #[error("timeout: {0}")]
    Timeout(String),
}

impl From<TcpByteSourceError> for ByteSourceError {
    fn from(value: TcpByteSourceError) -> Self {
        ByteSourceError::Failed(value.to_string())
    }
}

/// Read-only TCP byte source implementing [`ByteSource`].
#[derive(Debug)]
pub struct TcpByteSource {
    stream: Option<TcpStream>,
    read_buf_size: usize,
}

impl TcpByteSource {
    const DEFAULT_READ_BUF: usize = 8192;

    /// Connect to `endpoint` (blocking, with connect timeout).
    pub fn connect(endpoint: &TcpEndpoint) -> Result<Self, TcpByteSourceError> {
        let addr_str = endpoint.socket_addr_string();
        let mut addrs = addr_str
            .to_socket_addrs()
            .map_err(|e| TcpByteSourceError::InvalidAddress(e.to_string()))?
            .peekable();
        if addrs.peek().is_none() {
            return Err(TcpByteSourceError::InvalidAddress(format!(
                "could not resolve {addr_str}"
            )));
        }
        let mut last_err = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, endpoint.connect_timeout) {
                Ok(stream) => {
                    if let Some(rt) = endpoint.read_timeout {
                        stream
                            .set_read_timeout(Some(rt))
                            .map_err(|e| TcpByteSourceError::ConnectionFailed(e.to_string()))?;
                    }
                    // Disable Nagle for test predictability (optional; harmless for research).
                    let _ = stream.set_nodelay(true);
                    return Ok(Self {
                        stream: Some(stream),
                        read_buf_size: Self::DEFAULT_READ_BUF,
                    });
                }
                Err(e) => {
                    last_err = Some(classify_connect_error(e));
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            TcpByteSourceError::ConnectionFailed(format!("unable to connect to {addr_str}"))
        }))
    }

    /// Wrap an already-connected stream (tests / advanced use).
    pub fn from_stream(stream: TcpStream) -> Self {
        let _ = stream.set_nodelay(true);
        Self {
            stream: Some(stream),
            read_buf_size: Self::DEFAULT_READ_BUF,
        }
    }

    pub fn set_read_buf_size(&mut self, size: usize) {
        self.read_buf_size = size.max(1);
    }

    /// Typed read (DATA / EOF / ERROR). Preferred over [`ByteSource::read`] when
    /// callers need [`TcpByteSourceError`] categories.
    pub fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, TcpByteSourceError> {
        let Some(stream) = self.stream.as_mut() else {
            return Err(TcpByteSourceError::Closed);
        };
        let mut buf = vec![0u8; self.read_buf_size];
        match stream.read(&mut buf) {
            Ok(0) => {
                // Clean EOF — drop stream so further reads report Closed/EOF consistently.
                self.stream = None;
                Ok(None)
            }
            Ok(n) => {
                buf.truncate(n);
                Ok(Some(buf))
            }
            Err(e) => {
                let kind = e.kind();
                if kind == std::io::ErrorKind::WouldBlock || kind == std::io::ErrorKind::TimedOut {
                    Err(TcpByteSourceError::Timeout(e.to_string()))
                } else {
                    Err(TcpByteSourceError::ReadFailed(e.to_string()))
                }
            }
        }
    }

    /// Close the connection (half-close write + drop). Idempotent.
    pub fn close(&mut self) {
        if let Some(stream) = self.stream.take() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    pub fn is_open(&self) -> bool {
        self.stream.is_some()
    }
}

impl Drop for TcpByteSource {
    fn drop(&mut self) {
        self.close();
    }
}

impl ByteSource for TcpByteSource {
    fn read(&mut self) -> Result<Option<Vec<u8>>, ByteSourceError> {
        if self.stream.is_none() {
            // Already saw EOF or closed → clean EOF for the pipeline.
            return Ok(None);
        }
        self.read_chunk().map_err(ByteSourceError::from)
    }
}

fn classify_connect_error(e: std::io::Error) -> TcpByteSourceError {
    let kind = e.kind();
    if kind == std::io::ErrorKind::TimedOut || kind == std::io::ErrorKind::WouldBlock {
        TcpByteSourceError::Timeout(e.to_string())
    } else {
        TcpByteSourceError::ConnectionFailed(e.to_string())
    }
}

/// Drain a [`ByteSource`] into [`crate::stream_framing::BapStreamDecoder`] only
/// (no session/crypto). Useful for TCP framing tests.
pub fn collect_raw_frames_from_source<S: ByteSource>(
    source: &mut S,
) -> Result<Vec<crate::stream_framing::RawBapFrame>, crate::bap_pipeline::PipelineError> {
    use crate::stream_framing::BapStreamDecoder;
    let mut decoder = BapStreamDecoder::new();
    let mut out = Vec::new();
    loop {
        match source.read()? {
            Some(chunk) => out.extend(decoder.push(&chunk)?),
            None => break,
        }
    }
    decoder.finish()?;
    Ok(out)
}

/// Local loopback helper for tests: listen on `127.0.0.1:0`, return bound address.
pub fn bind_loopback_listener() -> Result<(TcpListener, SocketAddr), TcpByteSourceError> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| TcpByteSourceError::ConnectionFailed(e.to_string()))?;
    let addr = listener
        .local_addr()
        .map_err(|e| TcpByteSourceError::ConnectionFailed(e.to_string()))?;
    Ok((listener, addr))
}

/// Spawn a one-shot local server that writes `chunks` then closes.
///
/// Returns the bound [`SocketAddr`]. Intended for unit tests only.
pub fn spawn_loopback_chunk_server(chunks: Vec<Vec<u8>>) -> Result<SocketAddr, TcpByteSourceError> {
    let (listener, addr) = bind_loopback_listener()?;
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_nodelay(true);
            for chunk in chunks {
                if stream.write_all(&chunk).is_err() {
                    break;
                }
            }
            let _ = stream.shutdown(Shutdown::Both);
        }
    });
    // Tiny yield so the accept thread is ready (best-effort).
    std::thread::sleep(Duration::from_millis(20));
    Ok(addr)
}
