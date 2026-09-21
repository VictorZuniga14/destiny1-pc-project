//! External client compatibility boundary (M4.7) — localhost TCP ingress only.
//!
//! Accepts bytes from an external BAP client harness, feeds [`BapStreamDecoder`],
//! and delivers frames to [`StatefulBapSession`]. Does **not** parse BAP itself,
//! connect to Bungie/Destiny, or store secrets.

use crate::bap_session::{BapSession, BapSessionError};
use crate::crypto::NonceDirection;
use crate::jsonl::Direction as JsonlDirection;
use crate::message_codec::{encode_message, BapMessage, KnownBapMessage, OpaquePayload};
use crate::protocol_state::{ProtocolState, ProtocolStateError, TransitionResult};
use crate::response_policy::ResponseAction;
use crate::stateful_bap_session::{StatefulBapSession, SyntheticSessionMaterial};
use crate::stream_framing::{BapStreamDecoder, RawBapFrame, StreamFramingError, MAX_BODY_LEN};
use crate::test_crypto_material::{SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use thiserror::Error;

pub const DEFAULT_MAX_CONNECTIONS: usize = 8;
pub const DEFAULT_MAX_READ_CHUNK: usize = 4096;
pub const DEFAULT_MAX_BUFFERED: usize = MAX_BODY_LEN + 64;
pub const DEFAULT_MAX_FRAMES_PER_ITER: usize = 64;

/// TCP / boundary lifecycle — separate from BAP [`ProtocolState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExternalConnectionState {
    Accepted,
    Reading,
    ProtocolActive,
    Closing,
    Closed,
}

impl ExternalConnectionState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "ACCEPTED",
            Self::Reading => "READING",
            Self::ProtocolActive => "PROTOCOL_ACTIVE",
            Self::Closing => "CLOSING",
            Self::Closed => "CLOSED",
        }
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BoundaryError {
    #[error("external bind/connect rejected: {0}")]
    ExternalEndpoint(String),
    #[error("bind failed: {0}")]
    Bind(String),
    #[error("accept failed: {0}")]
    Accept(String),
    #[error("io: {0}")]
    Io(String),
    #[error("limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("framing: {0}")]
    Framing(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("already closed")]
    AlreadyClosed,
    #[error("not connected")]
    NotConnected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorCategory {
    Framing,
    Protocol,
    Crypto,
    Limit,
    Io,
    Other,
}

impl ErrorCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Framing => "Framing",
            Self::Protocol => "Protocol",
            Self::Crypto => "Crypto",
            Self::Limit => "Limit",
            Self::Io => "Io",
            Self::Other => "Other",
        }
    }
}

/// Safe boundary events — metadata only (no payloads/keys/nonce).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalBoundaryEvent {
    ConnectionAccepted { connection_id: u64 },
    BytesReceived { connection_id: u64, byte_len: usize },
    FrameRecovered {
        connection_id: u64,
        frame_index: u64,
        direction: String,
        kind: u8,
        body_len: usize,
    },
    FrameRejected {
        connection_id: u64,
        category: String,
        detail: String,
    },
    ProtocolEvent {
        connection_id: u64,
        protocol_state: String,
        label: String,
    },
    ConnectionError {
        connection_id: u64,
        category: String,
        detail: String,
    },
    ConnectionClosed {
        connection_id: u64,
        reason: String,
    },
}

impl ExternalBoundaryEvent {
    pub fn safe_label(&self) -> String {
        match self {
            Self::ConnectionAccepted { connection_id } => {
                format!("ConnectionAccepted id={connection_id}")
            }
            Self::BytesReceived {
                connection_id,
                byte_len,
            } => format!("BytesReceived id={connection_id} len={byte_len}"),
            Self::FrameRecovered {
                connection_id,
                frame_index,
                direction,
                kind,
                body_len,
            } => format!(
                "FrameRecovered id={connection_id} idx={frame_index} dir={direction} kind={kind} body_len={body_len}"
            ),
            Self::FrameRejected {
                connection_id,
                category,
                detail,
            } => format!("FrameRejected id={connection_id} cat={category} detail={detail}"),
            Self::ProtocolEvent {
                connection_id,
                protocol_state,
                label,
            } => format!("ProtocolEvent id={connection_id} state={protocol_state} {label}"),
            Self::ConnectionError {
                connection_id,
                category,
                detail,
            } => format!("ConnectionError id={connection_id} cat={category} detail={detail}"),
            Self::ConnectionClosed {
                connection_id,
                reason,
            } => format!("ConnectionClosed id={connection_id} reason={reason}"),
        }
    }
}

pub fn assert_localhost_bind(addr: SocketAddr) -> Result<(), BoundaryError> {
    match addr.ip() {
        IpAddr::V4(v4) if v4 == Ipv4Addr::LOCALHOST => Ok(()),
        IpAddr::V6(v6) if v6.is_loopback() => Ok(()),
        other => Err(BoundaryError::ExternalEndpoint(other.to_string())),
    }
}

fn encode_via_codec(msg_id: u16, context: u32, direction: JsonlDirection, payload: &[u8]) -> Vec<u8> {
    let opaque = OpaquePayload {
        context,
        direction,
        payload: payload.to_vec(),
    };
    let msg = match msg_id {
        0x1E => BapMessage::Known(KnownBapMessage::DestinyServiceHandshakeRequest(opaque)),
        0x1F => BapMessage::Known(KnownBapMessage::DestinyServiceHandshakeResponse(opaque)),
        0x19 => BapMessage::Known(KnownBapMessage::SessionLoginRequest(opaque)),
        0x1A => BapMessage::Known(KnownBapMessage::SessionLoginResponse {
            context,
            direction,
            record: None,
            raw_payload: payload.to_vec(),
        }),
        0x79 => BapMessage::Known(KnownBapMessage::EncryptedHandshakeRequest(opaque)),
        0x7A => BapMessage::Known(KnownBapMessage::EncryptedHandshakeStatus(opaque)),
        0x12E => BapMessage::Known(KnownBapMessage::Message0x12E(opaque)),
        0x12F => BapMessage::Known(KnownBapMessage::Message0x12F(opaque)),
        0xFA => BapMessage::Known(KnownBapMessage::Message0xFA(opaque)),
        0xFB => BapMessage::Known(KnownBapMessage::Message0xFB(opaque)),
        _ => return payload.to_vec(),
    };
    encode_message(&msg).unwrap_or_else(|_| payload.to_vec())
}

/// Per-connection boundary state (no credentials/tokens in events).
pub struct ExternalClientConnection {
    pub connection_id: u64,
    conn_state: ExternalConnectionState,
    decoder: BapStreamDecoder,
    pub stateful: StatefulBapSession,
    stream: Option<TcpStream>,
    events: Vec<ExternalBoundaryEvent>,
    frame_index: u64,
    max_buffered: usize,
    max_frames_per_iter: usize,
    outbound: Vec<Vec<u8>>,
}

impl ExternalClientConnection {
    pub fn new_synthetic(connection_id: u64) -> Result<Self, BoundaryError> {
        Self::with_material(
            connection_id,
            SyntheticSessionMaterial {
                key: SYNTHETIC_SESSION_KEY,
                nonce: SYNTHETIC_SESSION_NONCE,
            },
        )
    }

    pub fn with_material(
        connection_id: u64,
        material: SyntheticSessionMaterial,
    ) -> Result<Self, BoundaryError> {
        let stateful = StatefulBapSession::with_material(connection_id, material)
            .map_err(|e| BoundaryError::Crypto(e.to_string()))?;
        let mut c = Self {
            connection_id,
            conn_state: ExternalConnectionState::Accepted,
            decoder: BapStreamDecoder::new(),
            stateful,
            stream: None,
            events: Vec::new(),
            frame_index: 0,
            max_buffered: DEFAULT_MAX_BUFFERED,
            max_frames_per_iter: DEFAULT_MAX_FRAMES_PER_ITER,
            outbound: Vec::new(),
        };
        c.push_event(ExternalBoundaryEvent::ConnectionAccepted { connection_id });
        Ok(c)
    }

    pub fn attach_stream(&mut self, stream: TcpStream) {
        self.stream = Some(stream);
    }

    pub fn connection_state(&self) -> ExternalConnectionState {
        self.conn_state
    }

    pub fn protocol_state(&self) -> ProtocolState {
        self.stateful.protocol_state()
    }

    pub fn events(&self) -> &[ExternalBoundaryEvent] {
        &self.events
    }

    pub fn safe_event_log(&self) -> Vec<String> {
        self.events.iter().map(|e| e.safe_label()).collect()
    }

    pub fn take_outbound(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.outbound)
    }

    pub fn buffered_len(&self) -> usize {
        self.decoder.buffered_len()
    }

    pub fn push_event(&mut self, ev: ExternalBoundaryEvent) {
        self.events.push(ev);
    }

    fn set_conn_state(&mut self, to: ExternalConnectionState) {
        self.conn_state = to;
    }

    /// Core ingress: TCP bytes → decoder → StatefulBapSession.
    pub fn feed_bytes(&mut self, bytes: &[u8]) -> Result<usize, BoundaryError> {
        if matches!(
            self.conn_state,
            ExternalConnectionState::Closed | ExternalConnectionState::Closing
        ) {
            return Err(BoundaryError::AlreadyClosed);
        }
        if self.decoder.buffered_len() + bytes.len() > self.max_buffered {
            self.reject(ErrorCategory::Limit, "buffered_bytes_exceeded");
            self.begin_close("limit_exceeded");
            return Err(BoundaryError::LimitExceeded("buffered"));
        }

        self.push_event(ExternalBoundaryEvent::BytesReceived {
            connection_id: self.connection_id,
            byte_len: bytes.len(),
        });
        if self.conn_state == ExternalConnectionState::Accepted {
            self.set_conn_state(ExternalConnectionState::Reading);
        }

        let frames = match self.decoder.push(bytes) {
            Ok(f) => f,
            Err(e) => {
                let detail = match &e {
                    StreamFramingError::InvalidMagic(_) => "invalid_magic",
                    StreamFramingError::InvalidKind(_) => "invalid_kind",
                    StreamFramingError::FrameTooLarge(_) => "oversized_frame",
                    StreamFramingError::IncompleteAtEnd(_) => "incomplete",
                };
                self.reject(ErrorCategory::Framing, detail);
                self.begin_close("framing_error");
                return Err(BoundaryError::Framing(detail.into()));
            }
        };

        if frames.len() > self.max_frames_per_iter {
            self.reject(ErrorCategory::Limit, "frames_per_iter");
            self.begin_close("limit_exceeded");
            return Err(BoundaryError::LimitExceeded("frames_per_iter"));
        }

        let mut processed = 0usize;
        for raw in frames {
            self.handle_raw_frame(raw)?;
            processed += 1;
        }
        Ok(processed)
    }

    fn handle_raw_frame(&mut self, raw: RawBapFrame) -> Result<(), BoundaryError> {
        let idx = self.frame_index;
        self.frame_index += 1;
        self.push_event(ExternalBoundaryEvent::FrameRecovered {
            connection_id: self.connection_id,
            frame_index: idx,
            direction: "C2S".into(),
            kind: raw.kind,
            body_len: raw.body_len(),
        });

        let decoded = match self
            .stateful
            .session
            .decode_frame(NonceDirection::ClientToServer, &raw.raw_bytes)
        {
            Ok(d) => d,
            Err(BapSessionError::DecryptFailed) => {
                self.reject(ErrorCategory::Crypto, "gcm_decrypt_failed");
                self.begin_close("crypto_error");
                return Err(BoundaryError::Crypto("gcm_decrypt_failed".into()));
            }
            Err(e) => {
                self.reject(ErrorCategory::Crypto, "auth_crypto");
                self.begin_close("crypto_error");
                return Err(BoundaryError::Crypto(e.to_string()));
            }
        };

        let handled = match self
            .stateful
            .handle_decoded_frame(&decoded, JsonlDirection::ClientToServer)
        {
            Ok(h) => h,
            Err(ProtocolStateError::InvalidMessage(_)) => {
                self.reject(ErrorCategory::Protocol, "invalid_message");
                return Err(BoundaryError::Protocol("invalid_message".into()));
            }
            Err(e) => {
                self.reject(ErrorCategory::Protocol, "protocol_error");
                return Err(BoundaryError::Protocol(e.to_string()));
            }
        };

        if let TransitionResult::Rejected { reason } = &handled.transition {
            self.reject(ErrorCategory::Protocol, "unexpected_message");
            self.push_event(ExternalBoundaryEvent::ProtocolEvent {
                connection_id: self.connection_id,
                protocol_state: self.protocol_state().as_str().into(),
                label: format!("Rejected"),
            });
            let _ = reason;
            self.begin_close("protocol_reject");
            return Err(BoundaryError::Protocol("unexpected_message".into()));
        }

        if self.conn_state == ExternalConnectionState::Reading {
            self.set_conn_state(ExternalConnectionState::ProtocolActive);
        }

        self.push_event(ExternalBoundaryEvent::ProtocolEvent {
            connection_id: self.connection_id,
            protocol_state: self.protocol_state().as_str().into(),
            label: format!(
                "msg=0x{:04x} {}",
                handled.message.id(),
                handled.transition.as_event_label()
            ),
        });

        for action in handled.actions {
            self.apply_response(action)?;
        }
        Ok(())
    }

    fn apply_response(&mut self, action: ResponseAction) -> Result<(), BoundaryError> {
        match action {
            ResponseAction::SendClear {
                msg_id,
                context,
                payload,
            } => {
                let body =
                    encode_via_codec(msg_id, context, JsonlDirection::ServerToClient, &payload);
                let bytes = BapSession::encode_clear(msg_id, context, &body);
                self.write_out(&bytes)?;
            }
            ResponseAction::SendEncrypted {
                msg_id,
                context,
                payload,
            } => {
                let body =
                    encode_via_codec(msg_id, context, JsonlDirection::ServerToClient, &payload);
                let bytes = self
                    .stateful
                    .session
                    .encode_encrypted(NonceDirection::ServerToClient, msg_id, context, &body)
                    .map_err(|e| BoundaryError::Crypto(e.to_string()))?;
                self.write_out(&bytes)?;
            }
            ResponseAction::ObserveOnly | ResponseAction::None => {}
            ResponseAction::Reject => {
                self.reject(ErrorCategory::Protocol, "policy_reject");
                self.begin_close("policy_reject");
                return Err(BoundaryError::Protocol("policy_reject".into()));
            }
        }
        Ok(())
    }

    fn write_out(&mut self, bytes: &[u8]) -> Result<(), BoundaryError> {
        if let Some(stream) = self.stream.as_mut() {
            stream
                .write_all(bytes)
                .map_err(|e| BoundaryError::Io(e.to_string()))?;
        } else {
            self.outbound.push(bytes.to_vec());
        }
        Ok(())
    }

    fn reject(&mut self, category: ErrorCategory, detail: &str) {
        self.push_event(ExternalBoundaryEvent::FrameRejected {
            connection_id: self.connection_id,
            category: category.as_str().into(),
            detail: detail.into(),
        });
    }

    pub fn begin_close(&mut self, reason: &str) {
        if matches!(self.conn_state, ExternalConnectionState::Closed) {
            return;
        }
        self.set_conn_state(ExternalConnectionState::Closing);
        self.stateful.begin_close();
        if let Some(s) = self.stream.take() {
            let _ = s.shutdown(Shutdown::Both);
        }
        self.stateful.finish_close();
        self.set_conn_state(ExternalConnectionState::Closed);
        self.push_event(ExternalBoundaryEvent::ConnectionClosed {
            connection_id: self.connection_id,
            reason: reason.into(),
        });
        self.decoder = BapStreamDecoder::new();
    }

    pub fn close(&mut self, reason: &str) {
        self.begin_close(reason);
    }

    pub fn notify_eof(&mut self) {
        self.begin_close("eof");
    }
}

#[derive(Debug, Clone)]
pub struct ExternalListenerConfig {
    pub host: String,
    pub port: u16,
    pub max_connections: usize,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
}

impl Default for ExternalListenerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 0,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            read_timeout: Some(Duration::from_secs(5)),
            write_timeout: Some(Duration::from_secs(5)),
        }
    }
}

impl ExternalListenerConfig {
    pub fn loopback_ephemeral() -> Self {
        Self::default()
    }
}

/// TCP listener bound exclusively to loopback.
pub struct ExternalClientListener {
    listener: TcpListener,
    addr: SocketAddr,
    next_id: Arc<AtomicU64>,
    pub config: ExternalListenerConfig,
}

impl ExternalClientListener {
    pub fn bind(config: ExternalListenerConfig) -> Result<Self, BoundaryError> {
        match config.host.as_str() {
            "127.0.0.1" | "localhost" | "::1" => {}
            "0.0.0.0" | "::" | "[::]" => {
                return Err(BoundaryError::ExternalEndpoint(config.host.clone()));
            }
            other => return Err(BoundaryError::ExternalEndpoint(other.into())),
        }
        let addr: SocketAddr = format!("{}:{}", config.host, config.port)
            .parse()
            .map_err(|e| BoundaryError::Bind(format!("{e}")))?;
        assert_localhost_bind(addr)?;
        let listener =
            TcpListener::bind(addr).map_err(|e| BoundaryError::Bind(e.to_string()))?;
        let bound = listener
            .local_addr()
            .map_err(|e| BoundaryError::Bind(e.to_string()))?;
        assert_localhost_bind(bound)?;
        Ok(Self {
            listener,
            addr: bound,
            next_id: Arc::new(AtomicU64::new(1)),
            config,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn accept_one(&self) -> Result<(u64, TcpStream), BoundaryError> {
        let (stream, peer) = self
            .listener
            .accept()
            .map_err(|e| BoundaryError::Accept(e.to_string()))?;
        assert_localhost_bind(peer)?;
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_nodelay(true);
        if let Some(t) = self.config.read_timeout {
            let _ = stream.set_read_timeout(Some(t));
        }
        if let Some(t) = self.config.write_timeout {
            let _ = stream.set_write_timeout(Some(t));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        Ok((id, stream))
    }

    pub fn into_parts(
        self,
    ) -> (
        TcpListener,
        SocketAddr,
        Arc<AtomicU64>,
        ExternalListenerConfig,
    ) {
        (self.listener, self.addr, self.next_id, self.config)
    }
}

/// Facade for creating offline / attached connections.
pub struct ExternalClientBoundary {
    pub config: ExternalListenerConfig,
}

impl ExternalClientBoundary {
    pub fn new(config: ExternalListenerConfig) -> Self {
        Self { config }
    }

    pub fn open_connection_synthetic(
        &self,
        connection_id: u64,
    ) -> Result<ExternalClientConnection, BoundaryError> {
        ExternalClientConnection::new_synthetic(connection_id)
    }
}

fn run_connection_worker(
    id: u64,
    stream: TcpStream,
    events: Arc<Mutex<Vec<ExternalBoundaryEvent>>>,
    read_timeout: Option<Duration>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_nodelay(true);
    if let Some(t) = read_timeout {
        let _ = stream.set_read_timeout(Some(t));
    }
    let mut conn = match ExternalClientConnection::new_synthetic(id) {
        Ok(c) => c,
        Err(_) => return,
    };
    conn.attach_stream(stream);
    flush_events(&events, &conn);

    let mut buf = [0u8; DEFAULT_MAX_READ_CHUNK];
    loop {
        if conn.connection_state() == ExternalConnectionState::Closed {
            break;
        }
        let n = {
            let Some(s) = conn.stream.as_mut() else {
                break;
            };
            match s.read(&mut buf) {
                Ok(0) => {
                    conn.notify_eof();
                    flush_events(&events, &conn);
                    break;
                }
                Ok(n) => n,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    conn.begin_close("timeout");
                    flush_events(&events, &conn);
                    break;
                }
                Err(_) => {
                    conn.begin_close("io_error");
                    flush_events(&events, &conn);
                    break;
                }
            }
        };
        let chunk = buf[..n].to_vec();
        if let Err(e) = conn.feed_bytes(&chunk) {
            conn.push_event(ExternalBoundaryEvent::ConnectionError {
                connection_id: id,
                category: ErrorCategory::Other.as_str().into(),
                detail: e.to_string(),
            });
            if conn.connection_state() != ExternalConnectionState::Closed {
                conn.begin_close("feed_error");
            }
            flush_events(&events, &conn);
            break;
        }
        flush_events(&events, &conn);
    }
}

fn flush_events(sink: &Arc<Mutex<Vec<ExternalBoundaryEvent>>>, conn: &ExternalClientConnection) {
    if let Ok(mut g) = sink.lock() {
        // Append only events beyond what we already copied (by growing length).
        let start = g
            .iter()
            .rev()
            .find(|e| match e {
                ExternalBoundaryEvent::ConnectionAccepted { connection_id }
                | ExternalBoundaryEvent::BytesReceived { connection_id, .. }
                | ExternalBoundaryEvent::FrameRecovered { connection_id, .. }
                | ExternalBoundaryEvent::FrameRejected { connection_id, .. }
                | ExternalBoundaryEvent::ProtocolEvent { connection_id, .. }
                | ExternalBoundaryEvent::ConnectionError { connection_id, .. }
                | ExternalBoundaryEvent::ConnectionClosed { connection_id, .. } => {
                    *connection_id == conn.connection_id
                }
            })
            .map(|_| 0);
        let _ = start;
        let already = g
            .iter()
            .filter(|e| match e {
                ExternalBoundaryEvent::ConnectionAccepted { connection_id }
                | ExternalBoundaryEvent::BytesReceived { connection_id, .. }
                | ExternalBoundaryEvent::FrameRecovered { connection_id, .. }
                | ExternalBoundaryEvent::FrameRejected { connection_id, .. }
                | ExternalBoundaryEvent::ProtocolEvent { connection_id, .. }
                | ExternalBoundaryEvent::ConnectionError { connection_id, .. }
                | ExternalBoundaryEvent::ConnectionClosed { connection_id, .. } => {
                    *connection_id == conn.connection_id
                }
            })
            .count();
        for e in conn.events().iter().skip(already) {
            g.push(e.clone());
        }
    }
}

/// Blocking harness: accept loop + workers + shared event collector.
pub struct ExternalBoundaryHarness {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
    events: Arc<Mutex<Vec<ExternalBoundaryEvent>>>,
    active: Arc<AtomicU64>,
}

impl ExternalBoundaryHarness {
    pub fn start(config: ExternalListenerConfig) -> Result<Self, BoundaryError> {
        let max = config.max_connections;
        let read_timeout = config.read_timeout;
        let listener = ExternalClientListener::bind(config)?;
        let addr = listener.addr();
        let (tcp, _a, next_id, _) = listener.into_parts();
        let _ = tcp.set_nonblocking(true);

        let stop = Arc::new(AtomicBool::new(false));
        let events = Arc::new(Mutex::new(Vec::new()));
        let active = Arc::new(AtomicU64::new(0));

        let stop_c = stop.clone();
        let events_c = events.clone();
        let active_c = active.clone();
        let accept_thread = thread::spawn(move || {
            while !stop_c.load(Ordering::SeqCst) {
                match tcp.accept() {
                    Ok((stream, peer)) => {
                        if assert_localhost_bind(peer).is_err() {
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }
                        if active_c.load(Ordering::SeqCst) as usize >= max {
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }
                        active_c.fetch_add(1, Ordering::SeqCst);
                        let id = next_id.fetch_add(1, Ordering::SeqCst);
                        let events_w = events_c.clone();
                        let active_w = active_c.clone();
                        thread::spawn(move || {
                            run_connection_worker(id, stream, events_w, read_timeout);
                            active_w.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Ok(Self {
            addr,
            stop,
            accept_thread: Some(accept_thread),
            events,
            active,
        })
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn events(&self) -> Vec<ExternalBoundaryEvent> {
        self.events.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn active_connections(&self) -> u64 {
        self.active.load(Ordering::SeqCst)
    }

    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(100));
        if let Some(h) = self.accept_thread.take() {
            let _ = h.join();
        }
    }
}

impl Drop for ExternalBoundaryHarness {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Lightweight test client for boundary (raw frames; may use CompatibilityClient for handshake).
pub struct BoundaryTestClient {
    stream: Option<TcpStream>,
    session: BapSession,
}

impl BoundaryTestClient {
    pub fn with_synthetic() -> Result<Self, BoundaryError> {
        let session = BapSession::new(&SYNTHETIC_SESSION_KEY, &SYNTHETIC_SESSION_NONCE)
            .map_err(|e| BoundaryError::Crypto(e.to_string()))?;
        Ok(Self {
            stream: None,
            session,
        })
    }

    pub fn with_keys(key: &[u8], nonce: &[u8]) -> Result<Self, BoundaryError> {
        let session =
            BapSession::new(key, nonce).map_err(|e| BoundaryError::Crypto(e.to_string()))?;
        Ok(Self {
            stream: None,
            session,
        })
    }

    pub fn connect(&mut self, addr: SocketAddr) -> Result<(), BoundaryError> {
        assert_localhost_bind(addr)?;
        let s = TcpStream::connect_timeout(&addr, Duration::from_secs(2))
            .map_err(|e| BoundaryError::Io(e.to_string()))?;
        let _ = s.set_nodelay(true);
        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
        self.stream = Some(s);
        Ok(())
    }

    pub fn send_raw(&mut self, bytes: &[u8]) -> Result<(), BoundaryError> {
        let s = self.stream.as_mut().ok_or(BoundaryError::NotConnected)?;
        s.write_all(bytes)
            .map_err(|e| BoundaryError::Io(e.to_string()))
    }

    pub fn send_frame(&mut self, bytes: &[u8]) -> Result<(), BoundaryError> {
        self.send_raw(bytes)
    }

    pub fn send_clear(&mut self, msg_id: u16, payload: &[u8]) -> Result<(), BoundaryError> {
        let bytes = BapSession::encode_clear(msg_id, 1, payload);
        self.send_raw(&bytes)
    }

    pub fn send_encrypted(&mut self, msg_id: u16, payload: &[u8]) -> Result<(), BoundaryError> {
        let bytes = self
            .session
            .encode_encrypted(NonceDirection::ClientToServer, msg_id, 1, payload)
            .map_err(|e| BoundaryError::Crypto(e.to_string()))?;
        self.send_raw(&bytes)
    }

    pub fn send_fragmented(&mut self, bytes: &[u8], chunk: usize) -> Result<(), BoundaryError> {
        let chunk = chunk.max(1);
        for part in bytes.chunks(chunk) {
            self.send_raw(part)?;
            thread::sleep(Duration::from_millis(2));
        }
        Ok(())
    }

    pub fn send_multiple_frames(&mut self, frames: &[&[u8]]) -> Result<(), BoundaryError> {
        let mut all = Vec::new();
        for f in frames {
            all.extend_from_slice(f);
        }
        self.send_raw(&all)
    }

    pub fn read_some(&mut self, buf: &mut [u8]) -> Result<usize, BoundaryError> {
        let s = self.stream.as_mut().ok_or(BoundaryError::NotConnected)?;
        s.read(buf).map_err(|e| BoundaryError::Io(e.to_string()))
    }

    pub fn session_mut(&mut self) -> &mut BapSession {
        &mut self.session
    }

    pub fn close(&mut self) {
        if let Some(s) = self.stream.take() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

/// Replay a safe trace fixture (metadata only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeTraceFile {
    pub name: String,
    #[serde(default)]
    pub notes: Vec<String>,
    pub expected_result: String,
    pub events: Vec<SafeTraceEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeTraceEvent {
    pub connection_id: u64,
    pub event: String,
    #[serde(default)]
    pub frame_index: Option<u64>,
    #[serde(default)]
    pub direction: Option<String>,
    #[serde(default)]
    pub kind: Option<u8>,
    #[serde(default)]
    pub body_len: Option<usize>,
    #[serde(default)]
    pub protocol_state: Option<String>,
    #[serde(default)]
    pub result: Option<String>,
}

pub fn validate_safe_trace(trace: &SafeTraceFile) -> Result<(), BoundaryError> {
    for e in &trace.events {
        let blob = serde_json::to_string(e).unwrap_or_default();
        if blob.contains("payload")
            || blob.contains("ciphertext")
            || blob.contains("plaintext")
            || blob.contains("hmac")
            || blob.contains("token")
            || blob.contains("credential")
        {
            return Err(BoundaryError::Protocol("unsafe_trace_field".into()));
        }
    }
    Ok(())
}
