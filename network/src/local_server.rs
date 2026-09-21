//! Local BAP compatibility server (M4.2 + M4.5 stateful) — localhost TCP only.
//!
//! Blocking `std::net` + one thread per connection. No Tokio, no Bungie,
//! no Destiny client, no UDP, no gameplay. Crypto material is synthetic only.

use crate::bap_session::{BapSession, BapSessionError, DecodedBapFrame};
use crate::crypto::NonceDirection;
use crate::jsonl::Direction as JsonlDirection;
use crate::local_protocol::{
    ProtocolErrorKind, ServerTraceEvent, SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE,
};
use crate::message_codec::{encode_message, BapMessage, KnownBapMessage, OpaquePayload};
use crate::protocol_state::{ProtocolState, ProtocolStateError, TransitionResult};
use crate::response_policy::ResponseAction;
use crate::stateful_bap_session::{StatefulBapSession, SyntheticSessionMaterial};
use crate::stream_framing::{BapStreamDecoder, StreamFramingError};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct LocalServerConfig {
    pub host: String,
    pub port: u16,
    pub read_timeout: Option<Duration>,
    pub write_timeout: Option<Duration>,
    pub max_connections: usize,
}

impl Default for LocalServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 0,
            read_timeout: Some(Duration::from_secs(5)),
            write_timeout: Some(Duration::from_secs(5)),
            max_connections: 8,
        }
    }
}

impl LocalServerConfig {
    pub fn loopback_ephemeral() -> Self {
        Self::default()
    }
}

#[derive(Debug, Error)]
pub enum LocalServerError {
    #[error("bind failed: {0}")]
    Bind(String),
    #[error("accept failed: {0}")]
    Accept(String),
    #[error("io: {0}")]
    Io(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("server stopped")]
    Stopped,
    #[error("max connections reached")]
    MaxConnections,
}

/// Per-connection session wrapper (secrets in memory only).
pub struct LocalBapSession {
    pub connection_id: u64,
    pub stateful: StatefulBapSession,
}

impl LocalBapSession {
    pub fn with_synthetic(connection_id: u64) -> Result<Self, LocalServerError> {
        Self::with_keys(
            connection_id,
            &SYNTHETIC_SESSION_KEY,
            &SYNTHETIC_SESSION_NONCE,
        )
    }

    pub fn with_keys(
        connection_id: u64,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<Self, LocalServerError> {
        if key.len() != 16 || nonce.len() != 12 {
            return Err(LocalServerError::Crypto(
                "synthetic key/nonce length".into(),
            ));
        }
        let mut material = SyntheticSessionMaterial::default();
        material.key.copy_from_slice(key);
        material.nonce.copy_from_slice(nonce);
        let stateful = StatefulBapSession::with_material(connection_id, material)
            .map_err(|e| LocalServerError::Crypto(e.to_string()))?;
        Ok(Self {
            connection_id,
            stateful,
        })
    }

    pub fn protocol_state(&self) -> ProtocolState {
        self.stateful.protocol_state()
    }

    pub fn session(&self) -> &BapSession {
        &self.stateful.session
    }

    pub fn session_mut(&mut self) -> &mut BapSession {
        &mut self.stateful.session
    }
}

/// Local BAP compatibility server.
pub struct LocalBapServer {
    config: LocalServerConfig,
    listener: Option<TcpListener>,
    bound_addr: Option<SocketAddr>,
    next_conn_id: AtomicU64,
    stop: Arc<AtomicBool>,
    accept_thread: Option<JoinHandle<()>>,
    session_key: Vec<u8>,
    session_nonce: Vec<u8>,
    traces: Arc<Mutex<Vec<ServerTraceEvent>>>,
    active: Arc<AtomicU64>,
}

impl LocalBapServer {
    pub fn new(config: LocalServerConfig) -> Self {
        Self::with_crypto(
            config,
            SYNTHETIC_SESSION_KEY.to_vec(),
            SYNTHETIC_SESSION_NONCE.to_vec(),
        )
    }

    pub fn with_crypto(config: LocalServerConfig, key: Vec<u8>, nonce: Vec<u8>) -> Self {
        Self {
            config,
            listener: None,
            bound_addr: None,
            next_conn_id: AtomicU64::new(1),
            stop: Arc::new(AtomicBool::new(false)),
            accept_thread: None,
            session_key: key,
            session_nonce: nonce,
            traces: Arc::new(Mutex::new(Vec::new())),
            active: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn bind(&mut self) -> Result<SocketAddr, LocalServerError> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener =
            TcpListener::bind(&addr).map_err(|e| LocalServerError::Bind(e.to_string()))?;
        listener
            .set_nonblocking(false)
            .map_err(|e| LocalServerError::Bind(e.to_string()))?;
        let bound = listener
            .local_addr()
            .map_err(|e| LocalServerError::Bind(e.to_string()))?;
        self.bound_addr = Some(bound);
        self.listener = Some(listener);
        Ok(bound)
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.bound_addr
    }

    pub fn port(&self) -> Option<u16> {
        self.bound_addr.map(|a| a.port())
    }

    pub fn traces(&self) -> Vec<ServerTraceEvent> {
        self.traces.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn clear_traces(&self) {
        if let Ok(mut g) = self.traces.lock() {
            g.clear();
        }
    }

    pub fn status_banner(&self) -> String {
        let port = self.port().unwrap_or(0);
        format!(
            "LOCAL_BAP_SERVER\nhost: {}\nport: {}\nstatus: LISTENING\nkey_present={}\nnonce_present={}",
            self.config.host,
            port,
            !self.session_key.is_empty(),
            !self.session_nonce.is_empty()
        )
    }

    pub fn start_background(&mut self) -> Result<(), LocalServerError> {
        if self.listener.is_none() {
            self.bind()?;
        }
        let listener = self
            .listener
            .take()
            .ok_or_else(|| LocalServerError::Bind("no listener".into()))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| LocalServerError::Bind(e.to_string()))?;

        let stop = Arc::clone(&self.stop);
        let traces = Arc::clone(&self.traces);
        let active = Arc::clone(&self.active);
        let key = self.session_key.clone();
        let nonce = self.session_nonce.clone();
        let max_conn = self.config.max_connections;
        let read_timeout = self.config.read_timeout;
        let write_timeout = self.config.write_timeout;
        let next_id = Arc::new(AtomicU64::new(
            self.next_conn_id.load(Ordering::SeqCst),
        ));

        let handle = thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if active.load(Ordering::SeqCst) as usize >= max_conn {
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }
                        let _ = stream.set_nonblocking(false);
                        let id = next_id.fetch_add(1, Ordering::SeqCst);
                        active.fetch_add(1, Ordering::SeqCst);
                        let traces_c = Arc::clone(&traces);
                        let active_c = Arc::clone(&active);
                        let key_c = key.clone();
                        let nonce_c = nonce.clone();
                        thread::spawn(move || {
                            let _ = handle_connection(
                                id,
                                stream,
                                &key_c,
                                &nonce_c,
                                read_timeout,
                                write_timeout,
                                traces_c,
                            );
                            active_c.fetch_sub(1, Ordering::SeqCst);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => {
                        if stop.load(Ordering::SeqCst) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(20));
                    }
                }
            }
        });
        self.accept_thread = Some(handle);
        Ok(())
    }

    pub fn serve_one(&mut self) -> Result<Vec<ServerTraceEvent>, LocalServerError> {
        if self.listener.is_none() {
            self.bind()?;
        }
        let listener = self
            .listener
            .as_ref()
            .ok_or_else(|| LocalServerError::Bind("no listener".into()))?;
        listener
            .set_nonblocking(false)
            .map_err(|e| LocalServerError::Accept(e.to_string()))?;
        let (stream, _) = listener
            .accept()
            .map_err(|e| LocalServerError::Accept(e.to_string()))?;
        let id = self.next_conn_id.fetch_add(1, Ordering::SeqCst);
        handle_connection(
            id,
            stream,
            &self.session_key,
            &self.session_nonce,
            self.config.read_timeout,
            self.config.write_timeout,
            Arc::clone(&self.traces),
        )?;
        Ok(self.traces())
    }

    pub fn serve_forever(&mut self) -> Result<(), LocalServerError> {
        if self.listener.is_none() {
            self.bind()?;
        }
        println!("{}", self.status_banner());
        self.start_background()?;
        while !self.stop.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(200));
        }
        self.shutdown();
        Ok(())
    }

    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(addr) = self.bound_addr {
            let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(100));
        }
        if let Some(h) = self.accept_thread.take() {
            let _ = h.join();
        }
    }
}

impl Drop for LocalBapServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn handle_connection(
    connection_id: u64,
    mut stream: TcpStream,
    key: &[u8],
    nonce: &[u8],
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
    traces: Arc<Mutex<Vec<ServerTraceEvent>>>,
) -> Result<(), LocalServerError> {
    let _ = stream.set_nodelay(true);
    if let Some(t) = read_timeout {
        let _ = stream.set_read_timeout(Some(t));
    }
    if let Some(t) = write_timeout {
        let _ = stream.set_write_timeout(Some(t));
    }

    let mut local = LocalBapSession::with_keys(connection_id, key, nonce)?;
    let mut decoder = BapStreamDecoder::new();
    let mut buf = [0u8; 4096];

    push_trace(
        &traces,
        ServerTraceEvent {
            timestamp: None,
            connection_id,
            direction: "SYS".into(),
            message_id: None,
            context: None,
            state: local.protocol_state().as_str().into(),
            action: "ACCEPT".into(),
        },
    );

    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => {
                local.stateful.begin_close();
                local.stateful.finish_close();
                push_trace(
                    &traces,
                    ServerTraceEvent {
                        timestamp: None,
                        connection_id,
                        direction: "SYS".into(),
                        message_id: None,
                        context: None,
                        state: local.protocol_state().as_str().into(),
                        action: "EOF".into(),
                    },
                );
                break;
            }
            Ok(n) => n,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                push_trace(
                    &traces,
                    ServerTraceEvent {
                        timestamp: None,
                        connection_id,
                        direction: "SYS".into(),
                        message_id: None,
                        context: None,
                        state: local.protocol_state().as_str().into(),
                        action: "TIMEOUT".into(),
                    },
                );
                break;
            }
            Err(e) => return Err(LocalServerError::Io(e.to_string())),
        };

        let frames = match decoder.push(&buf[..n]) {
            Ok(f) => f,
            Err(StreamFramingError::InvalidMagic(m)) => {
                push_trace(
                    &traces,
                    ServerTraceEvent {
                        timestamp: None,
                        connection_id,
                        direction: "C2S".into(),
                        message_id: None,
                        context: None,
                        state: local.protocol_state().as_str().into(),
                        action: format!("PROTOCOL_ERROR invalid magic 0x{m:02x}"),
                    },
                );
                let _ = stream.shutdown(Shutdown::Both);
                return Err(LocalServerError::Protocol(
                    ProtocolErrorKind::ProtocolError.as_str().into(),
                ));
            }
            Err(StreamFramingError::InvalidKind(k)) => {
                push_trace(
                    &traces,
                    ServerTraceEvent {
                        timestamp: None,
                        connection_id,
                        direction: "C2S".into(),
                        message_id: None,
                        context: None,
                        state: local.protocol_state().as_str().into(),
                        action: format!("PROTOCOL_ERROR invalid kind 0x{k:02x}"),
                    },
                );
                let _ = stream.shutdown(Shutdown::Both);
                return Err(LocalServerError::Protocol(
                    ProtocolErrorKind::ProtocolError.as_str().into(),
                ));
            }
            Err(e) => {
                push_trace(
                    &traces,
                    ServerTraceEvent {
                        timestamp: None,
                        connection_id,
                        direction: "C2S".into(),
                        message_id: None,
                        context: None,
                        state: local.protocol_state().as_str().into(),
                        action: format!("PROTOCOL_ERROR {e}"),
                    },
                );
                let _ = stream.shutdown(Shutdown::Both);
                return Err(LocalServerError::Protocol(e.to_string()));
            }
        };

        for raw in frames {
            let decoded = match local
                .session_mut()
                .decode_frame(NonceDirection::ClientToServer, &raw.raw_bytes)
            {
                Ok(d) => d,
                Err(BapSessionError::DecryptFailed) => {
                    push_trace(
                        &traces,
                        ServerTraceEvent {
                            timestamp: None,
                            connection_id,
                            direction: "C2S".into(),
                            message_id: None,
                            context: None,
                            state: local.protocol_state().as_str().into(),
                            action: ProtocolErrorKind::GcmDecryptFailure.as_str().into(),
                        },
                    );
                    let _ = stream.shutdown(Shutdown::Both);
                    return Err(LocalServerError::Crypto(
                        ProtocolErrorKind::GcmDecryptFailure.as_str().into(),
                    ));
                }
                Err(e) => {
                    push_trace(
                        &traces,
                        ServerTraceEvent {
                            timestamp: None,
                            connection_id,
                            direction: "C2S".into(),
                            message_id: None,
                            context: None,
                            state: local.protocol_state().as_str().into(),
                            action: format!("AUTH/CRYPTO ERROR {e}"),
                        },
                    );
                    let _ = stream.shutdown(Shutdown::Both);
                    return Err(LocalServerError::Crypto(
                        ProtocolErrorKind::AuthCryptoError.as_str().into(),
                    ));
                }
            };

            let (msg_id, context) = frame_ids(&decoded);
            push_trace(
                &traces,
                ServerTraceEvent {
                    timestamp: None,
                    connection_id,
                    direction: "C2S".into(),
                    message_id: msg_id,
                    context,
                    state: local.protocol_state().as_str().into(),
                    action: "RECV".into(),
                },
            );

            let handled = match local
                .stateful
                .handle_decoded_frame(&decoded, JsonlDirection::ClientToServer)
            {
                Ok(h) => h,
                Err(ProtocolStateError::InvalidMessage(detail)) => {
                    push_trace(
                        &traces,
                        ServerTraceEvent {
                            timestamp: None,
                            connection_id,
                            direction: "C2S".into(),
                            message_id: msg_id,
                            context,
                            state: local.protocol_state().as_str().into(),
                            action: format!("InvalidMessage {detail}"),
                        },
                    );
                    let _ = stream.shutdown(Shutdown::Both);
                    return Err(LocalServerError::Protocol("InvalidMessage".into()));
                }
                Err(e) => {
                    push_trace(
                        &traces,
                        ServerTraceEvent {
                            timestamp: None,
                            connection_id,
                            direction: "C2S".into(),
                            message_id: msg_id,
                            context,
                            state: local.protocol_state().as_str().into(),
                            action: format!("UNEXPECTED_MESSAGE {e}"),
                        },
                    );
                    let _ = stream.shutdown(Shutdown::Both);
                    return Err(LocalServerError::Protocol(
                        ProtocolErrorKind::UnexpectedMessage.as_str().into(),
                    ));
                }
            };

            if let TransitionResult::Rejected { reason } = &handled.transition {
                push_trace(
                    &traces,
                    ServerTraceEvent {
                        timestamp: None,
                        connection_id,
                        direction: "C2S".into(),
                        message_id: msg_id,
                        context,
                        state: local.protocol_state().as_str().into(),
                        action: format!("UNEXPECTED_MESSAGE {reason}"),
                    },
                );
                let _ = stream.shutdown(Shutdown::Both);
                return Err(LocalServerError::Protocol(
                    ProtocolErrorKind::UnexpectedMessage.as_str().into(),
                ));
            }

            if let TransitionResult::Advanced { from, to } = &handled.transition {
                push_trace(
                    &traces,
                    ServerTraceEvent {
                        timestamp: None,
                        connection_id,
                        direction: "SYS".into(),
                        message_id: None,
                        context: None,
                        state: to.as_str().into(),
                        action: format!("ChangeState {}→{}", from.as_str(), to.as_str()),
                    },
                );
            }

            for action in handled.actions {
                match action {
                    ResponseAction::SendClear {
                        msg_id,
                        context,
                        payload,
                    } => {
                        let body = encode_via_codec(
                            msg_id,
                            context,
                            JsonlDirection::ServerToClient,
                            &payload,
                        );
                        let bytes = BapSession::encode_clear(msg_id, context, &body);
                        stream
                            .write_all(&bytes)
                            .map_err(|e| LocalServerError::Io(e.to_string()))?;
                        push_trace(
                            &traces,
                            ServerTraceEvent {
                                timestamp: None,
                                connection_id,
                                direction: "S2C".into(),
                                message_id: Some(msg_id),
                                context: Some(context),
                                state: local.protocol_state().as_str().into(),
                                action: "SendFrame".into(),
                            },
                        );
                    }
                    ResponseAction::SendEncrypted {
                        msg_id,
                        context,
                        payload,
                    } => {
                        let body = encode_via_codec(
                            msg_id,
                            context,
                            JsonlDirection::ServerToClient,
                            &payload,
                        );
                        let bytes = local
                            .session_mut()
                            .encode_encrypted(
                                NonceDirection::ServerToClient,
                                msg_id,
                                context,
                                &body,
                            )
                            .map_err(|e| LocalServerError::Crypto(e.to_string()))?;
                        stream
                            .write_all(&bytes)
                            .map_err(|e| LocalServerError::Io(e.to_string()))?;
                        push_trace(
                            &traces,
                            ServerTraceEvent {
                                timestamp: None,
                                connection_id,
                                direction: "S2C".into(),
                                message_id: Some(msg_id),
                                context: Some(context),
                                state: local.protocol_state().as_str().into(),
                                action: "SendFrame".into(),
                            },
                        );
                    }
                    ResponseAction::ObserveOnly | ResponseAction::None => {}
                    ResponseAction::Reject => {
                        let _ = stream.shutdown(Shutdown::Both);
                        return Err(LocalServerError::Protocol(
                            ProtocolErrorKind::UnexpectedMessage.as_str().into(),
                        ));
                    }
                }
            }
        }
    }

    local.stateful.finish_close();
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn frame_ids(frame: &DecodedBapFrame) -> (Option<u16>, Option<u32>) {
    match frame {
        DecodedBapFrame::Clear {
            msg_id, context, ..
        } => (Some(*msg_id), Some(*context)),
        DecodedBapFrame::Decrypted {
            msg_id, context, ..
        } => (*msg_id, *context),
        DecodedBapFrame::Opaque { .. } => (None, None),
    }
}

fn push_trace(traces: &Arc<Mutex<Vec<ServerTraceEvent>>>, ev: ServerTraceEvent) {
    if let Ok(mut g) = traces.lock() {
        g.push(ev);
    }
}

fn encode_via_codec(
    msg_id: u16,
    context: u32,
    direction: JsonlDirection,
    payload: &[u8],
) -> Vec<u8> {
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
