//! Local BAP compatibility client (M4.6) — localhost TCP only.
//!
//! Not the Destiny 1 client. Synthetic crypto only. No Bungie / UDP / gameplay.

use crate::bap_session::{BapSession, BapSessionError, DecodedBapFrame};
use crate::crypto::NonceDirection;
use crate::jsonl::Direction;
use crate::local_protocol::{
    PAYLOAD_19, PAYLOAD_1E, PAYLOAD_79, PAYLOAD_FA, SIM_CONTEXT, MSG_12E, MSG_19, MSG_1A, MSG_1E,
    MSG_1F, MSG_79, MSG_7A, MSG_FA, MSG_FB,
};
use crate::message_codec::{
    decode_from_frame, encode_message, BapMessage, KnownBapMessage, OpaquePayload,
    UnknownBapMessage,
};
use crate::message_dispatcher::MessageDispatcher;
use crate::stream_framing::{BapStreamDecoder, StreamFramingError};
use crate::test_crypto_material::{SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::time::Duration;
use thiserror::Error;

/// Client-side protocol execution states (local policy — not Bungie SM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClientProtocolState {
    Disconnected,
    Connected,
    ServiceHandshakeSent,
    ServiceHandshakeComplete,
    SessionLoginSent,
    SessionEstablished,
    EncryptedHandshakeSent,
    EncryptedChannelEstablished,
    Active,
    Closing,
    Closed,
}

impl ClientProtocolState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disconnected => "DISCONNECTED",
            Self::Connected => "CONNECTED",
            Self::ServiceHandshakeSent => "SERVICE_HANDSHAKE_SENT",
            Self::ServiceHandshakeComplete => "SERVICE_HANDSHAKE_COMPLETE",
            Self::SessionLoginSent => "SESSION_LOGIN_SENT",
            Self::SessionEstablished => "SESSION_ESTABLISHED",
            Self::EncryptedHandshakeSent => "ENCRYPTED_HANDSHAKE_SENT",
            Self::EncryptedChannelEstablished => "ENCRYPTED_CHANNEL_ESTABLISHED",
            Self::Active => "ACTIVE",
            Self::Closing => "CLOSING",
            Self::Closed => "CLOSED",
        }
    }
}

impl Default for ClientProtocolState {
    fn default() -> Self {
        Self::Disconnected
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CompatibilityClientError {
    #[error("not connected")]
    NotConnected,
    #[error("external endpoint rejected: {0}")]
    ExternalEndpoint(String),
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("io: {0}")]
    Io(String),
    #[error("framing: {0}")]
    Framing(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    #[error("unexpected message 0x{0:04x}")]
    UnexpectedMessage(u16),
    #[error("invalid state {0}")]
    InvalidState(&'static str),
    #[error("already closed")]
    AlreadyClosed,
    #[error("eof")]
    Eof,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum CompatibilityClientEvent {
    Connected { addr: String },
    MessageSent { id: u16, direction: String },
    MessageReceived { id: u16, direction: String },
    Decoded { id: u16, known: bool },
    StateTransition { from: String, to: String },
    CryptoEstablished,
    MessageRejected { id: u16, reason: String },
    Disconnected,
}

impl CompatibilityClientEvent {
    pub fn safe_label(&self) -> String {
        match self {
            Self::Connected { addr } => format!("Connected addr={addr}"),
            Self::MessageSent { id, direction } => {
                format!("MessageSent id=0x{id:04x} dir={direction}")
            }
            Self::MessageReceived { id, direction } => {
                format!("MessageReceived id=0x{id:04x} dir={direction}")
            }
            Self::Decoded { id, known } => format!("Decoded id=0x{id:04x} known={known}"),
            Self::StateTransition { from, to } => format!("StateTransition {from}→{to}"),
            Self::CryptoEstablished => "CryptoEstablished".into(),
            Self::MessageRejected { id, reason } => {
                format!("MessageRejected id=0x{id:04x} reason={reason}")
            }
            Self::Disconnected => "Disconnected".into(),
        }
    }
}

fn opaque(id: u16, dir: Direction, payload: &[u8]) -> BapMessage {
    let o = OpaquePayload {
        context: SIM_CONTEXT,
        direction: dir,
        payload: payload.to_vec(),
    };
    match id {
        0x1E => BapMessage::Known(KnownBapMessage::DestinyServiceHandshakeRequest(o)),
        0x1F => BapMessage::Known(KnownBapMessage::DestinyServiceHandshakeResponse(o)),
        0x19 => BapMessage::Known(KnownBapMessage::SessionLoginRequest(o)),
        0x1A => BapMessage::Known(KnownBapMessage::SessionLoginResponse {
            context: SIM_CONTEXT,
            direction: dir,
            record: None,
            raw_payload: payload.to_vec(),
        }),
        0x79 => BapMessage::Known(KnownBapMessage::EncryptedHandshakeRequest(o)),
        0x7A => BapMessage::Known(KnownBapMessage::EncryptedHandshakeStatus(o)),
        0x12E => BapMessage::Known(KnownBapMessage::Message0x12E(o)),
        0x12F => BapMessage::Known(KnownBapMessage::Message0x12F(o)),
        0xFA => BapMessage::Known(KnownBapMessage::Message0xFA(o)),
        0xFB => BapMessage::Known(KnownBapMessage::Message0xFB(o)),
        _ => BapMessage::Unknown(UnknownBapMessage {
            id,
            context: SIM_CONTEXT,
            direction: dir,
            payload: payload.to_vec(),
        }),
    }
}

fn codec_body(msg: &BapMessage) -> Result<Vec<u8>, CompatibilityClientError> {
    encode_message(msg).map_err(|e| CompatibilityClientError::InvalidMessage(e.to_string()))
}

fn frame_msg_id(frame: &DecodedBapFrame) -> Option<u16> {
    match frame {
        DecodedBapFrame::Clear { msg_id, .. } => Some(*msg_id),
        DecodedBapFrame::Decrypted { msg_id, .. } => *msg_id,
        DecodedBapFrame::Opaque { .. } => None,
    }
}

/// Reject non-loopback endpoints for the M4.6 harness.
pub fn assert_localhost_only(addr: SocketAddr) -> Result<(), CompatibilityClientError> {
    match addr.ip() {
        IpAddr::V4(v4) if v4 == Ipv4Addr::LOCALHOST => Ok(()),
        IpAddr::V6(v6) if v6.is_loopback() => Ok(()),
        other => Err(CompatibilityClientError::ExternalEndpoint(other.to_string())),
    }
}

/// Live localhost compatibility client (distinct from [`crate::replay_client::BapReplayClient`]).
pub struct BapCompatibilityClient {
    stream: Option<TcpStream>,
    session: Option<BapSession>,
    material_key: [u8; 16],
    material_nonce: [u8; 12],
    decoder: BapStreamDecoder,
    state: ClientProtocolState,
    dispatcher: MessageDispatcher,
    pending: Vec<DecodedBapFrame>,
    read_buf: Vec<u8>,
    pub events: Vec<CompatibilityClientEvent>,
    crypto_ready: bool,
}

impl BapCompatibilityClient {
    pub fn new_synthetic() -> Self {
        Self::with_material(SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE)
    }

    pub fn with_material(key: [u8; 16], nonce: [u8; 12]) -> Self {
        Self {
            stream: None,
            session: None,
            material_key: key,
            material_nonce: nonce,
            decoder: BapStreamDecoder::new(),
            state: ClientProtocolState::Disconnected,
            dispatcher: MessageDispatcher::new(),
            pending: Vec::new(),
            read_buf: vec![0u8; 4096],
            events: Vec::new(),
            crypto_ready: false,
        }
    }

    pub fn state(&self) -> ClientProtocolState {
        self.state
    }

    pub fn session(&self) -> Option<&BapSession> {
        self.session.as_ref()
    }

    pub fn session_mut(&mut self) -> Option<&mut BapSession> {
        self.session.as_mut()
    }

    pub fn client_to_server_counter(&self) -> u64 {
        self.session
            .as_ref()
            .map(|s| s.client_to_server_counter())
            .unwrap_or(0)
    }

    pub fn server_to_client_counter(&self) -> u64 {
        self.session
            .as_ref()
            .map(|s| s.server_to_client_counter())
            .unwrap_or(0)
    }

    pub fn safe_event_log(&self) -> Vec<String> {
        self.events.iter().map(|e| e.safe_label()).collect()
    }

    fn set_state(&mut self, to: ClientProtocolState) {
        let from = self.state;
        if from != to {
            self.events.push(CompatibilityClientEvent::StateTransition {
                from: from.as_str().into(),
                to: to.as_str().into(),
            });
            self.state = to;
        }
    }

    pub fn connect(&mut self, addr: SocketAddr) -> Result<(), CompatibilityClientError> {
        self.connect_timeout(addr, Duration::from_secs(2))
    }

    pub fn connect_timeout(
        &mut self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> Result<(), CompatibilityClientError> {
        assert_localhost_only(addr)?;
        if matches!(
            self.state,
            ClientProtocolState::Closed | ClientProtocolState::Closing
        ) {
            return Err(CompatibilityClientError::AlreadyClosed);
        }
        let stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| CompatibilityClientError::Connect(e.to_string()))?;
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        // Crypto is created after synthetic 0x1A (local policy); session held for clear first.
        let session = BapSession::new(&self.material_key, &self.material_nonce)
            .map_err(|e| CompatibilityClientError::Crypto(e.to_string()))?;
        self.session = Some(session);
        self.stream = Some(stream);
        self.decoder = BapStreamDecoder::new();
        self.pending.clear();
        self.crypto_ready = false;
        self.set_state(ClientProtocolState::Connected);
        self.events.push(CompatibilityClientEvent::Connected {
            addr: addr.to_string(),
        });
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
            && !matches!(
                self.state,
                ClientProtocolState::Disconnected
                    | ClientProtocolState::Closed
                    | ClientProtocolState::Closing
            )
    }

    fn send_raw(&mut self, bytes: &[u8]) -> Result<(), CompatibilityClientError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or(CompatibilityClientError::NotConnected)?;
        stream
            .write_all(bytes)
            .map_err(|e| CompatibilityClientError::Io(e.to_string()))
    }

    pub fn send_clear(
        &mut self,
        msg_id: u16,
        payload: &[u8],
    ) -> Result<(), CompatibilityClientError> {
        let msg = opaque(msg_id, Direction::ClientToServer, payload);
        let body = codec_body(&msg)?;
        let bytes = BapSession::encode_clear(msg_id, SIM_CONTEXT, &body);
        self.send_raw(&bytes)?;
        self.events.push(CompatibilityClientEvent::MessageSent {
            id: msg_id,
            direction: "C2S".into(),
        });
        Ok(())
    }

    pub fn send_encrypted(
        &mut self,
        msg_id: u16,
        payload: &[u8],
    ) -> Result<(), CompatibilityClientError> {
        if !self.crypto_ready
            && !matches!(
                self.state,
                ClientProtocolState::SessionEstablished
                    | ClientProtocolState::EncryptedHandshakeSent
                    | ClientProtocolState::EncryptedChannelEstablished
                    | ClientProtocolState::Active
            )
        {
            return Err(CompatibilityClientError::InvalidState(
                "crypto not established for encrypted send",
            ));
        }
        let msg = opaque(msg_id, Direction::ClientToServer, payload);
        let body = codec_body(&msg)?;
        let session = self
            .session
            .as_mut()
            .ok_or(CompatibilityClientError::NotConnected)?;
        let bytes = session
            .encode_encrypted(NonceDirection::ClientToServer, msg_id, SIM_CONTEXT, &body)
            .map_err(|e| CompatibilityClientError::Crypto(e.to_string()))?;
        self.send_raw(&bytes)?;
        self.events.push(CompatibilityClientEvent::MessageSent {
            id: msg_id,
            direction: "C2S".into(),
        });
        Ok(())
    }

    /// Feed raw TCP bytes into the stream decoder (chunking / multi-frame tests).
    pub fn feed_bytes(
        &mut self,
        bytes: &[u8],
    ) -> Result<Vec<DecodedBapFrame>, CompatibilityClientError> {
        let frames = self
            .decoder
            .push(bytes)
            .map_err(|e| map_framing(e))?;
        let mut out = Vec::new();
        for raw in frames {
            let session = self
                .session
                .as_mut()
                .ok_or(CompatibilityClientError::NotConnected)?;
            match session.decode_frame(NonceDirection::ServerToClient, &raw.raw_bytes) {
                Ok(d) => out.push(d),
                Err(BapSessionError::DecryptFailed) => {
                    return Err(CompatibilityClientError::Crypto("GCM decrypt failed".into()));
                }
                Err(e) => {
                    return Err(CompatibilityClientError::Crypto(e.to_string()));
                }
            }
        }
        Ok(out)
    }

    pub fn read_frame(&mut self) -> Result<DecodedBapFrame, CompatibilityClientError> {
        if let Some(f) = self.pending.pop() {
            return Ok(f);
        }
        loop {
            let n = {
                let stream = self
                    .stream
                    .as_mut()
                    .ok_or(CompatibilityClientError::NotConnected)?;
                match stream.read(&mut self.read_buf) {
                    Ok(0) => return Err(CompatibilityClientError::Eof),
                    Ok(n) => n,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        return Err(CompatibilityClientError::Io("timeout".into()));
                    }
                    Err(e) => return Err(CompatibilityClientError::Io(e.to_string())),
                }
            };
            let chunk = self.read_buf[..n].to_vec();
            let decoded = self.feed_bytes(&chunk)?;
            if let Some(first) = decoded.first().cloned() {
                for extra in decoded.into_iter().skip(1).rev() {
                    self.pending.push(extra);
                }
                return Ok(first);
            }
        }
    }

    fn expect_inbound(
        &mut self,
        frame: &DecodedBapFrame,
        expected_id: u16,
        encrypted: bool,
    ) -> Result<BapMessage, CompatibilityClientError> {
        let id = frame_msg_id(frame).ok_or_else(|| {
            CompatibilityClientError::InvalidMessage("opaque frame has no message id".into())
        })?;
        if id != expected_id {
            self.events.push(CompatibilityClientEvent::MessageRejected {
                id,
                reason: format!("expected 0x{expected_id:04x}"),
            });
            return Err(CompatibilityClientError::UnexpectedMessage(id));
        }
        match (encrypted, frame) {
            (false, DecodedBapFrame::Clear { .. }) => {}
            (true, DecodedBapFrame::Decrypted { .. }) => {}
            _ => {
                return Err(CompatibilityClientError::InvalidMessage(
                    "clear/encrypted mismatch".into(),
                ));
            }
        }
        let msg = decode_from_frame(frame, Direction::ServerToClient)
            .map_err(|e| CompatibilityClientError::InvalidMessage(e.to_string()))?;
        self.events.push(CompatibilityClientEvent::MessageReceived {
            id,
            direction: "S2C".into(),
        });
        self.events.push(CompatibilityClientEvent::Decoded {
            id,
            known: msg.is_known(),
        });
        let _ = self.dispatcher.dispatch(&msg);
        Ok(msg)
    }

    /// Reject inbound if message ID is not expected in current state.
    pub fn validate_expected_response(
        &mut self,
        frame: &DecodedBapFrame,
        expected_id: u16,
    ) -> Result<(), CompatibilityClientError> {
        let id = frame_msg_id(frame).unwrap_or(0);
        if id != expected_id {
            self.events.push(CompatibilityClientEvent::MessageRejected {
                id,
                reason: format!("out of order; expected 0x{expected_id:04x}"),
            });
            return Err(CompatibilityClientError::UnexpectedMessage(id));
        }
        Ok(())
    }

    /// Full synthetic handshake against LocalBapServer.
    pub fn run_handshake(&mut self) -> Result<(), CompatibilityClientError> {
        if self.state != ClientProtocolState::Connected {
            return Err(CompatibilityClientError::InvalidState(
                "handshake requires Connected",
            ));
        }

        // 0x1E → 0x1F
        self.send_clear(MSG_1E, PAYLOAD_1E)?;
        self.set_state(ClientProtocolState::ServiceHandshakeSent);
        let f = self.read_frame()?;
        self.expect_inbound(&f, MSG_1F, false)?;
        self.set_state(ClientProtocolState::ServiceHandshakeComplete);

        // 0x19 → 0x1A
        self.send_clear(MSG_19, PAYLOAD_19)?;
        self.set_state(ClientProtocolState::SessionLoginSent);
        let f = self.read_frame()?;
        let msg = self.expect_inbound(&f, MSG_1A, false)?;
        // Structural validation for synthetic harness 0x1A (opaque ASCII ok).
        if msg.id() != MSG_1A {
            return Err(CompatibilityClientError::UnexpectedMessage(msg.id()));
        }
        self.set_state(ClientProtocolState::SessionEstablished);
        self.crypto_ready = true;
        self.events
            .push(CompatibilityClientEvent::CryptoEstablished);

        // 0x79 → 0x7A
        self.send_encrypted(MSG_79, PAYLOAD_79)?;
        self.set_state(ClientProtocolState::EncryptedHandshakeSent);
        let f = self.read_frame()?;
        self.expect_inbound(&f, MSG_7A, true)?;
        self.set_state(ClientProtocolState::EncryptedChannelEstablished);
        self.set_state(ClientProtocolState::Active);
        Ok(())
    }

    pub fn send_nat_probe(&mut self) -> Result<(), CompatibilityClientError> {
        if !matches!(
            self.state,
            ClientProtocolState::EncryptedChannelEstablished | ClientProtocolState::Active
        ) {
            return Err(CompatibilityClientError::InvalidState("need Active"));
        }
        self.send_encrypted(MSG_12E, payload_12e())?;
        self.set_state(ClientProtocolState::Active);
        Ok(())
    }

    pub fn send_keepalive(&mut self) -> Result<DecodedBapFrame, CompatibilityClientError> {
        if self.state != ClientProtocolState::Active
            && self.state != ClientProtocolState::EncryptedChannelEstablished
        {
            return Err(CompatibilityClientError::InvalidState("need Active"));
        }
        self.send_clear(MSG_FA, PAYLOAD_FA)?;
        let f = self.read_frame()?;
        self.expect_inbound(&f, MSG_FB, false)?;
        self.set_state(ClientProtocolState::Active);
        Ok(f)
    }

    pub fn send_unknown(
        &mut self,
        id: u16,
        payload: &[u8],
    ) -> Result<(), CompatibilityClientError> {
        self.send_clear(id, payload)
    }

    pub fn close(&mut self) -> Result<(), CompatibilityClientError> {
        self.set_state(ClientProtocolState::Closing);
        if let Some(s) = self.stream.take() {
            let _ = s.shutdown(Shutdown::Both);
        }
        self.set_state(ClientProtocolState::Closed);
        self.events
            .push(CompatibilityClientEvent::Disconnected);
        self.session = None;
        self.crypto_ready = false;
        self.pending.clear();
        self.decoder = BapStreamDecoder::new();
        Ok(())
    }
}

fn payload_12e() -> &'static [u8] {
    // Prefer dedicated constant when present.
    #[allow(dead_code)]
    const FALLBACK: &[u8] = b"SIM_12E";
    if !PAYLOAD_12E_OPT.is_empty() {
        PAYLOAD_12E_OPT
    } else {
        FALLBACK
    }
}

// local_protocol may not export PAYLOAD_12E — use inline.
const PAYLOAD_12E_OPT: &[u8] = b"SIM_12E";

fn map_framing(e: StreamFramingError) -> CompatibilityClientError {
    CompatibilityClientError::Framing(e.to_string())
}

/// Full compatibility scenario runner (offline localhost).
pub struct LocalCompatibilityScenario;

impl LocalCompatibilityScenario {
    pub fn run(
        client: &mut BapCompatibilityClient,
        addr: SocketAddr,
    ) -> Result<(), CompatibilityClientError> {
        client.connect(addr)?;
        client.run_handshake()?;
        client.send_nat_probe()?;
        // 0x12F is S2C-oriented under local direction policy; client stays Active after 0x12E.
        let _ = client.send_keepalive()?;
        client.send_unknown(0x00AB, b"UNK_AB")?;
        // Server ObserveOnly — no reply expected; do not block on read.
        client.close()?;
        Ok(())
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn rejects_external_ip() {
        let addr = SocketAddr::from(([8, 8, 8, 8], 1234));
        assert!(assert_localhost_only(addr).is_err());
    }

    #[test]
    fn accepts_loopback() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 9));
        assert!(assert_localhost_only(addr).is_ok());
    }
}
