//! Local BAP replay client (M4.2) — connects only to localhost test servers.
//!
//! Named [`BapReplayClient`] deliberately — not a Destiny/Bungie client.

use crate::bap_session::{BapSession, BapSessionError, DecodedBapFrame};
use crate::crypto::NonceDirection;
use crate::local_protocol::{
    parse_msg_id, payload_for_msg, CryptoFixture, HandshakeReplayFixture, LocalProtocolError,
    ProtocolErrorKind, SimState, SIM_CONTEXT, SYNTHETIC_SESSION_KEY, SYNTHETIC_SESSION_NONCE,
    MSG_19, MSG_1A, MSG_1E, MSG_1F, MSG_79, MSG_7A, MSG_SYN_A, MSG_SYN_A_RSP, MSG_SYN_B,
    MSG_SYN_B_RSP, PAYLOAD_19, PAYLOAD_1E, PAYLOAD_79, PAYLOAD_SYN_A, PAYLOAD_SYN_B,
};
use crate::stream_framing::{BapStreamDecoder, StreamFramingError};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReplayClientError {
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("io: {0}")]
    Io(String),
    #[error("framing: {0}")]
    Framing(String),
    #[error("crypto: {0}")]
    Crypto(String),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("unexpected frame: {0}")]
    Unexpected(String),
    #[error("{0}")]
    Fixture(#[from] LocalProtocolError),
}

/// Replay / harness client for the local BAP compatibility server.
pub struct BapReplayClient {
    stream: Option<TcpStream>,
    session: BapSession,
    decoder: BapStreamDecoder,
    pub sim_state: SimState,
    read_buf: Vec<u8>,
    /// Pending decoded frames from previous TCP reads.
    pending: Vec<DecodedBapFrame>,
}

impl BapReplayClient {
    pub fn with_synthetic() -> Result<Self, ReplayClientError> {
        Self::with_keys(&SYNTHETIC_SESSION_KEY, &SYNTHETIC_SESSION_NONCE)
    }

    pub fn with_keys(key: &[u8], nonce: &[u8]) -> Result<Self, ReplayClientError> {
        let session =
            BapSession::new(key, nonce).map_err(|e| ReplayClientError::Crypto(e.to_string()))?;
        Ok(Self {
            stream: None,
            session,
            decoder: BapStreamDecoder::new(),
            sim_state: SimState::SimStart,
            read_buf: vec![0u8; 4096],
            pending: Vec::new(),
        })
    }

    pub fn from_crypto_fixture(fx: &CryptoFixture) -> Result<Self, ReplayClientError> {
        let key = fx.key_bytes()?;
        let nonce = fx.nonce_bytes()?;
        Self::with_keys(&key, &nonce)
    }

    pub fn connect(&mut self, addr: SocketAddr) -> Result<(), ReplayClientError> {
        self.connect_timeout(addr, Duration::from_secs(2))
    }

    pub fn connect_timeout(
        &mut self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> Result<(), ReplayClientError> {
        let stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| ReplayClientError::Connect(e.to_string()))?;
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        self.stream = Some(stream);
        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub fn session(&self) -> &BapSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut BapSession {
        &mut self.session
    }

    pub fn send_raw(&mut self, bytes: &[u8]) -> Result<(), ReplayClientError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| ReplayClientError::Connect("not connected".into()))?;
        stream
            .write_all(bytes)
            .map_err(|e| ReplayClientError::Io(e.to_string()))?;
        Ok(())
    }

    pub fn send_clear(
        &mut self,
        msg_id: u16,
        context: u32,
        payload: &[u8],
    ) -> Result<(), ReplayClientError> {
        let bytes = BapSession::encode_clear(msg_id, context, payload);
        self.send_raw(&bytes)
    }

    pub fn send_encrypted(
        &mut self,
        msg_id: u16,
        context: u32,
        payload: &[u8],
    ) -> Result<(), ReplayClientError> {
        let bytes = self
            .session
            .encode_encrypted(NonceDirection::ClientToServer, msg_id, context, payload)
            .map_err(|e| ReplayClientError::Crypto(e.to_string()))?;
        self.send_raw(&bytes)
    }

    /// Read until at least one full frame is decoded (or error/EOF).
    pub fn read_frame(&mut self) -> Result<DecodedBapFrame, ReplayClientError> {
        if let Some(f) = self.pending.pop() {
            return Ok(f);
        }
        loop {
            let n = {
                let stream = self
                    .stream
                    .as_mut()
                    .ok_or_else(|| ReplayClientError::Connect("not connected".into()))?;
                match stream.read(&mut self.read_buf) {
                    Ok(0) => {
                        return Err(ReplayClientError::Io("EOF".into()));
                    }
                    Ok(n) => n,
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        return Err(ReplayClientError::Io("timeout".into()));
                    }
                    Err(e) => return Err(ReplayClientError::Io(e.to_string())),
                }
            };

            let frames = self
                .decoder
                .push(&self.read_buf[..n])
                .map_err(|e| map_framing(e))?;

            let mut decoded = Vec::new();
            for raw in frames {
                match self
                    .session
                    .decode_frame(NonceDirection::ServerToClient, &raw.raw_bytes)
                {
                    Ok(d) => decoded.push(d),
                    Err(BapSessionError::DecryptFailed) => {
                        return Err(ReplayClientError::Crypto(
                            ProtocolErrorKind::GcmDecryptFailure.as_str().into(),
                        ));
                    }
                    Err(e) => {
                        return Err(ReplayClientError::Crypto(format!(
                            "{}: {e}",
                            ProtocolErrorKind::AuthCryptoError.as_str()
                        )));
                    }
                }
            }
            if let Some(first) = decoded.first().cloned() {
                // Keep remaining in pending (reverse so pop order is FIFO).
                for extra in decoded.into_iter().skip(1).rev() {
                    self.pending.push(extra);
                }
                return Ok(first);
            }
            // Incomplete frame — keep reading.
        }
    }

    /// SIMULATED_HANDSHAKE: 1E→1F→19→1A→79→7A then SIM_READY.
    pub fn run_handshake(&mut self) -> Result<(), ReplayClientError> {
        self.send_clear(MSG_1E, SIM_CONTEXT, PAYLOAD_1E)?;
        self.sim_state = SimState::Sim1eSent;
        let f = self.read_frame()?;
        expect_clear(&f, MSG_1F)?;
        self.sim_state = SimState::Sim1fSent;

        self.send_clear(MSG_19, SIM_CONTEXT, PAYLOAD_19)?;
        self.sim_state = SimState::Sim19Sent;
        let f = self.read_frame()?;
        expect_clear(&f, MSG_1A)?;
        self.sim_state = SimState::Sim1aSent;

        self.send_encrypted(MSG_79, SIM_CONTEXT, PAYLOAD_79)?;
        self.sim_state = SimState::Sim79Sent;
        let f = self.read_frame()?;
        expect_decrypted(&f, MSG_7A)?;
        self.sim_state = SimState::Sim7aSent;
        self.sim_state = SimState::SimReady;
        Ok(())
    }

    /// Post-handshake encrypted A/B exchange.
    pub fn run_encrypted_sequence(&mut self) -> Result<(), ReplayClientError> {
        if self.sim_state != SimState::SimReady {
            return Err(ReplayClientError::Protocol(
                "encrypted sequence requires SIM_READY".into(),
            ));
        }
        self.send_encrypted(MSG_SYN_A, SIM_CONTEXT, PAYLOAD_SYN_A)?;
        let f = self.read_frame()?;
        expect_decrypted(&f, MSG_SYN_A_RSP)?;

        self.send_encrypted(MSG_SYN_B, SIM_CONTEXT, PAYLOAD_SYN_B)?;
        let f = self.read_frame()?;
        expect_decrypted(&f, MSG_SYN_B_RSP)?;
        Ok(())
    }

    /// Execute a handshake_replay.json fixture (synthetic steps).
    pub fn run_fixture(&mut self, fx: &HandshakeReplayFixture) -> Result<(), ReplayClientError> {
        if fx.protocol != "SIMULATED_HANDSHAKE" {
            return Err(ReplayClientError::Protocol(format!(
                "unsupported protocol label '{}'",
                fx.protocol
            )));
        }
        for step in &fx.steps {
            let msg_id = parse_msg_id(&step.id)?;
            let context = step.context.unwrap_or(SIM_CONTEXT);
            let payload = if let Some(ref hx) = step.payload_hex {
                crate::local_protocol::hex_decode(hx)?
            } else {
                payload_for_msg(msg_id).to_vec()
            };

            match step.direction.as_str() {
                "C2S" => {
                    if step.encrypted {
                        self.send_encrypted(msg_id, context, &payload)?;
                    } else {
                        self.send_clear(msg_id, context, &payload)?;
                    }
                }
                "S2C" => {
                    let frame = self.read_frame()?;
                    if step.encrypted {
                        expect_decrypted(&frame, msg_id)?;
                    } else {
                        expect_clear(&frame, msg_id)?;
                    }
                }
                other => {
                    return Err(ReplayClientError::Protocol(format!(
                        "bad direction {other}"
                    )));
                }
            }
        }
        self.sim_state = SimState::SimReady;
        Ok(())
    }

    pub fn close(&mut self) {
        if let Some(s) = self.stream.take() {
            let _ = s.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for BapReplayClient {
    fn drop(&mut self) {
        self.close();
    }
}

fn expect_clear(frame: &DecodedBapFrame, msg_id: u16) -> Result<(), ReplayClientError> {
    match frame {
        DecodedBapFrame::Clear { msg_id: id, .. } if *id == msg_id => Ok(()),
        other => Err(ReplayClientError::Unexpected(format!(
            "expected clear 0x{msg_id:04x}, got {other:?}"
        ))),
    }
}

fn expect_decrypted(frame: &DecodedBapFrame, msg_id: u16) -> Result<(), ReplayClientError> {
    match frame {
        DecodedBapFrame::Decrypted {
            msg_id: Some(id), ..
        } if *id == msg_id => Ok(()),
        other => Err(ReplayClientError::Unexpected(format!(
            "expected decrypted 0x{msg_id:04x}, got {other:?}"
        ))),
    }
}

fn map_framing(e: StreamFramingError) -> ReplayClientError {
    match e {
        StreamFramingError::InvalidMagic(_) | StreamFramingError::InvalidKind(_) => {
            ReplayClientError::Framing(ProtocolErrorKind::ProtocolError.as_str().into())
        }
        other => ReplayClientError::Framing(other.to_string()),
    }
}
