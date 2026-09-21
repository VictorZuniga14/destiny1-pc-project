//! CLI / offline verify helpers for M4.2 local server + replay.

use crate::local_protocol::{CryptoFixture, HandshakeReplayFixture, LocalProtocolError};
use crate::local_server::{LocalBapServer, LocalServerConfig, LocalServerError};
use crate::replay_client::{BapReplayClient, ReplayClientError};
use std::path::Path;
use std::thread;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LocalServerVerifyError {
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("fixture: {0}")]
    Fixture(String),
    #[error("server: {0}")]
    Server(#[from] LocalServerError),
    #[error("client: {0}")]
    Client(#[from] ReplayClientError),
    #[error("verify failed: {0}")]
    Failed(String),
}

impl From<LocalProtocolError> for LocalServerVerifyError {
    fn from(e: LocalProtocolError) -> Self {
        LocalServerVerifyError::Fixture(e.to_string())
    }
}

/// Run `local-replay` against a handshake fixture (starts ephemeral local server).
pub fn run_local_replay(path: impl AsRef<Path>) -> Result<(), LocalServerVerifyError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(LocalServerVerifyError::FileNotFound(
            path.display().to_string(),
        ));
    }
    let text = std::fs::read_to_string(path)
        .map_err(|e| LocalServerVerifyError::Fixture(e.to_string()))?;
    let fixture: HandshakeReplayFixture = serde_json::from_str(&text)
        .map_err(|e| LocalServerVerifyError::Fixture(e.to_string()))?;

    let crypto_path = path
        .parent()
        .map(|p| p.join("crypto_fixture.json"))
        .filter(|p| p.exists());
    let (key, nonce) = if let Some(cp) = crypto_path {
        let ctext = std::fs::read_to_string(&cp)
            .map_err(|e| LocalServerVerifyError::Fixture(e.to_string()))?;
        let cf: CryptoFixture = serde_json::from_str(&ctext)
            .map_err(|e| LocalServerVerifyError::Fixture(e.to_string()))?;
        (cf.key_bytes()?, cf.nonce_bytes()?)
    } else {
        let cf = CryptoFixture::synthetic_default();
        (cf.key_bytes()?, cf.nonce_bytes()?)
    };

    let mut server = LocalBapServer::with_crypto(
        LocalServerConfig::loopback_ephemeral(),
        key.clone(),
        nonce.clone(),
    );
    let addr = server.bind()?;
    server.start_background()?;
    thread::sleep(Duration::from_millis(30));

    let mut client = BapReplayClient::with_keys(&key, &nonce)?;
    client.connect(addr)?;

    println!("LOCAL_REPLAY: start fixture={}", fixture.name);
    client.run_fixture(&fixture)?;
    if fixture.protocol == "SIMULATED_HANDSHAKE" {
        client.run_encrypted_sequence()?;
    }

    let c2s = client.session().client_to_server_counter();
    let s2c = client.session().server_to_client_counter();
    println!("LOCAL_REPLAY: c2s_counter={c2s} s2c_counter={s2c}");
    if c2s == 0 || s2c == 0 {
        client.close();
        server.shutdown();
        return Err(LocalServerVerifyError::Failed(
            "nonce counters did not advance".into(),
        ));
    }

    for ev in server.traces() {
        let mid = ev
            .message_id
            .map(|m| format!("0x{m:04x}"))
            .unwrap_or_else(|| "-".into());
        println!(
            "TRACE conn={} dir={} id={} state={} action={}",
            ev.connection_id, ev.direction, mid, ev.state, ev.action
        );
    }

    client.close();
    server.shutdown();
    println!("LOCAL_REPLAY: VERIFIED");
    Ok(())
}

/// Offline verify: bind ephemeral server, synthetic handshake + encrypted sequence.
pub fn run_local_server_verify() -> Result<(), LocalServerVerifyError> {
    let mut server = LocalBapServer::new(LocalServerConfig::loopback_ephemeral());
    let addr = server.bind()?;
    server.start_background()?;
    thread::sleep(Duration::from_millis(30));

    let mut client = BapReplayClient::with_synthetic()?;
    client.connect(addr)?;
    client.run_handshake()?;
    client.run_encrypted_sequence()?;

    let c2s = client.session().client_to_server_counter();
    let s2c = client.session().server_to_client_counter();
    if c2s == 0 || s2c == 0 {
        client.close();
        server.shutdown();
        return Err(LocalServerVerifyError::Failed(
            "nonce counters did not advance".into(),
        ));
    }

    client.close();
    server.shutdown();
    println!("LOCAL_SERVER_VERIFY: VERIFIED");
    Ok(())
}

/// Run `local-server` CLI (localhost listen until process exit).
pub fn run_local_server_cli() -> Result<(), LocalServerVerifyError> {
    let mut server = LocalBapServer::new(LocalServerConfig::loopback_ephemeral());
    let addr = server.bind()?;
    println!("{}", server.status_banner());
    println!("bound_addr={addr}");
    println!("(localhost only — no external network)");
    server.start_background()?;
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
