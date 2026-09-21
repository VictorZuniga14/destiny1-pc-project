//! Minimal offline CLI helpers (no networking).

use crate::bap_pipeline_verify::{self, PipelineVerifyError};
use crate::bap_session_verify::{self, BapVerifyError};
use crate::evidence_adapter::{self, AdapterError};
use crate::framing::FrameKind;
use crate::gcm_first_frame::{self, FirstFrameError};
use crate::gcm_nonce_reconstruct::{self, NonceInputError};
use crate::gcm_sequence::{self, SequenceError};
use crate::jsonl::{self, JsonlError};
use crate::message_inventory_verify::{self, MessageInventoryError};
use crate::message_correlation_verify;
use crate::multi_capture::MultiCaptureStatus;
use crate::multi_capture_verify::{self, MultiCaptureVerifyError};
use crate::local_server_verify::{self, LocalServerVerifyError};
use crate::payload_structure_verify;
use crate::protocol_spec_verify;
use crate::session_crypto_verify::{self, VerifyInputError};
use crate::state_machine_verify;
use crate::stream_framing_verify::{self, StreamVerifyError};
use crate::timeline::{Timeline, TimelineEntry};
use crate::udp_evidence_verify::{self, UdpEvidenceVerifyError};
use crate::message_codec_verify::{self, MessageCodecVerifyError};
use crate::stateful_server_verify::{self, StatefulServerVerifyError};
use crate::compatibility_client_verify::{self, CompatibilityClientVerifyError};
use crate::external_boundary_verify::{self, ExternalBoundaryVerifyError};
use crate::observation_verify::{self, ObservationVerifyError};
use crate::compatibility_matrix_verify::{self, CompatibilityMatrixVerifyError};
use crate::signon_verify::{self, SignOnVerifyError};
use std::path::Path;
use thiserror::Error;

const USAGE: &str = "usage: destiny1-network timeline <path> | destiny1-network timeline-external <path> | destiny1-network session-crypto-verify <path> | destiny1-network gcm-nonce-reconstruct <path> | destiny1-network gcm-first-frame-verify <path> | destiny1-network gcm-sequence-verify <path> | destiny1-network bap-session-verify <path> | destiny1-network bap-stream-verify <path> | destiny1-network bap-pipeline-verify <path> | destiny1-network multi-capture-verify <manifest-or-fixture> | destiny1-network message-inventory <manifest> | destiny1-network payload-structure-verify <manifest> | destiny1-network message-correlation-verify <manifest> | destiny1-network state-machine-verify <manifest> | destiny1-network protocol-spec-verify <manifest> | destiny1-network local-server | destiny1-network local-replay <fixture> | destiny1-network udp-evidence-verify <manifest> | destiny1-network message-codec-verify [manifest] | destiny1-network stateful-server-verify | destiny1-network compatibility-client-verify | destiny1-network external-boundary-verify | destiny1-network observation-verify | destiny1-network observation-diff <expected> <observed> | destiny1-network compatibility-matrix-verify | destiny1-network compatibility-matrix-report | destiny1-network signon-verify | destiny1-network signon-report";

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{USAGE}")]
    Usage,
    #[error(
        "unknown command '{0}' (supported: timeline, timeline-external, session-crypto-verify, gcm-nonce-reconstruct, gcm-first-frame-verify, gcm-sequence-verify, bap-session-verify, bap-stream-verify, bap-pipeline-verify, multi-capture-verify, message-inventory, payload-structure-verify, message-correlation-verify, state-machine-verify, protocol-spec-verify, local-server, local-server-verify, local-replay, udp-evidence-verify, message-codec-verify, stateful-server-verify, local-server-e2e, compatibility-client-verify, external-boundary-verify, observation-verify, observation-diff, compatibility-matrix-verify, compatibility-matrix-report, signon-verify, signon-report)"
    )]
    UnknownCommand(String),
    #[error("file not found: {0}")]
    FileNotFound(String),
    #[error("{0}")]
    Jsonl(#[from] JsonlError),
    #[error("external evidence: {0}")]
    Adapter(#[from] AdapterError),
    #[error("{0}")]
    SessionCrypto(#[from] VerifyInputError),
    #[error("session-crypto-verify: cryptographic checks failed (see report above)")]
    SessionCryptoFailed,
    #[error("{0}")]
    GcmNonce(#[from] NonceInputError),
    #[error("gcm-nonce-reconstruct: derived nonce does not match expected (see report above)")]
    GcmNonceMismatch,
    #[error("{0}")]
    FirstFrame(#[from] FirstFrameError),
    #[error("gcm-first-frame-verify: decrypt/length check failed (see report above)")]
    FirstFrameFailed,
    #[error("{0}")]
    Sequence(#[from] SequenceError),
    #[error("gcm-sequence-verify: sequence check failed (see report above)")]
    SequenceFailed,
    #[error("{0}")]
    BapVerify(#[from] BapVerifyError),
    #[error("bap-session-verify: validation failed (see report above)")]
    BapVerifyFailed,
    #[error("{0}")]
    StreamVerify(#[from] StreamVerifyError),
    #[error("bap-stream-verify: validation failed (see report above)")]
    StreamVerifyFailed,
    #[error("{0}")]
    PipelineVerify(#[from] PipelineVerifyError),
    #[error("bap-pipeline-verify: validation failed (see report above)")]
    PipelineVerifyFailed,
    #[error("{0}")]
    MultiCapture(#[from] MultiCaptureVerifyError),
    #[error("multi-capture-verify: blocked or failed (see report above)")]
    MultiCaptureFailed,
    #[error("{0}")]
    MessageInventory(#[from] MessageInventoryError),
    #[error("message-inventory: failed (see report above)")]
    MessageInventoryFailed,
    #[error("{0}")]
    LocalServer(#[from] LocalServerVerifyError),
    #[error("local-replay: verification failed (see report above)")]
    LocalReplayFailed,
    #[error("{0}")]
    UdpEvidence(#[from] UdpEvidenceVerifyError),
    #[error("udp-evidence-verify: failed (see report above)")]
    UdpEvidenceFailed,
    #[error("{0}")]
    MessageCodec(#[from] MessageCodecVerifyError),
    #[error("message-codec-verify: failed (see report above)")]
    MessageCodecFailed,
    #[error("{0}")]
    StatefulServer(#[from] StatefulServerVerifyError),
    #[error("stateful-server-verify: failed (see report above)")]
    StatefulServerFailed,
    #[error("{0}")]
    CompatibilityClient(#[from] CompatibilityClientVerifyError),
    #[error("compatibility-client-verify: failed (see report above)")]
    CompatibilityClientFailed,
    #[error("{0}")]
    ExternalBoundary(#[from] ExternalBoundaryVerifyError),
    #[error("external-boundary-verify: failed (see report above)")]
    ExternalBoundaryFailed,
    #[error("{0}")]
    Observation(#[from] ObservationVerifyError),
    #[error("observation-verify: failed (see report above)")]
    ObservationFailed,
    #[error("{0}")]
    CompatibilityMatrix(#[from] CompatibilityMatrixVerifyError),
    #[error("compatibility-matrix-verify: failed (see report above)")]
    CompatibilityMatrixFailed,
    #[error("{0}")]
    SignOn(#[from] SignOnVerifyError),
    #[error("signon-verify: failed (see report above)")]
    SignOnFailed,
}

impl CliError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage | Self::UnknownCommand(_) => 2,
            Self::FileNotFound(_)
            | Self::Jsonl(_)
            | Self::Adapter(_)
            | Self::SessionCrypto(_)
            | Self::SessionCryptoFailed
            | Self::GcmNonce(_)
            | Self::GcmNonceMismatch
            | Self::FirstFrame(_)
            | Self::FirstFrameFailed
            | Self::Sequence(_)
            | Self::SequenceFailed
            | Self::BapVerify(_)
            | Self::BapVerifyFailed
            | Self::StreamVerify(_)
            | Self::StreamVerifyFailed
            | Self::PipelineVerify(_)
            | Self::PipelineVerifyFailed
            | Self::MultiCapture(_)
            | Self::MultiCaptureFailed
            | Self::MessageInventory(_)
            | Self::MessageInventoryFailed
            | Self::LocalServer(_)
            | Self::LocalReplayFailed
            | Self::UdpEvidence(_)
            | Self::UdpEvidenceFailed
            | Self::MessageCodec(_)
            | Self::MessageCodecFailed
            | Self::StatefulServer(_)
            | Self::StatefulServerFailed
            | Self::CompatibilityClient(_)
            | Self::CompatibilityClientFailed
            | Self::ExternalBoundary(_)
            | Self::ExternalBoundaryFailed
            | Self::Observation(_)
            | Self::ObservationFailed
            | Self::CompatibilityMatrix(_)
            | Self::CompatibilityMatrixFailed
            | Self::SignOn(_)
            | Self::SignOnFailed => 1,
        }
    }
}

fn is_path_cmd(cmd: &str) -> bool {
    matches!(
        cmd,
        "timeline"
            | "timeline-external"
            | "session-crypto-verify"
            | "gcm-nonce-reconstruct"
            | "gcm-first-frame-verify"
            | "gcm-sequence-verify"
            | "bap-session-verify"
            | "bap-stream-verify"
            | "bap-pipeline-verify"
            | "multi-capture-verify"
            | "message-inventory"
            | "payload-structure-verify"
            | "message-correlation-verify"
            | "state-machine-verify"
            | "protocol-spec-verify"
            | "local-replay"
            | "udp-evidence-verify"
    )
}

/// Parse argv (without program name) and run the requested command.
pub fn run(args: &[String]) -> Result<(), CliError> {
    match args {
        [] => Err(CliError::Usage),
        [cmd, ..] if cmd == "help" || cmd == "--help" || cmd == "-h" => Err(CliError::Usage),
        [cmd] if is_path_cmd(cmd) => Err(CliError::Usage),
        [cmd, path] if cmd == "timeline" => run_timeline(path),
        [cmd, path] if cmd == "timeline-external" => run_timeline_external(path),
        [cmd, path] if cmd == "session-crypto-verify" => run_session_crypto_verify(path),
        [cmd, path] if cmd == "gcm-nonce-reconstruct" => run_gcm_nonce_reconstruct(path),
        [cmd, path] if cmd == "gcm-first-frame-verify" => run_gcm_first_frame_verify(path),
        [cmd, path] if cmd == "gcm-sequence-verify" => run_gcm_sequence_verify(path),
        [cmd, path] if cmd == "bap-session-verify" => run_bap_session_verify(path),
        [cmd, path] if cmd == "bap-stream-verify" => run_bap_stream_verify(path),
        [cmd, path] if cmd == "bap-pipeline-verify" => run_bap_pipeline_verify(path),
        [cmd, path] if cmd == "multi-capture-verify" => run_multi_capture_verify(path),
        [cmd, path] if cmd == "message-inventory" => run_message_inventory(path),
        [cmd, path] if cmd == "payload-structure-verify" => run_payload_structure_verify(path),
        [cmd, path] if cmd == "message-correlation-verify" => run_message_correlation_verify(path),
        [cmd, path] if cmd == "state-machine-verify" => run_state_machine_verify(path),
        [cmd, path] if cmd == "protocol-spec-verify" => run_protocol_spec_verify(path),
        [cmd, path] if cmd == "local-replay" => run_local_replay(path),
        [cmd, path] if cmd == "udp-evidence-verify" => run_udp_evidence_verify(path),
        [cmd] if cmd == "message-codec-verify" => run_message_codec_verify(None),
        [cmd, path] if cmd == "message-codec-verify" => run_message_codec_verify(Some(path)),
        [cmd] if cmd == "stateful-server-verify" => run_stateful_server_verify(),
        [cmd] if cmd == "compatibility-client-verify" => run_compatibility_client_verify(),
        [cmd] if cmd == "external-boundary-verify" => run_external_boundary_verify(),
        [cmd] if cmd == "observation-verify" => run_observation_verify(),
        [cmd, expected, observed] if cmd == "observation-diff" => {
            run_observation_diff(expected, observed)
        }
        [cmd] if cmd == "compatibility-matrix-verify" => run_compatibility_matrix_verify(),
        [cmd] if cmd == "compatibility-matrix-report" => run_compatibility_matrix_report(),
        [cmd] if cmd == "signon-verify" => run_signon_verify(),
        [cmd] if cmd == "signon-report" => run_signon_report(),
        [cmd] if cmd == "local-server-verify" => run_local_server_verify(),
        [cmd] if cmd == "local-server-e2e" => run_local_server_e2e(),
        [cmd] if cmd == "local-server" => run_local_server(),
        [cmd, ..] if is_path_cmd(cmd) => Err(CliError::Usage),
        [cmd, ..] => Err(CliError::UnknownCommand(cmd.clone())),
    }
}

pub fn run_timeline(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let records = jsonl::parse_jsonl_path(path)?;
    print_timeline(&Timeline::from_evidence(&records));
    Ok(())
}

/// External `decrypted_bap.jsonl`-compatible file → adapter → timeline.
pub fn run_timeline_external(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let records = evidence_adapter::adapt_jsonl_path(path)?;
    print_timeline(&Timeline::from_evidence(&records));
    Ok(())
}

pub fn run_session_crypto_verify(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let report = session_crypto_verify::verify_from_path(path)?;
    print!("{}", report);
    match report.classification() {
        crate::crypto::VerifyClass::Verified => Ok(()),
        crate::crypto::VerifyClass::Partial | crate::crypto::VerifyClass::Failed => {
            Err(CliError::SessionCryptoFailed)
        }
    }
}

pub fn run_gcm_nonce_reconstruct(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let report = gcm_nonce_reconstruct::reconstruct_from_path(path)?;
    print!("{}", report);
    match report.matches_expected {
        Some(false) => Err(CliError::GcmNonceMismatch),
        _ => Ok(()),
    }
}

/// Offline AES-GCM decrypt of the first encrypted frame using real wire + M2.3/M2.4b inputs.
pub fn run_gcm_first_frame_verify(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let report = gcm_first_frame::verify_from_path(path)?;
    print!("{}", report);
    if report.verified() {
        Ok(())
    } else {
        Err(CliError::FirstFrameFailed)
    }
}

/// Offline multi-frame AES-GCM verify with per-direction nonce progression.
pub fn run_gcm_sequence_verify(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let report = gcm_sequence::verify_from_path(path)?;
    print!("{}", report);
    if report.all_verified() {
        Ok(())
    } else {
        Err(CliError::SequenceFailed)
    }
}

/// Offline BapSession mass verify (clear + encrypted framing + crypto).
pub fn run_bap_session_verify(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let report = bap_session_verify::verify_from_path(path)?;
    print!("{}", report);
    if report.verified() {
        Ok(())
    } else {
        Err(CliError::BapVerifyFailed)
    }
}

/// Offline chunked stream → BapStreamDecoder → BapSession (M2.7).
pub fn run_bap_stream_verify(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let report = stream_framing_verify::verify_from_path(
        path,
        stream_framing_verify::DEFAULT_CHUNK_SIZES,
    )?;
    print!("{}", report);
    if report.verified() {
        Ok(())
    } else {
        Err(CliError::StreamVerifyFailed)
    }
}

/// Offline MockByteSource → pipeline → BapSession (M2.8).
pub fn run_bap_pipeline_verify(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let report = bap_pipeline_verify::verify_from_path(
        path,
        crate::byte_source::DEFAULT_PIPELINE_CHUNK_SIZES,
    )?;
    print!("{}", report);
    if report.verified() {
        Ok(())
    } else {
        Err(CliError::PipelineVerifyFailed)
    }
}

/// Offline multi-capture stability (M2.9). Accepts a manifest JSON or a single
/// pipeline fixture. Exit 0 for VERIFIED_MULTI_CAPTURE or READY_FOR_EXTERNAL_CAPTURE.
pub fn run_multi_capture_verify(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let text = std::fs::read_to_string(path).map_err(|_| {
        CliError::MultiCapture(MultiCaptureVerifyError::Io)
    })?;
    let summary = {
        let is_manifest = serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .and_then(|v| v.get("captures").map(|_| true))
            .unwrap_or(false);
        if is_manifest {
            multi_capture_verify::verify_from_manifest_path(path)?
        } else {
            multi_capture_verify::verify_single_pipeline_fixture(path)?
        }
    };
    print!("{}", summary);
    match summary.status {
        MultiCaptureStatus::VerifiedMultiCapture | MultiCaptureStatus::ReadyForExternalCapture => {
            Ok(())
        }
        MultiCaptureStatus::Blocked => Err(CliError::MultiCaptureFailed),
    }
}

/// Offline message inventory across pipeline-ready captures (M3.1).
pub fn run_message_inventory(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let report = message_inventory_verify::run_from_manifest(path)?;
    print!("{}", report);
    let out = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("message_inventory_safe.json");
    // Prefer writing under fixtures/message_inventory when manifest lives there.
    let export_path = if path
        .components()
        .any(|c| c.as_os_str() == "multi_capture")
    {
        Path::new("fixtures/message_inventory/cross_capture_safe.json").to_path_buf()
    } else {
        out
    };
    if let Some(parent) = export_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    message_inventory_verify::write_safe_export(&export_path, &report.safe_export)?;
    println!();
    println!("safe_export: {}", export_path.display());
    Ok(())
}

/// Offline payload structure analysis (M3.2).
pub fn run_payload_structure_verify(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let report = payload_structure_verify::run_from_manifest(path)?;
    print!("{}", report);
    let export_path = payload_structure_verify::default_export_path(path);
    payload_structure_verify::write_safe_export(&export_path, &report)?;
    println!();
    println!("safe_export: {}", export_path.display());
    Ok(())
}

/// Offline message correlation analysis (M3.3).
pub fn run_message_correlation_verify(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let report = message_correlation_verify::run_from_manifest(path)?;
    print!("{}", report);
    let export_path = message_correlation_verify::default_export_path(path);
    message_correlation_verify::write_safe_export(&export_path, &report.safe_export)?;
    println!();
    println!("safe_export: {}", export_path.display());
    Ok(())
}

/// Offline observational state machine (M3.4).
pub fn run_state_machine_verify(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let report = state_machine_verify::run_from_manifest(path)?;
    print!("{}", report);
    let export_path = state_machine_verify::default_export_path(path);
    state_machine_verify::write_safe_export(&export_path, &report.safe_export)?;
    println!();
    println!("safe_export: {}", export_path.display());
    Ok(())
}

/// Offline protocol specification export (M4.1).
pub fn run_protocol_spec_verify(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let report = protocol_spec_verify::run_from_manifest(path)?;
    print!("{}", report);
    let export_path = protocol_spec_verify::default_export_path(path);
    protocol_spec_verify::write_safe_export(&export_path, &report.export)?;
    println!();
    println!("safe_export: {}", export_path.display());
    Ok(())
}

pub fn run_local_replay(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    local_server_verify::run_local_replay(path).map_err(|e| match e {
        LocalServerVerifyError::FileNotFound(p) => CliError::FileNotFound(p),
        other => CliError::LocalServer(other),
    })
}

pub fn run_local_server() -> Result<(), CliError> {
    local_server_verify::run_local_server_cli().map_err(CliError::LocalServer)
}

pub fn run_local_server_verify() -> Result<(), CliError> {
    local_server_verify::run_local_server_verify().map_err(CliError::LocalServer)
}

pub fn run_local_server_e2e() -> Result<(), CliError> {
    // Thin CLI wrapper: run the same offline path as local-server-verify and report PASS.
    local_server_verify::run_local_server_verify().map_err(CliError::LocalServer)?;
    println!("LOCAL_SERVER_E2E: PASS");
    Ok(())
}

pub fn run_udp_evidence_verify(path: impl AsRef<Path>) -> Result<(), CliError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(CliError::FileNotFound(path.display().to_string()));
    }
    let report = udp_evidence_verify::run_from_manifest(path)?;
    print!("{}", report);
    if report.result == "VERIFIED" {
        Ok(())
    } else {
        Err(CliError::UdpEvidenceFailed)
    }
}

pub fn run_message_codec_verify(path: Option<&String>) -> Result<(), CliError> {
    let report = if let Some(p) = path {
        let path = Path::new(p);
        if !path.exists() {
            return Err(CliError::FileNotFound(path.display().to_string()));
        }
        message_codec_verify::run_from_manifest(path)?
    } else {
        message_codec_verify::run_default()?
    };
    print!("{}", report);
    if report.result == "VERIFIED" {
        Ok(())
    } else {
        Err(CliError::MessageCodecFailed)
    }
}

pub fn run_stateful_server_verify() -> Result<(), CliError> {
    stateful_server_verify::run_default().map_err(|e| match e {
        StatefulServerVerifyError::FileNotFound(p) => CliError::FileNotFound(p),
        other => CliError::StatefulServer(other),
    })
}

pub fn run_compatibility_client_verify() -> Result<(), CliError> {
    compatibility_client_verify::run_default().map_err(|e| match e {
        CompatibilityClientVerifyError::FileNotFound(p) => CliError::FileNotFound(p),
        other => CliError::CompatibilityClient(other),
    })
}

pub fn run_external_boundary_verify() -> Result<(), CliError> {
    external_boundary_verify::run_default().map_err(|e| match e {
        ExternalBoundaryVerifyError::FileNotFound(p) => CliError::FileNotFound(p),
        other => CliError::ExternalBoundary(other),
    })
}

pub fn run_observation_verify() -> Result<(), CliError> {
    observation_verify::run_default().map_err(|e| match e {
        ObservationVerifyError::FileNotFound(p) => CliError::FileNotFound(p),
        other => CliError::Observation(other),
    })
}

pub fn run_observation_diff(expected: &str, observed: &str) -> Result<(), CliError> {
    let e = Path::new(expected);
    let o = Path::new(observed);
    if !e.exists() {
        return Err(CliError::FileNotFound(expected.into()));
    }
    if !o.exists() {
        return Err(CliError::FileNotFound(observed.into()));
    }
    observation_verify::run_diff(e, o).map_err(CliError::Observation)
}

pub fn run_compatibility_matrix_verify() -> Result<(), CliError> {
    compatibility_matrix_verify::run_verify().map_err(|e| match e {
        CompatibilityMatrixVerifyError::FileNotFound(p) => CliError::FileNotFound(p),
        other => CliError::CompatibilityMatrix(other),
    })
}

pub fn run_compatibility_matrix_report() -> Result<(), CliError> {
    compatibility_matrix_verify::run_report().map_err(CliError::CompatibilityMatrix)
}

pub fn run_signon_verify() -> Result<(), CliError> {
    signon_verify::run_verify().map_err(|e| match e {
        SignOnVerifyError::FileNotFound(p) => CliError::FileNotFound(p),
        other => CliError::SignOn(other),
    })
}

pub fn run_signon_report() -> Result<(), CliError> {
    signon_verify::run_report().map_err(CliError::SignOn)
}

fn print_timeline(timeline: &Timeline) {
    for line in timeline.format_cli_lines() {
        println!("{line}");
    }
}

impl Timeline {
    pub fn format_cli_lines(&self) -> Vec<String> {
        self.entries().iter().map(|e| e.format_cli_line()).collect()
    }
}

impl TimelineEntry {
    pub fn format_cli_line(&self) -> String {
        let ts = format!("[{:06}ms]", self.timestamp_ms);
        let dir = match self.direction {
            crate::jsonl::Direction::ClientToServer => "C -> S",
            crate::jsonl::Direction::ServerToClient => "S -> C",
        };
        let kind_n = self.kind.as_u8();
        match self.kind {
            FrameKind::Encrypted => {
                format!(
                    "{ts} {dir} | kind={kind_n} | encrypted | payload_len={}",
                    self.payload_length
                )
            }
            FrameKind::Clear | FrameKind::Other(_) => {
                let id = match self.message_id {
                    Some(id) => format!("0x{id:04x}"),
                    None => "unknown".to_string(),
                };
                let name = self.message_name.unwrap_or("unknown");
                let context = match self.context {
                    Some(c) => format!("context={c}"),
                    None => "context=?".to_string(),
                };
                format!(
                    "{ts} {dir} | kind={kind_n} | {id} | {name} | {context} | payload_len={}",
                    self.payload_length
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{clear_frame, encrypted_frame};
    use crate::jsonl::Direction;
    use crate::timeline::TimelineEntry;

    #[test]
    fn formats_clear_and_encrypted_lines() {
        let clear =
            TimelineEntry::from_parts(52, Direction::ClientToServer, &clear_frame(0x19, 2, b"ab"));
        assert_eq!(
            clear.format_cli_line(),
            "[000052ms] C -> S | kind=2 | 0x0019 | session-login-request | context=2 | payload_len=2"
        );
        let enc = TimelineEntry::from_parts(
            103,
            Direction::ClientToServer,
            &encrypted_frame([0u8; 16], &[1, 2, 3, 4]),
        );
        assert_eq!(
            enc.format_cli_line(),
            "[000103ms] C -> S | kind=1 | encrypted | payload_len=20"
        );
    }

    #[test]
    fn usage_on_empty_args() {
        let err = run(&[]).unwrap_err();
        assert!(matches!(err, CliError::Usage));
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn missing_file_timeline() {
        let err = run(&["timeline".into(), "no/such/file.jsonl".into()]).unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_timeline_external() {
        let err = run(&[
            "timeline-external".into(),
            "no/such/external.jsonl".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_session_crypto_verify() {
        let err = run(&[
            "session-crypto-verify".into(),
            "no/such/verify.json".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_gcm_nonce_reconstruct() {
        let err = run(&[
            "gcm-nonce-reconstruct".into(),
            "no/such/nonce.json".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_gcm_first_frame_verify() {
        let err = run(&[
            "gcm-first-frame-verify".into(),
            "no/such/frame.json".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_gcm_sequence_verify() {
        let err = run(&[
            "gcm-sequence-verify".into(),
            "no/such/sequence.json".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_bap_session_verify() {
        let err = run(&[
            "bap-session-verify".into(),
            "no/such/bap.json".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_bap_stream_verify() {
        let err = run(&[
            "bap-stream-verify".into(),
            "no/such/stream.json".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_bap_pipeline_verify() {
        let err = run(&[
            "bap-pipeline-verify".into(),
            "no/such/pipeline.json".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_multi_capture_verify() {
        let err = run(&[
            "multi-capture-verify".into(),
            "no/such/manifest.json".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_message_inventory() {
        let err = run(&[
            "message-inventory".into(),
            "no/such/inventory.json".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_payload_structure_verify() {
        let err = run(&[
            "payload-structure-verify".into(),
            "no/such/payload.json".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_message_correlation_verify() {
        let err = run(&[
            "message-correlation-verify".into(),
            "no/such/correlation.json".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_state_machine_verify() {
        let err = run(&[
            "state-machine-verify".into(),
            "no/such/state.json".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn missing_file_protocol_spec_verify() {
        let err = run(&[
            "protocol-spec-verify".into(),
            "no/such/spec.json".into(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::FileNotFound(_)));
        assert_eq!(err.exit_code(), 1);
    }
}
