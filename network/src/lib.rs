//! Offline BAP analyzer for Destiny 1 network research.
//!
//! This crate parses documented BAP framing, classifies known message IDs,
//! and builds timelines from synthetic or locally supplied evidence records.
//! It does **not** speak to live servers or handle UDP.
//!
//! Crypto modules are offline primitives for synthetic fixtures and local
//! session-record experiments only.

pub mod bap_pipeline;
pub mod bap_pipeline_verify;
pub mod bap_session;
pub mod bap_session_verify;
pub mod byte_source;
pub mod cli;
pub mod compatibility_client;
pub mod compatibility_client_verify;
pub mod compatibility_matrix;
pub mod compatibility_matrix_verify;
pub mod crypto;
pub mod evidence_adapter;
pub mod external_boundary_verify;
pub mod external_client_boundary;
pub mod framing;
pub mod gcm_first_frame;
pub mod gcm_nonce_reconstruct;
pub mod gcm_sequence;
pub mod jsonl;
pub mod local_protocol;
pub mod local_server;
pub mod local_server_verify;
pub mod message_codec;
pub mod message_codec_verify;
pub mod message_dispatcher;
pub mod message_inventory;
pub mod message_inventory_verify;
pub mod message_correlation;
pub mod message_correlation_verify;
pub mod message_registry;
pub mod messages;
pub mod multi_capture;
pub mod multi_capture_verify;
pub mod observation;
pub mod observation_analyze;
pub mod observation_diff;
pub mod observation_scenarios;
pub mod observation_trace;
pub mod observation_verify;
pub mod payload_structure;
pub mod payload_structure_verify;
pub mod protocol_observation;
pub mod protocol_spec;
pub mod protocol_spec_verify;
pub mod replay_client;
pub mod session_crypto_verify;
pub mod protocol_state;
pub mod response_policy;
pub mod signon;
pub mod signon_analysis;
pub mod signon_boundary;
pub mod signon_spec;
pub mod signon_verify;
pub mod state_machine;
pub mod state_machine_verify;
pub mod stateful_bap_session;
pub mod stateful_server_verify;
pub mod stream_framing;
pub mod stream_framing_verify;
pub mod tcp_byte_source;
pub mod test_crypto_material;
pub mod timeline;
pub mod udp_analysis;
pub mod udp_evidence;
pub mod udp_evidence_verify;

pub use bap_pipeline::{BapOfflinePipeline, PipelineError};
pub use bap_session::{BapSession, BapSessionError, DecodedBapFrame};
pub use byte_source::{ByteSource, ByteSourceError, MockByteSource};
pub use crypto::{
    AesGcmBlob, CryptoError, KEY_LEN, NONCE_LEN, TAG_LEN, SessionCryptoContext, decrypt_aes_gcm,
    encrypt_aes_gcm,
};
pub use evidence_adapter::{adapt_jsonl_path, adapt_jsonl_str, adapt_line, AdapterError};
pub use framing::{BapFrame, ClearBody, EncryptedBody, FrameBody, FrameKind, FramingError};
pub use jsonl::{Direction, EvidenceRecord, JsonlError};
pub use message_inventory::{
    CaptureMessageInventory, CrossCaptureMessageComparison, EvidenceLabel, MessageInventory,
    MessageObservation,
};
pub use messages::{MessageClass, MessageInfo, classify};
pub use multi_capture::{
    CaptureValidationReport, InvariantClass, MultiCaptureStatus, MultiCaptureSummary,
};
pub use local_server::{LocalBapServer, LocalServerConfig, LocalServerError};
pub use replay_client::{BapReplayClient, ReplayClientError};
pub use stream_framing::{BapStreamDecoder, RawBapFrame, StreamFramingError, MAX_BODY_LEN};
pub use tcp_byte_source::{TcpByteSource, TcpByteSourceError, TcpEndpoint};
pub use timeline::{Timeline, TimelineEntry};
