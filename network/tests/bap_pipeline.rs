//! BapOfflinePipeline tests (synthetic material only).

use destiny1_network::bap_pipeline::{BapOfflinePipeline, PipelineError};
use destiny1_network::bap_session::{clear_raw, encrypted_raw, DecodedBapFrame};
use destiny1_network::byte_source::{
    chunk_stream, ByteSourceError, MockByteSource, DEFAULT_PIPELINE_CHUNK_SIZES,
};
use destiny1_network::crypto::{encrypt_aes_gcm, NonceDirection, SessionCryptoContext};
use destiny1_network::stream_framing::StreamFramingError;

fn synth_key() -> [u8; 16] {
    *b"SYNTH_PIPE_KEY16"
}
fn synth_nonce() -> [u8; 12] {
    *b"SYNTHPIPNONC"
}

fn enc(
    maker: &mut SessionCryptoContext,
    dir: NonceDirection,
    plaintext: &[u8],
) -> Vec<u8> {
    let nonce = maker.next_nonce(dir);
    let blob = encrypt_aes_gcm(maker.session_key(), &nonce, plaintext, b"").unwrap();
    encrypted_raw(blob.tag, &blob.ciphertext)
}

#[test]
fn pipeline_mixed_clear_encrypted_unidirectional() {
    let key = synth_key();
    let sn = synth_nonce();
    let mut maker = SessionCryptoContext::new(&key, &sn).unwrap();

    let f1 = clear_raw(0x1e, 0, b"a");
    let f2 = enc(&mut maker, NonceDirection::ClientToServer, b"ABCDEF");
    let f3 = clear_raw(0x19, 1, b"b");
    let f4 = enc(&mut maker, NonceDirection::ClientToServer, b"GHIJKL");

    let mut stream = Vec::new();
    for f in [&f1, &f2, &f3, &f4] {
        stream.extend_from_slice(f);
    }
    let chunks = chunk_stream(&stream, &[5, 11, 3]);
    let mut source = MockByteSource::new(chunks);
    let mut pipe = BapOfflinePipeline::new(&key, &sn).unwrap();
    let out = pipe
        .run_unidirectional(&mut source, NonceDirection::ClientToServer)
        .unwrap();

    assert_eq!(out.len(), 4);
    assert!(matches!(out[0], DecodedBapFrame::Clear { msg_id: 0x1e, .. }));
    assert!(out[1].is_decrypted());
    assert!(matches!(out[2], DecodedBapFrame::Clear { msg_id: 0x19, .. }));
    assert!(out[3].is_decrypted());
    // clear does not consume; two encrypted → C counter = 2
    assert_eq!(pipe.client_to_server_counter(), 2);
    assert_eq!(pipe.server_to_client_counter(), 0);
}

#[test]
fn pipeline_bidirectional_independent_counters() {
    let key = synth_key();
    let sn = synth_nonce();
    let mut maker = SessionCryptoContext::new(&key, &sn).unwrap();

    let c0 = enc(&mut maker, NonceDirection::ClientToServer, b"AAAAAA");
    let s0 = enc(&mut maker, NonceDirection::ServerToClient, b"BBBBBB");
    let c1 = enc(&mut maker, NonceDirection::ClientToServer, b"CCCCCC");
    let s1 = enc(&mut maker, NonceDirection::ServerToClient, b"DDDDDD");

    let mut stream = Vec::new();
    for f in [&c0, &s0, &c1, &s1] {
        stream.extend_from_slice(f);
    }
    let dirs = [
        NonceDirection::ClientToServer,
        NonceDirection::ServerToClient,
        NonceDirection::ClientToServer,
        NonceDirection::ServerToClient,
    ];
    let mut source = MockByteSource::new(chunk_stream(&stream, &[1, 7, 13]));
    let mut pipe = BapOfflinePipeline::new(&key, &sn).unwrap();
    let out = pipe.run_directed(&mut source, &dirs).unwrap();
    assert_eq!(out.len(), 4);
    assert!(out.iter().all(|d| d.is_decrypted()));
    assert_eq!(pipe.client_to_server_counter(), 2);
    assert_eq!(pipe.server_to_client_counter(), 2);
}

#[test]
fn aggressive_chunking_matches_direct() {
    let key = synth_key();
    let sn = synth_nonce();
    let mut maker = SessionCryptoContext::new(&key, &sn).unwrap();
    let frames = [
        clear_raw(0x1e, 0, b""),
        enc(&mut maker, NonceDirection::ClientToServer, b"ABCDEF"),
        clear_raw(0x1f, 0, b"z"),
        enc(&mut maker, NonceDirection::ClientToServer, b"123456"),
    ];
    let mut stream = Vec::new();
    for f in &frames {
        stream.extend_from_slice(f);
    }

    let mut direct = BapOfflinePipeline::new(&key, &sn).unwrap();
    let mut one_shot = MockByteSource::new(vec![stream.clone()]);
    let expected = direct
        .run_unidirectional(&mut one_shot, NonceDirection::ClientToServer)
        .unwrap();

    for &size in DEFAULT_PIPELINE_CHUNK_SIZES {
        let mut pipe = BapOfflinePipeline::new(&key, &sn).unwrap();
        let mut src = MockByteSource::new(chunk_stream(&stream, &[size]));
        let got = pipe
            .run_unidirectional(&mut src, NonceDirection::ClientToServer)
            .unwrap();
        assert_eq!(got, expected, "chunk size {size}");
        assert_eq!(pipe.client_to_server_counter(), 2);
    }
}

#[test]
fn source_error_propagates() {
    let key = synth_key();
    let sn = synth_nonce();
    let mut source = MockByteSource::from_results(vec![Err(ByteSourceError::Failed(
        "intentional".into(),
    ))]);
    let mut pipe = BapOfflinePipeline::new(&key, &sn).unwrap();
    let err = pipe
        .run_unidirectional(&mut source, NonceDirection::ClientToServer)
        .unwrap_err();
    assert!(matches!(
        err,
        PipelineError::Source(ByteSourceError::Failed(_))
    ));
}

#[test]
fn incomplete_stream_at_eof_fails() {
    let key = synth_key();
    let sn = synth_nonce();
    let full = clear_raw(0x1e, 0, b"hello");
    let mut truncated = full.clone();
    truncated.extend_from_slice(&full[..4]); // half of next header/frame
    let mut source = MockByteSource::new(vec![truncated]);
    let mut pipe = BapOfflinePipeline::new(&key, &sn).unwrap();
    let err = pipe
        .run_unidirectional(&mut source, NonceDirection::ClientToServer)
        .unwrap_err();
    assert!(matches!(
        err,
        PipelineError::Stream(StreamFramingError::IncompleteAtEnd(_))
    ));
}

#[test]
fn empty_source_ok() {
    let mut source = MockByteSource::new(Vec::<Vec<u8>>::new());
    let mut pipe = BapOfflinePipeline::new(&synth_key(), &synth_nonce()).unwrap();
    let out = pipe
        .run_unidirectional(&mut source, NonceDirection::ClientToServer)
        .unwrap();
    assert!(out.is_empty());
}

#[test]
fn direction_mismatch_errors() {
    let key = synth_key();
    let sn = synth_nonce();
    let f = clear_raw(0x1e, 0, b"");
    let mut source = MockByteSource::new(vec![f]);
    let mut pipe = BapOfflinePipeline::new(&key, &sn).unwrap();
    let err = pipe
        .run_directed(&mut source, &[NonceDirection::ClientToServer; 2])
        .unwrap_err();
    assert!(matches!(
        err,
        PipelineError::DirectionCountMismatch { dirs: 2, frames: 1 }
    ));
}
