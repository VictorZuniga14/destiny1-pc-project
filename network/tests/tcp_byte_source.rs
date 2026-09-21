//! M2.10 TcpByteSource tests — local loopback only (127.0.0.1).

use destiny1_network::bap_pipeline::BapOfflinePipeline;
use destiny1_network::bap_session::clear_raw;
use destiny1_network::byte_source::ByteSource;
use destiny1_network::crypto::NonceDirection;
use destiny1_network::stream_framing::{BapStreamDecoder, StreamFramingError};
use destiny1_network::tcp_byte_source::{
    collect_raw_frames_from_source, spawn_loopback_chunk_server, TcpByteSource, TcpByteSourceError,
    TcpEndpoint,
};
use std::io::Write;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

fn connect_local(port: u16) -> TcpByteSource {
    let ep = TcpEndpoint::loopback(port, Duration::from_secs(2)).unwrap();
    let mut last = None;
    for _ in 0..50 {
        match TcpByteSource::connect(&ep) {
            Ok(src) => return src,
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    panic!("connect_local failed: {:?}", last);
}

fn read_all(src: &mut TcpByteSource) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        match src.read().unwrap() {
            Some(chunk) => out.extend_from_slice(&chunk),
            None => break,
        }
    }
    out
}

#[test]
fn rejects_empty_host() {
    let err = TcpEndpoint::new("", 9, Duration::from_secs(1), None).unwrap_err();
    assert!(matches!(err, TcpByteSourceError::InvalidAddress(_)));
}

#[test]
fn rejects_zero_port() {
    let err = TcpEndpoint::new("127.0.0.1", 0, Duration::from_secs(1), None).unwrap_err();
    assert!(matches!(err, TcpByteSourceError::InvalidAddress(_)));
}

#[test]
fn rejects_zero_connect_timeout() {
    let err = TcpEndpoint::new("127.0.0.1", 9, Duration::from_secs(0), None).unwrap_err();
    assert!(matches!(err, TcpByteSourceError::InvalidTimeout(_)));
}

#[test]
fn basic_read_byte_for_byte() {
    let payload = vec![0xaa, 0xbb, 0xcc, 0xdd];
    let addr = spawn_loopback_chunk_server(vec![payload.clone()]).unwrap();
    let mut src = connect_local(addr.port());
    let got = read_all(&mut src);
    assert_eq!(got, payload);
}

#[test]
fn fragmented_tcp_chunks_concat() {
    let chunks = vec![vec![0xaa], vec![0xbb, 0xcc], vec![0xdd, 0xee, 0xff]];
    let expected: Vec<u8> = chunks.iter().flatten().copied().collect();
    let addr = spawn_loopback_chunk_server(chunks).unwrap();
    let mut src = connect_local(addr.port());
    let got = read_all(&mut src);
    assert_eq!(got, expected);
}

#[test]
fn multiple_bap_frames_over_tcp() {
    let f1 = clear_raw(0x1e, 0, b"one");
    let f2 = clear_raw(0x1f, 1, b"two");
    let f3 = clear_raw(0x19, 2, b"three");
    let mut stream = Vec::new();
    stream.extend_from_slice(&f1);
    stream.extend_from_slice(&f2);
    stream.extend_from_slice(&f3);

    let addr = spawn_loopback_chunk_server(vec![stream]).unwrap();
    let mut src = connect_local(addr.port());
    let frames = collect_raw_frames_from_source(&mut src).unwrap();
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0].raw_bytes, f1);
    assert_eq!(frames[1].raw_bytes, f2);
    assert_eq!(frames[2].raw_bytes, f3);
}

#[test]
fn split_frame_across_tcp_writes() {
    let frame = clear_raw(0xfa, 0, b"KEEP");
    let mid = frame.len() / 2;
    let part_a = frame[..mid].to_vec();
    let part_b = frame[mid..].to_vec();
    assert!(!part_a.is_empty() && !part_b.is_empty());

    let addr = spawn_loopback_chunk_server(vec![part_a, part_b]).unwrap();
    let mut src = connect_local(addr.port());
    // Force small reads so decoder sees incremental pushes regardless of TCP coalesce.
    src.set_read_buf_size(3);
    let frames = collect_raw_frames_from_source(&mut src).unwrap();
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].raw_bytes, frame);
}

#[test]
fn eof_after_bytes_is_none_not_error() {
    let addr = spawn_loopback_chunk_server(vec![vec![1, 2, 3]]).unwrap();
    let mut src = connect_local(addr.port());
    assert_eq!(src.read_chunk().unwrap(), Some(vec![1, 2, 3]));
    assert_eq!(src.read_chunk().unwrap(), None);
    // Subsequent ByteSource reads stay clean EOF.
    assert_eq!(src.read().unwrap(), None);
}

#[test]
fn incomplete_frame_finish_incomplete_at_end() {
    let frame = clear_raw(0x12, 0, b"ABCDEFGH");
    let partial = frame[..frame.len().saturating_sub(4)].to_vec();
    assert!(partial.len() < frame.len());

    let addr = spawn_loopback_chunk_server(vec![partial]).unwrap();
    let mut src = connect_local(addr.port());
    let mut decoder = BapStreamDecoder::new();
    loop {
        match src.read().unwrap() {
            Some(chunk) => {
                let got = decoder.push(&chunk).unwrap();
                assert!(got.is_empty(), "partial must not yield a full frame yet");
            }
            None => break,
        }
    }
    let err = decoder.finish().unwrap_err();
    assert!(matches!(err, StreamFramingError::IncompleteAtEnd(_)));
}

#[test]
fn connection_refused_on_closed_port() {
    // Bind and immediately drop → port not listening.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let ep = TcpEndpoint::loopback(port, Duration::from_millis(300)).unwrap();
    let err = TcpByteSource::connect(&ep).unwrap_err();
    assert!(
        matches!(
            err,
            TcpByteSourceError::ConnectionFailed(_) | TcpByteSourceError::Timeout(_)
        ),
        "unexpected: {err:?}"
    );
}

#[test]
fn pipeline_decode_clear_frames_via_tcp() {
    let f1 = clear_raw(0x1e, 0, b"hello");
    let f2 = clear_raw(0x1f, 0, b"world");
    let mut stream = Vec::new();
    stream.extend_from_slice(&f1);
    stream.extend_from_slice(&f2);

    let addr = spawn_loopback_chunk_server(vec![stream]).unwrap();
    let mut src = connect_local(addr.port());
    let key = *b"TCP_PIPE_TESTKEY";
    let sn = *b"TCPPIPENONCE";
    let mut pipe = BapOfflinePipeline::new(&key, &sn).unwrap();
    let decoded = pipe
        .run_unidirectional(&mut src, NonceDirection::ClientToServer)
        .unwrap();
    assert_eq!(decoded.len(), 2);
}

#[test]
fn local_only_endpoints_in_helpers() {
    let addr = spawn_loopback_chunk_server(vec![vec![0]]).unwrap();
    assert_eq!(addr.ip().to_string(), "127.0.0.1");
}

/// Offline capture wire replay over local TCP (no Internet).
/// Uses synthetic BAP when evidence is absent; with evidence, concatenates frame_hex.
#[test]
fn capture_wire_replay_over_local_tcp() {
    let wire = load_capture_wire_or_synthetic();
    assert!(!wire.is_empty());

    // Serve in awkward chunks to stress TcpByteSource + decoder.
    let chunks = destiny1_network::byte_source::chunk_stream(&wire, &[7, 13, 29, 3, 64]);
    let addr = spawn_loopback_chunk_server(chunks).unwrap();
    let mut src = connect_local(addr.port());
    src.set_read_buf_size(11);

    let frames = collect_raw_frames_from_source(&mut src).unwrap();
    assert!(!frames.is_empty());

    // Round-trip: re-encode by concatenating recovered raw bytes equals input wire
    // only when input was complete frames (true for both synthetic and capture fixtures).
    let mut rebuilt = Vec::new();
    for f in &frames {
        rebuilt.extend_from_slice(&f.raw_bytes);
    }
    assert_eq!(rebuilt, wire);
}

fn load_capture_wire_or_synthetic() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../evidence/local/bap_session_verify.json");
    if path.exists() {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) {
                if let Some(frames) = v.get("frames").and_then(|f| f.as_array()) {
                    let mut out = Vec::new();
                    for fr in frames {
                        if let Some(hex) = fr.get("frame_hex").and_then(|h| h.as_str()) {
                            if let Ok(bytes) = decode_hex(hex) {
                                out.extend_from_slice(&bytes);
                            }
                        }
                    }
                    if !out.is_empty() {
                        return out;
                    }
                }
            }
        }
    }
    // Synthetic fallback (still offline / local).
    let mut out = Vec::new();
    out.extend_from_slice(&clear_raw(0x1e, 0, b"synth-a"));
    out.extend_from_slice(&clear_raw(0x1f, 0, b"synth-b"));
    out.extend_from_slice(&clear_raw(0x19, 1, b"synth-c"));
    out
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    let t = s.trim();
    if t.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let bytes = t.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = from_hex(bytes[i])?;
        let lo = from_hex(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn from_hex(b: u8) -> Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

#[test]
fn close_is_idempotent() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let _ = s.write_all(&[9]);
        let _ = s.shutdown(Shutdown::Both);
    });
    std::thread::sleep(Duration::from_millis(20));
    let mut src = TcpByteSource::from_stream(TcpStream::connect(addr).unwrap());
    src.close();
    src.close();
    assert!(!src.is_open());
    let _ = handle.join();
}
