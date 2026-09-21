//! Incremental BAP stream framing tests (synthetic only).

use destiny1_network::bap_session::{clear_raw, encrypted_raw};
use destiny1_network::framing::{clear_frame, encrypted_frame};
use destiny1_network::stream_framing::{
    BapStreamDecoder, StreamFramingError, MAX_BODY_LEN, STREAM_HEADER_LEN,
};

fn sample_clear() -> Vec<u8> {
    clear_raw(0x1e, 1, b"abc")
}

fn sample_enc() -> Vec<u8> {
    encrypted_raw([0x11; 16], b"cipherXX")
}

#[test]
fn single_push_complete_frame() {
    let mut d = BapStreamDecoder::new();
    let f = sample_clear();
    let out = d.push(&f).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].raw_bytes, f);
    assert_eq!(out[0].kind, 2);
    assert_eq!(d.buffered_len(), 0);
    d.finish().unwrap();
}

#[test]
fn header_byte_by_byte() {
    let f = sample_clear();
    let mut d = BapStreamDecoder::new();
    for (i, b) in f.iter().enumerate() {
        let out = d.push(&[*b]).unwrap();
        if i + 1 < f.len() {
            assert!(out.is_empty(), "early frame at byte {i}");
        } else {
            assert_eq!(out.len(), 1);
            assert_eq!(out[0].raw_bytes, f);
        }
    }
    d.finish().unwrap();
}

#[test]
fn header_complete_body_partial() {
    let f = sample_clear();
    assert!(f.len() > STREAM_HEADER_LEN + 1);
    let mut d = BapStreamDecoder::new();
    let split = STREAM_HEADER_LEN + 1;
    assert!(d.push(&f[..split]).unwrap().is_empty());
    let out = d.push(&f[split..]).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].raw_bytes, f);
}

#[test]
fn all_split_offsets() {
    let f = sample_enc();
    for split in 1..f.len() {
        let mut d = BapStreamDecoder::new();
        let a = d.push(&f[..split]).unwrap();
        let b = d.push(&f[split..]).unwrap();
        let mut got = a;
        got.extend(b);
        assert_eq!(got.len(), 1, "split={split}");
        assert_eq!(got[0].raw_bytes, f, "split={split}");
        assert_eq!(d.buffered_len(), 0);
    }
}

#[test]
fn three_frames_one_chunk() {
    let a = sample_clear();
    let b = sample_enc();
    let c = clear_raw(0x19, 2, b"xy");
    let mut stream = Vec::new();
    stream.extend_from_slice(&a);
    stream.extend_from_slice(&b);
    stream.extend_from_slice(&c);
    let mut d = BapStreamDecoder::new();
    let out = d.push(&stream).unwrap();
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].raw_bytes, a);
    assert_eq!(out[1].raw_bytes, b);
    assert_eq!(out[2].raw_bytes, c);
    d.finish().unwrap();
}

#[test]
fn complete_plus_partial_next() {
    let a = sample_clear();
    let b = sample_enc();
    let mut first = a.clone();
    first.extend_from_slice(&b[..4]);
    let mut d = BapStreamDecoder::new();
    let out1 = d.push(&first).unwrap();
    assert_eq!(out1.len(), 1);
    assert_eq!(out1[0].raw_bytes, a);
    assert_eq!(d.buffered_len(), 4);
    let out2 = d.push(&b[4..]).unwrap();
    assert_eq!(out2.len(), 1);
    assert_eq!(out2[0].raw_bytes, b);
    d.finish().unwrap();
}

#[test]
fn arbitrary_chunk_sizes_match_originals() {
    let frames = [
        sample_clear(),
        sample_enc(),
        clear_raw(0x1a, 0, b""),
        encrypted_raw([0xaa; 16], b"zzzzzzzz"),
    ];
    let mut stream = Vec::new();
    for f in &frames {
        stream.extend_from_slice(f);
    }
    let chunk_sizes = [1usize, 2, 5, 7, 13, 3, 64, 11];
    let mut d = BapStreamDecoder::new();
    let mut recovered = Vec::new();
    let mut off = 0;
    let mut i = 0;
    while off < stream.len() {
        let n = chunk_sizes[i % chunk_sizes.len()].min(stream.len() - off);
        i += 1;
        recovered.extend(d.push(&stream[off..off + n]).unwrap());
        off += n;
    }
    d.finish().unwrap();
    assert_eq!(recovered.len(), frames.len());
    for (got, exp) in recovered.iter().zip(frames.iter()) {
        assert_eq!(&got.raw_bytes, exp);
    }
}

#[test]
fn invalid_magic() {
    let mut d = BapStreamDecoder::new();
    let err = d.push(&[0x00, 0x02, 0, 0, 0, 0]).unwrap_err();
    assert_eq!(err, StreamFramingError::InvalidMagic(0x00));
}

#[test]
fn invalid_kind() {
    let mut d = BapStreamDecoder::new();
    // magic ok, kind=3, body_len=0
    let err = d.push(&[0x01, 0x03, 0, 0, 0, 0]).unwrap_err();
    assert_eq!(err, StreamFramingError::InvalidKind(0x03));
}

#[test]
fn incomplete_body_not_error() {
    let f = sample_clear();
    let mut d = BapStreamDecoder::new();
    assert!(d.push(&f[..STREAM_HEADER_LEN]).unwrap().is_empty());
    assert!(d.push(&f[STREAM_HEADER_LEN..f.len() - 1]).unwrap().is_empty());
    assert_eq!(d.buffered_len(), f.len() - 1);
    // finish with leftover → IncompleteAtEnd
    assert!(matches!(
        d.finish(),
        Err(StreamFramingError::IncompleteAtEnd(_))
    ));
}

#[test]
fn body_len_excessive() {
    let mut d = BapStreamDecoder::with_max_body_len(32);
    // body_len = 1000
    let hdr = [0x01u8, 0x02, 0, 0, 0x03, 0xe8];
    let err = d.push(&hdr).unwrap_err();
    assert_eq!(err, StreamFramingError::FrameTooLarge(1000));
}

#[test]
fn max_body_len_constant_documented() {
    assert!(MAX_BODY_LEN >= 64 * 1024);
    let d = BapStreamDecoder::new();
    assert_eq!(d.max_body_len(), MAX_BODY_LEN);
}

#[test]
fn serialize_helpers_round_trip_via_stream() {
    let frame = clear_frame(0x19, 7, b"payload");
    let bytes = frame.serialize().unwrap();
    let mut d = BapStreamDecoder::new();
    let out = d.push(&bytes).unwrap();
    assert_eq!(out[0].raw_bytes, bytes);
    assert_eq!(out[0].body, bytes[STREAM_HEADER_LEN..]);
}

#[test]
fn empty_push_ok() {
    let mut d = BapStreamDecoder::new();
    assert!(d.push(&[]).unwrap().is_empty());
    d.finish().unwrap();
}

#[test]
fn enc_frame_via_helper() {
    let frame = encrypted_frame([1u8; 16], b"ct");
    let bytes = frame.serialize().unwrap();
    let mut d = BapStreamDecoder::new();
    let out = d.push(&bytes).unwrap();
    assert_eq!(out[0].kind, 1);
    assert_eq!(out[0].body.len(), 18);
}
