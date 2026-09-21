//! Capture / synthetic stream→session pipeline tests.

use destiny1_network::bap_session::{clear_raw, encrypted_raw};
use destiny1_network::crypto::{encrypt_aes_gcm, NonceDirection, SessionCryptoContext};
use destiny1_network::stream_framing::BapStreamDecoder;
use destiny1_network::stream_framing_verify;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn synthetic_stream_then_session_via_verify() {
    let key = *b"SYNTH_STR_KEY16!";
    let sn = *b"SYNTHSTRNONC";
    let mut maker = SessionCryptoContext::new(&key, &sn).unwrap();

    let c_clear = clear_raw(0x1e, 0, b"");
    let nonce = maker.next_nonce(NonceDirection::ClientToServer);
    let blob = encrypt_aes_gcm(maker.session_key(), &nonce, b"ABCDEF", b"").unwrap();
    let c_enc = encrypted_raw(blob.tag, &blob.ciphertext);

    let json = format!(
        r#"{{
          "capture":"synth-stream",
          "session_key_hex":"{k}",
          "session_nonce_hex":"{sn}",
          "frames":[
            {{"direction":"client_to_server","frame_hex":"{cc}"}},
            {{"direction":"client_to_server","frame_hex":"{ce}"}}
          ]
        }}"#,
        k = hex(&key),
        sn = hex(&sn),
        cc = hex(&c_clear),
        ce = hex(&c_enc),
    );

    let report = stream_framing_verify::verify_from_json_str(&json, &[1, 7, 13]).unwrap();
    assert!(report.verified(), "{report}");
    assert_eq!(report.frames_recovered, 2);
    assert_eq!(report.clear_frames, 1);
    assert_eq!(report.encrypted_decrypt_success, 1);
    assert!(!report.to_string().contains("SYNTH"));
}

#[test]
fn recovered_bytes_match_concat() {
    let a = clear_raw(0x1e, 1, b"x");
    let b = clear_raw(0x1f, 1, b"y");
    let mut stream = a.clone();
    stream.extend_from_slice(&b);
    let mut d = BapStreamDecoder::new();
    let mut got = Vec::new();
    for chunk in stream.chunks(3) {
        got.extend(d.push(chunk).unwrap());
    }
    d.finish().unwrap();
    assert_eq!(got.len(), 2);
    assert_eq!(got[0].raw_bytes, a);
    assert_eq!(got[1].raw_bytes, b);
}
