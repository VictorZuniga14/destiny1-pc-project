//! Synthetic first-frame GCM verify path (no real Destiny wire secrets).

use destiny1_network::crypto::{KEY_LEN, NONCE_LEN, TAG_LEN, encrypt_aes_gcm};
use destiny1_network::gcm_first_frame;

#[test]
fn synthetic_round_trip_via_verify_json() {
    let key = *b"SYNTH_GCM_KEY16!";
    let nonce = *b"SYNTHNONCE12";
    let plaintext = b"ABCDEF"; // 6 bytes like 0x79
    let aad = b"";
    let blob = encrypt_aes_gcm(&key, &nonce, plaintext, aad).unwrap();
    assert_eq!(blob.tag.len(), TAG_LEN);
    assert_eq!(blob.ciphertext.len(), plaintext.len());

    let json = format!(
        r#"{{
          "session_key_hex": "{}",
          "nonce_hex": "{}",
          "tag_hex": "{}",
          "ciphertext_hex": "{}",
          "aad_hex": "",
          "expected_plaintext_len": 6
        }}"#,
        hex(&key),
        hex(&nonce),
        hex(&blob.tag),
        hex(&blob.ciphertext),
    );
    let report = gcm_first_frame::verify_from_json_str(&json).unwrap();
    assert!(report.decrypt_ok);
    assert_eq!(report.plaintext_length, Some(6));
    assert!(report.verified());
    assert_eq!(report.key_length, KEY_LEN);
    assert_eq!(report.nonce_length, NONCE_LEN);
    let s = report.to_string();
    assert!(!s.contains("SYNTH"));
    assert!(!s.contains(&hex(&key)));
}

#[test]
fn synthetic_wrong_tag_fails() {
    let key = *b"SYNTH_GCM_KEY16!";
    let nonce = *b"SYNTHNONCE12";
    let mut blob = encrypt_aes_gcm(&key, &nonce, b"ABCDEF", b"").unwrap();
    blob.tag[0] ^= 1;
    let json = format!(
        r#"{{
          "session_key_hex": "{}",
          "nonce_hex": "{}",
          "tag_hex": "{}",
          "ciphertext_hex": "{}",
          "aad_hex": "",
          "expected_plaintext_len": 6
        }}"#,
        hex(&key),
        hex(&nonce),
        hex(&blob.tag),
        hex(&blob.ciphertext),
    );
    let report = gcm_first_frame::verify_from_json_str(&json).unwrap();
    assert!(!report.decrypt_ok);
    assert!(!report.verified());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
