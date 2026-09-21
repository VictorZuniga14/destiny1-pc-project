//! Synthetic GCM sequence + nonce increment tests (no real secrets).

use destiny1_network::crypto::{
    NonceDirection, encrypt_aes_gcm, increment_nonce, initial_direction_nonce,
};
use destiny1_network::gcm_sequence;

fn synth_key() -> [u8; 16] {
    *b"SYNTH_SEQ_KEY16!"
}
fn synth_session_nonce() -> [u8; 12] {
    *b"SYNTHNONCE12"
}

#[test]
fn increment_nonce_steps() {
    let mut n = [0u8; 12];
    n[0] = 0xfe;
    increment_nonce(&mut n);
    assert_eq!(n[0], 0xff);
    increment_nonce(&mut n);
    assert_eq!(n[0], 0);
    assert_eq!(n[1], 1);
}

#[test]
fn initial_bases_differ_for_directions() {
    let sn = synth_session_nonce();
    let c = initial_direction_nonce(&sn, NonceDirection::ClientToServer).unwrap();
    let s = initial_direction_nonce(&sn, NonceDirection::ServerToClient).unwrap();
    assert_eq!(&c[..11], &s[..11]);
    assert_eq!(c[11], s[11] ^ 1);
}

#[test]
fn synthetic_two_frame_alternating_sequence() {
    let key = synth_key();
    let sn = synth_session_nonce();
    let mut c_n = initial_direction_nonce(&sn, NonceDirection::ClientToServer).unwrap();
    let mut s_n = initial_direction_nonce(&sn, NonceDirection::ServerToClient).unwrap();

    let pt_c = b"ABCDEF"; // 6
    let pt_s = b"ABCDEFGH"; // 8
    let blob_c = encrypt_aes_gcm(&key, &c_n, pt_c, b"").unwrap();
    increment_nonce(&mut c_n);
    let blob_s = encrypt_aes_gcm(&key, &s_n, pt_s, b"").unwrap();
    increment_nonce(&mut s_n);

    let json = format!(
        r#"{{
          "session_key_hex":"{k}",
          "session_nonce_hex":"{sn}",
          "aad_hex":"",
          "frames":[
            {{"id_hex":"0x79","direction":"client_to_server","tag_hex":"{tc}","ciphertext_hex":"{cc}","expected_plaintext_len":6}},
            {{"id_hex":"0x7a","direction":"server_to_client","tag_hex":"{ts}","ciphertext_hex":"{cs}","expected_plaintext_len":8}}
          ]
        }}"#,
        k = hex(&key),
        sn = hex(&sn),
        tc = hex(&blob_c.tag),
        cc = hex(&blob_c.ciphertext),
        ts = hex(&blob_s.tag),
        cs = hex(&blob_s.ciphertext),
    );
    let report = gcm_sequence::verify_from_json_str(&json).unwrap();
    assert!(report.all_verified());
    assert_eq!(report.frames[0].direction_enc_ordinal, 0);
    assert_eq!(report.frames[1].direction_enc_ordinal, 0);
    assert!(!report.to_string().contains("SYNTH"));
}

#[test]
fn synthetic_wrong_order_fails_second() {
    let key = synth_key();
    let sn = synth_session_nonce();
    let mut c_n = initial_direction_nonce(&sn, NonceDirection::ClientToServer).unwrap();
    let pt1 = b"AAAAAA";
    let pt2 = b"BBBBBB";
    let b1 = encrypt_aes_gcm(&key, &c_n, pt1, b"").unwrap();
    increment_nonce(&mut c_n);
    let b2 = encrypt_aes_gcm(&key, &c_n, pt2, b"").unwrap();
    // Feed second ciphertext first → should fail decrypt on first entry
    let json = format!(
        r#"{{
          "session_key_hex":"{k}",
          "session_nonce_hex":"{sn}",
          "aad_hex":"",
          "frames":[
            {{"id_hex":"0x12e","direction":"client_to_server","tag_hex":"{t2}","ciphertext_hex":"{c2}","expected_plaintext_len":6}},
            {{"id_hex":"0x79","direction":"client_to_server","tag_hex":"{t1}","ciphertext_hex":"{c1}","expected_plaintext_len":6}}
          ]
        }}"#,
        k = hex(&key),
        sn = hex(&sn),
        t1 = hex(&b1.tag),
        c1 = hex(&b1.ciphertext),
        t2 = hex(&b2.tag),
        c2 = hex(&b2.ciphertext),
    );
    let report = gcm_sequence::verify_from_json_str(&json).unwrap();
    assert!(!report.frames[0].decrypt_ok);
    assert!(!report.all_verified());
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
