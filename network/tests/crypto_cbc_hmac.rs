//! Synthetic AES-CBC + HMAC-SHA256 tests (no real Destiny secrets).

use destiny1_network::crypto::{
    AES128_KEY_LEN, HMAC_SHA256_LEN, IV_LEN, MIN_SESSION_PLAINTEXT, SESSION_KEY_LEN,
    SESSION_NONCE_LEN, CbcHmacError, HmacMessageKind, build_hmac_message, compute_hmac_sha256,
    decrypt_aes128_cbc_raw, encrypt_aes128_cbc_pkcs7, validate_pkcs7, verify_hmac_sha256,
    verify_session_record,
};

fn synth_aes_key() -> [u8; AES128_KEY_LEN] {
    *b"SYNTH_AES_KEY16!"
}

fn synth_hmac_key() -> &'static [u8] {
    b"SYNTH_HMAC_KEY_MATERIAL_NOT_REAL"
}

fn synth_iv() -> [u8; IV_LEN] {
    *b"SYNTHETIC_IV_16B"
}

/// nonce(12) + session_key(16) = 28 bytes — matches d1-re minimum layout.
fn synth_session_plaintext() -> Vec<u8> {
    let mut pt = Vec::with_capacity(MIN_SESSION_PLAINTEXT);
    pt.extend_from_slice(b"SYNTH_NONCE!"); // 12
    pt.extend_from_slice(b"SYNTH_SESS_KEY16"); // 16
    assert_eq!(pt.len(), MIN_SESSION_PLAINTEXT);
    pt
}

fn build_synthetic_record() -> (u32, [u8; IV_LEN], Vec<u8>, [u8; HMAC_SHA256_LEN]) {
    let aes_key = synth_aes_key();
    let iv = synth_iv();
    let plaintext = synth_session_plaintext();
    let ciphertext = encrypt_aes128_cbc_pkcs7(&aes_key, &iv, &plaintext).unwrap();
    // record_len = cipher_len + 0x30 (IV16 + HMAC32 accounted as in d1-re)
    let record_len = (ciphertext.len() + 0x30) as u32;
    let msg = build_hmac_message(
        HmacMessageKind::LengthIvCiphertext,
        record_len,
        &iv,
        &ciphertext,
    )
    .unwrap();
    let tag = compute_hmac_sha256(synth_hmac_key(), &msg).unwrap();
    (record_len, iv, ciphertext, tag)
}

#[test]
fn hmac_correct() {
    let (record_len, iv, ciphertext, tag) = build_synthetic_record();
    let msg = build_hmac_message(
        HmacMessageKind::LengthIvCiphertext,
        record_len,
        &iv,
        &ciphertext,
    )
    .unwrap();
    assert!(verify_hmac_sha256(synth_hmac_key(), &msg, &tag).unwrap());
}

#[test]
fn hmac_incorrect() {
    let (record_len, iv, ciphertext, mut tag) = build_synthetic_record();
    tag[0] ^= 0x01;
    let msg = build_hmac_message(
        HmacMessageKind::LengthIvCiphertext,
        record_len,
        &iv,
        &ciphertext,
    )
    .unwrap();
    assert!(!verify_hmac_sha256(synth_hmac_key(), &msg, &tag).unwrap());
}

#[test]
fn aes_cbc_decrypt_correct() {
    let aes_key = synth_aes_key();
    let iv = synth_iv();
    let plaintext = synth_session_plaintext();
    let ciphertext = encrypt_aes128_cbc_pkcs7(&aes_key, &iv, &plaintext).unwrap();
    let raw = decrypt_aes128_cbc_raw(&aes_key, &iv, &ciphertext).unwrap();
    let unpadded_len = validate_pkcs7(&raw).unwrap();
    assert_eq!(&raw[..unpadded_len], plaintext.as_slice());
}

#[test]
fn padding_correct() {
    let mut block = vec![0xABu8; 12];
    block.extend_from_slice(&[4, 4, 4, 4]); // PKCS#7 pad for 16-byte block
    assert_eq!(validate_pkcs7(&block).unwrap(), 12);
}

#[test]
fn padding_incorrect() {
    let bad = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 3]; // last claims pad=3 but bytes differ
    assert_eq!(validate_pkcs7(&bad), Err(CbcHmacError::InvalidPadding));
}

#[test]
fn combined_cbc_hmac_correct() {
    let (record_len, iv, ciphertext, tag) = build_synthetic_record();
    let report = verify_session_record(
        HmacMessageKind::LengthIvCiphertext,
        record_len,
        &iv,
        &ciphertext,
        &tag,
        &synth_aes_key(),
        synth_hmac_key(),
    )
    .unwrap();
    assert!(report.hmac_valid);
    assert!(report.decrypt_ok);
    assert_eq!(report.pkcs7_valid, Some(true));
    assert_eq!(report.pkcs7_unpadded_len, Some(MIN_SESSION_PLAINTEXT));
    assert!(report.structure_length_compatible);
    assert_eq!(report.candidate_nonce_offset, Some(0));
    assert_eq!(report.candidate_session_key_offset, Some(SESSION_NONCE_LEN));
    assert_eq!(SESSION_NONCE_LEN, 12);
    assert_eq!(SESSION_KEY_LEN, 16);
    assert!(report.success());
    assert_eq!(
        report.classification(),
        destiny1_network::crypto::VerifyClass::Verified
    );}

#[test]
fn modified_ciphertext_detected() {
    let (record_len, iv, mut ciphertext, tag) = build_synthetic_record();
    ciphertext[0] ^= 0x01;
    let report = verify_session_record(
        HmacMessageKind::LengthIvCiphertext,
        record_len,
        &iv,
        &ciphertext,
        &tag,
        &synth_aes_key(),
        synth_hmac_key(),
    )
    .unwrap();
    assert!(!report.hmac_valid);
    assert!(!report.success());
}

#[test]
fn modified_hmac_detected() {
    let (record_len, iv, ciphertext, mut tag) = build_synthetic_record();
    tag[0] ^= 0x01;
    let report = verify_session_record(
        HmacMessageKind::LengthIvCiphertext,
        record_len,
        &iv,
        &ciphertext,
        &tag,
        &synth_aes_key(),
        synth_hmac_key(),
    )
    .unwrap();
    assert!(!report.hmac_valid);
    assert!(!report.success());
}

#[test]
fn report_display_has_no_secret_looking_hex_blobs() {
    let (record_len, iv, ciphertext, tag) = build_synthetic_record();
    let report = verify_session_record(
        HmacMessageKind::LengthIvCiphertext,
        record_len,
        &iv,
        &ciphertext,
        &tag,
        &synth_aes_key(),
        synth_hmac_key(),
    )
    .unwrap();
    let s = report.to_string();
    assert!(s.contains("VERIFIED"));
    assert!(s.contains("hmac_valid: true"));
    assert!(!s.contains("SYNTH"));
    assert!(
        !has_long_hex_run(&s),
        "display leaked a long hex run:\n{s}"
    );
}

fn has_long_hex_run(s: &str) -> bool {
    let mut run = 0usize;
    for c in s.chars() {
        if c.is_ascii_hexdigit() {
            run += 1;
            if run >= 32 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}
