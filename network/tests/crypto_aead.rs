//! Offline AES-GCM tests using only synthetic key/nonce/plaintext material.

use destiny1_network::crypto::{
    AesGcmBlob, CryptoError, KEY_LEN, NONCE_LEN, TAG_LEN, decrypt_aes_gcm, encrypt_aes_gcm,
};
use destiny1_network::framing::{
    self, BapFrame, ClearBody, EncryptedBody, FrameBody, FrameKind,
};

/// Obviously synthetic material — not from captures or third-party secrets.
fn synthetic_key() -> [u8; KEY_LEN] {
    *b"SYNTHETIC_KEY16!" // exactly 16 bytes; inventado
}

fn synthetic_nonce() -> [u8; NONCE_LEN] {
    *b"SYNTH_NONCE!" // exactly 12 bytes; inventado
}

#[test]
fn encrypt_decrypt_round_trip() {
    let key = synthetic_key();
    let nonce = synthetic_nonce();
    let aad = b"synthetic-aad";
    let plaintext = b"hello-synthetic-plaintext";

    let blob = encrypt_aes_gcm(&key, &nonce, plaintext, aad).unwrap();
    assert_eq!(blob.tag.len(), TAG_LEN);
    let recovered = decrypt_aes_gcm(&key, &nonce, &blob.ciphertext, &blob.tag, aad).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn modified_ciphertext_fails() {
    let key = synthetic_key();
    let nonce = synthetic_nonce();
    let aad = b"";
    let mut blob = encrypt_aes_gcm(&key, &nonce, b"payload", aad).unwrap();
    if blob.ciphertext.is_empty() {
        blob.ciphertext.push(0);
    } else {
        blob.ciphertext[0] ^= 0x01;
    }
    let err = decrypt_aes_gcm(&key, &nonce, &blob.ciphertext, &blob.tag, aad).unwrap_err();
    assert_eq!(err, CryptoError::DecryptFailed);
}

#[test]
fn modified_tag_fails() {
    let key = synthetic_key();
    let nonce = synthetic_nonce();
    let aad = b"";
    let mut blob = encrypt_aes_gcm(&key, &nonce, b"payload", aad).unwrap();
    blob.tag[0] ^= 0x01;
    let err = decrypt_aes_gcm(&key, &nonce, &blob.ciphertext, &blob.tag, aad).unwrap_err();
    assert_eq!(err, CryptoError::DecryptFailed);
}

#[test]
fn wrong_nonce_fails() {
    let key = synthetic_key();
    let nonce = synthetic_nonce();
    let aad = b"";
    let blob = encrypt_aes_gcm(&key, &nonce, b"payload", aad).unwrap();
    let mut bad_nonce = nonce;
    bad_nonce[0] ^= 0x01;
    let err = decrypt_aes_gcm(&key, &bad_nonce, &blob.ciphertext, &blob.tag, aad).unwrap_err();
    assert_eq!(err, CryptoError::DecryptFailed);
}

#[test]
fn wrong_key_fails() {
    let key = synthetic_key();
    let nonce = synthetic_nonce();
    let aad = b"";
    let blob = encrypt_aes_gcm(&key, &nonce, b"payload", aad).unwrap();
    let mut bad_key = key;
    bad_key[0] ^= 0x01;
    let err = decrypt_aes_gcm(&bad_key, &nonce, &blob.ciphertext, &blob.tag, aad).unwrap_err();
    assert_eq!(err, CryptoError::DecryptFailed);
}

#[test]
fn wrong_aad_fails() {
    let key = synthetic_key();
    let nonce = synthetic_nonce();
    let blob = encrypt_aes_gcm(&key, &nonce, b"payload", b"aad-a").unwrap();
    let err = decrypt_aes_gcm(&key, &nonce, &blob.ciphertext, &blob.tag, b"aad-b").unwrap_err();
    assert_eq!(err, CryptoError::DecryptFailed);
}

#[test]
fn bap_plaintext_survives_aes_gcm_and_parser() {
    // Clear BAP body: msg_id=0x19, context=0x11, payload=synthetic
    let clear = framing::clear_frame(0x19, 0x11, b"\xde\xad\xbe\xef");
    let clear_body = match &clear.body {
        FrameBody::Clear(c) => {
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&c.msg_id.to_be_bytes());
            bytes.extend_from_slice(&c.context.to_be_bytes());
            bytes.extend_from_slice(&c.payload);
            bytes
        }
        _ => panic!("expected clear"),
    };

    let key = synthetic_key();
    let nonce = synthetic_nonce();
    // Explicit synthetic AAD — NOT claimed as Destiny wire AAD.
    let aad = b"";

    let blob = encrypt_aes_gcm(&key, &nonce, &clear_body, aad).unwrap();

    // Pack into BAP kind=1 frame: [tag:16][ciphertext...]
    let encrypted_frame = framing::encrypted_frame(blob.tag, &blob.ciphertext);
    let wire = encrypted_frame.serialize().unwrap();
    let (parsed_enc, _) = BapFrame::parse(&wire).unwrap();
    assert_eq!(parsed_enc.kind, FrameKind::Encrypted);

    let EncryptedBody { tag, ciphertext } = match parsed_enc.body {
        FrameBody::Encrypted(e) => e,
        _ => panic!("expected encrypted body"),
    };

    let recovered = decrypt_aes_gcm(&key, &nonce, &ciphertext, &tag, aad).unwrap();
    assert_eq!(recovered, clear_body);

    // Feed recovered plaintext through clear-body layout via a synthetic kind=2 frame.
    let mut rebuild = vec![0x01, 0x02];
    let len = u32::try_from(recovered.len()).unwrap();
    rebuild.extend_from_slice(&len.to_be_bytes());
    rebuild.extend_from_slice(&recovered);
    let (parsed_clear, _) = BapFrame::parse(&rebuild).unwrap();
    match parsed_clear.body {
        FrameBody::Clear(ClearBody {
            msg_id,
            context,
            payload,
        }) => {
            assert_eq!(msg_id, 0x19);
            assert_eq!(context, 0x11);
            assert_eq!(payload, b"\xde\xad\xbe\xef");
        }
        _ => panic!("expected clear after decrypt"),
    }
}

#[test]
fn blob_body_bytes_round_trip_layout() {
    let blob = AesGcmBlob {
        tag: [0xAB; 16],
        ciphertext: vec![1, 2, 3],
    };
    let body = blob.to_body_bytes();
    assert_eq!(&body[..16], &[0xAB; 16]);
    assert_eq!(&body[16..], &[1, 2, 3]);
    let again = AesGcmBlob::from_body_bytes(&body).unwrap();
    assert_eq!(again, blob);
}

#[test]
fn rejects_bad_key_length() {
    let err = encrypt_aes_gcm(b"short", &synthetic_nonce(), b"x", b"").unwrap_err();
    assert!(matches!(err, CryptoError::BadKeyLength(_)));
}
