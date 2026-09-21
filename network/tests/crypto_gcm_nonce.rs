//! Synthetic first-frame GCM nonce transform tests (no real secrets).

use destiny1_network::crypto::{
    GCM_NONCE_LEN, NonceDirection, NonceTransform, apply_nonce_transform,
    default_transform_for, nonces_equal, reconstruct_first_frame_nonce,
};

fn synth_session_nonce() -> [u8; GCM_NONCE_LEN] {
    *b"SYNTHNONCE12" // 12 bytes; inventado
}

#[test]
fn identity_leaves_bytes_unchanged() {
    let sn = synth_session_nonce();
    let out = apply_nonce_transform(&sn, NonceTransform::Identity).unwrap();
    assert!(nonces_equal(&out, &sn).unwrap());
}

#[test]
fn xor_last_byte_1_flips_only_last() {
    let sn = synth_session_nonce();
    let out = apply_nonce_transform(&sn, NonceTransform::XorLastByte(1)).unwrap();
    assert_eq!(&out[..11], &sn[..11]);
    assert_eq!(out[11], sn[11] ^ 1);
    assert!(!nonces_equal(&out, &sn).unwrap());
}

#[test]
fn default_transform_matches_direction_hypothesis() {
    assert_eq!(
        default_transform_for(NonceDirection::ClientToServer),
        NonceTransform::XorLastByte(1)
    );
    assert_eq!(
        default_transform_for(NonceDirection::ServerToClient),
        NonceTransform::Identity
    );
}

#[test]
fn increment_nonce_wraps_first_byte() {
    let mut n = [0xff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    destiny1_network::crypto::increment_nonce(&mut n);
    assert_eq!(n[0], 0);
    assert_eq!(n[1], 1);
}

#[test]
fn reconstruct_c2s_matches_expected_xor() {
    let sn = synth_session_nonce();
    let expected = apply_nonce_transform(&sn, NonceTransform::XorLastByte(1)).unwrap();
    let report = reconstruct_first_frame_nonce(
        &sn,
        NonceDirection::ClientToServer,
        NonceTransform::XorLastByte(1),
        Some(&expected),
    )
    .unwrap();
    assert_eq!(report.matches_expected, Some(true));
    assert_eq!(report.session_nonce_length, 12);
    assert_eq!(report.derived_nonce_length, 12);
    let s = report.to_string();
    assert!(s.contains("XorLastByte(1)"));
    assert!(!s.contains("SYNTH"));
}

#[test]
fn reconstruct_mismatch_detected() {
    let sn = synth_session_nonce();
    let wrong = sn;
    let report = reconstruct_first_frame_nonce(
        &sn,
        NonceDirection::ClientToServer,
        NonceTransform::XorLastByte(1),
        Some(&wrong),
    )
    .unwrap();
    assert_eq!(report.matches_expected, Some(false));
}

#[test]
fn rejects_bad_length() {
    let err = apply_nonce_transform(&[1, 2, 3], NonceTransform::Identity).unwrap_err();
    assert!(matches!(
        err,
        destiny1_network::crypto::GcmNonceError::BadSessionNonceLength(3)
    ));
}
