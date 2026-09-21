//! Unit tests for SessionCryptoContext (synthetic material only).

use destiny1_network::crypto::{
    NonceDirection, SessionCryptoContext, increment_nonce, initial_direction_nonce, nonces_equal,
};

fn synth_key() -> [u8; 16] {
    *b"SYNTH_CTX_KEY16!"
}
fn synth_nonce() -> [u8; 12] {
    *b"SYNTHNONCE12"
}

#[test]
fn initial_counters_are_zero() {
    let ctx = SessionCryptoContext::new(&synth_key(), &synth_nonce()).unwrap();
    assert_eq!(ctx.client_to_server_counter(), 0);
    assert_eq!(ctx.server_to_client_counter(), 0);
}

#[test]
fn first_c2s_nonce_is_xor_last_byte_1() {
    let mut ctx = SessionCryptoContext::new(&synth_key(), &synth_nonce()).unwrap();
    let expected =
        initial_direction_nonce(&synth_nonce(), NonceDirection::ClientToServer).unwrap();
    let got = ctx.next_nonce(NonceDirection::ClientToServer);
    assert!(nonces_equal(&got, &expected).unwrap());
    assert_eq!(ctx.client_to_server_counter(), 1);
    assert_eq!(ctx.server_to_client_counter(), 0);
}

#[test]
fn first_s2c_nonce_is_identity() {
    let mut ctx = SessionCryptoContext::new(&synth_key(), &synth_nonce()).unwrap();
    let expected =
        initial_direction_nonce(&synth_nonce(), NonceDirection::ServerToClient).unwrap();
    let got = ctx.next_nonce(NonceDirection::ServerToClient);
    assert!(nonces_equal(&got, &expected).unwrap());
    assert_eq!(&got, &synth_nonce());
    assert_eq!(ctx.server_to_client_counter(), 1);
    assert_eq!(ctx.client_to_server_counter(), 0);
}

#[test]
fn counters_independent_ccsccs() {
    let mut ctx = SessionCryptoContext::new(&synth_key(), &synth_nonce()).unwrap();
    // C C S C S S
    ctx.next_nonce(NonceDirection::ClientToServer);
    assert_eq!(ctx.client_to_server_counter(), 1);
    ctx.next_nonce(NonceDirection::ClientToServer);
    assert_eq!(ctx.client_to_server_counter(), 2);
    ctx.next_nonce(NonceDirection::ServerToClient);
    assert_eq!(ctx.server_to_client_counter(), 1);
    ctx.next_nonce(NonceDirection::ClientToServer);
    assert_eq!(ctx.client_to_server_counter(), 3);
    ctx.next_nonce(NonceDirection::ServerToClient);
    assert_eq!(ctx.server_to_client_counter(), 2);
    ctx.next_nonce(NonceDirection::ServerToClient);
    assert_eq!(ctx.server_to_client_counter(), 3);
    assert_eq!(ctx.client_to_server_counter(), 3);
}

#[test]
fn increment_matches_nonce_after_increments_helper() {
    let sn = synth_nonce();
    let base = initial_direction_nonce(&sn, NonceDirection::ClientToServer).unwrap();
    let mut ctx = SessionCryptoContext::new(&synth_key(), &sn).unwrap();
    for i in 0u64..5 {
        let expected = SessionCryptoContext::nonce_after_increments(&base, i);
        let got = ctx.next_nonce(NonceDirection::ClientToServer);
        assert!(nonces_equal(&got, &expected).unwrap(), "mismatch at {i}");
    }
}

#[test]
fn session_nonce_base_not_mutated() {
    let sn = synth_nonce();
    let mut ctx = SessionCryptoContext::new(&synth_key(), &sn).unwrap();
    for _ in 0..10 {
        ctx.next_nonce(NonceDirection::ClientToServer);
        ctx.next_nonce(NonceDirection::ServerToClient);
    }
    assert_eq!(ctx.session_nonce(), &sn);
}

#[test]
fn alternating_directions_keep_independent_sequences() {
    let sn = synth_nonce();
    let c_base = initial_direction_nonce(&sn, NonceDirection::ClientToServer).unwrap();
    let s_base = initial_direction_nonce(&sn, NonceDirection::ServerToClient).unwrap();
    let mut ctx = SessionCryptoContext::new(&synth_key(), &sn).unwrap();

    let mut c_expected = c_base;
    let mut s_expected = s_base;
    for i in 0..6 {
        if i % 2 == 0 {
            let got = ctx.next_nonce(NonceDirection::ClientToServer);
            assert!(nonces_equal(&got, &c_expected).unwrap());
            increment_nonce(&mut c_expected);
        } else {
            let got = ctx.next_nonce(NonceDirection::ServerToClient);
            assert!(nonces_equal(&got, &s_expected).unwrap());
            increment_nonce(&mut s_expected);
        }
    }
    assert_eq!(ctx.client_to_server_counter(), 3);
    assert_eq!(ctx.server_to_client_counter(), 3);
}

#[test]
fn debug_does_not_leak_key_material() {
    let ctx = SessionCryptoContext::new(&synth_key(), &synth_nonce()).unwrap();
    let s = format!("{ctx:?}");
    assert!(!s.contains("SYNTH"));
    assert!(s.contains("client_to_server_counter"));
}
