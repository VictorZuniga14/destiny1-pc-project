//! Central synthetic crypto material for local harnesses (M4.2–M4.6).
//!
//! Marked **SYNTHETIC_TEST_ONLY**. Never from SignOn, PCAP, or live Destiny.
//! Not a real session key. Never print these bytes in normal logs.

/// Explicit label for audits / fixtures.
pub const SYNTHETIC_TEST_ONLY_LABEL: &str = "SYNTHETIC_TEST_ONLY";

/// Deterministic AES-128 test key (`00..=0f`). Not a real capture key.
pub const SYNTHETIC_SESSION_KEY: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f,
];

/// Deterministic GCM base nonce (`10..=1b`). Not a real capture nonce.
pub const SYNTHETIC_SESSION_NONCE: [u8; 12] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
];

/// Hex encoding for fixtures (safe metadata only).
pub fn key_hex() -> String {
    hex_encode(&SYNTHETIC_SESSION_KEY)
}

pub fn nonce_hex() -> String {
    hex_encode(&SYNTHETIC_SESSION_NONCE)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths() {
        assert_eq!(SYNTHETIC_SESSION_KEY.len(), 16);
        assert_eq!(SYNTHETIC_SESSION_NONCE.len(), 12);
    }

    #[test]
    fn not_ascii_password_shaped() {
        // Must not look like the old ASCII harness strings.
        assert_ne!(&SYNTHETIC_SESSION_KEY, b"LOCALSERVER_KEY!");
        assert_ne!(&SYNTHETIC_SESSION_NONCE[..], b"LOCALNONCE12");
    }
}
