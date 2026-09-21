//! Message ID classifier from `docs/networking/message-matrix.md`.
//!
//! Only names listed in that matrix are recognized. Unknown IDs stay unnamed.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageInfo {
    pub id: u16,
    pub name: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    Known(MessageInfo),
    Unknown { id: u16 },
}

impl MessageClass {
    pub fn id(self) -> u16 {
        match self {
            Self::Known(info) => info.id,
            Self::Unknown { id } => id,
        }
    }

    pub fn name(self) -> Option<&'static str> {
        match self {
            Self::Known(info) => Some(info.name),
            Self::Unknown { .. } => None,
        }
    }

    pub fn is_known(self) -> bool {
        matches!(self, Self::Known(_))
    }
}

/// Names sourced exclusively from `docs/networking/message-matrix.md`.
const KNOWN: &[(u16, &str)] = &[
    (0x0A, "generated-completion-request"),
    (0x0B, "generated-completion-response"),
    (0x0C, "status-like-request"),
    (0x0D, "status-like-response"),
    (0x19, "session-login-request"),
    (0x1A, "session-login-response"),
    (0x1E, "destiny-service-handshake-request"),
    (0x1F, "destiny-service-handshake-response"),
    (0x79, "encrypted-handshake-request"),
    (0x7A, "encrypted-handshake-status"),
    (0xFA, "keepalive-request"),
    (0xFB, "keepalive-status"),
    (0x12D, "activity-state"),
    (0x12E, "nat-report"),
    (0x12F, "nat-report-status"),
];

pub fn lookup_name(id: u16) -> Option<&'static str> {
    KNOWN.iter().find(|(known_id, _)| *known_id == id).map(|(_, name)| *name)
}

pub fn classify(id: u16) -> MessageClass {
    match lookup_name(id) {
        Some(name) => MessageClass::Known(MessageInfo { id, name }),
        None => MessageClass::Unknown { id },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_session_login() {
        let c = classify(0x19);
        assert!(c.is_known());
        assert_eq!(c.name(), Some("session-login-request"));
    }

    #[test]
    fn unknown_id_has_no_name() {
        let c = classify(0xDEAD);
        assert!(!c.is_known());
        assert_eq!(c.name(), None);
        assert_eq!(c.id(), 0xDEAD);
    }
}
