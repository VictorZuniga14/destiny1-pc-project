//! Chronological timeline of classified BAP evidence.

use crate::framing::{BapFrame, FrameBody, FrameKind};
use crate::jsonl::{Direction, EvidenceRecord};
use crate::messages::{self, MessageClass};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimelineEntry {
    pub timestamp_ms: u64,
    pub direction: Direction,
    pub kind: FrameKind,
    pub message_id: Option<u16>,
    pub message_name: Option<&'static str>,
    pub message_class: Option<MessageClass>,
    pub context: Option<u32>,
    pub payload_length: usize,
}

impl TimelineEntry {
    pub fn from_evidence(record: &EvidenceRecord) -> Self {
        Self::from_parts(record.timestamp_ms, record.direction, &record.frame)
    }

    pub fn from_parts(timestamp_ms: u64, direction: Direction, frame: &BapFrame) -> Self {
        let (message_id, context, payload_length) = match &frame.body {
            FrameBody::Clear(c) => (Some(c.msg_id), Some(c.context), c.payload.len()),
            FrameBody::Encrypted(e) => (None, None, 16 + e.ciphertext.len()),
            FrameBody::Opaque(b) => (None, None, b.len()),
        };
        let (message_class, message_name) = match message_id {
            Some(id) => {
                let class = messages::classify(id);
                (Some(class), class.name())
            }
            None => (None, None),
        };
        Self {
            timestamp_ms,
            direction,
            kind: frame.kind,
            message_id,
            message_name,
            message_class,
            context,
            payload_length,
        }
    }

    /// Human-readable one-liner, e.g. `00:00.087  S → C  0x1a session-login-response`.
    pub fn format_line(&self) -> String {
        let ts = format_timestamp_ms(self.timestamp_ms);
        let dir = self.direction.short();
        let id = match self.message_id {
            Some(id) => format!("0x{id:x}"),
            None => match self.kind {
                FrameKind::Encrypted => "encrypted".to_string(),
                FrameKind::Other(k) => format!("kind=0x{k:02x}"),
                FrameKind::Clear => "clear?".to_string(),
            },
        };
        let name = self.message_name.unwrap_or("");
        if name.is_empty() {
            format!("{ts}  {dir}  {id}")
        } else {
            format!("{ts}  {dir}  {id}  {name}")
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Timeline {
    entries: Vec<TimelineEntry>,
}

impl Timeline {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn from_evidence(records: &[EvidenceRecord]) -> Self {
        let mut entries: Vec<_> = records.iter().map(TimelineEntry::from_evidence).collect();
        entries.sort_by_key(|e| (e.timestamp_ms, direction_order(e.direction)));
        Self { entries }
    }

    pub fn push(&mut self, entry: TimelineEntry) {
        self.entries.push(entry);
    }

    /// Sort by timestamp, then client→server before server→client on ties.
    pub fn sort(&mut self) {
        self.entries
            .sort_by_key(|e| (e.timestamp_ms, direction_order(e.direction)));
    }

    pub fn entries(&self) -> &[TimelineEntry] {
        &self.entries
    }

    pub fn format_lines(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.format_line()).collect()
    }
}

fn direction_order(d: Direction) -> u8 {
    match d {
        Direction::ClientToServer => 0,
        Direction::ServerToClient => 1,
    }
}

fn format_timestamp_ms(ms: u64) -> String {
    let total_secs = ms / 1000;
    let millis = ms % 1000;
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    format!("{mins:02}:{secs:02}.{millis:03}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::clear_frame;
    use crate::jsonl::Direction;

    #[test]
    fn orders_by_timestamp() {
        let mut tl = Timeline::new();
        tl.push(TimelineEntry::from_parts(
            100,
            Direction::ServerToClient,
            &clear_frame(0x1A, 1, b""),
        ));
        tl.push(TimelineEntry::from_parts(
            50,
            Direction::ClientToServer,
            &clear_frame(0x19, 1, b""),
        ));
        tl.sort();
        assert_eq!(tl.entries()[0].message_id, Some(0x19));
        assert_eq!(tl.entries()[1].message_id, Some(0x1A));
    }
}
