//! What an event says, and the codes that name what happened.
//!
//! Codes are numbers, stable for good: a code is never reused for something
//! else and never renumbered, because a log is read years after it was
//! written, by builds that did not exist then. A reader meets codes newer
//! than itself as "unknown event", never as an error.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// One thing that happened, as sealed into a record. Short field names: a
/// busy device writes many of these.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// This device's own count of events, from 0, with no gaps. A record
    /// missing from the log leaves a hole a reader sees.
    pub i: u64,
    /// When, in milliseconds since the epoch, by this device's clock.
    pub t: i64,
    /// What happened: one of the [`codes`].
    pub c: u16,
    /// How many times, when repeats close together were folded into one.
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub n: u32,
    /// What it happened to: an entry, a file or a key, by id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub o: Option<String>,
    /// What that was called then, so it is recognisable after it is gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l: Option<String>,
    /// Anything else the event carries, by name: a site, a key's label, a
    /// count. A reader shows what it does not know as it is.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub x: BTreeMap<String, Value>,
}

fn one() -> u32 {
    1
}

fn is_one(n: &u32) -> bool {
    *n == 1
}

impl Event {
    pub fn new(code: u16, at: i64) -> Self {
        Self {
            i: 0,
            t: at,
            c: code,
            n: 1,
            o: None,
            l: None,
            x: BTreeMap::new(),
        }
    }

    pub fn on(mut self, object: impl Into<String>, label: impl Into<String>) -> Self {
        self.o = Some(object.into());
        self.l = Some(label.into());
        self
    }

    pub fn with(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.x.insert(key.to_string(), value.into());
        self
    }
}

/// The event codes. Grouped by tens; a gap is room for the group to grow.
pub mod codes {
    pub const UNLOCKED: u16 = 1;
    pub const LOCKED: u16 = 2;
    pub const UNLOCK_REFUSED: u16 = 3;

    pub const ENTRY_REVEALED: u16 = 10;
    pub const SECRET_COPIED: u16 = 11;
    pub const CODE_COPIED: u16 = 12;
    pub const BROWSER_FILLED: u16 = 13;
    pub const APP_FILLED: u16 = 14;
    /// The desktop's SSH agent signed with a key kept in the silo.
    pub const SSH_SIGNED: u16 = 15;

    pub const ENTRY_CREATED: u16 = 20;
    pub const ENTRY_EDITED: u16 = 21;
    pub const ENTRY_DELETED: u16 = 22;
    pub const ENTRY_RESTORED: u16 = 23;
    pub const HISTORY_CLEARED: u16 = 24;

    pub const FILE_OPENED: u16 = 30;
    pub const FILE_SAVED_OUTSIDE: u16 = 31;
    pub const FILE_ADDED: u16 = 32;
    pub const FILE_TRASHED: u16 = 33;
    pub const FILE_PURGED: u16 = 34;

    pub const PASSWORDS_IMPORTED: u16 = 40;
    pub const PASSWORDS_EXPORTED: u16 = 41;

    pub const KEY_ADDED: u16 = 50;
    pub const KEY_REMOVED: u16 = 51;
    pub const RECOVERY_CODE_USED: u16 = 52;
    pub const RECOVERY_CODE_CHANGED: u16 = 53;
    pub const SILO_KEY_ROTATED: u16 = 54;

    pub const LOG_STARTED: u16 = 60;
    pub const LOG_STOPPED: u16 = 61;
    pub const RETENTION_CHANGED: u16 = 62;
    pub const SEGMENTS_EXPIRED: u16 = 63;

    pub const DEVICE_JOINED: u16 = 70;
    pub const SILO_REPAIRED: u16 = 71;
}

/// What a code is called on screen and in an export. A code this build does
/// not know is named by its number.
pub fn describe(code: u16) -> String {
    use codes::*;
    let known = match code {
        UNLOCKED => "Unlocked",
        LOCKED => "Locked",
        UNLOCK_REFUSED => "Unlock refused",
        ENTRY_REVEALED => "Entry shown",
        SECRET_COPIED => "Secret copied",
        CODE_COPIED => "One-time code copied",
        BROWSER_FILLED => "Filled in the browser",
        APP_FILLED => "Filled in an app",
        SSH_SIGNED => "Signed with an SSH key",
        ENTRY_CREATED => "Entry created",
        ENTRY_EDITED => "Entry edited",
        ENTRY_DELETED => "Entry deleted",
        ENTRY_RESTORED => "Earlier version restored",
        HISTORY_CLEARED => "Entry history cleared",
        FILE_OPENED => "File opened",
        FILE_SAVED_OUTSIDE => "File saved outside the silo",
        FILE_ADDED => "File added",
        FILE_TRASHED => "File moved to the trash",
        FILE_PURGED => "File deleted for good",
        PASSWORDS_IMPORTED => "Passwords imported",
        PASSWORDS_EXPORTED => "Passwords exported",
        KEY_ADDED => "Key added",
        KEY_REMOVED => "Key removed",
        RECOVERY_CODE_USED => "Recovery code used",
        RECOVERY_CODE_CHANGED => "Recovery code changed",
        SILO_KEY_ROTATED => "Silo key changed",
        LOG_STARTED => "Activity log started",
        LOG_STOPPED => "Activity log stopped",
        RETENTION_CHANGED => "Log retention changed",
        SEGMENTS_EXPIRED => "Old log segments removed",
        DEVICE_JOINED => "Device joined",
        SILO_REPAIRED => "Silo repaired",
        _ => return format!("Unknown event {code}"),
    };
    known.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_event_is_compact_and_reads_back() {
        let event = Event::new(codes::SECRET_COPIED, 1_789_000_000_000)
            .on("e1", "Bank")
            .with("field", "password");
        let json = serde_json::to_string(&event).unwrap();
        assert_eq!(
            json,
            r#"{"i":0,"t":1789000000000,"c":11,"o":"e1","l":"Bank","x":{"field":"password"}}"#
        );
        assert_eq!(serde_json::from_str::<Event>(&json).unwrap(), event);
    }

    #[test]
    fn a_later_build_s_fields_and_codes_are_read_not_refused() {
        let json = r#"{"i":3,"t":5,"c":999,"n":4,"new_field":true}"#;
        let event: Event = serde_json::from_str(json).unwrap();
        assert_eq!(event.n, 4);
        assert_eq!(describe(event.c), "Unknown event 999");
    }

    /// The numbers are the format. This list fails loudly if one moves.
    #[test]
    fn codes_never_move() {
        use codes::*;
        let pinned = [
            (UNLOCKED, 1),
            (LOCKED, 2),
            (UNLOCK_REFUSED, 3),
            (ENTRY_REVEALED, 10),
            (SECRET_COPIED, 11),
            (CODE_COPIED, 12),
            (BROWSER_FILLED, 13),
            (APP_FILLED, 14),
            (SSH_SIGNED, 15),
            (ENTRY_CREATED, 20),
            (ENTRY_EDITED, 21),
            (ENTRY_DELETED, 22),
            (ENTRY_RESTORED, 23),
            (HISTORY_CLEARED, 24),
            (FILE_OPENED, 30),
            (FILE_SAVED_OUTSIDE, 31),
            (FILE_ADDED, 32),
            (FILE_TRASHED, 33),
            (FILE_PURGED, 34),
            (PASSWORDS_IMPORTED, 40),
            (PASSWORDS_EXPORTED, 41),
            (KEY_ADDED, 50),
            (KEY_REMOVED, 51),
            (RECOVERY_CODE_USED, 52),
            (RECOVERY_CODE_CHANGED, 53),
            (SILO_KEY_ROTATED, 54),
            (LOG_STARTED, 60),
            (LOG_STOPPED, 61),
            (RETENTION_CHANGED, 62),
            (SEGMENTS_EXPIRED, 63),
            (DEVICE_JOINED, 70),
            (SILO_REPAIRED, 71),
        ];
        for (code, number) in pinned {
            assert_eq!(code, number);
            assert!(!describe(code).starts_with("Unknown"), "{code} has a name");
        }
    }
}
