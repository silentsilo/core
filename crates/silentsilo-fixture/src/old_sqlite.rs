//! The rusqlite the old core tags build against, and a way across to this
//! build's. Both sit on one libsqlite3-sys (`compat/README.md`), so a
//! connection either opens is the same SQLite handle; only the Rust type
//! differs. Tests that run old and new code over one database use these.

pub use rusqlite_old::Connection as OldConnection;

/// `old` seen as this build's `Connection`, for the length of `f`.
pub fn with_new<R>(old: &OldConnection, f: impl FnOnce(&rusqlite::Connection) -> R) -> R {
    // SAFETY: both crates wrap the `sqlite3` type of one libsqlite3-sys.
    // `from_handle` does not close the handle, and the borrowed connection
    // is dropped before this returns, while `old` still owns it.
    let conn = unsafe { rusqlite::Connection::from_handle(old.handle()) }
        .expect("a live handle is always accepted");
    f(&conn)
}

/// `new` seen as the old tags' `Connection`, for the length of `f`.
pub fn with_old<R>(new: &rusqlite::Connection, f: impl FnOnce(&OldConnection) -> R) -> R {
    // SAFETY: as in `with_new`.
    let conn = unsafe { OldConnection::from_handle(new.handle()) }
        .expect("a live handle is always accepted");
    f(&conn)
}

/// An in-memory database for the old tags, with foreign keys on as every
/// release opens its own.
pub fn old_in_memory() -> OldConnection {
    let conn = OldConnection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON;").unwrap();
    conn
}

/// Either connection seen as this build's, for code written once for both,
/// such as a macro that builds a device on each release.
pub trait AsThisBuild {
    fn as_this_build<R>(&self, f: impl FnOnce(&rusqlite::Connection) -> R) -> R;
}

impl AsThisBuild for rusqlite::Connection {
    fn as_this_build<R>(&self, f: impl FnOnce(&rusqlite::Connection) -> R) -> R {
        f(self)
    }
}

impl AsThisBuild for OldConnection {
    fn as_this_build<R>(&self, f: impl FnOnce(&rusqlite::Connection) -> R) -> R {
        with_new(self, f)
    }
}
