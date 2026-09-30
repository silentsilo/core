//! What the suites need to test the two things a clean temporary directory
//! cannot show: real storage, and a hostile environment. Dev-dependency only.

use std::path::Path;

/// Set in the release lane, where a suite that skips itself is a failure:
/// green has to mean the tests ran.
const REQUIRE: &str = "SILENTSILO_TEST_REQUIRE_BACKENDS";

/// Reports a suite standing down for want of an endpoint, or fails when the
/// caller has declared that endpoints must be there.
pub fn skip_or_fail(what: &str) {
    if std::env::var(REQUIRE).is_ok() {
        panic!(
            "{what}, and {REQUIRE} is set: the release lane requires every backend to be \
             reachable. Start them with scripts/test-local.ps1, or unset {REQUIRE}."
        );
    }
    eprintln!("skipped: {what}");
}

/// Holds a file open the way a scanner does just after a write. On Windows
/// a rename onto a held destination fails outright, which is how every
/// durable write once became "Access is denied".
pub struct HeldOpen(#[allow(dead_code)] std::fs::File);

impl HeldOpen {
    /// Opens `path` for reading and keeps the handle until dropped. Shared
    /// for reading and writing but not for delete, as a scanner opens it:
    /// a plain write goes through, a rename onto the file does not. Rust's
    /// own default shares delete too, and a POSIX-style rename then succeeds.
    pub fn reading(path: &Path) -> Self {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            // FILE_SHARE_READ | FILE_SHARE_WRITE
            options.share_mode(0x1 | 0x2);
        }
        Self(
            options
                .open(path)
                .expect("the file to hold open must exist"),
        )
    }
}

/// Puts a directory where a file is about to be written, making "cannot
/// create here" deterministic. It is a separate failure from "cannot change
/// what is already there".
pub struct BlockedPath(std::path::PathBuf);

impl BlockedPath {
    pub fn at(path: &Path) -> Self {
        std::fs::create_dir_all(path).expect("blocking the path");
        Self(path.to_path_buf())
    }
}

impl Drop for BlockedPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
