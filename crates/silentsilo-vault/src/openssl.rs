//! The OpenSSL SQLCipher links is vendored with the build machine's path as
//! its OPENSSLDIR. Left to itself, libcrypto reads `openssl.cnf` from there,
//! or from `OPENSSL_CONF`, on first use, and a config can load a provider
//! library into the process. So it is initialised first, with no config.
//!
//! SQLite is initialised in the same step. SQLite marks itself initialised
//! before it runs SQLCipher's own setup, and SQLCipher registers
//! `sqlcipher_export` only at the end of that setup. A second thread opening
//! its first connection in between got one without the function, and the
//! working copy's export failed with "no such function: sqlcipher_export".
//! Inside the `Once`, every other thread waits until both are done.

use std::sync::Once;

// Links the libcrypto the symbol below lives in.
use openssl_sys as _;

const OPENSSL_INIT_NO_LOAD_CONFIG: u64 = 0x0000_0080;

unsafe extern "C" {
    fn OPENSSL_init_crypto(opts: u64, settings: *const std::ffi::c_void) -> std::ffi::c_int;
}

/// Initialises OpenSSL without reading any configuration. Must run before the
/// process opens its first SQLite connection, since SQLCipher initialises
/// OpenSSL with SQLite. Every connection this workspace opens calls it; a
/// client opening its own connections calls it first.
pub fn init_openssl() {
    static ONCE: Once = Once::new();
    // Safety: no settings pointer, and later initialisations keep these options.
    ONCE.call_once(|| unsafe {
        OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, std::ptr::null());
        rusqlite::ffi::sqlite3_initialize();
    });
}
