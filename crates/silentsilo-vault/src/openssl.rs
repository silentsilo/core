//! The OpenSSL SQLCipher links is vendored with the build machine's path as
//! its OPENSSLDIR. Left to itself, libcrypto reads `openssl.cnf` from there,
//! or from `OPENSSL_CONF`, on first use, and a config can load a provider
//! library into the process. So it is initialised first, with no config.

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
    });
}
