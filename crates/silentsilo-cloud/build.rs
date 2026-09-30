//! Google's desktop client secret, for `Provider::client_secret`. From the
//! environment when set (CI), else from the file the release machine keeps
//! outside every repository, so a development build finds it too. Neither
//! present: the build has no Google Drive.

use std::path::PathBuf;

const VAR: &str = "SILENTSILO_GOOGLE_CLIENT_SECRET";

fn main() {
    println!("cargo:rerun-if-env-changed={VAR}");
    if std::env::var(VAR).is_ok_and(|v| !v.trim().is_empty()) {
        return;
    }
    let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) else {
        return;
    };
    let file = PathBuf::from(home)
        .join(".silentsilo-release")
        .join("google-client-secret.txt");
    println!("cargo:rerun-if-changed={}", file.display());
    if let Ok(secret) = std::fs::read_to_string(&file) {
        let secret = secret.trim();
        if !secret.is_empty() {
            println!("cargo:rustc-env={VAR}={secret}");
        }
    }
}
