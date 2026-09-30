//! Signs a test account in and stores its refresh token for the live suite
//! (`tests/live.rs`), in `%USERPROFILE%\.silentsilo-test\cloud.env` (or
//! `~/.silentsilo-test/cloud.env`), outside every repository. The token is
//! written there and never printed.
//!
//! ```text
//! cargo run -p silentsilo-cloud --example sign-in -- onedrive
//! cargo run -p silentsilo-cloud --example sign-in -- dropbox
//! SILENTSILO_GOOGLE_CLIENT_SECRET=... cargo run -p silentsilo-cloud --example sign-in -- google-drive
//! ```
//!
//! Use accounts made for testing: the suite writes and deletes files.

use std::path::PathBuf;
use std::sync::Arc;

use silentsilo_cloud::{PersistToken, Provider};

struct Discard;

impl PersistToken for Discard {
    fn save(&self, _: &str) -> Result<(), String> {
        Ok(())
    }
}

fn env_file() -> PathBuf {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .expect("a home directory");
    PathBuf::from(home)
        .join(".silentsilo-test")
        .join("cloud.env")
}

fn open_browser(url: &str) -> Result<(), String> {
    #[cfg(windows)]
    let mut command = {
        let mut c = std::process::Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    command.spawn().map(|_| ()).map_err(|e| e.to_string())
}

#[tokio::main]
async fn main() {
    let kind = std::env::args().nth(1).unwrap_or_default();
    let Some(provider) = Provider::from_kind(&kind) else {
        eprintln!("usage: sign-in <onedrive|dropbox|google-drive>");
        std::process::exit(2);
    };
    if !provider.available() {
        eprintln!(
            "{} needs SILENTSILO_GOOGLE_CLIENT_SECRET at build time",
            provider.name()
        );
        std::process::exit(2);
    }
    let var = match provider {
        Provider::OneDrive => "SILENTSILO_TEST_ONEDRIVE_TOKEN",
        Provider::Dropbox => "SILENTSILO_TEST_DROPBOX_TOKEN",
        Provider::GoogleDrive => "SILENTSILO_TEST_GDRIVE_TOKEN",
    };

    eprintln!("Sign in to {} in the browser that opens.", provider.name());
    let signed_in = match silentsilo_cloud::sign_in(provider, Arc::new(Discard), open_browser).await
    {
        Ok(signed_in) => signed_in,
        Err(e) => {
            eprintln!("sign-in failed: {e}");
            std::process::exit(1);
        }
    };
    let token = signed_in.tokens.refresh_token().await;

    let path = env_file();
    std::fs::create_dir_all(path.parent().unwrap()).expect("the folder for cloud.env");
    let kept: Vec<String> = std::fs::read_to_string(&path)
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.starts_with(&format!("{var}=")))
        .map(str::to_string)
        .collect();
    let mut text = kept.join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    text.push_str(&format!("{var}={}\n", token.as_str()));
    std::fs::write(&path, text).expect("cloud.env written");
    eprintln!(
        "Signed in as {}. {var} is in {}.",
        signed_in.account.label,
        path.display()
    );
}
