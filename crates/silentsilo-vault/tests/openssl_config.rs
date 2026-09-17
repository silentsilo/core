//! The vendored OpenSSL must never read a configuration file: its compiled-in
//! OPENSSLDIR is a path on the build machine, and a config can load a
//! provider library into the process.

use std::process::Command;

use silentsilo_vault::VaultSession;
use uuid::Uuid;

const CHILD: &str = "SILENTSILO_OPENSSL_CONFIG_CHILD";

/// Run in a child process, so OpenSSL starts fresh with `OPENSSL_CONF` set.
#[test]
fn a_config_naming_a_missing_provider_is_never_loaded() {
    if std::env::var_os(CHILD).is_some() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("silo");
        let id = Uuid::new_v4();
        let session = VaultSession::provision(root.clone(), id, "secret").unwrap();
        session
            .conn
            .execute_batch(&format!(
                "CREATE TABLE vault_meta (key TEXT PRIMARY KEY, value TEXT);
                 INSERT INTO vault_meta VALUES ('vault_id', '{id}');"
            ))
            .unwrap();
        session.backup_locally().unwrap();
        let dek = session.dek.clone();
        drop(session);
        VaultSession::open_with_dek(root, dek).expect("the silo opens");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let module = dir.path().join("missing-provider.dll");
    let conf = dir.path().join("openssl.cnf");
    // Diagnostics on: a provider that fails to load fails initialisation.
    std::fs::write(
        &conf,
        format!(
            "openssl_conf = init\nconfig_diagnostics = 1\n\n[init]\nproviders = providers\n\n\
             [providers]\nhostile = hostile\n\n[hostile]\nmodule = {}\nactivate = 1\n",
            module.display().to_string().replace('\\', "/")
        ),
    )
    .unwrap();

    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_config_naming_a_missing_provider_is_never_loaded",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env("OPENSSL_CONF", &conf)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && stdout.contains("1 passed"),
        "child failed:\n{stdout}\n{stderr}"
    );
}
