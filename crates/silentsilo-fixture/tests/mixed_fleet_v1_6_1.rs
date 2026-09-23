//! A fleet half updated from core 1.6.1, the core desktop 1.1.0 and Android
//! 1.1.0 ship: devices still on 1.6.1 beside devices on this build, all
//! syncing against the same storage.
//!
//! Since 1.6.1 the sync pass lives in `silentsilo-app`, so every device runs
//! `run_sync_pass` of its own version, the 1.6.1 crates pulled in by tag.
//! The silo is made on 1.6.1 with a recovery code, one security key and two
//! folder copies, a working one and a never-delete one. Every device joins
//! with the key; two of them then update in place, which is the first unlock
//! of a 1.6.1 silo folder by this build.
//!
//! What must hold:
//!
//! - no pass fails, holds records back or finds an unreadable object, on
//!   either version, and every device shows the same tree and passwords;
//! - every file and attachment opens with the bytes that were added, on
//!   both versions, and nothing added is gone unless a purge took it or a
//!   later add over the same name replaced it;
//! - compaction on either version leaves the other syncing, after a rebuild
//!   when it fell below the horizon, with its offline work kept;
//! - a key replacement on either version sends a device of the other that
//!   was not kept to rejoin before it writes anything, and once it rejoined
//!   with a kept key it reads everything and is not sent back;
//! - an inbox item sent by either version is imported by the other.
//!
//! A key replacement leaves the never-delete copy under the old key, and
//! every later push to it fails, on both versions. That failure is the one
//! allowed after a replacement, and it is checked to be exactly that.
//!
//! Printed, not asserted: a 1.6.1 device left out of a replacement whose
//! never-delete copy is listed first. 1.6.1 lets the first copy that answers
//! decide whether its key is current, so it writes records under the old
//! key to that copy, and every device on the new key then reports them
//! unreadable and holds back what sorts after them. Only the working copy
//! is checked, which it must not touch.
//!
//! Two devices importing one inbox item agree on its folder on this build,
//! also when the import folder was trashed or purged. 1.6.1 then makes a
//! folder under a fresh id and keeps the item there, so the item waits for
//! its importer to finish it before a 1.6.1 device looks.
//!
//! A 1.6.1 device compacts only while it still holds its whole log: its
//! `capture_at` builds the snapshot from the local log only, so after a
//! rebuild, a rejoin or its own compaction it publishes one without the
//! state below its base. This build restores the base first, and a device on
//! it compacts whatever happened before.
//!
//! Every pass sweeps storage, and a step of the everyday script stands for a
//! day, so the 30-day grace can run out during the run on both versions.
//!
//! The random lifecycles run the same scenarios in an order a seed picks,
//! with days offline, a copy unplugged, locks, updates and new devices in
//! between, and check everything after each one. A failure prints the seed
//! and the events up to it; `SILENTSILO_LIFECYCLE_SHRINK=1` cuts that down to
//! the events it needs, printed ready to paste into `lifecycle_regressions`.
//! `SILENTSILO_LIFECYCLE_SEED=7` or `=1..500` picks seeds and
//! `SILENTSILO_LIFECYCLE_EVENTS` how many events each runs.
//!
//! `SILENTSILO_MIXED_SEED` picks another script, `SILENTSILO_MIXED_TRACE`
//! prints what each device does.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusqlite::Connection;
use uuid::Uuid;

/// The one security key every device joins with and every replacement keeps.
const KEY_ID: &str = "aa11";
const WRAP: [u8; 32] = [7; 32];

/// The password entry attachments are added to. Never deleted by the script.
const ATTACHED: u128 = 9;

// ── A seeded order ──────────────────────────────────────────────────

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }

    fn pick<T: Clone>(&mut self, items: &[T]) -> Option<T> {
        (!items.is_empty()).then(|| items[self.below(items.len())].clone())
    }

    fn bytes(&mut self) -> Vec<u8> {
        let len = 64 + self.below(3000);
        (0..len).map(|_| self.next() as u8).collect()
    }
}

const FOLDER_NAMES: &[&str] = &["Docs", "docs", "Photos", "x", "X", "x (2)", "Școală"];
const FILE_NAMES: &[&str] = &["a.txt", "A.txt", "a (2).txt", "report.pdf", "notă.md"];
const PASSWORD_IDS: &[u128] = &[1, 2, 3, 4];

fn trace(line: impl AsRef<str>) {
    if std::env::var("SILENTSILO_MIXED_TRACE").is_ok() {
        eprintln!("{}", line.as_ref());
    }
}

// ── What a host gives both versions ─────────────────────────────────

/// A device's storage settings, in its own order: each copy's folder, and
/// whether deletes are allowed there.
struct FleetHost {
    copies: Mutex<Vec<(PathBuf, bool)>>,
}

impl FleetHost {
    fn new(copies: Vec<(PathBuf, bool)>) -> Self {
        Self {
            copies: Mutex::new(copies),
        }
    }

    fn copies(&self) -> Vec<(PathBuf, bool)> {
        self.copies.lock().unwrap().clone()
    }

    fn warned(&self, area: &str, detail: &str) {
        trace(format!("  warning [{area}] {detail}"));
    }
}

/// What a pass came to, on either version.
#[derive(Debug, Default)]
struct Pass {
    moved: usize,
    unreadable: Vec<String>,
    held_back: usize,
    /// Copies that failed, by label, with why.
    failed: Vec<(String, String)>,
    needs_rebuild: bool,
    needs_rejoin: bool,
    key_material_replaced: bool,
    inbox_imported: usize,
    inbox_refused: Vec<String>,
    skipped: bool,
}

/// What the push to a never-delete copy left under the old key says.
const STALE_COPY: &str = "does not open with this device's key";

/// What this build says about a never-delete copy under the replaced key,
/// which it leaves out rather than fails.
const RETIRED: &str = "gets no new backups";

/// What a pass says about a folder copy that is not there.
const UNPLUGGED: &str = "is not available";

impl Pass {
    /// Nothing failed, waited or was refused. After a key replacement the
    /// never-delete copy may fail, for that reason only, and a copy that is
    /// unplugged may fail for being unreachable.
    fn assert_clean(&self, context: &str, replaced: bool, down: &HashSet<&str>) {
        let failed_elsewhere = self.failed.iter().any(|(label, why)| {
            !(replaced
                && label == "never-delete"
                && (why.contains(STALE_COPY) || why.contains(RETIRED))
                || down.contains(label.as_str()) && why.contains(UNPLUGGED))
        });
        assert!(
            self.unreadable.is_empty()
                && self.held_back == 0
                && !failed_elsewhere
                && !self.needs_rebuild
                && !self.needs_rejoin
                && !self.key_material_replaced
                && self.inbox_refused.is_empty()
                && !self.skipped,
            "{context}: {self:?}"
        );
    }
}

// ── The same device code, compiled against each version ─────────────

macro_rules! version {
    ($module:ident, $app:ident, $vault:ident, $vfs:ident, $sync:ident, $crypto:ident, $store:ident, $commit:path) => {
        // Only 1.6.1 creates the silo.
        #[allow(dead_code)]
        mod $module {
            use std::path::{Path, PathBuf};

            use ::$app as app;
            use ::$crypto as crypto;
            use ::$store as store;
            use ::$sync as sync;
            use ::$vault as vault;
            use ::$vfs as vfs;
            use store::ObjectStore;
            use uuid::Uuid;

            use super::{FleetHost, KEY_ID, Pass, WRAP};

            impl app::Host for FleetHost {
                fn emit(&self, _event: app::AppEvent) {}
                fn warn(&self, area: &str, detail: &str) {
                    self.warned(area, detail);
                }
                fn targets(&self, _silo_id: Uuid) -> Vec<vault::BackupTarget> {
                    self.copies()
                        .into_iter()
                        .map(|(path, working)| vault::BackupTarget {
                            config: store::StoreConfig::Folder { path },
                            label: if working { "working" } else { "never-delete" }.into(),
                            role: if working {
                                vault::TargetRole::Working
                            } else {
                                vault::TargetRole::Archive
                            },
                        })
                        .collect()
                }
            }

            fn key() -> app::flows::DeviceKey {
                app::flows::DeviceKey {
                    kind: vault::KIND_FIDO2.into(),
                    derivation: vault::DERIVATION_HMAC_V1.into(),
                    credential_id: KEY_ID.into(),
                    public_key: String::new(),
                    wrap_key: WRAP,
                    label: "Key".into(),
                }
            }

            fn now() -> i64 {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0)
            }

            pub struct Dev {
                pub state: app::AppState,
                pub silo: vault::SiloEntry,
            }

            impl Dev {
                /// A new silo with a recovery code and the security key.
                pub fn create(root: PathBuf, host: &FleetHost) -> Self {
                    let vault_id = Uuid::new_v4();
                    let session =
                        vault::VaultSession::provision(root.clone(), vault_id, "secret").unwrap();
                    vfs::Vfs::new(&session).ensure_initialized().unwrap();
                    let (_code, envelope) =
                        vault::create_recovery_envelope(&session.dek, &session.kek).unwrap();
                    vault::save_recovery_envelope(&root, &envelope).unwrap();
                    app::flows::enrol_device_key(&session, &key()).unwrap();
                    Self::open(root, vault_id, session, host)
                }

                /// Joining with the security key, as a new device or a rejoin.
                pub async fn join(
                    root: PathBuf,
                    storage: &Path,
                    host: &FleetHost,
                ) -> Result<Self, String> {
                    let store = store::FolderStore::new(storage.to_path_buf());
                    let offer = app::flows::key_join_begin(&store).await?;
                    let join = app::flows::key_join_open(&store, &offer, KEY_ID, &WRAP).await?;
                    let session =
                        app::flows::recovery_join_provision(&store, &join, root.clone(), "secret")
                            .await?;
                    let plan = sync::fetch_join_plan_reporting(&store, join.dek(), &mut |_, _| {})
                        .await
                        .map_err(|e| e.to_string())?;
                    let (session, _) = app::flows::join_finish(session, plan)?;
                    Ok(Self::open(root, offer.vault_id, session, host))
                }

                /// Unlocking with the security key.
                pub fn unlock(root: PathBuf, vault_id: Uuid, host: &FleetHost) -> Self {
                    let (session, _) =
                        app::flows::open_with_device_key(root.clone(), KEY_ID, &WRAP, vault_id)
                            .expect("the key opens the silo");
                    Self::open(root, vault_id, session, host)
                }

                fn open(
                    root: PathBuf,
                    vault_id: Uuid,
                    session: vault::VaultSession,
                    host: &FleetHost,
                ) -> Self {
                    let state = app::AppState::default();
                    state.open_session(host, vault_id, session).unwrap();
                    Self {
                        state,
                        silo: vault::SiloEntry {
                            id: vault_id,
                            name: "Mixed".into(),
                            path: root,
                            last_opened: 0,
                            auto_lock_minutes: None,
                        },
                    }
                }

                pub fn lock(&self, host: &FleetHost) {
                    self.state.close_session(host, self.silo.id).unwrap();
                }

                pub fn with<T>(&self, f: impl FnOnce(&vault::VaultSession) -> T) -> T {
                    let sessions = self.state.sessions.lock().unwrap();
                    f(&sessions[&self.silo.id])
                }

                pub fn conn<T>(&self, f: impl FnOnce(&rusqlite::Connection) -> T) -> T {
                    self.with(|s| f(&s.conn))
                }

                pub fn vfs<T>(&self, f: impl FnOnce(vfs::Vfs<'_>) -> T) -> T {
                    self.with(|s| f(vfs::Vfs::new(s)))
                }

                pub fn kek(&self) -> [u8; 32] {
                    self.with(|s| *s.kek.as_bytes())
                }

                pub async fn pass(&self, host: &FleetHost) -> Pass {
                    let r = app::run_sync_pass(&self.state, host, &self.silo)
                        .await
                        .unwrap_or_else(|e| panic!("a pass failed: {e}"));
                    Pass {
                        moved: r.ops_pushed + r.ops_applied + r.blobs_uploaded + r.inbox_imported,
                        unreadable: r.unreadable,
                        held_back: r.held_back,
                        failed: r
                            .targets
                            .iter()
                            .filter_map(|t| t.failed.clone().map(|f| (t.label.clone(), f)))
                            .collect(),
                        needs_rebuild: r.needs_rebuild,
                        needs_rejoin: r.needs_rejoin,
                        key_material_replaced: r.key_material_replaced,
                        inbox_imported: r.inbox_imported,
                        inbox_refused: r.inbox_refused,
                        skipped: r.skipped,
                    }
                }

                pub fn import(
                    &self,
                    folder: Uuid,
                    name: &str,
                    bytes: &[u8],
                ) -> Option<(Uuid, String)> {
                    let file = app::files::import_file(
                        &self.state,
                        &self.silo,
                        folder,
                        &mut { bytes },
                        name,
                        None,
                    )
                    .ok()?;
                    Some((file.id, file.content_hash?))
                }

                pub async fn read(&self, host: &FleetHost, id: Uuid) -> Result<Vec<u8>, String> {
                    app::files::read_file(&self.state, host, &self.silo, id, 1 << 20)
                        .await
                        .map(|file| file.bytes)
                }

                /// The desktop's `password_attach_file`: the content goes to
                /// the blob store and its key into the entry, with no row.
                pub fn attach(&self, bytes: &[u8]) -> serde_json::Value {
                    let (root, kek) = self.with(|s| (s.paths.root.clone(), s.kek.clone()));
                    let source = tempfile::NamedTempFile::new().unwrap();
                    std::fs::write(source.path(), bytes).unwrap();
                    let blob_id = Uuid::new_v4();
                    let content_key = crypto::generate_content_key();
                    let blob_key = crypto::wrap_content_key(&content_key, &kek).unwrap();
                    let path = vault::VaultPaths::new(root.clone()).blob_path(blob_id);
                    let sealed = crypto::encrypt_file(
                        source.path(),
                        &path,
                        &content_key,
                        Uuid::now_v7(),
                        blob_id,
                    )
                    .unwrap();
                    let _ =
                        vault::record_blob_present(&root, blob_id, sealed.size_bytes as i64, false);
                    serde_json::json!({
                        "blob_id": blob_id.to_string(),
                        "name": "scan.bin",
                        "size_bytes": sealed.plain_bytes as i64,
                        "blob_key": blob_key,
                    })
                }

                /// The desktop's `password_open_attachment`, into memory.
                pub async fn open_blob(
                    &self,
                    host: &FleetHost,
                    blob_id: Uuid,
                    blob_key: &str,
                ) -> Result<Vec<u8>, String> {
                    let root = self.silo.path.clone();
                    let path = vault::VaultPaths::new(root.clone()).blob_path(blob_id);
                    if !path.is_file() {
                        let stores: Vec<store::FolderStore> = host
                            .copies()
                            .into_iter()
                            .map(|(p, _)| store::FolderStore::new(p))
                            .collect();
                        let refs: Vec<&dyn ObjectStore> =
                            stores.iter().map(|s| s as &dyn ObjectStore).collect();
                        sync::fetch_blob_from_any(&refs, &root, blob_id)
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    let kek = self.with(|s| s.kek.clone());
                    let key =
                        crypto::unwrap_content_key(blob_key, &kek).map_err(|e| e.to_string())?;
                    let out = tempfile::NamedTempFile::new().unwrap();
                    crypto::decrypt_blob(&path, out.path(), &key, blob_id)
                        .map_err(|e| e.to_string())?;
                    std::fs::read(out.path()).map_err(|e| e.to_string())
                }

                pub fn uncache(&self, blob: Uuid) {
                    let _ = vault::remove_blob_from_cache(&self.silo.path, blob);
                }

                /// The pass's compaction, with a policy that compacts now:
                /// the default one waits for a month and 5,000 records.
                pub async fn compact(&self, host: &FleetHost) -> u64 {
                    let policy = vfs::CompactionPolicy {
                        retain_seconds: 0,
                        keep_recent: 10,
                        min_records: 0,
                    };
                    let (vault_id, dek) = self.with(|s| (s.vault_id, s.dek.clone()));
                    let snapshot = self
                        .with(|s| sync::plan_compaction(&s.conn, vault_id, &policy, now()))
                        .unwrap()
                        .expect("a horizon to compact at");
                    // As the pass does: a copy that refuses keeps its whole
                    // log, and the device prunes once any copy took it.
                    let mut published = false;
                    for (path, working) in host.copies() {
                        published |= sync::publish_compaction(
                            &store::FolderStore::new(path),
                            &dek,
                            &snapshot,
                            working,
                        )
                        .await
                        .is_ok();
                    }
                    assert!(published, "no copy took the snapshot");
                    let mut sessions = self.state.sessions.lock().unwrap();
                    let session = sessions.get_mut(&self.silo.id).unwrap();
                    sync::finish_compaction(&mut session.conn, &snapshot).unwrap();
                    snapshot.horizon
                }

                /// The desktop's `vault_rebuild_from_snapshot`: the most
                /// current copy serves it. Returns how many of this device's
                /// unpushed records were written again.
                pub async fn rebuild(&self, host: &FleetHost) -> usize {
                    let dek = self.with(|s| s.dek.clone());
                    let mut plan: Option<(vfs::Snapshot, Vec<vfs::OpRecord>)> = None;
                    for (path, _) in host.copies() {
                        if let Ok(Some(found)) =
                            sync::fetch_rebuild(&store::FolderStore::new(path), &dek).await
                        {
                            let better = plan.as_ref().is_none_or(|(best, ops)| {
                                (found.0.horizon, found.1.len()) > (best.horizon, ops.len())
                            });
                            if better {
                                plan = Some(found);
                            }
                        }
                    }
                    let (snapshot, incoming) = plan.expect("a snapshot to rebuild from");
                    let mut sessions = self.state.sessions.lock().unwrap();
                    let session = sessions.get_mut(&self.silo.id).unwrap();
                    sync::apply_rebuild(&mut session.conn, &snapshot, incoming)
                        .unwrap()
                        .kept_local
                }

                /// A key replacement the way the desktop of this version
                /// runs one, keeping the one key, then the lock it ends with.
                pub async fn replace_key(&self, host: &FleetHost) {
                    let (old, kek, root) =
                        self.with(|s| (s.dek.clone(), s.kek.clone(), s.paths.root.clone()));
                    let new = crypto::generate_dek();
                    vault::rotation::stage_rotation(&root, &new, &kek, &old).unwrap();
                    for (path, working) in host.copies() {
                        if !working {
                            continue;
                        }
                        let outcome = sync::reseal_under_new_key(
                            &store::FolderStore::new(path),
                            &old,
                            &new,
                            &mut |_, _| {},
                        )
                        .await
                        .unwrap();
                        assert!(outcome.failed.is_empty(), "{:?}", outcome.failed);
                    }
                    let mut keys = vault::load_fido_keys(&root).unwrap();
                    for credential in keys.keys.iter_mut() {
                        if credential.credential_id == KEY_ID {
                            credential.wrapped_dek =
                                hex::encode(vault::wrap_dek_bytes(&new, &WRAP).unwrap());
                        } else {
                            credential.revoked = true;
                        }
                    }
                    let (_code, recovery) = vault::create_recovery_envelope(&new, &kek).unwrap();
                    let staged = vault::VaultPaths::new(root.clone()).db_enc_staged_path();
                    self.with(|s| s.stage_local_backup(&new, &staged)).unwrap();
                    $commit(&root, &keys, &recovery);
                    for (path, working) in host.copies() {
                        if working {
                            sync::push_recovery_envelope(&store::FolderStore::new(path), &recovery)
                                .await
                                .unwrap();
                        }
                    }
                    self.lock(host);
                }
            }

            /// A phone allowed to send, set up while the silo was open.
            pub struct Phone {
                identity: sync::inbox::SenderIdentity,
                secret: crypto::inbox::EcSecret,
            }

            impl Phone {
                pub async fn register(storage: &Path, vault_id: Uuid, kek: [u8; 32]) -> Self {
                    let store = store::FolderStore::new(storage.to_path_buf());
                    let kek = crypto::ContentKek::from_bytes(kek);
                    let (key_id, inbox_public) =
                        sync::inbox::ensure_inbox_key(&store, &kek).await.unwrap();
                    let secret = crypto::inbox::EcSecret::generate();
                    let sender_id = Uuid::new_v4();
                    sync::inbox::register_sender(
                        &store,
                        &kek,
                        &sync::inbox::SenderRecord {
                            version: sync::inbox::INBOX_VERSION,
                            sender_id,
                            public_key: hex::encode(secret.public_key()),
                            credential_id: KEY_ID.into(),
                            label: "Phone".into(),
                            created_at: 0,
                        },
                    )
                    .await
                    .unwrap();
                    Self {
                        identity: sync::inbox::SenderIdentity {
                            vault_id,
                            sender_id,
                            key_id,
                            inbox_public,
                        },
                        secret,
                    }
                }

                pub async fn send(&self, storage: &Path, item_id: Uuid, name: &str, bytes: &[u8]) {
                    let store = store::FolderStore::new(storage.to_path_buf());
                    let dir = tempfile::tempdir().unwrap();
                    let source = dir.path().join(name);
                    std::fs::write(&source, bytes).unwrap();
                    sync::inbox::send_item(
                        &store,
                        &self.identity,
                        &sync::inbox::OutgoingItem {
                            item_id,
                            source: &source,
                            name: name.into(),
                            mime_type: Some("image/jpeg".into()),
                            taken_at: None,
                            folder: vec!["Phone".into()],
                            source_kind: "photos".into(),
                        },
                        &|message| Ok(self.secret.sign(message)),
                    )
                    .await
                    .unwrap();
                }
            }
        }
    };
}

version!(
    old,
    silentsilo_app_v1_6_1,
    silentsilo_vault_v1_6_1,
    silentsilo_vfs_v1_6_1,
    silentsilo_sync_v1_6_1,
    silentsilo_crypto_v1_6_1,
    silentsilo_store_v1_6_1,
    super::commit_on_1_6_1
);
version!(
    new,
    silentsilo_app,
    silentsilo_vault,
    silentsilo_vfs,
    silentsilo_sync,
    silentsilo_crypto,
    silentsilo_store,
    super::commit_on_this_build
);

/// Desktop 1.1.0 on 1.6.1: the key moves first, then the snapshot, then the
/// keys and the recovery envelope are written.
fn commit_on_1_6_1(
    root: &Path,
    keys: &silentsilo_vault_v1_6_1::StoredFidoKeys,
    recovery: &silentsilo_vault_v1_6_1::RecoveryEnvelope,
) {
    silentsilo_vault_v1_6_1::rotation::commit_rotation(root).unwrap();
    move_staged_snapshot(root);
    silentsilo_vault_v1_6_1::save_fido_keys(
        root,
        keys,
        silentsilo_vault_v1_6_1::Authority::Machine,
    )
    .unwrap();
    silentsilo_vault_v1_6_1::save_recovery_envelope(root, recovery).unwrap();
}

/// This build: the keys and the recovery envelope commit with the key.
fn commit_on_this_build(
    root: &Path,
    keys: &silentsilo_vault::StoredFidoKeys,
    recovery: &silentsilo_vault::RecoveryEnvelope,
) {
    silentsilo_vault::rotation::commit_rotation_with(
        root,
        keys,
        silentsilo_vault::Authority::Machine,
        Some(recovery),
    )
    .unwrap();
    move_staged_snapshot(root);
}

fn move_staged_snapshot(root: &Path) {
    let paths = silentsilo_vault::VaultPaths::new(root.to_path_buf());
    silentsilo_core::rename_with_retry(&paths.db_enc_staged_path(), &paths.db_enc_path()).unwrap();
    std::fs::copy(paths.db_enc_path(), paths.db_enc_backup_path()).unwrap();
}

// ── Devices ─────────────────────────────────────────────────────────

enum Kind {
    Old(old::Dev),
    New(new::Dev),
}

/// Runs the same body against whichever version the device is on.
macro_rules! on {
    ($device:expr, |$d:ident| $body:expr) => {
        match &$device.kind {
            Kind::Old($d) => $body,
            Kind::New($d) => $body,
        }
    };
}

struct Device {
    name: &'static str,
    dir: tempfile::TempDir,
    root: PathBuf,
    host: FleetHost,
    kind: Kind,
    /// The day of this device's last pass, for the sweep's grace.
    swept_on: AtomicUsize,
}

impl Device {
    fn is_old(&self) -> bool {
        matches!(self.kind, Kind::Old(_))
    }

    fn version(&self) -> &'static str {
        if self.is_old() { "1.6.1" } else { "this build" }
    }

    fn conn<T>(&self, f: impl FnOnce(&Connection) -> T) -> T {
        on!(self, |d| d.conn(f))
    }

    fn vault_id(&self) -> Uuid {
        on!(self, |d| d.silo.id)
    }

    /// One pass, sweeping storage every time rather than once a day, with
    /// the grace moved on by the days since this device last swept.
    async fn pass(&self, day: usize) -> Pass {
        let days = day.saturating_sub(self.swept_on.swap(day, Ordering::SeqCst));
        // A day is longer than the longest backoff, 15 minutes.
        if days > 0 {
            self.press_sync();
        }
        self.conn(|conn| {
            conn.execute(
                "DELETE FROM vault_meta WHERE key LIKE 'blob_sweep_at:%'",
                [],
            )
            .unwrap();
            conn.execute(
                "UPDATE blob_gc_seen SET first_seen = first_seen - ?1",
                [days as i64 * 24 * 60 * 60],
            )
            .unwrap();
        });
        let pass = on!(self, |d| d.pass(&self.host).await);
        trace(format!(
            "  {} ({}) pass: {pass:?}",
            self.name,
            self.version()
        ));
        pass
    }

    /// What pressing Sync does first: every copy is tried again now, one
    /// in its backoff included.
    fn press_sync(&self) {
        for (path, _) in self.host.copies() {
            let target = silentsilo_store::StoreConfig::Folder { path }.target_id();
            self.conn(|conn| silentsilo_vfs::reset_target_backoff(conn, target).unwrap());
        }
    }

    /// A file's bytes: as the app shows a live file, and from its row for
    /// one in the trash, which the app does not open.
    async fn read(&self, id: Uuid) -> Result<Vec<u8>, String> {
        let row: (String, String, bool) = self.conn(|conn| {
            conn.query_row(
                "SELECT blob_id, blob_key, deleted_at IS NOT NULL FROM files WHERE id = ?1",
                [id.to_string()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .map_err(|e| e.to_string())
        })?;
        match row {
            (_, _, false) => on!(self, |d| d.read(&self.host, id).await),
            (blob, key, true) => {
                let blob = Uuid::parse_str(&blob).unwrap();
                on!(self, |d| d.open_blob(&self.host, blob, &key).await)
            }
        }
    }

    /// The update: the app on 1.6.1 locks, this build unlocks the same
    /// folder with the same key.
    fn update(&mut self) {
        let Kind::Old(old) = &self.kind else {
            return;
        };
        old.lock(&self.host);
        let vault_id = old.silo.id;
        self.kind = Kind::New(new::Dev::unlock(self.root.clone(), vault_id, &self.host));
        let version: String = self.conn(|conn| {
            conn.query_row(
                "SELECT value FROM vault_meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap()
        });
        assert_eq!(version, silentsilo_vfs::SCHEMA_VERSION.to_string());
    }

    /// Unlocks again after the lock a key replacement ends with.
    fn unlock(&mut self) {
        let vault_id = self.vault_id();
        self.kind = match &self.kind {
            Kind::Old(_) => Kind::Old(old::Dev::unlock(self.root.clone(), vault_id, &self.host)),
            Kind::New(_) => Kind::New(new::Dev::unlock(self.root.clone(), vault_id, &self.host)),
        };
    }

    /// Removes the silo from this device and joins it again with the key,
    /// on the same version.
    async fn rejoin(&mut self, working: &Path) {
        on!(self, |d| d.lock(&self.host));
        let root = self.dir.path().join(format!("rejoined-{}", Uuid::new_v4()));
        self.kind = match &self.kind {
            Kind::Old(_) => Kind::Old(
                old::Dev::join(root.clone(), working, &self.host)
                    .await
                    .unwrap(),
            ),
            Kind::New(_) => Kind::New(
                new::Dev::join(root.clone(), working, &self.host)
                    .await
                    .unwrap(),
            ),
        };
        self.root = root;
    }
}

/// Every folder with its id, for a failure to be read.
fn folder_ids(device: &Device) -> Vec<String> {
    device.conn(|conn| {
        conn.prepare(
            "SELECT path || ' ' || id || ' trashed=' || (deleted_at IS NOT NULL)
               FROM folders ORDER BY path",
        )
        .unwrap()
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
    })
}

fn live_folders(device: &Device) -> Vec<Uuid> {
    uuids(
        device,
        "SELECT id FROM folders WHERE deleted_at IS NULL AND path != '/Inbox'
          ORDER BY path COLLATE NOCASE",
    )
}

fn uuids(device: &Device, sql: &str) -> Vec<Uuid> {
    device.conn(|conn| {
        conn.prepare(sql)
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(|id| Uuid::parse_str(&id.unwrap()).unwrap())
            .collect()
    })
}

/// Every file row, trash included, with its content hash.
fn every_file(device: &Device) -> Vec<(Uuid, String)> {
    device.conn(|conn| {
        conn.prepare("SELECT id, content_hash FROM files ORDER BY id")
            .unwrap()
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })
            .unwrap()
            .map(|row| {
                let (id, hash) = row.unwrap();
                (
                    Uuid::parse_str(&id).unwrap(),
                    hash.expect("every file has a content hash"),
                )
            })
            .collect()
    })
}

fn live_files(device: &Device) -> Vec<Uuid> {
    uuids(
        device,
        "SELECT id FROM files WHERE deleted_at IS NULL ORDER BY id",
    )
}

fn passwords(device: &Device) -> Vec<serde_json::Value> {
    on!(device, |d| d.vfs(|v| v.list_passwords().unwrap()))
        .iter()
        .map(|raw| serde_json::from_str(raw).unwrap())
        .collect()
}

/// What a device shows, comparable across devices and versions.
fn picture(device: &Device) -> (BTreeSet<String>, BTreeSet<String>, BTreeSet<String>) {
    let (folders, files) = device.conn(|conn| {
        let folders = conn
            .prepare("SELECT path, deleted_at IS NOT NULL FROM folders")
            .unwrap()
            .query_map([], |r| {
                Ok(format!(
                    "{} trashed={}",
                    r.get::<_, String>(0)?,
                    r.get::<_, bool>(1)?
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let files = conn
            .prepare(
                "SELECT d.path, f.name, f.blob_id, f.content_hash,
                        f.deleted_at IS NOT NULL, d.deleted_at IS NOT NULL
                   FROM files f JOIN folders d ON d.id = f.folder_id",
            )
            .unwrap()
            .query_map([], |r| {
                Ok(format!(
                    "{}/{} blob={} hash={:?} trashed={} folder_trashed={}",
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, bool>(4)?,
                    r.get::<_, bool>(5)?
                ))
            })
            .unwrap()
            .map(Result::unwrap)
            .collect();
        (folders, files)
    });
    let passwords = on!(device, |d| d.vfs(|v| v.list_passwords().unwrap()))
        .into_iter()
        .collect();
    (folders, files, passwords)
}

/// Every object in a folder copy, by path, with a hash of its bytes.
fn storage_state(root: &Path) -> BTreeMap<String, [u8; 32]> {
    fn walk(dir: &Path, root: &Path, out: &mut BTreeMap<String, [u8; 32]>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, root, out);
            } else {
                let key = path
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                out.insert(
                    key,
                    *blake3::hash(&std::fs::read(&path).unwrap()).as_bytes(),
                );
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

// ── What was added, for judging what may be gone ────────────────────

#[derive(Default)]
struct Ledger {
    /// Content added, by hash, with its bytes.
    added: HashMap<String, Vec<u8>>,
    /// Content a later add over the same name replaced in place.
    replaced: HashSet<String>,
    /// Content in the trash of a device when that device emptied it.
    purged: HashSet<String>,
    /// Content written to a file a purge named.
    named: HashSet<String>,
    /// Attachments added, by blob, with their bytes.
    attachments: HashMap<Uuid, Vec<u8>>,
}

impl Ledger {
    fn may_be_gone(&self, hash: &str) -> bool {
        self.replaced.contains(hash) || self.purged.contains(hash) || self.named.contains(hash)
    }

    /// Notes the content of every file a purge named, from the records a
    /// device on this build still holds. Called before every compaction
    /// prunes them.
    fn learn_purges(&mut self, device: &Device) {
        use silentsilo_vfs::{OpBody, VaultOp};
        let records = device.conn(|conn| silentsilo_vfs::all_ops(conn).unwrap());
        let named: HashSet<Uuid> = records
            .iter()
            .filter_map(|r| match &r.op {
                OpBody::Known(VaultOp::Purge { file_ids, .. }) => Some(file_ids.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        for record in &records {
            if let OpBody::Known(
                VaultOp::AddFile {
                    id, content_hash, ..
                }
                | VaultOp::ReplaceFileContent {
                    id, content_hash, ..
                },
            ) = &record.op
                && named.contains(id)
            {
                self.named.insert(content_hash.clone());
            }
        }
    }
}

// ── A fleet ─────────────────────────────────────────────────────────

/// One device of a fleet: its name, whether it stays on 1.6.1, and whether
/// its working copy is listed before the never-delete one.
struct Spec {
    name: &'static str,
    stays_on_1_6_1: bool,
    working_first: bool,
}

struct Fleet {
    _storage: (tempfile::TempDir, tempfile::TempDir),
    working: PathBuf,
    archive: PathBuf,
    devices: Vec<Device>,
    /// Devices left out of passes and checks: not kept in a key replacement
    /// and not rejoined yet.
    out: HashSet<usize>,
    /// The step of the everyday script, read as the day by the sweeps.
    day: usize,
    /// A key replacement happened, so the never-delete copy is stale.
    replaced: bool,
    /// Copies unplugged for now, by label.
    down: HashSet<&'static str>,
    /// Devices whose log a rebuild, a rejoin or their own compaction cut
    /// short, which 1.6.1 cannot compact from.
    short_log: Mutex<HashSet<usize>>,
    ledger: Ledger,
}

impl Fleet {
    /// The silo made on 1.6.1 by the first device, joined with the key by
    /// the others, then the ones that do not stay updated in place.
    async fn new(specs: &[Spec]) -> Self {
        let working = tempfile::tempdir().unwrap();
        let archive = tempfile::tempdir().unwrap();
        let mut fleet = Self {
            working: working.path().to_path_buf(),
            archive: archive.path().to_path_buf(),
            _storage: (working, archive),
            devices: Vec::new(),
            out: HashSet::new(),
            day: 0,
            replaced: false,
            down: HashSet::new(),
            short_log: Mutex::new(HashSet::new()),
            ledger: Ledger::default(),
        };
        for (i, spec) in specs.iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("silo");
            let (w, a) = (
                (fleet.working.clone(), true),
                (fleet.archive.clone(), false),
            );
            let host = FleetHost::new(if spec.working_first {
                vec![w, a]
            } else {
                vec![a, w]
            });
            let dev = if i == 0 {
                old::Dev::create(root.clone(), &host)
            } else {
                old::Dev::join(root.clone(), &fleet.working, &host)
                    .await
                    .expect("joins with the key on 1.6.1")
            };
            fleet.devices.push(Device {
                name: spec.name,
                dir,
                root,
                host,
                kind: Kind::Old(dev),
                swept_on: AtomicUsize::new(0),
            });
            fleet.settle("while joining").await;
        }
        for (d, spec) in fleet.devices.iter_mut().zip(specs) {
            if !spec.stays_on_1_6_1 {
                d.update();
            }
        }
        fleet.settle("after the update").await;
        fleet
    }

    fn active(&self) -> impl Iterator<Item = (usize, &Device)> {
        self.devices
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.out.contains(i))
    }

    async fn pass(&self, i: usize, context: &str) -> Pass {
        let pass = self.devices[i].pass(self.day).await;
        self.judge(i, pass, context).await
    }

    /// Asserts a pass clean, with one allowance. After a key replacement
    /// 1.6.1 fails on the never-delete copy for good and never sees every
    /// copy again, so its received mark stops and any later compaction sends
    /// it to rebuild. It rebuilds here on its own version, as its user
    /// would, and the pass is run again.
    async fn judge(&self, i: usize, pass: Pass, context: &str) -> Pass {
        let d = &self.devices[i];
        let pass = if pass.needs_rebuild && d.is_old() && self.replaced {
            trace(format!("  {} (1.6.1) rebuilds after a replacement", d.name));
            on!(d, |x| x.rebuild(&d.host).await);
            self.short_log.lock().unwrap().insert(i);
            d.pass(self.day).await
        } else {
            pass
        };
        pass.assert_clean(
            &format!("{context}: {} ({})", d.name, d.version()),
            self.replaced,
            &self.down,
        );
        pass
    }

    /// Syncs until a whole round moves nothing. Settling is time passing, so
    /// every backoff is over first: a copy left waiting would read as quiet.
    async fn settle(&self, context: &str) {
        for _ in 0..12 {
            let mut moved = 0;
            for (_, d) in self.active() {
                d.press_sync();
            }
            for (i, _) in self.active() {
                moved += self.pass(i, context).await.moved;
            }
            if moved == 0 {
                return;
            }
        }
        panic!("{context}: the devices never stopped exchanging changes");
    }

    /// Every device shows the same thing, every file and attachment opens
    /// with its bytes, and nothing added is gone that may not be.
    async fn check(&mut self, context: &str) {
        let active: Vec<usize> = self.active().map(|(i, _)| i).collect();
        let reference = active
            .iter()
            .copied()
            .find(|i| !self.devices[*i].is_old())
            .expect("a device on this build");
        let expected = picture(&self.devices[reference]);
        for &i in &active {
            let d = &self.devices[i];
            let got = picture(d);
            for (what, a, b) in [
                ("folders", &expected.0, &got.0),
                ("files", &expected.1, &got.1),
                ("passwords", &expected.2, &got.2),
            ] {
                assert!(
                    a == b,
                    "{context}: {what} differ on {} ({})\n  only on {}: {:#?}\n  only there: {:#?}\n  folders on {}: {:#?}\n  folders there: {:#?}",
                    d.name,
                    d.version(),
                    self.devices[reference].name,
                    a.difference(b).collect::<Vec<_>>(),
                    b.difference(a).collect::<Vec<_>>(),
                    self.devices[reference].name,
                    folder_ids(&self.devices[reference]),
                    folder_ids(d),
                );
            }
        }
        let clashes: Vec<String> = self.devices[reference].conn(|conn| {
            conn.prepare(
                "SELECT lower(name) FROM files WHERE deleted_at IS NULL
                  GROUP BY folder_id, lower(name) HAVING COUNT(*) > 1
                 UNION ALL
                 SELECT lower(name) FROM folders WHERE deleted_at IS NULL AND parent_id IS NOT NULL
                  GROUP BY parent_id, lower(name) HAVING COUNT(*) > 1",
            )
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
        });
        assert!(clashes.is_empty(), "{context}: names clash: {clashes:?}");

        let mut files = 0;
        let mut attachments = 0;
        for &i in &active {
            let d = &self.devices[i];
            for (id, hash) in every_file(d) {
                let expected = self
                    .ledger
                    .added
                    .get(&hash)
                    .unwrap_or_else(|| panic!("{context}: {id} holds content nobody added"));
                let bytes = d.read(id).await.unwrap_or_else(|e| {
                    panic!(
                        "{context}: file {id} does not open on {} ({}): {e}",
                        d.name,
                        d.version()
                    )
                });
                assert_eq!(
                    &bytes, expected,
                    "{context}: file {id} changed on {}",
                    d.name
                );
                files += 1;
            }
            for entry in passwords(d) {
                let Some(list) = entry.get("attachments").and_then(|a| a.as_array()) else {
                    continue;
                };
                for attachment in list {
                    let blob = Uuid::parse_str(attachment["blob_id"].as_str().unwrap()).unwrap();
                    let key = attachment["blob_key"].as_str().unwrap();
                    let bytes =
                        on!(d, |x| x.open_blob(&d.host, blob, key).await).unwrap_or_else(|e| {
                            panic!(
                                "{context}: attachment {blob} does not open on {} ({}): {e}",
                                d.name,
                                d.version()
                            )
                        });
                    assert_eq!(
                        Some(&bytes),
                        self.ledger.attachments.get(&blob),
                        "{context}: attachment {blob} changed on {}",
                        d.name
                    );
                    attachments += 1;
                }
            }
        }

        self.ledger.learn_purges(&self.devices[reference]);
        let kept: HashSet<String> = every_file(&self.devices[reference])
            .into_iter()
            .map(|(_, hash)| hash)
            .collect();
        let lost: Vec<&String> = self
            .ledger
            .added
            .keys()
            .filter(|hash| !kept.contains(*hash) && !self.ledger.may_be_gone(hash))
            .collect();
        assert!(lost.is_empty(), "{context}: content lost: {lost:?}");
        println!(
            "{context}: {} devices agree; {files} file reads and {attachments} attachment reads matched",
            active.len()
        );
    }

    fn index(&self, name: &str) -> usize {
        self.devices.iter().position(|d| d.name == name).unwrap()
    }

    // ── What each device can do ─────────────────────────────────────

    /// One change on device `i`, chosen by `rng`.
    fn act(&mut self, i: usize, rng: &mut Rng) {
        let step = self.day;
        let d = &self.devices[i];
        let choice = rng.below(18);
        trace(format!(
            "step {step}: {} ({}) action {choice}",
            d.name,
            d.version()
        ));
        match choice {
            0..=2 => {
                if let Some(parent) = rng.pick(&live_folders(d)) {
                    let name = rng.pick(FOLDER_NAMES).unwrap();
                    let r = on!(d, |x| x.vfs(|v| v
                        .create_folder(parent, name)
                        .map(|f| f.id)
                        .map_err(|e| e.to_string())));
                    trace(format!("  folder {name}: {r:?}"));
                }
            }
            3..=6 => {
                let Some(folder) = rng.pick(&live_folders(d)) else {
                    return;
                };
                let name = rng.pick(FILE_NAMES).unwrap();
                let bytes = rng.bytes();
                self.import(i, folder, name, bytes);
            }
            7 => {
                if let Some(id) = rng.pick(&live_files(d)) {
                    let name = rng.pick(FILE_NAMES).unwrap();
                    let r = on!(d, |x| x.vfs(|v| v
                        .rename_file(id, name)
                        .map(|_| ())
                        .map_err(|e| e.to_string())));
                    trace(format!("  rename file {id} to {name}: {r:?}"));
                } else if let Some(id) = rng.pick(&live_folders(d)) {
                    let name = rng.pick(FOLDER_NAMES).unwrap();
                    let r = on!(d, |x| x.vfs(|v| v
                        .rename_folder(id, name)
                        .map(|_| ())
                        .map_err(|e| e.to_string())));
                    trace(format!("  rename folder {id} to {name}: {r:?}"));
                }
            }
            8 => {
                if let (Some(id), Some(to)) = (rng.pick(&live_files(d)), rng.pick(&live_folders(d)))
                {
                    let r = on!(d, |x| x.vfs(|v| v
                        .move_file(id, to)
                        .map(|f| f.id)
                        .map_err(|e| e.to_string())));
                    trace(format!("  move file {id} to {to}: {r:?}"));
                }
            }
            9 => {
                let folders = live_folders(d);
                if let (Some(id), Some(to)) = (rng.pick(&folders), rng.pick(&folders)) {
                    let r = on!(d, |x| x.vfs(|v| v
                        .move_folder(id, to)
                        .map(|f| f.id)
                        .map_err(|e| e.to_string())));
                    trace(format!("  move folder {id} to {to}: {r:?}"));
                }
            }
            10 => {
                if let Some(id) = rng.pick(&live_files(d)) {
                    let r = on!(d, |x| x
                        .vfs(|v| v.trash_file(id).map_err(|e| e.to_string())));
                    trace(format!("  trash file {id}: {r:?}"));
                }
            }
            11 => {
                if let Some(id) = rng.pick(&live_folders(d)) {
                    let r = on!(d, |x| x
                        .vfs(|v| v.trash_folder(id).map_err(|e| e.to_string())));
                    trace(format!("  trash folder {id}: {r:?}"));
                }
            }
            12 => {
                let trashed = uuids(
                    d,
                    "SELECT id FROM files WHERE deleted_at IS NOT NULL ORDER BY id",
                );
                if let Some(id) = rng.pick(&trashed) {
                    let r = on!(d, |x| x
                        .vfs(|v| v.restore_file(id).map(|_| ()).map_err(|e| e.to_string())));
                    trace(format!("  restore file {id}: {r:?}"));
                }
            }
            13 => {
                if rng.below(3) == 0 {
                    self.empty_trash(i);
                }
            }
            14..=15 => {
                let id = Uuid::from_u128(rng.pick(PASSWORD_IDS).unwrap());
                if rng.below(4) == 0 {
                    let _ = on!(d, |x| x
                        .vfs(|v| v.delete_password(id).map_err(|e| e.to_string())));
                } else {
                    let password = format!("pw-{}", rng.next());
                    self.upsert(i, id, &password);
                }
            }
            _ => {
                let bytes = rng.bytes();
                self.attach(i, bytes);
            }
        }
    }

    fn import(&mut self, i: usize, folder: Uuid, name: &str, bytes: Vec<u8>) -> Option<Uuid> {
        let d = &self.devices[i];
        // Over a name already in the folder the content is replaced.
        let replaced: Vec<String> = d.conn(|conn| {
            conn.prepare(
                "SELECT content_hash FROM files
                  WHERE folder_id = ?1 AND lower(name) = lower(?2) AND deleted_at IS NULL",
            )
            .unwrap()
            .query_map([folder.to_string(), name.to_string()], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
        });
        self.ledger.replaced.extend(replaced);
        let (id, hash) = on!(d, |x| x.import(folder, name, &bytes))?;
        trace(format!("  added {hash} as {name} id {id}"));
        self.ledger.added.insert(hash, bytes);
        Some(id)
    }

    fn empty_trash(&mut self, i: usize) {
        let d = &self.devices[i];
        let in_trash: Vec<String> = d.conn(|conn| {
            conn.prepare(
                "SELECT f.content_hash FROM files f JOIN folders d ON d.id = f.folder_id
                  WHERE (f.deleted_at IS NOT NULL OR d.deleted_at IS NOT NULL)
                    AND f.content_hash IS NOT NULL",
            )
            .unwrap()
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
        });
        self.ledger.purged.extend(in_trash);
        let orphaned = on!(d, |x| x.vfs(|v| v
            .empty_trash()
            .map(|(_, blobs)| blobs)
            .map_err(|e| e.to_string())));
        trace(format!("  emptied trash: {orphaned:?}"));
        // As the apps do: the local copy goes, storage keeps its own until
        // the sweep.
        for blob in orphaned.unwrap_or_default() {
            on!(d, |x| x.uncache(blob));
        }
    }

    fn upsert(&self, i: usize, id: Uuid, password: &str) {
        let entry = serde_json::json!({
            "id": id.to_string(),
            "service": "site",
            "username": "alex",
            "password": password,
            "url": "", "notes": "", "category": "General",
            "created_at": 0, "updated_at": self.day, "type": "login",
        });
        let data = entry.to_string();
        let d = &self.devices[i];
        on!(d, |x| x.vfs(|v| v.upsert_password(id, &data).unwrap()));
    }

    /// Adds an attachment to the attachments entry as this device shows it.
    fn attach(&mut self, i: usize, bytes: Vec<u8>) {
        let id = Uuid::from_u128(ATTACHED);
        let d = &self.devices[i];
        let mut list: Vec<serde_json::Value> = passwords(d)
            .into_iter()
            .find(|e| e["id"] == id.to_string())
            .and_then(|e| e.get("attachments").and_then(|a| a.as_array()).cloned())
            .unwrap_or_default();
        let attachment = on!(d, |x| x.attach(&bytes));
        let blob = Uuid::parse_str(attachment["blob_id"].as_str().unwrap()).unwrap();
        trace(format!("  attached {blob}"));
        self.ledger.attachments.insert(blob, bytes);
        list.push(attachment);
        let entry = serde_json::json!({
            "id": id.to_string(),
            "service": "scanner",
            "username": "alex",
            "password": "pw",
            "url": "", "notes": "", "category": "General",
            "created_at": 0, "updated_at": self.day, "type": "login",
            "attachments": list,
        });
        let data = entry.to_string();
        on!(d, |x| x.vfs(|v| v.upsert_password(id, &data).unwrap()));
    }

    /// Passes in a seeded order, two of them at once now and then.
    async fn passes(&self, rng: &mut Rng, context: &str) {
        let mut order: Vec<usize> = self.active().map(|(i, _)| i).collect();
        for k in (1..order.len()).rev() {
            order.swap(k, rng.below(k + 1));
        }
        let mut rest = &order[..];
        while !rest.is_empty() {
            if rest.len() >= 2 && rng.below(2) == 0 {
                let (a, b) = (&self.devices[rest[0]], &self.devices[rest[1]]);
                let (x, y) = tokio::join!(a.pass(self.day), b.pass(self.day));
                self.judge(rest[0], x, context).await;
                self.judge(rest[1], y, context).await;
                rest = &rest[2..];
            } else {
                self.pass(rest[0], context).await;
                rest = &rest[1..];
            }
        }
    }
}

// ── The scenarios ───────────────────────────────────────────────────

/// Changes on every device, both versions, with interleaved passes.
async fn everyday_use(fleet: &mut Fleet, rng: &mut Rng, rounds: usize, actors: &[usize]) {
    for _ in 0..rounds {
        fleet.day += 1;
        for &i in actors {
            for _ in 0..1 + rng.below(2) {
                fleet.act(i, rng);
            }
        }
        fleet.passes(rng, &format!("day {}", fleet.day)).await;
    }
    fleet.settle("after everyday use").await;
    fleet.check("after everyday use").await;
}

/// A device that stopped syncing while another compacted past it: it is
/// told to rebuild before it writes anything, rebuilds on its own version
/// with its offline work kept, and nothing is lost anywhere.
async fn compaction_past(fleet: &mut Fleet, rng: &mut Rng, compactor: usize, behind: usize) {
    let context = format!(
        "compaction by {} ({}) past {} ({})",
        fleet.devices[compactor].name,
        fleet.devices[compactor].version(),
        fleet.devices[behind].name,
        fleet.devices[behind].version()
    );
    let reference = fleet.index("updated A");
    fleet.ledger.learn_purges(&fleet.devices[reference]);
    fleet.out.insert(behind);
    let busy: Vec<usize> = fleet
        .active()
        .map(|(i, _)| i)
        .filter(|i| fleet.devices[*i].name != "1.6.1 probe")
        .collect();
    for _ in 0..8 {
        for &i in &busy {
            fleet.act(i, rng);
            let password = format!("pw-{}", rng.next());
            fleet.upsert(i, Uuid::from_u128(1), &password);
        }
        fleet.passes(rng, &context).await;
    }
    // Offline work on the device left behind.
    let root = silentsilo_vfs::root_folder_id_for(fleet.devices[behind].vault_id());
    let offline = format!("offline on {}.txt", fleet.devices[behind].name);
    let offline_file = fleet
        .import(behind, root, &offline, offline.as_bytes().to_vec())
        .unwrap();
    fleet.upsert(behind, Uuid::from_u128(2), "set offline");

    // The policy compacts only what is 30 days old, so a month passes first:
    // compacting at once put the horizon above what a device held back by a
    // backoff of minutes had received, which no real compaction can do.
    fleet.day += 30;
    fleet.settle(&context).await;
    fleet.ledger.learn_purges(&fleet.devices[reference]);
    let horizon = on!(fleet.devices[compactor], |d| d
        .compact(&fleet.devices[compactor].host)
        .await);
    println!("{context}: compacted at {horizon}");
    fleet.settle(&context).await;

    let before = (storage_state(&fleet.working), storage_state(&fleet.archive));
    let stale = fleet.devices[behind].pass(fleet.day).await;
    assert!(stale.needs_rebuild, "{context}: {stale:?}");
    assert!(
        before == (storage_state(&fleet.working), storage_state(&fleet.archive)),
        "{context}: the device below the horizon wrote to storage"
    );
    let kept = on!(fleet.devices[behind], |d| d
        .rebuild(&fleet.devices[behind].host)
        .await);
    assert!(kept >= 2, "{context}: offline work not kept ({kept})");
    fleet.out.remove(&behind);
    fleet.short_log.lock().unwrap().extend([compactor, behind]);
    fleet.settle(&context).await;
    fleet.check(&context).await;
    for (i, d) in fleet.active() {
        assert!(
            live_files(d).contains(&offline_file),
            "{context}: the offline file is missing on {i}"
        );
    }
}

/// An item sent by one version's phone, imported by the other version.
async fn inbox_across(fleet: &mut Fleet, sender_on_1_6_1: bool, importer: usize) {
    let context = format!(
        "inbox from a {} phone into {} ({})",
        if sender_on_1_6_1 {
            "1.6.1"
        } else {
            "this build's"
        },
        fleet.devices[importer].name,
        fleet.devices[importer].version()
    );
    let registrar = &fleet.devices[importer];
    let (vault_id, kek) = (registrar.vault_id(), on!(registrar, |d| d.kek()));
    let item = Uuid::now_v7();
    let expected = format!("a photo for {context}").into_bytes();
    // Sent twice, as by a phone retrying: 1.6.1 sends the item again over
    // the first, this build leaves a sent item alone.
    if sender_on_1_6_1 {
        let phone = old::Phone::register(&fleet.working, vault_id, kek).await;
        phone
            .send(&fleet.working, item, "IMG_0001.jpg", b"first try")
            .await;
        phone
            .send(&fleet.working, item, "IMG_0001.jpg", &expected)
            .await;
    } else {
        let phone = new::Phone::register(&fleet.working, vault_id, kek).await;
        phone
            .send(&fleet.working, item, "IMG_0001.jpg", &expected)
            .await;
        phone
            .send(&fleet.working, item, "IMG_0001.jpg", b"second try")
            .await;
    }

    let pass = fleet.pass(importer, &context).await;
    assert_eq!(pass.inbox_imported, 1, "{context}: {pass:?}");
    let hash: String = fleet.devices[importer].conn(|conn| {
        conn.query_row(
            "SELECT content_hash FROM files WHERE id = ?1",
            [item.to_string()],
            |r| r.get(0),
        )
        .unwrap()
    });
    fleet.ledger.added.insert(hash, expected.clone());
    // 1.6.1 imports an item another device is importing into a folder of
    // its own when the import folder is gone (see the top of this file), so
    // the importer finishes it before any 1.6.1 device looks.
    if fleet.active().any(|(_, d)| d.is_old()) {
        fleet.pass(importer, &context).await;
        fleet.pass(importer, &context).await;
    }
    fleet.settle(&context).await;
    for (_, d) in fleet.active() {
        assert_eq!(
            d.read(item).await.unwrap(),
            expected,
            "{context}: on {}",
            d.name
        );
    }
    let envelope = fleet.working.join(format!("inbox/items/{item}.env"));
    assert!(
        !envelope.exists(),
        "{context}: the item never left the inbox"
    );
    fleet.check(&context).await;
}

/// A key replacement by `replacer`. Every other device of `not_kept` was
/// not kept: it is told to rejoin before it writes anything, then rejoins
/// with the key on its own version and reads everything.
async fn key_replaced(fleet: &mut Fleet, replacer: usize, not_kept: &[usize]) {
    let context = format!(
        "key replaced by {} ({})",
        fleet.devices[replacer].name,
        fleet.devices[replacer].version()
    );
    fleet.settle(&context).await;
    // Something each of them would push.
    for &i in not_kept {
        fleet.upsert(i, Uuid::from_u128(3), &format!("not pushed from {i}"));
    }
    {
        let d = &fleet.devices[replacer];
        on!(d, |x| x.replace_key(&d.host).await);
    }
    fleet.devices[replacer].unlock();
    fleet.replaced = true;
    for &i in not_kept {
        fleet.out.insert(i);
    }
    fleet.pass(replacer, &context).await;

    for &i in not_kept {
        let d = &fleet.devices[i];
        for _ in 0..2 {
            let before = (storage_state(&fleet.working), storage_state(&fleet.archive));
            let pass = d.pass(fleet.day).await;
            assert!(
                pass.needs_rejoin && !pass.key_material_replaced,
                "{context}: {} ({}) was not told to rejoin: {pass:?}",
                d.name,
                d.version()
            );
            assert!(
                before == (storage_state(&fleet.working), storage_state(&fleet.archive)),
                "{context}: {} ({}) wrote to storage after the key moved on",
                d.name,
                d.version()
            );
        }
    }
    for &i in not_kept {
        let working = fleet.working.clone();
        fleet.devices[i].rejoin(&working).await;
        fleet.devices[i].swept_on.store(fleet.day, Ordering::SeqCst);
        fleet.out.remove(&i);
        fleet.short_log.lock().unwrap().insert(i);
    }
    // Several rounds: a device sent back to rejoin would show it here. Sync
    // pressed on each, so the never-delete copy is read, not waited out.
    fleet.settle(&context).await;
    let active: Vec<usize> = fleet.active().map(|(i, _)| i).collect();
    for _ in 0..2 {
        for &i in &active {
            fleet.devices[i].press_sync();
            let pass = fleet.pass(i, &context).await;
            assert!(
                pass.failed.iter().any(|(label, _)| label == "never-delete"),
                "{context}: the never-delete copy was not tried: {pass:?}"
            );
        }
    }
    fleet.check(&context).await;
}

/// A 1.6.1 device not kept in a key replacement made here, with its
/// never-delete copy listed first: 1.6.1 lets the first copy that answers
/// decide, and that copy still opens under the old key. Checked: nothing
/// reaches the working copy. Printed: what it does to the rest.
async fn probe_stale_copy_first(fleet: &mut Fleet, probe: usize) {
    let context = "a retired 1.6.1 device with the never-delete copy first";
    let working_before = storage_state(&fleet.working);
    let archive_before = storage_state(&fleet.archive);
    fleet.upsert(probe, Uuid::from_u128(4), "from a retired device");
    fleet.devices[probe].press_sync();
    let pass = fleet.devices[probe].pass(fleet.day).await;
    println!(
        "{context}: needs_rejoin={} failed={:?} unreadable={} held_back={}",
        pass.needs_rejoin,
        pass.failed,
        pass.unreadable.len(),
        pass.held_back
    );
    let working_after = storage_state(&fleet.working);
    assert!(
        working_before == working_after,
        "{context}: it wrote to the working copy"
    );
    let archive_after = storage_state(&fleet.archive);
    let written: Vec<&String> = archive_after
        .iter()
        .filter(|(k, v)| archive_before.get(*k) != Some(v))
        .map(|(k, _)| k)
        .collect();
    println!("{context}: it wrote to the never-delete copy: {written:?}");

    // What the devices on the new key make of it.
    fleet.out.insert(probe);
    let first = fleet.index("updated A");
    fleet.upsert(first, Uuid::from_u128(1), "after the retired device wrote");
    for (i, d) in fleet.active() {
        d.press_sync();
        let pass = d.pass(fleet.day).await;
        println!("{context}: then {i} {} ({}): {pass:?}", d.name, d.version());
    }
}

fn seed() -> u64 {
    std::env::var("SILENTSILO_MIXED_SEED")
        .map(|s| s.parse().expect("a number"))
        .unwrap_or(1)
}

#[tokio::test]
async fn a_1_6_1_device_beside_updated_ones_loses_nothing_and_breaks_nothing() {
    work_dirs_for_this_test();
    let mut rng = Rng::new(seed());
    let mut fleet = Fleet::new(&[
        Spec {
            name: "1.6.1",
            stays_on_1_6_1: true,
            working_first: true,
        },
        Spec {
            name: "1.6.1 probe",
            stays_on_1_6_1: true,
            working_first: false,
        },
        Spec {
            name: "updated A",
            stays_on_1_6_1: false,
            working_first: true,
        },
        Spec {
            name: "updated B",
            stays_on_1_6_1: false,
            working_first: false,
        },
    ])
    .await;
    let (stays, probe, a, b) = (0, 1, 2, 3);

    everyday_use(&mut fleet, &mut rng, 32, &[stays, a, b]).await;

    // In this order each 1.6.1 compactor still holds its whole log: 1.6.1
    // publishes a short snapshot from a device that was rebuilt before (see
    // above). The third one is that case on this build: `b` was rebuilt by
    // the first step and compacts again, and nothing may be lost.
    compaction_past(&mut fleet, &mut rng, stays, b).await;
    compaction_past(&mut fleet, &mut rng, a, stays).await;
    compaction_past(&mut fleet, &mut rng, b, a).await;

    inbox_across(&mut fleet, true, a).await;
    inbox_across(&mut fleet, false, stays).await;

    // The probe is not kept either; it stays out until the end.
    fleet.out.insert(probe);
    key_replaced(&mut fleet, a, &[stays, b]).await;
    everyday_use(&mut fleet, &mut rng, 5, &[stays, a, b]).await;

    probe_stale_copy_first(&mut fleet, probe).await;
}

#[tokio::test]
async fn a_key_replaced_on_1_6_1_sends_updated_devices_to_rejoin_once() {
    work_dirs_for_this_test();
    let mut rng = Rng::new(seed() + 1000);
    let mut fleet = Fleet::new(&[
        Spec {
            name: "1.6.1",
            stays_on_1_6_1: true,
            working_first: true,
        },
        Spec {
            name: "updated A",
            stays_on_1_6_1: false,
            working_first: true,
        },
        Spec {
            name: "updated B",
            stays_on_1_6_1: false,
            working_first: false,
        },
    ])
    .await;
    let (stays, a, b) = (0, 1, 2);
    everyday_use(&mut fleet, &mut rng, 10, &[stays, a, b]).await;
    key_replaced(&mut fleet, stays, &[a, b]).await;
    everyday_use(&mut fleet, &mut rng, 5, &[stays, a, b]).await;
}

/// Where both versions keep working copies and blob bookkeeping, pointed
/// into `target/`: updating in place needs both versions to find the same
/// cache. Set once, before either test starts anything that reads it.
fn work_dirs_for_this_test() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/test-work-mixed-1-6-1");
        std::fs::create_dir_all(&base).unwrap();
        let base = base.canonicalize().unwrap();
        let work = if cfg!(windows) {
            base.join("SilentSilo").join("work")
        } else {
            base.join("silentsilo").join("work")
        };
        // SAFETY: both tests call this first, and `call_once` holds the
        // other back until the variables are set.
        unsafe {
            std::env::set_var("LOCALAPPDATA", &base);
            std::env::set_var("XDG_CACHE_HOME", &base);
            std::env::set_var("SILENTSILO_TEST_WORK_BASE", &work);
        }
    });
}

// ── Random lifecycles ───────────────────────────────────────────────

/// One thing that happens to the fleet, with the seed of its own choices.
/// Whom it happens to is picked when it runs, from the fleet as it is then,
/// so a plan with events left out still means something.
#[derive(Debug, Clone, Copy)]
enum Event {
    Everyday { seed: u64, rounds: usize },
    Compaction { seed: u64 },
    Inbox { seed: u64 },
    KeyReplaced { seed: u64 },
    LockUnlock { seed: u64 },
    Update { seed: u64 },
    Offline { seed: u64, rounds: usize },
    StorageDown { seed: u64, rounds: usize },
    JoinNew { seed: u64 },
}

/// At most this many devices, new ones joining included.
const MAX_DEVICES: usize = 6;

fn plan(seed: u64, events: usize) -> Vec<Event> {
    let mut rng = Rng::new(seed);
    (0..events)
        .map(|_| {
            let seed = rng.next();
            match rng.below(100) {
                0..=27 => Event::Everyday {
                    seed,
                    rounds: 1 + rng.below(4),
                },
                28..=42 => Event::Compaction { seed },
                43..=49 => Event::Inbox { seed },
                50..=56 => Event::KeyReplaced { seed },
                57..=66 => Event::LockUnlock { seed },
                67..=70 => Event::Update { seed },
                // Past the 30-day grace now and then.
                71..=83 => Event::Offline {
                    seed,
                    rounds: 3 + rng.below(38),
                },
                84..=93 => Event::StorageDown {
                    seed,
                    rounds: 1 + rng.below(4),
                },
                _ => Event::JoinNew { seed },
            }
        })
        .collect()
}

impl Fleet {
    fn every(&self) -> Vec<usize> {
        self.active().map(|(i, _)| i).collect()
    }

    async fn happen(&mut self, event: Event) {
        match event {
            Event::Everyday { seed, rounds } => {
                let actors = self.every();
                everyday_use(self, &mut Rng::new(seed), rounds, &actors).await;
            }
            Event::Compaction { seed } => {
                let mut rng = Rng::new(seed);
                // 1.6.1 publishes a short snapshot from a cut log (see the
                // top of this file), which only updating fixes.
                let can: Vec<usize> = self
                    .every()
                    .into_iter()
                    .filter(|i| {
                        !self.devices[*i].is_old() || !self.short_log.lock().unwrap().contains(i)
                    })
                    .collect();
                let Some(compactor) = rng.pick(&can) else {
                    return;
                };
                let others: Vec<usize> = self
                    .every()
                    .into_iter()
                    .filter(|i| *i != compactor)
                    .collect();
                let behind = rng.pick(&others).unwrap();
                compaction_past(self, &mut rng, compactor, behind).await;
            }
            Event::Inbox { seed } => {
                let mut rng = Rng::new(seed);
                let importer = rng.pick(&self.every()).unwrap();
                inbox_across(self, rng.below(2) == 0, importer).await;
            }
            Event::KeyReplaced { seed } => {
                // Every device is updated first, as the release notes ask:
                // 1.6.1 after a replacement fails on the never-delete copy
                // for good, and what that does to its rebuilds is pinned by
                // `a_1_6_1_rebuild_beside_a_dead_copy_writes_old_history_again`.
                for i in self.every() {
                    if self.devices[i].is_old() {
                        self.devices[i].update();
                    }
                }
                self.settle("updated before a key replacement").await;
                let mut rng = Rng::new(seed);
                let replacer = rng.pick(&self.every()).unwrap();
                let rest: Vec<usize> = self
                    .every()
                    .into_iter()
                    .filter(|i| *i != replacer)
                    .collect();
                key_replaced(self, replacer, &rest).await;
                self.short_log.lock().unwrap().insert(replacer);
            }
            Event::LockUnlock { seed } => {
                let mut rng = Rng::new(seed);
                let i = rng.pick(&self.every()).unwrap();
                // A change not synced yet, which the lock has to keep.
                self.act(i, &mut rng);
                let context = format!("{} locked and unlocked", self.devices[i].name);
                {
                    let d = &self.devices[i];
                    on!(d, |x| x.lock(&d.host));
                }
                self.devices[i].unlock();
                self.settle(&context).await;
                self.check(&context).await;
            }
            Event::Update { seed } => {
                let old: Vec<usize> = self
                    .every()
                    .into_iter()
                    .filter(|i| self.devices[*i].is_old())
                    .collect();
                let Some(i) = Rng::new(seed).pick(&old) else {
                    return;
                };
                let context = format!("{} updated", self.devices[i].name);
                self.devices[i].update();
                self.settle(&context).await;
                self.check(&context).await;
            }
            Event::Offline { seed, rounds } => {
                let mut rng = Rng::new(seed);
                let away = rng.pick(&self.every()).unwrap();
                offline_for(self, &mut rng, away, rounds).await;
            }
            Event::StorageDown { seed, rounds } => {
                let mut rng = Rng::new(seed);
                let working = rng.below(2) == 0;
                storage_down(self, &mut rng, working, rounds).await;
            }
            Event::JoinNew { seed } => {
                if self.devices.len() < MAX_DEVICES {
                    join_new(self, &mut Rng::new(seed)).await;
                }
            }
        }
    }
}

/// A device that does not sync for `rounds` days while it and the others
/// go on working, then comes back.
async fn offline_for(fleet: &mut Fleet, rng: &mut Rng, away: usize, rounds: usize) {
    let context = format!(
        "{} ({}) offline for {rounds} days",
        fleet.devices[away].name,
        fleet.devices[away].version()
    );
    fleet.out.insert(away);
    let everyone: Vec<usize> = (0..fleet.devices.len()).collect();
    for _ in 0..rounds {
        fleet.day += 1;
        for &i in &everyone {
            if rng.below(2) == 0 {
                fleet.act(i, rng);
            }
        }
        fleet.passes(rng, &context).await;
    }
    fleet.out.remove(&away);
    fleet.settle(&context).await;
    fleet.check(&context).await;
}

/// A copy unplugged for `rounds` days while every device goes on working.
/// Devices on 1.6.1 sleep through it: 1.6.1 reads a missing folder as an
/// empty copy and writes into it, which
/// `a_1_6_1_device_writes_into_an_unplugged_folder` pins.
async fn storage_down(fleet: &mut Fleet, rng: &mut Rng, working: bool, rounds: usize) {
    let (path, label) = if working {
        (fleet.working.clone(), "working")
    } else {
        (fleet.archive.clone(), "never-delete")
    };
    let context = format!("the {label} copy unplugged for {rounds} days");
    let away = path.with_extension("unplugged");
    std::fs::rename(&path, &away).unwrap();
    fleet.down.insert(label);
    let asleep: Vec<usize> = fleet
        .every()
        .into_iter()
        .filter(|i| fleet.devices[*i].is_old())
        .collect();
    fleet.out.extend(asleep.iter().copied());
    for _ in 0..rounds {
        fleet.day += 1;
        for i in fleet.every() {
            fleet.act(i, rng);
        }
        fleet.passes(rng, &context).await;
    }
    assert!(
        !path.exists(),
        "{context}: a device wrote into the missing folder"
    );
    std::fs::rename(&away, &path).unwrap();
    fleet.down.remove(label);
    for i in asleep {
        fleet.out.remove(&i);
    }
    fleet.settle(&context).await;
    fleet.check(&context).await;
}

/// A new device on this build joins with the key, its copies in a random
/// order.
async fn join_new(fleet: &mut Fleet, rng: &mut Rng) {
    let n = fleet.devices.len();
    let name: &'static str = Box::leak(format!("joined {n}").into_boxed_str());
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("silo");
    let (w, a) = (
        (fleet.working.clone(), true),
        (fleet.archive.clone(), false),
    );
    let host = FleetHost::new(if rng.below(2) == 0 {
        vec![w, a]
    } else {
        vec![a, w]
    });
    let dev = new::Dev::join(root.clone(), &fleet.working, &host)
        .await
        .unwrap_or_else(|e| panic!("{name} does not join: {e}"));
    fleet.devices.push(Device {
        name,
        dir,
        root,
        host,
        kind: Kind::New(dev),
        swept_on: AtomicUsize::new(fleet.day),
    });
    fleet.short_log.lock().unwrap().insert(n);
    let context = format!("{name} joined");
    fleet.settle(&context).await;
    fleet.check(&context).await;
}

async fn run_lifecycle(events: &[Event], at: &AtomicUsize) {
    let mut fleet = Fleet::new(&[
        Spec {
            name: "1.6.1",
            stays_on_1_6_1: true,
            working_first: true,
        },
        Spec {
            name: "1.6.1 B",
            stays_on_1_6_1: true,
            working_first: true,
        },
        Spec {
            name: "updated A",
            stays_on_1_6_1: false,
            working_first: true,
        },
        Spec {
            name: "updated B",
            stays_on_1_6_1: false,
            working_first: false,
        },
    ])
    .await;
    for (n, event) in events.iter().enumerate() {
        at.store(n, Ordering::SeqCst);
        trace(format!("event {n}: {event:?}"));
        fleet.happen(*event).await;
    }
}

/// Runs a plan on a thread of its own, so a failure comes back as the
/// event it happened at and the message, and the next attempt can start.
fn attempt(events: &[Event]) -> Result<(), (usize, String)> {
    let events = events.to_vec();
    let at = std::sync::Arc::new(AtomicUsize::new(0));
    let at_run = at.clone();
    std::thread::Builder::new()
        .stack_size(64 << 20)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(run_lifecycle(&events, &at_run))
        })
        .unwrap()
        .join()
        .map_err(|panic| {
            let why = panic
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            (at.load(Ordering::SeqCst), why)
        })
}

/// Drops every event the failure does not need, one at a time.
fn shrink(mut events: Vec<Event>) -> Vec<Event> {
    let mut i = 0;
    while i < events.len() {
        let mut fewer = events.clone();
        fewer.remove(i);
        match attempt(&fewer) {
            Err((at, _)) => {
                fewer.truncate(at + 1);
                events = fewer;
            }
            Ok(()) => i += 1,
        }
    }
    events
}

fn lifecycle_seeds() -> Vec<u64> {
    match std::env::var("SILENTSILO_LIFECYCLE_SEED") {
        Ok(range) if range.contains("..") => {
            let (from, to) = range.split_once("..").unwrap();
            (from.parse().expect("a number")..to.parse().expect("a number")).collect()
        }
        Ok(seed) => vec![seed.parse().expect("a number")],
        Err(_) => vec![1, 2],
    }
}

#[test]
fn random_lifecycles_lose_nothing_and_break_nothing() {
    work_dirs_for_this_test();
    let events = std::env::var("SILENTSILO_LIFECYCLE_EVENTS")
        .map(|n| n.parse().expect("a number"))
        .unwrap_or(10);
    let mut failures = Vec::new();
    for seed in lifecycle_seeds() {
        let plan = plan(seed, events);
        let Err((at, why)) = attempt(&plan) else {
            println!("seed {seed}: {events} events, all held");
            continue;
        };
        let mut failing = plan[..=at].to_vec();
        if std::env::var("SILENTSILO_LIFECYCLE_SHRINK").is_ok() {
            failing = shrink(failing);
        }
        failures.push(format!(
            "seed {seed}, event {at} ({:?}): {why}\n  replay: {failing:?}",
            plan[at]
        ));
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// Plans a random run once failed on, cut down to what the failure needed.
#[test]
fn lifecycle_regressions() {
    work_dirs_for_this_test();
    let plans: &[&[Event]] = &[];
    for plan in plans {
        if let Err((at, why)) = attempt(plan) {
            panic!("event {at} of {plan:?}: {why}");
        }
    }
}

/// Pinned, fixed in this build by `undelivered_own_ops`: a rebuild writes
/// again what this device wrote and no copy holds. 1.6.1 takes every record
/// not on every copy, and beside a never-delete copy left under a replaced
/// key that is all of them, other devices' included. Its rebuild writes that
/// history again as new changes, and a folder purged meanwhile comes back.
#[tokio::test]
async fn a_1_6_1_rebuild_beside_a_dead_copy_writes_old_history_again() {
    work_dirs_for_this_test();
    let mut rng = Rng::new(seed() + 2000);
    let mut fleet = Fleet::new(&[
        Spec {
            name: "1.6.1",
            stays_on_1_6_1: true,
            working_first: true,
        },
        Spec {
            name: "updated A",
            stays_on_1_6_1: false,
            working_first: true,
        },
    ])
    .await;
    let (old, a) = (0, 1);
    key_replaced(&mut fleet, a, &[old]).await;
    everyday_use(&mut fleet, &mut rng, 4, &[old, a]).await;

    fleet.out.insert(old);
    for _ in 0..20 {
        fleet.upsert(a, Uuid::from_u128(1), &format!("pw-{}", rng.next()));
        fleet.pass(a, "before the compaction").await;
    }
    fleet.day += 30;
    fleet.settle("before the compaction").await;
    on!(fleet.devices[a], |d| d
        .compact(&fleet.devices[a].host)
        .await);

    let stale = fleet.devices[old].pass(fleet.day).await;
    assert!(stale.needs_rebuild, "{stale:?}");
    let written_again = on!(fleet.devices[old], |d| d
        .rebuild(&fleet.devices[old].host)
        .await);
    assert!(
        written_again > 0,
        "1.6.1 no longer writes old history again: drop this pin and the note in `happen`"
    );
    println!("1.6.1 wrote {written_again} records again after its rebuild");
}

/// What `storage_down` keeps 1.6.1 away from: with its folder copy gone it
/// lists nothing, pushes everything and recreates the folder. This build
/// refuses the copy as unreachable and writes nothing.
#[tokio::test]
async fn a_1_6_1_device_writes_into_an_unplugged_folder() {
    work_dirs_for_this_test();
    let mut fleet = Fleet::new(&[
        Spec {
            name: "1.6.1",
            stays_on_1_6_1: true,
            working_first: true,
        },
        Spec {
            name: "updated A",
            stays_on_1_6_1: false,
            working_first: true,
        },
    ])
    .await;
    let away = fleet.working.with_extension("unplugged");
    std::fs::rename(&fleet.working, &away).unwrap();

    fleet.upsert(1, Uuid::from_u128(1), "while unplugged on this build");
    let pass = fleet.devices[1].pass(1).await;
    assert!(
        pass.failed
            .iter()
            .any(|(l, why)| l == "working" && why.contains(UNPLUGGED)),
        "{pass:?}"
    );
    assert!(
        !fleet.working.exists(),
        "this build wrote into the missing folder"
    );

    fleet.upsert(0, Uuid::from_u128(1), "while unplugged on 1.6.1");
    let pass = fleet.devices[0].pass(1).await;
    println!("1.6.1: {pass:?}");
    assert!(
        fleet.working.exists(),
        "1.6.1 no longer writes into a missing folder: drop the note in storage_down"
    );
    std::fs::remove_dir_all(&fleet.working).unwrap();
    std::fs::rename(&away, &fleet.working).unwrap();
    fleet.out.insert(0);
}
