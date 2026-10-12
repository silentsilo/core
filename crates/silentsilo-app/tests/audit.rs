//! The activity log through the sync pass: a device learns of the log from
//! storage, and its sealed events reach every copy before they leave it.

use std::path::Path;

use silentsilo_app::{AppEvent, AppState, Host, run_sync_pass, sync_now};
use silentsilo_audit::{
    AuditKey, AuditPolicy, Event, KeyPair, PolicyKey, Scope, Segment, SegmentKey, Spool, Unchecked,
    codes, open_event,
};
use silentsilo_store::{FolderStore, ObjectStore, StoreConfig};
use silentsilo_vault::{BackupTarget, SiloEntry, TargetRole, VaultSession};
use silentsilo_vfs::Vfs;
use uuid::Uuid;

/// The copies a device has. Strict, a warning fails the test; a copy that
/// is unplugged on purpose warns, so that test is not.
struct Copies(Vec<BackupTarget>, bool);

impl Host for Copies {
    fn emit(&self, _event: AppEvent) {}
    fn warn(&self, area: &str, detail: &str) {
        if self.1 {
            panic!("[{area}] {detail}");
        }
    }
    fn targets(&self, _silo_id: Uuid) -> Vec<BackupTarget> {
        self.0.clone()
    }
}

/// Copy B's folder taken away and a file left in its place, so every write
/// to it fails, as for a drive in a drawer. Undone by [`plug_in`].
fn unplug(dir: &Path) {
    std::fs::rename(dir, dir.with_extension("away")).unwrap();
    std::fs::write(dir, b"not a folder").unwrap();
}

fn plug_in(dir: &Path) {
    std::fs::remove_file(dir).unwrap();
    std::fs::rename(dir.with_extension("away"), dir).unwrap();
}

fn copy(dir: &Path) -> BackupTarget {
    BackupTarget {
        config: StoreConfig::Folder {
            path: dir.to_path_buf(),
        },
        label: String::new(),
        role: TargetRole::Working,
    }
}

struct Device {
    _dir: tempfile::TempDir,
    state: AppState,
    silo: SiloEntry,
}

impl Device {
    fn new(host: &Copies) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("silo");
        let vault_id = Uuid::new_v4();
        let session = VaultSession::provision(root.clone(), vault_id, "s").unwrap();
        Vfs::new(&session).ensure_initialized().unwrap();
        let state = AppState::default();
        state.open_session(host, vault_id, session).unwrap();
        Self {
            _dir: dir,
            state,
            silo: SiloEntry {
                id: vault_id,
                name: "T".into(),
                path: root,
                last_opened: 0,
                auto_lock_minutes: None,
            },
        }
    }

    fn id(&self) -> Uuid {
        let sessions = self.state.sessions.lock().unwrap();
        silentsilo_vfs::device_id(&sessions[&self.silo.id].conn).unwrap()
    }

    fn kek(&self) -> silentsilo_crypto::ContentKek {
        self.state.sessions.lock().unwrap()[&self.silo.id]
            .kek
            .clone()
    }

    fn spool(&self) -> Spool {
        Spool::open(
            &self.silo.path,
            self.id(),
            self.kek().as_bytes(),
            Unchecked::Refuse,
        )
        .unwrap()
    }

    /// What tags this silo's policies: a key from its current DEK.
    fn policy_key(&self) -> PolicyKey {
        PolicyKey::new(
            self.state.sessions.lock().unwrap()[&self.silo.id]
                .dek
                .as_bytes(),
        )
    }

    fn tags(&self) -> SegmentKey {
        SegmentKey::new(self.kek().as_bytes())
    }

    /// Makes the silo an organisation's: one enrolled organisation key per
    /// `(credential id, byte)`, whose wrap key is that byte 32 times.
    fn administered_by(&self, keys: &[(&str, u8)]) {
        use silentsilo_vault::{StoredFidoCredential, StoredFidoKeys};
        let credentials = {
            let sessions = self.state.sessions.lock().unwrap();
            let dek = &sessions[&self.silo.id].dek;
            keys.iter()
                .enumerate()
                .map(|(slot, (id, byte))| StoredFidoCredential {
                    kind: silentsilo_vault::KIND_FIDO2.into(),
                    derivation: silentsilo_vault::DERIVATION_HMAC_V1.into(),
                    policy: silentsilo_vault::POLICY_ORG.into(),
                    credential_id: id.to_string(),
                    public_key: "3059".into(),
                    key_slot: slot as u8,
                    rp_id: "silentsilo.com".into(),
                    label: "Organisation".into(),
                    wrapped_dek: hex::encode(
                        silentsilo_vault::wrap_dek_bytes(dek, &[*byte; 32]).unwrap(),
                    ),
                    platform: false,
                    revoked: false,
                })
                .collect()
        };
        silentsilo_vault::save_fido_keys(
            &self.silo.path,
            &StoredFidoKeys { keys: credentials },
            silentsilo_vault::Authority::Machine,
        )
        .unwrap();
    }
}

/// A personal log, turned on, as enabling it will leave storage.
async fn turn_on(device: &Device, store: &FolderStore) -> KeyPair {
    let keys = KeyPair::generate();
    let mut key = AuditKey::new(&keys, Scope::Silo, 1);
    key.wrap_for(
        silentsilo_audit::BY_SILO,
        &keys.private,
        device.kek().as_bytes(),
    )
    .unwrap();
    let policy = AuditPolicy::new(true, &keys.id(), None, Scope::Silo, 1);
    silentsilo_sync::audit_log::write_audit_key(store, &key)
        .await
        .unwrap();
    silentsilo_sync::audit_log::write_audit_policy(store, &device.kek(), &policy)
        .await
        .unwrap();
    keys
}

async fn segments_in(store: &FolderStore) -> Vec<Segment> {
    let mut out = Vec::new();
    for entry in store.list("audit/").await.unwrap() {
        if silentsilo_audit::parse_segment_key(&entry.key).is_some() {
            out.push(Segment::from_bytes(&store.get(&entry.key).await.unwrap()).unwrap());
        }
    }
    out
}

#[tokio::test]
async fn events_reach_every_copy_before_they_leave_the_device() {
    let (a, holder) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let b = holder.path().join("b");
    std::fs::create_dir(&b).unwrap();
    let both = Copies(vec![copy(a.path()), copy(&b)], true);
    let lenient = Copies(vec![copy(a.path()), copy(&b)], false);
    let device = Device::new(&both);
    let (store_a, store_b) = (
        FolderStore::new(a.path().to_path_buf()),
        FolderStore::new(b.clone()),
    );

    // Turned on elsewhere, before this device's first pass: the pass learns
    // of it and pins that key rather than starting a log of its own.
    let keys = turn_on(&device, &store_a).await;
    run_sync_pass(&device.state, &both, &device.silo)
        .await
        .unwrap();
    let mut spool = device.spool();
    assert!(spool.pinned().is_some());
    spool
        .record(Event::new(codes::SECRET_COPIED, 2).on("e1", "Bank"))
        .unwrap();
    spool.close(3).unwrap();
    drop(spool);

    // B unplugged: the segment reaches A and stays here.
    unplug(&b);
    run_sync_pass(&device.state, &lenient, &device.silo)
        .await
        .unwrap();
    assert_eq!(segments_in(&store_a).await.len(), 1);
    assert_eq!(
        device.spool().outbox().unwrap().len(),
        1,
        "B does not hold it yet"
    );

    // Plugged back in: B gets it too, and it leaves this device. B backs off
    // after its failure, so the pass that reaches it is a later one.
    plug_in(&b);
    for _ in 0..3 {
        if device.spool().outbox().unwrap().is_empty() {
            break;
        }
        {
            let sessions = device.state.sessions.lock().unwrap();
            let conn = &sessions[&device.silo.id].conn;
            silentsilo_vfs::reset_target_backoff(conn, copy(&b).config.target_id()).unwrap();
        }
        run_sync_pass(&device.state, &both, &device.silo)
            .await
            .unwrap();
    }
    let on_b = segments_in(&store_b).await;
    assert_eq!(on_b.len(), 1);
    assert!(device.spool().outbox().unwrap().is_empty());

    // What storage holds opens with the log's key only.
    let event = open_event(&keys.private, device.id(), &on_b[0].records[0]).unwrap();
    assert_eq!(event.c, codes::SECRET_COPIED);
    assert_eq!(event.l.as_deref(), Some("Bank"));
}

#[tokio::test]
async fn an_organisation_log_stays_mandatory_when_its_queue_breaks() {
    let host = Copies(Vec::new(), true);
    let device = Device::new(&host);
    let id = device.silo.id;
    let keys = KeyPair::generate();
    let policy = AuditPolicy::new(true, &keys.id(), Some(365), Scope::Org, 1);
    device
        .spool()
        .apply_policy(&policy, &AuditKey::new(&keys, Scope::Org, 1), 1)
        .unwrap();
    assert_eq!(
        device
            .state
            .audit_record(id, Event::new(codes::UNLOCKED, 1))
            .unwrap(),
        Some(0)
    );

    let state = device
        .silo
        .path
        .join(silentsilo_audit::QUEUE_DIR)
        .join("state.json");
    std::fs::write(&state, b"not json").unwrap();
    assert!(
        device
            .state
            .audit_record(id, Event::new(codes::SECRET_COPIED, 2))
            .is_err()
    );
    assert!(
        device.state.audit_is_mandatory(id),
        "still an organisation's"
    );
}

#[tokio::test]
async fn a_personal_silo_with_a_broken_queue_is_not_mandatory() {
    let host = Copies(Vec::new(), true);
    let device = Device::new(&host);
    let state = device
        .silo
        .path
        .join(silentsilo_audit::QUEUE_DIR)
        .join("state.json");
    std::fs::create_dir_all(state.parent().unwrap()).unwrap();
    std::fs::write(&state, b"not json").unwrap();
    assert!(!device.state.audit_is_mandatory(device.silo.id));
}

#[tokio::test]
async fn a_silo_nobody_set_starts_its_log_at_the_first_pass() {
    let a = tempfile::tempdir().unwrap();
    let host = Copies(vec![copy(a.path())], true);
    let device = Device::new(&host);
    run_sync_pass(&device.state, &host, &device.silo)
        .await
        .unwrap();
    let pinned = device.spool().pinned().cloned().unwrap();
    assert!(pinned.enabled);
    let store = FolderStore::new(a.path().to_path_buf());
    let policy = silentsilo_sync::audit_log::read_audit_policy(&store, &device.kek())
        .await
        .unwrap()
        .unwrap();
    assert!(policy.enabled);
    assert!(device.state.audit_status(device.silo.id).unwrap().enabled);
}

#[tokio::test]
async fn a_log_turned_off_on_a_copy_stays_off_on_a_device_that_never_set_it() {
    let a = tempfile::tempdir().unwrap();
    let host = Copies(vec![copy(a.path())], true);
    let device = Device::new(&host);
    let store = FolderStore::new(a.path().to_path_buf());
    // Another device turned it off: the copy holds a key and "off".
    let keys = KeyPair::generate();
    let mut key = AuditKey::new(&keys, Scope::Silo, 1);
    key.wrap_for(
        silentsilo_audit::BY_SILO,
        &keys.private,
        device.kek().as_bytes(),
    )
    .unwrap();
    let off = AuditPolicy::new(false, &keys.id(), None, Scope::Silo, 5);
    silentsilo_sync::audit_log::write_audit_key(&store, &key)
        .await
        .unwrap();
    silentsilo_sync::audit_log::write_audit_policy(&store, &device.kek(), &off)
        .await
        .unwrap();

    run_sync_pass(&device.state, &host, &device.silo)
        .await
        .unwrap();
    assert!(device.spool().pinned().is_some_and(|p| !p.enabled));
    let still = silentsilo_sync::audit_log::read_audit_policy(&store, &device.kek())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still, off, "the copy keeps the choice made elsewhere");
}

#[tokio::test]
async fn a_copy_that_cannot_be_read_holds_the_default_back() {
    let (a, holder) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let b = holder.path().join("b");
    std::fs::create_dir_all(&b).unwrap();
    let host = Copies(vec![copy(a.path()), copy(&b)], false);
    let device = Device::new(&host);
    unplug(&b);
    run_sync_pass(&device.state, &host, &device.silo).await.ok();
    assert!(device.spool().pinned().is_none(), "not started blind");
    // Resting after its failure, it is not asked at all: still a copy
    // that has not answered.
    run_sync_pass(&device.state, &host, &device.silo).await.ok();
    assert!(device.spool().pinned().is_none(), "not while it rests");
    plug_in(&b);
    sync_now(&device.state, &host, &device.silo).await.ok();
    assert!(device.spool().pinned().is_some_and(|p| p.enabled));
}

#[tokio::test]
async fn a_copy_holding_a_policy_whose_key_does_not_read_holds_the_default_back() {
    let a = tempfile::tempdir().unwrap();
    let host = Copies(vec![copy(a.path())], false);
    let device = Device::new(&host);
    let store = FolderStore::new(a.path().to_path_buf());
    // "Off" reached the copy; its key file did not.
    let keys = KeyPair::generate();
    let off = AuditPolicy::new(false, &keys.id(), None, Scope::Silo, 5);
    silentsilo_sync::audit_log::write_audit_policy(&store, &device.kek(), &off)
        .await
        .unwrap();

    run_sync_pass(&device.state, &host, &device.silo).await.ok();
    assert!(device.spool().pinned().is_none(), "not started over an off");
    let still = silentsilo_sync::audit_log::read_audit_policy(&store, &device.kek())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(still, off);
}

#[tokio::test]
async fn off_chosen_before_the_log_started_is_kept_and_spread() {
    let a = tempfile::tempdir().unwrap();
    let host = Copies(vec![copy(a.path())], true);
    let device = Device::new(&host);
    device.state.set_audit_log(device.silo.id, false).unwrap();
    run_sync_pass(&device.state, &host, &device.silo)
        .await
        .unwrap();
    assert!(!device.state.audit_status(device.silo.id).unwrap().enabled);
    let store = FolderStore::new(a.path().to_path_buf());
    let policy = silentsilo_sync::audit_log::read_audit_policy(&store, &device.kek())
        .await
        .unwrap()
        .unwrap();
    assert!(!policy.enabled, "the copy holds the choice");
}

#[tokio::test]
async fn a_silo_with_no_copies_starts_when_opened_and_respects_off() {
    let host = Copies(Vec::new(), true);
    let device = Device::new(&host);
    let id = device.silo.id;
    device.state.start_audit_by_default(&host, id).unwrap();
    assert!(device.state.audit_status(id).unwrap().enabled);
    device.state.set_audit_log(id, false).unwrap();
    device.state.start_audit_by_default(&host, id).unwrap();
    assert!(
        !device.state.audit_status(id).unwrap().enabled,
        "off stays off"
    );
}

#[tokio::test]
async fn a_lock_is_the_last_event_and_closes_its_segment() {
    let a = tempfile::tempdir().unwrap();
    let host = Copies(vec![copy(a.path())], true);
    let device = Device::new(&host);
    let store = FolderStore::new(a.path().to_path_buf());
    let keys = turn_on(&device, &store).await;
    run_sync_pass(&device.state, &host, &device.silo)
        .await
        .unwrap();

    let id = device.silo.id;
    assert_eq!(
        device
            .state
            .audit_record(id, Event::new(codes::UNLOCKED, 1))
            .unwrap(),
        Some(0)
    );
    assert!(!device.state.audit_is_mandatory(id), "a personal log");
    let device_id = device.id();
    let kek = device.kek();
    device.state.close_session(&host, id).unwrap();

    // Closed into a segment at the lock, with no pass in between.
    let outbox = Spool::open(
        &device.silo.path,
        device_id,
        kek.as_bytes(),
        Unchecked::Refuse,
    )
    .unwrap()
    .outbox()
    .unwrap();
    assert_eq!(outbox.len(), 1);
    let codes_written: Vec<u16> = outbox[0]
        .records
        .iter()
        .map(|r| open_event(&keys.private, device_id, r).unwrap().c)
        .collect();
    assert_eq!(codes_written, vec![codes::UNLOCKED, codes::LOCKED]);
}

#[tokio::test]
async fn a_log_turned_on_with_no_copies_records_at_once() {
    let host = Copies(Vec::new(), true);
    let device = Device::new(&host);
    let id = device.silo.id;
    assert!(!device.state.audit_status(id).unwrap().enabled);
    device.state.set_audit_log(id, true).unwrap();
    let status = device.state.audit_status(id).unwrap();
    assert!(status.enabled && status.kept && !status.organisation);
    // The start, then what happened after it.
    assert_eq!(
        device
            .state
            .audit_record(id, Event::new(codes::SECRET_COPIED, 5))
            .unwrap(),
        Some(1)
    );
    assert_eq!(device.state.audit_status(id).unwrap().waiting, 2);
}

#[tokio::test]
async fn a_log_turned_on_reaches_the_copies_and_turns_off_there_too() {
    let a = tempfile::tempdir().unwrap();
    let host = Copies(vec![copy(a.path())], true);
    let device = Device::new(&host);
    let id = device.silo.id;
    let store = FolderStore::new(a.path().to_path_buf());

    device.state.set_audit_log(id, true).unwrap();
    run_sync_pass(&device.state, &host, &device.silo)
        .await
        .unwrap();
    let on = silentsilo_sync::audit_log::read_audit_policy(&store, &device.kek())
        .await
        .unwrap()
        .expect("published");
    assert!(on.enabled);
    let key = silentsilo_sync::audit_log::read_audit_key(&store, &on.key_id)
        .await
        .unwrap()
        .expect("its key too");
    // Whoever opens the silo reads its log.
    assert!(
        key.unwrap_with(silentsilo_audit::BY_SILO, device.kek().as_bytes())
            .is_ok()
    );

    device.state.set_audit_log(id, false).unwrap();
    assert_eq!(
        device
            .state
            .audit_record(id, Event::new(codes::SECRET_COPIED, 5))
            .unwrap(),
        None,
        "off"
    );
    run_sync_pass(&device.state, &host, &device.silo)
        .await
        .unwrap();
    let off = silentsilo_sync::audit_log::read_audit_policy(&store, &device.kek())
        .await
        .unwrap()
        .unwrap();
    assert!(!off.enabled);
    assert!(off.changed_at > on.changed_at);

    // On again, under the same key.
    device.state.set_audit_log(id, true).unwrap();
    assert_eq!(device.spool().policy().unwrap().unwrap().key_id, on.key_id);
}

#[tokio::test]
async fn a_newer_policy_on_a_copy_wins_over_this_device_s() {
    let a = tempfile::tempdir().unwrap();
    let host = Copies(vec![copy(a.path())], true);
    let device = Device::new(&host);
    let id = device.silo.id;
    let store = FolderStore::new(a.path().to_path_buf());
    device.state.set_audit_log(id, true).unwrap();
    run_sync_pass(&device.state, &host, &device.silo)
        .await
        .unwrap();

    // Another device turned it off later.
    let mut later = device.spool().policy().unwrap().unwrap();
    later.enabled = false;
    later.changed_at += 100;
    let later = later.tagged(&device.policy_key());
    silentsilo_sync::audit_log::write_audit_policy(&store, &device.kek(), &later)
        .await
        .unwrap();
    // Read again at the next pass that finds the policy due.
    {
        let mut spool = device.spool();
        let (policy, key) = (
            spool.policy().unwrap().unwrap(),
            spool.key().unwrap().unwrap(),
        );
        spool.apply_policy(&policy, &key, 0).unwrap();
    }
    run_sync_pass(&device.state, &host, &device.silo)
        .await
        .unwrap();
    assert!(!device.state.audit_status(id).unwrap().enabled);
}

#[tokio::test]
async fn an_organisation_log_cannot_be_turned_off() {
    let host = Copies(Vec::new(), true);
    let device = Device::new(&host);
    let keys = KeyPair::generate();
    let policy = AuditPolicy::new(true, &keys.id(), Some(365), Scope::Org, 1);
    device
        .spool()
        .apply_policy(&policy, &AuditKey::new(&keys, Scope::Org, 1), 1)
        .unwrap();
    assert!(device.state.set_audit_log(device.silo.id, false).is_err());
    assert!(device.state.audit_status(device.silo.id).unwrap().enabled);
}

/// Read again at the next pass, as it is every ten minutes.
fn due_again(device: &Device) {
    let mut spool = device.spool();
    let (policy, key) = (
        spool.policy().unwrap().unwrap(),
        spool.key().unwrap().unwrap(),
    );
    spool.apply_policy(&policy, &key, 0).unwrap();
}

async fn policy_on(device: &Device, store: &FolderStore) -> AuditPolicy {
    silentsilo_sync::audit_log::read_audit_policy(store, &device.kek())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn a_newer_policy_not_signed_with_the_silo_s_key_is_not_followed_and_is_put_right() {
    let a = tempfile::tempdir().unwrap();
    let host = Copies(vec![copy(a.path())], true);
    let device = Device::new(&host);
    let id = device.silo.id;
    let store = FolderStore::new(a.path().to_path_buf());
    device.state.set_audit_log(id, true).unwrap();
    run_sync_pass(&device.state, &host, &device.silo)
        .await
        .unwrap();
    let on = policy_on(&device, &store).await;
    assert!(
        on.is_authentic(&device.policy_key()),
        "tagged as it is spread"
    );

    // Someone who held the silo before its key changed, and still has the
    // content key, turns the log off on the copy.
    let mut forged = on.clone();
    forged.enabled = false;
    forged.changed_at += 100;
    forged.auth = None;
    silentsilo_sync::audit_log::write_audit_policy(&store, &device.kek(), &forged)
        .await
        .unwrap();
    due_again(&device);
    let lenient = Copies(vec![copy(a.path())], false);
    run_sync_pass(&device.state, &lenient, &device.silo)
        .await
        .unwrap();
    assert!(device.state.audit_status(id).unwrap().enabled);
    let now_there = policy_on(&device, &store).await;
    assert!(now_there.enabled);
    assert!(now_there.is_authentic(&device.policy_key()));
    assert!(
        now_there.changed_at > forged.changed_at,
        "dated after it, for a release that follows the newest"
    );
}

#[tokio::test]
async fn a_policy_tagged_under_an_earlier_silo_key_is_tagged_again() {
    let a = tempfile::tempdir().unwrap();
    let host = Copies(vec![copy(a.path())], true);
    let device = Device::new(&host);
    let store = FolderStore::new(a.path().to_path_buf());
    device.state.set_audit_log(device.silo.id, true).unwrap();
    run_sync_pass(&device.state, &host, &device.silo)
        .await
        .unwrap();
    // The same policy, tagged under the DEK before a rotation.
    let before = policy_on(&device, &store)
        .await
        .tagged(&PolicyKey::new(&[9; 32]));
    silentsilo_sync::audit_log::write_audit_policy(&store, &device.kek(), &before)
        .await
        .unwrap();
    due_again(&device);
    run_sync_pass(&device.state, &host, &device.silo)
        .await
        .unwrap();
    let after = policy_on(&device, &store).await;
    assert_eq!(after.changed_at, before.changed_at);
    assert!(after.is_authentic(&device.policy_key()));
}

#[tokio::test]
async fn a_policy_dated_far_ahead_is_not_taken_in() {
    let a = tempfile::tempdir().unwrap();
    let host = Copies(vec![copy(a.path())], false);
    let device = Device::new(&host);
    let store = FolderStore::new(a.path().to_path_buf());
    let keys = turn_on(&device, &store).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let ahead = AuditPolicy::new(true, &keys.id(), None, Scope::Silo, now + 10 * 86_400);
    silentsilo_sync::audit_log::write_audit_policy(&store, &device.kek(), &ahead)
        .await
        .unwrap();
    run_sync_pass(&device.state, &host, &device.silo)
        .await
        .unwrap();
    assert!(device.spool().pinned().is_none());
}

#[tokio::test]
async fn a_queue_a_release_before_the_check_left_is_taken_in_once_then_checked() {
    let host = Copies(Vec::new(), true);
    let device = Device::new(&host);
    let id = device.silo.id;
    // A personal log pinned by 1.9: nothing in the queue is checked.
    let keys = KeyPair::generate();
    let mut key = AuditKey::new(&keys, Scope::Silo, 1);
    key.wrap_for(
        silentsilo_audit::BY_SILO,
        &keys.private,
        device.kek().as_bytes(),
    )
    .unwrap();
    let policy = AuditPolicy::new(true, &keys.id(), None, Scope::Silo, 1);
    let queue = device.silo.path.join(silentsilo_audit::QUEUE_DIR);
    std::fs::create_dir_all(&queue).unwrap();
    std::fs::write(queue.join("key.json"), key.to_json().unwrap()).unwrap();
    std::fs::write(
        queue.join("policy.json"),
        serde_json::to_vec(&policy).unwrap(),
    )
    .unwrap();
    let state = serde_json::json!({
        "next_event": 0, "next_segment": 0, "last_hash": "", "closed_through": 0,
        "pinned": {
            "key_id": key.key_id, "public_key": key.public_key, "scope": "silo",
            "enabled": true, "retention_days": null, "checked_at": 0
        }
    });
    std::fs::write(queue.join("state.json"), state.to_string()).unwrap();

    assert_eq!(
        device
            .state
            .audit_record(id, Event::new(codes::UNLOCKED, 1))
            .unwrap(),
        Some(0)
    );
    assert_eq!(device.spool().pinned().unwrap().key_id, key.key_id);

    // From now on a pin without its check is someone else's: written into
    // the folder with a key of their own, it is not sealed to.
    let theirs = KeyPair::generate();
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(queue.join("state.json")).unwrap()).unwrap();
    state.as_object_mut().unwrap().remove("pin_check");
    state["pinned"]["key_id"] = hex::encode(theirs.id()).into();
    state["pinned"]["public_key"] = hex::encode(&theirs.public).into();
    std::fs::write(queue.join("state.json"), state.to_string()).unwrap();
    device
        .state
        .audit_record(id, Event::new(codes::SECRET_COPIED, 2))
        .unwrap();
    let segment = device.spool().close(3).unwrap().unwrap();
    for record in &segment.records {
        assert!(open_event(&keys.private, segment.device, record).is_ok());
        assert!(open_event(&theirs.private, segment.device, record).is_err());
    }
}

mod reading {
    use super::*;
    use silentsilo_app::audit_read::{
        Reader, read_audit_log, read_audit_log_local, read_audit_log_within,
    };

    /// Another device's run of segments, its events numbered from 0, tagged
    /// as this build writes them.
    fn their_segments(
        device: Uuid,
        public: &[u8],
        per_segment: &[u16],
        tags: &SegmentKey,
    ) -> Vec<Segment> {
        let mut out: Vec<Segment> = Vec::new();
        let mut i = 0;
        for (seq, codes_in) in per_segment.iter().enumerate() {
            let mut records = Vec::new();
            for _ in 0..*codes_in {
                let mut event = Event::new(codes::FILE_OPENED, 100 + i as i64);
                event.i = i;
                records.push(silentsilo_audit::seal_event(public, device, &event).unwrap());
                i += 1;
            }
            let prev = out.last().map_or([0u8; 32], |s| s.hash());
            out.push(
                Segment {
                    device,
                    seq: seq as u64,
                    prev,
                    closed_at: 1,
                    records,
                    tag: None,
                }
                .tag_with(tags),
            );
        }
        out
    }

    #[tokio::test]
    async fn a_log_with_no_copies_reads_from_this_computer() {
        let host = Copies(Vec::new(), true);
        let device = Device::new(&host);
        let id = device.silo.id;
        device.state.set_audit_log(id, true).unwrap();
        device
            .state
            .audit_record(
                id,
                Event::new(codes::SECRET_COPIED, i64::MAX / 2).on("e1", "Bank"),
            )
            .unwrap();
        let read = read_audit_log(&device.state, &host, &device.silo, &Reader::Silo)
            .await
            .unwrap();
        let codes_read: Vec<u16> = read.entries.iter().map(|e| e.event.c).collect();
        assert_eq!(codes_read, vec![codes::SECRET_COPIED, codes::LOG_STARTED]);
        assert_eq!(read.entries[0].what, "Secret copied");
        assert_eq!(read.devices.len(), 1);
        assert!(read.devices[0].missing_events.is_empty());
        assert_eq!(read.unreadable, 0);

        // Held for the next read while the silo is open, gone once it locks.
        assert!(device.state.holds_audit_read(id));
        let again = read_audit_log(&device.state, &host, &device.silo, &Reader::Silo)
            .await
            .unwrap();
        assert_eq!(again.entries.len(), read.entries.len());
        device.state.close_session(&host, id).unwrap();
        assert!(!device.state.holds_audit_read(id));
    }

    /// A WebDAV address that accepts the connection and never answers.
    fn silent_copy() -> (std::net::TcpListener, BackupTarget) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = BackupTarget {
            config: StoreConfig::WebDav(silentsilo_store::WebDavConfig {
                url: format!("http://127.0.0.1:{port}/dav"),
                username: "u".into(),
                password: "p".into(),
            }),
            label: "Silent NAS".into(),
            role: TargetRole::Working,
        };
        (listener, target)
    }

    #[tokio::test]
    async fn a_copy_that_does_not_answer_does_not_hold_the_others() {
        let a = tempfile::tempdir().unwrap();
        let (_listener, silent) = silent_copy();
        let host = Copies(vec![silent, copy(a.path())], false);
        let device = Device::new(&host);
        let id = device.silo.id;
        device.state.set_audit_log(id, true).unwrap();
        run_sync_pass(
            &device.state,
            &Copies(vec![copy(a.path())], false),
            &device.silo,
        )
        .await
        .unwrap();
        let store = FolderStore::new(a.path().to_path_buf());
        let public = device.spool().key().unwrap().unwrap().public().unwrap();
        let other = Uuid::new_v4();
        for segment in their_segments(other, &public, &[2], &device.tags()) {
            store
                .put(
                    &silentsilo_audit::segment_key(other, segment.seq),
                    segment.to_bytes(),
                )
                .await
                .unwrap();
        }

        let started = std::time::Instant::now();
        let read = read_audit_log_within(
            &device.state,
            &host,
            &device.silo,
            &Reader::Silo,
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(10));
        assert_eq!(read.copies_unread, vec!["Silent NAS".to_string()]);
        assert!(read.devices.iter().any(|d| d.device == other));
    }

    #[tokio::test]
    async fn the_local_read_touches_no_copy() {
        let (_listener, silent) = silent_copy();
        let host = Copies(vec![silent], false);
        let device = Device::new(&host);
        let id = device.silo.id;
        device.state.set_audit_log(id, true).unwrap();
        device
            .state
            .audit_record(
                id,
                Event::new(codes::SECRET_COPIED, i64::MAX / 2).on("e1", "Bank"),
            )
            .unwrap();
        let started = std::time::Instant::now();
        let read = read_audit_log_local(&device.state, &device.silo, &Reader::Silo).unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(read.copies_unread.is_empty());
        let codes_read: Vec<u16> = read.entries.iter().map(|e| e.event.c).collect();
        assert_eq!(codes_read, vec![codes::SECRET_COPIED, codes::LOG_STARTED]);
    }

    #[tokio::test]
    async fn records_under_a_key_this_device_left_still_read() {
        let a = tempfile::tempdir().unwrap();
        let host = Copies(vec![copy(a.path())], true);
        let device = Device::new(&host);
        let id = device.silo.id;
        let store = FolderStore::new(a.path().to_path_buf());
        device.state.set_audit_log(id, true).unwrap();
        run_sync_pass(&device.state, &host, &device.silo)
            .await
            .unwrap();

        // Another device started the log at the same time, under its own
        // key, and its policy is the newer: this one follows it.
        let theirs = KeyPair::generate();
        let mut key = AuditKey::new(&theirs, Scope::Silo, 2);
        key.wrap_for(
            silentsilo_audit::BY_SILO,
            &theirs.private,
            device.kek().as_bytes(),
        )
        .unwrap();
        let newer = AuditPolicy::new(true, &theirs.id(), None, Scope::Silo, i64::MAX / 4);
        silentsilo_sync::audit_log::write_audit_key(&store, &key)
            .await
            .unwrap();
        device.spool().apply_policy(&newer, &key, 0).unwrap();
        device
            .state
            .audit_record(id, Event::new(codes::FILE_OPENED, 50))
            .unwrap();

        let read = read_audit_log(&device.state, &host, &device.silo, &Reader::Silo)
            .await
            .unwrap();
        assert_eq!(read.unreadable, 0, "the first key's records open too");
        assert_eq!(read.entries.len(), 2);
    }

    #[tokio::test]
    async fn every_device_s_segments_are_read_and_a_hole_is_named() {
        let a = tempfile::tempdir().unwrap();
        let host = Copies(vec![copy(a.path())], true);
        let device = Device::new(&host);
        let id = device.silo.id;
        let store = FolderStore::new(a.path().to_path_buf());
        device.state.set_audit_log(id, true).unwrap();
        run_sync_pass(&device.state, &host, &device.silo)
            .await
            .unwrap();

        // Another device wrote three segments; the middle one is gone.
        let public = device.spool().key().unwrap().unwrap().public().unwrap();
        let other = Uuid::new_v4();
        for segment in their_segments(other, &public, &[2, 3, 1], &device.tags()) {
            if segment.seq != 1 {
                store.put(&segment.key(), segment.to_bytes()).await.unwrap();
            }
        }
        // And one record sealed to a key that is not the log's.
        let stranger = KeyPair::generate();
        let mut odd = their_segments(Uuid::new_v4(), &stranger.public, &[1], &device.tags());
        let odd = odd.remove(0);
        store.put(&odd.key(), odd.to_bytes()).await.unwrap();

        let read = read_audit_log(&device.state, &host, &device.silo, &Reader::Silo)
            .await
            .unwrap();
        let theirs = read.devices.iter().find(|d| d.device == other).unwrap();
        assert_eq!(theirs.events, 3);
        assert_eq!(theirs.missing_segments, vec![1]);
        assert_eq!(theirs.missing_events, vec![(2, 4)]);
        assert_eq!(read.unreadable, 1);
        assert!(read.copies_unread.is_empty());

        // Read again from what was kept, with the copy gone.
        std::fs::remove_dir_all(a.path().join("audit")).unwrap();
        let again = read_audit_log(&device.state, &host, &device.silo, &Reader::Silo)
            .await
            .unwrap();
        assert_eq!(
            again
                .devices
                .iter()
                .find(|d| d.device == other)
                .unwrap()
                .events,
            3
        );
    }

    #[tokio::test]
    async fn forged_segments_are_refused_and_damaged_ones_leave_the_cache() {
        let a = tempfile::tempdir().unwrap();
        let host = Copies(vec![copy(a.path())], true);
        let device = Device::new(&host);
        let id = device.silo.id;
        let store = FolderStore::new(a.path().to_path_buf());
        device.state.set_audit_log(id, true).unwrap();
        run_sync_pass(&device.state, &host, &device.silo)
            .await
            .unwrap();
        let public = device.spool().key().unwrap().unwrap().public().unwrap();
        let other = Uuid::new_v4();
        let segments = their_segments(other, &public, &[2, 1], &device.tags());
        for segment in &segments {
            store.put(&segment.key(), segment.to_bytes()).await.unwrap();
        }
        // A third written by storage, which has the public key and not the
        // silo's: it does not get in.
        let forged = their_segments(other, &public, &[1, 1, 1], &SegmentKey::new(&[1; 32]))
            .pop()
            .unwrap();
        store.put(&forged.key(), forged.to_bytes()).await.unwrap();

        let read = read_audit_log(&device.state, &host, &device.silo, &Reader::Silo)
            .await
            .unwrap();
        let trail = read.devices.iter().find(|d| d.device == other).unwrap();
        assert_eq!(trail.events, 3);
        assert_eq!(trail.refused_segments, vec![2]);
        let cache = device.silo.path.join(silentsilo_app::audit_read::CACHE_DIR);
        let cached = |seq: u64| cache.join(other.to_string()).join(format!("{seq:012}.seg"));
        assert!(!cached(2).exists(), "a forged segment is not kept");

        // A cached segment damaged on this disk is dropped and fetched again.
        std::fs::write(cached(0), b"noise").unwrap();
        let again = read_audit_log(&device.state, &host, &device.silo, &Reader::Silo)
            .await
            .unwrap();
        let trail = again.devices.iter().find(|d| d.device == other).unwrap();
        assert_eq!(trail.events, 3);
        assert_eq!(std::fs::read(cached(0)).unwrap(), segments[0].to_bytes());
    }

    #[tokio::test]
    async fn a_copy_that_cannot_be_read_is_named() {
        let (a, holder) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let b = holder.path().join("b");
        std::fs::create_dir(&b).unwrap();
        let host = Copies(vec![copy(a.path()), copy(&b)], false);
        let device = Device::new(&host);
        device.state.set_audit_log(device.silo.id, true).unwrap();
        unplug(&b);
        let read = read_audit_log(&device.state, &host, &device.silo, &Reader::Silo)
            .await
            .unwrap();
        assert_eq!(read.copies_unread.len(), 1);
        plug_in(&b);
    }

    #[tokio::test]
    async fn an_organisation_log_is_not_read_with_the_silo_s_key() {
        let host = Copies(Vec::new(), true);
        let device = Device::new(&host);
        let keys = KeyPair::generate();
        let policy = AuditPolicy::new(true, &keys.id(), Some(365), Scope::Org, 1);
        device
            .spool()
            .apply_policy(&policy, &AuditKey::new(&keys, Scope::Org, 1), 1)
            .unwrap();
        assert!(
            read_audit_log(&device.state, &host, &device.silo, &Reader::Silo)
                .await
                .is_err()
        );
    }
}

mod organisation {
    use super::*;
    use silentsilo_app::audit_admin::{OrgKeyTouch, expire_audit_segments};
    use silentsilo_app::audit_read::{Reader, read_audit_log};
    use zeroize::Zeroizing;

    fn touch(id: &str, byte: u8) -> OrgKeyTouch {
        OrgKeyTouch {
            credential_id: id.into(),
            wrap_key: Zeroizing::new([byte; 32]),
        }
    }

    fn reader(t: &OrgKeyTouch) -> Reader {
        Reader::Organisation {
            credential_id: t.credential_id.clone(),
            wrap_key: t.wrap_key.clone(),
        }
    }

    /// A device on a silo an organisation administers with three keys.
    fn org_device(host: &Copies) -> Device {
        let device = Device::new(host);
        device.administered_by(&[("aa", 1), ("bb", 2), ("cc", 3)]);
        device
    }

    #[tokio::test]
    async fn an_organisation_log_starts_only_with_one_of_the_silo_s_organisation_keys() {
        let host = Copies(Vec::new(), true);
        let device = Device::new(&host);
        let id = device.silo.id;
        assert!(
            device
                .state
                .start_org_audit_log(id, &touch("aa", 1), None)
                .is_err(),
            "a silo no organisation administers"
        );
        device.administered_by(&[("aa", 1)]);
        assert!(
            device
                .state
                .start_org_audit_log(id, &touch("aa", 2), None)
                .is_err(),
            "a touch that does not open the key's envelope"
        );
        assert!(
            device
                .state
                .start_org_audit_log(id, &touch("bb", 1), None)
                .is_err(),
            "a key the silo does not have"
        );
        assert!(
            device
                .state
                .start_org_audit_log(id, &touch("aa", 1), Some(30))
                .is_err(),
            "kept less than 90 days"
        );
        device
            .state
            .start_org_audit_log(id, &touch("aa", 1), None)
            .unwrap();
        assert!(device.state.audit_status(id).unwrap().organisation);
        assert!(
            device
                .state
                .add_org_audit_reader(id, &touch("aa", 1), &touch("dd", 4))
                .is_err(),
            "a reader the silo does not have"
        );
    }

    #[tokio::test]
    async fn a_retention_under_ninety_days_is_refused() {
        let host = Copies(Vec::new(), true);
        let device = org_device(&host);
        let id = device.silo.id;
        device
            .state
            .start_org_audit_log(id, &touch("aa", 1), Some(365))
            .unwrap();
        let err = device
            .state
            .set_org_audit_retention(id, Some(89))
            .unwrap_err();
        assert!(err.contains("err.audit_retention_short"), "{err}");
        assert_eq!(
            device.state.audit_status(id).unwrap().retention_days,
            Some(365)
        );
        device.state.set_org_audit_retention(id, Some(90)).unwrap();
        assert_eq!(
            device.state.audit_status(id).unwrap().retention_days,
            Some(90)
        );
    }

    #[tokio::test]
    async fn an_organisation_s_policy_on_a_silo_none_administers_is_not_taken_in() {
        let a = tempfile::tempdir().unwrap();
        let host = Copies(vec![copy(a.path())], false);
        let device = Device::new(&host);
        let store = FolderStore::new(a.path().to_path_buf());
        // Written by someone holding the content key: a log for a key of
        // their own, as an organisation's.
        let theirs = KeyPair::generate();
        let mut key = AuditKey::new(&theirs, Scope::Org, 1);
        key.wrap_for("aa", &theirs.private, &[9; 32]).unwrap();
        let policy = AuditPolicy::new(true, &theirs.id(), None, Scope::Org, 1);
        silentsilo_sync::audit_log::write_audit_key(&store, &key)
            .await
            .unwrap();
        silentsilo_sync::audit_log::write_audit_policy(&store, &device.kek(), &policy)
            .await
            .unwrap();
        run_sync_pass(&device.state, &host, &device.silo)
            .await
            .unwrap();
        assert!(device.spool().pinned().is_none());

        // On a silo an organisation does administer, a key naming none of
        // its keys is not its log either.
        device.administered_by(&[("bb", 2)]);
        run_sync_pass(&device.state, &host, &device.silo)
            .await
            .unwrap();
        assert!(device.spool().pinned().is_none());
    }

    #[tokio::test]
    async fn an_organisation_log_replaces_a_personal_one_and_only_its_keys_read_it() {
        let a = tempfile::tempdir().unwrap();
        let host = Copies(vec![copy(a.path())], true);
        let device = org_device(&host);
        let id = device.silo.id;
        device.state.set_audit_log(id, true).unwrap();
        let admin = touch("aa", 1);
        device
            .state
            .start_org_audit_log(id, &admin, Some(365))
            .unwrap();

        let status = device.state.audit_status(id).unwrap();
        assert!(status.enabled && status.organisation);
        assert_eq!(status.retention_days, Some(365));
        assert!(device.state.audit_is_mandatory(id));
        assert!(device.state.set_audit_log(id, false).is_err());
        assert!(
            device.state.start_org_audit_log(id, &admin, None).is_err(),
            "started once"
        );

        run_sync_pass(&device.state, &host, &device.silo)
            .await
            .unwrap();
        assert!(
            read_audit_log(&device.state, &host, &device.silo, &Reader::Silo)
                .await
                .is_err(),
            "the silo's own key does not read it"
        );
        let read = read_audit_log(&device.state, &host, &device.silo, &reader(&admin))
            .await
            .unwrap();
        assert_eq!(read.entries[0].event.c, codes::LOG_STARTED);
        // The personal log's records are sealed to its own key.
        assert_eq!(read.unreadable, 2);
    }

    #[tokio::test]
    async fn another_organisation_key_reads_it_and_ways_in_reach_every_copy() {
        let a = tempfile::tempdir().unwrap();
        let host = Copies(vec![copy(a.path())], true);
        let device = org_device(&host);
        let id = device.silo.id;
        let store = FolderStore::new(a.path().to_path_buf());
        let (first, second, third) = (touch("aa", 1), touch("bb", 2), touch("cc", 3));
        device
            .state
            .start_org_audit_log(id, &first, Some(365))
            .unwrap();
        device
            .state
            .add_org_audit_reader(id, &first, &second)
            .unwrap();
        assert!(
            device
                .state
                .add_org_audit_reader(id, &third, &third)
                .is_err(),
            "a key that does not read it cannot add one"
        );
        run_sync_pass(&device.state, &host, &device.silo)
            .await
            .unwrap();
        assert!(
            read_audit_log(&device.state, &host, &device.silo, &reader(&second))
                .await
                .is_ok()
        );

        // Another device added a third way in on the copy.
        let key_id = device.spool().key().unwrap().unwrap().key_id;
        let mut theirs = silentsilo_sync::audit_log::read_audit_key(&store, &key_id)
            .await
            .unwrap()
            .unwrap();
        let private = theirs.unwrap_with("aa", &[1; 32]).unwrap();
        theirs.wrap_for("cc", &private, &[3; 32]).unwrap();
        silentsilo_sync::audit_log::write_audit_key(&store, &theirs)
            .await
            .unwrap();
        // Due again, as it is every ten minutes.
        {
            let mut spool = device.spool();
            let (policy, key) = (
                spool.policy().unwrap().unwrap(),
                spool.key().unwrap().unwrap(),
            );
            spool.apply_policy(&policy, &key, 0).unwrap();
        }
        run_sync_pass(&device.state, &host, &device.silo)
            .await
            .unwrap();
        let here = device.spool().key().unwrap().unwrap();
        for (by, byte) in [("aa", 1), ("bb", 2), ("cc", 3)] {
            assert!(here.unwrap_with(by, &[byte; 32]).is_ok(), "{by}");
        }
        let there = silentsilo_sync::audit_log::read_audit_key(&store, &key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(there, here);
    }

    #[tokio::test]
    async fn segments_past_the_retention_are_removed_and_the_rest_kept() {
        let a = tempfile::tempdir().unwrap();
        let host = Copies(vec![copy(a.path())], true);
        let device = org_device(&host);
        let id = device.silo.id;
        let store = FolderStore::new(a.path().to_path_buf());
        let admin = touch("aa", 1);
        device.state.start_org_audit_log(id, &admin, None).unwrap();
        let public = device.spool().key().unwrap().unwrap().public().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let other = Uuid::new_v4();
        for (seq, age_days) in [(0u64, 120i64), (1, 60), (2, 1)] {
            let mut event = Event::new(codes::FILE_OPENED, now);
            event.i = seq;
            let segment = Segment {
                device: other,
                seq,
                prev: [0; 32],
                closed_at: now - age_days * 86_400_000,
                records: vec![silentsilo_audit::seal_event(&public, other, &event).unwrap()],
                tag: None,
            }
            .tag_with(&device.tags());
            store.put(&segment.key(), segment.to_bytes()).await.unwrap();
        }
        // An old one storage made up, tagged under a key it does not have.
        let mut forged = Segment::from_bytes(
            &store
                .get(&silentsilo_audit::segment_key(other, 0))
                .await
                .unwrap(),
        )
        .unwrap();
        forged.seq = 3;
        let forged = forged.tag_with(&SegmentKey::new(&[1; 32]));
        store.put(&forged.key(), forged.to_bytes()).await.unwrap();

        assert_eq!(
            expire_audit_segments(&device.state, &host, &device.silo)
                .await
                .unwrap(),
            0,
            "kept for good"
        );
        device.state.set_org_audit_retention(id, Some(90)).unwrap();
        assert_eq!(
            expire_audit_segments(&device.state, &host, &device.silo)
                .await
                .unwrap(),
            1,
            "only the one past 90 days, and not the forged one"
        );
        assert_eq!(segments_in(&store).await.len(), 3);
        let read = read_audit_log(&device.state, &host, &device.silo, &reader(&admin))
            .await
            .unwrap();
        assert!(
            read.entries
                .iter()
                .any(|e| e.event.c == codes::SEGMENTS_EXPIRED)
        );
    }

    /// Audit L1: a segment copied under another one's name is neither read
    /// as that one nor expired in its place.
    #[tokio::test]
    async fn a_segment_moved_under_another_name_is_not_taken_for_it() {
        let a = tempfile::tempdir().unwrap();
        let host = Copies(vec![copy(a.path())], true);
        let device = org_device(&host);
        let id = device.silo.id;
        let store = FolderStore::new(a.path().to_path_buf());
        let admin = touch("aa", 1);
        device.state.start_org_audit_log(id, &admin, None).unwrap();
        let public = device.spool().key().unwrap().unwrap().public().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let other = Uuid::new_v4();
        let mut segments = Vec::new();
        for (seq, age_days) in [(0u64, 120i64), (1, 1)] {
            let mut event = Event::new(codes::FILE_OPENED, now);
            event.i = seq;
            let segment = Segment {
                device: other,
                seq,
                prev: [0; 32],
                closed_at: now - age_days * 86_400_000,
                records: vec![silentsilo_audit::seal_event(&public, other, &event).unwrap()],
                tag: None,
            }
            .tag_with(&device.tags());
            store.put(&segment.key(), segment.to_bytes()).await.unwrap();
            segments.push(segment);
        }
        // The old segment over the recent one's name.
        store
            .put(&segments[1].key(), segments[0].to_bytes())
            .await
            .unwrap();

        let read = read_audit_log(&device.state, &host, &device.silo, &reader(&admin))
            .await
            .unwrap();
        let trail = read.devices.iter().find(|d| d.device == other).unwrap();
        assert_eq!(trail.events, 1, "read twice: {trail:?}");

        device.state.set_org_audit_retention(id, Some(90)).unwrap();
        assert_eq!(
            expire_audit_segments(&device.state, &host, &device.silo)
                .await
                .unwrap(),
            1,
            "only the genuine old one"
        );
        assert_eq!(
            store.get(&segments[1].key()).await.unwrap(),
            segments[0].to_bytes(),
            "left for the reader to name"
        );
    }
}
