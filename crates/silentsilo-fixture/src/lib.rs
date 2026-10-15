//! Builds a silo with something of every kind in it, and reads one back.
//! Development only. It exists so `fixtures/` can hold silos written by
//! past releases and every build can prove it still opens them.
//!
//! Two properties make it possible: storage can be a plain folder, so a
//! "bucket" commits to the repo, and a silo rebuilds from storage with
//! only a recovery code, so it runs headless.
//!
//! The corpus is awkward on purpose. Every entry has broken something or
//! is one platform away from it: the two Unicode spellings of a word,
//! names differing only in case, a name Windows refuses, replaced
//! content, things in the bin.
//!
//! Every fixture up to `v1.10.0` holds stand-ins for content: no blobs,
//! no keys file, and a silo that opens with its recovery code or its
//! device secret. `v1.10.1` and its twin, written by [`create_rich`], hold
//! the same corpus as a silo in use looks:
//!
//! - real blobs under real content keys, in the silo folder and in
//!   storage, for every file row and for one password attachment;
//! - one more password entry, carrying that attachment;
//! - `keys/fido.json` with three keys, each published to `keys/` as its
//!   envelope: the test authenticator's FIDO2 key, and a Secure Enclave and
//!   an Android Keystore key of the right shape. The last is marked
//!   `unconfirmed` in the silo folder, which publishing leaves out. Their
//!   wrap keys are fixed, see [`fixture_wrap_key`];
//! - `master.dek.enc` under the first key, as enrolment leaves it, so the
//!   device secret no longer opens the silo;
//! - `silo.json`;
//! - an inbox with its key, one sender (the Android key's device) and one
//!   photo waiting to be imported.
//!
//! What the content decrypts to is in `expected-content.txt` beside
//! `expected.txt`, from [`content_from_store`]. Content larger than one
//! chunk (4 MiB) is left to the unit tests, to keep the repository small.

use std::path::{Path, PathBuf};

use silentsilo_core::{CoreError, FileEntry};
use silentsilo_store::{ObjectStore, StoreConfig};
use silentsilo_vault::{
    Authority, StoredFidoCredential, StoredFidoKeys, VaultSession, load_recovery_envelope,
    save_recovery_envelope, unwrap_with_code,
};
use silentsilo_vfs::{Vfs, all_ops, pending_ops, replay};
use uuid::Uuid;

/// A stand-in for a wrapped content key.
///
/// The fixtures before `v1.10.1` never decrypt content, and a real wrapping
/// carries a random nonce, which would make the recorded bytes differ on
/// every run and turn a deterministic fixture into a coin toss. The rich
/// ones record what the content decrypts to instead.
const FIXTURE_BLOB_KEY: &str = "fixture-blob-key";

/// The code every fixture is sealed with. A fixed value on purpose: it is
/// written into the tests, and a fixture nobody can open is worse than none.
pub const FIXTURE_CODE: &str = "TEST-TEST-TEST-TEST-TEST-TEST-TEST-TEST";

/// Where the two halves of a fixture live under its directory.
pub fn silo_dir(root: &Path) -> PathBuf {
    root.join("silo")
}

pub fn store_dir(root: &Path) -> PathBuf {
    root.join("store")
}

fn store_at(root: &Path) -> Result<Box<dyn ObjectStore>, String> {
    StoreConfig::Folder {
        path: store_dir(root),
    }
    .open()
    .map_err(|e| e.to_string())
}

/// Writes a complete fixture: a silo, its storage, and a recovery envelope
/// that opens it.
pub async fn create(root: &Path) -> Result<(), String> {
    create_inner(root, false, false).await
}

/// The same corpus, compacted: a snapshot in the store and the records
/// below its horizon pruned. A separate fixture because the two prove
/// different things: without a committed compacted silo the snapshot
/// format has no golden bytes, and a break in it would pass every test
/// and then refuse a real archive.
pub async fn create_compacted(root: &Path) -> Result<(), String> {
    create_inner(root, true, false).await
}

/// The corpus with real content, keys, a marker and an inbox, as the
/// module documentation lists. First written as `v1.10.1`.
pub async fn create_rich(root: &Path) -> Result<(), String> {
    create_inner(root, false, true).await
}

/// [`create_rich`], compacted as [`create_compacted`] is.
pub async fn create_rich_compacted(root: &Path) -> Result<(), String> {
    create_inner(root, true, true).await
}

async fn create_inner(root: &Path, compact: bool, rich: bool) -> Result<(), String> {
    std::fs::create_dir_all(store_dir(root)).map_err(|e| e.to_string())?;
    let vault_id = Uuid::from_u128(0x5117_0000_0000_0000_0000_0000_0000_0001);

    let session = VaultSession::provision(silo_dir(root), vault_id, FIXTURE_DEVICE_SECRET)
        .map_err(|e| e.to_string())?;
    Vfs::new(&session)
        .ensure_initialized()
        .map_err(|e| e.to_string())?;
    let content = if rich {
        Content::Real(&session)
    } else {
        Content::StandIn
    };
    populate(&session, &content)?;
    if rich {
        add_attachment_entry(&session)?;
    }

    let store = store_at(root)?;
    silentsilo_sync::put_manifest(&*store, vault_id)
        .await
        .map_err(|e| e.to_string())?;

    // The content key wrapper, without which the blobs a future build finds
    // here are ciphertext it has no way into. A fixture that omits it is not
    // a backup, it is a tree.
    let kek_envelope =
        silentsilo_vault::wrap_kek_bytes(&session.kek, &session.dek).map_err(|e| e.to_string())?;
    silentsilo_sync::publish_content_kek(&*store, &kek_envelope)
        .await
        .map_err(|e| e.to_string())?;

    if rich {
        publish_rich(&session, &*store).await?;
    }

    let pending = pending_ops(&session.conn).map_err(|e| e.to_string())?;
    silentsilo_sync::push_ops(&*store, &session.dek, &pending)
        .await
        .map_err(|e| e.to_string())?;
    write_activity_log(&*store, &session).await?;

    if compact {
        // A horizon in the middle of the log, so the fixture holds both
        // halves of a compacted silo: state that exists only in the snapshot,
        // and records that still replay on top of it.
        let ops = all_ops(&session.conn).map_err(|e| e.to_string())?;
        let mut lamports: Vec<u64> = ops.iter().map(|r| r.lamport).collect();
        lamports.sort_unstable();
        lamports.dedup();
        let horizon = lamports[lamports.len() / 2];
        let snapshot = silentsilo_vfs::capture_at(&session.conn, vault_id, horizon)
            .map_err(|e| e.to_string())?;
        silentsilo_sync::publish_compaction(&*store, &session.dek, &snapshot, true)
            .await
            .map_err(|e| e.to_string())?;
    }

    // Sealed under a known code rather than a security key, which is what
    // lets the fixture be opened by a test with no hardware attached.
    let envelope =
        silentsilo_vault::seal_under_code_for_fixtures(&session.dek, FIXTURE_CODE, &session.kek)
            .map_err(|e| e.to_string())?;
    save_recovery_envelope(&session.paths.root, &envelope).map_err(|e| e.to_string())?;
    silentsilo_sync::push_recovery_envelope(&*store, &envelope)
        .await
        .map_err(|e| e.to_string())?;

    session.backup_locally().map_err(|e| e.to_string())?;
    Ok(())
}

/// Rebuilds the silo from storage alone, using only the recovery code, and
/// returns what it found.
///
/// Deliberately not a copy of the silo folder: the question a fixture answers
/// is whether a build years later can reconstruct a vault from a bucket and a
/// piece of paper, which is the only path that matters when the machine is
/// gone.
pub async fn digest_from_store(root: &Path, code: &str) -> Result<Vec<String>, String> {
    let rebuilt = rebuild_from_store(root, code).await?;
    let activity = activity_lines(&*rebuilt.store, &rebuilt.session.kek).await?;
    let mut lines = digest(&rebuilt.session.conn).map_err(|e| e.to_string())?;
    lines.extend(activity);
    Ok(lines)
}

/// A silo rebuilt from a fixture's storage, and the storage itself.
struct Rebuilt {
    // Declared before the directory it lives in, so it closes first.
    session: VaultSession,
    store: Box<dyn ObjectStore>,
    _scratch: tempfile::TempDir,
}

/// What [`digest_from_store`] and [`content_from_store`] both start from.
async fn rebuild_from_store(root: &Path, code: &str) -> Result<Rebuilt, String> {
    let store = store_at(root)?;
    let manifest = silentsilo_sync::read_manifest(&*store)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no manifest in the fixture store".to_string())?;
    let envelope = silentsilo_sync::fetch_recovery_envelope(&*store)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no recovery envelope in the fixture store".to_string())?;
    let dek = unwrap_with_code(&envelope, code).map_err(|e| e.to_string())?;

    let scratch = tempfile::tempdir().map_err(|e| e.to_string())?;
    // The fixture's own KEK, taken from the store like any joining device.
    // Replay never opens content, so a missing one is not fatal here: a
    // fresh key lets the replay proceed and proves the tree, which is what
    // this fixture is for.
    let kek = match silentsilo_sync::fetch_content_kek(&*store)
        .await
        .map_err(|e| e.to_string())?
    {
        Some(envelope) => {
            silentsilo_vault::unwrap_kek_bytes(&envelope, &dek).map_err(|e| e.to_string())?
        }
        None => silentsilo_crypto::generate_content_kek(),
    };
    let session = VaultSession::provision_with_dek(
        scratch.path().to_path_buf(),
        manifest.vault_id,
        "fixture-replay-device",
        dek.clone(),
        kek,
    )
    .map_err(|e| e.to_string())?;
    Vfs::new(&session)
        .ensure_initialized()
        .map_err(|e| e.to_string())?;

    // A compacted silo starts from its snapshot, exactly as the app's own
    // recovery does: the records below the horizon are gone from storage,
    // and replaying only what is left onto an empty tree would rebuild the
    // tail of the history rather than the silo.
    let snapshot = silentsilo_sync::latest_snapshot(&*store, &dek)
        .await
        .map_err(|e| e.to_string())?;
    let horizon = snapshot.as_ref().map(|s| s.horizon).unwrap_or(0);
    if let Some(snapshot) = snapshot {
        silentsilo_vfs::snapshot::restore(&session.conn, &snapshot).map_err(|e| e.to_string())?;
    }

    let ops = silentsilo_sync::fetch_all_ops_above(&*store, &dek, horizon)
        .await
        .map_err(|e| e.to_string())?;
    replay(&session.conn, ops).map_err(|e| e.to_string())?;

    Ok(Rebuilt {
        session,
        store,
        _scratch: scratch,
    })
}

/// A personal activity log as 1.9.0 first wrote it to storage: the key with
/// its private half wrapped under the content key, the sealed policy, and
/// one device's run of two chained segments.
async fn write_activity_log(store: &dyn ObjectStore, session: &VaultSession) -> Result<(), String> {
    use silentsilo_audit::{
        AuditKey, AuditPolicy, BY_SILO, Event, KeyPair, Scope, Segment, codes, seal_event,
    };
    let err = |e: silentsilo_audit::AuditError| e.to_string();
    let sync = |e: silentsilo_sync::SyncError| e.to_string();

    let keys = KeyPair::generate();
    let mut key = AuditKey::new(&keys, Scope::Silo, 1_789_000_000);
    key.wrap_for(BY_SILO, &keys.private, session.kek.as_bytes())
        .map_err(err)?;
    let policy = AuditPolicy::new(true, &keys.id(), None, Scope::Silo, 1_789_000_000)
        .tagged(&silentsilo_audit::PolicyKey::new(session.dek.as_bytes()));
    silentsilo_sync::audit_log::write_audit_key(store, &key)
        .await
        .map_err(sync)?;
    silentsilo_sync::audit_log::write_audit_policy(store, &session.kek, &policy)
        .await
        .map_err(sync)?;

    let device = Uuid::from_u128(0x5117_0000_0000_0000_0000_0000_0000_a0d1);
    let runs = [
        vec![
            Event::new(codes::LOG_STARTED, 0),
            Event::new(codes::UNLOCKED, 0).with("key", "YubiKey"),
        ],
        vec![
            Event::new(codes::SECRET_COPIED, 0)
                .on("00000000-0000-0000-0000-000000000024", "Ștampile SRL")
                .with("field", "password"),
            Event::new(codes::LOCKED, 0),
        ],
    ];
    let mut prev = [0u8; 32];
    let mut i = 0u64;
    for (seq, run) in runs.into_iter().enumerate() {
        let mut records = Vec::new();
        for mut event in run {
            event.i = i;
            event.t = 1_789_000_000_000 + i as i64 * 1000;
            records.push(seal_event(&keys.public, device, &event).map_err(err)?);
            i += 1;
        }
        let segment = Segment {
            device,
            seq: seq as u64,
            prev,
            closed_at: 1_789_000_000_000 + i as i64 * 1000,
            records,
            tag: None,
        }
        .tag_with(&silentsilo_audit::SegmentKey::new(session.kek.as_bytes()));
        prev = segment.hash();
        store
            .put(&segment.key(), segment.to_bytes())
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// The activity log a store holds, as sorted lines: its policy, every event
/// in it, and what the reading found wrong. Nothing for a store that keeps
/// none, which is every fixture written before 1.9.0.
async fn activity_lines(
    store: &dyn ObjectStore,
    kek: &silentsilo_crypto::ContentKek,
) -> Result<Vec<String>, String> {
    let sync = |e: silentsilo_sync::SyncError| e.to_string();
    let Some(policy) = silentsilo_sync::audit_log::read_audit_policy(store, kek)
        .await
        .map_err(sync)?
    else {
        return Ok(Vec::new());
    };
    let keys = silentsilo_sync::audit_log::read_silo_keys(store, kek)
        .await
        .map_err(sync)?;
    let held: Vec<(silentsilo_audit::KeyId, &[u8])> =
        keys.iter().map(|(id, k)| (*id, &k[..])).collect();
    let mut segments = Vec::new();
    for object in store
        .list(silentsilo_audit::AUDIT_PREFIX)
        .await
        .map_err(|e| e.to_string())?
    {
        if silentsilo_audit::parse_segment_key(&object.key).is_none() {
            continue;
        }
        let bytes = store.get(&object.key).await.map_err(|e| e.to_string())?;
        segments.push(silentsilo_audit::Segment::from_bytes(&bytes).map_err(|e| e.to_string())?);
    }
    let read = silentsilo_audit::reading::read_log(
        segments,
        &[],
        &held,
        &silentsilo_audit::SegmentKey::new(kek.as_bytes()),
    );

    let mut lines = vec![format!(
        "activity policy enabled={} scope={} retention={:?} keys={}",
        policy.enabled,
        serde_json::to_string(&policy.scope).map_err(|e| e.to_string())?,
        policy.retention_days,
        keys.len()
    )];
    for entry in &read.entries {
        let e = &entry.event;
        lines.push(format!(
            "activity event {} i={} t={} c={} o={} l={} x={}",
            entry.device,
            e.i,
            e.t,
            e.c,
            e.o.as_deref().unwrap_or(""),
            e.l.as_deref().unwrap_or(""),
            serde_json::to_string(&e.x).map_err(|e| e.to_string())?,
        ));
    }
    for trail in &read.devices {
        lines.push(format!(
            "activity trail {} events={} missing={:?} segments_missing={:?} broken={:?}",
            trail.device,
            trail.events,
            trail.missing_events,
            trail.missing_segments,
            trail.broken_segments
        ));
        // Only when there are any: the fixtures before tags have none.
        if !trail.refused_segments.is_empty() {
            lines.push(format!(
                "activity refused {} segments={:?}",
                trail.device, trail.refused_segments
            ));
        }
    }
    lines.push(format!("activity unreadable={}", read.unreadable));
    lines.sort();
    Ok(lines)
}

/// Opens the silo folder itself, the way an installed app does on the first
/// unlock after an update: recovery code to DEK, DEK over `vault.db.enc`.
///
/// The store never enters the picture, which is the point. `digest_from_store`
/// answers for the machine that is gone; this answers for the one that just
/// updated, which is every existing user. Pass a copy: unlocking writes a
/// working copy for this path.
pub fn digest_from_silo(silo: &Path, code: &str) -> Result<Vec<String>, String> {
    let envelope = load_recovery_envelope(silo).map_err(|e| e.to_string())?;
    let dek = unwrap_with_code(&envelope, code).map_err(|e| e.to_string())?;
    let session =
        VaultSession::open_with_dek(silo.to_path_buf(), dek).map_err(|e| e.to_string())?;
    digest_and_close(session)
}

/// What a session on a copied silo holds, then the working copy it wrote
/// gone.
pub fn digest_and_close(session: VaultSession) -> Result<Vec<String>, String> {
    let lines = digest(&session.conn).map_err(|e| e.to_string())?;
    let root = session.paths.root.clone();
    // The connection holds the working copy open; Windows will not delete
    // an open file. All of it goes: the copy is a throwaway.
    drop(session);
    silentsilo_vault::wipe_work_dir(&root);
    Ok(lines)
}

/// The secret every fixture's silo was provisioned with, which opens
/// `master.dek.enc` until a key is enrolled.
pub const FIXTURE_DEVICE_SECRET: &str = "fixture-device-secret";

/// Everything the vault holds, as sorted lines.
///
/// Lives in silentsilo-vfs now, because a test restore asks the same
/// question of a live silo that a fixture asks of an old one, and two copies
/// of this would drift into disagreeing about what "the same vault" means.
pub use silentsilo_vfs::digest;

/// The corpus. Every line here is a case that has broken something, or is
/// one platform away from breaking it.
fn populate(session: &VaultSession, content: &Content<'_>) -> Result<(), String> {
    let vfs = Vfs::new(session);
    let err = |e: CoreError| e.to_string();
    let root = vfs.root_folder_id().map_err(err)?;

    let docs = vfs.create_folder(root, "Acte").map_err(err)?;
    let nested = vfs.create_folder(docs.id, "2026").map_err(err)?;
    // Diacritics, so the fixture fails if Unicode handling ever changes.
    let stamps = vfs.create_folder(root, "Ștampile").map_err(err)?;

    let contract = content
        .add_file(
            &vfs,
            docs.id,
            "contract.pdf",
            Uuid::from_u128(0x11),
            2048,
            "hash-contract",
            Some("application/pdf"),
        )
        .map_err(err)?;
    let old = content
        .add_file(
            &vfs,
            nested.id,
            "vechi.txt",
            Uuid::from_u128(0x12),
            10,
            "hash-old",
            None,
        )
        .map_err(err)?;
    content
        .add_file(
            &vfs,
            root,
            "notițe.md",
            Uuid::from_u128(0x13),
            100,
            "hash-notes-first",
            Some("text/markdown"),
        )
        .map_err(err)?;
    // A file with no content at all: the size-zero edge that chunking gets
    // wrong first.
    content
        .add_file(
            &vfs,
            stamps.id,
            "gol.bin",
            Uuid::from_u128(0x14),
            0,
            "hash-empty",
            None,
        )
        .map_err(err)?;
    // A leading dot is a name, not an extension.
    content
        .add_file(
            &vfs,
            root,
            ".gitignore",
            Uuid::from_u128(0x15),
            7,
            "hash-dot",
            None,
        )
        .map_err(err)?;

    // Same name again, which replaces the content in place and supersedes
    // the first blob. Nothing collects that blob, which is exactly what M2
    // will have to deal with, and the fixture is where it will show up.
    content
        .add_file(
            &vfs,
            root,
            "notițe.md",
            Uuid::from_u128(0x16),
            250,
            "hash-notes-second",
            Some("text/markdown"),
        )
        .map_err(err)?;

    vfs.set_file_favorite(contract.id, true).map_err(err)?;
    vfs.set_folder_favorite(docs.id, true).map_err(err)?;
    vfs.trash_file(old.id).map_err(err)?;

    vfs.upsert_password(
        Uuid::from_u128(0x21),
        r#"{"id":"00000000-0000-0000-0000-000000000021","service":"bank","username":"alex"}"#,
    )
    .map_err(err)?;
    vfs.upsert_password(
        Uuid::from_u128(0x22),
        r#"{"id":"00000000-0000-0000-0000-000000000022","service":"mail","username":"alex"}"#,
    )
    .map_err(err)?;

    // Renames: the record carries the new name, and replay must land on it,
    // not on the one it was created under.
    let draft = content
        .add_file(
            &vfs,
            docs.id,
            "ciornă.txt",
            Uuid::from_u128(0x17),
            64,
            "hash-draft",
            None,
        )
        .map_err(err)?;
    vfs.rename_file(draft.id, "final.txt").map_err(err)?;
    let temp = vfs.create_folder(root, "Temp").map_err(err)?;
    vfs.rename_folder(temp.id, "Arhivă").map_err(err)?;

    // A folder in the bin with its file still inside it.
    let bin = vfs.create_folder(root, "Vechituri").map_err(err)?;
    content
        .add_file(
            &vfs,
            bin.id,
            "ruginit.dat",
            Uuid::from_u128(0x18),
            5,
            "hash-rust",
            None,
        )
        .map_err(err)?;
    vfs.trash_folder(bin.id).map_err(err)?;

    // Trashed and brought back: the restore must undo the trash exactly.
    vfs.trash_file(draft.id).map_err(err)?;
    vfs.restore_file(draft.id).map_err(err)?;

    // Purged outright. The id must stay gone at replay, not come back as a
    // file whose blob no longer exists.
    let ephemeral = content
        .add_file(
            &vfs,
            root,
            "efemer.tmp",
            Uuid::from_u128(0x19),
            3,
            "hash-tmp",
            None,
        )
        .map_err(err)?;
    vfs.trash_file(ephemeral.id).map_err(err)?;
    vfs.purge_items(&[ephemeral.id]).map_err(err)?;

    // An entry as 1.4 writes it: custom fields, one hidden, an earlier
    // version, and an SSH key the agent may offer. Opaque to core, carried
    // whole forever.
    vfs.upsert_password(
        Uuid::from_u128(0x24),
        r#"{"id":"00000000-0000-0000-0000-000000000024","service":"Ștampile SRL","username":"ana","password":"new-pass","url":"","notes":"","category":"","created_at":1789000000000,"updated_at":1789000100000,"type":"ssh_key","ssh_agent":true,"fields":[{"name":"Customer number","value":"40021","hidden":false},{"name":"Card PIN","value":"1234","hidden":true}],"history":[{"saved_at":1789000000000,"service":"Ștampile SRL","username":"ana","password":"old-pass"}]}"#,
    )
    .map_err(err)?;

    // A password that was deleted: deletion is a record, not an absence.
    vfs.upsert_password(
        Uuid::from_u128(0x23),
        r#"{"id":"00000000-0000-0000-0000-000000000023","service":"old","username":"x"}"#,
    )
    .map_err(err)?;
    vfs.delete_password(Uuid::from_u128(0x23)).map_err(err)?;

    // What a machine says about itself, and what someone renamed it to.
    // Decoration, but decoration that has to replay forever.
    vfs.announce_device(Some("FIXTURE-PC"), "Windows 11 Pro")
        .map_err(err)?;
    let this_device = silentsilo_vfs::device_id(&session.conn).map_err(err)?;
    vfs.set_device_label(this_device, "Biroul").map_err(err)?;

    // A name typed in decomposed Unicode (s + U+0326), the spelling macOS
    // produces. The stored name must come out precomposed, on every
    // platform, forever.
    content
        .add_file(
            &vfs,
            root,
            "s\u{0326}iret.txt",
            Uuid::from_u128(0x1A),
            9,
            "hash-nfd",
            None,
        )
        .map_err(err)?;

    // Sanity: the corpus has to be big enough to be worth comparing.
    let ops = all_ops(&session.conn).map_err(err)?;
    if ops.len() < 25 {
        return Err(format!("the corpus is too thin: {} operations", ops.len()));
    }
    Ok(())
}

// ── The rich fixture ────────────────────────────────────────────────

/// Where the corpus's file content comes from.
enum Content<'a> {
    /// Stand-ins: no blob, [`FIXTURE_BLOB_KEY`] and the hash given. Every
    /// fixture before `v1.10.1`.
    StandIn,
    /// A real blob in the silo folder under a real content key, holding
    /// [`fixture_bytes`] of the file's name and size.
    Real(&'a VaultSession),
}

impl Content<'_> {
    /// `Vfs::add_file`, with the stand-in arguments every earlier fixture
    /// was written with, or with the content's real key and hash.
    #[allow(clippy::too_many_arguments)]
    fn add_file(
        &self,
        vfs: &Vfs,
        folder_id: Uuid,
        name: &str,
        blob_id: Uuid,
        size: i64,
        stand_in_hash: &str,
        mime_type: Option<&str>,
    ) -> Result<FileEntry, CoreError> {
        match self {
            Content::StandIn => vfs.add_file(
                folder_id,
                name,
                blob_id,
                size,
                stand_in_hash,
                mime_type,
                FIXTURE_BLOB_KEY,
            ),
            Content::Real(session) => {
                let plain = fixture_bytes(name, size as usize);
                let (hash, key) =
                    seal_content(session, blob_id, &plain).map_err(CoreError::Crypto)?;
                vfs.add_file(folder_id, name, blob_id, size, &hash, mime_type, &key)
            }
        }
    }
}

/// The plaintext of a file in the rich fixture: its name and a newline,
/// repeated to its size. Fixed by the corpus, and different per file, so a
/// blob opened under the wrong row shows.
pub fn fixture_bytes(name: &str, size: usize) -> Vec<u8> {
    name.bytes()
        .chain(std::iter::once(b'\n'))
        .cycle()
        .take(size)
        .collect()
}

/// Seals `plain` into the silo folder as `blob_id` under a fresh content
/// key, as an import does. Returns the content hash and the wrapped key.
fn seal_content(
    session: &VaultSession,
    blob_id: Uuid,
    plain: &[u8],
) -> Result<(String, String), String> {
    let key = silentsilo_crypto::generate_content_key();
    let wrapped =
        silentsilo_crypto::wrap_content_key(&key, &session.kek).map_err(|e| e.to_string())?;
    let sealed = silentsilo_crypto::encrypt_stream(
        &mut { plain },
        &session.paths.blob_path(blob_id),
        &key,
        Uuid::new_v4(),
        blob_id,
    )
    .map_err(|e| e.to_string())?;
    Ok((hex::encode(sealed.header.content_hash), wrapped))
}

const ATTACHMENT_ENTRY: u128 = 0x25;
const ATTACHMENT_BLOB: u128 = 0x31;
const ATTACHMENT_NAME: &str = "scanare.pdf";

/// A password entry with a file attached: the one blob no file row names.
fn add_attachment_entry(session: &VaultSession) -> Result<(), String> {
    let plain = fixture_bytes(ATTACHMENT_NAME, 1500);
    let (_, blob_key) = seal_content(session, Uuid::from_u128(ATTACHMENT_BLOB), &plain)?;
    let entry = serde_json::json!({
        "id": Uuid::from_u128(ATTACHMENT_ENTRY).to_string(),
        "service": "Primăria",
        "username": "ana",
        "password": "parola-de-test",
        "url": "",
        "notes": "",
        "category": "",
        "created_at": 1_789_000_000_000_i64,
        "updated_at": 1_789_000_000_000_i64,
        "attachments": [{
            "blob_id": Uuid::from_u128(ATTACHMENT_BLOB).to_string(),
            "name": ATTACHMENT_NAME,
            "size_bytes": plain.len(),
            "blob_key": blob_key,
        }],
    });
    Vfs::new(session)
        .upsert_password(Uuid::from_u128(ATTACHMENT_ENTRY), &entry.to_string())
        .map_err(|e| e.to_string())
}

/// What a silo in use has besides its records: content in storage, keys,
/// the marker and an inbox.
async fn publish_rich(session: &VaultSession, store: &dyn ObjectStore) -> Result<(), String> {
    let root = &session.paths.root;

    // Every blob a row or an entry names goes up. The superseded and the
    // purged ones go, as a sweep would take them.
    let mut named: std::collections::HashSet<Uuid> = Vfs::new(session)
        .blob_keys()
        .map_err(|e| e.to_string())?
        .into_keys()
        .collect();
    named.insert(Uuid::from_u128(ATTACHMENT_BLOB));
    let blobs = std::fs::read_dir(session.paths.blobs_dir()).map_err(|e| e.to_string())?;
    for entry in blobs {
        let path = entry.map_err(|e| e.to_string())?.path();
        let Some(blob_id) = path
            .file_stem()
            .and_then(|s| Uuid::parse_str(&s.to_string_lossy()).ok())
        else {
            continue;
        };
        if named.contains(&blob_id) {
            let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
            store
                .put(&format!("blobs/{blob_id}.sslo"), bytes)
                .await
                .map_err(|e| e.to_string())?;
        } else {
            std::fs::remove_file(&path).map_err(|e| e.to_string())?;
        }
    }

    let keys = fixture_keys(session.vault_id, &session.dek)?;
    silentsilo_vault::save_fido_keys(root, &keys, Authority::Machine).map_err(|e| e.to_string())?;
    // The first key enrolled takes `master.dek.enc` over, as enrolment does.
    let first = fixture_wrap_key(session.vault_id, &keys.keys[0])
        .ok_or_else(|| "the first key has no fixture wrap key".to_string())?;
    silentsilo_vault::save_dek(root, &session.dek, &first).map_err(|e| e.to_string())?;
    silentsilo_sync::publish_key_envelopes(store, &keys, true)
        .await
        .map_err(|e| e.to_string())?;
    silentsilo_vault::write_marker(root, session.vault_id).map_err(|e| e.to_string())?;

    send_inbox_item(session, store, &keys.keys[2].credential_id).await
}

/// The test authenticator's secret and credential id, as the soft backend
/// of `silentsilo-fido` (feature `test-authenticator`) holds them. Its wrap
/// key is BLAKE3 keyed by the secret over the credential id followed by
/// `silentsilo-dek-v1:{vault_id}`, so a debug build with that backend
/// opens the fixture with its key.
const SOFT_AUTHENTICATOR_SECRET: &[u8; 32] = b"silentsilo-test-authenticator-01";
const SOFT_KEY_ID: &[u8] = b"soft-key-0";

/// The context the fixture's device key wrap keys are derived under:
/// `blake3::derive_key(DEVICE_WRAP_CONTEXT, credential id bytes)`. No
/// enclave or Keystore is involved; the entries only have the shape real
/// ones have.
const DEVICE_WRAP_CONTEXT: &str = "silentsilo fixture device wrap key v1";

/// A Secure Enclave credential id: 16-byte tag, then a 65-byte point.
fn enclave_key_id() -> Vec<u8> {
    [&b"fixture-enclave1"[..], &[0x04], &[0xe5; 64]].concat()
}

/// An Android Keystore credential id: 16-byte tag, 12-byte nonce, then 48
/// bytes of wrapped key and tag.
fn keystore_key_id() -> Vec<u8> {
    [&b"fixture-keystore"[..], &[0xa5; 12], &[0x5a; 48]].concat()
}

/// The fixed wrap key that opens a fixture key's `wrapped_dek`, or `None`
/// for a key the fixture did not write.
pub fn fixture_wrap_key(vault_id: Uuid, key: &StoredFidoCredential) -> Option<[u8; 32]> {
    let id = hex::decode(&key.credential_id).ok()?;
    if id == SOFT_KEY_ID {
        let mut hasher = blake3::Hasher::new_keyed(SOFT_AUTHENTICATOR_SECRET);
        hasher.update(&id);
        hasher.update(format!("silentsilo-dek-v1:{vault_id}").as_bytes());
        return Some(*hasher.finalize().as_bytes());
    }
    (id == enclave_key_id() || id == keystore_key_id())
        .then(|| blake3::derive_key(DEVICE_WRAP_CONTEXT, &id))
}

/// The rich fixture's three keys, each wrapping `dek` under its
/// [`fixture_wrap_key`].
pub fn fixture_keys(
    vault_id: Uuid,
    dek: &silentsilo_crypto::MasterDek,
) -> Result<StoredFidoKeys, String> {
    let entry =
        |kind: &str, derivation: &str, id: Vec<u8>, slot: u8, label: &str| StoredFidoCredential {
            kind: kind.into(),
            derivation: derivation.into(),
            policy: String::new(),
            credential_id: hex::encode(id),
            public_key: String::new(),
            key_slot: slot,
            rp_id: "silentsilo.com".into(),
            label: label.into(),
            wrapped_dek: String::new(),
            platform: kind != silentsilo_vault::KIND_FIDO2,
            revoked: false,
            unconfirmed: false,
        };
    let mut keys = vec![
        entry(
            silentsilo_vault::KIND_FIDO2,
            silentsilo_vault::DERIVATION_HMAC_V1,
            SOFT_KEY_ID.to_vec(),
            0,
            "Cheia de test",
        ),
        entry(
            silentsilo_vault::KIND_SECURE_ENCLAVE,
            silentsilo_vault::DERIVATION_ECDH_P256_V1,
            enclave_key_id(),
            1,
            "MacBook Touch ID",
        ),
        entry(
            silentsilo_vault::KIND_ANDROID_KEYSTORE,
            silentsilo_vault::DERIVATION_KEYSTORE_AES_GCM_V1,
            keystore_key_id(),
            2,
            "Telefonul Anei",
        ),
    ];
    // Taken in from storage and not used here yet. Local only: the
    // published envelope leaves it out.
    keys[2].unconfirmed = true;
    for key in &mut keys {
        let wrap = fixture_wrap_key(vault_id, key).ok_or("no wrap key")?;
        let wrapped = silentsilo_vault::wrap_dek_bytes(dek, &wrap).map_err(|e| e.to_string())?;
        key.wrapped_dek = hex::encode(wrapped);
    }
    Ok(StoredFidoKeys { keys })
}

const INBOX_SENDER: u128 = 0x5117_0000_0000_0000_0000_0000_0000_5e4d;
const INBOX_ITEM: u128 = 0x5117_0000_0000_0000_0000_0000_0000_0041;
const INBOX_NAME: &str = "IMG_0001.jpg";

/// One photo from the phone the Android key belongs to, waiting in the
/// inbox for an unlocked device to import it.
async fn send_inbox_item(
    session: &VaultSession,
    store: &dyn ObjectStore,
    credential_id: &str,
) -> Result<(), String> {
    use silentsilo_sync::inbox::{
        INBOX_VERSION, OutgoingItem, SenderIdentity, SenderRecord, ensure_inbox_key,
        register_sender, send_item,
    };
    let sync = |e: silentsilo_sync::SyncError| e.to_string();

    let (key_id, inbox_public) = ensure_inbox_key(store, &session.kek).await.map_err(sync)?;
    let signer =
        silentsilo_crypto::inbox::EcSecret::from_bytes([0x22; 32]).map_err(|e| e.to_string())?;
    let sender_id = Uuid::from_u128(INBOX_SENDER);
    let record = SenderRecord {
        version: INBOX_VERSION,
        sender_id,
        public_key: hex::encode(signer.public_key()),
        credential_id: credential_id.to_string(),
        label: "Telefonul Anei".into(),
        created_at: 1_789_000_000,
    };
    register_sender(store, &session.kek, &record)
        .await
        .map_err(sync)?;

    let source = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    std::fs::write(source.path(), fixture_bytes(INBOX_NAME, 333)).map_err(|e| e.to_string())?;
    let identity = SenderIdentity {
        vault_id: session.vault_id,
        sender_id,
        key_id,
        inbox_public,
    };
    let item = OutgoingItem {
        item_id: Uuid::from_u128(INBOX_ITEM),
        source: source.path(),
        name: INBOX_NAME.into(),
        mime_type: Some("image/jpeg".into()),
        taken_at: Some(1_789_000_000),
        folder: vec!["Telefon".into(), "Poze".into()],
        source_kind: "photos".into(),
    };
    send_item(store, &identity, &item, &|message| Ok(signer.sign(message)))
        .await
        .map_err(sync)
}

/// What the content in a fixture's storage decrypts to, as sorted lines:
/// a BLAKE3 per file, password entry, attachment and inbox item, and per
/// key envelope whether its fixture wrap key opens the vault key.
///
/// From storage and the recovery code alone, like [`digest_from_store`].
/// Only the rich fixtures have content to read; on the others this fails
/// at the first stand-in key.
pub async fn content_from_store(root: &Path, code: &str) -> Result<Vec<String>, String> {
    let rebuilt = rebuild_from_store(root, code).await?;
    let session = &rebuilt.session;
    let store = &*rebuilt.store;
    let staging = tempfile::tempdir().map_err(|e| e.to_string())?;
    let mut lines = Vec::new();

    for (path, blob_id, blob_key, hash, deleted) in file_rows(&session.conn)? {
        let blob_id = Uuid::parse_str(&blob_id).map_err(|e| e.to_string())?;
        let object = format!("blobs/{blob_id}.sslo");
        let plain = open_content(store, &staging, &object, blob_id, &blob_key, &hash, session)
            .await
            .map_err(|e| format!("{path}: {e}"))?;
        lines.push(format!(
            "content file {path} deleted={} {}",
            u8::from(deleted),
            described(&plain)
        ));
    }

    for json in Vfs::new(session)
        .list_passwords()
        .map_err(|e| e.to_string())?
    {
        let entry: serde_json::Value = serde_json::from_str(&json).map_err(|e| e.to_string())?;
        let id = entry["id"].as_str().unwrap_or_default().to_string();
        lines.push(format!(
            "content password {id} blake3={}",
            blake3::hash(json.as_bytes()).to_hex()
        ));
        for attachment in entry["attachments"].as_array().into_iter().flatten() {
            let name = attachment["name"].as_str().unwrap_or_default();
            let blob_id = Uuid::parse_str(attachment["blob_id"].as_str().unwrap_or_default())
                .map_err(|e| e.to_string())?;
            let blob_key = attachment["blob_key"].as_str().unwrap_or_default();
            let object = format!("blobs/{blob_id}.sslo");
            let plain = open_content(store, &staging, &object, blob_id, blob_key, "", session)
                .await
                .map_err(|e| format!("attachment {name}: {e}"))?;
            lines.push(format!(
                "content attachment {id}::{name} {}",
                described(&plain)
            ));
        }
    }

    for key in silentsilo_sync::fetch_key_envelopes(store)
        .await
        .map_err(|e| e.to_string())?
    {
        let opens = fixture_wrap_key(session.vault_id, &key)
            .and_then(|wrap| silentsilo_vault::unwrap_dek_hex(&key.wrapped_dek, &wrap).ok())
            .is_some_and(|dek| dek.as_bytes() == session.dek.as_bytes());
        lines.push(format!(
            "content key {} {} slot={} platform={} label={} opens={opens}",
            key.kind, key.derivation, key.key_slot, key.platform, key.label
        ));
    }

    let scan = silentsilo_sync::inbox::scan_inbox(store, session.vault_id, &session.kek)
        .await
        .map_err(|e| e.to_string())?;
    for item in &scan.ready {
        let blob_key = item.blob_key(&session.kek).map_err(|e| e.to_string())?;
        let object = format!(
            "{}{}.sslo",
            silentsilo_sync::inbox::INBOX_ITEMS_PREFIX,
            item.item_id
        );
        let plain = open_content(
            store,
            &staging,
            &object,
            item.blob_id,
            &blob_key,
            &item.content_hash,
            session,
        )
        .await
        .map_err(|e| format!("inbox {}: {e}", item.name))?;
        lines.push(format!(
            "content inbox {}::{} sender={} source={} mime={} taken_at={:?} {}",
            item.folder.join("/"),
            item.name,
            item.sender_label,
            item.source,
            item.mime_type.as_deref().unwrap_or(""),
            item.taken_at,
            described(&plain)
        ));
    }
    for refused in &scan.refused {
        lines.push(format!(
            "content inbox refused {} {}",
            refused.object, refused.reason
        ));
    }

    lines.sort();
    Ok(lines)
}

/// Path, blob id, wrapped key, content hash and trashed, per file row.
type FileRow = (String, String, String, String, bool);

fn file_rows(conn: &rusqlite::Connection) -> Result<Vec<FileRow>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT fo.path || '::' || f.name, f.blob_id, COALESCE(f.blob_key, ''),
                    COALESCE(f.content_hash, ''), f.deleted_at IS NOT NULL
               FROM files f JOIN folders fo ON fo.id = f.folder_id",
        )
        .map_err(|e| e.to_string())?;
    stmt.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        ))
    })
    .map_err(|e| e.to_string())?
    .collect::<Result<Vec<_>, _>>()
    .map_err(|e| e.to_string())
}

fn described(plain: &[u8]) -> String {
    format!(
        "bytes={} blake3={}",
        plain.len(),
        blake3::hash(plain).to_hex()
    )
}

/// One blob from storage, opened with its wrapped key and checked against
/// the hash its record holds.
async fn open_content(
    store: &dyn ObjectStore,
    staging: &tempfile::TempDir,
    object: &str,
    blob_id: Uuid,
    blob_key: &str,
    recorded_hash: &str,
    session: &VaultSession,
) -> Result<Vec<u8>, String> {
    let key =
        silentsilo_crypto::unwrap_content_key(blob_key, &session.kek).map_err(|e| e.to_string())?;
    let sealed = staging.path().join(format!("{blob_id}.sslo"));
    let plain = staging.path().join(format!("{blob_id}.plain"));
    store
        .get_to_file(object, &sealed)
        .await
        .map_err(|e| e.to_string())?;
    silentsilo_crypto::decrypt_file(&sealed, &plain, &key, blob_id, recorded_hash)
        .map_err(|e| e.to_string())?;
    std::fs::read(&plain).map_err(|e| e.to_string())
}

// ── The fixture manifest ────────────────────────────────────────────

/// Where the SHA-256 of every committed fixture file is kept, in the
/// format `sha256sum` writes: `<hex>  <path under fixtures/>`.
pub const SUMS_FILE: &str = "SHA256SUMS";

/// The fixtures directory of this crate.
pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// One `sha256sum` line per file under `dir`, with paths relative to
/// `fixtures`, sorted by path. The bytes are hashed as stored:
/// `.gitattributes` marks every fixture file binary, so no checkout
/// rewrites a line ending.
pub fn sums(fixtures: &Path, dir: &Path) -> Result<Vec<String>, String> {
    use sha2::Digest as _;
    let mut lines = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).map_err(|e| e.to_string())? {
            let path = entry.map_err(|e| e.to_string())?.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let relative = path
                .strip_prefix(fixtures)
                .map_err(|e| e.to_string())?
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
            lines.push((
                relative.clone(),
                format!("{}  {relative}", hex::encode(sha2::Sha256::digest(&bytes))),
            ));
        }
    }
    lines.sort();
    Ok(lines.into_iter().map(|(_, line)| line).collect())
}
