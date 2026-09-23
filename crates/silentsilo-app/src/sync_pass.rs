//! One sync pass, in the order the desktop's `docs/ARCHITECTURE.md`
//! describes and for the reasons given there.

use std::sync::atomic::{AtomicBool, Ordering};

use silentsilo_store::ObjectStore;
use silentsilo_sync as sync;
use silentsilo_vault::{SiloEntry, load_fido_keys};
use silentsilo_vfs::{
    OpRecord, Vfs, highest_applied_lamport, mark_delivered, pending_ops_for, record_target_failure,
    record_target_success, replay, settle_delivery, target_last_success, target_retry_in,
};
use uuid::Uuid;

use crate::{AppEvent, AppState, Host};

/// What the last sync pass did, for the status bar.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct SyncReport {
    /// Which silo this pass was about. The background loop reaches every
    /// open silo, so a screen reacting to these has to know which one it is
    /// being told about: the rebuild prompt in particular outlives the
    /// screen that raised it, and answering it against the wrong silo
    /// rebuilds a silo nobody asked about.
    #[serde(default)]
    pub silo_id: String,
    pub configured: bool,
    pub ops_pushed: usize,
    pub ops_fetched: usize,
    pub ops_applied: usize,
    pub blobs_uploaded: usize,
    /// Blobs pulled down because this device keeps a full copy. Reported so
    /// the status line can say why a quiet pass moved gigabytes.
    pub blobs_fetched: usize,
    pub blobs_failed: usize,
    /// Content a file points at that a copy had lost, put back from this
    /// device or another copy.
    #[serde(default)]
    pub blobs_restored: usize,
    /// Entries another device's changes forced a rename on, so the UI can
    /// tell the user rather than letting a file quietly change name.
    pub renamed: Vec<String>,
    /// This device fell behind a compaction and has to be rebuilt from the
    /// current state before it can sync again. A field rather than an
    /// error: the silo is healthy, this copy is stale.
    pub needs_rebuild: bool,
    /// The silo's key was rotated from another device and this one was not
    /// kept. Nothing was pushed or pulled: it has to rejoin with a current
    /// credential or the recovery code.
    #[serde(default)]
    pub needs_rejoin: bool,
    /// The silo's content key in storage does not open with this device's
    /// key, while the records beside it still do. A rotation cannot leave a
    /// target that way, so the object was replaced or put back from an older
    /// copy. Nothing was pushed, and rejoining would not help: the storage
    /// is what has to be fixed. Separate from `needs_rejoin` because the
    /// screen has to say something else entirely.
    #[serde(default)]
    pub key_material_replaced: bool,
    /// Records dropped from the bucket by a compaction this pass ran, so the
    /// status line can say the log got shorter rather than leaving the user
    /// wondering what the extra work was.
    pub compacted: usize,
    /// One entry per configured target, so a second copy that is falling
    /// behind can be seen rather than averaged away.
    #[serde(default)]
    pub targets: Vec<TargetStatus>,
    /// True when another pass was already running and this one stood down.
    /// Nothing was attempted, so the counters are zero for a reason that has
    /// nothing to do with being up to date. Without this the UI reads those
    /// zeroes as "Already up to date." while an upload is still in flight.
    #[serde(default)]
    pub skipped: bool,
    /// Operation objects that could not be read, with why. They do not stop
    /// the pass, but records above the lowest of them wait; see `held_back`.
    #[serde(default)]
    pub unreadable: Vec<String>,
    /// Readable records not applied yet because an unreadable object sits
    /// below them in the log. Retried on every pass.
    #[serde(default)]
    pub held_back: usize,
    /// Items a locked device sent that this pass recorded as files.
    #[serde(default)]
    pub inbox_imported: usize,
    /// Items left in an inbox, with why: an unknown sender, a removed key, a
    /// newer format.
    #[serde(default)]
    pub inbox_refused: Vec<String>,
}

/// Where a running pass is, for a status line and a marker on the file being
/// moved. A pass ends with its `SyncReport`, which is also the signal that
/// nothing is moving any more.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncProgress {
    pub silo_id: String,
    /// `sending-changes`, `uploading`, `fetching-changes`, `downloading` or
    /// `importing`.
    pub phase: &'static str,
    /// How many of `total` came before this step.
    pub done: usize,
    pub total: usize,
    /// How much of the file this step moves has moved, and how big it is.
    /// Both zero where the step is not one file's bytes: a status line on a
    /// single large upload needs these, since `done` stands still for the
    /// whole of it.
    pub bytes_done: u64,
    pub bytes_total: u64,
    /// The file this step moves, when it is one the silo lists.
    pub file_id: Option<String>,
    pub name: Option<String>,
    /// The copy an upload is going to, when there is more than one.
    pub target: Option<String>,
}

/// Tells the interface where the pass is. A blob is named by the file it
/// belongs to, read without touching the silo's idle timer: a background
/// pass is not use.
///
/// `named` is what the last report resolved, so a blob reporting its bytes
/// several times looks its file up once: the lookup takes the session lock,
/// and taking it four times a second for a gigabyte would be this reporting
/// its own progress into the way of everything else.
#[allow(clippy::too_many_arguments)]
fn report_progress(
    state: &AppState,
    host: &dyn Host,
    silo_id: Uuid,
    phase: &'static str,
    step: ProgressStep,
    blob_id: Option<Uuid>,
    named: &mut Option<(Uuid, Option<(Uuid, String)>)>,
    target: Option<&str>,
) {
    let file = match blob_id {
        None => None,
        Some(blob) => {
            if named.as_ref().is_none_or(|(seen, _)| *seen != blob) {
                let found = (|| {
                    let sessions = state.sessions.lock().ok()?;
                    let session = sessions.get(&silo_id)?;
                    Vfs::new(session).file_for_blob(blob).ok().flatten()
                })();
                *named = Some((blob, found));
            }
            named.as_ref().and_then(|(_, file)| file.clone())
        }
    };
    host.emit(AppEvent::SyncProgress(SyncProgress {
        silo_id: silo_id.to_string(),
        phase,
        done: step.done,
        total: step.total,
        bytes_done: step.bytes_done,
        bytes_total: step.bytes_total,
        file_id: file.as_ref().map(|(id, _)| id.to_string()),
        name: file.map(|(_, name)| name),
        target: target.map(str::to_string),
    }));
}

/// The four numbers a progress report carries, so the call does not take
/// four bare integers in a row.
#[derive(Debug, Default, Clone, Copy)]
struct ProgressStep {
    done: usize,
    total: usize,
    bytes_done: u64,
    bytes_total: u64,
}

impl ProgressStep {
    /// A step counted in items rather than bytes.
    fn counted(done: usize, total: usize) -> Self {
        Self {
            done,
            total,
            ..Self::default()
        }
    }
}

/// Records go by in the thousands; a status line needs a tenth of that.
fn worth_saying(done: usize, total: usize) -> bool {
    done.is_multiple_of(10) || done + 1 == total
}

/// How one target fared this pass, so "the second one is behind" can be said
/// rather than hidden behind a single green tick.
#[derive(Debug, Clone, serde::Serialize)]
pub struct TargetStatus {
    pub id: String,
    /// What the user called it, or what the store says about itself.
    pub label: String,
    pub ops_pushed: usize,
    pub blobs_uploaded: usize,
    /// Why this target got nothing this pass. `None` means it kept up.
    pub failed: Option<String>,
    /// Unix seconds of the last pass this target accepted everything, or 0
    /// if it never has. The screen turns this into "last written 47 days
    /// ago", which is a fact someone can act on, unlike a red dot that has
    /// been red since a disk went in a drawer.
    pub last_success: i64,
    /// Seconds until this target is worth trying again, 0 when it is due
    /// now. Non-zero means this pass deliberately left it alone.
    pub retry_in: i64,
    /// True when the pass skipped it rather than tried and failed.
    pub waiting: bool,
    /// Records this target is still owed. Counted per target, because "12
    /// changes not backed up" is only true of the target that is missing
    /// them.
    pub ops_behind: usize,
}

/// A pass someone asked for: every backoff cleared, and a background pass
/// already running waited out rather than reported as nothing to do.
pub async fn sync_now(
    state: &AppState,
    host: &dyn Host,
    silo: &SiloEntry,
) -> Result<SyncReport, String> {
    // Pressing the button clears every backoff timer first. The wait exists
    // to stop this device hammering a target that is not answering, which is
    // not the situation when someone is sitting there asking for a pass now.
    let configured = host.targets(silo.id);
    if let Ok(sessions) = state.sessions.lock()
        && let Some(session) = sessions.get(&silo.id)
    {
        for target in &configured {
            let _ = silentsilo_vfs::reset_target_backoff(&session.conn, target.config.target_id());
        }
    }
    // Someone pressed a button and is owed an answer about their own silo, so
    // a background pass already running is waited out rather than reported as
    // nothing to do. Bounded: a pass that never finishes must not leave the
    // button spinning for the rest of the session.
    wait_for_pass_to_finish(state, WAIT_FOR_PASS).await;
    run_sync_pass(state, host, silo).await
}

/// How long a pressed Sync waits for a pass already running.
const WAIT_FOR_PASS: std::time::Duration = std::time::Duration::from_secs(90);

async fn wait_for_pass_to_finish(state: &AppState, limit: std::time::Duration) {
    let deadline = std::time::Instant::now() + limit;
    while state.sync_in_flight.load(Ordering::SeqCst) {
        if std::time::Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

/// Guards a pass so only one runs at a time.
///
/// Released on drop, so an error or an early return can't leave sync wedged
/// off for the rest of the session.
struct SyncGuard<'a>(&'a AtomicBool);

impl<'a> SyncGuard<'a> {
    fn acquire(flag: &'a AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .ok()
            .map(|_| Self(flag))
    }
}

impl Drop for SyncGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// A target opened and ready to talk to, with what it is called.
struct OpenTarget {
    id: uuid::Uuid,
    label: String,
    store: Box<dyn ObjectStore>,
    /// What this target in particular has not received yet. Read per target
    /// rather than shared, so an unplugged disk's backlog is not offered to
    /// a bucket that already took it.
    owed: Vec<OpRecord>,
    /// Whether the app may send this target a delete at all. Checked before
    /// every deletion rather than relying on the storage to refuse: a target
    /// meant to be append-only should not depend on a bucket policy being
    /// configured correctly for that to hold.
    role: silentsilo_vault::TargetRole,
    last_success: i64,
}

/// Syncs one silo, named rather than assumed: more than one can be open,
/// and the background pass has to reach all of them.
pub async fn run_sync_pass(
    state: &AppState,
    host: &dyn Host,
    silo: &SiloEntry,
) -> Result<SyncReport, String> {
    let configured = host.targets(silo.id);
    if configured.is_empty() {
        return Ok(SyncReport::default());
    }

    // Two passes at once would each read the same pending queue and send it
    // twice. Skipping is right rather than queueing: the pass already
    // running will pick up whatever this one would have sent.
    let Some(_guard) = SyncGuard::acquire(&state.sync_in_flight) else {
        return Ok(SyncReport {
            configured: true,
            skipped: true,
            ..SyncReport::default()
        });
    };
    let root = silo.path.clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let every_target: Vec<Uuid> = configured.iter().map(|t| t.config.target_id()).collect();

    // Everything the network phase needs is read up front, then the lock is
    // released, so a slow upload never blocks the UI. What each target is
    // owed is read per target: one shared queue would let a disk in a
    // drawer decide what the bucket is offered.
    let (due, dek, kek, vault_id, applied_through, base, known) = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        let session = sessions
            .get(&silo.id)
            .ok_or_else(|| "Unlock the silo before syncing.".to_string())?;
        let conn = &session.conn;

        let mut due = Vec::new();
        for id in &every_target {
            due.push((
                *id,
                pending_ops_for(conn, *id).map_err(|e| e.to_string())?,
                target_last_success(conn, *id).map_err(|e| e.to_string())?,
                target_retry_in(conn, *id, now).map_err(|e| e.to_string())?,
            ));
        }
        (
            due,
            session.dek.clone(),
            session.kek.clone(),
            session.vault_id,
            highest_applied_lamport(conn).map_err(|e| e.to_string())?,
            silentsilo_vfs::snapshot::read_base(conn).map_err(|e| e.to_string())?,
            silentsilo_vfs::all_op_ids(conn).map_err(|e| e.to_string())?,
        )
    };
    let local_horizon = base.as_ref().map(|s| s.horizon).unwrap_or(0);

    // A target whose settings will not open is reported, not skipped in
    // silence. A target inside its backoff window is left alone and says
    // so.
    let mut targets: Vec<OpenTarget> = Vec::new();
    let mut resting: Vec<TargetStatus> = Vec::new();
    for (target, (id, owed, last_success, retry_in)) in configured.iter().zip(due) {
        let mut status = TargetStatus {
            id: id.to_string(),
            label: target.label.clone(),
            ops_pushed: 0,
            blobs_uploaded: 0,
            failed: None,
            last_success,
            retry_in,
            waiting: retry_in > 0,
            ops_behind: owed.len(),
        };
        if retry_in > 0 {
            resting.push(status);
            continue;
        }
        match target.config.open() {
            Ok(store) => {
                let label = if target.label.is_empty() {
                    store.describe()
                } else {
                    target.label.clone()
                };
                targets.push(OpenTarget {
                    id,
                    label,
                    store,
                    owed,
                    role: target.role,
                    last_success,
                });
            }
            Err(e) => {
                status.failed = Some(e.to_string());
                resting.push(status);
            }
        }
    }
    if targets.is_empty() {
        // Nothing was written, so nothing settles. Failures are still
        // recorded: a target whose settings will not open should back off
        // like any other, or a broken config means a pass every ten seconds
        // for as long as it stays broken.
        record_target_outcomes(state, silo, &resting, now)?;
        return Ok(announce(
            host,
            silo,
            SyncReport {
                configured: true,
                targets: resting,
                ..SyncReport::default()
            },
        ));
    }

    // Asked before anything is sent: a device behind the horizon would push
    // records nobody will ever apply, and tell this user their work was
    // saved. The lowest horizon across targets decides it.
    let stores: Vec<&dyn ObjectStore> = targets.iter().map(|t| &*t.store).collect();
    let horizon = match sync::lowest_snapshot_horizon(&stores).await {
        Ok(horizon) => horizon,
        // Every target opened and none answered: a drive that is not
        // plugged in, a server that is down. Each one fails and backs off.
        Err(e) => {
            let failed: Vec<TargetStatus> = targets
                .iter()
                .map(|t| TargetStatus {
                    id: t.id.to_string(),
                    label: t.label.clone(),
                    ops_pushed: 0,
                    blobs_uploaded: 0,
                    failed: Some(e.to_string()),
                    last_success: t.last_success,
                    retry_in: 0,
                    waiting: false,
                    ops_behind: t.owed.len(),
                })
                .collect();
            resting.extend(failed);
            record_target_outcomes(state, silo, &resting, now)?;
            return Ok(announce(
                host,
                silo,
                SyncReport {
                    configured: true,
                    targets: resting,
                    ..SyncReport::default()
                },
            ));
        }
    };
    // What this device received, not the highest record it holds: its own
    // records count in the latter. Before a complete fetch has recorded a
    // watermark, the old bound.
    let received = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        sessions
            .get(&silo.id)
            .and_then(|s| silentsilo_vfs::snapshot::received_through(&s.conn).ok())
            .flatten()
    };
    let known_through = received.unwrap_or(applied_through);
    let mut behind = false;
    if horizon > local_horizon && known_through <= horizon {
        // The listing's word for the horizon is only a name. Checked against
        // the snapshots themselves before a rebuild is asked for: a copy
        // under a higher name would ask for one on every pass.
        // Targets whose listing is below `horizon` were left out of it as
        // stale, and are left out here too.
        let mut verified: Option<u64> = None;
        for target in &targets {
            if !matches!(sync::snapshot_horizon(&*target.store).await, Ok(h) if h >= horizon) {
                continue;
            }
            if let Ok(found) = sync::verified_snapshot_horizon(&*target.store, &dek).await {
                verified = Some(verified.map_or(found, |v| v.min(found)));
            }
        }
        behind = verified.is_some_and(|v| v > local_horizon && known_through <= v);
    }
    // The received mark can pass a horizon that still hides records this
    // device never saw: written offline long ago, sent late, and folded into
    // a snapshot and pruned before it fetched them. Once per new horizon,
    // what its own log says is held against the snapshot.
    if !behind && horizon > local_horizon {
        behind = missed_below_horizon(state, silo, &targets, &dek, vault_id, local_horizon).await?;
    }
    if behind {
        return Ok(announce(
            host,
            silo,
            SyncReport {
                configured: true,
                needs_rebuild: true,
                ..SyncReport::default()
            },
        ));
    }

    // Also before anything is sent: a device whose key was rotated away on
    // another machine must not push. Its records would be sealed under a
    // key nobody else holds, and its stale KEK envelope would overwrite the
    // rotated one in the bucket. Every copy that answers is asked and the
    // gravest answer wins: a copy that missed the rotation still says
    // current, and letting it decide pushed its stale envelope over the
    // rotated one.
    //
    // Never-delete copies vote only on a silo that has no other kind. A
    // rotation does not touch them, so to a device on the new key they
    // always look rotated: counting them sent that device to rejoin in a
    // loop, and letting them decide while the working copy was unplugged
    // did the same.
    let has_working = configured.iter().any(|t| t.role.allows_delete());
    let mut states = Vec::new();
    let mut archive_states = Vec::new();
    let mut retired: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    for target in &targets {
        // Unreachable: it has no say, and the push below fails on it.
        let Ok(state) = sync::kek_envelope_state(&*target.store, &dek).await else {
            continue;
        };
        // Records here open under this key and the content key does not,
        // which no rotation produces.
        if state == sync::KekState::Replaced {
            host.warn(
                "keys",
                &format!(
                    "{}: the silo's content key there does not open with this device's key, \
                     while the records beside it do. A rotation cannot do that, so the object \
                     was replaced or put back from an older copy. Nothing was sent.",
                    target.label
                ),
            );
        }
        if target.role.allows_delete() {
            states.push(state);
        } else {
            if has_working && state == sync::KekState::Rotated {
                retired.insert(target.id);
            }
            archive_states.push(state);
        }
    }
    let deciding = if has_working {
        gravest_kek_state(&states)
    } else {
        archive_states.first().copied()
    };
    match deciding {
        Some(sync::KekState::Rotated) => {
            return Ok(announce(
                host,
                silo,
                SyncReport {
                    configured: true,
                    needs_rejoin: true,
                    ..SyncReport::default()
                },
            ));
        }
        // Rejoining reads the same object, so telling the user to rejoin
        // would send them round a loop that cannot end.
        Some(sync::KekState::Replaced) => {
            return Ok(announce(
                host,
                silo,
                SyncReport {
                    configured: true,
                    key_material_replaced: true,
                    ..SyncReport::default()
                },
            ));
        }
        // Current somewhere and nothing worse, or nothing to compare against
        // yet (a new silo, a copy caught mid-overwrite).
        _ => {}
    }

    // A never-delete copy that does not open under this key, on a silo with
    // working copies, was left under the key a replacement retired. It
    // takes nothing from this key again, so it is left out of the pass
    // rather than failed and waited on: waiting held the inbox, the sweep
    // and compaction for as long as it stayed configured.
    let mut retired_statuses = Vec::new();
    targets.retain(|t| {
        if !retired.contains(&t.id) {
            return true;
        }
        retired_statuses.push(TargetStatus {
            id: t.id.to_string(),
            label: t.label.clone(),
            ops_pushed: 0,
            blobs_uploaded: 0,
            failed: Some(RETIRED_COPY.into()),
            last_success: t.last_success,
            retry_in: 0,
            waiting: true,
            ops_behind: t.owed.len(),
        });
        false
    });
    let live_targets = every_target.len() - retired.len();

    // Other devices' keys in, and this device's revocations out as markers,
    // before the push publishes anything: publishing first would put back a
    // key another device just revoked. Never on a silo with no keys file.
    let mut marked: std::collections::HashSet<String> = std::collections::HashSet::new();
    if silentsilo_vault::is_fido_enrolled(&root)
        && let Ok(mut local) = load_fido_keys(&root)
    {
        let mut changed = false;
        for target in &targets {
            match sync::reconcile_key_envelopes(&*target.store, &kek, &mut local, now).await {
                Ok(outcome) => {
                    changed |= outcome.changed();
                    marked.extend(outcome.marked);
                }
                Err(e) => host.warn("keys", &format!("{}: {e}", target.label)),
            }
        }
        if changed
            && let Err(e) = silentsilo_vault::save_fido_keys(
                &root,
                &local,
                silentsilo_vault::Authority::Machine,
            )
        {
            host.warn("keys", &format!("could not save the reconciled keys: {e}"));
        }
    }

    // ── Out, to every target ────────────────────────────────────────
    // Each target is pushed to on its own: `push_ops` asks whether a record
    // is already there, and a wrapper answering for all of them would skip
    // the target that is missing it.
    let mut statuses = resting;
    let mut ops_pushed = 0;
    let mut blobs_uploaded = 0;
    let mut blobs_failed = 0;

    // Read once rather than per target: the same bytes go to each copy, and
    // the key file is re-read only when a revocation changes it.
    let kek_envelope = silentsilo_vault::wrap_kek_bytes(&kek, &dek).map_err(|e| e.to_string())?;
    // Turned off elsewhere stays off; made elsewhere since is kept.
    let recovery_targets: Vec<(&dyn ObjectStore, bool)> = targets
        .iter()
        .map(|t| (&*t.store, t.role.allows_delete()))
        .collect();
    let settled = sync::settle_recovery_envelope(&recovery_targets, &kek, &root).await;
    if settled.refused_unauthenticated {
        host.warn(
            "recovery",
            "a newer recovery envelope in storage carries no tag from this silo, \
             so the code this device holds was kept. Check for a device still on \
             an older release before changing the recovery code.",
        );
    }
    let recovery = settled.envelope;
    let mut keys = load_fido_keys(&root).ok();

    let several_copies = targets.len() > 1;
    // Targets that took everything they were owed. Kept apart from the
    // status, which a later failed fetch also marks: what was delivered
    // stays delivered, and the fetch failure is still reported.
    let mut pushed_to: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    for target in &targets {
        let silo_state = sync::SiloState {
            vault_id,
            dek: &dek,
            kek_envelope: &kek_envelope,
            recovery: recovery.as_ref(),
            keys: keys.as_ref(),
            base: base.as_ref(),
            vault_root: &root,
        };
        // What the last blob report resolved to a file, so several reports
        // about one blob cost one lookup.
        let mut named = None;
        let outcome = sync::push_everything_to_reporting(
            &sync::TargetPush {
                id: target.id,
                store: &*target.store,
                allows_delete: target.role.allows_delete(),
                owed: &target.owed,
            },
            &silo_state,
            &mut |step| match step {
                sync::PushStep::Ops { done, total } => {
                    if worth_saying(done, total) {
                        report_progress(
                            state,
                            host,
                            silo.id,
                            "sending-changes",
                            ProgressStep::counted(done, total),
                            None,
                            &mut named,
                            None,
                        );
                    }
                }
                sync::PushStep::Blob(blob) => report_progress(
                    state,
                    host,
                    silo.id,
                    "uploading",
                    ProgressStep {
                        done: blob.done,
                        total: blob.total,
                        bytes_done: blob.bytes_done,
                        bytes_total: blob.bytes_total,
                    },
                    Some(blob.blob_id),
                    &mut named,
                    several_copies.then_some(target.label.as_str()),
                ),
            },
        )
        .await;

        // A revocation storage has now confirmed, with its marker in place
        // for the other devices: the tombstone has done its job and the local
        // list can drop it.
        if !outcome.revoked.is_empty()
            && let Some(list) = keys.as_mut()
        {
            list.keys.retain(|k| {
                !(outcome.revoked.contains(&k.credential_id) && marked.contains(&k.credential_id))
            });
            // Dropping tombstones only. The keys being forgotten here were
            // already retired, with whatever proof that took at the time, so
            // this takes nothing away that the silo still had.
            silentsilo_vault::save_fido_keys(&root, list, silentsilo_vault::Authority::Machine)
                .map_err(|e| e.to_string())?;
        }

        ops_pushed += outcome.ops_pushed;
        blobs_uploaded += outcome.blobs_uploaded;
        blobs_failed += outcome.blobs_failed;
        if outcome.failed.is_none() {
            pushed_to.insert(target.id);
        }
        statuses.push(TargetStatus {
            id: target.id.to_string(),
            label: target.label.clone(),
            ops_pushed: outcome.ops_pushed,
            blobs_uploaded: outcome.blobs_uploaded,
            // Everything it was owed either arrived this pass or was already
            // there; `push_ops` skips what the target already holds.
            ops_behind: if outcome.failed.is_some() {
                target.owed.len()
            } else {
                0
            },
            failed: outcome.failed,
            last_success: 0,
            retry_in: 0,
            waiting: false,
        });
    }

    // ── In, from every target ───────────────────────────────────────
    //
    // A record may exist on one target and not another, so all of them are
    // read and the results replayed together. Replay is idempotent and order
    // independent, which is what makes reading the same record twice free.
    let mut incoming = Vec::new();
    let mut unreadable: Vec<sync::UnreadableOp> = Vec::new();
    let mut fetch_failed = false;
    let mut misplaced: Vec<String> = Vec::new();
    let mut listed_through = 0u64;
    for target in &targets {
        match sync::fetch_missing_ops_reporting(
            &*target.store,
            &dek,
            &known,
            local_horizon,
            &mut |done, total| {
                if worth_saying(done, total) {
                    report_progress(
                        state,
                        host,
                        silo.id,
                        "fetching-changes",
                        ProgressStep::counted(done, total),
                        None,
                        &mut None,
                        None,
                    );
                }
            },
        )
        .await
        {
            Ok(mut got) => {
                incoming.append(&mut got.records);
                unreadable.append(&mut got.unreadable);
                misplaced.append(&mut got.misplaced);
                listed_through = listed_through.max(got.listed_through);
            }
            Err(e) => {
                fetch_failed = true;
                if let Some(status) = statuses.iter_mut().find(|s| s.id == target.id.to_string())
                    && status.failed.is_none()
                {
                    status.failed = Some(format!("Could not read changes from it: {e}"));
                }
            }
        }
    }
    // An object unreadable on one copy but fetched intact from another is
    // not a hole in the log.
    for key in &misplaced {
        host.warn(
            "sync",
            &format!("{key} holds a record under another name; skipped"),
        );
    }
    let fetched_ids: std::collections::HashSet<Uuid> = incoming.iter().map(|r| r.op_id).collect();
    unreadable.retain(|u| u.op_id.is_none_or(|id| !fetched_ids.contains(&id)));
    let (incoming, held_back) = sync::usable_prefix(incoming, &unreadable);
    // Everything every copy holds was read and nothing is held back.
    let view_complete =
        !fetch_failed && unreadable.is_empty() && held_back == 0 && targets.len() == live_targets;
    let fetched = incoming.len();
    for u in &unreadable {
        host.warn("sync", &format!("{} could not be read: {}", u.key, u.error));
    }

    let replayed = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        let session = sessions
            .get(&silo.id)
            .ok_or_else(|| "The silo was locked during the sync.".to_string())?;
        let report = replay(&session.conn, incoming).map_err(|e| e.to_string())?;
        if view_complete {
            silentsilo_vfs::snapshot::record_received_through(&session.conn, listed_through)
                .map_err(|e| e.to_string())?;
        }

        // Written down per target, after the write and never before: a
        // record noted as delivered without having arrived is one this
        // device will never offer again.
        //
        // All of it in one transaction, across every target. `mark_delivered`
        // takes a savepoint of its own and nests inside this one, so this is
        // the only commit the sessions mutex pays for. Rolling back on the
        // way out is the safe direction: the next pass offers the records
        // again, finds them in storage and marks them then.
        let delivery = session
            .conn
            .unchecked_transaction()
            .map_err(|e| e.to_string())?;
        for target in &targets {
            if pushed_to.contains(&target.id) {
                mark_delivered(&session.conn, target.id, &target.owed)
                    .map_err(|e| e.to_string())?;
            }
        }
        delivery.commit().map_err(|e| e.to_string())?;
        report
    };

    // `pushed` gates local pruning as well as re-sending, so it may only be
    // set once every configured target holds the record. Compaction dropping
    // something one target never received would leave it permanently short,
    // with no local copy left to offer. A target removed from the list stops
    // being waited for, which is what makes this terminate.
    {
        let mut sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        if let Some(session) = sessions.get_mut(&silo.id) {
            settle_delivery(&mut session.conn, &every_target).map_err(|e| e.to_string())?;
        }
    }
    // The same accounting for content. Both tables also drop what they hold
    // for a target that is no longer configured, so removing a copy and
    // adding another leaves nothing claiming the new one is up to date.
    silentsilo_vault::settle_blob_delivery(&root, &every_target).map_err(|e| e.to_string())?;
    // Content a purge left here for the push, now that every copy has it.
    let referenced = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        sessions
            .get(&silo.id)
            .and_then(|session| Vfs::new(session).referenced_blobs_with_attachments().ok())
    };
    if let Some(referenced) = referenced {
        let _ = silentsilo_vault::drop_delivered_unreferenced(&root, &referenced);
    }
    record_target_outcomes(state, silo, &statuses, now)?;

    // ── The inbox ───────────────────────────────────────────────────
    //
    // After the push, so an item recorded by an earlier pass has had its
    // record sent before it may leave the inbox. With more than one copy the
    // content comes down too, for the next push to spread.
    let every_copy_reached =
        statuses.len() == live_targets && statuses.iter().all(|s| s.failed.is_none() && !s.waiting);
    statuses.extend(retired_statuses);
    let inbox_targets: Vec<crate::inbox_import::InboxTarget<'_>> = targets
        .iter()
        .map(|t| crate::inbox_import::InboxTarget {
            id: t.id,
            store: &*t.store,
            label: &t.label,
            may_finish: every_copy_reached && t.role.allows_delete(),
        })
        .collect();
    let inbox = crate::inbox_import::import_inbox(
        &crate::inbox_import::Session { state, id: silo.id },
        &|detail: &str| host.warn("inbox", detail),
        &root,
        &inbox_targets,
        &kek,
        vault_id,
        every_target.len() > 1,
        &|done: usize, total: usize| {
            report_progress(
                state,
                host,
                silo.id,
                "importing",
                ProgressStep::counted(done, total),
                None,
                &mut None,
                None,
            )
        },
    )
    .await;

    // ── Housekeeping ────────────────────────────────────────────────
    //
    // Content is fetched from whichever copy has it: a blob is the same
    // bytes everywhere, so there is nothing to choose between them, and the
    // first target being behind must not stop a full copy from filling up.
    let reachable: Vec<(Uuid, &dyn ObjectStore)> =
        targets.iter().map(|t| (t.id, &*t.store)).collect();
    sync::recheck_absent_blobs(&reachable, &root).await;
    let pulled =
        fetch_missing_for_full_copy(state, host, silo, &reachable, every_copy_reached).await;
    // What came down, from the inbox or for the full copy, is on the copy it
    // came from, and no longer counts as waiting to back up there.
    if pulled > 0 || inbox.imported > 0 {
        let _ = silentsilo_vault::settle_blob_delivery(&root, &every_target);
    }

    // Both steps below act on what this device believes the silo holds:
    // compaction drops records under its snapshot, and the sweep deletes
    // content nothing references. With a record held back, unreadable, or
    // on a copy that could not be read, that belief is short. Files others
    // added would look unreferenced and have their content deleted, and the
    // records missing here would be pruned from storage. Neither runs then.

    // Compaction publishes to each target before pruning it, which
    // `publish_compaction` guarantees for the target it is given. A target
    // that fails keeps its whole log, which is safe: it simply has more
    // history than it needs.
    let compacted = if view_complete {
        run_compaction(state, silo, &targets, &dek, vault_id).await?
    } else {
        0
    };

    // The sweep exists to delete, so an append-only target is skipped
    // outright rather than swept and refused. Content that nothing
    // references staying there for ever is what that role means, and the
    // Copies panel says so instead of the sweep pretending to run.
    let mut blobs_restored = 0;
    if view_complete {
        for target in targets.iter().filter(|t| t.role.allows_delete()) {
            blobs_restored +=
                run_blob_sweep(state, host, silo, (target.id, &*target.store), &reachable).await?;
        }
    }

    let report = SyncReport {
        silo_id: silo.id.to_string(),
        configured: true,
        ops_pushed,
        ops_fetched: fetched,
        ops_applied: replayed.applied,
        blobs_uploaded,
        blobs_fetched: pulled,
        blobs_failed,
        blobs_restored,
        renamed: replayed
            .renamed
            .iter()
            .map(|(from, to)| format!("{from} → {to}"))
            .collect(),
        needs_rebuild: false,
        needs_rejoin: false,
        key_material_replaced: false,
        compacted,
        targets: statuses,
        skipped: false,
        unreadable: unreadable
            .iter()
            .map(|u| format!("{}: {}", u.key, u.error))
            .collect(),
        held_back,
        inbox_imported: inbox.imported,
        inbox_refused: inbox.refused,
    };

    // The file list is stale the moment remote changes land.
    if report.ops_applied > 0 || report.inbox_imported > 0 {
        host.emit(AppEvent::VaultChanged);
    }

    Ok(announce(host, silo, report))
}

/// Publishes what a pass came to, and hands it back.
///
/// Every return from `run_sync_pass` goes through this, including the two
/// that give up before any target is touched. Anything reporting per-target
/// state goes stale the instant a background pass finishes, and the only
/// clue was that leaving the page and coming back fixed it.
///
/// `needs_rebuild` is the reason this is not simply the last line of the
/// function. That answer used to return early and emit nothing, so a device
/// that had fallen behind a compaction sat there syncing nothing in either
/// direction every two minutes, in silence, and only said so if the user
/// happened to press Sync by hand.
fn announce(host: &dyn Host, silo: &SiloEntry, report: SyncReport) -> SyncReport {
    let report = SyncReport {
        silo_id: silo.id.to_string(),
        ..report
    };
    host.emit(AppEvent::SyncReport(report.clone()));
    report
}

/// Writes down how each target the pass actually tried came out. Success
/// is a timestamp, failure lengthens the backoff. Targets the pass
/// deliberately skipped are left alone: counting a skip as a failure would
/// leave a disk plugged back in unwritten for hours.
/// Whether a snapshot above this device's base holds something its own log
/// does not at the same horizon. The horizon last found to agree is kept in
/// `vault_meta`, so each one is fetched and replayed once.
async fn missed_below_horizon(
    state: &AppState,
    silo: &SiloEntry,
    targets: &[OpenTarget],
    dek: &silentsilo_crypto::MasterDek,
    vault_id: Uuid,
    local_horizon: u64,
) -> Result<bool, String> {
    const CHECKED: &str = "snapshot_checked_through";
    let checked: u64 = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        let Some(session) = sessions.get(&silo.id) else {
            return Ok(false);
        };
        session
            .conn
            .query_row(
                "SELECT value FROM vault_meta WHERE key = ?1",
                [CHECKED],
                |r| r.get::<_, String>(0),
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    for target in targets {
        match sync::snapshot_horizon(&*target.store).await {
            Ok(h) if h > local_horizon.max(checked) => {}
            _ => continue,
        }
        let Ok(Some(theirs)) = sync::latest_snapshot(&*target.store, dek).await else {
            continue;
        };
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        let Some(session) = sessions.get(&silo.id) else {
            return Ok(false);
        };
        let Ok(mine) = silentsilo_vfs::state_at(&session.conn, vault_id, theirs.horizon) else {
            continue;
        };
        if silentsilo_vfs::holds_more(&theirs, &mine) {
            return Ok(true);
        }
        session
            .conn
            .execute(
                "INSERT OR REPLACE INTO vault_meta(key, value) VALUES (?1, ?2)",
                [CHECKED, &theirs.horizon.to_string()],
            )
            .map_err(|e| e.to_string())?;
    }
    Ok(false)
}

/// Why a never-delete copy left under a replaced key gets nothing.
pub const RETIRED_COPY: &str = "Kept under the encryption key that was replaced, so it gets no new \
     backups. Remove it and add a new never-delete copy.";

/// The answer that decides when copies disagree about the content key:
/// rotated before replaced before current before absent. A rotation seen on
/// any copy means this device's key is retired, whatever an older copy says.
fn gravest_kek_state(states: &[sync::KekState]) -> Option<sync::KekState> {
    let rank = |state: &sync::KekState| match state {
        sync::KekState::Rotated => 3,
        sync::KekState::Replaced => 2,
        sync::KekState::Current => 1,
        sync::KekState::Absent => 0,
    };
    states.iter().copied().max_by_key(rank)
}

fn record_target_outcomes(
    state: &AppState,
    silo: &SiloEntry,
    statuses: &[TargetStatus],
    now: i64,
) -> Result<(), String> {
    let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
    let Some(session) = sessions.get(&silo.id) else {
        return Ok(());
    };
    for status in statuses {
        if status.waiting {
            continue;
        }
        let Ok(id) = Uuid::parse_str(&status.id) else {
            continue;
        };
        if status.failed.is_some() {
            record_target_failure(&session.conn, id, now).map_err(|e| e.to_string())?;
        } else {
            record_target_success(&session.conn, id, now).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Downloads whatever this device is missing, when it is meant to hold a
/// full copy. Bounded per pass so a hundred-gigabyte silo does not hold
/// the sync loop for hours; every following pass carries on where this one
/// stopped. Failures are counted rather than raised.
async fn fetch_missing_for_full_copy(
    state: &AppState,
    host: &dyn Host,
    silo: &SiloEntry,
    stores: &[(Uuid, &dyn ObjectStore)],
    every_copy: bool,
) -> usize {
    if !silentsilo_vault::keep_full_copy(&silo.path) {
        return 0;
    }

    // The blob directory is walked before the lock, not under it: on a full
    // copy it is thousands of entries, and every command waits on that lock.
    // Content no copy holds would be asked for, and fail, every pass.
    let root = silo.path.clone();
    let listed = tokio::task::spawn_blocking(move || {
        silentsilo_vault::list_local_blob_ids(&root)
            .into_iter()
            .chain(silentsilo_vault::list_absent_blob_ids(&root))
            .collect::<std::collections::HashSet<Uuid>>()
    })
    .await;
    let Ok(here) = listed else {
        return 0;
    };
    let missing: Vec<Uuid> = {
        let Ok(sessions) = state.sessions.lock() else {
            return 0;
        };
        let Some(session) = sessions.get(&silo.id) else {
            return 0;
        };
        // With attachments: a full copy that left them out would restore
        // every file and no attachment.
        match Vfs::new(session).referenced_blobs_with_attachments() {
            Ok(referenced) => referenced.difference(&here).copied().collect(),
            Err(_) => return 0,
        }
    };

    let mut fetched = 0;
    let batch: Vec<Uuid> = missing.into_iter().take(FULL_COPY_FETCH_PER_PASS).collect();
    let mut named = None;
    for (done, blob_id) in batch.iter().copied().enumerate() {
        report_progress(
            state,
            host,
            silo.id,
            "downloading",
            ProgressStep::counted(done, batch.len()),
            Some(blob_id),
            &mut named,
            None,
        );
        // One object that will not come down must not stop the rest. It was
        // a `break`, so a single blob missing from the bucket, or one whose
        // bytes are damaged, held every later blob back on every pass
        // afterwards: a device asked to keep a full copy never became one
        // and never said why.
        match sync::fetch_blob_from_targets(stores, &silo.path, blob_id, every_copy).await {
            Ok(_) => fetched += 1,
            Err(e) => host.warn("sync", &format!("blob {blob_id} did not come down: {e}")),
        }
    }
    fetched
}

/// How many blobs one pass will pull when catching a full copy up.
///
/// Enough that a small silo completes in one go, small enough that a large
/// one does not hold the loop for an hour before anything else gets a turn.
const FULL_COPY_FETCH_PER_PASS: usize = 50;

/// Shortens the log if it has grown enough to be worth it. Run only at the
/// end of a pass that just succeeded, which is what entitles this device to
/// declare records deletable. Three phases because the vault connection
/// cannot be held across an await. Failures are swallowed: compaction is
/// housekeeping and the next pass proposes the same work again.
async fn run_compaction(
    state: &AppState,
    silo: &SiloEntry,
    targets: &[OpenTarget],
    dek: &silentsilo_crypto::MasterDek,
    vault_id: uuid::Uuid,
) -> Result<usize, String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let policy = silentsilo_vfs::CompactionPolicy::default();

    let planned = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        let Some(session) = sessions.get(&silo.id) else {
            return Ok(0);
        };
        sync::plan_compaction(&session.conn, vault_id, &policy, now)
    };
    let Ok(Some(snapshot)) = planned else {
        return Ok(0);
    };

    // Every target gets the snapshot, and each prunes only after its own
    // copy of it has landed, which `publish_compaction` guarantees for the
    // target it is handed. A target that fails keeps its whole log: more
    // history than it needs, which is the harmless direction to fail in.
    let mut published_anywhere = false;
    for target in targets {
        // An append-only target takes the snapshot and keeps its whole log.
        // The snapshot still helps: it is a PUT on a fresh key and it is
        // what a joining device replays from instead of the log's start.
        if sync::publish_compaction(&*target.store, dek, &snapshot, target.role.allows_delete())
            .await
            .is_ok()
        {
            published_anywhere = true;
        }
    }
    if !published_anywhere {
        return Ok(0);
    }

    let dropped = {
        let mut sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        // Locked or closed while the upload ran. The snapshot is in the
        // bucket and the records it covers are gone from it, which is a
        // complete and consistent state; this device simply keeps a longer
        // log than it needs until the next pass.
        let Some(session) = sessions.get_mut(&silo.id) else {
            return Ok(0);
        };
        match sync::finish_compaction(&mut session.conn, &snapshot) {
            Ok(report) => report.dropped,
            Err(_) => 0,
        }
    };

    Ok(dropped)
}

/// How often a silo's storage is swept for content nothing points at.
///
/// A sweep lists every blob, which is the most expensive request this app
/// makes of a metered bucket. What it reclaims is storage, and storage that
/// has been wasted for a day is no worse than storage wasted for a minute.
const BLOB_SWEEP_INTERVAL_SECS: i64 = 24 * 60 * 60;

/// How long content stays in storage after this device first saw nothing
/// point at it. A device that has not synced meanwhile can still write a
/// record naming it: a move made on top of an edit or a purge it had not
/// received copies the old content's id. The same span as the compaction
/// margin, past which such a device has to rebuild anyway.
const BLOB_SWEEP_GRACE_SECS: i64 = 30 * 24 * 60 * 60;

/// How old an unfinished upload has to be before the sweep aborts it. A
/// younger one may be another device's, still sending a large file.
const STALE_UPLOAD_AGE: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

/// Deletes content nothing references, at most once a day, and only what
/// was unreferenced on an earlier sweep and for the whole grace period. The
/// same listing puts back content a file points at that the target lost.
/// Runs after a successful pass, when the referenced set is trustworthy.
/// Also aborts unfinished uploads older than [`STALE_UPLOAD_AGE`].
/// Errors are swallowed: housekeeping. Returns how many blobs went back.
async fn run_blob_sweep(
    state: &AppState,
    host: &dyn Host,
    silo: &SiloEntry,
    target: (Uuid, &dyn ObjectStore),
    reachable: &[(Uuid, &dyn ObjectStore)],
) -> Result<usize, String> {
    let (target, store) = target;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let plan = {
        let sessions = state.sessions.lock().map_err(|e| e.to_string())?;
        let Some(session) = sessions.get(&silo.id) else {
            return Ok(0);
        };
        // Every read here gives up rather than failing the pass: a missing
        // bookkeeping table once turned this `?` into a sync that failed a
        // day after first open.
        if !matches!(
            silentsilo_vfs::snapshot::sweep_due(
                &session.conn,
                target,
                now,
                BLOB_SWEEP_INTERVAL_SECS
            ),
            Ok(true)
        ) {
            return Ok(0);
        }
        // Attachments included: they have no row in `files`, so the bare
        // tree set reads them as orphans and the sweep deletes them.
        let (Ok(referenced), Ok(first_seen)) = (
            Vfs::new(session).referenced_blobs_with_attachments(),
            silentsilo_vfs::snapshot::gc_first_seen(&session.conn, target, now),
        ) else {
            return Ok(0);
        };
        (referenced, first_seen)
    };
    let (referenced, first_seen) = plan;

    // With the blob sweep because it deletes too, and lists: once a day, and
    // only on a target whose role allows deletes.
    if let Err(e) = sync::abort_stale_uploads(store, STALE_UPLOAD_AGE).await {
        host.warn(
            "sweep",
            &format!("unfinished uploads were not cleared: {e}"),
        );
    }

    // Only a candidate past its grace may go on this sweep.
    let due: std::collections::HashSet<Uuid> = first_seen
        .iter()
        .filter(|(_, seen)| now - **seen >= BLOB_SWEEP_GRACE_SECS)
        .map(|(id, _)| *id)
        .collect();

    let Ok(outcome) = sync::sweep_orphan_blobs(store, &referenced, &due).await else {
        return Ok(0);
    };

    let listed: std::collections::HashSet<Uuid> = outcome.listed.iter().copied().collect();
    let mut missing: Vec<Uuid> = referenced.difference(&listed).copied().collect();
    missing.sort();
    let restored = if missing.is_empty() {
        0
    } else {
        let others: Vec<(Uuid, &dyn ObjectStore)> = reachable
            .iter()
            .filter(|(id, _)| *id != target)
            .copied()
            .collect();
        let put_back =
            sync::restore_missing_blobs((target, store), &others, &silo.path, &missing).await;
        put_back.restored.len()
    };

    let mut sessions = state.sessions.lock().map_err(|e| e.to_string())?;
    let Some(session) = sessions.get_mut(&silo.id) else {
        // Locked while the listing ran. The candidate set is not written, so
        // the next sweep starts these blobs over at first sighting, which is
        // the safe direction.
        return Ok(restored);
    };
    let seen = outcome
        .candidates
        .into_iter()
        .map(|id| (id, first_seen.get(&id).copied().unwrap_or(now)))
        .collect();
    let _ = silentsilo_vfs::snapshot::set_gc_first_seen(&mut session.conn, target, &seen);
    let _ = silentsilo_vfs::snapshot::record_sweep(&session.conn, target, now);
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;

    use silentsilo_store::{StoreError, StoredObject};
    use silentsilo_vault::{BackupTarget, VaultSession};

    use super::*;

    struct Quiet;

    impl Host for Quiet {
        fn emit(&self, _event: AppEvent) {}
        fn warn(&self, _area: &str, _detail: &str) {}
        fn targets(&self, _silo_id: Uuid) -> Vec<BackupTarget> {
            Vec::new()
        }
    }

    /// A folder that counts the sweep's requests to abort unfinished uploads.
    struct CountingStore {
        inner: silentsilo_store::FolderStore,
        aborts: Arc<AtomicUsize>,
    }

    #[async_trait::async_trait]
    impl ObjectStore for CountingStore {
        async fn put(&self, key: &str, body: Vec<u8>) -> Result<(), StoreError> {
            self.inner.put(key, body).await
        }
        async fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
            self.inner.get(key).await
        }
        async fn head(&self, key: &str) -> Result<Option<i64>, StoreError> {
            self.inner.head(key).await
        }
        async fn delete(&self, key: &str) -> Result<(), StoreError> {
            self.inner.delete(key).await
        }
        async fn list(&self, prefix: &str) -> Result<Vec<StoredObject>, StoreError> {
            self.inner.list(prefix).await
        }
        fn describe(&self) -> String {
            self.inner.describe()
        }
        async fn abort_stale_uploads(
            &self,
            prefix: &str,
            older_than: std::time::Duration,
        ) -> Result<usize, StoreError> {
            self.aborts.fetch_add(1, Ordering::SeqCst);
            self.inner.abort_stale_uploads(prefix, older_than).await
        }
    }

    #[tokio::test]
    async fn the_sweep_aborts_stale_uploads_once_a_day() {
        let dir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let root = dir.path().join("silo");
        let session = VaultSession::provision(root.clone(), Uuid::new_v4(), "s").unwrap();
        Vfs::new(&session).ensure_initialized().unwrap();
        let silo = SiloEntry {
            id: Uuid::new_v4(),
            name: "Sweep".into(),
            path: root,
            last_opened: 0,
            auto_lock_minutes: None,
        };
        let state = AppState::default();
        state.open_session(&Quiet, silo.id, session).unwrap();
        let aborts = Arc::new(AtomicUsize::new(0));
        let store = CountingStore {
            inner: silentsilo_store::FolderStore::new(storage.path().to_path_buf()),
            aborts: aborts.clone(),
        };
        let id = Uuid::new_v4();
        let all: Vec<(Uuid, &dyn ObjectStore)> = vec![(id, &store)];
        let sweep = || run_blob_sweep(&state, &Quiet, &silo, (id, &store), &all);

        sweep().await.unwrap();
        // One request per prefix: blobs/, snapshots/, inbox/.
        assert_eq!(aborts.load(Ordering::SeqCst), 3);
        sweep().await.unwrap();
        assert_eq!(aborts.load(Ordering::SeqCst), 3, "swept twice a day");

        state.sessions.lock().unwrap()[&silo.id]
            .conn
            .execute(
                "DELETE FROM vault_meta WHERE key LIKE 'blob_sweep_at:%'",
                [],
            )
            .unwrap();
        sweep().await.unwrap();
        assert_eq!(aborts.load(Ordering::SeqCst), 6);
    }
}
