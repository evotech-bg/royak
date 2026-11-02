use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
#[path = "contract_tests.rs"]
mod contract;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("royak-backup-engine-stage-{}", Uid::new().as_str()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn dir(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn id() -> Identity {
    Identity {
        user: "operator".into(),
        groups: Vec::new(),
    }
}
fn admin() -> Identity {
    Identity {
        user: "admin".into(),
        groups: vec!["system:masters".into()],
    }
}
fn grant(world: &mut DesiredWorld, verbs: &[&str], resources: &[&str]) {
    world.rbac_roles.insert(
        "operator".into(),
        crate::reconcile::RbacRole {
            name: "operator".into(),
            kind: "RbacRole".into(),
            namespace: None,
            rules: vec![crate::reconcile::RbacRule {
                resources: resources.iter().map(|v| (*v).into()).collect(),
                verbs: verbs.iter().map(|v| (*v).into()).collect(),
                namespaces: vec!["default".into()],
                resource_names: Vec::new(),
            }],
        },
    );
}
fn add_claim(world: &mut DesiredWorld, name: &str) {
    let pv = format!("pv-{name}");
    let key = crate::store::obj_key("default", name);
    world.pvs.insert(
        pv.clone(),
        crate::reconcile::StoredPV {
            name: pv.clone(),
            capacity: "1Gi".into(),
            storage_class: "test".into(),
            host_path: "/not-source-authority".into(),
            access_mode: "ReadWriteOnce".into(),
            status: crate::reconcile::PVStatus::Bound,
            bound_to: Some(key.clone()),
        },
    );
    world.pvcs.insert(
        key.clone(),
        crate::reconcile::StoredPVC {
            name: name.into(),
            namespace: "default".into(),
            storage_class: "test".into(),
            requested: "1Gi".into(),
            access_mode: "ReadWriteOnce".into(),
            bound_pv: Some(pv.clone()),
        },
    );
    let ns = world.storage_identities.namespaces["default"].clone();
    world.storage_identities.claims.insert(
        key,
        crate::storage_identity::ClaimIdentity {
            uid: Uid::new(),
            namespace_uid: ns,
        },
    );
    world.storage_identities.volumes.insert(pv, Uid::new());
}
fn world() -> DesiredWorld {
    let mut w = DesiredWorld::new();
    w.cluster_id = "test-backup-cluster".into();
    add_claim(&mut w, "data");
    grant(
        &mut w,
        &["create", "verify", "cancel"],
        &["backups", "restores"],
    );
    w
}
fn source(w: &DesiredWorld) -> SourceDescriptor {
    SourceDescriptor {
        binding: Binding::resolve(w, "default", "data").unwrap(),
        capture_uid: Uid::new(),
        immutable_snapshot_uid: Uid::new(),
        volume_epoch: 4,
        volume_operation: Uid::new(),
        node_uid: Uid::new(),
        node_boot_id: "12345678-1234-1234-1234-123456789abc".into(),
        filesystem_uuid: "abcdef12-1234-1234-1234-123456789abc".into(),
        backend_identity_sha256: "a".repeat(64),
        mount_id: 44,
        readonly_generation: "observed-snapshot-generation".into(),
        consistency: Consistency::Cold,
        consistency_evidence_sha256: "b".repeat(64),
        capture_started_unix_ms: 10,
        capture_finished_unix_ms: 11,
    }
}
fn repository(w: &DesiredWorld) -> Repository {
    Repository {
        uid: Uid::new(),
        namespace_uid: w.storage_identities.namespaces["default"].clone(),
        repository_id: "c".repeat(64),
        credential_uid: Uid::new(),
        approved_backend_sha256: "d".repeat(64),
        restic_binary_sha256: "e".repeat(64),
    }
}
pub(super) fn fixture() -> (DesiredWorld, Registry, Uid) {
    let w = world();
    let repo = repository(&w);
    let mut registry = Registry::fresh();
    registry
        .approve_repository(&w, &admin(), repo.clone())
        .unwrap();
    let plan = CapturePlan::authorized(&w, &id(), source(&w), &repo, false).unwrap();
    let uid = registry.enqueue(&w, plan).unwrap();
    (w, registry, uid)
}
fn start(w: &DesiredWorld, r: &mut Registry, uid: &Uid) -> Attempt {
    r.start(
        w,
        uid,
        Uid::new(),
        "12345678-1234-1234-1234-123456789abc".into(),
        100,
    )
    .unwrap()
}
pub(super) fn captured(plan: &CapturePlan) -> CaptureReceipt {
    let manifest = RecoveryManifest {
        version: 1,
        plan_sha256: plan.hash().unwrap(),
        source: plan.source.clone(),
        repository_uid: plan.repository.uid.clone(),
        repository_id: plan.repository.repository_id.clone(),
        desired_generation: plan.desired_generation,
        driver: "restic".into(),
        repository_format: 2,
        payload_snapshot_path: "/observed/immutable/source".into(),
        tree_sha256: "f".repeat(64),
    };
    CaptureReceipt(CaptureEvidence {
        snapshot_id: "1".repeat(64),
        manifest_sha256: digest(&manifest).unwrap(),
        manifest_snapshot_path: "/private/manifest.json".into(),
        manifest,
        tree_sha256: "f".repeat(64),
        finished_unix_ms: 150,
        adapter_receipt_sha256: "2".repeat(64),
    })
}
fn capture_done(w: &DesiredWorld, r: &mut Registry, uid: &Uid) {
    let attempt = start(w, r, uid);
    let receipt = captured(r.job(uid).unwrap().plan());
    r.captured(uid, &attempt.uid, receipt).unwrap();
}

fn repository_check_running(previous_check: bool) -> (DesiredWorld, Registry, Uid, Attempt) {
    let (w, mut r, uid) = fixture();
    capture_done(&w, &mut r, &uid);
    if previous_check {
        r.request_check(&w, &id(), &uid).unwrap();
        let attempt = start(&w, &mut r, &uid);
        let checked = CheckReceipt(CheckEvidence {
            snapshot_id: r
                .job(&uid)
                .unwrap()
                .captured
                .as_ref()
                .unwrap()
                .snapshot_id
                .clone(),
            checked_unix_ms: 200,
            full_read_data: true,
            adapter_receipt_sha256: "3".repeat(64),
        });
        r.checked(&uid, &attempt.uid, checked).unwrap();
    }
    r.request_check(&w, &id(), &uid).unwrap();
    let attempt = start(&w, &mut r, &uid);
    (w, r, uid, attempt)
}

#[test]
fn repository_check_snapshot_cannot_drop_existing_evidence() {
    let (_, mut old, uid, attempt) = repository_check_running(false);
    let proof = CheckReceipt(CheckEvidence {
        snapshot_id: old
            .job(&uid)
            .unwrap()
            .captured
            .as_ref()
            .unwrap()
            .snapshot_id
            .clone(),
        checked_unix_ms: 200,
        full_read_data: true,
        adapter_receipt_sha256: "3".repeat(64),
    });
    old.checked(&uid, &attempt.uid, proof).unwrap();
    let mut dropped = old.clone();
    dropped.jobs.get_mut(&uid).unwrap().repository_checked = None;
    assert!(
        old.validate_snapshot_successor(&dropped).is_err(),
        "trusted snapshot may not discard a completed repository check"
    );
    // Also exercise a shape whose individual Job.validate remains valid: a
    // running refresh may legitimately have no evidence on its FIRST check,
    // but a snapshot cannot erase evidence this follower already accepted.
    let (_, refreshing, uid, _) = repository_check_running(true);
    let mut erased_during_refresh = refreshing.clone();
    erased_during_refresh
        .jobs
        .get_mut(&uid)
        .unwrap()
        .repository_checked = None;
    erased_during_refresh.validate().unwrap();
    assert!(refreshing
        .validate_snapshot_successor(&erased_during_refresh)
        .is_err());
}

#[test]
fn repository_check_snapshot_cannot_regress_check_time() {
    let (_, old, uid, _) = repository_check_running(true);
    let mut older = old.clone();
    older
        .jobs
        .get_mut(&uid)
        .unwrap()
        .repository_checked
        .as_mut()
        .unwrap()
        .checked_unix_ms = 199;
    assert!(
        old.validate_snapshot_successor(&older).is_err(),
        "snapshot must retain monotonic repository check evidence"
    );
    let mut newer = old.clone();
    newer
        .jobs
        .get_mut(&uid)
        .unwrap()
        .repository_checked
        .as_mut()
        .unwrap()
        .checked_unix_ms = 201;
    assert!(
        old.validate_snapshot_successor(&newer).is_ok(),
        "a newer check on the exact captured point remains valid"
    );
}

#[test]
fn repository_check_finish_requires_a_receipt_even_on_first_check() {
    for previous in [false, true] {
        let (_, running, uid, _) = repository_check_running(previous);
        let mut missing = running.clone();
        let job = missing.jobs.get_mut(&uid).unwrap();
        job.state = State::Idle;
        job.attempt = None;
        job.partial_effects_possible = false;
        job.repository_checked = None;
        assert!(
            running.validate_transition(&missing).is_err(),
            "check completion cannot drop/omit its receipt (previous={previous})"
        );
    }
}

#[test]
fn repository_check_finish_cannot_replace_with_older_evidence() {
    let (_, running, uid, _) = repository_check_running(true);
    let mut older = running.clone();
    let job = older.jobs.get_mut(&uid).unwrap();
    job.state = State::Idle;
    job.attempt = None;
    job.partial_effects_possible = false;
    job.repository_checked.as_mut().unwrap().checked_unix_ms = 199;
    assert!(
        running.validate_transition(&older).is_err(),
        "check completion cannot roll back the accepted check time"
    );
    let mut newer = older;
    newer
        .jobs
        .get_mut(&uid)
        .unwrap()
        .repository_checked
        .as_mut()
        .unwrap()
        .checked_unix_ms = 201;
    assert!(
        running.validate_transition(&newer).is_ok(),
        "legitimate check refresh remains possible"
    );
}

#[test]
fn repository_check_invalid_acknowledgement_does_not_mutate_running_job() {
    let (_, mut running, uid, attempt) = repository_check_running(true);
    let before = running.clone();
    let wrong = CheckReceipt(CheckEvidence {
        snapshot_id: "9".repeat(64),
        checked_unix_ms: 201,
        full_read_data: true,
        adapter_receipt_sha256: "4".repeat(64),
    });
    assert!(running.checked(&uid, &attempt.uid, wrong).is_err());
    assert_eq!(
        running, before,
        "invalid opaque acknowledgement must not partially modify the registry"
    );
    let stale = CheckReceipt(CheckEvidence {
        snapshot_id: before
            .job(&uid)
            .unwrap()
            .captured
            .as_ref()
            .unwrap()
            .snapshot_id
            .clone(),
        checked_unix_ms: 199,
        full_read_data: true,
        adapter_receipt_sha256: "5".repeat(64),
    });
    assert!(running.checked(&uid, &attempt.uid, stale).is_err());
    assert_eq!(
        running, before,
        "time-regressing acknowledgement must not mutate the running job"
    );
}

#[test]
fn view_is_not_data_export_and_secret_export_is_separate() {
    let mut w = world();
    let repo = repository(&w);
    grant(&mut w, &["get", "list"], &["*"]);
    assert!(CapturePlan::authorized(&w, &id(), source(&w), &repo, false).is_err());
    grant(&mut w, &["create"], &["backups"]);
    assert!(CapturePlan::authorized(&w, &id(), source(&w), &repo, false).is_ok());
    assert!(CapturePlan::authorized(&w, &id(), source(&w), &repo, true).is_err());
    assert!(
        CapturePlan::authorized(&w, &admin(), source(&w), &repo, true)
            .unwrap_err()
            .contains("escrow")
    );
}
#[test]
fn repository_identity_is_namespace_uid_scoped_not_tags() {
    let w = world();
    let mut repo = repository(&w);
    repo.namespace_uid = Uid::new();
    assert!(CapturePlan::authorized(&w, &admin(), source(&w), &repo, false).is_err());
    let mut r = Registry::fresh();
    assert!(r.approve_repository(&w, &id(), repository(&w)).is_err());
}
#[test]
fn namespace_claim_and_volume_recreation_revoke_saved_plan() {
    let (mut w, r, uid) = fixture();
    let job = r.job(&uid).unwrap();
    w.storage_identities
        .claims
        .get_mut(&crate::store::obj_key("default", "data"))
        .unwrap()
        .uid = Uid::new();
    assert!(job.plan.reauthorize(&w).is_err());
    let (mut w, r, uid) = fixture();
    w.storage_identities
        .namespaces
        .insert("default".into(), Uid::new());
    assert!(r.job(&uid).unwrap().plan.reauthorize(&w).is_err());
    let (mut w, r, uid) = fixture();
    w.storage_identities
        .volumes
        .insert("pv-data".into(), Uid::new());
    assert!(r.job(&uid).unwrap().plan.reauthorize(&w).is_err());
}
#[test]
fn plan_is_immutable_and_deserialized_tamper_fails() {
    let (_, r, uid) = fixture();
    let mut json = serde_json::to_value(&r).unwrap();
    json["jobs"][uid.as_str()]["plan"]["desired_generation"] = 999.into();
    let altered: Registry = serde_json::from_value(json).unwrap();
    assert!(altered.validate().is_err());
    let mut next = r.clone();
    next.jobs.get_mut(&uid).unwrap().plan.desired_generation += 1;
    assert!(r.validate_transition(&next).is_err());
    assert!(serde_json::from_str::<Registry>(
        "{\"version\":1,\"repositories\":{},\"jobs\":{},\"mounted\":true}"
    )
    .is_err());
}

#[test]
fn transition_validation_rejects_imported_evidence_phase_skips_and_attempt_replacement() {
    let (w, mut r, uid) = fixture();
    let empty = Registry::fresh();
    let mut forged = r.clone();
    forged.jobs.get_mut(&uid).unwrap().captured = Some(captured(r.job(&uid).unwrap().plan()).0);
    forged.jobs.get_mut(&uid).unwrap().state = State::Idle;
    assert!(forged.validate().is_ok());
    assert!(empty.validate_transition(&forged).is_err());
    assert!(r.validate_transition(&forged).is_err());
    let before = r.clone();
    let a = start(&w, &mut r, &uid);
    before.validate_transition(&r).unwrap();
    let mut switched = r.clone();
    switched
        .jobs
        .get_mut(&uid)
        .unwrap()
        .attempt
        .as_mut()
        .unwrap()
        .uid = Uid::new();
    assert!(r.validate_transition(&switched).is_err());
    let running = r.clone();
    r.interrupted(&uid, &a.uid, "BACKUP_TIMEOUT").unwrap();
    running.validate_transition(&r).unwrap();
    let unknown = r.clone();
    r.recover_after_restart();
    unknown.validate_transition(&r).unwrap();
}

#[test]
fn verification_right_can_be_revoked_without_revoking_capture_right() {
    let (mut w, mut r, uid) = fixture();
    capture_done(&w, &mut r, &uid);
    r.request_check(&w, &id(), &uid).unwrap();
    grant(&mut w, &["create", "cancel"], &["backups", "restores"]);
    assert!(r.job(&uid).unwrap().plan.reauthorize(&w).is_ok());
    assert!(r.job(&uid).unwrap().execution_authorized(&w, 300).is_err());
    assert!(r
        .start(
            &w,
            &uid,
            Uid::new(),
            "12345678-1234-1234-1234-123456789abc".into(),
            300
        )
        .is_err());
}
#[test]
fn repository_and_volume_dispatch_are_serialized_and_unknown_blocks_retry() {
    let (w, mut r, uid) = fixture();
    let mut second = r.job(&uid).unwrap().plan.clone();
    second.uid = Uid::new();
    let second = r.enqueue(&w, second).unwrap();
    let a = start(&w, &mut r, &uid);
    assert!(r
        .start(&w, &second, Uid::new(), a.boot_id.clone(), 101)
        .is_err());
    r.interrupted(&uid, &a.uid, "BACKUP_TIMEOUT").unwrap();
    assert_eq!(r.job(&uid).unwrap().state, State::NeedsReconciliation);
    assert!(r
        .start(&w, &uid, Uid::new(), a.boot_id.clone(), 102)
        .is_err());
    assert!(r.start(&w, &second, Uid::new(), a.boot_id, 103).is_err());
}
#[test]
fn cancellation_is_durable_intent_not_false_no_effect() {
    let (w, mut r, uid) = fixture();
    let a = start(&w, &mut r, &uid);
    assert!(r.job(&uid).unwrap().worker_may_continue(&w, &a.uid, 100));
    r.request_cancel(&w, &id(), &uid).unwrap();
    assert_eq!(r.job(&uid).unwrap().state, State::CancelRequested);
    assert!(!r.job(&uid).unwrap().worker_may_continue(&w, &a.uid, 101));
    let receipt = captured(r.job(&uid).unwrap().plan());
    assert!(r.captured(&uid, &a.uid, receipt).is_err());
    r.interrupted(&uid, &a.uid, "BACKUP_CANCELLED").unwrap();
    assert!(r.job(&uid).unwrap().partial_effects_possible);
    assert!(r.job(&uid).unwrap().captured.is_none());
}

#[test]
fn read_metadata_is_scoped_to_current_namespace_uid_and_does_not_export_data() {
    let (mut w, r, uid) = fixture();
    grant(&mut w, &["get", "list"], &["backups"]);
    assert!(r.get_authorized(&w, &id(), "default", &uid).is_ok());
    assert_eq!(r.list_authorized(&w, &id(), "default").unwrap().len(), 1);
    assert!(r.job(&uid).unwrap().plan.reauthorize(&w).is_err());
    w.storage_identities
        .namespaces
        .insert("other".into(), Uid::new());
    assert!(r.get_authorized(&w, &admin(), "other", &uid).is_err());
    assert!(r.list_authorized(&w, &admin(), "other").unwrap().is_empty());
    w.storage_identities
        .namespaces
        .insert("default".into(), Uid::new());
    assert!(r.get_authorized(&w, &admin(), "default", &uid).is_err());
    assert!(r
        .list_authorized(&w, &admin(), "default")
        .unwrap()
        .is_empty());
}
#[test]
fn permission_removal_is_rechecked_after_queue_and_during_execution() {
    let (mut w, mut r, uid) = fixture();
    let a = start(&w, &mut r, &uid);
    w.rbac_roles.remove("operator");
    assert!(r.job(&uid).unwrap().execution_authorized(&w, 110).is_err());
    r.interrupted(&uid, &a.uid, "BACKUP_AUTH_REVOKED").unwrap();
    let (mut w, mut r, uid) = fixture();
    w.rbac_roles.remove("operator");
    assert!(r.start(&w, &uid, Uid::new(), a.boot_id, 200).is_err());
}
#[test]
fn capture_check_restore_milestones_are_not_conflated() {
    let (w, mut r, uid) = fixture();
    capture_done(&w, &mut r, &uid);
    let j = r.job(&uid).unwrap();
    assert!(j.captured.is_some());
    assert!(j.repository_checked.is_none());
    assert!(j.restore_verified.is_none());
    r.request_check(&w, &id(), &uid).unwrap();
    let a = start(&w, &mut r, &uid);
    let c = CheckReceipt(CheckEvidence {
        snapshot_id: r
            .job(&uid)
            .unwrap()
            .captured
            .as_ref()
            .unwrap()
            .snapshot_id
            .clone(),
        checked_unix_ms: 200,
        full_read_data: true,
        adapter_receipt_sha256: "3".repeat(64),
    });
    r.checked(&uid, &a.uid, c).unwrap();
    assert!(r.job(&uid).unwrap().repository_checked.is_some());
    assert!(r.job(&uid).unwrap().restore_verified.is_none());
}
#[test]
fn restore_approval_binds_new_volume_expiry_hash_and_permission() {
    let (mut w, mut r, uid) = fixture();
    capture_done(&w, &mut r, &uid);
    add_claim(&mut w, "new-data");
    let old = Binding::resolve(&w, "default", "data").unwrap();
    assert!(RestorePlan::new(&w, &id(), r.job(&uid).unwrap(), old, 1000, 200).is_err());
    let new = Binding::resolve(&w, "default", "new-data").unwrap();
    let plan = RestorePlan::new(&w, &id(), r.job(&uid).unwrap(), new, 1000, 200).unwrap();
    let hash = plan.hash().unwrap();
    assert!(plan.reauthorize(&w, 300, &hash).is_ok());
    assert!(plan.reauthorize(&w, 1000, &hash).is_err());
    assert!(plan.reauthorize(&w, 300, &"a".repeat(64)).is_err());
    w.rbac_roles.remove("operator");
    assert!(plan.reauthorize(&w, 300, &hash).is_err());
}
#[test]
fn journal_fsync_replay_preserves_unknown_attempt_and_rejects_links() {
    const NAME: &str =
        "backup_engine::tests::journal_fsync_replay_preserves_unknown_attempt_and_rejects_links";
    if isolate_journal_fixture(NAME) {
        return;
    }
    let scratch = Scratch::new();
    let path = scratch.dir("journal");
    let (w, r, uid) = fixture();
    let mut journal = journal::Journal::open(&path).unwrap();
    journal
        .transaction(|next| {
            *next = r;
            Ok(())
        })
        .unwrap();
    let a = journal
        .transaction(|next| Ok(start(&w, next, &uid)))
        .unwrap();
    assert!(journal::Journal::open(&path).is_err());
    drop(journal);
    let reopened = journal::Journal::open(&path).unwrap();
    let j = reopened.state().job(&uid).unwrap();
    assert_eq!(j.state, State::NeedsReconciliation);
    assert_eq!(j.attempt.as_ref().unwrap().uid, a.uid);
    drop(reopened);
    let link = scratch.0.join("link");
    symlink(&path, &link).unwrap();
    assert!(journal::Journal::open(&link).is_err());
    let other = scratch.dir("bad");
    symlink(path.join("jobs.json"), other.join("jobs.json")).unwrap();
    assert!(journal::Journal::open(&other).is_err());
    let hard = scratch.dir("hardlink");
    std::fs::hard_link(path.join("jobs.json"), hard.join("jobs.json")).unwrap();
    assert!(journal::Journal::open(&hard).is_err());
    assert!(journal::Journal::open(Path::new("/")).is_err());
}

/// CLOEXEC is an exec boundary, not a fork boundary. Other concurrently running
/// tests may briefly fork a copy of every open file description before exec.
/// Isolate this fixture, rather than relaxing flock or retrying/sleeping around
/// the immediate-reopen assertion. Exact child mode runs this one test only.
fn isolate_journal_fixture(name: &str) -> bool {
    const CHILD: &str = "ROYAK_TEST_BACKUP_JOURNAL_ISOLATED";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        return false;
    }
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env(CHILD, name)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "isolated journal fixture failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    // Forward diagnostic stderr only. Do not forward the child harness stdout
    // summary: qualification readers must count the outer complete test run.
    eprint!("{}", String::from_utf8_lossy(&result.stderr));
    true
}

#[test]
fn journal_cloexec_retains_forked_lock_until_controlled_exec() {
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::process::CommandExt;
    const NAME: &str =
        "backup_engine::tests::journal_cloexec_retains_forked_lock_until_controlled_exec";
    const EXEC_PROBE: &str = "ROYAK_TEST_BACKUP_JOURNAL_EXEC_PROBE";
    if let Some(path) = std::env::var_os(EXEC_PROBE) {
        // This is the same exact test after the controlled child's exec, not an
        // extra test which silently passes when a helper environment is absent.
        assert_eq!(
            std::env::var("ROYAK_TEST_BACKUP_JOURNAL_ISOLATED").as_deref(),
            Ok(NAME)
        );
        let path = PathBuf::from(path);
        assert_eq!(
            path.file_name().and_then(|p| p.to_str()),
            Some("journal-fork")
        );
        assert!(path
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("royak-backup-engine-stage-"));
        let acquired = journal::Journal::open(&path).expect(
            "exec must close inherited CLOEXEC lock before this exact probe can acquire it",
        );
        assert_ne!(
            unsafe { libc::fcntl(acquired.lock_fd_for_fixture(), libc::F_GETFD) }
                & libc::FD_CLOEXEC,
            0
        );
        drop(acquired);
        return;
    }
    if isolate_journal_fixture(NAME) {
        return;
    }
    fn pipe() -> (std::fs::File, std::fs::File) {
        let mut descriptors = [-1; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        for descriptor in descriptors {
            assert_eq!(
                unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) },
                0
            );
        }
        unsafe {
            (
                std::fs::File::from_raw_fd(descriptors[0]),
                std::fs::File::from_raw_fd(descriptors[1]),
            )
        }
    }
    let scratch = Scratch::new();
    let path = scratch.dir("journal-fork");
    let held = journal::Journal::open(&path).unwrap();
    let lock_fd = held.lock_fd_for_fixture();
    assert_ne!(
        unsafe { libc::fcntl(lock_fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
        0,
        "the production lock descriptor must already be CLOEXEC"
    );
    let (mut ready_read, ready_write) = pipe();
    let (go_read, mut go_write) = pipe();
    let ready_in = ready_read.as_raw_fd();
    let ready_out = ready_write.as_raw_fd();
    let go_in = go_read.as_raw_fd();
    let go_out = go_write.as_raw_fd();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", NAME, "--test-threads=1", "--nocapture"])
        .env("ROYAK_TEST_BACKUP_JOURNAL_ISOLATED", NAME)
        .env(EXEC_PROBE, &path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // Only async-signal-safe libc calls in this post-fork/pre-exec barrier.
    // Closing unused child ends ensures parent unwinding sends EOF, not an
    // indefinitely retained self-writer. No product code or lock flags change.
    unsafe {
        command.pre_exec(move || {
            libc::close(ready_in);
            libc::close(go_out);
            let flags = libc::fcntl(lock_fd, libc::F_GETFD);
            let observed = if flags >= 0 && flags & libc::FD_CLOEXEC != 0 {
                b'C'
            } else {
                b'N'
            };
            if libc::write(ready_out, (&observed as *const u8).cast(), 1) != 1 {
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            libc::close(ready_out);
            let mut release = 0u8;
            let read = libc::read(go_in, (&mut release as *mut u8).cast(), 1);
            libc::close(go_in);
            if read != 1 || release != b'G' {
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(())
        });
    }
    // Command::spawn waits for exec completion; use a parent thread so this
    // test can inspect the intentionally paused fork, without any timed sleep.
    let spawning = std::thread::spawn(move || command.spawn());
    let mut ready = libc::pollfd {
        fd: ready_in,
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(
        unsafe { libc::poll(&mut ready, 1, 5000) },
        1,
        "controlled child did not reach the pre-exec barrier"
    );
    let mut observed = [0u8];
    ready_read.read_exact(&mut observed).unwrap();
    assert_eq!(
        observed,
        [b'C'],
        "child must observe inherited lock with FD_CLOEXEC still set"
    );
    drop(held);
    let blocked = journal::Journal::open(&path);
    assert!(
        matches!(blocked, Err(ref error) if error == "backup worker already owns this journal"),
        "forked child must retain the same locked file description before exec"
    );
    go_write.write_all(b"G").unwrap();
    drop(go_write);
    drop(go_read);
    drop(ready_write);
    drop(ready_read);
    let result = spawning
        .join()
        .unwrap()
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert!(
        result.status.success(),
        "post-exec acquisition failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let reopened = journal::Journal::open(&path).unwrap();
    drop(reopened);
    eprintln!("journal observation: FD_CLOEXEC verified in parent and fork; lock retained before exec and released after exec; no sleep/retry/lock relaxation");
}
#[test]
fn tree_does_not_follow_symlinks_and_detects_modes_bytes_and_specials() {
    let scratch = Scratch::new();
    let source = scratch.dir("source");
    std::fs::write(source.join("file"), b"original").unwrap();
    std::fs::set_permissions(source.join("file"), std::fs::Permissions::from_mode(0o640)).unwrap();
    assert_eq!(
        std::fs::metadata(source.join("file")).unwrap().permissions().mode() & 0o777,
        0o640
    );
    symlink("/outside/missing", source.join("link")).unwrap();
    let a = tree::inventory(&source, || true).unwrap();
    std::fs::write(source.join("file"), b"changed").unwrap();
    let b = tree::inventory(&source, || true).unwrap();
    assert_ne!(a, b);
    std::fs::set_permissions(source.join("file"), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_ne!(b, tree::inventory(&source, || true).unwrap());
    assert!(tree::inventory(&source, || false).is_err());
    let fifo = std::ffi::CString::new(source.join("fifo").as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(tree::inventory(&source, || true).is_err());
}

/// Deliberately opt-in: test creates a NEW private repository and never opens
/// any old repo. It tests the Royak adapter/job journal, not a driver/PG volume.
#[test]
fn real_pinned_restic_engine_fixture() {
    let binary = std::env::var("ROYAK_STAGE_RESTIC").expect(
        "real adapter test requires explicitly pinned ROYAK_STAGE_RESTIC; absence is not PASS",
    );
    let binary = Path::new(&binary).canonicalize().unwrap();
    let scratch = Scratch::new();
    let repository_path = scratch.dir("repository");
    let work = scratch.dir("work");
    let source_path = scratch.dir("cold-fixture");
    let creds = scratch.dir("credential");
    let password_file = creds.join("key");
    std::fs::write(
        &password_file,
        format!("{}{}", Uid::new().as_str(), Uid::new().as_str()),
    )
    .unwrap();
    std::fs::set_permissions(&password_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(source_path.join("данни"), b"cold fixture exact bytes\n").unwrap();
    std::fs::set_permissions(
        source_path.join("данни"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    symlink("/nonexistent/outside-source", source_path.join("symlink")).unwrap();
    // This explicit initialization is fixture setup, NOT an engine operation.
    let result = std::process::Command::new(&binary)
        .env_clear()
        .env("RESTIC_PASSWORD_FILE", &password_file)
        .args(["--repo"])
        .arg(&repository_path)
        .args(["--no-cache", "init", "--repository-version", "2"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let config = std::process::Command::new(&binary)
        .env_clear()
        .env("RESTIC_PASSWORD_FILE", &password_file)
        .args(["--repo"])
        .arg(&repository_path)
        .args(["--no-cache", "cat", "config"])
        .output()
        .unwrap();
    assert!(config.status.success());
    let config: serde_json::Value = serde_json::from_slice(&config.stdout).unwrap();
    let w = world();
    let mut repo = repository(&w);
    repo.repository_id = config["id"].as_str().unwrap().into();
    repo.restic_binary_sha256 = sha(&std::fs::read(&binary).unwrap());
    repo.approved_backend_sha256 = digest(&(
        "local-owned-v1",
        repository_path.to_str().unwrap(),
        &repo.repository_id,
        &repo.namespace_uid,
        &repo.credential_uid,
    ))
    .unwrap();
    let adapter = restic::Restic::open(
        &binary,
        &repository_path,
        &password_file,
        &work,
        repo.clone(),
        restic::Budget::new(30, 1024).unwrap(),
        || true,
    )
    .unwrap();
    let mut registry = Registry::fresh();
    registry
        .approve_repository(&w, &admin(), repo.clone())
        .unwrap();
    let plan = CapturePlan::authorized(&w, &id(), source(&w), &repo, false).unwrap();
    let uid = registry.enqueue(&w, plan.clone()).unwrap();
    let attempt = start(&w, &mut registry, &uid);
    let receipt = adapter
        .capture_fixture(&source_path, &plan, 250, || {
            registry
                .job(&uid)
                .unwrap()
                .execution_authorized(&w, 200)
                .is_ok()
        })
        .unwrap();
    registry.captured(&uid, &attempt.uid, receipt).unwrap();
    registry.validate().unwrap();
    eprintln!(
        "adapter evidence: captured exact listed full ID with protected manifest and stable tree"
    );
    assert!(registry.job(&uid).unwrap().repository_checked.is_none());
    let captured = registry
        .job(&uid)
        .unwrap()
        .captured
        .as_ref()
        .unwrap()
        .clone();
    assert_eq!(
        adapter.restore_fixture(&plan, &captured, || true).unwrap(),
        captured.tree_sha256
    );
    eprintln!("adapter evidence: new isolated restore matched bytes modes and symlink targets");
    registry.request_check(&w, &id(), &uid).unwrap();
    let attempt = start(&w, &mut registry, &uid);
    let checked = adapter.check(&plan, &captured, 300, || true).unwrap();
    registry.checked(&uid, &attempt.uid, checked).unwrap();
    assert!(registry.job(&uid).unwrap().repository_checked.is_some());
    assert!(registry.job(&uid).unwrap().restore_verified.is_none());
    eprintln!("adapter evidence: full repository read-data check remained distinct from production RestoreVerified");
    // A later point must not change the original protected recovery point.
    std::fs::write(source_path.join("данни"), b"later incremental content").unwrap();
    let mut later_plan = plan.clone();
    later_plan.uid = Uid::new();
    later_plan.source.capture_uid = Uid::new();
    later_plan.source.immutable_snapshot_uid = Uid::new();
    let later = adapter
        .capture_fixture(&source_path, &later_plan, 310, || true)
        .unwrap();
    assert_ne!(later.0.snapshot_id, captured.snapshot_id);
    assert_eq!(
        adapter.restore_fixture(&plan, &captured, || true).unwrap(),
        captured.tree_sha256
    );
    eprintln!("adapter evidence: distinct incremental point did not alter historical restore");
    // Remove an explicitly named input AFTER independent pre-inventory, before
    // restic starts. Unlike chmod(000), this produces real incomplete exit 3
    // for root and non-root alike. Only this NEW owned fixture manifest is
    // removed; no source data, existing repo or production behavior changes.
    let mut incomplete_plan = later_plan.clone();
    incomplete_plan.uid = Uid::new();
    let marker = work
        .join(format!("capture-{}", incomplete_plan.uid.as_str()))
        .join("royak-recovery.json");
    let mut injected = false;
    let incomplete = adapter.capture_fixture(&source_path, &incomplete_plan, 320, || {
        if !injected && marker.exists() {
            std::fs::remove_file(&marker).unwrap();
            injected = true;
        }
        true
    });
    assert!(injected);
    assert_eq!(incomplete.err().as_deref(), Some("BACKUP_INCOMPLETE"));
    eprintln!("adapter evidence: root-compatible real restic exit 3 from missing exact owned manifest input rejected without capture receipt");
    // Source loss does not remove historical recovery point; scratch restore
    // validation never authorizes a production volume or workload cutover.
    std::fs::remove_dir_all(&source_path).unwrap();
    assert_eq!(
        adapter.restore_fixture(&plan, &captured, || true).unwrap(),
        captured.tree_sha256
    );
    eprintln!("adapter evidence: historical point restored after owned source deletion");
    assert!(adapter.restore_volume().is_err());
    assert!(adapter.check(&plan, &captured, 350, || false).is_err());
    // Wrong credential and binary changes fail closed with no secret output.
    let wrong = creds.join("wrong");
    std::fs::write(&wrong, b"wrong-key").unwrap();
    std::fs::set_permissions(&wrong, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(restic::Restic::open(
        &binary,
        &repository_path,
        &wrong,
        &work,
        repo.clone(),
        restic::Budget::new(10, 1024).unwrap(),
        || true
    )
    .is_err());
    eprintln!("adapter evidence: wrong repository key rejected without secret output");
    let mut wrong_repo = repo.clone();
    wrong_repo.restic_binary_sha256 = "0".repeat(64);
    assert!(restic::Restic::open(
        &binary,
        &repository_path,
        &password_file,
        &work,
        wrong_repo,
        restic::Budget::new(10, 1024).unwrap(),
        || true
    )
    .is_err());
    eprintln!("adapter evidence: changed pinned binary hash rejected before spawn");
    // Deliberate pack corruption in NEW disposable repository only.
    let mut packs = Vec::new();
    for prefix in std::fs::read_dir(repository_path.join("data")).unwrap() {
        for file in std::fs::read_dir(prefix.unwrap().path()).unwrap() {
            packs.push(file.unwrap().path());
        }
    }
    use std::io::{Read, Seek, Write};
    assert!(!packs.is_empty());
    for pack in &packs {
        std::fs::set_permissions(pack, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pack)
            .unwrap();
        file.seek(std::io::SeekFrom::Start(20)).unwrap();
        let mut b = [0];
        file.read_exact(&mut b).unwrap();
        file.seek(std::io::SeekFrom::Start(20)).unwrap();
        file.write_all(&[b[0] ^ 0xff]).unwrap();
        file.sync_all().unwrap();
    }
    assert!(adapter.check(&plan, &captured, 400, || true).is_err());
    assert!(adapter.restore_fixture(&plan, &captured, || true).is_err());
    eprintln!("adapter evidence: corrupt packs rejected by full check and fresh restore");
    // Stop a genuinely spawned pinned native child. No false no-effect claim,
    // no automatic unlock; exact child is reaped before private fixture cleanup.
    restic::arm_spawn_revocation_fixture();
    let revoked = adapter.check(&plan, &captured, 450, || !restic::fixture_child_spawned());
    assert_eq!(revoked.err().as_deref(), Some("BACKUP_AUTH_REVOKED"));
    assert!(restic::leader_reaped_dispatch_blocked_for_fixture());
    assert!(adapter
        .check(&plan, &captured, 460, || true)
        .err()
        .unwrap()
        .contains("descendant lease unresolved"));
    eprintln!("adapter evidence: revoked native leader killed/reaped; unresolved descendant lease blocks further dispatch (not a group-cleanup claim)");
}
