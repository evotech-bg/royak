//! Real DesiredWorld/DesiredState/persist/store/Raft integration, no mock auth.
use super::*;
use crate::{persist, raft_node, store};
use std::sync::{Arc, RwLock};

#[test]
fn desired_state_and_schema_seven_roundtrip_preserve_jobs_and_identities() {
    let (mut world, registry, uid) = super::tests::fixture();
    world.backup_registry = registry;
    let state = world.to_state();
    let encoded = persist::encode(&state, &[]).unwrap();
    let envelope: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(envelope["schemaVersion"], 9);
    let (decoded, _, previous) = persist::decode(std::str::from_utf8(&encoded).unwrap()).unwrap();
    assert_eq!(previous, None);
    assert_eq!(decoded.backup_registry, state.backup_registry);
    let restored = DesiredWorld::from_state(decoded);
    assert_eq!(
        restored.backup_registry.job(&uid).unwrap().plan(),
        world.backup_registry.job(&uid).unwrap().plan()
    );
    assert_eq!(restored.storage_identities, world.storage_identities);
    let mut missing = envelope;
    missing["state"]
        .as_object_mut()
        .unwrap()
        .remove("backup_registry");
    assert!(
        persist::decode(&missing.to_string()).is_err(),
        "new schema may not request a missing-field migration"
    );
}

#[test]
fn older_schemas_migrate_absence_only_and_cannot_smuggle_backup_jobs() {
    let world = DesiredWorld::new();
    let value: serde_json::Value =
        serde_json::from_slice(&persist::encode(&world.to_state(), &[]).unwrap()).unwrap();
    let (mut with_jobs, registry, _) = super::tests::fixture();
    with_jobs.backup_registry = registry;
    let mut legacy_jobs = serde_json::to_value(&with_jobs.to_state()).unwrap();
    Registry::legacy_v1_fixture(&mut legacy_jobs);
    let jobs = legacy_jobs["backup_registry"].clone();
    for schema in [2, 3, 4, 5] {
        let mut old = value.clone();
        old["schemaVersion"] = schema.into();
        old["state"]
            .as_object_mut()
            .unwrap()
            .remove("storage_node_directory");
        old["state"]
            .as_object_mut()
            .unwrap()
            .remove("backup_registry");
        let (migrated, _, previous) = persist::decode(&old.to_string()).unwrap();
        assert_eq!(previous, Some(schema));
        assert_eq!(migrated.backup_registry, Registry::fresh());
        old["state"]["backup_registry"] = jobs.clone();
        assert!(
            persist::decode(&old.to_string()).is_err(),
            "schema {schema} cannot import backup authority"
        );
    }
    // The permissive v0/v1 loader must be guarded BEFORE it can ignore fields.
    for legacy in [
        serde_json::json!({"backup_registry":jobs}),
        serde_json::json!({"schemaVersion":1,"backup_registry":jobs}),
    ] {
        assert!(persist::decode(&legacy.to_string()).is_err());
    }
}

#[test]
fn central_commit_refuses_phase_skips_without_touching_live_state() {
    let (world, mut registry, uid) = super::tests::fixture();
    let world = Arc::new(RwLock::new(world));
    let before = world.read().unwrap().to_state();
    let actual = DesiredWorld::from_state(before.clone());
    let attempt = registry
        .start(
            &actual,
            &uid,
            Uid::new(),
            "12345678-1234-1234-1234-123456789abc".into(),
            100,
        )
        .unwrap();
    let receipt = super::tests::captured(registry.job(&uid).unwrap().plan());
    registry.captured(&uid, &attempt.uid, receipt).unwrap();
    let mut next = before.clone();
    next.generation += 1;
    next.backup_registry = registry;
    let rejected = store::commit_state(&world, before.generation, next).unwrap_err();
    assert!(format!("{rejected:?}").contains("intent only"));
    assert_eq!(
        world.read().unwrap().to_state().to_canonical_json(),
        before.to_canonical_json()
    );
}

#[test]
fn file_commit_failure_does_not_ack_or_install_backup_intent() {
    const CHILD: &str = "ROYAK_TEST_BACKUP_FILE_COMMIT_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "backup_engine::integration_tests::file_commit_failure_does_not_ack_or_install_backup_intent", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("royak-backup-commit-{}", Uid::new().as_str()));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("state.json");
    let path = path.to_str().unwrap();
    let owner = persist::try_own(path).unwrap().unwrap();
    store::set_owns_state(true);
    store::set_durability(store::Durability::File { path: path.into() });
    let (actual, registry, uid) = super::tests::fixture();
    let world = Arc::new(RwLock::new(actual));
    let before = world.read().unwrap().to_state();
    persist::save(path, &before, &[]).unwrap();
    // A real filesystem failure in both debug and normal release, including
    // UID0. The old debug-only environment hook is deliberately not enabled
    // in production release. Block only this isolated child's exact temp name.
    let blocker = format!("{path}.tmp.{}", std::process::id());
    std::fs::create_dir(&blocker).unwrap();
    let failed = store::commit(&world, |candidate| {
        candidate.backup_registry = registry.clone();
        Ok(uid.clone())
    });
    assert!(matches!(failed, Err(store::CommitError::Unavailable(_))));
    assert!(!world.read().unwrap().backup_registry.has_authority());
    assert!(!persist::load(path)
        .unwrap()
        .state
        .backup_registry
        .has_authority());
    std::fs::remove_dir(&blocker).unwrap();
    let accepted = store::commit(&world, |candidate| {
        candidate.backup_registry = registry.clone();
        Ok(uid.clone())
    })
    .unwrap();
    assert_eq!(accepted, uid);
    assert_eq!(persist::load(path).unwrap().state.backup_registry, registry);
    assert_eq!(world.read().unwrap().generation, before.generation + 1);
    store::set_owns_state(false);
    drop(owner);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn aead_domain_blocks_old_readers_and_legacy_imports() {
    const CHILD: &str = "ROYAK_TEST_BACKUP_AEAD_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "backup_engine::integration_tests::aead_domain_blocks_old_readers_and_legacy_imports", "--nocapture"])
            .env(CHILD,"1").env("ROYAK_CLUSTER_SECRET", "backup-domain-isolated-fixture-secret-0123456789")
            .env_remove("ROYAK_CLUSTER_SECRET_FILE").output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        return;
    }
    let (mut world, registry, _) = super::tests::fixture();
    world.backup_registry = registry;
    let state = world.to_state();
    let sealed = raft_node::Sealing::Cluster.seal(&state).unwrap();
    assert_eq!(
        raft_node::Sealing::Cluster
            .unseal(&sealed)
            .unwrap()
            .backup_registry,
        state.backup_registry
    );
    let mut legacy_state = serde_json::to_value(&state).unwrap();
    Registry::legacy_v1_fixture(&mut legacy_state);
    // A genuine pre-schema8 envelope had no node-directory field. The separate
    // smuggling regressions still require inserted new fields to be refused.
    legacy_state.as_object_mut().unwrap().remove("storage_node_directory");
    for domain in [
        b"royak-raft-state-v1".as_slice(),
        b"royak-raft-state-v2-security",
        b"royak-raft-state-v3-storage-identities",
        b"royak-raft-state-v4-host-access",
    ] {
        assert!(crate::auth::unseal_for_cluster(domain, &sealed).is_err());
        let old =
            crate::auth::seal_for_cluster(domain, &serde_json::to_vec(&legacy_state).unwrap()).unwrap();
        assert!(raft_node::Sealing::Cluster.unseal(&old).is_err());
    }
    let mut old_empty = serde_json::to_value(DesiredWorld::new().to_state()).unwrap();
    old_empty.as_object_mut().unwrap().remove("backup_registry");
    old_empty.as_object_mut().unwrap().remove("storage_node_directory");
    let old = crate::auth::seal_for_cluster(
        b"royak-raft-state-v4-host-access",
        &serde_json::to_vec(&old_empty).unwrap(),
    )
    .unwrap();
    assert_eq!(
        raft_node::Sealing::Cluster
            .unseal(&old)
            .unwrap()
            .backup_registry,
        Registry::fresh()
    );
    let invalid_new = crate::auth::seal_for_cluster(
        b"royak-raft-state-v5-backup-jobs",
        &serde_json::to_vec(&old_empty).unwrap(),
    )
    .unwrap();
    assert!(raft_node::Sealing::Cluster.unseal(&invalid_new).is_err());
}

#[tokio::test]
async fn real_raft_apply_and_snapshot_preserve_backup_monotonicity() {
    use openraft::storage::{RaftSnapshotBuilder, RaftStorage};
    use openraft::{Entry, EntryPayload, LogId};
    let (world, registry, uid) = super::tests::fixture();
    let initial = world.to_state();
    let world = Arc::new(RwLock::new(world));
    let mut engine = raft_node::NeuroStore::in_memory(world.clone());
    async fn apply(
        engine: &mut Arc<raft_node::NeuroStore>,
        world: &Arc<RwLock<DesiredWorld>>,
        registry: Registry,
        index: u64,
    ) -> bool {
        let base = world.read().unwrap().to_state();
        let mut next = base.clone();
        next.generation += 1;
        next.backup_registry = registry;
        let entry = Entry::<raft_node::NeuroTypeConfig> {
            log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), index),
            payload: EntryPayload::Normal(crate::consensus::Command::Commit {
                base_generation: base.generation,
                state: raft_node::Sealing::Plain.seal(&next).unwrap(),
            }),
        };
        engine.apply_to_state_machine(&[entry]).await.unwrap()[0].applied
    }
    assert!(apply(&mut engine, &world, registry.clone(), 1).await);
    let mut complete = registry.clone();
    let actual = DesiredWorld::from_state(world.read().unwrap().to_state());
    let attempt = complete
        .start(
            &actual,
            &uid,
            Uid::new(),
            "12345678-1234-1234-1234-123456789abc".into(),
            100,
        )
        .unwrap();
    let running = complete.clone();
    let receipt = super::tests::captured(complete.job(&uid).unwrap().plan());
    complete.captured(&uid, &attempt.uid, receipt).unwrap();
    assert!(
        !apply(&mut engine, &world, complete.clone(), 2).await,
        "phase skip cannot import a capture acknowledgement"
    );
    assert!(apply(&mut engine, &world, running, 3).await);
    assert!(apply(&mut engine, &world, complete.clone(), 4).await);
    let snapshot = engine.build_snapshot().await.unwrap();
    let follower_world = Arc::new(RwLock::new(DesiredWorld::from_state(initial.clone())));
    let mut follower = raft_node::NeuroStore::in_memory(follower_world.clone());
    follower
        .install_snapshot(&snapshot.meta, snapshot.snapshot)
        .await
        .unwrap();
    assert_eq!(follower_world.read().unwrap().backup_registry, complete);
    let old_world = Arc::new(RwLock::new(DesiredWorld::from_state(initial)));
    let mut old_store = raft_node::NeuroStore::in_memory(old_world);
    let old = old_store.build_snapshot().await.unwrap();
    assert!(follower
        .install_snapshot(&old.meta, old.snapshot)
        .await
        .is_err());
    assert_eq!(follower_world.read().unwrap().backup_registry, complete);
}

#[test]
fn precapture_file_commit_failure_never_acknowledges_or_installs_reservation() {
    const CHILD: &str = "ROYAK_TEST_PRECAPTURE_COMMIT_CHILD";
    if std::env::var(CHILD).as_deref() != Ok("1") {
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "backup_engine::integration_tests::precapture_file_commit_failure_never_acknowledges_or_installs_reservation", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        return;
    }
    let root = std::env::temp_dir().canonicalize().unwrap()
        .join(format!("royak-precapture-commit-{}", Uid::new().as_str()));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("state.json");
    let path = path.to_str().unwrap();
    let _owner = persist::try_own(path).unwrap().unwrap();
    store::set_owns_state(true);
    store::set_durability(store::Durability::File { path: path.into() });
    let (mut actual, mut registry, _) = super::tests::fixture();
    registry.jobs.clear();
    let repo = registry.repositories.keys().next().unwrap().clone();
    actual.backup_registry = registry;
    let world = Arc::new(RwLock::new(actual));
    let before = world.read().unwrap().to_state();
    persist::save(path, &before, &[]).unwrap();
    let blocker = format!("{path}.tmp.{}", std::process::id());
    std::fs::create_dir(&blocker).unwrap();
    let actor = Identity { user: "operator".into(), groups: vec![] };
    let mutate = |candidate: &mut DesiredWorld| {
        // store::commit's scratch DATA, never a live actor/physical permit.
        let scope = DesiredWorld::from_state(candidate.to_state());
        candidate.backup_registry.reserve_capture_request(&scope, &actor,
            "default", "data", &repo, Consistency::Cold, &"a".repeat(64))
            .map_err(|e| (409, e))
    };
    let failed = store::commit(&world, &mutate);
    assert!(matches!(failed, Err(store::CommitError::Unavailable(_))));
    assert_eq!(world.read().unwrap().backup_registry, before.backup_registry);
    assert_eq!(persist::load(path).unwrap().state.backup_registry, before.backup_registry);
    std::fs::remove_dir(&blocker).unwrap();
    let uid = store::commit(&world, &mutate).unwrap();
    assert!(world.read().unwrap().backup_registry.job(&uid).is_none());
    assert_eq!(world.read().unwrap().backup_registry, persist::load(path).unwrap().state.backup_registry);
    let replay = store::commit(&world, &mutate).unwrap();
    assert_eq!(replay, uid);
    store::set_owns_state(false);
}
