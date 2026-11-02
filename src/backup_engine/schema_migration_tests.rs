//! Actual persist/Raft decode boundaries. Synthetic metadata is used only to
//! exercise serialization policy; no physical source/target receipt is minted.
use super::*;
use crate::{persist, raft_node, store::DesiredState};

fn states_without_restore() -> (Vec<DesiredState>, Uid) {
    let (mut world, mut registry, uid) = super::tests::fixture();
    let mut states = Vec::new();
    world.backup_registry = registry.clone();
    states.push(world.to_state());
    let attempt = registry
        .start(
            &world,
            &uid,
            Uid::new(),
            "12345678-1234-1234-1234-123456789abc".into(),
            100,
        )
        .unwrap();
    world.backup_registry = registry.clone();
    states.push(world.to_state());
    let receipt = super::tests::captured(registry.job(&uid).unwrap().plan());
    registry.captured(&uid, &attempt.uid, receipt).unwrap();
    world.backup_registry = registry.clone();
    states.push(world.to_state());
    let actor = Identity {
        user: "operator".into(),
        groups: vec![],
    };
    registry.request_check(&world, &actor, &uid).unwrap();
    let attempt = registry
        .start(
            &world,
            &uid,
            Uid::new(),
            "12345678-1234-1234-1234-123456789abc".into(),
            180,
        )
        .unwrap();
    world.backup_registry = registry.clone();
    states.push(world.to_state());
    let checked = CheckReceipt(CheckEvidence {
        snapshot_id: registry
            .job(&uid)
            .unwrap()
            .captured()
            .unwrap()
            .snapshot_id
            .clone(),
        checked_unix_ms: 200,
        full_read_data: true,
        adapter_receipt_sha256: "3".repeat(64),
    });
    registry.checked(&uid, &attempt.uid, checked).unwrap();
    world.backup_registry = registry;
    states.push(world.to_state());
    (states, uid)
}

fn disk_value(state: &DesiredState, schema: u32) -> serde_json::Value {
    let mut value: serde_json::Value =
        serde_json::from_slice(&persist::encode(state, &[]).unwrap()).unwrap();
    value["schemaVersion"] = schema.into();
    if schema < persist::SCHEMA_VERSION {
        Registry::legacy_v1_fixture(&mut value["state"]);
    }
    if schema <= 7 {
        value["state"]
            .as_object_mut()
            .unwrap()
            .remove("storage_node_directory");
    }
    value
}
fn old_value(state: &DesiredState) -> serde_json::Value {
    let mut raw = serde_json::to_value(state).unwrap();
    Registry::legacy_v1_fixture(&mut raw);
    raw.as_object_mut()
        .unwrap()
        .remove("storage_node_directory");
    raw
}

fn restore_metadata_only() -> (DesiredState, Uid) {
    let (states, uid) = states_without_restore();
    let mut state = states.last().unwrap().clone();
    let job = state.backup_registry.jobs.get_mut(&uid).unwrap();
    let mut destination = job.plan.source.binding.clone();
    destination.claim_name = "fresh-target-policy-only".into();
    destination.pv_name = "fresh-pv-policy-only".into();
    destination.claim_uid = Uid::new();
    destination.volume_uid = Uid::new();
    let captured = job.captured.as_ref().unwrap();
    let plan = RestorePlan {
        uid: Uid::new(),
        capture_plan_sha256: job.plan_sha256.clone(),
        repository_uid: job.plan.repository.uid.clone(),
        snapshot_id: captured.snapshot_id.clone(),
        manifest_sha256: captured.manifest_sha256.clone(),
        destination: destination.clone(),
        requested_by: job.operation_requested_by.clone(),
        expires_unix_ms: 1000,
    };
    let evidence = RestoreEvidence {
        snapshot_id: captured.snapshot_id.clone(),
        destination_volume_uid: destination.volume_uid,
        tree_sha256: captured.tree_sha256.clone(),
        verified_unix_ms: 500,
        application_evidence_sha256: None,
        adapter_receipt_sha256: "4".repeat(64),
        restore_plan_sha256: plan.hash().unwrap(),
        attempt_uid: Uid::new(),
    };
    job.requested = Operation::Restore;
    job.restore_plan = Some(plan);
    job.restore_verified = Some(evidence);
    job.state = State::Idle;
    job.attempt = None;
    job.attempts_started += 1;
    job.partial_effects_possible = false;
    state.backup_registry.validate_state(&state).unwrap();
    (state, uid)
}

fn cluster_isolated(name: &str) -> bool {
    const KEY: &str = "ROYAK_SCHEMA7_AEAD_ISOLATED";
    if std::env::var(KEY).as_deref() == Ok(name) {
        return false;
    }
    let test = format!("backup_engine::schema_migration_tests::{name}");
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &test, "--nocapture", "--test-threads=1"])
        .env(KEY, name)
        .env(
            "ROYAK_CLUSTER_SECRET",
            "schema7-isolated-fixture-secret-0123456789",
        )
        .env_remove("ROYAK_CLUSTER_SECRET_FILE")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "isolated AEAD fixture failed:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    true
}

#[test]
fn schema6_empty_and_no_restore_histories_migrate_without_synthesizing_authority() {
    assert_eq!(persist::SCHEMA_VERSION, 9);
    let empty = DesiredWorld::new().to_state();
    let (states, _) = states_without_restore();
    for state in std::iter::once(&empty).chain(states.iter()) {
        let original = disk_value(state, 6).to_string();
        let (decoded, _, previous) = persist::decode(&original).unwrap();
        assert_eq!(previous, Some(6));
        assert_eq!(decoded.to_canonical_json(), state.to_canonical_json());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&persist::encode(&decoded, &[]).unwrap())
                .unwrap()["schemaVersion"],
            9
        );
    }
}

#[test]
fn schema6_load_and_upgrade_preserve_original_backup_bytes() {
    let (states, _) = states_without_restore();
    let state = states.last().unwrap();
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("royak-schema7-{}", Uid::new().as_str()));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("state.json");
    let text = disk_value(state, 6).to_string();
    std::fs::write(&path, &text).unwrap();
    let loaded = persist::load(path.to_str().unwrap()).unwrap();
    assert!(!loaded.fresh);
    assert_eq!(loaded.migrated_from, Some(6));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    persist::backup_before_migration(path.to_str().unwrap(), 6).unwrap();
    persist::save(path.to_str().unwrap(), &loaded.state, &loaded.nodes).unwrap();
    assert_eq!(
        std::fs::read_to_string(root.join("state.json.v6.bak")).unwrap(),
        text
    );
    assert_eq!(
        persist::load(path.to_str().unwrap()).unwrap().migrated_from,
        None
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn schema6_restore_fields_and_unbound_history_are_explicitly_refused_before_deserialize() {
    let (states, uid) = states_without_restore();
    let state = states.last().unwrap();
    for fault in 0..4 {
        let mut value = disk_value(state, 6);
        let job = &mut value["state"]["backup_registry"]["jobs"][uid.as_str()];
        match fault {
            0 => job["requested"] = "Restore".into(),
            1 => job["restore_plan"] = serde_json::json!({"legacy":"unbound"}),
            2 => job["restore_verified"] = serde_json::json!({"snapshot_id":"1".repeat(64)}),
            _ => job["attempt"] = serde_json::json!({"operation":"Restore"}),
        }
        let error = persist::decode(&value.to_string()).err().unwrap();
        assert!(
            error.contains("legacy restore state"),
            "fault={fault}: {error}"
        );
    }
    let (state, _) = restore_metadata_only();
    assert!(
        persist::decode(&disk_value(&state, 6).to_string())
            .err()
            .unwrap()
            .contains("legacy restore state"),
        "new-shaped fields under old schema do not acquire new meaning"
    );
}

#[test]
fn schema6_missing_registry_and_pre_backup_authority_are_not_inferred_or_dropped() {
    let (states, _) = states_without_restore();
    let state = &states[0];
    let mut value = disk_value(state, 6);
    value["state"]
        .as_object_mut()
        .unwrap()
        .remove("backup_registry");
    assert!(persist::decode(&value.to_string())
        .err()
        .unwrap()
        .contains("registry is missing"));
    for version in [0, 1, 2, 3, 4, 5] {
        let value = if version <= 1 {
            serde_json::json!({"schemaVersion":version,"backup_registry":state.backup_registry})
        } else {
            disk_value(state, version)
        };
        assert!(
            persist::decode(&value.to_string()).is_err(),
            "schema{version} may not import even capture authority"
        );
    }
}

#[test]
fn schema7_requires_exact_new_restore_fields_without_defaults() {
    let (state, uid) = restore_metadata_only();
    let encoded = disk_value(&state, 7);
    let (decoded, _, previous) = persist::decode(&encoded.to_string()).unwrap();
    assert_eq!(previous, Some(7));
    assert_eq!(decoded.backup_registry, state.backup_registry);
    for field in ["restore_plan_sha256", "attempt_uid"] {
        let mut value = encoded.clone();
        value["state"]["backup_registry"]["jobs"][uid.as_str()]["restore_verified"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            persist::decode(&value.to_string()).is_err(),
            "missing {field} cannot be synthesized"
        );
    }
    let mut tampered = encoded;
    tampered["state"]["backup_registry"]["jobs"][uid.as_str()]["restore_verified"]
        ["restore_plan_sha256"] = "0".repeat(64).into();
    assert!(persist::decode(&tampered.to_string()).is_err());
}

#[test]
fn persisted_registry_never_turns_missing_inner_maps_into_empty_history() {
    let (states, _) = states_without_restore();
    let state = states.last().unwrap();
    for schema in [6, 7, 8] {
        for field in ["version", "repositories", "jobs"] {
            let mut value = disk_value(state, schema);
            value["state"]["backup_registry"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            let error = persist::decode(&value.to_string()).err().unwrap();
            assert!(
                error.contains("explicit version/repositories/jobs"),
                "schema={schema},field={field}: {error}"
            );
        }
    }
}

#[test]
fn authenticated_registry_never_defaults_missing_inner_history_maps() {
    if cluster_isolated("authenticated_registry_never_defaults_missing_inner_history_maps") {
        return;
    }
    let (states, _) = states_without_restore();
    let state = states.last().unwrap();
    for domain in [
        b"royak-raft-state-v5-backup-jobs".as_slice(),
        b"royak-raft-state-v6-restore-contract",
        b"royak-raft-state-v7-node-directory",
    ] {
        for field in ["version", "repositories", "jobs"] {
            let mut value = serde_json::to_value(state).unwrap();
            Registry::legacy_v1_fixture(&mut value);
            if domain != b"royak-raft-state-v7-node-directory" {
                value
                    .as_object_mut()
                    .unwrap()
                    .remove("storage_node_directory");
            }
            value["backup_registry"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            let sealed =
                crate::auth::seal_for_cluster(domain, &serde_json::to_vec(&value).unwrap())
                    .unwrap();
            let error = raft_node::Sealing::Cluster.unseal(&sealed).err().unwrap();
            assert!(
                error.contains("explicit version/repositories/jobs"),
                "field={field}: {error}"
            );
        }
    }
}

#[test]
fn new_raft_purpose_roundtrips_and_old_readers_cannot_authenticate() {
    if cluster_isolated("new_raft_purpose_roundtrips_and_old_readers_cannot_authenticate") {
        return;
    }
    let (state, _) = restore_metadata_only();
    let sealed = raft_node::Sealing::Cluster.seal(&state).unwrap();
    assert_eq!(
        raft_node::Sealing::Cluster
            .unseal(&sealed)
            .unwrap()
            .backup_registry,
        state.backup_registry
    );
    for old in [
        b"royak-raft-state-v1".as_slice(),
        b"royak-raft-state-v2-security",
        b"royak-raft-state-v3-storage-identities",
        b"royak-raft-state-v4-host-access",
        b"royak-raft-state-v5-backup-jobs",
        b"royak-raft-state-v6-restore-contract",
    ] {
        assert!(
            crate::auth::unseal_for_cluster(old, &sealed).is_err(),
            "old domain cannot authenticate strict restore state"
        );
    }
    assert!(
        crate::auth::unseal_for_cluster(b"royak-raft-state-v8-precapture-reservations", &sealed).is_ok()
    );
}

#[test]
fn backup_domain_v5_preserves_no_restore_history_but_never_upgrades_restore() {
    if cluster_isolated("backup_domain_v5_preserves_no_restore_history_but_never_upgrades_restore")
    {
        return;
    }
    let (states, _) = states_without_restore();
    for state in std::iter::once(DesiredWorld::new().to_state()).chain(states) {
        let old = crate::auth::seal_for_cluster(
            b"royak-raft-state-v5-backup-jobs",
            &serde_json::to_vec(&old_value(&state)).unwrap(),
        )
        .unwrap();
        let decoded = raft_node::Sealing::Cluster.unseal(&old).unwrap();
        assert_eq!(decoded.to_canonical_json(), state.to_canonical_json());
    }
    let (state, uid) = restore_metadata_only();
    let value = old_value(&state);
    for strip_fields in [false, true] {
        let mut old_value = value.clone();
        if strip_fields {
            let evidence = old_value["backup_registry"]["jobs"][uid.as_str()]["restore_verified"]
                .as_object_mut()
                .unwrap();
            evidence.remove("restore_plan_sha256");
            evidence.remove("attempt_uid");
        }
        let old = crate::auth::seal_for_cluster(
            b"royak-raft-state-v5-backup-jobs",
            &serde_json::to_vec(&old_value).unwrap(),
        )
        .unwrap();
        assert!(raft_node::Sealing::Cluster
            .unseal(&old)
            .err()
            .unwrap()
            .contains("legacy restore state"));
    }
}

#[test]
fn raft_old_and_new_domains_reject_missing_backup_registry_consistently() {
    if cluster_isolated("raft_old_and_new_domains_reject_missing_backup_registry_consistently") {
        return;
    }
    let mut value = old_value(&DesiredWorld::new().to_state());
    value.as_object_mut().unwrap().remove("backup_registry");
    for domain in [
        b"royak-raft-state-v5-backup-jobs".as_slice(),
        b"royak-raft-state-v6-restore-contract",
    ] {
        let sealed =
            crate::auth::seal_for_cluster(domain, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(raft_node::Sealing::Cluster.unseal(&sealed).is_err());
    }
    let old = crate::auth::seal_for_cluster(
        b"royak-raft-state-v4-host-access",
        &serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    assert_eq!(
        raft_node::Sealing::Cluster
            .unseal(&old)
            .unwrap()
            .backup_registry,
        Registry::fresh()
    );
}

#[test]
fn new_raft_purpose_does_not_default_missing_strict_restore_fields() {
    if cluster_isolated("new_raft_purpose_does_not_default_missing_strict_restore_fields") {
        return;
    }
    let (state, uid) = restore_metadata_only();
    for field in ["restore_plan_sha256", "attempt_uid"] {
        let mut value = serde_json::to_value(&state).unwrap();
        value["backup_registry"]["jobs"][uid.as_str()]["restore_verified"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        let sealed = crate::auth::seal_for_cluster(
            b"royak-raft-state-v8-precapture-reservations",
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert!(raft_node::Sealing::Cluster.unseal(&sealed).is_err());
    }
}

fn managed_unwritable() -> (DesiredWorld, Uid) {
    let mut world = DesiredWorld::new();
    let class: crate::spec::Resource = serde_json::from_value(serde_json::json!({
        "kind":"StorageClass","metadata":{"name":"managed"},
        "spec":{"provisioner":crate::storage_lifecycle::PROVISIONER,"reclaimPolicy":"Retain"}}))
    .unwrap();
    world.apply(&class).unwrap();
    let claim:crate::spec::Resource=serde_json::from_value(serde_json::json!({
        "kind":"PersistentVolumeClaim","metadata":{"name":"data","namespace":"a"},
        "spec":{"storageClassName":"managed","accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"64Mi"}}}})).unwrap();
    world.apply(&claim).unwrap();
    let pv = world.pvcs["a/data"].bound_pv.as_ref().unwrap();
    let uid = world.storage_identities.volumes[pv].clone();
    (world, uid)
}
fn reserve_metadata_only(world: &mut DesiredWorld, uid: &Uid) {
    let boot: crate::storage_boot::BootId =
        serde_json::from_value(serde_json::json!("12345678-1234-1234-1234-123456789abc")).unwrap();
    world
        .storage_identities
        .lifecycle
        .get_mut(uid)
        .unwrap()
        .begin_provision(
            [Uid::new(), Uid::new(), Uid::new()],
            [boot.clone(), boot.clone(), boot],
            Uid::new(),
        )
        .unwrap();
}
fn raw_storage_error(error: &str) -> bool {
    error.contains("legacy managed volume has data/writer history")
        || error.contains("old state/envelope cannot import")
        || error.contains("unknown legacy managed-volume field")
}
fn insert_legacy_authority(value: &mut serde_json::Value, uid: &Uid, fault: usize) {
    let record = &mut value["storage_identities"]["lifecycle"]["volumes"][uid.as_str()];
    match fault {
        0 => record["phase"] = "Attached".into(),
        1 => record["filesystem_uuid"] = "abcdef12-1234-1234-1234-123456789abc".into(),
        2 => record["assignment"] = serde_json::json!({"plausible":"writer"}),
        3 => record["evidence"] = serde_json::json!({"plausible":"receipt"}),
        4 => {
            record["data_generation"] = serde_json::json!({"version":1,"plausible":"new-contract"})
        }
        _ => record["initialize_operation"] = Uid::new().as_str().into(),
    }
}

#[test]
fn schema6_real_pending_and_provisioning_metadata_stays_unwritable_and_unchanged() {
    let (mut world, uid) = managed_unwritable();
    for preparing in [false, true] {
        if preparing {
            reserve_metadata_only(&mut world, &uid);
        }
        let state = world.to_state();
        if preparing {
            assert!(persist::decode(&disk_value(&state, 6).to_string())
                .err()
                .unwrap()
                .contains("legacy replica node identities"));
            continue; // New directory contract never backfills old replica UIDs.
        }
        let (loaded, _, previous) = persist::decode(&disk_value(&state, 6).to_string()).unwrap();
        assert_eq!(previous, Some(6));
        assert_eq!(loaded.to_canonical_json(), state.to_canonical_json());
        let volume = loaded.storage_identities.lifecycle.get(&uid).unwrap();
        assert!(volume.assignment().is_none());
        assert_eq!(volume.epoch(), 0);
        assert!(matches!(
            volume.phase(),
            crate::storage_lifecycle::Phase::PendingProvision
                | crate::storage_lifecycle::Phase::Provisioning
        ));
    }
}

#[test]
fn every_old_disk_reader_refuses_writer_filesystem_receipt_and_new_generation_before_parse() {
    let (world, uid) = managed_unwritable();
    let state = world.to_state();
    for schema in 0..=6 {
        for fault in 0..6 {
            let mut raw = old_value(&state);
            insert_legacy_authority(&mut raw, &uid, fault);
            let value = if schema <= 1 {
                raw.as_object_mut()
                    .unwrap()
                    .insert("schemaVersion".into(), schema.into());
                raw
            } else {
                let mut value = disk_value(&state, schema);
                value["state"] = raw;
                value
            };
            let error = persist::decode(&value.to_string()).err().unwrap();
            assert!(
                raw_storage_error(&error),
                "schema={schema},fault={fault}: {error}"
            );
        }
    }
}

#[test]
fn every_old_aead_domain_refuses_managed_data_authority_before_typed_parse() {
    if cluster_isolated("every_old_aead_domain_refuses_managed_data_authority_before_typed_parse") {
        return;
    }
    let (world, uid) = managed_unwritable();
    for domain in [
        b"royak-raft-state-v1".as_slice(),
        b"royak-raft-state-v2-security",
        b"royak-raft-state-v3-storage-identities",
        b"royak-raft-state-v4-host-access",
        b"royak-raft-state-v5-backup-jobs",
    ] {
        for fault in 0..6 {
            let mut value = old_value(&world.to_state());
            insert_legacy_authority(&mut value, &uid, fault);
            let sealed =
                crate::auth::seal_for_cluster(domain, &serde_json::to_vec(&value).unwrap())
                    .unwrap();
            let error = raft_node::Sealing::Cluster.unseal(&sealed).err().unwrap();
            assert!(raw_storage_error(&error), "fault={fault}: {error}");
        }
    }
}

#[test]
fn old_backup_aead_preserves_real_unwritable_managed_intents_without_generation_backfill() {
    if cluster_isolated(
        "old_backup_aead_preserves_real_unwritable_managed_intents_without_generation_backfill",
    ) {
        return;
    }
    let (mut world, uid) = managed_unwritable();
    for preparing in [false, true] {
        if preparing {
            reserve_metadata_only(&mut world, &uid);
        }
        let state = world.to_state();
        let sealed = crate::auth::seal_for_cluster(
            b"royak-raft-state-v5-backup-jobs",
            &serde_json::to_vec(&old_value(&state)).unwrap(),
        )
        .unwrap();
        if preparing {
            assert!(raft_node::Sealing::Cluster
                .unseal(&sealed)
                .err()
                .unwrap()
                .contains("legacy replica node identities"));
            continue;
        }
        let decoded = raft_node::Sealing::Cluster.unseal(&sealed).unwrap();
        assert_eq!(decoded.to_canonical_json(), state.to_canonical_json());
        assert_eq!(
            decoded
                .storage_identities
                .lifecycle
                .get(&uid)
                .unwrap()
                .epoch(),
            0
        );
        assert!(decoded
            .storage_identities
            .lifecycle
            .get(&uid)
            .unwrap()
            .assignment()
            .is_none());
    }
}

 

#[test]
fn precapture_v7_history_migrates_and_v8_requires_explicit_reservation_history() {
    if cluster_isolated("precapture_v7_history_migrates_and_v8_requires_explicit_reservation_history") {
        return;
    }
    let (states, _) = states_without_restore();
    for state in states {
        let mut old = serde_json::to_value(&state).unwrap();
        Registry::legacy_v1_fixture(&mut old);
        let sealed = crate::auth::seal_for_cluster(
            b"royak-raft-state-v7-node-directory", &serde_json::to_vec(&old).unwrap()).unwrap();
        assert_eq!(raft_node::Sealing::Cluster.unseal(&sealed).unwrap().backup_registry,
            state.backup_registry);
    }
    let (world, mut registry, _) = super::tests::fixture();
    registry.jobs.clear();
    let repo = registry.repositories.keys().next().unwrap().clone();
    let actor = Identity { user: "operator".into(), groups: vec![] };
    registry.reserve_capture_request(&world, &actor, "default", "data", &repo,
        Consistency::FilesystemCrashConsistent, &"a".repeat(64)).unwrap();
    let mut state = world.to_state();
    state.backup_registry = registry;
    let current = raft_node::Sealing::Cluster.seal(&state).unwrap();
    assert!(crate::auth::unseal_for_cluster(b"royak-raft-state-v7-node-directory", &current).is_err());
    for missing in [false, true] {
        let mut raw = serde_json::to_value(&state).unwrap();
        if missing { raw["backup_registry"].as_object_mut().unwrap().remove("capture_reservations"); }
        else { raw["backup_registry"]["capture_reservations"] = serde_json::Value::Null; }
        let sealed = crate::auth::seal_for_cluster(
            b"royak-raft-state-v8-precapture-reservations",
            &serde_json::to_vec(&raw).unwrap()).unwrap();
        assert!(raft_node::Sealing::Cluster.unseal(&sealed).is_err());
    }
    let mut smuggled = serde_json::to_value(&state).unwrap();
    smuggled["backup_registry"]["version"] = 1.into();
    let sealed = crate::auth::seal_for_cluster(
        b"royak-raft-state-v7-node-directory", &serde_json::to_vec(&smuggled).unwrap()).unwrap();
    assert!(raft_node::Sealing::Cluster.unseal(&sealed).err().unwrap()
        .contains("legacy backup schema/domain cannot import pre-capture"));
}
