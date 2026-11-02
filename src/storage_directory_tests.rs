//! Source fixtures only until a separately authorized joined compile/run.
//! Model registry data is NEVER a VerifiedDirectory or physical capability.
use super::*;
use crate::storage_identity::Uid;
use crate::storage_node_directory::{DirectoryDto, NodePin};
fn uid(n: u64) -> Uid {
    serde_json::from_value(serde_json::json!(format!("{n:032x}"))).unwrap()
}
fn id(index: u64) -> LogId<u64> {
    LogId::new(openraft::CommittedLeaderId::new(7, 1), index)
}
fn model() -> (Registry, StoredMembership<u64, BasicNode>) {
    let membership = StoredMembership::new(
        Some(id(1)),
        openraft::Membership::new(
            vec![[1, 2, 3].into_iter().collect()],
            None::<std::collections::BTreeSet<u64>>,
        ),
    );
    let directory = DirectoryDto {
        version: 1,
        cluster_id: "aabbccddeeff".into(),
        nodes: (1..=3)
            .map(|n| NodePin {
                node_uid: uid(n),
                raft_id: n,
                signer_name: format!("node-{n}"),
                wireguard_key: format!("{}{}=", "A".repeat(42), ["E", "I", "M"][(n - 1) as usize]),
                wireguard_ip: std::net::Ipv4Addr::new(10, 214, 0, n as u8),
            })
            .collect(),
    };
    let proposal = EnrollmentProposal {
        version: 1,
        command_uid: uid(100),
        directory,
        base_generation: 0,
        term: 7,
        leader: 1,
        membership_sha256: data::digest(&serde_json::to_vec(&membership).unwrap()),
    };
    (Registry::from_entry(&proposal, id(2)).unwrap(), membership)
}
fn state_with_registry(registry: Registry) -> DesiredState {
    let mut state = DesiredWorld::new().to_state();
    state.cluster_id = "aabbccddeeff".into();
    state.storage_node_directory = registry;
    state
}
#[tokio::test]
async fn actual_generic_raft_commit_cannot_enroll_even_well_formed_serde_directory() {
    let world = Arc::new(std::sync::RwLock::new(DesiredWorld::from_state(
        state_with_registry(Registry::fresh()),
    )));
    let mut store = NeuroStore::in_memory(world.clone());
    let mut next = world.read().unwrap().to_state();
    next.storage_node_directory = model().0;
    next.generation = 1;
    let entry = Entry {
        log_id: id(2),
        payload: EntryPayload::Normal(Command::Commit {
            base_generation: 0,
            state: Sealing::Plain.seal(&next).unwrap(),
        }),
    };
    let response = store.apply_to_state_machine(&[entry]).await.unwrap();
    assert!(!response[0].applied);
    assert!(!world.read().unwrap().storage_node_directory.has_authority());
    assert!(store.storage_directory_history.lock().unwrap().is_none());
}
#[tokio::test]
async fn actual_snapshot_install_cannot_create_a_missing_applied_history_guard() {
    let world = Arc::new(std::sync::RwLock::new(DesiredWorld::from_state(
        state_with_registry(Registry::fresh()),
    )));
    let mut store = NeuroStore::in_memory(world.clone());
    let (registry, membership) = model();
    let state = state_with_registry(registry);
    let meta = SnapshotMeta {
        last_log_id: Some(id(3)),
        last_membership: membership,
        snapshot_id: "model-untrusted-enrollment".into(),
    };
    let file = SnapshotFile {
        meta: meta.clone(),
        state: Sealing::Plain.seal(&state).unwrap(),
    };
    assert!(store
        .install_snapshot(
            &meta,
            Box::new(Cursor::new(serde_json::to_vec(&file).unwrap()))
        )
        .await
        .is_err());
    assert!(!world.read().unwrap().storage_node_directory.has_authority());
    assert!(store.current_snapshot.read().await.is_none());
}
#[tokio::test]
async fn actual_snapshot_cannot_remove_or_replace_existing_enrollment_history() {
    let (registry, membership) = model();
    let world = Arc::new(std::sync::RwLock::new(DesiredWorld::from_state(
        state_with_registry(registry.clone()),
    )));
    let mut store = NeuroStore::in_memory(world.clone());
    *store.storage_directory_history.lock().unwrap() = Some(registry.clone()); // Explicit in-process model, Plain cannot issue.
    let state = state_with_registry(Registry::fresh());
    let meta = SnapshotMeta {
        last_log_id: Some(id(3)),
        last_membership: membership,
        snapshot_id: "model-rollback".into(),
    };
    let file = SnapshotFile {
        meta: meta.clone(),
        state: Sealing::Plain.seal(&state).unwrap(),
    };
    assert!(store
        .install_snapshot(
            &meta,
            Box::new(Cursor::new(serde_json::to_vec(&file).unwrap()))
        )
        .await
        .is_err());
    assert_eq!(world.read().unwrap().storage_node_directory, registry);
}
#[test]
fn membership_change_and_snapshot_before_enrollment_refuse_without_reconfiguration() {
    let (registry, membership) = model();
    registry.require_membership(&membership).unwrap();
    let meta = SnapshotMeta {
        last_log_id: Some(id(1)),
        last_membership: membership,
        snapshot_id: "too-early".into(),
    };
    assert!(require_snapshot_index(&registry, &meta).is_err());
    let changed = StoredMembership::new(
        Some(id(4)),
        openraft::Membership::new(
            vec![[1, 2, 4].into_iter().collect()],
            None::<std::collections::BTreeSet<u64>>,
        ),
    );
    assert!(registry.require_membership(&changed).is_err());
}
#[tokio::test]
async fn actual_membership_apply_then_general_snapshot_preserves_history_but_denies_storage() {
    use openraft::storage::RaftSnapshotBuilder;
    let (registry, membership) = model();
    let world = Arc::new(std::sync::RwLock::new(DesiredWorld::from_state(
        state_with_registry(registry.clone()),
    )));
    let mut store = NeuroStore::in_memory(world.clone());
    *store.storage_directory_history.lock().unwrap() = Some(registry.clone()); // Plain, explicitly model data; no production proof.
    {
        let mut sm = store.sm.lock().unwrap();
        sm.membership = membership;
        sm.last_applied = Some(id(2));
    }
    let changed = openraft::Membership::new(
        vec![[1, 2, 4].into_iter().collect()],
        None::<std::collections::BTreeSet<u64>>,
    );
    let entry = Entry {
        log_id: id(3),
        payload: EntryPayload::Membership(changed),
    };
    store.apply_to_state_machine(&[entry]).await.unwrap();
    let actual_membership = store.sm.lock().unwrap().membership.clone();
    assert!(
        registry.require_membership(&actual_membership).is_err(),
        "issuer remains inactive on actual membership drift"
    );
    let snapshot = store
        .build_snapshot()
        .await
        .expect("general Raft snapshot must not become fatal due to storage-inactive state");
    let file: SnapshotFile = serde_json::from_slice(snapshot.snapshot.get_ref()).unwrap();
    let state = Sealing::Plain.unseal(&file.state).unwrap();
    assert_eq!(state.storage_node_directory, registry);
    assert_eq!(snapshot.meta.last_membership, actual_membership);
    validate_startup(&store, Some(&file)).unwrap();
    // Install into the same history-owning model node also remains a general
    // Raft operation, not an implicit reconfiguration of the storage directory.
    store
        .install_snapshot(
            &snapshot.meta,
            Box::new(Cursor::new(serde_json::to_vec(&file).unwrap())),
        )
        .await
        .unwrap();
    assert_eq!(world.read().unwrap().storage_node_directory, registry);
}
#[test]
fn safe_schema7_metadata_migrates_to_explicit_unenrolled_without_new_node_uid() {
    let state = DesiredWorld::new().to_state();
    let mut old: serde_json::Value =
        serde_json::from_slice(&crate::persist::encode(&state, &[]).unwrap()).unwrap();
    old["schemaVersion"] = 7.into();
    crate::backup_engine::Registry::legacy_v1_fixture(&mut old["state"]);
    old["state"]
        .as_object_mut()
        .unwrap()
        .remove("storage_node_directory");
    let bytes = old.to_string();
    let (decoded, _, previous) = crate::persist::decode(&bytes).unwrap();
    assert_eq!(previous, Some(7));
    assert_eq!(decoded.storage_node_directory, Registry::fresh());
    assert_eq!(decoded.storage_identities, state.storage_identities);
    assert_eq!(old.to_string(), bytes);
    for schema in [0, 1, 2, 6, 7] {
        let mut hidden = old.clone();
        hidden["schemaVersion"] = schema.into();
        hidden["state"]["storage_node_directory"] =
            serde_json::to_value(Registry::fresh()).unwrap();
        assert!(crate::persist::decode(&hidden.to_string()).is_err());
    }
}
#[test]
fn schema8_never_defaults_missing_directory_or_inner_history_fields() {
    let state = DesiredWorld::new().to_state();
    let encoded: serde_json::Value =
        serde_json::from_slice(&crate::persist::encode(&state, &[]).unwrap()).unwrap();
    for field in ["storage_node_directory", "version", "enrollment"] {
        let mut malformed = encoded.clone();
        if field == "storage_node_directory" {
            malformed["state"].as_object_mut().unwrap().remove(field);
        } else {
            malformed["state"]["storage_node_directory"]
                .as_object_mut()
                .unwrap()
                .remove(field);
        }
        assert!(
            crate::persist::decode(&malformed.to_string()).is_err(),
            "{field}"
        );
    }
}
fn isolated(name: &str) -> bool {
    const KEY: &str = "ROYAK_DIRECTORY_DOMAIN_ISOLATED";
    if std::env::var(KEY).as_deref() == Ok(name) {
        return false;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("raft_node::storage_directory_authority::tests::{name}"),
            "--test-threads=1",
        ])
        .env(KEY, name)
        .env(
            "ROYAK_CLUSTER_SECRET",
            "node-directory-isolated-root-test-0123456789",
        )
        .env_remove("ROYAK_CLUSTER_SECRET_FILE")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}
#[test]
fn old_aead_domains_cannot_smuggle_current_directory_fields_or_authenticate_new_domain() {
    if isolated(
        "old_aead_domains_cannot_smuggle_current_directory_fields_or_authenticate_new_domain",
    ) {
        return;
    }
    let state = DesiredWorld::new().to_state();
    let sealed = Sealing::Cluster.seal(&state).unwrap();
    for domain in [
        SEAL_PURPOSE,
        SECURITY_SEAL_PURPOSE,
        STORAGE_SEAL_PURPOSE,
        HOST_SEAL_PURPOSE,
        BACKUP_SEAL_PURPOSE,
        RESTORE_SEAL_PURPOSE,
    ] {
        assert!(crate::auth::unseal_for_cluster(domain, &sealed).is_err());
        let raw = serde_json::to_vec(&state).unwrap();
        let smuggled = crate::auth::seal_for_cluster(domain, &raw).unwrap();
        assert!(Sealing::Cluster.unseal(&smuggled).is_err());
        let mut old = serde_json::to_value(&state).unwrap();
        if domain == BACKUP_SEAL_PURPOSE || domain == RESTORE_SEAL_PURPOSE {
            crate::backup_engine::Registry::legacy_v1_fixture(&mut old);
        } else {
            old.as_object_mut().unwrap().remove("backup_registry");
        }
        old.as_object_mut()
            .unwrap()
            .remove("storage_node_directory");
        let valid_old =
            crate::auth::seal_for_cluster(domain, &serde_json::to_vec(&old).unwrap()).unwrap();
        assert_eq!(
            Sealing::Cluster
                .unseal(&valid_old)
                .unwrap()
                .storage_node_directory,
            Registry::fresh()
        );
    }
}
#[tokio::test]
async fn failed_local_history_write_is_storage_error_and_does_not_advance_last_applied() {
    if isolated("failed_local_history_write_is_storage_error_and_does_not_advance_last_applied") {
        return;
    }
    use std::os::unix::fs::{symlink, PermissionsExt};
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("royak-directory-fatal-{}", Uid::new().as_str()));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    // This is an exact owned unsafe path; no foreign resource is touched.
    symlink(&root, root.join("storage-node-history")).unwrap();
    let (mut registry, membership) = model();
    let mut dto = registry.directory().unwrap().clone();
    dto.cluster_id = crate::auth::derived_cluster_id().unwrap();
    let proposal = EnrollmentProposal {
        version: 1,
        command_uid: Uid::new(),
        directory: dto,
        base_generation: 0,
        term: 7,
        leader: 1,
        membership_sha256: data::digest(&serde_json::to_vec(&membership).unwrap()),
    };
    registry = Registry::fresh();
    let mut state = state_with_registry(registry);
    state.cluster_id = proposal.directory.cluster_id.clone();
    let world = Arc::new(std::sync::RwLock::new(DesiredWorld::from_state(state)));
    let mut store = Arc::new(NeuroStore::empty(
        Some(root.clone()),
        Sealing::Cluster,
        world.clone(),
    ));
    store.sm.lock().unwrap().membership = membership;
    let entry = Entry {
        log_id: id(2),
        payload: EntryPayload::Normal(Command::EnrollStorageDirectory {
            base_generation: 0,
            proposal: proposal.seal().unwrap(),
        }),
    };
    assert!(store.apply_to_state_machine(&[entry]).await.is_err());
    assert!(store.sm.lock().unwrap().last_applied.is_none());
    assert!(!world.read().unwrap().storage_node_directory.has_authority());
    assert!(!root.join("enrollment.sealed").exists());
    std::fs::remove_file(root.join("storage-node-history")).unwrap();
    std::fs::remove_dir(root).unwrap();
}
