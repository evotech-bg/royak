//! Pure policy fixtures. These do not construct VerifiedBackupSource, a live
//! fresh-target receipt, a mount/writer, or a successful physical restore.
use super::super::recovery_contract::{
    ControlPreview, RecoveryIntent, RecoveryMapping, SecretSelection,
};
use super::*;

fn checked() -> (DesiredWorld, Registry, Uid) {
    let (w, mut r, uid) = fixture();
    capture_done(&w, &mut r, &uid);
    r.request_check(&w, &id(), &uid).unwrap();
    let attempt = start(&w, &mut r, &uid);
    let evidence = CheckReceipt(CheckEvidence {
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
    r.checked(&uid, &attempt.uid, evidence).unwrap();
    (w, r, uid)
}
fn target(w: &mut DesiredWorld, ns: &str, name: &str) -> Binding {
    if !w.namespaces.iter().any(|n| n == ns) {
        w.namespaces.push(ns.into());
        w.storage_identities
            .namespaces
            .insert(ns.into(), Uid::new());
    }
    let key = crate::store::obj_key(ns, name);
    let pv = format!("target-{ns}-{name}");
    w.pvs.insert(
        pv.clone(),
        crate::reconcile::StoredPV {
            name: pv.clone(),
            capacity: "1Gi".into(),
            storage_class: "test".into(),
            host_path: "/not-physical-authority".into(),
            access_mode: "ReadWriteOnce".into(),
            status: crate::reconcile::PVStatus::Bound,
            bound_to: Some(key.clone()),
        },
    );
    w.pvcs.insert(
        key.clone(),
        crate::reconcile::StoredPVC {
            name: name.into(),
            namespace: ns.into(),
            storage_class: "test".into(),
            requested: "1Gi".into(),
            access_mode: "ReadWriteOnce".into(),
            bound_pv: Some(pv.clone()),
        },
    );
    w.storage_identities.claims.insert(
        key,
        crate::storage_identity::ClaimIdentity {
            uid: Uid::new(),
            namespace_uid: w.storage_identities.namespaces[ns].clone(),
        },
    );
    w.storage_identities.volumes.insert(pv, Uid::new());
    Binding::resolve(w, ns, name).unwrap()
}
fn reserve_restore() -> (DesiredWorld, Registry, Uid) {
    let (mut w, mut r, uid) = checked();
    let destination = target(&mut w, "default", "fresh");
    let plan = RestorePlan::new(&w, &id(), r.job(&uid).unwrap(), destination, 1000, 300).unwrap();
    let hash = plan.hash().unwrap();
    r.request_restore(&w, &uid, plan, &hash, 300).unwrap();
    (w, r, uid)
}
fn running_policy_only(r: &mut Registry, uid: &Uid) -> Uid {
    // Deliberate metadata-only invalid-completion fixture. Public start refuses
    // Restore until an independently observed physical target lease exists.
    let job = r.jobs.get_mut(uid).unwrap();
    let attempt = Uid::new();
    job.state = State::Running;
    job.attempts_started += 1;
    job.partial_effects_possible = true;
    job.attempt = Some(Attempt {
        uid: attempt.clone(),
        operation: Operation::Restore,
        started_unix_ms: 350,
        node_uid: Uid::new(),
        boot_id: "12345678-1234-1234-1234-123456789abc".into(),
    });
    attempt
}
fn evidence_for_negative_test(r: &Registry, uid: &Uid, attempt: Uid) -> RestoreEvidence {
    let job = r.job(uid).unwrap();
    let captured = job.captured.as_ref().unwrap();
    let plan = job.restore_plan.as_ref().unwrap();
    RestoreEvidence {
        snapshot_id: captured.snapshot_id.clone(),
        destination_volume_uid: plan.destination.volume_uid.clone(),
        tree_sha256: captured.tree_sha256.clone(),
        verified_unix_ms: 500,
        application_evidence_sha256: None,
        adapter_receipt_sha256: "4".repeat(64),
        restore_plan_sha256: plan.hash().unwrap(),
        attempt_uid: attempt,
    }
}

#[test]
fn restore_intent_cannot_dispatch_without_physical_target_lease() {
    let (w, mut r, uid) = reserve_restore();
    let before = r.clone();
    assert!(r
        .start(
            &w,
            &uid,
            Uid::new(),
            "12345678-1234-1234-1234-123456789abc".into(),
            350
        )
        .unwrap_err()
        .contains("fresh-target lease"));
    assert_eq!(r, before);
}
#[test]
fn restore_completion_cannot_omit_restore_verified_evidence() {
    let (_, mut r, uid) = reserve_restore();
    running_policy_only(&mut r, &uid);
    let running = r.clone();
    let job = r.jobs.get_mut(&uid).unwrap();
    job.state = State::Idle;
    job.attempt = None;
    job.partial_effects_possible = false;
    assert!(r.validate().is_err());
    assert!(running.validate_transition(&r).is_err());
}
#[test]
fn invalid_restore_ack_is_atomic_and_binds_plan_attempt_target_and_freshness() {
    let (_, mut r, uid) = reserve_restore();
    let attempt = running_policy_only(&mut r, &uid);
    let before = r.clone();
    for fault in 0..6 {
        let mut receipt = evidence_for_negative_test(&r, &uid, attempt.clone());
        match fault {
            0 => receipt.snapshot_id = "9".repeat(64),
            1 => receipt.destination_volume_uid = Uid::new(),
            2 => receipt.restore_plan_sha256 = "0".repeat(64),
            3 => receipt.attempt_uid = Uid::new(),
            4 => receipt.verified_unix_ms = 199,
            _ => receipt.verified_unix_ms = 1000,
        }
        assert!(
            r.restored(&uid, &attempt, RestoreReceipt(receipt)).is_err(),
            "fault={fault}"
        );
        assert_eq!(r, before, "fault={fault} must not alter the running job");
    }
}
#[test]
fn stale_source_and_far_future_restore_approval_are_refused() {
    let (mut w, mut r, uid) = checked();
    let destination = target(&mut w, "default", "fresh");
    let mut plan =
        RestorePlan::new(&w, &id(), r.job(&uid).unwrap(), destination, 1000, 300).unwrap();
    plan.expires_unix_ms = 2_000_000;
    let hash = plan.hash().unwrap();
    assert!(plan.reauthorize(&w, 300, &hash).is_err());
    plan.expires_unix_ms = 1000;
    let hash = plan.hash().unwrap();
    w.storage_identities
        .claims
        .get_mut(&crate::store::obj_key("default", "data"))
        .unwrap()
        .uid = Uid::new();
    assert!(r.request_restore(&w, &uid, plan, &hash, 300).is_err());
}
#[test]
fn restore_target_cannot_be_reserved_twice_even_before_dispatch() {
    let (mut w, mut r, uid) = checked();
    let mut second = r.job(&uid).unwrap().plan.clone();
    second.uid = Uid::new();
    let second_uid = r.enqueue(&w, second).unwrap();
    capture_done(&w, &mut r, &second_uid);
    r.request_check(&w, &id(), &second_uid).unwrap();
    let a = start(&w, &mut r, &second_uid);
    r.checked(
        &second_uid,
        &a.uid,
        CheckReceipt(CheckEvidence {
            snapshot_id: r
                .job(&second_uid)
                .unwrap()
                .captured
                .as_ref()
                .unwrap()
                .snapshot_id
                .clone(),
            checked_unix_ms: 200,
            full_read_data: true,
            adapter_receipt_sha256: "3".repeat(64),
        }),
    )
    .unwrap();
    let destination = target(&mut w, "default", "fresh");
    let first = RestorePlan::new(
        &w,
        &id(),
        r.job(&uid).unwrap(),
        destination.clone(),
        1000,
        300,
    )
    .unwrap();
    let second = RestorePlan::new(
        &w,
        &id(),
        r.job(&second_uid).unwrap(),
        destination,
        1000,
        300,
    )
    .unwrap();
    r.request_restore(&w, &uid, first.clone(), &first.hash().unwrap(), 300)
        .unwrap();
    let before = r.clone();
    assert!(r
        .request_restore(
            &w,
            &second_uid,
            second.clone(),
            &second.hash().unwrap(),
            300
        )
        .is_err());
    assert_eq!(r, before);
    let job = r.jobs.get_mut(&second_uid).unwrap();
    job.restore_plan = Some(second);
    job.requested = Operation::Restore;
    job.state = State::Queued;
    assert!(
        r.validate().is_err(),
        "whole-state replacement must not bypass destination uniqueness"
    );
}
#[test]
fn pending_restore_target_cannot_become_an_immutable_capture_source_by_metadata() {
    let (w, mut r, uid) = reserve_restore();
    let job = r.job(&uid).unwrap();
    let mut descriptor = job.plan.source.clone();
    descriptor.binding = job.restore_plan.as_ref().unwrap().destination.clone();
    let plan = CapturePlan::authorized(&w, &id(), descriptor, &job.plan.repository, false).unwrap();
    assert!(r.enqueue(&w, plan).is_err());
}
#[test]
fn formerly_used_capture_volume_is_not_a_fresh_restore_target() {
    let (mut w, mut r, uid) = checked();
    let destination = target(&mut w, "default", "used");
    let job = r.job(&uid).unwrap();
    let mut descriptor = job.plan.source.clone();
    descriptor.binding = destination.clone();
    let plan = CapturePlan::authorized(&w, &id(), descriptor, &job.plan.repository, false).unwrap();
    r.enqueue(&w, plan).unwrap();
    let restore =
        RestorePlan::new(&w, &id(), r.job(&uid).unwrap(), destination, 1000, 300).unwrap();
    assert!(r
        .request_restore(&w, &uid, restore.clone(), &restore.hash().unwrap(), 300)
        .is_err());
}

fn preview(w: &DesiredWorld) -> ControlPreview {
    ControlPreview::prepare(w, &admin(), "default", SecretSelection::Omit, 100, 1000).unwrap()
}
fn recovery(w: &mut DesiredWorld, p: &ControlPreview) -> RecoveryIntent {
    let source = Binding::resolve(w, "default", "data").unwrap();
    let destination = target(w, "recovered", "data");
    RecoveryIntent::prepare(
        w,
        &admin(),
        p,
        "recovered",
        vec![RecoveryMapping {
            source_volume_uid: source.volume_uid,
            destination,
        }],
        200,
        900,
    )
    .unwrap()
}
#[test]
fn view_and_secret_read_are_not_control_or_secret_export_authority() {
    let mut w = world();
    grant(&mut w, &["get", "list"], &["*"]);
    assert!(
        ControlPreview::prepare(&w, &id(), "default", SecretSelection::Omit, 100, 1000).is_err()
    );
    w.secrets.insert(
        "default/key".into(),
        crate::reconcile::StoredSecret {
            name: "key".into(),
            namespace: "default".into(),
            data: Default::default(),
        },
    );
    grant(&mut w, &["export"], &["controlbackups"]);
    assert!(
        ControlPreview::prepare(&w, &id(), "default", SecretSelection::Omit, 100, 1000).is_ok()
    );
    assert!(ControlPreview::prepare(
        &w,
        &id(),
        "default",
        SecretSelection::ExplicitNames(vec!["key".into()]),
        100,
        1000
    )
    .is_err());
}
#[test]
fn control_preview_never_serializes_secret_raw_manifest_or_annotation_payload() {
    let mut w = world();
    const SECRET: &str = "synthetic-never-export-secret-value";
    w.secrets.insert(
        "default/key".into(),
        crate::reconcile::StoredSecret {
            name: "key".into(),
            namespace: "default".into(),
            data: std::collections::HashMap::from([("password".into(), SECRET.into())]),
        },
    );
    w.manifests.insert(
        "Secret/default/key".into(),
        serde_json::json!({"kind":"Secret","data":{"password":SECRET},
        "metadata":{"annotations":{"kubectl.kubernetes.io/last-applied-configuration":SECRET}}}),
    );
    let p = preview(&w);
    let encoded = serde_json::to_string(&p).unwrap();
    assert!(!encoded.contains(SECRET));
    assert!(!p.audit_metadata().to_string().contains(SECRET));
    assert!(p.export_bytes().is_err());
    assert!(p
        .blocked_requirements()
        .contains(&"AuthoritativeCommittedRead"));
}
#[test]
fn explicit_secret_grant_still_cannot_bypass_independent_escrow() {
    let mut w = world();
    w.secrets.insert(
        "default/key".into(),
        crate::reconcile::StoredSecret {
            name: "key".into(),
            namespace: "default".into(),
            data: std::collections::HashMap::from([("secret".into(), "sensitive-value".into())]),
        },
    );
    grant(&mut w, &["export"], &["controlbackups", "secrets"]);
    let p = ControlPreview::prepare(
        &w,
        &id(),
        "default",
        SecretSelection::ExplicitNames(vec!["key".into()]),
        100,
        1000,
    )
    .unwrap();
    assert!(p
        .blocked_requirements()
        .contains(&"IndependentSecretEscrowAndMaterialExport"));
    assert!(p.export_bytes().is_err());
    assert!(!serde_json::to_string(&p)
        .unwrap()
        .contains("sensitive-value"));
    assert!(!p.audit_metadata().to_string().contains("\"key\""));
}
#[test]
fn preview_approval_tracks_current_identity_generation_window_and_rights() {
    let mut w = world();
    grant(&mut w, &["export"], &["controlbackups"]);
    let p =
        ControlPreview::prepare(&w, &id(), "default", SecretSelection::Omit, 100, 1000).unwrap();
    let hash = p.hash().unwrap();
    assert!(p.reauthorize(&w, &id(), 200, &hash).is_ok());
    assert!(p.reauthorize(&w, &id(), 99, &hash).is_err());
    assert!(p.reauthorize(&w, &id(), 1000, &hash).is_err());
    assert!(p.reauthorize(&w, &id(), 200, &"0".repeat(64)).is_err());
    w.rbac_roles.remove("operator");
    assert!(p.reauthorize(&w, &id(), 200, &hash).is_err());
    grant(&mut w, &["export"], &["controlbackups"]);
    w.generation += 1;
    assert!(p.reauthorize(&w, &id(), 200, &hash).is_err());
}
#[test]
fn namespace_recreation_cannot_retarget_old_control_preview() {
    let mut w = world();
    let p = preview(&w);
    let hash = p.hash().unwrap();
    w.storage_identities
        .namespaces
        .insert("default".into(), Uid::new());
    assert!(p.reauthorize(&w, &admin(), 200, &hash).is_err());
}
#[test]
fn recovery_is_quarantined_and_never_materializes_live_authority() {
    let mut w = world();
    let p = preview(&w);
    let r = recovery(&mut w, &p);
    let before = w.to_state().to_canonical_json();
    assert!(r.reauthorize(&w, &admin(), 300, &r.hash().unwrap()).is_ok());
    assert!(!r.workloads_may_start());
    assert!(r.materialize_desired_state().is_err());
    assert_eq!(w.to_state().to_canonical_json(), before);
    for forbidden in [
        "connect_sessions",
        "raft_peers",
        "writer_grants",
        "host_access",
        "rbac_bindings",
    ] {
        let mut encoded = serde_json::to_value(&r).unwrap();
        encoded[forbidden] = serde_json::json!([]);
        assert!(serde_json::from_value::<RecoveryIntent>(encoded).is_err());
    }
    let mut encoded = serde_json::to_value(&r).unwrap();
    encoded["phase"] = "Ready".into();
    assert!(serde_json::from_value::<RecoveryIntent>(encoded).is_err());
}
#[test]
fn recovery_requires_cluster_recovery_not_only_namespace_restore_rights() {
    let mut w = world();
    let p = preview(&w);
    let source = Binding::resolve(&w, "default", "data").unwrap();
    let dest = target(&mut w, "recovered", "data");
    grant(
        &mut w,
        &["recover", "create"],
        &["controlbackups", "restores"],
    );
    assert!(RecoveryIntent::prepare(
        &w,
        &id(),
        &p,
        "recovered",
        vec![RecoveryMapping {
            source_volume_uid: source.volume_uid,
            destination: dest
        }],
        200,
        900
    )
    .is_err());
}
#[test]
fn recovery_refuses_missing_duplicate_foreign_and_stale_target_mappings() {
    let mut w = world();
    let p = preview(&w);
    let source = Binding::resolve(&w, "default", "data").unwrap();
    let dest = target(&mut w, "recovered", "data");
    assert!(RecoveryIntent::prepare(&w, &admin(), &p, "recovered", vec![], 200, 900).is_err());
    let mapping = RecoveryMapping {
        source_volume_uid: source.volume_uid,
        destination: dest.clone(),
    };
    assert!(RecoveryIntent::prepare(
        &w,
        &admin(),
        &p,
        "recovered",
        vec![mapping.clone(), mapping.clone()],
        200,
        900
    )
    .is_err());
    let mut foreign = mapping.clone();
    foreign.destination.namespace_uid = Uid::new();
    assert!(
        RecoveryIntent::prepare(&w, &admin(), &p, "recovered", vec![foreign], 200, 900).is_err()
    );
    let r =
        RecoveryIntent::prepare(&w, &admin(), &p, "recovered", vec![mapping], 200, 900).unwrap();
    w.storage_identities
        .claims
        .get_mut(&crate::store::obj_key("recovered", "data"))
        .unwrap()
        .uid = Uid::new();
    assert!(r
        .reauthorize(&w, &admin(), 300, &r.hash().unwrap())
        .is_err());
}
#[test]
fn recovery_cancel_and_expiry_do_not_turn_into_cutover() {
    let mut w = world();
    let p = preview(&w);
    let mut r = recovery(&mut w, &p);
    let approval = r.hash().unwrap();
    assert!(r.reauthorize(&w, &admin(), 900, &approval).is_err());
    r.cancel(&w, &admin(), 300, &approval).unwrap();
    assert!(!r.workloads_may_start());
    assert!(r
        .reauthorize(&w, &admin(), 301, &r.hash().unwrap())
        .is_err());
    assert!(r.materialize_desired_state().is_err());
}
