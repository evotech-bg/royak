//! Commit first, then deliver a non-deserializable local agent capability.
//! The native/LINSTOR choice is behind ReplicaAgent, not encoded in Core ACKs.
use crate::reconcile::DesiredWorld;
use crate::storage_boot::BootId;
use crate::storage_identity::Uid;
use crate::storage_lifecycle::{Owner, Phase, Volume};
use std::sync::{Arc, RwLock};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplicaTarget {
    pub node_uid: Uid,
    pub boot_id: BootId,
}

/// Cannot be parsed from an HTTP body, private helper JSON or backend stdout.
/// Issued only after store::commit returns success, never after UNKNOWN.
#[derive(Clone, Debug)]
pub(crate) struct ProvisionIntent {
    owner: Owner,
    operation_uid: Uid,
    capacity_bytes: u64,
    targets: [ReplicaTarget; 3],
}

impl ProvisionIntent {
    pub(crate) fn owner(&self) -> &Owner {
        &self.owner
    }
    pub(crate) fn operation_uid(&self) -> &Uid {
        &self.operation_uid
    }
    pub(crate) fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }
    pub(crate) fn targets(&self) -> &[ReplicaTarget; 3] {
        &self.targets
    }

    pub(crate) fn matches(&self, volume: &Volume) -> bool {
        volume.phase() == Phase::Provisioning
            && volume.data_generation().is_none()
            && volume.epoch() == 0
            && volume.assignment().is_none()
            && volume.owner() == &self.owner
            && volume.operation() == &self.operation_uid
            && volume.capacity_bytes() == self.capacity_bytes
            && volume.replicas().is_some_and(|ids| {
                ids.iter()
                    .zip(&self.targets)
                    .all(|(id, t)| id == &t.node_uid)
            })
            && volume.provision_boots().is_some_and(|boots| {
                boots
                    .iter()
                    .zip(&self.targets)
                    .all(|(boot, t)| boot == &t.boot_id)
            })
    }

    pub(crate) fn check_current(&self, world: &Arc<RwLock<DesiredWorld>>) -> Result<(), String> {
        let w = world.read().map_err(|_| "storage world lock poisoned")?;
        let volume = w
            .storage_identities
            .lifecycle
            .get(&self.owner.volume_uid)
            .ok_or("committed storage intent no longer exists")?;
        if w.cluster_id != self.owner.cluster_id || !self.matches(volume) {
            return Err("storage intent is stale, uncommitted or belongs to another owner".into());
        }
        // Validate the current namespace/PVC/PV identity graph too, not merely
        // the historic volume record (retained records may outlive the claim).
        w.storage_identities.validate(&w.to_state())?;
        Ok(())
    }
}

pub(crate) fn reserve_provision(
    world: &Arc<RwLock<DesiredWorld>>,
    volume_uid: &Uid,
    targets: [ReplicaTarget; 3],
    operation_uid: Uid,
) -> Result<ProvisionIntent, crate::store::CommitError> {
    crate::store::commit(world, |w| {
        let volume = w
            .storage_identities
            .lifecycle
            .get_mut(volume_uid)
            .ok_or_else(|| (404, "managed volume is absent".into()))?;
        let nodes = targets.clone().map(|t| t.node_uid);
        let boots = targets.clone().map(|t| t.boot_id);
        volume
            .begin_provision(nodes, boots, operation_uid.clone())
            .map_err(|e| (409, e))?;
        Ok(ProvisionIntent {
            owner: volume.owner().clone(),
            operation_uid,
            capacity_bytes: volume.capacity_bytes(),
            targets,
        })
    })
}

/// Replaceable physical boundary. A prepared Secondary can never ACK the
/// lifecycle's Provisioned transition: this result has no such conversion.
pub(crate) trait ReplicaAgent {
    type SecondaryPrepared;
    fn prepare_secondary(
        &self,
        world: &Arc<RwLock<DesiredWorld>>,
        intent: &ProvisionIntent,
    ) -> Result<Self::SecondaryPrepared, String>;
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeProjection {
    volume: Volume,
    storage_class: crate::reconcile::StoredStorageClass,
    pv: crate::reconcile::StoredPV,
    pvc: crate::reconcile::StoredPVC,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    namespace_identities: Option<std::collections::BTreeMap<String, Uid>>,
}

impl ProvisionIntent {
    /// Identity-only storage projection, no ConfigMaps/Secrets/auth or workloads.
    /// Child MUST use live inherited issuer approval, never this as live state.
    pub(crate) fn export_native_projection(
        &self,
        world: &Arc<RwLock<DesiredWorld>>,
    ) -> Result<Vec<u8>, String> {
        let w = world
            .try_read()
            .map_err(|_| "live world busy/unavailable before helper dispatch")?;
        w.storage_identities.validate(&w.to_state())?;
        let volume = w
            .storage_identities
            .lifecycle
            .get(&self.owner.volume_uid)
            .filter(|v| self.matches(v))
            .ok_or("stale native helper intent")?;
        let pv = w
            .pvs
            .get(&self.owner.pv_name)
            .ok_or("native helper PV missing")?;
        let key = crate::store::obj_key(&self.owner.namespace, &self.owner.claim_name);
        let pvc = w.pvcs.get(&key).ok_or("native helper PVC missing")?;
        let sc = w
            .storage_classes
            .get(&pv.storage_class)
            .ok_or("native helper storage class missing")?;
        serde_json::to_vec(&NativeProjection {
            volume: volume.clone(),
            storage_class: sc.clone(),
            pv: pv.clone(),
            pvc: pvc.clone(),
            namespace_identities: if self.owner.namespace == crate::store::DEFAULT_NS {
                None
            } else {
                Some(std::collections::BTreeMap::from([
                    (
                        crate::store::DEFAULT_NS.into(),
                        w.storage_identities
                            .namespaces
                            .get(crate::store::DEFAULT_NS)
                            .ok_or("default namespace identity missing")?
                            .clone(),
                    ),
                    (
                        self.owner.namespace.clone(),
                        self.owner.namespace_uid.clone(),
                    ),
                ]))
            },
        })
        .map_err(|_| "cannot encode storage-only helper identity projection".into())
    }

    /// Only the inherited private FD/nonce/cgroup verifier can supply this
    /// capability. No raw byte/JSON public constructor or frozen-world permit.
    pub(crate) fn from_verified_native_helper(
        capability: &crate::storage_driver::dispatcher::VerifiedNativeAuthority,
    ) -> Result<(Arc<RwLock<DesiredWorld>>, Self), String> {
        let projection: NativeProjection = serde_json::from_slice(capability.projection_bytes())
            .map_err(|_| "invalid inherited storage identity projection")?;
        let owner = projection.volume.owner().clone();
        let nodes = projection
            .volume
            .replicas()
            .ok_or("helper projection lacks replica identities")?;
        let boots = projection
            .volume
            .provision_boots()
            .ok_or("helper projection lacks committed boots")?;
        let targets = std::array::from_fn(|i| ReplicaTarget {
            node_uid: nodes[i].clone(),
            boot_id: boots[i].clone(),
        });
        let intent = Self {
            owner: owner.clone(),
            operation_uid: projection.volume.operation().clone(),
            capacity_bytes: projection.volume.capacity_bytes(),
            targets,
        };
        if !intent.matches(&projection.volume) || !capability.matches_intent(&intent) {
            return Err("inherited native identity/operation/boot mismatch".into());
        }
        let mut w = DesiredWorld::new();
        w.cluster_id = owner.cluster_id.clone();
        let namespaces = projection.namespace_identities.clone().unwrap_or_else(|| {
            std::collections::BTreeMap::from([(
                owner.namespace.clone(),
                owner.namespace_uid.clone(),
            )])
        });
        let required = if owner.namespace == crate::store::DEFAULT_NS {
            1
        } else {
            2
        };
        if namespaces.len() != required
            || !namespaces.contains_key(crate::store::DEFAULT_NS)
            || namespaces.get(&owner.namespace) != Some(&owner.namespace_uid)
        {
            return Err(
                "native identity projection lacks exact default+owner namespace UIDs".into(),
            );
        }
        w.namespaces = namespaces.keys().cloned().collect();
        w.storage_classes.insert(
            projection.storage_class.name.clone(),
            projection.storage_class,
        );
        w.pvs.insert(projection.pv.name.clone(), projection.pv);
        w.pvcs.insert(
            crate::store::obj_key(&owner.namespace, &owner.claim_name),
            projection.pvc,
        );
        w.storage_identities=serde_json::from_value(serde_json::json!({
            "version":1,"namespaces":namespaces,
            "claims":{crate::store::obj_key(&owner.namespace,&owner.claim_name):{"uid":&owner.claim_uid,"namespace_uid":&owner.namespace_uid}},
            "volumes":{&owner.pv_name:&owner.volume_uid},
            "lifecycle":{"version":1,"volumes":{owner.volume_uid.as_str():projection.volume}}
        })).map_err(|_|"invalid inherited identity graph")?;
        w.storage_identities.validate(&w.to_state())?;
        Ok((Arc::new(RwLock::new(w)), intent))
    }
}

// The next adapter boundary must separately prove all three backend identities,
// initialized generation + fully synced UpToDate replicas, filesystem UUID and
// no writer. No constructor for VerifiedReceipt is added in this stage.

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nondefault_native_projection_preserves_real_default_and_owner_identity() {
        let (world, uid, targets) = world();
        let operation = Uid::new();
        let owner = {
            let mut w = world.write().unwrap();
            let v = w.storage_identities.lifecycle.get_mut(&uid).unwrap();
            v.begin_provision(
                targets.clone().map(|t| t.node_uid),
                targets.clone().map(|t| t.boot_id),
                operation.clone(),
            )
            .unwrap();
            v.owner().clone()
        };
        let intent = ProvisionIntent {
            owner: owner.clone(),
            operation_uid: operation,
            capacity_bytes: world
                .read()
                .unwrap()
                .storage_identities
                .lifecycle
                .get(&uid)
                .unwrap()
                .capacity_bytes(),
            targets,
        };
        let raw = intent.export_native_projection(&world).unwrap();
        let p: NativeProjection = serde_json::from_slice(&raw).unwrap();
        let ids = p.namespace_identities.unwrap();
        assert_eq!(ids.len(), 2);
        assert_eq!(
            ids[crate::store::DEFAULT_NS],
            world.read().unwrap().storage_identities.namespaces[crate::store::DEFAULT_NS]
        );
        assert_eq!(ids[&owner.namespace], owner.namespace_uid);
        world
            .write()
            .unwrap()
            .storage_identities
            .namespaces
            .remove(crate::store::DEFAULT_NS);
        assert!(
            intent.export_native_projection(&world).is_err(),
            "missing default UID must not be synthesized"
        );
    }
    fn world() -> (Arc<RwLock<DesiredWorld>>, Uid, [ReplicaTarget; 3]) {
        let mut w = DesiredWorld::new();
        for value in [
            serde_json::json!({"kind":"StorageClass","metadata":{"name":"replicated"},"spec":{"provisioner":crate::storage_lifecycle::PROVISIONER,"reclaimPolicy":"Retain"}}),
            serde_json::json!({"kind":"PersistentVolumeClaim","metadata":{"name":"data","namespace":"a"},"spec":{"storageClassName":"replicated","accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"64Mi"}}}}),
        ] {
            w.apply(&serde_json::from_value(value).unwrap()).unwrap();
        }
        let uid = w.storage_identities.volumes[w.pvcs["a/data"].bound_pv.as_ref().unwrap()].clone();
        let targets = std::array::from_fn(|_| ReplicaTarget {
            node_uid: Uid::new(),
            boot_id: serde_json::from_value(serde_json::json!(
                "71cb439a-d59b-4d47-9058-2134d97ebd7f"
            ))
            .unwrap(),
        });
        (Arc::new(RwLock::new(w)), uid, targets)
    }
    #[test]
    fn non_durable_intent_never_escapes_commit_and_live_world_is_unchanged() {
        // Other full-suite tests deliberately enable the global file owner.
        // Isolate this negative gate in a fresh test process rather than race
        // their flags or reset shared process-wide durability configuration.
        const ISOLATED: &str = "ROYAK_STORAGE_COMMIT_TEST_ISOLATED";
        if std::env::var_os(ISOLATED).is_none() {
            let output=std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","storage_controller::tests::non_durable_intent_never_escapes_commit_and_live_world_is_unchanged","--test-threads=1"])
                .env(ISOLATED,"1").output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stdout)
            );
            return;
        }
        let (world, uid, targets) = world();
        // A new isolated test process owns neither a state lock nor a Raft
        // quorum. A metadata-only begin_provision is not an agent grant.
        assert!(!crate::store::owns_state());
        let before = world.read().unwrap().to_state().to_canonical_json();
        assert!(matches!(
            reserve_provision(&world, &uid, targets, Uid::new()),
            Err(crate::store::CommitError::NotLeader(_))
        ));
        assert_eq!(world.read().unwrap().to_state().to_canonical_json(), before);
    }
    #[test]
    fn identity_match_is_exact_and_rejects_boot_operation_or_owner_drift() {
        let (world, uid, targets) = world();
        let operation_uid = Uid::new();
        let mut w = world.write().unwrap();
        let volume = w.storage_identities.lifecycle.get_mut(&uid).unwrap();
        volume
            .begin_provision(
                targets.clone().map(|t| t.node_uid),
                targets.clone().map(|t| t.boot_id),
                operation_uid.clone(),
            )
            .unwrap();
        // Test-only structural binding; NOT returned from reserve_provision,
        // never passed to a physical adapter and never treated as a receipt.
        let intent = ProvisionIntent {
            owner: volume.owner().clone(),
            capacity_bytes: volume.capacity_bytes(),
            operation_uid,
            targets,
        };
        assert!(intent.matches(volume));
        for field in 0..5 {
            let mut other = intent.clone();
            match field {
                0 => other.operation_uid = Uid::new(),
                1 => other.owner.namespace_uid = Uid::new(),
                2 => other.owner.claim_uid = Uid::new(),
                3 => other.targets[0].node_uid = Uid::new(),
                _ => {
                    other.targets[0].boot_id = serde_json::from_value(serde_json::json!(
                        "b12c439a-d59b-4d47-9058-2134d97ebd7f"
                    ))
                    .unwrap()
                }
            }
            assert!(!other.matches(volume));
        }
    }

    #[test]
    fn file_commit_returns_intent_only_after_reloadable_boot_bound_state_exists() {
        const ISOLATED: &str = "ROYAK_STORAGE_DURABLE_TEST_ISOLATED";
        if std::env::var_os(ISOLATED).is_none() {
            let output=std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","storage_controller::tests::file_commit_returns_intent_only_after_reloadable_boot_bound_state_exists","--test-threads=1"])
                .env(ISOLATED,"1").output().unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let path = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("royak-agent-commit-{}.json", Uid::new().as_str()));
        crate::store::set_durability(crate::store::Durability::File {
            path: path.to_str().unwrap().into(),
        });
        crate::store::set_owns_state(true);
        let (world, uid, targets) = world();
        let intent = reserve_provision(&world, &uid, targets, Uid::new()).unwrap();
        intent.check_current(&world).unwrap();
        let reloaded = crate::persist::load(path.to_str().unwrap()).unwrap();
        assert!(intent.matches(
            reloaded
                .state
                .storage_identities
                .lifecycle
                .get(&uid)
                .unwrap()
        ));
        assert_eq!(reloaded.state.generation, 1);
        assert_eq!(
            reloaded
                .state
                .storage_identities
                .lifecycle
                .get(&uid)
                .unwrap()
                .phase(),
            Phase::Provisioning
        );
        assert!(world
            .read()
            .unwrap()
            .pvs
            .values()
            .all(|pv| pv.host_path.is_empty()));
        std::fs::remove_file(&path).unwrap();
        let _ = std::fs::remove_file(format!("{}.nrns", path.display()));
    }
}

/// Receiver-side cold intent factory. A raw offer/current World is not enough:
/// accepted remote session and actual applied Core must agree on every field.
pub(crate) fn from_accepted_cold_receiver(
    session:&crate::storage_remote_protocol::ReceiverSession,
    observed:&crate::raft_node::storage_remote_core::CoreObservation,
)->Result<ProvisionIntent,String> {
    let spec=session.accepted_cold_spec()?;
    let volume=observed.volume();
    if spec.owner!=*volume.owner() || spec.operation_uid!=*volume.operation() ||
        observed.local_node_uid()!=Some(&spec.target_node_uid) ||
        observed.actual_boot()!=&spec.target_boot || volume.phase()!=Phase::Provisioning ||
        volume.epoch()!=0 || volume.assignment().is_some() || volume.data_generation().is_some() {
        return Err("accepted cold receiver no longer matches actual applied Core".into());
    }
    let nodes=volume.replicas().ok_or("cold receiver replicas absent")?;
    let boots=volume.provision_boots().ok_or("cold receiver boots absent")?;
    let targets=std::array::from_fn(|index|ReplicaTarget {node_uid:nodes[index].clone(),boot_id:boots[index].clone()});
    let intent=ProvisionIntent {owner:volume.owner().clone(),operation_uid:volume.operation().clone(),
        capacity_bytes:volume.capacity_bytes(),targets};
    if !intent.matches(volume) {return Err("receiver intent cannot be reconstructed from nonmatching Core".into());}
    Ok(intent)
}

/// Normal controller CAS precondition: private plan fsync is not a lock on
/// mutable PVC/SC metadata. Check the exact observed scope INSIDE the one
/// actual commit closure, then reserve, never an out-of-lock check+mutation.
pub(crate) fn reserve_provision_scoped(world:&Arc<RwLock<DesiredWorld>>,uid:&Uid,
    targets:[ReplicaTarget;3],operation:Uid,expected_scope:&str,allowed_classes:&[String])
    ->Result<ProvisionIntent,crate::store::CommitError> {
    crate::store::commit(world,|current|{
        let volume=current.storage_identities.lifecycle.get(uid).ok_or_else(||(404,"managed volume absent".into()))?;
        let owner=volume.owner();
        let pv=current.pvs.get(&owner.pv_name).ok_or_else(||(409,"PV absent".into()))?;
        let pvc=current.pvcs.get(&crate::store::obj_key(&owner.namespace,&owner.claim_name))
            .ok_or_else(||(409,"PVC absent".into()))?;
        let class=current.storage_classes.get(&pv.storage_class).ok_or_else(||(409,"class absent".into()))?;
        let scope=crate::storage_remote_protocol::hash(&serde_json::to_vec(&(volume,pv,pvc,class))
            .map_err(|_|(409,"cannot bind managed scope".into()))?);
        if scope!=expected_scope || !allowed_classes.contains(&pv.storage_class) ||
            class.provisioner!=crate::storage_lifecycle::PROVISIONER {
            return Err((409,"managed scope/class changed before reservation".into()));
        }
        let volume=current.storage_identities.lifecycle.get_mut(uid).ok_or_else(||(404,"volume absent".into()))?;
        let nodes=targets.clone().map(|target|target.node_uid);
        let boots=targets.clone().map(|target|target.boot_id);
        volume.begin_provision(nodes,boots,operation.clone()).map_err(|error|(409,error))?;
        Ok(ProvisionIntent {owner:volume.owner().clone(),operation_uid:operation,
            capacity_bytes:volume.capacity_bytes(),targets})
    })
}

