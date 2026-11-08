//! Dataset identity is planned durably before the first initialization write.
//! It is not a writer registry and a stored provenance reference is not a fresh
//! physical observation. Actual initialization must recheck every local fact.
use super::{valid_hash, valid_uuid, BootId, Owner, Phase, Uid, Volume};
use crate::reconcile::DesiredWorld;
use crate::storage_controller::ProvisionIntent;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};
#[path = "storage_initialization_projection.rs"]
mod initialization_projection;
#[path = "storage_init_physical_proof.rs"]
pub(crate) mod physical;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VirginReplicaRef {
    pub(crate) volume_uid: Uid,
    pub(crate) prepare_operation_uid: Uid,
    pub(crate) node_uid: Uid,
    pub(crate) node_boot_id: BootId,
    pub(crate) pool_uid: Uid,
    pub(crate) allocation_nonce: Uid,
    pub(crate) lv_uuid: String,
    pub(crate) drbd_device_uuid: String,
    pub(crate) requested_bytes: u64,
    pub(crate) exposed_bytes: u64,
    pub(crate) plan_sha256: String,
    pub(crate) zero_sha256: String,
    pub(crate) observation_sha256: String,
}
fn lv_uuid(value: &str) -> bool {
    value.len() == 38
        && value.split('-').map(str::len).eq([6, 4, 4, 4, 4, 4, 6])
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
impl VirginReplicaRef {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.requested_bytes == 0
            || self.exposed_bytes
                != crate::storage_driver::rounded_data_bytes(self.requested_bytes)?
            || !lv_uuid(&self.lv_uuid)
            || self.drbd_device_uuid.len() != 16
            || self.drbd_device_uuid == "0000000000000000"
            || !self
                .drbd_device_uuid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || ![
                &self.plan_sha256,
                &self.zero_sha256,
                &self.observation_sha256,
            ]
            .into_iter()
            .all(|v| valid_hash(v))
        {
            return Err("invalid exact virgin-replica provenance".into());
        }
        Ok(())
    }
}

/// Collects actual typed local observations only. It has no deserializer or
/// constructor accepting stdout/JSON. Authenticated remote observation delivery
/// must be added separately before a leader can collect three remote facts.
pub(crate) struct VerifiedVirginSet {
    owner: Owner,
    preparation: Uid,
    facts: [VirginReplicaRef; 3],
    held: Option<Arc<crate::storage_driver::dispatcher::init_authority::RetainedLineage>>,
}
impl VerifiedVirginSet {
    /// A persisted reference is not accepted here: the caller must still own
    /// three newly observed opaque local proofs. Remote delivery is separate.
    pub(crate) fn check_initialization(&self, intent: &InitializationIntent) -> Result<(), String> {
        if self.owner != intent.owner
            || self.preparation != intent.generation.prepare_operation_uid
            || self.facts != intent.generation.virgin_replicas
        {
            return Err(
                "fresh observations differ from the committed exact initialization lineage".into(),
            );
        }
        if let Some(held) = &self.held {
            held.matches_initialization(intent)?;
        }
        Ok(())
    }
    /// Requires actual retained completed jobs; bare diagnostic probes cannot
    /// reserve Core data after releasing their node admission/kernel locks.
    pub(crate) fn from_retained_jobs(
        intent: &ProvisionIntent,
        held: Arc<crate::storage_driver::dispatcher::init_authority::RetainedLineage>,
    ) -> Result<Self, String> {
        held.assert_held()?;
        let facts = held.facts().clone();
        validate_facts(
            intent.owner(),
            intent.operation_uid(),
            intent.capacity_bytes(),
            &intent.targets().clone().map(|target| target.node_uid),
            &intent.targets().clone().map(|target| target.boot_id),
            &facts,
        )?;
        Ok(Self {
            owner: intent.owner().clone(),
            preparation: intent.operation_uid().clone(),
            facts,
            held: Some(held),
        })
    }
    pub(crate) fn retained_lineage(
        &self,
    ) -> Option<&Arc<crate::storage_driver::dispatcher::init_authority::RetainedLineage>> {
        self.held.as_ref()
    }
}

fn validate_facts(
    owner: &Owner,
    prepare: &Uid,
    capacity: u64,
    nodes: &[Uid; 3],
    boots: &[BootId; 3],
    facts: &[VirginReplicaRef; 3],
) -> Result<(), String> {
    let mut nonces = BTreeSet::new();
    let mut lvs = BTreeSet::new();
    let mut devices = BTreeSet::new();
    for (i, fact) in facts.iter().enumerate() {
        fact.validate()?;
        if fact.volume_uid != owner.volume_uid
            || &fact.prepare_operation_uid != prepare
            || fact.node_uid != nodes[i]
            || fact.node_boot_id != boots[i]
            || fact.requested_bytes != capacity
            || !nonces.insert(&fact.allocation_nonce)
            || !lvs.insert(&fact.lv_uuid)
            || !devices.insert(&fact.drbd_device_uuid)
        {
            return Err("virgin replicas are incomplete, duplicated or for another committed preparation/boot".into());
        }
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DataGeneration {
    pub(crate) version: u32,
    pub(crate) uid: Uid,
    pub(crate) prepare_operation_uid: Uid,
    pub(crate) initialize_operation_uid: Uid,
    pub(crate) filesystem_uuid: String,
    pub(crate) initializer_node_uid: Uid,
    pub(crate) virgin_replicas: [VirginReplicaRef; 3],
}
fn filesystem_uuid() -> String {
    let uid = Uid::new();
    let raw = uid.as_str();
    // A distinct server-owned identity. No UUID is read from an existing disk.
    format!(
        "{}-{}-4{}-a{}-{}",
        &raw[..8],
        &raw[8..12],
        &raw[13..16],
        &raw[17..20],
        &raw[20..]
    )
}
impl DataGeneration {
    pub(crate) fn validate(&self, volume: &Volume) -> Result<(), String> {
        let nodes = volume
            .replicas
            .as_ref()
            .ok_or("generation has no replicas")?;
        let boots = volume
            .provision_boots
            .as_ref()
            .ok_or("generation has no committed boots")?;
        if self.version != 1
            || !valid_uuid(&self.filesystem_uuid)
            || self.filesystem_uuid == "00000000-0000-0000-0000-000000000000"
            || self.prepare_operation_uid == self.initialize_operation_uid
            || self.uid == volume.owner.volume_uid
            || self.uid == self.prepare_operation_uid
            || self.uid == self.initialize_operation_uid
            || !nodes.contains(&self.initializer_node_uid)
        {
            return Err("invalid immutable dataset initialization identity".into());
        }
        validate_facts(
            &volume.owner,
            &self.prepare_operation_uid,
            volume.capacity_bytes,
            nodes,
            boots,
            &self.virgin_replicas,
        )
    }
}

/// Created only after durable commit. This is an initialization operation, not
/// a mount/writer capability; the existing Assignment remains the sole writer.
#[derive(Clone, Debug)]
pub(crate) struct InitializationIntent {
    owner: Owner,
    generation: DataGeneration,
    capacity_bytes: u64,
}
impl InitializationIntent {
    pub(crate) fn owner(&self) -> &Owner {
        &self.owner
    }
    pub(crate) fn generation(&self) -> &DataGeneration {
        &self.generation
    }
    pub(crate) fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }
    pub(crate) fn operation_uid(&self) -> &Uid {
        &self.generation.initialize_operation_uid
    }
    pub(crate) fn local_initializer(
        &self,
        node: &Uid,
        boot: &BootId,
    ) -> Result<&VirginReplicaRef, String> {
        if node != &self.generation.initializer_node_uid {
            return Err("only the committed initializer may create this fresh generation".into());
        }
        self.generation
            .virgin_replicas
            .iter()
            .find(|fact| &fact.node_uid == node && &fact.node_boot_id == boot)
            .ok_or_else(|| "initializer boot changed; no initialization replay permitted".into())
    }
    pub(crate) fn matches(&self, volume: &Volume) -> bool {
        volume.phase == Phase::Provisioning
            && volume.epoch == 0
            && volume.assignment.is_none()
            && volume.filesystem_uuid.is_none()
            && volume.owner == self.owner
            && volume.capacity_bytes == self.capacity_bytes
            && volume.operation == self.generation.initialize_operation_uid
            && volume.data_generation.as_ref() == Some(&self.generation)
    }
    pub(crate) fn check_current(&self, world: &Arc<RwLock<DesiredWorld>>) -> Result<(), String> {
        let w = world
            .try_read()
            .map_err(|_| "live initialization world busy/unavailable")?;
        if w.cluster_id != self.owner.cluster_id
            || !w
                .storage_identities
                .lifecycle
                .get(&self.owner.volume_uid)
                .is_some_and(|v| self.matches(v))
        {
            return Err(
                "initialization intent is stale or not the committed owner/generation".into(),
            );
        }
        w.storage_identities.validate(&w.to_state())
    }
}

/// The returned commit value retains all exact node leases throughout actual
/// durable publication, not only while the scratch-state closure is running.
pub(crate) struct ReservedInitialization {
    intent: InitializationIntent,
    virgin: VerifiedVirginSet,
}
impl std::ops::Deref for ReservedInitialization {
    type Target = InitializationIntent;
    fn deref(&self) -> &Self::Target {
        &self.intent
    }
}
impl ReservedInitialization {
    pub(crate) fn into_parts(self) -> (InitializationIntent, VerifiedVirginSet) {
        (self.intent, self.virgin)
    }
}
pub(crate) fn reserve_initialization(
    world: &Arc<RwLock<DesiredWorld>>,
    prepare: &ProvisionIntent,
    virgin: VerifiedVirginSet,
    initializer: Uid,
    operation: Uid,
) -> Result<ReservedInitialization, crate::store::CommitError> {
    crate::store::commit(world, move |w| {
        let volume = w
            .storage_identities
            .lifecycle
            .get_mut(&prepare.owner().volume_uid)
            .ok_or_else(|| (404, "managed volume absent".into()))?;
        if virgin.owner != *prepare.owner() || virgin.preparation != *prepare.operation_uid() {
            return Err((
                409,
                "virgin observations belong to another preparation".into(),
            ));
        }
        if let Some(existing) = &volume.data_generation {
            if existing.initialize_operation_uid == operation
                && existing.initializer_node_uid == initializer
                && existing.virgin_replicas == virgin.facts
                && volume.phase == Phase::Provisioning
                && volume.assignment.is_none()
                && volume.operation == operation
                && volume.owner == virgin.owner
            {
                return Ok(ReservedInitialization {
                    intent: InitializationIntent {
                        owner: volume.owner.clone(),
                        generation: existing.clone(),
                        capacity_bytes: volume.capacity_bytes,
                    },
                    virgin,
                });
            }
            return Err((
                409,
                "initialization already reserved; never replace or reinitialize its dataset".into(),
            ));
        }
        if !prepare.matches(volume) {
            return Err((
                409,
                "preparation is not the current committed unwritable operation".into(),
            ));
        }
        let generation = DataGeneration {
            version: 1,
            uid: Uid::new(),
            prepare_operation_uid: virgin.preparation.clone(),
            initialize_operation_uid: operation,
            filesystem_uuid: filesystem_uuid(),
            initializer_node_uid: initializer,
            virgin_replicas: virgin.facts.clone(),
        };
        volume
            .begin_initialization(generation.clone())
            .map_err(|e| (409, e))?;
        Ok(ReservedInitialization {
            intent: InitializationIntent {
                owner: volume.owner.clone(),
                generation,
                capacity_bytes: volume.capacity_bytes,
            },
            virgin,
        })
    })
}

/// A prospective record only. The actual move-only distributed round remains
/// at its producer; this DATA cannot become the old three-local-jobs proof.
pub(crate) fn propose_generation(
    round: &crate::storage_driver::native_runtime::init::DistributedColdRound,
    initializer: Uid,
    operation: Uid,
) -> Result<DataGeneration, String> {
    pipeline_live(round.deadline())?;
    let prepare = round.prepare();
    validate_facts(prepare.owner(), prepare.operation_uid(), prepare.capacity_bytes(),
        &prepare.targets().clone().map(|target| target.node_uid),
        &prepare.targets().clone().map(|target| target.boot_id), round.facts())?;
    if operation == *prepare.operation_uid()
        || !prepare.targets().iter().any(|target| target.node_uid == initializer)
    { return Err("distributed generation has wrong initializer or reused operation".into()); }
    Ok(DataGeneration {
        version: 1,
        uid: Uid::new(),
        prepare_operation_uid: prepare.operation_uid().clone(),
        initialize_operation_uid: operation,
        filesystem_uuid: filesystem_uuid(),
        initializer_node_uid: initializer,
        virgin_replicas: round.facts().clone(),
    })
}

fn pipeline_live(deadline: std::time::Instant) -> Result<(), String> {
    let now = std::time::Instant::now();
    if now >= deadline || deadline.duration_since(now) > std::time::Duration::from_secs(180) {
        return Err("original initialization pipeline deadline expired or invalid".into());
    }
    Ok(())
}
fn actual_distributed_world(world: &Arc<RwLock<DesiredWorld>>) -> Result<(), String> {
    let handle = crate::raft_node::RAFT.get().ok_or("distributed initialization requires actual Raft")?;
    if handle.sealing != crate::raft_node::Sealing::Cluster
        || !crate::raft_node::storage_remote_core::is_actual_world(world)
    { return Err("distributed initialization refuses plain/foreign/frozen World".into()); }
    Ok(())
}
fn rejected(reason: String) -> crate::store::CommitError {
    crate::store::CommitError::Rejected(409, reason)
}

/// Borrows the armed owners. Neither commit rejection nor UNKNOWN publication
/// drops a node lease; only the owner can later perform a verified transition.
pub(crate) fn reserve_distributed_initialization(
    world: &Arc<RwLock<DesiredWorld>>,
    round: &crate::storage_driver::native_runtime::init::ArmedInitializationRound,
) -> Result<InitializationIntent, crate::store::CommitError> {
    actual_distributed_world(world).map_err(rejected)?;
    pipeline_live(round.deadline()).map_err(rejected)?;
    round.assert_actual_store(world).map_err(rejected)?;
    let intent = crate::store::commit(world, |current| {
        pipeline_live(round.deadline()).map_err(|error| (409, error))?;
        round.validate_commit_scope(current).map_err(|error| (409, error))?;
        let volume = current.storage_identities.lifecycle.get_mut(&round.prepare().owner().volume_uid)
            .ok_or_else(|| (404, String::from("managed volume absent")))?;
        if !round.prepare().matches(volume) || volume.data_generation.is_some() {
            return Err((409, "distributed initialization is one-shot, not metadata replay authority".into()));
        }
        round.generation().validate(volume).map_err(|error| (409, error))?;
        if round.generation().prepare_operation_uid != *round.prepare().operation_uid() {
            return Err((409, "armed generation preparation changed".into()));
        }
        volume.begin_initialization(round.generation().clone()).map_err(|error| (409, error))?;
        Ok(InitializationIntent { owner: volume.owner.clone(), generation: round.generation().clone(),
            capacity_bytes: volume.capacity_bytes })
    })?;
    // A successful-but-late commit is diagnostic UNKNOWN, not a renewed grant.
    pipeline_live(round.deadline()).map_err(crate::store::CommitError::Unknown)?;
    Ok(intent)
}

/// Acknowledged metadata only. No release, mount or writer capability.
pub(crate) struct CommittedGeneration { intent: InitializationIntent }
impl CommittedGeneration {
    pub(crate) fn intent(&self) -> &InitializationIntent { &self.intent }
    pub(crate) fn generation(&self) -> &DataGeneration { self.intent.generation() }
    pub(crate) fn owner(&self) -> &Owner { self.intent.owner() }
}

fn validate_offline_round(intent: &InitializationIntent,
    primary: &physical::PrimaryFlushObservation,
    offline: &[physical::OfflineReplicaObservation; 3]) -> Result<(), String> {
    primary.validate_for(intent)?;
    for (index, observation) in offline.iter().enumerate() {
        observation.validate_for(intent)?;
        if observation.replica != intent.generation().virgin_replicas[index]
            || observation.data_sha256 != primary.data_sha256
            || observation.filesystem_uuid != primary.filesystem_uuid
        { return Err("three independent offline copies must equal the flushed initializer generation".into()); }
    }
    Ok(())
}

/// Only the producer-owned live round can reach this private lifecycle receipt
/// factory. Parsed observations alone cannot call it. All three physical facts
/// and their fresh completion/owner checks must have survived at the producer.
pub(crate) fn commit_distributed_provisioned(
    world: &Arc<RwLock<DesiredWorld>>,
    round: &crate::storage_driver::native_runtime::init::VerifiedInitializedRound,
) -> Result<CommittedGeneration, crate::store::CommitError> {
    actual_distributed_world(world).map_err(rejected)?;
    pipeline_live(round.deadline()).map_err(rejected)?;
    round.assert_actual_store(world).map_err(rejected)?;
    validate_offline_round(round.intent(), round.primary(), round.offline()).map_err(rejected)?;
    let digest = crate::storage_remote_protocol::hash(&serde_json::to_vec(&(
        "royak-physical-three-node-generation-v1", round.intent().owner(), round.intent().generation(),
        round.primary(), round.offline())).map_err(|_| rejected("cannot bind physical generation evidence".into()))?);
    let evidence = super::EvidenceRef { uid: Uid::new(), sha256: digest };
    let committed = crate::store::commit(world, |current| {
        pipeline_live(round.deadline()).map_err(|error| (409, error))?;
        round.validate_commit_scope(current).map_err(|error| (409, error))?;
        validate_offline_round(round.intent(), round.primary(), round.offline()).map_err(|error| (409, error))?;
        let volume = current.storage_identities.lifecycle.get_mut(&round.intent().owner().volume_uid)
            .ok_or_else(|| (404, String::from("initialized volume absent")))?;
        if !round.intent().matches(volume) {
            return Err((409, "physical completion no longer matches exact committed initialization".into()));
        }
        let replicas = volume.replicas.clone().ok_or_else(|| (409, String::from("replica set absent")))?;
        let receipt = super::VerifiedReceipt {
            volume_uid: volume.owner.volume_uid.clone(), operation: volume.operation.clone(), epoch: 0,
            node_uid: None, node_boot_id: None, writer_uid: None,
            data_generation_uid: round.intent().generation().uid.clone(), evidence,
            observation: super::Observation::Provisioned { replicas,
                filesystem_uuid: round.intent().generation().filesystem_uuid.clone() },
        };
        volume.provisioned(&receipt).map_err(|error| (409, error))?;
        Ok(CommittedGeneration { intent: round.intent().clone() })
    })?;
    pipeline_live(round.deadline()).map_err(crate::store::CommitError::Unknown)?;
    Ok(committed)
}

#[cfg(test)]
pub(super) fn model_generation(volume: &mut Volume, fs: &str) {
    let nodes = volume.replicas.clone().unwrap();
    let boots = volume.provision_boots.clone().unwrap();
    let prepare = volume.operation.clone();
    let facts = std::array::from_fn(|i| VirginReplicaRef {
        volume_uid: volume.uid().clone(),
        prepare_operation_uid: prepare.clone(),
        node_uid: nodes[i].clone(),
        node_boot_id: boots[i].clone(),
        pool_uid: Uid::new(),
        allocation_nonce: Uid::new(),
        lv_uuid: format!("00000{i}-0000-0000-0000-0000-0000-000000"),
        drbd_device_uuid: format!("{i:016x}f")[1..].into(),
        requested_bytes: volume.capacity_bytes,
        exposed_bytes: crate::storage_driver::rounded_data_bytes(volume.capacity_bytes).unwrap(),
        plan_sha256: "a".repeat(64),
        zero_sha256: "b".repeat(64),
        observation_sha256: "c".repeat(64),
    });
    let plan = DataGeneration {
        version: 1,
        uid: Uid::new(),
        prepare_operation_uid: prepare,
        initialize_operation_uid: Uid::new(),
        filesystem_uuid: fs.into(),
        initializer_node_uid: nodes[0].clone(),
        virgin_replicas: facts,
    };
    volume.begin_initialization(plan).unwrap();
}

#[cfg(test)]
pub(crate) fn model_initialization_for_authority_tests(
) -> (Arc<RwLock<DesiredWorld>>, InitializationIntent) {
    let (mut world, uid) = tests::prepared();
    let volume = world.storage_identities.lifecycle.get_mut(&uid).unwrap();
    model_generation(volume, "12345678-1234-4234-a234-123456789abc");
    let intent = InitializationIntent {
        owner: volume.owner.clone(),
        generation: volume.data_generation.clone().unwrap(),
        capacity_bytes: volume.capacity_bytes,
    };
    (Arc::new(RwLock::new(world)), intent)
}
#[cfg(test)]
mod tests {
    use super::*;
    const FS: &str = "12345678-1234-4234-a234-123456789abc";
    pub(super) fn prepared() -> (DesiredWorld, Uid) {
        let mut w = DesiredWorld::new();
        for raw in [
            serde_json::json!({"kind":"StorageClass","metadata":{"name":"gen"},"spec":{"provisioner":super::super::PROVISIONER}}),
            serde_json::json!({"kind":"PersistentVolumeClaim","metadata":{"name":"data","namespace":"a"},"spec":{"storageClassName":"gen","resources":{"requests":{"storage":"64Mi"}}}}),
        ] {
            w.apply(&serde_json::from_value(raw).unwrap()).unwrap();
        }
        let uid = w.storage_identities.volumes[w.pvcs["a/data"].bound_pv.as_ref().unwrap()].clone();
        w.storage_identities
            .lifecycle
            .get_mut(&uid)
            .unwrap()
            .begin_provision(
                std::array::from_fn(|_| Uid::new()),
                std::array::from_fn(|_| serde_json::from_value(serde_json::json!(FS)).unwrap()),
                Uid::new(),
            )
            .unwrap();
        (w, uid)
    }
    #[test]
    fn model_init_is_single_operation_and_remains_unwritable() {
        let (mut w, uid) = prepared();
        let before = w.storage_identities.lifecycle.clone();
        let v = w.storage_identities.lifecycle.get_mut(&uid).unwrap();
        let prepare = v.operation.clone();
        model_generation(v, FS);
        let plan = v.data_generation.clone().unwrap();
        assert_ne!(v.operation, prepare);
        assert_eq!(v.phase, Phase::Provisioning);
        assert!(v.assignment.is_none());
        assert!(v.filesystem_uuid.is_none());
        assert!(v
            .begin_attach(
                0,
                plan.initializer_node_uid.clone(),
                v.provision_boots.as_ref().unwrap()[0].clone(),
                Uid::new(),
                Uid::new()
            )
            .is_err());
        let old = v.clone();
        assert!(v.begin_initialization(plan).is_err());
        assert_eq!(v, &old);
        assert!(
            v.begin_provision(
                v.replicas.clone().unwrap(),
                v.provision_boots.clone().unwrap(),
                v.operation.clone()
            )
            .is_err(),
            "initialization operation cannot be reissued as allocation/zeroing authority"
        );
        assert_eq!(v, &old);
        before
            .validate_transition(&w.storage_identities.lifecycle)
            .unwrap();
    }
    #[test]
    fn dataset_and_writer_generation_cannot_be_retargeted() {
        let (mut w, uid) = prepared();
        model_generation(w.storage_identities.lifecycle.get_mut(&uid).unwrap(), FS);
        let old = w.storage_identities.lifecycle.clone();
        let mut changed = old.clone();
        changed
            .get_mut(&uid)
            .unwrap()
            .data_generation
            .as_mut()
            .unwrap()
            .uid = Uid::new();
        assert!(old.validate_transition(&changed).is_err());
        let v = w.storage_identities.lifecycle.get_mut(&uid).unwrap();
        let plan = v.data_generation.clone().unwrap();
        let receipt = super::super::VerifiedReceipt {
            volume_uid: uid.clone(),
            operation: v.operation.clone(),
            epoch: 0,
            node_uid: None,
            node_boot_id: None,
            writer_uid: None,
            data_generation_uid: plan.uid.clone(),
            evidence: super::super::EvidenceRef {
                uid: Uid::new(),
                sha256: "d".repeat(64),
            },
            observation: super::super::Observation::Provisioned {
                replicas: v.replicas.clone().unwrap(),
                filesystem_uuid: FS.into(),
            },
        };
        v.provisioned(&receipt).unwrap();
        v.begin_attach(
            0,
            plan.initializer_node_uid.clone(),
            v.provision_boots.as_ref().unwrap()[0].clone(),
            Uid::new(),
            Uid::new(),
        )
        .unwrap();
        v.assignment.as_mut().unwrap().data_generation_uid = Uid::new();
        assert!(v.validate().is_err());
    }
    #[test]
    fn wrong_replica_boot_duplicate_backend_or_initializer_is_not_fresh() {
        let (mut w, uid) = prepared();
        model_generation(w.storage_identities.lifecycle.get_mut(&uid).unwrap(), FS);
        let v = w.storage_identities.lifecycle.get_mut(&uid).unwrap();
        let plan = v.data_generation.clone().unwrap();
        for case in 0..5 {
            let mut bad = plan.clone();
            match case {
                0 => bad.virgin_replicas[0].node_uid = Uid::new(),
                1 => bad.virgin_replicas[0].prepare_operation_uid = Uid::new(),
                2 => {
                    bad.virgin_replicas[1].allocation_nonce =
                        bad.virgin_replicas[0].allocation_nonce.clone()
                }
                3 => {
                    bad.virgin_replicas[1].drbd_device_uuid =
                        bad.virgin_replicas[0].drbd_device_uuid.clone()
                }
                _ => bad.initializer_node_uid = Uid::new(),
            }
            assert!(bad.validate(v).is_err(), "case{case}");
        }
        let intent = InitializationIntent {
            owner: v.owner.clone(),
            generation: plan.clone(),
            capacity_bytes: v.capacity_bytes,
        };
        let boot = plan.virgin_replicas[0].node_boot_id.clone();
        intent
            .local_initializer(&plan.initializer_node_uid, &boot)
            .unwrap();
        assert!(intent
            .local_initializer(&plan.virgin_replicas[1].node_uid, &boot)
            .is_err());
        let other: BootId =
            serde_json::from_value(serde_json::json!("bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb"))
                .unwrap();
        assert!(intent
            .local_initializer(&plan.initializer_node_uid, &other)
            .is_err());
    }
    #[test]
    fn filesystem_receipt_must_match_exact_planned_generation() {
        let (mut w, uid) = prepared();
        let v = w.storage_identities.lifecycle.get_mut(&uid).unwrap();
        model_generation(v, FS);
        let before = v.clone();
        let mut receipt = super::super::VerifiedReceipt {
            volume_uid: uid,
            operation: v.operation.clone(),
            epoch: 0,
            node_uid: None,
            node_boot_id: None,
            writer_uid: None,
            data_generation_uid: Uid::new(),
            evidence: super::super::EvidenceRef {
                uid: Uid::new(),
                sha256: "d".repeat(64),
            },
            observation: super::super::Observation::Provisioned {
                replicas: v.replicas.clone().unwrap(),
                filesystem_uuid: FS.into(),
            },
        };
        assert!(v.provisioned(&receipt).is_err());
        assert_eq!(v, &before);
        receipt.data_generation_uid = v.data_generation.as_ref().unwrap().uid.clone();
        receipt.observation = super::super::Observation::Provisioned {
            replicas: v.replicas.clone().unwrap(),
            filesystem_uuid: "bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb".into(),
        };
        assert!(v.provisioned(&receipt).is_err());
        assert_eq!(v, &before);
    }
    #[test]
    fn new_filesystem_identity_is_not_a_storage_or_existing_uuid() {
        let a = filesystem_uuid();
        let b = filesystem_uuid();
        assert_ne!(a, b);
        assert!(valid_uuid(&a));
        assert_eq!(&a[14..15], "4");
        assert_eq!(&a[19..20], "a");
    }
    #[test]
    fn distributed_completion_data_needs_three_distinct_exact_offline_copies() {
        // DATA validator only. No live round, physical proof or receipt is made.
        let (_,intent)=model_initialization_for_authority_tests();
        let primary=physical::PrimaryFlushObservation {version:1,owner:intent.owner().clone(),
            data_generation_uid:intent.generation().uid.clone(),initialize_operation_uid:intent.operation_uid().clone(),
            filesystem_uuid:intent.generation().filesystem_uuid.clone(),replica:intent.generation().virgin_replicas[0].clone(),
            backing_major:253,backing_minor:1,backing_bytes:192*1024*1024,data_sha256:"a".repeat(64),
            flush_sha256:"b".repeat(64),evidence_sha256:"c".repeat(64)};
        let offline=std::array::from_fn(|index|physical::OfflineReplicaObservation {version:1,owner:intent.owner().clone(),
            data_generation_uid:intent.generation().uid.clone(),initialize_operation_uid:intent.operation_uid().clone(),
            filesystem_uuid:intent.generation().filesystem_uuid.clone(),replica:intent.generation().virgin_replicas[index].clone(),
            backing_major:253,backing_minor:index as u64+1,backing_bytes:192*1024*1024,data_sha256:"a".repeat(64),
            offline_metadata_sha256:"d".repeat(64),drbd_current_uuid:"0123456789abcdef".into(),evidence_sha256:"e".repeat(64)});
        validate_offline_round(&intent,&primary,&offline).unwrap();
        for case in 0..7 {
            let mut bad=offline.clone();
            match case {0=>bad[1]=bad[0].clone(),1=>bad[2].data_sha256="f".repeat(64),2=>bad[1].filesystem_uuid="bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb".into(),
                3=>bad[0].replica.allocation_nonce=Uid::new(),4=>bad[2].drbd_current_uuid="0000000000000004".into(),
                5=>bad[2].replica.exposed_bytes+=4096,_=>bad[0].owner.claim_uid=Uid::new()}
            assert!(validate_offline_round(&intent,&primary,&bad).is_err(),"data case {case}");
        }
    }
    #[test]
    fn distributed_generation_never_accepts_a_frozen_or_plain_world_pointer() {
        let world=Arc::new(RwLock::new(DesiredWorld::new()));
        assert!(actual_distributed_world(&world).is_err());
        let now=std::time::Instant::now();
        assert!(pipeline_live(now).is_err());
        assert!(pipeline_live(now+std::time::Duration::from_secs(181)).is_err());
    }
    #[test]
    fn file_durable_generation_commit_failure_and_exact_replay() {
        const KEY: &str = "ROYAK_GENERATION_COMMIT_ISOLATED";
        if std::env::var_os(KEY).is_none() {
            let output=std::process::Command::new(std::env::current_exe().unwrap()).args([
                "--exact","storage_lifecycle::generation::tests::file_durable_generation_commit_failure_and_exact_replay","--test-threads=1","--nocapture"])
                .env(KEY,"1").output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("royak-generation-commit-{}", Uid::new().as_str()));
        std::fs::create_dir(&root).unwrap();
        let path = root.join("state.json");
        crate::store::set_durability(crate::store::Durability::File {
            path: path.to_str().unwrap().into(),
        });
        crate::store::set_owns_state(true);
        let (w, uid) = prepared();
        let v = w.storage_identities.lifecycle.get(&uid).unwrap();
        let targets = std::array::from_fn(|i| crate::storage_controller::ReplicaTarget {
            node_uid: v.replicas.as_ref().unwrap()[i].clone(),
            boot_id: v.provision_boots.as_ref().unwrap()[i].clone(),
        });
        let operation = v.operation.clone();
        let world = Arc::new(RwLock::new(w));
        let prepare =
            crate::storage_controller::reserve_provision(&world, &uid, targets, operation.clone())
                .unwrap();
        let mut model = world
            .read()
            .unwrap()
            .storage_identities
            .lifecycle
            .get(&uid)
            .unwrap()
            .clone();
        model_generation(&mut model, FS);
        let plan = model.data_generation.unwrap();
        let initializer = plan.initializer_node_uid.clone();
        let init = Uid::new();
        let facts = || VerifiedVirginSet {
            owner: prepare.owner().clone(),
            preparation: prepare.operation_uid().clone(),
            facts: plan.virgin_replicas.clone(),
            held: None, // logical durability fixture, never physical authority
        };
        let before = world.read().unwrap().to_state().to_canonical_json();
        let blocker =
            std::path::PathBuf::from(format!("{}.tmp.{}", path.display(), std::process::id()));
        std::fs::create_dir(&blocker).unwrap();
        assert!(reserve_initialization(
            &world,
            &prepare,
            facts(),
            initializer.clone(),
            init.clone()
        )
        .is_err());
        assert_eq!(world.read().unwrap().to_state().to_canonical_json(), before);
        std::fs::remove_dir(&blocker).unwrap();
        let accepted =
            reserve_initialization(&world, &prepare, facts(), initializer.clone(), init.clone())
                .unwrap();
        assert!(prepare.check_current(&world).is_err());
        accepted.check_current(&world).unwrap();
        assert!(
            crate::storage_controller::reserve_provision(
                &world,
                &uid,
                prepare.targets().clone(),
                init.clone()
            )
            .is_err(),
            "even exact initialization operation must not mint a backing prepare/zero capability"
        );
        let loaded = crate::persist::load(path.to_str().unwrap()).unwrap();
        assert_eq!(
            loaded
                .state
                .storage_identities
                .lifecycle
                .get(&uid)
                .unwrap()
                .data_generation
                .as_ref(),
            Some(&accepted.generation)
        );
        let retry = reserve_initialization(&world, &prepare, facts(), initializer, init).unwrap();
        assert_eq!(accepted.generation, retry.generation);
        let before = world.read().unwrap().to_state().to_canonical_json();
        assert!(reserve_initialization(
            &world,
            &prepare,
            facts(),
            plan.initializer_node_uid,
            Uid::new()
        )
        .is_err());
        assert_eq!(world.read().unwrap().to_state().to_canonical_json(), before);
        std::fs::remove_dir_all(root).unwrap();
    }
}
