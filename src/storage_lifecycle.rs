//! Durable intent/acknowledgement boundary for managed replicated volumes.
//!
//! This is the control-plane state machine, NOT physical fencing evidence.
//! A driver must independently verify kernel/device/writer observations before
//! it can construct VerifiedReceipt. There is deliberately no HTTP/JSON
//! deserializer or public constructor for such a receipt. Until that adapter
//! is connected, native claims stay Pending and cannot enter workload mounts.
use crate::storage_boot::BootId;
use crate::storage_identity::Uid;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
#[path = "storage_generation_compat.rs"]
mod generation_compat;
pub(crate) use generation_compat::legacy_without_data_authority;
#[path = "storage_data_generation.rs"]
pub(crate) mod generation;
#[path = "storage_pod_attachment.rs"]
pub(crate) mod pod_attachment;
use generation::DataGeneration;

pub const PROVISIONER: &str = "royak/drbd-lvm";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Phase {
    PendingProvision,
    Provisioning,
    Detached,
    Attaching,
    Attached,
    Detaching,
    Fencing,
    Released,
    Deleting,
    Deleted,
}

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Self::PendingProvision => "PendingProvision",
            Self::Provisioning => "Provisioning",
            Self::Detached => "Detached",
            Self::Attaching => "Attaching",
            Self::Attached => "Attached",
            Self::Detaching => "Detaching",
            Self::Fencing => "Fencing",
            Self::Released => "Released",
            Self::Deleting => "Deleting",
            Self::Deleted => "Deleted",
        }
    }
    fn retired(self) -> bool {
        matches!(self, Self::Released | Self::Deleted)
    }
    fn has_writer(self) -> bool {
        matches!(
            self,
            Self::Attaching | Self::Attached | Self::Detaching | Self::Fencing
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    pub(crate) cluster_id: String,
    pub(crate) namespace: String,
    pub(crate) claim_name: String,
    pub(crate) pv_name: String,
    pub(crate) namespace_uid: Uid,
    pub(crate) claim_uid: Uid,
    pub(crate) volume_uid: Uid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assignment {
    pub epoch: u64,
    pub node_uid: Uid,
    pub node_boot_id: BootId,
    pub writer_uid: Uid,
    pub attach_operation: Uid,
    pub data_generation_uid: Uid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceRef {
    uid: Uid,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Volume {
    version: u32,
    owner: Owner,
    capacity_bytes: u64,
    reclaim_policy: String,
    phase: Phase,
    epoch: u64,
    operation: Uid,
    replicas: Option<[Uid; 3]>,
    #[serde(default)]
    provision_boots: Option<[BootId; 3]>,
    #[serde(default)]
    data_generation: Option<DataGeneration>,
    filesystem_uuid: Option<String>,
    assignment: Option<Assignment>,
    // Absent only for never-writer epoch0 history. Old strict readers reject
    // this security-bearing field when present; do not backfill from names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pod_writer: Option<crate::storage_pod_writer::PodWriterBinding>,
    // Phase-typed meaning: in Attaching this is ONLY the unchanged PRIOR
    // completed Detached proof. It is not a Mounted observation/capability.
    // A real Mounted receipt replaces it only on Attaching -> Attached.
    evidence: Option<EvidenceRef>,
}

/// Opaque proof obtained by the trusted backend adapter, not a user supplied
/// assertion. It is intentionally neither Serialize nor Deserialize. Adapter
/// integration and its real fault tests remain required before mounts exist.
#[allow(dead_code)]
pub(crate) struct VerifiedReceipt {
    volume_uid: Uid,
    operation: Uid,
    epoch: u64,
    node_uid: Option<Uid>,
    node_boot_id: Option<BootId>,
    writer_uid: Option<Uid>,
    data_generation_uid: Uid,
    evidence: EvidenceRef,
    observation: Observation,
}

#[allow(dead_code)]
enum Observation {
    Provisioned {
        replicas: [Uid; 3],
        filesystem_uuid: String,
    },
    Mounted {
        filesystem_uuid: String,
    },
    Detached,
    Fenced,
    Deleted,
}

pub(crate) fn valid_uuid(s: &str) -> bool {
    s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Volume {
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn uid(&self) -> &Uid {
        &self.owner.volume_uid
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn assignment(&self) -> Option<&Assignment> {
        self.assignment.as_ref()
    }
    pub(crate) fn pod_writer(&self) -> Option<&crate::storage_pod_writer::PodWriterBinding> {
        self.pod_writer.as_ref()
    }
    pub fn operation(&self) -> &Uid {
        &self.operation
    }
    pub(crate) fn owner(&self) -> &Owner {
        &self.owner
    }
    pub(crate) fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }
    pub(crate) fn replicas(&self) -> Option<&[Uid; 3]> {
        self.replicas.as_ref()
    }
    pub(crate) fn provision_boots(&self) -> Option<&[BootId; 3]> {
        self.provision_boots.as_ref()
    }
    pub(crate) fn data_generation(&self) -> Option<&DataGeneration> {self.data_generation.as_ref()}
    pub(crate) fn begin_initialization(&mut self,plan:DataGeneration)->Result<(),String>{
        if self.phase!=Phase::Provisioning || self.data_generation.is_some() || self.assignment.is_some()
            || self.epoch!=0 || self.filesystem_uuid.is_some() || plan.prepare_operation_uid!=self.operation
        {return Err("initialization requires a previously uninitialized exact preparation".into());}
        self.fresh_operation(&plan.initialize_operation_uid)?;
        let mut next=self.clone();next.operation=plan.initialize_operation_uid.clone();next.data_generation=Some(plan);
        next.validate()?;*self=next;Ok(())
    }

    fn check_epoch(&self, expected: u64) -> Result<(), String> {
        if expected != self.epoch {
            return Err("stale volume attachment epoch".into());
        }
        Ok(())
    }
    fn fresh_operation(&self, operation: &Uid) -> Result<(), String> {
        if operation == &self.operation {
            return Err("a new lifecycle intent requires a fresh operation UID".into());
        }
        Ok(())
    }
    fn check_receipt(&self, r: &VerifiedReceipt) -> Result<(), String> {
        if r.volume_uid != self.owner.volume_uid
            || r.operation != self.operation
            || r.epoch != self.epoch
            || !valid_hash(&r.evidence.sha256)
            || self.data_generation.as_ref().map(|g|&g.uid)!=Some(&r.data_generation_uid)
        {
            return Err("backend receipt does not match this committed operation".into());
        }
        if let Some(a) = &self.assignment {
            if r.node_uid.as_ref() != Some(&a.node_uid)
                || r.node_boot_id.as_ref() != Some(&a.node_boot_id)
                || r.writer_uid.as_ref() != Some(&a.writer_uid)
            {
                return Err("backend receipt is for a different writer/node".into());
            }
        } else if r.node_uid.is_some() || r.node_boot_id.is_some() || r.writer_uid.is_some() {
            return Err("unexpected writer in a backend receipt".into());
        }
        Ok(())
    }

    /// Reserve and COMMIT before sending any allocation request to a backend.
    #[allow(dead_code)]
    pub fn begin_provision(
        &mut self,
        replicas: [Uid; 3],
        boots: [BootId; 3],
        operation: Uid,
    ) -> Result<(), String> {
        if self.phase == Phase::Provisioning
            && self.data_generation.is_none()
            && self.operation == operation
            && self.replicas.as_ref() == Some(&replicas)
            && self.provision_boots.as_ref() == Some(&boots)
        {
            return Ok(());
        }
        self.fresh_operation(&operation)?;
        if self.phase != Phase::PendingProvision
            || replicas.iter().collect::<BTreeSet<_>>().len() != 3
        {
            return Err(
                "provision requires a fresh volume and three distinct replica nodes".into(),
            );
        }
        self.phase = Phase::Provisioning;
        self.operation = operation;
        self.replicas = Some(replicas);
        self.provision_boots = Some(boots);
        Ok(())
    }

    /// Must follow independent observation of the exact new backend resource,
    /// filesystem and all three replicas. A command exit code alone is not it.
    #[allow(dead_code)]
    pub(crate) fn provisioned(&mut self, r: &VerifiedReceipt) -> Result<(), String> {
        self.check_receipt(r)?;
        let Observation::Provisioned {
            replicas,
            filesystem_uuid,
        } = &r.observation
        else {
            return Err("wrong receipt kind".into());
        };
        if self.phase == Phase::Detached
            && self.evidence.as_ref() == Some(&r.evidence)
            && self.filesystem_uuid.as_ref() == Some(filesystem_uuid)
            && self.replicas.as_ref() == Some(replicas)
        {
            return Ok(());
        }
        if self.phase != Phase::Provisioning
            || self.replicas.as_ref() != Some(replicas)
            || !valid_uuid(filesystem_uuid)
            || self.data_generation.as_ref().map(|g|g.filesystem_uuid.as_str())!=Some(filesystem_uuid.as_str())
        {
            return Err("unverified or conflicting provision result".into());
        }
        self.filesystem_uuid = Some(filesystem_uuid.clone());
        self.phase = Phase::Detached;
        self.evidence = Some(r.evidence.clone());
        Ok(())
    }

    /// One committed writer, monotonic epochs and exact retry identity. There
    /// is no lease-expiry transition from Attached/Fencing back to Detached.
    #[cfg(test)]
    pub fn begin_attach(
        &mut self,
        expected_epoch: u64,
        node: Uid,
        boot: BootId,
        writer: Uid,
        operation: Uid,
    ) -> Result<Assignment, String> {
        // Compatibility for existing labelled lifecycle MODELS, never a
        // production constructor or physical/mount authority producer.
        let binding=crate::storage_pod_writer::model_binding(self,writer);
        self.begin_pod_attach(expected_epoch,node,boot,binding,operation)
    }

    pub(crate) fn begin_pod_attach(
        &mut self,
        expected_epoch: u64,
        node: Uid,
        boot: BootId,
        binding: crate::storage_pod_writer::PodWriterBinding,
        operation: Uid,
    ) -> Result<Assignment, String> {
        binding.validate_volume(self)?;
        let writer=binding.uid().as_uid().clone();
        if matches!(self.phase, Phase::Attaching | Phase::Attached) {
            if let Some(a) = &self.assignment {
                if a.node_uid == node
                    && a.node_boot_id == boot
                    && a.writer_uid == writer
                    && a.attach_operation == operation
                    && expected_epoch.checked_add(1) == Some(a.epoch)
                    && self.pod_writer.as_ref()==Some(&binding)
                {
                    return Ok(a.clone());
                }
            }
        }
        self.check_epoch(expected_epoch)?;
        self.fresh_operation(&operation)?;
        if self.phase != Phase::Detached
            || self.evidence.is_none()
            || !self.replicas.as_ref().is_some_and(|r| r.contains(&node))
            || self.pod_writer.as_ref().is_some_and(|old|old.uid()==binding.uid())
        {
            return Err("volume is not detached or node is not a replica".into());
        }
        let epoch = self
            .epoch
            .checked_add(1)
            .ok_or("volume attachment epoch exhausted")?;
        let assignment = Assignment {
            epoch,
            node_uid: node,
            node_boot_id: boot,
            writer_uid: writer,
            attach_operation: operation.clone(),
            data_generation_uid:self.data_generation.as_ref().ok_or("volume has no initialized dataset identity")?.uid.clone(),
        };
        let mut next=self.clone();
        next.epoch = epoch;
        next.operation = operation;
        next.assignment = Some(assignment.clone());
        next.pod_writer = Some(binding);
        next.phase = Phase::Attaching;
        // Retain the exact prior completed proof so every actual receiver can
        // compare first-epoch initialized lineage against CURRENT Core after
        // reservation. A private journal/serde baseline is not its authority.
        next.validate()?;
        *self=next;
        Ok(assignment)
    }

    #[allow(dead_code)]
    pub(crate) fn attached(&mut self, r: &VerifiedReceipt) -> Result<(), String> {
        self.check_receipt(r)?;
        let Observation::Mounted { filesystem_uuid } = &r.observation else {
            return Err("wrong receipt kind".into());
        };
        if !matches!(self.phase, Phase::Attaching | Phase::Attached)
            || self.filesystem_uuid.as_ref() != Some(filesystem_uuid)
        {
            return Err("mount did not prove the expected filesystem/attachment".into());
        }
        if self.phase == Phase::Attached && self.evidence.as_ref() != Some(&r.evidence) {
            return Err("conflicting mount acknowledgement".into());
        }
        self.phase = Phase::Attached;
        self.evidence = Some(r.evidence.clone());
        Ok(())
    }

    #[allow(dead_code)]
    pub fn begin_detach(&mut self, epoch: u64, operation: Uid) -> Result<(), String> {
        self.check_epoch(epoch)?;
        if self.phase == Phase::Detaching && self.operation == operation {
            return Ok(());
        }
        self.fresh_operation(&operation)?;
        if !matches!(self.phase, Phase::Attached | Phase::Attaching) {
            return Err("no detachable writer".into());
        }
        self.phase = Phase::Detaching;
        self.operation = operation;
        self.evidence = None;
        Ok(())
    }

    /// Ambiguous attach/detach outcomes retain the old writer reservation.
    /// Only a separately verified physical/clean-detach receipt can clear it.
    #[allow(dead_code)]
    pub fn begin_fence(&mut self, epoch: u64, operation: Uid) -> Result<(), String> {
        self.check_epoch(epoch)?;
        if self.phase == Phase::Fencing && self.operation == operation {
            return Ok(());
        }
        self.fresh_operation(&operation)?;
        if !matches!(
            self.phase,
            Phase::Attached | Phase::Attaching | Phase::Detaching
        ) {
            return Err("no writer to fence".into());
        }
        self.phase = Phase::Fencing;
        self.operation = operation;
        self.evidence = None;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn detached(&mut self, r: &VerifiedReceipt) -> Result<(), String> {
        if self.phase == Phase::Detached
            && r.volume_uid == self.owner.volume_uid
            && r.operation == self.operation
            && r.epoch == self.epoch
            && self.evidence.as_ref() == Some(&r.evidence)
            && self.data_generation.as_ref().map(|g|&g.uid)==Some(&r.data_generation_uid)
            && matches!(r.observation, Observation::Detached | Observation::Fenced)
        {
            return Ok(());
        }
        self.check_receipt(r)?;
        if !matches!(
            (self.phase, &r.observation),
            (Phase::Detaching, Observation::Detached) | (Phase::Fencing, Observation::Fenced)
        ) {
            return Err("writer requires matching detach/fence evidence".into());
        }
        self.phase = Phase::Detached;
        self.assignment = None;
        self.evidence = Some(r.evidence.clone());
        Ok(())
    }

    #[allow(dead_code)]
    pub fn begin_release(&mut self, epoch: u64, operation: Uid) -> Result<(), String> {
        self.check_epoch(epoch)?;
        if matches!(self.phase, Phase::Released | Phase::Deleting) && self.operation == operation {
            return Ok(());
        }
        self.fresh_operation(&operation)?;
        if self.phase != Phase::Detached {
            return Err("release requires a verified detached volume".into());
        }
        self.operation = operation;
        self.phase = if self.reclaim_policy == "Retain" {
            Phase::Released
        } else {
            Phase::Deleting
        };
        self.evidence = None;
        Ok(())
    }

    #[allow(dead_code)]
    pub(crate) fn deleted(&mut self, r: &VerifiedReceipt) -> Result<(), String> {
        self.check_receipt(r)?;
        if self.phase == Phase::Deleted
            && matches!(r.observation, Observation::Deleted)
            && self.evidence.as_ref() == Some(&r.evidence)
        {
            return Ok(());
        }
        if self.phase != Phase::Deleting || !matches!(r.observation, Observation::Deleted) {
            return Err("delete requires proof that all exact backend replicas are removed".into());
        }
        self.phase = Phase::Deleted;
        self.evidence = Some(r.evidence.clone());
        Ok(())
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || self.capacity_bytes == 0
            || !matches!(self.reclaim_policy.as_str(), "Retain" | "Delete")
        {
            return Err("invalid managed volume contract version/capacity/policy".into());
        }
        if self.phase.has_writer() != self.assignment.is_some() {
            return Err("volume writer/phase mismatch".into());
        }
        if (self.epoch>0)!=self.pod_writer.is_some() {
            return Err("writer-bearing history lacks explicit durable PodWriter identity; no backfill".into());
        }
        if let Some(binding)=&self.pod_writer {
            binding.validate_volume(self)?;
            if self.assignment.as_ref().is_some_and(|a|&a.writer_uid!=binding.uid().as_uid()) {
                return Err("Assignment writer differs from durable PodWriter identity".into());
            }
        }
        if let Some(plan)=&self.data_generation {
            plan.validate(self)?;
            if self.phase==Phase::PendingProvision || self.phase==Phase::Provisioning&&self.operation!=plan.initialize_operation_uid
                || self.filesystem_uuid.as_ref().is_some_and(|fs|fs!=&plan.filesystem_uuid)
            {return Err("dataset identity differs from initialization intent or filesystem".into());}
        }
        if !matches!(self.phase,Phase::PendingProvision|Phase::Provisioning|Phase::Deleted) && self.data_generation.is_none(){
            return Err("live backend history lacks the authenticated dataset-generation contract".into());
        }
        if let Some(a) = &self.assignment {
            if a.epoch == 0
                || a.epoch != self.epoch
                || !self
                    .replicas
                    .as_ref()
                    .is_some_and(|r| r.contains(&a.node_uid))
                || self.data_generation.as_ref().map(|g|&g.uid)!=Some(&a.data_generation_uid)
            {
                return Err("invalid volume writer epoch or node".into());
            }
        }
        if let Some(r) = &self.replicas {
            if r.iter().collect::<BTreeSet<_>>().len() != 3 {
                return Err("replica identities are not distinct".into());
            }
        }
        if self
            .filesystem_uuid
            .as_ref()
            .is_some_and(|s| !valid_uuid(s))
            || self
                .evidence
                .as_ref()
                .is_some_and(|e| !valid_hash(&e.sha256))
        {
            return Err("invalid filesystem identity or evidence hash".into());
        }
        if self.phase == Phase::PendingProvision
            && (self.replicas.is_some()
                || self.provision_boots.is_some()
                || self.filesystem_uuid.is_some()
                || self.epoch != 0
                || self.evidence.is_some())
            || self.phase==Phase::PendingProvision && self.data_generation.is_some()
        {
            return Err("fresh pending volume contains backend authority".into());
        }
        if self.phase == Phase::Provisioning
            && (self.replicas.is_none()
                || self.provision_boots.is_none()
                || self.filesystem_uuid.is_some()
                || self.epoch != 0)
        {
            return Err("invalid provisioning intent".into());
        }
        if !matches!(
            self.phase,
            Phase::PendingProvision | Phase::Provisioning | Phase::Deleted
        ) && (self.replicas.is_none() || self.filesystem_uuid.is_none())
        {
            return Err("volume has no verified backend identity".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    version: u32,
    volumes: BTreeMap<Uid, Volume>,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            version: 1,
            volumes: BTreeMap::new(),
        }
    }
}

impl Registry {
    /// Conservative deletion denial, never a live owner/grant. Includes
    /// retained histories after current claim indexes disappeared.
    pub(crate) fn contains_writer_pod(&self,namespace:&str,pod:&str)->bool{
        self.volumes.values().any(|volume|volume.pod_writer().is_some_and(|writer|
            writer.namespace()==namespace&&writer.pod()==pod))
    }
    pub(crate) fn contains_writer_workload(&self,namespace:&str,workload:&str)->bool{
        self.volumes.values().any(|volume|volume.pod_writer().is_some_and(|writer|
            writer.namespace()==namespace&&writer.workload()==workload))
    }
    /// Negative-only policy admission against canonical retained writer DATA.
    /// Missing workload source cannot prove that live sidecars stopped.
    pub(crate) fn retained_writer_policy_conflict(&self,world:&crate::reconcile::DesiredWorld,
        namespace:&str,selector:&str)->bool{
        self.volumes.values().any(|volume|volume.pod_writer().is_some_and(|writer|{
            if writer.namespace()!=namespace{return false;}
            // A PRESENT but changed template is equally ambiguous as a
            // missing source: OLD native init/sidecar names may still live.
            if writer.check_source_current(world).is_err(){return true;}
            if crate::workload::managed::policy_selects_names(selector,writer.workload(),std::iter::once(writer.pod())){return true;}
            world.deployments.get(&crate::store::obj_key(namespace,writer.workload())).map_or(true,|deployment|
                crate::workload::managed::policy_may_select_workload(selector,namespace,writer.workload(),
                    &deployment.init_containers,&deployment.containers))
        }))
    }
    pub fn is_empty(&self) -> bool {
        self.volumes.is_empty()
    }
    pub fn get(&self, uid: &Uid) -> Option<&Volume> {
        self.volumes.get(uid)
    }
    #[allow(dead_code)]
    pub fn get_mut(&mut self, uid: &Uid) -> Option<&mut Volume> {
        self.volumes.get_mut(uid)
    }

    pub fn for_pv<'a>(
        &'a self,
        ids: &crate::storage_identity::Identities,
        name: &str,
    ) -> Option<&'a Volume> {
        ids.volumes.get(name).and_then(|id| self.get(id))
    }

    /// Registration only creates an unwritable intent for a NEW controller-
    /// generated PV. Loaded state missing this record is rejected, not adopted.
    pub fn register_pending(world: &mut crate::reconcile::DesiredWorld) -> Result<(), String> {
        let ids = &world.storage_identities;
        let mut pending = Vec::new();
        for pv in world.pvs.values().filter(|v| {
            world
                .storage_classes
                .get(&v.storage_class)
                .is_some_and(|s| s.provisioner == PROVISIONER)
        }) {
            let Some(key) = &pv.bound_to else {
                continue;
            };
            let id = ids
                .volumes
                .get(&pv.name)
                .ok_or("managed PV has no server identity")?;
            if ids.lifecycle.volumes.contains_key(id) {
                continue;
            }
            let claim = world.pvcs.get(key).ok_or("managed PV has no claim")?;
            let claim_id = ids
                .claims
                .get(key)
                .ok_or("managed claim has no server identity")?;
            let sc = &world.storage_classes[&pv.storage_class];
            if !pv.host_path.is_empty()
                || claim.bound_pv.as_deref() != Some(pv.name.as_str())
                || pv.access_mode != "ReadWriteOnce"
            {
                return Err("refusing to adopt a host path or inconsistent legacy volume as managed storage".into());
            }
            pending.push(Volume {
                version: 1,
                owner: Owner {
                    cluster_id: world.cluster_id.clone(),
                    namespace: claim.namespace.clone(),
                    claim_name: claim.name.clone(),
                    pv_name: pv.name.clone(),
                    namespace_uid: claim_id.namespace_uid.clone(),
                    claim_uid: claim_id.uid.clone(),
                    volume_uid: id.clone(),
                },
                capacity_bytes: crate::storage::capacity_bytes(&pv.capacity)?,
                reclaim_policy: sc.reclaim_policy.clone(),
                phase: Phase::PendingProvision,
                epoch: 0,
                operation: Uid::new(),
                replicas: None,
                provision_boots: None,
                data_generation: None,
                filesystem_uuid: None,
                assignment: None,
                pod_writer: None,
                evidence: None,
            });
        }
        for volume in pending {
            world
                .storage_identities
                .lifecycle
                .volumes
                .insert(volume.owner.volume_uid.clone(), volume);
        }
        Ok(())
    }

    pub fn may_remove_metadata(&self, uid: &Uid) -> bool {
        self.get(uid)
            .is_none_or(|v| v.phase == Phase::PendingProvision || v.phase.retired())
    }
    pub fn cancel_unstarted(&mut self, uid: &Uid) -> Result<(), String> {
        if let Some(v) = self.volumes.get_mut(uid) {
            if v.phase == Phase::PendingProvision {
                v.phase = Phase::Deleted;
            } else if !v.phase.retired() {
                return Err(
                    "managed volume needs verified release before metadata deletion".into(),
                );
            }
        }
        Ok(())
    }

    pub fn validate(&self, state: &crate::store::DesiredState) -> Result<(), String> {
        if self.version != 1 {
            return Err("unsupported volume lifecycle version".into());
        }
        let ids = &state.storage_identities;
        let mut active_claims = BTreeSet::new();
        for (uid, v) in &self.volumes {
            v.validate()?;
            if let Some(binding)=v.pod_writer() {binding.validate_group(self)?;}
            if uid != &v.owner.volume_uid || v.owner.cluster_id != state.cluster_id {
                return Err("managed volume cluster/UID mismatch".into());
            }
            if !v.phase.retired() {
                let key = crate::store::obj_key(&v.owner.namespace, &v.owner.claim_name);
                let claim = state
                    .pvcs
                    .get(&key)
                    .ok_or("live managed volume lost its claim")?;
                let pv = state
                    .pvs
                    .get(&v.owner.pv_name)
                    .ok_or("live managed volume lost its PV")?;
                let identity = ids
                    .claims
                    .get(&key)
                    .ok_or("live managed volume lost its claim UID")?;
                let sc = state
                    .storage_classes
                    .get(&pv.storage_class)
                    .ok_or("managed volume lost its storage class")?;
                if ids.volumes.get(&v.owner.pv_name) != Some(uid)
                    || identity.uid != v.owner.claim_uid
                    || identity.namespace_uid != v.owner.namespace_uid
                    || ids.namespaces.get(&v.owner.namespace) != Some(&v.owner.namespace_uid)
                    || claim.bound_pv.as_deref() != Some(v.owner.pv_name.as_str())
                    || pv.bound_to.as_deref() != Some(key.as_str())
                    || sc.provisioner != PROVISIONER
                    || sc.reclaim_policy != v.reclaim_policy
                    || crate::storage::capacity_bytes(&pv.capacity)? != v.capacity_bytes
                    || pv.access_mode != "ReadWriteOnce"
                    || !active_claims.insert(&v.owner.claim_uid)
                {
                    return Err(
                        "managed volume owner/binding/policy does not match current incarnations"
                            .into(),
                    );
                }
            }
        }
        for pv in state.pvs.values().filter(|pv| {
            state
                .storage_classes
                .get(&pv.storage_class)
                .is_some_and(|s| s.provisioner == PROVISIONER)
        }) {
            if let Some(key) = &pv.bound_to {
                let id = ids
                    .volumes
                    .get(&pv.name)
                    .ok_or("managed PV lost identity")?;
                let v = self
                    .get(id)
                    .ok_or("managed PV has no lifecycle; legacy adoption is refused")?;
                let identity = ids
                    .claims
                    .get(key)
                    .ok_or("managed PV binding has no claim identity")?;
                if key != &crate::store::obj_key(&v.owner.namespace, &v.owner.claim_name)
                    || identity.uid != v.owner.claim_uid
                    || identity.namespace_uid != v.owner.namespace_uid
                {
                    return Err(
                        "managed volume cannot be rebound to another claim incarnation".into(),
                    );
                }
            }
        }
        Ok(())
    }

    /// Prevent accidental rollback/removal through a full-state commit, even
    /// when its outer desired-state generation is fresh. Snapshot restart is
    /// validated separately; backend journals must also reject stale grants.
    pub fn validate_transition(&self, next: &Self) -> Result<(), String> {
        for (uid, new) in &next.volumes {
            if let Some(old) = self.get(uid) {
                if old.owner != new.owner
                    || old.capacity_bytes != new.capacity_bytes
                    || old.reclaim_policy != new.reclaim_policy
                    || old.replicas.is_some() && old.replicas != new.replicas
                    || old.provision_boots.is_some() && old.provision_boots != new.provision_boots
                    || old.filesystem_uuid.is_some() && old.filesystem_uuid != new.filesystem_uuid
                    || old.data_generation.is_some() && old.data_generation != new.data_generation
                {
                    return Err("managed volume immutable backend/owner identity changed".into());
                }
                if new == old {
                    continue;
                }
                if old.pod_writer!=new.pod_writer {
                    if old.phase!=Phase::Detached || new.phase!=Phase::Attaching
                        || new.pod_writer.is_none()
                        || old.pod_writer.as_ref().zip(new.pod_writer.as_ref()).is_some_and(|(a,b)|a.uid()==b.uid()) {
                        return Err("PodWriter history may change only with a new canonical Assignment".into());
                    }
                }
                if old.phase==Phase::Detached && new.phase==Phase::Attaching
                    && (old.evidence.is_none() || new.evidence!=old.evidence) {
                    return Err("attachment must retain the exact prior completed proof; no clear/change/backfill".into());
                }
                if old.phase.has_writer()
                    && new.phase.has_writer()
                    && old.assignment != new.assignment
                {
                    return Err(
                        "an existing attachment cannot change writer/node within its epoch".into(),
                    );
                }
                let initializing = old.phase==Phase::Provisioning && new.phase==Phase::Provisioning
                    && old.data_generation.is_none() && new.data_generation.as_ref().is_some_and(|g|
                        g.prepare_operation_uid==old.operation && g.initialize_operation_uid==new.operation);
                if old.data_generation.is_none() && new.data_generation.is_some() && !initializing {
                    return Err("dataset identity can only enter through a new committed initialization operation".into());
                }
                let legal = initializing || matches!(
                    (old.phase, new.phase),
                    (
                        Phase::PendingProvision,
                        Phase::Provisioning | Phase::Deleted
                    ) | (Phase::Provisioning, Phase::Detached)
                        | (
                            Phase::Detached,
                            Phase::Attaching | Phase::Released | Phase::Deleting
                        )
                        | (
                            Phase::Attaching,
                            Phase::Attached | Phase::Detaching | Phase::Fencing
                        )
                        | (Phase::Attached, Phase::Detaching | Phase::Fencing)
                        | (Phase::Detaching, Phase::Detached | Phase::Fencing)
                        | (Phase::Fencing, Phase::Detached)
                        | (Phase::Deleting, Phase::Deleted)
                );
                let epoch = if old.phase == Phase::Detached && new.phase == Phase::Attaching {
                    old.epoch.checked_add(1)
                } else {
                    Some(old.epoch)
                };
                if !legal || epoch != Some(new.epoch) {
                    return Err("illegal managed volume transition or epoch rollback".into());
                }
                if matches!(
                    new.phase,
                    Phase::Provisioning
                        | Phase::Attaching
                        | Phase::Detaching
                        | Phase::Fencing
                        | Phase::Released
                        | Phase::Deleting
                ) && old.operation == new.operation
                {
                    return Err("new lifecycle intent reused an operation identity".into());
                }
                if matches!(new.phase, Phase::Attached | Phase::Detached)
                    && (new.operation != old.operation || new.evidence.is_none())
                {
                    return Err(
                        "backend acknowledgement does not match the current lifecycle intent"
                            .into(),
                    );
                }
            } else if new.phase != Phase::PendingProvision || new.epoch != 0 {
                return Err("new managed volume cannot import live attachment authority".into());
            }
        }
        if self.volumes.keys().any(|id| !next.volumes.contains_key(id)) {
            return Err("managed volume history cannot be silently removed".into());
        }
        Ok(())
    }
}

#[cfg(test)]
pub(crate) fn model_pod_writer_world() -> (crate::reconcile::DesiredWorld,Uid,Uid,BootId) {
    // Explicit pure lifecycle model; never called by a production producer.
    let (mut world,uid)=tests::world("Retain");
    let nodes=tests::provision(&mut world,&uid);
    world.apply(&serde_json::from_value(serde_json::json!({"kind":"Deployment",
        "metadata":{"name":"db","namespace":"a"},"spec":{"replicas":1,"template":{"spec":{
        "containers":[{"name":"db","image":"postgres:17","volumeMounts":[{"name":"data","mountPath":"/data"}]}],
        "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data"}}]}}}})).unwrap()).unwrap();
    (world,uid,nodes[0].clone(),serde_json::from_str("\"12345678-1234-4234-a234-123456789abc\"").unwrap())
}

#[cfg(test)]
mod attaching_prior_evidence_regressions {
    use super::*;
    #[test]
    fn detached_to_attaching_retains_exact_prior_evidence_not_a_mounted_ack() {
        let (mut world,uid,node,boot)=model_pod_writer_world();
        let before=world.storage_identities.lifecycle.clone();
        let prior=before.get(&uid).unwrap().evidence.clone().unwrap();
        world.storage_identities.lifecycle.get_mut(&uid).unwrap()
            .begin_attach(0,node,boot,Uid::new(),Uid::new()).unwrap();
        let volume=world.storage_identities.lifecycle.get(&uid).unwrap();
        assert_eq!(volume.phase,Phase::Attaching);assert_eq!(volume.evidence,Some(prior));
        before.validate_transition(&world.storage_identities.lifecycle).unwrap();
        assert!(crate::storage::bound_volume(&world,"a","data").is_err());
        // A JSON-shaped Attaching record/prior proof is never an FD owner or
        // mounted capability. No production mount constructor is called here.
        assert_ne!(volume.phase,Phase::Attached);
    }
    #[test]
    fn cleared_changed_or_missing_prior_evidence_cannot_enter_attaching() {
        let (mut world,uid,node,boot)=model_pod_writer_world();
        let before=world.storage_identities.lifecycle.clone();
        world.storage_identities.lifecycle.get_mut(&uid).unwrap()
            .begin_attach(0,node.clone(),boot.clone(),Uid::new(),Uid::new()).unwrap();
        for case in 0..3 {
            let mut candidate=world.storage_identities.lifecycle.clone();
            let evidence=&mut candidate.get_mut(&uid).unwrap().evidence;
            match case {0=>*evidence=None,1=>evidence.as_mut().unwrap().uid=Uid::new(),
                _=>evidence.as_mut().unwrap().sha256="b".repeat(64)}
            assert!(before.validate_transition(&candidate).is_err(),"prior proof case {case}");
        }
        let mut missing=before.clone();missing.get_mut(&uid).unwrap().evidence=None;
        assert!(missing.get_mut(&uid).unwrap().begin_attach(0,node,boot,Uid::new(),Uid::new()).is_err());
        assert!(missing.validate_transition(&world.storage_identities.lifecycle).is_err());
    }
}

#[cfg(test)]
pub(crate) fn model_decode_exact_cp3_volume(raw:serde_json::Value)->Result<(),String> {
    // Exact cp3 Volume serde field/types/default attributes, isolated for the
    // old-reader contract test. This is not execution of an old server ELF.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Cp3Volume {
        version:u32,owner:Owner,capacity_bytes:u64,reclaim_policy:String,
        phase:Phase,epoch:u64,operation:Uid,replicas:Option<[Uid;3]>,
        #[serde(default)]
        provision_boots:Option<[BootId;3]>,
        #[serde(default)]
        data_generation:Option<DataGeneration>,
        filesystem_uuid:Option<String>,assignment:Option<Assignment>,evidence:Option<EvidenceRef>,
    }
    serde_json::from_value::<Cp3Volume>(raw).map(|_|()).map_err(|e|e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcile::DesiredWorld;
    const FS: &str = "71cb439a-d59b-4d47-9058-2134d97ebd7f";
    fn boot() -> BootId {
        serde_json::from_value(serde_json::json!(FS)).unwrap()
    }
    fn boots() -> [BootId; 3] {
        [boot(), boot(), boot()]
    }

    fn resource(value: serde_json::Value) -> crate::spec::Resource {
        serde_json::from_value(value).unwrap()
    }
    pub(super) fn world(policy: &str) -> (DesiredWorld, Uid) {
        let mut w = DesiredWorld::new();
        w.apply(&resource(
            serde_json::json!({"kind":"StorageClass","metadata":{"name":"replicated"},
            "spec":{"provisioner":PROVISIONER,"reclaimPolicy":policy}}),
        ))
        .unwrap();
        w.apply(&resource(serde_json::json!({"kind":"PersistentVolumeClaim","metadata":{"name":"data","namespace":"a"},
            "spec":{"storageClassName":"replicated","accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"64Mi"}}}}))).unwrap();
        let pv = w.pvcs["a/data"].bound_pv.as_ref().unwrap();
        let id = w.storage_identities.volumes[pv].clone();
        (w, id)
    }
    fn receipt(v: &Volume, observation: Observation) -> VerifiedReceipt {
        VerifiedReceipt {
            volume_uid: v.uid().clone(),
            operation: v.operation.clone(),
            epoch: v.epoch,
            node_uid: v.assignment.as_ref().map(|a| a.node_uid.clone()),
            node_boot_id: v.assignment.as_ref().map(|a| a.node_boot_id.clone()),
            writer_uid: v.assignment.as_ref().map(|a| a.writer_uid.clone()),
            data_generation_uid:v.data_generation.as_ref().expect("model receipt needs planned dataset").uid.clone(),
            evidence: EvidenceRef {
                uid: Uid::new(),
                sha256: "a".repeat(64),
            },
            observation,
        }
    }
    pub(super) fn provision(w: &mut DesiredWorld, id: &Uid) -> [Uid; 3] {
        let nodes = [Uid::new(), Uid::new(), Uid::new()];
        let v = w.storage_identities.lifecycle.get_mut(id).unwrap();
        v.begin_provision(nodes.clone(), boots(), Uid::new())
            .unwrap();
        generation::model_generation(v,FS);
        let r = receipt(
            v,
            Observation::Provisioned {
                replicas: nodes.clone(),
                filesystem_uuid: FS.into(),
            },
        );
        v.provisioned(&r).unwrap();
        nodes
    }
    fn checkpoint(w: &DesiredWorld, old: &mut Registry) {
        let state = w.to_state();
        state.storage_identities.validate(&state).unwrap();
        old.validate_transition(&state.storage_identities.lifecycle)
            .unwrap();
        let path =
            std::env::temp_dir().join(format!("royak-volume-state-{}.json", Uid::new().as_str()));
        crate::persist::save(path.to_str().unwrap(), &state, &[]).unwrap();
        let loaded = crate::persist::load(path.to_str().unwrap()).unwrap();
        assert_eq!(loaded.state.storage_identities, state.storage_identities);
        std::fs::remove_file(&path).unwrap();
        let _ = std::fs::remove_file(format!("{}.nrns", path.display()));
        *old = state.storage_identities.lifecycle;
    }

    #[test]
    fn native_claim_reserves_only_unwritable_metadata_and_never_adopts_a_path() {
        let (mut w, id) = world("Retain");
        let pv = w.pvcs["a/data"].bound_pv.as_ref().unwrap();
        assert!(w.pvs[pv].host_path.is_empty());
        assert_eq!(
            w.storage_identities.lifecycle.get(&id).unwrap().phase,
            Phase::PendingProvision
        );
        assert!(crate::storage::bound_volume(&w, "a", "data").is_err());
        w.materialize_storage();
        w.to_state()
            .storage_identities
            .validate(&w.to_state())
            .unwrap();
        for body in [
            serde_json::json!({"kind":"StorageClass","metadata":{"name":"bad"},"spec":{"provisioner":PROVISIONER,"hostPathPrefix":"/existing"}}),
            serde_json::json!({"kind":"PersistentVolume","metadata":{"name":"adopt"},"spec":{"storageClassName":"replicated","hostPath":{"path":"/existing"}}}),
            serde_json::json!({"kind":"PersistentVolumeClaim","metadata":{"name":"shared","namespace":"a"},"spec":{"storageClassName":"replicated","accessModes":["ReadWriteMany"]}}),
        ] {
            assert!(w.apply(&resource(body)).is_err());
        }
        assert_eq!(w.storage_identities.lifecycle.volumes.len(), 1);
        let mut missing = w.to_state();
        missing.storage_identities.lifecycle = Registry::default();
        assert!(
            missing.storage_identities.validate(&missing).is_err(),
            "loaded native data cannot acquire fresh authority automatically"
        );
    }

    #[test]
    fn legacy_schema_or_envelope_cannot_bypass_managed_authority_version_barrier() {
        let (w, _) = world("Retain");
        for version in [0, 1] {
            let mut state = w.to_state();
            state.storage_identities.version = version;
            assert!(crate::storage_identity::Identities::migrate(&mut state).is_err());
        }
        let mut file: serde_json::Value =
            serde_json::from_slice(&crate::persist::encode(&w.to_state(), &[]).unwrap()).unwrap();
        for version in [2, 3] {
            file["schemaVersion"] = version.into();
            assert!(crate::persist::decode(&file.to_string()).is_err());
        }
    }

    #[test]
    fn every_single_writer_transition_is_durable_and_retention_is_explicit() {
        for policy in ["Retain", "Delete"] {
            let (mut w, id) = world(policy);
            let mut old = Registry::default();
            checkpoint(&w, &mut old);
            let nodes = [Uid::new(), Uid::new(), Uid::new()];
            w.storage_identities
                .lifecycle
                .get_mut(&id)
                .unwrap()
                .begin_provision(nodes.clone(), boots(), Uid::new())
                .unwrap();
            checkpoint(&w, &mut old);
            let v = w.storage_identities.lifecycle.get_mut(&id).unwrap();
            generation::model_generation(v,FS);
            checkpoint(&w, &mut old);
            let v = w.storage_identities.lifecycle.get_mut(&id).unwrap();
            let r = receipt(
                v,
                Observation::Provisioned {
                    replicas: nodes.clone(),
                    filesystem_uuid: FS.into(),
                },
            );
            v.provisioned(&r).unwrap();
            v.provisioned(&r).unwrap();
            checkpoint(&w, &mut old);
            let writer = Uid::new();
            let op = Uid::new();
            let v = w.storage_identities.lifecycle.get_mut(&id).unwrap();
            let first = v
                .begin_attach(0, nodes[0].clone(), boot(), writer.clone(), op.clone())
                .unwrap();
            assert_eq!(
                v.begin_attach(0, nodes[0].clone(), boot(), writer.clone(), op.clone())
                    .unwrap(),
                first
            );
            checkpoint(&w, &mut old);
            let v = w.storage_identities.lifecycle.get_mut(&id).unwrap();
            let mounted = receipt(
                v,
                Observation::Mounted {
                    filesystem_uuid: FS.into(),
                },
            );
            v.attached(&mounted).unwrap();
            v.attached(&mounted).unwrap();
            checkpoint(&w, &mut old);
            let v = w.storage_identities.lifecycle.get_mut(&id).unwrap();
            assert!(v
                .begin_attach(1, nodes[1].clone(), boot(), Uid::new(), Uid::new())
                .is_err());
            assert_eq!(
                v.begin_attach(0, nodes[0].clone(), boot(), writer, op)
                    .unwrap(),
                first
            );
            v.begin_detach(1, Uid::new()).unwrap();
            checkpoint(&w, &mut old);
            assert!(w.validate_storage_delete("pvc", "a", "data").is_err());
            let v = w.storage_identities.lifecycle.get_mut(&id).unwrap();
            let detached = receipt(v, Observation::Detached);
            v.detached(&detached).unwrap();
            v.detached(&detached).unwrap();
            checkpoint(&w, &mut old);
            let v = w.storage_identities.lifecycle.get_mut(&id).unwrap();
            v.begin_release(1, Uid::new()).unwrap();
            checkpoint(&w, &mut old);
            if policy == "Delete" {
                let v = w.storage_identities.lifecycle.get_mut(&id).unwrap();
                let deleted = receipt(v, Observation::Deleted);
                v.deleted(&deleted).unwrap();
                v.deleted(&deleted).unwrap();
                checkpoint(&w, &mut old);
            }
            assert!(w.validate_storage_delete("pvc", "a", "data").is_ok());
            assert!(w.delete_resource("pvc", "a", "data").unwrap().is_empty());
            checkpoint(&w, &mut old);
            assert_eq!(
                w.storage_identities.lifecycle.get(&id).unwrap().phase,
                if policy == "Delete" {
                    Phase::Deleted
                } else {
                    Phase::Released
                }
            );
        }
    }

    #[test]
    fn ambiguous_attach_cannot_hand_off_on_time_or_unrelated_receipts() {
        let (mut w, id) = world("Delete");
        let nodes = provision(&mut w, &id);
        let v = w.storage_identities.lifecycle.get_mut(&id).unwrap();
        v.begin_attach(0, nodes[0].clone(), boot(), Uid::new(), Uid::new())
            .unwrap();
        let old_mount = receipt(
            v,
            Observation::Mounted {
                filesystem_uuid: FS.into(),
            },
        );
        v.begin_fence(1, Uid::new()).unwrap();
        let before = serde_json::to_value(&v).unwrap();
        assert!(v
            .begin_attach(1, nodes[1].clone(), boot(), Uid::new(), Uid::new())
            .is_err());
        assert!(v.attached(&old_mount).is_err());
        for field in 0..5 {
            let mut r = receipt(v, Observation::Fenced);
            match field {
                0 => r.epoch += 1,
                1 => r.volume_uid = Uid::new(),
                2 => r.operation = Uid::new(),
                3 => r.node_uid = Some(nodes[1].clone()),
                _ => r.writer_uid = Some(Uid::new()),
            }
            assert!(v.detached(&r).is_err());
            assert_eq!(serde_json::to_value(&v).unwrap(), before);
        }
        let fenced = receipt(v, Observation::Fenced);
        v.detached(&fenced).unwrap();
        v.detached(&fenced).unwrap();
        let next = v
            .begin_attach(1, nodes[1].clone(), boot(), Uid::new(), Uid::new())
            .unwrap();
        assert_eq!(next.epoch, 2);
        assert!(v.attached(&old_mount).is_err());
        assert!(v.detached(&fenced).is_err());
    }

    #[test]
    fn attachment_epoch_overflow_and_non_replica_node_fail_without_mutation() {
        let (mut w, id) = world("Retain");
        let nodes = provision(&mut w, &id);
        let v = w.storage_identities.lifecycle.get_mut(&id).unwrap();
        let before = v.clone();
        assert!(v
            .begin_attach(0, Uid::new(), boot(), Uid::new(), Uid::new())
            .is_err());
        assert_eq!(*v, before);
        v.epoch = u64::MAX;
        let before = v.clone();
        assert!(v
            .begin_attach(u64::MAX, nodes[0].clone(), boot(), Uid::new(), Uid::new())
            .is_err());
        assert_eq!(*v, before);
    }

    #[test]
    fn full_state_commit_cannot_skip_fencing_roll_back_epoch_or_swap_writer() {
        let (mut w, id) = world("Retain");
        let nodes = provision(&mut w, &id);
        let v = w.storage_identities.lifecycle.get_mut(&id).unwrap();
        v.begin_attach(0, nodes[0].clone(), boot(), Uid::new(), Uid::new())
            .unwrap();
        let old = w.storage_identities.lifecycle.clone();
        for change in 0..4 {
            let mut forged = old.clone();
            let v = forged.get_mut(&id).unwrap();
            match change {
                0 => {
                    v.phase = Phase::Detached;
                    v.assignment = None;
                }
                1 => {
                    v.epoch = 0;
                }
                2 => {
                    v.phase = Phase::Attached;
                    v.assignment.as_mut().unwrap().writer_uid = Uid::new();
                }
                _ => {
                    v.phase = Phase::Attached;
                    v.evidence = None;
                }
            }
            assert!(old.validate_transition(&forged).is_err());
        }
        assert!(old.validate_transition(&Registry::default()).is_err());
        assert!(Registry::default().validate_transition(&old).is_err());
    }

    #[test]
    fn cancellation_of_unstarted_intent_preserves_tombstone_and_namespace_boundary() {
        let (mut w, id) = world("Delete");
        let before = w.storage_identities.lifecycle.clone();
        assert!(w.delete_resource("namespace", "", "a").unwrap().is_empty());
        w.to_state()
            .storage_identities
            .validate(&w.to_state())
            .unwrap();
        before
            .validate_transition(&w.storage_identities.lifecycle)
            .unwrap();
        assert_eq!(
            w.storage_identities.lifecycle.get(&id).unwrap().phase,
            Phase::Deleted
        );
        assert!(w.storage_identities.claims.is_empty());
        let old_owner = w
            .storage_identities
            .lifecycle
            .get(&id)
            .unwrap()
            .owner
            .clone();
        w.apply(&resource(serde_json::json!({"kind":"PersistentVolumeClaim","metadata":{"name":"data","namespace":"a"},
            "spec":{"storageClassName":"replicated","resources":{"requests":{"storage":"64Mi"}}}}))).unwrap();
        let new_pv = w.pvcs["a/data"].bound_pv.as_ref().unwrap();
        let new_id = &w.storage_identities.volumes[new_pv];
        assert_ne!(new_id, &id);
        let new = w.storage_identities.lifecycle.get(new_id).unwrap();
        assert_ne!(old_owner.namespace_uid, new.owner.namespace_uid);
        assert_ne!(old_owner.claim_uid, new.owner.claim_uid);
        assert_eq!(new.phase, Phase::PendingProvision);
    }

    #[test]
    fn boot_change_cannot_replay_mount_detach_fence_or_rewrite_a_committed_writer() {
        let (mut w, id) = world("Retain");
        let nodes = provision(&mut w, &id);
        let v = w.storage_identities.lifecycle.get_mut(&id).unwrap();
        let writer = Uid::new();
        let op = Uid::new();
        v.begin_attach(0, nodes[0].clone(), boot(), writer.clone(), op.clone())
            .unwrap();
        let another: BootId =
            serde_json::from_value(serde_json::json!("b12c439a-d59b-4d47-9058-2134d97ebd7f"))
                .unwrap();
        let before = v.clone();
        assert!(v
            .begin_attach(0, nodes[0].clone(), another.clone(), writer, op)
            .is_err());
        let mut mount = receipt(
            v,
            Observation::Mounted {
                filesystem_uuid: FS.into(),
            },
        );
        mount.node_boot_id = Some(another.clone());
        assert!(v.attached(&mount).is_err());
        assert_eq!(*v, before);
        v.begin_fence(1, Uid::new()).unwrap();
        let mut fence = receipt(v, Observation::Fenced);
        fence.node_boot_id = Some(another.clone());
        assert!(v.detached(&fence).is_err());
        assert!(v.assignment.is_some());
        let mut legacy = serde_json::to_value(&v).unwrap();
        legacy["assignment"]
            .as_object_mut()
            .unwrap()
            .remove("node_boot_id");
        assert!(serde_json::from_value::<Volume>(legacy).is_err());
        let old = w.storage_identities.lifecycle.clone();
        let mut forged = old.clone();
        forged
            .get_mut(&id)
            .unwrap()
            .assignment
            .as_mut()
            .unwrap()
            .node_boot_id = another;
        assert!(old.validate_transition(&forged).is_err());
    }

    #[test]
    fn provisioning_boot_set_is_durable_exact_and_cannot_be_backfilled() {
        let (mut w, id) = world("Retain");
        let nodes = [Uid::new(), Uid::new(), Uid::new()];
        let v = w.storage_identities.lifecycle.get_mut(&id).unwrap();
        let op = Uid::new();
        v.begin_provision(nodes.clone(), boots(), op.clone())
            .unwrap();
        v.begin_provision(nodes.clone(), boots(), op.clone())
            .unwrap();
        let mut other = boots();
        other[1] =
            serde_json::from_value(serde_json::json!("b12c439a-d59b-4d47-9058-2134d97ebd7f"))
                .unwrap();
        assert!(v.begin_provision(nodes, other, op).is_err());
        let mut legacy = serde_json::to_value(&v).unwrap();
        legacy.as_object_mut().unwrap().remove("provision_boots");
        let legacy: Volume = serde_json::from_value(legacy).unwrap();
        assert!(
            legacy.validate().is_err(),
            "missing boot observations must not gain authority on migration"
        );
    }
}
