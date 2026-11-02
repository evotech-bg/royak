//! Attachment DATA and the private actual-round metadata join.
//! This module is a child of storage_lifecycle, never a public receipt factory.
//! No deserializer below can construct a round, drain token, FD or mount owner.
use super::*;
use crate::reconcile::DesiredWorld;
use crate::storage_pod_writer::{ManagedMountRef, PodWriterBinding};
use crate::storage_remote_protocol::{Revision, VerifiedDirectory};
use std::sync::{Arc, RwLock};

pub(crate) const ATTACH_ROUND_MS:u64=180_000;
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub(crate) enum AttachPhase {
    ActivateReplica,
    ObserveSynchronized,
    PromoteTarget,
    Mount,
    ObserveMounted,
}
impl AttachPhase {
    pub(crate) fn writer_only(self)->bool {
        matches!(self,Self::PromoteTarget|Self::Mount|Self::ObserveMounted)
    }
}

/// Current replica boot is DISTINCT from retained preparation provenance.
/// Reboot does not rewrite generation.virgin_replicas or mint a fresh worker.
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttachReplicaTarget {
    pub(crate) node_uid:Uid,
    pub(crate) current_boot:BootId,
    pub(crate) pool_uid:Uid,
    pub(crate) plan_sha256:String,
}

/// Closed historical DATA, not a live retained replica capability. Rebuilt
/// from the actual protected per-node initialization journals, then compared
/// to CURRENT canonical Core's retained prior EvidenceRef on every phase.
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitialReplicaLineage {
    pub(crate) committed_evidence_uid:Uid,
    pub(crate) primary:generation::physical::PrimaryFlushObservation,
    pub(crate) offline:[generation::physical::OfflineReplicaObservation;3],
}
impl InitialReplicaLineage {
    /// Historical DATA handoff from genuine acknowledged initialization, NOT
    /// a surviving init/attach permission. The normal actor still requires a
    /// new successful writer commit and actual fresh parent per boundary.
    pub(crate) fn from_acknowledged_initialization(world:&Arc<RwLock<DesiredWorld>>,
        actual:&crate::storage_driver::native_runtime::init::VerifiedInitializedRound,
        committed:&crate::storage_lifecycle::generation::CommittedGeneration)->Result<Self,String>{
        actual.assert_actual_store(world)?;
        if committed.intent().operation_uid()!=actual.intent().operation_uid() || committed.generation()!=actual.intent().generation(){
            return Err("historical handoff is not same actual acknowledged generation".into());
        }
        let current=world.try_read().map_err(|_|"initialized historical source busy")?;
        let volume=current.storage_identities.lifecycle.get(&committed.owner().volume_uid).ok_or("initialized source absent")?;
        if volume.owner()!=committed.owner() || volume.phase()!=Phase::Detached || volume.epoch()!=0
            || volume.assignment().is_some() || volume.pod_writer().is_some() || volume.data_generation()!=Some(committed.generation()) {
            return Err("historical handoff source is not exact current never-attached Detached generation".into());
        }
        let lineage=Self {committed_evidence_uid:volume.evidence.as_ref().ok_or("actual initialized receipt absent")?.uid.clone(),
            primary:actual.primary().clone(),offline:actual.offline().clone()};
        lineage.check_initial_generation(volume)?;Ok(lineage)
    }
    pub(crate) fn check_current_first_attach(&self,volume:&Volume)->Result<(),String> {
        if volume.phase()!=Phase::Attaching || volume.epoch()!=1 {
            return Err("only first attachment has initialized-offline lineage; clean-detach producer required for later epochs".into());
        }
        self.check_initial_generation(volume)
    }
    /// Necessary DATA join only. Called before reservation on Detached0 and
    /// during Attaching1; never accepts Attached/Mounted as this prior proof.
    pub(crate) fn check_initial_generation(&self,volume:&Volume)->Result<(),String> {
        if !matches!((volume.phase(),volume.epoch()),(Phase::Detached,0)|(Phase::Attaching,1)) {
            return Err("initialization prior proof is not current for this lifecycle phase/epoch".into());
        }
        let g=volume.data_generation().ok_or("initialized dataset missing")?;g.validate(volume)?;
        let p=&self.primary;
        if p.version!=1 || p.owner!=*volume.owner() || p.data_generation_uid!=g.uid
            || p.initialize_operation_uid!=g.initialize_operation_uid || p.filesystem_uuid!=g.filesystem_uuid
            || p.replica.node_uid!=g.initializer_node_uid || !g.virgin_replicas.contains(&p.replica)
            || !valid_hash(&p.data_sha256) || !valid_hash(&p.flush_sha256) || !valid_hash(&p.evidence_sha256)
            || p.backing_bytes<p.replica.exposed_bytes || p.backing_major>u32::MAX as u64 || p.backing_minor>u32::MAX as u64 {
            return Err("initial primary history differs from committed exact generation".into());
        }
        for (i,o) in self.offline.iter().enumerate() {
            if o.version!=1 || o.owner!=*volume.owner() || o.data_generation_uid!=g.uid
                || o.initialize_operation_uid!=g.initialize_operation_uid || o.filesystem_uuid!=g.filesystem_uuid
                || o.replica!=g.virgin_replicas[i] || o.data_sha256!=p.data_sha256
                || !valid_hash(&o.data_sha256) || !valid_hash(&o.offline_metadata_sha256) || !valid_hash(&o.evidence_sha256)
                || o.backing_bytes<o.replica.exposed_bytes || o.backing_major>u32::MAX as u64 || o.backing_minor>u32::MAX as u64
                || o.drbd_current_uuid.len()!=16 || ["0000000000000000","0000000000000004"].contains(&o.drbd_current_uuid.as_str())
                || !o.drbd_current_uuid.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) {
                return Err("all three exact initialized offline histories are required".into());
            }
        }
        let digest=crate::storage_remote_protocol::hash(&serde_json::to_vec(&(
            "royak-physical-three-node-generation-v1",volume.owner(),g,&self.primary,&self.offline))
            .map_err(|_|"cannot bind initialized prior proof")?);
        if volume.evidence.as_ref().is_none_or(|e|e.uid!=self.committed_evidence_uid || e.sha256!=digest) {
            return Err("initialization histories do not equal CURRENT canonical prior completed proof".into());
        }
        Ok(())
    }
    pub(crate) fn data_sha256(&self)->&str {&self.primary.data_sha256}
}

/// Closed wire DATA. Current metadata + authenticated sessions are necessary
/// but not sufficient: only the private FD/cgroup producer mints a permit.
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedAttachScope {
    pub(crate) version:u32,
    pub(crate) owner:Owner,
    pub(crate) mount_ref:ManagedMountRef,
    pub(crate) pod_writer:PodWriterBinding,
    pub(crate) generation:generation::DataGeneration,
    pub(crate) initial_lineage:InitialReplicaLineage,
    pub(crate) replicas:[AttachReplicaTarget;3],
    pub(crate) round_uid:Uid,
    pub(crate) phase:AttachPhase,
    pub(crate) phase_job_uid:Uid,
    pub(crate) phase_node_uid:Uid,
    pub(crate) phase_boot:BootId,
    pub(crate) issuer_node_uid:Uid,
    pub(crate) issuer_boot:BootId,
    pub(crate) issuer_revision:Revision,
    pub(crate) scope_sha256:String,
    pub(crate) directory_sha256:String,
    pub(crate) remaining_budget_ms:u64,
}
impl ExpectedAttachScope {
    pub(crate) fn validate(&self)->Result<(),String> {
        if self.version!=1 || !self.issuer_revision.at_least(&self.issuer_revision)
            || self.remaining_budget_ms==0 || self.remaining_budget_ms>ATTACH_ROUND_MS
            || !valid_hash(&self.scope_sha256) || !valid_hash(&self.directory_sha256)
            || self.mount_ref.volume_uid()!=&self.owner.volume_uid
            || self.mount_ref.generation_uid()!=&self.generation.uid
            || self.mount_ref.filesystem_uuid()!=self.generation.filesystem_uuid
            || self.mount_ref.writer_uid()!=self.pod_writer.uid()
            || self.pod_writer.namespace_uid()!=&self.owner.namespace_uid
            || self.mount_ref.epoch()==0 || self.generation.version!=1
            || !valid_uuid(&self.generation.filesystem_uuid)
            || self.generation.filesystem_uuid=="00000000-0000-0000-0000-000000000000" {
            return Err("invalid complete attachment DATA scope".into());
        }
        let mut nodes=BTreeSet::new();
        let mut pools=BTreeSet::new();
        for target in &self.replicas {
            let fact=self.generation.virgin_replicas.iter().find(|f|f.node_uid==target.node_uid)
                .ok_or("attachment target is not a committed initialized replica")?;
            fact.validate()?;
            if !nodes.insert(target.node_uid.clone()) || !pools.insert(target.pool_uid.clone())
                || target.pool_uid!=fact.pool_uid || target.plan_sha256!=fact.plan_sha256
                || fact.volume_uid!=self.owner.volume_uid
                || fact.prepare_operation_uid!=self.generation.prepare_operation_uid
                || !valid_hash(&target.plan_sha256) {
                return Err("attachment replica/plan/pool lineage changed or duplicated".into());
            }
        }
        let writer=self.replicas.iter().find(|r|&r.node_uid==self.mount_ref.node_uid())
            .ok_or("canonical attachment writer is not an initialized replica")?;
        let phase=self.replicas.iter().find(|r|r.node_uid==self.phase_node_uid)
            .ok_or("attachment phase target is not an initialized replica")?;
        if &writer.current_boot!=self.mount_ref.node_boot() || phase.current_boot!=self.phase_boot
            || self.phase.writer_only() && &self.phase_node_uid!=self.mount_ref.node_uid() {
            return Err("attachment role/current boot differs from exact target phase".into());
        }
        Ok(())
    }
    pub(crate) fn target(&self)->Result<&AttachReplicaTarget,String> {
        self.validate()?;
        self.replicas.iter().find(|r|r.node_uid==self.phase_node_uid).ok_or("attachment phase target absent".into())
    }
    /// Necessary DATA comparison, not fresh quorum or physical authority.
    /// Every actual issuer/receiver additionally joins the actual store pointer
    /// and current Pod source under its freshly observed revision.
    pub(crate) fn check_volume(&self,volume:&Volume)->Result<(),String> {
        self.validate()?;
        self.generation.validate(volume)?;
        self.initial_lineage.check_current_first_attach(volume)?;
        self.mount_ref.check_metadata(volume)?;
        self.pod_writer.validate_volume(volume)?;
        if volume.owner()!=&self.owner || volume.data_generation()!=Some(&self.generation)
            || volume.pod_writer()!=Some(&self.pod_writer) || volume.operation()!=self.mount_ref.operation_uid()
            || !matches!(volume.phase(),Phase::Attaching|Phase::Attached) {
            return Err("attachment differs from exact current Pod/claim/dataset/writer metadata".into());
        }
        Ok(())
    }
    pub(crate) fn check_observed(&self,view:&crate::raft_node::storage_remote_core::CoreObservation,
        directory:&VerifiedDirectory)->Result<(),String> {
        self.check_volume(view.volume())?;
        if view.cluster_id()!=self.owner.cluster_id || directory.cluster_id()!=self.owner.cluster_id
            || view.directory_commitment()!=Some(self.directory_sha256.as_str())
            || directory.digest()!=self.directory_sha256 || view.scope_sha256()!=self.scope_sha256
            || !view.revision().at_least(&self.issuer_revision)
            || directory.pin(&self.issuer_node_uid)?.raft_id!=self.issuer_revision.leader_raft_id {
            return Err("attachment is not exact authenticated current receiver/issuer Core".into());
        }
        for replica in &self.replicas {directory.pin(&replica.node_uid)?;}
        Ok(())
    }
    pub(crate) fn check_receiver(&self,view:&crate::raft_node::storage_remote_core::CoreObservation,
        directory:&VerifiedDirectory)->Result<(),String> {
        self.check_observed(view,directory)?;
        if view.local_node_uid()!=Some(&self.phase_node_uid) || view.actual_boot()!=&self.phase_boot {
            return Err("attachment receiver is not the exact actual local node/boot".into());
        }
        Ok(())
    }
    pub(crate) fn check_issuer(&self,view:&crate::raft_node::storage_remote_core::CoreObservation,
        directory:&VerifiedDirectory)->Result<(),String> {
        self.check_observed(view,directory)?;
        if view.local_node_uid()!=Some(&self.issuer_node_uid) || view.actual_boot()!=&self.issuer_boot {
            return Err("attachment issuer is not the exact actual local node/boot".into());
        }
        Ok(())
    }
}

/// Diagnostic bytes only. A helper's serde output is NOT this process's
/// VerifiedAttachDrain, VerifiedManagedMount or root-owned mount lifetime.
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AttachPhaseObservation {
    pub(crate) version:u32,
    pub(crate) phase:AttachPhase,
    pub(crate) scope_sha256:String,
    pub(crate) node_uid:Uid,
    pub(crate) boot:BootId,
    pub(crate) raw_kernel:serde_json::Value,
    pub(crate) exposed_data_sha256:Option<String>,
    pub(crate) mounted:Option<MountObservation>,
    pub(crate) evidence_sha256:String,
}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MountObservation {
    pub(crate) mount_id:u64,
    pub(crate) namespace_device:u64,
    pub(crate) namespace_inode:u64,
    pub(crate) device_major:u32,
    pub(crate) device_minor:u32,
    pub(crate) filesystem_uuid:String,
    pub(crate) target:String,
    pub(crate) private_propagation:bool,
}
impl AttachPhaseObservation {
    pub(crate) fn validate(&self,scope:&ExpectedAttachScope)->Result<(),String> {
        scope.validate()?;
        if self.version!=1 || self.phase!=scope.phase || self.scope_sha256!=scope_digest(scope)?
            || self.node_uid!=scope.phase_node_uid || self.boot!=scope.phase_boot
            || !valid_hash(&self.evidence_sha256) || self.evidence_sha256!=self.digest()?
            || self.exposed_data_sha256.as_deref().is_some_and(|v|!valid_hash(v))
            || self.raw_kernel.is_null() {
            return Err("helper attachment diagnostic has another exact scope/phase/node/boot".into());
        }
        if let Some(mount)=&self.mounted {
            if !matches!(scope.phase,AttachPhase::Mount|AttachPhase::ObserveMounted)
                || &scope.phase_node_uid!=scope.mount_ref.node_uid() || mount.mount_id==0
                || mount.namespace_inode==0 || mount.filesystem_uuid!=scope.generation.filesystem_uuid
                || mount.target!=mount_path(&scope.mount_ref) || !mount.private_propagation {
                return Err("attachment diagnostic mount identity/role differs".into());
            }
        } else if matches!(scope.phase,AttachPhase::Mount|AttachPhase::ObserveMounted) {
            return Err("actual mounted target observation missing".into());
        }
        Ok(())
    }
    pub(crate) fn digest(&self)->Result<String,String> {
        use sha2::{Digest,Sha256};
        let bytes=serde_json::to_vec(&(self.version,self.phase,&self.scope_sha256,&self.node_uid,&self.boot,
            &self.raw_kernel,&self.exposed_data_sha256,&self.mounted))
            .map_err(|_|"cannot bind actual attachment diagnostic")?;
        if bytes.len()>1024*1024 {return Err("attachment diagnostic exceeds existing helper output bound".into());}
        Ok(format!("{:x}",Sha256::digest(bytes)))
    }
}
pub(crate) fn scope_digest(scope:&ExpectedAttachScope)->Result<String,String> {
    use sha2::{Digest,Sha256};
    let raw=serde_json::to_vec(scope).map_err(|_|"cannot bind complete attach scope")?;
    if raw.len()>32*1024 {return Err("attach scope exceeds fixed frame".into());}
    Ok(format!("{:x}",Sha256::digest(raw)))
}
pub(crate) fn mount_path(reference:&ManagedMountRef)->String {
    // Exact reserved private root; no user-selected source/destination path.
    format!("/var/lib/royak/storage/mounts/{}/{}/{}",reference.volume_uid().as_str(),
        reference.epoch(),reference.writer_uid().as_uid().as_str())
}

/// Read-only comparison of a receipt already in CURRENT metadata. Presence
/// of prior Attaching evidence never satisfies this Mounted-phase predicate.
pub(crate) fn check_mounted_receipt_data(volume:&Volume,uid:&Uid,sha256:&str)->Result<(),String> {
    if volume.phase()!=Phase::Attached || !valid_hash(sha256)
        || volume.evidence.as_ref().is_none_or(|e|&e.uid!=uid || e.sha256!=sha256) {
        return Err("current exact Mounted acknowledgement absent; prior proof is not mount readiness".into());
    }Ok(())
}
/// DATA comparison only, never a terminal permission or reconstructed owner.
pub(crate) fn check_terminal_detached_receipt_data(volume:&Volume,operation:&Uid,sha256:&str)->Result<(),String>{
    if volume.phase()!=Phase::Detached||volume.operation()!=operation||volume.assignment().is_some()||!valid_hash(sha256)
        ||volume.evidence.as_ref().is_none_or(|e|e.sha256!=sha256){
        return Err("current actual terminal Detached acknowledgement differs".into());}
    Ok(())
}

/// This represents an ACKed metadata transition only, never reconstruction
/// of a live mount from Attached/Assignment JSON after restart.
pub(crate) struct CommittedAttachment {
    writer:crate::storage_pod_writer::PodWriterUid,
    evidence:BTreeMap<Uid,String>,
}
impl CommittedAttachment {
    pub(crate) fn writer_uid(&self)->&crate::storage_pod_writer::PodWriterUid {&self.writer}
    pub(crate) fn evidence(&self)->&BTreeMap<Uid,String> {&self.evidence}
}
pub(crate) async fn commit_pod_attached(world:&Arc<RwLock<DesiredWorld>>,
    round:&crate::storage_driver::native_runtime::mount::VerifiedMountedRound)
    ->Result<CommittedAttachment,crate::store::CommitError> {
    let prepared=round.prepare_mounted_commit(world).await?;
    prepared.execute().await
}

/// Called ONLY by the existing owned IO worker with an actual rooted,
/// purpose-specific one-use prepared permission. No blocking Raft in Tokio.
pub(crate) fn commit_prepared_in_owned_io(world:&Arc<RwLock<DesiredWorld>>,
    prepared:&crate::storage_driver::native_runtime::mount::commit::PreparedMountedCommit)
    ->Result<CommittedAttachment,crate::store::CommitError> {
    use crate::store::CommitError;
    let round=prepared.round();
    round.assert_actual_store(world).map_err(CommitError::Unavailable)?;
    crate::store::commit(world,|scratch| {
        round.assert_actual_store(world).map_err(|e|(409,e))?;
        prepared.validate_scratch(scratch).map_err(|e|(409,e))?;
        let mut evidence=BTreeMap::new();
        for (uid,witness) in round.witnesses() {
            let volume=scratch.storage_identities.lifecycle.get_mut(uid)
                .ok_or((409,"mounted exact volume disappeared".into()))?;
            witness.check_current_volume(volume).map_err(|e|(409,e))?;
            let assignment=volume.assignment().ok_or((409,"canonical mounted Assignment absent".into()))?;
            let receipt=VerifiedReceipt {volume_uid:uid.clone(),operation:assignment.attach_operation.clone(),epoch:assignment.epoch,
                node_uid:Some(assignment.node_uid.clone()),node_boot_id:Some(assignment.node_boot_id.clone()),
                writer_uid:Some(assignment.writer_uid.clone()),data_generation_uid:assignment.data_generation_uid.clone(),
                evidence:EvidenceRef {uid:witness.evidence_uid().clone(),sha256:witness.evidence_sha256().into()},
                observation:Observation::Mounted {filesystem_uuid:witness.filesystem_uuid().into()}};
            volume.attached(&receipt).map_err(|e|(409,e))?;
            evidence.insert(uid.clone(),witness.evidence_sha256().to_string());
        }
        prepared.validate_post_scratch(scratch).map_err(|e|(409,e))?;
        Ok(CommittedAttachment {writer:round.writer_uid().clone(),evidence})
    })
}

/// Actual terminal caller on the SAME owned IO worker. The argument can only
/// be produced by the live original terminal actor with fresh one-use Core
/// authorization and, for Detached, the exact three independent current
/// physical completions. No public/raw/serde receipt constructor is added.
pub(crate) fn commit_terminal_in_owned_io(world:&Arc<RwLock<DesiredWorld>>,
    prepared:&crate::storage_driver::native_runtime::mount::consumer::terminal::commit::PreparedTerminalMetadata)
    ->Result<(),crate::store::CommitError>{
    use crate::store::CommitError;
    use crate::storage_driver::native_runtime::mount::consumer::terminal::commit::MetadataKind;
    if !Arc::ptr_eq(world,prepared.actual_store())||!crate::raft_node::storage_remote_core::is_actual_world(world){
        return Err(CommitError::Unavailable("terminal actual sealed store pointer differs".into()));}
    crate::store::commit(world,|scratch|{
        prepared.validate_scratch(scratch).map_err(|e|(409,e))?;
        let reference=prepared.original_reference().map_err(|e|(409,e))?;
        let volume=scratch.storage_identities.lifecycle.get_mut(reference.volume_uid()).ok_or((409,"terminal exact dataset disappeared".into()))?;
        match prepared.kind(){
            MetadataKind::BeginDetaching=>volume.begin_detach(reference.epoch(),prepared.operation_uid().clone()).map_err(|e|(409,e))?,
            MetadataKind::CommitDetached=>{
                let proof=prepared.offline().map_err(|e|(409,e))?;
                let assignment=volume.assignment().ok_or((409,"terminal original writer Assignment absent".into()))?;
                let receipt=VerifiedReceipt{volume_uid:reference.volume_uid().clone(),operation:prepared.operation_uid().clone(),epoch:reference.epoch(),
                    node_uid:Some(assignment.node_uid.clone()),node_boot_id:Some(assignment.node_boot_id.clone()),writer_uid:Some(assignment.writer_uid.clone()),
                    data_generation_uid:reference.generation_uid().clone(),evidence:EvidenceRef{uid:proof.evidence_uid().clone(),sha256:proof.evidence_sha256().into()},
                    observation:Observation::Detached};
                volume.detached(&receipt).map_err(|e|(409,e))?;
            },
        }
        prepared.validate_post_scratch(scratch).map_err(|e|(409,e))?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn model_lineage(volume:&mut Volume)->InitialReplicaLineage {
        // DATA model only, not a physical producer/receipt capability.
        let g=volume.data_generation().unwrap().clone();
        let fact=g.virgin_replicas.iter().find(|f|f.node_uid==g.initializer_node_uid).unwrap().clone();
        let primary=generation::physical::PrimaryFlushObservation {version:1,owner:volume.owner().clone(),
            data_generation_uid:g.uid.clone(),initialize_operation_uid:g.initialize_operation_uid.clone(),
            filesystem_uuid:g.filesystem_uuid.clone(),backing_major:253,backing_minor:0,backing_bytes:fact.exposed_bytes,
            replica:fact,data_sha256:"a".repeat(64),flush_sha256:"b".repeat(64),evidence_sha256:"c".repeat(64)};
        let offline=std::array::from_fn(|i|generation::physical::OfflineReplicaObservation {version:1,
            owner:volume.owner().clone(),data_generation_uid:g.uid.clone(),initialize_operation_uid:g.initialize_operation_uid.clone(),
            filesystem_uuid:g.filesystem_uuid.clone(),replica:g.virgin_replicas[i].clone(),backing_major:253,backing_minor:i as u64,
            backing_bytes:g.virgin_replicas[i].exposed_bytes,data_sha256:primary.data_sha256.clone(),
            offline_metadata_sha256:"d".repeat(64),drbd_current_uuid:"1234567890abcdef".into(),evidence_sha256:"e".repeat(64)});
        let uid=Uid::new();
        let digest=crate::storage_remote_protocol::hash(&serde_json::to_vec(&(
            "royak-physical-three-node-generation-v1",volume.owner(),&g,&primary,&offline)).unwrap());
        volume.evidence=Some(EvidenceRef {uid:uid.clone(),sha256:digest});
        InitialReplicaLineage {committed_evidence_uid:uid,primary,offline}
    }
    #[test]
    fn initialization_data_must_match_current_canonical_prior_proof_after_reservation() {
        let (mut world,uid,node,boot)=super::super::model_pod_writer_world();
        let v=world.storage_identities.lifecycle.get_mut(&uid).unwrap();
        let lineage=model_lineage(v);lineage.check_initial_generation(v).unwrap();
        v.begin_attach(0,node,boot,Uid::new(),Uid::new()).unwrap();
        lineage.check_current_first_attach(v).unwrap();
        for case in 0..5 {
            let mut bad=lineage.clone();match case {0=>bad.committed_evidence_uid=Uid::new(),
                1=>bad.offline[1].data_sha256="f".repeat(64),2=>bad.offline[2]=bad.offline[1].clone(),
                3=>bad.primary.flush_sha256="f".repeat(64),_=>bad.offline[0].filesystem_uuid="12345678-1234-4234-a234-123456789abc".into()}
            assert!(bad.check_current_first_attach(v).is_err(),"lineage DATA case {case}");
        }
        let old=v.evidence.take();assert!(lineage.check_current_first_attach(v).is_err());v.evidence=old;
        assert!(check_mounted_receipt_data(v,&lineage.committed_evidence_uid,&v.evidence.as_ref().unwrap().sha256).is_err());
    }
    #[test]
    fn later_epoch_or_attached_prior_data_is_not_initial_mount_readiness() {
        let (mut world,uid,node,boot)=super::super::model_pod_writer_world();
        let v=world.storage_identities.lifecycle.get_mut(&uid).unwrap();let lineage=model_lineage(v);
        v.begin_attach(0,node,boot,Uid::new(),Uid::new()).unwrap();
        v.epoch=2;assert!(lineage.check_current_first_attach(v).is_err());
        v.epoch=1;v.phase=Phase::Attached;assert!(lineage.check_initial_generation(v).is_err());
        // No test/model method above produces VerifiedManagedMount or drain.
    }
}
