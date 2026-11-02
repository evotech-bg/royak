//! Durable managed Pod incarnation DATA, not a mount/writer capability.
//!
//! Assignment remains the only current writer reservation. This embedded
//! per-volume binding is retained after detach as history, never used to
//! reconstruct a live mount, FD, dispatcher owner or physical receipt.
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::reconcile::DesiredWorld;
use crate::storage_boot::BootId;
use crate::storage_identity::Uid;
use crate::storage_lifecycle::{Assignment, Phase, Volume};
use crate::store::CommitError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct PodWriterUid(Uid);
impl PodWriterUid {
    pub(crate) fn as_uid(&self) -> &Uid { &self.0 }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct VolumeBinding {
    claim_uid: Uid,
    generation_uid: Uid,
    filesystem_uuid: String,
}

/// Serialized identity/history only. Its deserializer grants NO physical right.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PodWriterBinding {
    version: u32,
    uid: PodWriterUid,
    namespace_uid: Uid,
    namespace: String,
    workload: String,
    pod: String,
    stateful: bool,
    ordinal: Option<u32>,
    source_sha256: String,
    volumes: BTreeMap<Uid, VolumeBinding>,
}
impl PodWriterBinding {
    pub(crate) fn uid(&self) -> &PodWriterUid { &self.uid }
    pub(crate) fn pod(&self) -> &str { &self.pod }
    pub(crate) fn namespace(&self)->&str {&self.namespace}
    pub(crate) fn workload(&self)->&str {&self.workload}
    pub(crate) fn ordinal(&self)->Option<u32> {self.ordinal}
    pub(crate) fn namespace_uid(&self) -> &Uid { &self.namespace_uid }
    pub(crate) fn source_sha256(&self) -> &str { &self.source_sha256 }
    /// Read-only source comparison. This is NOT an attachment/mount grant and
    /// accepts no asserted boot, world-ownership flag or capability DTO.
    pub(crate) fn check_source_current(&self, world:&DesiredWorld)->Result<(),String> {
        let request=PodWriterRequest {namespace:self.namespace.clone(),workload:self.workload.clone(),
            pod:self.pod.clone(),ordinal:self.ordinal,operation_uid:self.uid.as_uid().clone(),
            expected_epochs:self.volumes.keys().map(|id|(id.clone(),0)).collect()};
        let current=resolve_source(world,&request)?;
        if current.namespace_uid!=self.namespace_uid || current.source_sha256!=self.source_sha256
            || current.stateful!=self.stateful || current.volumes!=self.volumes {
            return Err("managed Pod source/incarnation changed after writer reservation".into());
        }
        self.validate_group(&world.storage_identities.lifecycle)
    }
    pub(crate) fn validate_group(&self,registry:&crate::storage_lifecycle::Registry)->Result<(),String> {
        for uid in self.volumes.keys() {
            self.validate_volume(registry.get(uid).ok_or("PodWriter history references an absent dataset")?)?;
        }
        Ok(())
    }
    pub(crate) fn validate_volume(&self, volume: &Volume) -> Result<(), String> {
        let owner=volume.owner();
        if self.version!=1 || !crate::reconcile::validate_name(&self.namespace)
            || !crate::reconcile::validate_name(&self.workload)
            || self.pod.is_empty() || self.pod.len()>256 || self.pod.contains('/')
            || self.namespace!=owner.namespace || self.namespace_uid!=owner.namespace_uid
            || self.volumes.is_empty() || self.volumes.len()>8
            || !valid_hash(&self.source_sha256) {
            return Err("invalid durable PodWriter identity/scope".into());
        }
        let stem=crate::store::pod_stem(&self.namespace,&self.workload);
        let suffix=self.pod.strip_prefix(&(stem+"-")).ok_or("PodWriter pod is outside exact workload stem")?;
        let index=suffix.parse::<u32>().map_err(|_|"invalid PodWriter pod ordinal")?;
        if suffix!=index.to_string() || self.stateful!=(self.ordinal.is_some())
            || self.ordinal.is_some_and(|ordinal|ordinal!=index) || index==0 {
            return Err("PodWriter pod/ordinal contract differs".into());
        }
        let target=self.volumes.get(volume.uid()).ok_or("PodWriter does not bind this exact volume")?;
        let generation=volume.data_generation().ok_or("PodWriter volume has no initialized generation")?;
        if target.claim_uid!=owner.claim_uid || target.generation_uid!=generation.uid
            || target.filesystem_uuid!=generation.filesystem_uuid {
            return Err("PodWriter claim/dataset/filesystem identity changed".into());
        }
        Ok(())
    }
}

fn valid_hash(value:&str)->bool {
    value.len()==64 && value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
}
fn hash<T:Serialize>(value:&T)->Result<String,String> {
    let raw=serde_json::to_vec(value).map_err(|_|"cannot encode exact managed Pod source")?;
    if raw.len()>32*1024 {return Err("managed Pod source exceeds fixed frame bound".into());}
    Ok(format!("{:x}",Sha256::digest(raw)))
}

/// An internal request, not Deserialize/Clone and never an attachment grant.
/// The controller must retain operation_uid across an ambiguous result; it
/// cannot generate another operation in response to a timeout/lost ACK.
pub(crate) struct PodWriterRequest {
    namespace:String,
    workload:String,
    pod:String,
    ordinal:Option<u32>,
    operation_uid:Uid,
    expected_epochs:BTreeMap<Uid,u64>,
}
impl PodWriterRequest {
    pub(crate) fn new(namespace:String,workload:String,pod:String,ordinal:Option<u32>,
        operation_uid:Uid,expected_epochs:BTreeMap<Uid,u64>)->Result<Self,String> {
        if !crate::reconcile::validate_name(&namespace) || !crate::reconcile::validate_name(&workload)
            || pod.is_empty() || pod.len()>256 || expected_epochs.is_empty() || expected_epochs.len()>8 {
            return Err("invalid bounded managed Pod reservation request".into());
        }
        Ok(Self {namespace,workload,pod,ordinal,operation_uid,expected_epochs})
    }
}

/// DATA reference for a future security-versioned launch endpoint. No path,
/// FD, mount namespace, mount ID, lease or asserted boolean crosses the wire.
/// Not yet a MountSource variant; existing launch/mount refusals stay active.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedMountRef {
    cluster_id:String,
    namespace_uid:Uid,
    claim_uid:Uid,
    volume_uid:Uid,
    generation_uid:Uid,
    filesystem_uuid:String,
    writer_uid:PodWriterUid,
    epoch:u64,
    attach_operation:Uid,
    node_uid:Uid,
    node_boot_id:BootId,
}
impl ManagedMountRef {
    /// DATA reference only: a serialized Volume can produce the same DATA.
    /// A real producer must separately require actual Core, private worker,
    /// kernel ownership and current FD/mount observations. No path is emitted.
    pub(crate) fn from_metadata(volume:&Volume)->Result<Self,String> {
        let owner=volume.owner();
        let assignment=volume.assignment().ok_or("managed mount reference has no canonical Assignment")?;
        let binding=volume.pod_writer().ok_or("managed mount reference has no durable PodWriter")?;
        binding.validate_volume(volume)?;
        if !matches!(volume.phase(),Phase::Attaching|Phase::Attached)
            || assignment.writer_uid!=*binding.uid().as_uid()
            || assignment.attach_operation!=*volume.operation()
            || assignment.epoch!=volume.epoch() {
            return Err("managed mount reference differs from canonical writer metadata".into());
        }
        let generation=volume.data_generation().ok_or("managed reference has no initialized dataset")?;
        if generation.uid!=assignment.data_generation_uid {
            return Err("managed reference assignment/dataset mismatch".into());
        }
        Ok(Self {cluster_id:owner.cluster_id.clone(),namespace_uid:owner.namespace_uid.clone(),
            claim_uid:owner.claim_uid.clone(),volume_uid:owner.volume_uid.clone(),generation_uid:generation.uid.clone(),
            filesystem_uuid:generation.filesystem_uuid.clone(),writer_uid:binding.uid().clone(),epoch:assignment.epoch,
            attach_operation:assignment.attach_operation.clone(),node_uid:assignment.node_uid.clone(),node_boot_id:assignment.node_boot_id.clone()})
    }
    pub(crate) fn check_metadata(&self,volume:&Volume)->Result<(),String> {
        if self!=&Self::from_metadata(volume)? {return Err("managed mount reference is not exact current metadata".into());}
        Ok(())
    }
    pub(crate) fn volume_uid(&self)->&Uid {&self.volume_uid}
    pub(crate) fn generation_uid(&self)->&Uid {&self.generation_uid}
    pub(crate) fn filesystem_uuid(&self)->&str {&self.filesystem_uuid}
    pub(crate) fn writer_uid(&self)->&PodWriterUid {&self.writer_uid}
    pub(crate) fn epoch(&self)->u64 {self.epoch}
    pub(crate) fn operation_uid(&self)->&Uid {&self.attach_operation}
    pub(crate) fn node_uid(&self)->&Uid {&self.node_uid}
    pub(crate) fn node_boot(&self)->&BootId {&self.node_boot_id}
}

/// Acknowledged Core metadata only. Cannot produce VerifiedManagedMount.
pub(crate) struct CommittedPodWriterIntent {
    binding:PodWriterBinding,
    assignments:BTreeMap<Uid,Assignment>,
}
impl CommittedPodWriterIntent {
    pub(crate) fn binding(&self)->&PodWriterBinding {&self.binding}
    pub(crate) fn assignments(&self)->&BTreeMap<Uid,Assignment> {&self.assignments}
    pub(crate) fn check_metadata_current(&self,world:&DesiredWorld)->Result<(),String> {
        let request=PodWriterRequest {namespace:self.binding.namespace.clone(),workload:self.binding.workload.clone(),
            pod:self.binding.pod.clone(),ordinal:self.binding.ordinal,operation_uid:self.binding.uid.as_uid().clone(),
            expected_epochs:self.binding.volumes.keys().map(|uid|(uid.clone(),0)).collect()};
        let source=resolve_source(world,&request)?;
        if source.namespace_uid!=self.binding.namespace_uid || source.source_sha256!=self.binding.source_sha256
            || source.stateful!=self.binding.stateful || source.volumes!=self.binding.volumes {
            return Err("committed PodWriter launch source is no longer current".into());
        }
        for (uid,assignment) in &self.assignments {
            let volume=world.storage_identities.lifecycle.get(uid).ok_or("committed PodWriter volume missing")?;
            self.binding.validate_volume(volume)?;
            if volume.pod_writer()!=Some(&self.binding) || volume.assignment()!=Some(assignment)
                || !matches!(volume.phase(),Phase::Attaching|Phase::Attached) {
                return Err("committed PodWriter metadata is stale".into());
            }
        }
        Ok(())
    }
}

struct ResolvedSource {
    namespace_uid:Uid,
    source_sha256:String,
    stateful:bool,
    volumes:BTreeMap<Uid,VolumeBinding>,
}
fn resolve_source(world:&DesiredWorld,request:&PodWriterRequest)->Result<ResolvedSource,String> {
    let key=crate::store::obj_key(&request.namespace,&request.workload);
    let deployment=world.deployments.get(&key).ok_or("current managed Pod workload absent")?;
    let namespace_uid=world.storage_identities.namespaces.get(&request.namespace)
        .ok_or("managed Pod namespace incarnation absent")?.clone();
    if deployment.namespace!=request.namespace || deployment.name!=request.workload || deployment.paused
        || deployment.replicas==0 || deployment.containers.is_empty() {
        return Err("managed Pod workload is not current/runnable".into());
    }
    let stem=crate::store::pod_stem(&request.namespace,&request.workload);
    let suffix=request.pod.strip_prefix(&(stem+"-")).ok_or("managed Pod request has foreign name")?;
    let index=suffix.parse::<u32>().map_err(|_|"managed Pod request has invalid ordinal")?;
    if suffix!=index.to_string() || deployment.stateful!=(request.ordinal.is_some())
        || deployment.stateful&&request.ordinal!=Some(index)
        || deployment.stateful&&(index==0 || index>deployment.replicas) || !deployment.stateful&&index==0 {
        return Err("managed Pod slot differs from current workload".into());
    }
    let mut volumes=BTreeMap::new();
    for container in deployment.init_containers.iter().chain(&deployment.containers) {
        for (source,_) in &container.volumes {
            let Some(claim_name)=source.strip_prefix("pvc:") else {
                if !(source.starts_with("cmv:") || source.starts_with("sev:") || source.starts_with("emptydir:")) {
                    return Err("managed Pod cannot mix legacy/unknown storage with native attachment".into());
                }
                continue;
            };
            let claim_key=crate::store::obj_key(&request.namespace,claim_name);
            let claim=world.pvcs.get(&claim_key).ok_or("managed Pod claim absent")?;
            let pv_name=claim.bound_pv.as_ref().ok_or("managed Pod claim unbound")?;
            let pv=world.pvs.get(pv_name).ok_or("managed Pod PV absent")?;
            if !world.storage_classes.get(&pv.storage_class).is_some_and(|s|s.provisioner==crate::storage_lifecycle::PROVISIONER)
                || pv.bound_to.as_ref()!=Some(&claim_key) || pv.storage_class!=claim.storage_class
                || claim.namespace!=request.namespace || claim.name!=claim_name
                || pv.status!=crate::reconcile::PVStatus::Bound || pv.access_mode!=claim.access_mode
                || crate::storage::capacity_bytes(&pv.capacity)?<crate::storage::capacity_bytes(&claim.requested)? {
                return Err("managed Pod does not have exact native two-way claim binding".into());
            }
            let identity=world.storage_identities.claims.get(&claim_key).ok_or("managed Pod claim UID absent")?;
            let uid=world.storage_identities.volumes.get(pv_name).ok_or("managed Pod PV UID absent")?;
            let volume=world.storage_identities.lifecycle.get(uid).ok_or("managed Pod lifecycle absent")?;
            let owner=volume.owner();let generation=volume.data_generation().ok_or("managed Pod dataset uninitialized")?;
            if identity.namespace_uid!=namespace_uid || identity.uid!=owner.claim_uid
                || owner.namespace_uid!=namespace_uid || owner.cluster_id!=world.cluster_id
                || owner.namespace!=request.namespace || owner.claim_name!=claim_name {
                return Err("managed Pod owner/claim incarnation changed".into());
            }
            volumes.insert(uid.clone(),VolumeBinding {claim_uid:identity.uid.clone(),
                generation_uid:generation.uid.clone(),filesystem_uuid:generation.filesystem_uuid.clone()});
        }
    }
    if volumes.is_empty() || volumes.len()>8 || volumes.keys().ne(request.expected_epochs.keys()) {
        return Err("managed Pod exact bounded volume set/epochs differ".into());
    }
    // Hash only the actual launch-defining source, not mutable idle/rollout
    // bookkeeping. Eligibility (pause/replicas/ordinal) is checked separately.
    let source_sha256=hash(&(&deployment.namespace,&deployment.name,deployment.stateful,
        &deployment.init_containers,&deployment.containers,&deployment.resource_limits,deployment.restart_nonce))?;
    Ok(ResolvedSource {namespace_uid,source_sha256,stateful:deployment.stateful,volumes})
}

fn reserve_in_scratch(world:&mut DesiredWorld,request:&PodWriterRequest,node:&Uid,boot:&BootId)
    ->Result<CommittedPodWriterIntent,String> {
    let source=resolve_source(world,request)?;
    // A repeated exact operation may diagnose its ACKed metadata. It never
    // reruns a physical action or fabricates any local retained capability.
    let existing=source.volumes.keys().filter_map(|uid|world.storage_identities.lifecycle.get(uid))
        .filter_map(|v|v.assignment().map(|a|(v,a))).collect::<Vec<_>>();
    if !existing.is_empty() {
        if existing.len()!=source.volumes.len() {return Err("partial/mixed PodWriter reservation; UNKNOWN".into());}
        let binding=existing[0].0.pod_writer().ok_or("old writer lacks durable PodWriter identity")?.clone();
        if binding.namespace_uid!=source.namespace_uid || binding.namespace!=request.namespace
            || binding.workload!=request.workload || binding.pod!=request.pod || binding.ordinal!=request.ordinal
            || binding.stateful!=source.stateful || binding.source_sha256!=source.source_sha256 || binding.volumes!=source.volumes {
            return Err("another Pod/source incarnation already reserves these volumes".into());
        }
        let mut assignments=BTreeMap::new();
        for (volume,assignment) in existing {
            if !matches!(volume.phase(),Phase::Attaching|Phase::Attached) || volume.pod_writer()!=Some(&binding)
                || assignment.writer_uid!=*binding.uid.as_uid() || assignment.node_uid!=*node
                || assignment.node_boot_id!=*boot || assignment.attach_operation!=request.operation_uid
                || request.expected_epochs.get(volume.uid()).and_then(|e|e.checked_add(1))!=Some(assignment.epoch) {
                return Err("unresolved/stale PodWriter assignment; no retry/new owner".into());
            }
            assignments.insert(volume.uid().clone(),assignment.clone());
        }
        return Ok(CommittedPodWriterIntent {binding,assignments});
    }
    let new_uid=Uid::new();
    if world.storage_identities.volumes.values().filter_map(|uid|world.storage_identities.lifecycle.get(uid))
        .filter_map(|volume|volume.pod_writer()).any(|old|old.uid().as_uid()==&new_uid) {
        return Err("new PodWriter UID collides with retained history; no automatic retry".into());
    }
    let binding=PodWriterBinding {version:1,uid:PodWriterUid(new_uid),namespace_uid:source.namespace_uid,
        namespace:request.namespace.clone(),workload:request.workload.clone(),pod:request.pod.clone(),
        stateful:source.stateful,ordinal:request.ordinal,source_sha256:source.source_sha256,volumes:source.volumes};
    // All reads/eligibility checks precede any scratch mutation.
    for uid in binding.volumes.keys() {
        let volume=world.storage_identities.lifecycle.get(uid).ok_or("managed volume disappeared")?;
        if volume.phase()!=Phase::Detached || volume.epoch()!=request.expected_epochs[uid]
            || !volume.replicas().is_some_and(|nodes|nodes.contains(node)) {
            return Err("managed volume is not exactly Detached/current/local-replica".into());
        }
        binding.validate_volume(volume)?;
    }
    let mut assignments=BTreeMap::new();
    for uid in binding.volumes.keys() {
        let volume=world.storage_identities.lifecycle.get_mut(uid).ok_or("managed volume disappeared")?;
        let assignment=volume.begin_pod_attach(request.expected_epochs[uid],node.clone(),boot.clone(),
            binding.clone(),request.operation_uid.clone())?;
        assignments.insert(uid.clone(),assignment);
    }
    Ok(CommittedPodWriterIntent {binding,assignments})
}

/// First REAL metadata producer: actual sealed Raft's current local leader.
/// Remote authenticated placement/physical permits remain separate required
/// integrations, not a raw-boot fallback to this function.
pub(crate) async fn reserve_local_pod_writer(world:&Arc<RwLock<DesiredWorld>>,request:&PodWriterRequest)
    ->Result<CommittedPodWriterIntent,CommitError> {
    // Preserve old entrypoint/name, but never synchronously block a Tokio
    // worker or nest Handle::block_on through raft::commit_blocking.
    let owned=PodWriterRequest::new(request.namespace.clone(),request.workload.clone(),request.pod.clone(),request.ordinal,
        request.operation_uid.clone(),request.expected_epochs.clone()).map_err(CommitError::Unavailable)?;
    let prepared=prepare_local_pod_writer(world,owned).await?;
    crate::storage_driver::native_runtime::commit_prepared_writer(prepared).await
}

struct PreparedWriterInner {
    world:Arc<RwLock<DesiredWorld>>,request:PodWriterRequest,
    view:crate::raft_node::storage_remote_core::RuntimeView,
    started:std::time::Instant,deadline:std::time::Instant,
    stage:std::sync::atomic::AtomicU8,invalid:std::sync::atomic::AtomicBool,
    observed:std::sync::Mutex<Option<String>>,
}
/// One-use actual Core metadata reservation. No serde/default/Clone/raw
/// fields; its negative owner reference cannot submit or reconstruct it.
pub(crate) struct PreparedPodWriterReservation {inner:Arc<PreparedWriterInner>}
pub(crate) struct WriterReservationOwner {inner:Arc<PreparedWriterInner>}
impl WriterReservationOwner {
    pub(crate) fn invalidate(&self){self.inner.invalid.store(true,std::sync::atomic::Ordering::Release);}
}
impl PreparedPodWriterReservation {
    pub(crate) fn owner(&self)->WriterReservationOwner{WriterReservationOwner {inner:self.inner.clone()}}
    fn live(&self,fresh:bool)->Result<(),String>{
        use std::sync::atomic::Ordering;
        let now=std::time::Instant::now();
        if self.inner.invalid.load(Ordering::Acquire)||!prepared_writer_clock(self.inner.started,self.inner.deadline,now,fresh){
            return Err("original prepared writer reservation expired/UNKNOWN".into());
        }
        crate::raft_node::storage_remote_core::require_same_actual_epoch(&self.inner.world,self.inner.view.revision())
    }
    /// Synchronous, only existing owned IO actor calls this. No async runtime
    /// is entered around store::commit; Raft owns its original5s wait.
    pub(crate) fn commit(self)->Result<CommittedPodWriterIntent,CommitError>{
        use std::sync::atomic::Ordering;
        self.inner.stage.compare_exchange(0,1,Ordering::AcqRel,Ordering::Acquire)
            .map_err(|_|CommitError::Unknown("prepared writer reservation already submitted".into()))?;
        self.live(true).map_err(CommitError::Unknown)?;
        let result=crate::store::commit(&self.inner.world,|scratch|{
            self.live(true).map_err(|e|(409,e))?;
            if scratch.generation!=self.inner.view.revision().desired_generation {
                return Err((409,"actual writer Core changed after fresh preparation".into()));
            }
            let intent=reserve_in_scratch(scratch,&self.inner.request,self.inner.view.local(),self.inner.view.boot()).map_err(|e|(409,e))?;
            self.live(true).map_err(|e|(409,e))?;Ok(intent)
        });
        // Record real outcome before checking whether a timely caller may
        // receive metadata. This is DATA, never a reconstructible grant.
        let note=match &result {Ok(intent)=>format!("ACKED writer {}",intent.binding().uid().as_uid().as_str()),Err(error)=>format!("NOT_CONFIRMED {error:?}")};
        *self.inner.observed.lock().unwrap_or_else(|p|p.into_inner())=Some(note);
        if let Err(error)=self.live(false){self.inner.invalid.store(true,Ordering::Release);return Err(CommitError::Unknown(error));}
        if result.is_err(){self.inner.invalid.store(true,Ordering::Release);}
        self.inner.stage.store(2,Ordering::Release);result
    }
}
fn prepared_writer_clock(started:std::time::Instant,deadline:std::time::Instant,now:std::time::Instant,fresh:bool)->bool{
    now>=started && now<deadline && (!fresh || now.duration_since(started)<std::time::Duration::from_millis(crate::raft_node::storage_remote_core::MAX_STORAGE_BOUNDARY_MS))
}
pub(crate) async fn prepare_local_pod_writer(world:&Arc<RwLock<DesiredWorld>>,request:PodWriterRequest)
    ->Result<PreparedPodWriterReservation,CommitError>{
    let started=std::time::Instant::now();
    if !crate::raft_node::storage_remote_core::is_actual_world(world) {
        return Err(CommitError::Unavailable("PodWriter requires actual Core world".into()));
    }
    let view=crate::raft_node::storage_remote_core::runtime_view(true).await.map_err(CommitError::Unavailable)?;
    let prepared=PreparedPodWriterReservation {inner:Arc::new(PreparedWriterInner {world:world.clone(),request,view,started,
        deadline:started+crate::raft_node::COMMIT_TIMEOUT,stage:std::sync::atomic::AtomicU8::new(0),invalid:std::sync::atomic::AtomicBool::new(false),
        observed:std::sync::Mutex::new(None)})};
    prepared.live(true).map_err(CommitError::Unavailable)?;Ok(prepared)
}

/// Current/legacy raw decode gate. Absence never mints identity, even schema8
/// or current AEAD plaintext. Safe never-writer epoch0 history is unchanged.
pub(crate) fn reject_unbound_writer_history(raw:&serde_json::Value)->Result<(),String> {
    let Some(registry)=raw.get("storage_identities").and_then(|v|v.get("lifecycle")) else {return Ok(())};
    let volumes=registry.get("volumes").and_then(|v|v.as_object()).ok_or("malformed raw lifecycle volume history")?;
    for volume in volumes.values() {
        let epoch=volume.get("epoch").and_then(|v|v.as_u64()).ok_or("malformed raw attachment epoch")?;
        let assignment=volume.get("assignment").filter(|v|!v.is_null());
        let phase=volume.get("phase").and_then(|v|v.as_str()).ok_or("malformed raw lifecycle phase")?;
        let writer=volume.get("pod_writer").filter(|v|!v.is_null());
        let bearing=epoch>0 || assignment.is_some() || matches!(phase,"Attaching"|"Attached"|"Detaching"|"Fencing");
        if bearing && writer.is_none() {return Err("legacy writer-bearing history needs explicit recovery; no PodWriter UID backfill".into());}
        if !bearing && writer.is_some() {return Err("never-writer history cannot import PodWriter identity".into());}
    }
    Ok(())
}

/// TEST-ONLY scratch metadata for the actual a/db source in the detached
/// model world. This is not a Raft ACK, FD/READY/mount or physical authority.
/// Do not replace the separate low-level lifecycle model_binding fixtures.
#[cfg(test)]
pub(crate) fn model_reserve_current_db_writer(
    world:&mut DesiredWorld,uid:&Uid,node:&Uid,boot:&BootId,
)->Result<(),String> {
    let request=PodWriterRequest::new("a".into(),"db".into(),
        format!("{}-1",crate::store::pod_stem("a","db")),None,Uid::new(),
        BTreeMap::from([(uid.clone(),0)]))?;
    // The same metadata factory resolves real current containers/limits,
    // namespace/claim/dataset identities and the exact volume/epoch set.
    reserve_in_scratch(world,&request,node,boot)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn model_binding(volume:&Volume,writer:Uid)->PodWriterBinding {
    let owner=volume.owner();let generation=volume.data_generation().expect("MODEL initialized dataset");
    PodWriterBinding {version:1,uid:PodWriterUid(writer),namespace_uid:owner.namespace_uid.clone(),
        namespace:owner.namespace.clone(),workload:"model".into(),pod:format!("{}-1",crate::store::pod_stem(&owner.namespace,"model")),
        stateful:true,ordinal:Some(1),source_sha256:"a".repeat(64),
        volumes:BTreeMap::from([(volume.uid().clone(),VolumeBinding {claim_uid:owner.claim_uid.clone(),
            generation_uid:generation.uid.clone(),filesystem_uuid:generation.filesystem_uuid.clone()})])}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_writer_clock_guard_is_data_only_and_never_renews_budget(){
        let now=std::time::Instant::now();let end=now+crate::raft_node::COMMIT_TIMEOUT;
        assert!(prepared_writer_clock(now,end,now,true));
        assert!(!prepared_writer_clock(now,end,end,false));
        assert!(!prepared_writer_clock(now+std::time::Duration::from_millis(1),end,now,true));
        let old=now+std::time::Duration::from_millis(crate::raft_node::storage_remote_core::MAX_STORAGE_BOUNDARY_MS);
        assert!(!prepared_writer_clock(now,end,old,true));assert!(prepared_writer_clock(now,end,old,false));
    }
    #[tokio::test]
    async fn split_writer_prepare_refuses_model_world_before_owned_io_submission(){
        let (world,uid,_,_)=fixture();let before=serde_json::to_value(world.to_state()).unwrap();
        let world=Arc::new(RwLock::new(world));
        assert!(prepare_local_pod_writer(&world,request(&uid)).await.is_err());
        assert_eq!(serde_json::to_value(world.read().unwrap().to_state()).unwrap(),before);
        assert!(world.read().unwrap().storage_identities.lifecycle.get(&uid).unwrap().assignment().is_none());
    }

    fn fixture()->(DesiredWorld,Uid,Uid,BootId) {
        crate::storage_lifecycle::model_pod_writer_world()
    }
    fn request(uid:&Uid)->PodWriterRequest {
        PodWriterRequest::new("a".into(),"db".into(),format!("{}-1",crate::store::pod_stem("a","db")),
            None,Uid::new(),BTreeMap::from([(uid.clone(),0)])).unwrap()
    }

    #[test]
    fn actual_scheduler_first_and_last_one_based_stateful_slots_join_writer_metadata() {
        // Actual scheduler function + metadata model, NOT a physical mount or
        // actual Raft/VM integration acceptance. No synthetic ordinal0 pass.
        for replicas in [1,3] {
            let (mut world,uid,node,boot)=fixture();
            let deployment=world.deployments.get_mut("a/db").unwrap();
            deployment.stateful=true;deployment.replicas=replicas;
            let previous:std::collections::HashSet<u32>=(1..replicas).collect();
            let ordinal=crate::reconcile::next_statefulset_ordinal(&previous,&previous,replicas).unwrap();
            assert_eq!(ordinal,replicas);
            let request=PodWriterRequest::new("a".into(),"db".into(),
                format!("{}-{ordinal}",crate::store::pod_stem("a","db")),Some(ordinal),Uid::new(),
                BTreeMap::from([(uid.clone(),0)])).unwrap();
            let intent=reserve_in_scratch(&mut world,&request,&node,&boot).unwrap();
            assert_eq!(intent.binding.ordinal,Some(ordinal));
            intent.check_metadata_current(&world).unwrap();
            intent.binding.check_source_current(&world).unwrap();
        }
    }

    #[test]
    fn stateful_zero_excess_noncanonical_or_wrong_ordinal_refuses_without_mutation() {
        for (suffix,ordinal) in [("0",Some(0)),("4",Some(4)),("01",Some(1)),("-1",Some(1)),("1",Some(2)),("1",None)] {
            let (mut world,uid,node,boot)=fixture();
            let deployment=world.deployments.get_mut("a/db").unwrap();
            deployment.stateful=true;deployment.replicas=3;
            let before=serde_json::to_vec(&world.to_state()).unwrap();
            let request=PodWriterRequest::new("a".into(),"db".into(),
                format!("{}-{suffix}",crate::store::pod_stem("a","db")),ordinal,Uid::new(),
                BTreeMap::from([(uid.clone(),0)])).unwrap();
            assert!(reserve_in_scratch(&mut world,&request,&node,&boot).is_err());
            assert_eq!(before,serde_json::to_vec(&world.to_state()).unwrap());
        }
    }

    #[test]
    fn durable_stateful_binding_rejects_zero_and_model_fixture_is_one_based() {
        let (world,uid,_,_)=fixture();let volume=world.storage_identities.lifecycle.get(&uid).unwrap();
        let good=model_binding(volume,Uid::new());assert_eq!(good.ordinal,Some(1));
        good.validate_volume(volume).unwrap();
        let mut zero=good;zero.pod=format!("{}-0",crate::store::pod_stem(&volume.owner().namespace,"model"));zero.ordinal=Some(0);
        assert!(zero.validate_volume(volume).is_err());
    }

    #[test]
    fn readonly_source_and_reference_data_do_not_bypass_changed_current_pod() {
        let (mut world,uid,node,boot)=fixture();
        let intent=reserve_in_scratch(&mut world,&request(&uid),&node,&boot).unwrap();
        let reference=ManagedMountRef::from_metadata(world.storage_identities.lifecycle.get(&uid).unwrap()).unwrap();
        reference.check_metadata(world.storage_identities.lifecycle.get(&uid).unwrap()).unwrap();
        intent.binding.check_source_current(&world).unwrap();
        let raw=serde_json::to_value(reference).unwrap();
        for forbidden in ["path","mount_id","fd","verified","lease"] {assert!(raw.get(forbidden).is_none());}
        world.deployments.get_mut("a/db").unwrap().containers[0].image="changed-pod-source".into();
        assert!(intent.binding.check_source_current(&world).is_err());
    }

    #[test]
    fn model_one_canonical_assignment_has_server_pod_incarnation_and_exact_dataset() {
        let (mut world,uid,node,boot)=fixture();let req=request(&uid);
        let intent=reserve_in_scratch(&mut world,&req,&node,&boot).unwrap();
        let volume=world.storage_identities.lifecycle.get(&uid).unwrap();
        assert_eq!(volume.phase(),Phase::Attaching);assert_eq!(volume.epoch(),1);
        assert_eq!(volume.assignment().unwrap().writer_uid,*intent.binding.uid().as_uid());
        assert_eq!(volume.pod_writer(),Some(&intent.binding));
        intent.check_metadata_current(&world).unwrap();
        world.storage_identities.validate(&world.to_state()).unwrap();
        assert!(serde_json::to_value(volume).unwrap().get("pod_writer").is_some());
    }

    #[test]
    fn model_exact_operation_retry_is_metadata_only_and_never_mints_another_uid() {
        let (mut world,uid,node,boot)=fixture();let req=request(&uid);
        let first=reserve_in_scratch(&mut world,&req,&node,&boot).unwrap();
        let before=serde_json::to_vec(&world.to_state()).unwrap();
        let second=reserve_in_scratch(&mut world,&req,&node,&boot).unwrap();
        assert_eq!(first.binding,second.binding);assert_eq!(first.assignments,second.assignments);
        assert_eq!(before,serde_json::to_vec(&world.to_state()).unwrap());
        let other=request(&uid);assert!(reserve_in_scratch(&mut world,&other,&node,&boot).is_err());
        assert_eq!(before,serde_json::to_vec(&world.to_state()).unwrap());
    }

    #[test]
    fn model_stale_epoch_wrong_replica_and_wrong_retry_boot_refuse_without_new_owner() {
        let (mut world,uid,node,boot)=fixture();let mut req=request(&uid);
        let before=serde_json::to_vec(&world.to_state()).unwrap();
        req.expected_epochs.insert(uid.clone(),1);
        assert!(reserve_in_scratch(&mut world,&req,&node,&boot).is_err());
        assert_eq!(before,serde_json::to_vec(&world.to_state()).unwrap());
        req.expected_epochs.insert(uid.clone(),0);
        assert!(reserve_in_scratch(&mut world,&req,&Uid::new(),&boot).is_err());
        let intent=reserve_in_scratch(&mut world,&req,&node,&boot).unwrap();
        let wrong:BootId=serde_json::from_str("\"12345678-1234-4234-a234-123456789abd\"").unwrap();
        assert!(reserve_in_scratch(&mut world,&req,&node,&wrong).is_err());
        intent.check_metadata_current(&world).unwrap();
    }

    #[test]
    fn model_source_replacement_or_foreign_namespace_does_not_reuse_writer() {
        let (mut world,uid,node,boot)=fixture();let req=request(&uid);
        reserve_in_scratch(&mut world,&req,&node,&boot).unwrap();
        world.deployments.get_mut("a/db").unwrap().containers[0].image="changed:tag".into();
        assert!(reserve_in_scratch(&mut world,&req,&node,&boot).is_err());
        let mut wrong=request(&uid);wrong.namespace="default".into();
        assert!(reserve_in_scratch(&mut world,&wrong,&node,&boot).is_err());
    }

    #[test]
    fn raw_current_schema_and_plain_raft_refuse_old_writer_without_uid_backfill() {
        let (mut world,uid,node,boot)=fixture();let req=request(&uid);
        reserve_in_scratch(&mut world,&req,&node,&boot).unwrap();
        let state=world.to_state();let raw=crate::persist::encode(&state,&[]).unwrap();
        let mut envelope:serde_json::Value=serde_json::from_slice(&raw).unwrap();
        assert_eq!(envelope["schemaVersion"],9);
        let volumes=envelope["state"]["storage_identities"]["lifecycle"]["volumes"].as_object_mut().unwrap();
        volumes.get_mut(uid.as_str()).unwrap().as_object_mut().unwrap().remove("pod_writer");
        assert!(crate::persist::decode(&envelope.to_string()).err().unwrap().contains("no PodWriter UID backfill"));
        assert!(crate::raft_node::Sealing::Plain.unseal(&envelope["state"].to_string()).err().unwrap().contains("no PodWriter UID backfill"));
    }

    #[test]
    fn raw_epoch_history_requires_binding_even_after_assignment_is_cleared() {
        let (world,uid,_,_)=fixture();let mut raw=serde_json::to_value(world.to_state()).unwrap();
        let volume=&mut raw["storage_identities"]["lifecycle"]["volumes"][uid.as_str()];
        volume["epoch"]=1.into();volume["assignment"]=serde_json::Value::Null;
        assert!(reject_unbound_writer_history(&raw).is_err());
        volume_null_test(raw,uid);
    }
    fn volume_null_test(mut raw:serde_json::Value,uid:Uid) {
        raw["storage_identities"]["lifecycle"]["volumes"][uid.as_str()]["pod_writer"]=serde_json::Value::Null;
        assert!(reject_unbound_writer_history(&raw).is_err());
    }

    #[test]
    fn safe_epoch_zero_history_is_unchanged_and_does_not_fabricate_binding() {
        let (world,uid,_,_)=fixture();let state=world.to_state();
        let volume=serde_json::to_value(world.storage_identities.lifecycle.get(&uid).unwrap()).unwrap();
        assert!(volume.get("pod_writer").is_none());
        let bytes=crate::persist::encode(&state,&[]).unwrap();
        let decoded=crate::persist::decode(std::str::from_utf8(&bytes).unwrap()).unwrap();
        let plain=serde_json::to_string(&state).unwrap();
        crate::raft_node::Sealing::Plain.unseal(&plain).unwrap();
        let _=decoded;assert_eq!(crate::persist::SCHEMA_VERSION,9);
    }

    #[test]
    fn old_strict_volume_field_set_refuses_new_writer_history_not_silently_ignores_it() {
        let (mut world,uid,node,boot)=fixture();
        let before=serde_json::to_value(world.storage_identities.lifecycle.get(&uid).unwrap()).unwrap();
        crate::storage_lifecycle::model_decode_exact_cp3_volume(before).unwrap();
        reserve_in_scratch(&mut world,&request(&uid),&node,&boot).unwrap();
        let after=serde_json::to_value(world.storage_identities.lifecycle.get(&uid).unwrap()).unwrap();
        let error=crate::storage_lifecycle::model_decode_exact_cp3_volume(after).err().unwrap();
        assert!(error.contains("unknown field `pod_writer`"));
    }

    #[test]
    fn mutable_binding_cannot_change_within_existing_assignment_epoch() {
        let (mut world,uid,node,boot)=fixture();
        reserve_in_scratch(&mut world,&request(&uid),&node,&boot).unwrap();
        let old=world.storage_identities.lifecycle.clone();
        let mut raw=serde_json::to_value(&old).unwrap();
        raw["volumes"][uid.as_str()]["pod_writer"]["source_sha256"]="b".repeat(64).into();
        let changed:crate::storage_lifecycle::Registry=serde_json::from_value(raw).unwrap();
        assert!(old.validate_transition(&changed).is_err());
    }

    #[tokio::test]
    async fn cloned_model_world_never_enters_actual_store_reservation_producer() {
        let (world,uid,_,_)=fixture();let world=Arc::new(RwLock::new(world));
        assert!(reserve_local_pod_writer(&world,&request(&uid)).await.is_err());
        assert!(world.read().unwrap().storage_identities.lifecycle.get(&uid).unwrap().assignment().is_none());
    }
}

