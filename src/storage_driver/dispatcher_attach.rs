//! Attachment ownership is distinct from the finite node-global worker slot.
//! Only a genuine registered attach parent can create/enqueue a new owner.
//! No raw/serde constructor, caller World or JSON capability is accepted.
use super::*;
#[path="dispatcher_consumer_lifetime.rs"]
pub(crate) mod consumer_lifetime;
#[path="dispatcher_terminal.rs"]
pub(crate) mod terminal;
#[path="dispatcher_attach_inventory.rs"]
pub(crate) mod inventory;
pub(crate) use terminal::{ReservedTerminalResources,TerminalTicket,TerminalRetirementTicket,VerifiedTerminalDrain,RetiredTerminalLease};
use crate::storage_boot::BootId;
use crate::storage_lifecycle::{Phase,Volume,pod_attachment::{ExpectedAttachScope,AttachPhaseObservation}};
use crate::storage_lifecycle::pod_attachment::{AttachPhase,scope_digest};
use crate::storage_pod_writer::ManagedMountRef;
use super::super::native_runtime::mount::parent::{VerifiedAttachParent,AttachNativeStep};
use crate::storage_remote_protocol::attachment::AttachBoundary;
use super::super::ManagedMountProbe;
use std::sync::Mutex;

/// ACTUAL root book retains this independently of tickets/errors. The only
/// constructor requires the genuine accepted parent and roots before enqueue.
/// Neither a persisted Assignment nor a wire report can instantiate it.
pub(crate) struct AttachOwner {
    world:Arc<RwLock<DesiredWorld>>,
    scope:ExpectedAttachScope,
    deadline:Instant,
    cancelled:Arc<AtomicBool>,
    resources:Mutex<AttachResources>,
    // The IO probe lock is DISTINCT from pure admission/session state. Fresh
    // parent callbacks can inspect resources without recursively locking the
    // probe, and no World/book/session lock is held through kernel IO.
    probe:Mutex<ManagedMountProbe>,
    first_parent:Arc<VerifiedAttachParent>,
    dispatcher_busy:Arc<AtomicBool>,
    quarantine:Mutex<Option<Quarantine>>,
    // Actual Watch process/file-table origin, rooted before first production
    // of original descriptors. Never reconstructed at terminal time.
    watch_process:Arc<Mutex<super::super::replica::initialize::managed_mount::terminal::origin::WatchProcessPin>>,
}
struct AttachResources {
    initialization_slot:Option<Arc<super::distributed_init::ReleasedInitializationSlot>>,
    // Actual same-book FD contexts, rooted before capture/spawn. Known drain
    // retires only temporary duplicates; UNKNOWN retains every acquired FD.
    inventory_contexts:Vec<Arc<inventory::RootedOwnedPoolInventory>>,
    // SAME actual node cgroup FD lineage retained during normal attachment.
    // This is not a new grant or a reopened/scanned leaf for terminal work.
    terminal_cgroup:Option<Arc<JobCgroup>>,
    terminal_resources:Option<Arc<ReservedTerminalResources>>,
    terminal_parent:Option<Arc<super::super::native_runtime::mount::consumer::terminal::VerifiedTerminalNodeParent>>,
    // Dedicated per-volume kernel lease is NOT either node-global duplicate.
    // Acquired/rooted by the fixed dispatcher before any physical child.
    volume_lease:Option<File>,
    global:Option<RetainedNodeAdmission>,
    global_safety:Option<File>,
    quarantined:bool,
    unknown:bool,
    current_parent:Option<Arc<VerifiedAttachParent>>,
    current_native:Option<live::JobIdentity>,
    current_step:Option<AttachNativeStep>,
    completed:Vec<AttachPhaseObservation>,
    enqueued:bool,
    effective_deadline:Instant,
}
#[derive(Debug,PartialEq,Eq)]
enum AdmissionMode {Partial,PhysicalWork,MountedLifetime}
fn admission_mode(volume:bool,primary:bool,safety:bool)->AdmissionMode {
    match (volume,primary,safety){(true,true,true)=>AdmissionMode::PhysicalWork,
        (true,false,false)=>AdmissionMode::MountedLifetime,_=>AdmissionMode::Partial}
}
fn clip_deadline(original:Instant,prior:Instant,parent:Instant)->Instant {original.min(prior).min(parent)}
impl AttachOwner {
    pub(crate) fn original_deadline(&self)->Instant {self.deadline}
    /// Pure current source/group check; no FD reconstruction, READY or effect
    /// permission. Different committed rounds remain deliberately refused.
    pub(in crate::storage_driver) fn require_inventory_group_member(&self,current:&VerifiedAttachParent)->Result<(),String>{
        current.require_live()?;self.assert_actual_store(current.actual_store())?;
        let a=&self.scope;let b=current.scope();
        if self.cancelled.load(Ordering::Acquire)||Instant::now()>=self.effective_deadline()
            ||a.round_uid!=b.round_uid||a.pod_writer!=b.pod_writer||a.phase_node_uid!=b.phase_node_uid
            ||a.phase_boot!=b.phase_boot||a.issuer_node_uid!=b.issuer_node_uid||a.issuer_boot!=b.issuer_boot
            ||a.directory_sha256!=b.directory_sha256||a.issuer_revision.term!=b.issuer_revision.term
            ||a.issuer_revision.leader_raft_id!=b.issuer_revision.leader_raft_id
            ||a.issuer_revision.membership_sha256!=b.issuer_revision.membership_sha256{
            return Err("inventory member has another actual group/source/boot/epoch or expired owner".into());}
        {
            let state=self.resources.lock().map_err(|_|"actual inventory member poisoned")?;
            if state.unknown||state.quarantined||state.volume_lease.is_none()
                ||state.terminal_resources.is_some()||state.terminal_parent.is_some()
                ||a.owner.volume_uid!=b.owner.volume_uid&&state.enqueued{
                return Err("inventory member partial/UNKNOWN/draining/another physical job".into());}
        }
        let world=self.world.try_read().map_err(|_|"actual inventory source busy")?;
        let volume=world.storage_identities.lifecycle.get(&a.owner.volume_uid).ok_or("actual inventory volume absent")?;
        a.check_volume(volume)?;a.pod_writer.check_source_current(&world)
    }
    fn effective_deadline(&self)->Instant {
        let Ok(state)=self.resources.lock() else{return Instant::now();};
        let deadline=state.effective_deadline;let parent=state.current_parent.clone();drop(state);
        parent.map_or(deadline,|p|deadline.min(p.original_deadline()))
    }
    pub(in crate::storage_driver) fn require_registered_parent(&self,parent:&VerifiedAttachParent)->Result<(),String> {
        parent.require_live()?;
        if !std::ptr::eq(Arc::as_ptr(parent.actual_store()),Arc::as_ptr(&self.world))
            || self.cancelled.load(Ordering::Acquire)
            || Instant::now()>=self.deadline || !same_round(&self.scope,parent.scope()) {
            return Err("attach parent is not the same actual original retained round".into());
        }
        let state=self.resources.lock().map_err(|_|"actual attach owner poisoned")?;
        if state.unknown || Instant::now()>=state.effective_deadline
            || state.effective_deadline>self.deadline
            || state.current_parent.as_ref().is_none_or(|p|!std::ptr::eq(Arc::as_ptr(p),parent)) {
            return Err("not the exact root-retained current accepted phase parent".into());
        }Ok(())
    }
    pub(in crate::storage_driver) fn scope(&self)->&ExpectedAttachScope {&self.scope}
    pub(in crate::storage_driver) fn assert_actual_store(&self,world:&Arc<RwLock<DesiredWorld>>)->Result<(),String> {
        if !Arc::ptr_eq(&self.world,world) || !crate::raft_node::storage_remote_core::is_actual_world(world) {
            return Err("attach owner is not rooted in actual Raft store".into());
        }Ok(())
    }
    pub(in crate::storage_driver) fn mark_unknown(&self) {
        self.cancelled.store(true,Ordering::Release);
        self.resources.lock().unwrap_or_else(|e|e.into_inner()).unknown=true;
        // Never remove root book entry, close any lease, reset busy, demote,
        // unmount, manufacture a no-effect outcome, or retry after this latch.
    }
    fn invalidate_round(&self) {
        self.mark_unknown();
        let parent=self.resources.lock().unwrap_or_else(|p|p.into_inner()).current_parent.clone()
            .unwrap_or_else(||self.first_parent.clone());
        // Book quarantine calls only mark_unknown (the local latch), so this
        // cannot recursively re-enter parent/book invalidation.
        parent.retain_unknown();
    }
    fn compare_current_source(&self)->Result<(),String> {
        self.assert_actual_store(&self.world)?;
        if Instant::now()>=self.effective_deadline() || self.cancelled.load(Ordering::Acquire)
            || self.scope.phase_boot!=BootId::current()? {
            return Err("original attach round expired/cancelled/another boot; retain ownership".into());
        }
        let world=self.world.try_read().map_err(|_|"actual attach world busy")?;
        let volume=world.storage_identities.lifecycle.get(&self.scope.owner.volume_uid).ok_or("actual attach dataset absent")?;
        self.scope.check_volume(volume)?;
        self.scope.pod_writer.check_source_current(&world)
    }
    fn actual_current_boundary(&self)->Result<(),String> {
        self.compare_current_source()?;
        let (parent,identity)= {
            let state=self.resources.lock().map_err(|_|"actual attach state poisoned")?;
            (state.current_parent.clone().ok_or("actual phase parent absent")?,
             state.current_native.clone().ok_or("actual native lineage absent")?)
        };
        self.require_registered_parent(&parent)?;
        let boundary=VerifiedLocalBoundary::attachment_observation(&identity)?;
        parent.approve(&boundary,AttachBoundary::Identity,boundary.binding())?;
        self.compare_current_source()
    }
    pub(in crate::storage_driver) fn rooted_mount_witness(self:&Arc<Self>)->Result<RootedMountWitness,String> {
        self.assert_actual_store(&self.world)?;
        let state=self.resources.lock().map_err(|_|"actual mounted owner poisoned")?;
        if state.unknown || state.quarantined || admission_mode(state.volume_lease.is_some(),state.global.is_some(),state.global_safety.is_some())!=AdmissionMode::MountedLifetime
            || self.cancelled.load(Ordering::Acquire) {
            return Err("actual installed mount owner still global/partial/unknown".into());
        }
        drop(state);
        let probe=self.probe.lock().map_err(|_|"rooted mounted probe poisoned")?;
        let mounted=probe.installed()?;
        Ok(RootedMountWitness {owner:self.clone(),reference:self.scope.mount_ref.clone(),
            evidence_uid:mounted.evidence_uid().clone(),evidence_sha256:mounted.evidence_sha256().into(),
            filesystem_uuid:mounted.observation().filesystem_uuid.clone()})
    }
}

/// No Clone/serde/raw constructor. Only the actual supervisor may eventually
/// mint this after same original Child terminal, both bounded PIPE EOF, exact
/// cgroup/resource drain, strict diagnostic join and current parent boundary.
/// The producer below uses the actual original child/cgroup supervisor.
pub(crate) struct VerifiedAttachDrain {
    inventory:Option<Arc<inventory::RootedOwnedPoolInventory>>,
    owner:Arc<AttachOwner>,
    scope:ExpectedAttachScope,
    diagnostic:super::super::replica::initialize::managed_mount::phases::WorkerObservation,
    parent:Arc<VerifiedAttachParent>,
    identity:live::JobIdentity,
    step:AttachNativeStep,
    block_major:u32,
    block_minor:u32,
    block_bytes:u64,
    evidence_sha256:String,
    completion:VerifiedLocalBoundary,
}
impl VerifiedAttachDrain {
    pub(in crate::storage_driver) fn require_owned_inventory_drain(&self)->Result<(),String>{
        let context=self.inventory.as_ref().ok_or("not an actual profile7 drained native")?;
        if !context.is_retired(){return Err("profile7 duplicate roles were not retired by actual native drain".into());}
        if !std::ptr::eq(Arc::as_ptr(context.parent()),Arc::as_ptr(&self.parent))||context.step()!=self.step{
            return Err("profile7 drain/context parent or native substep differs".into());}Ok(())
    }
    pub(in crate::storage_driver) fn native_identity(&self)->&live::JobIdentity{&self.identity}
    pub(in crate::storage_driver) fn require_lineage_parent(&self,parent:&VerifiedAttachParent)->Result<(),String>{
        if !std::ptr::eq(Arc::as_ptr(&self.parent),parent)||self.scope!=*parent.scope(){
            return Err("inventory origin is not SAME actual drain parent/scope".into());}Ok(())
    }
    pub(in crate::storage_driver) fn require_same_inventory_owner(&self,current:&VerifiedAttachDrain)->Result<(),String>{
        if !Arc::ptr_eq(&self.owner,&current.owner)||!same_round(&self.scope,&current.scope){
            return Err("inventory provisional/final drain changed actual original owner/round".into());}Ok(())
    }
    pub(in crate::storage_driver) fn require_completed_inventory_origin(&self)->Result<(),String>{
        self.parent.require_completed_inventory_origin(self)
    }
    /// Pure current original-parent/resource check plus actual Watch origin
    /// observation only; NEVER a replacement for a fresh Core/IO grant.
    pub(in crate::storage_driver) fn require_current_origin_without_io_grant(&self)->Result<(),String>{
        self.require_parent(&self.parent)?;
        if Instant::now()>=self.deadline(){return Err("original provisional observation deadline expired".into());}
        self.require_original_watch_files()
    }
    pub(in crate::storage_driver) fn original_watch_process(&self)->Arc<Mutex<super::super::replica::initialize::managed_mount::terminal::origin::WatchProcessPin>>{
        self.owner.watch_process.clone()
    }
    pub(in crate::storage_driver) fn require_original_watch_files(&self)->Result<(),String>{
        self.owner.watch_process.lock().map_err(|_|"original Watch process source poisoned")?.verify_serving_thread(&self.scope.phase_boot)
    }
    pub(crate) fn scope(&self)->&ExpectedAttachScope {&self.scope}
    pub(in crate::storage_driver) fn deadline(&self)->Instant {self.owner.effective_deadline()}
    pub(crate) fn observation(&self)->Result<&AttachPhaseObservation,String> {
        self.diagnostic.phase.as_ref().ok_or("publication anchor is not a mounted/replica observation".into())
    }
    pub(in crate::storage_driver) fn anchor_observation(&self)->Result<&super::super::replica::initialize::managed_mount::anchor::AnchorMountObservation,String> {
        if self.step!=AttachNativeStep::PublicationAnchor {return Err("not the actual drained anchor substep".into());}
        self.diagnostic.anchor.as_ref().ok_or("actual supervised anchor observation absent".into())
    }
    pub(in crate::storage_driver) fn step(&self)->AttachNativeStep {self.step}
    pub(crate) fn completion_sha256(&self)->&str {self.completion.binding()}
    pub(in crate::storage_driver) fn require_parent(&self,parent:&VerifiedAttachParent)->Result<(),String> {
        self.owner.require_registered_parent(parent)?;
        if !std::ptr::eq(Arc::as_ptr(&self.parent),parent) || self.scope!=*parent.scope()
            || self.identity.node_uid!=self.scope.phase_node_uid || self.identity.boot_id!=self.scope.phase_boot.as_str()
            || !valid_hash(self.completion.binding()) || !valid_hash(&self.evidence_sha256) {
            return Err("actual drain is not this exact parent/native/scope".into());
        }
        let state=self.owner.resources.lock().map_err(|_|"actual drain owner poisoned")?;
        if state.current_native.as_ref()!=Some(&self.identity) || state.current_step!=Some(self.step) {
            return Err("actual drain belongs to a prior native substep".into());
        }Ok(())
    }
    pub(in crate::storage_driver) fn block_identity(&self)->(u32,u32,u64) {(self.block_major,self.block_minor,self.block_bytes)}
    pub(in crate::storage_driver) fn evidence_sha256(&self)->&str {&self.evidence_sha256}
    pub(in crate::storage_driver) fn checkpoint(&self)->Result<(),String> {
        self.require_parent(&self.parent)?;self.owner.actual_current_boundary()?;self.require_parent(&self.parent)
    }
}

/// Inherited helper capability. No serde/Clone/default/raw/bool constructor.
/// The only producer checks real capsule-v5 + inherited root FD/cgroup mode.
pub(in crate::storage_driver) struct VerifiedAttachPhase {
    identity:live::JobIdentity,scope:ExpectedAttachScope,step:AttachNativeStep,deadline:Instant,
    publication:Option<super::super::replica::initialize::managed_mount::PublicationRef>,
    existing_anchor:Option<super::super::replica::initialize::managed_mount::anchor::OwnedAnchorReference>,
    owned_inventory:Option<inventory::InheritedOwnedPoolInventory>,
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachPayload {pool:super::super::Config,scope:ExpectedAttachScope,step:AttachNativeStep,
    publication:Option<super::super::replica::initialize::managed_mount::PublicationRef>,
    existing_anchor:Option<super::super::replica::initialize::managed_mount::anchor::OwnedAnchorReference>}
pub(super) fn valid_capsule(capsule:&Capsule)->bool {
    let Ok(payload)=serde_json::from_value::<AttachPayload>(capsule.payload.config.clone()) else{return false;};
    capsule.version==5 && capsule.payload.extended==Some(ExtendedJob::AttachEpochOne)
        && payload.pool.validate().is_ok() && payload.scope.validate().is_ok()
        && step_allowed(payload.scope.phase,payload.step)
        && (payload.publication.is_some()==(payload.step==AttachNativeStep::FilesystemMount
            || payload.scope.phase==AttachPhase::ObserveMounted))
        && (payload.existing_anchor.is_none() || payload.step==AttachNativeStep::PublicationAnchor)
        && payload.pool.node_uid==payload.scope.phase_node_uid
        && capsule.identity.node_uid==payload.scope.phase_node_uid
        && capsule.identity.boot_id==payload.scope.phase_boot.as_str()
        && capsule.identity.volume_uid==payload.scope.owner.volume_uid
        && &capsule.identity.operation_uid==payload.scope.mount_ref.operation_uid()
        && capsule.payload.dataset_uid.as_ref()==Some(&payload.scope.generation.uid)
        && capsule.payload.projection.is_empty() && capsule.payload.initialization.is_none()
        && capsule.payload.worker_remaining_ms.is_some_and(|n|n>0 && n<=payload.scope.remaining_budget_ms)
        && capsule.payload.remote_binding.as_deref()==Some(scope_digest(&payload.scope).unwrap_or_default().as_str())
}
fn step_allowed(phase:AttachPhase,step:AttachNativeStep)->bool {
    if phase==AttachPhase::Mount {matches!(step,AttachNativeStep::PublicationAnchor|AttachNativeStep::FilesystemMount)}
    else {step==AttachNativeStep::Single}
}
impl VerifiedAttachPhase {
    pub(in crate::storage_driver) fn from_inherited(authority:&VerifiedNativeAuthority)->Result<(Self,super::super::Config),String> {
        if !valid_capsule(&authority.capsule){return Err("not an exact inherited v5 attach worker".into());}
        live::require_identity(&authority.capsule.identity)?;
        let payload:AttachPayload=serde_json::from_value(authority.capsule.payload.config.clone()).map_err(|_|"invalid private attach payload")?;
        let remaining=authority.capsule.payload.worker_remaining_ms.ok_or("original attach budget absent")?;
        let deadline=Instant::now().checked_add(Duration::from_millis(remaining)).ok_or("attach budget overflow")?;
        Ok((Self {identity:authority.capsule.identity.clone(),scope:payload.scope,step:payload.step,
            deadline,publication:payload.publication,existing_anchor:payload.existing_anchor,owned_inventory:None},payload.pool))
    }
    pub(in crate::storage_driver) fn scope(&self)->&ExpectedAttachScope {&self.scope}
    pub(in crate::storage_driver) fn owned_inventory(&self)->Option<&inventory::InheritedOwnedPoolInventory>{self.owned_inventory.as_ref()}
    pub(in crate::storage_driver) fn step(&self)->AttachNativeStep {self.step}
    pub(in crate::storage_driver) fn deadline(&self)->Instant {self.deadline}
    pub(in crate::storage_driver) fn publication(&self)->Option<&super::super::replica::initialize::managed_mount::PublicationRef> {self.publication.as_ref()}
    pub(in crate::storage_driver) fn existing_anchor(&self)->Option<&super::super::replica::initialize::managed_mount::anchor::OwnedAnchorReference> {self.existing_anchor.as_ref()}
    pub(in crate::storage_driver) fn checkpoint(&self)->Result<(),String> {
        if let Some(inventory)=&self.owned_inventory{inventory.require_kernel_current()?;}
        if Instant::now()>=self.deadline || BootId::current()?!=self.scope.phase_boot {return Err("original attach worker budget/boot expired; UNKNOWN".into());}
        live::require_identity(&self.identity)?;
        if let Some(inventory)=&self.owned_inventory{inventory.require_kernel_current()?;}
        if Instant::now()>=self.deadline{return Err("attach boundary returned after original deadline".into());}Ok(())
    }
    pub(in crate::storage_driver) fn before_read(&self,offset:u64,length:u64)->Result<(),String> {
        if let Some(inventory)=&self.owned_inventory{inventory.require_kernel_current()?;}
        if Instant::now()>=self.deadline || BootId::current()?!=self.scope.phase_boot {return Err("original direct-read budget/boot expired".into());}
        live::attachment_channel_identity(&self.identity)?;
        let bytes=self.scope.generation.virgin_replicas[0].exposed_bytes;
        if !read_range_allowed(self.scope.phase,self.step,bytes,offset,length) {return Err("attach read outside exact first-epoch extent".into());}
        live::before_attachment_read(&self.scope,offset,length)?;
        if Instant::now()>=self.deadline {return Err("direct-read grant returned after original budget".into());}
        live::attachment_channel_identity(&self.identity)?;
        if let Some(inventory)=&self.owned_inventory{inventory.require_kernel_current()?;}Ok(())
    }
    pub(in crate::storage_driver) fn before_anchor(&self,operation:&str,identity:Option<(u64,u64,u64)>)->Result<(),String> {
        if self.scope.phase!=AttachPhase::Mount || self.step!=AttachNativeStep::PublicationAnchor {return Err("not the closed anchor substep".into());}
        self.checkpoint()?;
        live::before_attachment_anchor(&self.scope,operation,identity)?;self.checkpoint()
    }
    pub(in crate::storage_driver) fn before_mount(&self,operation:&str,detail:&impl Serialize)->Result<(),String> {
        if self.scope.phase!=AttachPhase::Mount || self.step!=AttachNativeStep::FilesystemMount {return Err("not the closed filesystem substep".into());}
        self.checkpoint()?;live::before_attachment_mount(&self.scope,operation,detail)?;self.checkpoint()
    }
}
fn read_range_allowed(phase:AttachPhase,step:AttachNativeStep,bytes:u64,offset:u64,length:u64)->bool {
    phase==AttachPhase::ObserveSynchronized && step==AttachNativeStep::Single && bytes>0 && bytes%4096==0
        && offset%4096==0 && length>0 && length<=1024*1024 && length%4096==0
        && offset.checked_add(length).is_some_and(|n|n<=bytes)
}
fn same_round(a:&ExpectedAttachScope,b:&ExpectedAttachScope)->bool {
    a.owner==b.owner && a.mount_ref==b.mount_ref && a.pod_writer==b.pod_writer && a.generation==b.generation
        && a.initial_lineage==b.initial_lineage && a.replicas==b.replicas && a.round_uid==b.round_uid
        && a.phase_node_uid==b.phase_node_uid && a.phase_boot==b.phase_boot && a.issuer_node_uid==b.issuer_node_uid
        && a.issuer_boot==b.issuer_boot && a.directory_sha256==b.directory_sha256
        && a.issuer_revision.term==b.issuer_revision.term && a.issuer_revision.leader_raft_id==b.issuer_revision.leader_raft_id
        && a.issuer_revision.membership_sha256==b.issuer_revision.membership_sha256
}

/// A borrowed metadata witness from the live root book, not a transferable
/// mount/launch capability. Holding this merely keeps the actual owner alive.
pub(crate) struct RootedMountWitness {
    owner:Arc<AttachOwner>,
    reference:ManagedMountRef,
    evidence_uid:Uid,
    evidence_sha256:String,
    filesystem_uuid:String,
}
impl RootedMountWitness {
    pub(crate) fn original_deadline(&self)->Instant {self.owner.effective_deadline()}
    /// Pure commit-scratch liveness. No boot read, filesystem IO or network
    /// operation occurs under the caller's actual World/book/session lock.
    pub(crate) fn require_commit_live(&self)->Result<(),String> {
        if Instant::now()>=self.owner.effective_deadline() || self.owner.cancelled.load(Ordering::Acquire) {
            return Err("original mounted round expired/cancelled; retain owner".into());
        }
        self.require_same_root(&self.owner)
    }
    /// Called on the existing fixed IO actor OUTSIDE World/book/session locks.
    /// This is a new kernel observation, not fresh quorum/action authority.
    pub(crate) fn reobserve_for_commit(&self,existing_deadline:Instant)->Result<(),String> {
        self.require_commit_live()?;
        if existing_deadline>self.owner.effective_deadline() || Instant::now()>=existing_deadline {
            return Err("mounted confirmation cannot renew the original round".into());
        }
        let result=(|| {
            let probe=self.owner.probe.lock().map_err(|_|"mounted observation owner poisoned")?;
            probe.installed()?.reobserve(existing_deadline)
        })();
        let result=result.and_then(|()|self.require_commit_live());
        if result.is_err() {self.owner.invalidate_round();}result
    }
    pub(crate) fn retain_unknown(&self) {self.owner.invalidate_round();}
    pub(crate) fn mounted_scope(&self)->Result<ExpectedAttachScope,String> {
        self.require_commit_live()?;
        let probe=self.owner.probe.lock().map_err(|_|"mounted scope owner poisoned")?;
        Ok(probe.installed()?.scope().clone())
    }
    pub(crate) fn reference(&self)->&ManagedMountRef {&self.reference}
    pub(crate) fn evidence_uid(&self)->&Uid {&self.evidence_uid}
    pub(crate) fn evidence_sha256(&self)->&str {&self.evidence_sha256}
    pub(crate) fn filesystem_uuid(&self)->&str {&self.filesystem_uuid}
    pub(crate) fn require_same_root(&self,owner:&Arc<AttachOwner>)->Result<(),String> {
        if !Arc::ptr_eq(&self.owner,owner) {return Err("mounted witness is not the actual root book owner".into());}
        let state=owner.resources.lock().map_err(|_|"rooted mount owner poisoned")?;
        if state.unknown || state.quarantined || admission_mode(state.volume_lease.is_some(),state.global.is_some(),state.global_safety.is_some())!=AdmissionMode::MountedLifetime
            || owner.cancelled.load(Ordering::Acquire) {
            return Err("rooted mounted lifetime changed/partial/UNKNOWN".into());
        }
        drop(state);
        let probe=owner.probe.lock().map_err(|_|"rooted mounted probe poisoned")?;
        let mounted=probe.installed()?;
        if mounted.scope().mount_ref!=self.reference || mounted.evidence_uid()!=&self.evidence_uid
            || mounted.evidence_sha256()!=self.evidence_sha256 {
            return Err("rooted physical mount evidence changed".into());
        }Ok(())
    }
    pub(crate) fn check_current_volume(&self,volume:&Volume)->Result<(),String> {
        self.require_same_root(&self.owner)?;
        self.reference.check_metadata(volume)?;
        if volume.phase()==Phase::Attaching {
            self.owner.scope.initial_lineage.check_current_first_attach(volume)?;
        } else if volume.phase()==Phase::Attached {
            crate::storage_lifecycle::pod_attachment::check_mounted_receipt_data(volume,
                &self.evidence_uid,&self.evidence_sha256)?;
        } else {return Err("actual mounted witness has another lifecycle phase".into());}
        Ok(())
    }
}

/// Original queue proof is private and can only be returned by an actual
/// failed try_send before receive. No current code manufactures this token.
struct NeverSubmitted { _private:() }
pub(crate) struct AttachTicket {receiver:mpsc::Receiver<Result<AttachPhaseObservation,String>>,owner:Arc<AttachOwner>}
impl AttachTicket {
    pub(crate) fn try_result(&self)->Result<Option<AttachPhaseObservation>,String> {
        match self.receiver.try_recv(){Ok(Ok(v))=>Ok(Some(v)),Ok(Err(e))=>Err(e),Err(mpsc::TryRecvError::Empty)=>Ok(None),
            Err(_)=>{self.owner.invalidate_round();Err("actual attachment worker result lost; owner retained UNKNOWN".into())}}
    }
    pub(crate) fn quarantine(&self){self.owner.invalidate_round();}
}
pub(crate) enum RetainedAttachError {
    Unavailable(String),
    NeverSubmitted(String),
    // Ticket/error is NOT the owner. Unknown payload is DATA only;
    // the actual runtime registry must retain both admissions independently.
    Unknown(String),
}
impl Dispatcher {
    /// No filesystem/network IO or effects here. The genuine parent was made
    /// only by actual issuer/receiver registration and the SAME actual book
    /// holds this owner before any queue/lease/physical effect can begin.
    pub(crate) fn begin_managed_attachment(&self,parent:Arc<VerifiedAttachParent>)
        ->Result<Arc<AttachOwner>,RetainedAttachError> {
        let make=||->Result<Arc<AttachOwner>,String>{
            parent.require_live()?;parent.scope().validate()?;
            let world=parent.actual_store().clone();
            if !crate::raft_node::storage_remote_core::is_actual_world(&world)
                || parent.scope().phase!=AttachPhase::ActivateReplica || Instant::now()>=parent.original_deadline(){
                return Err("attachment must begin from actual registered first replica phase".into());
            }
            let owner=Arc::new(AttachOwner {world,scope:parent.scope().clone(),deadline:parent.original_deadline(),
                cancelled:Arc::new(AtomicBool::new(false)),probe:Mutex::new(ManagedMountProbe::empty_before_effect()),
                first_parent:parent.clone(),dispatcher_busy:self.busy.clone(),quarantine:Mutex::new(None),resources:Mutex::new(AttachResources {volume_lease:None,global:None,
                    global_safety:None,quarantined:false,unknown:false,current_parent:None,current_native:None,current_step:None,
                    completed:Vec::new(),enqueued:false,effective_deadline:parent.original_deadline(),
                    terminal_cgroup:None,terminal_resources:None,terminal_parent:None,inventory_contexts:Vec::new(),initialization_slot:None}),
                watch_process:Arc::new(Mutex::new(super::super::replica::initialize::managed_mount::terminal::origin::WatchProcessPin::empty()))});
            parent.root_book().retain_before_enqueue(owner.clone())?;Ok(owner)
        };make().map_err(RetainedAttachError::Unavailable)
    }
    pub(crate) fn submit_attach_phase(&self,owner:Arc<AttachOwner>,parent:Arc<VerifiedAttachParent>)
        ->Result<AttachTicket,RetainedAttachError> {
        let mut state=owner.resources.lock().map_err(|_|RetainedAttachError::Unknown("actual owner poisoned".into()))?;
        if !Arc::ptr_eq(&owner.dispatcher_busy,&self.busy) || state.unknown || state.enqueued || owner.cancelled.load(Ordering::Acquire)
            || !same_round(&owner.scope,parent.scope())
            || parent.require_live().is_err() || expected_next(&owner.scope,&state.completed)!=Some(parent.scope().phase) {
            return Err(RetainedAttachError::Unavailable("not the next same actual original attach phase".into()));
        }
        state.effective_deadline=clip_deadline(owner.deadline,state.effective_deadline,parent.original_deadline());
        if Instant::now()>=state.effective_deadline {return Err(RetainedAttachError::Unavailable("original attach round expired; no renewal".into()));}
        if state.global.is_none(){
            if self.busy.compare_exchange(false,true,Ordering::AcqRel,Ordering::Acquire).is_err(){
                return Err(RetainedAttachError::NeverSubmitted("node slot busy; original phase was never enqueued".into()));
            }
            state.global=Some(RetainedNodeAdmission {lease:None,busy:self.busy.clone(),release_on_drop:false});
        }
        state.enqueued=true;state.current_parent=Some(parent.clone());state.current_native=None;state.current_step=None;
        let (send,receive)=mpsc::sync_channel(1);drop(state);
        match self.queue.try_send(WorkItem::Attachment(AttachmentWork {owner:owner.clone(),parent,result:send})) {
            Ok(())=>Ok(AttachTicket {receiver:receive,owner}),
            Err(mpsc::TrySendError::Full(work))|Err(mpsc::TrySendError::Disconnected(work))=>{
                // The ACTUAL failed send returns the original move-only Work;
                // no receiver can have observed it. This is not a timeout or
                // an inferred zero-effect result after submission.
                drop(work);owner.release_never_submitted(NeverSubmitted {_private:()})
                    .map_err(RetainedAttachError::Unknown)?;
                Err(RetainedAttachError::NeverSubmitted("exact queue send failed before receive; no actor started".into()))
            }
        }
    }
}
fn expected_next(scope:&ExpectedAttachScope,done:&[AttachPhaseObservation])->Option<AttachPhase> {
    use AttachPhase::*;
    match done.last().map(|o|o.phase) {
        None=>Some(ActivateReplica),Some(ActivateReplica)=>Some(ObserveSynchronized),
        Some(ObserveSynchronized) if scope.mount_ref.node_uid()==&scope.phase_node_uid=>Some(PromoteTarget),
        Some(PromoteTarget)=>Some(Mount),Some(Mount)=>Some(ObserveMounted),_=>None,
    }
}
impl AttachOwner {
    fn release_never_submitted(&self,_proof:NeverSubmitted)->Result<(),String> {
        let mut state=self.resources.lock().map_err(|_|"never-submitted owner poisoned")?;
        if state.current_native.is_some() || state.global_safety.is_some() || state.quarantined
            || state.global.as_ref().is_some_and(|g|g.lease.is_some()) {
            self.cancelled.store(true,Ordering::Release);state.unknown=true;
            drop(state);self.invalidate_round();
            return Err("cannot prove no actor/effect after enqueue failure; retain".into());
        }
        if let Some(global)=state.global.take(){global.busy.store(false,Ordering::Release);drop(global);}
        state.enqueued=false;state.current_parent=None;Ok(())
    }
}
pub(super) struct AttachmentWork {
    owner:Arc<AttachOwner>,parent:Arc<VerifiedAttachParent>,result:mpsc::SyncSender<Result<AttachPhaseObservation,String>>,
}
pub(super) fn run_work(config:&Config,work:&mut AttachmentWork) {
    let result=(|| {
        work.owner.require_registered_parent(&work.parent)?;
        let agent=NativeAgent::from_attach_parent(&work.parent)?;
        let steps=if work.parent.scope().phase==AttachPhase::Mount {
            vec![AttachNativeStep::PublicationAnchor,AttachNativeStep::FilesystemMount]
        }else{vec![AttachNativeStep::Single]};
        let mut final_observation=None;
        for step in steps {
            if step==AttachNativeStep::PublicationAnchor {
                work.owner.probe.lock().map_err(|_|"rooted publication probe poisoned")?.observe_anchor_before_effect(work.parent.scope(),work.owner.effective_deadline())?;
            }
            let drain=Arc::new(inventory::launch_owned(config,work,&agent,step)?);
            if step==AttachNativeStep::PublicationAnchor {
                work.owner.probe.lock().map_err(|_|"rooted publication probe poisoned")?.prepare_publication_after_anchor(&drain)?;
            }else{
                if step==AttachNativeStep::FilesystemMount {
                    // Fresh boundary on SAME original parent, with no probe
                    // guard across authorization. Capture original FDs BEFORE
                    // Complete/ticket progression, then fresh post-observation.
                    drain.checkpoint()?;
                    {
                        let mut probe=work.owner.probe.lock().map_err(|_|"actual provisional capture probe poisoned")?;
                        probe.capture_inventory_after_filesystem_mount(drain.clone())?;
                    }
                    drain.checkpoint()?;
                }
                let observation=drain.observation()?.clone();
                if work.parent.scope().phase==AttachPhase::ObserveMounted {
                    drain.checkpoint()?;
                    {
                        let mut probe=work.owner.probe.lock().map_err(|_|"actual final mounted probe poisoned")?;
                        probe.install_after_actual_drain(&drain)?;
                    }
                    drain.checkpoint()?;
                }
                final_observation=Some(observation);
            }
            work.parent.complete(&drain,&drain.completion)?;
        }
        let observation=final_observation.ok_or("actual full phase observation absent")?;
        work.parent.require_live()?;work.owner.compare_current_source()?;
        if observation.phase==AttachPhase::ObserveMounted {
            let probe=work.owner.probe.lock().map_err(|_|"actual installed Watch owner poisoned")?;
            if probe.installed()?.scope()!=work.parent.scope() {
                return Err("actual installed mount is not the same final accepted scope".into());
            }
        }
        let release=observation.phase==AttachPhase::ObserveMounted
            || observation.phase==AttachPhase::ObserveSynchronized && work.owner.scope.mount_ref.node_uid()!=&work.owner.scope.phase_node_uid;
        let mut state=work.owner.resources.lock().map_err(|_|"actual phase completion state poisoned")?;
        if state.unknown || state.quarantined || !state.enqueued || Instant::now()>=state.effective_deadline
            || work.owner.cancelled.load(Ordering::Acquire) || state.global.as_ref().is_none_or(|g|g.lease.is_none())
            || state.global_safety.is_none() || state.volume_lease.is_none() {
            return Err("actual final owner changed/expired/partial; BOTH global references retained".into());
        }
        work.parent.require_live()?;
        if Instant::now()>=state.effective_deadline.min(work.parent.original_deadline()) {
            return Err("original accepted round expired at final admission handoff; retain BOTH references".into());
        }
        state.completed.push(observation.clone());state.enqueued=false;
        if release {
            // For the writer, actual Watch FD ownership was installed above.
            // Followers keep their independent per-volume lease+online exact
            // Secondary owner, never a fake mounted witness. UNKNOWN earlier
            // cannot reach this infallible final admission handoff.
            let primary=state.global.take();let safety=state.global_safety.take();
            let busy=primary.as_ref().unwrap().busy.clone();drop(primary);drop(safety);busy.store(false,Ordering::Release);
        }
        Ok(observation)
    })();
    if result.is_err(){work.owner.mark_unknown();work.parent.retain_unknown();}
    let _=work.result.try_send(result);
    // Caller/ticket loss cannot drop the owner/book or this actual quarantine.
    // No replacement worker, retry, cleanup, deadline release or PID adoption.
    loop {
        let mut held=work.owner.quarantine.lock().unwrap_or_else(|e|e.into_inner());
        let Some(q)=held.as_mut() else {break;};
        if let Some(child)=q.child.as_mut(){if matches!(child.try_wait(),Ok(Some(_))){q.child=None;}}
        let drained=q.child.is_none() && matches!(q.cgroup.populated(),Ok(false));drop(held);
        if drained {break;}std::thread::sleep(Duration::from_millis(50));
    }
}
fn native_kind(request:&live::Request,identity:&live::JobIdentity)->Option<AttachBoundary> {
    if request.version!=1 || request.sequence==0 || &request.identity!=identity || !valid_hash(&request.detail_sha256){return None;}
    Some(match request.boundary.as_str(){
        "helper-start" if request.detail_sha256==hash(b"native-first-attachment-v5")=>AttachBoundary::Start,
        "identity-check"=>AttachBoundary::Identity,"fixed-program"=>AttachBoundary::Program,
        "attachment-read"=>AttachBoundary::Read,"attachment-anchor-bind"=>AttachBoundary::AnchorBind,
        "attachment-anchor-private"=>AttachBoundary::AnchorPrivate,"attachment-mount-ext4"=>AttachBoundary::MountExt4,
        "attachment-make-private"=>AttachBoundary::MakePrivate,_=>return None,
    })
}
pub(super) fn diagnostic_matches(raw:&[u8],identity:&live::JobIdentity,scope:&ExpectedAttachScope,step:AttachNativeStep)->bool {
    let Ok(value)=serde_json::from_slice::<super::super::replica::initialize::managed_mount::phases::WorkerObservation>(raw)else{return false;};
    value.validate(scope,step).is_ok() && identity.node_uid==scope.phase_node_uid
        && identity.boot_id==scope.phase_boot.as_str() && identity.volume_uid==scope.owner.volume_uid
        && &identity.operation_uid==scope.mount_ref.operation_uid()
}
fn launch(config:&Config,work:&AttachmentWork,agent:&NativeAgent,step:AttachNativeStep)->Result<VerifiedAttachDrain,String> {
    work.owner.require_registered_parent(&work.parent)?;
    if !cfg!(target_os="linux") || unsafe{libc::geteuid()}!=0{return Err("physical attachment requires Linux root".into());}
    work.owner.watch_process.lock().map_err(|_|"actual Watch process origin poisoned")?
        .capture_before_production(&work.parent.scope().phase_boot)?;
    let scope=work.parent.scope().clone();let (pool,plan)=agent.attachment_parts(&scope)?;
    if config.node_uid!=scope.phase_node_uid {return Err("actual dispatcher node differs before any journal effect".into());}
    let path=config.journal_root.join(config.node_uid.as_str());let dir=Dir::open(&path,true)?;
    if dir.bounded_entries(512)?.iter().filter(|n|n.starts_with("attempt-")).count()>=128 {
        return Err("128 immutable attempts retained; no attach admission".into());
    }
    {
        let mut state=work.owner.resources.lock().map_err(|_|"actual global lease state poisoned")?;
        if state.global.as_ref().ok_or("actual admission absent")?.lease.is_none(){
            let lease=dir.lock()?;state.global.as_mut().unwrap().lease=Some(lease);
            let safety=state.global.as_ref().unwrap().lease.as_ref().unwrap().try_clone().map_err(|_|"actual global lease safety duplicate failed")?;
            state.global_safety=Some(safety);
        }
        if state.volume_lease.is_none(){
            let volume=Dir::open(&path.join(format!("mount-{}",scope.owner.volume_uid.as_str())),true)?;
            state.volume_lease=Some(volume.lock()?);
        }
    }
    let lease=work.owner.resources.lock().map_err(|_|"actual lease state poisoned")?.global.as_ref()
        .and_then(|g|g.lease.as_ref()).ok_or("original global lease absent")?.try_clone().map_err(|_|"cannot inherit actual global lease")?;
    let cgroup=JobCgroup::open(&config.delegated_cgroup_root,config.node_uid.as_str())?;
    let identity_pair=cgroup.identity()?;
    let original_cgroup={work.owner.resources.lock().map_err(|_|"original cgroup provenance owner poisoned")?.terminal_cgroup.clone()};
    if let Some(original)=original_cgroup {
        if original.identity()?!=identity_pair{return Err("same node cgroup incarnation changed; no terminal adoption".into());}
    }else{
        let original=Arc::new(cgroup.try_clone()?);
        let mut state=work.owner.resources.lock().map_err(|_|"original cgroup provenance owner poisoned")?;
        if state.terminal_cgroup.is_some(){return Err("original cgroup provenance raced; no replacement".into());}
        state.terminal_cgroup=Some(original);
    }
    if cgroup.populated()?{return Err("actual attachment cgroup not empty; no new helper".into());}
    cgroup.prune_empty_command_scopes()?;
    let binding=CgroupBinding {version:1,node_uid:config.node_uid.clone(),boot_id:scope.phase_boot.as_str().into(),device:identity_pair.0,inode:identity_pair.1};
    match dir.read("cgroup-binding.json")? {
        Some(raw)=>{let old:CgroupBinding=serde_json::from_slice(&raw).map_err(|_|"actual cgroup binding corrupt")?;
            if old.version!=1 || old.node_uid!=binding.node_uid || old.boot_id!=binding.boot_id || old.device!=binding.device || old.inode!=binding.inode {
                return Err("actual cgroup binding differs; no rewrite/adoption".into());
            }},
        None=>dir.write_new("cgroup-binding.json",&serde_json::to_vec(&binding).map_err(|_|"cgroup binding encoding")?)?,
    }
    if let Some(raw)=dir.read("current.json")? {
        let prior=load_record(&raw)?;
        if prior.state!=State::Complete || prior.identity.node_uid!=config.node_uid || prior.identity.boot_id!=scope.phase_boot.as_str() {
            return Err("predecessor is not actual same-boot drained Complete; no reset/adoption".into());
        }
    }
    let deadline=work.owner.effective_deadline();
    let remaining=deadline.saturating_duration_since(Instant::now()).min(config.deadline);
    let remaining_ms=u64::try_from(remaining.as_millis()).map_err(|_|"attach remaining overflow")?;
    if remaining_ms==0 || remaining_ms>scope.remaining_budget_ms{return Err("original registered remaining budget invalid/expired".into());}
    let publication=if step==AttachNativeStep::FilesystemMount || scope.phase==AttachPhase::ObserveMounted {
        Some(work.owner.probe.lock().map_err(|_|"publication owner poisoned")?.publication()?)
    }else{None};
    let existing_anchor=if step==AttachNativeStep::PublicationAnchor {
        work.owner.probe.lock().map_err(|_|"rooted anchor owner poisoned")?.existing_anchor_reference(&scope,deadline)?
    }else{None};
    let payload=Payload {config:serde_json::to_value(AttachPayload {pool,scope:scope.clone(),step,publication,existing_anchor}).map_err(|_|"attach payload encoding")?,
        plan,projection:Vec::new(),extended:Some(ExtendedJob::AttachEpochOne),dataset_uid:Some(scope.generation.uid.clone()),
        remote_binding:Some(scope_digest(&scope)?),initialization:None,worker_remaining_ms:Some(remaining_ms)};
    let payload_sha256=hash(&serde_json::to_vec(&payload).map_err(|_|"attach payload hash")?);
    let identity=live::JobIdentity {node_uid:config.node_uid.clone(),boot_id:scope.phase_boot.as_str().into(),volume_uid:scope.owner.volume_uid.clone(),
        operation_uid:scope.mount_ref.operation_uid().clone(),attempt_uid:if step==AttachNativeStep::Single {scope.phase_job_uid.clone()}else{Uid::new()},binding_sha256:hash(&serde_json::to_vec(&(
            "actual-first-attach-v5",&scope,step,&payload_sha256,&config.helper_sha256,&config.budget)).map_err(|_|"attach identity encoding")?)};
    let start=cgroup.enforce_budget(&config.budget)?;
    let capsule=Capsule {version:5,identity:identity.clone(),payload,budget:config.budget.clone()};
    if !valid_capsule(&capsule){return Err("invalid exact v5 capsule before any child launch".into());}
    let bytes=serde_json::to_vec(&capsule).map_err(|_|"attach capsule encoding")?;
    if bytes.len() as u64>CAPSULE_LIMIT{return Err("attach capsule exceeds unchanged bound".into());}
    let filename=format!("capsule-{}.json",identity.attempt_uid.as_str());dir.write_new(&filename,&bytes)?;
    let capsule_file=open_private(&path.join(filename))?;
    let mut record=Record {version:5,identity:identity.clone(),payload_sha256,image_sha256:config.helper_sha256.clone(),state:State::LaunchIntent,
        resources_start:start,resources_final:None};publish(&dir,&record)?;
    let image=open_image(&config.helper_image,&config.helper_sha256)?;
    {let mut state=work.owner.resources.lock().map_err(|_|"actual native owner poisoned")?;
        state.current_native=Some(identity.clone());state.current_step=Some(step);}
    work.parent.bind_native(&identity,step)?;
    let (control,child_control)=UnixStream::pair().map_err(|_|"attach control pair failed")?;
    let procs=cgroup.procs_for_child()?;
    let fds=[lease.as_raw_fd(),capsule_file.as_raw_fd(),child_control.as_raw_fd()];let parent_pid=std::process::id();
    let mut command=Command::new(image_exec_path(&image,&config.helper_image)?);
    command.args(["storage-driver","native-worker","--journal"]).arg(&path)
        .arg("--lease-fd").arg(fds[0].to_string()).arg("--capsule-fd").arg(fds[1].to_string())
        .arg("--control-fd").arg(fds[2].to_string()).arg("--attempt").arg(identity.attempt_uid.as_str())
        .arg("--cgroup-root").arg(&config.delegated_cgroup_root).env_clear().env("PATH","/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL","C").env("HOME","/").current_dir("/").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    unsafe {command.pre_exec(move||{
        #[cfg(target_os="linux")]
        if libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)!=0 || libc::getppid() as u32!=parent_pid {return Err(std::io::Error::last_os_error());}
        if libc::write(procs.as_raw_fd(),b"0\n".as_ptr().cast(),2)!=2{return Err(std::io::Error::last_os_error());}
        for fd in fds {let flags=libc::fcntl(fd,libc::F_GETFD);if flags<0 || libc::fcntl(fd,libc::F_SETFD,flags & !libc::FD_CLOEXEC)<0{return Err(std::io::Error::last_os_error());}}
        Ok(())});}
    let observer=cgroup.try_clone()?;let cancelled=work.owner.cancelled.clone();
    work.owner.require_registered_parent(&work.parent)?;
    let child=command.spawn().map_err(|_|"attach spawn UNKNOWN; original owner/admission retained")?;
    drop(child_control);drop(image);drop(capsule_file);
    // After spawn: only infallible drops/time clipping precede the supervisor.
    let timeout=deadline.saturating_duration_since(Instant::now()).min(remaining);
    let (outcome,quarantine)=supervise(child,control,cgroup,lease,timeout,&identity,&cancelled,
        DiagnosticProfile::Attachment {scope:&scope,step},|request|{
            let Some(kind)=native_kind(request,&identity)else{return Ok(Some(false));};
            let boundary=VerifiedLocalBoundary::new(request,&identity)?;
            let detail=hash(&serde_json::to_vec(request).map_err(|_|"actual attach request encoding")?);
            work.parent.approve(&boundary,kind,&detail)?;Ok(Some(true))
        })?;
    if let Some(q)=quarantine {
        *work.owner.quarantine.lock().unwrap_or_else(|e|e.into_inner())=Some(q);
        work.owner.resources.lock().unwrap_or_else(|e|e.into_inner()).quarantined=true;
    }
    record.resources_final=Some(observer.resource_snapshot(&config.budget)?);
    let drained=record.resources_final.as_ref().is_some_and(|end|end.pids_current==0 && end.cpu_usage_us>=record.resources_start.cpu_usage_us
        && end.cpu_user_us>=record.resources_start.cpu_user_us && end.cpu_system_us>=record.resources_start.cpu_system_us);
    let (raw,extra)=match outcome {
        Outcome::CompletedDiagnostics {stdout,retained_lease:Some(extra),..} if drained && !observer.populated()?
            && !work.owner.resources.lock().map_err(|_|"actual quarantine state poisoned")?.quarantined=>(stdout,extra),
        _=>{record.state=State::Unknown;publish(&dir,&record)?;return Err("actual child/EOF/cgroup/resource drain failed; owner UNKNOWN".into());}
    };
    let diagnostic=serde_json::from_slice(&raw).map_err(|_|"actual helper diagnostic corrupt")?;
    record.state=State::Complete;publish(&dir,&record)?;
    let completion=VerifiedLocalBoundary::attachment_completion(&identity,&record,&raw)?;
    drop(extra);
    Ok(VerifiedAttachDrain {inventory:None,owner:work.owner.clone(),scope,parent:work.parent.clone(),identity,step,diagnostic,
        block_major:147,block_minor:agent.attachment_minor(),block_bytes:work.parent.scope().generation.virgin_replicas[0].exposed_bytes,
        evidence_sha256:hash(&raw),completion})
}

/// Startup admission only, never an owner reconstruction. ANY prior attach
/// operational history/publication requires explicit recovery in this first
/// checkpoint. Existing cold/init journals are not renamed or deleted.
pub(in crate::storage_driver) fn read_closed_history_only(config:&Config)->Result<std::collections::BTreeSet<Uid>,String> {
    let dir=Dir::open(&config.journal_root.join(config.node_uid.as_str()),false)?;
    if dir.bounded_entries(512)?.iter().any(|n|n.starts_with("attach-") || n.starts_with("mount-")) {
        return Err("retained attachment history exists; no JSON reconstruction/reset/adoption".into());
    }
    Ok(std::collections::BTreeSet::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity()->live::JobIdentity {live::JobIdentity {node_uid:Uid::new(),boot_id:"12345678-1234-4234-a234-123456789abc".into(),
        volume_uid:Uid::new(),operation_uid:Uid::new(),attempt_uid:Uid::new(),binding_sha256:"a".repeat(64)}}
    /// Pure DATA fixture only. It never creates a parent/session, actor, worker
    /// permit, real drain, FD owner, physical receipt or launch permission.
    fn scope()->ExpectedAttachScope {
        use crate::storage_lifecycle::generation::physical::{PrimaryFlushObservation,OfflineReplicaObservation};
        let (mut world,uid,node,boot)=crate::storage_lifecycle::model_pod_writer_world();
        let volume=world.storage_identities.lifecycle.get_mut(&uid).unwrap();
        let binding=crate::storage_pod_writer::model_binding(volume,Uid::new());
        volume.begin_pod_attach(0,node.clone(),boot.clone(),binding.clone(),Uid::new()).unwrap();
        let generation=volume.data_generation().unwrap().clone();
        let fact=generation.virgin_replicas.iter().find(|f|f.node_uid==generation.initializer_node_uid).unwrap().clone();
        let primary=PrimaryFlushObservation {version:1,owner:volume.owner().clone(),data_generation_uid:generation.uid.clone(),
            initialize_operation_uid:generation.initialize_operation_uid.clone(),replica:fact.clone(),filesystem_uuid:generation.filesystem_uuid.clone(),
            backing_major:253,backing_minor:0,backing_bytes:fact.exposed_bytes,data_sha256:"a".repeat(64),flush_sha256:"b".repeat(64),evidence_sha256:"c".repeat(64)};
        let offline=std::array::from_fn(|i|OfflineReplicaObservation {version:1,owner:volume.owner().clone(),data_generation_uid:generation.uid.clone(),
            initialize_operation_uid:generation.initialize_operation_uid.clone(),replica:generation.virgin_replicas[i].clone(),
            filesystem_uuid:generation.filesystem_uuid.clone(),backing_major:253,backing_minor:i as u64,
            backing_bytes:generation.virgin_replicas[i].exposed_bytes,data_sha256:"a".repeat(64),offline_metadata_sha256:"d".repeat(64),
            drbd_current_uuid:"1234567890abcdef".into(),evidence_sha256:"e".repeat(64)});
        let replicas=std::array::from_fn(|i|{let f=&generation.virgin_replicas[i];crate::storage_lifecycle::pod_attachment::AttachReplicaTarget {
            node_uid:f.node_uid.clone(),current_boot:if f.node_uid==node {boot.clone()}else{f.node_boot_id.clone()},
            pool_uid:f.pool_uid.clone(),plan_sha256:f.plan_sha256.clone()}});
        ExpectedAttachScope {version:1,owner:volume.owner().clone(),mount_ref:ManagedMountRef::from_metadata(volume).unwrap(),pod_writer:binding,
            generation,initial_lineage:crate::storage_lifecycle::pod_attachment::InitialReplicaLineage {committed_evidence_uid:Uid::new(),primary,offline},replicas,
            round_uid:Uid::new(),phase:AttachPhase::ActivateReplica,phase_job_uid:Uid::new(),phase_node_uid:node.clone(),phase_boot:boot.clone(),
            issuer_node_uid:node,issuer_boot:boot,issuer_revision:crate::storage_remote_protocol::Revision {term:1,leader_raft_id:1,applied_term:1,
                applied_leader_raft_id:1,applied_index:1,desired_generation:1,membership_sha256:"a".repeat(64)},
            scope_sha256:"b".repeat(64),directory_sha256:"c".repeat(64),remaining_budget_ms:180000}
    }
    fn observation(s:&ExpectedAttachScope,phase:AttachPhase)->AttachPhaseObservation {
        AttachPhaseObservation {version:1,phase,scope_sha256:scope_digest(s).unwrap(),node_uid:s.phase_node_uid.clone(),boot:s.phase_boot.clone(),
            raw_kernel:serde_json::json!({"MODEL":true}),exposed_data_sha256:None,mounted:None,evidence_sha256:"a".repeat(64)}
    }
    #[test]
    fn attach_native_boundary_map_rejects_old_kinds_zeroing_and_foreign_attempts() {
        let id=identity();let mut request=live::Request {version:1,identity:id.clone(),sequence:1,nonce:Uid::new(),
            boundary:"helper-start".into(),detail_sha256:hash(b"native-first-attachment-v5")};
        assert_eq!(native_kind(&request,&id),Some(AttachBoundary::Start));
        for name in ["zero-write","zero-fsync","initialization-read","arbitrary-program","format","mount"] {
            request.boundary=name.into();assert!(native_kind(&request,&id).is_none());
        }
        request.boundary="helper-start".into();request.detail_sha256=hash(b"native-distributed-init-phase-v4");
        assert!(native_kind(&request,&id).is_none());
        request.boundary="attachment-read".into();request.detail_sha256="a".repeat(64);
        assert_eq!(native_kind(&request,&id),Some(AttachBoundary::Read));
        request.identity.attempt_uid=Uid::new();assert!(native_kind(&request,&id).is_none());
    }
    #[test]
    fn mount_has_exactly_two_closed_internal_substeps_not_single_or_retry_profile() {
        for p in [AttachPhase::ActivateReplica,AttachPhase::ObserveSynchronized,AttachPhase::PromoteTarget,AttachPhase::ObserveMounted] {
            assert!(step_allowed(p,AttachNativeStep::Single));
            assert!(!step_allowed(p,AttachNativeStep::PublicationAnchor));assert!(!step_allowed(p,AttachNativeStep::FilesystemMount));
        }
        assert!(!step_allowed(AttachPhase::Mount,AttachNativeStep::Single));
        assert!(step_allowed(AttachPhase::Mount,AttachNativeStep::PublicationAnchor));
        assert!(step_allowed(AttachPhase::Mount,AttachNativeStep::FilesystemMount));
    }
    #[test]
    fn direct_attach_reads_bind_phase_alignment_extent_and_original_one_mib_chunk() {
        assert!(read_range_allowed(AttachPhase::ObserveSynchronized,AttachNativeStep::Single,4096,0,4096));
        for (p,step,bytes,at,n) in [(AttachPhase::Mount,AttachNativeStep::FilesystemMount,4096,0,4096),
            (AttachPhase::ActivateReplica,AttachNativeStep::Single,4096,0,4096),
            (AttachPhase::ObserveSynchronized,AttachNativeStep::Single,4096,1,4096),
            (AttachPhase::ObserveSynchronized,AttachNativeStep::Single,4096,0,8192),
            (AttachPhase::ObserveSynchronized,AttachNativeStep::Single,4*1024*1024,0,2*1024*1024),
            (AttachPhase::ObserveSynchronized,AttachNativeStep::Single,u64::MAX,u64::MAX-4095,4096)] {
            assert!(!read_range_allowed(p,step,bytes,at,n));
        }
    }
    #[test]
    fn same_round_accepts_fresh_unrelated_revision_but_not_term_or_owned_lineage_change() {
        let a=scope();let mut b=a.clone();b.issuer_revision.desired_generation+=1;b.issuer_revision.applied_index+=1;
        b.phase=AttachPhase::ObserveSynchronized;b.phase_job_uid=Uid::new();assert!(same_round(&a,&b));
        for case in 0..5 {let mut bad=b.clone();match case {0=>bad.issuer_revision.term+=1,1=>bad.directory_sha256="f".repeat(64),
            2=>bad.round_uid=Uid::new(),3=>bad.replicas[1].current_boot=bad.phase_boot.clone(),_=>bad.generation.uid=Uid::new()}
            if case==3 && bad.replicas[1].current_boot==b.replicas[1].current_boot {bad.replicas[1].plan_sha256="f".repeat(64);}
            assert!(!same_round(&a,&bad),"DATA case {case}");}
    }
    #[test]
    fn writer_and_secondary_local_progress_never_skip_full_physical_phase_order() {
        use AttachPhase::*;let writer=scope();let mut done=Vec::new();
        for phase in [ActivateReplica,ObserveSynchronized,PromoteTarget,Mount,ObserveMounted] {
            assert_eq!(expected_next(&writer,&done),Some(phase));done.push(observation(&writer,phase));
        }assert_eq!(expected_next(&writer,&done),None);
        let mut secondary=writer.clone();secondary.phase_node_uid=secondary.replicas.iter().find(|r|&r.node_uid!=secondary.mount_ref.node_uid()).unwrap().node_uid.clone();
        assert_eq!(expected_next(&secondary,&[observation(&secondary,ActivateReplica),observation(&secondary,ObserveSynchronized)]),None);
    }
    #[test]
    fn opaque_boundary_identity_comparison_cannot_swap_anchor_and_filesystem_attempts() {
        let id=identity();let request=live::Request {version:1,identity:id.clone(),sequence:1,nonce:Uid::new(),boundary:"identity-check".into(),detail_sha256:"a".repeat(64)};
        // Constructor format test only: no actual Core/parent or physical grant.
        let boundary=VerifiedLocalBoundary::new(&request,&id).unwrap();boundary.require_native_identity(&id).unwrap();
        let mut next=id;next.attempt_uid=Uid::new();assert!(boundary.require_native_identity(&next).is_err());
    }
    #[test]
    fn policy_a_distinguishes_physical_dual_refs_from_retained_post_handoff_volume_lifetime() {
        assert_eq!(admission_mode(true,true,true),AdmissionMode::PhysicalWork);
        assert_eq!(admission_mode(true,false,false),AdmissionMode::MountedLifetime);
        for (volume,primary,safety) in [(false,false,false),(true,false,true),(true,true,false),(false,true,true)] {
            assert_eq!(admission_mode(volume,primary,safety),AdmissionMode::Partial);
        }
        // DATA predicate only, not an FD census or handoff producer. Actual
        // code reaches the two-reference take ONLY after same-child/EOF/cgroup
        // drain, installed Watch FDs, fresh Complete and original live budget.
        // A later commit failure latches the rooted mounted lifetime UNKNOWN;
        // it cannot claim already released global refs or trigger another drop.
    }
    #[test]
    fn later_receiver_parent_clock_can_only_shorten_original_local_round() {
        let now=Instant::now();let original=now+Duration::from_secs(180);
        let first=clip_deadline(original,original,original+Duration::from_millis(2));assert_eq!(first,original);
        let shorter=clip_deadline(original,first,now+Duration::from_secs(100));assert!(shorter<first);
        assert_eq!(clip_deadline(original,shorter,now+Duration::from_secs(160)),shorter);
        assert_eq!(clip_deadline(original,shorter,now),now);
    }
}
