//! Closed authenticated terminal protocol. DTOs carry facts/requests only.
//! Every receiver resolves its SAME actual owner/resources; no Rust capability
//! is transported or rebuilt from a serialized observation.
use super::*;
use crate::storage_driver::dispatcher::attachment::{AttachOwner,ReservedTerminalResources,VerifiedTerminalDrain};
use crate::storage_driver::replica::initialize::managed_mount::terminal::TerminalResourceObservation;
use crate::storage_lifecycle::{Owner,Phase};
use crate::storage_lifecycle::pod_attachment::ExpectedAttachScope;
use std::sync::Weak;

#[derive(Clone,Debug,PartialEq,Eq,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceKey {owner:Owner,generation:Uid,writer:crate::storage_pod_writer::PodWriterUid,
    attachment:Uid,round:Uid,issuer:Uid,issuer_boot:BootId}
#[derive(serde::Serialize,serde::Deserialize)]
#[serde(tag="command",deny_unknown_fields)]
enum Request {
    PrepareResources{plan:Uid,source_sha256:String,source:SourceKey,node_job:Uid,nonce:Uid,revision:protocol::Revision},
    RegisterNode{plan:Uid,source:SourceKey,node_job:Uid,nonce:Uid,revision:protocol::Revision},
    RegisterChallenge{plan:Uid,node_job:Uid,nonce:Uid,commitment:String},
    NativeBoundary{plan:Uid,node_job:Uid,session:Uid,sequence:u64,nonce:Uid,step:TerminalNativeStep,
        kind:TerminalBoundary,detail:String,native_sha256:String},
    NativeResult{plan:Uid,node_job:Uid,session:Uid,sequence:u64,nonce:Uid,step:TerminalNativeStep,
        kind:TerminalBoundary,detail:String,result:String,native_sha256:String},
    Execute{plan:Uid,node_job:Uid,session:Uid,nonce:Uid,step:TerminalNativeStep},
    Inspect{plan:Uid,node_job:Uid,session:Uid,nonce:Uid},
    ConfirmDetached{plan:Uid,node_job:Uid,session:Uid,nonce:Uid,revision:protocol::Revision,evidence:String},
    RetireLease{plan:Uid,node_job:Uid,session:Uid,nonce:Uid},
}
#[derive(serde::Serialize,serde::Deserialize)]
#[serde(tag="reply",deny_unknown_fields)]
enum Reply {
    Prepared{plan:Uid,node_job:Uid,nonce:Uid,reservation:Uid,commitment:String,
        scope:ExpectedAttachScope,observation:TerminalResourceObservation,mandatory_admissions:usize},
    Grant{plan:Uid,node_job:Uid,nonce:Uid,session:Uid,remaining_ms:u64,revision:protocol::Revision,directory:String},
    Accepted{plan:Uid,node_job:Uid,nonce:Uid,session:Uid},
    Boundary{plan:Uid,node_job:Uid,session:Uid,sequence:u64,nonce:Uid,kind:TerminalBoundary,
        detail:String,revision:protocol::Revision,directory:String},
    ResultRecorded{plan:Uid,node_job:Uid,session:Uid,sequence:u64,nonce:Uid},
    Pending{plan:Uid,node_job:Uid,nonce:Uid},
    Complete{plan:Uid,node_job:Uid,nonce:Uid,step:TerminalNativeStep,
        observation:crate::storage_driver::replica::initialize::managed_mount::terminal::TerminalPhysicalObservation,
        completion:String},
    DetachedConfirmed{plan:Uid,node_job:Uid,nonce:Uid,revision:protocol::Revision},
    Retired{plan:Uid,node_job:Uid,nonce:Uid,evidence:String},
}
fn encode(value:&impl serde::Serialize)->Result<Vec<u8>,String>{protocol::encode_node(value)}
fn decode<T:serde::de::DeserializeOwned>(raw:&[u8])->Result<T,String>{protocol::decode_node(raw)}
fn receiver_deadline_data(challenge_started:Instant,remaining_ms:u64)->Result<Instant,String>{
    if remaining_ms==0||remaining_ms>180000{return Err("terminal receiver remaining budget outside original180s".into());}
    challenge_started.checked_add(Duration::from_millis(remaining_ms)).ok_or("terminal receiver original budget overflow".into())
}
pub(in crate::storage_driver::native_runtime::mount) struct ReceiverPreparation {
    shared:Arc<Shared>,book:Arc<MountBook>,owner:Arc<AttachOwner>,scope:ExpectedAttachScope,
    source:SourceKey,plan:Uid,node_job:Uid,source_hash:String,nonce:Uid,
    attempted:AtomicBool,failed:AtomicBool,resources:Mutex<Option<Arc<ReservedTerminalResources>>>,
    commitment:Mutex<Option<String>>,accepted:Mutex<Option<Arc<AcceptedTerminalReceiver>>>,
    parent:Mutex<Option<Arc<VerifiedTerminalNodeParent>>>,
    pending:Mutex<Option<NodePending>>,
    registration:Mutex<Option<(Instant,Uid)>>,
}
pub(super) struct AcceptedTerminalReceiver {
    prepared:Arc<ReceiverPreparation>,started:Instant,deadline:Instant,session:Uid,
    issuer_revision:protocol::Revision,directory:String,unknown:AtomicBool,
    sequence:std::sync::atomic::AtomicU64,detached:Mutex<Option<protocol::Revision>>,
    detached_evidence:Mutex<Option<String>>,
}
impl AcceptedTerminalReceiver {
    pub(super) fn require_accepted(&self)->Result<(),String>{
        if self.unknown.load(Ordering::Acquire)||self.prepared.failed.load(Ordering::Acquire)
            ||!self.prepared.shared.controller_alive.load(Ordering::Acquire)||Instant::now()<self.started||Instant::now()>=self.deadline
            ||!core::is_actual_world(&self.prepared.shared.world){return Err("original accepted terminal receiver expired/UNKNOWN/dead".into());}
        let actual=self.prepared.book.state.try_lock().map_err(|_|"terminal receiver root busy")?;
        if !actual.terminal_preparations.get(&self.prepared.plan).is_some_and(|p|std::ptr::eq(Arc::as_ptr(p),&*self.prepared)){
            return Err("terminal receiver is not SAME actual registered root".into());}
        drop(actual);self.prepared.owner.require_terminal_retained()
    }
    pub(super) fn retain_unknown(&self){self.unknown.store(true,Ordering::Release);self.prepared.owner.mark_unknown();}
    pub(super) fn owner(&self)->&Arc<AttachOwner>{&self.prepared.owner}
    pub(super) fn shared(&self)->&Arc<Shared>{&self.prepared.shared}
    pub(super) fn node_job_uid(&self)->&Uid{&self.prepared.node_job}
    pub(super) fn operation_uid(&self)->&Uid{&self.prepared.plan}
    pub(super) fn started(&self)->Instant{self.started}
    pub(super) fn deadline(&self)->Instant{self.deadline}
    pub(super) fn require_detached_confirmed(&self)->Result<(),String>{
        self.require_accepted()?;
        let revision=self.detached.try_lock().map_err(|_|"terminal actual Detached confirm busy")?.clone()
            .ok_or("no authenticated current actual Detached confirmation")?;
        core::require_same_actual_epoch(&self.prepared.shared.world,&revision)?;
        let world=self.prepared.shared.world.try_read().map_err(|_|"actual Detached source busy")?;
        let volume=world.storage_identities.lifecycle.get(&self.prepared.source.owner.volume_uid).ok_or("Detached source absent")?;
        let evidence=self.detached_evidence.try_lock().map_err(|_|"terminal actual Detached evidence busy")?.clone().ok_or("no actual Detached evidence confirmation")?;
        if volume.phase()!=Phase::Detached||volume.operation()!=&self.prepared.plan||volume.assignment().is_some()
            ||volume.owner()!=&self.prepared.source.owner||volume.data_generation().map(|g|&g.uid)!=Some(&self.prepared.source.generation){
            return Err("actual confirmed terminal Detached metadata changed".into());}
        crate::storage_lifecycle::pod_attachment::check_terminal_detached_receipt_data(volume,&self.prepared.plan,&evidence)?;
        Ok(())
    }
}
struct NodePending {step:TerminalNativeStep,ticket:Option<crate::storage_driver::dispatcher::attachment::TerminalTicket>,
    completed:Option<Arc<VerifiedTerminalDrain>>,unknown:bool,attempted:bool,
    retired:Option<Arc<crate::storage_driver::dispatcher::attachment::RetiredTerminalLease>>,
    retire_requested:bool,retire_attempted:bool,
    retirement:Option<crate::storage_driver::dispatcher::attachment::TerminalRetirementTicket>}
pub(super) struct IssuerNodeProgress {
    registration_nonce:Option<Uid>,grant_issued:bool,current:Option<TerminalNativeStep>,
    identities:BTreeMap<TerminalNativeStep,String>,completed:BTreeSet<TerminalNativeStep>,
    pending:BTreeMap<(TerminalBoundary,String),String>,results:BTreeSet<(TerminalBoundary,String)>,
}
impl IssuerNodeProgress {pub(super) fn new()->Self{Self{registration_nonce:None,grant_issued:false,current:None,
    identities:BTreeMap::new(),completed:BTreeSet::new(),pending:BTreeMap::new(),results:BTreeSet::new()}}}
struct RetainPreparationFailure {actual:Arc<ReceiverPreparation>,finished:bool}
impl Drop for RetainPreparationFailure {fn drop(&mut self){if !self.finished{
    self.actual.failed.store(true,Ordering::Release);self.actual.owner.mark_unknown();
}}}
struct RetainIssuerFailure {round:Arc<RegisteredDrainRound>,finished:bool}
impl Drop for RetainIssuerFailure {fn drop(&mut self){if !self.finished{self.round.mark_unknown();}}}
pub(super) async fn prepare_all(shared:&Arc<Shared>,plan:&Arc<PreparedTerminalPlan>)->Result<(),String>{
    let view=core::runtime_view(true).await?;
    let directory=VerifiedDirectory::from_runtime(&view)?;
    if directory.pin(view.local())?.raft_id!=view.revision().leader_raft_id||view.local()!=&shared.pool.node_uid{
        return Err("terminal pre-Create reservations require actual local acknowledged leader".into());}
    let uid=plan.operation.key.references.keys().next().ok_or("actual terminal volume absent")?;
    let owner=plan.operation.ready.book.state.try_lock().map_err(|_|"actual pre-Create root busy")?.owners
        .get(uid).cloned().ok_or("original pre-Create owner absent")?;
    let source=original_source(&owner);
    for (node,node_job) in &plan.node_jobs {
        plan.operation.live()?;
        let nonce=Uid::new();
        if node==&shared.pool.node_uid {
            let observed=core::observe_local_async(uid).await?;
            check_current(shared,&owner,&source,&observed,None)?;
            let preparation=Arc::new(ReceiverPreparation{shared:shared.clone(),book:plan.operation.ready.book.clone(),owner:owner.clone(),
                scope:owner.scope().clone(),source:source.clone(),plan:plan.uid.clone(),node_job:node_job.clone(),source_hash:plan.source.clone(),nonce,
                attempted:AtomicBool::new(true),failed:AtomicBool::new(false),resources:Mutex::new(None),commitment:Mutex::new(None),
                accepted:Mutex::new(None),parent:Mutex::new(None),pending:Mutex::new(None),registration:Mutex::new(None)});
            {let mut state=preparation.book.state.try_lock().map_err(|_|"local pre-Create terminal root busy")?;
                if !state.terminal_preparations.is_empty(){return Err("local original terminal reservation already attempted; no replacement".into());}
                state.terminal_preparations.insert(plan.uid.clone(),preparation.clone());}
            let mut retain=RetainPreparationFailure{actual:preparation.clone(),finished:false};
            let current=preparation.clone();let runtime=shared.clone();let config=shared.dispatcher_configuration();
            let resources=shared.io.run(move||{
                let actual=runtime.dispatcher.reserve_terminal_resources(current.owner.clone(),config)?;
                *current.resources.lock().unwrap_or_else(|p|p.into_inner())=Some(actual.clone());
                actual.require_current()?;Ok(actual)
            }).await?;
            let facts=resources.observation();let mandatory=resources.mandatory_admissions();
            validate_resource_facts(&facts,owner.scope(),node,mandatory)?;
            let commitment=digest(&encode(&(&plan.uid,node_job,&plan.source,&source,resources.reservation_uid(),&facts,mandatory))?);
            *preparation.commitment.lock().unwrap_or_else(|p|p.into_inner())=Some(commitment.clone());
            let actual=ResourceReservation{node:node.clone(),boot:facts.boot.clone(),volume:facts.volume_uid.clone(),pool:facts.pool_uid.clone(),
                dispatcher_entries:facts.reserved_dispatch_entries,pool_entries:facts.reserved_pool_entries,attempts:facts.reserved_attempts,
                receipt_sha256:commitment,reservation:resources.reservation_uid().clone(),scope:owner.scope().clone(),
                local:Some(resources),transport:None,mandatory_admissions:mandatory};
            plan.charged_nodes.lock().unwrap_or_else(|p|p.into_inner()).insert(node.clone(),actual);
            retain.finished=true;
        }else{
            let request=encode(&Request::PrepareResources{plan:plan.uid.clone(),source_sha256:plan.source.clone(),source:source.clone(),node_job:node_job.clone(),nonce:nonce.clone(),revision:view.revision().clone()})?;
            let peer=shared.call(PATH,&request,node,&directory).await?;
            if peer.sender()!=node||peer.receiver()!=&shared.pool.node_uid{return Err("terminal pre-Create reply endpoint mismatch".into());}
            let Reply::Prepared{plan:reply_plan,node_job:reply_job,nonce:reply_nonce,reservation,commitment,scope,observation,mandatory_admissions}=decode(peer.body())?
                else{return Err("terminal resource reply is not actual Prepared DATA".into());};
            if reply_plan!=plan.uid||reply_job!=*node_job||reply_nonce!=nonce||original_source_matches_scope(&scope,&source).is_err(){
                return Err("terminal resource ACK differs from exact original source/plan/nonce".into());}
            if scope.owner!=owner.scope().owner||scope.generation!=owner.scope().generation||scope.pod_writer!=owner.scope().pod_writer
                ||scope.mount_ref!=owner.scope().mount_ref||scope.replicas!=owner.scope().replicas
                ||scope.directory_sha256!=directory.digest(){
                return Err("terminal resource ACK differs from FULL actual original owner/generation/replica/writer scope".into());}
            validate_resource_facts(&observation,&scope,node,mandatory_admissions)?;
            let expected=digest(&encode(&(&plan.uid,node_job,&plan.source,&source,&reservation,&observation,mandatory_admissions))?);
            if commitment!=expected{return Err("actual receiver resource commitment changed".into());}
            // Root authenticated frame + exact DATA BEFORE later live checks.
            // It never constructs a receiver Rust resource owner on issuer.
            let actual=ResourceReservation{node:node.clone(),boot:observation.boot.clone(),volume:observation.volume_uid.clone(),pool:observation.pool_uid.clone(),
                dispatcher_entries:observation.reserved_dispatch_entries,pool_entries:observation.reserved_pool_entries,attempts:observation.reserved_attempts,
                receipt_sha256:commitment,reservation,scope,local:None,transport:Some(peer),mandatory_admissions};
            plan.charged_nodes.lock().unwrap_or_else(|p|p.into_inner()).insert(node.clone(),actual);
        }
        plan.operation.live()?;
    }
    plan.require_nodes_precharged()
}
fn original_source_matches_scope(scope:&ExpectedAttachScope,source:&SourceKey)->Result<(),String>{
    if scope.owner!=source.owner||scope.generation.uid!=source.generation||scope.pod_writer.uid()!=&source.writer
        ||scope.mount_ref.operation_uid()!=&source.attachment||scope.round_uid!=source.round
        ||scope.issuer_node_uid!=source.issuer||scope.issuer_boot!=source.issuer_boot{
        return Err("resource observation has another original PodWriter/claim/round".into());}
    Ok(())
}
fn validate_resource_facts(facts:&TerminalResourceObservation,scope:&ExpectedAttachScope,node:&Uid,mandatory:usize)->Result<(),String>{
    let attempts=if scope.mount_ref.node_uid()==node{3}else{2};
    let fact=scope.generation.virgin_replicas.iter().find(|fact|&fact.node_uid==node).ok_or("resource node outside actual replica set")?;
    let expected=crate::storage_driver::replica::initialize::managed_mount::terminal::mandatory_admissions(fact.exposed_bytes,scope.mount_ref.node_uid()==node)?;
    if mandatory!=expected||&facts.node_uid!=node||scope.phase_node_uid!=*node||facts.boot!=scope.phase_boot||facts.volume_uid!=scope.owner.volume_uid
        ||facts.pool_uid!=fact.pool_uid||facts.dispatch_identity.1==0||facts.pool_identity.1==0
        ||facts.reserved_attempts!=attempts||facts.reserved_dispatch_entries!=2*attempts||facts.reserved_pool_entries!=2*attempts
        ||facts.atomic_temp_peak!=1||facts.existing_attempts.checked_add(attempts).is_none_or(|n|n>128)
        ||facts.existing_dispatch_entries.checked_add(2*attempts+1).is_none_or(|n|n>512)
        ||facts.existing_pool_entries.checked_add(2*attempts+1).is_none_or(|n|n>512)||mandatory>512{
        return Err("actual receiver terminal resource/frame/attempt budget is partial/excessive/stale BEFORE Create".into());}
    Ok(())
}

fn original_source(owner:&AttachOwner)->SourceKey{
    let scope=owner.scope();SourceKey {owner:scope.owner.clone(),generation:scope.generation.uid.clone(),
        writer:scope.pod_writer.uid().clone(),attachment:scope.mount_ref.operation_uid().clone(),round:scope.round_uid.clone(),
        issuer:scope.issuer_node_uid.clone(),issuer_boot:scope.issuer_boot.clone()}
}
fn check_current(shared:&Shared,owner:&AttachOwner,source:&SourceKey,observed:&core::CoreObservation,
    terminal:Option<&Uid>)->Result<VerifiedDirectory,String>{
    if !core::is_actual_world(&shared.world)||original_source(owner)!=*source{return Err("terminal source is not exact original actual owner".into());}
    let directory=shared.directory_for(observed)?;
    if observed.local_node_uid()!=Some(&shared.pool.node_uid)||observed.actual_boot()!=&owner.scope().phase_boot
        ||directory.pin(&source.issuer)?.raft_id!=observed.revision().leader_raft_id
        ||directory.digest()!=owner.scope().directory_sha256{return Err("terminal actual node/boot/directory/issuer changed".into());}
    let world=shared.world.try_read().map_err(|_|"actual terminal Core busy")?;
    let volume=world.storage_identities.lifecycle.get(&source.owner.volume_uid).ok_or("actual terminal volume absent")?;
    if world.generation!=observed.revision().desired_generation||volume!=observed.volume()||volume.owner()!=&source.owner
        ||volume.data_generation()!=Some(&owner.scope().generation)||volume.pod_writer()!=Some(&owner.scope().pod_writer)
        ||volume.epoch()!=owner.scope().mount_ref.epoch(){return Err("terminal canonical current claim/dataset/writer scope changed".into());}
    let assignment=volume.assignment().ok_or("terminal actual original assignment absent")?;
    if assignment.attach_operation!=source.attachment||assignment.writer_uid!=*source.writer.as_uid()
        ||assignment.node_uid!=*owner.scope().mount_ref.node_uid()||assignment.node_boot_id!=*owner.scope().mount_ref.node_boot(){
        return Err("terminal assignment differs from original actual owner".into());}
    let claim=world.storage_identities.claims.get(&crate::store::obj_key(&source.owner.namespace,&source.owner.claim_name))
        .ok_or("terminal actual claim identity absent")?;
    if claim.uid!=source.owner.claim_uid||claim.namespace_uid!=source.owner.namespace_uid
        ||world.storage_identities.namespaces.get(&source.owner.namespace)!=Some(&source.owner.namespace_uid)
        ||world.storage_identities.volumes.get(&source.owner.pv_name)!=Some(&source.owner.volume_uid){
        return Err("terminal actual namespace/claim/PV incarnation changed".into());}
    check_current_bound_objects(shared,&world,&source.owner)?;
    if let Some(operation)=terminal {
        let workload=crate::store::obj_key(owner.scope().pod_writer.namespace(),owner.scope().pod_writer.workload());
        if world.deployments.contains_key(&workload){return Err("terminal original desired removal is no longer current".into());}
        if volume.phase()!=Phase::Detaching||volume.operation()!=operation{return Err("terminal new Detaching operation not actually applied".into());}
    }else{
        if volume.phase()!=Phase::Attached||volume.operation()!=&source.attachment{return Err("pre-Create resource preparation requires actual original Attached group".into());}
        owner.scope().pod_writer.check_source_current(&world)?;
    }
    Ok(directory)
}
fn check_current_bound_objects(shared:&Shared,world:&DesiredWorld,owner:&Owner)->Result<(),String>{
    let key=crate::store::obj_key(&owner.namespace,&owner.claim_name);
    let pvc=world.pvcs.get(&key).ok_or("terminal actual current PVC absent")?;
    let pv=world.pvs.get(&owner.pv_name).ok_or("terminal actual current PV absent")?;
    let class=world.storage_classes.get(&pv.storage_class).ok_or("terminal current native class absent")?;
    if pvc.bound_pv.as_ref()!=Some(&owner.pv_name)||pv.bound_to.as_deref()!=Some(key.as_str())
        ||pv.status!=crate::reconcile::PVStatus::Bound||pvc.storage_class!=pv.storage_class
        ||class.provisioner!=crate::storage_lifecycle::PROVISIONER||!shared.config.storage_class_allowlist.contains(&pv.storage_class){
        return Err("terminal actual current PVC/PV/class binding changed".into());}Ok(())
}
pub(super) async fn prepare_receiver(shared:&Arc<Shared>,peer:VerifiedPeerFrame,request_deadline:Instant)->Result<Vec<u8>,String>{
    let Request::PrepareResources{plan,source_sha256,source,node_job,nonce,revision}=decode(peer.body())?
        else{return Err("not a closed readonly terminal resource request".into());};
    if peer.receiver()!=&shared.pool.node_uid||peer.sender()!=&source.issuer||!is_hash(&source_sha256){
        return Err("terminal resource request has wrong authenticated endpoints/source".into());}
    let book=ROOTED_BOOK.get().ok_or("terminal resource receiver has no actual live owner book")?.clone();
    if !Arc::ptr_eq(book.world(),&shared.world){return Err("terminal resource receiver differs from actual store".into());}
    let owner={book.state.try_lock().map_err(|_|"terminal resource owner book busy")?.owners
        .get(&source.owner.volume_uid).cloned().ok_or("terminal resource source has no original local owner")?};
    core::wait_applied_hint(&revision,request_deadline).await?;
    let observed=core::observe_local_async(&source.owner.volume_uid).await?;
    check_current(shared,&owner,&source,&observed,None)?;
    let preparation=Arc::new(ReceiverPreparation {shared:shared.clone(),book:book.clone(),owner:owner.clone(),scope:owner.scope().clone(),
        source,plan:plan.clone(),node_job:node_job.clone(),source_hash:source_sha256,nonce:nonce.clone(),attempted:AtomicBool::new(false),
        failed:AtomicBool::new(false),resources:Mutex::new(None),commitment:Mutex::new(None),accepted:Mutex::new(None),parent:Mutex::new(None),pending:Mutex::new(None),registration:Mutex::new(None)});
    {let mut state=book.state.try_lock().map_err(|_|"terminal preparation root busy")?;
        if state.terminal_preparations.len()>=1||state.terminal_preparations.contains_key(&plan){return Err("terminal readonly preparation already attempted/UNKNOWN; no re-reserve".into());}
        state.terminal_preparations.insert(plan.clone(),preparation.clone());}
    let mut retain=RetainPreparationFailure{actual:preparation.clone(),finished:false};
    preparation.attempted.store(true,Ordering::Release);
    let current=preparation.clone();let config=shared.dispatcher_configuration();let runtime=shared.clone();
    let result=shared.io.run(move||{
        if Instant::now()>=request_deadline{return Err("original readonly resource request expired before IO".into());}
        let reserved=runtime.dispatcher.reserve_terminal_resources(current.owner.clone(),config)?;
        *current.resources.lock().unwrap_or_else(|p|p.into_inner())=Some(reserved.clone()); // BEFORE any reply/live checks.
        reserved.require_current()?;
        let facts=reserved.observation();let mandatory=reserved.mandatory_admissions();
        if mandatory>512{return Err("mandatory terminal fixed/read budget exceeds512 BEFORE Create".into());}
        let commitment=digest(&encode(&(&current.plan,&current.node_job,&current.source_hash,&current.source,
            reserved.reservation_uid(),&facts,mandatory))?);
        *current.commitment.lock().unwrap_or_else(|p|p.into_inner())=Some(commitment.clone());
        Ok((reserved.reservation_uid().clone(),commitment,facts,mandatory))
    }).await;
    let (reservation,commitment,observation,mandatory)=match result{Ok(value)=>value,Err(error)=>{
        preparation.failed.store(true,Ordering::Release);return Err(error);}};
    let after=core::observe_local_async(&preparation.source.owner.volume_uid).await?;
    check_current(shared,&owner,&preparation.source,&after,None)?;
    if Instant::now()>=request_deadline{preparation.failed.store(true,Ordering::Release);return Err("readonly terminal prepare ACK late; resources retained".into());}
    let reply=encode(&Reply::Prepared{plan,node_job,nonce,reservation,commitment,scope:preparation.scope.clone(),observation,mandatory_admissions:mandatory})?;
    retain.finished=true;Ok(reply)
}

fn issuer_round(shared:&Arc<Shared>,plan:&Uid)->Result<Arc<RegisteredDrainRound>,String>{
    let book=ROOTED_BOOK.get().ok_or("terminal issuer has no actual rooted book")?;
    if !Arc::ptr_eq(book.world(),&shared.world){return Err("terminal issuer actual store changed".into());}
    let operations=book.state.try_lock().map_err(|_|"terminal issuer operation root busy")?.consumer.history.values().cloned().collect::<Vec<_>>();
    for operation in operations{
        let prepared=operation.terminal_plan.try_lock().map_err(|_|"terminal issuer prepared root busy")?.as_ref().cloned();
        if let Some(prepared)=prepared {if &prepared.uid==plan{
            return prepared.round.try_lock().map_err(|_|"terminal issuer actual round busy")?.as_ref().cloned()
                .ok_or("terminal issuer round has not actually registered".into());
        }}
    }Err("terminal issuer plan is not original actual operation".into())
}
fn receiver_preparation(shared:&Arc<Shared>,plan:&Uid,node_job:&Uid)->Result<Arc<ReceiverPreparation>,String>{
    let book=ROOTED_BOOK.get().ok_or("terminal receiver actual book absent")?;
    if !Arc::ptr_eq(book.world(),&shared.world){return Err("terminal receiver source is not actual registered World".into());}
    let prepared=book.state.try_lock().map_err(|_|"terminal receiver preparation root busy")?.terminal_preparations
        .get(plan).cloned().ok_or("terminal receiver has no pre-Create actual resource reservation")?;
    if &prepared.node_job!=node_job||prepared.failed.load(Ordering::Acquire)||!prepared.attempted.load(Ordering::Acquire){
        return Err("terminal receiver original resource preparation differs/UNKNOWN".into());}
    prepared.owner.require_terminal_retained()?;
    Ok(prepared)
}
fn expected_node(round:&Arc<RegisteredDrainRound>,node:&Uid,job:&Uid)->Result<Arc<RegisteredTerminalNode>,String>{
    let expected=round.node_jobs.try_lock().map_err(|_|"terminal issuer node table busy")?.get(node).cloned()
        .ok_or("authenticated terminal node is outside original three-node plan")?;
    if &expected.uid!=job{return Err("terminal node job differs from exact pre-Create original slot".into());}Ok(expected)
}
fn session_for(round:&RegisteredDrainRound,node:&Uid)->Result<Uid,String>{
    round.plan.node_sessions.get(node).cloned().ok_or("original terminal session DATA slot absent".into())
}
async fn append_issuer(round:&Arc<RegisteredDrainRound>,node:&Arc<RegisteredTerminalNode>,tag:u16,binding:&str)->Result<(),String>{
    let current=round.clone();let job=node.uid.clone();let binding=binding.to_string();
    round.shared.io.run(move||current.shared.journal.terminal_node_append(&current.plan.budget,&job,tag,&binding)).await
}
fn check_issuer_observation(round:&Arc<RegisteredDrainRound>,node:&RegisteredTerminalNode,observed:&core::CoreObservation)->Result<VerifiedDirectory,String>{
    round.require_live()?;
    if observed.local_node_uid()!=Some(&round.shared.pool.node_uid)||observed.actual_boot()!=&node.scope.issuer_boot
        ||!observed.revision().at_least(&round.revision){return Err("terminal actual issuer epoch/boot changed".into());}
    let directory=round.shared.directory_for(observed)?;
    if directory.digest()!=round.directory||node.scope.phase_boot!=node.boot||directory.pin(&node.node)?.node_uid!=node.node{
        return Err("terminal registered peer boot/directory changed".into());}
    let current=round.shared.world.try_read().map_err(|_|"terminal issuer current actual World busy")?;
    if current.generation!=observed.revision().desired_generation
        ||current.storage_identities.lifecycle.get(&node.scope.owner.volume_uid)!=Some(observed.volume()){
        return Err("terminal issuer source changed after THIS actual barrier".into());}
    round.check_world(&current)?;Ok(directory)
}
/// Fresh local request bound to the actual registered round, never a caller
/// supplied clock/revision or decoded World. Admission is durable first.
pub(super) async fn local_observation(round:&Arc<RegisteredDrainRound>,node:&Arc<RegisteredTerminalNode>,
    tag:u16,effect:TerminalEffect,resource:String,detail:&impl serde::Serialize)->Result<VerifiedTerminalEffect,String>{
    round.require_live()?;round.shared.check_attach_config().await?;round.require_live()?;let nonce=Uid::new();
    let binding=digest(&encode(&("terminal-local-original-v1",&round.plan.uid,&node.uid,&nonce,detail))?);
    append_issuer(round,node,tag,&binding).await?;
    let request=TerminalReadRequest{round:round.clone(),effect,binding,resource,nonce};
    let observed=core::observe_terminal_issuer(&node.scope.owner.volume_uid,&request).await?;
    observed.require_fresh_terminal(&request,Instant::now())?;check_issuer_observation(round,node,&observed)?;
    Ok(VerifiedTerminalEffect{request,observed,spent:AtomicBool::new(false),node_job:node.uid.clone()})
}
pub(super) async fn register_all(round:&Arc<RegisteredDrainRound>)->Result<(),String>{
    round.require_live()?;if !round.begun.load(Ordering::Acquire){return Err("terminal receiver registration precedes actual Detaching ACK".into());}
    let view=core::runtime_view(true).await?;let directory=VerifiedDirectory::from_runtime(&view)?;
    let jobs=round.node_jobs.lock().map_err(|_|"terminal node registrations poisoned")?.values().cloned().collect::<Vec<_>>();
    for node in jobs{
        round.require_live()?;let nonce=Uid::new();
        if node.node==round.shared.pool.node_uid{
            let parent=VerifiedTerminalNodeParent::local(round.clone(),&node.node)?;
            let prepared=receiver_preparation(&round.shared,&round.plan.uid,&node.uid)?;
            *prepared.parent.lock().unwrap_or_else(|p|p.into_inner())=Some(parent);
            {let mut progress=node.progress.lock().map_err(|_|"local terminal registration state poisoned")?;
                if progress.grant_issued||progress.registration_nonce.is_some(){return Err("local terminal registration already attempted".into());}
                progress.registration_nonce=Some(nonce.clone());progress.grant_issued=true;}
            let grant=local_observation(round,&node,1,TerminalEffect::NativeObservation,
                digest(&encode(&(&round.plan.uid,&node.uid,&nonce))?),&("local-register",&nonce)).await?;
            grant.consume_resource(&grant.request.resource)?;
        }else{
            let resource=round.plan.charged_nodes.lock().map_err(|_|"terminal original resource facts poisoned")?
                .get(&node.node).map(|r|r.scope.clone()).ok_or("original receiver scope absent")?;
            let request=encode(&Request::RegisterNode{plan:round.plan.uid.clone(),source:SourceKey{
                owner:resource.owner.clone(),generation:resource.generation.uid.clone(),writer:resource.pod_writer.uid().clone(),
                attachment:resource.mount_ref.operation_uid().clone(),round:resource.round_uid.clone(),issuer:resource.issuer_node_uid.clone(),issuer_boot:resource.issuer_boot.clone()},
                node_job:node.uid.clone(),nonce:nonce.clone(),revision:view.revision().clone()})?;
            let reply=round.shared.call(PATH,&request,&node.node,&directory).await?;
            let Reply::Accepted{plan,node_job,nonce:echo,session}=decode(reply.body())?else{return Err("terminal receiver registration not actually accepted".into());};
            if reply.sender()!=&node.node||reply.receiver()!=&round.shared.pool.node_uid||plan!=round.plan.uid||node_job!=node.uid
                ||echo!=nonce||session!=session_for(round,&node.node)?{return Err("terminal accepted receiver session differs from exact original round".into());}
        }
        round.require_live()?;
    }Ok(())
}
async fn register_receiver(shared:&Arc<Shared>,peer:VerifiedPeerFrame,request_deadline:Instant)->Result<Vec<u8>,String>{
    let Request::RegisterNode{plan,source,node_job,nonce,revision}=decode(peer.body())?else{return Err("not a terminal registration offer".into());};
    let prepared=receiver_preparation(shared,&plan,&node_job)?;
    if peer.sender()!=&prepared.source.issuer||peer.receiver()!=&shared.pool.node_uid||source!=prepared.source{
        return Err("terminal registration sender/source differs from actual reserved parent".into());}
    if prepared.accepted.try_lock().map_err(|_|"terminal receiver accepted root busy")?.is_some()
        ||prepared.parent.try_lock().map_err(|_|"terminal receiver parent root busy")?.is_some(){return Err("terminal receiver registration already accepted/UNKNOWN; no repeat".into());}
    let started=Instant::now();let challenge=Uid::new();
    // Root attempted registration BEFORE any await. No failed/lost challenge
    // can create a fresh receiver deadline on a later offer.
    {let mut slot=prepared.registration.lock().map_err(|_|"terminal registration clock poisoned")?;
        if slot.is_some(){return Err("terminal receiver registration already attempted; retained UNKNOWN".into());}
        *slot=Some((started,challenge.clone()));}
    let mut retain=RetainPreparationFailure{actual:prepared.clone(),finished:false};
    let result=async{
        core::wait_applied_hint(&revision,request_deadline).await?;
        let before=core::observe_local_async(&source.owner.volume_uid).await?;
        let directory=check_current(shared,&prepared.owner,&source,&before,Some(&plan))?;
        let commitment=prepared.commitment.lock().map_err(|_|"terminal actual resource commitment poisoned")?.clone()
            .ok_or("terminal resources were not actually acknowledged before Create")?;
        let request=encode(&Request::RegisterChallenge{plan:plan.clone(),node_job:node_job.clone(),nonce:challenge.clone(),commitment})?;
        let grant=shared.call(PATH,&request,&source.issuer,&directory).await?;
        let Reply::Grant{plan:actual_plan,node_job:actual_job,nonce:echo,session,remaining_ms,revision:confirmed,directory:confirmed_directory}=decode(grant.body())?
            else{return Err("actual issuer did not authorize terminal receiver session".into());};
        if grant.sender()!=&source.issuer||grant.receiver()!=&shared.pool.node_uid||actual_plan!=plan||actual_job!=node_job
            ||echo!=challenge||remaining_ms==0||remaining_ms>180000||confirmed_directory!=directory.digest(){
            return Err("terminal grant differs from exact accepted challenge/resources".into());}
        let deadline=receiver_deadline_data(started,remaining_ms)?;
        if Instant::now()>=deadline||Instant::now()>=request_deadline{return Err("terminal grant arrived after original receiver budget".into());}
        core::wait_applied_hint(&confirmed,deadline.min(request_deadline)).await?;
        let after=core::observe_local_async(&source.owner.volume_uid).await?;
        check_current(shared,&prepared.owner,&source,&after,Some(&plan))?;
        if !after.revision().at_least(&confirmed){return Err("actual receiver has not applied terminal grant scope".into());}
        let receiver=Arc::new(AcceptedTerminalReceiver{prepared:prepared.clone(),started,deadline,session:session.clone(),issuer_revision:confirmed,
            directory:confirmed_directory,unknown:AtomicBool::new(false),sequence:std::sync::atomic::AtomicU64::new(0),detached:Mutex::new(None),detached_evidence:Mutex::new(None)});
        *prepared.accepted.lock().unwrap_or_else(|p|p.into_inner())=Some(receiver.clone()); // before fallible parent registration.
        let parent=VerifiedTerminalNodeParent::accepted(receiver)?;
        *prepared.parent.lock().unwrap_or_else(|p|p.into_inner())=Some(parent);
        encode(&Reply::Accepted{plan,node_job,nonce,session})
    }.await;
    if result.is_err(){prepared.failed.store(true,Ordering::Release);prepared.owner.mark_unknown();}
    retain.finished=result.is_ok();
    result
}
async fn issuer_registration(shared:&Arc<Shared>,peer:VerifiedPeerFrame)->Result<Vec<u8>,String>{
    let Request::RegisterChallenge{plan,node_job,nonce,commitment}=decode(peer.body())?else{return Err("not terminal receiver challenge".into());};
    let round=issuer_round(shared,&plan)?;round.require_live()?;
    if !round.begun.load(Ordering::Acquire)||peer.receiver()!=&shared.pool.node_uid{return Err("terminal node challenge before actual Detaching/at wrong receiver".into());}
    let node=expected_node(&round,peer.sender(),&node_job)?;
    let mut retain=RetainIssuerFailure{round:round.clone(),finished:false};
    let expected=round.plan.charged_nodes.lock().map_err(|_|"terminal original commitments poisoned")?.get(peer.sender())
        .map(|r|r.receipt_sha256.clone()).ok_or("no actual original receiver resource ACK")?;
    if commitment!=expected{return Err("terminal challenge not bound to SAME pre-Create resource commitment".into());}
    {let mut state=node.progress.lock().map_err(|_|"terminal issuer registration poisoned")?;
        if state.grant_issued||state.registration_nonce.is_some(){return Err("terminal grant already attempted; no challenge retry".into());}
        state.registration_nonce=Some(nonce.clone());state.grant_issued=true;}
    append_issuer(&round,&node,1,peer.read_challenge().binding()).await?;
    let observed=core::observe_issuer(&node.scope.owner.volume_uid,peer.read_challenge()).await?;
    let directory=check_issuer_observation(&round,&node,&observed)?;
    let remaining_ms=u64::try_from(round.deadline.saturating_duration_since(Instant::now()).as_millis()).map_err(|_|"terminal remaining budget overflow")?;
    if remaining_ms==0{return Err("terminal issuer original budget exhausted before session grant".into());}
    let reply=encode(&Reply::Grant{plan,node_job,nonce,session:session_for(&round,&node.node)?,remaining_ms,
        revision:observed.revision().clone(),directory:directory.digest().into()})?;
    retain.finished=true;Ok(reply)
}
fn admit_native(round:&Arc<RegisteredDrainRound>,node:&Arc<RegisteredTerminalNode>,session:&Uid,sequence:u64,
    step:TerminalNativeStep,kind:TerminalBoundary,detail:&str,native:&str,result:Option<&str>)->Result<(),String>{
    if *session!=session_for(round,&node.node)?||!is_hash(detail)||!is_hash(native)||result.is_some_and(|value|!is_hash(value)){
        return Err("terminal native session/request/result binding malformed or changed".into());}
    if result.is_none()&&kind==TerminalBoundary::RetireLease{require_local_detached_confirmed(round)?;}
    let native_request=digest(&encode(&("terminal-actual-native-one-use-v1",step,kind,detail,native,result))?);
    {let mut consumed=node.consumed.lock().map_err(|_|"terminal actual native one-use set poisoned")?;
        if consumed.len()>=512||!consumed.insert(native_request){return Err("SAME actual terminal native request/outcome already admitted; no fresh RPC retry".into());}}
    let mut progress=node.progress.lock().map_err(|_|"terminal issuer node progress poisoned")?;
    if !progress.grant_issued||sequence==0||sequence>512||node.sequence.load(Ordering::Acquire).checked_add(1)!=Some(sequence){
        return Err("terminal native sequence skipped/replayed/over512 or node unregistered".into());}
    let writer=node.scope.mount_ref.node_uid()==&node.node;
    if result.is_some(){
        if !parent::irreversible(kind)||progress.current!=Some(step)
            ||progress.identities.get(&step).map(String::as_str)!=Some(native)
            ||!progress.pending.contains_key(&(kind,detail.into()))||progress.results.contains(&(kind,detail.into())){
            return Err("terminal outcome has no SAME admitted native irreversible effect".into());}
        progress.pending.remove(&(kind,detail.into()));progress.results.insert((kind,detail.into()));
    }else{
        round.require_live()?;
        if kind==TerminalBoundary::RetireLease{
            if step!=TerminalNativeStep::OfflineAndObserve||!progress.completed.contains(&step)||!round.detached.load(Ordering::Acquire){
                return Err("terminal lease retirement before actual all-node Detached confirmation".into());}
        }else{
            if !parent::allowed(step,kind,writer){return Err("terminal native effect outside closed step/role matrix".into());}
            if !progress.identities.contains_key(&step){
                let next=if writer&&!progress.completed.contains(&TerminalNativeStep::UnmountAndDemote){TerminalNativeStep::UnmountAndDemote}
                    else if !progress.completed.contains(&TerminalNativeStep::ObserveSecondarySynchronized){TerminalNativeStep::ObserveSecondarySynchronized}
                    else{TerminalNativeStep::OfflineAndObserve};
                if step!=next||kind!=TerminalBoundary::Start||!progress.pending.is_empty()
                    ||progress.current.is_some_and(|prior|!progress.completed.contains(&prior)){
                    return Err("terminal native step skipped/replayed or prior helper unresolved".into());}
                progress.identities.insert(step,native.into());progress.current=Some(step);
            }
            if progress.current!=Some(step)||progress.completed.contains(&step){return Err("terminal native step is not actual current helper".into());}
        }
        if progress.identities.get(&step).map(String::as_str)!=Some(native){return Err("terminal original native incarnation changed".into());}
        if parent::irreversible(kind){
            if progress.pending.contains_key(&(kind,detail.into()))||progress.results.contains(&(kind,detail.into())){
                return Err("terminal irreversible request already consumed; never retry".into());}
            progress.pending.insert((kind,detail.into()),native.into());
        }
        if kind==TerminalBoundary::Complete{
            if !progress.pending.is_empty()||!progress.completed.insert(step){return Err("terminal Complete has partial effects or is repeated".into());}
        }
    }
    node.sequence.store(sequence,Ordering::Release);Ok(())
}
async fn issuer_boundary(shared:&Arc<Shared>,peer:VerifiedPeerFrame)->Result<Vec<u8>,String>{
    let Request::NativeBoundary{plan,node_job,session,sequence,nonce,step,kind,detail,native_sha256}=decode(peer.body())?
        else{return Err("not closed terminal native boundary".into());};
    let round=issuer_round(shared,&plan)?;round.require_live()?;
    if peer.receiver()!=&shared.pool.node_uid{return Err("terminal boundary endpoint changed".into());}
    let node=expected_node(&round,peer.sender(),&node_job)?;
    let mut retain=RetainIssuerFailure{round:round.clone(),finished:false};
    admit_native(&round,&node,&session,sequence,step,kind,&detail,&native_sha256,None)?;
    append_issuer(&round,&node,610,peer.read_challenge().binding()).await?;
    let observed=core::observe_issuer(&node.scope.owner.volume_uid,peer.read_challenge()).await?;
    let directory=check_issuer_observation(&round,&node,&observed)?;
    round.require_live()?;
    let reply=encode(&Reply::Boundary{plan,node_job,session,sequence,nonce,kind,detail,revision:observed.revision().clone(),directory:directory.digest().into()})?;
    retain.finished=true;Ok(reply)
}
async fn issuer_result(shared:&Arc<Shared>,peer:VerifiedPeerFrame)->Result<Vec<u8>,String>{
    let Request::NativeResult{plan,node_job,session,sequence,nonce,step,kind,detail,result,native_sha256}=decode(peer.body())?
        else{return Err("not terminal effect result".into());};
    let round=issuer_round(shared,&plan)?;
    if peer.receiver()!=&shared.pool.node_uid{return Err("terminal result endpoint changed".into());}
    let node=expected_node(&round,peer.sender(),&node_job)?;
    let mut retain=RetainIssuerFailure{round:round.clone(),finished:false};
    // Matching admitted actual outcome is retained even if the original clock
    // crossed during syscall. This is DATA recording, never another grant.
    admit_native(&round,&node,&session,sequence,step,kind,&detail,&native_sha256,Some(&result))?;
    append_issuer(&round,&node,611,peer.read_challenge().binding()).await?;
    if Instant::now()>=round.deadline{round.mark_unknown();return Err("actual terminal result retained after original deadline; UNKNOWN".into());}
    let reply=encode(&Reply::ResultRecorded{plan,node_job,session,sequence,nonce})?;retain.finished=true;Ok(reply)
}
pub(super) async fn authorize_native(parent:Arc<VerifiedTerminalNodeParent>,boundary:&crate::storage_driver::dispatcher::VerifiedLocalBoundary,
    kind:TerminalBoundary,detail:&str)->Result<(),String>{
    let (step,native)=parent.native_binding(boundary,kind,detail)?;parent.require_live()?;
    if let Some(round)=parent.local_round(){
        let node=expected_node(round,&parent.scope().phase_node_uid,parent.node_job_uid())?;
        let sequence=node.sequence.load(Ordering::Acquire).checked_add(1).ok_or("terminal local sequence overflow")?;
        admit_native(round,&node,&session_for(round,&node.node)?,sequence,step,kind,detail,&native,None)?;
        let permission=local_observation(round,&node,610,TerminalEffect::NativeObservation,detail.into(),
            &(sequence,step,kind,detail,&native,boundary.binding())).await?;
        permission.consume_resource(detail)?;
        parent.require_live()
    }else{
        let receiver=parent.receiver_session().ok_or("genuine terminal parent has no accepted origin")?;
        receiver.require_accepted()?;
        let started=Instant::now();
        let before=core::observe_local_async(&parent.scope().owner.volume_uid).await?;
        let directory=if kind==TerminalBoundary::RetireLease{check_detached_observed(receiver,&before)?}
            else{check_current(parent.runtime(),parent.owner(),&receiver.prepared.source,&before,Some(parent.terminal_operation_uid()))?};
        let sequence=receiver.sequence.fetch_add(1,Ordering::AcqRel).checked_add(1).ok_or("terminal receiver sequence overflow")?;
        let nonce=Uid::new();let request=encode(&Request::NativeBoundary{plan:receiver.prepared.plan.clone(),node_job:receiver.prepared.node_job.clone(),
            session:receiver.session.clone(),sequence,nonce:nonce.clone(),step,kind,detail:detail.into(),native_sha256:native})?;
        let reply=parent.runtime().call(PATH,&request,&receiver.prepared.source.issuer,&directory).await?;
        let Reply::Boundary{plan,node_job,session,sequence:echo_sequence,nonce:echo,kind:echo_kind,detail:echo_detail,revision,directory:echo_directory}=decode(reply.body())?
            else{return Err("terminal issuer did not positively authorize exact native boundary".into());};
        if reply.sender()!=&receiver.prepared.source.issuer||reply.receiver()!=&parent.scope().phase_node_uid||plan!=receiver.prepared.plan
            ||node_job!=receiver.prepared.node_job||session!=receiver.session||echo_sequence!=sequence||echo!=nonce||echo_kind!=kind
            ||echo_detail!=detail||echo_directory!=receiver.directory||!revision.at_least(&receiver.issuer_revision){
            receiver.retain_unknown();return Err("terminal boundary reply does not match original challenge/session".into());}
        let fresh_deadline=started.checked_add(Duration::from_millis(core::MAX_STORAGE_BOUNDARY_MS)).ok_or("terminal boundary freshness overflow")?
            .min(parent.original_deadline());
        core::wait_applied_hint(&revision,fresh_deadline).await?;
        let after=core::observe_local_async(&parent.scope().owner.volume_uid).await?;
        if kind==TerminalBoundary::RetireLease{check_detached_observed(receiver,&after)?;}
        else{check_current(parent.runtime(),parent.owner(),&receiver.prepared.source,&after,Some(parent.terminal_operation_uid()))?;}
        if !after.revision().at_least(&revision)||Instant::now()>=fresh_deadline{return Err("terminal receiver actual applied boundary late/lagging".into());}
        receiver.require_accepted()?;parent.require_live()
    }
}
pub(super) async fn record_native_result(parent:Arc<VerifiedTerminalNodeParent>,boundary:&crate::storage_driver::dispatcher::VerifiedLocalBoundary,
    kind:TerminalBoundary,detail:&str,result:&str)->Result<(),String>{
    let (step,native)=parent.native_result_binding(boundary)?;
    if let Some(round)=parent.local_round(){
        let node=expected_node(round,&parent.scope().phase_node_uid,parent.node_job_uid())?;
        let sequence=node.sequence.load(Ordering::Acquire).checked_add(1).ok_or("terminal local result sequence overflow")?;
        admit_native(round,&node,&session_for(round,&node.node)?,sequence,step,kind,detail,&native,Some(result))?;
        let binding=digest(&encode(&(sequence,step,kind,detail,result,native,boundary.binding()))?);
        append_issuer(round,&node,611,&binding).await?;
        if Instant::now()>=round.deadline{round.mark_unknown();return Err("terminal native result retained late; no completion".into());}Ok(())
    }else{
        let receiver=parent.receiver_session().ok_or("terminal result actual session absent")?;
        let sequence=receiver.sequence.fetch_add(1,Ordering::AcqRel).checked_add(1).ok_or("terminal outcome sequence overflow")?;
        let nonce=Uid::new();let request=encode(&Request::NativeResult{plan:receiver.prepared.plan.clone(),node_job:receiver.prepared.node_job.clone(),
            session:receiver.session.clone(),sequence,nonce:nonce.clone(),step,kind,detail:detail.into(),result:result.into(),native_sha256:native})?;
        // Current authenticated directory is transport identity, not a fresh
        // effect grant. A late matching outcome is still sent/retained.
        let view=core::runtime_view(false).await?;let directory=VerifiedDirectory::from_runtime(&view)?;
        if directory.digest()!=receiver.directory{return Err("terminal actual result directory changed; retained UNKNOWN".into());}
        let reply=parent.runtime().call(PATH,&request,&receiver.prepared.source.issuer,&directory).await?;
        let Reply::ResultRecorded{plan,node_job,session,sequence:echo_sequence,nonce:echo}=decode(reply.body())?
            else{return Err("terminal effect result not acknowledged; retained UNKNOWN".into());};
        if reply.sender()!=&receiver.prepared.source.issuer||reply.receiver()!=&parent.scope().phase_node_uid||plan!=receiver.prepared.plan
            ||node_job!=receiver.prepared.node_job||session!=receiver.session||echo_sequence!=sequence||echo!=nonce{
            return Err("terminal result ACK changed original session/effect".into());}
        Ok(())
    }
}
fn accepted_for(prepared:&Arc<ReceiverPreparation>,session:&Uid,sender:&Uid)->Result<Arc<AcceptedTerminalReceiver>,String>{
    let receiver=prepared.accepted.try_lock().map_err(|_|"actual terminal accepted session busy")?.as_ref().cloned()
        .ok_or("terminal node has not accepted actual issuer registration")?;
    if &receiver.session!=session||sender!=&prepared.source.issuer{return Err("terminal node request is not exact authenticated accepted session".into());}
    receiver.require_accepted()?;Ok(receiver)
}
fn enqueue_node_data(prepared:&Arc<ReceiverPreparation>,step:TerminalNativeStep)->Result<(),String>{
    let parent=prepared.parent.try_lock().map_err(|_|"actual terminal parent root busy")?.as_ref().cloned().ok_or("actual terminal node parent absent")?;
    parent.require_live()?;
    {let pending=prepared.pending.try_lock().map_err(|_|"terminal same node pending state busy")?;
        if let Some(pending)=pending.as_ref(){
            if pending.step==step{return if pending.unknown{Err("original terminal node step UNKNOWN; no retry".into())}else{Ok(())};}
            if pending.unknown||pending.completed.is_none(){return Err("prior original terminal node step unresolved".into());}
        }}
    let mut state=prepared.book.state.try_lock().map_err(|_|"terminal original DATA slot busy")?;
    if state.consumer.pending.is_some(){return Err("same original one-slot controller already owns pending DATA".into());}
    state.consumer.mode.enter_drain()?;
    *prepared.pending.lock().map_err(|_|"terminal node pending state poisoned")?=Some(NodePending{step,ticket:None,completed:None,unknown:false,attempted:false,retired:None,retire_requested:false,retire_attempted:false,retirement:None});
    state.consumer.pending=Some(PendingConsumerData::DrainNode(prepared.clone()));
    // Neither this DATA ACK nor its DTO authorizes physical work. The same
    // original controller later moves the exact rooted parent/resources.
    prepared.book.invalid.store(true,Ordering::Release);Ok(())
}
async fn execute_request(shared:&Arc<Shared>,peer:VerifiedPeerFrame)->Result<Vec<u8>,String>{
    let Request::Execute{plan,node_job,session,nonce,step}=decode(peer.body())?else{return Err("not terminal node Execute DATA".into());};
    if peer.receiver()!=&shared.pool.node_uid{return Err("terminal Execute receiver differs".into());}
    let prepared=receiver_preparation(shared,&plan,&node_job)?;
    accepted_for(&prepared,&session,peer.sender())?;enqueue_node_data(&prepared,step)?;
    encode(&Reply::Accepted{plan,node_job,nonce,session})
}
async fn inspect_request(shared:&Arc<Shared>,peer:VerifiedPeerFrame)->Result<Vec<u8>,String>{
    let Request::Inspect{plan,node_job,session,nonce}=decode(peer.body())?else{return Err("not terminal node inspection DATA".into());};
    if peer.receiver()!=&shared.pool.node_uid{return Err("terminal Inspect receiver differs".into());}
    let prepared=receiver_preparation(shared,&plan,&node_job)?;accepted_for(&prepared,&session,peer.sender())?;
    let pending=prepared.pending.try_lock().map_err(|_|"terminal original ticket state busy")?;
    let pending=pending.as_ref().ok_or("terminal node step never accepted")?;
    if pending.unknown{return Err("original terminal physical work UNKNOWN; not empty/completed".into());}
    if let Some(retired)=pending.retired.as_ref(){
        if retired.node_uid()!=&shared.pool.node_uid||retired.volume_uid()!=&prepared.source.owner.volume_uid{
            return Err("terminal retired result is not SAME actual original node/volume".into());}
        return encode(&Reply::Retired{plan,node_job,nonce,evidence:retired.evidence_sha256().into()});
    }
    if let Some(actual)=pending.completed.as_ref(){
        let parent=prepared.parent.try_lock().map_err(|_|"terminal current actual parent busy")?.as_ref().cloned().ok_or("terminal parent absent")?;
        actual.require_parent(&parent)?;
        return encode(&Reply::Complete{plan,node_job,nonce,step:actual.step(),observation:actual.observation().clone(),completion:actual.completion_sha256().into()});
    }
    encode(&Reply::Pending{plan,node_job,nonce})
}
async fn drive_node_once(shared:&Arc<Shared>,prepared:&Arc<ReceiverPreparation>)->Result<(),String>{
    let parent=prepared.parent.try_lock().map_err(|_|"terminal node parent busy")?.as_ref().cloned().ok_or("original terminal node parent absent")?;
    parent.require_live()?;
    let resources=prepared.resources.try_lock().map_err(|_|"original terminal resource root busy")?.as_ref().cloned()
        .ok_or("actual pre-Create reservation absent; never reconstruct at drain")?;
    let already_complete={let state=prepared.pending.try_lock().map_err(|_|"terminal pending native state busy")?;
        let pending=state.as_ref().ok_or("original terminal node slot disappeared")?;
        if pending.unknown{return Err("original terminal node unresolved work UNKNOWN; no resubmission".into());}
        pending.completed.is_some()};
    if already_complete{return drive_retirement_once(shared,prepared,&parent).await;}
    let submit={let mut state=prepared.pending.try_lock().map_err(|_|"terminal pending native state busy")?;
        let pending=state.as_mut().ok_or("original terminal node slot disappeared")?;
        if pending.unknown{return Err("original terminal node unresolved work UNKNOWN; no resubmission".into());}
        if pending.completed.is_some(){return Err("terminal completion changed during original step admission".into());}
        if !pending.attempted{pending.attempted=true;Some(pending.step)}else{None}};
    if let Some(step)=submit{
        let runtime=shared.clone();let owner=prepared.owner.clone();let actual_parent=parent.clone();
        let ticket=shared.io.run(move||runtime.dispatcher.submit_terminal_phase(owner,actual_parent,resources,step)
            .map_err(terminal_enqueue_error)).await?;
        // The physical dispatcher roots the real work before returning. Root
        // the original ticket before any later checks/poll/transport reply.
        let mut pending=prepared.pending.lock().unwrap_or_else(|p|p.into_inner());
        pending.as_mut().ok_or("terminal node pending root absent after actual submit")?.ticket=Some(ticket);
    }
    let observed={let mut pending=prepared.pending.try_lock().map_err(|_|"terminal actual ticket busy")?;
        let pending=pending.as_mut().ok_or("terminal original pending state absent")?;
        pending.ticket.as_mut().ok_or("terminal attempted enqueue lacks original ticket; UNKNOWN")?.try_result()?};
    if let Some(drain)=observed{
        {let mut pending=prepared.pending.lock().unwrap_or_else(|p|p.into_inner());
            pending.as_mut().ok_or("terminal original pending root lost")?.completed=Some(drain.clone());} // before fallible validations.
        drain.require_parent(&parent)?;parent.require_live()?;
        let mut book=prepared.book.state.try_lock().map_err(|_|"terminal original DATA slot busy after drain")?;
        match book.consumer.pending.as_ref(){
            Some(PendingConsumerData::DrainNode(actual)) if Arc::ptr_eq(actual,prepared)=>book.consumer.pending=None,
            Some(PendingConsumerData::Drain(actual)) if actual.uid==prepared.plan=>(), // same leader group actor, no second slot
            _=>return Err("terminal completed native belongs to another original DATA slot".into()),
        }
    }Ok(())
}
/// SAME original Watch/controller loop only. No request task owns a helper or
/// waits for a terminal effect. Returning true suppresses ordinary READY work.
pub(in crate::storage_driver::native_runtime::mount) async fn poll_existing_slot(shared:&Arc<Shared>,book:&Arc<MountBook>)->Result<bool,String>{
    if !shared.controller_alive.load(Ordering::Acquire)||!Arc::ptr_eq(book.world(),&shared.world){return Err("original terminal controller/store not live".into());}
    let (pending,mode)={let state=book.state.try_lock().map_err(|_|"original terminal DATA slot busy")?;(state.consumer.pending.clone(),state.consumer.mode)};
    match pending{
        Some(PendingConsumerData::DrainNode(prepared))=>{
            let result=drive_node_once(shared,&prepared).await;
            if result.is_err(){prepared.failed.store(true,Ordering::Release);prepared.owner.mark_unknown();
                if let Some(pending)=prepared.pending.lock().unwrap_or_else(|p|p.into_inner()).as_mut(){pending.unknown=true;}
                if let Some(parent)=prepared.parent.lock().unwrap_or_else(|p|p.into_inner()).as_ref(){parent.retain_unknown();}}
            Ok(true) // retain original slot/work even on UNKNOWN; never retry.
        },
        Some(PendingConsumerData::Drain(plan))=>{
            if !plan.registered.load(Ordering::Acquire){
                let result=super::run_original_drain(shared,plan.clone()).await;
                if result.is_err(){if let Some(round)=plan.round.lock().unwrap_or_else(|p|p.into_inner()).as_ref(){round.mark_unknown();}
                    plan.operation.invalidate("same original terminal actor failed/late; original ownership retained");}
            }
            Ok(true)
        },
        _=>Ok(mode!=ControllerMode::Operational),
    }
}
pub(super) enum CompletionOrigin {Local(Arc<VerifiedTerminalDrain>),Remote(VerifiedPeerFrame)}
pub(super) struct TerminalCompletion {
    node:Uid,scope:ExpectedAttachScope,step:TerminalNativeStep,
    observation:crate::storage_driver::replica::initialize::managed_mount::terminal::TerminalPhysicalObservation,
    completion:String,origin:CompletionOrigin,
}
impl TerminalCompletion {
    pub(super) fn observation(&self)->&crate::storage_driver::replica::initialize::managed_mount::terminal::TerminalPhysicalObservation{&self.observation}
    pub(super) fn completion_sha256(&self)->&str{&self.completion}
    pub(super) fn require_original(&self,round:&Arc<RegisteredDrainRound>)->Result<(),String>{
        round.require_live()?;
        let node=round.node_jobs.try_lock().map_err(|_|"terminal proof original nodes busy")?.get(&self.node).cloned().ok_or("terminal proof node not original")?;
        if self.scope!=node.scope||!is_hash(&self.completion){return Err("terminal completion source/native hash differs from original".into());}
        self.observation.validate(&self.scope,&round.plan.uid,self.step)?;
        if !node.progress.try_lock().map_err(|_|"terminal proof issuer progress busy")?.completed.contains(&self.step){
            return Err("terminal report lacks actual fresh Complete permission on registered node chain".into());}
        match &self.origin{
            CompletionOrigin::Local(drain)=>{
                let prepared=receiver_preparation(&round.shared,&round.plan.uid,&node.uid)?;
                let parent=prepared.parent.try_lock().map_err(|_|"terminal actual proof parent busy")?.as_ref().cloned().ok_or("terminal proof parent absent")?;
                drain.require_parent(&parent)?;
                if drain.step()!=self.step||drain.completion_sha256()!=self.completion{return Err("terminal proof differs from actual original supervisor drain".into());}
            },
            CompletionOrigin::Remote(peer)=>if peer.sender()!=&self.node||peer.receiver()!=&round.shared.pool.node_uid{
                return Err("terminal report was not received through actual authenticated expected node transport".into());
            },
        }Ok(())
    }
}
pub(super) async fn execute_node(round:&Arc<RegisteredDrainRound>,node:&Uid,step:TerminalNativeStep)->Result<Arc<TerminalCompletion>,String>{
    round.require_live()?;let expected=round.node_jobs.try_lock().map_err(|_|"original terminal target table busy")?.get(node).cloned().ok_or("terminal target outside original group")?;
    let observed=if node==&round.shared.pool.node_uid{
        let prepared=receiver_preparation(&round.shared,&round.plan.uid,&expected.uid)?;
        {let mut pending=prepared.pending.try_lock().map_err(|_|"terminal local pending state busy")?;
            if pending.as_ref().is_some_and(|p|p.unknown||p.completed.is_none()){
                return Err("original local terminal helper is unresolved; no repeated step".into());}
            *pending=Some(NodePending{step,ticket:None,completed:None,unknown:false,attempted:false,retired:None,retire_requested:false,retire_attempted:false,retirement:None});}
        loop{
            round.require_live()?;drive_node_once(&round.shared,&prepared).await?;
            let complete=prepared.pending.try_lock().map_err(|_|"terminal local completion root busy")?.as_ref().and_then(|p|p.completed.clone());
            if let Some(drain)=complete{break Arc::new(TerminalCompletion{node:node.clone(),scope:expected.scope.clone(),step,
                observation:drain.observation().clone(),completion:drain.completion_sha256().into(),origin:CompletionOrigin::Local(drain)});}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }else{
        let directory=VerifiedDirectory::from_runtime(&core::runtime_view(true).await?)?;
        if directory.digest()!=round.directory{return Err("terminal actual directory changed before Execute".into());}
        let session=session_for(round,node)?;let nonce=Uid::new();
        let request=encode(&Request::Execute{plan:round.plan.uid.clone(),node_job:expected.uid.clone(),session:session.clone(),nonce:nonce.clone(),step})?;
        let accepted=round.shared.call(PATH,&request,node,&directory).await?; // once only, never retry a lost ACK
        let Reply::Accepted{plan,node_job,nonce:echo,session:echo_session}=decode(accepted.body())?else{return Err("terminal receiver did not accept original node DATA".into());};
        if accepted.sender()!=node||accepted.receiver()!=&round.shared.pool.node_uid||plan!=round.plan.uid||node_job!=expected.uid||echo!=nonce||echo_session!=session{
            return Err("terminal Execute ACK differs from exact original session/node/step".into());}
        loop{
            round.require_live()?;let nonce=Uid::new();
            let request=encode(&Request::Inspect{plan:round.plan.uid.clone(),node_job:expected.uid.clone(),session:session.clone(),nonce:nonce.clone()})?;
            let peer=round.shared.call(PATH,&request,node,&directory).await?;
            if peer.sender()!=node||peer.receiver()!=&round.shared.pool.node_uid{return Err("terminal completion peer differs".into());}
            match decode(peer.body())?{
                Reply::Pending{plan,node_job,nonce:echo} if plan==round.plan.uid&&node_job==expected.uid&&echo==nonce=>(),
                Reply::Complete{plan,node_job,nonce:echo,step:actual_step,observation,completion}
                    if plan==round.plan.uid&&node_job==expected.uid&&echo==nonce&&actual_step==step=>{
                    break Arc::new(TerminalCompletion{node:node.clone(),scope:expected.scope.clone(),step,observation,completion,origin:CompletionOrigin::Remote(peer)});
                },
                _=>return Err("terminal completion is not original actual accepted node step".into()),
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    // Root the actual object/frame BEFORE fallible full-scope/proof checks.
    round.completions.lock().unwrap_or_else(|p|p.into_inner()).insert((node.clone(),step),observed.clone());
    observed.require_original(round)?;Ok(observed)
}
pub(super) fn require_local_detached_confirmed(round:&Arc<RegisteredDrainRound>)->Result<(),String>{
    round.require_live()?;
    if !round.detached.load(Ordering::Acquire){return Err("terminal actual Detached ACK absent".into());}
    let prepared=round.metadata.try_lock().map_err(|_|"terminal actual Detached metadata root busy")?.iter()
        .find(|p|p.kind()==commit::MetadataKind::CommitDetached).cloned().ok_or("terminal actual Detached producer absent")?;
    prepared.require_confirmed()?;
    let evidence=round.detached_evidence.try_lock().map_err(|_|"terminal original Detached evidence busy")?.clone().ok_or("terminal actual Detached evidence absent")?;
    let world=round.shared.world.try_read().map_err(|_|"terminal actual Detached current source busy")?;
    round.check_world(&world)?;
    let uid=round.plan.operation.key.references.keys().next().ok_or("terminal actual Detached V1 absent")?;
    crate::storage_lifecycle::pod_attachment::check_terminal_detached_receipt_data(
        world.storage_identities.lifecycle.get(uid).ok_or("terminal actual Detached volume absent")?,&round.plan.uid,&evidence)
}
fn check_detached_observed(receiver:&AcceptedTerminalReceiver,observed:&core::CoreObservation)->Result<VerifiedDirectory,String>{
    receiver.require_detached_confirmed()?;
    let prepared=&receiver.prepared;
    let directory=prepared.shared.directory_for(observed)?;
    let minimum=receiver.detached.try_lock().map_err(|_|"terminal actual confirmed Detached revision busy")?.clone().ok_or("terminal confirmed Detached revision absent")?;
    if observed.local_node_uid()!=Some(&prepared.scope.phase_node_uid)||observed.actual_boot()!=&prepared.scope.phase_boot
        ||!observed.revision().at_least(&minimum)||directory.digest()!=receiver.directory{
        return Err("terminal post-Detached actual node/boot/revision/directory changed".into());}
    let world=prepared.shared.world.try_read().map_err(|_|"terminal actual Detached receiver source busy")?;
    let volume=world.storage_identities.lifecycle.get(&prepared.source.owner.volume_uid).ok_or("terminal Detached volume absent")?;
    let claim=world.storage_identities.claims.get(&crate::store::obj_key(&prepared.source.owner.namespace,&prepared.source.owner.claim_name))
        .ok_or("terminal post-Detached original claim identity absent")?;
    if world.generation!=observed.revision().desired_generation||volume!=observed.volume()
        ||volume.owner()!=&prepared.source.owner||volume.pod_writer()!=Some(&prepared.scope.pod_writer)
        ||volume.data_generation()!=Some(&prepared.scope.generation)||volume.epoch()!=prepared.scope.mount_ref.epoch()
        ||claim.uid!=prepared.source.owner.claim_uid||claim.namespace_uid!=prepared.source.owner.namespace_uid
        ||world.storage_identities.namespaces.get(&prepared.source.owner.namespace)!=Some(&prepared.source.owner.namespace_uid)
        ||world.storage_identities.volumes.get(&prepared.source.owner.pv_name)!=Some(&prepared.source.owner.volume_uid){
        return Err("terminal actual post-Detached source/namespace/PV/group differs".into());}
    check_current_bound_objects(&prepared.shared,&world,&prepared.source.owner)?;
    let workload=crate::store::obj_key(prepared.scope.pod_writer.namespace(),prepared.scope.pod_writer.workload());
    if world.deployments.contains_key(&workload){return Err("terminal desired removal source reappeared".into());}
    Ok(directory)
}
async fn confirm_detached_request(shared:&Arc<Shared>,peer:VerifiedPeerFrame,request_deadline:Instant)->Result<Vec<u8>,String>{
    let Request::ConfirmDetached{plan,node_job,session,nonce,revision,evidence}=decode(peer.body())?
        else{return Err("not terminal actual Detached confirmation DATA".into());};
    if !is_hash(&evidence)||peer.receiver()!=&shared.pool.node_uid{return Err("terminal Detached confirmation malformed/wrong receiver".into());}
    let prepared=receiver_preparation(shared,&plan,&node_job)?;
    let receiver=accepted_for(&prepared,&session,peer.sender())?;
    let parent=prepared.parent.try_lock().map_err(|_|"terminal actual Detached parent busy")?.as_ref().cloned().ok_or("terminal parent absent")?;
    let drain=prepared.pending.try_lock().map_err(|_|"terminal actual final offline root busy")?.as_ref()
        .and_then(|p|(!p.unknown&&p.step==TerminalNativeStep::OfflineAndObserve).then(||p.completed.clone()).flatten())
        .ok_or("terminal Detached confirmation lacks SAME actual final offline drain")?;
    drain.require_parent(&parent)?;
    core::wait_applied_hint(&revision,request_deadline.min(receiver.deadline)).await?;
    let observed=core::observe_local_async(&prepared.source.owner.volume_uid).await?;
    let directory=shared.directory_for(&observed)?;
    if directory.digest()!=receiver.directory||!observed.revision().at_least(&revision)
        ||observed.actual_boot()!=&prepared.scope.phase_boot||observed.local_node_uid()!=Some(&shared.pool.node_uid){
        return Err("terminal receiver has not actually applied exact Detached confirmation scope".into());}
    crate::storage_lifecycle::pod_attachment::check_terminal_detached_receipt_data(observed.volume(),&plan,&evidence)?;
    // This is current acknowledgement DATA only. RetireLease still performs
    // a distinct fresh request-bound issuer quorum grant for EACH close.
    *receiver.detached.lock().unwrap_or_else(|p|p.into_inner())=Some(observed.revision().clone());
    *receiver.detached_evidence.lock().unwrap_or_else(|p|p.into_inner())=Some(evidence);
    check_detached_observed(&receiver,&observed)?;
    if Instant::now()>=request_deadline{return Err("terminal Detached confirmation DATA late; no retirement grant".into());}
    encode(&Reply::DetachedConfirmed{plan,node_job,nonce,revision:observed.revision().clone()})
}
fn enqueue_retirement(prepared:&Arc<ReceiverPreparation>)->Result<(),String>{
    let parent=prepared.parent.try_lock().map_err(|_|"terminal retirement actual parent busy")?.as_ref().cloned().ok_or("terminal retirement parent absent")?;
    parent.require_detached_confirmed()?;
    {let mut pending=prepared.pending.try_lock().map_err(|_|"terminal actual retirement state busy")?;
        let pending=pending.as_mut().ok_or("terminal actual final offline result absent")?;
        if pending.unknown||pending.step!=TerminalNativeStep::OfflineAndObserve||pending.completed.is_none(){return Err("terminal retirement lacks known original offline drain".into());}
        if pending.retire_requested{return Ok(());} // duplicate DATA, never another effect/clock
        pending.retire_requested=true;}
    let mut state=prepared.book.state.try_lock().map_err(|_|"terminal actual retirement DATA slot busy")?;
    match state.consumer.pending.as_ref(){
        None=>state.consumer.pending=Some(PendingConsumerData::DrainNode(prepared.clone())),
        Some(PendingConsumerData::Drain(plan)) if plan.uid==prepared.plan=>(),
        Some(PendingConsumerData::DrainNode(actual)) if Arc::ptr_eq(actual,prepared)=>(),
        _=>return Err("terminal retirement cannot replace occupied original DATA slot".into()),
    }
    state.consumer.mode.enter_drain()?;Ok(())
}
async fn retire_request(shared:&Arc<Shared>,peer:VerifiedPeerFrame)->Result<Vec<u8>,String>{
    let Request::RetireLease{plan,node_job,session,nonce}=decode(peer.body())?else{return Err("not terminal final retirement DATA".into());};
    if peer.receiver()!=&shared.pool.node_uid{return Err("terminal retirement endpoint changed".into());}
    let prepared=receiver_preparation(shared,&plan,&node_job)?;let accepted=accepted_for(&prepared,&session,peer.sender())?;
    accepted.require_detached_confirmed()?;enqueue_retirement(&prepared)?;
    encode(&Reply::Accepted{plan,node_job,nonce,session})
}
async fn drive_retirement_once(shared:&Arc<Shared>,prepared:&Arc<ReceiverPreparation>,parent:&Arc<VerifiedTerminalNodeParent>)->Result<(),String>{
    let submit={let mut pending=prepared.pending.try_lock().map_err(|_|"terminal actual retirement root busy")?;
        let pending=pending.as_mut().ok_or("terminal actual final offline state absent")?;
        if pending.unknown{return Err("terminal original retirement UNKNOWN; no resubmission".into());}
        if !pending.retire_requested||pending.retired.is_some(){return Ok(());}
        if pending.retire_attempted{None}else{pending.retire_attempted=true;Some(pending.completed.as_ref().cloned().ok_or("terminal actual final drain absent")?)}};
    parent.require_detached_confirmed()?;
    if let Some(drain)=submit{
        let runtime=shared.clone();let owner=prepared.owner.clone();let current=parent.clone();
        let resources=prepared.resources.try_lock().map_err(|_|"terminal actual retirement reservation busy")?.as_ref().cloned().ok_or("terminal original pre-Create reservation absent")?;
        // Enqueue-only on fixed IO. The actual callbacks/irreversible closes
        // run on the EXISTING dispatcher thread, so their Journal IO cannot
        // deadlock on the inspector or block a Tokio request handler.
        let ticket=shared.io.run(move||runtime.dispatcher.submit_terminal_retirement(owner,current,resources,drain)
            .map_err(terminal_enqueue_error)).await?;
        prepared.pending.lock().unwrap_or_else(|p|p.into_inner()).as_mut().ok_or("terminal retirement root disappeared after actual enqueue")?.retirement=Some(ticket);
    }
    let actual={let pending=prepared.pending.try_lock().map_err(|_|"terminal original retirement ticket busy")?;
        pending.as_ref().ok_or("terminal original retirement state absent")?.retirement.as_ref().ok_or("terminal retirement attempted without original ticket")?.try_result()?};
    if let Some(retired)=actual{
        prepared.pending.lock().unwrap_or_else(|p|p.into_inner()).as_mut().ok_or("terminal retirement result root disappeared")?.retired=Some(retired.clone());
        if retired.node_uid()!=&shared.pool.node_uid||retired.volume_uid()!=&prepared.source.owner.volume_uid||!is_hash(retired.evidence_sha256()){
            return Err("actual terminal retired result differs from original retained node/group".into());}
        parent.require_detached_confirmed()?;
        let mut state=prepared.book.state.try_lock().map_err(|_|"terminal final original retirement DATA slot busy")?;
        match state.consumer.pending.as_ref(){
            Some(PendingConsumerData::DrainNode(actual)) if Arc::ptr_eq(actual,prepared)=>state.consumer.pending=None,
            Some(PendingConsumerData::Drain(plan)) if plan.uid==prepared.plan=>(),
            _=>return Err("terminal final retirement belongs to another original DATA slot".into()),
        }
    }Ok(())
}
pub(super) async fn confirm_and_retire_all(round:&Arc<RegisteredDrainRound>)->Result<(),String>{
    require_local_detached_confirmed(round)?;
    let observed=core::observe_local_async(round.plan.operation.key.references.keys().next().ok_or("terminal actual volume absent")?).await?;
    let directory=round.shared.directory_for(&observed)?;
    let evidence=round.detached_evidence.try_lock().map_err(|_|"terminal actual Detached evidence busy")?.clone().ok_or("terminal actual Detached evidence absent")?;
    let nodes=round.node_jobs.try_lock().map_err(|_|"terminal retirement actual node set busy")?.values().cloned().collect::<Vec<_>>();
    for node in nodes{
        require_local_detached_confirmed(round)?;
        if node.node==round.shared.pool.node_uid{
            let prepared=receiver_preparation(&round.shared,&round.plan.uid,&node.uid)?;
            enqueue_retirement(&prepared)?;
            let parent=prepared.parent.try_lock().map_err(|_|"terminal actual local retirement parent busy")?.as_ref().cloned().ok_or("terminal original local parent absent")?;
            loop{
                require_local_detached_confirmed(round)?;drive_retirement_once(&round.shared,&prepared,&parent).await?;
                if prepared.pending.try_lock().map_err(|_|"terminal actual local retirement result busy")?.as_ref().is_some_and(|p|p.retired.is_some()){break;}
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }else{
            let session=session_for(round,&node.node)?;let nonce=Uid::new();
            let request=encode(&Request::ConfirmDetached{plan:round.plan.uid.clone(),node_job:node.uid.clone(),session:session.clone(),nonce:nonce.clone(),
                revision:observed.revision().clone(),evidence:evidence.clone()})?;
            let reply=round.shared.call(PATH,&request,&node.node,&directory).await?;
            let Reply::DetachedConfirmed{plan,node_job,nonce:echo,revision}=decode(reply.body())?else{return Err("terminal actual receiver Detached confirmation absent".into());};
            if reply.sender()!=&node.node||reply.receiver()!=&round.shared.pool.node_uid||plan!=round.plan.uid||node_job!=node.uid||echo!=nonce
                ||!revision.at_least(observed.revision()){return Err("terminal receiver Detached confirmation differs from actual ACK scope".into());}
            let nonce=Uid::new();let request=encode(&Request::RetireLease{plan:round.plan.uid.clone(),node_job:node.uid.clone(),session:session.clone(),nonce:nonce.clone()})?;
            let reply=round.shared.call(PATH,&request,&node.node,&directory).await?; // once-only DATA admission
            let Reply::Accepted{plan,node_job,nonce:echo,session:echo_session}=decode(reply.body())?else{return Err("terminal receiver did not accept original retirement DATA".into());};
            if reply.sender()!=&node.node||reply.receiver()!=&round.shared.pool.node_uid||plan!=round.plan.uid||node_job!=node.uid||echo!=nonce||echo_session!=session{
                return Err("terminal retirement DATA ACK differs from original node/session".into());}
            loop{
                require_local_detached_confirmed(round)?;let nonce=Uid::new();
                let request=encode(&Request::Inspect{plan:round.plan.uid.clone(),node_job:node.uid.clone(),session:session.clone(),nonce:nonce.clone()})?;
                let peer=round.shared.call(PATH,&request,&node.node,&directory).await?;
                if peer.sender()!=&node.node||peer.receiver()!=&round.shared.pool.node_uid{return Err("terminal retirement result authenticated endpoint differs".into());}
                match decode(peer.body())?{
                    Reply::Retired{plan,node_job,nonce:echo,evidence}if plan==round.plan.uid&&node_job==node.uid&&echo==nonce&&is_hash(&evidence)=>{
                        // Retain the authenticated actual result before any
                        // later check; it cannot reconstruct a local lease.
                        round.retired_receivers.lock().unwrap_or_else(|p|p.into_inner()).insert(node.node.clone(),(evidence,peer));break;
                    },
                    Reply::Pending{plan,node_job,nonce:echo}if plan==round.plan.uid&&node_job==node.uid&&echo==nonce=>(),
                    Reply::Complete{plan,node_job,nonce:echo,..}if plan==round.plan.uid&&node_job==node.uid&&echo==nonce=>(), // final original dispatcher retirement still pending
                    _=>return Err("terminal original retirement result is not current exact node/session".into()),
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }require_local_detached_confirmed(round)
}
pub(super) fn retirement_evidence(round:&Arc<RegisteredDrainRound>)->Result<BTreeMap<Uid,String>,String>{
    require_local_detached_confirmed(round)?;
    let nodes=round.node_jobs.try_lock().map_err(|_|"actual retired original node set busy")?.values().cloned().collect::<Vec<_>>();
    let mut result=BTreeMap::new();
    for node in nodes{
        let evidence=if node.node==round.shared.pool.node_uid{
            let prepared=receiver_preparation(&round.shared,&round.plan.uid,&node.uid)?;
            let retired=prepared.pending.try_lock().map_err(|_|"actual local retired lease root busy")?.as_ref()
                .and_then(|p|p.retired.clone()).ok_or("no actual typed local retired original lease")?;
            if retired.node_uid()!=&node.node||retired.volume_uid()!=&node.scope.owner.volume_uid{return Err("actual local retired lease scope differs".into());}
            retired.evidence_sha256().to_string()
        }else{
            let results=round.retired_receivers.try_lock().map_err(|_|"actual remote retirement roots busy")?;
            let (evidence,peer)=results.get(&node.node).ok_or("actual remote retirement acknowledgement absent")?;
            if peer.sender()!=&node.node||peer.receiver()!=&round.shared.pool.node_uid{return Err("actual retired peer scope differs".into());}
            evidence.clone()
        };
        if !is_hash(&evidence)||result.insert(node.node.clone(),evidence).is_some(){return Err("actual retired group malformed/repeated".into());}
    }
    if result.len()!=3{return Err("all three actual retirements required".into());}Ok(result)
}
pub(in crate::storage_driver::native_runtime) async fn handle(shared:&Arc<Shared>,peer:VerifiedPeerFrame,deadline:Instant)->Result<Vec<u8>,String>{
    if !shared.config.attaches()||!shared.controller_alive.load(Ordering::Acquire)||Instant::now()>=deadline{
        return Err("terminal route requires explicitv3 SAME live original controller and request budget".into());}
    let request=decode::<Request>(peer.body())?;
    // Late matching outcomes are DATA, not permission. Preserve their chance
    // to be recorded through the original held Journal even when config has
    // changed. EVERY positive request still re-pins the exact private bytes.
    if !matches!(&request,Request::NativeResult{..}){shared.check_attach_config().await?;}
    if Instant::now()>=deadline{return Err("terminal request original transport budget expired".into());}
    match request{
        Request::PrepareResources{..}=>prepare_receiver(shared,peer,deadline).await,
        Request::RegisterNode{..}=>register_receiver(shared,peer,deadline).await,
        Request::RegisterChallenge{..}=>issuer_registration(shared,peer).await,
        Request::NativeBoundary{..}=>issuer_boundary(shared,peer).await,
        Request::NativeResult{..}=>issuer_result(shared,peer).await,
        Request::Execute{..}=>execute_request(shared,peer).await,
        Request::Inspect{..}=>inspect_request(shared,peer).await,
        Request::ConfirmDetached{..}=>confirm_detached_request(shared,peer,deadline).await,
        Request::RetireLease{..}=>retire_request(shared,peer).await,
    }
}
fn terminal_enqueue_error(error:crate::storage_driver::dispatcher::attachment::RetainedAttachError)->String{
    use crate::storage_driver::dispatcher::attachment::RetainedAttachError::*;
    match error{Unavailable(error)=>format!("terminal unavailable: {error}"),NeverSubmitted(error)=>format!("terminal proven not enqueued: {error}"),
        Unknown(error)=>format!("terminal original enqueue UNKNOWN: {error}")}
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test] fn terminal_wire_is_closed_bounded_data_not_raw_stop_kill_or_authority(){
        for raw in [br#"{"command":"Stop","container":"name"}"#.as_slice(),br#"{"command":"Kill","signal":"SIGKILL"}"#,
            br#"{"command":"Finish","completed":true}"#,br#"{"command":"RetireLease","scope":{},"default_authority":true}"#]{
            assert!(decode::<Request>(raw).is_err());
        }
        assert!(decode::<Request>(&vec![b'x';32*1024+1]).is_err());
    }
    #[test] fn terminal_inspect_data_preserves_exact_original_session_without_constructing_owner(){
        let plan=Uid::new();let node_job=Uid::new();let session=Uid::new();let nonce=Uid::new();
        let bytes=encode(&Request::Inspect{plan:plan.clone(),node_job:node_job.clone(),session:session.clone(),nonce:nonce.clone()}).unwrap();
        match decode::<Request>(&bytes).unwrap(){Request::Inspect{plan:p,node_job:j,session:s,nonce:n}=>{
            assert_eq!(p,plan);assert_eq!(j,node_job);assert_eq!(s,session);assert_eq!(n,nonce);
        },_=>panic!("closed DATA kind changed")}
        let mut value:serde_json::Value=serde_json::from_slice(&bytes).unwrap();value["authority"]=serde_json::json!(true);
        assert!(decode::<Request>(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(receiver_deadline_data(Instant::now(),0).is_err());
        assert!(receiver_deadline_data(Instant::now(),180001).is_err());
    }
    #[test] fn terminal_shortened_grant_uses_original_challenge_clock_not_delayed_receipt(){
        let challenge=Instant::now();let receipt=challenge+Duration::from_millis(200);
        let deadline=receiver_deadline_data(challenge,500).unwrap();
        assert_eq!(deadline,challenge+Duration::from_millis(500));assert_ne!(deadline,receipt+Duration::from_millis(500));
        assert!(receipt<deadline);assert!(challenge+Duration::from_millis(501)>=deadline);
    }
}
