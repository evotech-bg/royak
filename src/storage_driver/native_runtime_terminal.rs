//! Genuine drain-only continuation of the original managed operation.
//! No persisted/read/wire authority constructor, no UNKNOWN reset or retry.
use super::*;
use std::fs::File;
use std::os::fd::{AsRawFd,IntoRawFd};
use std::os::unix::fs::MetadataExt;
#[path="native_terminal_process.rs"]
mod process;
pub(super) use process::OriginalProcessPin;
#[path="native_terminal_parent.rs"]
mod parent;
pub(crate) use parent::{VerifiedTerminalNodeParent,TerminalNativeStep,TerminalBoundary};
#[path="native_terminal_protocol.rs"]
pub(in crate::storage_driver::native_runtime) mod wire;
#[path="native_terminal_commit.rs"]
pub(crate) mod commit;

pub(crate) const PATH:&str="/_royak/storage/managed-terminal-v1";
/// Actual scoped original task lifetime; this negative-only flag cannot
/// manufacture an operation, process pin, parent or permission.
pub(in crate::storage_driver::native_runtime) struct OriginalControllerGuard {shared:Arc<Shared>}
impl OriginalControllerGuard {
    pub(in crate::storage_driver::native_runtime) fn enter(shared:Arc<Shared>)->Self{
        shared.controller_alive.store(true,Ordering::Release);Self{shared}
    }
}
impl Drop for OriginalControllerGuard {fn drop(&mut self){self.shared.controller_alive.store(false,Ordering::Release);}}
#[derive(Clone,Debug,serde::Serialize)]
pub(crate) struct TerminalSubmission {pub(crate) operation:Uid,pub(crate) terminal:Uid,pub(crate) status:&'static str}
/// Normal desired-removal DATA adapter. Exact original CID lookup precedes
/// any selector use; no IO/await/quorum or owner construction here.
pub(crate) fn submit_retirement_data(namespace:&str,pod:&str,cid:&str)->Result<TerminalSubmission,String>{
    if cid.len()!=64||!cid.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){
        return Err("terminal DATA NeverAccepted: exact full owned CID required".into());}
    let book=ROOTED_BOOK.get().ok_or("terminal DATA NeverAccepted: no original book")?.clone();
    let shared=book.shared.upgrade().ok_or("terminal DATA NeverAccepted: original runtime disappeared")?;
    if !shared.controller_alive.load(Ordering::Acquire)||!core::is_actual_world(&book.world){
        return Err("terminal DATA NeverAccepted: original actor is not live; no adoption".into());}
    let mut state=book.state.try_lock().map_err(|_|"terminal DATA NeverAccepted: original book busy")?;
    let operation=state.consumer.history.values().find(|op|op.key.namespace==namespace&&op.key.pod==pod
        &&op.containers.try_lock().ok().is_some_and(|containers|containers.contains_key(cid))).cloned()
        .ok_or("terminal DATA NeverAccepted: CID/namespace/pod not same actual operation")?;
    let plan=operation.terminal_plan.try_lock().map_err(|_|"terminal original plan busy")?
        .as_ref().cloned().ok_or("terminal DATA NeverAccepted: no pre-Create terminal plan")?;
    if let Some(PendingConsumerData::Drain(original))=state.consumer.pending.as_ref(){
        if Arc::ptr_eq(original,&plan){return Ok(plan.submission());}
    }
    if plan.registered.load(Ordering::Acquire){return Ok(plan.submission());}
    {
        let current=book.world.try_read().map_err(|_|"terminal DATA actual source busy")?;
        if !removal_source_absent(&current,&operation.key){return Err("terminal DATA NeverAccepted: original workload still present; not a removal grant".into());}
    }
    if state.consumer.pending.is_some(){return Err("terminal DATA NeverAccepted: same original launch/node slot still occupied".into());}
    state.consumer.mode.enter_drain()?;
    plan.accept_original_clock()?;
    state.consumer.pending=Some(PendingConsumerData::Drain(plan.clone()));
    // Negative latches only. Preserve all canonical metadata/desired state and
    // ordinary UNKNOWN. Actor later obtains a DISTINCT fresh drain permission.
    operation.status.store(UNKNOWN,Ordering::Release);book.invalid.store(true,Ordering::Release);
    Ok(plan.submission())
}
fn removal_source_absent(world:&DesiredWorld,key:&LaunchKey)->bool{
    removal_source_absent_data(world,&key.namespace,&key.namespace_uid,&key.workload)
}
fn removal_source_absent_data(world:&DesiredWorld,namespace:&str,namespace_uid:&Uid,workload:&str)->bool{
    world.storage_identities.namespaces.get(namespace)==Some(namespace_uid)
        &&!world.deployments.contains_key(&crate::store::obj_key(namespace,workload))
}
fn discover_original_removed_operation(shared:&Arc<Shared>,book:&Arc<MountBook>)->Result<(),String>{
    if !shared.controller_alive.load(Ordering::Acquire){return Err("dead original actor cannot discover retirement".into());}
    let originals={let state=book.state.try_lock().map_err(|_|"original removal discovery book busy")?;
        if state.consumer.pending.is_some()||state.consumer.mode==ControllerMode::Terminal{return Ok(());}
        state.consumer.history.values().cloned().collect::<Vec<_>>()};
    for operation in originals {
        {let world=book.world.try_read().map_err(|_|"actual removal source busy")?;
            if !removal_source_absent(&world,&operation.key){continue;}}
        let Some(plan)=operation.terminal_plan.try_lock().map_err(|_|"original terminal plan busy")?.as_ref().cloned()else{continue;};
        if plan.registered.load(Ordering::Acquire){continue;}
        let mut state=book.state.try_lock().map_err(|_|"original retirement DATA slot busy")?;
        if state.consumer.pending.is_some(){return Ok(());}
        if !state.consumer.history.get(&operation.uid).is_some_and(|same|Arc::ptr_eq(same,&operation)){
            return Err("original removal operation root changed".into());}
        state.consumer.mode.enter_drain()?;plan.accept_original_clock()?;
        state.consumer.pending=Some(PendingConsumerData::Drain(plan));
        operation.status.store(UNKNOWN,Ordering::Release);book.invalid.store(true,Ordering::Release);
        // This only submits DATA. Empty CID map is NEVER a no-start proof;
        // actual private never-submitted/PIDFD admission occurs on the actor.
        return Ok(());
    }Ok(())
}
fn latch_original_error(shared:&Arc<Shared>,book:&Arc<MountBook>,operation:Option<&Arc<ManagedPodOperation>>,reason:&str){
    if let Some(operation)=operation {operation.invalidate(reason);}
    shared.unknown(None,"TERMINAL_DRAIN_ONLY");
    let mut state=book.state.lock().unwrap_or_else(|p|p.into_inner());
    let _=state.consumer.mode.enter_drain();
    if let Some(operation)=operation {
        // Only the actually returned original launch future may relinquish
        // this DATA slot. Its real IO work is independently retained and a
        // drain cannot make a NeverSubmitted proof until that IO settles.
        if matches!(state.consumer.pending.as_ref(),Some(PendingConsumerData::Launch(same)) if Arc::ptr_eq(same,operation)){
            state.consumer.pending=None;
        }
    }
}
pub(super) async fn serve_original_consumer(shared:Arc<Shared>,book:Arc<MountBook>,interval:u64)->Result<(),String>{
    if interval==0||!shared.config.attaches(){return Err("original consumer actor requires explicitv3/nonzero unchanged cadence".into());}
    loop {
        if !shared.controller_alive.load(Ordering::Acquire){return Err("original controller lifetime ended; no actor adoption".into());}
        let mode=book.state.lock().map_err(|_|"original controller book poisoned")?.consumer.mode;
        if mode==ControllerMode::Operational {
            if shared.check_attach_config().await.is_err()||book.invalid.load(Ordering::Acquire){
                latch_original_error(&shared,&book,None,"original consumer configuration/lifetime UNKNOWN");
            }else{
                let pending=book.state.lock().map_err(|_|"original pending slot poisoned")?.consumer.pending.clone();
                if let Some(PendingConsumerData::Launch(operation))=pending {
                    let result=run_operation(&shared,operation.clone()).await;
                    retain_actual_launch_return(&operation);
                    if result.is_err(){latch_original_error(&shared,&book,Some(&operation),"original launch failed/late/ambiguous");}
                }
                let active={book.state.lock().map_err(|_|"original active roots poisoned")?.consumer.history.values()
                    .filter(|operation|operation.status.load(Ordering::Acquire)==RUNNING).cloned().collect::<Vec<_>>()};
                for operation in active {
                    let owned={operation.containers.lock().map_err(|_|"original CID roots poisoned")?.values()
                        .filter(|container|container.role!="init").cloned().collect::<Vec<_>>()};
                    for container in owned {
                        match inspect_current(&shared,&operation,container).await {
                            Ok(observed) if observed.running=>(),
                            _=>{latch_original_error(&shared,&book,Some(&operation),"original managed task changed/exited; drain-only");break;}
                        }
                    }
                }
            }
        }
        // Node service also runs on this SAME loop; no per-request task or
        // execution queue owns terminal physical work or its result.
        discover_original_removed_operation(&shared,&book)?;
        wire::poll_existing_slot(&shared,&book).await?;
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}
pub(in crate::storage_driver::native_runtime) async fn park_original_controller(shared:Arc<Shared>,interval:u64){
    if interval==0{return;}
    loop {
        if let Some(book)=ROOTED_BOOK.get(){
            if Arc::ptr_eq(book.world(),&shared.world){
                latch_original_error(&shared,book,None,"same original controller parked drain-only");
                let _=discover_original_removed_operation(&shared,book);
                // A poisoned/permanently failed service is not a new actor or
                // renewed attempt. Keep original owners and the same task.
                let _=wire::poll_existing_slot(&shared,book).await;
            }
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq,serde::Serialize,serde::Deserialize)]
pub(crate) enum TerminalEffect {SignalTerm,CloseProcessNamespace,FlushMount,CloseMounted,Unmount,
    CloseBlock,Demote,ObserveSecondary,Offline,Read,CloseRead,Complete,RetireLease,BeginDetaching,CommitDetached,NativeObservation}
#[derive(Clone,Copy,Debug,PartialEq,Eq,serde::Serialize)]
pub(super) enum ControllerMode {Operational,DrainOnly,Terminal}
impl ControllerMode {
    fn enter_drain(&mut self)->Result<(),String>{
        match self{Self::Operational=>{*self=Self::DrainOnly;Ok(())},Self::DrainOnly=>Ok(()),
            Self::Terminal=>Err("terminal original actor cannot reopen a drain/launch".into())}
    }
}
/// Minted ONLY after awaiting the original run_operation future on the SAME
/// controller. It is not a boolean/report saying Docker had no containers.
pub(super) struct FinishedLaunch {operation:Uid}
fn retain_actual_launch_return(operation:&Arc<ManagedPodOperation>){
    let mut slot=operation.launch_finished.lock().unwrap_or_else(|p|p.into_inner());
    if slot.is_none(){*slot=Some(Arc::new(FinishedLaunch{operation:operation.uid.clone()}));}
}
struct KnownOriginalNeverSubmitted {operation:Arc<ManagedPodOperation>,completion:Arc<FinishedLaunch>}
impl KnownOriginalNeverSubmitted {
    fn capture(shared:&Arc<Shared>,plan:&Arc<PreparedTerminalPlan>)->Result<Self,String>{
        plan.require_full_precharge()?;
        let operation=plan.operation.clone();
        if !shared.controller_alive.load(Ordering::Acquire)||shared.io.busy.load(Ordering::Acquire)!=0
            ||operation.status.load(Ordering::Acquire)!=UNKNOWN{
            return Err("known-never-submitted requires live original actor, revoked launch and settled SAME IO".into());}
        let state=operation.ready.book.state.try_lock().map_err(|_|"original no-submit book busy")?;
        if state.consumer.mode!=ControllerMode::DrainOnly{return Err("original launch is not monotonically revoked".into());}
        drop(state);
        let completion=operation.launch_finished.try_lock().map_err(|_|"original launch return poisoned")?
            .as_ref().cloned().ok_or("original launch future not actually returned")?;
        let result=Self{operation,completion};result.require_current()?;Ok(result)
    }
    fn require_current(&self)->Result<(),String>{
        if self.completion.operation!=self.operation.uid||self.operation.status.load(Ordering::Acquire)!=UNKNOWN{
            return Err("known-never-submitted differs from original revoked operation".into());}
        let slot=self.operation.launch_finished.try_lock().map_err(|_|"original launch return busy")?;
        if !slot.as_ref().is_some_and(|actual|Arc::ptr_eq(actual,&self.completion)){return Err("original launch return proof changed".into());}
        drop(slot);
        let actions=self.operation.actions.try_lock().map_err(|_|"original action roots busy")?;
        require_never_submitted_data(actions.values().map(|a|(Arc::ptr_eq(&a.operation,&self.operation),a.submitted.load(Ordering::Acquire))))?;
        let containers=self.operation.containers.try_lock().map_err(|_|"original CID roots busy")?;
        if !containers.is_empty(){return Err("known-never-submitted contradicts an actual Create receipt".into());}
        Ok(())
    }
}
fn require_never_submitted_data(actions:impl Iterator<Item=(bool,bool)>)->Result<(),String>{
    if actions.into_iter().any(|(same_original,may_have_submitted)|!same_original||may_have_submitted){
        return Err("original Materialize/Create/Start may have submitted or changed owner; never infer no-start".into());}
    Ok(())
}
#[derive(Clone,Debug,PartialEq,Eq,serde::Serialize)]
struct FileIdentity {number:i32,device:u64,inode:u64,rdev:u64,mode:u32}
impl FileIdentity {
    fn actual(file:&File)->Result<Self,String>{let m=file.metadata().map_err(|_|"original terminal FD metadata unavailable")?;
        Ok(Self {number:file.as_raw_fd(),device:m.dev(),inode:m.ino(),rdev:m.rdev(),mode:m.mode()})}
    fn digest(&self)->Result<String,String>{Ok(digest(&serde_json::to_vec(self).map_err(|_|"exact terminal FD binding encode")?))}
}
#[derive(Clone,Debug,serde::Serialize)]
enum CloseState {Prepared,Consumed{number:i32},Closed{number:i32},ErrorAfterConsume{number:i32,errno:Option<i32>}}
/// Root this INSIDE the original owner BEFORE close. It never owns a File
/// temporary that could drop on a failed precondition, and never reopens.
pub(crate) struct ClosedDescriptor {
    original:FileIdentity,state:CloseState,permission:Option<VerifiedTerminalEffect>,
}
impl ClosedDescriptor {
    pub(crate) fn prepare(permission:VerifiedTerminalEffect,file:&File,effect:TerminalEffect)->Result<Self,String>{
        let identity=FileIdentity::actual(file)?;
        permission.require_exact(effect,&identity.digest()?)?;
        Ok(Self{original:identity,state:CloseState::Prepared,permission:Some(permission)})
    }
    pub(crate) fn close(&mut self,slot:&mut Option<File>)->Result<(),String>{
        if !matches!(self.state,CloseState::Prepared){return Err("original FD close already consumed; never retry".into());}
        let file=slot.as_ref().ok_or("original descriptor slot absent; not proven closed")?;
        if FileIdentity::actual(file)?!=self.original{return Err("original descriptor slot changed before close".into());}
        let permission=self.permission.as_ref().ok_or("close lacks actual one-use effect permission")?;
        permission.consume_resource(&self.original.digest()?)?;
        // All fallible identity/authority checks precede taking the File. The
        // rooted state changes BEFORE libc and is never rolled back on error.
        let raw=slot.take().unwrap().into_raw_fd();self.state=CloseState::Consumed{number:raw};
        let result=unsafe{libc::close(raw)};
        let errno=if result==0{None}else{std::io::Error::last_os_error().raw_os_error()};
        self.state=if result==0{CloseState::Closed{number:raw}}else{CloseState::ErrorAfterConsume{number:raw,errno}};
        let facts=serde_json::to_vec(&(&self.original,&self.state)).map_err(|_|"consumed close state encode")?;
        let recorded=self.permission.as_ref().unwrap().record_result(&facts);
        if result!=0 {self.permission.as_ref().unwrap().unknown();return Err("original descriptor close error AFTER consume; no retry/reopen".into());}
        recorded?;self.require_closed()
    }
    pub(crate) fn require_closed(&self)->Result<(),String>{
        if matches!(self.state,CloseState::Closed{..}){Ok(())}else{Err("original descriptor has no known successful explicit close".into())}
    }
}

/// Prepared only from the actual rebuilt plan + genuine READY set. Numeric
/// records/resource charges do NOT themselves authorize terminal effects.
pub(super) struct PreparedTerminalPlan {
    uid:Uid,operation:Arc<ManagedPodOperation>,source:String,
    budget:Arc<journal::TerminalEvidenceBudget>,
    charged_nodes:Mutex<BTreeMap<Uid,ResourceReservation>>,
    registered:AtomicBool,round:Mutex<Option<Arc<RegisteredDrainRound>>>,
    accepted_started:Mutex<Option<Instant>>,node_jobs:BTreeMap<Uid,Uid>,node_sessions:BTreeMap<Uid,Uid>,precreate_sealed:AtomicBool,
    containers:usize,materializations:usize,
}
struct ResourceReservation {
    node:Uid,boot:BootId,volume:Uid,pool:Uid,
    dispatcher_entries:usize,pool_entries:usize,attempts:usize,
    // Genuine receiver owns original directory descriptors in its rooted
    // node object; these are authenticated observation hashes, NOT grants.
    receipt_sha256:String,
    reservation:Uid,scope:crate::storage_lifecycle::pod_attachment::ExpectedAttachScope,
    local:Option<Arc<crate::storage_driver::dispatcher::attachment::ReservedTerminalResources>>,
    transport:Option<VerifiedPeerFrame>,mandatory_admissions:usize,
}
pub(super) fn capture_original_process(shared:&Arc<Shared>,operation:&Arc<ManagedPodOperation>,
    owned:&Arc<OwnedManagedContainer>,connection:&mut crate::docker::ManagedConsumerConnection,
    deadline:Instant)->Result<(),String>{
    if !Arc::ptr_eq(&owned.operation,operation)||owned.status.load(Ordering::Acquire)!=CONTAINER_STARTED{
        return Err("process capture lacks same actual acknowledged Start/container root".into());}
    let plan=operation.terminal_plan.lock().map_err(|_|"original pre-Create terminal plan poisoned")?
        .as_ref().cloned().ok_or("original Start lacks complete pre-Create terminal plan")?;
    plan.require_full_precharge()?;
    let before=crate::docker::managed::inspect_process(connection,&owned.expected,owned,deadline)?;
    let mut pin=owned.process.lock().map_err(|_|"original process pin root poisoned")?;
    let identity=pin.capture(&before,deadline)?;
    let after=crate::docker::managed::inspect_process(connection,&owned.expected,owned,deadline)?;
    pin.require_candidate(&after,deadline)?;
    drop(pin);
    // The actual FD object is already inside owned.process before any write.
    shared.journal.terminal_record(&plan.budget,&operation.uid,journal::TerminalRecordKind::ProcessPin,
        owned.nonce(),&identity)?;
    operation.live()?;if Instant::now()>=deadline{return Err("original process capture late after Start".into());}Ok(())
}
impl PreparedTerminalPlan {
    pub(super) async fn prepare(shared:&Arc<Shared>,operation:&Arc<ManagedPodOperation>,
        source:String,containers:usize,materializations:usize)->Result<Arc<Self>,String>{
        operation.live()?;
        if operation.key.references.len()!=1||!shared.config.attaches(){return Err("terminal pre-Create producer requires actual one-volumev3 plan".into());}
        let (nodes,scope,original_owner)={
            let world=shared.world.try_read().map_err(|_|"actual terminal pre-Create source busy")?;
            let uid=operation.key.references.keys().next().unwrap();
            let volume=world.storage_identities.lifecycle.get(uid).ok_or("actual pre-Create dataset absent")?;
            operation.ready.binding.validate_volume(volume)?;
            let generation=volume.data_generation().ok_or("actual pre-Create initialized dataset absent")?;
            let owner=operation.ready.book.state.try_lock().map_err(|_|"actual pre-Create owner book busy")?.owners
                .get(uid).cloned().ok_or("actual original pre-Create mount owner absent")?;
            (generation.virgin_replicas.iter().map(|fact|(fact.node_uid.clone(),Uid::new())).collect::<BTreeMap<_,_>>(),owner.scope().clone(),owner)
        };
        if nodes.len()!=3{return Err("terminal requires exactly three actual enrolled replica node slots".into());}
        let current=operation.clone();let journal=shared.journal.clone();let source_io=source.clone();
        let budget=shared.io.run(move||{
            current.live()?;
            let charged=Arc::new(journal.reserve_terminal_consumer_plan(&source_io,containers,materializations,1)?);
            *current.budget.lock().unwrap_or_else(|p|p.into_inner())=Some(charged.clone());
            current.live()?;Ok(charged)
        }).await?;
        let terminal=budget.terminal()?;
        let sessions=nodes.keys().map(|node|(node.clone(),Uid::new())).collect();
        let plan=Arc::new(Self {uid:Uid::new(),operation:operation.clone(),source,budget:terminal,charged_nodes:Mutex::new(BTreeMap::new()),
            registered:AtomicBool::new(false),round:Mutex::new(None),accepted_started:Mutex::new(None),node_jobs:nodes,node_sessions:sessions,
            precreate_sealed:AtomicBool::new(false),containers,materializations});
        *operation.terminal_plan.lock().unwrap_or_else(|p|p.into_inner())=Some(plan.clone()); // BEFORE cross-node IO/results.
        wire::prepare_all(shared,&plan).await?;
        plan.require_nodes_precharged()?;
        // Read-only supported-wire admission BEFORE any consumer Create.
        // Same actual retained daemon capability, not host/historical JSON.
        let version_deadline=Instant::now()+Duration::from_secs(30);
        let (daemon_identity,daemon_version_sha256)=shared.io.run(move||{
            let mut connection=original_owner.terminal_consumer_connection(version_deadline)?;
            let version=crate::docker::managed::terminal_daemon_version(&mut connection,version_deadline)?;
            Ok((connection.identity_sha256()?,version))
        }).await?;
        let headers={let nodes=plan.charged_nodes.lock().map_err(|_|"actual terminal header reservations poisoned")?;
            nodes.iter().map(|(node,resource)|Ok((plan.node_jobs.get(node).ok_or("terminal original job slot absent")?.clone(),
                serde_json::json!({"layout":3,"kind":"terminal-node-original-pre-create-header-v1","plan":plan.uid,
                    "original_consumer_operation":plan.operation.uid,"source_sha256":plan.source,"node_job":plan.node_jobs[node],
                    "session_data_only":plan.node_sessions[node],"original_scope":resource.scope,
                    "actual_reservation_uid":resource.reservation,"actual_reservation_commitment":resource.receipt_sha256,
                    "mandatory_physical_admissions":resource.mandatory_admissions,
                    "mandatory_total_admissions":total_node_mandatory(resource.mandatory_admissions,resource.scope.mount_ref.node_uid()==node,plan.containers)?,"maximum_chain_frames":512,
                    "maximum_pages":2,"page_bytes":32768,"live_deadline_authority":false,"restart_authority":false}))))
                .collect::<Result<Vec<_>,String>>()?};
        for (job,header) in headers {
            let journal=shared.journal.clone();let original=plan.clone();
            shared.io.run(move||journal.terminal_node_header(&original.budget,&original.operation.uid,&job,&header)).await?;
        }
        let facts={let nodes=plan.charged_nodes.lock().map_err(|_|"original all-node precharge roots poisoned")?;
            nodes.values().map(|n|serde_json::json!({"node":n.node,"boot":n.boot,"volume":n.volume,"pool":n.pool,
                "reservation_uid":n.reservation,"commitment":n.receipt_sha256,"mandatory_admissions":n.mandatory_admissions,
                "attempt_slots":n.attempts,"dispatch_entries":n.dispatcher_entries,"pool_entries":n.pool_entries})).collect::<Vec<_>>()};
        let original=plan.clone();let journal=shared.journal.clone();
        shared.io.run(move||journal.terminal_record(&original.budget,&original.operation.uid,
            journal::TerminalRecordKind::RootAdmission,&original.uid,
            &serde_json::json!({"phase":"PRE_CREATE_FULL_TERMINAL_RESERVATION","source_sha256":original.source,
                "source_owner":scope.owner,"actual_node_reservations":facts,
                "actual_daemon_identity_sha256":daemon_identity,"actual_daemon_version_sha256":daemon_version_sha256,
                "effect_permission":false}))).await?;
        plan.precreate_sealed.store(true,Ordering::Release);
        plan.require_full_precharge()?;operation.live()?;Ok(plan)
    }
    fn accept_original_clock(&self)->Result<(),String>{
        let mut clock=self.accepted_started.try_lock().map_err(|_|"original terminal acceptance clock busy")?;
        if clock.is_none(){*clock=Some(Instant::now());}Ok(())
    }
    fn submission(&self)->TerminalSubmission{
        let status=match self.round.try_lock(){
            Ok(round)=>match round.as_ref(){Some(r) if r.unknown.load(Ordering::Acquire)=>"UNKNOWN",
                Some(r) if r.retired.load(Ordering::Acquire)=>"OWNERSHIP_QUIESCENCE_ONLY",
                Some(r) if r.detached.load(Ordering::Acquire)=>"DETACHED_CONFIRMATION_PENDING_RETIREMENT",
                Some(_)=>"DRAINING",None if self.registered.load(Ordering::Acquire)=>"UNKNOWN_REGISTERING",
                None=>"ACCEPTED"},Err(_)=>"UNKNOWN"};
        TerminalSubmission{operation:self.operation.uid.clone(),terminal:self.uid.clone(),status}
    }
    pub(super) fn require_full_precharge(&self)->Result<(),String>{
        if !self.precreate_sealed.load(Ordering::Acquire){return Err("actual terminal headers/full pre-Create envelope not sealed".into());}
        self.require_nodes_precharged()
    }
    pub(super) fn require_nodes_precharged(&self)->Result<(),String>{
        if self.operation.key.references.len()!=1||self.budget.source_sha256()!=self.source{
            return Err("terminal precharge differs from same original actual Pod source".into());}
        let nodes=self.charged_nodes.lock().map_err(|_|"terminal node precharges poisoned")?;
        if nodes.len()!=3{return Err("complete actual three-node dispatch/pool precharge not acknowledged BEFORE Create".into());}
        let uid=self.operation.key.references.keys().next().unwrap();
        for reservation in nodes.values(){
            if &reservation.volume!=uid||reservation.receipt_sha256.len()!=64||reservation.attempts==0
                ||reservation.mandatory_admissions>512||!self.node_jobs.contains_key(&reservation.node){
                return Err("terminal receiver budget fact is partial or differs".into());}
            total_node_mandatory(reservation.mandatory_admissions,reservation.scope.mount_ref.node_uid()==&reservation.node,self.containers)?;
        }Ok(())
    }
}
fn total_node_mandatory(physical:usize,writer:bool,containers:usize)->Result<usize,String>{
    if !(1..=128).contains(&containers){return Err("terminal original actual plan container count invalid".into());}
    // In addition to the physical producer's mandatory LOWER bound: one
    // actual node registration; on writer four metadata before/confirm
    // frames and per container one signal, one tagged original-cgroup fact,
    // one namespace-close before, one namespace-close result. Nonempty waits
    // and extra physical partial-FD checks ADD; this is not a fit guarantee.
    let actor=if writer{containers.checked_mul(4).and_then(|n|n.checked_add(5)).ok_or("terminal actor frame count overflow")?}else{1};
    let total=physical.checked_add(actor).ok_or("terminal complete mandatory frame count overflow")?;
    if total>512{return Err("complete physical+actor terminal frame lower bound exceeds512 BEFORE Create".into());}Ok(total)
}
/// Actual parent roots this separately from ordinary READY/cancel state.
pub(crate) struct RegisteredDrainRound {
    plan:Arc<PreparedTerminalPlan>,shared:Arc<Shared>,started:Instant,deadline:Instant,
    revision:protocol::Revision,directory:String,unknown:AtomicBool,
    begun:AtomicBool,detached:AtomicBool,retired:AtomicBool,
    node_jobs:Mutex<BTreeMap<Uid,Arc<RegisteredTerminalNode>>>,
    completions:Mutex<BTreeMap<(Uid,TerminalNativeStep),Arc<wire::TerminalCompletion>>>,
    metadata:Mutex<Vec<Arc<commit::PreparedTerminalMetadata>>>,detached_evidence:Mutex<Option<String>>,
    signals:Mutex<BTreeMap<String,Arc<SignalAttempt>>>,
    processes:Mutex<Option<Arc<OriginalProcessesDrained>>>,
    retired_receivers:Mutex<BTreeMap<Uid,(String,VerifiedPeerFrame)>>,
    owner:crate::storage_lifecycle::Owner,generation:crate::storage_lifecycle::generation::DataGeneration,
}
struct RegisteredTerminalNode {
    uid:Uid,node:Uid,boot:BootId,scope:crate::storage_lifecycle::pod_attachment::ExpectedAttachScope,
    owner:Option<Arc<crate::storage_driver::dispatcher::attachment::AttachOwner>>,
    consumed:Mutex<BTreeSet<String>>,sequence:std::sync::atomic::AtomicU64,
    progress:Mutex<wire::IssuerNodeProgress>,
}
impl RegisteredDrainRound {
    async fn register(shared:&Arc<Shared>,plan:Arc<PreparedTerminalPlan>)->Result<Arc<Self>,String>{
        if plan.registered.swap(true,Ordering::AcqRel){return Err("original terminal round already accepted/UNKNOWN; no repeat".into());}
        plan.require_full_precharge()?;shared.journal.terminal_healthy(&plan.budget)?;
        let started=plan.accepted_started.lock().map_err(|_|"original terminal clock poisoned")?.ok_or("no original DATA acceptance clock")?;
        let deadline=started.checked_add(Duration::from_secs(180)).ok_or("terminal original clock overflow")?;
        while shared.io.busy.load(Ordering::Acquire)!=0 {
            if Instant::now()>=deadline{return Err("original IO did not settle inside original terminal clock; retained".into());}
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        if !shared.controller_alive.load(Ordering::Acquire)||!Arc::ptr_eq(plan.operation.ready.book.world(),&shared.world){
            return Err("original terminal actor/store disappeared".into());}
        let view=core::runtime_view(true).await?;
        if view.local()!=&shared.pool.node_uid||view.boot()!=plan.operation.key.references.values().next().ok_or("empty terminal group")?.node_boot()
            ||view.directory().nodes.iter().find(|node|node.node_uid==*view.local()).is_none_or(|node|node.raft_id!=view.revision().leader_raft_id){
            return Err("terminal requires SAME actual local acknowledged writer/leader".into());}
        let book=plan.operation.ready.book.clone();let mut expected=BTreeMap::new();
        {let resources=plan.charged_nodes.lock().map_err(|_|"original node reservations poisoned")?;
            for (node,resource) in resources.iter(){
                let owner=if node==view.local(){Some(book.state.try_lock().map_err(|_|"actual terminal owner book busy")?.owners
                    .get(&resource.volume).cloned().ok_or("original local terminal owner absent")?)}else{None};
                expected.insert(node.clone(),Arc::new(RegisteredTerminalNode{uid:plan.node_jobs.get(node).ok_or("original node job slot absent")?.clone(),
                    node:node.clone(),boot:resource.boot.clone(),scope:resource.scope.clone(),owner,
                    consumed:Mutex::new(BTreeSet::new()),sequence:std::sync::atomic::AtomicU64::new(0),progress:Mutex::new(wire::IssuerNodeProgress::new())}));
            }}
        let (original_owner,original_generation)={let first=expected.values().next().ok_or("terminal actual original scope absent")?;
            (first.scope.owner.clone(),first.scope.generation.clone())};
        if expected.values().any(|node|node.scope.owner!=original_owner||node.scope.generation!=original_generation){
            return Err("terminal all-node original full owner/generation differs".into());}
        let round=Arc::new(Self {plan:plan.clone(),shared:shared.clone(),started,deadline,revision:view.revision().clone(),
            directory:view.directory().sha256()?,unknown:AtomicBool::new(false),begun:AtomicBool::new(false),detached:AtomicBool::new(false),retired:AtomicBool::new(false),
            node_jobs:Mutex::new(expected),completions:Mutex::new(BTreeMap::new()),metadata:Mutex::new(Vec::new()),detached_evidence:Mutex::new(None),signals:Mutex::new(BTreeMap::new()),processes:Mutex::new(None),retired_receivers:Mutex::new(BTreeMap::new()),
            owner:original_owner,generation:original_generation});
        *plan.round.lock().unwrap_or_else(|p|p.into_inner())=Some(round.clone()); // BEFORE further live checks/await.
        {let current=shared.world.try_read().map_err(|_|"actual terminal registration source busy")?;round.check_world(&current)?;}
        round.require_live()?;Ok(round)
    }
    fn require_live(&self)->Result<(),String>{
        if self.unknown.load(Ordering::Acquire)||Instant::now()<self.started||Instant::now()>=self.deadline
            || !core::is_actual_world(&self.shared.world){return Err("original terminal round expired/UNKNOWN/store lost".into());}
        core::require_same_actual_epoch(&self.shared.world,&self.revision)?;
        self.shared.journal.terminal_healthy(&self.plan.budget)
    }
    fn check_world(&self,world:&DesiredWorld)->Result<(),String>{
        let expected=if self.detached.load(Ordering::Acquire){TerminalWorldPhase::Detached}
            else if self.begun.load(Ordering::Acquire){TerminalWorldPhase::Detaching}else{TerminalWorldPhase::OriginalAttached};
        self.check_world_phase(world,expected)
    }
    fn check_world_phase(&self,world:&DesiredWorld,expected:TerminalWorldPhase)->Result<(),String>{
        self.require_live()?;
        if !removal_source_absent(world,&self.plan.operation.key){return Err("original desired removal changed/reappeared before terminal boundary".into());}
        if world.cluster_id!=self.shared.pool.cluster_id||self.plan.operation.key.references.len()!=1{
            return Err("terminal actual cluster/group differs".into());}
        for (uid,reference) in &self.plan.operation.key.references {
            let volume=world.storage_identities.lifecycle.get(uid).ok_or("terminal actual volume disappeared")?;
            if volume.owner()!=&self.owner||volume.owner().volume_uid!=*uid||volume.data_generation()!=Some(&self.generation)
                ||self.generation.uid!=*reference.generation_uid()||self.generation.filesystem_uuid!=reference.filesystem_uuid()
                ||volume.pod_writer()!=Some(&self.plan.operation.ready.binding)
                ||volume.epoch()!=reference.epoch() {return Err("terminal canonical writer/generation/epoch changed".into());}
            if expected==TerminalWorldPhase::Detached{
                if volume.assignment().is_some(){return Err("terminal acknowledged Detached retained an Assignment".into());}
            }else{
                let assignment=volume.assignment().ok_or("terminal original Assignment absent")?;
                if assignment.writer_uid!=*reference.writer_uid().as_uid()||assignment.node_uid!=*reference.node_uid()
                    ||assignment.node_boot_id!=*reference.node_boot()||assignment.attach_operation!=*reference.operation_uid(){
                    return Err("terminal original writer assignment changed".into());}
            }
            let pvc=world.pvcs.get(&crate::store::obj_key(&volume.owner().namespace,&volume.owner().claim_name))
                .ok_or("terminal original claim absent")?;
            let pv=world.pvs.get(&volume.owner().pv_name).ok_or("terminal original PV absent")?;
            let claim_key=crate::store::obj_key(&volume.owner().namespace,&volume.owner().claim_name);
            let identity=world.storage_identities.claims.get(&claim_key).ok_or("terminal claim identity absent")?;
            if identity.uid!=volume.owner().claim_uid||identity.namespace_uid!=volume.owner().namespace_uid
                ||world.storage_identities.namespaces.get(&volume.owner().namespace)!=Some(&volume.owner().namespace_uid)
                ||world.storage_identities.volumes.get(&volume.owner().pv_name)!=Some(uid)
                ||pvc.bound_pv.as_ref()!=Some(&volume.owner().pv_name)||pv.bound_to.as_deref()!=Some(claim_key.as_str())
                ||pv.status!=crate::reconcile::PVStatus::Bound||pvc.storage_class!=pv.storage_class{
                return Err("terminal original claim namespace/PV identity changed".into());}
            let class=world.storage_classes.get(&pv.storage_class).ok_or("terminal current native StorageClass absent")?;
            if class.provisioner!=crate::storage_lifecycle::PROVISIONER||!self.shared.config.storage_class_allowlist.contains(&pv.storage_class){
                return Err("terminal current native StorageClass no longer admitted".into());}
            match expected{
                TerminalWorldPhase::OriginalAttached=>if volume.phase()!=Phase::Attached||volume.operation()!=reference.operation_uid(){return Err("terminal source is not original acknowledged Attached writer".into());},
                TerminalWorldPhase::Detaching=>if volume.phase()!=Phase::Detaching||volume.operation()!=&self.plan.uid{return Err("terminal current Detaching is not this acknowledged operation".into());},
                TerminalWorldPhase::Detached=>if volume.phase()!=Phase::Detached||volume.operation()!=&self.plan.uid{return Err("terminal current Detached is not this acknowledged operation".into());},
            }
        }Ok(())
    }
    fn mark_unknown(&self){self.unknown.store(true,Ordering::Release);self.plan.operation.invalidate("original terminal round UNKNOWN; no retry/reset");}
}
#[derive(Clone,Copy,PartialEq,Eq)]
enum TerminalWorldPhase {OriginalAttached,Detaching,Detached}
/// Only actual registered round + exact rooted owner/PIDFD boundary can mint
/// this request. It cannot be decoded from the transport/body/report.
pub(crate) struct TerminalReadRequest {
    round:Arc<RegisteredDrainRound>,effect:TerminalEffect,binding:String,resource:String,nonce:Uid,
}
impl TerminalReadRequest {
    pub(crate) fn require_produced(&self)->Result<(),String>{
        self.round.require_live()?;
        if self.nonce.as_str().is_empty()||!is_hash(&self.binding)||!is_hash(&self.resource){return Err("actual terminal request malformed".into());}
        Ok(())
    }
    pub(crate) fn binding(&self)->&str{&self.binding}
}
/// One-use actual-Core permission, not a serde/default/caller clock token.
pub(crate) struct VerifiedTerminalEffect {
    request:TerminalReadRequest,observed:core::CoreObservation,spent:AtomicBool,
    node_job:Uid,
}
impl VerifiedTerminalEffect {
    pub(crate) fn deadline(&self)->Instant{self.request.round.deadline}
    fn require_exact(&self,effect:TerminalEffect,resource:&str)->Result<(),String>{
        self.request.require_produced()?;
        self.observed.require_fresh_terminal(&self.request,Instant::now())?;
        if self.request.effect!=effect||self.request.resource!=resource||self.spent.load(Ordering::Acquire){return Err("terminal one-use permission resource/purpose changed".into());}
        let world=self.request.round.shared.world.try_read().map_err(|_|"terminal actual World busy at effect edge")?;
        if world.generation!=self.observed.revision().desired_generation{return Err("terminal source changed after actual barrier".into());}
        self.request.round.check_world(&world)
    }
    fn consume_resource(&self,resource:&str)->Result<(),String>{
        self.require_exact(self.request.effect,resource)?;
        if self.spent.swap(true,Ordering::AcqRel){return Err("original terminal effect permission already spent".into());}Ok(())
    }
    fn record_result(&self,raw:&[u8])->Result<(),String>{
        let result=self.request.round.shared.journal.terminal_node_append(&self.request.round.plan.budget,&self.node_job,602,
            &digest(&serde_json::to_vec(&(&self.request.binding,digest(raw))).map_err(|_|"terminal result binding")?));
        if result.is_err()||Instant::now()>=self.deadline(){self.unknown();return Err("terminal result late/UNKNOWN; consumed resource retained as tombstone".into());}
        result
    }
    fn unknown(&self){self.request.round.mark_unknown();}
}
pub(crate) struct VerifiedSignalTerm {
    effect:VerifiedTerminalEffect,container:Arc<OwnedManagedContainer>,path:String,daemon:String,version:String,
    original_signal_deadline:Instant,
    original:Arc<SignalAttempt>,
}
struct SignalAttempt {container:Arc<OwnedManagedContainer>,deadline:Instant,submitted:AtomicBool,
    outcome:Mutex<Option<serde_json::Value>>}
pub(crate) struct SubmittedSignalTerm {effect:VerifiedTerminalEffect,container:Arc<OwnedManagedContainer>,original:Arc<SignalAttempt>}
impl VerifiedSignalTerm {
    pub(crate) fn consume(self,connection:&crate::docker::ManagedConsumerConnection,path:&str,deadline:Instant)
        ->Result<SubmittedSignalTerm,String>{
        if deadline!=self.original_signal_deadline||Instant::now()>=deadline||deadline>self.effect.deadline()
            ||self.original.deadline!=deadline||!Arc::ptr_eq(&self.original.container,&self.container)
            ||path!=self.path||path!=format!("/containers/{}/kill?signal=SIGTERM",self.container.id())
            ||connection.identity_sha256()?!=self.daemon||!is_hash(&self.version){return Err("typed SignalTerm differs from original exact attested effect".into());}
        self.effect.consume_resource(&self.effect.request.resource)?;
        consume_signal_once(&self.original.submitted)?;
        Ok(SubmittedSignalTerm{effect:self.effect,container:self.container,original:self.original})
    }
}
fn consume_signal_once(latch:&AtomicBool)->Result<(),String>{
    if latch.swap(true,Ordering::AcqRel){return Err("original SIGTERM wire already may have submitted; no retry".into());}Ok(())
}
impl SubmittedSignalTerm {
    pub(crate) fn transport_unknown(&self){
        *self.original.outcome.lock().unwrap_or_else(|p|p.into_inner())=Some(serde_json::json!({"wire":"UNKNOWN","signal":"SIGTERM","may_have_submitted":true}));
        self.effect.unknown();
    }
    pub(crate) fn observed(&self,status:u16,raw:&[u8]){
        let round=&self.effect.request.round;
        let outcome=serde_json::json!({"actual_cid":self.container.id(),"http_status":status,"body_sha256":digest(raw),
            "signal":"SIGTERM","process_drained":false});
        *self.original.outcome.lock().unwrap_or_else(|p|p.into_inner())=Some(outcome.clone());
        let result=round.shared.journal.terminal_record(&round.plan.budget,&round.plan.operation.uid,
            journal::TerminalRecordKind::SignalOutcome,self.container.nonce(),
            &outcome);
        if result.is_err()||status!=204||!raw.is_empty()||Instant::now()>=self.original.deadline{self.effect.unknown();}
    }
}

struct OriginalProcessesDrained {
    operation:Arc<ManagedPodOperation>,containers:Vec<Arc<OwnedManagedContainer>>,
    observations:BTreeMap<String,process::OriginalCgroupDrain>,never_submitted:Option<KnownOriginalNeverSubmitted>,
}
impl OriginalProcessesDrained {
    fn require_same(&self,round:&RegisteredDrainRound)->Result<(),String>{
        if !Arc::ptr_eq(&self.operation,&round.plan.operation){return Err("terminal process proof differs from original managed operation".into());}
        if let Some(proof)=&self.never_submitted{return proof.require_current();}
        let actual=self.operation.containers.try_lock().map_err(|_|"terminal original CID roots busy")?;
        if actual.len()!=self.containers.len()||self.observations.len()!=self.containers.len()||self.containers.is_empty(){
            return Err("terminal original process group is partial/changed".into());}
        for container in &self.containers{
            if !actual.get(container.id()).is_some_and(|same|Arc::ptr_eq(same,container))||!self.observations.contains_key(container.id()){
                return Err("terminal process proof is not same original rooted CID".into());}
            container.process.try_lock().map_err(|_|"terminal original process pin busy")?.require_namespace_closed()?;
        }Ok(())
    }
}
async fn signal_and_drain_original(round:&Arc<RegisteredDrainRound>)->Result<Arc<OriginalProcessesDrained>,String>{
    round.require_live()?;
    let containers=round.plan.operation.containers.try_lock().map_err(|_|"terminal original actual CID roots busy")?.values().cloned().collect::<Vec<_>>();
    if containers.is_empty(){
        let proof=KnownOriginalNeverSubmitted::capture(&round.shared,&round.plan)?;
        let result=Arc::new(OriginalProcessesDrained{operation:round.plan.operation.clone(),containers,observations:BTreeMap::new(),never_submitted:Some(proof)});
        *round.processes.lock().unwrap_or_else(|p|p.into_inner())=Some(result.clone());result.require_same(round)?;return Ok(result);
    }
    let expected_count={let plan=round.plan.operation.plan.try_lock().map_err(|_|"terminal actual original launch plan busy")?;
        let plan=plan.as_ref().ok_or("terminal actual original launch plan absent")?;plan.containers.len().checked_add(plan.init_containers.len()).ok_or("terminal original container count overflow")?};
    if containers.len()!=expected_count||containers.iter().any(|container|container.status.load(Ordering::Acquire)!=CONTAINER_STARTED){
        return Err("original Create/Start group partial/may-have-submitted; no no-start inference or adoption".into());}
    let node=round.node_jobs.try_lock().map_err(|_|"terminal actual writer node root busy")?.get(&round.shared.pool.node_uid).cloned().ok_or("terminal actual writer registration absent")?;
    let owner=node.owner.as_ref().cloned().ok_or("terminal original writer owner absent")?;
    for container in &containers{
        round.require_live()?;
        let deadline=(Instant::now()+Duration::from_secs(30)).min(round.deadline);
        let attempt=Arc::new(SignalAttempt{container:container.clone(),deadline,submitted:AtomicBool::new(false),outcome:Mutex::new(None)});
        {let mut roots=round.signals.try_lock().map_err(|_|"terminal signal original roots busy")?;
            if roots.contains_key(container.id()){return Err("original SIGTERM already attempted; no retry".into());}
            roots.insert(container.id().into(),attempt.clone());}
        let current=container.clone();let actual_owner=owner.clone();
        let (mut connection,version,identity,already_exited)=round.shared.io.run(move||{
            let mut connection=actual_owner.terminal_consumer_connection(deadline)?;
            let version=crate::docker::managed::terminal_daemon_version(&mut connection,deadline)?;
            let candidate=crate::docker::managed::inspect_process(&mut connection,&current.expected,&current,deadline)?;
            let pin=current.process.try_lock().map_err(|_|"terminal original process pin busy")?;
            let identity=pin.identity()?.clone();
            let already_exited=pin.observe_original_drain(deadline)?;
            if already_exited.is_none(){pin.require_candidate(&candidate,deadline)?;}
            Ok((connection,version,identity,already_exited))
        }).await?;
        let resource=digest(&serde_json::to_vec(&("terminal-once-original-sigterm-v1",&round.plan.uid,&identity,connection.identity_sha256()?,&version))
            .map_err(|_|"terminal signal exact original binding encode")?);
        let original=round.clone();let current=container.clone();let resource_io=resource.clone();let version_io=version.clone();
        round.shared.io.run(move||original.shared.journal.terminal_record(&original.plan.budget,&original.plan.operation.uid,
            journal::TerminalRecordKind::SignalAdmission,current.nonce(),&serde_json::json!({"actual_cid":current.id(),"signal":"SIGTERM",
                "resource":resource_io,"actual_daemon_version_sha256":version_io,"already_original_exited":already_exited}))).await?;
        if let Some(tag)=already_exited{
            let outcome=serde_json::json!({"signal_submitted":false,"reason":"ORIGINAL_PINNED_TASK_ALREADY_DRAINED","actual_cgroup_fact":tag});
            *attempt.outcome.lock().unwrap_or_else(|p|p.into_inner())=Some(outcome.clone());
            let original=round.clone();let current=container.clone();
            round.shared.io.run(move||original.shared.journal.terminal_record(&original.plan.budget,&original.plan.operation.uid,
                journal::TerminalRecordKind::SignalOutcome,current.nonce(),&outcome)).await?;
            continue;
        }
        let effect=wire::local_observation(round,&node,630,TerminalEffect::SignalTerm,resource.clone(),
            &(container.id(),container.nonce(),&resource,&version)).await?;
        let permission=VerifiedSignalTerm{effect,container:container.clone(),path:format!("/containers/{}/kill?signal=SIGTERM",container.id()),
            daemon:connection.identity_sha256()?,version,original_signal_deadline:deadline,original:attempt};
        let current=container.clone();
        round.shared.io.run(move||{
            let candidate=crate::docker::managed::inspect_process(&mut connection,&current.expected,&current,deadline)?;
            current.process.try_lock().map_err(|_|"terminal original process pin busy before signal")?.require_candidate(&candidate,deadline)?;
            crate::docker::managed::signal_term(&mut connection,permission,&current,deadline)
        }).await?;
    }
    let mut observations=BTreeMap::new();
    for container in &containers{
        loop{
            round.require_live()?;let current=container.clone();let deadline=round.deadline;
            let observed=round.shared.io.run(move||current.process.try_lock().map_err(|_|"terminal actual process pin busy")?.observe_original_drain(deadline)).await?;
            if let Some(tag)=observed{
                let current=container.clone();let original=round.clone();let job=node.uid.clone();
                round.shared.io.run(move||{
                    let identity=current.process.try_lock().map_err(|_|"terminal original tagged process identity busy")?.identity()?.clone();
                    let binding=digest(&serde_json::to_vec(&("original-cgroup-drain-fact-v1",current.id(),identity,tag)).map_err(|_|"terminal original cgroup fact encode")?);
                    original.shared.journal.terminal_node_append(&original.plan.budget,&job,632,&binding)
                }).await?;
                observations.insert(container.id().into(),tag);break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // Explicitly close only the actual original namespace descriptor.
        // PIDFD/proc/cgroup originals remain retained read-only evidence.
        let resource=container.process.try_lock().map_err(|_|"terminal original namespace root busy")?.namespace_resource_sha256()?;
        let permission=wire::local_observation(round,&node,631,TerminalEffect::CloseProcessNamespace,resource.clone(),
            &(container.id(),"close-original-process-mount-namespace",&resource)).await?;
        let current=container.clone();
        round.shared.io.run(move||current.process.try_lock().map_err(|_|"terminal original namespace close root busy")?.close_namespace(permission)).await?;
    }
    let result=Arc::new(OriginalProcessesDrained{operation:round.plan.operation.clone(),containers,observations,never_submitted:None});
    *round.processes.lock().unwrap_or_else(|p|p.into_inner())=Some(result.clone());result.require_same(round)?;Ok(result)
}

async fn run_original_drain(shared:&Arc<Shared>,plan:Arc<PreparedTerminalPlan>)->Result<(),String>{
    let round=RegisteredDrainRound::register(shared,plan).await?;
    let _processes=signal_and_drain_original(&round).await?;
    let begin=commit::PreparedTerminalMetadata::prepare(round.clone(),commit::MetadataKind::BeginDetaching,None).await?;
    begin.execute().await?;begin.require_confirmed()?;
    wire::register_all(&round).await?;
    let writer=round.plan.operation.key.references.values().next().ok_or("terminal original writer absent")?.node_uid().clone();
    wire::execute_node(&round,&writer,TerminalNativeStep::UnmountAndDemote).await?;
    let nodes=round.node_jobs.try_lock().map_err(|_|"terminal original node set busy")?.keys().cloned().collect::<Vec<_>>();
    // All three independent live Secondary/UpToDate observations precede ANY
    // down. Sequential offline does not pretend already-down peers Connected.
    for node in &nodes{wire::execute_node(&round,node,TerminalNativeStep::ObserveSecondarySynchronized).await?;}
    for node in &nodes{
        let proof=wire::execute_node(&round,node,TerminalNativeStep::OfflineAndObserve).await?;
        let original=round.clone();let node=node.clone();let observation=proof.observation().clone();let completion=proof.completion_sha256().to_string();
        round.shared.io.run(move||original.shared.journal.terminal_record(&original.plan.budget,&original.plan.operation.uid,
            journal::TerminalRecordKind::OfflineSummary,&node,&serde_json::json!({"actual_physical":observation,"completion_sha256":completion}))).await?;
    }
    let offline=commit::VerifiedTerminalOfflineSet::collect(&round)?;
    let detached=commit::PreparedTerminalMetadata::prepare(round.clone(),commit::MetadataKind::CommitDetached,Some(offline)).await?;
    detached.execute().await?;detached.require_confirmed()?;
    wire::confirm_and_retire_all(&round).await?;
    let original=round.clone();
    round.shared.io.run(move||{
        let processes=original.processes.try_lock().map_err(|_|"terminal actual process proof root busy")?.as_ref().cloned().ok_or("terminal actual process proof absent")?;
        processes.require_same(&original)?;
        let all_retired=wire::retirement_evidence(&original)?;
        let remote_retired={let results=original.retired_receivers.try_lock().map_err(|_|"actual remote retired result roots busy")?;
            if results.len()!=2{return Err("actual remote retired group is partial; no terminal success".into());}
            results.iter().map(|(node,(evidence,peer))|serde_json::json!({"node":node,"actual_retired_evidence_sha256":evidence,
                "authenticated_result_body_sha256":digest(peer.body())})).collect::<Vec<_>>()};
        original.shared.journal.terminal_record(&original.plan.budget,&original.plan.operation.uid,journal::TerminalRecordKind::RootOutcome,&original.plan.uid,
            &serde_json::json!({"status":"OWNERSHIP_QUIESCENCE_ONLY","original_process_cgroup_facts":processes.observations,
                "actual_remote_retirement_results":remote_retired,
                "actual_all_three_retirement_evidence":all_retired,
                "known_original_never_submitted":processes.never_submitted.is_some(),"stopped_container_objects_retained":true,
                "backend_data_and_empty_private_anchor_retained":true,"postgres_clean_shutdown_proven":false}))
    }).await?;
    round.require_live()?;
    let mut state=round.plan.operation.ready.book.state.try_lock().map_err(|_|"terminal final original book busy")?;
    if !matches!(state.consumer.pending.as_ref(),Some(PendingConsumerData::Drain(actual)) if Arc::ptr_eq(actual,&round.plan)){
        return Err("terminal final original DATA operation changed".into());}
    round.retired.store(true,Ordering::Release);state.consumer.mode=ControllerMode::Terminal;state.consumer.pending=None;Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn consumed_close_state_cannot_be_reinterpreted_as_still_owned_or_retryable(){
        for state in [CloseState::Consumed{number:11},CloseState::Closed{number:11},CloseState::ErrorAfterConsume{number:11,errno:Some(libc::EINTR)}]{
            assert!(!matches!(state,CloseState::Prepared));
        }
    }
    #[test] fn terminal_mode_has_no_unknown_to_operational_transition(){
        let mut mode=ControllerMode::Operational;mode.enter_drain().unwrap();assert_eq!(mode,ControllerMode::DrainOnly);
        mode.enter_drain().unwrap();assert_eq!(mode,ControllerMode::DrainOnly);
        mode=ControllerMode::Terminal;assert!(mode.enter_drain().is_err());assert_eq!(mode,ControllerMode::Terminal);
    }
    #[test] fn original_never_submitted_data_refuses_races_changed_owner_and_any_lost_create_ack(){
        assert!(require_never_submitted_data([(true,false),(true,false)].into_iter()).is_ok());
        for actions in [[(true,true),(true,false)],[(true,false),(false,false)],[(true,false),(true,true)]]{
            assert!(require_never_submitted_data(actions.into_iter()).is_err());
        }
        // No CID/empty census is an input or a NoStart permission here.
    }
    #[test] fn once_only_signal_latch_never_reopens_after_lost_reply_or_error(){
        let latch=AtomicBool::new(false);consume_signal_once(&latch).unwrap();
        assert!(consume_signal_once(&latch).is_err());assert!(latch.load(Ordering::Acquire));
        assert!(consume_signal_once(&latch).is_err());
    }
    #[test] fn complete_terminal_node_frame_lower_bound_counts_actor_records_before_create(){
        assert_eq!(total_node_mandatory(187,true,1).unwrap(),196);
        assert_eq!(total_node_mandatory(191,true,1).unwrap(),200);
        assert_eq!(total_node_mandatory(163,false,1).unwrap(),164);
        assert_eq!(total_node_mandatory(503,true,1).unwrap(),512);
        assert!(total_node_mandatory(504,true,1).is_err());
        assert!(total_node_mandatory(2107,true,1).is_err());
        assert!(total_node_mandatory(2083,false,1).is_err());
        assert!(total_node_mandatory(1,true,0).is_err());
        assert!(total_node_mandatory(1,true,129).is_err());
        // Lower-bound DATA only, never a physical fit/time/permission proof.
    }
    #[test] fn ordinary_removal_data_requires_original_namespace_and_actual_source_absence(){
        // Real DesiredWorld apply/removal DATA only. No book/owner/process/
        // session is constructed and this cannot authorize a terminal action.
        let mut world=DesiredWorld::new();
        let resource=serde_json::json!({"kind":"Deployment","metadata":{"name":"db","namespace":"tenant"},
            "spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"main","image":"busybox:1.37"}]}}}});
        world.apply(&serde_json::from_value(resource).unwrap()).unwrap();
        let namespace=world.storage_identities.namespaces["tenant"].clone();
        assert!(!removal_source_absent_data(&world,"tenant",&namespace,"db"));
        world.deployments.remove(&crate::store::obj_key("tenant","db"));
        assert!(removal_source_absent_data(&world,"tenant",&namespace,"db"));
        assert!(!removal_source_absent_data(&world,"other",&namespace,"db"));
        assert!(!removal_source_absent_data(&world,"tenant",&Uid::new(),"db"));
        let resource=serde_json::json!({"kind":"Deployment","metadata":{"name":"db","namespace":"tenant"},
            "spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"changed","image":"busybox:1.37","command":["false"]}]}}}});
        world.apply(&serde_json::from_value(resource).unwrap()).unwrap();
        assert!(!removal_source_absent_data(&world,"tenant",&namespace,"db"));
    }
    #[test] fn actual_statefulset_apply_stays_present_in_shared_map_until_exact_removal(){
        // Actual model apply/delete only; no process, owner, session or grant.
        let mut world=DesiredWorld::new();
        let resource=serde_json::json!({"kind":"StatefulSet","metadata":{"name":"db","namespace":"tenant"},
            "spec":{"replicas":1,"serviceName":"db","template":{"spec":{"containers":[{"name":"main","image":"busybox:1.37"}]}}}});
        world.apply(&serde_json::from_value(resource).unwrap()).unwrap();
        let namespace=world.storage_identities.namespaces["tenant"].clone();
        let key=crate::store::obj_key("tenant","db");
        assert!(world.deployments.contains_key(&key));
        assert!(!removal_source_absent_data(&world,"tenant",&namespace,"db"));
        assert!(!removal_source_absent_data(&world,"other",&namespace,"db"));
        assert!(!removal_source_absent_data(&world,"tenant",&Uid::new(),"db"));
        assert!(world.delete_resource("statefulsets","tenant","db").unwrap().is_empty());
        assert!(!world.deployments.contains_key(&key));
        assert!(removal_source_absent_data(&world,"tenant",&namespace,"db"));
        assert!(!removal_source_absent_data(&world,"tenant",&Uid::new(),"db"));
    }

}
