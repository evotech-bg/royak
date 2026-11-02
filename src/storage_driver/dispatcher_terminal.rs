//! Same-owner terminal physical work on the existing dispatcher, never a
//! replacement worker or a JSON/counter capability. All producers are private.
use super::*;
use crate::storage_driver::native_runtime::mount::consumer::terminal::{
    VerifiedTerminalNodeParent,TerminalNativeStep,TerminalBoundary};
use crate::storage_driver::replica::initialize::managed_mount::terminal as physical;
use crate::storage_driver::replica::initialize::managed_mount::anchor;
use physical::origin::{WatchProcessObservation,InheritedWatchProcess};
pub(crate) use physical::{TerminalResourceObservation,TerminalPhysicalObservation,TerminalReferenceDisposition,mandatory_admissions};
use std::collections::BTreeSet;
use std::os::fd::IntoRawFd;

pub(in crate::storage_driver::dispatcher) fn config_fingerprint(c:&Config)->Result<String,String>{
    Ok(hash(&serde_json::to_vec(&(&c.journal_root,&c.delegated_cgroup_root,&c.node_uid,
        &c.helper_image,&c.helper_sha256,c.deadline.as_millis(),&c.budget)).map_err(|_|"actual dispatcher policy encoding failed")?))
}
struct ReservedDirectories {
    dispatch:Option<Arc<Dir>>,pool:Option<Arc<Dir>>,
    namespace:Option<Arc<File>>,namespace_identity:Option<(u64,u64)>,
    fresh_dispatch:Option<Arc<Dir>>,fresh_pool:Option<Arc<Dir>>,
    dispatch_names:BTreeSet<String>,pool_names:BTreeSet<String>,
    observation:Option<TerminalResourceObservation>,failed:bool,
    next_step:usize,queued:bool,parent:Option<Arc<VerifiedTerminalNodeParent>>,
    current_identity:Option<live::JobIdentity>,drains:Vec<Arc<VerifiedTerminalDrain>>,
    retirement:Option<Arc<RetiredTerminalLease>>,lease_closes:std::collections::BTreeMap<&'static str,LeaseCloseOutcome>,retiring:bool,
    retirement_submitted:bool,retirement_queued:bool,
    watch_roles:Option<Arc<ReservedWatchRoles>>,
}
struct ReservedWatchRoles {pidfd:File,proc:File,observation:WatchProcessObservation}
#[derive(Clone,Debug,Serialize)]
enum LeaseCloseOutcome {Consumed{fd:i32,device:u64,inode:u64},Closed{fd:i32,device:u64,inode:u64},
    ErrorAfterConsume{fd:i32,device:u64,inode:u64,errno:Option<i32>}}
/// Rooted in SAME AttachOwner before every fallible directory read. UID and
/// counters are observations, NOT a terminal grant or restored worker owner.
pub(crate) struct ReservedTerminalResources {
    uid:Uid,owner:Arc<AttachOwner>,config:Config,policy:String,dispatch_path:std::path::PathBuf,
    pool_path:std::path::PathBuf,attempts:Vec<Uid>,mandatory:usize,
    invalid:Arc<AtomicBool>,state:Mutex<ReservedDirectories>,
}
impl ReservedTerminalResources {
    pub(crate) fn reservation_uid(&self)->&Uid{&self.uid}
    pub(crate) fn mandatory_admissions(&self)->usize{self.mandatory}
    pub(crate) fn observation(&self)->TerminalResourceObservation{
        self.state.lock().unwrap_or_else(|p|p.into_inner()).observation.as_ref()
            .expect("only successful genuine reservation exposes its observation").clone()
    }
    fn latch(&self){self.invalid.store(true,Ordering::Release);
        self.state.lock().unwrap_or_else(|p|p.into_inner()).failed=true;}
    /// Read-only original-directory/cgroup/boot/counter re-observation on the
    /// existing IO worker or dispatcher. It NEVER opens/recreates a cgroup.
    pub(crate) fn require_current(&self)->Result<(),String>{
        let result=(||{
            if self.invalid.load(Ordering::Acquire)||config_fingerprint(&self.config)?!=self.policy
                || BootId::current()?!=self.owner.scope.phase_boot{return Err("original terminal resource policy/boot UNKNOWN".into());}
            self.owner.require_actual_watch_files()?;
            let roles={self.state.lock().map_err(|_|"actual precharged process roles poisoned")?.watch_roles.clone()
                .ok_or("actual inherited Watch process roles were not precharged")?};
            physical::origin::verify_retained_pair(&roles.pidfd,&roles.proc,&roles.observation)?;
            let(held_ns,expected_ns)={let s=self.state.lock().map_err(|_|"terminal original namespace root poisoned")?;
                let held=s.namespace.as_ref().cloned().ok_or("original terminal Watch namespace FD absent")?;
                let expected=s.namespace_identity.ok_or("original terminal namespace identity absent")?;
                (held,expected)};
            if physical::namespace_identity(held_ns.as_ref())?!=expected_ns{return Err("original terminal namespace FD changed".into());}
            if physical::namespace_identity(&physical::capture_watch_namespace()?)?!=expected_ns{
                return Err("actual terminal Watch namespace changed; no reference replay".into());}
            let (dispatch,pool,names_d,names_p,observation)={
                let s=self.state.lock().map_err(|_|"terminal resource owner poisoned")?;
                if s.failed||s.fresh_dispatch.is_some()||s.fresh_pool.is_some(){return Err("terminal original resource recheck UNKNOWN".into());}
                (s.dispatch.clone().ok_or("original dispatch FD absent")?,s.pool.clone().ok_or("original pool FD absent")?,
                    s.dispatch_names.clone(),s.pool_names.clone(),s.observation.clone().ok_or("resource reservation incomplete")?)
            };
            let fresh=Arc::new(Dir::open(&self.dispatch_path,false)?);
            self.state.lock().map_err(|_|"terminal resource owner poisoned")?.fresh_dispatch=Some(fresh.clone());
            if dispatch.retained_identity()?!=observation.dispatch_identity || fresh.retained_identity()?!=observation.dispatch_identity{
                return Err("original dispatch pathname/FD incarnation changed".into());}
            let fresh=Arc::new(Dir::open(&self.pool_path,false)?);
            self.state.lock().map_err(|_|"terminal resource owner poisoned")?.fresh_pool=Some(fresh.clone());
            if pool.retained_identity()?!=observation.pool_identity || fresh.retained_identity()?!=observation.pool_identity{
                return Err("original pool pathname/FD incarnation changed".into());}
            let current_d: BTreeSet<_>=dispatch.bounded_entries(512)?.into_iter().collect();
            let current_p: BTreeSet<_>=pool.bounded_entries(512)?.into_iter().collect();
            if !names_d.is_subset(&current_d)||!names_p.is_subset(&current_p)
                || current_d.iter().chain(&current_p).any(|n|n.starts_with(".txn-")){
                return Err("old terminal evidence removed or unfinished atomic write; no adoption".into());}
            let allowed_d: BTreeSet<_>=self.attempts.iter().flat_map(|a|[
                format!("capsule-{}.json",a.as_str()),format!("attempt-{}.json",a.as_str())]).collect();
            let allowed_p:BTreeSet<_>=self.attempts.iter().flat_map(|a|[
                format!("terminal-{}-intent.json",a.as_str()),format!("terminal-{}-complete.json",a.as_str())]).collect();
            if current_d.difference(&names_d).any(|n|!allowed_d.contains(n))
                ||current_p.difference(&names_p).any(|n|!allowed_p.contains(n))
                ||current_d.len()>observation.existing_dispatch_entries+observation.reserved_dispatch_entries
                ||current_p.len()>observation.existing_pool_entries+observation.reserved_pool_entries{
                return Err("actual uncharged dispatch/pool entry appeared".into());}
            let cgroup={let s=self.owner.resources.lock().map_err(|_|"same cgroup owner poisoned")?;
                s.terminal_cgroup.as_ref().cloned().ok_or("actual original cgroup provenance absent")?};
            // Population may be nonzero only inside the SAME original helper.
            // Readonly pre-Create caller additionally requires empty census.
            cgroup.resource_snapshot(&self.config.budget)?;
            self.owner.require_actual_watch_files()?;
            let mut s=self.state.lock().map_err(|_|"terminal resource owner poisoned")?;
            if s.failed||self.invalid.load(Ordering::Acquire){return Err("terminal resource failed during recheck".into());}
            s.fresh_dispatch=None;s.fresh_pool=None;Ok(())
        })();if result.is_err(){self.latch();}result
    }
    fn require_empty(&self)->Result<(),String>{
        self.require_current()?;
        let cg={let state=self.owner.resources.lock().map_err(|_|"same original cgroup owner poisoned")?;
            state.terminal_cgroup.as_ref().cloned().ok_or("no original terminal cgroup")?};
        cg.task_census_empty()?;
        if cg.populated()?||cg.resource_snapshot(&self.config.budget)?.pids_current!=0{
            return Err("same original terminal cgroup/tasks remain active".into());}Ok(())
    }
}
impl AttachOwner {
    pub(in crate::storage_driver) fn require_actual_watch_files(&self)->Result<(),String>{
        self.watch_process.lock().map_err(|_|"actual original Watch process root poisoned")?.verify_serving_thread(&self.scope.phase_boot)
    }
    /// SAME original daemon capability on the existing fixed IO actor. The
    /// caller still needs its distinct fresh actual-Core terminal signal token.
    pub(crate) fn terminal_consumer_connection(&self,deadline:Instant)
        ->Result<crate::docker::ManagedConsumerConnection,String>{
        self.require_terminal_retained()?;
        if Instant::now()>=deadline{return Err("original terminal transport deadline expired".into());}
        let connection={let probe=self.probe.lock().map_err(|_|"same terminal daemon probe poisoned")?;
            probe.terminal_daemon_connection(deadline)?};
        self.require_terminal_retained()?;
        if Instant::now()>=deadline{return Err("terminal authenticated transport completed late; no signal permission".into());}
        Ok(connection)
    }
    /// PURE same-original lineage; old operational UNKNOWN/expired attach
    /// clocks are never reset or used as a drain permission.
    pub(crate) fn require_terminal_retained(&self)->Result<(),String>{
        self.assert_actual_store(&self.world)?;
        self.watch_process.try_lock().map_err(|_|"original Watch origin busy/poisoned; no pure permission")?.require_rooted()?;
        let state=self.resources.lock().map_err(|_|"original terminal owner poisoned")?;
        if state.quarantined||state.enqueued||state.terminal_cgroup.is_none()
            ||state.terminal_resources.is_none()||self.quarantine.try_lock().map_err(|_|"original helper quarantine busy")?.is_some(){
            return Err("original work/cgroup/terminal resource lineage unresolved".into());}
        let resources=state.terminal_resources.as_ref().unwrap().clone();
        let volume_absent=state.volume_lease.is_none();
        drop(state); // no owner -> resource-state nested mutex order
        if !std::ptr::eq(Arc::as_ptr(&resources.owner),self){return Err("terminal resources belong to another owner".into());}
        let terminal=resources.state.lock().map_err(|_|"original terminal resource state poisoned")?;
        require_terminal_resource_flags(terminal.failed,resources.invalid.load(Ordering::Acquire))?;
        if volume_absent{
            if !terminal.lease_closes.contains_key("volume"){return Err("original per-volume lease absent without close tombstone".into());}
        }
        Ok(())
    }
    pub(crate) fn retain_terminal_parent(self:&Arc<Self>,parent:Arc<VerifiedTerminalNodeParent>)->Result<(),String>{
        if !Arc::ptr_eq(parent.owner(),self)||!Arc::ptr_eq(parent.actual_store(),&self.world)
            ||parent.scope()!=&self.scope{return Err("terminal parent does not own this exact actual original scope".into());}
        self.require_terminal_retained()?;
        let mut state=self.resources.lock().map_err(|_|"original terminal parent root poisoned")?;
        if let Some(old)=&state.terminal_parent{
            if !Arc::ptr_eq(old,&parent){return Err("actual terminal parent already rooted; no replacement".into());}
        }else{state.terminal_parent=Some(parent);}
        Ok(())
    }
    pub(crate) fn require_terminal_parent(&self,parent:&VerifiedTerminalNodeParent)->Result<(),String>{
        self.require_terminal_retained()?;
        if !std::ptr::eq(Arc::as_ptr(parent.owner()),self)||!Arc::ptr_eq(parent.actual_store(),&self.world)
            ||parent.scope()!=&self.scope{return Err("terminal parent changed original store/owner/scope".into());}
        let state=self.resources.lock().map_err(|_|"actual terminal parent root poisoned")?;
        if state.terminal_parent.as_ref().is_none_or(|p|!std::ptr::eq(Arc::as_ptr(p),parent)){
            return Err("terminal parent is not same root-retained actual session".into());}Ok(())
    }
}
fn require_terminal_resource_flags(failed:bool,invalid:bool)->Result<(),String>{
    if failed||invalid{return Err("actual terminal resource UNKNOWN is sticky; no later permission".into());}Ok(())
}
fn precharge_mandatory_extent(bytes:u64,writer:bool)->Result<usize,String>{
    let count=physical::mandatory_admissions(bytes,writer)?;
    if count>512{return Err("known mandatory terminal read/effect admissions exceed512 BEFORE Create".into());}Ok(count)
}
impl Dispatcher {
    pub(crate) fn reserve_terminal_resources(&self,owner:Arc<AttachOwner>,config:Config)->Result<Arc<ReservedTerminalResources>,String>{
        if !Arc::ptr_eq(&owner.dispatcher_busy,&self.busy)||config_fingerprint(&config)?!=self.policy_sha256
            ||config.node_uid!=owner.scope.phase_node_uid||BootId::current()?!=owner.scope.phase_boot{
            return Err("terminal resource request has another actual dispatcher/node/policy".into());}
        owner.assert_actual_store(&owner.world)?;
        owner.require_actual_watch_files()?;
        let writer=owner.scope.phase_node_uid==*owner.scope.mount_ref.node_uid();
        let mandatory=precharge_mandatory_extent(owner.scope.generation.virgin_replicas[0].exposed_bytes,writer)?;
        let count=if writer{3}else{2};
        let pool=owner.first_parent.pool().clone();pool.validate()?;
        let resource=Arc::new(ReservedTerminalResources{
            uid:Uid::new(),dispatch_path:config.journal_root.join(config.node_uid.as_str()),pool_path:pool.journal_path(),
            policy:config_fingerprint(&config)?,config,owner:owner.clone(),attempts:(0..count).map(|_|Uid::new()).collect(),
            mandatory,invalid:Arc::new(AtomicBool::new(false)),
            state:Mutex::new(ReservedDirectories{dispatch:None,pool:None,fresh_dispatch:None,fresh_pool:None,
                namespace:None,namespace_identity:None,
                dispatch_names:BTreeSet::new(),pool_names:BTreeSet::new(),observation:None,failed:false,next_step:0,
                queued:false,parent:None,current_identity:None,drains:Vec::new(),retirement:None,
                lease_closes:std::collections::BTreeMap::new(),retiring:false,retirement_submitted:false,retirement_queued:false,watch_roles:None})});
        {
            let mut state=owner.resources.lock().map_err(|_|"original terminal reserve root poisoned")?;
            if state.terminal_resources.is_some(){return Err("original terminal resource reservation already attempted; no retry".into());}
            if state.enqueued||state.quarantined||state.global.is_some()||state.global_safety.is_some()
                ||state.volume_lease.is_none()||state.terminal_cgroup.is_none()
                ||state.completed.last().map(|v|v.phase)!=Some(if writer{AttachPhase::ObserveMounted}else{AttachPhase::ObserveSynchronized}){
                return Err("original terminal resources not genuinely handed off/drained".into());}
            state.terminal_resources=Some(resource.clone()); // ROOT before opening ANY directory
        }
        let result=(||{
            let(pidfd,proc,observation)=owner.watch_process.lock().map_err(|_|"actual original Watch process root poisoned")?
                .duplicate_for_child(&owner.scope.phase_boot)?;
            resource.state.lock().map_err(|_|"actual precharged process role root poisoned")?.watch_roles=Some(Arc::new(ReservedWatchRoles{pidfd,proc,observation}));
            // SAME early-held namespace Arc; no second open/dup at pre-Create.
            let namespace=owner.watch_process.lock().map_err(|_|"actual retained Watch namespace poisoned")?
                .retained_namespace(&owner.scope.phase_boot)?;
            resource.state.lock().map_err(|_|"terminal original namespace root poisoned")?.namespace=Some(namespace.clone());
            let identity=physical::namespace_identity(namespace.as_ref())?;
            resource.state.lock().map_err(|_|"terminal original namespace root poisoned")?.namespace_identity=Some(identity);
            let dispatch=Arc::new(Dir::open(&resource.dispatch_path,false)?);
            resource.state.lock().map_err(|_|"terminal reservation root poisoned")?.dispatch=Some(dispatch.clone());
            let pool=Arc::new(Dir::open(&resource.pool_path,false)?);
            resource.state.lock().map_err(|_|"terminal reservation root poisoned")?.pool=Some(pool.clone());
            let dispatch_names:BTreeSet<_>=dispatch.bounded_entries(512)?.into_iter().collect();
            let pool_names:BTreeSet<_>=pool.bounded_entries(512)?.into_iter().collect();
            if dispatch_names.iter().chain(&pool_names).any(|n|n.starts_with(".txn-")){return Err("unfinished original metadata transaction".into());}
            let attempts=dispatch_names.iter().filter(|n|n.starts_with("attempt-")&&n.ends_with(".json")).count();
            let actual_native={owner.resources.lock().map_err(|_|"original completed native owner poisoned")?.current_native.clone()
                .ok_or("original completed attachment native identity absent")?};
            let prior=load_record(&dispatch.read("current.json")?.ok_or("actual completed predecessor absent; no new history")?)?;
            if prior.state!=State::Complete||prior.identity!=actual_native
                ||prior.image_sha256!=resource.config.helper_sha256
                ||!prior.resources_final.as_ref().is_some_and(|v|v.pids_current==0){
                return Err("readonly terminal reservation lacks actual SAME completed dispatch lineage".into());}
            if attempts.checked_add(count).is_none_or(|n|n>128)
                ||dispatch_names.len().checked_add(2*count+1).is_none_or(|n|n>512)
                ||pool_names.len().checked_add(2*count+1).is_none_or(|n|n>512){
                return Err("complete terminal helper/dispatch/pool/temp reservation cannot fit BEFORE Create".into());}
            let observation=TerminalResourceObservation{node_uid:owner.scope.phase_node_uid.clone(),boot:owner.scope.phase_boot.clone(),
                volume_uid:owner.scope.owner.volume_uid.clone(),pool_uid:owner.scope.target()?.pool_uid.clone(),
                dispatch_identity:dispatch.retained_identity()?,pool_identity:pool.retained_identity()?,
                existing_dispatch_entries:dispatch_names.len(),existing_pool_entries:pool_names.len(),existing_attempts:attempts,
                reserved_attempts:count,reserved_dispatch_entries:2*count,reserved_pool_entries:2*count,atomic_temp_peak:1};
            let mut state=resource.state.lock().map_err(|_|"terminal reservation root poisoned")?;
            state.dispatch_names=dispatch_names;state.pool_names=pool_names;state.observation=Some(observation);drop(state);
            resource.require_empty()?;precharge_native_capsules(&resource)?;Ok(resource.clone())
        })();if result.is_err(){resource.latch();}result
    }
}
/// Size-only DATA serialization of every finite precharged terminal helper.
/// No native authority, parent/grant, file or receipt is constructed here.
/// Future operation/node-job UIDs are fixed-width Uid; maximum positive FD
/// numbers/remaining-ms cover actual later roles without truncating identity.
fn precharge_native_capsules(resource:&Arc<ReservedTerminalResources>)->Result<(),String>{
    resource.owner.require_actual_watch_files()?;
    let scope=resource.owner.scope.clone();let pool=resource.owner.first_parent.pool().clone();
    let plan=super::super::super::replica::initialize::managed_mount::phases::retained_plan(&pool,&scope)?.runtime_wire()?;
    let publication=resource.owner.probe.lock().map_err(|_|"actual original publication sizing root poisoned")?.terminal_publication(&scope)?;
    let(cgroup,namespace,roles)={let s=resource.state.lock().map_err(|_|"actual source capsule sizing root poisoned")?;
        let c=resource.owner.resources.lock().map_err(|_|"actual original cgroup root poisoned")?.terminal_cgroup.as_ref().cloned().ok_or("original cgroup absent")?;
        (c,s.namespace_identity.ok_or("actual original namespace absent")?,s.watch_roles.clone().ok_or("actual process roles not reserved")?)};
    for (i,attempt) in resource.attempts.iter().enumerate(){
        let step=physical::expected_step(scope.phase_node_uid==*scope.mount_ref.node_uid(),i).ok_or("precharged finite step absent")?;
        let inner=TerminalPayload{pool:pool.clone(),scope:scope.clone(),operation:resource.uid.clone(),node_job:resource.uid.clone(),
            reservation:resource.uid.clone(),step,publication:publication.clone(),cgroup_identity:cgroup.identity()?,
            pool_identity:resource.observation().pool_identity,delegated_root:resource.config.delegated_cgroup_root.clone(),namespace_identity:namespace,
            watch_process:roles.observation.clone(),watch_pidfd:i32::MAX,watch_proc:i32::MAX-1};
        let payload=Payload{config:serde_json::to_value(&inner).map_err(|_|"terminal precharge DATA encode")?,plan:plan.clone(),projection:Vec::new(),
            extended:Some(ExtendedJob::TerminateManaged),dataset_uid:Some(scope.generation.uid.clone()),remote_binding:Some(payload_binding(&inner)?),initialization:None,worker_remaining_ms:Some(180_000)};
        let identity=live::JobIdentity{node_uid:scope.phase_node_uid.clone(),boot_id:scope.phase_boot.as_str().into(),volume_uid:scope.owner.volume_uid.clone(),
            operation_uid:resource.uid.clone(),attempt_uid:attempt.clone(),binding_sha256:"0".repeat(64)};
        let size=serde_json::to_vec(&Capsule{version:6,identity,payload,budget:resource.config.budget.clone()}).map_err(|_|"terminal precharge capsule DATA encode")?.len();
        if size as u64>CAPSULE_LIMIT{return Err("actual complete terminal capsule/maximum FD roles cannot fit BEFORE Create".into());}
    }resource.owner.require_actual_watch_files()
}
pub(crate) struct TerminalTicket {resources:Arc<ReservedTerminalResources>,receiver:mpsc::Receiver<Result<Arc<VerifiedTerminalDrain>,String>>}
impl TerminalTicket {
    pub(crate) fn try_result(&self)->Result<Option<Arc<VerifiedTerminalDrain>>,String>{
        match self.receiver.try_recv(){Ok(Ok(d))=>Ok(Some(d)),Ok(Err(e))=>Err(e),Err(mpsc::TryRecvError::Empty)=>Ok(None),
            Err(_)=>{self.quarantine();Err("original terminal result lost; actual owner retained".into())}}
    }
    pub(crate) fn quarantine(&self){self.resources.latch();
        let parent={self.resources.state.lock().unwrap_or_else(|p|p.into_inner()).parent.clone()};
        if let Some(parent)=parent{parent.retain_unknown();}}
}
pub(in crate::storage_driver::dispatcher) struct TerminalWork {
    owner:Arc<AttachOwner>,parent:Arc<VerifiedTerminalNodeParent>,resources:Arc<ReservedTerminalResources>,
    step:TerminalNativeStep,result:mpsc::SyncSender<Result<Arc<VerifiedTerminalDrain>,String>>,
}
/// Final close must execute on the SAME dispatcher, not Shared.io: its fresh
/// parent barrier may itself append through Shared.io. No nested IO wait.
pub(in crate::storage_driver::dispatcher) struct TerminalRetirementWork {
    parent:Arc<VerifiedTerminalNodeParent>,resources:Arc<ReservedTerminalResources>,drain:Arc<VerifiedTerminalDrain>,
    result:mpsc::SyncSender<Result<Arc<RetiredTerminalLease>,String>>,
}
pub(crate) struct TerminalRetirementTicket {
    resources:Arc<ReservedTerminalResources>,receiver:mpsc::Receiver<Result<Arc<RetiredTerminalLease>,String>>,
}
impl TerminalRetirementTicket {
    pub(crate) fn try_result(&self)->Result<Option<Arc<RetiredTerminalLease>>,String>{
        match self.receiver.try_recv(){Ok(Ok(value))=>Ok(Some(value)),Ok(Err(error))=>Err(error),
            Err(mpsc::TryRecvError::Empty)=>Ok(None),Err(_)=>{self.quarantine();Err("terminal retirement reply lost; actual tombstones/result remain rooted".into())}}
    }
    pub(crate) fn quarantine(&self){self.resources.latch();
        let parent={self.resources.state.lock().unwrap_or_else(|p|p.into_inner()).parent.clone()};
        if let Some(parent)=parent{parent.retain_unknown();}}
}
impl Dispatcher {
    pub(crate) fn submit_terminal_retirement(&self,owner:Arc<AttachOwner>,parent:Arc<VerifiedTerminalNodeParent>,
        resources:Arc<ReservedTerminalResources>,drain:Arc<VerifiedTerminalDrain>)
        ->Result<TerminalRetirementTicket,RetainedAttachError>{
        owner.require_terminal_parent(&parent).map_err(RetainedAttachError::Unavailable)?;
        drain.require_parent(&parent).map_err(RetainedAttachError::Unavailable)?;
        parent.require_detached_confirmed().map_err(RetainedAttachError::Unavailable)?;
        if !Arc::ptr_eq(&owner,&resources.owner)||!Arc::ptr_eq(&owner.dispatcher_busy,&self.busy)
            ||!Arc::ptr_eq(&drain.resources,&resources)||resources.policy!=self.policy_sha256{
            return Err(RetainedAttachError::Unavailable("retirement does not own SAME original dispatcher/drain/resources".into()));}
        {let mut state=resources.state.lock().map_err(|_|RetainedAttachError::Unknown("actual retirement root poisoned".into()))?;
            if state.failed||state.queued||state.retirement_submitted||state.retiring||state.retirement.is_some()
                ||state.next_step!=resources.attempts.len()||state.drains.last().is_none_or(|last|!Arc::ptr_eq(last,&drain)){
                return Err(RetainedAttachError::Unavailable("retirement not original final known drain or already submitted".into()));}
            state.retirement_submitted=true;state.retirement_queued=true;state.parent=Some(parent.clone());
        }
        let(send,receive)=mpsc::sync_channel(1);
        match self.queue.try_send(WorkItem::TerminalRetire(TerminalRetirementWork{parent,resources:resources.clone(),drain,result:send})){
            Ok(())=>Ok(TerminalRetirementTicket{resources,receiver:receive}),
            Err(mpsc::TrySendError::Full(original))|Err(mpsc::TrySendError::Disconnected(original))=>{
                drop(original); // exact original Work returned BEFORE receive
                resources.state.lock().map_err(|_|RetainedAttachError::Unknown("retirement no-receive root poisoned".into()))?.retirement_queued=false;
                Err(RetainedAttachError::NeverSubmitted("final retirement Work never received; all original physical owners remain, no retry".into()))
            }
        }
    }
}
pub(in crate::storage_driver::dispatcher) fn run_retirement(work:&mut TerminalRetirementWork){
    let result=work.drain.retire_original_lease(&work.parent);
    if result.is_err(){work.resources.latch();work.parent.retain_unknown();}
    work.resources.state.lock().unwrap_or_else(|p|p.into_inner()).retirement_queued=false;
    // Actual retirement object/tombstones were rooted BEFORE this send. A
    // vanished ticket cannot recreate already closed descriptors or claim held.
    let _=work.result.try_send(result);
}
pub(crate) struct VerifiedTerminalDrain {
    owner:Arc<AttachOwner>,parent:Arc<VerifiedTerminalNodeParent>,resources:Arc<ReservedTerminalResources>,
    identity:live::JobIdentity,step:TerminalNativeStep,observation:TerminalPhysicalObservation,
    record:Record,raw:Vec<u8>,completion:VerifiedLocalBoundary,
}
impl VerifiedTerminalDrain {
    pub(crate) fn require_parent(&self,parent:&VerifiedTerminalNodeParent)->Result<(),String>{
        self.owner.require_terminal_parent(parent)?;
        if !std::ptr::eq(Arc::as_ptr(&self.parent),parent)||!Arc::ptr_eq(&self.owner,&self.resources.owner)
            ||self.record.state!=State::Complete||self.record.identity!=self.identity{
            return Err("terminal actual drain has another original parent/native/resource lineage".into());}
        self.observation.validate(parent.scope(),parent.terminal_operation_uid(),self.step)
    }
    pub(crate) fn step(&self)->TerminalNativeStep{self.step}
    pub(crate) fn observation(&self)->&TerminalPhysicalObservation{&self.observation}
    pub(crate) fn completion_sha256(&self)->&str{self.completion.binding()}
}
pub(crate) struct RetiredTerminalLease {node:Uid,volume:Uid,evidence:String}
impl RetiredTerminalLease {
    pub(crate) fn node_uid(&self)->&Uid{&self.node}
    pub(crate) fn volume_uid(&self)->&Uid{&self.volume}
    pub(crate) fn evidence_sha256(&self)->&str{&self.evidence}
}

#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminalPayload {
    pool:super::super::super::Config,scope:ExpectedAttachScope,operation:Uid,node_job:Uid,reservation:Uid,
    step:TerminalNativeStep,publication:Option<physical::TerminalPublication>,
    cgroup_identity:(u64,u64),pool_identity:(u64,u64),delegated_root:std::path::PathBuf,
    namespace_identity:(u64,u64),
    watch_process:WatchProcessObservation,watch_pidfd:i32,watch_proc:i32,
}
fn payload_binding(value:&TerminalPayload)->Result<String,String>{
    Ok(hash(&serde_json::to_vec(&("actual-managed-terminal-v1",value)).map_err(|_|"terminal exact payload binding failed")?))
}
pub(in crate::storage_driver::dispatcher) fn valid_capsule(capsule:&Capsule)->bool{
    let Ok(payload)=serde_json::from_value::<TerminalPayload>(capsule.payload.config.clone())else{return false;};
    let writer=payload.scope.phase_node_uid==*payload.scope.mount_ref.node_uid();
    capsule.version==6 && capsule.payload.extended==Some(ExtendedJob::TerminateManaged)
        &&payload.pool.validate().is_ok()&&payload.scope.validate().is_ok()
        &&capsule.identity.node_uid==payload.scope.phase_node_uid
        &&capsule.identity.boot_id==payload.scope.phase_boot.as_str()
        &&capsule.identity.volume_uid==payload.scope.owner.volume_uid&&capsule.identity.operation_uid==payload.operation
        &&payload.pool.node_uid==payload.scope.phase_node_uid
        &&(payload.step!=TerminalNativeStep::UnmountAndDemote||writer)
        &&payload.publication.is_some()==writer
        &&payload.cgroup_identity.1>0&&payload.pool_identity.1>0&&payload.namespace_identity.1>0&&payload.delegated_root.is_absolute()
        &&payload.watch_process.pid>0&&payload.watch_process.boot()==&payload.scope.phase_boot
        &&payload.watch_process.namespace()==payload.namespace_identity
        &&payload.watch_pidfd>=3&&payload.watch_proc>=3&&payload.watch_pidfd!=payload.watch_proc
        &&capsule.payload.dataset_uid.as_ref()==Some(&payload.scope.generation.uid)
        &&capsule.payload.worker_remaining_ms.is_some_and(|n|n>0&&n<=180_000)
        &&capsule.payload.projection.is_empty()&&capsule.payload.initialization.is_none()
        &&capsule.payload.remote_binding.as_deref()==payload_binding(&payload).ok().as_deref()
}
/// Kernel observation input only. Its PRIVATE producer below has already
/// joined actual protected capsule/lease/launching-root socket and original FD.
pub(in crate::storage_driver) struct VerifiedInheritedTerminalCgroup {
    file:File,identity:(u64,u64),budget:super::super::super::ResourceBudget,
}
impl VerifiedInheritedTerminalCgroup {
    pub(in crate::storage_driver) fn into_kernel_parts(self)->(File,(u64,u64),super::super::super::ResourceBudget){
        (self.file,self.identity,self.budget)
    }
}
pub(in crate::storage_driver::dispatcher) fn take_inherited_cgroup(capsule:&Capsule,binding:&CgroupBinding,
    lease:&File,control:&UnixStream,root:&std::path::Path)->Result<VerifiedInheritedTerminalCgroup,String>{
    if !cfg!(target_os="linux")||!valid_capsule(capsule){return Err("terminal inherited cgroup needs exact private v6 capsule".into());}
    live::verify_terminal_parent_channel(control)?;
    let payload:TerminalPayload=serde_json::from_value(capsule.payload.config.clone()).map_err(|_|"terminal cgroup payload invalid")?;
    let raw=std::env::var("ROYAK_TERMINAL_CGROUP_FD").map_err(|_|"actual terminal cgroup FD was not inherited")?
        .parse::<i32>().map_err(|_|"terminal inherited FD number malformed")?;
    if raw<3||raw==lease.as_raw_fd()||raw==control.as_raw_fd(){return Err("terminal original cgroup FD aliases another inherited role".into());}
    // Inspect the raw number BEFORE taking ownership: a wrong number must
    // not close an unrelated already-owned capsule/socket/directory on Err.
    verify_original_cgroup_number(raw,payload.cgroup_identity)?;
    let file=unsafe{File::from_raw_fd(raw)};
    let flags=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFD)};
    if flags<0||unsafe{libc::fcntl(file.as_raw_fd(),libc::F_SETFD,flags|libc::FD_CLOEXEC)}<0{
        return Err("cannot confine original cgroup FD to terminal helper".into());}
    let m=file.metadata().map_err(|_|"original inherited cgroup metadata absent")?;
    let named=root.join(format!("rkjob-{}",capsule.identity.node_uid.as_str()));
    let pathname=std::fs::symlink_metadata(&named).map_err(|_|"original terminal node leaf disappeared; never recreate")?;
    if root!=payload.delegated_root||std::fs::canonicalize(root).map_err(|_|"original cgroup root unavailable")?!=root
        ||pathname.file_type().is_symlink()||!pathname.is_dir()||!m.is_dir()
        ||(m.dev(),m.ino())!=payload.cgroup_identity||(pathname.dev(),pathname.ino())!=payload.cgroup_identity
        ||binding.version!=1||binding.node_uid!=capsule.identity.node_uid||binding.boot_id!=capsule.identity.boot_id
        ||(binding.device,binding.inode)!=payload.cgroup_identity
        ||BootId::current()?.as_str()!=capsule.identity.boot_id
        ||unsafe{libc::flock(lease.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}!=0{
        return Err("terminal original cgroup/boot/private lease incarnation changed".into());}
    Ok(VerifiedInheritedTerminalCgroup{file,identity:payload.cgroup_identity,budget:capsule.budget.clone()})
}
// Read-only actual-kernel observation, not an authority producer. In
// particular an env number, successful fstat, or ordinary directory alone
// cannot mint VerifiedInheritedTerminalCgroup.
fn verify_original_cgroup_number(raw:i32,expected:(u64,u64))->Result<(),String>{
    let mut stat:libc::stat=unsafe{std::mem::zeroed()};
    let mut filesystem:libc::statfs=unsafe{std::mem::zeroed()};
    if raw<3||unsafe{libc::fstat(raw,&mut stat)}!=0||unsafe{libc::fstatfs(raw,&mut filesystem)}!=0
        ||filesystem.f_type as u64!=0x63677270
        ||(stat.st_mode as u32&libc::S_IFMT as u32)!=libc::S_IFDIR as u32
        ||(stat.st_dev as u64,stat.st_ino as u64)!=expected{
        return Err("inherited number is not the SAME actual cgroup directory; no ownership/adoption".into());
    }Ok(())
}
pub(in crate::storage_driver) struct VerifiedTerminalPhase {
    identity:live::JobIdentity,payload:TerminalPayload,deadline:Instant,effects:Mutex<Sha256>,
    watch:InheritedWatchProcess,
}
/// Read-only classification witness from actual original process FDs and a
/// fresh matching inherited-channel census ACK. Never serde/raw/bool ctor.
pub(in crate::storage_driver) struct VerifiedReferenceCensusContext<'a>{
    phase:&'a VerifiedTerminalPhase,point:anchor::TerminalCensusPoint,
    references:Vec<physical::WatchCloseReference>,begin:String,
}
impl VerifiedReferenceCensusContext<'_>{
    pub(in crate::storage_driver) fn point(&self)->anchor::TerminalCensusPoint{self.point}
    pub(in crate::storage_driver) fn leader(&self)->u32{self.phase.watch.pid()}
    pub(in crate::storage_driver) fn potential_original(&self,tgid:u32,number:&str)->bool{
        tgid==self.leader()&&number.parse::<i32>().ok().is_some_and(|n|self.references.iter().any(|r|r.number()==n))
    }
    pub(in crate::storage_driver) fn before_fstat(&self,tgid:u32,tid:u32,namespace:(u64,u64))->Result<(),String>{
        self.phase.local_live()?;
        if namespace!=self.phase.payload.namespace_identity{return Err("represented Watch task namespace changed".into());}
        self.phase.watch.verify_observed_table(tgid,tid)
    }
    pub(in crate::storage_driver) fn after_fstat(&self,tgid:u32,tid:u32,namespace:(u64,u64),number:&str,
        metadata:&std::fs::Metadata)->Result<i32,String>{
        self.before_fstat(tgid,tid,namespace)?;
        let matches=self.references.iter().filter(|r|r.matches_observed(number,metadata)).collect::<Vec<_>>();
        if matches.len()!=1{return Err("observed Watch FD is not SAME original retained block File slot".into());}
        Ok(matches[0].number())
    }
    pub(in crate::storage_driver) fn require_leader_slots(&self,seen:&BTreeSet<i32>)->Result<(),String>{
        self.phase.local_live()?;
        if self.references.iter().any(|r|!seen.contains(&r.number())){
            return Err("original pinned Watch leader reference table was not completely observed".into());}Ok(())
    }
    pub(in crate::storage_driver) fn provenance_sha256(&self)->Result<String,String>{
        Ok(hash(self.provenance_json()?.as_bytes()))
    }
    pub(in crate::storage_driver) fn provenance_json(&self)->Result<String,String>{
        serde_json::to_string(&(&self.phase.identity,self.point,&self.phase.payload.watch_process,&self.references,&self.begin))
            .map_err(|_|"actual represented reference provenance encode failed".into())
    }
    pub(in crate::storage_driver) fn finish(self,census:&anchor::TerminalReferenceCensus)->Result<(),String>{
        self.phase.local_live()?;
        let outcome=hash(&serde_json::to_vec(census).map_err(|_|"actual reference census encode failed")?);
        let detail=self.phase.detail_bytes(TerminalBoundary::Identity,&("reference-census-end-v2",self.point,&self.begin,&outcome))?;
        let receipt=live::terminal_reference_end(self.point.code()?,&self.begin,&outcome,&detail)?;
        self.phase.effects.lock().map_err(|_|"terminal reference chain poisoned")?.update(receipt.request_sha256()?.as_bytes());
        self.phase.local_live()
    }
}
/// Minted ONLY from actual private v6 worker authority and verified original
/// inherited process roles. No raw/serde/default constructor.
pub(in crate::storage_driver) struct VerifiedWatchProcessInheritance {pidfd:File,proc:File,observation:WatchProcessObservation}
impl VerifiedWatchProcessInheritance {
    pub(in crate::storage_driver) fn into_parts(self)->(File,File,WatchProcessObservation){(self.pidfd,self.proc,self.observation)}
}
fn take_watch_process(authority:&VerifiedNativeAuthority,payload:&TerminalPayload)->Result<VerifiedWatchProcessInheritance,String>{
    let(peer,control)=live::terminal_parent_identity()?;
    let roles=[payload.watch_pidfd,payload.watch_proc];
    if roles.iter().any(|raw|*raw<3||[*raw==control,*raw==authority._lease.as_raw_fd(),*raw==authority._capsule_file.as_raw_fd()].contains(&true)){
        return Err("actual Watch inherited role aliases another original capability".into());}
    physical::origin::verify_borrowed_pair(roles[0],roles[1],&payload.watch_process,peer)?;
    let pidfd=unsafe{File::from_raw_fd(roles[0])};let proc=unsafe{File::from_raw_fd(roles[1])};
    for file in [&pidfd,&proc]{let flags=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_GETFD)};
        if flags<0||unsafe{libc::fcntl(file.as_raw_fd(),libc::F_SETFD,flags|libc::FD_CLOEXEC)}<0{
            return Err("cannot confine inherited original Watch process roles".into());}}
    Ok(VerifiedWatchProcessInheritance{pidfd,proc,observation:payload.watch_process.clone()})
}
impl VerifiedTerminalPhase {
    pub(in crate::storage_driver) fn begin_reference_census(&self,point:anchor::TerminalCensusPoint)
        ->Result<VerifiedReferenceCensusContext<'_>,String>{
        self.local_live()?;point.code()?;
        if self.step()!=TerminalNativeStep::UnmountAndDemote||self.scope().phase_node_uid!=*self.scope().mount_ref.node_uid(){
            return Err("only current genuine writer unmount can represent original block slots".into());}
        let references=self.payload.publication.as_ref().ok_or("actual original publication absent")?.closes.iter()
            .filter(|r|!r.is_mounted()).cloned().collect::<Vec<_>>();
        if references.is_empty()||references.len()>2||references.iter().map(|r|r.number()).collect::<BTreeSet<_>>().len()!=references.len(){
            return Err("original block reference source absent/duplicated/over bound".into());}
        let detail=self.detail_bytes(TerminalBoundary::Identity,&("reference-census-begin-v2",point,&self.payload.watch_process,&references))?;
        let receipt=live::terminal_reference_begin(point.code()?,&detail)?;let begin=receipt.request_sha256()?;
        self.effects.lock().map_err(|_|"terminal reference chain poisoned")?.update(begin.as_bytes());self.local_live()?;
        Ok(VerifiedReferenceCensusContext{phase:self,point,references,begin})
    }
    pub(in crate::storage_driver) fn from_inherited(authority:&VerifiedNativeAuthority)
        ->Result<(Self,super::super::super::Config),String>{
        if !valid_capsule(&authority.capsule){return Err("not exact inherited managed-terminal v6 worker".into());}
        live::terminal_channel_identity(&authority.capsule.identity)?;
        let payload:TerminalPayload=serde_json::from_value(authority.capsule.payload.config.clone()).map_err(|_|"terminal actual payload corrupt")?;
        let remaining=authority.capsule.payload.worker_remaining_ms.ok_or("terminal original remaining deadline absent")?;
        let deadline=Instant::now().checked_add(Duration::from_millis(remaining)).ok_or("terminal deadline overflow")?;
        let watch=InheritedWatchProcess::from_verified(take_watch_process(authority,&payload)?)?;
        let pool=payload.pool.clone();
        Ok((Self{identity:authority.capsule.identity.clone(),payload,deadline,effects:Mutex::new(Sha256::new()),watch},pool))
    }
    pub(in crate::storage_driver) fn scope(&self)->&ExpectedAttachScope{&self.payload.scope}
    pub(in crate::storage_driver) fn step(&self)->TerminalNativeStep{self.payload.step}
    pub(in crate::storage_driver) fn operation(&self)->&Uid{&self.payload.operation}
    pub(in crate::storage_driver) fn identity(&self)->&live::JobIdentity{&self.identity}
    pub(in crate::storage_driver) fn deadline(&self)->Instant{self.deadline}
    pub(in crate::storage_driver) fn publication(&self)->Option<&physical::TerminalPublication>{self.payload.publication.as_ref()}
    fn local_live(&self)->Result<(),String>{
        self.watch.require_live()?;
        if Instant::now()>=self.deadline||BootId::current()?!=self.payload.scope.phase_boot{
            return Err("original terminal helper budget/boot expired; no later action".into());}
        if physical::namespace_identity(&physical::capture_watch_namespace()?)?!=self.payload.namespace_identity{
            return Err("actual terminal helper is in another original namespace".into());}
        live::terminal_channel_identity(&self.identity)
    }
    pub(in crate::storage_driver) fn detail_bytes<T:Serialize>(&self,kind:TerminalBoundary,value:&T)->Result<Vec<u8>,String>{
        serde_json::to_vec(&("managed-terminal-action-v1",&self.payload.operation,&self.payload.node_job,
            scope_digest(&self.payload.scope)?,self.payload.step,kind,value)).map_err(|_|"terminal closed action binding failed".into())
    }
    pub(in crate::storage_driver) fn begin_effect<T:Serialize>(&self,kind:TerminalBoundary,value:&T)->Result<live::TerminalRequestReceipt,String>{
        self.local_live()?;
        let receipt=live::terminal_request(kind,&self.detail_bytes(kind,value)?)?;
        self.effects.lock().map_err(|_|"terminal effect chain poisoned")?.update(receipt.request_sha256()?.as_bytes());
        self.local_live()?;Ok(receipt)
    }
    pub(in crate::storage_driver) fn finish_effect<T:Serialize>(&self,receipt:live::TerminalRequestReceipt,
        kind:TerminalBoundary,result:&T)->Result<(),String>{
        let result_hash=hash(&serde_json::to_vec(result).map_err(|_|"actual terminal result encoding failed")?);
        // Result may arrive late: parent records matching admitted DATA first,
        // then rejects timeliness; this never creates another effect grant.
        receipt.record_result(kind,&result_hash)?;
        self.effects.lock().map_err(|_|"terminal effect chain poisoned")?.update(result_hash.as_bytes());
        self.local_live()
    }
    pub(in crate::storage_driver) fn checkpoint(&self)->Result<(),String>{
        self.begin_effect(TerminalBoundary::Identity,&"same-original-terminal-worker").map(|_|())
    }
    pub(in crate::storage_driver) fn before_read(&self,offset:u64,length:u64)->Result<(),String>{
        let bytes=self.scope().generation.virgin_replicas[0].exposed_bytes;
        if self.step()!=TerminalNativeStep::OfflineAndObserve||length==0||length>1024*1024||length%4096!=0
            ||offset%4096!=0||offset.checked_add(length).is_none_or(|n|n>bytes){
            return Err("terminal read outside exact unchanged1MiB offline extent".into());}
        self.begin_effect(TerminalBoundary::Read,&(offset,length)).map(|_|())
    }
    pub(in crate::storage_driver) fn close_watch(&self,reference:&physical::WatchCloseReference)->Result<(),String>{
        let kind=if reference.is_mounted(){TerminalBoundary::CloseMounted}else{TerminalBoundary::CloseBlock};
        // Actual Watch callback closes+records this exact original descriptor
        // BEFORE its positive response. No duplicate child result is submitted.
        self.begin_effect(kind,&("watch-reference",reference)).map(|_|())
    }
    pub(in crate::storage_driver) fn effects_sha256(&self)->Result<String,String>{
        Ok(format!("{:x}",self.effects.lock().map_err(|_|"terminal effect chain poisoned")?.clone().finalize()))
    }
    pub(in crate::storage_driver) fn local_live_after_evidence(&self)->Result<(),String>{self.local_live()}
    pub(in crate::storage_driver) fn verify_pool_directory(&self,dir:&Dir)->Result<(),String>{
        if dir.retained_identity()?!=self.payload.pool_identity{return Err("terminal helper pool descriptor differs from actual reserved original".into());}
        self.local_live()
    }
}
impl Dispatcher {
    pub(crate) fn submit_terminal_phase(&self,owner:Arc<AttachOwner>,parent:Arc<VerifiedTerminalNodeParent>,
        resources:Arc<ReservedTerminalResources>,step:TerminalNativeStep)->Result<TerminalTicket,RetainedAttachError>{
        owner.require_terminal_parent(&parent).map_err(RetainedAttachError::Unavailable)?;
        parent.require_live().map_err(RetainedAttachError::Unavailable)?;
        if !Arc::ptr_eq(&owner,&resources.owner)||!Arc::ptr_eq(&owner.dispatcher_busy,&self.busy)
            ||resources.policy!=self.policy_sha256||resources.invalid.load(Ordering::Acquire){
            return Err(RetainedAttachError::Unavailable("not SAME terminal owner/dispatcher/reservation".into()));}
        {
            let state=owner.resources.lock().map_err(|_|RetainedAttachError::Unknown("actual terminal owner poisoned".into()))?;
            if state.terminal_resources.as_ref().is_none_or(|r|!Arc::ptr_eq(r,&resources)){
                return Err(RetainedAttachError::Unavailable("wire/caller resource is not actual rooted reservation".into()));}
        }
        let writer=owner.scope.phase_node_uid==*owner.scope.mount_ref.node_uid();
        let mut reserved=resources.state.lock().map_err(|_|RetainedAttachError::Unknown("original terminal reservation poisoned".into()))?;
        if reserved.failed||reserved.queued||physical::expected_step(writer,reserved.next_step)!=Some(step){
            return Err(RetainedAttachError::Unavailable("terminal helper skipped/repeated/unknown/already queued".into()));}
        let mut state=owner.resources.lock().map_err(|_|RetainedAttachError::Unknown("actual terminal owner poisoned".into()))?;
        let acquired=if state.global.is_none(){
            if state.global_safety.is_some()||self.busy.compare_exchange(false,true,Ordering::AcqRel,Ordering::Acquire).is_err(){
                return Err(RetainedAttachError::NeverSubmitted("terminal node slot busy; no queue send/actor".into()));}
            state.global=Some(RetainedNodeAdmission{lease:None,busy:self.busy.clone(),release_on_drop:false});true
        }else{
            if state.global.as_ref().is_none_or(|g|!Arc::ptr_eq(&g.busy,&self.busy))||!self.busy.load(Ordering::Acquire){
                return Err(RetainedAttachError::Unknown("retained terminal global admission lost SAME dispatcher registry".into()));}
            false
        };
        reserved.queued=true;reserved.parent=Some(parent.clone());drop(state);drop(reserved);
        let(send,receive)=mpsc::sync_channel(1);
        match self.queue.try_send(WorkItem::Terminal(TerminalWork{owner:owner.clone(),parent,resources:resources.clone(),step,result:send})){
            Ok(())=>Ok(TerminalTicket{resources,receiver:receive}),
            Err(mpsc::TrySendError::Full(original))|Err(mpsc::TrySendError::Disconnected(original))=>{
                drop(original); // actual returned move-only Work, NEVER received
                let mut s=resources.state.lock().map_err(|_|RetainedAttachError::Unknown("original queue-failure root poisoned".into()))?;
                s.queued=false;drop(s);
                if acquired{
                    let mut state=owner.resources.lock().map_err(|_|RetainedAttachError::Unknown("actual queue-failure admission poisoned".into()))?;
                    if state.global.as_ref().is_some_and(|v|v.lease.is_some())||state.global_safety.is_some(){
                        return Err(RetainedAttachError::Unknown("cannot prove never-started terminal admission; retained".into()));}
                    let original=state.global.take();drop(original);self.busy.store(false,Ordering::Release);
                }
                Err(RetainedAttachError::NeverSubmitted("exact failed terminal send before receive; earlier real stages retained".into()))
            }
        }
    }
}
fn exclusive_probe<T>(probe:&Mutex<T>)->Result<std::sync::MutexGuard<'_,T>,String>{
    probe.try_lock().map_err(|_|"active original mounted-source borrow; cannot close concurrently".into())
}
pub(in crate::storage_driver::dispatcher) fn run_work(config:&Config,work:&mut TerminalWork){
    let result=(||{
        work.owner.require_terminal_parent(&work.parent)?;work.parent.require_live()?;
        work.resources.require_empty()?;
        {
            let mut probe=exclusive_probe(&work.owner.probe)?;
            probe.begin_terminal(&work.parent)?;
        }
        let drain=launch(config,work)?; // actual opaque result already rooted
        if work.step==TerminalNativeStep::UnmountAndDemote{
            work.owner.probe.lock().map_err(|_|"original terminal underlay owner poisoned")?.verify_terminal_unmounted(&work.parent)?;
        }
        let actual=work.owner.probe.lock().map_err(|_|"original terminal reference owner poisoned")?
            .terminal_closed_dispositions(&work.parent)?;
        if actual!=(drain.observation.mounted_refs,drain.observation.block_refs){
            return Err("actual Watch descriptor tombstones differ from child diagnostics".into());}
        work.parent.complete(&drain,&drain.completion)?;
        work.parent.require_live()?;
        let mut state=work.resources.state.lock().map_err(|_|"original terminal completed root poisoned")?;
        if state.failed||!state.queued||work.resources.invalid.load(Ordering::Acquire){
            return Err("terminal completion raced actual retained UNKNOWN".into());}
        state.next_step+=1;state.queued=false;Ok(drain)
    })();
    if result.is_err(){work.resources.latch();work.parent.retain_unknown();}
    let _=work.result.try_send(result);
    // Same actual dispatcher worker remains with original quarantine. No
    // ticket/HTTP/error Drop releases actual child/cgroup/global references.
    loop{
        let mut state=work.owner.quarantine.lock().unwrap_or_else(|p|p.into_inner());
        let Some(original)=state.as_mut()else{break};
        if let Some(child)=original.child.as_mut(){if matches!(child.try_wait(),Ok(Some(_))){original.child=None;}}
        let drained=original.child.is_none()&&matches!(original.cgroup.populated(),Ok(false));drop(state);
        if drained{break;}std::thread::sleep(Duration::from_millis(50));
    }
}
fn action_bytes(payload:&TerminalPayload,kind:TerminalBoundary,value:&impl Serialize)->Result<Vec<u8>,String>{
    serde_json::to_vec(&("managed-terminal-action-v1",&payload.operation,&payload.node_job,scope_digest(&payload.scope)?,
        payload.step,kind,value)).map_err(|_|"actual terminal action binding failed".into())
}
/// Constructor is private to this dispatcher module and used ONLY after the
/// one actual parent.approve below succeeds. No serde/Clone/raw/bool factory.
pub(in crate::storage_driver) struct ApprovedReferenceCensus {prepared:physical::PreparedReferenceCensus}
impl ApprovedReferenceCensus {
    pub(in crate::storage_driver) fn into_prepared(self)->physical::PreparedReferenceCensus{self.prepared}
}
struct ReferenceCensusFailure<'a>{work:&'a TerminalWork,finished:bool}
impl Drop for ReferenceCensusFailure<'_>{fn drop(&mut self){
    if !self.finished{
        // NEVER acquire probe here. Inner lexical probe guards unwind/drop
        // first; existing resources and parent latches do not acquire probe.
        self.work.resources.latch();self.work.parent.retain_unknown();
    }
}}
fn authorize_reference_census_unlocked(work:&TerminalWork,boundary:&VerifiedLocalBoundary,
    identity:&live::JobIdentity,point:anchor::TerminalCensusPoint,begin:Option<&str>,
    detail:&str,refs:&[physical::WatchCloseReference])->Result<(),String>{
    let mut failure=ReferenceCensusFailure{work,finished:false};
    let prepared={
        let mut probe=work.owner.probe.lock().map_err(|_|"actual original reference probe poisoned")?;
        probe.prepare_reference_census(&work.parent,identity,point,begin,detail,refs)?
    }; // ALL probe guards end BEFORE the actual blocking fresh authorization.
    work.parent.approve(boundary,TerminalBoundary::Identity,detail)?;
    let approved=ApprovedReferenceCensus{prepared};
    work.resources.require_current()?;work.parent.require_live()?;
    {
        let mut probe=work.owner.probe.lock().map_err(|_|"actual pending reference probe poisoned")?;
        probe.commit_reference_census(&work.parent,approved)?;
    }
    failure.finished=true;Ok(())
}
fn handle_request(work:&TerminalWork,payload:&TerminalPayload,identity:&live::JobIdentity,
    request:&live::Request)->Result<Option<bool>,String>{
    if &request.identity!=identity||request.version!=1||request.sequence==0||!valid_hash(&request.detail_sha256){
        return Ok(Some(false));}
    let boundary=VerifiedLocalBoundary::new(request,identity)?;
    let detail=hash(&serde_json::to_vec(request).map_err(|_|"actual terminal request encoding failed")?);
    if request.boundary.starts_with("terminal-reference-census-"){
        if work.step!=TerminalNativeStep::UnmountAndDemote||payload.scope.phase_node_uid!=*payload.scope.mount_ref.node_uid(){
            return Err("reference representation outside genuine writer unmount".into());}
        work.resources.require_current()?;work.parent.require_live()?;
        let refs=payload.publication.as_ref().ok_or("actual writer publication absent")?.closes.iter()
            .filter(|r|!r.is_mounted()).cloned().collect::<Vec<_>>();
        let pieces=request.boundary.split('/').collect::<Vec<_>>();
        let point=anchor::TerminalCensusPoint::from_code(pieces.get(1).ok_or("reference census point absent")?
            .parse::<u8>().map_err(|_|"reference census point malformed")?)?;
        let(begin,expected)=match pieces.first().copied(){
            Some("terminal-reference-census-begin")if pieces.len()==2=>(None,
                action_bytes(payload,TerminalBoundary::Identity,&("reference-census-begin-v2",point,&payload.watch_process,&refs))?),
            Some("terminal-reference-census-end")if pieces.len()==4&&valid_hash(pieces[2])&&valid_hash(pieces[3])=>(Some(pieces[2]),
                action_bytes(payload,TerminalBoundary::Identity,&("reference-census-end-v2",point,pieces[2],pieces[3]))?),
            _=>return Err("closed reference census subframe malformed".into())};
        if request.detail_sha256!=hash(&expected){return Err("reference census actual request binding changed".into());}
        authorize_reference_census_unlocked(work,&boundary,identity,point,begin,&detail,&refs)?;
        return Ok(Some(true));
    }
    if request.boundary.starts_with("terminal-result/"){
        let pieces=request.boundary.split('/').collect::<Vec<_>>();
        if pieces.len()!=4||pieces[0]!="terminal-result"||!valid_hash(pieces[2])||!valid_hash(pieces[3]){
            return Err("terminal result subframe malformed".into());}
        let code=pieces[1].parse::<u8>().map_err(|_|"terminal result kind malformed")?;
        let kind=terminal_kind_code(code).ok_or("terminal result kind outside closed enum")?;
        if !matches!(kind,TerminalBoundary::FlushMount|TerminalBoundary::CloseMounted|TerminalBoundary::Unmount
            |TerminalBoundary::CloseBlock|TerminalBoundary::Demote|TerminalBoundary::Offline|TerminalBoundary::CloseRead|TerminalBoundary::RetireLease){
            return Err("observation/result subframe cannot create another effect permission".into());}
        if request.detail_sha256!=hash(&serde_json::to_vec(&("managed-terminal-result-v1",code,pieces[2],pieces[3]))
            .map_err(|_|"actual terminal result binding encode failed")?){return Err("terminal result detail differs from exact payload".into());}
        work.parent.record_native_result(&boundary,kind,pieces[2],pieces[3])?;
        if kind==TerminalBoundary::Unmount{
            // Actual target/underlay is independently observed, not inferred
            // from the child result hash. This precedes any Watch block close.
            work.owner.probe.lock().map_err(|_|"actual terminal unmount proof owner poisoned")?.verify_terminal_unmounted(&work.parent)?;
        }
        return Ok(Some(true));
    }
    let Some(kind)=native_kind(request,identity)else{return Ok(Some(false))};
    work.resources.require_current()?;work.parent.require_live()?;
    if kind==TerminalBoundary::Unmount{
        work.owner.probe.lock().map_err(|_|"actual completed reference census root poisoned")?.require_before_unmount_census()?;
    }
    if matches!(kind,TerminalBoundary::CloseMounted|TerminalBoundary::CloseBlock){
        if let Some(publication)=&payload.publication{
            for reference in &publication.closes{
                let expected_kind=if reference.is_mounted(){TerminalBoundary::CloseMounted}else{TerminalBoundary::CloseBlock};
                if expected_kind==kind && request.detail_sha256==hash(&action_bytes(payload,kind,&("watch-reference",reference))?){
                    work.owner.probe.lock().map_err(|_|"original terminal close owner poisoned")?
                        .close_terminal_reference(&work.parent,&boundary,reference,&detail)?;
                    return Ok(Some(true));
                }
            }
        }
    }
    work.parent.approve(&boundary,kind,&detail)?;Ok(Some(true))
}
fn launch(config:&Config,work:&TerminalWork)->Result<Arc<VerifiedTerminalDrain>,String>{
    work.resources.require_empty()?;work.parent.require_live()?;
    if !cfg!(target_os="linux")||unsafe{libc::geteuid()}!=0{return Err("actual terminal helper needs Linux root".into());}
    let agent=NativeAgent::from_terminal_parent(&work.parent)?;
    let(scope,operation)=(work.parent.scope().clone(),work.parent.terminal_operation_uid().clone());
    let(pool,plan)=agent.terminal_parts(&scope)?;
    let(dir,index)={
        let s=work.resources.state.lock().map_err(|_|"actual terminal dispatch owner poisoned")?;
        (s.dispatch.clone().ok_or("original reserved dispatch FD absent")?,s.next_step)
    };
    let attempt=work.resources.attempts.get(index).ok_or("no precharged original terminal attempt")?.clone();
    {
        let mut state=work.owner.resources.lock().map_err(|_|"actual terminal global root poisoned")?;
        if state.global.as_ref().ok_or("terminal actual work admission absent")?.lease.is_none(){
            let lease=dir.lock_existing()?;state.global.as_mut().unwrap().lease=Some(lease);
            state.global_safety=Some(state.global.as_ref().unwrap().lease.as_ref().unwrap().try_clone()
                .map_err(|_|"terminal global safety duplicate unavailable")?);
        }
        if state.volume_lease.is_none(){return Err("terminal original per-volume lease lost".into());}
    }
    let lease=work.owner.resources.lock().map_err(|_|"terminal original global root poisoned")?.global.as_ref()
        .and_then(|v|v.lease.as_ref()).ok_or("terminal original global lease absent")?.try_clone().map_err(|_|"terminal inherited actual lease duplicate failed")?;
    let original_cgroup={work.owner.resources.lock().map_err(|_|"terminal original cgroup root poisoned")?.terminal_cgroup.as_ref()
        .cloned().ok_or("terminal original node cgroup missing; never reopen/adopt")?};
    let cgroup=original_cgroup.try_clone()?;
    cgroup.task_census_empty()?;
    let start=cgroup.resource_snapshot(&config.budget)?;
    if start.pids_current!=0||cgroup.populated()?{return Err("terminal original job cgroup is not drained".into());}
    let cgroup_identity=cgroup.identity()?;
    let binding:CgroupBinding=serde_json::from_slice(&dir.read("cgroup-binding.json")?.ok_or("original terminal cgroup binding absent")?)
        .map_err(|_|"original terminal cgroup binding corrupt")?;
    if binding.version!=1||binding.node_uid!=scope.phase_node_uid||binding.boot_id!=scope.phase_boot.as_str()
        ||(binding.device,binding.inode)!=cgroup_identity{return Err("same original terminal cgroup binding changed".into());}
    let prior=load_record(&dir.read("current.json")?.ok_or("actual completed predecessor required; no new journal")?)?;
    let expected_previous={work.resources.state.lock().map_err(|_|"terminal actual prior native root poisoned")?.current_identity.clone()};
    let expected_previous=if let Some(actual)=expected_previous{actual}else{
        work.owner.resources.lock().map_err(|_|"actual original prior attachment poisoned")?.current_native.clone().ok_or("original native identity absent")?};
    if prior.state!=State::Complete||prior.identity!=expected_previous
        ||prior.identity.node_uid!=scope.phase_node_uid||prior.identity.boot_id!=scope.phase_boot.as_str(){
        return Err("terminal predecessor not SAME-boot actual Complete; no reset/adoption".into());}
    let remaining=work.parent.original_deadline().saturating_duration_since(Instant::now()).min(config.deadline);
    let ms=u64::try_from(remaining.as_millis()).map_err(|_|"terminal remaining budget overflow")?;
    if ms==0||ms>180_000{return Err("terminal original finite deadline absent/expired".into());}
    let publication=work.owner.probe.lock().map_err(|_|"terminal original publication root poisoned")?.terminal_publication(&scope)?;
    let watch_roles={work.resources.state.lock().map_err(|_|"actual precharged inherited Watch roles poisoned")?.watch_roles.clone()
        .ok_or("actual inherited Watch process roles were not precharged")?};
    physical::origin::verify_retained_pair(&watch_roles.pidfd,&watch_roles.proc,&watch_roles.observation)?;
    let inner=TerminalPayload{pool,scope:scope.clone(),operation:operation.clone(),node_job:work.parent.node_job_uid().clone(),
        reservation:work.resources.uid.clone(),step:work.step,publication,cgroup_identity,
        pool_identity:work.resources.observation().pool_identity,delegated_root:config.delegated_cgroup_root.clone(),
        namespace_identity:work.resources.state.lock().map_err(|_|"original terminal namespace root poisoned")?.namespace_identity.ok_or("original terminal namespace absent")?,
        watch_process:watch_roles.observation.clone(),watch_pidfd:watch_roles.pidfd.as_raw_fd(),watch_proc:watch_roles.proc.as_raw_fd()};
    let remote_binding=payload_binding(&inner)?;
    let payload=Payload{config:serde_json::to_value(&inner).map_err(|_|"terminal private payload encode failed")?,plan,
        projection:Vec::new(),extended:Some(ExtendedJob::TerminateManaged),dataset_uid:Some(scope.generation.uid.clone()),
        remote_binding:Some(remote_binding),initialization:None,worker_remaining_ms:Some(ms)};
    let payload_sha256=hash(&serde_json::to_vec(&payload).map_err(|_|"terminal actual payload hash failed")?);
    let identity=live::JobIdentity{node_uid:scope.phase_node_uid.clone(),boot_id:scope.phase_boot.as_str().into(),
        volume_uid:scope.owner.volume_uid.clone(),operation_uid:operation.clone(),attempt_uid:attempt,
        binding_sha256:hash(&serde_json::to_vec(&("managed-terminal-native-v6",&payload_sha256,&config.helper_sha256,&config.budget,
            &work.resources.uid)).map_err(|_|"terminal native identity binding failed")?)};
    let capsule=Capsule{version:6,identity:identity.clone(),payload,budget:config.budget.clone()};
    if !valid_capsule(&capsule){return Err("terminal private capsule invalid before child".into());}
    let bytes=serde_json::to_vec(&capsule).map_err(|_|"terminal capsule encode failed")?;
    if bytes.len()as u64>CAPSULE_LIMIT{return Err("terminal private capsule exceeds unchanged64KiB cap".into());}
    let filename=format!("capsule-{}.json",identity.attempt_uid.as_str());dir.write_new(&filename,&bytes)?;
    let capsule_file=open_private(&work.resources.dispatch_path.join(filename))?;
    let mut record=Record{version:6,identity:identity.clone(),payload_sha256,image_sha256:config.helper_sha256.clone(),
        state:State::LaunchIntent,resources_start:start,resources_final:None};
    publish(&dir,&record)?;
    let image=open_image(&config.helper_image,&config.helper_sha256)?;
    work.parent.bind_native(&identity,work.step)?;
    work.resources.state.lock().map_err(|_|"terminal native root poisoned")?.current_identity=Some(identity.clone());
    let(control,child_control)=UnixStream::pair().map_err(|_|"terminal private channel pair failed")?;
    let procs=cgroup.procs_for_child()?;let inherited_cgroup=cgroup.retained_directory_for_terminal()?;
    let fds=[lease.as_raw_fd(),capsule_file.as_raw_fd(),child_control.as_raw_fd(),inherited_cgroup.as_raw_fd(),watch_roles.pidfd.as_raw_fd(),watch_roles.proc.as_raw_fd()];
    let parent_pid=std::process::id();
    let mut command=Command::new(image_exec_path(&image,&config.helper_image)?);
    command.args(["storage-driver","native-worker","--journal"]).arg(&work.resources.dispatch_path)
        .arg("--lease-fd").arg(fds[0].to_string()).arg("--capsule-fd").arg(fds[1].to_string())
        .arg("--control-fd").arg(fds[2].to_string()).arg("--attempt").arg(identity.attempt_uid.as_str())
        .arg("--cgroup-root").arg(&config.delegated_cgroup_root).env_clear().env("PATH","/usr/sbin:/usr/bin:/sbin:/bin")
        .env("ROYAK_TERMINAL_CGROUP_FD",fds[3].to_string()).env("LC_ALL","C").env("HOME","/").current_dir("/")
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    unsafe{command.pre_exec(move||{
        #[cfg(target_os="linux")]
        if libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)!=0||libc::getppid()as u32!=parent_pid{return Err(std::io::Error::last_os_error());}
        if libc::write(procs.as_raw_fd(),b"0\n".as_ptr().cast(),2)!=2{return Err(std::io::Error::last_os_error());}
        for fd in fds{let flags=libc::fcntl(fd,libc::F_GETFD);
            if flags<0||libc::fcntl(fd,libc::F_SETFD,flags&!libc::FD_CLOEXEC)<0{return Err(std::io::Error::last_os_error());}}
        Ok(())
    });}
    let observer=cgroup.try_clone()?;let cancelled=work.resources.invalid.clone();
    work.parent.require_live()?;work.resources.require_current()?;
    let original_deadline=work.parent.original_deadline();
    let child=command.spawn().map_err(|_|"terminal helper spawn UNKNOWN; original owner/resources retained")?;
    drop(child_control);drop(inherited_cgroup);drop(watch_roles);drop(image);drop(capsule_file);
    // NO fallible computation between spawn and handing original Child to
    // the SAME reviewed bounded supervisor.
    let timeout=original_deadline.saturating_duration_since(Instant::now()).min(remaining);
    let(outcome,quarantine)=supervise(child,control,cgroup,lease,timeout,&identity,&cancelled,
        DiagnosticProfile::Terminal{scope:&scope,operation:&operation,step:work.step},
        |request|handle_request(work,&inner,&identity,request))?;
    if let Some(original)=quarantine{
        *work.owner.quarantine.lock().unwrap_or_else(|p|p.into_inner())=Some(original);
        work.owner.resources.lock().unwrap_or_else(|p|p.into_inner()).quarantined=true;
    }
    record.resources_final=Some(observer.resource_snapshot(&config.budget)?);
    observer.task_census_empty()?;
    let drained=record.resources_final.as_ref().is_some_and(|r|r.pids_current==0
        &&r.cpu_usage_us>=record.resources_start.cpu_usage_us&&r.cpu_user_us>=record.resources_start.cpu_user_us
        &&r.cpu_system_us>=record.resources_start.cpu_system_us)&&!observer.populated()?
        &&work.owner.quarantine.lock().map_err(|_|"terminal quarantine poisoned")?.is_none();
    let(raw,extra)=match outcome{
        Outcome::CompletedDiagnostics{stdout,retained_lease:Some(lease),..}if drained=>(stdout,lease),
        _=>{record.state=State::Unknown;publish(&dir,&record)?;return Err("terminal original child/EOF/cgroup drain not proven; UNKNOWN".into());}
    };
    let observation:TerminalPhysicalObservation=serde_json::from_slice(&raw).map_err(|_|"terminal actual diagnostic malformed")?;
    observation.validate(&scope,&operation,work.step)?;
    record.state=State::Complete;publish(&dir,&record)?;
    let completion=VerifiedLocalBoundary::terminal_completion(&identity,&record,&raw)?;
    drop(extra);
    let drain=Arc::new(VerifiedTerminalDrain{owner:work.owner.clone(),parent:work.parent.clone(),resources:work.resources.clone(),
        identity,step:work.step,observation,record,raw,completion});
    // ROOT ACTUAL opaque drain BEFORE any parent report/ticket send.
    work.resources.state.lock().map_err(|_|"actual terminal drain root poisoned")?.drains.push(drain.clone());
    Ok(drain)
}

#[derive(Clone,Copy)]
enum LeaseSlot {GlobalPrimary,GlobalSafety,Volume}
impl LeaseSlot {
    fn key(self)->&'static str{match self{Self::GlobalPrimary=>"global-primary",Self::GlobalSafety=>"global-safety",Self::Volume=>"volume"}}
    fn raw(self,state:&AttachResources)->Result<i32,String>{
        match self{Self::GlobalPrimary=>state.global.as_ref().and_then(|v|v.lease.as_ref()),
            Self::GlobalSafety=>state.global_safety.as_ref(),Self::Volume=>state.volume_lease.as_ref()}
            .map(AsRawFd::as_raw_fd).ok_or_else(||"original terminal lease slot missing; not a successful close".into())
    }
    fn take(self,state:&mut AttachResources)->Option<File>{
        match self{Self::GlobalPrimary=>state.global.as_mut().and_then(|v|v.lease.take()),
            Self::GlobalSafety=>state.global_safety.take(),Self::Volume=>state.volume_lease.take()}
    }
}
fn lease_stamp(raw:i32)->Result<(u64,u64),String>{
    let mut stat:libc::stat=unsafe{std::mem::zeroed()};
    if unsafe{libc::fstat(raw,&mut stat)}!=0{return Err("same actual original terminal lease descriptor unavailable".into());}
    Ok((stat.st_dev as u64,stat.st_ino as u64))
}
impl VerifiedTerminalDrain {
    fn retire_original_lease(&self,parent:&VerifiedTerminalNodeParent)->Result<Arc<RetiredTerminalLease>,String>{
        self.require_parent(parent)?;parent.require_detached_confirmed()?;
        if self.step!=TerminalNativeStep::OfflineAndObserve{return Err("only actual final offline drain can retire original lease".into());}
        self.resources.require_empty()?;
        {
            let mut state=self.resources.state.lock().map_err(|_|"actual final retirement owner poisoned")?;
            if state.retiring||state.retirement.is_some()||state.failed||state.queued||!state.retirement_queued||!state.retirement_submitted
                ||state.next_step!=self.resources.attempts.len()
                ||state.drains.last().is_none_or(|last|!std::ptr::eq(Arc::as_ptr(last),self)){
                return Err("original terminal retirement repeated/not actual final known drain".into());}
            state.retiring=true; // exclusive original close ownership, no new effect grant
        }
        let result=(||{
            // Finite node work pair first; exact per-volume writer lease last.
            // On any partial/error outcome every remaining actual reference
            // and irreversible consumed tombstone remains rooted.
            for slot in [LeaseSlot::GlobalPrimary,LeaseSlot::GlobalSafety,LeaseSlot::Volume]{
                parent.require_detached_confirmed()?;
                let raw={let state=self.owner.resources.lock().map_err(|_|"actual retiring lease owner poisoned")?;slot.raw(&state)?};
                // Original Files stay rooted; retiring flag prevents all other
                // terminal takes. No descriptor clone, IO under resource mutex
                // or authority from the raw scalar is introduced here.
                self.owner.require_actual_watch_files()?;
                let(device,inode)=lease_stamp(raw)?;
                self.owner.require_actual_watch_files()?;
                let detail=hash(&serde_json::to_vec(&("terminal-original-lease-close-v1",parent.terminal_operation_uid(),
                    parent.node_job_uid(),slot.key(),raw,device,inode,&self.identity)).map_err(|_|"actual lease close binding failed")?);
                let boundary=VerifiedLocalBoundary::terminal_observation(&self.identity,&self.record,&self.raw,&detail)?;
                parent.approve(&boundary,TerminalBoundary::RetireLease,&detail)?;
                self.owner.require_actual_watch_files()?;
                if lease_stamp(raw)?!=(device,inode){return Err("original lease changed during actual retirement barrier".into());}
                self.owner.require_actual_watch_files()?;
                self.resources.state.lock().map_err(|_|"actual close-consumed root poisoned")?.lease_closes.insert(slot.key(),
                    LeaseCloseOutcome::Consumed{fd:raw,device,inode});
                let original={
                    let mut state=self.owner.resources.lock().map_err(|_|"actual retiring resource poisoned")?;
                    if slot.raw(&state)?!=raw{return Err("original lease slot changed before take".into());}
                    slot.take(&mut state).ok_or("original lease take missing")?
                };
                let number=original.into_raw_fd();let closed=unsafe{libc::close(number)};
                let errno=if closed==0{None}else{std::io::Error::last_os_error().raw_os_error()};
                let serving=self.owner.require_actual_watch_files();
                let known=closed==0&&serving.is_ok();
                let outcome=if known{LeaseCloseOutcome::Closed{fd:number,device,inode}}
                    else if serving.is_err(){LeaseCloseOutcome::Consumed{fd:number,device,inode}}
                    else{LeaseCloseOutcome::ErrorAfterConsume{fd:number,device,inode,errno}};
                {
                    let mut state=self.resources.state.lock().unwrap_or_else(|p|p.into_inner());
                    state.lease_closes.insert(slot.key(),outcome.clone());
                    if known&&slot.key()=="volume"{
                        // Actual irreversible retirement is rooted BEFORE a
                        // late fsync/reply can fail. It never reconstructs FDs.
                        let evidence=hash(&serde_json::to_vec(&(parent.terminal_operation_uid(),&self.identity,
                            &state.lease_closes)).map_err(|_|"actual retired lease evidence encode failed")?);
                        state.retirement=Some(Arc::new(RetiredTerminalLease{node:self.identity.node_uid.clone(),
                            volume:self.identity.volume_uid.clone(),evidence}));
                    }
                }
                if known&&slot.key()=="volume"{
                    let mut state=self.owner.resources.lock().unwrap_or_else(|p|p.into_inner());
                    if state.global.as_ref().is_some_and(|g|g.lease.is_none())&&state.global_safety.is_none()&&state.volume_lease.is_none(){
                        let original=state.global.take();drop(original);
                        self.owner.dispatcher_busy.store(false,Ordering::Release);
                    }
                }
                let outcome_hash=hash(&serde_json::to_vec(&outcome).map_err(|_|"actual irreversible lease result encode failed")?);
                let recorded=parent.record_native_result(&boundary,TerminalBoundary::RetireLease,&detail,&outcome_hash);
                if closed!=0{return Err("terminal original lease close error AFTER consume; no retry/reopen".into());}
                recorded?;
                serving?;
            }
            parent.require_detached_confirmed()?;
            self.resources.state.lock().map_err(|_|"actual final retired lease root poisoned")?.retirement.clone()
                .ok_or_else(||"actual original lease retirement missing".into())
        })();
        if result.is_err(){self.resources.latch();parent.retain_unknown();}result
    }
}
fn terminal_kind_code(code:u8)->Option<TerminalBoundary>{
    use TerminalBoundary::*;Some(match code{0=>Start,1=>Identity,2=>Program,3=>Read,4=>FlushMount,5=>CloseMounted,6=>Unmount,
        7=>CloseBlock,8=>Demote,9=>ObserveSecondary,10=>Offline,11=>CloseRead,12=>Complete,13=>RetireLease,_=>return None})
}
fn native_kind(request:&live::Request,identity:&live::JobIdentity)->Option<TerminalBoundary>{
    if request.version!=1||request.sequence==0||&request.identity!=identity||!valid_hash(&request.detail_sha256){return None;}
    use TerminalBoundary::*;
    Some(match request.boundary.as_str(){
        "helper-start" if request.detail_sha256==hash(b"native-managed-terminal-v1")=>Start,
        "identity-check"|"terminal-identity"=>Identity,"fixed-program"=>Program,"terminal-read"=>Read,
        "terminal-flush"=>FlushMount,"terminal-close-mounted"=>CloseMounted,"terminal-unmount"=>Unmount,
        "terminal-close-block"=>CloseBlock,"terminal-demote"=>Demote,"terminal-observe-secondary"=>ObserveSecondary,
        "terminal-offline"=>Offline,"terminal-close-read"=>CloseRead,_=>return None})
}
pub(in crate::storage_driver::dispatcher) fn diagnostic_matches(raw:&[u8],identity:&live::JobIdentity,
    scope:&ExpectedAttachScope,operation:&Uid,step:TerminalNativeStep)->bool{
    serde_json::from_slice::<TerminalPhysicalObservation>(raw).is_ok_and(|value|
        value.validate(scope,operation,step).is_ok()&&identity.node_uid==scope.phase_node_uid
            &&identity.boot_id==scope.phase_boot.as_str()&&identity.volume_uid==scope.owner.volume_uid
            &&&identity.operation_uid==operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn terminal_census_split_source_keeps_one_actual_approve_outside_probe_guards_and_receipt_after_it(){
        let source=include_str!("dispatcher_terminal.rs");
        let body=source.split_once("fn authorize_reference_census_unlocked(").unwrap().1.split_once("\nfn handle_request(").unwrap().0;
        let prepare=body.find("probe.prepare_reference_census(").unwrap();
        let release=body.find("}; // ALL probe guards end BEFORE").unwrap();
        let approve=body.find("work.parent.approve(").unwrap();
        let receipt=body.find("let approved=ApprovedReferenceCensus{prepared}").unwrap();
        let recheck=body.find("work.resources.require_current()?").unwrap();
        let commit=body.find("probe.commit_reference_census(").unwrap();
        assert!(prepare<release&&release<approve&&approve<receipt&&receipt<recheck&&recheck<commit);
        assert_eq!(body.matches(".approve(").count(),1);
        assert_eq!(body.matches("let approved=ApprovedReferenceCensus{prepared};").count(),1);
        assert!(body[approve..receipt].matches(".lock(").next().is_none());
        assert!(!body.contains("Instant::now()"));assert!(!body.contains("spawn"));
    }
    #[test]
    fn terminal_census_failure_guard_source_latches_without_probe_lock_and_unwinds_inner_guards_first(){
        let source=include_str!("dispatcher_terminal.rs");
        let drop=source.split_once("impl Drop for ReferenceCensusFailure<'_>").unwrap().1
            .split_once("\nfn authorize_reference_census_unlocked(").unwrap().0;
        assert!(drop.contains("self.work.resources.latch();self.work.parent.retain_unknown();"));
        assert!(!drop.contains(".probe"));assert!(!drop.contains(".lock("));
        let body=source.split_once("fn authorize_reference_census_unlocked(").unwrap().1.split_once("\nfn handle_request(").unwrap().0;
        assert!(body.find("let mut failure=").unwrap()<body.find("let prepared={").unwrap());
        let commit=body.find("probe.commit_reference_census(").unwrap();
        let guard_end=body[commit..].find("\n    }").unwrap()+commit;
        assert!(guard_end<body.find("failure.finished=true").unwrap());
        // Lexical drop-order/conservation source checks only. No physical
        // work, parent, approved receipt or runtime mutex is fabricated.
    }
    #[test]
    fn terminal_actual_resource_precharge_uses_the_new_four_observation_bound_before_create(){
        assert_eq!(precharge_mandatory_extent(64*1024*1024,true).unwrap(),63+2*64);
        assert_eq!(precharge_mandatory_extent(64*1024*1024,false).unwrap(),35+2*64);
        for writer in [false,true]{assert!(precharge_mandatory_extent(1024*1024*1024,writer).is_err());}
        assert!(precharge_mandatory_extent(0,true).is_err());
        // This is the SAME private budget function called by the genuine
        // factory, not a resource/grant/parent or physical-completion model.
    }
    #[test]
    fn terminal_resource_failure_flags_are_monotonic_negative_not_old_consumer_unknown_authority(){
        require_terminal_resource_flags(false,false).unwrap();
        for(failed,invalid)in [(true,false),(false,true),(true,true)]{
            assert!(require_terminal_resource_flags(failed,invalid).is_err());}
        // This only tests the private negative DATA fence. No resource owner,
        // parent, grant, actual Core or opaque completion is constructed.
    }
    #[test]
    fn terminal_active_probe_borrow_refuses_before_any_close_and_preserves_original_value(){
        let probe=Mutex::new(vec!["actual-owner-slot DATA"]);let held=probe.lock().unwrap();
        assert!(exclusive_probe(&probe).is_err());assert_eq!(held.len(),1);drop(held);
        assert_eq!(exclusive_probe(&probe).unwrap()[0],"actual-owner-slot DATA");
    }
    #[test]
    fn terminal_regular_owned_file_and_invalid_number_never_become_cgroup_authority(){
        use std::os::unix::fs::OpenOptionsExt;
        let path=std::env::temp_dir().join(format!("royak-terminal-wrong-cgroup-{}",Uid::new().as_str()));
        let file=std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path).unwrap();
        let m=file.metadata().unwrap();
        assert!(verify_original_cgroup_number(file.as_raw_fd(),(m.dev(),m.ino())).is_err());
        assert!(verify_original_cgroup_number(-1,(m.dev(),m.ino())).is_err());
        // Read-only rejection did NOT take/close this original unrelated FD.
        assert_eq!(file.metadata().unwrap().ino(),m.ino());drop(file);std::fs::remove_file(path).unwrap();
    }
    #[test]
    fn terminal_boundary_kind_and_native_identity_are_closed_data_not_generic_program_authority(){
        let identity=live::JobIdentity{node_uid:Uid::new(),boot_id:"12345678-1234-4234-8234-123456789abc".into(),
            volume_uid:Uid::new(),operation_uid:Uid::new(),attempt_uid:Uid::new(),binding_sha256:"a".repeat(64)};
        let mut request=live::Request{version:1,identity:identity.clone(),sequence:1,nonce:Uid::new(),
            boundary:"terminal-unmount".into(),detail_sha256:"b".repeat(64)};
        assert_eq!(native_kind(&request,&identity),Some(TerminalBoundary::Unmount));
        for code in 0..14{assert_eq!(live::terminal_boundary_code(terminal_kind_code(code).unwrap()),code);}
        assert!(terminal_kind_code(14).is_none());
        for name in ["format","zero-write","up","initialize","terminal-unknown","retire-lease"]{
            request.boundary=name.into();assert!(native_kind(&request,&identity).is_none());}
        request.boundary="terminal-read".into();request.identity.attempt_uid=Uid::new();
        assert!(native_kind(&request,&identity).is_none());request.identity=identity.clone();request.sequence=0;
        assert!(native_kind(&request,&identity).is_none());
    }
    #[test]
    fn terminal_v6_record_envelope_keeps_checksum_boot_and_real_final_resource_requirements(){
        // Record DATA validation only; this cannot create an actual child
        // drain, terminal parent, reservation or Completed capability.
        let budget=crate::storage_driver::ResourceBudget{pids_max:64,memory_max_bytes:256*1024*1024,
            cpu_quota_us:100_000,cpu_period_us:100_000};
        let snapshot=crate::storage_driver::job_cgroup::ResourceSnapshot{budget,pids_current:0,
            memory_current_bytes:0,cpu_usage_us:0,cpu_user_us:0,cpu_system_us:0};
        let mut record=Record{version:6,identity:live::JobIdentity{node_uid:Uid::new(),
            boot_id:"12345678-1234-4234-8234-123456789abc".into(),volume_uid:Uid::new(),operation_uid:Uid::new(),
            attempt_uid:Uid::new(),binding_sha256:"a".repeat(64)},payload_sha256:"b".repeat(64),image_sha256:"c".repeat(64),
            state:State::Complete,resources_start:snapshot.clone(),resources_final:Some(snapshot)};
        let encode=|record:&Record|serde_json::to_vec(&serde_json::json!({"version":1,
            "sha256":hash(&serde_json::to_vec(record).unwrap()),"record":record})).unwrap();
        for version in 1..=7{record.version=version;assert_eq!(load_record(&encode(&record)).unwrap().version,version);}
        for version in [0,8,u32::MAX]{record.version=version;assert!(load_record(&encode(&record)).is_err());}record.version=6;
        record.resources_final.as_mut().unwrap().pids_current=1;assert!(load_record(&encode(&record)).is_err());
        record.resources_final.as_mut().unwrap().pids_current=0;record.identity.boot_id="not-a-boot".into();
        assert!(load_record(&encode(&record)).is_err());
        record.identity.boot_id="12345678-1234-4234-8234-123456789abc".into();
        assert!(load_record(&encode(&record)).is_ok());
        let mut tampered:serde_json::Value=serde_json::from_slice(&encode(&record)).unwrap();
        let original_checksum=tampered["sha256"].as_str().unwrap().to_string();
        let changed_checksum=format!("{}{}",if original_checksum.starts_with('0'){"1"}else{"0"},&original_checksum[1..]);
        assert_eq!(changed_checksum.len(),original_checksum.len());assert_ne!(changed_checksum,original_checksum);assert!(valid_hash(&changed_checksum));
        tampered["sha256"]=changed_checksum.into();assert!(load_record(&serde_json::to_vec(&tampered).unwrap()).is_err());
    }
    #[test]
    fn terminal_record_profiles_cannot_cross_complete_boundary_domains(){
        // DATA only. Every generic record below is valid. Only a wrong
        // profile is passed to the actual opaque completion constructors;
        // matching v6 terminal /v7 inventory constructors are NEVER called.
        let budget=crate::storage_driver::ResourceBudget{pids_max:64,memory_max_bytes:256*1024*1024,
            cpu_quota_us:100_000,cpu_period_us:100_000};
        let snapshot=crate::storage_driver::job_cgroup::ResourceSnapshot{budget,pids_current:0,
            memory_current_bytes:0,cpu_usage_us:0,cpu_user_us:0,cpu_system_us:0};
        let mut record=Record{version:1,identity:live::JobIdentity{node_uid:Uid::new(),
            boot_id:"12345678-1234-4234-8234-123456789abc".into(),volume_uid:Uid::new(),operation_uid:Uid::new(),
            attempt_uid:Uid::new(),binding_sha256:"a".repeat(64)},payload_sha256:"b".repeat(64),image_sha256:"c".repeat(64),
            state:State::Complete,resources_start:snapshot.clone(),resources_final:Some(snapshot)};
        let encode=|record:&Record|serde_json::to_vec(&serde_json::json!({"version":1,
            "sha256":hash(&serde_json::to_vec(record).unwrap()),"record":record})).unwrap();
        let detail="d".repeat(64);assert!(valid_hash(&detail));
        for version in [1,2,3,4,5,7]{
            record.version=version;let raw=encode(&record);
            assert_eq!(load_record(&raw).unwrap().version,version);
            assert!(VerifiedLocalBoundary::terminal_completion(&record.identity,&record,&raw).is_err());
            assert!(VerifiedLocalBoundary::terminal_observation(&record.identity,&record,&raw,&detail).is_err());
        }
        record.version=6;let raw=encode(&record);assert_eq!(load_record(&raw).unwrap().version,6);
        assert!(VerifiedLocalBoundary::owned_inventory_completion(&record.identity,&record,&raw).is_err());
    }
}
