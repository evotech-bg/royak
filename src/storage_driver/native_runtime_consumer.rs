//! Ordinary managed Docker consumer on the EXISTING normal Watch controller.
//! DATA submission does no IO/quorum. Actual READY, source lifetime and fresh
//! action-specific Core permission are distinct producer-owned requirements.
use super::*;
use crate::storage_pod_writer::{ManagedMountRef,PodWriterBinding};
use crate::workload::{PodLaunch,ContainerLaunch,managed::{LaunchKey,Submission,SubmissionStatus}};
use crate::storage_driver::dispatcher::attachment::{RootedMountWitness,
    consumer_lifetime::{RootedConsumerMountWitness,VerifiedManagedSource}};
use std::sync::atomic::{AtomicU8,AtomicBool,Ordering};
#[path="native_runtime_terminal.rs"]
pub(crate) mod terminal;

const ACCEPTED:u8=0;const ACTIVE:u8=1;const RUNNING:u8=2;const UNKNOWN:u8=3;
const MAX_OPERATIONS:usize=128;
const MAX_CONSUMER_ACTIONS:usize=3*crate::workload::managed::MAX_DATA_CONTAINERS;
pub(super) struct ConsumerBook {
    pending:Option<PendingConsumerData>,
    history:BTreeMap<Uid,Arc<ManagedPodOperation>>,
    mode:terminal::ControllerMode,
}
#[derive(Clone)]
enum PendingConsumerData {Launch(Arc<ManagedPodOperation>),Drain(Arc<terminal::PreparedTerminalPlan>),
    DrainNode(Arc<terminal::wire::ReceiverPreparation>)}
impl ConsumerBook {pub(super) fn new()->Self{Self{pending:None,history:BTreeMap::new(),mode:terminal::ControllerMode::Operational}}}

/// Only the real confirmed READY book can construct this. It is deliberately
/// NOT the expired attach ExpectedJob or a deserialized Attached receipt.
pub(crate) struct VerifiedReadyMountSet {
    book:Arc<MountBook>,
    confirmed:Arc<commit::PreparedMountedCommit>,
    binding:PodWriterBinding,
    references:BTreeMap<Uid,ManagedMountRef>,
}
impl VerifiedReadyMountSet {
    fn from_actual_book(book:Arc<MountBook>)->Result<Arc<Self>,String>{
        let confirmed={book.state.try_lock().map_err(|_|"READY book busy/poisoned")?.commit.clone()
            .ok_or("no actual MountedCommit/Confirm result; request NeverAccepted")?};
        confirmed.require_ready_lifetime()?;
        let references=confirmed.ready_round().witnesses.iter().map(|(uid,w)|(uid.clone(),w.reference().clone()))
            .collect::<BTreeMap<_,_>>();
        let binding={
            let world=book.world.try_read().map_err(|_|"actual READY metadata busy")?;
            let first=references.keys().next().ok_or("READY group empty")?;
            let volume=world.storage_identities.lifecycle.get(first).ok_or("READY current dataset absent")?;
            let binding=volume.pod_writer().ok_or("READY current PodWriter absent")?.clone();
            for (uid,reference) in &references{
                let volume=world.storage_identities.lifecycle.get(uid).ok_or("READY group is partial")?;
                if volume.phase()!=Phase::Attached || volume.pod_writer()!=Some(&binding)
                    || ManagedMountRef::from_metadata(volume)?!=*reference {
                    return Err("actual READY group differs from canonical Attached writer".into());
                }
            }
            binding.check_source_current(&world)?;binding
        };
        let value=Arc::new(Self{book,confirmed,binding,references});
        value.require_current()?;Ok(value)
    }
    /// Pure negative ownership fence. Fresh Core is still required separately.
    pub(crate) fn require_current(&self)->Result<(),String>{
        if self.book.invalid.load(Ordering::Acquire)||!core::is_actual_world(&self.book.world){
            return Err("actual READY lifetime revoked/lost".into());
        }
        self.confirmed.require_ready_lifetime()
    }
    pub(crate) fn require_witness(&self,witness:&RootedMountWitness)->Result<(),String>{
        self.require_current()?;
        let expected=self.confirmed.ready_round().witnesses.get(witness.reference().volume_uid())
            .ok_or("source is not in the actual READY group")?;
        if expected.reference()!=witness.reference() || expected.evidence_uid()!=witness.evidence_uid()
            || expected.evidence_sha256()!=witness.evidence_sha256(){
            return Err("source evidence differs from the actual confirmed READY group".into());
        }
        let state=self.book.state.try_lock().map_err(|_|"READY witness book busy/poisoned")?;
        crate::storage_driver::dispatcher::attachment::consumer_lifetime::require_ready_owner_now(
            witness,state.owners.get(witness.reference().volume_uid()).ok_or("actual READY owner absent")?)
    }
    fn require_key(&self,key:&LaunchKey)->Result<(),String>{
        self.require_current()?;
        if key.references!=self.references || key.writer!=*self.binding.uid()
            || key.namespace_uid!=*self.binding.namespace_uid() || key.namespace!=self.binding.namespace()
            || key.workload!=self.binding.workload() || key.pod!=self.binding.pod()
            || key.ordinal!=self.binding.ordinal(){
            return Err("managed DATA is not the complete exact actual READY PodWriter group".into());
        }
        Ok(())
    }
    fn sources(self:&Arc<Self>,deadline:Instant)->Result<BTreeMap<Uid,VerifiedManagedSource>,String>{
        self.require_current()?;
        let mut result=BTreeMap::new();
        for (uid,witness) in &self.confirmed.ready_round().witnesses{
            let current=RootedConsumerMountWitness::from_ready_group(self.clone(),witness)?;
            result.insert(uid.clone(),current.source_for_consumer(deadline)?);
        }
        self.require_current()?;Ok(result)
    }
}

struct ManagedPodOperation {
    uid:Uid,key:LaunchKey,ready:Arc<VerifiedReadyMountSet>,status:AtomicU8,
    plan:Mutex<Option<PodLaunch>>,source_sha256:Mutex<Option<String>>,
    containers:Mutex<BTreeMap<String,Arc<OwnedManagedContainer>>>,
    actions:Mutex<BTreeMap<Uid,Arc<ConsumerAction>>>,
    unknown:Mutex<Option<String>>,
    sources:Mutex<Option<Arc<BTreeMap<Uid,VerifiedManagedSource>>>>,
    internal_root:Mutex<Option<std::fs::File>>,
    internal:Mutex<BTreeMap<String,Arc<InternalSource>>>,
    budget:Mutex<Option<Arc<journal::ConsumerEvidenceBudget>>>,budget_attempted:AtomicBool,
    terminal_plan:Mutex<Option<Arc<terminal::PreparedTerminalPlan>>>,
    launch_finished:Mutex<Option<Arc<terminal::FinishedLaunch>>>,
}
impl ManagedPodOperation {
    fn receipt(&self)->Submission{Submission{operation:self.uid.clone(),status:match if self.ready.book.invalid.load(Ordering::Acquire){UNKNOWN}else{self.status.load(Ordering::Acquire)}{
        RUNNING=>SubmissionStatus::Running,UNKNOWN=>SubmissionStatus::Unknown,
        ACTIVE=>SubmissionStatus::InProgress,_=>SubmissionStatus::Accepted}}}
    fn invalidate(&self,reason:&str){
        self.status.store(UNKNOWN,Ordering::Release);
        let mut retained=self.unknown.lock().unwrap_or_else(|p|p.into_inner());
        if retained.is_none(){*retained=Some(reason.chars().take(256).collect());}
        drop(retained);
        self.ready.book.quarantine("managed consumer original operation UNKNOWN; no rollback/retry");
    }
    fn live(&self)->Result<(),String>{
        if self.status.load(Ordering::Acquire)==UNKNOWN{return Err("original managed consumer UNKNOWN".into());}
        self.ready.require_current()
    }
}
struct RetainOperation {operation:Arc<ManagedPodOperation>,finished:bool}
impl Drop for RetainOperation {fn drop(&mut self){if !self.finished{self.operation.invalidate("managed actor/result dropped");}}}

/// Synchronous DATA-only adapter, safe while ordinary reconcile owns its
/// detached snapshot/commit guard. No HTTP/kernel IO/await/block_on here.
pub(crate) fn submit_data(plan:&PodLaunch)->Result<Submission,String>{
    let key=LaunchKey::from_plan_data(plan)?;
    let book=ROOTED_BOOK.get().ok_or("managed request NeverAccepted: no actual local READY book")?.clone();
    {
        let state=book.state.try_lock().map_err(|_|"managed DATA book busy/poisoned; NeverAccepted")?;
        if let Some(original)=state.consumer.history.values().find(|op|op.key==key){
            return Ok(original.receipt()); // SAME operation, no new time/grant.
        }
    }
    let ready=VerifiedReadyMountSet::from_actual_book(book.clone())?;ready.require_key(&key)?;
    let operation=Arc::new(ManagedPodOperation {uid:Uid::new(),key,ready,status:AtomicU8::new(ACCEPTED),
        plan:Mutex::new(None),source_sha256:Mutex::new(None),containers:Mutex::new(BTreeMap::new()),
        actions:Mutex::new(BTreeMap::new()),unknown:Mutex::new(None),sources:Mutex::new(None),
        internal_root:Mutex::new(None),internal:Mutex::new(BTreeMap::new()),
        budget:Mutex::new(None),budget_attempted:AtomicBool::new(false),terminal_plan:Mutex::new(None),launch_finished:Mutex::new(None)});
    let mut state=book.state.try_lock().map_err(|_|"managed DATA slot busy/poisoned; NeverAccepted")?;
    if let Some(original)=state.consumer.history.values().find(|op|op.key==operation.key){return Ok(original.receipt());}
    if state.consumer.mode!=terminal::ControllerMode::Operational||book.invalid.load(Ordering::Acquire)||state.unknown.is_some()||state.consumer.pending.is_some()
        || state.consumer.history.len()>=MAX_OPERATIONS{
        return Err("managed request NeverAccepted: one slot busy/UNKNOWN/history bounded-full".into());
    }
    state.consumer.history.insert(operation.uid.clone(),operation.clone());
    state.consumer.pending=Some(PendingConsumerData::Launch(operation.clone()));
    Ok(operation.receipt())
}
pub(crate) fn submit_peer_data(world:&Arc<RwLock<DesiredWorld>>,signer:&str,plan:&PodLaunch)->Result<Submission,String>{
    let book=ROOTED_BOOK.get().ok_or("native DATA receiver has no actual local READY book")?;
    if !Arc::ptr_eq(book.world(),world)||!core::is_actual_world(world){return Err("native DATA receiver refuses supplied/frozen world".into());}
    {
        let current=world.try_read().map_err(|_|"native DATA current source busy")?;
        if plan.cluster_id!=current.cluster_id||plan.node!=crate::store::node_name()
            || plan.namespace_uid.as_ref()!=current.storage_identities.namespaces.get(&plan.namespace){
            return Err("native DATA is for another cluster/node/namespace incarnation".into());
        }
        let directory=current.storage_node_directory.directory().ok_or("native DATA directory absent")?;
        let handle=crate::raft_node::RAFT.get().ok_or("native DATA actual Raft absent")?;
        let metrics=handle.raft.metrics().borrow().clone();
        let leader=metrics.current_leader.ok_or("native DATA issuer unknown")?;
        if !data_signer_matches(directory,leader,&book.node,signer){
            return Err("native DATA is not from the current registered local leader; no remote-writer fallback".into());
        }
    }
    // Signature/name and DATA only select a request; actual later request-
    // bound quorum and READY lifetime, NEVER this metrics observation, grant.
    submit_data(plan)
}
fn data_signer_matches(directory:&crate::storage_node_directory::DirectoryDto,leader:u64,local:&Uid,signer:&str)->bool{
    directory.nodes.iter().any(|pin|pin.raft_id==leader&&&pin.node_uid==local&&pin.signer_name==signer)
}
pub(crate) fn registered_target(selector:&str)->bool{
    let Some(book)=ROOTED_BOOK.get()else{return false;};
    let state=book.state.lock().unwrap_or_else(|p|p.into_inner());
    for operation in state.consumer.history.values(){
        let containers=operation.containers.lock().unwrap_or_else(|p|p.into_inner());
        if containers.values().any(|c|c.matches_selector(selector)){return true;}
        if operation.key.destinations.contains_key(selector.trim_start_matches('/')){return true;}
    }
    false
}
pub(crate) fn retained_pod(namespace:&str,pod:&str)->bool{
    ROOTED_BOOK.get().is_some_and(|book|book.state.lock().unwrap_or_else(|p|p.into_inner()).consumer.history.values()
        .any(|operation|operation.key.namespace==namespace&&operation.key.pod==pod))
}
pub(crate) fn eligible_container(id:&str)->bool{
    let Some(book)=ROOTED_BOOK.get()else{return false;};
    let owned={
        let Ok(state)=book.state.try_lock()else{return false;};
        state.consumer.history.values().find_map(|operation|{
            let roots=operation.containers.try_lock().ok()?;
            roots.get(id).cloned()
        })
    };
    let Some(owned)=owned else{return false;};
    if owned.operation.status.load(Ordering::Acquire)!=RUNNING
        || owned.status.load(Ordering::Acquire)!=CONTAINER_STARTED{return false;}
    let Ok(world)=book.world.try_read()else{return false;};
    let Ok(actual)=source_graph(&world,&owned.operation)else{return false;};
    owned.operation.source_sha256.try_lock().ok().is_some_and(|source|source.as_ref()==Some(&actual))
}

fn source_graph(world:&DesiredWorld,operation:&ManagedPodOperation)->Result<String,String>{
    let key=&operation.key;operation.ready.require_key(key)?;
    let binding=&operation.ready.binding;binding.check_source_current(world)?;
    let deployment=world.deployments.get(&crate::store::obj_key(binding.namespace(),binding.workload()))
        .ok_or("actual managed workload absent")?;
    if deployment.paused || deployment.replicas==0 || world.cluster_id!=key.cluster
        || world.storage_identities.namespaces.get(&key.namespace)!=Some(&key.namespace_uid){
        return Err("actual managed workload/namespace revoked".into());
    }
    let policies=world.network_policies.iter().filter(|(_,p)|p.namespace==key.namespace).collect::<BTreeMap<_,_>>();
    if policies.values().any(|policy|crate::workload::managed::policy_selects_names(
        &policy.pod_selector,&key.workload,key.destinations.keys().map(String::as_str))){
        return Err("applicable native NetworkPolicy unsupported; no new consumer effect/Ready claim".into());
    }
    let mut volumes=Vec::new();
    for (uid,reference) in &key.references{
        let volume=world.storage_identities.lifecycle.get(uid).ok_or("actual managed dataset absent")?;
        if volume.phase()!=Phase::Attached || ManagedMountRef::from_metadata(volume)?!=*reference
            || volume.pod_writer()!=Some(binding){return Err("actual managed Assignment/PodWriter/group changed".into());}
        let owner=volume.owner();let pv=world.pvs.get(&owner.pv_name).ok_or("actual managed PV absent")?;
        let pvc=world.pvcs.get(&crate::store::obj_key(&owner.namespace,&owner.claim_name)).ok_or("actual managed PVC absent")?;
        let class=world.storage_classes.get(&pv.storage_class).ok_or("actual managed StorageClass absent")?;
        volumes.push((uid,volume,pv,pvc,class));
    }
    let mut configmaps=BTreeMap::new();let mut secrets=BTreeMap::new();
    for container in deployment.init_containers.iter().chain(&deployment.containers){
        for name in &container.env_from_configmaps{
            let key=crate::store::obj_key(&deployment.namespace,name);
            configmaps.insert(key.clone(),world.configmaps.get(&key).ok_or("actual ConfigMap source absent")?);
        }
        for name in &container.env_from_secrets{
            let key=crate::store::obj_key(&deployment.namespace,name);
            secrets.insert(key.clone(),world.secrets.get(&key).ok_or("actual Secret source absent")?);
        }
        for reference in &container.env_refs{
            let key=crate::store::obj_key(&deployment.namespace,&reference.object);
            if reference.secret {if let Some(value)=world.secrets.get(&key){secrets.insert(key,value);}
                else if !reference.optional{return Err("actual Secret env source absent".into());}}
            else if let Some(value)=world.configmaps.get(&key){configmaps.insert(key,value);}
                else if !reference.optional{return Err("actual ConfigMap env source absent".into());}
        }
        for (source,_) in &container.volumes{
            if let Some(name)=source.strip_prefix("cmv:"){
                let key=crate::store::obj_key(&deployment.namespace,name);
                configmaps.insert(key.clone(),world.configmaps.get(&key).ok_or("actual projected ConfigMap absent")?);
            }else if let Some(name)=source.strip_prefix("sev:"){
                let key=crate::store::obj_key(&deployment.namespace,name);
                secrets.insert(key.clone(),world.secrets.get(&key).ok_or("actual projected Secret absent")?);
            }
        }
    }
    let ca=world.cluster_ca.as_ref().map(|ca|ca.cert_pem.as_str());
    let directory=world.storage_node_directory.directory().ok_or("actual guarded directory absent")?;
    // Hash only; Secret/env values are NEVER emitted in evidence or errors.
    let encoded=serde_json::to_vec(&("managed-consumer-current-source-v1",key,binding,deployment,
        volumes,configmaps,secrets,ca,directory,policies)).map_err(|_|"actual managed source hashing failed")?;
    if encoded.len()>1024*1024{return Err("relevant consumer source exceeds existing1MiB frame bound".into());}
    Ok(digest(&encoded))
}
fn capture_actual_plan(shared:&Shared,operation:&ManagedPodOperation)->Result<PodLaunch,String>{
    operation.live()?;
    let (mut snapshot,deployment,expected)={
        let world=shared.world.try_read().map_err(|_|"actual managed source Core busy")?;
        let graph=source_graph(&world,operation)?;
        let deployment=world.deployments.get(&crate::store::obj_key(&operation.key.namespace,&operation.key.workload))
            .ok_or("actual managed workload disappeared")?.clone();
        (world.clone(),deployment,graph)
    };
    let src=crate::workload::PodSource{kind:"deployment",namespace:&deployment.namespace,owner:&deployment.name,
        init_containers:&deployment.init_containers,containers:&deployment.containers,limits:deployment.resource_limits.as_ref(),
        restart_nonce:deployment.restart_nonce};
    let plan=crate::workload::plan_pod(&mut snapshot,&src,&operation.key.pod,operation.key.ordinal,&crate::store::node_name())?;
    if LaunchKey::from_plan_data(&plan)?!=operation.key{return Err("actual rebuilt managed launch differs from submitted DATA identity".into());}
    let mut files=std::collections::BTreeSet::new();let mut actions=0usize;
    for container in plan.init_containers.iter().chain(&plan.containers){
        actions+=2;
        if container.mounts.iter().any(|m|!matches!(m.source,crate::workload::MountSource::Managed{..})){actions+=1;}
        for mount in &container.mounts{
            if let crate::workload::MountSource::Projected{name,secret,files:values}=&mount.source{
                for key in values.keys(){files.insert((*secret,name.clone(),key.clone()));}
            }
        }
    }
    if actions>MAX_CONSUMER_ACTIONS||files.len()>512{return Err("consumer exceeds derived384 action/512 private-entry ownership guards; no effect submitted".into());}
    *operation.source_sha256.lock().map_err(|_|"actual managed source digest poisoned")?=Some(expected);
    *operation.plan.lock().map_err(|_|"actual managed rebuilt plan poisoned")?=Some(plan.clone());
    operation.live()?;Ok(plan)
}

const CONTAINER_CREATED:u8=0;const CONTAINER_VERIFIED:u8=1;const CONTAINER_STARTING:u8=2;const CONTAINER_STARTED:u8=3;
pub(crate) struct OwnedManagedContainer {
    id:String,name:String,nonce:Uid,operation:Arc<ManagedPodOperation>,
    image_id:String,create_body_sha256:String,status:AtomicU8,expected:Arc<crate::docker::managed::PreparedCreate>,
    started_stamp:Mutex<Option<String>>,role:String,
    process:Mutex<terminal::OriginalProcessPin>,
}
impl OwnedManagedContainer {
    pub(crate) fn id(&self)->&str{&self.id}
    pub(crate) fn name(&self)->&str{&self.name}
    pub(crate) fn nonce(&self)->&Uid{&self.nonce}
    pub(crate) fn operation_uid(&self)->&Uid{&self.operation.uid}
    pub(crate) fn writer(&self)->&crate::storage_pod_writer::PodWriterUid{&self.operation.key.writer}
    pub(crate) fn image_id(&self)->&str{&self.image_id}
    pub(crate) fn create_body_sha256(&self)->&str{&self.create_body_sha256}
    fn matches_selector(&self,value:&str)->bool{
        let value=value.trim_start_matches('/');
        value==self.name || value==self.id || value.len()>=12 && value.len()<64
            && value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) && self.id.starts_with(value)
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq,serde::Serialize)]
pub(crate) enum ConsumerPurpose {Materialize,Create,Start}
struct ConsumerAction {
    uid:Uid,operation:Arc<ManagedPodOperation>,purpose:ConsumerPurpose,
    request:Mutex<Option<Arc<EffectRequest>>>,started:Instant,deadline:Instant,
    journaled:AtomicBool,submitted:AtomicBool,outcome:Mutex<Option<String>>,
    known_container:Mutex<Option<Arc<OwnedManagedContainer>>>,
    start_target:Mutex<Option<Arc<OwnedManagedContainer>>>,
}
struct EffectRequest {method:String,path:String,body:Option<Vec<u8>>,body_sha256:String,daemon_sha256:String}
impl ConsumerAction {
    /// Original clock is owned/rooted BEFORE image/network/source preflights.
    /// Later request preparation cannot renew it or accept a caller deadline.
    fn begin(operation:Arc<ManagedPodOperation>,purpose:ConsumerPurpose)->Result<Arc<Self>,String>{
        operation.live()?;
        let now=Instant::now();
        let duration=if purpose==ConsumerPurpose::Start{Duration::from_secs(60)}else{Duration::from_secs(30)};
        let action=Arc::new(Self{uid:Uid::new(),operation:operation.clone(),purpose,request:Mutex::new(None),started:now,deadline:now+duration,
            journaled:AtomicBool::new(false),submitted:AtomicBool::new(false),outcome:Mutex::new(None),
            known_container:Mutex::new(None),start_target:Mutex::new(None)});
        let mut actions=operation.actions.lock().map_err(|_|"original consumer action book poisoned")?;
        if actions.len()>=MAX_CONSUMER_ACTIONS{return Err("derived consumer action history bound exhausted".into());}
        actions.insert(action.uid.clone(),action.clone());Ok(action)
    }
    fn prepare(&self,connection:&crate::docker::ManagedConsumerConnection,method:&str,path:String,body:Option<Vec<u8>>)
        ->Result<Arc<EffectRequest>,String>{
        self.live()?;
        let daemon_sha256=connection.identity_sha256()?;
        if body.as_ref().is_some_and(|b|b.len()>1024*1024)||!matches!(method,"POST"|"LOCAL")||!is_hash(&daemon_sha256){
            return Err("closed consumer action request is malformed/oversized".into());
        }
        let request=Arc::new(EffectRequest{method:method.into(),path,body_sha256:digest(body.as_deref().unwrap_or(&[])),body,daemon_sha256});
        let mut original=self.request.lock().map_err(|_|"consumer request preparation poisoned")?;
        if original.is_some()||self.journaled.load(Ordering::Acquire)||self.submitted.load(Ordering::Acquire){
            return Err("original consumer request already prepared/submitted; no retry".into());
        }
        *original=Some(request.clone());Ok(request)
    }
    fn prepared(&self)->Result<Arc<EffectRequest>,String>{
        self.request.lock().map_err(|_|"consumer prepared request poisoned")?.as_ref().cloned()
            .ok_or_else(||"original actual preflight/request preparation absent".into())
    }
    fn live(&self)->Result<(),String>{
        self.operation.live()?;
        if Instant::now()<self.started || Instant::now()>=self.deadline{return Err("original consumer action expired".into());}
        Ok(())
    }
    async fn authorize(self:&Arc<Self>,shared:&Arc<Shared>)->Result<VerifiedConsumerAction,String>{
        self.live()?;
        let value=self.clone();let journal=shared.journal.clone();let prepared=self.prepared()?;
        let budget=budget_for(&self.operation)?;
        shared.io.run(move||{
            value.live()?;
            journal.consumer_admission(&budget,&value.operation.uid,&value.uid,value.purpose,
                &value.operation.key,&prepared.method,&prepared.path,&prepared.body_sha256,&prepared.daemon_sha256)?;
            value.journaled.store(true,Ordering::Release);value.live()
        }).await?;
        let request=ConsumerReadRequest::new(self.clone())?;
        let first=self.operation.key.references.keys().next().ok_or("empty original consumer group")?;
        let observed=core::observe_consumer_issuer(first,&request).await?;
        let directory=shared.directory_for(&observed)?;
        if observed.local_node_uid()!=Some(&shared.pool.node_uid) || observed.actual_boot()!=&self.operation.ready.book.boot
            || directory.pin(&shared.pool.node_uid)?.raft_id!=observed.revision().leader_raft_id{
            return Err("new consumer action lacks actual current local acknowledged leader/boot".into());
        }
        observed.require_fresh_consumer(&request,Instant::now())?;
        {
            let world=shared.world.try_read().map_err(|_|"actual consumer Core busy after barrier")?;
            if world.generation!=observed.revision().desired_generation
                || world.storage_identities.lifecycle.get(first)!=Some(observed.volume()){
                return Err("consumer actual Core changed after THIS coherent capture".into());
            }
            self.require_source(&world)?;
        }
        self.live()?;
        Ok(VerifiedConsumerAction{action:self.clone(),request,observed,spent:AtomicBool::new(false)})
    }
    fn require_source(&self,world:&DesiredWorld)->Result<(),String>{
        let expected=self.operation.source_sha256.lock().map_err(|_|"consumer source digest poisoned")?
            .clone().ok_or("no actual rebuilt source")?;
        if source_graph(world,&self.operation)?!=expected{return Err("actual consumer source/group changed".into());}
        Ok(())
    }
}
fn is_hash(value:&str)->bool{value.len()==64&&value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}

/// Genuine local request, private producer only. No raw hash/wire constructor.
pub(crate) struct ConsumerReadRequest {action:Arc<ConsumerAction>,request:Arc<EffectRequest>,nonce:Uid,binding:String}
impl ConsumerReadRequest {
    fn new(action:Arc<ConsumerAction>)->Result<Self,String>{
        action.live()?;
        if !action.journaled.load(Ordering::Acquire)||action.submitted.load(Ordering::Acquire){
            return Err("consumer action was not durably admitted or already submitted".into());
        }
        let request=action.prepared()?;
        let nonce=Uid::new();
        let binding=digest(&serde_json::to_vec(&("managed-consumer-request-v1",&action.operation.uid,&action.uid,
            action.purpose,&action.operation.key,&request.method,&request.path,&request.body_sha256,&request.daemon_sha256,&nonce))
            .map_err(|_|"consumer exact request binding failed")?);
        Ok(Self{action,request,nonce,binding})
    }
    pub(crate) fn binding(&self)->&str{&self.binding}
    pub(crate) fn require_produced(&self)->Result<(),String>{
        self.action.live()?;
        if self.nonce.as_str().is_empty()||!self.action.journaled.load(Ordering::Acquire)
            || self.action.submitted.load(Ordering::Acquire)||!Arc::ptr_eq(&self.action.prepared()?,&self.request){
            return Err("consumer request lost original admission".into());}
        Ok(())
    }
}
/// One-use actual fresh request-bound Core permission, never serde/Clone.
pub(crate) struct VerifiedConsumerAction {
    action:Arc<ConsumerAction>,request:ConsumerReadRequest,observed:core::CoreObservation,spent:AtomicBool,
}
impl VerifiedConsumerAction {
    pub(crate) fn consume(self,connection:&crate::docker::ManagedConsumerConnection,
        method:&str,path:&str,body:Option<&[u8]>,deadline:Instant)->Result<SubmittedConsumerAction,String>{
        self.action.live()?;self.request.require_produced()?;
        self.observed.require_fresh_consumer(&self.request,Instant::now())?;
        core::require_same_actual_epoch(&self.action.operation.ready.book.world,self.observed.revision())?;
        if deadline!=self.action.deadline || method!=self.request.request.method || path!=self.request.request.path
            || body!=self.request.request.body.as_deref()
            || connection.identity_sha256()?!=self.request.request.daemon_sha256{
            return Err("consumer permission differs from exact original daemon/method/path/body/deadline".into());
        }
        {
            let world=self.action.operation.ready.book.world.try_read().map_err(|_|"actual consumer source busy at effect edge")?;
            self.action.require_source(&world)?;
        }
        self.action.live()?;
        if self.spent.swap(true,Ordering::AcqRel)||self.action.submitted.swap(true,Ordering::AcqRel){
            return Err("consumer one-use permission already spent".into());
        }
        if self.action.purpose==ConsumerPurpose::Start{
            let owned=self.action.start_target.lock().map_err(|_|"original Start target poisoned")?.as_ref().cloned()
                .ok_or("original Start has no actual owned target")?;
            if !Arc::ptr_eq(&owned.operation,&self.action.operation)
                || self.request.request.path!=format!("/containers/{}/start",owned.id()){
                return Err("original Start target differs from actual full CID".into());
            }
            owned.status.compare_exchange(CONTAINER_VERIFIED,CONTAINER_STARTING,Ordering::AcqRel,Ordering::Acquire)
                .map_err(|_|"owned container Start already possible/unknown; never retry")?;
        }
        Ok(SubmittedConsumerAction{action:self.action.clone()})
    }
}
impl Drop for VerifiedConsumerAction {fn drop(&mut self){
    if !self.spent.load(Ordering::Acquire){self.action.operation.invalidate("original consumer permission dropped/unconsumed");}
}}
/// Original submitted-operation observation sink, NOT another effect grant.
pub(crate) struct SubmittedConsumerAction {action:Arc<ConsumerAction>}
impl SubmittedConsumerAction {
    pub(crate) fn record_response(&self,status:u16,raw:&[u8]){
        // Candidate ID remains DATA if framing/receipt validation later fails.
        let candidate=serde_json::from_slice::<serde_json::Value>(raw).ok()
            .and_then(|v|v.get("Id").and_then(|v|v.as_str()).map(str::to_string))
            .filter(|v|v.len()==64&&v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)));
        *self.action.outcome.lock().unwrap_or_else(|p|p.into_inner())=
            Some(format!("HTTP{status};body_sha256={};candidate_id_DATA={}",digest(raw),candidate.as_deref().unwrap_or("unknown")));
    }
    pub(crate) fn record_transport_unknown(&self){
        *self.action.outcome.lock().unwrap_or_else(|p|p.into_inner())=Some("POST_SUBMITTED_TRANSPORT_UNKNOWN".into());
    }
    pub(crate) fn invalidate_after_response(&self){
        self.action.operation.invalidate("complete response arrived after original deadline/identity/lifetime edge");
    }
}

fn sources_for(operation:&ManagedPodOperation)->Result<Arc<BTreeMap<Uid,VerifiedManagedSource>>,String>{
    operation.sources.lock().map_err(|_|"original source-capability ownership poisoned")?.as_ref().cloned()
        .ok_or_else(||"actual owned source set absent; no JSON/path fallback".into())
}
async fn ensure_sources(shared:&Arc<Shared>,action:&Arc<ConsumerAction>)->Result<(),String>{
    if action.operation.sources.lock().map_err(|_|"actual source set poisoned")?.is_some(){return action.live();}
    let current=action.clone();
    shared.io.run(move||{
        current.live()?;
        let sources=Arc::new(current.operation.ready.sources(current.deadline)?);
        let mut retained=current.operation.sources.lock().map_err(|_|"actual source root poisoned")?;
        if retained.is_some(){return Err("source set already produced; no replacement".into());}
        *retained=Some(sources);drop(retained);current.live()
    }).await
}
fn reobserve_inputs(operation:&ManagedPodOperation,deadline:Instant)->Result<(),String>{
    operation.live()?;
    for source in sources_for(operation)?.values(){source.reobserve(deadline)?;}
    let internal=operation.internal.lock().map_err(|_|"internal source roots poisoned")?.values().cloned().collect::<Vec<_>>();
    for source in internal{source.reobserve(deadline)?;}
    operation.live()
}
fn connect_for(operation:&ManagedPodOperation,deadline:Instant)->Result<crate::docker::ManagedConsumerConnection,String>{
    sources_for(operation)?.values().next().ok_or("actual source group empty")?.connect(deadline)
}
fn record_action_result(shared:&Shared,action:&ConsumerAction,status:u16,cid:Option<&str>,known:&str)->Result<(),String>{
    // Original IO records known data BEFORE any fallible evidence/send/live
    // check. Late known output is retained, not promoted to timely success.
    *action.outcome.lock().unwrap_or_else(|p|p.into_inner())=Some(format!("{known}:{}",cid.unwrap_or("none")));
    let budget=budget_for(&action.operation)?;
    shared.journal.consumer_outcome(budget.as_ref(),&action.operation.uid,&action.uid,status,cid,known)
}
fn budget_for(operation:&ManagedPodOperation)->Result<Arc<journal::ConsumerEvidenceBudget>,String>{
    operation.terminal_plan.try_lock().map_err(|_|"actual pre-Create terminal roots busy")?.as_ref()
        .ok_or("no actual pre-Create all-node terminal reservation")?.require_full_precharge()?;
    let budget=operation.budget.lock().map_err(|_|"actual consumer evidence budget poisoned")?.as_ref().cloned()
        .ok_or("actual whole-plan evidence budget not admitted; no consumer effect")?;
    let source=operation.source_sha256.lock().map_err(|_|"actual source budget binding poisoned")?.clone()
        .ok_or("actual source budget binding absent")?;
    if budget.source_sha256()!=source{return Err("actual charged budget belongs to another rebuilt source".into());}
    Ok(budget)
}
async fn reserve_plan_budget(shared:&Arc<Shared>,operation:&Arc<ManagedPodOperation>,plan:&PodLaunch)->Result<(),String>{
    if operation.budget_attempted.swap(true,Ordering::AcqRel){return Err("original consumer budget already attempted; no retry".into());}
    let containers=plan.init_containers.len().checked_add(plan.containers.len()).ok_or("actual plan container count overflow")?;
    let materializations=plan.init_containers.iter().chain(&plan.containers)
        .filter(|container|container.mounts.iter().any(|m|!matches!(m.source,crate::workload::MountSource::Managed{..}))).count();
    let source=operation.source_sha256.lock().map_err(|_|"actual consumer source hash poisoned")?.clone().ok_or("actual rebuilt plan source absent")?;
    terminal::PreparedTerminalPlan::prepare(shared,operation,source,containers,materializations).await?;
    operation.live()
}
fn retain_created(action:&Arc<ConsumerAction>,expected:Arc<crate::docker::managed::PreparedCreate>,
    actual:&crate::docker::managed::DockerCreated)->Arc<OwnedManagedContainer>{
    // Called ONLY immediately after the real permission-bearing201 adapter.
    // No fallible check/evidence or poisoned-lock error can lose known CID.
    let id=actual.id().to_string();
    let owned=Arc::new(OwnedManagedContainer{id:id.clone(),name:expected.name().into(),
        nonce:expected.nonce().clone(),operation:action.operation.clone(),image_id:expected.image_id().into(),
        create_body_sha256:digest(expected.body()),status:AtomicU8::new(CONTAINER_CREATED),
        started_stamp:Mutex::new(None),role:expected.role().into(),expected,
        process:Mutex::new(terminal::OriginalProcessPin::empty_before_start())});
    *action.known_container.lock().unwrap_or_else(|p|p.into_inner())=Some(owned.clone());
    let mut roots=action.operation.containers.lock().unwrap_or_else(|p|p.into_inner());
    let collision=roots.contains_key(&id);
    if !collision{roots.insert(id,owned.clone());}
    drop(roots);
    if collision{action.operation.invalidate("actual Create returned conflicting existing CID; both observations retained");}
    owned
}
async fn materialize_step(shared:&Arc<Shared>,operation:&Arc<ManagedPodOperation>,plan:&PodLaunch,container:&ContainerLaunch)
    ->Result<Vec<(String,String)>,String>{
    if !container.mounts.iter().any(|m|!matches!(m.source,crate::workload::MountSource::Managed{..})){return Ok(vec![]);}
    let action=ConsumerAction::begin(operation.clone(),ConsumerPurpose::Materialize)?;
    ensure_sources(shared,&action).await?;
    let current=action.clone();let mounts=container.mounts.clone();let name=container.docker_name.clone();
    let mut connection=shared.io.run(move||{
        reobserve_inputs(&current.operation,current.deadline)?;
        let connection=connect_for(&current.operation,current.deadline)?;
        current.prepare(&connection,"LOCAL",format!("/local/materialize/{name}"),
            Some(serde_json::to_vec(&mounts).map_err(|_|"materialization binding encode failed")?))?;
        Ok(connection)
    }).await?;
    let permission=action.authorize(shared).await?;
    let current=action.clone();let shared=shared.clone();let plan=plan.clone();let container=container.clone();
    shared.clone().io.run(move||{
        reobserve_inputs(&current.operation,current.deadline)?;connection.validate(current.deadline)?;
        let request=current.prepared()?;
        permission.consume(&connection,&request.method,&request.path,request.body.as_deref(),current.deadline)?;
        let paths=materialize_internal(&current.operation,&plan,&container,current.deadline)?;
        record_action_result(&shared,&current,200,None,"LOCAL_MATERIALIZED")?;
        current.live()?;Ok(paths)
    }).await
}
async fn create_one(shared:&Arc<Shared>,operation:&Arc<ManagedPodOperation>,plan:&PodLaunch,container:&ContainerLaunch)
    ->Result<Arc<OwnedManagedContainer>,String>{
    let internal=materialize_step(shared,operation,plan,container).await?;
    let action=ConsumerAction::begin(operation.clone(),ConsumerPurpose::Create)?;
    ensure_sources(shared,&action).await?;
    let current=action.clone();let plan=plan.clone();let container=container.clone();
    let (mut connection,prepared)=shared.io.run(move||{
        reobserve_inputs(&current.operation,current.deadline)?;
        let mut connection=connect_for(&current.operation,current.deadline)?;
        let image=crate::docker::managed::inspect_image(&mut connection,&container.image,current.deadline)?;
        let network=crate::docker::managed::inspect_network(&mut connection,&plan.namespace,current.deadline)?;
        let sources=sources_for(&current.operation)?;
        let prepared=Arc::new(crate::docker::managed::prepare_create(&plan,&container,&current.operation.uid,current.uid.clone(),
            image,network,sources.as_ref(),&internal)?);
        current.prepare(&connection,"POST",prepared.path().into(),Some(prepared.body().to_vec()))?;
        Ok((connection,prepared))
    }).await?;
    let permission=action.authorize(shared).await?;
    let current=action.clone();let shared_io=shared.clone();let expected=prepared.clone();
    let owned=shared.io.run(move||{
        reobserve_inputs(&current.operation,current.deadline)?;
        let actual=crate::docker::managed::create(&mut connection,permission,&expected,current.deadline)?;
        let owned=retain_created(&current,expected,&actual);
        record_action_result(&shared_io,&current,201,Some(owned.id()),"CREATE_201_KNOWN")?;
        current.live()?;Ok(owned)
    }).await?;
    let current=action.clone();let checked=owned.clone();
    shared.io.run(move||{
        reobserve_inputs(&current.operation,current.deadline)?;
        let mut connection=connect_for(&current.operation,current.deadline)?;
        let observed=crate::docker::managed::inspect_owned(&mut connection,&checked.expected,&checked,current.deadline)?;
        if observed.running||!zero_started(&observed.started_at){return Err("newly created owned container already started/unknown; no Start".into());}
        current.live()?;
        checked.status.compare_exchange(CONTAINER_CREATED,CONTAINER_VERIFIED,Ordering::AcqRel,Ordering::Acquire)
            .map_err(|_|"actual created CID was already consumed")?;
        Ok(())
    }).await?;
    Ok(owned)
}
fn zero_started(value:&str)->bool{value=="0001-01-01T00:00:00Z"||value=="0001-01-01T00:00:00.000000000Z"}
async fn start_one(shared:&Arc<Shared>,operation:&Arc<ManagedPodOperation>,owned:Arc<OwnedManagedContainer>)->Result<(),String>{
    if !Arc::ptr_eq(&owned.operation,operation)||owned.status.load(Ordering::Acquire)!=CONTAINER_VERIFIED{
        return Err("Start requires the same actual verified Created CID; no restart/adopt".into());
    }
    let action=ConsumerAction::begin(operation.clone(),ConsumerPurpose::Start)?;
    *action.start_target.lock().map_err(|_|"actual original Start ownership poisoned")?=Some(owned.clone());
    let current=action.clone();let checked=owned.clone();
    let mut connection=shared.io.run(move||{
        reobserve_inputs(&current.operation,current.deadline)?;
        let mut connection=connect_for(&current.operation,current.deadline)?;
        let observed=crate::docker::managed::inspect_owned(&mut connection,&checked.expected,&checked,current.deadline)?;
        if observed.running||!zero_started(&observed.started_at){return Err("actual owned CID is no longer never-started; no blind Start".into());}
        current.prepare(&connection,"POST",format!("/containers/{}/start",checked.id()),None)?;
        Ok(connection)
    }).await?;
    let permission=action.authorize(shared).await?;
    let current=action.clone();let shared_io=shared.clone();
    shared.io.run(move||{
        reobserve_inputs(&current.operation,current.deadline)?;
        crate::docker::managed::start(&mut connection,permission,&owned,current.deadline)?;
        owned.status.store(CONTAINER_STARTED,Ordering::Release); // Known ACK, not current Running or OS drain.
        record_action_result(&shared_io,&current,204,Some(owned.id()),"START_204_KNOWN")?;
        terminal::capture_original_process(&shared_io,&current.operation,&owned,&mut connection,current.deadline)?;
        current.live()
    }).await
}
async fn inspect_current(shared:&Arc<Shared>,operation:&Arc<ManagedPodOperation>,owned:Arc<OwnedManagedContainer>)
    ->Result<crate::docker::managed::ContainerObservation,String>{
    inspect_before(shared,operation,owned,Instant::now()+Duration::from_secs(30)).await
}
async fn inspect_before(shared:&Arc<Shared>,operation:&Arc<ManagedPodOperation>,owned:Arc<OwnedManagedContainer>,
    deadline:Instant)->Result<crate::docker::managed::ContainerObservation,String>{
    if Instant::now()>=deadline{return Err("original readonly observation deadline expired before request".into());}
    let current=operation.clone();let expected=owned.clone();
    shared.io.run(move||{
        current.live()?;
        if Instant::now()>=deadline{return Err("original readonly observation deadline expired on IO queue".into());}
        reobserve_inputs(&current,deadline)?;
        let mut connection=connect_for(&current,deadline)?;
        let observed=crate::docker::managed::inspect_owned(&mut connection,&expected.expected,&expected,deadline)?;
        if zero_started(&observed.started_at){return Err("owned Start ACK has no actual started incarnation".into());}
        {
            let mut original=expected.started_stamp.lock().map_err(|_|"actual started incarnation poisoned")?;
            if original.as_ref().is_some_and(|known|known!=&observed.started_at){
                return Err("same full CID has another unadmitted process incarnation; never adopt".into());
            }
            if original.is_none(){*original=Some(observed.started_at.clone());}
        }
        current.live()?;
        if Instant::now()>=deadline{return Err("actual readonly response completed after original observation deadline".into());}
        Ok(observed)
    }).await
}
async fn run_operation(shared:&Arc<Shared>,operation:Arc<ManagedPodOperation>)->Result<(),String>{
    let mut retain=RetainOperation{operation:operation.clone(),finished:false};
    operation.status.compare_exchange(ACCEPTED,ACTIVE,Ordering::AcqRel,Ordering::Acquire)
        .map_err(|_|"original managed operation already active/UNKNOWN; no retry")?;
    let plan=capture_actual_plan(shared,&operation)?;
    reserve_plan_budget(shared,&operation,&plan).await?;
    for container in &plan.init_containers{
        let owned=create_one(shared,&operation,&plan,container).await?;
        start_one(shared,&operation,owned.clone()).await?;
        let original_deadline=Instant::now()+Duration::from_secs(120);
        loop{
            if Instant::now()>=original_deadline{return Err("original120s init observation expired before request".into());}
            let call_deadline=original_deadline.min(Instant::now()+Duration::from_secs(30));
            let observed=inspect_before(shared,&operation,owned.clone(),call_deadline).await?;
            if init_observation_decision(original_deadline,Instant::now(),observed.running,observed.exit_code)?{break;}
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        // Known completed init container stays exactly owned/recorded.
        // Removal is NOT a prerequisite or a writer-volume release proof.
    }
    let mut mains=Vec::new();
    for container in &plan.containers{mains.push(create_one(shared,&operation,&plan,container).await?);}
    for owned in &mains{start_one(shared,&operation,owned.clone()).await?;}
    for owned in mains{
        if !inspect_current(shared,&operation,owned).await?.running{
            return Err("owned main exited before complete Pod start; partial group retained".into());
        }
    }
    {
        let world=shared.world.try_read().map_err(|_|"actual source busy at final launch edge")?;
        let expected=operation.source_sha256.lock().map_err(|_|"actual source digest poisoned")?.clone().ok_or("actual source digest absent")?;
        if source_graph(&world,&operation)?!=expected{return Err("actual Pod source changed during launch".into());}
    }
    operation.live()?;operation.status.store(RUNNING,Ordering::Release);
    {
        let mut state=operation.ready.book.state.lock().map_err(|_|"original pending slot poisoned")?;
        if !matches!(state.consumer.pending.as_ref(),Some(PendingConsumerData::Launch(same)) if Arc::ptr_eq(same,&operation)){
            return Err("actual pending owner changed; no completion from returned JSON".into());
        }
        state.consumer.pending=None; // history/CIDs/FDs/leases stay rooted.
    }
    retain.finished=true;Ok(())
}
/// DATA clock decision only, not a process/volume drain or completion receipt.
fn init_observation_decision(deadline:Instant,now:Instant,running:bool,exit_code:i64)->Result<bool,String>{
    if now>=deadline{return Err("original120s init observation expired, including late exited-success".into());}
    if running{return Ok(false);}
    if exit_code!=0{return Err("actual owned init exited nonzero; retain without rollback".into());}
    Ok(true)
}
#[cfg(test)]
mod observation_clock_regressions{
    use super::*;
    #[test]
    fn init_success_at_or_after_original_120s_is_not_accepted(){
        let start=Instant::now();let deadline=start+Duration::from_secs(120);
        assert_eq!(init_observation_decision(deadline,deadline-Duration::from_nanos(1),false,0),Ok(true));
        assert!(init_observation_decision(deadline,deadline,false,0).is_err());
        assert!(init_observation_decision(deadline,deadline+Duration::from_secs(29),false,0).is_err());
        // This actual branch is used AFTER the readonly response and BEFORE
        // accepting exited-success. No fake READY/owner/process constructor.
    }
    #[test]
    fn init_running_and_failure_do_not_renew_original_observation_budget(){
        let start=Instant::now();let original=start+Duration::from_secs(120);
        assert_eq!(init_observation_decision(original,start+Duration::from_secs(119),true,0),Ok(false));
        assert!(init_observation_decision(original,start+Duration::from_secs(119),false,1).is_err());
        assert!(init_observation_decision(original,original,true,0).is_err());
        let call=original.min(start+Duration::from_secs(119)+Duration::from_secs(30));
        assert_eq!(call,original);
    }
    #[test]
    fn consumer_action_bound_is_derived_not_the_helper_attempt_limit(){
        assert_eq!(MAX_CONSUMER_ACTIONS,384);
        assert!(2*crate::workload::managed::MAX_DATA_CONTAINERS<=MAX_CONSUMER_ACTIONS);
        // Evidence reservation can still REFUSE 4*C+2*M against remaining512;
        // this DATA ceiling is NOT a claim of128-container physical capacity.
        assert_eq!(4*crate::workload::managed::MAX_DATA_CONTAINERS+2*128,768);
    }
}
pub(super) async fn run(shared:Arc<Shared>,book:Arc<MountBook>,interval:u64)->Result<(),String>{
    terminal::serve_original_consumer(shared,book,interval).await
}

struct InternalSource {
    path:std::path::PathBuf,directory:std::fs::File,identity:(u64,u64),declared:String,
    files:Mutex<BTreeMap<String,(Arc<std::fs::File>,String,u32)>>,projected:bool,complete:AtomicBool,
}
fn open_directory(path:&std::path::Path)->Result<std::fs::File,String>{
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)
        .open(path).map_err(|_|"actual private consumer directory unavailable".to_string())
}
fn file_identity(file:&std::fs::File)->Result<(u64,u64),String>{
    use std::os::unix::fs::MetadataExt;
    let metadata=file.metadata().map_err(|_|"consumer source FD stat unavailable")?;
    Ok((metadata.dev(),metadata.ino()))
}
impl InternalSource {
    fn reobserve(&self,deadline:Instant)->Result<(),String>{
        use std::os::{fd::AsRawFd,unix::fs::{MetadataExt,OpenOptionsExt,FileExt}};
        if Instant::now()>=deadline{return Err("original consumer materialization observation expired".into());}
        if !self.complete.load(Ordering::Acquire){return Err("private source materialization incomplete/UNKNOWN".into());}
        let reopened=open_directory(&self.path)?;
        if file_identity(&reopened)?!=self.identity||file_identity(&self.directory)?!=self.identity{
            return Err("same private consumer directory was replaced".into());
        }
        if self.projected{
            let files=self.files.lock().map_err(|_|"actual projected FD ownership poisoned")?;
            let entries=std::fs::read_dir(format!("/proc/self/fd/{}",self.directory.as_raw_fd()))
                .map_err(|_|"projected source census unavailable")?;
            let mut count=0usize;
            for entry in entries{
                count+=1;if count>512{return Err("projected source exceeds existing512 entry bound".into());}
                let entry=entry.map_err(|_|"projected source census incomplete")?;
                let name=entry.file_name().into_string().map_err(|_|"projected source name invalid")?;
                if !files.contains_key(&name){return Err("projected source has an extra/stale key".into());}
            }
            if count!=files.len(){return Err("projected source lost a key".into());}
            for (name,(held,expected,mode)) in files.iter(){
                let reopened=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC)
                    .open(self.path.join(name)).map_err(|_|"same projected source key absent")?;
                let metadata=reopened.metadata().map_err(|_|"projected source stat unavailable")?;
                if !metadata.is_file()||metadata.uid()!=0||metadata.nlink()!=1||metadata.mode()&0o777!=*mode
                    || metadata.len()>1024*1024||file_identity(&reopened)?!=file_identity(held)?{
                    return Err("same projected key FD/owner/mode changed".into());
                }
                let mut bytes=vec![0u8;usize::try_from(metadata.len()).map_err(|_|"projected size overflow")?];
                reopened.read_exact_at(&mut bytes,0).map_err(|_|"projected source read incomplete")?;
                if digest(&bytes)!=*expected{return Err("projected source bytes changed".into());}
                if Instant::now()>=deadline{return Err("projected observation completed late".into());}
            }
        }
        Ok(())
    }
}
fn materialize_internal(operation:&Arc<ManagedPodOperation>,plan:&PodLaunch,container:&ContainerLaunch,
    deadline:Instant)->Result<Vec<(String,String)>,String>{
    use std::os::unix::fs::{DirBuilderExt,OpenOptionsExt,PermissionsExt};
    use std::io::Write;
    let mut result=Vec::new();
    for mount in &container.mounts{
        let (key,projected,files)=match &mount.source{
            crate::workload::MountSource::Managed{..}=>continue,
            crate::workload::MountSource::EmptyDir{name}=>(format!("empty-{name}"),false,None),
            crate::workload::MountSource::Projected{name,secret,files}=>(format!("{}-{name}",if *secret{"secret"}else{"configmap"}),true,Some((files,*secret))),
            _=>return Err("native materialization cannot select legacy/public host paths".into()),
        };
        operation.live()?;
        if Instant::now()>=deadline{return Err("original materialization action expired".into());}
        let declared=digest(&serde_json::to_vec(&(&key,&mount.source)).map_err(|_|"materialization source binding failed")?);
        let existing={operation.internal.lock().map_err(|_|"consumer internal source book poisoned")?.get(&key).cloned()};
        if let Some(existing)=existing{
            if existing.declared!=declared{return Err("same private source has changed declaration".into());}
            existing.reobserve(deadline)?;
            result.push((existing.path.to_string_lossy().into_owned(),mount.container_path.clone()));continue;
        }
        let pdir=std::path::PathBuf::from(crate::workload::pod_dir(&plan.namespace,&plan.pod));
        crate::host_access::reject_native_publication_source(pdir.to_str().ok_or("private consumer path is not UTF8")?)?;
        {
            let mut original=operation.internal_root.lock().map_err(|_|"private consumer root poisoned")?;
            if original.is_none(){
                let parent=pdir.parent().ok_or("consumer root parent absent")?;
                let _parent=crate::storage_driver::private_fs::Dir::open(parent,true)?;
                std::fs::DirBuilder::new().mode(0o700).create(&pdir)
                    .map_err(|_|"fresh consumer scratch collision/UNKNOWN; never adopt/delete")?;
                *original=Some(open_directory(&pdir)?); // Root BEFORE later fallible checks.
            }
            if file_identity(original.as_ref().unwrap())?!=file_identity(&open_directory(&pdir)?)?{
                return Err("actual original consumer root path changed".into());
            }
        }
        let path=pdir.join(&key);
        std::fs::DirBuilder::new().mode(0o755).create(&path)
            .map_err(|_|"fresh internal source already exists/UNKNOWN; never retry/delete")?;
        let directory=open_directory(&path)?;let identity=file_identity(&directory)?;
        let actual=Arc::new(InternalSource{path,directory,identity,declared,files:Mutex::new(BTreeMap::new()),projected,complete:AtomicBool::new(false)});
        operation.internal.lock().map_err(|_|"internal source book poisoned")?.insert(key,actual.clone());
        // Actual directory FD is rooted BEFORE permissions/files/IO can fail.
        actual.directory.set_permissions(std::fs::Permissions::from_mode(0o755))
            .map_err(|_|"internal directory permissions UNKNOWN")?;
        if let Some((files,secret))=files{
            let total=files.values().try_fold(0usize,|n,value|n.checked_add(value.len()).ok_or("projected source overflow"))?;
            if files.len()>512||total>1024*1024{return Err("projected source exceeds existing frame/entry bounds".into());}
            for (name,value) in files{
                operation.live()?;
                if name.is_empty()||name=="."||name==".."||name.contains('/')||name.as_bytes().contains(&0){
                    return Err("projected source key is not an exact leaf".into());
                }
                let mode=if secret{0o600}else{0o644};
                let file=Arc::new(std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(mode)
                    .custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(actual.path.join(name))
                    .map_err(|_|"new projected key create UNKNOWN; no retry")?);
                actual.files.lock().map_err(|_|"projected FD ownership poisoned")?
                    .insert(name.clone(),(file.clone(),digest(value.as_bytes()),mode));
                file.set_permissions(std::fs::Permissions::from_mode(mode)).map_err(|_|"projected key mode UNKNOWN")?;
                (&*file).write_all(value.as_bytes()).map_err(|_|"projected key write UNKNOWN")?;
                file.sync_all().map_err(|_|"projected key fsync UNKNOWN")?;
                if Instant::now()>=deadline{return Err("materialization action expired mid-write; retained UNKNOWN".into());}
            }
        }
        actual.directory.sync_all().map_err(|_|"internal source directory fsync UNKNOWN")?;
        operation.live()?;
        if Instant::now()>=deadline{return Err("materialization final action edge late".into());}
        actual.complete.store(true,Ordering::Release);
        actual.reobserve(deadline)?;result.push((actual.path.to_string_lossy().into_owned(),mount.container_path.clone()));
    }
    operation.live()?;Ok(result)
}
