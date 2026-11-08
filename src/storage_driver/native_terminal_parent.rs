//! Genuine per-node terminal parent, retained before any grant/native launch.
//! Factories accept only actual local registration or accepted transport state.
use super::*;
use crate::storage_driver::dispatcher::{VerifiedLocalBoundary,attachment::{AttachOwner,VerifiedTerminalDrain}};
use crate::storage_driver::live_authority::JobIdentity;
use crate::storage_lifecycle::pod_attachment::ExpectedAttachScope;
use std::sync::Weak;

#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord,serde::Serialize,serde::Deserialize)]
pub(crate) enum TerminalNativeStep {UnmountAndDemote,ObserveSecondarySynchronized,OfflineAndObserve}
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord,serde::Serialize,serde::Deserialize)]
pub(crate) enum TerminalBoundary {Start,Identity,Program,Read,FlushMount,CloseMounted,Unmount,CloseBlock,
    Demote,ObserveSecondary,Offline,CloseRead,Complete,RetireLease}
pub(super) fn irreversible(kind:TerminalBoundary)->bool{matches!(kind,TerminalBoundary::FlushMount|TerminalBoundary::CloseMounted
    |TerminalBoundary::Unmount|TerminalBoundary::CloseBlock|TerminalBoundary::Demote|TerminalBoundary::Offline
    |TerminalBoundary::CloseRead|TerminalBoundary::RetireLease)}
pub(super) fn allowed(step:TerminalNativeStep,kind:TerminalBoundary,writer:bool)->bool{
    use TerminalBoundary::*;use TerminalNativeStep::*;
    match kind {
        Start|Identity|Program|Complete=>true,
        FlushMount|CloseMounted|Unmount|Demote=>writer&&step==UnmountAndDemote,
        ObserveSecondary=>step==ObserveSecondarySynchronized,
        Offline|Read|CloseRead=>step==OfflineAndObserve,
        CloseBlock=>if writer{step==UnmountAndDemote}else{step==OfflineAndObserve},
        RetireLease=>false, // Separate post-Detached actual-confirmation edge.
    }
}
enum Origin {Local(Arc<RegisteredDrainRound>),Receiver(Arc<wire::AcceptedTerminalReceiver>)}
struct NativeState {current:Option<TerminalNativeStep>,identities:BTreeMap<TerminalNativeStep,JobIdentity>,
    completed:BTreeSet<TerminalNativeStep>,pending:BTreeMap<(TerminalBoundary,String),String>,
    results:BTreeSet<(TerminalBoundary,String)>}
/// Not Clone/serde/default. Same Arc roots in AttachOwner before actual work.
pub(crate) struct VerifiedTerminalNodeParent {
    this:Weak<Self>,origin:Origin,shared:Arc<Shared>,owner:Arc<AttachOwner>,
    scope:ExpectedAttachScope,node_job:Uid,operation:Uid,started:Instant,deadline:Instant,
    native:Mutex<NativeState>,unknown:AtomicBool,handle:tokio::runtime::Handle,
}
struct RetainFailedParent<'a>{parent:&'a VerifiedTerminalNodeParent,finished:bool}
impl Drop for RetainFailedParent<'_>{fn drop(&mut self){if !self.finished{self.parent.retain_unknown();}}}
impl VerifiedTerminalNodeParent {
    pub(super) fn local(round:Arc<RegisteredDrainRound>,node:&Uid)->Result<Arc<Self>,String>{
        round.require_live()?;
        let expected=round.node_jobs.lock().map_err(|_|"terminal expected nodes poisoned")?.get(node).cloned()
            .ok_or("actual terminal node registration absent")?;
        let owner=expected.owner.as_ref().cloned().ok_or("remote DTO is not a local terminal owner")?;
        if node!=&round.shared.pool.node_uid{return Err("local terminal parent targets another node".into());}
        owner.require_terminal_retained()?;
        let value=Arc::new_cyclic(|this|Self{this:this.clone(),origin:Origin::Local(round.clone()),shared:round.shared.clone(),
            owner:owner.clone(),scope:expected.scope.clone(),node_job:expected.uid.clone(),operation:round.plan.uid.clone(),
            started:round.started,deadline:round.deadline,native:Mutex::new(NativeState{current:None,identities:BTreeMap::new(),
                completed:BTreeSet::new(),pending:BTreeMap::new(),results:BTreeSet::new()}),unknown:AtomicBool::new(false),
            handle:tokio::runtime::Handle::current()});
        owner.retain_terminal_parent(value.clone())?;value.require_live()?;Ok(value)
    }
    pub(super) fn accepted(receiver:Arc<wire::AcceptedTerminalReceiver>)->Result<Arc<Self>,String>{
        receiver.require_accepted()?;
        let owner=receiver.owner().clone();owner.require_terminal_retained()?;
        let value=Arc::new_cyclic(|this|Self{this:this.clone(),origin:Origin::Receiver(receiver.clone()),shared:receiver.shared().clone(),
            owner:owner.clone(),scope:owner.scope().clone(),node_job:receiver.node_job_uid().clone(),operation:receiver.operation_uid().clone(),
            started:receiver.started(),deadline:receiver.deadline(),native:Mutex::new(NativeState{current:None,identities:BTreeMap::new(),
                completed:BTreeSet::new(),pending:BTreeMap::new(),results:BTreeSet::new()}),unknown:AtomicBool::new(false),
            handle:tokio::runtime::Handle::current()});
        owner.retain_terminal_parent(value.clone())?;value.require_live()?;Ok(value)
    }
    pub(crate) fn scope(&self)->&ExpectedAttachScope{&self.scope}
    pub(crate) fn pool(&self)->&crate::storage_driver::Config{&self.shared.pool}
    pub(crate) fn actual_store(&self)->&Arc<RwLock<DesiredWorld>>{&self.shared.world}
    pub(crate) fn original_deadline(&self)->Instant{self.deadline}
    pub(crate) fn node_job_uid(&self)->&Uid{&self.node_job}
    pub(crate) fn terminal_operation_uid(&self)->&Uid{&self.operation}
    pub(crate) fn owner(&self)->&Arc<AttachOwner>{&self.owner}
    pub(super) fn runtime(&self)->&Arc<Shared>{&self.shared}
    pub(super) fn local_round(&self)->Option<&Arc<RegisteredDrainRound>>{match &self.origin{Origin::Local(round)=>Some(round),_=>None}}
    pub(super) fn receiver_session(&self)->Option<&Arc<wire::AcceptedTerminalReceiver>>{match &self.origin{Origin::Receiver(receiver)=>Some(receiver),_=>None}}
    pub(super) fn native_binding(&self,boundary:&VerifiedLocalBoundary,kind:TerminalBoundary,detail:&str)->Result<(TerminalNativeStep,String),String>{
        let step=self.require_native(boundary,kind,detail)?;
        let state=self.native.lock().map_err(|_|"terminal actual native binding poisoned")?;
        let identity=state.identities.get(&step).ok_or("terminal actual native identity absent")?;
        Ok((step,digest(&serde_json::to_vec(identity).map_err(|_|"actual terminal JobIdentity encode")?)))
    }
    pub(super) fn native_result_binding(&self,boundary:&VerifiedLocalBoundary)->Result<(TerminalNativeStep,String),String>{
        let state=self.native.lock().map_err(|_|"terminal actual outcome binding poisoned")?;
        let step=state.current.ok_or("terminal actual outcome step absent")?;
        let identity=state.identities.get(&step).ok_or("terminal actual outcome identity absent")?;
        boundary.require_native_identity(identity)?;
        Ok((step,digest(&serde_json::to_vec(identity).map_err(|_|"actual terminal outcome JobIdentity encode")?)))
    }
    pub(crate) fn require_live(&self)->Result<(),String>{
        if self.unknown.load(Ordering::Acquire)||Instant::now()<self.started||Instant::now()>=self.deadline
            ||!self.shared.controller_alive.load(Ordering::Acquire)||!core::is_actual_world(&self.shared.world){
            return Err("same original terminal node parent expired/UNKNOWN/dead; no reconstruction".into());}
        self.owner.require_terminal_parent(self)?;
        match &self.origin{Origin::Local(round)=>round.require_live(),Origin::Receiver(receiver)=>receiver.require_accepted()}
    }
    pub(crate) fn retain_unknown(&self){
        self.unknown.store(true,Ordering::Release);self.owner.mark_unknown();
        match &self.origin{Origin::Local(round)=>round.mark_unknown(),Origin::Receiver(receiver)=>receiver.retain_unknown()}
    }
    pub(crate) fn bind_native(&self,identity:&JobIdentity,step:TerminalNativeStep)->Result<(),String>{
        self.require_live()?;
        if identity.node_uid!=self.scope.phase_node_uid||identity.boot_id!=self.scope.phase_boot.as_str()
            ||identity.volume_uid!=self.scope.owner.volume_uid||identity.operation_uid!=self.operation{
            return Err("terminal native identity is not exact node/boot/volume/new operation".into());}
        let writer=self.scope.mount_ref.node_uid()==&self.scope.phase_node_uid;
        let mut state=self.native.lock().map_err(|_|"terminal native parent poisoned")?;
        let next=if writer&&!state.completed.contains(&TerminalNativeStep::UnmountAndDemote){TerminalNativeStep::UnmountAndDemote}
            else if !state.completed.contains(&TerminalNativeStep::ObserveSecondarySynchronized){TerminalNativeStep::ObserveSecondarySynchronized}
            else{TerminalNativeStep::OfflineAndObserve};
        if step!=next||state.identities.contains_key(&step)||!state.pending.is_empty()
            ||state.current.is_some_and(|prior|!state.completed.contains(&prior)){
            return Err("terminal native step skipped/replayed/another unresolved helper".into());}
        state.current=Some(step);state.identities.insert(step,identity.clone());Ok(())
    }
    fn require_native(&self,boundary:&VerifiedLocalBoundary,kind:TerminalBoundary,detail:&str)->Result<TerminalNativeStep,String>{
        self.require_live()?;
        if !is_hash(detail){return Err("terminal complete native RequestSHA malformed".into());}
        let state=self.native.lock().map_err(|_|"terminal native identity poisoned")?;
        let step=state.current.ok_or("terminal actual native identity not bound")?;
        boundary.require_native_identity(state.identities.get(&step).ok_or("terminal current native absent")?)?;
        let writer=self.scope.mount_ref.node_uid()==&self.scope.phase_node_uid;
        if kind==TerminalBoundary::RetireLease{
            if step!=TerminalNativeStep::OfflineAndObserve||!state.completed.contains(&step){return Err("lease retirement precedes actual final native drain".into());}
            drop(state);self.require_detached_confirmed()?;
        }else if state.completed.contains(&step)||!allowed(step,kind,writer){return Err("terminal boundary outside exact current step/role".into());}
        Ok(step)
    }
    pub(crate) fn approve(&self,boundary:&VerifiedLocalBoundary,kind:TerminalBoundary,detail:&str)->Result<(),String>{
        let mut retain=RetainFailedParent{parent:self,finished:false};
        self.require_native(boundary,kind,detail)?;
        if kind==TerminalBoundary::Complete && !self.native.lock().map_err(|_|"terminal completion state poisoned")?.pending.is_empty(){
            return Err("terminal Complete has an unresolved irreversible effect/result".into());}
        if tokio::runtime::Handle::try_current().is_ok(){return Err("terminal physical boundary must run on existing fixed worker, not Tokio handler".into());}
        let this=self.this.upgrade().ok_or("actual root parent disappeared")?;
        self.handle.block_on(wire::authorize_native(this,boundary,kind,detail))?;
        self.require_native(boundary,kind,detail)?;
        if irreversible(kind){
            let mut state=self.native.lock().map_err(|_|"terminal pending effect poisoned")?;
            if state.pending.len()>=512||state.results.contains(&(kind,detail.into()))
                ||state.pending.contains_key(&(kind,detail.into())){
                return Err("terminal irreversible effect already admitted/full; no retry".into());}
            state.pending.insert((kind,detail.into()),boundary.binding().into());
        }retain.finished=true;Ok(())
    }
    pub(crate) fn record_native_result(&self,boundary:&VerifiedLocalBoundary,kind:TerminalBoundary,
        detail:&str,result:&str)->Result<(),String>{
        let mut retain=RetainFailedParent{parent:self,finished:false};
        if !irreversible(kind)||!is_hash(detail)||!is_hash(result){return Err("terminal outcome is not a closed admitted irreversible effect".into());}
        // Actual outcome may be late. Verify original identity/pending mapping
        // without minting a new permission or requiring a now-expired grant.
        {let state=self.native.lock().map_err(|_|"terminal outcome state poisoned")?;
            let step=state.current.ok_or("terminal outcome has no original native")?;
            boundary.require_native_identity(state.identities.get(&step).ok_or("terminal actual native absent")?)?;
            if !state.pending.contains_key(&(kind,detail.into()))||state.results.contains(&(kind,detail.into())){
                return Err("terminal result before admission/replayed/changed native effect".into());}
        }
        if tokio::runtime::Handle::try_current().is_ok(){return Err("terminal result must be recorded on original fixed worker".into());}
        let this=self.this.upgrade().ok_or("root terminal parent absent")?;
        self.handle.block_on(wire::record_native_result(this,boundary,kind,detail,result))?;
        {let mut state=self.native.lock().map_err(|_|"terminal outcome state poisoned")?;
            state.pending.remove(&(kind,detail.into()));state.results.insert((kind,detail.into()));}
        if Instant::now()>=self.deadline{self.retain_unknown();return Err("terminal result durably observed after original deadline; not Complete".into());}retain.finished=true;Ok(())
    }
    pub(crate) fn complete(&self,drain:&VerifiedTerminalDrain,boundary:&VerifiedLocalBoundary)->Result<(),String>{
        let mut retain=RetainFailedParent{parent:self,finished:false};
        drain.require_parent(self)?;
        self.approve(boundary,TerminalBoundary::Complete,boundary.binding())?;
        let step=drain.step();
        {let mut state=self.native.lock().map_err(|_|"terminal final drain state poisoned")?;
            if state.current!=Some(step)||!state.pending.is_empty()||!state.completed.insert(step){return Err("terminal drain duplicate/partial/out of order".into());}}
        self.require_live()?;retain.finished=true;Ok(())
    }
    pub(crate) fn require_detached_confirmed(&self)->Result<(),String>{
        self.require_live()?;
        match &self.origin{Origin::Local(round)=>wire::require_local_detached_confirmed(round),
            Origin::Receiver(receiver)=>receiver.require_detached_confirmed()}
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn terminal_native_effect_matrix_cannot_activate_format_mount_or_skip_writer_role(){
        use TerminalBoundary::*;use TerminalNativeStep::*;
        assert!(allowed(UnmountAndDemote,Unmount,true));assert!(!allowed(UnmountAndDemote,Unmount,false));
        assert!(!allowed(ObserveSecondarySynchronized,Offline,true));assert!(allowed(OfflineAndObserve,Read,false));
        assert!(!allowed(OfflineAndObserve,Demote,true));assert!(!allowed(OfflineAndObserve,RetireLease,true));
    }
    #[test] fn irreversible_set_is_closed_and_nested_read_identity_program_remain_observations(){
        for kind in [TerminalBoundary::Identity,TerminalBoundary::Program,TerminalBoundary::Read,TerminalBoundary::Start]{assert!(!irreversible(kind));}
        for kind in [TerminalBoundary::CloseMounted,TerminalBoundary::Unmount,TerminalBoundary::CloseBlock,TerminalBoundary::Offline]{assert!(irreversible(kind));}
    }
}
