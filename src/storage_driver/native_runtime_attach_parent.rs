//! Genuine attach parent registration from one acknowledged actual-Core writer.
//! No raw World/deadline/session constructor; no cold/init authority fallback.
use super::*;
use crate::storage_pod_writer::CommittedPodWriterIntent;
use crate::storage_lifecycle::pod_attachment::{AttachPhase,ExpectedAttachScope,ATTACH_ROUND_MS};
use crate::storage_remote_protocol::attachment::{self as wire,AttachBoundary,Purpose};
use crate::storage_driver::dispatcher::VerifiedLocalBoundary;
use std::sync::atomic::{AtomicU8,AtomicBool,Ordering};
use std::collections::BTreeSet;

pub(crate) struct RegisteredAttachRound {
    shared:Arc<Shared>,book:Arc<MountBook>,intent:Arc<CommittedPodWriterIntent>,
    templates:BTreeMap<Uid,ExpectedAttachScope>,deadline:Instant,invalid:Arc<AtomicBool>,
}
impl RegisteredAttachRound {
    /// Only a consumed successful real metadata producer can register the
    /// expected plan. Templates are DATA checked against that CURRENT store.
    /// Original time is minted HERE before barriers, never accepted on wire.
    pub(crate) async fn register(shared:Arc<Shared>,intent:Arc<CommittedPodWriterIntent>,
        templates:Vec<ExpectedAttachScope>)->Result<Arc<Self>,String> {
        let started=Instant::now();
        if !shared.config.attaches(){return Err("attach registration requires explicit private v3 mode".into());}
        let deadline=started.checked_add(Duration::from_millis(ATTACH_ROUND_MS)).ok_or("attach original deadline overflow")?;
        if !core::is_actual_world(&shared.world) || templates.is_empty() || templates.len()>8 {
            return Err("attach registration requires bounded actual acknowledged writer".into());
        }
        let view=core::runtime_view(true).await?;
        let mut by_volume=BTreeMap::new();let mut round=None;
        {
            let world=shared.world.try_read().map_err(|_|"attach actual Core busy")?;
            if world.generation!=view.revision().desired_generation {return Err("attach Core changed during registration".into());}
            intent.check_metadata_current(&world)?;
            for mut scope in templates {
                scope.validate()?;
                if scope.phase!=AttachPhase::ActivateReplica || scope.issuer_node_uid!=*view.local()
                    || scope.issuer_boot!=*view.boot() || scope.mount_ref.node_uid()!=view.local()
                    || scope.mount_ref.node_boot()!=view.boot() || scope.pod_writer!=*intent.binding()
                    || scope.directory_sha256!=view.directory().sha256()?
                    || !view.revision().at_least(&scope.issuer_revision)
                    || intent.assignments().get(&scope.owner.volume_uid)!=world.storage_identities.lifecycle
                        .get(&scope.owner.volume_uid).and_then(|v|v.assignment())
                    || round.as_ref().is_some_and(|uid|uid!=&scope.round_uid) {
                    return Err("attach template differs from acknowledged actual local leader/writer".into());
                }
                scope.check_volume(world.storage_identities.lifecycle.get(&scope.owner.volume_uid).ok_or("attach volume absent")?)?;
                let volume=world.storage_identities.lifecycle.get(&scope.owner.volume_uid).ok_or("actual attach volume absent")?;
                let pv=world.pvs.get(&scope.owner.pv_name).ok_or("attach PV absent")?;
                let pvc=world.pvcs.get(&crate::store::obj_key(&scope.owner.namespace,&scope.owner.claim_name)).ok_or("actual attach PVC absent")?;
                let class=&pv.storage_class;
                if !shared.config.storage_class_allowlist.contains(class){return Err("attach class outside approved runtime allowlist".into());}
                scope.scope_sha256=digest(&serde_json::to_vec(&(volume,pv,pvc,world.storage_classes.get(class).ok_or("actual attach class absent")?)).map_err(|_|"actual attach scope hashing failed")?);
                scope.issuer_revision=view.revision().clone();
                round=Some(scope.round_uid.clone());
                if by_volume.insert(scope.owner.volume_uid.clone(),scope).is_some(){return Err("duplicate attach volume template".into());}
            }
            if by_volume.keys().ne(intent.assignments().keys()){return Err("partial managed Pod attach group refused".into());}
        }
        if Instant::now()>=deadline {return Err("attach registration consumed original deadline".into());}
        let book=MountBook::from_actual_runtime(&shared).await?;
        let registered=Arc::new(Self {shared,book:book.clone(),intent,templates:by_volume,
            deadline,invalid:book.invalid.clone()});
        {
            let mut state=book.state.lock().map_err(|_|"actual mount book poisoned")?;
            if state.unknown.is_some() || state.round.is_some(){return Err("actual attach round active/UNKNOWN; no replacement".into());}
            state.round=Some(registered.clone());
        }
        Ok(registered)
    }
    pub(crate) fn original_deadline(&self)->Instant {self.deadline}
    pub(crate) fn actual_store(&self)->&Arc<RwLock<DesiredWorld>> {&self.shared.world}
    pub(crate) fn require_live(&self)->Result<(),String> {
        if self.invalid.load(Ordering::Acquire)||Instant::now()>=self.deadline
            || !core::is_actual_world(&self.shared.world) {return Err("original attach round expired/UNKNOWN/store lost".into());}
        core::require_same_actual_epoch(&self.shared.world,&self.templates.values().next().ok_or("empty registered attach group")?.issuer_revision)
    }
    pub(crate) fn retain_unknown(&self){self.invalid.store(true,Ordering::Release);self.book.quarantine("attach round UNKNOWN");}
    /// Closed phase plan; a caller cannot change pool/replica/data identity.
    /// Advancement is admitted only after Core's actual completion producer.
    pub(crate) async fn register_phase(self:&Arc<Self>,volume:&Uid,phase:AttachPhase,target:&Uid)
        ->Result<Arc<ExpectedAttachJob>,String> {
        self.require_live()?;
        let template=self.templates.get(volume).ok_or("volume not in original acknowledged group")?;
        let observed=core::observe_local_async(volume).await?;
        if !observed.revision().at_least(&template.issuer_revision){return Err("attach round term/member/leader changed; no phase re-registration".into());}
        let directory=self.shared.directory_for(&observed)?;
        let mut scope=template.clone();scope.phase=phase;scope.phase_node_uid=target.clone();
        scope.phase_boot=scope.replicas.iter().find(|r|&r.node_uid==target).ok_or("phase target outside original replicas")?.current_boot.clone();
        scope.phase_job_uid=Uid::new();scope.issuer_revision=observed.revision().clone();
        scope.scope_sha256=observed.scope_sha256().into();
        scope.remaining_budget_ms=u64::try_from(self.deadline.saturating_duration_since(Instant::now()).as_millis()).map_err(|_|"attach remaining overflow")?;
        scope.check_issuer(&observed,&directory)?;
        {
            let world=self.shared.world.try_read().map_err(|_|"actual attach world busy")?;
            self.intent.check_metadata_current(&world)?;
        }
        self.require_live()?;
        let expected=Arc::new(ExpectedAttachJob {round:self.clone(),scope,session:Uid::new(),
            issuer:Mutex::new(None),admissions:Mutex::new(BTreeSet::new()),local_mounted:AtomicU8::new(0),completed:AtomicBool::new(false)});
        let mut state=self.book.state.lock().map_err(|_|"mount registration book poisoned")?;
        if state.unknown.is_some() || state.jobs.len()>=128 {return Err("attach expected-history bound/UNKNOWN".into());}
        // Sequential per-volume phase order is consumed from actual completion
        // receipts, never report JSON, caller phase or registration alone.
        let progress=state.progress.entry(volume.clone()).or_default();
        let step=phase_step(template,phase,target)?;
        if *progress!=step {return Err("attach phase skipped/repeated or prior completion not acknowledged".into());}
        if state.jobs.values().any(|e|!e.completed.load(Ordering::Acquire)) {
            return Err("previous actual attach phase still active/UNKNOWN".into());
        }
        state.jobs.insert(expected.scope.phase_job_uid.clone(),expected.clone());
        Ok(expected)
    }
}
fn phase_step(template:&ExpectedAttachScope,phase:AttachPhase,target:&Uid)->Result<usize,String>{
    let index=template.replicas.iter().position(|r|&r.node_uid==target).ok_or("phase target absent")?;
    Ok(match phase {AttachPhase::ActivateReplica=>index,AttachPhase::ObserveSynchronized=>3+index,
        AttachPhase::PromoteTarget if target==template.mount_ref.node_uid()=>6,
        AttachPhase::Mount if target==template.mount_ref.node_uid()=>7,
        AttachPhase::ObserveMounted if target==template.mount_ref.node_uid()=>8,
        _=>return Err("attach writer-only phase has another target".into())})
}
pub(crate) struct ExpectedAttachJob {
    round:Arc<RegisteredAttachRound>,scope:ExpectedAttachScope,session:Uid,
    pub(super) issuer:Mutex<Option<wire::Issuer>>,admissions:Mutex<BTreeSet<String>>,
    local_mounted:AtomicU8,
    // Set only by actual local completion or authenticated accepted remote
    // completion protocol. Neither registration nor grant sets this.
    completed:AtomicBool,
}
impl ExpectedAttachJob {
    pub(crate) fn scope(&self)->&ExpectedAttachScope {&self.scope}
    pub(crate) fn original_deadline(&self)->Instant{self.round.deadline}
    pub(crate) fn session_uid(&self)->&Uid{&self.session}
    pub(crate) fn invalidate_fast(&self){self.round.invalid.store(true,Ordering::Release);}
    pub(crate) fn require_live(&self)->Result<(),String>{self.round.require_live()}
    pub(crate) fn retain_unknown(&self){self.round.retain_unknown();}
    pub(crate) fn require_current(&self,view:&core::CoreObservation,directory:&VerifiedDirectory,purpose:Purpose)->Result<(),String>{
        self.require_live()?;
        if self.completed.load(Ordering::Acquire)&&!matches!(purpose,Purpose::MountedCommit|Purpose::MountedCommitConfirm){
            return Err("completed attach phase cannot authorize another physical action".into());
        }
        if purpose==Purpose::MountedCommitConfirm {wire::check_post_envelope(&self.scope,view,directory,true)?;}
        else {self.scope.check_issuer(view,directory)?;}
        let world=self.round.shared.world.try_read().map_err(|_|"actual attach world busy")?;
        if world.generation!=view.revision().desired_generation
            || world.storage_identities.lifecycle.get(&self.scope.owner.volume_uid)!=Some(view.volume()) {
            return Err("actual attach Core changed after THIS observation".into());
        }
        self.round.intent.check_metadata_current(&world)?;
        Ok(())
    }
    pub(crate) fn require_detail(&self,purpose:Purpose,detail:&str)->Result<(),String>{
        self.require_live()?;
        if purpose==Purpose::PhaseBoundary(AttachBoundary::InventoryRead){return Err("generic expected admission rejects new inventory domain".into());}
        if !valid_detail(detail) {return Err("invalid attach detail digest".into());}
        if matches!(purpose,Purpose::MountedCommit|Purpose::MountedCommitConfirm) {
            if self.scope.phase!=AttachPhase::ObserveMounted || !self.completed.load(Ordering::Acquire)
                || detail!=self.round.book.mounted_group_digest(self.round.intent.binding().uid())? {
                return Err("mounted permission lacks actual complete rooted group".into());
            }
        }
        Ok(())
    }
    pub(super) fn admit(&self,purpose:Purpose,detail:&str)->Result<String,String>{
        self.require_detail(purpose,detail)?;
        let transition=match purpose {Purpose::MountedCommit=>Some((0,1)),Purpose::MountedCommitConfirm=>Some((1,2)),_=>None};
        if let Some((from,to))=transition {
            self.local_mounted.compare_exchange(from,to,Ordering::AcqRel,Ordering::Acquire).map_err(|_|"mounted local purpose already spent/out of order")?;
        }
        let binding=digest(&serde_json::to_vec(&(self.scope.phase_job_uid.clone(),purpose,detail)).map_err(|_|"attach request binding failed")?);
        let mut seen=self.admissions.lock().map_err(|_|"attach admissions poisoned")?;
        if seen.len()>=512 || !seen.insert(binding.clone()) {return Err("attach admission replay/full; no retry".into());}
        Ok(binding)
    }
    /// Same original512 set; distinct producer bound to genuine context or
    /// authenticated exact receiver facts, never generic detail permission.
    pub(super) fn admit_owned_inventory(&self,binding:&str)->Result<(),String>{
        self.require_live()?;
        if !valid_detail(binding)||self.completed.load(Ordering::Acquire){return Err("owned inventory job completed/invalid".into());}
        let mut seen=self.admissions.lock().map_err(|_|"actual inventory admissions poisoned")?;
        if seen.len()>=512||!seen.insert(binding.into()){return Err("inventory replay/full within SAME512 admissions".into());}Ok(())
    }
    fn record_completion(&self,scope:&ExpectedAttachScope)->Result<(),String>{
        self.require_live()?;
        if scope!=&self.scope{return Err("actual completion differs from registered phase".into());}
        let mut state=self.round.book.state.lock().map_err(|_|"attach completion book poisoned")?;
        let template=self.round.templates.get(&scope.owner.volume_uid).ok_or("registered completion volume absent")?;
        let step=phase_step(template,scope.phase,&scope.phase_node_uid)?;
        if state.unknown.is_some()||state.progress.get(&scope.owner.volume_uid).copied().unwrap_or(0)!=step
            || self.completed.swap(true,Ordering::AcqRel){return Err("attach completion replay/order/UNKNOWN".into());}
        self.require_live()?;
        state.progress.insert(scope.owner.volume_uid.clone(),step+1);Ok(())
    }
}
fn valid_detail(value:&str)->bool{value.len()==64&&value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
enum Side {Local(Arc<ExpectedAttachJob>),Remote(Arc<Mutex<wire::Receiver>>)}
struct PendingReceiverOwner {book:Arc<MountBook>,finished:bool}
impl Drop for PendingReceiverOwner {fn drop(&mut self){if !self.finished {self.book.quarantine("attach receiver grant lost/failed; pending session retained");}}}
struct ParentRetainOnDrop {parent:Arc<VerifiedAttachParent>,finished:bool}
impl Drop for ParentRetainOnDrop {fn drop(&mut self){if !self.finished{self.parent.retain_unknown();}}}
struct RoundRetainOnDrop {round:Arc<RegisteredAttachRound>,finished:bool}
impl Drop for RoundRetainOnDrop {fn drop(&mut self){if !self.finished{self.round.retain_unknown();}}}
struct ExpectedRetainOnDrop {job:Arc<ExpectedAttachJob>,finished:bool}
impl Drop for ExpectedRetainOnDrop {fn drop(&mut self){if !self.finished{self.job.retain_unknown();}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq,serde::Serialize,serde::Deserialize)]
pub(crate) enum AttachNativeStep {Single,PublicationAnchor,FilesystemMount}
struct NativeState {current:Option<(crate::storage_driver::live_authority::JobIdentity,AttachNativeStep)>,anchor_drained:bool,finished:bool,
    inventory:Option<Arc<crate::storage_driver::dispatcher::attachment::inventory::RootedOwnedPoolInventory>>}
pub(crate) struct VerifiedAttachParent {
    shared:Arc<Shared>,book:Arc<MountBook>,scope:ExpectedAttachScope,deadline:Instant,
    side:Side,invalid:Arc<AtomicBool>,native:Mutex<NativeState>,
    receiver_clock:Option<Arc<Mutex<Instant>>>,
}
impl VerifiedAttachParent {
    /// Readonly completion provenance of the ACTUAL prior FS drain. Never
    /// renews its native permission or constructs a current inventory grant.
    pub(in crate::storage_driver) fn require_completed_inventory_origin(&self,
        drain:&crate::storage_driver::dispatcher::attachment::VerifiedAttachDrain)->Result<(),String>{
        self.require_live()?;drain.require_lineage_parent(self)?;
        let native=self.native.lock().map_err(|_|"actual inventory origin native state poisoned")?;
        if !native.finished||native.current.as_ref().is_none_or(|(identity,step)|identity!=drain.native_identity()
            ||*step!=AttachNativeStep::FilesystemMount)||self.scope.phase!=AttachPhase::Mount{
            return Err("provisional origin lacks actual acknowledged FS phase completion".into());}Ok(())
    }
    pub(in crate::storage_driver) fn bind_native(&self,identity:&crate::storage_driver::live_authority::JobIdentity,step:AttachNativeStep)->Result<(),String> {
        self.require_live()?;
        if identity.node_uid!=self.scope.phase_node_uid || identity.boot_id!=self.scope.phase_boot.as_str()
            || identity.volume_uid!=self.scope.owner.volume_uid || identity.operation_uid!=*self.scope.mount_ref.operation_uid()
            || step==AttachNativeStep::Single && identity.attempt_uid!=self.scope.phase_job_uid {
            return Err("attach parent native attempt/owner/boot differs".into());
        }
        let mut native=self.native.lock().map_err(|_|"attach native binding poisoned")?;
        if native.inventory.as_ref().is_some_and(|c|!c.is_retired()){
            return Err("previous profile7 FD context lacks actual drain retirement".into());}
        if native.finished || match (self.scope.phase,step,&native.current,native.anchor_drained) {
            (AttachPhase::Mount,AttachNativeStep::PublicationAnchor,None,false)=>false,
            (AttachPhase::Mount,AttachNativeStep::FilesystemMount,Some((prior,AttachNativeStep::PublicationAnchor)),true)
                if prior.attempt_uid!=identity.attempt_uid=>false,
            (phase,AttachNativeStep::Single,None,false) if phase!=AttachPhase::Mount=>false,
            _=>true,
        } {return Err("attach native substep skipped/repeated/retried".into());}
        native.current=Some((identity.clone(),step));native.inventory=None;Ok(())
    }
    pub(in crate::storage_driver) fn bind_owned_inventory_native(&self,identity:&crate::storage_driver::live_authority::JobIdentity,
        step:AttachNativeStep,context:Arc<crate::storage_driver::dispatcher::attachment::inventory::RootedOwnedPoolInventory>)->Result<(),String>{
        context.require_native(identity)?;
        if !std::ptr::eq(Arc::as_ptr(context.parent()),self)||context.step()!=step{return Err("not SAME actual profile7 parent/substep".into());}
        self.bind_native(identity,step)?;
        let mut native=self.native.lock().map_err(|_|"actual profile7 native binding poisoned")?;
        if native.current.as_ref().is_none_or(|(i,s)|i!=identity||*s!=step)||native.inventory.is_some(){return Err("actual profile7 bind changed".into());}
        native.inventory=Some(context);Ok(())
    }
    fn require_owned_inventory_native(&self,context:&Arc<crate::storage_driver::dispatcher::attachment::inventory::RootedOwnedPoolInventory>,
        boundary:&VerifiedLocalBoundary)->Result<(),String>{
        self.require_live()?;
        {let native=self.native.lock().map_err(|_|"actual profile7 parent poisoned")?;
            let(identity,step)=native.current.as_ref().ok_or("actual profile7 native absent")?;
            boundary.require_native_identity(identity)?;
            if native.finished||*step!=context.step()||native.inventory.as_ref().is_none_or(|c|!Arc::ptr_eq(c,context)){
                return Err("inventory request not current genuine profile7 native bind".into());}}
        context.require_boundary(boundary)
    }
    pub(in crate::storage_driver) fn approve_owned_inventory(&self,context:Arc<crate::storage_driver::dispatcher::attachment::inventory::RootedOwnedPoolInventory>,
        boundary:&VerifiedLocalBoundary,detail:&str)->Result<(),String>{
        let result=(||{
            self.require_owned_inventory_native(&context,boundary)?;
            if !valid_detail(detail){return Err("invalid inventory actual request detail".into());}
            let rt=crate::raft_node::RAFT.get().ok_or("actual inventory Raft absent")?.rt.clone();
            // No probe/book/resource/session/native guards across this wait.
            rt.block_on(self.fresh_owned_inventory(context.clone(),boundary,detail))?;
            self.require_owned_inventory_native(&context,boundary)
        })();if result.is_err(){context.retain_unknown();}result
    }
    async fn fresh_owned_inventory(&self,context:Arc<crate::storage_driver::dispatcher::attachment::inventory::RootedOwnedPoolInventory>,
        boundary:&VerifiedLocalBoundary,detail:&str)->Result<(),String>{
        self.require_owned_inventory_native(&context,boundary)?;
        let purpose=Purpose::PhaseBoundary(AttachBoundary::InventoryRead);
        match &self.side{
            Side::Local(expected)=>{
                let binding=digest(&serde_json::to_vec(&("actual-owned-inventory-v7",expected.scope(),context.uid(),context.native_data()?,
                    context.step(),context.commitment()?,boundary.binding(),detail)).map_err(|_|"actual inventory admission binding")?);
                expected.admit_owned_inventory(&binding)?;
                durable_admit(&self.shared,expected.clone(),purpose,&binding).await?;
                let view=core::observe_native_issuer(&self.scope.owner.volume_uid,boundary).await?;
                let directory=self.shared.directory_for(&view)?;
                expected.require_current(&view,&directory,purpose)?;view.require_fresh_native(boundary,Instant::now())?;
                self.require_owned_inventory_native(&context,boundary)
            },
            Side::Remote(session)=>{
                let before=core::observe_local_async(&self.scope.owner.volume_uid).await?;
                let directory=self.shared.directory_for(&before)?;
                self.scope.check_receiver(&before,&directory)?;super::check_actual_current(&self.shared,&before,&self.scope)?;
                self.require_owned_inventory_native(&context,boundary)?;
                let request={session.lock().map_err(|_|"actual inventory session poisoned")?.owned_inventory_request(context.clone(),boundary,detail)?};
                let reply=self.shared.call(wire::PATH,&request,&self.scope.issuer_node_uid,&directory).await?;
                let(minimum,deadline)={session.lock().map_err(|_|"inventory pending poisoned")?.owned_inventory_hint(&reply)?};
                core::wait_applied_hint(&minimum,deadline.min(self.original_deadline())).await?;
                let after=core::observe_local_async(&self.scope.owner.volume_uid).await?;
                let directory=self.shared.directory_for(&after)?;super::check_actual_current(&self.shared,&after,&self.scope)?;
                let permission={session.lock().map_err(|_|"inventory accept poisoned")?.accept_owned_inventory(reply,&after,&directory)?};
                self.require_owned_inventory_native(&context,boundary)?;permission.consume(detail)
            },
        }
    }
    pub(crate) fn scope(&self)->&ExpectedAttachScope{&self.scope}
    pub(crate) fn original_deadline(&self)->Instant{
        self.receiver_clock.as_ref().map_or(self.deadline,|clock|self.deadline.min(*clock.lock().unwrap_or_else(|p|p.into_inner())))
    }
    pub(crate) fn actual_store(&self)->&Arc<RwLock<DesiredWorld>>{&self.shared.world}
    pub(crate) fn pool(&self)->&crate::storage_driver::Config{&self.shared.pool}
    pub(crate) fn root_book(&self)->&Arc<MountBook>{&self.book}
    pub(crate) fn require_live(&self)->Result<(),String>{
        if self.receiver_clock.as_ref().is_some_and(|clock|clock.is_poisoned())
            || !core::is_actual_world(&self.shared.world)||Instant::now()>=self.original_deadline()||self.invalid.load(Ordering::Acquire){
            return Err("actual attach parent expired/UNKNOWN".into());
        }
        if let Side::Local(expected)=&self.side {expected.require_live()?;}
        core::require_same_actual_epoch(&self.shared.world,&self.scope.issuer_revision)
    }
    pub(crate) async fn local(expected:Arc<ExpectedAttachJob>)->Result<Arc<Self>,String>{
        expected.require_live()?;
        let parent=Arc::new(Self {shared:expected.round.shared.clone(),book:expected.round.book.clone(),
            scope:expected.scope.clone(),deadline:expected.round.deadline,invalid:expected.round.invalid.clone(),side:Side::Local(expected),native:Mutex::new(NativeState{current:None,anchor_drained:false,finished:false,inventory:None}),receiver_clock:None});
        parent.root_before_use()?;Ok(parent)
    }
    /// A transport frame is necessary but not a grant. This challenges actual
    /// issuer registration, waits actual applied state and accepts exact reply.
    pub(crate) async fn receiver(shared:Arc<Shared>,offer:VerifiedPeerFrame,request_deadline:Instant)->Result<Arc<Self>,String>{
        let scope=match wire::decode_node::<wire::NodeRequest>(offer.body())? {
            wire::NodeRequest::Offer{scope,..}=>scope,
            _=>return Err("receiver parent requires actual authenticated offer".into()),
        };
        if offer.sender()!=&scope.issuer_node_uid || offer.receiver()!=&scope.phase_node_uid {return Err("attach offer authenticated identity differs".into());}
        scope.validate()?;
        // Once-only Offer is not retried. Synchronize only the actual local
        // applied log before challenge, inside the original socket budget.
        core::wait_applied_hint(&scope.issuer_revision,request_deadline.min(Instant::now()+Duration::from_millis(core::MAX_STORAGE_BOUNDARY_MS))).await?;
        let before=core::observe_local_async(&scope.owner.volume_uid).await?;
        let directory=shared.directory_for(&before)?;
        super::check_actual_current(&shared,&before,&scope)?;
        let (mut session,request)=wire::Receiver::challenge(scope.clone(),&before,&directory)?;
        let book=MountBook::from_actual_runtime(&shared).await?;
        {
            let state=book.state.lock().map_err(|_|"receiver original-round clock book poisoned")?;
            if let Some(clock)=state.receiver_clocks.get(&scope.round_uid){
                session.shorten_original_to(*clock.lock().map_err(|_|"receiver original clock poisoned")?)?;
            }else if state.owners.contains_key(&scope.owner.volume_uid){
                return Err("existing receiver owner has no retained original clock; quarantine rather than renew".into());
            }
        }
        let session=Arc::new(Mutex::new(session));
        {
            let mut state=book.state.lock().map_err(|_|"pending receiver book poisoned")?;
            if state.unknown.is_some() || state.pending_receivers.len()>=128 || state.pending_receivers.contains_key(&scope.phase_job_uid){
                return Err("pending receiver duplicate/full/UNKNOWN; no grant retry".into());
            }
            state.pending_receivers.insert(scope.phase_job_uid.clone(),session.clone());
        }
        // Root the SAME unaccepted session BEFORE requesting a real grant.
        let mut retain=PendingReceiverOwner {book:book.clone(),finished:false};
        let reply=shared.call(wire::PATH,&request,&scope.issuer_node_uid,&directory).await?;
        let (minimum,deadline)={session.lock().map_err(|_|"pending receiver poisoned")?.reply_hint(&reply)?};
        core::wait_applied_hint(&minimum,deadline.min(request_deadline)).await?;
        let after=core::observe_local_async(&scope.owner.volume_uid).await?;
        let directory=shared.directory_for(&after)?;
        super::check_actual_current(&shared,&after,&scope)?;
        {session.lock().map_err(|_|"pending receiver poisoned")?.accept(reply,&after,&directory)?.consume(Purpose::PhaseGrant,&protocol::hash(b"attach-grant"))?;}
        let deadline={session.lock().map_err(|_|"pending receiver poisoned")?.deadline()?};
        let clock={
            let mut state=book.state.lock().map_err(|_|"receiver original clock book poisoned")?;
            if state.receiver_clocks.len()>=128 && !state.receiver_clocks.contains_key(&scope.round_uid){return Err("receiver original clock history full".into());}
            let clock=state.receiver_clocks.entry(scope.round_uid.clone()).or_insert_with(||Arc::new(Mutex::new(deadline))).clone();
            {let mut original=clock.lock().map_err(|_|"receiver original round clock poisoned")?;*original=(*original).min(deadline);}
            clock
        };
        {session.lock().map_err(|_|"receiver clipping poisoned")?.shorten_original_to(*clock.lock().map_err(|_|"receiver clock poisoned")?)?;}
        let invalid=book.invalid.clone();
        let parent=Arc::new(Self {shared,book,scope,deadline,side:Side::Remote(session),invalid,native:Mutex::new(NativeState{current:None,anchor_drained:false,finished:false,inventory:None}),receiver_clock:Some(clock)});
        parent.root_before_use()?;
        if let Side::Remote(session)=&parent.side {session.lock().map_err(|_|"receiver parent link poisoned")?.bind_actual_parent(&parent)?;}
        retain.finished=true;Ok(parent)
    }
    fn root_before_use(self:&Arc<Self>)->Result<(),String>{
        self.require_live()?;
        let mut state=self.book.state.lock().map_err(|_|"actual parent book poisoned")?;
        if state.unknown.is_some() || state.parents.len()>=128 || state.parents.contains_key(&self.scope.phase_job_uid){
            return Err("attach parent duplicate/full/UNKNOWN; no replacement".into());
        }
        state.parents.insert(self.scope.phase_job_uid.clone(),self.clone());Ok(())
    }
    pub(crate) fn retain_unknown(&self){
        self.invalid.store(true,Ordering::Release);self.book.quarantine("actual attach parent UNKNOWN");
        if let Side::Remote(session)=&self.side {session.lock().unwrap_or_else(|p|p.into_inner()).revoke();}
    }
    pub(crate) fn invalidate_fast(&self){self.invalid.store(true,Ordering::Release);}
    pub(crate) fn approve(&self,boundary:&VerifiedLocalBoundary,kind:AttachBoundary,detail:&str)->Result<(),String>{
        self.require_live()?;
        let inventory={
            let native=self.native.lock().map_err(|_|"attach native identity poisoned")?;
            let (identity,step)=native.current.as_ref().ok_or("attach parent has no actual inherited native attempt")?;
            boundary.require_native_identity(identity)?;
            if matches!(kind,AttachBoundary::AnchorBind|AttachBoundary::AnchorPrivate)&&*step!=AttachNativeStep::PublicationAnchor
                || matches!(kind,AttachBoundary::MountExt4|AttachBoundary::MakePrivate)&&*step!=AttachNativeStep::FilesystemMount {
                return Err("attach boundary has wrong exact native substep".into());
            }
            native.inventory.clone()
        };
        if let Some(context)=&inventory{
            if context.is_retired(){if !matches!(kind,AttachBoundary::Identity|AttachBoundary::Complete){
                return Err("drained profile7 native cannot authorize another helper effect/read/program".into());}}
            else{context.require_current()?;}
        }
        if !kind.allowed(self.scope.phase)||!valid_detail(detail){return Err("attach boundary not allowed by exact phase".into());}
        let exact=digest(&serde_json::to_vec(&(boundary.binding(),detail,kind)).map_err(|_|"attach boundary binding failed")?);
        let rt=crate::raft_node::RAFT.get().ok_or("actual attach Raft absent")?.rt.clone();
        let result=rt.block_on(self.fresh(Purpose::PhaseBoundary(kind),&exact,true)).and_then(|()|{
            if let Some(context)=&inventory{if !context.is_retired(){context.require_current()?;}}Ok(())
        });
        if result.is_err(){self.retain_unknown();}result
    }
    pub(in crate::storage_driver) fn complete(&self,drain:&crate::storage_driver::dispatcher::attachment::VerifiedAttachDrain,
        boundary:&VerifiedLocalBoundary)->Result<(),String> {
        let result=(|| {
            self.require_live()?;drain.require_parent(self)?;
            self.approve(boundary,AttachBoundary::Complete,drain.completion_sha256())?;
            let step=drain.step();
            {
                let native=self.native.lock().map_err(|_|"attach completion native state poisoned")?;
                if native.finished || native.current.as_ref().map(|(_,s)|*s)!=Some(step){return Err("actual drain has another native substep".into());}
            }
            if step==AttachNativeStep::PublicationAnchor {
                let mut native=self.native.lock().map_err(|_|"attach anchor completion poisoned")?;
                self.require_live()?;
                if native.anchor_drained{return Err("anchor completion repeated".into());}
                native.anchor_drained=true;
                // Actual drained intermediate anchor, NO fabricated mount or
                // phase completion, no phase advance/no release/retry.
                return Ok(());
            }
            drain.observation()?.validate(&self.scope)?;
            let rt=crate::raft_node::RAFT.get().ok_or("actual attach Raft absent")?.rt.clone();
            rt.block_on(async {
                match &self.side {
                    Side::Local(expected)=>expected.record_completion(&self.scope),
                    Side::Remote(session)=>{
                        let before=core::observe_local_async(&self.scope.owner.volume_uid).await?;
                        let directory=self.shared.directory_for(&before)?;
                        super::check_actual_current(&self.shared,&before,&self.scope)?;
                        let request={session.lock().map_err(|_|"attach report session poisoned")?.report_after_drain(drain)?};
                        let reply=self.shared.call(wire::PATH,&request,&self.scope.issuer_node_uid,&directory).await?;
                        let (minimum,deadline)={session.lock().map_err(|_|"attach report session poisoned")?.reply_hint(&reply)?};
                        core::wait_applied_hint(&minimum,deadline.min(self.original_deadline())).await?;
                        let after=core::observe_local_async(&self.scope.owner.volume_uid).await?;
                        let directory=self.shared.directory_for(&after)?;
                        super::check_actual_current(&self.shared,&after,&self.scope)?;
                        let token={session.lock().map_err(|_|"attach report session poisoned")?.accept(reply,&after,&directory)?};
                        // Report is a fact under the actual session, never a
                        // conversion into this node's mount FD/receipt.
                        token.consume_report()?;self.require_live()
                    }
                }
            })?;
            let mut native=self.native.lock().map_err(|_|"attach final native state poisoned")?;
            self.require_live()?;native.finished=true;Ok(())
        })();
        if result.is_err(){self.retain_unknown();}result
    }
    async fn fresh(&self,purpose:Purpose,detail:&str,require_owner:bool)->Result<(),String>{
        self.require_live()?;
        if require_owner {self.book.root_for(&self.scope.owner.volume_uid)?.require_registered_parent(self)?;}
        match &self.side {
            Side::Local(expected)=>{
                let binding=expected.admit(purpose,detail)?;
                durable_admit(&self.shared,expected.clone(),purpose,&binding).await?;
                let request=wire::local_request(expected,purpose,detail)?;
                let observed=core::observe_attach_issuer(&self.scope.owner.volume_uid,&request).await?;
                let directory=self.shared.directory_for(&observed)?;
                let permission=wire::local_permission(expected,request,&observed,&directory)?;
                self.require_live()?;
                if require_owner {self.book.root_for(&self.scope.owner.volume_uid)?.require_registered_parent(self)?;}
                permission.consume(purpose,detail)
            }
            Side::Remote(session)=>{
                let before=core::observe_local_async(&self.scope.owner.volume_uid).await?;
                let directory=self.shared.directory_for(&before)?;
                self.scope.check_receiver(&before,&directory)?;
                super::check_actual_current(&self.shared,&before,&self.scope)?;
                let request={session.lock().map_err(|_|"attach receiver poisoned")?.request(purpose,detail)?};
                let reply=self.shared.call(purpose.path(),&request,&self.scope.issuer_node_uid,&directory).await?;
                let (minimum,deadline)={session.lock().map_err(|_|"attach receiver poisoned")?.reply_hint(&reply)?};
                core::wait_applied_hint(&minimum,deadline.min(self.original_deadline())).await?;
                let after=core::observe_local_async(&self.scope.owner.volume_uid).await?;
                let directory=self.shared.directory_for(&after)?;
                super::check_actual_current(&self.shared,&after,&self.scope)?;
                let permission={session.lock().map_err(|_|"attach receiver poisoned")?.accept(reply,&after,&directory)?};
                self.require_live()?;
                if require_owner {self.book.root_for(&self.scope.owner.volume_uid)?.require_registered_parent(self)?;}
                permission.consume(purpose,detail)
            }
        }
    }
}
async fn durable_admit(shared:&Arc<Shared>,expected:Arc<ExpectedAttachJob>,purpose:Purpose,binding:&str)->Result<(),String>{
    let journal=shared.journal.clone();let binding=binding.to_string();
    shared.io.run(move||journal.attach_admission(&expected,purpose,&binding)).await
}
async fn authorize_owned_inventory(shared:&Arc<Shared>,path:&str,peer:VerifiedPeerFrame)->Result<Vec<u8>,String>{
    if path!=wire::PATH{return Err("owned inventory domain reached another route".into());}
    let request=wire::owned_inventory::InventoryRequest::decode(peer.body())?;
    let book=ROOTED_BOOK.get().ok_or("actual inventory registration book absent")?.clone();
    if !Arc::ptr_eq(book.world(),&shared.world){return Err("inventory request reached another actual world".into());}
    let expected={book.state.lock().map_err(|_|"actual inventory expected book poisoned")?.jobs
        .get(&request.scope.phase_job_uid).cloned().ok_or("no actual expected inventory phase")?};
    let mut retain=ExpectedRetainOnDrop{job:expected.clone(),finished:false};
    if request.scope!=*expected.scope()||peer.sender()!=&expected.scope.phase_node_uid||peer.receiver()!=&expected.scope.issuer_node_uid{
        return Err("inventory authenticated receiver/job/scope differs".into());}
    let binding=digest(peer.body());expected.admit_owned_inventory(&binding)?;
    let purpose=Purpose::PhaseBoundary(AttachBoundary::InventoryRead);
    durable_admit(shared,expected.clone(),purpose,&binding).await?;
    let observed=core::observe_issuer(&expected.scope.owner.volume_uid,peer.read_challenge()).await?;
    let directory=shared.directory_for(&observed)?;expected.require_current(&observed,&directory,purpose)?;
    let result={let mut issuer=expected.issuer.lock().map_err(|_|"inventory issuer poisoned")?;
        issuer.as_mut().ok_or("inventory requires SAME already accepted attach session")?.authorize_owned_inventory(peer,&observed,&directory)};
    if result.is_ok(){retain.finished=true;}result
}
pub(in crate::storage_driver::native_runtime) async fn authorize(shared:&Arc<Shared>,path:&str,peer:VerifiedPeerFrame)->Result<Vec<u8>,String>{
    if wire::owned_inventory::is_domain(peer.body())?{
        return authorize_owned_inventory(shared,path,peer).await;
    }
    let request=wire::Request::decode(peer.body())?;
    if path!=request.path(){return Err("attach request purpose reached wrong closed route".into());}
    let book=ROOTED_BOOK.get().ok_or("actual registered parent book absent")?.clone();
    if !Arc::ptr_eq(book.world(),&shared.world){return Err("attach request reached another actual store".into());}
    let expected={book.state.lock().map_err(|_|"attach expected book poisoned")?.jobs
        .get(&request.scope.phase_job_uid).cloned().ok_or("no actual registered parent expected job")?};
    let mut retain=ExpectedRetainOnDrop {job:expected.clone(),finished:false};
    // The expected scope comes from consumed actual metadata + parent, NEVER
    // from request.scope. Exact full equality is rechecked inside issuer.
    if request.scope!=*expected.scope() || peer.sender()!=&expected.scope.phase_node_uid || peer.receiver()!=&expected.scope.issuer_node_uid {
        return Err("attach request differs from exact registered parent/signer".into());
    }
    expected.require_detail(request.purpose,request.detail())?;
    let binding=request.hash()?;
    {
        let mut seen=expected.admissions.lock().map_err(|_|"attach admissions poisoned")?;
        if seen.len()>=512 || !seen.insert(binding.clone()){return Err("attach RPC replay/full; retained".into());}
    }
    durable_admit(shared,expected.clone(),request.purpose,&binding).await?;
    let observed=core::observe_issuer(&expected.scope.owner.volume_uid,peer.read_challenge()).await?;
    let directory=shared.directory_for(&observed)?;
    expected.require_current(&observed,&directory,request.purpose)?;
    let mut issuer=expected.issuer.lock().map_err(|_|"attach issuer poisoned")?;
    if issuer.is_none(){*issuer=Some(wire::Issuer::new(expected.clone()));}
    let result=issuer.as_mut().unwrap().authorize(peer,&observed,&directory);
    drop(issuer);
    match result {
        Ok(reply)=>{
            if let Some(completion)=reply.completion {
                if completion.job()!=&expected.scope.phase_job_uid {expected.retain_unknown();return Err("authenticated completion job differs".into());}
                completion.observation().validate(expected.scope())?;
                if let Err(error)=expected.record_completion(expected.scope()){expected.retain_unknown();return Err(error);}
            }
            retain.finished=true;Ok(reply.bytes)
        }
        Err(error)=>{expected.retain_unknown();Err(error)}
    }
}

fn attach_error(error:crate::storage_driver::dispatcher::attachment::RetainedAttachError)->String{
    use crate::storage_driver::dispatcher::attachment::RetainedAttachError::*;
    match error {Unavailable(e)=>format!("attach unavailable: {e}"),NeverSubmitted(e)=>format!("attach proven not enqueued: {e}"),Unknown(e)=>format!("attach UNKNOWN: {e}")}
}
pub(super) struct RootedTicket {ticket:crate::storage_driver::dispatcher::attachment::AttachTicket,
    result:Option<Result<crate::storage_lifecycle::pod_attachment::AttachPhaseObservation,String>>}
async fn enqueue(parent:Arc<VerifiedAttachParent>)->Result<(),String>{
    let mut retain=ParentRetainOnDrop {parent:parent.clone(),finished:false};
    parent.require_live()?;let shared=parent.shared.clone();let work_shared=shared.clone();let book=parent.book.clone();
    let retained=parent.clone();
    let result=shared.io.run(move||{
        retained.require_live()?;
        let existing={let state=book.state.lock().map_err(|_|"attach owner book poisoned")?;
            if state.unknown.is_some(){return Err("attach book UNKNOWN; no enqueue".into());}
            state.owners.get(&retained.scope.owner.volume_uid).cloned()};
        let owner=match existing {
            Some(owner)=>owner,
            None if retained.scope.phase==AttachPhase::ActivateReplica=>work_shared.dispatcher.begin_managed_attachment(retained.clone()).map_err(attach_error)?,
            None=>return Err("later attach phase has no exact retained local owner; no reconstruction".into()),
        };
        let ticket=work_shared.dispatcher.submit_attach_phase(owner,retained.clone()).map_err(attach_error)?;
        let mut state=book.state.lock().map_err(|_|"attach ticket root poisoned")?;
        if state.tickets.len()>=128 || state.tickets.contains_key(&retained.scope.phase_job_uid){return Err("attach ticket root duplicate/full; worker/owner retained".into());}
        state.tickets.insert(retained.scope.phase_job_uid.clone(),Arc::new(Mutex::new(RootedTicket {ticket,result:None})));
        Ok(())
    }).await;
    if result.is_err(){parent.retain_unknown();}retain.finished=result.is_ok();result
}
fn inspect_ticket(book:&Arc<MountBook>,job:&Uid)->Result<Option<crate::storage_lifecycle::pod_attachment::AttachPhaseObservation>,String>{
    let result=inspect_ticket_inner(book,job);
    if result.is_err(){book.quarantine("actual attach ticket missing/poisoned/UNKNOWN");}result
}
fn inspect_ticket_inner(book:&Arc<MountBook>,job:&Uid)->Result<Option<crate::storage_lifecycle::pod_attachment::AttachPhaseObservation>,String>{
    let ticket={
        let state=book.state.lock().map_err(|_|"attach ticket book poisoned")?;
        if state.unknown.is_some(){return Err("actual attach runtime UNKNOWN".into());}
        state.tickets.get(job).cloned().ok_or("exact original attach ticket missing")?
    };
    let observed={
        let mut actual=ticket.lock().map_err(|_|"original attach ticket poisoned")?;
        if let Some(result)=&actual.result{return result.clone().map(Some);}
        match actual.ticket.try_result() {
            Ok(Some(observation))=>{actual.result=Some(Ok(observation.clone()));Ok(Some(observation))}
            Ok(None)=>Ok(None),
            Err(error)=>{actual.result=Some(Err(error.clone()));Err(error)}
        }
    };
    if observed.is_err(){book.quarantine("actual original attach ticket failed/UNKNOWN");}observed
}
pub(in crate::storage_driver::native_runtime) async fn node_request(shared:&Arc<Shared>,peer:VerifiedPeerFrame,request_deadline:Instant)->Result<Vec<u8>,String>{
    let request:wire::NodeRequest=wire::decode_node(peer.body())?;
    let reply=match request {
        wire::NodeRequest::Offer{scope,nonce}=>{
            if peer.sender()!=&scope.issuer_node_uid || peer.receiver()!=&scope.phase_node_uid {return Err("attach offer peer differs".into());}
            let parent=VerifiedAttachParent::receiver(shared.clone(),peer,request_deadline).await?;
            let job=parent.scope.phase_job_uid.clone();
            enqueue(parent).await?;
            wire::NodeReply::Queued {job,nonce}
        }
        wire::NodeRequest::Inspect{job,nonce}=>{
            let book=ROOTED_BOOK.get().ok_or("actual attach book absent")?.clone();
            if !Arc::ptr_eq(book.world(),&shared.world){return Err("attach inspect reached another actual runtime".into());}
            let parent={book.state.lock().map_err(|_|"attach parent lookup poisoned")?.parents.get(&job).cloned().ok_or("exact attach parent absent")?};
            parent.require_live()?;
            if peer.sender()!=&parent.scope.issuer_node_uid || peer.receiver()!=&parent.scope.phase_node_uid{return Err("attach inspection peer differs".into());}
            match inspect_ticket(&book,&job)? {Some(observation)=>wire::NodeReply::Completed{job,nonce,observation},
                None=>wire::NodeReply::InFlight{job,nonce}}
        }
        wire::NodeRequest::Readiness{volume,nonce}=>{
            let observed=core::observe_local_async(&volume).await?;
            let directory=shared.directory_for(&observed)?;
            if peer.receiver()!=&shared.pool.node_uid || directory.pin(peer.sender())?.raft_id!=observed.revision().leader_raft_id {
                return Err("attach readiness is restricted to actual current registered leader".into());
            }
            if Instant::now()>=request_deadline{return Err("attach readiness original request expired".into());}
            let observation=super::normal::readiness(shared,&volume).await?;
            if Instant::now()>=request_deadline{return Err("attach readiness completed after original request deadline".into());}
            wire::NodeReply::Readiness {nonce,observation}
        }
    };
    wire::encode_node(&reply)
}
impl RegisteredAttachRound {
    /// Runs on the existing normal controller actor, never a request-created
    /// thread/task. One job at a time; same original deadline covers all.
    pub(crate) async fn run_registered(self:&Arc<Self>)->Result<crate::storage_lifecycle::pod_attachment::CommittedAttachment,String>{
        let mut retain=RoundRetainOnDrop {round:self.clone(),finished:false};
        let result=self.run_inner().await;
        if result.is_err(){self.retain_unknown();}retain.finished=result.is_ok();result
    }
    async fn run_inner(self:&Arc<Self>)->Result<crate::storage_lifecycle::pod_attachment::CommittedAttachment,String>{
        for (uid,template) in &self.templates {
            for phase in [AttachPhase::ActivateReplica,AttachPhase::ObserveSynchronized,AttachPhase::PromoteTarget,AttachPhase::Mount,AttachPhase::ObserveMounted] {
                let targets=if phase.writer_only(){vec![template.mount_ref.node_uid().clone()]}
                    else {template.replicas.iter().map(|r|r.node_uid.clone()).collect()};
                for target in targets {
                    let expected=self.register_phase(uid,phase,&target).await?;
                    self.run_phase(expected).await?;
                }
            }
        }
        self.require_live()?;
        let expected=self.templates.iter().map(|(uid,scope)|(uid.clone(),scope.mount_ref.clone())).collect();
        let round=self.book.mounted_round(self.intent.binding().uid(),&expected)?;
        crate::storage_lifecycle::pod_attachment::commit_pod_attached(&self.shared.world,&round).await.map_err(|e|format!("mounted commit retained: {e:?}"))
    }
    async fn run_phase(self:&Arc<Self>,expected:Arc<ExpectedAttachJob>)->Result<(),String>{
        self.require_live()?;
        if expected.scope.phase_node_uid==expected.scope.issuer_node_uid {
            let parent=VerifiedAttachParent::local(expected.clone()).await?;
            enqueue(parent).await?;
            loop {
                self.require_live()?;
                if let Some(observation)=inspect_ticket(&self.book,&expected.scope.phase_job_uid)? {
                    observation.validate(expected.scope())?;
                    if !expected.completed.load(Ordering::Acquire){return Err("actual ticket completed without same registered parent completion".into());}
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }else{
            let observed=core::observe_local_async(&expected.scope.owner.volume_uid).await?;
            let directory=self.shared.directory_for(&observed)?;
            let nonce=Uid::new();
            let offer=wire::encode_node(&wire::NodeRequest::Offer{scope:expected.scope.clone(),nonce:nonce.clone()})?;
            let reply=self.shared.call(wire::OFFER_PATH,&offer,&expected.scope.phase_node_uid,&directory).await?;
            if reply.sender()!=&expected.scope.phase_node_uid || reply.receiver()!=&expected.scope.issuer_node_uid{return Err("attach offer response signer/receiver differs".into());}
            match wire::decode_node::<wire::NodeReply>(reply.body())? {
                wire::NodeReply::Queued{job,nonce:reply_nonce} if job==expected.scope.phase_job_uid&&reply_nonce==nonce=>(),
                _=>return Err("attach offer lost/ambiguous/wrong exact acknowledgement".into()),
            }
            loop {
                self.require_live()?;
                let nonce=Uid::new();
                let query=wire::encode_node(&wire::NodeRequest::Inspect{job:expected.scope.phase_job_uid.clone(),nonce:nonce.clone()})?;
                let reply=self.shared.call(wire::OFFER_PATH,&query,&expected.scope.phase_node_uid,&directory).await?;
                if reply.sender()!=&expected.scope.phase_node_uid || reply.receiver()!=&expected.scope.issuer_node_uid{return Err("attach inspection response signer/receiver differs".into());}
                match wire::decode_node::<wire::NodeReply>(reply.body())? {
                    wire::NodeReply::InFlight{job,nonce:reply_nonce} if job==expected.scope.phase_job_uid&&reply_nonce==nonce=>(),
                    wire::NodeReply::Completed{job,nonce:reply_nonce,observation} if job==expected.scope.phase_job_uid&&reply_nonce==nonce=>{
                        observation.validate(expected.scope())?;
                        if !expected.completed.load(Ordering::Acquire){return Err("target ticket terminal without accepted actual session completion".into());}
                        break;
                    }
                    _=>return Err("actual attach ticket observation changed identity/nonce".into()),
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        self.require_live()
    }
}


