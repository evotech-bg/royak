//! Closed attach-only wire session. DATA cannot construct its registered parent.
//! Cold/init protocol and predicates are intentionally not reused or weakened.
use super::*;
use crate::storage_lifecycle::pod_attachment::{AttachPhase,ExpectedAttachScope};
use crate::storage_driver::native_runtime::mount::parent::ExpectedAttachJob;
use std::sync::atomic::{AtomicBool,Ordering};
#[path="storage_attach_inventory_protocol.rs"]
pub(crate) mod owned_inventory;

pub(crate) const PATH:&str="/royak/v1/storage/node/attach";
pub(crate) const OFFER_PATH:&str="/royak/v1/storage/node/attach-offer";
pub(crate) const MOUNTED_PATH:&str="/royak/v1/storage/node/mounted-commit";
const WIRE:&str="royak-managed-attach-session-v1";
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum NodeRequest {Offer {scope:ExpectedAttachScope,nonce:Uid},Inspect {job:Uid,nonce:Uid},Readiness {volume:Uid,nonce:Uid}}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Readiness {pub(crate) volume:Uid,pub(crate) node:Uid,pub(crate) boot:BootId,pub(crate) pool:Uid,
    pub(crate) directory_sha256:String,pub(crate) revision:Revision,pub(crate) available:bool}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) enum NodeReply {Queued {job:Uid,nonce:Uid},InFlight {job:Uid,nonce:Uid},Completed {job:Uid,nonce:Uid,
    observation:crate::storage_lifecycle::pod_attachment::AttachPhaseObservation},Readiness {nonce:Uid,observation:Readiness}}
pub(crate) fn encode_node<T:Serialize>(value:&T)->Result<Vec<u8>,String>{encode(value)}
pub(crate) fn decode_node<T:for<'de>Deserialize<'de>>(raw:&[u8])->Result<T,String>{decode(raw)}
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub(crate) enum AttachBoundary {Start,Identity,Program,Read,AnchorBind,AnchorPrivate,MountExt4,MakePrivate,Complete,InventoryRead}
impl AttachBoundary {
    pub(crate) fn allowed(self,phase:AttachPhase)->bool {
        match self {
            // New purpose has a DISTINCT actual-context producer/decoder.
            // It is NEVER admitted by the legacy generic permission domain.
            Self::InventoryRead=>false,
            Self::Read=>phase==AttachPhase::ObserveSynchronized,
            Self::AnchorBind|Self::AnchorPrivate|Self::MountExt4|Self::MakePrivate=>phase==AttachPhase::Mount,
            Self::Start|Self::Identity|Self::Program|Self::Complete=>true,
        }
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub(crate) enum Purpose {PhaseGrant,PhaseBoundary(AttachBoundary),PhaseReport,MountedCommit,MountedCommitConfirm}
impl Purpose {
    pub(crate) fn path(self)->&'static str {
        match self {Self::MountedCommit|Self::MountedCommitConfirm=>MOUNTED_PATH,_=>PATH}
    }
}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    domain:String,version:u32,pub(crate) scope:ExpectedAttachScope,
    pub(crate) purpose:Purpose,pub(crate) sequence:u64,nonce:Uid,
    session:Option<Uid>,detail_sha256:String,
    completion:Option<crate::storage_lifecycle::pod_attachment::AttachPhaseObservation>,
}
impl Request {
    fn validate(&self)->Result<(),String> {
        self.scope.validate()?;
        match (&self.purpose,&self.completion) {
            (Purpose::PhaseReport,Some(observation))=>observation.validate(&self.scope)?,
            (Purpose::PhaseReport,None)=>return Err("phase report observation absent".into()),
            (_,Some(_))=>return Err("unexpected observation on an effect permission".into()),
            (_,None)=>(),
        }
        if self.domain!=WIRE || self.version!=1 || !valid_hash(&self.detail_sha256)
            || self.purpose==Purpose::PhaseGrant && self.detail_sha256!=hash(b"attach-grant")
            || matches!(self.purpose,Purpose::PhaseGrant)!=(self.sequence==0 && self.session.is_none())
            || matches!(self.purpose,Purpose::PhaseBoundary(kind) if !kind.allowed(self.scope.phase))
            || matches!(self.purpose,Purpose::MountedCommit|Purpose::MountedCommitConfirm)
                && self.scope.phase!=AttachPhase::ObserveMounted {
            return Err("invalid closed attach request/purpose/phase".into());
        }Ok(())
    }
    pub(crate) fn decode(raw:&[u8])->Result<Self,String> {let value:Self=super::decode(raw)?;value.validate()?;Ok(value)}
    pub(crate) fn hash(&self)->Result<String,String> {Ok(hash(&encode(self)?))}
    pub(crate) fn path(&self)->&'static str {self.purpose.path()}
    pub(crate) fn detail(&self)->&str{&self.detail_sha256}
}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    domain:String,version:u32,scope_sha256:String,purpose:Purpose,sequence:u64,nonce:Uid,
    request_sha256:String,session:Uid,confirmed_revision:Revision,remaining_ms:u64,
}
/// Actual local request binding, not a generic hash constructor.
pub(crate) struct LocalRequest {request:Request,started:Instant}
impl LocalRequest {
    pub(crate) fn challenge(&self)->Result<ReadChallenge,String> {
        Ok(ReadChallenge {binding:hash(&encode(&self.request)?)})
    }
    pub(crate) fn binding(&self)->Result<String,String> {Ok(self.challenge()?.binding().into())}
    pub(crate) fn request(&self)->&Request {&self.request}
}
struct Pending {request:Request,started:Instant}
/// Unaccepted challenge is not permission. Only exact transport + current Core
/// acceptance creates a one-use token. This object stays rooted by actual parent.
pub(crate) struct Receiver {
    scope:ExpectedAttachScope,deadline:Instant,
    session:Option<Uid>,next:u64,pending:Option<Pending>,invalid:Arc<AtomicBool>,
    committed:bool,confirmed:bool,complete_granted:bool,
    owner:Option<std::sync::Weak<crate::storage_driver::native_runtime::mount::parent::VerifiedAttachParent>>,
    inventory_pending:Option<owned_inventory::PendingInventory>,
}
impl Receiver {
    pub(crate) fn challenge(scope:ExpectedAttachScope,view:&CoreObservation,directory:&VerifiedDirectory)
        ->Result<(Self,Vec<u8>),String> {
        scope.check_receiver(view,directory)?;
        let now=Instant::now();
        let deadline=now.checked_add(Duration::from_millis(scope.remaining_budget_ms)).ok_or("attach deadline overflow")?;
        let mut value=Self {scope,deadline,session:None,next:0,pending:None,
            invalid:Arc::new(AtomicBool::new(false)),committed:false,confirmed:false,complete_granted:false,owner:None,inventory_pending:None};
        let bytes=value.request(Purpose::PhaseGrant,&hash(b"attach-grant"))?;
        Ok((value,bytes))
    }
    pub(crate) fn request(&mut self,purpose:Purpose,detail:&str)->Result<Vec<u8>,String> {
        self.live()?;
        if self.inventory_pending.is_some()||purpose==Purpose::PhaseBoundary(AttachBoundary::InventoryRead){
            return self.deny("generic attach request cannot produce owned inventory permission");}
        if purpose!=Purpose::PhaseGrant && self.owner.is_none(){return self.deny("unbound protocol session is not an actual physical parent");}
        if self.pending.is_some() || !valid_hash(detail)
            || self.session.is_none() && purpose!=Purpose::PhaseGrant
            || self.session.is_some() && purpose==Purpose::PhaseGrant
            || purpose==Purpose::MountedCommit && self.committed
            || purpose==Purpose::MountedCommitConfirm && (!self.committed || self.confirmed) {
            return self.deny("attach session replay/order/pending conflict");
        }
        let request=Request {domain:WIRE.into(),version:1,scope:self.scope.clone(),purpose,
            sequence:self.next,nonce:Uid::new(),session:self.session.clone(),detail_sha256:detail.into(),completion:None};
        request.validate()?;
        let raw=encode(&request)?;
        self.pending=Some(Pending {request,started:Instant::now()});Ok(raw)
    }
    pub(crate) fn reply_hint(&self,peer:&VerifiedPeerFrame)->Result<(Revision,Instant),String> {
        self.live()?;
        let pending=self.pending.as_ref().ok_or("attach reply without pending request")?;
        let reply:Reply=decode(peer.body())?;
        check_reply(&pending.request,&reply)?;
        peer_identity(peer,&self.scope,true)?;
        let (_,fresh)=reply_deadlines(self.deadline,pending.started,reply.remaining_ms,Instant::now())?;
        Ok((reply.confirmed_revision,fresh))
    }
    pub(crate) fn accept(&mut self,peer:VerifiedPeerFrame,view:&CoreObservation,directory:&VerifiedDirectory)
        ->Result<OnePermission,String> {
        let outcome=(|| {
            self.live()?;peer_identity(&peer,&self.scope,true)?;
            let pending=self.pending.as_ref().ok_or("attach reply without original pending request")?;
            let reply:Reply=decode(peer.body())?;check_reply(&pending.request,&reply)?;
            if !matches!(pending.request.purpose,Purpose::MountedCommitConfirm) {
                self.scope.check_receiver(view,directory)?;
            } else {check_post_envelope(&self.scope,view,directory,false)?;}
            if !view.revision().at_least(&reply.confirmed_revision) {
                return Err("attach receiver has not actually applied reply revision".into());
            }
            let now=Instant::now();
            // Challenge START, never reply receipt. Later boundaries can only shorten.
            let (original,freshness)=reply_deadlines(self.deadline,pending.started,reply.remaining_ms,now)?;
            self.deadline=original;
            let purpose=pending.request.purpose;let detail=pending.request.detail_sha256.clone();
            self.session=Some(reply.session);self.next=self.next.checked_add(1).ok_or("attach sequence overflow")?;
            if purpose==Purpose::MountedCommit {self.committed=true;}
            if purpose==Purpose::MountedCommitConfirm {self.confirmed=true;}
            if purpose==Purpose::PhaseBoundary(AttachBoundary::Start){self.complete_granted=false;}
            if purpose==Purpose::PhaseBoundary(AttachBoundary::Complete){self.complete_granted=true;}
            self.pending=None;
            Ok(OnePermission {purpose,detail,deadline:self.deadline.min(freshness),
                invalid:self.invalid.clone(),spent:AtomicBool::new(false),owner:self.owner.as_ref().map(|weak|weak.upgrade().ok_or("actual attach parent lost")).transpose()?,expected:None})
        })();
        if outcome.is_err(){self.revoke();}outcome
    }
    pub(crate) fn deadline(&self)->Result<Instant,String> {self.live()?;Ok(self.deadline)}
    pub(crate) fn shorten_original_to(&mut self,earlier:Instant)->Result<(),String>{
        self.live()?;self.deadline=self.deadline.min(earlier);self.live()
    }
    pub(crate) fn scope(&self)->&ExpectedAttachScope {&self.scope}
    pub(crate) fn bind_actual_parent(&mut self,parent:&Arc<crate::storage_driver::native_runtime::mount::parent::VerifiedAttachParent>)->Result<(),String>{
        self.live()?;parent.require_live()?;
        if self.owner.is_some() || self.pending.is_some() || self.session.is_none() || parent.scope()!=&self.scope
            || parent.original_deadline()!=self.deadline {return self.deny("receiver cannot change actual parent ownership");}
        self.owner=Some(Arc::downgrade(parent));Ok(())
    }
    pub(crate) fn report_after_drain(&mut self,drain:&crate::storage_driver::dispatcher::attachment::VerifiedAttachDrain)->Result<Vec<u8>,String>{
        self.live()?;
        if !self.complete_granted || self.pending.is_some() || drain.scope()!=&self.scope{return self.deny("phase report lacks actual completed session/drain");}
        let observation=drain.observation()?.clone();observation.validate(&self.scope)?;
        let detail=hash(&encode(&("actual-supervised-phase-report",drain.completion_sha256(),&observation))?);
        let request=Request {domain:WIRE.into(),version:1,scope:self.scope.clone(),purpose:Purpose::PhaseReport,
            sequence:self.next,nonce:Uid::new(),session:self.session.clone(),detail_sha256:detail,completion:Some(observation)};
        request.validate()?;let raw=encode(&request)?;
        self.pending=Some(Pending {request,started:Instant::now()});Ok(raw)
    }
    pub(crate) fn revoke(&self){self.invalid.store(true,Ordering::Release);}
    fn deny<T>(&self,error:&str)->Result<T,String>{self.revoke();Err(error.into())}
    fn live(&self)->Result<(),String>{
        if let Some(owner)=&self.owner {owner.upgrade().ok_or("actual receiver parent lost")?.require_live()?;}
        if self.invalid.load(Ordering::Acquire)||Instant::now()>=self.deadline {Err("attach session expired/UNKNOWN".into())}else{Ok(())}
    }
}
fn peer_identity(peer:&VerifiedPeerFrame,scope:&ExpectedAttachScope,reply:bool)->Result<(),String>{
    let (sender,receiver)=if reply {(&scope.issuer_node_uid,&scope.phase_node_uid)}
        else {(&scope.phase_node_uid,&scope.issuer_node_uid)};
    if peer.sender()!=sender || peer.receiver()!=receiver {Err("attach authenticated peer UID differs".into())}else{Ok(())}
}
fn check_reply(request:&Request,reply:&Reply)->Result<(),String>{
    check_reply_fields(&ReplyExpectation {purpose:request.purpose,sequence:request.sequence,nonce:request.nonce.clone(),
        request_sha256:request.hash()?,scope_sha256:hash(&encode(&request.scope)?),session:request.session.clone(),
        minimum:request.scope.issuer_revision.clone(),maximum_ms:request.scope.remaining_budget_ms},reply)
}
struct ReplyExpectation {purpose:Purpose,sequence:u64,nonce:Uid,request_sha256:String,scope_sha256:String,
    session:Option<Uid>,minimum:Revision,maximum_ms:u64}
fn check_reply_fields(request:&ReplyExpectation,reply:&Reply)->Result<(),String>{
    if reply.domain!=WIRE || reply.version!=1 || reply.purpose!=request.purpose
        || reply.sequence!=request.sequence || reply.nonce!=request.nonce
        || reply.request_sha256!=request.request_sha256 || reply.scope_sha256!=request.scope_sha256
        || !reply.confirmed_revision.at_least(&request.minimum)
        || reply.remaining_ms==0 || reply.remaining_ms>request.maximum_ms
        || request.session.as_ref().is_some_and(|s|s!=&reply.session) {
        return Err("attach reply is not exact original purpose/nonce/spec/session/revision".into());
    }Ok(())
}
fn reply_deadlines(original:Instant,request_started:Instant,remaining_ms:u64,now:Instant)->Result<(Instant,Instant),String>{
    if remaining_ms==0 || remaining_ms>180_000 || now<request_started{return Err("invalid attach original reply budget".into());}
    let accepted=original.min(request_started.checked_add(Duration::from_millis(remaining_ms)).ok_or("attach deadline overflow")?);
    let fresh=accepted.min(request_started.checked_add(Duration::from_millis(MAX_BOUNDARY_MS)).ok_or("attach freshness overflow")?);
    if now>=fresh{return Err("attach reply consumed original/fresh boundary budget".into());}
    Ok((accepted,fresh))
}
pub(crate) fn check_post_envelope(scope:&ExpectedAttachScope,view:&CoreObservation,
    directory:&VerifiedDirectory,issuer:bool)->Result<(),String>{
    // Necessary DATA only: the actual runtime separately checks complete mounted
    // group and exact canonical receipt. Never old Attaching prior-proof equality.
    if view.cluster_id()!=scope.owner.cluster_id || directory.cluster_id()!=scope.owner.cluster_id
        || view.directory_commitment()!=Some(scope.directory_sha256.as_str())
        || view.volume().owner()!=&scope.owner || view.volume().phase()!=Phase::Attached
        || view.volume().data_generation()!=Some(&scope.generation)
        || view.volume().pod_writer()!=Some(&scope.pod_writer)
        || directory.digest()!=scope.directory_sha256
        || !view.revision().at_least(&scope.issuer_revision)
        || directory.pin(&scope.issuer_node_uid)?.raft_id!=scope.issuer_revision.leader_raft_id {
        return Err("mounted confirmation differs from actual post-state envelope".into());
    }
    scope.mount_ref.check_metadata(view.volume())?;
    let (uid,boot)=if issuer {(&scope.issuer_node_uid,&scope.issuer_boot)}else{(&scope.phase_node_uid,&scope.phase_boot)};
    if view.local_node_uid()!=Some(uid)||view.actual_boot()!=boot {return Err("mounted confirmation local identity/boot changed".into());}
    Ok(())
}
/// Consumed at most once. Original actual owner/session also remains separately
/// rooted; dropping this token cannot release a physical object or allow retry.
pub(crate) struct OnePermission {purpose:Purpose,detail:String,deadline:Instant,invalid:Arc<AtomicBool>,spent:AtomicBool,
    owner:Option<Arc<crate::storage_driver::native_runtime::mount::parent::VerifiedAttachParent>>,expected:Option<Arc<ExpectedAttachJob>>}
pub(crate) struct AuthenticatedCompletion {job:Uid,observation:crate::storage_lifecycle::pod_attachment::AttachPhaseObservation,request_sha256:String}
impl AuthenticatedCompletion {
    pub(crate) fn job(&self)->&Uid{&self.job}
    pub(crate) fn observation(&self)->&crate::storage_lifecycle::pod_attachment::AttachPhaseObservation{&self.observation}
    pub(crate) fn request_sha256(&self)->&str{&self.request_sha256}
}
pub(crate) struct AuthorizedReply {pub(crate) bytes:Vec<u8>,pub(crate) completion:Option<AuthenticatedCompletion>}
impl OnePermission {
    pub(crate) fn consume_report(&self)->Result<(),String>{self.consume(Purpose::PhaseReport,&self.detail)}
    pub(crate) fn check_live(&self)->Result<(),String>{
        if let Some(owner)=&self.owner {owner.require_live()?;}
        if let Some(expected)=&self.expected {expected.require_live()?;}
        if self.invalid.load(Ordering::Acquire)||Instant::now()>=self.deadline {Err("attach permission expired/revoked".into())}else{Ok(())}
    }
    pub(crate) fn consume(&self,purpose:Purpose,detail:&str)->Result<(),String>{
        self.check_live()?;
        if self.purpose!=purpose || self.detail!=detail || self.spent.swap(true,Ordering::AcqRel) {
            self.invalid.store(true,Ordering::Release);return Err("attach permission wrong-purpose/detail or replay".into());
        }self.check_live()
    }
}
impl Drop for OnePermission {fn drop(&mut self){if !self.spent.load(Ordering::Acquire){
    self.invalid.store(true,Ordering::Release);
    // Fast one-way revocation only; never block Drop under a scratch/book lock.
    if let Some(owner)=&self.owner {owner.invalidate_fast();}
    if let Some(expected)=&self.expected {expected.invalidate_fast();}
}}}
/// Actual expected registration is required; a verified transport signature or
/// received group alone cannot construct this issuer.
pub(crate) struct Issuer {
    expected:Arc<ExpectedAttachJob>,session:Uid,next:u64,closed:bool,
    committed:bool,confirmed:bool,complete_granted:bool,
    inventory_bindings:Vec<owned_inventory::AcceptedInventoryNative>,
}
impl Issuer {
    pub(crate) fn new(expected:Arc<ExpectedAttachJob>)->Self{
        Self {expected,session:Uid::new(),next:0,closed:false,committed:false,confirmed:false,complete_granted:false,inventory_bindings:Vec::new()}
    }
    pub(crate) fn authorize(&mut self,peer:VerifiedPeerFrame,view:&CoreObservation,directory:&VerifiedDirectory)
        ->Result<AuthorizedReply,String>{
        let request=Request::decode(peer.body())?;
        let outcome=(|| {
            self.expected.require_current(view,directory,request.purpose)?;
            peer_identity(&peer,self.expected.scope(),false)?;
            view.require_fresh_issuer_for(&peer,Instant::now(),Duration::from_millis(MAX_BOUNDARY_MS))?;
            if self.closed || request.scope!=*self.expected.scope() || request.sequence!=self.next
                || (self.next==0)!=(request.purpose==Purpose::PhaseGrant)
                || request.session.as_ref()!=(if self.next==0 {None}else{Some(&self.session)})
                || request.purpose==Purpose::MountedCommit && self.committed
                || request.purpose==Purpose::MountedCommitConfirm && (!self.committed||self.confirmed) {
                return Err("unregistered/replayed/out-of-order attach purpose".into());
            }
            self.expected.require_detail(request.purpose,&request.detail_sha256)?;
            if request.purpose==Purpose::PhaseReport && !self.complete_granted{return Err("phase report before actual Complete permission".into());}
            let now=Instant::now();let deadline=self.expected.original_deadline();
            let ms=u64::try_from(deadline.saturating_duration_since(now).as_millis()).map_err(|_|"attach remaining overflow")?;
            if ms==0 {return Err("original attach issuer deadline expired".into());}
            let reply=Reply {domain:WIRE.into(),version:1,scope_sha256:hash(&encode(&request.scope)?),
                purpose:request.purpose,sequence:request.sequence,nonce:request.nonce.clone(),
                request_sha256:hash(peer.body()),session:self.session.clone(),confirmed_revision:view.revision().clone(),
                remaining_ms:ms.min(self.expected.scope().remaining_budget_ms)};
            self.next=self.next.checked_add(1).ok_or("attach sequence exhausted")?;
            if request.purpose==Purpose::MountedCommit {self.committed=true;}
            if request.purpose==Purpose::MountedCommitConfirm {self.confirmed=true;}
            if request.purpose==Purpose::PhaseBoundary(AttachBoundary::Start){self.complete_granted=false;}
            if request.purpose==Purpose::PhaseBoundary(AttachBoundary::Complete){self.complete_granted=true;}
            let completion=if request.purpose==Purpose::PhaseReport {
                let observation=request.completion.as_ref().ok_or("phase report observation absent")?;
                observation.validate(self.expected.scope())?;
                Some(AuthenticatedCompletion {job:self.expected.scope().phase_job_uid.clone(),observation:observation.clone(),request_sha256:request.hash()?})
            }else{None};
            Ok(AuthorizedReply {bytes:encode(&reply)?,completion})
        })();
        if outcome.is_err(){self.closed=true;self.expected.retain_unknown();}outcome
    }
}
/// Local leader follows the same closed purposes and a request-bound real
/// Core barrier, without fabricating a transport frame for itself.
pub(crate) fn local_request(expected:&ExpectedAttachJob,purpose:Purpose,detail:&str)
    ->Result<LocalRequest,String>{
    expected.require_live()?;
    if purpose==Purpose::PhaseBoundary(AttachBoundary::InventoryRead){return Err("old local request cannot mint inventory permission".into());}
    expected.require_detail(purpose,detail)?;
    let request=Request {domain:WIRE.into(),version:1,scope:expected.scope().clone(),purpose,
        sequence:match purpose {Purpose::MountedCommit=>1,Purpose::MountedCommitConfirm=>2,_=>0},
        nonce:Uid::new(),session:Some(expected.session_uid().clone()),detail_sha256:detail.into(),completion:None};
    // Local phase grant has no remote envelope/session. Every physical local
    // action is independently real quorum-bound by this fresh nonce.
    if !valid_hash(detail) {return Err("invalid local attach request binding".into());}
    Ok(LocalRequest {request,started:Instant::now()})
}
pub(crate) fn local_permission(expected:&Arc<ExpectedAttachJob>,request:LocalRequest,
    view:&CoreObservation,directory:&VerifiedDirectory)->Result<OnePermission,String>{
    expected.require_current(view,directory,request.request.purpose)?;
    view.require_fresh_attach(&request,Instant::now())?;
    let deadline=expected.original_deadline().min(request.started+Duration::from_millis(MAX_BOUNDARY_MS));
    if Instant::now()>=deadline {expected.retain_unknown();return Err("local attach response arrived late".into());}
    Ok(OnePermission {purpose:request.request.purpose,detail:request.request.detail_sha256,deadline,
        invalid:Arc::new(AtomicBool::new(false)),spent:AtomicBool::new(false),owner:None,expected:Some(expected.clone())})
}
#[cfg(test)]
#[path="storage_attach_protocol_tests.rs"]
mod tests;

