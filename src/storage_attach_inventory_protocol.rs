//! Profile7-only authenticated DATA facts. Remote tuples are NOT local FD
//! ownership. Receiver roots/rechecks its OWN opaque actual context before
//! request, after real applied Core, and at once-only consumption.
use super::*;
use crate::storage_driver::dispatcher::{VerifiedLocalBoundary,attachment::inventory::RootedOwnedPoolInventory};
use crate::storage_driver::native_runtime::mount::parent::AttachNativeStep;
const DOMAIN:&str="royak-owned-mounted-inventory-read-v1";
const PROFILE:u32=7;
/// Authenticated wire DATA only, not the launch-side actual JobIdentity or a
/// local FD/context constructor. The opaque receiver compares every field.
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InventoryNativeData {pub(crate) node_uid:Uid,pub(crate) boot_id:String,
    pub(crate) volume_uid:Uid,pub(crate) operation_uid:Uid,pub(crate) attempt_uid:Uid,pub(crate) binding_sha256:String}
impl InventoryNativeData {pub(crate) fn require_exact(&self,expected:&Self)->Result<(),String>{
    if self!=expected{return Err("inventory DATA does not match all SIX actual native identity fields".into());}Ok(())}}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InventoryRequest {
    domain:String,version:u32,profile:u32,pub(crate) scope:ExpectedAttachScope,
    session:Uid,sequence:u64,nonce:Uid,native:InventoryNativeData,step:AttachNativeStep,
    context_uid:Uid,context_sha256:String,detail_sha256:String,
}
impl InventoryRequest {
    fn validate(&self)->Result<(),String>{
        self.scope.validate()?;
        let step=if self.scope.phase==AttachPhase::Mount{matches!(self.step,AttachNativeStep::PublicationAnchor|AttachNativeStep::FilesystemMount)}else{self.step==AttachNativeStep::Single};
        if self.domain!=DOMAIN||self.version!=1||self.profile!=PROFILE||!step||self.sequence==0
            ||self.native.node_uid!=self.scope.phase_node_uid||self.native.boot_id!=self.scope.phase_boot.as_str()
            ||self.native.volume_uid!=self.scope.owner.volume_uid||self.native.operation_uid!=*self.scope.mount_ref.operation_uid()
            ||self.step==AttachNativeStep::Single&&self.native.attempt_uid!=self.scope.phase_job_uid
            ||!valid_hash(&self.native.binding_sha256)||!valid_hash(&self.context_sha256)||!valid_hash(&self.detail_sha256){
            return Err("invalid distinct profile7 inventory request/native/context domain".into());}Ok(())
    }
    pub(crate) fn decode(raw:&[u8])->Result<Self,String>{let value:Self=decode(raw)?;value.validate()?;Ok(value)}
    pub(crate) fn binding(&self)->Result<String,String>{Ok(hash(&encode(self)?))}
}
/// Closed discriminator only. Matching the new domain never falls back to
/// legacy decoding on malformed/extra fields; malformed outer JSON refuses.
pub(crate) fn is_domain(raw:&[u8])->Result<bool,String>{
    // This discriminator NEVER normalizes fields into a Value before the
    // closed decoder sees the ORIGINAL bytes. Duplicate domain keys refuse.
    #[derive(Deserialize)]struct Domain {domain:String}
    let value:Domain=decode(raw)?;Ok(value.domain==DOMAIN)
}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct InventoryReply {domain:String,version:u32,profile:u32,request_sha256:String,
    session:Uid,sequence:u64,nonce:Uid,confirmed_revision:Revision,remaining_ms:u64}
pub(super) struct PendingInventory {request:InventoryRequest,raw_sha256:String,started:Instant,context:Arc<RootedOwnedPoolInventory>}
pub(super) struct AcceptedInventoryNative {native:InventoryNativeData,step:AttachNativeStep,context_uid:Uid,context_sha256:String}
pub(crate) struct InventoryPermission {context:Arc<RootedOwnedPoolInventory>,native:InventoryNativeData,detail:String,
    deadline:Instant,spent:AtomicBool}
impl InventoryPermission {
    pub(crate) fn consume(self,detail:&str)->Result<(),String>{
        self.context.require_native_data(&self.native)?;
        if self.detail!=detail||Instant::now()>=self.deadline||self.spent.swap(true,Ordering::AcqRel){
            return Err("owned inventory response late/mismatched/replayed".into());}
        self.context.require_native_data(&self.native)
    }
}
impl Drop for InventoryPermission {fn drop(&mut self){if !self.spent.load(Ordering::Acquire){self.context.retain_unknown();}}}
impl Receiver {
    pub(crate) fn owned_inventory_request(&mut self,context:Arc<RootedOwnedPoolInventory>,
        boundary:&VerifiedLocalBoundary,detail:&str)->Result<Vec<u8>,String>{
        self.live()?;
        let native=context.native_data()?;context.require_native_data_pure(&native)?;context.require_boundary_pure(boundary)?;
        if self.pending.is_some()||self.inventory_pending.is_some()||self.scope!=*context.scope()||!valid_hash(detail){
            return self.deny("inventory pending/source/detail conflict");}
        let owner=self.owner.as_ref().and_then(|p|p.upgrade()).ok_or("inventory session lacks actual parent")?;
        if !std::ptr::eq(Arc::as_ptr(context.parent()),Arc::as_ptr(&owner)){return self.deny("inventory is not this actual session parent");}
        let request=InventoryRequest{domain:DOMAIN.into(),version:1,profile:PROFILE,scope:self.scope.clone(),
            session:self.session.clone().ok_or("actual accepted inventory session absent")?,sequence:self.next,nonce:Uid::new(),
            native,step:context.step(),context_uid:context.uid().clone(),context_sha256:context.commitment()?,detail_sha256:detail.into()};
        request.validate()?;let raw=encode(&request)?;
        self.inventory_pending=Some(PendingInventory{request,raw_sha256:hash(&raw),started:Instant::now(),context});Ok(raw)
    }
    pub(crate) fn owned_inventory_hint(&self,peer:&VerifiedPeerFrame)->Result<(Revision,Instant),String>{
        self.live()?;let pending=self.inventory_pending.as_ref().ok_or("inventory response without SAME pending context")?;
        let reply:InventoryReply=decode(peer.body())?;check(&pending.request,&pending.raw_sha256,&reply)?;peer_identity(peer,&self.scope,true)?;
        pending.context.require_native_data_pure(&pending.request.native)?;
        let(_,fresh)=reply_deadlines(self.deadline,pending.started,reply.remaining_ms,Instant::now())?;
        Ok((reply.confirmed_revision,fresh))
    }
    pub(crate) fn accept_owned_inventory(&mut self,peer:VerifiedPeerFrame,view:&CoreObservation,directory:&VerifiedDirectory)
        ->Result<InventoryPermission,String>{
        let result=(||{
            self.live()?;let pending=self.inventory_pending.as_ref().ok_or("inventory accept without original pending")?;
            pending.context.require_native_data_pure(&pending.request.native)?;
            let reply:InventoryReply=decode(peer.body())?;check(&pending.request,&pending.raw_sha256,&reply)?;peer_identity(&peer,&self.scope,true)?;
            self.scope.check_receiver(view,directory)?;
            if !view.revision().at_least(&reply.confirmed_revision){return Err("inventory reply Core revision not actually applied".into());}
            let(original,fresh)=reply_deadlines(self.deadline,pending.started,reply.remaining_ms,Instant::now())?;
            pending.context.require_native_data_pure(&pending.request.native)?;
            let permission=InventoryPermission{context:pending.context.clone(),native:pending.request.native.clone(),detail:pending.request.detail_sha256.clone(),
                deadline:original.min(fresh),spent:AtomicBool::new(false)};
            self.deadline=original;self.next=self.next.checked_add(1).ok_or("inventory original session sequence overflow")?;
            self.inventory_pending=None;Ok(permission)
        })();if result.is_err(){self.revoke();}result
    }
}
fn check(request:&InventoryRequest,raw_sha256:&str,reply:&InventoryReply)->Result<(),String>{
    if !valid_hash(raw_sha256)||reply.domain!=DOMAIN||reply.version!=1||reply.profile!=PROFILE||reply.request_sha256!=raw_sha256
        ||reply.session!=request.session||reply.sequence!=request.sequence||reply.nonce!=request.nonce
        ||!reply.confirmed_revision.at_least(&request.scope.issuer_revision)||reply.remaining_ms==0
        ||reply.remaining_ms>request.scope.remaining_budget_ms{return Err("not the exact distinct original inventory response".into());}Ok(())
}
impl Issuer {
    pub(crate) fn authorize_owned_inventory(&mut self,peer:VerifiedPeerFrame,view:&CoreObservation,directory:&VerifiedDirectory)->Result<Vec<u8>,String>{
        let request=InventoryRequest::decode(peer.body())?;
        let result=(||{
            let purpose=Purpose::PhaseBoundary(AttachBoundary::InventoryRead);
            self.expected.require_current(view,directory,purpose)?;peer_identity(&peer,self.expected.scope(),false)?;
            view.require_fresh_issuer_for(&peer,Instant::now(),Duration::from_millis(MAX_BOUNDARY_MS))?;
            if self.closed||self.next==0||self.complete_granted||request.scope!=*self.expected.scope()
                ||request.session!=self.session||request.sequence!=self.next{return Err("inventory wrong expected job/current session/order".into());}
            if let Some(prior)=self.inventory_bindings.iter().find(|p|p.step==request.step){
                if prior.native!=request.native||prior.context_uid!=request.context_uid||prior.context_sha256!=request.context_sha256{
                    return Err("inventory actual native/context changed; no rebind".into());}
            }else{
                if self.inventory_bindings.len()>=2||self.inventory_bindings.iter().any(|p|p.native.attempt_uid==request.native.attempt_uid)
                    ||request.step==AttachNativeStep::FilesystemMount&&self.inventory_bindings.last().is_none_or(|p|p.step!=AttachNativeStep::PublicationAnchor){
                    return Err("inventory fixed native substep skipped/reused/full".into());}
                self.inventory_bindings.push(AcceptedInventoryNative{native:request.native.clone(),step:request.step,
                    context_uid:request.context_uid.clone(),context_sha256:request.context_sha256.clone()});
            }
            let now=Instant::now();let remaining=u64::try_from(self.expected.original_deadline().saturating_duration_since(now).as_millis()).map_err(|_|"inventory remaining overflow")?;
            if remaining==0{return Err("inventory original round expired".into());}
            let reply=InventoryReply{domain:DOMAIN.into(),version:1,profile:PROFILE,request_sha256:hash(peer.body()),session:self.session.clone(),
                sequence:request.sequence,nonce:request.nonce,confirmed_revision:view.revision().clone(),remaining_ms:remaining.min(request.scope.remaining_budget_ms)};
            self.next=self.next.checked_add(1).ok_or("inventory session sequence exhausted")?;encode(&reply)
        })();if result.is_err(){self.closed=true;self.expected.retain_unknown();}result
    }
}
#[cfg(test)]
mod tests{
    use super::*;
    fn request()->InventoryRequest{
        let scope=crate::storage_driver::dispatcher::attachment::inventory::tests::data_scope();
        let native=InventoryNativeData{node_uid:scope.phase_node_uid.clone(),boot_id:scope.phase_boot.as_str().into(),
            volume_uid:scope.owner.volume_uid.clone(),operation_uid:scope.mount_ref.operation_uid().clone(),attempt_uid:scope.phase_job_uid.clone(),binding_sha256:"a".repeat(64)};
        InventoryRequest{domain:DOMAIN.into(),version:1,profile:7,scope,session:Uid::new(),sequence:1,nonce:Uid::new(),native,
            step:AttachNativeStep::Single,context_uid:Uid::new(),context_sha256:"b".repeat(64),detail_sha256:"c".repeat(64)}
    }
    fn reply(r:&InventoryRequest)->InventoryReply{InventoryReply{domain:DOMAIN.into(),version:1,profile:7,request_sha256:r.binding().unwrap(),
        session:r.session.clone(),sequence:r.sequence,nonce:r.nonce.clone(),confirmed_revision:r.scope.issuer_revision.clone(),remaining_ms:500}}
    #[test]fn v7_wire_is_distinct_and_legacy_generic_paths_refuse_inventory(){
        let r=request();let raw=encode(&r).unwrap();InventoryRequest::decode(&raw).unwrap();assert!(is_domain(&raw).unwrap());
        assert!(super::super::Request::decode(&raw).is_err());
        for phase in [AttachPhase::ActivateReplica,AttachPhase::ObserveSynchronized,AttachPhase::PromoteTarget,AttachPhase::Mount,AttachPhase::ObserveMounted]{
            assert!(!AttachBoundary::InventoryRead.allowed(phase));}
        for profile in [1,2,3,4,5,6,8]{let mut bad=r.clone();bad.profile=profile;assert!(InventoryRequest::decode(&encode(&bad).unwrap()).is_err());}
    }
    #[test]fn v7_original_raw_unknown_and_duplicate_fields_refuse_without_value_normalization(){
        let raw=String::from_utf8(encode(&request()).unwrap()).unwrap();
        let unknown=raw.replacen('{',"{\"unknown\":false,",1);assert!(InventoryRequest::decode(unknown.as_bytes()).is_err());
        let duplicate=raw.replacen('{',"{\"domain\":\"royak-owned-mounted-inventory-read-v1\",",1);
        assert!(InventoryRequest::decode(duplicate.as_bytes()).is_err());assert!(is_domain(duplicate.as_bytes()).is_err());
        let duplicated_native=raw.replacen("\"native\":{","\"native\":{\"node_uid\":\"00000000000000000000000000000001\",",1);
        assert_ne!(duplicated_native,raw);assert!(InventoryRequest::decode(duplicated_native.as_bytes()).is_err());
    }
    #[test]fn v7_all_six_native_fields_must_equal_the_actual_data_snapshot(){
        let expected=request().native;expected.require_exact(&expected).unwrap();
        for case in 0..6{let mut changed=expected.clone();match case{0=>changed.node_uid=Uid::new(),1=>changed.boot_id="12345678-1234-4234-a234-123456789abc".into(),
            2=>changed.volume_uid=Uid::new(),3=>changed.operation_uid=Uid::new(),4=>changed.attempt_uid=Uid::new(),_=>changed.binding_sha256="f".repeat(64)}
            if case==1&&changed.boot_id==expected.boot_id{changed.boot_id="22345678-1234-4234-a234-123456789abc".into();}
            assert!(changed.require_exact(&expected).is_err(),"six-field negative {case}");}
    }
    #[test]fn v7_reply_requires_exact_pending_full_source_session_nonce_and_profile(){
        let r=request();let good=reply(&r);let raw=r.binding().unwrap();check(&r,&raw,&good).unwrap();
        for case in 0..8{let mut bad=good.clone();match case{0=>bad.request_sha256="d".repeat(64),1=>bad.session=Uid::new(),2=>bad.nonce=Uid::new(),
            3=>bad.sequence+=1,4=>bad.profile=6,5=>bad.domain=WIRE.into(),6=>bad.remaining_ms=0,_=>bad.confirmed_revision.term=0}
            assert!(check(&r,&raw,&bad).is_err(),"pending negative {case}");}
        let mut source=r.clone();source.context_uid=Uid::new();assert!(check(&source,&source.binding().unwrap(),&good).is_err());
        source=r.clone();source.context_sha256="e".repeat(64);assert!(check(&source,&source.binding().unwrap(),&good).is_err());
        let start=Instant::now();let original=start+Duration::from_secs(180);
        assert!(reply_deadlines(original,start,500,start+Duration::from_millis(500)).is_err());
    }
    #[test]fn v7_local_and_remote_source_keep_actual_context_pre_post_and_same_512_accounting(){
        let source=include_str!("storage_driver/native_runtime_attach_parent.rs");
        let actual=source.split("pub(in crate::storage_driver) fn approve_owned_inventory(").nth(1).unwrap().split("pub(crate) fn scope(").next().unwrap();
        assert!(actual.matches("require_owned_inventory_native").count()>=4);
        assert!(actual.contains("core::observe_native_issuer"));assert!(actual.contains("core::wait_applied_hint"));
        assert!(actual.contains("durable_admit"));assert!(actual.contains("permission.consume(detail)"));
        let admissions=source.split("fn admit_owned_inventory(").nth(1).unwrap().split("fn record_completion(").next().unwrap();
        assert!(admissions.contains("seen.len()>=512"));assert!(admissions.contains("!seen.insert(binding.into())"));
    }
}
