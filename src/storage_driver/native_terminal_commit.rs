//! Genuine original terminal metadata transitions on the existing fixed IO.
//! Before/scratch/after fences; a late known ACK is retained, never success.
use super::*;
use crate::store::CommitError;
use std::sync::atomic::AtomicU8;
const ROOTED:u8=0;const AUTHORIZED:u8=1;const SUBMITTED:u8=2;const ACKED:u8=3;const CONFIRMED:u8=4;const FAILED:u8=5;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum MetadataKind {BeginDetaching,CommitDetached}
impl MetadataKind {
    fn before(self)->TerminalWorldPhase{match self{Self::BeginDetaching=>TerminalWorldPhase::OriginalAttached,Self::CommitDetached=>TerminalWorldPhase::Detaching}}
    fn after(self)->TerminalWorldPhase{match self{Self::BeginDetaching=>TerminalWorldPhase::Detaching,Self::CommitDetached=>TerminalWorldPhase::Detached}}
    fn effect(self)->TerminalEffect{match self{Self::BeginDetaching=>TerminalEffect::BeginDetaching,Self::CommitDetached=>TerminalEffect::CommitDetached}}
    fn records(self)->(journal::TerminalRecordKind,journal::TerminalRecordKind){match self{
        Self::BeginDetaching=>(journal::TerminalRecordKind::DetachingAdmission,journal::TerminalRecordKind::DetachingOutcome),
        Self::CommitDetached=>(journal::TerminalRecordKind::DetachedAdmission,journal::TerminalRecordKind::DetachedOutcome)}}
}
/// Original actual local drains / authenticated current receiver completions,
/// not a deserializable receipt or three manufactured local held objects.
pub(crate) struct VerifiedTerminalOfflineSet {
    round:Arc<RegisteredDrainRound>,ordered:[Arc<wire::TerminalCompletion>;3],evidence:Uid,sha256:String,
}
impl VerifiedTerminalOfflineSet {
    pub(super) fn collect(round:&Arc<RegisteredDrainRound>)->Result<Arc<Self>,String>{
        round.require_live()?;
        let reference=round.plan.operation.key.references.values().next().ok_or("terminal offline group absent")?;
        let generation={let current=round.shared.world.try_read().map_err(|_|"terminal offline canonical source busy")?;
            round.check_world_phase(&current,TerminalWorldPhase::Detaching)?;
            current.storage_identities.lifecycle.get(reference.volume_uid()).ok_or("terminal offline dataset absent")?.data_generation()
                .cloned().ok_or("terminal offline committed generation absent")?};
        let rows={let proofs=round.completions.try_lock().map_err(|_|"actual terminal proof roots busy")?;
            generation.virgin_replicas.iter().map(|fact|proofs.get(&(fact.node_uid.clone(),TerminalNativeStep::OfflineAndObserve))
                .cloned().ok_or("all three actual independent offline completions required")).collect::<Result<Vec<_>,_>>()?};
        let ordered:[Arc<wire::TerminalCompletion>;3]=rows.try_into().map_err(|_|"terminal requires exact three offline owners")?;
        let mut expected_hash=None;
        for proof in &ordered{
            proof.require_original(round)?;
            let hash=proof.observation().data_sha256.as_ref().ok_or("terminal independent current offline hash absent")?;
            if !is_hash(hash)||expected_hash.as_ref().is_some_and(|old|old!=hash){return Err("three actual post-writer offline data hashes differ; UNKNOWN".into());}
            expected_hash=Some(hash.clone());
        }
        let facts=ordered.iter().map(|p|(p.observation(),p.completion_sha256())).collect::<Vec<_>>();
        let sha256=digest(&serde_json::to_vec(&("royak-actual-three-node-terminal-detached-v1",&round.plan.uid,reference,&generation,facts))
            .map_err(|_|"exact current terminal offline proof encoding failed")?);
        Ok(Arc::new(Self{round:round.clone(),ordered,evidence:Uid::new(),sha256}))
    }
    pub(crate) fn require_current(&self,round:&RegisteredDrainRound)->Result<(),String>{
        if !std::ptr::eq(Arc::as_ptr(&self.round),round)||!is_hash(&self.sha256){return Err("terminal offline proof is another original round".into());}
        for proof in &self.ordered{proof.require_original(&self.round)?;}Ok(())
    }
    pub(crate) fn evidence_uid(&self)->&Uid{&self.evidence}
    pub(crate) fn evidence_sha256(&self)->&str{&self.sha256}
}
pub(crate) struct PreparedTerminalMetadata {
    round:Arc<RegisteredDrainRound>,kind:MetadataKind,stage:AtomicU8,
    pre:String,post:Mutex<Option<String>>,permission:Mutex<Option<VerifiedTerminalEffect>>,
    offline:Option<Arc<VerifiedTerminalOfflineSet>>,outcome:Mutex<Option<serde_json::Value>>,
}
struct RetainOriginal {prepared:Arc<PreparedTerminalMetadata>,finished:bool}
impl Drop for RetainOriginal {fn drop(&mut self){if !self.finished{self.prepared.unknown();}}}
impl PreparedTerminalMetadata {
    pub(crate) fn actual_store(&self)->&Arc<RwLock<DesiredWorld>>{&self.round.shared.world}
    pub(crate) fn kind(&self)->MetadataKind{self.kind}
    pub(crate) fn operation_uid(&self)->&Uid{&self.round.plan.uid}
    pub(crate) fn original_reference(&self)->Result<&crate::storage_pod_writer::ManagedMountRef,String>{
        self.round.plan.operation.key.references.values().next().ok_or("actual terminal original reference absent".into())
    }
    pub(crate) fn offline(&self)->Result<&VerifiedTerminalOfflineSet,String>{self.offline.as_deref().ok_or("actual three-node offline set absent".into())}
    fn pure_live(&self)->Result<(),String>{
        self.round.require_live()?;
        if self.stage.load(Ordering::Acquire)==FAILED{return Err("original terminal metadata operation UNKNOWN".into());}
        if let Some(offline)=&self.offline{offline.require_current(&self.round)?;}Ok(())
    }
    fn permission_live(&self)->Result<(),String>{
        self.pure_live()?;
        let permission=self.permission.try_lock().map_err(|_|"terminal metadata permission busy")?;
        let permission=permission.as_ref().ok_or("terminal metadata lacks genuine fresh authorized permission")?;
        permission.observed.require_fresh_terminal(&permission.request,Instant::now())?;
        if !permission.spent.load(Ordering::Acquire)||permission.request.effect!=self.kind.effect()||permission.request.resource!=self.pre{
            return Err("terminal metadata one-use permission differs/not actually consumed".into());}
        Ok(())
    }
    pub(crate) fn validate_scratch(&self,scratch:&DesiredWorld)->Result<(),String>{
        if self.stage.load(Ordering::Acquire)!=SUBMITTED{return Err("terminal scratch not from actual once-only submitted IO operation".into());}
        self.permission_live()?;
        if graph(&self.round,scratch,self.kind.before())?!=self.pre{return Err("terminal current exact scratch graph changed since fresh barrier".into());}Ok(())
    }
    pub(crate) fn validate_post_scratch(&self,scratch:&DesiredWorld)->Result<(),String>{
        self.permission_live()?;let post=graph(&self.round,scratch,self.kind.after())?;
        let mut original=self.post.try_lock().map_err(|_|"terminal post scratch graph busy")?;
        if original.is_some(){return Err("terminal scratch callback repeated; no repeat metadata effect".into());}
        *original=Some(post);self.permission_live()
    }
    fn unknown(&self){self.stage.store(FAILED,Ordering::Release);self.round.mark_unknown();}
    pub(super) async fn prepare(round:Arc<RegisteredDrainRound>,kind:MetadataKind,offline:Option<Arc<VerifiedTerminalOfflineSet>>)->Result<Arc<Self>,String>{
        round.require_live()?;
        let processes=round.processes.try_lock().map_err(|_|"terminal original actual process proof root busy")?.as_ref().cloned()
            .ok_or("terminal metadata cannot precede actual original process/namespace drain")?;
        processes.require_same(&round)?;
        if (kind==MetadataKind::CommitDetached)!=offline.is_some(){return Err("terminal metadata purpose lacks exact genuine offline producer".into());}
        if let Some(proof)=&offline{proof.require_current(&round)?;}
        let pre={let world=round.shared.world.try_read().map_err(|_|"terminal metadata pre-scope actual source busy")?;graph(&round,&world,kind.before())?};
        let prepared=Arc::new(Self{round:round.clone(),kind,stage:AtomicU8::new(ROOTED),pre,post:Mutex::new(None),permission:Mutex::new(None),offline,outcome:Mutex::new(None)});
        {let mut roots=round.metadata.try_lock().map_err(|_|"terminal metadata original roots busy")?;
            if roots.len()>=2||roots.iter().any(|p|p.kind==kind){return Err("terminal metadata purpose already attempted/UNKNOWN; no retry".into());}
            roots.push(prepared.clone());}
        let mut retain=RetainOriginal{prepared:prepared.clone(),finished:false};
        let node=round.node_jobs.try_lock().map_err(|_|"terminal metadata issuer node root busy")?.get(&round.shared.pool.node_uid).cloned()
            .ok_or("terminal metadata issuer has no original actual resource/node job")?;
        let original=prepared.clone();let journal=round.shared.journal.clone();
        round.shared.io.run(move||journal.terminal_record(&original.round.plan.budget,&original.round.plan.operation.uid,
            original.kind.records().0,&original.round.plan.uid,&serde_json::json!({"purpose":format!("{:?}",original.kind),"pre_graph":original.pre}))).await?;
        let permission=wire::local_observation(&round,&node,620,kind.effect(),prepared.pre.clone(),&(format!("{kind:?}"),&prepared.pre)).await?;
        permission.consume_resource(&prepared.pre)?;
        *prepared.permission.lock().unwrap_or_else(|p|p.into_inner())=Some(permission);
        prepared.stage.compare_exchange(ROOTED,AUTHORIZED,Ordering::AcqRel,Ordering::Acquire).map_err(|_|"terminal metadata authorization invalidated")?;
        prepared.permission_live()?;retain.finished=true;Ok(prepared)
    }
    pub(super) async fn execute(self:&Arc<Self>)->Result<(),String>{
        let mut retain=RetainOriginal{prepared:self.clone(),finished:false};self.permission_live()?;
        self.stage.compare_exchange(AUTHORIZED,SUBMITTED,Ordering::AcqRel,Ordering::Acquire).map_err(|_|"terminal metadata submission already consumed")?;
        let value=self.clone();let current=self.round.shared.world.clone();
        let result=self.round.shared.io.run(move||{
            let actual=crate::storage_lifecycle::pod_attachment::commit_terminal_in_owned_io(&current,&value);
            let outcome=match &actual{Ok(())=>serde_json::json!({"actual_store_ack":true,"late":Instant::now()>=value.round.deadline}),
                Err(error)=>serde_json::json!({"actual_store_ack":false,"error_sha256":digest(format!("{error:?}").as_bytes())})};
            *value.outcome.lock().unwrap_or_else(|p|p.into_inner())=Some(outcome.clone()); // original IO result BEFORE any fallible evidence/send.
            value.round.shared.journal.terminal_record(&value.round.plan.budget,&value.round.plan.operation.uid,
                value.kind.records().1,&value.round.plan.uid,&outcome)?;
            Ok(actual.map_err(|error|format!("terminal original metadata outcome retained: {error:?}")))
        }).await?;
        result?;self.pure_live()?;
        if !actual_ack_timely(Instant::now(),self.round.deadline){return Err("original terminal store ACK arrived after original deadline; retained outcome only".into());}
        self.stage.compare_exchange(SUBMITTED,ACKED,Ordering::AcqRel,Ordering::Acquire).map_err(|_|"terminal metadata late/invalid ACK")?;
        // Record the actually ACKed phase before obtaining confirmation. A
        // failed confirmation leaves that real phase visible, never a retry.
        match self.kind{MetadataKind::BeginDetaching=>self.round.begun.store(true,Ordering::Release),MetadataKind::CommitDetached=>{
            let proof=self.offline()?;
            *self.round.detached_evidence.lock().unwrap_or_else(|p|p.into_inner())=Some(proof.evidence_sha256().into());
            self.round.detached.store(true,Ordering::Release);
        }}
        let node=self.round.node_jobs.try_lock().map_err(|_|"terminal confirm issuer node root busy")?.get(&self.round.shared.pool.node_uid).cloned().ok_or("terminal actual issuer node absent")?;
        let post=self.post.try_lock().map_err(|_|"terminal actual post-scope busy")?.clone().ok_or("terminal commit had no exact post-scratch scope")?;
        let confirm=wire::local_observation(&self.round,&node,621,self.kind.effect(),post.clone(),&("post-ACK-confirm",format!("{:?}",self.kind),&post)).await?;
        {let world=self.round.shared.world.try_read().map_err(|_|"terminal actual confirm source busy")?;
            if graph(&self.round,&world,self.kind.after())?!=post{return Err("terminal confirmed current graph differs from actual committed post scope".into());}}
        confirm.consume_resource(&post)?;self.pure_live()?;
        self.stage.compare_exchange(ACKED,CONFIRMED,Ordering::AcqRel,Ordering::Acquire).map_err(|_|"terminal confirm invalidated at last edge")?;
        retain.finished=true;Ok(())
    }
    pub(super) fn require_confirmed(&self)->Result<(),String>{
        self.pure_live()?;
        if self.stage.load(Ordering::Acquire)!=CONFIRMED{return Err("actual terminal metadata confirmation absent/late/UNKNOWN".into());}Ok(())
    }
}
fn actual_ack_timely(now:Instant,original_deadline:Instant)->bool{now<original_deadline}
fn graph(round:&RegisteredDrainRound,world:&DesiredWorld,phase:TerminalWorldPhase)->Result<String,String>{
    round.check_world_phase(world,phase)?;
    let reference=round.plan.operation.key.references.values().next().ok_or("terminal exact V1 reference absent")?;
    let volume=world.storage_identities.lifecycle.get(reference.volume_uid()).ok_or("terminal graph exact dataset absent")?;
    let owner=volume.owner();let key=crate::store::obj_key(&owner.namespace,&owner.claim_name);
    let pvc=world.pvcs.get(&key).ok_or("terminal graph PVC absent")?;let pv=world.pvs.get(&owner.pv_name).ok_or("terminal graph PV absent")?;
    let class=world.storage_classes.get(&pv.storage_class).ok_or("terminal graph StorageClass absent")?;
    Ok(digest(&serde_json::to_vec(&("terminal-exact-current-group-v1",volume,pv,pvc,class,
        world.storage_identities.namespaces.get(&owner.namespace),world.storage_identities.claims.get(&key),&round.plan.operation.key))
        .map_err(|_|"terminal exact graph encode failed")?))
}

#[cfg(test)]
mod tests{
    use super::*;
    #[test] fn actual_terminal_ack_success_at_or_after_original_deadline_is_not_confirmed(){
        // Clock DATA only, no round/permission or physical proof constructor.
        let start=Instant::now();let deadline=start+Duration::from_secs(180);
        assert!(actual_ack_timely(deadline-Duration::from_nanos(1),deadline));
        assert!(!actual_ack_timely(deadline,deadline));
        assert!(!actual_ack_timely(deadline+Duration::from_secs(1),deadline));
    }
    #[test] fn terminal_metadata_before_after_phase_matrix_never_reuses_old_attach_ready(){
        assert!(MetadataKind::BeginDetaching.before()==TerminalWorldPhase::OriginalAttached);
        assert!(MetadataKind::BeginDetaching.after()==TerminalWorldPhase::Detaching);
        assert!(MetadataKind::CommitDetached.before()==TerminalWorldPhase::Detaching);
        assert!(MetadataKind::CommitDetached.after()==TerminalWorldPhase::Detached);
        assert!(MetadataKind::BeginDetaching.effect()!=MetadataKind::CommitDetached.effect());
    }
}
