//! Before/scratch/after Mounted commit, rooted independently of caller future.
use super::*;
use super::parent::{ExpectedAttachJob,VerifiedAttachParent};
use crate::storage_remote_protocol::attachment::{self as wire,Purpose};
use crate::storage_lifecycle::pod_attachment::CommittedAttachment;
use crate::store::CommitError;
use std::sync::atomic::{AtomicU8,Ordering};

const ROOTED:u8=0;const PREPARED:u8=1;const SUBMITTED:u8=2;const ACKED:u8=3;const READY:u8=4;const UNKNOWN:u8=5;
pub(crate) struct PreparedMountedCommit {
    round:Arc<VerifiedMountedRound>,expected:Arc<ExpectedAttachJob>,shared:Arc<Shared>,
    original:Instant,detail:String,pre_graph:String,post_graph:Mutex<Option<String>>,
    permission:Mutex<Option<wire::OnePermission>>,stage:AtomicU8,
    outcome:Mutex<Option<ObservedCommitOutcome>>,
}
#[derive(serde::Serialize)]
enum ObservedCommitOutcome {
    Confirmed {writer:crate::storage_pod_writer::PodWriterUid,evidence:BTreeMap<Uid,String>,late_at_observation:bool},
    NotConfirmed {reason:String,reason_sha256:String},
}
struct RetainOnDrop {prepared:Arc<PreparedMountedCommit>,finished:bool}
impl Drop for RetainOnDrop {fn drop(&mut self){if !self.finished {self.prepared.unknown("mounted commit caller dropped/failed");}}}
impl MountBook {
    pub(super) fn mounted_group_digest(self:&Arc<Self>,writer:&crate::storage_pod_writer::PodWriterUid)->Result<String,String>{
        let state=self.state.lock().map_err(|_|"mounted book poisoned")?;
        if state.unknown.is_some() || state.owners.is_empty() || state.owners.len()>8 {return Err("mounted group absent/unknown".into());}
        let mut rows=Vec::new();
        for (uid,owner) in &state.owners {
            let witness=owner.rooted_mount_witness()?;
            if witness.reference().writer_uid()!=writer {return Err("mounted group mixes PodWriterUIDs".into());}
            witness.require_commit_live()?;
            rows.push((uid.clone(),witness.reference().clone(),witness.evidence_uid().clone(),witness.evidence_sha256().to_string()));
        }
        Ok(digest(&serde_json::to_vec(&("mounted-complete-group-v1",writer,rows)).map_err(|_|"mounted group hash failed")?))
    }
}
impl PreparedMountedCommit {
    /// Long-lived ownership after the genuine final confirm; deliberately
    /// NOT an old attach action permission or a deadline extension.
    pub(super) fn require_ready_lifetime(&self)->Result<(),String>{
        if self.stage.load(Ordering::Acquire)!=READY || self.round.book.invalid.load(Ordering::Acquire){
            return Err("genuine MountedCommit/Confirm READY lifetime absent".into());
        }
        let state=self.round.book.state.try_lock().map_err(|_|"READY ownership book busy/poisoned")?;
        if state.unknown.is_some() || state.current.as_ref()!=Some(&self.round.round)
            || !state.commit.as_ref().is_some_and(|actual|std::ptr::eq(Arc::as_ptr(actual),self))
            || state.owners.len()!=self.round.witnesses.len() {
            return Err("actual READY mounted group changed/partial/UNKNOWN".into());
        }
        for (uid,witness) in &self.round.witnesses{
            crate::storage_driver::dispatcher::attachment::consumer_lifetime::require_ready_owner_now(
                witness,state.owners.get(uid).ok_or("actual READY owner absent")?)?;
        }
        if self.stage.load(Ordering::Acquire)!=READY || self.round.book.invalid.load(Ordering::Acquire){
            return Err("READY lifetime invalidated during observation".into());}
        Ok(())
    }
    pub(super) fn ready_round(&self)->&Arc<VerifiedMountedRound>{&self.round}
    pub(crate) fn round(&self)->&VerifiedMountedRound{&self.round}
    pub(crate) fn actual_store(&self)->&Arc<RwLock<DesiredWorld>>{self.round.book.world()}
    fn live_owners(&self)->Result<(),String>{
        if self.stage.load(Ordering::Acquire)==UNKNOWN || Instant::now()>=self.original {return Err("mounted commit original round expired/UNKNOWN".into());}
        self.expected.require_live()?;
        self.round.assert_actual_store(&self.shared.world)?;
        for witness in self.round.witnesses.values(){witness.require_commit_live()?;}
        Ok(())
    }
    pub(crate) fn validate_scratch(&self,scratch:&DesiredWorld)->Result<(),String>{
        self.live_owners()?;
        if self.stage.load(Ordering::Acquire)!=SUBMITTED || graph(&self.round,scratch,false)?!=self.pre_graph {
            return Err("mounted prepared permission/current scratch scope changed".into());
        }
        self.permission.lock().map_err(|_|"mounted permission poisoned")?.as_ref().ok_or("mounted commit not actually authorized")?.check_live()?;
        Ok(())
    }
    pub(crate) fn validate_post_scratch(&self,scratch:&DesiredWorld)->Result<(),String>{
        self.live_owners()?;
        self.permission.lock().map_err(|_|"mounted permission poisoned")?.as_ref().ok_or("mounted permission absent")?.check_live()?;
        let next=graph(&self.round,scratch,true)?;
        let mut stored=self.post_graph.lock().map_err(|_|"mounted post-scope poisoned")?;
        if stored.is_some(){return Err("mounted scratch callback repeated".into());}
        *stored=Some(next);
        self.live_owners()
    }
    fn unknown(&self,reason:&str){
        self.stage.store(UNKNOWN,Ordering::Release);
        // Latch ownership BEFORE any fallible evidence path. No removal/reset.
        self.expected.retain_unknown();self.round.book.quarantine(reason);
        for witness in self.round.witnesses.values(){witness.retain_unknown();}
    }
    async fn physical_reobserve(self:&Arc<Self>)->Result<(),String>{
        self.live_owners()?;let value=self.clone();
        self.shared.io.run(move||{
            value.live_owners()?;
            for witness in value.round.witnesses.values(){witness.reobserve_for_commit(value.original)?;}
            value.live_owners()
        }).await?;
        self.live_owners()
    }
    async fn fresh_permission(self:&Arc<Self>,purpose:Purpose)->Result<wire::OnePermission,String>{
        self.live_owners()?;
        let admission=self.expected.admit(purpose,&self.detail)?;
        let journal=self.shared.journal.clone();let expected=self.expected.clone();
        self.shared.io.run(move||journal.attach_admission(&expected,purpose,&admission)).await?;
        self.live_owners()?;
        let request=wire::local_request(&self.expected,purpose,&self.detail)?;
        let observed=core::observe_attach_issuer(&self.expected.scope().owner.volume_uid,&request).await?;
        let directory=self.shared.directory_for(&observed)?;
        {
            let world=self.shared.world.try_read().map_err(|_|"mounted actual Core busy")?;
            if world.generation!=observed.revision().desired_generation
                || world.storage_identities.lifecycle.get(&self.expected.scope().owner.volume_uid)!=Some(observed.volume()){
                return Err("mounted full group changed after THIS coherent Core observation".into());
            }
            let actual=graph(&self.round,&world,purpose==Purpose::MountedCommitConfirm)?;
            let wanted=if purpose==Purpose::MountedCommit {self.pre_graph.clone()}
                else {self.post_graph.lock().map_err(|_|"mounted post-scope poisoned")?.clone().ok_or("no actual committed post-scope")?};
            if actual!=wanted{return Err("mounted expected complete pre/post group changed".into());}
        }
        self.live_owners()?;
        wire::local_permission(&self.expected,request,&observed,&directory)
    }
    pub(crate) async fn execute(self:Arc<Self>)->Result<CommittedAttachment,CommitError>{
        let mut retain=RetainOnDrop {prepared:self.clone(),finished:false};
        let result=self.execute_inner().await;
        if result.is_err(){self.unknown("mounted commit failed/late/ambiguous; retained");}
        retain.finished=result.is_ok();result
    }
    async fn execute_inner(self:&Arc<Self>)->Result<CommittedAttachment,CommitError>{
        self.live_owners().map_err(CommitError::Unknown)?;
        self.stage.compare_exchange(PREPARED,SUBMITTED,Ordering::AcqRel,Ordering::Acquire).map_err(|_|CommitError::Unknown("mounted commit one-use submission state changed".into()))?;
        let value=self.clone();let world=self.shared.world.clone();
        // Existing ONE owned IO worker/queue. Inspector timeout/future Drop
        // cannot drop this captured Arc or original blocking store operation.
        let outcome=self.shared.io.run(move||{
            let actual=crate::storage_lifecycle::pod_attachment::commit_prepared_in_owned_io(&world,&value);
            let observed=match &actual {
                Ok(confirmed)=>ObservedCommitOutcome::Confirmed {writer:confirmed.writer_uid().clone(),evidence:confirmed.evidence().clone(),late_at_observation:Instant::now()>=value.original},
                Err(error)=>{let reason=format!("{error:?}");ObservedCommitOutcome::NotConfirmed {reason:reason.chars().take(1024).collect(),reason_sha256:digest(reason.as_bytes())}},
            };
            // The SAME original IO operation records known outcome in the
            // rooted object BEFORE fallible journal/send. Caller timeout/Drop
            // never turns late known committed data into Ready or erases it.
            let encoded={let mut retained=value.outcome.lock().unwrap_or_else(|p|p.into_inner());
                *retained=Some(observed);
                serde_json::to_vec(retained.as_ref().unwrap()).map_err(|_|"actual mounted outcome encoding failed")?};
            value.shared.journal.attach_outcome(value.expected.scope(),&encoded)?;
            Ok(actual)
        })
            .await.map_err(CommitError::Unknown)?;
        let committed=outcome.map_err(|error|CommitError::Unknown(format!("mounted proposal outcome retained: {error:?}")))?;
        self.live_owners().map_err(CommitError::Unknown)?;
        self.stage.compare_exchange(SUBMITTED,ACKED,Ordering::AcqRel,Ordering::Acquire)
            .map_err(|_|CommitError::Unknown("mounted ACK arrived after invalidation".into()))?;
        self.physical_reobserve().await.map_err(CommitError::Unknown)?;
        let confirmation=self.fresh_permission(Purpose::MountedCommitConfirm).await.map_err(CommitError::Unknown)?;
        let mut state=self.round.book.state.lock().map_err(|_|CommitError::Unknown("mounted book poisoned after ACK".into()))?;
        // Final check occurs AFTER lock wait. No IO or await in this section.
        self.live_owners().map_err(CommitError::Unknown)?;
        confirmation.check_live().map_err(CommitError::Unknown)?;
        if state.unknown.is_some() || state.current.as_ref()!=Some(&self.round.round)
            || !state.commit.as_ref().is_some_and(|same|Arc::ptr_eq(same,self)){
            return Err(CommitError::Unknown("mounted rooted group changed at final Ready edge".into()));
        }
        for (uid,witness) in &self.round.witnesses {
            witness.require_same_root(state.owners.get(uid).ok_or_else(||CommitError::Unknown("mounted owner disappeared".into()))?)
                .map_err(CommitError::Unknown)?;
        }
        confirmation.consume(Purpose::MountedCommitConfirm,&self.detail).map_err(CommitError::Unknown)?;
        self.stage.compare_exchange(ACKED,READY,Ordering::AcqRel,Ordering::Acquire)
            .map_err(|_|CommitError::Unknown("mounted final confirmation invalidated".into()))?;
        // Keep exact owners, FDs, leases and history. READY here confirms only
        // metadata admission, never a Docker start/action capability.
        let _=&mut state;Ok(committed)
    }
}
impl VerifiedMountedRound {
    pub(crate) async fn prepare_mounted_commit(&self,world:&Arc<RwLock<DesiredWorld>>)
        ->Result<Arc<PreparedMountedCommit>,CommitError>{
        self.assert_actual_store(world).map_err(CommitError::Unavailable)?;
        let shared=self.book.shared.upgrade().ok_or_else(||CommitError::Unavailable("actual Watch runtime owner lost".into()))?;
        shared.check_attach_config().await.map_err(CommitError::Unavailable)?;
        let expected_refs=self.witnesses.iter().map(|(uid,w)|(uid.clone(),w.reference().clone())).collect();
        let owned=Arc::new(self.book.mounted_round(&self.writer,&expected_refs).map_err(CommitError::Unavailable)?);
        let first=owned.witnesses.values().next().ok_or_else(||CommitError::Unavailable("empty mounted group".into()))?;
        let scope=first.mounted_scope().map_err(CommitError::Unavailable)?;
        let expected={
            let state=self.book.state.lock().map_err(|_|CommitError::Unavailable("mounted job book poisoned".into()))?;
            state.jobs.get(&scope.phase_job_uid).cloned().ok_or_else(||CommitError::Unavailable("no actual registered final attach parent".into()))?
        };
        if scope!=*expected.scope() || scope.issuer_node_uid!=self.book.node || scope.phase_node_uid!=self.book.node {
            return Err(CommitError::Unavailable("remote writer needs actual leader-side distributed mounted-round producer; no local fallback".into()));
        }
        let original=expected.original_deadline();
        for witness in owned.witnesses.values(){
            witness.require_commit_live().map_err(CommitError::Unavailable)?;
            if witness.original_deadline()!=original {return Err(CommitError::Unavailable("mounted group has different original deadlines".into()));}
        }
        let detail=self.book.mounted_group_digest(&self.writer).map_err(CommitError::Unavailable)?;
        let pre_graph={let current=world.try_read().map_err(|_|CommitError::Unavailable("actual mounted Core busy".into()))?;
            graph(&owned,&current,false).map_err(CommitError::Unavailable)?};
        let prepared=Arc::new(PreparedMountedCommit {round:owned,expected,shared,original,detail,pre_graph,
            post_graph:Mutex::new(None),permission:Mutex::new(None),stage:AtomicU8::new(ROOTED),outcome:Mutex::new(None)});
        {
            let mut state=self.book.state.lock().map_err(|_|CommitError::Unavailable("mounted book poisoned".into()))?;
            if state.unknown.is_some()||state.commit.is_some(){return Err(CommitError::Unavailable("mounted commit already active/UNKNOWN; no retry".into()));}
            state.commit=Some(prepared.clone());
        }
        let mut retain=RetainOnDrop {prepared:prepared.clone(),finished:false};
        let outcome=async {
            prepared.physical_reobserve().await?;
            let permission=prepared.fresh_permission(Purpose::MountedCommit).await?;
            permission.consume(Purpose::MountedCommit,&prepared.detail)?;
            *prepared.permission.lock().map_err(|_|"mounted commit permission poisoned")?=Some(permission);
            prepared.live_owners()?;
            prepared.stage.compare_exchange(ROOTED,PREPARED,Ordering::AcqRel,Ordering::Acquire).map_err(|_|"mounted preparation invalidated")?;
            Ok::<(),String>(())
        }.await;
        if let Err(error)=outcome {prepared.unknown("mounted preparation UNKNOWN");return Err(CommitError::Unknown(error));}
        retain.finished=true;Ok(prepared)
    }
}
fn graph(round:&VerifiedMountedRound,world:&DesiredWorld,post:bool)->Result<String,String>{
    let directory=world.storage_node_directory.directory().ok_or("mounted guarded directory absent")?;
    let mut rows=Vec::new();
    for (uid,witness) in &round.witnesses {
        let volume=world.storage_identities.lifecycle.get(uid).ok_or("mounted dataset disappeared")?;
        if volume.phase()!=if post {Phase::Attached}else{Phase::Attaching}{return Err("mounted group has wrong pre/post phase".into());}
        witness.require_commit_live()?;witness.check_current_volume(volume)?;
        let owner=volume.owner();
        let pv=world.pvs.get(&owner.pv_name).ok_or("mounted PV absent")?;
        let pvc=world.pvcs.get(&crate::store::obj_key(&owner.namespace,&owner.claim_name)).ok_or("mounted PVC absent")?;
        let class=world.storage_classes.get(&pv.storage_class).ok_or("mounted class absent")?;
        let namespace=world.storage_identities.namespaces.get(&owner.namespace).ok_or("mounted namespace incarnation absent")?;
        volume.pod_writer().ok_or("mounted PodWriter absent")?.check_source_current(world)?;
        rows.push((uid,volume,pv,pvc,class,namespace));
    }
    Ok(digest(&serde_json::to_vec(&("mounted-current-group-v1",directory,rows)).map_err(|_|"mounted graph binding failed")?))
}

