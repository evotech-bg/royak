//! One existing Watch controller continuation. Histories below are DATA only;
//! new writer authority comes only from a successful actual sealed-Core commit.
use super::*;
use crate::storage_lifecycle::pod_attachment::{InitialReplicaLineage,ExpectedAttachScope,AttachPhase,AttachReplicaTarget};
use crate::storage_pod_writer::{PodWriterRequest,CommittedPodWriterIntent};
use crate::storage_remote_protocol::attachment as wire;
use std::sync::atomic::{AtomicBool,Ordering};

pub(super) struct WriterReservation {operation:Uid,result:Mutex<Option<Result<Arc<CommittedPodWriterIntent>,String>>>,taken:AtomicBool,
    prepared:Mutex<Option<crate::storage_pod_writer::WriterReservationOwner>>}
struct RetainReservation {book:Arc<MountBook>,operation:Arc<WriterReservation>,finished:bool}
impl Drop for RetainReservation {fn drop(&mut self){if !self.finished{
    if let Some(prepared)=self.operation.prepared.lock().unwrap_or_else(|p|p.into_inner()).as_ref(){prepared.invalidate();}
    self.book.quarantine("normal writer reservation/actor UNKNOWN; original result retained");
}}}
struct RetainController {book:Arc<MountBook>,finished:bool}
impl Drop for RetainController {fn drop(&mut self){if !self.finished{self.book.quarantine("normal attach controller dropped/failed; no automatic continuation");}}}
#[derive(Clone,serde::Serialize)]
struct Candidate {namespace:String,workload:String,pod:String,ordinal:Option<u32>,epochs:BTreeMap<Uid,u64>}
/// Only the ACTUAL same-Watch successful release owner can register a slot.
/// This does not add a next-volume init loop or reconstruct a lost owner.
pub(in crate::storage_driver::native_runtime) async fn retain_released_slot(shared:&Arc<Shared>,
    owner:Arc<dispatcher::distributed_init::HeldInitializationOwner>)->Result<(),String>{
    if !shared.config.attaches(){return Ok(());}
    let slot=owner.released_slot()?;
    let volume=owner.reference().volume_uid.clone();
    let observed=core::observe_local_async(&volume).await?;
    if observed.volume().phase()!=Phase::Detached || observed.volume().epoch()!=0
        || observed.volume().assignment().is_some() || observed.volume().pod_writer().is_some(){
        return Err("released slot handoff is not actual initialized Detached epoch0".into());
    }
    let dataset=observed.volume().data_generation().ok_or("released slot initialized dataset absent")?.uid.clone();
    let node=shared.pool.node_uid.clone();let boot=observed.actual_boot().clone();
    let root=shared.config.delegated_cgroup_root.clone();let budget=shared.dispatcher_configuration().budget;
    let check=slot.clone();let checked_volume=volume.clone();let checked_dataset=dataset.clone();
    shared.io.run(move||check.inspect_empty(&root,&node,&boot,&checked_volume,&checked_dataset,&budget).map(|_|())).await?;
    let book=MountBook::from_actual_runtime(shared).await?;
    let mut state=book.state.lock().map_err(|_|"released slot book poisoned")?;
    if state.unknown.is_some() || book.invalid.load(Ordering::Acquire){return Err("released slot book UNKNOWN".into());}
    if let Some((actual_dataset,actual_slot))=state.released_slots.get(&volume){
        if actual_dataset==&dataset && Arc::ptr_eq(actual_slot,&slot){return Ok(());}
        return Err("released slot already has another actual dataset/owner; no replacement".into());
    }
    if state.released_slots.len()>=128 {return Err("released slot history bound exhausted".into());}
    state.released_slots.insert(volume,(dataset,slot));Ok(())
}
/// DATA-routing only. It does not construct T or supply physical authority.
fn exact_released_slot<'a,T>(slots:&'a BTreeMap<Uid,(Uid,T)>,volume:&Uid,dataset:&Uid)->Result<&'a T,String>{
    let (actual,value)=slots.get(volume).ok_or("actual per-volume released slot absent; no scan/single-owner fallback")?;
    if actual!=dataset{return Err("actual per-volume released slot dataset differs".into());}
    Ok(value)
}
/// Loop-control DATA only. Inspect is NOT readiness, a grant or an owner: the
/// real indexed slot's actual FD/current Core observations remain mandatory.
#[derive(Debug,PartialEq,Eq)]
enum HandoffHint {Wait,Inspect,Refuse}
fn handoff_hint(indexed:bool,incoming:bool,busy:bool,invalid:bool)->HandoffHint {
    if invalid {HandoffHint::Refuse}
    else if !indexed || incoming || busy {HandoffHint::Wait}
    else {HandoffHint::Inspect}
}
/// The SAME controller waits without constructing a MountBook or touching the
/// dispatcher journal. In particular Provisioning metadata on a follower is
/// NOT its same-process local release/handoff. While cold/init is active this
/// performs no Inspector/identity IO, so its independent RPC can make progress.
pub(in crate::storage_driver::native_runtime) async fn wait_for_post_init_release(
    shared:&Arc<Shared>,interval:u64)->Result<(),String>{
    if !shared.config.attaches() || interval==0 {
        return Err("post-init attach handoff requires opted-in existing controller cadence".into());
    }
    loop {
        if !core::is_actual_world(&shared.world) {
            return Err("post-init handoff lost actual Raft world".into());
        }
        let mut invalid=shared.pipeline_invalid.load(Ordering::Acquire);
        let indexed=if let Some(book)=ROOTED_BOOK.get() {
            if !Arc::ptr_eq(book.world(),&shared.world) || book.node!=shared.pool.node_uid {
                return Err("post-init handoff book belongs to another actual Watch/node".into());
            }
            let state=book.state.lock().map_err(|_|"post-init handoff index poisoned")?;
            invalid|=book.invalid.load(Ordering::Acquire)||state.unknown.is_some();
            state.released_slots.iter().next().map(|(volume,(dataset,slot))|
                (book.clone(),volume.clone(),dataset.clone(),slot.clone()))
        } else {None};
        match handoff_hint(indexed.is_some(),shared.incoming.load(Ordering::Acquire),
            shared.dispatcher.busy(),invalid) {
            HandoffHint::Refuse=>return Err("post-init handoff is UNKNOWN; no normal attach".into()),
            HandoffHint::Wait=>{
                tokio::time::sleep(Duration::from_secs(interval)).await;
                continue;
            },
            HandoffHint::Inspect=>(),
        }
        let (book,volume,dataset,slot)=indexed.ok_or("actual indexed release disappeared")?;
        shared.check_attach_config().await?; // deliberately NOT old pipeline_deadline
        let observed=core::observe_local_async(&volume).await?;
        if observed.local_node_uid()!=Some(&shared.pool.node_uid) || observed.actual_boot()!=book.current_boot()
            || observed.volume().phase()!=Phase::Detached || observed.volume().epoch()!=0
            || observed.volume().assignment().is_some() || observed.volume().pod_writer().is_some()
            || observed.volume().data_generation().is_none_or(|g|g.uid!=dataset) {
            return Err("post-init handoff no longer names current never-attached local dataset/boot".into());
        }
        let root=shared.config.delegated_cgroup_root.clone();let node=shared.pool.node_uid.clone();
        let boot=observed.actual_boot().clone();let expected_volume=volume.clone();let expected_dataset=dataset.clone();
        let budget=shared.dispatcher_configuration().budget;
        if !shared.io.run(move||slot.inspect_empty(&root,&node,&boot,&expected_volume,&expected_dataset,&budget)).await? {
            return Err("actual same-process released slot was not proved empty".into());
        }
        let after=core::observe_local_async(&volume).await?;
        if !core::is_actual_world(&shared.world) || after.local_node_uid()!=Some(&shared.pool.node_uid)
            || after.actual_boot()!=book.current_boot() || after.volume().phase()!=Phase::Detached
            || after.volume().epoch()!=0 || after.volume().assignment().is_some() || after.volume().pod_writer().is_some()
            || after.volume().data_generation().is_none_or(|g|g.uid!=dataset)
            || shared.pipeline_invalid.load(Ordering::Acquire) || book.invalid.load(Ordering::Acquire) {
            return Err("actual post-init handoff changed during FD/Core observations".into());
        }
        if shared.incoming.load(Ordering::Acquire)||shared.dispatcher.busy() {
            tokio::time::sleep(Duration::from_secs(interval)).await;
            continue;
        }
        return Ok(()); // flow only; new round still needs fresh full authority
    }
}
pub(in crate::storage_driver::native_runtime) async fn remember_after_actual_release(shared:&Arc<Shared>,
    committed:&crate::storage_lifecycle::generation::CommittedGeneration,history:InitialReplicaLineage)->Result<(),String>{
    if !shared.config.attaches() || !core::is_actual_world(&shared.world) {return Err("historical handoff requires actual opted-in Watch".into());}
    // Called only after release_all returns actual success. These observations
    // do NOT themselves manufacture a release or a future mount capability.
    if shared.incoming.load(Ordering::Acquire)||shared.dispatcher.busy()||shared.pipeline_invalid.load(Ordering::Acquire){
        return Err("initialization handoff is still active/UNKNOWN".into());
    }
    {
        let current=shared.world.try_read().map_err(|_|"historical handoff Core busy")?;
        let volume=current.storage_identities.lifecycle.get(&committed.owner().volume_uid).ok_or("historical initialized volume absent")?;
        if volume.data_generation()!=Some(committed.generation()){return Err("historical initialized dataset changed".into());}
        history.check_initial_generation(volume)?;
    }
    let book=MountBook::from_actual_runtime(shared).await?;
    let mut state=book.state.lock().map_err(|_|"historical book poisoned")?;
    if state.unknown.is_some() || state.initialized.len()>=128 || state.initialized.contains_key(&committed.owner().volume_uid){
        return Err("historical cache duplicate/full/UNKNOWN; no reconstruction".into());
    }
    state.initialized.insert(committed.owner().volume_uid.clone(),history);Ok(())
}
pub(super) async fn readiness(shared:&Arc<Shared>,volume:&Uid)->Result<wire::Readiness,String>{
    shared.check_attach_config().await?;
    if shared.pipeline_invalid.load(Ordering::Acquire){return Err("actual prior runtime UNKNOWN".into());}
    let observed=core::observe_local_async(volume).await?;
    let directory=shared.directory_for(&observed)?;
    let generation=observed.volume().data_generation().ok_or("attach readiness dataset not initialized")?;
    let local=observed.local_node_uid().ok_or("actual ready local identity absent")?;
    let fact=generation.virgin_replicas.iter().find(|f|&f.node_uid==local).ok_or("actual local node is not initialized replica")?;
    if observed.volume().phase()!=Phase::Detached || observed.volume().epoch()!=0 || observed.volume().assignment().is_some()
        || observed.volume().pod_writer().is_some() || local!=&shared.pool.node_uid || fact.pool_uid!=shared.pool.pool_uid {
        return Err("attach readiness differs from current never-attached dataset/node/pool".into());
    }
    // Cold availability correctly refuses every existing leaf. First attach
    // instead needs the SAME actual released-init FD retained by this Watch;
    // an apparently empty scanned leaf is never adopted as ownership.
    let released = {
        let book=ROOTED_BOOK.get().ok_or("actual released-slot book absent; no reconstruction")?;
        if !Arc::ptr_eq(book.world(),&shared.world){return Err("released slot book belongs to another actual Watch".into());}
        let state=book.state.lock().map_err(|_|"actual released slot book poisoned")?;
        if state.unknown.is_some() || book.invalid.load(Ordering::Acquire){return Err("actual released-slot book UNKNOWN".into());}
        exact_released_slot(&state.released_slots,volume,&generation.uid)?.clone()
    };
    let root=shared.config.delegated_cgroup_root.clone();let node=shared.pool.node_uid.clone();
    let boot=observed.actual_boot().clone();let dataset=generation.uid.clone();let checked_volume=volume.clone();
    let budget=shared.dispatcher_configuration().budget;
    let slot=shared.io.run(move||released.inspect_empty(&root,&node,&boot,&checked_volume,&dataset,&budget)).await?;
    let available=slot&&!shared.dispatcher.busy()&&!shared.incoming.load(Ordering::Acquire)
        && ROOTED_BOOK.get().is_none_or(|book|!book.invalid.load(Ordering::Acquire));
    Ok(wire::Readiness {volume:volume.clone(),node:local.clone(),boot:observed.actual_boot().clone(),
        pool:shared.pool.pool_uid.clone(),directory_sha256:directory.digest().into(),revision:observed.revision().clone(),available})
}
fn candidate(world:&DesiredWorld,histories:&BTreeMap<Uid,InitialReplicaLineage>,allowlist:&[String])->Result<Option<Candidate>,String>{
    let mut keys=world.deployments.keys().collect::<Vec<_>>();keys.sort();
    for key in keys {
        let workload=&world.deployments[key];
        if workload.paused || workload.replicas==0 || workload.containers.is_empty(){continue;}
        let mut epochs=BTreeMap::new();let mut eligible=true;let mut native=false;
        for container in workload.init_containers.iter().chain(&workload.containers){
            for (source,_) in &container.volumes{
                let Some(claim)=source.strip_prefix("pvc:")else{
                    if !(source.starts_with("cmv:")||source.starts_with("sev:")||source.starts_with("emptydir:")){eligible=false;}
                    continue;
                };
                let claim_key=crate::store::obj_key(&workload.namespace,claim);
                let Some(pvc)=world.pvcs.get(&claim_key)else{eligible=false;continue;};
                let Some(pv_name)=&pvc.bound_pv else{eligible=false;continue;};
                let Some(pv)=world.pvs.get(pv_name)else{eligible=false;continue;};
                if !world.storage_classes.get(&pv.storage_class).is_some_and(|class|class.provisioner==crate::storage_lifecycle::PROVISIONER)
                    || !allowlist.contains(&pv.storage_class){eligible=false;continue;}
                native=true;
                let Some(uid)=world.storage_identities.volumes.get(pv_name)else{eligible=false;continue;};
                let Some(volume)=world.storage_identities.lifecycle.get(uid)else{eligible=false;continue;};
                let Some(history)=histories.get(uid)else{eligible=false;continue;};
                if volume.phase()!=Phase::Detached || volume.epoch()!=0 || volume.assignment().is_some() || volume.pod_writer().is_some()
                    || volume.owner().namespace!=workload.namespace || volume.owner().claim_name!=claim
                    || history.check_initial_generation(volume).is_err(){eligible=false;continue;}
                epochs.insert(uid.clone(),0);
            }
        }
        if !native || !eligible || epochs.is_empty(){continue;}
        if epochs.len()>8{return Err("normal managed Pod exceeds existing8-volume bound".into());}
        let ordinal=if workload.stateful {
            let empty=std::collections::HashSet::new();
            Some(crate::reconcile::next_statefulset_ordinal(&empty,&empty,workload.replicas).ok_or("no actual first StatefulSet slot")?)
        }else{None};
        let index=ordinal.unwrap_or(1);
        let pod=format!("{}-{index}",crate::store::pod_stem(&workload.namespace,&workload.name));
        return Ok(Some(Candidate {namespace:workload.namespace.clone(),workload:workload.name.clone(),pod,ordinal,epochs}));
    }Ok(None)
}
async fn collect_readiness(shared:&Arc<Shared>,candidate:&Candidate,view:&core::RuntimeView)
    ->Result<BTreeMap<(Uid,Uid),wire::Readiness>,String>{
    let directory=VerifiedDirectory::from_runtime(view)?;let mut ready=BTreeMap::new();
    for uid in candidate.epochs.keys(){
        let observed=core::observe_local_async(uid).await?;
        for fact in &observed.volume().data_generation().ok_or("pending Pod dataset absent")?.virgin_replicas {
            let data=if fact.node_uid==shared.pool.node_uid {readiness(shared,uid).await?}else{
                let nonce=Uid::new();
                let request=wire::encode_node(&wire::NodeRequest::Readiness {volume:uid.clone(),nonce:nonce.clone()})?;
                let reply=shared.call(wire::OFFER_PATH,&request,&fact.node_uid,&directory).await?;
                if reply.sender()!=&fact.node_uid || reply.receiver()!=&shared.pool.node_uid{return Err("readiness authenticated peer differs".into());}
                match wire::decode_node::<wire::NodeReply>(reply.body())?{
                    wire::NodeReply::Readiness{nonce:actual,observation}if actual==nonce=>observation,
                    _=>return Err("actual readiness nonce/data differs".into()),
                }
            };
            if !data.available || data.volume!=*uid || data.node!=fact.node_uid || data.pool!=fact.pool_uid
                || data.directory_sha256!=directory.digest() || !data.revision.at_least(view.revision()){
                return Err("actual fresh node/pool/slot/directory readiness unavailable".into());
            }
            ready.insert((uid.clone(),fact.node_uid.clone()),data);
        }
    }Ok(ready)
}
async fn reserve_once(shared:&Arc<Shared>,book:&Arc<MountBook>,candidate:&Candidate)->Result<Arc<CommittedPodWriterIntent>,String>{
    let operation=Uid::new();
    let request=PodWriterRequest::new(candidate.namespace.clone(),candidate.workload.clone(),candidate.pod.clone(),
        candidate.ordinal,operation.clone(),candidate.epochs.clone())?;
    let original=Arc::new(WriterReservation {operation:operation.clone(),result:Mutex::new(None),taken:AtomicBool::new(false),prepared:Mutex::new(None)});
    {
        let mut state=book.state.lock().map_err(|_|"actual writer reservation book poisoned")?;
        if state.unknown.is_some()||state.reservation.is_some(){return Err("writer reservation already submitted/UNKNOWN; no new operation".into());}
        state.reservation=Some(original.clone());
    }
    let mut retain=RetainReservation {book:book.clone(),operation:original.clone(),finished:false};
    let journal=shared.journal.clone();let value=candidate.clone();let op=operation.clone();
    shared.io.run(move||journal.attach_reservation(&op,&value)).await?;
    let prepared=crate::storage_pod_writer::prepare_local_pod_writer(&shared.world,request).await.map_err(|e|format!("actual writer prepare denied: {e:?}"))?;
    *original.prepared.lock().map_err(|_|"writer prepared owner slot poisoned")?=Some(prepared.owner());
    let actual=original.clone();
    shared.io.run(move||{
        let outcome=prepared.commit()
            .map(Arc::new).map_err(|e|format!("actual writer reservation not confirmed: {e:?}"));
        *actual.result.lock().unwrap_or_else(|p|p.into_inner())=Some(outcome);
        Ok(())
    }).await?;
    if book.invalid.load(Ordering::Acquire){return Err("writer result arrived after actor invalidation; retained".into());}
    if original.taken.swap(true,Ordering::AcqRel){return Err("actual writer result already consumed".into());}
    // Retain SAME actual ACK object in original IO/root book even if the
    // caller drops while building templates. Arc is metadata ownership only;
    // the one-use registration/parent, never Arc cloning, grants effects.
    let intent=original.result.lock().map_err(|_|"actual writer outcome poisoned")?.as_ref()
        .ok_or("original writer operation has no terminal result; not zero/no effect")?.clone()?;
    {
        let current=shared.world.try_read().map_err(|_|"acknowledged writer current source busy")?;
        intent.check_metadata_current(&current)?;
    }
    retain.finished=true;Ok(intent)
}
async fn templates(shared:&Arc<Shared>,book:&Arc<MountBook>,intent:&CommittedPodWriterIntent,
    ready:&BTreeMap<(Uid,Uid),wire::Readiness>)->Result<Vec<ExpectedAttachScope>,String>{
    let view=core::runtime_view(true).await?;
    let directory=VerifiedDirectory::from_runtime(&view)?;let round=Uid::new();let mut result=Vec::new();
    let histories={book.state.lock().map_err(|_|"actual lineage cache poisoned")?.initialized.clone()};
    for uid in intent.assignments().keys(){
        let observed=core::observe_local_async(uid).await?;
        let current_directory=shared.directory_for(&observed)?;
        if current_directory.digest()!=directory.digest() || !observed.revision().at_least(view.revision()){
            return Err("normal attach source/issuer changed across actual writer ACK".into());
        }
        let volume=observed.volume();let generation=volume.data_generation().ok_or("acknowledged initialized dataset absent")?.clone();
        let replicas=generation.virgin_replicas.iter().map(|fact|{
            let actual=ready.get(&(uid.clone(),fact.node_uid.clone())).ok_or("actual ready target absent")?;
            if actual.pool!=fact.pool_uid || actual.directory_sha256!=directory.digest()
                || actual.revision.term!=view.revision().term || actual.revision.leader_raft_id!=view.revision().leader_raft_id
                || actual.revision.membership_sha256!=view.revision().membership_sha256{
                return Err("ready target changed exact pool/directory/issuer epoch".into());
            }
            Ok(AttachReplicaTarget {node_uid:fact.node_uid.clone(),current_boot:actual.boot.clone(),
                pool_uid:fact.pool_uid.clone(),plan_sha256:fact.plan_sha256.clone()})
        }).collect::<Result<Vec<_>,String>>()?;
        let replicas:[AttachReplicaTarget;3]=replicas.try_into().map_err(|_|"exact three ready targets required")?;
        let scope=ExpectedAttachScope {version:1,owner:volume.owner().clone(),
            mount_ref:crate::storage_pod_writer::ManagedMountRef::from_metadata(volume)?,pod_writer:intent.binding().clone(),
            generation,initial_lineage:histories.get(uid).cloned().ok_or("actual same-process initialized history absent")?,
            phase:AttachPhase::ActivateReplica,phase_node_uid:replicas[0].node_uid.clone(),phase_boot:replicas[0].current_boot.clone(),
            replicas,round_uid:round.clone(),phase_job_uid:Uid::new(),issuer_node_uid:view.local().clone(),issuer_boot:view.boot().clone(),
            issuer_revision:view.revision().clone(),scope_sha256:observed.scope_sha256().into(),directory_sha256:directory.digest().into(),
            remaining_budget_ms:crate::storage_lifecycle::pod_attachment::ATTACH_ROUND_MS};
        scope.check_issuer(&observed,&directory)?;result.push(scope);
    }Ok(result)
}
pub(in crate::storage_driver::native_runtime) async fn run(shared:Arc<Shared>,interval:u64)->Result<(),String>{
    if !shared.config.attaches(){return Ok(());}
    if interval==0{return Err("normal attach actor requires existing positive Watch cadence".into());}
    let book=MountBook::from_actual_runtime(&shared).await?;
    let mut retain=RetainController {book:book.clone(),finished:false};
    loop {
        // Poll/latch the same original terminal DATA slot BEFORE ordinary
        // attach/READY/current-source guards can reject issuer Detaching.
        // No new actor, queue, worker or reconstructed receiver authority.
        if super::consumer::terminal::wire::poll_existing_slot(&shared,&book).await?{
            tokio::time::sleep(Duration::from_secs(interval)).await;
            continue;
        }
        shared.check_attach_config().await?;
        if shared.pipeline_invalid.load(Ordering::Acquire)||book.invalid.load(Ordering::Acquire){return Err("normal attach actor UNKNOWN; no reconstruction".into());}
        let view=core::runtime_view(false).await?;
        let local=crate::raft_node::RAFT.get().ok_or("actual attach Raft absent")?.node_id;
        if local==view.revision().leader_raft_id{
            let histories={book.state.lock().map_err(|_|"normal lineage book poisoned")?.initialized.clone()};
            let pending={let current=shared.world.try_read().map_err(|_|"normal managed workload source busy")?;
                candidate(&current,&histories,&shared.config.storage_class_allowlist)?};
            if let Some(pending)=pending{
                // Repeated observations before submission are not grant/commit/
                // offer retries. Once reserve_once starts, ANY failure exits.
                if let Ok(ready)=collect_readiness(&shared,&pending,&view).await {
                    let intent=reserve_once(&shared,&book,&pending).await?;
                    let data=templates(&shared,&book,&intent,&ready).await?;
                    let round=parent::RegisteredAttachRound::register(shared.clone(),intent,data).await?;
                    let _metadata=round.run_registered().await?;
                    // First-epoch normal pipeline only. A later attach epoch,
                    // failover/recovery or another group needs explicit current
                    // live ownership transition, never restart/JSON adoption.
                    retain.finished=true;
                    return super::consumer::run(shared.clone(),book.clone(),interval).await;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn follower_provisioning_without_released_index_only_waits(){
        // Pure loop-hint DATA: neither Provisioning JSON nor an existing
        // dispatcher directory is even an input, much less an FD producer.
        for incoming in [false,true] {for busy in [false,true] {
            assert_eq!(handoff_hint(false,incoming,busy,false),HandoffHint::Wait);
        }}
    }
    #[test]
    fn indexed_but_active_handoff_never_skips_actual_release_observation(){
        for (incoming,busy) in [(true,false),(false,true),(true,true)] {
            assert_eq!(handoff_hint(true,incoming,busy,false),HandoffHint::Wait);
        }
        // Inspect is deliberately not a Ready variant/capability. The live
        // caller must still have the genuine slot and perform its actual IO.
        assert_eq!(handoff_hint(true,false,false,false),HandoffHint::Inspect);
    }
    #[test]
    fn unknown_handoff_is_refusal_for_every_index_and_busy_hint(){
        for indexed in [false,true] {for incoming in [false,true] {for busy in [false,true] {
            assert_eq!(handoff_hint(indexed,incoming,busy,true),HandoffHint::Refuse);
        }}}
    }
    #[test]
    fn released_slot_data_routing_keeps_two_exact_volume_dataset_pairs_separate(){
        let first=Uid::new();let second=Uid::new();let first_dataset=Uid::new();let second_dataset=Uid::new();
        // Literal markers are DATA, not fake FDs or actual provenance slots.
        let data=BTreeMap::from([(first.clone(),(first_dataset.clone(),"first DATA")),
            (second.clone(),(second_dataset.clone(),"second DATA"))]);
        assert_eq!(*exact_released_slot(&data,&first,&first_dataset).unwrap(),"first DATA");
        assert_eq!(*exact_released_slot(&data,&second,&second_dataset).unwrap(),"second DATA");
        assert!(exact_released_slot(&data,&first,&second_dataset).is_err());
        assert!(exact_released_slot(&data,&second,&first_dataset).is_err());
    }
    #[test]
    fn released_slot_data_routing_has_no_last_owner_or_missing_history_fallback(){
        let first=Uid::new();let last=Uid::new();let dataset=Uid::new();
        let data=BTreeMap::from([(last.clone(),(dataset.clone(),"last DATA"))]);
        assert!(exact_released_slot(&data,&first,&dataset).is_err());
        assert!(exact_released_slot(&data,&last,&Uid::new()).is_err());
        let absent:BTreeMap<Uid,(Uid,&str)>=BTreeMap::new();
        assert!(exact_released_slot(&absent,&last,&dataset).is_err());
    }
    #[test]
    fn normal_candidate_never_rebuilds_initialized_history_from_core_json(){
        let (world,_,_,_)=crate::storage_lifecycle::model_pod_writer_world();
        let allow=world.storage_classes.keys().cloned().collect::<Vec<_>>();
        assert!(candidate(&world,&BTreeMap::new(),&allow).unwrap().is_none());
    }
    #[test]
    fn paused_or_missing_managed_source_never_creates_normal_candidate(){
        let (mut world,_,_,_)=crate::storage_lifecycle::model_pod_writer_world();
        for deployment in world.deployments.values_mut(){deployment.paused=true;}
        assert!(candidate(&world,&BTreeMap::new(),&["managed".into()]).unwrap().is_none());
        world.deployments.clear();assert!(candidate(&world,&BTreeMap::new(),&["managed".into()]).unwrap().is_none());
    }
}

