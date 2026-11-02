//! Distinct attachment lifetime. This is NOT the one-shot cold/init pipeline.
//! Root-owned entries outlive every ticket/HTTP result/error value. No serde
//! reader reconstructs an actor, mount FD, lease, or completed physical proof.
use super::*;
use crate::storage_lifecycle::pod_attachment::{ExpectedAttachScope,scope_digest};
use crate::storage_pod_writer::{ManagedMountRef,PodWriterUid};
use super::super::dispatcher::attachment::{AttachOwner,RootedMountWitness};
use std::collections::BTreeSet;
#[path="native_runtime_attach_parent.rs"]
pub(crate) mod parent;
#[path="native_runtime_mounted_commit.rs"]
pub(crate) mod commit;
#[path="native_runtime_mount_controller.rs"]
pub(crate) mod normal;
#[path="native_runtime_consumer.rs"]
pub(crate) mod consumer;
#[path="native_runtime_mount_inventory.rs"]
mod inventory;
pub(in crate::storage_driver) use inventory::SameGroupInventoryRoots;
static ROOTED_BOOK:OnceLock<Arc<MountBook>>=OnceLock::new();
pub(super) fn runtime_unknown(world:&Arc<RwLock<DesiredWorld>>){
    if let Some(book)=ROOTED_BOOK.get(){if Arc::ptr_eq(book.world(),world){book.quarantine("actual Watch runtime UNKNOWN");}}
}

/// One bounded actual Watch owner book. This operational ownership index is
/// NOT a second durable writer registry: Assignment/PodWriter remain canonical.
pub(in crate::storage_driver) struct MountBook {
    world:Arc<RwLock<DesiredWorld>>,
    node:Uid,
    boot:BootId,
    state:Mutex<BookState>,
    shared:std::sync::Weak<Shared>,
    invalid:Arc<AtomicBool>,
}
struct BookState {
    current:Option<Uid>,
    owners:BTreeMap<Uid,Arc<AttachOwner>>,
    history:BTreeSet<Uid>,
    unknown:Option<String>,
    round:Option<Arc<parent::RegisteredAttachRound>>,
    jobs:BTreeMap<Uid,Arc<parent::ExpectedAttachJob>>,
    parents:BTreeMap<Uid,Arc<parent::VerifiedAttachParent>>,
    pending_receivers:BTreeMap<Uid,Arc<Mutex<protocol::attachment::Receiver>>>,
    receiver_clocks:BTreeMap<Uid,Arc<Mutex<Instant>>>,
    tickets:BTreeMap<Uid,Arc<Mutex<parent::RootedTicket>>>,
    initialized:BTreeMap<Uid,crate::storage_lifecycle::pod_attachment::InitialReplicaLineage>,
    released_slots:BTreeMap<Uid,(Uid,Arc<dispatcher::distributed_init::ReleasedInitializationSlot>)>,
    reservation:Option<Arc<normal::WriterReservation>>,
    progress:BTreeMap<Uid,usize>,
    commit:Option<Arc<commit::PreparedMountedCommit>>,
    consumer:consumer::ConsumerBook,
    terminal_preparations:BTreeMap<Uid,Arc<consumer::terminal::wire::ReceiverPreparation>>,
}
impl MountBook {
    /// The private runtime calls this only after its existing startup/source
    /// checks. Actual sealed Core/directory/local boot are checked again here.
    pub(in crate::storage_driver) async fn from_actual_runtime(shared:&Arc<Shared>)->Result<Arc<Self>,String> {
        if !core::is_actual_world(&shared.world) {return Err("mount book requires actual Raft world".into());}
        if let Some(book)=ROOTED_BOOK.get() {
            if Arc::ptr_eq(book.world(),&shared.world) && book.current_boot()==&BootId::current()? {return Ok(book.clone());}
            return Err("a different actual mount book is already rooted; no replacement/adoption".into());
        }
        let view=core::runtime_view(false).await?;
        if view.local()!=&shared.pool.node_uid || view.boot()!=&BootId::current()?
            || view.directory().cluster_id!=shared.pool.cluster_id {
            return Err("mount book has no exact actual enrolled local runtime".into());
        }
        let configuration=shared.dispatcher_configuration();
        let history=shared.io.run(move || {
            // Read-only admission. Active/installed/unknown journal or existing
            // publication is explicit recovery, NEVER reconstructed ownership.
            super::super::dispatcher::attachment::read_closed_history_only(&configuration)
        }).await?;
        let book=Arc::new(Self {world:shared.world.clone(),node:view.local().clone(),boot:view.boot().clone(),shared:Arc::downgrade(shared),invalid:Arc::new(AtomicBool::new(false)),
            state:Mutex::new(BookState {current:None,owners:BTreeMap::new(),history,unknown:None,
                round:None,jobs:BTreeMap::new(),parents:BTreeMap::new(),pending_receivers:BTreeMap::new(),receiver_clocks:BTreeMap::new(),tickets:BTreeMap::new(),initialized:BTreeMap::new(),released_slots:BTreeMap::new(),reservation:None,progress:BTreeMap::new(),commit:None,consumer:consumer::ConsumerBook::new(),terminal_preparations:BTreeMap::new()})});
        ROOTED_BOOK.set(book.clone()).map_err(|_|"mount book already rooted concurrently; no replacement")?;
        Ok(book)
    }
    pub(super) fn world(&self)->&Arc<RwLock<DesiredWorld>> {&self.world}
    pub(super) fn current_boot(&self)->&BootId {&self.boot}
    /// Only an actual private dispatcher owner enters this map. The caller
    /// does not transfer away the map's strong reference when enqueue fails.
    pub(in crate::storage_driver) fn retain_before_enqueue(self:&Arc<Self>,owner:Arc<AttachOwner>)->Result<(),String> {
        owner.assert_actual_store(&self.world)?;
        let scope=owner.scope();scope.validate()?;
        if scope.phase_node_uid!=self.node || scope.phase_boot!=self.boot || self.boot!=BootId::current()? {
            return Err("rooted mount work has another actual local node/boot".into());
        }
        let mut state=self.state.lock().map_err(|_|"mount book poisoned; retain all owners")?;
        if state.unknown.is_some() || state.history.len()>=128 && !state.history.contains(&scope.round_uid) || state.owners.len()>=8
            || state.current.as_ref().is_some_and(|uid|uid!=&scope.round_uid)
            || state.owners.contains_key(scope.mount_ref.volume_uid()) {
            return Err("mount owner slot/history is active, unknown, duplicate or bounded-full".into());
        }
        state.current=Some(scope.round_uid.clone());state.history.insert(scope.round_uid.clone());
        state.owners.insert(scope.mount_ref.volume_uid().clone(),owner);
        Ok(())
    }
    pub(super) fn quarantine(&self,reason:&str) {
        self.invalid.store(true,Ordering::Release);
        let mut state=self.state.lock().unwrap_or_else(|e|e.into_inner());
        if state.unknown.is_none() {state.unknown=Some(reason.chars().take(256).collect());}
        for owner in state.owners.values() {owner.mark_unknown();}
        // No clear/reset, lease release, unmount, demotion, caller-dependent
        // Arc drop or journal-based owner reconstruction occurs here.
    }
    pub(super) fn root_for(&self,uid:&Uid)->Result<Arc<AttachOwner>,String> {
        let state=self.state.lock().map_err(|_|"mount book unavailable; no action")?;
        if state.unknown.is_some() {return Err("mount book UNKNOWN; no new action".into());}
        state.owners.get(uid).cloned().ok_or("exact actual rooted mount owner absent".into())
    }
    pub(super) fn mounted_round(self:&Arc<Self>,writer:&PodWriterUid,
        expected:&BTreeMap<Uid,ManagedMountRef>)->Result<VerifiedMountedRound,String> {
        if expected.is_empty() || expected.len()>8 || !core::is_actual_world(&self.world) {
            return Err("bounded actual mounted Pod group required".into());
        }
        let state=self.state.lock().map_err(|_|"mount book unavailable")?;
        if state.unknown.is_some() || state.owners.len()!=expected.len() {
            return Err("partial/unknown mount group cannot acknowledge Attached".into());
        }
        let mut witnesses=BTreeMap::new();
        for (uid,reference) in expected {
            if reference.writer_uid()!=writer {return Err("mounted group has mixed durable PodWriterUIDs".into());}
            let owner=state.owners.get(uid).ok_or("mounted group owner missing")?;
            let witness=owner.rooted_mount_witness()?;
            if witness.reference()!=reference {return Err("actual mounted witness has another canonical reference".into());}
            witnesses.insert(uid.clone(),witness);
        }
        let round=state.current.clone().ok_or("mounted group has no actual round")?;
        Ok(VerifiedMountedRound {book:self.clone(),round,writer:writer.clone(),witnesses})
    }
}

/// Cannot be made from wire DATA. Only the book can collect these from its
/// ACTUAL installed owner objects after supervisor drain and Watch FD probes.
/// Borrowed throughout store::commit: failed/lost ACK never drops ownership.
pub(crate) struct VerifiedMountedRound {
    book:Arc<MountBook>,
    round:Uid,
    writer:PodWriterUid,
    witnesses:BTreeMap<Uid,RootedMountWitness>,
}
impl VerifiedMountedRound {
    pub(crate) fn writer_uid(&self)->&PodWriterUid {&self.writer}
    pub(crate) fn witnesses(&self)->&BTreeMap<Uid,RootedMountWitness> {&self.witnesses}
    pub(crate) fn assert_actual_store(&self,world:&Arc<RwLock<DesiredWorld>>)->Result<(),String> {
        if !Arc::ptr_eq(world,&self.book.world) || !core::is_actual_world(world) {
            return Err("mounted metadata receipt requires its actual live Raft store".into());
        }
        Ok(())
    }
    /// Synchronous no-IO scratch comparison. Kernel re-observation already
    /// happened in the actual Watch dispatcher before this private object.
    pub(crate) fn validate_commit_scope(&self,scratch:&DesiredWorld)->Result<(),String> {
        self.assert_actual_store(&self.book.world)?;
        if self.book.invalid.load(Ordering::Acquire){return Err("mounted group UNKNOWN".into());}
        let state=self.book.state.lock().map_err(|_|"rooted mount group poisoned")?;
        if state.unknown.is_some() || state.current.as_ref()!=Some(&self.round)
            || state.owners.len()!=self.witnesses.len() || self.witnesses.is_empty() {
            return Err("actual installed mount group changed, partial or UNKNOWN".into());
        }
        for (uid,witness) in &self.witnesses {
            witness.require_commit_live()?;
            let owner=state.owners.get(uid).ok_or("actual mounted owner disappeared")?;
            witness.require_same_root(owner)?;
            let volume=scratch.storage_identities.lifecycle.get(uid).ok_or("current mounted dataset absent")?;
            witness.check_current_volume(volume)?;
            volume.pod_writer().ok_or("current PodWriter history absent")?.check_source_current(scratch)?;
        }
        Ok(())
    }
}

/// Compare the actual CURRENT scratch/read revision, not the round's original
/// desired generation. Unrelated writes need a fresh observation, not a global
///180s freeze; incompatible source/claim/writer/boot changes still refuse.
pub(super) fn check_actual_current(shared:&Shared,observed:&core::CoreObservation,
    scope:&ExpectedAttachScope)->Result<(),String> {
    if !core::is_actual_world(&shared.world) {return Err("attachment refuses a supplied/frozen world".into());}
    let world=shared.world.try_read().map_err(|_|"actual attach world busy")?;
    if world.generation!=observed.revision().desired_generation || world.cluster_id!=observed.cluster_id() {
        return Err("actual attach source changed since THIS fresh Core observation".into());
    }
    let volume=world.storage_identities.lifecycle.get(&scope.owner.volume_uid).ok_or("actual attach volume absent")?;
    if volume!=observed.volume() {return Err("actual attach scope changed after coherent Core capture".into());}
    scope.check_volume(volume)?;
    scope.pod_writer.check_source_current(&world)?;
    world.storage_identities.validate(&world.to_state())?;
    Ok(())
}
