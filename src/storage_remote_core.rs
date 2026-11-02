//! SOURCE-ONLY raft_node child module. Non-mutating coherent metadata reads.
//! The proposed RaftHandle store pointer is the ACTUAL store used by its Raft,
//! never a caller-provided frozen DesiredWorld. No authority from JSON metrics.
use super::*;
use crate::storage_boot::BootId;
use crate::storage_identity::Uid;
use crate::storage_lifecycle::Volume;
use crate::storage_remote_protocol::{hash, ReadChallenge, Revision, VerifiedPeerFrame};
use std::time::{Duration, Instant};
pub(crate) const MAX_STORAGE_BOUNDARY_MS: u64 = super::LEADER_LEASE_MS;

#[cfg_attr(test, derive(Clone))]
pub(crate) struct CoreObservation {
    revision: Revision,
    cluster_id: String,
    volume: Volume,
    scope_sha256: String,
    local_node_uid: Option<Uid>,
    actual_boot: BootId,
    captured: Instant,
    barrier_started: Option<Instant>,
    barrier_for: Option<String>,
    directory_commitment: Option<String>,
    voters: Vec<u64>,
}

#[cfg(test)]
pub(crate) fn model_for_protocol_tests(
    volume: Volume,
    revision: Revision,
    node: Uid,
    boot: BootId,
    scope: String,
    directory: Option<String>,
    now: Instant,
    issuer: bool,
) -> CoreObservation {
    // Explicit protocol model only. Not called by production capture and never
    // accepted by a physical worker or lifecycle receipt constructor.
    CoreObservation {
        cluster_id: volume.owner().cluster_id.clone(),
        volume,
        revision,
        scope_sha256: scope,
        local_node_uid: Some(node),
        actual_boot: boot,
        captured: now,
        barrier_started: issuer.then_some(now),
        barrier_for: None,
        directory_commitment: directory,
        voters: vec![1, 2, 3],
    }
}
impl CoreObservation {
    pub(crate) fn require_fresh_terminal(&self,
        request:&crate::storage_driver::native_runtime::mount::consumer::terminal::TerminalReadRequest,
        now:Instant)->Result<(),String>{
        request.require_produced()?;
        let started=self.barrier_started.ok_or("terminal effect has no actual request-bound quorum barrier")?;
        if self.barrier_for.as_deref()!=Some(request.binding())||now<self.captured||now<started
            ||now.duration_since(started)>=Duration::from_millis(MAX_STORAGE_BOUNDARY_MS){
            return Err("terminal quorum belongs to another request or expired".into());}
        Ok(())
    }
    pub(crate) fn require_fresh_consumer(&self,
        request:&crate::storage_driver::native_runtime::mount::consumer::ConsumerReadRequest,now:Instant)->Result<(),String>{
        request.require_produced()?;
        let started=self.barrier_started.ok_or("no actual consumer quorum barrier")?;
        if self.barrier_for.as_deref()!=Some(request.binding()) || now<self.captured || now<started
            || now.duration_since(started)>=Duration::from_millis(MAX_STORAGE_BOUNDARY_MS){
            return Err("consumer quorum belongs to another request or is expired".into());
        }
        Ok(())
    }
    pub(crate) fn require_fresh_attach(
        &self, request:&crate::storage_remote_protocol::attachment::LocalRequest, now:Instant,
    )->Result<(),String> {
        let started=self.barrier_started.ok_or("no actual attach quorum barrier")?;
        if self.barrier_for.as_deref()!=Some(request.binding()?.as_str()) || now<self.captured || now<started
            || now.duration_since(started)>=Duration::from_millis(MAX_STORAGE_BOUNDARY_MS) {
            return Err("attach barrier belongs to another request or expired".into());
        }Ok(())
    }
    pub(crate) fn require_fresh_native(
        &self,
        request: &crate::storage_driver::dispatcher::VerifiedLocalBoundary,
        now: Instant,
    ) -> Result<(), String> {
        let start = self.barrier_started.ok_or("no native issuer barrier")?;
        if self.barrier_for.as_deref() != Some(request.binding())
            || now < self.captured
            || now < start
            || now.duration_since(start) > Duration::from_millis(MAX_STORAGE_BOUNDARY_MS)
        {
            return Err("native boundary barrier is stale or belongs to another request".into());
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn bind_model_request(&self, request: &VerifiedPeerFrame) -> Self {
        let mut model = self.clone();
        model.barrier_for = Some(request.read_challenge().binding().to_string());
        model
    }
    pub(crate) fn revision(&self) -> &Revision {
        &self.revision
    }
    pub(crate) fn cluster_id(&self) -> &str {
        &self.cluster_id
    }
    pub(crate) fn volume(&self) -> &Volume {
        &self.volume
    }
    pub(crate) fn scope_sha256(&self) -> &str {
        &self.scope_sha256
    }
    pub(crate) fn local_node_uid(&self) -> Option<&Uid> {
        self.local_node_uid.as_ref()
    }
    pub(crate) fn actual_boot(&self) -> &BootId {
        &self.actual_boot
    }
    pub(crate) fn directory_commitment(&self) -> Option<&str> {
        self.directory_commitment.as_deref()
    }
    pub(crate) fn voters(&self) -> &[u64] {
        &self.voters
    }
    pub(crate) fn require_fresh_issuer_for(
        &self,
        request: &VerifiedPeerFrame,
        now: Instant,
        maximum: Duration,
    ) -> Result<(), String> {
        let started = self
            .barrier_started
            .ok_or("local follower observation is not leader/quorum authority")?;
        if self.barrier_for.as_deref() != Some(request.read_challenge().binding())
            || now < self.captured
            || now < started
            || now.duration_since(started) > maximum
        {
            return Err("issuer barrier aged out; request fresh quorum confirmation".into());
        }
        Ok(())
    }
}

/// Parameter is lookup identity only, not an authorization grant. No state
/// write, own-state flag, helper spawn, RPC route or new physical action here.
pub(crate) fn observe_local(volume_uid: &Uid) -> Result<CoreObservation, String> {
    let candidate = directory_candidate()?;
    let local = match candidate.directory() {
        Some(directory) => Some(crate::storage_driver::node_identity::observe(
            directory,
            RAFT.get().ok_or("actual Raft missing")?.node_id,
        )?),
        None => None,
    };
    capture(volume_uid, None, None, candidate, local)
}
pub(crate) async fn observe_local_async(volume_uid: &Uid) -> Result<CoreObservation, String> {
    let candidate = directory_candidate()?;
    let local = inspect_candidate(&candidate).await?;
    capture(volume_uid, None, None, candidate, local)
}
fn directory_candidate() -> Result<crate::storage_node_directory::Registry, String> {
    let handle = RAFT.get().ok_or("actual Raft missing")?;
    let registry = handle
        .storage_store
        .world
        .try_read()
        .map_err(|_| "directory observation busy")?
        .storage_node_directory
        .clone();
    Ok(registry)
}
async fn inspect_candidate(
    candidate: &crate::storage_node_directory::Registry,
) -> Result<Option<crate::storage_driver::node_identity::LocalObservation>, String> {
    match candidate.directory() {
        Some(directory) => Ok(Some(
            crate::storage_driver::node_identity::observe_async(
                directory,
                RAFT.get().ok_or("actual Raft missing")?.node_id,
            )
            .await?,
        )),
        None => Ok(None),
    }
}

/// Fresh real quorum heartbeat + application barrier, bounded independently of
/// cached IS_RAFT_LEADER and non-ticking millis_since_quorum_ack snapshots.
/// A parked async runtime fails the explicit monotonic elapsed check too.
pub(crate) async fn observe_issuer(
    volume_uid: &Uid,
    request: ReadChallenge,
) -> Result<CoreObservation, String> {
    observe_bound_issuer(volume_uid, request.binding().to_string()).await
}
pub(crate) async fn observe_native_issuer(
    volume_uid: &Uid,
    request: &crate::storage_driver::dispatcher::VerifiedLocalBoundary,
) -> Result<CoreObservation, String> {
    observe_bound_issuer(volume_uid, request.binding().to_string()).await
}
pub(crate) async fn observe_attach_issuer(volume_uid:&Uid,
    request:&crate::storage_remote_protocol::attachment::LocalRequest)->Result<CoreObservation,String> {
    observe_bound_issuer(volume_uid,request.binding()?).await
}
pub(crate) async fn observe_consumer_issuer(volume_uid:&Uid,
    request:&crate::storage_driver::native_runtime::mount::consumer::ConsumerReadRequest)->Result<CoreObservation,String>{
    request.require_produced()?;
    observe_bound_issuer(volume_uid,request.binding().to_string()).await
}
pub(crate) async fn observe_terminal_issuer(volume_uid:&Uid,
    request:&crate::storage_driver::native_runtime::mount::consumer::terminal::TerminalReadRequest)
    ->Result<CoreObservation,String>{
    request.require_produced()?;
    observe_bound_issuer(volume_uid,request.binding().to_string()).await
}
pub(crate) fn is_actual_world(world: &Arc<std::sync::RwLock<DesiredWorld>>) -> bool {
    RAFT.get()
        .is_some_and(|h| Arc::ptr_eq(world, &h.storage_store.world))
}
/// Readonly conservative consumer-deletion denial, never fresh authority.
pub(crate) fn retained_writer_pod(namespace:&str,pod:&str)->Result<bool,String>{
    let Some(handle)=RAFT.get()else{return Ok(false);};
    let world=handle.storage_store.world.try_read().map_err(|_|"actual retained writer history busy")?;
    Ok(world.storage_identities.lifecycle.contains_writer_pod(namespace,pod))
}
/// NEGATIVE epoch fence only. Metrics cannot mint a storage permission; every
/// positive request still needs its actual fresh request-bound quorum barrier.
/// This pure check is safe inside a commit scratch closure (no World/FS/IO).
pub(crate) fn require_same_actual_epoch(world:&Arc<std::sync::RwLock<DesiredWorld>>,revision:&Revision)->Result<(),String>{
    let h=RAFT.get().ok_or("actual attach Raft disappeared")?;
    if !Arc::ptr_eq(world,&h.storage_store.world) || h.sealing!=Sealing::Cluster
        || h.storage_store.sealing!=Sealing::Cluster || h.storage_store.dir.is_none(){return Err("actual sealed attach store changed".into());}
    let current=h.raft.metrics().borrow().clone();
    let membership=hash(&serde_json::to_vec(current.membership_config.as_ref()).map_err(|_|"attach membership bind failed")?);
    if current.running_state.is_err() || current.current_term!=revision.term || current.current_leader!=Some(revision.leader_raft_id)
        || membership!=revision.membership_sha256 {return Err("attach term/leader/membership changed; no adoption of old round".into());}
    Ok(())
}
async fn observe_bound_issuer(
    volume_uid: &Uid,
    binding: String,
) -> Result<CoreObservation, String> {
    // Inspect first, without blocking any Tokio/Raft worker; then obtain a
    // fresh barrier for this exact request. Both ages are checked at capture.
    let candidate = directory_candidate()?;
    let local = inspect_candidate(&candidate).await?;
    let fresh = fresh_quorum().await?;
    capture(
        volume_uid,
        Some((fresh.started, fresh.term, fresh.membership_sha256, binding)),
        Some(fresh.minimum),
        candidate,
        local,
    )
}
pub(super) struct FreshQuorum {
    pub(super) started: Instant,
    pub(super) term: u64,
    pub(super) membership_sha256: String,
    pub(super) minimum: LogId<NeuroNodeId>,
}
/// Shared actual barrier, not a second metrics/world revision authority.
pub(super) async fn fresh_quorum() -> Result<FreshQuorum, String> {
    let handle = RAFT
        .get()
        .ok_or("storage issuer requires active durable Raft")?;
    if handle.sealing != Sealing::Cluster {
        return Err("test/plain Raft cannot mint production storage observations".into());
    }
    if handle.storage_store.sealing != Sealing::Cluster || handle.storage_store.dir.is_none() {
        return Err("storage barrier requires the actual durable sealed store".into());
    }
    let before = handle.raft.metrics().borrow().clone();
    if before.current_leader != Some(handle.node_id) || before.running_state.is_err() {
        return Err("not actual current storage issuer leader".into());
    }
    let started = Instant::now();
    let maximum = Duration::from_millis(MAX_STORAGE_BOUNDARY_MS);
    let applied = tokio::time::timeout(maximum, handle.raft.ensure_linearizable())
        .await
        .map_err(|_| "storage quorum read barrier timed out")?
        .map_err(|_| "storage quorum read barrier denied")?
        .ok_or("storage quorum read barrier has no applied log")?;
    if started.elapsed() >= maximum {
        return Err("storage read barrier response aged out; no new action".into());
    }
    let after = handle.raft.metrics().borrow().clone();
    if before.current_term != after.current_term
        || before.current_leader != after.current_leader
        || before.membership_config != after.membership_config
    {
        return Err("leader term/membership changed across quorum barrier".into());
    }
    let membership = hash(
        &serde_json::to_vec(before.membership_config.as_ref())
            .map_err(|_| "cannot bind barrier membership")?,
    );
    Ok(FreshQuorum {
        started,
        term: before.current_term,
        membership_sha256: membership,
        minimum: applied,
    })
}

pub(super) struct EnrollmentView {
    pub(super) generation: u64,
    pub(super) cluster_id: String,
    pub(super) registry: crate::storage_node_directory::Registry,
    pub(super) term: u64,
    pub(super) leader: u64,
    pub(super) membership_sha256: String,
    pub(super) voters: Vec<u64>,
}
pub(super) async fn observe_enrollment() -> Result<EnrollmentView, String> {
    let barrier = fresh_quorum().await?;
    let handle = RAFT.get().ok_or("actual enrollment Raft missing")?;
    let sm = handle
        .storage_store
        .sm
        .try_lock()
        .map_err(|_| "actual apply observation busy")?;
    let world = handle
        .storage_store
        .world
        .try_read()
        .map_err(|_| "actual enrollment world busy")?;
    let metrics = handle.raft.metrics().borrow().clone();
    let fingerprint =
        hash(&serde_json::to_vec(&sm.membership).map_err(|_| "invalid actual membership")?);
    if barrier.started.elapsed() >= Duration::from_millis(MAX_STORAGE_BOUNDARY_MS)
        || metrics.current_term != barrier.term
        || metrics.current_leader != Some(handle.node_id)
        || metrics.membership_config.as_ref() != &sm.membership
        || fingerprint != barrier.membership_sha256
        || sm.last_applied.is_none_or(|id| id < barrier.minimum)
        || sm.membership.membership().is_in_joint_consensus()
        || crate::auth::derived_cluster_id().as_deref() != Some(world.cluster_id.as_str())
    {
        return Err("enrollment quorum/term/membership/applied state changed or aged out".into());
    }
    world
        .storage_node_directory
        .validate_state(&world.to_state())?;
    if world.storage_node_directory.has_authority() {
        let guard = handle
            .storage_store
            .storage_directory_history
            .lock()
            .map_err(|_| "directory history poisoned")?;
        world.storage_node_directory.require_guard(guard.as_ref())?;
        world
            .storage_node_directory
            .require_membership(&sm.membership)?;
    }
    Ok(EnrollmentView {
        generation: world.generation,
        cluster_id: world.cluster_id.clone(),
        registry: world.storage_node_directory.clone(),
        term: barrier.term,
        leader: handle.node_id,
        membership_sha256: fingerprint,
        voters: sm.membership.membership().voter_ids().collect(),
    })
}

fn capture(
    volume_uid: &Uid,
    barrier: Option<(Instant, u64, String, String)>,
    minimum: Option<LogId<NeuroNodeId>>,
    candidate: crate::storage_node_directory::Registry,
    local: Option<crate::storage_driver::node_identity::LocalObservation>,
) -> Result<CoreObservation, String> {
    let handle = RAFT
        .get()
        .ok_or("storage observation requires active actual Raft store")?;
    if handle.sealing != Sealing::Cluster
        || handle.storage_store.sealing != Sealing::Cluster
        || handle.storage_store.dir.is_none()
    {
        return Err("storage observation requires the actual durable sealed store".into());
    }
    // Existing apply/snapshot order is sm -> world. Holding both prevents
    // sm.last_applied from being paired with a half-applied world generation.
    let actual_boot = BootId::current()?;
    // The opaque fixed-worker observation was obtained before these locks.
    let sm = handle
        .storage_store
        .sm
        .try_lock()
        .map_err(|_| "storage apply observation busy or poisoned")?;
    let world = handle
        .storage_store
        .world
        .try_read()
        .map_err(|_| "storage committed world observation busy or poisoned")?;
    let metrics = handle.raft.metrics().borrow().clone();
    let leader = metrics.current_leader.ok_or("current leader unknown")?;
    let applied = sm
        .last_applied
        .ok_or("storage state is not backed by an applied Raft entry")?;
    if metrics.running_state.is_err()
        || metrics.membership_config.as_ref() != &sm.membership
        || minimum.is_some_and(|id| applied < id)
        || metrics.current_term < applied.leader_id.term
        || barrier.as_ref().is_some_and(|(_, term, _, _)| {
            *term != metrics.current_term || leader != handle.node_id
        })
    {
        return Err("storage observation leader/revision/membership is incoherent".into());
    }
    let volume = world
        .storage_identities
        .lifecycle
        .get(volume_uid)
        .ok_or("storage managed volume absent")?
        .clone();
    let owner = volume.owner();
    if crate::auth::derived_cluster_id().as_deref() != Some(world.cluster_id.as_str()) {
        return Err(
            "committed cluster identity does not match authenticated cluster secret".into(),
        );
    }
    let binding =
        crate::backup_engine::Binding::resolve(&world, &owner.namespace, &owner.claim_name)?;
    if binding.cluster_id != owner.cluster_id
        || binding.namespace_uid != owner.namespace_uid
        || binding.claim_uid != owner.claim_uid
        || binding.volume_uid != owner.volume_uid
        || binding.pv_name != owner.pv_name
        || world.cluster_id != owner.cluster_id
    {
        return Err("storage namespace/claim/volume incarnation changed".into());
    }
    let pv = world.pvs.get(&owner.pv_name).ok_or("bound PV missing")?;
    let pvc = world
        .pvcs
        .get(&crate::store::obj_key(&owner.namespace, &owner.claim_name))
        .ok_or("bound PVC missing")?;
    let class = world
        .storage_classes
        .get(&pv.storage_class)
        .ok_or("storage class missing")?;
    let scope_sha256 = hash(
        &serde_json::to_vec(&(&volume, pv, pvc, class))
            .map_err(|_| "cannot bind exact storage scope")?,
    );
    let membership_sha256 = hash(
        &serde_json::to_vec(&sm.membership)
            .map_err(|_| "cannot bind committed storage membership")?,
    );
    if barrier
        .as_ref()
        .is_some_and(|(_, _, membership, _)| membership != &membership_sha256)
    {
        return Err("membership changed after storage quorum barrier".into());
    }
    let revision = Revision {
        term: metrics.current_term,
        leader_raft_id: leader,
        applied_term: applied.leader_id.term,
        applied_leader_raft_id: applied.leader_id.node_id,
        applied_index: applied.index,
        desired_generation: world.generation,
        membership_sha256,
    };
    if candidate != world.storage_node_directory {
        return Err("directory changed during local identity observation".into());
    }
    let (local_node_uid, directory_commitment) =
        match (world.storage_node_directory.directory(), local) {
            (Some(directory), Some(local)) => {
                let guard = handle
                    .storage_store
                    .storage_directory_history
                    .lock()
                    .map_err(|_| "directory history poisoned")?;
                world.storage_node_directory.require_guard(guard.as_ref())?;
                world
                    .storage_node_directory
                    .require_membership(&sm.membership)?;
                if directory.voters() != sm.membership.membership().voter_ids().collect::<Vec<_>>()
                    || sm.membership.membership().is_in_joint_consensus()
                {
                    return Err(
                        "directory membership reconfiguration is unsupported; issuer inactive"
                            .into(),
                    );
                }
                local.require_current(directory, handle.node_id)?;
                if local.boot() != &actual_boot {
                    return Err("actual local boot changed during capture".into());
                }
                (Some(local.node_uid().clone()), Some(directory.sha256()?))
            }
            (None, None) => (None, None),
            _ => {
                return Err("committed directory has no exact private/kernel local binding".into())
            }
        };
    let voters = sm.membership.membership().voter_ids().collect();
    Ok(CoreObservation {
        revision,
        cluster_id: world.cluster_id.clone(),
        volume,
        scope_sha256,
        local_node_uid,
        actual_boot,
        captured: Instant::now(),
        barrier_started: barrier.as_ref().map(|b| b.0),
        barrier_for: barrier.map(|b| b.3),
        directory_commitment,
        voters,
    })
}

/// Guarded actual directory read for optional normal runtime startup/readiness.
/// Observation only: it cannot grant a job or replace a per-boundary barrier.
pub(crate) struct RuntimeView {
    directory: crate::storage_node_directory::DirectoryDto,
    local: Uid,
    boot: BootId,
    revision: Revision,
    volumes: Vec<Volume>,
}
impl RuntimeView {
    pub(crate) fn directory(&self)->&crate::storage_node_directory::DirectoryDto { &self.directory }
    pub(crate) fn local(&self)->&Uid { &self.local }
    pub(crate) fn boot(&self)->&BootId { &self.boot }
    pub(crate) fn revision(&self)->&Revision { &self.revision }
    pub(crate) fn volumes(&self)->&[Volume] { &self.volumes }
}
pub(crate) async fn runtime_view(leader:bool)->Result<RuntimeView,String> {
    let candidate=directory_candidate()?;
    let local=inspect_candidate(&candidate).await?.ok_or("runtime has no explicit local binding")?;
    let barrier=if leader {Some(fresh_quorum().await?)} else {None};
    let handle=RAFT.get().ok_or("actual runtime Raft absent")?;
    if handle.sealing!=Sealing::Cluster || handle.storage_store.sealing!=Sealing::Cluster ||
        handle.storage_store.dir.is_none() {
        return Err("runtime requires durable sealed actual Raft".into());
    }
    let sm=handle.storage_store.sm.try_lock().map_err(|_|"runtime apply observation busy")?;
    let world=handle.storage_store.world.try_read().map_err(|_|"runtime world observation busy")?;
    let metrics=handle.raft.metrics().borrow().clone();
    let applied=sm.last_applied.ok_or("runtime lacks applied entry")?;
    let current_leader=metrics.current_leader.ok_or("runtime leader unknown")?;
    let membership=hash(&serde_json::to_vec(&sm.membership).map_err(|_|"invalid runtime membership")?);
    if metrics.running_state.is_err() || metrics.membership_config.as_ref()!=&sm.membership ||
        sm.membership.membership().is_in_joint_consensus() ||
        candidate!=world.storage_node_directory ||
        crate::auth::derived_cluster_id().as_deref()!=Some(world.cluster_id.as_str()) ||
        metrics.current_term<applied.leader_id.term {
        return Err("incoherent runtime directory/Core read".into());
    }
    if let Some(fresh)=barrier {
        if fresh.started.elapsed()>=Duration::from_millis(MAX_STORAGE_BOUNDARY_MS) ||
            fresh.term!=metrics.current_term || current_leader!=handle.node_id ||
            applied<fresh.minimum || membership!=fresh.membership_sha256 {
            return Err("runtime issuer observation changed or aged out".into());
        }
    }
    let guard=handle.storage_store.storage_directory_history.lock()
        .map_err(|_|"runtime applied directory history poisoned")?;
    world.storage_node_directory.require_guard(guard.as_ref())?;
    world.storage_node_directory.require_membership(&sm.membership)?;
    let directory=world.storage_node_directory.directory().ok_or("runtime directory unenrolled")?;
    local.require_current(directory,handle.node_id)?;
    if directory.nodes.len()!=3 || directory.voters()!=sm.membership.membership().voter_ids().collect::<Vec<_>>() {
        return Err("cold runtime requires exactly three enrolled voters".into());
    }
    // Reject excess metadata rather than silently hide an unresolved volume.
    if world.pvs.len()>512 {return Err("runtime managed census exceeds fixed bound".into());}
    let mut volumes=Vec::new();
    for pv in world.pvs.values().filter(|pv|world.storage_classes.get(&pv.storage_class)
        .is_some_and(|sc|sc.provisioner==crate::storage_lifecycle::PROVISIONER)) {
        let uid=world.storage_identities.volumes.get(&pv.name).ok_or("runtime PV identity absent")?;
        volumes.push(world.storage_identities.lifecycle.get(uid).ok_or("runtime lifecycle absent")?.clone());
    }
    Ok(RuntimeView {directory:directory.clone(),local:local.node_uid().clone(),boot:local.boot().clone(),
        revision:Revision {term:metrics.current_term,leader_raft_id:current_leader,
            applied_term:applied.leader_id.term,applied_leader_raft_id:applied.leader_id.node_id,
            applied_index:applied.index,desired_generation:world.generation,membership_sha256:membership},
        volumes })
}

/// Metrics are used ONLY to await apply readiness. No capability/authority is
/// returned; callers must capture actual coherent Core and run strict checks.
pub(crate) async fn wait_applied_hint(minimum:&Revision,deadline:Instant)->Result<(),String> {
    let handle=RAFT.get().ok_or("actual apply observer unavailable")?;
    if handle.sealing!=Sealing::Cluster || handle.storage_store.sealing!=Sealing::Cluster || handle.storage_store.dir.is_none() {
        return Err("apply synchronization requires actual durable sealed Raft".into());
    }
    let mut metrics=handle.raft.metrics();
    loop {
        if Instant::now()>=deadline {return Err("original read/response budget exhausted waiting for apply".into());}
        let ready={
            let view=metrics.borrow();
            if view.running_state.is_err(){return Err("actual Raft failed during apply synchronization".into());}
            let membership=hash(&serde_json::to_vec(view.membership_config.as_ref()).map_err(|_|"invalid actual apply membership")?);
            apply_hint_ready(minimum,view.current_term,view.current_leader,
                view.last_applied.map(|id|(id.index,id.leader_id.term,id.leader_id.node_id)),&membership)?
        };
        if ready{return Ok(());}
        let remaining=deadline.saturating_duration_since(Instant::now());
        tokio::time::timeout(remaining,metrics.changed()).await
            .map_err(|_|"original apply wait deadline exhausted")?
            .map_err(|_|"actual apply observation stream closed")?;
    }
}
fn apply_hint_ready(minimum:&Revision,term:u64,leader:Option<u64>,applied:Option<(u64,u64,u64)>,membership:&str)->Result<bool,String> {
    if term<minimum.term {return Ok(false);}
    if term!=minimum.term || leader.is_some_and(|id|id!=minimum.leader_raft_id) || membership!=minimum.membership_sha256 {
        return Err("term/leader/membership changed during read-only apply wait".into());
    }
    if leader.is_none(){return Ok(false);}
    let Some((index,applied_term,applied_leader))=applied else {return Ok(false);};
    if index<minimum.applied_index || applied_term<minimum.applied_term {return Ok(false);}
    if (index==minimum.applied_index && (applied_term!=minimum.applied_term || applied_leader!=minimum.applied_leader_raft_id)) ||
        (applied_term==minimum.applied_term && applied_leader!=minimum.applied_leader_raft_id) {
        return Err("applied log lineage differs during synchronization".into());
    }
    Ok(true)
}

#[cfg(test)]
mod apply_synchronization_tests {
    use super::*;
    fn minimum()->Revision {Revision {term:7,leader_raft_id:1,applied_term:7,applied_leader_raft_id:1,
        applied_index:50,desired_generation:41,membership_sha256:"a".repeat(64)}}
    #[test]
    fn caught_up_hint_and_actual_lag_are_distinct_without_authority() {
        let required=minimum();
        assert!(apply_hint_ready(&required,7,Some(1),Some((50,7,1)),&"a".repeat(64)).unwrap());
        assert!(!apply_hint_ready(&required,7,Some(1),Some((49,7,1)),&"a".repeat(64)).unwrap());
        assert!(!apply_hint_ready(&required,7,Some(1),None,&"a".repeat(64)).unwrap());
        assert!(!apply_hint_ready(&required,6,Some(1),Some((50,6,1)),&"a".repeat(64)).unwrap());
    }
    #[test]
    fn changed_term_leader_membership_or_log_lineage_refuses_apply_wait() {
        let required=minimum();
        for (term,leader,log,membership) in [
            (8,Some(1),(50,7,1),"a".repeat(64)),(7,Some(2),(50,7,1),"a".repeat(64)),
            (7,Some(1),(50,7,1),"b".repeat(64)),(7,Some(1),(50,7,2),"a".repeat(64))] {
            assert!(apply_hint_ready(&required,term,leader,Some(log),&membership).is_err());
        }
    }
}
