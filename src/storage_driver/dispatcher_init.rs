//! Distributed initialization uses the existing dispatcher thread and keeps
//! the exact live cold reservation. These opaque values are not wire DTOs.
use super::*;
use crate::storage_lifecycle::generation::{
    physical::{ExpectedInitScope, InitPhase, PhaseObservation},
    DataGeneration, InitializationIntent, VirginReplicaRef,
};
use std::sync::Mutex;
#[path = "dispatcher_init_parent.rs"]
mod parent;
pub(in crate::storage_driver) use parent::{scope_current, InitParent};

/// Constructed only after inherited capsule/lease/cgroup/root-parent checks.
/// No caller World, serde value or boolean can construct this permit.
pub(crate) struct VerifiedDistributedInitPhase {
    identity: live::JobIdentity,
    scope: ExpectedInitScope,
    intent: InitializationIntent,
    deadline: Instant,
}
impl VerifiedDistributedInitPhase {
    pub(in crate::storage_driver) fn from_inherited(
        authority: &VerifiedNativeAuthority,
        intent: &InitializationIntent,
    ) -> Result<Self, String> {
        if !authority.matches_distributed_initialization(intent) {
            return Err("inherited worker is not this exact distributed phase".into());
        }
        let scope = authority.distributed_initialization_scope()?.clone();
        live::require_identity(&authority.capsule.identity)?;
        let remaining = authority
            .capsule
            .payload
            .worker_remaining_ms
            .ok_or("inherited phase remaining budget absent")?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(remaining))
            .ok_or("inherited initialization deadline overflow")?;
        Ok(Self {
            identity: authority.capsule.identity.clone(),
            scope,
            intent: intent.clone(),
            deadline,
        })
    }
    pub(crate) fn phase(&self) -> InitPhase {
        self.scope.phase
    }
    pub(crate) fn fact(&self) -> &VirginReplicaRef {
        // The only constructor validated this exact membership first.
        self.scope
            .generation
            .virgin_replicas
            .iter()
            .find(|fact| {
                fact.node_uid == self.scope.target_node_uid
                    && fact.node_boot_id == self.scope.target_boot
            })
            .expect("opaque verified phase retains exact target")
    }
    pub(crate) fn intent(&self) -> &InitializationIntent {
        &self.intent
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    fn within_deadline(&self) -> Result<(), String> {
        if Instant::now() >= self.deadline {
            return Err("original initialization phase budget expired; UNKNOWN".into());
        }
        Ok(())
    }
    pub(crate) fn check_inputs(
        &self,
        cfg: &super::super::Config,
        intent: &InitializationIntent,
        plan_sha256: &str,
    ) -> Result<(), String> {
        self.within_deadline()?;
        cfg.validate()?;
        let fact = self.fact();
        if self.intent.owner() != intent.owner()
            || self.intent.generation() != intent.generation()
            || self.intent.capacity_bytes() != intent.capacity_bytes()
            || cfg.cluster_id != intent.owner().cluster_id
            || cfg.node_uid != fact.node_uid
            || cfg.pool_uid != fact.pool_uid
            || fact.plan_sha256 != plan_sha256
            || crate::storage_boot::BootId::current() != Ok(fact.node_boot_id.clone())
        {
            return Err(
                "physical inputs differ from exact inherited generation/target/pool/plan/boot"
                    .into(),
            );
        }
        live::require_identity(&self.identity)?;
        self.within_deadline()
    }
    pub(crate) fn checkpoint(&self) -> Result<(), String> {
        self.within_deadline()?;
        live::require_identity(&self.identity)?;
        self.within_deadline()
    }
    pub(crate) fn before_read(&self, offset: u64, length: u64) -> Result<(), String> {
        self.within_deadline()?;
        if !read_range_allowed(self.scope.phase, self.fact().exposed_bytes, offset, length) {
            return Err("initialization read is not the exact bounded exposed extent".into());
        }
        live::before_initialization_read(
            &self.scope.owner.volume_uid,
            &self.scope.generation.uid,
            &self.scope.phase,
            offset,
            length,
        )?;
        self.within_deadline()
    }
}
fn read_range_allowed(phase: InitPhase, bytes: u64, offset: u64, length: u64) -> bool {
    matches!(
        phase,
        InitPhase::ActivateSecondary | InitPhase::FlushPrimary | InitPhase::ObserveOffline
    ) && bytes > 0
        && bytes % 4096 == 0
        && offset % 4096 == 0
        && length > 0
        && length <= 1024 * 1024
        && length % 4096 == 0
        && offset.checked_add(length).is_some_and(|end| end <= bytes)
}

impl VerifiedNativeAuthority {
    /// Distinct v4 checker; the old local-v2 initializer checker is unchanged.
    pub(crate) fn distributed_initialization_scope(&self) -> Result<&ExpectedInitScope, String> {
        if self.capsule.version != 4 || !valid_capsule_profile(&self.capsule) {
            return Err("not an exact verified distributed initialization capsule".into());
        }
        self.capsule
            .payload
            .initialization
            .as_ref()
            .ok_or_else(|| "phase scope absent".into())
    }
    pub(crate) fn matches_distributed_initialization(&self, intent: &InitializationIntent) -> bool {
        self.distributed_initialization_scope().is_ok_and(|scope| {
            scope.owner == *intent.owner()
                && scope.generation == *intent.generation()
                && self.capsule.identity.operation_uid == *intent.operation_uid()
                && scope.generation.virgin_replicas.iter().any(|fact| {
                    fact.node_uid == self.capsule.identity.node_uid
                        && fact.node_boot_id.as_str() == self.capsule.identity.boot_id
                        && fact.requested_bytes == intent.capacity_bytes()
                })
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdReport {
    kind: String,
    volume_uid: Uid,
    operation_uid: Uid,
    node_uid: Uid,
    node_boot_id: crate::storage_boot::BootId,
    pod_access_granted: bool,
    observation: VirginReport,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VirginReport {
    kind: String,
    reference: VirginReplicaRef,
}
impl ColdPreparedHeld {
    pub(crate) fn validated_reference(&self) -> Result<VirginReplicaRef, String> {
        let report: ColdReport = serde_json::from_slice(self.diagnostics()?)
            .map_err(|_| "invalid exact actual cold helper output")?;
        let fact = report.observation.reference;
        fact.validate()?;
        if report.kind != "royak-agent-virgin-offline-prepared-v2"
            || report.observation.kind != "royak-virgin-offline-replica-observation-v1"
            || report.pod_access_granted
            || report.volume_uid != self.intent.owner().volume_uid
            || report.operation_uid != *self.intent.operation_uid()
            || report.node_uid != self.identity.node_uid
            || report.node_boot_id.as_str() != self.identity.boot_id
            || fact.volume_uid != report.volume_uid
            || fact.prepare_operation_uid != report.operation_uid
            || fact.node_uid != report.node_uid
            || fact.node_boot_id != report.node_boot_id
            || fact.requested_bytes != self.intent.capacity_bytes()
            || fact.pool_uid != self.expected_pool
            || fact.plan_sha256 != self.expected_plan_sha256
        {
            return Err(
                "cold output does not bind actual retained helper/owner/boot/pool/plan".into(),
            );
        }
        self.assert_retained()?;
        Ok(fact)
    }
    fn assert_retained(&self) -> Result<(), String> {
        if self.reservation.lease.is_none()
            || !self.reservation.busy.load(Ordering::Acquire)
            || self.cancelled.load(Ordering::Acquire)
        {
            return Err("actual cold reservation is cancelled/released".into());
        }
        Ok(())
    }
}

/// Shared only inside one serial Watch/dispatcher actor. Sharing this Arc does
/// not clone a cold capability or open two jobs; State admits one exact phase.
pub(crate) struct HeldInitializationOwner {
    cold: Mutex<ColdPreparedHeld>,
    prepare: ProvisionIntent,
    world: Arc<RwLock<DesiredWorld>>,
    agent: NativeAgent,
    prepare_job_uid: Uid,
    prepare_spec_sha256: String,
    invalid: Arc<AtomicBool>,
    safety: Mutex<Option<File>>,
    reference: VirginReplicaRef,
    deadline: Instant,
    state: Mutex<OwnerState>,
    released_slot: Mutex<Option<Arc<ReleasedInitializationSlot>>>,
}
enum OwnerState {
    Cold,
    Armed(DataGeneration),
    Ready {
        intent: InitializationIntent,
        next: usize,
        completed: Option<CompletedPhase>,
    },
    Running {
        intent: InitializationIntent,
        next: usize,
        scope: ExpectedInitScope,
    },
    Unknown,
    Released,
}
/// Private supervisor producer only, after actual reap/resource/cgroup drain,
/// durable Complete and a freshly consumed completion boundary.
struct CompletedPhase {
    scope: ExpectedInitScope,
    observation: PhaseObservation,
    completion_sha256: String,
    cgroup_identity: (u64, u64),
}
impl HeldInitializationOwner {
    pub(in crate::storage_driver) fn from_actual_cold(
        cold: ColdPreparedHeld,
        safety: File,
        deadline: Instant,
        prepare_job_uid: Uid,
        prepare_spec_sha256: String,
        invalid: Arc<AtomicBool>,
    ) -> Result<Arc<Self>, (ColdPreparedHeld, File, String)> {
        let checked = (|| {
            let fact = cold.validated_reference()?;
            let original = cold
                .reservation
                .lease
                .as_ref()
                .ok_or("cold lease absent")?
                .metadata()
                .map_err(|_| "cannot inspect actual cold lease")?;
            let duplicate = safety
                .metadata()
                .map_err(|_| "cannot inspect retained safety duplicate")?;
            if original.dev() != duplicate.dev()
                || original.ino() != duplicate.ino()
                || original.uid() != 0
                || duplicate.uid() != 0
                || deadline <= Instant::now()
                || deadline > Instant::now() + Duration::from_secs(180)
                || !valid_hash(&prepare_spec_sha256)
            {
                return Err("cold continuation lost exact lease/budget".into());
            }
            Ok(fact)
        })();
        match checked {
            Ok(reference) => Ok(Arc::new(Self {
                prepare: cold.intent.clone(),
                world: cold.world.clone(),
                agent: cold.agent.clone(),
                cold: Mutex::new(cold),
                safety: Mutex::new(Some(safety)),
                reference,
                deadline,
                prepare_job_uid,
                prepare_spec_sha256,
                invalid,
                state: Mutex::new(OwnerState::Cold),
                released_slot: Mutex::new(None),
            })),
            Err(reason) => Err((cold, safety, reason)),
        }
    }
    pub(crate) fn reference(&self) -> &VirginReplicaRef {
        &self.reference
    }
    pub(crate) fn prepare(&self) -> &ProvisionIntent {
        &self.prepare
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn prepare_job_uid(&self) -> &Uid {
        &self.prepare_job_uid
    }
    pub(crate) fn prepare_spec_sha256(&self) -> &str {
        &self.prepare_spec_sha256
    }
    pub(crate) fn released_slot(&self) -> Result<Arc<ReleasedInitializationSlot>, String> {
        let state = self.state.lock().map_err(|_| "released init owner state poisoned")?;
        if !matches!(*state, OwnerState::Released) {
            return Err("initialization has not actually released its known drained pair".into());
        }
        self.released_slot.lock().map_err(|_| "released init slot poisoned")?
            .as_ref().cloned().ok_or_else(|| "actual released-init FD provenance absent".into())
    }
    pub(crate) fn check_offer(&self, scope: &ExpectedInitScope) -> Result<(), String> {
        self.assert_held()?;
        scope.validate()?;
        if scope.prepare_job_uid != self.prepare_job_uid
            || scope.target_node_uid != self.reference.node_uid
            || scope.target_boot != self.reference.node_boot_id
            || scope.owner != *self.prepare.owner()
            || !scope
                .generation
                .virgin_replicas
                .iter()
                .any(|fact| fact == &self.reference)
        {
            return Err("offered phase differs from this actual retained preparation".into());
        }
        let state = self.state.lock().map_err(|_| "init owner state poisoned")?;
        match &*state {
            OwnerState::Armed(generation)
                if generation == &scope.generation
                    && scope.phase == InitPhase::ActivateSecondary =>
            {
                Ok(())
            }
            OwnerState::Ready { intent, next, .. }
                if intent.generation() == &scope.generation
                    && phase_schedule(
                        self.reference.node_uid == intent.generation().initializer_node_uid,
                    )
                    .get(*next)
                        == Some(&scope.phase) =>
            {
                Ok(())
            }
            _ => Err("offered phase is repeated/out-of-order or owner UNKNOWN".into()),
        }
    }
    pub(crate) fn arm(&self, generation: &DataGeneration) -> Result<(), String> {
        self.prepare.check_current(&self.world)?;
        self.assert_held()?;
        let mut state = self.state.lock().map_err(|_| "init owner state poisoned")?;
        if !matches!(*state, OwnerState::Cold)
            || generation.prepare_operation_uid != *self.prepare.operation_uid()
            || !generation
                .virgin_replicas
                .iter()
                .any(|fact| fact == &self.reference)
        {
            return Err("owner cannot arm changed/repeated prospective generation".into());
        }
        let world = self.world.try_read().map_err(|_| "arm actual World busy")?;
        let volume = world
            .storage_identities
            .lifecycle
            .get(&self.reference.volume_uid)
            .ok_or("arm volume absent")?;
        generation.validate(volume)?;
        *state = OwnerState::Armed(generation.clone());
        Ok(())
    }
    pub(crate) fn install_committed_intent(
        &self,
        intent: &InitializationIntent,
    ) -> Result<(), String> {
        intent.check_current(&self.world)?;
        self.assert_held()?;
        let mut state = self.state.lock().map_err(|_| "init owner state poisoned")?;
        match &*state {
            OwnerState::Armed(generation)
                if generation == intent.generation()
                    && self.prepare.owner() == intent.owner()
                    && self.prepare.operation_uid() == &generation.prepare_operation_uid =>
            {
                *state = OwnerState::Ready {
                    intent: intent.clone(),
                    next: 0,
                    completed: None,
                };
                Ok(())
            }
            OwnerState::Ready { intent: actual, .. }
                if actual.generation() == intent.generation()
                    && actual.owner() == intent.owner() =>
            {
                Ok(())
            }
            _ => Err("prepare-to-init handoff is not this retained armed owner".into()),
        }
    }
    fn assert_held(&self) -> Result<(), String> {
        self.cold
            .lock()
            .map_err(|_| "cold reservation poisoned")?
            .assert_retained()?;
        if self
            .safety
            .lock()
            .map_err(|_| "safety duplicate poisoned")?
            .is_none()
            || Instant::now() >= self.deadline
            || self.invalid.load(Ordering::Acquire)
        {
            return Err("initialization reservation/deadline unavailable; UNKNOWN".into());
        }
        Ok(())
    }
    pub(crate) fn unknown(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        *state = OwnerState::Unknown;
        // All actual files/lease/busy remain owned by this retained object.
    }
    pub(crate) fn begin_phase(
        self: &Arc<Self>,
        scope: &ExpectedInitScope,
    ) -> Result<OwnedPhaseContinuation, String> {
        scope.validate()?;
        self.assert_held()?;
        let mut state = self.state.lock().map_err(|_| "init owner state poisoned")?;
        let OwnerState::Ready { intent, next, .. } = &*state else {
            return Err("retained owner is not ready for one exact continuation".into());
        };
        intent.check_current(&self.world)?;
        let schedule =
            phase_schedule(self.reference.node_uid == intent.generation().initializer_node_uid);
        if schedule.get(*next) != Some(&scope.phase)
            || scope.target_node_uid != self.reference.node_uid
            || scope.target_boot != self.reference.node_boot_id
            || scope.owner != *intent.owner()
            || scope.generation != *intent.generation()
            || scope.remaining_budget_ms == 0
        {
            return Err(
                "continuation is repeated/out of order or changed exact target/generation/budget"
                    .into(),
            );
        }
        let current = intent.clone();
        let position = *next;
        *state = OwnerState::Running {
            intent: current.clone(),
            next: position,
            scope: scope.clone(),
        };
        Ok(OwnedPhaseContinuation {
            owner: self.clone(),
            scope: scope.clone(),
            intent: current,
            finished: false,
        })
    }
    fn check_running(&self, scope: &ExpectedInitScope) -> Result<(), String> {
        self.assert_held()?;
        let state = self.state.lock().map_err(|_| "init owner state poisoned")?;
        let OwnerState::Running {
            intent,
            scope: actual,
            ..
        } = &*state
        else {
            return Err("no actual owned running phase".into());
        };
        if actual != scope {
            return Err("current phase lineage changed".into());
        }
        intent.check_current(&self.world)
    }
    pub(crate) fn completed(
        &self,
        job: &Uid,
    ) -> Result<Option<(PhaseObservation, String)>, String> {
        self.assert_held()?;
        let state = self.state.lock().map_err(|_| "init owner state poisoned")?;
        match &*state {
            OwnerState::Ready {
                intent,
                completed: Some(done),
                ..
            } if &done.scope.phase_job_uid == job => {
                intent.check_current(&self.world)?;
                Ok(Some((
                    done.observation.clone(),
                    done.completion_sha256.clone(),
                )))
            }
            OwnerState::Running { scope, .. } if &scope.phase_job_uid == job => Ok(None),
            _ => Err("phase result is not this actual current retained job".into()),
        }
    }
    pub(crate) fn verify_detached_drain(
        self: &Arc<Self>,
        observed: &crate::raft_node::storage_remote_core::CoreObservation,
        config: &Config,
    ) -> Result<VerifiedIdleRelease, String> {
        self.assert_held()?;
        let state = self.state.lock().map_err(|_| "init owner state poisoned")?;
        let OwnerState::Ready {
            intent,
            next,
            completed: Some(done),
        } = &*state
        else {
            return Err("no physically completed final owner to release".into());
        };
        let schedule =
            phase_schedule(self.reference.node_uid == intent.generation().initializer_node_uid);
        if *next != schedule.len()
            || done.scope.phase != InitPhase::ObserveOffline
            || done.observation.offline.is_none()
        {
            return Err("release requires completed independent offline proof".into());
        }
        detached_current(intent, observed.volume())?;
        if observed.local_node_uid() != Some(&self.reference.node_uid)
            || observed.actual_boot() != &self.reference.node_boot_id
            || !crate::raft_node::storage_remote_core::is_actual_world(&self.world)
        {
            return Err("release observation is not actual exact local Core/boot".into());
        }
        let cgroup = JobCgroup::open(
            &config.delegated_cgroup_root,
            self.reference.node_uid.as_str(),
        )?;
        if cgroup.identity() != Ok(done.cgroup_identity)
            || cgroup.populated()?
            || cgroup.resource_snapshot(&config.budget)?.pids_current != 0
        {
            return Err("release lacks actual same-cgroup final drain".into());
        }
        cgroup.prune_empty_command_scopes()?;
        let census = cgroup.task_census_empty()?;
        if !census.processes.is_empty() || !census.threads.is_empty() {
            return Err("release task observations are not empty".into());
        }
        let journal = config.journal_root.join(self.reference.node_uid.as_str());
        let binding = Dir::open(&journal, false)?.read("cgroup-binding.json")?
            .ok_or("actual init cgroup binding absent at drain")?;
        let decoded: CgroupBinding = serde_json::from_slice(&binding)
            .map_err(|_| "actual init cgroup binding malformed at drain")?;
        if decoded.version != 1 || decoded.node_uid != self.reference.node_uid
            || decoded.boot_id != self.reference.node_boot_id.as_str()
            || (decoded.device, decoded.inode) != done.cgroup_identity {
            return Err("actual drained init cgroup binding changed".into());
        }
        let evidence = hash(
            &serde_json::to_vec(&(
                "initialized-idle-v4",
                &done.scope,
                &done.completion_sha256,
                &done.observation,
                observed.revision(),
                done.cgroup_identity,
            ))
            .map_err(|_| "cannot bind exact idle closeout")?,
        );
        self.assert_held()?;
        let slot = Arc::new(ReleasedInitializationSlot {
            cgroup, identity: done.cgroup_identity, root: config.delegated_cgroup_root.clone(),
            journal, binding_sha256: hash(&binding), node: self.reference.node_uid.clone(),
            boot: self.reference.node_boot_id.clone(), volume: self.reference.volume_uid.clone(),
            generation: intent.generation().uid.clone(), budget: config.budget.clone(),
        });
        Ok(VerifiedIdleRelease {
            owner: self.clone(),
            intent: intent.clone(),
            cgroup_identity: done.cgroup_identity,
            evidence,
            configuration: config.delegated_cgroup_root.clone(),
            slot,
        })
    }
}
fn detached_current(
    intent: &InitializationIntent,
    volume: &crate::storage_lifecycle::Volume,
) -> Result<(), String> {
    if volume.phase() != crate::storage_lifecycle::Phase::Detached
        || volume.epoch() != 0
        || volume.assignment().is_some()
        || volume.owner() != intent.owner()
        || volume.operation() != intent.operation_uid()
        || volume.data_generation() != Some(intent.generation())
    {
        return Err(
            "actual Core is not the exact acknowledged initialized Detached generation".into(),
        );
    }
    Ok(())
}
/// Only actual final supervisor proof + current Core + actual cgroup census
/// can mint this. Journal bytes cannot construct it, and Drop never releases.
pub(crate) struct VerifiedIdleRelease {
    owner: Arc<HeldInitializationOwner>,
    intent: InitializationIntent,
    cgroup_identity: (u64, u64),
    evidence: String,
    configuration: PathBuf,
    slot: Arc<ReleasedInitializationSlot>,
}

/// Producer-owned provenance of this uninterrupted Watch's ACTUAL successful
/// initialization release. It is NOT a future grant and has no wire constructor.
/// Its retained read-only cgroup FD outlives the expired init action deadline.
pub(crate) struct ReleasedInitializationSlot {
    cgroup: JobCgroup,
    identity: (u64,u64),
    root: PathBuf,
    journal: PathBuf,
    binding_sha256: String,
    node: Uid,
    boot: crate::storage_boot::BootId,
    volume: Uid,
    generation: Uid,
    budget: crate::storage_driver::job_cgroup::ResourceBudget,
}
impl ReleasedInitializationSlot {
    /// Lineage only, fixed dispatcher IO. Successful clone is returned with
    /// NO further fallible work: caller MUST root it in the SAME AttachOwner
    /// before recheck/role capture. Generation UID is not DatasetUID.
    pub(in crate::storage_driver) fn duplicate_for_owned_inventory(&self,config:&Config,
        scope:&crate::storage_lifecycle::pod_attachment::ExpectedAttachScope)->Result<JobCgroup,String>{
        if !self.inspect_empty(&config.delegated_cgroup_root,&config.node_uid,&scope.phase_boot,
            &scope.owner.volume_uid,&scope.generation.uid,&config.budget)?{
            return Err("actual original initialized cgroup is not known empty".into());}
        self.cgroup.try_clone()
    }
    pub(in crate::storage_driver) fn recheck_owned_inventory_clone(&self,actual:&JobCgroup,config:&Config,
        scope:&crate::storage_lifecycle::pod_attachment::ExpectedAttachScope)->Result<(),String>{
        if actual.identity()?!=self.identity||!self.inspect_empty(&config.delegated_cgroup_root,&config.node_uid,
            &scope.phase_boot,&scope.owner.volume_uid,&scope.generation.uid,&config.budget)?{
            return Err("rooted v7 cgroup clone is not SAME original released incarnation".into());}Ok(())
    }
    /// Existing fixed IO actor only. Scalars are expected DATA compared against
    /// the actual retained provenance; none can construct or renew authority.
    pub(in crate::storage_driver) fn inspect_empty(&self, root: &std::path::Path,
        node: &Uid, boot: &crate::storage_boot::BootId, volume: &Uid, generation: &Uid,
        budget: &crate::storage_driver::job_cgroup::ResourceBudget) -> Result<bool,String> {
        if !released_slot_scope_matches(&self.root,&self.node,&self.boot,&self.volume,&self.generation,
            &self.budget,root,node,boot,volume,generation,budget)
            || crate::storage_boot::BootId::current()? != self.boot {
            return Err("released-init slot differs from actual boot/node/dataset/configuration".into());
        }
        if std::fs::canonicalize(root).map_err(|_|"released cgroup parent absent")? != root {
            return Err("released cgroup parent path changed".into());
        }
        let named = std::fs::symlink_metadata(root.join(format!("rkjob-{}",node.as_str())))
            .map_err(|_| "same owned released cgroup path absent")?;
        if !named.is_dir() || named.uid()!=0 || named.mode() & 0o022 != 0
            || (named.dev(),named.ino()) != self.identity
            || self.cgroup.identity()? != self.identity {
            return Err("same retained released cgroup FD/path identity changed".into());
        }
        let raw = Dir::open(&self.journal,false)?.read("cgroup-binding.json")?
            .ok_or("same released cgroup binding absent")?;
        if hash(&raw) != self.binding_sha256 {return Err("same released cgroup binding changed".into());}
        let census = self.cgroup.task_census_empty()?;
        let resources = self.cgroup.resource_snapshot(budget)?;
        if !census.processes.is_empty() || !census.threads.is_empty()
            || resources.pids_current != 0 || self.cgroup.populated()?
            || self.cgroup.identity()? != self.identity {
            return Err("released cgroup is no longer known empty with exact caps".into());
        }
        let after=std::fs::symlink_metadata(root.join(format!("rkjob-{}",node.as_str())))
            .map_err(|_|"released cgroup named path disappeared during observation")?;
        if std::fs::canonicalize(root).map_err(|_|"released cgroup parent disappeared")? != root
            || !after.is_dir() || after.uid()!=0 || after.mode() & 0o022 != 0
            || (after.dev(),after.ino())!=self.identity || self.cgroup.identity()?!=self.identity {
            return Err("released cgroup path/FD changed during observation".into());
        }
        Ok(true)
    }
}
fn released_slot_scope_matches(held_root:&std::path::Path,held_node:&Uid,
    held_boot:&crate::storage_boot::BootId,held_volume:&Uid,held_generation:&Uid,
    held_budget:&crate::storage_driver::job_cgroup::ResourceBudget,root:&std::path::Path,node:&Uid,
    boot:&crate::storage_boot::BootId,volume:&Uid,generation:&Uid,
    budget:&crate::storage_driver::job_cgroup::ResourceBudget)->bool {
    held_root==root && held_node==node && held_boot==boot && held_volume==volume
        && held_generation==generation && held_budget==budget
}
impl VerifiedIdleRelease {
    pub(crate) fn evidence(&self) -> &str {
        &self.evidence
    }
    pub(crate) fn release(self) -> Result<(), String> {
        self.owner.assert_held()?;
        self.slot.inspect_empty(&self.configuration,&self.owner.reference.node_uid,
            &self.owner.reference.node_boot_id,&self.owner.reference.volume_uid,
            &self.intent.generation().uid,&self.slot.budget)?;
        let world = self
            .owner
            .world
            .try_read()
            .map_err(|_| "actual Detached graph busy at release")?;
        let volume = world
            .storage_identities
            .lifecycle
            .get(&self.intent.owner().volume_uid)
            .ok_or("actual Detached generation absent at release")?;
        detached_current(&self.intent, volume)?;
        world.storage_identities.validate(&world.to_state())?;
        let mut state = self
            .owner
            .state
            .lock()
            .map_err(|_| "init owner state poisoned")?;
        if !matches!(
            *state,
            OwnerState::Ready {
                completed: Some(_),
                ..
            }
        ) {
            return Err("actual owner no longer ready for success-only release".into());
        }
        let mut cold = self
            .owner
            .cold
            .lock()
            .map_err(|_| "cold reservation poisoned")?;
        let mut safety = self
            .owner
            .safety
            .lock()
            .map_err(|_| "safety reservation poisoned")?;
        if cold.reservation.lease.is_none() || safety.is_none() {
            return Err("release has no exact retained pair; never reset busy".into());
        }
        let mut released_slot = self.owner.released_slot.lock()
            .map_err(|_| "released init slot poisoned")?;
        if released_slot.is_some() || self.slot.identity != self.cgroup_identity {
            return Err("released-init provenance already installed or changed".into());
        }
        // All potentially slow I/O and mutex acquisition is now behind us.
        if !final_release_live(
            self.owner.deadline,
            Instant::now(),
            cold.cancelled.load(Ordering::Acquire),
            self.owner.invalid.load(Ordering::Acquire),
        ) {
            return Err(
                "final release became expired/cancelled/UNKNOWN; retain BOTH references".into(),
            );
        }
        cold.assert_retained()?;
        // Root the same actual FD BEFORE releasing either finite worker ref.
        // No fallible operation or physical observation follows this handoff.
        *released_slot = Some(self.slot);
        *state = OwnerState::Released;
        let primary = cold.reservation.lease.take();
        let duplicate = safety.take();
        drop(primary);
        drop(duplicate);
        cold.reservation.busy.store(false, Ordering::Release);
        Ok(())
    }
}
fn final_release_live(deadline: Instant, now: Instant, cancelled: bool, unknown: bool) -> bool {
    now < deadline && !cancelled && !unknown
}

/// Moving this continuation to the existing dispatcher never releases the
/// underlying owner. Lost caller/result or any early return makes it UNKNOWN.
pub(crate) struct OwnedPhaseContinuation {
    owner: Arc<HeldInitializationOwner>,
    scope: ExpectedInitScope,
    intent: InitializationIntent,
    finished: bool,
}
impl Drop for OwnedPhaseContinuation {
    fn drop(&mut self) {
        if !self.finished {
            self.owner.unknown();
        }
    }
}
impl OwnedPhaseContinuation {
    fn complete(mut self, verified: VerifiedPhaseCompletion) -> Result<(), String> {
        self.owner.check_running(&self.scope)?;
        verified
            .observation
            .validate_for(&self.intent, self.scope.phase, &self.owner.reference)?;
        if verified.scope != self.scope {
            return Err("supervised phase completion changed exact scope".into());
        }
        let mut state = self
            .owner
            .state
            .lock()
            .map_err(|_| "init owner state poisoned")?;
        let OwnerState::Running {
            intent,
            next,
            scope,
        } = &*state
        else {
            return Err("phase completion lost actual running ownership".into());
        };
        if scope != &self.scope {
            return Err("phase completion is stale/repeated".into());
        }
        let completed = CompletedPhase {
            scope: self.scope.clone(),
            observation: verified.observation,
            completion_sha256: verified.completion_sha256,
            cgroup_identity: verified.cgroup_identity,
        };
        *state = OwnerState::Ready {
            intent: intent.clone(),
            next: next + 1,
            completed: Some(completed),
        };
        self.finished = true;
        Ok(())
    }
}
struct VerifiedPhaseCompletion {
    scope: ExpectedInitScope,
    observation: PhaseObservation,
    completion_sha256: String,
    cgroup_identity: (u64, u64),
}

pub(super) struct InitializationWork {
    continuation: Option<OwnedPhaseContinuation>,
    parent: InitParent,
    pub(super) result: mpsc::SyncSender<Result<(), String>>,
}
pub(crate) struct InitializationTicket {
    result: mpsc::Receiver<Result<(), String>>,
    owner: Arc<HeldInitializationOwner>,
}
impl InitializationTicket {
    pub(crate) fn try_result(&self) -> Result<Option<()>, String> {
        match self.result.try_recv() {
            Ok(Ok(())) => Ok(Some(())),
            Ok(Err(error)) => Err(error),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(_) => Err("initialization supervisor result lost; UNKNOWN".into()),
        }
    }
    pub(crate) fn quarantine(&self) {
        self.owner.unknown();
    }
}
impl Dispatcher {
    pub(in crate::storage_driver) fn submit_owned_initialization(
        &self,
        continuation: OwnedPhaseContinuation,
        parent: InitParent,
    ) -> Result<InitializationTicket, String> {
        if !self.busy.load(Ordering::Acquire) {
            continuation.owner.unknown();
            return Err("owned continuation lost original busy reservation".into());
        }
        continuation.owner.check_running(&continuation.scope)?;
        let owner = continuation.owner.clone();
        let (send, receive) = mpsc::sync_channel(1);
        self.queue
            .try_send(WorkItem::Initialization(InitializationWork {
                continuation: Some(continuation),
                parent,
                result: send,
            }))
            .map_err(|_| "fixed dispatcher unavailable; owned initialization UNKNOWN")?;
        Ok(InitializationTicket {
            result: receive,
            owner,
        })
    }
}

/// Complete is produced only after actual child reap, cgroup/resource drain,
/// durable v4 Complete, exact observation parsing and fresh parent completion.
pub(super) fn run_phase(
    config: &Config,
    work: &mut InitializationWork,
) -> (Result<(), String>, Option<Quarantine>) {
    let mut quarantine = None;
    let result = (|| {
        let continuation = work
            .continuation
            .as_ref()
            .ok_or("owned continuation missing")?;
        let owner = continuation.owner.clone();
        let scope = continuation.scope.clone();
        let intent = continuation.intent.clone();
        owner.check_running(&scope)?;
        cold_authority::require_actual_cluster_world(&owner.world)?;
        if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
            return Err("distributed physical dispatcher requires Linux root; no fallback".into());
        }
        let (pool, plan, projection) = owner.agent.initialization_parts(&intent, &owner.world)?;
        let node = owner.reference.node_uid.clone();
        let boot = owner.reference.node_boot_id.as_str().to_string();
        if node != config.node_uid {
            return Err("phase dispatcher node changed".into());
        }
        let dirpath = config.journal_root.join(node.as_str());
        let dir = Dir::open(&dirpath, false)?;
        let entries = dir.bounded_entries(512)?;
        if entries
            .iter()
            .filter(|name| name.starts_with("attempt-"))
            .count()
            >= 128
        {
            return Err("128 immutable attempts retained; no phase admission".into());
        }
        // Clone the SAME already held open file description; never call lock().
        let lease = owner
            .cold
            .lock()
            .map_err(|_| "cold lease owner poisoned")?
            .reservation
            .lease
            .as_ref()
            .ok_or("retained original lease missing")?
            .try_clone()
            .map_err(|_| "cannot pass exact retained lease into phase")?;
        let cgroup = JobCgroup::open(&config.delegated_cgroup_root, node.as_str())?;
        let cgroup_identity = cgroup.identity()?;
        let binding: CgroupBinding = serde_json::from_slice(
            &dir.read("cgroup-binding.json")?
                .ok_or("continuation requires existing exact cgroup binding")?,
        )
        .map_err(|_| "invalid continuation cgroup binding")?;
        if binding.version != 1
            || binding.node_uid != node
            || binding.boot_id != boot
            || (binding.device, binding.inode) != cgroup_identity
            || cgroup.populated()?
        {
            return Err("original phase cgroup identity changed or is not drained".into());
        }
        cgroup.prune_empty_command_scopes()?;
        let prior = load_record(
            &dir.read("current.json")?
                .ok_or("completed predecessor absent")?,
        )?;
        if prior.state != State::Complete
            || prior.identity.node_uid != node
            || prior.identity.boot_id != boot
            || prior.identity.volume_uid != scope.owner.volume_uid
        {
            return Err("phase predecessor is not exact actual Complete/drained lineage".into());
        }
        let remaining = owner
            .deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(scope.remaining_budget_ms))
            .min(config.deadline);
        let worker_remaining_ms =
            u64::try_from(remaining.as_millis()).map_err(|_| "phase remaining time overflow")?;
        if worker_remaining_ms == 0 {
            return Err("original pipeline deadline expired before launch".into());
        }
        let payload = Payload {
            config: pool,
            plan,
            projection,
            extended: Some(ExtendedJob::InitializeDistributed),
            dataset_uid: Some(intent.generation().uid.clone()),
            remote_binding: Some(work.parent.binding()?),
            initialization: Some(scope.clone()),
            worker_remaining_ms: Some(worker_remaining_ms),
        };
        let payload_sha256 =
            hash(&serde_json::to_vec(&payload).map_err(|_| "cannot bind phase payload")?);
        let identity = live::JobIdentity {
            node_uid: node,
            boot_id: boot,
            volume_uid: scope.owner.volume_uid.clone(),
            operation_uid: intent.operation_uid().clone(),
            attempt_uid: Uid::new(),
            binding_sha256: hash(
                &serde_json::to_vec(&(
                    "distributed-init-phase-v4",
                    &scope,
                    &payload_sha256,
                    &config.helper_sha256,
                    &config.budget,
                ))
                .map_err(|_| "cannot bind actual phase job")?,
            ),
        };
        let resources_start = cgroup.enforce_budget(&config.budget)?;
        let capsule = Capsule {
            version: 4,
            identity: identity.clone(),
            payload,
            budget: config.budget.clone(),
        };
        if !valid_capsule_profile(&capsule) {
            return Err("invalid exact phase capsule profile".into());
        }
        let bytes = serde_json::to_vec(&capsule).map_err(|_| "cannot encode phase capsule")?;
        if bytes.len() as u64 > CAPSULE_LIMIT {
            return Err("phase capsule exceeds fixed bound".into());
        }
        let filename = format!("capsule-{}.json", identity.attempt_uid.as_str());
        dir.write(&filename, &bytes)?;
        let capsule_file = open_private(&dirpath.join(&filename))?;
        let mut record = Record {
            version: 4,
            identity: identity.clone(),
            payload_sha256,
            image_sha256: config.helper_sha256.clone(),
            state: State::LaunchIntent,
            resources_start,
            resources_final: None,
        };
        publish(&dir, &record)?;
        let image = open_image(&config.helper_image, &config.helper_sha256)?;
        work.parent.bind_native(&identity)?;
        let (control, child_control) =
            UnixStream::pair().map_err(|_| "cannot create inherited phase control")?;
        let procs = cgroup.procs_for_child()?;
        let fds = [
            lease.as_raw_fd(),
            capsule_file.as_raw_fd(),
            child_control.as_raw_fd(),
        ];
        let parent_pid = std::process::id();
        let mut command = Command::new(image_exec_path(&image, &config.helper_image)?);
        command
            .args(["storage-driver", "native-worker", "--journal"])
            .arg(&dirpath)
            .arg("--lease-fd")
            .arg(fds[0].to_string())
            .arg("--capsule-fd")
            .arg(fds[1].to_string())
            .arg("--control-fd")
            .arg(fds[2].to_string())
            .arg("--attempt")
            .arg(identity.attempt_uid.as_str())
            .arg("--cgroup-root")
            .arg(&config.delegated_cgroup_root)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LC_ALL", "C")
            .env("HOME", "/")
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        unsafe {
            command.pre_exec(move || {
                #[cfg(target_os = "linux")]
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() as u32 != parent_pid
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::write(procs.as_raw_fd(), b"0\n".as_ptr().cast(), 2) != 2 {
                    return Err(std::io::Error::last_os_error());
                }
                for fd in fds {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        owner.check_running(&scope)?;
        let observer = cgroup.try_clone()?;
        let cancel = owner
            .cold
            .lock()
            .map_err(|_| "cold cancellation owner poisoned")?
            .cancelled
            .clone();
        let child = command
            .spawn()
            .map_err(|_| "phase spawn UNKNOWN; durable intent retained")?;
        drop(child_control);
        drop(image);
        drop(capsule_file);
        let timeout = owner
            .deadline
            .saturating_duration_since(Instant::now())
            .min(remaining);
        let (outcome, retained) = supervise(
            child,
            control,
            cgroup,
            lease,
            timeout,
            &identity,
            &cancel,
            DiagnosticProfile::Initialization {
                scope: &scope,
                intent: &intent,
            },
            |request| work.parent.approve(request),
        )?;
        quarantine = retained;
        record.resources_final = Some(observer.resource_snapshot(&config.budget)?);
        let drained = record.resources_final.as_ref().is_some_and(|end| {
            end.pids_current == 0
                && end.cpu_usage_us >= record.resources_start.cpu_usage_us
                && end.cpu_user_us >= record.resources_start.cpu_user_us
                && end.cpu_system_us >= record.resources_start.cpu_system_us
        });
        let (stdout, extra_lease) = match outcome {
            Outcome::CompletedDiagnostics {
                stdout,
                retained_lease: Some(lease),
                ..
            } if drained && quarantine.is_none() && !observer.populated()? => (stdout, lease),
            _ => {
                record.state = State::Unknown;
                publish(&dir, &record)?;
                return Err(
                    "phase child/resources/cgroup outcome UNKNOWN; reservation retained".into(),
                );
            }
        };
        let observation: PhaseObservation = serde_json::from_slice(&stdout)
            .map_err(|_| "actual pinned helper phase output malformed")?;
        observation.validate_for(&intent, scope.phase, &owner.reference)?;
        record.state = State::Complete;
        publish(&dir, &record)?;
        let completion =
            VerifiedLocalBoundary::initialization_completion(&identity, &record, &stdout)?;
        work.parent.complete(&completion)?;
        let verified = VerifiedPhaseCompletion {
            scope,
            observation,
            completion_sha256: completion.binding().into(),
            cgroup_identity,
        };
        work.continuation
            .take()
            .ok_or("owned phase consumed twice")?
            .complete(verified)?;
        drop(extra_lease);
        Ok(())
    })();
    if result.is_err() {
        if let Some(continuation) = work.continuation.as_ref() {
            continuation.owner.unknown();
        }
    }
    (result, quarantine)
}

pub(crate) fn phase_schedule(initializer: bool) -> Vec<InitPhase> {
    use InitPhase::*;
    let all = [
        ActivateSecondary,
        ObserveFresh,
        Bootstrap,
        ObserveSynchronized,
        Promote,
        Format,
        FlushPrimary,
        ObserveReplicated,
        Demote,
        ObserveDemoted,
        Offline,
        ObserveOffline,
    ];
    all.into_iter()
        .filter(|phase| initializer || !phase.initializer_only())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn released_init_slot_scope_is_exact_data_not_a_new_action_deadline_or_grant() {
        let root=std::path::Path::new("/sys/fs/cgroup/owned");
        let node=Uid::new();let volume=Uid::new();let generation=Uid::new();
        let boot:crate::storage_boot::BootId=serde_json::from_str("\"71cb439a-d59b-4d47-9058-2134d97ebd7f\"").unwrap();
        let other_boot:crate::storage_boot::BootId=serde_json::from_str("\"81cb439a-d59b-4d47-9058-2134d97ebd7f\"").unwrap();
        let budget=crate::storage_driver::job_cgroup::ResourceBudget{
            pids_max:64,memory_max_bytes:256*1024*1024,cpu_quota_us:100_000,cpu_period_us:100_000};
        let check=|r:&std::path::Path,n:&Uid,b:&crate::storage_boot::BootId,v:&Uid,g:&Uid,
            caps:&crate::storage_driver::job_cgroup::ResourceBudget|released_slot_scope_matches(
                root,&node,&boot,&volume,&generation,&budget,r,n,b,v,g,caps);
        assert!(check(root,&node,&boot,&volume,&generation,&budget));
        assert!(!check(std::path::Path::new("/sys/fs/cgroup/other"),&node,&boot,&volume,&generation,&budget));
        assert!(!check(root,&Uid::new(),&boot,&volume,&generation,&budget));
        assert!(!check(root,&node,&other_boot,&volume,&generation,&budget));
        assert!(!check(root,&node,&boot,&Uid::new(),&generation,&budget));
        assert!(!check(root,&node,&boot,&volume,&Uid::new(),&budget));
        let mut changed=budget.clone();changed.pids_max+=1;
        assert!(!check(root,&node,&boot,&volume,&generation,&changed));
        // This pure comparator creates no ReleasedInitializationSlot, retained
        // FD, session permission, mount owner or receipt.
    }
    #[test]
    fn bounded_direct_read_requires_exact_phase_alignment_and_extent() {
        assert!(read_range_allowed(
            InitPhase::FlushPrimary,
            64 * 1024 * 1024,
            0,
            1024 * 1024
        ));
        assert!(read_range_allowed(InitPhase::ObserveOffline, 4096, 0, 4096));
        assert!(read_range_allowed(
            InitPhase::ActivateSecondary,
            4096,
            0,
            4096
        ));
        for (phase, bytes, offset, length) in [
            (InitPhase::Format, 4096, 0, 4096),
            (InitPhase::ObserveOffline, 4096, 1, 4096),
            (InitPhase::ObserveOffline, 4096, 0, 0),
            (InitPhase::ObserveOffline, 4096, 0, 8192),
            (InitPhase::FlushPrimary, u64::MAX, u64::MAX - 4095, 4096),
            (InitPhase::FlushPrimary, 4 * 1024 * 1024, 0, 2 * 1024 * 1024),
        ] {
            assert!(!read_range_allowed(phase, bytes, offset, length));
        }
    }
    #[test]
    fn secondary_phase_schedule_never_bootstraps_promotes_formats_or_flushes_primary() {
        let secondary = phase_schedule(false);
        assert_eq!(secondary.len(), 7);
        assert!(secondary.iter().all(|phase| !phase.initializer_only()));
        assert_eq!(phase_schedule(true).len(), 12);
        assert_eq!(secondary.last(), Some(&InitPhase::ObserveOffline));
    }
    #[test]
    fn final_idle_release_rechecks_late_deadline_cancel_and_unknown_after_io() {
        let start = Instant::now();
        let deadline = start + Duration::from_millis(1);
        assert!(final_release_live(deadline, start, false, false));
        assert!(!final_release_live(deadline, deadline, false, false));
        assert!(!final_release_live(deadline, start, true, false));
        assert!(!final_release_live(deadline, start, false, true));
        assert!(!final_release_live(
            deadline,
            deadline + Duration::from_secs(1),
            false,
            false
        ));
    }
}

