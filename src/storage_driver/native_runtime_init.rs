//! Producer-owned distributed rounds. Authenticated reports are retained as
//! data beside actual local ownership; they never become three local FDs.
use super::*;
use crate::storage_controller::ProvisionIntent;
use crate::storage_lifecycle::generation::{
    physical::{
        ExpectedInitScope, InitPhase, OfflineReplicaObservation, PhaseObservation,
        PrimaryFlushObservation,
    },
    DataGeneration, InitializationIntent, VirginReplicaRef,
};
use dispatcher::distributed_init::HeldInitializationOwner;

struct CommitScope {
    volume: Volume,
    exact_graph_sha256: String,
}
fn graph_hash(world: &DesiredWorld, volume: &Volume) -> Result<String, String> {
    world.storage_identities.validate(&world.to_state())?;
    let owner = volume.owner();
    let pv = world.pvs.get(&owner.pv_name).ok_or("round PV absent")?;
    let pvc = world
        .pvcs
        .get(&crate::store::obj_key(&owner.namespace, &owner.claim_name))
        .ok_or("round PVC absent")?;
    let class = world
        .storage_classes
        .get(&pv.storage_class)
        .ok_or("round class absent")?;
    let ns = world
        .storage_identities
        .namespaces
        .get(&owner.namespace)
        .ok_or("round namespace UID absent")?;
    let default = world
        .storage_identities
        .namespaces
        .get(crate::store::DEFAULT_NS)
        .ok_or("round default UID absent")?;
    if world.cluster_id != owner.cluster_id || ns != &owner.namespace_uid {
        return Err("round cluster/namespace incarnation changed".into());
    }
    Ok(digest(
        &serde_json::to_vec(&(
            world.cluster_id.as_str(),
            volume,
            pv,
            pvc,
            class,
            ns,
            default,
        ))
        .map_err(|_| "cannot bind exact round graph")?,
    ))
}
impl CommitScope {
    fn capture(shared: &Shared, volume: &Volume) -> Result<Self, String> {
        if !core::is_actual_world(&shared.world) {
            return Err("round refuses caller World".into());
        }
        let world = shared
            .world
            .try_read()
            .map_err(|_| "actual round World busy")?;
        if world.storage_identities.lifecycle.get(volume.uid()) != Some(volume) {
            return Err("round volume changed before exact scope capture".into());
        }
        Ok(Self {
            volume: volume.clone(),
            exact_graph_sha256: graph_hash(&world, volume)?,
        })
    }
    fn validate(&self, world: &DesiredWorld) -> Result<(), String> {
        if world.storage_identities.lifecycle.get(self.volume.uid()) != Some(&self.volume)
            || graph_hash(world, &self.volume)? != self.exact_graph_sha256
        {
            return Err("actual commit scratch graph changed since live round admission".into());
        }
        Ok(())
    }
}

pub(crate) struct DistributedColdRound {
    shared: Arc<Shared>,
    prepare: ProvisionIntent,
    facts: [VirginReplicaRef; 3],
    deadline: Instant,
    local: Arc<HeldInitializationOwner>,
    authenticated: Vec<VerifiedPeerFrame>,
    prepare_jobs: [Uid; 3],
    prepare_hashes: [String; 3],
    issuer_revision: protocol::Revision,
    directory_sha256: String,
}
impl DistributedColdRound {
    pub(crate) fn prepare(&self) -> &ProvisionIntent {
        &self.prepare
    }
    pub(crate) fn facts(&self) -> &[VirginReplicaRef; 3] {
        &self.facts
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    fn live(&self) -> Result<(), String> {
        if self.shared.pipeline_invalid.load(Ordering::Acquire)
            || Instant::now() >= self.deadline
            || self.authenticated.len() != 2
            || self.local.reference()
                != self
                    .facts
                    .iter()
                    .find(|fact| fact.node_uid == self.shared.pool.node_uid)
                    .ok_or("local cold fact absent")?
        {
            return Err(
                "distributed round expired/unknown/lost authenticated local lineage".into(),
            );
        }
        Ok(())
    }
}

pub(crate) struct ArmedInitializationRound {
    cold: DistributedColdRound,
    generation: DataGeneration,
    scope: CommitScope,
    arm_replies: Vec<VerifiedPeerFrame>,
}
impl ArmedInitializationRound {
    pub(crate) fn prepare(&self) -> &ProvisionIntent {
        self.cold.prepare()
    }
    pub(crate) fn generation(&self) -> &DataGeneration {
        &self.generation
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.cold.deadline
    }
    pub(crate) fn assert_actual_store(
        &self,
        world: &Arc<RwLock<DesiredWorld>>,
    ) -> Result<(), String> {
        self.cold.live()?;
        if !Arc::ptr_eq(world, &self.cold.shared.world)
            || !core::is_actual_world(world)
            || self.arm_replies.len() != 2
        {
            return Err(
                "armed round is not the actual store or three retained participants".into(),
            );
        }
        Ok(())
    }
    pub(crate) fn validate_commit_scope(&self, world: &DesiredWorld) -> Result<(), String> {
        self.cold.live()?;
        self.scope.validate(world)?;
        if self.generation.virgin_replicas != self.cold.facts
            || self.generation.prepare_operation_uid != *self.prepare().operation_uid()
            || !self.prepare().matches(&self.scope.volume)
        {
            return Err("prospective generation changed after exact inert arming".into());
        }
        self.generation.validate(&self.scope.volume)
    }
}

pub(crate) struct VerifiedInitializedRound {
    armed: Arc<ArmedInitializationRound>,
    intent: InitializationIntent,
    offline: [OfflineReplicaObservation; 3],
    primary: PrimaryFlushObservation,
    scope: CommitScope,
    completion_replies: Vec<VerifiedPeerFrame>,
    history: Vec<PhaseEvidence>,
}
impl VerifiedInitializedRound {
    pub(crate) fn intent(&self) -> &InitializationIntent {
        &self.intent
    }
    pub(crate) fn offline(&self) -> &[OfflineReplicaObservation; 3] {
        &self.offline
    }
    pub(crate) fn primary(&self) -> &PrimaryFlushObservation {
        &self.primary
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.armed.deadline()
    }
    pub(crate) fn assert_actual_store(
        &self,
        world: &Arc<RwLock<DesiredWorld>>,
    ) -> Result<(), String> {
        self.armed.assert_actual_store(world)?;
        if self.completion_replies.len() != 2 {
            return Err("independent current completions absent".into());
        }
        Ok(())
    }
    pub(crate) fn validate_commit_scope(&self, world: &DesiredWorld) -> Result<(), String> {
        self.armed.cold.live()?;
        self.scope.validate(world)?;
        if !self.intent.matches(&self.scope.volume)
            || self.intent.generation() != self.armed.generation()
        {
            return Err("completed round no longer matches actual init operation".into());
        }
        self.primary.validate_for(&self.intent)?;
        let mut nodes = std::collections::BTreeSet::new();
        for observed in &self.offline {
            observed.validate_for(&self.intent)?;
            if observed.data_sha256 != self.primary.data_sha256
                || !nodes.insert(&observed.replica.node_uid)
            {
                return Err(
                    "independent offline replicas differ from flushed designated primary".into(),
                );
            }
        }
        if nodes
            != self
                .intent
                .generation()
                .virgin_replicas
                .iter()
                .map(|fact| &fact.node_uid)
                .collect()
        {
            return Err("independent exact three-node set changed".into());
        }
        Ok(())
    }
}

/// Only this module's current actual coordinator can register the next full
/// expected phase. No deserializer/default/public raw-fields constructor.
pub(crate) struct ExpectedInitJob {
    spec: JobSpec,
    intent: InitializationIntent,
    deadline: Instant,
    shared: std::sync::Weak<Shared>,
    completed: AtomicBool,
}
impl ExpectedInitJob {
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn spec(&self) -> &JobSpec {
        &self.spec
    }
    pub(crate) fn hash(&self) -> Result<String, String> {
        Ok(digest(&protocol::encode_node(&self.spec)?))
    }
    pub(crate) fn require_current(
        &self,
        observed: &core::CoreObservation,
        directory: &VerifiedDirectory,
    ) -> Result<(), String> {
        let shared = self
            .shared
            .upgrade()
            .ok_or("actual runtime phase owner was lost")?;
        if self.completed.load(Ordering::Acquire)
            || shared.pipeline_invalid.load(Ordering::Acquire)
            || Instant::now() >= self.deadline
            || !self.intent.matches(observed.volume())
        {
            return Err("expected phase lost actual pipeline authority".into());
        }
        self.spec.check_observed(observed, directory)
    }
}
enum PhaseEvidence {
    Local {
        scope: ExpectedInitScope,
        completion_sha256: String,
    },
    Remote {
        scope: ExpectedInitScope,
        completion_sha256: String,
        frame: VerifiedPeerFrame,
    },
}
fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn remaining(deadline: Instant) -> Result<u64, String> {
    let value = u64::try_from(
        deadline
            .saturating_duration_since(Instant::now())
            .as_millis(),
    )
    .map_err(|_| "remaining pipeline accounting overflow")?;
    if value == 0 || value > 180_000 {
        return Err("original pipeline expired/out of bounds".into());
    }
    Ok(value)
}
async fn current_leader(
    shared: &Shared,
    intent: &InitializationIntent,
    original: &protocol::Revision,
    directory_sha256: &str,
) -> Result<(core::CoreObservation, VerifiedDirectory), String> {
    shared
        .pipeline_deadline()?
        .ok_or("original pipeline missing")?;
    let fresh = core::runtime_view(true).await?;
    let observed = core::observe_local_async(&intent.owner().volume_uid).await?;
    let directory = shared.directory_for(&observed)?;
    if fresh.local() != &shared.pool.node_uid
        || !observed.revision().at_least(fresh.revision())
        || !observed.revision().at_least(original)
        || directory.digest() != directory_sha256
        || !intent.matches(observed.volume())
        || observed.actual_boot() != fresh.boot()
    {
        return Err("original initializer leader/term/directory/owner changed; UNKNOWN".into());
    }
    Ok((observed, directory))
}
pub(super) async fn continue_pipeline(
    shared: Arc<Shared>,
    prepare: ProvisionIntent,
    ready: [NodeReadiness; 3],
    plans: Vec<replica::Plan>,
    interval: u64,
) -> Result<(), String> {
    let deadline = shared
        .pipeline_deadline()?
        .ok_or("no original pipeline budget")?;
    let local = ensure_owner(&shared, remaining(deadline)?).await?;
    let view = core::runtime_view(true).await?;
    let observed = core::observe_local_async(&prepare.owner().volume_uid).await?;
    let directory = shared.directory_for(&observed)?;
    if !prepare.matches(observed.volume())
        || !observed.revision().at_least(view.revision())
        || local.prepare().owner() != prepare.owner()
        || local.prepare().operation_uid() != prepare.operation_uid()
    {
        return Err("cold collector no longer owns the actual committed preparation".into());
    }
    let handles = std::mem::take(
        &mut *shared
            .remote_held
            .lock()
            .map_err(|_| "remote cold handles poisoned")?,
    );
    if handles.len() != 2 || plans.len() != 3 {
        return Err("three exact cold participants are missing".into());
    }
    let mut handles = handles.into_iter().map(Some).collect::<Vec<_>>();
    let mut facts = Vec::with_capacity(3);
    let mut jobs = Vec::with_capacity(3);
    let mut hashes = Vec::with_capacity(3);
    let mut authenticated = Vec::with_capacity(2);
    for (index, target) in prepare.targets().iter().enumerate() {
        let (fact, job, hash) = if target.node_uid == shared.pool.node_uid {
            (
                local.reference().clone(),
                local.prepare_job_uid().clone(),
                local.prepare_spec_sha256().to_string(),
            )
        } else {
            let slot = handles
                .iter_mut()
                .find(|slot| {
                    slot.as_ref()
                        .is_some_and(|held| held._node == target.node_uid)
                })
                .ok_or("authenticated exact cold node absent")?;
            let handle = slot.take().ok_or("cold node consumed twice")?;
            let fact = handle
                ._reference
                .ok_or("peer did not return versioned current cold reference")?;
            if handle._transport.sender() != &target.node_uid
                || handle._transport.receiver() != &shared.pool.node_uid
                || handle._evidence_sha256.len() != 64
            {
                return Err("cold reference is not bound to actual expected peer response".into());
            }
            authenticated.push(handle._transport);
            (fact, handle._job, handle._spec_sha256)
        };
        fact.validate()?;
        if fact.volume_uid != prepare.owner().volume_uid
            || fact.prepare_operation_uid != *prepare.operation_uid()
            || fact.node_uid != target.node_uid
            || fact.node_boot_id != target.boot_id
            || fact.pool_uid != ready[index].pool_uid
            || fact.plan_sha256 != plans[index].runtime_hash()?
            || fact.requested_bytes != prepare.capacity_bytes()
        {
            return Err(
                "independent cold fact changed exact committed node/pool/plan/boot lineage".into(),
            );
        }
        facts.push(fact);
        jobs.push(job);
        hashes.push(hash);
    }
    let cold = DistributedColdRound {
        shared: shared.clone(),
        prepare,
        facts: facts
            .try_into()
            .map_err(|_| "exact three ordered facts required")?,
        deadline,
        local,
        authenticated,
        prepare_jobs: jobs
            .try_into()
            .map_err(|_| "exact three cold jobs required")?,
        prepare_hashes: hashes
            .try_into()
            .map_err(|_| "exact three cold hashes required")?,
        issuer_revision: observed.revision().clone(),
        directory_sha256: directory.digest().to_string(),
    };
    cold.live()?;
    let generation = crate::storage_lifecycle::generation::propose_generation(
        &cold,
        shared.pool.node_uid.clone(),
        Uid::new(),
    )?;
    let generation_hash = digest(&protocol::encode_node(&generation)?);
    let mut arm_replies = Vec::with_capacity(2);
    for index in 0..3 {
        let fact = &cold.facts[index];
        if fact.node_uid == shared.pool.node_uid {
            cold.local.arm(&generation)?;
            let journal = shared.journal.clone();
            let owner = cold.local.clone();
            let data = generation.clone();
            shared.io.run(move || journal.arm(&owner, &data)).await?;
        } else {
            let nonce = Uid::new();
            let request = NodeJobRequest::ArmInitialization {
                nonce: nonce.clone(),
                prepare_job_uid: cold.prepare_jobs[index].clone(),
                prepare_spec_sha256: cold.prepare_hashes[index].clone(),
                generation: generation.clone(),
                remaining_budget_ms: remaining(deadline)?,
            };
            let peer = shared
                .call(
                    protocol::NODE_JOB_PATH,
                    &protocol::encode_node(&request)?,
                    &fact.node_uid,
                    &directory,
                )
                .await?;
            match protocol::decode_node(peer.body())? {
                NodeJobReply::Armed {
                    nonce: actual,
                    prepare_job_uid,
                    generation_sha256,
                    reference,
                } if actual == nonce
                    && prepare_job_uid == cold.prepare_jobs[index]
                    && generation_sha256 == generation_hash
                    && reference == *fact =>
                {
                    arm_replies.push(peer)
                }
                _ => {
                    return Err(
                        "inert arming reply UNKNOWN/mismatched; no reservation retry".into(),
                    )
                }
            }
        }
    }
    let actual = core::observe_local_async(&generation.virgin_replicas[0].volume_uid).await?;
    if !cold.prepare.matches(actual.volume())
        || !actual.revision().at_least(observed.revision())
        || shared.directory_for(&actual)?.digest() != directory.digest()
    {
        return Err("prepared scope changed while arming; UNKNOWN".into());
    }
    let scope = CommitScope::capture(&shared, actual.volume())?;
    let armed = Arc::new(ArmedInitializationRound {
        cold,
        generation,
        scope,
        arm_replies,
    });
    let world = shared.world.clone();
    let committing = armed.clone();
    let intent = shared
        .io
        .run(move || {
            crate::storage_lifecycle::generation::reserve_distributed_initialization(
                &world,
                &committing,
            )
            .map_err(|_| String::from("initialization commit UNKNOWN/refused; never retry"))
        })
        .await?;
    armed.cold.local.install_committed_intent(&intent)?;
    let (reserved, directory) =
        current_leader(&shared, &intent, observed.revision(), directory.digest()).await?;
    let journal = shared.journal.clone();
    let operation = intent.operation_uid().clone();
    let acknowledged = digest(&protocol::encode_node(intent.generation())?);
    shared
        .io
        .run(move || journal.phase(&operation, "INIT_RESERVED", &acknowledged))
        .await?;
    let mut primary = None;
    let mut offline = std::collections::BTreeMap::new();
    let mut final_replies = Vec::with_capacity(2);
    let mut history = Vec::with_capacity(26);
    use InitPhase::*;
    let phases = [
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
    for phase in phases {
        for (index, fact) in intent.generation().virgin_replicas.iter().enumerate() {
            if phase.initializer_only() && fact.node_uid != intent.generation().initializer_node_uid
            {
                continue;
            }
            let (current, current_directory) =
                current_leader(&shared, &intent, reserved.revision(), directory.digest()).await?;
            let scope = ExpectedInitScope {
                version: 1,
                owner: intent.owner().clone(),
                generation: intent.generation().clone(),
                issuer_node_uid: shared.pool.node_uid.clone(),
                issuer_boot: current.actual_boot().clone(),
                issuer_revision: current.revision().clone(),
                directory_sha256: directory.digest().to_string(),
                scope_sha256: current.scope_sha256().to_string(),
                target_node_uid: fact.node_uid.clone(),
                target_boot: fact.node_boot_id.clone(),
                prepare_job_uid: armed.cold.prepare_jobs[index].clone(),
                phase_job_uid: Uid::new(),
                phase,
                remaining_budget_ms: remaining(deadline)?,
            };
            let (observation, evidence) = if fact.node_uid == shared.pool.node_uid {
                run_local(&shared, &armed.cold.local, &intent, scope.clone()).await?
            } else {
                run_remote(
                    &shared,
                    &intent,
                    scope.clone(),
                    &current,
                    &current_directory,
                    deadline,
                    interval,
                )
                .await?
            };
            observation.validate_for(&intent, phase, fact)?;
            if let Some(value) = &observation.primary {
                primary = Some(value.clone());
            }
            if let Some(value) = &observation.offline {
                offline.insert(fact.node_uid.clone(), value.clone());
            }
            match evidence {
                PhaseEvidence::Remote {
                    frame,
                    scope,
                    completion_sha256,
                } if phase == ObserveOffline => {
                    final_replies.push(frame);
                    history.push(PhaseEvidence::Local {
                        scope,
                        completion_sha256,
                    });
                }
                other => history.push(other),
            }
        }
    }
    let (current, _) =
        current_leader(&shared, &intent, reserved.revision(), directory.digest()).await?;
    let scope = CommitScope::capture(&shared, current.volume())?;
    let ordered = intent
        .generation()
        .virgin_replicas
        .iter()
        .map(|fact| {
            offline
                .remove(&fact.node_uid)
                .ok_or("independent final offline observation absent")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let verified = Arc::new(VerifiedInitializedRound {
        armed,
        intent: intent.clone(),
        offline: ordered
            .try_into()
            .map_err(|_| "exact three independent offline observations required")?,
        primary: primary.ok_or("actual flushed designated primary proof absent")?,
        scope,
        completion_replies: final_replies,
        history,
    });
    let world = shared.world.clone();
    let finishing = verified.clone();
    let committed = shared
        .io
        .run(move || {
            crate::storage_lifecycle::generation::commit_distributed_provisioned(&world, &finishing)
                .map_err(|_| String::from("physical generation receipt commit UNKNOWN; no retry"))
        })
        .await?;
    let attachment_history=if shared.config.attaches() {
        Some(crate::storage_lifecycle::pod_attachment::InitialReplicaLineage::from_acknowledged_initialization(&shared.world,&verified,&committed)?)
    }else{None};
    release_all(&shared, &verified, &committed, deadline).await?;
    if let Some(history)=attachment_history {
        // Only after all actual Detached/drain/release acknowledgements.
        // DATA history is not a renewed initialization or attachment grant.
        super::mount::normal::remember_after_actual_release(&shared,&committed,history).await?;
    }
    Ok(())
}

async fn run_local(
    shared: &Arc<Shared>,
    owner: &Arc<HeldInitializationOwner>,
    intent: &InitializationIntent,
    scope: ExpectedInitScope,
) -> Result<(PhaseObservation, PhaseEvidence), String> {
    let parent = dispatcher::distributed_init::InitParent::establish_local(
        shared.clone(),
        owner,
        scope.clone(),
        intent,
    )
    .await?;
    let journal = shared.journal.clone();
    let actual = owner.clone();
    let recorded = scope.clone();
    shared
        .io
        .run(move || journal.local_init(&actual, &recorded))
        .await?;
    let continuation = owner.begin_phase(&scope)?;
    let ticket = shared
        .dispatcher
        .submit_owned_initialization(continuation, parent)?;
    wait_phase(ticket, owner.deadline()).await?;
    let (observation, completion_sha256) = owner
        .completed(&scope.phase_job_uid)?
        .ok_or("actual local completion absent")?;
    let journal = shared.journal.clone();
    let job = scope.phase_job_uid.clone();
    let evidence = completion_sha256.clone();
    shared
        .io
        .run(move || journal.phase(&job, "PHASE_COMPLETE", &evidence))
        .await?;
    Ok((
        observation,
        PhaseEvidence::Local {
            scope,
            completion_sha256,
        },
    ))
}
async fn run_remote(
    shared: &Arc<Shared>,
    intent: &InitializationIntent,
    scope: ExpectedInitScope,
    current: &core::CoreObservation,
    directory: &VerifiedDirectory,
    deadline: Instant,
    interval: u64,
) -> Result<(PhaseObservation, PhaseEvidence), String> {
    let fact = intent
        .generation()
        .virgin_replicas
        .iter()
        .find(|fact| fact.node_uid == scope.target_node_uid)
        .ok_or("phase exact target absent")?;
    let spec = JobSpec {
        version: 2,
        owner: scope.owner.clone(),
        operation_uid: intent.operation_uid().clone(),
        dataset_uid: Some(intent.generation().uid.clone()),
        kind: JobKind::InitializeVirginGeneration,
        issuer_node_uid: scope.issuer_node_uid.clone(),
        issuer_boot: scope.issuer_boot.clone(),
        target_node_uid: scope.target_node_uid.clone(),
        target_boot: scope.target_boot.clone(),
        job_uid: scope.phase_job_uid.clone(),
        plan_sha256: fact.plan_sha256.clone(),
        scope_sha256: scope.scope_sha256.clone(),
        directory_sha256: scope.directory_sha256.clone(),
        issuer_revision: scope.issuer_revision.clone(),
        maximum_duration_ms: scope.remaining_budget_ms,
        initialization: Some(scope.clone()),
    };
    spec.check_observed(current, directory)?;
    let expected = Arc::new(ExpectedInitJob {
        spec: spec.clone(),
        intent: intent.clone(),
        deadline,
        shared: Arc::downgrade(shared),
        completed: AtomicBool::new(false),
    });
    let journal = shared.journal.clone();
    let registration = expected.clone();
    shared
        .io
        .run(move || journal.register_init(&registration))
        .await?;
    {
        let mut book = shared
            .expected_init
            .lock()
            .map_err(|_| "expected init book poisoned")?;
        if book
            .get(&fact.node_uid)
            .is_some_and(|prior| !prior.completed.load(Ordering::Acquire))
        {
            return Err("prior actual phase unresolved; no expected job replacement".into());
        }
        book.insert(fact.node_uid.clone(), expected.clone());
    }
    let hash = expected.hash()?;
    let nonce = Uid::new();
    let inspect = NodeJobRequest::InspectInitialization {
        nonce: nonce.clone(),
        spec: spec.clone(),
    };
    let peer = shared
        .call(
            protocol::NODE_JOB_PATH,
            &protocol::encode_node(&inspect)?,
            &fact.node_uid,
            directory,
        )
        .await?;
    match protocol::decode_node(peer.body())? {
        NodeJobReply::InitializationReady {
            nonce: actual,
            expected_spec_sha256,
            scope_sha256,
            revision,
        } if actual == nonce
            && expected_spec_sha256 == hash
            && scope_sha256 == scope.scope_sha256
            && revision.at_least(&scope.issuer_revision) => {}
        _ => return Err("exact target applied initialization readiness absent; no Offer".into()),
    }
    let offer = NodeJobRequest::OfferInitialization { spec: spec.clone() };
    let peer = shared
        .call(
            protocol::NODE_JOB_PATH,
            &protocol::encode_node(&offer)?,
            &fact.node_uid,
            directory,
        )
        .await?;
    match protocol::decode_node(peer.body())? {
        NodeJobReply::Offered {
            job_uid,
            spec_sha256,
        } if job_uid == spec.job_uid && spec_sha256 == hash => {}
        _ => return Err("phase offer reply UNKNOWN; no repeat".into()),
    }
    loop {
        if Instant::now() >= deadline {
            return Err("original pipeline expired while observing phase".into());
        }
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let nonce = Uid::new();
        let inspect = NodeJobRequest::InspectPhase {
            nonce: nonce.clone(),
            job_uid: spec.job_uid.clone(),
            spec_sha256: hash.clone(),
        };
        let peer = shared
            .call(
                protocol::NODE_JOB_PATH,
                &protocol::encode_node(&inspect)?,
                &fact.node_uid,
                directory,
            )
            .await?;
        match protocol::decode_node(peer.body())? {
            NodeJobReply::PhaseWorking {
                nonce: actual,
                job_uid,
                spec_sha256,
            } if actual == nonce && job_uid == spec.job_uid && spec_sha256 == hash => {}
            NodeJobReply::PhaseComplete {
                nonce: actual,
                job_uid,
                spec_sha256,
                observation,
                completion_sha256,
            } if actual == nonce
                && job_uid == spec.job_uid
                && spec_sha256 == hash
                && is_hash(&completion_sha256) =>
            {
                observation.validate_for(intent, scope.phase, fact)?;
                let current =
                    core::observe_issuer(&scope.owner.volume_uid, peer.read_challenge()).await?;
                current.require_fresh_issuer_for(
                    &peer,
                    Instant::now(),
                    Duration::from_millis(core::MAX_STORAGE_BOUNDARY_MS),
                )?;
                let directory = shared.directory_for(&current)?;
                expected.require_current(&current, &directory)?;
                expected.completed.store(true, Ordering::Release);
                return Ok((
                    observation,
                    PhaseEvidence::Remote {
                        scope,
                        completion_sha256,
                        frame: peer,
                    },
                ));
            }
            _ => {
                return Err("phase status/completion UNKNOWN or mismatched; no next action".into())
            }
        }
    }
}
async fn release_all(
    shared: &Arc<Shared>,
    verified: &VerifiedInitializedRound,
    committed: &crate::storage_lifecycle::generation::CommittedGeneration,
    deadline: Instant,
) -> Result<(), String> {
    let fresh = core::runtime_view(true).await?;
    let observed = core::observe_local_async(&committed.owner().volume_uid).await?;
    let directory = shared.directory_for(&observed)?;
    if committed.generation() != verified.intent().generation()
        || observed.volume().phase() != Phase::Detached
        || observed.volume().assignment().is_some()
        || observed.volume().data_generation() != Some(committed.generation())
        || !observed.revision().at_least(fresh.revision())
        || !observed
            .revision()
            .at_least(&verified.armed.cold.issuer_revision)
        || directory.digest() != verified.armed.cold.directory_sha256
        || Instant::now() >= deadline
    {
        return Err(
            "actual exact Detached publication/leader unavailable; keep reservations".into(),
        );
    }
    for fact in &committed.generation().virgin_replicas {
        if fact.node_uid == shared.pool.node_uid {
            continue;
        }
        let nonce = Uid::new();
        let request = NodeJobRequest::AcknowledgeDetached {
            nonce: nonce.clone(),
            data_generation_uid: committed.generation().uid.clone(),
            initialize_operation_uid: committed.intent().operation_uid().clone(),
            minimum_revision: observed.revision().clone(),
        };
        let peer = shared
            .call(
                protocol::NODE_JOB_PATH,
                &protocol::encode_node(&request)?,
                &fact.node_uid,
                &directory,
            )
            .await?;
        match protocol::decode_node(peer.body())? {
            NodeJobReply::DetachedAcknowledged {
                nonce: actual,
                data_generation_uid,
                initialize_operation_uid,
                closeout_sha256,
            } if actual == nonce
                && data_generation_uid == committed.generation().uid
                && initialize_operation_uid == *committed.intent().operation_uid()
                && is_hash(&closeout_sha256) => {}
            _ => return Err("remote actual Detached release UNKNOWN; no reset/retry".into()),
        }
    }
    let owner = verified.armed.cold.local.clone();
    let released_owner = shared.config.attaches().then(||owner.clone());
    let config = shared.dispatcher_configuration();
    let release = shared
        .io
        .run(move || owner.verify_detached_drain(&observed, &config))
        .await?;
    let evidence = release.evidence().to_string();
    let journal = shared.journal.clone();
    let operation = committed.intent().operation_uid().clone();
    shared
        .io
        .run(move || journal.phase(&operation, "DETACHED_DRAINED", &evidence))
        .await?;
    shared.io.run(move || release.release()).await?;
    if let Some(owner)=released_owner {
        super::mount::normal::retain_released_slot(shared,owner).await?;
    }
    shared.incoming.store(false, Ordering::Release);
    Ok(())
}

fn known_owner(shared: &Shared) -> Result<Arc<HeldInitializationOwner>, String> {
    shared
        .initialization_owner
        .lock()
        .map_err(|_| "initialization owner poisoned")?
        .as_ref()
        .cloned()
        .ok_or_else(|| "actual same-process initialization owner absent; no reconstruction".into())
}
fn install_owner(
    shared: &Arc<Shared>,
    remaining_ms: u64,
) -> Result<Arc<HeldInitializationOwner>, String> {
    if let Ok(owner) = known_owner(shared) {
        return Ok(owner);
    }
    if remaining_ms == 0 || remaining_ms > 180_000 {
        return Err("invalid remaining cold pipeline budget".into());
    }
    let deadline = shared
        .pipeline_deadline()?
        .ok_or("original cold pipeline budget absent")?
        .min(Instant::now() + Duration::from_millis(remaining_ms));
    let mut target = shared
        .initialization_owner
        .lock()
        .map_err(|_| "initialization owner poisoned")?;
    if let Some(owner) = target.as_ref() {
        return Ok(owner.clone());
    }
    let mut held = shared
        .held
        .lock()
        .map_err(|_| "actual cold held owner poisoned")?;
    let mut safety = shared
        .unknown_lease
        .lock()
        .map_err(|_| "actual safety reservation poisoned")?;
    let (job, hash, cold, durable) = held.take().ok_or("no actual cold completion to continue")?;
    if !durable {
        *held = Some((job, hash, cold, durable));
        return Err("actual cold closeout was not durable; no arming".into());
    }
    let Some(duplicate) = safety.take() else {
        *held = Some((job, hash, cold, durable));
        return Err("cold safety reference absent; no lock reconstruction".into());
    };
    match HeldInitializationOwner::from_actual_cold(
        cold,
        duplicate,
        deadline,
        job.clone(),
        hash.clone(),
        shared.pipeline_invalid.clone(),
    ) {
        Ok(owner) => {
            *target = Some(owner.clone());
            Ok(owner)
        }
        Err((cold, duplicate, error)) => {
            *held = Some((job, hash, cold, durable));
            *safety = Some(duplicate);
            Err(error)
        }
    }
}
async fn ensure_owner(
    shared: &Arc<Shared>,
    remaining: u64,
) -> Result<Arc<HeldInitializationOwner>, String> {
    let actual = shared.clone();
    shared
        .io
        .run(move || install_owner(&actual, remaining))
        .await
}
fn require_issuer(
    shared: &Shared,
    peer: &VerifiedPeerFrame,
    observed: &core::CoreObservation,
    directory: &VerifiedDirectory,
) -> Result<(), String> {
    if peer.receiver() != &shared.pool.node_uid
        || observed.local_node_uid() != Some(&shared.pool.node_uid)
        || directory.pin(peer.sender())?.raft_id != observed.revision().leader_raft_id
    {
        return Err(
            "private init request is not exact current leader to local enrolled boot".into(),
        );
    }
    Ok(())
}
pub(super) async fn handle(
    shared: Arc<Shared>,
    peer: VerifiedPeerFrame,
    request: NodeJobRequest,
    request_deadline: Instant,
) -> Result<Vec<u8>, String> {
    if !shared.config.initializes() {
        return Err("this runtime is explicitly cold-only; init refused".into());
    }
    let deadline = shared
        .pipeline_deadline()?
        .ok_or("original live cold pipeline absent")?
        .min(request_deadline);
    let reply = match request {
        NodeJobRequest::ArmInitialization {
            nonce,
            prepare_job_uid,
            prepare_spec_sha256,
            generation,
            remaining_budget_ms,
        } => {
            let observed =
                core::observe_local_async(&generation.virgin_replicas[0].volume_uid).await?;
            let directory = shared.directory_for(&observed)?;
            require_issuer(&shared, &peer, &observed, &directory)?;
            let owner = ensure_owner(&shared, remaining_budget_ms).await?;
            if owner.prepare_job_uid() != &prepare_job_uid
                || owner.prepare_spec_sha256() != prepare_spec_sha256
            {
                return Err("arm request changed exact cold job binding".into());
            }
            owner.arm(&generation)?;
            let journal = shared.journal.clone();
            let actual = owner.clone();
            let prospective = generation.clone();
            if let Err(error) = shared
                .io
                .run(move || journal.arm(&actual, &prospective))
                .await
            {
                shared.unknown(Some(prepare_job_uid), "ARM_DURABILITY_UNKNOWN");
                return Err(error);
            }
            if Instant::now() >= deadline {
                shared.unknown(None, "ARM_REPLY_DEADLINE");
                return Err("arm reply expired; UNKNOWN".into());
            }
            NodeJobReply::Armed {
                nonce,
                prepare_job_uid,
                generation_sha256: digest(&protocol::encode_node(&generation)?),
                reference: owner.reference().clone(),
            }
        }
        NodeJobRequest::InspectInitialization { nonce, spec } => {
            let owner = known_owner(&shared)?;
            let scope = spec
                .initialization
                .as_ref()
                .ok_or("exact phase scope absent")?;
            if peer.sender() != &spec.issuer_node_uid || peer.receiver() != &spec.target_node_uid {
                return Err("phase readiness wrong authenticated issuer/target".into());
            }
            core::wait_applied_hint(&spec.issuer_revision, deadline.min(owner.deadline())).await?;
            let observed = core::observe_local_async(&spec.owner.volume_uid).await?;
            let directory = shared.directory_for(&observed)?;
            require_issuer(&shared, &peer, &observed, &directory)?;
            spec.check_observed(&observed, &directory)?;
            owner.check_offer(scope)?;
            NodeJobReply::InitializationReady {
                nonce,
                expected_spec_sha256: digest(&protocol::encode_node(&spec)?),
                scope_sha256: observed.scope_sha256().into(),
                revision: observed.revision().clone(),
            }
        }
        NodeJobRequest::OfferInitialization { spec } => {
            let owner = known_owner(&shared)?;
            let scope = spec
                .initialization
                .as_ref()
                .ok_or("exact phase scope absent")?;
            let observed = core::observe_local_async(&spec.owner.volume_uid).await?;
            let directory = shared.directory_for(&observed)?;
            require_issuer(&shared, &peer, &observed, &directory)?;
            if peer.sender() != &spec.issuer_node_uid || peer.receiver() != &spec.target_node_uid {
                return Err("phase offer wrong authenticated issuer/target".into());
            }
            spec.check_observed(&observed, &directory)?;
            owner.check_offer(scope)?;
            shared
                .init_receiver_busy
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map_err(|_| "one exact initialization offer already active/unknown")?;
            let spec_hash = digest(&protocol::encode_node(&spec)?);
            *shared
                .init_receiver_job
                .lock()
                .map_err(|_| "phase receiver state poisoned")? =
                Some((spec.job_uid.clone(), spec_hash.clone(), spec.clone()));
            let journal = shared.journal.clone();
            let admitted = spec.clone();
            if let Err(error) = shared
                .io
                .run(move || journal.receiver_init(&admitted))
                .await
            {
                shared.unknown(Some(spec.job_uid.clone()), "PHASE_INTENT_UNKNOWN");
                return Err(error);
            }
            let receiver = shared.clone();
            let job = spec.clone();
            tokio::spawn(async move {
                if let Err(_error) = run_remote_phase(receiver.clone(), owner, job.clone()).await {
                    receiver.unknown(Some(job.job_uid), "INIT_PHASE_UNKNOWN");
                }
            });
            NodeJobReply::Offered {
                job_uid: spec.job_uid,
                spec_sha256: spec_hash,
            }
        }
        NodeJobRequest::InspectPhase {
            nonce,
            job_uid,
            spec_sha256,
        } => {
            let owner = known_owner(&shared)?;
            let (_, hash, spec) = shared
                .init_receiver_job
                .lock()
                .map_err(|_| "phase receiver state poisoned")?
                .as_ref()
                .filter(|(job, hash, _)| job == &job_uid && hash == &spec_sha256)
                .cloned()
                .ok_or("phase status differs from exact admitted job")?;
            let observed = core::observe_local_async(&spec.owner.volume_uid).await?;
            let directory = shared.directory_for(&observed)?;
            require_issuer(&shared, &peer, &observed, &directory)?;
            spec.check_observed(&observed, &directory)?;
            match owner.completed(&job_uid) {
                Ok(Some((observation, completion_sha256)))
                    if !shared.init_receiver_busy.load(Ordering::Acquire) =>
                {
                    NodeJobReply::PhaseComplete {
                        nonce,
                        job_uid,
                        spec_sha256: hash,
                        observation,
                        completion_sha256,
                    }
                }
                _ if shared.init_receiver_busy.load(Ordering::Acquire) => {
                    NodeJobReply::PhaseWorking {
                        nonce,
                        job_uid,
                        spec_sha256: hash,
                    }
                }
                _ => return Err("actual completed phase unavailable; UNKNOWN".into()),
            }
        }
        NodeJobRequest::AcknowledgeDetached {
            nonce,
            data_generation_uid,
            initialize_operation_uid,
            minimum_revision,
        } => {
            let owner = known_owner(&shared)?;
            core::wait_applied_hint(&minimum_revision, deadline.min(owner.deadline())).await?;
            let observed = core::observe_local_async(&owner.reference().volume_uid).await?;
            let directory = shared.directory_for(&observed)?;
            require_issuer(&shared, &peer, &observed, &directory)?;
            if observed
                .volume()
                .data_generation()
                .map(|generation| &generation.uid)
                != Some(&data_generation_uid)
                || observed.volume().operation() != &initialize_operation_uid
                || shared.init_receiver_busy.load(Ordering::Acquire)
            {
                return Err("Detached acknowledgement differs or has active/unknown phase".into());
            }
            let config = shared.dispatcher_configuration();
            let actual = owner.clone();
            let release = shared
                .io
                .run(move || actual.verify_detached_drain(&observed, &config))
                .await?;
            let evidence = release.evidence().to_string();
            let journal = shared.journal.clone();
            let job = initialize_operation_uid.clone();
            let proof = evidence.clone();
            if let Err(error) = shared
                .io
                .run(move || journal.phase(&job, "DETACHED_DRAINED", &proof))
                .await
            {
                shared.unknown(Some(initialize_operation_uid), "DETACHED_CLOSEOUT_UNKNOWN");
                return Err(error);
            }
            if let Err(error) = shared.io.run(move || release.release()).await {
                shared.unknown(Some(initialize_operation_uid), "DETACHED_RELEASE_UNKNOWN");
                return Err(error);
            }
            if shared.config.attaches() {
                if let Err(error)=super::mount::normal::retain_released_slot(&shared,owner).await {
                    shared.unknown(Some(initialize_operation_uid),"DETACHED_SLOT_HANDOFF_UNKNOWN");
                    return Err(error);
                }
            }
            shared.incoming.store(false, Ordering::Release);
            NodeJobReply::DetachedAcknowledged {
                nonce,
                data_generation_uid,
                initialize_operation_uid,
                closeout_sha256: evidence,
            }
        }
        _ => return Err("not an initialization node operation".into()),
    };
    protocol::encode_node(&reply)
}
async fn wait_phase(
    ticket: dispatcher::distributed_init::InitializationTicket,
    deadline: Instant,
) -> Result<(), String> {
    loop {
        match ticket.try_result() {
            Ok(Some(())) => return Ok(()),
            Ok(None) => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            ticket.quarantine();
            return Err("original pipeline expired; owned worker retained UNKNOWN".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn run_remote_phase(
    shared: Arc<Shared>,
    owner: Arc<HeldInitializationOwner>,
    spec: JobSpec,
) -> Result<(), String> {
    let (parent, _intent) = dispatcher::distributed_init::InitParent::establish_remote(
        shared.clone(),
        &owner,
        spec.clone(),
    )
    .await?;
    let continuation =
        owner.begin_phase(spec.initialization.as_ref().ok_or("phase scope absent")?)?;
    let ticket = shared
        .dispatcher
        .submit_owned_initialization(continuation, parent)?;
    wait_phase(ticket, owner.deadline()).await?;
    let (_, evidence) = owner
        .completed(&spec.job_uid)?
        .ok_or("actual phase completion absent")?;
    let journal = shared.journal.clone();
    let job = spec.job_uid;
    shared
        .io
        .run(move || journal.phase(&job, "PHASE_COMPLETE", &evidence))
        .await?;
    shared.init_receiver_busy.store(false, Ordering::Release);
    Ok(())
}

#[cfg(test)]
mod scope_tests {
    use super::*;
    #[test]
    fn supplied_round_graph_cannot_hide_namespace_recreation() {
        let (world, intent) =
            crate::storage_lifecycle::generation::model_initialization_for_authority_tests();
        let mut changed = world.read().unwrap().clone();
        let volume = changed
            .storage_identities
            .lifecycle
            .get(&intent.owner().volume_uid)
            .unwrap()
            .clone();
        let original = graph_hash(&changed, &volume).unwrap();
        changed
            .storage_identities
            .namespaces
            .insert(intent.owner().namespace.clone(), Uid::new());
        assert!(graph_hash(&changed, &volume).is_err());
        assert_eq!(original.len(), 64);
    }
}

