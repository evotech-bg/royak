//! Init-specific local control boundary. No route or init submission is wired.
//! Retain exact cold node reservations through generation commit; never turn
//! successful generic diagnostics, elapsed time or quorum into a writer/fence.
use super::*;
use crate::storage_lifecycle::generation::{
    InitializationIntent, ReservedInitialization, VirginReplicaRef,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ColdWire {
    kind: String,
    volume_uid: Uid,
    operation_uid: Uid,
    node_uid: Uid,
    node_boot_id: crate::storage_boot::BootId,
    pod_access_granted: bool,
    observation: VirginWire,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VirginWire {
    kind: String,
    reference: VirginReplicaRef,
}

/// The only constructor consumes three opaque, completed, still-held cold
/// jobs. Serialized references/CLI JSON cannot construct this capability.
pub(crate) struct RetainedLineage {
    jobs: [ColdPreparedHeld; 3],
    facts: [VirginReplicaRef; 3],
}
impl RetainedLineage {
    pub(crate) fn from_cold_jobs(
        jobs: [ColdPreparedHeld; 3],
        prepare: &ProvisionIntent,
    ) -> Result<Self, String> {
        let mut facts = Vec::with_capacity(3);
        for (i, job) in jobs.iter().enumerate() {
            let raw = job.diagnostics()?;
            let wire: ColdWire = serde_json::from_slice(raw)
                .map_err(|_| "invalid exact verified cold-worker report")?;
            let fact = wire.observation.reference;
            fact.validate()?;
            let target = &prepare.targets()[i];
            if wire.kind != "royak-agent-virgin-offline-prepared-v2"
                || wire.observation.kind != "royak-virgin-offline-replica-observation-v1"
                || wire.pod_access_granted
                || wire.volume_uid != prepare.owner().volume_uid
                || wire.operation_uid != *prepare.operation_uid()
                || wire.node_uid != target.node_uid
                || wire.node_boot_id != target.boot_id
                || job.intent.owner() != prepare.owner()
                || job.intent.operation_uid() != prepare.operation_uid()
                || fact.volume_uid != wire.volume_uid
                || fact.prepare_operation_uid != wire.operation_uid
                || fact.node_uid != wire.node_uid
                || fact.node_boot_id != wire.node_boot_id
                || fact.requested_bytes != prepare.capacity_bytes()
                || fact.pool_uid != job.expected_pool
                || fact.plan_sha256 != job.expected_plan_sha256
                || job.identity.node_uid != target.node_uid
            {
                return Err(
                    "cold attestation does not bind exact pinned worker/owner/plan/node/boot"
                        .into(),
                );
            }
            facts.push(fact);
        }
        let facts: [VirginReplicaRef; 3] = facts
            .try_into()
            .map_err(|_| "exactly three held cold jobs required")?;
        let held = Self { jobs, facts };
        held.assert_held()?;
        Ok(held)
    }
    pub(crate) fn facts(&self) -> &[VirginReplicaRef; 3] {
        &self.facts
    }
    pub(crate) fn assert_held(&self) -> Result<(), String> {
        for job in &self.jobs {
            if job.reservation.lease.is_none()
                || !job.reservation.busy.load(Ordering::Acquire)
                || job.cancelled.load(Ordering::Acquire)
            {
                return Err(
                    "cold node reservation cancelled/released; no initialization authority".into(),
                );
            }
        }
        Ok(())
    }
    pub(crate) fn matches_initialization(
        &self,
        intent: &InitializationIntent,
    ) -> Result<(), String> {
        self.assert_held()?;
        if self.facts != intent.generation().virgin_replicas
            || self.jobs.iter().any(|job| {
                job.intent.owner() != intent.owner()
                    || job.intent.operation_uid() != &intent.generation().prepare_operation_uid
            })
        {
            return Err(
                "retained cold reservations belong to another committed initialization".into(),
            );
        }
        Ok(())
    }
}

/// Private dispatcher factory only. It requires an actual durable reservation
/// retaining all three cold locks; test-only metadata sets cannot open it.
pub(super) struct InitializationParent {
    intent: InitializationIntent,
    world: Arc<RwLock<DesiredWorld>>,
    held: Arc<RetainedLineage>,
    identity: live::JobIdentity,
    deadline: Instant,
    cancelled: Arc<AtomicBool>,
}
impl InitializationParent {
    pub(super) fn new(
        reserved: ReservedInitialization,
        world: Arc<RwLock<DesiredWorld>>,
        identity: live::JobIdentity,
        deadline: Instant,
        cancelled: Arc<AtomicBool>,
    ) -> Result<Self, String> {
        let (intent, fresh) = reserved.into_parts();
        let held = fresh
            .retained_lineage()
            .ok_or("initialization requires three actual retained cold reservations")?
            .clone();
        held.matches_initialization(&intent)?;
        intent.check_current(&world)?;
        let boot: crate::storage_boot::BootId =
            serde_json::from_value(serde_json::json!(identity.boot_id))
                .map_err(|_| "invalid initializer boot")?;
        intent.local_initializer(&identity.node_uid, &boot)?;
        if identity.volume_uid != intent.owner().volume_uid
            || identity.operation_uid != *intent.operation_uid()
            || deadline <= Instant::now()
            || deadline > Instant::now() + Duration::from_secs(900)
            || !crate::raft_node::storage_remote_core::is_actual_world(&world)
        {
            return Err(
                "initialization parent is not bound to the actual live committed job".into(),
            );
        }
        Ok(Self {
            intent,
            world,
            held,
            identity,
            deadline,
            cancelled,
        })
    }
    pub(super) fn approve(&self, request: &live::Request) -> Result<Option<bool>, String> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Ok(Some(false));
        }
        let verified = VerifiedLocalBoundary::new(request, &self.identity)?;
        if !boundary_allowed(request, &self.identity, &self.intent)? {
            return Ok(Some(false));
        }
        self.held.matches_initialization(&self.intent)?;
        self.intent.check_current(&self.world)?;
        // This must run on the one dedicated dispatcher supervisor, never a
        // Tokio blocking-pool fan-out or a follower owns_state shortcut.
        let handle = crate::raft_node::RAFT
            .get()
            .ok_or("initialization requires real quorum-backed Raft")?;
        let observed = handle.rt.block_on(
            crate::raft_node::storage_remote_core::observe_native_issuer(
                &self.intent.owner().volume_uid,
                &verified,
            ),
        )?;
        observed.require_fresh_native(&verified, Instant::now())?;
        self.intent.check_current(&self.world)?;
        self.held.matches_initialization(&self.intent)?;
        if !self.intent.matches(observed.volume())
            || self.cancelled.load(Ordering::Acquire)
            || Instant::now() >= self.deadline
        {
            return Ok(Some(false));
        }
        Ok(Some(true))
    }
}
fn proof_digest(
    expected: &live::JobIdentity,
    intent: &InitializationIntent,
) -> Result<String, String> {
    Ok(hash(
        &serde_json::to_vec(&(
            "held-virgin-lineage-v2",
            expected,
            intent.owner(),
            intent.generation(),
        ))
        .map_err(|_| "cannot bind inherited virgin transfer")?,
    ))
}
/// Pure typed predicate only, never an authority/token constructor. The actual
/// callback above separately checks real world, held locks and a fresh barrier.
fn boundary_allowed(
    request: &live::Request,
    expected: &live::JobIdentity,
    intent: &InitializationIntent,
) -> Result<bool, String> {
    if request.version != 1
        || &request.identity != expected
        || expected.volume_uid != intent.owner().volume_uid
        || expected.operation_uid != *intent.operation_uid()
        || !valid_hash(&request.detail_sha256)
    {
        return Ok(false);
    }
    match request.boundary.as_str() {
        "helper-start" => Ok(request.detail_sha256 == hash(b"native-initialize-new-only-v2")),
        "identity-check" | "fixed-program" => Ok(true),
        "virgin-set-proof" => Ok(request.detail_sha256 == proof_digest(expected, intent)?),
        // Initializing an existing prepared generation must never reacquire
        // raw backing zeroing/allocation authority or an arbitrary boundary.
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn model() -> (
        Arc<RwLock<DesiredWorld>>,
        InitializationIntent,
        live::JobIdentity,
    ) {
        let (world, intent) =
            crate::storage_lifecycle::generation::model_initialization_for_authority_tests();
        let fact = &intent.generation().virgin_replicas[0];
        let id = live::JobIdentity {
            node_uid: fact.node_uid.clone(),
            boot_id: fact.node_boot_id.as_str().into(),
            volume_uid: intent.owner().volume_uid.clone(),
            operation_uid: intent.operation_uid().clone(),
            attempt_uid: Uid::new(),
            binding_sha256: "a".repeat(64),
        };
        (world, intent, id)
    }
    #[test]
    fn init_boundary_rejects_prepare_zeroing_and_unbound_transfer() {
        let (_, intent, id) = model();
        for boundary in [
            "zero-write",
            "zero-fsync",
            "prepare",
            "shell",
            "virgin-set-proof",
        ] {
            let request = live::Request {
                version: 1,
                identity: id.clone(),
                sequence: 1,
                nonce: Uid::new(),
                boundary: boundary.into(),
                detail_sha256: "b".repeat(64),
            };
            assert!(!boundary_allowed(&request, &id, &intent).unwrap());
        }
        let request = live::Request {
            version: 1,
            identity: id.clone(),
            sequence: 1,
            nonce: Uid::new(),
            boundary: "virgin-set-proof".into(),
            detail_sha256: proof_digest(&id, &intent).unwrap(),
        };
        assert!(boundary_allowed(&request, &id, &intent).unwrap()); // predicate only, no grant
    }
    #[test]
    fn init_checks_actual_scope_operation_and_boot_without_a_prepare_fallback() {
        let (world, intent, id) = model();
        intent.check_current(&world).unwrap();
        let request = live::Request {
            version: 1,
            identity: id.clone(),
            sequence: 1,
            nonce: Uid::new(),
            boundary: "identity-check".into(),
            detail_sha256: "b".repeat(64),
        };
        assert!(boundary_allowed(&request, &id, &intent).unwrap());
        let mut wrong = id.clone();
        wrong.operation_uid = Uid::new();
        assert!(!boundary_allowed(&request, &wrong, &intent).unwrap());
        world
            .write()
            .unwrap()
            .storage_identities
            .claims
            .get_mut(&crate::store::obj_key(
                &intent.owner().namespace,
                &intent.owner().claim_name,
            ))
            .unwrap()
            .uid = Uid::new();
        assert!(intent.check_current(&world).is_err());
        let mode = VerifiedWorkerMode {
            identity: id,
            extended: None,
            dataset_uid: Some(intent.generation().uid.clone()),
        };
        assert!(mode
            .check_initialization(&intent)
            .unwrap_err()
            .contains("separate v2 kind"));
    }
    #[test]
    fn native_barrier_challenge_binds_attempt_sequence_nonce_and_detail() {
        let (_, intent, id) = model();
        let request = live::Request {
            version: 1,
            identity: id.clone(),
            sequence: 1,
            nonce: Uid::new(),
            boundary: "identity-check".into(),
            detail_sha256: "b".repeat(64),
        };
        let first = VerifiedLocalBoundary::new(&request, &id).unwrap();
        let mut next = live::Request {
            version: 1,
            identity: id.clone(),
            sequence: 2,
            nonce: Uid::new(),
            boundary: "identity-check".into(),
            detail_sha256: "b".repeat(64),
        };
        assert_ne!(
            first.binding(),
            VerifiedLocalBoundary::new(&next, &id).unwrap().binding()
        );
        next.identity.operation_uid = Uid::new();
        assert!(VerifiedLocalBoundary::new(&next, &id).is_err());
        let _ = intent;
    }
    #[test]
    fn cold_and_legacy_modes_cannot_initialize_even_with_matching_logical_fields() {
        let (_, intent, identity) = model();
        for (extended, dataset_uid) in [
            (None, None),
            (Some(ExtendedJob::PrepareVirginOffline), None),
            (
                Some(ExtendedJob::PrepareVirginOffline),
                Some(intent.generation().uid.clone()),
            ),
            (Some(ExtendedJob::InitializeReserved), None),
            (Some(ExtendedJob::InitializeReserved), Some(Uid::new())),
        ] {
            let mode = VerifiedWorkerMode {
                identity: identity.clone(),
                extended,
                dataset_uid,
            };
            assert!(mode
                .check_initialization(&intent)
                .unwrap_err()
                .contains("separate v2 kind"));
        }
    }
}
