//! Cold preparation never treats a supplied projection/cache as authority.
//! Standalone cold is unsupported; historical online diagnostics are separate.
use super::*;
use crate::raft_node::storage_remote_core::{self as core, CoreObservation};

pub(super) fn require_actual_cluster_world(
    world: &Arc<RwLock<DesiredWorld>>,
) -> Result<(), String> {
    let handle = crate::raft_node::RAFT
        .get()
        .ok_or("cold preparation requires actual durable Raft")?;
    if handle.sealing != crate::raft_node::Sealing::Cluster || !core::is_actual_world(world) {
        return Err("cold preparation refuses standalone, frozen clone and foreign world".into());
    }
    Ok(())
}

pub(super) struct ColdParent<'a> {
    world: &'a Arc<RwLock<DesiredWorld>>,
    intent: &'a ProvisionIntent,
    identity: &'a live::JobIdentity,
    cancelled: &'a AtomicBool,
    deadline: Instant,
    expected_scope: String,
    expected_directory: String,
    expected_revision: crate::storage_remote_protocol::Revision,
}
impl<'a> ColdParent<'a> {
    pub(super) fn new(
        world: &'a Arc<RwLock<DesiredWorld>>,
        intent: &'a ProvisionIntent,
        identity: &'a live::JobIdentity,
        deadline: Instant,
        cancelled: &'a AtomicBool,
    ) -> Result<Self, String> {
        require_actual_cluster_world(world)?;
        intent.check_current(world)?;
        let local = core::observe_local(&intent.owner().volume_uid)?;
        let directory = local
            .directory_commitment()
            .ok_or("cold directory not enrolled")?;
        validate_observation(
            intent,
            identity,
            local.scope_sha256(),
            directory,
            local.revision(),
            &local,
        )?;
        if crate::raft_node::RAFT.get().map(|h| h.node_id) != Some(local.revision().leader_raft_id)
        {
            return Err("cold dispatch is not on the actual current leader".into());
        }
        if !decision_live(cancelled.load(Ordering::Acquire), deadline, Instant::now()) {
            return Err("cold dispatch already cancelled/expired".into());
        }
        Ok(Self {
            world,
            intent,
            identity,
            cancelled,
            deadline,
            expected_scope: local.scope_sha256().to_string(),
            expected_directory: directory.to_string(),
            expected_revision: local.revision().clone(),
        })
    }
    pub(super) fn approve(&self, request: &live::Request) -> Result<Option<bool>, String> {
        if !boundary_allowed(request, self.identity) {
            return Ok(Some(false));
        }
        let challenge = VerifiedLocalBoundary::cold(request, self.identity)?;
        self.check_fresh(&challenge)?;
        Ok(Some(true))
    }
    pub(super) fn complete(&self, completion: &VerifiedLocalBoundary) -> Result<(), String> {
        self.check_fresh(completion)
    }
    fn check_fresh(&self, challenge: &VerifiedLocalBoundary) -> Result<(), String> {
        if !decision_live(
            self.cancelled.load(Ordering::Acquire),
            self.deadline,
            Instant::now(),
        ) {
            return Err("cold boundary cancelled/expired; no new action or held proof".into());
        }
        require_actual_cluster_world(self.world)?;
        self.intent.check_current(self.world)?;
        // One fixed std::thread supervisor only. No cached scheduler lease,
        // follower owns_state, copied leader state or JSON-supplied revision.
        let handle = crate::raft_node::RAFT
            .get()
            .ok_or("actual cold issuer missing")?;
        let observed = handle.rt.block_on(core::observe_native_issuer(
            &self.intent.owner().volume_uid,
            challenge,
        ))?;
        observed.require_fresh_native(challenge, Instant::now())?;
        require_actual_cluster_world(self.world)?;
        self.intent.check_current(self.world)?;
        validate_observation(
            self.intent,
            self.identity,
            &self.expected_scope,
            &self.expected_directory,
            &self.expected_revision,
            &observed,
        )?;
        if !decision_live(
            self.cancelled.load(Ordering::Acquire),
            self.deadline,
            Instant::now(),
        ) {
            return Err("cold approval raced cancellation/deadline after quorum barrier".into());
        }
        Ok(())
    }
}
fn decision_live(cancelled: bool, deadline: Instant, now: Instant) -> bool {
    !cancelled && now < deadline
}
fn boundary_allowed(request: &live::Request, identity: &live::JobIdentity) -> bool {
    request.version == 1
        && request.sequence > 0
        && &request.identity == identity
        && valid_hash(&request.detail_sha256)
        && match request.boundary.as_str() {
            "helper-start" => request.detail_sha256 == hash(b"native-virgin-offline-only-v2"),
            "identity-check" | "fixed-program" | "zero-write" | "zero-fsync" => true,
            _ => false,
        }
}
fn validate_observation(
    intent: &ProvisionIntent,
    identity: &live::JobIdentity,
    expected_scope: &str,
    expected_directory: &str,
    revision: &crate::storage_remote_protocol::Revision,
    observed: &CoreObservation,
) -> Result<(), String> {
    if !intent.matches(observed.volume())
        || observed.cluster_id() != intent.owner().cluster_id
        || observed.local_node_uid() != Some(&identity.node_uid)
        || observed.actual_boot().as_str() != identity.boot_id
        || observed.directory_commitment() != Some(expected_directory)
        || observed.revision().term != revision.term
        || observed.revision().leader_raft_id != revision.leader_raft_id
        || observed.revision().membership_sha256 != revision.membership_sha256
        || observed.scope_sha256() != expected_scope
        || identity.volume_uid != intent.owner().volume_uid
        || &identity.operation_uid != intent.operation_uid()
        || !intent.targets().iter().any(|target| {
            target.node_uid == identity.node_uid && target.boot_id.as_str() == identity.boot_id
        })
    {
        return Err("cold actual Core scope/node/boot/directory/operation changed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity() -> live::JobIdentity {
        live::JobIdentity {
            node_uid: Uid::new(),
            boot_id: "12345678-1234-4234-a234-123456789abc".into(),
            volume_uid: Uid::new(),
            operation_uid: Uid::new(),
            attempt_uid: Uid::new(),
            binding_sha256: "a".repeat(64),
        }
    }
    #[test]
    fn standalone_or_frozen_world_without_actual_raft_never_mints_cold_parent() {
        let projection = Arc::new(RwLock::new(DesiredWorld::new()));
        assert!(require_actual_cluster_world(&projection).is_err());
    }
    #[test]
    fn cold_start_never_reuses_online_or_initializer_start_authority() {
        let id = identity();
        let mut request = live::Request {
            version: 1,
            identity: id.clone(),
            sequence: 1,
            nonce: Uid::new(),
            boundary: "helper-start".into(),
            detail_sha256: hash(b"native-virgin-offline-only-v2"),
        };
        assert!(boundary_allowed(&request, &id)); // pure predicate, not grant
        for hash_input in [
            b"native-secondary-only".as_slice(),
            b"native-initialize-new-only-v2",
        ] {
            request.detail_sha256 = hash(hash_input);
            assert!(!boundary_allowed(&request, &id));
        }
        request.boundary = "format".into();
        assert!(!boundary_allowed(&request, &id));
    }
    #[test]
    fn cancellation_and_deadline_remain_negative_after_a_hypothetical_successful_barrier() {
        let now = Instant::now();
        assert!(decision_live(false, now + Duration::from_secs(1), now));
        assert!(!decision_live(true, now + Duration::from_secs(1), now));
        assert!(!decision_live(false, now, now));
    }
    #[test]
    fn changing_native_nonce_or_sequence_changes_the_exact_cold_barrier_challenge() {
        let id = identity();
        let mut request = live::Request {
            version: 1,
            identity: id.clone(),
            sequence: 1,
            nonce: Uid::new(),
            boundary: "zero-write".into(),
            detail_sha256: "a".repeat(64),
        };
        let first = VerifiedLocalBoundary::cold(&request, &id).unwrap();
        request.nonce = Uid::new();
        assert_ne!(
            first.binding(),
            VerifiedLocalBoundary::cold(&request, &id)
                .unwrap()
                .binding()
        );
        request.sequence = 2;
        assert_ne!(
            first.binding(),
            VerifiedLocalBoundary::cold(&request, &id)
                .unwrap()
                .binding()
        );
    }
}
