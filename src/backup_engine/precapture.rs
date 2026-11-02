//! Authoritative pre-capture INTENT only. No path, process, mount, grant,
//! deadline renewal or physical completion constructor is exposed here.
use super::*;
use serde::de::{MapAccess, Visitor};
use std::fmt;

const MAX_HISTORY: usize = 4096;
const MAX_REQUEST_BYTES: usize = 32 * 1024;
const MAX_REGISTRY_BYTES: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureRequestScope {
    binding: Binding,
    repository: Repository,
    // DATA snapshot, not actor incarnation/current credentials/revocation proof.
    requested_by: IdentityRecord,
    consistency: Consistency,
    idempotency_key: String,
    source_lineage_sha256: String,
}
impl CaptureRequestScope {
    fn same_semantic_request(&self, other: &Self) -> bool {
        self.binding == other.binding
            && self.repository == other.repository
            && self.requested_by.user == other.requested_by.user
            && self.consistency == other.consistency
            && self.idempotency_key == other.idempotency_key
        // Original groups/lineage are first-admission observations, not new
        // caller payload. They remain immutable in the retained record.
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureRequest {
    version: u32,
    operation_uid: Uid,
    snapshot_uid: Uid,
    admitted_generation: u64,
    scope: CaptureRequestScope,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum ReservationState {
    Queued,
    Cancelled,
    NeedsReconciliation,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CaptureReservation {
    request: CaptureRequest,
    request_sha256: String,
    state: ReservationState,
    failure_code: Option<String>,
}

// New reservation-map duplicate keys are not silently last-wins. Existing
// jobs/repository map duplicate semantics are not changed by this component.
pub(super) fn unique_reservations<'de, D>(
    decoder: D,
) -> Result<BTreeMap<Uid, CaptureReservation>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Unique;
    impl<'de> Visitor<'de> for Unique {
        type Value = BTreeMap<Uid, CaptureReservation>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a unique pre-capture reservation map")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
            let mut out = BTreeMap::new();
            while let Some((uid, reservation)) = map.next_entry::<Uid, CaptureReservation>()? {
                if out.insert(uid, reservation).is_some() {
                    return Err(serde::de::Error::custom("duplicate pre-capture operation UID"));
                }
                if out.len() > MAX_HISTORY {
                    return Err(serde::de::Error::custom("pre-capture history admission exhausted"));
                }
            }
            Ok(out)
        }
    }
    decoder.deserialize_map(Unique)
}

impl CaptureRequest {
    fn validate(&self) -> Result<(), String> {
        let scope = &self.scope;
        scope.repository.validate()?;
        if self.version != 1
            || self.operation_uid == self.snapshot_uid
            || scope.binding.cluster_id.is_empty()
            || scope.binding.cluster_id.len() > 256
            || scope.binding.namespace.is_empty()
            || scope.binding.namespace.len() > 63
            || scope.binding.claim_name.is_empty()
            || scope.binding.claim_name.len() > 253
            || scope.binding.pv_name.is_empty()
            || scope.binding.pv_name.len() > 253
            || scope.repository.namespace_uid != scope.binding.namespace_uid
            || scope.requested_by.user.is_empty()
            || scope.requested_by.user.len() > 1024
            || scope.requested_by.groups.len() > 128
            || scope.requested_by.groups.iter().any(|g| g.len() > 256)
            || !hash_ok(&scope.idempotency_key)
            || !hash_ok(&scope.source_lineage_sha256)
            || serde_json::to_vec(self).map_err(|_| "cannot encode capture request")?.len()
                > MAX_REQUEST_BYTES
        {
            return Err("invalid or excessive immutable pre-capture request".into());
        }
        Ok(())
    }
}
fn failed_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code.bytes().all(|v| v.is_ascii_uppercase() || v == b'_')
}
impl CaptureReservation {
    pub(super) fn request_binding(&self) -> &Binding { &self.request.scope.binding }
    fn validate(&self) -> Result<(), String> {
        self.request.validate()?;
        if self.request_sha256 != digest(&self.request)?
            || match self.state {
                ReservationState::NeedsReconciliation =>
                    self.failure_code.as_deref().is_none_or(|v| !failed_code(v)),
                ReservationState::Queued | ReservationState::Cancelled => self.failure_code.is_some(),
            }
        {
            return Err("invalid pre-capture reservation state/hash".into());
        }
        Ok(())
    }
    fn holds_conflict(&self) -> bool {
        self.state != ReservationState::Cancelled
    }
    fn same_key(&self, scope: &CaptureRequestScope) -> bool {
        let old = &self.request.scope;
        old.binding.cluster_id == scope.binding.cluster_id
            && old.binding.namespace_uid == scope.binding.namespace_uid
            && old.requested_by.user == scope.requested_by.user
            && old.idempotency_key == scope.idempotency_key
    }
    fn require_successor(&self, next: &Self) -> Result<(), String> {
        if self.request != next.request || self.request_sha256 != next.request_sha256 {
            return Err("pre-capture request/UIDs/history are immutable".into());
        }
        if self == next {
            return Ok(());
        }
        if self.state != ReservationState::Queued
            || !matches!(next.state, ReservationState::Cancelled | ReservationState::NeedsReconciliation)
        {
            return Err("pre-capture quarantine/cancellation cannot be reset or retried".into());
        }
        next.validate()
    }
}
fn lineage(world: &DesiredWorld, binding: &Binding) -> Result<String, String> {
    // None is explicitly a metadata observation, not legacy/path permission.
    digest(&world.storage_identities.lifecycle.get(&binding.volume_uid))
}

impl Registry {
    #[cfg(test)]
    pub(crate) fn legacy_v1_fixture(raw: &mut serde_json::Value) {
        // DATA-only old-format fixture. Never erase actual reservation facts.
        let registry = raw.get_mut("backup_registry").unwrap();
        assert!(registry["capture_reservations"].as_object().unwrap().is_empty());
        registry.as_object_mut().unwrap().remove("capture_reservations");
        registry["version"] = 1.into();
    }

    /// Pure metadata mutation on store::commit's scratch world. The returned UID
    /// is not committed/effect authority. The ordinary caller may acknowledge
    /// only the actual store/Raft result. No API caller is added in this stage.
    pub(crate) fn reserve_capture_request(
        &mut self,
        world: &DesiredWorld,
        actor: &Identity,
        namespace: &str,
        claim: &str,
        repository_uid: &Uid,
        consistency: Consistency,
        idempotency_key: &str,
    ) -> Result<Uid, String> {
        self.validate()?;
        if !hash_ok(idempotency_key) || actor.user.is_empty() || actor.user.len() > 1024
            || actor.groups.len() > 128 || actor.groups.iter().any(|g| g.len() > 256)
        {
            return Err("capture idempotency key must be 64 lowercase hex; authenticated actor required".into());
        }
        let binding = Binding::resolve(world, namespace, claim)?;
        require(world, actor, "create", "backups", Some(namespace), Some(claim))?;
        let repository = self.repositories.get(repository_uid)
            .ok_or("capture repository is not approved")?.clone();
        let mut scope = CaptureRequestScope {
            source_lineage_sha256: String::new(),
            binding,
            repository,
            requested_by: IdentityRecord::of(actor),
            consistency,
            idempotency_key: idempotency_key.into(),
        };
        // Re-authorize/re-resolve FIRST, even for exact replay. Generation/time
        // are not new semantic input and never renew the first accepted record.
        if let Some(old) = self.capture_reservations.values().find(|r| r.same_key(&scope)) {
            if !old.request.scope.same_semantic_request(&scope) {
                return Err("capture idempotency key reused with changed immutable request".into());
            }
            return Ok(old.request.operation_uid.clone());
        }
        scope.source_lineage_sha256 = lineage(world, &scope.binding)?;
        if self.jobs.len() + self.capture_reservations.len() >= MAX_HISTORY
            || self.capture_conflict(&scope.repository.uid, &scope.binding)
            || self.jobs.values().any(|job| job.restore_verified.is_none()
                && job.restore_plan.as_ref().is_some_and(|p|
                    p.destination.volume_uid == scope.binding.volume_uid
                        || p.destination.claim_uid == scope.binding.claim_uid))
        {
            return Err("capture repository/volume is reserved or shared history exhausted".into());
        }
        let operation_uid = Uid::new();
        let request = CaptureRequest {
            version: 1,
            operation_uid: operation_uid.clone(),
            snapshot_uid: Uid::new(),
            admitted_generation: world.generation,
            scope,
        };
        request.validate()?;
        let mut next = self.clone();
        next.capture_reservations.insert(operation_uid.clone(), CaptureReservation {
            request_sha256: digest(&request)?,
            request,
            state: ReservationState::Queued,
            failure_code: None,
        });
        next.validate()?;
        *self = next;
        Ok(operation_uid)
    }

    pub(crate) fn cancel_capture_request(
        &mut self, world: &DesiredWorld, actor: &Identity, uid: &Uid,
    ) -> Result<(), String> {
        let old = self.capture_reservations.get(uid).ok_or("capture request absent")?;
        let binding = &old.request.scope.binding;
        if !binding.current(world) {
            return Err("capture request belongs to a different claim/namespace incarnation".into());
        }
        require(world, actor, "cancel", "backups", Some(&binding.namespace), Some(uid.as_str()))?;
        if old.state == ReservationState::NeedsReconciliation {
            return Err("quarantined capture cannot be cancelled into known no-effect".into());
        }
        if old.state == ReservationState::Cancelled {
            return Ok(());
        }
        // This version has NO physical start/grant method. Queued cancellation
        // is therefore intent-only; future start requires a distinct contract.
        self.capture_reservations.get_mut(uid).unwrap().state = ReservationState::Cancelled;
        Ok(())
    }

    /// Negative-only. A lost commit reply must first be joined to actual
    /// authoritative state; this method never fabricates a successful commit.
    pub(crate) fn quarantine_capture_request(&mut self, uid: &Uid, code: &str) -> Result<(), String> {
        if !failed_code(code) {
            return Err("invalid capture failure code".into());
        }
        let old = self.capture_reservations.get_mut(uid).ok_or("capture request absent")?;
        if old.state == ReservationState::Cancelled {
            return Err("known intent-only cancellation cannot become an executed capture".into());
        }
        if old.state == ReservationState::NeedsReconciliation {
            return Ok(());
        }
        old.state = ReservationState::NeedsReconciliation;
        old.failure_code = Some(code.into());
        Ok(())
    }

    pub(super) fn recover_capture_requests(&mut self) {
        for reservation in self.capture_reservations.values_mut() {
            if reservation.state == ReservationState::Queued {
                reservation.state = ReservationState::NeedsReconciliation;
                reservation.failure_code = Some("CAPTURE_OWNER_RESTARTED".into());
            }
        }
    }

    pub(super) fn capture_conflict(&self, repository: &Uid, binding: &Binding) -> bool {
        self.capture_reservations.values().any(|r| r.holds_conflict()
            && (&r.request.scope.repository.uid == repository
                || r.request.scope.binding.volume_uid == binding.volume_uid
                || r.request.scope.binding.claim_uid == binding.claim_uid))
            || self.jobs.values().any(|job|
                (job.attempt.is_some() || job.state == State::Queued)
                && (&job.plan.repository.uid == repository
                    || job.plan.source.binding.volume_uid == binding.volume_uid
                    || job.plan.source.binding.claim_uid == binding.claim_uid))
    }

    pub(super) fn reservation_blocks(&self, repository: &Uid, binding: &Binding) -> bool {
        self.capture_reservations.values().any(|r| r.holds_conflict()
            && (&r.request.scope.repository.uid == repository
                || r.request.scope.binding.volume_uid == binding.volume_uid
                || r.request.scope.binding.claim_uid == binding.claim_uid))
    }

    pub(super) fn validate_capture_requests(&self) -> Result<(), String> {
        if self.jobs.len() + self.capture_reservations.len() > MAX_HISTORY {
            return Err("combined backup job/pre-capture history admission exhausted".into());
        }
        let mut keys = BTreeSet::new();
        let mut active_repositories = BTreeSet::new();
        let mut active_volumes = BTreeSet::new();
        let mut active_claims = BTreeSet::new();
        let operation_uids: BTreeSet<_> = self.jobs.keys()
            .chain(self.capture_reservations.keys())
            .chain(self.jobs.values().flat_map(|j|
                [&j.plan.source.volume_operation, &j.plan.source.capture_uid]))
            .collect();
        let existing_snapshots: BTreeSet<_> = self.jobs.values()
            .map(|j| &j.plan.source.immutable_snapshot_uid).collect();
        let mut snapshots = BTreeSet::new();
        for (uid, r) in &self.capture_reservations {
            r.validate()?;
            let s = &r.request.scope;
            if uid != &r.request.operation_uid || self.jobs.contains_key(uid)
                || operation_uids.contains(&r.request.snapshot_uid)
                || existing_snapshots.contains(uid)
                || existing_snapshots.contains(&r.request.snapshot_uid)
                || !snapshots.insert(&r.request.snapshot_uid)
                || self.repositories.get(&s.repository.uid) != Some(&s.repository)
                || !keys.insert((&s.binding.cluster_id, &s.binding.namespace_uid,
                    &s.requested_by.user, &s.idempotency_key))
                || r.holds_conflict()
                    && (!active_repositories.insert(&s.repository.uid)
                        || !active_volumes.insert(&s.binding.volume_uid)
                        || !active_claims.insert(&s.binding.claim_uid))
            {
                return Err("capture reservation identity/repository/conflict violation".into());
            }
            if r.holds_conflict() && self.jobs.values().any(|j|
                (j.attempt.is_some() || j.state == State::Queued)
                    && (j.plan.repository.uid == s.repository.uid
                        || j.plan.source.binding.volume_uid == s.binding.volume_uid
                        || j.plan.source.binding.claim_uid == s.binding.claim_uid)
                || j.restore_verified.is_none() && j.restore_plan.as_ref().is_some_and(|p|
                    p.destination.volume_uid == s.binding.volume_uid
                        || p.destination.claim_uid == s.binding.claim_uid))
            {
                return Err("capture reservation conflicts with backup/restore attempt".into());
            }
        }
        // Reuse the existing backup Registry journal byte ceiling; it is NOT
        // the unrelated native-runtime 512-file/16MiB budget or backend quota.
        if !self.capture_reservations.is_empty()
            && serde_json::to_vec(self).map_err(|_| "cannot bound backup registry")?.len()
                > MAX_REGISTRY_BYTES
        {
            return Err("pre-capture registry byte admission exhausted".into());
        }
        Ok(())
    }

    pub(super) fn validate_capture_successor(&self, next: &Self, snapshot: bool) -> Result<(), String> {
        for (uid, old) in &self.capture_reservations {
            let new = next.capture_reservations.get(uid)
                .ok_or("pre-capture history cannot be discarded")?;
            old.require_successor(new)?;
        }
        if !snapshot && next.capture_reservations.iter().any(|(uid, r)|
            !self.capture_reservations.contains_key(uid)
                && (r.state != ReservationState::Queued || r.failure_code.is_some()))
        {
            return Err("new pre-capture records may import queued intent only".into());
        }
        Ok(())
    }

    pub(super) fn capture_cluster_matches(&self, cluster: &str) -> bool {
        self.capture_reservations.values()
            .all(|r| r.request.scope.binding.cluster_id == cluster)
    }

    /// v1 history is preserved only after an OLD schema/domain raw guard.
    pub(crate) fn migrate_v1_precapture_empty(&mut self) -> Result<(), String> {
        if self.version != 1 || !self.capture_reservations.is_empty() {
            return Err("legacy backup history cannot import pre-capture reservations".into());
        }
        let mut next = self.clone();
        next.version = 2;
        next.validate()?;
        *self = next;
        Ok(())
    }

    pub(crate) fn require_legacy_precapture_absence(raw: &serde_json::Value) -> Result<(), String> {
        if raw.get("version").and_then(|v| v.as_u64()) != Some(1)
            || !raw.get("repositories").is_some_and(|v| v.is_object())
            || !raw.get("jobs").is_some_and(|v| v.is_object())
        {
            return Err("backup registry state requires explicit version/repositories/jobs fields in legacy context".into());
        }
        if raw.get("capture_reservations").is_some() {
            return Err("legacy backup schema/domain cannot import pre-capture reservation history".into());
        }
        Ok(())
    }

    /// Parse ONLY the existing Registry subtree from original current-schema
    /// bytes so Value-first disk decoding cannot collapse new struct/map
    /// duplicates. This produces DATA, never a worker permission.
    pub(crate) fn check_current_capture_encoding(content: &str) -> Result<(), String> {
        #[derive(Deserialize)]
        struct State { backup_registry: Registry }
        #[derive(Deserialize)]
        struct Envelope { state: State }
        let envelope: Envelope = serde_json::from_str(content)
            .map_err(|_| "invalid/duplicate current backup reservation encoding")?;
        envelope.state.backup_registry.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn base() -> (DesiredWorld, Registry, Uid) {
        let (world, mut registry, _) = super::super::tests::fixture();
        let repository = registry.repositories.keys().next().unwrap().clone();
        registry.jobs.clear(); // DATA-only fixture, no process/source receipt.
        (world, registry, repository)
    }
    fn actor() -> Identity { Identity { user: "operator".into(), groups: vec![] } }
    fn reserve(w: &DesiredWorld, r: &mut Registry, repo: &Uid, key: char) -> Result<Uid, String> {
        r.reserve_capture_request(w, &actor(), "default", "data", repo, Consistency::Cold, &key.to_string().repeat(64))
    }
    #[test]
    fn reservation_is_bounded_intent_not_final_plan_or_capability() {
        let (w, mut r, repo) = base();
        let uid = reserve(&w, &mut r, &repo, 'a').unwrap();
        let record = &r.capture_reservations[&uid];
        assert_eq!(record.state, ReservationState::Queued);
        assert_ne!(record.request.operation_uid, record.request.snapshot_uid);
        assert!(r.job(&uid).is_none());
        let raw = serde_json::to_string(record).unwrap();
        for forbidden in ["source_path", "mount_id", "\"committed\"", "deadline", "readonly"] {
            assert!(!raw.contains(forbidden));
        }
        r.validate().unwrap();
    }
    #[test]
    fn replay_ignores_new_generation_but_not_immutable_scope_or_rights() {
        let (mut w, mut r, repo) = base();
        let uid = reserve(&w, &mut r, &repo, 'a').unwrap();
        let before = r.clone();
        w.generation += 91;
        assert_eq!(reserve(&w, &mut r, &repo, 'a').unwrap(), uid);
        assert_eq!(r, before);
        assert!(r.reserve_capture_request(&w, &actor(), "default", "data", &repo,
            Consistency::ApplicationConsistent, &"a".repeat(64)).is_err());
        w.rbac_roles.clear();
        assert!(reserve(&w, &mut r, &repo, 'a').is_err());
        assert_eq!(r, before);
    }

    #[test]
    fn phase_progress_and_current_group_changes_replay_original_admission_observations() {
        let (mut w, mut r, repo) = base();
        w.pvs.get_mut("pv-data").unwrap().host_path.clear();
        w.storage_classes.insert("test".into(), crate::reconcile::StoredStorageClass {
            name: "test".into(), provisioner: crate::storage_lifecycle::PROVISIONER.into(),
            host_path_prefix: String::new(), reclaim_policy: "Retain".into(), provisioned_count: 0,
        });
        crate::storage_lifecycle::Registry::register_pending(&mut w).unwrap();
        let uid = reserve(&w, &mut r, &repo, 'a').unwrap();
        let original = r.clone();
        let binding = Binding::resolve(&w, "default", "data").unwrap();
        let boot: crate::storage_boot::BootId = serde_json::from_value(
            serde_json::json!("71cb439a-d59b-4d47-9058-2134d97ebd7f")).unwrap();
        w.storage_identities.lifecycle.get_mut(&binding.volume_uid).unwrap()
            .begin_provision([Uid::new(), Uid::new(), Uid::new()],
                [boot.clone(), boot.clone(), boot], Uid::new()).unwrap();
        assert_ne!(lineage(&w, &binding).unwrap(),
            r.capture_reservations[&uid].request.scope.source_lineage_sha256);
        let mut current_actor = actor();
        current_actor.groups = vec!["new-observed-group".into(), "another-group".into()];
        assert_eq!(r.reserve_capture_request(&w, &current_actor, "default", "data", &repo,
            Consistency::Cold, &"a".repeat(64)).unwrap(), uid);
        current_actor.groups.reverse();
        assert_eq!(r.reserve_capture_request(&w, &current_actor, "default", "data", &repo,
            Consistency::Cold, &"a".repeat(64)).unwrap(), uid);
        assert_eq!(r, original);
    }

    #[test]
    fn token_and_actor_metadata_have_finite_limits() {
        let (w, mut r, repo) = base();
        for key in ["a".repeat(63), "a".repeat(65), "A".repeat(64), "/".repeat(64)] {
            assert!(r.reserve_capture_request(&w, &actor(), "default", "data", &repo,
                Consistency::Cold, &key).is_err());
        }
        let mut oversized = actor();
        oversized.groups = vec!["g".repeat(257)];
        assert!(r.reserve_capture_request(&w, &oversized, "default", "data", &repo,
            Consistency::Cold, &"b".repeat(64)).is_err());
        assert!(r.capture_reservations.is_empty());
    }
    #[test]
    fn reused_incarnation_and_changed_repository_do_not_replay_old_operation() {
        let (mut w, mut r, repo) = base();
        let uid = reserve(&w, &mut r, &repo, 'a').unwrap();
        let old = r.clone();
        let claim = crate::store::obj_key("default", "data");
        w.storage_identities.claims.get_mut(&claim).unwrap().uid = Uid::new();
        assert!(reserve(&w, &mut r, &repo, 'a').is_err());
        assert_eq!(r, old);
        assert_eq!(r.capture_reservations[&uid].state, ReservationState::Queued);
    }
    #[test]
    fn cancellation_and_restart_never_requeue_or_refund_history() {
        let (w, mut r, repo) = base();
        let uid = reserve(&w, &mut r, &repo, 'a').unwrap();
        r.cancel_capture_request(&w, &actor(), &uid).unwrap();
        assert_eq!(reserve(&w, &mut r, &repo, 'a').unwrap(), uid);
        assert_eq!(r.capture_reservations[&uid].state, ReservationState::Cancelled);
        let next_uid = reserve(&w, &mut r, &repo, 'b').unwrap();
        r.recover_after_restart();
        assert_eq!(r.capture_reservations[&next_uid].state, ReservationState::NeedsReconciliation);
        assert!(r.cancel_capture_request(&w, &actor(), &next_uid).is_err());
        assert_eq!(reserve(&w, &mut r, &repo, 'b').unwrap(), next_uid);
        assert_eq!(r.capture_reservations.len(), 2);
    }
    #[test]
    fn combined_history_limit_counts_cancelled_requests_with_jobs() {
        let (w, mut r, repo) = base();
        let uid = reserve(&w, &mut r, &repo, 'a').unwrap();
        r.cancel_capture_request(&w, &actor(), &uid).unwrap();
        let template = r.capture_reservations[&uid].clone();
        for i in 1..MAX_HISTORY - 1 {
            let mut row = template.clone();
            row.request.operation_uid = Uid::new();
            row.request.snapshot_uid = Uid::new();
            row.request.scope.idempotency_key = format!("{i:064x}");
            row.request_sha256 = digest(&row.request).unwrap();
            r.capture_reservations.insert(row.request.operation_uid.clone(), row);
        }
        let (_, legacy, job_uid) = super::super::tests::fixture();
        let mut job = legacy.jobs[&job_uid].clone();
        job.plan.source.binding = Binding::resolve(&w, "default", "data").unwrap();
        job.plan.repository = r.repositories[&repo].clone();
        job.plan_sha256 = job.plan.hash().unwrap();
        job.state = State::Cancelled;
        let mut extra_plan = job.plan.clone();
        extra_plan.uid = Uid::new();
        r.jobs.insert(job_uid, job);
        r.validate().unwrap();
        assert_eq!(r.jobs.len() + r.capture_reservations.len(), MAX_HISTORY);
        let before = r.clone();
        assert!(reserve(&w, &mut r, &repo, 'f').is_err());
        assert!(r.enqueue(&w, extra_plan).is_err());
        assert_eq!(r, before);
    }
    #[test]
    fn active_legacy_attempt_and_new_intent_conflict_in_both_directions() {
        let (w, mut old, uid) = super::super::tests::fixture();
        let repo = old.job(&uid).unwrap().plan.repository.uid.clone();
        assert!(reserve(&w, &mut old, &repo, 'a').is_err());
        let plan = old.job(&uid).unwrap().plan.clone();
        old.jobs.clear();
        reserve(&w, &mut old, &repo, 'a').unwrap();
        assert!(old.enqueue(&w, plan).is_err());
        old.validate().unwrap();
    }
    #[test]
    fn transition_refuses_discard_request_rewrite_and_quarantine_reset() {
        let (w, mut r, repo) = base();
        let uid = reserve(&w, &mut r, &repo, 'a').unwrap();
        let mut next = r.clone();
        next.capture_reservations.clear();
        assert!(r.validate_transition(&next).is_err());
        let mut next = r.clone();
        let row = next.capture_reservations.get_mut(&uid).unwrap();
        row.request.snapshot_uid = Uid::new();
        row.request_sha256 = digest(&row.request).unwrap();
        assert!(r.validate_transition(&next).is_err());
        r.quarantine_capture_request(&uid, "LOST_ACK").unwrap();
        let mut next = r.clone();
        next.capture_reservations.get_mut(&uid).unwrap().state = ReservationState::Queued;
        next.capture_reservations.get_mut(&uid).unwrap().failure_code = None;
        assert!(r.validate_transition(&next).is_err());
    }
    #[test]
    fn current_disk_requires_explicit_nonnull_reservations_and_rejects_duplicates() {
        let (w, r, _) = base();
        let mut state = w.to_state();
        state.backup_registry = r;
        let text = String::from_utf8(crate::persist::encode(&state, &[]).unwrap()).unwrap();
        for replacement in [None, Some(serde_json::Value::Null)] {
            let mut raw: serde_json::Value = serde_json::from_str(&text).unwrap();
            if let Some(value) = replacement {
                raw["state"]["backup_registry"]["capture_reservations"] = value;
            } else {
                raw["state"]["backup_registry"].as_object_mut().unwrap().remove("capture_reservations");
            }
            assert!(crate::persist::decode(&raw.to_string()).is_err());
        }
        let duplicate = text.replacen("\"capture_reservations\": {}", "\"capture_reservations\": {}, \"capture_reservations\": {}", 1);
        assert_ne!(duplicate, text);
        assert!(crate::persist::decode(&duplicate).is_err());
    }
    #[test]
    fn legacy_v1_history_migrates_but_old_schema_reservations_refuse() {
        let (w, mut r, repo) = base();
        let mut state = w.to_state();
        state.backup_registry = r.clone();
        let mut raw: serde_json::Value = serde_json::from_slice(&crate::persist::encode(&state, &[]).unwrap()).unwrap();
        raw["schemaVersion"] = 8.into();
        raw["state"]["backup_registry"]["version"] = 1.into();
        raw["state"]["backup_registry"].as_object_mut().unwrap().remove("capture_reservations");
        let (migrated, _, _) = crate::persist::decode(&raw.to_string()).unwrap();
        assert_eq!(migrated.backup_registry, r);
        reserve(&w, &mut r, &repo, 'a').unwrap();
        raw["state"]["backup_registry"] = serde_json::to_value(&r).unwrap();
        assert!(crate::persist::decode(&raw.to_string()).err().unwrap().contains("backup"));
    }

    #[test]
    fn raw_active_claim_alias_is_rejected_even_with_distinct_volume_and_repository() {
        let (w, mut r, repo) = base();
        let uid = reserve(&w, &mut r, &repo, 'a').unwrap();
        let mut second = r.capture_reservations[&uid].clone();
        let mut second_repo = second.request.scope.repository.clone();
        second_repo.uid = Uid::new();
        second_repo.repository_id = "f".repeat(64);
        r.repositories.insert(second_repo.uid.clone(), second_repo.clone());
        second.request.operation_uid = Uid::new();
        second.request.snapshot_uid = Uid::new();
        second.request.scope.idempotency_key = "b".repeat(64);
        second.request.scope.repository = second_repo;
        second.request.scope.binding.volume_uid = Uid::new();
        second.request.scope.binding.pv_name = "different-pv-same-claim".into();
        second.request_sha256 = digest(&second.request).unwrap();
        r.capture_reservations.insert(second.request.operation_uid.clone(), second);
        assert!(r.validate().is_err());
    }
    #[test]
    fn cancelled_snapshot_identity_cannot_be_reused_or_alias_an_operation() {
        let (w, mut r, repo) = base();
        let uid = reserve(&w, &mut r, &repo, 'a').unwrap();
        r.cancel_capture_request(&w, &actor(), &uid).unwrap();
        let snapshot = r.capture_reservations[&uid].request.snapshot_uid.clone();
        let next_uid = reserve(&w, &mut r, &repo, 'b').unwrap();
        for alias in [snapshot, uid] {
            let mut next = r.clone();
            let row = next.capture_reservations.get_mut(&next_uid).unwrap();
            row.request.snapshot_uid = alias;
            row.request_sha256 = digest(&row.request).unwrap();
            assert!(next.validate().is_err());
            assert!(r.validate_transition(&next).is_err());
        }
    }
    #[test]
    fn reservation_snapshot_cannot_alias_existing_job_or_source_snapshot() {
        let (w, mut r, repo) = base();
        let uid = reserve(&w, &mut r, &repo, 'a').unwrap();
        r.cancel_capture_request(&w, &actor(), &uid).unwrap();
        let (_, legacy, job_uid) = super::super::tests::fixture();
        let mut job = legacy.jobs[&job_uid].clone();
        job.plan.source.binding = Binding::resolve(&w, "default", "data").unwrap();
        job.plan.repository = r.repositories[&repo].clone();
        job.plan_sha256 = job.plan.hash().unwrap();
        let snapshot = job.plan.source.immutable_snapshot_uid.clone();
        r.jobs.insert(job_uid.clone(), job);
        r.validate().unwrap();
        for alias in [job_uid, snapshot] {
            let mut bad = r.clone();
            let row = bad.capture_reservations.get_mut(&uid).unwrap();
            row.request.snapshot_uid = alias;
            row.request_sha256 = digest(&row.request).unwrap();
            assert!(bad.validate().is_err());
        }
    }
    #[test]
    fn duplicate_raw_operation_uid_refuses_both_registry_and_actual_raft_decoder() {
        let (w, mut r, repo) = base();
        let uid = reserve(&w, &mut r, &repo, 'a').unwrap();
        let row = serde_json::to_string(&r.capture_reservations[&uid]).unwrap();
        let duplicate_map = format!("{{\"{}\":{},\"{}\":{}}}", uid.as_str(), row, uid.as_str(), row);
        let reg = serde_json::to_string(&r).unwrap();
        let original_map = serde_json::to_string(&r.capture_reservations).unwrap();
        let duplicate_reg = reg.replacen(&original_map, &duplicate_map, 1);
        assert_ne!(duplicate_reg, reg);
        assert!(serde_json::from_str::<Registry>(&duplicate_reg).is_err());
        let mut state = w.to_state();
        state.backup_registry = r;
        let raw = serde_json::to_string(&state).unwrap();
        let duplicate_state = raw.replacen(&reg, &duplicate_reg, 1);
        assert_ne!(duplicate_state, raw);
        assert!(crate::raft_node::Sealing::Plain.unseal(&duplicate_state).is_err());
        let disk = format!("{{\"schemaVersion\":9,\"generation\":{},\"clusterId\":{},\"state\":{},\"nodes\":[]}}",
            state.generation, serde_json::to_string(&state.cluster_id).unwrap(), duplicate_state);
        assert!(crate::persist::decode(&disk).is_err());
    }
    #[test]
    fn schema8_missing_node_directory_never_defaults_during_precapture_migration() {
        let (w, r, _) = base();
        let mut state = w.to_state();
        state.backup_registry = r;
        let mut raw: serde_json::Value = serde_json::from_slice(&crate::persist::encode(&state, &[]).unwrap()).unwrap();
        raw["schemaVersion"] = 8.into();
        Registry::legacy_v1_fixture(&mut raw["state"]);
        raw["state"].as_object_mut().unwrap().remove("storage_node_directory");
        assert!(crate::persist::decode(&raw.to_string()).is_err());
    }
    #[test]
    fn journal_fsync_reopen_retains_original_request_and_quarantines_without_retry() {
        use std::os::unix::fs::PermissionsExt;
        let (w, r, repo) = base();
        let root = std::env::temp_dir().canonicalize().unwrap()
            .join(format!("royak-precapture-journal-{}", Uid::new().as_str()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut legacy = serde_json::to_value(&r).unwrap();
        legacy.as_object_mut().unwrap().remove("capture_reservations");
        legacy["version"] = 1.into();
        std::fs::write(root.join("jobs.json"), serde_json::to_vec(&legacy).unwrap()).unwrap();
        std::fs::set_permissions(root.join("jobs.json"), std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut journal = super::super::journal::Journal::open(&root).unwrap();
        assert_eq!(journal.state(), &r);
        let uid = journal.transaction(|next| {
            *next = r.clone();
            reserve(&w, next, &repo, 'a')
        }).unwrap();
        let original = journal.state().capture_reservations[&uid].request.clone();
        drop(journal);
        let mut reopened = super::super::journal::Journal::open(&root).unwrap();
        assert_eq!(reopened.state().capture_reservations[&uid].request, original);
        assert_eq!(reopened.state().capture_reservations[&uid].state, ReservationState::NeedsReconciliation);
        assert_eq!(reopened.transaction(|next| reserve(&w, next, &repo, 'a')).unwrap(), uid);
        assert_eq!(reopened.state().capture_reservations[&uid].request, original);
        let retained = reopened.state().clone();
        drop(reopened);
        let row = serde_json::to_string(&retained.capture_reservations[&uid]).unwrap();
        let map = serde_json::to_string(&retained.capture_reservations).unwrap();
        let duplicate = serde_json::to_string(&retained).unwrap().replacen(&map,
            &format!("{{\"{}\":{},\"{}\":{}}}", uid.as_str(), row, uid.as_str(), row), 1);
        std::fs::write(root.join("jobs.json"), duplicate).unwrap();
        assert!(super::super::journal::Journal::open(&root).is_err());
        for missing in [false, true] {
            let mut raw = serde_json::to_value(&retained).unwrap();
            if missing { raw.as_object_mut().unwrap().remove("capture_reservations"); }
            else { raw["capture_reservations"] = serde_json::Value::Null; }
            std::fs::write(root.join("jobs.json"), serde_json::to_vec(&raw).unwrap()).unwrap();
            assert!(super::super::journal::Journal::open(&root).is_err());
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

}
