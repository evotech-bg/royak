//! Royak-owned backup lifecycle. Restic is a replaceable data adapter, not an
//! authorization service. Persisted descriptors are evidence, never mount
//! capabilities; a worker must separately hold a live driver source receipt.
//!
//! Registry joins DesiredState/commit/Raft. Live source/restore workers remain unavailable.
#[path = "backup_engine/journal.rs"]
pub mod journal;
#[path = "backup_engine/recovery_contract.rs"]
pub mod recovery_contract;
#[path = "backup_engine/restic.rs"]
pub mod restic;
#[path = "backup_engine/tree.rs"]
mod tree;
#[path = "backup_engine/precapture.rs"]
mod precapture;

use crate::auth::{self, Attrs, Identity};
use crate::reconcile::DesiredWorld;
use crate::storage_identity::Uid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|v| format!("{v:02x}"))
        .collect()
}
pub(crate) fn digest<T: Serialize>(value: &T) -> Result<String, String> {
    Ok(sha(
        &serde_json::to_vec(value).map_err(|_| "cannot encode backup identity")?
    ))
}
pub(crate) fn hash_ok(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn require(
    world: &DesiredWorld,
    who: &Identity,
    verb: &str,
    resource: &str,
    namespace: Option<&str>,
    name: Option<&str>,
) -> Result<(), String> {
    if auth::authorize(
        world,
        who,
        &Attrs::new(verb, resource, None, namespace, name),
    ) {
        Ok(())
    } else {
        Err("backup operation is not authorized".into())
    }
}

/// Resolved from committed server-owned UIDs. A reused name never selects old
/// data or inherits permission on an earlier namespace/claim incarnation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub cluster_id: String,
    pub namespace: String,
    pub namespace_uid: Uid,
    pub claim_name: String,
    pub claim_uid: Uid,
    pub pv_name: String,
    pub volume_uid: Uid,
}
impl Binding {
    pub fn resolve(
        world: &DesiredWorld,
        namespace: &str,
        claim_name: &str,
    ) -> Result<Self, String> {
        let key = crate::store::obj_key(namespace, claim_name);
        let claim = world.pvcs.get(&key).ok_or("claim not found")?;
        let claim_id = world
            .storage_identities
            .claims
            .get(&key)
            .ok_or("claim identity absent")?;
        let namespace_uid = world
            .storage_identities
            .namespaces
            .get(namespace)
            .ok_or("namespace identity absent")?;
        let pv_name = claim.bound_pv.as_ref().ok_or("claim is not bound")?;
        let pv = world.pvs.get(pv_name).ok_or("bound volume absent")?;
        if claim.namespace != namespace
            || claim.name != claim_name
            || &claim_id.namespace_uid != namespace_uid
            || pv.bound_to.as_deref() != Some(key.as_str())
        {
            return Err("claim/volume binding is not reciprocal".into());
        }
        let volume_uid = world
            .storage_identities
            .volumes
            .get(pv_name)
            .ok_or("volume identity absent")?;
        Ok(Self {
            cluster_id: world.cluster_id.clone(),
            namespace: namespace.into(),
            namespace_uid: namespace_uid.clone(),
            claim_name: claim_name.into(),
            claim_uid: claim_id.uid.clone(),
            pv_name: pv_name.clone(),
            volume_uid: volume_uid.clone(),
        })
    }
    pub fn current(&self, world: &DesiredWorld) -> bool {
        Self::resolve(world, &self.namespace, &self.claim_name).as_ref() == Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Consistency {
    Cold,
    FilesystemCrashConsistent,
    ApplicationConsistent,
}

/// Serializable provenance only. It deliberately has no source path and does
/// not prove readonly/consistent by deserialization. Driver capability required.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceDescriptor {
    pub binding: Binding,
    pub capture_uid: Uid,
    pub immutable_snapshot_uid: Uid,
    pub volume_epoch: u64,
    pub volume_operation: Uid,
    pub node_uid: Uid,
    pub node_boot_id: String,
    pub filesystem_uuid: String,
    pub backend_identity_sha256: String,
    pub mount_id: u64,
    pub readonly_generation: String,
    pub consistency: Consistency,
    pub consistency_evidence_sha256: String,
    pub capture_started_unix_ms: u64,
    pub capture_finished_unix_ms: u64,
}
impl SourceDescriptor {
    fn validate(&self) -> Result<(), String> {
        if self.mount_id == 0
            || self.readonly_generation.is_empty()
            || self.readonly_generation.len() > 256
            || self.capture_started_unix_ms == 0
            || self.capture_finished_unix_ms < self.capture_started_unix_ms
            || !crate::storage_lifecycle::valid_uuid(&self.node_boot_id)
            || !crate::storage_lifecycle::valid_uuid(&self.filesystem_uuid)
            || !hash_ok(&self.backend_identity_sha256)
            || !hash_ok(&self.consistency_evidence_sha256)
        {
            return Err("invalid backup source evidence descriptor".into());
        }
        Ok(())
    }
}

/// Scope/identity of an operator-approved repository. Each repository belongs
/// to exactly one namespace UID. Tags DO NOT implement tenant isolation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub uid: Uid,
    pub namespace_uid: Uid,
    pub repository_id: String,
    pub credential_uid: Uid,
    pub approved_backend_sha256: String,
    pub restic_binary_sha256: String,
}
impl Repository {
    fn validate(&self) -> Result<(), String> {
        if !hash_ok(&self.repository_id)
            || !hash_ok(&self.approved_backend_sha256)
            || !hash_ok(&self.restic_binary_sha256)
        {
            Err("invalid approved backup repository".into())
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturePlan {
    pub version: u32,
    pub uid: Uid,
    pub source: SourceDescriptor,
    pub repository: Repository,
    pub desired_generation: u64,
    pub requested_by: IdentityRecord,
    pub includes_secrets: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRecord {
    pub user: String,
    pub groups: Vec<String>,
}
impl IdentityRecord {
    fn of(id: &Identity) -> Self {
        Self {
            user: id.user.clone(),
            groups: id.groups.clone(),
        }
    }
    fn identity(&self) -> Identity {
        Identity {
            user: self.user.clone(),
            groups: self.groups.clone(),
        }
    }
}
impl CapturePlan {
    pub(crate) fn authorized(
        world: &DesiredWorld,
        id: &Identity,
        source: SourceDescriptor,
        repository: &Repository,
        includes_secrets: bool,
    ) -> Result<Self, String> {
        source.validate()?;
        repository.validate()?;
        let binding = &source.binding;
        require(
            world,
            id,
            "create",
            "backups",
            Some(&binding.namespace),
            Some(&binding.claim_name),
        )?;
        if includes_secrets {
            require(
                world,
                id,
                "export",
                "secrets",
                Some(&binding.namespace),
                None,
            )?;
            return Err(
                "control-plane secret export/escrow adapter is not implemented; no backup started"
                    .into(),
            );
        }
        if !binding.current(world) || repository.namespace_uid != binding.namespace_uid {
            return Err(
                "source/repository no longer belongs to the current namespace and claim".into(),
            );
        }
        // Even a privileged caller cannot turn an unobserved descriptor into a
        // physical source. This builds intent ONLY; execution needs the driver.
        Ok(Self {
            version: 1,
            uid: Uid::new(),
            source,
            repository: repository.clone(),
            desired_generation: world.generation,
            requested_by: IdentityRecord::of(id),
            includes_secrets,
        })
    }
    pub fn hash(&self) -> Result<String, String> {
        digest(self)
    }
    pub fn reauthorize(&self, world: &DesiredWorld) -> Result<(), String> {
        self.validate()?;
        let b = &self.source.binding;
        if !b.current(world) {
            return Err("backup source identity changed".into());
        }
        let id = self.requested_by.identity();
        require(
            world,
            &id,
            "create",
            "backups",
            Some(&b.namespace),
            Some(&b.claim_name),
        )?;
        if self.includes_secrets {
            require(world, &id, "export", "secrets", Some(&b.namespace), None)?;
        }
        Ok(())
    }
    fn validate(&self) -> Result<(), String> {
        self.source.validate()?;
        self.repository.validate()?;
        if self.version != 1
            || self.repository.namespace_uid != self.source.binding.namespace_uid
            || self.requested_by.user.is_empty()
            || self.includes_secrets
        {
            return Err("invalid immutable backup plan".into());
        }
        Ok(())
    }
}

/// No Deserialize and no raw constructor. Holding this borrow is necessary for
/// capture; the persisted plan alone can never grant source filesystem access.
pub struct BackupSource<'a> {
    driver: &'a crate::storage_driver::capture::VerifiedBackupSource,
}
impl<'a> BackupSource<'a> {
    pub fn from_driver_source(
        driver: &'a crate::storage_driver::capture::VerifiedBackupSource,
    ) -> Result<Self, String> {
        if !driver.descriptor().readonly {
            return Err("driver did not observe a read-only immutable source".into());
        }
        Ok(Self { driver })
    }
    pub fn plan(
        &self,
        world: &DesiredWorld,
        id: &Identity,
        namespace: &str,
        claim: &str,
        repo: &Repository,
        includes_secrets: bool,
    ) -> Result<CapturePlan, String> {
        CapturePlan::authorized(
            world,
            id,
            self.descriptor(world, namespace, claim)?,
            repo,
            includes_secrets,
        )
    }
    fn descriptor(
        &self,
        world: &DesiredWorld,
        namespace: &str,
        claim: &str,
    ) -> Result<SourceDescriptor, String> {
        let binding = Binding::resolve(world, namespace, claim)?;
        self.descriptor_for_binding(binding)
    }
    fn descriptor_for_binding(&self, binding: Binding) -> Result<SourceDescriptor, String> {
        let observed = self.driver.descriptor();
        if !observed.readonly
            || binding.cluster_id != observed.cluster_id
            || binding.namespace_uid != observed.namespace_uid
            || binding.claim_uid != observed.claim_uid
            || binding.volume_uid != observed.volume_uid
        {
            return Err("driver source identity differs from committed claim".into());
        }
        let consistency = match observed.consistency {
            crate::storage_driver::capture::Consistency::Cold => Consistency::Cold,
            crate::storage_driver::capture::Consistency::FilesystemCrashConsistent => {
                Consistency::FilesystemCrashConsistent
            }
            crate::storage_driver::capture::Consistency::ApplicationConsistent => {
                Consistency::ApplicationConsistent
            }
        };
        Ok(SourceDescriptor {
            binding,
            capture_uid: observed.capture_uid.clone(),
            immutable_snapshot_uid: observed.snapshot_uid.clone(),
            volume_epoch: observed.epoch,
            volume_operation: observed.operation_uid.clone(),
            node_uid: observed.node_uid.clone(),
            node_boot_id: observed.node_boot_id.as_str().into(),
            filesystem_uuid: observed.filesystem_uuid.clone(),
            backend_identity_sha256: digest(&(
                &observed.backend_device_uuid,
                observed.source_major,
                observed.source_minor,
                &observed.filesystem_uuid,
                &observed.snapshot_uid,
            ))?,
            mount_id: observed.mount_id,
            readonly_generation: observed.generation.clone(),
            consistency,
            consistency_evidence_sha256: observed.evidence_sha256.clone(),
            capture_started_unix_ms: observed.capture_started_unix_ms,
            capture_finished_unix_ms: observed.capture_finished_unix_ms,
        })
    }
    pub(crate) fn worker_path(&self, plan: &CapturePlan) -> Result<&std::path::Path, String> {
        if self.descriptor_for_binding(plan.source.binding.clone())? != plan.source {
            return Err("driver source changed since capture plan".into());
        }
        self.driver.source_path_for_worker()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    Capture,
    RepositoryCheck,
    Restore,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum State {
    Queued,
    Running,
    CancelRequested,
    NeedsReconciliation,
    Idle,
    Cancelled,
    Failed,
}

/// Kept distinct: successful capture does not establish repository integrity;
/// successful repository check does not establish application recovery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureEvidence {
    pub snapshot_id: String,
    pub manifest_sha256: String,
    pub manifest_snapshot_path: String,
    pub manifest: RecoveryManifest,
    pub tree_sha256: String,
    pub finished_unix_ms: u64,
    pub adapter_receipt_sha256: String,
}
/// Stored INSIDE the encrypted snapshot. The full snapshot ID cannot be put
/// inside its own content-addressed snapshot without a circular hash; the
/// independently listed exact ID is bound to this manifest hash by CaptureEvidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryManifest {
    pub version: u32,
    pub plan_sha256: String,
    pub source: SourceDescriptor,
    pub repository_uid: Uid,
    pub repository_id: String,
    pub desired_generation: u64,
    pub driver: String,
    pub repository_format: u32,
    /// A snapshot tree index, NEVER a host-side source path authority.
    pub payload_snapshot_path: String,
    pub tree_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckEvidence {
    pub snapshot_id: String,
    pub checked_unix_ms: u64,
    pub full_read_data: bool,
    pub adapter_receipt_sha256: String,
}
impl CheckEvidence {
    fn validate_for_snapshot(&self, snapshot_id: &str) -> Result<(), String> {
        if !self.full_read_data
            || self.snapshot_id != snapshot_id
            || !hash_ok(&self.adapter_receipt_sha256)
            || self.checked_unix_ms == 0
        {
            return Err("repository check is not bound to captured point".into());
        }
        Ok(())
    }
}
/// Capture identity is immutable, while full repository checks can be refreshed.
/// A refresh may neither erase accepted evidence nor move its time backwards.
/// Clock regressions fail closed; this is not a replacement for a trusted check
/// receipt or proof that every future repository operation remains healthy.
fn validate_check_progress(
    previous: Option<&CheckEvidence>,
    next: Option<&CheckEvidence>,
) -> Result<(), String> {
    if let Some(previous) = previous {
        let next = next.ok_or("accepted repository check evidence cannot be discarded")?;
        if next.snapshot_id != previous.snapshot_id
            || next.checked_unix_ms < previous.checked_unix_ms
        {
            return Err(
                "repository check evidence cannot regress or change captured identity".into(),
            );
        }
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreEvidence {
    pub snapshot_id: String,
    pub destination_volume_uid: Uid,
    pub tree_sha256: String,
    pub verified_unix_ms: u64,
    pub application_evidence_sha256: Option<String>,
    pub adapter_receipt_sha256: String,
    /// Strict new receipt bindings; neither is a physical destination proof.
    pub restore_plan_sha256: String,
    pub attempt_uid: Uid,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    pub uid: Uid,
    pub operation: Operation,
    pub started_unix_ms: u64,
    pub node_uid: Uid,
    pub boot_id: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    plan: CapturePlan,
    plan_sha256: String,
    state: State,
    requested: Operation,
    operation_requested_by: IdentityRecord,
    attempt: Option<Attempt>,
    attempts_started: u32,
    captured: Option<CaptureEvidence>,
    repository_checked: Option<CheckEvidence>,
    restore_verified: Option<RestoreEvidence>,
    restore_plan: Option<RestorePlan>,
    /// Error codes only. Child output (potential secrets/paths) is never stored.
    failure_code: Option<String>,
    /// Stop/restart can leave an unacknowledged snapshot, repo lock, or partial
    /// new restore volume. Preserve that uncertainty; never auto-unlock/retry.
    partial_effects_possible: bool,
}
impl Job {
    pub fn plan(&self) -> &CapturePlan {
        &self.plan
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub fn captured(&self) -> Option<&CaptureEvidence> {
        self.captured.as_ref()
    }
    pub fn repository_checked(&self) -> Option<&CheckEvidence> {
        self.repository_checked.as_ref()
    }
    pub fn restore_verified(&self) -> Option<&RestoreEvidence> {
        self.restore_verified.as_ref()
    }
    pub fn attempt(&self) -> Option<&Attempt> {
        self.attempt.as_ref()
    }
    pub fn worker_may_continue(&self, world: &DesiredWorld, attempt_uid: &Uid, now: u64) -> bool {
        self.state == State::Running
            && self.attempt.as_ref().map(|a| &a.uid) == Some(attempt_uid)
            && self.execution_authorized(world, now).is_ok()
    }
    pub fn execution_authorized(&self, world: &DesiredWorld, now: u64) -> Result<(), String> {
        self.plan.reauthorize(world)?;
        let b = &self.plan.source.binding;
        match self.requested {
            Operation::Capture => Ok(()),
            Operation::RepositoryCheck => require(
                world,
                &self.operation_requested_by.identity(),
                "verify",
                "backups",
                Some(&b.namespace),
                Some(self.plan.uid.as_str()),
            ),
            Operation::Restore => {
                let plan = self.restore_plan.as_ref().ok_or("restore intent missing")?;
                plan.reauthorize(world, now, &plan.hash()?)
            }
        }
    }
    fn matches_attempt(&self, attempt: &Uid) -> Result<(), String> {
        if self.state != State::Running || self.attempt.as_ref().map(|a| &a.uid) != Some(attempt) {
            Err("stale or cancelled backup attempt acknowledgement".into())
        } else {
            Ok(())
        }
    }
    fn validate(&self) -> Result<(), String> {
        self.plan.validate()?;
        if self.plan.hash()? != self.plan_sha256
            || self.attempts_started > 1024
            || self.operation_requested_by.user.is_empty()
            || self.failure_code.as_ref().is_some_and(|code| {
                code.is_empty()
                    || code.len() > 64
                    || !code.bytes().all(|v| v.is_ascii_uppercase() || v == b'_')
            })
        {
            return Err("backup plan tamper/attempt limit".into());
        }
        if matches!(
            self.state,
            State::Running | State::CancelRequested | State::NeedsReconciliation
        ) != self.attempt.is_some()
        {
            return Err("backup attempt/state mismatch".into());
        }
        if let Some(a) = &self.attempt {
            if a.operation != self.requested
                || a.started_unix_ms == 0
                || !crate::storage_lifecycle::valid_uuid(&a.boot_id)
            {
                return Err("invalid backup attempt".into());
            }
        }
        if let Some(c) = &self.captured {
            if !hash_ok(&c.snapshot_id)
                || !hash_ok(&c.manifest_sha256)
                || !hash_ok(&c.tree_sha256)
                || !hash_ok(&c.adapter_receipt_sha256)
                || c.finished_unix_ms == 0
                || c.manifest.version != 1
                || c.manifest.plan_sha256 != self.plan_sha256
                || c.manifest.source != self.plan.source
                || c.manifest.repository_uid != self.plan.repository.uid
                || c.manifest.repository_id != self.plan.repository.repository_id
                || c.manifest.desired_generation != self.plan.desired_generation
                || c.manifest.driver != "restic"
                || c.manifest.repository_format != 2
                || c.manifest.tree_sha256 != c.tree_sha256
                || digest(&c.manifest)? != c.manifest_sha256
                || !snapshot_path_ok(&c.manifest_snapshot_path)
                || !snapshot_path_ok(&c.manifest.payload_snapshot_path)
            {
                return Err("invalid capture evidence".into());
            }
        }
        if let Some(c) = &self.repository_checked {
            c.validate_for_snapshot(
                &self
                    .captured
                    .as_ref()
                    .ok_or("repository check has no captured point")?
                    .snapshot_id,
            )?;
        }
        if self.state == State::Idle
            && self.requested == Operation::RepositoryCheck
            && self.repository_checked.is_none()
        {
            return Err("repository check completion requires full-read evidence".into());
        }
        if let Some(r) = &self.restore_verified {
            let c = self
                .captured
                .as_ref()
                .ok_or("restore verified without capture")?;
            let plan = self
                .restore_plan
                .as_ref()
                .ok_or("restore evidence has no exact approval plan")?;
            if r.snapshot_id != c.snapshot_id
                || r.tree_sha256 != c.tree_sha256
                || r.verified_unix_ms == 0
                || r.verified_unix_ms >= plan.expires_unix_ms
                || r.restore_plan_sha256 != plan.hash()?
                || self.repository_checked.as_ref().is_none_or(|checked| {
                    checked.snapshot_id != r.snapshot_id
                        || r.verified_unix_ms < checked.checked_unix_ms
                })
                || !hash_ok(&r.adapter_receipt_sha256)
                || r.application_evidence_sha256
                    .as_ref()
                    .is_some_and(|v| !hash_ok(v))
                || self
                    .restore_plan
                    .as_ref()
                    .map(|p| &p.destination.volume_uid)
                    != Some(&r.destination_volume_uid)
            {
                return Err("restore verification mismatch".into());
            }
        }
        if self.state == State::Idle
            && self.requested == Operation::Restore
            && self.restore_verified.is_none()
        {
            return Err("restore completion requires exact verified evidence".into());
        }
        if let Some(p) = &self.restore_plan {
            let c = self
                .captured
                .as_ref()
                .ok_or("restore plan has no captured point")?;
            if p.capture_plan_sha256 != self.plan_sha256
                || p.repository_uid != self.plan.repository.uid
                || p.snapshot_id != c.snapshot_id
                || p.manifest_sha256 != c.manifest_sha256
                || p.destination.namespace_uid != self.plan.source.binding.namespace_uid
                || p.destination.cluster_id != self.plan.source.binding.cluster_id
                || p.destination.volume_uid == self.plan.source.binding.volume_uid
                || p.destination.claim_uid == self.plan.source.binding.claim_uid
                || p.requested_by.user.is_empty()
                || p.expires_unix_ms == 0
            {
                return Err("restore intent identity or exact recovery point differs".into());
            }
        }
        Ok(())
    }
}

/// Exact human approval for a fresh destination. This is an intent, not an
/// empty-volume/mount capability. No existing source or data volume overwrite.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestorePlan {
    pub uid: Uid,
    pub capture_plan_sha256: String,
    pub repository_uid: Uid,
    pub snapshot_id: String,
    pub manifest_sha256: String,
    pub destination: Binding,
    pub requested_by: IdentityRecord,
    pub expires_unix_ms: u64,
}
impl RestorePlan {
    pub fn hash(&self) -> Result<String, String> {
        digest(self)
    }
    pub fn new(
        world: &DesiredWorld,
        id: &Identity,
        job: &Job,
        destination: Binding,
        expires_unix_ms: u64,
        now: u64,
    ) -> Result<Self, String> {
        let captured = job.captured.as_ref().ok_or("backup is not captured")?;
        job.plan.reauthorize(world)?;
        require(
            world,
            id,
            "create",
            "restores",
            Some(&destination.namespace),
            Some(&destination.claim_name),
        )?;
        if !destination.current(world)
            || destination.namespace_uid != job.plan.source.binding.namespace_uid
            || destination.cluster_id != job.plan.source.binding.cluster_id
            || destination.volume_uid == job.plan.source.binding.volume_uid
            || destination.claim_uid == job.plan.source.binding.claim_uid
            || expires_unix_ms <= now
            || expires_unix_ms.saturating_sub(now) > 15 * 60 * 1000
        {
            return Err(
                "restore requires a distinct current namespace-owned target and bounded approval"
                    .into(),
            );
        }
        Ok(Self {
            uid: Uid::new(),
            capture_plan_sha256: job.plan_sha256.clone(),
            repository_uid: job.plan.repository.uid.clone(),
            snapshot_id: captured.snapshot_id.clone(),
            manifest_sha256: captured.manifest_sha256.clone(),
            destination,
            requested_by: IdentityRecord::of(id),
            expires_unix_ms,
        })
    }
    pub fn reauthorize(
        &self,
        world: &DesiredWorld,
        now: u64,
        approved_hash: &str,
    ) -> Result<(), String> {
        if self.hash()? != approved_hash
            || now == 0
            || self.expires_unix_ms.saturating_sub(now) > 15 * 60 * 1000
            || now >= self.expires_unix_ms
            || !self.destination.current(world)
        {
            return Err(
                "restore approval expired, changed or belongs to an old namespace/claim".into(),
            );
        }
        require(
            world,
            &self.requested_by.identity(),
            "create",
            "restores",
            Some(&self.destination.namespace),
            Some(&self.destination.claim_name),
        )
    }
}

/// Opaque adapter acknowledgements: never deserialize client JSON into these.
pub(crate) struct CaptureReceipt(CaptureEvidence);
pub(crate) struct CheckReceipt(CheckEvidence);
pub(crate) struct RestoreReceipt(RestoreEvidence);
pub(crate) struct ReconciledNoEffect {
    _private: (),
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Registry {
    version: u32,
    repositories: BTreeMap<Uid, Repository>,
    jobs: BTreeMap<Uid, Job>,
    #[serde(default, deserialize_with = "precapture::unique_reservations")]
    capture_reservations: BTreeMap<Uid, precapture::CaptureReservation>,
}
impl Registry {
    pub fn fresh() -> Self {
        Self {
            version: 2,
            ..Self::default()
        }
    }
    pub fn has_authority(&self) -> bool {
        !self.repositories.is_empty() || !self.jobs.is_empty() || !self.capture_reservations.is_empty()
    }
    /// Old schemas/encryption domains may migrate absence ONLY. Any imported
    /// job/repository, including a completed history, requires explicit recovery.
    pub(crate) fn migrate_legacy_empty(&mut self) -> Result<(), String> {
        if self.has_authority() || self.version > 1 {
            return Err("legacy state/envelope cannot import backup authority".into());
        }
        *self = Self::fresh();
        Ok(())
    }
    /// Registry's permissive serde defaults exist for pre-backup migration,
    /// not permission to discard a missing persisted jobs/repository map.
    pub(crate) fn require_explicit_state_fields(raw: &serde_json::Value) -> Result<(), String> {
        if raw.get("version").and_then(|v| v.as_u64()) != Some(2)
            || !raw.get("repositories").is_some_and(|v| v.is_object())
            || !raw.get("jobs").is_some_and(|v| v.is_object())
            || !raw.get("capture_reservations").is_some_and(|v| v.is_object())
        {
            return Err("backup registry state requires explicit version/repositories/jobs/capture_reservations fields; refusing to infer missing history".into());
        }
        Ok(())
    }
    /// Schema6 / backup-domain-v5 already protected capture/check records, but
    /// did not protect the strict restore plan/attempt contract. Inspect the
    /// JSON before typed decoding so even old receipts missing the new fields
    /// fail with an explicit recovery requirement, never fabricated defaults.
    pub(crate) fn reject_pre_contract_restore(raw: &serde_json::Value) -> Result<(), String> {
        let object = raw.as_object().ok_or("malformed legacy backup registry")?;
        if let Some(jobs) = object.get("jobs") {
            let jobs = jobs.as_object().ok_or("malformed legacy backup jobs")?;
            for job in jobs.values() {
                let job = job.as_object().ok_or("malformed legacy backup job")?;
                if job.get("restore_plan").is_some_and(|v| !v.is_null())
                    || job.get("restore_verified").is_some_and(|v| !v.is_null())
                    || job.get("requested").and_then(|v| v.as_str()) == Some("Restore")
                    || job.get("attempt").and_then(|v| v.get("operation"))
                        .and_then(|v| v.as_str()) == Some("Restore")
                {
                    return Err("legacy restore state requires explicit recovery; no plan/attempt evidence is synthesized".into());
                }
            }
        }
        Ok(())
    }
    /// No fields or authority are added. Preserve valid pre-contract capture /
    /// check history exactly, while every restore-bearing state is refused.
    pub(crate) fn validate_pre_contract_no_restore(&self) -> Result<(), String> {
        if self.jobs.values().any(|job| {
            job.requested == Operation::Restore
                || job.restore_plan.is_some()
                || job.restore_verified.is_some()
                || job.attempt.as_ref().is_some_and(|a| a.operation == Operation::Restore)
        }) {
            return Err("legacy restore state requires explicit recovery".into());
        }
        self.validate()
    }
    pub(crate) fn validate_state(&self, state: &crate::store::DesiredState) -> Result<(), String> {
        self.validate()?;
        if self
            .jobs
            .values()
            .any(|job| job.plan.source.binding.cluster_id != state.cluster_id)
            || !self.capture_cluster_matches(&state.cluster_id)
        {
            return Err("backup registry contains foreign cluster identities".into());
        }
        Ok(())
    }
    pub(crate) fn validate_snapshot_successor(&self, next: &Self) -> Result<(), String> {
        self.validate()?;
        next.validate()?;
        self.validate_capture_successor(next, true)?;
        for (uid, old) in &self.jobs {
            let new = next
                .jobs
                .get(uid)
                .ok_or("snapshot cannot discard backup history")?;
            validate_check_progress(
                old.repository_checked.as_ref(),
                new.repository_checked.as_ref(),
            )?;
            if old.plan != new.plan
                || old.plan_sha256 != new.plan_sha256
                || old.attempts_started > new.attempts_started
                || old.captured.is_some() && old.captured != new.captured
                || old.restore_plan.is_some() && old.restore_plan != new.restore_plan
                || old.restore_verified.is_some() && old.restore_verified != new.restore_verified
            {
                return Err("snapshot rolls back or replaces backup identity/evidence".into());
            }
        }
        for (uid, repository) in &self.repositories {
            if next.repositories.get(uid) != Some(repository) {
                return Err("snapshot replaces approved backup repository".into());
            }
        }
        Ok(())
    }
    pub fn job(&self, uid: &Uid) -> Option<&Job> {
        self.jobs.get(uid)
    }
    pub fn get_authorized(
        &self,
        world: &DesiredWorld,
        id: &Identity,
        namespace: &str,
        uid: &Uid,
    ) -> Result<&Job, String> {
        require(
            world,
            id,
            "get",
            "backups",
            Some(namespace),
            Some(uid.as_str()),
        )?;
        let namespace_uid = world
            .storage_identities
            .namespaces
            .get(namespace)
            .ok_or("backup namespace absent")?;
        self.jobs
            .get(uid)
            .filter(|job| {
                job.plan.source.binding.namespace == namespace
                    && &job.plan.source.binding.namespace_uid == namespace_uid
                    && job.plan.source.binding.cluster_id == world.cluster_id
            })
            .ok_or("backup not found in current namespace".into())
    }
    pub fn list_authorized(
        &self,
        world: &DesiredWorld,
        id: &Identity,
        namespace: &str,
    ) -> Result<Vec<&Job>, String> {
        require(world, id, "list", "backups", Some(namespace), None)?;
        let namespace_uid = world
            .storage_identities
            .namespaces
            .get(namespace)
            .ok_or("backup namespace absent")?;
        Ok(self
            .jobs
            .values()
            .filter(|job| {
                job.plan.source.binding.namespace == namespace
                    && &job.plan.source.binding.namespace_uid == namespace_uid
                    && job.plan.source.binding.cluster_id == world.cluster_id
            })
            .collect())
    }
    pub fn approve_repository(
        &mut self,
        world: &DesiredWorld,
        id: &Identity,
        repository: Repository,
    ) -> Result<(), String> {
        require(world, id, "create", "backuprepositories", None, None)?;
        repository.validate()?;
        if !world
            .storage_identities
            .namespaces
            .values()
            .any(|uid| uid == &repository.namespace_uid)
            || self
                .repositories
                .values()
                .any(|r| r.repository_id == repository.repository_id && r != &repository)
            || self
                .repositories
                .get(&repository.uid)
                .is_some_and(|r| r != &repository)
        {
            return Err(
                "repository is absent, reused across tenants or cannot be replaced in-place".into(),
            );
        }
        self.repositories.insert(repository.uid.clone(), repository);
        Ok(())
    }
    pub(crate) fn enqueue(
        &mut self,
        world: &DesiredWorld,
        plan: CapturePlan,
    ) -> Result<Uid, String> {
        plan.reauthorize(world)?;
        if self.reservation_blocks(&plan.repository.uid, &plan.source.binding) {
            return Err("capture source/repository held by pre-capture reservation".into());
        }
        if self.jobs.values().any(|job| {
            job.restore_verified.is_none()
                && job.restore_plan.as_ref().is_some_and(|restore| {
                    restore.destination.volume_uid == plan.source.binding.volume_uid
                        || restore.destination.claim_uid == plan.source.binding.claim_uid
                })
        }) {
            return Err("capture source is a reserved or unresolved restore target".into());
        }
        if self.version != 2
            || self.jobs.len() + self.capture_reservations.len() >= 4096
            || self.repositories.get(&plan.repository.uid) != Some(&plan.repository)
            || self.jobs.contains_key(&plan.uid)
            || self.capture_reservations.contains_key(&plan.uid)
        {
            return Err("unapproved repository, duplicate job or job admission exhausted".into());
        }
        let uid = plan.uid.clone();
        let plan_sha256 = plan.hash()?;
        let operation_requested_by = plan.requested_by.clone();
        self.jobs.insert(
            uid.clone(),
            Job {
                plan,
                plan_sha256,
                state: State::Queued,
                requested: Operation::Capture,
                operation_requested_by,
                attempt: None,
                attempts_started: 0,
                captured: None,
                repository_checked: None,
                restore_verified: None,
                restore_plan: None,
                failure_code: None,
                partial_effects_possible: false,
            },
        );
        Ok(uid)
    }
    /// Commit this before spawning. Serializes each repository AND each volume.
    pub fn start(
        &mut self,
        world: &DesiredWorld,
        uid: &Uid,
        node_uid: Uid,
        boot_id: String,
        now: u64,
    ) -> Result<Attempt, String> {
        let job = self.jobs.get(uid).ok_or("backup job absent")?;
        job.execution_authorized(world, now)?;
        if self.reservation_blocks(&job.plan.repository.uid, &job.plan.source.binding) {
            return Err("backup source/repository held by pre-capture reservation".into());
        }
        if job.requested == Operation::Restore {
            return Err("restore dispatch requires an independently verified fresh-target lease; adapter unavailable".into());
        }
        if job.state != State::Queued
            || job.attempts_started >= 1024
            || now == 0
            || !crate::storage_lifecycle::valid_uuid(&boot_id)
        {
            return Err("backup job is not dispatchable".into());
        }
        if self.jobs.iter().any(|(other_uid, other)| {
            other_uid != uid
                && other.attempt.is_some()
                && (other.plan.repository.uid == job.plan.repository.uid
                    || other.plan.source.binding.volume_uid == job.plan.source.binding.volume_uid)
        }) {
            return Err(
                "repository/volume already has an in-flight or unreconciled operation".into(),
            );
        }
        let job = self.jobs.get_mut(uid).unwrap();
        let attempt = Attempt {
            uid: Uid::new(),
            operation: job.requested,
            started_unix_ms: now,
            node_uid,
            boot_id,
        };
        job.attempts_started += 1;
        job.state = State::Running;
        job.attempt = Some(attempt.clone());
        job.partial_effects_possible = true;
        Ok(attempt)
    }
    pub fn request_cancel(
        &mut self,
        world: &DesiredWorld,
        id: &Identity,
        uid: &Uid,
    ) -> Result<(), String> {
        let job = self.jobs.get_mut(uid).ok_or("backup job absent")?;
        let b = &job.plan.source.binding;
        require(
            world,
            id,
            "cancel",
            "backups",
            Some(&b.namespace),
            Some(uid.as_str()),
        )?;
        if !b.current(world) {
            return Err("backup namespace/claim identity changed".into());
        }
        match job.state {
            State::Queued => {
                job.state = State::Cancelled;
                job.partial_effects_possible = false;
            }
            State::Running | State::CancelRequested => job.state = State::CancelRequested,
            State::NeedsReconciliation => {}
            _ => return Err("backup job has no active operation".into()),
        }
        Ok(())
    }
    /// Called after child reaping OR on restart. Cancellation/revocation does
    /// not erase unknown effects or permit an automatic retry/overwrite.
    pub fn interrupted(&mut self, uid: &Uid, attempt: &Uid, code: &str) -> Result<(), String> {
        let j = self.jobs.get_mut(uid).ok_or("backup job absent")?;
        if j.attempt.as_ref().map(|a| &a.uid) != Some(attempt)
            || code.is_empty()
            || code.len() > 64
            || !code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        {
            return Err("invalid interrupted attempt".into());
        }
        j.state = State::NeedsReconciliation;
        j.failure_code = Some(code.into());
        j.partial_effects_possible = true;
        Ok(())
    }
    pub fn recover_after_restart(&mut self) {
        self.recover_capture_requests();
        for job in self.jobs.values_mut() {
            if matches!(job.state, State::Running | State::CancelRequested) {
                job.state = State::NeedsReconciliation;
                job.failure_code = Some("WORKER_RESTARTED".into());
                job.partial_effects_possible = true;
            }
        }
    }
    pub(crate) fn captured(
        &mut self,
        uid: &Uid,
        attempt: &Uid,
        receipt: CaptureReceipt,
    ) -> Result<(), String> {
        let j = self.jobs.get_mut(uid).ok_or("backup job absent")?;
        j.matches_attempt(attempt)?;
        if j.requested != Operation::Capture || j.captured.is_some() {
            return Err("wrong capture acknowledgement".into());
        }
        j.captured = Some(receipt.0);
        j.state = State::Idle;
        j.attempt = None;
        j.partial_effects_possible = false;
        j.validate()
    }
    pub fn request_check(
        &mut self,
        world: &DesiredWorld,
        id: &Identity,
        uid: &Uid,
    ) -> Result<(), String> {
        let j = self.jobs.get_mut(uid).ok_or("backup job absent")?;
        j.plan.reauthorize(world)?;
        require(
            world,
            id,
            "verify",
            "backups",
            Some(&j.plan.source.binding.namespace),
            Some(uid.as_str()),
        )?;
        if j.state != State::Idle || j.captured.is_none() {
            return Err("capture is not ready for verification".into());
        }
        j.requested = Operation::RepositoryCheck;
        j.operation_requested_by = IdentityRecord::of(id);
        j.state = State::Queued;
        Ok(())
    }
    pub(crate) fn checked(
        &mut self,
        uid: &Uid,
        attempt: &Uid,
        receipt: CheckReceipt,
    ) -> Result<(), String> {
        let j = self.jobs.get(uid).ok_or("backup job absent")?;
        j.matches_attempt(attempt)?;
        if j.requested != Operation::RepositoryCheck {
            return Err("wrong repository check acknowledgement".into());
        }
        let mut next = j.clone();
        next.repository_checked = Some(receipt.0);
        next.state = State::Idle;
        next.attempt = None;
        next.partial_effects_possible = false;
        next.validate()?;
        validate_check_progress(
            j.repository_checked.as_ref(),
            next.repository_checked.as_ref(),
        )?;
        // Publish only after validation. An invalid acknowledgement must leave
        // the running attempt and all previous evidence untouched.
        self.jobs.insert(uid.clone(), next);
        Ok(())
    }
    pub fn request_restore(
        &mut self,
        world: &DesiredWorld,
        uid: &Uid,
        plan: RestorePlan,
        approved_hash: &str,
        now: u64,
    ) -> Result<(), String> {
        let j = self.jobs.get(uid).ok_or("backup job absent")?;
        j.plan.reauthorize(world)?;
        plan.reauthorize(world, now, approved_hash)?;
        let c = j.captured.as_ref().ok_or("capture absent")?;
        if self.reservation_blocks(&j.plan.repository.uid, &j.plan.source.binding)
            || self.capture_reservations.values().any(|r|
                r.request_binding().volume_uid == plan.destination.volume_uid
                    || r.request_binding().claim_uid == plan.destination.claim_uid)
        {
            return Err("restore source/repository/target conflicts with pre-capture history".into());
        }
        if j.state != State::Idle
            || j.repository_checked.is_none()
            || j.restore_plan.is_some()
            || plan.capture_plan_sha256 != j.plan_sha256
            || plan.repository_uid != j.plan.repository.uid
            || plan.snapshot_id != c.snapshot_id
            || plan.manifest_sha256 != c.manifest_sha256
        {
            return Err("restore is not an exact checked point or target was already used".into());
        }
        if self.jobs.values().any(|other| {
            other.plan.source.binding.volume_uid == plan.destination.volume_uid
                || other.plan.source.binding.claim_uid == plan.destination.claim_uid
                || other.restore_plan.as_ref().is_some_and(|reserved| {
                    reserved.destination.volume_uid == plan.destination.volume_uid
                        || reserved.destination.claim_uid == plan.destination.claim_uid
                })
        }) {
            return Err(
                "restore target has prior backup use or an existing restore reservation".into(),
            );
        }
        let j = self.jobs.get_mut(uid).unwrap();
        j.operation_requested_by = plan.requested_by.clone();
        j.restore_plan = Some(plan);
        j.requested = Operation::Restore;
        j.state = State::Queued;
        Ok(())
    }
    pub(crate) fn restored(
        &mut self,
        uid: &Uid,
        attempt: &Uid,
        receipt: RestoreReceipt,
    ) -> Result<(), String> {
        let j = self.jobs.get(uid).ok_or("backup job absent")?;
        j.matches_attempt(attempt)?;
        if j.requested != Operation::Restore {
            return Err("wrong restore acknowledgement".into());
        }
        if receipt.0.attempt_uid != *attempt {
            return Err("restore receipt belongs to a different attempt".into());
        }
        let mut next = j.clone();
        next.restore_verified = Some(receipt.0);
        next.state = State::Idle;
        next.attempt = None;
        next.partial_effects_possible = false;
        next.validate()?;
        self.jobs.insert(uid.clone(), next);
        Ok(())
    }
    /// No public constructor for no-effect proof. Adapter reconciliation must
    /// independently prove absence. A caller boolean/empty tag query is not it.
    pub(crate) fn retry_after_no_effect(
        &mut self,
        uid: &Uid,
        attempt: &Uid,
        _proof: ReconciledNoEffect,
    ) -> Result<(), String> {
        let j = self.jobs.get_mut(uid).ok_or("backup job absent")?;
        if j.state != State::NeedsReconciliation
            || j.attempt.as_ref().map(|v| &v.uid) != Some(attempt)
            || j.requested == Operation::Restore
        {
            return Err(
                "retry requires exact no-effect reconciliation; restore targets are never reused"
                    .into(),
            );
        }
        j.state = State::Queued;
        j.attempt = None;
        j.failure_code = None;
        j.partial_effects_possible = false;
        Ok(())
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 2 || self.jobs.len() > 4096 || self.repositories.len() > 256 {
            return Err("unsupported/excessive backup registry".into());
        }
        self.validate_capture_requests()?;
        let mut repo_ids = BTreeSet::new();
        for (uid, repo) in &self.repositories {
            repo.validate()?;
            if uid != &repo.uid || !repo_ids.insert(&repo.repository_id) {
                return Err("duplicate repository/tenant boundary".into());
            }
        }
        let mut active_repos = BTreeSet::new();
        let mut active_volumes = BTreeSet::new();
        let mut restore_volumes = BTreeSet::new();
        let mut restore_claims = BTreeSet::new();
        let source_volumes: BTreeSet<_> = self
            .jobs
            .values()
            .map(|job| &job.plan.source.binding.volume_uid)
            .collect();
        let source_claims: BTreeSet<_> = self
            .jobs
            .values()
            .map(|job| &job.plan.source.binding.claim_uid)
            .collect();
        for (uid, job) in &self.jobs {
            job.validate()?;
            if let Some(plan) = &job.restore_plan {
                if !restore_volumes.insert(&plan.destination.volume_uid)
                    || !restore_claims.insert(&plan.destination.claim_uid)
                {
                    return Err(
                        "multiple restore intents reserve the same target incarnation".into(),
                    );
                }
                if job.restore_verified.is_none()
                    && (source_volumes.contains(&plan.destination.volume_uid)
                        || source_claims.contains(&plan.destination.claim_uid))
                {
                    return Err("unresolved restore target is also a capture source".into());
                }
            }
            if uid != &job.plan.uid
                || self.repositories.get(&job.plan.repository.uid) != Some(&job.plan.repository)
            {
                return Err("job repository/identity not approved".into());
            }
            if job.attempt.is_some()
                && (!active_repos.insert(&job.plan.repository.uid)
                    || !active_volumes.insert(&job.plan.source.binding.volume_uid))
            {
                return Err("conflicting in-flight backup ownership".into());
            }
        }
        Ok(())
    }
    pub fn validate_transition(&self, next: &Self) -> Result<(), String> {
        self.validate()?;
        next.validate()?;
        self.validate_capture_successor(next, false)?;
        for (uid, old) in &self.jobs {
            let new = next
                .jobs
                .get(uid)
                .ok_or("backup evidence cannot be removed by state replacement")?;
            validate_check_progress(
                old.repository_checked.as_ref(),
                new.repository_checked.as_ref(),
            )?;
            if old.plan != new.plan
                || old.plan_sha256 != new.plan_sha256
                || old.attempts_started > new.attempts_started
                || old.captured.is_some() && old.captured != new.captured
                || old.restore_plan.is_some() && old.restore_plan != new.restore_plan
                || old.restore_verified.is_some() && old.restore_verified != new.restore_verified
            {
                return Err("immutable backup plan/evidence changed or rolled back".into());
            }
            if old == new {
                continue;
            }
            let dispatch = old.state == State::Queued && new.state == State::Running;
            let finish = old.state == State::Running && new.state == State::Idle;
            let queue = old.state == State::Idle && new.state == State::Queued;
            let cancel_queued = old.state == State::Queued && new.state == State::Cancelled;
            let cancel_running = old.state == State::Running && new.state == State::CancelRequested;
            let unknown = matches!(
                old.state,
                State::Running | State::CancelRequested | State::NeedsReconciliation
            ) && new.state == State::NeedsReconciliation;
            let reconciled_retry =
                old.state == State::NeedsReconciliation && new.state == State::Queued;
            if !(dispatch
                || finish
                || queue
                || cancel_queued
                || cancel_running
                || unknown
                || reconciled_retry)
                || new.attempts_started != old.attempts_started + u32::from(dispatch)
                || !queue
                    && (new.requested != old.requested
                        || new.operation_requested_by != old.operation_requested_by)
                || new.captured != old.captured && !(finish && old.requested == Operation::Capture)
                || new.repository_checked != old.repository_checked
                    && !(finish && old.requested == Operation::RepositoryCheck)
                || new.restore_verified != old.restore_verified
                    && !(finish && old.requested == Operation::Restore)
                || new.restore_plan != old.restore_plan
                    && !(queue && new.requested == Operation::Restore)
                || matches!(
                    new.state,
                    State::Running | State::CancelRequested | State::NeedsReconciliation
                ) && !dispatch
                    && new.attempt != old.attempt
                || queue && (new.requested == Operation::Capture || new.attempt.is_some())
                || dispatch
                    && (new
                        .attempt
                        .as_ref()
                        .is_none_or(|a| a.operation != old.requested)
                        || new.failure_code != old.failure_code
                        || !new.partial_effects_possible)
                || finish && (new.attempt.is_some() || new.partial_effects_possible)
                || finish
                    && old.requested == Operation::Restore
                    && new.restore_verified.as_ref().is_none_or(|evidence| {
                        old.attempt.as_ref().map(|attempt| &attempt.uid)
                            != Some(&evidence.attempt_uid)
                    })
                || unknown && !new.partial_effects_possible
            {
                return Err("illegal backup job transition or unbound acknowledgement".into());
            }
        }
        for (uid, job) in &next.jobs {
            if !self.jobs.contains_key(uid)
                && (job.state != State::Queued
                    || job.requested != Operation::Capture
                    || job.attempt.is_some()
                    || job.attempts_started != 0
                    || job.captured.is_some()
                    || job.repository_checked.is_some()
                    || job.restore_verified.is_some()
                    || job.restore_plan.is_some()
                    || job.failure_code.is_some()
                    || job.partial_effects_possible
                    || job.operation_requested_by != job.plan.requested_by)
            {
                return Err(
                    "new backup jobs may import intent only, never execution/evidence authority"
                        .into(),
                );
            }
        }
        for (uid, old) in &self.repositories {
            if next.repositories.get(uid) != Some(old) {
                return Err("approved repository identity cannot be replaced in-place".into());
            }
        }
        Ok(())
    }
}

pub(crate) fn snapshot_path_ok(path: &str) -> bool {
    use std::path::{Component, Path};
    path.len() <= 4096
        && Path::new(path).is_absolute()
        && path != "/"
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
        && !path.contains('\0')
}

#[cfg(test)]
#[path = "backup_engine/integration_tests.rs"]
mod integration_tests;
#[cfg(test)]
#[path = "backup_engine/tests.rs"]
mod tests;
#[cfg(test)]
#[path = "backup_engine/schema_migration_tests.rs"]
mod schema_migration_tests;
