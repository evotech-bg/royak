//! Private storage protocol. Wire DTOs are data, never a physical receipt.
//! Optional normal runtime requires an actual guarded committed directory;
//! cold offers do not grant work. Grants additionally join live expected jobs.
//! No initialization, writer, mount or lifecycle receipt is exposed here.
use crate::raft_node::storage_remote_core::CoreObservation;
use crate::storage_boot::BootId;
use crate::storage_identity::Uid;
use crate::storage_lifecycle::generation::physical::{ExpectedInitScope, PhaseObservation};
use crate::storage_lifecycle::generation::{DataGeneration, VirginReplicaRef};
use crate::storage_lifecycle::{Owner, Phase};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
#[path = "storage_attach_protocol.rs"]
pub(crate) mod attachment;

pub(crate) const MAX_FRAME_BYTES: usize = 32 * 1024;
const MAX_JOB_MS: u64 = 900_000;
const MAX_BOUNDARY_MS: u64 = crate::raft_node::storage_remote_core::MAX_STORAGE_BOUNDARY_MS;
const MAX_DIRECTORY_NODES: usize = 32;
pub(crate) const DOMAIN: &[u8] = b"royak-storage-issuer-v1";
pub(crate) const GRANT_PATH: &str = "/royak/v1/storage/node/grant";
pub(crate) const BOUNDARY_PATH: &str = "/royak/v1/storage/node/boundary";
pub(crate) const NODE_JOB_PATH: &str = "/royak/v1/storage/node/job";

pub(crate) fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    let raw = serde_json::to_vec(value).map_err(|_| "invalid storage protocol value")?;
    if raw.len() > MAX_FRAME_BYTES {
        return Err("storage protocol frame exceeds bound".into());
    }
    Ok(raw)
}
fn decode<T: for<'a> Deserialize<'a>>(raw: &[u8]) -> Result<T, String> {
    if raw.is_empty() || raw.len() > MAX_FRAME_BYTES {
        return Err("invalid bounded storage protocol frame".into());
    }
    serde_json::from_slice(raw).map_err(|_| "malformed storage protocol frame".into())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Revision {
    pub(crate) term: u64,
    pub(crate) leader_raft_id: u64,
    pub(crate) applied_term: u64,
    pub(crate) applied_leader_raft_id: u64,
    pub(crate) applied_index: u64,
    pub(crate) desired_generation: u64,
    pub(crate) membership_sha256: String,
}
impl Revision {
    fn valid(&self) -> bool {
        self.term > 0
            && self.leader_raft_id > 0
            && self.applied_term <= self.term
            && self.applied_index > 0
            && self.desired_generation > 0
            && valid_hash(&self.membership_sha256)
    }
    pub(crate) fn at_least(&self, other: &Self) -> bool {
        self.valid()
            && other.valid()
            && self.term == other.term
            && self.leader_raft_id == other.leader_raft_id
            && self.membership_sha256 == other.membership_sha256
            && self.applied_index >= other.applied_index
            && self.applied_term >= other.applied_term
            && (self.applied_term != other.applied_term
                || self.applied_leader_raft_id == other.applied_leader_raft_id)
            && self.desired_generation >= other.desired_generation
            && (self.applied_index != other.applied_index
                || (self.applied_term == other.applied_term
                    && self.applied_leader_raft_id == other.applied_leader_raft_id
                    && self.desired_generation == other.desired_generation))
    }
}

pub(crate) use crate::storage_node_directory::{DirectoryDto, NodePin};
/// Not Deserialize: only actual Core + its applied-history guard can supply
/// the matching commitment. Raw schema8 fields alone are not sufficient.
#[derive(Clone)]
pub(crate) struct VerifiedDirectory {
    dto: DirectoryDto,
    sha256: String,
}
impl VerifiedDirectory {
    pub(crate) fn from_runtime(
        view: &crate::raft_node::storage_remote_core::RuntimeView,
    ) -> Result<Self, String> {
        let dto = view.directory().clone();
        dto.validate()?;
        Ok(Self {
            sha256: dto.sha256()?,
            dto,
        })
    }
    pub(crate) fn from_core(observed: &CoreObservation, dto: DirectoryDto) -> Result<Self, String> {
        dto.validate()?;
        let commitment = observed.directory_commitment().ok_or(
            "no committed guarded storage-node directory; explicit enrollment/recovery required",
        )?;
        let sha256 = hash(&encode(&dto)?);
        let mut ids = dto.nodes.iter().map(|n| n.raft_id).collect::<Vec<_>>();
        ids.sort_unstable();
        let mut voters = observed.voters().to_vec();
        voters.sort_unstable();
        if commitment != sha256 || dto.cluster_id != observed.cluster_id() || ids != voters {
            return Err("node directory is not the current committed exact identity map".into());
        }
        Ok(Self { dto, sha256 })
    }
    pub(crate) fn pin(&self, id: &Uid) -> Result<&NodePin, String> {
        self.dto
            .nodes
            .iter()
            .find(|n| &n.node_uid == id)
            .ok_or_else(|| "storage member UID is not registered".into())
    }
    pub(crate) fn signer(&self, name: &str) -> Result<&NodePin, String> {
        self.dto
            .nodes
            .iter()
            .find(|n| n.signer_name == name)
            .ok_or_else(|| "storage RPC signer is not registered".into())
    }
    pub(crate) fn digest(&self) -> &str {
        &self.sha256
    }
    pub(crate) fn cluster_id(&self) -> &str {
        &self.dto.cluster_id
    }
    pub(crate) fn dto_nodes(&self) -> &[NodePin] {
        &self.dto.nodes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum JobKind {
    PrepareVirginOffline,
    PrepareClosedSecondary,
    ObserveVirginReplica,
    InitializeVirginGeneration,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Boundary {
    ColdStart,
    ColdIdentity,
    ColdProgram,
    ColdZeroWrite,
    ColdZeroFsync,
    ColdComplete,
    InitStart,
    InitIdentity,
    InitProgram,
    InitRead,
    InitComplete,
    Checkpoint,
    ReadInventory,
    PrepareNewBacking,
    CreateNewMetadata,
    ActivateClosedSecondary,
    ObserveVirgin,
}
impl Boundary {
    fn permits(self, kind: JobKind) -> bool {
        match kind {
            JobKind::PrepareVirginOffline => matches!(
                self,
                Self::ColdStart
                    | Self::ColdIdentity
                    | Self::ColdProgram
                    | Self::ColdZeroWrite
                    | Self::ColdZeroFsync
                    | Self::ColdComplete
            ),
            JobKind::PrepareClosedSecondary => matches!(
                self,
                Self::Checkpoint
                    | Self::ReadInventory
                    | Self::PrepareNewBacking
                    | Self::CreateNewMetadata
                    | Self::ActivateClosedSecondary
            ),
            JobKind::ObserveVirginReplica => matches!(
                self,
                Self::Checkpoint | Self::ReadInventory | Self::ObserveVirgin
            ),
            JobKind::InitializeVirginGeneration => matches!(
                self,
                Self::InitStart
                    | Self::InitIdentity
                    | Self::InitProgram
                    | Self::InitRead
                    | Self::InitComplete
            ),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JobSpec {
    pub(crate) version: u32,
    pub(crate) owner: Owner,
    pub(crate) operation_uid: Uid,
    pub(crate) dataset_uid: Option<Uid>,
    pub(crate) kind: JobKind,
    pub(crate) issuer_node_uid: Uid,
    pub(crate) issuer_boot: BootId,
    pub(crate) target_node_uid: Uid,
    pub(crate) target_boot: BootId,
    pub(crate) job_uid: Uid,
    pub(crate) plan_sha256: String,
    pub(crate) scope_sha256: String,
    pub(crate) directory_sha256: String,
    pub(crate) issuer_revision: Revision,
    pub(crate) maximum_duration_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) initialization: Option<ExpectedInitScope>,
}
impl JobSpec {
    pub(crate) fn check_observed(
        &self,
        view: &CoreObservation,
        directory: &VerifiedDirectory,
    ) -> Result<(), String> {
        self.current(view, directory)
    }
    fn validate(&self) -> Result<(), String> {
        if !matches!(
            (self.version, self.kind, self.initialization.as_ref()),
            (
                1,
                JobKind::PrepareVirginOffline
                    | JobKind::PrepareClosedSecondary
                    | JobKind::ObserveVirginReplica,
                None
            ) | (2, JobKind::InitializeVirginGeneration, Some(_))
        ) || self.issuer_node_uid == self.target_node_uid
            || !self.issuer_revision.valid()
            || self.maximum_duration_ms == 0
            || self.maximum_duration_ms > MAX_JOB_MS
            || self.kind == JobKind::PrepareVirginOffline && self.maximum_duration_ms > 180_000
            || ![
                &self.plan_sha256,
                &self.scope_sha256,
                &self.directory_sha256,
            ]
            .into_iter()
            .all(|s| valid_hash(s))
            || matches!(
                self.kind,
                JobKind::PrepareVirginOffline
                    | JobKind::PrepareClosedSecondary
                    | JobKind::ObserveVirginReplica
            ) && self.dataset_uid.is_some()
            || self.kind == JobKind::InitializeVirginGeneration && self.dataset_uid.is_none()
        {
            return Err("invalid exact storage job binding".into());
        }
        if let Some(scope) = &self.initialization {
            scope.validate()?;
            let fact = scope
                .generation
                .virgin_replicas
                .iter()
                .find(|fact| {
                    fact.node_uid == scope.target_node_uid && fact.node_boot_id == scope.target_boot
                })
                .ok_or("initialization target absent")?;
            if scope.owner != self.owner
                || scope.generation.initialize_operation_uid != self.operation_uid
                || self.dataset_uid.as_ref() != Some(&scope.generation.uid)
                || scope.issuer_node_uid != self.issuer_node_uid
                || scope.issuer_boot != self.issuer_boot
                || scope.target_node_uid != self.target_node_uid
                || scope.target_boot != self.target_boot
                || scope.phase_job_uid != self.job_uid
                || scope.issuer_revision != self.issuer_revision
                || scope.directory_sha256 != self.directory_sha256
                || scope.scope_sha256 != self.scope_sha256
                || fact.plan_sha256 != self.plan_sha256
                || scope.remaining_budget_ms != self.maximum_duration_ms
                || self.maximum_duration_ms > 180_000
            {
                return Err("phase spec differs from complete initialization scope".into());
            }
        }
        Ok(())
    }
    fn current(&self, view: &CoreObservation, directory: &VerifiedDirectory) -> Result<(), String> {
        self.validate()?;
        if let Some(scope) = &self.initialization {
            if view.volume().data_generation() != Some(&scope.generation) {
                return Err("phase dataset differs from actual committed generation".into());
            }
        }
        if self.owner != *view.volume().owner()
            || self.owner.cluster_id != view.cluster_id()
            || directory.cluster_id() != view.cluster_id()
            || self.scope_sha256 != view.scope_sha256()
            || self.directory_sha256 != directory.digest()
            || view.volume().operation() != &self.operation_uid
            || view.volume().phase() != Phase::Provisioning
            || view.volume().epoch() != 0
            || view.volume().assignment().is_some()
            || view.volume().data_generation().map(|g| g.uid.clone()) != self.dataset_uid
            || !view.revision().at_least(&self.issuer_revision)
            || !view
                .volume()
                .replicas()
                .zip(view.volume().provision_boots())
                .is_some_and(|(nodes, boots)| {
                    nodes
                        .iter()
                        .zip(boots)
                        .any(|(id, boot)| id == &self.target_node_uid && boot == &self.target_boot)
                })
        {
            return Err(
                "storage job no longer matches actual committed receiver/issuer state".into(),
            );
        }
        if directory.pin(&self.issuer_node_uid)?.raft_id != self.issuer_revision.leader_raft_id {
            return Err("storage issuer UID is not the pinned current Raft leader".into());
        }
        directory.pin(&self.target_node_uid)?;
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRequest {
    version: u32,
    spec: JobSpec,
    receiver_nonce: Uid,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantReply {
    version: u32,
    grant_uid: Uid,
    request_sha256: String,
    receiver_nonce: Uid,
    issuer_nonce: Uid,
    spec: JobSpec,
    confirmed_revision: Revision,
    remaining_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryRequest {
    version: u32,
    grant_uid: Uid,
    job_uid: Uid,
    sequence: u64,
    nonce: Uid,
    kind: Boundary,
    detail_sha256: String,
    local_revision: Revision,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BoundaryReply {
    version: u32,
    grant_uid: Uid,
    job_uid: Uid,
    sequence: u64,
    nonce: Uid,
    request_sha256: String,
    confirmed_revision: Revision,
    approved: bool,
}

/// Created only by the future authenticated transport adapter after HMAC,
/// dedicated-domain unseal, socket endpoint and actual WG key/AllowedIPs checks.
/// No Deserialize and no raw constructor exposed to API/JSON callers.
pub(crate) struct VerifiedPeerFrame {
    sender: Uid,
    receiver: Uid,
    body: Vec<u8>,
}
impl VerifiedPeerFrame {
    pub(crate) fn sender(&self) -> &Uid {
        &self.sender
    }
    pub(crate) fn receiver(&self) -> &Uid {
        &self.receiver
    }
    pub(crate) fn read_challenge(&self) -> ReadChallenge {
        ReadChallenge {
            binding: hash(
                &serde_json::to_vec(&(&self.sender, &self.receiver, hash(&self.body)))
                    .expect("fixed bounded challenge tuple"),
            ),
        }
    }
    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }
    pub(crate) fn from_transport(
        proof: crate::storage_driver::remote_transport::VerifiedStorageTransport,
        body: Vec<u8>,
    ) -> Result<Self, String> {
        if body.is_empty() || body.len() > MAX_FRAME_BYTES {
            return Err("invalid verified storage body bound".into());
        }
        let (sender, receiver) = proof.consume()?;
        Ok(Self {
            sender,
            receiver,
            body,
        })
    }
}
/// Constructed only from an already verified peer frame. It is not a raw
/// digest supplied by a caller and has no deserializer/clone/raw constructor.
pub(crate) struct ReadChallenge {
    binding: String,
}
impl ReadChallenge {
    pub(crate) fn binding(&self) -> &str {
        &self.binding
    }
}

/// Protocol session only. It has no conversion to an agent intent, verified
/// worker mode, lifecycle receipt, mount or fence; wiring needs separate review.
pub(crate) struct ReceiverSession {
    spec: JobSpec,
    challenge: Uid,
    started: Instant,
    deadline: Instant,
    grant: Option<Uid>,
    next_sequence: u64,
    pending: Option<Pending>,
    closed: bool,
    gate: Arc<Mutex<BoundaryGate>>,
}
#[derive(Default)]
struct BoundaryGate {
    closed: bool,
    authorized: Option<(u64, Uid)>,
}
struct Pending {
    request: BoundaryRequest,
    hash: String,
    started: Instant,
}
pub(crate) struct OneBoundary {
    grant: Uid,
    sequence: u64,
    nonce: Uid,
    kind: Boundary,
    detail_sha256: String,
    deadline: Instant,
    gate: Arc<Mutex<BoundaryGate>>,
    consumed: bool,
}
impl OneBoundary {
    /// Consuming this token prevents a second local start, not cancellation or
    /// rollback of a syscall already entered. No physical worker consumes it yet.
    pub(crate) fn consume(self, kind: Boundary, detail_sha256: &str) -> Result<(), String> {
        self.consume_inner(kind, detail_sha256, Instant::now())
    }
    #[cfg(test)]
    fn consume_at(self, kind: Boundary, detail_sha256: &str, now: Instant) -> Result<(), String> {
        self.consume_inner(kind, detail_sha256, now)
    }
    fn consume_inner(
        mut self,
        kind: Boundary,
        detail_sha256: &str,
        now: Instant,
    ) -> Result<(), String> {
        let _lineage = (&self.grant, self.sequence, &self.nonce);
        let mut gate = self
            .gate
            .lock()
            .map_err(|_| "boundary revocation gate poisoned")?;
        if gate.closed
            || gate.authorized.as_ref() != Some(&(self.sequence, self.nonce.clone()))
            || self.kind != kind
            || self.detail_sha256 != detail_sha256
            || now >= self.deadline
        {
            gate.closed = true;
            return Err("single boundary expired or changed; no new storage action".into());
        }
        gate.authorized = None;
        self.consumed = true;
        Ok(())
    }
}
impl Drop for OneBoundary {
    fn drop(&mut self) {
        if !self.consumed {
            if let Ok(mut gate) = self.gate.lock() {
                gate.closed = true;
                gate.authorized = None;
            }
        }
    }
}
impl ReceiverSession {
    pub(crate) fn accepted_deadline(&self) -> Result<Instant, String> {
        self.accepted_deadline_at(Instant::now())
    }
    fn accepted_deadline_at(&self, now: Instant) -> Result<Instant, String> {
        if self.revoked() || self.grant.is_none() || now >= self.deadline {
            return Err("no current accepted original receiver deadline".into());
        }
        Ok(self.deadline)
    }
    /// Readiness hint only. Strict accept()/boundary_reply() still performs
    /// current Core verification and is the sole state/token transition.
    pub(crate) fn grant_wait_hint(
        &self,
        peer: &VerifiedPeerFrame,
    ) -> Result<(Revision, Instant), String> {
        self.grant_wait_hint_at(peer, Instant::now())
    }
    fn grant_wait_hint_at(
        &self,
        peer: &VerifiedPeerFrame,
        now: Instant,
    ) -> Result<(Revision, Instant), String> {
        let reply: GrantReply = decode(peer.body())?;
        let request = GrantRequest {
            version: 1,
            spec: self.spec.clone(),
            receiver_nonce: self.challenge.clone(),
        };
        let deadline = self
            .deadline
            .min(
                self.started
                    .checked_add(Duration::from_millis(MAX_BOUNDARY_MS))
                    .ok_or("original grant read deadline overflow")?,
            )
            .min(
                self.started
                    .checked_add(Duration::from_millis(
                        reply.remaining_ms.min(MAX_BOUNDARY_MS),
                    ))
                    .ok_or("grant remaining deadline overflow")?,
            );
        if self.revoked()
            || self.grant.is_some()
            || now < self.started
            || now >= deadline
            || peer.sender != self.spec.issuer_node_uid
            || peer.receiver != self.spec.target_node_uid
            || reply.version != 1
            || reply.spec != self.spec
            || reply.receiver_nonce != self.challenge
            || reply.request_sha256 != hash(&encode(&request)?)
            || reply.remaining_ms == 0
            || reply.remaining_ms > self.spec.maximum_duration_ms
            || !reply
                .confirmed_revision
                .at_least(&self.spec.issuer_revision)
        {
            return Err("invalid/late grant read synchronization hint".into());
        }
        Ok((reply.confirmed_revision, deadline))
    }
    pub(crate) fn boundary_wait_hint(
        &self,
        peer: &VerifiedPeerFrame,
    ) -> Result<(Revision, Instant), String> {
        self.boundary_wait_hint_at(peer, Instant::now())
    }
    fn boundary_wait_hint_at(
        &self,
        peer: &VerifiedPeerFrame,
        now: Instant,
    ) -> Result<(Revision, Instant), String> {
        let pending = self
            .pending
            .as_ref()
            .ok_or("no original pending boundary")?;
        let reply: BoundaryReply = decode(peer.body())?;
        let deadline = self.deadline.min(
            pending
                .started
                .checked_add(Duration::from_millis(MAX_BOUNDARY_MS))
                .ok_or("original boundary read deadline overflow")?,
        );
        if self.revoked()
            || now < pending.started
            || now >= deadline
            || peer.sender != self.spec.issuer_node_uid
            || peer.receiver != self.spec.target_node_uid
            || reply.version != 1
            || !reply.approved
            || Some(&reply.grant_uid) != self.grant.as_ref()
            || reply.job_uid != self.spec.job_uid
            || reply.sequence != pending.request.sequence
            || reply.nonce != pending.request.nonce
            || reply.request_sha256 != pending.hash
            || !reply
                .confirmed_revision
                .at_least(&pending.request.local_revision)
        {
            return Err("invalid/late boundary read synchronization hint".into());
        }
        Ok((reply.confirmed_revision, deadline))
    }
    pub(crate) fn accepted_cold_spec(&self) -> Result<&JobSpec, String> {
        if self.revoked()
            || self.grant.is_none()
            || self.spec.kind != JobKind::PrepareVirginOffline
            || Instant::now() >= self.deadline
        {
            return Err("no accepted current cold receiver session".into());
        }
        Ok(&self.spec)
    }
    pub(crate) fn accepted_init_spec(&self) -> Result<&JobSpec, String> {
        if self.revoked()
            || self.grant.is_none()
            || self.spec.kind != JobKind::InitializeVirginGeneration
            || self.spec.version != 2
            || self.spec.initialization.is_none()
            || Instant::now() >= self.deadline
        {
            return Err("no accepted exact distributed initialization session".into());
        }
        Ok(&self.spec)
    }
    fn close(&mut self) {
        self.closed = true;
        self.pending = None;
        if let Ok(mut gate) = self.gate.lock() {
            gate.closed = true;
            gate.authorized = None;
        }
    }
    fn revoked(&self) -> bool {
        self.closed || self.gate.lock().map_or(true, |g| g.closed)
    }
    pub(crate) fn challenge(
        spec: JobSpec,
        local: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<(Self, Vec<u8>), String> {
        spec.current(local, directory)?;
        if local.local_node_uid() != Some(&spec.target_node_uid)
            || local.actual_boot() != &spec.target_boot
        {
            return Err("grant challenge is not on exact target node/boot".into());
        }
        let challenge = Uid::new();
        let request = GrantRequest {
            version: 1,
            spec: spec.clone(),
            receiver_nonce: challenge.clone(),
        };
        let deadline = now
            .checked_add(Duration::from_millis(spec.maximum_duration_ms))
            .ok_or("job deadline overflow")?;
        Ok((
            Self {
                spec,
                challenge,
                started: now,
                deadline,
                grant: None,
                next_sequence: 1,
                pending: None,
                closed: false,
                gate: Arc::new(Mutex::new(BoundaryGate::default())),
            },
            encode(&request)?,
        ))
    }
    pub(crate) fn accept(
        &mut self,
        peer: VerifiedPeerFrame,
        local: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<(), String> {
        let result = (|| {
            if self.revoked()
                || self.grant.is_some()
                || now < self.started
                || now >= self.deadline
                || now.duration_since(self.started) > Duration::from_millis(MAX_BOUNDARY_MS)
                || peer.sender != self.spec.issuer_node_uid
                || peer.receiver != self.spec.target_node_uid
            {
                return Err("stale/replayed or wrong-peer storage grant".into());
            }
            let reply: GrantReply = decode(peer.body())?;
            let request = GrantRequest {
                version: 1,
                spec: self.spec.clone(),
                receiver_nonce: self.challenge.clone(),
            };
            if reply.version != 1
                || reply.spec != self.spec
                || reply.receiver_nonce != self.challenge
                || reply.request_sha256 != hash(&encode(&request)?)
                || reply.remaining_ms == 0
                || reply.remaining_ms > self.spec.maximum_duration_ms
                || !reply
                    .confirmed_revision
                    .at_least(&self.spec.issuer_revision)
                || !local.revision().at_least(&reply.confirmed_revision)
            {
                return Err("grant nonce/revision/deadline differs from exact challenge".into());
            }
            self.spec.current(local, directory)?;
            // Anchor to challenge START, never receipt time; network delay must
            // consume the budget. No sender wall clock can extend local access.
            self.deadline = self.deadline.min(
                self.started
                    .checked_add(Duration::from_millis(reply.remaining_ms))
                    .ok_or("grant deadline overflow")?,
            );
            if now >= self.deadline {
                return Err("grant arrived after fixed job deadline".into());
            }
            self.grant = Some(reply.grant_uid);
            Ok(())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub(crate) fn boundary(
        &mut self,
        kind: Boundary,
        detail_sha256: String,
        local: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<Vec<u8>, String> {
        if self.revoked()
            || self.pending.is_some()
            || self.gate.lock().map_or(true, |g| g.authorized.is_some())
            || now >= self.deadline
            || !kind.permits(self.spec.kind)
            || !valid_hash(&detail_sha256)
        {
            self.close();
            return Err("closed/overlapping/unapproved storage boundary".into());
        }
        if let Err(error) = self.spec.current(local, directory) {
            self.close();
            return Err(error);
        }
        let request = BoundaryRequest {
            version: 1,
            grant_uid: self.grant.clone().ok_or("grant not accepted")?,
            job_uid: self.spec.job_uid.clone(),
            sequence: self.next_sequence,
            nonce: Uid::new(),
            kind,
            detail_sha256,
            local_revision: local.revision().clone(),
        };
        let bytes = encode(&request)?;
        self.pending = Some(Pending {
            hash: hash(&bytes),
            request,
            started: now,
        });
        Ok(bytes)
    }
    pub(crate) fn boundary_reply(
        &mut self,
        peer: VerifiedPeerFrame,
        local: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<OneBoundary, String> {
        let result = (|| {
            let pending = self
                .pending
                .take()
                .ok_or("no outstanding exact storage boundary")?;
            if self.revoked()
                || now < pending.started
                || now >= self.deadline
                || now.duration_since(pending.started) > Duration::from_millis(MAX_BOUNDARY_MS)
                || peer.sender != self.spec.issuer_node_uid
                || peer.receiver != self.spec.target_node_uid
            {
                return Err("late or wrong-peer boundary approval".into());
            }
            let reply: BoundaryReply = decode(peer.body())?;
            if reply.version != 1
                || !reply.approved
                || Some(&reply.grant_uid) != self.grant.as_ref()
                || reply.job_uid != self.spec.job_uid
                || reply.sequence != pending.request.sequence
                || reply.nonce != pending.request.nonce
                || reply.request_sha256 != pending.hash
                || !reply
                    .confirmed_revision
                    .at_least(&pending.request.local_revision)
                || !local.revision().at_least(&reply.confirmed_revision)
            {
                return Err("denied/replayed/mismatched storage boundary".into());
            }
            self.spec.current(local, directory)?;
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or("storage sequence exhausted")?;
            {
                let mut gate = self
                    .gate
                    .lock()
                    .map_err(|_| "boundary revocation gate poisoned")?;
                if gate.closed || gate.authorized.is_some() {
                    return Err("revoked or overlapping unconsumed boundary".into());
                }
                gate.authorized = Some((reply.sequence, reply.nonce.clone()));
            }
            Ok(OneBoundary {
                grant: reply.grant_uid,
                sequence: reply.sequence,
                nonce: reply.nonce,
                kind: pending.request.kind,
                detail_sha256: pending.request.detail_sha256,
                deadline: self
                    .deadline
                    .min(pending.started + Duration::from_millis(MAX_BOUNDARY_MS)),
                gate: self.gate.clone(),
                consumed: false,
            })
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub(crate) fn transport_lost(&mut self) {
        self.close();
    }
}
impl Drop for ReceiverSession {
    fn drop(&mut self) {
        self.close();
    }
}

pub(crate) struct IssuerSession {
    spec: JobSpec,
    grant: Uid,
    deadline: Instant,
    next_sequence: u64,
    closed: bool,
}
impl IssuerSession {
    pub(crate) fn grant_bound(
        peer: VerifiedPeerFrame,
        observed: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<(Self, Vec<u8>), String> {
        Self::grant_bound_deadline(peer, observed, directory, now, None)
    }
    fn grant_bound_deadline(
        peer: VerifiedPeerFrame,
        observed: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
        original: Option<Instant>,
    ) -> Result<(Self, Vec<u8>), String> {
        let request: GrantRequest = decode(peer.body())?;
        let spec = &request.spec;
        spec.current(observed, directory)?;
        observed.require_fresh_issuer_for(&peer, now, Duration::from_millis(MAX_BOUNDARY_MS))?;
        if request.version != 1
            || peer.sender != spec.target_node_uid
            || peer.receiver != spec.issuer_node_uid
            || observed.local_node_uid() != Some(&spec.issuer_node_uid)
            || observed.actual_boot() != &spec.issuer_boot
        {
            return Err("grant did not reach exact current leader boot".into());
        }
        let grant = Uid::new();
        let (deadline, remaining_ms) =
            bounded_grant_deadline(now, spec.maximum_duration_ms, original)?;
        let reply = GrantReply {
            version: 1,
            grant_uid: grant.clone(),
            request_sha256: hash(peer.body()),
            receiver_nonce: request.receiver_nonce,
            issuer_nonce: Uid::new(),
            spec: spec.clone(),
            confirmed_revision: observed.revision().clone(),
            remaining_ms,
        };
        Ok((
            Self {
                spec: spec.clone(),
                grant,
                deadline,
                next_sequence: 1,
                closed: false,
            },
            encode(&reply)?,
        ))
    }
    pub(crate) fn approve_bound(
        &mut self,
        peer: VerifiedPeerFrame,
        observed: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<Vec<u8>, String> {
        let result = (|| {
            if self.closed
                || now >= self.deadline
                || peer.sender != self.spec.target_node_uid
                || peer.receiver != self.spec.issuer_node_uid
            {
                return Err("closed/expired/wrong-peer issuer session".into());
            }
            self.spec.current(observed, directory)?;
            observed.require_fresh_issuer_for(
                &peer,
                now,
                Duration::from_millis(MAX_BOUNDARY_MS),
            )?;
            if observed.local_node_uid() != Some(&self.spec.issuer_node_uid)
                || observed.actual_boot() != &self.spec.issuer_boot
            {
                return Err("issuer node/boot changed".into());
            }
            let request: BoundaryRequest = decode(peer.body())?;
            if request.version != 1
                || request.grant_uid != self.grant
                || request.job_uid != self.spec.job_uid
                || request.sequence != self.next_sequence
                || !request.kind.permits(self.spec.kind)
                || !valid_hash(&request.detail_sha256)
                || !request.local_revision.at_least(&self.spec.issuer_revision)
                || !observed.revision().at_least(&request.local_revision)
            {
                return Err("out-of-order/replayed/unapproved storage boundary".into());
            }
            self.next_sequence = self
                .next_sequence
                .checked_add(1)
                .ok_or("storage sequence exhausted")?;
            encode(&BoundaryReply {
                version: 1,
                grant_uid: self.grant.clone(),
                job_uid: self.spec.job_uid.clone(),
                sequence: request.sequence,
                nonce: request.nonce,
                request_sha256: hash(peer.body()),
                confirmed_revision: observed.revision().clone(),
                approved: true,
            })
        })();
        if result.is_err() {
            self.closed = true;
        }
        result
    }
    pub(crate) fn transport_lost(&mut self) {
        self.closed = true;
    }
}
fn bounded_grant_deadline(
    now: Instant,
    maximum_ms: u64,
    original: Option<Instant>,
) -> Result<(Instant, u64), String> {
    let limit = now
        .checked_add(Duration::from_millis(maximum_ms))
        .ok_or("issuer deadline overflow")?;
    let deadline = original.map_or(limit, |original| limit.min(original));
    let remaining_ms = u64::try_from(deadline.saturating_duration_since(now).as_millis())
        .map_err(|_| "issuer remaining budget overflow")?;
    if remaining_ms == 0 || remaining_ms > maximum_ms {
        return Err("original pipeline has no grant budget; never renew it".into());
    }
    Ok((deadline, remaining_ms))
}

/// Bounded admission metadata, NOT a second writer registry. Expiry, lost
/// transport or a new leader does not prove a node job drained. Retain closed
/// entries; no JSON close/delete/TTL method silently frees an unresolved slot.
pub(crate) struct IssuerBook {
    nodes: std::collections::BTreeMap<Uid, IssuerSession>,
}
impl IssuerBook {
    pub(crate) fn new() -> Self {
        Self {
            nodes: std::collections::BTreeMap::new(),
        }
    }
    pub(crate) fn grant(
        &mut self,
        peer: VerifiedPeerFrame,
        observed: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<Vec<u8>, String> {
        let node = peer.sender.clone();
        if self.nodes.len() >= MAX_DIRECTORY_NODES || self.nodes.contains_key(&node) {
            return Err("node has an unresolved storage job or issuer admission is full".into());
        }
        let (session, reply) = IssuerSession::grant_bound(peer, observed, directory, now)?;
        self.nodes.insert(node, session);
        Ok(reply)
    }
    pub(crate) fn boundary(
        &mut self,
        peer: VerifiedPeerFrame,
        observed: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<Vec<u8>, String> {
        self.nodes
            .get_mut(&peer.sender)
            .ok_or("unknown storage grant; no restore from wire JSON")?
            .approve_bound(peer, observed, directory, now)
    }
    pub(crate) fn transport_lost(&mut self, node: &Uid) {
        if let Some(session) = self.nodes.get_mut(node) {
            session.transport_lost();
        }
    }
    // Future release must consume independent exact-node/job/cgroup/lease drain
    // evidence, not elapsed time, quorum alone or a peer's unverified JSON.
}

/// Bounded phase sessions are retained by exact job UID, not overwritten as a
/// new grant for a still-unresolved node. At most two remote nodes x12 phases.
pub(crate) struct InitIssuerBook {
    jobs: std::collections::BTreeMap<Uid, IssuerSession>,
}
impl InitIssuerBook {
    pub(crate) fn new() -> Self {
        Self {
            jobs: std::collections::BTreeMap::new(),
        }
    }
    pub(crate) fn grant_expected(
        &mut self,
        expected: &crate::storage_driver::native_runtime::init::ExpectedInitJob,
        peer: VerifiedPeerFrame,
        observed: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<Vec<u8>, String> {
        expected.require_current(observed, directory)?;
        let request: GrantRequest = decode(peer.body())?;
        if request.spec != *expected.spec()
            || self.jobs.contains_key(&request.spec.job_uid)
            || self.jobs.len() >= MAX_DIRECTORY_NODES
        {
            return Err(
                "phase grant differs/repeats or retained session admission is exhausted".into(),
            );
        }
        let job = request.spec.job_uid.clone();
        let (session, reply) = IssuerSession::grant_bound_deadline(
            peer,
            observed,
            directory,
            now,
            Some(expected.deadline()),
        )?;
        self.jobs.insert(job, session);
        Ok(reply)
    }
    pub(crate) fn boundary_expected(
        &mut self,
        expected: &crate::storage_driver::native_runtime::init::ExpectedInitJob,
        peer: VerifiedPeerFrame,
        observed: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<Vec<u8>, String> {
        expected.require_current(observed, directory)?;
        let request: BoundaryRequest = decode(peer.body())?;
        if request.job_uid != expected.spec().job_uid {
            return Err("old phase cannot cross the current full expected job boundary".into());
        }
        self.jobs
            .get_mut(&request.job_uid)
            .ok_or("no live phase grant")?
            .approve_bound(peer, observed, directory, now)
    }
}

/// Live controller registration, never a wire/journal deserializer. Only an
/// acknowledged ProvisionIntent plus actual applied Core can create this value.
pub(crate) struct ExpectedColdJob {
    spec: JobSpec,
}
impl ExpectedColdJob {
    pub(crate) fn register(
        spec: JobSpec,
        intent: &crate::storage_controller::ProvisionIntent,
        core: &CoreObservation,
        directory: &VerifiedDirectory,
    ) -> Result<Self, String> {
        spec.current(core, directory)?;
        if spec.kind != JobKind::PrepareVirginOffline
            || !intent.matches(core.volume())
            || spec.owner != *intent.owner()
            || spec.operation_uid != *intent.operation_uid()
        {
            return Err("expected cold job lacks acknowledged exact reservation".into());
        }
        Ok(Self { spec })
    }
    pub(crate) fn spec(&self) -> &JobSpec {
        &self.spec
    }
    pub(crate) fn hash(&self) -> Result<String, String> {
        Ok(hash(&encode(&self.spec)?))
    }
    pub(crate) fn require_request(&self, peer: &VerifiedPeerFrame) -> Result<(), String> {
        let request: GrantRequest = decode(peer.body())?;
        if request.spec != self.spec {
            return Err("grant differs from full committed expected cold job".into());
        }
        Ok(())
    }
}
impl IssuerBook {
    pub(crate) fn grant_expected_deadline(
        &mut self,
        expected: &ExpectedColdJob,
        peer: VerifiedPeerFrame,
        core: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
        original: Instant,
    ) -> Result<Vec<u8>, String> {
        expected.require_request(&peer)?;
        let node = peer.sender.clone();
        if self.nodes.len() >= MAX_DIRECTORY_NODES || self.nodes.contains_key(&node) {
            return Err("node has an unresolved storage job or issuer admission is full".into());
        }
        let (session, reply) =
            IssuerSession::grant_bound_deadline(peer, core, directory, now, Some(original))?;
        self.nodes.insert(node, session);
        Ok(reply)
    }
    pub(crate) fn grant_expected(
        &mut self,
        expected: &ExpectedColdJob,
        peer: VerifiedPeerFrame,
        core: &CoreObservation,
        directory: &VerifiedDirectory,
        now: Instant,
    ) -> Result<Vec<u8>, String> {
        expected.require_request(&peer)?;
        self.grant(peer, core, directory, now)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeReadiness {
    pub(crate) version: u32,
    pub(crate) node_uid: Uid,
    pub(crate) boot: BootId,
    pub(crate) directory_sha256: String,
    pub(crate) pool_uid: Uid,
    pub(crate) pool_sha256: String,
    pub(crate) hostname: String,
    pub(crate) vg_name: String,
    pub(crate) free_bytes: u64,
    pub(crate) extent_bytes: u64,
    pub(crate) max_volume_bytes: u64,
    pub(crate) max_managed_bytes: u64,
    pub(crate) managed_bytes: u64,
    pub(crate) interface: String,
    pub(crate) minor_first: u16,
    pub(crate) minor_last: u16,
    pub(crate) port_first: u16,
    pub(crate) port_last: u16,
    pub(crate) available: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AppliedColdObservation {
    pub(crate) expected_spec_sha256: String,
    pub(crate) scope_sha256: String,
    pub(crate) revision: Revision,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum NodeJobRequest {
    InspectReadiness {
        nonce: Uid,
        expected: Option<JobSpec>,
    },
    OfferVirginOffline {
        spec: JobSpec,
        pool_sha256: String,
        plan: serde_json::Value,
    },
    InspectHeld {
        job_uid: Uid,
        spec_sha256: String,
    },
    ArmInitialization {
        nonce: Uid,
        prepare_job_uid: Uid,
        prepare_spec_sha256: String,
        generation: DataGeneration,
        remaining_budget_ms: u64,
    },
    InspectInitialization {
        nonce: Uid,
        spec: JobSpec,
    },
    OfferInitialization {
        spec: JobSpec,
    },
    InspectPhase {
        nonce: Uid,
        job_uid: Uid,
        spec_sha256: String,
    },
    AcknowledgeDetached {
        nonce: Uid,
        data_generation_uid: Uid,
        initialize_operation_uid: Uid,
        minimum_revision: Revision,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub(crate) enum NodeJobReply {
    Readiness {
        nonce: Uid,
        observation: NodeReadiness,
        applied: Option<AppliedColdObservation>,
    },
    Offered {
        job_uid: Uid,
        spec_sha256: String,
    },
    WorkingObservation {
        job_uid: Uid,
        spec_sha256: String,
    },
    Held {
        job_uid: Uid,
        spec_sha256: String,
        evidence_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reference: Option<VirginReplicaRef>,
    },
    Armed {
        nonce: Uid,
        prepare_job_uid: Uid,
        generation_sha256: String,
        reference: VirginReplicaRef,
    },
    InitializationReady {
        nonce: Uid,
        expected_spec_sha256: String,
        scope_sha256: String,
        revision: Revision,
    },
    PhaseComplete {
        nonce: Uid,
        job_uid: Uid,
        spec_sha256: String,
        observation: PhaseObservation,
        completion_sha256: String,
    },
    PhaseWorking {
        nonce: Uid,
        job_uid: Uid,
        spec_sha256: String,
    },
    DetachedAcknowledged {
        nonce: Uid,
        data_generation_uid: Uid,
        initialize_operation_uid: Uid,
        closeout_sha256: String,
    },
    Unknown {
        job_uid: Option<Uid>,
        code: String,
    },
}
pub(crate) fn encode_node<T: Serialize>(value: &T) -> Result<Vec<u8>, String> {
    encode(value)
}
pub(crate) fn decode_node<T: for<'a> Deserialize<'a>>(raw: &[u8]) -> Result<T, String> {
    decode(raw)
}

/// Inner purpose separation on top of node_rpc's signed/sealed request/response.
/// Only codecs, not authority constructors. HMAC alone proves cluster membership.
pub(crate) fn seal_protocol_frame(plain: &[u8]) -> Result<Vec<u8>, String> {
    if plain.is_empty() || plain.len() > MAX_FRAME_BYTES {
        return Err("invalid storage frame bound".into());
    }
    crate::auth::seal_for_cluster(DOMAIN, plain).map(String::into_bytes)
}
pub(crate) fn open_protocol_frame(sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() > 64 * 1024 {
        return Err("sealed storage frame exceeds bound".into());
    }
    let value = std::str::from_utf8(sealed).map_err(|_| "invalid storage sealed frame")?;
    let plain = crate::auth::unseal_for_cluster(DOMAIN, value)?;
    if plain.is_empty() || plain.len() > MAX_FRAME_BYTES {
        return Err("unsealed storage frame exceeds bound".into());
    }
    Ok(plain)
}

#[cfg(test)]
#[path = "storage_remote_protocol_tests.rs"]
mod tests;

