//! Fixed-worker process boundary with separate local and remote cold parents.
//! Required cgroup-v2 population barrier + inherited node lock. No raw JSON
//! grant constructor, follower-to-local fallback, tunnel or writer receipt.
use super::{
    agent::NativeAgent, job_cgroup::JobCgroup, live_authority as live, private_fs::Dir, process,
};
#[path = "cold_authority.rs"]
mod cold_authority;
#[path = "remote_cold_authority.rs"]
pub(crate) mod remote_cold_authority;
pub(crate) use remote_cold_authority::RemoteColdParent;
#[path = "dispatcher_init.rs"]
pub(crate) mod distributed_init;
#[path = "init_authority.rs"]
pub(crate) mod init_authority;
#[path = "dispatcher_attach.rs"]
pub(crate) mod attachment;
use crate::reconcile::DesiredWorld;
use crate::storage_controller::{ProvisionIntent, ReplicaAgent};
use crate::storage_identity::Uid;
pub(crate) use distributed_init::VerifiedDistributedInitPhase;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, RwLock,
};
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 1024 * 1024;
const CAPSULE_LIMIT: u64 = 64 * 1024;
const REAP_GRACE: Duration = Duration::from_secs(2);

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone)]
pub(crate) struct Config {
    pub journal_root: PathBuf,
    pub delegated_cgroup_root: PathBuf,
    pub node_uid: Uid,
    pub helper_image: PathBuf,
    pub helper_sha256: String,
    pub deadline: Duration,
    pub budget: super::ResourceBudget,
}

#[derive(Clone, Copy)]
pub(crate) enum Replay {
    NewOnly,
    ResumeExact,
}
#[derive(Debug)]
pub(crate) enum Outcome {
    CompletedDiagnostics {
        stdout: Vec<u8>,
        stderr_sha256: String,
        retained_lease: Option<File>,
    },
    ColdPreparedHeld {
        held: ColdPreparedHeld,
    },
    Unknown {
        reason: String,
    },
}
/// Exact completed cold job still owns node admission/kernel lock. Diagnostic
/// bytes are NOT a VirginReplica/VerifiedVirginSet or a lifecycle/fence receipt.
pub(crate) struct ColdPreparedHeld {
    identity: live::JobIdentity,
    raw: Vec<u8>,
    reservation: RetainedNodeAdmission,
    cancelled: Arc<AtomicBool>,
    intent: ProvisionIntent,
    world: Arc<RwLock<DesiredWorld>>,
    expected_pool: Uid,
    expected_plan_sha256: String,
    agent: NativeAgent,
}
impl std::fmt::Debug for ColdPreparedHeld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ColdPreparedHeld")
            .field("identity", &self.identity)
            .field("attestation_sha256", &hash(&self.raw))
            .finish()
    }
}
impl ColdPreparedHeld {
    pub(crate) fn diagnostics(&self) -> Result<&[u8], String> {
        self.intent.check_current(&self.world)?;
        if self.reservation.lease.is_none() || self.cancelled.load(Ordering::Acquire) {
            return Err("cold node reservation no longer held or cancelled".into());
        }
        Ok(&self.raw)
    }
}
struct RetainedNodeAdmission {
    lease: Option<File>,
    busy: Arc<AtomicBool>,
    release_on_drop: bool,
}
impl Drop for RetainedNodeAdmission {
    fn drop(&mut self) {
        drop(self.lease.take());
        if self.release_on_drop {
            self.busy.store(false, Ordering::Release);
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum ExtendedJob {
    PrepareVirginOffline,
    InitializeReserved,
    InitializeDistributed,
    AttachEpochOne,
    TerminateManaged,
    AttachWithOwnedInventory,
}
/// Only exact dispatcher/control code constructs this; never Deserialize.
pub(crate) struct VerifiedLocalBoundary {
    binding: String,
    native_identity:live::JobIdentity,
}
impl VerifiedLocalBoundary {
    fn owned_inventory_completion(identity:&live::JobIdentity,record:&Record,raw:&[u8])->Result<Self,String>{
        if record.version!=7||record.state!=State::Complete||&record.identity!=identity
            ||!record.resources_final.as_ref().is_some_and(|r|r.pids_current==0){return Err("profile7 completion lacks actual original child/resource drain".into());}
        Ok(Self{native_identity:identity.clone(),binding:hash(&serde_json::to_vec(&("actual-owned-inventory-attach-completed-v7",identity,record,hash(raw)))
            .map_err(|_|"actual profile7 completion binding")?)})
    }
    fn terminal_completion(identity:&live::JobIdentity,record:&Record,raw:&[u8])->Result<Self,String>{
        if record.version!=6||record.state!=State::Complete||&record.identity!=identity
            ||!record.resources_final.as_ref().is_some_and(|r|r.pids_current==0){
            return Err("terminal completion lacks actual v6 same-child/cgroup drain".into());
        }
        Ok(Self{native_identity:identity.clone(),binding:hash(&serde_json::to_vec(&(
            "actual-terminal-completed-v6",identity,record,hash(raw))).map_err(|_|"actual terminal completion binding failed")?)})
    }
    fn terminal_observation(identity:&live::JobIdentity,record:&Record,raw:&[u8],detail:&str)->Result<Self,String>{
        let completed=Self::terminal_completion(identity,record,raw)?;
        if !valid_hash(detail){return Err("terminal post-drain observation detail malformed".into());}
        Ok(Self{native_identity:identity.clone(),binding:hash(&serde_json::to_vec(&(
            "actual-terminal-post-drain-v6",completed.binding(),detail,Uid::new())).map_err(|_|"terminal post-drain binding failed")?)})
    }
    fn attachment_observation(identity:&live::JobIdentity)->Result<Self,String> {
        let nonce=Uid::new();
        Ok(Self {native_identity:identity.clone(),binding:hash(&serde_json::to_vec(&(
            "actual-watch-attach-observation-v5",identity,nonce))
            .map_err(|_|"cannot bind actual Watch observation")?)})
    }
    fn attachment_completion(identity:&live::JobIdentity,record:&Record,raw:&[u8])->Result<Self,String> {
        if record.version!=5 || record.state!=State::Complete || &record.identity!=identity
            || !record.resources_final.as_ref().is_some_and(|r|r.pids_current==0) {
            return Err("attach completion lacks actual v5 same-child/cgroup drain".into());
        }
        Ok(Self {native_identity:identity.clone(),binding:hash(&serde_json::to_vec(&(
            "actual-attach-completed-v5",identity,record,hash(raw)))
            .map_err(|_|"cannot bind actual attach drain")?)})
    }
    fn new(request: &live::Request, expected: &live::JobIdentity) -> Result<Self, String> {
        if request.version != 1
            || request.sequence == 0
            || &request.identity != expected
            || !valid_hash(&request.detail_sha256)
        {
            return Err("invalid exact local init boundary".into());
        }
        Ok(Self {
            native_identity:expected.clone(),
            binding: hash(
                &serde_json::to_vec(&(
                    "native-init-boundary-v2",
                    expected,
                    request.sequence,
                    &request.nonce,
                    &request.boundary,
                    &request.detail_sha256,
                ))
                .map_err(|_| "cannot bind native boundary")?,
            ),
        })
    }
    pub(crate) fn binding(&self) -> &str {
        &self.binding
    }
    /// Pure same-launched-attempt comparison. The field is set only by the
    /// actual private request/drain producers; hashes/domains are unchanged.
    pub(in crate::storage_driver) fn require_native_identity(&self,expected:&live::JobIdentity)->Result<(),String> {
        if &self.native_identity!=expected {return Err("boundary is not this actual native attempt".into());}Ok(())
    }
    fn cold(request: &live::Request, expected: &live::JobIdentity) -> Result<Self, String> {
        let original = Self::new(request, expected)?;
        Ok(Self {
            native_identity:original.native_identity,
            binding: hash(
                &serde_json::to_vec(&("native-cold-boundary-v2", original.binding))
                    .map_err(|_| "cannot bind cold boundary")?,
            ),
        })
    }
    /// Private dispatcher call site only, after successful exit, empty actual
    /// cgroup, resource closeout and durable Complete record. Not a JSON proof.
    fn cold_completion(
        identity: &live::JobIdentity,
        record: &Record,
        stdout: &[u8],
    ) -> Result<Self, String> {
        if ![2, 3].contains(&record.version)
            || record.state != State::Complete
            || &record.identity != identity
            || !record
                .resources_final
                .as_ref()
                .is_some_and(|r| r.pids_current == 0)
        {
            return Err("cold completion lacks exact successful resource closeout".into());
        }
        Ok(Self {
            native_identity:identity.clone(),
            binding: hash(
                &serde_json::to_vec(&("native-cold-completed-v2", identity, record, hash(stdout)))
                    .map_err(|_| "cannot bind completed cold worker")?,
            ),
        })
    }
    fn initialization_completion(
        identity: &live::JobIdentity,
        record: &Record,
        stdout: &[u8],
    ) -> Result<Self, String> {
        if record.version != 4
            || record.state != State::Complete
            || &record.identity != identity
            || !record
                .resources_final
                .as_ref()
                .is_some_and(|resource| resource.pids_current == 0)
        {
            return Err("initialization completion lacks actual exact successful drain".into());
        }
        Ok(Self {
            native_identity:identity.clone(),
            binding: hash(
                &serde_json::to_vec(&(
                    "native-initialization-completed-v4",
                    identity,
                    record,
                    hash(stdout),
                ))
                .map_err(|_| "cannot bind phase drain completion")?,
            ),
        })
    }
}
pub(crate) struct Ticket {
    receiver: mpsc::Receiver<Outcome>,
    cancelled: Arc<AtomicBool>,
}
impl Ticket {
    /// Exact ticket only; cancellation is not a no-effect/rollback guarantee.
    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
    pub(crate) fn try_result(&self) -> Result<Option<Outcome>, String> {
        match self.receiver.try_recv() {
            Ok(v) => Ok(Some(v)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(_) => Err("storage supervisor disconnected; outcome UNKNOWN".into()),
        }
    }
}
struct Work {
    world: Arc<RwLock<DesiredWorld>>,
    intent: ProvisionIntent,
    agent: NativeAgent,
    replay: Replay,
    result: mpsc::SyncSender<Outcome>,
    cancelled: Arc<AtomicBool>,
    extended: Option<ExtendedJob>,
    busy: Arc<AtomicBool>,
    remote: Option<RemoteColdParent>,
    runtime: bool,
    runtime_check: Option<Arc<super::native_runtime::Shared>>,
}
enum WorkItem {
    Preparation(Work),
    Initialization(distributed_init::InitializationWork),
    Attachment(attachment::AttachmentWork),
    Terminal(attachment::terminal::TerminalWork),
    TerminalRetire(attachment::terminal::TerminalRetirementWork),
}
pub(crate) struct Dispatcher {
    queue: mpsc::SyncSender<WorkItem>,
    busy: Arc<AtomicBool>,
    policy_sha256:String,
}

impl Dispatcher {
    pub(crate) fn start(config: Config) -> Result<Self, String> {
        config.budget.validate()?;
        if !valid_hash(&config.helper_sha256)
            || config.deadline.is_zero()
            || config.deadline > Duration::from_secs(900)
        {
            return Err("invalid pinned storage dispatcher policy".into());
        }
        let (send, receive) = mpsc::sync_channel::<WorkItem>(1);
        let policy_sha256=attachment::terminal::config_fingerprint(&config)?;
        let busy = Arc::new(AtomicBool::new(false));
        let held = busy.clone();
        std::thread::Builder::new()
            .name("royak-storage-dispatch".into())
            .spawn(move || {
                while let Ok(item) = receive.recv() {
                    let item=match item {
                        WorkItem::Attachment(mut work)=>{attachment::run_work(&config,&mut work);continue;},
                        WorkItem::Terminal(mut work)=>{attachment::terminal::run_work(&config,&mut work);continue;},
                        WorkItem::TerminalRetire(mut work)=>{attachment::terminal::run_retirement(&mut work);continue;},
                        other=>other,
                    };
                    let WorkItem::Preparation(mut work) = item else {
                        if let WorkItem::Initialization(mut init) = item {
                            let (result, quarantine) =
                                distributed_init::run_phase(&config, &mut init);
                            let _ = init.result.try_send(result);
                            if let Some(quarantine) = quarantine {
                                quarantine.wait_until_empty();
                            }
                        }
                        continue;
                    };
                    match run_native(&config, &mut work) {
                        Ok((outcome, quarantine)) => {
                            let retained = matches!(outcome, Outcome::ColdPreparedHeld { .. });
                            let _ = work.result.try_send(outcome);
                            // No replacement worker/thread is created. D-state or
                            // uncertain descendants retain this one admission slot.
                            if let Some(q) = quarantine {
                                q.wait_until_empty();
                            }
                            if retained {
                                continue;
                            }
                        }
                        Err(reason) => {
                            let _ = work.result.try_send(Outcome::Unknown { reason });
                        }
                    }
                    if !work.runtime {
                        held.store(false, Ordering::Release);
                    }
                    // Normal runtime is one-shot. UNKNOWN never resets admission.
                }
            })
            .map_err(|_| "cannot start fixed storage supervisor")?;
        Ok(Self { queue: send, busy,policy_sha256 })
    }
    /// No filesystem IO, waiting, spawn_blocking or thread creation on caller.
    pub(crate) fn submit_secondary(
        &self,
        world: Arc<RwLock<DesiredWorld>>,
        intent: ProvisionIntent,
        agent: NativeAgent,
        replay: Replay,
    ) -> Result<Ticket, String> {
        self.submit(world, intent, agent, replay, None)
    }
    /// Separate cold preparation. Never runs Online/up and never returns a
    /// Core proof from stdout. Held result retains this node's exact lease.
    pub(crate) fn submit_virgin_offline(
        &self,
        world: Arc<RwLock<DesiredWorld>>,
        intent: ProvisionIntent,
        agent: NativeAgent,
        replay: Replay,
    ) -> Result<Ticket, String> {
        self.submit(
            world,
            intent,
            agent,
            replay,
            Some(ExtendedJob::PrepareVirginOffline),
        )
    }
    fn submit(
        &self,
        world: Arc<RwLock<DesiredWorld>>,
        intent: ProvisionIntent,
        agent: NativeAgent,
        replay: Replay,
        extended: Option<ExtendedJob>,
    ) -> Result<Ticket, String> {
        self.submit_authorized(world, intent, agent, replay, extended, None, false, None)
    }
    pub(crate) fn busy(&self) -> bool {
        self.busy.load(Ordering::Acquire)
    }
    pub(crate) fn submit_runtime_local(
        &self,
        world: Arc<RwLock<DesiredWorld>>,
        intent: ProvisionIntent,
        agent: NativeAgent,
        check: Arc<super::native_runtime::Shared>,
    ) -> Result<Ticket, String> {
        self.submit_authorized(
            world,
            intent,
            agent,
            Replay::NewOnly,
            Some(ExtendedJob::PrepareVirginOffline),
            None,
            true,
            Some(check),
        )
    }
    pub(crate) fn submit_runtime_remote(
        &self,
        parent: RemoteColdParent,
        agent: NativeAgent,
    ) -> Result<Ticket, String> {
        let world = parent.world();
        let intent = parent.intent().clone();
        self.submit_authorized(
            world,
            intent,
            agent,
            Replay::NewOnly,
            Some(ExtendedJob::PrepareVirginOffline),
            Some(parent),
            true,
            None,
        )
    }
    fn submit_authorized(
        &self,
        world: Arc<RwLock<DesiredWorld>>,
        intent: ProvisionIntent,
        agent: NativeAgent,
        replay: Replay,
        extended: Option<ExtendedJob>,
        remote: Option<RemoteColdParent>,
        runtime: bool,
        runtime_check: Option<Arc<super::native_runtime::Shared>>,
    ) -> Result<Ticket, String> {
        let actual = runtime_check
            .as_ref()
            .map(|shared| shared.runtime_cancellation())
            .or_else(|| {
                remote
                    .as_ref()
                    .map(|parent| parent.lease_owner().runtime_cancellation())
            });
        let cancelled = cancellation_for_runtime(runtime, actual)?;
        self.busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| "one exact storage node job is already active/quarantined; no queue")?;
        let (send, receive) = mpsc::sync_channel(1);
        if self
            .queue
            .try_send(WorkItem::Preparation(Work {
                world,
                intent,
                agent,
                replay,
                result: send,
                cancelled: cancelled.clone(),
                extended,
                busy: self.busy.clone(),
                remote,
                runtime,
                runtime_check,
            }))
            .is_err()
        {
            self.busy.store(false, Ordering::Release);
            return Err("fixed storage supervisor unavailable; no job admitted".into());
        }
        Ok(Ticket {
            receiver: receive,
            cancelled,
        })
    }
}
fn cancellation_for_runtime(
    runtime: bool,
    shared: Option<Arc<AtomicBool>>,
) -> Result<Arc<AtomicBool>, String> {
    if runtime {
        let actual = shared.ok_or("normal runtime has no actual shared cancellation scope")?;
        if actual.load(Ordering::Acquire) {
            return Err("normal runtime is already UNKNOWN".into());
        }
        Ok(actual)
    } else {
        Ok(Arc::new(AtomicBool::new(false)))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    config: serde_json::Value,
    plan: serde_json::Value,
    projection: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extended: Option<ExtendedJob>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dataset_uid: Option<Uid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    remote_binding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    initialization: Option<crate::storage_lifecycle::generation::physical::ExpectedInitScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    worker_remaining_ms: Option<u64>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capsule {
    version: u32,
    identity: live::JobIdentity,
    payload: Payload,
    budget: super::ResourceBudget,
}
fn valid_capsule_profile(capsule: &Capsule) -> bool {
    if capsule.version==7{return attachment::inventory::valid_capsule(capsule);}
    if capsule.version==6{return attachment::terminal::valid_capsule(capsule);}
    if capsule.version==5 {return attachment::valid_capsule(capsule);}
    if capsule.version == 4 {
        return capsule.payload.extended == Some(ExtendedJob::InitializeDistributed)
            && capsule
                .payload
                .initialization
                .as_ref()
                .is_some_and(|scope| {
                    scope.validate().is_ok()
                        && capsule.payload.dataset_uid.as_ref() == Some(&scope.generation.uid)
                        && capsule.identity.node_uid == scope.target_node_uid
                        && capsule.identity.boot_id == scope.target_boot.as_str()
                        && capsule.identity.volume_uid == scope.owner.volume_uid
                        && capsule.identity.operation_uid
                            == scope.generation.initialize_operation_uid
                })
            && capsule
                .payload
                .worker_remaining_ms
                .is_some_and(|remaining| {
                    remaining > 0
                        && capsule
                            .payload
                            .initialization
                            .as_ref()
                            .is_some_and(|scope| remaining <= scope.remaining_budget_ms)
                })
            && capsule
                .payload
                .remote_binding
                .as_deref()
                .is_some_and(valid_hash);
    }
    if capsule.payload.initialization.is_some() || capsule.payload.worker_remaining_ms.is_some() {
        return false;
    }
    if capsule.version == 3 {
        return capsule.payload.extended == Some(ExtendedJob::PrepareVirginOffline)
            && capsule.payload.dataset_uid.is_none()
            && capsule
                .payload
                .remote_binding
                .as_deref()
                .is_some_and(valid_hash);
    }
    if capsule.payload.remote_binding.is_some() {
        return false;
    }
    match (
        capsule.version,
        capsule.payload.extended,
        capsule.payload.dataset_uid.as_ref(),
    ) {
        (1, None, None) | (2, Some(ExtendedJob::PrepareVirginOffline), None) => true,
        (2, Some(ExtendedJob::InitializeReserved), Some(_)) => true,
        _ => false,
    }
}
#[derive(Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum State {
    LaunchIntent,
    Unknown,
    Complete,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    identity: live::JobIdentity,
    payload_sha256: String,
    image_sha256: String,
    state: State,
    resources_start: super::job_cgroup::ResourceSnapshot,
    resources_final: Option<super::job_cgroup::ResourceSnapshot>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    sha256: String,
    record: Record,
}
fn load_record(raw: &[u8]) -> Result<Record, String> {
    let envelope: Envelope =
        serde_json::from_slice(raw).map_err(|_| "corrupt exact dispatch envelope")?;
    if envelope.version != 1
        || hash(
            &serde_json::to_vec(&envelope.record).map_err(|_| "invalid dispatch checksum input")?,
        ) != envelope.sha256
    {
        return Err("dispatch checksum/version mismatch; never replace/adopt".into());
    }
    let record = &envelope.record;
    if ![1, 2, 3, 4, 5, 6, 7].contains(&record.version)
        || !valid_hash(&record.identity.binding_sha256)
        || !valid_hash(&record.image_sha256)
        || !valid_hash(&record.payload_sha256)
        || !crate::storage_lifecycle::valid_uuid(&record.identity.boot_id)
    {
        return Err("invalid exact dispatch lineage".into());
    }
    record.resources_start.budget.validate()?;
    if record.state == State::Complete {
        let end = record
            .resources_final
            .as_ref()
            .ok_or("Complete dispatch lacks actual resource closeout")?;
        if end.budget != record.resources_start.budget
            || end.pids_current != 0
            || end.cpu_usage_us < record.resources_start.cpu_usage_us
            || end.cpu_user_us < record.resources_start.cpu_user_us
            || end.cpu_system_us < record.resources_start.cpu_system_us
        {
            return Err("Complete dispatch resource lineage is inconsistent".into());
        }
    }
    Ok(envelope.record)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CgroupBinding {
    version: u32,
    node_uid: Uid,
    boot_id: String,
    device: u64,
    inode: u64,
}

/// A private inherited descriptor/nonce/cgroup verification result, never
/// Deserialize or a caller-provided world snapshot masquerading as authority.
pub(crate) struct VerifiedNativeAuthority {
    capsule: Capsule,
    _lease: File,
    _capsule_file: File,
}
/// Not Deserialize/Serialize and no raw-fields constructor outside this module.
/// Only a verified inherited launch can mint the physical NativeAgent mode.
#[derive(Clone)]
pub(super) struct VerifiedWorkerMode {
    identity: live::JobIdentity,
    extended: Option<ExtendedJob>,
    dataset_uid: Option<Uid>,
}
impl VerifiedWorkerMode {
    /// Separate operation identity; a Secondary preparation launch cannot
    /// reuse its capability for filesystem initialization.
    pub(super) fn check_initialization(
        &self,
        intent: &crate::storage_lifecycle::generation::InitializationIntent,
    ) -> Result<(), String> {
        if self.extended != Some(ExtendedJob::InitializeReserved)
            || self.dataset_uid.as_ref() != Some(&intent.generation().uid)
        {
            return Err(
                "initialization requires an exact separate v2 kind and dataset binding".into(),
            );
        }
        if self.identity.volume_uid != intent.owner().volume_uid
            || self.identity.operation_uid != *intent.operation_uid()
        {
            return Err(
                "verified worker does not own this dataset initialization operation".into(),
            );
        }
        let boot = crate::storage_boot::BootId::current()?;
        if boot.as_str() != self.identity.boot_id {
            return Err("initializer worker boot changed".into());
        }
        intent.local_initializer(&self.identity.node_uid, &boot)?;
        live::require_identity(&self.identity)
    }
    pub(super) fn check(&self, intent: &ProvisionIntent) -> Result<(), String> {
        if self.extended.is_some() || self.dataset_uid.is_some() {
            return Err("cold worker cannot run the historical online Secondary flow".into());
        }
        self.check_preparation_binding(intent)
    }
    pub(super) fn check_virgin(&self, intent: &ProvisionIntent) -> Result<(), String> {
        if self.extended != Some(ExtendedJob::PrepareVirginOffline) || self.dataset_uid.is_some() {
            return Err("only exact cold-worker kind may prepare a virgin offline replica".into());
        }
        self.check_preparation_binding(intent)
    }
    fn check_preparation_binding(&self, intent: &ProvisionIntent) -> Result<(), String> {
        if self.identity.volume_uid != intent.owner().volume_uid
            || self.identity.operation_uid != *intent.operation_uid()
            || !intent.targets().iter().any(|t| {
                t.node_uid == self.identity.node_uid && t.boot_id.as_str() == self.identity.boot_id
            })
        {
            return Err("verified worker mode is for another immutable job".into());
        }
        live::require_identity(&self.identity)
    }
}
impl VerifiedNativeAuthority {
    pub(super) fn worker_mode(&self) -> VerifiedWorkerMode {
        VerifiedWorkerMode {
            identity: self.capsule.identity.clone(),
            extended: self.capsule.payload.extended,
            dataset_uid: self.capsule.payload.dataset_uid.clone(),
        }
    }
    pub(crate) fn projection_bytes(&self) -> &[u8] {
        &self.capsule.payload.projection
    }
    pub(super) fn config(&self) -> &serde_json::Value {
        &self.capsule.payload.config
    }
    pub(super) fn plan(&self) -> &serde_json::Value {
        &self.capsule.payload.plan
    }
    pub(crate) fn matches_intent(&self, intent: &ProvisionIntent) -> bool {
        let id = &self.capsule.identity;
        self.capsule.version!=5 && self.capsule.version!=6 && self.capsule.version!=7
            && self.capsule.payload.extended != Some(ExtendedJob::InitializeReserved)
            && id.volume_uid == intent.owner().volume_uid
            && id.operation_uid == *intent.operation_uid()
            && intent
                .targets()
                .iter()
                .any(|t| t.node_uid == id.node_uid && t.boot_id.as_str() == id.boot_id)
    }
    pub(super) fn is_cold(&self) -> bool {
        self.capsule.payload.extended == Some(ExtendedJob::PrepareVirginOffline)
    }
    pub(crate) fn matches_initialization(
        &self,
        intent: &crate::storage_lifecycle::generation::InitializationIntent,
    ) -> bool {
        let id = &self.capsule.identity;
        self.capsule.version == 2
            && self.capsule.payload.extended == Some(ExtendedJob::InitializeReserved)
            && self.capsule.payload.dataset_uid.as_ref() == Some(&intent.generation().uid)
            && id.volume_uid == intent.owner().volume_uid
            && id.operation_uid == *intent.operation_uid()
            && id.node_uid == intent.generation().initializer_node_uid
            && intent
                .generation()
                .virgin_replicas
                .iter()
                .any(|f| f.node_uid == id.node_uid && f.node_boot_id.as_str() == id.boot_id)
    }
}

fn authoritative() -> bool {
    if crate::raft_node::is_clustered() {
        crate::raft_node::is_cluster_scheduler()
    } else {
        crate::store::owns_state()
    }
}

fn run_native(config: &Config, work: &mut Work) -> Result<(Outcome, Option<Quarantine>), String> {
    let dispatch_started = Instant::now();
    let is_cold = work.extended == Some(ExtendedJob::PrepareVirginOffline);
    let mut remote_parent = work.remote.take();
    let runtime_check = work.runtime_check.clone();
    if remote_parent.is_some() && (!is_cold || !work.runtime) {
        return Err("remote authority is cold runtime only".into());
    }
    if is_cold {
        cold_authority::require_actual_cluster_world(&work.world)?;
    }
    if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
        return Err(
            "production storage process dispatcher requires Linux root; no fallback".into(),
        );
    }
    if remote_parent.is_none() && !authoritative() {
        return Err("original storage issuer no longer owns state/quorum authority".into());
    }
    if work.cancelled.load(Ordering::Acquire) {
        return Err("dispatch cancelled before launch; intent remains unacknowledged".into());
    }
    let (node, boot, pool, plan, projection) =
        work.agent.helper_parts(&work.intent, &work.world)?;
    if node != config.node_uid {
        return Err("native helper node does not match dispatcher ownership".into());
    }
    let payload = Payload {
        config: pool,
        plan,
        projection,
        extended: work.extended,
        dataset_uid: None,
        remote_binding: remote_parent.as_ref().map(|p| p.binding()).transpose()?,
        initialization: None,
        worker_remaining_ms: None,
    };
    let payload_hash =
        hash(&serde_json::to_vec(&payload).map_err(|_| "cannot bind native helper payload")?);
    let binding = hash(
        &serde_json::to_vec(&(
            &node,
            &boot,
            work.intent.owner(),
            work.intent.operation_uid(),
            &payload_hash,
            &config.helper_sha256,
            &config.budget,
        ))
        .map_err(|_| "cannot bind native helper job")?,
    );
    let dirpath = config.journal_root.join(node.as_str());
    let dir = Dir::open(&dirpath, true)?;
    let lease = dir.lock()?;
    let lease_owner = remote_parent
        .as_ref()
        .map(|p| p.lease_owner())
        .or_else(|| runtime_check.clone());
    let safety_lease = lease_owner
        .map(|owner| {
            lease.try_clone().map(|lease| RuntimeSafetyLease {
                lease: Some(lease),
                owner,
            })
        })
        .transpose()
        .map_err(|_| "cannot retain runtime unknown node reservation")?;
    let entries = dir.bounded_entries(512)?;
    if entries.iter().filter(|s| s.starts_with("attempt-")).count() >= 128 {
        return Err("128 immutable helper attempts retained; explicit review/retention required, no auto-delete".into());
    }
    let cgroup = JobCgroup::open(&config.delegated_cgroup_root, node.as_str())?;
    let (device, inode) = cgroup.identity()?;
    match dir.read("cgroup-binding.json")? {
        Some(raw) => {
            let old: CgroupBinding =
                serde_json::from_slice(&raw).map_err(|_| "corrupt cgroup ownership binding")?;
            if old.version != 1
                || old.node_uid != node
                || old.boot_id != boot
                || old.device != device
                || old.inode != inode
            {
                return Err(
                    "owned cgroup boot/inode identity changed; explicit recovery required".into(),
                );
            }
        }
        None if cgroup.newly_created() => dir.write(
            "cgroup-binding.json",
            &serde_json::to_vec(&CgroupBinding {
                version: 1,
                node_uid: node.clone(),
                boot_id: boot.clone(),
                device,
                inode,
            })
            .map_err(|_| "cannot bind cgroup ownership")?,
        )?,
        None => {
            return Err("existing cgroup without private ownership record is never adopted".into())
        }
    }
    if cgroup.populated()? {
        return Err(
            "owned node job cgroup is still populated; UNKNOWN, never overlap/restart".into(),
        );
    }
    cgroup.prune_empty_command_scopes()?;
    if let Some(old) = dir.read("current.json")? {
        let old = load_record(&old)?;
        if old.identity.node_uid != node || old.identity.boot_id != boot {
            return Err(
                "previous node-job boot/identity differs; explicit recovery required".into(),
            );
        }
        if ![1, 2, 3].contains(&old.version)
            || !valid_hash(&old.payload_sha256)
            || !valid_hash(&old.image_sha256)
        {
            return Err("invalid dispatch journal".into());
        }
        if old.state != State::Complete
            && (old.identity.binding_sha256 != binding || matches!(work.replay, Replay::NewOnly))
        {
            return Err("previous dispatch is UNKNOWN; only explicit same-binding reconciliation may resume".into());
        }
    }
    let resources_start = cgroup.enforce_budget(&config.budget)?;
    let identity = live::JobIdentity {
        node_uid: node,
        boot_id: boot,
        volume_uid: work.intent.owner().volume_uid.clone(),
        operation_uid: work.intent.operation_uid().clone(),
        attempt_uid: Uid::new(),
        binding_sha256: binding,
    };
    let capsule = Capsule {
        version: if remote_parent.is_some() {
            3
        } else if work.extended.is_some() {
            2
        } else {
            1
        },
        identity: identity.clone(),
        payload,
        budget: config.budget.clone(),
    };
    let bytes =
        serde_json::to_vec(&capsule).map_err(|_| "cannot encode bounded native helper capsule")?;
    if bytes.len() as u64 > CAPSULE_LIMIT {
        return Err("storage-only helper capsule exceeds bound".into());
    }
    let filename = format!("capsule-{}.json", identity.attempt_uid.as_str());
    dir.write(&filename, &bytes)?;
    let capsule_file = open_private(&dirpath.join(&filename))?;
    let mut record = Record {
        version: if remote_parent.is_some() {
            3
        } else if work.extended.is_some() {
            2
        } else {
            1
        },
        identity: identity.clone(),
        payload_sha256: payload_hash,
        image_sha256: config.helper_sha256.clone(),
        state: State::LaunchIntent,
        resources_start,
        resources_final: None,
    };
    publish(&dir, &record)?; // durable before spawning any helper
    let image = open_image(&config.helper_image, &config.helper_sha256)?;
    if let Some(parent) = remote_parent.as_mut() {
        parent.bind_native(&identity)?;
    }
    let cold_parent = if is_cold && remote_parent.is_none() {
        Some(cold_authority::ColdParent::new(
            &work.world,
            &work.intent,
            &identity,
            dispatch_started
                .checked_add(config.deadline)
                .ok_or("cold deadline overflow")?
                .min(
                    runtime_check
                        .as_ref()
                        .map(|shared| shared.pipeline_deadline())
                        .transpose()?
                        .flatten()
                        .unwrap_or(dispatch_started + config.deadline),
                ),
            &work.cancelled,
        )?)
    } else {
        None
    };
    let (control, child_control) =
        UnixStream::pair().map_err(|_| "cannot create inherited issuer channel")?;
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
            // Cgroup membership is installed BEFORE exec/helper IO. No PID transfer race.
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
    let resource_observer = cgroup.try_clone()?;
    let pipeline_deadline = runtime_check
        .as_ref()
        .map(|shared| shared.pipeline_deadline())
        .transpose()?
        .flatten();
    let remote_deadline = remote_parent
        .as_ref()
        .map(|parent| parent.deadline())
        .transpose()?;
    let pipeline_deadline = [pipeline_deadline, remote_deadline]
        .into_iter()
        .flatten()
        .min();
    let child = command
        .spawn()
        .map_err(|_| "cannot start exact pinned storage helper; journal remains UNKNOWN")?;
    drop(child_control);
    drop(image);
    drop(capsule_file);
    let (mut outcome, quarantine) = supervise(
        child,
        control,
        cgroup,
        lease,
        pipeline_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(config.deadline)
            .min(config.deadline),
        &identity,
        &work.cancelled,
        if work.extended.is_some() {
            DiagnosticProfile::Cold
        } else {
            DiagnosticProfile::Secondary
        },
        |r| {
            if let Some(check) = &runtime_check {
                crate::raft_node::RAFT
                    .get()
                    .ok_or("runtime actual Raft absent")?
                    .rt
                    .block_on(check.check_config())?;
            }
            let reply = if let Some(parent) = remote_parent.as_mut() {
                parent.approve(r)
            } else {
                match &cold_parent {
                    Some(parent) => parent.approve(r),
                    None => live::parent_approval(r, &identity, &work.intent, &work.world),
                }
            };
            if let Some(check) = &runtime_check {
                check.pipeline_deadline()?;
            }
            reply
        },
    )?;
    match resource_observer.resource_snapshot(&config.budget) {
        Ok(snapshot) => {
            if matches!(outcome, Outcome::CompletedDiagnostics { .. })
                && (snapshot.pids_current != 0
                    || snapshot.cpu_usage_us < record.resources_start.cpu_usage_us
                    || snapshot.cpu_user_us < record.resources_start.cpu_user_us
                    || snapshot.cpu_system_us < record.resources_start.cpu_system_us)
            {
                outcome = Outcome::Unknown {
                    reason: "resource drain/counter lineage not complete".into(),
                };
            }
            record.resources_final = Some(snapshot);
        }
        Err(e) => {
            outcome = Outcome::Unknown {
                reason: format!("resource closeout unavailable/mismatched: {e}"),
            }
        }
    }
    record.state = if matches!(outcome, Outcome::CompletedDiagnostics { .. }) {
        State::Complete
    } else {
        State::Unknown
    };
    if let Err(e) = publish(&dir, &record) {
        return Ok((
            Outcome::Unknown {
                reason: format!("dispatch closeout was not durable: {e}"),
            },
            quarantine,
        ));
    }
    if work.extended == Some(ExtendedJob::PrepareVirginOffline) {
        outcome = match outcome {
            Outcome::CompletedDiagnostics {
                stdout,
                retained_lease: Some(lease),
                ..
            } => {
                let completion =
                    VerifiedLocalBoundary::cold_completion(&identity, &record, &stdout)?;
                let complete = if let Some(parent) = remote_parent.as_mut() {
                    parent.complete(&completion)
                } else {
                    cold_parent
                        .as_ref()
                        .ok_or("cold job has no actual-Core parent")?
                        .complete(&completion)
                };
                if let Err(reason) = complete {
                    return Ok((Outcome::Unknown { reason }, quarantine));
                }
                let (expected_pool, expected_plan_sha256) =
                    work.agent.cold_expected(&work.intent)?;
                Outcome::ColdPreparedHeld {
                    held: ColdPreparedHeld {
                        identity,
                        raw: stdout,
                        reservation: RetainedNodeAdmission {
                            lease: Some(lease),
                            busy: work.busy.clone(),
                            release_on_drop: !work.runtime,
                        },
                        cancelled: work.cancelled.clone(),
                        intent: work.intent.clone(),
                        world: work.world.clone(),
                        expected_pool,
                        expected_plan_sha256,
                        agent: work.agent.clone(),
                    },
                }
            }
            other => other,
        };
    }
    // A normal runtime retains a duplicate of the SAME owned flock even if
    // ticket delivery/caller lifetime is lost. It cannot reconstruct a held
    // proof from this guard, and cannot reset the runtime busy admission.
    drop(safety_lease);
    Ok((outcome, quarantine))
}

struct RuntimeSafetyLease {
    lease: Option<File>,
    owner: Arc<super::native_runtime::Shared>,
}
impl Drop for RuntimeSafetyLease {
    fn drop(&mut self) {
        if let Some(lease) = self.lease.take() {
            self.owner.retain_unknown_lease(lease);
        }
    }
}

#[cfg(test)]
mod normal_runtime_admission_tests {
    use super::*;
    #[test]
    fn runtime_admission_drop_is_not_recovery() {
        let busy = Arc::new(AtomicBool::new(true));
        let admission = RetainedNodeAdmission {
            lease: None,
            busy: busy.clone(),
            release_on_drop: false,
        };
        drop(admission);
        assert!(busy.load(Ordering::Acquire));
        let legacy = RetainedNodeAdmission {
            lease: None,
            busy: busy.clone(),
            release_on_drop: true,
        };
        drop(legacy);
        assert!(!busy.load(Ordering::Acquire));
    }
    #[test]
    fn runtime_cancellation_uses_the_same_shared_unknown_arc_at_the_positive_send_gate() {
        let shared = Arc::new(AtomicBool::new(false));
        let worker = cancellation_for_runtime(true, Some(shared.clone())).unwrap();
        assert!(Arc::ptr_eq(&shared, &worker));
        let start = Instant::now();
        assert!(approval_is_live_at(
            worker.load(Ordering::Acquire),
            start,
            Duration::from_secs(1),
            start
        ));
        shared.store(true, Ordering::Release);
        assert!(!approval_is_live_at(
            worker.load(Ordering::Acquire),
            start,
            Duration::from_secs(1),
            start
        ));
        assert!(cancellation_for_runtime(true, None).is_err());
        assert!(cancellation_for_runtime(true, Some(shared.clone())).is_err());
        let legacy = cancellation_for_runtime(false, None).unwrap();
        assert!(!Arc::ptr_eq(&legacy, &shared));
        assert!(!legacy.load(Ordering::Acquire));
    }
}

fn publish(dir: &Dir, record: &Record) -> Result<(), String> {
    let hash_input =
        serde_json::to_vec(record).map_err(|_| "cannot encode exact dispatch journal")?;
    let bytes = serde_json::to_vec(&Envelope {
        version: 1,
        sha256: hash(&hash_input),
        record: record.clone(),
    })
    .map_err(|_| "cannot encode durable dispatch envelope")?;
    dir.write(
        &format!("attempt-{}.json", record.identity.attempt_uid.as_str()),
        &bytes,
    )?;
    dir.write("current.json", &bytes)
}

fn open_private(path: &Path) -> Result<File, String> {
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "cannot open inherited private capsule")?;
    let m = f.metadata().map_err(|_| "cannot inspect private capsule")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > CAPSULE_LIMIT
    {
        return Err("inherited capsule is not bounded/private/singly-linked".into());
    }
    Ok(f)
}
fn open_image(path: &Path, expected: &str) -> Result<File, String> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "pinned helper image unavailable")?;
    let m = file
        .metadata()
        .map_err(|_| "cannot inspect pinned helper image")?;
    if !image_stat_allowed(m.is_file(), m.uid(), m.mode(), m.len()) {
        return Err("pinned helper image is not trusted root-owned bounded file".into());
    }
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    let mut read_bytes = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| "cannot hash pinned helper image")?;
        if n == 0 {
            break;
        }
        read_bytes = read_bytes
            .checked_add(n as u64)
            .ok_or("helper hash byte accounting overflow")?;
        if read_bytes > m.len() || read_bytes > 128 * 1024 * 1024 {
            return Err("helper grew beyond pinned bounded input".into());
        }
        hash.update(&buf[..n]);
    }
    if format!("{:x}", hash.finalize()) != expected {
        return Err("native helper image SHA256 differs from operator pin".into());
    }
    let after = file
        .metadata()
        .map_err(|_| "cannot recheck pinned helper metadata")?;
    if !image_stat_allowed(after.is_file(), after.uid(), after.mode(), after.len())
        || after.len() != m.len()
        || after.mtime() != m.mtime()
        || after.mtime_nsec() != m.mtime_nsec()
        || after.ctime() != m.ctime()
        || after.ctime_nsec() != m.ctime_nsec()
    {
        return Err("pinned helper changed while hashing".into());
    }
    Ok(file)
}
fn image_stat_allowed(regular: bool, uid: u32, mode: u32, bytes: u64) -> bool {
    regular && uid == 0 && mode & 0o022 == 0 && mode & 0o111 != 0 && bytes <= 128 * 1024 * 1024
}
/// Same readonly prerequisite as the actual pre-exec pin, no worker grant.
pub(super) fn check_helper_image(path: &Path, expected: &str) -> Result<(), String> {
    open_image(path, expected).map(drop)
}

#[cfg(test)]
mod normal_helper_prerequisites {
    use super::*;
    #[test]
    fn readonly_helper_prerequisite_rejects_missing_image_without_launch() {
        assert!(check_helper_image(
            Path::new("/definitely-missing-royak-runtime-helper"),
            &"a".repeat(64)
        )
        .is_err());
    }
    #[test]
    fn helper_metadata_predicate_requires_root_regular_bounded_executable() {
        assert!(image_stat_allowed(true, 0, 0o755, 128));
        for args in [
            (false, 0, 0o755, 128),
            (true, 1000, 0o755, 128),
            (true, 0, 0o775, 128),
            (true, 0, 0o644, 128),
            (true, 0, 0o755, 128 * 1024 * 1024 + 1),
        ] {
            assert!(!image_stat_allowed(args.0, args.1, args.2, args.3));
        }
    }
}
#[cfg(target_os = "linux")]
fn image_exec_path(image: &File, _original: &Path) -> Result<PathBuf, String> {
    Ok(PathBuf::from(format!(
        "/proc/self/fd/{}",
        image.as_raw_fd()
    )))
}
#[cfg(not(target_os = "linux"))]
fn image_exec_path(_image: &File, _original: &Path) -> Result<PathBuf, String> {
    Err("Linux pinned-fd execution required".into())
}

pub(super) struct Quarantine {
    child: Option<Child>,
    cgroup: JobCgroup,
    _lease: File,
}
impl Quarantine {
    fn wait_until_empty(mut self) {
        loop {
            if let Some(child) = &mut self.child {
                if process::exited_unreaped(child).unwrap_or(false) {
                    if child.wait().is_ok() {
                        self.child = None;
                    }
                }
            }
            if self.child.is_none() && matches!(self.cgroup.populated(), Ok(false)) {
                if self.cgroup.prune_empty_command_scopes().is_ok() {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn nonblocking(fd: RawFd) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err("cannot bound helper pipe IO".into());
    }
    Ok(())
}

fn approval_is_live_at(
    cancelled: bool,
    started: Instant,
    deadline: Duration,
    now: Instant,
) -> bool {
    !cancelled && now >= started && now.duration_since(started) < deadline
}
#[derive(Clone, Copy)]
enum DiagnosticProfile<'a> {
    Terminal {scope:&'a crate::storage_lifecycle::pod_attachment::ExpectedAttachScope,
        operation:&'a Uid,step:super::native_runtime::mount::consumer::terminal::TerminalNativeStep},
    Attachment {scope:&'a crate::storage_lifecycle::pod_attachment::ExpectedAttachScope,
        step:super::native_runtime::mount::parent::AttachNativeStep},
    Secondary,
    Cold,
    Initialization {
        scope: &'a crate::storage_lifecycle::generation::physical::ExpectedInitScope,
        intent: &'a crate::storage_lifecycle::generation::InitializationIntent,
    },
}
fn diagnostic_matches(
    raw: &[u8],
    identity: &live::JobIdentity,
    profile: DiagnosticProfile<'_>,
) -> bool {
    if let DiagnosticProfile::Terminal{scope,operation,step}=profile{
        return attachment::terminal::diagnostic_matches(raw,identity,scope,operation,step);
    }
    if let DiagnosticProfile::Attachment {scope,step}=profile {
        return attachment::diagnostic_matches(raw,identity,scope,step);
    }
    if let DiagnosticProfile::Initialization { scope, intent } = profile {
        let Ok(observed) = serde_json::from_slice::<
            crate::storage_lifecycle::generation::physical::PhaseObservation,
        >(raw) else {
            return false;
        };
        let Some(fact) = scope.generation.virgin_replicas.iter().find(|fact| {
            fact.node_uid == identity.node_uid && fact.node_boot_id.as_str() == identity.boot_id
        }) else {
            return false;
        };
        return scope.target_node_uid == identity.node_uid
            && scope.target_boot.as_str() == identity.boot_id
            && scope.owner.volume_uid == identity.volume_uid
            && scope.generation.initialize_operation_uid == identity.operation_uid
            && observed.validate_for(intent, scope.phase, fact).is_ok();
    }
    let Ok(observed) = serde_json::from_slice::<serde_json::Value>(raw) else {
        return false;
    };
    observed["kind"]
        == if matches!(profile, DiagnosticProfile::Cold) {
            "royak-agent-virgin-offline-prepared-v2"
        } else {
            "royak-agent-secondary-prepared-v1"
        }
        && observed["volume_uid"] == identity.volume_uid.as_str()
        && observed["operation_uid"] == identity.operation_uid.as_str()
        && observed["node_uid"] == identity.node_uid.as_str()
        && observed["node_boot_id"] == identity.boot_id
        && observed["pod_access_granted"] == false
}
fn supervise(
    mut child: Child,
    mut control: UnixStream,
    cgroup: JobCgroup,
    lease: File,
    deadline: Duration,
    identity: &live::JobIdentity,
    cancelled: &AtomicBool,
    profile: DiagnosticProfile<'_>,
    mut approve: impl FnMut(&live::Request) -> Result<Option<bool>, String>,
) -> Result<(Outcome, Option<Quarantine>), String> {
    let stdout = match child.stdout.take() {
        Some(v) => v,
        None => {
            return Ok(abort_poll(
                child,
                cgroup,
                lease,
                "helper stdout unavailable".into(),
            ))
        }
    };
    let stderr = match child.stderr.take() {
        Some(v) => v,
        None => {
            return Ok(abort_poll(
                child,
                cgroup,
                lease,
                "helper stderr unavailable".into(),
            ))
        }
    };
    if let Err(e) = nonblocking(stdout.as_raw_fd()).and_then(|_| nonblocking(stderr.as_raw_fd())) {
        return Ok(abort_poll(child, cgroup, lease, e));
    }
    if control.set_nonblocking(true).is_err() {
        return Ok(abort_poll(
            child,
            cgroup,
            lease,
            "cannot bound issuer control IO".into(),
        ));
    }
    let mut pipes: [Box<dyn Read>; 2] = [Box::new(stdout), Box::new(stderr)];
    let mut data = [Vec::new(), Vec::new()];
    let mut closed = [false, false];
    let mut buffer = Vec::with_capacity(live::CONTROL_BUFFER_MAX);
    let mut pending = None;
    let mut sequence = 0;
    let start = Instant::now();
    let mut error = None;
    let mut exited = false;
    loop {
        if cancelled.load(Ordering::Acquire) {
            error = Some("exact storage ticket cancelled; submitted IO remains UNKNOWN".into());
            break;
        }
        if start.elapsed() >= deadline {
            error = Some("storage helper deadline; submitted IO outcome UNKNOWN".into());
            break;
        }
        for i in 0..2 {
            if closed[i] {
                continue;
            }
            let mut bytes = [0; 8192];
            loop {
                match pipes[i].read(&mut bytes) {
                    Ok(0) => {
                        closed[i] = true;
                        break;
                    }
                    Ok(n) => {
                        if data[i].len() + n > OUTPUT_LIMIT {
                            error = Some("helper output exceeded bound".into());
                            break;
                        }
                        data[i].extend_from_slice(&bytes[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        error = Some("helper output became UNKNOWN".into());
                        break;
                    }
                }
            }
        }
        if error.is_some() {
            break;
        }
        let mut bytes = [0; 4096];
        match control.read(&mut bytes) {
            Ok(0) => {}
            Ok(n) => {
                if let Err(e) = live::append_control(&mut buffer, pending.is_some(), &bytes[..n]) {
                    error = Some(e);
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => {
                error = Some("live issuer channel failed".into());
                break;
            }
        }
        if pending.is_none() {
            pending = match live::decode_pending(&mut buffer) {
                Ok(v) => v,
                Err(e) => {
                    error = Some(e);
                    break;
                }
            };
        }
        if let Some(request) = &pending {
            if request.sequence != sequence + 1 || request.identity != *identity {
                error = Some("replayed/misbound live storage approval".into());
                break;
            }
            match approve(request) {
                Ok(Some(approved)) => {
                    // Approval may have waited on a real read barrier. Never
                    // send a positive reply after cancellation/deadline raced.
                    if !approval_is_live_at(
                        cancelled.load(Ordering::Acquire),
                        start,
                        deadline,
                        Instant::now(),
                    ) {
                        error = Some(
                            "storage approval became stale during callback; outcome UNKNOWN".into(),
                        );
                        break;
                    }
                    let response = live::Response {
                        version: 1,
                        sequence: request.sequence,
                        nonce: request.nonce.clone(),
                        approved,
                    };
                    if let Err(e) = live::write_frame(&mut control, &response) {
                        error = Some(e);
                        break;
                    }
                    sequence = request.sequence;
                    pending = None;
                    if !approved {
                        error = Some(
                            "issuer lost current state/quorum authority; outcome UNKNOWN".into(),
                        );
                        break;
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    error = Some(e);
                    break;
                }
            }
        }
        exited = match process::exited_unreaped(&child) {
            Ok(v) => v,
            Err(e) => {
                error = Some(e);
                break;
            }
        };
        if exited && closed.iter().all(|v| *v) {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    // Only the inode-anchored owned cgroup is signalled here, never a PID/PGID
    // that may already have been reaped/reused. This includes FD-closing descendants.
    if error.is_some() || exited {
        if let Err(e) = cgroup.kill_exact() {
            error = Some(e);
        }
    }
    let until = Instant::now() + REAP_GRACE;
    while !exited && Instant::now() < until {
        exited = match process::exited_unreaped(&child) {
            Ok(v) => v,
            Err(e) => {
                error = Some(e);
                break;
            }
        };
        if !exited {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let status = if exited {
        match child.wait() {
            Ok(v) => Some(v),
            Err(_) => {
                error = Some("cannot reap exact owned helper".into());
                None
            }
        }
    } else {
        None
    };
    let mut empty = false;
    while Instant::now() < until {
        match cgroup.populated() {
            Ok(false) => {
                empty = true;
                break;
            }
            Ok(true) => {}
            Err(e) => {
                error = Some(e);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if empty {
        if let Err(e) = cgroup.prune_empty_command_scopes() {
            error = Some(e);
        }
    }
    let mut completed_lease = Some(lease);
    let quarantine = if !empty || status.is_none() {
        Some(Quarantine {
            child: if status.is_none() { Some(child) } else { None },
            cgroup,
            _lease: completed_lease.take().expect("owned exact node lease"),
        })
    } else {
        None
    };
    if error.is_none() && status.as_ref().is_some_and(|s| s.success()) && quarantine.is_none() {
        if !diagnostic_matches(&data[0], identity, profile) {
            return Ok((
                Outcome::Unknown {
                    reason: "helper diagnostic binding mismatch".into(),
                },
                quarantine,
            ));
        }
        Ok((
            Outcome::CompletedDiagnostics {
                stdout: data[0].clone(),
                stderr_sha256: hash(&data[1]),
                retained_lease: if !matches!(profile, DiagnosticProfile::Secondary) {
                    completed_lease.take()
                } else {
                    None
                },
            },
            None,
        ))
    } else {
        Ok((
            Outcome::Unknown {
                reason: error.unwrap_or_else(|| {
                    "helper failed or descendants remain; outcome UNKNOWN".into()
                }),
            },
            quarantine,
        ))
    }
}

fn abort_poll(
    child: Child,
    cgroup: JobCgroup,
    lease: File,
    reason: String,
) -> (Outcome, Option<Quarantine>) {
    let _ = cgroup.kill_exact();
    (
        Outcome::Unknown { reason },
        Some(Quarantine {
            child: Some(child),
            cgroup,
            _lease: lease,
        }),
    )
}

/// Hidden CLI entry. Descriptors must be inherited from the private dispatcher,
/// not opened from request JSON. It performs only the existing Secondary slice.
pub(crate) fn run_worker(
    journal: &Path,
    lease_fd: i32,
    capsule_fd: i32,
    control_fd: i32,
    attempt: &str,
    cgroup_root: &Path,
) -> Result<(), String> {
    if !cfg!(target_os = "linux")
        || unsafe { libc::geteuid() } != 0
        || lease_fd < 3
        || capsule_fd < 3
        || control_fd < 3
        || lease_fd == capsule_fd
        || lease_fd == control_fd
        || capsule_fd == control_fd
    {
        return Err("invalid inherited native helper descriptors/platform".into());
    }
    for fd in [lease_fd, capsule_fd, control_fd] {
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
            return Err("inherited descriptor is closed/unavailable".into());
        }
    }
    let dir = Dir::open(journal, false)?;
    let record = load_record(
        &dir.read("current.json")?
            .ok_or("missing committed dispatch record")?,
    )?;
    if ![1, 2, 3, 4, 5, 6, 7].contains(&record.version)
        || record.state != State::LaunchIntent
        || record.identity.attempt_uid.as_str() != attempt
    {
        return Err("native helper attempt is stale/not launched".into());
    }
    let lease = unsafe { File::from_raw_fd(lease_fd) };
    let capsule_file = unsafe { File::from_raw_fd(capsule_fd) };
    let lock_meta =
        std::fs::symlink_metadata(journal.join("lock")).map_err(|_| "node lease missing")?;
    let inherited = lease
        .metadata()
        .map_err(|_| "inherited node lease unavailable")?;
    if inherited.dev() != lock_meta.dev()
        || inherited.ino() != lock_meta.ino()
        || inherited.uid() != 0
        || inherited.mode() & 0o077 != 0
        || unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err("inherited exact node kernel lease not held".into());
    }
    let path = journal.join(format!("capsule-{attempt}.json"));
    let expected = open_private(&path)?
        .metadata()
        .map_err(|_| "capsule disappeared")?;
    let actual = capsule_file
        .metadata()
        .map_err(|_| "inherited capsule disappeared")?;
    if expected.dev() != actual.dev() || expected.ino() != actual.ino() || actual.uid() != 0 {
        return Err("inherited capsule inode differs from private launch".into());
    }
    let mut bytes = Vec::new();
    (&capsule_file)
        .take(CAPSULE_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read inherited capsule")?;
    if bytes.len() as u64 > CAPSULE_LIMIT {
        return Err("inherited capsule exceeded bound".into());
    }
    let capsule: Capsule =
        serde_json::from_slice(&bytes).map_err(|_| "malformed inherited capsule")?;
    if capsule.version != record.version
        || !valid_capsule_profile(&capsule)
        || capsule.identity != record.identity
        || hash(&serde_json::to_vec(&capsule.payload).map_err(|_| "cannot bind inherited payload")?)
            != record.payload_sha256
        || crate::storage_boot::BootId::current()?.as_str() != record.identity.boot_id
    {
        return Err("inherited capsule binding/boot changed".into());
    }
    // Old1-5 retain their exact path. V6 NEVER invokes open/mkdir/adoption:
    // it consumes only the actual extra original-directory FD inherited by
    // this private lease/capsule/launching-root channel.
    let legacy_cgroup=if capsule.version==6||capsule.version==7{None}else{Some(JobCgroup::open(cgroup_root,record.identity.node_uid.as_str())?)};
    let binding: CgroupBinding = serde_json::from_slice(
        &dir.read("cgroup-binding.json")?
            .ok_or("private cgroup ownership missing")?,
    )
    .map_err(|_| "invalid private cgroup ownership")?;
    let mut terminal_control=None;
    let cgroup=if let Some(original)=legacy_cgroup{original}else{
        terminal_control=Some(unsafe{UnixStream::from_raw_fd(control_fd)});
        if capsule.version==7{
            let verified=attachment::inventory::take_inherited_cgroup(&capsule,&binding,&lease,capsule_file.as_raw_fd(),
                terminal_control.as_ref().unwrap(),cgroup_root)?;
            JobCgroup::from_verified_owned_inventory_inherited(verified)?
        }else{
            let verified=attachment::terminal::take_inherited_cgroup(&capsule,&binding,&lease,
                terminal_control.as_ref().unwrap(),cgroup_root)?;
            JobCgroup::from_verified_terminal_inherited(verified)?
        }
    };
    let (device, inode) = cgroup.identity()?;
    if binding.version != 1
        || binding.node_uid != record.identity.node_uid
        || binding.boot_id != record.identity.boot_id
        || binding.device != device
        || binding.inode != inode
    {
        return Err("worker cgroup inode/boot differs from exact private launch".into());
    }
    if capsule.budget != record.resources_start.budget {
        return Err("inherited resource admission differs from launch".into());
    }
    cgroup.resource_snapshot(&capsule.budget)?;
    if !cgroup.contains(std::process::id())? {
        return Err("worker is outside exact owned kernel job cgroup".into());
    }
    let stream=if let Some(original)=terminal_control{original}else{unsafe{UnixStream::from_raw_fd(control_fd)}};
    live::install(stream, record.identity.clone(), cgroup)?;
    let authority = VerifiedNativeAuthority {
        capsule,
        _lease: lease,
        _capsule_file: capsule_file,
    };
    if authority.capsule.version==7{
        attachment::inventory::confine_profile7_baseline(&authority)?;
        let diagnostic=NativeAgent::run_verified_owned_inventory_phase(&authority)?;
        println!("{}",serde_json::to_string(&diagnostic).map_err(|_|"cannot encode profile7 diagnostic")?);return Ok(());
    }
    if authority.capsule.version==6 {
        let diagnostic=NativeAgent::run_verified_terminal_phase(&authority)?;
        println!("{}",serde_json::to_string(&diagnostic).map_err(|_|"cannot encode terminal diagnostic")?);
        return Ok(());
    }
    if authority.capsule.version==5 {
        let diagnostic=NativeAgent::run_verified_attachment_phase(&authority)?;
        println!("{}",serde_json::to_string(&diagnostic).map_err(|_|"cannot encode attach diagnostic")?);
        return Ok(());
    }
    if authority.capsule.version == 4 {
        let diagnostic = NativeAgent::run_verified_distributed_phase(&authority)?;
        println!(
            "{}",
            serde_json::to_string(&diagnostic).map_err(|_| "cannot encode phase diagnostic")?
        );
        return Ok(());
    }
    if authority.is_cold() {
        let receipt = NativeAgent::run_verified_cold_helper(&authority)?;
        println!(
            "{}",
            serde_json::to_string(&receipt).map_err(|_| "cannot encode cold diagnostics")?
        );
        return Ok(());
    }
    let receipt = NativeAgent::run_verified_helper(&authority)?;
    println!(
        "{}",
        serde_json::to_string(&receipt).map_err(|_| "cannot encode native helper diagnostics")?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    const ENTRY: &str = "storage_driver::dispatcher::tests::native_fixture_entrypoint";
    #[test]
    fn distributed_phase_diagnostic_is_not_mislabelled_as_cold_or_foreign_output() {
        use crate::storage_lifecycle::generation::physical::{
            ExpectedInitScope, InitPhase, PhaseObservation,
        };
        let (_, intent) =
            crate::storage_lifecycle::generation::model_initialization_for_authority_tests();
        let fact = &intent.generation().virgin_replicas[0];
        let identity = live::JobIdentity {
            node_uid: fact.node_uid.clone(),
            boot_id: fact.node_boot_id.as_str().into(),
            volume_uid: intent.owner().volume_uid.clone(),
            operation_uid: intent.operation_uid().clone(),
            attempt_uid: Uid::new(),
            binding_sha256: "a".repeat(64),
        };
        let scope = ExpectedInitScope {
            version: 1,
            owner: intent.owner().clone(),
            generation: intent.generation().clone(),
            issuer_node_uid: fact.node_uid.clone(),
            issuer_boot: fact.node_boot_id.clone(),
            issuer_revision: crate::storage_remote_protocol::Revision {
                term: 1,
                leader_raft_id: 1,
                applied_term: 1,
                applied_leader_raft_id: 1,
                applied_index: 1,
                desired_generation: 1,
                membership_sha256: "b".repeat(64),
            },
            directory_sha256: "c".repeat(64),
            scope_sha256: "d".repeat(64),
            target_node_uid: fact.node_uid.clone(),
            target_boot: fact.node_boot_id.clone(),
            prepare_job_uid: Uid::new(),
            phase_job_uid: Uid::new(),
            phase: InitPhase::ObserveFresh,
            remaining_budget_ms: 1000,
        };
        let mut data = PhaseObservation {
            version: 1,
            phase: scope.phase,
            owner: intent.owner().clone(),
            data_generation_uid: intent.generation().uid.clone(),
            initialize_operation_uid: intent.operation_uid().clone(),
            replica: fact.clone(),
            raw_kernel: Some(serde_json::json!({"role":"Secondary"})),
            primary: None,
            offline: None,
            evidence_sha256: "e".repeat(64),
        };
        let profile = DiagnosticProfile::Initialization {
            scope: &scope,
            intent: &intent,
        };
        let raw = serde_json::to_vec(&data).unwrap();
        assert!(diagnostic_matches(&raw, &identity, profile));
        assert!(!diagnostic_matches(
            &raw,
            &identity,
            DiagnosticProfile::Cold
        ));
        data.initialize_operation_uid = Uid::new();
        assert!(!diagnostic_matches(
            &serde_json::to_vec(&data).unwrap(),
            &identity,
            profile
        ));
        assert!(!diagnostic_matches(
            br#"{"kind":"royak-agent-virgin-offline-prepared-v2"}"#,
            &identity,
            profile
        ));
    }
    #[test]
    fn callback_wait_cannot_send_positive_after_cancel_or_deadline() {
        let start = Instant::now();
        let limit = Duration::from_secs(1);
        assert!(approval_is_live_at(
            false,
            start,
            limit,
            start + Duration::from_millis(1)
        ));
        assert!(!approval_is_live_at(
            true,
            start,
            limit,
            start + Duration::from_millis(1)
        ));
        assert!(!approval_is_live_at(false, start, limit, start + limit));
        assert!(!approval_is_live_at(
            false,
            start,
            limit,
            start + limit + Duration::from_millis(1)
        ));
    }
    #[test]
    fn legacy_payload_bytes_and_new_job_profiles_are_not_interchangeable() {
        let payload = Payload {
            config: serde_json::json!({"a":1}),
            plan: serde_json::json!({"b":2}),
            projection: vec![1, 2],
            extended: None,
            dataset_uid: None,
            remote_binding: None,
            initialization: None,
            worker_remaining_ms: None,
        };
        assert_eq!(
            serde_json::to_string(&payload).unwrap(),
            "{\"config\":{\"a\":1},\"plan\":{\"b\":2},\"projection\":[1,2]}"
        );
        let (_, intent) =
            crate::storage_lifecycle::generation::model_initialization_for_authority_tests();
        let fact = &intent.generation().virgin_replicas[0];
        let mut capsule = Capsule {
            version: 1,
            identity: live::JobIdentity {
                node_uid: fact.node_uid.clone(),
                boot_id: fact.node_boot_id.as_str().into(),
                volume_uid: intent.owner().volume_uid.clone(),
                operation_uid: intent.operation_uid().clone(),
                attempt_uid: Uid::new(),
                binding_sha256: "a".repeat(64),
            },
            payload,
            budget: super::super::ResourceBudget {
                pids_max: 16,
                memory_max_bytes: 64 * 1024 * 1024,
                cpu_quota_us: 10000,
                cpu_period_us: 100000,
            },
        };
        assert!(valid_capsule_profile(&capsule));
        capsule.payload.extended = Some(ExtendedJob::PrepareVirginOffline);
        assert!(!valid_capsule_profile(&capsule));
        capsule.version = 2;
        assert!(valid_capsule_profile(&capsule));
        capsule.payload.extended = Some(ExtendedJob::InitializeReserved);
        assert!(!valid_capsule_profile(&capsule));
        capsule.payload.dataset_uid = Some(intent.generation().uid.clone());
        assert!(valid_capsule_profile(&capsule));
    }
    #[test]
    fn retained_cold_admission_releases_kernel_lock_before_reopening_slot() {
        const KEY: &str = "ROYAK_COLD_LEASE_ISOLATED";
        if std::env::var_os(KEY).is_none() {
            let output=std::process::Command::new(std::env::current_exe().unwrap()).args([
            "--exact","storage_driver::dispatcher::tests::retained_cold_admission_releases_kernel_lock_before_reopening_slot","--test-threads=1"])
            .env(KEY,"1").output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("royak-cold-admission-{}", Uid::new().as_str()));
        let dir = Dir::open(&root, true).unwrap();
        let lease = dir.lock().unwrap();
        let busy = Arc::new(AtomicBool::new(true));
        let held = RetainedNodeAdmission {
            lease: Some(lease),
            busy: busy.clone(),
            release_on_drop: true,
        };
        assert!(dir.lock().is_err());
        assert!(busy.load(Ordering::Acquire));
        drop(held);
        assert!(!busy.load(Ordering::Acquire));
        drop(dir.lock().unwrap());
        std::fs::remove_dir_all(root).unwrap();
    }

    // Test-only ownership guard. A dropped std::process::Child does not kill or
    // reap its process. Never signal after ECHILD/unknown ownership: a stale
    // numeric PID must not become authority over another process.
    struct FixtureChild(Option<Child>);
    #[derive(Debug, PartialEq, Eq)]
    enum FixtureCleanup {
        Reaped,
        KilledAndReaped,
        OwnershipUnknown,
        Failed,
    }
    impl FixtureChild {
        fn new(child: Child) -> Self {
            Self(Some(child))
        }
        fn cleanup(&mut self) -> FixtureCleanup {
            let Some(child) = self.0.as_mut() else {
                return FixtureCleanup::Reaped;
            };
            let exited = match process::exited_unreaped(child) {
                Ok(value) => value,
                Err(_) => return FixtureCleanup::OwnershipUnknown,
            };
            // This unreaped direct Child reserves its PID even if it exits
            // between waitid(WNOWAIT) and kill. No other fixture path reaps it.
            if !exited && child.kill().is_err() {
                return FixtureCleanup::Failed;
            }
            if child.wait().is_err() {
                return FixtureCleanup::Failed;
            }
            self.0.take();
            if exited {
                FixtureCleanup::Reaped
            } else {
                FixtureCleanup::KilledAndReaped
            }
        }
    }
    impl std::ops::Deref for FixtureChild {
        type Target = Child;
        fn deref(&self) -> &Child {
            self.0.as_ref().expect("fixture child already consumed")
        }
    }
    impl std::ops::DerefMut for FixtureChild {
        fn deref_mut(&mut self) -> &mut Child {
            self.0.as_mut().expect("fixture child already consumed")
        }
    }
    impl Drop for FixtureChild {
        fn drop(&mut self) {
            // In particular do not panic again while unwinding an assertion.
            let _ = self.cleanup();
        }
    }

    fn isolated_lease_test(name: &str) -> bool {
        const KEY: &str = "RK_DISPATCH_ISOLATED_LEASE_TEST";
        let path = format!("{}::{name}", module_path!());
        let exact = path.split_once("::").unwrap().1;
        if std::env::var(KEY).ok().as_deref() == Some(exact) {
            return false;
        }
        // Re-exec BEFORE creating a lease. Unrelated parallel suite forks can
        // inherit a CLOEXEC flock until their exec; no such peer exists in this
        // exact one-test actor. Production locking and the suite stay unchanged.
        let mut actor = FixtureChild::new(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", exact, "--test-threads=1", "--nocapture"])
                .env(KEY, exact)
                .env_remove("RK_DISPATCH_FIXTURE_MODE")
                .stdin(Stdio::null())
                .spawn()
                .unwrap(),
        );
        own_wait(&mut actor);
        true
    }

    fn temp() -> PathBuf {
        let path = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("rk-dispatch-fixture-{}", Uid::new().as_str()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    fn identity() -> live::JobIdentity {
        live::JobIdentity {
            node_uid: Uid::new(),
            boot_id: "71cb439a-d59b-4d47-9058-2134d97ebd7f".into(),
            volume_uid: Uid::new(),
            operation_uid: Uid::new(),
            attempt_uid: Uid::new(),
            binding_sha256: "a".repeat(64),
        }
    }
    fn fixture(
        mode: &str,
        lease: Option<RawFd>,
        control: Option<RawFd>,
        root: &Path,
        id: Option<&live::JobIdentity>,
    ) -> FixtureChild {
        let mut c = Command::new(std::env::current_exe().unwrap());
        c.args(["--exact", ENTRY, "--test-threads=1", "--nocapture"])
            .env("RK_DISPATCH_FIXTURE_MODE", mode)
            .env("RK_DISPATCH_FIXTURE_ROOT", root)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(fd) = lease {
            c.env("RK_DISPATCH_FIXTURE_LEASE", fd.to_string());
        }
        if let Some(fd) = control {
            c.env("RK_DISPATCH_FIXTURE_CONTROL", fd.to_string());
        }
        if let Some(id) = id {
            c.env("RK_DISPATCH_FIXTURE_ID", serde_json::to_string(id).unwrap());
        }
        for fd in [lease, control].into_iter().flatten() {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(
                flags >= 0 && flags & libc::FD_CLOEXEC != 0,
                "parent fixture descriptors must remain CLOEXEC"
            );
        }
        unsafe {
            c.pre_exec(move || {
                for fd in [lease, control].into_iter().flatten() {
                    let flags = libc::fcntl(fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
        let child = c.spawn().unwrap();
        for fd in [lease, control].into_iter().flatten() {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(
                flags >= 0 && flags & libc::FD_CLOEXEC != 0,
                "child pre_exec must not change the parent's FD flags"
            );
        }
        FixtureChild::new(child)
    }
    fn own_wait(child: &mut FixtureChild) {
        let until = Instant::now() + Duration::from_secs(3);
        while !process::exited_unreaped(child).unwrap() {
            assert!(Instant::now() < until, "owned fixture failed to exit");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(child.wait().unwrap().success());
        child.0.take();
    }

    /// Fixture entry itself always runs a real subprocess smoke when invoked
    /// by the ordinary test suite. Environment modes are cfg(test)-only and
    /// never enter NativeAgent, a block device or a production grant constructor.
    #[test]
    fn native_fixture_entrypoint() {
        let Ok(mode) = std::env::var("RK_DISPATCH_FIXTURE_MODE") else {
            let root = temp();
            let mut child = fixture("smoke", None, None, &root, None);
            own_wait(&mut child);
            std::fs::remove_dir(root).unwrap();
            return;
        };
        if mode == "smoke" {
            assert!(!live::installed());
            return;
        }
        let root = PathBuf::from(std::env::var_os("RK_DISPATCH_FIXTURE_ROOT").unwrap());
        if mode == "issuer-flood" {
            actual_issuer_flood(&root);
            return;
        }
        if mode == "issuer-loss" {
            actual_issuer_loss(&root);
            return;
        }
        let control_fd: i32 = std::env::var("RK_DISPATCH_FIXTURE_CONTROL")
            .unwrap()
            .parse()
            .unwrap();
        let mut control = unsafe { UnixStream::from_raw_fd(control_fd) };
        let control_flags = unsafe { libc::fcntl(control_fd, libc::F_GETFD) };
        assert!(control_flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(control_fd, libc::F_SETFD, control_flags | libc::FD_CLOEXEC) },
            0
        );
        if mode == "hold-lease" || mode == "close-lease" || mode == "orphan-parent" {
            let fd: i32 = std::env::var("RK_DISPATCH_FIXTURE_LEASE")
                .unwrap()
                .parse()
                .unwrap();
            let lease = unsafe { File::from_raw_fd(fd) };
            let lease_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(lease_flags >= 0);
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, lease_flags | libc::FD_CLOEXEC) },
                0
            );
            if mode == "orphan-parent" {
                let _child = fixture(
                    "hold-lease",
                    Some(lease.as_raw_fd()),
                    Some(control.as_raw_fd()),
                    &root,
                    None,
                );
                std::process::exit(0); // actual creator process exits, not just a dropped handle
            }
            if mode == "close-lease" {
                drop(lease);
                assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EBADF)
                );
            } else {
                control.write_all(b"R").unwrap();
                let mut stop = [0];
                control.read_exact(&mut stop).unwrap();
                drop(lease);
                return;
            }
            control.write_all(b"R").unwrap();
            let mut stop = [0];
            control.read_exact(&mut stop).unwrap();
            return;
        }
        let id: live::JobIdentity =
            serde_json::from_str(&std::env::var("RK_DISPATCH_FIXTURE_ID").unwrap()).unwrap();
        if mode == "flood-pending" {
            let request = live::Request {
                version: 1,
                identity: id,
                sequence: 1,
                nonce: Uid::new(),
                boundary: "fixed-program".into(),
                detail_sha256: "b".repeat(64),
            };
            live::write_frame(&mut control, &request).unwrap();
            let mut start = [0];
            control.read_exact(&mut start).unwrap();
            assert_eq!(&start, b"F");
            let chunk = [7u8; 4096];
            for _ in 0..16384 {
                if control.write_all(&chunk).is_err() {
                    break;
                }
            }
            return;
        }
        // Native fixture proves control-channel revocation using actual owned
        // regular-file IO, not a fake kernel cgroup or backend success response.
        live::install_fixture(control, id.clone()).unwrap();
        let first = live::before_block_write(&id.volume_uid, 0, 1);
        if mode == "denied" {
            assert!(first.is_err());
            assert!(!root.join("writes").exists());
            return;
        }
        first.unwrap();
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(root.join("writes"))
            .unwrap();
        file.write_all(b"1").unwrap();
        file.sync_all().unwrap();
        assert!(
            live::before_block_write(&id.volume_uid, 1, 1).is_err(),
            "no new mutation after parent channel loss"
        );
        assert_eq!(std::fs::read(root.join("writes")).unwrap(), b"1");
    }

    #[test]
    fn creator_exit_and_restart_cannot_overlap_descendant_held_node_lease() {
        if isolated_lease_test("creator_exit_and_restart_cannot_overlap_descendant_held_node_lease")
        {
            return;
        }
        let root = temp();
        let dir = Dir::open(&root, false).unwrap();
        let lease = dir.lock().unwrap();
        let id = identity();
        dir.write("current.json", &serde_json::to_vec(&id).unwrap())
            .unwrap();
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut creator = fixture(
            "orphan-parent",
            Some(lease.as_raw_fd()),
            Some(child.as_raw_fd()),
            &root,
            None,
        );
        drop(child);
        drop(lease);
        drop(dir);
        let mut ready = [0];
        parent.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"R");
        own_wait(&mut creator);
        let restarted = Dir::open(&root, false).unwrap();
        let recovered: live::JobIdentity =
            serde_json::from_slice(&restarted.read("current.json").unwrap().unwrap()).unwrap();
        assert_eq!(recovered, id);
        assert!(
            restarted.lock().is_err(),
            "same or new operation cannot replace a live inherited lease"
        );
        parent.write_all(b"X").unwrap();
        let mut eof = [0];
        assert_eq!(parent.read(&mut eof).unwrap(), 0);
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            match restarted.lock() {
                Ok(lock) => {
                    drop(lock);
                    break;
                }
                Err(_) => {
                    assert!(Instant::now() < until);
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
        drop(restarted);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn utility_can_close_inherited_fd_so_kernel_cgroup_gate_is_mandatory() {
        if isolated_lease_test("utility_can_close_inherited_fd_so_kernel_cgroup_gate_is_mandatory")
        {
            return;
        }
        let root = temp();
        let dir = Dir::open(&root, false).unwrap();
        let lease = dir.lock().unwrap();
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut utility = fixture(
            "close-lease",
            Some(lease.as_raw_fd()),
            Some(child.as_raw_fd()),
            &root,
            None,
        );
        drop(child);
        drop(lease);
        let mut ready = [0];
        parent.read_exact(&mut ready).unwrap();
        let replacement = dir.lock().unwrap(); // FD-close is NOT proof that utility exited
        assert!(!process::exited_unreaped(&utility).unwrap());
        assert!(
            JobCgroup::open(&root, &"a".repeat(32)).is_err(),
            "ordinary files/native fallback never authorize production dispatch"
        );
        drop(replacement);
        parent.write_all(b"X").unwrap();
        own_wait(&mut utility);
        drop(dir);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fixture_child_guard_reaps_on_early_scope_exit_and_refuses_reaped_pid() {
        let mut unrelated =
            FixtureChild::new(Command::new("/bin/sleep").arg("30").spawn().unwrap());
        let pid = std::cell::Cell::new(0u32);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let owned = FixtureChild::new(Command::new("/bin/sleep").arg("30").spawn().unwrap());
            pid.set(owned.id());
            panic!("controlled early fixture assertion");
        }));
        assert!(result.is_err());
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid.get() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert!(
            unrelated.try_wait().unwrap().is_none(),
            "unrelated owned control must remain live"
        );
        let mut reaped = FixtureChild::new(
            Command::new("/bin/sh")
                .args(["-c", "exit 0"])
                .spawn()
                .unwrap(),
        );
        assert!(reaped.wait().unwrap().success());
        assert_eq!(
            reaped.cleanup(),
            FixtureCleanup::OwnershipUnknown,
            "no signal after waitid reports lost ownership/ECHILD"
        );
        assert!(unrelated.try_wait().unwrap().is_none());
        assert_eq!(unrelated.cleanup(), FixtureCleanup::KilledAndReaped);
    }

    #[test]
    fn parent_channel_loss_prevents_second_real_file_mutation() {
        let root = temp();
        let id = identity();
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut worker = fixture(
            "two-writes",
            None,
            Some(child.as_raw_fd()),
            &root,
            Some(&id),
        );
        drop(child);
        let first: live::Request = live::read_frame(&mut parent).unwrap();
        assert_eq!(first.sequence, 1);
        assert_eq!(first.identity, id);
        live::write_frame(
            &mut parent,
            &live::Response {
                version: 1,
                sequence: 1,
                nonce: first.nonce,
                approved: true,
            },
        )
        .unwrap();
        let second: live::Request = live::read_frame(&mut parent).unwrap();
        assert_eq!(second.sequence, 2);
        drop(parent);
        own_wait(&mut worker);
        assert_eq!(std::fs::read(root.join("writes")).unwrap(), b"1");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn denial_or_replayed_nonce_prevents_first_real_file_mutation() {
        for replay in [false, true] {
            let root = temp();
            let id = identity();
            let (mut parent, child) = UnixStream::pair().unwrap();
            parent
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut worker = fixture("denied", None, Some(child.as_raw_fd()), &root, Some(&id));
            drop(child);
            let request: live::Request = live::read_frame(&mut parent).unwrap();
            live::write_frame(
                &mut parent,
                &live::Response {
                    version: 1,
                    sequence: request.sequence,
                    nonce: if replay { Uid::new() } else { request.nonce },
                    approved: replay,
                },
            )
            .unwrap();
            own_wait(&mut worker);
            assert!(!root.join("writes").exists());
            std::fs::remove_dir_all(root).unwrap();
        }
    }

    fn actual_issuer_context(
        root: &Path,
    ) -> (
        Arc<RwLock<DesiredWorld>>,
        ProvisionIntent,
        live::JobIdentity,
    ) {
        let mut world = DesiredWorld::new();
        for value in [
            serde_json::json!({"kind":"StorageClass","metadata":{"name":"replicated"},"spec":{"provisioner":crate::storage_lifecycle::PROVISIONER,"reclaimPolicy":"Retain"}}),
            serde_json::json!({"kind":"PersistentVolumeClaim","metadata":{"name":"data","namespace":"a"},"spec":{"storageClassName":"replicated","accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"64Mi"}}}}),
        ] {
            world
                .apply(&serde_json::from_value(value).unwrap())
                .unwrap();
        }
        let uid = world.storage_identities.volumes[world.pvcs["a/data"].bound_pv.as_ref().unwrap()]
            .clone();
        let targets = std::array::from_fn(|_| crate::storage_controller::ReplicaTarget {
            node_uid: Uid::new(),
            boot_id: serde_json::from_value(serde_json::json!(
                "71cb439a-d59b-4d47-9058-2134d97ebd7f"
            ))
            .unwrap(),
        });
        let path = root.join("actual-state.json");
        crate::store::set_durability(crate::store::Durability::File {
            path: path.to_str().unwrap().into(),
        });
        crate::store::set_owns_state(true);
        let world = Arc::new(RwLock::new(world));
        let intent =
            crate::storage_controller::reserve_provision(&world, &uid, targets, Uid::new())
                .unwrap();
        assert!(crate::persist::load(path.to_str().unwrap()).is_ok());
        let id = live::JobIdentity {
            node_uid: intent.targets()[0].node_uid.clone(),
            boot_id: intent.targets()[0].boot_id.as_str().into(),
            volume_uid: uid,
            operation_uid: intent.operation_uid().clone(),
            attempt_uid: Uid::new(),
            binding_sha256: "a".repeat(64),
        };
        (world, intent, id)
    }
    fn actual_issuer_loss(root: &Path) {
        let (world, intent, id) = actual_issuer_context(root);
        let request = live::Request {
            version: 1,
            identity: id.clone(),
            sequence: 1,
            nonce: Uid::new(),
            boundary: "fixed-program".into(),
            detail_sha256: "b".repeat(64),
        };
        assert_eq!(
            live::parent_approval(&request, &id, &intent, &world).unwrap(),
            Some(true)
        );
        let lock = world.write().unwrap();
        assert_eq!(
            live::parent_approval(&request, &id, &intent, &world).unwrap(),
            None
        );
        drop(lock);
        // The identity snapshot remains unchanged. Current ownership loss alone
        // must revoke later boundaries; it is not a fake backend receipt.
        crate::store::set_owns_state(false);
        assert_eq!(
            live::parent_approval(&request, &id, &intent, &world).unwrap(),
            Some(false)
        );
        NativeAgent::assert_parent_trait_refuses_without_verified_mode(&world, &intent);
        crate::store::set_owns_state(true);
        let mut stale = id.clone();
        stale.boot_id = "b12c439a-d59b-4d47-9058-2134d97ebd7f".into();
        let stale_request = live::Request {
            identity: stale.clone(),
            ..request
        };
        assert!(live::parent_approval(&stale_request, &stale, &intent, &world).is_err());
    }
    #[test]
    fn unchanged_snapshot_is_not_authority_after_actual_issuer_owner_loss() {
        let root = temp();
        let mut child = fixture("issuer-loss", None, None, &root, None);
        own_wait(&mut child);
        std::fs::remove_dir_all(root).unwrap();
    }
    fn actual_issuer_flood(root: &Path) {
        let (world, intent, id) = actual_issuer_context(root);
        let (mut parent, child) = UnixStream::pair().unwrap();
        parent
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut broken = fixture(
            "flood-pending",
            None,
            Some(child.as_raw_fd()),
            root,
            Some(&id),
        );
        drop(child);
        let request: live::Request = live::read_frame(&mut parent).unwrap();
        let write_lock = world.write().unwrap();
        assert_eq!(
            live::parent_approval(&request, &id, &intent, &world).unwrap(),
            None,
            "actual live world contention must leave approval pending"
        );
        let mut buffer = Vec::with_capacity(live::CONTROL_BUFFER_MAX);
        let original_capacity = buffer.capacity();
        parent.write_all(b"F").unwrap();
        let mut bytes = [0u8; 4096];
        let size = parent.read(&mut bytes).unwrap();
        assert!(size > 0);
        assert!(
            live::append_control(&mut buffer, true, &bytes[..size]).is_err(),
            "pipelining while pending must refuse BEFORE append"
        );
        assert!(buffer.is_empty());
        assert_eq!(buffer.capacity(), original_capacity);
        assert!(buffer.capacity() <= live::CONTROL_BUFFER_MAX);
        drop(write_lock);
        drop(parent);
        own_wait(&mut broken);
    }
    #[test]
    fn pending_live_approval_flood_is_rejected_without_parent_buffer_growth() {
        let root = temp();
        let mut child = fixture("issuer-flood", None, None, &root, None);
        own_wait(&mut child);
        std::fs::remove_dir_all(root).unwrap();
    }
}
