//! Opt-in normal Watch cold-only runtime. This module never grants a writer,
//! initializes a dataset, creates pools/WireGuard, or resumes saved authority.
use super::{
    agent::NativeAgent,
    dispatcher::{self, ColdPreparedHeld, Dispatcher, Outcome, Ticket},
    lvm,
    private_fs::{self, Dir},
    replica, Config as PoolConfig, ResourceBudget,
};
#[path = "native_runtime_init.rs"]
pub(crate) mod init;
#[path = "native_runtime_mount.rs"]
pub(crate) mod mount;
#[path = "native_runtime_journal.rs"]
mod journal;
use crate::raft_node::storage_remote_core as core;
use crate::{
    reconcile::DesiredWorld,
    storage_boot::BootId,
    storage_identity::Uid,
    storage_lifecycle::{Phase, Volume},
    storage_remote_protocol::{
        self as protocol, Boundary, ExpectedColdJob, IssuerBook, JobKind, JobSpec, NodeJobReply,
        NodeJobRequest, NodeReadiness, VerifiedDirectory, VerifiedPeerFrame,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex, OnceLock, RwLock,
    },
    time::{Duration, Instant},
};

const JOB: Duration = Duration::from_secs(180);
const IO_WAIT: Duration = Duration::from_secs(2);
type IoWork = Box<dyn FnOnce() + Send + 'static>;
#[derive(Clone)]
struct Inspector {
    send: std::sync::mpsc::SyncSender<IoWork>,
    busy: Arc<AtomicUsize>,
}
static INSPECTOR: OnceLock<Inspector> = OnceLock::new();
static STARTED: AtomicBool = AtomicBool::new(false);
pub(crate) async fn commit_prepared_writer(prepared:crate::storage_pod_writer::PreparedPodWriterReservation)
    ->Result<crate::storage_pod_writer::CommittedPodWriterIntent,crate::store::CommitError>{
    let io=INSPECTOR.get().ok_or_else(||crate::store::CommitError::Unavailable("actual fixed native IO actor unavailable".into()))?;
    io.run(move||Ok(prepared.commit())).await.map_err(crate::store::CommitError::Unknown)?
}
impl Inspector {
    fn start() -> Result<Self, String> {
        let (send, receive) = std::sync::mpsc::sync_channel::<IoWork>(1);
        std::thread::Builder::new()
            .name("royak-native-runtime-io".into())
            .spawn(move || {
                while let Ok(work) = receive.recv() {
                    work();
                }
            })
            .map_err(|_| "cannot start fixed runtime I/O inspector")?;
        Ok(Self {
            send,
            busy: Arc::new(AtomicUsize::new(0)),
        })
    }
    async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        self.busy
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                if n < 2 {
                    Some(n + 1)
                } else {
                    None
                }
            })
            .map_err(|_| "runtime I/O worker plus one waiter are active/unknown")?;
        let busy = self.busy.clone();
        let (send, receive) = tokio::sync::oneshot::channel();
        let job = Box::new(move || {
            struct Release(Arc<AtomicUsize>);
            impl Drop for Release {
                fn drop(&mut self) {
                    self.0.fetch_sub(1, Ordering::AcqRel);
                }
            }
            let _release = Release(busy);
            let _ = send.send(work());
        });
        if self.send.try_send(job).is_err() {
            self.busy.fetch_sub(1, Ordering::AcqRel);
            return Err("runtime inspector queue full/unavailable".into());
        }
        // Timeout never owns/releases the worker's admission or actual work.
        tokio::time::timeout(IO_WAIT, receive)
            .await
            .map_err(|_| "runtime I/O UNKNOWN; owned worker retains admission")?
            .map_err(|_| "runtime inspector result lost; UNKNOWN")?
    }
}
pub(super) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(super) fn reserved_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute()
        || !path.starts_with("/var/lib/royak/storage")
        || path == Path::new("/var/lib/royak/storage")
        || path.components().any(|p| {
            !matches!(
                p,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(
            "native runtime paths must be canonical descendants of reserved storage".into(),
        );
    }
    Ok(())
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Configuration {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    initialization_mode: Option<InitializationMode>,
    #[serde(default,skip_serializing_if="Option::is_none")]
    attachment_mode:Option<AttachmentMode>,
    pool_config: PathBuf,
    journal_root: PathBuf,
    delegated_cgroup_root: PathBuf,
    helper_image: PathBuf,
    helper_sha256: String,
    interface: String,
    rpc_port: u16,
    storage_class_allowlist: Vec<String>,
    minor_first: u16,
    minor_last: u16,
    port_first: u16,
    port_last: u16,
    resource_budget: ResourceBudget,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum InitializationMode {
    InitializeOffline,
}
#[derive(Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
enum AttachmentMode {AttachManagedEpochOne}
impl Configuration {
    fn initializes(&self) -> bool {
        (self.version==2 || self.version==3) && self.initialization_mode==Some(InitializationMode::InitializeOffline)
    }
    fn attaches(&self)->bool{self.version==3 && self.initialization_mode==Some(InitializationMode::InitializeOffline)
        && self.attachment_mode==Some(AttachmentMode::AttachManagedEpochOne)}
}
pub(crate) struct ApprovedConfiguration {
    config: Configuration,
    path: PathBuf,
    hash: String,
    pool: PoolConfig,
    pool_hash: String,
}
fn policy_fields(config: &Configuration) -> Result<(), String> {
    if !matches!(
        (config.version, config.initialization_mode,config.attachment_mode),
        (1,None,None) | (2,Some(InitializationMode::InitializeOffline),None)
            | (3,Some(InitializationMode::InitializeOffline),Some(AttachmentMode::AttachManagedEpochOne))
    ) || config.rpc_port == 0
        || config.interface.is_empty()
        || config.interface.len() > 15
        || !config
            .interface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        || !(512..=32767).contains(&config.minor_first)
        || config.minor_last < config.minor_first
        || config.minor_last - config.minor_first > 15
        || config.minor_last > 32767
        || !(20000..=59999).contains(&config.port_first)
        || config.port_last < config.port_first
        || config.port_last - config.port_first > 15
        || config.port_last > 59999
        || config.storage_class_allowlist.is_empty()
        || config.storage_class_allowlist.len() > 32
        || config
            .storage_class_allowlist
            .iter()
            .any(|n| n.is_empty() || n.len() > 253)
        || config
            .storage_class_allowlist
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != config.storage_class_allowlist.len()
        || config.helper_sha256.len() != 64
        || !config
            .helper_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || config.resource_budget
            != (ResourceBudget {
                pids_max: 64,
                memory_max_bytes: 256 * 1024 * 1024,
                cpu_quota_us: 100_000,
                cpu_period_us: 100_000,
            })
    {
        return Err("invalid fixed cold runtime infrastructure policy".into());
    }
    for path in [
        &config.pool_config,
        &config.journal_root,
        &config.helper_image,
    ] {
        reserved_path(path)?;
    }
    Ok(())
}
fn policy(config: &Configuration) -> Result<(), String> {
    policy_fields(config)?;
    if !config.delegated_cgroup_root.starts_with("/sys/fs/cgroup")
        || config.delegated_cgroup_root == Path::new("/sys/fs/cgroup")
        || std::fs::canonicalize(&config.delegated_cgroup_root)
            .map_err(|_| "predelegated cgroup root absent")?
            != config.delegated_cgroup_root
    {
        return Err("exact canonical predelegated cgroup root required".into());
    }
    Ok(())
}
pub(crate) fn configure(
    path: &Path,
    clustered: bool,
    docker: bool,
    tls: bool,
) -> Result<ApprovedConfiguration, String> {
    if !cfg!(target_os = "linux")
        || unsafe { libc::geteuid() } != 0
        || !clustered
        || !docker
        || !tls
    {
        return Err(
            "native runtime requires Linux root, clustered Docker and explicit TLS; no fallback"
                .into(),
        );
    }
    if std::env::var_os("ROYAK_STORAGE_QUALIFICATION_FD").is_some() {
        return Err("normal runtime cannot share the qualification actuator".into());
    }
    reserved_path(path)?;
    let raw = private_fs::read_private(path)?;
    let config: Configuration = serde_json::from_slice(&raw)
        .map_err(|_| "invalid strict private native runtime configuration")?;
    policy(&config)?;
    let pool = PoolConfig::load(&config.pool_config)?;
    let pool_hash = digest(&private_fs::read_private(&config.pool_config)?);
    Ok(ApprovedConfiguration {
        config,
        path: path.to_owned(),
        hash: digest(&raw),
        pool,
        pool_hash,
    })
}

pub(crate) struct Runtime {
    _shared: Arc<Shared>,
    _listener: tokio::task::JoinHandle<()>,
    _controller: tokio::task::JoinHandle<()>,
}
pub(crate) struct Shared {
    controller_alive:AtomicBool,
    config: Configuration,
    config_path: PathBuf,
    config_hash: String,
    pool: PoolConfig,
    pool_file_hash: String,
    world: Arc<RwLock<DesiredWorld>>,
    io: Inspector,
    journal: Arc<journal::Journal>,
    dispatcher: Dispatcher,
    incoming: AtomicBool,
    expected: Mutex<BTreeMap<Uid, Arc<ExpectedColdJob>>>,
    issuers: Mutex<IssuerBook>,
    held: Mutex<Option<(Uid, String, ColdPreparedHeld, bool)>>,
    unknown: Mutex<Option<(Option<Uid>, String)>>,
    receiver_job: Mutex<Option<(Uid, String, std::time::Instant)>>,
    remote_held: Mutex<Vec<RemoteHeld>>,
    unknown_lease: Mutex<Option<std::fs::File>>,
    pipeline_invalid: Arc<AtomicBool>,
    pipeline_deadline: Mutex<Option<Instant>>,
    initialization_owner: Mutex<Option<Arc<dispatcher::distributed_init::HeldInitializationOwner>>>,
    expected_init: Mutex<BTreeMap<Uid, Arc<init::ExpectedInitJob>>>,
    init_issuers: Mutex<protocol::InitIssuerBook>,
    init_receiver_busy: AtomicBool,
    init_receiver_job: Mutex<Option<(Uid, String, JobSpec)>>,
    serial: Arc<tokio::sync::Semaphore>,
    waiter: Arc<tokio::sync::Semaphore>,
}
impl Shared {
    pub(super) async fn check_attach_config(&self)->Result<(),String> {
        if !self.config.attaches(){return Err("first managed attachment requires explicit root-private runtime v3 opt-in".into());}
        let path=self.config_path.clone();let cfg_hash=self.config_hash.clone();
        let pool_path=self.config.pool_config.clone();let pool_hash=self.pool_file_hash.clone();
        self.io.run(move|| {
            if digest(&private_fs::read_private(&path)?)!=cfg_hash || digest(&private_fs::read_private(&pool_path)?)!=pool_hash {
                return Err("attach runtime private config/pool changed; UNKNOWN".into());
            }Ok(())
        }).await
    }
    pub(super) fn runtime_cancellation(&self) -> Arc<AtomicBool> {
        self.pipeline_invalid.clone()
    }
    pub(super) fn shorten_pipeline_deadline(&self, accepted: Instant) -> Result<(), String> {
        let mut original = self
            .pipeline_deadline
            .lock()
            .map_err(|_| "pipeline deadline poisoned")?;
        if let Some(limit) = original.as_mut() {
            *limit = (*limit).min(accepted);
        }
        Ok(())
    }
    fn dispatcher_configuration(&self) -> dispatcher::Config {
        dispatcher::Config {
            journal_root: self.config.journal_root.join("dispatch"),
            delegated_cgroup_root: self.config.delegated_cgroup_root.clone(),
            node_uid: self.pool.node_uid.clone(),
            helper_image: self.config.helper_image.clone(),
            helper_sha256: self.config.helper_sha256.clone(),
            deadline: JOB,
            budget: self.config.resource_budget.clone(),
        }
    }
    pub(super) fn pipeline_deadline(&self) -> Result<Option<Instant>, String> {
        if self.pipeline_invalid.load(Ordering::Acquire) {
            return Err("pipeline is UNKNOWN/quarantined".into());
        }
        let deadline = *self
            .pipeline_deadline
            .lock()
            .map_err(|_| "pipeline deadline poisoned")?;
        if deadline.is_some_and(|limit| Instant::now() >= limit) {
            return Err("original initialization pipeline deadline expired".into());
        }
        Ok(deadline)
    }
    pub(super) fn retain_unknown_lease(&self, lease: std::fs::File) {
        // Recovery of this mutex does not grant authority. It only prevents a
        // panic/drop path from releasing the exact already-owned node lock.
        let mut held = self.unknown_lease.lock().unwrap_or_else(|p| p.into_inner());
        if held.is_none() {
            *held = Some(lease);
        }
    }
    pub(super) fn world(&self) -> &Arc<RwLock<DesiredWorld>> {
        &self.world
    }
    pub(super) async fn check_config(&self) -> Result<(), String> {
        self.pipeline_deadline()?;
        let path = self.config_path.clone();
        let cfg_hash = self.config_hash.clone();
        let pool_path = self.config.pool_config.clone();
        let pool_hash = self.pool_file_hash.clone();
        self.io
            .run(move || {
                if digest(&private_fs::read_private(&path)?) != cfg_hash
                    || digest(&private_fs::read_private(&pool_path)?) != pool_hash
                {
                    return Err("runtime configuration or approved pool changed".into());
                }
                Ok(())
            })
            .await?;
        self.pipeline_deadline()?;
        Ok(())
    }
    pub(super) fn directory_for(
        &self,
        observed: &core::CoreObservation,
    ) -> Result<VerifiedDirectory, String> {
        let dto = self
            .world
            .try_read()
            .map_err(|_| "runtime actual World busy")?
            .storage_node_directory
            .directory()
            .cloned()
            .ok_or("runtime directory absent")?;
        VerifiedDirectory::from_core(observed, dto)
    }
    pub(super) async fn call(
        &self,
        path: &str,
        bytes: &[u8],
        peer: &Uid,
        directory: &VerifiedDirectory,
    ) -> Result<VerifiedPeerFrame, String> {
        super::remote_transport::call(
            path,
            bytes,
            &self.config.interface,
            &self.pool.node_uid,
            peer,
            self.config.rpc_port,
            directory,
        )
        .await
    }
    async fn readiness(&self) -> Result<NodeReadiness, String> {
        self.check_config().await?;
        let view = core::runtime_view(false).await?;
        if view.local() != &self.pool.node_uid
            || view.directory().cluster_id != self.pool.cluster_id
        {
            return Err("runtime approved pool differs from actual enrolled local identity".into());
        }
        let config = self.config.clone();
        let pool = self.pool.clone();
        let directory = view.directory().sha256()?;
        let available = !self.incoming.load(Ordering::Acquire) && !self.dispatcher.busy();
        let ready = self
            .io
            .run(move || {
                dispatcher::check_helper_image(&config.helper_image, &config.helper_sha256)?;
                let slot = if available {
                    super::job_cgroup::runtime_slot_available(
                        &config.delegated_cgroup_root,
                        &pool.node_uid,
                    )?
                } else {
                    false
                };
                lvm::runtime_readiness(
                    &pool,
                    directory,
                    config.interface,
                    config.minor_first,
                    config.minor_last,
                    config.port_first,
                    config.port_last,
                    available && slot,
                )
            })
            .await?;
        if &ready.boot != view.boot() {
            return Err("pool boot changed during readiness".into());
        }
        self.pipeline_deadline()?;
        Ok(ready)
    }
    fn unknown(&self, job: Option<Uid>, code: &str) {
        self.pipeline_invalid.store(true, Ordering::Release);
        mount::runtime_unknown(&self.world);
        if let Ok(owner) = self.initialization_owner.lock() {
            if let Some(owner) = owner.as_ref() {
                owner.unknown();
            }
        }
        if let Ok(mut state) = self.unknown.lock() {
            *state = Some((job, code.to_string()));
        }
        // No incoming/busy reset. A later status is not a grant or recovery.
    }
    async fn handle(
        self: &Arc<Self>,
        path: &str,
        peer: VerifiedPeerFrame,
        request_deadline: Instant,
    ) -> Result<Vec<u8>, String> {
        let _wait = self
            .waiter
            .clone()
            .try_acquire_owned()
            .map_err(|_| "one privileged waiter already present")?;
        let serial = tokio::time::timeout(
            request_deadline.saturating_duration_since(Instant::now()),
            self.serial.clone().acquire_owned(),
        )
        .await
        .map_err(|_| "privileged storage wait expired")?
        .map_err(|_| "privileged storage service closed")?;
        drop(_wait);
        let attach_path=path==protocol::attachment::PATH || path==protocol::attachment::OFFER_PATH || path==protocol::attachment::MOUNTED_PATH;
        let terminal_path=path==mount::consumer::terminal::PATH;
        // Attach lifetime is distinct from the one-shot cold/init pipeline.
        // It still pins the SAME private config/pool on the fixed IO worker.
        if terminal_path {
            // Old operational UNKNOWN is monotonic and is not reset to
            // READY. The genuine terminal handler separately requires the
            // original live actor, actual rooted owner and fresh drain-only
            // session; this branch grants no effect from config presence.
            if !self.config.attaches(){return Err("terminal private route requires explicit nativev3".into());}
        }else if attach_path {self.check_attach_config().await?;} else {self.check_config().await?;}
        let result = if terminal_path {
            mount::consumer::terminal::wire::handle(self,peer,request_deadline).await
        }else if path==protocol::attachment::OFFER_PATH {
            mount::parent::node_request(self,peer,request_deadline).await
        } else if attach_path {
            mount::parent::authorize(self,path,peer).await
        } else if path == protocol::NODE_JOB_PATH {
            self.node_job(peer, request_deadline).await
        } else if path == protocol::GRANT_PATH || path == protocol::BOUNDARY_PATH {
            self.authorize(path, peer).await
        } else {
            Err("unknown private storage route".into())
        };
        drop(serial);
        result
    }
    async fn authorize(&self, path: &str, peer: VerifiedPeerFrame) -> Result<Vec<u8>, String> {
        if self.config.initializes() {
            self.pipeline_deadline()?
                .ok_or("initialization pipeline has not started")?;
        }
        let phase = self
            .expected_init
            .lock()
            .map_err(|_| "expected init book poisoned")?
            .get(peer.sender())
            .cloned();
        if let Some(expected) = phase {
            let before =
                core::observe_issuer(&expected.spec().owner.volume_uid, peer.read_challenge())
                    .await?;
            let directory = self.directory_for(&before)?;
            expected.require_current(&before, &directory)?;
            if path == protocol::GRANT_PATH {
                let journal = self.journal.clone();
                let job = expected.clone();
                let request = digest(peer.body());
                self.io
                    .run(move || journal.issuer_init(&job, &request))
                    .await?;
                let current =
                    core::observe_issuer(&expected.spec().owner.volume_uid, peer.read_challenge())
                        .await?;
                let directory = self.directory_for(&current)?;
                expected.require_current(&current, &directory)?;
                return self
                    .init_issuers
                    .lock()
                    .map_err(|_| "init issuer book poisoned")?
                    .grant_expected(&expected, peer, &current, &directory, Instant::now());
            }
            return self
                .init_issuers
                .lock()
                .map_err(|_| "init issuer book poisoned")?
                .boundary_expected(&expected, peer, &before, &directory, Instant::now());
        }
        // Exact expected registration is required before obtaining authority.
        let expected = self
            .expected
            .lock()
            .map_err(|_| "expected job book poisoned")?
            .get(peer.sender())
            .cloned()
            .ok_or("no acknowledged controller job for this node")?;
        if path == protocol::GRANT_PATH {
            expected.require_request(&peer)?;
        }
        let observation =
            core::observe_issuer(&expected.spec().owner.volume_uid, peer.read_challenge()).await?;
        let directory = self.directory_for(&observation)?;
        if path == protocol::GRANT_PATH {
            let request = digest(peer.body());
            let journal = self.journal.clone();
            let registration = expected.clone();
            self.io
                .run(move || journal.issuer(&registration, &request))
                .await?;
            // Journal/network waits consume barrier age. Refresh this SAME
            // request after fsync, never grant from the stale observation.
            let observation =
                core::observe_issuer(&expected.spec().owner.volume_uid, peer.read_challenge())
                    .await?;
            let directory = self.directory_for(&observation)?;
            let original = self.pipeline_deadline()?;
            let mut book = self.issuers.lock().map_err(|_| "issuer book poisoned")?;
            if let Some(original) = original {
                book.grant_expected_deadline(
                    &expected,
                    peer,
                    &observation,
                    &directory,
                    Instant::now(),
                    original,
                )
            } else {
                book.grant_expected(&expected, peer, &observation, &directory, Instant::now())
            }
        } else {
            self.issuers
                .lock()
                .map_err(|_| "issuer book poisoned")?
                .boundary(peer, &observation, &directory, std::time::Instant::now())
        }
    }
    async fn node_job(
        self: &Arc<Self>,
        peer: VerifiedPeerFrame,
        request_deadline: Instant,
    ) -> Result<Vec<u8>, String> {
        let request: NodeJobRequest = protocol::decode_node(peer.body())?;
        let reply = match request {
            NodeJobRequest::InspectReadiness { nonce, expected } => {
                let observation = self.readiness().await?;
                let applied = if let Some(spec) = expected {
                    if peer.sender() != &spec.issuer_node_uid
                        || peer.receiver() != &spec.target_node_uid
                        || spec.target_node_uid != self.pool.node_uid
                        || spec.kind != JobKind::PrepareVirginOffline
                    {
                        return Err("exact postcommit readiness reached wrong issuer/target".into());
                    }
                    let deadline = request_deadline
                        .min(Instant::now() + Duration::from_millis(core::MAX_STORAGE_BOUNDARY_MS));
                    core::wait_applied_hint(&spec.issuer_revision, deadline).await?;
                    let actual = core::observe_local_async(&spec.owner.volume_uid).await?;
                    let directory = self.directory_for(&actual)?;
                    spec.check_observed(&actual, &directory)?;
                    if actual.local_node_uid() != Some(&spec.target_node_uid)
                        || actual.actual_boot() != &spec.target_boot
                        || observation.boot != *actual.actual_boot()
                        || Instant::now() >= deadline
                    {
                        return Err(
                            "exact readiness changed boot or exceeded original request budget"
                                .into(),
                        );
                    }
                    Some(protocol::AppliedColdObservation {
                        expected_spec_sha256: digest(&protocol::encode_node(&spec)?),
                        scope_sha256: actual.scope_sha256().to_string(),
                        revision: actual.revision().clone(),
                    })
                } else {
                    None
                };
                NodeJobReply::Readiness {
                    nonce,
                    observation,
                    applied,
                }
            }
            NodeJobRequest::OfferVirginOffline {
                spec,
                pool_sha256,
                plan,
            } => {
                if peer.sender() != &spec.issuer_node_uid
                    || peer.receiver() != &spec.target_node_uid
                    || spec.target_node_uid != self.pool.node_uid
                    || spec.kind != JobKind::PrepareVirginOffline
                {
                    return Err("offer did not arrive from exact issuer to target".into());
                }
                let ready = self.readiness().await?;
                if !ready.available
                    || ready.pool_sha256 != pool_sha256
                    || ready.boot != spec.target_boot
                {
                    return Err("offer pool/boot/slot changed".into());
                }
                let local = core::observe_local_async(&spec.owner.volume_uid).await?;
                let directory = self.directory_for(&local)?;
                // challenge validates offered scope/current actual Core, but
                // creates NO accepted grant or physical mode.
                let _ = protocol::ReceiverSession::challenge(
                    spec.clone(),
                    &local,
                    &directory,
                    std::time::Instant::now(),
                )?;
                let actual_plan =
                    replica::Plan::from_runtime_offer(plan, &self.pool, &spec, &directory, &ready)?;
                self.incoming
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .map_err(|_| "receiver cold slot already reserved")?;
                if self.config.initializes() {
                    let mut deadline = self
                        .pipeline_deadline
                        .lock()
                        .map_err(|_| "pipeline deadline poisoned")?;
                    if deadline.is_some() {
                        return Err("receiver pipeline cannot be restarted/renewed".into());
                    }
                    *deadline = Some(
                        Instant::now()
                            .checked_add(Duration::from_millis(spec.maximum_duration_ms))
                            .ok_or("original receiver cold deadline overflow")?,
                    );
                }
                let encoded = protocol::encode_node(&spec)?;
                let spec_hash = digest(&encoded);
                let journal = self.journal.clone();
                let recorded = spec.clone();
                let offer_hash = spec_hash.clone();
                self.io
                    .run(move || journal.receiver(&recorded, &offer_hash))
                    .await?;
                *self
                    .receiver_job
                    .lock()
                    .map_err(|_| "receiver job poisoned")? = Some((
                    spec.job_uid.clone(),
                    spec_hash.clone(),
                    std::time::Instant::now(),
                ));
                let shared = self.clone();
                let launched = spec.clone();
                // A transport disconnect cannot own/drop this admitted task.
                tokio::spawn(async move {
                    if let Err(_error) = shared.run_receiver(launched.clone(), actual_plan).await {
                        shared.unknown(Some(launched.job_uid), "RECEIVER_UNKNOWN");
                    }
                });
                NodeJobReply::Offered {
                    job_uid: spec.job_uid,
                    spec_sha256: spec_hash,
                }
            }
            NodeJobRequest::InspectHeld {
                job_uid,
                spec_sha256,
            } => {
                let held = self
                    .held
                    .lock()
                    .map_err(|_| "receiver held state poisoned")?;
                if let Some((actual, hash, held, durable)) = held.as_ref() {
                    if actual != &job_uid || hash != &spec_sha256 {
                        return Err("held query differs from exact job".into());
                    }
                    if *durable {
                        NodeJobReply::Held {
                            job_uid,
                            spec_sha256,
                            evidence_sha256: digest(held.diagnostics()?),
                            reference: if self.config.initializes() {
                                Some(held.validated_reference()?)
                            } else {
                                None
                            },
                        }
                    } else {
                        NodeJobReply::Unknown {
                            job_uid: Some(job_uid),
                            code: "HELD_CLOSEOUT_UNKNOWN".into(),
                        }
                    }
                } else {
                    let active = self
                        .receiver_job
                        .lock()
                        .map_err(|_| "receiver state poisoned")?;
                    if self
                        .unknown
                        .lock()
                        .map_err(|_| "receiver unknown state poisoned")?
                        .is_none()
                        && active.as_ref().is_some_and(|(job, hash, started)| {
                            job == &job_uid && hash == &spec_sha256 && started.elapsed() < JOB
                        })
                    {
                        NodeJobReply::WorkingObservation {
                            job_uid,
                            spec_sha256,
                        }
                    } else {
                        NodeJobReply::Unknown {
                            job_uid: Some(job_uid),
                            code: "NOT_HELD_OR_UNKNOWN".into(),
                        }
                    }
                }
            }
            request @ (NodeJobRequest::ArmInitialization { .. }
            | NodeJobRequest::InspectInitialization { .. }
            | NodeJobRequest::OfferInitialization { .. }
            | NodeJobRequest::InspectPhase { .. }
            | NodeJobRequest::AcknowledgeDetached { .. }) => {
                return init::handle(self.clone(), peer, request, request_deadline).await;
            }
        };
        protocol::encode_node(&reply)
    }
    async fn run_receiver(
        self: &Arc<Self>,
        spec: JobSpec,
        plan: replica::Plan,
    ) -> Result<(), String> {
        let parent = dispatcher::RemoteColdParent::establish(self.clone(), spec.clone()).await?;
        let agent = NativeAgent::from_runtime(self.pool.clone(), plan, parent.intent())?;
        let ticket = self.dispatcher.submit_runtime_remote(parent, agent)?;
        let held = wait_ticket(ticket).await?;
        let evidence = digest(held.diagnostics()?);
        let journal = self.journal.clone();
        let job = spec.job_uid.clone();
        *self.held.lock().map_err(|_| "held state poisoned")? = Some((
            spec.job_uid.clone(),
            digest(&protocol::encode_node(&spec)?),
            held,
            false,
        ));
        self.io
            .run(move || journal.phase(&job, "HELD", &evidence))
            .await?;
        self.held
            .lock()
            .map_err(|_| "held state poisoned")?
            .as_mut()
            .ok_or("actual held lease lost")?
            .3 = true;
        Ok(())
    }
}

async fn wait_ticket(ticket: Ticket) -> Result<ColdPreparedHeld, String> {
    let started = std::time::Instant::now();
    loop {
        match ticket.try_result()? {
            Some(Outcome::ColdPreparedHeld { held }) => return Ok(held),
            Some(_) => return Err("native cold outcome UNKNOWN/non-held".into()),
            None => {}
        }
        if started.elapsed() >= JOB {
            ticket.cancel();
            return Err("native cold worker deadline UNKNOWN".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
pub(super) async fn inspect_transport(
    directory: VerifiedDirectory,
    local: Uid,
    interface: String,
) -> Result<String, String> {
    INSPECTOR
        .get()
        .ok_or("normal runtime inspector absent")?
        .run(move || super::remote_transport::inspect_runtime(&directory, &local, &interface))
        .await
}

pub(crate) async fn start(
    approved: ApprovedConfiguration,
    world: Arc<RwLock<DesiredWorld>>,
    interval: u64,
) -> Result<Runtime, String> {
    if STARTED.swap(true, Ordering::AcqRel) {
        return Err("native runtime already started or UNKNOWN".into());
    }
    let io = Inspector::start()?;
    INSPECTOR
        .set(io.clone())
        .map_err(|_| "native runtime inspector already installed")?;
    let handle = crate::raft_node::RAFT
        .get()
        .ok_or("actual sealed Raft not ready")?;
    if !core::is_actual_world(&world) {
        return Err("native runtime refuses caller World".into());
    }
    // Only observation/readiness waiting on existing Raft changes; no repeated
    // commit, enrollment or physical operation is issued here.
    let mut metrics = handle.raft.metrics();
    let view = tokio::time::timeout(crate::raft_node::COMMIT_TIMEOUT, async {
        loop {
            if let Ok(view) = core::runtime_view(false).await {
                break Ok::<_, String>(view);
            }
            metrics
                .changed()
                .await
                .map_err(|_| "runtime Raft readiness stream ended")?;
        }
    })
    .await
    .map_err(|_| "runtime directory readiness UNKNOWN")??;
    if view.local() != &approved.pool.node_uid
        || view.directory().cluster_id != approved.pool.cluster_id
    {
        return Err("approved pool is not actual local cluster/node".into());
    }
    let directory = VerifiedDirectory::from_runtime(&view)?;
    let root = approved.config.journal_root.clone();
    let cluster = approved.pool.cluster_id.clone();
    let node = approved.pool.node_uid.clone();
    let boot = view.boot().clone();
    let hash = approved.hash.clone();
    let journal = Arc::new(
        io.run(move || journal::Journal::open(&root, cluster, node, boot, hash))
            .await?,
    );
    let fresh = startup_fresh(journal.fresh()?, view.volumes());
    let dispatcher = Dispatcher::start(dispatcher::Config {
        journal_root: approved.config.journal_root.join("dispatch"),
        delegated_cgroup_root: approved.config.delegated_cgroup_root.clone(),
        node_uid: approved.pool.node_uid.clone(),
        helper_image: approved.config.helper_image.clone(),
        helper_sha256: approved.config.helper_sha256.clone(),
        deadline: JOB,
        budget: approved.config.resource_budget.clone(),
    })?;
    let shared = Arc::new(Shared {
        controller_alive:AtomicBool::new(false),
        config: approved.config,
        config_path: approved.path,
        config_hash: approved.hash,
        pool: approved.pool,
        pool_file_hash: approved.pool_hash,
        world,
        io,
        journal,
        dispatcher,
        incoming: AtomicBool::new(!fresh),
        expected: Mutex::new(BTreeMap::new()),
        issuers: Mutex::new(IssuerBook::new()),
        held: Mutex::new(None),
        unknown: Mutex::new(None),
        receiver_job: Mutex::new(None),
        remote_held: Mutex::new(Vec::new()),
        unknown_lease: Mutex::new(None),
        pipeline_invalid: Arc::new(AtomicBool::new(false)),
        pipeline_deadline: Mutex::new(None),
        initialization_owner: Mutex::new(None),
        expected_init: Mutex::new(BTreeMap::new()),
        init_issuers: Mutex::new(protocol::InitIssuerBook::new()),
        init_receiver_busy: AtomicBool::new(false),
        init_receiver_job: Mutex::new(None),
        serial: Arc::new(tokio::sync::Semaphore::new(1)),
        waiter: Arc::new(tokio::sync::Semaphore::new(1)),
    });
    let _ = shared.readiness().await?; // Actual pool match before listener opens.
    let listener = server(shared.clone(), directory).await?;
    let coordinator = shared.clone();
    let controller = tokio::spawn(async move {
        let _original_controller=mount::consumer::terminal::OriginalControllerGuard::enter(coordinator.clone());
        if !fresh {
            coordinator.unknown(None, "STARTUP_UNRESOLVED");
            if coordinator.config.attaches(){mount::consumer::terminal::park_original_controller(coordinator.clone(),interval).await;}
            return;
        }
        if let Err(_error) = control(coordinator.clone(), interval).await {
            coordinator.unknown(None, "CONTROLLER_UNKNOWN");
            if coordinator.config.attaches(){mount::consumer::terminal::park_original_controller(coordinator.clone(),interval).await;}
            return;
        }
        if coordinator.config.attaches() {
            if let Err(_error)=mount::normal::wait_for_post_init_release(&coordinator,interval).await {
                coordinator.unknown(None,"ATTACH_HANDOFF_UNKNOWN");
                mount::consumer::terminal::park_original_controller(coordinator.clone(),interval).await;
                return;
            }
            if let Err(_error)=mount::normal::run(coordinator.clone(),interval).await {
                coordinator.unknown(None,"ATTACH_CONTROLLER_UNKNOWN");
            }
            mount::consumer::terminal::park_original_controller(coordinator.clone(),interval).await;
        }
    });
    Ok(Runtime {
        _shared: shared,
        _listener: listener,
        _controller: controller,
    })
}

/// Authenticated status handle only; it cannot become local retained lineage,
/// VerifiedVirginSet or any lifecycle receipt, even though the receiver holds
/// an actual lease. No Deserialize or raw status-only constructor exists.
struct RemoteHeld {
    _node: Uid,
    _job: Uid,
    _spec_sha256: String,
    _evidence_sha256: String,
    _transport: VerifiedPeerFrame,
    _reference: Option<crate::storage_lifecycle::generation::VirginReplicaRef>,
}
fn startup_fresh(journal_fresh: bool, volumes: &[Volume]) -> bool {
    journal_fresh
        && !volumes
            .iter()
            .any(|volume| volume.phase() == Phase::Provisioning)
}

fn eligible(shared: &Shared, volume: &Volume) -> Result<bool, String> {
    if volume.phase() != Phase::PendingProvision
        || volume.epoch() != 0
        || volume.assignment().is_some()
        || volume.data_generation().is_some()
    {
        return Ok(false);
    }
    let world = shared
        .world
        .try_read()
        .map_err(|_| "candidate world busy")?;
    let pv = world
        .pvs
        .get(&volume.owner().pv_name)
        .ok_or("candidate PV absent")?;
    let class = world
        .storage_classes
        .get(&pv.storage_class)
        .ok_or("candidate class absent")?;
    Ok(class.provisioner == crate::storage_lifecycle::PROVISIONER
        && shared
            .config
            .storage_class_allowlist
            .contains(&pv.storage_class))
}
fn capacity(ready: &NodeReadiness, requested: u64) -> Result<(), String> {
    if !ready.available || requested > ready.max_volume_bytes || ready.extent_bytes == 0 {
        return Err("cold pool unavailable or volume/extent limit invalid".into());
    }
    let bytes = requested
        .checked_add(128 * 1024 * 1024)
        .and_then(|n| n.checked_add(ready.extent_bytes - 1))
        .map(|n| n / ready.extent_bytes * ready.extent_bytes)
        .ok_or("cold capacity accounting overflow")?;
    if bytes > ready.free_bytes
        || ready
            .managed_bytes
            .checked_add(bytes)
            .is_none_or(|n| n > ready.max_managed_bytes)
    {
        return Err("cold capacity/quota unavailable".into());
    }
    Ok(())
}
async fn collect_readiness(
    shared: &Shared,
    view: &core::RuntimeView,
    directory: &VerifiedDirectory,
    requested: u64,
) -> Result<[NodeReadiness; 3], String> {
    let mut ready = Vec::with_capacity(3);
    for pin in directory.dto_nodes() {
        let observation = if &pin.node_uid == view.local() {
            shared.readiness().await?
        } else {
            let nonce = Uid::new();
            let request = protocol::encode_node(&NodeJobRequest::InspectReadiness {
                nonce: nonce.clone(),
                expected: None,
            })?;
            let peer = shared
                .call(protocol::NODE_JOB_PATH, &request, &pin.node_uid, &directory)
                .await?;
            match protocol::decode_node(peer.body())? {
                NodeJobReply::Readiness {
                    nonce: returned,
                    observation,
                    ..
                } if returned == nonce => observation,
                _ => return Err("peer did not return exact readiness nonce".into()),
            }
        };
        if observation.version != 1
            || observation.node_uid != pin.node_uid
            || observation.directory_sha256 != directory.digest()
        {
            return Err("readiness node/directory differs".into());
        }
        capacity(&observation, requested)?;
        ready.push(observation);
    }
    let ready: [NodeReadiness; 3] = ready
        .try_into()
        .map_err(|_| "exactly three readiness observations required")?;
    Ok(ready)
}

async fn control(shared: Arc<Shared>, interval: u64) -> Result<(), String> {
    if interval == 0 {
        return Err("normal cold controller requires positive existing Watch cadence".into());
    }
    let mut waiting = false;
    let (view, volume, directory, before, ready) = loop {
        let view = core::runtime_view(false).await?;
        if view
            .volumes()
            .iter()
            .any(|v| v.phase() == Phase::Provisioning)
        {
            return Ok(());
        }
        let leader = crate::raft_node::RAFT
            .get()
            .ok_or("actual Raft absent")?
            .node_id
            == view.revision().leader_raft_id;
        let mut selected = None;
        if leader {
            for volume in view.volumes() {
                if eligible(&shared, volume)? {
                    selected = Some(volume.clone());
                    break;
                }
            }
        }
        if let Some(volume) = selected {
            let directory = VerifiedDirectory::from_runtime(&view)?;
            let before = core::observe_local_async(volume.uid()).await?;
            match collect_readiness(&shared, &view, &directory, volume.capacity_bytes()).await {
                Ok(ready) => break (view, volume, directory, before, ready),
                Err(_) => {
                    if !waiting {
                        eprintln!(
                            "[storage-native] readiness unavailable; no provisioning intent issued"
                        );
                        waiting = true;
                    }
                }
            }
        }
        // Readiness is pure observation. This is the existing Watch cadence,
        // never a repeated reservation/grant/offer/physical operation.
        tokio::time::sleep(Duration::from_secs(interval)).await;
    };
    let minor = ready
        .iter()
        .map(|r| r.minor_first)
        .max()
        .ok_or("no minor range")?;
    let port = ready
        .iter()
        .map(|r| r.port_first)
        .max()
        .ok_or("no port range")?;
    if ready
        .iter()
        .any(|r| minor > r.minor_last || port > r.port_last)
    {
        return Err("no approved common DRBD slot".into());
    }
    let operation = Uid::new();
    let run = Uid::new();
    let mut secret = [0u8; 24];
    use rand::RngCore;
    rand::rngs::OsRng
        .try_fill_bytes(&mut secret)
        .map_err(|_| "CSPRNG unavailable")?;
    let secret = secret
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let plans = ready
        .iter()
        .map(|local| {
            replica::Plan::for_runtime(
                local,
                volume.owner(),
                &operation,
                &ready,
                &directory,
                minor,
                port,
                &secret,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    // No caller supplied per-volume path/plan, no secret in argv/env/status.
    let payload = serde_json::json!({"version":1,"run":run,"owner":volume.owner(),"operation":operation,
        "readiness":ready,"directory_sha256":directory.digest(),"pending_scope_sha256":before.scope_sha256(),
        "plans":plans.iter().map(|p|p.runtime_wire()).collect::<Result<Vec<_>,_>>()?});
    shared
        .incoming
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "one runtime run already reserved")?;
    let journal = shared.journal.clone();
    let immutable_run = run.clone();
    let evidence_volume = volume.uid().clone();
    shared
        .io
        .run(move || {
            journal.precharge_group(&immutable_run,std::slice::from_ref(&evidence_volume))?;
            journal.begin(&immutable_run,&evidence_volume,&payload)
        })
        .await?;
    let world = shared.world.clone();
    let target_volume = volume.uid().clone();
    let op = operation.clone();
    let targets = std::array::from_fn(|index| crate::storage_controller::ReplicaTarget {
        node_uid: ready[index].node_uid.clone(),
        boot_id: ready[index].boot.clone(),
    });
    let expected_scope = before.scope_sha256().to_string();
    let classes = shared.config.storage_class_allowlist.clone();
    let intent = shared
        .io
        .run(move || {
            crate::storage_controller::reserve_provision_scoped(
                &world,
                &target_volume,
                targets,
                op,
                &expected_scope,
                &classes,
            )
            .map_err(|_| String::from("actual provisioning commit UNKNOWN/refused; never repeat"))
        })
        .await?;
    let current = core::observe_local_async(volume.uid()).await?;
    let current_directory = shared.directory_for(&current)?;
    if current_directory.digest() != directory.digest()
        || current.revision().term != before.revision().term
        || current.revision().leader_raft_id != before.revision().leader_raft_id
    {
        return Err("issuer/directory changed across acknowledged reservation".into());
    }
    let issuer_boot = view.boot().clone();
    if shared.config.initializes() {
        let mut deadline = shared
            .pipeline_deadline
            .lock()
            .map_err(|_| "pipeline deadline poisoned")?;
        if deadline.is_some() {
            return Err("one original pipeline already admitted".into());
        }
        *deadline = Some(Instant::now() + JOB);
    }
    let mut jobs: BTreeMap<Uid, JobSpec> = BTreeMap::new();
    let mut registrations = Vec::new();
    for (index, target) in ready
        .iter()
        .enumerate()
        .filter(|(_, r)| &r.node_uid != view.local())
    {
        let spec = JobSpec {
            version: 1,
            owner: intent.owner().clone(),
            operation_uid: operation.clone(),
            dataset_uid: None,
            kind: JobKind::PrepareVirginOffline,
            issuer_node_uid: view.local().clone(),
            issuer_boot: issuer_boot.clone(),
            target_node_uid: target.node_uid.clone(),
            target_boot: target.boot.clone(),
            job_uid: Uid::new(),
            plan_sha256: plans[index].runtime_hash()?,
            scope_sha256: current.scope_sha256().to_string(),
            directory_sha256: directory.digest().to_string(),
            issuer_revision: current.revision().clone(),
            maximum_duration_ms: 180_000,
            initialization: None,
        };
        let expected = Arc::new(ExpectedColdJob::register(
            spec.clone(),
            &intent,
            &current,
            &directory,
        )?);
        let journal = shared.journal.clone();
        let durable = expected.clone();
        shared
            .io
            .run(move || journal.register_expected(&durable))
            .await?;
        jobs.insert(target.node_uid.clone(), spec);
        registrations.push((target.node_uid.clone(), expected));
    }
    {
        let mut expected = shared
            .expected
            .lock()
            .map_err(|_| "expected book poisoned")?;
        if !expected.is_empty() {
            return Err("expected book already contains a run".into());
        }
        for (node, job) in registrations {
            expected.insert(node, job);
        }
    }
    for (index, target) in ready.iter().enumerate() {
        if &target.node_uid == view.local() {
            let agent =
                NativeAgent::from_runtime(shared.pool.clone(), plans[index].clone(), &intent)?;
            let ticket = shared.dispatcher.submit_runtime_local(
                shared.world.clone(),
                intent.clone(),
                agent,
                shared.clone(),
            )?;
            let held = wait_ticket(ticket).await?;
            let evidence = digest(held.diagnostics()?);
            *shared
                .held
                .lock()
                .map_err(|_| "local held state poisoned")? =
                Some((run.clone(), before.scope_sha256().to_string(), held, false));
            let journal = shared.journal.clone();
            let durable_run = run.clone();
            shared
                .io
                .run(move || journal.phase(&durable_run, "HELD", &evidence))
                .await?;
            shared
                .held
                .lock()
                .map_err(|_| "local held state poisoned")?
                .as_mut()
                .ok_or("actual local held lease missing")?
                .3 = true;
        } else {
            let spec = jobs
                .get(&target.node_uid)
                .ok_or("expected remote job absent")?
                .clone();
            let spec_sha256 = digest(&protocol::encode_node(&spec)?);
            let nonce = Uid::new();
            let synchronize = NodeJobRequest::InspectReadiness {
                nonce: nonce.clone(),
                expected: Some(spec.clone()),
            };
            let observed = shared
                .call(
                    protocol::NODE_JOB_PATH,
                    &protocol::encode_node(&synchronize)?,
                    &target.node_uid,
                    &directory,
                )
                .await?;
            match protocol::decode_node(observed.body())? {
                NodeJobReply::Readiness {
                    nonce: returned,
                    observation,
                    applied: Some(applied),
                } if returned == nonce
                    && observation.available
                    && observation.node_uid == spec.target_node_uid
                    && observation.boot == spec.target_boot
                    && observation.directory_sha256 == spec.directory_sha256
                    && observation.pool_sha256 == target.pool_sha256
                    && applied.expected_spec_sha256 == spec_sha256
                    && applied.scope_sha256 == spec.scope_sha256
                    && applied.revision.at_least(&spec.issuer_revision) => {}
                _ => {
                    return Err(
                        "target has not proved exact applied postcommit scope; no Offer sent"
                            .into(),
                    )
                }
            }
            let offer = NodeJobRequest::OfferVirginOffline {
                spec: spec.clone(),
                pool_sha256: target.pool_sha256.clone(),
                plan: plans[index].runtime_wire()?,
            };
            let ack = shared
                .call(
                    protocol::NODE_JOB_PATH,
                    &protocol::encode_node(&offer)?,
                    &target.node_uid,
                    &directory,
                )
                .await?;
            match protocol::decode_node(ack.body())? {
                NodeJobReply::Offered {
                    job_uid,
                    spec_sha256: hash,
                } if job_uid == spec.job_uid && hash == spec_sha256 => {}
                _ => return Err("remote offer reply UNKNOWN/mismatched; no resubmit".into()),
            }
            let started = std::time::Instant::now();
            loop {
                tokio::time::sleep(Duration::from_secs(interval)).await;
                if started.elapsed() >= JOB {
                    return Err("remote cold result deadline UNKNOWN".into());
                }
                let inspect = NodeJobRequest::InspectHeld {
                    job_uid: spec.job_uid.clone(),
                    spec_sha256: spec_sha256.clone(),
                };
                let peer = shared
                    .call(
                        protocol::NODE_JOB_PATH,
                        &protocol::encode_node(&inspect)?,
                        &target.node_uid,
                        &directory,
                    )
                    .await?;
                match protocol::decode_node(peer.body())? {
                    NodeJobReply::WorkingObservation {
                        job_uid,
                        spec_sha256: hash,
                    } if job_uid == spec.job_uid && hash == spec_sha256 => {}
                    NodeJobReply::Held {
                        job_uid,
                        spec_sha256: hash,
                        evidence_sha256,
                        reference,
                    } if job_uid == spec.job_uid && hash == spec_sha256 => {
                        shared
                            .remote_held
                            .lock()
                            .map_err(|_| "remote handles poisoned")?
                            .push(RemoteHeld {
                                _node: target.node_uid.clone(),
                                _job: job_uid,
                                _spec_sha256: hash,
                                _evidence_sha256: evidence_sha256,
                                _transport: peer,
                                _reference: reference,
                            });
                        break;
                    }
                    _ => return Err("remote held status UNKNOWN; no next target".into()),
                }
            }
        }
    }
    if shared.config.initializes() {
        init::continue_pipeline(shared.clone(), intent, ready, plans, interval).await?;
    }
    Ok(())
}

async fn server(
    shared: Arc<Shared>,
    directory: VerifiedDirectory,
) -> Result<tokio::task::JoinHandle<()>, String> {
    let local = shared.pool.node_uid.clone();
    let interface = shared.config.interface.clone();
    let port = shared.config.rpc_port;
    let bound = directory.clone();
    let handle = tokio::runtime::Handle::current();
    // The std worker performs all sync ip/wg reads. Enter the reactor only on
    // that owned thread to register the already device-bound Tokio listener.
    let listener = shared
        .io
        .run(move || {
            let _reactor = handle.enter();
            super::remote_transport::DeviceBoundStorageListener::bind(
                &bound, &local, &interface, port,
            )
        })
        .await?;
    let tls = shared
        .io
        .run(move || {
            let (certificate, key) = crate::tls_identity::for_state()?;
            crate::tls_identity::server_config(&certificate, &key)
        })
        .await?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    Ok(tokio::spawn(async move {
        loop {
            let (socket, context) = match listener.accept().await {
                Ok(value) => value,
                Err(_) => {
                    shared.unknown(None, "PRIVATE_LISTENER_UNKNOWN");
                    return;
                }
            };
            let shared = shared.clone();
            let directory = directory.clone();
            let tls = acceptor.clone();
            // accept() minted the bounded permit, retained by the socket token.
            // The connection task cannot outlive the fixed RPC transport bound.
            let request_deadline = Instant::now() + IO_WAIT;
            tokio::spawn(async move {
                let context = Arc::new(context);
                let operation = async {
                    let stream = tls
                        .accept(socket)
                        .await
                        .map_err(|_| "private storage TLS handshake refused")?;
                    let service = hyper::service::service_fn(move |request| {
                        let shared = shared.clone();
                        let directory = directory.clone();
                        let context = context.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(
                                http_request(shared, directory, context, request_deadline, request)
                                    .await,
                            )
                        }
                    });
                    hyper::server::conn::http1::Builder::new()
                        .keep_alive(false)
                        .max_buf_size(128 * 1024)
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await
                        .map_err(|_| "private storage HTTP connection UNKNOWN")
                };
                let _ = tokio::time::timeout(
                    request_deadline.saturating_duration_since(Instant::now()),
                    operation,
                )
                .await;
            });
        }
    }))
}
type HttpResponse = hyper::Response<http_body_util::Full<hyper::body::Bytes>>;
fn response(status: u16, path: &str, nonce: &str, plain: Result<Vec<u8>, String>) -> HttpResponse {
    let encoded = match plain {
        Ok(value) => protocol::seal_protocol_frame(&value),
        Err(_) => protocol::seal_protocol_frame(b"{\"kind\":\"StorageUnknown\"}"),
    };
    let Ok(encoded) = encoded else {
        return hyper::Response::builder()
            .status(500)
            .body(http_body_util::Full::new(hyper::body::Bytes::new()))
            .expect("fixed response");
    };
    let (wire, headers) = crate::node_rpc::seal_and_sign_response(path, nonce, status, &encoded);
    if wire.is_empty() || headers.is_empty() {
        return hyper::Response::builder()
            .status(500)
            .body(http_body_util::Full::new(hyper::body::Bytes::new()))
            .expect("fixed response");
    }
    let mut result = hyper::Response::builder()
        .status(status)
        .header("connection", "close")
        .header("content-type", "application/octet-stream");
    for (name, value) in headers {
        result = result.header(name, value);
    }
    result
        .body(http_body_util::Full::new(hyper::body::Bytes::from(wire)))
        .expect("fixed signed response")
}
/// Read-only HTTP envelope shape only, never authenticated peer/grant DATA.
/// Actual inbound HMAC/socket/directory verification remains mandatory below.
fn http_request_head_preflight(
    method:&hyper::Method,
    uri:&hyper::Uri,
    headers:&hyper::HeaderMap,
)->Result<(),&'static str> {
    for field in [crate::auth::HDR_NODE,crate::auth::HDR_TS,crate::auth::HDR_NONCE,crate::auth::HDR_SIG] {
        if headers.get_all(field).iter().count()!=1 {
            return Err("missing/duplicate private authentication header");
        }
    }
    let nonce=headers.get(crate::auth::HDR_NONCE).and_then(|value|value.to_str().ok()).unwrap_or("");
    if method!=&hyper::Method::POST || uri.query().is_some() || nonce.is_empty() || nonce.len()>256
        || !super::remote_transport::supported_route(uri.path()) {
        return Err("private storage request refused");
    }
    Ok(())
}

/// Only returns borrowed frame DATA. This is not a peer/Shared/phase permit.
fn http_request_frame_preflight<'a>(
    wire_len:usize,
    frame:&'a hyper::body::Frame<hyper::body::Bytes>,
)->Result<Option<&'a hyper::body::Bytes>,(u16,&'static str)> {
    if let Some(data)=frame.data_ref() {
        if data.len()>(96*1024usize).saturating_sub(wire_len) {
            return Err((413,"private frame too large"));
        }
        Ok(Some(data))
    } else if frame.trailers_ref().is_some() {
        Err((400,"private trailers refused"))
    } else {
        Ok(None)
    }
}

async fn http_request(
    shared: Arc<Shared>,
    directory: VerifiedDirectory,
    context: Arc<super::remote_transport::AcceptedStorageContext>,
    request_deadline: Instant,
    request: hyper::Request<hyper::body::Incoming>,
) -> HttpResponse {
    use http_body_util::BodyExt;
    let (parts, mut body) = request.into_parts();
    let path = parts.uri.path().to_owned();
    let nonce = parts
        .headers
        .get(crate::auth::HDR_NONCE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    if let Err(reason)=http_request_head_preflight(&parts.method,&parts.uri,&parts.headers) {
        return response(403,&path,&nonce,Err(reason.into()));
    }
    let mut wire = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(_) => return response(400, &path, &nonce, Err("incomplete private frame".into())),
        };
        match http_request_frame_preflight(wire.len(),&frame) {
            Ok(Some(data))=>wire.extend_from_slice(data),
            Ok(None)=>{},
            Err((status,reason))=>return response(status,&path,&nonce,Err(reason.into())),
        }
    }
    let method = parts.method.to_string();
    let verified_path = path.clone();
    let headers = parts.headers;
    let verified = shared
        .io
        .run(move || {
            super::remote_transport::inbound(
                &method,
                &verified_path,
                |name| {
                    headers
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned)
                },
                &wire,
                &context,
                &directory,
            )
        })
        .await;
    let peer = match verified {
        Ok(peer) => peer,
        Err(_) => {
            return response(
                403,
                &path,
                &nonce,
                Err("storage transport verification refused".into()),
            )
        }
    };
    let result = shared.handle(&path, peer, request_deadline).await;
    response(
        if result.is_ok() { 200 } else { 409 },
        &path,
        &nonce,
        result,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn attachment_v3_is_explicit_and_v1_v2_remain_non_mounting(){
        let mut cfg=config();assert!(!cfg.attaches());
        cfg.version=2;cfg.initialization_mode=Some(InitializationMode::InitializeOffline);
        policy_fields(&cfg).unwrap();assert!(cfg.initializes());assert!(!cfg.attaches());
        cfg.version=3;assert!(policy_fields(&cfg).is_err());assert!(!cfg.attaches());
        cfg.attachment_mode=Some(AttachmentMode::AttachManagedEpochOne);
        policy_fields(&cfg).unwrap();assert!(cfg.attaches());assert!(cfg.initializes());
        cfg.version=2;assert!(policy_fields(&cfg).is_err());assert!(!cfg.attaches());
    }
    #[test]
    fn attachment_mode_cannot_default_from_missing_or_unknown_private_json(){
        let mut cfg=config();cfg.version=3;cfg.initialization_mode=Some(InitializationMode::InitializeOffline);
        cfg.attachment_mode=Some(AttachmentMode::AttachManagedEpochOne);
        let mut raw=serde_json::to_value(cfg).unwrap();raw.as_object_mut().unwrap().remove("attachment_mode");
        let decoded:Configuration=serde_json::from_value(raw.clone()).unwrap();assert!(policy_fields(&decoded).is_err());assert!(!decoded.attaches());
        raw["attachment_mode"]="AttachAnything".into();assert!(serde_json::from_value::<Configuration>(raw).is_err());
    }
    fn config() -> Configuration {
        Configuration {
            version: 1,
            initialization_mode: None,
            attachment_mode:None,
            pool_config: "/var/lib/royak/storage/test/pool.json".into(),
            journal_root: "/var/lib/royak/storage/test/runtime".into(),
            delegated_cgroup_root: "/sys/fs/cgroup/royak-test".into(),
            helper_image: "/var/lib/royak/storage/test/royak".into(),
            helper_sha256: "a".repeat(64),
            interface: "wg-test".into(),
            rpc_port: 24444,
            storage_class_allowlist: vec!["managed".into()],
            minor_first: 512,
            minor_last: 512,
            port_first: 22000,
            port_last: 22000,
            resource_budget: ResourceBudget {
                pids_max: 64,
                memory_max_bytes: 256 * 1024 * 1024,
                cpu_quota_us: 100_000,
                cpu_period_us: 100_000,
            },
        }
    }
    #[test]
    fn strict_runtime_configuration_has_no_device_selector_or_unknown_field_default() {
        let good = serde_json::to_value(config()).unwrap();
        serde_json::from_value::<Configuration>(good.clone()).unwrap();
        for field in [
            "device",
            "node_uid",
            "shared_secret",
            "allow_follower",
            "program_timeout",
        ] {
            let mut bad = good.clone();
            bad[field] = serde_json::json!("injected");
            assert!(serde_json::from_value::<Configuration>(bad).is_err());
        }
        let mut missing = good;
        missing.as_object_mut().unwrap().remove("resource_budget");
        assert!(serde_json::from_value::<Configuration>(missing).is_err());
    }
    #[test]
    fn runtime_policy_preserves_exact_resource_and_minor_port_bounds() {
        policy_fields(&config()).unwrap();
        let mut bad = config();
        bad.resource_budget.pids_max = 65;
        assert!(policy_fields(&bad).is_err());
        let mut bad = config();
        bad.resource_budget.memory_max_bytes += 1;
        assert!(policy_fields(&bad).is_err());
        let mut bad = config();
        bad.minor_last = 511;
        assert!(policy_fields(&bad).is_err());
        let mut bad = config();
        bad.port_last = 21999;
        assert!(policy_fields(&bad).is_err());
        let mut bad = config();
        bad.storage_class_allowlist.push("managed".into());
        assert!(policy_fields(&bad).is_err());
    }
    #[test]
    fn root_private_runtime_paths_cannot_select_public_alias_or_parent() {
        for bad in [
            "/tmp/native.json",
            "relative",
            "/var/lib/royak/storage",
            "/var/lib/royak/storage/../pool.json",
        ] {
            assert!(reserved_path(Path::new(bad)).is_err());
        }
        reserved_path(Path::new("/var/lib/royak/storage/runtime/native.json")).unwrap();
    }
    #[test]
    fn configured_mode_refuses_noncluster_or_nondocker_or_plaintext_before_file_io() {
        for (clustered, docker, tls) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            assert!(configure(Path::new("/definitely-not-read"), clustered, docker, tls).is_err());
        }
    }
    #[test]
    fn compatible_existing_pending_world_is_not_an_empty_world_requirement() {
        let mut world = DesiredWorld::new();
        for raw in [
            serde_json::json!({"kind":"StorageClass","metadata":{"name":"managed"},"spec":{"provisioner":crate::storage_lifecycle::PROVISIONER}}),
            serde_json::json!({"kind":"PersistentVolumeClaim","metadata":{"name":"data","namespace":"existing"},"spec":{"storageClassName":"managed","resources":{"requests":{"storage":"64Mi"}}}}),
        ] {
            world.apply(&serde_json::from_value(raw).unwrap()).unwrap();
        }
        let uid = world.storage_identities.volumes
            [world.pvcs["existing/data"].bound_pv.as_ref().unwrap()]
        .clone();
        let volume = world
            .storage_identities
            .lifecycle
            .get(&uid)
            .unwrap()
            .clone();
        assert!(startup_fresh(true, &[volume.clone()]));
        assert!(!startup_fresh(false, &[volume.clone()]));
        let mut provisioning = volume;
        let boot: BootId =
            serde_json::from_value(serde_json::json!("12345678-1234-4234-a234-123456789abc"))
                .unwrap();
        provisioning
            .begin_provision(
                [Uid::new(), Uid::new(), Uid::new()],
                [boot.clone(), boot.clone(), boot],
                Uid::new(),
            )
            .unwrap();
        assert!(!startup_fresh(true, &[provisioning]));
    }
}


#[cfg(test)]
mod private_http_envelope_regressions {
    use super::*;
    fn routes()->[&'static str;6] {
        [protocol::NODE_JOB_PATH,protocol::GRANT_PATH,protocol::BOUNDARY_PATH,
            protocol::attachment::PATH,protocol::attachment::OFFER_PATH,protocol::attachment::MOUNTED_PATH]
    }
    fn head(path:&str)->(hyper::Method,hyper::Uri,hyper::HeaderMap) {
        // Shape DATA only: these strings are NOT a valid signature/enrolled peer.
        let request=hyper::Request::builder().method("POST").uri(path)
            .header(crate::auth::HDR_NODE,"peer-DATA")
            .header(crate::auth::HDR_TS,"0")
            .header(crate::auth::HDR_NONCE,"nonce-DATA")
            .header(crate::auth::HDR_SIG,"not-a-valid-mac-DATA")
            .body(()).unwrap();
        let (parts,_)=request.into_parts();(parts.method,parts.uri,parts.headers)
    }
    #[test]
    fn actual_http_callee_accepts_exact_six_head_envelopes_as_data_only() {
        assert_eq!(routes().into_iter().collect::<std::collections::BTreeSet<_>>().len(),6);
        for route in routes() {
            let (method,uri,headers)=head(route);
            assert!(super::super::remote_transport::supported_route(route));
            let shape_only:()=http_request_head_preflight(&method,&uri,&headers).unwrap();
            assert_eq!(shape_only,());
        }
        // No Shared/AcceptedStorageContext/VerifiedPeerFrame constructor exists here.
    }
    #[test]
    fn actual_http_callee_refuses_nonpost_and_every_query_including_empty() {
        for route in routes() {
            let (_,uri,headers)=head(route);
            for verb in ["GET","HEAD","PUT","PATCH","DELETE","OPTIONS"] {
                assert!(http_request_head_preflight(&verb.parse().unwrap(),&uri,&headers).is_err());
            }
            for suffix in ["?","?x=1"] {
                let (method,uri,headers)=head(&format!("{route}{suffix}"));
                assert!(http_request_head_preflight(&method,&uri,&headers).is_err());
            }
        }
    }
    #[test]
    fn closed_six_route_predicate_is_shared_not_a_prefix_or_terminal_family() {
        for route in routes() {
            for invalid in [format!("{route}/"),format!("{route}/extra"),format!("{route}-extra")] {
                let (method,uri,headers)=head(&invalid);
                assert!(!super::super::remote_transport::supported_route(&invalid));
                assert!(http_request_head_preflight(&method,&uri,&headers).is_err());
            }
        }
        for invalid in ["/","/api/v1/pods","/royak/v1/storage/node/restore",
            "/royak/v1/storage/node/terminal","/royak/v1/storage/node/%6aob"] {
            let (method,uri,headers)=head(invalid);
            assert!(!super::super::remote_transport::supported_route(invalid));
            assert!(http_request_head_preflight(&method,&uri,&headers).is_err());
        }
    }
    #[test]
    fn actual_http_callee_requires_each_auth_header_exactly_once() {
        for field in [crate::auth::HDR_NODE,crate::auth::HDR_TS,crate::auth::HDR_NONCE,crate::auth::HDR_SIG] {
            let (method,uri,mut headers)=head(protocol::attachment::OFFER_PATH);
            headers.remove(field);
            assert_eq!(http_request_head_preflight(&method,&uri,&headers),Err("missing/duplicate private authentication header"));
            let (method,uri,mut headers)=head(protocol::attachment::MOUNTED_PATH);
            headers.append(field,hyper::header::HeaderValue::from_static("duplicate-DATA"));
            assert_eq!(http_request_head_preflight(&method,&uri,&headers),Err("missing/duplicate private authentication header"));
        }
    }
    #[test]
    fn actual_http_nonce_shape_refuses_empty_long_nontext_and_preserves_256_head_bound() {
        for invalid in ["".to_string(),"x".repeat(257)] {
            let (method,uri,mut headers)=head(protocol::attachment::PATH);
            headers.insert(crate::auth::HDR_NONCE,hyper::header::HeaderValue::from_bytes(invalid.as_bytes()).unwrap());
            assert_eq!(http_request_head_preflight(&method,&uri,&headers),Err("private storage request refused"));
        }
        let (method,uri,mut headers)=head(protocol::NODE_JOB_PATH);
        headers.insert(crate::auth::HDR_NONCE,hyper::header::HeaderValue::from_bytes(b"\xff").unwrap());
        assert_eq!(http_request_head_preflight(&method,&uri,&headers),Err("private storage request refused"));
        headers.insert(crate::auth::HDR_NONCE,hyper::header::HeaderValue::from_bytes("x".repeat(256).as_bytes()).unwrap());
        assert!(http_request_head_preflight(&method,&uri,&headers).is_ok());
        // Downstream verify_node's separate64-byte/HMAC checks are unchanged.
    }
    #[test]
    fn envelope_shape_never_claims_peer_auth_and_missing_node_auth_still_refuses() {
        for route in routes() {
            let (method,uri,mut headers)=head(route);
            headers.insert("x-unrelated-data",hyper::header::HeaderValue::from_static("not-authority"));
            assert!(http_request_head_preflight(&method,&uri,&headers).is_ok());
            assert!(crate::auth::verify_node("POST",route,|_|None,b"DATA").is_err());
        }
        // Refusal can precede signature verification when no cluster key is configured.
        // This is NOT a valid-HMAC or enrolled-peer positive test.
    }
    #[test]
    fn actual_http_frame_callee_keeps_exact_96k_and_saturating_overflow_refusal() {
        let frame=hyper::body::Frame::data(hyper::body::Bytes::from(vec![1u8;96*1024]));
        assert_eq!(http_request_frame_preflight(0,&frame).unwrap().unwrap().len(),96*1024);
        let extra=hyper::body::Frame::data(hyper::body::Bytes::from(vec![1u8;96*1024+1]));
        assert!(matches!(http_request_frame_preflight(0,&extra),Err((413,"private frame too large"))));
        let one=hyper::body::Frame::data(hyper::body::Bytes::from_static(b"x"));
        assert!(http_request_frame_preflight(96*1024-1,&one).is_ok());
        assert!(matches!(http_request_frame_preflight(96*1024,&one),Err((413,"private frame too large"))));
        assert!(matches!(http_request_frame_preflight(usize::MAX,&one),Err((413,"private frame too large"))));
    }
    #[test]
    fn actual_http_frame_callee_refuses_trailers_even_when_empty() {
        let frame=hyper::body::Frame::trailers(hyper::HeaderMap::new());
        assert!(matches!(http_request_frame_preflight(0,&frame),Err((400,"private trailers refused"))));
        let empty=hyper::body::Frame::data(hyper::body::Bytes::new());
        assert!(http_request_frame_preflight(96*1024,&empty).unwrap().unwrap().is_empty());
    }
    #[test]
    fn actual_http_frame_callee_repeated_chunks_never_reset_the_aggregate_bound() {
        let mut wire_len=0;
        for size in [1usize,1024,96*1024-1025] {
            let frame=hyper::body::Frame::data(hyper::body::Bytes::from(vec![0u8;size]));
            wire_len+=http_request_frame_preflight(wire_len,&frame).unwrap().unwrap().len();
        }
        assert_eq!(wire_len,96*1024);
        let one=hyper::body::Frame::data(hyper::body::Bytes::from_static(b"x"));
        assert!(matches!(http_request_frame_preflight(wire_len,&one),Err((413,"private frame too large"))));
    }
}

#[cfg(test)]
mod terminal_http_envelope_regressions {
    use super::*;
    #[test]
    fn terminal_http_head_uses_one_literal_shared_route_not_a_prefix_or_public_signal_family(){
        let route=mount::consumer::terminal::PATH;
        let request=hyper::Request::builder().method("POST").uri(route)
            .header(crate::auth::HDR_NODE,"DATA-peer").header(crate::auth::HDR_TS,"0")
            .header(crate::auth::HDR_NONCE,"DATA-nonce").header(crate::auth::HDR_SIG,"not-authentication-DATA")
            .body(()).unwrap();
        let (parts,_)=request.into_parts();
        assert!(super::super::remote_transport::supported_route(route));
        assert!(http_request_head_preflight(&parts.method,&parts.uri,&parts.headers).is_ok());
        for path in [format!("{route}/"),format!("{route}/kill"),format!("{route}-extra"),"/containers/x/kill?signal=SIGTERM".into()]{
            assert!(!super::super::remote_transport::supported_route(&path));
            let uri=path.parse::<hyper::Uri>().unwrap();assert!(http_request_head_preflight(&parts.method,&uri,&parts.headers).is_err());
        }
        assert!(http_request_head_preflight(&hyper::Method::GET,&parts.uri,&parts.headers).is_err());
        let queried=format!("{route}?").parse::<hyper::Uri>().unwrap();
        assert!(http_request_head_preflight(&parts.method,&queried,&parts.headers).is_err());
        assert!(crate::auth::verify_node("POST",route,|_|None,b"DATA").is_err());
        // Shape DATA cannot create Shared, actual accepted socket, parent or
        // terminal effect permission; old nine envelope bodies are intact.
    }
}
