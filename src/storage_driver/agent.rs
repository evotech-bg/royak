//! Synchronous, one-job-per-node physical adapter. Invoke from one dedicated
//! bounded helper worker, never spawn an unbounded Tokio blocking-pool job.
//! A stuck kernel IO keeps the job/lock unresolved: it is not cancellation or
//! authority to start a writer elsewhere. Per-command bounds remain in process.
use super::{lvm, private_fs::Dir, replica, Config, Request};
use crate::reconcile::DesiredWorld;
use crate::storage_boot::BootId;
use crate::storage_controller::{ProvisionIntent, ReplicaAgent};
use crate::storage_identity::Uid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[derive(Clone)]
pub(crate) struct NativeAgent {
    config: Config,
    plan: replica::Plan,
    worker: Option<super::dispatcher::VerifiedWorkerMode>,
}

/// Opaque diagnostic proof. This type does not implement Deserialize and
/// cannot become lifecycle::VerifiedReceipt, a mount grant or a backup source.
#[derive(Debug, Serialize)]
pub(crate) struct SecondaryPrepared {
    kind: &'static str,
    cluster_id: String,
    namespace_uid: Uid,
    claim_uid: Uid,
    volume_uid: Uid,
    operation_uid: Uid,
    node_uid: Uid,
    node_boot_id: BootId,
    lv_uuid: String,
    drbd_device_uuid: String,
    exposed_capacity_bytes: u64,
    evidence_sha256: String,
    pod_access_granted: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Stage {
    Intent,
    BackingPrepared,
    MetadataReady,
    OnlineIntent,
    Complete,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Job {
    version: u32,
    binding_sha256: String,
    stage: Stage,
    last_unknown_sha256: Option<String>,
    last_observation_sha256: Option<String>,
}
/// Actual worker output remains diagnostic; the dispatcher owns the separate
/// retained admission/lease capability and does not parse this into Core proof.
#[derive(Serialize)]
pub(super) struct VirginOfflinePrepared {
    kind: &'static str,
    volume_uid: Uid,
    operation_uid: Uid,
    node_uid: Uid,
    node_boot_id: BootId,
    pod_access_granted: bool,
    observation: replica::VirginReplica,
}

fn hash(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Job {
    fn load_or_new(dir: &Dir, name: &str, binding: &str) -> Result<Self, String> {
        let Some(raw) = dir.read(name)? else {
            return Ok(Self {
                version: 1,
                binding_sha256: binding.into(),
                stage: Stage::Intent,
                last_unknown_sha256: None,
                last_observation_sha256: None,
            });
        };
        let job: Self = serde_json::from_slice(&raw).map_err(|_| "corrupt storage agent job")?;
        if job.version != 1
            || job.binding_sha256 != binding
            || !valid_hash(binding)
            || job
                .last_unknown_sha256
                .as_ref()
                .is_some_and(|s| !valid_hash(s))
            || job
                .last_observation_sha256
                .as_ref()
                .is_some_and(|s| !valid_hash(s))
            || (job.stage == Stage::Complete && job.last_observation_sha256.is_none())
        {
            return Err("storage job belongs to another intent/boot/backend or is corrupt".into());
        }
        Ok(job)
    }
    fn save(&self, dir: &Dir, name: &str) -> Result<(), String> {
        dir.write(
            name,
            &serde_json::to_vec(self).map_err(|_| "cannot encode storage agent job")?,
        )
    }
    fn observed_stage(&mut self, stage: Stage, dir: &Dir, name: &str) -> Result<(), String> {
        self.stage = stage;
        self.save(dir, name)
    }
}

impl NativeAgent {
    pub(super) fn run_verified_owned_inventory_phase(authority:&super::dispatcher::VerifiedNativeAuthority)
        ->Result<replica::initialize::managed_mount::phases::WorkerObservation,String>{
        super::live_authority::require_owned_inventory_installed()?;
        let(permit,config)=super::dispatcher::attachment::VerifiedAttachPhase::from_owned_inventory_inherited(authority)?;
        let plan:replica::Plan=serde_json::from_value(authority.plan().clone()).map_err(|_|"invalid exact profile7 inherited plan")?;
        replica::initialize::managed_mount::phases::execute(&config,&plan,&permit)
    }
    pub(super) fn from_terminal_parent(parent:&super::native_runtime::mount::consumer::terminal::VerifiedTerminalNodeParent)->Result<Self,String>{
        parent.require_live()?;
        let config=parent.pool().clone();config.validate()?;
        let plan=replica::initialize::managed_mount::phases::retained_plan(&config,parent.scope())?;
        parent.require_live()?;Ok(Self{config,plan,worker:None})
    }
    pub(super) fn terminal_parts(&self,scope:&crate::storage_lifecycle::pod_attachment::ExpectedAttachScope)->Result<(Config,serde_json::Value),String>{
        self.config.validate()?;
        replica::initialize::managed_mount::phases::check_inputs(&self.config,&self.plan,scope)?;
        Ok((self.config.clone(),self.plan.runtime_wire()?))
    }
    pub(super) fn run_verified_terminal_phase(authority:&super::dispatcher::VerifiedNativeAuthority)
        ->Result<replica::initialize::managed_mount::terminal::TerminalPhysicalObservation,String>{
        super::live_authority::require_terminal_installed()?;
        let(permit,config)=super::dispatcher::attachment::terminal::VerifiedTerminalPhase::from_inherited(authority)?;
        let plan:replica::Plan=serde_json::from_value(authority.plan().clone()).map_err(|_|"invalid private terminal plan")?;
        replica::initialize::managed_mount::terminal::execute(&config,&plan,&permit)
    }
    pub(super) fn from_attach_parent(parent:&super::native_runtime::mount::parent::VerifiedAttachParent)->Result<Self,String> {
        parent.require_live()?;
        let config=parent.pool().clone();config.validate()?;
        let plan=replica::initialize::managed_mount::phases::retained_plan(&config,parent.scope())?;
        parent.require_live()?;
        Ok(Self {config,plan,worker:None})
    }
    pub(super) fn attachment_parts(&self,scope:&crate::storage_lifecycle::pod_attachment::ExpectedAttachScope)
        ->Result<(Config,serde_json::Value),String> {
        self.config.validate()?;
        replica::initialize::managed_mount::phases::check_inputs(&self.config,&self.plan,scope)?;
        Ok((self.config.clone(),self.plan.runtime_wire()?))
    }
    pub(super) fn attachment_minor(&self)->u32 {replica::initialize::managed_mount::phases::minor(&self.plan)}
    pub(super) fn run_verified_attachment_phase(authority:&super::dispatcher::VerifiedNativeAuthority)
        ->Result<replica::initialize::managed_mount::phases::WorkerObservation,String> {
        super::live_authority::require_attachment_installed()?;
        let (permit,config)=super::dispatcher::attachment::VerifiedAttachPhase::from_inherited(authority)?;
        let plan:replica::Plan=serde_json::from_value(authority.plan().clone()).map_err(|_|"invalid exact inherited attachment plan")?;
        replica::initialize::managed_mount::phases::execute(&config,&plan,&permit)
    }
    pub(super) fn run_verified_distributed_phase(
        capability: &super::dispatcher::VerifiedNativeAuthority,
    ) -> Result<crate::storage_lifecycle::generation::physical::PhaseObservation, String> {
        super::live_authority::require_distributed_initialization_installed()?;
        let (_,intent)=crate::storage_lifecycle::generation::InitializationIntent::
            from_verified_distributed_native_helper(capability)?;
        let config: Config = serde_json::from_value(capability.config().clone())
            .map_err(|_| "invalid inherited distributed pool")?;
        let plan: replica::Plan = serde_json::from_value(capability.plan().clone())
            .map_err(|_| "invalid inherited distributed plan")?;
        let permit =
            super::dispatcher::VerifiedDistributedInitPhase::from_inherited(capability, &intent)?;
        let result = replica::initialize::phases::execute_phase(&config, &plan, &intent, &permit)?;
        Ok(result.observation().clone())
    }
    pub(super) fn initialization_parts(
        &self,
        intent: &crate::storage_lifecycle::generation::InitializationIntent,
        world: &Arc<RwLock<DesiredWorld>>,
    ) -> Result<(serde_json::Value, serde_json::Value, Vec<u8>), String> {
        self.config.validate()?;
        intent.check_current(world)?;
        let fact = intent
            .generation()
            .virgin_replicas
            .iter()
            .find(|fact| fact.node_uid == self.config.node_uid)
            .ok_or("phase node absent from committed generation")?;
        if fact.pool_uid != self.config.pool_uid || fact.plan_sha256 != self.plan.runtime_hash()? {
            return Err("phase pool or immutable plan changed".into());
        }
        Ok((
            serde_json::to_value(&self.config).map_err(|_| "cannot encode phase pool")?,
            self.plan.runtime_wire()?,
            intent.export_native_projection(world)?,
        ))
    }
    pub(super) fn from_runtime(
        config: Config,
        plan: replica::Plan,
        intent: &ProvisionIntent,
    ) -> Result<Self, String> {
        config.validate()?;
        plan.bind_intent(&config, intent)?;
        Ok(Self {
            config,
            plan,
            worker: None,
        })
    }
    pub(super) fn run_verified_cold_helper(
        capability: &super::dispatcher::VerifiedNativeAuthority,
    ) -> Result<VirginOfflinePrepared, String> {
        if !capability.is_cold() {
            return Err("cold preparation requires the exact v2 worker kind".into());
        }
        super::live_authority::require_cold_installed()?;
        let (world, intent) = ProvisionIntent::from_verified_native_helper(capability)?;
        let config: Config = serde_json::from_value(capability.config().clone())
            .map_err(|_| "invalid inherited cold pool configuration")?;
        config.validate()?;
        let plan: replica::Plan = serde_json::from_value(capability.plan().clone())
            .map_err(|_| "invalid inherited cold replica plan")?;
        let agent = Self {
            config,
            plan,
            worker: Some(capability.worker_mode()),
        };
        agent.prepare_virgin_offline(&world, &intent)
    }
    fn check_cold(&self, intent: &ProvisionIntent, boot: &BootId) -> Result<(), String> {
        self.worker
            .as_ref()
            .ok_or("cold physical preparation requires verified worker mode")?
            .check_virgin(intent)?;
        if &self.boot(intent)? != boot {
            return Err("cold worker node boot changed".into());
        }
        self.plan.bind_intent(&self.config, intent)?;
        Ok(())
    }
    /// Unlike historical prepare_secondary this stops before OnlineIntent/up.
    /// Every retry performs a real MetadataReady/offline direct observation.
    fn prepare_virgin_offline(
        &self,
        world: &Arc<RwLock<DesiredWorld>>,
        intent: &ProvisionIntent,
    ) -> Result<VirginOfflinePrepared, String> {
        let _ = world; // identity projection only; all authority is live parent
        self.worker
            .as_ref()
            .ok_or("cold physical preparation requires verified worker mode")?
            .check_virgin(intent)?;
        let boot = self.boot(intent)?;
        self.check_cold(intent, &boot)?;
        let request = self.request(intent)?;
        let plan_hash = self.plan.bind_intent(&self.config, intent)?;
        let binding = hash(
            &serde_json::to_vec(&(
                "prepare-virgin-offline-v2",
                intent.owner(),
                intent.operation_uid(),
                intent.capacity_bytes(),
                intent
                    .targets()
                    .iter()
                    .map(|t| (&t.node_uid, &t.boot_id))
                    .collect::<Vec<_>>(),
                &self.config,
                &plan_hash,
            ))
            .map_err(|_| "cannot bind cold preparation job")?,
        );
        let dir = Dir::open(&self.journal_path(), true)?;
        let _lock = dir.lock()?;
        let name = format!("virgin-{}.json", intent.owner().volume_uid.as_str());
        let mut job = Job::load_or_new(&dir, &name, &binding)?;
        job.save(&dir, &name)?;
        let result: Result<VirginOfflinePrepared, String> = (|| {
            self.check_cold(intent, &boot)?;
            lvm::prepare(&self.config, &request)?;
            job.observed_stage(Stage::BackingPrepared, &dir, &name)?;
            self.check_cold(intent, &boot)?;
            replica::run(&self.config, &self.plan, replica::Mode::Create)?;
            self.check_cold(intent, &boot)?;
            let observation = replica::observe_virgin(&self.config, &self.plan)?;
            self.check_cold(intent, &boot)?;
            // Only the actual never-activated probe permits this stage marker;
            // never relabel an old Online/Offline result as virgin.
            job.observed_stage(Stage::MetadataReady, &dir, &name)?;
            let bytes =
                serde_json::to_vec(&observation).map_err(|_| "cannot bind cold observation")?;
            job.last_observation_sha256 = Some(hash(&bytes));
            job.last_unknown_sha256 = None;
            job.observed_stage(Stage::Complete, &dir, &name)?;
            Ok(VirginOfflinePrepared {
                kind: "royak-agent-virgin-offline-prepared-v2",
                volume_uid: intent.owner().volume_uid.clone(),
                operation_uid: intent.operation_uid().clone(),
                node_uid: self.config.node_uid.clone(),
                node_boot_id: boot.clone(),
                pod_access_granted: false,
                observation,
            })
        })();
        if let Err(error) = &result {
            job.last_unknown_sha256 = Some(hash(error.as_bytes()));
            job.save(&dir, &name)?;
        }
        result
    }
    pub(super) fn cold_expected(&self, intent: &ProvisionIntent) -> Result<(Uid, String), String> {
        Ok((
            self.config.pool_uid.clone(),
            self.plan.bind_intent(&self.config, intent)?,
        ))
    }
    #[cfg(test)]
    pub(super) fn assert_parent_trait_refuses_without_verified_mode(
        world: &Arc<RwLock<DesiredWorld>>,
        intent: &ProvisionIntent,
    ) {
        let mut config = super::test_config();
        config.cluster_id = intent.owner().cluster_id.clone();
        config.node_uid = intent.targets()[0].node_uid.clone();
        let peers=intent.targets().iter().enumerate().map(|(i,t)|serde_json::json!({
            "node_uid":t.node_uid,"node_id":i,"hostname":format!("n{i}"),"address":format!("10.77.0.{}",i+1),
            "public_key":format!("{}=",["A","B","C"][i].repeat(43)),"vg_name":config.vg_name
        })).collect::<Vec<_>>();
        let plan:replica::Plan=serde_json::from_value(serde_json::json!({"version":1,"cluster_id":config.cluster_id,
            "pool_uid":config.pool_uid,"volume_uid":intent.owner().volume_uid,"operation_uid":intent.operation_uid(),
            "minor":512,"port":22000,"interface":"wg-test","shared_secret":"0".repeat(48),"peers":peers})).unwrap();
        let parent = Self {
            config,
            plan,
            worker: None,
        };
        let error = ReplicaAgent::prepare_secondary(&parent, world, intent).unwrap_err();
        assert!(
            error.contains("opaque verified worker context"),
            "must refuse BEFORE any platform/device IO: {error}"
        );
    }
    pub(super) fn helper_parts(
        &self,
        intent: &ProvisionIntent,
        world: &Arc<RwLock<DesiredWorld>>,
    ) -> Result<
        (
            crate::storage_identity::Uid,
            String,
            serde_json::Value,
            serde_json::Value,
            Vec<u8>,
        ),
        String,
    > {
        self.plan.bind_intent(&self.config, intent)?;
        let boot = self.boot(intent)?;
        let projection = intent.export_native_projection(world)?;
        Ok((
            self.config.node_uid.clone(),
            boot.as_str().into(),
            serde_json::to_value(&self.config).map_err(|_| "cannot encode private pool binding")?,
            serde_json::to_value(&self.plan).map_err(|_| "cannot encode private replica plan")?,
            projection,
        ))
    }

    pub(super) fn run_verified_helper(
        capability: &super::dispatcher::VerifiedNativeAuthority,
    ) -> Result<SecondaryPrepared, String> {
        super::live_authority::require_installed()?;
        let (world, intent) = ProvisionIntent::from_verified_native_helper(capability)?;
        let config: Config = serde_json::from_value(capability.config().clone())
            .map_err(|_| "invalid inherited pool configuration")?;
        config.validate()?;
        let plan: replica::Plan = serde_json::from_value(capability.plan().clone())
            .map_err(|_| "invalid inherited replica plan")?;
        let agent = Self {
            config,
            plan,
            worker: Some(capability.worker_mode()),
        };
        agent.plan.bind_intent(&agent.config, &intent)?;
        ReplicaAgent::prepare_secondary(&agent, &world, &intent)
    }
    /// The root operator's pinned private config/plan, not an HTTP source path.
    pub(crate) fn load(config: &Path, plan: &Path) -> Result<Self, String> {
        if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
            return Err("native storage agent requires explicitly configured Linux root".into());
        }
        let config = Config::load(config)?;
        let plan: replica::Plan = serde_json::from_slice(&super::private_fs::read_private(plan)?)
            .map_err(|_| "invalid private native replica plan")?;
        Ok(Self {
            config,
            plan,
            worker: None,
        })
    }

    fn boot(&self, intent: &ProvisionIntent) -> Result<BootId, String> {
        let actual = BootId::current()?;
        let target = intent
            .targets()
            .iter()
            .find(|t| t.node_uid == self.config.node_uid)
            .ok_or("this node is not a committed replica target")?;
        if actual != target.boot_id {
            return Err(
                "committed storage grant is for another node boot; no replay permitted".into(),
            );
        }
        Ok(actual)
    }

    fn request(&self, intent: &ProvisionIntent) -> Result<Request, String> {
        let owner = intent.owner();
        let request = Request {
            version: 1,
            cluster_id: owner.cluster_id.clone(),
            node_uid: self.config.node_uid.clone(),
            pool_uid: self.config.pool_uid.clone(),
            namespace_uid: owner.namespace_uid.clone(),
            claim_uid: owner.claim_uid.clone(),
            volume_uid: owner.volume_uid.clone(),
            operation_uid: intent.operation_uid().clone(),
            capacity_bytes: intent.capacity_bytes(),
        };
        request.validate(&self.config)?;
        Ok(request)
    }

    fn journal_path(&self) -> PathBuf {
        Path::new("/var/lib/royak/storage/agents").join(self.config.node_uid.as_str())
    }

    fn check(
        &self,
        world: &Arc<RwLock<DesiredWorld>>,
        intent: &ProvisionIntent,
        boot: &BootId,
    ) -> Result<(), String> {
        let _ = world; // projection identity data, never live issuer authority
        self.worker
            .as_ref()
            .ok_or("physical native agent requires opaque verified worker context")?
            .check(intent)?;
        if &self.boot(intent)? != boot {
            return Err("node boot changed during storage job".into());
        }
        self.plan.bind_intent(&self.config, intent)?;
        Ok(())
    }
}

impl ReplicaAgent for NativeAgent {
    type SecondaryPrepared = SecondaryPrepared;

    fn prepare_secondary(
        &self,
        world: &Arc<RwLock<DesiredWorld>>,
        intent: &ProvisionIntent,
    ) -> Result<SecondaryPrepared, String> {
        // Parent-loaded agents may export a job but cannot perform physical IO.
        // No identity-only fallback, even with an unchanged desired snapshot.
        self.worker
            .as_ref()
            .ok_or("physical native agent requires opaque verified worker context")?
            .check(intent)?;
        let boot = self.boot(intent)?;
        self.check(world, intent, &boot)?;
        let request = self.request(intent)?;
        let plan_hash = self.plan.bind_intent(&self.config, intent)?;
        let binding = hash(
            &serde_json::to_vec(&(
                intent.owner(),
                intent.operation_uid(),
                intent.capacity_bytes(),
                intent
                    .targets()
                    .iter()
                    .map(|t| (&t.node_uid, &t.boot_id))
                    .collect::<Vec<_>>(),
                &self.config,
                &plan_hash,
            ))
            .map_err(|_| "cannot bind committed storage job")?,
        );
        let dir = Dir::open(&self.journal_path(), true)?;
        // Nonblocking: no queue, no detached thread, one active helper per node.
        let _lock = dir.lock()?;
        let name = format!("prepare-{}.json", intent.owner().volume_uid.as_str());
        let mut job = Job::load_or_new(&dir, &name, &binding)?;
        job.save(&dir, &name)?; // intent durable before first physical mutation
        let result: Result<SecondaryPrepared, String> = (|| {
            self.check(world, intent, &boot)?;
            lvm::prepare(&self.config, &request)?;
            job.observed_stage(Stage::BackingPrepared, &dir, &name)?;
            self.check(world, intent, &boot)?;
            replica::run(&self.config, &self.plan, replica::Mode::Create)?;
            job.observed_stage(Stage::MetadataReady, &dir, &name)?;
            self.check(world, intent, &boot)?;
            job.observed_stage(Stage::OnlineIntent, &dir, &name)?;
            replica::run(&self.config, &self.plan, replica::Mode::Online)?;
            self.check(world, intent, &boot)?;
            // Fresh kernel + backing + transport + nftables observation on
            // EVERY retry. Never resurrect an ACK from a Complete JSON cache.
            let observed = replica::run(&self.config, &self.plan, replica::Mode::Observe)?;
            let (lv_uuid, drbd_device_uuid, exposed_capacity_bytes, evidence_sha256) =
                replica::verified_secondary(observed, &self.config, &self.plan, intent, &boot)?;
            self.check(world, intent, &boot)?;
            let owner = intent.owner();
            let prepared = SecondaryPrepared {
                kind: "royak-agent-secondary-prepared-v1",
                cluster_id: owner.cluster_id.clone(),
                namespace_uid: owner.namespace_uid.clone(),
                claim_uid: owner.claim_uid.clone(),
                volume_uid: owner.volume_uid.clone(),
                operation_uid: intent.operation_uid().clone(),
                node_uid: self.config.node_uid.clone(),
                node_boot_id: boot.clone(),
                lv_uuid,
                drbd_device_uuid,
                exposed_capacity_bytes,
                evidence_sha256: evidence_sha256.clone(),
                pod_access_granted: false,
            };
            job.last_observation_sha256 = Some(evidence_sha256);
            job.last_unknown_sha256 = None;
            job.observed_stage(Stage::Complete, &dir, &name)?;
            Ok(prepared)
        })();
        if let Err(e) = &result {
            // Preserve the last durable intent. Never mark failed mutations
            // absent, unmount/demote, create replacement data or clear a writer.
            job.last_unknown_sha256 = Some(hash(e.as_bytes()));
            job.save(&dir, &name)?;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn durable_job_replay_binds_exact_intent_and_never_returns_cached_authority() {
        let root = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("royak-agent-job-{}", Uid::new().as_str()));
        let dir = Dir::open(&root, true).unwrap();
        let lock = dir.lock().unwrap();
        assert!(dir.lock().is_err()); // same mechanism as production admission
        let mut job = Job::load_or_new(&dir, "job.json", &"a".repeat(64)).unwrap();
        job.save(&dir, "job.json").unwrap();
        job.observed_stage(Stage::OnlineIntent, &dir, "job.json")
            .unwrap();
        job.last_unknown_sha256 = Some("b".repeat(64));
        job.save(&dir, "job.json").unwrap();
        let replay = Job::load_or_new(&dir, "job.json", &"a".repeat(64)).unwrap();
        assert_eq!(replay.stage, Stage::OnlineIntent);
        assert!(Job::load_or_new(&dir, "job.json", &"c".repeat(64)).is_err());
        job.stage = Stage::Complete;
        job.save(&dir, "job.json").unwrap();
        assert!(Job::load_or_new(&dir, "job.json", &"a".repeat(64)).is_err());
        drop(lock);
        drop(dir);
        std::fs::remove_dir_all(root).unwrap();
    }
}
