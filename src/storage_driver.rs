//! Optional, privileged Linux storage primitives. No pod mount is granted here.
//!
//! Operator maintenance entry points are limited to an explicitly fingerprinted
//! pool and brand-new, journal-owned LVs. The cluster lifecycle/controller and
//! DRBD/mount/fencing adapter still have to be connected and qualified.
#[path = "storage_driver/agent.rs"]
mod agent;
#[path = "storage_driver/capture.rs"]
pub(crate) mod capture;
#[path = "storage_driver/dispatcher.rs"]
pub(crate) mod dispatcher;
#[path = "storage_driver/job_cgroup.rs"]
mod job_cgroup;
pub(crate) use job_cgroup::ResourceBudget;
#[path = "storage_driver/live_authority.rs"]
mod live_authority;
#[path = "storage_driver/lvm.rs"]
mod lvm;
#[path = "storage_driver/node_identity.rs"]
pub(crate) mod node_identity;
#[path = "storage_driver/private_fs.rs"]
mod private_fs;
#[path = "storage_driver/process.rs"]
mod process;
#[path = "storage_driver/storage_remote_transport.rs"]
pub(crate) mod remote_transport;
#[path = "storage_driver/native_runtime.rs"]
pub(crate) mod native_runtime;
#[path = "storage_driver/replica.rs"]
mod replica;
pub(crate) use agent::{NativeAgent, SecondaryPrepared};
pub(crate) use replica::VirginReplica;
pub(in crate::storage_driver) use replica::initialize::managed_mount::WatchMountProbe as ManagedMountProbe;
pub(crate) use replica::initialize::managed_mount::VerifiedManagedMount;

use crate::storage_identity::Uid;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(clap::Subcommand)]
pub enum Action {
    /// Fixed local-root read-only namespace/anchor census; DATA only, no grant
    ObserveManagedAnchor,
    /// Explicitly create a NEW root-private node identity; reads WG, changes no network
    NodeIdentityInit {
        #[arg(long)]
        path: PathBuf,
        #[arg(long)]
        raft_id: u64,
        #[arg(long)]
        signer_name: String,
        #[arg(long)]
        interface: String,
    },
    /// Read an exact never-activated new replica; no journal/data writes or grants
    ReplicaVirginObserve {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        plan: PathBuf,
    },
    #[command(hide = true)]
    NativeWorker {
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        lease_fd: i32,
        #[arg(long)]
        capsule_fd: i32,
        #[arg(long)]
        control_fd: i32,
        #[arg(long)]
        attempt: String,
        #[arg(long)]
        cgroup_root: PathBuf,
    },
    /// Initialize only a fresh blank journal-owned DRBD replica; no writer or filesystem
    ReplicaCreate {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        plan: PathBuf,
    },
    /// Activate an exact replica as a closed Secondary over verified WireGuard
    ReplicaOnline {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        plan: PathBuf,
    },
    /// Take only an exact closed Secondary offline; never force/demote a writer
    ReplicaOffline {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        plan: PathBuf,
    },
    /// Observe the exact local replica without granting application access
    ReplicaObserve {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        plan: PathBuf,
    },
    /// Read-only inventory of an explicitly approved Linux pool
    Inspect {
        #[arg(long)]
        config: PathBuf,
    },
    /// Allocate and fully zero a NEW backing LV; does not format, mount or grant pod access
    Prepare {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        request: PathBuf,
    },
    /// Remove only an exact journal-owned LV still proven wholly zero and unformatted
    DiscardUnformatted {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        volume_uid: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    version: u32,
    cluster_id: String,
    node_uid: Uid,
    pool_uid: Uid,
    vg_name: String,
    vg_uuid: String,
    pv_uuid: String,
    disk_serial: String,
    max_volume_bytes: u64,
    max_managed_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    version: u32,
    cluster_id: String,
    node_uid: Uid,
    pool_uid: Uid,
    namespace_uid: Uid,
    claim_uid: Uid,
    volume_uid: Uid,
    operation_uid: Uid,
    capacity_bytes: u64,
}

fn lvm_uuid(value: &str) -> bool {
    value.len() == 38
        && value.split('-').map(str::len).eq([6, 4, 4, 4, 4, 4, 6])
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.+-".contains(&b))
}

impl Config {
    fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || self.cluster_id.len() != 12
            || !self
                .cluster_id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || !safe_name(&self.vg_name)
            || !lvm_uuid(&self.vg_uuid)
            || !lvm_uuid(&self.pv_uuid)
            || self.disk_serial.is_empty()
            || self.disk_serial.len() > 64
            || !self
                .disk_serial
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || self.node_uid == self.pool_uid
            || self.max_volume_bytes < 16 * 1024 * 1024
            || self.max_volume_bytes > 1024_u64.pow(4)
            || self.max_managed_bytes < 128 * 1024 * 1024
        {
            return Err("invalid approved storage-pool configuration".into());
        }
        Ok(())
    }
    fn load(path: &Path) -> Result<Self, String> {
        let config: Self = serde_json::from_slice(&private_fs::read_private(path)?)
            .map_err(|_| "invalid private pool JSON")?;
        config.validate()?;
        Ok(config)
    }
    fn journal_path(&self) -> PathBuf {
        Path::new("/var/lib/royak/storage/pools").join(self.pool_uid.as_str())
    }
}

impl Request {
    fn exposed_bytes(&self) -> Result<u64, String> {
        rounded_data_bytes(self.capacity_bytes)
    }
    fn validate(&self, cfg: &Config) -> Result<(), String> {
        if self.version != 1
            || self.cluster_id != cfg.cluster_id
            || self.node_uid != cfg.node_uid
            || self.pool_uid != cfg.pool_uid
            || self.capacity_bytes < 16 * 1024 * 1024
            || self.capacity_bytes > cfg.max_volume_bytes
            || [
                &self.namespace_uid,
                &self.claim_uid,
                &self.volume_uid,
                &self.operation_uid,
                &self.node_uid,
                &self.pool_uid,
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
                != 6
        {
            return Err(
                "allocation request does not match approved node/pool/identity/capacity".into(),
            );
        }
        Ok(())
    }
    fn lv_name(&self) -> String {
        format!("rkvol_{}", self.volume_uid.as_str())
    }
}

pub(crate) fn rounded_data_bytes(bytes: u64) -> Result<u64, String> {
    if bytes == 0 {
        return Err("zero capacity is not a block volume".into());
    }
    bytes
        .checked_add(4095)
        .map(|n| (n / 4096) * 4096)
        .ok_or("block volume capacity overflow".into())
}

pub fn run(action: &Action) -> Result<(), String> {
    if matches!(action,Action::ObserveManagedAnchor) {
        let value=replica::initialize::managed_mount::anchor::diagnostic()?;
        let bytes=serde_json::to_vec(&value).map_err(|_|"cannot encode bounded anchor diagnostic")?;
        if bytes.len()>1024*1024 {return Err("anchor diagnostic exceeds unchanged output bound".into());}
        println!("{}",String::from_utf8(bytes).map_err(|_|"anchor diagnostic encoding")?);
        return Ok(());
    }
    if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
        return Err("storage-driver requires an explicitly configured Linux root operator; no operation performed".into());
    }
    if let Action::NodeIdentityInit {
        path,
        raft_id,
        signer_name,
        interface,
    } = action
    {
        let pin = node_identity::initialize(path, *raft_id, signer_name, interface)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&pin).map_err(|_| "cannot encode new public node pin")?
        );
        return Ok(());
    }
    if let Action::NativeWorker {
        journal,
        lease_fd,
        capsule_fd,
        control_fd,
        attempt,
        cgroup_root,
    } = action
    {
        return dispatcher::run_worker(
            journal,
            *lease_fd,
            *capsule_fd,
            *control_fd,
            attempt,
            cgroup_root,
        );
    }
    let path = match action {
        Action::NativeWorker { .. } | Action::NodeIdentityInit { .. } | Action::ObserveManagedAnchor => unreachable!(),
        Action::ReplicaVirginObserve { config, .. } => config,
        Action::ReplicaCreate { config, .. }
        | Action::ReplicaOnline { config, .. }
        | Action::ReplicaOffline { config, .. }
        | Action::ReplicaObserve { config, .. } => config,
        Action::Inspect { config }
        | Action::Prepare { config, .. }
        | Action::DiscardUnformatted { config, .. } => config,
    };
    let config = Config::load(path)?;
    let value = match action {
        Action::NativeWorker { .. } | Action::NodeIdentityInit { .. } | Action::ObserveManagedAnchor => unreachable!(),
        Action::ReplicaVirginObserve { plan, .. } => {
            let plan: replica::Plan = serde_json::from_slice(&private_fs::read_private(plan)?)
                .map_err(|_| "invalid private replica plan")?;
            serde_json::to_value(replica::observe_virgin(&config, &plan)?)
        }
        Action::ReplicaCreate { plan, .. }
        | Action::ReplicaOnline { plan, .. }
        | Action::ReplicaOffline { plan, .. }
        | Action::ReplicaObserve { plan, .. } => {
            let plan: replica::Plan = serde_json::from_slice(&private_fs::read_private(plan)?)
                .map_err(|_| "invalid private replication plan JSON")?;
            let mode = match action {
                Action::ReplicaCreate { .. } => replica::Mode::Create,
                Action::ReplicaOnline { .. } => replica::Mode::Online,
                Action::ReplicaOffline { .. } => replica::Mode::Offline,
                _ => replica::Mode::Observe,
            };
            serde_json::to_value(replica::run(&config, &plan, mode)?)
        }
        Action::Inspect { .. } => serde_json::to_value(lvm::inspect(&config)?),
        Action::Prepare { request, .. } => {
            let request: Request = serde_json::from_slice(&private_fs::read_private(request)?)
                .map_err(|_| "invalid private allocation request JSON")?;
            request.validate(&config)?;
            serde_json::to_value(lvm::prepare(&config, &request)?)
        }
        Action::DiscardUnformatted { volume_uid, .. } => {
            let uid: Uid = serde_json::from_value(serde_json::json!(volume_uid))
                .map_err(|_| "invalid volume UID")?;
            serde_json::to_value(lvm::discard(&config, &uid)?)
        }
    }
    .map_err(|_| "cannot encode storage-driver result")?;
    println!(
        "{}",
        serde_json::to_string_pretty(&value).map_err(|_| "cannot encode result")?
    );
    Ok(())
}

#[cfg(test)]
fn test_config() -> Config {
    Config {
        version: 1,
        cluster_id: "123456abcdef".into(),
        node_uid: Uid::new(),
        pool_uid: Uid::new(),
        vg_name: "rkqs_test".into(),
        vg_uuid: "AAAAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAAAA".into(),
        pv_uuid: "BBBBBB-BBBB-BBBB-BBBB-BBBB-BBBB-BBBBBB".into(),
        disk_serial: "DISK_TEST_1".into(),
        max_volume_bytes: 128 * 1024 * 1024,
        max_managed_bytes: 256 * 1024 * 1024,
    }
}
#[cfg(test)]
fn test_request(c: &Config) -> Request {
    Request {
        version: 1,
        cluster_id: c.cluster_id.clone(),
        node_uid: c.node_uid.clone(),
        pool_uid: c.pool_uid.clone(),
        namespace_uid: Uid::new(),
        claim_uid: Uid::new(),
        volume_uid: Uid::new(),
        operation_uid: Uid::new(),
        capacity_bytes: 64 * 1024 * 1024,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requested_byte_capacity_rounds_up_without_silent_underallocation() {
        assert_eq!(
            rounded_data_bytes(16 * 1024 * 1024).unwrap(),
            16 * 1024 * 1024
        );
        assert_eq!(
            rounded_data_bytes(16 * 1024 * 1024 + 1).unwrap(),
            16 * 1024 * 1024 + 4096
        );
        assert!(rounded_data_bytes(0).is_err());
        assert!(rounded_data_bytes(u64::MAX).is_err());
    }
    #[test]
    fn config_and_request_are_typed_bounded_and_cannot_target_another_pool() {
        let c = test_config();
        c.validate().unwrap();
        let r = test_request(&c);
        r.validate(&c).unwrap();
        for i in 0..7 {
            let mut c = c.clone();
            match i {
                0 => c.vg_name = "--help".into(),
                1 => c.vg_uuid = "../../disk".into(),
                2 => c.disk_serial = "disk\nroot".into(),
                3 => c.version = 2,
                4 => c.max_volume_bytes = 0,
                5 => c.node_uid = c.pool_uid.clone(),
                _ => c.cluster_id = "LEGACY".into(),
            }
            assert!(c.validate().is_err());
        }
        for i in 0..5 {
            let mut r = r.clone();
            match i {
                0 => r.node_uid = Uid::new(),
                1 => r.pool_uid = Uid::new(),
                2 => r.capacity_bytes = u64::MAX,
                3 => r.namespace_uid = r.volume_uid.clone(),
                _ => r.version = 0,
            }
            assert!(r.validate(&c).is_err());
        }
        let mut value = serde_json::to_value(&c).unwrap();
        value["command"] = "wipefs".into();
        assert!(serde_json::from_value::<Config>(value).is_err());
    }
}

