//! Journalled DRBD lifecycle for an exact NEW backing LV. This layer can only
//! create metadata, activate a closed Secondary, observe it, or take it offline.
//! The unconnected initializer review module is separate from these operator
//! modes; neither path grants a mount, application writer or Core receipt.
use super::{
    lvm,
    private_fs::Dir,
    process::{self, Program},
    Config,
};
use crate::storage_identity::Uid;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::net::Ipv4Addr;
#[path = "replica_guard.rs"]
mod guard;
#[path = "replica_initialize.rs"]
pub(super) mod initialize;
#[path="replica_initialized_activation.rs"]
pub(in crate::storage_driver) mod initialized_activation;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Peer {
    node_uid: Uid,
    node_id: u8,
    hostname: String,
    address: Ipv4Addr,
    public_key: String,
    vg_name: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    version: u32,
    cluster_id: String,
    pool_uid: Uid,
    volume_uid: Uid,
    operation_uid: Uid,
    minor: u16,
    port: u16,
    interface: String,
    shared_secret: String,
    peers: [Peer; 3],
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Stage {
    MetadataIntent,
    MetadataReady,
    OnlineIntent,
    Online,
    OfflineIntent,
    Offline,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u32,
    plan: Plan,
    allocation_nonce: Uid,
    lv_uuid: String,
    stage: Stage,
    device_uuid: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    sha256: String,
    record: Record,
}
#[derive(Clone, Copy)]
pub(super) enum Mode {
    Create,
    Online,
    Offline,
    Observe,
}
#[derive(Serialize)]
pub(super) struct Receipt {
    kind: &'static str,
    volume_uid: Uid,
    node_uid: Uid,
    boot_id: String,
    operation_uid: Uid,
    resource: String,
    minor: u16,
    capacity_bytes: u64,
    exposed_capacity_bytes: u64,
    lv_uuid: String,
    device_uuid: String,
    plan_sha256: String,
    stage: Stage,
    kernel: Option<Value>,
    encrypted_only_guard_table: Option<String>,
    pod_access_granted: bool,
}
fn hash(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

/// Actual local observation. It deliberately cannot be deserialized from
/// stdout/JSON; the persisted reference is provenance, not this capability.
#[derive(Debug,Serialize)]
pub(crate) struct VirginReplica {
    kind:&'static str,
    reference:crate::storage_lifecycle::generation::VirginReplicaRef,
}
impl VirginReplica {
    pub(crate) fn into_reference(self)->crate::storage_lifecycle::generation::VirginReplicaRef{self.reference}
}
fn pristine_metadata_identity(dump:&str,node:u8)->Result<String,String>{
    let (device,current)=parse_metadata(dump,node)?;
    let nodes:Vec<_>=dump.lines().filter_map(|line|line.strip_prefix("node-id ")).collect();
    if nodes.len()!=1 || nodes[0].trim()!="-1;" || current!="0000000000000004"{
        return Err("fresh initializer requires never-activated UUID_JUST_CREATED metadata".into());
    }
    Ok(device)
}
/// Reads only an existing exact MetadataReady allocation. There is no journal
/// creation/publication, apply-al, up/down, zero write, promotion or filesystem
/// command. An exclusive O_DIRECT full exposed-data read is independently
/// bracketed by pristine metadata, exact config/record and absent-kernel checks.
pub(super) fn observe_virgin(cfg:&Config,plan:&Plan)->Result<VirginReplica,String>{
    if !cfg!(target_os="linux") || unsafe{libc::geteuid()}!=0{
        return Err("real virgin observation requires the Linux root node agent".into());
    }
    plan.validate(cfg)?;
    if hostname()?!=plan.local(cfg)?.hostname{return Err("virgin probe is not on the pinned node".into());}
    let (dir,_lock,pool,allocation,lv)=lvm::prepared_context_readonly(cfg,&plan.volume_uid)?;
    if allocation.request.operation_uid!=plan.operation_uid || status(plan)?.is_some(){return Err("virgin probe requires exact offline preparation".into());}
    let record=load(&dir,plan)?.ok_or("virgin replica journal absent")?;
    if record.stage!=Stage::MetadataReady || record.lv_uuid!=lv.uuid || record.allocation_nonce!=allocation.allocation_nonce{
        return Err("only never-activated exact MetadataReady replicas are virgin".into());
    }
    let journal_before=dir.read(&journal_name(plan))?.ok_or("replica journal disappeared")?;
    let expected_config=plan.config(allocation.request.exposed_bytes()?);
    if dir.read(&config_name(plan))?.as_deref()!=Some(expected_config.as_bytes()){
        return Err("virgin replica configuration differs from its immutable plan".into());
    }
    let read_identity=||->Result<String,String>{
        if status(plan)?.is_some(){return Err("virgin resource became active".into());}
        lvm::verify_unheld(&lv)?;
        let dump=String::from_utf8(adm(cfg,plan,"dump-md")?).map_err(|_|"invalid virgin metadata output")?;
        let device=pristine_metadata_identity(&dump,plan.local(cfg)?.node_id)?;
        verify_superblock(cfg,plan,&lv,&device)?;
        if record.device_uuid.as_deref()!=Some(&device){return Err("virgin DRBD device UUID changed".into());}
        Ok(device)
    };
    let device=read_identity()?;
    let zero=lvm::verify_zero_data(cfg,&allocation,&lv)?;
    if read_identity()?!=device || dir.read(&journal_name(plan))?.as_deref()!=Some(journal_before.as_slice())
        || dir.read(&config_name(plan))?.as_deref()!=Some(expected_config.as_bytes())
        || crate::storage_boot::BootId::current()?.as_str()!=pool.boot_id
    {return Err("virgin identity/boot/journal changed across direct observation".into());}
    let observed=serde_json::to_vec(&serde_json::json!({"version":1,"volume_uid":plan.volume_uid,
        "prepare_operation_uid":plan.operation_uid,"node_uid":cfg.node_uid,"boot_id":pool.boot_id,
        "pool_uid":cfg.pool_uid,"allocation_nonce":allocation.allocation_nonce,"lv_uuid":lv.uuid,
        "device_uuid":device,"capacity_bytes":allocation.request.capacity_bytes,
        "exposed_bytes":allocation.request.exposed_bytes()?,"zero_sha256":zero,
        "replica_journal_sha256":hash(&journal_before),"plan_sha256":hash(&serde_json::to_vec(plan).map_err(|_|"cannot bind plan")?)}))
        .map_err(|_|"cannot bind virgin observation")?;
    let reference=crate::storage_lifecycle::generation::VirginReplicaRef{
        volume_uid:plan.volume_uid.clone(),prepare_operation_uid:plan.operation_uid.clone(),node_uid:cfg.node_uid.clone(),
        node_boot_id:serde_json::from_value(serde_json::json!(pool.boot_id)).map_err(|_|"invalid actual node boot")?,
        pool_uid:cfg.pool_uid.clone(),allocation_nonce:allocation.allocation_nonce,
        lv_uuid:lv.uuid,drbd_device_uuid:device,requested_bytes:allocation.request.capacity_bytes,
        exposed_bytes:allocation.request.exposed_bytes()?,plan_sha256:hash(&serde_json::to_vec(plan).map_err(|_|"cannot bind plan")?),
        zero_sha256:zero,observation_sha256:hash(&observed)};
    reference.validate()?;
    Ok(VirginReplica{kind:"royak-virgin-offline-replica-observation-v1",reference})
}

/// Consumes only an actual kernel-backed helper result, never diagnostic JSON.
pub(super) fn verified_secondary(
    receipt: Receipt,
    cfg: &Config,
    plan: &Plan,
    intent: &crate::storage_controller::ProvisionIntent,
    boot: &crate::storage_boot::BootId,
) -> Result<(String, String, u64, String), String> {
    let expected = plan.bind_intent(cfg, intent)?;
    if receipt.kind != "royak-secondary-replica-v1"
        || receipt.node_uid != cfg.node_uid
        || receipt.boot_id != boot.as_str()
        || receipt.volume_uid != intent.owner().volume_uid
        || receipt.operation_uid != *intent.operation_uid()
        || receipt.capacity_bytes != intent.capacity_bytes()
        || receipt.plan_sha256 != expected
        || receipt.stage != Stage::Online
        || receipt.kernel.is_none()
        || receipt.encrypted_only_guard_table.is_none()
        || receipt.pod_access_granted
        || receipt.lv_uuid.is_empty()
        || receipt.device_uuid.len() != 16
        || receipt.device_uuid == "0000000000000000"
    {
        return Err("kernel-backed result does not prove the exact closed Secondary".into());
    }
    let digest = hash(&serde_json::to_vec(&receipt).map_err(|_| "cannot bind helper evidence")?);
    Ok((
        receipt.lv_uuid,
        receipt.device_uuid,
        receipt.exposed_capacity_bytes,
        digest,
    ))
}
fn host(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.as_bytes()[0].is_ascii_alphanumeric()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-".contains(&c))
}
fn key(s: &str) -> bool {
    s.len() == 44
        && s.ends_with('=')
        && s.as_bytes()[..43]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(b))
}
impl Plan {
    pub(super) fn bind_intent(
        &self,
        cfg: &Config,
        intent: &crate::storage_controller::ProvisionIntent,
    ) -> Result<String, String> {
        self.validate(cfg)?;
        let owner = intent.owner();
        if self.cluster_id != owner.cluster_id
            || self.volume_uid != owner.volume_uid
            || self.operation_uid != *intent.operation_uid()
            || self
                .peers
                .iter()
                .map(|p| &p.node_uid)
                .collect::<BTreeSet<_>>()
                != intent
                    .targets()
                    .iter()
                    .map(|t| &t.node_uid)
                    .collect::<BTreeSet<_>>()
        {
            return Err(
                "physical replica plan differs from the committed volume operation/replicas".into(),
            );
        }
        Ok(hash(
            &serde_json::to_vec(self).map_err(|_| "cannot hash replica plan")?,
        ))
    }
    fn name(&self) -> String {
        format!("rkv{}", self.volume_uid.as_str())
    }
    fn local<'a>(&'a self, cfg: &Config) -> Result<&'a Peer, String> {
        self.peers
            .iter()
            .find(|p| p.node_uid == cfg.node_uid)
            .ok_or("local node is not a planned replica".into())
    }
    fn validate(&self, cfg: &Config) -> Result<(), String> {
        if self.version != 1
            || self.cluster_id != cfg.cluster_id
            || self.pool_uid != cfg.pool_uid
            || !(512..=32767).contains(&self.minor)
            || !(20000..=59999).contains(&self.port)
            || self.interface.is_empty()
            || self.interface.len() > 15
            || !self
                .interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || self.shared_secret.len() != 48
            || !self
                .shared_secret
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            || self
                .peers
                .iter()
                .map(|p| &p.node_uid)
                .collect::<BTreeSet<_>>()
                .len()
                != 3
            || self
                .peers
                .iter()
                .map(|p| &p.hostname)
                .collect::<BTreeSet<_>>()
                .len()
                != 3
            || self
                .peers
                .iter()
                .map(|p| p.address)
                .collect::<BTreeSet<_>>()
                .len()
                != 3
            || self
                .peers
                .iter()
                .map(|p| &p.public_key)
                .collect::<BTreeSet<_>>()
                .len()
                != 3
            || self.peers.iter().enumerate().any(|(i, p)| {
                p.node_id != i as u8
                    || !host(&p.hostname)
                    || !key(&p.public_key)
                    || !p.address.is_private()
                    || !super::safe_name(&p.vg_name)
            })
            || self.local(cfg)?.vg_name != cfg.vg_name
        {
            return Err("invalid replication plan/node/pool/transport identities".into());
        }
        Ok(())
    }
    fn config(&self, capacity: u64) -> String {
        let mut text = format!(
            "global {{ usage-count no; }}\nresource {} {{\n",
            self.name()
        );
        text.push_str(" options { auto-promote no; quorum majority; quorum-minimum-redundancy 2; on-no-quorum io-error; on-no-data-accessible io-error; }\n");
        text.push_str(&format!(" net {{ protocol C; allow-two-primaries no; cram-hmac-alg sha256; shared-secret \"{}\"; verify-alg sha256; }}\n",self.shared_secret));
        text.push_str(&format!(
            " disk {{ size {}k; disk-flushes yes; md-flushes yes; on-io-error detach; }}\n",
            capacity / 1024
        ));
        for p in &self.peers {
            text.push_str(&format!(" on {} {{ node-id {}; address {}:{}; device /dev/drbd{}; disk /dev/{}/rkvol_{}; meta-disk internal; }}\n",
                p.hostname,p.node_id,p.address,self.port,self.minor,p.vg_name,self.volume_uid.as_str()));
        }
        text.push_str(&format!(
            " connection-mesh {{ hosts {}; }}\n}}\n",
            self.peers
                .iter()
                .map(|p| p.hostname.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        ));
        text
    }
}
fn output(program: Program, args: &[String]) -> Result<Vec<u8>, String> {
    process::run(program, args)?.success(&format!("{program:?}"))
}
fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}
fn hostname() -> Result<String, String> {
    let mut value = [0u8; 256];
    if unsafe { libc::gethostname(value.as_mut_ptr().cast(), value.len()) } != 0 {
        return Err("cannot read local hostname".into());
    }
    let end = value
        .iter()
        .position(|b| *b == 0)
        .ok_or("unterminated hostname")?;
    String::from_utf8(value[..end].to_vec()).map_err(|_| "invalid hostname".into())
}
fn transport(cfg: &Config, plan: &Plan) -> Result<(), String> {
    let local = plan.local(cfg)?;
    if hostname()? != local.hostname {
        return Err("replica hostname does not match the pinned local node".into());
    }
    let text = |args: &[&str]| -> Result<String, String> {
        String::from_utf8(output(Program::Wireguard, &strings(args))?)
            .map_err(|_| "invalid WireGuard output".into())
    };
    if text(&["show", &plan.interface, "public-key"])?.trim() != local.public_key {
        return Err("local WireGuard identity mismatch".into());
    }
    let expected = plan
        .peers
        .iter()
        .filter(|p| p.node_uid != cfg.node_uid)
        .map(|p| p.public_key.as_str())
        .collect::<BTreeSet<_>>();
    let actual = text(&["show", &plan.interface, "peers"])?;
    if actual.split_whitespace().collect::<BTreeSet<_>>() != expected {
        return Err("WireGuard peer set mismatch".into());
    }
    let allowed = text(&["show", &plan.interface, "allowed-ips"])?;
    let mut seen = BTreeSet::new();
    for line in allowed.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() != 2 {
            return Err("ambiguous WireGuard allowed IPs".into());
        }
        let peer = plan
            .peers
            .iter()
            .find(|p| p.public_key == parts[0] && p.node_uid != cfg.node_uid)
            .ok_or("unknown WireGuard peer")?;
        if parts[1] != format!("{}/32", peer.address) || !seen.insert(parts[0]) {
            return Err("WireGuard allows an unexpected address or duplicate peer".into());
        }
    }
    if seen != expected {
        return Err("incomplete WireGuard address map".into());
    }
    let addr: Value = serde_json::from_slice(&output(
        Program::Ip,
        &strings(&["-j", "address", "show", "dev", &plan.interface]),
    )?)
    .map_err(|_| "invalid IP inventory")?;
    let links = addr
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("missing transport interface")?;
    let flags = links[0]["flags"]
        .as_array()
        .ok_or("missing interface flags")?;
    let addresses = links[0]["addr_info"]
        .as_array()
        .ok_or("missing interface addresses")?;
    if !flags.iter().any(|f| f == "UP")
        || !addresses.iter().any(|a| {
            a["family"] == "inet" && a["local"] == local.address.to_string() && a["prefixlen"] == 32
        })
    {
        return Err("encrypted transport address is not up on the approved interface".into());
    }
    for peer in plan.peers.iter().filter(|p| p.node_uid != cfg.node_uid) {
        let route: Value = serde_json::from_slice(&output(
            Program::Ip,
            &strings(&["-j", "route", "get", &peer.address.to_string()]),
        )?)
        .map_err(|_| "invalid route inventory")?;
        let routes = route
            .as_array()
            .filter(|a| a.len() == 1)
            .ok_or("ambiguous replica route")?;
        if routes[0]["dev"] != plan.interface || routes[0]["prefsrc"] != local.address.to_string() {
            return Err("replica route bypasses the approved WireGuard interface".into());
        }
    }
    Ok(())
}
fn all_status() -> Result<Vec<Value>, String> {
    serde_json::from_slice::<Value>(&output(
        Program::Drbdsetup,
        &strings(&["status", "--json"]),
    )?)
    .map_err(|_| "invalid DRBD status JSON")?
    .as_array()
    .cloned()
    .ok_or("invalid DRBD status array".into())
}
fn status(plan: &Plan) -> Result<Option<Value>, String> {
    let all = all_status()?;
    let named: Vec<_> = all.iter().filter(|v| v["name"] == plan.name()).collect();
    if named.len() > 1 {
        return Err("ambiguous active resource identity".into());
    }
    if all.iter().filter(|v| v["name"] != plan.name()).any(|v| {
        v["devices"]
            .as_array()
            .is_some_and(|d| d.iter().any(|d| d["minor"] == plan.minor))
    }) {
        return Err("planned minor belongs to another DRBD resource".into());
    }
    Ok(named.first().map(|v| (*v).clone()))
}
fn secondary(cfg: &Config, plan: &Plan, capacity: u64, state: &Value) -> Result<(), String> {
    let capacity = super::rounded_data_bytes(capacity)?;
    let dev = state["devices"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("replica has an unexpected device set")?;
    if state["node-id"] != plan.local(cfg)?.node_id
        || state["role"] != "Secondary"
        || dev[0]["minor"] != plan.minor
        || dev[0]["volume"] != 0
        || dev[0]["open"] != false
        || dev[0]["size"] != capacity / 1024
    {
        return Err(
            "replica is not the exact closed Secondary; never force a writer offline".into(),
        );
    }
    let peers = state["connections"]
        .as_array()
        .filter(|a| a.len() == 2)
        .ok_or("unexpected DRBD connection set")?;
    let mut seen = BTreeSet::new();
    for peer in peers {
        let id = peer["peer-node-id"]
            .as_u64()
            .ok_or("missing peer node identity")?;
        let expected = plan
            .peers
            .iter()
            .find(|p| p.node_id as u64 == id && p.node_uid != cfg.node_uid)
            .ok_or("unplanned active peer")?;
        if !seen.insert(id) || peer["name"] != expected.hostname {
            return Err("DRBD peer identity mismatch".into());
        }
        let paths = peer["paths"]
            .as_array()
            .filter(|a| a.len() == 1)
            .ok_or("unexpected DRBD path set")?;
        let path = &paths[0];
        let local = plan.local(cfg)?;
        if path["this_host"]["address"] != local.address.to_string()
            || path["remote_host"]["address"] != expected.address.to_string()
            || path["this_host"]["port"] != plan.port
            || path["remote_host"]["port"] != plan.port
        {
            return Err("DRBD path differs from the encrypted plan".into());
        }
    }
    Ok(())
}
fn values<'a>(v: &'a Value, key: &str, out: &mut Vec<&'a Value>) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                if k == key {
                    out.push(v);
                }
                values(v, key, out);
            }
        }
        Value::Array(a) => {
            for v in a {
                values(v, key, out);
            }
        }
        _ => (),
    }
}
fn same_existing_paths(
    expected: &std::path::Path,
    observed: &Value,
) -> Result<std::path::PathBuf, String> {
    let expected = std::fs::canonicalize(expected)
        .map_err(|_| "expected backing path is missing or unresolved")?;
    let observed = observed
        .as_str()
        .ok_or("kernel backing path is not a string")?;
    let observed = std::fs::canonicalize(observed)
        .map_err(|_| "kernel backing path is missing or unresolved")?;
    if observed != expected {
        return Err("active DRBD backing does not match the pinned new LV".into());
    }
    Ok(observed)
}
fn kernel_config(cfg: &Config, plan: &Plan, lv: &lvm::Lv) -> Result<(), String> {
    let show: Value = serde_json::from_slice(&output(
        Program::Drbdsetup,
        &strings(&["show", &plan.name(), "--json"]),
    )?)
    .map_err(|_| "invalid DRBD kernel configuration")?;
    for (key, allowed) in [
        (
            "auto-promote",
            vec![Value::Bool(false), Value::String("no".into())],
        ),
        ("quorum", vec![Value::String("majority".into())]),
        (
            "quorum-minimum-redundancy",
            vec![Value::from(2), Value::String("2".into())],
        ),
        ("on-no-quorum", vec![Value::String("io-error".into())]),
        (
            "on-no-data-accessible",
            vec![Value::String("io-error".into())],
        ),
        ("protocol", vec![Value::String("C".into())]),
        (
            "allow-two-primaries",
            vec![Value::Bool(false), Value::String("no".into())],
        ),
        (
            "disk-flushes",
            vec![Value::Bool(true), Value::String("yes".into())],
        ),
        (
            "md-flushes",
            vec![Value::Bool(true), Value::String("yes".into())],
        ),
    ] {
        let mut got = Vec::new();
        values(&show, key, &mut got);
        if got.is_empty() || got.iter().any(|v| !allowed.contains(v)) {
            return Err(format!(
                "kernel DRBD safety option {key} is missing or changed"
            ));
        }
    }
    let mut disks = Vec::new();
    values(&show, "backing-disk", &mut disks);
    let expected = format!("/dev/{}/rkvol_{}", cfg.vg_name, plan.volume_uid.as_str());
    if disks.len() != 1 {
        return Err("unexpected active DRBD backing set".into());
    }
    verify_backing_path(std::path::Path::new(&expected), disks[0], lv)
}
fn verify_backing_path(
    expected: &std::path::Path,
    observed: &Value,
    lv: &lvm::Lv,
) -> Result<(), String> {
    let backing = same_existing_paths(expected, observed)?;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let meta = std::fs::metadata(backing).map_err(|_| "cannot stat active backing device")?;
    if !meta.file_type().is_block_device()
        || libc::major(meta.rdev() as _) as u64 != lv.major
        || libc::minor(meta.rdev() as _) as u64 != lv.minor
    {
        return Err("active backing major/minor does not match the exact LV".into());
    }
    Ok(())
}
fn journal_name(plan: &Plan) -> String {
    format!("replica-{}.json", plan.volume_uid.as_str())
}
fn config_name(plan: &Plan) -> String {
    format!("replica-{}.conf", plan.volume_uid.as_str())
}
fn save(dir: &Dir, r: &Record) -> Result<(), String> {
    let bytes = serde_json::to_vec(r).map_err(|_| "cannot encode private replica journal")?;
    let value = serde_json::to_vec(&Envelope {
        version: 1,
        sha256: hash(&bytes),
        record: serde_json::from_slice(&bytes).map_err(|_| "invalid replica record")?,
    })
    .map_err(|_| "cannot encode replica envelope")?;
    dir.write(&journal_name(&r.plan), &value)
}
fn load(dir: &Dir, plan: &Plan) -> Result<Option<Record>, String> {
    let Some(bytes) = dir.read(&journal_name(plan))? else {
        return Ok(None);
    };
    let e: Envelope = serde_json::from_slice(&bytes)
        .map_err(|_| "corrupt replica journal; never reinitialize")?;
    if e.version != 1
        || e.record.version != 1
        || hash(&serde_json::to_vec(&e.record).map_err(|_| "invalid replica record")?) != e.sha256
        || e.record.plan != *plan
        || (e.record.stage != Stage::MetadataIntent && e.record.device_uuid.is_none())
    {
        return Err(
            "replica journal checksum/plan/operation mismatch; never adopt or reinitialize".into(),
        );
    }
    Ok(Some(e.record))
}
fn adm(cfg: &Config, plan: &Plan, op: &str) -> Result<Vec<u8>, String> {
    process::run(
        Program::Drbdadm,
        &strings(&[
            "-c",
            cfg.journal_path()
                .join(config_name(plan))
                .to_str()
                .ok_or("invalid internal config path")?,
            op,
            &plan.name(),
        ]),
    )?
    .success(&format!("drbdadm {op}"))
}
fn validate_superblock(
    raw: &Value,
    expected_node: u8,
    expected_bytes: u64,
    device_uuid: &str,
) -> Result<(), String> {
    let uuid = raw["device_uuid"]
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .filter(|s| s.len() == 16 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("missing or malformed superblock device identity")?;
    let node = raw["node_id"]
        .as_i64()
        .ok_or("missing superblock node identity")?;
    if uuid.to_ascii_lowercase() != device_uuid
        || raw["magic"] != "0x8374026D"
        || raw["bm_max_peers"] != 2
        || (node != -1 && node != expected_node as i64)
        || raw["#meta"]["bd_size"] != expected_bytes
        || raw["#meta"]["dump_offset"]
            .as_u64()
            .and_then(|n| n.checked_add(4096))
            != Some(expected_bytes)
        || raw["#meta"]["valid"] != "VALID_MD_FOUND"
        || raw["#meta"]["dumped_as"] != "v09"
        || raw["#meta"]["looks_like"] != "v09"
    {
        return Err("offline superblock is not the exact planned v09 backing incarnation".into());
    }
    if node == -1
        && (raw["current_uuid"] != "0x0000000000000004"
            || raw["effective_size"] != 0
            || raw["flags"] != "0x00000080"
            || raw["members"] != "0x0000000000000000")
    {
        return Err("unassigned superblock contains prior data authority".into());
    }
    Ok(())
}
fn verify_superblock(
    cfg: &Config,
    plan: &Plan,
    lv: &lvm::Lv,
    device_uuid: &str,
) -> Result<(), String> {
    lvm::verify_unheld(lv)?;
    let path = format!("/dev/{}/rkvol_{}", cfg.vg_name, plan.volume_uid.as_str());
    let raw: Value = serde_json::from_slice(&output(
        Program::Drbdmeta,
        &strings(&[
            &plan.minor.to_string(),
            "v09",
            &path,
            "internal",
            "dump-superblock",
            "--output-format=json",
        ]),
    )?)
    .map_err(|_| "invalid offline superblock JSON")?;
    validate_superblock(&raw, plan.local(cfg)?.node_id, lv.bytes, device_uuid)?;
    verify_backing_path(
        std::path::Path::new(&path),
        &raw["#meta"]["md_device_name"],
        lv,
    )
}
fn metadata(cfg: &Config, plan: &Plan) -> Result<(String, String), String> {
    let dump =
        String::from_utf8(adm(cfg, plan, "dump-md")?).map_err(|_| "invalid metadata dump")?;
    parse_metadata(&dump, plan.local(cfg)?.node_id)
}
fn parse_metadata(dump: &str, expected_node: u8) -> Result<(String, String), String> {
    let one = |prefix: &str| -> Result<String, String> {
        let rows = dump
            .lines()
            .filter_map(|s| s.strip_prefix(prefix))
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err("missing/ambiguous metadata identity".into());
        }
        Ok(rows[0].trim().trim_end_matches(';').to_string())
    };
    let node = one("node-id ")?;
    if one("version ")? != "\"v09\""
        || (node != "-1" && node != expected_node.to_string())
        || one("max-peers ")? != "2"
    {
        return Err("metadata version/node/peer geometry mismatch".into());
    }
    let parse = |s: String| -> Result<String, String> {
        let s = s.strip_prefix("0x").ok_or("invalid metadata UUID")?;
        if s.len() != 16 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid metadata UUID".into());
        }
        Ok(s.to_ascii_lowercase())
    };
    let device = parse(one("device-uuid ")?)?;
    let current = parse(one("current-uuid ")?)?;
    if device == "0000000000000000" {
        return Err("metadata has no backend device identity".into());
    }
    if node == "-1" {
        // DRBD v09 create-md leaves a deliberately unattached node-id -1,
        // zero effective size and UUID_JUST_CREATED (4), not a data generation.
        // Accept this only with the complete pristine metadata signature.
        // The kernel's exact planned node-id is separately required after up.
        if current != "0000000000000004"
            || one("la-size-sect ")? != "0"
            || one("flags ")? != "0x00000080"
            || one("members ")? != "0x0000000000000000"
        {
            return Err("unassigned metadata is not a pristine newly created replica".into());
        }
        for (field, expected) in [
            ("bitmap-index ", "-1"),
            ("bitmap-uuid ", "0x0000000000000000"),
            ("bitmap-dagtag ", "0x0000000000000000"),
            ("flags ", "0x00000000"),
        ] {
            let values = dump
                .lines()
                .filter(|s| s.starts_with(char::is_whitespace))
                .filter_map(|s| s.trim().strip_prefix(field))
                .collect::<Vec<_>>();
            if values.len() != 32
                || values
                    .iter()
                    .any(|v| v.trim().trim_end_matches(';') != expected)
            {
                return Err("unassigned metadata has prior peer authority".into());
            }
        }
        let histories = dump.split("history-uuids {").collect::<Vec<_>>();
        if histories.len() != 2 {
            return Err("missing or ambiguous metadata history".into());
        }
        let history = histories[1]
            .split_once('}')
            .ok_or("unterminated metadata history")?
            .0;
        let entries = history
            .split_whitespace()
            .map(|v| v.trim_end_matches(';'))
            .collect::<Vec<_>>();
        if entries.len() != 32 || entries.iter().any(|s| *s != "0x0000000000000000") {
            return Err("unassigned metadata contains data history".into());
        }
    }
    Ok((device, current))
}

pub(super) fn run(cfg: &Config, plan: &Plan, mode: Mode) -> Result<Receipt, String> {
    plan.validate(cfg)?;
    let (dir, _lock, pool, allocation, lv) = lvm::prepared_context(cfg, &plan.volume_uid)?;
    if pool
        .drbd_module_version
        .as_ref()
        .is_none_or(|s| !s.starts_with("9."))
    {
        return Err("approved DRBD9 kernel module is not loaded".into());
    }
    if allocation.request.operation_uid != plan.operation_uid {
        return Err("replica operation is not the committed backing-allocation intent".into());
    }
    if status(plan)?.is_none() {
        // Inspect the actual block major/minor, not just our planned DRBD
        // resource/minor. A holder using an alias is equally authoritative.
        lvm::verify_unheld(&lv)?;
    }
    let conf = plan.config(allocation.request.exposed_bytes()?);
    let mut record = if let Some(r) = load(&dir, plan)? {
        if r.lv_uuid != lv.uuid || r.allocation_nonce != allocation.allocation_nonce {
            return Err("replica backing incarnation changed".into());
        }
        match dir.read(&config_name(plan))? {
            Some(bytes) if bytes == conf.as_bytes() => (),
            None if r.stage == Stage::MetadataIntent && status(plan)?.is_none() => {
                // Crash between the durable intent and private config publish.
                // Recreate only while the exact fresh LV is still wholly blank.
                lvm::verify_blank(cfg, &allocation, &lv)?;
                dir.write(&config_name(plan), conf.as_bytes())?;
            }
            _ => {
                return Err(
                    "private DRBD configuration changed; never rewrite it implicitly".into(),
                )
            }
        }
        r
    } else {
        if !matches!(mode, Mode::Create)
            || status(plan)?.is_some()
            || dir.read(&config_name(plan))?.is_some()
        {
            return Err("unknown replica/configuration is never adopted".into());
        }
        transport(cfg, plan)?;
        lvm::verify_blank(cfg, &allocation, &lv)?;
        let r = Record {
            version: 1,
            plan: plan.clone(),
            allocation_nonce: allocation.allocation_nonce.clone(),
            lv_uuid: lv.uuid.clone(),
            stage: Stage::MetadataIntent,
            device_uuid: None,
        };
        save(&dir, &r)?;
        dir.write(&config_name(plan), conf.as_bytes())?;
        r
    };
    let guard = guard::Guard::new(cfg, plan, &record.allocation_nonce)?;
    match mode {
        Mode::Create => {
            if record.stage == Stage::MetadataIntent {
                if status(plan)?.is_some() {
                    return Err(
                        "initial metadata outcome is ambiguous while a resource is active".into(),
                    );
                }
                let observed = match metadata(cfg, plan) {
                    Ok(value) => value,
                    Err(_) => {
                        lvm::verify_blank(cfg,&allocation,&lv).map_err(|_|"metadata outcome UNKNOWN and backing is not wholly blank; never overwrite")?;
                        adm(cfg, plan, "create-md")?;
                        metadata(cfg, plan)?
                    }
                };
                if observed.1 != "0000000000000004" {
                    return Err("initial metadata unexpectedly contains a data generation; adoption refused".into());
                }
                lvm::verify_zero_data(cfg, &allocation, &lv)?;
                record.device_uuid = Some(observed.0);
                record.stage = Stage::MetadataReady;
                save(&dir, &record)?;
            }
        }
        Mode::Online => {
            if matches!(record.stage, Stage::MetadataIntent | Stage::OfflineIntent) {
                return Err(
                    "replica needs metadata/offline intent reconciliation before activation".into(),
                );
            }
            transport(cfg, plan)?;
            if let Some(state) = status(plan)? {
                if !matches!(record.stage, Stage::OnlineIntent | Stage::Online) {
                    return Err("unexpected activation outside the durable online intent".into());
                }
                secondary(cfg, plan, allocation.request.capacity_bytes, &state)?;
                kernel_config(cfg, plan, &lv)?;
                guard.verify()?;
            } else {
                verify_superblock(
                    cfg,
                    plan,
                    &lv,
                    record
                        .device_uuid
                        .as_deref()
                        .ok_or("missing replica identity")?,
                )?;
                record.stage = Stage::OnlineIntent;
                save(&dir, &record)?;
                guard.ensure(cfg, &dir)?;
                // Replaying the ordinary offline activity log is mandatory
                // before activation, not invalidate/reset/forced promotion.
                adm(cfg, plan, "apply-al")?;
                if record.device_uuid.as_ref() != Some(&metadata(cfg, plan)?.0) {
                    return Err("activity-log replay changed backend identity".into());
                }
                adm(cfg, plan, "up")?;
                let state =
                    status(plan)?.ok_or("activation outcome UNKNOWN: kernel resource absent")?;
                secondary(cfg, plan, allocation.request.capacity_bytes, &state)?;
                kernel_config(cfg, plan, &lv)?;
            }
            record.stage = Stage::Online;
            save(&dir, &record)?;
        }
        Mode::Offline => {
            if record.stage == Stage::MetadataIntent {
                return Err("initial metadata intent is not yet reconciled".into());
            }
            if let Some(state) = status(plan)? {
                secondary(cfg, plan, allocation.request.capacity_bytes, &state)?;
                kernel_config(cfg, plan, &lv)?;
                record.stage = Stage::OfflineIntent;
                save(&dir, &record)?;
                adm(cfg, plan, "down")?;
            }
            if status(plan)?.is_some() {
                return Err("offline outcome UNKNOWN: exact resource is still active".into());
            }
            // Even a closed Secondary can have an unclean activity log after
            // down. Read the independent superblock identity BEFORE replay;
            // never overwrite/reinitialize metadata or waive the dirty flag.
            verify_superblock(
                cfg,
                plan,
                &lv,
                record
                    .device_uuid
                    .as_deref()
                    .ok_or("missing replica identity")?,
            )?;
            record.stage = Stage::OfflineIntent;
            save(&dir, &record)?;
            adm(cfg, plan, "apply-al")?;
            let observed = metadata(cfg, plan)?;
            if record.device_uuid.as_ref() != Some(&observed.0) {
                return Err("offline backing metadata identity changed".into());
            }
            // Keep the packet boundary until DRBD is absent and its exact
            // backing metadata has been reconciled. Never flush foreign rules.
            guard.remove()?;
            record.stage = Stage::Offline;
            save(&dir, &record)?;
        }
        Mode::Observe => (),
    }
    let active = status(plan)?;
    let mut encrypted_only_guard_table = None;
    if let Some(state) = &active {
        transport(cfg, plan)?;
        secondary(cfg, plan, allocation.request.capacity_bytes, state)?;
        kernel_config(cfg, plan, &lv)?;
        encrypted_only_guard_table = Some(guard.verify()?);
    } else if record.device_uuid.as_ref() != Some(&metadata(cfg, plan)?.0) {
        return Err("offline metadata identity is missing or changed".into());
    }
    // Repeat durable publication before ACK, even on idempotent retries.
    if !matches!(mode, Mode::Observe) {
        save(&dir, &record)?;
    }
    Ok(Receipt {
        kind: "royak-secondary-replica-v1",
        volume_uid: plan.volume_uid.clone(),
        node_uid: cfg.node_uid.clone(),
        boot_id: pool.boot_id,
        operation_uid: plan.operation_uid.clone(),
        resource: plan.name(),
        minor: plan.minor,
        capacity_bytes: allocation.request.capacity_bytes,
        exposed_capacity_bytes: allocation.request.exposed_bytes()?,
        lv_uuid: record.lv_uuid,
        device_uuid: record
            .device_uuid
            .ok_or("metadata not independently observed")?,
        plan_sha256: hash(&serde_json::to_vec(plan).map_err(|_| "cannot bind plan")?),
        stage: record.stage,
        kernel: active,
        encrypted_only_guard_table,
        pod_access_granted: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dirty_log_recovery_requires_the_exact_independent_superblock_identity() {
        let raw = serde_json::json!({"device_uuid":"0xA030C2C07CC93076","node_id":2,"magic":"0x8374026D","bm_max_peers":2,
            "#meta":{"bd_size":201326592,"dump_offset":201322496,"valid":"VALID_MD_FOUND","dumped_as":"v09","looks_like":"v09"},"flags":"0x00000000"});
        validate_superblock(&raw, 2, 201326592, "a030c2c07cc93076").unwrap();
        for case in 0..7 {
            let mut bad = raw.clone();
            match case {
                0 => bad["device_uuid"] = "0x0000000000000000".into(),
                1 => bad["node_id"] = 0.into(),
                2 => bad["#meta"]["bd_size"] = 1.into(),
                3 => bad["#meta"]["dump_offset"] = 0.into(),
                4 => bad["magic"] = "unknown".into(),
                5 => bad["bm_max_peers"] = 1.into(),
                _ => bad["#meta"]["valid"] = "INVALID_MD".into(),
            }
            assert!(
                validate_superblock(&bad, 2, 201326592, "a030c2c07cc93076").is_err(),
                "case {case}"
            );
        }
        let mut fresh = raw.clone();
        fresh["node_id"] = (-1).into();
        fresh["flags"] = "0x00000080".into();
        fresh["current_uuid"] = "0x0000000000000004".into();
        fresh["effective_size"] = 0.into();
        fresh["members"] = "0x0000000000000000".into();
        validate_superblock(&fresh, 2, 201326592, "a030c2c07cc93076").unwrap();
        fresh["flags"] = "0x00000000".into();
        assert!(validate_superblock(&fresh, 2, 201326592, "a030c2c07cc93076").is_err());
    }
    fn pristine_metadata() -> String {
        let mut text="version \"v09\";\nmax-peers 2;\nnode-id -1;\ncurrent-uuid 0x0000000000000004;\nflags 0x00000080;\nmembers 0x0000000000000000;\nla-size-sect 0;\ndevice-uuid 0xDC978FB77707E876;\n".to_string();
        for i in 0..32 {
            text.push_str(&format!("peer[{i}] {{\n    bitmap-index -1;\n    bitmap-uuid 0x0000000000000000;\n    bitmap-dagtag 0x0000000000000000;\n    flags 0x00000000;\n}}\n"));
        }
        text.push_str("history-uuids {\n");
        for _ in 0..32 {
            text.push_str("    0x0000000000000000;\n");
        }
        text.push_str("}\n");
        text
    }
    #[test]fn initializer_virgin_parser_refuses_even_assigned_zero_generation_marker(){
        let text=pristine_metadata();assert!(pristine_metadata_identity(&text,0).is_ok());
        for changed in [text.replacen("node-id -1;","node-id 0;",1),
            text.replacen("current-uuid 0x0000000000000004;","current-uuid 0x1122334455667788;",1),
            text.replacen("flags 0x00000080;","flags 0x00000081;",1)]{
            assert!(pristine_metadata_identity(&changed,0).is_err());
        }
    }
    #[test]
    fn real_v09_unattached_marker_is_not_mistaken_for_a_data_generation() {
        let text = pristine_metadata();
        assert_eq!(
            parse_metadata(&text, 0).unwrap(),
            ("dc978fb77707e876".into(), "0000000000000004".into())
        );
        for (old, new) in [
            ("node-id -1;", "node-id 2;"),
            (
                "current-uuid 0x0000000000000004;",
                "current-uuid 0x0000000000000000;",
            ),
            ("flags 0x00000080;", "flags 0x00000081;"),
            ("la-size-sect 0;", "la-size-sect 131072;"),
            (
                "bitmap-uuid 0x0000000000000000;",
                "bitmap-uuid 0x1122334455667788;",
            ),
            (
                "device-uuid 0xDC978FB77707E876;",
                "device-uuid 0x0000000000000000;",
            ),
        ] {
            assert!(
                parse_metadata(&text.replacen(old, new, 1), 0).is_err(),
                "{old}"
            );
        }
        let assigned = text.replacen("node-id -1;", "node-id 0;", 1);
        assert!(parse_metadata(&assigned, 0).is_ok());
        assert!(parse_metadata(&assigned, 1).is_err());
        assert!(parse_metadata(&(text.clone() + "node-id -1;\n"), 0).is_err());
    }
    #[test]
    fn absent_kernel_and_expected_paths_do_not_compare_as_equal_unknowns() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("royak-backing-path-{}", Uid::new().as_str()));
        std::fs::create_dir(&root).unwrap();
        let expected = root.join("expected");
        let other = root.join("other");
        assert!(same_existing_paths(
            &expected,
            &Value::String(other.to_string_lossy().into_owned())
        )
        .is_err());
        std::fs::write(&expected, b"owned path identity test").unwrap();
        assert!(same_existing_paths(&expected, &Value::Null).is_err());
        assert!(same_existing_paths(
            &expected,
            &Value::String(other.to_string_lossy().into_owned())
        )
        .is_err());
        assert!(same_existing_paths(
            &expected,
            &Value::String(expected.to_string_lossy().into_owned())
        )
        .is_ok());
        std::fs::remove_dir_all(root).unwrap();
    }
    fn plan(c: &Config) -> Plan {
        Plan {
            version: 1,
            cluster_id: c.cluster_id.clone(),
            pool_uid: c.pool_uid.clone(),
            volume_uid: Uid::new(),
            operation_uid: Uid::new(),
            minor: 512,
            port: 23000,
            interface: "rkstore0".into(),
            shared_secret: "a".repeat(48),
            peers: std::array::from_fn(|i| Peer {
                node_uid: if i == 0 {
                    c.node_uid.clone()
                } else {
                    Uid::new()
                },
                node_id: i as u8,
                hostname: format!("node-{i}"),
                address: Ipv4Addr::new(10, 246, 74, i as u8 + 1),
                public_key: format!("{}=", ((b'A' + i as u8) as char).to_string().repeat(43)),
                vg_name: c.vg_name.clone(),
            }),
        }
    }
    #[test]
    fn plan_cannot_inject_config_retarget_nodes_or_weaken_replication() {
        let c = super::super::test_config();
        let p = plan(&c);
        p.validate(&c).unwrap();
        for case in 0..9 {
            let mut bad = p.clone();
            match case {
                0 => bad.shared_secret = "quote\";".into(),
                1 => bad.peers[1].hostname = "x { }".into(),
                2 => bad.peers[1].address = Ipv4Addr::new(8, 8, 8, 8),
                3 => bad.peers[1].node_uid = bad.peers[0].node_uid.clone(),
                4 => bad.minor = 301,
                5 => bad.port = 22,
                6 => bad.peers[0].vg_name = "--bad".into(),
                7 => bad.interface = "x;reboot".into(),
                _ => bad.peers[2].public_key = bad.peers[1].public_key.clone(),
            }
            assert!(bad.validate(&c).is_err(), "case {case}");
        }
        let text = p.config(64 * 1024 * 1024);
        for required in [
            "protocol C;",
            "auto-promote no;",
            "quorum majority;",
            "quorum-minimum-redundancy 2;",
            "allow-two-primaries no;",
            "disk-flushes yes;",
            "md-flushes yes;",
            "size 65536k;",
        ] {
            assert!(text.contains(required));
        }
        assert!(!text.contains("handlers"));
        assert!(!text.contains("include"));
    }
    #[test]
    fn journal_checksum_and_exact_plan_are_required_without_exposing_credentials() {
        let c = super::super::test_config();
        let p = plan(&c);
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("royak-replica-{}", Uid::new().as_str()));
        let dir = Dir::open(&root, true).unwrap();
        let record = Record {
            version: 1,
            plan: p.clone(),
            allocation_nonce: Uid::new(),
            lv_uuid: c.vg_uuid.clone(),
            stage: Stage::MetadataIntent,
            device_uuid: None,
        };
        save(&dir, &record).unwrap();
        assert!(load(&dir, &p).unwrap().is_some());
        let mut other = p.clone();
        other.peers[1].address = Ipv4Addr::new(10, 246, 74, 9);
        assert!(load(&dir, &other).is_err());
        dir.write(&journal_name(&p), b"{broken").unwrap();
        assert!(load(&dir, &p).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}

pub(super) fn runtime_hostname()->Result<String,String> { hostname() }
impl Plan {
    /// Closed factory: inputs are authenticated readiness data and a guarded
    /// directory, never user YAML/device paths. This is still not a grant.
    pub(super) fn for_runtime(local:&crate::storage_remote_protocol::NodeReadiness,
        owner:&crate::storage_lifecycle::Owner,operation:&Uid,
        peers:&[crate::storage_remote_protocol::NodeReadiness;3],
        directory:&crate::storage_remote_protocol::VerifiedDirectory,
        minor:u16,port:u16,secret:&str)->Result<Self,String> {
        if !(512..=32767).contains(&minor) || !(20000..=59999).contains(&port) ||
            secret.len()!=48 || !secret.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) ||
            peers.iter().map(|r|&r.node_uid).collect::<BTreeSet<_>>().len()!=3 ||
            peers.iter().map(|r|&r.hostname).collect::<BTreeSet<_>>().len()!=3 ||
            peers.iter().any(|r|r.version!=1 || !r.available || r.directory_sha256!=directory.digest() ||
                !host(&r.hostname) || !super::safe_name(&r.vg_name) || r.interface.is_empty() || r.interface.len()>15 ||
                !r.interface.bytes().all(|b|b.is_ascii_alphanumeric()||b"_-".contains(&b)) ||
                minor<r.minor_first || minor>r.minor_last || port<r.port_first || port>r.port_last) {
            return Err("runtime plan readiness/range differs from exact enrolled nodes".into());
        }
        let members=peers.iter().enumerate().map(|(index,readiness)|{
            let pin=directory.pin(&readiness.node_uid)?;
            Ok(Peer {node_uid:pin.node_uid.clone(),node_id:index as u8,hostname:readiness.hostname.clone(),
                address:pin.wireguard_ip,public_key:pin.wireguard_key.clone(),vg_name:readiness.vg_name.clone()})
        }).collect::<Result<Vec<_>,String>>()?;
        let peers=members.try_into().map_err(|_|"runtime requires three exact replica peers")?;
        Ok(Self {version:1,cluster_id:owner.cluster_id.clone(),pool_uid:local.pool_uid.clone(),
            volume_uid:owner.volume_uid.clone(),operation_uid:operation.clone(),minor,port,
            interface:local.interface.clone(),shared_secret:secret.to_owned(),peers})
    }
    pub(super) fn runtime_wire(&self)->Result<serde_json::Value,String> {
        serde_json::to_value(self).map_err(|_|"cannot encode private runtime plan".into())
    }
    pub(super) fn runtime_hash(&self)->Result<String,String> {
        Ok(hash(&serde_json::to_vec(self).map_err(|_|"cannot bind private runtime plan")?))
    }
    pub(super) fn from_runtime_offer(value:serde_json::Value,cfg:&Config,
        spec:&crate::storage_remote_protocol::JobSpec,
        directory:&crate::storage_remote_protocol::VerifiedDirectory,
        readiness:&crate::storage_remote_protocol::NodeReadiness)->Result<Self,String> {
        let plan:Self=serde_json::from_value(value).map_err(|_|"invalid closed cold plan")?;
        plan.validate(cfg)?;
        if plan.runtime_hash()?!=spec.plan_sha256 || plan.volume_uid!=spec.owner.volume_uid ||
            plan.operation_uid!=spec.operation_uid || plan.interface!=readiness.interface ||
            plan.minor<readiness.minor_first || plan.minor>readiness.minor_last ||
            plan.port<readiness.port_first || plan.port>readiness.port_last ||
            plan.local(cfg)?.hostname!=readiness.hostname ||
            plan.peers.iter().any(|peer|directory.pin(&peer.node_uid).map_or(true,|pin|
                peer.address!=pin.wireguard_ip || peer.public_key!=pin.wireguard_key)) {
            return Err("cold offer differs from local pool/plan/directory policy".into());
        }
        Ok(plan)
    }
}

