//! Constrained thick-LVM allocation. Never create a PV/VG, adopt an LV, format
//! a filesystem, mount a device, force removal or free an unproved device.
use super::{
    private_fs::Dir,
    process::{self, Program},
    Config, Request,
};
use crate::storage_identity::Uid;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
#[path="lvm_owned_inventory.rs"]
pub(in crate::storage_driver) mod owned_inventory;
#[cfg(target_os = "linux")]
use std::path::Path;

#[derive(Clone, Debug, Serialize)]
pub struct Lv {
    name: String,
    pub(super) uuid: String,
    pub(super) bytes: u64,
    tags: BTreeSet<String>,
    attr: String,
    segtype: String,
    pub(super) major: u64,
    pub(super) minor: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Pool {
    kind: &'static str,
    cluster_id: String,
    node_uid: Uid,
    pool_uid: Uid,
    pub(super) boot_id: String,
    disk_path: String,
    disk_serial: String,
    pv_uuid: String,
    vg_name: String,
    vg_uuid: String,
    size_bytes: u64,
    free_bytes: u64,
    extent_bytes: u64,
    logical_volumes: Vec<Lv>,
    pub(super) drbd_module_version: Option<String>,
    pod_access_granted: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
    version: u32,
    cluster_id: String,
    node_uid: Uid,
    pool_uid: Uid,
    vg_uuid: String,
    pv_uuid: String,
    disk_serial: String,
}
impl From<&Config> for Binding {
    fn from(c: &Config) -> Self {
        Self {
            version: 1,
            cluster_id: c.cluster_id.clone(),
            node_uid: c.node_uid.clone(),
            pool_uid: c.pool_uid.clone(),
            vg_uuid: c.vg_uuid.clone(),
            pv_uuid: c.pv_uuid.clone(),
            disk_serial: c.disk_serial.clone(),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum Stage {
    Reserved,
    Zeroing,
    Prepared,
    Discarding,
    Destroyed,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Allocation {
    lv_uuid: String,
    bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalRecord {
    version: u32,
    pub(super) request: Request,
    pub(super) allocation_nonce: Uid,
    stage: Stage,
    allocation: Option<Allocation>,
    high_epoch: u64,
    zero_sha256: Option<String>,
    pod_access_granted: bool,
}

/// Keep the same pool lock across local replica journal/device operations.
pub(super) fn prepared_context(
    cfg: &Config,
    uid: &Uid,
) -> Result<(Dir, std::fs::File, Pool, LocalRecord, Lv), String> {
    inspect(cfg)?;
    let (dir, lock) = journal(cfg)?;
    let pool = inspect(cfg)?;
    let record = load(&dir, uid)?.ok_or("no prepared backing allocation exists")?;
    validate_record(cfg, &record)?;
    if record.stage != Stage::Prepared {
        return Err("replication requires a completed Prepared allocation".into());
    }
    let lv = owned_lv(&pool, cfg, &record)?
        .ok_or("prepared backing disappeared; never replace it with empty data")?
        .clone();
    Ok((dir, lock, pool, record, lv))
}

pub(super) fn verify_blank(cfg: &Config, record: &LocalRecord, lv: &Lv) -> Result<String, String> {
    block_io(cfg, record, lv, false)
}
/// Observation-only variant: no directory, lock, binding, allocation or journal
/// publication is created. The existing exact pool lock spans all probe IO.
pub(super) fn prepared_context_readonly(cfg:&Config,uid:&Uid)->Result<(Dir,std::fs::File,Pool,LocalRecord,Lv),String>{
    let dir=Dir::open(&cfg.journal_path(),false)?;
    let lock=dir.lock_existing()?;
    let bytes=dir.read("pool.json")?.ok_or("existing pool binding is required for read-only observation")?;
    let binding:Binding=serde_json::from_slice(&bytes).map_err(|_|"corrupt pool identity journal")?;
    if binding!=Binding::from(cfg){return Err("pool observation binding changed".into());}
    let pool=inspect(cfg)?;
    let record=load(&dir,uid)?.ok_or("prepared allocation journal required")?;
    validate_record(cfg,&record)?;
    if record.stage!=Stage::Prepared{return Err("read-only replica observation requires Prepared allocation".into());}
    let lv=owned_lv(&pool,cfg,&record)?.ok_or("exact prepared LV disappeared")?.clone();
    Ok((dir,lock,pool,record,lv))
}
pub(super) fn verify_zero_data(
    cfg: &Config,
    record: &LocalRecord,
    lv: &Lv,
) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        block_io_extent(
            cfg,
            record,
            lv,
            false,
            Some(record.request.exposed_bytes()?),
            false,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (cfg, record, lv);
        Err("direct backing-device IO requires Linux".into())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    sha256: String,
    record: LocalRecord,
}

fn field<'a>(row: &'a Value, key: &str) -> Result<&'a str, String> {
    row.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .ok_or_else(|| format!("incomplete storage inventory field {key}"))
}
fn number(s: &str) -> Result<u64, String> {
    let (whole, frac) = s.trim().split_once('.').unwrap_or((s.trim(), ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || !frac.bytes().all(|b| b == b'0')
    {
        return Err("non-integral/unknown storage size in inventory".into());
    }
    whole.parse().map_err(|_| "storage size overflow".into())
}
fn rows(value: &Value, key: &str) -> Result<Vec<Value>, String> {
    let reports = value
        .get("report")
        .and_then(Value::as_array)
        .filter(|a| a.len() == 1)
        .ok_or("incomplete LVM report")?;
    reports[0]
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .ok_or("missing LVM report table".into())
}
fn command(program: Program, args: &[&str]) -> Result<Value, String> {
    let args = args.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let bytes = process::run(program, &args)?.success("inventory")?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid bounded storage inventory JSON".into())
}
// NAME is intentionally not selected; require hierarchy explicitly so the
// existing selected-disk recursive mount/swap guard sees every descendant.
fn lsblk_inventory_args() -> &'static [&'static str] {
    &["--json", "--bytes", "-o", "PATH,TYPE,SERIAL,MOUNTPOINTS", "--tree"]
}

fn flatten<'a>(nodes: &'a [Value], out: &mut Vec<&'a Value>) -> Result<(), String> {
    for node in nodes {
        out.push(node);
        if let Some(c) = node.get("children") {
            flatten(c.as_array().ok_or("invalid block-device tree")?, out)?;
        }
    }
    Ok(())
}
fn unmounted_tree(node: &Value) -> Result<(), String> {
    let mounts = node
        .get("mountpoints")
        .and_then(Value::as_array)
        .ok_or("missing mountpoint inventory")?;
    if mounts
        .iter()
        .any(|m| !m.is_null() && m.as_str() != Some(""))
    {
        return Err("approved storage disk contains a mounted filesystem or swap".into());
    }
    if let Some(c) = node.get("children") {
        for child in c.as_array().ok_or("invalid block tree")? {
            unmounted_tree(child)?;
        }
    }
    Ok(())
}

fn validate_inventory(
    cfg: &Config,
    pvs: &Value,
    vgs: &Value,
    lvs: &Value,
    blocks: &Value,
    boot_id: String,
) -> Result<Pool, String> {
    let vgrows = rows(vgs, "vg")?;
    let pvs = rows(pvs, "pv")?;
    let vg: Vec<_> = vgrows
        .iter()
        .filter(|r| field(r, "vg_name").ok() == Some(cfg.vg_name.as_str()))
        .collect();
    if vg.len() != 1 || field(vg[0], "vg_uuid")? != cfg.vg_uuid {
        return Err("VG name/UUID is missing, changed or ambiguous".into());
    }
    let pv: Vec<_> = pvs
        .iter()
        .filter(|r| field(r, "vg_uuid").ok() == Some(cfg.vg_uuid.as_str()))
        .collect();
    if pv.len() != 1
        || field(pv[0], "pv_uuid")? != cfg.pv_uuid
        || field(pv[0], "vg_name")? != cfg.vg_name
    {
        return Err("pool is not the exact approved single-PV volume group".into());
    }
    let disk_path = field(pv[0], "pv_name")?.to_string();
    let mut devices = Vec::new();
    flatten(
        blocks
            .get("blockdevices")
            .and_then(Value::as_array)
            .ok_or("missing block inventory")?,
        &mut devices,
    )?;
    let disks: Vec<_> = devices
        .into_iter()
        .filter(|d| {
            d.get("type").and_then(Value::as_str) == Some("disk")
                && d.get("serial").and_then(Value::as_str).map(str::trim)
                    == Some(cfg.disk_serial.as_str())
        })
        .collect();
    if disks.len() != 1 || field(disks[0], "path")? != disk_path {
        return Err("physical disk serial/path does not match the approved PV".into());
    }
    unmounted_tree(disks[0])?;
    let size = number(field(vg[0], "vg_size")?)?;
    let free = number(field(vg[0], "vg_free")?)?;
    let extent = number(field(vg[0], "vg_extent_size")?)?;
    if size == 0 || free > size || extent == 0 || extent % 4096 != 0 {
        return Err("invalid pool geometry".into());
    }
    let mut volumes = Vec::new();
    for r in rows(lvs, "lv")?
        .into_iter()
        .filter(|r| field(r, "vg_uuid").ok() == Some(cfg.vg_uuid.as_str()))
    {
        let major = field(&r, "lv_kernel_major")?;
        let minor = field(&r, "lv_kernel_minor")?;
        volumes.push(Lv {
            name: field(&r, "lv_name")?.into(),
            uuid: field(&r, "lv_uuid")?.into(),
            bytes: number(field(&r, "lv_size")?)?,
            tags: field(&r, "lv_tags")?
                .split(',')
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .collect(),
            attr: field(&r, "lv_attr")?.into(),
            segtype: field(&r, "segtype")?.into(),
            major: if major == "-1" {
                u64::MAX
            } else {
                number(major)?
            },
            minor: if minor == "-1" {
                u64::MAX
            } else {
                number(minor)?
            },
        });
    }
    Ok(Pool {
        kind: "royak-approved-lvm-pool-v1",
        cluster_id: cfg.cluster_id.clone(),
        node_uid: cfg.node_uid.clone(),
        pool_uid: cfg.pool_uid.clone(),
        boot_id,
        disk_path,
        disk_serial: cfg.disk_serial.clone(),
        pv_uuid: cfg.pv_uuid.clone(),
        vg_name: cfg.vg_name.clone(),
        vg_uuid: cfg.vg_uuid.clone(),
        size_bytes: size,
        free_bytes: free,
        extent_bytes: extent,
        logical_volumes: volumes,
        drbd_module_version: None,
        pod_access_granted: false,
    })
}

pub fn inspect(cfg: &Config) -> Result<Pool, String> {
    let pvs = command(
        Program::Pvs,
        &[
            "--reportformat",
            "json",
            "--units",
            "b",
            "--nosuffix",
            "-o",
            "pv_name,pv_uuid,vg_name,vg_uuid",
        ],
    )?;
    let vgs = command(
        Program::Vgs,
        &[
            "--reportformat",
            "json",
            "--units",
            "b",
            "--nosuffix",
            "-o",
            "vg_name,vg_uuid,vg_size,vg_free,vg_extent_size",
        ],
    )?;
    let lvs=command(Program::Lvs,&["--reportformat","json","--units","b","--nosuffix","-o","vg_uuid,lv_name,lv_uuid,lv_size,lv_tags,lv_attr,segtype,lv_kernel_major,lv_kernel_minor"])?;
    let blocks = command(Program::Lsblk, lsblk_inventory_args())?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|_| "cannot read Linux boot identity")?;
    if !crate::storage_lifecycle::valid_uuid(boot.trim()) {
        return Err("invalid Linux boot identity".into());
    }
    let mut result = validate_inventory(cfg, &pvs, &vgs, &lvs, &blocks, boot.trim().into())?;
    result.drbd_module_version = match std::fs::read_to_string("/sys/module/drbd/version") {
        Ok(s) => Some(s.trim().into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err("cannot inspect DRBD module version".into()),
    };
    Ok(result)
}

fn journal(cfg: &Config) -> Result<(Dir, std::fs::File), String> {
    let dir = Dir::open(&cfg.journal_path(), true)?;
    let lock = dir.lock()?;
    let binding = Binding::from(cfg);
    if let Some(bytes) = dir.read("pool.json")? {
        let old: Binding =
            serde_json::from_slice(&bytes).map_err(|_| "corrupt pool identity journal")?;
        if old != binding {
            return Err("storage pool identity changed; automatic adoption refused".into());
        }
    } else {
        if !dir.empty_except_lock()? {
            return Err("pool identity journal is missing beside existing records; automatic rebinding refused".into());
        }
        dir.write(
            "pool.json",
            &serde_json::to_vec(&binding).map_err(|_| "cannot encode pool binding")?,
        )?;
    }
    Ok((dir, lock))
}
fn filename(uid: &Uid) -> String {
    format!("{}.json", uid.as_str())
}
fn save(dir: &Dir, record: &LocalRecord) -> Result<(), String> {
    let bytes = serde_json::to_vec(record).map_err(|_| "cannot encode allocation journal")?;
    let envelope = Envelope {
        version: 1,
        sha256: format!("{:x}", Sha256::digest(&bytes)),
        record: record.clone(),
    };
    dir.write(
        &filename(&record.request.volume_uid),
        &serde_json::to_vec(&envelope).map_err(|_| "cannot encode allocation envelope")?,
    )
}
fn load(dir: &Dir, uid: &Uid) -> Result<Option<LocalRecord>, String> {
    let Some(bytes) = dir.read(&filename(uid))? else {
        return Ok(None);
    };
    let envelope: Envelope =
        serde_json::from_slice(&bytes).map_err(|_| "corrupt allocation journal")?;
    let canonical =
        serde_json::to_vec(&envelope.record).map_err(|_| "cannot verify allocation journal")?;
    if envelope.version != 1
        || envelope.record.request.volume_uid != *uid
        || envelope.sha256 != format!("{:x}", Sha256::digest(&canonical))
    {
        return Err("allocation journal checksum/identity is invalid".into());
    }
    Ok(Some(envelope.record))
}
fn required_bytes(request: &Request, extent: u64) -> Result<u64, String> {
    // Conservative reserve for two peer bitmaps/AL and future filesystem work.
    let total = request
        .capacity_bytes
        .checked_add(128 * 1024 * 1024)
        .ok_or("allocation size overflow")?;
    total
        .checked_add(extent - 1)
        .and_then(|n| (n / extent).checked_mul(extent))
        .ok_or("allocation size overflow".into())
}
fn tags(cfg: &Config, record: &LocalRecord) -> BTreeSet<String> {
    [
        format!("royak.pool.{}", cfg.pool_uid.as_str()),
        format!("royak.volume.{}", record.request.volume_uid.as_str()),
        format!("royak.allocation.{}", record.allocation_nonce.as_str()),
    ]
    .into_iter()
    .collect()
}
fn owned_lv<'a>(
    pool: &'a Pool,
    cfg: &Config,
    record: &LocalRecord,
) -> Result<Option<&'a Lv>, String> {
    let found: Vec<_> = pool
        .logical_volumes
        .iter()
        .filter(|v| v.name == record.request.lv_name())
        .collect();
    if found.len() > 1 {
        return Err("ambiguous backing LV identity".into());
    }
    let Some(lv) = found.first().copied() else {
        return Ok(None);
    };
    if lv.tags != tags(cfg, record)
        || !super::lvm_uuid(&lv.uuid)
        || lv.segtype != "linear"
        || !lv.attr.starts_with("-w")
        || lv.bytes != required_bytes(&record.request, pool.extent_bytes)?
        || record
            .allocation
            .as_ref()
            .is_some_and(|a| a.lv_uuid != lv.uuid || a.bytes != lv.bytes)
    {
        return Err(
            "existing LV is not the exact journal-owned new allocation; adoption refused".into(),
        );
    }
    Ok(Some(lv))
}
fn validate_record(cfg: &Config, r: &LocalRecord) -> Result<(), String> {
    r.request.validate(cfg)?;
    if r.version != 1
        || r.high_epoch != 0
        || r.pod_access_granted
        || (r.stage != Stage::Reserved && r.allocation.is_none())
        || (r.stage == Stage::Reserved && (r.allocation.is_some() || r.zero_sha256.is_some()))
        || (r.stage == Stage::Zeroing && r.zero_sha256.is_some())
        || (matches!(
            r.stage,
            Stage::Prepared | Stage::Discarding | Stage::Destroyed
        ) && r.zero_sha256.is_none())
        || r.zero_sha256.as_ref().is_some_and(|s| {
            s.len() != 64
                || !s
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        })
    {
        return Err("unsupported or inconsistent backing-allocation journal".into());
    }
    Ok(())
}
fn check_budget(cfg: &Config, pool: &Pool, request: &Request) -> Result<(), String> {
    let bytes = required_bytes(request, pool.extent_bytes)?;
    let marker = format!("royak.pool.{}", cfg.pool_uid.as_str());
    let used = pool
        .logical_volumes
        .iter()
        .filter(|v| v.tags.contains(&marker))
        .try_fold(0u64, |n, v| n.checked_add(v.bytes))
        .ok_or("pool allocation accounting overflow")?;
    if bytes > pool.free_bytes
        || used
            .checked_add(bytes)
            .is_none_or(|n| n > cfg.max_managed_bytes)
    {
        return Err("approved pool capacity/quota would be exceeded".into());
    }
    Ok(())
}

pub fn prepare(cfg: &Config, request: &Request) -> Result<LocalRecord, String> {
    request.validate(cfg)?;
    inspect(cfg)?; // No journal creation for a mismatched or OS-mounted pool.
    let (dir, _lock) = journal(cfg)?;
    let mut pool = inspect(cfg)?;
    let existing = load(&dir, &request.volume_uid)?;
    let mut record = if let Some(r) = existing {
        validate_record(cfg, &r)?;
        if &r.request != request {
            return Err("allocation UID belongs to another request/incarnation".into());
        }
        r
    } else {
        if pool
            .logical_volumes
            .iter()
            .any(|v| v.name == request.lv_name())
        {
            return Err("unknown existing LV is never adopted without its durable journal".into());
        }
        check_budget(cfg, &pool, request)?;
        let r = LocalRecord {
            version: 1,
            request: request.clone(),
            allocation_nonce: Uid::new(),
            stage: Stage::Reserved,
            allocation: None,
            high_epoch: 0,
            zero_sha256: None,
            pod_access_granted: false,
        };
        save(&dir, &r)?;
        r
    };
    if matches!(record.stage, Stage::Destroyed | Stage::Discarding) {
        return Err("retired allocation UID cannot be reused".into());
    }
    if owned_lv(&pool, cfg, &record)?.is_none() {
        if record.stage != Stage::Reserved {
            return Err(
                "previously allocated LV disappeared; refusing replacement with empty data".into(),
            );
        }
        check_budget(cfg, &pool, request)?;
        let bytes = required_bytes(request, pool.extent_bytes)?;
        let mut args = vec![
            "--devices".into(),
            pool.disk_path.clone(),
            "--yes".into(),
            "--wipesignatures".into(),
            "n".into(),
            "--zero".into(),
            "n".into(),
            "--type".into(),
            "linear".into(),
            "--extents".into(),
            (bytes / pool.extent_bytes).to_string(),
            "--name".into(),
            request.lv_name(),
        ];
        for tag in tags(cfg, &record) {
            args.extend(["--addtag".into(), tag]);
        }
        args.extend(["--".into(), cfg.vg_name.clone(), pool.disk_path.clone()]);
        process::run(Program::Lvcreate, &args)?.success("lvcreate")?;
        pool = inspect(cfg)?;
    }
    let lv = owned_lv(&pool, cfg, &record)?
        .ok_or("new LV not independently observed")?
        .clone();
    if record.stage == Stage::Prepared {
        // Never re-zero a prepared allocation on retry. That could destroy
        // data written by a later layer whose acknowledgement was lost.
        // Republish the identical receipt before acknowledging: the previous
        // call may have observed rename but failed its directory fsync.
        save(&dir, &record)?;
        return Ok(record);
    }
    record.allocation = Some(Allocation {
        lv_uuid: lv.uuid.clone(),
        bytes: lv.bytes,
    });
    record.stage = Stage::Zeroing;
    save(&dir, &record)?;
    let hash = block_io(cfg, &record, &lv, true)?;
    record.zero_sha256 = Some(hash);
    record.stage = Stage::Prepared;
    save(&dir, &record)?;
    Ok(record)
}

pub fn discard(cfg: &Config, uid: &Uid) -> Result<LocalRecord, String> {
    inspect(cfg)?;
    let (dir, _lock) = journal(cfg)?;
    let pool = inspect(cfg)?;
    let mut record = load(&dir, uid)?.ok_or("no journal-owned allocation exists")?;
    validate_record(cfg, &record)?;
    let lv = owned_lv(&pool, cfg, &record)?.cloned();
    if record.stage == Stage::Destroyed {
        if lv.is_some() {
            return Err("destroyed allocation unexpectedly has a device; never adopt it".into());
        }
        save(&dir, &record)?;
        return Ok(record);
    }
    if !matches!(record.stage, Stage::Prepared | Stage::Discarding) {
        return Err("only a completed unformatted new allocation can be discarded".into());
    }
    if let Some(lv) = lv {
        let hash = block_io(cfg, &record, &lv, false)?;
        if record.zero_sha256.as_ref() != Some(&hash) {
            return Err("allocation no longer matches its verified zero extent".into());
        }
        record.stage = Stage::Discarding;
        save(&dir, &record)?;
        let args = vec![
            "--devices".into(),
            pool.disk_path.clone(),
            "--yes".into(),
            "--".into(),
            format!("{}/{}", cfg.vg_name, record.request.lv_name()),
        ];
        process::run(Program::Lvremove, &args)?.success("lvremove")?;
        let current = inspect(cfg)?;
        if owned_lv(&current, cfg, &record)?.is_some() {
            return Err("removed LV still exists; outcome UNKNOWN".into());
        }
    } else if record.stage != Stage::Discarding {
        return Err("LV disappeared before a recorded discard intent; investigate".into());
    }
    record.stage = Stage::Destroyed;
    save(&dir, &record)?;
    Ok(record)
}

#[cfg(not(target_os = "linux"))]
fn block_io(_: &Config, _: &LocalRecord, _: &Lv, _: bool) -> Result<String, String> {
    Err("direct backing-device IO requires Linux".into())
}

#[cfg(target_os = "linux")]
fn block_io(cfg: &Config, record: &LocalRecord, lv: &Lv, zero: bool) -> Result<String, String> {
    block_io_extent(cfg, record, lv, zero, None, true)
}

pub(super) fn verify_unheld(lv: &Lv) -> Result<(), String> {
    verify_holders_directory(std::path::Path::new(&format!(
        "/sys/dev/block/{}:{}/holders",
        lv.major, lv.minor
    )))
}
fn verify_holders_directory(path: &std::path::Path) -> Result<(), String> {
    let mut holders = std::fs::read_dir(path).map_err(|_| "cannot inspect block holders")?;
    if holders.next().is_some() {
        return Err("backing device is held by another layer; direct IO refused".into());
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn block_io_extent(
    cfg: &Config,
    record: &LocalRecord,
    lv: &Lv,
    zero: bool,
    prefix: Option<u64>,
    probe_blank: bool,
) -> Result<String, String> {
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    use std::time::{Duration, Instant};
    let canonical =
        std::fs::canonicalize(format!("/dev/{}/{}", cfg.vg_name, record.request.lv_name()))
            .map_err(|_| "backing device unavailable")?;
    let leaf = canonical
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("invalid backing device")?;
    if canonical.parent() != Some(Path::new("/dev"))
        || !leaf
            .strip_prefix("dm-")
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err("backing path is not the expected device-mapper node".into());
    }
    verify_unheld(lv)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(zero)
        .custom_flags(
            libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_EXCL | libc::O_DIRECT | libc::O_SYNC,
        )
        .open(&canonical)
        .map_err(|_| "backing device cannot be opened exclusively")?;
    let m = file
        .metadata()
        .map_err(|_| "cannot inspect open block device")?;
    if !m.file_type().is_block_device()
        || m.rdev() != libc::makedev(lv.major as u32, lv.minor as u32)
    {
        return Err("open device identity changed".into());
    }
    let mut bytes: u64 = 0;
    // Linux BLKGETSIZE64: verify geometry through the already-open descriptor.
    // libc exposes a signed 32-bit request on musl and unsigned long on glibc.
    // Preserve the ioctl request's bits while letting the ABI infer its type.
    if unsafe { libc::ioctl(file.as_raw_fd(), 0x80081272u32 as _, &mut bytes) } != 0
        || bytes != lv.bytes
        || bytes % 4096 != 0
    {
        return Err("open backing geometry does not match journal".into());
    }
    if let Some(prefix) = prefix {
        if zero || prefix == 0 || prefix > bytes || prefix % 4096 != 0 {
            return Err("invalid bounded data verification extent".into());
        }
        bytes = prefix;
    }
    let len = 1024 * 1024;
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err("cannot allocate aligned direct-IO buffer".into());
    }
    struct Buffer(*mut libc::c_void, usize);
    impl Drop for Buffer {
        fn drop(&mut self) {
            unsafe {
                libc::munmap(self.0, self.1);
            }
        }
    }
    let buffer = Buffer(ptr, len);
    let data = unsafe { std::slice::from_raw_parts_mut(buffer.0 as *mut u8, len) };
    let deadline = Instant::now() + Duration::from_secs(600);
    if zero {
        let mut left = bytes;
        while left > 0 {
            if Instant::now() > deadline {
                return Err(
                    "new-allocation zeroing deadline; journal remains Zeroing, no access granted"
                        .into(),
                );
            }
            let count = left.min(len as u64) as usize;
            // Parent loss/cancel/quorum loss prevents every later fresh write.
            // A syscall already entered before loss remains UNKNOWN; this
            // handshake is not a promise to cancel or undo kernel IO.
            super::live_authority::before_block_write(
                &record.request.volume_uid,
                bytes - left,
                count as u64,
            )?;
            file.write_all(&data[..count])
                .map_err(|_| "new-allocation zeroing IO failed; outcome UNKNOWN")?;
            left -= count as u64;
        }
        super::live_authority::before_block_fsync(&record.request.volume_uid)?;
        file.sync_all()
            .map_err(|_| "new-allocation durability barrier failed")?;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| "cannot rewind new allocation")?;
    }
    let mut left = bytes;
    let mut hash = Sha256::new();
    while left > 0 {
        if Instant::now() > deadline {
            return Err("direct zero-verification deadline; no operation acknowledged".into());
        }
        let count = left.min(len as u64) as usize;
        file.read_exact(&mut data[..count])
            .map_err(|_| "short/failed independent direct read")?;
        if data[..count].iter().any(|b| *b != 0) {
            return Err("allocation contains nonzero data; destructive cleanup refused".into());
        }
        hash.update(&data[..count]);
        left -= count as u64;
    }
    if probe_blank {
        let args = vec![
            "-p".into(),
            "-o".into(),
            "export".into(),
            canonical.to_string_lossy().into_owned(),
        ];
        let signature = process::run(Program::Blkid, &args)?;
        if signature.code != 2 || !signature.stdout.is_empty() || !signature.stderr.is_empty() {
            return Err("backing extent has a signature or cannot be independently probed".into());
        }
    }
    Ok(format!("{:x}", hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn inventory(c: &Config) -> (Value, Value, Value, Value) {
        (
            json!({"report":[{"pv":[{"pv_name":"/dev/sdb","pv_uuid":c.pv_uuid,"vg_name":c.vg_name,"vg_uuid":c.vg_uuid}]}]}),
            json!({"report":[{"vg":[{"vg_name":c.vg_name,"vg_uuid":c.vg_uuid,"vg_size":"2143289344.00","vg_free":"1073741824.00","vg_extent_size":"4194304.00"}]}]}),
            json!({"report":[{"lv":[]}]}),
            json!({"blockdevices":[{"path":"/dev/sdb","type":"disk","serial":c.disk_serial,"mountpoints":[null],"children":[]}]}),
        )
    }
    #[test]
    fn inventory_fingerprints_refuse_boot_disks_ambiguous_serials_and_wrong_pools() {
        let c = super::super::test_config();
        let (p, v, l, b) = inventory(&c);
        assert!(validate_inventory(&c, &p, &v, &l, &b, "test".into()).is_ok());
        for i in 0..7 {
            let (mut p, mut v, l, mut b) = inventory(&c);
            match i {
                0 => p["report"][0]["pv"][0]["pv_uuid"] = "wrong".into(),
                1 => v["report"][0]["vg"][0]["vg_uuid"] = "wrong".into(),
                2 => b["blockdevices"][0]["mountpoints"] = json!(["/"]),
                3 => b["blockdevices"][0]["children"] = json!([{"mountpoints":["/boot/efi"]}]),
                4 => {
                    let clone = b["blockdevices"][0].clone();
                    b["blockdevices"].as_array_mut().unwrap().push(clone);
                }
                5 => {
                    let clone = p["report"][0]["pv"][0].clone();
                    p["report"][0]["pv"].as_array_mut().unwrap().push(clone);
                }
                _ => v["report"][0]["vg"][0]["vg_free"] = "unknown".into(),
            }
            assert!(
                validate_inventory(&c, &p, &v, &l, &b, "test".into()).is_err(),
                "case {i}"
            );
        }
        assert!(number("1.5").is_err());
        assert!(number("-1").is_err());
        assert_eq!(number("1.000").unwrap(), 1);
    }
    #[test]
    fn existing_volume_requires_exact_nonce_uuid_size_and_type() {
        let c = super::super::test_config();
        let request = super::super::test_request(&c);
        let (p, v, l, b) = inventory(&c);
        let mut pool = validate_inventory(&c, &p, &v, &l, &b, "test".into()).unwrap();
        let mut record = LocalRecord {
            version: 1,
            request,
            allocation_nonce: Uid::new(),
            stage: Stage::Zeroing,
            allocation: Some(Allocation {
                lv_uuid: c.vg_uuid.clone(),
                bytes: 192 * 1024 * 1024,
            }),
            high_epoch: 0,
            zero_sha256: None,
            pod_access_granted: false,
        };
        let lv = Lv {
            name: record.request.lv_name(),
            uuid: c.vg_uuid.clone(),
            bytes: 192 * 1024 * 1024,
            tags: tags(&c, &record),
            attr: "-wi-a-----".into(),
            segtype: "linear".into(),
            major: 253,
            minor: 1,
        };
        pool.logical_volumes = vec![lv.clone()];
        assert!(owned_lv(&pool, &c, &record).unwrap().is_some());
        for i in 0..4 {
            let mut bad = lv.clone();
            match i {
                0 => {
                    bad.tags.clear();
                }
                1 => bad.uuid = c.pv_uuid.clone(),
                2 => bad.bytes += 4096,
                _ => bad.segtype = "thin".into(),
            }
            pool.logical_volumes = vec![bad];
            assert!(owned_lv(&pool, &c, &record).is_err());
        }
        pool.logical_volumes = vec![lv];
        assert!(
            check_budget(&c, &pool, &record.request).is_err(),
            "a second reservation must not bypass the quota on retry"
        );
        record.stage = Stage::Prepared;
        assert!(
            validate_record(&c, &record).is_err(),
            "prepared needs durable zero-read evidence"
        );
    }
    #[test]
    fn corrupt_or_missing_journal_never_becomes_an_adoption_source() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("royak-driver-journal-{}", Uid::new().as_str()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = Dir::open(&path, false).unwrap();
        let c = super::super::test_config();
        let request = super::super::test_request(&c);
        let record = LocalRecord {
            version: 1,
            request,
            allocation_nonce: Uid::new(),
            stage: Stage::Reserved,
            allocation: None,
            high_epoch: 0,
            zero_sha256: None,
            pod_access_granted: false,
        };
        save(&dir, &record).unwrap();
        assert_eq!(
            load(&dir, &record.request.volume_uid)
                .unwrap()
                .unwrap()
                .allocation_nonce,
            record.allocation_nonce
        );
        let mut value: Value = serde_json::from_slice(
            &dir.read(&filename(&record.request.volume_uid))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        value["record"]["high_epoch"] = 1.into();
        dir.write(
            &filename(&record.request.volume_uid),
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
        assert!(load(&dir, &record.request.volume_uid).is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn unavailable_or_nonempty_holders_never_mean_unheld() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("royak-held-device-{}", Uid::new().as_str()));
        assert!(verify_holders_directory(&root).is_err());
        std::fs::create_dir(&root).unwrap();
        verify_holders_directory(&root).unwrap();
        // The sysfs entry name is not an allowlist: a different DRBD minor or
        // device-mapper alias is just as much a holder as the planned minor.
        std::fs::write(root.join("dm-987"), b"test holder").unwrap();
        assert!(verify_holders_directory(&root)
            .unwrap_err()
            .contains("held by another layer"));
        std::fs::remove_dir_all(root).unwrap();
    }
}

/// Actual read-only local pool projection for the normal cold scheduler.
/// No files, locks, allocations or authority are created by this observation.
pub(super) fn runtime_readiness(cfg:&Config,directory_sha256:String,interface:String,
    minor_first:u16,minor_last:u16,port_first:u16,port_last:u16,available:bool)
    ->Result<crate::storage_remote_protocol::NodeReadiness,String> {
    cfg.validate()?;
    let pool=inspect(cfg)?;
    if pool.drbd_module_version.as_ref().is_none_or(|v|!v.starts_with("9.")) {
        return Err("runtime requires an already loaded approved DRBD9 module".into());
    }
    let marker=format!("royak.pool.{}",cfg.pool_uid.as_str());
    let used=pool.logical_volumes.iter().filter(|lv|lv.tags.contains(&marker))
        .try_fold(0u64,|sum,lv|sum.checked_add(lv.bytes)).ok_or("runtime pool accounting overflow")?;
    let boot=crate::storage_boot::BootId::current()?;
    if boot.as_str()!=pool.boot_id || pool.node_uid!=cfg.node_uid || pool.pool_uid!=cfg.pool_uid {
        return Err("actual runtime pool/boot identity changed".into());
    }
    let hostname=super::replica::runtime_hostname()?;
    Ok(crate::storage_remote_protocol::NodeReadiness {version:1,node_uid:cfg.node_uid.clone(),boot,
        directory_sha256,pool_uid:cfg.pool_uid.clone(),
        pool_sha256:super::native_runtime::digest(&serde_json::to_vec(cfg).map_err(|_|"cannot bind pool config")?),
        hostname,vg_name:cfg.vg_name.clone(),free_bytes:pool.free_bytes,extent_bytes:pool.extent_bytes,
        max_volume_bytes:cfg.max_volume_bytes,max_managed_bytes:cfg.max_managed_bytes,managed_bytes:used,
        interface,minor_first,minor_last,port_first,port_last,available})
}


#[cfg(test)]
#[path = "lvm_inventory_tree_tests.rs"]
mod inventory_tree_regressions;
