//! REVIEW CANDIDATE, deliberately not connected to any CLI/dispatcher job kind.
//! Fixed virgin-only physical actuation, not a Core/writer/fencing receipt.
//! Before activation review: authenticated remote observation delivery and an
//! initialization-specific live-parent dispatcher/projection are still missing.
use super::*;
use crate::storage_driver::dispatcher::VerifiedWorkerMode;
use crate::storage_lifecycle::generation::{InitializationIntent, VerifiedVirginSet};
use std::time::{Duration, Instant};
#[path = "replica_init_phases.rs"]
pub(in crate::storage_driver) mod phases;
#[path = "managed_mount.rs"]
pub(in crate::storage_driver) mod managed_mount;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
enum InitPhase {
    ActivateIntent,
    BootstrapIntent,
    Synchronized,
    PromoteIntent,
    FormatIntent,
    Formatted,
    DemoteIntent,
    OfflineIntent,
    Complete,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InitRecord {
    version: u32,
    binding_sha256: String,
    data_generation_uid: Uid,
    initialize_operation_uid: Uid,
    phase: InitPhase,
    data_sha256: Option<String>,
    offline_metadata_sha256: Option<String>,
}
/// Diagnostic only. It cannot ACK Provisioned or supply an application writer,
/// mount, backup source, remote authority or physical fence.
#[derive(Debug, Serialize)]
pub(crate) struct InitializedOffline {
    kind: &'static str,
    volume_uid: Uid,
    data_generation_uid: Uid,
    initialize_operation_uid: Uid,
    filesystem_uuid: String,
    node_uid: Uid,
    node_boot_id: String,
    exposed_bytes: u64,
    data_sha256: String,
    offline_metadata_sha256: String,
    pod_access_granted: bool,
}

fn bootstrap_args(config_path: &str, resource: &str) -> Vec<String> {
    // Exact 9.3.4/9.35 supported path: FULL resync, never --clear-bitmap,
    // --assume-clean, invalidation, forced recovery or a quorum change.
    strings(&[
        "-c",
        config_path,
        "new-current-uuid",
        "--force-resync",
        resource,
    ])
}
fn fs_args(uuid: &str, device: &str) -> Vec<String> {
    // No -F/no silent overwrite. UUID was allocated in the durable generation.
    strings(&[
        "-q",
        "-U",
        uuid,
        "-E",
        "lazy_itable_init=0,lazy_journal_init=0",
        device,
    ])
}
fn filesystem_signature(raw: &[u8], uuid: &str) -> Result<(), String> {
    let text = std::str::from_utf8(raw).map_err(|_| "invalid filesystem observation")?;
    let mut values = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or("invalid filesystem observation field")?;
        if values.insert(key, value).is_some() {
            return Err("duplicate filesystem identity field".into());
        }
    }
    if values.get("TYPE") != Some(&"ext4")
        || values.get("UUID") != Some(&uuid)
        || values.get("USAGE").is_some_and(|v| *v != "filesystem")
        || values.contains_key("PTTYPE")
        || values.contains_key("PART_ENTRY_UUID")
    {
        return Err("filesystem type/UUID does not match committed new dataset".into());
    }
    Ok(())
}
fn filesystem_probe(device: &str, expected: Option<&str>) -> Result<(), String> {
    if expected.is_none() {
        return Err("pre-format absence requires a genuine phase-bound promoted-DRBD byte observation".into());
    }
    let observed = process::run(Program::Blkid, &strings(&["-p", "-o", "export", device]))?;
    if let Some(uuid) = expected {
        filesystem_signature(
            &observed.success("independent filesystem observation")?,
            uuid,
        )
    } else {
        Err("new DRBD extent has a signature or its absence cannot be proved".into())
    }
}

/// All three diskful members as independently reported by this actual local
/// kernel view; NOT three independently authenticated remote observations.
fn synchronized(
    cfg: &Config,
    plan: &Plan,
    bytes: u64,
    state: &Value,
    primary: bool,
) -> Result<(), String> {
    let mut closed = state.clone();
    closed["role"] = "Secondary".into();
    secondary(cfg, plan, bytes, &closed)?;
    if state["role"] != if primary { "Primary" } else { "Secondary" }
        || state["suspended"] != false
        || state["force-io-failures"] != false
        || state["devices"][0]["disk-state"] != "UpToDate"
        || state["devices"][0]["client"] != false
        || state["devices"][0]["quorum"] != true
        || state["devices"][0]["upper-pending"] != 0
        || state["devices"][0]["lower-pending"] != 0
    {
        return Err("initializer lacks exact closed fully synchronized disk/quorum state".into());
    }
    for connection in state["connections"]
        .as_array()
        .ok_or("missing synchronization peers")?
    {
        let peers = connection["peer_devices"]
            .as_array()
            .filter(|a| a.len() == 1)
            .ok_or("ambiguous peer data set")?;
        let peer = &peers[0];
        if connection["connection-state"] != "Connected"
            || connection["peer-role"] != "Secondary"
            || connection["ap-in-flight"] != 0
            || connection["rs-in-flight"] != 0
            || connection["paths"][0]["established"] != true
            || peer["volume"] != 0
            || peer["replication-state"] != "Established"
            || peer["peer-disk-state"] != "UpToDate"
            || peer["peer-client"] != false
            || peer["resync-suspended"] != "no"
            || peer["out-of-sync"] != 0
            || peer["pending"] != 0
            || peer["unacked"] != 0
        {
            return Err("all three replicas must be diskful UpToDate with completed full resync and zero pending IO".into());
        }
    }
    Ok(())
}
fn fresh_online(cfg: &Config, plan: &Plan, bytes: u64, state: &Value) -> Result<(), String> {
    secondary(cfg, plan, bytes, state)?;
    if state["devices"][0]["disk-state"] != "Inconsistent"
        || state["devices"][0]["client"] != false
        || state["connections"]
            .as_array()
            .ok_or("missing fresh peers")?
            .iter()
            .any(|p| {
                p["connection-state"] != "Connected"
                    || p["peer-role"] != "Secondary"
                    || p["paths"][0]["established"] != true
                    || p["peer_devices"].as_array().is_none_or(|d| {
                        d.len() != 1
                            || d[0]["volume"] != 0
                            || d[0]["replication-state"] != "Established"
                            || d[0]["peer-disk-state"] != "Inconsistent"
                            || d[0]["peer-client"] != false
                    })
            })
    {
        return Err(
            "only three just-created closed Inconsistent diskful replicas may bootstrap".into(),
        );
    }
    Ok(())
}

/// The complete allocation is initialized before any Rust byte slice exists.
/// Keep this constructor shared with the regression test, including on native
/// non-Linux test hosts where the actual block-device reader is unavailable.
#[cfg(any(target_os = "linux", test))]
struct AlignedReadBuffer {
    pointer: std::ptr::NonNull<u8>,
    layout: std::alloc::Layout,
}
#[cfg(any(target_os = "linux", test))]
impl AlignedReadBuffer {
    fn new() -> Result<Self, String> {
        let layout = std::alloc::Layout::from_size_align(1024 * 1024, 4096)
            .map_err(|_| "invalid direct buffer")?;
        // SAFETY: layout is nonzero and valid. alloc_zeroed initializes every
        // u8 before bytes_mut constructs a reference to the allocation.
        let pointer = std::ptr::NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) })
            .ok_or("cannot allocate bounded direct dataset read buffer")?;
        Ok(Self { pointer, layout })
    }
    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: this uniquely borrowed buffer owns layout.size() initialized
        // bytes until Drop. No other reference or owner of the allocation exists.
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.layout.size()) }
    }
}
#[cfg(any(target_os = "linux", test))]
impl Drop for AlignedReadBuffer {
    fn drop(&mut self) {
        // SAFETY: the non-null pointer was allocated with this exact layout,
        // and it has not been freed or transferred to any other owner.
        unsafe { std::alloc::dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

#[cfg(not(target_os = "linux"))]
fn direct_hash(
    _: &std::path::Path,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: Instant,
) -> Result<String, String> {
    Err("actual dataset direct observation requires Linux".into())
}
#[cfg(target_os = "linux")]
fn direct_hash(
    path: &std::path::Path,
    major: u64,
    minor: u64,
    device_bytes: u64,
    extent_bytes: u64,
    deadline: Instant,
) -> Result<String, String> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    if extent_bytes == 0 || extent_bytes > device_bytes || extent_bytes % 4096 != 0 {
        return Err("invalid exact dataset extent".into());
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_EXCL | libc::O_DIRECT)
        .open(path)
        .map_err(|_| "cannot exclusively direct-read exact dataset block device")?;
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect dataset descriptor")?;
    let mut actual_bytes: u64 = 0;
    if !metadata.file_type().is_block_device()
        || metadata.rdev() != libc::makedev(major as u32, minor as u32)
        || unsafe { libc::ioctl(file.as_raw_fd(), 0x80081272u32 as _, &mut actual_bytes) } != 0
        || actual_bytes != device_bytes
    {
        return Err("dataset descriptor identity/geometry changed".into());
    }
    let mut buffer = AlignedReadBuffer::new()?;
    let data = buffer.bytes_mut();
    let mut left = extent_bytes;
    let mut digest = Sha256::new();
    while left > 0 {
        if Instant::now() >= deadline {
            return Err("dataset observation deadline; no result acknowledged".into());
        }
        crate::storage_driver::live_authority::checkpoint()?;
        let count = left.min(data.len() as u64) as usize;
        file.read_exact(&mut data[..count])
            .map_err(|_| "short/failed direct dataset read")?;
        digest.update(&data[..count]);
        left -= count as u64;
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// Not exported to CLI. Both arguments are opaque: a stored JSON reference,
/// raw helper stdout or original prepare job cannot call this physical path.
/// Any non-Complete/Complete prior init record refuses reformatting alike;
/// crash reconciliation remains explicit rather than repeating mkfs/UUID work.
pub(crate) fn initialize_new_offline(
    cfg: &Config,
    plan: &Plan,
    intent: &InitializationIntent,
    fresh: VerifiedVirginSet,
    worker: &VerifiedWorkerMode,
    deadline: Instant,
) -> Result<InitializedOffline, String> {
    if !cfg!(target_os = "linux")
        || unsafe { libc::geteuid() } != 0
        || deadline <= Instant::now()
        || deadline > Instant::now() + Duration::from_secs(900)
    {
        return Err("initializer requires Linux root and bounded verified job deadline".into());
    }
    worker.check_initialization(intent)?;
    fresh.check_initialization(intent)?;
    plan.validate(cfg)?;
    if cfg.cluster_id != intent.owner().cluster_id
        || plan.volume_uid != intent.owner().volume_uid
        || plan.operation_uid != intent.generation().prepare_operation_uid
    {
        return Err("initializer backend differs from exact committed preparation lineage".into());
    }
    let boot = crate::storage_boot::BootId::current()?;
    let fact = intent.local_initializer(&cfg.node_uid, &boot)?;
    if &observe_virgin(cfg, plan)?.into_reference() != fact {
        return Err("fresh local replica differs from committed physical provenance".into());
    }
    let (dir, lock, _, allocation, lv) = lvm::prepared_context_readonly(cfg, &plan.volume_uid)?;
    let filename = format!("initialize-{}.json", plan.volume_uid.as_str());
    if dir.read(&filename)?.is_some() {
        return Err(
            "existing initialization record never authorizes reformat or implicit recovery".into(),
        );
    }
    let binding = hash(
        &serde_json::to_vec(&(cfg, plan, intent.owner(), intent.generation(), fact))
            .map_err(|_| "cannot bind initialization")?,
    );
    let mut record = InitRecord {
        version: 1,
        binding_sha256: binding,
        data_generation_uid: intent.generation().uid.clone(),
        initialize_operation_uid: intent.operation_uid().clone(),
        phase: InitPhase::ActivateIntent,
        data_sha256: None,
        offline_metadata_sha256: None,
    };
    let publish = |record: &InitRecord| -> Result<(), String> {
        worker.check_initialization(intent)?;
        dir.write(
            &filename,
            &serde_json::to_vec(record).map_err(|_| "cannot encode initializer journal")?,
        )
    };
    publish(&record)?;
    drop(lock);
    // Existing exact secondary activation, including apply-al, transport guard,
    // private plan and backing identity. No forced promotion is used.
    run(cfg, plan, Mode::Online)?;
    let (_held_dir, _pool_lock, pool, current, held_lv) =
        lvm::prepared_context_readonly(cfg, &plan.volume_uid)?;
    if held_lv.uuid != lv.uuid
        || current.allocation_nonce != allocation.allocation_nonce
        || pool.boot_id != boot.as_str()
    {
        return Err("backing/boot changed during exact initializer activation".into());
    }
    let mut replica = load(&dir, plan)?.ok_or("active exact replica journal missing")?;
    let boundary = || -> Result<(), String> {
        worker.check_initialization(intent)?;
        if Instant::now() >= deadline {
            return Err("initializer deadline; outcome UNKNOWN, no new write".into());
        }
        transport(cfg, plan)?;
        kernel_config(cfg, plan, &held_lv)?;
        guard::Guard::new(cfg, plan, &allocation.allocation_nonce)?.verify()?;
        Ok(())
    };
    boundary()?;
    fresh_online(
        cfg,
        plan,
        intent.capacity_bytes(),
        &status(plan)?.ok_or("new resource disappeared")?,
    )?;
    record.phase = InitPhase::BootstrapIntent;
    publish(&record)?;
    let conf = cfg.journal_path().join(config_name(plan));
    output(
        Program::Drbdadm,
        &bootstrap_args(
            conf.to_str().ok_or("invalid internal config path")?,
            &plan.name(),
        ),
    )?;
    loop {
        boundary()?;
        let state = status(plan)?.ok_or("resync resource disappeared")?;
        if synchronized(cfg, plan, intent.capacity_bytes(), &state, false).is_ok() {
            break;
        }
        // No mutation or time-only success: poll actual kernel progress within
        // the already admitted deadline. Failure cannot mint a receipt.
        std::thread::sleep(Duration::from_millis(100));
    }
    record.phase = InitPhase::Synchronized;
    publish(&record)?;
    boundary()?;
    record.phase = InitPhase::PromoteIntent;
    publish(&record)?;
    adm(cfg, plan, "primary")?;
    boundary()?;
    synchronized(
        cfg,
        plan,
        intent.capacity_bytes(),
        &status(plan)?.ok_or("promoted resource disappeared")?,
        true,
    )?;
    let device = format!("/dev/drbd{}", plan.minor);
    filesystem_probe(&device, None)?;
    record.phase = InitPhase::FormatIntent;
    publish(&record)?;
    output(
        Program::MkfsExt4,
        &fs_args(&intent.generation().filesystem_uuid, &device),
    )?;
    boundary()?;
    filesystem_probe(&device, Some(&intent.generation().filesystem_uuid))?;
    let bytes = allocation.request.exposed_bytes()?;
    let data = direct_hash(
        std::path::Path::new(&device),
        147,
        plan.minor as u64,
        bytes,
        bytes,
        deadline,
    )?;
    synchronized(
        cfg,
        plan,
        intent.capacity_bytes(),
        &status(plan)?.ok_or("formatted resource disappeared")?,
        true,
    )?;
    record.phase = InitPhase::Formatted;
    record.data_sha256 = Some(data.clone());
    publish(&record)?;
    boundary()?;
    record.phase = InitPhase::DemoteIntent;
    publish(&record)?;
    adm(cfg, plan, "secondary")?;
    boundary()?;
    synchronized(
        cfg,
        plan,
        intent.capacity_bytes(),
        &status(plan)?.ok_or("demoted resource disappeared")?,
        false,
    )?;
    record.phase = InitPhase::OfflineIntent;
    publish(&record)?;
    replica.stage = Stage::OfflineIntent;
    save(&dir, &replica)?;
    adm(cfg, plan, "down")?;
    worker.check_initialization(intent)?;
    if status(plan)?.is_some() {
        return Err("normal initializer down outcome UNKNOWN".into());
    }
    verify_superblock(cfg, plan, &held_lv, &fact.drbd_device_uuid)?;
    adm(cfg, plan, "apply-al")?;
    let (device_uuid, current_uuid) = metadata(cfg, plan)?;
    if device_uuid != fact.drbd_device_uuid
        || ["0000000000000000", "0000000000000004"].contains(&current_uuid.as_str())
    {
        return Err("initialized offline DRBD generation/device identity is missing".into());
    }
    lvm::verify_unheld(&held_lv)?;
    let backing = std::fs::canonicalize(format!(
        "/dev/{}/rkvol_{}",
        cfg.vg_name,
        plan.volume_uid.as_str()
    ))
    .map_err(|_| "offline exact backing disappeared")?;
    filesystem_probe(
        backing.to_str().ok_or("invalid backing path")?,
        Some(&intent.generation().filesystem_uuid),
    )?;
    let offline = direct_hash(
        &backing,
        held_lv.major,
        held_lv.minor,
        held_lv.bytes,
        bytes,
        deadline,
    )?;
    if offline != data {
        return Err("normal offline backing data differs from primary observation".into());
    }
    let md = adm(cfg, plan, "dump-md")?;
    guard::Guard::new(cfg, plan, &allocation.allocation_nonce)?.remove()?;
    replica.stage = Stage::Offline;
    save(&dir, &replica)?;
    record.phase = InitPhase::Complete;
    record.offline_metadata_sha256 = Some(hash(&md));
    publish(&record)?;
    Ok(InitializedOffline {
        kind: "royak-initialized-local-offline-diagnostic-v1",
        volume_uid: plan.volume_uid.clone(),
        data_generation_uid: intent.generation().uid.clone(),
        initialize_operation_uid: intent.operation_uid().clone(),
        filesystem_uuid: intent.generation().filesystem_uuid.clone(),
        node_uid: cfg.node_uid.clone(),
        node_boot_id: boot.as_str().into(),
        exposed_bytes: bytes,
        data_sha256: data,
        offline_metadata_sha256: hash(&md),
        pod_access_granted: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn direct_read_buffer_is_initialized_aligned_bounded_and_exclusively_borrowed() {
        let mut buffer = AlignedReadBuffer::new().unwrap();
        let data = buffer.bytes_mut();
        assert_eq!(data.len(), 1024 * 1024);
        assert_eq!(data.as_ptr() as usize % 4096, 0);
        assert!(data.iter().all(|byte| *byte == 0));
        data[0] = 19;
        let last = data.len() - 1;
        data[last] = 37;
        let data = buffer.bytes_mut();
        assert_eq!(data[0], 19);
        assert_eq!(data[data.len() - 1], 37);
    }
    fn fixture() -> (Config, Plan, Value) {
        let cfg = crate::storage_driver::test_config();
        let nodes = [cfg.node_uid.clone(), Uid::new(), Uid::new()];
        let peers = std::array::from_fn(|i| Peer {
            node_uid: nodes[i].clone(),
            node_id: i as u8,
            hostname: format!("n{i}"),
            address: format!("10.77.0.{}", i + 1).parse().unwrap(),
            public_key: format!("{}=", ["A", "B", "C"][i].repeat(43)),
            vg_name: cfg.vg_name.clone(),
        });
        let plan = Plan {
            version: 1,
            cluster_id: cfg.cluster_id.clone(),
            pool_uid: cfg.pool_uid.clone(),
            volume_uid: Uid::new(),
            operation_uid: Uid::new(),
            minor: 512,
            port: 22000,
            interface: "wg-test".into(),
            shared_secret: "0".repeat(48),
            peers,
        };
        let connections=plan.peers.iter().skip(1).map(|p|serde_json::json!({
            "peer-node-id":p.node_id,"name":p.hostname,"connection-state":"Connected","peer-role":"Secondary",
            "ap-in-flight":0,"rs-in-flight":0,"paths":[{"this_host":{"address":"10.77.0.1","port":22000},
            "remote_host":{"address":p.address,"port":22000},"established":true}],"peer_devices":[{
                "volume":0,"replication-state":"Established","peer-disk-state":"UpToDate","peer-client":false,
                "resync-suspended":"no","out-of-sync":0,"pending":0,"unacked":0}]})).collect::<Vec<_>>();
        let state = serde_json::json!({"node-id":0,"role":"Secondary","suspended":false,"force-io-failures":false,
            "devices":[{"volume":0,"minor":512,"open":false,"size":65536,"disk-state":"UpToDate",
                "client":false,"quorum":true,"upper-pending":0,"lower-pending":0}],"connections":connections});
        (cfg, plan, state)
    }
    #[test]
    fn actual_status_validation_requires_all_three_completed_diskful_copies() {
        let (cfg, plan, good) = fixture();
        synchronized(&cfg, &plan, 64 * 1024 * 1024, &good, false).unwrap();
        let mut primary = good.clone();
        primary["role"] = "Primary".into();
        synchronized(&cfg, &plan, 64 * 1024 * 1024, &primary, true).unwrap();
        assert!(synchronized(&cfg, &plan, 64 * 1024 * 1024, &primary, false).is_err());
        for case in 0..20 {
            let mut bad = good.clone();
            match case {
                0 => bad["devices"][0]["quorum"] = false.into(),
                1 => bad["devices"][0]["open"] = true.into(),
                2 => bad["devices"][0]["disk-state"] = "Inconsistent".into(),
                3 => bad["devices"][0]["upper-pending"] = 1.into(),
                4 => bad["devices"][0]["lower-pending"] = Value::Null,
                5 => bad["connections"][0]["connection-state"] = "Connecting".into(),
                6 => bad["connections"][1]["peer-role"] = "Primary".into(),
                7 => bad["connections"][0]["rs-in-flight"] = 1.into(),
                8 => bad["connections"][0]["ap-in-flight"] = Value::Null,
                9 => bad["connections"][0]["paths"][0]["established"] = false.into(),
                10 => {
                    bad["connections"][0]["peer_devices"][0]["peer-disk-state"] =
                        "Inconsistent".into()
                }
                11 => bad["connections"][0]["peer_devices"][0]["out-of-sync"] = 1.into(),
                12 => bad["connections"][0]["peer_devices"][0]["out-of-sync"] = Value::Null,
                13 => bad["connections"][0]["peer_devices"][0]["peer-client"] = true.into(),
                14 => {
                    bad["connections"][0]["peer_devices"][0]["replication-state"] =
                        "SyncSource".into()
                }
                15 => bad["connections"]
                    .as_array_mut()
                    .unwrap()
                    .pop()
                    .map(|_| ())
                    .unwrap(),
                16 => bad["connections"][0]["peer-node-id"] = 2.into(),
                17 => bad["suspended"] = true.into(),
                18 => bad["force-io-failures"] = true.into(),
                _ => bad["devices"][0]["client"] = true.into(),
            }
            assert!(
                synchronized(&cfg, &plan, 64 * 1024 * 1024, &bad, false).is_err(),
                "case {case}"
            );
        }
        assert!(
            fresh_online(&cfg, &plan, 64 * 1024 * 1024, &good).is_err(),
            "UpToDate is not a virgin bootstrap state"
        );
        let mut fresh = good.clone();
        fresh["devices"][0]["disk-state"] = "Inconsistent".into();
        for peer in fresh["connections"].as_array_mut().unwrap() {
            peer["peer_devices"][0]["peer-disk-state"] = "Inconsistent".into();
        }
        fresh_online(&cfg, &plan, 64 * 1024 * 1024, &fresh).unwrap();
        assert!(
            synchronized(&cfg, &plan, 64 * 1024 * 1024, &fresh, false).is_err(),
            "connected is not synchronized"
        );
    }
    #[test]
    fn fixed_bootstrap_and_format_never_skip_sync_or_force_an_existing_filesystem() {
        let args = bootstrap_args("/private/exact.conf", "rkvol_exact");
        assert_eq!(
            args,
            [
                "-c",
                "/private/exact.conf",
                "new-current-uuid",
                "--force-resync",
                "rkvol_exact"
            ]
        );
        assert!(!args
            .iter()
            .any(|s| s.contains("clear-bitmap") || s == "--force" || s.contains("quorum")));
        let args = fs_args("12345678-1234-4234-a234-123456789abc", "/dev/drbd512");
        assert!(!args.iter().any(|s| s == "-F" || s == "-FF"));
        assert!(args
            .iter()
            .any(|s| s == "lazy_itable_init=0,lazy_journal_init=0"));
    }
    #[test]
    fn exact_independent_filesystem_signature_is_mandatory() {
        let uuid = "12345678-1234-4234-a234-123456789abc";
        let good = format!("DEVNAME=/dev/drbd512\nUUID={uuid}\nTYPE=ext4\nUSAGE=filesystem\n");
        filesystem_signature(good.as_bytes(), uuid).unwrap();
        for bad in [
            good.replace("TYPE=ext4", "TYPE=xfs"),
            good.replace(uuid, "bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb"),
            format!("{good}UUID={uuid}\n"),
            format!("{good}PTTYPE=gpt\n"),
            format!("{good}PART_ENTRY_UUID=old\n"),
            "TYPE=ext4\n".into(),
        ] {
            assert!(filesystem_signature(bad.as_bytes(), uuid).is_err());
        }
    }
}

#[cfg(test)]
mod legacy_format_probe_containment_tests {
    use super::*;

    #[test]
    fn legacy_format_probe_none_refuses_before_any_program_with_unusable_device() {
        // An interior NUL cannot become a valid exec argument if this guard regresses.
        // The exact error and source-order case distinguish containment from probe failure.
        let error = filesystem_probe("\0royak-format-probe-containment", None).unwrap_err();
        assert_eq!(
            error,
            "pre-format absence requires a genuine phase-bound promoted-DRBD byte observation"
        );
        // No process, File, device, current permission or physical proof is constructed.
    }

    #[test]
    fn legacy_format_probe_source_none_guard_precedes_original_blkid_and_preserves_some() {
        let source = include_str!("replica_initialize.rs")
            .split("\n#[cfg(test)]")
            .next()
            .unwrap();
        let signature =
            "fn filesystem_probe(device: &str, expected: Option<&str>) -> Result<(), String> {";
        assert_eq!(source.matches(signature).count(), 1);
        let body = source
            .split(signature)
            .nth(1)
            .unwrap()
            .split("\n/// All three diskful members")
            .next()
            .unwrap();
        let guard = body.find("if expected.is_none() {").unwrap();
        let refused = body.find(
            "return Err(\"pre-format absence requires a genuine phase-bound promoted-DRBD byte observation\".into());",
        ).unwrap();
        let program = body.find(
            "let observed = process::run(Program::Blkid, &strings(&[\"-p\", \"-o\", \"export\", device]))?;",
        ).unwrap();
        assert!(guard < refused && refused < program);
        assert_eq!(body.matches("process::run(").count(), 1);
        assert!(!body.contains("observed.code == 2"));
        assert!(!body.contains("observed.stdout.is_empty()"));
        assert!(!body.contains("observed.stderr.is_empty()"));
        assert!(body.contains(
            "if let Some(uuid) = expected {\n        filesystem_signature(\n            &observed.success(\"independent filesystem observation\")?,\n            uuid,\n        )\n    } else {",
        ));
    }

    #[test]
    fn legacy_pre_format_callers_keep_none_before_mkfs_and_some_verification_after() {
        let initialize = include_str!("replica_initialize.rs")
            .split("\n#[cfg(test)]")
            .next()
            .unwrap();
        let original = initialize
            .split("pub(crate) fn initialize_new_offline(")
            .nth(1)
            .unwrap();
        let negative = "filesystem_probe(&device, None)?;";
        let positive = "filesystem_probe(&device, Some(&intent.generation().filesystem_uuid))?;";
        assert_eq!(original.matches(negative).count(), 1);
        let none = original.find(negative).unwrap();
        let intent = original.find("record.phase = InitPhase::FormatIntent;").unwrap();
        let mkfs = original.find("Program::MkfsExt4,").unwrap();
        let some = original.find(positive).unwrap();
        assert!(none < intent && intent < mkfs && mkfs < some);

        let phases = include_str!("replica_init_phases.rs")
            .split("\n#[cfg(test)]")
            .next()
            .unwrap();
        assert_eq!(phases.matches("Phase::Format => {").count(), 1);
        let format = phases
            .split("Phase::Format => {")
            .nth(1)
            .unwrap()
            .split("Phase::FlushPrimary => {")
            .next()
            .unwrap();
        assert_eq!(format.matches(negative).count(), 1);
        let none = format.find(negative).unwrap();
        let current = format.find("check_time(permit)?;").unwrap();
        let mkfs = format.find("Program::MkfsExt4,").unwrap();
        let some = format.find(positive).unwrap();
        assert!(none < current && current < mkfs && mkfs < some);
        // SOURCE order only. Neither caller is run and Format is not enabled.
    }
}
