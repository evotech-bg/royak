//! One exact physically authorized phase; never a coordinator or wire grant.
//! The same initialization filename excludes the historical monolith. Each
//! effect has an immutable fsynced intent and no physical replay constructor.
use super::*;
use crate::storage_driver::dispatcher::VerifiedDistributedInitPhase;
use crate::storage_lifecycle::generation::{
    physical::{
        InitPhase as Phase, OfflineReplicaObservation, PhaseObservation, PrimaryFlushObservation,
    },
    VirginReplicaRef,
};

/// Only execute_phase constructs this result, after actual IO and final current
/// boundary. Its observation getter exposes DATA for the verified helper's
/// stdout; that serialized DATA cannot reconstruct this opaque result.
pub(in crate::storage_driver) struct VerifiedPhysicalPhaseResult {
    observation: PhaseObservation,
}
impl VerifiedPhysicalPhaseResult {
    pub(in crate::storage_driver) fn observation(&self) -> &PhaseObservation {
        &self.observation
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhaseRecord {
    version: u32,
    binding_sha256: String,
    node_uid: Uid,
    node_boot_id: crate::storage_boot::BootId,
    data_generation_uid: Uid,
    initialize_operation_uid: Uid,
    phase: Phase,
    in_progress: bool,
    observation_sha256: Option<String>,
}
fn phase_number(phase: Phase) -> u8 {
    match phase {
        Phase::ActivateSecondary => 1,
        Phase::ObserveFresh => 2,
        Phase::Bootstrap => 3,
        Phase::ObserveSynchronized => 4,
        Phase::Promote => 5,
        Phase::Format => 6,
        Phase::FlushPrimary => 7,
        Phase::ObserveReplicated => 8,
        Phase::Demote => 9,
        Phase::ObserveDemoted => 10,
        Phase::Offline => 11,
        Phase::ObserveOffline => 12,
    }
}
fn previous(phase: Phase, initializer: bool) -> Option<Phase> {
    Some(match phase {
        Phase::ActivateSecondary => return None,
        Phase::ObserveFresh => Phase::ActivateSecondary,
        Phase::Bootstrap => Phase::ObserveFresh,
        Phase::ObserveSynchronized => {
            if initializer {
                Phase::Bootstrap
            } else {
                Phase::ObserveFresh
            }
        }
        Phase::Promote => Phase::ObserveSynchronized,
        Phase::Format => Phase::Promote,
        Phase::FlushPrimary => Phase::Format,
        Phase::ObserveReplicated => {
            if initializer {
                Phase::FlushPrimary
            } else {
                Phase::ObserveSynchronized
            }
        }
        Phase::Demote => Phase::ObserveReplicated,
        Phase::ObserveDemoted => {
            if initializer {
                Phase::Demote
            } else {
                Phase::ObserveReplicated
            }
        }
        Phase::Offline => Phase::ObserveDemoted,
        Phase::ObserveOffline => Phase::Offline,
    })
}
fn check_time(permit: &VerifiedDistributedInitPhase) -> Result<(), String> {
    let now = Instant::now();
    if now >= permit.deadline() || permit.deadline().duration_since(now) > Duration::from_secs(180)
    {
        return Err(
            "original distributed pipeline deadline expired or invalid; no next effect".into(),
        );
    }
    permit.checkpoint()
}
fn digest_json(value: &impl Serialize) -> Result<String, String> {
    Ok(hash(
        &serde_json::to_vec(value).map_err(|_| "cannot bind exact initialization phase")?,
    ))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn phase_binding(
    cfg: &Config,
    plan: &Plan,
    intent: &InitializationIntent,
    fact: &VirginReplicaRef,
) -> Result<String, String> {
    digest_json(&(
        "distributed-initialize-v2",
        cfg,
        plan,
        intent.owner(),
        intent.generation(),
        fact,
    ))
}
fn begin(
    dir: &Dir,
    cfg: &Config,
    plan: &Plan,
    intent: &InitializationIntent,
    fact: &VirginReplicaRef,
    phase: Phase,
    binding: &str,
) -> Result<PhaseRecord, String> {
    let filename = format!("initialize-{}.json", plan.volume_uid.as_str());
    let prior = dir.read(&filename)?;
    match (
        previous(
            phase,
            cfg.node_uid == intent.generation().initializer_node_uid,
        ),
        prior,
    ) {
        (None, None) => (),
        (Some(expected), Some(raw)) => {
            let old: PhaseRecord = serde_json::from_slice(&raw).map_err(|_| {
                "old/unknown initialization history cannot be adopted by distributed phases"
            })?;
            if old.version != 2
                || old.binding_sha256 != binding
                || old.node_uid != cfg.node_uid
                || old.node_boot_id != fact.node_boot_id
                || old.data_generation_uid != intent.generation().uid
                || old.initialize_operation_uid != *intent.operation_uid()
                || old.in_progress
                || old.phase != expected
                || old
                    .observation_sha256
                    .as_deref()
                    .is_none_or(|value| !valid_hash(value))
            {
                return Err(
                    "phase history is unknown, replayed, out of order or for another exact owner"
                        .into(),
                );
            }
            let prefix = format!(
                "initialize-{}-{:02}",
                plan.volume_uid.as_str(),
                phase_number(expected)
            );
            let complete = dir
                .read(&format!("{prefix}-complete.json"))?
                .ok_or("previous phase completion history missing")?;
            let (recorded, observation): (String, PhaseObservation) =
                serde_json::from_slice(&complete)
                    .map_err(|_| "previous phase completion history corrupt")?;
            if old.observation_sha256.as_deref() != Some(recorded.as_str())
                || digest_json(&observation)? != recorded
            {
                return Err("previous phase completion hash changed".into());
            }
            observation.validate_for(intent, expected, fact)?;
            let immutable = dir
                .read(&format!("{prefix}-intent.json"))?
                .ok_or("previous immutable phase intent missing")?;
            let prior_intent: PhaseRecord = serde_json::from_slice(&immutable)
                .map_err(|_| "previous immutable phase intent corrupt")?;
            if prior_intent.version != 2
                || prior_intent.phase != expected
                || !prior_intent.in_progress
                || prior_intent.binding_sha256 != binding
                || prior_intent.node_uid != cfg.node_uid
                || prior_intent.node_boot_id != fact.node_boot_id
                || prior_intent.data_generation_uid != intent.generation().uid
                || prior_intent.initialize_operation_uid != *intent.operation_uid()
                || prior_intent.observation_sha256.is_some()
            {
                return Err("previous immutable phase intent differs from exact lineage".into());
            }
        }
        _ => return Err("initialization phase is not a fresh once-only continuation".into()),
    }
    // Bounded retained history; never evict an unresolved phase to make room.
    if dir.bounded_entries(512)?.len() > 508 {
        return Err("initialization evidence budget exhausted".into());
    }
    let record = PhaseRecord {
        version: 2,
        binding_sha256: binding.to_string(),
        node_uid: cfg.node_uid.clone(),
        node_boot_id: fact.node_boot_id.clone(),
        data_generation_uid: intent.generation().uid.clone(),
        initialize_operation_uid: intent.operation_uid().clone(),
        phase,
        in_progress: true,
        observation_sha256: None,
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| "cannot encode phase intent")?;
    dir.write_new(
        &format!(
            "initialize-{}-{:02}-intent.json",
            plan.volume_uid.as_str(),
            phase_number(phase)
        ),
        &bytes,
    )?;
    dir.write(&filename, &bytes)?; // BOTH publications are durable before any effect.
    Ok(record)
}
fn finish(
    dir: &Dir,
    plan: &Plan,
    mut record: PhaseRecord,
    observation: &PhaseObservation,
) -> Result<(), String> {
    record.in_progress = false;
    record.observation_sha256 = Some(digest_json(observation)?);
    let bytes = serde_json::to_vec(&record).map_err(|_| "cannot encode exact phase completion")?;
    dir.write_new(
        &format!(
            "initialize-{}-{:02}-complete.json",
            plan.volume_uid.as_str(),
            phase_number(record.phase)
        ),
        &serde_json::to_vec(&(record.observation_sha256.as_ref(), observation))
            .map_err(|_| "cannot encode physical observation history")?,
    )?;
    dir.write(
        &format!("initialize-{}.json", plan.volume_uid.as_str()),
        &bytes,
    )
}

fn verify_backing(
    cfg: &Config,
    plan: &Plan,
    fact: &VirginReplicaRef,
    allocation: &lvm::LocalRecord,
    lv: &lvm::Lv,
    boot: &str,
) -> Result<(), String> {
    if cfg.node_uid != fact.node_uid
        || cfg.pool_uid != fact.pool_uid
        || plan.volume_uid != fact.volume_uid
        || plan.operation_uid != fact.prepare_operation_uid
        || fact.node_boot_id.as_str() != boot
        || allocation.allocation_nonce != fact.allocation_nonce
        || allocation.request.operation_uid != fact.prepare_operation_uid
        || lv.uuid != fact.lv_uuid
        || allocation.request.capacity_bytes != fact.requested_bytes
        || allocation.request.exposed_bytes()? != fact.exposed_bytes
        || digest_json(plan)? != fact.plan_sha256
    {
        return Err(
            "actual initialization backing/boot/plan differs from committed cold lineage".into(),
        );
    }
    let record =
        load(&Dir::open(&cfg.journal_path(), false)?, plan)?.ok_or("replica lineage missing")?;
    if record.device_uuid.as_deref() != Some(fact.drbd_device_uuid.as_str())
        || record.lv_uuid != lv.uuid
        || record.allocation_nonce != fact.allocation_nonce
    {
        return Err("replica physical lineage changed".into());
    }
    Ok(())
}
fn online_boundary(
    cfg: &Config,
    plan: &Plan,
    lv: &lvm::Lv,
    nonce: &Uid,
    permit: &VerifiedDistributedInitPhase,
) -> Result<(), String> {
    check_time(permit)?;
    transport(cfg, plan)?;
    kernel_config(cfg, plan, lv)?;
    guard::Guard::new(cfg, plan, nonce)?.verify()?;
    Ok(())
}
/// Local state plus exact intended peer roles. Unlike the old monolith,
/// independent Secondary observations can see exactly the ONE initializer
/// Primary; a Primary on any other node still refuses.
fn synchronized_roles(
    cfg: &Config,
    plan: &Plan,
    bytes: u64,
    state: &Value,
    primary: Option<&Uid>,
) -> Result<(), String> {
    let mut closed = state.clone();
    closed["role"] = "Secondary".into();
    secondary(cfg, plan, bytes, &closed)?;
    let expected_local = if primary == Some(&cfg.node_uid) {
        "Primary"
    } else {
        "Secondary"
    };
    if state["role"] != expected_local
        || state["suspended"] != false
        || state["force-io-failures"] != false
        || state["devices"][0]["disk-state"] != "UpToDate"
        || state["devices"][0]["client"] != false
        || state["devices"][0]["quorum"] != true
        || state["devices"][0]["upper-pending"] != 0
        || state["devices"][0]["lower-pending"] != 0
    {
        return Err("phase lacks exact synchronized local role/data/quorum".into());
    }
    for connection in state["connections"]
        .as_array()
        .ok_or("synchronization peers absent")?
    {
        let id = connection["peer-node-id"]
            .as_u64()
            .ok_or("peer ID absent")?;
        let peer = plan
            .peers
            .iter()
            .find(|peer| peer.node_id as u64 == id)
            .ok_or("unplanned synchronization peer")?;
        let expected_role = if primary == Some(&peer.node_uid) {
            "Primary"
        } else {
            "Secondary"
        };
        let devices = connection["peer_devices"]
            .as_array()
            .filter(|items| items.len() == 1)
            .ok_or("ambiguous synchronized peer device")?;
        let device = &devices[0];
        if connection["connection-state"] != "Connected"
            || connection["peer-role"] != expected_role
            || connection["ap-in-flight"] != 0
            || connection["rs-in-flight"] != 0
            || connection["paths"][0]["established"] != true
            || device["volume"] != 0
            || device["replication-state"] != "Established"
            || device["peer-disk-state"] != "UpToDate"
            || device["peer-client"] != false
            || device["resync-suspended"] != "no"
            || device["out-of-sync"] != 0
            || device["pending"] != 0
            || device["unacked"] != 0
        {
            return Err(
                "three exact diskful copies/roles have not independently synchronized".into(),
            );
        }
    }
    Ok(())
}
fn local_closed_for_down(
    cfg: &Config,
    plan: &Plan,
    bytes: u64,
    state: &Value,
) -> Result<(), String> {
    secondary(cfg, plan, bytes, state)?;
    // Planned previous peers may already be DOWN. Their disconnect is not
    // treated as synced proof, nor does it authorize a Primary/format step.
    if state["suspended"] != false
        || state["force-io-failures"] != false
        || state["devices"][0]["disk-state"] != "UpToDate"
        || state["devices"][0]["client"] != false
        || state["devices"][0]["upper-pending"] != 0
        || state["devices"][0]["lower-pending"] != 0
        || state["connections"]
            .as_array()
            .ok_or("offline peer set absent")?
            .iter()
            .any(|peer| !matches!(peer["peer-role"].as_str(), Some("Secondary" | "Unknown")))
    {
        return Err("ordinary down requires exact closed quiescent Secondary".into());
    }
    Ok(())
}
fn wait_state(
    cfg: &Config,
    plan: &Plan,
    intent: &InitializationIntent,
    lv: &lvm::Lv,
    nonce: &Uid,
    permit: &VerifiedDistributedInitPhase,
    fresh: bool,
    primary: Option<&Uid>,
) -> Result<Value, String> {
    loop {
        online_boundary(cfg, plan, lv, nonce, permit)?;
        let state = status(plan)?.ok_or("initialization resource disappeared")?;
        // Bind geometry/topology even while allowing read-only sync progress.
        let mut closed = state.clone();
        closed["role"] = "Secondary".into();
        secondary(cfg, plan, intent.capacity_bytes(), &closed)?;
        let expected = if primary == Some(&cfg.node_uid) {
            "Primary"
        } else {
            "Secondary"
        };
        if state["role"] != expected {
            return Err("unexpected local Primary/Secondary role".into());
        }
        let valid = if fresh {
            fresh_online(cfg, plan, intent.capacity_bytes(), &state)
        } else {
            synchronized_roles(cfg, plan, intent.capacity_bytes(), &state, primary)
        };
        if valid.is_ok() {
            check_time(permit)?;
            return Ok(state);
        }
        // Observation only; no command/operation/grant is retried or extended.
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(not(target_os = "linux"))]
fn read_hash(
    _: &std::path::Path,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: bool,
    _: &VerifiedDistributedInitPhase,
) -> Result<String, String> {
    Err("actual phase read requires Linux block IO".into())
}
#[cfg(target_os = "linux")]
fn read_hash(
    path: &std::path::Path,
    major: u64,
    minor: u64,
    bytes: u64,
    exposed: u64,
    require_zero: bool,
    permit: &VerifiedDistributedInitPhase,
) -> Result<String, String> {
    use std::io::Read;
    use std::os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    };
    if exposed == 0
        || exposed > bytes
        || exposed % 4096 != 0
        || major > u32::MAX as u64
        || minor > u32::MAX as u64
    {
        return Err("invalid exact initialized extent geometry".into());
    }
    check_time(permit)?;
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_EXCL | libc::O_DIRECT)
        .open(path)
        .map_err(|_| "cannot exclusively direct-read initialized extent")?;
    let meta = file
        .metadata()
        .map_err(|_| "initialized descriptor unavailable")?;
    let mut size = 0u64;
    if !meta.file_type().is_block_device()
        || meta.rdev() != libc::makedev(major as u32, minor as u32)
        || unsafe { libc::ioctl(file.as_raw_fd(), 0x80081272u32 as _, &mut size) } != 0
        || size != bytes
    {
        return Err("initialized descriptor identity/size changed".into());
    }
    let mut buffer = AlignedReadBuffer::new()?;
    let mut position = 0u64;
    let mut digest = Sha256::new();
    while position < exposed {
        let count = (exposed - position).min(buffer.layout.size() as u64) as usize;
        check_time(permit)?;
        permit.before_read(position, count as u64)?;
        file.read_exact(&mut buffer.bytes_mut()[..count])
            .map_err(|_| "short/failed exact initialized extent read")?;
        if require_zero && buffer.bytes_mut()[..count].iter().any(|byte| *byte != 0) {
            return Err("fresh cold extent is no longer wholly zero; no activation".into());
        }
        digest.update(&buffer.bytes_mut()[..count]);
        position += count as u64;
    }
    check_time(permit)?;
    let mut after = 0u64;
    if unsafe { libc::ioctl(file.as_raw_fd(), 0x80081272u32 as _, &mut after) } != 0
        || after != bytes
    {
        return Err("initialized descriptor size changed across direct read".into());
    }
    Ok(format!("{:x}", digest.finalize()))
}
fn verify_virgin_before_activation(
    cfg: &Config,
    plan: &Plan,
    intent: &InitializationIntent,
    permit: &VerifiedDistributedInitPhase,
) -> Result<(), String> {
    let fact = permit.fact();
    let (dir, _lock, pool, allocation, lv) = lvm::prepared_context_readonly(cfg, &plan.volume_uid)?;
    verify_backing(cfg, plan, fact, &allocation, &lv, &pool.boot_id)?;
    let record = load(&dir, plan)?.ok_or("fresh replica journal absent")?;
    if record.stage != Stage::MetadataReady || status(plan)?.is_some() {
        return Err("only never-activated MetadataReady replica may enter initialization".into());
    }
    let journal_before = dir
        .read(&journal_name(plan))?
        .ok_or("fresh replica journal disappeared")?;
    let conf = plan.config(fact.exposed_bytes);
    if dir.read(&config_name(plan))?.as_deref() != Some(conf.as_bytes()) {
        return Err("fresh private plan changed".into());
    }
    check_time(permit)?;
    lvm::verify_unheld(&lv)?;
    let before = String::from_utf8(adm(cfg, plan, "dump-md")?)
        .map_err(|_| "invalid fresh metadata output")?;
    if pristine_metadata_identity(&before, plan.local(cfg)?.node_id)? != fact.drbd_device_uuid {
        return Err("fresh metadata is not the exact just-created device".into());
    }
    verify_superblock(cfg, plan, &lv, &fact.drbd_device_uuid)?;
    let backing = std::fs::canonicalize(format!(
        "/dev/{}/rkvol_{}",
        cfg.vg_name,
        plan.volume_uid.as_str()
    ))
    .map_err(|_| "fresh backing disappeared")?;
    let zero = read_hash(
        &backing,
        lv.major,
        lv.minor,
        lv.bytes,
        fact.exposed_bytes,
        true,
        permit,
    )?;
    let after = String::from_utf8(adm(cfg, plan, "dump-md")?)
        .map_err(|_| "invalid fresh metadata output")?;
    if zero != fact.zero_sha256
        || pristine_metadata_identity(&after, plan.local(cfg)?.node_id)? != fact.drbd_device_uuid
        || status(plan)?.is_some()
        || dir.read(&journal_name(plan))?.as_deref() != Some(journal_before.as_slice())
        || dir.read(&config_name(plan))?.as_deref() != Some(conf.as_bytes())
        || intent.generation().prepare_operation_uid != plan.operation_uid
    {
        return Err("fresh exact cold lineage changed across protected direct zero read".into());
    }
    check_time(permit)
}
#[cfg(not(target_os = "linux"))]
fn flush_primary(
    _: &str,
    _: u16,
    _: u64,
    _: &VerifiedDistributedInitPhase,
) -> Result<String, String> {
    Err("actual initializer flush requires Linux".into())
}
#[cfg(target_os = "linux")]
fn flush_primary(
    device: &str,
    minor: u16,
    bytes: u64,
    permit: &VerifiedDistributedInitPhase,
) -> Result<String, String> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    };
    check_time(permit)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_EXCL)
        .open(device)
        .map_err(|_| "cannot pin exact primary for durability flush")?;
    let meta = file
        .metadata()
        .map_err(|_| "primary flush descriptor unavailable")?;
    let mut size = 0u64;
    if !meta.file_type().is_block_device()
        || meta.rdev() != libc::makedev(147, minor as u32)
        || unsafe { libc::ioctl(file.as_raw_fd(), 0x80081272u32 as _, &mut size) } != 0
        || size != bytes
    {
        return Err("primary flush descriptor identity/geometry changed".into());
    }
    check_time(permit)?; // exact phase + generation boundary immediately before fsync
    file.sync_all()
        .map_err(|_| "primary block fsync outcome UNKNOWN")?;
    check_time(permit)?;
    digest_json(&(
        "actual-primary-block-fsync-v1",
        meta.rdev(),
        size,
        permit.fact(),
        permit.intent().generation(),
    ))
}

pub(in crate::storage_driver) fn execute_phase(
    cfg: &Config,
    plan: &Plan,
    intent: &InitializationIntent,
    permit: &VerifiedDistributedInitPhase,
) -> Result<VerifiedPhysicalPhaseResult, String> {
    if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
        return Err("physical initialization phase requires Linux root".into());
    }
    let phase = permit.phase();
    let fact = permit.fact();
    permit.check_inputs(cfg, intent, &digest_json(plan)?)?;
    check_time(permit)?;
    plan.validate(cfg)?;
    if fact.volume_uid != intent.owner().volume_uid
        || !intent
            .generation()
            .virgin_replicas
            .iter()
            .any(|item| item == fact)
        || plan.operation_uid != intent.generation().prepare_operation_uid
        || phase.initializer_only() && cfg.node_uid != intent.generation().initializer_node_uid
    {
        return Err("physical phase is not bound to exact designated dataset/node".into());
    }
    // Only before FIRST activation: an actual virgin probe, never a relabelled
    // Online/Offline report. It does its own private pool lock/direct zero read.
    if phase == Phase::ActivateSecondary {
        verify_virgin_before_activation(cfg, plan, intent, permit)?;
    }
    let (dir, lock, pool, allocation, lv) = lvm::prepared_context_readonly(cfg, &plan.volume_uid)?;
    verify_backing(cfg, plan, fact, &allocation, &lv, &pool.boot_id)?;
    let binding = phase_binding(cfg, plan, intent, fact)?;
    let record = begin(&dir, cfg, plan, intent, fact, phase, &binding)?;
    let mut observation = PhaseObservation {
        version: 1,
        phase,
        owner: intent.owner().clone(),
        data_generation_uid: intent.generation().uid.clone(),
        initialize_operation_uid: intent.operation_uid().clone(),
        replica: fact.clone(),
        raw_kernel: None,
        primary: None,
        offline: None,
        evidence_sha256: "0".repeat(64),
    };
    if phase == Phase::ActivateSecondary {
        drop(lock); // existing activation obtains that SAME pool lock itself
        check_time(permit)?;
        run(cfg, plan, Mode::Online)?;
        let (_again_dir, _again_lock, again_pool, again_allocation, again_lv) =
            lvm::prepared_context_readonly(cfg, &plan.volume_uid)?;
        verify_backing(
            cfg,
            plan,
            fact,
            &again_allocation,
            &again_lv,
            &again_pool.boot_id,
        )?;
        online_boundary(
            cfg,
            plan,
            &again_lv,
            &again_allocation.allocation_nonce,
            permit,
        )?;
        let state = status(plan)?.ok_or("activation returned without actual resource")?;
        secondary(cfg, plan, intent.capacity_bytes(), &state)?;
        observation.raw_kernel = Some(state);
        observation.evidence_sha256 = digest_json(&(phase, &binding, &observation.raw_kernel))?;
        observation.validate_for(intent, phase, fact)?;
        check_time(permit)?;
        finish(&dir, plan, record, &observation)?;
        check_time(permit)?;
        return Ok(VerifiedPhysicalPhaseResult { observation });
    }
    let _pool_lock = lock; // all remaining exact commands/reads retain this lock
    let device = format!("/dev/drbd{}", plan.minor);
    match phase {
        Phase::ActivateSecondary => unreachable!(),
        Phase::ObserveFresh => {
            observation.raw_kernel = Some(wait_state(
                cfg,
                plan,
                intent,
                &lv,
                &allocation.allocation_nonce,
                permit,
                true,
                None,
            )?);
        }
        Phase::Bootstrap => {
            online_boundary(cfg, plan, &lv, &allocation.allocation_nonce, permit)?;
            fresh_online(
                cfg,
                plan,
                intent.capacity_bytes(),
                &status(plan)?.ok_or("fresh resource missing")?,
            )?;
            let conf = cfg.journal_path().join(config_name(plan));
            output(
                Program::Drbdadm,
                &bootstrap_args(conf.to_str().ok_or("invalid config path")?, &plan.name()),
            )?;
            observation.raw_kernel = status(plan)?;
        }
        Phase::ObserveSynchronized | Phase::ObserveDemoted => {
            observation.raw_kernel = Some(wait_state(
                cfg,
                plan,
                intent,
                &lv,
                &allocation.allocation_nonce,
                permit,
                false,
                None,
            )?);
        }
        Phase::Promote => {
            online_boundary(cfg, plan, &lv, &allocation.allocation_nonce, permit)?;
            synchronized_roles(
                cfg,
                plan,
                intent.capacity_bytes(),
                &status(plan)?.ok_or("promotion resource missing")?,
                None,
            )?;
            adm(cfg, plan, "primary")?;
            let state = status(plan)?.ok_or("promoted resource missing")?;
            synchronized_roles(
                cfg,
                plan,
                intent.capacity_bytes(),
                &state,
                Some(&intent.generation().initializer_node_uid),
            )?;
            observation.raw_kernel = Some(state);
        }
        Phase::Format => {
            online_boundary(cfg, plan, &lv, &allocation.allocation_nonce, permit)?;
            synchronized_roles(
                cfg,
                plan,
                intent.capacity_bytes(),
                &status(plan)?.ok_or("format resource missing")?,
                Some(&cfg.node_uid),
            )?;
            filesystem_probe(&device, None)?;
            check_time(permit)?;
            output(
                Program::MkfsExt4,
                &fs_args(&intent.generation().filesystem_uuid, &device),
            )?;
            filesystem_probe(&device, Some(&intent.generation().filesystem_uuid))?;
            observation.raw_kernel = status(plan)?;
        }
        Phase::FlushPrimary => {
            online_boundary(cfg, plan, &lv, &allocation.allocation_nonce, permit)?;
            synchronized_roles(
                cfg,
                plan,
                intent.capacity_bytes(),
                &status(plan)?.ok_or("flush resource missing")?,
                Some(&cfg.node_uid),
            )?;
            filesystem_probe(&device, Some(&intent.generation().filesystem_uuid))?;
            let flush = flush_primary(&device, plan.minor, fact.exposed_bytes, permit)?;
            let data = read_hash(
                std::path::Path::new(&device),
                147,
                plan.minor as u64,
                fact.exposed_bytes,
                fact.exposed_bytes,
                false,
                permit,
            )?;
            filesystem_probe(&device, Some(&intent.generation().filesystem_uuid))?;
            let state = status(plan)?.ok_or("flushed resource missing")?;
            synchronized_roles(
                cfg,
                plan,
                intent.capacity_bytes(),
                &state,
                Some(&cfg.node_uid),
            )?;
            let evidence = digest_json(&(
                "flushed-primary-v1",
                intent.generation(),
                fact,
                &flush,
                &data,
                &state,
            ))?;
            observation.primary = Some(PrimaryFlushObservation {
                version: 1,
                owner: intent.owner().clone(),
                data_generation_uid: intent.generation().uid.clone(),
                initialize_operation_uid: intent.operation_uid().clone(),
                filesystem_uuid: intent.generation().filesystem_uuid.clone(),
                replica: fact.clone(),
                backing_major: lv.major,
                backing_minor: lv.minor,
                backing_bytes: lv.bytes,
                data_sha256: data,
                flush_sha256: flush,
                evidence_sha256: evidence,
            });
            observation.raw_kernel = Some(state);
        }
        Phase::ObserveReplicated => {
            observation.raw_kernel = Some(wait_state(
                cfg,
                plan,
                intent,
                &lv,
                &allocation.allocation_nonce,
                permit,
                false,
                Some(&intent.generation().initializer_node_uid),
            )?);
        }
        Phase::Demote => {
            online_boundary(cfg, plan, &lv, &allocation.allocation_nonce, permit)?;
            synchronized_roles(
                cfg,
                plan,
                intent.capacity_bytes(),
                &status(plan)?.ok_or("demotion resource missing")?,
                Some(&cfg.node_uid),
            )?;
            adm(cfg, plan, "secondary")?;
            let state = status(plan)?.ok_or("demoted resource missing")?;
            synchronized_roles(cfg, plan, intent.capacity_bytes(), &state, None)?;
            observation.raw_kernel = Some(state);
        }
        Phase::Offline => {
            online_boundary(cfg, plan, &lv, &allocation.allocation_nonce, permit)?;
            local_closed_for_down(
                cfg,
                plan,
                intent.capacity_bytes(),
                &status(plan)?.ok_or("offline resource missing")?,
            )?;
            let mut replica = load(&dir, plan)?.ok_or("offline replica lineage missing")?;
            replica.stage = Stage::OfflineIntent;
            save(&dir, &replica)?;
            adm(cfg, plan, "down")?;
            if status(plan)?.is_some() {
                return Err("normal down outcome UNKNOWN".into());
            }
            verify_superblock(cfg, plan, &lv, &fact.drbd_device_uuid)?;
            adm(cfg, plan, "apply-al")?;
            if metadata(cfg, plan)?.0 != fact.drbd_device_uuid {
                return Err("offline device UUID changed".into());
            }
            guard::Guard::new(cfg, plan, &allocation.allocation_nonce)?.remove()?;
            replica.stage = Stage::Offline;
            save(&dir, &replica)?;
        }
        Phase::ObserveOffline => {
            check_time(permit)?;
            let replica = load(&dir, plan)?.ok_or("offline observation lineage missing")?;
            if replica.stage != Stage::Offline || status(plan)?.is_some() {
                return Err("offline observation requires actual absent kernel resource".into());
            }
            verify_superblock(cfg, plan, &lv, &fact.drbd_device_uuid)?;
            lvm::verify_unheld(&lv)?;
            let before = metadata(cfg, plan)?;
            if before.0 != fact.drbd_device_uuid
                || ["0000000000000000", "0000000000000004"].contains(&before.1.as_str())
            {
                return Err("offline initialized DRBD identity missing".into());
            }
            let backing = std::fs::canonicalize(format!(
                "/dev/{}/rkvol_{}",
                cfg.vg_name,
                plan.volume_uid.as_str()
            ))
            .map_err(|_| "offline backing disappeared")?;
            filesystem_probe(
                backing.to_str().ok_or("invalid backing path")?,
                Some(&intent.generation().filesystem_uuid),
            )?;
            let data = read_hash(
                &backing,
                lv.major,
                lv.minor,
                lv.bytes,
                fact.exposed_bytes,
                false,
                permit,
            )?;
            if status(plan)?.is_some() || metadata(cfg, plan)? != before {
                return Err("offline data/metadata changed across direct read".into());
            }
            lvm::verify_unheld(&lv)?;
            filesystem_probe(
                backing.to_str().ok_or("invalid backing path")?,
                Some(&intent.generation().filesystem_uuid),
            )?;
            let md = adm(cfg, plan, "dump-md")?;
            let mdhash = hash(&md);
            let evidence = digest_json(&(
                "independent-offline-copy-v1",
                intent.generation(),
                fact,
                &lv,
                &before,
                &data,
                &mdhash,
            ))?;
            observation.offline = Some(OfflineReplicaObservation {
                version: 1,
                owner: intent.owner().clone(),
                data_generation_uid: intent.generation().uid.clone(),
                initialize_operation_uid: intent.operation_uid().clone(),
                filesystem_uuid: intent.generation().filesystem_uuid.clone(),
                replica: fact.clone(),
                backing_major: lv.major,
                backing_minor: lv.minor,
                backing_bytes: lv.bytes,
                data_sha256: data,
                offline_metadata_sha256: mdhash,
                drbd_current_uuid: before.1,
                evidence_sha256: evidence,
            });
        }
    }
    check_time(permit)?;
    observation.evidence_sha256 = digest_json(&(
        phase,
        &binding,
        &observation.raw_kernel,
        &observation.primary,
        &observation.offline,
    ))?;
    observation.validate_for(intent, phase, fact)?;
    finish(&dir, plan, record, &observation)?;
    check_time(permit)?;
    Ok(VerifiedPhysicalPhaseResult { observation })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn topology() -> (Config, Plan, Value) {
        let cfg = crate::storage_driver::test_config();
        let nodes = [cfg.node_uid.clone(), Uid::new(), Uid::new()];
        let peers = std::array::from_fn(|index| Peer {
            node_uid: nodes[index].clone(),
            node_id: index as u8,
            hostname: format!("n{index}"),
            address: format!("10.77.0.{}", index + 1).parse().unwrap(),
            public_key: format!("{}=", ["A", "B", "C"][index].repeat(43)),
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
        let connections=plan.peers.iter().skip(1).map(|peer|serde_json::json!({"peer-node-id":peer.node_id,"name":peer.hostname,
            "connection-state":"Connected","peer-role":"Secondary","ap-in-flight":0,"rs-in-flight":0,
            "paths":[{"this_host":{"address":"10.77.0.1","port":22000},"remote_host":{"address":peer.address,"port":22000},"established":true}],
            "peer_devices":[{"volume":0,"replication-state":"Established","peer-disk-state":"UpToDate","peer-client":false,
                "resync-suspended":"no","out-of-sync":0,"pending":0,"unacked":0}]})).collect::<Vec<_>>();
        let state = serde_json::json!({"node-id":0,"role":"Secondary","suspended":false,"force-io-failures":false,
            "devices":[{"volume":0,"minor":512,"open":false,"size":65536,"disk-state":"UpToDate","client":false,
                "quorum":true,"upper-pending":0,"lower-pending":0}],"connections":connections});
        (cfg, plan, state)
    }
    #[test]
    fn independent_secondary_view_accepts_only_designated_initializer_primary() {
        let (cfg, plan, mut state) = topology();
        let initializer = plan.peers[1].node_uid.clone();
        state["connections"][0]["peer-role"] = "Primary".into();
        synchronized_roles(&cfg, &plan, 64 * 1024 * 1024, &state, Some(&initializer)).unwrap();
        assert!(synchronized_roles(&cfg, &plan, 64 * 1024 * 1024, &state, None).is_err());
        for case in 0..5 {
            let mut bad = state.clone();
            match case {
                0 => bad["connections"][1]["peer-role"] = "Primary".into(),
                1 => bad["role"] = "Primary".into(),
                2 => bad["connections"][0]["peer_devices"][0]["out-of-sync"] = 1.into(),
                3 => bad["devices"][0]["quorum"] = false.into(),
                _ => bad["connections"][0]["ap-in-flight"] = Value::Null,
            }
            assert!(
                synchronized_roles(&cfg, &plan, 64 * 1024 * 1024, &bad, Some(&initializer))
                    .is_err(),
                "case{case}"
            );
        }
    }
    #[test]
    fn planned_down_allows_closed_peer_disconnect_but_not_an_open_or_primary_local_device() {
        let (cfg, plan, mut state) = topology();
        state["devices"][0]["quorum"] = false.into();
        for peer in state["connections"].as_array_mut().unwrap() {
            peer["connection-state"] = "StandAlone".into();
            peer["peer-role"] = "Unknown".into();
            peer["paths"][0]["established"] = false.into();
        }
        local_closed_for_down(&cfg, &plan, 64 * 1024 * 1024, &state).unwrap();
        assert!(synchronized_roles(&cfg, &plan, 64 * 1024 * 1024, &state, None).is_err());
        for case in 0..4 {
            let mut bad = state.clone();
            match case {
                0 => bad["role"] = "Primary".into(),
                1 => bad["devices"][0]["open"] = true.into(),
                2 => bad["devices"][0]["upper-pending"] = 1.into(),
                _ => bad["connections"][0]["peer-role"] = "Primary".into(),
            }
            assert!(local_closed_for_down(&cfg, &plan, 64 * 1024 * 1024, &bad).is_err());
        }
    }
    #[test]
    fn closed_phase_graph_has_no_follower_format_or_phase_skip() {
        assert_eq!(
            previous(Phase::ObserveSynchronized, false),
            Some(Phase::ObserveFresh)
        );
        assert_eq!(
            previous(Phase::ObserveSynchronized, true),
            Some(Phase::Bootstrap)
        );
        assert_eq!(previous(Phase::Format, true), Some(Phase::Promote));
        assert_eq!(previous(Phase::ObserveOffline, false), Some(Phase::Offline));
        for phase in [
            Phase::Bootstrap,
            Phase::Promote,
            Phase::Format,
            Phase::FlushPrimary,
            Phase::Demote,
        ] {
            assert!(phase.initializer_only());
        }
        let mut numbers = std::collections::BTreeSet::new();
        for phase in [
            Phase::ActivateSecondary,
            Phase::ObserveFresh,
            Phase::Bootstrap,
            Phase::ObserveSynchronized,
            Phase::Promote,
            Phase::Format,
            Phase::FlushPrimary,
            Phase::ObserveReplicated,
            Phase::Demote,
            Phase::ObserveDemoted,
            Phase::Offline,
            Phase::ObserveOffline,
        ] {
            assert!(numbers.insert(phase_number(phase)));
        }
        assert_eq!(numbers.len(), 12);
    }
    #[test]
    fn physical_phase_journal_keeps_unknown_intent_and_refuses_replay_skip_or_legacy_adoption() {
        // Actual private FILE IO only; no permit, physical result, block IO,
        // program, generation receipt or current-Core authority is constructed.
        let (_, intent) =
            crate::storage_lifecycle::generation::model_initialization_for_authority_tests();
        let fact = &intent.generation().virgin_replicas[0];
        let (mut cfg, mut plan, _) = topology();
        cfg.node_uid = fact.node_uid.clone();
        cfg.pool_uid = fact.pool_uid.clone();
        plan.volume_uid = fact.volume_uid.clone();
        plan.operation_uid = fact.prepare_operation_uid.clone();
        let path = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("royak-init-journal-data-{}", Uid::new().as_str()));
        let dir = Dir::open(&path, true).unwrap();
        let binding = "a".repeat(64);
        let record = begin(
            &dir,
            &cfg,
            &plan,
            &intent,
            fact,
            Phase::ActivateSecondary,
            &binding,
        )
        .unwrap();
        assert!(begin(
            &dir,
            &cfg,
            &plan,
            &intent,
            fact,
            Phase::ActivateSecondary,
            &binding
        )
        .is_err());
        assert!(begin(
            &dir,
            &cfg,
            &plan,
            &intent,
            fact,
            Phase::ObserveFresh,
            &binding
        )
        .is_err());
        let observation = PhaseObservation {
            version: 1,
            phase: Phase::ActivateSecondary,
            owner: intent.owner().clone(),
            data_generation_uid: intent.generation().uid.clone(),
            initialize_operation_uid: intent.operation_uid().clone(),
            replica: fact.clone(),
            raw_kernel: None,
            primary: None,
            offline: None,
            evidence_sha256: "c".repeat(64),
        };
        finish(&dir, &plan, record, &observation).unwrap();
        assert!(begin(&dir, &cfg, &plan, &intent, fact, Phase::Format, &binding).is_err());
        let next = begin(
            &dir,
            &cfg,
            &plan,
            &intent,
            fact,
            Phase::ObserveFresh,
            &binding,
        )
        .unwrap();
        assert_eq!(next.phase, Phase::ObserveFresh);
        assert!(next.in_progress);
        dir.write(
            &format!("initialize-{}.json", plan.volume_uid.as_str()),
            b"{\"version\":1}",
        )
        .unwrap();
        assert!(begin(
            &dir,
            &cfg,
            &plan,
            &intent,
            fact,
            Phase::ObserveFresh,
            &binding
        )
        .is_err());
        drop(dir);
        std::fs::remove_dir_all(path).unwrap();
    }
}
