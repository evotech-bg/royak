//! Pinned inherited helper's closed first-attach physical path. Stdout is DATA;
//! only the original Watch supervisor can mint its own actual drain/lifetime.
use super::*;
use crate::storage_driver::dispatcher::attachment::VerifiedAttachPhase;
use crate::storage_driver::native_runtime::mount::parent::AttachNativeStep;
use crate::storage_lifecycle::pod_attachment::{AttachPhase,AttachPhaseObservation,scope_digest};
use crate::storage_lifecycle::generation::physical::{InitPhase,PhaseObservation};

#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::storage_driver) struct WorkerObservation {
    pub(in crate::storage_driver) version:u32,
    pub(in crate::storage_driver) scope_sha256:String,
    pub(in crate::storage_driver) step:AttachNativeStep,
    pub(in crate::storage_driver) phase:Option<AttachPhaseObservation>,
    pub(in crate::storage_driver) anchor:Option<anchor::AnchorMountObservation>,
}
impl WorkerObservation {
    pub(in crate::storage_driver) fn validate(&self,scope:&ExpectedAttachScope,step:AttachNativeStep)->Result<(),String> {
        if self.version!=1 || self.scope_sha256!=scope_digest(scope)? || self.step!=step {
            return Err("actual worker diagnostic has another exact closed scope/substep".into());
        }
        match step {
            AttachNativeStep::PublicationAnchor=>{
                let a=self.anchor.as_ref().ok_or("actual new anchor observation missing")?;
                if scope.phase!=AttachPhase::Mount || self.phase.is_some() || a.boot!=scope.phase_boot
                    || a.mount_id==0 || a.inode==0 || a.namespace.1==0 || !valid_hash(&a.preserved_mountinfo_sha256) {
                    return Err("anchor-only observation is not a mounted-volume receipt".into());
                }
            },
            _=>{if self.anchor.is_some(){return Err("non-anchor phase carries anchor output".into());}
                self.phase.as_ref().ok_or("actual phase observation absent")?.validate(scope)?;}
        }Ok(())
    }
}
fn valid_hash(v:&str)->bool {v.len()==64 && v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn digest(v:&impl Serialize)->Result<String,String>{Ok(hash(&serde_json::to_vec(v).map_err(|_|"cannot bind closed attachment evidence")?))}
pub(in crate::storage_driver) fn minor(plan:&Plan)->u32 {plan.minor as u32}

/// Protected local DATA loader, not capability construction. Actual parent
/// current Core/namespace/pool remains mandatory at every physical boundary.
pub(in crate::storage_driver) fn retained_plan(cfg:&Config,scope:&ExpectedAttachScope)->Result<Plan,String> {
    cfg.validate()?;scope.validate()?;
    let dir=Dir::open(&cfg.journal_path(),false)?;
    let raw=dir.read(&format!("replica-{}.json",scope.owner.volume_uid.as_str()))?.ok_or("retained exact replica journal absent")?;
    let envelope:Envelope=serde_json::from_slice(&raw).map_err(|_|"retained replica envelope corrupt")?;
    let plan=envelope.record.plan.clone();
    let record=load(&dir,&plan)?.ok_or("retained replica disappeared")?;
    if envelope.version!=1 || record.plan!=plan {return Err("retained replica envelope differs".into());}
    check_inputs(cfg,&plan,scope)?;Ok(plan)
}
pub(in crate::storage_driver) fn check_inputs(cfg:&Config,plan:&Plan,scope:&ExpectedAttachScope)->Result<(),String> {
    cfg.validate()?;plan.validate(cfg)?;scope.validate()?;
    let target=scope.target()?;
    let fact=scope.generation.virgin_replicas.iter().find(|f|f.node_uid==cfg.node_uid).ok_or("phase node absent from generation")?;
    if cfg.node_uid!=scope.phase_node_uid || cfg.pool_uid!=target.pool_uid || cfg.cluster_id!=scope.owner.cluster_id
        || plan.volume_uid!=scope.owner.volume_uid || plan.operation_uid!=scope.generation.prepare_operation_uid
        || plan.runtime_hash()?!=target.plan_sha256 || fact.pool_uid!=cfg.pool_uid
        || crate::storage_boot::BootId::current()?!=target.current_boot {
        return Err("actual attachment pool/plan/current boot differs from committed generation/target".into());
    }Ok(())
}
fn local_initial_lineage(dir:&Dir,plan:&Plan,scope:&ExpectedAttachScope)->Result<(),String> {
    let raw=dir.read(&format!("initialize-{}-12-complete.json",plan.volume_uid.as_str()))?
        .ok_or("actual protected final offline initialization history absent")?;
    let (recorded,observation):(String,PhaseObservation)=serde_json::from_slice(&raw)
        .map_err(|_|"actual offline initialization history corrupt")?;
    let local=scope.initial_lineage.offline.iter().find(|o|o.replica.node_uid==scope.phase_node_uid)
        .ok_or("local offline history missing from canonical prior proof")?;
    if !valid_hash(&recorded) || recorded!=digest(&observation)? || observation.phase!=InitPhase::ObserveOffline
        || observation.owner!=scope.owner || observation.data_generation_uid!=scope.generation.uid
        || observation.initialize_operation_uid!=scope.generation.initialize_operation_uid
        || observation.replica!=local.replica || observation.offline.as_ref()!=Some(local) || observation.primary.is_some() {
        return Err("local protected history is not exact committed offline birth lineage".into());
    }
    // Existing files are historical birth provenance, never rewritten to this
    // new boot. No activation is permitted from a Complete-shaped JSON alone.
    Ok(())
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct AttachRecord {version:u32,round_uid:Uid,phase_job_uid:Uid,phase:AttachPhase,
    step:AttachNativeStep,scope_sha256:String,complete:bool,evidence_sha256:Option<String>}
fn begin(dir:&Dir,scope:&ExpectedAttachScope,step:AttachNativeStep)->Result<(AttachRecord,String),String> {
    let filename=format!("attach-{}-{}-{:?}-{:?}-intent.json",scope.owner.volume_uid.as_str(),scope.round_uid.as_str(),scope.phase,step);
    let record=AttachRecord {version:1,round_uid:scope.round_uid.clone(),phase_job_uid:scope.phase_job_uid.clone(),
        phase:scope.phase,step,scope_sha256:scope_digest(scope)?,complete:false,evidence_sha256:None};
    if dir.bounded_entries(512)?.len()>508{return Err("attachment evidence retention full".into());}
    dir.write_new(&filename,&serde_json::to_vec(&record).map_err(|_|"attach intent encoding")?)?;
    Ok((record,filename))
}
fn online(cfg:&Config,plan:&Plan,allocation:&lvm::LocalRecord,lv:&lvm::Lv,permit:&VerifiedAttachPhase)->Result<(),String> {
    permit.checkpoint()?;transport(cfg,plan)?;kernel_config(cfg,plan,lv)?;
    guard::Guard::new(cfg,plan,&allocation.allocation_nonce)?.verify()?;permit.checkpoint()
}
fn sync_roles(cfg:&Config,plan:&Plan,bytes:u64,state:&Value,writer:Option<&Uid>)->Result<(),String> {
    let mut closed=state.clone();closed["role"]="Secondary".into();secondary(cfg,plan,bytes,&closed)?;
    if state["role"]!=if writer==Some(&cfg.node_uid){"Primary"}else{"Secondary"}
        || state["suspended"]!=false || state["force-io-failures"]!=false
        || state["devices"][0]["disk-state"]!="UpToDate" || state["devices"][0]["client"]!=false
        || state["devices"][0]["quorum"]!=true || state["devices"][0]["upper-pending"]!=0 || state["devices"][0]["lower-pending"]!=0 {
        return Err("attachment lacks exact local synchronized role/disk/quorum".into());
    }
    for connection in state["connections"].as_array().ok_or("replica peer data absent")? {
        let peer=plan.peers.iter().find(|p|connection["peer-node-id"]==p.node_id).ok_or("unplanned replication peer")?;
        let expected=if writer==Some(&peer.node_uid){"Primary"}else{"Secondary"};
        let devices=connection["peer_devices"].as_array().filter(|d|d.len()==1).ok_or("ambiguous peer device")?;
        let d=&devices[0];
        if connection["connection-state"]!="Connected" || connection["peer-role"]!=expected
            || connection["ap-in-flight"]!=0 || connection["rs-in-flight"]!=0 || connection["paths"][0]["established"]!=true
            || d["volume"]!=0 || d["replication-state"]!="Established" || d["peer-disk-state"]!="UpToDate"
            || d["peer-client"]!=false || d["resync-suspended"]!="no" || d["out-of-sync"]!=0 || d["pending"]!=0 || d["unacked"]!=0 {
            return Err("all three independent intended roles/copies have not synchronized".into());
        }
    }Ok(())
}
fn wait_synchronized(cfg:&Config,plan:&Plan,allocation:&lvm::LocalRecord,lv:&lvm::Lv,
    permit:&VerifiedAttachPhase,writer:Option<&Uid>)->Result<Value,String> {
    loop {
        online(cfg,plan,allocation,lv,permit)?;
        let state=status(plan)?.ok_or("actual attachment resource disappeared")?;
        let mut closed=state.clone();closed["role"]="Secondary".into();
        secondary(cfg,plan,permit.scope().generation.virgin_replicas[0].requested_bytes,&closed)?;
        let expected=if writer==Some(&cfg.node_uid){"Primary"}else{"Secondary"};
        if state["role"]!=expected {return Err("unexpected local role during first healthy attachment".into());}
        for connection in state["connections"].as_array().ok_or("actual peer roles absent")? {
            let peer=plan.peers.iter().find(|p|connection["peer-node-id"]==p.node_id).ok_or("unplanned peer")?;
            if connection["peer-role"]=="Primary" && writer!=Some(&peer.node_uid){return Err("unexpected remote Primary; no waiting/fallback".into());}
        }
        if sync_roles(cfg,plan,permit.scope().generation.virgin_replicas[0].requested_bytes,&state,writer).is_ok(){
            permit.checkpoint()?;return Ok(state);
        }
        // Read-only kernel progress under SAME original deadline; no command
        // effect, reservation, offer, promotion or mount is retried here.
        std::thread::sleep(Duration::from_millis(100));
    }
}
#[cfg(target_os="linux")]
fn exposed_hash(plan:&Plan,scope:&ExpectedAttachScope,permit:&VerifiedAttachPhase)->Result<String,String> {
    use std::io::Read;use std::os::{fd::AsRawFd,unix::fs::{FileTypeExt,OpenOptionsExt}};
    let bytes=scope.generation.virgin_replicas[0].exposed_bytes;
    let mut file=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_CLOEXEC|libc::O_NOFOLLOW|libc::O_DIRECT|libc::O_EXCL)
        .open(format!("/dev/drbd{}",plan.minor)).map_err(|_|"cannot exclusively pin actual initialized DRBD extent")?;
    let metadata=file.metadata().map_err(|_|"DRBD read FD metadata")?;let mut size=0u64;
    if !metadata.file_type().is_block_device() || metadata.rdev()!=libc::makedev(147,plan.minor as u32)
        || unsafe{libc::ioctl(file.as_raw_fd(),0x80081272u32 as _,&mut size)}!=0 || size!=bytes {
        return Err("actual exposed initialized extent identity/geometry changed".into());
    }
    let mut buffer=AlignedReadBuffer::new()?;let mut at=0u64;let mut sha=Sha256::new();
    while at<bytes {let length=(bytes-at).min(buffer.layout.size() as u64) as usize;
        permit.before_read(at,length as u64)?;
        file.read_exact(&mut buffer.bytes_mut()[..length]).map_err(|_|"short/failed actual extent read; UNKNOWN")?;
        permit.checkpoint()?;sha.update(&buffer.bytes_mut()[..length]);at+=length as u64;
    }
    let mut after=0u64;if unsafe{libc::ioctl(file.as_raw_fd(),0x80081272u32 as _,&mut after)}!=0 || after!=bytes {
        return Err("actual extent size changed across independent read".into());
    }permit.checkpoint()?;Ok(format!("{:x}",sha.finalize()))
}
#[cfg(not(target_os="linux"))]
fn exposed_hash(_: &Plan,_:&ExpectedAttachScope,_:&VerifiedAttachPhase)->Result<String,String>{Err("actual direct reads require Linux".into())}

pub(in crate::storage_driver) fn execute(cfg:&Config,plan:&Plan,permit:&VerifiedAttachPhase)->Result<WorkerObservation,String> {
    if !cfg!(target_os="linux") || unsafe{libc::geteuid()}!=0 {return Err("actual attachment requires Linux root".into());}
    let scope=permit.scope();check_inputs(cfg,plan,scope)?;permit.checkpoint()?;
    let fact=scope.generation.virgin_replicas.iter().find(|f|f.node_uid==cfg.node_uid).ok_or("committed replica absent")?;
    let (dir,lock,pool,allocation,lv)=if let Some(inventory)=permit.owned_inventory(){
        lvm::owned_inventory::prepared_context_owned(inventory,cfg,&plan.volume_uid)?
    }else{lvm::prepared_context_readonly(cfg,&plan.volume_uid)?};
    local_initial_lineage(&dir,plan,scope)?;
    let record=load(&dir,plan)?.ok_or("physical replica journal absent")?;
    if record.lv_uuid!=fact.lv_uuid || record.allocation_nonce!=fact.allocation_nonce
        || record.device_uuid.as_ref()!=Some(&fact.drbd_device_uuid) || lv.uuid!=fact.lv_uuid
        || allocation.allocation_nonce!=fact.allocation_nonce || allocation.request.operation_uid!=scope.generation.prepare_operation_uid
        || allocation.request.capacity_bytes!=fact.requested_bytes || pool.boot_id!=scope.phase_boot.as_str() {
        return Err("actual backing incarnation/birth lineage/current boot changed".into());
    }
    let (mut record,filename)=begin(&dir,scope,permit.step())?;
    let mut output=WorkerObservation {version:1,scope_sha256:scope_digest(scope)?,step:permit.step(),phase:None,anchor:None};
    let mut observation=AttachPhaseObservation {version:1,phase:scope.phase,scope_sha256:scope_digest(scope)?,node_uid:cfg.node_uid.clone(),
        boot:scope.phase_boot.clone(),raw_kernel:serde_json::Value::Null,exposed_data_sha256:None,mounted:None,evidence_sha256:"0".repeat(64)};
    if permit.step()==AttachNativeStep::PublicationAnchor {
        let mut anchor=anchor::AnchorProbe::empty();
        if let Some(reference)=permit.existing_anchor(){anchor.observe_inherited_existing(permit,reference)?;}
        else{anchor.observe_within(permit.deadline())?;anchor.bootstrap(permit)?;}
        output.anchor=Some(anchor.completed()?);
    } else {
        match scope.phase {
            AttachPhase::ActivateReplica=>{
                if load(&dir,plan)?.is_none_or(|r|r.stage!=Stage::Offline) || status(plan)?.is_some() {
                    return Err("first attach requires real completed offline replica; no adoption/replay".into());
                }
                verify_superblock(cfg,plan,&lv,&fact.drbd_device_uuid)?;
                let (_,current)=metadata(cfg,plan)?;
                let historical=scope.initial_lineage.offline.iter().find(|o|o.replica.node_uid==cfg.node_uid).ok_or("offline node missing")?;
                if current!=historical.drbd_current_uuid {return Err("actual offline generation UUID differs from committed initialized history".into());}
                drop(lock);permit.checkpoint()?;
                if permit.owned_inventory().is_some(){super::super::super::initialized_activation::activate(cfg,plan,permit)?;}
                else{run(cfg,plan,Mode::Online)?;}
                let (_d,_l,_p,a,v)=if let Some(inventory)=permit.owned_inventory(){
                    lvm::owned_inventory::prepared_context_owned(inventory,cfg,&plan.volume_uid)?
                }else{lvm::prepared_context_readonly(cfg,&plan.volume_uid)?};
                online(cfg,plan,&a,&v,permit)?;
                observation.raw_kernel=status(plan)?.ok_or("activation returned without actual resource")?;
                secondary(cfg,plan,fact.requested_bytes,&observation.raw_kernel)?;
            },
            AttachPhase::ObserveSynchronized=>{
                observation.raw_kernel=wait_synchronized(cfg,plan,&allocation,&lv,permit,None)?;
                filesystem_probe(&format!("/dev/drbd{}",plan.minor),Some(&scope.generation.filesystem_uuid))?;
                let data=exposed_hash(plan,scope,permit)?;
                if data!=scope.initial_lineage.data_sha256(){return Err("fresh independent initialized data hash differs before first writer".into());}
                observation.exposed_data_sha256=Some(data);
                observation.raw_kernel=wait_synchronized(cfg,plan,&allocation,&lv,permit,None)?;
            },
            AttachPhase::PromoteTarget=>{
                wait_synchronized(cfg,plan,&allocation,&lv,permit,None)?;
                adm(cfg,plan,"primary")?;
                observation.raw_kernel=status(plan)?.ok_or("promotion result UNKNOWN")?;
                sync_roles(cfg,plan,fact.requested_bytes,&observation.raw_kernel,Some(&cfg.node_uid))?;
            },
            AttachPhase::Mount=>{
                if permit.step()!=AttachNativeStep::FilesystemMount{return Err("invalid closed Mount substep".into());}
                wait_synchronized(cfg,plan,&allocation,&lv,permit,Some(&cfg.node_uid))?;
                filesystem_probe(&format!("/dev/drbd{}",plan.minor),Some(&scope.generation.filesystem_uuid))?;
                observation.mounted=Some(mount_exact(plan,permit)?);
                observation.raw_kernel=wait_synchronized(cfg,plan,&allocation,&lv,permit,Some(&cfg.node_uid))?;
            },
            AttachPhase::ObserveMounted=>{
                observation.raw_kernel=wait_synchronized(cfg,plan,&allocation,&lv,permit,Some(&cfg.node_uid))?;
                #[cfg(target_os="linux")]
                {let ns=open_current_namespace()?;let fd=open_private_target(&mount_path(&scope.mount_ref))?;
                    observation.mounted=Some(observe_mounted(&fd,&mount_path(&scope.mount_ref),fd_identity(&ns)?,147,plan.minor as u32,&scope.generation.filesystem_uuid)?);}
                #[cfg(not(target_os="linux"))]
                {return Err("actual mounted observation requires Linux".into());}
            },
        }
        observation.evidence_sha256=observation.digest()?;observation.validate(scope)?;
        output.phase=Some(observation);
    }
    permit.checkpoint()?;output.validate(scope,permit.step())?;
    record.complete=true;record.evidence_sha256=Some(digest(&output)?);
    dir.write_new(&filename.replace("-intent.json","-complete.json"),&serde_json::to_vec(&(record,&output)).map_err(|_|"attach completion encoding")?)?;
    permit.checkpoint()?;Ok(output)
}

#[cfg(not(target_os="linux"))]
fn mount_exact(_: &Plan,_:&VerifiedAttachPhase)->Result<MountObservation,String>{Err("actual mount requires Linux".into())}
#[cfg(target_os="linux")]
fn mount_exact(plan:&Plan,permit:&VerifiedAttachPhase)->Result<MountObservation,String> {
    let scope=permit.scope();let target=mount_path(&scope.mount_ref);
    let publication=permit.publication().ok_or("actual Watch pre-mount publication FD references absent")?;
    let mut held=ParentFdProbe::empty();held.capture(scope,permit.deadline())?;
    let before=held.recheck(scope,permit.deadline())?;
    let initial=open_private_target(&target)?;let initial_identity=observe_parent_kernel(&initial)?;
    if before.parent!=publication.parent || (initial_identity.device,initial_identity.inode,initial_identity.mount_id)
        !=(publication.target_device,publication.target_inode,publication.target_mount_id)
        || (before.namespace_device,before.namespace_inode)!=(publication.namespace_device,publication.namespace_inode) {
        return Err("actual helper parent/empty target differs from Watch's held pre-effect references".into());
    }
    let device=format!("/dev/drbd{}",plan.minor);let source=open_exact_block(&device)?;
    use std::os::unix::fs::FileTypeExt;
    let block=source.metadata().map_err(|_|"actual mount source FD metadata")?;
    if !block.file_type().is_block_device() || block.rdev()!=libc::makedev(147,plan.minor as u32){return Err("actual mount source is not initialized pinned DRBD device".into());}
    use std::os::fd::AsRawFd;
    // A direct kernel block lookup through this held FD is not a Docker bind
    // source/publication path. Docker will receive only a separately verified
    // fixed published directory after its own future consumer admission.
    let source_name=std::ffi::CString::new(format!("/proc/self/fd/{}",source.as_raw_fd())).unwrap();
    let target_name=std::ffi::CString::new(target.as_str()).unwrap();
    held.recheck(scope,permit.deadline())?;
    permit.before_mount("mount-ext4",&(publication,block.rdev()))?;
    // No repair/format/force/discard/remount/recursive/lazy flags. The source
    // block FD and exact fixed target-parent FDs stay alive over the syscall.
    if unsafe{libc::mount(source_name.as_ptr(),target_name.as_ptr(),c"ext4".as_ptr(),libc::MS_NODEV|libc::MS_NOSUID,std::ptr::null())}!=0 {
        return Err("ext4 mount result UNKNOWN; retain all actual owners".into());
    }
    // Reopen the NEW mount, never treat the old pre-mount directory FD as it.
    let mounted=open_private_target(&target)?;let ns=open_current_namespace()?;
    let first=observe_mounted(&mounted,&target,fd_identity(&ns)?,147,plan.minor as u32,&scope.generation.filesystem_uuid)?;
    permit.before_mount("make-private",&first)?;
    if unsafe{libc::mount(std::ptr::null(),target_name.as_ptr(),std::ptr::null(),libc::MS_PRIVATE,std::ptr::null())}!=0 {
        return Err("new exact mount MakePrivate result UNKNOWN; no recursive fallback".into());
    }
    let after=open_private_target(&target)?;
    let observed=observe_mounted(&after,&target,fd_identity(&ns)?,147,plan.minor as u32,&scope.generation.filesystem_uuid)?;
    if observed.mount_id!=first.mount_id {return Err("new target mount replaced during privatization".into());}
    permit.checkpoint()?;Ok(observed)
}
