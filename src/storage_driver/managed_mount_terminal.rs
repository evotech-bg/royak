//! Closed terminal physical DATA and same-original Watch descriptor lifetime.
//! No wire value constructs a parent, resource reservation, drain or retired lease.
use super::*;
use crate::storage_boot::BootId;
use crate::storage_driver::dispatcher::{VerifiedLocalBoundary,attachment::terminal::VerifiedTerminalPhase};
use crate::storage_driver::native_runtime::mount::consumer::terminal::{
    VerifiedTerminalNodeParent,TerminalNativeStep,TerminalBoundary};
use std::os::fd::{AsRawFd,IntoRawFd};
use std::os::unix::fs::{FileTypeExt,OpenOptionsExt};
use std::collections::BTreeMap;
#[path="managed_mount_terminal_origin.rs"]
pub(in crate::storage_driver) mod origin;
fn valid_hash(value:&str)->bool{value.len()==64&&value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
fn strict_dm_leaf(path:&std::path::Path)->bool{
    path.parent()==Some(std::path::Path::new("/dev"))&&path.file_name().and_then(|v|v.to_str())
        .and_then(|v|v.strip_prefix("dm-")).is_some_and(|v|!v.is_empty()&&v.bytes().all(|b|b.is_ascii_digit()))
}
#[cfg(target_os="linux")]
pub(in crate::storage_driver) fn capture_watch_namespace()->Result<File,String>{open_current_namespace()}
#[cfg(not(target_os="linux"))]
pub(in crate::storage_driver) fn capture_watch_namespace()->Result<File,String>{Err("terminal namespace observation requires Linux".into())}
pub(in crate::storage_driver) fn namespace_identity(file:&File)->Result<(u64,u64),String>{
    let m=file.metadata().map_err(|_|"terminal actual namespace descriptor unavailable")?;Ok((m.dev(),m.ino()))
}

#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TerminalResourceObservation {
    pub(crate) node_uid:Uid,pub(crate) boot:BootId,pub(crate) volume_uid:Uid,pub(crate) pool_uid:Uid,
    pub(crate) dispatch_identity:(u64,u64),pub(crate) pool_identity:(u64,u64),
    pub(crate) existing_dispatch_entries:usize,pub(crate) existing_pool_entries:usize,
    pub(crate) existing_attempts:usize,pub(crate) reserved_attempts:usize,
    pub(crate) reserved_dispatch_entries:usize,pub(crate) reserved_pool_entries:usize,
    pub(crate) atomic_temp_peak:usize,
}

fn is_writer(scope:&ExpectedAttachScope)->bool{scope.phase_node_uid==*scope.mount_ref.node_uid()}
/// Mandatory LOWER BOUND of source-fixed records, not a liveness maximum.
/// Common Start/entry/final/Complete=4 per helper; writer3/follower2 helpers.
/// Read is unchanged <=1MiB, with fresh preRead+postIdentity on EACH chunk.
pub(crate) fn mandatory_admissions(exposed_bytes:u64,writer:bool)->Result<usize,String>{
    if exposed_bytes==0||exposed_bytes%4096!=0{return Err("terminal extent geometry invalid".into());}
    let chunks=exposed_bytes.checked_add(1024*1024-1).ok_or("terminal read count overflow")?/(1024*1024);
    let read=usize::try_from(chunks).map_err(|_|"terminal read count does not fit platform")?.checked_mul(2).ok_or("terminal read count overflow")?;
    // Source-mandatory Programs: old strict pool inspect4 + kernel_config1
    // per helper. Writer unmount: common4 +6 irreversible pairs12 +8 Programs
    // =24. Observe: common4 +5 context Programs +Observe1 +status1 =11.
    // Offline: common4 +5 context Programs +down pair2 +5 Programs +closeRead
    // pair2 =18. Additional partial-FD closes/remote reports/rechecks/waits ADD
    // records; this remains a conservative LOWER bound, never a positive grant.
    // Final Detached-confirmed retirement explicitly closes primary+safety+
    // per-volume Files: three additional before/result pairs6 on SAME chain.
    // Two fresh provenance observations around EACH of Before/AfterUnmount.
    read.checked_add(if writer{63}else{35}).ok_or_else(||"terminal mandatory admission count overflow".into())
}
fn step_sequence(writer:bool,index:usize)->Option<TerminalNativeStep>{
    use TerminalNativeStep::*;
    if writer{[UnmountAndDemote,ObserveSecondarySynchronized,OfflineAndObserve].get(index).copied()}
    else{[ObserveSecondarySynchronized,OfflineAndObserve].get(index).copied()}
}
pub(in crate::storage_driver) fn expected_step(writer:bool,index:usize)->Option<TerminalNativeStep>{step_sequence(writer,index)}
fn terminal_local_secondary(cfg:&Config,plan:&Plan,bytes:u64,state:&Value)->Result<(),String>{
    secondary(cfg,plan,bytes,state)?;
    if state["suspended"]!=false||state["force-io-failures"]!=false
        ||state["devices"][0]["disk-state"]!="UpToDate"||state["devices"][0]["client"]!=false
        ||state["devices"][0]["upper-pending"]!=0||state["devices"][0]["lower-pending"]!=0
        ||state["connections"].as_array().is_none_or(|peers|peers.iter().any(|p|
            !matches!(p["peer-role"].as_str(),Some("Secondary"|"Unknown")))){
        return Err("terminal down requires exact unheld local Secondary UpToDate/no writer/pending IO".into());}
    Ok(())
}
fn terminal_all_secondary(cfg:&Config,plan:&Plan,bytes:u64,state:&Value)->Result<(),String>{
    terminal_local_secondary(cfg,plan,bytes,state)?;
    if state["devices"][0]["quorum"]!=true{return Err("terminal all-three secondary synchronization lacks quorum".into());}
    for peer in state["connections"].as_array().ok_or("terminal peer set absent")?{
        let devices=peer["peer_devices"].as_array().filter(|v|v.len()==1).ok_or("terminal peer device set ambiguous")?;
        let d=&devices[0];
        if peer["connection-state"]!="Connected"||peer["peer-role"]!="Secondary"
            ||peer["ap-in-flight"]!=0||peer["rs-in-flight"]!=0||peer["paths"][0]["established"]!=true
            ||d["volume"]!=0||d["replication-state"]!="Established"||d["peer-disk-state"]!="UpToDate"
            ||d["peer-client"]!=false||d["resync-suspended"]!="no"||d["out-of-sync"]!=0||d["pending"]!=0||d["unacked"]!=0{
            return Err("terminal all-three exact copies not Secondary/UpToDate/synchronized".into());}
    }Ok(())
}
fn observe_all_secondary(cfg:&Config,plan:&Plan,permit:&VerifiedTerminalPhase)->Result<Value,String>{
    loop{
        permit.begin_effect(TerminalBoundary::ObserveSecondary,&"all-three-independent-secondary")?;
        let state=status(plan)?.ok_or("terminal actual replica disappeared")?;
        terminal_local_secondary(cfg,plan,permit.scope().generation.virgin_replicas[0].requested_bytes,&state)?;
        if terminal_all_secondary(cfg,plan,permit.scope().generation.virgin_replicas[0].requested_bytes,&state).is_ok(){return Ok(state);}
        permit.checkpoint()?;
        // Existing finite read-only100ms cadence; no effect or offer retry.
        std::thread::sleep(Duration::from_millis(100));
    }
}
fn close_helper_file(slot:&mut Option<File>,permit:&VerifiedTerminalPhase,kind:TerminalBoundary,
    closes:&mut Vec<CloseTombstone>)->Result<(),String>{
    let identity=DescriptorIdentity::of(slot.as_ref().ok_or("helper original close slot missing")?)?;
    let receipt=permit.begin_effect(kind,&("helper-reference",&identity))?;
    closes.push(CloseTombstone{identity,outcome:CloseOutcome::Prepared,
        #[cfg(test)] fault_after_actual_close:false}); // root before File.take
    let tombstone=closes.last_mut().unwrap();
    let result=consume_close(slot,tombstone);
    let recorded=permit.finish_effect(receipt,kind,tombstone);
    result?;recorded
}
#[cfg(target_os="linux")]
fn offline_hash(cfg:&Config,plan:&Plan,lv:&lvm::Lv,permit:&VerifiedTerminalPhase,
    closes:&mut Vec<CloseTombstone>)->Result<String,String>{
    use std::io::Read;
    lvm::verify_unheld(lv)?;
    let bytes=permit.scope().generation.virgin_replicas[0].exposed_bytes;
    let logical=format!("/dev/{}/rkvol_{}",cfg.vg_name,plan.volume_uid.as_str());
    let path=std::fs::canonicalize(&logical).map_err(|_|"terminal logical LV target disappeared")?;
    if !strict_dm_leaf(&path){return Err("terminal LV must resolve to an exact /dev/dm-<digits> leaf".into());}
    let mut file=Some(std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_DIRECT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC)
        .open(&path).map_err(|_|"actual terminal offline backing descriptor unavailable")?);
    let metadata=file.as_ref().unwrap().metadata().map_err(|_|"actual terminal backing descriptor metadata")?;
    let mut observed_size=0u64;
    if !metadata.file_type().is_block_device()||metadata.rdev()!=libc::makedev(
        u32::try_from(lv.major).map_err(|_|"terminal LV major overflow")?,u32::try_from(lv.minor).map_err(|_|"terminal LV minor overflow")?)
        ||unsafe{libc::ioctl(file.as_ref().unwrap().as_raw_fd(),0x80081272u32 as _,&mut observed_size)}!=0
        ||observed_size!=lv.bytes||bytes==0||bytes>lv.bytes||bytes%4096!=0{
        return Err("actual terminal offline backing identity/geometry changed".into());}
    let mut buffer=AlignedReadBuffer::new()?;let mut at=0u64;let mut data=Sha256::new();
    while at<bytes{
        let length=(bytes-at).min(buffer.layout.size()as u64)as usize;
        permit.before_read(at,length as u64)?;
        file.as_mut().unwrap().read_exact(&mut buffer.bytes_mut()[..length]).map_err(|_|"actual terminal full-extent read failed; UNKNOWN")?;
        permit.checkpoint()?;
        if at==0{
            let raw=&buffer.bytes_mut()[..length];
            if raw.len()<1144||raw[1080..1082]!=[0x53,0xef]||format_uuid(&raw[1128..1144])?!=permit.scope().generation.filesystem_uuid{
                return Err("actual post-application offline ext4 UUID differs from original initialized dataset".into());}
        }
        data.update(&buffer.bytes_mut()[..length]);at+=length as u64;
    }
    let mut after=0u64;
    if unsafe{libc::ioctl(file.as_ref().unwrap().as_raw_fd(),0x80081272u32 as _,&mut after)}!=0||after!=observed_size{
        return Err("actual terminal backing geometry changed across full read".into());}
    close_helper_file(&mut file,permit,TerminalBoundary::CloseRead,closes)?;
    Ok(format!("{:x}",data.finalize()))
}
#[cfg(not(target_os="linux"))]
fn offline_hash(_: &Config,_:&Plan,_:&lvm::Lv,_:&VerifiedTerminalPhase,_:&mut Vec<CloseTombstone>)->Result<String,String>{
    Err("actual terminal offline direct read requires Linux".into())
}
#[cfg(target_os="linux")]
fn unmount_and_demote(cfg:&Config,plan:&Plan,permit:&VerifiedTerminalPhase,closes:&mut Vec<CloseTombstone>)->Result<Value,String>{
    let publication=permit.publication().ok_or("writer terminal has no original publication facts")?;
    let scope=permit.scope();let target=mount_path(&scope.mount_ref);
    let namespace=open_current_namespace()?;let namespace_identity=fd_identity(&namespace)?;
    if namespace_identity!=(publication.publication.namespace_device,publication.publication.namespace_inode){
        return Err("terminal helper is not original Watch mount namespace".into());}
    let parent=open_private_target(&parent_path(&target)?)?;
    if observe_parent_kernel(&parent)?!=publication.publication.parent{return Err("terminal original fixed target parent changed".into());}
    let mut mounted=Some(open_private_target(&target)?);
    let actual=observe_mounted(mounted.as_ref().unwrap(),&target,namespace_identity,publication.mounted.device_major,
        publication.mounted.device_minor,&scope.generation.filesystem_uuid)?;
    if actual!=publication.mounted{return Err("terminal actual mounted incarnation differs".into());}
    let flush=permit.begin_effect(TerminalBoundary::FlushMount,&actual)?;
    let syncfs=unsafe{libc::syncfs(mounted.as_ref().unwrap().as_raw_fd())};
    let fsync=if syncfs==0{mounted.as_ref().unwrap().sync_all().map_err(|e|e.raw_os_error())}else{Err(std::io::Error::last_os_error().raw_os_error())};
    permit.finish_effect(flush,TerminalBoundary::FlushMount,&(syncfs,fsync.as_ref().err().copied()))?;
    fsync.map_err(|_|"terminal syncfs/fsync result UNKNOWN")?;
    for reference in publication.closes.iter().filter(|r|r.slot.mounted()){permit.close_watch(reference)?;}
    close_helper_file(&mut mounted,permit,TerminalBoundary::CloseMounted,closes)?;
    let context=permit.begin_reference_census(anchor::TerminalCensusPoint::BeforeUnmount)?;
    let before=anchor::terminal_reference_census(publication.block(),Some(&actual),anchor::TerminalCensusPoint::BeforeUnmount,permit.deadline(),Some(&context))?;
    context.finish(&before)?;
    if observe_parent_kernel(&parent)?!=publication.publication.parent{return Err("terminal fixed parent changed before umount".into());}
    let unmount=permit.begin_effect(TerminalBoundary::Unmount,&(&actual,&before))?;
    let name=std::ffi::CString::new(target.as_str()).map_err(|_|"terminal fixed target malformed")?;
    let result=unsafe{libc::umount2(name.as_ptr(),libc::UMOUNT_NOFOLLOW)};
    let errno=if result==0{None}else{std::io::Error::last_os_error().raw_os_error()};
    permit.finish_effect(unmount,TerminalBoundary::Unmount,&(result,errno))?;
    if result!=0{return Err("true non-force terminal umount UNKNOWN; no retry/lazy detach".into());}
    let uncovered=open_private_target(&target)?;let underlay=observe_parent_kernel(&uncovered)?;
    if(underlay.device,underlay.inode,underlay.mount_id)!=(publication.publication.target_device,
        publication.publication.target_inode,publication.publication.target_mount_id){
        return Err("true umount did not uncover SAME original target".into());}
    let context=permit.begin_reference_census(anchor::TerminalCensusPoint::AfterUnmount)?;
    let after=anchor::terminal_reference_census(publication.block(),None,anchor::TerminalCensusPoint::AfterUnmount,permit.deadline(),Some(&context))?;
    context.finish(&after)?;
    for reference in publication.closes.iter().filter(|r|!r.slot.mounted()){permit.close_watch(reference)?;}
    // Deliberately AFTER true unmount: old strict inspect's recursive mounted
    // guard is NOT relaxed or bypassed for cold/ordinary allocation. Before
    // this point the genuine parent + SAME installed FD/plan own the target.
    let(_context,_pool_lock,pool,allocation,lv)=lvm::prepared_context_readonly(cfg,&scope.owner.volume_uid)?;
    let fact=scope.generation.virgin_replicas.iter().find(|f|f.node_uid==cfg.node_uid).ok_or("terminal writer generation target absent")?;
    if pool.boot_id!=scope.phase_boot.as_str()||lv.uuid!=fact.lv_uuid||allocation.allocation_nonce!=fact.allocation_nonce
        ||allocation.request.operation_uid!=scope.generation.prepare_operation_uid{
        return Err("terminal actual pool/LV changed after true unmount; retain stage UNKNOWN".into());}
    kernel_config(cfg,plan,&lv)?;
    let before_demote=status(plan)?.ok_or("writer terminal resource absent before demote")?;
    if before_demote["role"]!="Primary"||before_demote["devices"][0]["open"]!=false{
        return Err("terminal demote requires same actual closed original Primary".into());}
    let demote=permit.begin_effect(TerminalBoundary::Demote,&(&scope.owner.volume_uid,&scope.generation.uid))?;
    let result=adm(cfg,plan,"secondary");
    let result_hash=result.as_ref().map(|raw|hash(raw)).map_err(|e|hash(e.as_bytes()));
    permit.finish_effect(demote,TerminalBoundary::Demote,&result_hash)?;
    result?;
    let secondary_state=status(plan)?.ok_or("writer terminal demote result absent")?;
    terminal_local_secondary(cfg,plan,scope.generation.virgin_replicas[0].requested_bytes,&secondary_state)?;
    Ok(serde_json::json!({"kind":"actual-terminal-unmounted-and-demoted-v1","before_reference_census":before,
        "after_reference_census":after,"underlay":underlay,"state":secondary_state,"helper_close_tombstones":closes}))
}
#[cfg(not(target_os="linux"))]
fn unmount_and_demote(_: &Config,_:&Plan,_:&VerifiedTerminalPhase,_:&mut Vec<CloseTombstone>)->Result<Value,String>{Err("actual terminal unmount requires Linux".into())}

pub(in crate::storage_driver) fn execute(cfg:&Config,plan:&Plan,permit:&VerifiedTerminalPhase)->Result<TerminalPhysicalObservation,String>{
    if !cfg!(target_os="linux")||unsafe{libc::geteuid()}!=0{return Err("actual terminal physical producer requires Linux root".into());}
    permit.checkpoint()?;phases::check_inputs(cfg,plan,permit.scope())?;
    let scope=permit.scope();let fact=scope.generation.virgin_replicas.iter().find(|f|f.node_uid==cfg.node_uid).ok_or("terminal actual replica absent")?;
    let context=if permit.step()==TerminalNativeStep::UnmountAndDemote{None}else{
        Some(lvm::prepared_context_readonly(cfg,&scope.owner.volume_uid)?)};
    let dir=Dir::open(&cfg.journal_path(),false)?;
    permit.verify_pool_directory(&dir)?;
    let replica=load(&dir,plan)?.ok_or("terminal original protected replica plan absent")?;
    if replica.lv_uuid!=fact.lv_uuid
        ||replica.allocation_nonce!=fact.allocation_nonce||replica.device_uuid.as_ref()!=Some(&fact.drbd_device_uuid)
        {
        return Err("terminal original prepared allocation/device/current boot differs".into());}
    if let Some((_,_,pool,allocation,lv))=&context{
        if pool.boot_id!=scope.phase_boot.as_str()||lv.uuid!=fact.lv_uuid||allocation.allocation_nonce!=fact.allocation_nonce
            ||allocation.request.operation_uid!=scope.generation.prepare_operation_uid{
            return Err("terminal original pool/allocation generation changed".into());}
        kernel_config(cfg,plan,lv)?;
    }
    let intent=format!("terminal-{}-intent.json",permit.identity().attempt_uid.as_str());
    let complete=format!("terminal-{}-complete.json",permit.identity().attempt_uid.as_str());
    let value=serde_json::json!({"version":1,"operation":permit.operation(),"identity":permit.identity(),
        "scope":scope,"step":permit.step(),"disposition":"UNKNOWN_BEFORE_PHYSICAL_TERMINAL","restart_authority":false});
    dir.write_new(&intent,&serde_json::to_vec(&value).map_err(|_|"terminal pool intent encoding failed")?)?;
    let mut closes=Vec::new();let mut data=None;
    let raw=match permit.step(){
        TerminalNativeStep::UnmountAndDemote=>unmount_and_demote(cfg,plan,permit,&mut closes)?,
        TerminalNativeStep::ObserveSecondarySynchronized=>observe_all_secondary(cfg,plan,permit)?,
        TerminalNativeStep::OfflineAndObserve=>{
            let lv=&context.as_ref().ok_or("terminal offline original prepared context absent")?.4;
            let before=status(plan)?.ok_or("actual terminal local replica already down; no adoption/retry")?;
            // This deliberately does NOT require peers Connected after earlier
            // sequential downs. Genuine parent proved all3 Secondary first.
            terminal_local_secondary(cfg,plan,fact.requested_bytes,&before)?;
            let census=anchor::terminal_reference_census((147,plan.minor as u32),None,anchor::TerminalCensusPoint::BeforeOffline,permit.deadline(),None)?;
            let offline=permit.begin_effect(TerminalBoundary::Offline,&(&scope.owner.volume_uid,&scope.generation.uid))?;
            let result=adm(cfg,plan,"down");let outcome=result.as_ref().map(|raw|hash(raw)).map_err(|e|hash(e.as_bytes()));
            permit.finish_effect(offline,TerminalBoundary::Offline,&outcome)?;result?;
            if status(plan)?.is_some(){return Err("actual terminal down still exposes resource; no forced retry".into());}
            lvm::verify_unheld(lv)?;verify_superblock(cfg,plan,lv,&fact.drbd_device_uuid)?;
            let(device,current)=metadata(cfg,plan)?;
            if device!=fact.drbd_device_uuid{return Err("terminal offline DRBD device incarnation changed".into());}
            data=Some(offline_hash(cfg,plan,lv,permit,&mut closes)?);
            let after=anchor::terminal_reference_census((147,plan.minor as u32),None,anchor::TerminalCensusPoint::AfterOffline,permit.deadline(),None)?;
            serde_json::json!({"kind":"actual-terminal-offline-observation-v1","before":before,
                "before_reference_census":census,"after_reference_census":after,
                "device_uuid":device,"current_uuid":current,"lv_uuid":lv.uuid,"exposed_bytes":fact.exposed_bytes,
                "read_descriptors_closed":closes})
        }
    };
    permit.checkpoint()?;
    let disposition=if is_writer(scope){TerminalReferenceDisposition::ClosedKnown}else{TerminalReferenceDisposition::NotOwnedOnSecondary};
    let observation=TerminalPhysicalObservation{version:1,terminal_operation_uid:permit.operation().clone(),
        volume_uid:scope.owner.volume_uid.clone(),data_generation_uid:scope.generation.uid.clone(),node_uid:cfg.node_uid.clone(),
        boot:scope.phase_boot.clone(),step:permit.step(),filesystem_uuid:scope.generation.filesystem_uuid.clone(),
        raw_kernel:raw,data_sha256:data,native_effects_sha256:permit.effects_sha256()?,mounted_refs:disposition,block_refs:disposition};
    observation.validate(scope,permit.operation(),permit.step())?;
    dir.write_new(&complete,&serde_json::to_vec(&observation).map_err(|_|"terminal pool completion encoding failed")?)?;
    permit.local_live_after_evidence()?;Ok(observation)
}
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub(crate) enum TerminalReferenceDisposition {RetainedOriginal,ClosedKnown,NotOwnedOnSecondary}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TerminalPhysicalObservation {
    pub(crate) version:u32,pub(crate) terminal_operation_uid:Uid,pub(crate) volume_uid:Uid,
    pub(crate) data_generation_uid:Uid,pub(crate) node_uid:Uid,pub(crate) boot:BootId,
    pub(crate) step:TerminalNativeStep,pub(crate) filesystem_uuid:String,pub(crate) raw_kernel:Value,
    pub(crate) data_sha256:Option<String>,pub(crate) native_effects_sha256:String,
    pub(crate) mounted_refs:TerminalReferenceDisposition,pub(crate) block_refs:TerminalReferenceDisposition,
}
impl TerminalPhysicalObservation {
    pub(crate) fn validate(&self,scope:&ExpectedAttachScope,operation:&Uid,step:TerminalNativeStep)->Result<(),String>{
        if self.version!=1 || self.raw_kernel.is_null() || &self.terminal_operation_uid!=operation || self.volume_uid!=scope.owner.volume_uid
            || self.data_generation_uid!=scope.generation.uid || self.node_uid!=scope.phase_node_uid
            || self.boot!=scope.phase_boot || self.step!=step || self.filesystem_uuid!=scope.generation.filesystem_uuid
            || !valid_hash(&self.native_effects_sha256)
            || self.data_sha256.as_deref().is_some_and(|v|!valid_hash(v))
            || (step==TerminalNativeStep::OfflineAndObserve)!=self.data_sha256.is_some(){
            return Err("terminal actual diagnostic differs from same operation/step/owner/boot/generation".into());
        }
        let writer=scope.phase_node_uid==*scope.mount_ref.node_uid();
        let expected=if writer{TerminalReferenceDisposition::ClosedKnown}else{TerminalReferenceDisposition::NotOwnedOnSecondary};
        if self.mounted_refs!=expected || self.block_refs!=expected {
            return Err("terminal diagnostic invents retained/closed reference disposition".into());
        }
        Ok(())
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub(in crate::storage_driver) enum WatchReference {InstalledMounted,PartialMounted,InstalledBlock,PartialBlock}
impl WatchReference {
    fn mounted(self)->bool{matches!(self,Self::InstalledMounted|Self::PartialMounted)}
    fn key(self)->&'static str{match self{Self::InstalledMounted=>"installed-mounted",Self::PartialMounted=>"partial-mounted",
        Self::InstalledBlock=>"installed-block",Self::PartialBlock=>"partial-block"}}
}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::storage_driver) struct DescriptorIdentity {
    number:i32,device:u64,inode:u64,rdev:u64,mode:u32,mount_id:Option<u64>,
}
impl DescriptorIdentity {
    fn of(file:&File)->Result<Self,String>{
        let m=file.metadata().map_err(|_|"same original terminal descriptor stat unavailable")?;
        #[cfg(target_os="linux")]
        let mount_id=if m.is_dir(){Some(observe_parent_kernel(file)?.mount_id)}else{None};
        #[cfg(not(target_os="linux"))]
        let mount_id=None;
        Ok(Self{number:file.as_raw_fd(),device:m.dev(),inode:m.ino(),rdev:m.rdev(),mode:m.mode(),mount_id})
    }
}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::storage_driver) struct WatchCloseReference {pub(in crate::storage_driver) slot:WatchReference,identity:DescriptorIdentity}
impl WatchCloseReference {
    pub(in crate::storage_driver) fn is_mounted(&self)->bool{self.slot.mounted()}
    pub(in crate::storage_driver) fn number(&self)->i32{self.identity.number}
    pub(in crate::storage_driver) fn matches_observed(&self,number:&str,metadata:&std::fs::Metadata)->bool{
        !self.slot.mounted()&&number.parse::<i32>().ok()==Some(self.identity.number)
            &&metadata.file_type().is_block_device()&&metadata.dev()==self.identity.device&&metadata.ino()==self.identity.inode
            &&metadata.rdev()==self.identity.rdev&&metadata.mode()==self.identity.mode
    }
}
#[derive(Clone,Debug,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::storage_driver) struct TerminalPublication {
    publication:PublicationRef,mounted:MountObservation,
    pub(in crate::storage_driver) closes:Vec<WatchCloseReference>,
}
impl TerminalPublication {
    pub(in crate::storage_driver) fn mount_id(&self)->u64{self.mounted.mount_id}
    pub(in crate::storage_driver) fn block(&self)->(u32,u32){(self.mounted.device_major,self.mounted.device_minor)}
}
#[derive(Clone,Debug,Serialize)]
enum CloseOutcome {Prepared,ConsumedUnknown,ClosedKnown,ErrorAfterConsume{errno:Option<i32>}}
#[derive(Clone,Debug,Serialize)]
struct CloseTombstone {identity:DescriptorIdentity,outcome:CloseOutcome,
    #[cfg(test)] #[serde(skip)] fault_after_actual_close:bool}
/// Root this in the existing probe BEFORE taking the File. Error-after-close
/// never implies the old number remains owned and is NEVER retried/reopened.
fn consume_close(slot:&mut Option<File>,tombstone:&mut CloseTombstone)->Result<(),String>{
    if !matches!(tombstone.outcome,CloseOutcome::Prepared){return Err("close slot already irreversibly consumed".into());}
    let file=slot.as_ref().ok_or("original close slot missing; absence is not closure")?;
    if DescriptorIdentity::of(file)?!=tombstone.identity{return Err("same original descriptor changed before close".into());}
    tombstone.outcome=CloseOutcome::ConsumedUnknown;
    let raw=slot.take().expect("checked original close slot").into_raw_fd();
    let result=unsafe{libc::close(raw)};
    // Test-only reported failure AFTER closing the owned test descriptor.
    // No production close retry, raw-FD factory, or authority path is added.
    #[cfg(test)] let result=if tombstone.fault_after_actual_close{-1}else{result};
    let errno=if result==0{None}else{std::io::Error::last_os_error().raw_os_error()};
    tombstone.outcome=if result==0{CloseOutcome::ClosedKnown}else{CloseOutcome::ErrorAfterConsume{errno}};
    if result!=0{return Err("descriptor close result UNKNOWN after consume; no retry".into());}Ok(())
}
fn close_reporting_unknown(actual:&Result<(),String>,recorded:&Result<(),String>)->bool{
    actual.is_err()||recorded.is_err()
}
pub(super) struct TerminalWatchState {
    operation:Uid,publication:Option<TerminalPublication>,closes:BTreeMap<String,CloseTombstone>,
    underlay_after:Option<File>,unmounted:bool,unknown:bool,
    census:ReferenceCensusProgress,
    census_pending:Option<std::sync::Arc<PendingReferenceCensus>>,
}
#[derive(Clone,Debug,PartialEq,Eq)]
enum ReferenceCensusProgress {None,BeforeStarted(String),BeforeComplete,AfterStarted(String),AfterComplete}
#[derive(Clone,Debug,PartialEq,Eq)]
struct ReferenceCensusKey {
    operation:Uid,native:crate::storage_driver::live_authority::JobIdentity,
    point:anchor::TerminalCensusPoint,begin:Option<String>,request:String,
    prior:ReferenceCensusProgress,unmounted:bool,references:Vec<WatchCloseReference>,
    publication_sha256:String,closes_sha256:String,
}
struct PendingReferenceCensus {
    parent:std::sync::Arc<VerifiedTerminalNodeParent>,key:ReferenceCensusKey,next:ReferenceCensusProgress,
}
/// Prepared local reservation only. Same probe retains its actual Arc even
/// if this move-only value or the caller disappears. No grant/raw constructor.
pub(in crate::storage_driver) struct PreparedReferenceCensus {pending:std::sync::Arc<PendingReferenceCensus>}
fn same_reference_census_key(expected:&ReferenceCensusKey,current:&ReferenceCensusKey)->Result<(),String>{
    if expected!=current{return Err("pending census state/reference incarnation changed across authorization".into());}Ok(())
}
fn reference_census_next(current:&ReferenceCensusProgress,point:anchor::TerminalCensusPoint,begin:Option<&str>,
    request:&str,unmounted:bool)->Result<ReferenceCensusProgress,String>{
    use anchor::TerminalCensusPoint::*;
    match(point,begin,current){
        (BeforeUnmount,None,ReferenceCensusProgress::None)if !unmounted=>Ok(ReferenceCensusProgress::BeforeStarted(request.into())),
        (BeforeUnmount,Some(key),ReferenceCensusProgress::BeforeStarted(old))if key==old&&!unmounted=>Ok(ReferenceCensusProgress::BeforeComplete),
        (AfterUnmount,None,ReferenceCensusProgress::BeforeComplete)if unmounted=>Ok(ReferenceCensusProgress::AfterStarted(request.into())),
        (AfterUnmount,Some(key),ReferenceCensusProgress::AfterStarted(old))if key==old&&unmounted=>Ok(ReferenceCensusProgress::AfterComplete),
        _=>Err("reference census skipped/repeated/unknown/out of order".into())
    }
}
impl WatchMountProbe {
    /// The daemon capability survives closing mounted/block descriptors. This
    /// is authenticated transport ONLY, never READY or a terminal signal grant.
    pub(in crate::storage_driver) fn terminal_daemon_connection(&self,deadline:Instant)
        ->Result<crate::docker::ManagedConsumerConnection,String>{
        self.installed.as_ref().ok_or("terminal original installed daemon capability absent")?
            .consumer_connection(deadline)
    }
    /// Protected original facts only; no fresh terminal permission is minted.
    pub(in crate::storage_driver) fn terminal_publication(&self,scope:&ExpectedAttachScope)->Result<Option<TerminalPublication>,String>{
        if let Some(state)=&self.terminal{
            if state.unknown{return Err("original terminal Watch state UNKNOWN".into());}
            return Ok(state.publication.clone());
        }
        if scope.phase_node_uid!=*scope.mount_ref.node_uid(){
            if self.installed.is_some()||self.mounted.is_some()||self.block.is_some(){return Err("secondary unexpectedly owns writer descriptor".into());}
            return Ok(None);
        }
        let installed=self.installed.as_ref().ok_or("terminal writer lacks actual installed original mount")?;
        installed.require_original_watch_files()?;
        if installed.scope.mount_ref!=scope.mount_ref || installed.scope.owner!=scope.owner
            || installed.scope.generation!=scope.generation || self.target_before.is_none()
            || self.publication_directories.len()!=3 || self.parent.parent_held.is_none() || self.parent.namespace_held.is_none(){
            return Err("terminal original underlay/parent/namespace/mount lineage incomplete".into());
        }
        let mut closes=Vec::new();
        for(slot,file)in [
            (WatchReference::InstalledMounted,installed.mounted.as_ref()),(WatchReference::PartialMounted,self.mounted.as_ref()),
            (WatchReference::InstalledBlock,installed.block.as_ref()),(WatchReference::PartialBlock,self.block.as_ref())]{
            if let Some(file)=file{
                installed.require_original_watch_files()?;
                let identity=DescriptorIdentity::of(file)?;
                installed.require_original_watch_files()?;closes.push(WatchCloseReference{slot,identity});}
        }
        if !closes.iter().any(|v|v.slot==WatchReference::InstalledMounted)
            || !closes.iter().any(|v|v.slot==WatchReference::InstalledBlock){return Err("actual installed terminal references already absent".into());}
        Ok(Some(TerminalPublication{publication:self.publication()?,mounted:installed.observation.clone(),closes}))
    }
    pub(in crate::storage_driver) fn begin_terminal(&mut self,parent:&VerifiedTerminalNodeParent)->Result<(),String>{
        if let Some(old)=&self.terminal{
            if old.operation!=*parent.terminal_operation_uid()||old.unknown||old.census_pending.is_some(){return Err("original terminal probe cannot be replaced/reset/pending".into());}
            return Ok(());
        }
        let publication=self.terminal_publication(parent.scope())?;
        self.terminal=Some(TerminalWatchState{operation:parent.terminal_operation_uid().clone(),publication,
            closes:BTreeMap::new(),underlay_after:None,unmounted:false,unknown:false,census:ReferenceCensusProgress::None,census_pending:None});Ok(())
    }
    /// Native Request's exact detail is verified by the dispatcher before this
    /// method. The genuine opaque boundary is reauthorized BEFORE File.take.
    pub(in crate::storage_driver) fn close_terminal_reference(&mut self,parent:&VerifiedTerminalNodeParent,
        boundary:&VerifiedLocalBoundary,reference:&WatchCloseReference,detail:&str)->Result<(),String>{
        let kind=if reference.slot.mounted(){TerminalBoundary::CloseMounted}else{TerminalBoundary::CloseBlock};
        parent.require_live()?;
        let state=self.terminal.as_ref().ok_or("no original root-owned terminal probe")?;
        if state.operation!=*parent.terminal_operation_uid()||state.unknown||state.census_pending.is_some()
            || !state.publication.as_ref().is_some_and(|p|p.closes.iter().any(|r|r.slot==reference.slot&&r.identity==reference.identity))
            || state.closes.contains_key(reference.slot.key()) || !reference.slot.mounted()
                &&(!state.unmounted||!matches!(state.census,ReferenceCensusProgress::AfterComplete)){
            return Err("terminal close absent/repeated/changed/out of order".into());
        }
        parent.approve(boundary,kind,detail)?;
        // Store expected incarnation BEFORE removing original ownership.
        self.terminal.as_mut().unwrap().closes.insert(reference.slot.key().into(),
            CloseTombstone{identity:reference.identity.clone(),outcome:CloseOutcome::Prepared,
                #[cfg(test)] fault_after_actual_close:false});
        let slot=match reference.slot{
            WatchReference::InstalledMounted=>&mut self.installed.as_mut().ok_or("installed mount object absent")?.mounted,
            WatchReference::PartialMounted=>&mut self.mounted,
            WatchReference::InstalledBlock=>&mut self.installed.as_mut().ok_or("installed block object absent")?.block,
            WatchReference::PartialBlock=>&mut self.block,
        };
        let state=self.terminal.as_mut().unwrap();
        let tombstone=state.closes.get_mut(reference.slot.key()).unwrap();
        parent.owner().require_actual_watch_files()?;
        let result=consume_close(slot,tombstone);
        let serving=parent.owner().require_actual_watch_files();
        if serving.is_err(){tombstone.outcome=CloseOutcome::ConsumedUnknown;}
        let result_hash=hash(&serde_json::to_vec(tombstone).map_err(|_|"actual close outcome encoding failed")?);
        let recorded=parent.record_native_result(boundary,kind,detail,&result_hash);
        if close_reporting_unknown(&result,&recorded)||serving.is_err(){state.unknown=true;parent.retain_unknown();}
        result?;recorded?;serving
    }
    /// First called after the admitted actual umount result, while its child
    /// may still live; called again after actual child+EOF+cgroup drain. Neither
    /// observation alone is a drain or a replacement mounted capability.
    pub(in crate::storage_driver) fn verify_terminal_unmounted(&mut self,parent:&VerifiedTerminalNodeParent)->Result<(),String>{
        #[cfg(not(target_os="linux"))]
        {let _=parent;Err("terminal actual underlay requires Linux".into())}
        #[cfg(target_os="linux")]
        {
            parent.require_live()?;
            let state=self.terminal.as_mut().ok_or("terminal underlay original absent")?;
            let publication=state.publication.as_ref().ok_or("secondary has no writer unmount")?;
            if state.operation!=*parent.terminal_operation_uid()||state.unknown||state.census_pending.is_some()
                ||!matches!(state.census,ReferenceCensusProgress::BeforeComplete|ReferenceCensusProgress::AfterStarted(_)|ReferenceCensusProgress::AfterComplete){
                return Err("underlay terminal observation unknown/another operation".into());
            }
            for reference in publication.closes.iter().filter(|r|r.slot.mounted()){
                if !state.closes.get(reference.slot.key()).is_some_and(|c|matches!(c.outcome,CloseOutcome::ClosedKnown)){
                    return Err("original mounted descriptor has no successful close tombstone".into());
                }
            }
            if state.underlay_after.is_none(){state.underlay_after=Some(open_private_target(&mount_path(&parent.scope().mount_ref))?);}
            let after=observe_parent_kernel(state.underlay_after.as_ref().unwrap())?;
            let before=observe_parent_kernel(self.target_before.as_ref().ok_or("retained pre-mount underlay absent")?)?;
            if after!=before || (after.device,after.inode,after.mount_id)!=(publication.publication.target_device,
                publication.publication.target_inode,publication.publication.target_mount_id){
                return Err("actual unmounted target is not SAME retained original underlay".into());
            }
            if fd_identity(&open_current_namespace()?)?!=fd_identity(self.parent.namespace_held.as_ref().ok_or("retained Watch namespace absent")?)?{
                return Err("actual terminal Watch namespace changed".into());
            }
            if !state.unmounted{self.anchor.retire_terminal_mount(parent,&publication.mounted)?;}
            state.unmounted=true;Ok(())
        }
    }
    pub(in crate::storage_driver) fn terminal_closed_dispositions(&self,parent:&VerifiedTerminalNodeParent)
        ->Result<(TerminalReferenceDisposition,TerminalReferenceDisposition),String>{
        let state=self.terminal.as_ref().ok_or("rooted terminal probe absent")?;
        if state.operation!=*parent.terminal_operation_uid()||state.unknown||state.census_pending.is_some(){return Err("rooted terminal probe unknown/pending/another operation".into());}
        let Some(publication)=&state.publication else {
            if self.installed.is_some()||self.mounted.is_some()||self.block.is_some()
                || parent.scope().phase_node_uid==*parent.scope().mount_ref.node_uid(){return Err("unproven secondary descriptor disposition".into());}
            return Ok((TerminalReferenceDisposition::NotOwnedOnSecondary,TerminalReferenceDisposition::NotOwnedOnSecondary));
        };
        let closed=|mounted:bool|publication.closes.iter().filter(|r|r.slot.mounted()==mounted)
            .all(|r|state.closes.get(r.slot.key()).is_some_and(|c|matches!(c.outcome,CloseOutcome::ClosedKnown)));
        if !state.unmounted||!matches!(state.census,ReferenceCensusProgress::AfterComplete)||!closed(true)||!closed(false)
            || self.mounted.is_some()||self.block.is_some()
            || self.installed.as_ref().is_some_and(|v|v.mounted.is_some()||v.block.is_some()){
            return Err("terminal original mounted/block references not actually closed".into());
        }
        Ok((TerminalReferenceDisposition::ClosedKnown,TerminalReferenceDisposition::ClosedKnown))
    }
    pub(in crate::storage_driver) fn require_before_unmount_census(&self)->Result<(),String>{
        if !self.terminal.as_ref().is_some_and(|s|!s.unknown&&s.census_pending.is_none()&&matches!(s.census,ReferenceCensusProgress::BeforeComplete)){
            return Err("actual completed BeforeUnmount reference census absent".into());}Ok(())
    }
    fn actual_retained_block_references(&self,parent:&VerifiedTerminalNodeParent)->Result<Vec<WatchCloseReference>,String>{
        parent.owner().require_actual_watch_files()?;
        let state=self.terminal.as_ref().ok_or("actual terminal probe absent")?;
        let publication=state.publication.as_ref().ok_or("only actual writer can represent retained block references")?;
        if state.unknown||state.operation!=*parent.terminal_operation_uid(){return Err("original reference source UNKNOWN/changed".into());}
        let mut refs=Vec::new();
        for reference in &publication.closes{
            if reference.slot.mounted(){
                if !state.closes.get(reference.slot.key()).is_some_and(|c|matches!(c.outcome,CloseOutcome::ClosedKnown)){
                    return Err("census representation precedes actual mounted-reference close".into());}
                continue;
            }
            if state.closes.contains_key(reference.slot.key()){return Err("original block slot already consumed; cannot represent retained".into());}
            let file=match reference.slot{
                WatchReference::InstalledBlock=>self.installed.as_ref().and_then(|v|v.block.as_ref()),
                WatchReference::PartialBlock=>self.block.as_ref(),_=>None}.ok_or("original block reference missing; never infer closure")?;
            parent.owner().require_actual_watch_files()?;
            if DescriptorIdentity::of(file)?!=reference.identity{return Err("actual original block File incarnation changed".into());}
            parent.owner().require_actual_watch_files()?;refs.push(reference.clone());
        }
        if refs.is_empty(){return Err("writer has no genuine original block slot to represent".into());}Ok(refs)
    }
    fn reference_census_key(&self,parent:&VerifiedTerminalNodeParent,
        native:&crate::storage_driver::live_authority::JobIdentity,point:anchor::TerminalCensusPoint,
        begin:Option<&str>,detail:&str)->Result<ReferenceCensusKey,String>{
        let references=self.actual_retained_block_references(parent)?;
        let state=self.terminal.as_ref().ok_or("actual census probe absent")?;
        Ok(ReferenceCensusKey{operation:state.operation.clone(),native:native.clone(),point,
            begin:begin.map(str::to_owned),request:detail.into(),prior:state.census.clone(),unmounted:state.unmounted,references,
            publication_sha256:hash(&serde_json::to_vec(&state.publication).map_err(|_|"actual census publication binding")?),
            closes_sha256:hash(&serde_json::to_vec(&state.closes).map_err(|_|"actual census close-state binding")?)})
    }
    pub(in crate::storage_driver) fn prepare_reference_census(&mut self,parent:&std::sync::Arc<VerifiedTerminalNodeParent>,
        native:&crate::storage_driver::live_authority::JobIdentity,point:anchor::TerminalCensusPoint,
        begin:Option<&str>,detail:&str,expected:&[WatchCloseReference])->Result<PreparedReferenceCensus,String>{
        parent.require_live()?;
        if self.terminal.as_ref().ok_or("actual terminal probe absent")?.census_pending.is_some(){
            return Err("original census already pending; no duplicate/retry".into());}
        let key=self.reference_census_key(parent,native,point,begin,detail)?;
        if key.references!=expected{return Err("native reference set differs from actual Watch File slots".into());}
        let next=reference_census_next(&key.prior,point,begin,detail,key.unmounted)?;
        let pending=std::sync::Arc::new(PendingReferenceCensus{parent:parent.clone(),key,next});
        // Root BEFORE dropping probe guard or invoking actual authorization.
        self.terminal.as_mut().unwrap().census_pending=Some(pending.clone());
        Ok(PreparedReferenceCensus{pending})
    }
    pub(in crate::storage_driver) fn commit_reference_census(&mut self,parent:&std::sync::Arc<VerifiedTerminalNodeParent>,
        approved:crate::storage_driver::dispatcher::attachment::terminal::ApprovedReferenceCensus)->Result<(),String>{
        let prepared=approved.into_prepared();let pending=&prepared.pending;
        let result=(||{
            parent.require_live()?;
            let state=self.terminal.as_ref().ok_or("actual pending census probe absent")?;
            if !std::sync::Arc::ptr_eq(parent,&pending.parent)
                ||state.census_pending.as_ref().is_none_or(|p|!std::sync::Arc::ptr_eq(p,pending)){
                return Err("approved census is not SAME root-retained original preparation".into());}
            let key=&pending.key;
            let current=self.reference_census_key(parent,&key.native,key.point,key.begin.as_deref(),&key.request)?;
            same_reference_census_key(key,&current)?;
            // Pure current parent/session/deadline/UNKNOWN/Journal guard after
            // actual same-original FD/KCMP/namespace re-observation. No await.
            parent.require_live()?;
            let state=self.terminal.as_mut().unwrap();
            state.census=pending.next.clone();state.census_pending=None;Ok(())
        })();
        if result.is_err(){if let Some(state)=self.terminal.as_mut(){state.unknown=true;}}
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Closed DATA only; deliberately no actual parent/probe/prepared/approved
    // object is constructed by this fixture or these equality regressions.
    fn census_key_data()->ReferenceCensusKey{
        ReferenceCensusKey{operation:Uid::new(),native:crate::storage_driver::live_authority::JobIdentity{
            node_uid:Uid::new(),boot_id:"12345678-1234-4234-8234-123456789abc".into(),volume_uid:Uid::new(),
            operation_uid:Uid::new(),attempt_uid:Uid::new(),binding_sha256:"a".repeat(64)},
            point:anchor::TerminalCensusPoint::BeforeUnmount,begin:None,request:"b".repeat(64),
            prior:ReferenceCensusProgress::None,unmounted:false,references:Vec::new(),
            publication_sha256:"c".repeat(64),closes_sha256:"d".repeat(64)}
    }
    #[test]
    fn terminal_census_prepared_key_rejects_changed_operation_native_request_phase_and_prior_state_data(){
        let key=census_key_data();same_reference_census_key(&key,&key.clone()).unwrap();
        for n in 0..14{let mut changed=key.clone();match n{
            0=>changed.operation=Uid::new(),1=>changed.native.attempt_uid=Uid::new(),
            2=>changed.native.operation_uid=Uid::new(),3=>changed.native.node_uid=Uid::new(),
            4=>changed.native.boot_id="22345678-1234-4234-8234-123456789abc".into(),
            5=>changed.native.volume_uid=Uid::new(),6=>changed.native.binding_sha256="e".repeat(64),
            7=>changed.point=anchor::TerminalCensusPoint::AfterUnmount,8=>changed.begin=Some("f".repeat(64)),
            9=>changed.request="e".repeat(64),10=>changed.prior=ReferenceCensusProgress::BeforeComplete,
            11=>changed.unmounted=true,12=>changed.publication_sha256="e".repeat(64),_=>changed.closes_sha256="e".repeat(64)}
            assert!(same_reference_census_key(&key,&changed).is_err(),"changed DATA field{n}");}
    }
    #[test]
    fn terminal_census_prepared_key_rejects_changed_original_slot_and_every_fd_identity_data_field(){
        let(_owned,slot,tombstone)=OwnedTemp::create();let mut key=census_key_data();
        key.references.push(WatchCloseReference{slot:WatchReference::InstalledBlock,identity:tombstone.identity});
        for n in 0..8{let mut changed=key.clone();if n==7{changed.references.clear();}else{
            let reference=&mut changed.references[0];match n{
            0=>reference.slot=WatchReference::PartialBlock,1=>reference.identity.number=-1,
            2=>reference.identity.device^=1,3=>reference.identity.inode^=1,4=>reference.identity.rdev^=1,
            5=>reference.identity.mode^=1,_=>reference.identity.mount_id=Some(1)}}
            assert!(same_reference_census_key(&key,&changed).is_err(),"changed original DATA field{n}");}
        assert!(slot.as_ref().unwrap().metadata().is_ok());
        // Ordinary owned regular FD DATA is NOT an actual block reference,
        // namespace, process-table proof, prepared request or physical grant.
    }
    #[test]
    fn terminal_census_commit_source_requires_same_rooted_pending_and_actual_postapproval_reobservation(){
        let source=include_str!("managed_mount_terminal.rs");
        let commit=source.split_once("fn commit_reference_census(").unwrap().1.split_once("\n#[cfg(test)]").unwrap().0;
        assert!(commit.contains("Arc::ptr_eq(parent,&pending.parent)"));
        assert!(commit.contains("Arc::ptr_eq(p,pending)"));
        let observe=commit.find("self.reference_census_key(parent,").unwrap();
        let compare=commit.find("same_reference_census_key(key,&current)?").unwrap();
        let live=commit[compare..].find("parent.require_live()?").unwrap()+compare;
        let apply=commit.find("state.census=pending.next.clone()").unwrap();
        let clear=commit.find("state.census_pending=None").unwrap();
        assert!(observe<compare&&compare<live&&live<apply&&apply<clear);
        assert_eq!(commit.matches("census_pending=None").count(),1);
        assert!(commit.contains("if result.is_err(){if let Some(state)=self.terminal.as_mut(){state.unknown=true;}"));
        assert!(!commit.contains(".approve("));assert!(!commit.contains(".take("));
        // Source placement, not an executed genuine-parent fault scenario.
    }
    #[test]
    fn terminal_reference_census_data_sequence_denies_skip_replay_wrong_ack_and_offline_representation(){
        use anchor::TerminalCensusPoint::*;
        let before=reference_census_next(&ReferenceCensusProgress::None,BeforeUnmount,None,"a",false).unwrap();
        assert!(reference_census_next(&before,BeforeUnmount,None,"a",false).is_err());
        assert!(reference_census_next(&before,BeforeUnmount,Some("wrong"),"b",false).is_err());
        assert!(reference_census_next(&before,AfterUnmount,None,"b",true).is_err());
        let done=reference_census_next(&before,BeforeUnmount,Some("a"),"b",false).unwrap();
        assert!(reference_census_next(&done,AfterUnmount,None,"c",false).is_err());
        let after=reference_census_next(&done,AfterUnmount,None,"c",true).unwrap();
        assert!(reference_census_next(&after,AfterUnmount,Some("wrong"),"d",true).is_err());
        let final_state=reference_census_next(&after,AfterUnmount,Some("c"),"d",true).unwrap();
        assert!(matches!(final_state,ReferenceCensusProgress::AfterComplete));
        for point in [BeforeUnmount,AfterUnmount,BeforeOffline,AfterOffline]{
            assert!(reference_census_next(&final_state,point,None,"replay",true).is_err());}
    }
    #[test]
    fn terminal_canonical_device_leaf_never_waives_nofollow_for_logical_or_arbitrary_paths(){
        use std::path::Path;
        for path in ["/dev/dm-0","/dev/dm-123"]{assert!(strict_dm_leaf(Path::new(path)));}
        for path in ["/dev/mapper/vg-lv","/dev/vg/rkvol_uid","/tmp/dm-1","/dev/dm-","/dev/dm-a","/dev/dm-1/child","/dev/../dev/dm-1"]{
            assert!(!strict_dm_leaf(Path::new(path)));}
    }
    #[test]
    fn terminal_equal_number_and_fstat_of_nonblock_file_never_become_reference_authority(){
        let(_owned,slot,tombstone)=OwnedTemp::create();let file=slot.as_ref().unwrap();
        let reference=WatchCloseReference{slot:WatchReference::InstalledBlock,identity:tombstone.identity};
        assert!(!reference.matches_observed(&file.as_raw_fd().to_string(),&file.metadata().unwrap()));
        // DATA match cannot mint the required actual private inherited census
        // context; KCMP and parent/process provenance are additional gates.
    }
    struct OwnedTemp {directory:std::path::PathBuf,path:std::path::PathBuf}
    impl OwnedTemp {
        fn create()->(Self,Option<File>,CloseTombstone){
            let directory=std::env::temp_dir().join(format!("royak-terminal-close-{}",Uid::new().as_str()));
            std::fs::create_dir(&directory).unwrap();
            let path=directory.join("original");
            let file=std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(&path).unwrap();
            let identity=DescriptorIdentity::of(&file).unwrap();
            (Self{directory,path},Some(file),CloseTombstone{identity,outcome:CloseOutcome::Prepared,fault_after_actual_close:false})
        }
    }
    impl Drop for OwnedTemp {fn drop(&mut self){
        std::fs::remove_file(&self.path).unwrap();std::fs::remove_dir(&self.directory).unwrap();
    }}
    #[test]
    fn owned_temp_original_close_is_once_only_and_retains_identity_tombstone(){
        let(_owned,mut slot,mut tombstone)=OwnedTemp::create();let original=tombstone.identity.clone();
        consume_close(&mut slot,&mut tombstone).unwrap();assert!(slot.is_none());
        assert!(matches!(tombstone.outcome,CloseOutcome::ClosedKnown));assert_eq!(tombstone.identity,original);
        assert!(consume_close(&mut slot,&mut tombstone).is_err());
        assert!(matches!(tombstone.outcome,CloseOutcome::ClosedKnown));
    }
    #[test]
    fn reported_close_error_after_actual_owned_temp_close_never_restores_or_retries_fd(){
        let(_owned,mut slot,mut tombstone)=OwnedTemp::create();tombstone.fault_after_actual_close=true;
        assert!(consume_close(&mut slot,&mut tombstone).is_err());assert!(slot.is_none());
        assert!(matches!(tombstone.outcome,CloseOutcome::ErrorAfterConsume{..}));
        assert!(consume_close(&mut slot,&mut tombstone).is_err());assert!(slot.is_none());
        assert!(close_reporting_unknown(&Err("reported actual close failure".into()),&Ok(())));
    }
    #[test]
    fn lost_result_after_known_temp_close_requires_unknown_without_fictional_held_fd(){
        let(_owned,mut slot,mut tombstone)=OwnedTemp::create();
        let actual=consume_close(&mut slot,&mut tombstone);assert!(actual.is_ok());
        assert!(close_reporting_unknown(&actual,&Err("lost result/fsync acknowledgement".into())));
        assert!(slot.is_none());assert!(matches!(tombstone.outcome,CloseOutcome::ClosedKnown));
        assert!(!close_reporting_unknown(&actual,&Ok(())));
    }
    #[test]
    fn mandatory_terminal_admissions_reject_one_gib_before_create_without_window_reuse(){
        assert_eq!(mandatory_admissions(64*1024*1024,true).unwrap(),191);
        assert_eq!(mandatory_admissions(64*1024*1024,false).unwrap(),163);
        assert_eq!(mandatory_admissions(1024*1024*1024,true).unwrap(),2111);
        assert_eq!(mandatory_admissions(1024*1024*1024,false).unwrap(),2083);
        for writer in [false,true]{assert!(mandatory_admissions(1024*1024*1024,writer).unwrap()>512);}
        for bytes in [0,1,4095,u64::MAX]{assert!(mandatory_admissions(bytes,true).is_err());}
    }
    #[test]
    fn terminal_step_sequence_is_finite_writer_three_secondary_two_and_never_restarts(){
        use TerminalNativeStep::*;
        assert_eq!((0..4).map(|n|expected_step(true,n)).collect::<Vec<_>>(),
            vec![Some(UnmountAndDemote),Some(ObserveSecondarySynchronized),Some(OfflineAndObserve),None]);
        assert_eq!((0..3).map(|n|expected_step(false,n)).collect::<Vec<_>>(),
            vec![Some(ObserveSecondarySynchronized),Some(OfflineAndObserve),None]);
        assert_eq!(expected_step(true,usize::MAX),None);
    }
    // Closed kernel-observation DATA only; no parent, grant, helper permit,
    // retained owner or positive physical result is constructed by this model.
    fn topology()->(Config,Plan,Value){
        let cfg=crate::storage_driver::test_config();
        let nodes=[cfg.node_uid.clone(),Uid::new(),Uid::new()];
        let peers=std::array::from_fn(|i|Peer{node_uid:nodes[i].clone(),node_id:i as u8,hostname:format!("n{i}"),
            address:format!("10.77.0.{}",i+1).parse().unwrap(),public_key:format!("{}=",["A","B","C"][i].repeat(43)),vg_name:cfg.vg_name.clone()});
        let plan=Plan{version:1,cluster_id:cfg.cluster_id.clone(),pool_uid:cfg.pool_uid.clone(),volume_uid:Uid::new(),
            operation_uid:Uid::new(),minor:512,port:22000,interface:"wg-test".into(),shared_secret:"0".repeat(48),peers};
        let peers=plan.peers.iter().skip(1).map(|p|serde_json::json!({"peer-node-id":p.node_id,"name":p.hostname,
            "connection-state":"Connected","peer-role":"Secondary","ap-in-flight":0,"rs-in-flight":0,
            "paths":[{"this_host":{"address":"10.77.0.1","port":22000},"remote_host":{"address":p.address,"port":22000},"established":true}],
            "peer_devices":[{"volume":0,"replication-state":"Established","peer-disk-state":"UpToDate","peer-client":false,
                "resync-suspended":"no","out-of-sync":0,"pending":0,"unacked":0}]})).collect::<Vec<_>>();
        let value=serde_json::json!({"node-id":0,"role":"Secondary","suspended":false,"force-io-failures":false,
            "devices":[{"volume":0,"minor":512,"open":false,"size":65536,"disk-state":"UpToDate","client":false,
                "quorum":true,"upper-pending":0,"lower-pending":0}],"connections":peers});
        (cfg,plan,value)
    }
    #[test]
    fn terminal_all_secondary_data_refuses_primary_open_pending_unknown_and_peer_role(){
        let(cfg,plan,good)=topology();terminal_all_secondary(&cfg,&plan,64*1024*1024,&good).unwrap();
        for n in 0..8{let mut bad=good.clone();match n{
            0=>bad["role"]="Primary".into(),1=>bad["devices"][0]["open"]=true.into(),
            2=>bad["devices"][0]["lower-pending"]=1.into(),3=>bad["devices"][0]["quorum"]=Value::Null,
            4=>bad["connections"][0]["peer-role"]="Primary".into(),5=>bad["connections"][0]["peer-role"]=Value::Null,
            6=>bad["connections"][0]["peer_devices"][0]["out-of-sync"]=1.into(),
            _=>bad["connections"][0]["paths"][0]["established"]=false.into()};
            assert!(terminal_all_secondary(&cfg,&plan,64*1024*1024,&bad).is_err(),"case{n}");}
    }
    #[test]
    fn terminal_local_down_data_is_distinct_from_prior_all_three_connected_proof(){
        let(cfg,plan,mut value)=topology();value["connections"][0]["peer-role"]="Unknown".into();
        value["connections"][0]["connection-state"]="StandAlone".into();value["devices"][0]["quorum"]=false.into();
        terminal_local_secondary(&cfg,&plan,64*1024*1024,&value).unwrap();
        assert!(terminal_all_secondary(&cfg,&plan,64*1024*1024,&value).is_err());
        value["connections"][0]["peer-role"]=Value::Null;
        assert!(terminal_local_secondary(&cfg,&plan,64*1024*1024,&value).is_err());
    }
}
