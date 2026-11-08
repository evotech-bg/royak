//! Distinct profile7 producer. Actual roots/FDs, never a path/JSON allowlist.
//! Legacy1-5 and terminal6 permissions are deliberately not reused.
#[cfg(test)]
#[path="dispatcher_attach_inventory_tests.rs"]
pub(crate) mod tests;
// Actual v7 launch is separate so old capsule5/worker paths remain strict.
use super::*;
use crate::storage_driver::native_runtime::mount::SameGroupInventoryRoots;
use crate::storage_driver::replica::initialize::managed_mount::inventory::{InventoryMemberSlot,InventoryMemberObservation};
use crate::storage_driver::replica::initialize::managed_mount::terminal::origin::{self,WatchProcessObservation};
pub(super) fn launch_owned(config:&Config,work:&AttachmentWork,agent:&NativeAgent,step:AttachNativeStep)->Result<VerifiedAttachDrain,String> {
    work.owner.require_registered_parent(&work.parent)?;
    if !cfg!(target_os="linux") || unsafe{libc::geteuid()}!=0{return Err("physical attachment requires Linux root".into());}
    work.owner.watch_process.lock().map_err(|_|"actual Watch process origin poisoned")?
        .capture_before_production(&work.parent.scope().phase_boot)?;
    let scope=work.parent.scope().clone();let (pool,plan)=agent.attachment_parts(&scope)?;
    if config.node_uid!=scope.phase_node_uid {return Err("actual dispatcher node differs before any journal effect".into());}
    let path=config.journal_root.join(config.node_uid.as_str());let dir=Dir::open(&path,false)?;
    if dir.bounded_entries(512)?.iter().filter(|n|n.starts_with("attempt-")).count()>=128 {
        return Err("128 immutable attempts retained; no attach admission".into());
    }
    {
        let mut state=work.owner.resources.lock().map_err(|_|"actual global lease state poisoned")?;
        if state.global.as_ref().ok_or("actual admission absent")?.lease.is_none(){
            let lease=dir.lock()?;state.global.as_mut().unwrap().lease=Some(lease);
            let safety=state.global.as_ref().unwrap().lease.as_ref().unwrap().try_clone().map_err(|_|"actual global lease safety duplicate failed")?;
            state.global_safety=Some(safety);
        }
        if state.volume_lease.is_none(){
            let volume=Dir::open(&path.join(format!("mount-{}",scope.owner.volume_uid.as_str())),true)?;
            state.volume_lease=Some(volume.lock()?);
        }
    }
    let lease=work.owner.resources.lock().map_err(|_|"actual lease state poisoned")?.global.as_ref()
        .and_then(|g|g.lease.as_ref()).ok_or("original global lease absent")?.try_clone().map_err(|_|"cannot inherit actual global lease")?;
    let slot=work.parent.root_book().released_slot_for_owned_inventory(&work.parent)?;
    {
        let mut state=work.owner.resources.lock().map_err(|_|"actual initialized slot root poisoned")?;
        if let Some(old)=&state.initialization_slot{if !Arc::ptr_eq(old,&slot){return Err("original released slot changed; no replacement".into());}}
        else{state.initialization_slot=Some(slot.clone());}
    }
    let original={work.owner.resources.lock().map_err(|_|"actual original cgroup root poisoned")?.terminal_cgroup.clone()};
    let original=if let Some(original)=original{original}else{
        origin::require_descriptor_headroom(2+capture_peak(8)?)?;
        let value=Arc::new(slot.duplicate_for_owned_inventory(config,&scope)?);
        // Root SAME newly cloned original before postinspection/further IO.
        work.owner.resources.lock().unwrap_or_else(|p|p.into_inner()).terminal_cgroup=Some(value.clone());value
    };
    slot.recheck_owned_inventory_clone(original.as_ref(),config,&scope)?;
    let cgroup=original.try_clone()?;
    let identity_pair=cgroup.identity()?;
    if cgroup.populated()?{return Err("actual attachment cgroup not empty; no new helper".into());}
    cgroup.prune_empty_command_scopes()?;
    let binding=CgroupBinding {version:1,node_uid:config.node_uid.clone(),boot_id:scope.phase_boot.as_str().into(),device:identity_pair.0,inode:identity_pair.1};
    match dir.read("cgroup-binding.json")? {
        Some(raw)=>{let old:CgroupBinding=serde_json::from_slice(&raw).map_err(|_|"actual cgroup binding corrupt")?;
            if old.version!=1 || old.node_uid!=binding.node_uid || old.boot_id!=binding.boot_id || old.device!=binding.device || old.inode!=binding.inode {
                return Err("actual cgroup binding differs; no rewrite/adoption".into());
            }},
        None=>return Err("original released initialization cgroup binding absent; no v7 creation/rebind".into()),
    }
    if let Some(raw)=dir.read("current.json")? {
        let prior=load_record(&raw)?;
        if prior.state!=State::Complete || prior.identity.node_uid!=config.node_uid || prior.identity.boot_id!=scope.phase_boot.as_str() {
            return Err("predecessor is not actual same-boot drained Complete; no reset/adoption".into());
        }
    }
    let deadline=work.owner.effective_deadline();
    let remaining=deadline.saturating_duration_since(Instant::now()).min(config.deadline);
    let remaining_ms=u64::try_from(remaining.as_millis()).map_err(|_|"attach remaining overflow")?;
    if remaining_ms==0 || remaining_ms>scope.remaining_budget_ms{return Err("original registered remaining budget invalid/expired".into());}
    let publication=if step==AttachNativeStep::FilesystemMount || scope.phase==AttachPhase::ObserveMounted {
        Some(work.owner.probe.lock().map_err(|_|"publication owner poisoned")?.publication()?)
    }else{None};
    let existing_anchor=if step==AttachNativeStep::PublicationAnchor {
        work.owner.probe.lock().map_err(|_|"rooted anchor owner poisoned")?.existing_anchor_reference(&scope,deadline)?
    }else{None};
    let context=work.owner.prepare_owned_pool_inventory(work.parent.clone(),step,config)?;
    let payload=Payload {config:serde_json::to_value(OwnedAttachPayload{attachment:AttachPayload {pool,scope:scope.clone(),step,publication,existing_anchor},roles:context.table()?}).map_err(|_|"actual v7 attach payload encoding")?,
        plan,projection:Vec::new(),extended:Some(ExtendedJob::AttachWithOwnedInventory),dataset_uid:Some(scope.generation.uid.clone()),
        remote_binding:Some(scope_digest(&scope)?),initialization:None,worker_remaining_ms:Some(remaining_ms)};
    let payload_sha256=hash(&serde_json::to_vec(&payload).map_err(|_|"attach payload hash")?);
    let identity=live::JobIdentity {node_uid:config.node_uid.clone(),boot_id:scope.phase_boot.as_str().into(),volume_uid:scope.owner.volume_uid.clone(),
        operation_uid:scope.mount_ref.operation_uid().clone(),attempt_uid:if step==AttachNativeStep::Single {scope.phase_job_uid.clone()}else{Uid::new()},binding_sha256:hash(&serde_json::to_vec(&(
            "actual-owned-inventory-first-attach-v7",&scope,step,&payload_sha256,&config.helper_sha256,&config.budget)).map_err(|_|"attach identity encoding")?)};
    let start=cgroup.enforce_budget(&config.budget)?;
    let capsule=Capsule {version:7,identity:identity.clone(),payload,budget:config.budget.clone()};
    if !valid_capsule(&capsule){return Err("invalid exact v7 capsule before any child launch".into());}
    let bytes=serde_json::to_vec(&capsule).map_err(|_|"attach capsule encoding")?;
    if bytes.len() as u64>CAPSULE_LIMIT{return Err("attach capsule exceeds unchanged bound".into());}
    let filename=format!("capsule-{}.json",identity.attempt_uid.as_str());dir.write_new(&filename,&bytes)?;
    let capsule_file=open_private(&path.join(filename))?;
    let mut record=Record {version:7,identity:identity.clone(),payload_sha256,image_sha256:config.helper_sha256.clone(),state:State::LaunchIntent,
        resources_start:start,resources_final:None};publish(&dir,&record)?;
    let image=open_image(&config.helper_image,&config.helper_sha256)?;
    {let mut state=work.owner.resources.lock().map_err(|_|"actual native owner poisoned")?;
        state.current_native=Some(identity.clone());state.current_step=Some(step);}
    context.bind_native(&identity)?;
    work.parent.bind_owned_inventory_native(&identity,step,context.clone())?;
    let (control,child_control)=UnixStream::pair().map_err(|_|"attach control pair failed")?;
    let procs=cgroup.procs_for_child()?;
    let mut fds=vec![lease.as_raw_fd(),capsule_file.as_raw_fd(),child_control.as_raw_fd()];
    let table=context.table()?;table.validate(&scope,Some([fds[0],fds[1],fds[2]]))?;
    fds.extend(table.role_numbers());if fds.len()!=total_roles(table.members.len())?{return Err("actual v7 total role count mismatch".into());}
    let argv_fds=[fds[0],fds[1],fds[2]];let parent_pid=std::process::id();
    let mut command=Command::new(image_exec_path(&image,&config.helper_image)?);
    command.args(["storage-driver","native-worker","--journal"]).arg(&path)
        .arg("--lease-fd").arg(argv_fds[0].to_string()).arg("--capsule-fd").arg(argv_fds[1].to_string())
        .arg("--control-fd").arg(argv_fds[2].to_string()).arg("--attempt").arg(identity.attempt_uid.as_str())
        .arg("--cgroup-root").arg(&config.delegated_cgroup_root).env_clear().env("PATH","/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL","C").env("HOME","/").current_dir("/").stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    unsafe {command.pre_exec(move||{
        #[cfg(target_os="linux")]
        if libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)!=0 || libc::getppid() as u32!=parent_pid {return Err(std::io::Error::last_os_error());}
        if libc::write(procs.as_raw_fd(),b"0\n".as_ptr().cast(),2)!=2{return Err(std::io::Error::last_os_error());}
        for &fd in &fds {let flags=libc::fcntl(fd,libc::F_GETFD);if flags<0 || libc::fcntl(fd,libc::F_SETFD,flags & !libc::FD_CLOEXEC)<0{return Err(std::io::Error::last_os_error());}}
        Ok(())});}
    let observer=cgroup.try_clone()?;let cancelled=work.owner.cancelled.clone();
    work.owner.require_registered_parent(&work.parent)?;
    let child=command.spawn().map_err(|_|"attach spawn UNKNOWN; original owner/admission retained")?;
    drop(child_control);drop(image);drop(capsule_file);
    // After spawn: only infallible drops/time clipping precede the supervisor.
    let timeout=deadline.saturating_duration_since(Instant::now()).min(remaining);
    let (outcome,quarantine)=supervise(child,control,cgroup,lease,timeout,&identity,&cancelled,
        DiagnosticProfile::Attachment {scope:&scope,step},|request|{
            if request.version!=1||request.sequence==0||request.identity!=identity||!valid_hash(&request.detail_sha256){return Ok(Some(false));}
            let boundary=VerifiedLocalBoundary::new(request,&identity)?;
            let detail=hash(&serde_json::to_vec(request).map_err(|_|"actual v7 request encoding")?);
            if let Some(operation)=InventoryOperation::from_boundary(&request.boundary){
                if request.detail_sha256!=hash(&operation.detail(&context.table()?)?){return Ok(Some(false));}
                work.parent.approve_owned_inventory(context.clone(),&boundary,&detail)?;
            }else{
                let kind=if request.boundary=="helper-start"&&request.detail_sha256==hash(b"native-owned-mounted-inventory-attachment-v7"){
                    AttachBoundary::Start
                }else if request.boundary=="helper-start"{return Ok(Some(false));}
                else{let Some(kind)=native_kind(request,&identity)else{return Ok(Some(false));};kind};
                work.parent.approve(&boundary,kind,&detail)?;
            }Ok(Some(true))
        })?;
    if let Some(q)=quarantine {
        *work.owner.quarantine.lock().unwrap_or_else(|e|e.into_inner())=Some(q);
        work.owner.resources.lock().unwrap_or_else(|e|e.into_inner()).quarantined=true;
    }
    record.resources_final=Some(observer.resource_snapshot(&config.budget)?);
    let drained=record.resources_final.as_ref().is_some_and(|end|end.pids_current==0 && end.cpu_usage_us>=record.resources_start.cpu_usage_us
        && end.cpu_user_us>=record.resources_start.cpu_user_us && end.cpu_system_us>=record.resources_start.cpu_system_us);
    let (raw,extra)=match outcome {
        Outcome::CompletedDiagnostics {stdout,retained_lease:Some(extra),..} if drained && !observer.populated()?
            && !work.owner.resources.lock().map_err(|_|"actual quarantine state poisoned")?.quarantined=>(stdout,extra),
        _=>{record.state=State::Unknown;publish(&dir,&record)?;return Err("actual child/EOF/cgroup/resource drain failed; owner UNKNOWN".into());}
    };
    let diagnostic=serde_json::from_slice(&raw).map_err(|_|"actual helper diagnostic corrupt")?;
    record.state=State::Complete;publish(&dir,&record)?;
    let completion=VerifiedLocalBoundary::owned_inventory_completion(&identity,&record,&raw)?;
    drop(extra);
    let drain=VerifiedAttachDrain {inventory:Some(context.clone()),owner:work.owner.clone(),scope,parent:work.parent.clone(),identity,step,diagnostic,
        block_major:147,block_minor:agent.attachment_minor(),block_bytes:work.parent.scope().generation.virgin_replicas[0].exposed_bytes,
        evidence_sha256:hash(&raw),completion};
    context.retire_after_actual_drain(&drain)?;Ok(drain)
}


pub(in crate::storage_driver) const PROFILE:u32=7;
const DOMAIN:&str="managed-owned-inventory-v1";
const MAX_MEMBERS:usize=8;
const BASELINE_ROLES:usize=3;
const ORIGINAL_CGROUP_ROLES:usize=1;
const WATCH_PROOF_ROLES:usize=2;
const SHARED_NAMESPACE_ROLES:usize=1;
/// Every ordinary inventory command remains the original fixed vector. This
/// closed operation is additionally fresh profile7/context-bound, not a new
/// Program path, generic command capability or native read-window exemption.
#[derive(Clone,Copy,Debug,Serialize,Deserialize,PartialEq,Eq)]
pub(in crate::storage_driver) enum InventoryOperation {Pvs,Vgs,Lvs,Lsblk,KernelCensus}
impl InventoryOperation {
    pub(in crate::storage_driver) fn boundary(self)->&'static str{match self{
        Self::Pvs=>"owned-inventory-pvs",Self::Vgs=>"owned-inventory-vgs",Self::Lvs=>"owned-inventory-lvs",
        Self::Lsblk=>"owned-inventory-lsblk",Self::KernelCensus=>"owned-inventory-kernel-census"}}
    fn from_boundary(value:&str)->Option<Self>{Some(match value{
        "owned-inventory-pvs"=>Self::Pvs,"owned-inventory-vgs"=>Self::Vgs,"owned-inventory-lvs"=>Self::Lvs,
        "owned-inventory-lsblk"=>Self::Lsblk,"owned-inventory-kernel-census"=>Self::KernelCensus,_=>return None})}
    pub(in crate::storage_driver) fn args(self)->&'static [&'static str]{match self{
        Self::Pvs=>&["--reportformat","json","--units","b","--nosuffix","-o","pv_name,pv_uuid,vg_name,vg_uuid"],
        Self::Vgs=>&["--reportformat","json","--units","b","--nosuffix","-o","vg_name,vg_uuid,vg_size,vg_free,vg_extent_size"],
        Self::Lvs=>&["--reportformat","json","--units","b","--nosuffix","-o","vg_uuid,lv_name,lv_uuid,lv_size,lv_tags,lv_attr,segtype,lv_kernel_major,lv_kernel_minor"],
        Self::Lsblk=>&["--json","--bytes","-o","PATH,TYPE,SERIAL,MOUNTPOINTS","--tree"],Self::KernelCensus=>&[]}}
    fn detail(self,table:&InventoryRoleTable)->Result<Vec<u8>,String>{
        serde_json::to_vec(&("actual-owned-inventory-read-v7",table.context_uid.clone(),hash(&serde_json::to_vec(table).map_err(|_|"inventory table encoding")?),self,self.args()))
            .map_err(|_|"actual inventory fixed-operation binding".into())
    }
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedAttachPayload {attachment:AttachPayload,roles:InventoryRoleTable}
impl InventoryRoleTable {
    fn role_numbers(&self)->Vec<i32>{let mut roles=vec![self.cgroup_fd,self.namespace_fd,self.watch_pidfd,self.watch_proc];
        for member in &self.members{roles.extend([member.mounted_fd,member.block_fd]);}roles}
    fn validate(&self,scope:&ExpectedAttachScope,baseline:Option<[i32;3]>)->Result<(),String>{
        if self.domain!=DOMAIN||self.version!=1||!valid_hash(&self.group_sha256)||self.source_scope_sha256!=scope_digest(scope)?
            ||self.round_uid!=scope.round_uid||self.namespace.1==0||self.watch.boot()!=&scope.phase_boot
            ||self.watch.namespace()!=self.namespace||self.cgroup_identity.1==0||!self.delegated_root.is_absolute(){
            return Err("invalid distinct actual profile7 role table/source/boot".into());}
        total_roles(self.members.len())?;let mut seen=std::collections::BTreeSet::new();
        if !self.members.is_empty()&&scope.mount_ref.node_uid()!=&scope.phase_node_uid{
            return Err("secondary node cannot represent writer-side mounted inventory".into());}
        if self.live_members.is_empty()||self.live_members.len()>MAX_MEMBERS{return Err("actual same-book live membership outside1..8".into());}
        let mut live=std::collections::BTreeSet::new();
        for fact in &self.live_members{fact.validate()?;if fact.node_uid!=scope.phase_node_uid||!live.insert(fact.volume_uid.clone()){
            return Err("actual same-book live member duplicated/different target".into());}}
        for fd in self.role_numbers().into_iter().chain(baseline.into_iter().flatten()){
            if fd<3||!seen.insert(fd){return Err("profile7 inherited roles duplicate/alias/invalid".into());}}
        let mut volumes=std::collections::BTreeSet::new();let mut mounts=std::collections::BTreeSet::new();let mut original_fds=std::collections::BTreeSet::new();
        for member in &self.members{let value=&member.observation;
            if !volumes.insert(value.fact.volume_uid.clone())||!mounts.insert(value.mounted.mount_id)||!self.live_members.contains(&value.fact)
                ||value.fact.node_uid!=scope.phase_node_uid||value.mounted.namespace_device!=self.namespace.0||value.mounted.namespace_inode!=self.namespace.1
                ||!valid_hash(&value.source_scope_sha256)||!valid_hash(&value.origin_completion_sha256)
                ||value.original_mounted.mount_id!=Some(value.mounted.mount_id)||value.original_block.mount_id.is_some()
                ||value.origin_native.node_uid!=scope.phase_node_uid||value.origin_native.boot_id!=scope.phase_boot.as_str()
                ||value.origin_native.volume_uid!=value.fact.volume_uid||!valid_hash(&value.origin_native.binding_sha256)
                ||value.mounted.target!=format!("/var/lib/royak/storage/mounts/{}/1/{}",value.fact.volume_uid.as_str(),scope.mount_ref.writer_uid().as_uid().as_str())
                ||!crate::storage_lifecycle::valid_uuid(&value.mounted.filesystem_uuid)||!value.mounted.private_propagation{
                return Err("malformed/aliased exact genuine inventory member DATA".into());}
            for fd in [value.original_mounted.number,value.original_block.number]{if fd<3||!original_fds.insert(fd){return Err("original Watch descriptor identity duplicated/invalid".into());}}
            if seen.contains(&value.original_mounted.number)||seen.contains(&value.original_block.number){
                return Err("inherited role aliases original Watch member descriptor".into());}
        }Ok(())
    }
}
pub(in crate::storage_driver::dispatcher) fn valid_capsule(capsule:&Capsule)->bool{
    let Ok(payload)=serde_json::from_value::<OwnedAttachPayload>(capsule.payload.config.clone())else{return false;};
    let a=&payload.attachment;
    capsule.version==PROFILE&&capsule.payload.extended==Some(ExtendedJob::AttachWithOwnedInventory)
        &&a.pool.validate().is_ok()&&a.scope.validate().is_ok()&&step_allowed(a.scope.phase,a.step)
        &&payload.roles.validate(&a.scope,None).is_ok()&&a.pool.node_uid==a.scope.phase_node_uid
        &&capsule.identity.node_uid==a.scope.phase_node_uid&&capsule.identity.boot_id==a.scope.phase_boot.as_str()
        &&capsule.identity.volume_uid==a.scope.owner.volume_uid&&&capsule.identity.operation_uid==a.scope.mount_ref.operation_uid()
        &&capsule.payload.dataset_uid.as_ref()==Some(&a.scope.generation.uid)&&capsule.payload.projection.is_empty()&&capsule.payload.initialization.is_none()
        &&capsule.payload.worker_remaining_ms.is_some_and(|n|n>0&&n<=a.scope.remaining_budget_ms)
        &&capsule.payload.remote_binding.as_deref()==Some(scope_digest(&a.scope).unwrap_or_default().as_str())
        &&(a.publication.is_some()==(a.step==AttachNativeStep::FilesystemMount||a.scope.phase==AttachPhase::ObserveMounted))
        &&(a.existing_anchor.is_none()||a.step==AttachNativeStep::PublicationAnchor)
}
/// Distinct opaque v7 original-cgroup input. No v6 permission/type reuse or
/// public constructor; only the private capsule+lease+root-channel join below.
pub(in crate::storage_driver) struct VerifiedInheritedInventoryCgroup {file:File,identity:(u64,u64),budget:super::super::super::ResourceBudget}
impl VerifiedInheritedInventoryCgroup {pub(in crate::storage_driver) fn into_kernel_parts(self)->(File,(u64,u64),super::super::super::ResourceBudget){(self.file,self.identity,self.budget)}}
pub(in crate::storage_driver::dispatcher) fn take_inherited_cgroup(capsule:&Capsule,binding:&CgroupBinding,lease:&File,
    capsule_fd:i32,control:&UnixStream,root:&std::path::Path)->Result<VerifiedInheritedInventoryCgroup,String>{
    #[cfg(not(target_os="linux"))]{let _=(capsule,binding,lease,capsule_fd,control,root);Err("profile7 needs Linux inherited original cgroup".into())}
    #[cfg(target_os="linux")]{
        if !valid_capsule(capsule){return Err("not actual distinct profile7 capsule".into());}
        live::verify_owned_inventory_parent_channel(control)?;
        let p:OwnedAttachPayload=serde_json::from_value(capsule.payload.config.clone()).map_err(|_|"invalid profile7 payload")?;
        p.roles.validate(&p.attachment.scope,Some([lease.as_raw_fd(),capsule_fd,control.as_raw_fd()]))?;
        let raw=p.roles.cgroup_fd;let mut stat:libc::stat=unsafe{std::mem::zeroed()};let mut fs:libc::statfs=unsafe{std::mem::zeroed()};
        if unsafe{libc::fstat(raw,&mut stat)}!=0||unsafe{libc::fstatfs(raw,&mut fs)}!=0||fs.f_type as u64!=0x63677270
            ||(stat.st_mode as u32&libc::S_IFMT as u32)!=libc::S_IFDIR as u32
            ||(stat.st_dev as u64,stat.st_ino as u64)!=p.roles.cgroup_identity{
            return Err("profile7 inherited role not SAME actual original cgroup directory".into());}
        let named=root.join(format!("rkjob-{}",capsule.identity.node_uid.as_str()));
        let m=std::fs::symlink_metadata(&named).map_err(|_|"original profile7 node leaf missing; never create")?;
        if root!=p.roles.delegated_root||std::fs::canonicalize(root).map_err(|_|"profile7 delegated root unavailable")?!=root
            ||m.file_type().is_symlink()||!m.is_dir()||(m.dev(),m.ino())!=p.roles.cgroup_identity
            ||binding.version!=1||binding.node_uid!=capsule.identity.node_uid||binding.boot_id!=capsule.identity.boot_id
            ||(binding.device,binding.inode)!=p.roles.cgroup_identity||BootId::current()?.as_str()!=capsule.identity.boot_id
            ||unsafe{libc::flock(lease.as_raw_fd(),libc::LOCK_EX|libc::LOCK_NB)}!=0{
            return Err("profile7 original cgroup/path/current boot/private lease differs".into());}
        let file=unsafe{File::from_raw_fd(raw)};confine(&file)?;
        Ok(VerifiedInheritedInventoryCgroup{file,identity:p.roles.cgroup_identity,budget:capsule.budget.clone()})
    }
}
fn confine(file:&File)->Result<(),String>{let raw=file.as_raw_fd();let flags=unsafe{libc::fcntl(raw,libc::F_GETFD)};
    if flags<0||unsafe{libc::fcntl(raw,libc::F_SETFD,flags|libc::FD_CLOEXEC)}<0{return Err("cannot confine actual profile7 inherited role before Program".into());}Ok(())}
pub(in crate::storage_driver::dispatcher) fn confine_profile7_baseline(authority:&VerifiedNativeAuthority)->Result<(),String>{
    if !valid_capsule(&authority.capsule){return Err("cannot confine foreign/non-v7 baseline as owned inventory".into());}
    confine(&authority._lease)?;confine(&authority._capsule_file)
    // Control is already confined by live::install; original cgroup is
    // confined by its DISTINCT v7 loader, remaining19(max) by the context.
}

/// Child-side v7 proof: protected private launch + actual original cgroup +
/// original Watch pidfd/proc + actual mount/block/ns roles. No serde/default/
/// raw capability constructor and no terminal-v6 permission/type conversion.
pub(in crate::storage_driver) struct InheritedOwnedPoolInventory {
    identity:live::JobIdentity,scope:ExpectedAttachScope,table:InventoryRoleTable,namespace:File,pidfd:File,proc:File,
    members:Vec<(File,File)>,deadline:Instant,failed:AtomicBool,budget:super::super::super::ResourceBudget,
}
impl InheritedOwnedPoolInventory {
    fn from_actual_inherited(authority:&VerifiedNativeAuthority,deadline:Instant)->Result<Self,String>{
        if !valid_capsule(&authority.capsule){return Err("not the distinct actual inherited profile7 authority".into());}
        let payload:OwnedAttachPayload=serde_json::from_value(authority.capsule.payload.config.clone()).map_err(|_|"actual profile7 roles malformed")?;
        let(peer,control)=live::owned_inventory_parent_identity()?;
        payload.roles.validate(&payload.attachment.scope,Some([authority._lease.as_raw_fd(),authority._capsule_file.as_raw_fd(),control]))?;
        origin::verify_borrowed_pair(payload.roles.watch_pidfd,payload.roles.watch_proc,&payload.roles.watch,peer)?;
        #[cfg(not(target_os="linux"))]{let _=deadline;return Err("profile7 requires Linux original kernel roles".into());}
        #[cfg(target_os="linux")]{
            // Raw numbers are joined to the protected exact table BEFORE
            // ownership is taken. Wrong roles must not close unrelated FDs.
            let mut namespace:libc::stat=unsafe{std::mem::zeroed()};let mut fs:libc::statfs=unsafe{std::mem::zeroed()};
            if unsafe{libc::fstat(payload.roles.namespace_fd,&mut namespace)}!=0||unsafe{libc::fstatfs(payload.roles.namespace_fd,&mut fs)}!=0
                ||fs.f_type as u64!=0x6e736673||unsafe{libc::ioctl(payload.roles.namespace_fd,0xb703)}!=libc::CLONE_NEWNS
                ||(namespace.st_dev as u64,namespace.st_ino as u64)!=payload.roles.namespace{
                return Err("profile7 original namespace descriptor/type/incarnation differs".into());}
            for member in &payload.roles.members{for(raw,expected)in [(member.mounted_fd,&member.observation.original_mounted),(member.block_fd,&member.observation.original_block)]{
                let mut m:libc::stat=unsafe{std::mem::zeroed()};
                if unsafe{libc::fstat(raw,&mut m)}!=0||(m.st_dev as u64,m.st_ino as u64,m.st_rdev as u64,m.st_mode as u32)
                    !=(expected.device,expected.inode,expected.rdev,expected.mode){return Err("profile7 inherited member role is not SAME original File incarnation".into());}
            }}
            let namespace=unsafe{File::from_raw_fd(payload.roles.namespace_fd)};confine(&namespace)?;
            let pidfd=unsafe{File::from_raw_fd(payload.roles.watch_pidfd)};confine(&pidfd)?;
            let proc=unsafe{File::from_raw_fd(payload.roles.watch_proc)};confine(&proc)?;
            let mut members=Vec::new();
            for member in &payload.roles.members{let mount=unsafe{File::from_raw_fd(member.mounted_fd)};confine(&mount)?;
                let block=unsafe{File::from_raw_fd(member.block_fd)};confine(&block)?;members.push((mount,block));}
            let value=Self{identity:authority.capsule.identity.clone(),scope:payload.attachment.scope,table:payload.roles,namespace,pidfd,proc,members,deadline,failed:AtomicBool::new(false),budget:authority.capsule.budget.clone()};
            value.require_kernel_current()?;Ok(value)
        }
    }
    pub(in crate::storage_driver) fn deadline(&self)->Instant{self.deadline}
    pub(in crate::storage_driver) fn scope(&self)->&ExpectedAttachScope{&self.scope}
    pub(in crate::storage_driver) fn table(&self)->&InventoryRoleTable{&self.table}
    pub(in crate::storage_driver) fn require_kernel_current(&self)->Result<(),String>{
        let result=(||{
            if self.failed.load(Ordering::Acquire)||Instant::now()>=self.deadline||BootId::current()?.as_str()!=self.identity.boot_id{
                return Err("actual profile7 original budget/boot/UNKNOWN".into());}
            live::attachment_channel_identity(&self.identity)?;
            live::owned_inventory_cgroup_current(&self.identity,self.table.cgroup_identity,&self.budget)?;
            origin::verify_retained_pair(&self.pidfd,&self.proc,&self.table.watch)?;
            #[cfg(not(target_os="linux"))]{return Err("profile7 actual kernel checks require Linux".into());}
            #[cfg(target_os="linux")]{
                let raw=unsafe{libc::syscall(libc::SYS_gettid)};let tid=u32::try_from(raw).map_err(|_|"actual helper TID overflow")?;
                origin::require_same_files(std::process::id(),tid)?;
                if super::super::super::replica::initialize::managed_mount::terminal::namespace_identity(&self.namespace)?!=self.table.namespace{
                    return Err("profile7 original held namespace changed".into());}
                let current=File::open("/proc/self/ns/mnt").map_err(|_|"actual current helper namespace unavailable")?;
                if super::super::super::replica::initialize::managed_mount::terminal::namespace_identity(&current)?!=self.table.namespace{
                    return Err("actual helper moved from original Watch namespace".into());}
                for(index,(mount,block))in self.members.iter().enumerate(){let row=&self.table.members[index];
                    let a=mount.metadata().map_err(|_|"inherited actual mounted File disappeared")?;
                    let b=block.metadata().map_err(|_|"inherited actual block File disappeared")?;
                    if (a.dev(),a.ino(),a.rdev(),a.mode())!=(row.observation.original_mounted.device,row.observation.original_mounted.inode,row.observation.original_mounted.rdev,row.observation.original_mounted.mode)
                        ||(b.dev(),b.ino(),b.rdev(),b.mode())!=(row.observation.original_block.device,row.observation.original_block.inode,row.observation.original_block.rdev,row.observation.original_block.mode){
                        return Err("actual inherited original member descriptors changed".into());}
                }
                origin::require_same_files(std::process::id(),tid)?;
                origin::verify_retained_pair(&self.pidfd,&self.proc,&self.table.watch)
            }
        })();if result.is_err(){self.failed.store(true,Ordering::Release);}result
    }
    pub(in crate::storage_driver) fn before_inventory(&self,operation:InventoryOperation)->Result<(),String>{
        self.require_kernel_current()?;
        live::before_owned_inventory(&self.identity,operation.boundary(),&operation.detail(&self.table)?)?;
        self.require_kernel_current()
    }
    pub(in crate::storage_driver) fn reobserve_members(&self)->Result<(),String>{
        self.require_kernel_current()?;
        for(index,(mounted,block))in self.members.iter().enumerate(){
            super::super::super::replica::initialize::managed_mount::inventory::verify_inherited_member(mounted,block,&self.table.members[index].observation)?;
        }self.require_kernel_current()
    }
    pub(in crate::storage_driver) fn verify_represented_table(&self,tgid:u32,tid:u32,namespace:(u64,u64))->Result<(),String>{
        self.require_kernel_current()?;
        if namespace!=self.table.namespace{return Err("managed reference from another actual namespace".into());}
        if tgid==self.table.watch.pid(){origin::require_same_files(self.table.watch.pid(),tid)?;}
        else if tgid==std::process::id(){origin::require_same_files(tgid,tid)?;}
        else{return Err("managed reference is not original pinned Watch or exact inherited helper".into());}
        self.require_kernel_current()
    }
    pub(in crate::storage_driver) fn represented_reference(&self,tgid:u32,number:i32,m:&std::fs::Metadata)->Result<bool,String>{
        for member in &self.table.members{
            let watch=tgid==self.table.watch.pid();let own=tgid==std::process::id();
            for(original,duplicate)in [(&member.observation.original_mounted,member.mounted_fd),(&member.observation.original_block,member.block_fd)]{
                let represented=watch&&(number==original.number||number==duplicate)||own&&number==duplicate;
                if represented{
                    if (m.dev(),m.ino(),m.rdev(),m.mode())!=(original.device,original.inode,original.rdev,original.mode){
                        return Err("represented Watch/helper slot is not SAME exact original File".into());}return Ok(true);
                }
            }
        }Ok(false)
    }
    pub(in crate::storage_driver) fn potential_reference(&self,tgid:u32,number:i32)->bool{
        self.table.members.iter().any(|member|{
            tgid==self.table.watch.pid()&&[member.observation.original_mounted.number,member.observation.original_block.number,
                member.mounted_fd,member.block_fd].contains(&number)
            ||tgid==std::process::id()&&[member.mounted_fd,member.block_fd].contains(&number)
        })
    }
}
impl VerifiedAttachPhase {
    pub(in crate::storage_driver) fn from_owned_inventory_inherited(authority:&VerifiedNativeAuthority)->Result<(Self,super::super::super::Config),String>{
        if !valid_capsule(&authority.capsule){return Err("not distinct inherited profile7 attach phase".into());}
        let payload:OwnedAttachPayload=serde_json::from_value(authority.capsule.payload.config.clone()).map_err(|_|"invalid exact profile7 attach payload")?;
        let remaining=authority.capsule.payload.worker_remaining_ms.ok_or("original profile7 remaining budget absent")?;
        let deadline=Instant::now().checked_add(Duration::from_millis(remaining)).ok_or("profile7 budget overflow")?;
        let inventory=InheritedOwnedPoolInventory::from_actual_inherited(authority,deadline)?;
        let p=payload.attachment;
        Ok((Self{identity:authority.capsule.identity.clone(),scope:p.scope,step:p.step,deadline,
            publication:p.publication,existing_anchor:p.existing_anchor,owned_inventory:Some(inventory)},p.pool))
    }
}
pub(in crate::storage_driver) fn total_roles(mounted:usize)->Result<usize,String>{
    if mounted>MAX_MEMBERS{return Err("owned inventory exceeds actual8 LIVE bound".into());}
    Ok(BASELINE_ROLES+ORIGINAL_CGROUP_ROLES+WATCH_PROOF_ROLES+SHARED_NAMESPACE_ROLES+2*mounted)
}
fn capture_peak(members:usize)->Result<u64,String>{
    // Excludes descriptors ALREADY included in the fresh actual count.
    // 4+2M new held roles; future capsule1/image1/control2/procs1/observer1;
    // spawn upper bound stdout/stderr PIPE4 +stdin-null1 +exec-error PIPE2;
    // readonly origin observer peak2 +atomic evidence temp1. Conservative
    // sum (not a claim all are concurrent), M8 =>36 ADDITIONAL descriptors.
    Ok(u64::try_from(total_roles(members)?-BASELINE_ROLES+6+7+2+1).map_err(|_|"profile7 descriptor peak overflow")?)
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::storage_driver) struct MemberRoleData {
    pub(in crate::storage_driver) observation:InventoryMemberObservation,
    pub(in crate::storage_driver) mounted_fd:i32,pub(in crate::storage_driver) block_fd:i32,
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::storage_driver) struct InventoryRoleTable {
    pub(in crate::storage_driver) domain:String,pub(in crate::storage_driver) version:u32,
    pub(in crate::storage_driver) context_uid:Uid,pub(in crate::storage_driver) group_sha256:String,
    pub(in crate::storage_driver) source_scope_sha256:String,pub(in crate::storage_driver) round_uid:Uid,
    pub(in crate::storage_driver) namespace:(u64,u64),pub(in crate::storage_driver) namespace_fd:i32,
    pub(in crate::storage_driver) watch:WatchProcessObservation,pub(in crate::storage_driver) watch_pidfd:i32,
    pub(in crate::storage_driver) watch_proc:i32,pub(in crate::storage_driver) members:Vec<MemberRoleData>,
    pub(in crate::storage_driver) cgroup_fd:i32,pub(in crate::storage_driver) cgroup_identity:(u64,u64),
    pub(in crate::storage_driver) delegated_root:std::path::PathBuf,
    pub(in crate::storage_driver) live_members:Vec<crate::storage_lifecycle::generation::VirginReplicaRef>,
}
struct ProcessRoles {pidfd:Option<Arc<File>>,proc:Option<Arc<File>>,observation:WatchProcessObservation}
/// Strongly root this BEFORE fallible role capture; no Clone/Serde/default/raw
/// constructor. All same-book members remain in the roots even when unmounted.
pub(crate) struct RootedOwnedPoolInventory {
    uid:Uid,owner:Arc<AttachOwner>,parent:Arc<VerifiedAttachParent>,step:AttachNativeStep,
    roots:SameGroupInventoryRoots,slots:Vec<Arc<InventoryMemberSlot>>,
    present:Mutex<Vec<Option<bool>>>,namespace:Mutex<Option<Arc<File>>>,watch:Mutex<Option<ProcessRoles>>,
    cgroup:Mutex<Option<Arc<File>>>,table:Mutex<Option<InventoryRoleTable>>,
    native:Mutex<Option<live::JobIdentity>>,failed:AtomicBool,retired:AtomicBool,budget:super::super::super::ResourceBudget,
}
impl RootedOwnedPoolInventory {
    fn latch(&self){self.failed.store(true,Ordering::Release);self.parent.retain_unknown();}
    pub(crate) fn retain_unknown(&self){self.latch();}
    pub(crate) fn uid(&self)->&Uid{&self.uid}
    pub(in crate::storage_driver) fn is_retired(&self)->bool{self.retired.load(Ordering::Acquire)&&!self.failed.load(Ordering::Acquire)}
    fn retire_after_actual_drain(&self,drain:&VerifiedAttachDrain)->Result<(),String>{
        let result=(||{
            drain.require_parent(&self.parent)?;self.require_native(&drain.identity)?;
            if drain.inventory.as_ref().is_none_or(|c|!std::ptr::eq(Arc::as_ptr(c),self))||drain.step!=self.step{
                return Err("not this SAME supervised profile7 child/context drain".into());}
            drain.diagnostic.validate(drain.scope(),drain.step())?;
            // Actual supervisor already established Child terminal + both
            // bounded EOF + original cgroup/resource drain before construction.
            // No close before these opaque facts; never on caller/error Drop.
            let mut namespace=self.namespace.lock().map_err(|_|"inventory namespace retirement poisoned")?;
            let mut watch=self.watch.lock().map_err(|_|"inventory proof retirement poisoned")?;
            let mut cgroup=self.cgroup.lock().map_err(|_|"inventory cgroup retirement poisoned")?;
            for slot in &self.slots{slot.retire_duplicates()?;}
            namespace.take();watch.take();cgroup.take();self.retired.store(true,Ordering::Release);Ok(())
        })();if result.is_err(){self.latch();}result
    }
    pub(crate) fn native_data(&self)->Result<crate::storage_remote_protocol::attachment::owned_inventory::InventoryNativeData,String>{
        use crate::storage_remote_protocol::attachment::owned_inventory::InventoryNativeData;
        let native=self.native.lock().map_err(|_|"actual profile7 native state poisoned")?;
        let n=native.as_ref().ok_or("profile7 actual native is not bound")?;
        Ok(InventoryNativeData{node_uid:n.node_uid.clone(),boot_id:n.boot_id.clone(),volume_uid:n.volume_uid.clone(),
            operation_uid:n.operation_uid.clone(),attempt_uid:n.attempt_uid.clone(),binding_sha256:n.binding_sha256.clone()})
    }
    pub(crate) fn require_native_data(&self,data:&crate::storage_remote_protocol::attachment::owned_inventory::InventoryNativeData)->Result<(),String>{
        self.require_native_data_pure(data)?;self.require_current()
    }
    /// No kernel/World/book IO. Used only while the existing protocol mutex
    /// validates framing; caller performs full actual checks OUTSIDE it.
    pub(crate) fn require_native_data_pure(&self,data:&crate::storage_remote_protocol::attachment::owned_inventory::InventoryNativeData)->Result<(),String>{
        if self.failed.load(Ordering::Acquire)||self.retired.load(Ordering::Acquire){return Err("actual inventory root failed/retired".into());}
        data.require_exact(&self.native_data()?)
    }
    pub(crate) fn require_boundary_pure(&self,boundary:&VerifiedLocalBoundary)->Result<(),String>{
        if self.failed.load(Ordering::Acquire)||self.retired.load(Ordering::Acquire){return Err("actual inventory context failed/retired".into());}
        let identity=self.native.lock().map_err(|_|"actual profile7 native state poisoned")?.clone().ok_or("actual profile7 native absent")?;
        boundary.require_native_identity(&identity)
    }
    pub(crate) fn require_boundary(&self,boundary:&VerifiedLocalBoundary)->Result<(),String>{
        self.require_boundary_pure(boundary)?;self.require_current()
    }
    pub(crate) fn scope(&self)->&ExpectedAttachScope{self.parent.scope()}
    pub(crate) fn parent(&self)->&Arc<VerifiedAttachParent>{&self.parent}
    pub(crate) fn step(&self)->AttachNativeStep{self.step}
    pub(in crate::storage_driver) fn table(&self)->Result<InventoryRoleTable,String>{
        if self.failed.load(Ordering::Acquire)||self.retired.load(Ordering::Acquire){return Err("owned inventory failed/retired; no reuse".into());}
        self.table.lock().map_err(|_|"actual inventory table poisoned")?.clone().ok_or("actual inventory role capture incomplete".into())
    }
    pub(crate) fn commitment(&self)->Result<String,String>{
        Ok(hash(&serde_json::to_vec(&self.table()?).map_err(|_|"actual full inventory table binding")?))
    }
    pub(in crate::storage_driver) fn bind_native(&self,identity:&live::JobIdentity)->Result<(),String>{
        self.require_current()?;
        if identity.node_uid!=self.scope().phase_node_uid||identity.boot_id!=self.scope().phase_boot.as_str()
            ||identity.volume_uid!=self.scope().owner.volume_uid||identity.operation_uid!=*self.scope().mount_ref.operation_uid(){
            return Err("profile7 actual native identity differs from original current scope".into());}
        let mut native=self.native.lock().map_err(|_|"actual inventory native root poisoned")?;
        if native.is_some(){return Err("owned inventory actual native already bound; no rebind/retry".into());}
        *native=Some(identity.clone());Ok(())
    }
    pub(in crate::storage_driver) fn require_native(&self,identity:&live::JobIdentity)->Result<(),String>{
        if self.native.lock().map_err(|_|"actual inventory native state poisoned")?.as_ref()!=Some(identity){
            return Err("owned inventory is not SAME bound actual v7 native attempt".into());}self.require_current()
    }
    /// Local negative observations only. Fresh InventoryRead authorization is
    /// separately performed with no book/resource/probe/World guards retained.
    pub(crate) fn require_current(&self)->Result<(),String>{
        let result=(||{
            if self.failed.load(Ordering::Acquire)||self.retired.load(Ordering::Acquire){return Err("actual inventory UNKNOWN/retired".into());}
            self.owner.require_registered_parent(&self.parent)?;
            self.roots.require_current(&self.parent)?;self.owner.require_actual_watch_files()?;
            let namespace=self.namespace.lock().map_err(|_|"actual inventory namespace poisoned")?.clone().ok_or("original namespace role absent")?;
            let table=self.table.lock().map_err(|_|"actual inventory table poisoned")?.clone();
            if let Some(table)=table{
                let original={self.owner.resources.lock().map_err(|_|"actual inventory cgroup provenance poisoned")?.terminal_cgroup.clone().ok_or("actual original cgroup provenance absent")?};
                let role=self.cgroup.lock().map_err(|_|"actual inventory cgroup role poisoned")?.clone().ok_or("actual inherited cgroup role missing")?;
                let m=role.metadata().map_err(|_|"actual original cgroup role metadata unavailable")?;
                if original.identity()?!=table.cgroup_identity||(m.dev(),m.ino())!=table.cgroup_identity{
                    return Err("actual original profile7 cgroup FD incarnation changed".into());}
                original.resource_snapshot(&self.budget)?;
                if super::super::super::replica::initialize::managed_mount::terminal::namespace_identity(namespace.as_ref())?!=table.namespace{
                    return Err("actual original inventory namespace FD changed".into());}
                let roles={let state=self.watch.lock().map_err(|_|"actual inventory proof roles poisoned")?;
                    let p=state.as_ref().ok_or("actual Watch process roles absent")?;
                    (p.pidfd.clone().ok_or("partial actual Watch pidfd role")?,p.proc.clone().ok_or("partial actual Watch proc role")?,p.observation.clone())};
                origin::verify_retained_pair(roles.0.as_ref(),roles.1.as_ref(),&roles.2)?;
                let present=self.present.lock().map_err(|_|"actual member disposition poisoned")?.clone();
                for(index,member)in self.roots.members().iter().enumerate(){
                    let observed=if present[index]==Some(true){Some(self.slots[index].files()?.2)}else if present[index]==Some(false){None}
                        else{return Err("actual inventory member disposition incomplete".into());};
                    member.require_inventory_group_member(&self.parent)?;
                    member.probe.lock().map_err(|_|"actual inventory member probe poisoned")?
                        .compare_owned_inventory_member(&self.parent,member.scope(),observed.as_ref())?;
                }
            }
            self.roots.require_current(&self.parent)?;self.owner.require_actual_watch_files()
        })();if result.is_err(){self.latch();}result
    }
}
impl AttachOwner {
    pub(in crate::storage_driver) fn prepare_owned_pool_inventory(self:&Arc<Self>,parent:Arc<VerifiedAttachParent>,step:AttachNativeStep,config:&Config)
        ->Result<Arc<RootedOwnedPoolInventory>,String>{
        self.require_registered_parent(&parent)?;
        if config.node_uid!=parent.scope().phase_node_uid{return Err("inventory actual dispatcher node differs".into());}
        let roots=parent.root_book().same_group_inventory(&parent)?;
        let count=roots.members().len();
        let value=Arc::new(RootedOwnedPoolInventory{uid:Uid::new(),owner:self.clone(),parent:parent.clone(),step,roots,
            slots:(0..count).map(|_|Arc::new(InventoryMemberSlot::empty())).collect(),present:Mutex::new(vec![None;count]),
            namespace:Mutex::new(None),watch:Mutex::new(None),cgroup:Mutex::new(None),table:Mutex::new(None),native:Mutex::new(None),
            failed:AtomicBool::new(false),retired:AtomicBool::new(false),budget:config.budget.clone()});
        {
            let mut state=self.resources.lock().map_err(|_|"actual inventory root owner poisoned")?;
            if state.inventory_contexts.len()>=128||state.inventory_contexts.last().is_some_and(|c|!c.retired.load(Ordering::Acquire)){
                return Err("previous actual inventory context unresolved/attempt bound reached".into());}
            state.inventory_contexts.push(value.clone()); // ROOT BEFORE any new FD
        }
        let result=(||{
            origin::require_descriptor_headroom(capture_peak(count)?)?;
            let original=self.watch_process.lock().map_err(|_|"original Watch namespace poisoned")?.retained_namespace(&self.scope.phase_boot)?;
            let duplicated=Arc::new(original.try_clone().map_err(|_|"actual shared namespace role duplicate")?);
            *value.namespace.lock().unwrap_or_else(|p|p.into_inner())=Some(duplicated.clone());
            let observation=self.watch_process.lock().map_err(|_|"actual Watch origin poisoned")?.observation()?.clone();
            *value.watch.lock().unwrap_or_else(|p|p.into_inner())=Some(ProcessRoles{pidfd:None,proc:None,observation});
            self.watch_process.lock().map_err(|_|"actual Watch origin poisoned")?.duplicate_for_owned_inventory(&self.scope.phase_boot,|is_proc,file|{
                let mut state=value.watch.lock().unwrap_or_else(|p|p.into_inner());let roles=state.as_mut().unwrap();
                if is_proc{roles.proc=Some(Arc::new(file));}else{roles.pidfd=Some(Arc::new(file));}
            })?;
            let cgroup={self.resources.lock().map_err(|_|"actual original cgroup root poisoned")?.terminal_cgroup.clone().ok_or("actual original cgroup absent")?};
            let duplicate=Arc::new(cgroup.retained_directory_for_owned_inventory()?);
            *value.cgroup.lock().unwrap_or_else(|p|p.into_inner())=Some(duplicate);
            let mut members=Vec::new();
            for(index,member)in value.roots.members().iter().enumerate(){
                member.require_inventory_group_member(&parent)?;
                let present=member.probe.lock().map_err(|_|"actual inventory capture probe poisoned")?
                    .capture_owned_inventory_member(&parent,member.scope(),&value.slots[index])?;
                value.present.lock().unwrap_or_else(|p|p.into_inner())[index]=Some(present);
                if present{let(m,b,observation)=value.slots[index].files()?;members.push(MemberRoleData{observation,mounted_fd:m.as_raw_fd(),block_fd:b.as_raw_fd()});}
            }
            total_roles(members.len())?;
            let watch=value.watch.lock().map_err(|_|"actual Watch proof root poisoned")?.as_ref().ok_or("actual Watch roles absent")?.observation.clone();
            let(pidfd,proc)={let s=value.watch.lock().map_err(|_|"actual Watch proof root poisoned")?;let p=s.as_ref().unwrap();
                (p.pidfd.as_ref().ok_or("partial actual pidfd role")?.as_raw_fd(),p.proc.as_ref().ok_or("partial actual proc role")?.as_raw_fd())};
            let namespace=super::super::super::replica::initialize::managed_mount::terminal::namespace_identity(duplicated.as_ref())?;
            let(cgroup_fd,cgroup_identity)={let state=value.cgroup.lock().map_err(|_|"actual inventory cgroup role poisoned")?;
                let fd=state.as_ref().ok_or("actual cgroup duplicate absent")?;let m=fd.metadata().map_err(|_|"actual cgroup duplicate metadata unavailable")?;
                (fd.as_raw_fd(),(m.dev(),m.ino()))};
            let table=InventoryRoleTable{domain:DOMAIN.into(),version:1,context_uid:value.uid.clone(),group_sha256:value.roots.commitment().into(),
                source_scope_sha256:scope_digest(parent.scope())?,round_uid:parent.scope().round_uid.clone(),namespace,namespace_fd:duplicated.as_raw_fd(),
                watch,watch_pidfd:pidfd,watch_proc:proc,members,cgroup_fd,cgroup_identity,
                delegated_root:config.delegated_cgroup_root.clone(),live_members:value.roots.members().iter().map(|member|
                    member.scope().generation.virgin_replicas.iter().find(|f|f.node_uid==parent.scope().phase_node_uid).cloned()
                        .ok_or_else(||"actual local same-book inventory fact absent".to_string())).collect::<Result<Vec<_>,_>>()?};
            *value.table.lock().unwrap_or_else(|p|p.into_inner())=Some(table);
            value.require_current()?;Ok(value.clone())
        })();if result.is_err(){value.latch();}result
    }
}
