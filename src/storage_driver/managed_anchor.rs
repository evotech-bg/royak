//! Fixed service-anchor observation and bootstrap, never a generic mount API.
//! Dedicated-VM root trust is an explicit external execution boundary. This
//! census does NOT prove absence of PIDless/adversarially hidden namespaces.
use super::*;
use crate::storage_driver::dispatcher::attachment::VerifiedAttachPhase;
use crate::storage_driver::dispatcher::attachment::terminal::VerifiedReferenceCensusContext;
use serde::Serialize;
use serde::Deserialize;
use std::os::unix::fs::FileTypeExt;
use std::sync::{Arc,Mutex,OnceLock};
#[cfg(target_os="linux")]
use std::os::fd::AsRawFd;
pub(super) const ANCHOR:&str="/var/lib/royak/storage/mounts";
const BASE:&str="/var/lib/royak/storage";
const MAX_TASKS:usize=16384;
const MAX_FDS:usize=4096;
const MAX_TOTAL_FDS:usize=65536;
const MAX_NAMESPACES:usize=64;
const MAX_MOUNTINFO_BYTES:usize=4*1024*1024;

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::storage_driver) struct AnchorMountObservation {
    pub(in crate::storage_driver) boot:crate::storage_boot::BootId,
    pub(in crate::storage_driver) namespace:(u64,u64),
    pub(in crate::storage_driver) device:u64,
    pub(in crate::storage_driver) inode:u64,
    pub(in crate::storage_driver) mount_id:u64,
    pub(in crate::storage_driver) major:u32,
    pub(in crate::storage_driver) minor:u32,
    pub(in crate::storage_driver) preserved_mountinfo_sha256:String,
}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::storage_driver) struct OwnedAnchorReference {
    anchor:AnchorMountObservation,node_uid:Uid,owned_mounts:std::collections::BTreeMap<String,MountObservation>,
}
/// One real Watch lifetime, not reconstructed after restart or from a receipt.
/// The index describes only actual installed submounts, never writer authority.
struct AnchorLifetime {anchor:File,namespace:File,node_uid:Uid,observation:AnchorMountObservation,
    mounts:Mutex<std::collections::BTreeMap<String,MountObservation>>,
    retired:Mutex<std::collections::BTreeMap<String,(Uid,MountObservation)>>}
static ROOTED_ANCHOR:OnceLock<Arc<AnchorLifetime>>=OnceLock::new();

#[derive(Serialize)]
pub(crate) struct AnchorDiagnostic {
    kind:&'static str,boot:crate::storage_boot::BootId,
    namespace:(u64,u64),anchor_present:bool,anchor_empty:bool,
    tasks:Vec<TaskObservation>,namespaces:Vec<NamespaceObservation>,
    unrepresented_namespace_fds:Vec<(u32,u32,u64)>,
    affected:Vec<AffectedPlace>,bootstrap_preconditions_satisfied:bool,
    limitations:&'static str,actuation_authorized:bool,
}
#[derive(Serialize)]
struct TaskObservation {tgid:u32,tid:u32,start_ticks:u64,namespace:(u64,u64),namespace_fds:Vec<u64>,
    descriptor_count:usize,descriptor_targets_sha256:String}
#[derive(Serialize)]
struct NamespaceObservation {identity:(u64,u64),representative_tid:u32,mountinfo_sha256:String,rows:usize}
#[derive(Serialize)]
struct AffectedPlace {namespace:(u64,u64),mount_id:u64,target:String,root:String,optional:Vec<String>}
struct HeldNamespace {file:File,identity:(u64,u64),tid:u32,mountinfo:String}
#[derive(Clone,Copy)]
enum AnchorPathStage {BaseOnly,BeforeBind,AfterNewBind}

/// Keep every original reference inside a root-owned Watch/worker object.
/// No returned diagnostic can reconstruct this object or authorize bootstrap.
pub(in crate::storage_driver) struct AnchorProbe {
    attempted:bool,unknown:bool,namespace:Option<File>,base:Option<File>,
    anchor:Option<File>,fresh_anchor:Option<File>,namespaces:Vec<HeldNamespace>,
    base_fresh:Option<File>,path_anchor_fresh:Option<File>,
    observation:Option<AnchorDiagnostic>,original_mountinfo:Option<String>,
    boot:Option<crate::storage_boot::BootId>,deadline:Option<Instant>,
    rechecks:Vec<AnchorProbe>,
    rooted_existing:Option<Arc<AnchorLifetime>>,validated_existing:Option<OwnedAnchorReference>,
    observation_deadline:Option<Instant>,
}
impl AnchorProbe {
    pub(in crate::storage_driver) fn empty()->Self {Self {attempted:false,unknown:false,
        namespace:None,base:None,anchor:None,fresh_anchor:None,namespaces:Vec::new(),base_fresh:None,path_anchor_fresh:None,
        observation:None,original_mountinfo:None,boot:None,deadline:None,rechecks:Vec::new(),
        rooted_existing:None,validated_existing:None,observation_deadline:None}}
    fn within_observation_budget(&self)->Result<(),String> {
        if self.observation_deadline.is_some_and(|deadline|Instant::now()>=deadline){return Err("original read-only census budget expired; no later effect".into());}Ok(())
    }
    pub(in crate::storage_driver) fn observe_within(&mut self,deadline:Instant)->Result<&AnchorDiagnostic,String> {
        if self.attempted || self.observation_deadline.is_some(){return Err("census budget cannot reset/renew".into());}
        self.observation_deadline=Some(deadline);self.within_observation_budget()?;self.observe_once()
    }
    pub(in crate::storage_driver) fn observe_for_owner(&mut self,scope:&ExpectedAttachScope,deadline:Instant)->Result<(),String> {
        if self.attempted || self.unknown {return Err("anchor owner already attempted/UNKNOWN".into());}
        if let Some(actual)=ROOTED_ANCHOR.get(){
            self.attempted=true;self.rooted_existing=Some(actual.clone());
            let result=actual.reference(scope,deadline).map(|reference|self.validated_existing=Some(reference));
            if result.is_err(){self.unknown=true;}result
        }else{self.observe_within(deadline).map(|_|())}
    }
    pub(in crate::storage_driver) fn reference(&self,scope:&ExpectedAttachScope,deadline:Instant)->Result<Option<OwnedAnchorReference>,String> {
        if self.unknown{return Err("actual anchor owner UNKNOWN".into());}
        self.rooted_existing.as_ref().map(|root|root.reference(scope,deadline)).transpose()
    }
    #[cfg(target_os="linux")]
    fn inspect(&mut self)->Result<AnchorDiagnostic,String> {
        use std::os::fd::AsRawFd;
        if unsafe{libc::geteuid()}!=0 {return Err("anchor observation requires local Linux root".into());}
        self.namespace=Some(open_current_namespace()?);
        let namespace=fd_identity(self.namespace.as_ref().unwrap())?;
        self.boot=Some(crate::storage_boot::BootId::current()?);
        self.base=Some(open_reserved_base()?);
        self.anchor=optional_anchor(self.base.as_ref().unwrap())?;
        let anchor_empty=match self.anchor.as_ref() {Some(fd)=>entries(fd,2)?.is_empty(),None=>true};
        let proc=owned_fd(unsafe{libc::open(c"/proc".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
        require_fs(&proc,0x9fa0)?;
        let mut tasks=Vec::new();let mut by_namespace=std::collections::BTreeMap::new();let mut total_fds=0usize;
        for pid in entries(&proc,MAX_TASKS)? {
            self.within_observation_budget()?;
            let Some(tgid)=decimal(&pid) else {continue};
            let process=open_directory_at(&proc,&pid)?;
            let task=open_directory_at(&process,"task")?;
            for name in entries(&task,MAX_TASKS)? {
                self.within_observation_budget()?;
                let tid=decimal(&name).ok_or("unexpected non-task directory in actual procfs")?;
                if tasks.len()>=MAX_TASKS {return Err("anchor task census exceeds fixed bound".into());}
                let actual=open_directory_at(&task,&name)?;
                let before=read_at(&actual,"stat",8192)?;let start_ticks=task_start(&before,tid)?;
                let ns=open_namespace_at(&actual)?;let identity=fd_identity(&ns)?;
                if !by_namespace.contains_key(&identity) {
                    let raw=String::from_utf8(read_at(&actual,"mountinfo",1024*1024)?).map_err(|_|"mountinfo not UTF8")?;
                    if self.namespaces.len()>=MAX_NAMESPACES || self.namespaces.iter().map(|h|h.mountinfo.len()).sum::<usize>()+raw.len()>MAX_MOUNTINFO_BYTES {
                        return Err("bounded namespace graph exhausted; no bootstrap".into());
                    }
                    parse_mounts(&raw)?;
                    self.namespaces.push(HeldNamespace {file:ns,identity,tid,mountinfo:raw});
                    by_namespace.insert(identity,self.namespaces.len()-1);
                }
                let descriptors=open_directory_at(&actual,"fd")?;
                let (namespace_fds,descriptor_count,descriptor_targets_sha256)=namespace_fd_links(&descriptors,self.observation_deadline,
                    MAX_FDS.min(MAX_TOTAL_FDS.saturating_sub(total_fds)))?;
                total_fds=total_fds.checked_add(descriptor_count).ok_or("descriptor census count overflow")?;
                if task_start(&read_at(&actual,"stat",8192)?,tid)?!=start_ticks {
                    return Err("task incarnation changed during namespace census".into());
                }
                tasks.push(TaskObservation {tgid,tid,start_ticks,namespace:identity,namespace_fds,descriptor_count,descriptor_targets_sha256});
            }
        }
        let mut unrepresented=Vec::new();
        for task in &tasks {for inode in &task.namespace_fds {
            if !by_namespace.keys().any(|(_,value)|value==inode) {unrepresented.push((task.tgid,task.tid,*inode));}
        }}
        let raw=String::from_utf8(read_at_thread("mountinfo",1024*1024)?).map_err(|_|"current mountinfo not UTF8")?;
        let rows=parse_mounts(&raw)?;
        let covering=unique_covering(&rows,ANCHOR)?;
        let base_identity=observe_parent_kernel(self.base.as_ref().unwrap())?;
        let base_is_actual_covering=base_identity.mount_id==covering.id && base_identity.major==covering.major
            && base_identity.minor==covering.minor;
        let mut affected=Vec::new();
        for held in &self.namespaces {
            if fd_identity(&held.file)?!=held.identity {return Err("held namespace identity changed".into());}
            let observed=parse_mounts(&held.mountinfo)?;
            for row in observed.iter().filter(|row|row.major==covering.major && row.minor==covering.minor) {
                let filesystem_path=join_root(&covering.root,&covering.target,ANCHOR)?;
                if within(&filesystem_path,&row.root) {
                    let relative=filesystem_path.strip_prefix(&row.root).ok_or("alias relative root changed")?.trim_start_matches('/');
                    let target=if relative.is_empty(){row.target.clone()}else{format!("{}/{relative}",row.target.trim_end_matches('/'))};
                    affected.push(AffectedPlace {namespace:held.identity,mount_id:row.id,target,root:row.root.clone(),optional:row.optional.clone()});
                }
            }
        }
        let existing=rows.iter().filter(|row|within(&row.target,ANCHOR)).count();
        // Cross-namespace aliases are surfaced, not called foreign. This first
        // actuator does not enter/change service namespaces; they require a
        // separately reviewed exact owned affected-place producer.
        let safe_aliases=fixed_owned_affected(&affected,namespace);
        let bootstrap_preconditions_satisfied=anchor_empty && existing==0 && safe_aliases && base_is_actual_covering && !affected.is_empty()
            && known_propagation(&covering.optional) && unrepresented.is_empty() && rows.iter().filter(|r|r.target=="/").count()==1;
        if fd_identity(&open_current_namespace()?)?!=namespace || crate::storage_boot::BootId::current()?!=*self.boot.as_ref().unwrap() {
            return Err("actual namespace/boot changed across preflight".into());
        }
        self.original_mountinfo=Some(raw);
        self.within_observation_budget()?;
        let namespaces=self.namespaces.iter().map(|h|NamespaceObservation {identity:h.identity,representative_tid:h.tid,
            mountinfo_sha256:hash(h.mountinfo.as_bytes()),rows:parse_mounts(&h.mountinfo).map(|r|r.len()).unwrap_or(0)}).collect();
        Ok(AnchorDiagnostic {kind:"royak-owned-anchor-readonly-observation-v1",boot:self.boot.as_ref().unwrap().clone(),
            namespace,anchor_present:self.anchor.is_some(),anchor_empty,tasks,namespaces,
            unrepresented_namespace_fds:unrepresented,affected,bootstrap_preconditions_satisfied,
            limitations:"visible census under explicitly dedicated VM root trust; not universal PIDless namespace absence; host UUID/Home admitted separately by Root",
            actuation_authorized:false})
    }
    pub(in crate::storage_driver) fn observe_once(&mut self)->Result<&AnchorDiagnostic,String> {
        if self.attempted || self.unknown {return Err("anchor observation one-shot/UNKNOWN; no replacement".into());}
        self.attempted=true;
        #[cfg(not(target_os="linux"))]
        let result:Result<AnchorDiagnostic,String>=Err("anchor observation requires Linux; no fallback".into());
        #[cfg(target_os="linux")]
        let result=self.inspect();
        match result {Ok(value)=>{self.observation=Some(value);Ok(self.observation.as_ref().unwrap())},Err(e)=>{self.unknown=true;Err(e)}}
    }
    /// The only mutation entry takes the actual private inherited permit.
    /// Approval JSON is neither accepted nor read here. Every direct syscall
    /// gets a new request-bound parent authorization; no recursive flags.
    pub(in crate::storage_driver) fn bootstrap(&mut self,permit:&VerifiedAttachPhase)->Result<(),String> {
        let result=(|| {
            #[cfg(not(target_os="linux"))]
            {let _=permit;return Err("owned anchor bootstrap requires Linux".into());}
            #[cfg(target_os="linux")]
            {
                use std::os::fd::AsRawFd;
                if self.deadline.is_some() || self.unknown {return Err("anchor bootstrap already attempted/UNKNOWN".into());}
                self.deadline=Some(permit.deadline());
                permit.checkpoint()?;
                let observed=self.observation.as_ref().ok_or("anchor preflight absent")?;
                if !observed.bootstrap_preconditions_satisfied || observed.boot!=permit.scope().phase_boot
                    || permit.scope().phase!=crate::storage_lifecycle::pod_attachment::AttachPhase::Mount {
                    return Err("affected anchor ownership is not proved; no creation/fallback".into());
                }
                self.recheck_initial()?;self.recheck_census(None)?;
                self.recheck_base_path(AnchorPathStage::BaseOnly)?;
                if self.anchor.is_none() {
                    permit.before_anchor("create-empty-directory",None)?;
                    if unsafe{libc::mkdirat(self.base.as_ref().unwrap().as_raw_fd(),c"mounts".as_ptr(),0o700)}!=0 {
                        return Err("fixed empty anchor directory creation UNKNOWN; retain".into());
                    }
                    self.anchor=optional_anchor(self.base.as_ref().unwrap())?;
                }
                let identity=observe_parent_kernel(self.anchor.as_ref().ok_or("created anchor missing")?)?;
                if !entries(self.anchor.as_ref().unwrap(),2)?.is_empty() {return Err("anchor not empty before bind".into());}
                self.recheck_census(None)?;
                self.recheck_base_path(AnchorPathStage::BeforeBind)?;
                permit.before_anchor("bind-self",Some((identity.device,identity.inode,identity.mount_id)))?;
                let path=std::ffi::CString::new(ANCHOR).unwrap();
                if unsafe{libc::mount(path.as_ptr(),path.as_ptr(),std::ptr::null(),libc::MS_BIND,std::ptr::null())}!=0 {
                    return Err("owned anchor bind result UNKNOWN; no retry/rollback".into());
                }
                self.fresh_anchor=optional_anchor(self.base.as_ref().unwrap())?;
                let mounted=observe_parent_kernel(self.fresh_anchor.as_ref().ok_or("actual new anchor FD missing")?)?;
                if mounted.device!=identity.device || mounted.inode!=identity.inode || mounted.mount_id==identity.mount_id {
                    return Err("bind did not produce exact new owned mount identity".into());
                }
                self.recheck_census(Some(&mounted))?;
                self.recheck_base_path(AnchorPathStage::AfterNewBind)?;
                permit.before_anchor("make-private",Some((mounted.device,mounted.inode,mounted.mount_id)))?;
                if unsafe{libc::mount(std::ptr::null(),path.as_ptr(),std::ptr::null(),libc::MS_PRIVATE,std::ptr::null())}!=0 {
                    return Err("owned anchor MakePrivate UNKNOWN; no root/recursive fallback".into());
                }
                let after=read_mounts()?;
                let row=after.iter().filter(|r|r.target==ANCHOR).collect::<Vec<_>>();
                if row.len()!=1 || row[0].id!=mounted.mount_id || !row[0].optional.is_empty() {
                    return Err("new owned anchor is not exact private mount".into());
                }
                let before=parse_mounts(self.original_mountinfo.as_ref().unwrap())?;
                let old=after.into_iter().filter(|r|r.target!=ANCHOR).collect::<Vec<_>>();
                if old!=before {return Err("common-root/foreign mount graph changed; retain UNKNOWN".into());}
                permit.checkpoint()?;
                Ok(())
            }
        })();if result.is_err(){self.unknown=true;}result
    }
    pub(in crate::storage_driver) fn completed(&self)->Result<AnchorMountObservation,String> {
        #[cfg(not(target_os="linux"))]
        {return Err("actual completed anchor requires Linux".into());}
        #[cfg(target_os="linux")]
        {
            if self.unknown || Instant::now()>=self.deadline.ok_or("original bootstrap absent")? {
                return Err("anchor outcome partial/expired/UNKNOWN".into());
            }
            let file=self.fresh_anchor.as_ref().ok_or("actual new anchor not retained")?;
            if let Some(existing)=self.validated_existing.as_ref(){
                verify_reference(existing,file,self.namespace.as_ref().ok_or("actual existing namespace absent")?)?;
                return Ok(existing.anchor.clone());
            }
            let identity=observe_parent_kernel(file)?;let rows=read_mounts()?;
            let found=rows.iter().filter(|row|row.target==ANCHOR).collect::<Vec<_>>();
            if found.len()!=1 || found[0].id!=identity.mount_id || !found[0].optional.is_empty() {
                return Err("retained new anchor is not current exact private mount".into());
            }
            Ok(AnchorMountObservation {boot:crate::storage_boot::BootId::current()?,
                namespace:fd_identity(self.namespace.as_ref().ok_or("actual namespace absent")?)?,
                device:identity.device,inode:identity.inode,mount_id:identity.mount_id,
                major:identity.major,minor:identity.minor,
                preserved_mountinfo_sha256:hash(self.original_mountinfo.as_ref().ok_or("original mount graph absent")?.as_bytes())})
        }
    }
    /// Only the actual supervisor drain can select this installation path.
    /// Helper JSON alone cannot call it. The Watch reopens the NEW anchor FD.
    pub(in crate::storage_driver) fn install_from_actual_drain(&mut self,
        drain:&crate::storage_driver::dispatcher::attachment::VerifiedAttachDrain)->Result<(),String> {
        let result=(|| {
            #[cfg(not(target_os="linux"))]
            {let _=drain;return Err("anchor installation requires Linux".into());}
            #[cfg(target_os="linux")]
            {
                if self.unknown || !self.attempted || self.deadline.is_some() || self.fresh_anchor.is_some() {
                    return Err("original Watch anchor preflight absent/partial/already used".into());
                }
                if let Some(root)=self.rooted_existing.clone(){
                    let current=root.reference(drain.scope(),drain.deadline())?;
                    if &current.anchor!=drain.anchor_observation()? {return Err("existing actual Watch anchor differs from supervised observation".into());}
                    self.deadline=Some(drain.deadline());
                    self.namespace=Some(root.namespace.try_clone().map_err(|_|"cannot retain actual shared namespace reference")?);
                    self.fresh_anchor=Some(root.anchor.try_clone().map_err(|_|"cannot retain actual shared anchor reference")?);
                    self.validated_existing=Some(current);drain.checkpoint()?;return Ok(());
                }
                let original=self.observation.as_ref().ok_or("Watch anchor observation absent")?;
                let actual=drain.anchor_observation()?;
                if !original.bootstrap_preconditions_satisfied || actual.boot!=original.boot
                    || actual.namespace!=original.namespace || actual.preserved_mountinfo_sha256!=hash(self.original_mountinfo.as_ref().unwrap().as_bytes()) {
                    return Err("actual helper anchor differs from Watch's original preflight".into());
                }
                self.deadline=Some(drain.deadline());drain.checkpoint()?;
                self.fresh_anchor=optional_anchor(self.base.as_ref().ok_or("original base FD absent")?)?;
                let now=observe_parent_kernel(self.fresh_anchor.as_ref().ok_or("new anchor absent after real drain")?)?;
                if (now.device,now.inode,now.mount_id,now.major,now.minor)!=(actual.device,actual.inode,actual.mount_id,actual.major,actual.minor) {
                    return Err("Watch's NEW anchor FD differs from supervised child".into());
                }
                let rows=read_mounts()?;
                let found=rows.iter().filter(|r|r.target==ANCHOR).collect::<Vec<_>>();
                if found.len()!=1 || found[0].id!=now.mount_id || !found[0].optional.is_empty()
                    || rows.into_iter().filter(|r|r.target!=ANCHOR).collect::<Vec<_>>()!=parse_mounts(self.original_mountinfo.as_ref().unwrap())? {
                    return Err("actual anchor is not the only exact private addition".into());
                }
                if fd_identity(&open_current_namespace()?)?!=actual.namespace || crate::storage_boot::BootId::current()?!=actual.boot {
                    return Err("anchor namespace/current boot changed".into());
                }
                drain.checkpoint()?;
                let root=Arc::new(AnchorLifetime {anchor:self.fresh_anchor.as_ref().unwrap().try_clone().map_err(|_|"retain actual anchor lifetime")?,
                    namespace:self.namespace.as_ref().ok_or("actual original namespace absent")?.try_clone().map_err(|_|"retain actual anchor namespace")?,
                    node_uid:drain.scope().phase_node_uid.clone(),observation:actual.clone(),mounts:Mutex::new(std::collections::BTreeMap::new()),
                    retired:Mutex::new(std::collections::BTreeMap::new())});
                ROOTED_ANCHOR.set(root.clone()).map_err(|_|"another actual anchor already rooted; no replacement/adoption")?;
                self.rooted_existing=Some(root);Ok(())
            }
        })();if result.is_err(){self.unknown=true;}result
    }
    pub(super) fn retained_anchor(&self)->Result<&File,String> {
        if self.unknown {return Err("anchor UNKNOWN; retain".into());}
        self.fresh_anchor.as_ref().ok_or("actual root-retained anchor FD absent".into())
    }
    pub(in crate::storage_driver) fn observe_inherited_existing(&mut self,permit:&VerifiedAttachPhase,
        expected:&OwnedAnchorReference)->Result<(),String> {
        #[cfg(not(target_os="linux"))]
        {let _=(permit,expected);return Err("actual private anchor requires Linux".into());}
        #[cfg(target_os="linux")]
        {
            if self.attempted || self.unknown{return Err("existing anchor observation already attempted/UNKNOWN".into());}
            self.attempted=true;self.deadline=Some(permit.deadline());
            let result=(||{
                if permit.existing_anchor()!=Some(expected) || expected.node_uid!=permit.scope().phase_node_uid {
                    return Err("existing anchor DATA not from exact inherited private capsule".into());
                }
                permit.checkpoint()?;self.namespace=Some(open_current_namespace()?);self.base=Some(open_reserved_base()?);
                self.fresh_anchor=optional_anchor(self.base.as_ref().unwrap())?;
                verify_reference(expected,self.fresh_anchor.as_ref().ok_or("actual expected anchor absent")?,self.namespace.as_ref().unwrap())?;
                self.validated_existing=Some(expected.clone());permit.checkpoint()
            })();if result.is_err(){self.unknown=true;}result
        }
    }
    pub(super) fn record_mounted(&self,drain:&crate::storage_driver::dispatcher::attachment::VerifiedAttachDrain,
        mounted:&File,observation:&MountObservation)->Result<(),String> {
        let root=self.rooted_existing.as_ref().ok_or("actual anchor lifetime not rooted")?;
        if drain.scope().phase!=crate::storage_lifecycle::pod_attachment::AttachPhase::ObserveMounted
            || drain.observation()?.mounted.as_ref()!=Some(observation){return Err("actual final drain/mount mismatch".into());}
        #[cfg(not(target_os="linux"))]
        {let _=mounted;return Err("actual installed submount requires Linux".into());}
        #[cfg(target_os="linux")]
        {
            let observed=observe_mounted(mounted,&observation.target,(observation.namespace_device,observation.namespace_inode),
                observation.device_major,observation.device_minor,&observation.filesystem_uuid)?;
            if &observed!=observation{return Err("actual rooted new submount changed before index install".into());}
            let mut mounts=root.mounts.lock().map_err(|_|"actual anchor ownership index poisoned")?;
            if mounts.len()>=8 || mounts.contains_key(&observation.target){return Err("actual owned mount index duplicate/full".into());}
            mounts.insert(observation.target.clone(),observation.clone());Ok(())
        }
    }
    #[cfg(target_os="linux")]
    fn recheck_initial(&self)->Result<(),String> {
        let old=self.observation.as_ref().ok_or("initial anchor observation absent")?;
        if self.unknown || Instant::now()>=self.deadline.ok_or("original anchor deadline absent")?
            || self.boot.as_ref()!=Some(&crate::storage_boot::BootId::current()?)
            || fd_identity(&open_current_namespace()?)?!=old.namespace
            || String::from_utf8(read_at_thread("mountinfo",1024*1024)?).map_err(|_|"mountinfo encoding")?!=*self.original_mountinfo.as_ref().unwrap() {
            return Err("anchor namespace/boot/mount graph changed before effect".into());
        }
        for held in &self.namespaces {if fd_identity(&held.file)?!=held.identity{return Err("namespace pin changed".into());}}
        Ok(())
    }
    #[cfg(target_os="linux")]
    fn recheck_base_path(&mut self,stage:AnchorPathStage)->Result<(),String> {
        if self.unknown || self.base_fresh.is_some() || self.path_anchor_fresh.is_some(){return Err("partial anchor path recheck retained".into());}
        self.base_fresh=Some(open_reserved_base()?);
        if observe_parent_kernel(self.base_fresh.as_ref().unwrap())?!=observe_parent_kernel(self.base.as_ref().ok_or("original base FD absent")?)? {
            return Err("reserved base path is covered/replaced; no anchor action".into());
        }
        if !matches!(stage,AnchorPathStage::BaseOnly) {
            self.path_anchor_fresh=optional_anchor(self.base_fresh.as_ref().unwrap())?;
            let original=match stage {AnchorPathStage::AfterNewBind=>self.fresh_anchor.as_ref(),
                AnchorPathStage::BeforeBind=>self.anchor.as_ref(),AnchorPathStage::BaseOnly=>None}.ok_or("actual owned anchor FD absent")?;
            if observe_parent_kernel(self.path_anchor_fresh.as_ref().ok_or("fixed anchor pathname absent")?)?!=observe_parent_kernel(original)? {
                return Err("anchor pathname no longer names the held exact object".into());
            }
        }
        drop(self.base_fresh.take());drop(self.path_anchor_fresh.take());Ok(())
    }
    #[cfg(target_os="linux")]
    fn recheck_census(&mut self,new_anchor:Option<&KernelParentIdentity>)->Result<(),String> {
        if self.rechecks.len()>=3 {return Err("anchor census continuation exhausted; no retry".into());}
        // Root the NEW empty holder before observe_once can acquire any FD.
        self.rechecks.push(AnchorProbe::empty());
        let index=self.rechecks.len()-1;self.rechecks[index].observe_within(self.deadline.ok_or("original anchor budget absent")?)?;
        let now=&self.rechecks[index];let old=self.observation.as_ref().ok_or("original census absent")?;
        let fresh=now.observation.as_ref().ok_or("fresh census absent")?;
        let task_set=|d:&AnchorDiagnostic|d.tasks.iter().map(|t|(t.tgid,t.tid,t.start_ticks,t.namespace)).collect::<BTreeSet<_>>();
        if old.boot!=fresh.boot || old.namespace!=fresh.namespace || task_set(old)!=task_set(fresh)
            || !fresh.unrepresented_namespace_fds.is_empty() || self.namespaces.len()!=now.namespaces.len() {
            return Err("visible task/namespace graph changed before owned anchor effect".into());
        }
        for before in &self.namespaces {
            let after=now.namespaces.iter().find(|n|n.identity==before.identity).ok_or("namespace disappeared")?;
            let prior=parse_mounts(&before.mountinfo)?;let current=parse_mounts(&after.mountinfo)?;
            if let Some(expected)=new_anchor {
                compare_after_bind(before.identity,old.namespace,&prior,&current,expected)?;
            } else if current!=prior {return Err("mount graph changed before anchor bind".into());}
        }
        Ok(())
    }
}

impl AnchorLifetime {
    fn reference(&self,scope:&ExpectedAttachScope,deadline:Instant)->Result<OwnedAnchorReference,String> {
        if Instant::now()>=deadline || scope.phase_node_uid!=self.node_uid || scope.phase_boot!=self.observation.boot {
            return Err("actual existing anchor belongs to another local node/boot/budget".into());
        }
        let reference=OwnedAnchorReference {anchor:self.observation.clone(),node_uid:self.node_uid.clone(),
            owned_mounts:self.mounts.lock().map_err(|_|"actual anchor index poisoned")?.clone()};
        #[cfg(not(target_os="linux"))]
        {return Err("actual anchor reference requires Linux".into());}
        #[cfg(target_os="linux")]
        {verify_reference(&reference,&self.anchor,&self.namespace)?;Ok(reference)}
    }
}
#[cfg(target_os="linux")]
fn verify_reference(reference:&OwnedAnchorReference,anchor:&File,namespace:&File)->Result<(),String> {
    let a=&reference.anchor;let actual=observe_parent_kernel(anchor)?;
    let base=open_reserved_base()?;let fresh=optional_anchor(&base)?.ok_or("registered anchor pathname absent")?;
    if observe_parent_kernel(&fresh)?!=actual || (actual.device,actual.inode,actual.mount_id,actual.major,actual.minor)
        !=(a.device,a.inode,a.mount_id,a.major,a.minor) || fd_identity(namespace)?!=a.namespace
        || fd_identity(&open_current_namespace()?)?!=a.namespace || crate::storage_boot::BootId::current()?!=a.boot
        || reference.owned_mounts.len()>8 {return Err("actual registered anchor FD/path/ns/boot changed".into());}
    let raw=String::from_utf8(read_at_thread("mountinfo",1024*1024)?).map_err(|_|"actual anchor mountinfo encoding")?;
    let rows=parse_mounts(&raw)?;
    let found=rows.iter().filter(|r|r.target==ANCHOR).collect::<Vec<_>>();
    if found.len()!=1 || found[0].id!=a.mount_id || !found[0].optional.is_empty(){return Err("registered anchor not exact private current mount".into());}
    let mut observed=std::collections::BTreeSet::new();
    for row in rows.iter().filter(|r|r.target!=ANCHOR && within(&r.target,ANCHOR)) {
        let expected=reference.owned_mounts.get(&row.target).ok_or("unregistered/unknown submount under owned anchor")?;
        let exact=exact_mounted(&rows,&row.target,expected.device_major,expected.device_minor)?;
        if exact.id!=expected.mount_id || !observed.insert(row.target.clone()) {return Err("actual owned submount identity changed/stacked".into());}
    }
    if observed.len()!=reference.owned_mounts.len(){return Err("actual registered owned submount missing".into());}
    let mut preserved=String::new();
    if !raw.ends_with('\n'){return Err("kernel mountinfo missing final line boundary".into());}
    for line in raw.lines(){let parsed=parse_mounts(&format!("{line}\n"))?;
        if !within(&parsed[0].target,ANCHOR){preserved.push_str(line);preserved.push('\n');}
    }
    if hash(preserved.as_bytes())!=a.preserved_mountinfo_sha256{return Err("common-root/foreign mount rows changed since actual anchor creation".into());}
    Ok(())
}

pub(crate) fn diagnostic()->Result<AnchorDiagnostic,String> {
    let mut probe=AnchorProbe::empty();probe.observe_once()?;
    probe.observation.take().ok_or("anchor diagnostic missing".into())
}
fn decimal(raw:&str)->Option<u32> {if raw.is_empty() || !raw.bytes().all(|b|b.is_ascii_digit()){return None;}raw.parse().ok().filter(|v|*v>0)}
pub(super) fn inventory_decimal(raw:&str)->Option<u32>{decimal(raw)}
pub(super) fn inventory_namespace_link(raw:&str)->Result<Option<u64>,String>{namespace_link(raw)}
#[cfg(target_os="linux")]
pub(super) fn inventory_read_link(dir:&File,name:&str)->Result<String,String>{read_link_at(dir,name)}
/// New readonly iterator does not share or rewind another consumer's directory
/// position. The legacy entries function and its tests remain unchanged.
#[cfg(target_os="linux")]
pub(super) fn inventory_entries(file:&File,limit:usize)->Result<Vec<String>,String>{
    use std::os::fd::{AsRawFd,FromRawFd,IntoRawFd};
    let before=file.metadata().map_err(|_|"actual inventory directory metadata unavailable")?;
    let raw=unsafe{libc::openat(file.as_raw_fd(),c".".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
    if raw<0{return Err("fresh anchored inventory iterator unavailable".into());}
    let fresh=unsafe{File::from_raw_fd(raw)};let m=fresh.metadata().map_err(|_|"fresh inventory iterator metadata unavailable")?;
    if !before.is_dir()||(m.dev(),m.ino())!=(before.dev(),before.ino()){return Err("fresh inventory iterator not SAME anchored directory".into());}
    let raw=fresh.into_raw_fd();let dir=unsafe{libc::fdopendir(raw)};
    if dir.is_null(){unsafe{libc::close(raw)};return Err("fresh inventory fdopendir unavailable".into());}
    struct Guard(*mut libc::DIR);impl Drop for Guard{fn drop(&mut self){unsafe{libc::closedir(self.0)};}}
    let guard=Guard(dir);let mut result=Vec::new();
    loop{unsafe{*libc::__errno_location()=0;}let row=unsafe{libc::readdir(guard.0)};
        if row.is_null(){if unsafe{*libc::__errno_location()}!=0{return Err("inventory iterator failed before real EOF".into());}break;}
        let name=unsafe{std::ffi::CStr::from_ptr((*row).d_name.as_ptr())}.to_str().map_err(|_|"inventory entry encoding")?;
        if name=="."||name==".."{continue;}if result.len()>=limit{return Err("inventory directory exceeds existing bound".into());}result.push(name.to_string());}
    let after=file.metadata().map_err(|_|"original inventory directory disappeared")?;
    if(after.dev(),after.ino())!=(before.dev(),before.ino()){return Err("anchored inventory directory changed".into());}
    result.sort();Ok(result)
}
#[cfg(all(test,target_os="linux"))]
mod owned_inventory_iteration_tests{
    use super::*;
    #[test]fn v7_actual_owned_directory_iteration_is_fresh_not_shared_offset_empty(){
        let path=std::env::temp_dir().join(format!("royak-owned-inventory-iterate-{}",Uid::new().as_str()));
        std::fs::create_dir(&path).unwrap();
        std::fs::OpenOptions::new().create_new(true).write(true).open(path.join("1")).unwrap();
        std::fs::OpenOptions::new().create_new(true).write(true).open(path.join("2")).unwrap();
        let original=File::open(&path).unwrap();let before=original.metadata().unwrap();
        assert_eq!(inventory_entries(&original,2).unwrap(),["1","2"]);
        assert_eq!(inventory_entries(&original,2).unwrap(),["1","2"]);
        assert!(inventory_entries(&original,1).is_err());
        let after=original.metadata().unwrap();assert_eq!((before.dev(),before.ino()),(after.dev(),after.ino()));
        drop(original);std::fs::remove_file(path.join("1")).unwrap();std::fs::remove_file(path.join("2")).unwrap();std::fs::remove_dir(path).unwrap();
        // An owned ordinary directory proves iterator lifetime ONLY. Never a
        // namespace, Watch process, kernel mount or actual book capability.
    }
}
fn fixed_owned_affected(places:&[AffectedPlace],namespace:(u64,u64))->bool {
    !places.is_empty() && places.iter().all(|p|p.namespace==namespace && p.target==ANCHOR)
}
fn known_propagation(tags:&[String])->bool {
    let mut seen=BTreeSet::new();tags.iter().all(|tag|{
        let Some((kind,id))=tag.split_once(':')else{return false;};
        matches!(kind,"shared"|"master"|"propagate_from") && seen.insert(kind)
            && id.parse::<u64>().is_ok_and(|id|id>0)
    })
}
fn namespace_link(link:&str)->Result<Option<u64>,String> {
    if !link.starts_with("mnt:"){return Ok(None);}
    let number=link.strip_prefix("mnt:[").and_then(|s|s.strip_suffix(']')).ok_or("malformed actual namespace FD link")?;
    let value=number.parse::<u64>().map_err(|_|"malformed actual namespace FD inode")?;
    if value==0{return Err("zero actual namespace FD inode".into());}Ok(Some(value))
}
fn compare_after_bind(namespace:(u64,u64),own:(u64,u64),before:&[MountRow],after:&[MountRow],expected:&KernelParentIdentity)->Result<(),String> {
    if namespace!=own {
        if after!=before{return Err("unaffected namespace graph changed after own anchor bind".into());}
        return Ok(());
    }
    let added=after.iter().filter(|r|r.target==ANCHOR).collect::<Vec<_>>();
    if added.len()!=1 || added[0].id!=expected.mount_id || added[0].major!=expected.major
        || added[0].minor!=expected.minor || !known_propagation(&added[0].optional) {
        return Err("unexpected actual new anchor identity/propagation".into());
    }
    if !after.iter().filter(|r|r.target!=ANCHOR).eq(before.iter()) {
        return Err("common-root/foreign mount rows changed after own bind".into());
    }Ok(())
}
pub(super) fn task_start(raw:&[u8],tid:u32)->Result<u64,String> {
    let text=std::str::from_utf8(raw).map_err(|_|"task stat not UTF8")?;
    let (head,tail)=text.rsplit_once(") ").ok_or("task stat boundary absent")?;
    if head.split_once(" (").and_then(|(pid,_)|pid.parse::<u32>().ok())!=Some(tid){return Err("task stat ID differs".into());}
    // A real early task can start at tick0; this is identity DATA, not a namespace exception.
    tail.split_whitespace().nth(19).and_then(|v|v.parse::<u64>().ok()).ok_or("task start tick missing".into())
}
fn unique_covering<'a>(rows:&'a[MountRow],target:&str)->Result<&'a MountRow,String> {
    let mut seen=BTreeSet::new();let mut best=None;
    for row in rows.iter().filter(|r|within(target,&r.target)) {
        if !seen.insert(row.target.as_str()){return Err("stacked covering anchor mount".into());}
        if best.is_none_or(|old:&MountRow|row.target.len()>old.target.len()){best=Some(row);}
    }best.ok_or("anchor covering mount absent".into())
}
fn join_root(root:&str,target:&str,path:&str)->Result<String,String> {
    if !within(path,target){return Err("path not below covering mount".into());}
    let relative=path.strip_prefix(target).ok_or("covering prefix mismatch")?.trim_start_matches('/');
    Ok(format!("{}/{relative}",root.trim_end_matches('/')))
}

#[cfg(target_os="linux")]
pub(in crate::storage_driver) fn require_fs(file:&File,magic:u64)->Result<(),String>{use std::os::fd::AsRawFd;let mut value:libc::statfs=unsafe{std::mem::zeroed()};
    if unsafe{libc::fstatfs(file.as_raw_fd(),&mut value)}!=0 || value.f_type as u64!=magic {return Err("expected actual kernel filesystem absent".into());}Ok(())}
#[cfg(target_os="linux")]
pub(super) fn open_directory_at(parent:&File,name:&str)->Result<File,String>{use std::os::fd::AsRawFd;let name=std::ffi::CString::new(name).map_err(|_|"invalid fixed directory component")?;
    owned_fd(unsafe{libc::openat(parent.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})}
#[cfg(target_os="linux")]
pub(in crate::storage_driver) fn read_at(parent:&File,name:&str,limit:usize)->Result<Vec<u8>,String>{use std::io::Read;use std::os::fd::AsRawFd;
    let name=std::ffi::CString::new(name).map_err(|_|"invalid fixed read name")?;
    let mut fd=owned_fd(unsafe{libc::openat(parent.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
    let mut raw=Vec::new();fd.by_ref().take(limit as u64+1).read_to_end(&mut raw).map_err(|_|"bounded kernel read failed")?;
    if raw.is_empty() || raw.len()>limit{return Err("kernel read empty/over bound".into());}Ok(raw)}
#[cfg(target_os="linux")]
fn read_at_thread(name:&str,limit:usize)->Result<Vec<u8>,String>{let proc=std::fs::File::open("/proc/thread-self").map_err(|_|"current thread proc directory absent")?;require_fs(&proc,0x9fa0)?;read_at(&proc,name,limit)}
#[cfg(target_os="linux")]
pub(super) fn open_namespace_at(task:&File)->Result<File,String>{use std::os::fd::AsRawFd;
    let fd=owned_fd(unsafe{libc::openat(task.as_raw_fd(),c"ns/mnt".as_ptr(),libc::O_RDONLY|libc::O_CLOEXEC)})?;
    require_fs(&fd,0x6e736673)?;if unsafe{libc::ioctl(fd.as_raw_fd(),0xb703)}!=libc::CLONE_NEWNS{return Err("not actual mount namespace".into());}Ok(fd)}
#[cfg(target_os="linux")]
fn read_link_at(dir:&File,name:&str)->Result<String,String>{use std::os::fd::AsRawFd;let name=std::ffi::CString::new(name).map_err(|_|"invalid descriptor name")?;
    let mut raw=[0u8;4097];let n=unsafe{libc::readlinkat(dir.as_raw_fd(),name.as_ptr(),raw.as_mut_ptr().cast(),raw.len())};
    if n<0 || n as usize>=raw.len(){return Err("descriptor census changed/unavailable".into());}String::from_utf8(raw[..n as usize].to_vec()).map_err(|_|"descriptor link encoding".into())}
#[cfg(target_os="linux")]
fn namespace_fd_links(dir:&File,deadline:Option<Instant>,limit:usize)->Result<(Vec<u64>,usize,String),String>{use std::os::fd::AsRawFd;
    // Keep the enumeration FD alive through ALL readlinkat calls. In our own
    // fd table it appears as an ordinary non-namespace directory descriptor;
    // closing it before resolving its listed name would manufacture a race.
    let mut iterator=std::fs::read_dir(format!("/proc/self/fd/{}",dir.as_raw_fd()))
        .map_err(|_|"cannot enumerate anchored actual task descriptor table")?;
    let mut seen=0usize;let mut result=Vec::new();let mut targets=Sha256::new();
    for entry in iterator.by_ref(){let entry=entry.map_err(|_|"descriptor census read UNKNOWN")?;
        if deadline.is_some_and(|end|Instant::now()>=end){return Err("original descriptor census budget expired".into());}
        if seen>=limit{return Err("descriptor census exceeds per-task/global bound".into());}seen+=1;
        let name=entry.file_name();let name=name.to_str().ok_or("descriptor name encoding")?;
        if name.is_empty() || !name.bytes().all(|b|b.is_ascii_digit()) || name.parse::<u32>().is_err(){return Err("non-numeric actual descriptor".into());}
        let link=read_link_at(dir,name)?;
        targets.update(name.as_bytes());targets.update([0]);targets.update(link.as_bytes());targets.update([0]);
        if let Some(inode)=namespace_link(&link)?{result.push(inode);}
    }Ok((result,seen,format!("{:x}",targets.finalize())))}
#[cfg(target_os="linux")]
fn open_reserved_base()->Result<File,String>{use std::os::fd::AsRawFd;
    let mut current=owned_fd(unsafe{libc::open(c"/".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_CLOEXEC)})?;
    for (index,component) in ["var","lib","royak","storage"].iter().enumerate(){
        current=open_directory_at(&current,component)?;let metadata=current.metadata().map_err(|_|"reserved root metadata")?;
        if metadata.uid()!=0 || metadata.mode()&0o022!=0 || index>=3 && metadata.mode()&0o077!=0 {
            return Err("reserved metadata root is not canonical root-private".into());
        }
    }let _=current.as_raw_fd();Ok(current)}
#[cfg(target_os="linux")]
fn optional_anchor(base:&File)->Result<Option<File>,String>{use std::os::fd::AsRawFd;
    let raw=unsafe{libc::openat(base.as_raw_fd(),c"mounts".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
    if raw<0 {return if std::io::Error::last_os_error().raw_os_error()==Some(libc::ENOENT){Ok(None)}else{Err("fixed anchor open failed".into())};}
    let fd=owned_fd(raw)?;require_private_parent(&observe_parent_kernel(&fd)?)?;Ok(Some(fd))}
#[cfg(target_os="linux")]
fn entries(file:&File,limit:usize)->Result<Vec<String>,String>{use std::os::fd::AsRawFd;
    let duplicate=unsafe{libc::fcntl(file.as_raw_fd(),libc::F_DUPFD_CLOEXEC,3)};if duplicate<0{return Err("cannot duplicate census FD".into());}
    let dir=unsafe{libc::fdopendir(duplicate)};if dir.is_null(){unsafe{libc::close(duplicate)};return Err("cannot anchor census stream".into());}
    struct Guard(*mut libc::DIR);impl Drop for Guard{fn drop(&mut self){unsafe{libc::closedir(self.0)};}}let guard=Guard(dir);
    unsafe{*libc::__errno_location()=0;libc::rewinddir(guard.0);}
    if unsafe{*libc::__errno_location()}!=0{return Err("census rewind UNKNOWN".into());}
    let mut result=Vec::new();loop {unsafe{*libc::__errno_location()=0;}
        let entry=unsafe{libc::readdir(guard.0)};if entry.is_null(){if unsafe{*libc::__errno_location()}!=0{return Err("census read UNKNOWN".into());}break;}
        let name=unsafe{std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())}.to_str().map_err(|_|"census filename encoding")?;
        if name=="." || name==".."{continue;}if result.len()>=limit{return Err("census bound exceeded".into());}result.push(name.to_owned());
    }result.sort();Ok(result)}


impl AnchorProbe {
    /// Index retirement is DATA only after independent SAME-underlay proof.
    /// The static original service anchor/namespace are never unmounted/dropped.
    pub(super) fn retire_terminal_mount(&self,parent:&crate::storage_driver::native_runtime::mount::consumer::terminal::VerifiedTerminalNodeParent,
        observation:&MountObservation)->Result<(),String>{
        parent.require_live()?;
        let root=self.rooted_existing.as_ref().ok_or("original terminal anchor lifetime absent")?;
        if root.node_uid!=parent.scope().phase_node_uid||observation.target!=mount_path(&parent.scope().mount_ref){
            return Err("terminal tombstone has another original anchor/mount owner".into());}
        let mut mounted=root.mounts.lock().map_err(|_|"original anchor index poisoned")?;
        if mounted.get(&observation.target)!=Some(observation){return Err("original mounted index absent/changed; no tombstone fabrication".into());}
        let mut retired=root.retired.lock().map_err(|_|"original anchor tombstone index poisoned")?;
        if retired.len()>=128||retired.contains_key(&observation.target){return Err("original anchor tombstone repeated/history full".into());}
        retired.insert(observation.target.clone(),(parent.terminal_operation_uid().clone(),observation.clone()));
        mounted.remove(&observation.target);Ok(())
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize)]
pub(in crate::storage_driver) enum TerminalCensusPoint {BeforeUnmount,AfterUnmount,BeforeOffline,AfterOffline}
impl TerminalCensusPoint {
    pub(in crate::storage_driver) fn code(self)->Result<u8,String>{match self{Self::BeforeUnmount=>Ok(0),Self::AfterUnmount=>Ok(1),_=>Err("offline census cannot represent retained block references".into())}}
    pub(in crate::storage_driver) fn from_code(value:u8)->Result<Self,String>{match value{0=>Ok(Self::BeforeUnmount),1=>Ok(Self::AfterUnmount),_=>Err("unknown reference census point".into())}}
}
#[derive(Clone,Debug,Serialize)]
pub(in crate::storage_driver) struct TerminalReferenceCensus {
    boot:crate::storage_boot::BootId,tasks:usize,descriptors:usize,namespaces:usize,
    task_reference_sha256:String,mount_graph_sha256:String,kernel_fs_absences:usize,
    no_storage_descriptors:bool,no_unclassified_storage_descriptors:bool,
    represented_original_block_references:usize,represented_originals_sha256:Option<String>,
    represented_originals_json:Option<String>,point:&'static str,
    limitations:&'static str,
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub(super) struct TerminalTaskStamp {pub(super) tgid:u32,pub(super) tid:u32,pub(super) start:u64,
    pub(super) flags:u64,pub(super) kthread:bool,pub(super) uid:[u32;4]}
pub(super) fn terminal_task_stamp(stat:&[u8],status:&[u8],tgid:u32,tid:u32)->Result<TerminalTaskStamp,String>{
    let start=task_start(stat,tid)?;
    let stat=std::str::from_utf8(stat).map_err(|_|"terminal task stat encoding")?;
    let tail=stat.rsplit_once(") ").ok_or("terminal task stat boundary")?.1;
    let flags=tail.split_whitespace().nth(6).and_then(|v|v.parse::<u64>().ok()).ok_or("terminal task flags absent")?;
    let text=std::str::from_utf8(status).map_err(|_|"terminal task status encoding")?;
    let one=|name:&str|->Result<&str,String>{
        let rows=text.lines().filter_map(|l|l.strip_prefix(name)).collect::<Vec<_>>();
        if rows.len()!=1{return Err("terminal task status field absent/duplicate".into());}Ok(rows[0].trim())
    };
    let pid=one("Pid:")?.parse::<u32>().map_err(|_|"terminal task PID invalid")?;
    let group=one("Tgid:")?.parse::<u32>().map_err(|_|"terminal task TGID invalid")?;
    let kernel=match one("Kthread:")?{"0"=>false,"1"=>true,_=>return Err("terminal Kthread status malformed".into())};
    let ids=one("Uid:")?.split_whitespace().map(str::parse::<u32>).collect::<Result<Vec<_>,_>>()
        .map_err(|_|"terminal task UID status malformed")?;
    if pid!=tid||group!=tgid||ids.len()!=4||((flags&0x00200000)!=0)!=kernel{
        return Err("terminal task incarnation/kernel classification inconsistent".into());}
    Ok(TerminalTaskStamp{tgid,tid,start,flags,kthread:kernel,uid:[ids[0],ids[1],ids[2],ids[3]]})
}
fn terminal_missing_fs_allowed(errno:Option<i32>,stamp:&TerminalTaskStamp,fd_count:usize)->bool{
    errno==Some(libc::ENOENT)&&stamp.kthread&&fd_count==0
}
fn terminal_kernel_absence_stable(before:&TerminalTaskStamp,after:&TerminalTaskStamp,before_fds:usize,after_fds:usize)->bool{
    before==after&&before.kthread&&before_fds==0&&after_fds==0
}
#[cfg(target_os="linux")]
pub(super) fn walk_fd_names(file:&File,limit:usize,mut visit:impl FnMut(&str)->Result<(),String>)->Result<usize,String>{
    use std::os::fd::{FromRawFd,IntoRawFd};
    // A DUP shares the original directory position. Open '.' relative to the
    // held descriptor to obtain a FRESH independent description, never a
    // numeric proc pathname or adopted replacement.
    let original=file.metadata().map_err(|_|"original FD-table directory unavailable")?;
    let duplicate=unsafe{libc::openat(file.as_raw_fd(),c".".as_ptr(),
        libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
    if duplicate<0{return Err("terminal descriptor iterator unavailable".into());}
    let fresh=unsafe{File::from_raw_fd(duplicate)};
    let observed=fresh.metadata().map_err(|_|"fresh anchored FD-table metadata unavailable")?;
    if !original.is_dir()||(original.dev(),original.ino())!=(observed.dev(),observed.ino()){
        return Err("fresh iterator is not SAME held FD-table directory".into());}
    let duplicate=fresh.into_raw_fd();
    let directory=unsafe{libc::fdopendir(duplicate)};
    if directory.is_null(){unsafe{libc::close(duplicate)};return Err("terminal descriptor iterator unavailable".into());}
    struct Guard(*mut libc::DIR);impl Drop for Guard{fn drop(&mut self){unsafe{libc::closedir(self.0)};}}
    let guard=Guard(directory);let mut count=0usize;
    loop{
        unsafe{*libc::__errno_location()=0;}
        let row=unsafe{libc::readdir(guard.0)};
        if row.is_null(){if unsafe{*libc::__errno_location()}!=0{return Err("terminal descriptor iteration UNKNOWN".into());}break;}
        let name=unsafe{std::ffi::CStr::from_ptr((*row).d_name.as_ptr())}.to_str().map_err(|_|"terminal fd name encoding")?;
        if name=="."||name==".."{continue;}
        if name.is_empty()||!name.bytes().all(|b|b.is_ascii_digit())||name.parse::<u32>().is_err()||count>=limit{
            return Err("terminal descriptor enumeration invalid/over bound".into());}
        count+=1;visit(name)?;
    }
    let after=file.metadata().map_err(|_|"original FD-table disappeared after enumeration")?;
    if(original.dev(),original.ino())!=(after.dev(),after.ino()){
        return Err("original FD-table incarnation changed".into());}
    Ok(count)
}
/// Bounded READONLY task+namespace+FD/root/cwd census under the explicit
/// dedicated-VM root boundary. It never closes somebody else's descriptor.
#[cfg(target_os="linux")]
pub(super) fn terminal_reference_census(device:(u32,u32),owned:Option<&MountObservation>,
    point:TerminalCensusPoint,deadline:Instant,context:Option<&VerifiedReferenceCensusContext<'_>>)->Result<TerminalReferenceCensus,String>{
    if context.is_some_and(|c|c.point()!=point){return Err("reference census point differs from genuine original context".into());}
    let boot=crate::storage_boot::BootId::current()?;
    let own=open_current_namespace()?;let own_id=fd_identity(&own)?;
    let proc=owned_fd(unsafe{libc::open(c"/proc".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
    require_fs(&proc,0x9fa0)?;
    let mut tasks=0usize;let mut descriptors=0usize;let mut kernel_fs_absences=0usize;let mut mount_bytes=0usize;
    let mut namespaces=std::collections::BTreeMap::new();let mut referenced=BTreeSet::new();
    let mut represented=0usize;let mut leader_slots=BTreeSet::new();
    let mut task_hash=Sha256::new();let mut graph_hash=Sha256::new();
    let storage=libc::makedev(device.0,device.1);
    for pid in entries(&proc,MAX_TASKS)?{
        let Some(tgid)=decimal(&pid)else{continue};
        let process=open_directory_at(&proc,&pid)?;let threads=open_directory_at(&process,"task")?;
        for name in entries(&threads,MAX_TASKS)?{
            if Instant::now()>=deadline||tasks>=MAX_TASKS{return Err("original terminal census budget/task cap exhausted".into());}
            let tid=decimal(&name).ok_or("terminal task identifier malformed")?;tasks+=1;
            let task=open_directory_at(&threads,&name)?;
            let stat=read_at(&task,"stat",4096)?;let status=read_at(&task,"status",65536)?;
            let before=terminal_task_stamp(&stat,&status,tgid,tid)?;
            let namespace=open_namespace_at(&task)?;let namespace_id=fd_identity(&namespace)?;
            let graph=read_at(&task,"mountinfo",1024*1024)?;
            if let Some(existing)=namespaces.get(&namespace_id){
                if existing!=&hash(&graph){return Err("same namespace graph changed during terminal census".into());}
            }else{
                if namespaces.len()>=MAX_NAMESPACES{return Err("terminal namespace census exceeds original cap".into());}
                mount_bytes=mount_bytes.checked_add(graph.len()).ok_or("terminal mount graph bytes overflow")?;
                if mount_bytes>MAX_MOUNTINFO_BYTES{return Err("terminal mount graphs exceed original total4MiB census bound".into());}
                let raw=std::str::from_utf8(&graph).map_err(|_|"terminal mountinfo encoding")?;
                for row in parse_mounts(raw)?{
                    if (row.major,row.minor)!=device{continue;}
                    let allowed=point==TerminalCensusPoint::BeforeUnmount&&namespace_id==own_id
                        &&owned.is_some_and(|o|o.mount_id==row.id&&o.target==row.target&&row.filesystem=="ext4"&&row.optional.is_empty());
                    if !allowed{return Err("actual storage mount alias/unrepresented owned place remains; no foreign mutation".into());}
                }
                graph_hash.update(namespace_id.0.to_be_bytes());graph_hash.update(namespace_id.1.to_be_bytes());graph_hash.update(&graph);
                namespaces.insert(namespace_id,hash(&graph));
            }
            let fds=open_directory_at(&task,"fd")?;
            let count=walk_fd_names(&fds,MAX_FDS,|number|{
                if Instant::now()>=deadline||descriptors>=MAX_TOTAL_FDS{return Err("terminal fd census budget/cap exhausted".into());}
                descriptors+=1;
                let link=read_link_at(&fds,number)?;
                if let Some(inode)=namespace_link(&link)?{referenced.insert(inode);}
                let path=format!("/proc/self/fd/{}/{}",fds.as_raw_fd(),number);
                let original=context.is_some_and(|c|c.potential_original(tgid,number));
                if original{context.unwrap().before_fstat(tgid,tid,namespace_id)?;}
                let metadata=std::fs::metadata(&path).map_err(|_|"terminal actual fd disappeared/permission UNKNOWN")?;
                if original{
                    let c=context.unwrap();let slot=c.after_fstat(tgid,tid,namespace_id,number,&metadata)?;
                    if !metadata.file_type().is_block_device()||metadata.rdev()!=storage{
                        return Err("represented original File is not the exact requested DRBD block device".into());}
                    represented+=1;if tid==c.leader(){leader_slots.insert(slot);}
                }
                if metadata.dev()==storage||metadata.file_type().is_block_device()&&metadata.rdev()==storage{
                    if !original{return Err("actual task still holds UNCLASSIFIED managed filesystem/block descriptor".into());}}
                task_hash.update(tgid.to_be_bytes());task_hash.update(tid.to_be_bytes());task_hash.update(number.as_bytes());
                task_hash.update(metadata.dev().to_be_bytes());task_hash.update(metadata.ino().to_be_bytes());task_hash.update(link.as_bytes());Ok(())
            })?;
            let mut missing=0usize;
            for link in ["root","cwd"]{
                match std::fs::metadata(format!("/proc/self/fd/{}/{link}",task.as_raw_fd())){
                    Ok(metadata)=>{if metadata.dev()==storage{return Err("actual task root/cwd still references managed filesystem".into());}
                        task_hash.update(metadata.dev().to_be_bytes());task_hash.update(metadata.ino().to_be_bytes());},
                    Err(error)if terminal_missing_fs_allowed(error.raw_os_error(),&before,count)=>{missing+=1;},
                    Err(_)=>return Err("terminal actual user/unknown task root/cwd unavailable".into()),
                }
            }
            let after=terminal_task_stamp(&read_at(&task,"stat",4096)?,&read_at(&task,"status",65536)?,tgid,tid)?;
            let after_ns=open_namespace_at(&task)?;
            if after!=before||fd_identity(&after_ns)?!=namespace_id||read_at(&task,"mountinfo",1024*1024)?!=graph{
                return Err("terminal task/namespace incarnation changed during reference census".into());}
            if missing>0{
                // Explicit stable PF_KTHREAD/Kthread1+ACTUAL empty table only.
                // Missing root/cwd remains recorded, never forged universal absence.
                let after_count=walk_fd_names(&fds,MAX_FDS,|_|Err("kernel task acquired descriptor during missing-fs observation".into()))?;
                if !terminal_kernel_absence_stable(&before,&after,count,after_count){
                    return Err("terminal kernel absence classification changed".into());}
                kernel_fs_absences+=missing;
            }
            task_hash.update(serde_json::to_vec(&(before.tgid,before.tid,before.start,before.flags,before.kthread,before.uid,missing))
                .map_err(|_|"terminal actual task binding failed")?);
        }
    }
    if referenced.iter().any(|inode|!namespaces.keys().any(|(_,seen)|seen==inode)){
        return Err("unrepresented actual mount-namespace FD remains; no hidden namespace absence proof".into());}
    if let Some(context)=context{context.require_leader_slots(&leader_slots)?;}
    if crate::storage_boot::BootId::current()?!=boot||fd_identity(&open_current_namespace()?)?!=own_id||Instant::now()>=deadline{
        return Err("original terminal census boot/namespace/budget changed".into());}
    Ok(TerminalReferenceCensus{boot,tasks,descriptors,namespaces:namespaces.len(),task_reference_sha256:format!("{:x}",task_hash.finalize()),
        mount_graph_sha256:format!("{:x}",graph_hash.finalize()),kernel_fs_absences,no_storage_descriptors:represented==0,
        no_unclassified_storage_descriptors:true,represented_original_block_references:represented,
        represented_originals_sha256:context.map(|c|c.provenance_sha256()).transpose()?,
        represented_originals_json:context.map(|c|c.provenance_json()).transpose()?,
        point:match point{TerminalCensusPoint::BeforeUnmount=>"BeforeUnmount",TerminalCensusPoint::AfterUnmount=>"AfterUnmount",
            TerminalCensusPoint::BeforeOffline=>"BeforeOffline",TerminalCensusPoint::AfterOffline=>"AfterOffline"},
        limitations:"Dedicated controlled VM visible task/namespace census; no universal adversarial PIDless namespace or kernel opener proof; non-force umount/down mandatory"})
}
#[cfg(not(target_os="linux"))]
pub(super) fn terminal_reference_census(_device:(u32,u32),_owned:Option<&MountObservation>,
    _point:TerminalCensusPoint,_deadline:Instant,_context:Option<&VerifiedReferenceCensusContext<'_>>)->Result<TerminalReferenceCensus,String>{Err("terminal actual reference census requires Linux".into())}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn affected_namespace_and_alias_decision_requires_exact_fixed_owned_place() {
        let place=|namespace,target:&str|AffectedPlace {namespace,mount_id:1,target:target.into(),root:"/".into(),optional:vec!["shared:42".into()]};
        assert!(fixed_owned_affected(&[place((1,2),ANCHOR)],(1,2)));
        assert!(!fixed_owned_affected(&[],(1,2)));
        assert!(!fixed_owned_affected(&[place((1,3),ANCHOR)],(1,2)));
        assert!(!fixed_owned_affected(&[place((1,2),"/foreign/alias")],(1,2)));
        // Distinct namespaces are unqualified here, not asserted foreign or
        // absent. Dedicated-VM root trust is not replaced by this predicate.
    }
    #[test]
    fn propagation_parser_never_normalizes_unknown_or_duplicate_parent_tags() {
        assert!(known_propagation(&[]));assert!(known_propagation(&["shared:42".into()]));
        assert!(known_propagation(&["shared:42".into(),"master:9".into(),"propagate_from:9".into()]));
        for tags in [vec!["shared:0".into()],vec!["shared:x".into()],vec!["unknown:42".into()],
            vec!["unbindable".into()],vec!["shared:1".into(),"shared:2".into()]] {assert!(!known_propagation(&tags));}
    }
    #[test]
    fn namespace_fd_link_parser_refuses_malformed_and_zero_without_absence_fallback() {
        assert_eq!(namespace_link("mnt:[123]").unwrap(),Some(123));
        assert_eq!(namespace_link("socket:[123]").unwrap(),None);
        for value in ["mnt:[0]","mnt:[x]","mnt:[123","mnt:123","mnt:[]"] {assert!(namespace_link(value).is_err());}
    }
    #[test]
    fn anchor_covering_selection_rejects_stacked_roots_before_any_bootstrap() {
        let line="1 0 8:1 / / rw shared:42 - ext4 /dev/root rw\n";
        let row=parse_mounts(line).unwrap();assert_eq!(unique_covering(&row,ANCHOR).unwrap().id,1);
        let stacked=parse_mounts(&format!("{line}2 1 8:1 / / rw shared:43 - ext4 /dev/root rw\n")).unwrap();
        assert!(unique_covering(&stacked,ANCHOR).is_err());
    }
    #[test]
    fn proc_task_identity_is_exact_tid_and_nonzero_start_not_numeric_pid_adoption() {
        let raw=format!("42 (name with ) bracket) S {} 777",vec!["0";18].join(" "));
        assert_eq!(task_start(raw.as_bytes(),42).unwrap(),777);
        assert!(task_start(raw.as_bytes(),43).is_err());
        assert!(task_start(b"42 (x) S 0",42).is_err());
    }
    #[test]
    fn unaffected_namespaces_keep_exact_old_graph_while_only_own_namespace_gets_new_anchor() {
        let old=parse_mounts("1 0 8:1 / / rw shared:42 - ext4 /dev/root rw\n").unwrap();
        let new=parse_mounts(&format!("1 0 8:1 / / rw shared:42 - ext4 /dev/root rw\n2 1 8:1 {ANCHOR} {ANCHOR} rw shared:99 - ext4 /dev/root rw\n")).unwrap();
        let identity=KernelParentIdentity {device:1,inode:2,mount_id:2,major:8,minor:1,uid:0,gid:0,mode:0o40700,nlink:2};
        compare_after_bind((1,2),(1,2),&old,&new,&identity).unwrap();
        compare_after_bind((1,3),(1,2),&old,&old,&identity).unwrap();
        assert!(compare_after_bind((1,3),(1,2),&old,&new,&identity).is_err());
        let changed=parse_mounts(&format!("1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:1 {ANCHOR} {ANCHOR} rw shared:99 - ext4 /dev/root rw\n")).unwrap();
        assert!(compare_after_bind((1,2),(1,2),&old,&changed,&identity).is_err());
    }

    #[test]
    fn actual_systemd_raw_zero_start_ticks_are_valid_identity_data() {
        // Literal actual lab proc DATA; not a fabricated namespace graph/capability.
        let cases:[&[u8];3]=[
            b"1 (systemd) S 0 1 1 0 -1 4194560 21084 1992946 93 1276 28 35 400 359 20 0 1 0 0 22745088 3124 18446744073709551615 222441476915200 222441476999652 281473960475872 0 0 0 671173123 4096 1260 1 0 0 17 1 0 0 0 0 0 222441477107616 222441477111920 222442198528000 281473960476488 281473960476499 281473960476499 281473960476653 0\n",
            b"1 (systemd) S 0 1 1 0 -1 4194560 22307 1737415 93 1351 27 35 693 396 20 0 1 0 0 22614016 3063 18446744073709551615 190905166004224 190905166088676 281474821687312 0 0 0 671173123 4096 1260 1 0 0 17 0 0 0 0 0 0 190905166196640 190905166200944 190905953406976 281474821689160 281474821689171 281474821689171 281474821689325 0\n",
            b"1 (systemd) S 0 1 1 0 -1 4194560 21954 2216149 93 1255 26 33 398 376 20 0 1 0 0 22810624 3089 18446744073709551615 192094438555648 192094438640100 281474699740320 0 0 0 671173123 4096 1260 1 0 0 17 0 0 0 0 0 0 192094438748064 192094438752368 192094462283776 281474699743048 281474699743059 281474699743059 281474699743213 0\n"
        ];
        for raw in cases {
            assert_eq!(task_start(raw,1).unwrap(),0);
            let text=std::str::from_utf8(raw).unwrap();
            let flags=text.rsplit_once(") ").unwrap().1.split_whitespace().nth(6).unwrap().parse::<u64>().unwrap();
            assert_eq!(flags & 0x0020_0000,0);
        }
    }
    #[test]
    fn actual_kernel_raw_zero_start_ticks_are_valid_without_classification_policy() {
        // Literal actual lab proc DATA; not a fabricated namespace graph/capability.
        let cases:[&[u8];3]=[
            b"2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            b"2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 1 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0\n",
            b"2 (kthreadd) S 0 0 0 0 -1 2129984 0 0 0 0 0 0 0 0 20 0 1 0 0 0 0 18446744073709551615 0 0 0 0 0 0 0 2147483647 0 1 0 0 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0\n"
        ];
        for raw in cases {
            assert_eq!(task_start(raw,2).unwrap(),0);
            let text=std::str::from_utf8(raw).unwrap();
            let flags=text.rsplit_once(") ").unwrap().1.split_whitespace().nth(6).unwrap().parse::<u64>().unwrap();
            assert_ne!(flags & 0x0020_0000,0);
        }
    }
    #[test]
    fn zero_start_keeps_malformed_missing_overflow_and_wrong_tid_refusals() {
        let valid=format!("2 (zero DATA) S {} 0",vec!["0";18].join(" "));
        assert_eq!(task_start(valid.as_bytes(),2).unwrap(),0);
        assert!(task_start(valid.as_bytes(),3).is_err());
        let missing=format!("2 (missing DATA) S {}",vec!["0";18].join(" "));
        assert!(task_start(missing.as_bytes(),2).is_err());
        for bad in ["not-a-number","-1","18446744073709551616"] {
            let raw=format!("2 (invalid DATA) S {} {bad}",vec!["0";18].join(" "));
            assert!(task_start(raw.as_bytes(),2).is_err());
        }
        assert!(task_start(b"2 no-comm-boundary S 0",2).is_err());
        assert!(task_start(b"2 (\xff) S 0",2).is_err());
        let maximum=format!("2 (u64 DATA) S {} {}",vec!["0";18].join(" "),u64::MAX);
        assert_eq!(task_start(maximum.as_bytes(),2).unwrap(),u64::MAX);
    }
    // DATA parser/decision regressions, NOT actual task/namespace absence proof.
    fn terminal_model_task(flags:u64,kernel:&str,pid:u32)->(String,String){
        let mut fields=vec!["0".to_string();20];fields[0]="S".into();fields[6]=flags.to_string();fields[19]="0".into();
        (format!("{pid} (terminal DATA) {}",fields.join(" ")),
            format!("Pid:\t{pid}\nTgid:\t{pid}\nKthread:\t{kernel}\nUid:\t0\t0\t0\t0\n"))
    }
    #[test]
    fn terminal_kernel_missing_fs_classification_never_excuses_user_permission_or_stat_mismatch(){
        let(stat,status)=terminal_model_task(0x0020_0000,"1",2);
        let kernel=terminal_task_stamp(stat.as_bytes(),status.as_bytes(),2,2).unwrap();
        assert!(terminal_missing_fs_allowed(Some(libc::ENOENT),&kernel,0));
        for errno in [None,Some(libc::EACCES),Some(libc::EPERM),Some(libc::EIO)]{
            assert!(!terminal_missing_fs_allowed(errno,&kernel,0));}
        let(stat,status)=terminal_model_task(0,"0",42);
        let user=terminal_task_stamp(stat.as_bytes(),status.as_bytes(),42,42).unwrap();
        assert!(!terminal_missing_fs_allowed(Some(libc::ENOENT),&user,0));
        for(flags,status_bit)in [(0,"1"),(0x0020_0000,"0")]{
            let(stat,status)=terminal_model_task(flags,status_bit,42);
            assert!(terminal_task_stamp(stat.as_bytes(),status.as_bytes(),42,42).is_err());}
    }
    #[test]
    fn terminal_kernel_absence_requires_both_actual_empty_tables_and_same_task_incarnation(){
        let(stat,status)=terminal_model_task(0x0020_0000,"1",2);
        let before=terminal_task_stamp(stat.as_bytes(),status.as_bytes(),2,2).unwrap();
        assert!(terminal_kernel_absence_stable(&before,&before,0,0));
        assert!(!terminal_kernel_absence_stable(&before,&before,1,0));
        assert!(!terminal_kernel_absence_stable(&before,&before,0,1));
        assert!(!terminal_missing_fs_allowed(Some(libc::ENOENT),&before,1));
        for n in 0..4{let mut changed=before.clone();match n{
            0=>changed.start=1,1=>changed.tid=3,2=>changed.flags^=1,_=>changed.uid[0]=1000};
            assert!(!terminal_kernel_absence_stable(&before,&changed,0,0));}
    }
    #[test]
    fn terminal_task_status_refuses_duplicate_pid_unknown_kernel_and_uid_shape(){
        let(stat,good)=terminal_model_task(0x0020_0000,"1",2);
        for bad in [format!("{good}Pid:\t2\n"),good.replace("Kthread:\t1","Kthread:\t2"),
            good.replace("Uid:\t0\t0\t0\t0","Uid:\t0\t0\t0"),good.replace("Tgid:\t2","Tgid:\t3")]{
            assert!(terminal_task_stamp(stat.as_bytes(),bad.as_bytes(),2,2).is_err());}
        assert!(terminal_task_stamp(stat.as_bytes(),good.as_bytes(),2,3).is_err());
    }
}

// These execute ONLY owned temporary regular-directory observations under
// Root's full Linux suite. They do not mint a proc/namespace/storage witness.
#[cfg(all(test,target_os="linux"))]
mod terminal_v2_iteration_tests {
    use super::*;
    use std::os::fd::AsRawFd;
    struct OwnedTable {root:std::path::PathBuf,file:File}
    impl OwnedTable {
        fn new()->Self{
            let root=std::env::temp_dir().join(format!("royak-terminal-table-{}",Uid::new().as_str()));
            std::fs::create_dir(&root).unwrap();std::fs::create_dir(root.join("table")).unwrap();
            let file=File::open(root.join("table")).unwrap();Self{root,file}
        }
        fn put(&self,name:&str){std::fs::OpenOptions::new().write(true).create_new(true).open(self.root.join("table").join(name)).unwrap();}
        fn names(&self)->Result<Vec<String>,String>{let mut result=Vec::new();walk_fd_names(&self.file,8,|name|{result.push(name.into());Ok(())})?;result.sort();Ok(result)}
    }
    impl Drop for OwnedTable {fn drop(&mut self){
        for directory in ["table","moved"]{
            let path=self.root.join(directory);if !path.exists(){continue;}
            for name in ["0","1","2","file"]{match std::fs::remove_file(path.join(name)){
                Ok(())=>(),Err(error)if error.kind()==std::io::ErrorKind::NotFound=>(),Err(error)=>panic!("owned fixture cleanup: {error}")}}
            std::fs::remove_dir(path).unwrap();
        }std::fs::remove_dir(&self.root).unwrap();
    }}
    #[test]
    fn terminal_fresh_fd_iteration_sees_new_numeric_entry_after_actual_empty_eof(){
        let table=OwnedTable::new();assert!(table.names().unwrap().is_empty());table.put("0");
        assert_eq!(table.names().unwrap(),vec!["0"]);assert_eq!(table.names().unwrap(),vec!["0"]);
    }
    #[test]
    fn terminal_fresh_fd_iteration_does_not_reuse_poisoned_original_directory_position(){
        let table=OwnedTable::new();table.put("1");table.put("2");
        let duplicate=unsafe{libc::fcntl(table.file.as_raw_fd(),libc::F_DUPFD_CLOEXEC,3)};assert!(duplicate>=0);
        let directory=unsafe{libc::fdopendir(duplicate)};assert!(!directory.is_null());
        while !unsafe{libc::readdir(directory)}.is_null(){}
        assert_eq!(unsafe{libc::closedir(directory)},0);
        assert_eq!(table.names().unwrap(),vec!["1","2"]);
    }
    #[test]
    fn terminal_fresh_fd_iteration_keeps_original_directory_after_named_path_replacement(){
        let table=OwnedTable::new();table.put("1");
        std::fs::rename(table.root.join("table"),table.root.join("moved")).unwrap();
        std::fs::create_dir(table.root.join("table")).unwrap();
        assert_eq!(table.names().unwrap(),vec!["1"]);
        let replacement=File::open(table.root.join("table")).unwrap();
        assert_eq!(walk_fd_names(&replacement,8,|_|Ok(())).unwrap(),0);
    }
    #[test]
    fn terminal_fresh_fd_iteration_refuses_non_numeric_over_cap_and_callback_errors(){
        let table=OwnedTable::new();table.put("0");table.put("1");
        assert!(walk_fd_names(&table.file,1,|_|Ok(())).is_err());
        assert!(walk_fd_names(&table.file,8,|_|Err("modeled metadata/permission failure".into())).is_err());
        table.put("file");assert!(table.names().is_err());
    }
}
