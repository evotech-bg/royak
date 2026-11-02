//! Include-only child of replica::initialize. Helpers emit DATA; only Watch's
//! actual post-drain probe below owns a mount. No serde/FD/bool constructor.
use super::*;
use crate::storage_lifecycle::pod_attachment::{ExpectedAttachScope,MountObservation,mount_path};
use crate::storage_driver::dispatcher::attachment::VerifiedAttachDrain;
use std::fs::File;
use std::os::unix::fs::MetadataExt;
#[path = "managed_anchor.rs"]
pub(in crate::storage_driver) mod anchor;
#[path = "managed_mount_phases.rs"]
pub(in crate::storage_driver) mod phases;
#[path = "managed_mount_terminal.rs"]
pub(in crate::storage_driver) mod terminal;
#[path = "managed_mount_inventory.rs"]
pub(in crate::storage_driver) mod inventory;

/// Rooted in AttachOwner BEFORE worker launch and never carried by a ticket.
/// Each newly opened FD is stored before any later fallible observation.
pub(in crate::storage_driver) struct WatchMountProbe {
    anchor:anchor::AnchorProbe,
    parent:ParentFdProbe,
    mount_scope:Option<ExpectedAttachScope>,
    target_before:Option<File>,
    publication_directories:Vec<File>,
    publication:Option<PublicationRef>,
    namespace:Option<File>,
    block:Option<File>,
    mounted:Option<File>,
    daemon:Option<crate::docker::VerifiedDaemonNamespace>,
    installed:Option<VerifiedManagedMount>,
    terminal:Option<terminal::TerminalWatchState>,
    provisional:Option<inventory::ProvisionalMountedInventory>,
}
impl WatchMountProbe {
    pub(in crate::storage_driver) fn empty_before_effect()->Self {
        Self {anchor:anchor::AnchorProbe::empty(),parent:ParentFdProbe::empty(),mount_scope:None,
            target_before:None,publication_directories:Vec::new(),publication:None,
            namespace:None,block:None,mounted:None,daemon:None,installed:None,terminal:None,provisional:None}
    }
    pub(in crate::storage_driver) fn observe_anchor_before_effect(&mut self,scope:&ExpectedAttachScope,deadline:Instant)->Result<(),String> {
        self.anchor.observe_for_owner(scope,deadline)
    }
    pub(in crate::storage_driver) fn existing_anchor_reference(&self,scope:&ExpectedAttachScope,deadline:Instant)
        ->Result<Option<anchor::OwnedAnchorReference>,String> {
        self.anchor.reference(scope,deadline)
    }
    /// Same fixed Watch worker, after first actual Mount-substep drain and
    /// before launching the second. Every new UID directory FD is rooted
    /// before subsequent fallible checks. No existing UID directory is adopted.
    pub(in crate::storage_driver) fn prepare_publication_after_anchor(&mut self,
        drain:&VerifiedAttachDrain)->Result<(),String> {
        #[cfg(not(target_os="linux"))]
        {let _=drain;return Err("publication requires Linux".into());}
        #[cfg(target_os="linux")]
        {
            use std::os::fd::AsRawFd;
            if self.mount_scope.is_some() || self.target_before.is_some() || self.publication.is_some() {
                return Err("publication already attempted; no retry/adoption".into());
            }
            self.mount_scope=Some(drain.scope().clone());
            self.anchor.install_from_actual_drain(drain)?;
            let scope=drain.scope();
            let components=[scope.mount_ref.volume_uid().as_str().to_string(),scope.mount_ref.epoch().to_string(),
                scope.mount_ref.writer_uid().as_uid().as_str().to_string()];
            for name in &components {
                drain.checkpoint()?;
                let parent=if self.publication_directories.is_empty(){self.anchor.retained_anchor()?}
                    else{self.publication_directories.last().unwrap()};
                let name=std::ffi::CString::new(name.as_str()).map_err(|_|"invalid canonical UID directory")?;
                if unsafe{libc::mkdirat(parent.as_raw_fd(),name.as_ptr(),0o700)}!=0 {
                    return Err("new UID directory absent/exists/UNKNOWN; never adopt or retry".into());
                }
                let opened=owned_fd(unsafe{libc::openat(parent.as_raw_fd(),name.as_ptr(),
                    libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
                self.publication_directories.push(opened);
                let parent=if self.publication_directories.len()==1{self.anchor.retained_anchor()?}
                    else{&self.publication_directories[self.publication_directories.len()-2]};
                parent.sync_all().map_err(|_|"publication directory fsync UNKNOWN")?;
                require_private_parent(&observe_parent_kernel(self.publication_directories.last().unwrap())?)?;
                drain.checkpoint()?;
            }
            self.target_before=Some(open_private_target(&mount_path(&scope.mount_ref))?);
            let target=observe_parent_kernel(self.target_before.as_ref().unwrap())?;
            self.parent.capture(scope,drain.deadline())?;
            let observation=self.parent.recheck(scope,drain.deadline())?;
            let anchor=observe_parent_kernel(self.anchor.retained_anchor()?)?;
            self.publication=Some(PublicationRef {target_device:target.device,target_inode:target.inode,
                target_mount_id:target.mount_id,parent:observation.parent,
                anchor_device:anchor.device,anchor_inode:anchor.inode,anchor_mount_id:anchor.mount_id,
                namespace_device:observation.namespace_device,namespace_inode:observation.namespace_inode});
            drain.checkpoint()
        }
    }
    pub(in crate::storage_driver) fn publication(&self)->Result<PublicationRef,String> {
        self.publication.clone().ok_or("actual original Watch publication references absent".into())
    }
    /// Necessary READ-ONLY observation. Future caller must already root this
    /// probe in the real actor and provide its actual retained attach permit's
    /// deadline + fresh session. This accepts DATA, NOT effect authority.
    pub(in crate::storage_driver) fn capture_parent_observation(&mut self,
        scope:&ExpectedAttachScope,existing_round_deadline:Instant)->Result<(),String> {
        self.parent.capture(scope,existing_round_deadline)
    }
    /// The same rooted original FDs/scope/monotone budget survive every call.
    /// Success returns diagnostic DATA only, never permission to mount.
    pub(in crate::storage_driver) fn recheck_parent_before_effect(&mut self,
        scope:&ExpectedAttachScope,existing_deadline:Instant)->Result<ParentObservation,String> {
        self.parent.recheck(scope,existing_deadline)
    }
    /// Called ONLY on the SAME actual fixed dispatcher thread after verified
    /// original Child terminal + both EOF + actual cgroup drain. Raw helper
    /// output cannot call this function or fabricate its opaque drain input.
    pub(in crate::storage_driver) fn install_after_actual_drain(&mut self,
        drain:&VerifiedAttachDrain)->Result<(),String> {
        if self.provisional.is_some(){return self.install_provisional_after_actual_drain(drain);}
        if self.installed.is_some() || self.namespace.is_some() || self.block.is_some()
            || self.mounted.is_some() || self.daemon.is_some() {
            return Err("mount probe already started; no retry/adopt/reopen after UNKNOWN".into());
        }
        #[cfg(not(target_os="linux"))]
        {let _=drain;return Err("actual managed mount ownership requires Linux".into());}
        #[cfg(target_os="linux")]
        {
            use std::os::unix::fs::{FileTypeExt,FileExt};
            drain.checkpoint()?;
            drain.require_original_watch_files()?;
            let scope=drain.scope();scope.validate()?;
            if scope.phase!=crate::storage_lifecycle::pod_attachment::AttachPhase::ObserveMounted
                || scope.mount_ref.epoch()!=1 || scope.mount_ref.node_boot()!=&crate::storage_boot::BootId::current()? {
                return Err("only first-epoch exact local mounted completion can install an owner".into());
            }
            self.namespace=Some(open_current_namespace()?);
            let namespace_identity=fd_identity(self.namespace.as_ref().unwrap())?;
            self.daemon=Some(crate::docker::inspect_managed_mount_daemon(drain.deadline())?);
            let daemon=self.daemon.as_ref().unwrap();
            daemon.validate_current(drain.deadline())?;
            if daemon.identity()!=namespace_identity {return Err("daemon/dispatcher namespace differs".into());}
            let (major,minor,bytes)=drain.block_identity();
            self.block=Some(open_exact_block(&format!("/dev/drbd{minor}"))?);
            let block=self.block.as_ref().unwrap();
            drain.require_original_watch_files()?;
            let metadata=block.metadata().map_err(|_|"cannot independently stat mounted block FD")?;
            let mut observed_bytes=0u64;
            use std::os::fd::AsRawFd;
            if !metadata.file_type().is_block_device() || metadata.rdev()!=libc::makedev(major,minor)
                || unsafe{libc::ioctl(block.as_raw_fd(),0x80081272u32 as _,&mut observed_bytes)}!=0
                || observed_bytes!=bytes || bytes!=scope.generation.virgin_replicas[0].exposed_bytes {
                return Err("actual mounted block identity/geometry differs".into());
            }
            drain.require_original_watch_files()?;
            // Read only fixed ext4 superblock fields, never trust a label or
            // helper's UUID. Each direct read is bound to fresh actual Core.
            let mut superblock=[0u8;120];
            drain.checkpoint()?;
            block.read_exact_at(&mut superblock,1024).map_err(|_|"mounted block UUID read failed; retained UNKNOWN")?;
            drain.checkpoint()?;
            if superblock[56..58]!=[0x53,0xef] || format_uuid(&superblock[104..120])?!=scope.generation.filesystem_uuid {
                return Err("independent mounted ext4 UUID differs from dataset".into());
            }
            let target=mount_path(&scope.mount_ref);
            self.mounted=Some(open_private_target(&target)?);
            let mounted=self.mounted.as_ref().unwrap();
            drain.require_original_watch_files()?;
            let observation=observe_mounted(mounted,&target,namespace_identity,major,minor,&scope.generation.filesystem_uuid)?;
            drain.require_original_watch_files()?;
            let reported=drain.observation()?.mounted.as_ref().ok_or("supervised final mounted observation absent")?;
            if &observation!=reported {return Err("Watch's independently reopened mount differs from supervised helper".into());}
            self.parent.recheck_after_actual_mount(self.mount_scope.as_ref().ok_or("original premount scope absent")?,
                drain,&observation)?;
            daemon.validate_current(drain.deadline())?;
            drain.checkpoint()?;
            self.anchor.record_mounted(drain,mounted,&observation)?;
            // All fallible checks precede these moves. The containing probe is
            // already root-owned, so no error/ticket Drop can discard owners.
            self.installed=Some(VerifiedManagedMount {
                namespace:self.namespace.take().unwrap(),block:Some(self.block.take().unwrap()),
                mounted:Some(self.mounted.take().unwrap()),daemon:self.daemon.take().unwrap(),
                scope:scope.clone(),observation,evidence_uid:Uid::new(),
                evidence_sha256:drain.evidence_sha256().to_string(),
                watch_process:drain.original_watch_process(),
                provisional_origin:None,
            });
            Ok(())
        }
    }
    pub(in crate::storage_driver) fn installed(&self)->Result<&VerifiedManagedMount,String> {
        if self.terminal.is_some(){return Err("original mounted owner entered irreversible terminal path; no consumer/READY borrow".into());}
        self.installed.as_ref().ok_or("actual Watch mount FD owner not installed".into())
    }
}

/// DATA carried only INSIDE the actual private v5 capsule. A deserialized copy
/// cannot create a worker permit, parent probe, drain or mounted lifetime.
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::storage_driver) struct PublicationRef {
    target_device:u64,target_inode:u64,target_mount_id:u64,
    parent:KernelParentIdentity,anchor_device:u64,anchor_inode:u64,anchor_mount_id:u64,
    namespace_device:u64,namespace_inode:u64,
}

#[derive(Clone,Copy,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelParentIdentity {
    device:u64,inode:u64,mount_id:u64,major:u32,minor:u32,
    uid:u32,gid:u32,mode:u32,nlink:u64,
}
/// Last necessary kernel observation DATA. No FD/lease/permit/serde input or
/// boolean-allow constructor. Parsed or cloned data cannot reconstruct a probe.
#[derive(Clone,Debug,PartialEq,Eq,Serialize)]
pub(in crate::storage_driver) struct ParentObservation {
    kind:&'static str,
    scope_sha256:String,
    target:String,parent_path:String,
    parent:KernelParentIdentity,
    covering_path:String,
    namespace_device:u64,namespace_inode:u64,
    observed_boot:crate::storage_boot::BootId,
}
struct ObservationBudget {original:Instant,current:Instant}
impl ObservationBudget {
    fn new(deadline:Instant,now:Instant)->Result<Self,String> {
        if now>=deadline {return Err("original parent observation budget expired".into());}
        Ok(Self {original:deadline,current:deadline})
    }
    fn check(&mut self,requested:Instant,now:Instant)->Result<(),String> {
        if requested>self.current || self.current>self.original || now>=requested {
            return Err("parent observation deadline expired/renewed; no recapture".into());
        }
        self.current=requested;Ok(())
    }
}
/// Operational references INSIDE the actual root-owned Watch probe, never an
/// HTTP/oneshot result. Empty has no positive authority. Partial acquired FDs
/// are assigned before each later fallible observation, retained on UNKNOWN.
struct ParentFdProbe {
    attempted:bool,unknown:bool,
    scope_sha256:Option<String>,budget:Option<ObservationBudget>,
    namespace_held:Option<File>,parent_held:Option<File>,
    namespace_fresh:Option<File>,parent_fresh:Option<File>,
    observation:Option<ParentObservation>,
}
impl ParentFdProbe {
    fn empty()->Self {
        Self {attempted:false,unknown:false,scope_sha256:None,budget:None,
            namespace_held:None,parent_held:None,namespace_fresh:None,parent_fresh:None,observation:None}
    }
    fn require_first_capture(&self)->Result<(),String> {
        if self.attempted || self.unknown {return Err("parent capture is one-shot/UNKNOWN; no replacement".into());}Ok(())
    }
    fn capture(&mut self,scope:&ExpectedAttachScope,deadline:Instant)->Result<(),String> {
        let result=(|| {
            self.require_first_capture()?;
            self.attempted=true;
            self.budget=Some(ObservationBudget::new(deadline,Instant::now())?);
            self.scope_sha256=Some(crate::storage_lifecycle::pod_attachment::scope_digest(scope)?);
            #[cfg(not(target_os="linux"))]
            {let _=scope;return Err("actual parent FD observation requires Linux; no path-only fallback".into());}
            #[cfg(target_os="linux")]
            {
                Self::scope_boot(scope)?;
                let target=mount_path(&scope.mount_ref);
                let parent_path=parent_path(&target)?;
                self.namespace_held=Some(open_current_namespace()?);
                self.parent_held=Some(open_private_target(&parent_path)?);
                let parent=observe_parent_kernel(self.parent_held.as_ref().unwrap())?;
                require_private_parent(&parent)?;
                let ns=fd_identity(self.namespace_held.as_ref().unwrap())?;
                let rows=read_mounts()?;
                let mount_id=private_covering_parent(&rows,&target,&parent)?;
                let covering_path=rows.iter().find(|row|row.id==mount_id).ok_or("actual parent row absent")?.target.clone();
                self.observation=Some(ParentObservation {kind:"royak-readonly-parent-fd-observation-v1",
                    scope_sha256:self.scope_sha256.clone().unwrap(),target,parent_path,parent,covering_path,
                    namespace_device:ns.0,namespace_inode:ns.1,observed_boot:crate::storage_boot::BootId::current()?});
                self.fresh_compare(scope,deadline)?;
                Ok(())
            }
        })();
        if result.is_err() {self.unknown=true;}result
    }
    fn recheck(&mut self,scope:&ExpectedAttachScope,deadline:Instant)->Result<ParentObservation,String> {
        let result=(|| {
            if !self.attempted || self.unknown || self.observation.is_none() {
                return Err("actual parent observation absent/partial/UNKNOWN; no action".into());
            }
            self.budget.as_mut().ok_or("original observation budget absent")?.check(deadline,Instant::now())?;
            #[cfg(not(target_os="linux"))]
            {let _=scope;return Err("parent FD recheck requires Linux".into());}
            #[cfg(target_os="linux")]
            {
                self.fresh_compare(scope,deadline)?;
                Ok(self.observation.as_ref().unwrap().clone())
            }
        })();
        if result.is_err() {self.unknown=true;}result
    }
    #[cfg(target_os="linux")]
    fn scope_boot(scope:&ExpectedAttachScope)->Result<(),String> {
        scope.validate()?;
        if scope.phase!=crate::storage_lifecycle::pod_attachment::AttachPhase::Mount
            || scope.phase_boot!=crate::storage_boot::BootId::current()? {
            return Err("parent observation has another phase/actual boot".into());
        }Ok(())
    }
    #[cfg(target_os="linux")]
    fn fresh_compare(&mut self,scope:&ExpectedAttachScope,deadline:Instant)->Result<(),String> {
        Self::scope_boot(scope)?;
        self.budget.as_mut().ok_or("original parent budget absent")?.check(deadline,Instant::now())?;
        if self.unknown || self.scope_sha256.as_deref()!=Some(crate::storage_lifecycle::pod_attachment::scope_digest(scope)?.as_str())
            || self.parent_fresh.is_some() || self.namespace_fresh.is_some() {
            return Err("parent scope changed/UNKNOWN or partial recheck retained; never replace".into());
        }
        let old=self.observation.as_ref().ok_or("original parent identity absent")?.clone();
        self.parent_fresh=Some(open_private_target(&old.parent_path)?);
        let held=observe_parent_kernel(self.parent_held.as_ref().ok_or("original parent FD missing")?)?;
        let fresh=observe_parent_kernel(self.parent_fresh.as_ref().unwrap())?;
        require_private_parent(&held)?;require_private_parent(&fresh)?;
        compare_parent_identity(&old.parent,&held,&fresh)?;
        let rows=read_mounts()?;
        let mount_id=private_covering_parent(&rows,&old.target,&fresh)?;
        if mount_id!=old.parent.mount_id {return Err("current parent mountID changed".into());}
        // Open current-thread namespace AFTER fresh parent and mountinfo reads.
        // Every acquired reference is rooted before any metadata/check failure.
        self.namespace_fresh=Some(open_current_namespace()?);
        let original_ns=fd_identity(self.namespace_held.as_ref().ok_or("original namespace FD missing")?)?;
        let current_ns=fd_identity(self.namespace_fresh.as_ref().unwrap())?;
        if original_ns!=(old.namespace_device,old.namespace_inode) || current_ns!=original_ns
            || crate::storage_boot::BootId::current()?!=old.observed_boot {
            return Err("actual parent namespace/boot changed".into());
        }
        self.budget.as_mut().unwrap().check(deadline,Instant::now())?;
        // Only successfully validated REDUNDANT observations close here. Both
        // ORIGINAL parent/ns FDs stay root-owned. Any failure above retains all
        // acquired references and the outer caller latches this probe UNKNOWN.
        drop(self.parent_fresh.take());drop(self.namespace_fresh.take());
        Ok(())
    }
    #[cfg(target_os="linux")]
    fn recheck_after_actual_mount(&mut self,original_scope:&ExpectedAttachScope,
        drain:&VerifiedAttachDrain,mounted:&MountObservation)->Result<(),String> {
        let result=(|| {
            Self::scope_boot(original_scope)?;
            let old=self.observation.as_ref().ok_or("premount original parent witness absent")?.clone();
            if self.unknown || !self.attempted || original_scope.mount_ref!=drain.scope().mount_ref
                || original_scope.round_uid!=drain.scope().round_uid || mounted.target!=old.target
                || self.scope_sha256.as_deref()!=Some(crate::storage_lifecycle::pod_attachment::scope_digest(original_scope)?.as_str()) {
                return Err("post-mount drain not the exact original target/round".into());
            }
            self.budget.as_mut().ok_or("original parent budget absent")?.check(drain.deadline(),Instant::now())?;
            if self.parent_fresh.is_some() || self.namespace_fresh.is_some(){return Err("partial parent recheck retained".into());}
            self.parent_fresh=Some(open_private_target(&old.parent_path)?);
            let held=observe_parent_kernel(self.parent_held.as_ref().ok_or("held parent absent")?)?;
            let fresh=observe_parent_kernel(self.parent_fresh.as_ref().unwrap())?;
            compare_parent_identity(&old.parent,&held,&fresh)?;
            let mut rows=read_mounts()?;
            let actual=exact_mounted(&rows,&mounted.target,mounted.device_major,mounted.device_minor)?;
            if actual.id!=mounted.mount_id{return Err("actual post-mount row differs from actual drain".into());}
            // Remove ONLY the genuine exact new mounted row just joined to the
            // private actual drain. Never accept a caller allow-existing flag.
            rows.retain(|row|row.id!=mounted.mount_id);
            private_covering_parent(&rows,&old.target,&fresh)?;
            self.namespace_fresh=Some(open_current_namespace()?);
            if fd_identity(self.namespace_fresh.as_ref().unwrap())?!=(old.namespace_device,old.namespace_inode)
                || fd_identity(self.namespace_held.as_ref().ok_or("original namespace absent")?)?!=(old.namespace_device,old.namespace_inode)
                || crate::storage_boot::BootId::current()?!=old.observed_boot {
                return Err("post-mount actual namespace/boot changed".into());
            }
            drain.checkpoint()?;
            drop(self.parent_fresh.take());drop(self.namespace_fresh.take());Ok(())
        })();if result.is_err(){self.unknown=true;}result
    }
    /// Necessary local FD observation only. The fixed dispatcher owns the
    /// genuine pre/post fresh barriers OUTSIDE the containing probe mutex.
    #[cfg(target_os="linux")]
    fn recheck_owned_mount_without_fresh_grant(&mut self,original_scope:&ExpectedAttachScope,
        drain:&VerifiedAttachDrain,mounted:&MountObservation)->Result<(),String>{
        let result=(||{
            Self::scope_boot(original_scope)?;
            let old=self.observation.as_ref().ok_or("original premount parent absent")?.clone();
            if self.unknown||!self.attempted||original_scope.mount_ref!=drain.scope().mount_ref
                ||original_scope.round_uid!=drain.scope().round_uid||mounted.target!=old.target
                ||self.scope_sha256.as_deref()!=Some(crate::storage_lifecycle::pod_attachment::scope_digest(original_scope)?.as_str()){
                return Err("provisional mount differs from SAME original parent/round".into());}
            self.budget.as_mut().ok_or("original parent deadline absent")?.check(drain.deadline(),Instant::now())?;
            if self.parent_fresh.is_some()||self.namespace_fresh.is_some(){return Err("partial parent observation remains rooted".into());}
            self.parent_fresh=Some(open_private_target(&old.parent_path)?);
            let held=observe_parent_kernel(self.parent_held.as_ref().ok_or("original parent FD absent")?)?;
            let fresh=observe_parent_kernel(self.parent_fresh.as_ref().unwrap())?;
            compare_parent_identity(&old.parent,&held,&fresh)?;
            let mut rows=read_mounts()?;
            let actual=exact_mounted(&rows,&mounted.target,mounted.device_major,mounted.device_minor)?;
            if actual.id!=mounted.mount_id{return Err("provisional actual mount row changed".into());}
            // Existing parent-only coverage algorithm; the whole-pool raw
            // inventory classifier never erases or normalizes any rows.
            rows.retain(|row|row.id!=mounted.mount_id);
            private_covering_parent(&rows,&old.target,&fresh)?;
            self.namespace_fresh=Some(open_current_namespace()?);
            if fd_identity(self.namespace_fresh.as_ref().unwrap())?!=(old.namespace_device,old.namespace_inode)
                ||fd_identity(self.namespace_held.as_ref().ok_or("original namespace FD absent")?)?!=(old.namespace_device,old.namespace_inode)
                ||crate::storage_boot::BootId::current()?!=old.observed_boot{return Err("provisional original namespace/boot changed".into());}
            drain.require_current_origin_without_io_grant()?;
            drop(self.parent_fresh.take());drop(self.namespace_fresh.take());Ok(())
        })();if result.is_err(){self.unknown=true;}result
    }
}
fn parent_path(target:&str)->Result<String,String> {
    std::path::Path::new(target).parent().and_then(|p|p.to_str()).map(str::to_string)
        .ok_or("fixed target has no canonical parent".into())
}
fn require_private_parent(parent:&KernelParentIdentity)->Result<(),String> {
    if parent.inode==0 || parent.uid!=0 || parent.mode&0o077!=0 {
        return Err("actual mount parent is not root-owned private metadata".into());
    }Ok(())
}
fn compare_parent_identity(original:&KernelParentIdentity,held:&KernelParentIdentity,
    reopened:&KernelParentIdentity)->Result<(),String> {
    if held!=original || reopened!=original {
        return Err("parent pathname or held FD is covered/replaced/changed".into());
    }Ok(())
}
#[cfg(target_os="linux")]
fn observe_parent_kernel(file:&File)->Result<KernelParentIdentity,String> {
    let before=file.metadata().map_err(|_|"parent FD metadata unavailable")?;
    if !before.is_dir() {return Err("actual parent FD is not a directory".into());}
    let stat=statx_abi::observe(file,libc::major(before.dev()),libc::minor(before.dev()))?;
    let after=file.metadata().map_err(|_|"parent FD post-observation unavailable")?;
    let record=|m:&std::fs::Metadata|KernelParentIdentity {device:m.dev(),inode:m.ino(),mount_id:stat.mount_id,
        major:libc::major(m.dev()),minor:libc::minor(m.dev()),uid:m.uid(),gid:m.gid(),mode:m.mode(),nlink:m.nlink()};
    if !after.is_dir() || record(&before)!=record(&after) {return Err("actual parent identity changed during statx observation".into());}
    Ok(record(&after))
}

/// Move-only physical lifetime; never Deserialize/Clone/default/raw FD input.
/// Drop closes observation FDs only: it NEVER unmounts/demotes/releases writer.
/// Actual runtime book retains this even when the HTTP/ticket caller vanishes.
pub(crate) struct VerifiedManagedMount {
    namespace:File,
    block:Option<File>,
    mounted:Option<File>,
    daemon:crate::docker::VerifiedDaemonNamespace,
    scope:ExpectedAttachScope,
    observation:MountObservation,
    evidence_uid:Uid,
    evidence_sha256:String,
    watch_process:std::sync::Arc<std::sync::Mutex<terminal::origin::WatchProcessPin>>,
    provisional_origin:Option<std::sync::Arc<VerifiedAttachDrain>>,
}
impl VerifiedManagedMount {
    pub(in crate::storage_driver) fn consumer_connection(&self,deadline:Instant)
        ->Result<crate::docker::ManagedConsumerConnection,String>{
        self.require_original_watch_files()?;
        let result=crate::docker::open_managed_consumer(&self.daemon,deadline)?;
        self.require_original_watch_files()?;Ok(result)
    }
    fn require_original_watch_files(&self)->Result<(),String>{
        self.watch_process.lock().map_err(|_|"original installed Watch file-table source poisoned")?
            .verify_serving_thread(&self.scope.phase_boot)
    }
    pub(in crate::storage_driver) fn scope(&self)->&ExpectedAttachScope {&self.scope}
    pub(in crate::storage_driver) fn evidence_uid(&self)->&Uid {&self.evidence_uid}
    pub(in crate::storage_driver) fn evidence_sha256(&self)->&str {&self.evidence_sha256}
    pub(in crate::storage_driver) fn observation(&self)->&MountObservation {&self.observation}
    /// Read-only liveness, NOT a new launch grant. The caller must separately
    /// possess its fresh actual Core/action-bound permission and own deadline.
    pub(in crate::storage_driver) fn reobserve(&self,existing_action_deadline:Instant)->Result<(),String> {
        #[cfg(not(target_os="linux"))]
        {let _=existing_action_deadline;Err("managed mount liveness requires Linux".into())}
        #[cfg(target_os="linux")]
        {
            use std::os::unix::fs::FileTypeExt;
            if Instant::now()>=existing_action_deadline {return Err("action budget expired; no mounted action".into());}
            self.require_original_watch_files()?;
            self.daemon.validate_current(existing_action_deadline)?;
            let now=open_current_namespace()?;
            let identity=fd_identity(&now)?;
            if identity!=fd_identity(&self.namespace)? || identity!=self.daemon.identity() {
                return Err("actual mount namespace changed".into());
            }
            let block=self.block.as_ref().ok_or("original block reference already terminal-consumed")?
                .metadata().map_err(|_|"retained mounted block descriptor unavailable")?;
            if !block.file_type().is_block_device()
                || block.rdev()!=libc::makedev(self.observation.device_major,self.observation.device_minor) {
                return Err("retained mounted block identity changed".into());
            }
            let target=mount_path(&self.scope.mount_ref);
            let current=open_private_target(&target)?;
            let reopened=observe_mounted(&current,&target,identity,self.observation.device_major,
                self.observation.device_minor,&self.scope.generation.filesystem_uuid)?;
            let retained=observe_mounted(self.mounted.as_ref().ok_or("original mounted reference already terminal-consumed")?,&target,identity,self.observation.device_major,
                self.observation.device_minor,&self.scope.generation.filesystem_uuid)?;
            if reopened!=self.observation || retained!=self.observation {
                return Err("published source no longer names the same retained mount".into());
            }
            self.daemon.validate_current(existing_action_deadline)?;
            self.require_original_watch_files()
        }
    }
}

#[derive(Debug,PartialEq,Eq)]
struct MountRow {id:u64,parent:u64,major:u32,minor:u32,root:String,target:String,
    options:Vec<String>,optional:Vec<String>,filesystem:String,source:String,super_options:Vec<String>}
fn unescape_mount(value:&str)->Result<String,String> {
    let raw=value.as_bytes();let mut at=0;let mut result=Vec::with_capacity(raw.len());
    while at<raw.len() {
        if raw[at]==b'\\' {
            let escaped=raw.get(at..at+4).ok_or("truncated mountinfo escape")?;
            result.push(match escaped {b"\\040"=>b' ',b"\\011"=>b'\t',b"\\012"=>b'\n',b"\\134"=>b'\\',
                _=>return Err("unknown mountinfo escape".into())});at+=4;
        } else {result.push(raw[at]);at+=1;}
    }
    String::from_utf8(result).map_err(|_|"non-UTF8 mountinfo path".into())
}
fn parse_mounts(raw:&str)->Result<Vec<MountRow>,String> {
    if raw.len()>1024*1024 || raw.lines().count()>4096 {return Err("mountinfo exceeds bounded observation".into());}
    let mut ids=BTreeSet::new();let mut rows=Vec::new();
    for line in raw.lines() {
        let (left,right)=line.split_once(" - ").ok_or("malformed mountinfo delimiter")?;
        let l:Vec<_>=left.split_whitespace().collect();let r:Vec<_>=right.split_whitespace().collect();
        if l.len()<6 || r.len()!=3 {return Err("malformed mountinfo field count".into());}
        let id=l[0].parse::<u64>().map_err(|_|"invalid mount ID")?;
        let parent=l[1].parse::<u64>().map_err(|_|"invalid parent mount ID")?;
        let (major,minor)=l[2].split_once(':').ok_or("invalid mount device")?;
        let major=major.parse::<u32>().map_err(|_|"invalid mount major")?;
        let minor=minor.parse::<u32>().map_err(|_|"invalid mount minor")?;
        let root=unescape_mount(l[3])?;let target=unescape_mount(l[4])?;
        if id==0 || !ids.insert(id) || !root.starts_with('/') || !target.starts_with('/') {
            return Err("duplicate/invalid mount identity".into());
        }
        rows.push(MountRow {id,parent,major,minor,root,target,options:l[5].split(',').map(str::to_string).collect(),
            optional:l[6..].iter().map(|v|v.to_string()).collect(),filesystem:r[0].into(),source:unescape_mount(r[1])?,
            super_options:r[2].split(',').map(str::to_string).collect()});
    }
    if rows.is_empty() {return Err("empty mountinfo is not private propagation proof".into());}Ok(rows)
}
fn within(path:&str,ancestor:&str)->bool {
    ancestor=="/" || path==ancestor || path.strip_prefix(ancestor).is_some_and(|suffix|suffix.starts_with('/'))
}
fn private_covering_parent(rows:&[MountRow],target:&str,actual:&KernelParentIdentity)->Result<u64,String> {
    if rows.iter().any(|r|r.target==target || within(&r.target,target)) {
        return Err("attachment target already mounted or contains another mount; no adoption".into());
    }
    let parent=parent_path(target)?;
    let mut paths=std::collections::BTreeMap::new();
    for row in rows.iter().filter(|row|within(&parent,&row.target)) {
        if paths.insert(row.target.as_str(),row).is_some() {
            return Err("stacked/duplicate covering parent path; no lexical selection".into());
        }
    }
    let depth=paths.keys().map(|path|path.len()).max().ok_or("mount parent has no kernel covering mount")?;
    let mut deepest=paths.values().filter(|row|row.target.len()==depth);
    let covering=deepest.next().ok_or("deepest parent absent")?;
    if deepest.next().is_some() || actual.mount_id==0 || actual.inode==0
        || covering.id!=actual.mount_id || covering.major!=actual.major || covering.minor!=actual.minor {
        return Err("deepest covering row is not the actual held/reopened parent FD mount/device".into());
    }
    // Shared/master/propagate_from are specifically unsafe before mount.
    // Unknown optional tags also refuse, never normalize foreign policy.
    if !covering.optional.is_empty() {return Err("covering mount is not proven private; no root/foreign propagation mutation".into());}
    Ok(covering.id)
}
fn exact_mounted<'a>(rows:&'a[MountRow],target:&str,major:u32,minor:u32)->Result<&'a MountRow,String> {
    let mut found=rows.iter().filter(|r|r.target==target);
    let row=found.next().ok_or("actual new target mount absent")?;
    if found.next().is_some() || rows.iter().any(|r|r.target!=target && within(&r.target,target))
        || row.major!=major || row.minor!=minor || row.root!="/" || row.filesystem!="ext4"
        || !row.optional.is_empty() || !row.options.iter().any(|v|v=="rw")
        || row.options.iter().any(|v|v=="ro") {
        return Err("mounted target is stacked/foreign/non-private/read-only or wrong initialized device".into());
    }
    Ok(row)
}
fn format_uuid(bytes:&[u8])->Result<String,String> {
    if bytes.len()!=16 || bytes.iter().all(|v|*v==0) {return Err("invalid actual filesystem UUID".into());}
    let hex:String=bytes.iter().map(|b|format!("{b:02x}")).collect();
    Ok(format!("{}-{}-{}-{}-{}",&hex[..8],&hex[8..12],&hex[12..16],&hex[16..20],&hex[20..]))
}
#[cfg(target_os="linux")]
fn owned_fd(raw:i32)->Result<File,String> {
    use std::os::fd::FromRawFd;
    if raw<0 {Err("cannot open actual anchored mount object".into())} else {Ok(unsafe{File::from_raw_fd(raw)})}
}
fn fd_identity(file:&File)->Result<(u64,u64),String> {
    let m=file.metadata().map_err(|_|"actual mounted FD metadata unavailable")?;Ok((m.dev(),m.ino()))
}
#[cfg(target_os="linux")]
fn open_current_namespace()->Result<File,String> {
    use std::os::fd::AsRawFd;
    let file=owned_fd(unsafe{libc::open(c"/proc/thread-self/ns/mnt".as_ptr(),libc::O_RDONLY|libc::O_CLOEXEC)})?;
    let mut fs:libc::statfs=unsafe{std::mem::zeroed()};
    if unsafe{libc::fstatfs(file.as_raw_fd(),&mut fs)}!=0 || fs.f_type as u64!=0x6e736673
        || unsafe{libc::ioctl(file.as_raw_fd(),0xb703)}!=libc::CLONE_NEWNS {
        return Err("actual Watch thread namespace not proved".into());
    }Ok(file)
}
#[cfg(target_os="linux")]
fn open_exact_block(path:&str)->Result<File,String> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new().read(true).custom_flags(libc::O_CLOEXEC|libc::O_NOFOLLOW).open(path)
        .map_err(|_|"cannot open exact initialized DRBD block FD".into())
}
#[cfg(target_os="linux")]
fn open_private_target(path:&str)->Result<File,String> {
    use std::os::fd::AsRawFd;
    use std::path::{Path,Component};use std::ffi::CString;
    if !path.starts_with("/var/lib/royak/storage/mounts/") {return Err("mount target outside fixed reserved root".into());}
    let mut current=owned_fd(unsafe{libc::open(c"/".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_CLOEXEC)})?;
    let parts:Vec<_>=Path::new(path).components().collect();let mut prefix=String::new();
    for (i,part) in parts.iter().enumerate() {
        let Component::Normal(part)=part else {if *part==Component::RootDir {continue;} return Err("noncanonical mount target".into());};
        let part=part.to_str().ok_or("invalid target encoding")?;prefix.push('/');prefix.push_str(part);
        let name=CString::new(part).map_err(|_|"invalid target component")?;
        current=owned_fd(unsafe{libc::openat(current.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
        let m=current.metadata().map_err(|_|"cannot stat actual mount parent")?;
        let private=prefix.starts_with("/var/lib/royak/storage");
        if m.uid()!=0 || m.mode()&0o022!=0 || private && i+1<parts.len() && m.mode()&0o077!=0 {
            return Err("mount ancestors must be canonical root-owned and reserved parents private".into());
        }
    }Ok(current)
}
#[cfg(target_os="linux")]
fn read_mounts()->Result<Vec<MountRow>,String> {
    use std::io::Read;use std::os::{fd::AsRawFd,unix::fs::OpenOptionsExt};
    let mut file=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_CLOEXEC|libc::O_NOFOLLOW)
        .open("/proc/thread-self/mountinfo").map_err(|_|"cannot observe actual Watch thread mountinfo")?;
    let mut fs:libc::statfs=unsafe{std::mem::zeroed()};
    if unsafe{libc::fstatfs(file.as_raw_fd(),&mut fs)}!=0 || fs.f_type as u64!=0x9fa0 {
        return Err("mountinfo is not actual procfs".into());
    }
    let mut raw=String::new();file.by_ref().take(1024*1024+1).read_to_string(&mut raw).map_err(|_|"mountinfo read failed")?;
    parse_mounts(&raw)
}
#[cfg(target_os="linux")]
fn observe_mounted(file:&File,target:&str,namespace:(u64,u64),major:u32,minor:u32,uuid:&str)->Result<MountObservation,String> {
    use std::os::fd::AsRawFd;
    let stat=statx_abi::observe(file,major,minor)?;
    let mut fs:libc::statfs=unsafe{std::mem::zeroed()};
    if unsafe{libc::fstatfs(file.as_raw_fd(),&mut fs)}!=0 || fs.f_type as u64!=0xef53 {
        return Err("new mount FD lacks actual mountID/ext4/block device identity".into());
    }
    let rows=read_mounts()?;let row=exact_mounted(&rows,target,major,minor)?;
    if row.id!=stat.mount_id {return Err("retained FD identifies covered/detached/another mount".into());}
    Ok(MountObservation {mount_id:row.id,namespace_device:namespace.0,namespace_inode:namespace.1,
        device_major:major,device_minor:minor,filesystem_uuid:uuid.into(),target:target.into(),private_propagation:true})
}

/// Fixed Linux v6.8 UAPI byte layout, independent of libc's optional musl
/// statx wrapper exports. No path/st_dev fallback or missing-mask waiver.
/// Reference: torvalds/linux v6.8 include/uapi/linux/stat.h. Fields are local
/// Rust DATA, never an FD/mount/readiness capability or a wire constructor.
#[cfg(any(target_os="linux",test))]
mod statx_abi {
    use std::mem::{align_of,offset_of,size_of};
    const BASIC:u32=0x07ff;
    const MOUNT_ID:u32=0x1000;
    const REQUEST:u32=BASIC|MOUNT_ID;
    #[repr(C)]
    #[derive(Clone,Copy)]
    struct Timestamp {seconds:i64,nanoseconds:u32,reserved:i32}
    #[repr(C)]
    struct KernelStatx {
        mask:u32,block_size:u32,attributes:u64,
        links:u32,uid:u32,gid:u32,mode:u16,spare0:[u16;1],
        inode:u64,bytes:u64,blocks:u64,attribute_mask:u64,
        accessed:Timestamp,born:Timestamp,changed:Timestamp,modified:Timestamp,
        special_major:u32,special_minor:u32,device_major:u32,device_minor:u32,
        mount_id:u64,direct_memory_alignment:u32,direct_offset_alignment:u32,
        spare3:[u64;12],
    }
    // UAPI's complete output buffer, not a short prefix supplied to kernel.
    const _:()={
        assert!(size_of::<Timestamp>()==16);
        assert!(align_of::<Timestamp>()==align_of::<i64>());
        assert!(offset_of!(Timestamp,seconds)==0);
        assert!(offset_of!(Timestamp,nanoseconds)==8);
        assert!(offset_of!(Timestamp,reserved)==12);
        assert!(size_of::<KernelStatx>()==0x100);
        assert!(align_of::<KernelStatx>()==align_of::<u64>());
        assert!(offset_of!(KernelStatx,mask)==0x00);
        assert!(offset_of!(KernelStatx,attributes)==0x08);
        assert!(offset_of!(KernelStatx,links)==0x10);
        assert!(offset_of!(KernelStatx,mode)==0x1c);
        assert!(offset_of!(KernelStatx,inode)==0x20);
        assert!(offset_of!(KernelStatx,accessed)==0x40);
        assert!(offset_of!(KernelStatx,born)==0x50);
        assert!(offset_of!(KernelStatx,changed)==0x60);
        assert!(offset_of!(KernelStatx,modified)==0x70);
        assert!(offset_of!(KernelStatx,special_major)==0x80);
        assert!(offset_of!(KernelStatx,device_major)==0x88);
        assert!(offset_of!(KernelStatx,device_minor)==0x8c);
        assert!(offset_of!(KernelStatx,mount_id)==0x90);
        assert!(offset_of!(KernelStatx,direct_memory_alignment)==0x98);
        assert!(offset_of!(KernelStatx,direct_offset_alignment)==0x9c);
        assert!(offset_of!(KernelStatx,spare3)==0xa0);
    };
    #[cfg(target_pointer_width="64")]
    const _:()=assert!(align_of::<KernelStatx>()==8);
    impl KernelStatx {
        fn zeroed()->Self {
            // Every member is an integer/array thereof; zero is valid and the
            // complete256B buffer exists before the kernel receives its pointer.
            unsafe{std::mem::zeroed()}
        }
    }
    #[derive(Debug,PartialEq,Eq)]
    pub(super) struct Identity {pub(super) mount_id:u64,pub(super) major:u32,pub(super) minor:u32}
    fn decode(result:i64,errno:Option<i32>,raw:&KernelStatx,major:u32,minor:u32)->Result<Identity,String> {
        if result==-1 {
            return Err(match errno {Some(value) if value>0=>format!("FD statx syscall failed (errno {value}); no fallback"),
                _=>"FD statx syscall failed with unavailable errno; no fallback".into()});
        }
        if result!=0 {return Err("unexpected nonzero FD statx syscall result; no fallback".into());}
        if raw.mask&MOUNT_ID==0 || raw.mount_id==0 || raw.device_major!=major || raw.device_minor!=minor {
            return Err("FD statx lacks exact supported mountID/device identity; no fallback".into());
        }
        Ok(Identity {mount_id:raw.mount_id,major:raw.device_major,minor:raw.device_minor})
    }
    #[cfg(target_os="linux")]
    fn observe_raw(fd:std::os::fd::RawFd,major:u32,minor:u32)->Result<Identity,String> {
        let mut raw=KernelStatx::zeroed();
        // Empty, NON-NULL C string is required on the approved Linux6.8.
        // libc's syscall symbol exists for GNU+musl even when statx wrappers
        // and constants are feature-gated out of the locked libc crate.
        let result=unsafe{libc::syscall(libc::SYS_statx,fd,c"".as_ptr(),libc::AT_EMPTY_PATH,REQUEST,
            &mut raw as *mut KernelStatx)};
        // errno is meaningful only on -1; capture before any later call.
        let errno=if result==-1 {std::io::Error::last_os_error().raw_os_error()} else {None};
        let result=i64::try_from(result).map_err(|_|"FD statx result cannot fit checked representation")?;
        decode(result,errno,&raw,major,minor)
    }
    #[cfg(target_os="linux")]
    pub(super) fn observe(file:&std::fs::File,major:u32,minor:u32)->Result<Identity,String> {
        use std::os::fd::AsRawFd;
        observe_raw(file.as_raw_fd(),major,minor)
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        fn model()->KernelStatx {
            let mut raw=KernelStatx::zeroed();raw.mask=REQUEST;raw.mount_id=91;raw.device_major=147;raw.device_minor=9;raw
        }
        fn fdinfo_mount_id(raw:&str)->Result<u64,String> {
            if raw.len()>16*1024 {return Err("fdinfo exceeds fixed observation bound".into());}
            let mut values=raw.lines().filter(|line|line.starts_with("mnt_id:"));
            let line=values.next().ok_or("exact fdinfo mountID absent")?;
            if values.next().is_some() {return Err("duplicate fdinfo mountID".into());}
            let fields:Vec<_>=line.split_whitespace().collect();
            if fields.len()!=2 || fields[0]!="mnt_id:" {return Err("malformed fdinfo mountID".into());}
            let value=fields[1].parse::<u64>().map_err(|_|"invalid fdinfo mountID")?;
            if value==0 || value.to_string()!=fields[1] {return Err("noncanonical fdinfo mountID".into());}Ok(value)
        }
        #[test]
        fn statx_uapi_v68_layout_has_full_buffer_and_exact_offsets() {
            assert_eq!((size_of::<KernelStatx>(),align_of::<KernelStatx>()),(256,align_of::<u64>()));
            assert_eq!((size_of::<Timestamp>(),offset_of!(Timestamp,reserved)),(16,12));
            assert_eq!((offset_of!(KernelStatx,device_major),offset_of!(KernelStatx,device_minor),offset_of!(KernelStatx,mount_id)),(136,140,144));
            assert_eq!((offset_of!(KernelStatx,spare3),size_of::<[u64;12]>()),(160,96));
            assert_eq!(REQUEST,0x17ff);
        }
        #[test]
        fn statx_nonzero_returns_and_errno_are_refusals_without_fallback() {
            let raw=model();assert!(decode(0,None,&raw,147,9).is_ok());
            for (result,errno) in [(-1,Some(9)),(-1,Some(38)),(-1,None),(-1,Some(0)),(1,None),(-2,None)] {
                let error=decode(result,errno,&raw,147,9).unwrap_err();assert!(error.contains("no fallback"));
                if errno==Some(9) {assert!(error.contains("errno 9"));}
            }
        }
        #[test]
        fn statx_missing_mask_zero_mount_id_or_device_mismatch_never_admits() {
            for case in 0..4 {
                let mut raw=model();match case {0=>raw.mask&=!MOUNT_ID,1=>raw.mount_id=0,2=>raw.device_major=148,_=>raw.device_minor=10}
                assert!(decode(0,None,&raw,147,9).is_err(),"statx identity DATA case {case}");
            }
            let mut raw=model();raw.mount_id=u64::MAX;
            assert_eq!(decode(0,None,&raw,147,9).unwrap().mount_id,u64::MAX);
        }
        #[test]
        fn statx_fdinfo_data_parser_refuses_missing_duplicate_noncanonical_or_oversize() {
            assert_eq!(fdinfo_mount_id("pos:\t0\nflags:\t0100000\nmnt_id:\t91\nino:\t1\n").unwrap(),91);
            for raw in ["pos: 0\n","mnt_id: 0\n","mnt_id: 01\n","mnt_id: -1\n","mnt_id: 91 extra\n","mnt_id: 91\nmnt_id: 91\n"] {
                assert!(fdinfo_mount_id(raw).is_err());
            }
            assert!(fdinfo_mount_id(&"x".repeat(16*1024+1)).is_err());
        }
        #[test]
        #[cfg(target_os="linux")]
        fn actual_linux_statx_owned_fd_matches_fdinfo_fstat_and_invalid_fd_refuses() {
            use std::fs::{self,File,OpenOptions,DirBuilder};use std::io::Read;
            use std::os::{fd::AsRawFd,unix::fs::{DirBuilderExt,OpenOptionsExt,MetadataExt}};
            // Only fixture-owned temporary metadata, no mount/namespace/DRBD
            // changes. No positive readiness/lease/capability is produced.
            struct OwnedTemp {root:std::path::PathBuf,file:std::path::PathBuf}
            impl Drop for OwnedTemp {fn drop(&mut self){let _=fs::remove_file(&self.file);let _=fs::remove_dir(&self.root);}}
            let root=std::env::temp_dir().join(format!("royak-statx-{}",crate::storage_identity::Uid::new().as_str()));
            DirBuilder::new().mode(0o700).create(&root).unwrap();
            let owned=OwnedTemp {file:root.join("empty-owned-file"),root};
            let directory=File::open(&owned.root).unwrap();
            let file=OpenOptions::new().read(true).write(true).create_new(true).mode(0o600)
                .custom_flags(libc::O_CLOEXEC|libc::O_NOFOLLOW).open(&owned.file).unwrap();
            for file in [&directory,&file] {
                let before=file.metadata().unwrap();let major=libc::major(before.dev());let minor=libc::minor(before.dev());
                let observed=observe(file,major,minor).expect("approved Linux kernel must provide actual FD statx MNT_ID; no skip/fallback");
                let mut raw=String::new();File::open(format!("/proc/self/fdinfo/{}",file.as_raw_fd())).unwrap()
                    .take(16*1024+1).read_to_string(&mut raw).unwrap();
                assert_eq!(observed.mount_id,fdinfo_mount_id(&raw).unwrap());
                assert_eq!((observed.major,observed.minor),(major,minor));
                let after=file.metadata().unwrap();assert_eq!((before.dev(),before.ino()),(after.dev(),after.ino()));
            }
            // Deterministic invalid sentinel, NOT a claim about a just-closed
            // numeric FD (which other parallel tests could legitimately reuse).
            let error=observe_raw(-1,0,0).unwrap_err();assert!(error.contains(&format!("errno {}",libc::EBADF)));
            drop(file);drop(directory);
            fs::remove_file(&owned.file).unwrap();fs::remove_dir(&owned.root).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn row(optional:&str)->String {format!("1 1 0:1 / / rw{} - ext4 /dev/root rw\n",optional)}
    fn model_parent(id:u64,major:u32,minor:u32)->KernelParentIdentity {
        // DATA-only selector model, never a held FD/probe/mount capability.
        KernelParentIdentity {device:1,inode:7,mount_id:id,major,minor,uid:0,gid:0,mode:0o40700,nlink:2}
    }
    #[test]
    fn real_mountinfo_shapes_refuse_shared_cover_before_any_mount() {
        let target="/var/lib/royak/storage/mounts/a/1/b";
        assert_eq!(private_covering_parent(&parse_mounts(&row("")).unwrap(),target,&model_parent(1,0,1)).unwrap(),1);
        for tag in [" shared:1"," master:2"," propagate_from:2"," future:9"," unbindable"] {
            assert!(private_covering_parent(&parse_mounts(&row(tag)).unwrap(),target,&model_parent(1,0,1)).is_err());
        }
    }
    #[test]
    fn path_prefix_and_stacked_mounts_are_not_normalized_as_owned() {
        assert!(!within("/private-other","/private"));assert!(within("/private/a","/private"));
        let base=row("");let target="/var/lib/royak/storage/mounts/a/1/b";
        for suffix in ["", "/child"] {
            let raw=format!("{base}2 1 147:9 / {target}{suffix} rw - ext4 /dev/drbd9 rw\n");
            assert!(private_covering_parent(&parse_mounts(&raw).unwrap(),target,&model_parent(1,0,1)).is_err());
        }
        let raw=format!("{base}2 1 147:9 / {target} rw - ext4 /dev/drbd9 rw\n");
        assert!(exact_mounted(&parse_mounts(&raw).unwrap(),target,147,9).is_ok());
        for altered in [raw.replace("147:9","147:8"),raw.replace("/ /var/lib","/sub /var/lib"),
            raw.replace("rw - ext4 /dev/drbd9","rw shared:3 - ext4 /dev/drbd9"),
            raw.replace("rw - ext4 /dev/drbd9","ro - ext4 /dev/drbd9")] {
            assert!(exact_mounted(&parse_mounts(&altered).unwrap(),target,147,9).is_err());
        }
    }
    #[test]
    fn parser_keeps_escaped_paths_but_rejects_bad_identity_or_unknown_escape() {
        assert_eq!(unescape_mount("/a\\040b").unwrap(),"/a b");
        for raw in ["1 1 0:1 / /a\\777 rw - ext4 x rw\n".to_string(),
            format!("{}{}",row(""),row("")),String::new(),"broken\n".into()] {
            assert!(parse_mounts(&raw).is_err());
        }
    }
    #[test]
    fn empty_probe_is_no_mounted_capability() {
        let probe=WatchMountProbe::empty_before_effect();assert!(probe.installed().is_err());
    }
    #[test]
    fn parent_row_selection_needs_actual_fd_id_device_and_nonzero_inode() {
        let target="/var/lib/royak/storage/mounts/a/1/b";
        let raw=format!("{}5 1 8:1 / /var/lib/royak/storage/mounts rw - ext4 /dev/owned rw\n",row(""));
        let rows=parse_mounts(&raw).unwrap();let actual=model_parent(5,8,1);
        assert_eq!(private_covering_parent(&rows,target,&actual).unwrap(),5);
        for case in 0..5 {
            let mut bad=actual;match case {0=>bad.mount_id=1,1=>bad.major=9,2=>bad.minor=2,3=>bad.inode=0,_=>bad.mount_id=0}
            assert!(private_covering_parent(&rows,target,&bad).is_err(),"parent DATA case {case}");
        }
        // A lexical deeper row cannot admit an older covered parent FD.
        let rows=parse_mounts(&(raw+"6 5 8:1 / /var/lib/royak/storage/mounts/a/1 rw - ext4 /dev/owned rw\n")).unwrap();
        assert!(private_covering_parent(&rows,target,&actual).is_err());
    }
    #[test]
    fn stacked_covering_paths_refuse_before_choice_in_either_row_order() {
        let target="/var/lib/royak/storage/mounts/a/1/b";
        let one="5 1 8:1 / /var/lib/royak/storage/mounts rw - ext4 /dev/owned rw\n";
        let two="6 1 8:1 / /var/lib/royak/storage/mounts rw - ext4 /dev/owned rw\n";
        for (first,last) in [(one,two),(two,one)] {
            let rows=parse_mounts(&format!("{}{first}{last}",row(""))).unwrap();
            for id in [5,6] {assert!(private_covering_parent(&rows,target,&model_parent(id,8,1)).is_err());}
        }
        let rows=parse_mounts(&format!("{}2 1 0:1 / / rw - ext4 /dev/root rw\n{one}",row(""))).unwrap();
        assert!(private_covering_parent(&rows,target,&model_parent(5,8,1)).is_err());
    }
    #[test]
    fn parent_observation_budget_can_shorten_but_never_renew_or_reset() {
        let now=Instant::now();let original=now+Duration::from_secs(10);
        let mut budget=ObservationBudget::new(original,now).unwrap();
        let shorter=now+Duration::from_secs(5);budget.check(shorter,now).unwrap();
        assert_eq!(budget.original,original);assert_eq!(budget.current,shorter);
        assert!(budget.check(original,now+Duration::from_secs(1)).is_err());
        assert!(budget.check(shorter,shorter).is_err());
        assert!(ObservationBudget::new(now,now).is_err());
    }
    #[test]
    fn parent_capture_state_has_no_recapture_or_unknown_reset_path() {
        let mut probe=ParentFdProbe::empty();probe.require_first_capture().unwrap();
        probe.attempted=true;assert!(probe.require_first_capture().is_err());
        probe.unknown=true;assert!(probe.require_first_capture().is_err());
        assert!(probe.parent_held.is_none() && probe.namespace_held.is_none());
        assert!(probe.observation.is_none());
        // No File or positive action capability was fabricated for this model.
    }
    #[test]
    fn held_and_reopened_parent_must_match_exact_inode_mount_and_trust_fields() {
        let original=model_parent(5,8,1);compare_parent_identity(&original,&original,&original).unwrap();
        require_private_parent(&original).unwrap();
        for case in 0..8 {
            let mut bad=original;match case {0=>bad.inode+=1,1=>bad.device+=1,2=>bad.mount_id+=1,3=>bad.uid=1,
                4=>bad.gid+=1,5=>bad.mode=0o40755,6=>bad.nlink+=1,_=>bad.minor+=1}
            assert!(compare_parent_identity(&original,&original,&bad).is_err());
            assert!(compare_parent_identity(&original,&bad,&original).is_err());
        }
        let mut public=original;public.mode=0o40755;assert!(require_private_parent(&public).is_err());
        let mut foreign=original;foreign.uid=1;assert!(require_private_parent(&foreign).is_err());
    }
    #[test]
    #[cfg(target_os="linux")]
    fn actual_parent_fd_reopen_detects_owned_path_replacement_without_mount_mutation() {
        use std::fs::{self,DirBuilder};use std::os::unix::fs::DirBuilderExt;
        struct Owned {root:std::path::PathBuf,done:bool}
        impl Drop for Owned {fn drop(&mut self){if !self.done {
            let _=fs::remove_dir(self.root.join("parent"));let _=fs::remove_dir(self.root.join("parent-old"));let _=fs::remove_dir(&self.root);
        }}}
        let root=std::env::temp_dir().join(format!("royak-parent-{}",Uid::new().as_str()));
        DirBuilder::new().mode(0o700).create(&root).unwrap();let mut owned=Owned {root,done:false};
        let path=owned.root.join("parent");DirBuilder::new().mode(0o700).create(&path).unwrap();
        let ns=open_current_namespace().unwrap();let namespace=fd_identity(&ns).unwrap();
        let held=File::open(&path).unwrap();let original=observe_parent_kernel(&held).unwrap();
        let same=File::open(&path).unwrap();let repeated=observe_parent_kernel(&same).unwrap();
        compare_parent_identity(&original,&observe_parent_kernel(&held).unwrap(),&repeated).unwrap();
        drop(same);
        fs::rename(&path,owned.root.join("parent-old")).unwrap();
        DirBuilder::new().mode(0o700).create(&path).unwrap();
        let replacement=File::open(&path).unwrap();
        assert!(compare_parent_identity(&original,&observe_parent_kernel(&held).unwrap(),&observe_parent_kernel(&replacement).unwrap()).is_err());
        let current_ns=open_current_namespace().unwrap();assert_eq!(namespace,fd_identity(&current_ns).unwrap());
        drop(replacement);drop(held);drop(current_ns);drop(ns);
        fs::remove_dir(&path).unwrap();fs::remove_dir(owned.root.join("parent-old")).unwrap();fs::remove_dir(&owned.root).unwrap();owned.done=true;
        // Actual inode/FD observations only, not private propagation admission.
    }
}
