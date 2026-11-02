//! Genuine same-Watch provisional lifetime. A helper observation is DATA;
//! only the original supervised FilesystemMount drain can enter this slot.
//! No serde/raw path/FD/default/Clone constructor and no READY publication.
use super::*;
use std::sync::Arc;
use crate::storage_driver::native_runtime::mount::parent::AttachNativeStep;
use crate::storage_lifecycle::pod_attachment::AttachPhase;
use crate::storage_lifecycle::generation::VirginReplicaRef;
use std::os::fd::AsRawFd;
use std::sync::{Mutex,atomic::{AtomicBool,Ordering}};
#[path="managed_mount_inventory_census.rs"]
pub(in crate::storage_driver) mod census;
/// Readonly actual inherited mount/block observation, not an FD/capability
/// constructor. Caller holds the genuine profile7 context/current permission.
#[cfg(target_os="linux")]
pub(in crate::storage_driver) fn verify_inherited_member(mount:&File,block:&File,expected:&InventoryMemberObservation)->Result<(),String>{
    use std::os::unix::fs::{FileExt,FileTypeExt};
    let m=block.metadata().map_err(|_|"inherited original block metadata unavailable")?;let mut size=0u64;
    if !m.file_type().is_block_device()||m.rdev()!=libc::makedev(expected.mounted.device_major,expected.mounted.device_minor)
        ||unsafe{libc::ioctl(block.as_raw_fd(),0x80081272u32 as _,&mut size)}!=0||size!=expected.fact.exposed_bytes{
        return Err("actual inherited block geometry/device differs".into());}
    let mut superblock=[0u8;120];block.read_exact_at(&mut superblock,1024).map_err(|_|"actual inherited fixed ext4 UUID read failed")?;
    if superblock[56..58]!=[0x53,0xef]||format_uuid(&superblock[104..120])?!=expected.mounted.filesystem_uuid{
        return Err("actual inherited ext4 identity differs".into());}
    let ns=open_current_namespace()?;
    let observed=observe_mounted(mount,&expected.mounted.target,fd_identity(&ns)?,expected.mounted.device_major,
        expected.mounted.device_minor,&expected.mounted.filesystem_uuid)?;
    if observed!=expected.mounted{return Err("actual inherited mounted target/namespace/mountID differs".into());}Ok(())
}
#[cfg(not(target_os="linux"))]
pub(in crate::storage_driver) fn verify_inherited_member(_:&File,_:&File,_:&InventoryMemberObservation)->Result<(),String>{Err("owned mounted inventory requires Linux".into())}

#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
pub(in crate::storage_driver) enum InventoryMountOrigin {Provisional,InstalledSameGroup}
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::storage_driver) struct InventoryFdObservation {
    pub(in crate::storage_driver) number:i32,pub(in crate::storage_driver) device:u64,
    pub(in crate::storage_driver) inode:u64,pub(in crate::storage_driver) rdev:u64,
    pub(in crate::storage_driver) mode:u32,pub(in crate::storage_driver) mount_id:Option<u64>,
}
impl InventoryFdObservation {
    fn of(file:&File)->Result<Self,String>{
        let m=file.metadata().map_err(|_|"actual inventory original FD metadata unavailable")?;
        #[cfg(target_os="linux")]
        let mount_id=if m.is_dir(){Some(observe_parent_kernel(file)?.mount_id)}else{None};
        #[cfg(not(target_os="linux"))]
        let mount_id=None;
        Ok(Self{number:file.as_raw_fd(),device:m.dev(),inode:m.ino(),rdev:m.rdev(),mode:m.mode(),mount_id})
    }
    pub(in crate::storage_driver) fn matches(&self,number:i32,m:&std::fs::Metadata)->bool{
        number==self.number&&(m.dev(),m.ino(),m.rdev(),m.mode())==(self.device,self.inode,self.rdev,self.mode)
    }
}
fn observe_original_inventory_fd(origin:&VerifiedAttachDrain,file:&File)->Result<InventoryFdObservation,String>{
    origin.require_original_watch_files()?;let value=InventoryFdObservation::of(file)?;
    origin.require_original_watch_files()?;Ok(value)
}
/// Closed diagnostic/capsule DATA only. No deserialized record can construct
/// an owned context, member FD, actual book root or physical mount lifetime.
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::storage_driver) struct InventoryMemberObservation {
    pub(in crate::storage_driver) kind:InventoryMountOrigin,
    pub(in crate::storage_driver) fact:VirginReplicaRef,
    pub(in crate::storage_driver) mounted:MountObservation,
    pub(in crate::storage_driver) source_scope_sha256:String,
    pub(in crate::storage_driver) origin_native:crate::storage_driver::live_authority::JobIdentity,
    pub(in crate::storage_driver) origin_completion_sha256:String,
    pub(in crate::storage_driver) original_mounted:InventoryFdObservation,
    pub(in crate::storage_driver) original_block:InventoryFdObservation,
}
/// Negative empty slot has no authority. The actual same-book builder roots
/// this before asking a genuine WatchMountProbe to fill it. Every FD is put
/// behind a strong Arc immediately; mutex guards do not span kernel IO.
pub(in crate::storage_driver) struct InventoryMemberSlot {
    failed:AtomicBool,
    observation:Mutex<Option<InventoryMemberObservation>>,
    mounted:Mutex<Option<Arc<File>>>,block:Mutex<Option<Arc<File>>>,
}
impl InventoryMemberSlot {
    pub(in crate::storage_driver) fn empty()->Self{Self{failed:AtomicBool::new(false),observation:Mutex::new(None),mounted:Mutex::new(None),block:Mutex::new(None)}}
    pub(in crate::storage_driver) fn files(&self)->Result<(Arc<File>,Arc<File>,InventoryMemberObservation),String>{
        if self.failed.load(Ordering::Acquire){return Err("actual inventory member slot UNKNOWN".into());}
        let m=self.mounted.lock().map_err(|_|"actual inventory member mount root poisoned")?.clone().ok_or("actual inherited member mount absent")?;
        let b=self.block.lock().map_err(|_|"actual inventory member block root poisoned")?.clone().ok_or("actual inherited member block absent")?;
        let o=self.observation.lock().map_err(|_|"actual inventory member observation poisoned")?.clone().ok_or("actual inventory member observation incomplete")?;
        Ok((m,b,o))
    }
    /// Only the containing actual context can call this after its SAME opaque
    /// native drain. Never an error/Drop/timeout rollback or original-FD close.
    pub(in crate::storage_driver) fn retire_duplicates(&self)->Result<(),String>{
        if self.failed.load(Ordering::Acquire){return Err("UNKNOWN member duplicates remain rooted".into());}
        let mut mounted=self.mounted.lock().map_err(|_|"actual duplicate mount root poisoned")?;
        let mut block=self.block.lock().map_err(|_|"actual duplicate block root poisoned")?;
        mounted.take();block.take();Ok(())
    }
}

pub(super) struct ProvisionalMountedInventory {
    origin:Arc<VerifiedAttachDrain>,
    namespace:Option<File>,block:Option<File>,mounted:Option<File>,
    observation:Option<MountObservation>,
    unknown:bool,
}
impl WatchMountProbe {
    /// Compare the exact original incarnation without opening/replacing any
    /// member FD. An unmounted member is valid only when its actual probe is
    /// genuinely clean, not partial/UNKNOWN or terminal-draining.
    pub(in crate::storage_driver) fn compare_owned_inventory_member(&self,
        current:&crate::storage_driver::native_runtime::mount::parent::VerifiedAttachParent,
        scope:&ExpectedAttachScope,expected:Option<&InventoryMemberObservation>)->Result<(),String>{
        current.require_live()?;
        if self.terminal.is_some(){return Err("inventory member entered terminal drain".into());}
        let actual=if let Some(value)=self.installed.as_ref(){
            let origin=value.provisional_origin.as_ref().ok_or("installed member lacks original v7 lineage")?;
            Some((InventoryMountOrigin::InstalledSameGroup,origin,&value.namespace,
                value.mounted.as_ref().ok_or("installed mounted reference absent")?,
                value.block.as_ref().ok_or("installed block reference absent")?,&value.observation))
        }else if let Some(value)=self.provisional.as_ref(){
            if value.unknown{return Err("provisional member UNKNOWN".into());}
            Some((InventoryMountOrigin::Provisional,&value.origin,value.namespace.as_ref().ok_or("partial original namespace")?,
                value.mounted.as_ref().ok_or("partial original mounted reference")?,value.block.as_ref().ok_or("partial original block reference")?,
                value.observation.as_ref().ok_or("partial original mount observation")?))
        }else{None};
        match(actual,expected){
            (None,None) if self.namespace.is_none()&&self.block.is_none()&&self.mounted.is_none()&&self.daemon.is_none()=>Ok(()),
            (Some((kind,origin,namespace,mounted,block,observation)),Some(expected))=>{
                origin.require_completed_inventory_origin()?;
                if expected.kind!=kind||&expected.mounted!=observation
                    ||expected.source_scope_sha256!=crate::storage_lifecycle::pod_attachment::scope_digest(scope)?
                    ||expected.origin_native!=*origin.native_identity()||expected.origin_completion_sha256!=origin.completion_sha256()
                    ||expected.fact!=*scope.generation.virgin_replicas.iter().find(|f|f.node_uid==scope.phase_node_uid).ok_or("actual member replica absent")?
                    ||fd_identity(namespace)?!=(observation.namespace_device,observation.namespace_inode)
                    ||observe_original_inventory_fd(origin,mounted)?!=expected.original_mounted
                    ||observe_original_inventory_fd(origin,block)?!=expected.original_block{
                    return Err("same-book original member scope/FD incarnation changed".into());}
                current.require_live()
            },
            _=>Err("inventory mounted membership changed or member is partial; no recapture".into()),
        }
    }
    #[cfg(not(target_os="linux"))]
    pub(in crate::storage_driver) fn capture_owned_inventory_member(&self,
        _current:&crate::storage_driver::native_runtime::mount::parent::VerifiedAttachParent,
        _scope:&ExpectedAttachScope,_slot:&InventoryMemberSlot)->Result<bool,String>{Err("actual owned inventory needs Linux".into())}
    /// No mount is a legitimate category for genuine same-group members not
    /// yet mounted (or a local Secondary). Partial/UNKNOWN is NEVER absence.
    #[cfg(target_os="linux")]
    pub(in crate::storage_driver) fn capture_owned_inventory_member(&self,
        current:&crate::storage_driver::native_runtime::mount::parent::VerifiedAttachParent,
        scope:&ExpectedAttachScope,slot:&InventoryMemberSlot)->Result<bool,String>{
        let result=(||{
            current.require_live()?;
            if self.terminal.is_some(){return Err("draining original member cannot enter owned inventory".into());}
            let(kind,origin,namespace,mounted,block,observed)=if let Some(installed)=self.installed.as_ref(){
                installed.require_original_watch_files()?;
                let origin=installed.provisional_origin.as_ref().ok_or("installed member lacks genuine v7 provisional lineage")?;
                (InventoryMountOrigin::InstalledSameGroup,origin,&installed.namespace,
                    installed.mounted.as_ref().ok_or("installed original mount File missing")?,
                    installed.block.as_ref().ok_or("installed original block File missing")?,&installed.observation)
            }else if let Some(provisional)=self.provisional.as_ref(){
                if provisional.unknown||provisional.observation.is_none(){return Err("partial provisional member UNKNOWN".into());}
                (InventoryMountOrigin::Provisional,&provisional.origin,provisional.namespace.as_ref().ok_or("actual provisional namespace absent")?,
                    provisional.mounted.as_ref().ok_or("actual provisional mount absent")?,provisional.block.as_ref().ok_or("actual provisional block absent")?,
                    provisional.observation.as_ref().unwrap())
            }else{
                if self.namespace.is_some()||self.block.is_some()||self.mounted.is_some()||self.daemon.is_some(){
                    return Err("partial uninstalled member is UNKNOWN, not not-yet-mounted".into());}
                return Ok(false);
            };
            origin.require_completed_inventory_origin()?;
            if scope.owner!=origin.scope().owner||scope.mount_ref!=origin.scope().mount_ref||scope.generation!=origin.scope().generation
                ||scope.round_uid!=current.scope().round_uid||scope.phase_boot!=current.scope().phase_boot{
                return Err("actual inventory member original source/round differs".into());}
            let fact=scope.generation.virgin_replicas.iter().find(|f|f.node_uid==scope.phase_node_uid).ok_or("actual inventory replica absent")?.clone();
            let original_mounted=observe_original_inventory_fd(origin,mounted)?;let original_block=observe_original_inventory_fd(origin,block)?;
            if fd_identity(namespace)?!=(observed.namespace_device,observed.namespace_inode){return Err("actual inventory original namespace FD changed".into());}
            if slot.mounted.lock().map_err(|_|"actual inventory role poisoned")?.is_some()
                ||slot.block.lock().map_err(|_|"actual inventory role poisoned")?.is_some(){return Err("actual inventory member role already attempted; no replacement".into());}
            terminal::origin::require_descriptor_headroom(2)?;
            let duplicate=Arc::new(mounted.try_clone().map_err(|_|"actual original mount duplicate unavailable")?);
            *slot.mounted.lock().unwrap_or_else(|p|p.into_inner())=Some(duplicate.clone());
            let duplicate=Arc::new(block.try_clone().map_err(|_|"actual original block duplicate unavailable")?);
            *slot.block.lock().unwrap_or_else(|p|p.into_inner())=Some(duplicate.clone());
            origin.require_original_watch_files()?;
            if observe_original_inventory_fd(origin,mounted)?!=original_mounted||observe_original_inventory_fd(origin,block)?!=original_block{
                return Err("actual original member FD table/incarnation changed during duplication".into());}
            let observation=InventoryMemberObservation{kind,fact,mounted:observed.clone(),source_scope_sha256:crate::storage_lifecycle::pod_attachment::scope_digest(scope)?,
                origin_native:origin.native_identity().clone(),origin_completion_sha256:origin.completion_sha256().into(),original_mounted,original_block};
            *slot.observation.lock().unwrap_or_else(|p|p.into_inner())=Some(observation);current.require_live()?;Ok(true)
        })();if result.is_err(){slot.failed.store(true,Ordering::Release);}result
    }
    /// SAME fixed dispatcher, with fresh current boundary immediately before
    /// and after this lexical probe scope. All acquired FDs and original drain
    /// are rooted before later fallible checks; partial errors never recapture.
    pub(in crate::storage_driver) fn capture_inventory_after_filesystem_mount(&mut self,
        drain:Arc<VerifiedAttachDrain>)->Result<(),String>{
        drain.require_owned_inventory_drain()?;
        if self.provisional.is_some()||self.installed.is_some(){return Err("provisional/installed mount already attempted; no adoption/retry".into());}
        self.provisional=Some(ProvisionalMountedInventory{origin:drain.clone(),namespace:None,block:None,
            mounted:None,observation:None,unknown:false});
        let result=(||{
            #[cfg(not(target_os="linux"))]
            {return Err("actual provisional mount ownership requires Linux".into());}
            #[cfg(target_os="linux")]
            {
                use std::os::fd::AsRawFd;
                use std::os::unix::fs::{FileTypeExt,FileExt};
                drain.require_current_origin_without_io_grant()?;
                let scope=drain.scope();
                if scope.phase!=AttachPhase::Mount||drain.step()!=AttachNativeStep::FilesystemMount
                    ||scope.mount_ref.epoch()!=1||scope.mount_ref.node_boot()!=&crate::storage_boot::BootId::current()?{
                    return Err("only genuine first-epoch current FilesystemMount drain can capture provisional ownership".into());}
                terminal::origin::require_descriptor_headroom(3)?;
                let held=self.provisional.as_mut().unwrap();
                held.namespace=Some(open_current_namespace()?);
                let namespace=fd_identity(held.namespace.as_ref().unwrap())?;
                let(major,minor,bytes)=drain.block_identity();
                held.block=Some(open_exact_block(&format!("/dev/drbd{minor}"))?);
                let block=held.block.as_ref().unwrap();
                let metadata=block.metadata().map_err(|_|"provisional actual block FD metadata")?;
                let mut size=0u64;
                if !metadata.file_type().is_block_device()||metadata.rdev()!=libc::makedev(major,minor)
                    ||unsafe{libc::ioctl(block.as_raw_fd(),0x80081272u32 as _,&mut size)}!=0
                    ||size!=bytes||bytes!=scope.generation.virgin_replicas[0].exposed_bytes{
                    return Err("provisional initialized block incarnation/geometry changed".into());}
                drain.require_current_origin_without_io_grant()?;
                let mut raw=[0u8;120];
                block.read_exact_at(&mut raw,1024).map_err(|_|"provisional actual ext4 read UNKNOWN")?;
                if raw[56..58]!=[0x53,0xef]||format_uuid(&raw[104..120])?!=scope.generation.filesystem_uuid{
                    return Err("provisional actual filesystem UUID changed".into());}
                let target=mount_path(&scope.mount_ref);
                held.mounted=Some(open_private_target(&target)?);
                let observation=observe_mounted(held.mounted.as_ref().unwrap(),&target,namespace,major,minor,&scope.generation.filesystem_uuid)?;
                if drain.observation()?.mounted.as_ref()!=Some(&observation){return Err("provisional reopened actual mount differs from original supervised drain".into());}
                self.parent.recheck_owned_mount_without_fresh_grant(self.mount_scope.as_ref().ok_or("original premount scope absent")?,
                    &drain,&observation)?;
                drain.require_current_origin_without_io_grant()?;
                self.provisional.as_mut().unwrap().observation=Some(observation);
                Ok(())
            }
        })();
        if result.is_err(){self.provisional.as_mut().unwrap().unknown=true;}
        result
    }
    /// Final owner exists ONLY after the NEW actual ObserveMounted drain.
    /// Earlier FS drain/FDs are provenance, never a renewed authorization.
    pub(in crate::storage_driver) fn install_provisional_after_actual_drain(&mut self,
        drain:&VerifiedAttachDrain)->Result<(),String>{
        #[cfg(not(target_os="linux"))]
        {let _=drain;return Err("actual managed mount installation requires Linux".into());}
        #[cfg(target_os="linux")]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::{FileTypeExt,FileExt};
            if self.installed.is_some()||self.namespace.is_some()||self.block.is_some()||self.mounted.is_some()||self.daemon.is_some(){
                return Err("final independent mount observation already attempted; no recapture".into());}
            let prior=self.provisional.as_ref().ok_or("actual provisional root absent")?;
            if prior.unknown||prior.observation.is_none()||prior.namespace.is_none()||prior.block.is_none()||prior.mounted.is_none(){
                return Err("partial/UNKNOWN provisional owner cannot install READY".into());}
            prior.origin.require_completed_inventory_origin()?;
            prior.origin.require_same_inventory_owner(drain)?;
            drain.require_current_origin_without_io_grant()?;
            let scope=drain.scope();
            if scope.phase!=AttachPhase::ObserveMounted||drain.step()!=AttachNativeStep::Single{
                return Err("final inventory install requires actual current ObserveMounted drain".into());}
            terminal::origin::require_descriptor_headroom(3)?;
            // Fresh independent FD observations are rooted separately. Error
            // preserves BOTH original provisional and every acquired fresh FD.
            self.namespace=Some(open_current_namespace()?);
            let namespace=fd_identity(self.namespace.as_ref().unwrap())?;
            self.daemon=Some(crate::docker::inspect_managed_mount_daemon(drain.deadline())?);
            let daemon=self.daemon.as_ref().unwrap();daemon.validate_current(drain.deadline())?;
            if daemon.identity()!=namespace{return Err("actual daemon/Watch namespace changed".into());}
            let(major,minor,bytes)=drain.block_identity();
            self.block=Some(open_exact_block(&format!("/dev/drbd{minor}"))?);
            let block=self.block.as_ref().unwrap();let m=block.metadata().map_err(|_|"actual final independent block metadata")?;
            let mut size=0u64;
            if !m.file_type().is_block_device()||m.rdev()!=libc::makedev(major,minor)
                ||unsafe{libc::ioctl(block.as_raw_fd(),0x80081272u32 as _,&mut size)}!=0
                ||size!=bytes||bytes!=scope.generation.virgin_replicas[0].exposed_bytes{return Err("actual final block incarnation/size changed".into());}
            let mut raw=[0u8;120];block.read_exact_at(&mut raw,1024).map_err(|_|"actual final filesystem UUID read UNKNOWN")?;
            if raw[56..58]!=[0x53,0xef]||format_uuid(&raw[104..120])?!=scope.generation.filesystem_uuid{
                return Err("actual final ext4 UUID differs from original dataset".into());}
            let target=mount_path(&scope.mount_ref);self.mounted=Some(open_private_target(&target)?);
            let observation=observe_mounted(self.mounted.as_ref().unwrap(),&target,namespace,major,minor,&scope.generation.filesystem_uuid)?;
            let prior=self.provisional.as_ref().unwrap();
            if prior.observation.as_ref()!=Some(&observation)||drain.observation()?.mounted.as_ref()!=Some(&observation)
                ||fd_identity(prior.namespace.as_ref().unwrap())?!=namespace{
                return Err("original provisional/new actual mount/namespace observations disagree".into());}
            let original=prior.block.as_ref().unwrap().metadata().map_err(|_|"original provisional block metadata absent")?;
            if(original.dev(),original.ino(),original.rdev(),original.mode())!=(m.dev(),m.ino(),m.rdev(),m.mode()){
                return Err("original provisional block File replaced; no path adoption".into());}
            let held=observe_mounted(prior.mounted.as_ref().unwrap(),&target,namespace,major,minor,&scope.generation.filesystem_uuid)?;
            if held!=observation{return Err("held provisional mount File changed before final install".into());}
            self.parent.recheck_owned_mount_without_fresh_grant(self.mount_scope.as_ref().ok_or("original premount scope absent")?,drain,&observation)?;
            daemon.validate_current(drain.deadline())?;drain.require_current_origin_without_io_grant()?;
            self.anchor.record_mounted(drain,prior.mounted.as_ref().unwrap(),&observation)?;
            // No fallible work after taking original ownership. The final
            // object retains original FDs AND the actual opaque FS lineage.
            let prior=self.provisional.as_mut().unwrap();
            self.installed=Some(VerifiedManagedMount{namespace:prior.namespace.take().unwrap(),block:prior.block.take(),mounted:prior.mounted.take(),
                daemon:self.daemon.take().unwrap(),scope:scope.clone(),observation,evidence_uid:Uid::new(),
                evidence_sha256:drain.evidence_sha256().into(),watch_process:drain.original_watch_process(),provisional_origin:Some(prior.origin.clone())});
            drop(self.provisional.take());
            // Redundant known-validated observations only; UNKNOWN never
            // reaches these drops, and original owners are already installed.
            drop(self.namespace.take());drop(self.block.take());drop(self.mounted.take());Ok(())
        }
    }
}
