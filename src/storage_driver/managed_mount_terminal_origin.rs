//! Actual once-captured Watch process origin. A PID/header/FD number is not
//! authority. Kernel KCMP_FILES equivalence is mandatory, never assumed from
//! Rust threads, TGID, namespace or equal block-node fstat alone.
use super::*;
use std::os::fd::{AsRawFd,FromRawFd};
#[derive(Clone,Debug,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::storage_driver) struct WatchProcessObservation {
    pub(in crate::storage_driver) pid:u32,boot:BootId,start:u64,captured_tid:u32,
    pidfd_identity:(u64,u64,u32),proc_identity:(u64,u64,u32),namespace:(u64,u64),
}
impl WatchProcessObservation {
    /// Readonly identity DATA; never constructs either permission domain.
    pub(in crate::storage_driver) fn pid(&self)->u32{self.pid}
    pub(in crate::storage_driver) fn boot(&self)->&BootId{&self.boot}
    pub(in crate::storage_driver) fn namespace(&self)->(u64,u64){self.namespace}
}
pub(in crate::storage_driver) struct WatchProcessPin {
    attempted:bool,unknown:bool,pidfd:Option<File>,proc:Option<File>,observation:Option<WatchProcessObservation>,
    namespace:Option<std::sync::Arc<File>>,
}
impl WatchProcessPin {
    pub(in crate::storage_driver) fn empty()->Self{Self{attempted:false,unknown:false,pidfd:None,proc:None,observation:None,namespace:None}}
    pub(in crate::storage_driver) fn require_rooted(&self)->Result<(),String>{
        if !self.attempted||self.unknown||self.pidfd.is_none()||self.proc.is_none()||self.namespace.is_none()||self.observation.is_none(){
            return Err("original Watch process origin absent/partial/UNKNOWN; no adoption".into());}Ok(())
    }
    pub(in crate::storage_driver) fn capture_before_production(&mut self,boot:&BootId)->Result<(),String>{
        if self.attempted{let result=self.verify_serving_thread(boot);if result.is_err(){self.unknown=true;}return result;}
        self.attempted=true;
        let result=self.capture_inner(boot);if result.is_err(){self.unknown=true;}result
    }
    #[cfg(not(target_os="linux"))]
    fn capture_inner(&mut self,_:&BootId)->Result<(),String>{Err("actual Watch process origin requires Linux".into())}
    #[cfg(target_os="linux")]
    fn capture_inner(&mut self,boot:&BootId)->Result<(),String>{
        if unsafe{libc::geteuid()}!=0||BootId::current()?!=*boot{return Err("original Watch origin needs current Linux root boot".into());}
        let pid=std::process::id();let tid=actual_tid()?;require_same_files(pid,tid)?;
        require_fd_headroom(3)?; // actual origin pidfd+proc+SAME namespace
        let root=owned_fd(unsafe{libc::open(c"/proc".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
        anchor::require_fs(&root,0x9fa0)?;
        self.proc=Some(anchor::open_directory_at(&root,&pid.to_string())?);
        drop(root); // no extra root-directory descriptor through verification
        let raw=unsafe{libc::syscall(libc::SYS_pidfd_open,libc::pid_t::try_from(pid).map_err(|_|"Watch PID overflow")?,0)};
        if raw<0{return Err("actual original Watch pidfd unavailable; no fallback".into());}
        self.pidfd=Some(unsafe{File::from_raw_fd(i32::try_from(raw).map_err(|_|"Watch pidfd out of range")?)});
        let stamp=leader_stamp(self.proc.as_ref().unwrap(),pid)?;
        // Root SAME newly opened namespace BEFORE any fstat/fs/ioctl check.
        let namespace=owned_fd(unsafe{libc::openat(self.proc.as_ref().unwrap().as_raw_fd(),c"ns/mnt".as_ptr(),libc::O_RDONLY|libc::O_CLOEXEC)})?;
        self.namespace=Some(std::sync::Arc::new(namespace));
        let namespace=self.namespace.as_ref().unwrap();
        verify_namespace_file(namespace.as_ref(),fd_identity(namespace.as_ref())?)?;
        let observation=WatchProcessObservation{pid,boot:boot.clone(),start:stamp.start,captured_tid:tid,
            pidfd_identity:file_identity(self.pidfd.as_ref().unwrap())?,proc_identity:file_identity(self.proc.as_ref().unwrap())?,
            namespace:fd_identity(namespace.as_ref())?};
        verify_pair(self.pidfd.as_ref().unwrap(),self.proc.as_ref().unwrap(),&observation)?;
        self.observation=Some(observation);require_same_files(pid,actual_tid()?)?;
        self.verify_serving_thread(boot)
    }
    pub(in crate::storage_driver) fn verify_serving_thread(&self,boot:&BootId)->Result<(),String>{
        self.require_rooted()?;
        #[cfg(not(target_os="linux"))]
        {let _=boot;Err("actual Watch file-table equivalence requires Linux".into())}
        #[cfg(target_os="linux")]
        {
            let o=self.observation.as_ref().unwrap();
            if &o.boot!=boot||BootId::current()?!=o.boot||std::process::id()!=o.pid{
                return Err("original Watch process/boot changed".into());}
            require_same_files(o.pid,actual_tid()?)?;
            verify_namespace_file(self.namespace.as_ref().unwrap().as_ref(),o.namespace)?;
            verify_pair(self.pidfd.as_ref().unwrap(),self.proc.as_ref().unwrap(),o)?;
            if fd_identity(&open_current_namespace()?)?!=o.namespace{return Err("actual serving Watch namespace changed".into());}
            require_same_files(o.pid,actual_tid()?)
        }
    }
    pub(in crate::storage_driver) fn duplicate_for_child(&self,boot:&BootId)->Result<(File,File,WatchProcessObservation),String>{
        self.verify_serving_thread(boot)?;
        require_fd_headroom(2)?; // two ACTUAL preallocated child role duplicates
        let a=self.pidfd.as_ref().unwrap().try_clone().map_err(|_|"original Watch pidfd duplicate unavailable")?;
        let b=self.proc.as_ref().unwrap().try_clone().map_err(|_|"original Watch proc duplicate unavailable")?;
        if a.as_raw_fd()<3||b.as_raw_fd()<3||a.as_raw_fd()==b.as_raw_fd(){return Err("actual fixed inherited process roles cannot be admitted".into());}
        self.verify_serving_thread(boot)?;Ok((a,b,self.observation.as_ref().unwrap().clone()))
    }
    pub(in crate::storage_driver) fn observation(&self)->Result<&WatchProcessObservation,String>{self.require_rooted()?;Ok(self.observation.as_ref().unwrap())}
    /// Distinct v7 sink roots EACH acquired duplicate before next fallibility.
    /// No terminal-v6 inheritance capability is constructed or reused.
    pub(in crate::storage_driver) fn duplicate_for_owned_inventory(&self,boot:&BootId,mut root:impl FnMut(bool,File))->Result<(),String>{
        self.verify_serving_thread(boot)?;require_fd_headroom(2)?;
        let pidfd=self.pidfd.as_ref().unwrap().try_clone().map_err(|_|"actual v7 original pidfd duplicate unavailable")?;
        root(false,pidfd);
        let proc=self.proc.as_ref().unwrap().try_clone().map_err(|_|"actual v7 original proc duplicate unavailable")?;
        root(true,proc);self.verify_serving_thread(boot)
    }
    pub(in crate::storage_driver) fn retained_namespace(&self,boot:&BootId)->Result<std::sync::Arc<File>,String>{
        self.verify_serving_thread(boot)?;Ok(self.namespace.as_ref().unwrap().clone())
    }
}
#[cfg(target_os="linux")]
fn verify_namespace_file(file:&File,expected:(u64,u64))->Result<(),String>{
    anchor::require_fs(file,0x6e736673)?;
    if unsafe{libc::ioctl(file.as_raw_fd(),0xb703)}!=libc::CLONE_NEWNS||fd_identity(file)?!=expected{
        return Err("SAME original held Watch namespace FD/type changed".into());}Ok(())
}
fn checked_fd_headroom(observed:u64,required:u64,soft:u64)->Result<(),String>{
    if observed.checked_add(required).is_none_or(|n|n>soft){return Err("known original descriptor headroom insufficient; no limit change".into());}Ok(())
}
/// Readonly negative headroom observation for the same private producer.
/// No limit mutation, descriptor adoption or effect permission is created.
pub(in crate::storage_driver) fn require_descriptor_headroom(required:u64)->Result<(),String>{require_fd_headroom(required)}
#[cfg(target_os="linux")]
fn require_fd_headroom(required:u64)->Result<(),String>{
    let mut before:libc::rlimit=unsafe{std::mem::zeroed()};let mut after:libc::rlimit=unsafe{std::mem::zeroed()};
    if unsafe{libc::getrlimit(libc::RLIMIT_NOFILE,&mut before)}!=0{return Err("actual descriptor limit unavailable".into());}
    let table=File::open("/proc/self/fd").map_err(|_|"actual own descriptor table unavailable")?;
    anchor::require_fs(&table,0x9fa0)?;
    // Includes the two temporary observer/iterator descriptors, deliberately
    // conservative. Independent anchored iteration, real EOF/errno, nozero.
    let observed=anchor::walk_fd_names(&table,65536,|_|Ok(()))?;
    if unsafe{libc::getrlimit(libc::RLIMIT_NOFILE,&mut after)}!=0||before.rlim_cur!=after.rlim_cur||before.rlim_max!=after.rlim_max{
        return Err("descriptor limit changed during original bounded observation".into());}
    checked_fd_headroom(u64::try_from(observed).map_err(|_|"descriptor count overflow")?,required,
        u64::try_from(before.rlim_cur).map_err(|_|"descriptor soft limit does not fit bounded accounting")?)
}
#[cfg(not(target_os="linux"))]
fn require_fd_headroom(_:u64)->Result<(),String>{Err("actual descriptor headroom observation requires Linux".into())}
fn file_identity(file:&File)->Result<(u64,u64,u32),String>{let m=file.metadata().map_err(|_|"original Watch process descriptor metadata unavailable")?;Ok((m.dev(),m.ino(),m.mode()))}
fn kcmp_result(raw:libc::c_long,errno:Option<i32>)->Result<(),String>{
    if raw==0{return Ok(());}Err(format!("actual KCMP_FILES not proven equal (return {raw}, errno {errno:?}); UNKNOWN"))
}
#[cfg(target_os="linux")]
fn actual_tid()->Result<u32,String>{
    let raw=unsafe{libc::syscall(libc::SYS_gettid)};
    u32::try_from(raw).ok().filter(|n|*n>0).ok_or_else(||"actual serving kernel TID unavailable".into())
}
#[cfg(target_os="linux")]
pub(in crate::storage_driver) fn require_same_files(leader:u32,tid:u32)->Result<(),String>{
    let a=libc::pid_t::try_from(leader).map_err(|_|"pinned Watch leader PID overflow")?;
    let b=libc::pid_t::try_from(tid).map_err(|_|"observed task TID overflow")?;
    if a<=0||b<=0{return Err("invalid actual file-table comparison identity".into());}
    // Linux6.8 UAPI KCMP_FILES=2; use libc's architecture-specific SYS_kcmp.
    let raw=unsafe{libc::syscall(libc::SYS_kcmp,a,b,2i32,0usize,0usize)};
    let errno=if raw<0{std::io::Error::last_os_error().raw_os_error()}else{None};kcmp_result(raw,errno)
}
#[cfg(not(target_os="linux"))]
pub(in crate::storage_driver) fn require_same_files(_:u32,_:u32)->Result<(),String>{Err("actual kernel files-table comparison requires Linux".into())}
#[cfg(target_os="linux")]
fn leader_stamp(proc:&File,pid:u32)->Result<anchor::TerminalTaskStamp,String>{
    anchor::require_fs(proc,0x9fa0)?;
    let stamp=anchor::terminal_task_stamp(&anchor::read_at(proc,"stat",8192)?,&anchor::read_at(proc,"status",65536)?,pid,pid)?;
    if stamp.kthread||stamp.uid!=[0,0,0,0]{return Err("original Watch leader is not same root user task".into());}Ok(stamp)
}
#[cfg(target_os="linux")]
fn pidfd_live(pidfd:&File,pid:u32)->Result<(),String>{
    let info=File::open("/proc/self/fdinfo").map_err(|_|"actual pidfd info root unavailable")?;
    anchor::require_fs(&info,0x9fa0)?;
    let raw=anchor::read_at(&info,&pidfd.as_raw_fd().to_string(),8192)?;
    let text=std::str::from_utf8(&raw).map_err(|_|"actual pidfd info encoding")?;
    let values=text.lines().filter_map(|l|l.strip_prefix("Pid:")).collect::<Vec<_>>();
    if values.len()!=1||values[0].trim().parse::<u32>().ok()!=Some(pid){return Err("inherited descriptor is not same actual live Watch pidfd".into());}
    let mut poll=libc::pollfd{fd:pidfd.as_raw_fd(),events:libc::POLLIN,revents:0};
    if unsafe{libc::poll(&mut poll,1,0)}!=0||poll.revents!=0{return Err("pinned original Watch exited/unknown".into());}Ok(())
}
#[cfg(target_os="linux")]
fn verify_pair(pidfd:&File,proc:&File,o:&WatchProcessObservation)->Result<(),String>{
    if BootId::current()?!=o.boot||file_identity(pidfd)?!=o.pidfd_identity||file_identity(proc)?!=o.proc_identity{
        return Err("original Watch pidfd/proc/boot incarnation changed".into());}
    pidfd_live(pidfd,o.pid)?;
    let a=leader_stamp(proc,o.pid)?;
    let namespace=anchor::open_namespace_at(proc)?;
    if a.start!=o.start||fd_identity(&namespace)?!=o.namespace||leader_stamp(proc,o.pid)?!=a{
        return Err("held original Watch process/namespace changed".into());}pidfd_live(pidfd,o.pid)
}
pub(in crate::storage_driver) fn verify_retained_pair(pidfd:&File,proc:&File,o:&WatchProcessObservation)->Result<(),String>{
    #[cfg(not(target_os="linux"))]{let _=(pidfd,proc,o);Err("actual process references require Linux".into())}
    #[cfg(target_os="linux")]{verify_pair(pidfd,proc,o)}
}
/// Readonly inherited original process observation, never Deserialize/raw ctor.
pub(in crate::storage_driver) struct InheritedWatchProcess {pidfd:File,proc:File,observation:WatchProcessObservation}
impl InheritedWatchProcess {
    pub(in crate::storage_driver) fn from_verified(value:crate::storage_driver::dispatcher::attachment::terminal::VerifiedWatchProcessInheritance)->Result<Self,String>{
        let(pidfd,proc,observation)=value.into_parts();let result=Self{pidfd,proc,observation};result.require_live()?;Ok(result)
    }
    pub(in crate::storage_driver) fn require_live(&self)->Result<(),String>{
        #[cfg(not(target_os="linux"))]{Err("inherited actual Watch process requires Linux".into())}
        #[cfg(target_os="linux")]{verify_pair(&self.pidfd,&self.proc,&self.observation)}
    }
    pub(in crate::storage_driver) fn pid(&self)->u32{self.observation.pid}
    pub(in crate::storage_driver) fn verify_observed_table(&self,tgid:u32,tid:u32)->Result<(),String>{
        self.require_live()?;if tgid!=self.observation.pid{return Err("storage reference is not original pinned Watch process".into());}
        require_same_files(self.observation.pid,tid)?;self.require_live()
    }
}
/// Validate borrowed raw child roles BEFORE taking them as File, so a bad
/// role never closes an unrelated inherited descriptor on this error path.
#[cfg(target_os="linux")]
pub(in crate::storage_driver) fn verify_borrowed_pair(pidfd:i32,proc:i32,o:&WatchProcessObservation,parent_pid:u32)->Result<(),String>{
    if o.pid!=parent_pid||pidfd<3||proc<3||pidfd==proc{return Err("Watch inherited roles/actual launching peer changed".into());}
    // Non-owning borrowed roles are converted only to TEMP duplicates for
    // bounded observation. Originals are never consumed until both validate.
    let a=unsafe{libc::fcntl(pidfd,libc::F_DUPFD_CLOEXEC,3)};
    if a<0{return Err("actual inherited Watch pidfd unavailable".into());}
    let a=unsafe{File::from_raw_fd(a)};
    let b=unsafe{libc::fcntl(proc,libc::F_DUPFD_CLOEXEC,3)};
    if b<0{return Err("actual inherited Watch proc unavailable".into());}
    let b=unsafe{File::from_raw_fd(b)};verify_pair(&a,&b,o)
}
#[cfg(not(target_os="linux"))]
pub(in crate::storage_driver) fn verify_borrowed_pair(_:i32,_:i32,_:&WatchProcessObservation,_:u32)->Result<(),String>{Err("original Watch process roles require Linux".into())}

#[cfg(test)]mod tests{
    use super::*;
    #[test]fn kcmp_requires_kernel_zero_never_equal_fstat_pid_or_rust_thread_assumption(){
        kcmp_result(0,None).unwrap();
        for raw in [1,2,3,i64::MAX as libc::c_long]{assert!(kcmp_result(raw,None).is_err());}
        for errno in [libc::EPERM,libc::ESRCH,libc::EINVAL,libc::ENOSYS]{assert!(kcmp_result(-1,Some(errno)).is_err());}
        assert!(kcmp_result(-1,None).is_err());
    }
    #[test]fn actual_descriptor_headroom_data_charges_three_origin_and_two_reserved_roles_without_raising_limits(){
        checked_fd_headroom(100,3,103).unwrap();assert!(checked_fd_headroom(100,3,102).is_err());
        checked_fd_headroom(103,2,105).unwrap();assert!(checked_fd_headroom(103,2,104).is_err());
        assert!(checked_fd_headroom(u64::MAX,1,u64::MAX).is_err());
        // 3 origin +2 reserved roles. Later namespace Arc sharing addsZERO FD,
        // not a claim that all remaining owner descriptors total only5.
        assert_eq!(3+2+0,5);
    }
    #[test]fn owned_regular_file_arc_sharing_retains_one_actual_descriptor_without_namespace_authority(){
        use std::sync::Arc;
        let path=std::env::temp_dir().join(format!("royak-origin-arc-{}",Uid::new().as_str()));
        let file=std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path).unwrap();
        let original=Arc::new(file);let number=original.as_raw_fd();let identity=file_identity(original.as_ref()).unwrap();
        let shared=original.clone();assert!(Arc::ptr_eq(&original,&shared));assert_eq!(shared.as_raw_fd(),number);
        drop(original);assert_eq!(file_identity(shared.as_ref()).unwrap(),identity);
        drop(shared);std::fs::remove_file(path).unwrap();
        // Genuine owned ordinary FD/Arc lifetime only, never a namespace or
        // WatchProcessPin/parent/census capability constructor.
    }
    #[cfg(target_os="linux")]
    #[test]fn actual_regular_file_tuple_never_substitutes_for_held_namespace_kernel_type(){
        let path=std::env::temp_dir().join(format!("royak-wrong-namespace-{}",Uid::new().as_str()));
        let file=std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path).unwrap();
        let m=file.metadata().unwrap();assert!(verify_namespace_file(&file,(m.dev(),m.ino())).is_err());
        drop(file);std::fs::remove_file(path).unwrap();
    }
    #[cfg(target_os="linux")]
    #[test]fn actual_regular_fdinfo_with_matching_fstat_does_not_become_watch_pidfd_or_proc_proof(){
        let path=std::env::temp_dir().join(format!("royak-wrong-origin-{}",Uid::new().as_str()));
        let file=std::fs::OpenOptions::new().read(true).write(true).create_new(true).open(&path).unwrap();
        let identity=file_identity(&file).unwrap();
        let observation=WatchProcessObservation{pid:std::process::id(),boot:BootId::current().unwrap(),start:0,captured_tid:1,
            pidfd_identity:identity,proc_identity:identity,namespace:(1,2)};
        assert!(verify_pair(&file,&file,&observation).is_err());
        drop(file);std::fs::remove_file(path).unwrap();
        // A deliberately forged DATA header is rejected; no opaque process
        // origin/census/parent is created from it.
    }
}
