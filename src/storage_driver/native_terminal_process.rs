//! Actual original Start process pin. Persisted/received process DATA never
//! reconstructs this owner. Rooted before later fallible checks on fixed IO.
use super::*;
use std::fs::File;
use std::os::fd::{AsRawFd,FromRawFd};
use std::os::unix::fs::{MetadataExt,OpenOptionsExt};

#[derive(Clone,Debug,serde::Serialize,PartialEq,Eq)]
pub(super) struct ProcessIdentity {
    pub(super) cid:String,pub(super) boot:BootId,pub(super) pid:u32,pub(super) start:u64,
    pub(super) started_at:String,pub(super) cgroup:String,
    pub(super) cgroup_device:u64,pub(super) cgroup_inode:u64,
    pub(super) cgroup_controls:[(u64,u64);3],
    pub(super) namespace_device:u64,pub(super) namespace_inode:u64,
}
/// Starts empty INSIDE the actual rooted container, before any proc open. A
/// partial failed capture remains in the same object, not in an Err temporary.
pub(in crate::storage_driver::native_runtime::mount::consumer) struct OriginalProcessPin {
    attempted:bool,complete:bool,unknown:bool,
    pidfd:Option<File>,proc:Option<File>,cgroup:Option<File>,namespace:Option<File>,
    controls:[Option<File>;3],
    identity:Option<ProcessIdentity>,namespace_close:Option<terminal::ClosedDescriptor>,
}
impl OriginalProcessPin {
    pub(in crate::storage_driver::native_runtime::mount::consumer) fn empty_before_start()->Self {Self {attempted:false,complete:false,unknown:false,
        pidfd:None,proc:None,cgroup:None,namespace:None,controls:[None,None,None],identity:None,namespace_close:None}}
    pub(super) fn capture(&mut self,actual:&crate::docker::managed::ActualProcessCandidate,
        deadline:Instant)->Result<ProcessIdentity,String>{
        if self.attempted {return Err("original process pin already attempted; never adopt/retry".into());}
        self.attempted=true;
        let result=self.capture_inner(actual,deadline);
        if result.is_err(){self.unknown=true;}result
    }
    #[cfg(not(target_os="linux"))]
    fn capture_inner(&mut self,_:&crate::docker::managed::ActualProcessCandidate,_:Instant)->Result<ProcessIdentity,String>{
        Err("actual original container PIDFD capture requires Linux".into())
    }
    #[cfg(target_os="linux")]
    fn capture_inner(&mut self,actual:&crate::docker::managed::ActualProcessCandidate,
        deadline:Instant)->Result<ProcessIdentity,String>{
        if unsafe{libc::geteuid()}!=0 || Instant::now()>=deadline || actual.pid()<=1 || !actual.running(){
            return Err("actual original Start is exited/ambiguous or capture deadline expired".into());
        }
        self.proc=Some(directory(&format!("/proc/{}",actual.pid()))?);
        filesystem(self.proc.as_ref().unwrap(),0x9fa0)?;
        let stat=read_at(self.proc.as_ref().unwrap(),"stat",8192)?;
        let start=parse_start(&stat,actual.pid())?;
        let raw=unsafe{libc::syscall(libc::SYS_pidfd_open,actual.pid(),0)};
        if raw<0{return Err("cannot pin actual original Start PIDFD; no terminal adoption".into());}
        self.pidfd=Some(unsafe{File::from_raw_fd(i32::try_from(raw).map_err(|_|"PIDFD out of range")?)});
        if pidfd_exited(self.pidfd.as_ref().unwrap())?{return Err("original task exited before pin; UNKNOWN".into());}
        let cgroup=parse_cgroup(&read_at(self.proc.as_ref().unwrap(),"cgroup",65536)?,actual.cid())?;
        let path=format!("/sys/fs/cgroup{cgroup}");
        if std::fs::canonicalize(&path).map_err(|_|"actual original cgroup absent")?!=std::path::Path::new(&path){
            return Err("actual original cgroup path is aliased".into());
        }
        self.cgroup=Some(directory(&path)?);filesystem(self.cgroup.as_ref().unwrap(),0x63677270)?;
        // These ORIGINAL descriptors must exist before Running is published.
        // Root each File before any later fallible identity/namespace check.
        for (index,name) in CONTROL_NAMES.iter().enumerate(){
            self.controls[index]=Some(open_at(self.cgroup.as_ref().unwrap(),name)?);
        }
        let mut control_identities=[(0,0);3];
        for (index,file) in self.controls.iter().enumerate(){
            control_identities[index]=control_identity(file.as_ref().ok_or("original control FD missing")?)?;
        }
        let ns_path=format!("/proc/self/fd/{}/ns/mnt",self.proc.as_ref().unwrap().as_raw_fd());
        self.namespace=Some(File::open(ns_path).map_err(|_|"cannot pin original task mount namespace")?);
        filesystem(self.namespace.as_ref().unwrap(),0x6e736673)?;
        if unsafe{libc::ioctl(self.namespace.as_ref().unwrap().as_raw_fd(),0xb703)}!=libc::CLONE_NEWNS {
            return Err("original process namespace is not mnt".into());
        }
        let cg=self.cgroup.as_ref().unwrap().metadata().map_err(|_|"original cgroup FD stat")?;
        let ns=self.namespace.as_ref().unwrap().metadata().map_err(|_|"original namespace FD stat")?;
        let identity=ProcessIdentity {cid:actual.cid().into(),boot:BootId::current()?,pid:actual.pid(),start,
            started_at:actual.started_at().into(),cgroup,cgroup_device:cg.dev(),cgroup_inode:cg.ino(),
            cgroup_controls:control_identities,
            namespace_device:ns.dev(),namespace_inode:ns.ino()};
        self.identity=Some(identity.clone());
        if parse_start(&read_at(self.proc.as_ref().unwrap(),"stat",8192)?,actual.pid())?!=start
            || parse_cgroup(&read_at(self.proc.as_ref().unwrap(),"cgroup",65536)?,actual.cid())?!=identity.cgroup
            || named_cgroup(&identity.cgroup)?!=NamedCgroup::Same((identity.cgroup_device,identity.cgroup_inode))
            || pidfd_exited(self.pidfd.as_ref().unwrap())? || Instant::now()>=deadline {
            return Err("original task incarnation changed/exited during capture".into());
        }
        self.complete=true;Ok(identity)
    }
    pub(super) fn require_candidate(&self,candidate:&crate::docker::managed::ActualProcessCandidate,
        deadline:Instant)->Result<(),String>{
        let identity=self.identity()?;
        if Instant::now()>=deadline || candidate.cid()!=identity.cid || candidate.pid()!=identity.pid
            || candidate.started_at()!=identity.started_at || !candidate.running() || candidate.paused() || candidate.restarting(){
            return Err("fresh actual Docker task differs from original pinned Start".into());
        }
        if pidfd_exited(self.pidfd.as_ref().ok_or("original PIDFD absent")?)?
            || parse_start(&read_at(self.proc.as_ref().ok_or("original proc FD absent")?,"stat",8192)?,identity.pid)?!=identity.start{
            return Err("actual original task exited/changed before signal".into());
        }Ok(())
    }
    pub(super) fn identity(&self)->Result<&ProcessIdentity,String>{
        if !self.complete||self.unknown {return Err("actual process pin incomplete/UNKNOWN; no reconstruction".into());}
        self.identity.as_ref().ok_or("actual original process identity absent".into())
    }
    pub(super) fn observed_exited_empty(&self,deadline:Instant)->Result<bool,String>{
        Ok(self.observe_original_drain(deadline)?.is_some())
    }
    pub(super) fn namespace_resource_sha256(&self)->Result<String,String>{
        self.identity()?;
        if self.namespace_close.is_some(){return Err("original process namespace already consumed; no new close".into());}
        terminal::FileIdentity::actual(self.namespace.as_ref().ok_or("original process namespace FD absent")?)?.digest()
    }
    pub(super) fn require_namespace_closed(&self)->Result<(),String>{
        self.identity()?;
        if self.namespace.is_some(){return Err("original process namespace reference remains owned; not closed".into());}
        self.namespace_close.as_ref().ok_or("original namespace missing without actual close tombstone")?.require_closed()
    }
    /// DATA tagged by the actual original-FD observation. Neither variant is
    /// a standalone drain capability or a replacement for terminal authority.
    pub(super) fn observe_original_drain(&self,deadline:Instant)->Result<Option<OriginalCgroupDrain>,String>{
        let identity=self.identity()?;
        if Instant::now()>=deadline || BootId::current()?!=identity.boot{return Err("original process drain boot/deadline changed".into());}
        let cg=self.cgroup.as_ref().ok_or("original process cgroup FD absent")?;
        filesystem(cg,0x63677270)?;
        let meta=cg.metadata().map_err(|_|"original process cgroup FD metadata")?;
        if (meta.dev(),meta.ino())!=(identity.cgroup_device,identity.cgroup_inode){return Err("original cgroup FD changed".into());}
        let before=named_cgroup(&identity.cgroup)?;
        if matches!(before,NamedCgroup::Same(actual) if actual!=(meta.dev(),meta.ino())){return Err("original named cgroup was replaced; no adoption".into());}
        let exited=pidfd_exited(self.pidfd.as_ref().ok_or("original PIDFD absent")?)?;
        if !exited{return Ok(None);}
        let mut reads=Vec::with_capacity(3);
        for (index,file) in self.controls.iter().enumerate(){
            let file=file.as_ref().ok_or("original cgroup control was never pinned; UNKNOWN")?;
            if control_identity(file)?!=identity.cgroup_controls[index]{return Err("original cgroup control identity changed".into());}
            reads.push(read_original_control(file,65536)?);
            if control_identity(file)?!=identity.cgroup_controls[index]{return Err("original control changed during read".into());}
        }
        if named_cgroup(&identity.cgroup)?!=before || !pidfd_exited(self.pidfd.as_ref().unwrap())?
            || BootId::current()?!=identity.boot{return Err("original drain observation raced identity/path/boot".into());}
        filesystem(cg,0x63677270)?;
        let after=cg.metadata().map_err(|_|"original cgroup final FD metadata")?;
        if (after.dev(),after.ino())!=(meta.dev(),meta.ino()){return Err("original cgroup identity changed during read".into());}
        if Instant::now()>=deadline{return Err("original process drain observation late".into());}
        classify_original_drain(before,&reads)
    }
    pub(super) fn close_namespace(&mut self,permit:terminal::VerifiedTerminalEffect)->Result<(),String>{
        self.identity()?;
        if self.namespace_close.is_some(){return Err("original task namespace close already consumed; no retry".into());}
        if !self.observed_exited_empty(permit.deadline())?{return Err("original task/cgroup not drained before namespace close".into());}
        let prepared=terminal::ClosedDescriptor::prepare(permit,
            self.namespace.as_ref().ok_or("original task namespace reference absent")?,
            terminal::TerminalEffect::CloseProcessNamespace)?;
        // Permission checks precede any move. Root the tombstone FIRST; even
        // a late/failed close-result write cannot lose the actual close state.
        self.namespace_close=Some(prepared);
        self.namespace_close.as_mut().unwrap().close(&mut self.namespace)?;
        self.namespace_close.as_ref().unwrap().require_closed()
    }
}
const CONTROL_NAMES:[&str;3]=["cgroup.events","cgroup.procs","cgroup.threads"];
#[derive(Clone,Copy,Debug,PartialEq,Eq,serde::Serialize)]
pub(super) enum OriginalCgroupDrain {OriginalLiveEmpty,OriginalKernelDeactivated}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum NamedCgroup {Same((u64,u64)),ExactEnoent}
#[derive(Debug)]
enum OriginalControlRead {Bytes(Vec<u8>),ExactEnodev}
fn named_cgroup(cgroup:&str)->Result<NamedCgroup,String>{
    match std::fs::symlink_metadata(format!("/sys/fs/cgroup{cgroup}")){
        Ok(meta) if meta.is_dir()&&!meta.file_type().is_symlink()=>Ok(NamedCgroup::Same((meta.dev(),meta.ino()))),
        Ok(_)=>Err("original cgroup path is not the original directory".into()),
        Err(error) if error.raw_os_error()==Some(libc::ENOENT)=>Ok(NamedCgroup::ExactEnoent),
        Err(_)=>Err("original cgroup name inaccessible; not ENOENT proof".into()),
    }
}
fn control_identity(file:&File)->Result<(u64,u64),String>{
    filesystem(file,0x63677270)?;
    let meta=file.metadata().map_err(|_|"original cgroup control FD stat")?;
    if !meta.is_file()||meta.ino()==0{return Err("original cgroup control type/identity invalid".into());}
    Ok((meta.dev(),meta.ino()))
}
fn read_original_control(file:&File,maximum:usize)->Result<OriginalControlRead,String>{
    use std::os::unix::fs::FileExt;
    // Offset zero on the SAME original file description, then consume through
    // EOF. Do not reopen by name or treat partial data + ENODEV as deactivated.
    let mut bytes=Vec::with_capacity(maximum.min(4096));let mut chunk=[0u8;4096];
    loop{
        let offset=u64::try_from(bytes.len()).map_err(|_|"original control offset overflow")?;
        match file.read_at(&mut chunk,offset){
            Ok(0)=>return Ok(OriginalControlRead::Bytes(bytes)),
            Ok(n)=>{if bytes.len().checked_add(n).is_none_or(|n|n>maximum){return Err("original control exceeds fixed bound".into());}bytes.extend_from_slice(&chunk[..n]);},
            Err(error) if error.raw_os_error()==Some(libc::ENODEV)&&bytes.is_empty()=>return Ok(OriginalControlRead::ExactEnodev),
            Err(_)=>return Err("original control failed/mixed partial read; UNKNOWN, not empty".into()),
        }
    }
}
fn classify_original_drain(named:NamedCgroup,reads:&[OriginalControlRead])->Result<Option<OriginalCgroupDrain>,String>{
    match reads{
        [OriginalControlRead::ExactEnodev,OriginalControlRead::ExactEnodev,OriginalControlRead::ExactEnodev]
            if named==NamedCgroup::ExactEnoent=>Ok(Some(OriginalCgroupDrain::OriginalKernelDeactivated)),
        [OriginalControlRead::Bytes(events),OriginalControlRead::Bytes(procs),OriginalControlRead::Bytes(threads)]
            if matches!(named,NamedCgroup::Same(_))=>{
                let populated=parse_populated(events)?;let procs=parse_tasks(procs)?;let threads=parse_tasks(threads)?;
                Ok((!populated&&procs.is_empty()&&threads.is_empty()).then_some(OriginalCgroupDrain::OriginalLiveEmpty))
            },
        _=>Err("original controls/path disagree; no generic missing/deactivated proof".into()),
    }
}
fn open_at(dir:&File,name:&str)->Result<File,String>{
    let name=std::ffi::CString::new(name).map_err(|_|"fixed process-pin name invalid")?;
    let raw=unsafe{libc::openat(dir.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
    if raw<0{return Err("original process/cgroup field unavailable; not zero".into());}
    Ok(unsafe{File::from_raw_fd(raw)})
}
fn directory(path:&str)->Result<File,String>{
    std::fs::OpenOptions::new().read(true).custom_flags(libc::O_CLOEXEC|libc::O_NOFOLLOW|libc::O_DIRECTORY)
        .open(path).map_err(|_|"actual anchored process/cgroup directory unavailable".into())
}
fn filesystem(file:&File,magic:u64)->Result<(),String>{
    let mut s:libc::statfs=unsafe{std::mem::zeroed()};
    if unsafe{libc::fstatfs(file.as_raw_fd(),&mut s)}!=0 || s.f_type as u64!=magic{return Err("actual process pin filesystem differs".into());}Ok(())
}
fn read_at(dir:&File,name:&str,maximum:usize)->Result<Vec<u8>,String>{
    use std::io::Read;
    let mut file=open_at(dir,name)?;let mut bytes=Vec::new();
    file.by_ref().take(u64::try_from(maximum).map_err(|_|"read bound overflow")?+1).read_to_end(&mut bytes).map_err(|_|"original process field read")?;
    if bytes.len()>maximum{return Err("original process field exceeds fixed bound".into());}Ok(bytes)
}
fn parse_start(raw:&[u8],pid:u32)->Result<u64,String>{
    let raw=std::str::from_utf8(raw).map_err(|_|"proc stat invalid UTF8")?;
    let (head,tail)=raw.rsplit_once(") ").ok_or("proc stat delimiter")?;
    if !head.starts_with(&format!("{pid} (")){return Err("proc stat is not exact original PID".into());}
    let fields=tail.split_whitespace().collect::<Vec<_>>();
    fields.get(19).ok_or("proc stat start absent")?.parse::<u64>().map_err(|_|"proc stat start invalid".into())
}
fn parse_cgroup(raw:&[u8],cid:&str)->Result<String,String>{
    if cid.len()!=64||!cid.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){return Err("full original CID absent".into());}
    let raw=std::str::from_utf8(raw).map_err(|_|"original cgroup UTF8")?;
    let rows=raw.lines().collect::<Vec<_>>();if rows.len()!=1{return Err("only exact unified cgroup-v2 original task supported".into());}
    let path=rows[0].strip_prefix("0::").ok_or("original cgroup-v2 marker absent")?;
    if !path.starts_with('/')||path.ends_with('/')||path.split('/').skip(1).any(|s|s.is_empty()||s=="."||s==".."){
        return Err("noncanonical original cgroup".into());}
    let last=path.rsplit('/').next().ok_or("original cgroup leaf absent")?;
    if last!=cid && last!=format!("docker-{cid}.scope"){return Err("original cgroup not bound to exact full CID".into());}
    Ok(path.into())
}
fn parse_tasks(raw:&[u8])->Result<BTreeSet<u32>,String>{
    let raw=std::str::from_utf8(raw).map_err(|_|"actual cgroup tasks UTF8")?;
    let mut out=BTreeSet::new();for row in raw.lines(){let pid=row.parse::<u32>().map_err(|_|"actual task malformed")?;
        if pid==0||pid.to_string()!=row||!out.insert(pid)||out.len()>16384{return Err("actual task duplicate/invalid/excessive".into());}}
    Ok(out)
}
fn parse_populated(raw:&[u8])->Result<bool,String>{
    let raw=std::str::from_utf8(raw).map_err(|_|"actual cgroup events UTF8")?;
    let mut seen=BTreeSet::new();let mut populated=None;
    for line in raw.lines(){let mut words=line.split_whitespace();let key=words.next().ok_or("empty cgroup event")?;
        let value=words.next().ok_or("cgroup event value absent")?;
        if words.next().is_some()||!seen.insert(key){return Err("duplicate/malformed cgroup event".into());}
        let n=value.parse::<u64>().map_err(|_|"cgroup event not unsigned")?;
        if value!=n.to_string(){return Err("cgroup event integer is noncanonical".into());}
        if key=="populated"{populated=Some(match n{0=>false,1=>true,_=>return Err("invalid populated value".into())});}}
    populated.ok_or("actual populated field missing; not zero".into())
}
fn pidfd_exited(file:&File)->Result<bool,String>{
    let mut p=libc::pollfd {fd:file.as_raw_fd(),events:libc::POLLIN,revents:0};
    if unsafe{libc::poll(&mut p,1,0)}<0||p.revents&(libc::POLLNVAL|libc::POLLERR)!=0{return Err("original PIDFD poll failed".into());}
    Ok(p.revents&libc::POLLIN!=0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn original_task_stat_zero_start_is_identity_data_not_a_missing_pin(){
        let tail=std::iter::once("S").chain(std::iter::repeat_n("0",19)).collect::<Vec<_>>().join(" ");
        assert_eq!(parse_start(format!("24 (name with ) space) {tail}").as_bytes(),24).unwrap(),0);
        assert!(parse_start(format!("25 (x) {tail}").as_bytes(),24).is_err());
    }
    #[test] fn original_cgroup_requires_full_cid_unified_and_canonical_leaf(){
        let cid="a".repeat(64);assert!(parse_cgroup(format!("0::/system.slice/docker-{cid}.scope\n").as_bytes(),&cid).is_ok());
        for path in [format!("0::/docker/{}\n",&cid[..12]),format!("0::/docker/../{cid}\n"),format!("0::/docker/{cid}\n1::/x\n"),format!("1::/docker/{cid}\n")]{assert!(parse_cgroup(path.as_bytes(),&cid).is_err());}
    }
    #[test] fn actual_task_census_missing_malformed_or_populated_never_means_empty(){
        for raw in [b"0\n".as_slice(),b"01\n",b"3\n3\n",b"-1\n",b"true\n"]{assert!(parse_tasks(raw).is_err());}
        assert!(parse_tasks(b"").unwrap().is_empty());
        for raw in [b"frozen 0\n".as_slice(),b"populated 2\n",b"populated 0\npopulated 0\n",b"populated false\n",b"populated +0\n",b"populated 00\n"]{assert!(parse_populated(raw).is_err());}
        assert!(parse_populated(b"populated 1\nfrozen 0\n").unwrap());
    }
    #[test] fn original_control_data_keeps_live_empty_and_kernel_deactivated_distinct(){
        // DATA predicate only: no original File/PIDFD owner or drain permit is
        // constructed by this test. The real caller supplies those checks.
        let live=[OriginalControlRead::Bytes(b"populated 0\nfrozen 0\n".to_vec()),
            OriginalControlRead::Bytes(vec![]),OriginalControlRead::Bytes(vec![])];
        assert_eq!(classify_original_drain(NamedCgroup::Same((7,12)),&live).unwrap(),Some(OriginalCgroupDrain::OriginalLiveEmpty));
        let dead=[OriginalControlRead::ExactEnodev,OriginalControlRead::ExactEnodev,OriginalControlRead::ExactEnodev];
        assert_eq!(classify_original_drain(NamedCgroup::ExactEnoent,&dead).unwrap(),Some(OriginalCgroupDrain::OriginalKernelDeactivated));
        assert!(classify_original_drain(NamedCgroup::Same((7,12)),&dead).is_err());
        assert!(classify_original_drain(NamedCgroup::ExactEnoent,&live).is_err());
    }
    #[test] fn original_control_data_mixed_errors_and_contradictory_census_never_grant_drain(){
        for index in 0..3{
            let mut mixed=[OriginalControlRead::ExactEnodev,OriginalControlRead::ExactEnodev,OriginalControlRead::ExactEnodev];
            mixed[index]=OriginalControlRead::Bytes(vec![]);
            assert!(classify_original_drain(NamedCgroup::ExactEnoent,&mixed).is_err());
        }
        for (events,procs,threads) in [(b"populated 1\n".as_slice(),b"".as_slice(),b"".as_slice()),
            (b"populated 0\n",b"12\n",b""),(b"populated 0\n",b"",b"12\n")]{
            let census=[OriginalControlRead::Bytes(events.to_vec()),OriginalControlRead::Bytes(procs.to_vec()),OriginalControlRead::Bytes(threads.to_vec())];
            assert_eq!(classify_original_drain(NamedCgroup::Same((7,12)),&census).unwrap(),None);
        }
        let malformed=[OriginalControlRead::Bytes(b"frozen 0\n".to_vec()),OriginalControlRead::Bytes(vec![]),OriginalControlRead::Bytes(vec![])];
        assert!(classify_original_drain(NamedCgroup::Same((7,12)),&malformed).is_err());
        assert!(classify_original_drain(NamedCgroup::ExactEnoent,&[]).is_err());
    }
}
