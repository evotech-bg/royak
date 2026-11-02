//! Durable, daemon-shared admission. No timer releases an unknown operation.
//! The Docker adapter is the only production constructor of observations.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};
#[path = "exec_adapter.rs"]
mod adapter;
#[path = "exec_credentials.rs"]
mod credentials;
#[path = "private_io.rs"]
mod private_io;
#[path = "exec_recovery.rs"]
mod recovery;
#[path = "exec_wire.rs"]
mod wire;

const PREFIX: &str = "EXEC_ADMISSION_UNKNOWN: ";
const PER_CONTAINER: usize = 2048;
const NODE_RECORDS: usize = 32768;
const CONTAINERS: usize = 512;
const SWEEP: usize = 8;
pub(crate) const ROOT: &str = "/var/lib/royak/exec-admission";
pub(crate) fn is_unknown(error: &str) -> bool {
    error.starts_with(PREFIX)
}
fn unknown(error: impl std::fmt::Display) -> String {
    format!("{PREFIX}{error}")
}
fn hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    boot: String,
    daemon_id: String,
    sender_pid: u32,
    sender_start: u64,
    sender_uid: u32,
    sender_gid: u32,
    sender_exe_dev: u64,
    sender_exe_ino: u64,
    socket_dev: u64,
    socket_ino: u64,
}
impl Binding {
    fn valid(&self) -> bool {
        self.boot.len() == 36
            && self.boot.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
                }
            })
            && !self.daemon_id.is_empty()
            && self.daemon_id.len() <= 128
            && self
                .daemon_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b':' || b == b'-')
            && self.sender_pid > 1
            && self.sender_start > 0
            && self.sender_uid == 0
            && self.sender_exe_ino > 0
            && self.socket_ino > 0
    }
}

/// Read-only actual-sender pin for managed mounts. This is neither a Docker
/// launch permit nor an FD/JSON constructor. The attested stream keeps the
/// existing sender pidfd alive; the held namespace alone is never freshness.
pub(crate) struct VerifiedDaemonNamespace {
    connection: credentials::AdmittedStream,
    namespace: File,
    watch_namespace: File,
    identity: (u64, u64),
}
/// Actual installed daemon-peer lifetime, never a caller namespace scalar.
/// The positive HTTP method is private to the closed typed consumer adapter.
pub(crate) struct ManagedConsumerConnection {
    connection:credentials::AdmittedStream,
    namespace:File,
    watch_namespace:File,
    identity:(u64,u64),
    binding:Binding,
}
enum LegacySocket {Attested(credentials::AdmittedStream),Plain(std::os::unix::net::UnixStream)}
impl std::io::Read for LegacySocket {
    fn read(&mut self,out:&mut[u8])->std::io::Result<usize>{match self{Self::Attested(s)=>s.read(out),Self::Plain(s)=>s.read(out)}}
}
impl std::io::Write for LegacySocket {
    fn write(&mut self,data:&[u8])->std::io::Result<usize>{match self{Self::Attested(s)=>s.write(data),Self::Plain(s)=>s.write(data)}}
    fn flush(&mut self)->std::io::Result<()>{match self{Self::Attested(s)=>s.flush(),Self::Plain(s)=>s.flush()}}
}
impl wire::TimedStream for LegacySocket {
    fn read_timeout(&self,t:Option<Duration>)->std::io::Result<()>{match self{Self::Attested(s)=>s.set_read_timeout(t),Self::Plain(s)=>s.set_read_timeout(t)}}
    fn write_timeout(&self,t:Option<Duration>)->std::io::Result<()>{match self{Self::Attested(s)=>s.set_write_timeout(t),Self::Plain(s)=>s.set_write_timeout(t)}}
}
/// Not a native permission. Only bounded actual inspect + conservative
/// native denial can construct this ONE legacy full-CID effect association.
pub(crate) struct LegacyContainerConnection {stream:LegacySocket,id:String,deadline:Instant,retirement_limit:Option<Instant>}
struct RetireStream<'a>{inner:&'a mut LegacySocket}
impl Read for RetireStream<'_>{fn read(&mut self,out:&mut[u8])->std::io::Result<usize>{self.inner.read(out)}}
impl Write for RetireStream<'_>{
    fn write(&mut self,data:&[u8])->std::io::Result<usize>{self.inner.write(data)}
    fn flush(&mut self)->std::io::Result<()>{self.inner.flush()}
}
impl wire::TimedStream for RetireStream<'_>{
    fn read_timeout(&self,t:Option<Duration>)->std::io::Result<()>{wire::TimedStream::read_timeout(&*self.inner,t)}
    fn write_timeout(&self,t:Option<Duration>)->std::io::Result<()>{
        wire::TimedStream::write_timeout(&*self.inner,t.map(|t|t.min(Duration::from_secs(5))))
    }
}
impl LegacyContainerConnection {
    pub(super) fn prepare_retirement(selector:&str)->Result<Self,String>{
        let now=Instant::now();let mut value=Self::prepare(selector,now+Duration::from_secs(15))?;
        value.retirement_limit=Some(now+Duration::from_secs(45));Ok(value)
    }
    pub(super) fn prepare(selector:&str,deadline:Instant)->Result<Self,String>{
        if crate::docker::managed::registered_target(selector){return Err("managed target requires genuine owned consumer action; legacy effect refused".into());}
        let selector=selector.trim_start_matches('/');
        if selector.is_empty()||selector.len()>512||!selector.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b)){
            return Err("legacy container selector malformed".into());
        }
        namespace_budget(deadline)?;
        let strict=crate::docker::managed::native_history_before_legacy()?;
        namespace_budget(deadline)?;
        let socket=crate::docker::docker_sock();
        let mut stream=if strict{
            if std::env::var("DOCKER_HOST").ok().is_some_and(|s|!s.starts_with("unix://")){
                return Err("native-history legacy mutation refuses non-Unix fallback".into());
            }
            LegacySocket::Attested(credentials::AdmittedStream::connect(&socket,None,deadline)?)
        }else{
            // Explicit ordinary legacy-only local Unix/proxy trust boundary;
            // this is NOT Linux sender/namespace attestation or native grant.
            LegacySocket::Plain(std::os::unix::net::UnixStream::connect(&socket).map_err(|_|"legacy Docker connection unavailable")?)
        };
        let response=wire::keepalive_get(&mut stream,&format!("/containers/{selector}/json"),wire::JSON,deadline)?;
        if response.status!=200{return Err("legacy exact inspect failed/404/UNKNOWN; no mutation".into());}
        if crate::docker::managed::inspected_native_history(&response.body)?{
            // Only actual transport observation latches this negative scope;
            // pure JSON/model parsers never mutate global runtime state.
            crate::docker::managed::requested_native_runtime();
            return Err("retained native history denies legacy mutation; no adoption".into());
        }
        let inspected=crate::docker::managed::strict_json(&response.body)?;
        for mount in inspected.get("Mounts").and_then(|v|v.as_array()).ok_or("actual mount census malformed")?{
            let source=mount.get("Source").and_then(|v|v.as_str()).ok_or("actual mount source missing")?;
            if !source.is_empty(){crate::host_access::reject_native_publication_source(source)?;}
        }
        let id=crate::docker::managed::legacy_inspected_id(&response.body,selector)?;
        if crate::docker::managed::registered_target(&id){return Err("actual full CID is genuinely managed; legacy effect refused".into());}
        if let LegacySocket::Attested(actual)=&stream{actual.validate()?;}
        namespace_budget(deadline)?;
        Ok(Self{stream,id,deadline,retirement_limit:None})
    }
    pub(super) fn start(mut self)->Result<(),String>{
        let path=format!("/containers/{}/start",self.id);
        let response=wire::request(&mut self.stream,"POST",&path,None,4096,self.deadline)?;
        namespace_budget(self.deadline)?;
        if matches!(response.status,204|304){Ok(())}else{Err("legacy full-CID Start failed/UNKNOWN".into())}
    }
    pub(super) fn stop(mut self)->Result<(),String>{
        let path=format!("/containers/{}/stop?t=10",self.id);
        let response=wire::request(&mut self.stream,"POST",&path,None,4096,self.deadline)?;
        namespace_budget(self.deadline)?;
        if matches!(response.status,204|304){Ok(())}else{Err("legacy full-CID Stop failed/UNKNOWN".into())}
    }
    pub(super) fn remove(mut self,force:bool)->Result<(),String>{
        let response=wire::delete_container(&mut self.stream,&self.id,force,self.deadline)?;
        namespace_budget(self.deadline)?;
        if matches!(response.status,204|404){Ok(())}else{Err("legacy full-CID remove failed/UNKNOWN".into())}
    }
    pub(super) fn connect(mut self,network:&str,aliases:&[&str])->Result<(),String>{
        if network.is_empty()||network.len()>256||!network.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b)){
            return Err("legacy network target malformed".into());
        }
        let body=serde_json::to_vec(&serde_json::json!({"Container":self.id,"EndpointConfig":{"Aliases":aliases}}))
            .map_err(|_|"legacy exact network request encoding failed")?;
        let response=wire::request(&mut self.stream,"POST",&format!("/networks/{network}/connect"),Some(&body),4096,self.deadline)?;
        namespace_budget(self.deadline)?;
        if response.status==200{Ok(())}else{Err("legacy full-CID network connect failed/UNKNOWN".into())}
    }
    pub(super) fn disconnect(mut self,network:&str)->Result<(),String>{
        if network.is_empty()||network.len()>256||!network.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b)){
            return Err("legacy network target malformed".into());
        }
        let body=serde_json::to_vec(&serde_json::json!({"Container":self.id,"Force":true})).map_err(|_|"legacy disconnect encoding failed")?;
        let response=wire::request(&mut self.stream,"POST",&format!("/networks/{network}/disconnect"),Some(&body),4096,self.deadline)?;
        namespace_budget(self.deadline)?;
        if response.status==200{Ok(())}else{Err("legacy full-CID network disconnect failed/UNKNOWN".into())}
    }
    pub(super) fn apply_netns_iptables(mut self,script:&str)->Result<(),String>{
        // The association was produced by a real native-denying inspection
        // of THIS full target CID. Never reconnect by pod name or helper ID.
        namespace_budget(self.deadline)?;
        let body=serde_json::to_vec(&serde_json::json!({
            "Image":"alpine:3.21","Cmd":["sh","-c",script],
            "HostConfig":{"NetworkMode":format!("container:{}",self.id),
                "CapAdd":["NET_ADMIN"],"AutoRemove":true}
        })).map_err(|_|"legacy netns helper encoding failed")?;
        if body.len()>wire::JSON{return Err("legacy netns helper exceeds bounded frame".into());}
        let created=wire::keepalive_post(&mut self.stream,"/containers/create",Some(&body),4096,self.deadline)?;
        namespace_budget(self.deadline)?;
        if created.status!=201{return Err("legacy netns helper Create not acknowledged; no Start/retry".into());}
        let helper=crate::docker::managed::legacy_helper_created_id(&created.body)?;
        let inspected=wire::keepalive_get(&mut self.stream,&format!("/containers/{helper}/json"),wire::JSON,self.deadline)?;
        namespace_budget(self.deadline)?;
        if inspected.status!=200{return Err("legacy netns helper inspect failed; no Start".into());}
        crate::docker::managed::require_legacy_netns_helper(&inspected.body,&helper,&self.id,script)?;
        let started=wire::keepalive_post(&mut self.stream,&format!("/containers/{helper}/start"),None,4096,self.deadline)?;
        namespace_budget(self.deadline)?;
        if started.status!=204{return Err("legacy netns helper Start unknown; no retry/delete".into());}
        // Preserve the legacy finite thirty-observation cadence. A transport
        // error is UNKNOWN, not evidence that AutoRemove completed.
        for _ in 0..30 {
            let observed=wire::keepalive_get(&mut self.stream,&format!("/containers/{helper}/json"),wire::JSON,self.deadline)?;
            namespace_budget(self.deadline)?;
            if observed.status==404{return Ok(());}
            if observed.status!=200{return Err("legacy netns helper observation UNKNOWN".into());}
            let data=crate::docker::managed::strict_json(&observed.body)?;
            if data.get("Id").and_then(|v|v.as_str())!=Some(helper.as_str()){
                return Err("legacy netns helper identity changed".into());
            }
            match data.get("State").and_then(|v|v.get("Running")).and_then(|v|v.as_bool()){
                Some(false)=>return Ok(()),Some(true)=>(),None=>return Err("legacy netns helper state malformed".into()),
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Err("legacy netns helper still running after original observation cadence".into())
    }
    pub(super) fn retire(mut self)->Result<(),String>{
        let overall=self.retirement_limit.ok_or("legacy retirement has no original45s envelope")?;
        let stop=wire::keepalive_post(&mut RetireStream{inner:&mut self.stream},
            &format!("/containers/{}/stop?t=10",self.id),None,4096,self.deadline)?;
        namespace_budget(self.deadline)?;
        if !matches!(stop.status,204|304){return Err("legacy stop not acknowledged; no delete".into());}
        let remove_deadline=overall.min(Instant::now()+Duration::from_secs(15));
        let removed=wire::keepalive_delete_container(&mut RetireStream{inner:&mut self.stream},&self.id,remove_deadline)?;
        namespace_budget(remove_deadline)?;
        if !matches!(removed.status,204|404){return Err("legacy removal not acknowledged".into());}
        let observe_deadline=overall.min(Instant::now()+Duration::from_secs(15));
        let absent=wire::keepalive_get(&mut RetireStream{inner:&mut self.stream},
            &format!("/containers/{}/json",self.id),wire::JSON,observe_deadline)?;
        namespace_budget(observe_deadline)?;
        if absent.status!=404{return Err("legacy exact full CID still exists/unknown".into());}
        // Full-CID Docker absence is NOT a native process/open-file/volume
        // drain, metadata GC or physical-fencing certificate.
        Ok(())
    }
}
impl ManagedConsumerConnection {
    pub(crate) fn terminal_signal(&mut self,
        permission:crate::storage_driver::native_runtime::mount::consumer::terminal::VerifiedSignalTerm,
        path:&str,deadline:Instant)->Result<(u16,Vec<u8>),String>{
        self.validate(deadline)?;
        let submitted=permission.consume(self,path,deadline)?;
        let response=match wire::request(&mut self.connection,"POST",path,None,4096,deadline){
            Ok(response)=>response,
            Err(error)=>{submitted.transport_unknown();return Err(error);}
        };
        submitted.observed(response.status,&response.body);
        if self.validate(deadline).is_err(){submitted.transport_unknown();}
        Ok((response.status,response.body))
    }
    pub(crate) fn validate(&self,deadline:Instant)->Result<(),String>{
        namespace_budget(deadline)?;
        self.connection.validate()?;
        #[cfg(target_os="linux")]
        {
            let current=current_mount_namespace(self.binding.sender_pid)?;
            let watch=current_watch_mount_namespace()?;
            if !same_mount_namespaces(self.identity,namespace_identity(&self.namespace)?,
                namespace_identity(&self.watch_namespace)?,namespace_identity(&current)?,namespace_identity(&watch)?){
                return Err("consumer actual sender/Watch mount namespace changed".into());
            }
            self.connection.validate()?;namespace_budget(deadline)
        }
        #[cfg(not(target_os="linux"))]
        {Err("managed consumer connection requires Linux actual-sender namespace".into())}
    }
    pub(crate) fn identity_sha256(&self)->Result<String,String>{
        use sha2::{Digest,Sha256};
        Ok(format!("{:x}",Sha256::digest(serde_json::to_vec(&(&self.binding,self.identity))
            .map_err(|_|"cannot bind actual consumer daemon identity")?)))
    }
    pub(crate) fn get(&mut self,path:&str,bound:usize,deadline:Instant)->Result<(u16,Vec<u8>),String>{
        self.validate(deadline)?;
        let response=wire::keepalive_get(&mut self.connection,path,bound,deadline)?;
        self.validate(deadline)?;Ok((response.status,response.body))
    }
    pub(crate) fn effect(&mut self,
        permission:crate::storage_driver::native_runtime::mount::consumer::VerifiedConsumerAction,
        method:&str,path:&str,body:Option<&[u8]>,bound:usize,deadline:Instant)->Result<(u16,Vec<u8>),String>{
        self.validate(deadline)?;
        let submitted=permission.consume(self,method,path,body,deadline)?;
        let response=match wire::request(&mut self.connection,method,path,body,bound,deadline){
            Ok(response)=>response,Err(error)=>{submitted.record_transport_unknown();return Err(error);}
        };
        submitted.record_response(response.status,&response.body);
        if self.validate(deadline).is_err(){submitted.invalidate_after_response();}
        // Complete late response remains observable DATA; original operation
        // is already UNKNOWN and cannot promote it to timely Create/Start.
        Ok((response.status,response.body))
    }
}
impl VerifiedDaemonNamespace {
    pub(super) fn consumer_connection(&self,deadline:Instant)->Result<ManagedConsumerConnection,String>{
        self.validate_current(deadline)?;
        let binding=self.connection.binding()?.clone();
        let socket=match std::env::var("DOCKER_HOST"){
            Ok(host)=>host.strip_prefix("unix://").filter(|path|path.starts_with('/'))
                .ok_or("managed consumer refuses remote/non-Unix selectors; no fallback")?.to_string(),
            Err(std::env::VarError::NotPresent)=>crate::docker::docker_sock(),
            Err(_)=>return Err("invalid managed consumer Docker selector".into()),
        };
        let connection=credentials::AdmittedStream::connect(&socket,Some(&binding),deadline)?;
        let value=ManagedConsumerConnection {connection,namespace:self.namespace.try_clone().map_err(|_|"cannot retain actual daemon namespace")?,
            watch_namespace:self.watch_namespace.try_clone().map_err(|_|"cannot retain actual Watch namespace")?,
            identity:self.identity,binding};
        value.validate(deadline)?;self.validate_current(deadline)?;Ok(value)
    }
    pub(super) fn admit(socket: &str, deadline: Instant) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        {
            namespace_budget(deadline)?;
            let connection = credentials::AdmittedStream::connect(socket, None, deadline)?;
            connection.validate()?;
            let pid = connection.binding()?.sender_pid;
            let watch_namespace = current_watch_mount_namespace()?;
            let namespace = current_mount_namespace(pid)?;
            connection.validate()?;
            let identity = namespace_identity(&namespace)?;
            if identity != namespace_identity(&watch_namespace)? {
                return Err("managed mount requires the actual dockerd and Watch mount namespace to be identical; no publisher fallback".into());
            }
            let pin = Self { connection, namespace, watch_namespace, identity };
            pin.validate_current(deadline)?;
            Ok(pin)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (socket, deadline);
            Err("managed mount daemon attestation requires local root Linux".into())
        }
    }
    pub(crate) fn identity(&self) -> (u64, u64) { self.identity }
    /// Call freshly at EACH positive physical/consumer boundary. Reopen both
    /// current namespaces: holding an old ns FD cannot hide dockerd setns().
    pub(crate) fn validate_current(&self, existing_action_deadline:Instant) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            namespace_budget(existing_action_deadline)?;
            self.connection.validate()?;
            let pid = self.connection.binding()?.sender_pid;
            let daemon_now = current_mount_namespace(pid)?;
            let watch_now = current_watch_mount_namespace()?;
            if !same_mount_namespaces(self.identity, namespace_identity(&self.namespace)?,
                namespace_identity(&self.watch_namespace)?, namespace_identity(&daemon_now)?,
                namespace_identity(&watch_now)?) {
                return Err("actual sender/Watch mount namespace changed; retained mount UNKNOWN".into());
            }
            self.connection.validate()?;
            namespace_budget(existing_action_deadline)
        }
        #[cfg(not(target_os = "linux"))]
        { let _=existing_action_deadline; Err("managed mount namespace validation requires Linux".into()) }
    }
}
fn namespace_budget(deadline: Instant) -> Result<(), String> {
    if Instant::now() >= deadline { Err("original managed mount budget expired".into()) } else { Ok(()) }
}
fn same_mount_namespaces(expected:(u64,u64), held:(u64,u64), watch_held:(u64,u64),
    daemon_now:(u64,u64), watch_now:(u64,u64))->bool {
    expected.1>0 && [held,watch_held,daemon_now,watch_now].iter().all(|v|*v==expected)
}
#[cfg(target_os = "linux")]
fn namespace_identity(file:&File)->Result<(u64,u64),String> {
    use std::os::{fd::AsRawFd,unix::fs::MetadataExt};
    let m=file.metadata().map_err(|_|"cannot stat actual mount namespace FD")?;
    let mut fs:libc::statfs=unsafe{std::mem::zeroed()};
    if unsafe{libc::fstatfs(file.as_raw_fd(),&mut fs)}!=0 || fs.f_type as u64!=0x6e736673
        || unsafe{libc::ioctl(file.as_raw_fd(),0xb703)}!=libc::CLONE_NEWNS || m.ino()==0 {
        return Err("FD is not an actual nsfs mount namespace".into());
    }
    Ok((m.dev(),m.ino()))
}
#[cfg(target_os = "linux")]
fn current_watch_mount_namespace()->Result<File,String> {
    let tid=u32::try_from(unsafe{libc::syscall(libc::SYS_gettid)})
        .map_err(|_|"cannot identify current Watch thread")?;
    current_mount_namespace(tid)
}
#[cfg(target_os = "linux")]
fn current_mount_namespace(pid:u32)->Result<File,String> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd,FromRawFd};
    if pid<=1 || unsafe{libc::geteuid()}!=0 {return Err("root actual process namespace required".into());}
    fn owned(raw:i32)->Result<File,String> {
        if raw<0 {Err("cannot open anchored current process namespace".into())}
        else {Ok(unsafe{File::from_raw_fd(raw)})}
    }
    let proc=owned(unsafe{libc::open(c"/proc".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
    let mut fs:libc::statfs=unsafe{std::mem::zeroed()};
    if unsafe{libc::fstatfs(proc.as_raw_fd(),&mut fs)}!=0 || fs.f_type as u64!=0x9fa0 {
        return Err("actual namespace inspection requires procfs".into());
    }
    let name=CString::new(pid.to_string()).map_err(|_|"invalid actual sender PID")?;
    let process=owned(unsafe{libc::openat(proc.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
    let ns=owned(unsafe{libc::openat(process.as_raw_fd(),c"ns".as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)})?;
    // Intentionally follow only this kernel-generated namespace symlink under
    // the anchored procfs/PID/ns tree, never a caller-selected filesystem path.
    let file=owned(unsafe{libc::openat(ns.as_raw_fd(),c"mnt".as_ptr(),libc::O_RDONLY|libc::O_CLOEXEC)})?;
    namespace_identity(&file)?;
    Ok(file)
}

#[cfg(test)]
mod managed_namespace_tests {
    use super::*;
    #[test]
    fn every_current_and_retained_namespace_must_match_not_only_held_fd() {
        let pin=(4,91);
        assert!(same_mount_namespaces(pin,pin,pin,pin,pin));
        for at in 0..4 {
            let mut actual=[pin;4];actual[at]=(4,92);
            assert!(!same_mount_namespaces(pin,actual[0],actual[1],actual[2],actual[3]));
        }
        assert!(!same_mount_namespaces((4,0),(4,0),(4,0),(4,0),(4,0)));
    }
    #[test]
    fn namespace_budget_is_original_and_never_renewed_by_validation() {
        assert!(namespace_budget(Instant::now()-Duration::from_millis(1)).is_err());
        assert!(namespace_budget(Instant::now()+Duration::from_secs(1)).is_ok());
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Owner {
    boot: String,
    pid: u32,
    start: u64,
}
impl Owner {
    fn valid(&self, binding: &Binding) -> bool {
        self.boot == binding.boot && self.pid > 1 && self.start > 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    UnknownCreate,
    Created,
    NeverStart,
    StartUnknown,
    Running,
    Terminal,
}
/// Execution accounting is separate from Docker metadata lifetime. Missing
/// legacy data is UNKNOWN, never a successful foreground/NoStart witness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
enum Execution {
    NoStart,
    PossibleRunning,
    OsDrained,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    nonce: String,
    exec: Option<String>,
    phase: Phase,
    owner: Owner,
    #[serde(default)]
    execution: Option<Execution>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    container: String,
    records: Vec<Record>,
    sweep: usize,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u32,
    attestation: String,
    binding: Binding,
    per_container: usize,
    node_records: usize,
    containers: usize,
}

#[derive(Debug)]
enum Container {
    Absent,
    Present { id: String, execs: Vec<String> },
}
#[derive(Debug)]
enum Exec {
    Absent,
    Present {
        id: String,
        container: String,
        running: bool,
        exit: Option<i64>,
    },
}

/// Not public HTTP DTOs. In production only adapter::Docker implements this.
trait Engine {
    fn binding(&mut self) -> Result<Binding, String>;
    fn container(&mut self, id: &str) -> Result<Container, String>;
    fn exec(&mut self, id: &str) -> Result<Exec, String>;
    fn create(
        &mut self,
        container: &str,
        body: &serde_json::Value,
    ) -> Result<String, CreateFailure>;
    fn owner_alive(&mut self, owner: &Owner) -> Result<bool, String>;
}
#[derive(Debug)]
enum CreateFailure {
    NotSubmitted(String),
    Ambiguous(String),
}
impl From<String> for CreateFailure {
    fn from(error: String) -> Self {
        Self::Ambiguous(error)
    }
}
impl From<&str> for CreateFailure {
    fn from(error: &str) -> Self {
        Self::Ambiguous(error.into())
    }
}

struct Store {
    dir: private_io::Dir,
    binding: Binding,
}
impl Store {
    fn open(
        path: &Path,
        binding: Binding,
        deadline: Instant,
        cancelled: &dyn Fn() -> Result<(), String>,
    ) -> Result<Self, String> {
        if !binding.valid() {
            return Err(unknown("unverified node/daemon identity"));
        }
        let dir = private_io::Dir::open(path, true).map_err(unknown)?;
        let store = Self { dir, binding };
        let _lock = store.lock("lock", deadline, cancelled)?;
        match store.dir.read("binding.json").map_err(unknown)? {
            Some(raw) => {
                let header: Header = serde_json::from_slice(&raw).map_err(unknown)?;
                if header.version != 2
                    || header.attestation != "linux-scm-dockerd-v1"
                    || header.binding != store.binding
                    || header.per_container != PER_CONTAINER
                    || header.node_records != NODE_RECORDS
                    || header.containers != CONTAINERS
                {
                    return Err(unknown("journal identity/policy changed; existing charges retained for explicit review"));
                }
            }
            None => {
                if !store
                    .dir
                    .bounded_entries(2)
                    .map_err(unknown)?
                    .iter()
                    .all(|n| n == "lock")
                {
                    return Err(unknown(
                        "binding absent in nonempty journal; no empty-state reset",
                    ));
                }
                let header = Header {
                    version: 2,
                    attestation: "linux-scm-dockerd-v1".into(),
                    binding: store.binding.clone(),
                    per_container: PER_CONTAINER,
                    node_records: NODE_RECORDS,
                    containers: CONTAINERS,
                };
                store
                    .dir
                    .write(
                        "binding.json",
                        &serde_json::to_vec(&header).map_err(unknown)?,
                    )
                    .map_err(unknown)?;
            }
        }
        Ok(store)
    }
    fn lock(
        &self,
        name: &str,
        deadline: Instant,
        cancelled: &dyn Fn() -> Result<(), String>,
    ) -> Result<File, String> {
        loop {
            cancelled()?;
            match self.dir.lock_named(name) {
                Ok(lock) => return Ok(lock),
                Err(error) if error == "storage pool already has an operation in progress" => {
                    if Instant::now() >= deadline {
                        return Err(unknown(
                            "journal lock unavailable within existing Create budget",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(unknown(error)),
            }
        }
    }
    fn stripe(cid: &str) -> String {
        format!(
            "stripe-{:02x}",
            u8::from_str_radix(&cid[..2], 16).unwrap() % 64
        )
    }
    fn filename(cid: &str) -> String {
        format!("{cid}.json")
    }
    fn read(&self, cid: &str) -> Result<Journal, String> {
        let Some(raw) = self.dir.read(&Self::filename(cid)).map_err(unknown)? else {
            return Ok(Journal {
                version: 1,
                container: cid.into(),
                records: vec![],
                sweep: 0,
            });
        };
        let journal: Journal = serde_json::from_slice(&raw).map_err(unknown)?;
        if ![1, 2].contains(&journal.version)
            || journal.container != cid
            || !hex(cid, 64)
            || journal.records.len() > PER_CONTAINER
            || journal.sweep > PER_CONTAINER
        {
            return Err(unknown("invalid exec journal header or bound"));
        }
        let mut nonces = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for r in &journal.records {
            if !hex(&r.nonce, 32)
                || !nonces.insert(r.nonce.as_str())
                || !r.owner.valid(&self.binding)
                || r.exec
                    .as_deref()
                    .is_some_and(|id| !hex(id, 64) || !ids.insert(id))
                || (r.phase != Phase::UnknownCreate && r.exec.is_none())
                || (journal.version == 1 && r.execution.is_some())
                || (matches!(
                    r.phase,
                    Phase::UnknownCreate | Phase::Created | Phase::NeverStart
                ) && r
                    .execution
                    .as_ref()
                    .is_some_and(|e| e != &Execution::NoStart))
                || (matches!(
                    r.phase,
                    Phase::StartUnknown | Phase::Running | Phase::Terminal
                ) && r.execution == Some(Execution::NoStart))
            {
                return Err(unknown("invalid or duplicate durable exec lineage"));
            }
        }
        Ok(journal)
    }
    fn write(&self, journal: &Journal) -> Result<(), String> {
        let mut next = journal.clone();
        next.version = 2;
        self.dir
            .write(
                &Self::filename(&journal.container),
                &serde_json::to_vec(&next).map_err(unknown)?,
            )
            .map_err(unknown)
    }
    fn all(&self) -> Result<Vec<Journal>, String> {
        let mut journals = Vec::new();
        let mut total = 0usize;
        let mut ids = BTreeSet::new();
        let mut nonces = BTreeSet::new();
        for name in self
            .dir
            .bounded_entries(CONTAINERS + 64 + 3)
            .map_err(unknown)?
        {
            if name == "lock"
                || name == "binding.json"
                || name == "coordinator-lock"
                || (name.starts_with("stripe-")
                    && name.len() == 9
                    && hex(&name[7..], 2)
                    && u8::from_str_radix(&name[7..], 16).unwrap() < 64)
            {
                continue;
            }
            let cid = name
                .strip_suffix(".json")
                .filter(|s| hex(s, 64))
                .ok_or_else(|| {
                    unknown("unexpected journal entry; possible interrupted write retained")
                })?;
            let journal = self.read(cid)?;
            total = total
                .checked_add(journal.records.len())
                .filter(|n| *n <= NODE_RECORDS)
                .ok_or_else(|| unknown("aggregate journal rows exceed fixed resource guard"))?;
            for r in &journal.records {
                if !nonces.insert(r.nonce.clone())
                    || r.exec.as_ref().is_some_and(|id| !ids.insert(id.clone()))
                {
                    return Err(unknown("cross-container duplicate exec lineage"));
                }
            }
            journals.push(journal);
        }
        if journals.len() > CONTAINERS
            || journals.iter().map(|j| j.records.len()).sum::<usize>() > NODE_RECORDS
        {
            return Err(unknown("journal resource guard exhausted/corrupt"));
        }
        Ok(journals)
    }
}

fn observe_container(engine: &mut impl Engine, cid: &str) -> Result<Vec<String>, String> {
    let Container::Present { id, execs } = engine.container(cid).map_err(unknown)? else {
        return Err(unknown("exact container absent; charges retained"));
    };
    if id != cid || execs.len() > PER_CONTAINER {
        return Err(unknown("container census association/bound invalid"));
    }
    let mut seen = BTreeSet::new();
    if execs.iter().any(|id| !hex(id, 64) || !seen.insert(id)) {
        return Err(unknown(
            "container census contains invalid/duplicate ExecIDs",
        ));
    }
    Ok(execs)
}

fn sweep(
    store: &Store,
    journal: &mut Journal,
    engine: &mut impl Engine,
    deadline: Instant,
) -> Result<(), String> {
    // Bounded incremental inspection; no wall-clock eviction. A complete sweep
    // is not claimed. Remaining records continue to consume capacity.
    let len = journal.records.len();
    if len == 0 {
        return Ok(());
    }
    let indices = (0..SWEEP.min(len))
        .map(|n| (journal.sweep + n) % len)
        .collect::<Vec<_>>();
    let mut remove = BTreeSet::new();
    for i in indices {
        let record = &mut journal.records[i];
        if record.phase == Phase::UnknownCreate {
            continue;
        }
        if record.phase == Phase::Created && !engine.owner_alive(&record.owner).map_err(unknown)? {
            // Before-Start fsync is mandatory in every caller, so a dead
            // creator with durable Created never submitted a Start request.
            record.phase = Phase::NeverStart;
            record.execution = Some(Execution::NoStart);
        }
        let id = record
            .exec
            .as_deref()
            .ok_or_else(|| unknown("known exec has no ID"))?;
        match engine.exec(id).map_err(unknown)? {
            Exec::Present {
                id: actual,
                container,
                running,
                exit,
            } => {
                if actual != id || container != journal.container {
                    return Err(unknown("known exec association mismatch"));
                }
                if running {
                    if record.phase == Phase::NeverStart || record.phase == Phase::Created {
                        return Err(unknown("exec ran outside durable Start lineage"));
                    }
                    record.phase = Phase::Running;
                    // Orphan signals belong ONLY to the fixed recovery worker,
                    // which retains the SAME Reference/pidfd across retries.
                    // Create-driven metadata observation must not recreate it.
                } else if exit.is_some()
                    && matches!(
                        record.phase,
                        Phase::StartUnknown | Phase::Running | Phase::Terminal
                    )
                {
                    record.phase = Phase::Terminal;
                } else if exit.is_some()
                    && matches!(record.phase, Phase::Created | Phase::NeverStart)
                {
                    return Err(unknown(
                        "exec terminal state contradicts durable never-start lineage",
                    ));
                }
            }
            Exec::Absent => {
                if record.execution == Some(Execution::OsDrained)
                    || (record.phase == Phase::NeverStart
                        && record.execution == Some(Execution::NoStart))
                {
                    // Moby ExecInspect404 also masks an existing exec when its
                    // container was removed. Only fresh same-CID200 makes this
                    // a metadata absence witness. Unknown tombstones survive.
                    observe_container(engine, &journal.container)?;
                    remove.insert(i);
                }
            }
        }
    }
    journal.records = journal
        .records
        .iter()
        .enumerate()
        .filter(|(i, _)| !remove.contains(i))
        .map(|(_, r)| r.clone())
        .collect();
    journal.sweep = if journal.records.is_empty() {
        0
    } else {
        (journal.sweep + SWEEP) % journal.records.len()
    };
    let _global = store.lock("lock", deadline, &|| Ok(()))?;
    if journal.records.is_empty() {
        store
            .dir
            .remove(&Store::filename(&journal.container))
            .map_err(unknown)
    } else {
        store.write(journal)
    }
}

#[derive(Debug)]
struct Created {
    container: String,
    id: String,
    nonce: String,
    binding: Binding,
    owner: Owner,
}
fn create_inner(
    path: &Path,
    engine: &mut impl Engine,
    owner: Owner,
    input: &str,
    nonce: &str,
    body: &serde_json::Value,
    deadline: Instant,
    cancelled: &dyn Fn() -> Result<(), String>,
) -> Result<Created, String> {
    if input.len() < 12 || input.len() > 64 || !hex(input, input.len()) || !hex(nonce, 32) {
        return Err(unknown(
            "exec requires an exact ID or unambiguous hex prefix and nonce",
        ));
    }
    let binding = engine.binding().map_err(unknown)?;
    if !owner.valid(&binding) {
        return Err(unknown("process owner identity unavailable"));
    }
    let Container::Present { id: cid, .. } = engine.container(input).map_err(unknown)? else {
        return Err(unknown("container absent"));
    };
    if !hex(&cid, 64) || !cid.starts_with(input) {
        return Err(unknown("container prefix retargeted/unverified"));
    }
    let store = Store::open(path, binding.clone(), deadline, cancelled)?;
    let _operation = store.lock(&Store::stripe(&cid), deadline, cancelled)?;
    if engine.binding().map_err(unknown)? != binding {
        return Err(unknown("daemon changed before admission"));
    }
    let actual = observe_container(engine, &cid)?;
    let mut journal = store.read(&cid)?;
    if journal
        .records
        .iter()
        .any(|r| r.phase == Phase::UnknownCreate)
    {
        return Err(unknown(
            "ambiguous Create freezes exact container; charge retained",
        ));
    }
    sweep(&store, &mut journal, engine, deadline)?;
    // No Docker calls inside the short global transaction. Every process sees
    // the fsynced charge before the side-effecting POST can be issued.
    {
        let _global = store.lock("lock", deadline, cancelled)?;
        let all = store.all()?;
        if all
            .iter()
            .any(|j| j.records.iter().any(|r| r.nonce == nonce))
        {
            return Err(unknown("exec nonce already charged"));
        }
        if all.iter().map(|j| j.records.len()).sum::<usize>() >= NODE_RECORDS
            || (!all.iter().any(|j| j.container == cid) && all.len() >= CONTAINERS)
            || journal
                .records
                .len()
                .checked_add(actual.len())
                .and_then(|n| n.checked_add(1))
                .is_none_or(|n| n > PER_CONTAINER)
        {
            return Err(unknown(
                "durable Docker exec metadata guard exhausted; no evidence evicted",
            ));
        }
        journal.records.push(Record {
            nonce: nonce.into(),
            exec: None,
            phase: Phase::UnknownCreate,
            owner: owner.clone(),
            execution: Some(Execution::NoStart),
        });
        store.write(&journal)?;
    }
    if let Err(error) = cancelled() {
        // A control-flow proof of no POST, not a guessed rollback of an
        // ambiguous operation. Failure to persist this leaves the charge.
        let _global = store.lock("lock", deadline, &|| Ok(()))?;
        journal.records.pop();
        if journal.records.is_empty() {
            store.dir.remove(&Store::filename(&cid)).map_err(unknown)?;
        } else {
            store.write(&journal)?;
        }
        return Err(error);
    }
    // Every error from this point leaves UnknownCreate durable. There is no
    // retry, inferred rollback, timeout reset, or nonce-to-ExecInspect.Env join.
    let id = match engine.create(&cid, body) {
        Ok(id) => id,
        Err(CreateFailure::Ambiguous(error)) => return Err(unknown(error)),
        Err(CreateFailure::NotSubmitted(error)) => {
            // The private adapter completed no side-effecting write: failure
            // was in same-connection preflight. This is a control-flow proof,
            // never inferred from timeout/404 after a POST attempt.
            let _global = store.lock("lock", deadline, &|| Ok(()))?;
            if journal.records.last().is_none_or(|r| {
                r.nonce != nonce
                    || r.owner != owner
                    || r.phase != Phase::UnknownCreate
                    || r.exec.is_some()
            }) {
                return Err(unknown("unsubmitted Create intent no longer matches"));
            }
            journal.records.pop();
            if journal.records.is_empty() {
                store.dir.remove(&Store::filename(&cid)).map_err(unknown)?;
            } else {
                store.write(&journal)?;
            }
            return Err(unknown(error));
        }
    };
    if !hex(&id, 64) {
        return Err(unknown("Create receipt has no full exec ID"));
    }
    match engine.exec(&id).map_err(unknown)? {
        Exec::Present {
            id: actual,
            container,
            running: false,
            exit: None,
        } if actual == id && container == cid => {}
        _ => return Err(unknown("new exec receipt association/state unverified")),
    }
    if engine.binding().map_err(unknown)? != binding {
        return Err(unknown("daemon changed after Create"));
    }
    {
        let _global = store.lock("lock", deadline, &|| Ok(()))?;
        if store
            .all()?
            .iter()
            .any(|j| j.records.iter().any(|r| r.exec.as_deref() == Some(&id)))
        {
            return Err(unknown("Create ID duplicated in journal"));
        }
        let record = journal.records.last_mut().unwrap();
        record.exec = Some(id.clone());
        record.phase = Phase::Created;
        store.write(&journal)?;
    }
    Ok(Created {
        container: cid,
        id,
        nonce: nonce.into(),
        binding,
        owner,
    })
}

fn transition(
    path: &Path,
    created: &Created,
    next: Phase,
    deadline: Instant,
) -> Result<(), String> {
    let store = Store::open(path, created.binding.clone(), deadline, &|| Ok(()))?;
    let _operation = store.lock(&Store::stripe(&created.container), deadline, &|| Ok(()))?;
    let _global = store.lock("lock", deadline, &|| Ok(()))?;
    let mut journal = store.read(&created.container)?;
    let r = journal
        .records
        .iter_mut()
        .find(|r| {
            r.nonce == created.nonce
                && r.exec.as_deref() == Some(&created.id)
                && r.owner == created.owner
        })
        .ok_or_else(|| unknown("exec start receipt not in durable journal"))?;
    if r.phase != Phase::Created || !matches!(next, Phase::StartUnknown | Phase::NeverStart) {
        return Err(unknown(
            "exec Start is not one-shot or never-start cancellation is too late",
        ));
    }
    r.phase = next;
    r.execution = Some(if r.phase == Phase::NeverStart {
        Execution::NoStart
    } else {
        Execution::PossibleRunning
    });
    store.write(&journal)
}

/// A synchronous control-flow witness owned by a Receipt that has not handed
/// bytes to the Start transport. Never called after submission or by timeout.
fn abort_before_post(path: &Path, created: &Created, deadline: Instant) -> Result<(), String> {
    let store = Store::open(path, created.binding.clone(), deadline, &|| Ok(()))?;
    let _operation = store.lock(&Store::stripe(&created.container), deadline, &|| Ok(()))?;
    let _global = store.lock("lock", deadline, &|| Ok(()))?;
    let mut journal = store.read(&created.container)?;
    let r = journal
        .records
        .iter_mut()
        .find(|r| {
            r.nonce == created.nonce
                && r.exec.as_deref() == Some(&created.id)
                && r.owner == created.owner
        })
        .ok_or_else(|| unknown("no-post receipt not in durable journal"))?;
    if !matches!(r.phase, Phase::Created | Phase::StartUnknown) {
        return Err(unknown("no-post witness contradicts durable phase"));
    }
    r.phase = Phase::NeverStart;
    r.execution = Some(Execution::NoStart);
    store.write(&journal)
}

pub(crate) use adapter::{create, probe_container, Receipt};
pub(crate) use recovery::{start_node_agent, Agent as RecoveryAgent};
pub(crate) fn recovery_ready() -> bool {
    recovery::ready()
}
pub(crate) fn recovery_usage() -> serde_json::Value {
    recovery::usage()
}
pub use credentials::AdmittedStream;
#[cfg(test)]
#[path = "exec_admission_tests.rs"]
mod tests;
