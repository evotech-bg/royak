//! Inherited local control channel; a private snapshot is identity data only.
//! No parent response, no later fresh program/direct-write boundary.
use crate::storage_identity::Uid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

const LIMIT: usize = 4096;
pub(super) const CONTROL_BUFFER_MAX: usize = LIMIT + 4;
static LIVE: OnceLock<WorkerChannel> = OnceLock::new();

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct JobIdentity {
    pub node_uid: Uid,
    pub boot_id: String,
    pub volume_uid: Uid,
    pub operation_uid: Uid,
    pub attempt_uid: Uid,
    pub binding_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub version: u32,
    pub identity: JobIdentity,
    pub sequence: u64,
    pub nonce: Uid,
    pub boundary: String,
    pub detail_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Response {
    pub version: u32,
    pub sequence: u64,
    pub nonce: Uid,
    pub approved: bool,
}
struct WorkerChannel {
    identity: JobIdentity,
    state: Mutex<(UnixStream, u64)>,
    cgroup: Option<super::job_cgroup::JobCgroup>,
}

pub(super) fn install(
    stream: UnixStream,
    identity: JobIdentity,
    cgroup: super::job_cgroup::JobCgroup,
) -> Result<(), String> {
    verify_local_root_parent(&stream)?;
    install_inner(stream, identity, Some(cgroup))
}
fn verify_local_root_parent(stream: &UnixStream) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
    if unsafe {
        libc::getsockname(
            stream.as_raw_fd(),
            (&mut address as *mut libc::sockaddr_un).cast(),
            &mut length,
        )
    } != 0
        || address.sun_family as i32 != libc::AF_UNIX
    {
        return Err("storage issuer channel must be inherited local Unix socket".into());
    }
    #[cfg(target_os = "linux")]
    {
        let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of_val(&peer) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut peer as *mut libc::ucred).cast(),
                &mut size,
            )
        } != 0
            || peer.uid != 0
            || peer.pid != unsafe { libc::getppid() }
        {
            return Err("storage issuer channel is not the root launching parent".into());
        }
    }
    Ok(())
}
/// Readonly primitive shared with profile7; no terminal permission/checker.
pub(super) fn verify_owned_inventory_parent_channel(stream:&UnixStream)->Result<(),String>{verify_local_root_parent(stream)}
pub(super) fn owned_inventory_parent_identity()->Result<(u32,i32),String>{
    #[cfg(not(target_os="linux"))]{Err("profile7 inherited launching peer requires Linux".into())}
    #[cfg(target_os="linux")]{use std::os::fd::AsRawFd;
        let channel=LIVE.get().ok_or("actual profile7 inherited channel absent")?;
        let guard=channel.state.lock().map_err(|_|"actual profile7 channel poisoned")?;verify_local_root_parent(&guard.0)?;
        let mut peer:libc::ucred=unsafe{std::mem::zeroed()};let mut size=std::mem::size_of_val(&peer)as libc::socklen_t;
        if unsafe{libc::getsockopt(guard.0.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,(&mut peer as *mut libc::ucred).cast(),&mut size)}!=0
            ||size as usize!=std::mem::size_of_val(&peer)||peer.pid<=0{return Err("actual profile7 launching peer unavailable".into());}
        Ok((u32::try_from(peer.pid).map_err(|_|"profile7 peer PID overflow")?,guard.0.as_raw_fd()))
    }
}
pub(super) fn require_owned_inventory_installed()->Result<(),String>{
    if !LIVE.get().is_some_and(|v|v.cgroup.is_some()){return Err("profile7 needs actual inherited containment/channel".into());}
    request("helper-start",b"native-owned-mounted-inventory-attachment-v7")
}
pub(super) fn before_owned_inventory(identity:&JobIdentity,boundary:&str,detail:&[u8])->Result<(),String>{
    attachment_channel_identity(identity)?;
    if !matches!(boundary,"owned-inventory-pvs"|"owned-inventory-vgs"|"owned-inventory-lvs"|"owned-inventory-lsblk"|"owned-inventory-kernel-census"){
        return Err("not a closed profile7 inventory observation".into());}
    request(boundary,detail)?;attachment_channel_identity(identity)
}
pub(super) fn owned_inventory_cgroup_current(identity:&JobIdentity,expected:(u64,u64),budget:&super::ResourceBudget)->Result<(),String>{
    let channel=LIVE.get().ok_or("actual profile7 channel absent")?;
    if &channel.identity!=identity{return Err("profile7 actual current native identity differs".into());}
    let cgroup=channel.cgroup.as_ref().ok_or("profile7 same inherited original cgroup absent")?;
    if cgroup.identity()?!=expected||!cgroup.contains(std::process::id())?{
        return Err("actual profile7 original cgroup/current membership differs".into());}
    cgroup.resource_snapshot(budget)?;
    if cgroup.identity()?!=expected||!cgroup.contains(std::process::id())?{
        return Err("profile7 original cgroup changed during current controls observation".into());}Ok(())
}
pub(super) fn verify_terminal_parent_channel(stream:&UnixStream)->Result<(),String>{
    verify_local_root_parent(stream)
}
pub(super) fn terminal_parent_identity()->Result<(u32,i32),String>{
    #[cfg(not(target_os="linux"))]{Err("actual terminal launching peer needs Linux".into())}
    #[cfg(target_os="linux")]{
        use std::os::fd::AsRawFd;
        let live=LIVE.get().ok_or("actual inherited terminal channel absent")?;
        let guard=live.state.lock().map_err(|_|"actual terminal channel poisoned")?;
        verify_local_root_parent(&guard.0)?;
        let mut peer:libc::ucred=unsafe{std::mem::zeroed()};let mut size=std::mem::size_of_val(&peer)as libc::socklen_t;
        if unsafe{libc::getsockopt(guard.0.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),&mut size)}!=0||size as usize!=std::mem::size_of_val(&peer)||peer.pid<=0{
            return Err("actual original root peer identity unavailable".into());}
        Ok((u32::try_from(peer.pid).map_err(|_|"actual root peer PID overflow")?,guard.0.as_raw_fd()))
    }
}
#[cfg(test)]
pub(super) fn install_fixture(stream: UnixStream, identity: JobIdentity) -> Result<(), String> {
    install_inner(stream, identity, None)
}
fn install_inner(
    stream: UnixStream,
    identity: JobIdentity,
    cgroup: Option<super::job_cgroup::JobCgroup>,
) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    // Do not pass the live grant channel through exec into LVM/DRBD programs.
    let fd = stream.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err("cannot confine inherited live-approval channel".into());
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "cannot bound live approval read")?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| "cannot bound live approval write")?;
    LIVE.set(WorkerChannel {
        identity,
        state: Mutex::new((stream, 0)),
        cgroup,
    })
    .map_err(|_| "live storage authority already installed".into())
}

fn request(boundary: &str, detail: &[u8]) -> Result<(), String> {
    let Some(live) = LIVE.get() else {
        return Ok(());
    }; // explicit legacy operator primitive only
    let mut guard = live
        .state
        .lock()
        .map_err(|_| "live storage authority poisoned")?;
    guard.1 = guard
        .1
        .checked_add(1)
        .ok_or("storage approval sequence exhausted")?;
    let req = Request {
        version: 1,
        identity: live.identity.clone(),
        sequence: guard.1,
        nonce: Uid::new(),
        boundary: boundary.into(),
        detail_sha256: format!("{:x}", Sha256::digest(detail)),
    };
    write_frame(&mut guard.0, &req)?;
    let response: Response = read_frame(&mut guard.0)?;
    if response.version != 1
        || response.sequence != req.sequence
        || response.nonce != req.nonce
        || !response.approved
    {
        return Err(
            "current issuer denied/mismatched storage mutation; outcome UNKNOWN, no new action"
                .into(),
        );
    }
    Ok(())
}

pub(super) fn require_installed() -> Result<(), String> {
    if !LIVE.get().is_some_and(|v| v.cgroup.is_some()) {
        return Err("native helper requires live inherited issuer approval".into());
    }
    request("helper-start", b"native-secondary-only")
}
pub(super) fn require_cold_installed() -> Result<(), String> {
    if !LIVE.get().is_some_and(|v| v.cgroup.is_some()) {
        return Err("cold helper requires exact inherited parent and kernel containment".into());
    }
    request("helper-start", b"native-virgin-offline-only-v2")
}
pub(super) fn require_initialization_installed() -> Result<(), String> {
    if !LIVE.get().is_some_and(|v| v.cgroup.is_some()) {
        return Err(
            "initializer requires exact inherited live parent and kernel containment".into(),
        );
    }
    request("helper-start", b"native-initialize-new-only-v2")
}
pub(super) fn require_distributed_initialization_installed() -> Result<(), String> {
    if !LIVE.get().is_some_and(|value| value.cgroup.is_some()) {
        return Err(
            "distributed initialization requires inherited root parent and actual cgroup".into(),
        );
    }
    request("helper-start", b"native-distributed-init-phase-v4")
}
pub(super) fn require_attachment_installed()->Result<(),String> {
    if !LIVE.get().is_some_and(|value|value.cgroup.is_some()) {
        return Err("attach requires inherited root parent and actual kernel containment".into());
    }
    request("helper-start",b"native-first-attachment-v5")
}
/// Necessary local inherited-context comparison only; NEVER a fresh grant.
/// Attach direct reads immediately follow this with their exact fresh Read
/// request, then the caller performs a fresh post-read Identity boundary.
pub(super) fn attachment_channel_identity(identity:&JobIdentity)->Result<(),String> {
    if !LIVE.get().is_some_and(|v|v.cgroup.is_some() && &v.identity==identity) {
        return Err("attach read lacks exact inherited private channel/kernel context".into());
    }Ok(())
}
pub(super) fn before_attachment_read(scope:&crate::storage_lifecycle::pod_attachment::ExpectedAttachScope,
    offset:u64,length:u64)->Result<(),String> {
    request("attachment-read",&serde_json::to_vec(&("first-attach-read-v5",&scope.owner.volume_uid,
        &scope.generation.uid,scope.phase,offset,length)).map_err(|_|"cannot bind attach read")?)
}
pub(super) fn before_attachment_anchor(scope:&crate::storage_lifecycle::pod_attachment::ExpectedAttachScope,
    operation:&str,identity:Option<(u64,u64,u64)>)->Result<(),String> {
    let boundary=match operation {"create-empty-directory"|"bind-self"=>"attachment-anchor-bind",
        "make-private"=>"attachment-anchor-private",_=>return Err("unknown fixed anchor operation".into())};
    request(boundary,&serde_json::to_vec(&("fixed-owned-anchor-v5",scope,operation,
        "/var/lib/royak/storage/mounts",identity)).map_err(|_|"cannot bind anchor syscall")?)
}
pub(super) fn before_attachment_mount(scope:&crate::storage_lifecycle::pod_attachment::ExpectedAttachScope,
    operation:&str,detail:&impl Serialize)->Result<(),String> {
    let boundary=match operation {"mount-ext4"=>"attachment-mount-ext4","make-private"=>"attachment-make-private",
        _=>return Err("unknown fixed attachment syscall".into())};
    request(boundary,&serde_json::to_vec(&("exact-managed-mount-v5",scope,operation,detail))
        .map_err(|_|"cannot bind mount syscall")?)
}
pub(super) fn before_initialization_read(
    volume: &Uid,
    generation: &Uid,
    phase: &crate::storage_lifecycle::generation::physical::InitPhase,
    offset: u64,
    length: u64,
) -> Result<(), String> {
    request(
        "initialization-read",
        &serde_json::to_vec(&(volume, generation, phase, offset, length))
            .map_err(|_| "cannot bind exact initialization read extent")?,
    )
}
/// Actual positive terminal acknowledgement from SAME inherited parent. No
/// serde/raw/default/Clone constructor; not a cross-process capability.
pub(super) struct TerminalRequestReceipt {request:Request}
impl TerminalRequestReceipt {
    pub(super) fn request_sha256(&self)->Result<String,String>{
        Ok(format!("{:x}",Sha256::digest(serde_json::to_vec(&self.request).map_err(|_|"terminal sent request encoding failed")?)))
    }
    pub(super) fn record_result(self,kind:super::native_runtime::mount::consumer::terminal::TerminalBoundary,
        result_sha256:&str)->Result<(),String>{
        if result_sha256.len()!=64||!result_sha256.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){
            return Err("terminal result is not an exact full hash".into());}
        terminal_channel_identity(&self.request.identity)?;
        let approved=self.request_sha256()?;
        let code=terminal_boundary_code(kind);
        let detail=serde_json::to_vec(&("managed-terminal-result-v1",code,&approved,result_sha256))
            .map_err(|_|"terminal actual result binding encode failed")?;
        let name=format!("terminal-result/{code}/{approved}/{result_sha256}");
        // This is DATA outcome of the exact previously approved request, never
        // another effect permission. Parent rejects absent/duplicate pending.
        terminal_request_inner(&name,&detail).map(|_|())
    }
}
pub(super) fn terminal_boundary_code(kind:super::native_runtime::mount::consumer::terminal::TerminalBoundary)->u8{
    use super::native_runtime::mount::consumer::terminal::TerminalBoundary::*;
    match kind{Start=>0,Identity=>1,Program=>2,Read=>3,FlushMount=>4,CloseMounted=>5,Unmount=>6,
        CloseBlock=>7,Demote=>8,ObserveSecondary=>9,Offline=>10,CloseRead=>11,Complete=>12,RetireLease=>13}
}
pub(super) fn terminal_channel_identity(identity:&JobIdentity)->Result<(),String>{
    if !LIVE.get().is_some_and(|v|v.cgroup.is_some()&&&v.identity==identity){
        return Err("terminal worker lacks exact inherited original channel/cgroup identity".into());}Ok(())
}
pub(super) fn require_terminal_installed()->Result<(),String>{
    if !LIVE.get().is_some_and(|v|v.cgroup.is_some()){return Err("managed terminal requires actual inherited cgroup authority".into());}
    request("helper-start",b"native-managed-terminal-v1")
}
pub(super) fn terminal_request(kind:super::native_runtime::mount::consumer::terminal::TerminalBoundary,
    detail:&[u8])->Result<TerminalRequestReceipt,String>{
    use super::native_runtime::mount::consumer::terminal::TerminalBoundary::*;
    let name=match kind{Identity=>"terminal-identity",Read=>"terminal-read",FlushMount=>"terminal-flush",
        CloseMounted=>"terminal-close-mounted",Unmount=>"terminal-unmount",CloseBlock=>"terminal-close-block",
        Demote=>"terminal-demote",ObserveSecondary=>"terminal-observe-secondary",Offline=>"terminal-offline",
        CloseRead=>"terminal-close-read",_=>return Err("terminal child cannot request this parent-only purpose".into())};
    terminal_request_inner(name,detail)
}
pub(super) fn terminal_reference_begin(point:u8,detail:&[u8])->Result<TerminalRequestReceipt,String>{
    if point>1{return Err("closed reference census point invalid".into());}
    terminal_request_inner(&format!("terminal-reference-census-begin/{point}"),detail)
}
pub(super) fn terminal_reference_end(point:u8,begin:&str,outcome:&str,detail:&[u8])->Result<TerminalRequestReceipt,String>{
    let valid=|v:&str|v.len()==64&&v.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b));
    if point>1||!valid(begin)||!valid(outcome){return Err("closed reference census completion binding invalid".into());}
    terminal_request_inner(&format!("terminal-reference-census-end/{point}/{begin}/{outcome}"),detail)
}
fn terminal_request_inner(name:&str,detail:&[u8])->Result<TerminalRequestReceipt,String>{
    let live=LIVE.get().filter(|v|v.cgroup.is_some()).ok_or("no original terminal parent channel")?;
    if name.len()>256||detail.len()>16*1024{return Err("terminal closed subframe exceeds unchanged frame bound".into());}
    let mut guard=live.state.lock().map_err(|_|"original terminal channel poisoned")?;
    guard.1=guard.1.checked_add(1).ok_or("terminal sequence exhausted")?;
    let request=Request{version:1,identity:live.identity.clone(),sequence:guard.1,nonce:Uid::new(),boundary:name.into(),
        detail_sha256:format!("{:x}",Sha256::digest(detail))};
    write_frame(&mut guard.0,&request)?;
    let response:Response=read_frame(&mut guard.0)?;
    if response.version!=1||response.sequence!=request.sequence||response.nonce!=request.nonce||!response.approved{
        return Err("terminal original request denied/lost/changed; UNKNOWN, no retry".into());}
    Ok(TerminalRequestReceipt{request})
}

pub(super) fn installed() -> bool {
    LIVE.get().is_some()
}
pub(super) fn require_identity(identity: &JobIdentity) -> Result<(), String> {
    if !LIVE
        .get()
        .is_some_and(|v| v.cgroup.is_some() && &v.identity == identity)
    {
        return Err("physical native agent requires exact opaque verified-worker context".into());
    }
    request("identity-check", b"verified-worker-context")
}
pub(super) fn checkpoint() -> Result<(), String> {
    request("identity-check", b"current-local-issuer")
}
pub(super) fn before_program(
    program: &str,
    args: &[String],
) -> Result<Option<super::job_cgroup::JobCgroup>, String> {
    let bytes =
        serde_json::to_vec(&(program, args)).map_err(|_| "cannot bind fixed storage command")?;
    request("fixed-program", &bytes)?;
    match LIVE.get() {
        None => Ok(None),
        Some(live) => Ok(Some(
            live.cgroup
                .as_ref()
                .ok_or("live helper lacks required kernel command containment")?
                .command_scope(Uid::new().as_str())?,
        )),
    }
}
pub(super) fn before_block_write(volume: &Uid, offset: u64, length: u64) -> Result<(), String> {
    request(
        "zero-write",
        &serde_json::to_vec(&(volume, offset, length)).map_err(|_| "cannot bind zero extent")?,
    )
}
pub(super) fn before_block_fsync(volume: &Uid) -> Result<(), String> {
    request("zero-fsync", volume.as_str().as_bytes())
}

pub(super) fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|_| "cannot encode storage approval frame")?;
    if bytes.is_empty() || bytes.len() > LIMIT {
        return Err("storage approval frame exceeds bound".into());
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(&bytes))
        .map_err(|_| {
            "issuer control channel lost; outcome UNKNOWN, no later mutation permitted".into()
        })
}
pub(super) fn read_frame<T: for<'d> Deserialize<'d>>(stream: &mut UnixStream) -> Result<T, String> {
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| "issuer control channel lost; no later mutation permitted")?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > LIMIT {
        return Err("invalid storage approval frame size".into());
    }
    let mut bytes = vec![0; size];
    stream
        .read_exact(&mut bytes)
        .map_err(|_| "issuer control channel interrupted")?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid storage approval frame".into())
}

pub(super) fn append_control(
    buffer: &mut Vec<u8>,
    pending: bool,
    bytes: &[u8],
) -> Result<(), String> {
    if bytes.is_empty() {
        return Ok(());
    }
    if pending {
        return Err("pipelined bytes while approval is pending; no extra data admitted".into());
    }
    let length = buffer
        .len()
        .checked_add(bytes.len())
        .filter(|n| *n <= CONTROL_BUFFER_MAX)
        .ok_or("storage approval control buffer exceeded hard bound")?;
    // Check BEFORE extend, irrespective of decode/pending state.
    if buffer.len() >= 4 {
        let expected = u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize;
        if expected == 0 || expected > LIMIT || length > expected + 4 {
            return Err("pipelined/oversized control frame refused before append".into());
        }
    }
    buffer.extend_from_slice(bytes);
    Ok(())
}
pub(super) fn decode_pending(buffer: &mut Vec<u8>) -> Result<Option<Request>, String> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let size = u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize;
    if size == 0 || size > LIMIT || buffer.len() > LIMIT + 4 {
        return Err("bounded approval channel violated".into());
    }
    if buffer.len() < size + 4 {
        return Ok(None);
    }
    if buffer.len() != size + 4 {
        return Err("only one outstanding approval is permitted".into());
    }
    let request = serde_json::from_slice(&buffer[4..]).map_err(|_| "malformed approval request")?;
    buffer.clear();
    Ok(Some(request))
}

/// Parent callback uses the ACTUAL live world and current issuer authority.
/// None means transient lock contention, not permission from a frozen clone.
pub(super) fn parent_approval(
    request: &Request,
    expected: &JobIdentity,
    intent: &crate::storage_controller::ProvisionIntent,
    world: &std::sync::Arc<std::sync::RwLock<crate::reconcile::DesiredWorld>>,
) -> Result<Option<bool>, String> {
    if request.version != 1
        || &request.identity != expected
        || ![
            "helper-start",
            "identity-check",
            "fixed-program",
            "zero-write",
            "zero-fsync",
        ]
        .contains(&request.boundary.as_str())
        || request.detail_sha256.len() != 64
        || !request
            .detail_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || expected.volume_uid != intent.owner().volume_uid
        || expected.operation_uid != *intent.operation_uid()
        || !intent
            .targets()
            .iter()
            .any(|t| t.node_uid == expected.node_uid && t.boot_id.as_str() == expected.boot_id)
    {
        return Err("storage approval binding/boundary mismatch".into());
    }
    let authoritative = if crate::raft_node::is_clustered() {
        crate::raft_node::is_cluster_scheduler()
    } else {
        crate::store::owns_state()
    };
    if !authoritative {
        return Ok(Some(false));
    }
    let guard = match world.try_read() {
        Ok(w) => w,
        Err(std::sync::TryLockError::WouldBlock) => return Ok(None),
        Err(_) => return Err("live committed world poisoned".into()),
    };
    let current = guard
        .storage_identities
        .lifecycle
        .get(&request.identity.volume_uid);
    let valid = current.is_some_and(|v| intent.matches(v))
        && guard.cluster_id == intent.owner().cluster_id
        && request.identity.operation_uid == *intent.operation_uid();
    // The full identity graph was validated at commit; owner UID/operation/
    // boots cannot change inside Provisioning. We do not authorize a follower.
    Ok(Some(valid))
}

#[cfg(test)]
mod buffer_tests {
    use super::*;
    #[test]
    fn unconditional_append_bound_rejects_pipeline_and_oversize_without_allocation_growth() {
        let mut buffer = Vec::with_capacity(CONTROL_BUFFER_MAX);
        let capacity = buffer.capacity();
        let chunk = [1u8; 4096];
        for _ in 0..1000 {
            assert!(append_control(&mut buffer, true, &chunk).is_err());
        }
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.capacity(), capacity);
        assert!(append_control(&mut buffer, false, &vec![0; CONTROL_BUFFER_MAX + 1]).is_err());
        assert_eq!(buffer.capacity(), capacity);
        assert!(buffer.is_empty());
        append_control(&mut buffer, false, &1u32.to_be_bytes()).unwrap();
        assert!(append_control(&mut buffer, false, b"too many bytes").is_err());
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.capacity(), capacity);
    }
}
