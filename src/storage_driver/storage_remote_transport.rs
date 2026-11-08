//! Dedicated socket/WireGuard identity adapter for the opt-in cold runtime.
//! Cluster HMAC alone does not identify a member: compare actual socket IPs,
//! kernel WireGuard type/local key and exact disjoint peer /32 AllowedIPs.
use super::process::{self, Program};
use crate::storage_identity::Uid;
use crate::storage_remote_protocol::{self as protocol, VerifiedDirectory, VerifiedPeerFrame};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct BoundListener {
    socket: tokio::net::TcpListener,
    interface: String,
    ifindex: u32,
    local: Uid,
    directory_sha256: String,
    slots: Arc<tokio::sync::Semaphore>,
}
/// Only an explicit private infrastructure configuration may start this
/// listener; there is no public API or plaintext listener fallback.
pub(crate) struct DeviceBoundStorageListener {
    inner: Arc<BoundListener>,
}
/// Only accept() below constructs this token; actual socket IPs alone, an API
/// PeerTransport, forwarded headers or user-supplied interface cannot make it.
pub(crate) struct AcceptedStorageContext {
    listener: Arc<BoundListener>,
    local: std::net::SocketAddr,
    remote: std::net::SocketAddr,
    _slot: tokio::sync::OwnedSemaphorePermit,
    accepted: std::net::TcpStream,
}
fn binding_matches(
    expected: &str,
    actual: &str,
    expected_index: u32,
    current_index: u32,
) -> Result<(), String> {
    if expected.is_empty()
        || expected != actual
        || expected_index == 0
        || expected_index != current_index
    {
        return Err("accepted storage flow lacks exact device-bound listener context".into());
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn kernel_binding(fd: std::os::fd::RawFd, interface: &str, index: u32) -> Result<(), String> {
    let mut name = [0u8; libc::IFNAMSIZ];
    let mut length = name.len() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_mut_ptr().cast(),
            &mut length,
        )
    } != 0
        || length == 0
        || length as usize > name.len()
    {
        return Err("cannot verify storage listener kernel device binding".into());
    }
    let end = name
        .iter()
        .position(|v| *v == 0)
        .ok_or("unterminated kernel device binding")?;
    let actual = std::str::from_utf8(&name[..end]).map_err(|_| "invalid kernel device binding")?;
    let cname = std::ffi::CString::new(interface).map_err(|_| "invalid storage interface")?;
    binding_matches(interface, actual, index, unsafe {
        libc::if_nametoindex(cname.as_ptr())
    })
}
#[cfg(not(target_os = "linux"))]
fn kernel_binding(_: std::os::fd::RawFd, _: &str, _: u32) -> Result<(), String> {
    Err("device-bound storage listener requires Linux".into())
}
impl DeviceBoundStorageListener {
    pub(crate) fn bind(
        directory: &VerifiedDirectory,
        local: &Uid,
        interface: &str,
        port: u16,
    ) -> Result<Self, String> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (directory, local, interface, port);
            Err("device-bound storage listener requires Linux".into())
        }
        #[cfg(target_os = "linux")]
        {
            if unsafe { libc::geteuid() } != 0 || port == 0 || !interface_name(interface) {
                return Err("invalid private storage listener policy".into());
            }
            inspect(directory, local, interface)?;
            let name = std::ffi::CString::new(interface).map_err(|_| "invalid interface")?;
            let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
            if index == 0 {
                return Err("WireGuard interface missing".into());
            }
            let socket = tokio::net::TcpSocket::new_v4()
                .map_err(|_| "cannot allocate bounded storage listener")?;
            if unsafe {
                libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_BINDTODEVICE,
                    name.as_ptr().cast(),
                    name.as_bytes_with_nul().len() as libc::socklen_t,
                )
            } != 0
            {
                return Err("cannot bind storage listener to WireGuard device".into());
            }
            socket
                .bind(std::net::SocketAddr::new(
                    IpAddr::V4(directory.pin(local)?.wireguard_ip),
                    port,
                ))
                .map_err(|_| "cannot bind exact private storage address")?;
            let socket = socket
                .listen(32)
                .map_err(|_| "cannot listen on exact private storage interface")?;
            kernel_binding(socket.as_raw_fd(), interface, index)?;
            Ok(Self {
                inner: Arc::new(BoundListener {
                    socket,
                    interface: interface.into(),
                    ifindex: index,
                    local: local.clone(),
                    directory_sha256: directory.digest().into(),
                    slots: Arc::new(tokio::sync::Semaphore::new(32)),
                }),
            })
        }
    }
    pub(crate) async fn accept(
        &self,
    ) -> Result<(tokio::net::TcpStream, AcceptedStorageContext), String> {
        let slot = self
            .inner
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "bounded storage listener closed")?;
        kernel_binding(
            self.inner.socket.as_raw_fd(),
            &self.inner.interface,
            self.inner.ifindex,
        )?;
        let (socket, remote) = self
            .inner
            .socket
            .accept()
            .await
            .map_err(|_| "storage accept failed")?;
        kernel_binding(
            self.inner.socket.as_raw_fd(),
            &self.inner.interface,
            self.inner.ifindex,
        )?;
        let local = socket
            .local_addr()
            .map_err(|_| "accepted storage endpoint unavailable")?;
        use std::os::fd::FromRawFd;
        let duplicated=unsafe {libc::fcntl(socket.as_raw_fd(),libc::F_DUPFD_CLOEXEC,3)};
        if duplicated<0 {return Err("cannot pin accepted storage socket".into());}
        let accepted=unsafe {std::net::TcpStream::from_raw_fd(duplicated)};
        kernel_binding(accepted.as_raw_fd(),&self.inner.interface,self.inner.ifindex)?;
        Ok((
            socket,
            AcceptedStorageContext {
                listener: self.inner.clone(),
                local,
                remote,
                _slot: slot,
                accepted,
            },
        ))
    }
}
impl AcceptedStorageContext {
    fn validate<'a>(
        &'a self,
        directory: &VerifiedDirectory,
    ) -> Result<(&'a str, &'a Uid, IpAddr, IpAddr), String> {
        kernel_binding(
            self.listener.socket.as_raw_fd(),
            &self.listener.interface,
            self.listener.ifindex,
        )?;
        kernel_binding(self.accepted.as_raw_fd(),&self.listener.interface,self.listener.ifindex)?;
        if self.accepted.local_addr().map_err(|_|"accepted local endpoint lost")?!=self.local ||
            self.accepted.peer_addr().map_err(|_|"accepted remote endpoint lost")?!=self.remote {
            return Err("accepted storage endpoints changed".into());
        }
        if self.listener.directory_sha256 != directory.digest()
            || self.local.ip() != IpAddr::V4(directory.pin(&self.listener.local)?.wireguard_ip)
        {
            return Err("accepted storage context directory/local identity changed".into());
        }
        Ok((
            &self.listener.interface,
            &self.listener.local,
            self.remote.ip(),
            self.local.ip(),
        ))
    }
}

pub(crate) struct VerifiedStorageTransport {
    sender: Uid,
    receiver: Uid,
    observed: Instant,
}
pub(super) fn supported_route(path:&str)->bool {
    [protocol::GRANT_PATH,protocol::BOUNDARY_PATH,protocol::NODE_JOB_PATH,
        protocol::attachment::PATH,protocol::attachment::OFFER_PATH,protocol::attachment::MOUNTED_PATH,
        super::native_runtime::mount::consumer::terminal::PATH].contains(&path)
}
impl VerifiedStorageTransport {
    pub(crate) fn consume(self) -> Result<(Uid, Uid), String> {
        if self.observed.elapsed() > Duration::from_secs(2) {
            return Err("storage transport observation expired".into());
        }
        Ok((self.sender, self.receiver))
    }
}
fn interface_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() < 16
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
fn output(program: Program, args: &[&str]) -> Result<Vec<u8>, String> {
    process::run(
        program,
        &args.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    )?
    .success("read-only storage transport observation")
}

/// This pure parser produces no proof; only inspect() below calls it on actual
/// fixed-program output. Never call wg dump/showconf (would expose private key).
fn validate_allowed_ips(
    raw: &str,
    directory: &VerifiedDirectory,
    local: &Uid,
) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for line in raw.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() != 2 || fields[1].contains(',') || !seen.insert(fields[0]) {
            return Err("ambiguous storage WireGuard peer map".into());
        }
        let pin = directory
            .dto_nodes()
            .iter()
            .find(|p| &p.node_uid != local && p.wireguard_key == fields[0])
            .ok_or("foreign/unregistered WireGuard peer")?;
        if fields[1] != format!("{}/32", pin.wireguard_ip) {
            return Err("storage WireGuard AllowedIPs permits spoofing or another address".into());
        }
    }
    if seen.len() + 1 != directory.dto_nodes().len() {
        return Err("storage WireGuard member set is incomplete".into());
    }
    Ok(())
}
fn inspect(directory: &VerifiedDirectory, local: &Uid, interface: &str) -> Result<String, String> {
    if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 || !interface_name(interface) {
        return Err("storage peer validation requires configured Linux root WireGuard".into());
    }
    let pin = directory.pin(local)?;
    let link: serde_json::Value = serde_json::from_slice(&output(
        Program::Ip,
        &["-j", "-d", "link", "show", "dev", interface],
    )?)
    .map_err(|_| "invalid WireGuard link observation")?;
    let entries = link
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("ambiguous WireGuard link")?;
    if entries[0]["linkinfo"]["info_kind"] != "wireguard"
        || !entries[0]["flags"]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v == "UP"))
    {
        return Err("storage transport is not an active kernel WireGuard interface".into());
    }
    let addresses: serde_json::Value = serde_json::from_slice(&output(
        Program::Ip,
        &["-j", "address", "show", "dev", interface],
    )?)
    .map_err(|_| "invalid WireGuard address observation")?;
    let entries = addresses
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("ambiguous WireGuard address interface")?;
    let ips = entries[0]["addr_info"]
        .as_array()
        .ok_or("WireGuard address set missing")?
        .iter()
        .filter(|v| v["family"] == "inet")
        .map(|v| v["local"].as_str().ok_or("invalid local WireGuard address"))
        .collect::<Result<Vec<_>, _>>()?;
    if ips.len() != 1 || ips[0] != pin.wireguard_ip.to_string() {
        return Err("storage interface must have exactly its pinned local IPv4 address".into());
    }
    let key = String::from_utf8(output(
        Program::Wireguard,
        &["show", interface, "public-key"],
    )?)
    .map_err(|_| "invalid public WireGuard key")?;
    if key.trim_end() != pin.wireguard_key {
        return Err("local WireGuard public key differs from registered node UID".into());
    }
    let allowed = String::from_utf8(output(
        Program::Wireguard,
        &["show", interface, "allowed-ips"],
    )?)
    .map_err(|_| "invalid public WireGuard peer map")?;
    validate_allowed_ips(&allowed, directory, local)?;
    Ok(protocol::hash(allowed.as_bytes()))
}

/// Requires context minted by the actual device-bound acceptor, not merely
/// matching socket IPs or a caller-provided interface/PeerTransport object.
pub(crate) fn inbound(
    method: &str,
    path: &str,
    headers: impl Fn(&str) -> Option<String>,
    wire: &[u8],
    socket: &AcceptedStorageContext,
    directory: &VerifiedDirectory,
) -> Result<VerifiedPeerFrame, String> {
    if method != "POST"
        || !supported_route(path)
        || wire.len() > 96 * 1024
    {
        return Err("invalid bounded private storage node request".into());
    }
    let (interface, local, remote_ip, local_ip) = socket.validate(directory)?;
    let signer = crate::auth::verify_node(method, path, headers, wire)?;
    let sender = directory.signer(&signer)?;
    let receiver = directory.pin(local)?;
    if sender.node_uid == *local
        || remote_ip != IpAddr::V4(sender.wireguard_ip)
        || local_ip != IpAddr::V4(receiver.wireguard_ip)
    {
        return Err(
            "storage signature did not arrive from its pinned WireGuard node/socket".into(),
        );
    }
    let before = inspect(directory, local, interface)?;
    let opened = crate::node_rpc::open_body(wire)?;
    let plain = protocol::open_protocol_frame(&opened)?;
    if inspect(directory, local, interface)? != before {
        return Err("WireGuard identity map changed across storage verification".into());
    }
    VerifiedPeerFrame::from_transport(
        VerifiedStorageTransport {
            sender: sender.node_uid.clone(),
            receiver: local.clone(),
            observed: Instant::now(),
        },
        plain,
    )
}

/// Existing response HMAC binds nonce/status; the numeric pinned peer and
/// SO_BINDTODEVICE bind transport. Inspection uses the fixed runtime worker.
pub(crate) async fn call(
    path: &str,
    plain: &[u8],
    interface: &str,
    local: &Uid,
    peer: &Uid,
    port: u16,
    directory: &VerifiedDirectory,
) -> Result<VerifiedPeerFrame, String> {
    if !supported_route(path)
        || port == 0
        || peer == local
    {
        return Err("invalid storage peer route".into());
    }
    let sender = directory.pin(local)?;
    let receiver = directory.pin(peer)?;
    if crate::store::node_name() != sender.signer_name {
        return Err("local node RPC signer differs from registered storage UID".into());
    }
    let before = super::native_runtime::inspect_transport(directory.clone(),local.clone(),interface.to_owned()).await?;
    let body = protocol::seal_protocol_frame(plain)?;
    let address = format!("{}:{port}", receiver.wireguard_ip);
    let sealed = crate::node_rpc::call_async_bound(
        "POST",
        &address,
        path,
        &body,
        Duration::from_secs(2),
        Some(interface),
    )
    .await?;
    let response = protocol::open_protocol_frame(&sealed)?;
    if super::native_runtime::inspect_transport(directory.clone(),local.clone(),interface.to_owned()).await? != before {
        return Err("WireGuard identity map changed across storage RPC".into());
    }
    VerifiedPeerFrame::from_transport(
        VerifiedStorageTransport {
            sender: peer.clone(),
            receiver: local.clone(),
            observed: Instant::now(),
        },
        response,
    )
}

#[cfg(test)]
pub(crate) fn allowed_ips_model(
    raw: &str,
    directory: &VerifiedDirectory,
    local: &Uid,
) -> Result<(), String> {
    validate_allowed_ips(raw, directory, local)
}
#[cfg(test)]
pub(crate) fn bound_listener_model(
    expected: &str,
    actual: &str,
    index: u32,
    current: u32,
) -> Result<(), String> {
    binding_matches(expected, actual, index, current)
}

pub(super) fn inspect_runtime(directory:&VerifiedDirectory,local:&Uid,interface:&str)->Result<String,String> {
    inspect(directory,local,interface)
}

#[cfg(test)]
mod normal_routes {
    #[test]
    fn actual_closed_transport_predicate_accepts_only_new_attach_purposes_and_offer_routes(){
        for path in [protocol::attachment::PATH,protocol::attachment::OFFER_PATH,protocol::attachment::MOUNTED_PATH]{assert!(supported_route(path));}
        for path in ["/royak/v1/storage/node/attach/", "/royak/v1/storage/node/attach/init", "/royak/v1/storage/node/mounted-commit/extra", "/api/v1/pods", "/royak/v1/storage/node/restore"]{assert!(!supported_route(path));}
    }
    use super::*;
    #[test]
    fn both_actual_transport_guards_share_the_closed_node_job_route() {
        for path in [protocol::GRANT_PATH,protocol::BOUNDARY_PATH,protocol::NODE_JOB_PATH] {assert!(supported_route(path));}
        for path in ["/api/v1/pods","/royak/v1/storage/node/init","/royak/v1/storage/node/job?x=1","/","/royak/v1/storage/node/offer"] {
            assert!(!supported_route(path));
        }
    }
}
