//! Root-private durable local identity. A file/JSON pin is data until the real
//! Raft ID, current kernel WG key/IP/interface and committed directory agree.
use super::{
    private_fs::{self, Dir},
    process::{self, Program},
};
use crate::storage_boot::BootId;
use crate::storage_node_directory::{self as directory, DirectoryDto, NodePin, Registry};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc, Mutex, OnceLock,
};
use std::time::{Duration, Instant};
const MAX_AGE: Duration =
    Duration::from_millis(crate::raft_node::storage_remote_core::MAX_STORAGE_BOUNDARY_MS);
static LOCAL: OnceLock<Source> = OnceLock::new();
static CONFIGURE: Mutex<()> = Mutex::new(());
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalFile {
    version: u32,
    cluster_id: String,
    pin: NodePin,
    interface: String,
}
struct Source {
    path: PathBuf,
    sha256: String,
    queue: mpsc::SyncSender<Inspection>,
    busy: Arc<AtomicBool>,
    runtime_raft_id: u64,
}
struct Budget {
    started: Instant,
    cancelled: AtomicBool,
}
impl Budget {
    fn check(&self) -> Result<(), String> {
        if self.cancelled.load(Ordering::Acquire) || self.started.elapsed() >= MAX_AGE {
            return Err("identity inspection cancelled/expired; no new read program".into());
        }
        Ok(())
    }
}
struct Cancel(Arc<Budget>);
impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
    }
}
enum Reply {
    Sync(mpsc::SyncSender<Result<LocalObservation, String>>),
    Async(tokio::sync::oneshot::Sender<Result<LocalObservation, String>>),
}
struct Inspection {
    directory: DirectoryDto,
    raft_id: u64,
    budget: Arc<Budget>,
    reply: Reply,
}
struct Slot(Arc<AtomicBool>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
pub(crate) struct LocalObservation {
    pin: NodePin,
    cluster_id: String,
    boot: BootId,
    interface: String,
    ifindex: u32,
    started: Instant,
    source_sha256: String,
}
fn root() -> Result<(), String> {
    if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
        return Err("storage node identity requires explicit Linux root configuration".into());
    }
    Ok(())
}
fn valid_interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() < 16
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
/// All enrollment control artifacts live under the SAME static root already
/// unconditionally reserved from hostaccess, including mount/parent aliases.
/// No arbitrary operator-chosen control roots need dynamic reservations.
fn control_path(path: &Path) -> Result<(), String> {
    let text = path.to_str().ok_or("invalid control path encoding")?;
    crate::host_access::validate_container_path(text)?;
    let reserved = Path::new("/var/lib/royak/storage");
    if path == reserved
        || !path.starts_with(reserved)
        || !path
            .parent()
            .is_some_and(|parent| parent.starts_with(reserved))
        || path.file_name().is_none()
    {
        return Err(
            "identity, consumed marker and approval must be under reserved /var/lib/royak/storage"
                .into(),
        );
    }
    // Actual callers additionally use anchored Dir/O_NOFOLLOW for EVERY
    // parent and leaf, owner/mode/link validation. Never canonicalize-follow
    // a /srv alias into this path and mistake the alias for safe storage.
    Ok(())
}
fn read(path: &Path) -> Result<(LocalFile, String), String> {
    control_path(path)?;
    root()?;
    let raw = private_fs::read_private(path)?;
    let file: LocalFile = serde_json::from_slice(&raw)
        .map_err(|_| "invalid exact root-private local-node identity")?;
    if file.version != 1
        || file.pin.raft_id == 0
        || !valid_interface(&file.interface)
        || !crate::store::is_dns_subdomain(&file.pin.signer_name)
        || !directory::valid_wireguard_key(&file.pin.wireguard_key)
        || !file.pin.wireguard_ip.is_private()
        || crate::auth::derived_cluster_id().as_deref() != Some(file.cluster_id.as_str())
    {
        return Err(
            "local storage-node identity does not match explicit cluster/key/address policy".into(),
        );
    }
    Ok((file, directory::digest(&raw)))
}
pub(crate) fn configure(path: &Path, actual_raft_id: u64) -> Result<(), String> {
    let _configure = CONFIGURE
        .lock()
        .map_err(|_| "identity configuration poisoned")?;
    if LOCAL.get().is_some() {
        return Err("storage local identity already configured".into());
    }
    let (file, sha256) = read(path)?;
    if file.pin.raft_id != actual_raft_id || file.pin.signer_name != crate::store::node_name() {
        return Err(
            "private storage identity conflicts with actual Raft ID or RPC signer configuration"
                .into(),
        );
    }
    let actual = kernel(&file.interface, None)?;
    if actual.key != file.pin.wireguard_key || actual.ip != file.pin.wireguard_ip {
        return Err(
            "configured private node identity is not this actual WG kernel identity".into(),
        );
    }
    let (queue, receive) = mpsc::sync_channel::<Inspection>(1);
    let busy = Arc::new(AtomicBool::new(false));
    let worker_busy = busy.clone();
    std::thread::Builder::new()
        .name("royak-storage-identity".into())
        .spawn(move || {
            while let Ok(work) = receive.recv() {
                let _slot = Slot(worker_busy.clone());
                let result = observe_direct(&work.directory, work.raft_id, &work.budget);
                match work.reply {
                    Reply::Sync(send) => {
                        let _ = send.try_send(result);
                    }
                    Reply::Async(send) => {
                        let _ = send.send(result);
                    }
                }
                // Timeout/drop never frees admission before an actually retained
                // command/cgroup is drained. This remains the same fixed worker.
                while !process::commands_drained() {
                    std::thread::park_timeout(Duration::from_millis(50));
                }
            }
        })
        .map_err(|_| "cannot start the single bounded identity inspector")?;
    LOCAL
        .set(Source {
            path: path.to_path_buf(),
            sha256,
            queue,
            busy,
            runtime_raft_id: actual_raft_id,
        })
        .map_err(|_| "storage local identity already configured".into())
}
pub(crate) fn observe(
    candidate: &DirectoryDto,
    actual_raft_id: u64,
) -> Result<LocalObservation, String> {
    if tokio::runtime::Handle::try_current().is_ok() {
        return Err(
            "synchronous identity observation forbidden on Tokio; use async bounded inspector"
                .into(),
        );
    }
    let (send, receive) = mpsc::sync_channel(1);
    let cancel = submit(candidate, actual_raft_id, Reply::Sync(send))?;
    let result = receive.recv_timeout(MAX_AGE).map_err(|_| {
        "identity observation UNKNOWN/expired; worker retains admission until actual cleanup"
    })?;
    cancel.0.check()?;
    result
}
pub(crate) async fn observe_async(
    candidate: &DirectoryDto,
    actual_raft_id: u64,
) -> Result<LocalObservation, String> {
    let (send, receive) = tokio::sync::oneshot::channel();
    let cancel = submit(candidate, actual_raft_id, Reply::Async(send))?;
    let result = tokio::time::timeout(MAX_AGE, receive)
        .await
        .map_err(|_| "identity observation UNKNOWN/expired; no slot TTL release")?
        .map_err(|_| "identity inspector unavailable")?;
    cancel.0.check()?;
    result
}
fn submit(candidate: &DirectoryDto, raft_id: u64, reply: Reply) -> Result<Cancel, String> {
    candidate.validate()?;
    let source = LOCAL
        .get()
        .ok_or("no explicit storage identity inspector")?;
    source
        .busy
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| "one exact identity inspection is active/unknown; no queue")?;
    let budget = Arc::new(Budget {
        started: Instant::now(),
        cancelled: AtomicBool::new(false),
    });
    if source
        .queue
        .try_send(Inspection {
            directory: candidate.clone(),
            raft_id,
            budget: budget.clone(),
            reply,
        })
        .is_err()
    {
        source.busy.store(false, Ordering::Release);
        return Err("fixed identity inspector unavailable".into());
    }
    Ok(Cancel(budget))
}
fn observe_direct(
    candidate: &DirectoryDto,
    actual_raft_id: u64,
    budget: &Budget,
) -> Result<LocalObservation, String> {
    budget.check()?;
    let started = budget.started;
    candidate.validate()?;
    let source = LOCAL
        .get()
        .ok_or("no explicitly configured root-private storage identity; no inferred UID")?;
    let (file, hash) = read(&source.path)?;
    if hash != source.sha256
        || file.pin.raft_id != actual_raft_id
        || file.pin.signer_name != crate::store::node_name()
        || file.cluster_id != candidate.cluster_id
        || candidate.pin(&file.pin.node_uid)? != &file.pin
    {
        return Err("local-node identity/config/directory was removed, changed or belongs to another machine".into());
    }
    let actual = kernel(&file.interface, Some(budget))?;
    if actual.key != file.pin.wireguard_key || actual.ip != file.pin.wireguard_ip {
        return Err("actual WG key/IP differs from exact committed node UID".into());
    }
    let allowed = String::from_utf8(guarded_output(
        Program::Wireguard,
        &["show", &file.interface, "allowed-ips"],
        Some(budget),
    )?)
    .map_err(|_| "invalid WG peer observation")?;
    check_peers(candidate, &file.pin, &allowed)?;
    if read(&source.path)?.1 != source.sha256 || started.elapsed() >= MAX_AGE {
        return Err("local identity observation changed or aged out".into());
    }
    let result = LocalObservation {
        pin: file.pin,
        cluster_id: file.cluster_id,
        boot: BootId::current()?,
        interface: file.interface,
        ifindex: actual.ifindex,
        started,
        source_sha256: hash,
    };
    result.require_current(candidate, actual_raft_id)?;
    Ok(result)
}
impl LocalObservation {
    pub(crate) fn node_uid(&self) -> &crate::storage_identity::Uid {
        &self.pin.node_uid
    }
    pub(crate) fn boot(&self) -> &BootId {
        &self.boot
    }
    pub(crate) fn require_current(
        &self,
        dto: &DirectoryDto,
        actual_raft_id: u64,
    ) -> Result<(), String> {
        let source = LOCAL
            .get()
            .ok_or("local identity configuration disappeared")?;
        if self.started.elapsed() >= MAX_AGE
            || source.sha256 != self.source_sha256
            || self.cluster_id != dto.cluster_id
            || self.pin.raft_id != actual_raft_id
            || dto.pin(&self.pin.node_uid)? != &self.pin
            || BootId::current()? != self.boot
            || interface_index(&self.interface)? != self.ifindex
        {
            return Err(
                "local storage identity/boot/interface/directory is no longer current".into(),
            );
        }
        Ok(())
    }
}
pub(crate) struct ApprovedEnrollment {
    directory: DirectoryDto,
}
impl ApprovedEnrollment {
    pub(crate) fn directory(&self) -> &DirectoryDto {
        &self.directory
    }
}
/// Explicit one-shot startup consent, not a revocable writer/session lease.
/// Constructor performs root-private file IO before any server runtime listens.
pub(crate) fn approve_enrollment(path: &Path) -> Result<ApprovedEnrollment, String> {
    Ok(ApprovedEnrollment {
        directory: load_approved(path)?,
    })
}
fn load_approved(path: &Path) -> Result<DirectoryDto, String> {
    control_path(path)?;
    root()?;
    let raw = private_fs::read_private(path)?;
    let d: DirectoryDto =
        serde_json::from_slice(&raw).map_err(|_| "invalid root-approved directory manifest")?;
    d.validate()?;
    if crate::auth::derived_cluster_id().as_deref() != Some(d.cluster_id.as_str()) {
        return Err("approved directory is for another authenticated cluster".into());
    }
    Ok(d)
}
pub(crate) fn initialize(
    path: &Path,
    raft_id: u64,
    signer: &str,
    interface: &str,
) -> Result<NodePin, String> {
    control_path(path)?;
    root()?;
    if raft_id == 0 || !crate::store::is_dns_subdomain(signer) {
        return Err("explicit nonzero Raft ID and signer are required".into());
    }
    crate::auth::require_cluster_secret()?;
    let cluster_id = crate::auth::derived_cluster_id().ok_or("cluster identity missing")?;
    let parent = path.parent().ok_or("identity parent missing")?;
    let name = path
        .file_name()
        .and_then(|p| p.to_str())
        .ok_or("invalid identity filename")?;
    let dir = Dir::open(parent, true)?;
    let _held = dir.lock()?;
    if dir.read(name)?.is_some() {
        return Err("local identity already exists; no replacement or UID reuse".into());
    }
    let observed = kernel(interface, None)?;
    let pin = NodePin {
        node_uid: crate::storage_identity::Uid::new(),
        raft_id,
        signer_name: signer.into(),
        wireguard_key: observed.key,
        wireguard_ip: observed.ip,
    };
    let file = LocalFile {
        version: 1,
        cluster_id,
        pin: pin.clone(),
        interface: interface.into(),
    };
    let raw = serde_json::to_vec(&file).map_err(|_| "cannot encode new local identity")?;
    dir.write_new(name, &raw)?;
    Ok(pin)
}
struct Kernel {
    key: String,
    ip: std::net::Ipv4Addr,
    ifindex: u32,
}
fn output(p: Program, args: &[&str]) -> Result<Vec<u8>, String> {
    process::run(p, &args.iter().map(|s| s.to_string()).collect::<Vec<_>>())?
        .success("read-only node identity observation")
}
fn guarded_output(p: Program, args: &[&str], budget: Option<&Budget>) -> Result<Vec<u8>, String> {
    if let Some(b) = budget {
        b.check()?;
    }
    let result = output(p, args)?;
    if let Some(b) = budget {
        b.check()?;
    }
    Ok(result)
}
fn interface_index(interface: &str) -> Result<u32, String> {
    if !valid_interface(interface) {
        return Err("invalid exact WG interface".into());
    }
    let c = std::ffi::CString::new(interface).map_err(|_| "invalid interface")?;
    let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
    if index == 0 {
        return Err("configured WG interface is missing".into());
    }
    Ok(index)
}
fn kernel(interface: &str, budget: Option<&Budget>) -> Result<Kernel, String> {
    root()?;
    let index = interface_index(interface)?;
    let link: serde_json::Value = serde_json::from_slice(&guarded_output(
        Program::Ip,
        &["-j", "-d", "link", "show", "dev", interface],
        budget,
    )?)
    .map_err(|_| "invalid kernel WG link output")?;
    let links = link
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("ambiguous WG interface")?;
    if links[0]["ifindex"].as_u64() != Some(u64::from(index))
        || links[0]["linkinfo"]["info_kind"] != "wireguard"
        || !links[0]["flags"]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v == "UP"))
    {
        return Err("identity interface is not actual active kernel WireGuard".into());
    }
    let addr: serde_json::Value = serde_json::from_slice(&guarded_output(
        Program::Ip,
        &["-j", "address", "show", "dev", interface],
        budget,
    )?)
    .map_err(|_| "invalid WG address output")?;
    let interfaces = addr
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("ambiguous WG address interface")?;
    let ips = interfaces[0]["addr_info"]
        .as_array()
        .ok_or("WG address inventory missing")?
        .iter()
        .filter(|a| a["family"] == "inet")
        .map(|a| {
            a["local"]
                .as_str()
                .ok_or("invalid WG address")
                .and_then(|s| {
                    s.parse::<std::net::Ipv4Addr>()
                        .map_err(|_| "invalid WG IPv4")
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if ips.len() != 1 || !ips[0].is_private() {
        return Err("one explicit private WG IPv4 required".into());
    }
    let key = String::from_utf8(guarded_output(
        Program::Wireguard,
        &["show", interface, "public-key"],
        budget,
    )?)
    .map_err(|_| "invalid public WG key output")?
    .trim_end()
    .to_string();
    if !directory::valid_wireguard_key(&key) || interface_index(interface)? != index {
        return Err("kernel WG identity changed or key invalid".into());
    }
    Ok(Kernel {
        key,
        ip: ips[0],
        ifindex: index,
    })
}
fn check_peers(dto: &DirectoryDto, local: &NodePin, raw: &str) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    for line in raw.lines() {
        let p = line.split_whitespace().collect::<Vec<_>>();
        if p.len() != 2 || !seen.insert(p[0]) {
            return Err("ambiguous actual WG peer list".into());
        }
        let pin = dto
            .nodes
            .iter()
            .find(|n| n.node_uid != local.node_uid && n.wireguard_key == p[0])
            .ok_or("foreign WG peer key")?;
        if p[1] != format!("{}/32", pin.wireguard_ip) {
            return Err("broad/wrong WG AllowedIPs cannot establish node identity".into());
        }
    }
    if seen.len() + 1 != dto.nodes.len() {
        return Err("actual WG peer set differs from approved voters".into());
    }
    Ok(())
}

/// Applied enrollment history, separate from user-restorable desired JSON.
/// Only the actual Raft enrollment apply calls this writer; snapshots may read
/// and compare, never create or replace a missing guard from their own payload.
pub(crate) fn load_guard(raft_dir: &Path) -> Result<Option<Registry>, String> {
    let path = raft_dir.join("storage-node-history");
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            require_no_consumed_identity()?;
            return Ok(None);
        }
        Err(_) => return Err("cannot observe local directory history".into()),
        Ok(_) => {}
    }
    let dir = Dir::open(&path, false)?;
    let Some(raw) = dir.read("enrollment.sealed")? else {
        require_no_consumed_identity()?;
        return Ok(None);
    };
    root()?;
    let sealed = std::str::from_utf8(&raw).map_err(|_| "invalid directory history encoding")?;
    let bytes = crate::auth::unseal_for_cluster(directory::GUARD_PURPOSE, sealed)?;
    let registry: Registry = serde_json::from_slice(&bytes)
        .map_err(|_| "invalid local directory applied-history guard")?;
    let cluster = crate::auth::derived_cluster_id().ok_or("history cluster identity missing")?;
    registry.validate(&cluster)?;
    if !registry.has_authority() {
        return Err("local history guard cannot be empty".into());
    }
    let (identity_dir, name) = identity_anchor(&registry)?;
    let marker = identity_dir
        .read(&name)?
        .ok_or("Raft directory history has no exact consumed-identity marker; explicit recovery")?;
    if decode_history(&marker)? != registry {
        return Err("local identity marker and Raft enrollment history differ".into());
    }
    Ok(Some(registry))
}
pub(crate) fn require_external_history(raft_dir: &Path) -> Result<(), String> {
    if let Some(source) = LOCAL.get() {
        let actual = std::fs::canonicalize(raft_dir)
            .map_err(|_| "cannot resolve actual Raft history directory")?;
        let identity =
            std::fs::canonicalize(&source.path).map_err(|_| "local identity disappeared")?;
        if identity.starts_with(actual) {
            return Err("local identity/consumed marker must be outside the Raft directory".into());
        }
    }
    Ok(())
}
fn marker_name(path: &Path) -> Result<String, String> {
    control_path(path)?;
    let base = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("invalid local identity filename")?;
    if base.is_empty() || base.len() > 96 {
        return Err("local identity filename exceeds marker bound".into());
    }
    let marker = format!("{base}.enrolled.sealed");
    control_path(&path.with_file_name(&marker))?;
    Ok(marker)
}
fn decode_history(raw: &[u8]) -> Result<Registry, String> {
    let sealed = std::str::from_utf8(raw).map_err(|_| "invalid consumed identity history")?;
    let bytes = crate::auth::unseal_for_cluster(directory::GUARD_PURPOSE, sealed)?;
    let registry: Registry =
        serde_json::from_slice(&bytes).map_err(|_| "malformed consumed identity history")?;
    registry.validate(&crate::auth::derived_cluster_id().ok_or("cluster identity missing")?)?;
    if !registry.has_authority() {
        return Err("consumed identity history is empty".into());
    }
    Ok(registry)
}
fn require_no_consumed_identity() -> Result<(), String> {
    if let Some(source) = LOCAL.get() {
        let parent = source.path.parent().ok_or("identity parent missing")?;
        if Dir::open(parent, false)?
            .read(&marker_name(&source.path)?)?
            .is_some()
        {
            return Err("identity was already consumed but Raft history is missing; explicit recovery, never automatic UID reuse".into());
        }
    }
    Ok(())
}
fn identity_anchor(registry: &Registry) -> Result<(Dir, String), String> {
    let source = LOCAL
        .get()
        .ok_or("enrollment apply requires each voter to have explicit local storage identity")?;
    let (file, hash) = read(&source.path)?;
    if hash != source.sha256
        || file.pin.raft_id != source.runtime_raft_id
        || registry
            .directory()
            .ok_or("directory missing")?
            .pin(&file.pin.node_uid)?
            != &file.pin
    {
        return Err("applied directory does not bind this voter's pinned local identity".into());
    }
    Ok((
        Dir::open(
            source.path.parent().ok_or("identity parent missing")?,
            false,
        )?,
        marker_name(&source.path)?,
    ))
}
pub(crate) fn persist_guard(raft_dir: &Path, registry: &Registry) -> Result<(), String> {
    root()?;
    let cluster = crate::auth::derived_cluster_id().ok_or("history cluster missing")?;
    registry.validate(&cluster)?;
    if !registry.has_authority() {
        return Err("cannot persist empty enrollment guard".into());
    }
    let path = raft_dir.join("storage-node-history");
    let dir = Dir::open(&path, true)?;
    let _lock = dir.lock()?;
    if let Some(existing) = load_guard(raft_dir)? {
        existing.require_unchanged(registry)?;
        return Ok(());
    }
    let bytes =
        serde_json::to_vec(registry).map_err(|_| "cannot encode applied directory history")?;
    let sealed = crate::auth::seal_for_cluster(directory::GUARD_PURPOSE, &bytes)?;
    let (identity_dir, marker) = identity_anchor(registry)?;
    let _identity_lock = identity_dir.lock()?;
    if identity_dir.read(&marker)?.is_some() {
        return Err(
            "consumed identity cannot recreate a missing Raft guard; explicit recovery".into(),
        );
    }
    // Bounded accidental-loss history only, NOT protection against hostile
    // root. A crash between these two fsync points requires explicit recovery.
    identity_dir.write_new(&marker, sealed.as_bytes())?;
    dir.write_new("enrollment.sealed", sealed.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_approval_and_marker_can_never_select_public_or_traversed_roots() {
        for path in [
            "/srv/private/node.json",
            "/srv/alias/node.json",
            "/var/lib/royak/storage-other/node.json",
            "/var/lib/royak/storage",
            "/var/lib/royak/storage/../node.json",
            "/var/lib/royak/storage//node.json",
            "relative/node.json",
        ] {
            assert!(control_path(Path::new(path)).is_err(), "{path}");
        }
        let identity = Path::new("/var/lib/royak/storage/control/node.json");
        control_path(identity).unwrap();
        control_path(&identity.with_file_name(marker_name(identity).unwrap())).unwrap();
        control_path(Path::new("/var/lib/royak/storage/control/approved.json")).unwrap();
        for public in [
            "/var/lib/royak/storage/control/node.json",
            "/var/lib/royak/storage/control/approved.json",
            "/var/lib/royak/storage/control/node.json.enrolled.sealed",
            "/var/lib/royak/storage/control",
            "/var/lib/royak",
        ] {
            assert!(
                crate::host_access::validate_public_path(public).is_err(),
                "{public}"
            );
        }
    }
    #[test]
    fn dangling_public_alias_and_its_control_children_cannot_escape_reserved_storage() {
        use std::os::unix::fs::symlink;
        let owned = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "royak-directory-alias-{}",
            crate::storage_identity::Uid::new().as_str()
        ));
        std::fs::create_dir(&owned).unwrap();
        let alias = owned.join("alias");
        symlink("/var/lib/royak/storage/control-not-created", &alias).unwrap();
        for leaf in ["node.json", "approved.json", "node.json.enrolled.sealed"] {
            let candidate = alias.join(leaf);
            assert!(control_path(&candidate).is_err());
            assert!(
                crate::host_access::validate_resolved_public_path(candidate.to_str().unwrap())
                    .is_err()
            );
        }
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir(owned).unwrap();
    }
    #[test]
    fn caller_timeout_or_drop_does_not_release_the_worker_owned_slot() {
        let busy = Arc::new(AtomicBool::new(true));
        let slot = Slot(busy.clone());
        let budget = Arc::new(Budget {
            started: Instant::now(),
            cancelled: AtomicBool::new(false),
        });
        let caller = Cancel(budget.clone());
        drop(caller);
        assert!(budget.check().is_err());
        assert!(busy.load(Ordering::Acquire));
        drop(slot);
        assert!(!busy.load(Ordering::Acquire));
    }
    #[test]
    fn expired_inspection_never_starts_a_subsequent_program() {
        let budget = Budget {
            started: Instant::now() - MAX_AGE,
            cancelled: AtomicBool::new(false),
        };
        assert!(budget.check().is_err());
        assert!(
            guarded_output(Program::Wireguard, &["not-a-valid-command"], Some(&budget)).is_err()
        );
    }
    #[tokio::test]
    async fn synchronous_observation_refuses_on_tokio_before_any_kernel_program() {
        let dto = DirectoryDto {
            version: 0,
            cluster_id: String::new(),
            nodes: Vec::new(),
        };
        let error = observe(&dto, 0).err().unwrap();
        assert!(error.contains("forbidden on Tokio"));
    }
    #[test]
    fn missing_or_foreign_local_binding_never_derives_uid_from_name_or_env() {
        assert!(LOCAL.get().is_none());
        assert!(read(Path::new(
            "/nonexistent/royak-node-identity-never-generated"
        ))
        .is_err());
        assert!(!Path::new("/nonexistent/royak-node-identity-never-generated").exists());
    }
    #[test]
    fn interface_names_cannot_select_shell_or_ordinary_routes() {
        for bad in ["", "eth0;wg", "../wg0", "wg 0", "wg0\n", "abcdefghijklmnop"] {
            assert!(!valid_interface(bad));
        }
        assert!(valid_interface("rkstore0"));
    }
}
