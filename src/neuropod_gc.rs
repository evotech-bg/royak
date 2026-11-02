//! Explicit ownership and restart-safe, fail-closed NeuroPod reclamation.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Owner {
    pub cluster: String,
    pub node: String,
    pub state: String,
    pub namespace: String,
    pub deployment: String,
    pub generation: u64,
}
impl Owner {
    pub fn current(w: &crate::reconcile::DesiredWorld, namespace: &str, deployment: &str) -> Self {
        let path = PathBuf::from(crate::state_path());
        let absolute = if path.is_absolute() {
            path
        } else {
            std::env::current_dir().unwrap_or_default().join(path)
        };
        Self {
            cluster: w.cluster_id.clone(),
            node: crate::store::node_name(),
            state: std::fs::canonicalize(&absolute)
                .unwrap_or(absolute)
                .to_string_lossy()
                .into(),
            namespace: namespace.into(),
            deployment: deployment.into(),
            generation: w.generation,
        }
    }
    pub fn same_scope(&self, other: &Self) -> bool {
        self.cluster == other.cluster && self.node == other.node && self.state == other.state
    }
    pub fn valid_name(&self, name: &str) -> bool {
        if !crate::store::is_dns_label(&self.namespace)
            || !crate::store::is_dns_label(&self.deployment)
        {
            return false;
        }
        let stem = crate::store::pod_stem(&self.namespace, &self.deployment);
        name.strip_prefix(&(stem.clone() + "-"))
            .and_then(|n| n.parse::<u32>().ok())
            .map(|n| n > 0 && name == format!("{stem}-{n}"))
            .unwrap_or(false)
    }
}

pub fn safe_component(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 240
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
pub fn safe_mount_path(path: &str) -> bool {
    let p = Path::new(path);
    p.is_absolute()
        && !path.contains('\0')
        && p.components().count() > 1
        && p.components().all(|c| {
            matches!(
                c,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}
pub fn write_meta(base: &Path, value: &Value) -> Result<(), String> {
    use std::io::Write;
    let tmp = base.join("meta.json.next");
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|e| format!("metadata open: {e}"))?;
    file.write_all(
        serde_json::to_string(value)
            .map_err(|e| e.to_string())?
            .as_bytes(),
    )
    .and_then(|_| file.sync_all())
    .map_err(|e| format!("metadata write: {e}"))?;
    std::fs::rename(tmp, base.join("meta.json")).map_err(|e| format!("metadata rename: {e}"))?;
    std::fs::File::open(base)
        .and_then(|f| f.sync_all())
        .map_err(|e| format!("metadata directory sync: {e}"))
}
pub fn read_meta(base: &Path) -> Result<Value, String> {
    for (path, directory) in [(base.to_path_buf(), true), (base.join("meta.json"), false)] {
        let meta = std::fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if meta.file_type().is_symlink()
            || (directory && !meta.is_dir())
            || (!directory && (!meta.is_file() || meta.len() > 65536))
        {
            return Err("unsafe or oversized pod metadata refused".into());
        }
    }
    let bytes = std::fs::read(base.join("meta.json")).map_err(|e| e.to_string())?;
    if bytes.len() > 65536 {
        return Err("oversized pod metadata".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| e.to_string())
}
pub struct Record {
    pub name: String,
    pub base: PathBuf,
    pub meta: Value,
    pub owner: Owner,
}
pub fn inventory(root: &Path) -> Vec<Record> {
    let mut records = Vec::new();
    if std::fs::symlink_metadata(root)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(true)
    {
        return records;
    }
    if let Ok(entries) = std::fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !safe_component(&name) {
                continue;
            }
            let Ok(meta) = read_meta(&entry.path()) else {
                continue;
            };
            if meta["name"].as_str() != Some(&name) {
                continue;
            }
            let Ok(owner) = serde_json::from_value::<Owner>(meta["owner"].clone()) else {
                continue;
            };
            if owner.valid_name(&name) {
                records.push(Record {
                    name,
                    base: entry.path(),
                    meta,
                    owner,
                });
            }
        }
    }
    records
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    pub start_ticks: u64,
    pub boot: String,
}
#[cfg(target_os = "linux")]
pub fn process_identity(pid: u32) -> Result<Process, String> {
    if pid <= 1 {
        return Err("invalid pod PID".into());
    }
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|e| e.to_string())?;
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .ok_or("invalid process stat")?
        .1
        .split_whitespace()
        .collect();
    if fields.first().copied() == Some("Z") {
        return Err("process exited".into());
    }
    let start_ticks = fields
        .get(19)
        .and_then(|x| x.parse().ok())
        .ok_or("invalid process birth")?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|e| e.to_string())?
        .trim()
        .into();
    Ok(Process {
        pid,
        start_ticks,
        boot,
    })
}
#[cfg(not(target_os = "linux"))]
pub fn process_identity(_: u32) -> Result<Process, String> {
    Err("managed NeuroPod requires Linux".into())
}
pub fn process_running(meta: &Value) -> bool {
    serde_json::from_value::<Process>(meta["process"].clone())
        .ok()
        .and_then(|p| {
            process_identity(p.pid)
                .ok()
                .map(|actual| actual.start_ticks == p.start_ticks && actual.boot == p.boot)
        })
        .unwrap_or(false)
}
#[cfg(target_os = "linux")]
fn stop_process(meta: &Value) -> Result<(), String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let Some(raw) = meta.get("process") else {
        return Ok(());
    };
    let p: Process = serde_json::from_value(raw.clone()).map_err(|_| "invalid process identity")?;
    if p.pid <= 1 {
        return Err("unsafe pod PID".into());
    }
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, p.pid, 0) } as i32;
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return if e.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(format!("pidfd open: {e}"))
        };
    }
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let Ok(actual) = process_identity(p.pid) else {
        return Ok(());
    };
    if actual.start_ticks != p.start_ticks || actual.boot != p.boot {
        return Ok(());
    } // recycled PID is NOT ours
    for (signal, wait_ms) in [(libc::SIGTERM, 1000), (libc::SIGKILL, 2000)] {
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            return Err("pod signal failed".into());
        }
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        if unsafe { libc::poll(&mut poll, 1, wait_ms) } > 0 {
            unsafe {
                libc::waitpid(p.pid as i32, std::ptr::null_mut(), libc::WNOHANG);
            }
            return Ok(());
        }
    }
    Err("pod process did not exit".into())
}
#[cfg(not(target_os = "linux"))]
fn stop_process(meta: &Value) -> Result<(), String> {
    if meta.get("process").is_some() {
        Err("managed NeuroPod requires Linux".into())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn command(program: &str, args: &[&str]) -> Result<(), String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{program} cleanup refused: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}
#[cfg(target_os = "linux")]
fn unmount(base: &Path) -> Result<(), String> {
    let source = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| e.to_string())?;
    let mut mounts: Vec<PathBuf> = source
        .lines()
        .filter_map(|line| line.split_whitespace().nth(4))
        .map(|p| {
            PathBuf::from(
                p.replace("\\040", " ")
                    .replace("\\011", "\t")
                    .replace("\\134", "\\"),
            )
        })
        .filter(|p| p.starts_with(base))
        .collect();
    mounts.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for mount in mounts {
        command("umount", &[mount.to_str().ok_or("invalid mount path")?])?;
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn unmount(_: &Path) -> Result<(), String> {
    Ok(())
}

pub fn reclaim(record: &Record, scope: &Owner) -> Result<PathBuf, String> {
    if !record.owner.same_scope(scope)
        || record.owner.generation > scope.generation
        || !record.owner.valid_name(&record.name)
    {
        return Err("pod ownership/generation mismatch".into());
    }
    // Re-read before acting. Unknown/unmarked/foreign/symlink records are never adopted.
    let meta = read_meta(&record.base)?;
    if meta != record.meta {
        return Err("pod metadata changed during GC".into());
    }
    for name in ["merged", "data", "upper", "work", "data.img"] {
        if std::fs::symlink_metadata(record.base.join(name))
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err("symlink pod resource refused".into());
        }
    }
    stop_process(&meta)?;
    unmount(&record.base)?; // no lazy detach, and NEVER remove files beneath a live mount
    if let Some(raw) = meta.get("network") {
        let net: crate::runtime::PodNetwork =
            serde_json::from_value(raw.clone()).map_err(|_| "invalid pod network metadata")?;
        let (ns, vh, vp) = crate::runtime::pod_network_names(&record.name);
        if net.pod_name != record.name
            || (net.namespace, net.veth_host, net.veth_pod) != (ns.clone(), vh.clone(), vp)
            || !net.exposed_ports.is_empty()
        {
            return Err("unexpected owned network identity".into());
        }
        #[cfg(target_os = "linux")]
        {
            if Path::new("/var/run/netns").join(&ns).exists() {
                command("ip", &["netns", "del", &ns])?;
            }
            if Path::new("/sys/class/net").join(&vh).exists() {
                command("ip", &["link", "del", &vh])?;
            }
        }
    }
    // Keep persistent user data outside ephemeral pod state. Never silently
    // destroy a data disk on Deployment deletion/scale-down.
    let home = record
        .base
        .parent()
        .and_then(Path::parent)
        .ok_or("invalid pod base")?;
    let retained = home
        .join("retained-neuropod-data")
        .join(&record.name)
        .join(format!("{:032x}", rand::random::<u128>()));
    std::fs::create_dir_all(&retained).map_err(|e| e.to_string())?;
    write_meta(&retained, &meta)?;
    let disk = record.base.join("data.img");
    if disk.exists() {
        std::fs::rename(&disk, retained.join("data.img"))
            .map_err(|e| format!("retain disk: {e}"))?;
    }
    std::fs::remove_dir_all(&record.base)
        .map_err(|e| format!("remove ephemeral pod state: {e}"))?;
    Ok(retained)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner() -> Owner {
        Owner {
            cluster: "c".into(),
            node: "n".into(),
            state: "/state".into(),
            namespace: "team-a".into(),
            deployment: "api".into(),
            generation: 4,
        }
    }
    #[test]
    fn ownership_is_not_a_name_prefix() {
        let a = owner();
        assert!(a.valid_name("rk-team-a_api-1"));
        assert!(!a.valid_name("rk-team-b_api-1"));
        assert!(!a.valid_name("rk-team-a_api-x"));
        assert!(!a.valid_name("rk-team-a_api-0"));
    }
    #[test]
    fn foreign_scope_is_never_owned() {
        let a = owner();
        for b in [
            Owner {
                cluster: "other".into(),
                ..a.clone()
            },
            Owner {
                node: "other".into(),
                ..a.clone()
            },
            Owner {
                state: "/other".into(),
                ..a.clone()
            },
        ] {
            assert!(!a.same_scope(&b));
        }
    }
    #[test]
    fn path_components_are_not_paths() {
        for bad in ["..", ".", "../x", "a/b", "a\\b", "a b", ""] {
            assert!(!safe_component(bad));
        }
        assert!(safe_component("rk-team-a_api-1"));
    }
    #[test]
    fn custom_absolute_mount_paths_are_supported_without_parent_traversal() {
        assert!(safe_mount_path("/data"));
        assert!(safe_mount_path("/var/lib/app"));
        for path in ["/", "relative", "/../../etc", "/data/../etc", "/a\0b"] {
            assert!(!safe_mount_path(path));
        }
    }
    #[test]
    fn inventory_preserves_unowned_and_symlinked_directories() {
        let root = std::env::temp_dir().join(format!("royak-gc-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(root.join("legacy")).unwrap();
        write_meta(&root.join("legacy"), &serde_json::json!({"name":"legacy"})).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("legacy"), root.join("link")).unwrap();
        assert!(inventory(&root).is_empty());
        assert!(root.join("legacy/meta.json").exists());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn foreign_or_future_records_cannot_be_reclaimed() {
        let scope = owner();
        for o in [
            Owner {
                generation: 5,
                ..scope.clone()
            },
            Owner {
                cluster: "other".into(),
                ..scope.clone()
            },
        ] {
            let r = Record {
                name: "rk-team-a_api-1".into(),
                base: PathBuf::from("/nonexistent"),
                meta: Value::Null,
                owner: o,
            };
            assert!(reclaim(&r, &scope).unwrap_err().contains("ownership"));
        }
    }
    #[test]
    fn reclamation_retains_data_without_touching_shared_files() {
        let home =
            std::env::temp_dir().join(format!("royak-retain-{:032x}", rand::random::<u128>()));
        let base = home.join("pods/rk-team-a_api-1");
        std::fs::create_dir_all(&base).unwrap();
        std::fs::create_dir_all(home.join("images/shared")).unwrap();
        std::fs::write(home.join("images/shared/sentinel"), b"image").unwrap();
        let o = owner();
        let meta = serde_json::json!({"name":"rk-team-a_api-1","owner":o});
        write_meta(&base, &meta).unwrap();
        std::fs::write(base.join("data.img"), b"persistent user data").unwrap();
        let r = Record {
            name: "rk-team-a_api-1".into(),
            base: base.clone(),
            meta,
            owner: o.clone(),
        };
        let archive = reclaim(&r, &o).unwrap();
        assert!(!base.exists());
        assert_eq!(
            std::fs::read(archive.join("data.img")).unwrap(),
            b"persistent user data"
        );
        assert!(home.join("images/shared/sentinel").exists());
        std::fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn network_names_do_not_collide_on_namespace_prefixes() {
        let a = crate::runtime::pod_network_names("rk-team-a_api-1");
        let b = crate::runtime::pod_network_names("rk-team-b_api-1");
        assert_ne!(a, b);
        assert!(a.1.len() < 16 && b.1.len() < 16);
    }
    #[test]
    fn address_allocation_reuses_holes_not_existing_pod_addresses() {
        let used = ["10.42.0.2".to_string(), "10.42.0.4".to_string()]
            .into_iter()
            .collect();
        assert_eq!(crate::runtime::next_pod_network_index(&used), Some(1));
        let full = (2..=254).map(|i| format!("10.42.0.{i}")).collect();
        assert_eq!(crate::runtime::next_pod_network_index(&full), None);
    }
}
