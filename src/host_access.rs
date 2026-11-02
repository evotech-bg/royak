//! Host access is a distinct cluster permission, not an implication of a
//! namespace's workload permissions. Permits are server-issued, incarnation-
//! and content-bound; they are never parsed from a Kubernetes manifest.
use crate::{
    auth,
    reconcile::{DesiredWorld, StoredContainer},
    spec::Resource,
    storage_identity::Uid,
    store::DesiredState,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Permit {
    version: u32,
    phase: String,
    namespace_uid: Uid,
    binding_sha256: String,
}
pub fn attrs() -> auth::Attrs {
    auth::Attrs::new("use", "hostaccess", None, None, None)
}
pub fn allowed(world: &DesiredWorld, caller: &auth::Identity) -> bool {
    auth::authorize(world, caller, &attrs())
}
pub fn dangerous(security: Option<&crate::security::SecurityContext>) -> bool {
    security
        .and_then(|s| s.capabilities.as_ref())
        .is_some_and(|c| {
            c.add
                .iter()
                .any(|v| v.strip_prefix("CAP_").unwrap_or(v) != "NET_BIND_SERVICE")
        })
}
pub fn stored_requires(c: &StoredContainer) -> bool {
    dangerous(c.security_context.as_ref())
        || c.volumes.iter().any(|(h, _)| {
            !["cmv:", "sev:", "emptydir:", "pvc:"]
                .iter()
                .any(|prefix| h.starts_with(prefix))
        })
}
fn digest(value: &Value) -> String {
    format!("{:x}", Sha256::digest(value.to_string().as_bytes()))
}
fn container_value(c: &StoredContainer) -> Result<Value, String> {
    let mut v = serde_json::to_value(c).map_err(|_| "cannot bind host-access container")?;
    v.as_object_mut()
        .ok_or("invalid host-access container")?
        .remove("host_access");
    Ok(v)
}
fn source_binding(
    cluster: &str,
    ns: &Uid,
    kind: &str,
    owner: &str,
    c: &StoredContainer,
) -> Result<String, String> {
    Ok(digest(
        &json!({"contract":1,"phase":"desired","cluster":cluster,"namespace_uid":ns,
        "kind":kind,"owner":owner,"container":container_value(c)?}),
    ))
}
fn check(permit: &Permit, ns: &Uid, phase: &str, hash: &str) -> Result<(), String> {
    if permit.version != 1
        || &permit.namespace_uid != ns
        || permit.phase != phase
        || permit.binding_sha256 != hash
    {
        return Err("host-access permit does not match this namespace incarnation and exact workload contract".into());
    }
    Ok(())
}
pub fn validate_source(
    world: &DesiredWorld,
    src: &crate::workload::PodSource<'_>,
    c: &StoredContainer,
) -> Result<(), String> {
    if !stored_requires(c) && c.host_access.is_none() {
        return Ok(());
    }
    let ns = world
        .storage_identities
        .namespaces
        .get(src.namespace)
        .ok_or("host access has no namespace incarnation")?;
    check(
        c.host_access.as_ref().ok_or(
            "host access has no server-issued permit; explicit authorized re-apply required",
        )?,
        ns,
        "desired",
        &source_binding(&world.cluster_id, ns, src.kind, src.owner, c)?,
    )
}
fn containers<'a>(
    state: &'a DesiredState,
) -> Vec<(&'a str, &'a str, &'a str, &'a StoredContainer)> {
    let mut out = Vec::new();
    for d in state.deployments.values() {
        for c in d.init_containers.iter().chain(d.containers.iter()) {
            out.push(("deployment", d.namespace.as_str(), d.name.as_str(), c));
        }
    }
    for d in state.daemonsets.values() {
        out.push((
            "daemonset",
            d.namespace.as_str(),
            d.name.as_str(),
            &d.container,
        ));
    }
    for d in state.jobs.values() {
        out.push(("job", d.namespace.as_str(), d.name.as_str(), &d.container));
    }
    for d in state.cronjobs.values() {
        out.push((
            "cronjob",
            d.namespace.as_str(),
            d.name.as_str(),
            &d.container,
        ));
    }
    out
}
pub fn has_authority(state: &DesiredState) -> bool {
    containers(state)
        .iter()
        .any(|(_, _, _, c)| c.host_access.is_some())
}
pub fn validate_state(state: &DesiredState) -> Result<(), String> {
    for (kind, ns, owner, c) in containers(state) {
        if let Some(permit) = &c.host_access {
            let ns = state
                .storage_identities
                .namespaces
                .get(ns)
                .ok_or("host permit has no namespace identity")?;
            check(
                permit,
                ns,
                "desired",
                &source_binding(&state.cluster_id, ns, kind, owner, c)?,
            )?;
            if !stored_requires(c) {
                return Err("unexpected host-access permit on an unprivileged container".into());
            }
        }
    }
    Ok(())
}
/// Local operator apply is trusted; HTTP callers must supply a freshly checked
/// cluster permission inside the commit, never a field from their request.
pub fn issue_resource(
    world: &mut DesiredWorld,
    r: &Resource,
    authorized: bool,
) -> Result<(), String> {
    let ns = crate::store::ns_of(r);
    let key = crate::store::obj_key(&ns, &r.metadata.name);
    let Some(ns_uid) = world.storage_identities.namespaces.get(&ns).cloned() else {
        return Ok(());
    };
    let cluster = world.cluster_id.clone();
    let owner = &r.metadata.name;
    let issue = |kind: &str, c: &mut StoredContainer| -> Result<(), String> {
        c.host_access = None;
        if stored_requires(c) {
            if !authorized {
                return Err("host access requires cluster-scoped use hostaccess permission".into());
            }
            c.host_access = Some(Permit {
                version: 1,
                phase: "desired".into(),
                namespace_uid: ns_uid.clone(),
                binding_sha256: source_binding(&cluster, &ns_uid, kind, owner, c)?,
            });
        }
        Ok(())
    };
    match r.kind.as_str() {
        "Deployment" | "ReplicaSet" | "StatefulSet" | "Pod" => {
            if let Some(d) = world.deployments.get_mut(&key) {
                for c in d.init_containers.iter_mut().chain(d.containers.iter_mut()) {
                    issue("deployment", c)?;
                }
            }
        }
        "DaemonSet" => {
            if let Some(d) = world.daemonsets.get_mut(&key) {
                issue("daemonset", &mut d.container)?;
            }
        }
        "Job" => {
            if let Some(d) = world.jobs.get_mut(&key) {
                issue("job", &mut d.container)?;
            }
        }
        "CronJob" => {
            if let Some(d) = world.cronjobs.get_mut(&key) {
                issue("cronjob", &mut d.container)?;
            }
        }
        _ => (),
    }
    Ok(())
}
fn pod_spec(r: &Resource) -> Result<Option<Value>, String> {
    let Some(spec) = &r.spec else {
        return Ok(None);
    };
    let v = serde_json::to_value(spec).map_err(|_| "invalid workload spec")?;
    let pod = match r.kind.as_str() {
        "Pod" => &v,
        "Deployment" | "ReplicaSet" | "StatefulSet" | "DaemonSet" | "Job" => &v["template"]["spec"],
        "CronJob" => &v["jobTemplate"]["spec"]["template"]["spec"],
        _ => return Ok(None),
    };
    Ok(Some(pod.clone()))
}
pub fn resource_requires(r: &Resource) -> Result<bool, String> {
    let Some(pod) = pod_spec(r)? else {
        return Ok(false);
    };
    for field in ["hostNetwork", "hostPID", "hostIPC"] {
        if pod.get(field).is_some_and(|v| v != false && !v.is_null()) {
            return Err(format!(
                "{field} is unsupported; host namespace access is not a hostaccess grant"
            ));
        }
    }
    // Legacy VCTs are raw host-directory allocation, not managed PVCs. They
    // require node-level approval until the native claim controller replaces
    // this path. Loaded schema-4 instances without permits stay blocked.
    let mut required = r.kind == "StatefulSet"
        && r.spec
            .as_ref()
            .and_then(|s| s.get("volumeClaimTemplates"))
            .and_then(|s| s.as_sequence())
            .is_some_and(|v| !v.is_empty());
    if let Some(volumes) = pod["volumes"].as_array() {
        for v in volumes {
            if let Some(h) = v.get("hostPath") {
                validate_public_path(
                    h["path"]
                        .as_str()
                        .ok_or("hostPath needs an absolute path")?,
                )?;
                required = true;
            }
        }
    }
    for field in ["initContainers", "containers"] {
        if let Some(containers) = pod[field].as_array() {
            for c in containers {
                if let Some(s) = c.get("securityContext").filter(|v| !v.is_null()) {
                    let s: crate::security::SecurityContext =
                        serde_json::from_value(s.clone()).map_err(|_| "invalid securityContext")?;
                    required |= dangerous(Some(&s));
                }
                if let Some(mounts) = c["volumeMounts"].as_array() {
                    for m in mounts {
                        validate_container_path(
                            m["mountPath"]
                                .as_str()
                                .ok_or("volumeMount needs mountPath")?,
                        )?;
                    }
                }
            }
        }
    }
    Ok(required)
}
fn clean(path: &str) -> Result<PathBuf, String> {
    let p = Path::new(path);
    if !p.is_absolute()
        || path.contains(':')
        || path.chars().any(char::is_control)
        || path.contains("//")
        || path.split('/').any(|p| matches!(p, "." | ".."))
        || p.components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err("host/mount path must be an unambiguous absolute path without traversal or bind options".into());
    }
    Ok(p.to_path_buf())
}
pub fn validate_container_path(path: &str) -> Result<(), String> {
    clean(path).map(|_| ())
}
fn reserved_roots() -> Vec<PathBuf> {
    let mut roots: Vec<_> = [
        "/dev",
        "/proc",
        "/sys",
        "/run",
        "/var/run",
        "/root",
        "/home",
        "/etc/ssh",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/kubernetes",
        "/var/lib/royak/storage",
        "/var/lib/royak/exec-admission",
        "/var/lib/docker",
        "/var/lib/containerd",
    ]
    .into_iter()
    .map(PathBuf::from)
    .collect();
    roots.push(PathBuf::from(crate::reconcile::royak_data_dir()));
    if let Ok(home) = std::env::var("HOME") {
        roots.push(Path::new(&home).join(".kube"));
    }
    if let Ok(state) = std::env::var("ROYAK_STATE") {
        if Path::new(&state).is_absolute() {
            roots.push(PathBuf::from(state));
        }
    }
    if let Ok(socket) = std::env::var("DOCKER_HOST") {
        if let Some(path) = socket.strip_prefix("unix://") {
            roots.push(PathBuf::from(path));
        }
    }
    roots
}
fn overlaps(a: &Path, b: &Path) -> bool {
    a.starts_with(b) || b.starts_with(a)
}
pub fn validate_public_path(path: &str) -> Result<(), String> {
    let candidate = clean(path)?;
    if reserved_roots().iter().any(|r| overlaps(&candidate, r)) {
        return Err(
            "host path overlaps a reserved node/storage/control path; hostaccess cannot publish it"
                .into(),
        );
    }
    Ok(())
}
fn resolved(path: &Path) -> Result<PathBuf, String> {
    let mut normal = PathBuf::from("/");
    for part in resolved_depth(path, 0)?.components() {
        match part {
            Component::Normal(p) => normal.push(p),
            Component::ParentDir => {
                normal.pop();
                if normal.as_os_str().is_empty() {
                    normal.push("/");
                }
            }
            Component::RootDir | Component::CurDir => (),
            _ => return Err("invalid resolved host path".into()),
        }
    }
    Ok(normal)
}
fn resolved_depth(path: &Path, depth: u8) -> Result<PathBuf, String> {
    if depth > 40 {
        return Err("host path symlink resolution exceeded bound".into());
    }
    let mut at = path;
    let mut suffix = Vec::new();
    loop {
        match std::fs::canonicalize(at) {
            Ok(mut p) => {
                for s in suffix.iter().rev() {
                    p.push(s);
                }
                return Ok(p);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // canonicalize also reports NotFound for a dangling symlink.
                // Do not mistake that existing alias for a fresh path: it may
                // point to a reserved storage directory not created yet.
                if std::fs::symlink_metadata(at).is_ok_and(|m| m.file_type().is_symlink()) {
                    let target =
                        std::fs::read_link(at).map_err(|_| "cannot inspect host path alias")?;
                    let target = if target.is_absolute() {
                        target
                    } else {
                        at.parent().ok_or("invalid alias parent")?.join(target)
                    };
                    let mut p = resolved_depth(&target, depth + 1)?;
                    for s in suffix.iter().rev() {
                        p.push(s);
                    }
                    return Ok(p);
                }
                suffix.push(
                    at.file_name()
                        .ok_or("cannot resolve host path")?
                        .to_os_string(),
                );
                at = at.parent().ok_or("cannot resolve host path")?;
            }
            Err(_) => {
                return Err(
                    "host path resolution is unavailable; refusing an unknown mount source".into(),
                )
            }
        }
    }
}
pub fn validate_resolved_public_path(path: &str) -> Result<(), String> {
    validate_public_path(path)?;
    let candidate = resolved(Path::new(path))?;
    let roots = reserved_roots()
        .iter()
        .map(|r| resolved(r))
        .collect::<Result<Vec<_>, _>>()?;
    for r in &roots {
        if overlaps(&candidate, r) {
            return Err("host path resolves into a reserved node/storage/control path".into());
        }
    }
    #[cfg(target_os = "linux")]
    {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open("/proc/self/mountinfo")
            .map_err(|_| "cannot inspect mount aliases")?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read mount aliases")?;
        if bytes.len() > 1024 * 1024 {
            return Err("mount alias inventory exceeds bound".into());
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| "invalid mount alias inventory")?;
        validate_mount_aliases(&candidate, &roots, &parse_mounts(text)?)?;
    }
    Ok(())
}
/// Fixed native-publication denial for legacy Docker/internal scratch paths.
/// This does NOT grant public hostaccess or relax its broader reserved roots.
/// Internal legacy VCT/projected paths keep their existing separate contract.
pub(crate) fn reject_native_publication_source(path:&str)->Result<(),String>{
    let candidate=clean(path)?;
    let protected=PathBuf::from("/var/lib/royak/storage/mounts");
    if overlaps(&candidate,&protected){return Err("legacy/control source overlaps native publication".into());}
    let candidate=resolved(&candidate)?;let protected=resolved(&protected)?;
    if overlaps(&candidate,&protected){return Err("legacy/control source aliases native publication".into());}
    #[cfg(target_os="linux")]
    {
        use std::io::Read;
        let mut bytes=Vec::new();
        std::fs::File::open("/proc/self/mountinfo").map_err(|_|"native alias census unavailable")?
            .take(1024*1024+1).read_to_end(&mut bytes).map_err(|_|"native alias census incomplete")?;
        if bytes.len()>1024*1024{return Err("native alias census exceeds existing bound".into());}
        let text=std::str::from_utf8(&bytes).map_err(|_|"native alias census malformed")?;
        validate_mount_aliases(&candidate,&[protected],&parse_mounts(text)?)?;
    }
    // Ordinary legacy-only proxy mode is NOT a Linux namespace attestation.
    // Genuine native publication always requires its separate actual source.
    Ok(())
}

#[cfg(test)]
mod native_publication_alias_regressions{
    use super::*;
    #[test]
    fn native_source_alias_subset_does_not_reclassify_ordinary_internal_scratch(){
        let protected=vec![PathBuf::from("/var/lib/royak/storage/mounts")];
        let census=parse_mounts("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 8:1 /var/lib/royak/storage/mounts /srv/native-alias rw - ext4 /dev/sda1 rw\n3 1 8:1 / /mirror rw - ext4 /dev/sda1 rw\n").unwrap();
        for path in ["/srv/native-alias","/srv/native-alias/dataset","/srv","/mirror/var/lib/royak/storage/mounts/x"]{
            assert!(validate_mount_aliases(Path::new(path),&protected,&census).is_err(),"{path}");
        }
        for path in ["/home/royak/pods/a/ordinary/configmap-settings","/home/royak/pvc/a/old","/srv/ordinary"]{
            validate_mount_aliases(Path::new(path),&protected,&census).unwrap();
        }
        // DATA mountinfo only; no filesystem access, mount owner or grant.
    }
}
#[derive(Clone)]
struct Mount {
    device: String,
    root: PathBuf,
    point: PathBuf,
}
fn mount_path(text: &str) -> Result<PathBuf, String> {
    let mut out = Vec::new();
    let mut it = text.as_bytes().iter().copied();
    while let Some(c) = it.next() {
        if c != b'\\' {
            out.push(c);
            continue;
        }
        let a = it.next().ok_or("incomplete mount path escape")?;
        let b = it.next().ok_or("incomplete mount path escape")?;
        let c = it.next().ok_or("incomplete mount path escape")?;
        if ![a, b, c].into_iter().all(|v| (b'0'..=b'7').contains(&v)) {
            return Err("invalid mount path escape".into());
        }
        let n = ((a - b'0') as u16) * 64 + ((b - b'0') as u16) * 8 + (c - b'0') as u16;
        if n == 0 || n > 255 {
            return Err("invalid mount path byte".into());
        }
        out.push(n as u8);
    }
    let p =
        PathBuf::from(String::from_utf8(out).map_err(|_| "non-UTF8 mount path is unsupported")?);
    if !p.is_absolute() {
        return Err("non-absolute mount path".into());
    }
    Ok(p)
}
fn parse_mounts(text: &str) -> Result<Vec<Mount>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let (left, right) = line.split_once(" - ").ok_or("malformed mount inventory")?;
        let fields: Vec<_> = left.split_whitespace().collect();
        if fields.len() < 6 || right.split_whitespace().count() < 3 {
            return Err("incomplete mount inventory".into());
        }
        let (major, minor) = fields[2].split_once(':').ok_or("invalid mount device")?;
        if major.parse::<u32>().is_err() || minor.parse::<u32>().is_err() {
            return Err("invalid mount device".into());
        }
        let filesystem = right
            .split_whitespace()
            .next()
            .ok_or("missing mount filesystem")?;
        let root = if filesystem == "nsfs" && !fields[3].starts_with('/') {
            // Linux exposes namespace objects as `net:[inode]`, not directory
            // roots. Keep their exact opaque identity; do not ignore the row
            // or treat an unrelated relative path as an ordinary mount root.
            let (kind, inode) = fields[3].split_once(":[").ok_or("invalid nsfs root")?;
            let inode = inode.strip_suffix(']').ok_or("invalid nsfs root")?;
            if ![
                "net",
                "mnt",
                "pid",
                "pid_for_children",
                "user",
                "uts",
                "ipc",
                "cgroup",
                "time",
                "time_for_children",
            ]
            .contains(&kind)
                || inode.is_empty()
                || !inode.bytes().all(|b| b.is_ascii_digit())
                || inode.parse::<u64>().ok().filter(|v| *v > 0).is_none()
            {
                return Err("invalid nsfs identity".into());
            }
            PathBuf::from(format!("/@royak-opaque-nsfs/{kind}/{inode}"))
        } else {
            mount_path(fields[3])?
        };
        out.push(Mount {
            device: fields[2].into(),
            root,
            point: mount_path(fields[4])?,
        });
    }
    if out.is_empty() {
        return Err("missing mount inventory is not an empty alias set".into());
    }
    Ok(out)
}
fn validate_mount_aliases(
    candidate: &Path,
    protected: &[PathBuf],
    mounts: &[Mount],
) -> Result<(), String> {
    for path in protected {
        let matches: Vec<_> = mounts
            .iter()
            .filter(|m| path.starts_with(&m.point))
            .collect();
        let depth = matches
            .iter()
            .map(|m| m.point.components().count())
            .max()
            .ok_or("reserved path has no mount identity")?;
        let best: Vec<_> = matches
            .into_iter()
            .filter(|m| m.point.components().count() == depth)
            .collect();
        let first = best[0];
        if best
            .iter()
            .any(|m| m.device != first.device || m.root != first.root)
        {
            return Err("ambiguous reserved mount identity".into());
        }
        let physical = first.root.join(
            path.strip_prefix(&first.point)
                .map_err(|_| "invalid reserved mount mapping")?,
        );
        let mut coordinates = vec![(first.device.as_str(), physical)];
        // A protected directory can CONTAIN a different filesystem (Docker
        // namespace objects, a private storage mount, etc.). Aliases of these
        // descendants must also be protected, not just aliases on its parent
        // filesystem.
        coordinates.extend(
            mounts
                .iter()
                .filter(|m| m.point.starts_with(path))
                .map(|m| (m.device.as_str(), m.root.clone())),
        );
        for (device, physical) in coordinates {
            for m in mounts.iter().filter(|m| m.device == device) {
                // Translate the protected filesystem coordinate through EVERY
                // mount, not just canonical path strings. A bind of a subdirectory
                // and a parent directory containing such a bind are both covered.
                let alias = if let Ok(relative) = physical.strip_prefix(&m.root) {
                    Some(m.point.join(relative))
                } else if m.root.starts_with(&physical) {
                    Some(m.point.clone())
                } else {
                    None
                };
                if alias.is_some_and(|alias| overlaps(candidate, &alias)) {
                    return Err(
                        "host path exposes a reserved node/storage/control mount alias".into(),
                    );
                }
            }
        }
    }
    Ok(())
}
pub fn launch_requires(c: &crate::workload::ContainerLaunch) -> bool {
    dangerous(c.security_context.as_ref())
        || c.mounts.iter().any(|m| {
            matches!(
                m.source,
                crate::workload::MountSource::HostPath { .. }
                    | crate::workload::MountSource::StatefulPath { .. }
            )
        })
}
fn launch_binding(
    l: &crate::workload::PodLaunch,
    c: &crate::workload::ContainerLaunch,
) -> Result<String, String> {
    let mut container = serde_json::to_value(c).map_err(|_| "cannot bind host-access launch")?;
    container
        .as_object_mut()
        .ok_or("invalid launch container")?
        .remove("host_access");
    Ok(digest(
        &json!({"contract":1,"phase":"launch","cluster":l.cluster_id,"namespace":l.namespace,"namespace_uid":l.namespace_uid,
        "node":l.node,"kind":l.kind,"owner":l.owner,"pod":l.pod,"template":l.template,"generation":l.generation,"ordinal":l.ordinal,"container":container}),
    ))
}
pub fn issue_launch(l: &mut crate::workload::PodLaunch) -> Result<(), String> {
    let ns = l
        .namespace_uid
        .as_ref()
        .ok_or("launch has no namespace incarnation")?
        .clone();
    let permits = l
        .init_containers
        .iter()
        .chain(l.containers.iter())
        .map(|c| {
            if launch_requires(c) {
                Ok(Some(Permit {
                    version: 1,
                    phase: "launch".into(),
                    namespace_uid: ns.clone(),
                    binding_sha256: launch_binding(l, c)?,
                }))
            } else {
                Ok(None)
            }
        })
        .collect::<Result<Vec<_>, String>>()?;
    for (c, p) in l
        .init_containers
        .iter_mut()
        .chain(l.containers.iter_mut())
        .zip(permits)
    {
        c.host_access = p;
    }
    Ok(())
}
pub fn validate_launch(l: &crate::workload::PodLaunch) -> Result<(), String> {
    let leaf = |s: &str| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.len() <= 512
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    };
    if !crate::store::is_dns_label(&l.namespace)
        || !crate::store::is_dns_subdomain(&l.owner)
        || !leaf(&l.pod)
    {
        return Err("invalid launch identity/path components".into());
    }
    for c in l.init_containers.iter().chain(l.containers.iter()) {
        if !crate::store::is_dns_label(&c.name) || !leaf(&c.docker_name) {
            return Err("invalid launch container identity".into());
        }
        for m in &c.mounts {
            validate_container_path(&m.container_path)?;
            match &m.source {
                crate::workload::MountSource::EmptyDir { name }
                | crate::workload::MountSource::Projected { name, .. }
                    if !crate::store::is_dns_subdomain(name) =>
                {
                    return Err("invalid internal volume path component".into())
                }
                _ => (),
            }
        }
        if !launch_requires(c) && c.host_access.is_none() {
            continue;
        }
        let ns = l
            .namespace_uid
            .as_ref()
            .ok_or("host launch has no namespace incarnation")?;
        check(
            c.host_access
                .as_ref()
                .ok_or("host launch has no server-issued permit")?,
            ns,
            "launch",
            &launch_binding(l, c)?,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn resource(ns: &str, host: bool, cap: bool) -> Resource {
        let mut pod = json!({"containers":[{"name":"main","image":"busybox:1.36","command":["sleep","600"]}]});
        if host {
            pod["volumes"] =
                json!([{"name":"data","hostPath":{"path":"/tmp/royak-authorized-host-test"}}]);
            pod["containers"][0]["volumeMounts"] = json!([{"name":"data","mountPath":"/app/data"}]);
        }
        if cap {
            pod["containers"][0]["securityContext"] = json!({"capabilities":{"add":["SYS_ADMIN"]}});
        }
        crate::spec::parse_yaml(&serde_json::to_string(&json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"app","namespace":ns},"spec":pod})).unwrap()).unwrap().remove(0)
    }
    fn plan(w: &mut DesiredWorld, ns: &str) -> Result<crate::workload::PodLaunch, String> {
        let d = w.deployments[&crate::store::obj_key(ns, "app")].clone();
        crate::workload::plan_pod(
            w,
            &crate::workload::PodSource {
                kind: "deployment",
                namespace: ns,
                owner: "app",
                init_containers: &d.init_containers,
                containers: &d.containers,
                limits: d.resource_limits.as_ref(),
                restart_nonce: d.restart_nonce,
            },
            "rk-app-1",
            if d.stateful { Some(1) } else { None },
            "node-1",
        )
    }
    #[test]
    fn namespace_admin_and_namespaced_hostaccess_rules_are_not_node_rights() {
        let mut w = DesiredWorld::new();
        let id = auth::Identity {
            user: "alice".into(),
            groups: vec![],
        };
        w.rbac_bindings.insert(
            "a/admin".into(),
            crate::reconcile::RbacBinding {
                name: "admin".into(),
                namespace: Some("a".into()),
                role_kind: "ClusterRole".into(),
                role_name: "admin".into(),
                subjects: vec![crate::reconcile::RbacSubject {
                    kind: "User".into(),
                    name: id.user.clone(),
                    namespace: None,
                }],
            },
        );
        assert!(auth::authorize(
            &w,
            &id,
            &auth::Attrs::new("create", "pods", None, Some("a"), None)
        ));
        assert!(!allowed(&w, &id));
        let mut global = w.rbac_bindings["a/admin"].clone();
        global.namespace = None;
        w.rbac_bindings.insert("global".into(), global);
        assert!(allowed(&w, &id));
        w.rbac_bindings.remove("global");
        assert!(!allowed(&w, &id));
    }
    #[test]
    fn untrusted_resource_cannot_issue_host_path_or_capability_permits() {
        for (host, cap) in [(true, false), (false, true), (true, true)] {
            let mut w = DesiredWorld::new();
            let before = serde_json::to_value(w.to_state()).unwrap();
            assert!(w
                .apply_with_host_access(&resource("a", host, cap), false)
                .unwrap_err()
                .contains("cluster-scoped"));
            assert_eq!(serde_json::to_value(w.to_state()).unwrap(), before);
        }
        let mut w = DesiredWorld::new();
        w.apply_with_host_access(&resource("a", false, false), false)
            .unwrap();
        assert!(!has_authority(&w.to_state()));
        plan(&mut w, "a").unwrap();
    }
    #[test]
    fn desired_permit_is_persistent_content_cluster_owner_and_namespace_bound() {
        let mut w = DesiredWorld::new();
        w.apply(&resource("a", true, true)).unwrap();
        let state = w.to_state();
        validate_state(&state).unwrap();
        let bytes = crate::persist::encode(&state, &[]).unwrap();
        let decoded = crate::persist::decode(std::str::from_utf8(&bytes).unwrap())
            .unwrap()
            .0;
        validate_state(&decoded).unwrap();
        assert!(has_authority(&decoded));
        for case in 0..5 {
            let mut bad = state.clone();
            match case {
                0 => {
                    bad.deployments.get_mut("a/app").unwrap().containers[0].image =
                        "attacker/image".into()
                }
                1 => {
                    bad.storage_identities
                        .namespaces
                        .insert("a".into(), Uid::new());
                }
                2 => bad.cluster_id.push('x'),
                3 => bad.deployments.get_mut("a/app").unwrap().name = "other".into(),
                _ => {
                    bad.deployments.get_mut("a/app").unwrap().containers[0].volumes[0].0 =
                        "/tmp/other".into()
                }
            }
            assert!(validate_state(&bad).is_err(), "case {case}");
        }
        let mut legacy: Value = serde_json::from_slice(&bytes).unwrap();
        legacy["schemaVersion"] = 4.into();
        legacy["state"].as_object_mut().unwrap().remove("backup_registry");
        legacy["state"].as_object_mut().unwrap().remove("storage_node_directory");
        assert!(crate::persist::decode(&legacy.to_string())
            .err()
            .unwrap()
            .contains("legacy state cannot import host-access"));
    }
    #[test]
    fn loaded_legacy_host_workload_requires_explicit_readmission_before_any_plan() {
        let mut w = DesiredWorld::new();
        w.apply(&resource("a", true, true)).unwrap();
        let mut state = w.to_state();
        state.deployments.get_mut("a/app").unwrap().containers[0].host_access = None;
        let mut loaded = DesiredWorld::from_state(state);
        let certs = loaded.pod_certs.len();
        assert!(plan(&mut loaded, "a")
            .unwrap_err()
            .contains("explicit authorized re-apply"));
        assert_eq!(loaded.pod_certs.len(), certs);
        loaded.apply(&resource("a", true, true)).unwrap();
        plan(&mut loaded, "a").unwrap();
    }
    #[test]
    fn launch_permit_is_bound_to_actual_resolved_plan_and_cannot_be_retargeted() {
        let mut w = DesiredWorld::new();
        w.apply(&resource("a", true, true)).unwrap();
        let p = plan(&mut w, "a").unwrap();
        validate_launch(&p).unwrap();
        assert_eq!(crate::workload::create_path(&p), "/royak/v4/create-pod");
        for case in 0..6 {
            let mut bad = p.clone();
            match case {
                0 => bad.containers[0].host_access = None,
                1 => bad.namespace = "b".into(),
                2 => bad.namespace_uid = Some(Uid::new()),
                3 => bad.node = "other-node".into(),
                4 => bad.containers[0].command = Some(vec!["cat".into(), "/app/data/key".into()]),
                _ => bad.generation += 1,
            }
            assert!(validate_launch(&bad).is_err(), "case {case}");
            assert!(
                crate::workload::launch_pod(&bad).is_err(),
                "refusal must precede Docker IO"
            );
        }
    }
    #[test]
    fn reserved_paths_and_bind_option_injection_cannot_be_granted_even_to_operator() {
        for path in [
            "/",
            "/var/lib/royak",
            "/var/lib/royak/storage/pools/a",
            "/dev/mapper/secret",
            "/proc/1/root",
            "/var/run/docker.sock",
            "/tmp/x:/host",
            "/tmp/../var",
            "/tmp/./x",
            "/tmp/x\n",
        ] {
            assert!(validate_public_path(path).is_err(), "{path}");
        }
        validate_public_path("/srv/approved-app").unwrap();
        assert!(validate_container_path("/app:rw,rshared").is_err());
    }
    #[test]
    fn dangling_storage_symlink_is_not_a_fresh_unreserved_directory() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("royak-host-alias-{}", Uid::new().as_str()));
        std::fs::create_dir(&root).unwrap();
        symlink("/var/lib/royak/storage/does-not-exist", root.join("alias")).unwrap();
        assert!(validate_resolved_public_path(root.join("alias/key").to_str().unwrap()).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn bind_aliases_and_their_parents_are_not_unreserved_public_paths() {
        let mounts=parse_mounts("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 8:1 /var/lib/royak/storage/pools/a /srv/public/alias rw - ext4 /dev/sda1 rw\n3 1 8:1 / /mirror rw - ext4 /dev/sda1 rw\n4 1 8:1 /var/lib/royak/storage /srv/escaped\\040alias rw - ext4 /dev/sda1 rw\n").unwrap();
        let protected = [PathBuf::from("/var/lib/royak/storage")];
        for path in [
            "/srv/public/alias/key",
            "/srv/public",
            "/mirror/var/lib/royak/storage/key",
            "/mirror",
            "/srv/escaped alias",
        ] {
            assert!(
                validate_mount_aliases(Path::new(path), &protected, &mounts).is_err(),
                "{path}"
            );
        }
        for path in ["/srv/app", "/mirror/tmp/app"] {
            validate_mount_aliases(Path::new(path), &protected, &mounts).unwrap();
        }
        assert!(parse_mounts("").is_err());
        assert!(parse_mounts("broken").is_err());
    }

    #[test]
    fn real_linux_nsfs_objects_are_not_directory_paths_or_ignored_aliases() {
        let text="1 0 8:1 / / rw - ext4 /dev/sda1 rw\n2 1 0:20 / /run rw - tmpfs tmpfs rw\n443 2 0:4 net:[4026532345] /run/docker/netns/690415840fad rw shared:396 - nsfs nsfs rw\n444 1 0:4 net:[4026532345] /srv/public/net-alias rw - nsfs nsfs rw\n445 1 0:21 / /var/lib/royak/storage/private rw - tmpfs tmpfs rw\n446 1 0:21 / /srv/private-alias rw - tmpfs tmpfs rw\n";
        let mounts = parse_mounts(text).unwrap();
        let protected = vec![
            PathBuf::from("/run"),
            PathBuf::from("/var/lib/royak/storage"),
        ];
        validate_mount_aliases(Path::new("/srv/ordinary"), &protected, &mounts).unwrap();
        for path in ["/srv/public/net-alias", "/srv/public", "/srv/private-alias"] {
            assert!(
                validate_mount_aliases(Path::new(path), &protected, &mounts).is_err(),
                "{path}"
            );
        }
        assert!(parse_mounts(&text.replace("net:[4026532345]", "net:[not-an-inode]")).is_err());
        assert!(parse_mounts(&text.replace("- nsfs nsfs", "- ext4 /dev/sda1")).is_err());
    }
    #[test]
    fn host_launch_and_raft_authority_have_real_crypto_upgrade_barriers() {
        const CHILD: &str = "ROYAK_TEST_HOST_ACCESS_CRYPTO_CHILD";
        if std::env::var(CHILD).as_deref() != Ok("1") {
            let r=std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","host_access::tests::host_launch_and_raft_authority_have_real_crypto_upgrade_barriers","--nocapture"])
                .env(CHILD,"1").env("ROYAK_CLUSTER_SECRET","host-access-isolated-test-secret-0123456789").env_remove("ROYAK_CLUSTER_SECRET_FILE").output().unwrap();
            assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
            return;
        }
        let mut w = DesiredWorld::new();
        w.apply(&resource("a", true, true)).unwrap();
        let p = plan(&mut w, "a").unwrap();
        let sealed = crate::workload::seal_launch(&p).unwrap();
        assert!(auth::unseal_for_cluster(b"royak-pod-launch-v1", &sealed).is_err());
        assert_eq!(crate::workload::unseal_launch(&sealed).unwrap(), p);
        let old = auth::seal_for_cluster(b"royak-pod-launch-v1", &serde_json::to_vec(&p).unwrap())
            .unwrap();
        assert!(crate::workload::unseal_launch(&old)
            .unwrap_err()
            .contains("legacy launch envelope"));
        let state = w.to_state();
        let sealed = crate::raft_node::Sealing::Cluster.seal(&state).unwrap();
        assert!(
            auth::unseal_for_cluster(b"royak-raft-state-v3-storage-identities", &sealed).is_err()
        );
        let mut legacy_state = serde_json::to_value(&state).unwrap();
        legacy_state.as_object_mut().unwrap().remove("backup_registry");
        legacy_state.as_object_mut().unwrap().remove("storage_node_directory");
        let old = auth::seal_for_cluster(
            b"royak-raft-state-v3-storage-identities",
            &serde_json::to_vec(&legacy_state).unwrap(),
        )
        .unwrap();
        assert!(crate::raft_node::Sealing::Cluster
            .unseal(&old)
            .err()
            .unwrap()
            .contains("legacy Raft envelope"));
    }
    #[test]
    fn real_schema4_upgrade_preserves_identity_but_never_mints_a_host_permit() {
        let mut w = DesiredWorld::new();
        w.apply(&resource("a", true, true)).unwrap();
        let mut state = w.to_state();
        state.deployments.get_mut("a/app").unwrap().containers[0].host_access = None;
        let mut value: Value =
            serde_json::from_slice(&crate::persist::encode(&state, &[]).unwrap()).unwrap();
        value["schemaVersion"] = 4.into();
        value["state"].as_object_mut().unwrap().remove("backup_registry");
        value["state"].as_object_mut().unwrap().remove("storage_node_directory");
        let (loaded, _, previous) = crate::persist::decode(&value.to_string()).unwrap();
        assert_eq!(previous, Some(4));
        assert_eq!(loaded.storage_identities, state.storage_identities);
        assert!(!has_authority(&loaded));
        assert!(plan(&mut DesiredWorld::from_state(loaded), "a").is_err());
    }
    fn legacy_vct() -> Resource {
        crate::spec::parse_yaml("kind: StatefulSet\nmetadata: {name: app, namespace: a}\nspec:\n  template:\n    spec:\n      containers:\n      - {name: main, image: busybox:1.36, volumeMounts: [{name: data, mountPath: /data}]}\n  volumeClaimTemplates: [{metadata: {name: data}}]\n").unwrap().remove(0)
    }
    #[test]
    fn legacy_vct_never_silently_selects_a_new_empty_directory_on_upgrade() {
        let mut w = DesiredWorld::new();
        w.apply(&legacy_vct()).unwrap();
        let p = plan(&mut w, "a").unwrap();
        let path = match &p.containers[0].mounts[0].source {
            crate::workload::MountSource::StatefulPath { path, .. } => path,
            _ => panic!("expected legacy stateful path"),
        };
        assert_eq!(
            path,
            &format!("{}/pvc/a/app-data-1", crate::reconcile::royak_data_dir())
        );
    }
    #[test]
    fn legacy_vct_is_node_access_until_real_claim_controller_exists() {
        let r = legacy_vct();
        assert!(resource_requires(&r).unwrap());
        assert!(DesiredWorld::new()
            .apply_with_host_access(&r, false)
            .is_err());
        let mut w = DesiredWorld::new();
        w.apply(&r).unwrap();
        let mut state = w.to_state();
        state.deployments.get_mut("a/app").unwrap().containers[0].host_access = None;
        assert!(plan(&mut DesiredWorld::from_state(state), "a").is_err());
    }
}

