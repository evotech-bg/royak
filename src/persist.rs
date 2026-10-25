//! On-disk desired state (schema v2).
//!
//! Contract:
//! * The JSON file at `path` is the single source of truth. `{path}.nrns` is a
//!   derived cache for the brain's search index, written after the JSON and
//!   never read back as state.
//! * A write is: temp file (0600) → fsync → rename over `path` → fsync of the
//!   directory. Only after all four succeed is the write reported successful.
//! * Loading never turns a problem into an empty cluster: an unreadable,
//!   unparsable, newer-schema or undecryptable state file is an error and the
//!   process refuses to start. A missing file is a fresh cluster.
//! * v0/v1 files are migrated on load (keys re-written to `namespace/name`);
//!   the original is kept as `{path}.v1.bak`.
//! * A running server holds an exclusive `flock` on `{path}.lock` for its whole
//!   lifetime. Offline CLI mutations take the same lock and refuse while a
//!   server owns the state; a second server waits as a standby.

use crate::reconcile::{ClusterNode, DesiredWorld};
use crate::store::{DesiredState, LEGACY_CLUSTER_ID};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 2;

#[derive(Serialize, Deserialize)]
struct FileV2 {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    generation: u64,
    #[serde(rename = "clusterId")]
    cluster_id: String,
    state: DesiredState,
    #[serde(default)]
    nodes: Vec<ClusterNode>,
}

/// Result of loading a state file.
pub struct Loaded {
    pub state: DesiredState,
    pub nodes: Vec<ClusterNode>,
    /// The file did not exist: a brand-new cluster.
    pub fresh: bool,
    /// The file was an older schema and has been converted in memory.
    pub migrated_from: Option<u32>,
}

fn seal_secrets(s: &mut DesiredState) -> Result<(), String> {
    for sec in s.secrets.values_mut() {
        for v in sec.data.values_mut() {
            *v = crate::encrypt_secret_value(v)?;
        }
    }
    Ok(())
}

fn unseal_secrets(s: &mut DesiredState) -> Result<(), String> {
    for (key, sec) in s.secrets.iter_mut() {
        for (k, v) in sec.data.iter_mut() {
            if v.starts_with("enc:") {
                *v = crate::decrypt_secret_value_strict(v)
                    .map_err(|e| format!("secret {key} key {k}: {e} — wrong ROYAK_SECRET_KEY / ~/.royak/secret.key?"))?;
            }
        }
    }
    Ok(())
}

fn fsync_dir(path: &str) -> Result<(), String> {
    let dir = std::path::Path::new(path).parent().filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let f = std::fs::File::open(dir).map_err(|e| format!("open dir {}: {e}", dir.display()))?;
    f.sync_all().map_err(|e| format!("fsync dir {}: {e}", dir.display()))
}

/// Atomically replace `path` with `bytes` (tmp + fsync + rename + dir fsync).
pub fn atomic_write(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    if let Some(fail) = test_fail_hook() {
        if path.contains(&fail) {
            return Err(format!("injected write failure for {path}"));
        }
    }
    let tmp = format!("{path}.tmp.{}", std::process::id());
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let res = (|| {
        let mut f = opts.open(&tmp).map_err(|e| format!("create {tmp}: {e}"))?;
        f.write_all(bytes).map_err(|e| format!("write {tmp}: {e}"))?;
        f.sync_all().map_err(|e| format!("fsync {tmp}: {e}"))?;
        drop(f);
        std::fs::rename(&tmp, path).map_err(|e| format!("rename {tmp} → {path}: {e}"))?;
        fsync_dir(path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    res
}

/// `ROYAK_TEST_FAIL_STATE_WRITE=<substring>`: debug builds only — make state
/// writes to matching paths fail, to prove that a failed write is not
/// acknowledged and not acted on.
fn test_fail_hook() -> Option<String> {
    if cfg!(debug_assertions) {
        if let Ok(v) = std::env::var("ROYAK_TEST_FAIL_STATE_WRITE") {
            if !v.is_empty() { return Some(v); }
        }
        let flag = format!("{}.fail-writes", crate::state_path());
        if std::path::Path::new(&flag).exists() {
            return Some(crate::state_path().to_string());
        }
    }
    None
}

/// Encode a state for disk (secrets sealed with the local state key).
pub fn encode(state: &DesiredState, nodes: &[ClusterNode]) -> Result<Vec<u8>, String> {
    let mut sealed = state.clone();
    seal_secrets(&mut sealed)?;
    let file = FileV2 {
        schema_version: SCHEMA_VERSION,
        generation: state.generation,
        cluster_id: state.cluster_id.clone(),
        state: sealed,
        nodes: nodes.to_vec(),
    };
    serde_json::to_vec_pretty(&file).map_err(|e| format!("serialize state: {e}"))
}

/// Durably write the state. Returns only after the data is on disk.
pub fn save(path: &str, state: &DesiredState, nodes: &[ClusterNode]) -> Result<(), String> {
    let bytes = encode(state, nodes)?;
    atomic_write(path, &bytes)?;
    write_cache(path, state);
    Ok(())
}

/// Best-effort derived cache (`.nrns`). Never authoritative, never loaded as state.
fn write_cache(path: &str, state: &DesiredState) {
    let mut ns = crate::neural_state::NeuralState::new();
    ns.set("_generation".to_string(), state.generation.to_le_bytes().to_vec());
    for (k, d) in &state.deployments {
        ns.set(format!("deployments/{k}"), serde_json::to_vec(&serde_json::json!({
            "name": d.name, "namespace": d.namespace, "replicas": d.replicas, "image": d.image,
        })).unwrap_or_default());
    }
    for (k, s) in &state.services {
        ns.set(format!("services/{k}"), serde_json::to_vec(&serde_json::json!({
            "name": s.name, "namespace": s.namespace, "type": s.service_type,
        })).unwrap_or_default());
    }
    let _ = ns.save(&format!("{path}.nrns"));
}

/// Decode a state file's bytes.
pub fn decode(content: &str) -> Result<(DesiredState, Vec<ClusterNode>, Option<u32>), String> {
    let v: serde_json::Value = serde_json::from_str(content)
        .map_err(|e| format!("state file is not valid JSON ({e}); refusing to start with an empty cluster"))?;
    if !v.is_object() {
        return Err("state file is not a JSON object; refusing to start".into());
    }
    match v.get("schemaVersion").map(|s| s.as_u64()) {
        Some(Some(n)) if n == SCHEMA_VERSION as u64 => {
            let file: FileV2 = serde_json::from_value(v)
                .map_err(|e| format!("state file (schema v2) is malformed: {e}; refusing to start"))?;
            let mut state = file.state;
            state.generation = file.generation;
            state.cluster_id = file.cluster_id;
            unseal_secrets(&mut state)?;
            Ok((state, file.nodes, None))
        }
        Some(Some(n)) if n > SCHEMA_VERSION as u64 => Err(format!(
            "state schema v{n} is newer than this binary supports (v{SCHEMA_VERSION}); refusing to downgrade")),
        Some(Some(n)) => {
            let world = crate::load_v1_world(&v)?;
            Ok((migrate_v1(world), Vec::new(), Some(n as u32)))
        }
        Some(None) => Err("schemaVersion is not a number; refusing to start".into()),
        None => {
            let world = crate::load_v1_world(&v)?;
            Ok((migrate_v1(world), Vec::new(), Some(0)))
        }
    }
}

/// Convert a world loaded by the v1 reader (maps keyed by bare name) into the
/// namespaced v2 layout. Nothing is dropped: every object keeps its own
/// namespace field, which becomes part of its key.
fn migrate_v1(mut w: DesiredWorld) -> DesiredState {
    use crate::store::obj_key;
    fn rekey<V>(m: &mut std::collections::HashMap<String, V>, key: impl Fn(&V) -> String) {
        let old = std::mem::take(m);
        for (_, v) in old {
            m.insert(key(&v), v);
        }
    }
    rekey(&mut w.deployments, |d| obj_key(&d.namespace, &d.name));
    rekey(&mut w.daemonsets, |d| obj_key(&d.namespace, &d.name));
    rekey(&mut w.jobs, |d| obj_key(&d.namespace, &d.name));
    rekey(&mut w.cronjobs, |d| obj_key(&d.namespace, &d.name));
    rekey(&mut w.hpas, |d| obj_key(&d.namespace, &d.name));
    rekey(&mut w.services, |d| obj_key(&d.namespace, &d.name));
    rekey(&mut w.ingresses, |d| obj_key(&d.namespace, &d.name));
    rekey(&mut w.network_policies, |d| obj_key(&d.namespace, &d.name));
    rekey(&mut w.resource_quotas, |d| obj_key(&d.namespace, &d.name));
    rekey(&mut w.limit_ranges, |d| obj_key(&d.namespace, &d.name));
    rekey(&mut w.configmaps, |d| obj_key(&d.namespace, &d.name));
    rekey(&mut w.secrets, |d| obj_key(&d.namespace, &d.name));
    rekey(&mut w.pvcs, |d| obj_key(&d.namespace, &d.name));
    rekey(&mut w.custom_resources, |d| obj_key(&d.namespace, &d.name));
    for pvc in w.pvcs.values() {
        if let Some(pv) = pvc.bound_pv.as_ref() {
            let key = obj_key(&pvc.namespace, &pvc.name);
            if let Some(p) = w.pvs.get_mut(pv) {
                if p.bound_to.as_deref() == Some(pvc.name.as_str()) {
                    p.bound_to = Some(key);
                }
            }
        }
    }
    // HPAs in v1 had no namespace field: they target a deployment in the
    // default namespace (the only one v1 could address).
    let rollouts = std::mem::take(&mut w.pending_rollouts);
    for (k, r) in rollouts {
        let key = if k.contains('/') { k } else { obj_key(crate::store::DEFAULT_NS, &k) };
        w.pending_rollouts.insert(key, r);
    }
    let mans = std::mem::take(&mut w.manifests);
    for (k, v) in mans {
        w.manifests.insert(k, v);
    }
    let mut s = w.to_state();
    s.cluster_id = LEGACY_CLUSTER_ID.to_string();
    s.generation = s.generation.max(1);
    s
}

/// Load the state at `path`. Missing file → fresh empty state. Anything else
/// that cannot be read faithfully → `Err` (the caller must not start).
pub fn load(path: &str) -> Result<Loaded, String> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let (state, nodes, migrated_from) = decode(&content).map_err(|e| format!("{path}: {e}"))?;
            Ok(Loaded { state, nodes, fresh: false, migrated_from })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // An older version may have left only the binary copy.
            let nrns = format!("{path}.nrns");
            if let Ok(ns) = crate::neural_state::NeuralState::load(&nrns) {
                if let Some(full) = ns.get("_full").and_then(|d| String::from_utf8(d.to_vec()).ok()) {
                    let (state, nodes, migrated_from) = decode(&full).map_err(|e| format!("{nrns}: {e}"))?;
                    return Ok(Loaded { state, nodes, fresh: false, migrated_from: migrated_from.or(Some(1)) });
                }
            }
            let mut state = DesiredWorld::new().to_state();
            state.cluster_id = std::env::var("ROYAK_CLUSTER_ID").ok().filter(|s| !s.is_empty())
                .or_else(crate::auth::derived_cluster_id)
                .unwrap_or_else(new_cluster_id);
            Ok(Loaded { state, nodes: Vec::new(), fresh: true, migrated_from: None })
        }
        Err(e) => Err(format!("{path}: cannot read state file: {e}; refusing to start")),
    }
}

fn new_cluster_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 6];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Keep the pre-migration file next to the migrated one.
pub fn backup_before_migration(path: &str) -> Result<(), String> {
    let bak = format!("{path}.v1.bak");
    if std::path::Path::new(&bak).exists() {
        return Ok(());
    }
    match std::fs::read(path) {
        Ok(bytes) => atomic_write(&bak, &bytes),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("read {path}: {e}")),
    }
}

// ─── Owner lock ────────────────────────────────────────────────────────────

/// Exclusive ownership of a state file, held for the life of the value.
pub struct OwnerLock {
    #[allow(dead_code)]
    file: std::fs::File,
}

fn try_flock(path: &str, block: bool) -> Result<Option<OwnerLock>, String> {
    let lock_path = format!("{path}.lock");
    let file = std::fs::OpenOptions::new().create(true).write(true).truncate(false).open(&lock_path)
        .map_err(|e| format!("open {lock_path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let op = if block { libc::LOCK_EX } else { libc::LOCK_EX | libc::LOCK_NB };
        let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock || err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Ok(None);
            }
            return Err(format!("flock {lock_path}: {err}"));
        }
    }
    let _ = block;
    Ok(Some(OwnerLock { file }))
}

/// Non-blocking attempt to own the state. `Ok(None)` = another process owns it.
pub fn try_own(path: &str) -> Result<Option<OwnerLock>, String> {
    try_flock(path, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A temporary directory removed on drop, even when the test panics.
    struct TmpDir(String);
    impl Drop for TmpDir {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }
    impl std::fmt::Display for TmpDir {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { f.write_str(&self.0) }
    }

    fn tmpdir(tag: &str) -> TmpDir {
        let d = format!("{}/royak-persist-{tag}-{}-{}", std::env::temp_dir().display(), std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }

    fn sample() -> DesiredState {
        let mut w = DesiredWorld::new();
        let docs = crate::spec::parse_yaml(r#"
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: a}
spec: {replicas: 2, template: {spec: {containers: [{name: c, image: "nginx:alpine"}]}}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: b}
spec: {replicas: 3, template: {spec: {containers: [{name: c, image: "nginx:alpine"}]}}}
---
apiVersion: v1
kind: Secret
metadata: {name: s, namespace: a}
stringData: {PASSWORD: hunter2}
"#).unwrap();
        for d in &docs { w.apply(d).unwrap(); }
        let mut s = w.to_state();
        s.generation = 7;
        s.cluster_id = "c1".into();
        s
    }

    #[test]
    fn roundtrip_is_lossless_and_secrets_are_sealed() {
        std::env::set_var("ROYAK_SECRET_KEY", "11".repeat(32));
        let d = tmpdir("rt");
        let p = format!("{d}/state.json");
        let s = sample();
        save(&p, &s, &[]).unwrap();
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(!raw.contains("hunter2"), "secret values must be sealed at rest");
        let l = load(&p).unwrap();
        assert!(!l.fresh);
        assert_eq!(l.state.to_canonical_json(), s.to_canonical_json());
        assert_eq!(l.state.deployments["a/web"].replicas, 2);
        assert_eq!(l.state.deployments["b/web"].replicas, 3);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }
    }

    #[test]
    fn corrupt_or_newer_state_refuses_instead_of_emptying() {
        let d = tmpdir("bad");
        let p = format!("{d}/state.json");
        std::fs::write(&p, "{\"schemaVersion\": 2, \"generation\": 3, \"clusterId\": \"x\", \"state\": {\"deployments\": 5}}").unwrap();
        assert!(load(&p).is_err());
        std::fs::write(&p, "{ not json").unwrap();
        assert!(load(&p).is_err());
        std::fs::write(&p, "{\"schemaVersion\": 99}").unwrap();
        assert!(load(&p).err().expect("newer schema must be refused").contains("newer"));
        std::fs::write(&p, "").unwrap();
        assert!(load(&p).is_err(), "a truncated (empty) file is not an empty cluster");
    }

    #[test]
    fn undecryptable_secret_refuses() {
        std::env::set_var("ROYAK_SECRET_KEY", "11".repeat(32));
        let s = sample();
        let mut bytes = String::from_utf8(encode(&s, &[]).unwrap()).unwrap();
        // corrupt one sealed value
        let i = bytes.find("enc:").unwrap() + 10;
        let c = if &bytes[i..i + 1] == "0" { "1" } else { "0" };
        bytes.replace_range(i..i + 1, c);
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn missing_file_is_a_fresh_cluster() {
        let d = tmpdir("fresh");
        let l = load(&format!("{d}/none.json")).unwrap();
        assert!(l.fresh);
        assert!(l.state.deployments.is_empty());
        assert_ne!(l.state.cluster_id, LEGACY_CLUSTER_ID);
    }

    #[test]
    fn v1_migration_keeps_every_namespace() {
        // A v1 file as written by the previous release (two namespaces only
        // representable through the object's own namespace field).
        let v1 = r#"{
          "schemaVersion": 1,
          "namespaces": ["default", "prod"],
          "deployments": [
            {"name": "web", "namespace": "default", "replicas": 2, "image": "nginx:alpine",
             "containers": [{"name": "web", "image": "nginx:alpine", "env": ["A=1"]}]},
            {"name": "api", "namespace": "prod", "replicas": 1, "image": "busybox",
             "containers": [{"name": "api", "image": "busybox"}]}
          ],
          "configmaps": [{"name": "cfg", "namespace": "prod", "data": {"K": "v"}}],
          "services": [{"name": "web", "namespace": "default", "type": "ClusterIP", "selector": {"app": "web"}, "ports": []}]
        }"#;
        let (s, _, from) = decode(v1).unwrap();
        assert_eq!(from, Some(1));
        assert_eq!(s.cluster_id, LEGACY_CLUSTER_ID);
        assert_eq!(s.deployments["default/web"].replicas, 2);
        assert_eq!(s.deployments["default/web"].containers[0].env, vec!["A=1".to_string()]);
        assert_eq!(s.deployments["prod/api"].namespace, "prod");
        assert_eq!(s.configmaps["prod/cfg"].data.get("K").map(|s| s.as_str()), Some("v"));
        assert!(s.services.contains_key("default/web"));
    }

    #[test]
    fn owner_lock_is_exclusive_across_handles() {
        let d = tmpdir("lock");
        let p = format!("{d}/state.json");
        let a = try_own(&p).unwrap();
        assert!(a.is_some());
        assert!(try_own(&p).unwrap().is_none(), "a second owner must be refused while the first holds it");
        drop(a);
        // flock belongs to the open file description: a child forked by a
        // concurrent test (e.g. `hostname`) shares it until its exec closes
        // the CLOEXEC fd, so release may be observed a moment later.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut again = try_own(&p).unwrap();
        while again.is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
            again = try_own(&p).unwrap();
        }
        assert!(again.is_some(), "the lock must be free once its owner drops it");
    }
}
