//! On-disk desired state (schema v9; node identities are never backfilled).
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

// Old readers ignore unknown container fields. A version barrier prevents
// downgrade from silently discarding newly enforced security constraints.
pub const SCHEMA_VERSION: u32 = 9;

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
                *v = crate::decrypt_secret_value_strict(v).map_err(|e| {
                    format!(
                        "secret {key} key {k}: {e} — wrong ROYAK_SECRET_KEY / ~/.royak/secret.key?"
                    )
                })?;
            }
        }
    }
    Ok(())
}

fn fsync_dir(path: &str) -> Result<(), String> {
    let dir = std::path::Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let f = std::fs::File::open(dir).map_err(|e| format!("open dir {}: {e}", dir.display()))?;
    f.sync_all()
        .map_err(|e| format!("fsync dir {}: {e}", dir.display()))
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
        f.write_all(bytes)
            .map_err(|e| format!("write {tmp}: {e}"))?;
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
            if !v.is_empty() {
                return Some(v);
            }
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
    state.storage_identities.validate(state)?;
    state.storage_node_directory.validate_state(state)?;
    state.backup_registry.validate_state(state)?;
    crate::host_access::validate_state(state)?;
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
    ns.set(
        "_generation".to_string(),
        state.generation.to_le_bytes().to_vec(),
    );
    for (k, d) in &state.deployments {
        ns.set(
            format!("deployments/{k}"),
            serde_json::to_vec(&serde_json::json!({
                "name": d.name, "namespace": d.namespace, "replicas": d.replicas, "image": d.image,
            }))
            .unwrap_or_default(),
        );
    }
    for (k, s) in &state.services {
        ns.set(
            format!("services/{k}"),
            serde_json::to_vec(&serde_json::json!({
                "name": s.name, "namespace": s.namespace, "type": s.service_type,
            }))
            .unwrap_or_default(),
        );
    }
    let _ = ns.save(&format!("{path}.nrns"));
}

/// Decode a state file's bytes.
pub fn decode(content: &str) -> Result<(DesiredState, Vec<ClusterNode>, Option<u32>), String> {
    let v: serde_json::Value = serde_json::from_str(content).map_err(|e| {
        format!("state file is not valid JSON ({e}); refusing to start with an empty cluster")
    })?;
    if !v.is_object() {
        return Err("state file is not a JSON object; refusing to start".into());
    }
    // The v0/v1 reader is deliberately permissive and would otherwise ignore
    // this new authority field. Inspect it before selecting ANY legacy reader.
    let schema = v.get("schemaVersion").and_then(|n| n.as_u64()).unwrap_or(0);
    if schema <= 7 {
        crate::storage_node_directory::legacy_without_node_authority(v.get("state").unwrap_or(&v))?;
    } else if (8..=SCHEMA_VERSION as u64).contains(&schema) {
        crate::storage_node_directory::Registry::require_explicit(
            v.get("state")
                .and_then(|s| s.get("storage_node_directory"))
                .ok_or("current state lacks explicit node-directory history")?,
        )?;
    }
    if schema <= 6 {
        crate::storage_lifecycle::legacy_without_data_authority(v.get("state").unwrap_or(&v))?;
    }
    if (6..=SCHEMA_VERSION as u64).contains(&schema) {
        let raw = v
            .get("state")
            .and_then(|state| state.get("backup_registry"))
            .ok_or(
                "current/previous backup registry is missing; refusing to infer backup history",
            )?;
        if schema == SCHEMA_VERSION as u64 {
            crate::backup_engine::Registry::require_explicit_state_fields(raw)?;
        } else {
            crate::backup_engine::Registry::require_legacy_precapture_absence(raw)?;
        }
        if schema == 6 {
            crate::backup_engine::Registry::reject_pre_contract_restore(raw)?;
        }
    }
    if schema < 6 {
        if v.get("state").unwrap_or(&v).get("backup_registry")
            .is_some_and(|r| r.get("capture_reservations").is_some())
        {
            return Err("legacy backup schema/domain cannot import pre-capture reservation history".into());
        }
    }
    // Preserve historical raw-domain guard precedence; still reject unbound
    // writer history before ANY typed backup/state or permissive v0/v1 reader.
    crate::storage_pod_writer::reject_unbound_writer_history(v.get("state").unwrap_or(&v))?;
    if schema == SCHEMA_VERSION as u64 {
        crate::backup_engine::Registry::check_current_capture_encoding(content)?;
    }
    if schema < 6 {
        if let Some(raw) = v.get("state").unwrap_or(&v).get("backup_registry") {
            let mut registry: crate::backup_engine::Registry = serde_json::from_value(raw.clone())
                .map_err(|_| "malformed legacy backup registry")?;
            registry.migrate_legacy_empty()?;
        }
    }
    let result = match v.get("schemaVersion").map(|s| s.as_u64()) {
        Some(Some(n)) if (2..=SCHEMA_VERSION as u64).contains(&n) => {
            let file: FileV2 = serde_json::from_value(v)
                .map_err(|e| format!("state file (schema v{n}) is malformed: {e}; refusing to start"))?;
            let mut state = file.state;
            state.generation = file.generation;
            state.cluster_id = file.cluster_id;
            unseal_secrets(&mut state)?;
            Ok((state, file.nodes, if n < SCHEMA_VERSION as u64 { Some(n as u32) } else { None }))
        }
        Some(Some(n)) if n > SCHEMA_VERSION as u64 => Err(format!(
            "state schema v{n} is newer than this binary supports (v{SCHEMA_VERSION}); refusing to downgrade")),
        Some(Some(n)) => {
            let world = crate::load_v1_world(&v)?;
            Ok((migrate_v1(world)?, Vec::new(), Some(n as u32)))
        }
        Some(None) => Err("schemaVersion is not a number; refusing to start".into()),
        None => {
            let world = crate::load_v1_world(&v)?;
            Ok((migrate_v1(world)?, Vec::new(), Some(0)))
        }
    };
    let (mut state, nodes, previous) = result?;
    if previous.is_some_and(|v| v <= 7) {
        // Explicit unenrolled metadata only. No UID/key/boot/node association
        // is derived from old names, replica arrays, ENV or census entries.
        state.storage_node_directory = crate::storage_node_directory::Registry::fresh();
    }
    state.storage_node_directory.validate_state(&state)?;
    if previous.is_some_and(|v| v < 5) && crate::host_access::has_authority(&state) {
        return Err("legacy state cannot import host-access authority".into());
    }
    if previous.is_some_and(|v| v < 4) {
        crate::storage_identity::Identities::migrate(&mut state)?;
    } else {
        state.storage_identities.validate(&state)?;
    }
    if previous.is_some_and(|v| v < 6) {
        state.backup_registry.migrate_legacy_empty()?;
    } else if previous.is_some_and(|v| v < SCHEMA_VERSION) {
        state.backup_registry.migrate_v1_precapture_empty()?;
        if previous == Some(6) {
            state.backup_registry.validate_pre_contract_no_restore()?;
        }
    }
    state.backup_registry.validate_state(&state)?;
    crate::host_access::validate_state(&state)?;
    Ok((state, nodes, previous))
}

/// Convert a world loaded by the v1 reader (maps keyed by bare name) into the
/// namespaced v2 layout. Nothing is dropped: every object keeps its own
/// namespace field, which becomes part of its key.
fn migrate_v1(mut w: DesiredWorld) -> Result<DesiredState, String> {
    // Only load_v1_world's trusted, synthesized empty default is reset here.
    // Raw imported registries were already checked before selecting this reader.
    if w.backup_registry.has_authority()
        || w.backup_registry != crate::backup_engine::Registry::fresh()
    {
        return Err("legacy converter expected a synthesized fresh empty backup registry".into());
    }
    w.backup_registry = crate::backup_engine::Registry::default();
    w.storage_identities = crate::storage_identity::Identities::default();
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
        let key = if k.contains('/') {
            k
        } else {
            obj_key(crate::store::DEFAULT_NS, &k)
        };
        w.pending_rollouts.insert(key, r);
    }
    let mans = std::mem::take(&mut w.manifests);
    for (k, v) in mans {
        w.manifests.insert(k, v);
    }
    let mut s = w.to_state();
    s.cluster_id = LEGACY_CLUSTER_ID.to_string();
    s.generation = s.generation.max(1);
    Ok(s)
}

/// Load the state at `path`. Missing file → fresh empty state. Anything else
/// that cannot be read faithfully → `Err` (the caller must not start).
pub fn load(path: &str) -> Result<Loaded, String> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let (state, nodes, migrated_from) =
                decode(&content).map_err(|e| format!("{path}: {e}"))?;
            Ok(Loaded {
                state,
                nodes,
                fresh: false,
                migrated_from,
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // An older version may have left only the binary copy.
            let nrns = format!("{path}.nrns");
            if let Ok(ns) = crate::neural_state::NeuralState::load(&nrns) {
                if let Some(full) = ns
                    .get("_full")
                    .and_then(|d| String::from_utf8(d.to_vec()).ok())
                {
                    let (state, nodes, migrated_from) =
                        decode(&full).map_err(|e| format!("{nrns}: {e}"))?;
                    return Ok(Loaded {
                        state,
                        nodes,
                        fresh: false,
                        migrated_from: migrated_from.or(Some(1)),
                    });
                }
            }
            let mut state = DesiredWorld::new().to_state();
            state.cluster_id = std::env::var("ROYAK_CLUSTER_ID")
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(crate::auth::derived_cluster_id)
                .unwrap_or_else(new_cluster_id);
            Ok(Loaded {
                state,
                nodes: Vec::new(),
                fresh: true,
                migrated_from: None,
            })
        }
        Err(e) => Err(format!(
            "{path}: cannot read state file: {e}; refusing to start"
        )),
    }
}

/// Export an existing, exclusively owned offline state file. This is NOT a
/// live Raft export or a data-volume backup. Never synthesize a fresh cluster,
/// follow a source symlink or replace an earlier recovery point.
pub fn backup_offline(path: &str, output: &str) -> Result<(), String> {
    use std::io::Read;
    let _owner = try_own(path)?.ok_or_else(|| {
        "offline backup refused: a running server owns the state; use a qualified live export"
            .to_string()
    })?;
    let raft = format!("{path}.raft");
    match std::fs::symlink_metadata(&raft) {
        Ok(_) => return Err("offline backup refused: clustered Raft state is authoritative; a seed-file export is not a cluster backup".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
        Err(e) => return Err(format!("cannot inspect Raft authority: {e}")),
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut source = options
        .open(path)
        .map_err(|e| format!("backup source must exist and be readable: {e}"))?;
    if !source
        .metadata()
        .map_err(|e| format!("backup source metadata: {e}"))?
        .is_file()
    {
        return Err("backup source must be a regular state file".into());
    }
    let mut content = String::new();
    source
        .read_to_string(&mut content)
        .map_err(|e| format!("read backup source: {e}"))?;
    let (state, _, _) = decode(&content)?;
    let bytes = encode(&state, &[])?;
    publish_new(output, &bytes)
}

/// Atomic no-clobber publication on the destination filesystem. A hard-link
/// publish cannot replace a file, directory, dangling symlink or concurrent
/// winner. The temporary file is private and owned exclusively by this call.
fn publish_new(path: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let tmp = format!(
        "{path}.tmp.{}.{:016x}",
        std::process::id(),
        rand::random::<u64>()
    );
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|e| format!("create private backup: {e}"))?;
    let result = (|| {
        file.write_all(bytes)
            .map_err(|e| format!("write backup: {e}"))?;
        file.sync_all().map_err(|e| format!("fsync backup: {e}"))?;
        std::fs::hard_link(&tmp, path)
            .map_err(|e| format!("publish backup without overwriting an existing path: {e}"))?;
        fsync_dir(path)
    })();
    drop(file);
    let cleanup = std::fs::remove_file(&tmp);
    result?;
    cleanup.map_err(|e| format!("backup published but private-temp cleanup failed: {e}"))?;
    fsync_dir(path)
}

fn new_cluster_id() -> String {
    use rand::RngCore;
    let mut b = [0u8; 6];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Keep the pre-migration file next to the migrated one.
pub fn backup_before_migration(path: &str, previous: u32) -> Result<(), String> {
    let bak = format!("{path}.v{}.bak", previous.max(1));
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
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| format!("open {lock_path}: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let op = if block {
            libc::LOCK_EX
        } else {
            libc::LOCK_EX | libc::LOCK_NB
        };
        let rc = unsafe { libc::flock(file.as_raw_fd(), op) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
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
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    impl std::fmt::Display for TmpDir {
        fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    fn tmpdir(tag: &str) -> TmpDir {
        let d = format!(
            "{}/royak-persist-{tag}-{}-{}",
            std::env::temp_dir().display(),
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        std::fs::create_dir_all(&d).unwrap();
        TmpDir(d)
    }

    fn sample() -> DesiredState {
        let mut w = DesiredWorld::new();
        let docs = crate::spec::parse_yaml(
            r#"
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
"#,
        )
        .unwrap();
        for d in &docs {
            w.apply(d).unwrap();
        }
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
        assert!(
            !raw.contains("hunter2"),
            "secret values must be sealed at rest"
        );
        let l = load(&p).unwrap();
        assert!(!l.fresh);
        assert_eq!(l.state.to_canonical_json(), s.to_canonical_json());
        assert_eq!(l.state.deployments["a/web"].replicas, 2);
        assert_eq!(l.state.deployments["b/web"].replicas, 3);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn schema_v3_storage_identity_migration_is_stable_and_keeps_source_bytes() {
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&encode(&sample(), &[]).unwrap()).unwrap();
        legacy["schemaVersion"] = 3.into();
        legacy["state"].as_object_mut().unwrap().remove("backup_registry");
        legacy["state"]
            .as_object_mut()
            .unwrap()
            .remove("storage_identities");
        legacy["state"]
            .as_object_mut()
            .unwrap()
            .remove("storage_node_directory");
        let bytes = serde_json::to_string(&legacy).unwrap();
        let (a, _, old) = decode(&bytes).unwrap();
        let (b, _, _) = decode(&bytes).unwrap();
        assert_eq!(old, Some(3));
        assert_eq!(a.storage_identities, b.storage_identities);
        let d = tmpdir("v3-identities");
        let path = format!("{d}/state.json");
        std::fs::write(&path, &bytes).unwrap();
        backup_before_migration(&path, 3).unwrap();
        save(&path, &a, &[]).unwrap();
        assert_eq!(
            std::fs::read_to_string(format!("{path}.v3.bak")).unwrap(),
            bytes
        );
        assert_eq!(
            load(&path).unwrap().state.storage_identities,
            a.storage_identities
        );
    }

    #[test]
    fn schema_v4_never_regenerates_missing_or_inconsistent_identities() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&encode(&sample(), &[]).unwrap()).unwrap();
        value["state"]
            .as_object_mut()
            .unwrap()
            .remove("storage_identities");
        assert!(decode(&value.to_string()).is_err());
        let mut value: serde_json::Value =
            serde_json::from_slice(&encode(&sample(), &[]).unwrap()).unwrap();
        value["state"]["storage_identities"]["namespaces"]["a"] = "not-a-valid-uid".into();
        assert!(decode(&value.to_string()).is_err());
    }

    #[test]
    fn schema_v2_upgrades_without_losing_security_and_keeps_its_own_backup() {
        let mut w = DesiredWorld::new();
        let yaml = "kind: Deployment\nmetadata: {name: sec}\nspec:\n  template:\n    spec:\n      containers:\n      - {name: c, image: alpine:3.22, securityContext: {runAsUser: 10001, runAsNonRoot: true}}\n";
        for r in crate::spec::parse_yaml(yaml).unwrap() {
            w.apply(&r).unwrap();
        }
        let mut value: serde_json::Value =
            serde_json::from_slice(&encode(&w.to_state(), &[]).unwrap()).unwrap();
        assert_eq!(value["schemaVersion"], SCHEMA_VERSION);
        value["schemaVersion"] = 2.into();
        value["state"].as_object_mut().unwrap().remove("backup_registry");
        value["state"]
            .as_object_mut()
            .unwrap()
            .remove("storage_node_directory");
        let old = serde_json::to_string(&value).unwrap();
        let (state, _, migrated) = decode(&old).unwrap();
        assert_eq!(migrated, Some(2));
        assert_eq!(
            state.deployments["default/sec"].containers[0]
                .security_context
                .as_ref()
                .unwrap()
                .run_as_user,
            Some(10001)
        );
        let dir = tmpdir("v2-security");
        let path = format!("{dir}/state.json");
        std::fs::write(&path, &old).unwrap();
        std::fs::write(format!("{path}.v1.bak"), "earlier v1 backup").unwrap();
        backup_before_migration(&path, 2).unwrap();
        assert_eq!(
            std::fs::read_to_string(format!("{path}.v2.bak")).unwrap(),
            old
        );
        assert_eq!(
            std::fs::read_to_string(format!("{path}.v1.bak")).unwrap(),
            "earlier v1 backup"
        );
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
        assert!(load(&p)
            .err()
            .expect("newer schema must be refused")
            .contains("newer"));
        std::fs::write(&p, "").unwrap();
        assert!(
            load(&p).is_err(),
            "a truncated (empty) file is not an empty cluster"
        );
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
        assert_eq!(
            s.deployments["default/web"].containers[0].env,
            vec!["A=1".to_string()]
        );
        assert_eq!(s.deployments["prod/api"].namespace, "prod");
        assert_eq!(
            s.configmaps["prod/cfg"].data.get("K").map(|s| s.as_str()),
            Some("v")
        );
        assert!(s.services.contains_key("default/web"));
    }

    #[test]
    fn owner_lock_is_exclusive_across_handles() {
        let d = tmpdir("lock");
        let p = format!("{d}/state.json");
        let a = try_own(&p).unwrap();
        assert!(a.is_some());
        assert!(
            try_own(&p).unwrap().is_none(),
            "a second owner must be refused while the first holds it"
        );
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
        assert!(
            again.is_some(),
            "the lock must be free once its owner drops it"
        );
    }

    #[test]
    fn backup_refuses_missing_corrupt_and_clustered_sources() {
        let dir = tmpdir("backup-refuse");
        let path = format!("{dir}/state.json");
        let out = format!("{dir}/backup.json");
        assert!(backup_offline(&path, &out).is_err());
        assert!(!std::path::Path::new(&out).exists());
        std::fs::write(&path, "{broken").unwrap();
        assert!(backup_offline(&path, &out).is_err());
        save(&path, &DesiredWorld::new().to_state(), &[]).unwrap();
        std::fs::create_dir(format!("{path}.raft")).unwrap();
        assert!(backup_offline(&path, &out).unwrap_err().contains("Raft"));
        assert!(!std::path::Path::new(&out).exists());
    }

    #[test]
    fn backup_requires_exclusive_owner() {
        let dir = tmpdir("backup-owner");
        let path = format!("{dir}/state.json");
        let out = format!("{dir}/backup.json");
        save(&path, &DesiredWorld::new().to_state(), &[]).unwrap();
        let _owner = try_own(&path).unwrap().unwrap();
        assert!(backup_offline(&path, &out)
            .unwrap_err()
            .contains("running server"));
        assert!(!std::path::Path::new(&out).exists());
    }

    #[test]
    fn backup_publishes_private_recoverable_state_without_changing_source() {
        std::env::set_var("ROYAK_SECRET_KEY", "11".repeat(32));
        let dir = tmpdir("backup-roundtrip");
        let path = format!("{dir}/state.json");
        let out = format!("{dir}/backup.json");
        let state = sample();
        save(&path, &state, &[]).unwrap();
        let before = std::fs::read(&path).unwrap();
        backup_offline(&path, &out).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(
            load(&out).unwrap().state.to_canonical_json(),
            state.to_canonical_json()
        );
        assert!(!std::fs::read_to_string(&out).unwrap().contains("hunter2"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn backup_never_overwrites_existing_paths() {
        let dir = tmpdir("backup-noclobber");
        let path = format!("{dir}/state.json");
        let out = format!("{dir}/backup.json");
        save(&path, &DesiredWorld::new().to_state(), &[]).unwrap();
        let before = std::fs::read(&path).unwrap();
        std::fs::write(&out, "earlier backup").unwrap();
        assert!(backup_offline(&path, &out).is_err());
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "earlier backup");
        assert!(backup_offline(&path, &path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        #[cfg(unix)]
        {
            let link = format!("{dir}/backup-link");
            std::os::unix::fs::symlink(&out, &link).unwrap();
            assert!(backup_offline(&path, &link).is_err());
            assert!(std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink());
            assert_eq!(std::fs::read_to_string(&out).unwrap(), "earlier backup");
        }
    }

    #[cfg(unix)]
    #[test]
    fn backup_rejects_symlink_source() {
        let dir = tmpdir("backup-source-link");
        let path = format!("{dir}/state.json");
        let link = format!("{dir}/source-link");
        save(&path, &DesiredWorld::new().to_state(), &[]).unwrap();
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(backup_offline(&link, &format!("{dir}/backup.json")).is_err());
    }
    #[test]
    fn genuine_v0_v1_absent_backup_registry_preserves_bytes_and_namespaces() {
        let d = tmpdir("precapture-genuine-legacy");
        for schema in [None, Some(0u32), Some(1u32)] {
            let mut raw = serde_json::json!({
                "namespaces": ["default", "prod"],
                "deployments": [
                    {"name":"web","namespace":"default","replicas":2,"image":"nginx"},
                    {"name":"api","namespace":"prod","replicas":3,"image":"busybox"}
                ],
                "configmaps": [{"name":"cfg","namespace":"prod","data":{"K":"original"}}],
                "services": []
            });
            if let Some(version) = schema {
                raw["schemaVersion"] = version.into();
            }
            assert!(raw.get("backup_registry").is_none());
            let input = raw.to_string();
            let path = format!("{d}/legacy-{}.json", schema.unwrap_or(0));
            std::fs::write(&path, input.as_bytes()).unwrap();
            let loaded = load(&path).unwrap();
            assert_eq!(loaded.migrated_from, Some(schema.unwrap_or(0)));
            assert_eq!(loaded.state.deployments["default/web"].replicas, 2);
            assert_eq!(loaded.state.deployments["prod/api"].replicas, 3);
            assert!(loaded.state.namespaces.iter().any(|n| n == "prod"));
            assert_eq!(loaded.state.configmaps["prod/cfg"].data.get("K").map(String::as_str), Some("original"));
            assert_eq!(loaded.state.backup_registry, crate::backup_engine::Registry::fresh());
            assert!(!loaded.state.backup_registry.has_authority());
            assert_eq!(std::fs::read(&path).unwrap(), input.as_bytes());
        }
        std::fs::remove_dir_all(&d.0).unwrap();
    }

    #[test]
    fn raw_v0_v1_cannot_import_current_empty_registry_with_or_without_new_map() {
        for schema in [None, Some(0u32), Some(1u32)] {
            for with_new_map in [false, true] {
                let mut raw = serde_json::json!({
                    "namespaces": ["default"],
                    "deployments": [],
                    "backup_registry": {"version":2,"repositories":{},"jobs":{}}
                });
                if let Some(version) = schema {
                    raw["schemaVersion"] = version.into();
                }
                if with_new_map {
                    raw["backup_registry"]["capture_reservations"] = serde_json::json!({});
                }
                let input = raw.to_string();
                assert!(decode(&input).is_err());
                assert_eq!(raw.to_string(), input);
            }
        }
    }

}
