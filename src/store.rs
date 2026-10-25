//! Desired-state identity, serialization and the commit path.
//!
//! Three things live here because they have to agree with each other:
//!
//! 1. **Identity.** Namespaced objects are stored under `"{namespace}/{name}"`
//!    ([`obj_key`]); cluster-scoped objects under their bare name. Every store
//!    access goes through these helpers so two namespaces can hold objects with
//!    the same name without one replacing the other.
//! 2. **Serialization.** [`DesiredState`] is the complete, lossless desired
//!    state (everything a write can change). It is what is persisted to disk,
//!    what Raft replicates, and what a candidate mutation is computed on.
//! 3. **Commit.** [`commit`] is the single write path for API mutations: a
//!    mutation runs on a *copy* of the desired state, the result is made durable
//!    (single node: fsync'd file; clustered: quorum-committed Raft entry) and
//!    only then installed into the live world. A failed commit leaves the live
//!    world untouched, so the reconcile loop never acts on a write the client
//!    was told failed.

use crate::reconcile::{self, DesiredWorld};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ─── Identity ──────────────────────────────────────────────────────────────

pub const DEFAULT_NS: &str = "default";

/// Store key of a namespaced object.
pub fn obj_key(ns: &str, name: &str) -> String {
    format!("{ns}/{name}")
}

/// Inverse of [`obj_key`]. A key without a slash is treated as a legacy
/// (pre-namespacing) key in the default namespace.
pub fn split_key(key: &str) -> (&str, &str) {
    key.split_once('/').unwrap_or((DEFAULT_NS, key))
}

/// Namespace of a parsed manifest (defaults to "default").
pub fn ns_of(r: &crate::spec::Resource) -> String {
    r.metadata.namespace.clone().filter(|s| !s.is_empty()).unwrap_or_else(|| DEFAULT_NS.to_string())
}

/// RFC 1123 label: what Kubernetes requires of a namespace name.
pub fn is_dns_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// RFC 1123 subdomain: what Kubernetes requires of most object names.
/// Crucially it never contains `_` or `/`, which Royak uses as separators.
pub fn is_dns_subdomain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.split('.').all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && !part.starts_with('-')
                && !part.ends_with('-')
        })
}

/// Container-name stem for a workload's pods. The default namespace keeps the
/// historical `rk-{name}` so pods created by older versions stay recognisable;
/// other namespaces embed the namespace behind an `_`, a character no valid
/// namespace or object name can contain — so two namespaces never collide.
pub fn pod_stem(ns: &str, name: &str) -> String {
    if ns == DEFAULT_NS { format!("rk-{name}") } else { format!("rk-{ns}_{name}") }
}

/// Which kinds are cluster-scoped (no namespace). Everything else Royak stores
/// is namespaced.
pub fn is_cluster_scoped_kind(kind: &str) -> bool {
    matches!(kind,
        "Namespace" | "PersistentVolume" | "StorageClass" | "IngressClass" | "ClusterRole"
        | "ClusterRoleBinding" | "ValidatingWebhookConfiguration" | "Node" | "Config"
        | "Function" | "Repository" | "Pipeline" | "Guard" | "Operator" | "RbacRole" | "NeuroPod")
}

/// [`is_cluster_scoped_kind`] for REST plural resource names.
pub fn is_cluster_scoped_kind_plural(resource: &str) -> bool {
    matches!(resource,
        "namespaces" | "persistentvolumes" | "storageclasses" | "ingressclasses" | "clusterroles"
        | "clusterrolebindings" | "validatingwebhookconfigurations" | "nodes"
        | "functions" | "repositories" | "pipelines" | "guards" | "operators" | "rbacroles" | "neuropods")
}

// ─── Container ownership ───────────────────────────────────────────────────

pub const LABEL_MANAGED: &str = "royak.managed";
pub const LABEL_CLUSTER: &str = "royak.cluster";
pub const LABEL_NODE: &str = "royak.node";
pub const LABEL_NAMESPACE: &str = "royak.namespace";
pub const LABEL_DEPLOYMENT: &str = "royak.deployment";
pub const LABEL_POD: &str = "royak.pod";
pub const LABEL_ROLE: &str = "royak.role";

/// The node name this process schedules as. `ROYAK_NODE_NAME` wins (needed when
/// several Royak processes share one host / one Docker daemon).
pub fn node_name() -> String {
    static N: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    N.get_or_init(reconcile::local_node_name).clone()
}

/// True if this container belongs to THIS node of THIS cluster and may be
/// managed (counted, restarted, removed) by our reconcile loop.
///
/// New containers carry `royak.cluster` + `royak.node`; only those matching us
/// are ours. Containers created by older versions carry neither: they are
/// adopted only by the default (unnamed) cluster and only if they look like
/// Royak's (the `royak.managed` label or the historical `rk-` name prefix).
/// Anything else on the Docker host — including another Royak instance's pods —
/// is never touched.
pub fn container_is_ours(c: &crate::docker::DockerContainer, cluster_id: &str, node: Option<&str>) -> bool {
    match (c.labels.get(LABEL_CLUSTER), c.labels.get(LABEL_NODE)) {
        // `node` is Some in cluster mode (several nodes may share one Docker
        // daemon); a single node manages every pod of its cluster.
        (Some(cl), Some(n)) => cl == cluster_id && node.map(|me| me == n).unwrap_or(true),
        (Some(cl), None) => cl == cluster_id,
        (None, _) => {
            legacy_adoption_enabled(cluster_id)
                && (c.labels.get(LABEL_MANAGED).map(|v| v == "true").unwrap_or(false)
                    || c.names.iter().any(|n| n.trim_start_matches('/').starts_with("rk-")))
        }
    }
}

/// Legacy (unlabelled) containers are adopted only by a cluster that never had
/// an explicit id — the upgrade path for an existing single-node install.
fn legacy_adoption_enabled(cluster_id: &str) -> bool {
    cluster_id == LEGACY_CLUSTER_ID
}

/// Cluster id assumed for state files written before cluster ids existed.
pub const LEGACY_CLUSTER_ID: &str = "legacy";

/// Pod identity of a managed container.
#[derive(Debug, Clone, PartialEq)]
pub struct PodOwner {
    pub namespace: String,
    pub deployment: String,
    pub pod: String,
    /// "main", "sidecar" or "init".
    pub role: String,
}

/// Resolve which deployment pod a container belongs to, from its labels; for
/// legacy containers without labels, from the historical `rk-{name}-{n}` name
/// in the default namespace (matched against the known deployment names, so
/// `rk-web-api-1` is never mistaken for a pod of `web`).
pub fn pod_owner(c: &crate::docker::DockerContainer, known_default_names: &[&str]) -> Option<PodOwner> {
    let cname = c.names.first().map(|n| n.trim_start_matches('/').to_string()).unwrap_or_default();
    if let Some(dep) = c.labels.get(LABEL_DEPLOYMENT) {
        let role = c.labels.get(LABEL_ROLE).cloned().unwrap_or_else(|| {
            if c.labels.get("royak.init").is_some() { "init".into() } else { "main".into() }
        });
        return Some(PodOwner {
            namespace: c.labels.get(LABEL_NAMESPACE).cloned().unwrap_or_else(|| DEFAULT_NS.to_string()),
            deployment: dep.clone(),
            pod: c.labels.get(LABEL_POD).cloned().unwrap_or_else(|| cname.clone()),
            role,
        });
    }
    // Legacy: rk-{name}-{ordinal}
    let rest = cname.strip_prefix("rk-")?;
    let (stem, ord) = rest.rsplit_once('-')?;
    if ord.is_empty() || !ord.bytes().all(|b| b.is_ascii_digit()) { return None; }
    if !known_default_names.contains(&stem) { return None; }
    Some(PodOwner {
        namespace: DEFAULT_NS.to_string(),
        deployment: stem.to_string(),
        pod: cname.clone(),
        role: "main".into(),
    })
}

// ─── Serializable desired state ────────────────────────────────────────────

fn default_runtime_cfg() -> reconcile::StoredConfig { reconcile::StoredConfig::default() }

/// The complete desired state. BTreeMaps (not HashMaps) so the JSON form is
/// canonical: equal states serialize to equal bytes, which lets the reconcile
/// loop detect "did this tick change desired state" by comparison.
#[derive(Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DesiredState {
    pub generation: u64,
    pub cluster_id: String,
    pub namespaces: Vec<String>,
    pub manifests: BTreeMap<String, serde_json::Value>,
    pub deployments: BTreeMap<String, reconcile::StoredDeployment>,
    pub daemonsets: BTreeMap<String, reconcile::StoredDaemonSet>,
    pub jobs: BTreeMap<String, reconcile::StoredJob>,
    pub cronjobs: BTreeMap<String, reconcile::StoredCronJob>,
    pub hpas: BTreeMap<String, reconcile::StoredHPA>,
    pub services: BTreeMap<String, reconcile::StoredService>,
    pub ingresses: BTreeMap<String, reconcile::StoredIngress>,
    pub ingress_classes: Vec<String>,
    pub network_policies: BTreeMap<String, reconcile::StoredNetworkPolicy>,
    pub resource_quotas: BTreeMap<String, reconcile::StoredResourceQuota>,
    pub limit_ranges: BTreeMap<String, reconcile::StoredLimitRange>,
    pub configmaps: BTreeMap<String, reconcile::StoredConfigMap>,
    pub secrets: BTreeMap<String, reconcile::StoredSecret>,
    pub pvs: BTreeMap<String, reconcile::StoredPV>,
    pub pvcs: BTreeMap<String, reconcile::StoredPVC>,
    pub storage_classes: BTreeMap<String, reconcile::StoredStorageClass>,
    pub pipelines: BTreeMap<String, reconcile::StoredPipeline>,
    pub functions: BTreeMap<String, reconcile::StoredFunction>,
    pub repositories: BTreeMap<String, reconcile::StoredRepository>,
    pub rbac_roles: BTreeMap<String, reconcile::RbacRole>,
    pub rbac_bindings: BTreeMap<String, reconcile::RbacBinding>,
    pub guards: BTreeMap<String, reconcile::Guard>,
    pub operators: BTreeMap<String, reconcile::Operator>,
    pub custom_resources: BTreeMap<String, reconcile::CustomResource>,
    pub admission_webhooks: BTreeMap<String, reconcile::AdmissionWebhook>,
    #[serde(default = "default_runtime_cfg")]
    pub config: reconcile::StoredConfig,
    pub pending_rollouts: BTreeMap<String, reconcile::RolloutState>,
}

fn to_b<V: Clone>(m: &std::collections::HashMap<String, V>) -> BTreeMap<String, V> {
    m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}
fn to_h<V>(m: BTreeMap<String, V>) -> std::collections::HashMap<String, V> {
    m.into_iter().collect()
}

impl DesiredWorld {
    /// Snapshot the desired (persistent, replicated) part of the world.
    pub fn to_state(&self) -> DesiredState {
        let mut ingress_classes: Vec<String> = self.ingress_classes.iter().cloned().collect();
        ingress_classes.sort();
        DesiredState {
            generation: self.generation,
            cluster_id: self.cluster_id.clone(),
            namespaces: self.namespaces.clone(),
            manifests: to_b(&self.manifests),
            deployments: to_b(&self.deployments),
            daemonsets: to_b(&self.daemonsets),
            jobs: to_b(&self.jobs),
            cronjobs: to_b(&self.cronjobs),
            hpas: to_b(&self.hpas),
            services: to_b(&self.services),
            ingresses: to_b(&self.ingresses),
            ingress_classes,
            network_policies: to_b(&self.network_policies),
            resource_quotas: to_b(&self.resource_quotas),
            limit_ranges: to_b(&self.limit_ranges),
            configmaps: to_b(&self.configmaps),
            secrets: to_b(&self.secrets),
            pvs: to_b(&self.pvs),
            pvcs: to_b(&self.pvcs),
            storage_classes: to_b(&self.storage_classes),
            pipelines: to_b(&self.pipelines),
            functions: to_b(&self.functions),
            repositories: to_b(&self.repositories),
            rbac_roles: to_b(&self.rbac_roles),
            rbac_bindings: to_b(&self.rbac_bindings),
            guards: to_b(&self.guards),
            operators: to_b(&self.operators),
            custom_resources: to_b(&self.custom_resources),
            admission_webhooks: to_b(&self.admission_webhooks),
            config: self.config.clone(),
            pending_rollouts: to_b(&self.pending_rollouts),
        }
    }

    /// Replace the desired part of the world with `s`, keeping runtime-only
    /// bookkeeping (events, probe state, node census, certificates).
    pub fn install_state(&mut self, s: DesiredState) {
        self.generation = s.generation;
        self.cluster_id = s.cluster_id;
        self.namespaces = s.namespaces;
        if !self.namespaces.iter().any(|n| n == DEFAULT_NS) {
            self.namespaces.insert(0, DEFAULT_NS.to_string());
        }
        self.manifests = to_h(s.manifests);
        self.deployments = to_h(s.deployments);
        self.daemonsets = to_h(s.daemonsets);
        self.jobs = to_h(s.jobs);
        self.cronjobs = to_h(s.cronjobs);
        self.hpas = to_h(s.hpas);
        self.services = to_h(s.services);
        self.ingresses = to_h(s.ingresses);
        self.ingress_classes = s.ingress_classes.into_iter().collect();
        self.network_policies = to_h(s.network_policies);
        self.resource_quotas = to_h(s.resource_quotas);
        self.limit_ranges = to_h(s.limit_ranges);
        self.configmaps = to_h(s.configmaps);
        self.secrets = to_h(s.secrets);
        self.pvs = to_h(s.pvs);
        self.pvcs = to_h(s.pvcs);
        self.storage_classes = to_h(s.storage_classes);
        self.pipelines = to_h(s.pipelines);
        self.functions = to_h(s.functions);
        self.repositories = to_h(s.repositories);
        self.rbac_roles = to_h(s.rbac_roles);
        self.rbac_bindings = to_h(s.rbac_bindings);
        self.guards = to_h(s.guards);
        self.operators = to_h(s.operators);
        self.custom_resources = to_h(s.custom_resources);
        self.admission_webhooks = to_h(s.admission_webhooks);
        self.config = s.config;
        self.pending_rollouts = to_h(s.pending_rollouts);
    }

    /// A detached world holding only `s` — the scratch copy a mutation runs on.
    pub fn from_state(s: DesiredState) -> DesiredWorld {
        let mut w = DesiredWorld::new();
        w.install_state(s);
        w
    }
}

impl DesiredState {
    /// Canonical JSON (secrets in plaintext — in memory only; see `seal`).
    pub fn to_canonical_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Desired state equality ignoring the generation counter.
    pub fn same_content(&self, other: &DesiredState) -> bool {
        let mut a = self.clone();
        let mut b = other.clone();
        a.generation = 0;
        b.generation = 0;
        a.to_canonical_json() == b.to_canonical_json()
    }
}

// ─── Commit path ───────────────────────────────────────────────────────────

/// Why a commit did not happen. Every variant means the live world is unchanged.
#[derive(Debug)]
pub enum CommitError {
    /// The mutation itself rejected the request (validation, not found, ...).
    Rejected(u16, String),
    /// The change could not be made durable (disk write failed, no quorum).
    Unavailable(String),
    /// This node may not accept writes (Raft follower, file-lease standby).
    NotLeader(Option<u64>),
    /// Proposed to Raft but no quorum confirmed it in time. Raft may still
    /// commit the entry once a quorum is back, so the outcome is unknown —
    /// never reported as success, never as "not applied".
    Unknown(String),
}

/// Serializes commits within the process so read-modify-write cycles never
/// interleave (two concurrent PATCHes both based on the same generation).
pub fn commit_lock() -> &'static std::sync::Mutex<()> {
    static L: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    L.get_or_init(|| std::sync::Mutex::new(()))
}

/// Durability backend for the live process. Set once at startup.
pub enum Durability {
    /// Single node: fsync'd file write is the commit point.
    File { path: String },
    /// Clustered: a quorum-committed Raft entry is the commit point.
    Raft,
}

static DURABILITY: std::sync::OnceLock<Durability> = std::sync::OnceLock::new();

static OWNS_STATE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Set once this process holds the state file's owner lock (single-node
/// server). Without it the file backend refuses every commit.
pub fn set_owns_state(v: bool) {
    OWNS_STATE.store(v, std::sync::atomic::Ordering::Release);
}

pub fn owns_state() -> bool {
    OWNS_STATE.load(std::sync::atomic::Ordering::Acquire)
}

pub fn set_durability(d: Durability) {
    let _ = DURABILITY.set(d);
}

fn durability() -> &'static Durability {
    DURABILITY.get().unwrap_or_else(|| {
        static FALLBACK: std::sync::OnceLock<Durability> = std::sync::OnceLock::new();
        FALLBACK.get_or_init(|| Durability::File { path: crate::state_path().to_string() })
    })
}

/// Run `mutate` against a copy of the desired state and commit the result.
///
/// The returned value of `mutate` is handed back only after the new state is
/// durable and installed. On any error the live world is exactly as before.
pub fn commit<T>(
    world: &std::sync::Arc<std::sync::RwLock<DesiredWorld>>,
    mutate: impl FnOnce(&mut DesiredWorld) -> Result<T, (u16, String)>,
) -> Result<T, CommitError> {
    let _serial = commit_lock().lock().unwrap_or_else(|e| e.into_inner());
    let base = { world.read().unwrap_or_else(|e| e.into_inner()).to_state() };
    let mut scratch = DesiredWorld::from_state(base.clone());
    let out = mutate(&mut scratch).map_err(|(c, m)| CommitError::Rejected(c, m))?;
    let mut next = scratch.to_state();
    if next.same_content(&base) {
        return Ok(out); // no-op write: nothing to make durable
    }
    next.generation = base.generation + 1;
    commit_state(world, base.generation, next)?;
    Ok(out)
}

/// Make `next` (computed from generation `base_generation`) durable and install
/// it. Used by [`commit`] and by the reconcile loop for its own desired-state
/// changes (HPA scaling, CronJob bookkeeping, ...).
pub fn commit_state(
    world: &std::sync::Arc<std::sync::RwLock<DesiredWorld>>,
    base_generation: u64,
    next: DesiredState,
) -> Result<(), CommitError> {
    match durability() {
        Durability::File { path } => {
            if !owns_state() {
                return Err(CommitError::NotLeader(None));
            }
            let mut w = world.write().unwrap_or_else(|e| e.into_inner());
            if w.generation != base_generation {
                return Err(CommitError::Unavailable(format!(
                    "concurrent modification (generation {} != {base_generation})", w.generation)));
            }
            let nodes = w.nodes_for_save();
            crate::persist::save(path, &next, &nodes).map_err(CommitError::Unavailable)?;
            w.install_state(next);
            Ok(())
        }
        Durability::Raft => crate::raft_node::commit_blocking(base_generation, next),
    }
}

impl DesiredWorld {
    /// Local node census, persisted alongside (not inside) the desired state.
    pub fn nodes_for_save(&self) -> Vec<reconcile::ClusterNode> {
        let mut v: Vec<reconcile::ClusterNode> = self.nodes.values().cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_namespaced_and_reversible() {
        assert_eq!(obj_key("team-a", "web"), "team-a/web");
        assert_eq!(split_key("team-a/web"), ("team-a", "web"));
        assert_eq!(split_key("legacy"), ("default", "legacy"));
    }

    #[test]
    fn pod_stems_never_collide_across_namespaces() {
        // default keeps the historical name; others embed ns behind '_'
        assert_eq!(pod_stem("default", "web"), "rk-web");
        assert_eq!(pod_stem("b", "same"), "rk-b_same");
        // A default-ns object named "b.same" (valid subdomain) must not collide
        // with ns "b" object "same".
        assert_ne!(pod_stem("default", "b.same"), pod_stem("b", "same"));
        assert!(!is_dns_subdomain("b_same"));
        assert!(!is_dns_label("b.c"));
    }

    #[test]
    fn legacy_owner_does_not_confuse_prefix_sharing_names() {
        let c = crate::docker::DockerContainer {
            id: "x".into(), names: vec!["/rk-web-api-1".into()], image: "i".into(),
            state: "running".into(), status: "".into(), labels: Default::default(),
        };
        let o = pod_owner(&c, &["web", "web-api"]).unwrap();
        assert_eq!(o.deployment, "web-api");
        assert!(pod_owner(&c, &["web"]).is_none(), "rk-web-api-1 is not a pod of web");
    }

    #[test]
    fn foreign_containers_are_never_ours() {
        let mut labels = std::collections::HashMap::new();
        labels.insert(LABEL_CLUSTER.to_string(), "other".to_string());
        labels.insert(LABEL_NODE.to_string(), "n1".to_string());
        let c = crate::docker::DockerContainer {
            id: "x".into(), names: vec!["/rk-web-1".into()], image: "i".into(),
            state: "running".into(), status: "".into(), labels,
        };
        assert!(!container_is_ours(&c, "mine", Some("n1")));
        assert!(!container_is_ours(&c, "mine", None));
        let mut mine = c.clone();
        mine.labels.insert(LABEL_CLUSTER.to_string(), "mine".to_string());
        assert!(container_is_ours(&mine, "mine", Some("n1")));
        assert!(!container_is_ours(&mine, "mine", Some("n2")), "another node's pod on a shared daemon is not ours");
        assert!(container_is_ours(&mine, "mine", None));
        let unlabelled = crate::docker::DockerContainer {
            id: "y".into(), names: vec!["/rk-web-1".into()], image: "i".into(),
            state: "running".into(), status: "".into(), labels: Default::default(),
        };
        assert!(!container_is_ours(&unlabelled, "mine", Some("n1")), "explicit clusters never adopt unlabelled pods");
        assert!(container_is_ours(&unlabelled, LEGACY_CLUSTER_ID, None));
        let network_proxy = crate::docker::DockerContainer {
            id: "z".into(), names: vec!["/network-proxy".into()], image: "i".into(),
            state: "running".into(), status: "".into(), labels: Default::default(),
        };
        assert!(!container_is_ours(&network_proxy, LEGACY_CLUSTER_ID, None),
            "substring 'rk-' inside another name is not a Royak pod");
    }

    #[test]
    fn state_roundtrip_is_lossless_and_canonical() {
        let mut w = DesiredWorld::new();
        let docs = crate::spec::parse_yaml(r#"
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: a}
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: c
        image: nginx:alpine
        command: ["sh", "-c", "sleep 1"]
        env: [{name: K, value: v}]
        envFrom: [{configMapRef: {name: cfg}}, {secretRef: {name: sec}}]
---
apiVersion: v1
kind: Secret
metadata: {name: sec, namespace: a}
stringData: {PASSWORD: hunter2}
"#).unwrap();
        for d in &docs { w.apply(d).unwrap(); }
        let s1 = w.to_state();
        let json1 = s1.to_canonical_json();
        let back: DesiredState = serde_json::from_str(&json1).unwrap();
        let w2 = DesiredWorld::from_state(back);
        assert_eq!(w2.to_state().to_canonical_json(), json1);
        let dep = &w2.deployments["a/web"];
        assert_eq!(dep.containers[0].env_from_configmaps, vec!["cfg".to_string()]);
        assert_eq!(dep.containers[0].env_from_secrets, vec!["sec".to_string()]);
    }
}
