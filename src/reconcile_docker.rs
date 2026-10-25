//! The Docker reconcile tick.
//!
//! Every node, every tick:
//!   * only containers that are provably ours (`store::container_is_ours`:
//!     cluster id + node labels) are ever counted, restarted or removed;
//!   * crashed pods (any container exited/dead) are removed as a whole;
//!   * containers whose owner no longer exists in desired state are removed
//!     (orphan GC, guarded by the generation label so a node that is behind
//!     the scheduler never kills a pod created for a newer state);
//!   * probes run for local pods; DaemonSet pods run locally.
//!
//! The scheduler (single node, or the Raft leader) additionally:
//!   * counts each workload's pods cluster-wide (`placement::workload_pods`)
//!     and creates / removes pods to match, through ONE launch contract
//!     (`workload::plan_pod` + `workload::launch_pod`, locally or on a peer);
//!   * rolls pods whose template hash differs (surge 1, never below the
//!     desired available count; StatefulSets one ordinal at a time);
//!   * runs Jobs, CronJobs, HPA, operators, repositories and pipelines.

use super::*;
use crate::placement::{self, PodView};
use crate::store::{self, obj_key, LABEL_NAMESPACE, LABEL_POD};
use crate::workload::{self, PodSource, LABEL_GENERATION};
use std::collections::HashSet;

/// Events produced off the reconcile thread (remote placement results).
fn deferred_events() -> &'static std::sync::Mutex<Vec<(String, String, String, String, String)>> {
    static Q: std::sync::OnceLock<std::sync::Mutex<Vec<(String, String, String, String, String)>>> = std::sync::OnceLock::new();
    Q.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

fn push_deferred(kind: &str, obj: &str, reason: &str, msg: &str, ty: &str) {
    if let Ok(mut q) = deferred_events().lock() {
        q.push((kind.into(), obj.into(), reason.into(), msg.into(), ty.into()));
    }
}

/// Crash history per workload, for CrashLoopBackOff.
fn crash_history() -> &'static std::sync::Mutex<HashMap<String, Vec<Instant>>> {
    static H: std::sync::OnceLock<std::sync::Mutex<HashMap<String, Vec<Instant>>>> = std::sync::OnceLock::new();
    H.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

const CRASH_WINDOW: Duration = Duration::from_secs(120);
const CRASH_LIMIT: usize = 5;

/// True while a workload crashed CRASH_LIMIT times within CRASH_WINDOW: its
/// pods are not recreated until the oldest crash leaves the window.
fn in_crash_backoff(key: &str) -> bool {
    let mut h = match crash_history().lock() { Ok(h) => h, Err(e) => e.into_inner() };
    let v = h.entry(key.to_string()).or_default();
    v.retain(|t| t.elapsed() < CRASH_WINDOW);
    v.len() >= CRASH_LIMIT
}

fn record_crash(key: &str) {
    if let Ok(mut h) = crash_history().lock() {
        h.entry(key.to_string()).or_default().push(Instant::now());
    }
}

pub(super) fn cname(c: &docker::DockerContainer) -> String {
    c.names.first().map(|n| n.trim_start_matches('/').to_string()).unwrap_or_default()
}

fn short(id: &str) -> &str { &id[..12.min(id.len())] }

/// Labels that make a non-pod container (pipeline stage, function, build)
/// recognisably ours.
pub(super) fn ownership_labels(desired: &DesiredWorld) -> Vec<(String, String)> {
    vec![
        (store::LABEL_MANAGED.to_string(), "true".to_string()),
        (store::LABEL_CLUSTER.to_string(), desired.cluster_id.clone()),
        (store::LABEL_NODE.to_string(), store::node_name()),
    ]
}

/// The node filter for ownership: in cluster mode several nodes may share a
/// Docker daemon (tests, single-host demos) so a node owns only its own pods.
pub(super) fn node_filter() -> Option<String> {
    if crate::raft_node::is_clustered() { Some(store::node_name()) } else { None }
}

/// Containers this node manages.
pub fn our_containers<'a>(desired: &DesiredWorld, actual: &'a [docker::DockerContainer]) -> Vec<&'a docker::DockerContainer> {
    let nf = node_filter();
    actual.iter().filter(|c| store::container_is_ours(c, &desired.cluster_id, nf.as_deref())).collect()
}

/// This node's pods as census entries, with readiness from probe state.
pub fn local_views(desired: &DesiredWorld, ours: &[&docker::DockerContainer]) -> Vec<PodView> {
    let default_deps: Vec<&str> = desired.deployments.values()
        .filter(|d| d.namespace == store::DEFAULT_NS).map(|d| d.name.as_str()).collect();
    let mut views = workload::local_pod_views(ours, &store::node_name(), &default_deps);
    for v in views.iter_mut() {
        if v.kind != "deployment" || !v.running { continue; }
        let Some(dep) = desired.deployments.get(&obj_key(&v.namespace, &v.owner)) else { continue };
        let main = dep.containers.first();
        let started = main.and_then(|c| c.startup_probe.as_ref()).is_none() || desired.startup_ok.contains(&v.pod);
        let ready_ok = main.and_then(|c| c.readiness_probe.as_ref()).is_none() || desired.pod_ready.contains(&v.pod);
        v.ready = started && ready_ok;
    }
    views
}

fn pod_key(c: &docker::DockerContainer, default_deps: &[&str]) -> Option<(String, String)> {
    if let Some(p) = c.labels.get(LABEL_POD) {
        let ns = c.labels.get(LABEL_NAMESPACE).cloned().unwrap_or_else(|| store::DEFAULT_NS.to_string());
        return Some((ns, p.clone()));
    }
    store::pod_owner(c, default_deps).map(|o| (o.namespace, o.pod))
}

fn owner_of(c: &docker::DockerContainer) -> Option<(&'static str, String)> {
    for (kind, label) in [("deployment", store::LABEL_DEPLOYMENT), ("daemonset", "royak.daemonset"), ("job", "royak.job"), ("cronjob", "royak.cronjob")] {
        if let Some(o) = c.labels.get(label) { return Some((kind, o.clone())); }
    }
    None
}

fn owner_exists(desired: &DesiredWorld, kind: &str, ns: &str, owner: &str) -> bool {
    let k = obj_key(ns, owner);
    match kind {
        "deployment" => desired.deployments.contains_key(&k),
        "daemonset" => desired.daemonsets.contains_key(&k),
        "job" => desired.jobs.contains_key(&k),
        "cronjob" => desired.cronjobs.contains_key(&k),
        _ => true,
    }
}

/// Docker-safe node suffix for per-node pod names.
fn node_suffix(node: &str) -> String {
    node.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' { c.to_ascii_lowercase() } else { '-' }).collect()
}

/// Per-tick scheduling context.
struct Ctx {
    me: String,
    local: Vec<PodView>,
    reports: Vec<placement::PeerReport>,
    pending: Vec<placement::Pending>,
    ready_nodes: HashSet<String>,
    node_addr: HashMap<String, String>,
    taken: HashSet<String>,
    clustered: bool,
}

impl Ctx {
    fn pods_of(&self, ns: &str, kind: &str, owner: &str) -> Vec<PodView> {
        placement::workload_pods(ns, kind, owner, &self.local, &self.reports, &self.pending, &self.ready_nodes)
    }

    fn pods_on(&self, node: &str) -> usize {
        if node == self.me { return self.local.len(); }
        self.reports.iter().find(|r| r.node == node).map(|r| r.pods.len()).unwrap_or(0)
            + self.pending.iter().filter(|p| p.view.node == node).count()
    }

    fn next_name(&mut self, stem: &str) -> String {
        let mut i = 1u32;
        loop {
            let n = format!("{stem}-{i}");
            if !self.taken.contains(&n) {
                self.taken.insert(n.clone());
                return n;
            }
            i += 1;
        }
    }
}

fn ordinal_of(pod: &str, stem: &str) -> Option<u32> {
    pod.strip_prefix(stem)?.strip_prefix('-')?.parse().ok()
}

/// Choose where a new pod of (ns, owner) runs.
fn choose_node(ctx: &Ctx, ns: &str, owner: &str, existing: &[PodView], host_local: bool) -> String {
    if !ctx.clustered || host_local {
        return ctx.me.clone();
    }
    let mut candidates: Vec<&String> = ctx.ready_nodes.iter()
        .filter(|n| **n == ctx.me || (ctx.node_addr.contains_key(*n) && !placement::in_backoff(n, ns, owner)))
        .collect();
    candidates.sort_by_key(|n| {
        let mine = existing.iter().filter(|p| &p.node == *n).count();
        (mine, ctx.pods_on(n), (*n).clone())
    });
    candidates.first().map(|s| (*s).clone()).unwrap_or_else(|| ctx.me.clone())
}

/// Remove one pod wherever it runs.
fn remove_view(p: &PodView, ctx: &mut Ctx, ours: &[&docker::DockerContainer], log: &mut Vec<String>) -> bool {
    placement::forget(&p.pod);
    if p.pending {
        return false; // in flight; cannot be removed yet
    }
    if p.node == ctx.me {
        workload::remove_pod(ours, &p.namespace, &p.pod);
        ctx.local.retain(|v| v.pod != p.pod);
        log.push(format!("    [remove] {} ✓", p.pod));
        true
    } else if let Some(addr) = ctx.node_addr.get(&p.node).cloned() {
        match remote_delete_pod(&addr, &p.namespace, &p.pod) {
            Ok(()) => {
                for r in ctx.reports.iter_mut() { r.pods.retain(|v| v.pod != p.pod); }
                log.push(format!("    [remove] {} on {} ✓", p.pod, p.node));
                true
            }
            Err(e) => {
                log.push(format!("    [warn] remove {} on {}: {e}", p.pod, p.node));
                false
            }
        }
    } else {
        log.push(format!("    [warn] {} is on {} whose address is unknown", p.pod, p.node));
        false
    }
}

/// Create one pod (local or remote) through the shared launch contract.
#[allow(clippy::too_many_arguments)]
fn create_pod(
    desired: &mut DesiredWorld,
    ctx: &mut Ctx,
    src: &PodSource,
    pod: &str,
    ordinal: Option<u32>,
    existing: &[PodView],
    log: &mut Vec<String>,
    events: &mut Vec<(String, String, String, String, String)>,
) -> bool {
    let host_local = workload::needs_host_local(src.containers, src.init_containers);
    let node = choose_node(ctx, src.namespace, src.owner, existing, host_local);
    let plan = match workload::plan_pod(desired, src, pod, ordinal, &node) {
        Ok(p) => p,
        Err(e) => {
            log.push(format!("    [error] {pod}: {e}"));
            events.push(("Pod".into(), pod.into(), "FailedCreate".into(), e, "Warning".into()));
            ctx.taken.remove(pod);
            return false;
        }
    };
    let main_image = plan.containers.first().map(|c| c.image.clone()).unwrap_or_default();
    let view = PodView {
        pod: pod.to_string(), node: node.clone(), namespace: src.namespace.to_string(),
        kind: src.kind.to_string(), owner: src.owner.to_string(), template: plan.template.clone(),
        image: main_image, running: false, ready: false, pending: true,
    };
    if node == ctx.me {
        match workload::launch_pod(&plan) {
            Ok(()) => {
                log.push(format!("    [create] {pod} on {node} ✓"));
                events.push(("Pod".into(), pod.into(), "Created".into(), format!("started on {node}"), "Normal".into()));
                ctx.local.push(PodView { running: true, pending: false, ..view });
                true
            }
            Err(e) => {
                log.push(format!("    [error] create {pod}: {e}"));
                events.push(("Pod".into(), pod.into(), "FailedCreate".into(), e, "Warning".into()));
                ctx.taken.remove(pod);
                false
            }
        }
    } else {
        let Some(addr) = ctx.node_addr.get(&node).cloned() else { return false };
        let sealed = match workload::seal_launch(&plan) {
            Ok(s) => s,
            Err(e) => { log.push(format!("    [error] {pod}: cannot seal plan: {e}")); return false; }
        };
        placement::record_dispatch(view.clone());
        ctx.pending.push(placement::Pending { view, dispatched: Instant::now(), acked: None });
        log.push(format!("    [multi-node] {pod} → {node} ({addr})"));
        let (p, n, ns, owner) = (pod.to_string(), node.clone(), src.namespace.to_string(), src.owner.to_string());
        std::thread::spawn(move || {
            let body = serde_json::json!({ "sealed": sealed }).to_string();
            match node_post(&addr, "/royak/v1/create-pod", &body, Duration::from_secs(placement::DISPATCH_TIMEOUT.as_secs())) {
                Ok(_) => placement::mark_acked(&p),
                Err(e) => {
                    placement::forget(&p);
                    placement::backoff_node(&n, &ns, &owner);
                    eprintln!("  ⚠ [multi-node] {p} on {n} failed: {e}");
                    push_deferred("Pod", &p, "FailedPlacement", &format!("node {n}: {e}"), "Warning");
                }
            }
        });
        true
    }
}

// ─── Signed node-to-node HTTP ──────────────────────────────────────────────

/// POST to a peer's node endpoint (signed request, verified response).
pub fn node_post(addr: &str, path: &str, body: &str, timeout: Duration) -> Result<String, String> {
    crate::node_rpc::call("POST", addr, path, body.as_bytes(), timeout).map(|b| String::from_utf8_lossy(&b).into_owned())
}

/// GET from a peer's node endpoint (signed request, verified response).
pub fn node_get(addr: &str, path: &str, timeout: Duration) -> Result<String, String> {
    crate::node_rpc::call("GET", addr, path, b"", timeout).map(|b| String::from_utf8_lossy(&b).into_owned())
}

pub fn remote_delete_pod(addr: &str, ns: &str, pod: &str) -> Result<(), String> {
    let body = serde_json::json!({"namespace": ns, "pod": pod}).to_string();
    node_post(addr, "/royak/v1/delete-pod", &body, Duration::from_secs(20)).map(|_| ())
}

// ─── The tick ──────────────────────────────────────────────────────────────

pub(super) fn reconcile_docker(desired: &mut DesiredWorld, brain: &mut OrinBrain) -> Vec<String> {
    let mut log = Vec::new();
    let mut events: Vec<(String, String, String, String, String)> = Vec::new();
    if let Ok(mut q) = deferred_events().lock() { events.append(&mut q); }

    if desired.cluster_ca.is_none() {
        match crate::net_security::ClusterCA::generate() {
            Ok(ca) => {
                log.push(format!("  [security] Cluster CA generated (fp: {})", ca.fingerprint));
                desired.cluster_ca = Some(ca);
            }
            Err(e) => log.push(format!("  [warn] CA generation failed: {e}")),
        }
    }
    if let Err(e) = docker::ensure_network() {
        log.push(format!("  [warn] network: {e}"));
    }
    for ns in desired.namespaces.clone() {
        if let Err(e) = docker::ensure_namespace_network(&ns) {
            log.push(format!("  [warn] network rk-{ns}: {e}"));
        }
    }
    let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let expired: Vec<String> = desired.pod_certs.iter()
        .filter(|(_, c)| !c.revoked && now_secs > c.expires_at).map(|(p, _)| p.clone()).collect();
    for pod in expired {
        if let Some(c) = desired.pod_certs.get_mut(&pod) { c.revoked = true; }
        events.push(("Pod".into(), pod, "CertExpired".into(), "mTLS certificate expired".into(), "Warning".into()));
    }

    let actual = match docker::list_containers(true) {
        Ok(c) => c,
        Err(e) => {
            log.push(format!("  [error] Docker: {e}"));
            return log;
        }
    };
    let ours = our_containers(desired, &actual);
    let default_deps_owned: Vec<String> = desired.deployments.values()
        .filter(|d| d.namespace == store::DEFAULT_NS).map(|d| d.name.clone()).collect();
    let default_deps: Vec<&str> = default_deps_owned.iter().map(|s| s.as_str()).collect();

    // ── 1. Crashed pods (every node, local) ──
    let mut by_pod: HashMap<(String, String), Vec<&docker::DockerContainer>> = HashMap::new();
    for c in &ours {
        if let Some(k) = pod_key(c, &default_deps) { by_pod.entry(k).or_default().push(c); }
    }
    let mut removed_pods: HashSet<String> = HashSet::new();
    for ((ns, pod), cs) in &by_pod {
        let owner = cs.iter().find_map(|c| owner_of(c)).or_else(|| {
            cs.iter().find_map(|c| store::pod_owner(c, &default_deps)).map(|o| ("deployment", o.deployment))
        });
        let Some((kind, owner)) = owner else { continue };
        if kind == "job" || kind == "cronjob" { continue; } // run-to-completion, handled below
        if kind == "deployment" && desired.deployments.get(&obj_key(ns, &owner)).map(|d| d.paused).unwrap_or(false) {
            continue; // hibernated pods are stopped on purpose
        }
        let crashed: Vec<&&docker::DockerContainer> = cs.iter().filter(|c| c.state == "exited" || c.state == "dead").collect();
        if crashed.is_empty() { continue; }
        // Crash history is per pod template: a fixed template starts fresh
        // instead of waiting out the crashes of the broken one.
        let tmpl = cs.iter().find_map(|c| c.labels.get(crate::workload::LABEL_TEMPLATE).cloned()).unwrap_or_default();
        let wkey = format!("{kind}/{}@{tmpl}", obj_key(ns, &owner));
        record_crash(&wkey);
        let count = desired.restart_count.entry(pod.clone()).or_insert(0);
        *count += 1;
        let detail = crashed.iter().map(|c| format!("{} {}", cname(c), c.status)).collect::<Vec<_>>().join(", ");
        log.push(format!("  [cleanup] {pod}: {detail} — removing pod (restart #{count})"));
        events.push(("Pod".into(), pod.clone(), "BackOff".into(), format!("container exited: {detail}"), "Warning".into()));
        let refs: Vec<&docker::DockerContainer> = cs.to_vec();
        workload::remove_pod(&refs, ns, pod);
        removed_pods.insert(pod.clone());
    }

    // ── 2. Orphans: owner gone from desired state (every node, local) ──
    let mut gc_done: HashSet<String> = HashSet::new();
    for c in &ours {
        let Some((kind, owner)) = owner_of(c) else { continue };
        let ns = c.labels.get(LABEL_NAMESPACE).cloned().unwrap_or_else(|| store::DEFAULT_NS.to_string());
        if owner_exists(desired, kind, &ns, &owner) { continue; }
        let gen: u64 = c.labels.get(LABEL_GENERATION).and_then(|g| g.parse().ok()).unwrap_or(0);
        if gen > desired.generation {
            continue; // created for a newer state than this node has seen yet
        }
        let pod = c.labels.get(LABEL_POD).cloned().unwrap_or_else(|| cname(c));
        if gc_done.insert(pod.clone()) {
            log.push(format!("  [gc] {pod}: {kind}/{owner} no longer exists in namespace {ns} — removing"));
        }
        docker::stop_container(&c.id).ok();
        docker::remove_container(&c.id, true).ok();
        removed_pods.insert(pod.clone());
        placement::forget(&pod);
    }
    for pod in &gc_done {
        let ns_dirs = std::fs::read_dir(format!("{}/pods", royak_data_dir())).ok();
        if let Some(rd) = ns_dirs {
            for e in rd.flatten() { let _ = std::fs::remove_dir_all(e.path().join(pod)); }
        }
    }
    let ours: Vec<&docker::DockerContainer> = ours.into_iter()
        .filter(|c| c.labels.get(LABEL_POD).map(|p| !removed_pods.contains(p)).unwrap_or(!removed_pods.contains(&cname(c))))
        .collect();

    // ── 3. Probes for local deployment pods ──
    run_probes(desired, &ours, &default_deps, &mut log, &mut events);

    let me = store::node_name();
    let clustered = crate::raft_node::is_clustered();
    let mut ctx = {
        let reports = if clustered { placement::peer_reports() } else { Vec::new() };
        let pending = if clustered { placement::pending_entries(&reports) } else { Vec::new() };
        let mut ready_nodes: HashSet<String> = desired.nodes.iter()
            .filter(|(n, node)| **n != me && node.status == NodeStatus::Ready)
            .map(|(n, _)| n.clone()).collect();
        ready_nodes.insert(me.clone());
        let node_addr: HashMap<String, String> = desired.nodes.iter()
            .filter(|(n, _)| **n != me).map(|(n, node)| (n.clone(), node.address.clone())).collect();
        let mut taken: HashSet<String> = actual.iter().map(cname).collect();
        taken.extend(placement::all_known_names(&reports, &pending));
        Ctx { me: me.clone(), local: local_views(desired, &ours), reports, pending, ready_nodes, node_addr, taken, clustered }
    };

    let is_scheduler = crate::raft_node::is_cluster_scheduler();
    let warm = placement::scheduler_ready(is_scheduler);
    let may_schedule = is_scheduler && (!ctx.clustered || warm);

    // ── 4. Deployments (scheduler) ──
    if is_scheduler && !may_schedule {
        log.push("  [scheduler] census warm-up — waiting for every peer's pod report before scheduling".to_string());
    }
    if may_schedule {
        let mut keys: Vec<String> = desired.deployments.keys().cloned().collect();
        keys.sort();
        for key in keys {
            schedule_deployment(desired, &key, &mut ctx, &ours, &mut log, &mut events);
        }
    } else if !is_scheduler {
        log.push("  [follower] not the scheduler — managing local pods only".to_string());
    }

    // ── 5. DaemonSets (every node, one local pod each) ──
    let mut ds_keys: Vec<String> = desired.daemonsets.keys().cloned().collect();
    ds_keys.sort();
    for key in ds_keys {
        let Some(ds) = desired.daemonsets.get(&key).cloned() else { continue };
        let containers = vec![ds.container.clone()];
        let src = PodSource { kind: "daemonset", namespace: &ds.namespace, owner: &ds.name,
            init_containers: &[], containers: &containers, limits: None, restart_nonce: 0 };
        let tmpl = workload::template_hash(&src);
        let mine: Vec<PodView> = ctx.local.iter()
            .filter(|v| v.kind == "daemonset" && v.namespace == ds.namespace && v.owner == ds.name).cloned().collect();
        let stale: Vec<PodView> = mine.iter().filter(|v| !v.template.is_empty() && v.template != tmpl).cloned().collect();
        for v in &stale {
            log.push(format!("  [daemonset] {}: template changed — replacing {}", ds.name, v.pod));
            remove_view(v, &mut ctx, &ours, &mut log);
        }
        if mine.len() > stale.len() {
            continue;
        }
        let base = store::pod_stem(&ds.namespace, &format!("ds-{}", ds.name));
        let pod = if clustered { format!("{base}.{}", node_suffix(&me)) } else { base };
        if ctx.taken.contains(&pod) && !stale.iter().any(|v| v.pod == pod) {
            log.push(format!("  [daemonset] {}: name {pod} is taken by a container Royak does not own", ds.name));
            continue;
        }
        ctx.taken.insert(pod.clone());
        match workload::plan_pod(desired, &src, &pod, None, &me).and_then(|p| workload::launch_pod(&p)) {
            Ok(()) => log.push(format!("  [daemonset] {}: {pod} started on {me}", ds.name)),
            Err(e) => {
                log.push(format!("  [daemonset] {}: {e}", ds.name));
                events.push(("DaemonSet".into(), obj_key(&ds.namespace, &ds.name), "FailedCreate".into(), e, "Warning".into()));
            }
        }
    }

    if may_schedule {
        schedule_jobs(desired, &mut ctx, &mut log, &mut events);
        schedule_cronjobs(desired, &mut ctx, &ours, &mut log, &mut events);
        run_hpa(desired, brain, &ctx, &ours, &mut log);
        run_pause(desired, brain, &ours, &mut log);
        reconcile_operators(desired, &mut log);
        watch_repositories(desired, &mut log);
        run_pipelines(desired, &ours, &mut log);
    }

    // ── Node bookkeeping ──
    let node_logs = check_node_health(desired);
    log.extend(node_logs);
    let running_here = ctx.local.iter().filter(|v| v.running).count() as u32;
    if let Some(local) = desired.nodes.get_mut(&me) {
        local.last_heartbeat = now_secs;
        local.pod_count = running_here;
        local.status = NodeStatus::Ready;
    }

    // ── Anomaly detection / guards (local pods) ──
    observe_and_guard(desired, brain, &ours, may_schedule, &mut log);

    if !desired.network_policies.is_empty() {
        enforce_network_policies(desired, &ours, &mut log);
    }

    for (kind, object, reason, message, event_type) in events {
        desired.record_event(&kind, &object, &reason, &message, &event_type);
    }

    train_brain(desired, brain, &ours, &mut log);
    log
}

fn run_probes(
    desired: &mut DesiredWorld,
    ours: &[&docker::DockerContainer],
    default_deps: &[&str],
    log: &mut Vec<String>,
    events: &mut Vec<(String, String, String, String, String)>,
) {
    let mut startup_passed = Vec::new();
    let mut startup_fail = Vec::new();
    let mut ready_now: HashSet<String> = HashSet::new();
    let mut probed: HashSet<String> = HashSet::new();
    for c in ours.iter().filter(|c| c.state == "running") {
        let role = c.labels.get(store::LABEL_ROLE).map(|s| s.as_str()).unwrap_or("main");
        if role != "main" { continue; }
        let Some(o) = store::pod_owner(c, default_deps) else { continue };
        let Some(dep) = desired.deployments.get(&obj_key(&o.namespace, &o.deployment)) else { continue };
        let Some(main) = dep.containers.first() else { continue };
        let (liveness, readiness, startup) = (main.liveness_probe.as_ref(), main.readiness_probe.as_ref(), main.startup_probe.as_ref());
        if liveness.is_none() && readiness.is_none() && startup.is_none() { continue; }
        let pod = o.pod.clone();
        probed.insert(pod.clone());
        if let Some(probe) = startup {
            if !desired.startup_ok.contains(&pod) {
                if check_probe(short(&c.id), probe) {
                    startup_passed.push(pod.clone());
                    log.push(format!("  [startup] {pod}: started ✓"));
                } else {
                    let key = format!("startup:{pod}");
                    let n = desired.restart_count.get(&key).copied().unwrap_or(0) + 1;
                    startup_fail.push(key);
                    if n >= probe.failure_threshold {
                        log.push(format!("  [startup] {pod}: failed {n}x — restarting"));
                        events.push(("Pod".into(), pod.clone(), "Unhealthy".into(), "Startup probe failed — restarting".into(), "Warning".into()));
                        docker::stop_container(&c.id).ok();
                        docker::start_container(&c.id).ok();
                    }
                }
                continue;
            }
        }
        if let Some(probe) = liveness {
            if !check_probe(short(&c.id), probe) {
                log.push(format!("  [health] {pod}: liveness FAILED — restarting"));
                events.push(("Pod".into(), pod.clone(), "Unhealthy".into(), "Liveness probe failed — restarting".into(), "Warning".into()));
                docker::stop_container(&c.id).ok();
                docker::start_container(&c.id).ok();
                continue;
            }
        }
        match readiness {
            Some(probe) => {
                if check_probe(short(&c.id), probe) { ready_now.insert(pod.clone()); }
                else { log.push(format!("  [ready] {pod}: NOT ready")); }
            }
            None => { ready_now.insert(pod.clone()); }
        }
    }
    for p in startup_passed {
        desired.restart_count.remove(&format!("startup:{p}"));
        desired.startup_ok.insert(p);
    }
    for k in startup_fail { *desired.restart_count.entry(k).or_insert(0) += 1; }
    // Readiness is re-evaluated every tick for probed pods.
    desired.pod_ready.retain(|p| !probed.contains(p));
    desired.pod_ready.extend(ready_now);
}

fn schedule_deployment(
    desired: &mut DesiredWorld,
    key: &str,
    ctx: &mut Ctx,
    ours: &[&docker::DockerContainer],
    log: &mut Vec<String>,
    events: &mut Vec<(String, String, String, String, String)>,
) {
    let Some(dep) = desired.deployments.get(key).cloned() else { return };
    if dep.paused { return; }
    let (ns, name) = (dep.namespace.as_str(), dep.name.as_str());
    let src = PodSource { kind: "deployment", namespace: ns, owner: name,
        init_containers: &dep.init_containers, containers: &dep.containers,
        limits: dep.resource_limits.as_ref(), restart_nonce: dep.restart_nonce };
    let tmpl = workload::template_hash(&src);
    let main_image = dep.containers.first().map(|c| normalize_image(&c.image)).unwrap_or_default();
    let stem = store::pod_stem(ns, name);
    let pods = ctx.pods_of(ns, "deployment", name);
    let is_current = |p: &PodView| p.template == tmpl || (p.template.is_empty() && normalize_image(&p.image) == main_image);
    let (cur, old): (Vec<PodView>, Vec<PodView>) = pods.iter().cloned().partition(|p| is_current(p));
    let target = dep.replicas as usize;
    let surge = match dep.strategy { Some(DeployStrategy::BlueGreen { .. }) => target.max(1), _ => 1 };
    let cur_ready = cur.iter().filter(|p| p.ready && !p.pending).count();
    let old_running = old.iter().filter(|p| p.running && !p.pending).count();

    // Rollout bookkeeping (informational; the template hash drives it).
    if !old.is_empty() && !desired.pending_rollouts.contains_key(key) {
        let old_image = old[0].image.clone();
        let new_image = dep.containers.first().map(|c| c.image.clone()).unwrap_or_default();
        log.push(format!("  [rollout] {key}: started ({} old pods → template {tmpl})", old.len()));
        events.push(("Deployment".into(), key.to_string(), "RolloutStarted".into(), format!("{old_image} → {new_image}"), "Normal".into()));
        desired.pending_rollouts.insert(key.to_string(), RolloutState {
            old_image, new_image, total_replicas: dep.replicas, old_pods: Default::default(), new_pods_created: 0,
        });
    } else if old.is_empty() && cur_ready >= target && desired.pending_rollouts.remove(key).is_some() {
        log.push(format!("  [rollout] {key}: COMPLETE ✓"));
        events.push(("Deployment".into(), key.to_string(), "RolloutComplete".into(), format!("{target} pods on template {tmpl}"), "Normal".into()));
    }

    // ── create ──
    let missing = target.saturating_sub(cur.len());
    let room = if old.is_empty() || dep.stateful { missing } else { (target + surge).saturating_sub(cur.len() + old.len()).min(missing) };
    let wkey = format!("deployment/{key}@{tmpl}");
    if room > 0 && in_crash_backoff(&wkey) {
        log.push(format!("  [CrashLoopBackOff] {key}: {CRASH_LIMIT} crashes within {}s — holding re-creation", CRASH_WINDOW.as_secs()));
        events.push(("Deployment".into(), key.to_string(), "CrashLoopBackOff".into(), "pods keep crashing; re-creation paused".into(), "Warning".into()));
    } else if room > 0 {
        if let Err(reason) = desired.check_quota(ns, room as u32) {
            log.push(format!("  [quota] {key}: BLOCKED — {reason}"));
            events.push(("Deployment".into(), key.to_string(), "QuotaExceeded".into(), reason, "Warning".into()));
        } else if dep.stateful {
            // Lowest missing ordinal, only once every lower ordinal is Ready,
            // and never while an old-template pod still exists.
            if old.is_empty() {
                let existing: HashSet<u32> = pods.iter().filter_map(|p| ordinal_of(&p.pod, &stem)).collect();
                let ready: HashSet<u32> = pods.iter().filter(|p| p.ready && !p.pending).filter_map(|p| ordinal_of(&p.pod, &stem)).collect();
                match next_statefulset_ordinal(&existing, &ready, dep.replicas) {
                    Some(ord) => {
                        let pod = format!("{stem}-{ord}");
                        if ctx.taken.contains(&pod) && !pods.iter().any(|p| p.pod == pod) {
                            log.push(format!("  [statefulset] {key}: {pod} is taken by a container Royak does not own"));
                        } else {
                            ctx.taken.insert(pod.clone());
                            log.push(format!("  [scale] {key}: creating ordinal {ord}"));
                            create_pod(desired, ctx, &src, &pod, Some(ord), &pods, log, events);
                        }
                    }
                    None if existing.len() < target => log.push(format!("  [statefulset] {key}: holding — previous ordinal not Ready yet")),
                    None => {}
                }
            }
        } else {
            log.push(format!("  [scale] {key}: {} → {target} (+{room})", cur.len()));
            events.push(("Deployment".into(), key.to_string(), "ScalingUp".into(), format!("{} → {target}", cur.len()), "Normal".into()));
            let mut all = pods.clone();
            for _ in 0..room {
                let pod = ctx.next_name(&stem);
                if create_pod(desired, ctx, &src, &pod, None, &all, log, events) {
                    let node = ctx.local.iter().find(|v| v.pod == pod).map(|v| v.node.clone())
                        .or_else(|| ctx.pending.iter().find(|p| p.view.pod == pod).map(|p| p.view.node.clone()))
                        .unwrap_or_default();
                    all.push(PodView { pod, node, namespace: ns.into(), kind: "deployment".into(), owner: name.into(),
                        template: tmpl.clone(), image: String::new(), running: false, ready: false, pending: true });
                }
            }
        }
    }

    // ── scale down (current-template excess) ──
    if cur.len() > target {
        let mut victims: Vec<PodView> = cur.iter().filter(|p| !p.pending).cloned().collect();
        victims.sort_by_key(|p| (p.ready, std::cmp::Reverse(ordinal_of(&p.pod, &stem).unwrap_or(0))));
        let excess = cur.len() - target;
        log.push(format!("  [scale] {key}: {} → {target} (-{excess})", cur.len()));
        events.push(("Deployment".into(), key.to_string(), "ScalingDown".into(), format!("{} → {target}", cur.len()), "Normal".into()));
        for v in victims.into_iter().take(excess) {
            remove_view(&v, ctx, ours, log);
        }
    }

    // ── retire old-template pods without dropping below the target ──
    if !old.is_empty() {
        if dep.stateful {
            let all_ready = pods.iter().all(|p| p.ready && !p.pending);
            if all_ready || target == 0 {
                if let Some(v) = old.iter().max_by_key(|p| ordinal_of(&p.pod, &stem).unwrap_or(0)) {
                    log.push(format!("  [rollout] {key}: replacing ordinal {}", v.pod));
                    remove_view(v, ctx, ours, log);
                }
            } else {
                log.push(format!("  [rollout] {key}: waiting for all ordinals to be Ready"));
            }
        } else {
            let removable = if target == 0 { old.len() } else { (cur_ready + old_running).saturating_sub(target) };
            let mut victims: Vec<PodView> = old.iter().filter(|p| !p.pending).cloned().collect();
            victims.sort_by_key(|p| p.running);
            for v in victims.iter().take(removable) {
                log.push(format!("  [rollout] {key}: retiring {} (old template)", v.pod));
                remove_view(v, ctx, ours, log);
            }
            if removable == 0 {
                log.push(format!("  [rollout] {key}: {cur_ready}/{target} new pods ready, {old_running} old still serving"));
            }
        }
    }

    if room == 0 && cur.len() == target && old.is_empty() {
        let ready = cur.iter().filter(|p| p.ready).count();
        log.push(format!("  [ok] {key}: {ready}/{target} ready"));
    }
}

fn schedule_jobs(desired: &mut DesiredWorld, ctx: &mut Ctx, log: &mut Vec<String>, events: &mut Vec<(String, String, String, String, String)>) {
    let mut keys: Vec<String> = desired.jobs.keys().cloned().collect();
    keys.sort();
    for key in keys {
        let Some(job) = desired.jobs.get(&key).cloned() else { continue };
        let pods = ctx.pods_of(&job.namespace, "job", &job.name);
        if !pods.is_empty() {
            let done = pods.iter().all(|p| !p.running && !p.pending);
            log.push(format!("  [ok] job/{key}: {}", if done { "completed" } else { "running" }));
            continue;
        }
        let containers = vec![job.container.clone()];
        let src = PodSource { kind: "job", namespace: &job.namespace, owner: &job.name,
            init_containers: &[], containers: &containers, limits: None, restart_nonce: 0 };
        let pod = store::pod_stem(&job.namespace, &format!("job-{}", job.name));
        if ctx.taken.contains(&pod) {
            log.push(format!("  [job] {key}: {pod} is taken by a container Royak does not own"));
            continue;
        }
        ctx.taken.insert(pod.clone());
        log.push(format!("  [job] {key}: starting"));
        create_pod(desired, ctx, &src, &pod, None, &pods, log, events);
    }
}

fn schedule_cronjobs(desired: &mut DesiredWorld, ctx: &mut Ctx, ours: &[&docker::DockerContainer], log: &mut Vec<String>, events: &mut Vec<(String, String, String, String, String)>) {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut keys: Vec<String> = desired.cronjobs.keys().cloned().collect();
    keys.sort();
    for key in keys {
        let Some(cron) = desired.cronjobs.get(&key).cloned() else { continue };
        // Keep the three most recent finished runs on this node.
        let mut finished: Vec<&PodView> = ctx.local.iter()
            .filter(|v| v.kind == "cronjob" && v.namespace == cron.namespace && v.owner == cron.name && !v.running).collect();
        finished.sort_by(|a, b| b.pod.cmp(&a.pod));
        for v in finished.iter().skip(3) {
            workload::remove_pod(ours, &v.namespace, &v.pod);
        }
        let interval_mins: u64 = cron.schedule.split_whitespace().next()
            .and_then(|s| s.trim_start_matches("*/").parse().ok()).unwrap_or(5);
        let due = cron.last_run.map(|last| now.saturating_sub(last) > interval_mins * 60).unwrap_or(true);
        if !due { continue; }
        let containers = vec![cron.container.clone()];
        let src = PodSource { kind: "cronjob", namespace: &cron.namespace, owner: &cron.name,
            init_containers: &[], containers: &containers, limits: None, restart_nonce: 0 };
        let pod = format!("{}-{now}", store::pod_stem(&cron.namespace, &format!("cron-{}", cron.name)));
        ctx.taken.insert(pod.clone());
        log.push(format!("  [cronjob] {key}: triggering ({})", cron.schedule));
        let existing = ctx.pods_of(&cron.namespace, "cronjob", &cron.name);
        create_pod(desired, ctx, &src, &pod, None, &existing, log, events);
        if let Some(c) = desired.cronjobs.get_mut(&key) { c.last_run = Some(now); }
    }
}

fn run_hpa(desired: &mut DesiredWorld, brain: &mut OrinBrain, ctx: &Ctx, ours: &[&docker::DockerContainer], log: &mut Vec<String>) {
    let hpa_now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut actions: Vec<(String, u32, String)> = Vec::new();
    for (hpa_key, hpa) in desired.hpas.iter() {
        let dkey = obj_key(&hpa.namespace, &hpa.deployment);
        let Some(dep) = desired.deployments.get(&dkey) else { continue };
        // CPU is sampled from the pods on this node (Docker stats are local).
        let local: Vec<&PodView> = ctx.local.iter()
            .filter(|v| v.kind == "deployment" && v.namespace == hpa.namespace && v.owner == hpa.deployment && v.running).collect();
        let samples: Vec<f32> = local.iter().filter_map(|v| {
            ours.iter().find(|c| c.labels.get(LABEL_POD) == Some(&v.pod) && c.labels.get(store::LABEL_ROLE).map(|r| r == "main").unwrap_or(true))
                .and_then(|c| docker::container_stats_peek(short(&c.id)).ok()).map(|(cpu, _)| cpu)
        }).collect();
        let avg_cpu = if samples.is_empty() { 0.0 } else { samples.iter().sum::<f32>() / samples.len() as f32 };
        brain.record_load(&dkey, avg_cpu, dep.replicas);
        let current = dep.replicas;
        let trend = brain.trend(&dkey);
        let since = hpa.last_scaled.map(|t| hpa_now.saturating_sub(t)).unwrap_or(u64::MAX);
        match hpa_decision(current, avg_cpu, hpa.target_cpu, hpa.min_replicas, hpa.max_replicas, since, HPA_STABILIZATION_SECS) {
            Some(t) => {
                log.push(format!("  [hpa] {dkey}: CPU {avg_cpu:.0}% (target {:.0}%) → {current} → {t} (trend: {trend})", hpa.target_cpu));
                actions.push((dkey, t, hpa_key.clone()));
            }
            None => log.push(format!("  [hpa] {dkey}: CPU {avg_cpu:.0}% — {current} replicas ok (trend: {trend})")),
        }
    }
    for (dkey, t, hkey) in actions {
        if let Some(d) = desired.deployments.get_mut(&dkey) { d.replicas = t; }
        if let Some(h) = desired.hpas.get_mut(&hkey) { h.last_scaled = Some(hpa_now); }
    }
}

fn run_pause(desired: &mut DesiredWorld, brain: &OrinBrain, ours: &[&docker::DockerContainer], log: &mut Vec<String>) {
    let keys: Vec<String> = desired.deployments.keys().cloned().collect();
    for key in keys {
        let Some(dep) = desired.deployments.get(&key) else { continue };
        let threshold = match dep.pause_after_idle { Some(t) if t > 0 => t, _ => continue };
        if dep.paused {
            log.push(format!("  [pause] {key}: hibernated 💤"));
            continue;
        }
        let pods: Vec<&&docker::DockerContainer> = ours.iter().filter(|c| c.state == "running"
            && c.labels.get(store::LABEL_DEPLOYMENT) == Some(&dep.name)
            && c.labels.get(LABEL_NAMESPACE).map(|s| s.as_str()).unwrap_or(store::DEFAULT_NS) == dep.namespace).collect();
        let idle = !pods.is_empty() && pods.iter().all(|c| docker::container_stats_peek(short(&c.id)).map(|(cpu, _)| cpu < 1.0).unwrap_or(false));
        let ticks = brain.ticks;
        let d = desired.deployments.get_mut(&key).expect("present");
        if !idle {
            d.idle_since = None;
            continue;
        }
        let since = *d.idle_since.get_or_insert(ticks);
        let idle_secs = (ticks - since) * 5;
        if idle_secs >= threshold {
            log.push(format!("  [pause] {key}: idle {idle_secs}s — hibernating"));
            for c in &pods { docker::stop_container(&c.id).ok(); }
            d.paused = true;
        }
    }
}

fn watch_repositories(desired: &mut DesiredWorld, log: &mut Vec<String>) {
    let triggers: Vec<(String, String)> = desired.repositories.iter()
        .filter_map(|(n, r)| r.pipeline.as_ref().map(|p| (n.clone(), p.clone()))).collect();
    for (repo_name, pipeline) in triggers {
        let Some(repo) = desired.repositories.get(&repo_name).cloned() else { continue };
        let head = if let Some(path) = &repo.path {
            std::process::Command::new("git").args(["rev-parse", "HEAD"]).current_dir(path).output().ok()
                .and_then(|o| String::from_utf8(o.stdout).ok()).map(|s| s.trim().to_string())
        } else if let Some(url) = &repo.url {
            std::process::Command::new("git").args(["ls-remote", url, &format!("refs/heads/{}", repo.branch)]).output().ok()
                .and_then(|o| String::from_utf8(o.stdout).ok()).and_then(|s| s.split_whitespace().next().map(|h| h.to_string()))
        } else { None };
        let Some(commit) = head.filter(|c| !c.is_empty()) else { continue };
        if repo.last_commit.as_deref() == Some(commit.as_str()) { continue; }
        log.push(format!("  [repo] {repo_name}: new commit {}", &commit[..8.min(commit.len())]));
        if let Some(r) = desired.repositories.get_mut(&repo_name) { r.last_commit = Some(commit); }
        if desired.pipelines.contains_key(&pipeline) {
            match start_pipeline(desired, &pipeline) {
                Ok(id) => log.push(format!("  [repo] triggered pipeline/{pipeline} (run #{id})")),
                Err(e) => log.push(format!("  [repo] trigger failed: {e}")),
            }
        }
    }
}

fn observe_and_guard(desired: &mut DesiredWorld, brain: &mut OrinBrain, ours: &[&docker::DockerContainer], may_schedule: bool, log: &mut Vec<String>) {
    let targets: Vec<(String, String)> = ours.iter().filter(|c| c.state == "running")
        .map(|c| (cname(c), short(&c.id).to_string())).collect();
    let handles: Vec<_> = targets.into_iter()
        .map(|(n, id)| std::thread::spawn(move || (n, docker::container_stats_peek(&id)))).collect();
    for h in handles {
        if let Ok((n, Ok((cpu, mem)))) = h.join() { brain.observe(&n, cpu, mem, 0); }
    }
    for (pod, kind, value, threshold) in brain.detect_anomalies() {
        log.push(format!("  [ANOMALY] {pod}: {kind} {value:.1} vs baseline {threshold:.1}"));
        if !may_schedule { continue; }
        let alert_fns: Vec<String> = desired.functions.values()
            .filter(|f| f.webhook_triggers.iter().any(|t| t.contains("alert") || t.contains("notify")))
            .map(|f| f.name.clone()).collect();
        for f in alert_fns {
            match invoke_function(desired, &f) {
                Ok(r) => log.push(format!("    [alert] → {f}: {r}")),
                Err(e) => log.push(format!("    [alert] → {f} failed: {e}")),
            }
        }
        let rules: Vec<(String, String)> = desired.guards.values()
            .flat_map(|g| g.rules.iter().filter(|r| match r.when.as_str() {
                "anomaly" | "high_cpu" => kind == "CPU",
                "high_memory" => kind == "MEM",
                "pod_crash" => kind == "RESTART",
                w => w == kind,
            }).map(|r| (g.name.clone(), r.action.clone()))).collect();
        let container = ours.iter().find(|c| cname(c) == pod).copied();
        for (guard, action) in rules {
            match action.as_str() {
                "restart" => if let Some(c) = container {
                    docker::stop_container(&c.id).ok();
                    docker::start_container(&c.id).ok();
                    log.push(format!("    [guard/{guard}] restarted {pod} ✓"));
                },
                "scale_up" => if let Some(c) = container {
                    if let Some(dep) = c.labels.get(store::LABEL_DEPLOYMENT) {
                        let ns = c.labels.get(LABEL_NAMESPACE).cloned().unwrap_or_else(|| store::DEFAULT_NS.to_string());
                        if let Some(d) = desired.deployments.get_mut(&obj_key(&ns, dep)) {
                            d.replicas += 1;
                            log.push(format!("    [guard/{guard}] scaled {ns}/{dep} to {} ✓", d.replicas));
                        }
                    }
                },
                other => if let Some(cmd) = desired.guards.get(&guard).and_then(|g| g.hooks.get(other)).cloned() {
                    log.push(format!("    [guard/{guard}] hook: {}", safe_exec_hook(&cmd)));
                },
            }
        }
    }
}

fn train_brain(desired: &DesiredWorld, brain: &mut OrinBrain, ours: &[&docker::DockerContainer], log: &mut Vec<String>) {
    let pods: Vec<crate::brain::PodState> = ours.iter().filter(|c| c.state == "running").map(|c| {
        let (cpu, mem) = docker::container_stats_peek(short(&c.id)).unwrap_or((0.0, 0.0));
        crate::brain::PodState {
            id: short(&c.id).to_string(), name: cname(c), node: "local".into(),
            status: crate::brain::PodStatus::Running, cpu_pct: cpu, mem_mb: mem, restarts: 0, age_secs: 0, image: c.image.clone(),
        }
    }).collect();
    if !pods.is_empty() {
        let desired_states: Vec<crate::brain::DesiredState> = desired.deployments.values().map(|d| crate::brain::DesiredState {
            name: d.name.clone(), replicas: d.replicas, image: d.image.clone(),
            cpu_limit: d.resource_limits.as_ref().and_then(|r| r.cpu_limit).unwrap_or(1.0),
            mem_limit: d.resource_limits.as_ref().and_then(|r| r.mem_limit).unwrap_or(512) as f32,
        }).collect();
        let cs = crate::brain::ClusterState { pods, nodes: vec![], desired: desired_states };
        let decision = brain.tick(&cs);
        let target = brain.decisions_to_target(&cs, &decision.actions);
        let loss = brain.train_step(&cs, &target, 0.001);
        if brain.train_steps % 10 == 0 {
            log.push(format!("  [brain] trained: step={}, loss={loss:.4}", brain.train_steps));
        }
    }
    if brain.train_steps > 0 && brain.train_steps % 50 == 0 && brain.save_weights(".royak-brain.bin").is_ok() {
        log.push(format!("  [brain] weights saved (step={})", brain.train_steps));
    }
}

/// A finished container succeeded iff it exited with status 0.
fn exited_ok(c: &docker::DockerContainer) -> bool {
    c.state == "exited" && c.status.starts_with("Exited (0)")
}

/// Pipeline runs — execute stages as Jobs in DAG order.
fn run_pipelines(desired: &mut DesiredWorld, ours: &[&docker::DockerContainer], log: &mut Vec<String>) {

    // Pre-pass: advance in-flight background BUILD stages. Builds run off-thread
    // (not as containers), so the container-based completion detection never
    // fires for them — poll the build registry directly and update their status.
    {
        let mut updates: Vec<(usize, String, StageStatus, String)> = Vec::new();
        for (ri, run) in desired.pipeline_runs.iter().enumerate() {
            let pipeline = match desired.pipelines.get(&run.pipeline) { Some(p) => p, None => continue };
            for s in pipeline.stages.iter().filter(|s| s.action.as_deref() == Some("build")) {
                let running = run.stage_status.iter().any(|(n, st)| n == &s.name && *st == StageStatus::Running);
                if !running { continue; }
                let tag = s.tag.clone().unwrap_or_else(|| format!("royak-{}:{}", run.pipeline, run.run_id));
                let job = format!("rk-build-{}-{}-{}", run.pipeline, run.run_id, s.name);
                match docker::poll_build(&job) {
                    docker::BuildPoll::Done(Ok(_)) => {
                        docker::clear_build(&job);
                        updates.push((ri, s.name.clone(), StageStatus::Succeeded,
                            format!("  [pipeline] {}#{}: stage '{}' built {tag} ✓", run.pipeline, run.run_id, s.name)));
                    }
                    docker::BuildPoll::Done(Err(e)) => {
                        docker::clear_build(&job);
                        let short: String = e.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or(&e).chars().take(200).collect();
                        updates.push((ri, s.name.clone(), StageStatus::Failed,
                            format!("  [pipeline] {}#{}: stage '{}' ✗ build failed: {short}", run.pipeline, run.run_id, s.name)));
                    }
                    docker::BuildPoll::NotStarted => {
                        // Process restarted mid-build; the in-memory job is gone.
                        // Reset to Pending so the stage rebuilds (crash-safety).
                        updates.push((ri, s.name.clone(), StageStatus::Pending,
                            format!("  [pipeline] {}#{}: stage '{}' build lost (restart) → retrying", run.pipeline, run.run_id, s.name)));
                    }
                    docker::BuildPoll::Running => {}
                }
            }
        }
        for (ri, sname, st, msg) in updates {
            if let Some(run_mut) = desired.pipeline_runs.get_mut(ri) {
                for (n, s) in run_mut.stage_status.iter_mut() { if n == &sname { *s = st.clone(); } }
            }
            log.push(msg);
        }
    }

    let mut run_idx = 0;
    while run_idx < desired.pipeline_runs.len() {
        let run = &desired.pipeline_runs[run_idx];
        let pipeline_name = run.pipeline.clone();
        let run_id = run.run_id;

        let pipeline = match desired.pipelines.get(&pipeline_name) {
            Some(p) => p,
            None => { run_idx += 1; continue; }
        };

        if run.is_complete() {
            let all_ok = run.stage_status.iter().all(|(_, s)| matches!(s, StageStatus::Succeeded | StageStatus::Skipped));
            let status = if all_ok { "SUCCEEDED" } else { "FAILED" };
            log.push(format!("  [pipeline] {pipeline_name}#{run_id}: {status} ✓"));
            run_idx += 1;
            continue;
        }

        // Find next runnable stage
        let next_stage_name = run.next_runnable();
        if let Some(stage_name) = next_stage_name {
            // Check if dependencies are met
            let stage_def = pipeline.stages.iter().find(|s| s.name == stage_name);
            let deps_met = if let Some(sd) = stage_def {
                if let Some(dep) = &sd.depends_on {
                    run.stage_status.iter().any(|(n, s)| n == dep && *s == StageStatus::Succeeded)
                } else {
                    true
                }
            } else {
                true
            };

            // Check if dependency FAILED → skip this stage
            let dep_failed = if let Some(sd) = stage_def {
                if let Some(dep) = &sd.depends_on {
                    run.stage_status.iter().any(|(n, s)| n == dep && *s == StageStatus::Failed)
                } else {
                    false
                }
            } else {
                false
            };

            if dep_failed {
                // Mark as skipped
                if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                    for (n, s) in run_mut.stage_status.iter_mut() {
                        if n == &stage_name { *s = StageStatus::Skipped; }
                    }
                }
                log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' SKIPPED (dependency failed)"));
                continue; // check next stage in same tick
            }

            if !deps_met {
                // Check if the dependency is currently running as a container
                let dep_name = stage_def.and_then(|s| s.depends_on.as_ref()).unwrap();
                let job_name = format!("rk-pipe-{pipeline_name}-{run_id}-{dep_name}");
                let dep_running = ours.iter().any(|c|
                    c.names.iter().any(|n| n.trim_start_matches('/') == job_name) && c.state == "running");
                let dep_exited = ours.iter().find(|c|
                    c.names.iter().any(|n| n.trim_start_matches('/') == job_name) && c.state == "exited");

                if let Some(exited) = dep_exited {
                    // Dep finished — its exit code decides success.
                    let ok = exited_ok(exited);
                    let dep_name = dep_name.clone();
                    if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                        for (n, s) in run_mut.stage_status.iter_mut() {
                            if *n == dep_name { *s = if ok { StageStatus::Succeeded } else { StageStatus::Failed }; }
                        }
                    }
                    log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{dep_name}' {}", if ok { "completed ✓" } else { "FAILED ✗" }));
                    continue; // re-evaluate this run
                } else if dep_running {
                    log.push(format!("  [pipeline] {pipeline_name}#{run_id}: waiting for '{dep_name}'..."));
                }
                run_idx += 1;
                continue;
            }

            // Check conditional (if:)
            if let Some(sd) = stage_def {
                if let Some(cond) = &sd.if_condition {
                    let skip = match cond.as_str() {
                        "always" => false,
                        "failure" => {
                            // Only run on prior failure
                            !run.stage_status.iter().any(|(_, s)| *s == StageStatus::Failed)
                        }
                        c if c.starts_with("branch") => {
                            // Simple branch check: "branch == main"
                            // Look up repo branch from any linked repository
                            let target_branch = c.split("==").nth(1).map(|s| s.trim()).unwrap_or("main");
                            let current_branch = desired.repositories.values()
                                .next().map(|r| r.branch.as_str()).unwrap_or("main");
                            current_branch != target_branch
                        }
                        _ => false,
                    };
                    if skip {
                        if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                            for (n, s) in run_mut.stage_status.iter_mut() {
                                if n == &stage_name { *s = StageStatus::Skipped; }
                            }
                        }
                        log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' SKIPPED (condition: {cond})"));
                        continue;
                    }
                }
            }

            // Execute the stage (with matrix expansion)
            if let Some(sd) = stage_def {
                if let Some(action) = &sd.action {
                    // Action stage (e.g., "apply")
                    if action == "apply" {
                        if let Some(file) = &sd.file {
                            log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' → apply {file}"));
                            match spec::parse_file(file) {
                                Ok(resources) => {
                                    for r in &resources {
                                        match desired.apply(&r) {
                                            Ok(msg) => log.push(format!("    ✓ {msg}")),
                                            Err(e) => log.push(format!("    ✗ {e}")),
                                        }
                                    }
                                    if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                        for (n, s) in run_mut.stage_status.iter_mut() {
                                            if n == &stage_name { *s = StageStatus::Succeeded; }
                                        }
                                    }
                                }
                                Err(e) => {
                                    log.push(format!("    ✗ apply failed: {e}"));
                                    if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                        for (n, s) in run_mut.stage_status.iter_mut() {
                                            if n == &stage_name { *s = StageStatus::Failed; }
                                        }
                                    }
                                }
                            }
                        }
                    } else if action == "build" {
                        // Build an image from a git context (PaaS: source → image).
                        // The build runs on a background thread so it never blocks
                        // the reconcile loop; we poll it across ticks like a Job.
                        let job = format!("rk-build-{pipeline_name}-{run_id}-{stage_name}");
                        let ctx_name = sd.context.clone();
                        let dockerfile = sd.dockerfile.clone().unwrap_or_else(|| "Dockerfile".to_string());
                        let tag = sd.tag.clone().unwrap_or_else(|| format!("royak-{pipeline_name}:{run_id}"));
                        let build_args = sd.build_args.clone();
                        // `sd` / `pipeline` are not used past this point in this arm.
                        match docker::poll_build(&job) {
                            docker::BuildPoll::NotStarted => {
                                let branch = desired.repositories.values().next()
                                    .map(|r| r.branch.clone()).unwrap_or_else(|| "main".to_string());
                                // Default context = the pipeline's first linked repo.
                                let ctx = ctx_name.or_else(|| desired.repositories.keys().next().cloned());
                                match ctx {
                                    None => {
                                        log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' ✗ build: no context (set stage.context or register a repo)"));
                                        if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                            for (n, s) in run_mut.stage_status.iter_mut() {
                                                if n == &stage_name { *s = StageStatus::Failed; }
                                            }
                                        }
                                    }
                                    Some(cn) => match resolve_build_context(desired, &cn, &branch) {
                                        Ok(dir) => {
                                            log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' → build {tag} from {dir} ({dockerfile})"));
                                            docker::start_build(&job, dir, dockerfile, tag, build_args);
                                            if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                                for (n, s) in run_mut.stage_status.iter_mut() {
                                                    if n == &stage_name { *s = StageStatus::Running; }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' ✗ build context: {e}"));
                                            if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                                for (n, s) in run_mut.stage_status.iter_mut() {
                                                    if n == &stage_name { *s = StageStatus::Failed; }
                                                }
                                            }
                                        }
                                    },
                                }
                            }
                            docker::BuildPoll::Running => {
                                log.push(format!("  [pipeline] {pipeline_name}#{run_id}: building '{stage_name}'..."));
                            }
                            docker::BuildPoll::Done(Ok(_)) => {
                                docker::clear_build(&job);
                                log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' built {tag} ✓"));
                                if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                    for (n, s) in run_mut.stage_status.iter_mut() {
                                        if n == &stage_name { *s = StageStatus::Succeeded; }
                                    }
                                }
                            }
                            docker::BuildPoll::Done(Err(e)) => {
                                docker::clear_build(&job);
                                let short: String = e.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or(&e).chars().take(200).collect();
                                log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' ✗ build failed: {short}"));
                                if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                    for (n, s) in run_mut.stage_status.iter_mut() {
                                        if n == &stage_name { *s = StageStatus::Failed; }
                                    }
                                }
                            }
                        }
                    }
                } else if sd.image.is_some() || !sd.matrix_images.is_empty() {
                    // Container stage — run as Job(s), with matrix expansion
                    let images: Vec<String> = if !sd.matrix_images.is_empty() {
                        sd.matrix_images.clone()
                    } else {
                        vec![sd.image.clone().unwrap_or_default()]
                    };
                    let is_matrix = images.len() > 1;
                    let mut all_done = true;
                    let mut any_failed = false;

                    for (mi, image) in images.iter().enumerate() {
                    let job_name = if is_matrix {
                        format!("rk-pipe-{pipeline_name}-{run_id}-{stage_name}-m{mi}")
                    } else {
                        format!("rk-pipe-{pipeline_name}-{run_id}-{stage_name}")
                    };

                    // Check if already running/completed
                    let exists = ours.iter().any(|c|
                        c.names.iter().any(|n| n.trim_start_matches('/') == job_name));

                    if !exists {
                        // Never wait for a registry under the desired-state lock.
                        match docker::ensure_image_nonblocking(image) {
                            docker::ImageState::Present => {}
                            docker::ImageState::Pulling => {
                                log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' waiting for image {image}"));
                                all_done = false;
                                continue;
                            }
                            docker::ImageState::Failed(e) => {
                                log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' image unavailable: {e}"));
                                all_done = false;
                                continue;
                            }
                        }
                        log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' → {image}"));
                        let cmd_refs: Vec<&str> = sd.command.as_ref()
                            .map(|c| c.iter().map(|s| s.as_str()).collect()).unwrap_or_default();
                        let cmd = if cmd_refs.is_empty() { None } else { Some(cmd_refs.as_slice()) };
                        let own = ownership_labels(desired);
                        let mut labels: Vec<(&str, &str)> = own.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
                        labels.push(("royak.pipeline", pipeline_name.as_str()));
                        labels.push(("royak.stage", stage_name.as_str()));
                        // Pipelines are cluster-admin objects: they receive the
                        // DEFAULT namespace's secrets only — never another
                        // tenant's namespace.
                        let mut full_env = sd.env.clone();
                        for secret in desired.secrets.values().filter(|s| s.namespace == store::DEFAULT_NS) {
                            for (k, v) in &secret.data {
                                full_env.push(format!("{k}={v}"));
                            }
                        }
                        full_env.push(format!("ROYAK_PIPELINE={pipeline_name}"));
                        full_env.push(format!("ROYAK_STAGE={stage_name}"));
                        full_env.push(format!("ROYAK_RUN_ID={run_id}"));
                        match docker::create_container(&job_name, image, cmd, &full_env, &labels) {
                            Ok(id) => {
                                docker::start_container(&id).ok();
                                if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                    for (n, s) in run_mut.stage_status.iter_mut() {
                                        if n == &stage_name { *s = StageStatus::Running; }
                                    }
                                }
                                log.push(format!("    [start] {job_name} ✓"));
                            }
                            Err(e) => {
                                log.push(format!("    [error] {job_name}: {e}"));
                                if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                    for (n, s) in run_mut.stage_status.iter_mut() {
                                        if n == &stage_name { *s = StageStatus::Failed; }
                                    }
                                }
                            }
                        }
                    } else {
                        // Check completion
                        let exited = ours.iter().any(|c|
                            c.names.iter().any(|n| n.trim_start_matches('/') == job_name) && c.state == "exited");
                        let still_running = ours.iter().any(|c|
                            c.names.iter().any(|n| n.trim_start_matches('/') == job_name) && c.state == "running");
                        if exited {
                            let ok = ours.iter().any(|c| c.names.iter().any(|n| n.trim_start_matches('/') == job_name) && exited_ok(c));
                            if !ok { any_failed = true; }
                            log.push(format!("    [matrix] {job_name} {}", if ok { "completed ✓" } else { "FAILED ✗" }));
                        } else if still_running {
                            all_done = false;
                        } else {
                            all_done = false;
                        }
                    }
                    } // end matrix loop

                    // Update stage status based on matrix results
                    if is_matrix {
                        if all_done && !any_failed {
                            if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                for (n, s) in run_mut.stage_status.iter_mut() {
                                    if n == &stage_name { *s = StageStatus::Succeeded; }
                                }
                            }
                            log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' ALL matrix jobs completed ✓"));
                        } else if any_failed {
                            if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                for (n, s) in run_mut.stage_status.iter_mut() {
                                    if n == &stage_name { *s = StageStatus::Failed; }
                                }
                            }
                        }
                    }
                }
            }
        }
        run_idx += 1;
    }

    // Clean up completed pipeline runs (keep last 10)
    desired.pipeline_runs.retain(|r| !r.is_complete());

}
