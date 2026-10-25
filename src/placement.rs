//! Cluster-wide pod accounting for the scheduler.
//!
//! The scheduler (single node: always; clustered: the Raft leader) decides how
//! many pods of a workload exist across the whole cluster from three sources:
//!
//! 1. **Local pods** — read from Docker on every tick (authoritative, fresh).
//! 2. **Peer census** — each Ready peer's own report of the pods it runs,
//!    sampled every few seconds (see `reconcile::spawn_peer_pod_sampler`).
//! 3. **Pending remote placements** — pods this scheduler has dispatched to a
//!    peer that the census does not show yet.
//!
//! Only *remote* dispatches are ever pending. A local pod is visible in Docker
//! the moment it is created, so it never needs optimistic accounting — the old
//! design also recorded local pods and kept counting a killed pod for up to
//! 30 s, which delayed self-healing by that long. A pending entry ends when:
//!   * the dispatch fails (forgotten immediately — the pod does not exist),
//!   * the census shows the pod (it is now counted from the census),
//!   * the peer acknowledged the create but the census has not shown it within
//!     [`ACKED_GRACE`] (the pod died or the report is lost — stop counting),
//!   * no acknowledgement arrived within [`DISPATCH_TIMEOUT`].
//!
//! The counting itself is a pure function ([`workload_pods`]) so it can be
//! tested without globals or Docker.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// How long a peer's census report stays usable if the peer stops answering.
/// After this the peer's pods are no longer counted (a NotReady node's pods
/// are excluded immediately, see [`workload_pods`]).
pub const CENSUS_MAX_AGE: Duration = Duration::from_secs(15);
/// Acknowledged remote create not yet visible in the census: count it for at
/// most this long (two census periods + slack).
pub const ACKED_GRACE: Duration = Duration::from_secs(10);
/// Remote create still in flight (image pull on the peer can be slow).
pub const DISPATCH_TIMEOUT: Duration = Duration::from_secs(150);
/// After a failed remote placement, do not pick that node for the same
/// workload again for this long.
pub const PLACEMENT_BACKOFF: Duration = Duration::from_secs(60);

/// One pod as seen by the scheduler, from whichever source.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct PodView {
    pub pod: String,
    pub node: String,
    pub namespace: String,
    /// "deployment", "daemonset", "job", "cronjob".
    pub kind: String,
    pub owner: String,
    /// Pod template hash the pod was created from ("" = unknown/legacy).
    pub template: String,
    pub image: String,
    pub running: bool,
    pub ready: bool,
    /// True for pods dispatched but not yet confirmed by the census.
    #[serde(default)]
    pub pending: bool,
}

/// A peer's census report.
#[derive(Clone, Debug)]
pub struct PeerReport {
    pub node: String,
    pub addr: String,
    pub pods: Vec<PodView>,
    pub at: Instant,
}

#[derive(Clone, Debug)]
pub struct Pending {
    pub view: PodView,
    pub dispatched: Instant,
    pub acked: Option<Instant>,
}

fn census() -> &'static std::sync::Mutex<HashMap<String, PeerReport>> {
    static C: std::sync::OnceLock<std::sync::Mutex<HashMap<String, PeerReport>>> = std::sync::OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn pending() -> &'static std::sync::Mutex<HashMap<String, Pending>> {
    static P: std::sync::OnceLock<std::sync::Mutex<HashMap<String, Pending>>> = std::sync::OnceLock::new();
    P.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn backoff() -> &'static std::sync::Mutex<HashMap<(String, String, String), Instant>> {
    static B: std::sync::OnceLock<std::sync::Mutex<HashMap<(String, String, String), Instant>>> = std::sync::OnceLock::new();
    B.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Replace a peer's census report.
pub fn set_peer_report(node: &str, addr: &str, pods: Vec<PodView>) {
    if let Ok(mut c) = census().lock() {
        c.insert(node.to_string(), PeerReport { node: node.to_string(), addr: addr.to_string(), pods, at: Instant::now() });
    }
}

/// Forget a peer's report (node removed).
#[allow(dead_code)]
pub fn drop_peer_report(node: &str) {
    if let Ok(mut c) = census().lock() { c.remove(node); }
}

/// Fresh peer reports (older than [`CENSUS_MAX_AGE`] are dropped).
pub fn peer_reports() -> Vec<PeerReport> {
    let mut c = match census().lock() { Ok(c) => c, Err(e) => e.into_inner() };
    c.retain(|_, r| r.at.elapsed() <= CENSUS_MAX_AGE);
    c.values().cloned().collect()
}

/// `(peer api address, pod name)` for every fresh peer pod — the shape the
/// ingress and the mesh router use to find which node hosts a pod.
pub fn peer_pod_addrs() -> Vec<(String, String)> {
    peer_reports().into_iter()
        .flat_map(|r| { let addr = r.addr.clone(); r.pods.into_iter().map(move |p| (addr.clone(), p.pod)) })
        .collect()
}

fn expected_peers() -> &'static std::sync::Mutex<Vec<String>> {
    static E: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> = std::sync::OnceLock::new();
    E.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// The configured peer API addresses (`--peers`) the census polls.
pub fn set_expected_peers(addrs: &[String]) {
    if let Ok(mut e) = expected_peers().lock() { *e = addrs.to_vec(); }
}

/// True once every configured peer has a fresh census report.
pub fn census_complete() -> bool {
    let expected = expected_peers().lock().map(|e| e.clone()).unwrap_or_default();
    let reports = peer_reports();
    expected.iter().all(|a| reports.iter().any(|r| &r.addr == a))
}

/// Census warm-up for a scheduler that just started or just won leadership:
/// it holds until every configured peer reported or [`CENSUS_MAX_AGE`] passed.
/// That is the same rule a running scheduler applies — a silent peer's pods
/// keep counting for `CENSUS_MAX_AGE` — instead of treating peers it has not
/// heard from YET as empty and creating their pods a second time.
pub fn scheduler_ready(may_schedule: bool) -> bool {
    static SINCE: std::sync::Mutex<Option<Instant>> = std::sync::Mutex::new(None);
    let mut since = match SINCE.lock() { Ok(s) => s, Err(e) => e.into_inner() };
    if !may_schedule {
        *since = None;
        return false;
    }
    let t = *since.get_or_insert_with(Instant::now);
    warm(t.elapsed(), census_complete())
}

fn warm(elapsed: Duration, complete: bool) -> bool {
    complete || elapsed >= CENSUS_MAX_AGE
}

/// Record a remote dispatch that is in flight.
pub fn record_dispatch(view: PodView) {
    if let Ok(mut p) = pending().lock() {
        p.insert(view.pod.clone(), Pending { view, dispatched: Instant::now(), acked: None });
    }
}

/// The peer confirmed it created the pod.
pub fn mark_acked(pod: &str) {
    if let Ok(mut p) = pending().lock() {
        if let Some(e) = p.get_mut(pod) { e.acked = Some(Instant::now()); }
    }
}

/// The pod does not exist (dispatch failed, or it was deleted).
pub fn forget(pod: &str) {
    if let Ok(mut p) = pending().lock() { p.remove(pod); }
}

/// Live pending entries, after expiring the ones that ended (see module docs).
pub fn pending_entries(reports: &[PeerReport]) -> Vec<Pending> {
    let seen: HashSet<&str> = reports.iter().flat_map(|r| r.pods.iter().map(|p| p.pod.as_str())).collect();
    let mut p = match pending().lock() { Ok(p) => p, Err(e) => e.into_inner() };
    p.retain(|name, e| !expired(e, seen.contains(name.as_str())));
    p.values().cloned().collect()
}

/// Pure expiry rule for one pending entry.
pub fn expired(e: &Pending, seen_in_census: bool) -> bool {
    if seen_in_census { return true; }
    match e.acked {
        Some(t) => t.elapsed() > ACKED_GRACE,
        None => e.dispatched.elapsed() > DISPATCH_TIMEOUT,
    }
}

/// Avoid `node` for (namespace, owner) for a while after it failed a placement.
pub fn backoff_node(node: &str, ns: &str, owner: &str) {
    if let Ok(mut b) = backoff().lock() {
        b.insert((node.to_string(), ns.to_string(), owner.to_string()), Instant::now());
    }
}

pub fn in_backoff(node: &str, ns: &str, owner: &str) -> bool {
    let mut b = match backoff().lock() { Ok(b) => b, Err(e) => e.into_inner() };
    b.retain(|_, t| t.elapsed() <= PLACEMENT_BACKOFF);
    b.contains_key(&(node.to_string(), ns.to_string(), owner.to_string()))
}

/// All pods of one workload across the cluster, de-duplicated by pod name.
///
/// * `local` — this node's pods (from Docker).
/// * `reports` — peer census; reports from nodes not in `ready_nodes` are
///   ignored (a NotReady node's pods are not counted, so the scheduler
///   replaces them elsewhere — Kubernetes' node-lost behaviour).
/// * `pending` — in-flight remote dispatches not yet in the census.
pub fn workload_pods(
    ns: &str,
    kind: &str,
    owner: &str,
    local: &[PodView],
    reports: &[PeerReport],
    pending: &[Pending],
    ready_nodes: &HashSet<String>,
) -> Vec<PodView> {
    let matches = |p: &PodView| p.namespace == ns && p.kind == kind && p.owner == owner;
    let mut out: Vec<PodView> = Vec::new();
    let mut names: HashSet<String> = HashSet::new();
    for p in local.iter().filter(|p| matches(p)) {
        if names.insert(p.pod.clone()) { out.push(p.clone()); }
    }
    for r in reports.iter().filter(|r| ready_nodes.contains(&r.node)) {
        for p in r.pods.iter().filter(|p| matches(p)) {
            if names.insert(p.pod.clone()) { out.push(p.clone()); }
        }
    }
    for e in pending.iter().filter(|e| matches(&e.view) && ready_nodes.contains(&e.view.node)) {
        if names.insert(e.view.pod.clone()) {
            let mut v = e.view.clone();
            v.pending = true;
            out.push(v);
        }
    }
    out
}

/// Every pod name known anywhere in the cluster (for collision-free naming),
/// including pods on NotReady nodes — their names stay reserved.
pub fn all_known_names(reports: &[PeerReport], pending: &[Pending]) -> HashSet<String> {
    let mut s: HashSet<String> = reports.iter().flat_map(|r| r.pods.iter().map(|p| p.pod.clone())).collect();
    s.extend(pending.iter().map(|e| e.view.pod.clone()));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn view(pod: &str, node: &str, owner: &str) -> PodView {
        PodView {
            pod: pod.into(), node: node.into(), namespace: "default".into(), kind: "deployment".into(),
            owner: owner.into(), template: "t".into(), image: "i".into(), running: true, ready: true, pending: false,
        }
    }
    fn report(node: &str, pods: Vec<PodView>) -> PeerReport {
        PeerReport { node: node.into(), addr: format!("{node}:1"), pods, at: Instant::now() }
    }
    fn ready(nodes: &[&str]) -> HashSet<String> { nodes.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn counts_local_census_and_pending_once_each() {
        let local = vec![view("rk-web-1", "a", "web"), view("rk-web-2", "a", "web")];
        let reports = vec![report("b", vec![view("rk-web-3", "b", "web"), view("rk-api-1", "b", "api"),
            view("rk-web-2", "b", "web")])];
        let pend = vec![Pending { view: view("rk-web-4", "b", "web"), dispatched: Instant::now(), acked: None }];
        let pods = workload_pods("default", "deployment", "web", &local, &reports, &pend, &ready(&["a", "b"]));
        let mut names: Vec<_> = pods.iter().map(|p| p.pod.as_str()).collect();
        names.sort();
        assert_eq!(names, vec!["rk-web-1", "rk-web-2", "rk-web-3", "rk-web-4"]);
        assert!(pods.iter().find(|p| p.pod == "rk-web-4").unwrap().pending);
    }

    #[test]
    fn namespace_and_owner_must_both_match() {
        let mut other_ns = view("rk-b_web-1", "a", "web");
        other_ns.namespace = "b".into();
        let local = vec![view("rk-web-1", "a", "web"), other_ns, view("rk-web-api-1", "a", "web-api")];
        let pods = workload_pods("default", "deployment", "web", &local, &[], &[], &ready(&["a"]));
        assert_eq!(pods.len(), 1, "same-named workload in another namespace and prefix-sharing names are not counted");
    }

    #[test]
    fn not_ready_nodes_are_not_counted_but_names_stay_reserved() {
        let reports = vec![report("b", vec![view("rk-web-1", "b", "web")])];
        let pods = workload_pods("default", "deployment", "web", &[], &reports, &[], &ready(&["a"]));
        assert!(pods.is_empty());
        assert!(all_known_names(&reports, &[]).contains("rk-web-1"));
    }

    #[test]
    fn a_killed_local_pod_is_not_counted_at_all() {
        // Regression for the 34 s self-heal delay: local pods are never
        // pending, so once Docker no longer lists one it is simply gone.
        let pods = workload_pods("default", "deployment", "web", &[], &[], &[], &ready(&["a"]));
        assert!(pods.is_empty());
    }

    #[test]
    fn pending_expiry_rules() {
        let base = Pending { view: view("rk-web-9", "b", "web"), dispatched: Instant::now(), acked: None };
        assert!(!expired(&base, false), "fresh in-flight dispatch counts");
        assert!(!warm(Duration::from_secs(3), false), "new scheduler waits for the census");
        assert!(warm(Duration::from_secs(3), true), "complete census ends the warm-up");
        assert!(warm(CENSUS_MAX_AGE, false), "silent peers stop counting after CENSUS_MAX_AGE");
        assert!(expired(&base, true), "census confirmation ends pending (counted from census instead)");
        let mut acked_old = base.clone();
        acked_old.acked = Some(Instant::now() - ACKED_GRACE - Duration::from_secs(1));
        assert!(expired(&acked_old, false), "acked but never seen: stop counting after the grace period");
        let mut timed_out = base.clone();
        timed_out.dispatched = Instant::now() - DISPATCH_TIMEOUT - Duration::from_secs(1);
        assert!(expired(&timed_out, false), "never acked: stop counting after the dispatch timeout");
    }
}
