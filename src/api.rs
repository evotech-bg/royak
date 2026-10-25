//! Royak API Server — kubectl/k9s compatible REST API.
//!
//! v0.2: Async with hyper + tokio for concurrent request handling.
//! Each connection gets its own tokio task — no blocking, no bottleneck.
//!
//! Endpoints:
//!   GET  /api/v1/pods
//!   GET  /api/v1/namespaces
//!   GET  /api/v1/configmaps
//!   GET  /api/v1/secrets
//!   GET  /apis/apps/v1/deployments
//!   GET  /api                        (API discovery)
//!   GET  /apis                       (API groups)
//!   GET  /version                    (server version)
//!   POST /api/v1/namespaces/{ns}/pods  (create)

use crate::docker;
use crate::spec;
use crate::reconcile::{self, DesiredWorld};
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::convert::Infallible;
use std::collections::HashMap;
use hyper::Request;
use hyper::body::Incoming;
use hyper::header::HeaderMap;
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use http_body_util::{BodyExt, Full, StreamBody};
use bytes::Bytes;
use tokio::net::TcpListener;

/// Boxed body type — supports both buffered (Full) and streaming responses
type BoxedBody = http_body_util::combinators::BoxBody<Bytes, Infallible>;

/// Byte stream from a tokio channel — implements futures Stream for hyper streaming responses
struct ByteStream {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
}

impl futures_core::Stream for ByteStream {
    type Item = Result<hyper::body::Frame<Bytes>, Infallible>;

    fn poll_next(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            std::task::Poll::Ready(Some(bytes)) => std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(bytes)))),
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

static RESOURCE_VERSION: AtomicU64 = AtomicU64::new(1);

fn next_rv() -> String {
    RESOURCE_VERSION.fetch_add(1, Ordering::Relaxed).to_string()
}

fn current_rv() -> String {
    RESOURCE_VERSION.load(Ordering::Relaxed).to_string()
}

/// Deterministic UUID-like string from kind/namespace/name (no uuid crate)
fn resource_uid(kind: &str, name: &str, ns: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325; // FNV-1a offset
    for byte in format!("{kind}/{ns}/{name}").bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        (hash >> 32) as u32,
        (hash >> 16) as u16 & 0xffff,
        hash as u16 & 0x0fff | 0x4000,
        ((hash >> 48) as u16 & 0x3fff) | 0x8000,
        hash & 0xffffffffffff)
}

fn now_rfc3339() -> String {
    rfc3339(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs())
}

fn rfc3339(secs: u64) -> String {
    let s = secs % 60; let m = (secs / 60) % 60; let h = (secs / 3600) % 24;
    let days = secs / 86400;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Mask sensitive paths in log output
fn mask_log_path(path: &str) -> String {
    if path.contains("/secrets") {
        path.split("/secrets").next().unwrap_or(path).to_string() + "/secrets/***"
    } else {
        path.to_string()
    }
}

/// Max YAML/JSON body size (10 MB)
const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Generate self-signed TLS certificate
pub fn generate_tls_cert() -> Result<(String, String), String> {
    let mut params = rcgen::CertificateParams::new(vec![
        "localhost".to_string(),
        "royak".to_string(),
        "127.0.0.1".to_string(),
    ]).map_err(|e| e.to_string())?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "Royak CA");
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "Royak");
    let key_pair = rcgen::KeyPair::generate().map_err(|e| e.to_string())?;
    let key_pem = key_pair.serialize_pem();
    let cert = params.self_signed(&key_pair).map_err(|e| e.to_string())?;
    Ok((cert.pem(), key_pem))
}

// ─── Response helpers ───

fn json_response(status: u16, body: &str) -> hyper::Response<BoxedBody> {
    hyper::Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        // Lets cross-origin dashboards (e.g. demo.royak.io) read the PUBLIC
        // endpoints. Everything else needs an `Authorization: Bearer` header,
        // which a browser only sends cross-origin after a preflight this server
        // never approves (no Access-Control-Allow-Headers).
        .header("Access-Control-Allow-Origin", "*")
        .body(Full::new(Bytes::from(body.to_string())).boxed())
        .unwrap()
}

fn typed_response(status: u16, body: &str, content_type: &str) -> hyper::Response<BoxedBody> {
    hyper::Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .header("Access-Control-Allow-Origin", "*")
        .body(Full::new(Bytes::from(body.to_string())).boxed())
        .unwrap()
}

fn stream_response(content_type: &str, rx: tokio::sync::mpsc::Receiver<Bytes>) -> hyper::Response<BoxedBody> {
    let stream = ByteStream { rx };
    hyper::Response::builder()
        .status(200)
        .header("Content-Type", content_type)
        .header("Transfer-Encoding", "chunked")
        .body(StreamBody::new(stream).boxed())
        .unwrap()
}

/// Parse query string into key-value map
fn parse_query(query: Option<&str>) -> HashMap<String, String> {
    query.unwrap_or("").split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?.to_string();
            let val = parts.next().unwrap_or("true").to_string();
            Some((key, val))
        })
        .collect()
}

// ─── Public demo controls (opt-in, sandboxed) ───
// Enabled ONLY with ROYAK_DEMO=1. Exposes a tiny, whitelisted set of safe
// actions (scale within 1..5, kill one pod) on a single demo deployment, so a
// public demo page can let visitors break things and watch Royak self-heal —
// WITHOUT exposing the control plane. Fail-safe: absent flag → routes 404.
fn demo_enabled() -> bool {
    std::env::var("ROYAK_DEMO").map(|v| v == "1" || v == "true").unwrap_or(false)
}
fn demo_app() -> String {
    std::env::var("ROYAK_DEMO_APP").unwrap_or_else(|_| "demo".to_string())
}
/// Coarse global rate limit for demo mutations (min gap between actions).
fn demo_rate_ok() -> bool {
    use std::sync::{Mutex, OnceLock};
    use std::time::{Duration, Instant};
    static LAST: OnceLock<Mutex<Instant>> = OnceLock::new();
    let m = LAST.get_or_init(|| Mutex::new(Instant::now() - Duration::from_secs(10)));
    let mut g = m.lock().unwrap();
    if g.elapsed() >= Duration::from_millis(600) { *g = Instant::now(); true } else { false }
}

// ─── Route handler (all business logic, synchronous) ───

// ─── Status helpers ───

fn status_json(code: u16, reason: &str, message: &str) -> String {
    serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Failure",
        "reason": reason, "message": message, "code": code}).to_string()
}

fn ok_status(message: &str) -> String {
    serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Success", "message": message}).to_string()
}

/// Map a failed commit to its HTTP answer. Every variant means "not applied".
fn commit_error(e: crate::store::CommitError) -> (u16, String) {
    use crate::store::CommitError;
    match e {
        CommitError::Rejected(code, msg) => {
            let reason = match code { 404 => "NotFound", 409 => "Conflict", 403 => "Forbidden", _ => "BadRequest" };
            (code, status_json(code, reason, &msg))
        }
        CommitError::Unavailable(msg) => (503, status_json(503, "ServiceUnavailable", &format!("change NOT applied: {msg}"))),
        CommitError::NotLeader(leader) => not_leader_body(leader),
        CommitError::Unknown(msg) => (504, status_json(504, "Timeout", &format!("outcome unknown: {msg}"))),
    }
}

/// A clustered follower (or a single-node standby) never accepts writes.
/// 421 names the leader and its API address when known.
fn not_leader_body(leader: Option<crate::raft_node::NeuroNodeId>) -> (u16, String) {
    let addr = leader.and_then(crate::raft_node::peer_address);
    let msg = match (leader, &addr) {
        (Some(l), Some(a)) => format!("this node does not accept writes; send them to the Raft leader (node {l} at {a})"),
        (Some(l), None) => format!("this node does not accept writes; send them to the Raft leader (node {l})"),
        (None, _) if crate::raft_node::is_clustered() => "no Raft leader is known right now (election or no quorum); the write was NOT applied".to_string(),
        (None, _) => "this process is in standby (another Royak process owns the state); the write was NOT applied".to_string(),
    };
    (421, serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "NotLeader",
        "message": msg, "leader": leader, "leaderAddress": addr, "code": 421}).to_string())
}

fn scale_object(name: &str, ns: &str, replicas: u32) -> String {
    serde_json::json!({
        "kind": "Scale", "apiVersion": "autoscaling/v1",
        "metadata": {"name": name, "namespace": ns, "uid": resource_uid("Scale", name, ns), "resourceVersion": current_rv().to_string()},
        "spec": {"replicas": replicas},
        "status": {"replicas": replicas, "selector": format!("app={name}")}
    }).to_string()
}

fn not_found_status(path: &str) -> String {
    status_json(404, "NotFound", &format!("resource not found: {path}"))
}

// ─── Pod lookup (only Royak's own containers, by namespace + pod label) ───

/// This node's containers that belong to this cluster (and, clustered, node).
fn our_local_containers(world: &DesiredWorld) -> Vec<docker::DockerContainer> {
    let all = docker::list_containers(true).unwrap_or_default();
    let ours: Vec<docker::DockerContainer> = reconcile::our_containers(world, &all).into_iter().cloned().collect();
    ours
}

/// The container of pod `ns/pod` on THIS node: `container` names the pod's
/// container (spec name); None = the main container.
fn find_pod_container(world: &DesiredWorld, ns: &str, pod: &str, container: Option<&str>) -> Option<docker::DockerContainer> {
    let ours = our_local_containers(world);
    let in_pod: Vec<&docker::DockerContainer> = ours.iter().filter(|c|
        c.labels.get(crate::store::LABEL_POD).map(|p| p == pod).unwrap_or(false)
        && c.labels.get(crate::store::LABEL_NAMESPACE).map(|s| s.as_str()).unwrap_or(crate::store::DEFAULT_NS) == ns
    ).collect();
    let is_main = |c: &&&docker::DockerContainer| c.labels.get(crate::store::LABEL_ROLE).map(|r| r == "main").unwrap_or(true);
    let pick = match container {
        // The pod JSON names the main container "main" (kubectl echoes it back).
        Some("main") => in_pod.iter().find(is_main),
        Some(cn) => in_pod.iter().find(|c| {
            let dn = cname(c);
            dn == pod && c.labels.get(crate::store::LABEL_ROLE).map(|r| r == "main").unwrap_or(true) && main_container_name(world, ns, c) == Some(cn.to_string())
                || dn == format!("{pod}-{cn}")
        }),
        None => in_pod.iter().find(is_main),
    };
    pick.map(|c| (*c).clone())
}

/// Spec name of a pod's main container (for `-c <name>` on the main one).
fn main_container_name(world: &DesiredWorld, ns: &str, c: &docker::DockerContainer) -> Option<String> {
    let dep = c.labels.get(crate::store::LABEL_DEPLOYMENT)?;
    world.deployments.get(&crate::store::obj_key(ns, dep))?.containers.first().map(|m| m.name.clone())
}

/// Which peer runs pod `ns/pod` (from the signed census)? `(node, address)`.
fn find_remote_pod(ns: &str, pod: &str) -> Option<(String, String)> {
    crate::placement::peer_reports().into_iter()
        .find(|r| r.pods.iter().any(|p| p.pod == pod && p.namespace == ns))
        .map(|r| (r.node, r.addr))
}

/// Every pod of the cluster this node knows about: local (from Docker) plus
/// the peers' census.
fn cluster_pods(world: &DesiredWorld) -> Vec<(crate::placement::PodView, String)> {
    let all = docker::list_containers(true).unwrap_or_default();
    let ours = reconcile::our_containers(world, &all);
    let mut out: Vec<(crate::placement::PodView, String)> = Vec::new();
    for v in reconcile::local_views(world, &ours) {
        let phase = local_phase(&ours, &v);
        out.push((v, phase));
    }
    for r in crate::placement::peer_reports() {
        for v in r.pods {
            let phase = if v.running { "Running".to_string() } else { "Succeeded".to_string() };
            out.push((v, phase));
        }
    }
    // Experimental process runtime (single node, default namespace, matched by
    // its `rk-` name only — it has no labels).
    for (name, image, running, _, _) in crate::runtime::NeuroPod::list_all() {
        if !name.starts_with("rk-") { continue; }
        out.push((crate::placement::PodView {
            pod: name, node: crate::store::node_name(), namespace: crate::store::DEFAULT_NS.into(),
            kind: "neuropod".into(), owner: String::new(), template: String::new(), image,
            running, ready: running, pending: false,
        }, if running { "Running".into() } else { "Pending".into() }));
    }
    out
}

fn local_phase(ours: &[&docker::DockerContainer], v: &crate::placement::PodView) -> String {
    if v.running { return "Running".into(); }
    let main = ours.iter().find(|c| c.labels.get(crate::store::LABEL_POD) == Some(&v.pod)
        && c.labels.get(crate::store::LABEL_ROLE).map(|r| r == "main").unwrap_or(true));
    match main {
        Some(c) if c.state == "exited" && c.status.starts_with("Exited (0)") => "Succeeded".into(),
        Some(c) if c.state == "exited" || c.state == "dead" => "Failed".into(),
        _ => "Pending".into(),
    }
}

fn pod_view_json(v: &crate::placement::PodView, phase: &str) -> serde_json::Value {
    let mut j = pod_json(&v.pod, &v.namespace, &v.image, phase, v.ready);
    j["metadata"]["labels"] = serde_json::json!({"app": v.owner, "royak.io/owner-kind": v.kind});
    j["spec"]["nodeName"] = serde_json::json!(v.node);
    j
}

fn list_pods(world: &DesiredWorld, ns: Option<&str>) -> String {
    let items: Vec<serde_json::Value> = cluster_pods(world).iter()
        .filter(|(v, _)| ns.map(|n| n == v.namespace).unwrap_or(true))
        .map(|(v, phase)| pod_view_json(v, phase)).collect();
    serde_json::json!({"kind": "PodList", "apiVersion": "v1", "metadata": {"resourceVersion": current_rv()}, "items": items}).to_string()
}

fn get_pod(world: &DesiredWorld, name: &str, ns: &str) -> (u16, String) {
    match cluster_pods(world).into_iter().find(|(v, _)| v.pod == name && v.namespace == ns) {
        Some((v, phase)) => (200, pod_view_json(&v, &phase).to_string()),
        None => (404, status_json(404, "NotFound", &format!("pods \"{name}\" not found in namespace \"{ns}\""))),
    }
}

fn pod_logs(world: &DesiredWorld, ns: &str, pod: &str, container: Option<&str>, tail: u32) -> (u16, String) {
    if let Some(c) = find_pod_container(world, ns, pod, container) {
        return match docker::get_logs(&c.id[..12.min(c.id.len())], tail) {
            Ok(logs) => (200, logs),
            Err(e) => (500, status_json(500, "InternalError", &format!("log error: {e}"))),
        };
    }
    if let Some((node, addr)) = find_remote_pod(ns, pod) {
        return match reconcile::fetch_remote_logs(&addr, ns, pod) {
            Ok(l) => (200, l),
            Err(e) => (502, status_json(502, "BadGateway", &format!("pod {pod} runs on {node}; log fetch failed: {e}"))),
        };
    }
    (404, status_json(404, "NotFound", &format!("pods \"{pod}\" not found in namespace \"{ns}\"")))
}

// ─── Write helpers ───

/// Parse a request body (JSON or YAML, one or more documents) into resources.
fn parse_body_resources(body: &[u8]) -> Result<Vec<spec::Resource>, String> {
    let body_str = String::from_utf8_lossy(body);
    if body_str.trim_start().starts_with('{') {
        serde_json::from_str::<serde_json::Value>(&body_str)
            .map_err(|e| format!("JSON parse: {e}"))
            .and_then(|v| serde_yaml::to_string(&v).map_err(|e| format!("YAML convert: {e}")))
            .and_then(|yaml| spec::parse_yaml(&yaml).map_err(|e| e.to_string()))
    } else {
        spec::parse_yaml(&body_str).map_err(|e| e.to_string())
    }
}

/// Bind every document to the request's namespace and authorize it.
///
/// * A document with no namespace takes the URL's (or "default").
/// * A document whose namespace differs from the URL's is rejected (400) —
///   a namespaced URL can never write into another namespace.
/// * Every document is authorized on its own (kind → resource, namespace,
///   name), so a multi-document body cannot smuggle a kind the caller may
///   not write.
fn bind_and_authorize(
    world: &DesiredWorld,
    caller: &crate::auth::Identity,
    verb: &str,
    url_ns: Option<&str>,
    url_name: Option<&str>,
    resources: &mut [spec::Resource],
) -> Result<(), (u16, String)> {
    if resources.is_empty() {
        return Err((400, status_json(400, "BadRequest", "request body holds no resource")));
    }
    for r in resources.iter_mut() {
        let cluster_scoped = crate::store::is_cluster_scoped_kind(&r.kind);
        let body_ns = r.metadata.namespace.clone().filter(|s| !s.is_empty());
        if !cluster_scoped {
            if let (Some(u), Some(b)) = (url_ns, body_ns.as_deref()) {
                if u != b {
                    return Err((400, status_json(400, "BadRequest", &format!(
                        "the namespace of the object ({b}) does not match the namespace on the request ({u})"))));
                }
            }
            r.metadata.namespace = Some(body_ns.or(url_ns.map(|s| s.to_string())).unwrap_or_else(|| crate::store::DEFAULT_NS.to_string()));
        }
        if let Some(n) = url_name {
            if r.metadata.name != n {
                return Err((400, status_json(400, "BadRequest", &format!(
                    "the name of the object ({}) does not match the name on the URL ({n})", r.metadata.name))));
            }
        }
        let attrs = crate::auth::Attrs {
            verb: verb.to_string(),
            resource: crate::auth::resource_for_kind(&r.kind),
            subresource: None,
            namespace: if cluster_scoped { None } else { r.metadata.namespace.clone() },
            name: Some(r.metadata.name.clone()),
        };
        if !crate::auth::authorize(world, caller, &attrs) {
            return Err((403, forbidden(caller, &attrs)));
        }
    }
    Ok(())
}

fn forbidden(caller: &crate::auth::Identity, a: &crate::auth::Attrs) -> String {
    status_json(403, "Forbidden", &format!("user \"{}\" cannot {}", caller.user, a.describe()))
}

/// Apply resources through the commit path; also records full Deployment
/// manifests (the base partial PATCHes merge into).
fn commit_apply(world: &Arc<RwLock<DesiredWorld>>, resources: Vec<spec::Resource>, docs: Vec<serde_json::Value>) -> (u16, String) {
    let first = resources.first().map(|r| (
        r.api_version.clone().unwrap_or_else(|| "v1".to_string()),
        r.kind.clone(),
        r.metadata.name.clone(),
        r.metadata.namespace.clone().unwrap_or_else(|| crate::store::DEFAULT_NS.to_string()),
        r.spec.as_ref().and_then(|v| serde_json::to_value(v).ok()).unwrap_or(serde_json::Value::Null),
    ));
    let res = crate::store::commit(world, move |w| {
        for r in &resources {
            w.apply(r).map_err(|e| (400, e))?;
        }
        for doc in &docs {
            if doc.get("kind").and_then(|k| k.as_str()) == Some("Deployment") {
                if let Some(n) = doc["metadata"]["name"].as_str() {
                    let dns = doc["metadata"]["namespace"].as_str().unwrap_or(crate::store::DEFAULT_NS);
                    w.manifests.insert(format!("Deployment/{dns}/{n}"), doc.clone());
                }
            }
        }
        Ok(())
    });
    match res {
        Ok(()) => {
            next_rv();
            let (api_version, kind, name, namespace, spec) = match first {
                Some(t) => t,
                None => ("v1".into(), "Status".into(), String::new(), crate::store::DEFAULT_NS.into(), serde_json::Value::Null),
            };
            (201, serde_json::json!({
                "apiVersion": api_version, "kind": kind,
                "metadata": {"name": name, "namespace": namespace, "resourceVersion": current_rv(),
                    "uid": resource_uid(&kind, &name, &namespace), "creationTimestamp": "1970-01-01T00:00:00Z"},
                "spec": spec,
            }).to_string())
        }
        Err(e) => commit_error(e),
    }
}

/// Request-scoped context for `route_request`.
struct Ctx<'a> {
    method: &'a str,
    path: &'a str,
    query: &'a HashMap<String, String>,
    body: &'a [u8],
    world: &'a Arc<RwLock<DesiredWorld>>,
    /// The authenticated caller (None only for public endpoints).
    caller: Option<&'a crate::auth::Identity>,
}

// ─── Route handler (all business logic, synchronous) ───

fn route_request(cx: &Ctx) -> (u16, String) {
    let (method, path, world) = (cx.method, cx.path, cx.world);
    eprintln!("  [api] {method} {}", mask_log_path(path));
    let k8s = crate::auth::parse_k8s_path(path);
    let qns = cx.query.get("namespace").map(|s| s.as_str()).filter(|s| !s.is_empty());

    match (method, path) {
        ("GET", "/healthz") | ("GET", "/readyz") | ("GET", "/livez") => return (200, "ok".to_string()),
        ("GET", "/version") => return (200, version_json()),
        ("GET", "/api") => return (200, api_versions()),
        ("GET", "/api/v1") => return (200, api_v1_resources()),
        ("GET", "/apis") => return (200, api_groups()),
        ("GET", "/apis/apps/v1") => return (200, apps_v1_resources()),
        ("GET", "/openapi/v2") => return (404, status_json(404, "NotFound", "v2 not served; v3 at /openapi/v3")),
        ("GET", "/openapi/v3") => return (200, openapi_v3_root()),
        ("GET", p) if p.starts_with("/openapi/v3/") => return (200, openapi_v3_group(p)),
        _ => {}
    }

    // ─── Sandboxed public demo controls (ROYAK_DEMO=1 only) ───
    match (method, path) {
        ("GET", "/demo/state") => {
            let snap = demo_state_snapshot().lock().unwrap_or_else(|e| e.into_inner()).clone();
            return (200, (*snap).clone());
        }
        ("GET", "/demo/info") => {
            let app = demo_app();
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            let reps = w.deployments.get(&crate::store::obj_key(crate::store::DEFAULT_NS, &app)).map(|d| d.replicas).unwrap_or(0);
            return (200, serde_json::json!({"demo": demo_enabled(), "app": app, "replicas": reps, "min": 1, "max": 5}).to_string());
        }
        ("POST", "/demo/scale") => {
            if !demo_rate_ok() { return (429, r#"{"status":"error","message":"slow down"}"#.to_string()); }
            let n = cx.query.get("n").and_then(|s| s.parse::<u32>().ok()).unwrap_or(1).clamp(1, 5);
            let app = demo_app();
            let key = crate::store::obj_key(crate::store::DEFAULT_NS, &app);
            return match crate::store::commit(world, |w| {
                let d = w.deployments.get_mut(&key).ok_or((404, format!("demo app '{app}' not found")))?;
                d.replicas = n;
                Ok(())
            }) {
                Ok(()) => { next_rv(); (200, serde_json::json!({"status": "ok", "app": app, "replicas": n}).to_string()) }
                Err(e) => commit_error(e),
            };
        }
        ("POST", "/demo/kill") => {
            if !demo_rate_ok() { return (429, r#"{"status":"error","message":"slow down"}"#.to_string()); }
            let app = demo_app();
            // Exactly one RUNNING pod of the demo deployment, among this
            // cluster's own containers — nothing else on the host.
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            let victim = our_local_containers(&w).into_iter().find(|c| c.state == "running"
                && c.labels.get(crate::store::LABEL_DEPLOYMENT) == Some(&app)
                && c.labels.get(crate::store::LABEL_NAMESPACE).map(|s| s.as_str()).unwrap_or(crate::store::DEFAULT_NS) == crate::store::DEFAULT_NS
                && c.labels.get(crate::store::LABEL_ROLE).map(|r| r == "main").unwrap_or(true));
            return match victim {
                Some(c) => {
                    let name = cname(&c);
                    let _ = docker::remove_container(&c.id, true);
                    (200, serde_json::json!({"status": "ok", "killed": name}).to_string())
                }
                None => (200, serde_json::json!({"status": "ok", "killed": serde_json::Value::Null, "message": "no running demo pod"}).to_string()),
            };
        }
        _ => {}
    }

    // ─── Royak endpoints ───
    match (method, path) {
        ("GET", "/royak/v1/raft/status") => {
            let h = crate::raft_node::RAFT.get();
            let (leader, me) = match h {
                Some(h) => (h.rt.block_on(h.raft.current_leader()), Some(h.node_id)),
                None => (None, None),
            };
            return (200, serde_json::json!({"enabled": me.is_some(), "nodeId": me, "leader": leader,
                "leaderAddress": leader.and_then(crate::raft_node::peer_address),
                "isLeader": me.is_some() && me == leader,
                // Leadership a quorum acknowledged within the lease; only then
                // does this node schedule pods.
                "leaderConfirmed": me.is_some() && crate::raft_node::is_cluster_scheduler(),
                "generation": world.read().unwrap_or_else(|e| e.into_inner()).generation}).to_string());
        }
        ("GET", "/royak/v1/flows") => {
            let flows = crate::flows::snapshot(500);
            let totals: Vec<serde_json::Value> = crate::flows::totals().into_iter().take(50)
                .map(|(dest, conns, up, down)| serde_json::json!({"dest": dest, "connections": conns, "bytesUp": up, "bytesDown": down})).collect();
            return (200, serde_json::json!({"flows": flows, "topTalkers": totals}).to_string());
        }
        ("GET", "/royak/v1/pipelines") => {
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            return (200, list_pipelines(&w));
        }
        ("GET", "/royak/v1/brain") => {
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            let ca_fp = w.cluster_ca.as_ref().map(|ca| ca.fingerprint.clone()).unwrap_or_default();
            let certs_issued = w.cluster_ca.as_ref().map(|ca| ca.issued_count).unwrap_or(0);
            return (200, serde_json::json!({
                "kind": "Brain", "status": "active",
                "features": ["backprop-training", "anomaly-detection", "load-prediction", "neural-scheduling"],
                "cluster": {
                    "nodes": w.nodes.len(), "deployments": w.deployments.len(),
                    "events": w.events.len(), "pods": w.deployments.values().map(|d| d.replicas).sum::<u32>(),
                    "services": w.services.len(), "namespaces": w.namespaces.len(),
                    "quotas": w.resource_quotas.len(), "policies": w.network_policies.len(),
                },
                "security": {"ca_fingerprint": ca_fp, "certs_issued": certs_issued,
                    "networks": w.namespaces.len() + 1, "audit_events": w.network_audit.len(), "pod_certs": w.pod_certs.len()}
            }).to_string());
        }
        ("GET", "/royak/v1/top/pods") => {
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            let mut items = Vec::new();
            for c in our_local_containers(&w).iter().filter(|c| c.state == "running") {
                let ns = c.labels.get(crate::store::LABEL_NAMESPACE).map(|s| s.as_str()).unwrap_or(crate::store::DEFAULT_NS);
                if qns.map(|q| q != ns).unwrap_or(false) { continue; }
                let (cpu_pct, mem_mb) = docker::container_stats_peek(&c.id[..12.min(c.id.len())]).unwrap_or((0.0, 0.0));
                items.push(serde_json::json!({"name": cname(c), "namespace": ns,
                    "cpu": format!("{cpu_pct:.1}%"), "memory": format!("{mem_mb:.0}Mi"), "cpu_raw": cpu_pct, "memory_raw_mb": mem_mb}));
            }
            return (200, serde_json::json!({"kind": "TopPods", "items": items}).to_string());
        }
        ("GET", "/royak/v1/top/nodes") => {
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            let items: Vec<serde_json::Value> = w.nodes.values().map(|n| {
                let cpu_pct = if n.cpu_capacity > 0.0 { (n.cpu_used / n.cpu_capacity) * 100.0 } else { 0.0 };
                let mem_pct = if n.mem_capacity > 0.0 { (n.mem_used / n.mem_capacity) * 100.0 } else { 0.0 };
                serde_json::json!({"name": n.name,
                    "cpu": format!("{:.0}/{:.0} ({:.0}%)", n.cpu_used, n.cpu_capacity, cpu_pct),
                    "memory": format!("{:.0}/{:.0}Mi ({:.0}%)", n.mem_used, n.mem_capacity, mem_pct),
                    "pods": n.pod_count})
            }).collect();
            return (200, serde_json::json!({"kind": "TopNodes", "items": items}).to_string());
        }
        ("GET", "/metrics") => {
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            let pods = cluster_pods(&w);
            let mut lines = vec![
                "# HELP royak_pods_total Total desired pod count".to_string(),
                "# TYPE royak_pods_total gauge".to_string(),
                format!("royak_pods_total {}", w.deployments.values().map(|d| d.replicas).sum::<u32>()),
                "# TYPE royak_deployments_total gauge".to_string(),
                format!("royak_deployments_total {}", w.deployments.len()),
                "# TYPE royak_services_total gauge".to_string(),
                format!("royak_services_total {}", w.services.len()),
                "# TYPE royak_namespaces_total gauge".to_string(),
                format!("royak_namespaces_total {}", w.namespaces.len()),
                "# TYPE royak_events_total counter".to_string(),
                format!("royak_events_total {}", w.events.len()),
                "# TYPE royak_state_generation gauge".to_string(),
                format!("royak_state_generation {}", w.generation),
            ];
            let mut deps: Vec<&reconcile::StoredDeployment> = w.deployments.values().collect();
            deps.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
            for dep in deps {
                let ready = pods.iter().filter(|(v, _)| v.kind == "deployment" && v.owner == dep.name && v.namespace == dep.namespace && v.ready).count();
                lines.push(format!("royak_deployment_replicas_desired{{namespace=\"{}\",deployment=\"{}\"}} {}", dep.namespace, dep.name, dep.replicas));
                lines.push(format!("royak_deployment_replicas_ready{{namespace=\"{}\",deployment=\"{}\"}} {ready}", dep.namespace, dep.name));
            }
            return (200, lines.join("\n") + "\n");
        }
        ("GET", "/royak/v1/logs") => {
            let search = cx.query.get("search").cloned().unwrap_or_default();
            let tail: u32 = cx.query.get("tail").and_then(|s| s.parse().ok()).unwrap_or(50);
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            let mut all_logs = Vec::new();
            for c in our_local_containers(&w).iter().filter(|c| c.state == "running") {
                let ns = c.labels.get(crate::store::LABEL_NAMESPACE).map(|s| s.as_str()).unwrap_or(crate::store::DEFAULT_NS);
                if qns.map(|q| q != ns).unwrap_or(false) { continue; }
                if let Ok(logs) = docker::get_logs(&c.id[..12.min(c.id.len())], tail) {
                    for line in logs.lines() {
                        if search.is_empty() || line.to_lowercase().contains(&search.to_lowercase()) {
                            all_logs.push(serde_json::json!({"namespace": ns, "pod": cname(c), "line": line}));
                        }
                    }
                }
            }
            return (200, serde_json::json!({"kind": "AggregatedLogs", "search": search, "count": all_logs.len(), "logs": all_logs}).to_string());
        }
        _ => {}
    }

    // ─── Rollout status / describe (Royak extensions, namespaced via ?namespace=) ───
    if let (true, Some(dep_name)) = (method == "GET", path.strip_prefix("/royak/v1/rollout/")) {
        let ns = qns.unwrap_or(crate::store::DEFAULT_NS);
        let key = crate::store::obj_key(ns, dep_name);
        let w = world.read().unwrap_or_else(|e| e.into_inner());
        let Some(dep) = w.deployments.get(&key) else {
            return (404, status_json(404, "NotFound", &format!("deployment {key} not found")));
        };
        let pods: Vec<crate::placement::PodView> = cluster_pods(&w).into_iter().map(|(v, _)| v)
            .filter(|v| v.kind == "deployment" && v.namespace == ns && v.owner == dep_name).collect();
        let src = crate::workload::PodSource { kind: "deployment", namespace: ns, owner: dep_name,
            init_containers: &dep.init_containers, containers: &dep.containers, limits: dep.resource_limits.as_ref(), restart_nonce: dep.restart_nonce };
        let tmpl = crate::workload::template_hash(&src);
        let updated_ready = pods.iter().filter(|p| p.template == tmpl && p.ready).count() as u32;
        let old = pods.iter().filter(|p| p.template != tmpl).count();
        let complete = updated_ready >= dep.replicas && old == 0;
        return (200, serde_json::json!({
            "kind": "RolloutStatus", "namespace": ns, "deployment": dep_name,
            "status": if complete { "complete" } else { "in-progress" },
            "template": tmpl, "updatedReady": updated_ready, "oldPods": old, "desired": dep.replicas,
            "progress": format!("{updated_ready}/{}", dep.replicas),
        }).to_string());
    }
    if let (true, Some(rest)) = (method == "GET", path.strip_prefix("/royak/v1/describe/")) {
        let mut it = rest.splitn(2, '/');
        let (resource, res_name) = (it.next().unwrap_or(""), it.next().unwrap_or(""));
        let ns = qns.unwrap_or(crate::store::DEFAULT_NS);
        let w = world.read().unwrap_or_else(|e| e.into_inner());
        return match resource {
            "deployment" | "deployments" => match w.deployments.get(&crate::store::obj_key(ns, res_name)) {
                Some(dep) => {
                    let events: Vec<String> = w.events.iter().filter(|e| e.namespace == ns && e.object == res_name)
                        .map(|e| format!("  {} {} — {} (×{})", e.event_type, e.reason, e.message, e.count)).collect();
                    (200, serde_json::json!({"kind": "Describe", "resource": "Deployment",
                        "metadata": {"name": dep.name, "namespace": dep.namespace},
                        "spec": {"replicas": dep.replicas, "paused": dep.paused,
                            "containers": dep.containers.iter().map(|c| format!("  - {}: {} (env: {})", c.name, c.image, c.env.len())).collect::<Vec<_>>()},
                        "events": events}).to_string())
                }
                None => (404, status_json(404, "NotFound", &format!("deployment {ns}/{res_name} not found"))),
            },
            "pod" | "pods" => match cluster_pods(&w).into_iter().find(|(v, _)| v.pod == res_name && v.namespace == ns) {
                Some((v, phase)) => {
                    let events: Vec<String> = w.events.iter().filter(|e| e.namespace == ns && e.object == res_name)
                        .map(|e| format!("  {} {} — {} (×{})", e.event_type, e.reason, e.message, e.count)).collect();
                    (200, serde_json::json!({"kind": "Describe", "resource": "Pod",
                        "metadata": {"name": v.pod, "namespace": v.namespace},
                        "spec": {"image": v.image, "node": v.node, "phase": phase, "ready": v.ready, "owner": format!("{}/{}", v.kind, v.owner)},
                        "events": events}).to_string())
                }
                None => (404, status_json(404, "NotFound", &format!("pod {ns}/{res_name} not found"))),
            },
            "node" | "nodes" => (200, get_node(&w, res_name).1),
            _ => (400, status_json(400, "BadRequest", &format!("describe not supported for: {resource}"))),
        };
    }

    // ─── Webhooks / function triggers (functions/invoke permission) ───
    if method == "POST" && path.starts_with("/hooks/repo/") {
        let repo_name = path.strip_prefix("/hooks/repo/").unwrap_or("").to_string();
        // Pipeline runs are runtime state (not replicated desired state).
        let mut w = world.write().unwrap_or_else(|e| e.into_inner());
        let Some(pipeline_name) = w.repositories.get(&repo_name).map(|r| r.pipeline.clone()) else {
            return (404, status_json(404, "NotFound", &format!("repo '{repo_name}' not found")));
        };
        let Some(pipeline_name) = pipeline_name else {
            return (400, status_json(400, "BadRequest", "repo has no pipeline configured"));
        };
        return match reconcile::start_pipeline(&mut w, &pipeline_name) {
            Ok(run_id) => { next_rv(); (200, serde_json::json!({"status": "ok", "pipeline": pipeline_name, "run_id": run_id}).to_string()) }
            Err(e) => (404, status_json(404, "NotFound", &e)),
        };
    }
    let trigger_fn = {
        let w = world.read().unwrap_or_else(|e| e.into_inner());
        w.functions.values().find(|f| f.http_triggers.iter().any(|t| t == path) || f.webhook_triggers.iter().any(|t| t == path))
            .map(|f| f.name.clone())
    };
    if let Some(name) = trigger_fn {
        return match crate::store::commit(world, |w| reconcile::invoke_function(w, &name).map_err(|e| (500, e))) {
            Ok(result) => (200, serde_json::json!({"status": "ok", "function": name, "result": result}).to_string()),
            Err(e) => commit_error(e),
        };
    }
    if path.starts_with("/hooks/") {
        return (404, status_json(404, "NotFound", &format!("no function registered for webhook {path}")));
    }

    let Some((url_ns, resource, name, sub)) = k8s else {
        return (404, status_json(404, "NotFound", &format!("the server could not find the requested resource: {path}")));
    };
    let caller = match cx.caller {
        Some(c) => c,
        None => return (401, status_json(401, "Unauthorized", "authentication required")),
    };

    match (method, sub) {
        // ─── Scale subresource ───
        ("GET", Some("scale")) if resource == "deployments" || resource == "statefulsets" => {
            let ns = url_ns.unwrap_or(crate::store::DEFAULT_NS);
            let name = name.unwrap_or("");
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            match w.deployments.get(&crate::store::obj_key(ns, name)) {
                Some(d) => (200, scale_object(name, ns, d.replicas)),
                None => (404, not_found_status(path)),
            }
        }
        ("PATCH" | "PUT", Some("scale")) if resource == "deployments" || resource == "statefulsets" => {
            let ns = url_ns.unwrap_or(crate::store::DEFAULT_NS).to_string();
            let name = name.unwrap_or("").to_string();
            let body_str = String::from_utf8_lossy(cx.body);
            let replicas = serde_json::from_str::<serde_json::Value>(&body_str).ok()
                .or_else(|| serde_yaml::from_str::<serde_json::Value>(&body_str).ok())
                .and_then(|v| v["spec"]["replicas"].as_u64());
            let Some(r) = replicas else {
                return (400, status_json(400, "BadRequest", "no spec.replicas in patch"));
            };
            let key = crate::store::obj_key(&ns, &name);
            match crate::store::commit(world, |w| {
                let d = w.deployments.get_mut(&key).ok_or((404, format!("deployments.apps \"{name}\" not found in namespace \"{ns}\"")))?;
                d.replicas = r as u32;
                Ok(())
            }) {
                Ok(()) => { next_rv(); (200, scale_object(&name, &ns, r as u32)) }
                Err(e) => commit_error(e),
            }
        }

        // ─── Pod logs (non-follow) ───
        ("GET", Some("log")) if resource == "pods" => {
            let ns = url_ns.unwrap_or(crate::store::DEFAULT_NS);
            let tail: u32 = cx.query.get("tailLines").or(cx.query.get("tail")).and_then(|s| s.parse().ok()).unwrap_or(100);
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            pod_logs(&w, ns, name.unwrap_or(""), cx.query.get("container").map(|s| s.as_str()), tail)
        }

        // ─── Pod exec (non-websocket, Royak JSON form) ───
        ("POST", Some("exec")) if resource == "pods" => {
            let ns = url_ns.unwrap_or(crate::store::DEFAULT_NS);
            let pod = name.unwrap_or("");
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            let cmd: Vec<String> = query_all(cx.path_and_query(), "command");
            let cmd: Vec<&str> = if cmd.is_empty() { vec!["sh"] } else { cmd.iter().map(|s| s.as_str()).collect() };
            match find_pod_container(&w, ns, pod, cx.query.get("container").map(|s| s.as_str())) {
                Some(c) => match docker::exec_in_container(&c.id[..12.min(c.id.len())], &cmd) {
                    Ok((code, output)) => (200, serde_json::json!({"kind": "ExecResult", "pod": pod, "exitCode": code, "output": output}).to_string()),
                    Err(e) => (500, status_json(500, "InternalError", &format!("exec error: {e}"))),
                },
                None if find_remote_pod(ns, pod).is_some() => (501, status_json(501, "NotImplemented", &format!("pod {ns}/{pod} runs on another node; exec is served by the node that runs it"))),
                None => (404, status_json(404, "NotFound", &format!("pods \"{pod}\" not found in namespace \"{ns}\""))),
            }
        }

        // ─── Reads ───
        ("GET", None) => {
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            let ns = url_ns;
            match (resource, name) {
                ("pods", Some(n)) => get_pod(&w, n, ns.unwrap_or(crate::store::DEFAULT_NS)),
                ("pods", None) => (200, list_pods(&w, ns)),
                ("deployments", Some(n)) => get_deployment(&w, n, ns.unwrap_or(crate::store::DEFAULT_NS)),
                ("deployments", None) => (200, list_deployments(&w, ns)),
                ("namespaces", Some(n)) => get_namespace(&w, n),
                ("namespaces", None) => (200, list_namespaces(&w)),
                ("configmaps", Some(n)) => get_configmap(&w, n, ns.unwrap_or(crate::store::DEFAULT_NS)),
                ("configmaps", None) => (200, list_configmaps(&w, ns)),
                ("secrets", Some(n)) => get_secret(&w, n, ns.unwrap_or(crate::store::DEFAULT_NS)),
                ("secrets", None) => (200, list_secrets(&w, ns)),
                ("nodes", Some(n)) => get_node(&w, n),
                ("nodes", None) => (200, list_nodes(&w)),
                ("services", Some(n)) => match w.services.get(&crate::store::obj_key(ns.unwrap_or(crate::store::DEFAULT_NS), n)) {
                    Some(s) => (200, service_json(s).to_string()),
                    None => (404, status_json(404, "NotFound", &format!("services \"{n}\" not found"))),
                },
                ("services", None) => {
                    let mut items: Vec<serde_json::Value> = w.services.values()
                        .filter(|s| ns.map(|n| n == s.namespace).unwrap_or(true)).map(service_json).collect();
                    items.sort_by_key(|v| (v["metadata"]["namespace"].as_str().unwrap_or("").to_string(), v["metadata"]["name"].as_str().unwrap_or("").to_string()));
                    (200, serde_json::json!({"kind": "ServiceList", "apiVersion": "v1", "metadata": {"resourceVersion": current_rv()}, "items": items}).to_string())
                }
                ("events", _) => {
                    let items: Vec<serde_json::Value> = w.events.iter().rev()
                        .filter(|e| ns.map(|n| n == e.namespace).unwrap_or(true)).take(50).map(event_json).collect();
                    (200, serde_json::json!({"kind": "EventList", "apiVersion": "v1", "metadata": {"resourceVersion": current_rv()}, "items": items}).to_string())
                }
                _ => (404, status_json(404, "NotFound", &format!("the server could not find the requested resource: {path}"))),
            }
        }

        // ─── DELETE ───
        ("DELETE", None) => {
            let Some(name) = name.map(|s| s.to_string()) else {
                return (400, status_json(400, "BadRequest", "resource name required"));
            };
            let ns = if resource == "namespaces" { name.clone() } else { url_ns.unwrap_or(crate::store::DEFAULT_NS).to_string() };
            if resource == "pods" {
                // Deleting a pod removes its containers; its owner (if any)
                // re-creates it. This is a runtime action, not a state change.
                let w = world.read().unwrap_or_else(|e| e.into_inner());
                let all = docker::list_containers(true).unwrap_or_default();
                let ours = reconcile::our_containers(&w, &all);
                let here = ours.iter().any(|c| c.labels.get(crate::store::LABEL_POD) == Some(&name)
                    && c.labels.get(crate::store::LABEL_NAMESPACE).map(|s| s.as_str()).unwrap_or(crate::store::DEFAULT_NS) == ns);
                if here {
                    crate::workload::remove_pod(&ours, &ns, &name);
                    crate::placement::forget(&name);
                    next_rv();
                    return (200, ok_status(&format!("pods/{name} deleted")));
                }
                return match find_remote_pod(&ns, &name) {
                    Some((node, addr)) => match reconcile::remote_delete_pod(&addr, &ns, &name) {
                        Ok(()) => { next_rv(); (200, ok_status(&format!("pods/{name} deleted (on {node})"))) }
                        Err(e) => (502, status_json(502, "BadGateway", &format!("pod {name} runs on {node}; delete failed: {e}"))),
                    },
                    None => (404, status_json(404, "NotFound", &format!("pods \"{name}\" not found in namespace \"{ns}\""))),
                };
            }
            let (res, n2, ns2) = (resource.to_string(), name.clone(), ns.clone());
            match crate::store::commit(world, move |w| {
                w.delete_resource(&res, &ns2, &n2).ok_or((404, format!("{res} \"{n2}\" not found in namespace \"{ns2}\"")))
            }) {
                Ok(cleanup) => {
                    reconcile::cleanup_paths(&cleanup);
                    next_rv();
                    (200, ok_status(&format!("{resource}/{name} deleted")))
                }
                Err(e) => commit_error(e),
            }
        }

        // ─── PATCH (strategic merge into the stored manifest, or field patch) ───
        ("PATCH", None) if name.is_some() && serde_json::from_slice::<serde_json::Value>(cx.body).map(|v| v.get("kind").is_none()).unwrap_or(false) => {
            let ns = url_ns.unwrap_or(crate::store::DEFAULT_NS).to_string();
            let name = name.unwrap_or("").to_string();
            let patch: serde_json::Value = serde_json::from_slice(cx.body).unwrap_or(serde_json::Value::Null);
            match resource {
                "deployments" | "statefulsets" => {
                    let mkey = format!("Deployment/{ns}/{name}");
                    let key = crate::store::obj_key(&ns, &name);
                    let caller = caller.clone();
                    let res = crate::store::commit(world, |w| {
                        if let Some(mut manifest) = w.manifests.get(&mkey).cloned() {
                            strategic_merge(&mut manifest, &patch);
                            let yaml = serde_yaml::to_string(&manifest).map_err(|e| (400, e.to_string()))?;
                            let mut resources = spec::parse_yaml(&yaml).map_err(|e| (400, format!("merged manifest invalid: {e}")))?;
                            bind_and_authorize(w, &caller, "patch", Some(&ns), Some(&name), &mut resources)
                                .map_err(|(c, m)| (c, serde_json::from_str::<serde_json::Value>(&m).ok().and_then(|v| v["message"].as_str().map(|s| s.to_string())).unwrap_or(m)))?;
                            for r in &resources { w.apply(r).map_err(|e| (400, e))?; }
                            w.manifests.insert(mkey.clone(), manifest.clone());
                            Ok(manifest)
                        } else {
                            let dep = w.deployments.get_mut(&key).ok_or((404, format!("deployments.apps \"{name}\" not found in namespace \"{ns}\"")))?;
                            if let Some(r) = patch.pointer("/spec/replicas").and_then(|v| v.as_u64()) { dep.replicas = r as u32; }
                            if let Some(img) = patch.pointer("/spec/template/spec/containers/0/image").and_then(|v| v.as_str()) {
                                dep.image = img.to_string();
                                if let Some(c) = dep.containers.first_mut() { c.image = img.to_string(); }
                            }
                            Ok(deployment_json(dep))
                        }
                    });
                    match res {
                        Ok(mut out) => {
                            next_rv();
                            out["metadata"]["resourceVersion"] = serde_json::json!(current_rv());
                            out["metadata"]["uid"] = serde_json::json!(resource_uid("Deployment", &name, &ns));
                            (200, out.to_string())
                        }
                        Err(e) => commit_error(e),
                    }
                }
                "configmaps" => {
                    let key = crate::store::obj_key(&ns, &name);
                    match crate::store::commit(world, |w| {
                        let cm = w.configmaps.get_mut(&key).ok_or((404, format!("configmaps \"{name}\" not found in namespace \"{ns}\"")))?;
                        if let Some(data) = patch.get("data").and_then(|d| d.as_object()) {
                            for (k, v) in data {
                                match v {
                                    serde_json::Value::Null => { cm.data.remove(k); }
                                    v => { cm.data.insert(k.clone(), v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string())); }
                                }
                            }
                        }
                        Ok(())
                    }) {
                        Ok(()) => { next_rv(); (200, ok_status(&format!("configmap/{name} patched"))) }
                        Err(e) => commit_error(e),
                    }
                }
                _ => (400, status_json(400, "BadRequest", &format!("PATCH not supported for {resource}"))),
            }
        }

        // ─── POST/PUT/PATCH with full objects: apply ───
        ("POST" | "PUT" | "PATCH", None) => {
            if cx.body.len() > MAX_BODY_SIZE {
                return (413, status_json(413, "RequestEntityTooLarge", "body too large"));
            }
            let mut resources = match parse_body_resources(cx.body) {
                Ok(r) => r,
                Err(e) => return (400, status_json(400, "BadRequest", &e)),
            };
            let verb = if method == "POST" { "create" } else if method == "PUT" { "update" } else { "patch" };
            {
                let w = world.read().unwrap_or_else(|e| e.into_inner());
                if let Err(resp) = bind_and_authorize(&w, caller, verb, url_ns, if method == "POST" { None } else { name }, &mut resources) {
                    return resp;
                }
            }
            // Keep raw docs (with the bound namespace) for the manifest store.
            let mut docs = body_docs_as_json(&String::from_utf8_lossy(cx.body));
            for (d, r) in docs.iter_mut().zip(resources.iter()) {
                if let Some(ns) = &r.metadata.namespace { d["metadata"]["namespace"] = serde_json::json!(ns); }
            }
            commit_apply(world, resources, docs)
        }

        _ => (405, status_json(405, "MethodNotAllowed", &format!("{method} {path} is not supported"))),
    }
}

impl Ctx<'_> {
    fn path_and_query(&self) -> String {
        let q: Vec<String> = self.query.iter().map(|(k, v)| format!("{k}={v}")).collect();
        format!("{}?{}", self.path, q.join("&"))
    }
}

/// All values of a repeated query parameter (`command=a&command=b`), decoded.
fn query_all(url: String, key: &str) -> Vec<String> {
    let q = url.split_once('?').map(|(_, q)| q).unwrap_or("");
    q.split('&').filter_map(|kv| kv.split_once('=')).filter(|(k, _)| *k == key)
        .map(|(_, v)| url_decode(&v.replace('+', " "))).collect()
}

fn service_json(s: &reconcile::StoredService) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1", "kind": "Service",
        "metadata": {"name": s.name, "namespace": s.namespace, "uid": resource_uid("Service", &s.name, &s.namespace)},
        "spec": {"type": s.service_type, "selector": s.selector,
            "ports": s.ports.iter().map(|p| serde_json::json!({"port": p.port, "targetPort": p.target_port, "protocol": p.protocol})).collect::<Vec<_>>()}
    })
}

fn event_json(e: &reconcile::ClusterEvent) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1", "kind": "Event",
        "metadata": {"name": format!("{}.{}", e.object, e.count), "namespace": e.namespace, "uid": resource_uid("Event", &e.object, &e.reason)},
        "involvedObject": {"kind": e.kind, "name": e.object, "namespace": e.namespace},
        "reason": e.reason, "message": e.message, "type": e.event_type, "count": e.count,
        "firstTimestamp": event_time(&e.first_seen), "lastTimestamp": event_time(&e.last_seen)
    })
}

/// Events store epoch seconds; Kubernetes clients expect RFC 3339.
fn event_time(stored: &str) -> String {
    stored.parse::<u64>().map(rfc3339).unwrap_or_else(|_| stored.to_string())
}

// ─── Node-to-node endpoints (HMAC-verified before they get here) ───

/// Runs a verified node request and signs the response, bound to the
/// request's nonce and the status, so the caller can verify it came from a
/// cluster member and answers this very request.
async fn handle_node_request(method: &str, path: &str, body: Bytes, world: Arc<RwLock<DesiredWorld>>, signer: String, req_nonce: String) -> hyper::Response<BoxedBody> {
    let (status, out) = if let Some(which) = path.strip_prefix("/royak/v1/raft/") {
        match crate::raft_node::handle_rpc(which, &body).await {
            Ok(json) => (200, json),
            Err(e) => (503, serde_json::json!({"error": e}).to_string()),
        }
    } else {
        let p = path.to_string();
        let m = method.to_string();
        tokio::task::spawn_blocking(move || node_route(&m, &p, &body, &world, &signer))
            .await
            .unwrap_or_else(|_| (500, status_json(500, "InternalError", "handler panicked")))
    };
    node_response(path, &req_nonce, status, out)
}

/// A sealed, signed answer to a verified node request.
fn node_response(path: &str, req_nonce: &str, status: u16, out: String) -> hyper::Response<BoxedBody> {
    let (wire, sig) = crate::node_rpc::seal_and_sign_response(path, req_nonce, status, out.as_bytes());
    let mut b = hyper::Response::builder()
        .status(status)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", wire.len());
    for (k, v) in sig {
        b = b.header(k, v);
    }
    b.body(Full::new(Bytes::from(wire)).boxed()).unwrap()
}

fn node_route(method: &str, path: &str, body: &[u8], world: &Arc<RwLock<DesiredWorld>>, signer: &str) -> (u16, String) {
    match (method, path) {
        ("POST", "/royak/v1/heartbeat") => {
            let hello: reconcile::NodeHello = match serde_json::from_slice(body) {
                Ok(h) => h,
                Err(e) => return (400, status_json(400, "BadRequest", &format!("bad hello: {e}"))),
            };
            if hello.node != signer {
                return (403, status_json(403, "Forbidden", "hello names a different node than the signature"));
            }
            let mut w = world.write().unwrap_or_else(|e| e.into_inner());
            reconcile::record_peer(&mut w, &hello);
            (200, serde_json::to_string(&reconcile::local_hello(&w)).unwrap_or_default())
        }
        ("GET", "/royak/v1/pods") => {
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            let all = docker::list_containers(true).unwrap_or_default();
            let ours = reconcile::our_containers(&w, &all);
            (200, serde_json::to_string(&reconcile::local_views(&w, &ours)).unwrap_or_else(|_| "[]".into()))
        }
        ("POST", "/royak/v1/create-pod") => {
            let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
            let Some(sealed) = v["sealed"].as_str() else {
                return (400, status_json(400, "BadRequest", "sealed pod plan required"));
            };
            let plan = match crate::workload::unseal_launch(sealed) {
                Ok(p) => p,
                Err(e) => return (400, status_json(400, "BadRequest", &format!("cannot open pod plan: {e}"))),
            };
            let (cluster_id, me) = (world.read().unwrap_or_else(|e| e.into_inner()).cluster_id.clone(), crate::store::node_name());
            if plan.cluster_id != cluster_id || plan.node != me {
                return (409, status_json(409, "Conflict", &format!("plan is for cluster {} node {}, this is cluster {cluster_id} node {me}", plan.cluster_id, plan.node)));
            }
            if plan.host_local {
                return (409, status_json(409, "Conflict", &format!("pod {} uses host-local storage, which exists only on the node that owns it; refusing remote placement", plan.pod)));
            }
            for c in plan.init_containers.iter().chain(plan.containers.iter()) {
                if !docker::image_exists_locally(&c.image) {
                    if let Err(e) = docker::pull_image(&c.image) {
                        return (503, status_json(503, "ImageUnavailable", &format!(
                            "image {:?} is not present on node {me} and cannot be pulled ({e}); local-only images must be distributed to every node", c.image)));
                    }
                }
            }
            match crate::workload::launch_pod(&plan) {
                Ok(()) => {
                    eprintln!("  ✓ [multi-node] launched {}/{} here (dispatched by {signer})", plan.namespace, plan.pod);
                    (200, serde_json::json!({"status": "ok", "pod": plan.pod}).to_string())
                }
                Err(e) => (500, status_json(500, "LaunchFailed", &format!("{}: {e}", plan.pod))),
            }
        }
        ("POST", "/royak/v1/delete-pod") => {
            let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
            let (Some(ns), Some(pod)) = (v["namespace"].as_str(), v["pod"].as_str()) else {
                return (400, status_json(400, "BadRequest", "namespace and pod required"));
            };
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            let all = docker::list_containers(true).unwrap_or_default();
            let ours = reconcile::our_containers(&w, &all);
            crate::workload::remove_pod(&ours, ns, pod);
            (200, serde_json::json!({"status": "ok", "pod": pod}).to_string())
        }
        ("GET", p) if p.starts_with("/royak/v1/pod-logs/") => {
            let rest = p.strip_prefix("/royak/v1/pod-logs/").unwrap_or("");
            let Some((ns, pod)) = rest.split_once('/') else {
                return (400, status_json(400, "BadRequest", "/royak/v1/pod-logs/<namespace>/<pod>"));
            };
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            match find_pod_container(&w, ns, pod, None) {
                Some(c) => match docker::get_logs(&c.id[..12.min(c.id.len())], 200) {
                    Ok(l) => (200, l),
                    Err(e) => (500, status_json(500, "InternalError", &e)),
                },
                None => (404, status_json(404, "NotFound", &format!("pod {ns}/{pod} is not on this node"))),
            }
        }
        _ => (404, status_json(404, "NotFound", &format!("no node endpoint {method} {path}"))),
    }
}

// ─── Async request handler: authentication + authorization for EVERY request ───

async fn handle_request(
    req: Request<Incoming>,
    world: Arc<RwLock<DesiredWorld>>,
) -> Result<hyper::Response<BoxedBody>, Infallible> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let full_url = uri.to_string();
    let headers = req.headers().clone();
    let query = parse_query(uri.query());
    let websocket = headers.get("upgrade").and_then(|v| v.to_str().ok())
        .map(|s| s.eq_ignore_ascii_case("websocket")).unwrap_or(false);

    // Dashboard: static page, no data.
    if (path == "/" || path == "/dashboard") && method == hyper::Method::GET {
        const DASHBOARD_HTML: &str = include_str!("dashboard.html");
        return Ok(hyper::Response::builder()
            .status(200)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(DASHBOARD_HTML)).boxed())
            .unwrap());
    }

    let access = crate::auth::classify(method.as_str(), &path, &query, websocket);

    // ── Node endpoints: HMAC signature over method, path, time, nonce, body ──
    if access == crate::auth::Access::Node {
        let body = req.collect().await.map(|c| c.to_bytes()).unwrap_or_default();
        let header = |k: &str| headers.get(k).and_then(|v| v.to_str().ok()).map(|s| s.to_string());
        return Ok(match crate::auth::verify_node(method.as_str(), &path, header, &body) {
            Ok(signer) => {
                let nonce = header(crate::auth::HDR_NONCE).unwrap_or_default();
                match crate::node_rpc::open_body(&body) {
                    Ok(plain) => handle_node_request(method.as_str(), &path, Bytes::from(plain), world, signer, nonce).await,
                    Err(e) => {
                        eprintln!("  ⛔ [auth] node endpoint {} {}: body not sealed for this cluster: {e}", method.as_str(), path);
                        node_response(&path, &nonce, 400, status_json(400, "BadRequest", "node RPC body must be sealed"))
                    }
                }
            }
            Err(e) => {
                eprintln!("  ⛔ [auth] node endpoint {} {}: {e}", method.as_str(), path);
                json_response(401, &status_json(401, "Unauthorized", "valid node signature required"))
            }
        });
    }

    // ── Users: identity only from a verified bearer token ──
    let identity = crate::auth::authenticate(headers.get("authorization").and_then(|v| v.to_str().ok()));
    match &access {
        crate::auth::Access::Public => {}
        crate::auth::Access::Node => unreachable!(),
        crate::auth::Access::Authenticated => {
            if identity.is_none() {
                return Ok(json_response(401, &status_json(401, "Unauthorized", "Unauthorized: valid bearer token required")));
            }
        }
        crate::auth::Access::Rbac(attrs) => {
            let Some(id) = &identity else {
                return Ok(json_response(401, &status_json(401, "Unauthorized", "Unauthorized: valid bearer token required")));
            };
            let allowed = {
                let w = world.read().unwrap_or_else(|e| e.into_inner());
                crate::auth::authorize(&w, id, attrs)
            };
            if !allowed {
                eprintln!("  ⛔ [rbac] {} denied: {}", id.user, attrs.describe());
                return Ok(json_response(403, &forbidden(id, attrs)));
            }
        }
    }
    let attrs_ns: Option<String> = match &access { crate::auth::Access::Rbac(a) => a.namespace.clone(), _ => None };

    // ── Streaming / upgraded endpoints (already authorized above) ──
    if path.contains("/pods/") && path.ends_with("/exec") && websocket {
        return Ok(handle_exec_ws(req, &path, &full_url, &headers, world).await);
    }
    if path.contains("/pods/") && path.ends_with("/portforward") && websocket
        && headers.get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).map(|s| s.contains("channel.k8s.io")).unwrap_or(false)
    {
        return Ok(handle_portforward_ws(req, &path, &full_url, &headers, world).await);
    }
    if path.contains("/pods/") && path.ends_with("/log")
        && matches!(query.get("follow").map(|v| v.as_str()), Some("true" | "1"))
    {
        return Ok(handle_log_stream(&path, &query, world).await);
    }
    if matches!(query.get("watch").map(|v| v.as_str()), Some("true" | "1")) {
        return Ok(handle_watch(&path, &query, world, attrs_ns).await);
    }

    let is_write = matches!(method, hyper::Method::POST | hyper::Method::PUT | hyper::Method::PATCH);
    let body_bytes = if is_write || method == hyper::Method::DELETE {
        match req.collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => return Ok(json_response(400, &status_json(400, "BadRequest", "could not read request body"))),
        }
    } else {
        Bytes::new()
    };
    if body_bytes.len() > MAX_BODY_SIZE {
        return Ok(json_response(413, &status_json(413, "RequestEntityTooLarge", "body too large")));
    }

    // ── Admission webhooks: validate object writes before they are applied ──
    if is_write && crate::auth::parse_k8s_path(&path).map(|(_, _, _, sub)| sub.is_none()).unwrap_or(false) {
        if let Some(deny) = admission_gate(&world, &body_bytes).await {
            return Ok(json_response(403, &deny));
        }
    }

    // route_request does blocking work (locks, Docker, fsync, Raft commit
    // wait) — keep it off the async workers.
    let (status, body) = tokio::task::spawn_blocking(move || {
        let cx = Ctx { method: method.as_str(), path: &path, query: &query, body: &body_bytes, world: &world, caller: identity.as_ref() };
        route_request(&cx)
    })
    .await
    .unwrap_or_else(|_| (500, status_json(500, "InternalError", "handler panicked")));
    Ok(json_response(status, &body))
}

// ─── Streaming handlers ───

/// Stream container logs (kubectl logs -f). Resolves the pod among this
/// node's own Royak containers by namespace + pod label.
async fn handle_log_stream(path: &str, query: &HashMap<String, String>, world: Arc<RwLock<DesiredWorld>>) -> hyper::Response<BoxedBody> {
    let Some((ns, _, Some(pod), _)) = crate::auth::parse_k8s_path(path) else {
        return json_response(400, &status_json(400, "BadRequest", "pod log path expected"));
    };
    let ns = ns.unwrap_or(crate::store::DEFAULT_NS).to_string();
    let pod = pod.to_string();
    let tail: u32 = query.get("tailLines").or(query.get("tail")).and_then(|s| s.parse().ok()).unwrap_or(100);
    let container = query.get("container").cloned();
    let (ns2, pod2) = (ns.clone(), pod.clone());
    let found = tokio::task::spawn_blocking(move || {
        let w = world.read().unwrap_or_else(|e| e.into_inner());
        find_pod_container(&w, &ns2, &pod2, container.as_deref()).map(|c| c.id[..12.min(c.id.len())].to_string())
    }).await.ok().flatten();
    let Some(cid) = found else {
        let msg = match find_remote_pod(&ns, &pod) {
            Some((node, _)) => format!("pod {ns}/{pod} runs on node {node}; follow its logs through that node's API"),
            None => format!("pods \"{pod}\" not found in namespace \"{ns}\""),
        };
        return json_response(404, &status_json(404, "NotFound", &msg));
    };
    eprintln!("  [stream] logs -f {ns}/{pod} (tail={tail})");
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    tokio::task::spawn_blocking(move || {
        docker::stream_logs_to_channel(&cid, tail, tx);
    });
    stream_response("text/plain; charset=utf-8", rx)
}

/// Watch resource changes (kubectl get -w). `ns` limits the stream to one
/// namespace (the request's namespace; authorization already checked it).
async fn handle_watch(path: &str, _query: &HashMap<String, String>, world: Arc<RwLock<DesiredWorld>>, ns: Option<String>) -> hyper::Response<BoxedBody> {
    let kind = crate::auth::parse_k8s_path(path).map(|(_, r, _, _)| r.to_string()).unwrap_or_default();
    eprintln!("  [watch] {kind} ns={}", ns.as_deref().unwrap_or("*"));
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        let snap = |world: Arc<RwLock<DesiredWorld>>, kind: String, ns: Option<String>| async move {
            tokio::task::spawn_blocking(move || watch_objects(&kind, &world, ns.as_deref())).await.unwrap_or_default()
        };
        let mut last = snap(world.clone(), kind.clone(), ns.clone()).await;
        for obj in last.values() {
            let line = format!("{}\n", serde_json::json!({"type": "ADDED", "object": obj}));
            if tx.send(Bytes::from(line)).await.is_err() { return; }
        }
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            interval.tick().await;
            if tx.is_closed() { return; }
            let cur = snap(world.clone(), kind.clone(), ns.clone()).await;
            for (key, obj) in &cur {
                let ty = match last.get(key) { None => "ADDED", Some(o) if o != obj => "MODIFIED", _ => continue };
                let line = format!("{}\n", serde_json::json!({"type": ty, "object": obj}));
                if tx.send(Bytes::from(line)).await.is_err() { return; }
            }
            for (key, obj) in &last {
                if !cur.contains_key(key) {
                    let line = format!("{}\n", serde_json::json!({"type": "DELETED", "object": obj}));
                    if tx.send(Bytes::from(line)).await.is_err() { return; }
                }
            }
            last = cur;
        }
    });
    stream_response("application/json", rx)
}

/// Current objects of a kind, keyed by `ns/name`, for watch diffs.
fn watch_objects(kind: &str, world: &Arc<RwLock<DesiredWorld>>, ns: Option<&str>) -> std::collections::BTreeMap<String, serde_json::Value> {
    let w = world.read().unwrap_or_else(|e| e.into_inner());
    let in_ns = |n: &str| ns.map(|q| q == n).unwrap_or(true);
    let mut out = std::collections::BTreeMap::new();
    match kind {
        "pods" => for (v, phase) in cluster_pods(&w) {
            if in_ns(&v.namespace) { out.insert(crate::store::obj_key(&v.namespace, &v.pod), pod_view_json(&v, &phase)); }
        },
        "deployments" => {
            let ready = ready_counts(&w);
            for d in w.deployments.values().filter(|d| in_ns(&d.namespace)) {
                let r = ready.get(&(d.namespace.clone(), d.name.clone())).copied().unwrap_or(0);
                out.insert(crate::store::obj_key(&d.namespace, &d.name), deployment_json_ready(d, r));
            }
        }
        "services" => for s in w.services.values().filter(|s| in_ns(&s.namespace)) {
            out.insert(crate::store::obj_key(&s.namespace, &s.name), service_json(s));
        },
        "events" => for e in w.events.iter().rev().filter(|e| in_ns(&e.namespace)).take(50) {
            out.insert(format!("{}/{}/{}", e.namespace, e.object, e.reason), event_json(e));
        },
        "namespaces" if ns.is_none() => for n in w.namespaces.iter() {
            out.insert(n.to_string(), serde_json::json!({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": n}, "status": {"phase": "Active"}}));
        },
        _ => {}
    }
    out
}

/// Resolve `.../namespaces/{ns}/pods/{pod}/{exec|portforward}` (+ optional
/// `container=`) to the short id of a RUNNING container of that pod on this
/// node. Err carries the HTTP answer (404, or a hint when the pod runs on a
/// peer).
async fn resolve_ws_container(path: &str, full_url: &str, world: Arc<RwLock<DesiredWorld>>) -> Result<String, hyper::Response<BoxedBody>> {
    let Some((ns, _, Some(pod), _)) = crate::auth::parse_k8s_path(path) else {
        return Err(json_response(400, &status_json(400, "BadRequest", "pod path expected")));
    };
    let ns = ns.unwrap_or(crate::store::DEFAULT_NS).to_string();
    let pod = pod.to_string();
    let container = query_all(full_url.to_string(), "container").into_iter().next();
    let (ns2, pod2) = (ns.clone(), pod.clone());
    let found = tokio::task::spawn_blocking(move || {
        let w = world.read().unwrap_or_else(|e| e.into_inner());
        find_pod_container(&w, &ns2, &pod2, container.as_deref())
            .filter(|c| c.state == "running")
            .map(|c| c.id[..12.min(c.id.len())].to_string())
    }).await.ok().flatten();
    found.ok_or_else(|| {
        let msg = match find_remote_pod(&ns, &pod) {
            Some((node, _)) => format!("pod {ns}/{pod} runs on node {node}; connect to that node's API"),
            None => format!("pods \"{pod}\" not found (or not running) in namespace \"{ns}\""),
        };
        json_response(404, &status_json(404, "NotFound", &msg))
    })
}

/// Docker name of a container (without the leading slash).
fn cname(c: &docker::DockerContainer) -> String {
    c.names.first().map(|n| n.trim_start_matches('/').to_string()).unwrap_or_default()
}

// ─── Async server ───

pub async fn serve(port: u16, world: Arc<RwLock<DesiredWorld>>) {
    serve_impl(port, world, false).await;
}

pub async fn serve_https(port: u16, world: Arc<RwLock<DesiredWorld>>) {
    serve_impl(port, world, true).await;
}

async fn serve_impl(port: u16, world: Arc<RwLock<DesiredWorld>>, use_tls: bool) {
    let addr = format!("0.0.0.0:{port}");

    // --tls is a promise: tokens never travel in cleartext. Any TLS setup
    // failure is fatal instead of silently serving plain HTTP.
    let tls_fail = |msg: String| -> ! {
        eprintln!("  ✗ TLS requested but unavailable: {msg} — refusing to serve plain HTTP");
        std::process::exit(2);
    };
    let tls_acceptor = if use_tls {
        let (cert_pem, key_pem) = generate_tls_cert().unwrap_or_else(|e| tls_fail(format!("cert generation: {e}")));
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let cert_path = format!("{home}/.kube/royak-ca.pem");
        if let Err(e) = crate::persist::atomic_write(&cert_path, cert_pem.as_bytes()) {
            eprintln!("  ⚠ could not write {cert_path}: {e}");
        }
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes()).filter_map(|r| r.ok()).collect();
        let key = rustls_pemfile::private_key(&mut key_pem.as_bytes()).ok().flatten()
            .unwrap_or_else(|| tls_fail("key parse failed".into()));
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap_or_else(|e| tls_fail(format!("config: {e}")));
        println!("  ✓ TLS cert: {cert_path}");
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
    } else {
        None
    };

    println!("    kubectl: export KUBECONFIG=~/.kube/royak.yaml && kubectl get pods");

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            // Running on without an API would look healthy and serve nothing.
            eprintln!("  ✗ API server failed to start on {addr}: {e} — exiting");
            std::process::exit(2);
        }
    };
    println!("  ✓ API server listening on {addr}{}", if tls_acceptor.is_some() { " (HTTPS)" } else { "" });

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => continue,
        };

        let world = world.clone();
        let tls = tls_acceptor.clone();

        tokio::spawn(async move {
            if let Some(acceptor) = tls {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let io = TokioIo::new(tls_stream);
                        let service = hyper::service::service_fn(move |req| {
                            let w = world.clone();
                            async move { handle_request(req, w).await }
                        });
                        http1::Builder::new().serve_connection(io, service).with_upgrades().await.ok();
                    }
                    Err(e) => eprintln!("  ✗ TLS handshake failed: {e}"),
                }
            } else {
                let io = TokioIo::new(stream);
                let service = hyper::service::service_fn(move |req| {
                    let w = world.clone();
                    async move { handle_request(req, w).await }
                });
                http1::Builder::new().serve_connection(io, service).with_upgrades().await.ok();
            }
        });
    }
}

// ─── Response builders ───

fn version_json() -> String {
    serde_json::json!({
        "major": "0",
        "minor": "2",
        "gitVersion": "v0.4.0-beta.1-royak",
        "gitCommit": "neural",
        "buildDate": "2026-04-16",
        "goVersion": "rust/1.77",
        "compiler": "rustc",
        "platform": format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH)
    }).to_string()
}

fn api_versions() -> String {
    serde_json::json!({
        "kind": "APIVersions",
        "versions": ["v1"],
        "serverAddressByClientCIDRs": [{"clientCIDR": "0.0.0.0/0", "serverAddress": "localhost:6443"}]
    }).to_string()
}

fn api_v1_resources() -> String {
    serde_json::json!({
        "kind": "APIResourceList",
        "groupVersion": "v1",
        "resources": [
            {"name": "pods", "singularName": "pod", "namespaced": true, "kind": "Pod", "verbs": ["get", "list", "create", "delete"]},
            {"name": "namespaces", "singularName": "namespace", "namespaced": false, "kind": "Namespace", "verbs": ["get", "list", "create", "delete"]},
            {"name": "configmaps", "singularName": "configmap", "namespaced": true, "kind": "ConfigMap", "verbs": ["get", "list", "create", "delete"]},
            {"name": "secrets", "singularName": "secret", "namespaced": true, "kind": "Secret", "verbs": ["get", "list", "create", "delete"]},
            {"name": "services", "singularName": "service", "namespaced": true, "kind": "Service", "verbs": ["get", "list"]},
            {"name": "nodes", "singularName": "node", "namespaced": false, "kind": "Node", "verbs": ["get", "list"]},
            {"name": "events", "singularName": "event", "namespaced": true, "kind": "Event", "verbs": ["get", "list"]},
            {"name": "pods/log", "singularName": "", "namespaced": true, "kind": "Pod", "verbs": ["get"]},
        ]
    }).to_string()
}

fn api_groups() -> String {
    serde_json::json!({
        "kind": "APIGroupList",
        "apiVersion": "v1",
        "groups": [
            {
                "name": "apps",
                "versions": [{"groupVersion": "apps/v1", "version": "v1"}],
                "preferredVersion": {"groupVersion": "apps/v1", "version": "v1"}
            }
        ]
    }).to_string()
}

fn apps_v1_resources() -> String {
    serde_json::json!({
        "kind": "APIResourceList",
        "groupVersion": "apps/v1",
        "resources": [
            {"name": "deployments", "singularName": "deployment", "namespaced": true, "kind": "Deployment", "verbs": ["get", "list", "create", "delete", "patch", "update"]},
            {"name": "deployments/scale", "singularName": "", "namespaced": true, "group": "autoscaling", "version": "v1", "kind": "Scale", "verbs": ["get", "patch", "update"]},
            {"name": "daemonsets", "singularName": "daemonset", "namespaced": true, "kind": "DaemonSet", "verbs": ["get", "list"]},
        ]
    }).to_string()
}

/// autoscaling/v1 Scale object — what kubectl scale reads and writes.
/// Minimal Swagger 2.0 / OpenAPI 2 spec. Retained for the day we decide
/// to serve v2 (as JSON with a non-strict Accept negotiator, or as
/// encoded Protobuf). Currently /openapi/v2 returns 404; kubectl uses v3.
#[allow(dead_code)]
fn openapi_v2_spec() -> String {
    serde_json::json!({
        "swagger": "2.0",
        "info": {
            "title": "Royak",
            "version": "v0.4.0-beta.1",
        },
        "paths": {},
        "definitions": {
            "io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "namespace": {"type": "string"},
                    "labels": {"type": "object", "additionalProperties": {"type": "string"}},
                    "annotations": {"type": "object", "additionalProperties": {"type": "string"}},
                }
            },
            "io.k8s.api.core.v1.ConfigMap": {
                "type": "object",
                "required": ["metadata"],
                "properties": {
                    "apiVersion": {"type": "string"},
                    "kind": {"type": "string"},
                    "metadata": {"$ref": "#/definitions/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"},
                    "data": {"type": "object", "additionalProperties": {"type": "string"}},
                    "spec": {"type": "object", "additionalProperties": {"type": "string"}},
                },
                "x-kubernetes-group-version-kind": [{"group": "", "version": "v1", "kind": "ConfigMap"}],
            },
            "io.k8s.api.core.v1.Secret": {
                "type": "object",
                "required": ["metadata"],
                "properties": {
                    "apiVersion": {"type": "string"},
                    "kind": {"type": "string"},
                    "metadata": {"$ref": "#/definitions/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"},
                    "data": {"type": "object", "additionalProperties": {"type": "string"}},
                    "spec": {"type": "object", "additionalProperties": {"type": "string"}},
                    "type": {"type": "string"},
                },
                "x-kubernetes-group-version-kind": [{"group": "", "version": "v1", "kind": "Secret"}],
            },
            "io.k8s.api.core.v1.Namespace": {
                "type": "object",
                "required": ["metadata"],
                "properties": {
                    "apiVersion": {"type": "string"},
                    "kind": {"type": "string"},
                    "metadata": {"$ref": "#/definitions/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"},
                    "spec": {"type": "object"},
                },
                "x-kubernetes-group-version-kind": [{"group": "", "version": "v1", "kind": "Namespace"}],
            },
            "io.k8s.api.core.v1.Service": {
                "type": "object",
                "required": ["metadata"],
                "properties": {
                    "apiVersion": {"type": "string"},
                    "kind": {"type": "string"},
                    "metadata": {"$ref": "#/definitions/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"},
                    "spec": {"type": "object"},
                },
                "x-kubernetes-group-version-kind": [{"group": "", "version": "v1", "kind": "Service"}],
            },
            "io.k8s.api.apps.v1.Deployment": {
                "type": "object",
                "required": ["metadata"],
                "properties": {
                    "apiVersion": {"type": "string"},
                    "kind": {"type": "string"},
                    "metadata": {"$ref": "#/definitions/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"},
                    "spec": {"type": "object"},
                },
                "x-kubernetes-group-version-kind": [{"group": "apps", "version": "v1", "kind": "Deployment"}],
            },
        }
    }).to_string()
}

/// OpenAPI v3 root — lists the per-group spec paths.
fn openapi_v3_root() -> String {
    serde_json::json!({
        "paths": {
            "api/v1": {"serverRelativeURL": "/openapi/v3/api/v1"},
            "apis/apps/v1": {"serverRelativeURL": "/openapi/v3/apis/apps/v1"},
        }
    }).to_string()
}

#[cfg(test)]
mod event_time_tests {
    use super::*;

    #[test]
    fn event_timestamps_render_as_rfc3339() {
        assert_eq!(event_time("0"), "1970-01-01T00:00:00Z");
        assert_eq!(event_time("1792936478"), "2026-10-25T13:54:38Z");
        assert_eq!(event_time("2026-10-25T13:14:38Z"), "2026-10-25T13:14:38Z");
    }
}

#[cfg(test)]
mod openapi_tests {
    use super::*;

    #[test]
    fn openapi_v3_root_lists_known_groups() {
        let root: serde_json::Value = serde_json::from_str(&openapi_v3_root()).unwrap();
        let paths = root["paths"].as_object().expect("paths object");
        assert!(paths.contains_key("api/v1"), "expect core/v1 group");
        assert!(paths.contains_key("apis/apps/v1"), "expect apps/v1 group");
    }

    #[test]
    fn openapi_v3_api_v1_has_configmap_schema() {
        let doc: serde_json::Value = serde_json::from_str(&openapi_v3_group("/openapi/v3/api/v1")).unwrap();
        let schemas = doc["components"]["schemas"].as_object().expect("schemas");
        assert!(schemas.contains_key("io.k8s.api.core.v1.ConfigMap"));
        assert!(schemas.contains_key("io.k8s.api.core.v1.Secret"));
        assert!(schemas.contains_key("io.k8s.api.core.v1.Namespace"));
    }

    #[test]
    fn openapi_v3_api_v1_paths_carry_gvk() {
        let doc: serde_json::Value = serde_json::from_str(&openapi_v3_group("/openapi/v3/api/v1")).unwrap();
        let cm_path = "/api/v1/namespaces/{namespace}/configmaps";
        let post = &doc["paths"][cm_path]["post"];
        assert!(!post.is_null(), "POST operation must exist at {cm_path}");
        // Operation-level extension is a single object (not array) — kubectl's
        // hasGVKExtensionV3 unmarshals it as map[string]string.
        let gvk = &post["x-kubernetes-group-version-kind"];
        assert_eq!(gvk["kind"].as_str(), Some("ConfigMap"));
        assert_eq!(gvk["version"].as_str(), Some("v1"));
    }

    #[test]
    fn openapi_v3_api_v1_has_patch_op_for_apply() {
        let doc: serde_json::Value = serde_json::from_str(&openapi_v3_group("/openapi/v3/api/v1")).unwrap();
        let cm_item = "/api/v1/namespaces/{namespace}/configmaps/{name}";
        let patch = &doc["paths"][cm_item]["patch"];
        assert!(!patch.is_null(), "PATCH operation must exist (kubectl apply lands here)");
        // Must accept application/apply-patch+yaml content type
        let content = &patch["requestBody"]["content"];
        assert!(!content["application/apply-patch+yaml"].is_null());
        // Must declare fieldValidation query param — kubectl checks this.
        let params = patch["parameters"].as_array().expect("params array");
        let has_field_validation = params.iter()
            .any(|p| p["name"].as_str() == Some("fieldValidation") && p["in"].as_str() == Some("query"));
        assert!(has_field_validation, "PATCH must declare fieldValidation query param");
    }

    #[test]
    fn openapi_v3_apps_v1_has_deployment_path() {
        let doc: serde_json::Value = serde_json::from_str(&openapi_v3_group("/openapi/v3/apis/apps/v1")).unwrap();
        let dep_path = "/apis/apps/v1/namespaces/{namespace}/deployments";
        assert!(!doc["paths"][dep_path].is_null(), "deployment path must exist");
    }
}

/// A kind we expose through the kubectl-compatible API. Drives the
/// OpenAPI v3 path + schema generation below.
struct KindDef {
    group: &'static str,      // "" for core, e.g. "apps"
    version: &'static str,    // "v1"
    kind: &'static str,       // "ConfigMap"
    list_kind: &'static str,  // "ConfigMapList"
    plural: &'static str,     // "configmaps"
    namespaced: bool,
    schema_pkg: &'static str, // "io.k8s.api.core.v1" or "io.k8s.api.apps.v1"
}

const KINDS_CORE_V1: &[KindDef] = &[
    KindDef { group: "", version: "v1", kind: "ConfigMap", list_kind: "ConfigMapList",
              plural: "configmaps", namespaced: true, schema_pkg: "io.k8s.api.core.v1" },
    KindDef { group: "", version: "v1", kind: "Secret", list_kind: "SecretList",
              plural: "secrets", namespaced: true, schema_pkg: "io.k8s.api.core.v1" },
    KindDef { group: "", version: "v1", kind: "Service", list_kind: "ServiceList",
              plural: "services", namespaced: true, schema_pkg: "io.k8s.api.core.v1" },
    KindDef { group: "", version: "v1", kind: "Pod", list_kind: "PodList",
              plural: "pods", namespaced: true, schema_pkg: "io.k8s.api.core.v1" },
    KindDef { group: "", version: "v1", kind: "Namespace", list_kind: "NamespaceList",
              plural: "namespaces", namespaced: false, schema_pkg: "io.k8s.api.core.v1" },
];

const KINDS_APPS_V1: &[KindDef] = &[
    KindDef { group: "apps", version: "v1", kind: "Deployment", list_kind: "DeploymentList",
              plural: "deployments", namespaced: true, schema_pkg: "io.k8s.api.apps.v1" },
    KindDef { group: "apps", version: "v1", kind: "DaemonSet", list_kind: "DaemonSetList",
              plural: "daemonsets", namespaced: true, schema_pkg: "io.k8s.api.apps.v1" },
];

/// GVK extension attached to OPERATIONS. kubectl's validator
/// (`hasGVKExtensionV3` in cli-runtime) reads this as a single object via
/// `map[string]string` — NOT as an array. Emitting an array here causes
/// kubectl to silently skip the operation ("Path not found for GVK").
fn gvk_ext_operation(k: &KindDef) -> serde_json::Value {
    serde_json::json!({"group": k.group, "version": k.version, "kind": k.kind})
}

/// GVK extension attached to SCHEMA definitions. This one IS an array,
/// matching real K8s OpenAPI convention.
fn gvk_ext_schema(group: &str, version: &str, kind: &str) -> serde_json::Value {
    serde_json::json!([{"group": group, "version": version, "kind": kind}])
}

fn schema_ref(pkg: &str, kind: &str) -> String {
    format!("#/components/schemas/{pkg}.{kind}")
}

/// Build the list-path (collection) and item-path (single resource)
/// operations for a kind. Real K8s serves:
///   GET    /.../{plural}              list
///   POST   /.../{plural}              create
///   GET    /.../{plural}/{name}       read
///   PUT    /.../{plural}/{name}       replace
///   PATCH  /.../{plural}/{name}       patch   ← kubectl apply lands here
///   DELETE /.../{plural}/{name}       delete
/// kubectl resolves a GVK by scanning operations; apply specifically
/// needs the PATCH operation to be visible at the item path.
fn kind_paths(k: &KindDef) -> Vec<(String, serde_json::Value)> {
    let prefix = if k.group.is_empty() {
        format!("/api/{}", k.version)
    } else {
        format!("/apis/{}/{}", k.group, k.version)
    };
    let (list_path, item_path) = if k.namespaced {
        (
            format!("{prefix}/namespaces/{{namespace}}/{}", k.plural),
            format!("{prefix}/namespaces/{{namespace}}/{}/{{name}}", k.plural),
        )
    } else {
        (
            format!("{prefix}/{}", k.plural),
            format!("{prefix}/{}/{{name}}", k.plural),
        )
    };
    let gvk = gvk_ext_operation(k);
    let schema = schema_ref(k.schema_pkg, k.kind);
    let list_schema = schema_ref(k.schema_pkg, k.list_kind);
    let status_schema = "#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.Status";
    let ns_suffix = if k.namespaced { "Namespaced" } else { "" };

    let params_namespaced = if k.namespaced {
        serde_json::json!([{"name": "namespace", "in": "path", "required": true, "schema": {"type": "string"}}])
    } else {
        serde_json::json!([])
    };
    let params_item = if k.namespaced {
        serde_json::json!([
            {"name": "name", "in": "path", "required": true, "schema": {"type": "string"}},
            {"name": "namespace", "in": "path", "required": true, "schema": {"type": "string"}},
        ])
    } else {
        serde_json::json!([
            {"name": "name", "in": "path", "required": true, "schema": {"type": "string"}},
        ])
    };

    let ok_resp = |ref_schema: &str| serde_json::json!({
        "200": {
            "description": "OK",
            "content": {"application/json": {"schema": {"$ref": ref_schema}}}
        }
    });
    let created_resp = |ref_schema: &str| serde_json::json!({
        "200": {"description": "OK", "content": {"application/json": {"schema": {"$ref": ref_schema}}}},
        "201": {"description": "Created", "content": {"application/json": {"schema": {"$ref": ref_schema}}}},
    });

    // Standard K8s mutation query parameters. kubectl's client-side apply
    // pre-flight specifically looks for `fieldValidation` and `fieldManager`
    // on mutating operations to decide whether to fall through to v2.
    let mutation_params = serde_json::json!([
        {"name": "dryRun", "in": "query", "schema": {"type": "string"}},
        {"name": "fieldManager", "in": "query", "schema": {"type": "string"}},
        {"name": "fieldValidation", "in": "query", "schema": {"type": "string"}},
        {"name": "pretty", "in": "query", "schema": {"type": "string"}},
    ]);
    let delete_params = serde_json::json!([
        {"name": "gracePeriodSeconds", "in": "query", "schema": {"type": "integer"}},
        {"name": "propagationPolicy", "in": "query", "schema": {"type": "string"}},
        {"name": "dryRun", "in": "query", "schema": {"type": "string"}},
    ]);

    let list_ops = serde_json::json!({
        "parameters": params_namespaced,
        "get": {
            "operationId": format!("list{ns_suffix}{}", k.kind),
            "x-kubernetes-action": "list",
            "x-kubernetes-group-version-kind": gvk.clone(),
            "responses": ok_resp(&list_schema),
        },
        "post": {
            "operationId": format!("create{ns_suffix}{}", k.kind),
            "x-kubernetes-action": "post",
            "x-kubernetes-group-version-kind": gvk.clone(),
            "parameters": mutation_params.clone(),
            "requestBody": {
                "required": true,
                "content": {"*/*": {"schema": {"$ref": schema.clone()}}}
            },
            "responses": created_resp(&schema),
        },
    });

    let item_ops = serde_json::json!({
        "parameters": params_item,
        "get": {
            "operationId": format!("read{ns_suffix}{}", k.kind),
            "x-kubernetes-action": "get",
            "x-kubernetes-group-version-kind": gvk.clone(),
            "responses": ok_resp(&schema),
        },
        "put": {
            "operationId": format!("replace{ns_suffix}{}", k.kind),
            "x-kubernetes-action": "put",
            "x-kubernetes-group-version-kind": gvk.clone(),
            "parameters": mutation_params.clone(),
            "requestBody": {
                "required": true,
                "content": {"*/*": {"schema": {"$ref": schema.clone()}}}
            },
            "responses": created_resp(&schema),
        },
        "patch": {
            "operationId": format!("patch{ns_suffix}{}", k.kind),
            "x-kubernetes-action": "patch",
            "x-kubernetes-group-version-kind": gvk.clone(),
            "parameters": serde_json::json!([
                {"name": "dryRun", "in": "query", "schema": {"type": "string"}},
                {"name": "fieldManager", "in": "query", "schema": {"type": "string"}},
                {"name": "fieldValidation", "in": "query", "schema": {"type": "string"}},
                {"name": "force", "in": "query", "schema": {"type": "boolean"}},
                {"name": "pretty", "in": "query", "schema": {"type": "string"}},
            ]),
            "requestBody": {
                "required": true,
                "content": {
                    "application/apply-patch+yaml": {"schema": {"$ref": schema.clone()}},
                    "application/strategic-merge-patch+json": {"schema": {"$ref": schema.clone()}},
                    "application/merge-patch+json": {"schema": {"$ref": schema.clone()}},
                    "application/json-patch+json": {"schema": {"$ref": schema.clone()}},
                }
            },
            "responses": ok_resp(&schema),
        },
        "delete": {
            "operationId": format!("delete{ns_suffix}{}", k.kind),
            "x-kubernetes-action": "delete",
            "x-kubernetes-group-version-kind": gvk.clone(),
            "parameters": delete_params.clone(),
            "responses": ok_resp(status_schema),
        },
    });

    vec![(list_path, list_ops), (item_path, item_ops)]
}

/// Build the OpenAPI v3 components.schemas map for a set of kinds.
fn kind_schemas(kinds: &[KindDef]) -> serde_json::Value {
    let mut schemas = serde_json::Map::new();

    // Shared meta schemas
    let object_meta = serde_json::json!({
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "namespace": {"type": "string"},
            "labels": {"type": "object", "additionalProperties": {"type": "string"}},
            "annotations": {"type": "object", "additionalProperties": {"type": "string"}},
            "uid": {"type": "string"},
            "resourceVersion": {"type": "string"},
            "creationTimestamp": {"type": "string"},
        }
    });
    let list_meta = serde_json::json!({
        "type": "object",
        "properties": {
            "resourceVersion": {"type": "string"},
            "continue": {"type": "string"},
        }
    });
    let status = serde_json::json!({
        "type": "object",
        "properties": {
            "kind": {"type": "string"},
            "apiVersion": {"type": "string"},
            "metadata": {"$ref": "#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.ListMeta"},
            "status": {"type": "string"},
            "message": {"type": "string"},
            "reason": {"type": "string"},
            "code": {"type": "integer"},
        }
    });
    schemas.insert("io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta".into(), object_meta);
    schemas.insert("io.k8s.apimachinery.pkg.apis.meta.v1.ListMeta".into(), list_meta);
    schemas.insert("io.k8s.apimachinery.pkg.apis.meta.v1.Status".into(), status);

    // Full pod-template schemas with strategic-merge hints. kubectl's
    // client-side apply walks these to compute its patch; without
    // spec.template it errors with "unable to find api field template".
    schemas.insert("io.k8s.api.core.v1.Container".into(), serde_json::json!({
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": {"type": "string"},
            "image": {"type": "string"},
            "command": {"type": "array", "items": {"type": "string"}},
            "args": {"type": "array", "items": {"type": "string"}},
            "env": {
                "type": "array",
                "items": {"type": "object", "properties": {"name": {"type": "string"}, "value": {"type": "string"}}},
                "x-kubernetes-patch-merge-key": "name",
                "x-kubernetes-patch-strategy": "merge"
            },
            "envFrom": {"type": "array", "items": {"type": "object"}},
            "ports": {
                "type": "array",
                "items": {"type": "object", "properties": {"containerPort": {"type": "integer"}, "protocol": {"type": "string"}}},
                "x-kubernetes-patch-merge-key": "containerPort",
                "x-kubernetes-patch-strategy": "merge"
            },
            "resources": {"type": "object", "properties": {
                "limits": {"type": "object", "additionalProperties": {"type": "string"}},
                "requests": {"type": "object", "additionalProperties": {"type": "string"}}
            }},
            "volumeMounts": {
                "type": "array",
                "items": {"type": "object", "properties": {"name": {"type": "string"}, "mountPath": {"type": "string"}}},
                "x-kubernetes-patch-merge-key": "mountPath",
                "x-kubernetes-patch-strategy": "merge"
            },
            "livenessProbe": {"type": "object"},
            "readinessProbe": {"type": "object"},
            "startupProbe": {"type": "object"},
        }
    }));
    schemas.insert("io.k8s.api.core.v1.PodSpec".into(), serde_json::json!({
        "type": "object",
        "properties": {
            "containers": {
                "type": "array",
                "items": {"$ref": "#/components/schemas/io.k8s.api.core.v1.Container"},
                "x-kubernetes-patch-merge-key": "name",
                "x-kubernetes-patch-strategy": "merge"
            },
            "initContainers": {
                "type": "array",
                "items": {"$ref": "#/components/schemas/io.k8s.api.core.v1.Container"},
                "x-kubernetes-patch-merge-key": "name",
                "x-kubernetes-patch-strategy": "merge"
            },
            "volumes": {
                "type": "array",
                "items": {"type": "object", "properties": {"name": {"type": "string"}}},
                "x-kubernetes-patch-merge-key": "name",
                "x-kubernetes-patch-strategy": "merge"
            },
            "restartPolicy": {"type": "string"},
        }
    }));
    schemas.insert("io.k8s.api.core.v1.PodTemplateSpec".into(), serde_json::json!({
        "type": "object",
        "properties": {
            "metadata": {"$ref": "#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"},
            "spec": {"$ref": "#/components/schemas/io.k8s.api.core.v1.PodSpec"},
        }
    }));
    schemas.insert("io.k8s.api.apps.v1.DeploymentSpec".into(), serde_json::json!({
        "type": "object",
        "properties": {
            "replicas": {"type": "integer"},
            "selector": {"type": "object", "properties": {
                "matchLabels": {"type": "object", "additionalProperties": {"type": "string"}}
            }},
            "strategy": {"type": "object", "properties": {"type": {"type": "string"}}},
            "template": {"$ref": "#/components/schemas/io.k8s.api.core.v1.PodTemplateSpec"},
        }
    }));

    for k in kinds {
        let spec_schema = if k.kind == "Deployment" {
            serde_json::json!({"$ref": "#/components/schemas/io.k8s.api.apps.v1.DeploymentSpec"})
        } else {
            serde_json::json!({"type": "object"})
        };
        let single = serde_json::json!({
            "type": "object",
            "x-kubernetes-group-version-kind": gvk_ext_schema(k.group, k.version, k.kind),
            "required": ["metadata"],
            "properties": {
                "apiVersion": {"type": "string"},
                "kind": {"type": "string"},
                "metadata": {"$ref": "#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.ObjectMeta"},
                "spec": spec_schema,
                "data": {"type": "object", "additionalProperties": {"type": "string"}},
            }
        });
        let list = serde_json::json!({
            "type": "object",
            "x-kubernetes-group-version-kind": gvk_ext_schema(k.group, k.version, k.list_kind),
            "required": ["items"],
            "properties": {
                "apiVersion": {"type": "string"},
                "kind": {"type": "string"},
                "metadata": {"$ref": "#/components/schemas/io.k8s.apimachinery.pkg.apis.meta.v1.ListMeta"},
                "items": {
                    "type": "array",
                    "items": {"$ref": &schema_ref(k.schema_pkg, k.kind)}
                },
            }
        });
        schemas.insert(format!("{}.{}", k.schema_pkg, k.kind), single);
        schemas.insert(format!("{}.{}", k.schema_pkg, k.list_kind), list);
    }
    serde_json::Value::Object(schemas)
}

/// OpenAPI v3 per-group spec. Generated from the kind table so adding a
/// new kind means appending one row, not hand-editing JSON.
fn openapi_v3_group(path: &str) -> String {
    let kinds: &[KindDef] = if path.contains("/apis/apps/v1") {
        KINDS_APPS_V1
    } else if path.contains("/api/v1") {
        KINDS_CORE_V1
    } else {
        &[]
    };

    let mut paths = serde_json::Map::new();
    for k in kinds {
        for (p, ops) in kind_paths(k) {
            paths.insert(p, ops);
        }
    }
    let schemas = kind_schemas(kinds);

    serde_json::json!({
        "openapi": "3.0.0",
        "info": {"title": "Royak", "version": "v0.4.0-beta.1"},
        "paths": serde_json::Value::Object(paths),
        "components": {"schemas": schemas},
    }).to_string()
}

// ─── Resource helpers ───

fn pod_json(name: &str, ns: &str, image: &str, phase: &str, running: bool) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {
            "name": name, "namespace": ns,
            "uid": resource_uid("Pod", name, ns),
            "resourceVersion": current_rv(),
            "labels": {"app": name.split('-').nth(1).unwrap_or(name)},
            "creationTimestamp": now_rfc3339()
        },
        "spec": {"containers": [{"name": "main", "image": image}]},
        "status": {
            "phase": phase,
            "containerStatuses": [{"name": "main", "ready": running, "restartCount": 0, "image": image}]
        }
    })
}

fn list_namespaces(world: &DesiredWorld) -> String {
    let items: Vec<serde_json::Value> = world.namespaces.iter().map(|ns| {
        serde_json::json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": ns, "uid": resource_uid("Namespace", ns, ""), "resourceVersion": current_rv(), "creationTimestamp": now_rfc3339()},
            "status": {"phase": "Active"}
        })
    }).collect();
    serde_json::json!({"kind": "NamespaceList", "apiVersion": "v1", "metadata": {"resourceVersion": current_rv()}, "items": items}).to_string()
}

fn get_namespace(world: &DesiredWorld, name: &str) -> (u16, String) {
    if world.namespaces.contains(&name.to_string()) {
        (200, serde_json::json!({
            "apiVersion": "v1", "kind": "Namespace",
            "metadata": {"name": name, "uid": resource_uid("Namespace", name, ""), "resourceVersion": current_rv(), "creationTimestamp": now_rfc3339()},
            "status": {"phase": "Active"}
        }).to_string())
    } else {
        (404, serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": format!("namespaces \"{name}\" not found"), "code": 404}).to_string())
    }
}

/// Ready pods per `(namespace, deployment)` across the cluster (local Docker
/// + peer census), counted once per request.
fn ready_counts(world: &DesiredWorld) -> HashMap<(String, String), u32> {
    let mut out: HashMap<(String, String), u32> = HashMap::new();
    for (v, _) in cluster_pods(world) {
        if v.kind == "deployment" && v.ready {
            *out.entry((v.namespace, v.owner)).or_default() += 1;
        }
    }
    out
}

fn deployment_json(dep: &reconcile::StoredDeployment) -> serde_json::Value {
    deployment_json_ready(dep, 0)
}

fn deployment_json_ready(dep: &reconcile::StoredDeployment, ready: u32) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "apps/v1", "kind": "Deployment",
        "metadata": {
            "name": dep.name, "namespace": dep.namespace,
            "uid": resource_uid("Deployment", &dep.name, &dep.namespace),
            "resourceVersion": current_rv(),
            "creationTimestamp": now_rfc3339()
        },
        "spec": {
            "replicas": dep.replicas,
            "selector": {"matchLabels": {"app": dep.name}},
            "template": {"spec": {"containers": dep.containers.iter().map(|c| serde_json::json!({"name": c.name, "image": c.image})).collect::<Vec<_>>()}}
        },
        "status": {"replicas": dep.replicas, "readyReplicas": ready, "availableReplicas": ready}
    })
}

fn list_deployments(world: &DesiredWorld, ns: Option<&str>) -> String {
    let ready = ready_counts(world);
    let items: Vec<serde_json::Value> = world.deployments.values()
        .filter(|d| ns.is_none() || ns == Some(d.namespace.as_str()))
        .map(|d| deployment_json_ready(d, ready.get(&(d.namespace.clone(), d.name.clone())).copied().unwrap_or(0))).collect();
    serde_json::json!({"kind": "DeploymentList", "apiVersion": "apps/v1", "metadata": {"resourceVersion": current_rv()}, "items": items}).to_string()
}

fn get_deployment(world: &DesiredWorld, name: &str, ns: &str) -> (u16, String) {
    match world.deployments.get(&crate::store::obj_key(ns, name)) {
        Some(dep) => {
            let ready = ready_counts(world).get(&(ns.to_string(), name.to_string())).copied().unwrap_or(0);
            let mut j = deployment_json_ready(dep, ready);
            // Surface stored annotations (incl. kubectl's last-applied-
            // configuration) so client-side apply can diff against them.
            if let Some(ann) = world.manifests.get(&format!("Deployment/{ns}/{name}"))
                .and_then(|m| m.get("metadata")).and_then(|md| md.get("annotations"))
            {
                j["metadata"]["annotations"] = ann.clone();
            }
            (200, j.to_string())
        }
        None => (404, serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": format!("deployments.apps \"{name}\" not found"), "code": 404}).to_string()),
    }
}

fn list_configmaps(world: &DesiredWorld, ns: Option<&str>) -> String {
    let items: Vec<serde_json::Value> = world.configmaps.values()
        .filter(|c| ns.is_none() || ns == Some(c.namespace.as_str()))
        .map(|cm| serde_json::json!({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": cm.name, "namespace": cm.namespace, "uid": resource_uid("ConfigMap", &cm.name, &cm.namespace), "resourceVersion": current_rv()},
            "data": cm.data
        })).collect();
    serde_json::json!({"kind": "ConfigMapList", "apiVersion": "v1", "metadata": {"resourceVersion": current_rv()}, "items": items}).to_string()
}

fn get_configmap(world: &DesiredWorld, name: &str, ns: &str) -> (u16, String) {
    match world.configmaps.get(&crate::store::obj_key(ns, name)) {
        Some(cm) => (200, serde_json::json!({
            "apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": cm.name, "namespace": cm.namespace, "uid": resource_uid("ConfigMap", &cm.name, &cm.namespace), "resourceVersion": current_rv()},
            "data": cm.data
        }).to_string()),
        None => (404, serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": format!("configmaps \"{name}\" not found"), "code": 404}).to_string()),
    }
}

fn list_secrets(world: &DesiredWorld, ns: Option<&str>) -> String {
    let items: Vec<serde_json::Value> = world.secrets.values()
        .filter(|s| ns.is_none() || ns == Some(s.namespace.as_str()))
        .map(|s| serde_json::json!({
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": s.name, "namespace": s.namespace, "uid": resource_uid("Secret", &s.name, &s.namespace), "resourceVersion": current_rv()},
            "type": "Opaque", "data": s.data
        })).collect();
    serde_json::json!({"kind": "SecretList", "apiVersion": "v1", "metadata": {"resourceVersion": current_rv()}, "items": items}).to_string()
}

fn get_secret(world: &DesiredWorld, name: &str, ns: &str) -> (u16, String) {
    match world.secrets.get(&crate::store::obj_key(ns, name)) {
        Some(s) => (200, serde_json::json!({
            "apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": s.name, "namespace": s.namespace, "uid": resource_uid("Secret", &s.name, &s.namespace), "resourceVersion": current_rv()},
            "type": "Opaque", "data": s.data
        }).to_string()),
        None => (404, serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": format!("secrets \"{name}\" not found"), "code": 404}).to_string()),
    }
}

fn list_nodes(world: &DesiredWorld) -> String {
    let items: Vec<serde_json::Value> = if world.nodes.is_empty() {
        let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "royak-node".to_string());
        vec![node_json(&hostname, "Ready", 0.0, 0.0, 0, 100.0, 8192.0)]
    } else {
        world.nodes.values().map(|n| {
            let status = match n.status { reconcile::NodeStatus::Ready => "Ready", reconcile::NodeStatus::NotReady => "NotReady", reconcile::NodeStatus::Draining => "Draining" };
            node_json(&n.name, status, n.cpu_used, n.mem_used, n.pod_count, n.cpu_capacity, n.mem_capacity)
        }).collect()
    };
    serde_json::json!({"kind": "NodeList", "apiVersion": "v1", "metadata": {"resourceVersion": current_rv()}, "items": items}).to_string()
}

fn node_json(name: &str, status: &str, cpu: f32, mem: f32, pods: u32, cpu_capacity: f32, mem_capacity: f32) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "v1", "kind": "Node",
        "metadata": {"name": name, "uid": resource_uid("Node", name, ""), "resourceVersion": current_rv(), "labels": {"node-role.royak.io/brain": "true"}},
        "status": {
            "conditions": [{"type": "Ready", "status": if status == "Ready" { "True" } else { "False" }, "reason": status}],
            "allocatable": {"cpu": format!("{:.0}", cpu_capacity), "memory": format!("{:.0}Mi", mem_capacity), "pods": "110"},
            "nodeInfo": {"kubeletVersion": "v0.4.0-beta.1-royak", "containerRuntimeVersion": "docker://24.0", "operatingSystem": std::env::consts::OS, "architecture": std::env::consts::ARCH}
        },
        "royak": {"cpu_used": cpu, "mem_used": mem, "pod_count": pods}
    })
}

fn get_node(world: &DesiredWorld, name: &str) -> (u16, String) {
    if let Some(n) = world.nodes.get(name) {
        let status = match n.status { reconcile::NodeStatus::Ready => "Ready", reconcile::NodeStatus::NotReady => "NotReady", reconcile::NodeStatus::Draining => "Draining" };
        (200, node_json(&n.name, status, n.cpu_used, n.mem_used, n.pod_count, n.cpu_capacity, n.mem_capacity).to_string())
    } else {
        (404, serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": format!("nodes \"{name}\" not found"), "code": 404}).to_string())
    }
}

fn list_pipelines(world: &DesiredWorld) -> String {
    let items: Vec<serde_json::Value> = world.pipelines.values().map(|p| {
        serde_json::json!({
            "kind": "Pipeline",
            "metadata": {"name": p.name},
            "spec": {
                "stages": p.stages.iter().map(|s| s.name.clone()).collect::<Vec<_>>(),
                "triggers": p.triggers.iter().map(|t| t.trigger_type.clone()).collect::<Vec<_>>(),
            }
        })
    }).collect();
    serde_json::json!({
        "kind": "PipelineList",
        "apiVersion": "royak/v1",
        "items": items
    }).to_string()
}

// ─── Ingress Controller (async) ───

pub async fn serve_ingress(port: u16, world: Arc<RwLock<DesiredWorld>>, use_tls: bool) {
    let addr = format!("0.0.0.0:{port}");

    let tls_acceptor = if use_tls {
        match generate_tls_cert() {
            Ok((cert_pem, key_pem)) => {
                let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
                    .filter_map(|r| r.ok())
                    .collect();
                if let Ok(Some(key)) = rustls_pemfile::private_key(&mut key_pem.as_bytes()) {
                    rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs, key)
                        .ok()
                        .map(|cfg| tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
                } else { None }
            }
            Err(_) => None,
        }
    } else { None };

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("  ✗ ingress failed to start on {addr}: {e} — exiting (use --ingress-port 0 to disable it)");
            std::process::exit(2);
        }
    };

    let proto = if tls_acceptor.is_some() { "HTTPS" } else { "HTTP" };
    println!("  ✓ ingress controller on :{port} ({proto})");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(_) => continue,
        };

        let world = world.clone();
        let tls = tls_acceptor.clone();

        tokio::spawn(async move {
            if let Some(acceptor) = tls {
                if let Ok(tls_stream) = acceptor.accept(stream).await {
                    let io = TokioIo::new(tls_stream);
                    let service = hyper::service::service_fn(move |req| {
                        let w = world.clone();
                        async move { handle_ingress(req, w).await }
                    });
                    http1::Builder::new().serve_connection(io, service).await.ok();
                }
            } else {
                let io = TokioIo::new(stream);
                let service = hyper::service::service_fn(move |req| {
                    let w = world.clone();
                    async move { handle_ingress(req, w).await }
                });
                http1::Builder::new().serve_connection(io, service).await.ok();
            }
        });
    }
}

async fn handle_ingress(
    req: Request<Incoming>,
    world: Arc<RwLock<DesiredWorld>>,
) -> Result<hyper::Response<BoxedBody>, Infallible> {
    let host = req.headers().get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(':').next().unwrap_or("")
        .to_string();
    let path = req.uri().path().to_string();

    // ACME HTTP-01 challenge response (Let's Encrypt)
    if path.starts_with("/.well-known/acme-challenge/") {
        let token = path.strip_prefix("/.well-known/acme-challenge/").unwrap_or("");
        // Check if we have a pending challenge for this token
        let acme_dir = std::env::var("ROYAK_ACME_DIR").unwrap_or_else(|_| "/tmp/royak-acme".to_string());
        let key_auth_path = format!("{acme_dir}/.challenge-{token}");
        if let Ok(key_auth) = std::fs::read_to_string(&key_auth_path) {
            eprintln!("  [acme] HTTP-01 challenge response for {host}");
            return Ok(typed_response(200, &key_auth, "text/plain"));
        }
    }

    // Fast path: serve from the lock-free pre-resolved snapshot — no world lock,
    // no per-request Docker call. This is what keeps the ingress concurrent even
    // while the reconcile loop holds the write lock during a tick. Falls through
    // to the live path if the route isn't in the snapshot yet.
    if let Some((ip, port, pod, pod_port)) = snapshot_backend(&host, &path) {
        let method = req.method().clone();
        let req_headers = req.headers().clone();
        let body_bytes = match req.collect().await {
            Ok(c) => c.to_bytes(),
            Err(_) => Bytes::new(),
        };
        return Ok(match proxy_request_async(&ip, port, &pod, pod_port, method.as_str(), &path, &req_headers, &body_bytes).await {
            Ok((status, body, resp_headers)) => {
                let mut builder = hyper::Response::builder().status(status);
                for (k, v) in resp_headers { builder = builder.header(k, v); }
                let body: BoxedBody = Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed();
                builder.body(body).unwrap_or_else(|_| typed_response(500, "response build failed", "text/plain"))
            }
            Err(e) => typed_response(502, &format!("Bad Gateway: {e}"), "text/plain"),
        });
    }

    let backend = {
        let w = world.read().unwrap();
        find_backend(&w, &host, &path)
    };

    let method = req.method().clone();
    let req_headers = req.headers().clone();

    // Read incoming request body (for POST/PUT/PATCH forwarding).
    let body_bytes = match req.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => Bytes::new(),
    };

    let resp = match backend {
        Some((ns, service, svc_port)) => {
            let canary_target = {
                let w = world.read().unwrap_or_else(|e| e.into_inner());
                resolve_canary_target(&w, &ns, &service, svc_port)
            };

            let (target_host, target_port, route_label) = match canary_target {
                Some((ip, port, label)) => (ip, port, label),
                None => {
                    // Service names like "web" aren't resolvable from the ingress
                    // process (which runs on the host, outside any Docker network).
                    // Look up a concrete pod container IP for this service.
                    let w = world.read().unwrap_or_else(|e| e.into_inner());
                    let port = resolve_target_port(&w, &ns, &service, svc_port);
                    match resolve_service_to_pod_ip(&w, &ns, &service) {
                        Some(ip) => (ip.clone(), port, format!("{ns}/{service}:{svc_port} → {ip}:{port}")),
                        None => {
                            drop(w);
                            return Ok(typed_response(503, &format!("Service Unavailable: no ready pod backs {ns}/{service}"), "text/plain"));
                        }
                    }
                }
            };

            eprintln!("  [ingress] {} {host}{path} → {route_label}", method.as_str());
            match proxy_request_async(
                &target_host, target_port, "", 0,
                method.as_str(), &path, &req_headers, &body_bytes,
            ).await {
                Ok((status, body, resp_headers)) => {
                    let mut builder = hyper::Response::builder().status(status);
                    for (k, v) in resp_headers {
                        builder = builder.header(k, v);
                    }
                    let body: BoxedBody = Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed();
                    builder.body(body).unwrap_or_else(|_| typed_response(500, "response build failed", "text/plain"))
                }
                Err(e) => typed_response(502, &format!("Bad Gateway: {e}"), "text/plain"),
            }
        }
        None => {
            eprintln!("  [ingress] {} {host}{path} → no backend (404)", method.as_str());
            let body_html = format!(
                "<html><body><h1>404 Not Found</h1><p>No ingress rule for {host}{path}</p><hr><p>Royak Ingress Controller</p></body></html>"
            );
            typed_response(404, &body_html, "text/html")
        }
    };
    Ok(resp)
}

/// Resolve canary target: if a service's deployment has a canary rollout,
/// route to old or new version based on canary weight (real traffic splitting).
fn resolve_canary_target(world: &DesiredWorld, ns: &str, service: &str, port: u16) -> Option<(String, u16, String)> {
    let svc = world.services.get(&crate::store::obj_key(ns, service))?;
    let app_name = svc.selector.get("app")?;
    let key = crate::store::obj_key(ns, app_name);
    // Rollouts are keyed like deployments (`ns/name`); older entries use the
    // bare name (default namespace only).
    let rollout = world.pending_rollouts.get(&key)
        .or_else(|| if ns == crate::store::DEFAULT_NS { world.pending_rollouts.get(app_name.as_str()) } else { None })?;
    let weight = world.deployments.get(&key)
        .and_then(|d| d.strategy.as_ref())
        .and_then(|s| match s {
            reconcile::DeployStrategy::Canary { weight, .. } => Some(*weight),
            _ => None,
        })
        .unwrap_or(50);
    let roll: u32 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().subsec_nanos()) % 100;
    let use_new = roll < weight;
    let target_image = if use_new { &rollout.new_image } else { &rollout.old_image };
    let version = if use_new { "canary" } else { "stable" };
    let all = docker::list_containers(false).ok()?;
    let container = reconcile::our_containers(world, &all).into_iter().find(|c| c.state == "running"
        && c.labels.get(crate::store::LABEL_DEPLOYMENT) == Some(app_name)
        && c.labels.get(crate::store::LABEL_NAMESPACE).map(|s| s.as_str()).unwrap_or(crate::store::DEFAULT_NS) == ns
        && c.labels.get(crate::store::LABEL_ROLE).map(|r| r == "main").unwrap_or(true)
        && c.image.contains(target_image.as_str()))?;
    let ip = docker::container_ip(&container.id[..12.min(container.id.len())]).ok()?;
    Some((ip, port, format!("{ns}/{service}:{port} [{version} {weight}%→{target_image}]")))
}

/// The deployment a service selects (its `app` selector), in its namespace.
fn service_backend(world: &DesiredWorld, ns: &str, service: &str) -> Option<String> {
    let svc = world.services.get(&crate::store::obj_key(ns, service))?;
    let app = svc.selector.get("app")?;
    world.deployments.get(&crate::store::obj_key(ns, app)).map(|d| d.name.clone())
}

fn resolve_service_to_pod_ip(world: &DesiredWorld, ns: &str, service: &str) -> Option<String> {
    resolve_service_to_all_pod_ips(world, ns, service).into_iter().next()
}

/// IPs of this node's READY pods backing `ns/service` — only this cluster's
/// own containers, matched by namespace + owner label (never a name prefix).
fn resolve_service_to_all_pod_ips(world: &DesiredWorld, ns: &str, service: &str) -> Vec<String> {
    let Some(dep) = service_backend(world, ns, service) else { return Vec::new() };
    let Ok(all) = docker::list_containers(false) else { return Vec::new() };
    let ours = reconcile::our_containers(world, &all);
    let mut ips = Vec::new();
    for v in reconcile::local_views(world, &ours) {
        if v.kind != "deployment" || v.owner != dep || v.namespace != ns || !v.running || !v.ready { continue; }
        if let Ok(ip) = docker::container_ip(&v.pod) {
            if !ip.is_empty() { ips.push(ip); }
        }
    }
    ips
}

/// Pure port-remap: given a Service's ports and the ingress rule's port, return
/// the container-side port to connect to. K8s semantics: the ingress rule names
/// the Service's published `port`; the pod actually listens on the matching
/// `targetPort`. Fall back to `rule_port` when no ServicePort matches (the
/// Service is unknown or exposes a single implicit port), which also mirrors K8s
/// where an unset targetPort defaults to `port`.
fn target_port_for(ports: &[crate::reconcile::ServicePort], rule_port: u16) -> u16 {
    ports.iter()
        .find(|p| p.port == rule_port)
        .map(|p| p.target_port)
        .unwrap_or(rule_port)
}

/// Resolve an ingress rule's port to the backing Service's targetPort so ingress
/// traffic reaches pods on the port they actually listen on.
fn resolve_target_port(world: &DesiredWorld, ns: &str, service: &str, rule_port: u16) -> u16 {
    match world.services.get(&crate::store::obj_key(ns, service)) {
        Some(svc) => target_port_for(&svc.ports, rule_port),
        None => rule_port,
    }
}

// ─── Lock-free ingress route snapshot ───
// The reconcile loop holds the world WRITE lock for a whole tick (docker I/O),
// which makes every ingress request block on `world.read()` and stalls the async
// runtime under concurrency (~10 req/s). Instead, the reconcile publishes a
// compact, pre-resolved routing table after each tick; ingress requests read it
// lock-free and skip the per-request docker container_ip call entirely.
#[derive(Clone)]
pub struct ResolvedRoute {
    pub host: String,
    pub path: String,
    /// (ip, port, target_pod, pod_port). target_pod empty → connect directly to
    /// a local pod IP (pod_port unused). Set → ip:port is a PEER's mesh proxy;
    /// inject X-Royak-Pod so the peer hands the request off to that pod, plus
    /// X-Royak-Port = pod_port (the pod's resolved Service targetPort) so the
    /// peer dials the pod on the port it actually listens on, not a hardcoded 80.
    pub backends: Vec<(String, u16, String, u16)>,
}

fn ingress_snapshot() -> &'static std::sync::Mutex<Arc<Vec<ResolvedRoute>>> {
    static SNAP: std::sync::OnceLock<std::sync::Mutex<Arc<Vec<ResolvedRoute>>>> = std::sync::OnceLock::new();
    SNAP.get_or_init(|| std::sync::Mutex::new(Arc::new(Vec::new())))
}

// Peer pod census for the ingress — (peer_api_addr, pod_name) — published by the
// reconcile loop's cluster census so the ingress can round-robin onto pods that
// live on OTHER nodes (reached via that node's mesh proxy).
/// Snapshot the cross-node pod census — `(peer_api_addr, pod_name)` pairs for
/// pods living on OTHER nodes. The mesh proxy's Router uses this to resolve a
/// Host-routed service to the peer that actually hosts its pods.
pub fn peer_pods() -> Vec<(String, String)> {
    crate::placement::peer_pod_addrs()
}

/// Rebuild the pre-resolved ingress routing table. Called by the reconcile loop
/// AFTER each tick (off the write-lock). Local pods resolve to their container
/// IP; pods on peer nodes resolve to that peer's mesh proxy + the pod name.
pub fn publish_ingress_snapshot(world: &DesiredWorld) {
    let peers = crate::placement::peer_reports();
    let mut routes = Vec::new();
    for ingress in world.ingresses.values() {
        for rule in &ingress.rules {
            for ip_path in &rule.paths {
                let mut backends: Vec<(String, u16, String, u16)> = Vec::new();
                // The ingress rule targets the Service's published `port` (e.g. 80),
                // but the pods listen on the Service's `targetPort` (e.g. 8080). We
                // connect straight to pod IPs, so resolve rule port → targetPort.
                let ns = ingress.namespace.as_str();
                let pod_port = resolve_target_port(world, ns, &ip_path.service, ip_path.port);
                // Local pods → direct (pod_port used as the connect port).
                for ip in resolve_service_to_all_pod_ips(world, ns, &ip_path.service) {
                    backends.push((ip, pod_port, String::new(), pod_port));
                }
                // Remote pods → via the owning peer's mesh proxy (:6550). We connect
                // to the mesh proxy port, but carry the pod's real targetPort as the
                // 4th field so the peer dials the pod on it (X-Royak-Port) not :80.
                if let Some(dep) = service_backend(world, ns, &ip_path.service) {
                    for r in &peers {
                        let host = r.addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(r.addr.as_str());
                        for p in r.pods.iter().filter(|p| p.kind == "deployment" && p.owner == dep && p.namespace == ns && p.running && p.ready) {
                            backends.push((host.to_string(), crate::cluster_mesh::DEFAULT_MESH_PORT, p.pod.clone(), pod_port));
                        }
                    }
                }
                if !backends.is_empty() {
                    routes.push(ResolvedRoute { host: rule.host.clone(), path: ip_path.path.clone(), backends });
                }
            }
        }
    }
    if let Ok(mut g) = ingress_snapshot().lock() {
        *g = Arc::new(routes);
    }
}

/// Longest-prefix lookup in the published snapshot. Lock-free (Arc clone).
/// Round-robins across ALL backends — local and remote — so a refresh lands on
/// a different pod, possibly on a different node. Returns (ip, port, target_pod).
fn snapshot_backend(host: &str, path: &str) -> Option<(String, u16, String, u16)> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static RR: AtomicUsize = AtomicUsize::new(0);
    let snap = ingress_snapshot().lock().ok()?.clone();
    let route = snap.iter()
        .filter(|r| (r.host.is_empty() || r.host == host) && path.starts_with(&r.path))
        .max_by_key(|r| r.path.len())?;
    if route.backends.is_empty() { return None; }
    let n = RR.fetch_add(1, Ordering::Relaxed);
    Some(route.backends[n % route.backends.len()].clone())
}

// ─── Consolidated demo dashboard snapshot (lock-free read model) ───
// The demo page used to poll /royak/v1/brain (world.read → blocks on the
// reconcile write-lock) + /royak/v1/top/pods (a docker call per request) +
// two endpoints that 404'd — every 2s. Under chaos the reconcile tick holds
// the world lock long enough to freeze all of it. Instead we publish ONE
// pre-rendered JSON blob after each tick and the page polls just /demo/state,
// served lock-free (Arc<String> clone) with zero world.read() and zero docker.
fn demo_state_snapshot() -> &'static std::sync::Mutex<Arc<String>> {
    static SNAP: std::sync::OnceLock<std::sync::Mutex<Arc<String>>> = std::sync::OnceLock::new();
    SNAP.get_or_init(|| std::sync::Mutex::new(Arc::new(String::from("{}"))))
}

// ─── Live activity feed — royak's reconcile decisions, for the demo ───
fn activity_log() -> &'static std::sync::Mutex<std::collections::VecDeque<String>> {
    static LOG: std::sync::OnceLock<std::sync::Mutex<std::collections::VecDeque<String>>> = std::sync::OnceLock::new();
    LOG.get_or_init(|| std::sync::Mutex::new(std::collections::VecDeque::new()))
}
/// Record an interesting reconcile decision (scale / routing / create / chaos /
/// heal) for the demo's live activity panel — you watch the orchestrator think.
pub fn push_activity(line: &str) {
    if let Ok(mut q) = activity_log().lock() {
        q.push_back(line.trim().to_string());
        while q.len() > 60 { q.pop_front(); }
    }
}

/// When this cluster first came alive (unix secs). Persisted to a file so it
/// survives royak restarts/redeploys — this is real *cluster* uptime, not a
/// per-page or per-process timer.
fn cluster_born_secs() -> u64 {
    static B: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *B.get_or_init(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        let path = format!("{home}/.royak/born");
        if let Ok(s) = std::fs::read_to_string(&path) {
            if let Ok(t) = s.trim().parse::<u64>() { if t > 0 { return t; } }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        std::fs::create_dir_all(format!("{home}/.royak")).ok();
        std::fs::write(&path, now.to_string()).ok();
        now
    })
}

/// Desired pod count = Σ deployment replicas. This is the *target* the cluster
/// is reconciling toward, NOT how many are currently running — a chaos kill or a
/// mid-rollout gap makes the two diverge. Pure; unit-tested.
pub(crate) fn desired_pod_count(world: &DesiredWorld) -> u32 {
    world.deployments.values().map(|d| d.replicas).sum()
}

/// Per-Service detail for the demo page: name, namespace, app selector, type,
/// ports (port→targetPort) and how many running pods currently back it.
///
/// Pure and lock-free — the caller passes the running-pod NAME census it already
/// gathered for this same snapshot (local container names + peer-node pods), and
/// backing pods are counted by the `rk-<deployment>-*` name prefix, the same
/// convention the ingress resolver uses. No docker calls, no world locks here, so
/// it is safe on the reconcile thread and unit-testable.
pub(crate) fn demo_service_details(
    world: &DesiredWorld,
    running_pod_names: &[String],
) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = world.services.values().map(|svc| {
        let app = svc.selector.get("app").cloned().unwrap_or_default();
        // Deployment backing this service (matched on app selector + namespace).
        let deployment = world.deployments.values()
            .find(|d| d.name == app && d.namespace == svc.namespace)
            .map(|d| d.name.clone());
        let backends = deployment.as_ref().map(|dep| {
            let prefix = format!("{}-", crate::store::pod_stem(&svc.namespace, dep));
            running_pod_names.iter()
                .filter(|n| n.trim_start_matches('/').strip_prefix(&prefix)
                    .map(|rest| !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_digit()))
                    .unwrap_or(false))
                .count()
        }).unwrap_or(0);
        let ports: Vec<serde_json::Value> = svc.ports.iter().map(|p| serde_json::json!({
            "port": p.port, "target_port": p.target_port,
        })).collect();
        serde_json::json!({
            "name": svc.name,
            "namespace": svc.namespace,
            "app": app,
            "type": svc.service_type,
            "ports": ports,
            "backends": backends,
        })
    }).collect();
    out.sort_by(|a, b| a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or("")));
    out
}

/// Per-Ingress-rule detail for the demo page: host, path → backend service:port.
/// Pure; derived straight from the world snapshot.
pub(crate) fn demo_ingress_details(world: &DesiredWorld) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    for ing in world.ingresses.values() {
        for rule in &ing.rules {
            for p in &rule.paths {
                out.push(serde_json::json!({
                    "host": rule.host,
                    "path": p.path,
                    "service": p.service,
                    "port": p.port,
                }));
            }
        }
    }
    out.sort_by(|a, b| {
        let ka = (a["host"].as_str().unwrap_or(""), a["path"].as_str().unwrap_or(""));
        let kb = (b["host"].as_str().unwrap_or(""), b["path"].as_str().unwrap_or(""));
        ka.cmp(&kb)
    });
    out
}

/// Per-HPA detail for the demo page: target deployment, min/max, target CPU% and
/// the deployment's current replica count. Pure; derived from the world snapshot.
pub(crate) fn demo_hpa_details(world: &DesiredWorld) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = world.hpas.values().map(|h| {
        let replicas = world.deployments.get(&crate::store::obj_key(&h.namespace, &h.deployment))
            .map(|d| d.replicas)
            .unwrap_or(0);
        serde_json::json!({
            "name": h.name,
            "deployment": h.deployment,
            "min": h.min_replicas,
            "max": h.max_replicas,
            "target_cpu": h.target_cpu,
            "replicas": replicas,
        })
    }).collect();
    out.sort_by(|a, b| a["name"].as_str().unwrap_or("").cmp(b["name"].as_str().unwrap_or("")));
    out
}

pub fn publish_demo_state(world: &DesiredWorld) {
    let certs_issued = world.cluster_ca.as_ref().map(|ca| ca.issued_count).unwrap_or(0);
    let uptime_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
        .saturating_sub(cluster_born_secs());
    // Per-pod cpu/mem from the 8s-cached docker stats (cheap; runs on the
    // reconcile thread between ticks, never on a request path).
    let mut pods = Vec::new();
    let mut pod_names: Vec<String> = Vec::new();  // running-pod name census (local + peer)
    if let Ok(containers) = docker::list_containers(true) {
        for c in reconcile::our_containers(world, &containers).into_iter()
            .filter(|c| c.state == "running" && c.labels.contains_key(crate::store::LABEL_POD))
        {
            let short = &c.id[..12.min(c.id.len())];
            let name = c.names.first().map(|s| s.trim_start_matches('/')).unwrap_or("?");
            let (cpu, mem) = docker::container_stats_peek(short).unwrap_or((0.0, 0.0));
            pod_names.push(name.to_string());
            pods.push(serde_json::json!({
                "name": name, "cpu_raw": cpu, "memory_raw_mb": mem,
                "cpu": format!("{:.1}%", cpu), "memory": format!("{:.0}Mi", mem),
                "remote": false,
            }));
        }
    }
    // Pods running on PEER nodes (from the ingress census) — so the dashboard
    // reflects the WHOLE cluster, not just this node. Stats aren't fetched
    // cross-node, so they show as remote.
    let peers = peer_pods();
    for (_, name) in &peers {
        pod_names.push(name.clone());
        pods.push(serde_json::json!({
            "name": name, "cpu_raw": 0.0, "memory_raw_mb": 0.0,
            "cpu": "peer", "memory": "peer", "remote": true,
        }));
    }
    // `pods` = Σ desired replicas (the reconcile TARGET); `pods_running` = pods
    // actually up right now (this snapshot's census). The two diverge whenever a
    // pod is mid-heal — the page's "Pods running" tile must use the actual one.
    let cluster = serde_json::json!({
        "pods": desired_pod_count(world),
        "pods_running": pods.len(),
        "deployments": world.deployments.len(),
        "nodes": world.nodes.len(),
        "services": world.services.len(),
        "namespaces": world.namespaces.len(),
    });
    // Compact per-object detail so the page can SHOW the services / ingress /
    // HPAs, not just their counts. All derived lock-free from this snapshot.
    let services = demo_service_details(world, &pod_names);
    let ingresses = demo_ingress_details(world);
    let hpas = demo_hpa_details(world);
    let demo = if demo_enabled() {
        let app = demo_app();
        let reps = world.deployments.get(&crate::store::obj_key(crate::store::DEFAULT_NS, &app)).map(|d| d.replicas).unwrap_or(0);
        serde_json::json!({"enabled": true, "app": app, "replicas": reps, "min": 1, "max": 5})
    } else {
        serde_json::json!({"enabled": false})
    };
    let activity: Vec<String> = activity_log().lock()
        .map(|q| q.iter().cloned().collect()).unwrap_or_default();
    let body = serde_json::json!({
        "cluster": cluster,
        "certs_issued": certs_issued,
        "running": pods.len(),
        "pods": pods,
        "services": services,
        "ingresses": ingresses,
        "hpas": hpas,
        "demo": demo,
        "activity": activity,
        "uptime_secs": uptime_secs,
    }).to_string();
    if let Ok(mut g) = demo_state_snapshot().lock() {
        *g = Arc::new(body);
    }
}

fn find_backend(world: &DesiredWorld, host: &str, path: &str) -> Option<(String, String, u16)> {
    for ingress in world.ingresses.values() {
        for rule in &ingress.rules {
            if !rule.host.is_empty() && rule.host != host { continue; }
            let mut best: Option<&reconcile::IngressPath> = None;
            for ip in &rule.paths {
                if path.starts_with(&ip.path) {
                    if best.is_none() || ip.path.len() > best.unwrap().path.len() {
                        best = Some(ip);
                    }
                }
            }
            if let Some(backend) = best {
                return Some((ingress.namespace.clone(), backend.service.clone(), backend.port));
            }
        }
    }
    None
}

/// Async proxy: forwards one HTTP request to `service:port` and returns
/// the raw response bytes (binary-safe; works for images, gzipped, etc.).
/// Replaces the old blocking std::net version that broke both the tokio
/// runtime (sync read in async context) and non-UTF8 payloads (String read).
/// Build the cross-node handoff header lines for a mesh hop. Empty when
/// target_pod is empty (same-node / direct-to-pod, no handoff). When set, emits
/// both X-Royak-Pod (which pod on the peer's docker bridge) and X-Royak-Port
/// (the pod's resolved Service targetPort) so the peer dials the right port.
fn handoff_headers(target_pod: &str, pod_port: u16) -> String {
    if target_pod.is_empty() {
        String::new()
    } else {
        format!("X-Royak-Pod: {target_pod}\r\nX-Royak-Port: {pod_port}\r\n")
    }
}

async fn proxy_request_async(
    service: &str,
    port: u16,
    target_pod: &str,
    pod_port: u16,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<(u16, Vec<u8>, Vec<(String, String)>), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let addr = format!("{service}:{port}");

    // Build the request line + headers. Pass the client's headers through
    // (except Host which we rewrite, hop-by-hop headers the RFC says should
    // not cross a proxy boundary, and our own handoff headers, which only we
    // may set).
    let mut req = format!("{method} {path} HTTP/1.1\r\n");
    req.push_str(&format!("Host: {service}\r\n"));
    // Cross-node: {service}:{port} is the peer's mesh proxy — tell it exactly
    // which local pod on its docker bridge to hand this request off to, and on
    // which port (the resolved Service targetPort) to dial it.
    req.push_str(&handoff_headers(target_pod, pod_port));
    for (name, val) in headers.iter() {
        let lname = name.as_str().to_ascii_lowercase();
        if matches!(lname.as_str(),
            "host" | "connection" | "keep-alive" | "proxy-authenticate" |
            "proxy-authorization" | "te" | "trailer" | "transfer-encoding" |
            "upgrade" | "content-length" | "x-royak-pod" | "x-royak-port"
        ) { continue; }
        if let Ok(v) = val.to_str() {
            req.push_str(&format!("{}: {}\r\n", name.as_str(), v));
        }
    }
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    req.push_str("Connection: close\r\n\r\n");
    let mut wire = req.into_bytes();
    wire.extend_from_slice(body);

    let raw = if !target_pod.is_empty() {
        // Peer hop: sealed with the cluster secret — the peer's mesh accepts
        // nothing else in cluster mode.
        crate::cluster_mesh::sealed_exchange(&addr, &wire, std::time::Duration::from_secs(15)).await?
    } else {
        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| format!("connect {addr}: timeout"))?
        .map_err(|e| format!("connect {addr}: {e}"))?;
        stream.write_all(&wire).await.map_err(|e| format!("write: {e}"))?;
        // Read everything until EOF (connection: close guarantees this).
        let mut raw = Vec::with_capacity(4096);
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            stream.read_to_end(&mut raw),
        )
        .await
        .map_err(|_| "read: timeout".to_string())?
        .map_err(|e| format!("read: {e}"))?;
        raw
    };

    // Split response into head + body. We need to forward status, headers,
    // and binary body separately (body may be non-UTF8).
    let sep = b"\r\n\r\n";
    let (head_bytes, body_bytes): (&[u8], &[u8]) = raw.windows(sep.len())
        .position(|w| w == sep)
        .map(|p| (&raw[..p], &raw[p + sep.len()..]))
        .ok_or_else(|| "response has no header/body separator".to_string())?;

    let head_str = std::str::from_utf8(head_bytes).map_err(|_| "non-utf8 response head".to_string())?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status: u16 = status_line.split_whitespace().nth(1)
        .and_then(|s| s.parse().ok()).unwrap_or(502);

    let mut resp_headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k = k.trim();
            let v = v.trim();
            let lk = k.to_ascii_lowercase();
            // Drop hop-by-hop + content-length (we compute our own).
            if matches!(lk.as_str(),
                "connection" | "keep-alive" | "proxy-authenticate" |
                "proxy-authorization" | "te" | "trailer" | "transfer-encoding" |
                "upgrade" | "content-length"
            ) { continue; }
            resp_headers.push((k.to_string(), v.to_string()));
        }
    }

    Ok((status, body_bytes.to_vec(), resp_headers))
}


/// Parse a request body (JSON or multi-doc YAML) into JSON manifests.
fn body_docs_as_json(body_str: &str) -> Vec<serde_json::Value> {
    if body_str.trim_start().starts_with('{') {
        serde_json::from_str::<serde_json::Value>(body_str).ok().into_iter().collect()
    } else {
        body_str.split("\n---")
            .filter_map(|d| serde_yaml::from_str::<serde_json::Value>(d.trim()).ok())
            .filter(|v| v.is_object())
            .collect()
    }
}

/// Strategic-merge a partial patch into a manifest. Objects merge key-by-key
/// (null deletes), arrays of objects merge by their K8s merge key
/// (name / containerPort / mountPath), other values replace.
fn strategic_merge(base: &mut serde_json::Value, patch: &serde_json::Value) {
    match (base, patch) {
        (serde_json::Value::Object(b), serde_json::Value::Object(p)) => {
            for (k, pv) in p {
                if pv.is_null() {
                    b.remove(k);
                    continue;
                }
                match b.get_mut(k) {
                    Some(bv) => {
                        if bv.is_array() && pv.is_array() {
                            merge_arrays(bv, pv);
                        } else if bv.is_object() && pv.is_object() {
                            strategic_merge(bv, pv);
                        } else {
                            *bv = pv.clone();
                        }
                    }
                    None => { b.insert(k.clone(), pv.clone()); }
                }
            }
        }
        (b, p) => { *b = p.clone(); }
    }
}

fn merge_arrays(base: &mut serde_json::Value, patch: &serde_json::Value) {
    const MERGE_KEYS: [&str; 3] = ["name", "containerPort", "mountPath"];
    let (Some(b), Some(p)) = (base.as_array().cloned(), patch.as_array()) else { return };
    // Find the merge key both sides use
    let key = MERGE_KEYS.iter().find(|k| {
        p.iter().all(|e| e.get(**k).is_some()) && b.iter().all(|e| e.get(**k).is_some()) && !p.is_empty()
    });
    match key {
        Some(k) => {
            let mut merged = b.clone();
            for pe in p {
                if let Some(be) = merged.iter_mut().find(|be| be.get(*k) == pe.get(*k)) {
                    strategic_merge(be, pe);
                } else {
                    merged.push(pe.clone());
                }
            }
            *base = serde_json::Value::Array(merged);
        }
        None => { *base = patch.clone(); }
    }
}

// ─── kubectl exec over WebSocket ───
//
// kubectl ≥1.30 runs exec over a WebSocket with the "channel" subprotocol:
// each binary message is prefixed with a channel byte (0 stdin, 1 stdout,
// 2 stderr, 3 error/status). We support the non-interactive case: run the
// command via the Docker exec API, stream captured stdout/stderr back, then
// send a metav1.Status on the error channel. Interactive -it (stdin + TTY)
// is not supported yet — the ledger says so.
async fn handle_exec_ws(
    req: hyper::Request<hyper::body::Incoming>,
    path: &str,
    full_url: &str,
    headers: &HeaderMap,
    world: Arc<RwLock<DesiredWorld>>,
) -> hyper::Response<BoxedBody> {
    // The pod's container among this node's own Royak containers, by
    // namespace + pod label (never a name substring of foreign containers).
    let pod_name = match resolve_ws_container(path, full_url, world).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // Repeated command params: ?command=sh&command=-c&command=...
    let cmd: Vec<String> = full_url.split_once('?')
        .map(|(_, q)| q.split('&')
            .filter_map(|kv| kv.strip_prefix("command="))
            .map(url_decode)
            .collect())
        .unwrap_or_default();

    let key = headers.get("sec-websocket-key").and_then(|v| v.to_str().ok()).unwrap_or("");
    if key.is_empty() || cmd.is_empty() {
        return json_response(400, r#"{"kind":"Status","status":"Failure","message":"exec needs a websocket upgrade and at least one command param","code":400}"#);
    }
    let accept = ws_accept_key(key);
    // Echo back a channel subprotocol the client offered (prefer v4).
    let offered = headers.get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).unwrap_or("");
    // Prefer v5: it adds explicit stream-close messages (channel 255), which
    // is what lets `kubectl exec -i pod -- cat` terminate when stdin closes.
    let proto = ["v5.channel.k8s.io", "v4.channel.k8s.io", "channel.k8s.io"]
        .iter().find(|p| offered.contains(*p)).copied().unwrap_or("v4.channel.k8s.io");

    let response = hyper::Response::builder()
        .status(101)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", accept)
        .header("Sec-WebSocket-Protocol", proto)
        .body(Full::new(Bytes::new()).boxed())
        .unwrap();

    // Interactive path: kubectl exec -i/-t sends stdin=true (and tty=true for -t).
    let wants_stdin = full_url.contains("stdin=true");
    let wants_tty = full_url.contains("tty=true");
    if wants_stdin {
        let pod2 = pod_name.clone();
        let cmd2 = cmd.clone();
        tokio::spawn(async move {
            let Ok(upgraded) = hyper::upgrade::on(req).await else { return };
            exec_interactive_bridge(upgraded, pod2, cmd2, wants_tty).await;
        });
        return response;
    }

    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(req).await else { return };
        let mut io = hyper_util::rt::TokioIo::new(upgraded);
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Resolve container + run the command off the reactor.
        let cmd_owned: Vec<String> = cmd.clone();
        let result = tokio::task::spawn_blocking(move || {
            let short = pod_name;
            let refs: Vec<&str> = cmd_owned.iter().map(|s| s.as_str()).collect();
            crate::docker::exec_capture(&short, &refs).ok()
        }).await.ok().flatten();

        match result {
            Some((exit, stdout, stderr)) => {
                if !stdout.is_empty() {
                    let _ = io.write_all(&ws_binary_frame(1, &stdout)).await;
                }
                if !stderr.is_empty() {
                    let _ = io.write_all(&ws_binary_frame(2, &stderr)).await;
                }
                let status = if exit == 0 {
                    serde_json::json!({"metadata": {}, "status": "Success"})
                } else {
                    serde_json::json!({
                        "metadata": {}, "status": "Failure",
                        "message": format!("command terminated with non-zero exit code: {exit}"),
                        "reason": "NonZeroExitCode",
                        "details": {"causes": [{"reason": "ExitCode", "message": exit.to_string()}]}
                    })
                };
                let _ = io.write_all(&ws_binary_frame(3, status.to_string().as_bytes())).await;
            }
            None => {
                let status = serde_json::json!({"metadata": {}, "status": "Failure", "message": "pod not found or exec failed", "reason": "InternalError"});
                let _ = io.write_all(&ws_binary_frame(3, status.to_string().as_bytes())).await;
            }
        }
        // Close frame (normal closure 1000) then linger briefly for the client close.
        let _ = io.write_all(&ws_close_frame(1000)).await;
        let _ = io.flush().await;
        let mut sink = [0u8; 1024];
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), io.read(&mut sink)).await;
    });

    response
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i+1..i+3]).ok()
                    .and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex { Some(b) => { out.push(b); i += 3; } None => { out.push(bytes[i]); i += 1; } }
            }
            b'+' => { out.push(b' '); i += 1; }
            b => { out.push(b); i += 1; }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}

/// RFC 6455 accept key: base64(SHA1(key + magic GUID)).
fn ws_accept_key(key: &str) -> String {
    let mut data = key.as_bytes().to_vec();
    data.extend_from_slice(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    b64_bytes(&sha1(&data))
}

/// Server-side WebSocket binary frame (unmasked) with a channel prefix byte.
fn ws_binary_frame(channel: u8, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(payload.len() + 1);
    body.push(channel);
    body.extend_from_slice(payload);
    ws_frame(0x2, &body)
}

fn ws_close_frame(code: u16) -> Vec<u8> {
    ws_frame(0x8, &code.to_be_bytes())
}

fn ws_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x80 | opcode];
    let n = payload.len();
    if n < 126 {
        f.push(n as u8);
    } else if n <= 0xFFFF {
        f.push(126);
        f.extend_from_slice(&(n as u16).to_be_bytes());
    } else {
        f.push(127);
        f.extend_from_slice(&(n as u64).to_be_bytes());
    }
    f.extend_from_slice(payload);
    f
}

/// SHA-1 (RFC 3174). Only used for the WebSocket handshake — not for
/// anything security-sensitive (the handshake spec requires SHA-1).
fn sha1(data: &[u8]) -> [u8; 20] {
    let (mut h0, mut h1, mut h2, mut h3, mut h4) =
        (0x67452301u32, 0xEFCDAB89u32, 0x98BADCFEu32, 0x10325476u32, 0xC3D2E1F0u32);
    let ml = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&ml.to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, word) in chunk.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d; d = c; c = b.rotate_left(30); b = a; a = tmp;
        }
        h0 = h0.wrapping_add(a); h1 = h1.wrapping_add(b); h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d); h4 = h4.wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, h) in [h0, h1, h2, h3, h4].iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&h.to_be_bytes());
    }
    out
}

fn b64_bytes(bytes: &[u8]) -> String {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[((triple >> 18) & 0x3F) as usize] as char);
        out.push(B64[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 { out.push(B64[((triple >> 6) & 0x3F) as usize] as char); } else { out.push('='); }
        if chunk.len() > 2 { out.push(B64[(triple & 0x3F) as usize] as char); } else { out.push('='); }
    }
    out
}

#[cfg(test)]
mod demo_detail_tests {
    use super::*;
    use crate::reconcile::{DesiredWorld, StoredService, StoredDeployment, StoredHPA, ServicePort, IngressRule, IngressPath, StoredIngress};
    use std::collections::HashMap;

    fn deploy(name: &str, replicas: u32) -> StoredDeployment {
        StoredDeployment {
            name: name.to_string(), namespace: "default".to_string(), replicas,
            init_containers: Vec::new(), containers: Vec::new(),
            image: String::new(), previous_image: None, command: None, env: Vec::new(),
            resource_limits: None, strategy: None,
            pause_after_idle: None, paused: false, idle_since: None, stateful: false,
            owner_ref: None,
            restart_nonce: 0,
        }
    }
    fn svc(name: &str, app: &str, ports: Vec<ServicePort>) -> StoredService {
        let mut selector = HashMap::new();
        selector.insert("app".to_string(), app.to_string());
        StoredService {
            name: name.to_string(), namespace: "default".to_string(),
            selector, ports, service_type: "ClusterIP".to_string(),
        }
    }
    fn port(p: u16, tp: u16) -> ServicePort {
        ServicePort { port: p, target_port: tp, protocol: "TCP".to_string(), node_port: None }
    }

    #[test]
    fn desired_pod_count_sums_replicas_and_differs_from_running() {
        // Two deployments desire 3 + 2 = 5 pods total.
        let mut w = DesiredWorld::new();
        w.deployments.insert("default/web".into(), deploy("web", 3));
        w.deployments.insert("default/api".into(), deploy("api", 2));
        assert_eq!(desired_pod_count(&w), 5);

        // The chaos monkey just killed one → only 4 running names in the census.
        // Desired (target) must NOT equal actual-running: this is exactly the
        // distinction the "Pods running" tile has to report honestly.
        let running = vec![
            "rk-web-1".to_string(), "rk-web-2".to_string(),
            "rk-api-1".to_string(), "rk-api-2".to_string(),
        ];
        assert_ne!(desired_pod_count(&w) as usize, running.len());
        assert_eq!(running.len(), 4);
    }

    #[test]
    fn service_details_count_backing_pods_by_name_prefix() {
        let mut w = DesiredWorld::new();
        w.deployments.insert("default/web".into(), deploy("web", 3));
        w.services.insert("default/web-svc".into(), svc("web-svc", "web", vec![port(80, 8080)]));
        // Census: 2 web pods running (one killed), plus an unrelated pod.
        let running = vec![
            "rk-web-4".to_string(), "/rk-web-7".to_string(), "rk-other-1".to_string(),
        ];
        let details = demo_service_details(&w, &running);
        assert_eq!(details.len(), 1);
        let s = &details[0];
        assert_eq!(s["name"], "web-svc");
        assert_eq!(s["app"], "web");
        assert_eq!(s["backends"], 2);  // rk-web-4 and /rk-web-7, not rk-other-1
        assert_eq!(s["ports"][0]["port"], 80);
        assert_eq!(s["ports"][0]["target_port"], 8080);
    }

    #[test]
    fn service_with_no_backing_deployment_reports_zero() {
        let mut w = DesiredWorld::new();
        w.services.insert("default/ghost".into(), svc("ghost", "missing", vec![port(80, 80)]));
        let details = demo_service_details(&w, &["rk-web-1".to_string()]);
        assert_eq!(details[0]["backends"], 0);
    }

    #[test]
    fn ingress_details_flatten_host_path_to_backend() {
        let mut w = DesiredWorld::new();
        w.ingresses.insert("default/ing".into(), StoredIngress {
            name: "ing".into(), namespace: "default".into(), ingress_class: None,
            rules: vec![IngressRule {
                host: "app.example.com".into(),
                paths: vec![IngressPath { path: "/api".into(), service: "api-svc".into(), port: 80 }],
            }],
        });
        let details = demo_ingress_details(&w);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0]["host"], "app.example.com");
        assert_eq!(details[0]["path"], "/api");
        assert_eq!(details[0]["service"], "api-svc");
        assert_eq!(details[0]["port"], 80);
    }

    #[test]
    fn hpa_details_report_current_replicas_of_target() {
        let mut w = DesiredWorld::new();
        w.deployments.insert("default/web".into(), deploy("web", 4));
        w.hpas.insert("default/web-hpa".into(), StoredHPA {
            name: "web-hpa".into(), namespace: "default".into(), deployment: "web".into(),
            min_replicas: 1, max_replicas: 5, target_cpu: 70.0,
            history: Vec::new(), last_scaled: None,
        });
        let details = demo_hpa_details(&w);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0]["deployment"], "web");
        assert_eq!(details[0]["min"], 1);
        assert_eq!(details[0]["max"], 5);
        assert_eq!(details[0]["target_cpu"], 70.0);
        assert_eq!(details[0]["replicas"], 4);  // current desired replicas of target
    }
}

#[cfg(test)]
mod ingress_port_tests {
    use super::*;
    use crate::reconcile::ServicePort;

    fn svc_port(port: u16, target_port: u16) -> ServicePort {
        ServicePort { port, target_port, protocol: "TCP".to_string(), node_port: None }
    }

    #[test]
    fn maps_rule_port_to_target_port() {
        // Service exposes port 80 → pods listen on 8080.
        let ports = vec![svc_port(80, 8080)];
        assert_eq!(target_port_for(&ports, 80), 8080);
    }

    #[test]
    fn target_port_unset_falls_back_to_port() {
        // targetPort unset ⇒ StoredService stores target_port == port; the rule
        // then resolves to the same port the Service publishes.
        let ports = vec![svc_port(80, 80)];
        assert_eq!(target_port_for(&ports, 80), 80);
    }

    #[test]
    fn unknown_port_falls_back_to_rule_port() {
        // Rule references a port the Service does not expose → keep the rule port.
        let ports = vec![svc_port(80, 8080)];
        assert_eq!(target_port_for(&ports, 443), 443);
    }

    #[test]
    fn no_ports_falls_back_to_rule_port() {
        assert_eq!(target_port_for(&[], 8000), 8000);
    }

    #[test]
    fn picks_the_matching_port_among_several() {
        let ports = vec![svc_port(80, 8080), svc_port(443, 8443)];
        assert_eq!(target_port_for(&ports, 443), 8443);
        assert_eq!(target_port_for(&ports, 80), 8080);
    }

    #[test]
    fn handoff_headers_carry_pod_and_port() {
        // A cross-node hop (target_pod set) must emit BOTH X-Royak-Pod and the
        // resolved targetPort as X-Royak-Port so the peer stops hardcoding :80.
        let h = handoff_headers("rk-web-1", 8080);
        assert!(h.contains("X-Royak-Pod: rk-web-1\r\n"), "missing pod header: {h:?}");
        assert!(h.contains("X-Royak-Port: 8080\r\n"), "missing port header: {h:?}");
    }

    #[test]
    fn handoff_headers_empty_for_direct_pod() {
        // Same-node / direct-to-pod (no handoff) → no injected headers.
        assert_eq!(handoff_headers("", 8080), "");
    }

    #[test]
    fn handoff_round_trips_through_mesh_parser() {
        // End-to-end of the wire contract: what the ingress writes is exactly
        // what the peer's mesh proxy reads back for the pod dial port.
        let head = format!(
            "GET / HTTP/1.1\r\nHost: web-svc\r\n{}\r\n",
            handoff_headers("rk-web-3", 8443)
        );
        assert_eq!(crate::cluster_mesh::parse_pod_port(&head), 8443);
    }

    #[test]
    fn handoff_absent_port_defaults_to_80_at_peer() {
        // Direct-pod head (no X-Royak-Port) → peer falls back to 80.
        let head = "GET / HTTP/1.1\r\nHost: web-svc\r\n\r\n";
        assert_eq!(crate::cluster_mesh::parse_pod_port(head), 80);
    }
}

#[cfg(test)]
mod ws_tests {
    use super::*;

    #[test]
    fn sha1_known_vector() {
        let d = sha1(b"abc");
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn ws_accept_rfc_example() {
        assert_eq!(ws_accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn ws_frame_small_payload() {
        let f = ws_frame(0x2, b"hello");
        assert_eq!(f[0], 0x82);
        assert_eq!(f[1], 5);
        assert_eq!(&f[2..], b"hello");
    }
}

// ─── Interactive kubectl exec (-it): full duplex WS ↔ Docker hijack ───

/// Read one WebSocket frame from an async reader. Returns (opcode, payload).
/// Client frames are masked per RFC 6455; we unmask. Handles 16/64-bit
/// extended lengths. Fragmentation is treated as separate frames (kubectl
/// sends whole frames for the channel protocol).
async fn ws_read_frame<R: tokio::io::AsyncRead + Unpin>(
    rd: &mut R,
) -> Option<(u8, Vec<u8>)> {
    use tokio::io::AsyncReadExt;
    let mut hdr = [0u8; 2];
    rd.read_exact(&mut hdr).await.ok()?;
    let opcode = hdr[0] & 0x0F;
    let masked = hdr[1] & 0x80 != 0;
    let mut len = (hdr[1] & 0x7F) as u64;
    if len == 126 {
        let mut ext = [0u8; 2];
        rd.read_exact(&mut ext).await.ok()?;
        len = u16::from_be_bytes(ext) as u64;
    } else if len == 127 {
        let mut ext = [0u8; 8];
        rd.read_exact(&mut ext).await.ok()?;
        len = u64::from_be_bytes(ext);
    }
    if len > 16 * 1024 * 1024 {
        return None; // sanity cap
    }
    let mask = if masked {
        let mut m = [0u8; 4];
        rd.read_exact(&mut m).await.ok()?;
        Some(m)
    } else {
        None
    };
    let mut payload = vec![0u8; len as usize];
    rd.read_exact(&mut payload).await.ok()?;
    if let Some(m) = mask {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= m[i % 4];
        }
    }
    Some((opcode, payload))
}

/// Interactive exec bridge: docker exec with AttachStdin (+TTY) hijacked to a
/// raw duplex unix socket, bridged to the WebSocket channel protocol.
/// Channels: 0 stdin (client→us), 1 stdout, 2 stderr, 3 error/status,
/// 4 resize (client→us, JSON {"Width":..,"Height":..}).
async fn exec_interactive_bridge(
    upgraded: hyper::upgrade::Upgraded,
    pod_name: String,
    cmd: Vec<String>,
    tty: bool,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let io = hyper_util::rt::TokioIo::new(upgraded);
    let (mut ws_rd, ws_wr) = tokio::io::split(io);
    let ws_wr = std::sync::Arc::new(tokio::sync::Mutex::new(ws_wr));

    // 1. Create the exec instance + hijack its start stream (blocking IO).
    let short = pod_name.clone();
    let setup = tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        crate::docker::exec_hijack(&short, &refs, tty).ok()
    }).await.ok().flatten();

    let Some((exec_id, unix_stream)) = setup else {
        let status = serde_json::json!({"metadata": {}, "status": "Failure", "message": "pod not found or exec create failed", "reason": "InternalError"});
        let mut w = ws_wr.lock().await;
        let _ = w.write_all(&ws_binary_frame(3, status.to_string().as_bytes())).await;
        let _ = w.write_all(&ws_close_frame(1000)).await;
        return;
    };

    let exec_id_for_status = exec_id.clone();
    let us_read = unix_stream.try_clone().ok();
    let (docker_tx, mut docker_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    // Docker routes writes to the process stdin only after the hijack upgrade
    // completes. The reader signals `upgraded` once it has seen the 101 head;
    // the stdin writer blocks on it so early keystrokes are not lost.
    let upgraded_barrier = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));

    // 2. Blocking thread: docker → channel
    if let Some(mut us_r) = us_read {
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = [0u8; 8192];
            loop {
                match us_r.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if docker_tx.send(buf[..n].to_vec()).is_err() { break; }
                    }
                    Err(_) => break,
                }
            }
            // channel drop signals EOF
        });
    }

    // 3. Blocking writer thread: stdin bytes → docker socket
    let (stdin_tx, stdin_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let mut stdin_tx = Some(stdin_tx);
    let mut us_w = unix_stream;
    let barrier_in = std::sync::Arc::clone(&upgraded_barrier);
    std::thread::spawn(move || {
        use std::io::Write;
        // Wait until the hijack upgrade is confirmed (bounded), then flush stdin.
        {
            let (m, cv) = &*barrier_in;
            let mut ready = m.lock().unwrap();
            while !*ready {
                let (g, to) = cv.wait_timeout(ready, std::time::Duration::from_secs(5)).unwrap();
                ready = g;
                if to.timed_out() { break; }
            }
        }
        while let Ok(chunk) = stdin_rx.recv() {
            if us_w.write_all(&chunk).is_err() { break; }
            let _ = us_w.flush();
        }
        // Best-effort half-close so the exec'd process sees stdin EOF.
        let _ = us_w.shutdown(std::net::Shutdown::Write);
    });

    // 4. Task: docker output → WS frames (TTY = raw on ch1; else demux)
    let wr_out = std::sync::Arc::clone(&ws_wr);
    let barrier_out = std::sync::Arc::clone(&upgraded_barrier);
    let out_task = tokio::spawn(async move {
        // Docker's hijacked stream starts with an HTTP response head — strip it.
        let mut head_done = false;
        let mut carry: Vec<u8> = Vec::new();
        while let Some(chunk) = docker_rx.recv().await {
            let mut data = if carry.is_empty() { chunk } else {
                let mut c = std::mem::take(&mut carry);
                c.extend_from_slice(&chunk);
                c
            };
            if !head_done {
                if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                    data = data.split_off(pos + 4);
                    head_done = true;
                    { let (m, cv) = &*barrier_out; *m.lock().unwrap() = true; cv.notify_all(); }
                    if data.is_empty() { continue; }
                } else {
                    carry = data;
                    continue;
                }
            }
            let mut w = wr_out.lock().await;
            if tty {
                if w.write_all(&ws_binary_frame(1, &data)).await.is_err() { break; }
            } else {
                // Demux docker stream frames {type,0,0,0,len_be,payload}
                carry = data;
                loop {
                    if carry.len() < 8 { break; }
                    let stype = carry[0];
                    let len = u32::from_be_bytes([carry[4], carry[5], carry[6], carry[7]]) as usize;
                    if carry.len() < 8 + len { break; }
                    let payload: Vec<u8> = carry[8..8 + len].to_vec();
                    let rest = carry.split_off(8 + len);
                    carry = rest;
                    let ch = if stype == 2 { 2 } else { 1 };
                    if w.write_all(&ws_binary_frame(ch, &payload)).await.is_err() { return; }
                }
            }
        }
        // Docker side finished: exit code + status + close.
        let exit = tokio::task::spawn_blocking(move || crate::docker::exec_exit_code(&exec_id_for_status))
            .await.ok().flatten().unwrap_or(-1);
        let status = if exit == 0 {
            serde_json::json!({"metadata": {}, "status": "Success"})
        } else {
            serde_json::json!({
                "metadata": {}, "status": "Failure",
                "message": format!("command terminated with non-zero exit code: {exit}"),
                "reason": "NonZeroExitCode",
                "details": {"causes": [{"reason": "ExitCode", "message": exit.to_string()}]}
            })
        };
        let mut w = wr_out.lock().await;
        let _ = w.write_all(&ws_binary_frame(3, status.to_string().as_bytes())).await;
        let _ = w.write_all(&ws_close_frame(1000)).await;
        let _ = w.flush().await;
    });

    // 5. This task: WS frames → stdin / resize / control
    loop {
        let Some((opcode, payload)) = ws_read_frame(&mut ws_rd).await else { break };
        match opcode {
            0x8 => break, // close
            0x9 => { // ping → pong
                let mut w = ws_wr.lock().await;
                let _ = w.write_all(&ws_frame(0xA, &payload)).await;
            }
            0x1 | 0x2 if !payload.is_empty() => {
                let ch = payload[0];
                let data = &payload[1..];
                match ch {
                    0 => {
                        if let Some(tx) = stdin_tx.as_ref() { let _ = tx.send(data.to_vec()); }
                    }
                    // v5 close message: payload byte names the closed channel.
                    255 => {
                        if data.first() == Some(&0) {
                            stdin_tx.take(); // drop → writer thread half-closes stdin
                        }
                    }
                    4 => {
                        // TTY resize: {"Width":W,"Height":H}
                        if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
                            let w_ = v["Width"].as_u64().unwrap_or(80);
                            let h = v["Height"].as_u64().unwrap_or(24);
                            let eid = exec_id.clone();
                            tokio::task::spawn_blocking(move || {
                                crate::docker::exec_resize(&eid, w_ as u32, h as u32)
                            });
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    stdin_tx.take(); // stdin EOF to the process
    let _ = out_task.await;
}

// ─── kubectl port-forward over WebSocket ───
//
// kubectl's WebSocket port-forward (v4.channel.k8s.io) multiplexes each
// forwarded port onto two channels: data = 2*i, error = 2*i+1 for the i-th
// requested port. Right after the socket opens, the server sends the port
// number as a 2-byte little-endian prefix on BOTH channels. Then client
// bytes on the data channel are forwarded to the pod's port and replies come
// back on the same data channel.
//
// Endpoint resolution: on Linux the royak host can reach the container IP
// directly. On macOS the Docker VM hides container IPs, so we fall back to the
// ephemeral host port Docker published for that container port (present when a
// NodePort/LoadBalancer service exposed it). If neither is reachable we send a
// message on the error channel — same honest Linux-data-path caveat as mesh.
async fn handle_portforward_ws(
    req: hyper::Request<hyper::body::Incoming>,
    path: &str,
    full_url: &str,
    headers: &HeaderMap,
    world: Arc<RwLock<DesiredWorld>>,
) -> hyper::Response<BoxedBody> {
    let pod_name = match resolve_ws_container(path, full_url, world).await {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    // ?ports=8080,9090 or repeated ?ports=
    let ports: Vec<u16> = full_url.split_once('?')
        .map(|(_, q)| q.split('&')
            .filter_map(|kv| kv.strip_prefix("ports="))
            .flat_map(|v| url_decode(v).split(',').filter_map(|p| p.trim().parse::<u16>().ok()).collect::<Vec<_>>())
            .collect())
        .unwrap_or_default();

    let key = headers.get("sec-websocket-key").and_then(|v| v.to_str().ok()).unwrap_or("");
    if key.is_empty() || ports.is_empty() {
        return json_response(400, r#"{"kind":"Status","status":"Failure","message":"port-forward needs a websocket upgrade and at least one ports= param","code":400}"#);
    }
    let accept = ws_accept_key(key);
    let offered = headers.get("sec-websocket-protocol").and_then(|v| v.to_str().ok()).unwrap_or("");
    let proto = ["v4.channel.k8s.io", "portforward.k8s.io"]
        .iter().find(|p| offered.contains(*p)).copied().unwrap_or("v4.channel.k8s.io");

    let response = hyper::Response::builder()
        .status(101)
        .header("Upgrade", "websocket")
        .header("Connection", "Upgrade")
        .header("Sec-WebSocket-Accept", accept)
        .header("Sec-WebSocket-Protocol", proto)
        .body(Full::new(Bytes::new()).boxed())
        .unwrap();

    tokio::spawn(async move {
        let Ok(upgraded) = hyper::upgrade::on(req).await else { return };
        let io = hyper_util::rt::TokioIo::new(upgraded);
        let (mut ws_rd, ws_wr) = tokio::io::split(io);
        let ws_wr = std::sync::Arc::new(tokio::sync::Mutex::new(ws_wr));
        use tokio::io::AsyncWriteExt;

        // Resolve each requested port to a reachable host:port off the reactor.
        let pod2 = pod_name.clone();
        let ports2 = ports.clone();
        let endpoints: Vec<Option<String>> = tokio::task::spawn_blocking(move || {
            let cid = Some(pod2);
            ports2.iter().map(|p| {
                let cid = cid.as_ref()?;
                // Linux: container IP is host-routable.
                if cfg!(target_os = "linux") {
                    if let Ok(ip) = crate::docker::container_ip(cid) {
                        return Some(format!("{ip}:{p}"));
                    }
                }
                // Fallback (macOS): published ephemeral host port.
                crate::docker::container_host_port(cid, *p).map(|hp| format!("127.0.0.1:{hp}"))
            }).collect()
        }).await.unwrap_or_default();

        // Send the port-number prefix on data + error channels for each port.
        {
            let mut w = ws_wr.lock().await;
            for (i, p) in ports.iter().enumerate() {
                let data_ch = (2 * i) as u8;
                let err_ch = (2 * i + 1) as u8;
                let prefix = p.to_le_bytes();
                let _ = w.write_all(&ws_binary_frame(data_ch, &prefix)).await;
                let _ = w.write_all(&ws_binary_frame(err_ch, &prefix)).await;
            }
        }

        // One TCP connection per port, opened lazily on first client byte.
        let conns: Vec<std::sync::Arc<tokio::sync::Mutex<Option<tokio::net::tcp::OwnedWriteHalf>>>> =
            ports.iter().map(|_| std::sync::Arc::new(tokio::sync::Mutex::new(None))).collect();

        loop {
            let Some((opcode, payload)) = ws_read_frame(&mut ws_rd).await else { break };
            match opcode {
                0x8 => break,
                0x9 => { let mut w = ws_wr.lock().await; let _ = w.write_all(&ws_frame(0xA, &payload)).await; }
                0x1 | 0x2 if !payload.is_empty() => {
                    let ch = payload[0];
                    let data = &payload[1..];
                    if ch % 2 != 0 { continue; } // error channels are server→client only
                    let idx = (ch / 2) as usize;
                    if idx >= ports.len() { continue; }
                    // Open the backend connection on first use.
                    let mut guard = conns[idx].lock().await;
                    if guard.is_none() {
                        let Some(Some(endpoint)) = endpoints.get(idx) else {
                            // No route (macOS + unpublished port): tell kubectl.
                            let mut w = ws_wr.lock().await;
                            let msg = format!("port {} not reachable from host (publish it via a NodePort/LoadBalancer service, or run royak on Linux)", ports[idx]);
                            let _ = w.write_all(&ws_binary_frame((2 * idx + 1) as u8, msg.as_bytes())).await;
                            continue;
                        };
                        match tokio::net::TcpStream::connect(endpoint).await {
                            Ok(tcp) => {
                                let (mut rd, wr) = tcp.into_split();
                                *guard = Some(wr);
                                // Pump backend → data channel.
                                let ws_back = std::sync::Arc::clone(&ws_wr);
                                let ch_data = (2 * idx) as u8;
                                tokio::spawn(async move {
                                    use tokio::io::AsyncReadExt;
                                    let mut buf = [0u8; 8192];
                                    loop {
                                        match rd.read(&mut buf).await {
                                            Ok(0) => break,
                                            Ok(n) => {
                                                let mut w = ws_back.lock().await;
                                                if w.write_all(&ws_binary_frame(ch_data, &buf[..n])).await.is_err() { break; }
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                });
                            }
                            Err(e) => {
                                let mut w = ws_wr.lock().await;
                                let msg = format!("connect {}: {e}", endpoints[idx].as_deref().unwrap_or("?"));
                                let _ = w.write_all(&ws_binary_frame((2 * idx + 1) as u8, msg.as_bytes())).await;
                                continue;
                            }
                        }
                    }
                    if let Some(wr) = guard.as_mut() {
                        use tokio::io::AsyncWriteExt;
                        let _ = wr.write_all(data).await;
                    }
                }
                _ => {}
            }
        }
    });

    response
}

/// Admission gate: for each parsed resource in the write body, POST an
/// AdmissionReview to every registered ValidatingWebhookConfiguration whose
/// rules match the kind. If any webhook denies (or is unreachable under a
/// Fail policy), return the denial JSON; None means admitted.
async fn admission_gate(world: &Arc<RwLock<DesiredWorld>>, body: &[u8]) -> Option<String> {
    // Snapshot the webhook set (cheap clone) so we don't hold the lock across await.
    let hooks: Vec<crate::reconcile::AdmissionWebhook> = {
        let w = world.read().unwrap();
        if w.admission_webhooks.is_empty() { return None; }
        w.admission_webhooks.values().cloned().collect()
    };
    let body_str = String::from_utf8_lossy(body);
    let resources = if body_str.trim_start().starts_with('{') {
        serde_json::from_str::<serde_json::Value>(&body_str).ok()
            .and_then(|v| serde_yaml::to_string(&v).ok())
            .and_then(|y| crate::spec::parse_yaml(&y).ok())
    } else {
        crate::spec::parse_yaml(&body_str).ok()
    }?;

    for r in &resources {
        let kind = r.kind.clone();
        let plural = format!("{}s", kind.to_lowercase());
        for h in &hooks {
            let matches = h.kinds.iter().any(|k| k == "*" || k.eq_ignore_ascii_case(&plural) || k.eq_ignore_ascii_case(&kind));
            if !matches { continue; }
            let review = serde_json::json!({
                "apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview",
                "request": {
                    "uid": resource_uid(&kind, &r.metadata.name, r.metadata.namespace.as_deref().unwrap_or("default")),
                    "kind": {"kind": kind},
                    "name": r.metadata.name,
                    "namespace": r.metadata.namespace.clone().unwrap_or_else(|| "default".to_string()),
                    "operation": "CREATE",
                    "object": serde_json::to_value(r.spec.as_ref()).unwrap_or(serde_json::Value::Null),
                }
            });
            match post_admission(&h.url, &review).await {
                Ok(allowed_msg) => {
                    if let Some(reason) = allowed_msg {
                        return Some(serde_json::json!({
                            "kind": "Status", "apiVersion": "v1", "status": "Failure",
                            "message": format!("admission webhook \"{}\" denied the request: {reason}", h.name),
                            "reason": "Forbidden", "code": 403
                        }).to_string());
                    }
                }
                Err(e) => {
                    if h.failure_policy.eq_ignore_ascii_case("Fail") {
                        return Some(serde_json::json!({
                            "kind": "Status", "apiVersion": "v1", "status": "Failure",
                            "message": format!("admission webhook \"{}\" unreachable ({e}); failurePolicy=Fail", h.name),
                            "reason": "InternalError", "code": 403
                        }).to_string());
                    }
                    // Ignore policy → admit.
                }
            }
        }
    }
    None
}

/// POST an AdmissionReview to a webhook. Returns Ok(None) = allowed,
/// Ok(Some(reason)) = denied, Err = transport failure.
async fn post_admission(url: &str, review: &serde_json::Value) -> Result<Option<String>, String> {
    let addr = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = match addr.split_once('/') {
        Some((hp, p)) => (hp.to_string(), format!("/{p}")),
        None => (addr.to_string(), "/".to_string()),
    };
    let body = serde_json::to_vec(review).map_err(|e| e.to_string())?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::time::timeout(std::time::Duration::from_secs(3),
        tokio::net::TcpStream::connect(&host_port)).await
        .map_err(|_| "connect timeout".to_string())?
        .map_err(|e| format!("connect: {e}"))?;
    let req = format!("POST {path} HTTP/1.1\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    stream.write_all(req.as_bytes()).await.map_err(|e| e.to_string())?;
    stream.write_all(&body).await.map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    tokio::time::timeout(std::time::Duration::from_secs(3), stream.read_to_end(&mut raw)).await
        .map_err(|_| "read timeout".to_string())?.map_err(|e| e.to_string())?;
    let sep = b"\r\n\r\n";
    let start = raw.windows(4).position(|w| w == sep).map(|p| p + 4).unwrap_or(0);
    let resp: serde_json::Value = serde_json::from_slice(&raw[start..]).map_err(|e| format!("bad review: {e}"))?;
    let allowed = resp["response"]["allowed"].as_bool().unwrap_or(false);
    if allowed {
        Ok(None)
    } else {
        let reason = resp["response"]["status"]["message"].as_str().unwrap_or("denied").to_string();
        Ok(Some(reason))
    }
}

#[cfg(test)]
mod namespaced_get_tests {
    use super::*;
    use crate::reconcile::{StoredConfigMap, StoredSecret};

    // Regression: single-object GETs looked objects up by bare name after keys
    // became `namespace/name`, so every ConfigMap/Secret GET returned 404.
    #[test]
    fn same_name_in_two_namespaces_resolves_per_namespace() {
        let mut w = DesiredWorld::new();
        for ns in ["a", "b"] {
            let data: HashMap<String, String> = [("who".to_string(), ns.to_string())].into();
            w.configmaps.insert(crate::store::obj_key(ns, "page"), StoredConfigMap { name: "page".into(), namespace: ns.into(), data: data.clone() });
            w.secrets.insert(crate::store::obj_key(ns, "cred"), StoredSecret { name: "cred".into(), namespace: ns.into(), data });
        }
        for ns in ["a", "b"] {
            let (code, body) = get_configmap(&w, "page", ns);
            assert_eq!(code, 200);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["data"]["who"], ns);
            assert_eq!(get_secret(&w, "cred", ns).0, 200);
        }
        assert_eq!(get_configmap(&w, "page", "c").0, 404);
        assert_eq!(get_secret(&w, "cred", "c").0, 404);
    }
}
