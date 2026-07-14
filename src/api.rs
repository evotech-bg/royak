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
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
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

/// Parse path segments: returns (namespace, resource_kind, resource_name)
fn parse_resource_path(path: &str) -> (Option<&str>, &str, Option<&str>) {
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    match parts.as_slice() {
        ["api", "v1", "namespaces", ns, resource, name] => (Some(ns), resource, Some(name)),
        ["apis", "apps", "v1", "namespaces", ns, resource, name] => (Some(ns), resource, Some(name)),
        ["api", "v1", "namespaces", ns, resource] => (Some(ns), resource, None),
        ["apis", "apps", "v1", "namespaces", ns, resource] => (Some(ns), resource, None),
        ["api", "v1", resource, name] => (None, resource, Some(name)),
        ["apis", "apps", "v1", resource, name] => (None, resource, Some(name)),
        ["api", "v1", resource] => (None, resource, None),
        ["apis", "apps", "v1", resource] => (None, resource, None),
        _ => (None, "", None),
    }
}

// ─── Auth helpers (adapted for hyper HeaderMap) ───

/// Check X-Royak-Token header for inter-node auth
fn check_node_auth(headers: &HeaderMap) -> bool {
    headers.get("x-royak-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.len() > 10)
        .unwrap_or(false)
}

/// Extract RBAC role from X-Royak-Role header
fn get_rbac_role(headers: &HeaderMap) -> String {
    headers.get("x-royak-role")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("admin")
        .to_string()
}

/// Map API path resource type to RBAC resource name
fn rbac_resource_from_path(path: &str) -> &str {
    let (_, resource, _) = parse_resource_path(path);
    resource
}

/// Map HTTP method to RBAC verb
fn rbac_verb_from_method(method: &str) -> &str {
    match method {
        "GET" => "get",
        "POST" => "create",
        "PUT" | "PATCH" => "update",
        "DELETE" => "delete",
        _ => "get",
    }
}

/// Mask sensitive paths in log output
fn mask_log_path(path: &str) -> String {
    if path.contains("/secrets") {
        path.split("/secrets").next().unwrap_or(path).to_string() + "/secrets/***"
    } else {
        path.to_string()
    }
}

/// Normalize Docker image name for comparison
fn normalize_image_for_api(image: &str) -> String {
    let img = image.trim_start_matches("docker.io/library/").trim_start_matches("docker.io/");
    if img.contains(':') { img.to_string() } else { format!("{img}:latest") }
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
        // Allow read-only cross-origin dashboards (e.g. demo.royak.io) to fetch
        // stats. This only exposes GET responses; mutations still require the
        // X-Royak-Token header, which CORS does not bypass.
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

fn route_request(
    method: &str,
    path: &str,
    full_url: &str,
    headers: &HeaderMap,
    body: &[u8],
    world: &Arc<RwLock<DesiredWorld>>,
) -> (u16, String) {
    eprintln!("  [api] {method} {}", mask_log_path(path));

    match (method, path) {
        // ─── Health checks ───
        ("GET", "/healthz") | ("GET", "/readyz") | ("GET", "/livez") => (200, "ok".to_string()),

        // ─── Version ───
        ("GET", "/version") => (200, version_json()),

        // ─── API Discovery ───
        ("GET", "/api") => (200, api_versions()),
        ("GET", "/api/v1") => (200, api_v1_resources()),
        ("GET", "/apis") => (200, api_groups()),
        ("GET", "/apis/apps/v1") => (200, apps_v1_resources()),

        // ─── OpenAPI spec (for kubectl client-side validation) ───
        // v2 is Protobuf-encoded in vanilla K8s; synthesising a valid
        // descriptor from Rust is disproportionate. v3 (JSON) is populated
        // with GVK metadata for the kinds we support — kubectl's strict
        // GVK-path matching still requires full K8s-style operation IDs
        // and schemas that we don't emit, so `kubectl apply` against
        // validation falls back and errors. `kubectl --validate=false` is
        // the standard workaround; get/delete/describe work natively.
        ("GET", "/openapi/v2") => (404, r#"{"status":"Failure","message":"v2 not served; v3 at /openapi/v3","code":404}"#.to_string()),
        ("GET", "/openapi/v3") => (200, openapi_v3_root()),
        ("GET", p) if p.starts_with("/openapi/v3/") => (200, openapi_v3_group(p)),

        // ─── Scale subresource: kubectl scale reads and patches this ───
        ("GET", _) if path.ends_with("/scale") && path.contains("/deployments/") => {
            let name = path.trim_end_matches("/scale").rsplit('/').next().unwrap_or("");
            let (ns, _, _) = parse_resource_path(path.trim_end_matches("/scale"));
            let w = world.read().unwrap();
            match w.deployments.get(name) {
                Some(d) => (200, scale_object(name, ns.unwrap_or("default"), d.replicas)),
                None => (404, not_found_status(path)),
            }
        }
        ("PATCH" | "PUT", _) if path.ends_with("/scale") && path.contains("/deployments/") => {
            let name = path.trim_end_matches("/scale").rsplit('/').next().unwrap_or("").to_string();
            let (ns, _, _) = parse_resource_path(path.trim_end_matches("/scale"));
            let ns = ns.unwrap_or("default").to_string();
            let body_str = String::from_utf8_lossy(body);
            let replicas = serde_json::from_str::<serde_json::Value>(&body_str).ok()
                .or_else(|| serde_yaml::from_str::<serde_json::Value>(&body_str).ok())
                .and_then(|v| v["spec"]["replicas"].as_u64());
            match replicas {
                Some(r) => {
                    let mut w = world.write().unwrap();
                    if let Some(d) = w.deployments.get_mut(&name) {
                        d.replicas = r as u32;
                        // Durability before ack — same contract as resource applies.
                        crate::save_state(crate::state_path(), &w);
                        next_rv();
                        (200, scale_object(&name, &ns, r as u32))
                    } else {
                        (404, not_found_status(path))
                    }
                }
                None => (400, r#"{"kind":"Status","status":"Failure","message":"no spec.replicas in patch","code":400}"#.to_string()),
            }
        }

        // ─── Sandboxed public demo controls (ROYAK_DEMO=1 only) ───
        // Consolidated dashboard read model — lock-free, no world.read(), no
        // docker call. Served from the snapshot published after each reconcile
        // tick, so it never blocks even while the reconcile holds the write lock.
        ("GET", "/demo/state") => {
            let snap = demo_state_snapshot().lock().unwrap().clone();
            (200, (*snap).clone())
        }
        ("GET", "/demo/info") => {
            if !demo_enabled() { (404, not_found_status(path)) }
            else {
                let app = demo_app();
                let w = world.read().unwrap();
                let reps = w.deployments.get(&app).map(|d| d.replicas).unwrap_or(0);
                (200, serde_json::json!({"demo": true, "app": app, "replicas": reps, "min": 1, "max": 5}).to_string())
            }
        }
        ("POST", _) if path == "/demo/scale" => {
            if !demo_enabled() { (404, not_found_status(path)) }
            else if !demo_rate_ok() { (429, r#"{"status":"error","message":"slow down"}"#.to_string()) }
            else {
                let q = full_url.split_once('?').map(|(_, s)| parse_query(Some(s))).unwrap_or_default();
                let n = q.get("n").and_then(|s| s.parse::<u32>().ok()).unwrap_or(1).clamp(1, 5);
                let app = demo_app();
                let mut w = world.write().unwrap();
                if let Some(d) = w.deployments.get_mut(&app) {
                    d.replicas = n;
                    crate::save_state(crate::state_path(), &w);
                    next_rv();
                    (200, serde_json::json!({"status": "ok", "app": app, "replicas": n}).to_string())
                } else {
                    (404, serde_json::json!({"status": "error", "message": format!("demo app '{app}' not found")}).to_string())
                }
            }
        }
        ("POST", _) if path == "/demo/kill" => {
            if !demo_enabled() { (404, not_found_status(path)) }
            else if !demo_rate_ok() { (429, r#"{"status":"error","message":"slow down"}"#.to_string()) }
            else {
                let app = demo_app();
                let prefix = format!("rk-{app}-");
                // Kill exactly one RUNNING pod of the demo app — nothing else.
                let killed = match crate::docker::list_containers(false) {
                    Ok(cs) => cs.into_iter()
                        .find(|c| c.state == "running"
                            && c.names.iter().any(|n| n.trim_start_matches('/').starts_with(&prefix)))
                        .map(|c| {
                            let name = c.names.first().map(|n| n.trim_start_matches('/').to_string()).unwrap_or_default();
                            let _ = crate::docker::remove_container(&c.id, true);
                            name
                        }),
                    Err(_) => None,
                };
                match killed {
                    Some(name) => (200, serde_json::json!({"status": "ok", "killed": name}).to_string()),
                    None => (200, serde_json::json!({"status": "ok", "killed": serde_json::Value::Null, "message": "no running demo pod"}).to_string()),
                }
            }
        }

        // ─── GET resources (list or single) ───
        // Guard: /log, /events and /scale have dedicated arms below/above —
        // without the guard this generic arm shadows them (match order).
        ("GET", _) if (path.starts_with("/api/v1/") || path.starts_with("/apis/apps/v1/"))
            && !path.ends_with("/log") && !path.ends_with("/scale") && !path.contains("/events") => {
            let w = world.read().unwrap();
            match parse_resource_path(path) {
                (ns, "pods", Some(name)) => get_pod(&w, name, ns.unwrap_or("default")),
                (ns, "deployments", Some(name)) => get_deployment(&w, name, ns.unwrap_or("default")),
                (_, "namespaces", Some(name)) => get_namespace(&w, name),
                (ns, "configmaps", Some(name)) => get_configmap(&w, name, ns.unwrap_or("default")),
                (ns, "secrets", Some(name)) => get_secret(&w, name, ns.unwrap_or("default")),
                (_, "nodes", Some(name)) => get_node(&w, name),
                (ns, "pods", None) => (200, list_pods(&w, ns)),
                (_, "namespaces", None) => (200, list_namespaces(&w)),
                (ns, "deployments", None) => (200, list_deployments(&w, ns)),
                (ns, "configmaps", None) => (200, list_configmaps(&w, ns)),
                (ns, "secrets", None) => (200, list_secrets(&w, ns)),
                (_, "services", None) => {
                    let items: Vec<serde_json::Value> = w.services.values().map(|s| serde_json::json!({
                        "apiVersion": "v1", "kind": "Service",
                        "metadata": {"name": s.name, "namespace": s.namespace, "uid": resource_uid("Service", &s.name, &s.namespace)},
                        "spec": {
                            "type": s.service_type,
                            "selector": s.selector,
                            "ports": s.ports.iter().map(|p| serde_json::json!({"port": p.port, "targetPort": p.target_port, "protocol": p.protocol})).collect::<Vec<_>>(),
                        }
                    })).collect();
                    (200, serde_json::json!({"kind": "ServiceList", "apiVersion": "v1", "metadata": {"resourceVersion": current_rv()}, "items": items}).to_string())
                }
                (_, "nodes", None) => (200, list_nodes(&w)),
                _ => (404, serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": format!("resource not found: {path}"), "code": 404}).to_string()),
            }
        }

        // ─── Events ───
        ("GET", _) if path.contains("/events") => {
            let w = world.read().unwrap();
            let items: Vec<serde_json::Value> = w.events.iter().rev().take(50).map(|e| {
                serde_json::json!({
                    "apiVersion": "v1", "kind": "Event",
                    "metadata": {"name": format!("{}.{}", e.object, e.count), "namespace": "default", "uid": resource_uid("Event", &e.object, &e.reason)},
                    "involvedObject": {"kind": e.kind, "name": e.object},
                    "reason": e.reason, "message": e.message,
                    "type": e.event_type, "count": e.count,
                    "firstTimestamp": e.first_seen, "lastTimestamp": e.last_seen
                })
            }).collect();
            (200, serde_json::json!({"kind": "EventList", "apiVersion": "v1", "metadata": {"resourceVersion": current_rv()}, "items": items}).to_string())
        }

        // ─── Pod logs ───
        ("GET", _) if path.contains("/pods/") && path.ends_with("/log") => {
            let parts: Vec<&str> = path.split('/').collect();
            let pod_name = parts.iter().rev().nth(1).unwrap_or(&"");
            let tail = 100u32;
            match docker::list_containers(true) {
                Ok(containers) => {
                    if let Some(c) = containers.iter().find(|c| c.names.iter().any(|n| n.contains(pod_name))) {
                        let short_id = &c.id[..12.min(c.id.len())];
                        match docker::get_logs(short_id, tail) {
                            Ok(logs) => (200, logs),
                            Err(e) => (500, format!("log error: {e}")),
                        }
                    } else {
                        (404, serde_json::json!({"kind":"Status","status":"Failure","message":format!("pod {} not found", pod_name),"code":404}).to_string())
                    }
                }
                Err(e) => (500, format!("docker error: {e}")),
            }
        }

        // ─── helpers for the arms above live at the bottom of the file ───

        // ─── Traffic flows (observability tap) ───
        ("GET", "/royak/v1/flows") => {
            let flows = crate::flows::snapshot(500);
            let totals: Vec<serde_json::Value> = crate::flows::totals().into_iter().take(50)
                .map(|(dest, conns, up, down)| serde_json::json!({
                    "dest": dest, "connections": conns, "bytesUp": up, "bytesDown": down,
                })).collect();
            (200, serde_json::json!({"flows": flows, "topTalkers": totals}).to_string())
        }

        // ─── Pipeline status ───
        ("GET", "/royak/v1/pipelines") => {
            let w = world.read().unwrap();
            (200, list_pipelines(&w))
        }

        // ─── Brain stats (enhanced for dashboard) ───
        ("GET", "/royak/v1/brain") => {
            let w = world.read().unwrap();
            let ca_fp = w.cluster_ca.as_ref().map(|ca| ca.fingerprint.clone()).unwrap_or_default();
            let certs_issued = w.cluster_ca.as_ref().map(|ca| ca.issued_count).unwrap_or(0);
            let networks = w.namespaces.len() + 1; // +1 for global
            (200, serde_json::json!({
                "kind": "Brain", "status": "active",
                "features": ["backprop-training", "anomaly-detection", "load-prediction", "neural-scheduling", "FP-TLS"],
                "cluster": {
                    "nodes": w.nodes.len(), "deployments": w.deployments.len(),
                    "events": w.events.len(), "pods": w.deployments.values().map(|d| d.replicas).sum::<u32>(),
                    "services": w.services.len(), "namespaces": w.namespaces.len(),
                    "quotas": w.resource_quotas.len(), "policies": w.network_policies.len(),
                },
                "training": {
                    "steps": 0, // filled by watch loop brain stats
                    "loss": 0.0,
                    "status": "learning",
                },
                "security": {
                    "ca_fingerprint": ca_fp,
                    "certs_issued": certs_issued,
                    "networks": networks,
                    "audit_events": w.network_audit.len(),
                    "pod_certs": w.pod_certs.len(),
                }
            }).to_string())
        }

        // ─── State sync GET ───
        ("GET", "/royak/v1/state") => {
            if !check_node_auth(headers) {
                eprintln!("  ⚠ [auth] /royak/v1/state: missing or invalid token");
                return (403, serde_json::json!({"status": "error", "message": "X-Royak-Token required for state sync"}).to_string());
            }
            let w = world.read().unwrap();
            (200, reconcile::export_state(&w).to_string())
        }

        // ─── State sync POST ───
        ("POST", "/royak/v1/state") => {
            if !check_node_auth(headers) {
                return (403, serde_json::json!({"status": "error", "message": "X-Royak-Token required"}).to_string());
            }
            match serde_json::from_slice::<serde_json::Value>(body) {
                Ok(remote) => {
                    let mut w = world.write().unwrap();
                    let log = reconcile::merge_state(&mut w, &remote);
                    next_rv();
                    (200, serde_json::json!({"status": "ok", "merged": log}).to_string())
                }
                Err(e) => (400, serde_json::json!({"status": "error", "message": e.to_string()}).to_string()),
            }
        }

        // ─── Heartbeat ───
        ("POST", "/royak/v1/heartbeat") => {
            if !check_node_auth(headers) {
                return (403, r#"{"status":"error","message":"auth required"}"#.to_string());
            }
            if let Ok(hb) = serde_json::from_slice::<serde_json::Value>(body) {
                if let Some(node_name) = hb["node"].as_str() {
                    let mut w = world.write().unwrap();
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                    if let Some(node) = w.nodes.get_mut(node_name) {
                        node.last_heartbeat = now;
                        node.cpu_used = hb["cpu_used"].as_f64().unwrap_or(node.cpu_used as f64) as f32;
                        node.mem_used = hb["mem_used"].as_f64().unwrap_or(node.mem_used as f64) as f32;
                        node.pod_count = hb["pod_count"].as_u64().unwrap_or(node.pod_count as u64) as u32;
                        if node.status == reconcile::NodeStatus::NotReady {
                            node.status = reconcile::NodeStatus::Ready;
                            eprintln!("  ✓ [heartbeat] {node_name}: back to Ready");
                        }
                    }
                }
            }
            (200, serde_json::json!({"status": "ok"}).to_string())
        }

        // ─── Multi-node: run a pod on THIS node (receiver of scheduling) ───
        // Another node's reconcile picked us and POSTs the pod here; we create it
        // on our local Docker. The sender is fire-and-forget over the private
        // subnet. Custom images built on another node must be pre-distributed —
        // we pull public images, and fail loudly for local-only ones.
        ("POST", "/royak/v1/create-pod") => {
            let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
            let pod = v["pod"].as_str().unwrap_or("").to_string();
            let deployment = v["deployment"].as_str().unwrap_or("").to_string();
            let image = v["image"].as_str().unwrap_or("").to_string();
            if pod.is_empty() || image.is_empty() {
                return (400, r#"{"kind":"Status","status":"Failure","message":"pod and image required","code":400}"#.to_string());
            }
            if !docker::image_exists_locally(&image) {
                if let Err(e) = docker::pull_image(&image) {
                    eprintln!("  ⚠ [multi-node] {pod}: image {image} not local + pull failed: {e}");
                    return (503, serde_json::json!({"status":"error","pod":pod,"message":format!("image '{image}' unavailable on this node (needs distribution): {e}")}).to_string());
                }
            }
            let labels = [("royak.managed", "true"), ("royak.deployment", deployment.as_str()), ("app", deployment.as_str())];
            match docker::create_container(&pod, &image, None, &[], &labels) {
                Ok(id) => {
                    // create ≠ start — must start it or it sits in "Created".
                    if let Err(e) = docker::start_container(&id) {
                        return (500, serde_json::json!({"status":"error","pod":pod,"message":format!("created but start failed: {e}")}).to_string());
                    }
                    eprintln!("  ✓ [multi-node] created + started {pod} here ({})", &id[..12.min(id.len())]);
                    (200, serde_json::json!({"status":"ok","pod":pod,"id":id}).to_string())
                }
                Err(e) => (500, serde_json::json!({"status":"error","pod":pod,"message":e}).to_string()),
            }
        }

        // ─── Multi-node: this node's running managed pods ───
        // Peers query this to count a deployment's replicas across the whole
        // cluster (so we don't over-provision or collide on pod names).
        ("GET", "/royak/v1/pods") => {
            let names: Vec<String> = docker::list_containers(false).unwrap_or_default()
                .into_iter()
                .filter(|c| c.state == "running"
                    && c.names.iter().any(|n| n.trim_start_matches('/').starts_with("rk-")))
                .filter_map(|c| c.names.first().map(|n| n.trim_start_matches('/').to_string()))
                .collect();
            (200, serde_json::json!({"pods": names}).to_string())
        }

        // ─── PATCH with a partial body (no "kind"): strategic merge ───
        // kubectl's client-side apply and `kubectl patch` send partial
        // patches. We merge them into the stored manifest and re-apply.
        ("PATCH", _) if path.contains("/deployments/") && !path.ends_with("/scale") && {
            let s = String::from_utf8_lossy(body);
            serde_json::from_str::<serde_json::Value>(&s)
                .map(|v| v.get("kind").is_none())
                .unwrap_or(false)
        } => {
            let name = path.rsplit('/').next().unwrap_or("").to_string();
            let (ns, _, _) = parse_resource_path(path);
            let ns = ns.unwrap_or("default").to_string();
            let key = format!("Deployment/{ns}/{name}");
            let patch: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(body)).unwrap_or(serde_json::Value::Null);
            let mut w = world.write().unwrap();
            let Some(mut manifest) = w.manifests.get(&key).cloned() else {
                return (404, not_found_status(path));
            };
            strategic_merge(&mut manifest, &patch);
            let yaml = serde_yaml::to_string(&manifest).unwrap_or_default();
            match spec::parse_yaml(&yaml) {
                Ok(resources) => {
                    for r in &resources {
                        if let Err(e) = w.apply(r) {
                            return (400, serde_json::json!({"kind": "Status", "status": "Failure", "message": e, "code": 400}).to_string());
                        }
                    }
                }
                Err(e) => {
                    return (400, serde_json::json!({"kind": "Status", "status": "Failure", "message": format!("merged manifest invalid: {e}"), "code": 400}).to_string());
                }
            }
            w.manifests.insert(key, manifest.clone());
            crate::save_state(crate::state_path(), &w);
            next_rv();
            let mut out = manifest;
            out["metadata"]["resourceVersion"] = serde_json::json!(current_rv().to_string());
            out["metadata"]["uid"] = serde_json::json!(resource_uid("Deployment", &name, &ns));
            (200, out.to_string())
        }

        // ─── POST/PUT/PATCH: Apply resources ───
        ("POST" | "PUT" | "PATCH", _) if path.contains("/namespaces/") || path.ends_with("/pods") || path.ends_with("/deployments") || path.ends_with("/configmaps") || path.ends_with("/secrets") => {
            // RBAC check
            let role = get_rbac_role(headers);
            let resource = rbac_resource_from_path(path);
            let verb = rbac_verb_from_method(method);
            let (ns, _, _) = parse_resource_path(path);
            let namespace = ns.unwrap_or("default");
            {
                let w = world.read().unwrap();
                if !w.check_rbac(&role, resource, verb, namespace) {
                    eprintln!("  ⚠ [rbac] {role} denied: {verb} {resource} in {namespace}");
                    return (403, serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Failure",
                        "message": format!("RBAC: role '{}' cannot {} {} in namespace '{}'", role, verb, resource, namespace),
                        "code": 403}).to_string());
                }
            }

            // Body size check
            if body.len() > MAX_BODY_SIZE {
                return (413, r#"{"kind":"Status","status":"Failure","message":"body too large","code":413}"#.to_string());
            }

            let body_str = String::from_utf8_lossy(body);

            // Try to parse as YAML or JSON
            let result = if body_str.trim_start().starts_with('{') {
                serde_json::from_str::<serde_json::Value>(&body_str)
                    .map_err(|e| format!("JSON parse: {e}"))
                    .and_then(|v| serde_yaml::to_string(&v).map_err(|e| format!("YAML convert: {e}")))
                    .and_then(|yaml| spec::parse_yaml(&yaml).map_err(|e| e.to_string()))
            } else {
                spec::parse_yaml(&body_str)
            };

            match result {
                Ok(resources) => {
                    let mut w = world.write().unwrap();
                    let mut applied_ok = true;
                    let mut err_msg = String::new();
                    for r in &resources {
                        if let Err(e) = w.apply(r) {
                            applied_ok = false;
                            err_msg = e;
                            break;
                        }
                    }
                    next_rv();
                    if !applied_ok {
                        return (400, serde_json::json!({
                            "kind": "Status", "apiVersion": "v1",
                            "status": "Failure", "message": err_msg, "code": 400
                        }).to_string());
                    }
                    // Remember full Deployment manifests — the base that
                    // partial PATCHes (client-side apply) merge into.
                    for doc in body_docs_as_json(&body_str) {
                        if doc.get("kind").and_then(|k| k.as_str()) == Some("Deployment") {
                            if let Some(n) = doc["metadata"]["name"].as_str() {
                                let dns = doc["metadata"]["namespace"].as_str().unwrap_or("default");
                                w.manifests.insert(format!("Deployment/{dns}/{n}"), doc.clone());
                            }
                        }
                    }
                    // Durability before ack: persist the mutation before the 201
                    // leaves the building. Without this, a hard kill between the
                    // ack and the reconcile loop's periodic save silently drops
                    // accepted API writes.
                    crate::save_state(crate::state_path(), &w);
                    // kubectl expects the server to echo back the created/applied
                    // object, not a Status wrapper. Reflect the first resource in
                    // the body with minimal metadata so client-side
                    // "object does not implement the Object interfaces" doesn't fire.
                    let first = resources.first();
                    let (api_version, kind, name, namespace) = match first {
                        Some(r) => (
                            r.api_version.clone().unwrap_or_else(|| "v1".to_string()),
                            r.kind.clone(),
                            r.metadata.name.clone(),
                            r.metadata.namespace.clone().unwrap_or_else(|| "default".to_string()),
                        ),
                        None => ("v1".to_string(), "Status".to_string(), String::new(), "default".to_string()),
                    };
                    (201, serde_json::json!({
                        "apiVersion": api_version,
                        "kind": kind,
                        "metadata": {
                            "name": name,
                            "namespace": namespace,
                            "resourceVersion": current_rv().to_string(),
                            "uid": resource_uid(&kind, &name, &namespace),
                            "creationTimestamp": "1970-01-01T00:00:00Z",
                        },
                        "spec": first.and_then(|r| r.spec.as_ref())
                            .and_then(|v| serde_json::to_value(v).ok())
                            .unwrap_or(serde_json::Value::Null),
                    }).to_string())
                }
                Err(e) => (400, serde_json::json!({
                    "kind": "Status", "apiVersion": "v1",
                    "status": "Failure", "message": e, "code": 400
                }).to_string()),
            }
        }

        // ─── DELETE ───
        ("DELETE", _) if path.starts_with("/api/v1/") || path.starts_with("/apis/apps/v1/") => {
            let role = get_rbac_role(headers);
            let (ns_del, resource, name) = parse_resource_path(path);
            let namespace = ns_del.unwrap_or("default");
            {
                let w = world.read().unwrap();
                if !w.check_rbac(&role, resource, "delete", namespace) {
                    eprintln!("  ⚠ [rbac] {role} denied: delete {resource} in {namespace}");
                    return (403, serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Failure",
                        "message": format!("RBAC: role '{}' cannot delete {} in namespace '{}'", role, resource, namespace),
                        "code": 403}).to_string());
                }
            }
            let name = match name {
                Some(n) => n.to_string(),
                None => return (400, serde_json::json!({"kind": "Status", "status": "Failure", "message": "resource name required", "code": 400}).to_string()),
            };
            let mut w = world.write().unwrap();
            let ok = match resource {
                "pods" => {
                    match docker::list_containers(true) {
                        Ok(containers) => {
                            if let Some(c) = containers.iter().find(|c| c.names.iter().any(|n| n.contains(&name))) {
                                docker::stop_container(&c.id).ok();
                                docker::remove_container(&c.id, true).ok();
                                true
                            } else { false }
                        }
                        Err(_) => false,
                    }
                }
                "deployments" => {
                    let prefix = format!("rk-{name}-");
                    if let Ok(containers) = docker::list_containers(true) {
                        for c in containers.iter().filter(|c| c.names.iter().any(|n| n.contains(&prefix))) {
                            docker::stop_container(&c.id).ok();
                            docker::remove_container(&c.id, true).ok();
                        }
                    }
                    w.delete_resource("deployments", &name)
                }
                "configmaps" => w.configmaps.remove(&name).is_some(),
                "secrets" => w.secrets.remove(&name).is_some(),
                "namespaces" => { w.namespaces.retain(|n| n != &name); true },
                _ => w.delete_resource(resource, &name),
            };
            if ok {
                next_rv();
                (200, serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Success", "message": format!("{resource}/{name} deleted")}).to_string())
            } else {
                (404, serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": format!("{resource}/{name} not found"), "code": 404}).to_string())
            }
        }

        // ─── Function invoke via HTTP trigger ───
        ("GET" | "POST", _) if {
            let w = world.read().unwrap();
            w.functions.values().any(|f| f.http_triggers.iter().any(|t| t == path))
        } => {
            let func_name = {
                let w = world.read().unwrap();
                w.functions.values()
                    .find(|f| f.http_triggers.iter().any(|t| t == path))
                    .map(|f| f.name.clone())
            };
            if let Some(name) = func_name {
                let mut w = world.write().unwrap();
                match reconcile::invoke_function(&mut w, &name) {
                    Ok(result) => (200, serde_json::json!({"status": "ok", "function": name, "result": result}).to_string()),
                    Err(e) => (500, serde_json::json!({"status": "error", "function": name, "error": e}).to_string()),
                }
            } else {
                (404, serde_json::json!({"error": "function not found"}).to_string())
            }
        }

        // ─── Webhook: git repo trigger ───
        ("POST", _) if path.starts_with("/hooks/repo/") => {
            let repo_name = path.strip_prefix("/hooks/repo/").unwrap_or("").to_string();
            let mut w = world.write().unwrap();
            if let Some(repo) = w.repositories.get(&repo_name) {
                if let Some(pipeline_name) = repo.pipeline.clone() {
                    if w.pipelines.contains_key(pipeline_name.as_str()) {
                        match reconcile::start_pipeline(&mut w, &pipeline_name) {
                            Ok(run_id) => {
                                next_rv();
                                eprintln!("  [webhook] repo/{repo_name} → pipeline/{pipeline_name} (run #{run_id})");
                                (200, serde_json::json!({"status": "ok", "pipeline": pipeline_name, "run_id": run_id}).to_string())
                            }
                            Err(e) => (500, serde_json::json!({"status": "error", "message": e}).to_string()),
                        }
                    } else {
                        (404, serde_json::json!({"status": "error", "message": format!("pipeline '{}' not found", pipeline_name)}).to_string())
                    }
                } else {
                    (400, serde_json::json!({"status": "error", "message": "repo has no pipeline configured"}).to_string())
                }
            } else {
                (404, serde_json::json!({"status": "error", "message": format!("repo '{}' not found", repo_name)}).to_string())
            }
        }

        // ─── Webhook: function trigger ───
        (_, _) if path.starts_with("/hooks/") => {
            let hook_path = path.to_string();
            let func_name = {
                let w = world.read().unwrap();
                w.functions.values()
                    .find(|f| f.webhook_triggers.iter().any(|t| t == &hook_path))
                    .map(|f| f.name.clone())
            };
            if let Some(name) = func_name {
                let mut w = world.write().unwrap();
                match reconcile::invoke_function(&mut w, &name) {
                    Ok(result) => (200, serde_json::json!({"status": "ok", "webhook": hook_path, "function": name, "result": result}).to_string()),
                    Err(e) => (500, serde_json::json!({"status": "error", "function": name, "error": e}).to_string()),
                }
            } else {
                (404, serde_json::json!({"error": format!("no function registered for webhook {hook_path}")}).to_string())
            }
        }

        // ─── kubectl exec ───
        ("POST", _) if path.contains("/pods/") && path.contains("/exec") => {
            let parts: Vec<&str> = path.split('/').collect();
            let pod_name = parts.iter().rev().nth(1).unwrap_or(&"");
            let cmd_str = full_url.split("command=").nth(1).unwrap_or("sh");
            let cmd_parts: Vec<&str> = cmd_str.split('&').next().unwrap_or(cmd_str)
                .split('+').collect();
            match docker::list_containers(true) {
                Ok(containers) => {
                    if let Some(c) = containers.iter().find(|c| c.names.iter().any(|n| n.contains(pod_name))) {
                        let short_id = &c.id[..12.min(c.id.len())];
                        match docker::exec_in_container(short_id, &cmd_parts) {
                            Ok((code, output)) => (200, serde_json::json!({
                                "kind": "ExecResult", "pod": pod_name,
                                "exitCode": code, "output": output
                            }).to_string()),
                            Err(e) => (500, serde_json::json!({"kind": "Status", "status": "Failure", "message": format!("exec error: {e}"), "code": 500}).to_string()),
                        }
                    } else {
                        (404, serde_json::json!({"kind": "Status", "status": "Failure", "message": format!("pod {} not found", pod_name), "code": 404}).to_string())
                    }
                }
                Err(e) => (500, serde_json::json!({"kind": "Status", "status": "Failure", "message": format!("docker: {e}"), "code": 500}).to_string()),
            }
        }

        // ─── kubectl describe ───
        ("GET", _) if path.contains("/describe/") => {
            let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            let (resource, res_name) = match parts.as_slice() {
                [.., "describe", r, n] => (*r, *n),
                _ => ("", ""),
            };
            let w = world.read().unwrap();
            match resource {
                "deployment" | "deployments" => {
                    match w.deployments.get(res_name) {
                        Some(dep) => {
                            let containers_desc: Vec<String> = dep.containers.iter().map(|c| {
                                format!("  - {}: {} (env: {})", c.name, c.image, c.env.len())
                            }).collect();
                            let events: Vec<String> = w.events.iter()
                                .filter(|e| e.object == res_name)
                                .map(|e| format!("  {} {} — {} (×{})", e.event_type, e.reason, e.message, e.count))
                                .collect();
                            let limits_desc = dep.resource_limits.as_ref().map(|r| {
                                format!("CPU: {:.1}-{:.1} cores, Mem: {}-{} MB",
                                    r.cpu_request.unwrap_or(0.0), r.cpu_limit.unwrap_or(0.0),
                                    r.mem_request.unwrap_or(0), r.mem_limit.unwrap_or(0))
                            }).unwrap_or_else(|| "none".to_string());
                            let strategy_desc = dep.strategy.as_ref().map(|s| match s {
                                reconcile::DeployStrategy::RollingUpdate { max_surge, max_unavailable } =>
                                    format!("RollingUpdate (maxSurge={max_surge}, maxUnavailable={max_unavailable})"),
                                reconcile::DeployStrategy::Canary { weight, .. } =>
                                    format!("Canary (weight={weight}%)"),
                                reconcile::DeployStrategy::BlueGreen { active } =>
                                    format!("BlueGreen (active={active})"),
                            }).unwrap_or_else(|| "RollingUpdate (default)".to_string());
                            (200, serde_json::json!({
                                "kind": "Describe", "resource": "Deployment",
                                "metadata": {"name": dep.name, "namespace": dep.namespace},
                                "spec": {
                                    "replicas": dep.replicas,
                                    "strategy": strategy_desc,
                                    "resourceLimits": limits_desc,
                                    "containers": containers_desc,
                                    "paused": dep.paused,
                                },
                                "events": events,
                            }).to_string())
                        }
                        None => (404, serde_json::json!({"kind": "Status", "status": "Failure", "message": format!("deployment {} not found", res_name), "code": 404}).to_string()),
                    }
                }
                "pod" | "pods" => {
                    match docker::list_containers(true) {
                        Ok(containers) => {
                            if let Some(c) = containers.iter().find(|c| c.names.iter().any(|n| n.contains(res_name))) {
                                let events: Vec<String> = w.events.iter()
                                    .filter(|e| e.object.contains(res_name))
                                    .map(|e| format!("  {} {} — {} (×{})", e.event_type, e.reason, e.message, e.count))
                                    .collect();
                                (200, serde_json::json!({
                                    "kind": "Describe", "resource": "Pod",
                                    "metadata": {"name": c.names.first().unwrap_or(&"?".to_string()), "namespace": "default"},
                                    "spec": {"image": c.image, "state": c.state, "id": &c.id[..12.min(c.id.len())]},
                                    "events": events,
                                }).to_string())
                            } else {
                                (404, serde_json::json!({"kind": "Status", "status": "Failure", "message": format!("pod {} not found", res_name), "code": 404}).to_string())
                            }
                        }
                        Err(e) => (500, serde_json::json!({"kind": "Status", "status": "Failure", "message": e, "code": 500}).to_string()),
                    }
                }
                "node" | "nodes" => {
                    match w.nodes.get(res_name) {
                        Some(n) => {
                            let status = match n.status { reconcile::NodeStatus::Ready => "Ready", reconcile::NodeStatus::NotReady => "NotReady", reconcile::NodeStatus::Draining => "Draining" };
                            (200, serde_json::json!({
                                "kind": "Describe", "resource": "Node",
                                "metadata": {"name": n.name},
                                "status": status,
                                "capacity": {"cpu": n.cpu_capacity, "memory": n.mem_capacity},
                                "usage": {"cpu": n.cpu_used, "memory": n.mem_used, "pods": n.pod_count},
                                "joinedAt": n.joined_at,
                            }).to_string())
                        }
                        None => (404, serde_json::json!({"kind": "Status", "status": "Failure", "message": format!("node {} not found", res_name), "code": 404}).to_string()),
                    }
                }
                _ => (400, serde_json::json!({"kind": "Status", "status": "Failure", "message": format!("describe not supported for: {resource}"), "code": 400}).to_string()),
            }
        }

        // ─── Rollout status ───
        ("GET", _) if path.starts_with("/royak/v1/rollout/") => {
            let dep_name = path.strip_prefix("/royak/v1/rollout/").unwrap_or("");
            let w = world.read().unwrap();
            if let Some(rollout) = w.pending_rollouts.get(dep_name) {
                let prefix = format!("rk-{dep_name}-");
                let new_norm = normalize_image_for_api(&rollout.new_image);
                let new_running = match docker::list_containers(true) {
                    Ok(containers) => containers.iter()
                        .filter(|c| c.names.iter().any(|n| n.contains(&prefix))
                            && c.state == "running"
                            && normalize_image_for_api(&c.image) == new_norm)
                        .count() as u32,
                    Err(_) => 0,
                };
                let progress = if rollout.total_replicas > 0 {
                    (new_running * 100) / rollout.total_replicas
                } else { 0 };
                (200, serde_json::json!({
                    "kind": "RolloutStatus", "deployment": dep_name,
                    "status": if new_running >= rollout.total_replicas { "complete" } else { "in-progress" },
                    "oldImage": rollout.old_image,
                    "newImage": rollout.new_image,
                    "progress": format!("{new_running}/{} ({progress}%)", rollout.total_replicas),
                    "ready": new_running,
                    "desired": rollout.total_replicas,
                }).to_string())
            } else if w.deployments.contains_key(dep_name) {
                (200, serde_json::json!({
                    "kind": "RolloutStatus", "deployment": dep_name,
                    "status": "complete", "message": "no rollout in progress"
                }).to_string())
            } else {
                (404, serde_json::json!({"kind": "Status", "status": "Failure", "message": format!("deployment {} not found", dep_name), "code": 404}).to_string())
            }
        }

        // ─── kubectl top pods ───
        ("GET", "/royak/v1/top/pods") => {
            match docker::list_containers(true) {
                Ok(containers) => {
                    let managed: Vec<&docker::DockerContainer> = containers.iter()
                        .filter(|c| c.names.iter().any(|n| n.contains("rk-")) && c.state == "running")
                        .collect();
                    let mut items: Vec<serde_json::Value> = Vec::new();
                    for c in &managed {
                        let short_id = &c.id[..12.min(c.id.len())];
                        let name = c.names.first().map(|s| s.trim_start_matches('/')).unwrap_or("?");
                        let (cpu_pct, mem_mb) = docker::container_stats(short_id).unwrap_or((0.0, 0.0));
                        items.push(serde_json::json!({
                            "name": name, "namespace": "default",
                            "cpu": format!("{:.1}%", cpu_pct),
                            "memory": format!("{:.0}Mi", mem_mb),
                            "cpu_raw": cpu_pct, "memory_raw_mb": mem_mb,
                        }));
                    }
                    (200, serde_json::json!({"kind": "TopPods", "items": items}).to_string())
                }
                Err(e) => (500, serde_json::json!({"kind": "Status", "status": "Failure", "message": e, "code": 500}).to_string()),
            }
        }

        // ─── Prometheus metrics ───
        ("GET", "/metrics") => {
            let w = world.read().unwrap();
            let pod_count: u32 = w.deployments.values().map(|d| d.replicas).sum();
            let mut lines = Vec::new();
            lines.push("# HELP royak_pods_total Total desired pod count".to_string());
            lines.push("# TYPE royak_pods_total gauge".to_string());
            lines.push(format!("royak_pods_total {pod_count}"));
            lines.push("# HELP royak_deployments_total Total deployments".to_string());
            lines.push("# TYPE royak_deployments_total gauge".to_string());
            lines.push(format!("royak_deployments_total {}", w.deployments.len()));
            lines.push("# HELP royak_services_total Total services".to_string());
            lines.push("# TYPE royak_services_total gauge".to_string());
            lines.push(format!("royak_services_total {}", w.services.len()));
            lines.push("# HELP royak_namespaces_total Total namespaces".to_string());
            lines.push("# TYPE royak_namespaces_total gauge".to_string());
            lines.push(format!("royak_namespaces_total {}", w.namespaces.len()));
            lines.push("# HELP royak_events_total Total cluster events".to_string());
            lines.push("# TYPE royak_events_total counter".to_string());
            lines.push(format!("royak_events_total {}", w.events.len()));
            lines.push("# HELP royak_network_audit_total Network audit events".to_string());
            lines.push("# TYPE royak_network_audit_total counter".to_string());
            lines.push(format!("royak_network_audit_total {}", w.network_audit.len()));
            lines.push("# HELP royak_certs_issued_total Certificates issued by CA".to_string());
            lines.push("# TYPE royak_certs_issued_total counter".to_string());
            lines.push(format!("royak_certs_issued_total {}", w.cluster_ca.as_ref().map(|ca| ca.issued_count).unwrap_or(0)));

            // Per-deployment metrics
            for dep in w.deployments.values() {
                let prefix = format!("rk-{}-", dep.name);
                let running = docker::list_containers(false).ok()
                    .map(|cs| cs.iter().filter(|c| c.names.iter().any(|n| n.contains(&prefix))).count())
                    .unwrap_or(0);
                lines.push(format!("royak_deployment_replicas_desired{{deployment=\"{}\"}} {}", dep.name, dep.replicas));
                lines.push(format!("royak_deployment_replicas_ready{{deployment=\"{}\"}} {running}", dep.name));
            }

            // Per-pod CPU/memory (from Docker stats)
            if let Ok(containers) = docker::list_containers(false) {
                for c in containers.iter().filter(|c| c.names.iter().any(|n| n.contains("rk-"))) {
                    let name = c.names.first().map(|s| s.trim_start_matches('/')).unwrap_or("?");
                    let short_id = &c.id[..12.min(c.id.len())];
                    if let Ok((cpu, mem)) = docker::container_stats(short_id) {
                        lines.push(format!("royak_pod_cpu_percent{{pod=\"{name}\"}} {cpu:.2}"));
                        lines.push(format!("royak_pod_memory_mb{{pod=\"{name}\"}} {mem:.1}"));
                    }
                }
            }

            return (200, lines.join("\n") + "\n");
        }

        // ─── Log aggregation: search across all pods ───
        ("GET", "/royak/v1/logs") => {
            let search = full_url.split("search=").nth(1)
                .and_then(|s| s.split('&').next())
                .unwrap_or("");
            let tail: u32 = full_url.split("tail=").nth(1)
                .and_then(|s| s.split('&').next())
                .and_then(|s| s.parse().ok())
                .unwrap_or(50);

            let mut all_logs = Vec::new();
            if let Ok(containers) = docker::list_containers(false) {
                for c in containers.iter().filter(|c| c.names.iter().any(|n| n.contains("rk-"))) {
                    let name = c.names.first().map(|s| s.trim_start_matches('/')).unwrap_or("?");
                    let short_id = &c.id[..12.min(c.id.len())];
                    if let Ok(logs) = docker::get_logs(short_id, tail) {
                        for line in logs.lines() {
                            if search.is_empty() || line.to_lowercase().contains(&search.to_lowercase()) {
                                all_logs.push(serde_json::json!({
                                    "pod": name, "line": line
                                }));
                            }
                        }
                    }
                }
            }
            (200, serde_json::json!({
                "kind": "AggregatedLogs",
                "search": search,
                "count": all_logs.len(),
                "logs": all_logs
            }).to_string())
        }

        // ─── kubectl top nodes ───
        ("GET", "/royak/v1/top/nodes") => {
            let w = world.read().unwrap();
            let items: Vec<serde_json::Value> = if w.nodes.is_empty() {
                let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "royak-node".to_string());
                let pods = match docker::list_containers(true) {
                    Ok(c) => c.iter().filter(|c| c.names.iter().any(|n| n.contains("rk-")) && c.state == "running").count(),
                    Err(_) => 0,
                };
                vec![serde_json::json!({"name": hostname, "cpu": "n/a", "memory": "n/a", "pods": pods})]
            } else {
                w.nodes.values().map(|n| {
                    let cpu_pct = if n.cpu_capacity > 0.0 { (n.cpu_used / n.cpu_capacity) * 100.0 } else { 0.0 };
                    let mem_pct = if n.mem_capacity > 0.0 { (n.mem_used / n.mem_capacity) * 100.0 } else { 0.0 };
                    serde_json::json!({
                        "name": n.name,
                        "cpu": format!("{:.0}/{:.0} ({:.0}%)", n.cpu_used, n.cpu_capacity, cpu_pct),
                        "memory": format!("{:.0}/{:.0}Mi ({:.0}%)", n.mem_used, n.mem_capacity, mem_pct),
                        "pods": n.pod_count,
                    })
                }).collect()
            };
            (200, serde_json::json!({"kind": "TopNodes", "items": items}).to_string())
        }

        // ─── PATCH resources ───
        ("PATCH", _) if path.starts_with("/api/v1/") || path.starts_with("/apis/apps/v1/") => {
            let (ns, resource, name) = parse_resource_path(path);
            let name = match name {
                Some(n) => n.to_string(),
                None => return (400, r#"{"kind":"Status","status":"Failure","message":"resource name required for PATCH","code":400}"#.to_string()),
            };
            let _ns = ns.unwrap_or("default");

            let patch: serde_json::Value = match serde_json::from_slice(body) {
                Ok(v) => v,
                Err(e) => return (400, serde_json::json!({"kind": "Status", "status": "Failure", "message": format!("JSON parse: {e}"), "code": 400}).to_string()),
            };

            let mut w = world.write().unwrap();
            match resource {
                "deployments" => {
                    if let Some(dep) = w.deployments.get_mut(&name) {
                        if let Some(r) = patch.pointer("/spec/replicas").and_then(|v| v.as_u64()) {
                            dep.replicas = r as u32;
                        }
                        let mut rollout_needed: Option<(String, String, u32)> = None;
                        if let Some(img) = patch.pointer("/spec/template/spec/containers/0/image").and_then(|v| v.as_str()) {
                            let old_image = dep.image.clone();
                            let replicas = dep.replicas;
                            dep.image = img.to_string();
                            if let Some(c) = dep.containers.first_mut() {
                                c.image = img.to_string();
                            }
                            if old_image != img {
                                rollout_needed = Some((old_image, img.to_string(), replicas));
                            }
                        }
                        if let Some((old_img, new_img, replicas)) = rollout_needed {
                            w.pending_rollouts.insert(name.clone(), reconcile::RolloutState {
                                old_image: old_img,
                                new_image: new_img,
                                total_replicas: replicas,
                                old_pods: std::collections::VecDeque::new(),
                                new_pods_created: 0,
                            });
                        }
                        next_rv();
                        (200, serde_json::json!({"kind": "Status", "status": "Success", "message": format!("deployment/{name} patched")}).to_string())
                    } else {
                        (404, serde_json::json!({"kind": "Status", "status": "Failure", "message": format!("deployment {} not found", name), "code": 404}).to_string())
                    }
                }
                "configmaps" => {
                    if let Some(cm) = w.configmaps.get_mut(&name) {
                        if let Some(data) = patch.get("data").and_then(|d| d.as_object()) {
                            for (k, v) in data {
                                if let Some(val) = v.as_str() {
                                    cm.data.insert(k.clone(), val.to_string());
                                }
                            }
                        }
                        next_rv();
                        (200, serde_json::json!({"kind": "Status", "status": "Success", "message": format!("configmap/{name} patched")}).to_string())
                    } else {
                        (404, serde_json::json!({"kind": "Status", "status": "Failure", "message": format!("configmap {} not found", name), "code": 404}).to_string())
                    }
                }
                _ => (400, serde_json::json!({"kind": "Status", "status": "Failure", "message": format!("PATCH not supported for {resource}"), "code": 400}).to_string()),
            }
        }

        // ─── 404 ───
        _ => (404, serde_json::json!({
            "kind": "Status", "apiVersion": "v1", "status": "Failure",
            "message": format!("the server could not find the requested resource: {path}"),
            "code": 404
        }).to_string()),
    }
}

// ─── Async request handler ───

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

    // Bearer token auth
    if let Ok(expected_token) = std::env::var("ROYAK_TOKEN") {
        if !expected_token.is_empty() {
            let auth = headers.get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            let expected = format!("Bearer {expected_token}");
            if auth != expected && !path.starts_with("/healthz") && !path.starts_with("/readyz") {
                return Ok(json_response(401,
                    r#"{"kind":"Status","status":"Failure","message":"Unauthorized: set Authorization: Bearer <token>","code":401}"#));
            }
        }
    }

    // ─── Dashboard: built-in web UI ───
    if (path == "/" || path == "/dashboard") && method == hyper::Method::GET {
        const DASHBOARD_HTML: &str = include_str!("dashboard.html");
        return Ok(hyper::Response::builder()
            .status(200)
            .header("Content-Type", "text/html; charset=utf-8")
            .body(Full::new(Bytes::from(DASHBOARD_HTML)).boxed())
            .unwrap());
    }

    // kubectl exec over WebSocket (channel protocol)
    if path.contains("/pods/") && path.ends_with("/exec")
        && headers.get("upgrade").and_then(|v| v.to_str().ok())
            .map(|s| s.eq_ignore_ascii_case("websocket")).unwrap_or(false)
    {
        return Ok(handle_exec_ws(req, &path, &full_url, &headers).await);
    }

    // kubectl port-forward: clean v4.channel.k8s.io websocket path (some
    // clients / KUBECTL_PORT_FORWARD_WEBSOCKETS). kubectl 1.36 defaults to
    // SPDY-tunneled-over-websocket which we do not decode — use
    // `royak port-forward` for a guaranteed local→pod tunnel.
    if path.contains("/pods/") && path.ends_with("/portforward")
        && headers.get("sec-websocket-protocol").and_then(|v| v.to_str().ok())
            .map(|s| s.contains("channel.k8s.io")).unwrap_or(false)
        && headers.get("upgrade").and_then(|v| v.to_str().ok())
            .map(|s| s.eq_ignore_ascii_case("websocket")).unwrap_or(false)
    {
        return Ok(handle_portforward_ws(req, &path, &full_url, &headers).await);
    }

    // ─── Streaming: kubectl logs -f ───
    if path.contains("/pods/") && path.ends_with("/log")
        && (query.get("follow").map(|v| v.as_str()) == Some("true")
            || query.get("follow").map(|v| v.as_str()) == Some("1"))
    {
        return Ok(handle_log_stream(&path, &query).await);
    }

    // ─── Streaming: kubectl get pods -w (watch) ───
    if query.get("watch").map(|v| v.as_str()) == Some("true")
        || query.get("watch").map(|v| v.as_str()) == Some("1")
    {
        return Ok(handle_watch(&path, &query, world).await);
    }

    // ─── Normal buffered request ───
    // Read body for write methods
    let body_bytes = if method == hyper::Method::POST || method == hyper::Method::PUT || method == hyper::Method::PATCH {
        req.collect().await.map(|c| c.to_bytes()).unwrap_or_default()
    } else {
        Bytes::new()
    };

    // ─── Raft status (leader id + this node) for tests/ops ───
    if path == "/royak/v1/raft/status" && method == hyper::Method::GET {
        let (leader, me) = crate::raft_node::raft_status().await;
        return Ok(json_response(200, &serde_json::json!({
            "enabled": me.is_some(), "nodeId": me, "leader": leader,
            "isLeader": me.is_some() && me == leader,
        }).to_string()));
    }
    // ─── Raft write: propose a scale command through consensus ───
    if path == "/royak/v1/raft/scale" && method == hyper::Method::POST {
        let v: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap_or_default();
        let cmd = crate::consensus::Command::Scale {
            name: v["name"].as_str().unwrap_or("").to_string(),
            namespace: v["namespace"].as_str().unwrap_or("default").to_string(),
            replicas: v["replicas"].as_u64().unwrap_or(1) as u32,
        };
        return Ok(match crate::raft_node::propose(cmd).await {
            Ok(msg) => json_response(200, &serde_json::json!({"committed": true, "message": msg}).to_string()),
            Err(e) => json_response(503, &serde_json::json!({"committed": false, "error": e}).to_string()),
        });
    }
    // ─── Raft RPC endpoints (inter-node consensus transport) ───
    if let Some(which) = path.strip_prefix("/royak/v1/raft/") {
        return Ok(match crate::raft_node::handle_rpc(which, &body_bytes).await {
            Ok(json) => json_response(200, &json),
            Err(e) => json_response(503, &serde_json::json!({"error": e}).to_string()),
        });
    }

    // ─── Admission webhooks: validate writes before they hit apply ───
    // (async because we POST an AdmissionReview to the webhook; route_request
    // is sync so this gate lives here.)
    if (method == hyper::Method::POST || method == hyper::Method::PUT || method == hyper::Method::PATCH)
        && !path.starts_with("/royak/v1/")
        && (path.contains("/namespaces/") || path.ends_with("/deployments")
            || path.ends_with("/configmaps") || path.ends_with("/secrets") || path.ends_with("/pods"))
    {
        if let Some(deny) = admission_gate(&world, &body_bytes).await {
            return Ok(json_response(403, &deny));
        }
    }

    // route_request is synchronous and does blocking work (RwLock waits, docker
    // calls, disk writes, stderr→journald logging). Running it inline would pin
    // a tokio worker thread for its whole duration — on a small box (1–2 cores =
    // 1–2 async workers) that serialises all concurrent requests. Offload it to
    // the blocking pool so the async workers stay free to accept/dispatch.
    let (status, body) = tokio::task::spawn_blocking(move || {
        route_request(method.as_str(), &path, &full_url, &headers, &body_bytes, &world)
    })
    .await
    .unwrap_or_else(|_| (500, r#"{"kind":"Status","status":"Failure","message":"handler panicked","code":500}"#.to_string()));
    Ok(json_response(status, &body))
}

// ─── Streaming handlers ───

/// Stream container logs (kubectl logs -f)
async fn handle_log_stream(path: &str, query: &HashMap<String, String>) -> hyper::Response<BoxedBody> {
    let parts: Vec<&str> = path.split('/').collect();
    let pod_name = parts.iter().rev().nth(1).unwrap_or(&"").to_string();
    let tail: u32 = query.get("tailLines")
        .or(query.get("tail"))
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    // Find container by pod name
    let container_id = docker::list_containers(true).ok()
        .and_then(|cs| cs.iter()
            .find(|c| c.names.iter().any(|n| n.contains(&pod_name)))
            .map(|c| c.id[..12.min(c.id.len())].to_string()));

    let Some(cid) = container_id else {
        return json_response(404, &serde_json::json!({"kind":"Status","status":"Failure","message":format!("pod {} not found", pod_name),"code":404}).to_string());
    };

    eprintln!("  [stream] logs -f {pod_name} (tail={tail})");

    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);

    // Stream logs in a blocking thread (Docker uses Unix socket)
    tokio::task::spawn_blocking(move || {
        docker::stream_logs_to_channel(&cid, tail, tx);
    });

    stream_response("text/plain; charset=utf-8", rx)
}

/// Watch resource changes (kubectl get pods -w)
async fn handle_watch(path: &str, query: &HashMap<String, String>, world: Arc<RwLock<DesiredWorld>>) -> hyper::Response<BoxedBody> {
    let resource_version: u64 = query.get("resourceVersion")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let (_, resource_kind, _) = parse_resource_path(path);
    let kind = resource_kind.to_string();

    eprintln!("  [watch] {kind} (rv={resource_version})");

    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(64);

    tokio::spawn(async move {
        #[allow(unused_assignments)]
        let mut last_rv = resource_version;
        #[allow(unused_assignments)]
        let mut last_snapshot: Vec<String> = Vec::new();

        // Send initial state as ADDED events
        {
            let events = build_watch_events(&kind, &world, "ADDED");
            for event in &events {
                let line = format!("{event}\n");
                if tx.send(Bytes::from(line)).await.is_err() { return; }
            }
            last_snapshot = events;
            last_rv = RESOURCE_VERSION.load(Ordering::Relaxed);
        }

        // Poll for changes
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            interval.tick().await;

            let current_rv = RESOURCE_VERSION.load(Ordering::Relaxed);
            if current_rv <= last_rv { continue; }
            last_rv = current_rv;

            let current = build_watch_events(&kind, &world, "MODIFIED");
            // Detect changes
            if current != last_snapshot {
                for event in &current {
                    if !last_snapshot.contains(event) {
                        let line = format!("{event}\n");
                        if tx.send(Bytes::from(line)).await.is_err() { return; }
                    }
                }
                // Detect deletions
                for old in &last_snapshot {
                    if !current.contains(old) {
                        // Extract the object and send DELETED
                        if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(old) {
                            v["type"] = serde_json::json!("DELETED");
                            let line = format!("{}\n", v);
                            if tx.send(Bytes::from(line)).await.is_err() { return; }
                        }
                    }
                }
                last_snapshot = current;
            }
        }
    });

    stream_response("application/json", rx)
}

/// Build watch events for a resource kind
fn build_watch_events(kind: &str, world: &Arc<RwLock<DesiredWorld>>, event_type: &str) -> Vec<String> {
    match kind {
        "pods" => {
            get_docker_pods(None).into_iter().map(|pod| {
                serde_json::json!({"type": event_type, "object": pod}).to_string()
            }).collect()
        }
        "deployments" => {
            let w = world.read().unwrap();
            w.deployments.values().map(|d| {
                serde_json::json!({"type": event_type, "object": deployment_json(d)}).to_string()
            }).collect()
        }
        "services" => {
            let w = world.read().unwrap();
            w.services.values().map(|s| {
                serde_json::json!({"type": event_type, "object": serde_json::json!({
                    "apiVersion": "v1", "kind": "Service",
                    "metadata": {"name": s.name, "namespace": s.namespace},
                    "spec": {"type": s.service_type, "selector": s.selector}
                })}).to_string()
            }).collect()
        }
        "events" => {
            let w = world.read().unwrap();
            w.events.iter().rev().take(20).map(|e| {
                serde_json::json!({"type": event_type, "object": {
                    "kind": "Event", "reason": e.reason, "message": e.message,
                    "involvedObject": {"kind": e.kind, "name": e.object},
                    "type": e.event_type, "count": e.count,
                }}).to_string()
            }).collect()
        }
        "namespaces" => {
            let w = world.read().unwrap();
            w.namespaces.iter().map(|ns| {
                serde_json::json!({"type": event_type, "object": {
                    "apiVersion": "v1", "kind": "Namespace",
                    "metadata": {"name": ns}, "status": {"phase": "Active"}
                }}).to_string()
            }).collect()
        }
        _ => Vec::new(),
    }
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

    let tls_acceptor = if use_tls {
        match generate_tls_cert() {
            Ok((cert_pem, key_pem)) => {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
                let cert_path = format!("{home}/.kube/royak-ca.pem");
                std::fs::write(&cert_path, &cert_pem).ok();

                let certs: Vec<_> = rustls_pemfile::certs(&mut cert_pem.as_bytes())
                    .filter_map(|r| r.ok())
                    .collect();
                let key_opt = rustls_pemfile::private_key(&mut key_pem.as_bytes())
                    .ok().flatten();
                if let Some(key) = key_opt {
                    match rustls::ServerConfig::builder()
                        .with_no_client_auth()
                        .with_single_cert(certs, key)
                    {
                        Ok(config) => {
                            println!("  ✓ API server listening on {addr} (HTTPS)");
                            println!("  ✓ TLS cert: {cert_path}");
                            Some(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
                        }
                        Err(e) => {
                            eprintln!("  ⚠ TLS config failed: {e}, using HTTP");
                            println!("  ✓ API server listening on {addr}");
                            None
                        }
                    }
                } else {
                    eprintln!("  ⚠ TLS key parse failed, using HTTP");
                    println!("  ✓ API server listening on {addr}");
                    None
                }
            }
            Err(e) => {
                eprintln!("  ⚠ cert generation failed: {e}, using HTTP");
                println!("  ✓ API server listening on {addr}");
                None
            }
        }
    } else {
        println!("  ✓ API server listening on {addr}");
        None
    };

    println!("    kubectl: export KUBECONFIG=~/.kube/royak.yaml && kubectl get pods");

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => { eprintln!("  ✗ API server failed to start on {addr}: {e}"); return; }
    };

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
fn scale_object(name: &str, ns: &str, replicas: u32) -> String {
    serde_json::json!({
        "kind": "Scale", "apiVersion": "autoscaling/v1",
        "metadata": {"name": name, "namespace": ns, "uid": resource_uid("Scale", name, ns), "resourceVersion": current_rv().to_string()},
        "spec": {"replicas": replicas},
        "status": {"replicas": replicas, "selector": format!("app={name}")}
    }).to_string()
}

fn not_found_status(path: &str) -> String {
    serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Failure",
        "message": format!("resource not found: {path}"), "code": 404}).to_string()
}

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

fn get_docker_pods(ns_filter: Option<&str>) -> Vec<serde_json::Value> {
    let mut items = Vec::new();

    // Docker containers
    if let Ok(containers) = docker::list_containers(true) {
        for c in containers.iter().filter(|c| c.names.iter().any(|n| n.contains("rk-"))) {
            let name = c.names.first().map(|s| s.trim_start_matches('/')).unwrap_or("?");
            let ns = c.labels.get("royak.namespace").map(|s| s.as_str()).unwrap_or("default");
            if let Some(f) = ns_filter { if f != ns { continue; } }
            let phase = match c.state.as_str() { "running" => "Running", "exited" => "Succeeded", "dead" => "Failed", _ => "Pending" };
            items.push(pod_json(name, ns, &c.image, phase, c.state == "running"));
        }
    }

    // NeuroPods (process-based, no Docker)
    let neuropods = crate::runtime::NeuroPod::list_all();
    for (name, image, _running, _used, _max) in &neuropods {
        if !name.starts_with("rk-") { continue; }
        let ns = "default";
        if let Some(f) = ns_filter { if f != ns { continue; } }
        // Check if process is actually running
        let meta_path = std::path::PathBuf::from(
            std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()))
            .join(".royak/pods").join(name).join("meta.json");
        let running = meta_path.exists();
        let phase = if running { "Running" } else { "Pending" };
        items.push(pod_json(name, ns, image, phase, running));
    }

    items
}

fn list_pods(world: &DesiredWorld, ns: Option<&str>) -> String {
    let _ = world;
    serde_json::json!({
        "kind": "PodList", "apiVersion": "v1",
        "metadata": {"resourceVersion": current_rv()},
        "items": get_docker_pods(ns)
    }).to_string()
}

fn get_pod(world: &DesiredWorld, name: &str, ns: &str) -> (u16, String) {
    let _ = world;
    let pods = get_docker_pods(Some(ns));
    match pods.into_iter().find(|p| p["metadata"]["name"].as_str() == Some(name)) {
        Some(pod) => (200, pod.to_string()),
        None => (404, serde_json::json!({"kind": "Status", "apiVersion": "v1", "status": "Failure", "message": format!("pods \"{name}\" not found"), "code": 404}).to_string()),
    }
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

fn deployment_json(dep: &reconcile::StoredDeployment) -> serde_json::Value {
    let prefix = format!("rk-{}-", dep.name);
    // Count Docker containers
    let docker_ready = match docker::list_containers(true) {
        Ok(containers) => containers.iter()
            .filter(|c| c.names.iter().any(|n| n.contains(&prefix)) && c.state == "running")
            .count() as u32,
        Err(_) => 0,
    };
    // Count NeuroPods
    let neuropod_ready = crate::runtime::NeuroPod::list_all().iter()
        .filter(|(name, _, _, _, _)| name.starts_with(&prefix))
        .count() as u32;
    let ready = docker_ready + neuropod_ready;
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
    let items: Vec<serde_json::Value> = world.deployments.values()
        .filter(|d| ns.is_none() || ns == Some(d.namespace.as_str()))
        .map(|d| deployment_json(d)).collect();
    serde_json::json!({"kind": "DeploymentList", "apiVersion": "apps/v1", "metadata": {"resourceVersion": current_rv()}, "items": items}).to_string()
}

fn get_deployment(world: &DesiredWorld, name: &str, ns: &str) -> (u16, String) {
    match world.deployments.get(name).filter(|d| d.namespace == ns) {
        Some(dep) => {
            let mut j = deployment_json(dep);
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
    match world.configmaps.get(name).filter(|c| c.namespace == ns) {
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
    match world.secrets.get(name).filter(|s| s.namespace == ns) {
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
        Err(e) => { eprintln!("  ✗ ingress failed to start on {addr}: {e}"); return; }
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
        Some((service, svc_port)) => {
            let canary_target = {
                let w = world.read().unwrap();
                resolve_canary_target(&w, &service, svc_port)
            };

            let (target_host, target_port, route_label) = match canary_target {
                Some((ip, port, label)) => (ip, port, label),
                None => {
                    // Service names like "web" aren't resolvable from the ingress
                    // process (which runs on the host, outside any Docker network).
                    // Look up a concrete pod container IP for this service.
                    let target_port_inner = svc_port;
                    match resolve_service_to_pod_ip(&world.read().unwrap(), &service) {
                        Some(ip) => (ip.clone(), target_port_inner, format!("{service}:{svc_port} → {ip}")),
                        None => (service.clone(), svc_port, format!("{service}:{svc_port}")),
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
fn resolve_canary_target(world: &DesiredWorld, service: &str, port: u16) -> Option<(String, u16, String)> {
    // Find which deployment this service selects
    let svc = world.services.get(service)?;
    let app_name = svc.selector.get("app")?;

    // Check if there's an active canary rollout for this deployment
    let rollout = world.pending_rollouts.get(app_name.as_str())?;

    // Get canary weight from deployment strategy
    let weight = world.deployments.get(app_name.as_str())
        .and_then(|d| d.strategy.as_ref())
        .and_then(|s| match s {
            reconcile::DeployStrategy::Canary { weight, .. } => Some(*weight),
            _ => None,
        })
        .unwrap_or(50); // default 50% if strategy doesn't specify

    // Roll weighted random: should this request go to new or old version?
    let roll: u32 = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().subsec_nanos()) % 100;

    let use_new = roll < weight;
    let target_image = if use_new { &rollout.new_image } else { &rollout.old_image };
    let version = if use_new { "canary" } else { "stable" };

    // Find a container running the target image
    if let Ok(containers) = docker::list_containers(false) {
        let prefix = format!("rk-{app_name}-");
        let matching: Vec<_> = containers.iter()
            .filter(|c| c.names.iter().any(|n| n.contains(&prefix)) && c.image.contains(target_image))
            .collect();

        if let Some(container) = matching.first() {
            let short_id = &container.id[..12.min(container.id.len())];
            if let Ok(ip) = docker::container_ip(short_id) {
                return Some((ip, port, format!("{service}:{port} [{version} {weight}%→{target_image}]")));
            }
        }
    }

    None // no canary routing possible, fall back to normal
}

/// Map a cluster service name to a concrete pod container IP on this host.
/// Needed because the ingress controller runs on the host (not inside a
/// Docker-managed namespace network), so Docker's built-in DNS resolver
/// for service-name → pod-IP is not available to us. We pick the first
/// pod that matches the service's app selector and belongs to the same
/// deployment; round-robin across pods is a v0.3 follow-up.
fn resolve_service_to_pod_ip(world: &DesiredWorld, service: &str) -> Option<String> {
    resolve_service_to_all_pod_ips(world, service).into_iter().next()
}

/// All ready pod IPs backing a service — the ingress load-balances across these
/// (round-robin), so hitting the same host lands on different pods per request.
fn resolve_service_to_all_pod_ips(world: &DesiredWorld, service: &str) -> Vec<String> {
    let Some(svc) = world.services.values().find(|s| s.name == service) else { return Vec::new() };
    let Some(app) = svc.selector.get("app").cloned() else { return Vec::new() };
    let Some(deployment) = world.deployments.values()
        .find(|d| d.name == app && d.namespace == svc.namespace) else { return Vec::new() };
    // Enumerate the ACTUAL running pods (rk-<deployment>-*) rather than guessing
    // ordinals 1..replicas — after a scale-down the survivors keep their original
    // numbers (e.g. rk-demosite-9/10/11), so index-guessing resolved nothing → 502.
    let prefix = format!("rk-{}-", deployment.name);
    let mut ips = Vec::new();
    if let Ok(containers) = docker::list_containers(false) {
        for c in containers.iter().filter(|c| c.state == "running"
            && c.names.iter().any(|n| n.trim_start_matches('/').starts_with(&prefix)))
        {
            if let Some(name) = c.names.first().map(|n| n.trim_start_matches('/')) {
                if let Ok(ip) = docker::container_ip(name) {
                    if !ip.is_empty() { ips.push(ip); }
                }
            }
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
fn resolve_target_port(world: &DesiredWorld, service: &str, rule_port: u16) -> u16 {
    match world.services.values().find(|s| s.name == service) {
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
fn peer_pods_store() -> &'static std::sync::Mutex<Vec<(String, String)>> {
    static P: std::sync::OnceLock<std::sync::Mutex<Vec<(String, String)>>> = std::sync::OnceLock::new();
    P.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}
pub fn set_peer_pods(entries: Vec<(String, String)>) {
    if let Ok(mut g) = peer_pods_store().lock() { *g = entries; }
}

/// Deployment name backing a service (via its `app` selector).
fn service_deployment(world: &DesiredWorld, service: &str) -> Option<String> {
    let svc = world.services.values().find(|s| s.name == service)?;
    let app = svc.selector.get("app")?;
    world.deployments.values()
        .find(|d| &d.name == app && d.namespace == svc.namespace)
        .map(|d| d.name.clone())
}

/// Rebuild the pre-resolved ingress routing table. Called by the reconcile loop
/// AFTER each tick (off the write-lock). Local pods resolve to their container
/// IP; pods on peer nodes resolve to that peer's mesh proxy + the pod name.
pub fn publish_ingress_snapshot(world: &DesiredWorld) {
    let peers = peer_pods_store().lock().map(|g| g.clone()).unwrap_or_default();
    let mut routes = Vec::new();
    for ingress in world.ingresses.values() {
        for rule in &ingress.rules {
            for ip_path in &rule.paths {
                let mut backends: Vec<(String, u16, String, u16)> = Vec::new();
                // The ingress rule targets the Service's published `port` (e.g. 80),
                // but the pods listen on the Service's `targetPort` (e.g. 8080). We
                // connect straight to pod IPs, so resolve rule port → targetPort.
                let pod_port = resolve_target_port(world, &ip_path.service, ip_path.port);
                // Local pods → direct (pod_port used as the connect port).
                for ip in resolve_service_to_all_pod_ips(world, &ip_path.service) {
                    backends.push((ip, pod_port, String::new(), pod_port));
                }
                // Remote pods → via the owning peer's mesh proxy (:6550). We connect
                // to the mesh proxy port, but carry the pod's real targetPort as the
                // 4th field so the peer dials the pod on it (X-Royak-Port) not :80.
                if let Some(dep) = service_deployment(world, &ip_path.service) {
                    let prefix = format!("rk-{dep}-");
                    for (addr, pod) in &peers {
                        if pod.starts_with(&prefix) {
                            let host = addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr.as_str());
                            backends.push((host.to_string(), crate::cluster_mesh::DEFAULT_MESH_PORT, pod.clone(), pod_port));
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
            let prefix = format!("rk-{dep}-");
            running_pod_names.iter()
                .filter(|n| n.trim_start_matches('/').starts_with(&prefix))
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
        let replicas = world.deployments.values()
            .find(|d| d.name == h.deployment)
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
        for c in containers.iter()
            .filter(|c| c.state == "running" && c.names.iter().any(|n| n.contains("rk-")))
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
    let peers = peer_pods_store().lock().map(|g| g.clone()).unwrap_or_default();
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
        let reps = world.deployments.get(&app).map(|d| d.replicas).unwrap_or(0);
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

fn find_backend(world: &DesiredWorld, host: &str, path: &str) -> Option<(String, u16)> {
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
                return Some((backend.service.clone(), backend.port));
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
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        TcpStream::connect(&addr),
    )
    .await
    .map_err(|_| format!("connect {addr}: timeout"))?
    .map_err(|e| format!("connect {addr}: {e}"))?;

    // Build the request line + headers. Pass the client's headers through
    // (except Host which we rewrite, and hop-by-hop headers the RFC says
    // should not cross a proxy boundary).
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
            "upgrade" | "content-length"
        ) { continue; }
        if let Ok(v) = val.to_str() {
            req.push_str(&format!("{}: {}\r\n", name.as_str(), v));
        }
    }
    req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    req.push_str("Connection: close\r\n\r\n");

    stream.write_all(req.as_bytes()).await.map_err(|e| format!("write head: {e}"))?;
    if !body.is_empty() {
        stream.write_all(body).await.map_err(|e| format!("write body: {e}"))?;
    }

    // Read everything until EOF (connection: close guarantees this).
    let mut raw = Vec::with_capacity(4096);
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        stream.read_to_end(&mut raw),
    )
    .await
    .map_err(|_| "read: timeout".to_string())?
    .map_err(|e| format!("read: {e}"))?;

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
) -> hyper::Response<BoxedBody> {
    // Pod name: .../pods/{name}/exec
    let pod_name = path.trim_end_matches("/exec").rsplit('/').next().unwrap_or("").to_string();

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
            let containers = crate::docker::list_containers(false).ok()?;
            let c = containers.iter().find(|c| c.names.iter().any(|n| n.trim_start_matches('/') == pod_name))?;
            let short = c.id[..12.min(c.id.len())].to_string();
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
        w.deployments.insert("web".into(), deploy("web", 3));
        w.deployments.insert("api".into(), deploy("api", 2));
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
        w.deployments.insert("web".into(), deploy("web", 3));
        w.services.insert("web-svc".into(), svc("web-svc", "web", vec![port(80, 8080)]));
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
        w.services.insert("ghost".into(), svc("ghost", "missing", vec![port(80, 80)]));
        let details = demo_service_details(&w, &["rk-web-1".to_string()]);
        assert_eq!(details[0]["backends"], 0);
    }

    #[test]
    fn ingress_details_flatten_host_path_to_backend() {
        let mut w = DesiredWorld::new();
        w.ingresses.insert("ing".into(), StoredIngress {
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
        w.deployments.insert("web".into(), deploy("web", 4));
        w.hpas.insert("web-hpa".into(), StoredHPA {
            name: "web-hpa".into(), deployment: "web".into(),
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
    let pod = pod_name.clone();
    let setup = tokio::task::spawn_blocking(move || {
        let containers = crate::docker::list_containers(false).ok()?;
        let c = containers.iter().find(|c| c.names.iter().any(|n| n.trim_start_matches('/') == pod))?;
        let short = c.id[..12.min(c.id.len())].to_string();
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
) -> hyper::Response<BoxedBody> {
    let pod_name = path.trim_end_matches("/portforward").rsplit('/').next().unwrap_or("").to_string();

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
            let containers = crate::docker::list_containers(false).ok();
            let cid = containers.as_ref().and_then(|cs| cs.iter()
                .find(|c| c.names.iter().any(|n| n.trim_start_matches('/') == pod2))
                .map(|c| c.id[..12.min(c.id.len())].to_string()));
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
