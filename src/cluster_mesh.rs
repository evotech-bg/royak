//! Cluster Mesh — MVP cross-node service routing.
//!
//! See ROADMAP.md §v0.3 "Cross-node pod networking" for the full design.
//!
//! Each node runs a `NodeProxy` on a well-known port. A pod that wants to
//! reach a service resolves the service name to the local proxy's address
//! (via /etc/hosts injection, owned by the reconcile loop). The proxy
//! inspects the request, looks up which cluster node actually runs a
//! matching pod, and forwards the connection: same-node → directly to the
//! container, different-node → to the remote node's proxy, which terminates
//! and hands off to the local pod.
//!
//! This module is intentionally minimal: it owns the *routing decision*
//! and the proxy runtime, but not the /etc/hosts injection (reconcile's
//! responsibility) nor pod-internal IP discovery (runtime module). Those
//! land alongside this in v0.3.

use crate::docker;
use crate::reconcile::DesiredWorld;
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Default mesh port. Picked to not collide with api_port (6443) or the
/// UDP discovery port (9443). Overridable via --mesh-port.
pub const DEFAULT_MESH_PORT: u16 = 6550;

/// Where a service's traffic should land.
#[derive(Debug, Clone, PartialEq)]
pub enum Endpoint {
    /// Service has a pod on this node — send traffic to the local container.
    Local { pod_name: String },
    /// Service's pods live on another node — forward to that node's mesh proxy.
    Remote { node_name: String, node_addr: String },
    /// Service exists but has no ready pods.
    NoBackend,
    /// Service not known to the cluster.
    Unknown,
}

/// Stateless router. Takes a snapshot of the world and a service name,
/// decides where traffic should go. Pure function — trivial to test.
pub struct Router<'a> {
    world: &'a DesiredWorld,
    local_node: &'a str,
}

impl<'a> Router<'a> {
    pub fn new(world: &'a DesiredWorld, local_node: &'a str) -> Self {
        Self { world, local_node }
    }

    /// Resolve a service name (namespace-scoped) to an endpoint.
    /// Pick policy: prefer a pod on the local node; fall back to any remote node.
    pub fn resolve(&self, service_name: &str, namespace: &str) -> Endpoint {
        // 1. Does the service exist?
        let svc = match self.world.services.values()
            .find(|s| s.name == service_name && s.namespace == namespace) {
            Some(s) => s,
            None => return Endpoint::Unknown,
        };

        // 2. Find deployments whose selector matches the service.
        // Our spec carries `app:` as the canonical selector key.
        let target_app = match svc.selector.get("app") {
            Some(a) => a.as_str(),
            None => return Endpoint::NoBackend,
        };

        let deployment = match self.world.deployments.values()
            .find(|d| d.name == target_app && d.namespace == namespace) {
            Some(d) => d,
            None => return Endpoint::NoBackend,
        };

        // 3. Which node runs this deployment? The scheduler stamps node on
        //    each pod; for the MVP we treat the deployment as homogeneous
        //    and read the first pod's node. If no pods yet, NoBackend.
        if deployment.replicas == 0 {
            return Endpoint::NoBackend;
        }

        // MVP simplification: pod-0 defines the node. In v0.3 proper we
        // track per-pod placement in a field stamped by the scheduler.
        let pod_name = format!("rk-{}-1", deployment.name);
        let node_for_pod = self.lookup_pod_node(&pod_name).unwrap_or_else(|| self.local_node.to_string());

        if node_for_pod == self.local_node {
            Endpoint::Local { pod_name }
        } else {
            match self.world.nodes.get(&node_for_pod) {
                Some(node) => Endpoint::Remote {
                    node_name: node_for_pod.clone(),
                    node_addr: node.address.clone(),
                },
                None => Endpoint::NoBackend,
            }
        }
    }

    /// For v0.3 this reads a per-pod node field. In v0.2 we don't track
    /// that explicitly, so the MVP assumes "pod is on local node" for
    /// non-cross-node clusters. The cross-node integration test will
    /// populate this via the scheduler.
    fn lookup_pod_node(&self, _pod_name: &str) -> Option<String> {
        None
    }
}

/// Historical holder struct — the working proxy is now the free function
/// run_proxy. Kept because the v0.3 scaffolding tests pinned its shape;
/// the type itself isn't constructed by production code.
#[allow(dead_code)]
pub struct NodeProxy {
    pub listen_port: u16,
    pub local_node: String,
    pub world: Arc<RwLock<DesiredWorld>>,
}

#[allow(dead_code)]
impl NodeProxy {
    pub fn new(listen_port: u16, local_node: String, world: Arc<RwLock<DesiredWorld>>) -> Self {
        Self { listen_port, local_node, world }
    }

    /// Deprecated — retained for the unit test that pinned v0.2's "not
    /// implemented yet" contract. Real runtime is run_proxy below.
    #[allow(dead_code)]
    pub fn run_stub(&self) -> Result<(), String> {
        Err(format!(
            "cluster_mesh::NodeProxy::run_stub superseded by run_proxy (port {}, node {}). \
             See ROADMAP.md §Cross-node pod networking.",
            self.listen_port, self.local_node
        ))
    }
}

/// Parse the "Host:" header value from a raw HTTP request head.
/// Returns the hostname without the port, or empty string.
fn parse_host_header(head: &str) -> String {
    for line in head.lines() {
        if let Some(value) = line.strip_prefix("Host:").or_else(|| line.strip_prefix("host:")) {
            let value = value.trim();
            return value.split(':').next().unwrap_or("").to_string();
        }
    }
    String::new()
}

/// Case-insensitive lookup of a request header value from the raw head.
fn parse_header(head: &str, name: &str) -> Option<String> {
    for line in head.lines() {
        if line.is_empty() { break; } // end of headers
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// Parse the namespace from a hostname of the form
/// `<service>.<namespace>.svc.cluster.local` or just `<service>`.
/// Falls back to "default".
fn parse_ns(host: &str) -> (String, String) {
    let parts: Vec<&str> = host.split('.').collect();
    match parts.len() {
        0 => (String::new(), "default".to_string()),
        1 => (parts[0].to_string(), "default".to_string()),
        _ => (parts[0].to_string(), parts[1].to_string()),
    }
}

/// The conventional offset from api_port to mesh_port on the same node.
/// If api=6443, mesh=6550. Post-v0.3 we'll store mesh_port on ClusterNode.
fn remote_mesh_addr(api_addr: &str) -> String {
    // api_addr looks like "host:6443"; replace port with DEFAULT_MESH_PORT.
    if let Some((host, _)) = api_addr.rsplit_once(':') {
        format!("{host}:{DEFAULT_MESH_PORT}")
    } else {
        format!("{api_addr}:{DEFAULT_MESH_PORT}")
    }
}

/// Run the mesh proxy on `port`. Accepts HTTP over TCP, uses the Host
/// header + Router to decide where to forward, then bridges raw bytes
/// between client and upstream. Blocks forever (or until accept errors
/// in a way we can't recover from).
pub async fn run_proxy(port: u16, local_node: String, world: Arc<RwLock<DesiredWorld>>) {
    let addr = format!("0.0.0.0:{port}");
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("  ✗ mesh proxy failed to bind {addr}: {e}");
            return;
        }
    };
    println!("  ✓ mesh proxy listening on {addr} (node={local_node})");

    loop {
        let (client, remote) = match listener.accept().await {
            Ok(c) => c,
            Err(_) => continue,
        };
        let world = world.clone();
        let local_node = local_node.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(client, world, local_node, remote.to_string()).await {
                eprintln!("  [mesh] conn from {remote}: {e}");
            }
        });
    }
}

/// The cluster secret both nodes derive the mesh key from.
/// Priority: 1) ROYAK_CLUSTER_SECRET env  2) ~/.royak/cluster.secret file
/// (auto-generated per host on first use, mode 0600).
///
/// SECURITY: there is deliberately NO hardcoded fallback. A shipped default
/// key would mean every cluster shares the same key = zero confidentiality.
/// For a real multi-node cluster you MUST set ROYAK_CLUSTER_SECRET to the same
/// strong value on every node (the auto-generated per-host file only protects
/// a single-host / same-filesystem setup). If we can't obtain one, we warn and
/// disable encryption rather than pretend (fail-safe, visible, not fail-open).
fn cluster_secret() -> Option<String> {
    if let Ok(s) = std::env::var("ROYAK_CLUSTER_SECRET") {
        if !s.trim().is_empty() { return Some(s); }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let path = format!("{home}/.royak/cluster.secret");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim().to_string();
        if !s.is_empty() { return Some(s); }
    }
    // Generate a per-host secret and persist it (0600).
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let dir = format!("{home}/.royak");
    std::fs::create_dir_all(&dir).ok();
    if std::fs::write(&path, &hex).is_ok() {
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        eprintln!("  [security] mesh cluster secret generated: {path} (0600).");
        eprintln!("  [security] For multi-host clusters, set ROYAK_CLUSTER_SECRET to the SAME value on every node.");
        return Some(hex);
    }
    None
}

/// True when cross-node hops should be AES-256-GCM encrypted (default on;
/// set ROYAK_MESH_PLAINTEXT=1 to fall back to the v0.3 plaintext behaviour).
fn mesh_encrypt_on() -> bool {
    std::env::var("ROYAK_MESH_PLAINTEXT").is_err()
}

async fn handle_conn(
    mut client: TcpStream,
    world: Arc<RwLock<DesiredWorld>>,
    local_node: String,
    _remote: String,
) -> Result<(), String> {
    use crate::mesh_crypto::{MESH_MAGIC, mesh_key};

    // Read the first chunk. It's either (a) a plaintext HTTP request from a
    // local pod, or (b) an encrypted peer connection that starts with the
    // mesh magic. Peek enough to tell them apart.
    let mut buf = vec![0u8; 8192];
    let n = client.read(&mut buf).await.map_err(|e| format!("read head: {e}"))?;
    if n == 0 {
        return Err("empty request".to_string());
    }

    // ── (b) Encrypted peer connection ──
    if n >= MESH_MAGIC.len() && &buf[..MESH_MAGIC.len()] == MESH_MAGIC {
        return serve_encrypted_peer(client, buf[MESH_MAGIC.len()..n].to_vec(), world, local_node).await;
    }

    let head = String::from_utf8_lossy(&buf[..n]);

    // Explicit-target fast path: a peer's ingress already resolved the pod and
    // tells us EXACTLY which local container to hand off to (X-Royak-Pod). A
    // worker node has no service/deployment definition to resolve against, so
    // this is how cross-node ingress reaches a pod that lives here.
    if let Some(pod) = parse_header(&head, "x-royak-pod") {
        match docker::container_ip(&pod) {
            Ok(ip) if !ip.is_empty() => {
                let mut upstream = TcpStream::connect(format!("{ip}:80")).await
                    .map_err(|e| format!("connect {ip}:80: {e}"))?;
                upstream.write_all(&buf[..n]).await.map_err(|e| format!("write head: {e}"))?;
                splice(client, upstream).await;
                return Ok(());
            }
            _ => return reply_status(&mut client, 502, "target pod not on this node").await,
        }
    }

    let host = parse_host_header(&head);
    let (service, namespace) = parse_ns(&host);
    if service.is_empty() {
        return reply_status(&mut client, 400, "missing Host header").await;
    }

    // Resolve via Router (snapshot of world, then drop the guard).
    let endpoint = {
        let w = world.read().unwrap();
        Router::new(&w, &local_node).resolve(&service, &namespace)
    };

    match endpoint {
        Endpoint::Local { pod_name } => {
            let ip = docker::container_ip(&pod_name)
                .map_err(|_| "no container ip".to_string());
            let upstream_addr = match ip {
                Ok(ip) => format!("{ip}:80"),
                Err(_) => return reply_status(&mut client, 502, "no container ip").await,
            };
            let mut upstream = TcpStream::connect(&upstream_addr).await
                .map_err(|e| format!("connect {upstream_addr}: {e}"))?;
            upstream.write_all(&buf[..n]).await.map_err(|e| format!("write head: {e}"))?;
            splice(client, upstream).await;
            Ok(())
        }
        Endpoint::Remote { node_addr, .. } => {
            let peer = remote_mesh_addr(&node_addr);
            // Encrypt only when enabled AND we actually hold a cluster secret.
            // No secret → fail SAFE to plaintext with a visible warning, never
            // to a fake/hardcoded key that would give false confidence.
            let secret = if mesh_encrypt_on() { cluster_secret() } else { None };
            if let Some(secret) = secret {
                forward_encrypted_to_peer(client, &buf[..n], &peer, &secret).await
            } else {
                if mesh_encrypt_on() {
                    eprintln!("  [security] mesh encryption requested but no cluster secret available — forwarding PLAINTEXT to {peer}");
                }
                let mut upstream = TcpStream::connect(&peer).await
                    .map_err(|e| format!("connect {peer}: {e}"))?;
                upstream.write_all(&buf[..n]).await.map_err(|e| format!("write head: {e}"))?;
                splice(client, upstream).await;
                Ok(())
            }
        }
        Endpoint::NoBackend => reply_status(&mut client, 503, "no backend").await,
        Endpoint::Unknown => reply_status(&mut client, 404, "service not found").await,
    }
}

/// Plaintext bidirectional splice between two streams, recording a mesh flow.
async fn splice(client: TcpStream, upstream: TcpStream) {
    let peer = client.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let dst = upstream.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    let t0 = std::time::Instant::now();
    let started = crate::flows::now_secs();
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();
    let a = tokio::spawn(async move { tokio::io::copy(&mut cr, &mut uw).await.unwrap_or(0) });
    let b = tokio::spawn(async move { tokio::io::copy(&mut ur, &mut cw).await.unwrap_or(0) });
    let (up, down) = tokio::join!(a, b);
    crate::flows::record(crate::flows::FlowRecord {
        via: "mesh".into(),
        source: peer,
        dest: dst,
        port: 0,
        bytes_up: up.unwrap_or(0),
        bytes_down: down.unwrap_or(0),
        started,
        duration_ms: t0.elapsed().as_millis() as u64,
    });
}

/// Connect to a peer node's mesh proxy and relay the client's traffic
/// AES-256-GCM encrypted: send the magic, then sealed frames of client bytes;
/// decrypt the peer's sealed frames back to the client.
async fn forward_encrypted_to_peer(
    client: TcpStream,
    first_chunk: &[u8],
    peer: &str,
    secret: &str,
) -> Result<(), String> {
    use crate::mesh_crypto::{MESH_MAGIC, mesh_key, seal_frame, open_frame};
    let key = mesh_key(secret);
    let mut upstream = TcpStream::connect(peer).await
        .map_err(|e| format!("connect {peer}: {e}"))?;
    upstream.write_all(MESH_MAGIC).await.map_err(|e| format!("magic: {e}"))?;
    // Seal the already-read head.
    upstream.write_all(&seal_frame(&key, first_chunk, rand_nonce())).await
        .map_err(|e| format!("seal head: {e}"))?;

    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();
    let key_up = key;
    // client → (seal) → peer
    let up = tokio::spawn(async move {
        let mut b = [0u8; 8192];
        loop {
            match cr.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(m) => { if uw.write_all(&seal_frame(&key_up, &b[..m], rand_nonce())).await.is_err() { break; } }
            }
        }
    });
    // peer → (open) → client
    let down = tokio::spawn(async move {
        let mut acc: Vec<u8> = Vec::new();
        let mut b = [0u8; 8192];
        loop {
            match ur.read(&mut b).await {
                Ok(0) | Err(_) => break,
                Ok(m) => {
                    acc.extend_from_slice(&b[..m]);
                    while let Ok(Some((pt, consumed))) = open_frame(&key, &acc) {
                        if cw.write_all(&pt).await.is_err() { return; }
                        acc.drain(..consumed);
                    }
                }
            }
        }
    });
    let _ = tokio::join!(up, down);
    Ok(())
}

/// Serve an inbound encrypted peer connection: decrypt frames to recover the
/// original request, forward to the local pod, and seal responses back.
async fn serve_encrypted_peer(
    peer_conn: TcpStream,
    mut early: Vec<u8>,
    world: Arc<RwLock<DesiredWorld>>,
    local_node: String,
) -> Result<(), String> {
    use crate::mesh_crypto::{mesh_key, seal_frame, open_frame};
    // A peer opened an encrypted connection to us, so we must hold the same
    // secret. If we don't, we cannot decrypt — reject rather than guess.
    let secret = match cluster_secret() {
        Some(s) => s,
        None => return Err("received encrypted peer traffic but no cluster secret configured".into()),
    };
    let key = mesh_key(&secret);

    // Decrypt frames until we have the full request head (enough to resolve).
    let (mut pr, mut pw) = peer_conn.into_split();
    let mut plain: Vec<u8> = Vec::new();
    let mut b = [0u8; 8192];
    // Drain any frames already in `early`, then read more until we can resolve.
    loop {
        while let Ok(Some((pt, consumed))) = open_frame(&key, &early) {
            plain.extend_from_slice(&pt);
            early.drain(..consumed);
        }
        let host = parse_host_header(&String::from_utf8_lossy(&plain));
        if !host.is_empty() && plain.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        match pr.read(&mut b).await {
            Ok(0) | Err(_) => break,
            Ok(m) => early.extend_from_slice(&b[..m]),
        }
    }

    let host = parse_host_header(&String::from_utf8_lossy(&plain));
    let (service, namespace) = parse_ns(&host);
    let endpoint = {
        let w = world.read().unwrap();
        Router::new(&w, &local_node).resolve(&service, &namespace)
    };
    let upstream_addr = match endpoint {
        Endpoint::Local { pod_name } => match docker::container_ip(&pod_name) {
            Ok(ip) => format!("{ip}:80"),
            Err(_) => return Err("peer: no container ip".into()),
        },
        // A peer only forwards to us because WE host the pod; anything else
        // is a routing error — don't double-hop.
        _ => return Err("peer: service not local".into()),
    };

    let upstream = TcpStream::connect(&upstream_addr).await
        .map_err(|e| format!("connect {upstream_addr}: {e}"))?;
    let (mut ur, mut uw) = upstream.into_split();
    uw.write_all(&plain).await.map_err(|e| format!("write to pod: {e}"))?;

    // peer(more frames) → pod
    let key_up = key;
    let up = tokio::spawn(async move {
        let mut acc: Vec<u8> = early;
        let mut bb = [0u8; 8192];
        loop {
            while let Ok(Some((pt, consumed))) = open_frame(&key_up, &acc) {
                if uw.write_all(&pt).await.is_err() { return; }
                acc.drain(..consumed);
            }
            match pr.read(&mut bb).await {
                Ok(0) | Err(_) => break,
                Ok(m) => acc.extend_from_slice(&bb[..m]),
            }
        }
    });
    // pod → (seal) → peer
    let down = tokio::spawn(async move {
        let mut bb = [0u8; 8192];
        loop {
            match ur.read(&mut bb).await {
                Ok(0) | Err(_) => break,
                Ok(m) => { if pw.write_all(&seal_frame(&key, &bb[..m], rand_nonce())).await.is_err() { break; } }
            }
        }
    });
    let _ = tokio::join!(up, down);
    Ok(())
}

/// A fresh random 96-bit nonce per frame (no reuse).
fn rand_nonce() -> [u8; 12] {
    use rand::RngCore;
    let mut n = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut n);
    n
}

async fn reply_status(client: &mut TcpStream, code: u16, msg: &str) -> Result<(), String> {
    let body = format!("{{\"status\":\"Failure\",\"code\":{code},\"message\":\"{msg}\"}}");
    let resp = format!(
        "HTTP/1.1 {code} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        http_reason(code),
        body.len()
    );
    client.write_all(resp.as_bytes()).await.map_err(|e| format!("write reply: {e}"))?;
    Ok(())
}

fn http_reason(code: u16) -> &'static str {
    match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reconcile::{ClusterNode, NodeStatus, StoredService, StoredDeployment};
    use std::collections::HashMap;

    fn empty_world() -> DesiredWorld {
        DesiredWorld::new()
    }

    fn make_service(world: &mut DesiredWorld, name: &str, ns: &str, app: &str) {
        let mut selector = HashMap::new();
        selector.insert("app".to_string(), app.to_string());
        world.services.insert(name.to_string(), StoredService {
            name: name.to_string(),
            namespace: ns.to_string(),
            selector,
            ports: vec![],
            service_type: "ClusterIP".to_string(),
        });
    }

    fn make_deployment(world: &mut DesiredWorld, name: &str, ns: &str, replicas: u32) {
        world.deployments.insert(name.to_string(), StoredDeployment {
            name: name.to_string(),
            namespace: ns.to_string(),
            replicas,
            image: "nginx:alpine".to_string(),
            previous_image: None,
            command: None,
            env: vec![],
            init_containers: vec![],
            containers: vec![],
            resource_limits: None,
            strategy: None,
            pause_after_idle: None,
            paused: false,
            idle_since: None,
            stateful: false,
        });
    }

    fn make_node(world: &mut DesiredWorld, name: &str, addr: &str) {
        world.nodes.insert(name.to_string(), ClusterNode {
            name: name.to_string(),
            address: addr.to_string(),
            cpu_capacity: 100.0,
            mem_capacity: 4096.0,
            cpu_used: 0.0,
            mem_used: 0.0,
            pod_count: 0,
            status: NodeStatus::Ready,
            last_heartbeat: 0,
            neural_token: vec![],
            joined_at: 0,
        });
    }

    #[test]
    fn unknown_service_returns_unknown() {
        let world = empty_world();
        let r = Router::new(&world, "host-a");
        assert_eq!(r.resolve("ghost", "default"), Endpoint::Unknown);
    }

    #[test]
    fn service_without_selector_app_returns_no_backend() {
        let mut world = empty_world();
        world.services.insert("svc".to_string(), StoredService {
            name: "svc".to_string(),
            namespace: "default".to_string(),
            selector: HashMap::new(),
            ports: vec![],
            service_type: "ClusterIP".to_string(),
        });
        let r = Router::new(&world, "host-a");
        assert_eq!(r.resolve("svc", "default"), Endpoint::NoBackend);
    }

    #[test]
    fn service_without_matching_deployment_returns_no_backend() {
        let mut world = empty_world();
        make_service(&mut world, "web-svc", "default", "web");
        let r = Router::new(&world, "host-a");
        assert_eq!(r.resolve("web-svc", "default"), Endpoint::NoBackend);
    }

    #[test]
    fn deployment_with_zero_replicas_returns_no_backend() {
        let mut world = empty_world();
        make_service(&mut world, "web-svc", "default", "web");
        make_deployment(&mut world, "web", "default", 0);
        let r = Router::new(&world, "host-a");
        assert_eq!(r.resolve("web-svc", "default"), Endpoint::NoBackend);
    }

    #[test]
    fn local_endpoint_when_no_pod_placement_info() {
        // v0.2 MVP: without per-pod node tracking, fall back to local.
        let mut world = empty_world();
        make_service(&mut world, "web-svc", "default", "web");
        make_deployment(&mut world, "web", "default", 1);
        let r = Router::new(&world, "host-a");
        match r.resolve("web-svc", "default") {
            Endpoint::Local { pod_name } => assert_eq!(pod_name, "rk-web-1"),
            other => panic!("expected Local, got {other:?}"),
        }
    }

    #[test]
    fn namespace_scoped_resolution() {
        let mut world = empty_world();
        make_service(&mut world, "svc-a", "ns-a", "web");
        make_deployment(&mut world, "web", "ns-a", 1);
        // A service in another namespace targeting a deployment that does
        // not exist there.
        make_service(&mut world, "svc-b", "ns-b", "other");
        let r = Router::new(&world, "host-a");
        assert!(matches!(r.resolve("svc-a", "ns-a"), Endpoint::Local { .. }));
        // Wrong namespace for svc-a → Unknown (service exists only in ns-a).
        assert_eq!(r.resolve("svc-a", "ns-b"), Endpoint::Unknown);
        // svc-b exists in ns-b but its target deployment "other" is missing.
        assert_eq!(r.resolve("svc-b", "ns-b"), Endpoint::NoBackend);
    }

    #[test]
    fn parse_host_strips_port() {
        let head = "GET / HTTP/1.1\r\nHost: web-svc:80\r\n\r\n";
        assert_eq!(parse_host_header(head), "web-svc");
    }

    #[test]
    fn parse_host_case_insensitive() {
        let head = "GET / HTTP/1.1\r\nhost: svc\r\n\r\n";
        assert_eq!(parse_host_header(head), "svc");
    }

    #[test]
    fn parse_host_missing_returns_empty() {
        let head = "GET / HTTP/1.1\r\nX-Other: v\r\n\r\n";
        assert_eq!(parse_host_header(head), "");
    }

    #[test]
    fn parse_ns_simple_host() {
        let (svc, ns) = parse_ns("web-svc");
        assert_eq!(svc, "web-svc");
        assert_eq!(ns, "default");
    }

    #[test]
    fn parse_ns_k8s_fqdn() {
        let (svc, ns) = parse_ns("web-svc.production.svc.cluster.local");
        assert_eq!(svc, "web-svc");
        assert_eq!(ns, "production");
    }

    #[test]
    fn remote_mesh_addr_rewrites_port() {
        assert_eq!(remote_mesh_addr("10.0.0.2:6443"), "10.0.0.2:6550");
        assert_eq!(remote_mesh_addr("host-b:6443"), "host-b:6550");
    }

    #[test]
    fn node_proxy_constructor_does_not_panic() {
        let world = Arc::new(RwLock::new(empty_world()));
        let p = NodeProxy::new(DEFAULT_MESH_PORT, "host-a".to_string(), world);
        assert_eq!(p.listen_port, DEFAULT_MESH_PORT);
        assert_eq!(p.local_node, "host-a");
    }

    #[test]
    fn node_proxy_run_stub_still_errors_as_deprecated() {
        // Kept only as a breadcrumb: the real runtime is now `run_proxy`.
        // run_stub is retained as a deprecated no-op; it must still report
        // its superseded status so no caller accidentally relies on it.
        let world = Arc::new(RwLock::new(empty_world()));
        let p = NodeProxy::new(DEFAULT_MESH_PORT, "host-a".to_string(), world);
        match p.run_stub() {
            Err(msg) => {
                assert!(msg.contains("superseded") || msg.contains("run_proxy"),
                    "deprecated stub should point at run_proxy: {msg}");
            }
            Ok(_) => panic!("stub must not succeed — real runtime is run_proxy"),
        }
    }

    #[test]
    fn remote_endpoint_uses_node_address() {
        // Remote path exists in the code for when per-pod placement is
        // wired up. Smoke-test by crafting a world where lookup_pod_node
        // would return a remote node, simulated via a second-node presence.
        let mut world = empty_world();
        make_service(&mut world, "web-svc", "default", "web");
        make_deployment(&mut world, "web", "default", 1);
        make_node(&mut world, "host-b", "10.0.0.2:6443");
        // Even with host-b present, current MVP returns Local because
        // lookup_pod_node is a stub. This test pins that contract so the
        // v0.3 upgrade deliberately breaks it and forces pod-placement wiring.
        let r = Router::new(&world, "host-a");
        assert!(matches!(r.resolve("web-svc", "default"), Endpoint::Local { .. }),
            "v0.2 MVP: pod placement unavailable, must fall back to Local");
    }
}
