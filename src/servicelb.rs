//! ServiceLB — userspace NodePort load balancer (klipper-lb-style).
//!
//! For every `Service` of `type: NodePort`, listen on `0.0.0.0:{nodePort}` and
//! forward TCP to the ephemeral host ports Docker assigned to the backing pods'
//! published `targetPort` (see `docker::create_container_full`). Forwarding via
//! host ports instead of container IPs means this works on macOS too, where the
//! Docker VM makes container IPs unreachable from the host.
//!
//! Reconciles every 3s: new NodePort services get listeners, removed ones are
//! torn down. Round-robin across running pods per connection.
//!
//! Known limit (documented in COMPATIBILITY.md): pods created *before* a
//! NodePort service was applied don't have their targetPort published — Docker
//! port bindings are fixed at container create. Re-apply or scale the
//! deployment to recreate pods with the port published; applying deployment and
//! service from the same file (the normal path) always works.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use crate::reconcile::DesiredWorld;

#[derive(Clone, PartialEq)]
struct LbSpec {
    service: String,
    node_port: u16,
    target_port: u16,
    deployment: String,
}

/// Drive NodePort listeners for as long as the process lives. Spawned on the
/// tokio runtime by both `royak watch` and `royak api`.
pub async fn run(world: Arc<RwLock<DesiredWorld>>) {
    let mut listeners: HashMap<u16, tokio::task::JoinHandle<()>> = HashMap::new();
    loop {
        let specs: Vec<LbSpec> = {
            let w = world.read().unwrap();
            w.services
                .values()
                .filter(|s| s.service_type == "NodePort" || s.service_type == "LoadBalancer")
                .flat_map(|s| {
                    let dep = s.selector.get("app").cloned().unwrap_or_default();
                    let svc = s.name.clone();
                    let is_lb = s.service_type == "LoadBalancer";
                    s.ports
                        .iter()
                        .filter_map(|p| {
                            // NodePort listens on nodePort; LoadBalancer exposes
                            // the service port itself on the node (single-node
                            // "external IP" = the node), klipper-lb-style.
                            let listen = if is_lb { Some(p.port) } else { p.node_port };
                            listen.map(|lp| LbSpec {
                                service: svc.clone(),
                                node_port: lp,
                                target_port: p.target_port,
                                deployment: dep.clone(),
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .collect()
        };

        let want: HashSet<u16> = specs.iter().map(|s| s.node_port).collect();
        listeners.retain(|port, handle| {
            if !want.contains(port) {
                handle.abort();
                eprintln!("  [servicelb] :{port} closed (service removed)");
                return false;
            }
            !handle.is_finished()
        });

        for spec in specs {
            if spec.deployment.is_empty() || listeners.contains_key(&spec.node_port) {
                continue;
            }
            let port = spec.node_port;
            listeners.insert(port, tokio::spawn(listen(spec)));
        }

        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    }
}

async fn listen(spec: LbSpec) {
    let listener = match tokio::net::TcpListener::bind(("0.0.0.0", spec.node_port)).await {
        Ok(l) => {
            eprintln!(
                "  [servicelb] :{} → {} (svc/{}, targetPort {})",
                spec.node_port, spec.deployment, spec.service, spec.target_port
            );
            l
        }
        Err(e) => {
            eprintln!("  [servicelb] cannot bind :{}: {e}", spec.node_port);
            return;
        }
    };

    let rr = Arc::new(AtomicUsize::new(0));
    loop {
        let (mut inbound, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        let dep = spec.deployment.clone();
        let svc = spec.service.clone();
        let tp = spec.target_port;
        let np = spec.node_port;
        let start = rr.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            // Docker calls are blocking unix-socket IO — keep them off the reactor.
            let backend =
                tokio::task::spawn_blocking(move || pick_backend(&dep, tp, start)).await.ok().flatten();
            let Some(host_port) = backend else { return };
            if let Ok(mut outbound) = tokio::net::TcpStream::connect(("127.0.0.1", host_port)).await {
                let t0 = std::time::Instant::now();
                let started = crate::flows::now_secs();
                // copy_bidirectional returns (a→b, b→a) byte counts.
                let (up, down) = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await
                    .unwrap_or((0, 0));
                crate::flows::record(crate::flows::FlowRecord {
                    via: "servicelb".into(),
                    source: peer.to_string(),
                    dest: svc,
                    port: np,
                    bytes_up: up,
                    bytes_down: down,
                    started,
                    duration_ms: t0.elapsed().as_millis() as u64,
                });
            }
        });
    }
}

/// Pick a running pod of `deployment` (round-robin from `start`) that has
/// `target_port` published, and return its ephemeral host port.
fn pick_backend(deployment: &str, target_port: u16, start: usize) -> Option<u16> {
    let containers = crate::docker::list_containers(false).ok()?;
    let mut pods: Vec<String> = containers
        .iter()
        .filter(|c| {
            c.state == "running"
                && c.labels.get("royak.deployment").map(|d| d.as_str()) == Some(deployment)
                && c.labels.get("royak.role").map(|r| r.as_str()) != Some("sidecar")
        })
        .filter_map(|c| c.names.first().map(|n| n.trim_start_matches('/').to_string()))
        .collect();
    pods.sort();
    if pods.is_empty() {
        return None;
    }
    // Try every pod starting at the round-robin index; skip pods created
    // before the service existed (no published port yet).
    for i in 0..pods.len() {
        let pod = &pods[(start + i) % pods.len()];
        if let Some(hp) = crate::docker::container_host_port(pod, target_port) {
            return Some(hp);
        }
    }
    eprintln!(
        "  [servicelb] no pod of {deployment} publishes port {target_port} — \
         re-apply or scale the deployment so pods are recreated with the port exposed"
    );
    None
}
