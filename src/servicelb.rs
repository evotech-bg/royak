//! ServiceLB — userspace NodePort load balancer (klipper-lb-style).
//!
//! For every `Service` of `type: NodePort`, listen on `0.0.0.0:{nodePort}` and
//! forward TCP to the ephemeral host ports Docker assigned to the backing pods'
//! published `targetPort` (see `docker::create_container_full`). Forwarding via
//! host ports instead of container IPs means this works on macOS too, where the
//! Docker VM makes container IPs unreachable from the host.
//!
//! Reconciles every second against the full Service spec, not just the port:
//! a listener stays bound for as long as some Service wants its port, and its
//! route (namespace, selector, targetPort) is swapped in place through a watch
//! channel, so a change reaches the next connection without rebinding and
//! without cutting connections already in flight. Removed ports are closed.
//!
//! Backends are this node's Ready pods only — the same readiness model the API
//! status and the ingress use (`reconcile::local_views`): a pod gets no traffic
//! before it is Ready and drops out as soon as it stops being Ready. Pods
//! without probes are Ready once running.
//!
//! Docker binds host ports only at container create; a pod that does not yet
//! publish a port a Service now targets is replaced by the deployment rollout
//! (see `publishes_all` in reconcile_docker) and only then becomes a backend.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

use tokio::sync::watch;

use crate::docker::DockerContainer;
use crate::placement::PodView;
use crate::reconcile::DesiredWorld;

#[derive(Clone, Debug, PartialEq)]
struct LbSpec {
    namespace: String,
    service: String,
    node_port: u16,
    target_port: u16,
    deployment: String,
}

/// Returns the host port of a backend for `spec`, round-robin from `start`.
type Resolver = Arc<dyn Fn(&LbSpec, usize) -> Option<u16> + Send + Sync>;

struct Listener {
    spec: watch::Sender<LbSpec>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Listener {fn drop(&mut self){self.task.abort();}}

struct StatePoller {
    stop:Arc<std::sync::atomic::AtomicBool>,
    thread:std::thread::Thread,
}
impl Drop for StatePoller {
    fn drop(&mut self){self.stop.store(true,Ordering::Release);self.thread.unpark();}
}

/// Drive NodePort listeners for as long as the process lives. Spawned on the
/// tokio runtime by both `royak watch` and `royak api`.
pub async fn run(world: Arc<RwLock<DesiredWorld>>) {
    let w = Arc::clone(&world);
    let resolve: Resolver = Arc::new(move |spec: &LbSpec, start: usize| pick_backend(&w, spec, start));
    let mut listeners: HashMap<u16, Listener> = HashMap::new();
    let mut conflicts_logged: HashSet<String> = HashSet::new();
    // A periodic snapshot must not continually wake arbitrary workers in the
    // shared blocking pool: that keeps every worker created by a past burst
    // alive. One fixed, named state reader preserves the SAME one-second poll
    // and lock semantics, without parking async workers or warming that pool.
    let (tx,mut snapshots)=watch::channel(None::<Wanted>);
    let stop=Arc::new(std::sync::atomic::AtomicBool::new(false));let worker_stop=stop.clone();
    let worker=std::thread::Builder::new().name("rk-lb-state".into()).spawn(move||{
        while !worker_stop.load(Ordering::Acquire){
            let wanted={let w=world.read().unwrap_or_else(|e|e.into_inner());desired_listeners(&w)};
            if worker_stop.load(Ordering::Acquire)||tx.send(Some(wanted)).is_err(){break;}
            std::thread::park_timeout(std::time::Duration::from_secs(1));
        }
    }).expect("ServiceLB state worker unavailable");
    let _poller=StatePoller{stop,thread:worker.thread().clone()};
    while snapshots.changed().await.is_ok() {
        let Some(wanted)=snapshots.borrow_and_update().clone() else{continue;};
        let mut current_conflicts=HashSet::new();
        for (port, losers) in &wanted.conflicts {
            let msg = format!("  [servicelb] :{port} is claimed by several services; using {}, ignoring {}",
                wanted.specs[port].service_ref(), losers.join(", "));
            current_conflicts.insert(msg);
        }
        // Deduplicate only the current snapshot, not all historical Services.
        for msg in refresh_conflict_cache(&mut conflicts_logged,current_conflicts){eprintln!("{msg}");}
        sync_listeners(&mut listeners, wanted.specs, &resolve);
    }
}

impl LbSpec {
    fn service_ref(&self) -> String {
        format!("{}/{}", self.namespace, self.service)
    }
}

#[derive(Clone)]
struct Wanted {
    specs: BTreeMap<u16, LbSpec>,
    /// port → services that also claim it but lost (for logging).
    conflicts: BTreeMap<u16, Vec<String>>,
}
fn refresh_conflict_cache(previous:&mut HashSet<String>,current:HashSet<String>)->Vec<String>{
    let mut fresh:Vec<_>=current.difference(previous).cloned().collect();fresh.sort();
    *previous=current;fresh
}

/// Every listener the Services ask for, keyed by the port to listen on. Two
/// Services claiming the same port is a conflict: the lexicographically first
/// `namespace/name` wins deterministically, so the route never flaps.
fn desired_listeners(w: &DesiredWorld) -> Wanted {
    let mut all: Vec<LbSpec> = Vec::new();
    for s in w.services.values() {
        if s.service_type != "NodePort" && s.service_type != "LoadBalancer" { continue; }
        let Some(dep) = s.selector.get("app").filter(|d| !d.is_empty()) else { continue };
        for p in &s.ports {
            // NodePort listens on nodePort; LoadBalancer exposes the service
            // port itself on the node (single-node "external IP" = the node).
            let listen = if s.service_type == "LoadBalancer" { Some(p.port) } else { p.node_port };
            if let Some(lp) = listen.filter(|lp| *lp != 0) {
                all.push(LbSpec {
                    namespace: s.namespace.clone(),
                    service: s.name.clone(),
                    node_port: lp,
                    target_port: p.target_port,
                    deployment: dep.clone(),
                });
            }
        }
    }
    all.sort_by(|a, b| (a.node_port, &a.namespace, &a.service, a.target_port).cmp(&(b.node_port, &b.namespace, &b.service, b.target_port)));
    let mut specs: BTreeMap<u16, LbSpec> = BTreeMap::new();
    let mut conflicts: BTreeMap<u16, Vec<String>> = BTreeMap::new();
    for s in all {
        match specs.get(&s.node_port) {
            None => { specs.insert(s.node_port, s); }
            Some(winner) if winner.service_ref() != s.service_ref() => {
                conflicts.entry(s.node_port).or_default().push(s.service_ref());
            }
            Some(_) => {} // same service lists the port twice — first entry wins
        }
    }
    Wanted { specs, conflicts }
}

/// Bring the running listeners in line with `wanted`: close ports no longer
/// wanted, swap the route of ports whose spec changed (bound socket and open
/// connections are kept), and bind new ports. A listener whose task ended
/// (e.g. the bind failed) is dropped and retried on the next pass.
fn sync_listeners(listeners: &mut HashMap<u16, Listener>, wanted: BTreeMap<u16, LbSpec>, resolve: &Resolver) {
    listeners.retain(|port, l| {
        if !wanted.contains_key(port) {
            l.task.abort();
            eprintln!("  [servicelb] :{port} closed (service removed)");
            return false;
        }
        !l.task.is_finished()
    });
    for (port, spec) in wanted {
        match listeners.get(&port) {
            Some(l) => {
                if *l.spec.borrow() != spec {
                    eprintln!("  [servicelb] :{port} → {}/{} (svc/{}, targetPort {}) [updated]",
                        spec.namespace, spec.deployment, spec.service, spec.target_port);
                    l.spec.send_replace(spec);
                }
            }
            None => {
                let (tx, rx) = watch::channel(spec);
                let task = tokio::spawn(listen(port, rx, Arc::clone(resolve)));
                listeners.insert(port, Listener { spec: tx, task });
            }
        }
    }
}

async fn listen(port: u16, spec: watch::Receiver<LbSpec>, resolve: Resolver) {
    #[cfg(test)]
    let bound = match tests::take_reserved(port) {
        Some(listener) => tokio::net::TcpListener::from_std(listener),
        None => tokio::net::TcpListener::bind(("0.0.0.0", port)).await,
    };
    #[cfg(not(test))]
    let bound = tokio::net::TcpListener::bind(("0.0.0.0", port)).await;
    let listener = match bound {
        Ok(l) => {
            let s = spec.borrow().clone();
            eprintln!("  [servicelb] :{port} → {}/{} (svc/{}, targetPort {})",
                s.namespace, s.deployment, s.service, s.target_port);
            l
        }
        Err(e) => {
            eprintln!("  [servicelb] cannot bind :{port}: {e}");
            return;
        }
    };

    let rr = Arc::new(AtomicUsize::new(0));
    loop {
        let (mut inbound, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => continue,
        };
        // The route is read per connection: a Service change applies to the
        // next connection, while this one keeps the backend it got.
        let route = spec.borrow().clone();
        let resolve = Arc::clone(&resolve);
        let start = rr.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            // Docker calls are blocking unix-socket IO — keep them off the reactor.
            let r = route.clone();
            let backend = tokio::task::spawn_blocking(move || resolve(&r, start)).await.ok().flatten();
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
                    dest: route.service,
                    port: route.node_port,
                    bytes_up: up,
                    bytes_down: down,
                    started,
                    duration_ms: t0.elapsed().as_millis() as u64,
                });
            }
        });
    }
}

/// Container names of the Ready main containers of `namespace/deployment` on
/// this node, sorted. Readiness comes from `views` (`reconcile::local_views`).
fn ready_backends(views: &[PodView], ours: &[&DockerContainer], namespace: &str, deployment: &str) -> Vec<String> {
    let ready: HashSet<&str> = views.iter()
        .filter(|v| v.kind == "deployment" && v.owner == deployment && v.namespace == namespace && v.running && v.ready)
        .map(|v| v.pod.as_str())
        .collect();
    let mut out: Vec<String> = ours.iter()
        .filter(|c| c.state == "running" && !c.labels.contains_key("royak.init"))
        .filter(|c| c.labels.get(crate::store::LABEL_ROLE).map(|r| r == "main").unwrap_or(true))
        .filter(|c| c.labels.get(crate::store::LABEL_NAMESPACE).map(|n| n.as_str()).unwrap_or(crate::store::DEFAULT_NS) == namespace)
        .filter_map(|c| {
            let name = c.names.first()?.trim_start_matches('/').to_string();
            let pod = c.labels.get(crate::store::LABEL_POD).cloned().unwrap_or_else(|| name.clone());
            ready.contains(pod.as_str()).then_some(name)
        })
        .collect();
    out.sort();
    out
}

/// Pick a Ready pod (round-robin from `start`) that has the target port
/// published, and return its ephemeral host port.
fn pick_backend(world: &Arc<RwLock<DesiredWorld>>, spec: &LbSpec, start: usize) -> Option<u16> {
    let containers = crate::docker::list_containers(false).ok()?;
    let w = world.read().unwrap_or_else(|e| e.into_inner());
    let ours = crate::reconcile::our_containers(&w, &containers);
    let views = crate::reconcile::local_views(&w, &ours);
    let pods = ready_backends(&views, &ours, &spec.namespace, &spec.deployment);
    drop(w);
    if pods.is_empty() {
        return None;
    }
    for i in 0..pods.len() {
        let pod = &pods[(start + i) % pods.len()];
        if let Some(hp) = crate::docker::container_host_port(pod, spec.target_port) {
            return Some(hp);
        }
    }
    // Ready pods exist but none publishes the port yet: the rollout replaces them.
    None
}

#[cfg(test)]
mod tests {
    include!("servicelb_cache_tests.rs");
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn reconcile_lock_does_not_park_async_heartbeat_timers() {
        let world = Arc::new(RwLock::new(DesiredWorld::new()));
        let locked = world.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let _guard = locked.write().unwrap();
            tx.send(()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(500));
        });
        rx.recv().unwrap();
        let start = std::time::Instant::now();
        let task = tokio::spawn(run(world));
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let elapsed = start.elapsed();
        task.abort();
        tokio::task::spawn_blocking(move || writer.join().unwrap()).await.unwrap();
        assert!(elapsed < std::time::Duration::from_millis(250), "ServiceLB parked the async runtime for {elapsed:?}");
    }

    fn world(yaml: &str) -> DesiredWorld {
        let mut w = DesiredWorld::new();
        for r in crate::spec::parse_yaml(yaml).unwrap() { w.apply(&r).unwrap(); }
        w
    }

    fn view(ns: &str, owner: &str, pod: &str, ready: bool) -> PodView {
        PodView {
            pod: pod.into(), node: "n1".into(), namespace: ns.into(), kind: "deployment".into(),
            owner: owner.into(), template: "t".into(), image: "i".into(), running: true, ready,
            pending: false, published: None,
        }
    }

    fn container(ns: &str, pod: &str, role: &str) -> DockerContainer {
        let mut labels = HashMap::new();
        labels.insert(crate::store::LABEL_NAMESPACE.to_string(), ns.to_string());
        labels.insert(crate::store::LABEL_POD.to_string(), pod.to_string());
        labels.insert(crate::store::LABEL_ROLE.to_string(), role.to_string());
        let name = if role == "main" { pod.to_string() } else { format!("{pod}-{role}") };
        DockerContainer { id: name.clone(), names: vec![format!("/{name}")], image: "i".into(),
            state: "running".into(), status: String::new(), labels, ports: vec![] }
    }

    #[test]
    fn only_ready_main_containers_of_the_right_namespace_are_backends() {
        let views = vec![
            view("a", "web", "rk-a_web-1", true),
            view("a", "web", "rk-a_web-2", false), // NotReady
            view("b", "web", "rk-b_web-1", true),  // same name, other namespace
            view("a", "api", "rk-a_api-1", true),  // other deployment
        ];
        let cs = [
            container("a", "rk-a_web-1", "main"), container("a", "rk-a_web-1", "sidecar"),
            container("a", "rk-a_web-2", "main"), container("b", "rk-b_web-1", "main"),
            container("a", "rk-a_api-1", "main"),
        ];
        let ours: Vec<&DockerContainer> = cs.iter().collect();
        assert_eq!(ready_backends(&views, &ours, "a", "web"), vec!["rk-a_web-1".to_string()]);
        assert_eq!(ready_backends(&views, &ours, "b", "web"), vec!["rk-b_web-1".to_string()]);
        let none_ready = vec![view("a", "web", "rk-a_web-1", false)];
        assert!(ready_backends(&none_ready, &ours, "a", "web").is_empty(), "no Ready pod → no backend");
    }

    const SVCS: &str = r#"
apiVersion: v1
kind: Service
metadata: {name: web, namespace: a}
spec:
  type: NodePort
  selector: {app: web}
  ports: [{port: 80, targetPort: 8080, nodePort: 30081}]
---
apiVersion: v1
kind: Service
metadata: {name: web, namespace: b}
spec:
  type: NodePort
  selector: {app: web}
  ports: [{port: 80, targetPort: 8080, nodePort: 30082}]
---
apiVersion: v1
kind: Service
metadata: {name: lb, namespace: a}
spec:
  type: LoadBalancer
  selector: {app: web}
  ports: [{port: 30090, targetPort: 9090}]
"#;

    #[test]
    fn listeners_follow_the_full_service_spec() {
        let mut w = world(SVCS);
        let want = desired_listeners(&w).specs;
        assert_eq!(want[&30081].namespace, "a");
        assert_eq!(want[&30082].namespace, "b", "same-named services in other namespaces keep their own backends");
        assert_eq!(want[&30090].target_port, 9090, "LoadBalancer listens on the service port");
        // Selector + targetPort change on the same nodePort changes the spec.
        for r in crate::spec::parse_yaml("apiVersion: v1\nkind: Service\nmetadata: {name: web, namespace: a}\nspec:\n  type: NodePort\n  selector: {app: alt}\n  ports: [{port: 80, targetPort: 9090, nodePort: 30081}]\n").unwrap() {
            w.apply(&r).unwrap();
        }
        let after = desired_listeners(&w).specs;
        assert_eq!((after[&30081].deployment.as_str(), after[&30081].target_port), ("alt", 9090));
        assert_eq!(after[&30082], want[&30082]);
    }

    #[test]
    fn a_node_port_already_in_use_is_rejected_at_apply() {
        let mut w = world(SVCS);
        let dup = SVCS.split("---").nth(1).unwrap().replace("nodePort: 30082", "nodePort: 30081");
        let e = w.apply(&crate::spec::parse_yaml(&dup).unwrap()[0]).unwrap_err();
        assert!(e.contains("30081") && e.contains("a/web"), "{e}");
        // Re-applying the owner itself is fine.
        let own = SVCS.split("---").next().unwrap();
        w.apply(&crate::spec::parse_yaml(own).unwrap()[0]).unwrap();
    }

    #[test]
    fn a_port_claimed_twice_has_one_deterministic_owner() {
        // State written before apply-time validation existed.
        let mut w = world(SVCS);
        w.services.get_mut("b/web").unwrap().ports[0].node_port = Some(30081);
        let wanted = desired_listeners(&w);
        assert_eq!(wanted.specs[&30081].service_ref(), "a/web");
        assert_eq!(wanted.conflicts[&30081], vec!["b/web".to_string()]);
    }

    async fn echo_server(reply: &'static str) -> u16 {
        let l = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else { return };
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(reply.as_bytes()).await.is_err() { return; }
                    }
                });
            }
        });
        port
    }

    async fn ask(s: &mut tokio::net::TcpStream) -> String {
        s.write_all(b"?").await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), s.read(&mut buf)).await
            .expect("no reply").unwrap();
        String::from_utf8_lossy(&buf[..n]).into_owned()
    }

    fn reserved() -> &'static std::sync::Mutex<HashMap<u16, std::net::TcpListener>> {
        static RESERVED: std::sync::OnceLock<std::sync::Mutex<HashMap<u16, std::net::TcpListener>>> = std::sync::OnceLock::new();
        RESERVED.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
    }
    pub(super) fn take_reserved(port: u16) -> Option<std::net::TcpListener> { reserved().lock().unwrap().remove(&port) }
    fn reserve(listener: std::net::TcpListener) -> u16 {
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        reserved().lock().unwrap().insert(port, listener);
        port
    }
    fn free_port() -> u16 {
        // Transfer an actually bound socket to the listener task. A port probe
        // followed by close/rebind races both other tests and host processes.
        reserve(std::net::TcpListener::bind(("0.0.0.0", 0)).unwrap())
    }

    fn spec(port: u16, dep: &str, target: u16) -> LbSpec {
        LbSpec { namespace: "a".into(), service: "web".into(), node_port: port, target_port: target, deployment: dep.into() }
    }

    #[tokio::test]
    async fn route_changes_reach_new_connections_without_rebinding() {
        let (a, alt) = (echo_server("A").await, echo_server("ALT").await);
        // Backends by (deployment, targetPort) — stands in for the Docker lookup.
        let resolve: Resolver = Arc::new(move |s: &LbSpec, _| match (s.deployment.as_str(), s.target_port) {
            ("a", 8080) => Some(a),
            ("alt", 8080) | ("a", 9090) => Some(alt),
            _ => None,
        });
        let port = free_port();
        let mut ls: HashMap<u16, Listener> = HashMap::new();
        sync_listeners(&mut ls, BTreeMap::from([(port, spec(port, "a", 8080))]), &resolve);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut old = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_eq!(ask(&mut old).await, "A");

        // Selector change on the same nodePort: new connections go to ALT,
        // the open connection keeps its backend.
        sync_listeners(&mut ls, BTreeMap::from([(port, spec(port, "alt", 8080))]), &resolve);
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_eq!(ask(&mut c).await, "ALT");
        assert_eq!(ask(&mut old).await, "A", "in-flight connection must not be cut");

        // targetPort change.
        sync_listeners(&mut ls, BTreeMap::from([(port, spec(port, "a", 9090))]), &resolve);
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_eq!(ask(&mut c).await, "ALT");

        // No backend → the connection is closed, never sent somewhere stale.
        sync_listeners(&mut ls, BTreeMap::from([(port, spec(port, "gone", 8080))]), &resolve);
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut buf = [0u8; 4];
        let _ = c.write_all(b"?").await;
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), c.read(&mut buf)).await.unwrap().unwrap_or(0);
        assert_eq!(n, 0);

        // Removal frees the port; re-creating binds it again with the new route.
        sync_listeners(&mut ls, BTreeMap::new(), &resolve);
        assert!(ls.is_empty());
        let mut freed = false;
        for _ in 0..40 {
            if let Ok(listener) = std::net::TcpListener::bind(("0.0.0.0", port)) {
                reserve(listener); freed = true; break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        assert!(freed, "listener must release the port when the service is removed");
        sync_listeners(&mut ls, BTreeMap::from([(port, spec(port, "a", 8080))]), &resolve);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        assert_eq!(ask(&mut c).await, "A");
        for l in ls.values() { l.task.abort(); }
    }
}
