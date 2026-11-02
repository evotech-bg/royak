//! Service-scoped, expiring TCP sessions. No arbitrary addresses or public relay.
use crate::{
    auth::{self, Attrs, Identity},
    reconcile::{DesiredWorld, StoredService},
    store,
};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, OnceLock, RwLock,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_TTL: u64 = 900;
const MAX_SESSIONS: usize = 256;
const CHUNK: usize = 16384;
#[derive(Clone)]
pub struct SecureTransport;
#[derive(Clone)]
pub struct PeerTransport {
    pub local: std::net::IpAddr,
    pub remote: std::net::IpAddr,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub service: String,
    pub port: u16,
    pub ttl_seconds: u64,
}
struct Session {
    id: String,
    namespace: String,
    target: Target,
    owner: Identity,
    cluster: String,
    fingerprint: String,
    deadline: Instant,
    expires: u64,
    stop: tokio::sync::watch::Sender<bool>,
    reason: Mutex<Option<String>>,
    active: AtomicUsize,
}
/// One counted connection, shared by its async owner and every detached
/// blocking worker. Only the LAST real owner returns capacity.
#[derive(Clone)]
struct ActiveLease(Arc<ActiveReservation>);
struct ActiveReservation {session:Arc<Session>}
impl Drop for ActiveReservation {
    fn drop(&mut self){self.session.active.fetch_sub(1,Ordering::SeqCst);}
}
impl ActiveLease {
    fn acquire(session:&Arc<Session>)->Option<Self>{
        if session.active.fetch_add(1,Ordering::SeqCst)>=8 {
            session.active.fetch_sub(1,Ordering::SeqCst);return None;
        }
        Some(Self(Arc::new(ActiveReservation{session:session.clone()})))
    }
    fn hold(&self)->Self{Self(self.0.clone())}
}
fn active_job<T:Send+'static>(lease:&ActiveLease,f:impl FnOnce()->T+Send+'static)->tokio::task::JoinHandle<T> {
    let worker=lease.hold();
    tokio::task::spawn_blocking(move||{let _worker=worker;f()})
}
async fn active_blocking<T:Send+'static>(lease:&ActiveLease,f:impl FnOnce()->T+Send+'static)->T {
    active_job(lease,f).await.expect("Connect blocking task failed")
}
async fn active_invalid_session(w:&Arc<RwLock<DesiredWorld>>,s:&Arc<Session>,lease:&ActiveLease)->Option<&'static str>{
    let (w,s)=(w.clone(),s.clone());
    active_job(lease,move||s.invalid(&w.read().unwrap_or_else(|e|e.into_inner()))).await.unwrap_or(Some("state inspection failed"))
}
struct Remote {
    origin: String,
    namespace: String,
    target: Target,
    fingerprint: String,
    deadline: Instant,
    lease: Mutex<Instant>,
    socket: Mutex<(TcpStream, u64, bool)>,
}
#[derive(Default)]
struct Registry {
    sessions: HashMap<String, Arc<Session>>,
    remote: HashMap<String, Arc<Remote>>,
    audit: VecDeque<Value>,
}
fn registry() -> &'static Mutex<Registry> {
    static R: OnceLock<Mutex<Registry>> = OnceLock::new();
    R.get_or_init(|| Mutex::new(Registry::default()))
}
fn reserve_session(r: &mut Registry, session: Arc<Session>) -> bool {
    // Pending grants count too. A stopped pending grant is not a revoked one.
    if r.sessions
        .values()
        .filter(|s| {
            s.owner.user == session.owner.user
                && s.reason.lock().unwrap_or_else(|e| e.into_inner()).is_none()
        })
        .count()
        >= 16
    {
        return false;
    }
    if r.sessions.len() >= MAX_SESSIONS {
        // Retained closed metadata must not exhaust access for other users.
        // Durable audit history is independent of this bounded runtime cache.
        // Keep closing sockets until their connection tasks have released them.
        r.sessions.retain(|_, s| {
            s.active.load(Ordering::SeqCst) > 0
                || s.reason.lock().unwrap_or_else(|e| e.into_inner()).is_none()
        });
    }
    if r.sessions.len() >= MAX_SESSIONS {
        return false;
    }
    r.sessions.insert(session.id.clone(), session);
    true
}
fn epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn issuer_ready() -> bool {
    if crate::raft_node::is_clustered() {
        crate::raft_node::is_cluster_scheduler()
    } else {
        store::owns_state()
    }
}
fn random_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    encode(&bytes)
}
fn encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() > CHUNK * 2 || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid bounded data frame".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| "invalid data frame".into()))
        .collect()
}
fn permission(
    w: &DesiredWorld,
    id: &Identity,
    verb: &str,
    sub: &str,
    ns: &str,
    t: &Target,
) -> bool {
    // Royak's optional port-specific resourceName is "service:port".
    [t.service.clone(), format!("{}:{}", t.service, t.port)]
        .iter()
        .any(|name| {
            auth::authorize(
                w,
                id,
                &Attrs::new(verb, "services", Some(sub), Some(ns), Some(name)),
            )
        })
}
fn fingerprint(s: &StoredService) -> String {
    use sha2::{Digest, Sha256};
    let selectors: BTreeMap<_, _> = s.selector.iter().collect();
    format!(
        "{:x}",
        Sha256::digest(
            json!([s.name, s.namespace, s.service_type, selectors, s.ports])
                .to_string()
                .as_bytes()
        )
    )
}
fn target_service(w: &DesiredWorld, ns: &str, t: &Target) -> Result<(StoredService, u16), String> {
    if !store::is_dns_label(ns)
        || !store::is_dns_label(&t.service)
        || t.port == 0
        || !(1..=MAX_TTL).contains(&t.ttl_seconds)
    {
        return Err("explicit namespace, Service, TCP port and TTL 1..900 required".into());
    }
    let s = w
        .services
        .get(&store::obj_key(ns, &t.service))
        .ok_or("Service not found")?;
    if s.selector.len() != 1 || !s.selector.contains_key("app") {
        return Err("Connect requires the supported app-only selector".into());
    }
    let ports: Vec<_> = s.ports.iter().filter(|p| p.port == t.port).collect();
    if ports.len() != 1 || ports[0].protocol != "TCP" || ports[0].target_port == 0 {
        return Err("port must identify one declared TCP Service port".into());
    }
    Ok((s.clone(), ports[0].target_port))
}
fn audit(event: Value) -> Result<(), String> {
    use std::fs::OpenOptions;
    let dir = crate::reconcile::royak_data_dir();
    std::fs::create_dir_all(&dir).map_err(|_| "Connect audit directory unavailable")?;
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut r = registry().lock().unwrap_or_else(|e| e.into_inner());
    let mut file = options
        .open(format!("{dir}/connect-audit.jsonl"))
        .map_err(|_| "Connect audit unavailable")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if file
            .metadata()
            .map_err(|_| "audit metadata")?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err("Connect audit must be private (0600)".into());
        }
    }
    let line = event.to_string() + "\n";
    if file.metadata().map_err(|_| "audit metadata")?.len() + line.len() as u64 > 8 * 1024 * 1024 {
        return Err("Connect audit capacity reached; rotate it before new access".into());
    }
    file.write_all(line.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|_| "Connect audit write failed")?;
    r.audit.push_back(event);
    while r.audit.len() > 1024 {
        r.audit.pop_front();
    }
    Ok(())
}
impl Session {
    fn event(&self, action: &str, reason: &str) -> Value {
        json!({"time":epoch(),"action":action,"reason":reason,"session":self.id,"user":self.owner.user,"namespace":self.namespace,"service":self.target.service,"port":self.target.port})
    }
    fn metadata(&self) -> Value {
        json!({"id":self.id,"namespace":self.namespace,"service":self.target.service,"port":self.target.port,"owner":self.owner.user,"expires_at":self.expires,"closed":*self.stop.borrow(),"reason":*self.reason.lock().unwrap_or_else(|e|e.into_inner()),"active_connections":self.active.load(Ordering::SeqCst)})
    }
    fn invalid(&self, w: &DesiredWorld) -> Option<&'static str> {
        if Instant::now() >= self.deadline {
            return Some("expired");
        }
        if !issuer_ready() {
            return Some("issuer lost authoritative state/quorum leadership");
        }
        if w.cluster_id != self.cluster
            || !permission(
                w,
                &self.owner,
                "create",
                "connect",
                &self.namespace,
                &self.target,
            )
        {
            return Some("permission removed");
        }
        if target_service(w, &self.namespace, &self.target)
            .map(|(s, _)| fingerprint(&s) != self.fingerprint)
            .unwrap_or(true)
        {
            return Some("Service changed or deleted");
        }
        None
    }
    fn close(&self, why: &str) -> Result<(), String> {
        let mut reason = self.reason.lock().unwrap_or_else(|e| e.into_inner());
        if reason.is_none() {
            *reason = Some(why.into());
            self.stop.send_replace(true);
            drop(reason);
            audit(self.event("closed", why))?;
        }
        Ok(())
    }
}
/// Called on every committed state installation, including deletions followed
/// immediately by recreation. Never reconstruct a grant from a reusable name.
pub fn state_installed(w: &DesiredWorld) {
    let (sessions, remotes) = {
        let r = registry().lock().unwrap_or_else(|e| e.into_inner());
        (
            r.sessions.values().cloned().collect::<Vec<_>>(),
            r.remote.values().cloned().collect::<Vec<_>>(),
        )
    };
    for s in sessions {
        if s.cluster == w.cluster_id {
            if let Some(why) = s.invalid(w) {
                let _ = s.close(why);
            }
        }
    }
    for r in remotes {
        if target_service(w, &r.namespace, &r.target)
            .map(|(s, _)| fingerprint(&s) != r.fingerprint)
            .unwrap_or(true)
        {
            let _ = r
                .socket
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .0
                .shutdown(Shutdown::Both);
        }
    }
}
fn sweep() {
    let mut r = registry().lock().unwrap_or_else(|e| e.into_inner());
    let now = Instant::now();
    // Watch receivers close upgraded connections, including completely idle ones.
    let expired: Vec<_> = r
        .sessions
        .values()
        .filter(|s| now >= s.deadline && !*s.stop.borrow())
        .cloned()
        .collect();
    r.sessions.retain(|_, s| {
        now.saturating_duration_since(s.deadline) < Duration::from_secs(120)
            || s.active.load(Ordering::SeqCst) > 0
    });
    r.remote.retain(|_, c| {
        let keep = now < c.deadline && now < *c.lease.lock().unwrap_or_else(|e| e.into_inner());
        if !keep {
            let _ = c
                .socket
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .0
                .shutdown(Shutdown::Both);
        }
        keep
    });
    drop(r);
    for s in expired {
        let _ = s.close("expired");
    }
}
fn start_sweeper() {
    static START: OnceLock<()> = OnceLock::new();
    START.get_or_init(|| {
        // Expiry/audit IO has one fixed process-lifetime worker. Repeated
        // spawn_blocking sweeps at 100 ms kept arbitrary shared-pool workers
        // warm after bursts. The sweep period and Connect limits are unchanged.
        std::thread::Builder::new().name("rk-connect-gc".into()).spawn(|| {
            let result=std::panic::catch_unwind(||loop {
                std::thread::sleep(Duration::from_millis(100));
                sweep();
            });
            // Never leave the control plane serving access after its only
            // expiry worker has died. OS process exit also closes its tunnels.
            if result.is_err(){std::process::abort();}
        }).expect("Connect expiry worker unavailable");
    });
}
fn response(code: u16, v: Value) -> hyper::Response<crate::api::BoxedBody> {
    crate::api::json_response(code, &v.to_string())
}
fn error(code: u16, s: impl Into<String>) -> hyper::Response<crate::api::BoxedBody> {
    response(code, json!({"error":s.into()}))
}

async fn invalid_session(w: &Arc<RwLock<DesiredWorld>>, s: &Arc<Session>) -> Option<&'static str> {
    let (w, s) = (w.clone(), s.clone());
    tokio::task::spawn_blocking(move || s.invalid(&w.read().unwrap_or_else(|e| e.into_inner())))
        .await
        .unwrap_or(Some("state inspection failed"))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    // Locks, Docker and durable audit writes must not park async/Raft workers.
    tokio::task::spawn_blocking(f)
        .await
        .expect("Connect blocking task failed")
}

fn transport_error_code(error: &str) -> &'static str {
    // Never copy a peer response, payload, address or credential into audit.
    for code in [
        "invalid bounded data frame",
        "invalid bounded Connect peer request",
        "invalid peer frame",
        "remote handle closed",
        "remote lease invalid",
        "remote Service changed",
        "out-of-order or replayed stream frame",
        "backend write failed; no retry",
        "Connection reset by peer",
        "Broken pipe",
        "Interrupted system call",
        "Transport endpoint is not connected",
        "bounded node RPC response exceeded",
        "unauthenticated response",
        "incomplete HTTP response",
        "decryption failed",
        "timed out",
        "HTTP 413",
        "HTTP 503",
    ] {
        if error.contains(code) {
            return code;
        }
    }
    "stream transport failed"
}

pub async fn handle(
    req: hyper::Request<hyper::body::Incoming>,
    w: Arc<RwLock<DesiredWorld>>,
    id: Identity,
) -> hyper::Response<crate::api::BoxedBody> {
    if req.extensions().get::<SecureTransport>().is_none() || !auth::secure_user_auth() {
        return error(403, "Connect requires TLS and token authentication");
    }
    start_sweeper();
    let path = req.uri().path().to_string();
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    if req.uri().query().is_some()
        || parts.len() < 6
        || parts[..4] != ["royak", "v1", "connect", "namespaces"]
        || !store::is_dns_label(parts[4])
    {
        return error(
            400,
            "invalid Connect path; query credentials/targets are not accepted",
        );
    }
    let ns = parts[4].to_string();
    let method = req.method().as_str().to_string();
    if parts.len() == 6 && parts[5] == "audit" && method == "GET" {
        return blocking(move || {
        let world = w.read().unwrap_or_else(|e| e.into_inner());
        let r = registry().lock().unwrap_or_else(|e| e.into_inner());
        response(
            200,
            json!({"items":r.audit.iter().filter(|e|e["namespace"]==ns && (e["user"]==id.user || id.is_master() || permission(&world,&id,"get","connect-audit",&ns,&Target{service:e["service"].as_str().unwrap_or("").into(),port:e["port"].as_u64().unwrap_or(0) as u16,ttl_seconds:1}))).collect::<Vec<_>>(),"scope":"bounded current-process metadata; durable JSONL on issuer"}),
        )
        }).await;
    }
    if parts[5] != "sessions" || parts.len() > 8 {
        return error(404, "Connect route not found");
    }
    if parts.len() == 6 {
        if method == "GET" {
            return blocking(move || {
            let r = registry().lock().unwrap_or_else(|e| e.into_inner());
            response(
                200,
                json!({"items":r.sessions.values().filter(|s|s.namespace==ns && (s.owner.user==id.user || id.is_master())).map(|s|s.metadata()).collect::<Vec<_>>()}),
            )
            }).await;
        }
        if method != "POST" {
            return error(405, "method not allowed");
        }
        if !issuer_ready() {
            return error(421,"Connect issuer must be the current quorum-confirmed leader/state owner; reconnect explicitly to that issuer");
        }
        let body = match tokio::time::timeout(
            Duration::from_secs(3),
            http_body_util::Limited::new(req.into_body(), 4096).collect(),
        )
        .await
        {
            Ok(Ok(b)) => b.to_bytes(),
            _ => return error(400, "bounded Connect request required"),
        };
        let target: Target = match serde_json::from_slice(&body) {
            Ok(t) => t,
            Err(_) => return error(400, "expected service, port, ttl_seconds only"),
        };
        let (ww, ii, nn, tt) = (w.clone(), id.clone(), ns.clone(), target.clone());
        let prepared = blocking(move || {
            let world = ww.read().unwrap_or_else(|e| e.into_inner());
            if !permission(&world, &ii, "create", "connect", &nn, &tt) {
                return Err((
                    403,
                    "explicit services/connect permission required".to_string(),
                ));
            }
            let (s, _) = match target_service(&world, &nn, &tt) {
                Ok(s) => s,
                Err(e) => return Err((400, e)),
            };
            Ok((world.cluster_id.clone(), fingerprint(&s)))
        })
        .await;
        let (cluster, fp) = match prepared {
            Ok(v) => v,
            Err((c, e)) => return error(c, e),
        };
        blocking(sweep).await;
        let (stop, _) = tokio::sync::watch::channel(true); // pending durable audit; not usable yet
        let s = Arc::new(Session {
            id: random_id(),
            namespace: ns,
            target: target.clone(),
            owner: id,
            cluster,
            fingerprint: fp,
            deadline: Instant::now() + Duration::from_secs(target.ttl_seconds),
            expires: epoch() + target.ttl_seconds,
            stop,
            reason: Mutex::new(None),
            active: AtomicUsize::new(0),
        });
        let ss = s.clone();
        let admitted = blocking(move || {
            let mut r = registry().lock().unwrap_or_else(|e| e.into_inner());
            reserve_session(&mut r, ss)
        })
        .await;
        if !admitted {
            return error(429, "Connect session limit");
        }
        let ss = s.clone();
        if let Err(e) = blocking(move || audit(ss.event("created", "explicit scoped grant"))).await
        {
            let ss = s.clone();
            blocking(move || {
                registry()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .sessions
                    .remove(&ss.id);
            })
            .await;
            return error(503, e);
        }
        // Close a create racing with a committed permission/Service change.
        return blocking(move || {
            let world = w.read().unwrap_or_else(|e| e.into_inner());
            if let Some(why) = s.invalid(&world) {
                let _ = s.close(why);
                return error(403, why);
            }
            if s.reason.lock().unwrap_or_else(|e| e.into_inner()).is_some() {
                return error(410, "session revoked during creation");
            }
            s.stop.send_replace(false);
            response(201, s.metadata())
        })
        .await;
    }
    let session_id = parts[6].to_string();
    let session = blocking(move || {
        registry()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .sessions
            .get(&session_id)
            .cloned()
    })
    .await;
    let Some(s) = session.filter(|s| s.namespace == ns) else {
        return error(404, "session not found on this issuer");
    };
    let own = s.owner == id;
    if method == "DELETE" && parts.len() == 7 {
        let (ww, ss) = (w.clone(), s.clone());
        let allowed = own
            || blocking(move || {
                permission(
                    &ww.read().unwrap_or_else(|e| e.into_inner()),
                    &id,
                    "delete",
                    "connect",
                    &ss.namespace,
                    &ss.target,
                )
            })
            .await;
        if !allowed {
            return error(
                403,
                "session owner or services/connect delete permission required",
            );
        }
        return blocking(move || match s.close("revoked") {
            Ok(()) => response(200, s.metadata()),
            Err(e) => response(503, json!({"revoked":true,"error":e})),
        })
        .await;
    }
    if !own {
        return error(403, "session belongs to another authenticated identity");
    }
    if let Some(why) = invalid_session(&w, &s).await {
        let ss = s.clone();
        let _ = tokio::task::spawn_blocking(move || ss.close(why)).await;
    }
    if method == "GET" && parts.len() == 7 {
        return response(200, s.metadata());
    }
    if parts.len() != 8 || parts[7] != "stream" || method != "GET" {
        return error(405, "method not allowed");
    }
    if *s.stop.borrow() {
        return error(410, "session is closed");
    }
    if req.headers().get("upgrade").and_then(|h| h.to_str().ok()) != Some("royak-connect-v1")
        || !req
            .headers()
            .get("connection")
            .and_then(|h| h.to_str().ok())
            .map(|v| {
                v.split(',')
                    .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
            })
            .unwrap_or(false)
    {
        return error(400, "royak-connect-v1 HTTP upgrade required");
    }
    let Some(lease)=ActiveLease::acquire(&s) else{return error(429,"connection limit");};
    let backend = match backend(w.clone(), s.clone(),&lease).await {
        Ok(b) => b,
        Err(e) => {
            let invalid = active_invalid_session(&w, &s,&lease).await;
            if let Some(why) = invalid {
                let ss = s.clone();
                let _ = active_blocking(&lease,move || ss.close(why)).await;
                return error(410, "session closed during backend resolution");
            }
            if *s.stop.borrow() {
                return error(410, "session is closed");
            }
            return error(503, e);
        }
    };
    let ss = s.clone();
    if let Err(e) = active_blocking(&lease,move || audit(ss.event("connection-open", "TCP"))).await {
        backend.close().await;
        return error(503, e);
    }
    let stopped_before_check = *s.stop.borrow();
    let no_longer_valid = stopped_before_check || active_invalid_session(&w, &s,&lease).await.is_some();
    if no_longer_valid {
        backend.close().await;
        return error(410, "session closed during backend resolution");
    }
    let mut stopped = s.stop.subscribe();
    tokio::spawn(async move {
        let lease=lease;
        let mut close_reason = "HTTP upgrade failed";
        if let Ok(io) = hyper::upgrade::on(req).await {
            close_reason = "TCP closed";
            let mut io = hyper_util::rt::TokioIo::new(io);
            let mut check = tokio::time::interval(Duration::from_millis(100));
            let transfer = backend.copy(&mut io);
            tokio::pin!(transfer);
            loop {
                tokio::select! {
                    result=&mut transfer=>{
                        if let Err(error)=result { close_reason=transport_error_code(&error); }
                        break;
                    },
                    _=stopped.changed()=>break,
                    _=check.tick()=>{
                        if *stopped.borrow(){break;}
                        // Reconcile can hold the world lock while inspecting Docker.
                        // Never park async/Raft workers waiting for that lock. The
                        // committed-state hook revokes rights/Service changes even
                        // while a reader cannot acquire it; TTL/quorum are lock-free.
                        let why=if Instant::now()>=s.deadline {Some("expired")}
                            else if !issuer_ready(){Some("issuer lost authoritative state/quorum leadership")}
                            else {match w.try_read(){
                                Ok(world)=>s.invalid(&world),
                                Err(std::sync::TryLockError::WouldBlock)=>None,
                                Err(std::sync::TryLockError::Poisoned(_))=>Some("state inspection failed"),
                            }};
                        if let Some(why)=why {
                            let ss=s.clone();
                            let closing_worker=lease.hold();
                            tokio::task::spawn_blocking(move||{let _worker=closing_worker;let _=ss.close(why);});
                            break;
                        }
                    }
                }
            }
        }
        backend.close().await;
        let _ = active_blocking(&lease,move || audit(s.event("connection-close", close_reason))).await;
    });
    hyper::Response::builder()
        .status(101)
        .header("Connection", "Upgrade")
        .header("Upgrade", "royak-connect-v1")
        .body(http_body_util::Full::new(bytes::Bytes::new()).boxed())
        .unwrap()
}

fn local_endpoint(w: &DesiredWorld, ns: &str, t: &Target) -> Result<String, String> {
    let (svc, port) = target_service(w, ns, t)?;
    let owner = &svc.selector["app"];
    let all = crate::docker::list_containers(false)?;
    let ours = crate::reconcile::our_containers(w, &all);
    for v in crate::reconcile::local_views(w, &ours) {
        if v.namespace != ns || &v.owner != owner || !v.ready {
            continue;
        }
        if let Some(c) = ours.iter().find(|c| {
            c.labels.get(store::LABEL_POD) == Some(&v.pod)
                && c.labels
                    .get(store::LABEL_ROLE)
                    .map(|s| s == "main")
                    .unwrap_or(true)
        }) {
            if cfg!(target_os = "linux") {
                return crate::docker::container_ip(&c.id).map(|ip| format!("{ip}:{port}"));
            }
            return crate::docker::container_host_port(&c.id, port)
                .map(|p| format!("127.0.0.1:{p}"))
                .ok_or("backend port is not reachable from this host".into());
        }
    }
    Err("no local Ready backend".into())
}
fn wireguard(node: &str) -> Result<(String, String), String> {
    let iface = std::env::var("ROYAK_CONNECT_WG_INTERFACE")
        .map_err(|_| "Connect WireGuard interface not configured")?;
    if iface.is_empty()
        || iface.len() > 15
        || !iface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("invalid WireGuard interface".into());
    }
    let out = std::process::Command::new("ip")
        .args(["-j", "-d", "link", "show", "dev", &iface])
        .output()
        .map_err(|_| "WireGuard interface inspection unavailable")?;
    let info: Value =
        serde_json::from_slice(&out.stdout).map_err(|_| "WireGuard interface unavailable")?;
    if !out.status.success()
        || info[0]["linkinfo"]["info_kind"] != "wireguard"
        || !info[0]["flags"]
            .as_array()
            .map(|a| a.iter().any(|f| f == "UP"))
            .unwrap_or(false)
    {
        return Err("configured interface is not an active kernel WireGuard interface".into());
    }
    let peers: BTreeMap<String, String> = serde_json::from_str(
        &std::env::var("ROYAK_CONNECT_WG_PEERS").map_err(|_| "WireGuard peer map missing")?,
    )
    .map_err(|_| "invalid WireGuard peer map")?;
    let addr = peers
        .get(node)
        .ok_or("no pinned WireGuard address for backend node")?
        .clone();
    let socket: std::net::SocketAddr = addr
        .parse()
        .map_err(|_| "numeric WireGuard peer address required")?;
    if !matches!(socket.ip(),std::net::IpAddr::V4(ip) if ip.is_private()) || socket.port() == 0 {
        return Err("private IPv4 WireGuard peer address required".into());
    }
    Ok((iface, addr))
}
pub fn validate_node_transport(
    signer: &str,
    transport: Option<&PeerTransport>,
) -> Result<(), String> {
    let transport = transport.ok_or("Connect peer transport unavailable")?;
    let (iface, addr) = wireguard(signer)?;
    let peer: std::net::SocketAddr = addr.parse().map_err(|_| "invalid peer")?;
    if transport.remote != peer.ip() {
        return Err(
            "Connect node request did not originate on its pinned WireGuard address".into(),
        );
    }
    let out = std::process::Command::new("ip")
        .args(["-j", "address", "show", "dev", &iface])
        .output()
        .map_err(|_| "WireGuard address inspection unavailable")?;
    let interfaces: Value =
        serde_json::from_slice(&out.stdout).map_err(|_| "WireGuard address unavailable")?;
    let matches = interfaces[0]["addr_info"]
        .as_array()
        .map(|a| {
            a.iter().any(|v| {
                v["local"]
                    .as_str()
                    .and_then(|ip| ip.parse::<std::net::IpAddr>().ok())
                    == Some(transport.local)
            })
        })
        .unwrap_or(false);
    if !out.status.success() || !matches {
        return Err("Connect node endpoint must be reached via its WireGuard address".into());
    }
    Ok(())
}
async fn remote_call(iface: &str, addr: &str, action: &str, body: Value) -> Result<Value, String> {
    let bytes = crate::node_rpc::call_async_bound(
        "POST",
        addr,
        &format!("/royak/v1/connect/node/{action}"),
        body.to_string().as_bytes(),
        Duration::from_secs(2),
        Some(iface),
    )
    .await?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid Connect peer response".into())
}
enum Backend {
    Local(tokio::sync::Mutex<tokio::net::TcpStream>),
    Remote {
        iface: String,
        addr: String,
        id: String,
    },
}
impl Backend {
    async fn close(&self) {
        if let Self::Remote { iface, addr, id } = self {
            let _ = remote_call(iface, addr, "close", json!({"id":id})).await;
        }
    }
    async fn copy<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        &self,
        io: &mut S,
    ) -> Result<(), String> {
        match self {
            Self::Local(socket) => {
                tokio::io::copy_bidirectional(io, &mut *socket.lock().await)
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(())
            }
            Self::Remote { iface, addr, id } => {
                let mut sequence = 0u64;
                let mut eof = false;
                let mut buf = [0; CHUNK];
                loop {
                    let size = if eof {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        0
                    } else {
                        match tokio::time::timeout(Duration::from_millis(20), io.read(&mut buf))
                            .await
                        {
                            Ok(Ok(0)) => {
                                eof = true;
                                0
                            }
                            Ok(Ok(n)) => n,
                            Ok(Err(e)) => return Err(e.to_string()),
                            Err(_) => 0,
                        }
                    };
                    let reply = remote_call(
                        iface,
                        addr,
                        "exchange",
                        json!({"id":id,"sequence":sequence,"data":encode(&buf[..size]),"eof":eof}),
                    )
                    .await?;
                    sequence += 1;
                    let data = decode(reply["data"].as_str().ok_or("invalid peer frame")?)?;
                    io.write_all(&data).await.map_err(|e| e.to_string())?;
                    io.flush().await.map_err(|e| e.to_string())?;
                    if reply["eof"] == true {
                        io.shutdown().await.map_err(|e| e.to_string())?;
                        return Ok(());
                    }
                }
            }
        }
    }
}
async fn backend(w: Arc<RwLock<DesiredWorld>>, s: Arc<Session>,lease:&ActiveLease) -> Result<Backend, String> {
    let ww = w.clone();
    let ss = s.clone();
    let local = active_job(lease,move || {
        local_endpoint(
            &ww.read().unwrap_or_else(|e| e.into_inner()),
            &ss.namespace,
            &ss.target,
        )
    })
    .await
    .map_err(|_| "backend lookup failed")?;
    if let Ok(addr) = local {
        let socket = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect(&addr),
        )
        .await
        .map_err(|_| "backend connect timeout")?
        .map_err(|_| "backend unavailable")?;
        return Ok(Backend::Local(tokio::sync::Mutex::new(socket)));
    }
    let (ww, ss) = (w.clone(), s.clone());
    let owner = active_blocking(lease,move || {
        ww.read()
            .unwrap_or_else(|e| e.into_inner())
            .services
            .get(&store::obj_key(&ss.namespace, &ss.target.service))
            .and_then(|x| x.selector.get("app"))
            .cloned()
            .ok_or("Service disappeared")
    })
    .await?;
    let node = crate::placement::peer_reports()
        .into_iter()
        .find(|p| {
            p.at.elapsed() < crate::placement::CENSUS_MAX_AGE
                && p.pods.iter().any(|v| {
                    v.namespace == s.namespace && v.owner == owner && v.ready && !v.pending
                })
        })
        .map(|p| p.node)
        .ok_or("no Ready Service backend")?;
    let (iface, addr) = active_job(lease,move || wireguard(&node))
        .await
        .map_err(|_| "WireGuard lookup failed")??;
    // The issuer enforces the precise deadline. Rounding the remote budget down
    // would kill a healthy stream up to one second before that deadline.
    let ttl = remaining_ttl(s.deadline, Instant::now()).ok_or("expired")?;
    let reply=remote_call(&iface,&addr,"open",json!({"namespace":s.namespace,"target":Target{ttl_seconds:ttl,..s.target.clone()},"fingerprint":s.fingerprint})).await?;
    Ok(Backend::Remote {
        iface,
        addr,
        id: reply["id"].as_str().ok_or("invalid remote handle")?.into(),
    })
}

fn remaining_ttl(deadline: Instant, now: Instant) -> Option<u64> {
    let remaining = deadline.saturating_duration_since(now);
    if remaining.is_zero() {
        None
    } else {
        Some(remaining.as_secs() + u64::from(remaining.subsec_nanos() != 0))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteOpen {
    namespace: String,
    target: Target,
    fingerprint: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Exchange {
    id: String,
    sequence: u64,
    data: String,
    eof: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handle {
    id: String,
}
pub fn node_request(
    method: &str,
    path: &str,
    body: &[u8],
    w: &Arc<RwLock<DesiredWorld>>,
    signer: &str,
) -> (u16, String) {
    start_sweeper();
    let result = (|| -> Result<Value, String> {
        if method != "POST" || body.len() > CHUNK * 2 + 4096 {
            return Err("invalid bounded Connect peer request".into());
        }
        sweep();
        match path.rsplit('/').next().unwrap_or("") {
            "open" => {
                let q: RemoteOpen =
                    serde_json::from_slice(body).map_err(|_| "invalid peer target")?;
                let world = w.read().unwrap_or_else(|e| e.into_inner());
                let (svc, _) = target_service(&world, &q.namespace, &q.target)?;
                if fingerprint(&svc) != q.fingerprint {
                    return Err("Service differs on backend node".into());
                }
                let endpoint = local_endpoint(&world, &q.namespace, &q.target)?;
                drop(world);
                let socket = TcpStream::connect_timeout(
                    &endpoint.parse().map_err(|_| "invalid local endpoint")?,
                    Duration::from_secs(2),
                )
                .map_err(|_| "backend unavailable")?;
                socket
                    .set_read_timeout(Some(Duration::from_millis(5)))
                    .map_err(|e| e.to_string())?;
                socket
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .map_err(|e| e.to_string())?;
                let id = random_id();
                let r = Arc::new(Remote {
                    origin: signer.into(),
                    namespace: q.namespace,
                    target: q.target.clone(),
                    fingerprint: q.fingerprint,
                    deadline: Instant::now() + Duration::from_secs(q.target.ttl_seconds),
                    lease: Mutex::new(Instant::now() + Duration::from_secs(3)),
                    socket: Mutex::new((socket, 0, false)),
                });
                let mut registry = registry().lock().unwrap_or_else(|e| e.into_inner());
                if registry.remote.len() >= 128 {
                    return Err("remote connection limit".into());
                }
                registry.remote.insert(id.clone(), r);
                Ok(json!({"id":id}))
            }
            "exchange" => {
                let q: Exchange = serde_json::from_slice(body).map_err(|_| "invalid peer frame")?;
                let data = decode(&q.data)?;
                let r = registry()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remote
                    .get(&q.id)
                    .cloned()
                    .ok_or("remote handle closed")?;
                if r.origin != signer
                    || Instant::now() >= r.deadline
                    || Instant::now() >= *r.lease.lock().unwrap_or_else(|e| e.into_inner())
                {
                    return Err("remote lease invalid".into());
                }
                let world = w.read().unwrap_or_else(|e| e.into_inner());
                if target_service(&world, &r.namespace, &r.target)
                    .map(|(s, _)| fingerprint(&s) != r.fingerprint)
                    .unwrap_or(true)
                {
                    return Err("remote Service changed".into());
                }
                drop(world);
                let mut socket = r.socket.lock().unwrap_or_else(|e| e.into_inner());
                if socket.1 != q.sequence || socket.2 && !data.is_empty() {
                    return Err("out-of-order or replayed stream frame".into());
                }
                socket.1 += 1;
                *r.lease.lock().unwrap_or_else(|e| e.into_inner()) =
                    Instant::now() + Duration::from_secs(3);
                if let Err(e) = socket.0.write_all(&data) {
                    let _ = socket.0.shutdown(Shutdown::Both);
                    return Err(format!("backend write failed; no retry: {e}"));
                }
                if q.eof && !socket.2 {
                    socket
                        .0
                        .shutdown(Shutdown::Write)
                        .map_err(|e| e.to_string())?;
                    socket.2 = true;
                }
                let mut buf = [0; CHUNK];
                let (size, eof) = read_backend(&mut socket.0, &mut buf)?;
                Ok(json!({"data":encode(&buf[..size]),"eof":eof}))
            }
            "close" => {
                let q: Handle = serde_json::from_slice(body).map_err(|_| "invalid handle")?;
                let mut r = registry().lock().unwrap_or_else(|e| e.into_inner());
                if r.remote
                    .get(&q.id)
                    .map(|x| x.origin != signer)
                    .unwrap_or(false)
                {
                    return Err("remote owner mismatch".into());
                }
                if let Some(c) = r.remote.remove(&q.id) {
                    let _ = c
                        .socket
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .0
                        .shutdown(Shutdown::Both);
                }
                Ok(json!({"closed":true}))
            }
            _ => Err("unknown Connect node operation".into()),
        }
    })();
    match result {
        Ok(v) => (200, v.to_string()),
        Err(e) => (503, json!({"error":e}).to_string()),
    }
}

fn read_backend(reader: &mut impl Read, buf: &mut [u8]) -> Result<(usize, bool), String> {
    match reader.read(buf) {
        Ok(0) => Ok((0, true)),
        Ok(n) => Ok((n, false)),
        // A timed socket read can be interrupted by a signal (e.g. child
        // completion during interface checks). The frame's bytes have already
        // been written exactly once. Return an empty non-EOF frame and let the
        // next exchange read pending bytes; never replay the write or extend
        // the existing read timeout with an unbounded EINTR retry loop.
        Err(error) if matches!(error.kind(), std::io::ErrorKind::Interrupted |
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => Ok((0, false)),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    include!("connect_reservation_tests.rs");
    use super::*;
    #[test]
    fn interrupted_backend_read_is_not_eof_and_retains_pending_bytes() {
        struct InterruptedOnce { first: bool, data: std::io::Cursor<Vec<u8>> }
        impl Read for InterruptedOnce {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if self.first { self.first = false; return Err(std::io::ErrorKind::Interrupted.into()); }
                std::io::Read::read(&mut self.data, out)
            }
        }
        let mut reader = InterruptedOnce { first: true, data: std::io::Cursor::new(vec![0, 1, 255, 42]) };
        let mut out = [0; 16];
        assert_eq!(read_backend(&mut reader, &mut out).unwrap(), (0, false));
        assert_eq!(read_backend(&mut reader, &mut out).unwrap(), (4, false));
        assert_eq!(&out[..4], &[0, 1, 255, 42]);
        assert_eq!(read_backend(&mut reader, &mut out).unwrap(), (0, true));
    }
    #[test]
    fn idle_backend_timeouts_stay_open_but_real_errors_fail() {
        struct ErrorReader(std::io::ErrorKind);
        impl Read for ErrorReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> { Err(self.0.into()) }
        }
        for kind in [std::io::ErrorKind::WouldBlock, std::io::ErrorKind::TimedOut] {
            assert_eq!(read_backend(&mut ErrorReader(kind), &mut [0; 8]).unwrap(), (0, false));
        }
        assert!(read_backend(&mut ErrorReader(std::io::ErrorKind::ConnectionReset), &mut [0; 8]).is_err());
    }
    #[test]
    fn transport_audit_keeps_only_fixed_error_codes() {
        assert_eq!(
            transport_error_code("10.0.0.1:443: HTTP 503: private-payload remote lease invalid"),
            "remote lease invalid"
        );
        assert_eq!(
            transport_error_code("private-token private-payload"),
            "stream transport failed"
        );
    }
    fn session_for_test(id: usize, user: usize) -> Arc<Session> {
        let (stop, _) = tokio::sync::watch::channel(false);
        Arc::new(Session {
            id: id.to_string(),
            namespace: "team".into(),
            target: Target {
                service: "api".into(),
                port: 80,
                ttl_seconds: 900,
            },
            owner: Identity {
                user: format!("user{user}"),
                groups: vec![],
            },
            cluster: "test".into(),
            fingerprint: "test".into(),
            deadline: Instant::now() + Duration::from_secs(900),
            expires: epoch() + 900,
            stop,
            reason: Mutex::new(None),
            active: AtomicUsize::new(0),
        })
    }
    #[test]
    fn closed_session_churn_cannot_exhaust_global_admission() {
        let mut r = Registry::default();
        for n in 0..MAX_SESSIONS * 3 {
            let session = session_for_test(n, 0);
            assert!(
                reserve_session(&mut r, session.clone()),
                "closed history blocked grant {n}"
            );
            *session.reason.lock().unwrap() = Some("revoked".into());
            session.stop.send_replace(true);
            assert!(r.sessions.len() <= MAX_SESSIONS);
        }
    }
    #[test]
    fn pending_session_grants_still_enforce_the_user_limit() {
        let mut r = Registry::default();
        for n in 0..16 {
            let session = session_for_test(n, 0);
            session.stop.send_replace(true);
            assert!(reserve_session(&mut r, session));
        }
        assert!(!reserve_session(&mut r, session_for_test(17, 0)));
    }
    #[test]
    fn global_limit_preserves_live_and_still_closing_connections() {
        let mut r = Registry::default();
        for n in 0..MAX_SESSIONS {
            assert!(reserve_session(&mut r, session_for_test(n, n / 16)));
        }
        let extra = session_for_test(MAX_SESSIONS, MAX_SESSIONS);
        assert!(!reserve_session(&mut r, extra.clone()));
        let closing = r.sessions["0"].clone();
        *closing.reason.lock().unwrap() = Some("revoked".into());
        closing.active.store(1, Ordering::SeqCst);
        assert!(!reserve_session(&mut r, extra.clone()));
        closing.active.store(0, Ordering::SeqCst);
        assert!(reserve_session(&mut r, extra));
        assert_eq!(r.sessions.len(), MAX_SESSIONS);
    }
    #[test]
    fn remote_budget_never_rounds_a_live_session_down_to_expired() {
        let now = Instant::now();
        assert_eq!(remaining_ttl(now, now), None);
        assert_eq!(remaining_ttl(now, now + Duration::from_nanos(1)), None);
        assert_eq!(remaining_ttl(now + Duration::from_nanos(1), now), Some(1));
        assert_eq!(remaining_ttl(now + Duration::from_secs(5), now), Some(5));
        assert_eq!(
            remaining_ttl(now + Duration::from_millis(4999), now),
            Some(5)
        );
    }
    #[test]
    fn bounded_frames_are_binary_safe() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
        for s in ["a", "gg"] {
            assert!(decode(s).is_err());
        }
        assert!(decode(&"00".repeat(CHUNK + 1)).is_err());
    }
    #[test]
    fn service_fingerprint_is_canonical() {
        let mut a = StoredService {
            name: "web".into(),
            namespace: "team".into(),
            selector: HashMap::new(),
            ports: vec![],
            service_type: "ClusterIP".into(),
        };
        a.selector.insert("z".into(), "1".into());
        a.selector.insert("a".into(), "2".into());
        let mut b = a.clone();
        b.selector = HashMap::from([("a".into(), "2".into()), ("z".into(), "1".into())]);
        assert_eq!(fingerprint(&a), fingerprint(&b));
        b.namespace = "other".into();
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }
    #[test]
    fn targets_refuse_ambient_addresses_and_lifetimes() {
        let w = DesiredWorld::new();
        for ttl in [0, 901] {
            assert!(target_service(
                &w,
                "team",
                &Target {
                    service: "web".into(),
                    port: 80,
                    ttl_seconds: ttl
                }
            )
            .is_err());
        }
        assert!(serde_json::from_str::<Target>(
            r#"{"service":"web","port":80,"ttl_seconds":60,"host":"127.0.0.1"}"#
        )
        .is_err());
    }
}
