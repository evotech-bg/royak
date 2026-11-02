//! Docker Engine API client — talks to /var/run/docker.sock
//!
//! This is the ONLY interface to the container runtime.
//! Everything else (scheduling, scaling, healing) is our logic on top.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

#[cfg(test)]
#[path="docker/exec_regressions.rs"]
mod exec_start_lifecycle_regressions;
#[cfg(test)]
#[path = "docker/exec_transport_regressions.rs"]
mod exec_transport_regressions;

#[path = "docker/exec_admission.rs"]
mod exec_admission;
pub use exec_admission::AdmittedStream as ExecStream;
pub(crate) fn exec_admission_unknown(error: &str) -> bool { exec_admission::is_unknown(error) }
pub(crate) use exec_admission::RecoveryAgent;
pub(crate) use exec_admission::VerifiedDaemonNamespace;
pub(crate) use exec_admission::ManagedConsumerConnection;
#[path="docker/managed_container.rs"]
pub(crate) mod managed;
pub(crate) fn open_managed_consumer(peer:&VerifiedDaemonNamespace,deadline:std::time::Instant)
    ->Result<ManagedConsumerConnection,String>{peer.consumer_connection(deadline)}
/// Read-only actual-sender namespace pin. Not container or mount authority.
pub(crate) fn inspect_managed_mount_daemon(deadline:std::time::Instant)->Result<VerifiedDaemonNamespace,String> {
    let socket=match std::env::var("DOCKER_HOST") {
        Ok(host)=>host.strip_prefix("unix://").filter(|p|p.starts_with('/'))
            .ok_or("managed mounts refuse remote/non-Unix Docker selectors")?.to_string(),
        Err(std::env::VarError::NotPresent)=>DOCKER_SOCK.to_string(),
        Err(_)=>return Err("invalid Docker selector; no mount fallback".into()),
    };
    exec_admission::VerifiedDaemonNamespace::admit(&socket,deadline)
}
pub(crate) fn start_exec_recovery(cluster: String, node: String) -> Result<RecoveryAgent, String> {
    exec_admission::start_node_agent(cluster, node)
}
pub(crate) fn diagnostic_recovery_ready() -> bool { exec_admission::recovery_ready() }
pub(crate) fn diagnostic_recovery_usage() -> serde_json::Value { exec_admission::recovery_usage() }

const DOCKER_SOCK: &str = "/var/run/docker.sock";

/// EINTR means no bytes were consumed by this read. Continue on the SAME
/// socket; never replay a Docker operation or hide other transport errors.
fn read_uninterrupted(reader: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    loop {
        match reader.read(buf) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

/// Socket path resolution: DOCKER_HOST (unix:// only) wins, else /var/run/docker.sock.
/// Colima, OrbStack and rootless Docker all set DOCKER_HOST to a per-user socket.
fn docker_sock() -> String {
    if let Ok(host) = std::env::var("DOCKER_HOST") {
        if let Some(path) = host.strip_prefix("unix://") {
            return path.to_string();
        }
    }
    DOCKER_SOCK.to_string()
}

/// Raw HTTP request over Unix socket
fn docker_request(method: &str, path: &str, body: Option<&str>) -> Result<String, String> {
    let mut stream = UnixStream::connect(docker_sock())
        .map_err(|e| format!("Cannot connect to Docker: {e}. Is Docker running?"))?;

    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();

    let content_length = body.map(|b| b.len()).unwrap_or(0);
    let request = if let Some(b) = body {
        format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {content_length}\r\n\
             \r\n{b}"
        )
    } else {
        format!(
            "{method} {path} HTTP/1.1\r\n\
             Host: localhost\r\n\
             \r\n"
        )
    };

    stream.write_all(request.as_bytes()).map_err(|e| format!("Write failed: {e}"))?;

    let mut response = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match read_uninterrupted(&mut stream, &mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(format!("Read failed: {e}")),
        }
        // Check if we've received the full response
        if response.windows(4).any(|w| w == b"\r\n\r\n") && !response.is_empty() {
            // Give it a tiny bit more time for body
            stream.set_read_timeout(Some(Duration::from_millis(100))).ok();
        }
    }

    let resp_str = String::from_utf8_lossy(&response).to_string();

    // Extract body from HTTP response
    if let Some(pos) = resp_str.find("\r\n\r\n") {
        let body = &resp_str[pos + 4..];
        // Handle chunked transfer encoding
        if resp_str.contains("Transfer-Encoding: chunked") {
            Ok(parse_chunked(body))
        } else {
            Ok(body.to_string())
        }
    } else {
        Ok(resp_str)
    }
}

/// Read one HTTP/1.1 response, stopping when the message is complete
/// (Content-Length reached, or the chunked terminator seen) instead of waiting
/// for the peer to close the connection — dockerd does not always close
/// promptly, and waiting for EOF stalled a reconcile tick for the whole read
/// timeout (60s).
fn read_http_response(stream: &mut impl Read) -> Result<(u16, String), String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 16384];
    let complete = |buf: &[u8]| -> bool {
        let Some(hpos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { return false };
        let head = String::from_utf8_lossy(&buf[..hpos]).to_ascii_lowercase();
        let body = &buf[hpos + 4..];
        if let Some(len) = head.lines().find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())) {
            return body.len() >= len;
        }
        if head.contains("transfer-encoding: chunked") {
            return body.ends_with(b"0\r\n\r\n");
        }
        // 204/304 or a status line only: no body follows.
        head.starts_with("http/1.1 204") || head.starts_with("http/1.1 304")
    };
    loop {
        if complete(&buf) { break; }
        match read_uninterrupted(stream, &mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) => return Err(format!("read failed: {e}")),
        }
    }
    let resp_str = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = resp_str.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = match resp_str.find("\r\n\r\n") {
        Some(pos) => {
            let raw = &resp_str[pos + 4..];
            if resp_str[..pos].to_ascii_lowercase().contains("transfer-encoding: chunked") { parse_chunked(raw) } else { raw.to_string() }
        }
        None => String::new(),
    };
    Ok((status, body))
}

/// Like `docker_request`, but fails on an HTTP error status (>= 400) instead
/// of returning the error body as if it were a success.
fn docker_request_checked(method: &str, path: &str, body: Option<&str>) -> Result<String, String> {
    let mut stream = UnixStream::connect(docker_sock())
        .map_err(|e| format!("Cannot connect to Docker: {e}. Is Docker running?"))?;
    stream.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let b = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{b}",
        b.len());
    stream.write_all(request.as_bytes()).map_err(|e| format!("Write failed: {e}"))?;
    let (status, body) = read_http_response(&mut stream).map_err(|e| format!("docker {method} {path}: {e}"))?;
    if status >= 400 || status == 0 {
        let msg = serde_json::from_str::<serde_json::Value>(&body).ok()
            .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| body.trim().to_string());
        return Err(format!("docker {method} {path}: HTTP {status}: {msg}"));
    }
    Ok(body)
}

/// Start a container, failing on any Docker error.
pub fn start_container_checked(id: &str) -> Result<(), String> {
    exec_admission::LegacyContainerConnection::prepare(id,std::time::Instant::now()+Duration::from_secs(60))?.start()
}

/// Connect a container to a network with DNS aliases, failing on any error.
pub fn connect_to_network_checked(container_id: &str, network: &str, aliases: &[&str]) -> Result<(), String> {
    exec_admission::LegacyContainerConnection::prepare(container_id,std::time::Instant::now()+Duration::from_secs(60))?.connect(network,aliases)
}

/// Exit code of a stopped container (None if it is still running or unknown).
pub fn container_exit_code(id: &str) -> Option<i64> {
    let body = docker_request_checked("GET", &format!("/containers/{id}/json"), None).ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    if v["State"]["Running"].as_bool() == Some(true) { return None; }
    v["State"]["ExitCode"].as_i64()
}

fn parse_chunked(data: &str) -> String {
    let mut result = String::new();
    let mut remaining = data;

    loop {
        // Read chunk size
        if let Some(pos) = remaining.find("\r\n") {
            let size_str = &remaining[..pos];
            let size = usize::from_str_radix(size_str.trim(), 16).unwrap_or(0);
            if size == 0 { break; }

            remaining = &remaining[pos + 2..];
            if remaining.len() >= size {
                result.push_str(&remaining[..size]);
                remaining = &remaining[size..];
                if remaining.starts_with("\r\n") {
                    remaining = &remaining[2..];
                }
            } else {
                result.push_str(remaining);
                break;
            }
        } else {
            result.push_str(remaining);
            break;
        }
    }
    result
}

// ─── Public API ───

/// Container info from Docker
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DockerContainer {
    #[serde(rename = "Id")]
    pub id: String,
    #[serde(rename = "Names")]
    pub names: Vec<String>,
    #[serde(rename = "Image")]
    pub image: String,
    #[serde(rename = "State")]
    pub state: String,
    #[serde(rename = "Status")]
    pub status: String,
    #[serde(rename = "Labels", default)]
    pub labels: std::collections::HashMap<String, String>,
    #[serde(rename = "Ports", default)]
    pub ports: Vec<DockerPort>,
}

#[derive(Debug, Clone, Default, serde::Deserialize, serde::Serialize)]
pub struct DockerPort {
    #[serde(rename = "PrivatePort", default)]
    pub private_port: u16,
    #[serde(rename = "PublicPort")]
    pub public_port: Option<u16>,
    #[serde(rename = "Type", default)]
    pub kind: String,
}

impl DockerContainer {
    /// Container TCP ports bound to a host port (sorted, deduplicated —
    /// Docker lists IPv4 and IPv6 bindings separately).
    pub fn published_ports(&self) -> Vec<u16> {
        let mut out: Vec<u16> = self.ports.iter()
            .filter(|p| p.public_port.is_some() && (p.kind.is_empty() || p.kind == "tcp"))
            .map(|p| p.private_port)
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }
}

/// List all containers
pub fn list_containers(all: bool) -> Result<Vec<DockerContainer>, String> {
    let path = if all { "/containers/json?all=true" } else { "/containers/json" };
    let body = docker_request("GET", path, None)?;
    serde_json::from_str(&body).map_err(|e| format!("Parse error: {e}\nBody: {}", &body[..200.min(body.len())]))
}

/// Create a container (with optional volume mounts)
pub fn create_container(name: &str, image: &str, cmd: Option<&[&str]>, env: &[String], labels: &[(&str, &str)]) -> Result<String, String> {
    create_container_with_limits(name, image, cmd, env, labels, &[], None, None)
}

/// Create a container with volume mounts (no resource limits)
#[allow(dead_code)]
pub fn create_container_with_volumes(name: &str, image: &str, cmd: Option<&[&str]>, env: &[String], labels: &[(&str, &str)], volumes: &[(String, String)]) -> Result<String, String> {
    create_container_with_limits(name, image, cmd, env, labels, volumes, None, None)
}

/// Create a container with volume mounts and optional resource limits
pub fn create_container_with_limits(name: &str, image: &str, cmd: Option<&[&str]>, env: &[String], labels: &[(&str, &str)], volumes: &[(String, String)], cpu_limit: Option<f32>, mem_limit_mb: Option<u64>) -> Result<String, String> {
    create_container_full(name, image, cmd, env, labels, volumes, cpu_limit, mem_limit_mb, &[])
}

/// Create a container, optionally publishing container ports to ephemeral host
/// ports (HostPort "0" — Docker picks). The ServiceLB proxy discovers the
/// ephemeral port via `container_host_port` and forwards NodePort traffic to it,
/// which works even where container IPs are not host-routable (macOS VMs).
#[allow(clippy::too_many_arguments)]
pub fn create_container_full(name: &str, image: &str, cmd: Option<&[&str]>, env: &[String], labels: &[(&str, &str)], volumes: &[(String, String)], cpu_limit: Option<f32>, mem_limit_mb: Option<u64>, publish_ports: &[u16]) -> Result<String, String> {
    create_container_secured(name, image, cmd, env, labels, volumes, cpu_limit, mem_limit_mb, publish_ports, None, false)
}

#[allow(clippy::too_many_arguments)]
pub fn create_container_secured(name: &str, image: &str, cmd: Option<&[&str]>, env: &[String], labels: &[(&str, &str)], volumes: &[(String, String)], cpu_limit: Option<f32>, mem_limit_mb: Option<u64>, publish_ports: &[u16], security: Option<&crate::security::SecurityContext>, probe_init: bool) -> Result<String, String> {
    managed::reject_legacy_create(name,labels,volumes)?;
    // Build JSON safely via serde_json (no string interpolation = no injection)
    let mut body_obj = serde_json::json!({"Image": image});
    if let Some(c) = cmd {
        body_obj["Cmd"] = serde_json::json!(c);
    }
    if !env.is_empty() {
        body_obj["Env"] = serde_json::json!(env);
    }
    if !labels.is_empty() {
        let label_map: serde_json::Map<String, serde_json::Value> = labels.iter()
            .map(|(k, v)| (k.to_string(), serde_json::json!(v)))
            .collect();
        body_obj["Labels"] = serde_json::Value::Object(label_map);
    }
    let mut host_config = serde_json::Map::new();
    configure_probe_init(&mut host_config, probe_init);
    if let Some(security) = security {
        security.validate()?;
        let image_user = if security.needs_image_user() {
            let raw = docker_request("GET", &format!("/images/{image}/json"), None)?;
            let value: serde_json::Value = serde_json::from_str(&raw).map_err(|e| format!("image user metadata: {e}"))?;
            value.get("Config").ok_or("image metadata has no Config")?
                .get("User").and_then(|v| v.as_str()).unwrap_or("").to_string()
        } else { String::new() };
        let (user, options) = security.docker_options(&image_user)?;
        if let Some(user) = user { body_obj["User"] = serde_json::json!(user); }
        host_config.extend(options);
    }
    if !volumes.is_empty() {
        let binds: Vec<String> = volumes.iter().map(|(h, c)| format!("{h}:{c}")).collect();
        host_config.insert("Binds".to_string(), serde_json::json!(binds));
    }
    if let Some(cpu) = cpu_limit {
        host_config.insert("NanoCpus".to_string(), serde_json::json!((cpu * 1_000_000_000.0) as u64));
    }
    if let Some(mb) = mem_limit_mb {
        host_config.insert("Memory".to_string(), serde_json::json!(mb * 1024 * 1024));
    }
    if !publish_ports.is_empty() {
        let mut exposed = serde_json::Map::new();
        let mut bindings = serde_json::Map::new();
        for p in publish_ports {
            let key = format!("{p}/tcp");
            exposed.insert(key.clone(), serde_json::json!({}));
            bindings.insert(key, serde_json::json!([{"HostPort": "0"}]));
        }
        body_obj["ExposedPorts"] = serde_json::Value::Object(exposed);
        host_config.insert("PortBindings".to_string(), serde_json::Value::Object(bindings));
    }
    body_obj["HostConfig"] = serde_json::Value::Object(host_config);

    let body = body_obj.to_string();
    let resp = docker_request("POST", &format!("/containers/create?name={name}"), Some(&body))?;

    // Extract container ID from response
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp) {
        if let Some(id) = v.get("Id").and_then(|v| v.as_str()) {
            return Ok(id.to_string());
        }
        if let Some(msg) = v.get("message").and_then(|v| v.as_str()) {
            return Err(msg.to_string());
        }
    }
    Err(format!("Unexpected response: {resp}"))
}

/// A shell cannot reap arbitrary grandchildren killed by a hard probe deadline.
/// Docker's minimal PID-1 init adopts them; failure to provide it must fail the
/// container create/start, never silently fall back to application PID 1.
fn configure_probe_init(host_config: &mut serde_json::Map<String, serde_json::Value>, enabled: bool) {
    if enabled { host_config.insert("Init".into(), serde_json::json!(true)); }
}

/// Resolve the ephemeral host port Docker assigned to `container_port` on a
/// running container. Returns None if the port is not published.
pub fn container_host_port(id_or_name: &str, container_port: u16) -> Option<u16> {
    let body = docker_request("GET", &format!("/containers/{id_or_name}/json"), None).ok()?;
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    v["NetworkSettings"]["Ports"][format!("{container_port}/tcp")]
        .as_array()?
        .first()?
        .get("HostPort")?
        .as_str()?
        .parse::<u16>()
        .ok()
}

/// Start a container
pub fn start_container(id: &str) -> Result<(), String> {
    exec_admission::LegacyContainerConnection::prepare(id,std::time::Instant::now()+Duration::from_secs(30))?.start()
}

/// Stop a container
pub fn stop_container(id: &str) -> Result<(), String> {
    exec_admission::LegacyContainerConnection::prepare(id,std::time::Instant::now()+Duration::from_secs(30))?.stop()
}

/// Remove a container
pub fn remove_container(id: &str, force: bool) -> Result<(), String> {
    exec_admission::LegacyContainerConnection::prepare(id,std::time::Instant::now()+Duration::from_secs(30))?.remove(force)
}

/// Migration must not mistake an HTTP error body for a successful stop. Never
/// force-remove a still-running legacy writer, and never remove its volumes.
pub fn retire_container_checked(id:&str)->Result<(),String>{
    exec_admission::LegacyContainerConnection::prepare_retirement(id)?.retire()
}

/// Pull an image (waits for completion)
/// True if an image already exists in the local Docker image store.
pub fn image_exists_locally(image: &str) -> bool {
    match docker_request("GET", &format!("/images/{image}/json"), None) {
        Ok(body) => body.contains("\"Id\"") || body.contains("\"Config\""),
        Err(_) => false,
    }
}

pub fn pull_image(image: &str) -> Result<(), String> {
    // IfNotPresent: never hit a registry for an image we already have — notably
    // images built locally by a `build` pipeline stage (royak-<app>:<tag>),
    // which have no registry to pull from and would otherwise 404 slowly.
    if image_exists_locally(image) {
        return Ok(());
    }
    let (repo, tag) = split_image(image);
    println!("    pulling {repo}:{tag}...");
    let path = format!("/images/create?fromImage={}&tag={}", repo, tag);

    let mut stream = std::os::unix::net::UnixStream::connect(docker_sock())
        .map_err(|e| format!("Docker connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(300))).ok();
    let request = format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(|e| format!("Write: {e}"))?;
    // The progress stream is chunked and ends when Docker is done — with
    // success or with an `error` line; reading the framed response never
    // waits for a timeout.
    let (status, body) = read_http_response(&mut stream).map_err(|e| format!("Pull {repo}:{tag}: {e}"))?;
    if status >= 400 {
        return Err(format!("Pull {repo}:{tag}: HTTP {status}: {}", body.trim()));
    }
    if let Some(err) = pull_stream_error(&body) {
        return Err(format!("Pull {repo}:{tag}: {err}"));
    }
    if image_exists_locally(image) {
        println!("    pulled {repo}:{tag} ✓");
        Ok(())
    } else {
        Err(format!("Pull {repo}:{tag}: image not available after pull"))
    }
}

fn split_image(image: &str) -> (&str, &str) {
    // A ':' after the last '/' is a tag; one before it is a registry port.
    match image.rfind(':') {
        Some(pos) if !image[pos..].contains('/') => (&image[..pos], &image[pos + 1..]),
        _ => (image, "latest"),
    }
}

/// The first `error` reported in Docker's JSON-lines pull progress stream.
fn pull_stream_error(body: &str) -> Option<String> {
    body.lines().filter_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok())
        .find_map(|v| v.get("error").and_then(|e| e.as_str()).map(|e| e.to_string()))
}

/// Outcome of a non-blocking image check.
#[derive(Debug, Clone, PartialEq)]
pub enum ImageState {
    Present,
    /// A background pull is running.
    Pulling,
    /// The last pull failed; no new attempt before the backoff ends.
    Failed(String),
}

static BACKGROUND_PULLS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The long-running server pulls missing images in the background. One-shot
/// CLI commands keep the blocking (bounded) pull: a background thread would
/// die with the process and the image would never arrive.
pub fn set_background_pulls(on: bool) {
    BACKGROUND_PULLS.store(on, std::sync::atomic::Ordering::Relaxed);
}

/// Non-blocking IfNotPresent: callers that hold the desired-state lock (the
/// reconcile tick) must never wait for a registry. A missing image is pulled
/// on a background thread (one per image); a failed pull is retried with a
/// growing backoff (10 s, doubling, max 5 min). Outside the server (see
/// `set_background_pulls`) the pull runs inline instead.
pub fn ensure_image_nonblocking(image: &str) -> ImageState {
    use std::collections::HashMap;
    if !BACKGROUND_PULLS.load(std::sync::atomic::Ordering::Relaxed) {
        if image_exists_locally(image) {
            return ImageState::Present;
        }
        return match pull_image(image) {
            Ok(()) => ImageState::Present,
            Err(msg) => ImageState::Failed(msg),
        };
    }
    use std::time::Instant;
    struct Entry { running: bool, failed: Option<(String, Instant, Duration)> }
    static P: std::sync::OnceLock<std::sync::Mutex<HashMap<String, Entry>>> = std::sync::OnceLock::new();
    let pulls = P.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    if image_exists_locally(image) {
        if let Ok(mut p) = pulls.lock() { p.remove(image); }
        return ImageState::Present;
    }
    let mut p = match pulls.lock() { Ok(p) => p, Err(e) => e.into_inner() };
    let e = p.entry(image.to_string()).or_insert(Entry { running: false, failed: None });
    if e.running {
        return ImageState::Pulling;
    }
    if let Some((msg, at, backoff)) = &e.failed {
        if at.elapsed() < *backoff {
            return ImageState::Failed(msg.clone());
        }
    }
    e.running = true;
    let prev = e.failed.as_ref().map(|(_, _, b)| *b);
    let img = image.to_string();
    std::thread::spawn(move || {
        let res = pull_image(&img);
        let mut p = match pulls.lock() { Ok(p) => p, Err(e) => e.into_inner() };
        if let Some(e) = p.get_mut(&img) {
            e.running = false;
            e.failed = match res {
                Ok(()) => None,
                Err(msg) => {
                    eprintln!("  ✗ [image] {msg}");
                    let next = prev.map(|b| (b * 2).min(Duration::from_secs(300))).unwrap_or(Duration::from_secs(10));
                    Some((msg, Instant::now(), next))
                }
            };
        }
    });
    ImageState::Pulling
}

/// Get container logs
pub fn get_logs(id: &str, tail: u32) -> Result<String, String> {
    let mut stream=UnixStream::connect(docker_sock()).map_err(|e|e.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(30))).map_err(|e|e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e|e.to_string())?;
    stream.write_all(format!("GET /containers/{id}/logs?stdout=true&stderr=true&tail={tail} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n").as_bytes()).map_err(|e|e.to_string())?;
    let mut body=LogBody::open(stream).map_err(|e|e.to_string())?;
    let mut clean=Vec::new();
    while let Some(data)=read_log_frame(&mut body).map_err(|e|e.to_string())?{
        extend_capture(&mut clean,&data)?;
    }
    Ok(String::from_utf8_lossy(&clean).into_owned())
}

const CAPTURE_LIMIT:usize=4*1024*1024;
fn extend_capture(target:&mut Vec<u8>,bytes:&[u8])->Result<(),String>{
    if target.len().checked_add(bytes.len()).filter(|n|*n<=CAPTURE_LIMIT).is_none(){
        return Err("buffered Pod output exceeds 4 MiB; use a streaming session".into());
    }
    target.extend_from_slice(bytes);Ok(())
}

/// Create the royak global network (backward compat, v0.1)
pub fn ensure_network() -> Result<(), String> {
    ensure_named_network("royak")
}

/// Create a named Docker network (idempotent)
pub fn ensure_named_network(name: &str) -> Result<(), String> {
    match docker_request_checked("GET", &format!("/networks/{name}"), None) {
        Ok(_) => return Ok(()),
        Err(e) if e.contains("HTTP 404") => {}
        Err(e) => return Err(e),
    }
    let body = serde_json::json!({
        "Name": name,
        "Driver": "bridge",
        "Labels": {
            "royak.managed": "true"
        },
        "Options": {
            "com.docker.network.bridge.enable_icc": "true",
            "com.docker.network.bridge.enable_ip_masquerade": "true"
        }
    }).to_string();
    // Checked: a failed create (e.g. Docker's address pools are exhausted)
    // must surface here, not later as "network not found" at container start.
    match docker_request_checked("POST", "/networks/create", Some(&body)) {
        Ok(_) => Ok(()),
        // Created concurrently by another caller.
        Err(e) if e.contains("HTTP 409") => Ok(()),
        Err(e) => Err(e),
    }
}

/// Create a per-namespace network: rk-{namespace}
/// Returns the network name.
pub fn ensure_namespace_network(namespace: &str) -> Result<String, String> {
    let net_name = format!("rk-{namespace}");
    ensure_named_network(&net_name)?;
    Ok(net_name)
}

/// Connect container to the global royak network (v0.1 compat)
pub fn connect_network(container_id: &str, aliases: &[&str]) -> Result<(), String> {
    connect_to_network(container_id, "royak", aliases)
}

/// Connect container to a specific network with DNS aliases
pub fn connect_to_network(container_id: &str, network: &str, aliases: &[&str]) -> Result<(), String> {
    exec_admission::LegacyContainerConnection::prepare(container_id,std::time::Instant::now()+Duration::from_secs(30))?.connect(network,aliases)
}

/// Disconnect container from a network
#[allow(dead_code)]
pub fn disconnect_from_network(container_id: &str, network: &str) -> Result<(), String> {
    exec_admission::LegacyContainerConnection::prepare(container_id,std::time::Instant::now()+Duration::from_secs(30))?.disconnect(network)
}

/// List all royak-managed networks
#[allow(dead_code)]
pub fn list_managed_networks() -> Result<Vec<(String, String)>, String> {
    let filter = r#"{"label":["royak.managed=true"]}"#;
    let encoded = filter.replace('{', "%7B").replace('}', "%7D")
        .replace('"', "%22").replace('[', "%5B").replace(']', "%5D")
        .replace(':', "%3A").replace(',', "%2C");
    let resp = docker_request("GET", &format!("/networks?filters={encoded}"), None)?;
    let nets: Vec<serde_json::Value> = serde_json::from_str(&resp).unwrap_or_default();
    Ok(nets.iter().filter_map(|n| {
        let name = n["Name"].as_str()?.to_string();
        let id = n["Id"].as_str().unwrap_or("").to_string();
        Some((name, id))
    }).collect())
}

/// Get which networks a container is connected to
#[allow(dead_code)]
pub fn container_networks(container_id: &str) -> Result<Vec<String>, String> {
    let resp = docker_request("GET", &format!("/containers/{container_id}/json"), None)?;
    let v: serde_json::Value = serde_json::from_str(&resp).map_err(|e| e.to_string())?;
    let networks = v["NetworkSettings"]["Networks"].as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    Ok(networks)
}

/// Cancelling a session shuts down the actual Docker stream, including idle
/// blocking readers. Registration and cancellation share a lock so a socket
/// created concurrently with revocation cannot escape shutdown.
#[derive(Default)]
pub struct SocketCancellation {
    sockets: std::sync::Mutex<Option<Vec<SessionSocket>>>,
    closed: std::sync::atomic::AtomicBool,
    execs: std::sync::Mutex<Vec<crate::exec_process::Reference>>,
}
struct SessionSocket {
    stream: UnixStream,
    exec: Option<crate::exec_process::Reference>,
}
impl SocketCancellation {
    fn register_exec(&self,container:&str,id:&str,nonce:String)->Result<crate::exec_process::Reference,String>{
        let mut execs=self.execs.lock().map_err(|_|"exec registration lock poisoned")?;
        self.check()?;let r=crate::exec_process::reference(container,id,nonce)?;execs.push(r.clone());Ok(r)
    }
    fn begin_exec_start(&self,r:&crate::exec_process::Reference)->Result<crate::exec_lifecycle::Attempt,String>{
        let execs=self.execs.lock().map_err(|_|"exec registration lock poisoned")?;
        self.check()?;
        if !execs.iter().any(|e|e.id==r.id){return Err("exec reference was retired before start".into());}
        r.start.begin()
    }
    pub fn has_execs(&self)->bool{!self.execs.lock().unwrap_or_else(|e|e.into_inner()).is_empty()}
    pub fn finish_execs(&self)->Result<bool,String>{
        let refs=self.execs.lock().unwrap_or_else(|e|e.into_inner()).clone();
        for reference in refs{
            let finished=crate::exec_process::finish(&reference);
            // Running is a start witness, not completion. Even a subsequent
            // pidfd verification error may now safely release held transport.
            if reference.start.phase()==crate::exec_lifecycle::Phase::Started || matches!(finished,Ok(true)) {
                self.close_exec_transport(&reference.id);
            }
            if !finished?{return Ok(false);}
            self.execs.lock().unwrap_or_else(|e|e.into_inner()).retain(|r|r.id!=reference.id);
        }
        Ok(!self.has_execs())
    }
    pub fn check(&self) -> Result<(), String> {
        if self.closed.load(std::sync::atomic::Ordering::Acquire) { Err("Pod session cancelled".into()) } else { Ok(()) }
    }
    fn register(&self, stream: &UnixStream) -> Result<(),String> {
        let mut sockets=self.sockets.lock().map_err(|_|"Pod session cancellation lock poisoned")?;
        if self.check().is_err() {let _=stream.shutdown(std::net::Shutdown::Both);return Err("Pod session cancelled".into());}
        sockets.get_or_insert_with(Vec::new).push(SessionSocket{stream:stream.try_clone().map_err(|e|e.to_string())?,exec:None});
        Ok(())
    }
    fn register_exec_transport(&self,stream:&UnixStream,reference:&crate::exec_process::Reference)->Result<(),String>{
        let mut sockets=self.sockets.lock().map_err(|_|"Pod session cancellation lock poisoned")?;
        if self.check().is_err(){let _=stream.shutdown(std::net::Shutdown::Both);return Err("Pod session cancelled".into());}
        sockets.get_or_insert_with(Vec::new).push(SessionSocket{stream:stream.try_clone().map_err(|e|e.to_string())?,exec:Some(reference.clone())});
        Ok(())
    }
    fn close_exec_transport(&self,id:&str){
        if !self.closed.load(std::sync::atomic::Ordering::Acquire){return;}
        let mut sockets=self.sockets.lock().unwrap_or_else(|e|e.into_inner());
        if let Some(items)=sockets.as_mut(){items.retain(|item|{
            if item.exec.as_ref().is_some_and(|r|r.id==id){let _=item.stream.shutdown(std::net::Shutdown::Both);false}else{true}
        });if items.is_empty(){*sockets=None;}}
    }
    /// Existing stdin worker calls this instead of a blind half-close. A full
    /// HTTP head is NOT process-start/termination proof. On cancellation the
    /// reaper owns held transport; on active v5 stdin EOF, poll the exact exec
    /// until a live start/terminal witness permits EOF without aborting Start.
    pub fn try_exec_stdin_eof(&self,id:&str)->Result<bool,String>{
        if self.check().is_err(){return Ok(true);}
        let reference=self.execs.lock().unwrap_or_else(|e|e.into_inner()).iter().find(|r|r.id==id).cloned().ok_or("unregistered exec stdin EOF")?;
        if !crate::exec_process::start_witness(&reference)?{return Ok(false);}
        let sockets=self.sockets.lock().unwrap_or_else(|e|e.into_inner());
        if self.check().is_err(){return Ok(true);}
        for item in sockets.as_deref().unwrap_or(&[]){if item.exec.as_ref().is_some_and(|r|r.id==id){item.stream.shutdown(std::net::Shutdown::Write).map_err(|e|e.to_string())?;}}
        Ok(true)
    }
    pub fn cancel(&self) {
        // Same gate as Created->Starting. Never hold it across socket IO.
        {
            let execs=self.execs.lock().unwrap_or_else(|e|e.into_inner());
            self.closed.store(true,std::sync::atomic::Ordering::Release);
            for r in execs.iter(){r.start.cancel_before_start();}
        }
        let mut sockets=self.sockets.lock().unwrap_or_else(|e|e.into_inner());
        let mut deferred=Vec::new();
        for item in sockets.take().unwrap_or_default(){
            if item.exec.as_ref().is_some_and(|r|matches!(r.start.phase(),crate::exec_lifecycle::Phase::Starting|crate::exec_lifecycle::Phase::Unknown)){
                // The daemon may not have reached Hijack/ContainerExecStart.
                // Closing now can strand Created/null forever. No client IO
                // is forwarded after cancel; only this bounded transport is held.
                deferred.push(item);
            }else{let _=item.stream.shutdown(std::net::Shutdown::Both);}
        }
        if !deferred.is_empty(){*sockets=Some(deferred);}
    }
}

/// Create an interactive exec (AttachStdin, optional TTY) and hijack the
/// start stream: returns (exec_id, raw duplex UnixStream positioned right at
/// the start of the response — the caller strips the HTTP head).
pub(crate) fn exec_upgrade_head_valid(head:&[u8])->bool{
    if head.len()>8192||!head.ends_with(b"\r\n\r\n"){return false;}
    let Ok(text)=std::str::from_utf8(head)else{return false;};
    let mut lines=text[..text.len()-4].split("\r\n");
    let mut status=lines.next().unwrap_or("").split_whitespace();
    if status.next()!=Some("HTTP/1.1")||status.next()!=Some("101"){return false;}
    let mut connection=false;let mut upgrade=false;
    for line in lines{
        if line.starts_with([' ','\t']){return false;}
        let Some((key,value))=line.split_once(':')else{return false;};
        if key.eq_ignore_ascii_case("connection"){connection|=value.split(',').any(|x|x.trim().eq_ignore_ascii_case("upgrade"));}
        if key.eq_ignore_ascii_case("upgrade"){
            if upgrade||!value.trim().eq_ignore_ascii_case("tcp"){return false;}upgrade=true;
        }
    }
    connection&&upgrade
}
pub fn exec_hijack(id: &str, cmd: &[&str], tty: bool, cancel: &SocketCancellation) -> Result<(String, ExecStream), String> {
    cancel.check()?;
    let nonce=crate::storage_identity::Uid::new().as_str().to_string();
    let body = serde_json::json!({
        "AttachStdin": true, "AttachStdout": true, "AttachStderr": !tty,
        "Tty": tty, "Cmd": cmd,"Env":[format!("ROYAK_EXEC_SESSION={nonce}")]
    });
    let mut receipt=exec_admission::create(id,&nonce,&body,&||cancel.check())?;
    let exec_id=receipt.id().to_string();
    let reference=cancel.register_exec(receipt.container(),&exec_id,nonce)?;

    let mut stream = receipt.connect_start()?;
    cancel.register_exec_transport(stream.cancellation_socket(),&reference)?;
    // No read timeout: this stream lives for the whole interactive session.
    let start_body = format!(r#"{{"Detach":false,"Tty":{tty}}}"#);
    let request = format!(
        "POST /exec/{exec_id}/start HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: {}\r\n\r\n{}",
        start_body.len(), start_body
    );
    let attempt=cancel.begin_exec_start(&reference)?;
    if let Err(error)=receipt.before_start().and_then(|_|cancel.check()).and_then(|_|receipt.submit_start()) {
        attempt.abort_before_post();
        return Err(error);
    }
    let _start_attempt=attempt;
    stream.write_all(request.as_bytes()).map_err(|e| format!("Write: {e}"))?;
    Ok((exec_id, stream))
}

/// Exit code of a finished exec instance.
pub fn exec_exit_code(exec_id: &str) -> Option<i64> {
    let inspect = docker_request("GET", &format!("/exec/{exec_id}/json"), None).ok()?;
    serde_json::from_str::<serde_json::Value>(&inspect).ok()
        .and_then(|v| v.get("ExitCode").and_then(|c| c.as_i64()))
}

pub(crate) fn inspect_registered_exec(exec_id:&str)->Result<serde_json::Value,String>{
    let body=docker_request_checked("GET",&format!("/exec/{exec_id}/json"),None)?;
    serde_json::from_str(&body).map_err(|_|"invalid registered exec observation".into())
}
pub(crate) fn registered_container_absent(container_id:&str)->Result<bool,String>{
    match docker_request_checked("GET",&format!("/containers/{container_id}/json"),None){
        Ok(_)=>Ok(false),Err(e) if e.starts_with(&format!("docker GET /containers/{container_id}/json: HTTP 404:"))=>Ok(true),Err(e)=>Err(e),
    }
}
pub(crate) fn inspect_pinned_container(id:&str)->Result<serde_json::Value,String>{
    if id.len()!=64||!id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){
        return Err("invalid exact Pod container ID".into());
    }
    let body=docker_request_checked("GET",&format!("/containers/{id}/json"),None)?;
    serde_json::from_str(&body).map_err(|_|"invalid pinned container observation".into())
}

/// Resize an exec's TTY.
pub fn exec_resize(exec_id: &str, w: u32, h: u32) -> Result<(), String> {
    docker_request("POST", &format!("/exec/{exec_id}/resize?w={w}&h={h}"), None)?;
    Ok(())
}

/// Execute a command and capture demultiplexed stdout/stderr separately.
/// Uses the raw Docker stream (8-byte frame headers: type, 0,0,0, len BE).
/// Powers `kubectl exec` (non-interactive) over the WebSocket channel protocol.
pub fn exec_capture(id: &str, cmd: &[&str], cancel: &SocketCancellation) -> Result<(i64, Vec<u8>, Vec<u8>), String> {
    cancel.check()?;
    let nonce=crate::storage_identity::Uid::new().as_str().to_string();
    // 1. Create exec instance
    let body = serde_json::json!({
        "AttachStdout": true, "AttachStderr": true, "Tty": false, "Cmd": cmd,"Env":[format!("ROYAK_EXEC_SESSION={nonce}")]
    });
    let mut receipt=exec_admission::create(id,&nonce,&body,&||cancel.check())?;
    let exec_id=receipt.id().to_string();
    let reference=cancel.register_exec(receipt.container(),&exec_id,nonce)?;

    // 2. Start exec on a raw connection and read the multiplexed stream
    let mut stream = receipt.connect_start()?;
    cancel.register_exec_transport(stream.cancellation_socket(),&reference)?;
    stream.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let start_body = r#"{"Detach":false,"Tty":false}"#;
    let request = format!(
        "POST /exec/{exec_id}/start HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        start_body.len(), start_body
    );
    let attempt=cancel.begin_exec_start(&reference)?;
    if let Err(error)=receipt.before_start().and_then(|_|cancel.check()).and_then(|_|receipt.submit_start()) {
        attempt.abort_before_post();
        return Err(error);
    }
    let _start_attempt=attempt;
    stream.write_all(request.as_bytes()).map_err(|e| format!("Write: {e}"))?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match read_uninterrupted(&mut stream, &mut buf) {
            Ok(0) => break,
            Ok(n) => extend_capture(&mut raw,&buf[..n])?,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(format!("Read: {e}")),
        }
    }
    cancel.check()?;
    // Strip HTTP response head
    let body_start = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(0);
    let mut payload = &raw[body_start..];
    // Docker may chunk-encode the hijacked stream on some versions; handle both.
    let dechunked;
    if raw[..body_start].windows(19).any(|w| w.eq_ignore_ascii_case(b"transfer-encoding: ")) {
        dechunked = dechunk_bytes(payload);
        payload = &dechunked;
    }
    // Demux stream frames
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let mut i = 0usize;
    while i + 8 <= payload.len() {
        let stype = payload[i];
        let len = u32::from_be_bytes([payload[i+4], payload[i+5], payload[i+6], payload[i+7]]) as usize;
        let end = (i + 8 + len).min(payload.len());
        match stype {
            2 => stderr.extend_from_slice(&payload[i+8..end]),
            _ => stdout.extend_from_slice(&payload[i+8..end]),
        }
        i = end;
    }

    // 3. Exit code
    let inspect = docker_request("GET", &format!("/exec/{exec_id}/json"), None)?;
    let exit_code = serde_json::from_str::<serde_json::Value>(&inspect).ok()
        .and_then(|v| v.get("ExitCode").and_then(|c| c.as_i64()))
        .unwrap_or(-1);
    Ok((exit_code, stdout, stderr))
}

/// Minimal chunked-transfer decoder for raw byte streams.
fn dechunk_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = data;
    loop {
        let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") else { break };
        let size_str = String::from_utf8_lossy(&rest[..pos]);
        let Ok(size) = usize::from_str_radix(size_str.trim(), 16) else { break };
        if size == 0 { break; }
        let start = pos + 2;
        let end = (start + size).min(rest.len());
        out.extend_from_slice(&rest[start..end]);
        if end + 2 <= rest.len() { rest = &rest[end + 2..]; } else { break; }
    }
    out
}

/// Execute a command inside a running container (for exec probes)
pub fn exec_in_container(id: &str, cmd: &[&str]) -> Result<(i64, String), String> {
    let nonce=crate::storage_identity::Uid::new().as_str().to_string();
    let body=serde_json::json!({"AttachStdout":true,"AttachStderr":true,"Cmd":cmd,"Env":[format!("ROYAK_EXEC_SESSION={nonce}")]});
    let mut receipt=exec_admission::create(id,&nonce,&body,&||Ok(()))?;
    let exec_id=receipt.id().to_string();
    let start_resp=String::from_utf8_lossy(&receipt.request_start(br#"{"Detach":false,"Tty":false}"#,4*1024*1024)?).into_owned();

    // 3. Inspect exec for exit code
    let inspect = docker_request("GET", &format!("/exec/{exec_id}/json"), None)?;
    let exit_code = serde_json::from_str::<serde_json::Value>(&inspect)
        .ok()
        .and_then(|v| v.get("ExitCode").and_then(|c| c.as_i64()))
        .unwrap_or(-1);

    Ok((exit_code, start_resp))
}

/// Run a probe command inside a container and return its exit code, waiting
/// at most `timeout`. The exec is started detached and polled, so a slow,
/// chatty or hung command is bounded by an in-container process-group watchdog.
/// Requires sh, setsid, sleep and /proc; refusal happens before user code when
/// these are absent. Timed-out non-daemonizing children are killed too.
/// Exit codes 126/127 mean the executable is missing or not runnable.
pub fn probe_exec(id: &str, cmd: &[&str], timeout: Duration) -> Result<i64, String> {
    if cmd.is_empty() { return Err("probe command is empty".into()); }
    let container=exec_admission::probe_container(id)?;
    let id=container["Id"].as_str().ok_or("probe has no exact container identity")?;
    if container["HostConfig"]["Init"] != serde_json::json!(true) {
        return Err("probe requires Docker init to reap timed-out descendants; recreate this legacy container with the current probe runtime".into());
    }
    let seconds = timeout.as_secs().max(1).to_string();
    let mut bounded = vec!["/bin/sh", "-c", include_str!("probe-watchdog.sh"), "royak-probe", &seconds];
    bounded.extend_from_slice(cmd);
    let nonce=crate::storage_identity::Uid::new().as_str().to_string();
    let body=serde_json::json!({"AttachStdout":false,"AttachStderr":false,"Cmd":bounded,"Env":[format!("ROYAK_EXEC_SESSION={nonce}")]});
    let mut receipt=exec_admission::create(id,&nonce,&body,&||Ok(()))?;
    let exec_id=receipt.id().to_string();
    receipt.request_start(br#"{"Detach":true,"Tty":false}"#,1024*1024)?;
    let deadline = std::time::Instant::now() + timeout + Duration::from_secs(2);
    loop {
        let inspect = docker_request("GET", &format!("/exec/{exec_id}/json"), None)?;
        let v: serde_json::Value = serde_json::from_str(&inspect).map_err(|e| format!("exec inspect: {e}"))?;
        if v["Running"] == serde_json::Value::Bool(false) {
            if let Some(code) = v["ExitCode"].as_i64() {
                if code == 125 { return Err("probe watchdog unavailable: image needs sh, setsid, sleep and /proc".into()); }
                if code == 137 { return Err(format!("probe timed out or was killed (deadline {}s)", seconds)); }
                return Ok(code);
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("probe watchdog did not report completion after {}s; runtime cleanup unconfirmed", timeout.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Docker's StartedAt changes even when the same container ID is restarted.
/// Return a stable incarnation and its observed wall-clock age; scheduling
/// converts the age once to a monotonic origin, not on every tick.
pub fn container_incarnation(id: &str) -> Result<(String, Duration), String> {
    let raw = docker_request("GET", &format!("/containers/{id}/json"), None)?;
    let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| format!("container inspect: {e}"))?;
    if v["State"]["Running"] != true { return Err("container is not running".into()); }
    let stamp = v["State"]["StartedAt"].as_str().ok_or("container has no start timestamp")?;
    let started = time::OffsetDateTime::parse(stamp, &time::format_description::well_known::Rfc3339)
        .map_err(|e| format!("invalid container start timestamp: {e}"))?;
    let nanos = (time::OffsetDateTime::now_utc() - started).whole_nanoseconds().max(0);
    let age = Duration::from_nanos(nanos.min(u64::MAX as i128) as u64);
    Ok((format!("{id}:{stamp}"), age))
}

fn tool_missing(code: i64) -> bool {
    code == 126 || code == 127
}

/// HTTP GET probe, run inside the container (curl, then wget). Healthy only on
/// a successful response; a missing tool falls through to the next one, and an
/// image with neither is an error — never a silent success.
pub fn http_check_container(id: &str, path: &str, port: u16, timeout: Duration) -> Result<bool, String> {
    // Probe the pod interface, not a resolver-dependent localhost address.
    // BusyBox wget can choose ::1 without trying IPv4; localhost also wrongly
    // accepts an app that only binds loopback and cannot receive service traffic.
    let url = http_probe_url(&container_ip(id)?, path, port)?;
    let secs = timeout.as_secs().max(1).to_string();
    let wait = timeout;
    let code = probe_exec(id, &["curl", "-sf", "-o", "/dev/null", "-m", &secs, &url], wait)?;
    if !tool_missing(code) {
        return Ok(code == 0);
    }
    let code = probe_exec(id, &["wget", "-q", "-O", "/dev/null", "-T", &secs, &url], wait)?;
    if !tool_missing(code) {
        return Ok(code == 0);
    }
    Err("httpGet probe needs curl or wget in the container image".to_string())
}

fn http_probe_url(ip: &str, path: &str, port: u16) -> Result<String, String> {
    let ip: std::net::IpAddr = ip.parse().map_err(|_| "invalid pod IP for HTTP probe".to_string())?;
    let host = match ip {
        std::net::IpAddr::V4(ip) => ip.to_string(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
    };
    Ok(format!("http://{host}:{port}{}", if path.is_empty() { "/" } else { path }))
}

/// TCP connect probe. Runs inside the pod's own network namespace against the
/// pod IP (what kubelet dials), so a port bound only to 127.0.0.1 fails here as
/// it would on Kubernetes. Needs `nc` or `bash` in the image; without either
/// the probe is an error, never a silent success.
pub fn tcp_check_container(id: &str, port: u16, timeout: Duration) -> Result<bool, String> {
    let ip = container_ip(id).unwrap_or_else(|_| "127.0.0.1".to_string());
    let secs = timeout.as_secs().max(1).to_string();
    let wait = timeout;
    let port_s = port.to_string();
    let code = probe_exec(id, &["nc", "-z", "-w", &secs, &ip, &port_s], wait)?;
    if !tool_missing(code) {
        return Ok(code == 0);
    }
    let code = probe_exec(id, &["bash", "-c", &format!("exec 3<>/dev/tcp/{ip}/{port}")], wait)?;
    if !tool_missing(code) {
        return Ok(code == 0);
    }
    Err("tcpSocket probe needs nc or bash in the container image".to_string())
}

/// Get stderr-only logs
pub fn get_stderr_logs(id: &str, tail: u32) -> Result<String, String> {
    docker_request("GET", &format!("/containers/{id}/logs?stdout=false&stderr=true&tail={tail}"), None)
}

/// Module-level cache for container CPU/mem, shared by the fetching path
/// (`container_stats`), the cache-only `container_stats_peek` used on the
/// reconcile hot path, and the background sampler.
fn stats_cache() -> &'static std::sync::Mutex<HashMap<String, ((f32, f32), std::time::Instant)>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<HashMap<String, ((f32, f32), std::time::Instant)>>> = std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}
/// How long a sampled value stays valid. Generously larger than the sampler
/// interval so a peek during a slow sampler pass still returns fresh-enough data.
const STATS_TTL: Duration = Duration::from_secs(15);

/// Get real CPU and memory stats for a container. Returns a cached value when
/// fresh, otherwise makes Docker's ~1-2s `/stats` call and caches it. Used by
/// the background sampler, one-shot CLI (`royak top`), and per-request API
/// handlers. NOT for the reconcile tick — use `container_stats_peek` there so a
/// slow sample can never stretch the tick.
pub fn container_stats(id: &str) -> Result<(f32, f32), String> {
    if let Some((val, at)) = stats_cache().lock().unwrap().get(id) {
        if at.elapsed() < STATS_TTL {
            return Ok(*val);
        }
    }
    let out = container_stats_uncached(id);
    if let Ok(v) = out {
        stats_cache().lock().unwrap().insert(id.to_string(), (v, std::time::Instant::now()));
    }
    out
}

/// Cache-only read — NEVER makes a Docker call, so it cannot stretch the
/// reconcile tick. Returns the last sampled value if fresh, else Err ("no sample
/// yet") which callers treat as "skip". The background sampler keeps it warm.
pub fn container_stats_peek(id: &str) -> Result<(f32, f32), String> {
    if let Some((val, at)) = stats_cache().lock().unwrap().get(id) {
        if at.elapsed() < STATS_TTL {
            return Ok(*val);
        }
    }
    Err("stats not sampled yet".to_string())
}

/// Force-refresh stats for many containers CONCURRENTLY (always samples, updates
/// the cache). One parallel pass instead of N serial ~1.8s samples. Used by the
/// background sampler.
pub fn refresh_stats(ids: &[String]) {
    let handles: Vec<_> = ids.iter().cloned()
        .map(|id| std::thread::spawn(move || {
            if let Ok(v) = container_stats_uncached(&id) {
                stats_cache().lock().unwrap().insert(id.clone(), (v, std::time::Instant::now()));
            }
        }))
        .collect();
    for h in handles { let _ = h.join(); }
}

/// Background thread that keeps the container-stats cache warm so the reconcile
/// tick (which only peeks) never blocks on Docker's slow `/stats` sampling.
/// Samples every ~4s; STATS_TTL (15s) comfortably covers the gap. Docker's
/// per-container sampling was the last thing stretching the tick (and causing
/// intermittent 502s under load) — moving it off the reconcile thread fixes it.
pub fn spawn_stats_sampler() {
    std::thread::spawn(|| loop {
        let ids: Vec<String> = list_containers(false)
            .map(|cs| cs.into_iter()
                .filter(|c| c.state == "running" && c.names.iter().any(|n| n.contains("rk-")))
                .map(|c| c.id[..12.min(c.id.len())].to_string())
                .collect())
            .unwrap_or_default();
        if !ids.is_empty() { refresh_stats(&ids); }
        std::thread::sleep(Duration::from_secs(4));
    });
}

fn container_stats_uncached(id: &str) -> Result<(f32, f32), String> {
    // Fast path: read cgroup v2 counters straight from the filesystem —
    // microseconds, no Docker `/stats` sampling (~1-2s/container). Falls back to
    // the Docker API when the unified-hierarchy scope isn't directly readable
    // (cgroupfs driver, cgroup v1, macOS/Colima, non-docker runtime).
    if let Some(v) = cgroup_stats_v2(id) {
        return Ok(v);
    }
    container_stats_docker_api(id)
}

/// Previous cgroup CPU-time reading per container, to compute CPU% as a rate
/// between samples (the background sampler polls every ~4s).
fn cgroup_prev() -> &'static std::sync::Mutex<HashMap<String, (u64, std::time::Instant)>> {
    static PREV: std::sync::OnceLock<std::sync::Mutex<HashMap<String, (u64, std::time::Instant)>>> = std::sync::OnceLock::new();
    PREV.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

/// Read CPU%/mem directly from cgroup v2 for a container (matched by short id).
/// Returns None when the systemd-driver scope dir isn't found, so the caller
/// falls back to the Docker API. CPU% is a rate vs the previous sample — 0 on a
/// container's first read, then real once the sampler has two data points.
fn cgroup_stats_v2(id: &str) -> Option<(f32, f32)> {
    let base = "/sys/fs/cgroup/system.slice";
    let prefix = format!("docker-{id}");
    let dir = std::fs::read_dir(base).ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .find(|n| n.starts_with(&prefix) && n.ends_with(".scope"))?;
    let scope = format!("{base}/{dir}");

    // CPU: cumulative usage_usec (across all cores) → % as delta over wall time.
    // Same convention as Docker: 100% == one full core, so a 2-core burn reads 200%.
    let usage_usec: u64 = std::fs::read_to_string(format!("{scope}/cpu.stat")).ok()?
        .lines()
        .find_map(|l| l.strip_prefix("usage_usec ").and_then(|v| v.trim().parse().ok()))?;
    let now = std::time::Instant::now();
    let cpu_pct = {
        let mut prev = cgroup_prev().lock().unwrap();
        let pct = match prev.get(id) {
            Some((u0, t0)) => {
                let dw = now.duration_since(*t0).as_micros();
                if dw > 0 { (usage_usec.saturating_sub(*u0) as f64 / dw as f64 * 100.0) as f32 } else { 0.0 }
            }
            None => 0.0,
        };
        prev.insert(id.to_string(), (usage_usec, now));
        pct
    };

    // Memory working set = memory.current − inactive_file (raw memory.current
    // includes reclaimable page cache; subtracting it matches Docker's number).
    let mem_current: u64 = std::fs::read_to_string(format!("{scope}/memory.current")).ok()?
        .trim().parse().ok()?;
    let inactive_file: u64 = std::fs::read_to_string(format!("{scope}/memory.stat")).ok()
        .and_then(|s| s.lines().find_map(|l| l.strip_prefix("inactive_file ").and_then(|v| v.trim().parse().ok())))
        .unwrap_or(0);
    let mem_mb = mem_current.saturating_sub(inactive_file) as f32 / 1_048_576.0;

    Some((cpu_pct, mem_mb))
}

/// Docker `/stats` API (one-shot). Fallback for when cgroup v2 can't be read directly.
fn container_stats_docker_api(id: &str) -> Result<(f32, f32), String> {
    // Docker stats API (one-shot, no stream)
    let resp = docker_request("GET", &format!("/containers/{id}/stats?stream=false"), None)?;

    let v: serde_json::Value = serde_json::from_str(&resp)
        .map_err(|e| format!("Stats parse: {e}"))?;

    // CPU: calculate percentage from cpu_stats vs precpu_stats
    let cpu_delta = v["cpu_stats"]["cpu_usage"]["total_usage"].as_f64().unwrap_or(0.0)
        - v["precpu_stats"]["cpu_usage"]["total_usage"].as_f64().unwrap_or(0.0);
    let system_delta = v["cpu_stats"]["system_cpu_usage"].as_f64().unwrap_or(0.0)
        - v["precpu_stats"]["system_cpu_usage"].as_f64().unwrap_or(0.0);
    let num_cpus = v["cpu_stats"]["online_cpus"].as_f64()
        .or_else(|| v["cpu_stats"]["cpu_usage"]["percpu_usage"].as_array().map(|a| a.len() as f64))
        .unwrap_or(1.0);

    let cpu_pct = if system_delta > 0.0 {
        (cpu_delta / system_delta) * num_cpus * 100.0
    } else {
        0.0
    };

    // Memory: usage in MB
    let mem_usage = v["memory_stats"]["usage"].as_f64().unwrap_or(0.0);
    let mem_cache = v["memory_stats"]["stats"]["cache"].as_f64().unwrap_or(0.0);
    let mem_mb = (mem_usage - mem_cache) / 1_048_576.0;

    Ok((cpu_pct as f32, mem_mb as f32))
}

/// Stream logs from a container (follow=true) — sends lines through a channel.
/// Runs in a blocking thread. Returns when container stops or channel closes.
pub fn stream_logs_to_channel(id: &str, tail: u32, tx: tokio::sync::mpsc::Sender<bytes::Bytes>, cancel: &SocketCancellation) {
    let path = format!("/containers/{id}/logs?stdout=true&stderr=true&tail={tail}&follow=true");

    let mut stream = match UnixStream::connect(docker_sock()) {
        Ok(s) => s,
        Err(_) => return,
    };
    if cancel.register(&stream).is_err() { return; }

    // No read timeout for streaming — block until data arrives
    stream.set_read_timeout(Some(Duration::from_secs(300))).ok();

    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() { return; }

    let Ok(mut body)=LogBody::open(stream) else{return;};

    while let Ok(Some(data))=read_log_frame(&mut body) {
        if tx.blocking_send(bytes::Bytes::from(data)).is_err() {
            return; // client disconnected
        }
    }
}

fn read_log_frame(reader:&mut impl Read)->std::io::Result<Option<Vec<u8>>>{
    let mut header=[0u8;8];
    if read_uninterrupted(reader,&mut header[..1])?==0{return Ok(None);}
    reader.read_exact(&mut header[1..])?;
    let size=u32::from_be_bytes(header[4..8].try_into().unwrap()) as usize;
    if ![1,2].contains(&header[0]) || header[1..4]!=[0,0,0] || size>crate::pod_sessions::DOCKER_FRAME_LIMIT{
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"invalid or oversized Docker log frame"));
    }
    let mut data=vec![0;size];reader.read_exact(&mut data)?;Ok(Some(data))
}

/// Docker log frames and HTTP chunks are independent boundaries. Decode the
/// HTTP layer incrementally, retaining at most one bounded frame in memory.
struct LogBody<R> {reader:R,chunked:bool,remaining:usize,need_crlf:bool,ended:bool}
impl<R:Read> LogBody<R> {
    fn line(reader:&mut R,bound:usize)->std::io::Result<Vec<u8>>{
        let mut line=Vec::new();let mut byte=[0];
        loop{
            reader.read_exact(&mut byte)?;line.push(byte[0]);
            if line.ends_with(b"\r\n"){line.truncate(line.len()-2);return Ok(line);}
            if line.len()>bound{return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"Docker log header exceeds bound"));}
        }
    }
    fn open(mut reader:R)->std::io::Result<Self>{
        let status=Self::line(&mut reader,8192)?;
        if status.split(|b|*b==b' ').nth(1)!=Some(b"200".as_slice()){
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"Docker logs did not return HTTP 200"));
        }
        let mut total=status.len();let mut chunked=false;
        loop{
            let line=Self::line(&mut reader,8192)?;total+=line.len()+2;
            if total>8192{return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"Docker log headers exceed bound"));}
            if line.is_empty(){break;}
            let lower=String::from_utf8_lossy(&line).to_ascii_lowercase();
            if let Some(value)=lower.strip_prefix("transfer-encoding:"){
                if value.trim()!="chunked"{return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"unsupported Docker log encoding"));}
                chunked=true;
            }
        }
        Ok(Self{reader,chunked,remaining:0,need_crlf:false,ended:false})
    }
}
impl<R:Read> Read for LogBody<R>{
    fn read(&mut self,out:&mut [u8])->std::io::Result<usize>{
        if out.is_empty()||self.ended{return Ok(0);}
        if !self.chunked{return read_uninterrupted(&mut self.reader,out);}
        if self.remaining==0{
            if self.need_crlf{
                let mut crlf=[0;2];self.reader.read_exact(&mut crlf)?;
                if crlf!=*b"\r\n"{return Err(std::io::Error::new(std::io::ErrorKind::InvalidData,"invalid Docker log chunk terminator"));}
            }
            let line=Self::line(&mut self.reader,128)?;
            let text=std::str::from_utf8(&line).map_err(|_|std::io::Error::new(std::io::ErrorKind::InvalidData,"invalid Docker log chunk"))?;
            self.remaining=usize::from_str_radix(text.split(';').next().unwrap_or("").trim(),16)
                .ok().filter(|n|*n<=1_000_000).ok_or_else(||std::io::Error::new(std::io::ErrorKind::InvalidData,"invalid or oversized Docker log chunk"))?;
            if self.remaining==0{self.ended=true;return Ok(0);}
            self.need_crlf=true;
        }
        let len=out.len().min(self.remaining);
        let n=read_uninterrupted(&mut self.reader,&mut out[..len])?;
        if n==0{return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof,"truncated Docker log chunk"));}
        self.remaining-=n;Ok(n)
    }
}

/// Get a container's IP address (from any connected network)
pub fn container_ip(container_id: &str) -> Result<String, String> {
    let resp = docker_request("GET", &format!("/containers/{container_id}/json"), None)?;
    let v: serde_json::Value = serde_json::from_str(&resp).map_err(|e| e.to_string())?;
    v["NetworkSettings"]["Networks"].as_object()
        .and_then(|nets| {
            nets.values()
                .filter_map(|net| net["IPAddress"].as_str())
                .find(|ip| !ip.is_empty())
                .map(|s| s.to_string())
                .or_else(|| nets.values()
                    .filter_map(|net| net["GlobalIPv6Address"].as_str())
                    .find(|ip| !ip.is_empty())
                    .map(|s| s.to_string()))
        })
        .ok_or_else(|| "no IP found".to_string())
}

/// Check if Docker is available
pub fn ping() -> bool {
    docker_request("GET", "/_ping", None).is_ok()
}

/// Apply iptables rules inside a pod's network namespace for real L4
/// NetworkPolicy enforcement. Runs a short-lived helper container that JOINS
/// the target pod's netns (`--network container:<id>`) with NET_ADMIN, so the
/// rules land in the pod's own namespace and persist for the pod's lifetime.
/// `rules` are iptables argument vectors (without the leading "iptables").
/// Idempotent: callers should flush (`-F`) as the first rule.
pub fn apply_netns_iptables(pod_id: &str, rules: &[Vec<String>]) -> Result<(), String> {
    // Native targets cannot enter this legacy NET_ADMIN path. The actual
    // readonly target inspect, Create and Start remain on one connection;
    // the helper uses the inspected full CID, never the caller's name/prefix.
    let connection=exec_admission::LegacyContainerConnection::prepare(
        pod_id,std::time::Instant::now()+std::time::Duration::from_secs(30))?;
    // Build a single sh script: install iptables (cached after first run),
    // then apply each rule. `|| true` on flush so a fresh chain doesn't error.
    let mut script = String::from("apk add --no-cache iptables >/dev/null 2>&1; ");
    for r in rules {
        script.push_str("iptables ");
        script.push_str(&r.join(" "));
        script.push_str(" 2>/dev/null || true; ");
    }
    connection.apply_netns_iptables(&script)
}

// ─── Image build from source (git context → OCI image) ───
//
// The keystone that turns Royak from "deploy existing images" (GitOps) into
// "build from source, then deploy" (PaaS). Builds happen via the Docker Engine
// `/build` endpoint: we tar the build context and POST it, streaming back the
// build log. Builds are slow (seconds to minutes), so a build MUST NOT run
// inline in the reconcile loop — `start_build` spawns it on a background thread
// and `poll_build` lets the loop check progress each tick without blocking.

use std::sync::{Arc, Mutex, OnceLock};
use std::collections::HashMap;

/// Build an image from a local context directory containing a Dockerfile.
/// Blocking — call from a background thread (see `start_build`). Returns the
/// build log on success, or an error message (Docker's own error text) on
/// failure. `tag` is the resulting image name:tag (may be a local-only tag).
pub fn build_image(context_dir: &str, dockerfile: &str, tag: &str, build_args: &[(String, String)]) -> Result<String, String> {
    if !std::path::Path::new(context_dir).exists() {
        return Err(format!("build context '{context_dir}' does not exist"));
    }
    if !std::path::Path::new(context_dir).join(dockerfile).exists() {
        return Err(format!("{dockerfile} not found in build context '{context_dir}'"));
    }

    // Tar the context (excluding .git to keep it small). `tar` is ubiquitous;
    // we stream its stdout into memory as the request body. `--no-xattrs` is
    // REQUIRED: macOS stamps files with a `com.apple.provenance` xattr that the
    // Linux-side builder rejects on unpack (`lsetxattr ... not supported`); the
    // flag is understood by both bsdtar (macOS) and GNU tar (Linux).
    let out = std::process::Command::new("tar")
        .args(["--no-xattrs", "--exclude=./.git", "-cf", "-", "-C", context_dir, "."])
        .output()
        .map_err(|e| format!("tar context failed: {e}"))?;
    if !out.status.success() {
        return Err(format!("tar context failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let tar_body = out.stdout;

    // POST the tar to /build. `rm=1&forcerm=1` cleans up intermediate build
    // containers; `dockerfile` names the Dockerfile within the context.
    let df = urlencode(dockerfile);
    let t = urlencode(tag);
    let mut path = format!("/build?t={t}&dockerfile={df}&rm=1&forcerm=1");
    // Build-time ARGs → the `buildargs` query param as a URL-encoded JSON map,
    // so a Dockerfile `ARG KEY` receives its value at build time.
    if !build_args.is_empty() {
        let map: serde_json::Map<String, serde_json::Value> = build_args.iter()
            .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
            .collect();
        let json = serde_json::Value::Object(map).to_string();
        path.push_str(&format!("&buildargs={}", urlencode(&json)));
    }

    let mut stream = UnixStream::connect(docker_sock())
        .map_err(|e| format!("Cannot connect to Docker: {e}"))?;
    // Builds can take minutes — generous read timeout, and we read until the
    // daemon closes the connection (end of the streamed build log).
    stream.set_read_timeout(Some(Duration::from_secs(900))).ok();

    let header = format!(
        "POST {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/x-tar\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        tar_body.len()
    );
    stream.write_all(header.as_bytes()).map_err(|e| format!("Write header: {e}"))?;
    stream.write_all(&tar_body).map_err(|e| format!("Write context: {e}"))?;
    stream.flush().ok();

    let mut response = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        match read_uninterrupted(&mut stream, &mut buf) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            // The daemon often RESETs the connection at the end of the build
            // stream instead of a clean EOF (seen on GitHub-hosted Docker). Treat
            // reset/broken-pipe as end-of-stream and judge success from the body
            // + the image store below, not from how the socket closed.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset
                   || e.kind() == std::io::ErrorKind::BrokenPipe => break,
            Err(e) => return Err(format!("Read build stream: {e}")),
        }
    }

    let text = String::from_utf8_lossy(&response).to_string();
    // Body starts after the HTTP headers; it's a stream of JSON objects, one
    // per progress line: {"stream":"..."} on progress, {"error":"...",
    // "errorDetail":{...}} on failure. Success has no "error" key.
    let body = text.split("\r\n\r\n").nth(1).unwrap_or(&text);
    // Collect human-readable "stream" lines for the log, and detect errors.
    let mut logbuf = String::new();
    let mut err: Option<String> = None;
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') { continue; }
        if let Some(msg) = json_str_field(line, "error") {
            err = Some(msg);
        } else if let Some(s) = json_str_field(line, "stream") {
            logbuf.push_str(&s);
        }
    }
    // A malformed HTTP status (e.g. 400/500) with no JSON error line.
    if err.is_none() && (text.starts_with("HTTP/1.1 4") || text.starts_with("HTTP/1.1 5")) {
        err = Some(text.lines().next().unwrap_or("build failed").to_string());
    }

    // Ground truth: if the tagged image now exists in the store, the build
    // succeeded — regardless of how the stream ended. This overrides a spurious
    // error from an abruptly-closed connection while still honouring a real
    // build error (which would have left no image).
    if image_exists_locally(tag) {
        return Ok(logbuf);
    }

    // No image in the store → the build did NOT succeed, even if the stream
    // ended without an explicit error line (e.g. a connection reset truncated
    // it, or a COPY failed against the wrong context). Never report success
    // without a resulting image.
    match err {
        Some(e) => Err(e.trim().to_string()),
        None => {
            let tail: String = logbuf.lines().rev().take(3).collect::<Vec<_>>().into_iter().rev().collect::<Vec<_>>().join(" ");
            Err(format!("build produced no image '{tag}' (stream ended without success){}",
                if tail.is_empty() { String::new() } else { format!(": …{tail}") }))
        }
    }
}

/// Minimal application/x-www-form-urlencode for query values (image tags,
/// filenames). Enough for the characters that appear in tags and paths.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Extract a top-level JSON string field's value from one compact JSON line,
/// unescaping the common `\n`, `\t`, `\"`, `\\` sequences. Deliberately tiny —
/// the Docker build stream lines are flat objects, so this avoids a JSON dep.
fn json_str_field(line: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = line.find(&needle)? + needle.len();
    let rest = &line[start..];
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('/') => out.push('/'),
                Some(other) => out.push(other),
                None => break,
            },
            other => out.push(other),
        }
    }
    Some(out)
}

/// Poll state for a background build job.
pub enum BuildPoll {
    NotStarted,
    Running,
    Done(Result<String, String>),
}

fn build_jobs() -> &'static Mutex<HashMap<String, Arc<Mutex<Option<Result<String, String>>>>>> {
    static JOBS: OnceLock<Mutex<HashMap<String, Arc<Mutex<Option<Result<String, String>>>>>>> = OnceLock::new();
    JOBS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Kick off a build on a background thread, keyed by `job`. Idempotent: if a
/// job with this key already exists, does nothing (the loop keeps polling it).
pub fn start_build(job: &str, context_dir: String, dockerfile: String, tag: String, build_args: Vec<(String, String)>) {
    let mut map = build_jobs().lock().unwrap();
    if map.contains_key(job) { return; }
    let slot: Arc<Mutex<Option<Result<String, String>>>> = Arc::new(Mutex::new(None));
    map.insert(job.to_string(), slot.clone());
    drop(map);
    std::thread::spawn(move || {
        let result = build_image(&context_dir, &dockerfile, &tag, &build_args);
        *slot.lock().unwrap() = Some(result);
    });
}

/// Check a build job's progress without blocking.
pub fn poll_build(job: &str) -> BuildPoll {
    let map = build_jobs().lock().unwrap();
    match map.get(job) {
        None => BuildPoll::NotStarted,
        Some(slot) => match &*slot.lock().unwrap() {
            None => BuildPoll::Running,
            Some(r) => BuildPoll::Done(r.clone()),
        },
    }
}

/// Forget a finished build job (call once its result has been consumed).
pub fn clear_build(job: &str) {
    build_jobs().lock().unwrap().remove(job);
}

#[cfg(test)]
mod pull_tests {
    use super::*;

    #[test]
    fn buffered_capture_is_bounded_without_silent_truncation(){
        let mut v=vec![b'x';CAPTURE_LIMIT-1];extend_capture(&mut v,b"y").unwrap();
        assert_eq!(v.len(),CAPTURE_LIMIT);assert!(extend_capture(&mut v,b"z").is_err());assert_eq!(v.len(),CAPTURE_LIMIT);
        assert!(read_log_frame(&mut std::io::Cursor::new([1,0,0,0,0xff,0xff,0xff,0xff])).is_err());
        assert!(read_log_frame(&mut std::io::Cursor::new([1,0,0])).is_err());
    }

    #[test]
    fn followed_logs_decode_http_chunks_independent_of_docker_frames() {
        let payload=b"\x01\0\0\0\0\0\0\x05hello\x02\0\0\0\0\0\0\x05error";
        let mut wire=b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        for part in payload.chunks(3){wire.extend_from_slice(format!("{:x};x=y\r\n",part.len()).as_bytes());wire.extend_from_slice(part);wire.extend_from_slice(b"\r\n");}
        wire.extend_from_slice(b"0\r\n\r\n");
        let mut body=LogBody::open(std::io::Cursor::new(wire)).unwrap();let mut result=Vec::new();body.read_to_end(&mut result).unwrap();assert_eq!(result,payload);
        let mut wire=b"HTTP/1.1 200 OK\r\n\r\n".to_vec();wire.extend_from_slice(payload);
        let mut body=LogBody::open(std::io::Cursor::new(wire)).unwrap();let mut result=Vec::new();body.read_to_end(&mut result).unwrap();assert_eq!(result,payload);
    }
    #[test]
    fn malformed_or_failed_docker_log_http_is_not_data() {
        assert!(LogBody::open(std::io::Cursor::new(b"HTTP/1.1 403 Denied\r\n\r\n")).is_err());
        for payload in ["3\r\nx", "zz\r\n", "10000000\r\n"] {
            let wire=format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{payload}");
            let mut body=LogBody::open(std::io::Cursor::new(wire)).unwrap();let mut result=Vec::new();assert!(body.read_to_end(&mut result).is_err());
        }
    }

    #[test]
    fn session_cancellation_closes_idle_socket_and_late_registration() {
        let cancellation=SocketCancellation::default();
        let (client,mut peer)=UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        cancellation.register(&client).unwrap();cancellation.cancel();
        assert!(cancellation.check().is_err());
        let mut byte=[0];assert_eq!(peer.read(&mut byte).unwrap(),0);
        let (late,mut peer)=UnixStream::pair().unwrap();peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert!(cancellation.register(&late).is_err());assert_eq!(peer.read(&mut byte).unwrap(),0);
        cancellation.cancel();
    }

    #[test]
    fn probe_reaper_is_explicit_and_only_enabled_for_probed_containers() {
        let mut options = serde_json::Map::new();
        configure_probe_init(&mut options, false);
        assert!(!options.contains_key("Init"));
        configure_probe_init(&mut options, true);
        assert_eq!(options.get("Init"), Some(&serde_json::json!(true)));
    }

    #[test]
    fn interrupted_reads_keep_the_same_partial_http_response() {
        struct InterruptedReader { bytes: std::io::Cursor<Vec<u8>>, interrupt: bool }
        impl Read for InterruptedReader {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                self.interrupt = !self.interrupt;
                if self.interrupt { return Err(std::io::ErrorKind::Interrupted.into()); }
                let limit = out.len().min(3);
                self.bytes.read(&mut out[..limit])
            }
        }
        let mut reader = InterruptedReader { bytes: std::io::Cursor::new(
            b"HTTP/1.1 201 Created\r\nContent-Length: 5\r\n\r\nhello".to_vec()), interrupt: false };
        assert_eq!(read_http_response(&mut reader).unwrap(), (201, "hello".into()));
    }

    #[test]
    fn read_retry_does_not_swallow_timeout_or_other_errors() {
        struct TimeoutReader;
        impl Read for TimeoutReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::TimedOut.into())
            }
        }
        assert_eq!(read_uninterrupted(&mut TimeoutReader, &mut [0; 8]).unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn http_probe_uses_explicit_pod_ip_and_ipv6_brackets() {
        assert_eq!(http_probe_url("172.20.0.2", "/health", 8000).unwrap(), "http://172.20.0.2:8000/health");
        assert_eq!(http_probe_url("fd00::2", "", 8000).unwrap(), "http://[fd00::2]:8000/");
        assert!(http_probe_url("localhost", "/", 80).is_err());
    }

    #[test]
    fn image_refs_split_tag_not_registry_port() {
        assert_eq!(split_image("alpine:3.22"), ("alpine", "3.22"));
        assert_eq!(split_image("alpine"), ("alpine", "latest"));
        assert_eq!(split_image("reg.local:5000/team/app"), ("reg.local:5000/team/app", "latest"));
        assert_eq!(split_image("reg.local:5000/team/app:v2"), ("reg.local:5000/team/app", "v2"));
    }

    #[test]
    fn pull_progress_error_lines_are_failures() {
        let ok = "{\"status\":\"Pulling from library/alpine\"}\r\n{\"status\":\"Digest: sha256:x\"}\r\n";
        assert_eq!(pull_stream_error(ok), None);
        let bad = "{\"status\":\"Pulling\"}\r\n{\"errorDetail\":{\"message\":\"no such host\"},\"error\":\"dial tcp: lookup zr.invalid: no such host\"}\r\n";
        assert_eq!(pull_stream_error(bad).as_deref(), Some("dial tcp: lookup zr.invalid: no such host"));
    }
}

