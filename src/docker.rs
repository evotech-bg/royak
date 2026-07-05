//! Docker Engine API client — talks to /var/run/docker.sock
//!
//! This is the ONLY interface to the container runtime.
//! Everything else (scheduling, scaling, healing) is our logic on top.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const DOCKER_SOCK: &str = "/var/run/docker.sock";

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
        match stream.read(&mut buf) {
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
    let resp = docker_request("POST", &format!("/containers/{id}/start"), None)?;
    if resp.contains("304") || resp.is_empty() || resp.contains("\"\"") {
        Ok(()) // already started or success
    } else if resp.contains("\"message\"") {
        Err(resp)
    } else {
        Ok(())
    }
}

/// Stop a container
pub fn stop_container(id: &str) -> Result<(), String> {
    docker_request("POST", &format!("/containers/{id}/stop?t=10"), None)?;
    Ok(())
}

/// Remove a container
pub fn remove_container(id: &str, force: bool) -> Result<(), String> {
    let force_param = if force { "?force=true" } else { "" };
    docker_request("DELETE", &format!("/containers/{id}{force_param}"), None)?;
    Ok(())
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
    let (repo, tag) = if let Some(pos) = image.rfind(':') {
        (&image[..pos], &image[pos+1..])
    } else {
        (image, "latest")
    };
    println!("    pulling {repo}:{tag}...");
    let path = format!("/images/create?fromImage={}&tag={}", repo, tag);

    let mut stream = std::os::unix::net::UnixStream::connect(docker_sock())
        .map_err(|e| format!("Docker connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(120))).ok();

    let request = format!("POST {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    stream.write_all(request.as_bytes()).map_err(|e| format!("Write: {e}"))?;

    let mut buf = [0u8; 4096];
    let mut response = String::new();
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                response.push_str(&String::from_utf8_lossy(&buf[..n]));
                // Check for errors first
                if response.contains("no space left") || response.contains("No space left") {
                    return Err(format!("Pull {repo}:{tag}: no disk space left"));
                }
                if response.contains("not found") || response.contains("manifest unknown") {
                    return Err(format!("Pull {repo}:{tag}: image not found"));
                }
                if response.contains("unauthorized") || response.contains("denied") {
                    return Err(format!("Pull {repo}:{tag}: access denied"));
                }
                // Check for success
                if response.contains("Downloaded") || response.contains("Already exists")
                    || response.contains("up to date") || response.contains("Pulled") {
                    break;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(format!("Pull: {e}")),
        }
    }

    // Verify image actually exists after pull
    let check = docker_request("GET", &format!("/images/{repo}:{tag}/json"), None);
    match check {
        Ok(body) if body.contains("Id") => {
            println!("    pulled {repo}:{tag} ✓");
            Ok(())
        }
        _ => Err(format!("Pull {repo}:{tag}: image not available after pull (disk full?)")),
    }
}

/// Get container logs
pub fn get_logs(id: &str, tail: u32) -> Result<String, String> {
    let raw = docker_request("GET", &format!("/containers/{id}/logs?stdout=true&stderr=true&tail={tail}"), None)?;
    // Docker multiplexed log format: each frame has 8-byte header [stream_type(1) + 0(3) + size(4)]
    // Strip these headers to get clean log output
    let mut clean = String::new();
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 8 <= bytes.len() && (bytes[i] == 1 || bytes[i] == 2) && bytes[i+1] == 0 && bytes[i+2] == 0 && bytes[i+3] == 0 {
            // Read frame size from bytes 4-7 (big-endian)
            let size = ((bytes[i+4] as usize) << 24) | ((bytes[i+5] as usize) << 16)
                     | ((bytes[i+6] as usize) << 8) | (bytes[i+7] as usize);
            i += 8;
            let end = (i + size).min(bytes.len());
            if let Ok(s) = std::str::from_utf8(&bytes[i..end]) {
                clean.push_str(s);
            }
            i = end;
        } else {
            // Not a frame header — copy raw
            if let Ok(s) = std::str::from_utf8(&bytes[i..]) {
                clean.push_str(s);
                break;
            }
            break;
        }
    }
    Ok(clean)
}

/// Create the royak global network (backward compat, v0.1)
pub fn ensure_network() -> Result<(), String> {
    ensure_named_network("royak")
}

/// Create a named Docker network (idempotent)
pub fn ensure_named_network(name: &str) -> Result<(), String> {
    let resp = docker_request("GET", &format!("/networks/{name}"), None);
    if let Ok(r) = &resp {
        if r.contains(name) && !r.contains("not found") {
            return Ok(());
        }
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
    docker_request("POST", "/networks/create", Some(&body))?;
    Ok(())
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
    let body = serde_json::json!({
        "Container": container_id,
        "EndpointConfig": {"Aliases": aliases}
    }).to_string();
    docker_request("POST", &format!("/networks/{network}/connect"), Some(&body))?;
    Ok(())
}

/// Disconnect container from a network
#[allow(dead_code)]
pub fn disconnect_from_network(container_id: &str, network: &str) -> Result<(), String> {
    let body = serde_json::json!({
        "Container": container_id,
        "Force": true
    }).to_string();
    docker_request("POST", &format!("/networks/{network}/disconnect"), Some(&body))?;
    Ok(())
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

/// Create an interactive exec (AttachStdin, optional TTY) and hijack the
/// start stream: returns (exec_id, raw duplex UnixStream positioned right at
/// the start of the response — the caller strips the HTTP head).
pub fn exec_hijack(id: &str, cmd: &[&str], tty: bool) -> Result<(String, UnixStream), String> {
    let body = serde_json::json!({
        "AttachStdin": true, "AttachStdout": true, "AttachStderr": !tty,
        "Tty": tty, "Cmd": cmd
    }).to_string();
    let resp = docker_request("POST", &format!("/containers/{id}/exec"), Some(&body))?;
    let exec_id = serde_json::from_str::<serde_json::Value>(&resp).ok()
        .and_then(|v| v.get("Id").and_then(|i| i.as_str()).map(|s| s.to_string()))
        .ok_or_else(|| format!("No exec ID in response: {resp}"))?;

    let mut stream = UnixStream::connect(docker_sock())
        .map_err(|e| format!("Docker connect: {e}"))?;
    // No read timeout: this stream lives for the whole interactive session.
    let start_body = format!(r#"{{"Detach":false,"Tty":{tty}}}"#);
    let request = format!(
        "POST /exec/{exec_id}/start HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: {}\r\n\r\n{}",
        start_body.len(), start_body
    );
    stream.write_all(request.as_bytes()).map_err(|e| format!("Write: {e}"))?;
    Ok((exec_id, stream))
}

/// Exit code of a finished exec instance.
pub fn exec_exit_code(exec_id: &str) -> Option<i64> {
    let inspect = docker_request("GET", &format!("/exec/{exec_id}/json"), None).ok()?;
    serde_json::from_str::<serde_json::Value>(&inspect).ok()
        .and_then(|v| v.get("ExitCode").and_then(|c| c.as_i64()))
}

/// Resize an exec's TTY.
pub fn exec_resize(exec_id: &str, w: u32, h: u32) -> Result<(), String> {
    docker_request("POST", &format!("/exec/{exec_id}/resize?w={w}&h={h}"), None)?;
    Ok(())
}

/// Execute a command and capture demultiplexed stdout/stderr separately.
/// Uses the raw Docker stream (8-byte frame headers: type, 0,0,0, len BE).
/// Powers `kubectl exec` (non-interactive) over the WebSocket channel protocol.
pub fn exec_capture(id: &str, cmd: &[&str]) -> Result<(i64, Vec<u8>, Vec<u8>), String> {
    // 1. Create exec instance
    let body = serde_json::json!({
        "AttachStdout": true, "AttachStderr": true, "Tty": false, "Cmd": cmd
    }).to_string();
    let resp = docker_request("POST", &format!("/containers/{id}/exec"), Some(&body))?;
    let exec_id = serde_json::from_str::<serde_json::Value>(&resp).ok()
        .and_then(|v| v.get("Id").and_then(|i| i.as_str()).map(|s| s.to_string()))
        .ok_or_else(|| format!("No exec ID in response: {resp}"))?;

    // 2. Start exec on a raw connection and read the multiplexed stream
    let mut stream = UnixStream::connect(docker_sock())
        .map_err(|e| format!("Docker connect: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let start_body = r#"{"Detach":false,"Tty":false}"#;
    let request = format!(
        "POST /exec/{exec_id}/start HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        start_body.len(), start_body
    );
    stream.write_all(request.as_bytes()).map_err(|e| format!("Write: {e}"))?;

    let mut raw = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) => return Err(format!("Read: {e}")),
        }
    }
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
    // 1. Create exec instance
    let body = serde_json::json!({"AttachStdout": true, "AttachStderr": true, "Cmd": cmd}).to_string();
    let resp = docker_request("POST", &format!("/containers/{id}/exec"), Some(&body))?;

    let exec_id = serde_json::from_str::<serde_json::Value>(&resp)
        .ok()
        .and_then(|v| v.get("Id").and_then(|i| i.as_str()).map(|s| s.to_string()))
        .ok_or_else(|| format!("No exec ID in response: {resp}"))?;

    // 2. Start exec
    let start_resp = docker_request("POST", &format!("/exec/{exec_id}/start"), Some(r#"{"Detach":false,"Tty":false}"#))?;

    // 3. Inspect exec for exit code
    let inspect = docker_request("GET", &format!("/exec/{exec_id}/json"), None)?;
    let exit_code = serde_json::from_str::<serde_json::Value>(&inspect)
        .ok()
        .and_then(|v| v.get("ExitCode").and_then(|c| c.as_i64()))
        .unwrap_or(-1);

    Ok((exit_code, start_resp))
}

/// HTTP health check via exec (try curl first, then wget — works in both alpine and debian)
pub fn http_check_container(id: &str, path: &str, port: u16) -> Result<bool, String> {
    let url = format!("http://localhost:{port}{path}");
    // Try curl first (debian/ubuntu)
    if let Ok((code, _)) = exec_in_container(id, &["curl", "-sf", "-o", "/dev/null", "-m", "2", &url]) {
        return Ok(code == 0);
    }
    // Fallback to wget (alpine)
    if let Ok((code, _)) = exec_in_container(id, &["wget", "-q", "-O", "/dev/null", "-T", "2", &url]) {
        return Ok(code == 0);
    }
    // Last resort: check if port is listening
    if let Ok((code, _)) = exec_in_container(id, &["sh", "-c", &format!("echo > /dev/tcp/localhost/{port}")]) {
        return Ok(code == 0);
    }
    Err("No http check tool available in container".to_string())
}

/// Get stderr-only logs
pub fn get_stderr_logs(id: &str, tail: u32) -> Result<String, String> {
    docker_request("GET", &format!("/containers/{id}/logs?stdout=false&stderr=true&tail={tail}"), None)
}

/// Get real CPU and memory stats from a running container
pub fn container_stats(id: &str) -> Result<(f32, f32), String> {
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
pub fn stream_logs_to_channel(id: &str, tail: u32, tx: tokio::sync::mpsc::Sender<bytes::Bytes>) {
    let path = format!("/containers/{id}/logs?stdout=true&stderr=true&tail={tail}&follow=true");

    let mut stream = match UnixStream::connect(docker_sock()) {
        Ok(s) => s,
        Err(_) => return,
    };

    // No read timeout for streaming — block until data arrives
    stream.set_read_timeout(Some(Duration::from_secs(300))).ok();

    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() { return; }

    // Skip HTTP headers
    let mut hdr = Vec::new();
    let mut one = [0u8; 1];
    loop {
        if stream.read_exact(&mut one).is_err() { return; }
        hdr.push(one[0]);
        if hdr.len() >= 4 && &hdr[hdr.len()-4..] == b"\r\n\r\n" { break; }
        if hdr.len() > 8192 { return; } // sanity
    }

    // Read Docker multiplexed log frames
    let mut frame_hdr = [0u8; 8];
    loop {
        match stream.read_exact(&mut frame_hdr) {
            Ok(_) => {}
            Err(_) => return, // connection closed or timeout
        }

        // frame_hdr[0] = stream type (1=stdout, 2=stderr)
        let size = ((frame_hdr[4] as usize) << 24)
                 | ((frame_hdr[5] as usize) << 16)
                 | ((frame_hdr[6] as usize) << 8)
                 | (frame_hdr[7] as usize);

        if size == 0 || size > 1_000_000 { continue; } // skip empty or suspicious

        let mut data = vec![0u8; size];
        if stream.read_exact(&mut data).is_err() { return; }

        if tx.blocking_send(bytes::Bytes::from(data)).is_err() {
            return; // client disconnected
        }
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
    // Build a single sh script: install iptables (cached after first run),
    // then apply each rule. `|| true` on flush so a fresh chain doesn't error.
    let mut script = String::from("apk add --no-cache iptables >/dev/null 2>&1; ");
    for r in rules {
        script.push_str("iptables ");
        script.push_str(&r.join(" "));
        script.push_str(" 2>/dev/null || true; ");
    }
    let body = serde_json::json!({
        "Image": "alpine:3.21",
        "Cmd": ["sh", "-c", script],
        "HostConfig": {
            "NetworkMode": format!("container:{pod_id}"),
            "CapAdd": ["NET_ADMIN"],
            "AutoRemove": true,
        },
    }).to_string();
    let resp = docker_request("POST", "/containers/create", Some(&body))?;
    let id = serde_json::from_str::<serde_json::Value>(&resp).ok()
        .and_then(|v| v.get("Id").and_then(|i| i.as_str()).map(|s| s.to_string()))
        .ok_or_else(|| format!("netns helper create failed: {resp}"))?;
    start_container(&id)?;
    // Wait briefly for it to finish (rules applied) — it exits on its own.
    for _ in 0..30 {
        match docker_request("GET", &format!("/containers/{id}/json"), None) {
            Ok(j) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&j) {
                    if v["State"]["Running"].as_bool() == Some(false) { break; }
                }
            }
            Err(_) => break, // AutoRemove already cleaned it up = done
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    Ok(())
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
pub fn build_image(context_dir: &str, dockerfile: &str, tag: &str) -> Result<String, String> {
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
    let path = format!("/build?t={t}&dockerfile={df}&rm=1&forcerm=1");

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
        match stream.read(&mut buf) {
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

    match err {
        Some(e) => Err(e.trim().to_string()),
        None => Ok(logbuf),
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
pub fn start_build(job: &str, context_dir: String, dockerfile: String, tag: String) {
    let mut map = build_jobs().lock().unwrap();
    if map.contains_key(job) { return; }
    let slot: Arc<Mutex<Option<Result<String, String>>>> = Arc::new(Mutex::new(None));
    map.insert(job.to_string(), slot.clone());
    drop(map);
    std::thread::spawn(move || {
        let result = build_image(&context_dir, &dockerfile, &tag);
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
