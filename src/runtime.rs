#![allow(dead_code)]
//! Runtime Abstraction — interface for container runtimes.
//!
//! Supports multiple backends:
//!   - Docker (via Unix socket, current default)
//!   - CRI (Container Runtime Interface — CRI-O, containerd)
//!   - NeuroDock (our neural container runtime, future)
//!
//! The reconcile loop talks to this trait, not docker.rs directly.
//! This means we can swap runtimes without changing orchestration logic.

use crate::docker;

/// Container info (runtime-agnostic)
#[derive(Debug, Clone)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub image: String,
    pub state: ContainerState,
    pub status: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ContainerState {
    Running,
    Stopped,
    Exited,
    Unknown,
}

/// Runtime capabilities
pub trait ContainerRuntime {
    fn name(&self) -> &str;
    fn ping(&self) -> bool;
    fn list(&self, all: bool) -> Result<Vec<Container>, String>;
    fn create(&self, name: &str, image: &str, cmd: Option<&[&str]>, env: &[String], labels: &[(&str, &str)]) -> Result<String, String>;
    fn start(&self, id: &str) -> Result<(), String>;
    fn stop(&self, id: &str) -> Result<(), String>;
    fn remove(&self, id: &str, force: bool) -> Result<(), String>;
    fn pull(&self, image: &str) -> Result<(), String>;
    fn logs(&self, id: &str, tail: u32) -> Result<String, String>;
    fn stats(&self, id: &str) -> Result<(f32, f32), String>;
    fn exec(&self, id: &str, cmd: &[&str]) -> Result<(i64, String), String>;
    fn ensure_network(&self) -> Result<(), String>;
    fn connect_network(&self, id: &str, aliases: &[&str]) -> Result<(), String>;
}

/// Docker runtime — talks to /var/run/docker.sock
pub struct DockerRuntime;

impl ContainerRuntime for DockerRuntime {
    fn name(&self) -> &str { "docker" }

    fn ping(&self) -> bool { docker::ping() }

    fn list(&self, all: bool) -> Result<Vec<Container>, String> {
        docker::list_containers(all).map(|cs| {
            cs.into_iter().map(|c| Container {
                id: c.id,
                name: c.names.first().map(|s| s.trim_start_matches('/').to_string()).unwrap_or_default(),
                image: c.image,
                state: match c.state.as_str() {
                    "running" => ContainerState::Running,
                    "exited" => ContainerState::Exited,
                    _ => ContainerState::Unknown,
                },
                status: c.status,
            }).collect()
        })
    }

    fn create(&self, name: &str, image: &str, cmd: Option<&[&str]>, env: &[String], labels: &[(&str, &str)]) -> Result<String, String> {
        docker::create_container(name, image, cmd, env, labels)
    }

    fn start(&self, id: &str) -> Result<(), String> { docker::start_container(id) }
    fn stop(&self, id: &str) -> Result<(), String> { docker::stop_container(id) }
    fn remove(&self, id: &str, force: bool) -> Result<(), String> { docker::remove_container(id, force) }
    fn pull(&self, image: &str) -> Result<(), String> { docker::pull_image(image) }
    fn logs(&self, id: &str, tail: u32) -> Result<String, String> { docker::get_logs(id, tail) }
    fn stats(&self, id: &str) -> Result<(f32, f32), String> { docker::container_stats(id) }
    fn exec(&self, id: &str, cmd: &[&str]) -> Result<(i64, String), String> { docker::exec_in_container(id, cmd) }
    fn ensure_network(&self) -> Result<(), String> { docker::ensure_network() }
    fn connect_network(&self, id: &str, aliases: &[&str]) -> Result<(), String> { docker::connect_network(id, aliases) }
}

/// CRI runtime stub — for CRI-O / containerd (via CRI gRPC protocol)
pub struct CriRuntime {
    pub socket: String,
}

impl CriRuntime {
    #[allow(dead_code)]
    pub fn new(socket: &str) -> Self {
        CriRuntime { socket: socket.to_string() }
    }
}

impl ContainerRuntime for CriRuntime {
    fn name(&self) -> &str { "cri" }
    fn ping(&self) -> bool { std::path::Path::new(&self.socket).exists() }
    fn list(&self, _all: bool) -> Result<Vec<Container>, String> {
        Err("CRI runtime: not yet implemented — use Docker for now".to_string())
    }
    fn create(&self, _name: &str, _image: &str, _cmd: Option<&[&str]>, _env: &[String], _labels: &[(&str, &str)]) -> Result<String, String> {
        Err("CRI runtime: create not implemented".to_string())
    }
    fn start(&self, _id: &str) -> Result<(), String> { Err("CRI: not implemented".to_string()) }
    fn stop(&self, _id: &str) -> Result<(), String> { Err("CRI: not implemented".to_string()) }
    fn remove(&self, _id: &str, _force: bool) -> Result<(), String> { Err("CRI: not implemented".to_string()) }
    fn pull(&self, _image: &str) -> Result<(), String> { Err("CRI: not implemented".to_string()) }
    fn logs(&self, _id: &str, _tail: u32) -> Result<String, String> { Err("CRI: not implemented".to_string()) }
    fn stats(&self, _id: &str) -> Result<(f32, f32), String> { Err("CRI: not implemented".to_string()) }
    fn exec(&self, _id: &str, _cmd: &[&str]) -> Result<(i64, String), String> { Err("CRI: not implemented".to_string()) }
    fn ensure_network(&self) -> Result<(), String> { Ok(()) }
    fn connect_network(&self, _id: &str, _aliases: &[&str]) -> Result<(), String> { Ok(()) }
}

// ─── Light Runtime: OCI images + Linux namespaces, zero Docker ───
//
// Pull: Docker Hub registry v2 API via curl (HTTPS)
// Extract: tar layers → merged rootfs
// Run:
//   Linux + root:  unshare --pid --mount --uts --fork + chroot (full isolation)
//   Linux no root: process-based (Termux)
//   macOS:         process-based (dev fallback)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

struct LightContainer {
    name: String,
    image: String,
    rootfs: PathBuf,
    pid: Option<u32>,
    state: ContainerState,
    log_path: PathBuf,
    env: Vec<String>,
    cmd: Vec<String>,
}

pub struct LightRuntime {
    base_dir: PathBuf,
    containers: Mutex<HashMap<String, LightContainer>>,
}

impl LightRuntime {
    pub fn new() -> Self {
        let base = dirs_or_home().join(".royak");
        std::fs::create_dir_all(base.join("images")).ok();
        std::fs::create_dir_all(base.join("containers")).ok();
        std::fs::create_dir_all(base.join("logs")).ok();
        LightRuntime {
            base_dir: base,
            containers: Mutex::new(HashMap::new()),
        }
    }
}

fn dirs_or_home() -> PathBuf {
    std::env::var("HOME").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/tmp"))
}

/// Run a command, return (exit_code, stdout)
fn run_cmd(cmd: &str, args: &[&str]) -> Result<(i32, String), String> {
    let output = std::process::Command::new(cmd).args(args)
        .output().map_err(|e| format!("{cmd}: {e}"))?;
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if code != 0 && stdout.is_empty() { return Err(stderr); }
    Ok((code, stdout))
}

// ─── OCI Registry Pull (via curl) ───

fn oci_pull(image: &str, dest: &Path) -> Result<Vec<String>, String> {
    let (repo, tag) = parse_image_ref(image);
    let token = oci_get_token(&repo)?;

    // Get manifest (may be a manifest list for multi-arch)
    let manifest_path = dest.join("manifest.json");
    let (_, raw_manifest) = run_cmd("curl", &[
        "-sL", "-o", "-",
        "-H", &format!("Authorization: Bearer {token}"),
        "-H", "Accept: application/vnd.docker.distribution.manifest.list.v2+json,application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.index.v1+json,application/vnd.oci.image.manifest.v1+json",
        &format!("https://registry-1.docker.io/v2/{repo}/manifests/{tag}"),
    ])?;

    let raw: serde_json::Value = serde_json::from_str(&raw_manifest)
        .map_err(|e| format!("parse manifest: {e}"))?;

    // Resolve manifest list → platform-specific manifest
    let manifest_str = if raw.get("manifests").is_some() {
        // Fat manifest — find our platform
        let arch = std::env::consts::ARCH; // "aarch64" or "x86_64"
        let oci_arch = match arch { "aarch64" => "arm64", "x86_64" => "amd64", a => a };
        let digest = raw["manifests"].as_array()
            .and_then(|ms| ms.iter().find(|m| {
                let p = &m["platform"];
                p["os"].as_str() == Some("linux") && p["architecture"].as_str() == Some(oci_arch)
            }))
            .and_then(|m| m["digest"].as_str())
            .ok_or(format!("no manifest for linux/{oci_arch}"))?;
        eprintln!("    resolved linux/{oci_arch} → {}", &digest[..24]);
        let (_, platform_manifest) = run_cmd("curl", &[
            "-sL", "-o", "-",
            "-H", &format!("Authorization: Bearer {token}"),
            "-H", "Accept: application/vnd.docker.distribution.manifest.v2+json,application/vnd.oci.image.manifest.v1+json",
            &format!("https://registry-1.docker.io/v2/{repo}/manifests/{digest}"),
        ])?;
        platform_manifest
    } else {
        raw_manifest
    };

    std::fs::write(&manifest_path, &manifest_str).map_err(|e| format!("write manifest: {e}"))?;
    let manifest: serde_json::Value = serde_json::from_str(&manifest_str)
        .map_err(|e| format!("parse platform manifest: {e}"))?;

    // Get config (contains default Cmd, Env, Entrypoint)
    if let Some(config_digest) = manifest.get("config").and_then(|c| c["digest"].as_str()) {
        let (_, config_str) = run_cmd("curl", &[
            "-sL", "-o", "-",
            "-H", &format!("Authorization: Bearer {token}"),
            &format!("https://registry-1.docker.io/v2/{repo}/blobs/{config_digest}"),
        ])?;
        std::fs::write(dest.join("config.json"), &config_str).ok();
    }

    // Download layers
    let layers = manifest.get("layers").and_then(|l| l.as_array())
        .ok_or("no layers in manifest")?;

    let mut layer_paths = Vec::new();
    for (i, layer) in layers.iter().enumerate() {
        let digest = layer["digest"].as_str().ok_or("layer has no digest")?;
        let layer_file = dest.join(format!("layer-{i}.tar.gz"));
        if !layer_file.exists() {
            eprintln!("    pulling layer {}/{} ({})...", i + 1, layers.len(), &digest[7..19]);
            let (code, _) = run_cmd("curl", &[
                "-sL", "-o", layer_file.to_str().unwrap(),
                "-H", &format!("Authorization: Bearer {token}"),
                &format!("https://registry-1.docker.io/v2/{repo}/blobs/{digest}"),
            ])?;
            if code != 0 { return Err(format!("layer download failed: {digest}")); }
        }
        layer_paths.push(layer_file.to_string_lossy().to_string());
    }
    Ok(layer_paths)
}

fn oci_get_token(repo: &str) -> Result<String, String> {
    let (_, body) = run_cmd("curl", &[
        "-sL",
        &format!("https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"),
    ])?;
    let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| format!("token parse: {e}"))?;
    v["token"].as_str().map(|s| s.to_string()).ok_or("no token in response".into())
}

fn parse_image_ref(image: &str) -> (String, String) {
    let img = image.trim();
    let (name, tag) = if img.contains(':') {
        let parts: Vec<&str> = img.splitn(2, ':').collect();
        (parts[0], parts[1])
    } else {
        (img, "latest")
    };
    // Prepend library/ for official images (nginx → library/nginx)
    let repo = if name.contains('/') { name.to_string() } else { format!("library/{name}") };
    (repo, tag.to_string())
}

fn extract_rootfs(layers: &[String], rootfs: &Path) -> Result<(), String> {
    std::fs::create_dir_all(rootfs).map_err(|e| format!("mkdir rootfs: {e}"))?;
    for layer in layers {
        run_cmd("tar", &["xzf", layer, "-C", rootfs.to_str().unwrap()])
            .map_err(|e| format!("extract {layer}: {e}"))?;
    }
    Ok(())
}

fn read_image_config(image_dir: &Path) -> (Vec<String>, Vec<String>) {
    let config_path = image_dir.join("config.json");
    let config_str = std::fs::read_to_string(&config_path).unwrap_or_default();
    let config: serde_json::Value = serde_json::from_str(&config_str).unwrap_or_default();
    let cc = &config["config"];

    let entrypoint: Vec<String> = cc.get("Entrypoint")
        .and_then(|e| e.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let cmd: Vec<String> = cc.get("Cmd")
        .and_then(|e| e.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let env: Vec<String> = cc.get("Env")
        .and_then(|e| e.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let mut full_cmd = entrypoint;
    full_cmd.extend(cmd);
    (full_cmd, env)
}

// ─── Process Execution ───

#[cfg(target_os = "linux")]
fn spawn_isolated(rootfs: &Path, cmd: &[String], env: &[String], hostname: &str, log_path: &Path) -> Result<u32, String> {
    // Try unshare (full isolation) first, fall back to chroot, then direct exec
    let log_file = std::fs::File::create(log_path).map_err(|e| format!("log: {e}"))?;
    let log_err = log_file.try_clone().map_err(|e| format!("log clone: {e}"))?;

    let has_unshare = std::process::Command::new("unshare").arg("--help")
        .output().map(|o| o.status.success()).unwrap_or(false);

    let child = if has_unshare && nix_is_root() {
        // Full container isolation: PID + mount + UTS namespaces
        let mut args = vec!["--pid", "--mount", "--uts", "--fork", "--mount-proc"];
        let rootfs_str = rootfs.to_str().unwrap_or(".");
        // unshare ... chroot rootfs cmd...
        let mut full_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        full_args.push("chroot".to_string());
        full_args.push(rootfs_str.to_string());
        full_args.extend(cmd.iter().cloned());

        std::process::Command::new("unshare")
            .args(&full_args)
            .envs(env.iter().filter_map(|e| e.split_once('=')).map(|(k, v)| (k, v)))
            .stdout(log_file).stderr(log_err)
            .spawn().map_err(|e| format!("unshare: {e}"))?
    } else {
        // No root: just run the command with PATH pointing to rootfs binaries
        let path = format!("{}/usr/local/sbin:{}/usr/local/bin:{}/usr/sbin:{}/usr/bin:{}/sbin:{}/bin",
            rootfs.display(), rootfs.display(), rootfs.display(),
            rootfs.display(), rootfs.display(), rootfs.display());
        std::process::Command::new(&cmd[0])
            .args(&cmd[1..])
            .env("PATH", &path)
            .envs(env.iter().filter_map(|e| e.split_once('=')).map(|(k, v)| (k, v)))
            .stdout(log_file).stderr(log_err)
            .spawn().map_err(|e| format!("spawn: {e}"))?
    };
    Ok(child.id())
}

#[cfg(target_os = "linux")]
fn nix_is_root() -> bool {
    unsafe { libc::getuid() == 0 }
}

#[cfg(not(target_os = "linux"))]
fn spawn_isolated(rootfs: &Path, cmd: &[String], env: &[String], _hostname: &str, log_path: &Path) -> Result<u32, String> {
    // macOS / other: run process directly (no namespace isolation)
    let log_file = std::fs::File::create(log_path).map_err(|e| format!("log: {e}"))?;
    let log_err = log_file.try_clone().map_err(|e| format!("log clone: {e}"))?;

    // Try to find the binary in rootfs first, then system PATH
    let bin = if rootfs.join(&cmd[0].trim_start_matches('/')).exists() {
        rootfs.join(&cmd[0].trim_start_matches('/'))
    } else {
        PathBuf::from(&cmd[0])
    };

    let child = std::process::Command::new(&bin)
        .args(&cmd[1..])
        .envs(env.iter().filter_map(|e| e.split_once('=')).map(|(k, v)| (k, v)))
        .stdout(log_file).stderr(log_err)
        .spawn().map_err(|e| format!("spawn {}: {e}", bin.display()))?;
    Ok(child.id())
}

// ─── ContainerRuntime implementation ───

impl ContainerRuntime for LightRuntime {
    fn name(&self) -> &str { "light" }

    fn ping(&self) -> bool {
        // Check curl is available (needed for registry pull)
        run_cmd("curl", &["--version"]).is_ok()
    }

    fn list(&self, _all: bool) -> Result<Vec<Container>, String> {
        let cs = self.containers.lock().map_err(|e| e.to_string())?;
        Ok(cs.values().map(|c| {
            let alive = c.pid.map(|p| is_pid_alive(p)).unwrap_or(false);
            Container {
                id: c.pid.map(|p| p.to_string()).unwrap_or_else(|| "none".into()),
                name: c.name.clone(),
                image: c.image.clone(),
                state: if alive { ContainerState::Running } else { ContainerState::Exited },
                status: if alive { "running".into() } else { "exited".into() },
            }
        }).collect())
    }

    fn create(&self, name: &str, image: &str, cmd: Option<&[&str]>, env: &[String], _labels: &[(&str, &str)]) -> Result<String, String> {
        let image_dir = self.base_dir.join("images").join(image.replace([':', '/'], "_"));
        let rootfs = self.base_dir.join("containers").join(name).join("rootfs");
        let log_path = self.base_dir.join("logs").join(format!("{name}.log"));

        // Pull if not cached
        if !image_dir.join("manifest.json").exists() {
            eprintln!("  [light] pulling {image}...");
            std::fs::create_dir_all(&image_dir).ok();
            let layers = oci_pull(image, &image_dir)?;
            eprintln!("  [light] extracting {} layers...", layers.len());
            extract_rootfs(&layers, &rootfs)?;
        } else if !rootfs.exists() {
            // Image cached but rootfs not extracted for this container
            let layers: Vec<String> = std::fs::read_dir(&image_dir).ok()
                .map(|rd| rd.filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().map(|x| x == "gz").unwrap_or(false))
                    .map(|e| e.path().to_string_lossy().to_string())
                    .collect::<Vec<_>>())
                .unwrap_or_default();
            if !layers.is_empty() {
                extract_rootfs(&layers, &rootfs)?;
            }
        }

        // Read default cmd/env from image config
        let (default_cmd, default_env) = read_image_config(&image_dir);
        let run_cmd_vec: Vec<String> = if let Some(c) = cmd {
            c.iter().map(|s| s.to_string()).collect()
        } else {
            default_cmd
        };
        let mut run_env = default_env;
        run_env.extend(env.iter().cloned());

        let mut cs = self.containers.lock().map_err(|e| e.to_string())?;
        cs.insert(name.to_string(), LightContainer {
            name: name.to_string(),
            image: image.to_string(),
            rootfs,
            pid: None,
            state: ContainerState::Stopped,
            log_path,
            env: run_env,
            cmd: run_cmd_vec,
        });
        Ok(format!("light:{name}"))
    }

    fn start(&self, id: &str) -> Result<(), String> {
        let mut cs = self.containers.lock().map_err(|e| e.to_string())?;
        let name = id.strip_prefix("light:").unwrap_or(id);
        let c = cs.get_mut(name).ok_or(format!("container {name} not found"))?;
        if c.cmd.is_empty() { return Err("no command configured".into()); }
        let pid = spawn_isolated(&c.rootfs, &c.cmd, &c.env, name, &c.log_path)?;
        c.pid = Some(pid);
        c.state = ContainerState::Running;
        Ok(())
    }

    fn stop(&self, id: &str) -> Result<(), String> {
        let mut cs = self.containers.lock().map_err(|e| e.to_string())?;
        let name = id.strip_prefix("light:").unwrap_or(id);
        if let Some(c) = cs.get_mut(name) {
            if let Some(pid) = c.pid {
                kill_pid(pid);
                c.state = ContainerState::Exited;
                c.pid = None;
            }
        }
        Ok(())
    }

    fn remove(&self, id: &str, _force: bool) -> Result<(), String> {
        self.stop(id).ok();
        let mut cs = self.containers.lock().map_err(|e| e.to_string())?;
        let name = id.strip_prefix("light:").unwrap_or(id);
        if let Some(c) = cs.remove(name) {
            std::fs::remove_dir_all(c.rootfs.parent().unwrap_or(&c.rootfs)).ok();
        }
        Ok(())
    }

    fn pull(&self, image: &str) -> Result<(), String> {
        let image_dir = self.base_dir.join("images").join(image.replace([':', '/'], "_"));
        if image_dir.join("manifest.json").exists() { return Ok(()); }
        std::fs::create_dir_all(&image_dir).ok();
        oci_pull(image, &image_dir)?;
        Ok(())
    }

    fn logs(&self, id: &str, tail: u32) -> Result<String, String> {
        let cs = self.containers.lock().map_err(|e| e.to_string())?;
        let name = id.strip_prefix("light:").unwrap_or(id);
        let c = cs.get(name).ok_or(format!("container {name} not found"))?;
        let content = std::fs::read_to_string(&c.log_path).unwrap_or_default();
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(tail as usize);
        Ok(lines[start..].join("\n"))
    }

    fn stats(&self, id: &str) -> Result<(f32, f32), String> {
        let cs = self.containers.lock().map_err(|e| e.to_string())?;
        let name = id.strip_prefix("light:").unwrap_or(id);
        let c = cs.get(name).ok_or(format!("container {name} not found"))?;
        match c.pid {
            Some(pid) => pid_stats(pid),
            None => Ok((0.0, 0.0)),
        }
    }

    fn exec(&self, id: &str, cmd: &[&str]) -> Result<(i64, String), String> {
        let cs = self.containers.lock().map_err(|e| e.to_string())?;
        let name = id.strip_prefix("light:").unwrap_or(id);
        let _c = cs.get(name).ok_or(format!("container {name} not found"))?;
        if cmd.is_empty() { return Err("empty command".into()); }
        let (code, out) = run_cmd(cmd[0], &cmd[1..])?;
        Ok((code as i64, out))
    }

    fn ensure_network(&self) -> Result<(), String> { Ok(()) } // host networking
    fn connect_network(&self, _id: &str, _aliases: &[&str]) -> Result<(), String> { Ok(()) }
}

// ─── Platform helpers ───

fn is_pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

fn kill_pid(pid: u32) {
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
        // Give 3s to exit gracefully, then SIGKILL
        std::thread::sleep(std::time::Duration::from_secs(3));
        libc::kill(pid as i32, libc::SIGKILL);
    }
}

#[cfg(target_os = "linux")]
fn pid_stats(pid: u32) -> Result<(f32, f32), String> {
    // Read from /proc/{pid}/stat and /proc/{pid}/status
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let mem_kb: f32 = status.lines()
        .find(|l| l.starts_with("VmRSS:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);
    Ok((1.0, mem_kb / 1024.0)) // rough CPU=1%, mem in MB
}

#[cfg(not(target_os = "linux"))]
fn pid_stats(pid: u32) -> Result<(f32, f32), String> {
    let (_, out) = run_cmd("ps", &["-p", &pid.to_string(), "-o", "%cpu,%mem"])?;
    let line = out.lines().nth(1).unwrap_or("0 0");
    let parts: Vec<f32> = line.split_whitespace().filter_map(|s| s.parse().ok()).collect();
    Ok((*parts.first().unwrap_or(&0.0), *parts.get(1).unwrap_or(&0.0)))
}

// ─── NeuroPod: App + self-growing persistent disk in one unit ───
//
// Flow: Docker image → OCI pull → rootfs + sparse data disk → deploy
// No Docker daemon at runtime. Just Linux syscalls.

pub struct NeuroPod {
    pub name: String,
    pub image: String,
    pub base_dir: PathBuf,
    pub rootfs: PathBuf,       // effective rootfs (merged on Linux, direct on macOS)
    pub image_rootfs: PathBuf, // shared read-only image rootfs
    pub upper_dir: PathBuf,    // per-pod overlay upper (copy-on-write changes)
    pub data_img: PathBuf,
    pub data_mount: PathBuf,
    pub disk_size_bytes: u64,
    pub mount_path: String,
    pub pid: Option<u32>,
    pub overlay_mounted: bool,
}

impl NeuroPod {
    /// Create a NeuroPod from a Docker image with a self-growing persistent disk.
    ///
    /// Storage architecture:
    ///   Image rootfs:  ~/.royak/images/{image}/rootfs  (shared, read-only)
    ///   Pod overlay:   ~/.royak/pods/{name}/upper      (per-pod changes only)
    ///   Merged view:   ~/.royak/pods/{name}/merged     (OverlayFS on Linux)
    ///   Data disk:     ~/.royak/pods/{name}/data.img   (sparse, self-growing)
    ///
    /// 10 pods from same image = 1 rootfs copy + 10 tiny overlay dirs.
    pub fn create(name: &str, image: &str, disk_size_mb: u64, mount_path: &str) -> Result<Self, String> {
        let base = dirs_or_home().join(".royak").join("pods").join(name);
        let upper_dir = base.join("upper");
        let work_dir = base.join("work");
        let merged = base.join("merged");
        let data_img = base.join("data.img");
        let data_mount = base.join("data");

        std::fs::create_dir_all(&upper_dir).map_err(|e| format!("mkdir upper: {e}"))?;
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("mkdir work: {e}"))?;
        std::fs::create_dir_all(&merged).map_err(|e| format!("mkdir merged: {e}"))?;
        std::fs::create_dir_all(&data_mount).map_err(|e| format!("mkdir data: {e}"))?;

        // Pull OCI image → shared rootfs (one per image, reused by all pods)
        let image_dir = dirs_or_home().join(".royak").join("images")
            .join(image.replace([':', '/'], "_"));
        let image_rootfs = image_dir.join("rootfs");

        if !image_rootfs.exists() {
            std::fs::create_dir_all(&image_dir).ok();
            eprintln!("  [neuropod] pulling {image}...");
            let layers = oci_pull(image, &image_dir)?;
            eprintln!("  [neuropod] extracting {} layers → shared rootfs", layers.len());
            extract_rootfs(&layers, &image_rootfs)?;
        } else {
            eprintln!("  [neuropod] image cached: {image}");
        }

        // Mount OverlayFS: shared image (lower) + pod changes (upper) → merged view
        #[cfg(target_os = "linux")]
        let overlay_mounted = {
            let lower = image_rootfs.to_str().unwrap_or(".");
            let upper = upper_dir.to_str().unwrap_or(".");
            let work = work_dir.to_str().unwrap_or(".");
            let mnt = merged.to_str().unwrap_or(".");
            let opts = format!("lowerdir={lower},upperdir={upper},workdir={work}");
            if run_cmd("mount", &["-t", "overlay", "overlay", "-o", &opts, mnt]).is_ok() {
                eprintln!("  [neuropod] overlayfs mounted (shared image + pod overlay)");
                true
            } else {
                eprintln!("  [neuropod] overlayfs failed (need root), using direct rootfs");
                false
            }
        };
        #[cfg(not(target_os = "linux"))]
        let overlay_mounted = false;

        // Effective rootfs: merged (overlay) or shared image (fallback)
        let effective_rootfs = if overlay_mounted {
            merged.clone()
        } else {
            image_rootfs.clone()
        };

        // Create sparse data disk (thin provisioned — occupies 0 bytes until written)
        if !data_img.exists() {
            let disk_bytes = disk_size_mb * 1024 * 1024;
            eprintln!("  [neuropod] creating sparse disk: {}MB (thin)", disk_size_mb);
            let f = std::fs::File::create(&data_img).map_err(|e| format!("create disk: {e}"))?;
            f.set_len(disk_bytes).map_err(|e| format!("truncate: {e}"))?;

            // Format as ext4 on Linux
            #[cfg(target_os = "linux")]
            {
                let img_str = data_img.to_str().unwrap_or("data.img");
                run_cmd("mkfs.ext4", &["-q", "-F", img_str])
                    .map_err(|e| format!("mkfs: {e}"))?;
                eprintln!("  [neuropod] formatted ext4");
            }
        }

        // Save metadata
        let meta = serde_json::json!({
            "name": name, "image": image,
            "diskSizeMB": disk_size_mb,
            "mountPath": mount_path,
            "created": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(),
        });
        std::fs::write(base.join("meta.json"), serde_json::to_string_pretty(&meta).unwrap_or_default()).ok();

        Ok(NeuroPod {
            name: name.to_string(),
            image: image.to_string(),
            base_dir: base,
            rootfs: effective_rootfs,
            image_rootfs,
            upper_dir,
            data_img, data_mount,
            disk_size_bytes: disk_size_mb * 1024 * 1024,
            mount_path: mount_path.to_string(),
            pid: None,
            overlay_mounted,
        })
    }

    /// Mount the data disk and start the NeuroPod
    pub fn start(&mut self, cmd: Option<&[&str]>, env: &[String]) -> Result<u32, String> {
        // Mount data disk via loop device (Linux)
        #[cfg(target_os = "linux")]
        {
            let img = self.data_img.to_str().unwrap_or("");
            let mnt = self.data_mount.to_str().unwrap_or("");
            run_cmd("mount", &["-o", "loop", img, mnt])
                .map_err(|e| format!("mount data disk: {e}"))?;
            eprintln!("  [neuropod] data disk mounted → {mnt}");

            // Bind-mount data into rootfs at mount_path
            let target = self.rootfs.join(self.mount_path.trim_start_matches('/'));
            std::fs::create_dir_all(&target).ok();
            let target_str = target.to_str().unwrap_or("");
            run_cmd("mount", &["--bind", mnt, target_str])
                .map_err(|e| format!("bind mount: {e}"))?;
        }

        // macOS: just use the data directory directly (no loop mount)
        #[cfg(not(target_os = "linux"))]
        {
            let target = self.rootfs.join(self.mount_path.trim_start_matches('/'));
            std::fs::create_dir_all(&target).ok();
            // Symlink data dir into rootfs
            let data_str = self.data_mount.to_str().unwrap_or("");
            let _target_str = target.to_str().unwrap_or("");
            // Copy approach for macOS (no bind mount without root)
            if !target.join(".neuropod").exists() {
                std::os::unix::fs::symlink(data_str, target.join(".neuropod-data")).ok();
            }
        }

        // Read default cmd from image config
        let image_dir = dirs_or_home().join(".royak").join("images")
            .join(self.image.replace([':', '/'], "_"));
        let (default_cmd, default_env) = read_image_config(&image_dir);

        let run_cmd_vec: Vec<String> = if let Some(c) = cmd {
            c.iter().map(|s| s.to_string()).collect()
        } else {
            default_cmd
        };
        let mut run_env: Vec<String> = default_env;
        run_env.extend(env.iter().cloned());
        run_env.push(format!("NEUROPOD_NAME={}", self.name));
        run_env.push(format!("NEUROPOD_DATA={}", self.mount_path));

        // Set up DNS inside rootfs (resolv.conf, hosts, hostname)
        let other_pods = NeuroPod::list_all();
        let peers: Vec<(String, String)> = other_pods.iter()
            .filter(|(n, _, _, _, _)| n != &self.name)
            .map(|(n, _, _, _, _)| {
                // Read peer's IP from meta if available
                let peer_meta = dirs_or_home().join(".royak").join("pods").join(n).join("meta.json");
                let ip = std::fs::read_to_string(&peer_meta).ok()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                    .and_then(|v| v["ip"].as_str().map(|s| s.to_string()))
                    .unwrap_or_else(|| "10.42.0.2".to_string());
                (n.clone(), ip)
            })
            .collect();
        setup_pod_dns(&self.rootfs, &self.name, "10.42.0.2", &peers);

        let log_path = self.base_dir.join("neuropod.log");
        let pid = spawn_isolated(&self.rootfs, &run_cmd_vec, &run_env, &self.name, &log_path)?;
        self.pid = Some(pid);
        eprintln!("  [neuropod] {} started (pid={pid})", self.name);
        Ok(pid)
    }

    /// Stop the NeuroPod and unmount data disk + overlay
    pub fn stop(&mut self) {
        if let Some(pid) = self.pid.take() {
            kill_pid(pid);
            eprintln!("  [neuropod] {} stopped (pid={pid})", self.name);
        }

        #[cfg(target_os = "linux")]
        {
            // Unmount data bind
            let target = self.rootfs.join(self.mount_path.trim_start_matches('/'));
            run_cmd("umount", &[target.to_str().unwrap_or("")]).ok();
            // Unmount data disk loop
            run_cmd("umount", &[self.data_mount.to_str().unwrap_or("")]).ok();
            // Unmount overlay
            if self.overlay_mounted {
                run_cmd("umount", &[self.rootfs.to_str().unwrap_or("")]).ok();
                self.overlay_mounted = false;
                eprintln!("  [neuropod] overlay unmounted (changes saved in upper/)");
            }
        }
    }

    /// Get actual disk usage (not allocated size)
    pub fn disk_usage(&self) -> (u64, u64) {
        let actual = std::fs::metadata(&self.data_img)
            .map(|m| m.len())
            .unwrap_or(0);
        // On Linux, sparse file metadata.len() returns allocated size
        // Use du for actual on-disk usage
        let on_disk = run_cmd("du", &["-sb", self.data_img.to_str().unwrap_or("")])
            .ok()
            .and_then(|(_, out)| out.split_whitespace().next().and_then(|s| s.parse().ok()))
            .unwrap_or(actual);
        (on_disk, self.disk_size_bytes) // (used, max)
    }

    /// Get logs
    pub fn logs(&self, tail: u32) -> String {
        let log_path = self.base_dir.join("neuropod.log");
        let content = std::fs::read_to_string(&log_path).unwrap_or_default();
        let lines: Vec<&str> = content.lines().collect();
        let start = lines.len().saturating_sub(tail as usize);
        lines[start..].join("\n")
    }

    /// Is this NeuroPod running?
    pub fn is_running(&self) -> bool {
        self.pid.map(|p| is_pid_alive(p)).unwrap_or(false)
    }

    /// List all NeuroPods on disk
    pub fn list_all() -> Vec<(String, String, bool, u64, u64)> {
        let pods_dir = dirs_or_home().join(".royak").join("pods");
        let mut result = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&pods_dir) {
            for entry in entries.flatten() {
                let meta_path = entry.path().join("meta.json");
                if let Ok(meta_str) = std::fs::read_to_string(&meta_path) {
                    if let Ok(meta) = serde_json::from_str::<serde_json::Value>(&meta_str) {
                        let name = meta["name"].as_str().unwrap_or("?").to_string();
                        let image = meta["image"].as_str().unwrap_or("?").to_string();
                        let data_img = entry.path().join("data.img");
                        let (used, max) = if data_img.exists() {
                            let max = meta["diskSizeMB"].as_u64().unwrap_or(0) * 1024 * 1024;
                            let used = run_cmd("du", &["-sb", data_img.to_str().unwrap_or("")])
                                .ok()
                                .and_then(|(_, out)| out.split_whitespace().next().and_then(|s| s.parse().ok()))
                                .unwrap_or(0);
                            (used, max)
                        } else { (0, 0) };
                        // Check if running
                        let running = false; // would need PID tracking
                        result.push((name, image, running, used, max));
                    }
                }
            }
        }
        result
    }
}

// ─── NeuroPod Networking: isolated network per pod, bridge for pod-to-pod ───

const BRIDGE_NAME: &str = "rk-bridge";
const BRIDGE_SUBNET: &str = "10.42.0";
const BRIDGE_IP: &str = "10.42.0.1";

/// Pod network state
pub struct PodNetwork {
    pub pod_name: String,
    pub namespace: String,     // Linux network namespace name
    pub ip: String,            // e.g. "10.42.0.2"
    pub veth_host: String,     // veth end on host side
    pub veth_pod: String,      // veth end inside pod
    pub exposed_ports: Vec<(u16, u16)>, // (host_port, container_port)
}

/// Ensure the NeuroPod bridge network exists (once per host)
#[cfg(target_os = "linux")]
pub fn ensure_pod_bridge() -> Result<(), String> {
    // Check if bridge exists
    if run_cmd("ip", &["link", "show", BRIDGE_NAME]).is_ok() {
        return Ok(());
    }

    eprintln!("  [neuropod-net] creating bridge {BRIDGE_NAME} ({BRIDGE_IP}/16)");
    run_cmd("ip", &["link", "add", BRIDGE_NAME, "type", "bridge"])?;
    run_cmd("ip", &["addr", "add", &format!("{BRIDGE_IP}/16"), "dev", BRIDGE_NAME])?;
    run_cmd("ip", &["link", "set", BRIDGE_NAME, "up"])?;

    // Enable IP forwarding
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").ok();

    // NAT for outbound (pods → internet)
    run_cmd("iptables", &["-t", "nat", "-A", "POSTROUTING",
        "-s", &format!("{BRIDGE_SUBNET}.0/16"), "-j", "MASQUERADE"]).ok();

    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn ensure_pod_bridge() -> Result<(), String> {
    Ok(()) // host networking on non-Linux
}

/// Create isolated network for a NeuroPod
#[cfg(target_os = "linux")]
pub fn create_pod_network(name: &str, pod_index: u32, ports: &[(u16, u16)]) -> Result<PodNetwork, String> {
    ensure_pod_bridge()?;

    let ns_name = format!("rk-{name}");
    let ip = format!("{BRIDGE_SUBNET}.{}", pod_index + 2); // .2, .3, .4, ...
    let veth_host = format!("veth-{}", &name[..name.len().min(8)]);
    let veth_pod = format!("vp-{}", &name[..name.len().min(10)]);

    eprintln!("  [neuropod-net] creating network namespace {ns_name} ({ip})");

    // Create network namespace
    run_cmd("ip", &["netns", "add", &ns_name])?;

    // Create veth pair
    run_cmd("ip", &["link", "add", &veth_host, "type", "veth", "peer", "name", &veth_pod])?;

    // Move pod-end into namespace
    run_cmd("ip", &["link", "set", &veth_pod, "netns", &ns_name])?;

    // Connect host-end to bridge
    run_cmd("ip", &["link", "set", &veth_host, "master", BRIDGE_NAME])?;
    run_cmd("ip", &["link", "set", &veth_host, "up"])?;

    // Configure IP inside namespace
    run_cmd("ip", &["netns", "exec", &ns_name, "ip", "addr", "add", &format!("{ip}/16"), "dev", &veth_pod])?;
    run_cmd("ip", &["netns", "exec", &ns_name, "ip", "link", "set", &veth_pod, "up"])?;
    run_cmd("ip", &["netns", "exec", &ns_name, "ip", "link", "set", "lo", "up"])?;
    run_cmd("ip", &["netns", "exec", &ns_name, "ip", "route", "add", "default", "via", BRIDGE_IP])?;

    // Port forwarding: host:port → pod:port
    for (host_port, container_port) in ports {
        eprintln!("  [neuropod-net] expose :{host_port} → {ip}:{container_port}");
        run_cmd("iptables", &["-t", "nat", "-A", "PREROUTING", "-p", "tcp",
            "--dport", &host_port.to_string(), "-j", "DNAT",
            "--to-destination", &format!("{ip}:{container_port}")])?;
        run_cmd("iptables", &["-A", "FORWARD", "-p", "tcp",
            "-d", &ip, "--dport", &container_port.to_string(), "-j", "ACCEPT"])?;
        // Also for localhost access
        run_cmd("iptables", &["-t", "nat", "-A", "OUTPUT", "-p", "tcp",
            "-o", "lo", "--dport", &host_port.to_string(), "-j", "DNAT",
            "--to-destination", &format!("{ip}:{container_port}")])?;
    }

    Ok(PodNetwork {
        pod_name: name.to_string(),
        namespace: ns_name,
        ip,
        veth_host,
        veth_pod,
        exposed_ports: ports.to_vec(),
    })
}

#[cfg(not(target_os = "linux"))]
pub fn create_pod_network(name: &str, _pod_index: u32, _ports: &[(u16, u16)]) -> Result<PodNetwork, String> {
    // macOS: no network namespace, use host networking
    Ok(PodNetwork {
        pod_name: name.to_string(),
        namespace: String::new(),
        ip: "127.0.0.1".to_string(),
        veth_host: String::new(),
        veth_pod: String::new(),
        exposed_ports: vec![],
    })
}

/// Clean up pod network on stop
#[cfg(target_os = "linux")]
pub fn destroy_pod_network(net: &PodNetwork) {
    // Remove port forwarding
    for (host_port, container_port) in &net.exposed_ports {
        run_cmd("iptables", &["-t", "nat", "-D", "PREROUTING", "-p", "tcp",
            "--dport", &host_port.to_string(), "-j", "DNAT",
            "--to-destination", &format!("{}:{container_port}", net.ip)]).ok();
        run_cmd("iptables", &["-D", "FORWARD", "-p", "tcp",
            "-d", &net.ip, "--dport", &container_port.to_string(), "-j", "ACCEPT"]).ok();
        run_cmd("iptables", &["-t", "nat", "-D", "OUTPUT", "-p", "tcp",
            "-o", "lo", "--dport", &host_port.to_string(), "-j", "DNAT",
            "--to-destination", &format!("{}:{container_port}", net.ip)]).ok();
    }
    // Delete veth (automatically removes pair)
    run_cmd("ip", &["link", "del", &net.veth_host]).ok();
    // Delete namespace
    run_cmd("ip", &["netns", "del", &net.namespace]).ok();
    eprintln!("  [neuropod-net] cleaned up {} ({})", net.pod_name, net.ip);
}

#[cfg(not(target_os = "linux"))]
pub fn destroy_pod_network(_net: &PodNetwork) {}

/// Write DNS config inside pod rootfs
pub fn setup_pod_dns(rootfs: &Path, pod_name: &str, pod_ip: &str, peers: &[(String, String)]) {
    let etc = rootfs.join("etc");
    std::fs::create_dir_all(&etc).ok();

    // /etc/resolv.conf — use host DNS
    let resolv = "nameserver 8.8.8.8\nnameserver 1.1.1.1\nsearch royak.local\n";
    std::fs::write(etc.join("resolv.conf"), resolv).ok();

    // /etc/hosts — pod name + peers for service discovery
    let mut hosts = format!("127.0.0.1 localhost\n{pod_ip} {pod_name} {pod_name}.royak.local\n");
    for (name, ip) in peers {
        hosts.push_str(&format!("{ip} {name} {name}.royak.local\n"));
    }
    std::fs::write(etc.join("hosts"), hosts).ok();

    // /etc/hostname
    std::fs::write(etc.join("hostname"), pod_name).ok();
}

/// Get runtime by name
pub fn get_runtime(name: &str) -> Box<dyn ContainerRuntime> {
    match name {
        "light" => Box::new(LightRuntime::new()),
        "cri" | "cri-o" | "containerd" => Box::new(CriRuntime::new("/var/run/crio/crio.sock")),
        _ => Box::new(DockerRuntime),
    }
}
