//! Test-only support. No production identity or journal-path override.
//! ROOT alone runs the Linux branch inside the owned no-host-socket runtime.
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub(super) const SCOPE: &str = "ROYAK_EXEC_FIXTURE_SCOPE";
pub(super) const OWNED: &str = "owned-no-host-socket-linux-runtime-v4_2";
const JOURNAL: &str = "/var/lib/royak/exec-admission";
const SUITE_LOCK: &str = "/var/lib/royak/exec-fixture-v4_2.lock";

struct Image {
    dir: PathBuf,
    exe: PathBuf,
}
impl Image {
    fn new() -> Self {
        let dir = std::fs::canonicalize("/tmp").unwrap().join(format!(
            "rkf-{}", crate::storage_identity::Uid::new().as_str()
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let exe = dir.join("dockerd");
        std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { dir, exe }
    }
}
impl Drop for Image {
    fn drop(&mut self) {
        // Exact created files only; no recursive deletion of an arbitrary path.
        cleanup(std::fs::remove_file(&self.exe), "copied fixture image");
        cleanup(std::fs::remove_dir(&self.dir), "fixture image directory");
    }
}

pub(super) fn isolated(module: &str, name: &str, key: &str, admission: bool) -> bool {
    let path = format!("{module}::{name}");
    let test = path.split_once("::").unwrap().1;
    if std::env::var(key).ok().as_deref() == Some(test) {
        #[cfg(not(target_os = "linux"))]
        if admission {
            native_refusal(test);
            return true;
        }
        #[cfg(target_os = "linux")]
        if admission {
            assert_eq!(std::env::var(SCOPE).ok().as_deref(), Some(OWNED),
                "fixture admission is authorized only inside the owned Linux test runtime");
            assert_eq!(unsafe { libc::geteuid() }, 0, "never skip nonroot Linux execution");
            let exe = std::fs::read_link("/proc/self/exe").unwrap();
            assert_eq!(exe.file_name().unwrap(), "dockerd");
        }
        return false;
    }
    let image = Image::new();
    let output = std::process::Command::new(&image.exe)
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(key, test).env_remove("DOCKER_HOST").output().unwrap();
    assert!(output.status.success(), "isolated exact fixture failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    true
}

#[cfg(not(target_os = "linux"))]
fn native_refusal(test: &str) {
    let dir = std::fs::canonicalize("/tmp").unwrap().join(format!(
        "rkn-{}", crate::storage_identity::Uid::new().as_str()
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let socket = dir.join("s");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    std::env::set_var("DOCKER_HOST", format!("unix://{}", socket.display()));
    let cancel = crate::docker::SocketCancellation::default();
    let result = crate::docker::exec_hijack(&"a".repeat(64), &["cat"], false, &cancel);
    let error = result.err().expect("non-Linux adapter must refuse admission");
    assert!(crate::docker::exec_admission_unknown(&error) && error.contains("Linux"), "{error}");
    assert!(!cancel.has_execs(), "unsupported adapter must not register a fake exec");
    assert!(matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "unsupported adapter must not connect or issue any POST");
    std::env::remove_var("DOCKER_HOST");
    drop(listener);
    std::fs::remove_file(socket).unwrap();
    std::fs::remove_dir(dir).unwrap();
    eprintln!("NATIVE_FAIL_CLOSED={test}; original_race_semantics=Linux_only; post_count=0");
}

/// The production fixed journal path is intentionally unchanged. Only these
/// five fixture cases serialize against each other; the full suite is parallel.
pub(super) struct JournalScope {
    #[cfg(target_os = "linux")]
    agent: Option<crate::docker::RecoveryAgent>,
    #[cfg(target_os = "linux")]
    _lock: File,
    #[cfg(target_os = "linux")]
    directory: (u64, u64),
    #[cfg(target_os = "linux")]
    socket: Option<(u64, u64)>,
}
impl JournalScope {
    pub(super) fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            assert_eq!(std::env::var(SCOPE).ok().as_deref(), Some(OWNED),
                "never create a host journal from a native/unscoped test");
            assert_eq!(unsafe { libc::geteuid() }, 0);
            let parent = Path::new("/var/lib/royak");
            if let Err(error) = std::fs::DirBuilder::new().mode(0o700).create(parent) {
                assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
            }
            for path in [Path::new("/var"), Path::new("/var/lib"), parent] {
                let m = std::fs::symlink_metadata(path).unwrap();
                assert!(m.is_dir() && m.uid() == 0 && m.mode() & 0o022 == 0,
                    "fixture ancestor is not trusted: {}", path.display());
            }
            let lock = OpenOptions::new().read(true).write(true).create(true).mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(SUITE_LOCK).unwrap();
            let m = lock.metadata().unwrap();
            assert!(m.is_file() && m.uid() == 0 && m.mode() & 0o077 == 0 && m.nlink() == 1 && m.len() == 0);
            let deadline = Instant::now() + Duration::from_secs(30);
            loop {
                if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 { break; }
                let error = std::io::Error::last_os_error();
                assert!(matches!(error.raw_os_error(), Some(libc::EWOULDBLOCK)), "{error}");
                assert!(Instant::now() < deadline, "bounded fixture journal lease unavailable");
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(matches!(std::fs::symlink_metadata(JOURNAL), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
                "preexisting journal state must be preserved, never deleted or adopted by a fixture");
            std::fs::DirBuilder::new().mode(0o700).create(JOURNAL).unwrap();
            let m = std::fs::symlink_metadata(JOURNAL).unwrap();
            return Self { agent: None, _lock: lock, directory: (m.dev(), m.ino()), socket: None };
        }
        #[cfg(not(target_os = "linux"))]
        Self {}
    }
    pub(super) fn pin_socket(&mut self, path: &Path) {
        #[cfg(target_os = "linux")]
        {
            let m = std::fs::symlink_metadata(path).unwrap();
            self.socket = Some((m.dev(), m.ino()));
        }
        #[cfg(not(target_os = "linux"))]
        let _ = path;
    }
    pub(super) fn start_agent(&mut self) {
        #[cfg(target_os = "linux")]
        {
            assert!(self.agent.is_none());
            self.agent=Some(crate::docker::start_exec_recovery("aabbccddeeff".into(),"fixture".into()).unwrap());
            let until=Instant::now()+Duration::from_secs(3); // existing fixture barrier bound
            while !crate::docker::diagnostic_recovery_ready() {
                assert!(Instant::now()<until,"real fixture coordinator did not complete: {}",crate::docker::diagnostic_recovery_usage());
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
    pub(super) fn stop_agent(&mut self) {
        #[cfg(target_os = "linux")]
        drop(self.agent.take()); // join real worker BEFORE fake server/journal teardown
    }
    #[cfg(target_os = "linux")]
    fn remove_exact_owned(&self) -> std::io::Result<()> {
        let invalid = || std::io::Error::new(std::io::ErrorKind::PermissionDenied,
            "fixture journal ownership changed; evidence retained");
        let m = std::fs::symlink_metadata(JOURNAL)?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o077 != 0 || (m.dev(), m.ino()) != self.directory {
            return Err(invalid());
        }
        let expected_cid = "a".repeat(64);
        let entries = std::fs::read_dir(JOURNAL)?.collect::<Result<Vec<_>, _>>()?;
        if entries.len() > 5 { return Err(invalid()); }
        let mut paths = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(invalid)?;
            if name != "lock" && name != "coordinator-lock" && name != "stripe-2a" && name != "binding.json" && name != format!("{expected_cid}.json") {
                return Err(invalid());
            }
            let path = entry.path();
            let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&path)?;
            let m = file.metadata()?;
            if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 || m.nlink() != 1 || m.len() > 1024 * 1024 {
                return Err(invalid());
            }
            if name == "binding.json" {
                let value: serde_json::Value = serde_json::from_reader(&file).map_err(|_| invalid())?;
                let b = &value["binding"];
                let exe = std::fs::metadata("/proc/self/exe")?;
                if value["attestation"] != "linux-scm-dockerd-v1"
                    || b["sender_pid"].as_u64() != Some(u64::from(std::process::id()))
                    || b["sender_exe_dev"].as_u64() != Some(exe.dev())
                    || b["sender_exe_ino"].as_u64() != Some(exe.ino())
                    || self.socket != b["socket_dev"].as_u64().zip(b["socket_ino"].as_u64()) {
                    return Err(invalid());
                }
            }
            paths.push((path, m.dev(), m.ino()));
        }
        for (path, dev, ino) in paths {
            let m = std::fs::symlink_metadata(&path)?;
            if (m.dev(), m.ino()) != (dev, ino) || !m.is_file() { return Err(invalid()); }
            std::fs::remove_file(path)?;
        }
        std::fs::remove_dir(JOURNAL)
    }
}
impl Drop for JournalScope {
    fn drop(&mut self) {
        self.stop_agent();
        #[cfg(target_os = "linux")]
        cleanup(self.remove_exact_owned(), "exact owned fixture journal");
        // Keep the one empty flock inode until the owned runtime is removed;
        // unlinking it while another fixture waits would split lock ownership.
    }
}

pub(super) fn cleanup(result: std::io::Result<()>, label: &str) {
    if let Err(error) = result {
        eprintln!("FIXTURE_CLEANUP_FAILED {label}: {error}");
        if !std::thread::panicking() { panic!("fixture cleanup failed: {label}: {error}"); }
    }
}
pub(super) fn info(stream: &mut UnixStream) {
    let body = r#"{"ID":"exec-regression-v4-2"}"#;
    stream.write_all(format!(
        "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Length: {}\r\n\r\n{body}", body.len()
    ).as_bytes()).unwrap();
}
pub(super) fn request(stream: &mut UnixStream) -> Option<(String, Vec<u8>)> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        assert!(bytes.len() < 8192);
        let mut byte = [0];
        match stream.read(&mut byte) {
            Ok(0) if bytes.is_empty() => return None,
            Ok(0) => panic!("truncated fixture request"),
            Ok(_) => bytes.push(byte[0]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe) => return None,
            Err(e) => panic!("fixture request failed: {e}"),
        }
    }
    let head = String::from_utf8(bytes).unwrap();
    let length = head.lines().find_map(|line| line.to_ascii_lowercase()
        .strip_prefix("content-length:").map(|value| value.trim().parse::<usize>().unwrap())).unwrap_or(0);
    assert!(length < 65536);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).unwrap();
    Some((head.lines().next().unwrap().to_owned(), body))
}
