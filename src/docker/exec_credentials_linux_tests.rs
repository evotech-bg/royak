//! Linux-only real Unix sockets/process credentials, not Docker. Root alone
//! runs this source fixture in the approved Linux execution environment.
use super::linux::{self, Creds};
use super::*;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{fs::PermissionsExt, net::UnixListener, process::CommandExt};
use std::process::{Child, Command, Stdio};

const INHERITED: i32 = 198;
const MODE: &str = "ROYAK_SCM_FIXTURE_MODE";
struct Fixture {
    root: std::path::PathBuf,
    listener: UnixListener,
    exe: std::path::PathBuf,
    socket: std::path::PathBuf,
}
impl Fixture {
    fn new(name: &str) -> Self {
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "Linux sender fixture requires root; never silently skip"
        );
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "rkscm-{}",
            crate::storage_identity::Uid::new().as_str()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let exe = root.join(name);
        std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let socket = root.join("s");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            root,
            listener,
            exe,
            socket,
        }
    }
    fn spawn(&self, mode: &str) -> Child {
        let mut cmd = command(&self.exe, mode, self.listener.as_raw_fd());
        cmd.stdout(Stdio::piped())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
fn command(exe: &std::path::Path, mode: &str, fd: i32) -> Command {
    let full = format!("{}::fixture_server_subprocess", module_path!());
    let test = full.split_once("::").unwrap().1;
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(MODE, mode);
    // Only async-signal-safe syscalls between fork and exec. The copied test
    // executable genuinely runs under the dockerd filename; no production
    // identity override, environment bypass or mocked kernel credential exists.
    unsafe {
        cmd.pre_exec(move || {
            if fd != INHERITED {
                if libc::dup2(fd, INHERITED) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            } else {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    cmd
}
fn request(stream: &mut UnixStream) -> std::io::Result<Option<String>> {
    let mut head = Vec::new();
    loop {
        let mut b = [0];
        match stream.read(&mut b)? {
            0 if head.is_empty() => return Ok(None),
            0 => return Err(std::io::ErrorKind::UnexpectedEof.into()),
            _ => {
                head.push(b[0]);
                if head.len() > 16 * 1024 {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
        }
    }
    let text = String::from_utf8(head).unwrap();
    let len = text
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    assert!(len <= 1024);
    let mut body = vec![0; len];
    stream.read_exact(&mut body)?;
    Ok(Some(text))
}
fn info(close: bool) -> Vec<u8> {
    let body = br#"{"ID":"fixture-daemon"}"#;
    format!(
        "HTTP/1.1 200 OK\r\nConnection: {}\r\nContent-Length: {}\r\n\r\n{}",
        if close { "close" } else { "keep-alive" },
        body.len(),
        std::str::from_utf8(body).unwrap()
    )
    .into_bytes()
}
fn align(n: usize) -> usize {
    let a = std::mem::size_of::<usize>();
    (n + a - 1) & !(a - 1)
}
fn send_control(
    stream: &UnixStream,
    bytes: &[u8],
    kind: i32,
    data: &[u8],
) -> std::io::Result<usize> {
    let head = align(std::mem::size_of::<libc::cmsghdr>());
    let len = head + data.len();
    let mut words = vec![0usize; align(len) / std::mem::size_of::<usize>()];
    unsafe {
        let header = words.as_mut_ptr() as *mut libc::cmsghdr;
        (*header).cmsg_len = len.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "fixture cmsg length overflow",
            )
        })?;
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = kind;
        std::ptr::copy_nonoverlapping(
            data.as_ptr(),
            (words.as_mut_ptr() as *mut u8).add(head),
            data.len(),
        );
    }
    let mut iov = libc::iovec {
        iov_base: bytes.as_ptr() as *mut libc::c_void,
        iov_len: bytes.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1usize.try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "fixture iov count overflow",
        )
    })?;
    msg.msg_control = words.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = align(len).try_into().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "fixture control length overflow",
        )
    })?;
    let n = unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) };
    if n < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        usize::try_from(n).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fixture send length overflow",
            )
        })
    }
}
fn finish(child: Child) -> serde_json::Value {
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "fixture failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once("FIXTURE=").map(|(_, value)| value))
        .map(|line| serde_json::from_str(line).unwrap())
        .last()
        .expect("fixture receipt missing")
}
fn fds() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

#[test]
fn fixture_server_subprocess() {
    let Ok(mode) = std::env::var(MODE) else {
        return;
    };
    if mode == "tail" {
        let mut socket = unsafe { UnixStream::from_raw_fd(INHERITED) };
        socket
            .write_all(std::env::var("ROYAK_SCM_TAIL").unwrap().as_bytes())
            .unwrap();
        return;
    }
    if matches!(mode.as_str(), "nonroot" | "forged-nonroot") {
        assert_eq!(unsafe { libc::setgid(65534) }, 0);
        assert_eq!(unsafe { libc::setuid(65534) }, 0);
    }
    let listener = unsafe { UnixListener::from_raw_fd(INHERITED) };
    let (mut socket, _) = listener.accept().unwrap();
    drop(listener);
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let first = request(&mut socket).unwrap().unwrap();
    assert!(first.starts_with("GET /info HTTP/1.1\r\n"));
    assert!(first.contains("Connection: keep-alive\r\n"));
    let bytes = info(mode == "close");
    let mut forged_errno = None;
    match mode.as_str() {
        "rights" | "ctrunc" => {
            let file = std::fs::File::open("/dev/null").unwrap();
            let n = if mode == "ctrunc" { 100 } else { 1 };
            let mut raw = Vec::new();
            for _ in 0..n {
                raw.extend_from_slice(&file.as_raw_fd().to_ne_bytes());
            }
            assert_eq!(
                send_control(&socket, &bytes, libc::SCM_RIGHTS, &raw).unwrap(),
                bytes.len()
            );
        }
        "forged-nonroot" => {
            let c = libc::ucred {
                pid: std::process::id().try_into().expect("Linux PID fits pid_t"),
                uid: 0,
                gid: 0,
            };
            let raw = unsafe {
                std::slice::from_raw_parts(&c as *const _ as *const u8, std::mem::size_of_val(&c))
            };
            let error = send_control(&socket, &bytes, libc::SCM_CREDENTIALS, raw).unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            forged_errno = error.raw_os_error();
            let _ = socket.shutdown(std::net::Shutdown::Write);
        }
        "mixed" => {
            let cut = bytes.len() - 8;
            socket.write_all(&bytes[..cut]).unwrap();
            let mut tail = command(
                &std::env::current_exe().unwrap(),
                "tail",
                socket.as_raw_fd(),
            );
            assert!(tail
                .env(
                    "ROYAK_SCM_TAIL",
                    std::str::from_utf8(&bytes[cut..]).unwrap()
                )
                .stdout(Stdio::null())
                .status()
                .unwrap()
                .success());
        }
        _ => socket.write_all(&bytes).unwrap(),
    }
    if mode == "dead-before-post" {
        let mut marker = [0];
        std::io::stdin().read_exact(&mut marker).unwrap();
        println!(
            "FIXTURE={}",
            serde_json::json!({"post_count":0,"sender_pid":std::process::id()})
        );
        return;
    }
    let mut posts = 0;
    loop {
        match request(&mut socket) {
            Ok(Some(head)) => {
                if head.starts_with("POST ") {
                    posts += 1;
                } else {
                    panic!("unexpected second request: {head}");
                }
                if mode == "mixed-after-post" {
                    let mut tail = command(
                        &std::env::current_exe().unwrap(),
                        "tail",
                        socket.as_raw_fd(),
                    );
                    assert!(tail.env("ROYAK_SCM_TAIL","HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").stdout(Stdio::null()).status().unwrap().success());
                } else {
                    socket.write_all(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").unwrap();
                }
                break;
            }
            Ok(None) => break,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
                ) =>
            {
                break
            }
            Err(error) => panic!("fixture did not observe bounded client close: {error}"),
        }
    }
    println!(
        "FIXTURE={}",
        serde_json::json!({"post_count":posts,"sender_pid":std::process::id(),"forged_errno":forged_errno})
    );
}

#[test]
fn inherited_listener_owner_is_not_used_as_actual_sender_and_post_reuses_attested_socket() {
    let fixture = Fixture::new("dockerd");
    let child = fixture.spawn("ok");
    let sender = child.id();
    let mut connection = AdmittedStream::connect(
        fixture.socket.to_str().unwrap(),
        None,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(
        connection.state.listener.pid,
        libc::pid_t::try_from(std::process::id()).unwrap()
    );
    assert_ne!(
        connection.state.listener.pid,
        libc::pid_t::try_from(sender).unwrap()
    );
    assert_eq!(connection.binding().unwrap().sender_pid, sender);
    let response = wire::request(
        &mut connection,
        "POST",
        "/containers/test/exec",
        Some(b"{}"),
        64,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(response.status, 201);
    drop(connection);
    assert_eq!(finish(child)["post_count"], 1);
}

fn refused(mode: &str, name: &str, entry: &str) {
    // Isolate only cases that compare process-wide FD census. The outer FULL
    // suite stays default-parallel; neither production identity nor test
    // selection is weakened. Established exact self-reexec recursion guard.
    const ISOLATED: &str = "ROYAK_SCM_FD_CASE_ISOLATED";
    let full = format!("{}::{entry}", module_path!());
    let test = full.split_once("::").unwrap().1;
    if std::env::var(ISOLATED).ok().as_deref() != Some(test) {
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(ISOLATED, test)
            .env_remove(MODE)
            .env_remove("DOCKER_HOST")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "isolated SCM FD case failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let fixture = Fixture::new(name);
    let child = fixture.spawn(mode);
    let before = fds();
    let result = AdmittedStream::connect(
        fixture.socket.to_str().unwrap(),
        None,
        Instant::now() + Duration::from_secs(2),
    );
    assert!(result.is_err(), "{mode} unexpectedly attested");
    drop(result);
    assert_eq!(fds(), before, "{mode} leaked received FD/pidfd/socket");
    let receipt = finish(child);
    assert_eq!(receipt["post_count"], 0);
    if mode == "forged-nonroot" {
        assert_eq!(receipt["forged_errno"], libc::EPERM);
    }
}
#[test]
fn nonroot_sender_is_refused_before_post() {
    refused(
        "nonroot",
        "dockerd",
        "nonroot_sender_is_refused_before_post",
    );
}
#[test]
fn nonroot_cannot_forge_root_scm_credentials_and_post_is_zero() {
    refused(
        "forged-nonroot",
        "dockerd",
        "nonroot_cannot_forge_root_scm_credentials_and_post_is_zero",
    );
}
#[test]
fn root_proxy_executable_is_refused_before_post() {
    refused(
        "ok",
        "proxy",
        "root_proxy_executable_is_refused_before_post",
    );
}
#[test]
fn mixed_actual_sender_chunks_are_refused_before_post() {
    refused(
        "mixed",
        "dockerd",
        "mixed_actual_sender_chunks_are_refused_before_post",
    );
}
#[test]
fn rights_are_closed_and_rejected_before_post() {
    refused(
        "rights",
        "dockerd",
        "rights_are_closed_and_rejected_before_post",
    );
}
#[test]
fn ctrunc_closes_every_delivered_right_and_refuses_post() {
    refused(
        "ctrunc",
        "dockerd",
        "ctrunc_closes_every_delivered_right_and_refuses_post",
    );
}
#[test]
fn close_response_cannot_be_used_as_same_connection_attestation() {
    refused(
        "close",
        "dockerd",
        "close_response_cannot_be_used_as_same_connection_attestation",
    );
}

#[test]
fn dead_pinned_sender_cannot_receive_a_post_after_successful_preflight() {
    let fixture = Fixture::new("dockerd");
    let mut child = fixture.spawn("dead-before-post");
    let mut connection = AdmittedStream::connect(
        fixture.socket.to_str().unwrap(),
        None,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    child.stdin.take().unwrap().write_all(b"x").unwrap();
    let receipt = finish(child);
    assert_eq!(receipt["post_count"], 0);
    assert!(wire::request(
        &mut connection,
        "POST",
        "/containers/test/exec",
        Some(b"{}"),
        64,
        Instant::now() + Duration::from_secs(2)
    )
    .is_err());
}

#[test]
fn cloned_hijack_reader_keeps_actual_sender_checks_after_post_submission() {
    let fixture = Fixture::new("dockerd");
    let child = fixture.spawn("mixed-after-post");
    let mut writer = AdmittedStream::connect(
        fixture.socket.to_str().unwrap(),
        None,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    let mut reader = writer.try_clone().unwrap();
    writer
        .write_all(&wire::request_head("POST", "/containers/test/exec", 2, false).unwrap())
        .unwrap();
    writer.write_all(b"{}").unwrap();
    reader
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut bytes = [0; 8192];
    let error = reader.read(&mut bytes).unwrap_err();
    assert!(error.to_string().contains("mixed response sender"));
    drop(reader);
    drop(writer);
    assert_eq!(finish(child)["post_count"], 1);
}

#[test]
fn pid1_missing_duplicate_and_unknown_control_are_never_authority() {
    assert!(linux::sender_credentials(Creds {
        pid: 1,
        uid: 0,
        gid: 0
    })
    .is_err());
    assert!(linux::sender_credentials(Creds {
        pid: 2,
        uid: 65534,
        gid: 65534
    })
    .is_err());
    assert!(linux::control(&[], 0, true).is_err());
    let header = align(std::mem::size_of::<libc::cmsghdr>());
    let mut words = vec![0usize; header / std::mem::size_of::<usize>()];
    unsafe {
        let c = words.as_mut_ptr() as *mut libc::cmsghdr;
        (*c).cmsg_len = header.try_into().expect("fixture cmsg length fits ABI");
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = 0x7fff;
    }
    let raw = unsafe { std::slice::from_raw_parts(words.as_ptr() as *const u8, header) };
    assert!(linux::control(raw, 0, true).is_err());
    assert!(linux::control(&[], libc::MSG_CTRUNC, true).is_err());
    let file = std::fs::File::open("/dev/null").unwrap();
    let mut unknown = control_words(0x7fff, &file.as_raw_fd().to_ne_bytes());
    let bytes = unsafe {
        std::slice::from_raw_parts_mut(
            unknown.as_mut_ptr() as *mut u8,
            unknown.len() * std::mem::size_of::<usize>(),
        )
    };
    assert!(linux::control(bytes, 0, true).is_err());
    assert!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } >= 0,
        "unknown integer payload must not close an arbitrary FD"
    );

    let creds = libc::ucred {
        pid: std::process::id().try_into().expect("Linux PID fits pid_t"),
        uid: 0,
        gid: 0,
    };
    let data = unsafe {
        std::slice::from_raw_parts(
            &creds as *const _ as *const u8,
            std::mem::size_of_val(&creds),
        )
    };
    let mut duplicate = control_words(libc::SCM_CREDENTIALS, data);
    duplicate.extend(control_words(libc::SCM_CREDENTIALS, data));
    let bytes = unsafe {
        std::slice::from_raw_parts(
            duplicate.as_ptr() as *const u8,
            duplicate.len() * std::mem::size_of::<usize>(),
        )
    };
    assert!(linux::control(bytes, 0, true).is_err());
}

fn control_words(kind: i32, data: &[u8]) -> Vec<usize> {
    let head = align(std::mem::size_of::<libc::cmsghdr>());
    let mut words = vec![0usize; align(head + data.len()) / std::mem::size_of::<usize>()];
    unsafe {
        let h = words.as_mut_ptr() as *mut libc::cmsghdr;
        (*h).cmsg_len = (head + data.len())
            .try_into()
            .expect("fixture cmsg length fits ABI");
        (*h).cmsg_level = libc::SOL_SOCKET;
        (*h).cmsg_type = kind;
        std::ptr::copy_nonoverlapping(
            data.as_ptr(),
            (words.as_mut_ptr() as *mut u8).add(head),
            data.len(),
        );
    }
    words
}

#[test]
fn pinned_kernel_scm_pidfd_format_is_closed_and_rejected_without_signal() {
    // EBADF on a closed descriptor number is process-wide evidence too: another
    // parallel case could otherwise reopen that number before the assertion.
    const KEY: &str = "ROYAK_SCM_PIDFD_CASE_ISOLATED";
    let full = format!(
        "{}::pinned_kernel_scm_pidfd_format_is_closed_and_rejected_without_signal",
        module_path!()
    );
    let test = full.split_once("::").unwrap().1;
    if std::env::var(KEY).ok().as_deref() != Some(test) {
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test, "--nocapture", "--test-threads=1"])
            .env(KEY, test)
            .env_remove(MODE)
            .env_remove("DOCKER_HOST")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "isolated pidfd close case failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        return;
    }
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
    assert!(raw >= 0);
    let fd = libc::c_int::try_from(raw).expect("kernel pidfd fits FD ABI");
    let words = control_words(0x04, &fd.to_ne_bytes());
    let bytes = unsafe {
        std::slice::from_raw_parts(
            words.as_ptr() as *const u8,
            words.len() * std::mem::size_of::<usize>(),
        )
    };
    assert!(linux::control(bytes, libc::MSG_CMSG_CLOEXEC, false).is_err());
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );
}
