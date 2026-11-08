//! Actual-sender Linux Unix-stream attestation. SO_PEERCRED identifies the
//! listener owner (possibly systemd), never substitutes for SCM_CREDENTIALS.
use super::{wire, Binding};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

pub struct AdmittedStream {
    stream: UnixStream,
    #[cfg(target_os = "linux")]
    state: linux::State,
}

impl AdmittedStream {
    pub(super) fn connect(
        socket: &str,
        expected: Option<&Binding>,
        deadline: Instant,
    ) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        {
            linux::connect(socket, expected, deadline)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (socket, expected, deadline);
            Err("actual-sender exec attestation requires the local Linux node agent; no proxy/native fallback".into())
        }
    }
    pub(super) fn binding(&self) -> Result<&Binding, String> {
        #[cfg(target_os = "linux")]
        {
            self.state
                .binding
                .as_ref()
                .ok_or("preflight is not fully attested".into())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("actual-sender identity requires Linux".into())
        }
    }
    pub(super) fn validate(&self) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            self.state.validate()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err("actual-sender identity requires Linux".into())
        }
    }
    /// Only the cancellation registry clones this raw socket for shutdown. All
    /// actual reads/writes remain on AdmittedStream and validate sender lineage.
    pub(crate) fn cancellation_socket(&self) -> &UnixStream {
        &self.stream
    }
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.stream.set_write_timeout(timeout)
    }
    pub fn shutdown(&self, how: std::net::Shutdown) -> std::io::Result<()> {
        self.stream.shutdown(how)
    }
    pub fn try_clone(&self) -> std::io::Result<Self> {
        self.validate().map_err(invalid)?;
        #[cfg(target_os = "linux")]
        {
            if self.state.position != self.state.filled {
                return Err(invalid(
                    "cannot clone an admitted stream with unconsumed received bytes",
                ));
            }
            Ok(Self {
                stream: self.stream.try_clone()?,
                state: self.state.clone_empty(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(invalid("admitted stream clone requires Linux"))
        }
    }
}
fn invalid(error: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, error.to_string())
}
impl wire::TimedStream for AdmittedStream {
    fn read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.set_read_timeout(timeout)
    }
    fn write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.set_write_timeout(timeout)
    }
}
impl Read for AdmittedStream {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        #[cfg(target_os = "linux")]
        {
            linux::receive(&self.stream, &mut self.state, out)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = out;
            Err(invalid("admitted read requires Linux"))
        }
    }
}
impl Write for AdmittedStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        #[cfg(target_os = "linux")]
        {
            if self.state.attested {
                self.state.validate().map_err(invalid)?;
            } else {
                let remaining = &self.state.preflight[self.state.preflight_written..];
                if bytes.len() > remaining.len() || bytes != &remaining[..bytes.len()] {
                    return Err(invalid(
                        "unattested socket may send only the exact GET/info preflight",
                    ));
                }
            }
            let n = self.stream.write(bytes)?;
            if !self.state.attested {
                self.state.preflight_written += n;
            }
            Ok(n)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = bytes;
            Err(invalid("admitted write requires Linux"))
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.validate().map_err(invalid)?;
        self.stream.flush()
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use serde::Deserialize;
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::sync::Arc;

    pub(super) const CONTROL_BYTES: usize = 256;
    const DATA_BYTES: usize = 8192;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Creds {
        pub pid: i32,
        pub uid: u32,
        pub gid: u32,
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct SocketId {
        path: String,
        dev: u64,
        ino: u64,
    }
    impl SocketId {
        fn read(path: &str) -> Result<Self, String> {
            if !std::path::Path::new(path).is_absolute() {
                return Err("Docker socket path is not absolute".into());
            }
            let m = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
            if !m.file_type().is_socket() || m.uid() != 0 || m.mode() & 0o002 != 0 {
                return Err(
                    "Docker socket must be a root-owned non-world-writable socket, not a link"
                        .into(),
                );
            }
            Ok(Self {
                path: path.into(),
                dev: m.dev(),
                ino: m.ino(),
            })
        }
        fn validate(&self) -> Result<(), String> {
            if Self::read(&self.path)? != *self {
                return Err("Docker socket path changed during attested connection".into());
            }
            Ok(())
        }
    }
    fn bounded_connect(path: &str, deadline: Instant) -> Result<UnixStream, String> {
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if raw < 0 {
            return Err(format!(
                "cannot create bounded Unix socket: {}",
                std::io::Error::last_os_error()
            ));
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let pass: libc::c_int = 1;
        let pass_len: libc::socklen_t = std::mem::size_of_val(&pass)
            .try_into()
            .map_err(|_| "SO_PASSCRED option length overflow")?;
        // Enable before connect, not merely before read: even an eager sender
        // cannot queue an uncredentialed greeting in the connect/setsockopt gap.
        if unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PASSCRED,
                &pass as *const _ as *const libc::c_void,
                pass_len,
            )
        } != 0
        {
            return Err("cannot enable SO_PASSCRED before connect".into());
        }
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let bytes = path.as_bytes();
        if bytes.is_empty() || bytes.contains(&0) || bytes.len() >= address.sun_path.len() {
            return Err("Unix socket path exceeds canonical address bound".into());
        }
        address.sun_family = libc::AF_UNIX
            .try_into()
            .map_err(|_| "AF_UNIX family overflow")?;
        // sun_path's c_char is signed on some targets and unsigned on others.
        // Copy path bytes instead of numerically narrowing UTF-8 code units.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                address.sun_path.as_mut_ptr() as *mut u8,
                bytes.len(),
            );
        }
        let size: libc::socklen_t =
            (std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1)
                .try_into()
                .map_err(|_| "Unix address length overflow")?;
        if Instant::now() >= deadline {
            return Err("Unix connect deadline expired before attempt".into());
        }
        let connected = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                &address as *const _ as *const libc::sockaddr,
                size,
            )
        };
        if connected != 0 {
            let error = std::io::Error::last_os_error();
            // AF_UNIX backlog EAGAIN is not a completed/in-progress connection.
            // Refuse it; never retry a side-effecting HTTP operation.
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(format!("Unix connect refused: {error}"));
            }
            loop {
                let left = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or("Unix connect deadline")?;
                let ms: i32 = left
                    .as_millis()
                    .saturating_add(1)
                    .min(i32::MAX as u128)
                    .try_into()
                    .map_err(|_| "poll duration overflow")?;
                let mut p = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLOUT,
                    revents: 0,
                };
                let n = unsafe { libc::poll(&mut p, 1, ms) };
                if n < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                if n <= 0 {
                    return Err("Unix connect did not complete within original budget".into());
                }
                let mut error: libc::c_int = 0;
                let mut len: libc::socklen_t = std::mem::size_of_val(&error)
                    .try_into()
                    .map_err(|_| "SO_ERROR option length overflow")?;
                if unsafe {
                    libc::getsockopt(
                        fd.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_ERROR,
                        &mut error as *mut _ as *mut libc::c_void,
                        &mut len,
                    )
                } != 0
                    || usize::try_from(len).ok() != Some(std::mem::size_of_val(&error))
                    || error != 0
                {
                    return Err("Unix connect completion unverified".into());
                }
                break;
            }
        }
        let stream = UnixStream::from(fd);
        stream
            .peer_addr()
            .map_err(|_| "Unix peer association absent after connect")?;
        stream.set_nonblocking(false).map_err(|e| e.to_string())?;
        Ok(stream)
    }
    fn bounded(path: &str, limit: u64) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|e| e.to_string())?
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > limit {
            return Err("process identity observation exceeds bound".into());
        }
        Ok(bytes)
    }
    pub(super) fn boot() -> Result<String, String> {
        Ok(
            std::str::from_utf8(&bounded("/proc/sys/kernel/random/boot_id", 128)?)
                .map_err(|_| "invalid boot identity")?
                .trim()
                .into(),
        )
    }
    pub(super) fn start(pid: u32) -> Result<u64, String> {
        let bytes = bounded(&format!("/proc/{pid}/stat"), 16 * 1024)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| "invalid process stat")?;
        text.rsplit_once(')')
            .ok_or("invalid process stat")?
            .1
            .split_whitespace()
            .nth(19)
            .ok_or("missing process start")?
            .parse()
            .map_err(|_| "invalid process start".into())
    }
    fn executable(pid: i32) -> Result<(u64, u64), String> {
        let path = format!("/proc/{pid}/exe");
        let target = std::fs::read_link(&path).map_err(|_| "sender executable unavailable")?;
        if target.file_name().and_then(|v| v.to_str()) != Some("dockerd") {
            return Err("actual response sender is not dockerd; no proxy/PID1 fallback".into());
        }
        let file = File::open(&path).map_err(|_| "cannot pin sender executable")?;
        let m = file.metadata().map_err(|e| e.to_string())?;
        if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("dockerd executable is not root-trusted".into());
        }
        Ok((m.dev(), m.ino()))
    }
    struct Sender {
        creds: Creds,
        pid: u32,
        boot: String,
        start: u64,
        exe_dev: u64,
        exe_ino: u64,
        pidfd: OwnedFd,
    }
    pub(super) fn sender_credentials(creds: Creds) -> Result<(), String> {
        if creds.uid != 0 || creds.pid <= 1 {
            return Err("actual sender must be root dockerd, never PID1/nonroot".into());
        }
        Ok(())
    }
    impl Sender {
        fn pin(creds: Creds) -> Result<Self, String> {
            sender_credentials(creds)?;
            let pid =
                u32::try_from(creds.pid).map_err(|_| "sender PID cannot fit trusted identity")?;
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, creds.pid, 0) };
            if raw < 0 {
                return Err("cannot pin actual dockerd sender with pidfd".into());
            }
            let raw_fd: libc::c_int = raw
                .try_into()
                .map_err(|_| "pidfd return value is outside FD range")?;
            let pidfd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            let flags = unsafe { libc::fcntl(pidfd.as_raw_fd(), libc::F_GETFD) };
            if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
                return Err("sender pidfd is not CLOEXEC".into());
            }
            let mut result = Self {
                creds,
                pid,
                boot: boot()?,
                start: 0,
                exe_dev: 0,
                exe_ino: 0,
                pidfd,
            };
            result.alive()?;
            result.start = start(pid)?;
            let exe = executable(creds.pid)?;
            result.exe_dev = exe.0;
            result.exe_ino = exe.1;
            result.validate()?;
            Ok(result)
        }
        fn alive(&self) -> Result<(), String> {
            let mut p = libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                let n = unsafe { libc::poll(&mut p, 1, 0) };
                if n < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                if n != 0 || p.revents != 0 {
                    return Err("pinned dockerd sender exited or pidfd state is unknown".into());
                }
                return Ok(());
            }
        }
        fn validate(&self) -> Result<(), String> {
            self.alive()?;
            if boot() != Ok(self.boot.clone())
                || start(self.pid) != Ok(self.start)
                || executable(self.creds.pid) != Ok((self.exe_dev, self.exe_ino))
            {
                return Err(
                    "pinned dockerd boot/start/executable changed or is unavailable".into(),
                );
            }
            self.alive()
        }
        fn binding(&self, socket: &SocketId, id: String) -> Binding {
            Binding {
                boot: self.boot.clone(),
                daemon_id: id,
                sender_pid: self.pid,
                sender_start: self.start,
                sender_uid: self.creds.uid,
                sender_gid: self.creds.gid,
                sender_exe_dev: self.exe_dev,
                sender_exe_ino: self.exe_ino,
                socket_dev: socket.dev,
                socket_ino: socket.ino,
            }
        }
    }
    pub(super) struct State {
        pub(super) binding: Option<Binding>,
        socket: SocketId,
        sender: Option<Arc<Sender>>,
        expected: Option<Binding>,
        pub(super) attested: bool,
        pub(super) preflight: Vec<u8>,
        pub(super) preflight_written: usize,
        data: [u8; DATA_BYTES],
        pub(super) position: usize,
        pub(super) filled: usize,
        pub(super) listener: Creds,
    }
    impl State {
        pub(super) fn clone_empty(&self) -> Self {
            Self {
                binding: self.binding.clone(),
                socket: self.socket.clone(),
                sender: self.sender.clone(),
                expected: self.expected.clone(),
                attested: self.attested,
                preflight: self.preflight.clone(),
                preflight_written: self.preflight_written,
                data: [0; DATA_BYTES],
                position: 0,
                filled: 0,
                listener: self.listener,
            }
        }
        pub(super) fn validate(&self) -> Result<(), String> {
            if !self.attested {
                return Err("connection preflight is incomplete".into());
            }
            let sender = self.sender.as_ref().ok_or("sender is not pinned")?;
            sender.validate()?;
            self.socket.validate()?;
            let binding = self.binding.as_ref().ok_or("sender binding absent")?;
            if sender.binding(&self.socket, binding.daemon_id.clone()) != *binding {
                return Err("attested connection lineage changed".into());
            }
            Ok(())
        }
        fn accept(&mut self, creds: Creds) -> Result<(), String> {
            if let Some(sender) = &self.sender {
                if sender.creds != creds {
                    return Err("mixed response sender credentials on one connection".into());
                }
                sender.validate()?;
            } else {
                let sender = Arc::new(Sender::pin(creds)?);
                if self.expected.as_ref().is_some_and(|b| {
                    b.sender_pid != sender.pid
                        || b.sender_uid != creds.uid
                        || b.sender_gid != creds.gid
                        || b.sender_start != sender.start
                        || b.boot != sender.boot
                        || b.sender_exe_dev != sender.exe_dev
                        || b.sender_exe_ino != sender.exe_ino
                }) {
                    return Err("actual sender differs from durable daemon lineage".into());
                }
                self.sender = Some(sender);
            }
            Ok(())
        }
    }
    fn listener(stream: &UnixStream) -> Result<Creds, String> {
        let mut c: libc::ucred = unsafe { std::mem::zeroed() };
        let mut n: libc::socklen_t = std::mem::size_of::<libc::ucred>()
            .try_into()
            .map_err(|_| "SO_PEERCRED option length overflow")?;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut c as *mut _ as *mut libc::c_void,
                &mut n,
            )
        } != 0
            || usize::try_from(n).ok() != Some(std::mem::size_of::<libc::ucred>())
            || c.uid != 0
            || c.pid < 1
        {
            return Err("listener credentials unavailable/nonroot".into());
        }
        // PID1 is allowed only as listener owner, never actual sender authority.
        Ok(Creds {
            pid: c.pid,
            uid: c.uid,
            gid: c.gid,
        })
    }
    #[derive(Deserialize)]
    struct Info {
        #[serde(rename = "ID")]
        id: String,
    }
    pub(super) fn connect(
        socket: &str,
        expected: Option<&Binding>,
        deadline: Instant,
    ) -> Result<AdmittedStream, String> {
        if unsafe { libc::geteuid() } != 0 {
            return Err("actual-sender admission requires the root local Linux node agent".into());
        }
        let identity = SocketId::read(socket)?;
        let stream = bounded_connect(socket, deadline)?;
        let peer = listener(&stream)?;
        identity.validate()?;
        let mut connection = AdmittedStream {
            stream,
            state: State {
                binding: None,
                socket: identity,
                sender: None,
                expected: expected.cloned(),
                attested: false,
                preflight: wire::request_head("GET", "/info", 0, true)?,
                preflight_written: 0,
                data: [0; DATA_BYTES],
                position: 0,
                filled: 0,
                listener: peer,
            },
        };
        let response = wire::keepalive_info(&mut connection, deadline)?;
        if response.status != 200 {
            return Err("same-connection GET/info refused".into());
        }
        let info: Info = serde_json::from_slice(&response.body)
            .map_err(|_| "missing/duplicate/invalid daemon ID in preflight")?;
        if connection.state.position != connection.state.filled
            || connection.state.preflight_written != connection.state.preflight.len()
        {
            return Err("preflight has extra received bytes or incomplete request".into());
        }
        let sender = connection
            .state
            .sender
            .as_ref()
            .ok_or("preflight had no actual SCM sender")?;
        sender.validate()?;
        connection.state.socket.validate()?;
        let binding = sender.binding(&connection.state.socket, info.id);
        if !binding.valid() || expected.is_some_and(|old| *old != binding) {
            return Err("preflight daemon/node/executable/socket lineage differs".into());
        }
        connection.state.binding = Some(binding);
        connection.state.attested = true;
        connection.validate()?;
        // The preflight's bounded RPC timeouts must not become a new idle TTL
        // on an interactive stream. Each RPC/capture caller reapplies its
        // existing explicit budget; hijack retains its original no-read-timeout.
        connection
            .stream
            .set_read_timeout(None)
            .map_err(|e| e.to_string())?;
        connection
            .stream
            .set_write_timeout(None)
            .map_err(|e| e.to_string())?;
        Ok(connection)
    }

    fn align(value: usize) -> Option<usize> {
        let size = std::mem::size_of::<usize>();
        value.checked_add(size - 1).map(|v| v & !(size - 1))
    }
    /// Kernel ancillary data is parsed before deciding on CTRUNC/unknown types,
    /// so already-installed SCM_RIGHTS descriptors are always closed on error.
    pub(super) fn control(
        bytes: &[u8],
        flags: i32,
        needs_creds: bool,
    ) -> Result<Option<Creds>, String> {
        let mut rights: Vec<OwnedFd> = Vec::new();
        let mut received_fds = std::collections::BTreeSet::new();
        let mut creds = None;
        let mut error = None;
        let mut offset = 0usize;
        let header = align(std::mem::size_of::<libc::cmsghdr>()).unwrap();
        while bytes.len().saturating_sub(offset) >= std::mem::size_of::<libc::cmsghdr>() {
            let h = unsafe {
                std::ptr::read_unaligned(bytes.as_ptr().add(offset) as *const libc::cmsghdr)
            };
            let len = usize::try_from(h.cmsg_len)
                .map_err(|_| "ancillary length cannot fit address space")?;
            if len < header || len > bytes.len() - offset {
                error = Some("malformed/truncated ancillary header");
                break;
            }
            let data = &bytes[offset + header..offset + len];
            // Linux v6.8 include/linux/socket.h pins SCM_PIDFD=0x04, one int.
            // SO_PASSPIDFD is never enabled here; still close/reject it if seen.
            if h.cmsg_level == libc::SOL_SOCKET
                && (h.cmsg_type == libc::SCM_RIGHTS || h.cmsg_type == 0x04)
            {
                error = Some("SCM_RIGHTS is forbidden on Docker metadata/data streams");
                let fd_bytes =
                    if h.cmsg_type == 0x04 && data.len() != std::mem::size_of::<libc::c_int>() {
                        error = Some("SCM_PIDFD must contain exactly one descriptor");
                        &[][..]
                    } else {
                        data
                    };
                for raw in fd_bytes.chunks_exact(std::mem::size_of::<libc::c_int>()) {
                    let fd =
                        unsafe { std::ptr::read_unaligned(raw.as_ptr() as *const libc::c_int) };
                    if fd < 0 {
                        error = Some("invalid received descriptor");
                        continue;
                    }
                    if !received_fds.insert(fd) {
                        error = Some("duplicate received descriptor number");
                        continue;
                    }
                    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
                    let flags = unsafe { libc::fcntl(owned.as_raw_fd(), libc::F_GETFD) };
                    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
                        error = Some("received descriptor was not atomically CLOEXEC");
                    }
                    rights.push(owned);
                }
                if data.len() % std::mem::size_of::<libc::c_int>() != 0 {
                    error = Some("misaligned received descriptors");
                }
                if h.cmsg_type == 0x04 && data.len() != std::mem::size_of::<libc::c_int>() {
                    error = Some("SCM_PIDFD must contain exactly one descriptor");
                }
            } else if h.cmsg_level == libc::SOL_SOCKET && h.cmsg_type == libc::SCM_CREDENTIALS {
                if data.len() != std::mem::size_of::<libc::ucred>() || creds.is_some() {
                    error = Some("missing/duplicate/malformed SCM_CREDENTIALS");
                } else {
                    let c =
                        unsafe { std::ptr::read_unaligned(data.as_ptr() as *const libc::ucred) };
                    creds = Some(Creds {
                        pid: c.pid,
                        uid: c.uid,
                        gid: c.gid,
                    });
                }
            } else {
                error = Some("unexpected ancillary control type");
            }
            let Some(next) = align(len).and_then(|n| offset.checked_add(n)) else {
                error = Some("ancillary offset overflow");
                break;
            };
            if next > bytes.len() {
                if offset + len != bytes.len() {
                    error = Some("invalid ancillary padding");
                }
                offset = bytes.len();
                break;
            }
            offset = next;
        }
        if bytes[offset..].iter().any(|b| *b != 0) {
            error = Some("unexpected ancillary trailing bytes");
        }
        if flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
            error = Some("truncated Unix response/control data");
        }
        if flags & !(libc::MSG_CMSG_CLOEXEC | libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
            error = Some("unexpected recvmsg flags");
        }
        if needs_creds && creds.is_none() {
            error = Some("nonempty response chunk has no SCM_CREDENTIALS");
        }
        drop(rights); // Also closes installed FDs before every rejected return.
        if let Some(error) = error {
            return Err(error.into());
        }
        Ok(creds)
    }
    pub(super) fn receive(
        stream: &UnixStream,
        state: &mut State,
        out: &mut [u8],
    ) -> std::io::Result<usize> {
        if state.position == state.filled {
            let mut control_words = [0usize; CONTROL_BYTES / std::mem::size_of::<usize>()];
            let mut iov = libc::iovec {
                iov_base: state.data.as_mut_ptr() as *mut libc::c_void,
                iov_len: state.data.len(),
            };
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1usize.try_into().map_err(invalid)?;
            message.msg_control = control_words.as_mut_ptr() as *mut libc::c_void;
            message.msg_controllen = CONTROL_BYTES.try_into().map_err(invalid)?;
            let n = loop {
                message.msg_controllen = CONTROL_BYTES.try_into().map_err(invalid)?;
                message.msg_flags = 0;
                let n = unsafe {
                    libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC)
                };
                if n < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                break n;
            };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let n = usize::try_from(n).map_err(invalid)?;
            let claimed = usize::try_from(message.msg_controllen).map_err(invalid)?;
            let actual = claimed.min(CONTROL_BYTES);
            let bytes =
                unsafe { std::slice::from_raw_parts(control_words.as_ptr() as *const u8, actual) };
            let creds = control(bytes, message.msg_flags, n > 0).map_err(invalid)?;
            if claimed > CONTROL_BYTES {
                return Err(invalid("kernel ancillary length exceeds supplied bound"));
            }
            if n == 0 {
                return Ok(0);
            }
            if n > state.data.len() {
                return Err(invalid("recvmsg data exceeds supplied bound"));
            }
            state
                .accept(creds.ok_or_else(|| invalid("missing actual sender"))?)
                .map_err(invalid)?;
            state.position = 0;
            state.filled = n;
        }
        let n = out.len().min(state.filled - state.position);
        out[..n].copy_from_slice(&state.data[state.position..state.position + n]);
        state.position += n;
        Ok(n)
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "exec_credentials_linux_tests.rs"]
mod tests;

#[cfg(target_os = "linux")]
pub(super) fn current_boot() -> Result<String, String> {
    linux::boot()
}
#[cfg(target_os = "linux")]
pub(super) fn process_start(pid: u32) -> Result<u64, String> {
    linux::start(pid)
}
