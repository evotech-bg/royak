//! Fixed-program, bounded, no-shell child execution, with explicit unknown IO.
use sha2::{Digest, Sha256};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};
struct Pending {
    child: Option<Child>,
    scope: Option<super::job_cgroup::JobCgroup>,
}
static CHILDREN: Mutex<Vec<Pending>> = Mutex::new(Vec::new());
/// Read-only exact-child reap/drain check for the one fixed identity worker.
/// Never signal a numeric PID or treat a busy/unknown lock as drained.
pub(super) fn commands_drained() -> bool {
    let Ok(mut pending) = CHILDREN.try_lock() else {
        return false;
    };
    pending.retain_mut(|p| {
        if let Some(child) = &mut p.child {
            if matches!(child.try_wait(), Ok(Some(_))) {
                p.child = None;
            }
        }
        p.child.is_some()
            || p.scope
                .as_ref()
                .is_some_and(|scope| !matches!(scope.populated(), Ok(false)))
    });
    pending.is_empty()
}
const LIMIT: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub enum Program {
    Pvs,
    Vgs,
    Lvs,
    Lsblk,
    Lvcreate,
    Lvremove,
    Blkid,
    Drbdadm,
    Drbdsetup,
    Drbdmeta,
    Wireguard,
    Ip,
    Nft,
    MkfsExt4,
}
impl Program {
    fn path(self) -> &'static str {
        match self {
            Self::Pvs => "/usr/sbin/pvs",
            Self::Vgs => "/usr/sbin/vgs",
            Self::Lvs => "/usr/sbin/lvs",
            Self::Lsblk => "/usr/bin/lsblk",
            Self::Lvcreate => "/usr/sbin/lvcreate",
            Self::Lvremove => "/usr/sbin/lvremove",
            Self::Blkid => "/usr/sbin/blkid",
            Self::Drbdadm => "/usr/sbin/drbdadm",
            Self::Drbdsetup => "/usr/sbin/drbdsetup",
            Self::Drbdmeta => "/usr/sbin/drbdmeta",
            Self::Wireguard => "/usr/bin/wg",
            Self::Ip => "/usr/sbin/ip",
            Self::Nft => "/usr/sbin/nft",
            Self::MkfsExt4 => "/usr/sbin/mkfs.ext4",
        }
    }
}
#[derive(Debug)]
pub struct Output {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}
impl Output {
    pub fn success(self, label: &str) -> Result<Vec<u8>, String> {
        if self.code == 0 {
            Ok(self.stdout)
        } else {
            Err(format!(
                "storage command {label} failed (exit {}, stderr sha256 {:x})",
                self.code,
                Sha256::digest(&self.stderr)
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commands_have_bounded_time_output_and_do_not_inherit_secrets() {
        std::env::set_var("ROYAK_TEST_DRIVER_SECRET", "not-a-real-secret");
        let output = execute("/usr/bin/env", &[], Duration::from_secs(1)).unwrap();
        assert!(!String::from_utf8_lossy(&output.stdout).contains("ROYAK_TEST_DRIVER_SECRET"));
        let started = Instant::now();
        assert!(
            execute("/bin/sleep", &["2".into()], Duration::from_millis(50))
                .unwrap_err()
                .contains("UNKNOWN")
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(execute("/usr/bin/yes", &[], Duration::from_secs(1))
            .unwrap_err()
            .contains("output exceeded"));
        assert!(CHILDREN.lock().unwrap().is_empty());
        let out = execute(
            "/bin/sh",
            &["-c".into(), "printf must-not-log >&2; exit 3".into()],
            Duration::from_secs(1),
        )
        .unwrap();
        let error = out.success("test").unwrap_err();
        assert!(!error.contains("must-not-log"));
        assert!(error.contains("sha256"));
    }

    #[test]
    fn exited_leader_remains_unreaped_until_descendant_pipe_group_is_cancelled() {
        let mut unrelated = Command::new("/bin/sleep").arg("3").spawn().unwrap();
        let started = Instant::now();
        let error = execute(
            "/bin/sh",
            &["-c".into(), "(sleep 5) & exit 0".into()],
            Duration::from_millis(80),
        )
        .unwrap_err();
        assert!(error.contains("UNKNOWN"));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(
            unrelated.try_wait().unwrap().is_none(),
            "never signal a foreign process/group"
        );
        unrelated.kill().unwrap();
        unrelated.wait().unwrap();
        assert!(CHILDREN.lock().unwrap().is_empty());
    }

    #[test]
    fn waitid_observation_reserves_leader_until_final_signal_and_reap() {
        let mut child = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .process_group(0)
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        while !exited_unreaped(&child).unwrap() {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(exited_unreaped(&child).unwrap());
        assert_eq!(
            unsafe { libc::kill(child.id() as i32, 0) },
            0,
            "zombie PID stays reserved, not reusable"
        );
        assert!(child.wait().unwrap().success());
        assert!(
            signal_owned_group(&child).is_err(),
            "reaped child must not be signalled by stale PGID"
        );
    }
}
pub fn run(program: Program, args: &[String]) -> Result<Output, String> {
    let scope = super::live_authority::before_program(&format!("{program:?}"), args)?;
    execute_scoped(program.path(), args, Duration::from_secs(15), scope)
}

/// Observe without reaping: the unreaped leader reserves the PGID until every
/// group signal is complete. Never follow try_wait/wait with kill(-old_pid).
pub(super) fn exited_unreaped(child: &Child) -> Result<bool, String> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    loop {
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result == 0 {
            return Ok(info.si_signo == libc::SIGCHLD);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(
                "cannot observe owned child without reaping; never signal an uncertain PGID".into(),
            );
        }
    }
}

fn signal_owned_group(child: &Child) -> Result<(), String> {
    // ECHILD/unknown ownership is a refusal, never permission to signal a PID.
    exited_unreaped(child)?;
    let r = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
    if r != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        return Err("cannot signal the still-reserved owned process group".into());
    }
    Ok(())
}
fn execute(path: &str, args: &[String], timeout: Duration) -> Result<Output, String> {
    execute_scoped(path, args, timeout, None)
}
fn execute_scoped(
    path: &str,
    args: &[String],
    timeout: Duration,
    scope: Option<super::job_cgroup::JobCgroup>,
) -> Result<Output, String> {
    let mut pending = CHILDREN.lock().unwrap_or_else(|e| e.into_inner());
    pending.retain_mut(|p| {
        if let Some(c) = &mut p.child {
            if matches!(c.try_wait(), Ok(Some(_))) {
                p.child = None;
            }
        }
        p.child.is_some()
            || p.scope
                .as_ref()
                .is_some_and(|s| !matches!(s.populated(), Ok(false)))
    });
    if !pending.is_empty() {
        return Err(
            "prior storage command still unreaped; outcome UNKNOWN, no new command permitted"
                .into(),
        );
    }
    let meta = std::fs::metadata(path).map_err(|_| "fixed storage program is unavailable")?;
    if !meta.is_file() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err("fixed storage program is not root-owned/read-only to other users".into());
    }
    let mut command = Command::new(path);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("LC_ALL", "C")
        .env("HOME", "/")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    let procs = scope.as_ref().map(|s| s.procs_for_child()).transpose()?;
    let parent = std::process::id();
    unsafe {
        command.pre_exec(move || {
            #[cfg(target_os = "linux")]
            {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                    || libc::getppid() as u32 != parent
                {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(procs) = &procs {
                    if libc::write(procs.as_raw_fd(), b"0\n".as_ptr().cast(), 2) != 2 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
            }
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|_| "cannot start fixed storage program")?;
    let out = match child.stdout.take() {
        Some(v) => v,
        None => {
            if let Some(scope) = &scope {
                let _ = scope.kill_exact();
            } else {
                let _ = signal_owned_group(&child);
            }
            pending.push(Pending {
                child: Some(child),
                scope,
            });
            return Err("missing command stdout; outcome UNKNOWN".into());
        }
    };
    let err = match child.stderr.take() {
        Some(v) => v,
        None => {
            if let Some(scope) = &scope {
                let _ = scope.kill_exact();
            } else {
                let _ = signal_owned_group(&child);
            }
            pending.push(Pending {
                child: Some(child),
                scope,
            });
            return Err("missing command stderr; outcome UNKNOWN".into());
        }
    };
    let fds = [out.as_raw_fd(), err.as_raw_fd()];
    for fd in fds {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            let _ = signal_owned_group(&child);
            if let Some(scope) = &scope {
                let _ = scope.kill_exact();
            }
            pending.push(Pending {
                child: Some(child),
                scope,
            });
            return Err("cannot bound command pipes; outcome UNKNOWN".into());
        }
    }
    let mut readers: [Box<dyn Read>; 2] = [Box::new(out), Box::new(err)];
    let mut bytes = [Vec::new(), Vec::new()];
    let mut closed = [false, false];
    let mut exited = false;
    let deadline = Instant::now() + timeout;
    let mut failure = None;
    loop {
        for i in 0..2 {
            if closed[i] {
                continue;
            }
            let mut buffer = [0u8; 16384];
            loop {
                match readers[i].read(&mut buffer) {
                    Ok(0) => {
                        closed[i] = true;
                        break;
                    }
                    Ok(n) => {
                        if bytes[i].len() + n > LIMIT {
                            failure = Some("storage command output exceeded bound");
                            break;
                        }
                        bytes[i].extend_from_slice(&buffer[..n]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => {
                        failure = Some("storage command pipe failed");
                        break;
                    }
                }
            }
        }
        if !exited {
            match exited_unreaped(&child) {
                Ok(s) => exited = s,
                Err(_) => failure = Some("cannot observe storage child"),
            }
        }
        if failure.is_some() || Instant::now() >= deadline {
            break;
        }
        if exited && closed.into_iter().all(|x| x) {
            let containment_error = scope.as_ref().and_then(|s| s.kill_exact().err());
            if let Some(e) = containment_error {
                pending.push(Pending {
                    child: Some(child),
                    scope,
                });
                return Err(format!("{e}; command outcome UNKNOWN"));
            }
            let status = match child.wait() {
                Ok(v) => v,
                Err(_) => {
                    pending.push(Pending {
                        child: Some(child),
                        scope,
                    });
                    return Err("cannot reap observed owned child; UNKNOWN".into());
                }
            };
            if scope
                .as_ref()
                .is_some_and(|s| !matches!(s.populated(), Ok(false)))
            {
                pending.push(Pending { child: None, scope });
                return Err(
                    "storage command descendants remain/unknown; no next command permitted".into(),
                );
            }
            return Ok(Output {
                code: status.code().unwrap_or(-1),
                stdout: bytes[0].clone(),
                stderr: bytes[1].clone(),
            });
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if let Err(e) = signal_owned_group(&child) {
        if let Some(scope) = &scope {
            let _ = scope.kill_exact();
        }
        pending.push(Pending {
            child: Some(child),
            scope,
        });
        return Err(format!("{e}; outcome UNKNOWN, child ownership retained"));
    }
    if let Some(scope) = &scope {
        let _ = scope.kill_exact();
    }
    let grace = Instant::now() + Duration::from_secs(2);
    while !exited && Instant::now() < grace {
        exited = match exited_unreaped(&child) {
            Ok(v) => v,
            Err(e) => {
                pending.push(Pending {
                    child: Some(child),
                    scope,
                });
                return Err(format!("{e}; UNKNOWN"));
            }
        };
        if !exited {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    if !exited {
        pending.push(Pending {
            child: Some(child),
            scope,
        });
    } else {
        if child.wait().is_err() {
            pending.push(Pending {
                child: Some(child),
                scope,
            });
            return Err("cannot reap owned storage child after final signal; UNKNOWN".into());
        }
        if scope
            .as_ref()
            .is_some_and(|s| !matches!(s.populated(), Ok(false)))
        {
            pending.push(Pending { child: None, scope });
        }
    }
    Err(format!(
        "{}; outcome UNKNOWN, inspect durable operation journal before retry",
        failure.unwrap_or("storage command deadline exceeded")
    ))
}
