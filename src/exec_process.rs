//! Stop only a registered foreground Docker exec. A Linux pidfd prevents PID
//! reuse retargeting; container cgroup, live exec association and a fresh injected
//! marker must all agree before any signal. No arbitrary host PID API exists.
use crate::docker;

#[derive(Clone)]
pub struct Reference {
    pub container: String,
    pub id: String,
    pub nonce: String,
    pub start: std::sync::Arc<crate::exec_lifecycle::Lifecycle>,
    #[cfg(target_os = "linux")]
    foreground: std::sync::Arc<std::sync::Mutex<Option<std::sync::Arc<PinnedForeground>>>>,
}

fn valid_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn reference(container: &str, id: &str, nonce: String) -> Result<Reference, String> {
    if !valid_hex(container, 64) || !valid_hex(id, 64) || !valid_hex(&nonce, 32) {
        return Err("invalid registered exec identity".into());
    }
    Ok(Reference {
        container: container.into(),
        id: id.into(),
        nonce,
        start: crate::exec_lifecycle::Lifecycle::new(),
        #[cfg(target_os = "linux")]
        foreground: std::sync::Arc::new(std::sync::Mutex::new(None)),
    })
}
fn info(r: &Reference) -> Result<Option<serde_json::Value>, String> {
    let v = match docker::inspect_registered_exec(&r.id) {
        Ok(v) => v,
        Err(e)
            if e.starts_with(&format!("docker GET /exec/{}/json: HTTP 404:", r.id))
                && docker::registered_container_absent(&r.container)? =>
        {
            return Ok(None)
        }
        Err(e) => return Err(e),
    };
    if v["ContainerID"].as_str() != Some(r.container.as_str()) || !v["Running"].is_boolean() {
        return Err("registered exec association is unverified".into());
    }
    Ok(Some(v))
}
/// Read-only start witness for stdin EOF. This never signals a process and
/// never retires a null/unknown exec or treats HTTP headers as completion.
pub fn start_witness(r: &Reference) -> Result<bool, String> {
    if r.start.never_started() {
        return Ok(true);
    }
    let Some(v) = info(r)? else {
        return Ok(true);
    };
    if v["Running"].as_bool() == Some(true) {
        r.start.observe_running();
        return Ok(true);
    }
    Ok(r.start.terminal_without_running(v["ExitCode"].as_i64()))
}
pub fn finish(r: &Reference) -> Result<bool, String> {
    finish_observed(r, &mut |r| info(r))
}

/// Private foreground execution proof, not a Docker metadata-GC receipt.
/// Constructed only after the SAME already-retained OS pin really exits.
pub(crate) struct RecoveryOsDrained {
    container: String,
    exec: String,
    nonce: String,
}
impl RecoveryOsDrained {
    pub(crate) fn matches(&self, container: &str, exec: &str, nonce: &str) -> bool {
        self.container == container && self.exec == exec && self.nonce == nonce
    }
}

/// Read-only poll of an ALREADY established exact foreground pin. No Docker,
/// new pidfd, process discovery, signal, or metadata-derived witness exists on
/// this path. An unsupported platform/no prior pin yields no proof, not zero.
pub(crate) fn recovery_retained_exit(
    reference: &Reference,
) -> Result<Option<RecoveryOsDrained>, String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = reference;
        Ok(None)
    }
    #[cfg(target_os = "linux")]
    {
        let Some(pin) = retained_pin(reference)? else {
            return Ok(None);
        };
        if !pin.exited()? {
            return Ok(None);
        }
        Ok(Some(RecoveryOsDrained {
            container: reference.container.clone(),
            exec: reference.id.clone(),
            nonce: reference.nonce.clone(),
        }))
    }
}

pub(crate) fn recovery_drain(
    reference: &Reference,
    observe: &mut impl FnMut(&Reference) -> Result<Option<serde_json::Value>, String>,
) -> Result<Option<RecoveryOsDrained>, String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (reference, observe);
        return Err("startup foreground recovery requires Linux; backlog retained".into());
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(proof) = recovery_retained_exit(reference)? {
            return Ok(Some(proof));
        }
        if matches!(
            reference.start.phase(),
            crate::exec_lifecycle::Phase::Created | crate::exec_lifecycle::Phase::NeverStarted
        ) {
            return Err("recovery lacks durable possible-Start lineage; no OS proof".into());
        }
        let observed = observe(reference)?;
        if retained_pin(reference)?.is_none()
            && !observed.as_ref().is_some_and(|v| v["Running"] == true)
        {
            return Err("old execution has no verified live foreground anchor; retain quarantine and inspect exact lineage manually".into());
        }
        let mut first = Some(observed);
        let result = finish_observed(reference, &mut |r| match first.take() {
            Some(value) => Ok(value),
            None => observe(r),
        })?;
        let exited = retained_pin(reference)?
            .ok_or("recovery cannot persist OSDrained without an actual retained pidfd")?
            .exited()?;
        if result && exited {
            recovery_retained_exit(reference)
        } else {
            Ok(None)
        }
    }
}

/// Private UNIT fixture, never built into production. Like the established
/// v4.2 retained-pin fixture it installs a real directly-owned child pidfd in a
/// test Reference; it does NOT prove production Docker/cgroup/nonce admission.
#[cfg(all(test, target_os = "linux"))]
pub(crate) mod startup_pin_fixture {
    use super::*;
    pub(crate) struct Owned {
        pub(crate) reference: Reference,
        child: std::process::Child,
    }
    impl Owned {
        pub(crate) fn new(reference: Reference) -> Self {
            use std::os::fd::FromRawFd;
            let child = std::process::Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .unwrap();
            // Own the child immediately so panic/error cleanup cannot orphan it.
            let fixture = Self { reference, child };
            let pid = i32::try_from(fixture.child.id()).unwrap();
            let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            let raw = libc::c_int::try_from(raw).unwrap();
            assert!(raw >= 0);
            let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
            let pin = std::sync::Arc::new(PinnedForeground {
                pid,
                start: process_start(pid).unwrap(),
                fd,
            });
            assert!(!pin.exited().unwrap());
            *fixture.reference.foreground.lock().unwrap() = Some(pin);
            fixture
        }
        pub(crate) fn exit(&mut self) {
            self.child.kill().unwrap();
            self.child.wait().unwrap();
        }
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(test)]
mod startup_recovery_proof_tests {
    use super::*;
    #[test]
    fn null_numeric_and_absent_metadata_never_create_an_os_drain_proof() {
        for exit in [
            serde_json::Value::Null,
            serde_json::json!(0),
            serde_json::json!(137),
        ] {
            let r = reference(&"a".repeat(64), &"b".repeat(64), "c".repeat(32)).unwrap();
            drop(r.start.begin().unwrap());
            let v = serde_json::json!({"ContainerID":r.container,"Running":false,"ExitCode":exit,"Pid":0});
            assert!(recovery_drain(&r, &mut |_| Ok(Some(v.clone()))).is_err());
        }
        let r = reference(&"a".repeat(64), &"b".repeat(64), "c".repeat(32)).unwrap();
        drop(r.start.begin().unwrap());
        assert!(recovery_drain(&r, &mut |_| Ok(None)).is_err());
    }
    #[test]
    fn explicit_cancel_before_start_does_not_consult_docker_or_mint_os_exit() {
        let r = reference(&"a".repeat(64), &"b".repeat(64), "c".repeat(32)).unwrap();
        r.start.cancel_before_start();
        assert!(r.start.never_started());
        assert!(recovery_drain(&r, &mut |_| panic!("explicit no-Start cannot consult Docker")).is_err());
    }
    #[test]
    fn never_submitted_lifecycle_is_not_relabelled_as_kernel_exit() {
        let r = reference(&"a".repeat(64), &"b".repeat(64), "c".repeat(32)).unwrap();
        assert!(recovery_drain(&r, &mut |_| panic!("no Docker read needed")).is_err());
    }
}
/// Node-internal observer injection; not a public PID/HTTP interface. The
/// durable gate supplies bounded peer-verified observations on every inspect.
pub(crate) fn finish_observed(
    r: &Reference,
    observe: &mut impl FnMut(&Reference) -> Result<Option<serde_json::Value>, String>,
) -> Result<bool, String> {
    // A known OS pin takes precedence over Docker's false/numeric shortcuts
    // on EVERY retry. Clones share one FD; no network call holds the slot lock.
    #[cfg(target_os = "linux")]
    if let Some(pin) = retained_pin(r)? {
        if pin.exited()? {
            return Ok(true); // OS exit only; no synthetic Docker ExitCode/GC.
        }
        if r.start.never_started() {
            return Err("never-start state contradicts a retained live foreground pin".into());
        }
    }
    if r.start.never_started() {
        return Ok(true);
    }
    let observed = observe(r)?;
    #[cfg(target_os = "linux")]
    if let Some(pin) = retained_pin(r)? {
        return stop_pinned(r, pin, observed.as_ref(), observe);
    }
    let Some(v) = observed else {
        return Ok(true);
    };
    if v["ContainerID"].as_str() != Some(r.container.as_str()) || !v["Running"].is_boolean() {
        return Err("attested exec association is unverified".into());
    }
    if v["Running"].as_bool() == Some(false) {
        // Initially ExitCode is null. Transport 101/200 is sent BEFORE
        // ContainerExecStart and is not process-start/termination proof.
        return Ok(r.start.terminal_without_running(v["ExitCode"].as_i64()));
    }
    r.start.observe_running();
    #[cfg(target_os = "linux")]
    {
        stop_linux(r, &v, observe)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err("foreground exec termination requires the local Linux node agent; capacity retained until it exits".into())
    }
}

#[cfg(target_os = "linux")]
fn bounded_proc(path: &str, bound: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut out = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| "exec process identity unavailable")?
        .take(bound + 1)
        .read_to_end(&mut out)
        .map_err(|_| "exec process identity unreadable")?;
    if out.len() as u64 > bound {
        return Err("exec process identity exceeds bound".into());
    }
    Ok(out)
}
fn cgroup_matches(bytes: &[u8], container: &str) -> bool {
    std::str::from_utf8(bytes).ok().is_some_and(|text| {
        text.lines()
            .filter_map(|l| l.splitn(3, ':').nth(2))
            .flat_map(|path| path.split('/'))
            .any(|part| {
                part == container
                    || part
                        .strip_prefix("docker-")
                        .and_then(|s| s.strip_suffix(".scope"))
                        == Some(container)
            })
    })
}
fn marker_matches(bytes: &[u8], nonce: &str) -> bool {
    let expected = format!("ROYAK_EXEC_SESSION={nonce}");
    bytes
        .split(|b| *b == 0)
        .any(|value| value == expected.as_bytes())
}

#[cfg(target_os = "linux")]
fn pin_process(pid: i32, r: &Reference) -> Result<PinnedForeground, String> {
    use std::os::fd::FromRawFd;
    if pid <= 1 || pid as u32 == std::process::id() {
        return Err("refusing unsafe exec PID".into());
    }
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err("cannot pin registered exec process".into());
    }
    let raw: libc::c_int = fd.try_into().map_err(|_| "pidfd exceeds descriptor ABI")?;
    let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    let flags = unsafe { libc::fcntl(std::os::fd::AsRawFd::as_raw_fd(&fd), libc::F_GETFD) };
    if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
        return Err("foreground pidfd is not CLOEXEC".into());
    }
    let pinned = PinnedForeground {
        pid,
        start: process_start(pid)?,
        fd,
    };
    if pinned.exited()? {
        return Err("foreground exited before its initial identity was established".into());
    }
    if !cgroup_matches(
        &bounded_proc(&format!("/proc/{pid}/cgroup"), 64 * 1024)?,
        &r.container,
    ) || !marker_matches(
        &bounded_proc(&format!("/proc/{pid}/environ"), 256 * 1024)?,
        &r.nonce,
    ) {
        return Err(
            "exec PID is not bound to the expected container/session; refusing signal".into(),
        );
    }
    if process_start(pid)? != pinned.start || pinned.exited()? {
        return Err("foreground identity changed while establishing the pin".into());
    }
    Ok(pinned)
}

/// Only an already-established exact OS pin may use this helper. Docker
/// metadata absence/non-running never overrules a known-live foreground. The
/// separate durable Docker metadata charge is NOT released by this boolean.
fn terminal_after_pin(
    reference: &Reference,
    expected_pid: i32,
    current: Option<&serde_json::Value>,
    pinned_exited: bool,
) -> Result<bool, String> {
    if let Some(current) = current {
        if current["ContainerID"].as_str() != Some(reference.container.as_str())
            || !current["Running"].is_boolean()
        {
            return Err("fresh attested exec association is unverified".into());
        }
        if current["Running"].as_bool() == Some(true)
            && current["Pid"].as_i64() != Some(i64::from(expected_pid))
        {
            return Err("exec PID changed during verification; refusing signal".into());
        }
    }
    if pinned_exited {
        return Ok(true);
    }
    match current {
        None => Err("Docker metadata absent while pinned foreground process is alive; capacity retained".into()),
        Some(value) if value["Running"].as_bool() == Some(false) => Err(
            "Docker non-running observation contradicts live pinned foreground process; capacity retained".into(),
        ),
        Some(_) => Ok(false),
    }
}

#[cfg(target_os = "linux")]
fn pidfd_exit_event(ready: i32, events: libc::c_short) -> Result<bool, String> {
    if ready == 0 && events == 0 {
        return Ok(false);
    }
    let allowed = libc::POLLIN | libc::POLLHUP;
    if ready == 1 && events & libc::POLLIN != 0 && events & !allowed == 0 {
        return Ok(true);
    }
    Err("pinned exec pidfd exit is unknown; capacity retained".into())
}

#[cfg(target_os = "linux")]
fn process_start(pid: i32) -> Result<u64, String> {
    let bytes = bounded_proc(&format!("/proc/{pid}/stat"), 16 * 1024)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "invalid foreground process stat")?;
    text.rsplit_once(')')
        .ok_or("invalid foreground process stat")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or("missing foreground process start")?
        .parse::<u64>()
        .ok()
        .filter(|start| *start > 0)
        .ok_or_else(|| "invalid foreground process start".into())
}

#[cfg(target_os = "linux")]
struct PinnedForeground {
    pid: i32,
    start: u64,
    fd: std::os::fd::OwnedFd,
}
#[cfg(target_os = "linux")]
impl PinnedForeground {
    fn exited(&self) -> Result<bool, String> {
        use std::os::fd::AsRawFd;
        let mut p = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut p, 1, 0) };
        pidfd_exit_event(ready, p.revents)
    }
    fn validate_live(&self, reference: &Reference) -> Result<(), String> {
        if process_start(self.pid)? != self.start
            || !cgroup_matches(
                &bounded_proc(&format!("/proc/{}/cgroup", self.pid), 64 * 1024)?,
                &reference.container,
            )
            || !marker_matches(
                &bounded_proc(&format!("/proc/{}/environ", self.pid), 256 * 1024)?,
                &reference.nonce,
            )
        {
            return Err(
                "retained foreground PID/start/container/session changed; refusing signal".into(),
            );
        }
        Ok(())
    }
}
#[cfg(target_os = "linux")]
fn retained_pin(reference: &Reference) -> Result<Option<std::sync::Arc<PinnedForeground>>, String> {
    Ok(reference
        .foreground
        .lock()
        .map_err(|_| "foreground pin ownership is unknown; capacity retained")?
        .clone())
}

#[cfg(target_os = "linux")]
fn ensure_pin(reference: &Reference, pid: i32) -> Result<std::sync::Arc<PinnedForeground>, String> {
    // Only bounded local pin/proc reads hold this lock. No Docker/network,
    // sleep, signal wait, FD duplication or recursive observer is under it.
    let mut slot = reference
        .foreground
        .lock()
        .map_err(|_| "foreground pin ownership is unknown; capacity retained")?;
    if let Some(pin) = slot.as_ref() {
        if pin.pid != pid {
            return Err("retained foreground PID differs; refusing a replacement pin".into());
        }
        return Ok(pin.clone());
    }
    let pin = std::sync::Arc::new(pin_process(pid, reference)?);
    *slot = Some(pin.clone());
    Ok(pin)
}

#[cfg(target_os = "linux")]
fn stop_linux(
    reference: &Reference,
    initial: &serde_json::Value,
    observe: &mut impl FnMut(&Reference) -> Result<Option<serde_json::Value>, String>,
) -> Result<bool, String> {
    let pid = initial["Pid"]
        .as_i64()
        .and_then(|p| i32::try_from(p).ok())
        .ok_or("missing registered exec PID")?;
    let pin = ensure_pin(reference, pid)?;
    stop_pinned(reference, pin, Some(initial), observe)
}

#[cfg(target_os = "linux")]
fn stop_pinned(
    reference: &Reference,
    pin: std::sync::Arc<PinnedForeground>,
    initial: Option<&serde_json::Value>,
    observe: &mut impl FnMut(&Reference) -> Result<Option<serde_json::Value>, String>,
) -> Result<bool, String> {
    use std::os::fd::AsRawFd;
    if terminal_after_pin(reference, pin.pid, initial, pin.exited()?)? {
        return Ok(true);
    }
    pin.validate_live(reference)?;
    let current = observe(reference)?;
    if terminal_after_pin(reference, pin.pid, current.as_ref(), pin.exited()?)? {
        return Ok(true);
    }
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        if pin.exited()? {
            return Ok(true);
        }
        pin.validate_live(reference)?;
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pin.fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
            return Err("registered exec signal was not acknowledged".into());
        }
        for _ in 0..10 {
            if pin.exited()? {
                return Ok(true);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
    pin.exited()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proc_identity_requires_exact_container_component_and_injected_marker() {
        let id = "a".repeat(64);
        let nonce = "b".repeat(32);
        assert!(cgroup_matches(
            format!("0::/system.slice/docker-{id}.scope\n").as_bytes(),
            &id
        ));
        assert!(!cgroup_matches(
            format!("0::/docker/{id}-other\n").as_bytes(),
            &id
        ));
        assert!(marker_matches(
            format!("X=1\0ROYAK_EXEC_SESSION={nonce}\0").as_bytes(),
            &nonce
        ));
        assert!(!marker_matches(
            format!("ROYAK_EXEC_SESSION={nonce}0\0").as_bytes(),
            &nonce
        ));
        assert!(reference("short", &id, nonce).is_err());
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn an_owned_test_child_outside_the_registered_cgroup_is_not_signalled() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let r = reference(&"a".repeat(64), &"b".repeat(64), "c".repeat(32)).unwrap();
        let result = pin_process(child.id() as i32, &r);
        assert!(child.try_wait().unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod pinned_terminal_regressions {
    use super::*;

    fn reference_fixture() -> Reference {
        reference(&"a".repeat(64), &"b".repeat(64), "c".repeat(32)).unwrap()
    }
    fn view(r: &Reference, running: bool, exit: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "ContainerID": r.container, "Running": running, "ExitCode": exit, "Pid": 2345,
        })
    }

    #[test]
    fn live_known_pin_cannot_be_finished_by_null_missing_numeric_or_absent_metadata() {
        let r = reference_fixture();
        assert!(terminal_after_pin(&r, 2345, None, false).is_err());
        for exit in [
            serde_json::Value::Null,
            serde_json::json!(0),
            serde_json::json!(137),
        ] {
            let current = view(&r, false, exit);
            assert!(terminal_after_pin(&r, 2345, Some(&current), false).is_err());
        }
        let missing_exit = serde_json::json!({"ContainerID": r.container, "Running": false});
        assert!(terminal_after_pin(&r, 2345, Some(&missing_exit), false).is_err());
    }

    #[test]
    fn verified_os_pin_exit_is_foreground_proof_without_inventing_an_exit_code() {
        let r = reference_fixture();
        assert_eq!(terminal_after_pin(&r, 2345, None, true), Ok(true));
        let null_exit = view(&r, false, serde_json::Value::Null);
        assert_eq!(
            terminal_after_pin(&r, 2345, Some(&null_exit), true),
            Ok(true)
        );
        assert!(null_exit["ExitCode"].is_null());
        let stale_running = view(&r, true, serde_json::Value::Null);
        assert_eq!(
            terminal_after_pin(&r, 2345, Some(&stale_running), true),
            Ok(true)
        );
    }

    #[test]
    fn changed_lineage_or_pid_remains_unknown_in_a_fresh_pinned_observation() {
        let r = reference_fixture();
        let mut wrong_container = view(&r, false, serde_json::json!(0));
        wrong_container["ContainerID"] = serde_json::json!("c".repeat(64));
        assert!(terminal_after_pin(&r, 2345, Some(&wrong_container), true).is_err());
        let wrong_pid = view(&r, true, serde_json::Value::Null);
        assert!(terminal_after_pin(&r, 9999, Some(&wrong_pid), true).is_err());
        let missing_running = serde_json::json!({"ContainerID": r.container, "ExitCode": 0});
        assert!(terminal_after_pin(&r, 2345, Some(&missing_running), true).is_err());
    }

    #[test]
    fn matching_live_running_pin_retains_foreground_state() {
        let r = reference_fixture();
        let current = view(&r, true, serde_json::Value::Null);
        assert_eq!(
            terminal_after_pin(&r, 2345, Some(&current), false),
            Ok(false)
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn pidfd_poll_errors_and_unrecognized_events_are_unknown_not_exit() {
        assert_eq!(pidfd_exit_event(0, 0), Ok(false));
        assert_eq!(pidfd_exit_event(1, libc::POLLIN), Ok(true));
        assert_eq!(pidfd_exit_event(1, libc::POLLIN | libc::POLLHUP), Ok(true));
        for (ready, events) in [
            (-1, 0),
            (1, libc::POLLNVAL),
            (1, libc::POLLERR),
            (1, libc::POLLHUP),
            (0, libc::POLLIN),
            (1, 0),
            (2, libc::POLLIN),
        ] {
            assert!(pidfd_exit_event(ready, events).is_err());
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn cloned_retries_keep_one_known_live_pin_until_real_os_exit() {
        use std::os::fd::{AsRawFd, FromRawFd};
        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = OwnedChild(
            std::process::Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .unwrap(),
        );
        let r = reference_fixture();
        let pid = i32::try_from(child.0.id()).unwrap();
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        let raw = libc::c_int::try_from(raw).unwrap();
        assert!(raw >= 0);
        // Private cfg(test) construction exercises retained-reference control
        // flow, not production cgroup/session admission or a signal capability.
        let pin = std::sync::Arc::new(PinnedForeground {
            pid,
            start: process_start(pid).unwrap(),
            fd: unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) },
        });
        assert!(!pin.exited().unwrap());
        *r.foreground.lock().unwrap() = Some(pin.clone());
        drop(r.start.begin().unwrap());
        r.start.observe_running();
        let clone = r.clone();
        let cloned_pin = retained_pin(&clone).unwrap().unwrap();
        assert!(std::sync::Arc::ptr_eq(&pin, &cloned_pin));
        assert_eq!(pin.fd.as_raw_fd(), cloned_pin.fd.as_raw_fd());
        for exit in [
            serde_json::Value::Null,
            serde_json::json!(0),
            serde_json::json!(137),
        ] {
            let snapshot = serde_json::json!({
                "ContainerID": r.container, "Running": false, "ExitCode": exit, "Pid": 0,
            });
            let mut calls = 0;
            assert!(finish_observed(&clone, &mut |_| {
                calls += 1;
                Ok(Some(snapshot.clone()))
            })
            .is_err());
            assert_eq!(calls, 1);
            assert!(child.0.try_wait().unwrap().is_none());
            assert!(std::sync::Arc::ptr_eq(
                &pin,
                &retained_pin(&r).unwrap().unwrap()
            ));
        }
        assert!(finish_observed(&clone, &mut |_| Ok(None)).is_err());
        // Kill/reap only this directly spawned test child; production code above
        // did not signal it for contradictory metadata.
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert!(pin.exited().unwrap());
        let mut called = false;
        assert_eq!(
            finish_observed(&clone, &mut |_| {
                called = true;
                Err("daemon unavailable".into())
            }),
            Ok(true)
        );
        assert!(
            !called,
            "known OS exit must not need a fabricated daemon receipt"
        );
    }
}
