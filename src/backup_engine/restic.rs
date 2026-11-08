//! Pinned bounded restic adapter. Local owned repositories only in this first
//! adapter; remote credentials/TLS/backend isolation require a separate adapter.
//! No shell, init, prune, forget, unlock, live-directory API or inherited env.
use super::journal::PrivateDir;
use super::{
    digest, hash_ok, sha, tree, BackupSource, CaptureEvidence, CapturePlan, CaptureReceipt,
    CheckEvidence, CheckReceipt, RecoveryManifest, Repository,
};
use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
const BINARY_LIMIT: u64 = 64 * 1024 * 1024;
static ACTIVE: AtomicBool = AtomicBool::new(false);
static UNREAPED: Mutex<Vec<Child>> = Mutex::new(Vec::new());
// A group signal/reaped leader does NOT prove absence of escaped descendants.
// Never admit another child after an abnormal exit without the separately
// required owned Linux cgroup populated=0/recovery receipt. No reset API exists.
static UNKNOWN_DESCENDANT_LEASE: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static FIXTURE_CHILD_SPAWNED: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
pub(super) fn arm_spawn_revocation_fixture() {
    FIXTURE_CHILD_SPAWNED.store(false, Ordering::Release);
}
#[cfg(test)]
pub(super) fn fixture_child_spawned() -> bool {
    FIXTURE_CHILD_SPAWNED.load(Ordering::Acquire)
}

#[cfg(test)]
pub(super) fn leader_reaped_dispatch_blocked_for_fixture() -> bool {
    UNREAPED.lock().unwrap().is_empty()
        && !ACTIVE.load(Ordering::Acquire)
        && UNKNOWN_DESCENDANT_LEASE.load(Ordering::Acquire)
}

/// Explicit operator budget, never a user-supplied arbitrary process timeout.
#[derive(Clone, Copy)]
pub struct Budget {
    seconds: u64,
    bandwidth_kib: u32,
}
impl Budget {
    pub fn new(seconds: u64, bandwidth_kib: u32) -> Result<Self, String> {
        if !(1..=7200).contains(&seconds) || !(64..=262_144).contains(&bandwidth_kib) {
            return Err("restic job budget is outside admitted bounds".into());
        }
        Ok(Self {
            seconds,
            bandwidth_kib,
        })
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandReceipt {
    code: i32,
    stdout_sha256: String,
    stderr_sha256: String,
}
struct Output {
    receipt: CommandReceipt,
    stdout: Vec<u8>,
}
struct Admission {
    release: bool,
}
impl Drop for Admission {
    fn drop(&mut self) {
        if self.release {
            ACTIVE.store(false, Ordering::Release);
        }
    }
}
fn reap_old() -> Result<(), String> {
    let mut children = UNREAPED
        .lock()
        .map_err(|_| "backup child registry is poisoned")?;
    let mut i = 0;
    while i < children.len() {
        match children[i].try_wait() {
            Ok(Some(_)) => {
                children.swap_remove(i);
            }
            _ => i += 1,
        }
    }
    if UNKNOWN_DESCENDANT_LEASE.load(Ordering::Acquire) {
        Err("backup descendant lease unresolved; independent cgroup recovery required".into())
    } else if children.is_empty() {
        Ok(())
    } else {
        Err("previous backup child has not been reaped; dispatch blocked".into())
    }
}
fn nonblock(fd: i32) -> Result<(), String> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        Err("cannot bound backup child output".into())
    } else {
        Ok(())
    }
}
fn drain(reader: &mut impl Read, out: &mut Vec<u8>) -> Result<bool, String> {
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Ok(true),
            Ok(n) => {
                if out.len() + n > OUTPUT_LIMIT {
                    return Err("BACKUP_OUTPUT_LIMIT".into());
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(false),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err("BACKUP_OUTPUT_READ".into()),
        }
    }
}
fn terminate(child: &mut Child) -> bool {
    // Dedicated child process group; never target a name or unrelated process.
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return true;
        }
        if Instant::now() >= end {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Resolved private runtime configuration, NOT Deserialize and never accepted
/// from a namespaced API. Repository already exists and ID must match approval.
pub struct Restic {
    binary: PathBuf,
    binary_sha256: String,
    repository: Repository,
    repository_dir: PrivateDir,
    password_parent: PrivateDir,
    password_name: String,
    work: PrivateDir,
    budget: Budget,
}
impl Restic {
    pub fn open(
        binary: &Path,
        repository_path: &Path,
        password_file: &Path,
        work: &Path,
        repository: Repository,
        budget: Budget,
        mut allowed: impl FnMut() -> bool,
    ) -> Result<Self, String> {
        repository.validate()?;
        let binary_parent = binary.parent().ok_or("backup executable has no parent")?;
        let _trusted_binary_parent = PrivateDir::open(binary_parent)?;
        let password_parent = PrivateDir::open(
            password_file
                .parent()
                .ok_or("credential reference has no parent")?,
        )?;
        let password_name = password_file
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or("invalid credential reference")?
            .to_owned();
        let value = Self {
            binary: binary.into(),
            binary_sha256: repository.restic_binary_sha256.clone(),
            repository,
            repository_dir: PrivateDir::open(repository_path)?,
            password_parent,
            password_name,
            work: PrivateDir::open(work)?,
            budget,
        };
        let expected_backend = digest(&(
            "local-owned-v1",
            repository_path.to_str().ok_or("invalid repository path")?,
            &value.repository.repository_id,
            &value.repository.namespace_uid,
            &value.repository.credential_uid,
        ))?;
        if expected_backend != value.repository.approved_backend_sha256 {
            return Err("runtime backup backend differs from operator approval".into());
        }
        let config = value.run(&["cat".into(), "config".into()], &mut allowed)?;
        if config.receipt.code != 0 {
            return Err("BACKUP_REPOSITORY_UNAVAILABLE".into());
        }
        let config: serde_json::Value = serde_json::from_slice(&config.stdout)
            .map_err(|_| "invalid restic repository config")?;
        if config.get("id").and_then(|v| v.as_str())
            != Some(value.repository.repository_id.as_str())
            || config.get("version").and_then(|v| v.as_u64()) != Some(2)
        {
            return Err("backup repository ID/format differs from approved identity".into());
        }
        Ok(value)
    }
    fn verify_executable(&self) -> Result<File, String> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&self.binary)
            .map_err(|_| "cannot open pinned backup executable")?;
        let m = file
            .metadata()
            .map_err(|_| "cannot inspect pinned backup executable")?;
        if !m.is_file()
            || m.len() > BINARY_LIMIT
            || m.nlink() != 1
            || m.mode() & 0o022 != 0
            || m.mode() & 0o111 == 0
            || (m.uid() != 0 && m.uid() != unsafe { libc::geteuid() })
        {
            return Err("backup executable ownership/type is not trusted".into());
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(BINARY_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot hash backup executable")?;
        let after = file
            .metadata()
            .map_err(|_| "cannot inspect pinned backup executable")?;
        if bytes.len() as u64 != m.len()
            || sha(&bytes) != self.binary_sha256
            || m.len() != after.len()
            || m.mtime() != after.mtime()
            || m.mtime_nsec() != after.mtime_nsec()
        {
            return Err("pinned backup executable changed or hash mismatched".into());
        }
        Ok(file)
    }
    fn run(&self, args: &[OsString], allowed: &mut impl FnMut() -> bool) -> Result<Output, String> {
        reap_old()?;
        if ACTIVE.swap(true, Ordering::AcqRel) {
            return Err("backup worker concurrency exhausted".into());
        }
        let mut admission = Admission { release: true };
        if !allowed() {
            return Err("BACKUP_AUTH_REVOKED".into());
        }
        let _pin = self.verify_executable()?;
        let mut password = self
            .password_parent
            .read(&self.password_name, 64 * 1024)?
            .ok_or("backup credential reference absent")?;
        let valid_password = !password.is_empty();
        password.fill(0);
        if !valid_password {
            return Err("empty backup credential is not allowed".into());
        }
        let mut command = Command::new(&self.binary);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("HOME", self.work.path())
            .env("GOMAXPROCS", "2")
            .env(
                "RESTIC_PASSWORD_FILE",
                self.password_parent.path().join(&self.password_name),
            )
            .arg("--repo")
            .arg(self.repository_dir.path())
            .arg("--no-cache")
            .arg("--limit-upload")
            .arg(self.budget.bandwidth_kib.to_string())
            .arg("--limit-download")
            .arg(self.budget.bandwidth_kib.to_string())
            .arg("--stuck-request-timeout")
            .arg("30s")
            .args(args)
            .current_dir(self.work.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command
            .spawn()
            .map_err(|_| "BACKUP_CHILD_SPAWN".to_owned())?;
        #[cfg(test)]
        FIXTURE_CHILD_SPAWNED.store(true, Ordering::Release);
        let mut out = child.stdout.take().ok_or("BACKUP_OUTPUT_PIPE")?;
        let mut err = child.stderr.take().ok_or("BACKUP_OUTPUT_PIPE")?;
        let started = Instant::now();
        let result = (|| {
            nonblock(out.as_raw_fd())?;
            nonblock(err.as_raw_fd())?;
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            loop {
                if !allowed() {
                    return Err("BACKUP_AUTH_REVOKED".to_owned());
                }
                if started.elapsed() >= Duration::from_secs(self.budget.seconds) {
                    return Err("BACKUP_TIMEOUT".to_owned());
                }
                let eof_out = drain(&mut out, &mut stdout)?;
                let eof_err = drain(&mut err, &mut stderr)?;
                // Do NOT reap a dead leader while pipe-holding descendants
                // remain. Its unreaped PID reserves the process-group identity
                // until every possible group signal below has been issued.
                if eof_out && eof_err {
                    if let Some(status) = child.try_wait().map_err(|_| "BACKUP_CHILD_WAIT")? {
                        return Ok(Output {
                            receipt: CommandReceipt {
                                code: status.code().unwrap_or(-1),
                                stdout_sha256: sha(&stdout),
                                stderr_sha256: sha(&stderr),
                            },
                            stdout,
                        });
                    }
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        })();
        if result.is_err() {
            UNKNOWN_DESCENDANT_LEASE.store(true, Ordering::Release);
            // ECHILD/failed wait means ownership is uncertain: never signal a
            // potentially re-used group. Otherwise no try_wait has reaped the
            // leader before this single signal; no later re-signal is allowed.
            let wait_uncertain = result
                .as_ref()
                .err()
                .is_some_and(|e| e == "BACKUP_CHILD_WAIT");
            if wait_uncertain || !terminate(&mut child) {
                UNREAPED
                    .lock()
                    .map_err(|_| "backup child registry poisoned")?
                    .push(child);
            }
            admission.release = true;
        }
        result
    }
    fn validate_plan(&self, plan: &CapturePlan) -> Result<(), String> {
        plan.validate()?;
        if plan.repository != self.repository {
            return Err("backup plan/runtime repository mismatch".into());
        }
        Ok(())
    }
    /// Live path cannot be supplied by an HTTP caller or reconstructed from the
    /// journal. Source observer must keep the read-only snapshot lease valid.
    pub(crate) fn capture(
        &self,
        source: &BackupSource<'_>,
        plan: &CapturePlan,
        now: u64,
        mut allowed: impl FnMut() -> bool,
    ) -> Result<CaptureReceipt, String> {
        self.validate_plan(plan)?;
        let path = source.worker_path(plan)?;
        self.capture_path(path, plan, now, &mut || {
            allowed() && source.worker_path(plan).is_ok()
        })
    }
    fn capture_path(
        &self,
        path: &Path,
        plan: &CapturePlan,
        now: u64,
        allowed: &mut impl FnMut() -> bool,
    ) -> Result<CaptureReceipt, String> {
        self.validate_plan(plan)?;
        let payload_path = path
            .to_str()
            .filter(|p| super::snapshot_path_ok(p))
            .ok_or("invalid observed source path")?;
        let before = tree::inventory(path, &mut *allowed)?;
        let work = self
            .work
            .mkdir_new(&format!("capture-{}", plan.uid.as_str()))?;
        let manifest = RecoveryManifest {
            version: 1,
            plan_sha256: plan.hash()?,
            source: plan.source.clone(),
            repository_uid: self.repository.uid.clone(),
            repository_id: self.repository.repository_id.clone(),
            desired_generation: plan.desired_generation,
            driver: "restic".into(),
            repository_format: 2,
            payload_snapshot_path: payload_path.into(),
            tree_sha256: before.clone(),
        };
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|_| "cannot encode protected recovery manifest")?;
        work.write("royak-recovery.json", &manifest_bytes)?;
        let manifest_path = work.path().join("royak-recovery.json");
        let tag = format!("royak-job:{}", plan.uid.as_str());
        let result = self.run(
            &[
                "backup".into(),
                "--quiet".into(),
                "--json".into(),
                "--one-file-system".into(),
                "--read-concurrency".into(),
                "2".into(),
                "--host".into(),
                format!("royak:{}", plan.source.binding.cluster_id).into(),
                "--tag".into(),
                tag.clone().into(),
                path.as_os_str().into(),
                manifest_path.as_os_str().into(),
            ],
            allowed,
        )?;
        // Exit 3 is an incomplete snapshot with possible effects, NOT captured.
        if result.receipt.code != 0 {
            return Err(if result.receipt.code == 3 {
                "BACKUP_INCOMPLETE"
            } else {
                "BACKUP_CAPTURE_FAILED"
            }
            .into());
        }
        let mut summaries = Vec::new();
        for line in result
            .stdout
            .split(|b| *b == b'\n')
            .filter(|v| !v.is_empty())
        {
            let row: serde_json::Value =
                serde_json::from_slice(line).map_err(|_| "invalid backup JSON output")?;
            if row.get("message_type").and_then(|v| v.as_str()) == Some("summary") {
                summaries.push(
                    row.get("snapshot_id")
                        .and_then(|v| v.as_str())
                        .ok_or("backup summary has no full snapshot ID")?
                        .to_owned(),
                );
            }
        }
        if summaries.len() != 1 || !hash_ok(&summaries[0]) {
            return Err("backup returned ambiguous/incomplete snapshot identity".into());
        }
        let snapshot = &summaries[0];
        self.list_exact(snapshot, &tag, allowed)?;
        let manifest_index = manifest_path
            .to_str()
            .ok_or("invalid protected manifest path")?;
        let actual = self.run(
            &["dump".into(), snapshot.into(), manifest_index.into()],
            allowed,
        )?;
        if actual.receipt.code != 0
            || actual.stdout != manifest_bytes
            || tree::inventory(path, &mut *allowed)? != before
        {
            return Err("BACKUP_SOURCE_OR_MANIFEST_CHANGED".into());
        }
        let evidence = CaptureEvidence {
            snapshot_id: snapshot.clone(),
            manifest_sha256: sha(&manifest_bytes),
            manifest_snapshot_path: manifest_index.into(),
            manifest,
            tree_sha256: before,
            finished_unix_ms: now,
            adapter_receipt_sha256: digest(&(&result.receipt, &actual.receipt))?,
        };
        Ok(CaptureReceipt(evidence))
    }
    fn list_exact(
        &self,
        snapshot: &str,
        tag: &str,
        allowed: &mut impl FnMut() -> bool,
    ) -> Result<(), String> {
        if !hash_ok(snapshot) {
            return Err("backup requires full snapshot identity, not latest/prefix".into());
        }
        let result = self.run(
            &[
                "snapshots".into(),
                "--json".into(),
                "--tag".into(),
                tag.into(),
                snapshot.into(),
            ],
            allowed,
        )?;
        let rows: Vec<serde_json::Value> = serde_json::from_slice(&result.stdout)
            .map_err(|_| "invalid repository snapshot listing")?;
        if result.receipt.code != 0
            || rows.len() != 1
            || rows[0].get("id").and_then(|v| v.as_str()) != Some(snapshot)
            || !rows[0]
                .get("tags")
                .and_then(|v| v.as_array())
                .is_some_and(|tags| tags.iter().any(|v| v.as_str() == Some(tag)))
        {
            return Err(
                "captured point is not independently listed with exact job identity".into(),
            );
        }
        Ok(())
    }
    pub(crate) fn check(
        &self,
        plan: &CapturePlan,
        captured: &CaptureEvidence,
        now: u64,
        mut allowed: impl FnMut() -> bool,
    ) -> Result<CheckReceipt, String> {
        self.validate_plan(plan)?;
        self.list_exact(
            &captured.snapshot_id,
            &format!("royak-job:{}", plan.uid.as_str()),
            &mut allowed,
        )?;
        let result = self.run(&["check".into(), "--read-data".into()], &mut allowed)?;
        if result.receipt.code != 0 {
            return Err("BACKUP_REPOSITORY_CHECK_FAILED".into());
        }
        Ok(CheckReceipt(CheckEvidence {
            snapshot_id: captured.snapshot_id.clone(),
            checked_unix_ms: now,
            full_read_data: true,
            adapter_receipt_sha256: digest(&result.receipt)?,
        }))
    }
    /// Production restore deliberately fails closed until the actual driver
    /// proves a NEW empty owned destination, no writers, and exact mount identity.
    /// An existing empty directory or a deserialized RestorePlan cannot do that.
    pub fn restore_volume(&self) -> Result<(), String> {
        Err("verified new-volume restore adapter is not available; no data written".into())
    }
    #[cfg(test)]
    pub(super) fn restore_fixture(
        &self,
        plan: &CapturePlan,
        captured: &CaptureEvidence,
        mut allowed: impl FnMut() -> bool,
    ) -> Result<String, String> {
        self.validate_plan(plan)?;
        let manifest = self.run(
            &[
                "dump".into(),
                captured.snapshot_id.clone().into(),
                captured.manifest_snapshot_path.clone().into(),
            ],
            &mut allowed,
        )?;
        if manifest.receipt.code != 0
            || sha(&manifest.stdout) != captured.manifest_sha256
            || serde_json::from_slice::<RecoveryManifest>(&manifest.stdout)
                .map_err(|_| "invalid protected manifest")?
                != captured.manifest
        {
            return Err("BACKUP_MANIFEST_MISMATCH".into());
        }
        // New reservation every attempt. No existing destination is accepted,
        // no overwrite/delete flags, no source or live volume is selected.
        let target = self.work.mkdir_new(&format!(
            "verify-{}",
            crate::storage_identity::Uid::new().as_str()
        ))?;
        let subtree = format!(
            "{}:{}",
            captured.snapshot_id, captured.manifest.payload_snapshot_path
        );
        let result = self.run(
            &[
                "restore".into(),
                subtree.into(),
                "--verify".into(),
                "--overwrite".into(),
                "never".into(),
                "--target".into(),
                target.path().as_os_str().into(),
            ],
            &mut allowed,
        )?;
        if result.receipt.code != 0 {
            return Err("BACKUP_ISOLATED_RESTORE_FAILED".into());
        }
        let observed = tree::inventory(target.path(), &mut allowed)?;
        if observed != captured.tree_sha256 {
            return Err("BACKUP_RESTORE_TREE_MISMATCH".into());
        }
        Ok(observed)
    }
}

#[cfg(test)]
impl Restic {
    /// Qualification fixture ONLY. Never exported or compiled as an API that
    /// can capture mounted/live volume directories. Does not mint driver proof.
    pub(super) fn capture_fixture(
        &self,
        source: &Path,
        plan: &CapturePlan,
        now: u64,
        mut allowed: impl FnMut() -> bool,
    ) -> Result<CaptureReceipt, String> {
        let _owned = PrivateDir::open(source)?;
        self.capture_path(source, plan, now, &mut allowed)
    }
}
