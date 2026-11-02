//! Required Linux kernel population barrier. No ordinary-directory fallback.
//! PGIDs and inherited FDs alone cannot prove FD-closing descendants are gone.
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Explicit operator admission, never inferred from a passing tiny fixture.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ResourceBudget {
    pub pids_max: u64,
    pub memory_max_bytes: u64,
    pub cpu_quota_us: u64,
    pub cpu_period_us: u64,
}
impl ResourceBudget {
    pub(super) fn validate(&self) -> Result<(), String> {
        if self.pids_max < 2
            || self.pids_max > 4096
            || self.memory_max_bytes < 64 * 1024 * 1024
            || self.memory_max_bytes > 16 * 1024 * 1024 * 1024
            || !(1000..=1_000_000).contains(&self.cpu_period_us)
            || self.cpu_quota_us < 1000
            || self.cpu_quota_us > self.cpu_period_us.saturating_mul(8)
        {
            return Err("explicit finite storage helper PID/memory/CPU budgets required".into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct ResourceSnapshot {
    pub budget: ResourceBudget,
    pub pids_current: u64,
    pub memory_current_bytes: u64,
    pub cpu_usage_us: u64,
    pub cpu_user_us: u64,
    pub cpu_system_us: u64,
}
fn number(raw: &str) -> Result<u64, String> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Err("unbounded/missing resource number".into());
    }
    raw.parse()
        .map_err(|_| "overflowing resource number".into())
}
fn cpu_accounting(raw: &str) -> Result<(u64, u64, u64), String> {
    let mut seen = std::collections::BTreeMap::new();
    for line in raw.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() != 2 || seen.insert(parts[0], number(parts[1])?).is_some() {
            return Err("malformed/duplicate CPU accounting".into());
        }
    }
    let get = |key: &str| {
        seen.get(key)
            .copied()
            .ok_or_else(|| format!("CPU accounting {key} unavailable"))
    };
    Ok((get("usage_usec")?, get("user_usec")?, get("system_usec")?))
}

pub(super) struct JobCgroup {
    directory: File,
    parent: Option<(File, std::ffi::CString)>,
    created: bool,
}

/// Literal bounded kernel membership observations, not an admission/grant.
pub(super) struct EmptyTaskCensus {
    pub processes: Vec<u32>,
    pub threads: Vec<u32>,
}
fn task_ids(raw: &str) -> Result<Vec<u32>, String> {
    if raw.len() > 4096 { return Err("oversized cgroup task census".into()); }
    let mut seen = std::collections::BTreeSet::new();
    let mut ids = Vec::new();
    for word in raw.split_whitespace() {
        if word.is_empty() || !word.bytes().all(|b| b.is_ascii_digit()) {
            return Err("malformed cgroup task census".into());
        }
        let id: u32 = word.parse().map_err(|_| "overflowing cgroup task id")?;
        if id == 0 || !seen.insert(id) { return Err("zero/duplicate cgroup task id".into()); }
        ids.push(id);
    }
    Ok(ids)
}

pub(super) fn population(raw: &str) -> Result<bool, String> {
    if raw.len() > 4096 {
        return Err("oversized cgroup events".into());
    }
    let mut found = None;
    for line in raw.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 2 {
            return Err("malformed cgroup events".into());
        }
        if fields[0] == "populated" {
            let value = match fields[1] {
                "0" => false,
                "1" => true,
                _ => return Err("invalid cgroup population".into()),
            };
            if found.replace(value).is_some() {
                return Err("duplicate cgroup population".into());
            }
        }
    }
    found.ok_or_else(|| "missing cgroup population is UNKNOWN, not empty".into())
}

/// Exact fixed controls only. The runtime prerequisite needs one additional
/// READ, never a new subtree/controller write capability. All old access pairs
/// are preserved byte-for-byte in the list below.
fn control_access_allowed(name:&str,write:bool)->bool {
    if name=="cgroup.subtree_control" || name=="cgroup.threads" {return !write;}
    ["cgroup.procs","cgroup.events","cgroup.kill","cgroup.type","pids.max",
        "memory.max","cpu.max","cpu.stat","pids.current","memory.current"].contains(&name)
}

impl JobCgroup {
    /// Distinct profile7 readonly inheritance. A duplicate of the SAME held
    /// original node leaf, never open/create/adopt by name or env number.
    pub(super) fn retained_directory_for_owned_inventory(&self)->Result<File,String>{
        #[cfg(not(target_os="linux"))]{Err("owned inventory original cgroup requires Linux".into())}
        #[cfg(target_os="linux")]{verify_directory(&self.directory)?;
            self.directory.try_clone().map_err(|_|"actual profile7 original cgroup duplicate unavailable".into())}
    }
    pub(super) fn from_verified_owned_inventory_inherited(
        verified:super::dispatcher::attachment::inventory::VerifiedInheritedInventoryCgroup,
    )->Result<Self,String>{
        #[cfg(not(target_os="linux"))]{let _=verified;Err("owned inventory original cgroup requires Linux".into())}
        #[cfg(target_os="linux")]{
            let(file,identity,budget)=verified.into_kernel_parts();verify_directory(&file)?;
            let value=Self{directory:file,parent:None,created:false};
            if value.identity()?!=identity||value.read("cgroup.type")?.trim()!="domain"||!value.contains(std::process::id())?{
                return Err("actual profile7 original cgroup incarnation/type/current membership differs".into());}
            value.resource_snapshot(&budget)?;Ok(value)
        }
    }
    /// Duplicate of an ACTUAL retained original node directory, never a path
    /// selector, cgroup creation or new worker/resource permission.
    #[cfg(target_os="linux")]
    pub(super) fn retained_directory_for_terminal(&self)->Result<File,String>{
        verify_directory(&self.directory)?;
        self.directory.try_clone().map_err(|_|"cannot retain original terminal cgroup directory".into())
    }
    /// Only the verified private v6 worker producer can construct this opaque
    /// input. It already checked original lease/capsule/socket/boot/name; this
    /// layer independently verifies actual kernel identity and membership.
    #[cfg(target_os="linux")]
    pub(super) fn from_verified_terminal_inherited(
        verified:super::dispatcher::attachment::terminal::VerifiedInheritedTerminalCgroup,
    )->Result<Self,String>{
        let(file,identity,budget)=verified.into_kernel_parts();
        verify_directory(&file)?;
        let value=Self{directory:file,parent:None,created:false};
        if value.identity()?!=identity || value.read("cgroup.type")?.trim()!="domain"
            || !value.contains(std::process::id())?{
            return Err("inherited original terminal cgroup incarnation/type/membership differs".into());
        }
        value.resource_snapshot(&budget)?;Ok(value)
    }
    #[cfg(not(target_os="linux"))]
    pub(super) fn retained_directory_for_terminal(&self)->Result<File,String>{Err("terminal inherited node cgroup requires Linux".into())}
    #[cfg(not(target_os="linux"))]
    pub(super) fn from_verified_terminal_inherited(_verified:super::dispatcher::attachment::terminal::VerifiedInheritedTerminalCgroup)->Result<Self,String>{
        Err("terminal inherited node cgroup requires Linux".into())
    }
    #[cfg(target_os = "linux")]
    pub(super) fn command_scope(&self, nonce: &str) -> Result<Self, String> {
        if nonce.len() != 32
            || !nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("invalid command cgroup identity".into());
        }
        let name = std::ffi::CString::new(format!("cmd-{nonce}")).unwrap();
        if unsafe { libc::mkdirat(self.directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err("cannot allocate fresh owned command cgroup".into());
        }
        let raw = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err("cannot open new command cgroup".into());
        }
        let value = Self {
            directory: unsafe { File::from_raw_fd(raw) },
            parent: Some((
                self.directory
                    .try_clone()
                    .map_err(|_| "cannot retain command parent")?,
                name,
            )),
            created: true,
        };
        verify_directory(&value.directory)?;
        value.open_control("cgroup.kill", true)?;
        if value.populated()? {
            return Err("fresh command cgroup unexpectedly populated".into());
        }
        Ok(value)
    }
    #[cfg(not(target_os = "linux"))]
    pub(super) fn command_scope(&self, _nonce: &str) -> Result<Self, String> {
        Err("Linux command cgroup required".into())
    }
    #[cfg(target_os = "linux")]
    pub(super) fn open(approved_root: &Path, node_uid: &str) -> Result<Self, String> {
        use std::os::unix::fs::OpenOptionsExt;
        if unsafe { libc::geteuid() } != 0
            || node_uid.len() != 32
            || !node_uid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("storage cgroup requires root and an exact server-owned node UID".into());
        }
        // Check canonical path + final opened cgroup inode. The root operator
        // must provide trusted ancestors: this is not an ancestor-permission
        // walker. The private boot/dev/inode binding prevents later adoption.
        // Never delegate the entire host cgroup root.
        if !approved_root.is_absolute()
            || std::fs::canonicalize(approved_root).map_err(|_| "approved cgroup root absent")?
                != approved_root
            || approved_root == Path::new("/sys/fs/cgroup")
        {
            return Err("explicit canonical delegated storage cgroup subtree required".into());
        }
        let root = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(approved_root)
            .map_err(|_| "cannot open approved storage cgroup root")?;
        verify_directory(&root)?;
        let name = std::ffi::CString::new(format!("rkjob-{node_uid}")).unwrap();
        let created = unsafe { libc::mkdirat(root.as_raw_fd(), name.as_ptr(), 0o700) } == 0;
        if !created && std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err("storage cgroup delegation unavailable; refusing helper launch".into());
        }
        let fd = unsafe {
            libc::openat(
                root.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("cannot open exact node job cgroup".into());
        }
        let value = Self {
            directory: unsafe { File::from_raw_fd(fd) },
            parent: None,
            created,
        };
        verify_directory(&value.directory)?;
        if value.read("cgroup.type")?.trim() != "domain" {
            return Err("storage helper requires a domain cgroup".into());
        }
        // Require atomic recursive kernel kill support before any helper starts.
        value.open_control("cgroup.kill", true)?;
        Ok(value)
    }
    #[cfg(not(target_os = "linux"))]
    pub(super) fn open(_approved_root: &Path, _node_uid: &str) -> Result<Self, String> {
        Err("production storage dispatch requires Linux cgroup v2; no native fallback".into())
    }
    pub(super) fn try_clone(&self) -> Result<Self, String> {
        Ok(Self {
            directory: self
                .directory
                .try_clone()
                .map_err(|_| "cannot retain owned cgroup handle")?,
            parent: None,
            created: false,
        })
    }
    pub(super) fn identity(&self) -> Result<(u64, u64), String> {
        let m = self
            .directory
            .metadata()
            .map_err(|_| "cannot bind kernel cgroup identity")?;
        Ok((m.dev(), m.ino()))
    }
    pub(super) fn newly_created(&self) -> bool {
        self.created
    }
    pub(super) fn enforce_budget(
        &self,
        budget: &ResourceBudget,
    ) -> Result<ResourceSnapshot, String> {
        budget.validate()?;
        if self.populated()? {
            return Err("never rewrite budgets of a populated node job".into());
        }
        for (name, value) in [
            ("pids.max", budget.pids_max.to_string()),
            ("memory.max", budget.memory_max_bytes.to_string()),
            (
                "cpu.max",
                format!("{} {}", budget.cpu_quota_us, budget.cpu_period_us),
            ),
        ] {
            self.open_control(name, true)?
                .write_all(format!("{value}\n").as_bytes())
                .map_err(|_| "delegated resource controller write failed")?;
        }
        self.resource_snapshot(budget)
    }
    pub(super) fn resource_snapshot(
        &self,
        budget: &ResourceBudget,
    ) -> Result<ResourceSnapshot, String> {
        if number(self.read("pids.max")?.trim())? != budget.pids_max
            || number(self.read("memory.max")?.trim())? != budget.memory_max_bytes
            || self.read("cpu.max")?.trim()
                != format!("{} {}", budget.cpu_quota_us, budget.cpu_period_us)
        {
            return Err("kernel resource limits differ from explicit operator admission".into());
        }
        let (usage, user, system) = cpu_accounting(&self.read("cpu.stat")?)?;
        Ok(ResourceSnapshot {
            budget: budget.clone(),
            pids_current: number(self.read("pids.current")?.trim())?,
            memory_current_bytes: number(self.read("memory.current")?.trim())?,
            cpu_usage_us: usage,
            cpu_user_us: user,
            cpu_system_us: system,
        })
    }
    #[cfg(target_os = "linux")]
    pub(super) fn prune_empty_command_scopes(&self) -> Result<(), String> {
        if self.populated()? {
            return Err("owned cgroup still populated; never prune/reuse".into());
        }
        let mut count = 0;
        for entry in std::fs::read_dir(format!("/proc/self/fd/{}", self.directory.as_raw_fd()))
            .map_err(|_| "cannot census owned command cgroups")?
        {
            let entry = entry.map_err(|_| "incomplete command cgroup census")?;
            if !entry
                .file_type()
                .map_err(|_| "unknown command cgroup entry")?
                .is_dir()
            {
                continue;
            }
            count += 1;
            if count > 4096 {
                return Err("owned command cgroup cleanup budget exceeded".into());
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "invalid cgroup name")?;
            let uid = name
                .strip_prefix("cmd-")
                .filter(|s| {
                    s.len() == 32
                        && s.bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                })
                .ok_or("foreign child cgroup; no implicit cleanup")?;
            let _ = uid;
            let name = std::ffi::CString::new(name).unwrap();
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err("command cgroup changed during cleanup".into());
            }
            let child = Self {
                directory: unsafe { File::from_raw_fd(fd) },
                parent: None,
                created: false,
            };
            verify_directory(&child.directory)?;
            if child.populated()? {
                return Err("command descendants remain; no cleanup/reuse".into());
            }
            if unsafe {
                libc::unlinkat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            } != 0
            {
                return Err("owned empty command cgroup removal failed; no reuse".into());
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    pub(super) fn prune_empty_command_scopes(&self) -> Result<(), String> {
        Err("Linux cgroup cleanup required".into())
    }
    fn open_control(&self, name: &str, write: bool) -> Result<File, String> {
        if !control_access_allowed(name,write) {
            return Err("invalid cgroup control file".into());
        }
        let name = std::ffi::CString::new(name).unwrap();
        let fd = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                name.as_ptr(),
                (if write {
                    libc::O_WRONLY
                } else {
                    libc::O_RDONLY
                }) | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err("owned cgroup control is unavailable; outcome UNKNOWN".into());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        verify_filesystem(&file)?;
        let a = self
            .directory
            .metadata()
            .map_err(|_| "cannot stat cgroup handle")?;
        let b = file.metadata().map_err(|_| "cannot stat cgroup control")?;
        if a.dev() != b.dev() || b.uid() != 0 || !b.is_file() || b.mode() & 0o022 != 0 {
            return Err("cgroup control inode/ownership changed".into());
        }
        Ok(file)
    }
    fn read(&self, name: &str) -> Result<String, String> {
        let mut text = String::new();
        self.open_control(name, false)?
            .take(4097)
            .read_to_string(&mut text)
            .map_err(|_| "cannot observe owned cgroup")?;
        if text.len() > 4096 {
            return Err("cgroup observation exceeded bound".into());
        }
        Ok(text)
    }
    pub(super) fn populated(&self) -> Result<bool, String> {
        population(&self.read("cgroup.events")?)
    }
    pub(super) fn task_census_empty(&self) -> Result<EmptyTaskCensus, String> {
        let before = self.identity()?;
        let processes = task_ids(&self.read("cgroup.procs")?)?;
        let threads = task_ids(&self.read("cgroup.threads")?)?;
        if self.identity()? != before || !processes.is_empty() || !threads.is_empty() {
            return Err("owned cgroup task census is changed/nonempty; UNKNOWN".into());
        }
        Ok(EmptyTaskCensus { processes, threads })
    }
    pub(super) fn procs_for_child(&self) -> Result<File, String> {
        self.open_control("cgroup.procs", true)
    }
    pub(super) fn kill_exact(&self) -> Result<(), String> {
        self.open_control("cgroup.kill", true)?
            .write_all(b"1\n")
            .map_err(|_| "cannot cancel exact owned cgroup; outcome UNKNOWN".into())
    }
    pub(super) fn contains(&self, pid: u32) -> Result<bool, String> {
        let text = self.read("cgroup.procs")?;
        let ids = text
            .split_whitespace()
            .map(|s| s.parse::<u32>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "invalid cgroup process census")?;
        Ok(ids.contains(&pid))
    }
}

impl Drop for JobCgroup {
    fn drop(&mut self) {
        let Some((parent, name)) = &self.parent else {
            return;
        };
        if !matches!(self.populated(), Ok(false)) {
            return;
        }
        let mut observed: libc::stat = unsafe { std::mem::zeroed() };
        let Ok(expected) = self.directory.metadata() else {
            return;
        };
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                &mut observed,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
            && observed.st_ino as u64 == expected.ino()
            && observed.st_dev as u64 == expected.dev()
        {
            unsafe {
                libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn verify_filesystem(file: &File) -> Result<(), String> {
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut fs) } != 0 || fs.f_type as u64 != 0x63677270 {
        return Err(
            "not actual kernel cgroup v2; ordinary files are never population proof".into(),
        );
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn verify_filesystem(_file: &File) -> Result<(), String> {
    Err("Linux cgroup v2 required".into())
}
#[cfg(target_os = "linux")]
fn verify_directory(file: &File) -> Result<(), String> {
    verify_filesystem(file)?;
    let m = file
        .metadata()
        .map_err(|_| "cannot stat delegated cgroup directory")?;
    if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
        return Err("cgroup delegation ownership is not trusted".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn released_slot_task_census_rejects_malformed_duplicate_zero_and_oversized_ids() {
        assert_eq!(task_ids("  \n\t").unwrap(), Vec::<u32>::new());
        assert_eq!(task_ids("12\n34\n").unwrap(), vec![12,34]);
        for bad in ["0", "-1", "true", "12 12", "4294967296", "1x", "+2"] {
            assert!(task_ids(bad).is_err(), "{bad}");
        }
        assert!(task_ids(&"1".repeat(4097)).is_err());
    }
    #[test]
    fn released_slot_threads_is_read_only_not_a_write_or_path_capability() {
        assert!(control_access_allowed("cgroup.threads", false));
        assert!(!control_access_allowed("cgroup.threads", true));
        for bad in ["../cgroup.threads", "cgroup.threads/x", "/cgroup.threads", "cgroup.threads\0"] {
            assert!(!control_access_allowed(bad,false));
            assert!(!control_access_allowed(bad,true));
        }
    }
    #[test]
    fn subtree_control_is_exact_read_only_and_never_a_new_write_or_path_capability() {
        assert!(control_access_allowed("cgroup.subtree_control",false));
        assert!(!control_access_allowed("cgroup.subtree_control",true));
        for name in ["cgroup.subtree_control/../cgroup.procs","../cgroup.subtree_control",
            "/sys/fs/cgroup/cgroup.subtree_control","cgroup.controllers","cgroup.freeze","cgroup.subtree_control\0"] {
            assert!(!control_access_allowed(name,false));assert!(!control_access_allowed(name,true));
        }
    }
    #[test]
    fn all_preexisting_control_access_pairs_remain_unchanged() {
        for name in ["cgroup.procs","cgroup.events","cgroup.kill","cgroup.type","pids.max",
            "memory.max","cpu.max","cpu.stat","pids.current","memory.current"] {
            assert!(control_access_allowed(name,false));assert!(control_access_allowed(name,true));
        }
        assert!(!control_access_allowed("",false));assert!(!control_access_allowed("unknown",true));
    }
    #[test]
    #[cfg(target_os="linux")]
    fn actual_kernel_subtree_control_read_pins_cgroup_fd_and_rejects_write_before_open() {
        use std::os::unix::fs::OpenOptionsExt;
        let configured=std::env::var_os("ROYAK_TEST_READONLY_DELEGATED_CGROUP_ROOT");
        let path=configured.as_ref().map(|value|std::path::PathBuf::from(value.as_os_str())).unwrap_or_else(||"/sys/fs/cgroup".into());
        assert!(path.is_absolute());assert_eq!(std::fs::canonicalize(&path).unwrap(),path);
        let directory=std::fs::OpenOptions::new().read(true)
            .custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(&path).unwrap();
        verify_directory(&directory).unwrap();
        let view=JobCgroup {directory,parent:None,created:false};let before=view.identity().unwrap();
        let observed=view.read("cgroup.subtree_control").unwrap();
        let file=view.open_control("cgroup.subtree_control",false).unwrap();verify_filesystem(&file).unwrap();
        let mut independently=String::new();file.take(4097).read_to_string(&mut independently).unwrap();
        assert!(independently.len()<=4096);assert_eq!(observed,independently);
        assert!(view.open_control("cgroup.subtree_control",true).is_err());
        assert_eq!(view.identity().unwrap(),before);
        if configured.is_some() {
            assert_ne!(path,Path::new("/sys/fs/cgroup"));
            assert!(runtime_slot_available(&path,&crate::storage_identity::Uid::new()).unwrap());
            assert_eq!(view.read("cgroup.subtree_control").unwrap(),observed);
        }
        // Actual kernel observation only: no node leaf is created, no write
        // FD/controller update/child/mount or work admission is produced.
    }
    #[test]
    fn population_parser_never_turns_unknown_into_empty() {
        assert_eq!(population("populated 0\nfrozen 0\n").unwrap(), false);
        assert_eq!(population("populated 1\nfrozen 0\n").unwrap(), true);
        for value in [
            "",
            "frozen 0\n",
            "populated 2\n",
            "populated 0\npopulated 1\n",
            "populated\n",
        ] {
            assert!(population(value).is_err());
        }
    }
    #[test]
    fn native_ordinary_directories_cannot_be_faked_cgroup_success() {
        assert!(JobCgroup::open(&std::env::temp_dir(), &"a".repeat(32)).is_err());
    }
    #[test]
    fn explicit_budget_and_cpu_accounting_reject_unknown_unbounded_or_duplicate_values() {
        // Parser contract only; not chosen/admitted deployment caps.
        let sample = ResourceBudget {
            pids_max: 64,
            memory_max_bytes: 256 * 1024 * 1024,
            cpu_quota_us: 100_000,
            cpu_period_us: 100_000,
        };
        sample.validate().unwrap();
        for raw in ["max", "", "-1", "1.0", "18446744073709551616"] {
            assert!(number(raw).is_err());
        }
        assert_eq!(
            cpu_accounting("usage_usec 12\nuser_usec 8\nsystem_usec 4\n").unwrap(),
            (12, 8, 4)
        );
        assert!(cpu_accounting("usage_usec 12\nuser_usec 8\n").is_err());
        assert!(
            cpu_accounting("usage_usec 12\nusage_usec 12\nuser_usec 8\nsystem_usec 4\n").is_err()
        );
        for case in 0..4 {
            let mut bad = sample.clone();
            match case {
                0 => bad.pids_max = 0,
                1 => bad.memory_max_bytes = 0,
                2 => bad.cpu_quota_us = 0,
                _ => bad.cpu_period_us = 0,
            };
            assert!(bad.validate().is_err());
        }
    }
}

    
/// Read-only runtime prerequisite. Does not create a node leaf, change
/// controllers/budgets or adopt an existing cgroup. Existing leaves are busy,
/// even when apparently empty; dispatcher ownership cannot come from a scan.
pub(super) fn runtime_slot_available(approved_root:&Path,node:&crate::storage_identity::Uid)->Result<bool,String> {
    #[cfg(not(target_os="linux"))]
    {let _=(approved_root,node);Err("normal cold requires real Linux cgroup-v2".into())}
    #[cfg(target_os="linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if std::fs::canonicalize(approved_root).map_err(|_|"runtime cgroup root absent")?!=approved_root ||
            approved_root==Path::new("/sys/fs/cgroup") {
            return Err("runtime cgroup root is not exact delegated subtree".into());
        }
        let root=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)
            .open(approved_root).map_err(|_|"runtime cgroup root cannot be inspected")?;
        verify_directory(&root)?;
        let view=JobCgroup {directory:root,parent:None,created:false};
        if view.read("cgroup.type")?.trim()!="domain" {return Err("runtime delegated root is not a domain".into());}
        let controllers=view.read("cgroup.subtree_control")?;
        let available=controllers.split_whitespace().collect::<std::collections::BTreeSet<_>>();
        if !["pids","memory","cpu"].iter().all(|name|available.contains(name)) {
            return Err("operator must predelegate PID/memory/CPU controllers".into());
        }
        let name=std::ffi::CString::new(format!("rkjob-{}",node.as_str())).map_err(|_|"invalid runtime node UID")?;
        let mut st=std::mem::MaybeUninit::<libc::stat>::uninit();
        let result=unsafe {libc::fstatat(view.directory.as_raw_fd(),name.as_ptr(),st.as_mut_ptr(),libc::AT_SYMLINK_NOFOLLOW)};
        if result==0 {Ok(false)} else if std::io::Error::last_os_error().kind()==std::io::ErrorKind::NotFound {Ok(true)}
        else {Err("runtime node cgroup slot UNKNOWN".into())}
    }
}


