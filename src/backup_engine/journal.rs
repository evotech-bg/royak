//! Private node journal. This is NOT the cluster's desired-state authority.
//! Before enabling distributed jobs, Registry must also join commit/Raft/schema
//! validation; a local worker journal only records intent/effects/recovery.
use super::Registry;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
const MAX_BYTES: u64 = 8 * 1024 * 1024;

fn fd(value: i32) -> Result<File, String> {
    if value < 0 {
        Err("private backup filesystem operation failed".into())
    } else {
        Ok(unsafe { File::from_raw_fd(value) })
    }
}
fn name(value: &str) -> Result<CString, String> {
    if value.is_empty() || value == "." || value == ".." || value.contains('/') {
        return Err("invalid private backup filename".into());
    }
    CString::new(value).map_err(|_| "invalid private backup filename".into())
}
fn regular(file: &File, max: u64) -> Result<(), String> {
    let m = file.metadata().map_err(|_| "cannot inspect backup file")?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > max
    {
        Err("backup file must be private, bounded, regular and singly linked".into())
    } else {
        Ok(())
    }
}
pub(crate) struct PrivateDir {
    file: File,
    path: PathBuf,
}
impl PrivateDir {
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        if !path.is_absolute() || path == Path::new("/") {
            return Err("backup directory must be absolute".into());
        }
        let mut current = fd(unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        })?;
        let parts: Vec<_> = path.components().collect();
        for (i, part) in parts.iter().enumerate() {
            if *part == Component::RootDir {
                continue;
            }
            let Component::Normal(part) = part else {
                return Err("non-canonical backup directory".into());
            };
            let part = name(part.to_str().ok_or("invalid backup path encoding")?)?;
            current = fd(unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    part.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?;
            let m = current
                .metadata()
                .map_err(|_| "cannot inspect backup directory")?;
            let owner = unsafe { libc::geteuid() };
            let sticky_root = m.uid() == 0 && m.mode() & 0o1000 != 0;
            if (m.uid() != 0 && m.uid() != owner)
                || (m.mode() & 0o022 != 0 && !sticky_root)
                || (i + 1 == parts.len() && (m.uid() != owner || m.mode() & 0o077 != 0))
            {
                return Err("backup path is not trusted/private".into());
            }
        }
        Ok(Self {
            file: current,
            path: path.into(),
        })
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    pub(crate) fn read(&self, filename: &str, max: u64) -> Result<Option<Vec<u8>>, String> {
        let n = name(filename)?;
        let value = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                n.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if value < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        let mut f = fd(value)?;
        regular(&f, max)?;
        let before = f.metadata().map_err(|_| "cannot inspect backup file")?;
        let mut bytes = Vec::new();
        (&mut f)
            .take(max + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read backup file")?;
        regular(&f, max)?;
        let after = f.metadata().map_err(|_| "cannot inspect backup file")?;
        if bytes.len() as u64 != before.len()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
        {
            return Err("backup file changed during read".into());
        }
        Ok(Some(bytes))
    }
    pub(crate) fn write(&self, filename: &str, bytes: &[u8]) -> Result<(), String> {
        if bytes.len() as u64 > MAX_BYTES {
            return Err("backup journal admission exhausted".into());
        }
        self.read(filename, MAX_BYTES)?;
        let dest = name(filename)?;
        let temp = name(&format!(
            ".txn-{}",
            crate::storage_identity::Uid::new().as_str()
        ))?;
        let mut file = fd(unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                temp.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        })?;
        let result = (|| {
            file.write_all(bytes)
                .map_err(|_| "cannot write backup journal")?;
            file.sync_all().map_err(|_| "cannot sync backup journal")?;
            if unsafe {
                libc::renameat(
                    self.file.as_raw_fd(),
                    temp.as_ptr(),
                    self.file.as_raw_fd(),
                    dest.as_ptr(),
                )
            } != 0
            {
                return Err("cannot publish backup journal".into());
            }
            self.file
                .sync_all()
                .map_err(|_| "cannot sync backup journal directory".into())
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(self.file.as_raw_fd(), temp.as_ptr(), 0);
            }
        }
        result
    }
    pub(crate) fn lock(&self) -> Result<File, String> {
        let file = fd(unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                c"worker.lock".as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_NONBLOCK
                    | libc::O_CLOEXEC,
                0o600,
            )
        })?;
        regular(&file, 64)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("backup worker already owns this journal".into());
        }
        Ok(file)
    }
    pub(crate) fn mkdir_new(&self, filename: &str) -> Result<Self, String> {
        let n = name(filename)?;
        if unsafe { libc::mkdirat(self.file.as_raw_fd(), n.as_ptr(), 0o700) } != 0 {
            return Err("fresh backup target already exists or cannot be reserved".into());
        }
        self.file
            .sync_all()
            .map_err(|_| "cannot persist new backup target")?;
        Self::open(&self.path.join(filename))
    }
}

pub struct Journal {
    dir: PrivateDir,
    _lock: File,
    state: Registry,
}
impl Journal {
    /// Caller creates the fresh 0700 directory. Never creates an arbitrary
    /// hierarchy, adopts an existing repository, or deletes old evidence.
    pub fn open(path: &Path) -> Result<Self, String> {
        let dir = PrivateDir::open(path)?;
        let lock = dir.lock()?;
        let mut state = match dir.read("jobs.json", MAX_BYTES)? {
            Some(data) => {
                let raw: serde_json::Value = serde_json::from_slice(&data)
                    .map_err(|_| "invalid durable backup registry")?;
                let old = raw.get("version").and_then(|v| v.as_u64()) == Some(1);
                if old {
                    Registry::require_legacy_precapture_absence(&raw)?;
                } else {
                    Registry::require_explicit_state_fields(&raw)?;
                }
                // Decode ORIGINAL bytes: do not collapse reservation-map or
                // known-struct duplicates through a Value conversion.
                let mut registry: Registry = serde_json::from_slice(&data)
                    .map_err(|_| "invalid durable backup registry")?;
                if old { registry.migrate_v1_precapture_empty()?; }
                registry
            },
            None => Registry::fresh(),
        };
        state.validate()?;
        state.recover_after_restart();
        dir.write(
            "jobs.json",
            &serde_json::to_vec(&state).map_err(|_| "cannot encode durable backup registry")?,
        )?;
        Ok(Self {
            dir,
            _lock: lock,
            state,
        })
    }
    pub fn state(&self) -> &Registry {
        &self.state
    }
    #[cfg(test)]
    pub(super) fn lock_fd_for_fixture(&self) -> std::os::fd::RawFd {
        self._lock.as_raw_fd()
    }
    /// Transaction closure executes against a copy. Failed persistence leaves
    /// old authority in memory; an ambiguous crash is reconciled on restart.
    pub fn transaction<T>(
        &mut self,
        update: impl FnOnce(&mut Registry) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut next = self.state.clone();
        let value = update(&mut next)?;
        self.state.validate_transition(&next)?;
        self.dir.write(
            "jobs.json",
            &serde_json::to_vec(&next).map_err(|_| "cannot encode durable backup registry")?,
        )?;
        self.state = next;
        Ok(value)
    }
}
