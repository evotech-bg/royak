//! Directory-FD anchored private files; never follow links or fall back to cache.
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
const LIMIT: u64 = 1024 * 1024;

fn name(s: &str) -> Result<CString, String> {
    if s.is_empty() || s == "." || s == ".." || s.contains('/') {
        return Err("invalid private filename".into());
    }
    CString::new(s).map_err(|_| "invalid private filename".into())
}
fn fd(value: i32) -> Result<File, String> {
    if value < 0 {
        Err(format!(
            "private file operation failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(unsafe { File::from_raw_fd(value) })
    }
}
fn regular(file: &File) -> Result<(), String> {
    let m = file.metadata().map_err(|e| e.to_string())?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.nlink() != 1
        || m.len() > LIMIT
    {
        return Err(
            "storage file must be bounded, singly linked, regular and owner-private".into(),
        );
    }
    Ok(())
}

/// Thread-local errno access for the two supported storage-driver platforms.
#[cfg(target_os = "linux")]
unsafe fn errno_slot() -> *mut libc::c_int {
    libc::__errno_location()
}
#[cfg(target_vendor = "apple")]
unsafe fn errno_slot() -> *mut libc::c_int {
    libc::__error()
}
#[cfg(not(any(target_os = "linux", target_vendor = "apple")))]
compile_error!("storage directory census requires an errno implementation for this target");

fn os_readdir(raw: *mut libc::DIR) -> *mut libc::dirent {
    unsafe { libc::readdir(raw) }
}

/// Owns the enumeration FD on every early-return/error path.
struct Enumeration {
    raw: *mut libc::DIR,
}
impl Enumeration {
    fn open(original: i32) -> Result<Self, String> {
        // Atomic CLOEXEC: no concurrent fork/exec descriptor leak window.
        let copied = fd(unsafe { libc::fcntl(original, libc::F_DUPFD_CLOEXEC, 3) })?;
        let raw = unsafe { libc::fdopendir(copied.as_raw_fd()) };
        if raw.is_null() {
            return Err("cannot open anchored directory census; outcome UNKNOWN".into());
        }
        std::mem::forget(copied); // ownership transferred to DIR
        let stream = Self { raw };
        unsafe {
            *errno_slot() = 0;
            libc::rewinddir(raw);
        }
        let error = unsafe { *errno_slot() };
        if error != 0 {
            return Err(format!(
                "directory census rewind failed (errno {error}); outcome UNKNOWN"
            ));
        }
        Ok(stream)
    }
    fn next(
        &mut self,
        read: &mut impl FnMut(*mut libc::DIR) -> *mut libc::dirent,
    ) -> Result<Option<Vec<u8>>, String> {
        // POSIX NULL means EOF only when errno stayed zero. Capture before
        // allocation/closedir or another library call can change this evidence.
        unsafe {
            *errno_slot() = 0;
        }
        let entry = read(self.raw);
        if entry.is_null() {
            let error = unsafe { *errno_slot() };
            if error != 0 {
                return Err(format!(
                    "directory census read failed (errno {error}); outcome UNKNOWN"
                ));
            }
            return Ok(None);
        }
        Ok(Some(
            unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }
                .to_bytes()
                .to_vec(),
        ))
    }
    fn finish(mut self) -> Result<(), String> {
        let raw = self.raw;
        self.raw = std::ptr::null_mut();
        if unsafe { libc::closedir(raw) } != 0 {
            return Err("directory census close failed; outcome UNKNOWN".into());
        }
        Ok(())
    }
}
impl Drop for Enumeration {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe {
                libc::closedir(self.raw);
            }
        }
    }
}

pub struct Dir {
    file: File,
}
impl Dir {
    pub(super) fn bounded_entries(&self, limit: usize) -> Result<Vec<String>, String> {
        self.entries_with_reader(limit, &mut os_readdir)
    }
    fn entries_with_reader(
        &self,
        limit: usize,
        read: &mut impl FnMut(*mut libc::DIR) -> *mut libc::dirent,
    ) -> Result<Vec<String>, String> {
        let mut stream = Enumeration::open(self.file.as_raw_fd())?;
        let result = (|| {
            let mut names = Vec::new();
            while let Some(bytes) = stream.next(read)? {
                if bytes == b"." || bytes == b".." {
                    continue;
                }
                if names.len() >= limit {
                    return Err(
                        "dispatcher journal retention budget exhausted; no evidence deleted".into(),
                    );
                }
                names.push(
                    String::from_utf8(bytes).map_err(|_| "invalid journal name; census UNKNOWN")?,
                );
            }
            Ok(names)
        })();
        let closed = stream.finish();
        match result {
            Err(e) => Err(e),
            Ok(value) => {
                closed?;
                Ok(value)
            }
        }
    }
    pub fn open(path: &Path, create: bool) -> Result<Self, String> {
        if !path.is_absolute() {
            return Err("private storage directory must be absolute".into());
        }
        let mut current = fd(unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        })?;
        let parts: Vec<_> = path.components().collect();
        for (i, part) in parts.iter().enumerate() {
            let Component::Normal(part) = part else {
                if *part == Component::RootDir {
                    continue;
                }
                return Err("non-canonical private storage path".into());
            };
            let raw = part.to_str().ok_or("invalid private path encoding")?;
            let n = name(raw)?;
            let mut opened = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    n.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if opened < 0
                && create
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound
            {
                if unsafe { libc::mkdirat(current.as_raw_fd(), n.as_ptr(), 0o700) } != 0 {
                    return Err("cannot create private directory".into());
                }
                current.sync_all().map_err(|e| e.to_string())?;
                opened = unsafe {
                    libc::openat(
                        current.as_raw_fd(),
                        n.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
            }
            current = fd(opened)?;
            let m = current.metadata().map_err(|e| e.to_string())?;
            let owner = unsafe { libc::geteuid() };
            let sticky = m.mode() & 0o1000 != 0 && m.uid() == 0;
            if (m.uid() != 0 && m.uid() != owner)
                || (m.mode() & 0o022 != 0 && !sticky)
                || (i + 1 == parts.len() && (m.uid() != owner || m.mode() & 0o077 != 0))
            {
                return Err("storage directory path is not privately owned/trusted".into());
            }
        }
        Ok(Self { file: current })
    }
    pub fn read(&self, filename: &str) -> Result<Option<Vec<u8>>, String> {
        let n = name(filename)?;
        let value = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                n.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if value < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        let mut file = fd(value)?;
        regular(&file)?;
        let before = file.metadata().map_err(|e| e.to_string())?;
        let mut data = Vec::new();
        (&mut file)
            .take(LIMIT + 1)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        regular(&file)?;
        let after = file.metadata().map_err(|e| e.to_string())?;
        if data.len() as u64 != before.len()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
        {
            return Err("private storage file changed while being read".into());
        }
        Ok(Some(data))
    }
    pub fn lock(&self) -> Result<File, String> {
        self.lock_named("lock")
    }
    pub fn lock_named(&self, filename: &str) -> Result<File, String> {
        let lock_name = name(filename)?;
        let file = fd(unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                lock_name.as_ptr(),
                libc::O_RDWR
                    | libc::O_CREAT
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0o600,
            )
        })?;
        regular(&file)?;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("storage pool already has an operation in progress".into());
        }
        Ok(file)
    }

    pub fn remove(&self, filename: &str) -> Result<(), String> {
        let n = name(filename)?;
        self.read(filename)?
            .ok_or("missing journal cannot be removed")?;
        if unsafe { libc::unlinkat(self.file.as_raw_fd(), n.as_ptr(), 0) } != 0 {
            return Err("cannot remove private journal".into());
        }
        self.file.sync_all().map_err(|e| e.to_string())
    }
    pub fn empty_except_lock(&self) -> Result<bool, String> {
        self.empty_with_reader(&mut os_readdir)
    }
    fn empty_with_reader(
        &self,
        read: &mut impl FnMut(*mut libc::DIR) -> *mut libc::dirent,
    ) -> Result<bool, String> {
        let mut stream = Enumeration::open(self.file.as_raw_fd())?;
        let result = (|| {
            while let Some(value) = stream.next(read)? {
                if value != b"." && value != b".." && value != b"lock" {
                    return Ok(false);
                }
            }
            Ok(true)
        })();
        // Close on success and errors; never turn an error into boolean empty.
        let closed = stream.finish();
        match result {
            Err(e) => Err(e),
            Ok(value) => {
                closed?;
                Ok(value)
            }
        }
    }
    pub fn write(&self, filename: &str, data: &[u8]) -> Result<(), String> {
        if data.len() as u64 > LIMIT {
            return Err("storage journal exceeds limit".into());
        }
        let dest = name(filename)?;
        // Reject existing symlinks, hardlinks and special files before replacing.
        self.read(filename)?;
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
            file.write_all(data).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            if unsafe {
                libc::renameat(
                    self.file.as_raw_fd(),
                    temp.as_ptr(),
                    self.file.as_raw_fd(),
                    dest.as_ptr(),
                )
            } != 0
            {
                return Err("cannot publish storage journal".into());
            }
            self.file.sync_all().map_err(|e| e.to_string())
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(self.file.as_raw_fd(), temp.as_ptr(), 0);
            }
        }
        result
    }
}
pub fn read_private(path: &Path) -> Result<Vec<u8>, String> {
    let parent = path.parent().ok_or("private file has no parent")?;
    let filename = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("invalid private filename")?;
    Dir::open(parent, false)?
        .read(filename)?
        .ok_or("private storage file does not exist".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn root() -> std::path::PathBuf {
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "royak-driver-fs-{}",
            crate::storage_identity::Uid::new().as_str()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn private_files_reject_links_permissions_and_special_inputs() {
        let path = root();
        let dir = Dir::open(&path, false).unwrap();
        let _lock = dir.lock().unwrap();
        assert!(dir.empty_except_lock().unwrap());
        assert!(dir.lock().is_err());
        dir.write("state.json", b"original").unwrap();
        assert!(!dir.empty_except_lock().unwrap());
        assert_eq!(dir.read("state.json").unwrap().unwrap(), b"original");
        assert_eq!(
            std::fs::metadata(path.join("state.json")).unwrap().mode() & 0o777,
            0o600
        );
        symlink(path.join("state.json"), path.join("link")).unwrap();
        assert!(dir.read("link").is_err());
        assert!(dir.write("link", b"overwrite").is_err());
        std::fs::hard_link(path.join("state.json"), path.join("hard")).unwrap();
        assert!(dir.read("state.json").is_err());
        assert!(dir.write("state.json", b"overwrite").is_err());
        std::fs::remove_file(path.join("hard")).unwrap();
        std::fs::set_permissions(
            path.join("state.json"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(dir.read("state.json").is_err());
        assert!(dir.read("../outside").is_err());
        assert!(dir.write("bad/path", b"x").is_err());
        assert!(dir
            .write("too-big", &vec![0u8; LIMIT as usize + 1])
            .is_err());
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn opened_directory_is_not_retargeted_by_a_path_swap() {
        let path = root();
        let opened = Dir::open(&path, false).unwrap();
        let moved = path.with_extension("moved");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::create_dir(&path).unwrap();
        opened.write("state.json", b"anchored").unwrap();
        assert_eq!(
            std::fs::read(moved.join("state.json")).unwrap(),
            b"anchored"
        );
        assert!(!path.join("state.json").exists());
        std::fs::remove_dir_all(path).unwrap();
        std::fs::remove_dir_all(moved).unwrap();
    }
    fn enumeration_fd_closed(raw: i32, expected: &std::fs::Metadata) {
        assert!(raw >= 0);
        let mut observed: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(raw, &mut observed) } == 0 {
            // Parallel tests may already reuse the number for another inode.
            assert!(
                observed.st_dev as u64 != expected.dev()
                    || observed.st_ino as u64 != expected.ino(),
                "enumeration descriptor still aliases the owned private directory"
            );
        } else {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF)
            );
        }
    }
    fn observe_enumeration_fd(raw: *mut libc::DIR, seen: &std::cell::Cell<i32>) {
        let fd = unsafe { libc::dirfd(raw) };
        assert!(fd >= 0);
        seen.set(fd);
        assert_ne!(
            unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0,
            "enumeration duplicate must be atomically close-on-exec"
        );
    }
    #[test]
    fn eio_before_existing_record_is_unknown_and_cannot_rebind_missing_pool() {
        let path = root();
        let dir = Dir::open(&path, false).unwrap();
        let lock = dir.lock().unwrap();
        dir.write("existing-record.json", b"retained-evidence")
            .unwrap();
        let seen = std::cell::Cell::new(-1);
        let mut reader = |raw: *mut libc::DIR| {
            observe_enumeration_fd(raw, &seen);
            let entry = os_readdir(raw);
            if !entry.is_null()
                && unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes()
                    == b"existing-record.json"
            {
                unsafe {
                    *errno_slot() = libc::EIO;
                }
                std::ptr::null_mut()
            } else {
                entry
            }
        };
        let result: Result<(), String> = (|| {
            // The same fail-closed condition used before publishing pool.json.
            if dir.empty_with_reader(&mut reader)? {
                dir.write("pool.json", b"must-not-mint")?;
            }
            Ok(())
        })();
        let error = result.unwrap_err();
        assert!(error.contains("UNKNOWN"));
        assert!(error.contains(&format!("errno {}", libc::EIO)));
        enumeration_fd_closed(seen.get(), &dir.file.metadata().unwrap());
        assert!(dir.read("pool.json").unwrap().is_none());
        assert_eq!(
            dir.read("existing-record.json").unwrap().unwrap(),
            b"retained-evidence"
        );
        drop(lock);
        drop(dir);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn first_read_eio_never_becomes_empty_even_for_an_empty_directory() {
        let path = root();
        let dir = Dir::open(&path, false).unwrap();
        let seen = std::cell::Cell::new(-1);
        let mut reader = |raw: *mut libc::DIR| {
            observe_enumeration_fd(raw, &seen);
            unsafe {
                *errno_slot() = libc::EIO;
            }
            std::ptr::null_mut()
        };
        assert!(dir
            .empty_with_reader(&mut reader)
            .unwrap_err()
            .contains("UNKNOWN"));
        enumeration_fd_closed(seen.get(), &dir.file.metadata().unwrap());
        drop(dir);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn errno_is_reset_before_each_read_and_real_eof_is_not_a_stale_error() {
        let path = root();
        let dir = Dir::open(&path, false).unwrap();
        let lock = dir.lock().unwrap();
        let seen = std::cell::Cell::new(-1);
        let mut reader = |raw: *mut libc::DIR| {
            observe_enumeration_fd(raw, &seen);
            let entry = os_readdir(raw);
            // POSIX does not require errno to be meaningful after non-NULL.
            if !entry.is_null() {
                unsafe {
                    *errno_slot() = libc::EIO;
                }
            }
            entry
        };
        assert!(dir.empty_with_reader(&mut reader).unwrap());
        enumeration_fd_closed(seen.get(), &dir.file.metadata().unwrap());
        drop(lock);
        drop(dir);
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn partial_dispatch_census_eio_cannot_return_a_partial_success_count() {
        let path = root();
        let dir = Dir::open(&path, false).unwrap();
        for name in ["attempt-one.json", "attempt-two.json", "attempt-three.json"] {
            dir.write(name, b"owned-evidence").unwrap();
        }
        let seen = std::cell::Cell::new(-1);
        let visible = std::cell::Cell::new(0usize);
        let mut reader = |raw: *mut libc::DIR| {
            observe_enumeration_fd(raw, &seen);
            let entry = os_readdir(raw);
            if !entry.is_null() {
                let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
                if name != b"." && name != b".." {
                    visible.set(visible.get() + 1);
                    if visible.get() == 2 {
                        unsafe {
                            *errno_slot() = libc::EIO;
                        }
                        return std::ptr::null_mut();
                    }
                }
            }
            entry
        };
        let result = dir.entries_with_reader(128, &mut reader);
        assert_eq!(
            visible.get(),
            2,
            "one real record must precede the injected failure"
        );
        assert!(
            result.unwrap_err().contains("UNKNOWN"),
            "partial inventory is not an admission count"
        );
        enumeration_fd_closed(seen.get(), &dir.file.metadata().unwrap());
        assert_eq!(dir.bounded_entries(128).unwrap().len(), 3);
        drop(dir);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn bounded_census_limit_failure_closes_fd_and_preserves_evidence() {
        let path = root();
        let dir = Dir::open(&path, false).unwrap();
        dir.write("attempt-one.json", b"kept").unwrap();
        let seen = std::cell::Cell::new(-1);
        let mut reader = |raw: *mut libc::DIR| {
            observe_enumeration_fd(raw, &seen);
            os_readdir(raw)
        };
        assert!(dir.entries_with_reader(0, &mut reader).is_err());
        enumeration_fd_closed(seen.get(), &dir.file.metadata().unwrap());
        assert_eq!(dir.read("attempt-one.json").unwrap().unwrap(), b"kept");
        drop(dir);
        std::fs::remove_dir_all(path).unwrap();
    }
}
