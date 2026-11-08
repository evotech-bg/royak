//! Bounded, no-follow inventory of an already observed immutable source or an
//! isolated freshly restored tree. A digest is validation, NOT source authority.
use super::{digest, sha};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
const MAX_FILES: usize = 100_000;
const MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_DEPTH: u32 = 64;

#[derive(Serialize)]
struct Entry {
    kind: &'static str,
    mode: u32,
    uid: u32,
    gid: u32,
    bytes: u64,
    content: String,
}
fn fd(value: i32) -> Result<File, String> {
    if value < 0 {
        Err("cannot inspect backup tree without following links".into())
    } else {
        Ok(unsafe { File::from_raw_fd(value) })
    }
}
pub(super) fn inventory(
    path: &Path,
    mut still_allowed: impl FnMut() -> bool,
) -> Result<String, String> {
    let path =
        CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| "invalid source path")?;
    let root = fd(unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    let device = root
        .metadata()
        .map_err(|_| "cannot inspect backup source")?
        .dev();
    let mut rows = BTreeMap::new();
    let mut bytes = 0;
    walk(
        &root,
        "",
        device,
        0,
        &mut rows,
        &mut bytes,
        &mut still_allowed,
    )?;
    digest(&rows)
}
fn walk(
    dir: &File,
    prefix: &str,
    device: u64,
    depth: u32,
    rows: &mut BTreeMap<String, Entry>,
    total: &mut u64,
    allowed: &mut impl FnMut() -> bool,
) -> Result<(), String> {
    if depth > MAX_DEPTH || !allowed() {
        return Err("backup tree limit/cancellation reached".into());
    }
    let dup = unsafe { libc::dup(dir.as_raw_fd()) };
    if dup < 0 {
        return Err("cannot enumerate backup tree".into());
    }
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        unsafe {
            libc::close(dup);
        }
        return Err("cannot enumerate backup tree".into());
    }
    // RAII closes even when a malformed/untrusted entry fails validation.
    struct Close(*mut libc::DIR);
    impl Drop for Close {
        fn drop(&mut self) {
            unsafe {
                libc::closedir(self.0);
            }
        }
    }
    let _close = Close(stream);
    unsafe {
        libc::rewinddir(stream);
    }
    let mut names = Vec::new();
    loop {
        let item = unsafe { libc::readdir(stream) };
        if item.is_null() {
            break;
        }
        let name = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if rows.len() + names.len() >= MAX_FILES {
            return Err("backup file-count limit reached".into());
        }
        names.push(
            std::str::from_utf8(name)
                .map_err(|_| "non-UTF8 backup filename is not supported by this adapter")?
                .to_owned(),
        );
    }
    names.sort();
    for name in names {
        if !allowed() {
            return Err("backup access revoked or cancelled".into());
        }
        let c = CString::new(name.as_bytes()).map_err(|_| "invalid backup filename")?;
        let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                dir.as_raw_fd(),
                c.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
        {
            return Err("backup tree changed during enumeration".into());
        }
        let st = unsafe { st.assume_init() };
        if st.st_dev as u64 != device {
            return Err("nested filesystem is outside capture authority".into());
        }
        let key = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let kind = st.st_mode & libc::S_IFMT;
        let mut entry = Entry {
            kind: "",
            mode: st.st_mode as u32 & 0o7777,
            uid: st.st_uid,
            gid: st.st_gid,
            bytes: 0,
            content: String::new(),
        };
        match kind {
            libc::S_IFDIR => {
                let child = fd(unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        c.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                })?;
                let meta = child
                    .metadata()
                    .map_err(|_| "cannot inspect backup directory")?;
                if meta.ino() != st.st_ino as u64 || meta.dev() != device {
                    return Err("backup directory identity changed".into());
                }
                entry.kind = "directory";
                rows.insert(key.clone(), entry);
                walk(&child, &key, device, depth + 1, rows, total, allowed)?;
            }
            libc::S_IFREG => {
                let mut file = fd(unsafe {
                    libc::openat(
                        dir.as_raw_fd(),
                        c.as_ptr(),
                        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                    )
                })?;
                let before = file.metadata().map_err(|_| "cannot inspect backup data")?;
                if !before.is_file()
                    || before.ino() != st.st_ino as u64
                    || before.dev() != device
                    || before.len() > MAX_BYTES.saturating_sub(*total)
                {
                    return Err("backup source identity/byte limit changed".into());
                }
                let mut hash = Sha256::new();
                let mut read = 0u64;
                let mut buffer = [0u8; 64 * 1024];
                loop {
                    if !allowed() {
                        return Err("backup access revoked or cancelled".into());
                    }
                    let n = file
                        .read(&mut buffer)
                        .map_err(|_| "cannot read complete backup source")?;
                    if n == 0 {
                        break;
                    }
                    read += n as u64;
                    if read > before.len() {
                        return Err("backup source grew while reading".into());
                    }
                    hash.update(&buffer[..n]);
                }
                let after = file.metadata().map_err(|_| "cannot inspect backup data")?;
                if read != before.len()
                    || before.len() != after.len()
                    || before.mtime() != after.mtime()
                    || before.mtime_nsec() != after.mtime_nsec()
                    || before.ctime() != after.ctime()
                    || before.ctime_nsec() != after.ctime_nsec()
                {
                    return Err("backup source changed while reading".into());
                }
                *total += read;
                entry.kind = "file";
                entry.bytes = read;
                entry.content = hash.finalize().iter().map(|v| format!("{v:02x}")).collect();
                rows.insert(key, entry);
            }
            libc::S_IFLNK => {
                let mut target = vec![0u8; 4097];
                let n = unsafe {
                    libc::readlinkat(
                        dir.as_raw_fd(),
                        c.as_ptr(),
                        target.as_mut_ptr().cast(),
                        target.len(),
                    )
                };
                if n < 0 || n as usize >= target.len() {
                    return Err("invalid/oversized backup symlink".into());
                }
                entry.kind = "symlink";
                entry.bytes = n as u64;
                entry.content = sha(&target[..n as usize]);
                rows.insert(key, entry);
            }
            _ => return Err("special files cannot be captured by this adapter".into()),
        }
        if rows.len() > MAX_FILES {
            return Err("backup file-count limit reached".into());
        }
    }
    Ok(())
}
