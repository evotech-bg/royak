//! Durable, per-state-file TLS identity shared by API and ingress.
//! A bad existing identity is an error, never permission to silently rotate it.
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u32,
    certificate: String,
    private_key: String,
}

fn private_file(file: &File) -> Result<(), String> {
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() > 64 * 1024 {
        return Err("TLS identity must be a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } || meta.nlink() != 1
        {
            return Err("TLS identity requires private, singly-linked owner-only storage".into());
        }
    }
    Ok(())
}

pub fn server_config(cert: &str, key: &str) -> Result<rustls::ServerConfig, String> {
    let certificates = rustls_pemfile::certs(&mut cert.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| "invalid TLS certificate PEM")?;
    let key = rustls_pemfile::private_key(&mut key.as_bytes())
        .map_err(|_| "invalid TLS key PEM")?
        .ok_or("missing TLS private key")?;
    rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| "TLS protocol configuration failed")?
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .map_err(|_| "TLS certificate/private key validation failed".into())
}

pub fn load_or_create(path: &Path) -> Result<(String, String), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| format!("TLS identity directory: {e}"))?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let lock = options
        .open(path.with_extension("tls-lock"))
        .map_err(|e| format!("TLS identity lock: {e}"))?;
    private_file(&lock)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err("TLS identity lock unavailable".into());
        }
    }
    let mut read = OpenOptions::new();
    read.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        read.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    match read.open(path) {
        Ok(mut file) => {
            private_file(&file)?;
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(64 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "TLS identity read failed")?;
            let identity: Identity = serde_json::from_slice(&bytes)
                .map_err(|_| "invalid stored TLS identity; refusing rotation")?;
            if identity.version != 1 {
                return Err("unsupported TLS identity version".into());
            }
            server_config(&identity.certificate, &identity.private_key)?;
            return Ok((identity.certificate, identity.private_key));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("TLS identity cannot be opened safely; refusing rotation".into()),
    }
    let (certificate, private_key) = crate::api::generate_tls_cert()?;
    server_config(&certificate, &private_key)?;
    let identity = Identity {
        version: 1,
        certificate,
        private_key,
    };
    let bytes = serde_json::to_vec(&identity).map_err(|_| "TLS identity encoding failed")?;
    let temporary = parent.join(format!(
        ".royak-tls-{}-{:016x}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| {
        let mut create = OpenOptions::new();
        create.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            create
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = create
            .open(&temporary)
            .map_err(|_| "TLS identity temporary file failed")?;
        file.write_all(&bytes)
            .map_err(|_| "TLS identity write failed")?;
        file.sync_all().map_err(|_| "TLS identity fsync failed")?;
        std::fs::rename(&temporary, path).map_err(|_| "TLS identity rename failed")?;
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| "TLS identity directory fsync failed")?;
        Ok((identity.certificate, identity.private_key))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub fn for_state() -> Result<(String, String), String> {
    load_or_create(Path::new(&format!("{}.tls.json", crate::state_path())))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp() -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("royak-tls-test-{:016x}", rand::random::<u64>()));
        std::fs::create_dir(&path).unwrap();
        path
    }
    #[test]
    fn identity_survives_reload_and_concurrent_listener_start() {
        let dir = temp();
        let path = dir.join("identity.json");
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || load_or_create(&p).unwrap())
            })
            .collect();
        let identities: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert!(identities.iter().all(|i| i == &identities[0]));
        assert_eq!(load_or_create(&path).unwrap(), identities[0]);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn corrupt_or_mismatched_identity_is_not_replaced() {
        let dir = temp();
        let path = dir.join("identity.json");
        let (cert, _) = load_or_create(&path).unwrap();
        let (_, foreign_key) = crate::api::generate_tls_cert().unwrap();
        let bytes = serde_json::to_vec(&Identity {
            version: 1,
            certificate: cert,
            private_key: foreign_key,
        })
        .unwrap();
        std::fs::write(&path, &bytes).unwrap();
        assert!(load_or_create(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(load_or_create(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn symlink_and_publicly_readable_identity_are_refused() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = temp();
        let path = dir.join("identity.json");
        load_or_create(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_create(&path).is_err());
        let link = dir.join("link.json");
        symlink(&path, &link).unwrap();
        assert!(load_or_create(&link).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn non_regular_identity_does_not_block_startup() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let dir = temp();
        let path = dir.join("identity.json");
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(load_or_create(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
