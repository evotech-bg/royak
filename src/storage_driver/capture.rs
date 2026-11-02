//! Read-only storage → backup seam. Descriptors are evidence, not authority.
//! No production constructor exists until snapshot/fence/mount observation is
//! implemented and qualified. A prepared Secondary must not reach this seam.
use crate::storage_boot::BootId;
use crate::storage_identity::Uid;
use serde::Serialize;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum Consistency {
    Cold,
    FilesystemCrashConsistent,
    ApplicationConsistent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CaptureDescriptor {
    pub cluster_id: String,
    pub namespace_uid: Uid,
    pub claim_uid: Uid,
    pub volume_uid: Uid,
    pub filesystem_uuid: String,
    pub epoch: u64,
    pub operation_uid: Uid,
    pub node_uid: Uid,
    pub node_boot_id: BootId,
    pub capture_uid: Uid,
    pub snapshot_uid: Uid,
    pub backend_device_uuid: String,
    pub source_major: u64,
    pub source_minor: u64,
    pub mount_id: u64,
    pub generation: String,
    pub readonly: bool,
    pub consistency: Consistency,
    pub evidence_sha256: String,
    pub capture_started_unix_ms: u64,
    pub capture_finished_unix_ms: u64,
}

/// Neither Deserialize nor a public raw-fields constructor is provided.
/// Future constructor must hold an opened private mount lease + pin namespace,
/// snapshot generation, exact device and actual read-only kernel mount ID.
pub(crate) struct VerifiedBackupSource {
    descriptor: CaptureDescriptor,
    source_path: PathBuf,
}

impl VerifiedBackupSource {
    pub(crate) fn descriptor(&self) -> &CaptureDescriptor {
        &self.descriptor
    }
    pub(crate) fn source_path_for_worker(&self) -> Result<&Path, String> {
        let _ = &self.source_path;
        Err("verified snapshot/mount capture is not implemented; backup source unavailable".into())
    }
}
