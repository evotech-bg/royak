//! Durable storage-member data, not a physical capability. Only the separate
//! internal Enrollment Raft command may install it; generic state/serde cannot.
use crate::storage_identity::Uid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(crate) const ENROLLMENT_PURPOSE: &[u8] = b"royak-storage-directory-enrollment-v1";
pub(crate) const GUARD_PURPOSE: &[u8] = b"royak-storage-directory-history-v1";
pub(crate) const MAX_BYTES: usize = 64 * 1024;
pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_cluster(value: &str) -> bool {
    value.len() == 12
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn valid_wireguard_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' {
        return false;
    }
    let mut accumulator = 0u32;
    let mut bits = 0;
    let mut decoded = Vec::with_capacity(32);
    for &b in &bytes[..43] {
        let n = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return false,
        };
        accumulator = (accumulator << 6) | u32::from(n);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            decoded.push((accumulator >> bits) as u8);
            accumulator &= (1u32 << bits) - 1;
        }
    }
    decoded.len() == 32 && bits == 2 && accumulator == 0 && decoded.iter().any(|b| *b != 0)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodePin {
    pub(crate) node_uid: Uid,
    pub(crate) raft_id: u64,
    pub(crate) signer_name: String,
    pub(crate) wireguard_key: String,
    pub(crate) wireguard_ip: std::net::Ipv4Addr,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DirectoryDto {
    pub(crate) version: u32,
    pub(crate) cluster_id: String,
    /// Canonically ascending Raft ID; names never create/replace identities.
    pub(crate) nodes: Vec<NodePin>,
}
impl DirectoryDto {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.version != 1
            || !valid_cluster(&self.cluster_id)
            || !(3..=32).contains(&self.nodes.len())
        {
            return Err("invalid explicit storage-node directory".into());
        }
        let (mut uids, mut ids, mut names, mut keys, mut ips) = (
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        );
        let mut previous = 0;
        for node in &self.nodes {
            if node.raft_id <= previous
                || node.node_uid.as_str() == "00000000000000000000000000000000"
                || !crate::store::is_dns_subdomain(&node.signer_name)
                || !node.wireguard_ip.is_private()
                || !valid_wireguard_key(&node.wireguard_key)
                || !uids.insert(&node.node_uid)
                || !ids.insert(node.raft_id)
                || !names.insert(&node.signer_name)
                || !keys.insert(&node.wireguard_key)
                || !ips.insert(node.wireguard_ip)
            {
                return Err("ambiguous, noncanonical or reused storage-node UID/voter/signer/WireGuard binding".into());
            }
            previous = node.raft_id;
        }
        Ok(())
    }
    pub(crate) fn sha256(&self) -> Result<String, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| "invalid directory encoding")?;
        if bytes.len() > MAX_BYTES {
            return Err("directory exceeds fixed bound".into());
        }
        Ok(digest(&bytes))
    }
    pub(crate) fn pin(&self, uid: &Uid) -> Result<&NodePin, String> {
        self.nodes
            .iter()
            .find(|p| &p.node_uid == uid)
            .ok_or_else(|| "storage-node UID is not enrolled".into())
    }
    pub(crate) fn voters(&self) -> Vec<u64> {
        self.nodes.iter().map(|p| p.raft_id).collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentHistory {
    pub(crate) command_uid: Uid,
    pub(crate) directory_sha256: String,
    pub(crate) membership_sha256: String,
    pub(crate) applied_term: u64,
    pub(crate) applied_leader: u64,
    pub(crate) applied_index: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrolled {
    directory: DirectoryDto,
    history: EnrollmentHistory,
}
/// Version zero means missing legacy data, never auto-created node identities.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    version: u32,
    enrollment: Option<Enrolled>,
}
impl Registry {
    pub(crate) fn fresh() -> Self {
        Self {
            version: 1,
            enrollment: None,
        }
    }
    pub(crate) fn has_authority(&self) -> bool {
        self.enrollment.is_some()
    }
    pub(crate) fn directory(&self) -> Option<&DirectoryDto> {
        self.enrollment.as_ref().map(|e| &e.directory)
    }
    pub(crate) fn history(&self) -> Option<&EnrollmentHistory> {
        self.enrollment.as_ref().map(|e| &e.history)
    }
    pub(crate) fn validate(&self, cluster: &str) -> Result<(), String> {
        if self.version != 1 {
            return Err("missing/unsupported explicit node-directory registry".into());
        }
        if let Some(e) = &self.enrollment {
            if e.directory.cluster_id != cluster
                || !valid_hash(&e.history.membership_sha256)
                || e.history.directory_sha256 != e.directory.sha256()?
                || e.history.applied_term == 0
                || e.history.applied_leader == 0
                || e.history.applied_index == 0
                || !e.directory.voters().contains(&e.history.applied_leader)
            {
                return Err("invalid immutable storage-directory enrollment history".into());
            }
        }
        Ok(())
    }
    pub(crate) fn validate_state(&self, state: &crate::store::DesiredState) -> Result<(), String> {
        self.validate(&state.cluster_id)?;
        if let Some(d) = self.directory() {
            for pin in &d.nodes {
                if state
                    .storage_identities
                    .namespaces
                    .values()
                    .chain(state.storage_identities.volumes.values())
                    .chain(state.storage_identities.claims.values().map(|c| &c.uid))
                    .any(|uid| uid == &pin.node_uid)
                {
                    return Err("node UID aliases a namespace/claim/volume identity".into());
                }
            }
            for uid in state.storage_identities.volumes.values() {
                if let Some(volume) = state.storage_identities.lifecycle.get(uid) {
                    if let Some(nodes) = volume.replicas() {
                        for node in nodes {
                            d.pin(node)?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
    /// Ordinary apply/restore/reconcile/Commit may preserve, never enroll,
    /// remove, replace or rewrite the original receipt, even with valid serde.
    pub(crate) fn require_unchanged(&self, next: &Self) -> Result<(), String> {
        if self != next {
            return Err("directory changes require the internal privileged enrollment transaction; reconfiguration/re-enrollment is unsupported".into());
        }
        Ok(())
    }
    pub(crate) fn from_entry(
        proposal: &EnrollmentProposal,
        log: openraft::LogId<u64>,
    ) -> Result<Self, String> {
        proposal.validate()?;
        if log.leader_id.term != proposal.term
            || log.leader_id.node_id != proposal.leader
            || log.index == 0
        {
            return Err("enrollment proposal crossed leader/term before actual apply".into());
        }
        Ok(Self {
            version: 1,
            enrollment: Some(Enrolled {
                directory: proposal.directory.clone(),
                history: EnrollmentHistory {
                    command_uid: proposal.command_uid.clone(),
                    directory_sha256: proposal.directory.sha256()?,
                    membership_sha256: proposal.membership_sha256.clone(),
                    applied_term: log.leader_id.term,
                    applied_leader: log.leader_id.node_id,
                    applied_index: log.index,
                },
            }),
        })
    }
    pub(crate) fn require_guard(&self, guard: Option<&Self>) -> Result<(), String> {
        if !self.has_authority() || guard != Some(self) {
            return Err("committed directory lacks exact local applied-history guard; explicit recovery, never serde re-enrollment".into());
        }
        Ok(())
    }
    pub(crate) fn require_membership(
        &self,
        membership: &openraft::StoredMembership<u64, openraft::BasicNode>,
    ) -> Result<(), String> {
        let Some(enrolled) = &self.enrollment else {
            return Err("directory is not enrolled".into());
        };
        if membership.membership().is_in_joint_consensus()
            || enrolled.directory.voters()
                != membership.membership().voter_ids().collect::<Vec<_>>()
            || enrolled.history.membership_sha256
                != digest(&serde_json::to_vec(membership).map_err(|_| "invalid membership")?)
        {
            return Err("directory membership change is unsupported; explicit guarded reconfiguration required".into());
        }
        Ok(())
    }
    pub(crate) fn require_explicit(raw: &serde_json::Value) -> Result<(), String> {
        let r = raw
            .as_object()
            .ok_or("node-directory registry must be an object")?;
        if r.len() != 2
            || r.get("version").and_then(|v| v.as_u64()) != Some(1)
            || !r.contains_key("enrollment")
        {
            return Err(
                "current schema/envelope must contain explicit node-directory fields".into(),
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentProposal {
    pub(crate) version: u32,
    pub(crate) command_uid: Uid,
    pub(crate) directory: DirectoryDto,
    pub(crate) base_generation: u64,
    pub(crate) term: u64,
    pub(crate) leader: u64,
    pub(crate) membership_sha256: String,
}
impl EnrollmentProposal {
    pub(crate) fn validate(&self) -> Result<(), String> {
        self.directory.validate()?;
        if self.version != 1
            || self.term == 0
            || !self.directory.voters().contains(&self.leader)
            || !valid_hash(&self.membership_sha256)
        {
            return Err("invalid internal node-directory proposal".into());
        }
        Ok(())
    }
    pub(crate) fn seal(&self) -> Result<String, String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| "invalid enrollment encoding")?;
        if bytes.len() > MAX_BYTES / 2 {
            return Err("enrollment proposal exceeds bound".into());
        }
        crate::auth::seal_for_cluster(ENROLLMENT_PURPOSE, &bytes)
    }
    pub(crate) fn open(sealed: &str) -> Result<Self, String> {
        if sealed.len() > MAX_BYTES {
            return Err("sealed enrollment exceeds bound".into());
        }
        let bytes = crate::auth::unseal_for_cluster(ENROLLMENT_PURPOSE, sealed)?;
        let p: Self =
            serde_json::from_slice(&bytes).map_err(|_| "malformed exact enrollment proposal")?;
        p.validate()?;
        Ok(p)
    }
}

pub(crate) fn require_unstarted(state: &crate::store::DesiredState) -> Result<(), String> {
    // A node directory cannot adopt pre-existing replica/data incarnations.
    let raw = serde_json::to_value(&state.storage_identities)
        .map_err(|_| "invalid storage identity data")?;
    let records = raw
        .get("lifecycle")
        .and_then(|v| v.get("volumes"))
        .and_then(|v| v.as_object())
        .ok_or("missing managed-volume inventory")?;
    for volume in records.values() {
        if volume.get("phase").and_then(|v| v.as_str()) != Some("PendingProvision")
            || volume.get("epoch").and_then(|v| v.as_u64()) != Some(0)
            || [
                "replicas",
                "provision_boots",
                "filesystem_uuid",
                "assignment",
                "evidence",
                "data_generation",
            ]
            .into_iter()
            .any(|key| volume.get(key).is_some_and(|v| !v.is_null()))
        {
            return Err("node enrollment cannot adopt started replica/data/writer history; explicit quarantined recovery required".into());
        }
    }
    Ok(())
}
pub(crate) fn legacy_without_node_authority(raw: &serde_json::Value) -> Result<(), String> {
    let root = raw.as_object().ok_or("legacy state must be an object")?;
    if root.contains_key("storage_node_directory") {
        return Err(
            "old schema/domain cannot import even newly-shaped node-directory authority".into(),
        );
    }
    crate::storage_lifecycle::legacy_without_data_authority(raw)?;
    if let Some(volumes) = root
        .get("storage_identities")
        .and_then(|v| v.get("lifecycle"))
        .and_then(|v| v.get("volumes"))
        .and_then(|v| v.as_object())
    {
        for volume in volumes.values() {
            if ["replicas", "provision_boots"]
                .into_iter()
                .any(|key| volume.get(key).is_some_and(|v| !v.is_null()))
            {
                return Err(
                    "legacy replica node identities cannot be re-enrolled/backfilled".into(),
                );
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn uid(n: u64) -> Uid {
        serde_json::from_value(serde_json::json!(format!("{n:032x}"))).unwrap()
    }
    fn directory() -> DirectoryDto {
        DirectoryDto {
            version: 1,
            cluster_id: "aabbccddeeff".into(),
            nodes: (1..=3)
                .map(|n| NodePin {
                    node_uid: uid(n),
                    raft_id: n,
                    signer_name: format!("node-{n}"),
                    wireguard_key: format!(
                        "{}{}=",
                        "A".repeat(42),
                        ["E", "I", "M"][(n - 1) as usize]
                    ),
                    wireguard_ip: std::net::Ipv4Addr::new(10, 213, 0, n as u8),
                })
                .collect(),
        }
    }
    #[test]
    fn canonical_directory_refuses_duplicate_or_reused_bindings() {
        let d = directory();
        d.validate().unwrap();
        for field in [
            "node_uid",
            "raft_id",
            "signer_name",
            "wireguard_key",
            "wireguard_ip",
        ] {
            let mut v = serde_json::to_value(&d).unwrap();
            v["nodes"][1][field] = v["nodes"][0][field].clone();
            assert!(
                serde_json::from_value::<DirectoryDto>(v)
                    .unwrap()
                    .validate()
                    .is_err(),
                "{field}"
            );
        }
        let mut d = d;
        d.nodes.swap(0, 1);
        assert!(d.validate().is_err());
    }
    #[test]
    fn key_shape_is_not_enough_noncanonical_and_zero_keys_refuse() {
        assert!(!valid_wireguard_key(&format!("{}=", "A".repeat(43))));
        assert!(!valid_wireguard_key(&format!("{}B=", "A".repeat(42))));
        assert!(valid_wireguard_key(&format!("{}E=", "A".repeat(42))));
    }
    #[test]
    fn serde_data_cannot_change_ordinary_registry_history() {
        let p = EnrollmentProposal {
            version: 1,
            command_uid: uid(100),
            directory: directory(),
            base_generation: 0,
            term: 2,
            leader: 1,
            membership_sha256: "a".repeat(64),
        };
        let enrolled = Registry::from_entry(
            &p,
            openraft::LogId::new(openraft::CommittedLeaderId::new(2, 1), 5),
        )
        .unwrap();
        enrolled.validate("aabbccddeeff").unwrap();
        assert!(Registry::fresh().require_unchanged(&enrolled).is_err());
        assert!(enrolled.require_unchanged(&Registry::fresh()).is_err());
        assert!(enrolled.require_guard(None).is_err());
        enrolled.require_guard(Some(&enrolled)).unwrap();
        let mut other = p.clone();
        other.command_uid = uid(101);
        let changed = Registry::from_entry(
            &other,
            openraft::LogId::new(openraft::CommittedLeaderId::new(2, 1), 5),
        )
        .unwrap();
        assert!(enrolled.require_unchanged(&changed).is_err());
        assert!(enrolled.require_guard(Some(&changed)).is_err());
    }
    #[test]
    fn old_domain_never_backfills_node_uids_or_accepts_smuggled_directory() {
        let safe =
            serde_json::json!({"storage_identities":{"lifecycle":{"version":1,"volumes":{}}}});
        legacy_without_node_authority(&safe).unwrap();
        let mut hidden = safe.clone();
        hidden["storage_node_directory"] = serde_json::to_value(Registry::fresh()).unwrap();
        assert!(legacy_without_node_authority(&hidden).is_err());
        let bad = serde_json::json!({"storage_identities":{"lifecycle":{"version":1,"volumes":{"v":{
            "version":1,"phase":"Provisioning","epoch":0,"replicas":["already-allocated"]}}}}});
        assert!(legacy_without_node_authority(&bad).is_err());
    }
}
