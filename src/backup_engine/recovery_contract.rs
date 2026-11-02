//! Metadata-only export/recovery planning. NO authoritative snapshot, Secret
//! material, restored state, writer permit, or runnable workload is produced.
//! The committed-read/encrypted-export/escrow/data/cutover adapters are absent.
use super::{digest, require, Binding};
use crate::{auth::Identity, reconcile::DesiredWorld, storage_identity::Uid};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

const MAX_ITEMS: usize = 128;
const MAX_APPROVAL_MS: u64 = 15 * 60 * 1000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretSelection {
    Omit,
    ExplicitNames(Vec<String>),
}

fn valid_window(issued: u64, expires: u64, now: u64) -> Result<(), String> {
    if issued == 0
        || expires <= issued
        || expires.saturating_sub(issued) > MAX_APPROVAL_MS
        || now < issued
        || now >= expires
    {
        return Err(
            "control recovery/export approval expired or outside its bounded window".into(),
        );
    }
    Ok(())
}
fn namespace_uid(world: &DesiredWorld, namespace: &str) -> Result<Uid, String> {
    world
        .storage_identities
        .namespaces
        .get(namespace)
        .cloned()
        .ok_or("control namespace not found".into())
}
fn secret_rights(
    world: &DesiredWorld,
    actor: &Identity,
    namespace: &str,
    selection: &SecretSelection,
) -> Result<(), String> {
    if let SecretSelection::ExplicitNames(names) = selection {
        if names.is_empty()
            || names.len() > MAX_ITEMS
            || names.iter().collect::<BTreeSet<_>>().len() != names.len()
        {
            return Err("Secret export needs a bounded explicit unique selection".into());
        }
        for name in names {
            if name.is_empty()
                || name.len() > 253
                || !world
                    .secrets
                    .contains_key(&crate::store::obj_key(namespace, name))
            {
                return Err("selected Secret is absent or invalid".into());
            }
            require(
                world,
                actor,
                "export",
                "secrets",
                Some(namespace),
                Some(name),
            )?;
        }
    }
    Ok(())
}

/// Not Deserialize: an arbitrary body cannot invent even this server-generated
/// preview. Its metadata digest is NOT a committed-state or archive proof.
#[derive(Clone, Debug, Serialize)]
pub struct ControlPreview {
    version: u32,
    uid: Uid,
    source_cluster_id: String,
    source_generation: u64,
    namespace: String,
    namespace_uid: Uid,
    actor: String,
    issued_unix_ms: u64,
    expires_unix_ms: u64,
    secrets: SecretSelection,
    object_counts: BTreeMap<String, usize>,
    volume_references: Vec<Binding>,
    raw_manifests_exported: bool,
    live_authorities_exported: bool,
}
impl ControlPreview {
    pub fn prepare(
        world: &DesiredWorld,
        actor: &Identity,
        namespace: &str,
        secrets: SecretSelection,
        issued_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> Result<Self, String> {
        valid_window(issued_unix_ms, expires_unix_ms, issued_unix_ms)?;
        if actor.user.is_empty() {
            return Err("authenticated export actor is required".into());
        }
        require(
            world,
            actor,
            "export",
            "controlbackups",
            Some(namespace),
            None,
        )?;
        secret_rights(world, actor, namespace, &secrets)?;
        let uid = namespace_uid(world, namespace)?;
        let mut volumes = Vec::new();
        for claim in world
            .pvcs
            .values()
            .filter(|claim| claim.namespace == namespace && claim.bound_pv.is_some())
        {
            if volumes.len() == MAX_ITEMS {
                return Err("control volume-reference preview limit reached".into());
            }
            volumes.push(Binding::resolve(world, namespace, &claim.name)?);
        }
        volumes.sort_by(|a, b| a.claim_uid.cmp(&b.claim_uid));
        // Counts only: never serialize raw manifests/last-applied annotations,
        // config/env values, Secret values/digests, credentials or host permits.
        let counts = BTreeMap::from([
            (
                "deployments".into(),
                world
                    .deployments
                    .values()
                    .filter(|v| v.namespace == namespace)
                    .count(),
            ),
            (
                "services".into(),
                world
                    .services
                    .values()
                    .filter(|v| v.namespace == namespace)
                    .count(),
            ),
            (
                "configmaps".into(),
                world
                    .configmaps
                    .values()
                    .filter(|v| v.namespace == namespace)
                    .count(),
            ),
            (
                "claims".into(),
                world
                    .pvcs
                    .values()
                    .filter(|v| v.namespace == namespace)
                    .count(),
            ),
        ]);
        Ok(Self {
            version: 1,
            uid: Uid::new(),
            source_cluster_id: world.cluster_id.clone(),
            source_generation: world.generation,
            namespace: namespace.into(),
            namespace_uid: uid,
            actor: actor.user.clone(),
            issued_unix_ms,
            expires_unix_ms,
            secrets,
            object_counts: counts,
            volume_references: volumes,
            raw_manifests_exported: false,
            live_authorities_exported: false,
        })
    }
    pub fn hash(&self) -> Result<String, String> {
        digest(self)
    }
    fn validate_metadata(&self) -> Result<(), String> {
        if self.version != 1
            || self.actor.is_empty()
            || self.source_cluster_id.is_empty()
            || self.namespace.is_empty()
            || self.volume_references.len() > MAX_ITEMS
            || self.raw_manifests_exported
            || self.live_authorities_exported
        {
            return Err("invalid non-authoritative control preview".into());
        }
        Ok(())
    }
    pub fn reauthorize(
        &self,
        world: &DesiredWorld,
        actor: &Identity,
        now: u64,
        approval_hash: &str,
    ) -> Result<(), String> {
        self.validate_metadata()?;
        valid_window(self.issued_unix_ms, self.expires_unix_ms, now)?;
        if self.version != 1
            || self.hash()? != approval_hash
            || self.actor != actor.user
            || self.source_cluster_id != world.cluster_id
            || self.source_generation != world.generation
            || namespace_uid(world, &self.namespace)? != self.namespace_uid
        {
            return Err("control preview changed or belongs to stale state/namespace/actor".into());
        }
        require(
            world,
            actor,
            "export",
            "controlbackups",
            Some(&self.namespace),
            None,
        )?;
        secret_rights(world, actor, &self.namespace, &self.secrets)
    }
    pub fn blocked_requirements(&self) -> Vec<&'static str> {
        let mut required = vec![
            "AuthoritativeCommittedRead",
            "EncryptedControlBundle",
            "IndependentRecoveryKeys",
            "PhysicalFreshVolumeReceipt",
            "DataValidation",
            "ExplicitWorkloadRebindAndCutover",
        ];
        if !matches!(self.secrets, SecretSelection::Omit) {
            required.push("IndependentSecretEscrowAndMaterialExport");
        }
        required
    }
    pub fn export_bytes(&self) -> Result<Vec<u8>, String> {
        Err("control preview is not an export: committed-read/encryption/independent-key adapters unavailable".into())
    }
    /// Audit shape intentionally excludes selected Secret names and ALL payloads.
    pub fn audit_metadata(&self) -> serde_json::Value {
        serde_json::json!({"kind":"ControlExportPreview", "uid":self.uid, "namespace_uid":self.namespace_uid,
            "source_generation":self.source_generation, "authoritative_export":false,
            "explicit_secret_count":match &self.secrets {SecretSelection::Omit=>0,SecretSelection::ExplicitNames(v)=>v.len()},
            "blocked":self.blocked_requirements()})
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryMapping {
    pub source_volume_uid: Uid,
    pub destination: Binding,
}

/// No Ready/Running/Attached variant: this package cannot activate old sessions,
/// peers, writer epochs, restored workloads, or deserialize a live recovery cap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecoveryPhase {
    Quarantined,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryIntent {
    version: u32,
    uid: Uid,
    source_preview_sha256: String,
    source_cluster_id: String,
    source_namespace_uid: Uid,
    destination_cluster_id: String,
    destination_namespace: String,
    destination_namespace_uid: Uid,
    destination_generation: u64,
    actor: String,
    mappings: Vec<RecoveryMapping>,
    issued_unix_ms: u64,
    expires_unix_ms: u64,
    phase: RecoveryPhase,
}
impl RecoveryIntent {
    fn validate_metadata(&self) -> Result<(), String> {
        if self.version != 1
            || self.actor.is_empty()
            || !super::hash_ok(&self.source_preview_sha256)
            || self.source_cluster_id.is_empty()
            || self.destination_cluster_id.is_empty()
            || self.source_namespace_uid == self.destination_namespace_uid
            || self.mappings.len() > MAX_ITEMS
        {
            return Err("invalid quarantined recovery metadata".into());
        }
        let mut sources = BTreeSet::new();
        let mut targets = BTreeSet::new();
        let mut claims = BTreeSet::new();
        for mapping in &self.mappings {
            if !sources.insert(&mapping.source_volume_uid)
                || !targets.insert(&mapping.destination.volume_uid)
                || !claims.insert(&mapping.destination.claim_uid)
                || mapping.destination.namespace != self.destination_namespace
                || mapping.destination.namespace_uid != self.destination_namespace_uid
                || mapping.destination.cluster_id != self.destination_cluster_id
            {
                return Err("invalid or duplicate recovery mapping".into());
            }
        }
        if self
            .mappings
            .iter()
            .any(|m| sources.contains(&m.destination.volume_uid))
        {
            return Err("recovery target aliases an exported source volume".into());
        }
        Ok(())
    }
    pub fn prepare(
        world: &DesiredWorld,
        actor: &Identity,
        source: &ControlPreview,
        destination_namespace: &str,
        mappings: Vec<RecoveryMapping>,
        issued_unix_ms: u64,
        expires_unix_ms: u64,
    ) -> Result<Self, String> {
        valid_window(issued_unix_ms, expires_unix_ms, issued_unix_ms)?;
        valid_window(
            source.issued_unix_ms,
            source.expires_unix_ms,
            issued_unix_ms,
        )?;
        // Cluster-scoped recovery is deliberately distinct from ordinary
        // namespace restore rights, and imports no source RBAC/host authority.
        require(world, actor, "recover", "controlbackups", None, None)?;
        require(
            world,
            actor,
            "create",
            "restores",
            Some(destination_namespace),
            None,
        )?;
        let destination_uid = namespace_uid(world, destination_namespace)?;
        if destination_uid == source.namespace_uid || mappings.len() > MAX_ITEMS {
            return Err("control recovery requires a fresh namespace incarnation and bounded explicit mapping".into());
        }
        let expected: BTreeSet<_> = source
            .volume_references
            .iter()
            .map(|b| b.volume_uid.clone())
            .collect();
        let supplied: BTreeSet<_> = mappings
            .iter()
            .map(|b| b.source_volume_uid.clone())
            .collect();
        let mut targets = BTreeSet::new();
        let mut claims = BTreeSet::new();
        if supplied != expected || mappings.len() != expected.len() {
            return Err("every source volume needs one exact explicit recovery binding".into());
        }
        for mapping in &mappings {
            let target = &mapping.destination;
            if target.namespace != destination_namespace
                || target.namespace_uid != destination_uid
                || !target.current(world)
                || expected.contains(&target.volume_uid)
                || !targets.insert(target.volume_uid.clone())
                || !claims.insert(target.claim_uid.clone())
            {
                return Err(
                    "recovery mapping is stale, reused, foreign or aliases source data".into(),
                );
            }
        }
        Ok(Self {
            version: 1,
            uid: Uid::new(),
            source_preview_sha256: source.hash()?,
            source_cluster_id: source.source_cluster_id.clone(),
            source_namespace_uid: source.namespace_uid.clone(),
            destination_cluster_id: world.cluster_id.clone(),
            destination_namespace: destination_namespace.into(),
            destination_namespace_uid: destination_uid,
            destination_generation: world.generation,
            actor: actor.user.clone(),
            mappings,
            issued_unix_ms,
            expires_unix_ms,
            phase: RecoveryPhase::Quarantined,
        })
    }
    pub fn hash(&self) -> Result<String, String> {
        digest(self)
    }
    pub fn reauthorize(
        &self,
        world: &DesiredWorld,
        actor: &Identity,
        now: u64,
        approval_hash: &str,
    ) -> Result<(), String> {
        self.validate_metadata()?;
        valid_window(self.issued_unix_ms, self.expires_unix_ms, now)?;
        if self.version != 1
            || self.phase != RecoveryPhase::Quarantined
            || self.hash()? != approval_hash
            || self.actor != actor.user
            || self.destination_cluster_id != world.cluster_id
            || self.destination_generation != world.generation
            || namespace_uid(world, &self.destination_namespace)? != self.destination_namespace_uid
            || self.mappings.iter().any(|m| !m.destination.current(world))
        {
            return Err(
                "recovery intent expired, cancelled, changed or lost its target identity".into(),
            );
        }
        require(world, actor, "recover", "controlbackups", None, None)?;
        require(
            world,
            actor,
            "create",
            "restores",
            Some(&self.destination_namespace),
            None,
        )
    }
    pub fn cancel(
        &mut self,
        world: &DesiredWorld,
        actor: &Identity,
        now: u64,
        approval_hash: &str,
    ) -> Result<(), String> {
        self.reauthorize(world, actor, now, approval_hash)?;
        self.phase = RecoveryPhase::Cancelled;
        Ok(())
    }
    pub fn workloads_may_start(&self) -> bool {
        false
    }
    pub fn materialize_desired_state(&self) -> Result<crate::store::DesiredState, String> {
        Err("quarantined recovery metadata cannot produce live desired state; physical data/rebind/cutover proof unavailable".into())
    }
    pub fn audit_metadata(&self) -> serde_json::Value {
        serde_json::json!({"kind":"ControlRecoveryIntent", "uid":self.uid, "source_namespace_uid":self.source_namespace_uid,
            "destination_namespace_uid":self.destination_namespace_uid, "mapping_count":self.mappings.len(),
            "phase":self.phase,"workloads_enabled":false})
    }
}
