//! Closed diagnostic DATA. None of these deserializable values is a worker,
//! retained node owner, live round, physical result or lifecycle receipt.
use super::{
    valid_hash, valid_uuid, BootId, DataGeneration, InitializationIntent, Owner, Uid,
    VirginReplicaRef,
};
use crate::storage_remote_protocol::Revision;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum InitPhase {
    ActivateSecondary,
    ObserveFresh,
    Bootstrap,
    ObserveSynchronized,
    Promote,
    Format,
    FlushPrimary,
    ObserveReplicated,
    Demote,
    ObserveDemoted,
    Offline,
    ObserveOffline,
}
impl InitPhase {
    pub(crate) fn initializer_only(self) -> bool {
        matches!(
            self,
            Self::Bootstrap | Self::Promote | Self::Format | Self::FlushPrimary | Self::Demote
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExpectedInitScope {
    pub(crate) version: u32,
    pub(crate) owner: Owner,
    pub(crate) generation: DataGeneration,
    pub(crate) issuer_node_uid: Uid,
    pub(crate) issuer_boot: BootId,
    pub(crate) issuer_revision: Revision,
    pub(crate) directory_sha256: String,
    pub(crate) scope_sha256: String,
    pub(crate) target_node_uid: Uid,
    pub(crate) target_boot: BootId,
    pub(crate) prepare_job_uid: Uid,
    pub(crate) phase_job_uid: Uid,
    pub(crate) phase: InitPhase,
    // Wire DATA only: the receiver anchors its own original monotonic deadline.
    pub(crate) remaining_budget_ms: u64,
}
impl ExpectedInitScope {
    pub(crate) fn validate(&self) -> Result<(), String> {
        let fact = self
            .generation
            .virgin_replicas
            .iter()
            .find(|fact| {
                fact.node_uid == self.target_node_uid && fact.node_boot_id == self.target_boot
            })
            .ok_or("phase target/boot absent from exact generation")?;
        fact.validate()?;
        if self.version != 1
            || self.remaining_budget_ms == 0
            || self.remaining_budget_ms > 180_000
            || !valid_hash(&self.directory_sha256)
            || !valid_hash(&self.scope_sha256)
            || !valid_hash(&self.issuer_revision.membership_sha256)
            || self.issuer_revision.term == 0
            || self.issuer_revision.leader_raft_id == 0
            || self.issuer_revision.applied_index == 0
            || self.issuer_revision.desired_generation == 0
            || self.generation.version != 1
            || !valid_uuid(&self.generation.filesystem_uuid)
            || self.generation.filesystem_uuid == "00000000-0000-0000-0000-000000000000"
            || self.generation.prepare_operation_uid == self.generation.initialize_operation_uid
            || fact.volume_uid != self.owner.volume_uid
            || fact.prepare_operation_uid != self.generation.prepare_operation_uid
            || self.prepare_job_uid == self.phase_job_uid
            || self.phase.initializer_only()
                && self.target_node_uid != self.generation.initializer_node_uid
        {
            return Err("invalid bounded exact initialization phase data".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrimaryFlushObservation {
    pub(crate) version: u32,
    pub(crate) owner: Owner,
    pub(crate) data_generation_uid: Uid,
    pub(crate) initialize_operation_uid: Uid,
    pub(crate) filesystem_uuid: String,
    pub(crate) replica: VirginReplicaRef,
    pub(crate) backing_major: u64,
    pub(crate) backing_minor: u64,
    pub(crate) backing_bytes: u64,
    pub(crate) data_sha256: String,
    pub(crate) flush_sha256: String,
    pub(crate) evidence_sha256: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OfflineReplicaObservation {
    pub(crate) version: u32,
    pub(crate) owner: Owner,
    pub(crate) data_generation_uid: Uid,
    pub(crate) initialize_operation_uid: Uid,
    pub(crate) filesystem_uuid: String,
    pub(crate) replica: VirginReplicaRef,
    pub(crate) backing_major: u64,
    pub(crate) backing_minor: u64,
    pub(crate) backing_bytes: u64,
    pub(crate) data_sha256: String,
    pub(crate) offline_metadata_sha256: String,
    pub(crate) drbd_current_uuid: String,
    pub(crate) evidence_sha256: String,
}
fn common(
    intent: &InitializationIntent,
    version: u32,
    owner: &Owner,
    generation: &Uid,
    operation: &Uid,
    filesystem: &str,
    replica: &VirginReplicaRef,
    major: u64,
    minor: u64,
    bytes: u64,
    data: &str,
    evidence: &str,
) -> Result<(), String> {
    replica.validate()?;
    if version != 1
        || owner != intent.owner()
        || generation != &intent.generation().uid
        || operation != intent.operation_uid()
        || filesystem != intent.generation().filesystem_uuid
        || !intent
            .generation()
            .virgin_replicas
            .iter()
            .any(|expected| expected == replica)
        || major > u32::MAX as u64
        || minor > u32::MAX as u64
        || bytes < replica.exposed_bytes
        || !valid_hash(data)
        || !valid_hash(evidence)
    {
        return Err("physical observation differs from exact dataset/node/backing lineage".into());
    }
    Ok(())
}
impl PrimaryFlushObservation {
    pub(crate) fn validate_for(&self, intent: &InitializationIntent) -> Result<(), String> {
        common(
            intent,
            self.version,
            &self.owner,
            &self.data_generation_uid,
            &self.initialize_operation_uid,
            &self.filesystem_uuid,
            &self.replica,
            self.backing_major,
            self.backing_minor,
            self.backing_bytes,
            &self.data_sha256,
            &self.evidence_sha256,
        )?;
        if self.replica.node_uid != intent.generation().initializer_node_uid
            || !valid_hash(&self.flush_sha256)
        {
            return Err("flushed primary is not the designated initializer".into());
        }
        Ok(())
    }
}
impl OfflineReplicaObservation {
    pub(crate) fn validate_for(&self, intent: &InitializationIntent) -> Result<(), String> {
        common(
            intent,
            self.version,
            &self.owner,
            &self.data_generation_uid,
            &self.initialize_operation_uid,
            &self.filesystem_uuid,
            &self.replica,
            self.backing_major,
            self.backing_minor,
            self.backing_bytes,
            &self.data_sha256,
            &self.evidence_sha256,
        )?;
        if !valid_hash(&self.offline_metadata_sha256)
            || self.drbd_current_uuid.len() != 16
            || ["0000000000000000", "0000000000000004"].contains(&self.drbd_current_uuid.as_str())
            || !self
                .drbd_current_uuid
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("offline initialized metadata/current UUID is missing".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PhaseObservation {
    pub(crate) version: u32,
    pub(crate) phase: InitPhase,
    pub(crate) owner: Owner,
    pub(crate) data_generation_uid: Uid,
    pub(crate) initialize_operation_uid: Uid,
    pub(crate) replica: VirginReplicaRef,
    pub(crate) raw_kernel: Option<serde_json::Value>,
    pub(crate) primary: Option<PrimaryFlushObservation>,
    pub(crate) offline: Option<OfflineReplicaObservation>,
    pub(crate) evidence_sha256: String,
}
impl PhaseObservation {
    pub(crate) fn validate_for(
        &self,
        intent: &InitializationIntent,
        phase: InitPhase,
        fact: &VirginReplicaRef,
    ) -> Result<(), String> {
        if self.version != 1
            || self.phase != phase
            || &self.replica != fact
            || self.owner != *intent.owner()
            || self.data_generation_uid != intent.generation().uid
            || self.initialize_operation_uid != *intent.operation_uid()
            || !valid_hash(&self.evidence_sha256)
            || self.primary.is_some() != (phase == InitPhase::FlushPrimary)
            || self.offline.is_some() != (phase == InitPhase::ObserveOffline)
        {
            return Err("phase observation is not the exact expected diagnostic".into());
        }
        if let Some(primary) = &self.primary {
            primary.validate_for(intent)?;
            if primary.replica != *fact {
                return Err("primary target changed".into());
            }
        }
        if let Some(offline) = &self.offline {
            offline.validate_for(intent)?;
            if offline.replica != *fact {
                return Err("offline target changed".into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn model() -> InitializationIntent {
        super::super::model_initialization_for_authority_tests().1
    }
    #[test]
    fn phase_scope_data_refuses_wrong_target_boot_initializer_or_renewed_wire_budget() {
        let intent = model();
        let source = &intent.generation().virgin_replicas[0];
        let target = &intent.generation().virgin_replicas[1];
        let good = ExpectedInitScope {
            version: 1,
            owner: intent.owner().clone(),
            generation: intent.generation().clone(),
            issuer_node_uid: source.node_uid.clone(),
            issuer_boot: source.node_boot_id.clone(),
            issuer_revision: Revision {
                term: 1,
                leader_raft_id: 1,
                applied_term: 1,
                applied_leader_raft_id: 1,
                applied_index: 1,
                desired_generation: 1,
                membership_sha256: "a".repeat(64),
            },
            directory_sha256: "b".repeat(64),
            scope_sha256: "c".repeat(64),
            target_node_uid: target.node_uid.clone(),
            target_boot: target.node_boot_id.clone(),
            prepare_job_uid: Uid::new(),
            phase_job_uid: Uid::new(),
            phase: InitPhase::ObserveFresh,
            remaining_budget_ms: 180_000,
        };
        good.validate().unwrap();
        for case in 0..7 {
            let mut bad = good.clone();
            match case {
                0 => bad.phase = InitPhase::Format,
                1 => bad.target_node_uid = Uid::new(),
                2 => {
                    bad.target_boot = serde_json::from_value(serde_json::json!(
                        "bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb"
                    ))
                    .unwrap()
                }
                3 => bad.remaining_budget_ms = 180_001,
                4 => bad.remaining_budget_ms = 0,
                5 => bad.prepare_job_uid = bad.phase_job_uid.clone(),
                _ => bad.generation.filesystem_uuid = "bad".into(),
            }
            assert!(bad.validate().is_err(), "scope data case{case}");
        }
    }
    pub(super) fn primary(intent: &InitializationIntent) -> PrimaryFlushObservation {
        PrimaryFlushObservation {
            version: 1,
            owner: intent.owner().clone(),
            data_generation_uid: intent.generation().uid.clone(),
            initialize_operation_uid: intent.operation_uid().clone(),
            filesystem_uuid: intent.generation().filesystem_uuid.clone(),
            replica: intent.generation().virgin_replicas[0].clone(),
            backing_major: 253,
            backing_minor: 1,
            backing_bytes: 192 * 1024 * 1024,
            data_sha256: "a".repeat(64),
            flush_sha256: "b".repeat(64),
            evidence_sha256: "c".repeat(64),
        }
    }
    #[test]
    fn diagnostic_primary_data_requires_exact_initializer_filesystem_generation_and_backing() {
        let intent = model();
        let good = primary(&intent);
        good.validate_for(&intent).unwrap();
        for case in 0..9 {
            let mut bad = good.clone();
            match case {
                0 => bad.replica = intent.generation().virgin_replicas[1].clone(),
                1 => bad.owner.namespace_uid = Uid::new(),
                2 => bad.data_generation_uid = Uid::new(),
                3 => bad.initialize_operation_uid = Uid::new(),
                4 => bad.filesystem_uuid = "bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb".into(),
                5 => {
                    bad.replica.node_boot_id = serde_json::from_value(serde_json::json!(
                        "bbbbbbbb-bbbb-4bbb-abbb-bbbbbbbbbbbb"
                    ))
                    .unwrap()
                }
                6 => bad.backing_bytes = 0,
                7 => bad.flush_sha256 = "bad".into(),
                _ => bad.data_sha256 = "bad".into(),
            }
            assert!(bad.validate_for(&intent).is_err(), "data case {case}");
        }
    }
    #[test]
    fn phase_data_cannot_move_primary_or_offline_payload_to_another_phase() {
        let intent = model();
        let primary = primary(&intent);
        let fact = primary.replica.clone();
        let mut observation = PhaseObservation {
            version: 1,
            phase: InitPhase::FlushPrimary,
            owner: intent.owner().clone(),
            data_generation_uid: intent.generation().uid.clone(),
            initialize_operation_uid: intent.operation_uid().clone(),
            replica: fact.clone(),
            raw_kernel: None,
            primary: Some(primary),
            offline: None,
            evidence_sha256: "d".repeat(64),
        };
        observation
            .validate_for(&intent, InitPhase::FlushPrimary, &fact)
            .unwrap();
        observation.phase = InitPhase::Format;
        assert!(observation
            .validate_for(&intent, InitPhase::Format, &fact)
            .is_err());
        observation.primary = None;
        observation.phase = InitPhase::ObserveOffline;
        assert!(observation
            .validate_for(&intent, InitPhase::ObserveOffline, &fact)
            .is_err());
    }
    #[test]
    fn physical_dto_unknown_fields_remain_data_decode_refusals() {
        let mut value = serde_json::to_value(primary(&model())).unwrap();
        value["verified"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PrimaryFlushObservation>(value).is_err());
        assert!(!InitPhase::ActivateSecondary.initializer_only());
        for phase in [
            InitPhase::Bootstrap,
            InitPhase::Promote,
            InitPhase::Format,
            InitPhase::FlushPrimary,
            InitPhase::Demote,
        ] {
            assert!(phase.initializer_only());
        }
    }
}
