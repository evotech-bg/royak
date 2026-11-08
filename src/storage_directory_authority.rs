//! The sole actual privileged directory CAS path. No HTTP/body/restore handler
//! calls enrollment. The explicit startup option reads a trusted private file.
use super::*;
use crate::storage_driver::node_identity;
use crate::storage_node_directory::{self as data, EnrollmentProposal, Registry};
use std::time::Duration;
#[cfg(test)]
#[path = "storage_directory_tests.rs"]
mod tests;

pub(crate) async fn enroll(approval: node_identity::ApprovedEnrollment) -> Result<(), String> {
    if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
        return Err("directory enrollment requires explicit Linux root".into());
    }
    let approved = approval.directory().clone();
    let handle = RAFT.get().ok_or("actual durable Raft is not ready")?;
    // Wait only for a readiness hint on the existing metrics stream; it is
    // NOT authority. No RPC retries and no larger fresh-barrier lease. Reuse
    // the existing commit budget rather than introducing a tunable daemon.
    let mut metrics = handle.raft.metrics();
    tokio::time::timeout(COMMIT_TIMEOUT, async {
        loop {
            let m = metrics.borrow().clone();
            if m.running_state.is_err() {
                return Err("Raft is not running");
            }
            if m.millis_since_quorum_ack.is_some() {
                if m.current_leader == Some(handle.node_id) {
                    return Ok(());
                }
                if m.current_leader.is_some() {
                    return Err("explicit enrollment is on a follower; no forwarding");
                }
            }
            metrics
                .changed()
                .await
                .map_err(|_| "Raft readiness stream closed")?;
        }
    })
    .await
    .map_err(|_| "enrollment readiness UNKNOWN; one attempt only")??;
    let local = node_identity::observe_async(&approved, handle.node_id).await?;
    let before = storage_remote_core::observe_enrollment().await?;
    local.require_current(&approved, handle.node_id)?;
    if before.cluster_id != approved.cluster_id || before.voters != approved.voters() {
        return Err("approved directory is not this exact current Raft voter set".into());
    }
    if let Some(existing) = before.registry.directory() {
        if existing != &approved {
            return Err(
                "directory already installed; rotation/re-enrollment is unsupported".into(),
            );
        }
        // This is a fresh confirmation of existing history, NOT re-enrollment.
        return Ok(());
    }
    let proposal = EnrollmentProposal {
        version: 1,
        command_uid: crate::storage_identity::Uid::new(),
        directory: approved.clone(),
        base_generation: before.generation,
        term: before.term,
        leader: before.leader,
        membership_sha256: before.membership_sha256,
    };
    let sealed = proposal.seal()?;
    // No changed lease or voter fallback. A timeout is an UNKNOWN result; the
    // caller performs no repeat, deletion, reenrollment or physical action.
    let reply = tokio::time::timeout(
        Duration::from_millis(storage_remote_core::MAX_STORAGE_BOUNDARY_MS),
        handle.raft.client_write(Command::EnrollStorageDirectory {
            base_generation: before.generation,
            proposal: sealed,
        }),
    )
    .await
    .map_err(|_| "directory commit deadline UNKNOWN; no automatic repeat")?
    .map_err(|_| "directory quorum commit UNKNOWN/refused; no fallback")?;
    if !reply.data.applied {
        return Err(format!("directory CAS refused: {}", reply.data.message));
    }
    let after = storage_remote_core::observe_enrollment().await?;
    if after.registry.directory() != Some(&approved) || after.voters != approved.voters() {
        return Err("directory changed before fresh post-commit confirmation".into());
    }
    // Refresh kernel/file observation after the potentially slow commit rather
    // than reusing the original local attestation past its one-second age.
    node_identity::observe_async(&approved, handle.node_id)
        .await?
        .require_current(&approved, handle.node_id)?;
    Ok(())
}

pub(super) fn apply_enrollment(
    store: &NeuroStore,
    base: u64,
    sealed: &str,
    log: LogId<NeuroNodeId>,
    membership: &StoredMembership<NeuroNodeId, BasicNode>,
) -> Result<NeuroResponse, String> {
    let mut world = store.world.write().unwrap_or_else(|e| e.into_inner());
    let result = (|| -> Result<Option<DesiredState>, String> {
        if store.sealing != Sealing::Cluster || store.dir.is_none() {
            return Err(
                "production directory enrollment requires actual durable sealed Raft".into(),
            );
        }
        let proposal = EnrollmentProposal::open(sealed)?;
        if proposal.base_generation != base
            || membership.membership().is_in_joint_consensus()
            || proposal.directory.voters()
                != membership.membership().voter_ids().collect::<Vec<_>>()
            || proposal.membership_sha256
                != data::digest(
                    &serde_json::to_vec(membership).map_err(|_| "invalid actual membership")?,
                )
            || proposal.directory.cluster_id != world.cluster_id
            || crate::auth::derived_cluster_id().as_deref() != Some(world.cluster_id.as_str())
        {
            return Err("enrollment command does not bind actual cluster/voters/membership".into());
        }
        let next_registry = Registry::from_entry(&proposal, log)?;
        if world.storage_node_directory.has_authority() {
            world
                .storage_node_directory
                .require_unchanged(&next_registry)?;
            let guard = store
                .storage_directory_history
                .lock()
                .map_err(|_| "history poisoned")?;
            next_registry.require_guard(guard.as_ref())?;
            return Ok(None);
        }
        if world.generation != base {
            return Err("directory enrollment CAS generation conflict".into());
        }
        let mut next = world.to_state();
        data::require_unstarted(&next)?;
        next.storage_node_directory = next_registry.clone();
        next.generation = base.checked_add(1).ok_or("generation exhausted")?;
        next.storage_node_directory.validate_state(&next)?;
        Ok(Some(next))
    })();
    let next = match result {
        Err(message) => {
            return Ok(NeuroResponse {
                applied: false,
                generation: world.generation,
                message,
            })
        }
        Ok(None) => {
            return Ok(NeuroResponse {
                applied: true,
                generation: world.generation,
                message: "same actual enrollment entry already installed".into(),
            })
        }
        Ok(Some(next)) => next,
    };
    // Guard IO failure is fatal storage apply, NOT an applied:false response:
    // Raft must stop rather than advance last_applied past missing local state.
    node_identity::persist_guard(store.dir.as_ref().unwrap(), &next.storage_node_directory)?;
    *store
        .storage_directory_history
        .lock()
        .map_err(|_| "history poisoned")? = Some(next.storage_node_directory.clone());
    let generation = next.generation;
    world.install_state(next);
    Ok(NeuroResponse {
        applied: true,
        generation,
        message: "exact approved node directory installed".into(),
    })
}

pub(super) fn validate_ordinary(
    store: &NeuroStore,
    registry: &Registry,
    at: u64,
) -> Result<(), String> {
    let guard = store
        .storage_directory_history
        .lock()
        .map_err(|_| "history poisoned")?;
    if registry.has_authority() {
        return registry.require_guard(guard.as_ref());
    }
    if guard
        .as_ref()
        .and_then(Registry::history)
        .is_some_and(|h| at >= h.applied_index)
    {
        return Err("ordinary Commit cannot pass or erase unresolved enrollment history".into());
    }
    Ok(())
}
pub(super) fn validate_startup(
    store: &NeuroStore,
    snapshot: Option<&SnapshotFile>,
) -> Result<(), String> {
    let guard = store
        .storage_directory_history
        .lock()
        .map_err(|_| "history poisoned")?
        .clone();
    let state = snapshot
        .map(|s| store.sealing.unseal(&s.state))
        .transpose()?;
    if let Some(registry) = state
        .as_ref()
        .map(|s| &s.storage_node_directory)
        .filter(|r| r.has_authority())
    {
        registry.require_guard(guard.as_ref())?;
        let snap = snapshot.ok_or("directory snapshot absent")?;
        require_snapshot_index(registry, &snap.meta)?;
        return Ok(());
    }
    if let Some(guard) = guard {
        // Ordinary crash gap: the old snapshot may precede the already-applied
        // enrollment, but the exact enrollment log must remain to replay. No
        // guard is recreated from snapshot/JSON and no issuer is enabled yet.
        let history = guard
            .history()
            .ok_or("guard has no actual enrollment entry")?;
        if snapshot
            .and_then(|s| s.meta.last_log_id)
            .is_some_and(|id| id.index >= history.applied_index)
        {
            return Err("snapshot discarded committed enrollment history".into());
        }
        let log = store.log.try_read().map_err(|_| "startup log busy")?;
        let entry = log
            .get(&history.applied_index)
            .ok_or("exact enrollment log missing; explicit recovery, never re-enroll UID")?;
        let EntryPayload::Normal(Command::EnrollStorageDirectory {
            base_generation,
            proposal,
        }) = &entry.payload
        else {
            return Err("guard points to a non-enrollment log".into());
        };
        let p = EnrollmentProposal::open(proposal)?;
        if p.base_generation != *base_generation || Registry::from_entry(&p, entry.log_id)? != guard
        {
            return Err("guard and retained enrollment log differ".into());
        }
    }
    Ok(())
}
fn require_snapshot_index(
    registry: &Registry,
    meta: &SnapshotMeta<NeuroNodeId, BasicNode>,
) -> Result<(), String> {
    let history = registry.history().ok_or("missing enrolled history")?;
    if meta
        .last_log_id
        .is_none_or(|id| id.index < history.applied_index)
    {
        return Err("snapshot cannot precede or discard its original enrollment history".into());
    }
    // The immutable registry/guard still match their ORIGINAL membership.
    // General Raft may have moved on; Core refuses storage grants on that
    // drift, while snapshot/startup continue without Fatal::StorageError.
    Ok(())
}
/// Caller holds sm -> world through validation, fsync and install, so a new
/// enrollment cannot race an older snapshot into discarding its state.
pub(super) fn validate_live_snapshot(
    store: &NeuroStore,
    current: &Registry,
    state: &DesiredState,
    meta: &SnapshotMeta<NeuroNodeId, BasicNode>,
) -> Result<(), String> {
    let guard = store
        .storage_directory_history
        .lock()
        .map_err(|_| "history poisoned")?
        .clone();
    if state.storage_node_directory.has_authority() {
        state.storage_node_directory.require_guard(guard.as_ref())?;
        require_snapshot_index(&state.storage_node_directory, meta)?;
    } else if guard.is_some() {
        return Err("snapshot cannot remove enrolled or unresolved directory history".into());
    }
    if current.has_authority() {
        current.require_unchanged(&state.storage_node_directory)?;
    }
    Ok(())
}
