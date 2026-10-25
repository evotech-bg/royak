//! The replicated command.
//!
//! In cluster mode every authoritative change to desired state — API apply,
//! PATCH, scale, delete, and the reconcile loop's own bookkeeping (HPA scale,
//! CronJob runs, rollout progress) — is computed on a copy of the state by
//! [`crate::store::commit`] and replicated as ONE command: the complete next
//! state plus the generation it was computed from. The state machine applies
//! it only if its current generation still equals that base (compare-and-
//! swap), so two writers racing on different nodes can never both win, and a
//! replayed or duplicated entry is a no-op instead of a double apply.
//!
//! Replicating whole states (not per-resource deltas) keeps the state machine
//! trivially deterministic: there is exactly one apply path, the same one the
//! single-node file backend uses. The cost is entry size, bounded by the
//! desired state (not the pods), and kept in check by snapshots + log purge.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Command {
    /// Replace desired state with `state` iff the state machine is at
    /// `base_generation`. `state` is the serialized [`crate::store::DesiredState`],
    /// sealed (AES-256-GCM) with a key derived from the cluster secret.
    Commit { base_generation: u64, state: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_roundtrips_through_json() {
        let cmd = Command::Commit { base_generation: 41, state: "opaque".into() };
        let s = serde_json::to_string(&cmd).expect("encode");
        let back: Command = serde_json::from_str(&s).expect("decode");
        assert_eq!(back, cmd);
    }
}
