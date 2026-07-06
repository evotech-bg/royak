#![allow(dead_code)]
//! Consensus — scaffolding for v0.4 multi-master HA.
//!
//! See ROADMAP.md §v0.4 "Real HA with consensus" for the full design.
//!
//! v0.2 shipped a file-based leader lease that provides a single-writer
//! guarantee on shared state (same host or shared FS). That is NOT a
//! Raft/Paxos replacement — it cannot tolerate a network partition
//! between hosts with independent storage.
//!
//! This module is the scaffolding that v0.4 will fill in. Today it:
//!
//!   1. Defines `Command` — the finite set of state-machine inputs that
//!      must be replicated. Every mutation the reconcile loop performs
//!      today maps to one of these.
//!   2. Defines `ConsensusBackend` — the trait the reconcile loop will
//!      call to propose a command. v0.3 wires a no-op backend that
//!      executes commands locally (matches current behaviour). v0.4
//!      swaps in an openraft-backed backend.
//!   3. Documents the crate-evaluation outcome so nobody has to re-do it.
//!
//! Keeping the scaffolding here means the reconcile call-sites that
//! mutate world state can already migrate to `backend.propose(cmd)` —
//! when Raft lands there is no surface-area change, just a backend swap.

use serde::{Deserialize, Serialize};

/// One atomic change to cluster state. Must serialize — Raft replicates
/// the byte form of this across followers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Command {
    /// Apply a parsed resource (from YAML/JSON POST). The body is the
    /// canonical JSON because we don't want to replicate the original
    /// text (comments, whitespace).
    Apply { kind: String, name: String, namespace: String, spec_json: String },
    /// Scale a deployment.
    Scale { name: String, namespace: String, replicas: u32 },
    /// Delete a resource.
    Delete { kind: String, name: String, namespace: String },
    /// Record a node heartbeat (lightweight; may or may not go through
    /// Raft in v0.4 — heartbeats are high-frequency and noisy for a log).
    Heartbeat { node: String, cpu_used: f32, mem_used: f32, pod_count: u32 },
}

/// Result of proposing a command. In single-writer mode this is always
/// immediate; with Raft it blocks until the entry is committed to a
/// quorum of the cluster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposeOutcome {
    pub committed: bool,
    pub message: String,
    /// Raft log index (post-v0.4). None in single-writer.
    pub index: Option<u64>,
}

/// Backend the reconcile loop calls to persist a state change.
///
/// Two implementations:
///
/// * **`LocalBackend`** (v0.2/v0.3) — executes commands in-process, no
///   replication. Exists so the reconcile loop can be written against a
///   stable interface today without waiting for Raft.
/// * **`RaftBackend`** (v0.4, not yet implemented) — uses openraft to
///   propose each command as a log entry and only returns after quorum
///   commit. On a follower, `propose` returns an error pointing the
///   caller at the leader.
pub trait ConsensusBackend: Send + Sync {
    /// Propose a state change. Blocks until locally persisted (local
    /// backend) or quorum-committed (raft backend).
    fn propose(&self, cmd: Command) -> ProposeOutcome;

    /// Is this node currently the leader? Followers should avoid
    /// initiating user-facing commands (API writes); they may still
    /// accept and forward them transparently.
    fn is_leader(&self) -> bool;

    /// Human-readable backend description (for `/version` and diagnostics).
    fn describe(&self) -> &'static str;
}

/// v0.2/v0.3 backend. Reports leadership via the existing file lease,
/// applies commands directly. Provided so call-sites can already use the
/// trait; the v0.4 swap flips the backend, not the call-sites.
pub struct LocalBackend {
    pub node_id: String,
}

impl LocalBackend {
    pub fn new(node_id: String) -> Self {
        Self { node_id }
    }
}

impl ConsensusBackend for LocalBackend {
    fn propose(&self, cmd: Command) -> ProposeOutcome {
        // The real apply/scale/delete logic lives in DesiredWorld methods.
        // This backend is not wired up to them yet; it's a record that
        // the command was accepted locally. v0.3 will pipe these through
        // to the reconcile loop's existing mutation path.
        ProposeOutcome {
            committed: true,
            message: format!("local:{cmd:?}"),
            index: None,
        }
    }

    fn is_leader(&self) -> bool {
        // v0.2/v0.3: leadership is answered by the file lease in
        // reconcile::try_acquire_lease. This backend is agnostic; the
        // reconcile loop consults the lease directly today.
        true
    }

    fn describe(&self) -> &'static str {
        "local-single-writer (file-based leader lease; see ROADMAP.md §v0.4 for quorum)"
    }
}

/// Placeholder for the v0.4 Raft backend. Constructing it returns an
/// error today — exists so IDE autocomplete and call-site planning can
/// reference the future API.
///
/// v0.4 Phase 1 lands in `crate::raft_node`: `RaftLocalBackend` is a
/// working single-node openraft node that accepts Commands, appends to a
/// log, and applies to `DesiredWorld`. Phase 2 (HTTP network transport)
/// and Phase 3 (reconcile-loop wiring) live on the roadmap.
pub struct RaftBackend;

impl RaftBackend {
    /// Planned multi-node constructor. For Phase 1, call
    /// `raft_node::build_single_node` instead.
    pub fn new_stub(peers: &[String]) -> Result<Self, String> {
        Err(format!(
            "consensus::RaftBackend multi-node lands in v0.4 Phase 2. \
             Peer count that would have been used: {}. Phase 1 (single-node) \
             is in raft_node::build_single_node.",
            peers.len()
        ))
    }
}

// ─── Crate evaluation (openraft vs async-raft) ──────────────────────────
//
// | Criterion              | openraft              | async-raft          |
// |------------------------|-----------------------|---------------------|
// | Actively maintained    | yes (Databend)        | no (forked)         |
// | Tokio native           | yes                   | yes                 |
// | Log compaction         | built-in              | manual              |
// | Snapshots              | yes                   | limited             |
// | Membership changes     | joint consensus       | simpler             |
// | Production users       | Databend, others      | fewer               |
// | Binary size impact     | ~80 KB release        | ~40 KB release      |
// | API ergonomics         | heavier, generic      | lighter, opinionated|
//
// Decision: openraft. Active maintenance + production usage are worth
// the heavier API. The ~80 KB overhead fits inside our <10 MB binary
// budget; current release is ~5.1 MB.
//
// Integration sketch (for v0.4 implementer):
//
//   use openraft::{Config, Raft};
//
//   struct RoyakApp { world: Arc<RwLock<DesiredWorld>> }
//
//   impl RaftStateMachine<Command, ...> for RoyakApp {
//       async fn apply(&mut self, cmd: Command) -> Result<Response, E> {
//           let mut w = self.world.write().unwrap();
//           match cmd {
//               Command::Apply {..}  => w.apply(resource_from(cmd))?,
//               Command::Scale {..}  => w.scale(name, ns, replicas)?,
//               Command::Delete {..} => w.delete_resource(kind, name),
//               Command::Heartbeat {..} => w.heartbeat(node, ...),
//           }
//       }
//   }
//
//   impl RaftStorage for RoyakStore { /* backed by state.json.nrns */ }
//   impl RaftNetwork for HttpTransport   { /* reuses /royak/v1/raft/* */ }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_roundtrips_through_json() {
        // Raft replicates serialized commands — every variant must survive
        // JSON roundtrip without data loss.
        let cases = vec![
            Command::Apply {
                kind: "ConfigMap".into(),
                name: "app".into(),
                namespace: "default".into(),
                spec_json: r#"{"KEY":"v"}"#.into(),
            },
            Command::Scale { name: "web".into(), namespace: "default".into(), replicas: 3 },
            Command::Delete { kind: "Deployment".into(), name: "web".into(), namespace: "default".into() },
            Command::Heartbeat { node: "host-a".into(), cpu_used: 0.5, mem_used: 128.0, pod_count: 2 },
        ];
        for cmd in cases {
            let s = serde_json::to_string(&cmd).expect("encode");
            let back: Command = serde_json::from_str(&s).expect("decode");
            assert_eq!(back, cmd, "mismatch after roundtrip");
        }
    }

    #[test]
    fn local_backend_accepts_and_reports_leader() {
        let b = LocalBackend::new("host-a".into());
        assert!(b.is_leader());
        let r = b.propose(Command::Scale {
            name: "web".into(),
            namespace: "default".into(),
            replicas: 4,
        });
        assert!(r.committed);
        assert!(r.index.is_none(), "local backend has no raft index");
    }

    #[test]
    fn local_backend_describe_mentions_v0_4_plan() {
        let b = LocalBackend::new("host-a".into());
        let desc = b.describe();
        assert!(desc.contains("ROADMAP") || desc.contains("v0.4"),
            "backend description should point readers at the roadmap: {desc}");
    }

    #[test]
    fn raft_backend_stub_points_at_phase2_and_phase1_impl() {
        // Multi-node backend lands in Phase 2; Phase 1 single-node is in
        // raft_node. The stub error must point both directions.
        let peers = vec!["10.0.0.2:6443".to_string(), "10.0.0.3:6443".to_string()];
        match RaftBackend::new_stub(&peers) {
            Err(msg) => {
                assert!(msg.contains("Phase 2") || msg.contains("v0.4"),
                    "stub should name the next phase: {msg}");
                assert!(msg.contains("raft_node") || msg.contains("Phase 1"),
                    "stub should point callers at the Phase 1 single-node impl: {msg}");
            }
            Ok(_) => panic!("multi-node Raft backend is a stub; must not succeed yet"),
        }
    }
}
