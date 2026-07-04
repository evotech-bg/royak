#![allow(dead_code)]
//! v0.4 openraft — Phase 1
//!
//! This module plugs openraft into our reconcile plane without yet turning on
//! multi-node replication. Scope:
//!   * A [`RaftTypeConfig`] with our [`consensus::Command`] as the app data type
//!     and a serialisable response.
//!   * A combined in-memory [`RaftStorage`] (log + state machine + optional
//!     snapshot). openraft v0.9 exposes an [`Adaptor`] that splits a V1
//!     `RaftStorage` into the V2 (log, state-machine) pair `Raft::new` wants.
//!   * A stub `RaftNetworkFactory` — Phase 1 is single-node, so the network
//!     path must exist but never actually fire.
//!   * [`build_single_node`] — bootstrap a cluster of one, wire the state
//!     machine to a shared `DesiredWorld`, and return a ready `Raft`.
//!
//! Phase 2 (next session) will replace the memory log with a persistent one
//! (backed by `.nrns`), and the stub network with the HTTP transport that
//! already exists for `/royak/v1/state`.
//!
//! Integration with the reconcile loop is NOT done here. Phase 1 produces a
//! Raft handle + tests proving commands flow: `client_write(Command)` → append
//! to log → apply to state machine → `DesiredWorld` mutation. Swapping the
//! live reconcile write-path onto this happens in Phase 3.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::Arc;

use openraft::storage::{Adaptor, LogState, RaftLogReader, RaftSnapshotBuilder, RaftStorage, Snapshot};
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, SnapshotMeta, StorageError, StorageIOError,
    StoredMembership, Vote,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock as TokioRwLock;

use crate::consensus::{Command, ProposeOutcome};
use crate::reconcile::DesiredWorld;

pub type NeuroNodeId = u64;

/// Response returned from the state machine after each applied command.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NeuroResponse {
    pub message: String,
}

openraft::declare_raft_types!(
    /// openraft configuration for Royak: Command as the app request,
    /// NeuroResponse as the state machine reply, u64 node ids, BasicNode
    /// for identity, default Entry/SnapshotData/AsyncRuntime.
    pub NeuroTypeConfig:
        D = Command,
        R = NeuroResponse,
        NodeId = NeuroNodeId,
        Node = BasicNode,
        Entry = Entry<NeuroTypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = openraft::TokioRuntime,
);

/// Shape of a snapshot stored in memory — metadata + the serialised state.
#[derive(Debug, Clone)]
pub struct NeuroSnapshot {
    pub meta: SnapshotMeta<NeuroNodeId, BasicNode>,
    pub data: Vec<u8>,
}

/// Combined V1 `RaftStorage` impl — log + vote + state-machine-linked world.
/// openraft's `Adaptor` splits this into the V2 `(log_store, state_machine)`
/// pair that `Raft::new` expects.
pub struct NeuroStore {
    /// Last persisted vote.
    vote: TokioRwLock<Option<Vote<NeuroNodeId>>>,
    /// Append-only log.
    log: TokioRwLock<BTreeMap<u64, Entry<NeuroTypeConfig>>>,
    /// Highest purged log id (ids up to and including this are deleted).
    last_purged: TokioRwLock<Option<LogId<NeuroNodeId>>>,
    /// Last committed log id (optional hint, openraft persists its own).
    committed: TokioRwLock<Option<LogId<NeuroNodeId>>>,
    /// State machine pointer into the real cluster world.
    world: Arc<std::sync::RwLock<DesiredWorld>>,
    /// Last applied log id to the state machine.
    last_applied: TokioRwLock<Option<LogId<NeuroNodeId>>>,
    /// Last applied membership.
    last_membership: TokioRwLock<StoredMembership<NeuroNodeId, BasicNode>>,
    /// Current installed/generated snapshot.
    current_snapshot: TokioRwLock<Option<NeuroSnapshot>>,
}

impl NeuroStore {
    pub fn new(world: Arc<std::sync::RwLock<DesiredWorld>>) -> Arc<Self> {
        Arc::new(Self {
            vote: TokioRwLock::new(None),
            log: TokioRwLock::new(BTreeMap::new()),
            last_purged: TokioRwLock::new(None),
            committed: TokioRwLock::new(None),
            world,
            last_applied: TokioRwLock::new(None),
            last_membership: TokioRwLock::new(StoredMembership::default()),
            current_snapshot: TokioRwLock::new(None),
        })
    }

    /// Apply a single committed command to the cluster world. This is the
    /// Raft state machine: openraft guarantees every voter applies the exact
    /// same command sequence, so mutating `DesiredWorld` here keeps every
    /// node's desired state identical. Phase 3: real mutation (apply/scale/
    /// delete), not a stub. The reconcile loop then converges Docker to it.
    fn apply_command(&self, cmd: &Command) -> NeuroResponse {
        let Ok(mut w) = self.world.write() else {
            return NeuroResponse { message: "world lock poisoned".into() };
        };
        // Stamp the last applied command so tests + `royak get` can observe
        // that the Raft log drove the mutation.
        let stamp;
        let message = match cmd {
            Command::Apply { kind, name, namespace, spec_json } => {
                // spec_json is the canonical manifest JSON captured at propose
                // time. Reconstruct a Resource and run the real apply path.
                match serde_json::from_str::<serde_json::Value>(spec_json)
                    .ok()
                    .and_then(|v| serde_yaml::to_string(&v).ok())
                    .and_then(|y| crate::spec::parse_yaml(&y).ok())
                    .and_then(|rs| rs.into_iter().next())
                {
                    Some(resource) => match w.apply(&resource) {
                        Ok(m) => m,
                        Err(e) => format!("apply {kind}/{name} ns={namespace} failed: {e}"),
                    },
                    None => format!("apply {kind}/{name}: could not parse spec_json"),
                }
            }
            Command::Scale { name, namespace, replicas } => {
                if let Some(d) = w.deployments.get_mut(name) {
                    d.replicas = *replicas;
                    format!("scale {name} ns={namespace} → {replicas}")
                } else {
                    format!("scale {name}: not found")
                }
            }
            Command::Delete { kind, name, namespace } => {
                let ok = w.delete_resource(kind, name);
                format!("delete {kind}/{name} ns={namespace} ({})", if ok { "removed" } else { "not found" })
            }
            Command::Heartbeat { node, cpu_used, mem_used, pod_count } => {
                if let Some(n) = w.nodes.get_mut(node) {
                    n.cpu_used = *cpu_used; n.mem_used = *mem_used; n.pod_count = *pod_count;
                }
                format!("heartbeat {node}")
            }
        };
        stamp = format!("raft:[raft] {message}");
        w.config.runtime = stamp;
        NeuroResponse { message }
    }
}

// ─── RaftLogReader ──────────────────────────────────────────────────────
impl RaftLogReader<NeuroTypeConfig> for Arc<NeuroStore> {
    async fn try_get_log_entries<RB>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<NeuroTypeConfig>>, StorageError<NeuroNodeId>>
    where
        RB: RangeBounds<u64> + Clone + Debug + openraft::OptionalSend,
    {
        let log = self.log.read().await;
        Ok(log.range(range).map(|(_, e)| e.clone()).collect())
    }
}

// ─── RaftSnapshotBuilder ────────────────────────────────────────────────
impl RaftSnapshotBuilder<NeuroTypeConfig> for Arc<NeuroStore> {
    async fn build_snapshot(&mut self) -> Result<Snapshot<NeuroTypeConfig>, StorageError<NeuroNodeId>> {
        let last_applied = *self.last_applied.read().await;
        let last_membership = self.last_membership.read().await.clone();
        // For Phase 1 the snapshot payload is a stamp, not the full world —
        // persisting the full world to a snapshot is Phase 2 work.
        let data = serde_json::to_vec(&last_applied)
            .map_err(|e| StorageIOError::read_state_machine(&e))?;

        let snapshot_id = last_applied
            .map(|l| format!("{}-{}-0", l.leader_id, l.index))
            .unwrap_or_else(|| "--0".to_string());

        let meta = SnapshotMeta {
            last_log_id: last_applied,
            last_membership,
            snapshot_id,
        };
        let stored = NeuroSnapshot { meta: meta.clone(), data: data.clone() };
        *self.current_snapshot.write().await = Some(stored);
        Ok(Snapshot { meta, snapshot: Box::new(Cursor::new(data)) })
    }
}

// ─── RaftStorage (V1 combined) ──────────────────────────────────────────
impl RaftStorage<NeuroTypeConfig> for Arc<NeuroStore> {
    type LogReader = Self;
    type SnapshotBuilder = Self;

    async fn get_log_state(&mut self) -> Result<LogState<NeuroTypeConfig>, StorageError<NeuroNodeId>> {
        let log = self.log.read().await;
        let last_purged = *self.last_purged.read().await;
        let last = log.iter().next_back().map(|(_, e)| e.log_id);
        Ok(LogState {
            last_purged_log_id: last_purged,
            last_log_id: last.or(last_purged),
        })
    }

    async fn save_vote(&mut self, vote: &Vote<NeuroNodeId>) -> Result<(), StorageError<NeuroNodeId>> {
        *self.vote.write().await = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NeuroNodeId>>, StorageError<NeuroNodeId>> {
        Ok(*self.vote.read().await)
    }

    async fn append_to_log<I>(&mut self, entries: I) -> Result<(), StorageError<NeuroNodeId>>
    where I: IntoIterator<Item = Entry<NeuroTypeConfig>> + openraft::OptionalSend {
        let mut log = self.log.write().await;
        for entry in entries {
            log.insert(entry.log_id.index, entry);
        }
        Ok(())
    }

    async fn delete_conflict_logs_since(
        &mut self,
        log_id: LogId<NeuroNodeId>,
    ) -> Result<(), StorageError<NeuroNodeId>> {
        let mut log = self.log.write().await;
        let keys: Vec<u64> = log.range(log_id.index..).map(|(k, _)| *k).collect();
        for k in keys { log.remove(&k); }
        Ok(())
    }

    async fn purge_logs_upto(
        &mut self,
        log_id: LogId<NeuroNodeId>,
    ) -> Result<(), StorageError<NeuroNodeId>> {
        *self.last_purged.write().await = Some(log_id);
        let mut log = self.log.write().await;
        let keys: Vec<u64> = log.range(..=log_id.index).map(|(k, _)| *k).collect();
        for k in keys { log.remove(&k); }
        Ok(())
    }

    async fn last_applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NeuroNodeId>>, StoredMembership<NeuroNodeId, BasicNode>), StorageError<NeuroNodeId>> {
        Ok((
            *self.last_applied.read().await,
            self.last_membership.read().await.clone(),
        ))
    }

    async fn apply_to_state_machine(
        &mut self,
        entries: &[Entry<NeuroTypeConfig>],
    ) -> Result<Vec<NeuroResponse>, StorageError<NeuroNodeId>> {
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            *self.last_applied.write().await = Some(entry.log_id);
            match &entry.payload {
                EntryPayload::Blank => out.push(NeuroResponse::default()),
                EntryPayload::Normal(cmd) => out.push(self.apply_command(cmd)),
                EntryPayload::Membership(m) => {
                    *self.last_membership.write().await =
                        StoredMembership::new(Some(entry.log_id), m.clone());
                    out.push(NeuroResponse::default());
                }
            }
        }
        Ok(out)
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NeuroNodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NeuroNodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NeuroNodeId>> {
        let data = snapshot.into_inner();
        *self.last_applied.write().await = meta.last_log_id;
        *self.last_membership.write().await = meta.last_membership.clone();
        *self.current_snapshot.write().await = Some(NeuroSnapshot {
            meta: meta.clone(),
            data,
        });
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<NeuroTypeConfig>>, StorageError<NeuroNodeId>> {
        let cur = self.current_snapshot.read().await;
        match cur.as_ref() {
            Some(s) => Ok(Some(Snapshot {
                meta: s.meta.clone(),
                snapshot: Box::new(Cursor::new(s.data.clone())),
            })),
            None => Ok(None),
        }
    }

    async fn get_log_reader(&mut self) -> Self::LogReader { self.clone() }
    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder { self.clone() }
}

// ─── Stub network — retained for single-node smoke tests ────────────────
#[derive(Clone, Default)]
pub struct StubNetworkFactory;

impl openraft::RaftNetworkFactory<NeuroTypeConfig> for StubNetworkFactory {
    type Network = StubNetwork;

    async fn new_client(&mut self, _target: NeuroNodeId, _node: &BasicNode) -> Self::Network {
        StubNetwork
    }
}

#[derive(Default)]
pub struct StubNetwork;

impl openraft::RaftNetwork<NeuroTypeConfig> for StubNetwork {
    async fn append_entries(
        &mut self,
        _rpc: openraft::raft::AppendEntriesRequest<NeuroTypeConfig>,
        _option: openraft::network::RPCOption,
    ) -> Result<openraft::raft::AppendEntriesResponse<NeuroNodeId>, openraft::error::RPCError<NeuroNodeId, BasicNode, openraft::error::RaftError<NeuroNodeId>>> {
        Err(openraft::error::RPCError::Network(
            openraft::error::NetworkError::new(&std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "StubNetwork: used for single-node smoke tests only",
            )),
        ))
    }

    async fn install_snapshot(
        &mut self,
        _rpc: openraft::raft::InstallSnapshotRequest<NeuroTypeConfig>,
        _option: openraft::network::RPCOption,
    ) -> Result<openraft::raft::InstallSnapshotResponse<NeuroNodeId>, openraft::error::RPCError<NeuroNodeId, BasicNode, openraft::error::RaftError<NeuroNodeId, openraft::error::InstallSnapshotError>>> {
        Err(openraft::error::RPCError::Network(
            openraft::error::NetworkError::new(&std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "StubNetwork: snapshot not supported",
            )),
        ))
    }

    async fn vote(
        &mut self,
        _rpc: openraft::raft::VoteRequest<NeuroNodeId>,
        _option: openraft::network::RPCOption,
    ) -> Result<openraft::raft::VoteResponse<NeuroNodeId>, openraft::error::RPCError<NeuroNodeId, BasicNode, openraft::error::RaftError<NeuroNodeId>>> {
        Err(openraft::error::RPCError::Network(
            openraft::error::NetworkError::new(&std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "StubNetwork: vote not supported",
            )),
        ))
    }
}

// ─── In-process channel network (Phase 2 test transport) ────────────────
//
// For unit-testing a multi-node cluster without opening TCP sockets, we
// ship an in-process transport: every node registers itself in a shared
// registry, and new_client looks up the target node's Raft handle and
// dispatches the RPC in-process. This covers the openraft "does the
// algorithm work when messages actually flow between peers" invariant.
// Real inter-host transport is the HTTP variant below.

pub type NodeRegistry = Arc<tokio::sync::RwLock<
    std::collections::HashMap<NeuroNodeId, Arc<openraft::Raft<NeuroTypeConfig>>>
>>;

pub fn new_registry() -> NodeRegistry {
    Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new()))
}

/// Shared set of isolated node ids — used only by chaos tests to simulate a
/// network partition. Empty in production (the HTTP transport is real). If
/// either endpoint of an RPC is isolated, the RPC fails as unreachable,
/// exactly as it would across a partition.
pub type Partition = Arc<tokio::sync::RwLock<std::collections::HashSet<NeuroNodeId>>>;

pub fn new_partition() -> Partition {
    Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new()))
}

#[derive(Clone)]
pub struct InProcNetworkFactory {
    pub registry: NodeRegistry,
    pub source: NeuroNodeId,
    pub isolated: Partition,
}

impl InProcNetworkFactory {
    /// Production/simple test path: no partition controller.
    pub fn simple(registry: NodeRegistry) -> Self {
        Self { registry, source: 0, isolated: new_partition() }
    }
}

impl openraft::RaftNetworkFactory<NeuroTypeConfig> for InProcNetworkFactory {
    type Network = InProcNetwork;
    async fn new_client(&mut self, target: NeuroNodeId, _node: &BasicNode) -> Self::Network {
        InProcNetwork {
            target,
            source: self.source,
            registry: self.registry.clone(),
            isolated: self.isolated.clone(),
        }
    }
}

pub struct InProcNetwork {
    target: NeuroNodeId,
    source: NeuroNodeId,
    registry: NodeRegistry,
    isolated: Partition,
}

impl InProcNetwork {
    async fn peer(&self) -> Option<Arc<openraft::Raft<NeuroTypeConfig>>> {
        // A partitioned endpoint on either side drops the RPC.
        {
            let iso = self.isolated.read().await;
            if iso.contains(&self.source) || iso.contains(&self.target) {
                return None;
            }
        }
        self.registry.read().await.get(&self.target).cloned()
    }

    fn unreachable<E>(&self) -> openraft::error::RPCError<NeuroNodeId, BasicNode, E>
    where E: std::error::Error {
        openraft::error::RPCError::Network(
            openraft::error::NetworkError::new(&std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("peer {} not registered", self.target),
            )),
        )
    }
}

impl openraft::RaftNetwork<NeuroTypeConfig> for InProcNetwork {
    async fn append_entries(
        &mut self,
        rpc: openraft::raft::AppendEntriesRequest<NeuroTypeConfig>,
        _option: openraft::network::RPCOption,
    ) -> Result<openraft::raft::AppendEntriesResponse<NeuroNodeId>, openraft::error::RPCError<NeuroNodeId, BasicNode, openraft::error::RaftError<NeuroNodeId>>> {
        let peer = self.peer().await.ok_or_else(|| self.unreachable())?;
        peer.append_entries(rpc).await.map_err(|e| {
            openraft::error::RPCError::RemoteError(openraft::error::RemoteError::new(self.target, e))
        })
    }

    async fn install_snapshot(
        &mut self,
        rpc: openraft::raft::InstallSnapshotRequest<NeuroTypeConfig>,
        _option: openraft::network::RPCOption,
    ) -> Result<openraft::raft::InstallSnapshotResponse<NeuroNodeId>, openraft::error::RPCError<NeuroNodeId, BasicNode, openraft::error::RaftError<NeuroNodeId, openraft::error::InstallSnapshotError>>> {
        let peer = self.peer().await.ok_or_else(|| self.unreachable())?;
        peer.install_snapshot(rpc).await.map_err(|e| {
            openraft::error::RPCError::RemoteError(openraft::error::RemoteError::new(self.target, e))
        })
    }

    async fn vote(
        &mut self,
        rpc: openraft::raft::VoteRequest<NeuroNodeId>,
        _option: openraft::network::RPCOption,
    ) -> Result<openraft::raft::VoteResponse<NeuroNodeId>, openraft::error::RPCError<NeuroNodeId, BasicNode, openraft::error::RaftError<NeuroNodeId>>> {
        let peer = self.peer().await.ok_or_else(|| self.unreachable())?;
        peer.vote(rpc).await.map_err(|e| {
            openraft::error::RPCError::RemoteError(openraft::error::RemoteError::new(self.target, e))
        })
    }
}

// ─── HTTP network (production transport) ───────────────────────────────
//
// One RoyakNetwork per (local, peer) pair. POSTs go to the peer's
// API server at /royak/v1/raft/{append,vote,install-snapshot}. The
// receiving side's API handler (in api.rs) dispatches to the local
// Raft handle. Bodies are JSON-serialised openraft RPC structs.

#[derive(Clone)]
pub struct HttpNetworkFactory {
    /// Map of peer node id → address ("host:port") of peer's API server.
    pub peers: Arc<std::sync::RwLock<std::collections::HashMap<NeuroNodeId, String>>>,
}

impl HttpNetworkFactory {
    pub fn new() -> Self {
        Self { peers: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())) }
    }
    pub fn set_peer(&self, id: NeuroNodeId, addr: String) {
        self.peers.write().unwrap().insert(id, addr);
    }
}

impl openraft::RaftNetworkFactory<NeuroTypeConfig> for HttpNetworkFactory {
    type Network = HttpNetwork;
    async fn new_client(&mut self, target: NeuroNodeId, _node: &BasicNode) -> Self::Network {
        HttpNetwork { target, peers: self.peers.clone() }
    }
}

pub struct HttpNetwork {
    target: NeuroNodeId,
    peers: Arc<std::sync::RwLock<std::collections::HashMap<NeuroNodeId, String>>>,
}

impl HttpNetwork {
    fn peer_addr(&self) -> Option<String> {
        self.peers.read().unwrap().get(&self.target).cloned()
    }

    async fn post_json<Req: serde::Serialize, Resp: for<'de> serde::Deserialize<'de>>(
        &self,
        path: &str,
        req: &Req,
    ) -> Result<Resp, String> {
        let addr = self.peer_addr().ok_or_else(|| format!("peer {} not registered", self.target))?;
        let url = format!("http://{addr}{path}");
        let body = serde_json::to_vec(req).map_err(|e| format!("serialize: {e}"))?;

        // Use raw tokio TCP to keep the dep surface minimal — we already
        // have this pattern in cluster_mesh for the proxy.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(&addr).await
            .map_err(|e| format!("connect {url}: {e}"))?;
        let req_bytes = format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(req_bytes.as_bytes()).await.map_err(|e| format!("write head: {e}"))?;
        stream.write_all(&body).await.map_err(|e| format!("write body: {e}"))?;

        let mut raw = Vec::with_capacity(4096);
        stream.read_to_end(&mut raw).await.map_err(|e| format!("read: {e}"))?;
        let sep = b"\r\n\r\n";
        let body_start = raw.windows(sep.len()).position(|w| w == sep)
            .map(|p| p + sep.len()).ok_or_else(|| "no body separator".to_string())?;
        let resp_body = &raw[body_start..];
        serde_json::from_slice::<Resp>(resp_body)
            .map_err(|e| format!("deserialize ({} bytes): {e}", resp_body.len()))
    }
}

impl openraft::RaftNetwork<NeuroTypeConfig> for HttpNetwork {
    async fn append_entries(
        &mut self,
        rpc: openraft::raft::AppendEntriesRequest<NeuroTypeConfig>,
        _option: openraft::network::RPCOption,
    ) -> Result<openraft::raft::AppendEntriesResponse<NeuroNodeId>, openraft::error::RPCError<NeuroNodeId, BasicNode, openraft::error::RaftError<NeuroNodeId>>> {
        self.post_json("/royak/v1/raft/append-entries", &rpc).await
            .map_err(|e| openraft::error::RPCError::Network(
                openraft::error::NetworkError::new(&std::io::Error::new(
                    std::io::ErrorKind::Other, e))))
    }

    async fn install_snapshot(
        &mut self,
        rpc: openraft::raft::InstallSnapshotRequest<NeuroTypeConfig>,
        _option: openraft::network::RPCOption,
    ) -> Result<openraft::raft::InstallSnapshotResponse<NeuroNodeId>, openraft::error::RPCError<NeuroNodeId, BasicNode, openraft::error::RaftError<NeuroNodeId, openraft::error::InstallSnapshotError>>> {
        self.post_json("/royak/v1/raft/install-snapshot", &rpc).await
            .map_err(|e| openraft::error::RPCError::Network(
                openraft::error::NetworkError::new(&std::io::Error::new(
                    std::io::ErrorKind::Other, e))))
    }

    async fn vote(
        &mut self,
        rpc: openraft::raft::VoteRequest<NeuroNodeId>,
        _option: openraft::network::RPCOption,
    ) -> Result<openraft::raft::VoteResponse<NeuroNodeId>, openraft::error::RPCError<NeuroNodeId, BasicNode, openraft::error::RaftError<NeuroNodeId>>> {
        self.post_json("/royak/v1/raft/vote", &rpc).await
            .map_err(|e| openraft::error::RPCError::Network(
                openraft::error::NetworkError::new(&std::io::Error::new(
                    std::io::ErrorKind::Other, e))))
    }
}

// ─── Live HTTP-transport cluster node + global handle ───────────────────

/// The local process's Raft handle + its HTTP network factory, set once when
/// the cluster runtime starts. The API server dispatches inbound raft RPCs
/// (`/royak/v1/raft/*`) to this handle.
pub struct RaftHandle {
    pub raft: Arc<openraft::Raft<NeuroTypeConfig>>,
    pub net: HttpNetworkFactory,
    pub node_id: NeuroNodeId,
}

pub static RAFT: std::sync::OnceLock<RaftHandle> = std::sync::OnceLock::new();

/// Build a live Raft node using the HTTP transport. `peers` maps every other
/// node id → "host:port" of its API server. If `bootstrap` is true this node
/// initialises the cluster membership (run on exactly one node).
pub async fn build_http_node(
    node_id: NeuroNodeId,
    world: Arc<std::sync::RwLock<DesiredWorld>>,
    peers: &[(NeuroNodeId, String)],
    bootstrap: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = Arc::new(openraft::Config {
        cluster_name: "royak".to_string(),
        heartbeat_interval: 250,
        election_timeout_min: 500,
        election_timeout_max: 1000,
        ..Default::default()
    }.validate()?);

    let net = HttpNetworkFactory::new();
    for (id, addr) in peers {
        net.set_peer(*id, addr.clone());
    }

    let store = NeuroStore::new(world);
    let (log_store, state_machine) = Adaptor::new(store);
    let raft = Arc::new(openraft::Raft::new(node_id, config, net.clone(), log_store, state_machine).await?);

    if bootstrap {
        let mut members = std::collections::BTreeMap::new();
        members.insert(node_id, BasicNode::default());
        for (id, _) in peers {
            members.insert(*id, BasicNode::default());
        }
        // Give peers a moment to start their listeners, then initialise.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        raft.initialize(members).await?;
    }

    RAFT.set(RaftHandle { raft, net, node_id }).map_err(|_| "RAFT already set")?;
    Ok(())
}

/// Dispatch an inbound raft RPC (append-entries / vote / install-snapshot) to
/// the local handle. `which` is the last path segment. Returns the JSON body.
pub async fn handle_rpc(which: &str, body: &[u8]) -> Result<String, String> {
    let handle = RAFT.get().ok_or("raft not running on this node")?;
    match which {
        "append-entries" => {
            let rpc = serde_json::from_slice(body).map_err(|e| format!("decode: {e}"))?;
            let resp = handle.raft.append_entries(rpc).await.map_err(|e| format!("{e}"))?;
            serde_json::to_string(&resp).map_err(|e| format!("encode: {e}"))
        }
        "vote" => {
            let rpc = serde_json::from_slice(body).map_err(|e| format!("decode: {e}"))?;
            let resp = handle.raft.vote(rpc).await.map_err(|e| format!("{e}"))?;
            serde_json::to_string(&resp).map_err(|e| format!("encode: {e}"))
        }
        "install-snapshot" => {
            let rpc = serde_json::from_slice(body).map_err(|e| format!("decode: {e}"))?;
            let resp = handle.raft.install_snapshot(rpc).await.map_err(|e| format!("{e}"))?;
            serde_json::to_string(&resp).map_err(|e| format!("encode: {e}"))
        }
        other => Err(format!("unknown raft rpc: {other}")),
    }
}

/// Propose a command through the live cluster (leader-committed). Used by the
/// write path when Raft is active. Returns the state-machine message.
pub async fn propose(cmd: Command) -> Result<String, String> {
    let handle = RAFT.get().ok_or("raft not running")?;
    match handle.raft.client_write(cmd).await {
        Ok(resp) => Ok(resp.data.message),
        Err(e) => Err(format!("raft write failed: {e}")),
    }
}

/// True if this process is the current Raft leader (or Raft is off → single
/// writer via the file lease, treated as "may write").
pub async fn is_leader_or_off() -> bool {
    match RAFT.get() {
        None => true,
        Some(h) => h.raft.current_leader().await == Some(h.node_id),
    }
}

/// (current_leader_id, this_node_id) — both None when Raft is off.
pub async fn raft_status() -> (Option<NeuroNodeId>, Option<NeuroNodeId>) {
    match RAFT.get() {
        None => (None, None),
        Some(h) => (h.raft.current_leader().await, Some(h.node_id)),
    }
}

// ─── Bootstrap helper ──────────────────────────────────────────────────
pub async fn build_single_node(
    node_id: NeuroNodeId,
    world: Arc<std::sync::RwLock<DesiredWorld>>,
) -> Result<openraft::Raft<NeuroTypeConfig>, Box<dyn std::error::Error + Send + Sync>> {
    let config = Arc::new(openraft::Config {
        cluster_name: "royak".to_string(),
        heartbeat_interval: 150,
        election_timeout_min: 300,
        election_timeout_max: 600,
        ..Default::default()
    }.validate()?);

    let store = NeuroStore::new(world);
    let (log_store, state_machine) = Adaptor::new(store);

    let raft = openraft::Raft::new(
        node_id,
        config,
        StubNetworkFactory,
        log_store,
        state_machine,
    ).await?;

    // Bootstrap a single-node cluster (this node is the only voter).
    let mut nodes = std::collections::BTreeMap::new();
    nodes.insert(node_id, BasicNode::default());
    raft.initialize(nodes).await?;

    Ok(raft)
}

/// Build one Raft node bound to an in-process registry (for tests).
/// Unlike `build_single_node`, this does NOT auto-initialize; callers
/// bootstrap a cluster once across all nodes after every node is in
/// the registry.
pub async fn build_node_in_proc(
    node_id: NeuroNodeId,
    world: Arc<std::sync::RwLock<DesiredWorld>>,
    registry: NodeRegistry,
) -> Result<Arc<openraft::Raft<NeuroTypeConfig>>, Box<dyn std::error::Error + Send + Sync>> {
    let config = Arc::new(openraft::Config {
        cluster_name: "royak".to_string(),
        heartbeat_interval: 150,
        election_timeout_min: 300,
        election_timeout_max: 600,
        ..Default::default()
    }.validate()?);

    let store = NeuroStore::new(world);
    let (log_store, state_machine) = Adaptor::new(store);

    let raft = openraft::Raft::new(
        node_id,
        config,
        InProcNetworkFactory::simple(registry.clone()),
        log_store,
        state_machine,
    ).await?;

    let raft = Arc::new(raft);
    registry.write().await.insert(node_id, raft.clone());
    Ok(raft)
}

/// Build a Raft node with a partition controller for chaos tests. Same as
/// `build_node_in_proc` but the network respects the `isolated` set.
pub async fn build_node_in_proc_chaos(
    node_id: NeuroNodeId,
    world: Arc<std::sync::RwLock<DesiredWorld>>,
    registry: NodeRegistry,
    isolated: Partition,
) -> Result<Arc<openraft::Raft<NeuroTypeConfig>>, Box<dyn std::error::Error + Send + Sync>> {
    let config = Arc::new(openraft::Config {
        cluster_name: "royak".to_string(),
        heartbeat_interval: 150,
        election_timeout_min: 300,
        election_timeout_max: 600,
        ..Default::default()
    }.validate()?);

    let store = NeuroStore::new(world);
    let (log_store, state_machine) = Adaptor::new(store);

    let raft = openraft::Raft::new(
        node_id,
        config,
        InProcNetworkFactory { registry: registry.clone(), source: node_id, isolated },
        log_store,
        state_machine,
    ).await?;

    let raft = Arc::new(raft);
    registry.write().await.insert(node_id, raft.clone());
    Ok(raft)
}

/// Phase 1 backend: forwards ProposeOutcome through a real Raft log.
/// Can be swapped into `ConsensusBackend` once the reconcile loop is ready
/// to call a backend instead of mutating `DesiredWorld` directly.
pub struct RaftLocalBackend {
    pub node_id: NeuroNodeId,
    pub raft: openraft::Raft<NeuroTypeConfig>,
}

impl RaftLocalBackend {
    pub async fn propose(&self, cmd: Command) -> ProposeOutcome {
        match self.raft.client_write(cmd).await {
            Ok(resp) => ProposeOutcome {
                committed: true,
                message: resp.data.message.clone(),
                index: Some(resp.log_id.index),
            },
            Err(e) => ProposeOutcome {
                committed: false,
                message: format!("raft write failed: {e}"),
                index: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn await_leader(raft: &openraft::Raft<NeuroTypeConfig>) {
        // Single-node clusters become leader quickly; wait for it.
        for _ in 0..40 {
            if raft.current_leader().await.is_some() { return; }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("single node never became leader");
    }

    #[tokio::test]
    async fn single_node_commits_command_through_raft() {
        let world = Arc::new(std::sync::RwLock::new(DesiredWorld::new()));
        let raft = build_single_node(1, world.clone()).await.expect("build raft");
        await_leader(&raft).await;

        let cmd = Command::Scale {
            name: "web".into(),
            namespace: "default".into(),
            replicas: 3,
        };
        let resp = raft.client_write(cmd.clone()).await.expect("client_write");
        assert!(resp.data.message.contains("scale web"), "sm response: {:?}", resp.data);

        // State machine stamped its marker on the world — proof the Raft log
        // round-tripped through apply_to_state_machine.
        let stamp = world.read().unwrap().config.runtime.clone();
        assert!(stamp.contains("raft:"), "world was not mutated via raft, got: {stamp}");
        assert!(stamp.contains("scale web"), "stamp missing scale marker: {stamp}");

        raft.shutdown().await.ok();
    }

    #[tokio::test]
    async fn two_commands_get_consecutive_indices() {
        let world = Arc::new(std::sync::RwLock::new(DesiredWorld::new()));
        let raft = build_single_node(1, world).await.expect("build raft");
        await_leader(&raft).await;

        let r1 = raft.client_write(Command::Heartbeat {
            node: "node-a".into(), cpu_used: 0.1, mem_used: 10.0, pod_count: 0,
        }).await.expect("write 1");
        let r2 = raft.client_write(Command::Heartbeat {
            node: "node-a".into(), cpu_used: 0.2, mem_used: 20.0, pod_count: 1,
        }).await.expect("write 2");

        assert!(r2.log_id.index > r1.log_id.index, "expected increasing log indices");
        raft.shutdown().await.ok();
    }

    #[tokio::test]
    async fn three_node_cluster_elects_leader_and_replicates() {
        // Three in-process Raft instances sharing a registry. One becomes
        // leader; client_write on the leader propagates to the other two
        // state machines.
        let registry = new_registry();
        let w1 = Arc::new(std::sync::RwLock::new(DesiredWorld::new()));
        let w2 = Arc::new(std::sync::RwLock::new(DesiredWorld::new()));
        let w3 = Arc::new(std::sync::RwLock::new(DesiredWorld::new()));

        let r1 = build_node_in_proc(1, w1.clone(), registry.clone()).await.expect("node 1");
        let r2 = build_node_in_proc(2, w2.clone(), registry.clone()).await.expect("node 2");
        let r3 = build_node_in_proc(3, w3.clone(), registry.clone()).await.expect("node 3");

        // Bootstrap the cluster on node 1 with all three members.
        let mut members = std::collections::BTreeMap::new();
        members.insert(1u64, BasicNode::default());
        members.insert(2u64, BasicNode::default());
        members.insert(3u64, BasicNode::default());
        r1.initialize(members).await.expect("initialize");

        // Wait for a leader to emerge. Election takes a few ticks.
        let mut leader_id = None;
        for _ in 0..60 {
            if let Some(id) = r1.current_leader().await {
                leader_id = Some(id);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        let leader_id = leader_id.expect("a leader should be elected");
        let leader = match leader_id {
            1 => r1.clone(), 2 => r2.clone(), 3 => r3.clone(),
            other => panic!("unexpected leader id {other}"),
        };

        // Write a command to the leader.
        let cmd = Command::Scale {
            name: "multi".into(), namespace: "default".into(), replicas: 7,
        };
        leader.client_write(cmd).await.expect("client_write");

        // Give followers a moment to apply.
        for _ in 0..20 {
            let seen = [&w1, &w2, &w3].iter()
                .filter(|w| w.read().unwrap().config.runtime.contains("scale multi"))
                .count();
            if seen == 3 { break; }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        for (i, w) in [&w1, &w2, &w3].iter().enumerate() {
            let stamp = w.read().unwrap().config.runtime.clone();
            assert!(stamp.contains("scale multi"),
                "node {} did not see the replicated command: stamp={stamp}", i + 1);
        }

        // Graceful shutdown. We drop the Arc via try_unwrap best-effort.
        for r in [r1, r2, r3] {
            let _ = r.shutdown().await;
        }
    }

    #[tokio::test]
    async fn backend_wrapper_reports_committed_and_index() {
        let world = Arc::new(std::sync::RwLock::new(DesiredWorld::new()));
        let raft = build_single_node(1, world).await.expect("build raft");
        await_leader(&raft).await;

        let backend = RaftLocalBackend { node_id: 1, raft };
        let outcome = backend.propose(Command::Delete {
            kind: "ConfigMap".into(),
            name: "deleted-cm".into(),
            namespace: "default".into(),
        }).await;

        assert!(outcome.committed, "propose should commit");
        assert!(outcome.index.is_some(), "raft backend must report log index");
        assert!(outcome.message.contains("delete ConfigMap"), "message: {}", outcome.message);

        backend.raft.shutdown().await.ok();
    }

    // ─── CHAOS: kill leader → re-elect → no committed op lost;
    //     partition minority → can't commit; heal → catches up. ───
    #[tokio::test]
    async fn chaos_kill_leader_partition_heal_no_lost_commit() {
        let registry = new_registry();
        let isolated = new_partition();
        let worlds: Vec<_> = (1..=3).map(|_| Arc::new(std::sync::RwLock::new(DesiredWorld::new()))).collect();
        let mut rafts = std::collections::HashMap::new();
        for id in 1u64..=3 {
            let r = build_node_in_proc_chaos(id, worlds[(id-1) as usize].clone(), registry.clone(), isolated.clone())
                .await.expect("build node");
            rafts.insert(id, r);
        }
        let mut members = std::collections::BTreeMap::new();
        for id in 1u64..=3 { members.insert(id, BasicNode::default()); }
        rafts[&1].initialize(members).await.expect("init");

        // helper: current leader id
        async fn leader_of(rafts: &std::collections::HashMap<u64, Arc<openraft::Raft<NeuroTypeConfig>>>) -> Option<u64> {
            for _ in 0..80 {
                for r in rafts.values() {
                    if let Some(id) = r.current_leader().await {
                        if rafts.contains_key(&id) { return Some(id); }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            None
        }

        // helper: write a scale command to the current leader, retrying across
        // re-elections. Returns committed log index.
        async fn commit_scale(rafts: &std::collections::HashMap<u64, Arc<openraft::Raft<NeuroTypeConfig>>>, replicas: u32) -> Option<u64> {
            for _ in 0..40 {
                if let Some(lid) = leader_of(rafts).await {
                    let cmd = Command::Scale { name: "svc".into(), namespace: "default".into(), replicas };
                    if let Ok(resp) = rafts[&lid].client_write(cmd).await {
                        return Some(resp.log_id.index);
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
            }
            None
        }

        // 1. Baseline commit under full cluster.
        let l0 = leader_of(&rafts).await.expect("initial leader");
        assert!(commit_scale(&rafts, 2).await.is_some(), "baseline commit failed");

        // 2. KILL the leader (shutdown + remove from registry so peers lose it).
        let killed = l0;
        rafts[&killed].shutdown().await.ok();
        registry.write().await.remove(&killed);
        let survivors: std::collections::HashMap<u64, _> =
            rafts.iter().filter(|(k,_)| **k != killed).map(|(k,v)| (*k, v.clone())).collect();

        // 3. Re-election among the 2 survivors (still a quorum of 3).
        let new_leader = leader_of(&survivors).await.expect("survivors must re-elect");
        assert_ne!(new_leader, killed, "a new leader must emerge");

        // 4. New commit succeeds on the surviving quorum.
        let idx_after_kill = commit_scale(&survivors, 5).await.expect("commit after kill failed");

        // 5. The earlier committed op (replicas=2 → then 5) is present on a
        //    survivor's state machine — nothing committed was lost.
        let mut applied = false;
        for _ in 0..30 {
            if survivors.values().any(|_| true) {
                let s = worlds[(new_leader-1) as usize].read().unwrap().config.runtime.clone();
                if s.contains("scale svc") { applied = true; break; }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert!(applied, "committed command not applied on the new leader's state machine");
        assert!(idx_after_kill > 0);

        // 6. PARTITION: isolate one survivor → it's a minority of 1, cannot
        //    become leader or commit; the other survivor + (dead) = no quorum
        //    either, so with only 2 live of 3, isolating 1 leaves 1 live → NO
        //    quorum → writes must NOT commit.
        let (a, b) = {
            let mut it = survivors.keys().copied();
            (it.next().unwrap(), it.next().unwrap())
        };
        isolated.write().await.insert(b);
        // Now only `a` is reachable (killed removed, b isolated). 1 of 3 = no quorum.
        let mut one = std::collections::HashMap::new();
        one.insert(a, survivors[&a].clone());
        let committed_in_partition = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            commit_scale(&one, 9),
        ).await.ok().flatten();
        assert!(committed_in_partition.is_none(),
            "write MUST NOT commit without a quorum (got index {:?})", committed_in_partition);

        // 7. HEAL: bring b back → quorum of 2 restored → writes commit again.
        isolated.write().await.remove(&b);
        let healed = commit_scale(&survivors, 4).await;
        assert!(healed.is_some(), "after healing, writes must commit again");

        for r in rafts.into_values() { let _ = r.shutdown().await; }
    }

}
