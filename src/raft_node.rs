//! Raft consensus for clustered desired state (openraft 0.9).
//!
//! * One command ([`Command::Commit`]): full next state + base generation,
//!   applied with compare-and-swap on the generation. See `consensus.rs`.
//! * Durable storage under `{data_dir}/raft-{node_id}/`:
//!     - `vote.json`, `committed.json` — atomic replace + fsync
//!     - `log.bin` — append-only records `[u32 len][8B sha256 prefix][json]`,
//!       fsync'd on append; a torn (incomplete) final record is truncated on
//!       start, a checksum mismatch is fatal
//!     - `snapshot.json` — last snapshot (meta + full sealed state); also the
//!       state machine's restart point (the log is replayed on top of it)
//! * Transport: HTTP POST to the peer's `/royak/v1/raft/*`, HMAC-signed with
//!   the cluster secret (see `auth.rs`); the receiver verifies before
//!   dispatching to the local Raft.
//! * [`commit_blocking`] is the clustered commit point used by
//!   [`crate::store::commit_state`]: it returns success only after the entry
//!   is committed by a quorum and applied on this (leader) node.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::path::PathBuf;
use std::sync::Arc;

use openraft::storage::{Adaptor, LogState, RaftLogReader, RaftSnapshotBuilder, RaftStorage, Snapshot};
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, SnapshotMeta, StorageError, StorageIOError,
    StoredMembership, Vote,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock as TokioRwLock;

use crate::consensus::Command;
use crate::reconcile::DesiredWorld;
use crate::store::{CommitError, DesiredState};

pub type NeuroNodeId = u64;

/// State machine reply.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct NeuroResponse {
    pub applied: bool,
    pub generation: u64,
    pub message: String,
}

openraft::declare_raft_types!(
    pub NeuroTypeConfig:
        D = Command,
        R = NeuroResponse,
        NodeId = NeuroNodeId,
        Node = BasicNode,
        Entry = Entry<NeuroTypeConfig>,
        SnapshotData = Cursor<Vec<u8>>,
        AsyncRuntime = openraft::TokioRuntime,
);

/// How replicated state is protected in log entries and snapshots.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Sealing {
    /// AES-256-GCM with a key derived from the cluster secret (production).
    Cluster,
    /// Plain JSON — in-process unit tests only.
    Plain,
}

const SEAL_PURPOSE: &[u8] = b"royak-raft-state-v1";

impl Sealing {
    pub fn seal(self, s: &DesiredState) -> Result<String, String> {
        let json = serde_json::to_vec(s).map_err(|e| e.to_string())?;
        match self {
            Sealing::Cluster => crate::auth::seal_for_cluster(SEAL_PURPOSE, &json),
            Sealing::Plain => String::from_utf8(json).map_err(|e| e.to_string()),
        }
    }
    pub fn unseal(self, sealed: &str) -> Result<DesiredState, String> {
        let bytes = match self {
            Sealing::Cluster => crate::auth::unseal_for_cluster(SEAL_PURPOSE, sealed)?,
            Sealing::Plain => sealed.as_bytes().to_vec(),
        };
        serde_json::from_slice(&bytes).map_err(|e| format!("replicated state: {e}"))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct SnapshotFile {
    meta: SnapshotMeta<NeuroNodeId, BasicNode>,
    /// Sealed DesiredState at `meta.last_log_id`.
    state: String,
}

struct SmState {
    last_applied: Option<LogId<NeuroNodeId>>,
    membership: StoredMembership<NeuroNodeId, BasicNode>,
}

pub struct NeuroStore {
    /// Durable directory; `None` keeps everything in memory (unit tests).
    dir: Option<PathBuf>,
    sealing: Sealing,
    vote: TokioRwLock<Option<Vote<NeuroNodeId>>>,
    committed: TokioRwLock<Option<LogId<NeuroNodeId>>>,
    log: TokioRwLock<BTreeMap<u64, Entry<NeuroTypeConfig>>>,
    last_purged: TokioRwLock<Option<LogId<NeuroNodeId>>>,
    world: Arc<std::sync::RwLock<DesiredWorld>>,
    sm: std::sync::Mutex<SmState>,
    current_snapshot: TokioRwLock<Option<SnapshotFile>>,
}

fn io_err<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

fn checksum(b: &[u8]) -> [u8; 8] {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(b);
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

fn encode_record(e: &Entry<NeuroTypeConfig>) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(e).map_err(|e| e.to_string())?;
    let mut rec = Vec::with_capacity(json.len() + 12);
    rec.extend_from_slice(&(json.len() as u32).to_be_bytes());
    rec.extend_from_slice(&checksum(&json));
    rec.extend_from_slice(&json);
    Ok(rec)
}

/// Parse `log.bin`. Returns the entries and the byte length of the valid
/// prefix (a torn final record is excluded). A corrupt complete record is an error.
fn decode_log(bytes: &[u8]) -> Result<(Vec<Entry<NeuroTypeConfig>>, usize), String> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        if bytes.len() - off < 12 { break; }
        let len = u32::from_be_bytes(bytes[off..off + 4].try_into().unwrap()) as usize;
        if bytes.len() - off - 12 < len { break; } // torn tail
        let sum = &bytes[off + 4..off + 12];
        let json = &bytes[off + 12..off + 12 + len];
        if checksum(json) != sum {
            return Err(format!("raft log record at byte {off} fails its checksum"));
        }
        let e: Entry<NeuroTypeConfig> = serde_json::from_slice(json)
            .map_err(|e| format!("raft log record at byte {off}: {e}"))?;
        out.push(e);
        off += 12 + len;
    }
    Ok((out, off))
}

impl NeuroStore {
    pub fn in_memory(world: Arc<std::sync::RwLock<DesiredWorld>>) -> Arc<Self> {
        Arc::new(Self::empty(None, Sealing::Plain, world))
    }

    fn empty(dir: Option<PathBuf>, sealing: Sealing, world: Arc<std::sync::RwLock<DesiredWorld>>) -> Self {
        Self {
            dir,
            sealing,
            vote: TokioRwLock::new(None),
            committed: TokioRwLock::new(None),
            log: TokioRwLock::new(BTreeMap::new()),
            last_purged: TokioRwLock::new(None),
            world,
            sm: std::sync::Mutex::new(SmState { last_applied: None, membership: StoredMembership::default() }),
            current_snapshot: TokioRwLock::new(None),
        }
    }

    /// Open (or create) durable storage in `dir` and restore the state machine
    /// from the last snapshot into `world`.
    pub fn open(dir: PathBuf, sealing: Sealing, world: Arc<std::sync::RwLock<DesiredWorld>>) -> Result<Arc<Self>, String> {
        std::fs::create_dir_all(&dir).map_err(|e| format!("create {}: {e}", dir.display()))?;
        let read_json = |name: &str| -> Result<Option<serde_json::Value>, String> {
            let p = dir.join(name);
            match std::fs::read(&p) {
                Ok(b) => serde_json::from_slice(&b).map(Some).map_err(|e| format!("{}: {e}", p.display())),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(format!("{}: {e}", p.display())),
            }
        };
        let store = Self::empty(Some(dir.clone()), sealing, world.clone());
        let vote: Option<Vote<NeuroNodeId>> = read_json("vote.json")?.map(serde_json::from_value).transpose().map_err(|e| e.to_string())?;
        let committed: Option<LogId<NeuroNodeId>> = read_json("committed.json")?.and_then(|v| serde_json::from_value(v).ok());
        let purged: Option<LogId<NeuroNodeId>> = read_json("purged.json")?.and_then(|v| serde_json::from_value(v).ok());
        let snap: Option<SnapshotFile> = read_json("snapshot.json")?.map(serde_json::from_value).transpose().map_err(|e| format!("snapshot.json: {e}"))?;
        let log_path = dir.join("log.bin");
        let (entries, valid) = match std::fs::read(&log_path) {
            Ok(b) => {
                let (entries, valid) = decode_log(&b)?;
                if valid < b.len() {
                    eprintln!("  [raft] truncating torn tail of {} ({} bytes)", log_path.display(), b.len() - valid);
                    let f = std::fs::OpenOptions::new().write(true).open(&log_path).map_err(|e| e.to_string())?;
                    f.set_len(valid as u64).map_err(|e| e.to_string())?;
                    f.sync_all().map_err(|e| e.to_string())?;
                }
                (entries, valid)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Vec::new(), 0),
            Err(e) => return Err(format!("{}: {e}", log_path.display())),
        };
        let _ = valid;
        {
            let mut log = store.log.try_write().expect("fresh lock");
            for e in entries { log.insert(e.log_id.index, e); }
        }
        *store.vote.try_write().expect("fresh lock") = vote;
        *store.committed.try_write().expect("fresh lock") = committed;
        *store.last_purged.try_write().expect("fresh lock") = purged;
        if let Some(s) = snap {
            let state = sealing.unseal(&s.state).map_err(|e| format!("snapshot.json: {e}"))?;
            eprintln!("  [raft] restored snapshot from disk (up to log {:?}, generation {})",
                s.meta.last_log_id.map(|l| l.index), state.generation);
            {
                let mut w = world.write().unwrap_or_else(|e| e.into_inner());
                w.install_state(state);
            }
            {
                let mut sm = store.sm.lock().unwrap();
                sm.last_applied = s.meta.last_log_id;
                sm.membership = s.meta.last_membership.clone();
            }
            *store.current_snapshot.try_write().expect("fresh lock") = Some(s);
        }
        Ok(Arc::new(store))
    }

    fn write_file(&self, name: &str, bytes: &[u8]) -> Result<(), std::io::Error> {
        if let Some(dir) = &self.dir {
            let p = dir.join(name);
            crate::persist::atomic_write(&p.to_string_lossy(), bytes).map_err(io_err)?;
        }
        Ok(())
    }

    fn rewrite_log(&self, log: &BTreeMap<u64, Entry<NeuroTypeConfig>>) -> Result<(), std::io::Error> {
        if self.dir.is_none() { return Ok(()); }
        let mut buf = Vec::new();
        for e in log.values() { buf.extend(encode_record(e).map_err(io_err)?); }
        self.write_file("log.bin", &buf)
    }

    fn append_records(&self, entries: &[Entry<NeuroTypeConfig>]) -> Result<(), std::io::Error> {
        use std::io::Write;
        let Some(dir) = &self.dir else { return Ok(()) };
        let mut buf = Vec::new();
        for e in entries { buf.extend(encode_record(e).map_err(io_err)?); }
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("log.bin"))?;
        f.write_all(&buf)?;
        f.sync_all()
    }

    /// The state machine: compare-and-swap install of a replicated state.
    fn apply_command(&self, cmd: &Command) -> NeuroResponse {
        match cmd {
            Command::Commit { base_generation, state } => {
                let next = match self.sealing.unseal(state) {
                    Ok(s) => s,
                    Err(e) => return NeuroResponse { applied: false, generation: 0, message: format!("cannot open replicated state: {e}") },
                };
                let mut w = self.world.write().unwrap_or_else(|e| e.into_inner());
                if w.generation != *base_generation {
                    return NeuroResponse {
                        applied: false,
                        generation: w.generation,
                        message: format!("conflict: state is at generation {}, write was based on {base_generation}", w.generation),
                    };
                }
                let g = next.generation;
                w.install_state(next);
                NeuroResponse { applied: true, generation: g, message: format!("generation {g}") }
            }
        }
    }
}

impl RaftLogReader<NeuroTypeConfig> for Arc<NeuroStore> {
    async fn try_get_log_entries<RB>(&mut self, range: RB) -> Result<Vec<Entry<NeuroTypeConfig>>, StorageError<NeuroNodeId>>
    where RB: RangeBounds<u64> + Clone + Debug + openraft::OptionalSend {
        let log = self.log.read().await;
        Ok(log.range(range).map(|(_, e)| e.clone()).collect())
    }
}

impl RaftSnapshotBuilder<NeuroTypeConfig> for Arc<NeuroStore> {
    async fn build_snapshot(&mut self) -> Result<Snapshot<NeuroTypeConfig>, StorageError<NeuroNodeId>> {
        // Capture state and last_applied atomically w.r.t. apply.
        let (meta, sealed) = {
            let sm = self.sm.lock().unwrap();
            let state = self.world.read().unwrap_or_else(|e| e.into_inner()).to_state();
            let sealed = self.sealing.seal(&state).map_err(|e| StorageIOError::read_state_machine(&io_err(e)))?;
            let snapshot_id = sm.last_applied
                .map(|l| format!("{}-{}-{}", l.leader_id, l.index, state.generation))
                .unwrap_or_else(|| format!("--{}", state.generation));
            (SnapshotMeta { last_log_id: sm.last_applied, last_membership: sm.membership.clone(), snapshot_id }, sealed)
        };
        let file = SnapshotFile { meta: meta.clone(), state: sealed };
        let bytes = serde_json::to_vec(&file).map_err(|e| StorageIOError::write_snapshot(Some(meta.signature()), &io_err(e)))?;
        self.write_file("snapshot.json", &bytes).map_err(|e| StorageIOError::write_snapshot(Some(meta.signature()), &e))?;
        *self.current_snapshot.write().await = Some(file);
        Ok(Snapshot { meta, snapshot: Box::new(Cursor::new(bytes)) })
    }
}

impl RaftStorage<NeuroTypeConfig> for Arc<NeuroStore> {
    type LogReader = Self;
    type SnapshotBuilder = Self;

    async fn get_log_state(&mut self) -> Result<LogState<NeuroTypeConfig>, StorageError<NeuroNodeId>> {
        let log = self.log.read().await;
        let last_purged = *self.last_purged.read().await;
        let last = log.iter().next_back().map(|(_, e)| e.log_id);
        Ok(LogState { last_purged_log_id: last_purged, last_log_id: last.or(last_purged) })
    }

    async fn save_vote(&mut self, vote: &Vote<NeuroNodeId>) -> Result<(), StorageError<NeuroNodeId>> {
        let bytes = serde_json::to_vec(vote).map_err(|e| StorageIOError::write_vote(&io_err(e)))?;
        self.write_file("vote.json", &bytes).map_err(|e| StorageIOError::write_vote(&e))?;
        *self.vote.write().await = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NeuroNodeId>>, StorageError<NeuroNodeId>> {
        Ok(*self.vote.read().await)
    }

    async fn save_committed(&mut self, committed: Option<LogId<NeuroNodeId>>) -> Result<(), StorageError<NeuroNodeId>> {
        let bytes = serde_json::to_vec(&committed).map_err(|e| StorageIOError::write(&io_err(e)))?;
        self.write_file("committed.json", &bytes).map_err(|e| StorageIOError::write(&e))?;
        *self.committed.write().await = committed;
        Ok(())
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NeuroNodeId>>, StorageError<NeuroNodeId>> {
        Ok(*self.committed.read().await)
    }

    async fn append_to_log<I>(&mut self, entries: I) -> Result<(), StorageError<NeuroNodeId>>
    where I: IntoIterator<Item = Entry<NeuroTypeConfig>> + openraft::OptionalSend {
        let entries: Vec<_> = entries.into_iter().collect();
        if entries.is_empty() { return Ok(()); }
        self.append_records(&entries).map_err(|e| StorageIOError::write_logs(&e))?;
        let mut log = self.log.write().await;
        for e in entries { log.insert(e.log_id.index, e); }
        Ok(())
    }

    async fn delete_conflict_logs_since(&mut self, log_id: LogId<NeuroNodeId>) -> Result<(), StorageError<NeuroNodeId>> {
        let mut log = self.log.write().await;
        let keys: Vec<u64> = log.range(log_id.index..).map(|(k, _)| *k).collect();
        for k in keys { log.remove(&k); }
        self.rewrite_log(&log).map_err(|e| StorageIOError::write_logs(&e))?;
        Ok(())
    }

    async fn purge_logs_upto(&mut self, log_id: LogId<NeuroNodeId>) -> Result<(), StorageError<NeuroNodeId>> {
        let bytes = serde_json::to_vec(&Some(log_id)).map_err(|e| StorageIOError::write(&io_err(e)))?;
        self.write_file("purged.json", &bytes).map_err(|e| StorageIOError::write(&e))?;
        *self.last_purged.write().await = Some(log_id);
        let mut log = self.log.write().await;
        let keys: Vec<u64> = log.range(..=log_id.index).map(|(k, _)| *k).collect();
        for k in keys { log.remove(&k); }
        self.rewrite_log(&log).map_err(|e| StorageIOError::write_logs(&e))?;
        Ok(())
    }

    async fn last_applied_state(&mut self) -> Result<(Option<LogId<NeuroNodeId>>, StoredMembership<NeuroNodeId, BasicNode>), StorageError<NeuroNodeId>> {
        let sm = self.sm.lock().unwrap();
        Ok((sm.last_applied, sm.membership.clone()))
    }

    async fn apply_to_state_machine(&mut self, entries: &[Entry<NeuroTypeConfig>]) -> Result<Vec<NeuroResponse>, StorageError<NeuroNodeId>> {
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            let mut sm = self.sm.lock().unwrap();
            sm.last_applied = Some(entry.log_id);
            match &entry.payload {
                EntryPayload::Blank => out.push(NeuroResponse::default()),
                EntryPayload::Normal(cmd) => out.push(self.apply_command(cmd)),
                EntryPayload::Membership(m) => {
                    sm.membership = StoredMembership::new(Some(entry.log_id), m.clone());
                    out.push(NeuroResponse::default());
                }
            }
        }
        Ok(out)
    }

    async fn begin_receiving_snapshot(&mut self) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NeuroNodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(&mut self, meta: &SnapshotMeta<NeuroNodeId, BasicNode>, snapshot: Box<Cursor<Vec<u8>>>) -> Result<(), StorageError<NeuroNodeId>> {
        let bytes = snapshot.into_inner();
        let file: SnapshotFile = serde_json::from_slice(&bytes)
            .map_err(|e| StorageIOError::read_snapshot(Some(meta.signature()), &io_err(e)))?;
        let state = self.sealing.unseal(&file.state)
            .map_err(|e| StorageIOError::read_snapshot(Some(meta.signature()), &io_err(e)))?;
        eprintln!("  [raft] installing snapshot from leader (up to log {:?}, generation {})",
            meta.last_log_id.map(|l| l.index), state.generation);
        let file = SnapshotFile { meta: meta.clone(), state: file.state };
        let disk = serde_json::to_vec(&file).map_err(|e| StorageIOError::write_snapshot(Some(meta.signature()), &io_err(e)))?;
        self.write_file("snapshot.json", &disk).map_err(|e| StorageIOError::write_snapshot(Some(meta.signature()), &e))?;
        {
            let mut sm = self.sm.lock().unwrap();
            self.world.write().unwrap_or_else(|e| e.into_inner()).install_state(state);
            sm.last_applied = meta.last_log_id;
            sm.membership = meta.last_membership.clone();
        }
        *self.current_snapshot.write().await = Some(file);
        Ok(())
    }

    async fn get_current_snapshot(&mut self) -> Result<Option<Snapshot<NeuroTypeConfig>>, StorageError<NeuroNodeId>> {
        let cur = self.current_snapshot.read().await;
        match cur.as_ref() {
            Some(s) => {
                let bytes = serde_json::to_vec(s).map_err(|e| StorageIOError::read_snapshot(Some(s.meta.signature()), &io_err(e)))?;
                Ok(Some(Snapshot { meta: s.meta.clone(), snapshot: Box::new(Cursor::new(bytes)) }))
            }
            None => Ok(None),
        }
    }

    async fn get_log_reader(&mut self) -> Self::LogReader { self.clone() }
    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder { self.clone() }
}

// ─── In-process network (unit tests: partitions, failover) ─────────────

#[cfg(test)]
pub type NodeRegistry = Arc<tokio::sync::RwLock<std::collections::HashMap<NeuroNodeId, Arc<openraft::Raft<NeuroTypeConfig>>>>>;
#[cfg(test)]
pub type Partition = Arc<tokio::sync::RwLock<std::collections::HashSet<NeuroNodeId>>>;

#[cfg(test)]
pub fn new_registry() -> NodeRegistry { Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())) }
#[cfg(test)]
pub fn new_partition() -> Partition { Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())) }

#[cfg(test)]
#[derive(Clone)]
pub struct InProcNetworkFactory {
    pub registry: NodeRegistry,
    pub source: NeuroNodeId,
    pub isolated: Partition,
}

#[cfg(test)]
impl openraft::RaftNetworkFactory<NeuroTypeConfig> for InProcNetworkFactory {
    type Network = InProcNetwork;
    async fn new_client(&mut self, target: NeuroNodeId, _node: &BasicNode) -> Self::Network {
        InProcNetwork { target, source: self.source, registry: self.registry.clone(), isolated: self.isolated.clone() }
    }
}

#[cfg(test)]
pub struct InProcNetwork {
    target: NeuroNodeId,
    source: NeuroNodeId,
    registry: NodeRegistry,
    isolated: Partition,
}

type RpcErr<E = openraft::error::RaftError<NeuroNodeId>> = openraft::error::RPCError<NeuroNodeId, BasicNode, E>;

fn unreachable<E: std::error::Error>(msg: String) -> RpcErr<E> {
    openraft::error::RPCError::Unreachable(openraft::error::Unreachable::new(&std::io::Error::new(std::io::ErrorKind::NotConnected, msg)))
}

#[cfg(test)]
impl InProcNetwork {
    async fn peer(&self) -> Option<Arc<openraft::Raft<NeuroTypeConfig>>> {
        let iso = self.isolated.read().await;
        if iso.contains(&self.source) || iso.contains(&self.target) { return None; }
        drop(iso);
        self.registry.read().await.get(&self.target).cloned()
    }
}

#[cfg(test)]
impl openraft::RaftNetwork<NeuroTypeConfig> for InProcNetwork {
    async fn append_entries(&mut self, rpc: openraft::raft::AppendEntriesRequest<NeuroTypeConfig>, _o: openraft::network::RPCOption)
        -> Result<openraft::raft::AppendEntriesResponse<NeuroNodeId>, RpcErr> {
        let p = self.peer().await.ok_or_else(|| unreachable(format!("peer {} unreachable", self.target)))?;
        p.append_entries(rpc).await.map_err(|e| openraft::error::RPCError::RemoteError(openraft::error::RemoteError::new(self.target, e)))
    }
    async fn install_snapshot(&mut self, rpc: openraft::raft::InstallSnapshotRequest<NeuroTypeConfig>, _o: openraft::network::RPCOption)
        -> Result<openraft::raft::InstallSnapshotResponse<NeuroNodeId>, RpcErr<openraft::error::RaftError<NeuroNodeId, openraft::error::InstallSnapshotError>>> {
        let p = self.peer().await.ok_or_else(|| unreachable(format!("peer {} unreachable", self.target)))?;
        p.install_snapshot(rpc).await.map_err(|e| openraft::error::RPCError::RemoteError(openraft::error::RemoteError::new(self.target, e)))
    }
    async fn vote(&mut self, rpc: openraft::raft::VoteRequest<NeuroNodeId>, _o: openraft::network::RPCOption)
        -> Result<openraft::raft::VoteResponse<NeuroNodeId>, RpcErr> {
        let p = self.peer().await.ok_or_else(|| unreachable(format!("peer {} unreachable", self.target)))?;
        p.vote(rpc).await.map_err(|e| openraft::error::RPCError::RemoteError(openraft::error::RemoteError::new(self.target, e)))
    }
}

// ─── HTTP network (production) ─────────────────────────────────────────

#[derive(Clone, Default)]
pub struct HttpNetworkFactory {
    pub peers: Arc<std::sync::RwLock<std::collections::HashMap<NeuroNodeId, String>>>,
}

impl HttpNetworkFactory {
    pub fn set_peer(&self, id: NeuroNodeId, addr: String) {
        self.peers.write().unwrap().insert(id, addr);
    }
    pub fn peer_addr(&self, id: NeuroNodeId) -> Option<String> {
        self.peers.read().unwrap().get(&id).cloned()
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
    async fn post_json<Req: Serialize, Resp: for<'de> Deserialize<'de>>(&self, path: &str, req: &Req, timeout: std::time::Duration) -> Result<Resp, String> {
        let addr = self.peers.read().unwrap().get(&self.target).cloned().ok_or_else(|| format!("peer {} not registered", self.target))?;
        let body = serde_json::to_vec(req).map_err(|e| format!("serialize: {e}"))?;
        let resp_body = crate::node_rpc::call_async("POST", &addr, path, &body, timeout).await
            .map_err(|e| format!("raft rpc: {e}"))?;
        serde_json::from_slice::<Resp>(&resp_body).map_err(|e| format!("decode ({} bytes): {e}", resp_body.len()))
    }
}

const RPC_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const SNAPSHOT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

impl openraft::RaftNetwork<NeuroTypeConfig> for HttpNetwork {
    async fn append_entries(&mut self, rpc: openraft::raft::AppendEntriesRequest<NeuroTypeConfig>, _o: openraft::network::RPCOption)
        -> Result<openraft::raft::AppendEntriesResponse<NeuroNodeId>, RpcErr> {
        self.post_json("/royak/v1/raft/append-entries", &rpc, RPC_TIMEOUT).await.map_err(unreachable)
    }
    async fn install_snapshot(&mut self, rpc: openraft::raft::InstallSnapshotRequest<NeuroTypeConfig>, _o: openraft::network::RPCOption)
        -> Result<openraft::raft::InstallSnapshotResponse<NeuroNodeId>, RpcErr<openraft::error::RaftError<NeuroNodeId, openraft::error::InstallSnapshotError>>> {
        self.post_json("/royak/v1/raft/install-snapshot", &rpc, SNAPSHOT_TIMEOUT).await.map_err(unreachable)
    }
    async fn vote(&mut self, rpc: openraft::raft::VoteRequest<NeuroNodeId>, _o: openraft::network::RPCOption)
        -> Result<openraft::raft::VoteResponse<NeuroNodeId>, RpcErr> {
        self.post_json("/royak/v1/raft/vote", &rpc, RPC_TIMEOUT).await.map_err(unreachable)
    }
}

// ─── Live node ─────────────────────────────────────────────────────────

pub struct RaftHandle {
    pub raft: Arc<openraft::Raft<NeuroTypeConfig>>,
    pub net: HttpNetworkFactory,
    pub node_id: NeuroNodeId,
    pub sealing: Sealing,
    pub rt: tokio::runtime::Handle,
}

pub static RAFT: std::sync::OnceLock<RaftHandle> = std::sync::OnceLock::new();

pub fn raft_config() -> Result<Arc<openraft::Config>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Arc::new(openraft::Config {
        cluster_name: "royak".to_string(),
        heartbeat_interval: 250,
        election_timeout_min: 1000,
        election_timeout_max: 2000,
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(64),
        max_in_snapshot_log_to_keep: 16,
        ..Default::default()
    }.validate()?))
}

/// Start this process's Raft node with durable storage in `dir`.
///
/// `seed` is the desired state found in this node's state file; on the
/// bootstrap node of a brand-new cluster it becomes the first committed
/// state (so an existing single-node install can be turned into a cluster
/// without losing its resources). On every other start the replicated state
/// (snapshot + log) is authoritative and `seed` is ignored.
pub async fn build_http_node(
    node_id: NeuroNodeId,
    world: Arc<std::sync::RwLock<DesiredWorld>>,
    peers: &[(NeuroNodeId, String)],
    bootstrap: bool,
    dir: PathBuf,
    seed: Option<DesiredState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let net = HttpNetworkFactory::default();
    for (id, addr) in peers { net.set_peer(*id, addr.clone()); }
    let store = NeuroStore::open(dir, Sealing::Cluster, world.clone())?;
    let fresh = store.log.read().await.is_empty() && store.current_snapshot.read().await.is_none();
    let (log_store, state_machine) = Adaptor::new(store);
    let raft = Arc::new(openraft::Raft::new(node_id, raft_config()?, net.clone(), log_store, state_machine).await?);
    RAFT.set(RaftHandle { raft: raft.clone(), net, node_id, sealing: Sealing::Cluster, rt: tokio::runtime::Handle::current() })
        .map_err(|_| "RAFT already set")?;

    if bootstrap && fresh {
        let mut members = BTreeMap::new();
        members.insert(node_id, BasicNode::default());
        for (id, _) in peers { members.insert(*id, BasicNode::default()); }
        match raft.initialize(members).await {
            Ok(()) => eprintln!("  [raft] cluster initialised by node {node_id}"),
            Err(e) => eprintln!("  [raft] initialise skipped: {e}"),
        }
        if let Some(mut seed) = seed {
            if !seed.same_content(&DesiredWorld::new().to_state()) || seed.generation > 0 {
                // Wait for our own leadership, then commit the seed as generation 1.
                for _ in 0..120 {
                    if raft.current_leader().await == Some(node_id) { break; }
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
                let base = world.read().unwrap_or_else(|e| e.into_inner()).generation;
                if base == 0 {
                    seed.generation = 1;
                    seed.cluster_id = world.read().unwrap_or_else(|e| e.into_inner()).cluster_id.clone();
                    let state = Sealing::Cluster.seal(&seed)?;
                    match raft.client_write(Command::Commit { base_generation: 0, state }).await {
                        Ok(r) if r.data.applied => eprintln!("  [raft] seeded cluster state from local file ({} deployments)", seed.deployments.len()),
                        Ok(r) => eprintln!("  [raft] seed not applied: {}", r.data.message),
                        Err(e) => eprintln!("  [raft] seed commit failed: {e}"),
                    }
                }
            }
        }
    }
    Ok(())
}

/// Dispatch an inbound (already node-authenticated) Raft RPC.
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

/// How long a clustered write waits for quorum before it is reported as
/// unavailable (HTTP 503). The client was not told "success", so a write
/// without quorum is never confirmed.
pub const COMMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Replicate `next` through Raft. Blocking — call from a non-async thread.
pub fn commit_blocking(base_generation: u64, next: DesiredState) -> Result<(), CommitError> {
    let h = RAFT.get().ok_or_else(|| CommitError::Unavailable("raft is not running yet on this node".into()))?;
    let state = h.sealing.seal(&next).map_err(CommitError::Unavailable)?;
    let raft = h.raft.clone();
    let res = h.rt.block_on(async move {
        tokio::time::timeout(COMMIT_TIMEOUT, raft.client_write(Command::Commit { base_generation, state })).await
    });
    match res {
        Err(_) => Err(CommitError::Unknown(format!(
            "no quorum within {}s — the write is NOT confirmed; it may still be applied if a quorum returns, so re-read before retrying",
            COMMIT_TIMEOUT.as_secs()))),
        Ok(Err(e)) => {
            if let openraft::error::RaftError::APIError(openraft::error::ClientWriteError::ForwardToLeader(f)) = &e {
                return Err(CommitError::NotLeader(f.leader_id));
            }
            Err(CommitError::Unavailable(format!("raft write failed: {e}")))
        }
        Ok(Ok(resp)) if resp.data.applied => Ok(()),
        Ok(Ok(resp)) => Err(CommitError::Unavailable(resp.data.message)),
    }
}

/// API address of a Raft node, if known (for not-leader redirects).
pub fn peer_address(id: NeuroNodeId) -> Option<String> {
    RAFT.get().and_then(|h| h.net.peer_addr(id))
}

pub static CLUSTER_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Set once this node's Raft instance is up (and, on the bootstrap node, the
/// seed commit was attempted). The reconcile loop does not tick before it.
pub static RAFT_READY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static IS_RAFT_LEADER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn is_clustered() -> bool {
    CLUSTER_MODE.load(std::sync::atomic::Ordering::Acquire)
}

/// Only the node that owns scheduling creates/scales/rolls pods: single-node
/// → always; clustered → the confirmed Raft leader.
pub fn is_cluster_scheduler() -> bool {
    use std::sync::atomic::Ordering;
    !CLUSTER_MODE.load(Ordering::Acquire) || IS_RAFT_LEADER.load(Ordering::Acquire)
}

/// Leadership that a quorum has confirmed recently. `current_leader()` alone
/// is not enough: a restarted node restores its committed self-vote and calls
/// itself leader before any peer answered, and a leader cut off in a minority
/// keeps the title until it learns of a newer term. Either would schedule
/// pods next to the real leader.
fn confirmed_leader(m: &openraft::RaftMetrics<NeuroNodeId, BasicNode>, me: NeuroNodeId) -> bool {
    if m.current_leader != Some(me) {
        return false;
    }
    let voters = m.membership_config.membership().voter_ids().count();
    if voters <= 1 {
        return true;
    }
    // Within one minimum election timeout no other node can have been elected.
    matches!(m.millis_since_quorum_ack, Some(ms) if ms < LEADER_LEASE_MS)
}

const LEADER_LEASE_MS: u64 = 1000;

pub async fn leadership_poller() {
    use std::sync::atomic::Ordering;
    loop {
        let is_leader = match RAFT.get() {
            Some(h) => confirmed_leader(&h.raft.metrics().borrow(), h.node_id),
            None => false,
        };
        IS_RAFT_LEADER.store(is_leader, Ordering::Release);
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
}

#[cfg(test)]
/// Test helper: a node on the in-process network, optionally durable.
pub async fn build_node_in_proc(
    node_id: NeuroNodeId,
    world: Arc<std::sync::RwLock<DesiredWorld>>,
    registry: NodeRegistry,
    isolated: Partition,
    dir: Option<PathBuf>,
) -> Result<Arc<openraft::Raft<NeuroTypeConfig>>, Box<dyn std::error::Error + Send + Sync>> {
    let config = Arc::new(openraft::Config {
        cluster_name: "royak-test".to_string(),
        heartbeat_interval: 100,
        election_timeout_min: 300,
        election_timeout_max: 600,
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(8),
        max_in_snapshot_log_to_keep: 2,
        ..Default::default()
    }.validate()?);
    let store = match dir {
        Some(d) => NeuroStore::open(d, Sealing::Plain, world)?,
        None => NeuroStore::in_memory(world),
    };
    let (log_store, state_machine) = Adaptor::new(store);
    let raft = Arc::new(openraft::Raft::new(node_id, config,
        InProcNetworkFactory { registry: registry.clone(), source: node_id, isolated }, log_store, state_machine).await?);
    registry.write().await.insert(node_id, raft.clone());
    Ok(raft)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    type Rafts = HashMap<u64, Arc<openraft::Raft<NeuroTypeConfig>>>;
    type Worlds = HashMap<u64, Arc<std::sync::RwLock<DesiredWorld>>>;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("royak-raft-{tag}-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    async fn cluster(n: u64, durable: Option<&PathBuf>) -> (Rafts, Worlds, NodeRegistry, Partition) {
        let registry = new_registry();
        let isolated = new_partition();
        let mut rafts = HashMap::new();
        let mut worlds = HashMap::new();
        for id in 1..=n {
            let w = Arc::new(std::sync::RwLock::new(DesiredWorld::new()));
            let dir = durable.map(|d| d.join(format!("n{id}")));
            let r = build_node_in_proc(id, w.clone(), registry.clone(), isolated.clone(), dir).await.unwrap();
            rafts.insert(id, r);
            worlds.insert(id, w);
        }
        let mut members = BTreeMap::new();
        for id in 1..=n { members.insert(id, BasicNode::default()); }
        rafts[&1].initialize(members).await.unwrap();
        (rafts, worlds, registry, isolated)
    }

    async fn leader(rafts: &Rafts, isolated: &Partition) -> u64 {
        for _ in 0..100 {
            let iso = isolated.read().await.clone();
            for (id, r) in rafts {
                if iso.contains(id) { continue; }
                if r.current_leader().await == Some(*id) { return *id; }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("no leader elected");
    }

    /// A write as the API would make it: next state = current + one change.
    fn next_state(w: &Arc<std::sync::RwLock<DesiredWorld>>, f: impl FnOnce(&mut DesiredWorld)) -> (u64, DesiredState) {
        let base = w.read().unwrap().to_state();
        let mut scratch = DesiredWorld::from_state(base.clone());
        f(&mut scratch);
        let mut next = scratch.to_state();
        next.generation = base.generation + 1;
        (base.generation, next)
    }

    fn add_ns(name: &str) -> impl FnOnce(&mut DesiredWorld) + '_ {
        move |w: &mut DesiredWorld| w.namespaces.push(name.to_string())
    }

    async fn write(r: &openraft::Raft<NeuroTypeConfig>, base: u64, next: DesiredState) -> Result<NeuroResponse, String> {
        let state = Sealing::Plain.seal(&next).unwrap();
        match tokio::time::timeout(std::time::Duration::from_secs(3), r.client_write(Command::Commit { base_generation: base, state })).await {
            Ok(Ok(resp)) => Ok(resp.data),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("timeout".into()),
        }
    }

    async fn converge(worlds: &Worlds, ids: &[u64], ns: &str) -> bool {
        for _ in 0..50 {
            if ids.iter().all(|i| worlds[i].read().unwrap().namespaces.iter().any(|n| n == ns)) { return true; }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        false
    }

    #[tokio::test]
    async fn replicates_and_rejects_stale_base() {
        let (rafts, worlds, _reg, iso) = cluster(3, None).await;
        let l = leader(&rafts, &iso).await;
        let (base, next) = next_state(&worlds[&l], add_ns("a"));
        let r = write(&rafts[&l], base, next.clone()).await.unwrap();
        assert!(r.applied);
        assert!(converge(&worlds, &[1, 2, 3], "a").await, "followers must apply the committed state");
        // A retried / duplicated write based on the old generation is a no-op.
        let r2 = write(&rafts[&l], base, next).await.unwrap();
        assert!(!r2.applied, "stale-base commit must be rejected by CAS");
        assert_eq!(worlds[&l].read().unwrap().generation, 1);
        for r in rafts.values() { let _ = r.shutdown().await; }
    }

    #[tokio::test]
    async fn minority_cannot_commit_and_failover_keeps_committed_writes() {
        let (rafts, worlds, _reg, iso) = cluster(3, None).await;
        let l = leader(&rafts, &iso).await;
        let (b, n) = next_state(&worlds[&l], add_ns("before"));
        assert!(write(&rafts[&l], b, n).await.unwrap().applied);
        assert!(converge(&worlds, &[1, 2, 3], "before").await);

        // Isolate the leader: it is a minority of one and cannot commit.
        iso.write().await.insert(l);
        let (b, n) = next_state(&worlds[&l], add_ns("minority"));
        assert!(write(&rafts[&l], b, n).await.is_err(), "an isolated leader must not confirm a write");
        assert!(!worlds[&l].read().unwrap().namespaces.iter().any(|x| x == "minority"),
            "an unconfirmed write must not reach the state machine");

        // The majority elects a new leader and keeps the committed write.
        let l2 = leader(&rafts, &iso).await;
        assert_ne!(l2, l);
        assert!(worlds[&l2].read().unwrap().namespaces.iter().any(|x| x == "before"));
        let (b, n) = next_state(&worlds[&l2], add_ns("after"));
        assert!(write(&rafts[&l2], b, n).await.unwrap().applied);

        // Heal: the old leader catches up, its unconfirmed write is discarded.
        iso.write().await.clear();
        assert!(converge(&worlds, &[1, 2, 3], "after").await, "old leader must catch up after heal");
        assert!(!worlds[&l].read().unwrap().namespaces.iter().any(|x| x == "minority"));
        for r in rafts.values() { let _ = r.shutdown().await; }
    }

    #[tokio::test]
    async fn delete_propagates() {
        let (rafts, worlds, _reg, iso) = cluster(3, None).await;
        let l = leader(&rafts, &iso).await;
        let (b, n) = next_state(&worlds[&l], add_ns("gone"));
        assert!(write(&rafts[&l], b, n).await.unwrap().applied);
        assert!(converge(&worlds, &[1, 2, 3], "gone").await);
        let (b, n) = next_state(&worlds[&l], |w| w.namespaces.retain(|x| x != "gone"));
        assert!(write(&rafts[&l], b, n).await.unwrap().applied);
        for _ in 0..50 {
            if [1, 2, 3].iter().all(|i| !worlds[i].read().unwrap().namespaces.iter().any(|x| x == "gone")) { break; }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        for i in [1u64, 2, 3] {
            assert!(!worlds[&i].read().unwrap().namespaces.iter().any(|x| x == "gone"), "node {i} still has deleted object");
        }
        for r in rafts.values() { let _ = r.shutdown().await; }
    }

    #[tokio::test]
    async fn restart_restores_vote_log_and_state_from_disk() {
        let dir = tmpdir("restart");
        let (rafts, worlds, _reg, iso) = cluster(3, Some(&dir)).await;
        let l = leader(&rafts, &iso).await;
        // Enough writes to trigger a snapshot + purge (policy: every 8 logs).
        for i in 0..20 {
            let (b, n) = next_state(&worlds[&l], add_ns(&format!("ns{i}")));
            assert!(write(&rafts[&l], b, n).await.unwrap().applied);
        }
        assert!(converge(&worlds, &[1, 2, 3], "ns19").await);
        let gen_before = worlds[&l].read().unwrap().generation;
        for r in rafts.values() { let _ = r.shutdown().await; }
        drop(rafts);

        // Restart all three from the same directories with EMPTY worlds.
        let registry = new_registry();
        let isolated = new_partition();
        let mut rafts2 = HashMap::new();
        let mut worlds2 = HashMap::new();
        for id in 1..=3u64 {
            let w = Arc::new(std::sync::RwLock::new(DesiredWorld::new()));
            let r = build_node_in_proc(id, w.clone(), registry.clone(), isolated.clone(), Some(dir.join(format!("n{id}")))).await.unwrap();
            rafts2.insert(id, r);
            worlds2.insert(id, w);
        }
        assert!(dir.join("n1/snapshot.json").exists(), "a snapshot must have been persisted");
        let l2 = leader(&rafts2, &isolated).await;
        // Restored state (snapshot + replayed log) and a new write still works.
        for _ in 0..50 {
            if worlds2[&l2].read().unwrap().generation >= gen_before { break; }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        assert_eq!(worlds2[&l2].read().unwrap().generation, gen_before);
        assert!(worlds2[&l2].read().unwrap().namespaces.iter().any(|x| x == "ns19"));
        let (b, n) = next_state(&worlds2[&l2], add_ns("post-restart"));
        assert!(write(&rafts2[&l2], b, n).await.unwrap().applied);
        assert!(converge(&worlds2, &[1, 2, 3], "post-restart").await);
        for r in rafts2.values() { let _ = r.shutdown().await; }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn torn_log_tail_is_truncated_and_corruption_is_fatal() {
        let e: Entry<NeuroTypeConfig> = Entry {
            log_id: LogId::new(openraft::CommittedLeaderId::new(1, 1), 1),
            payload: EntryPayload::Blank,
        };
        let rec = encode_record(&e).unwrap();
        let mut two = rec.clone();
        two.extend_from_slice(&rec);
        let (entries, valid) = decode_log(&two).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(valid, two.len());
        let torn = &two[..two.len() - 3];
        let (entries, valid) = decode_log(torn).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(valid, rec.len());
        let mut bad = two.clone();
        let n = bad.len();
        bad[n - 2] ^= 0x20;
        assert!(decode_log(&bad).is_err());
    }
}
