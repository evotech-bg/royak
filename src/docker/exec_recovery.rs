//! Explicit Linux-root node-agent startup/orphan coordinator. One active
//! coordinator per exact daemon journal; not shared-principal quota support.
//! Request handlers read only the fast gate. No scan/Docker call starts there.
use super::*;
use crate::exec_process::{RecoveryOsDrained, Reference};
use std::collections::BTreeMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, OnceLock,
};

const CADENCE: Duration = Duration::from_secs(1); // existing cleanup cadence
const OPERATION: Duration = Duration::from_secs(30); // existing Docker budget
const COORDINATOR: &str = "coordinator-lock";
static STARTED: AtomicBool = AtomicBool::new(false);
static STOPPING: AtomicBool = AtomicBool::new(false);
static STATUS: OnceLock<Mutex<Status>> = OnceLock::new();

#[derive(Clone)]
struct Status {
    phase: &'static str,
    metadata: Option<usize>,
    backlog: Option<usize>,
    action: String,
    owned: BTreeSet<String>,
}
impl Default for Status {
    fn default() -> Self {
        Self { phase: "Closed", metadata: None, backlog: None,
            action: "explicit Linux-root node-agent recovery has not established ownership; do not reset the journal".into(), owned: BTreeSet::new() }
    }
}
fn status() -> &'static Mutex<Status> {
    STATUS.get_or_init(|| Mutex::new(Status::default()))
}
fn publish(
    phase: &'static str,
    metadata: Option<usize>,
    backlog: Option<usize>,
    action: impl ToString,
    owned: BTreeSet<String>,
) {
    if let Ok(mut current) = status().lock() {
        *current = Status {
            phase,
            metadata,
            backlog,
            action: action.to_string().chars().take(512).collect(),
            owned,
        };
    }
}
pub(super) fn ready() -> bool {
    !STOPPING.load(Ordering::Acquire) && status().try_lock().is_ok_and(|s| s.phase == "Ready")
}
pub(super) fn usage() -> serde_json::Value {
    if STOPPING.load(Ordering::Acquire) {
        return serde_json::json!({"state":"Closed","metadata_records":null,
            "unattributed_possible_running":null,"action":"node-agent coordinator stopping; admission closed"});
    }
    match status().try_lock() {
        Ok(s) => serde_json::json!({"state":s.phase,"metadata_records":s.metadata,
            "unattributed_possible_running":s.backlog,"action":s.action,
            "single_daemon_coordinator":true,"shared_principal_accounting":false}),
        Err(_) => serde_json::json!({"state":"Unknown","metadata_records":null,
            "unattributed_possible_running":null,"action":"recovery state unavailable; admission remains closed"}),
    }
}
pub(super) fn allow_create(input: &str) -> Result<(), String> {
    if STOPPING.load(Ordering::Acquire) {
        return Err(unknown("diagnostic coordinator stopping"));
    }
    let current = status()
        .try_lock()
        .map_err(|_| unknown("startup recovery gate unavailable"))?;
    if current.phase != "Ready" {
        return Err(unknown(format!(
            "explicit Linux-root startup recovery is {}: {}",
            current.phase, current.action
        )));
    }
    if !(12..=64).contains(&input.len())
        || !hex(input, input.len())
        || current
            .owned
            .iter()
            .filter(|id| id.starts_with(input))
            .count()
            != 1
    {
        return Err(unknown(
            "container is not an exact/unambiguous member of the owned startup census",
        ));
    }
    Ok(())
}

/// No Deserialize/raw grant constructor. The explicit watch startup supplies
/// its actual cluster/node scope, before any API/reconcile work is admitted.
pub(crate) struct Agent {
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Agent {
    fn drop(&mut self) {
        STOPPING.store(true, Ordering::Release);
        publish(
            "Closed",
            None,
            None,
            "node-agent coordinator stopping; no replacement worker",
            BTreeSet::new(),
        );
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                eprintln!("[exec-recovery] worker panicked; restart requires a fresh closed recovery scan");
            }
        }
    }
}
pub(crate) fn start_node_agent(cluster: String, node: String) -> Result<Agent, String> {
    if !cfg!(target_os = "linux") || unsafe { libc::geteuid() } != 0 {
        return Err(unknown(
            "explicit diagnostic node-agent requires Linux root; no native/proxy fallback",
        ));
    }
    if !hex(&cluster, 12) || !crate::store::is_dns_subdomain(&node) {
        return Err(unknown("diagnostic recovery requires explicit labelled cluster/node scope; legacy adoption is unsupported"));
    }
    STARTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| unknown("one recovery worker was already started; no replacement/fan-out"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let cancel = stop.clone();
    let worker = std::thread::Builder::new()
        .name("rk-exec-recover".into())
        .spawn(move || {
            struct FailClosed;
            impl Drop for FailClosed {
                fn drop(&mut self) {
                    publish(
                        "Blocked",
                        None,
                        None,
                        "coordinator ended/ownership unknown; explicit node-agent restart required",
                        BTreeSet::new(),
                    );
                }
            }
            let _closed = FailClosed;
            publish("Scanning",None,None,"fixed worker establishing actual daemon ownership and complete bounded startup census",BTreeSet::new());
            if let Err(error) = run(&cluster, &node, &cancel) {
                publish("Blocked", None, None, error, BTreeSet::new());
                // Retain one worker, no self-replacement. No timer clears state.
                while !cancel.load(Ordering::Acquire) {
                    std::thread::sleep(CADENCE);
                }
            }
        })
        .map_err(|_| unknown("cannot start the fixed recovery worker"))?;
    Ok(Agent {
        stop,
        worker: Some(worker),
    })
}

pub(super) struct Census {
    pub(super) id: String,
    pub(super) execs: Vec<String>,
}
pub(super) trait RecoveryEngine: Engine {
    fn owned_census(&mut self, cluster: &str, node: &str) -> Result<Vec<Census>, String>;
    fn drain(&mut self, reference: &Reference) -> Result<Option<RecoveryOsDrained>, String>;
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Key {
    container: String,
    exec: String,
    nonce: String,
    owner: Owner,
}
struct Pending {
    key: Key,
    reference: Reference,
}
#[derive(Default)]
struct Cursor {
    pending: Option<Pending>,
}
impl Cursor {
    fn select(&mut self, candidate: Option<Key>) -> Result<(), String> {
        // Never replace a retained OS reference merely because a fresh census
        // chooses another row or a network/metadata operation failed.
        if self.pending.is_none() {
            if let Some(key) = candidate {
                let reference =
                    crate::exec_process::reference(&key.container, &key.exec, key.nonce.clone())
                        .map_err(unknown)?;
                drop(reference.start.begin().map_err(unknown)?); // unknown, NO Start I/O
                self.pending = Some(Pending { key, reference });
            }
        }
        Ok(())
    }
}
struct Inventory {
    metadata: usize,
    unresolved: usize,
    owned: BTreeSet<String>,
    candidate: Option<Key>,
}
fn possible(record: &Record) -> bool {
    !matches!(
        record.execution,
        Some(Execution::NoStart | Execution::OsDrained)
    ) && matches!(
        record.phase,
        Phase::StartUnknown | Phase::Running | Phase::Terminal
    )
}
fn inventory(
    journals: &[Journal],
    census: Vec<Census>,
    current: &Owner,
) -> Result<Inventory, String> {
    if journals.len() > CONTAINERS || census.len() > CONTAINERS {
        return Err(unknown("recovery CID census exceeds fixed resource bound"));
    }
    let mut known = BTreeMap::new();
    let mut metadata = 0usize;
    let mut unresolved = 0usize;
    let mut candidate = None;
    for journal in journals {
        metadata = metadata
            .checked_add(journal.records.len())
            .filter(|n| *n <= NODE_RECORDS)
            .ok_or_else(|| unknown("recovery aggregate rows exceed fixed resource bound"))?;
        for row in &journal.records {
            if let Some(exec) = &row.exec {
                if known
                    .insert(exec.clone(), journal.container.clone())
                    .is_some()
                {
                    return Err(unknown("duplicate recovery exec identity"));
                }
            }
            if row.owner != *current && possible(row) {
                unresolved += 1;
                if candidate.is_none() {
                    candidate = Some(Key {
                        container: journal.container.clone(),
                        exec: row
                            .exec
                            .clone()
                            .ok_or_else(|| unknown("possible-running row has no exact exec ID"))?,
                        nonce: row.nonce.clone(),
                        owner: row.owner.clone(),
                    });
                }
            }
        }
    }
    let mut owned = BTreeSet::new();
    let mut actual_ids = BTreeSet::new();
    for container in census {
        if !hex(&container.id, 64)
            || !owned.insert(container.id.clone())
            || container.execs.len() > PER_CONTAINER
        {
            return Err(unknown("invalid/duplicate owned recovery container census"));
        }
        for id in container.execs {
            if !hex(&id, 64) || !actual_ids.insert(id.clone()) || actual_ids.len() > NODE_RECORDS {
                return Err(unknown(
                    "invalid/duplicate/oversized aggregate actual ExecIDs",
                ));
            }
            if known.get(&id) != Some(&container.id) {
                return Err(unknown("owned container has an unattributed exec ID; no Env guessing/adoption; explicit recovery required"));
            }
        }
    }
    // Missing CID is NOT termination. Only metadata-only NoStart histories may
    // outlive their container without contributing an execution claim.
    if journals
        .iter()
        .any(|j| !owned.contains(&j.container) && j.records.iter().any(possible))
    {
        return Err(unknown("possible-running journal CID is absent/foreign to the actual owned census; retain quarantine"));
    }
    Ok(Inventory {
        metadata,
        unresolved,
        owned,
        candidate,
    })
}
fn os_drained(
    store: &Store,
    key: &Key,
    proof: RecoveryOsDrained,
    deadline: Instant,
) -> Result<(), String> {
    if !proof.matches(&key.container, &key.exec, &key.nonce) {
        return Err(unknown(
            "OS drain proof does not bind exact journal lineage",
        ));
    }
    let _cid = store.lock(&Store::stripe(&key.container), deadline, &|| Ok(()))?;
    let _global = store.lock("lock", deadline, &|| Ok(()))?;
    let mut journal = store.read(&key.container)?;
    let row = journal
        .records
        .iter_mut()
        .find(|r| {
            r.nonce == key.nonce && r.exec.as_deref() == Some(&key.exec) && r.owner == key.owner
        })
        .ok_or_else(|| unknown("OS drain row changed/disappeared; no inferred rollback"))?;
    if !possible(row) {
        return Err(unknown("OS drain contradicts execution disposition"));
    }
    row.execution = Some(Execution::OsDrained);
    store.write(&journal)
}

/// Called only AFTER the pass reattests the same current binding and obtains
/// a bounded, validated durable journal snapshot. It can consume an existing
/// retained kernel-exit proof before a missing CID makes the full census fail.
/// Neither the lineage snapshot nor an empty/null/404 observation is a proof.
fn before_census_retained_exit(
    store: &Store,
    cursor: &mut Cursor,
    journals: &[Journal],
    deadline: Instant,
) -> Result<bool, String> {
    let Some(work) = cursor.pending.as_ref() else {
        return Ok(false);
    };
    if work.reference.container != work.key.container
        || work.reference.id != work.key.exec
        || work.reference.nonce != work.key.nonce
    {
        return Err(unknown(
            "retained Reference and durable key do not match; no exit receipt",
        ));
    }
    let matches = journals
        .iter()
        .filter(|journal| journal.container == work.key.container)
        .flat_map(|journal| &journal.records)
        .filter(|row| {
            row.exec.as_deref() == Some(work.key.exec.as_str())
                && row.nonce == work.key.nonce
                && row.owner == work.key.owner
                && possible(row)
        })
        .count();
    if matches != 1 {
        return Err(unknown("retained foreground lacks one exact durable possible-running lineage; retain quarantine"));
    }
    let Some(proof) =
        crate::exec_process::recovery_retained_exit(&work.reference).map_err(unknown)?
    else {
        return Ok(false); // no prior actual pin/live pin NEVER becomes OSDrained
    };
    os_drained(store, &work.key, proof, deadline)?; // locked revalidation + fsync
    cursor.pending = None; // only after the exact proof was durably recorded
    Ok(true)
}
fn run(cluster: &str, node: &str, stop: &AtomicBool) -> Result<(), String> {
    let deadline = Instant::now() + OPERATION;
    let mut engine = adapter::recovery_open(deadline).map_err(unknown)?;
    let binding = engine.binding().map_err(unknown)?;
    let store = Store::open(Path::new(ROOT), binding.clone(), deadline, &|| Ok(()))?;
    let _coordinator = store.dir.lock_named(COORDINATOR)
        .map_err(|_| unknown("another diagnostic coordinator owns this exact daemon journal; this process is read-only for diagnostics"))?;
    #[cfg(target_os = "linux")]
    let current = Owner {
        boot: binding.boot.clone(),
        pid: std::process::id(),
        start: credentials::process_start(std::process::id())?,
    };
    #[cfg(not(target_os = "linux"))]
    return Err(unknown("startup recovery requires Linux process identity"));
    #[cfg(target_os = "linux")]
    {
        let mut cursor = Cursor::default();
        while !stop.load(Ordering::Acquire) {
            let deadline = Instant::now() + OPERATION;
            let pass = (|| -> Result<(), String> {
                engine = adapter::recovery_open(deadline).map_err(unknown)?;
                if engine.binding().map_err(unknown)? != binding {
                    return Err(unknown(
                        "daemon/boot/socket epoch changed; do not reinterpret old charges",
                    ));
                }
                let journals = {
                    let _global = store.lock("lock", deadline, &|| Ok(()))?;
                    store.all()?
                };
                if before_census_retained_exit(&store, &mut cursor, &journals, deadline)? {
                    publish("Draining",Some(journals.iter().map(|journal|journal.records.len()).sum()),None,
                        "retained foreground OS exit fsynced; metadata charged and complete census still required",BTreeSet::new());
                    return Ok(()); // NEVER open Ready from this local proof alone
                }
                let actual = engine.owned_census(cluster, node).map_err(unknown)?;
                let view = inventory(&journals, actual, &current)?;
                cursor.select(view.candidate)?;
                if let Some(work) = cursor.pending.as_ref() {
                    publish("Draining", Some(view.metadata), Some(view.unresolved), "old execution has no user attribution; one exact retained foreground is being checked", BTreeSet::new());
                    if engine.owner_alive(&work.key.owner).map_err(unknown)? {
                        return Err(unknown("old execution owner is still active; no signal or invented shared-user admission; wait for exact owner drain"));
                    }
                    if let Some(proof) = engine.drain(&work.reference).map_err(unknown)? {
                        os_drained(&store, &work.key, proof, deadline)?;
                        cursor.pending = None;
                    }
                    return Ok(()); // zero is established only by a later complete scan
                }
                if view.unresolved != 0 {
                    return Err(unknown(
                        "unattributed recovery backlog remains; no admission",
                    ));
                }
                publish(
                    "Ready",
                    Some(view.metadata),
                    Some(0),
                    "execution backlog cleared; metadata charges/limits still apply",
                    view.owned,
                );
                Ok(())
            })();
            if let Err(error) = pass {
                // SAME pending Reference/pidfd stays owned even on error/timeout.
                publish("Blocked", None, None, error, BTreeSet::new());
            }
            std::thread::sleep(CADENCE);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owner(pid: u32) -> Owner {
        Owner {
            boot: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
            pid,
            start: 10,
        }
    }
    fn row(phase: Phase, execution: Option<Execution>) -> Record {
        Record {
            nonce: "c".repeat(32),
            exec: Some("b".repeat(64)),
            phase,
            owner: owner(100),
            execution,
        }
    }
    fn journal(record: Record) -> Journal {
        Journal {
            version: 2,
            container: "a".repeat(64),
            records: vec![record],
            sweep: 0,
        }
    }
    fn census() -> Vec<Census> {
        vec![Census {
            id: "a".repeat(64),
            execs: vec!["b".repeat(64)],
        }]
    }
    #[test]
    fn old_terminal_is_possible_execution_not_an_os_witness() {
        for phase in [Phase::StartUnknown, Phase::Running, Phase::Terminal] {
            assert!(possible(&row(phase, None)));
        }
        assert!(!possible(&row(Phase::NeverStart, None)));
        assert!(!possible(&row(Phase::UnknownCreate, None)));
        assert!(!possible(&row(Phase::Running, Some(Execution::OsDrained))));
    }
    #[test]
    fn unattributed_old_rows_block_without_a_fabricated_user() {
        let view = inventory(
            &[journal(row(Phase::StartUnknown, None))],
            census(),
            &owner(200),
        )
        .unwrap();
        assert_eq!(view.unresolved, 1);
        assert!(view.candidate.is_some());
        let own = inventory(
            &[journal(row(Phase::StartUnknown, None))],
            census(),
            &owner(100),
        )
        .unwrap();
        assert_eq!(own.unresolved, 0); // current real leases remain process-local
    }
    #[test]
    fn absent_or_foreign_container_does_not_drain_an_old_execution() {
        assert!(inventory(&[journal(row(Phase::Terminal, None))], vec![], &owner(200)).is_err());
    }
    #[test]
    fn unknown_actual_id_cannot_be_joined_by_env_or_empty_disk() {
        assert!(inventory(&[], census(), &owner(200)).is_err());
        let mut wrong = census();
        wrong[0].execs.push("d".repeat(64));
        assert!(inventory(&[journal(row(Phase::NeverStart, None))], wrong, &owner(200)).is_err());
    }
    #[test]
    fn empty_complete_owned_census_is_distinct_from_unknown() {
        let view = inventory(&[], vec![], &owner(200)).unwrap();
        assert_eq!(view.unresolved, 0);
        let closed = Status::default();
        assert_eq!(closed.backlog, None);
        assert_ne!(closed.phase, "Ready");
    }
    #[test]
    fn duplicate_census_or_oversized_journal_is_refused() {
        let mut rows = census();
        rows.push(Census {
            id: "a".repeat(64),
            execs: vec![],
        });
        assert!(inventory(&[journal(row(Phase::NeverStart, None))], rows, &owner(200)).is_err());
        let rows = (0..=CONTAINERS)
            .map(|_| journal(row(Phase::NeverStart, None)))
            .collect::<Vec<_>>();
        assert!(inventory(&rows, vec![], &owner(200)).is_err());
    }
    #[test]
    fn retries_keep_one_reference_and_never_replace_its_lifecycle() {
        let first = Key {
            container: "a".repeat(64),
            exec: "b".repeat(64),
            nonce: "c".repeat(32),
            owner: owner(100),
        };
        let second = Key {
            exec: "d".repeat(64),
            nonce: "e".repeat(32),
            ..first.clone()
        };
        let mut cursor = Cursor::default();
        cursor.select(Some(first.clone())).unwrap();
        let retained = cursor.pending.as_ref().unwrap().reference.clone();
        for _ in 0..100 {
            cursor.select(Some(second.clone())).unwrap();
            cursor.select(None).unwrap(); // failed/partial later inventory cannot release it
            let current = cursor.pending.as_ref().unwrap();
            assert_eq!(current.key, first);
            assert!(Arc::ptr_eq(&current.reference.start, &retained.start));
            assert!(!current.reference.start.never_started()); // no raw NoStart authority
        }
    }
    #[test]
    fn retained_metadata_only_rows_do_not_fabricate_an_old_execution_count() {
        for phase in [Phase::UnknownCreate, Phase::Created, Phase::NeverStart] {
            let view = inventory(&[journal(row(phase, None))], census(), &owner(200)).unwrap();
            assert_eq!(view.metadata, 1);
            assert_eq!(view.unresolved, 0);
            assert!(view.candidate.is_none()); // metadata is STILL charged separately
        }
    }
    #[test]
    fn only_an_explicit_os_disposition_clears_possible_running_classification() {
        let view = inventory(
            &[journal(row(
                Phase::Terminal,
                Some(Execution::PossibleRunning),
            ))],
            census(),
            &owner(200),
        )
        .unwrap();
        assert_eq!(view.unresolved, 1);
        let view = inventory(
            &[journal(row(Phase::Terminal, Some(Execution::OsDrained)))],
            census(),
            &owner(200),
        )
        .unwrap();
        assert_eq!(view.metadata, 1);
        assert_eq!(view.unresolved, 0);
    }

    struct PrivateRoot(std::path::PathBuf);
    impl PrivateRoot {
        fn new() -> Self {
            use std::os::unix::fs::DirBuilderExt;
            let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "rkr2-{}",
                crate::storage_identity::Uid::new().as_str()
            ));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }
    }
    impl Drop for PrivateRoot {
        fn drop(&mut self) {
            for name in [
                "lock".to_string(),
                "binding.json".to_string(),
                "stripe-2a".to_string(),
                Store::filename(&"a".repeat(64)),
            ] {
                match std::fs::remove_file(self.0.join(name)) {
                    Ok(()) => (),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => panic!("exact r2 fixture cleanup failed: {error}"),
                }
            }
            std::fs::remove_dir(&self.0).unwrap();
        }
    }
    fn test_binding() -> Binding {
        Binding {
            boot: owner(100).boot,
            daemon_id: "r2-fixture".into(),
            sender_pid: 100,
            sender_start: 42,
            sender_uid: 0,
            sender_gid: 0,
            sender_exe_dev: 1,
            sender_exe_ino: 7,
            socket_dev: 1,
            socket_ino: 2,
        }
    }
    fn test_deadline() -> Instant {
        Instant::now() + OPERATION
    }
    fn recovery_cursor() -> Cursor {
        let key = Key {
            container: "a".repeat(64),
            exec: "b".repeat(64),
            nonce: "c".repeat(32),
            owner: owner(100),
        };
        let mut cursor = Cursor::default();
        cursor.select(Some(key)).unwrap();
        cursor
    }
    #[test]
    fn cid404_without_a_prior_pin_never_persists_os_drained_or_zero_backlog() {
        let root = PrivateRoot::new();
        let store = Store::open(&root.0, test_binding(), test_deadline(), &|| Ok(())).unwrap();
        store
            .write(&journal(row(
                Phase::Running,
                Some(Execution::PossibleRunning),
            )))
            .unwrap();
        let mut cursor = recovery_cursor();
        let snapshot = store.all().unwrap();
        assert!(inventory(&snapshot, vec![], &owner(200)).is_err()); // actual-CID404 model
        let before = store
            .dir
            .read(&Store::filename(&"a".repeat(64)))
            .unwrap()
            .unwrap();
        assert!(
            !before_census_retained_exit(&store, &mut cursor, &snapshot, test_deadline()).unwrap()
        );
        assert!(cursor.pending.is_some());
        assert_eq!(
            store
                .dir
                .read(&Store::filename(&"a".repeat(64)))
                .unwrap()
                .unwrap(),
            before
        );
        assert!(inventory(&store.all().unwrap(), vec![], &owner(200)).is_err());
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn prior_real_pidfd_exit_can_fsync_os_drained_before_cid404_census_without_metadata_gc() {
        let root = PrivateRoot::new();
        let store = Store::open(&root.0, test_binding(), test_deadline(), &|| Ok(())).unwrap();
        store
            .write(&journal(row(
                Phase::Running,
                Some(Execution::PossibleRunning),
            )))
            .unwrap();
        let mut cursor = recovery_cursor();
        let reference = cursor.pending.as_ref().unwrap().reference.clone();
        let mut actual = crate::exec_process::startup_pin_fixture::Owned::new(reference);
        assert!(Arc::ptr_eq(
            &actual.reference.start,
            &cursor.pending.as_ref().unwrap().reference.start
        ));
        let snapshot = store.all().unwrap();
        assert!(inventory(&snapshot, vec![], &owner(200)).is_err()); // SAME missing-CID observations
        assert!(
            !before_census_retained_exit(&store, &mut cursor, &snapshot, test_deadline()).unwrap(),
            "known-live pidfd is not exit"
        );
        actual.exit(); // kill/reap ONLY the directly owned test child
        assert!(
            before_census_retained_exit(&store, &mut cursor, &snapshot, test_deadline()).unwrap()
        );
        assert!(cursor.pending.is_none());
        let reopened = Store::open(&root.0, test_binding(), test_deadline(), &|| Ok(())).unwrap();
        let durable = reopened.all().unwrap();
        assert_eq!(
            durable[0].records.len(),
            1,
            "OS proof must NOT reclaim Docker metadata"
        );
        assert_eq!(
            durable[0].records[0].phase,
            Phase::Running,
            "no fabricated numeric Terminal"
        );
        assert_eq!(durable[0].records[0].execution, Some(Execution::OsDrained));
        let view = inventory(&durable, vec![], &owner(200)).unwrap();
        assert_eq!(view.unresolved, 0);
        assert_eq!(view.metadata, 1);
        // Ready publication is still separate and requires a NEW complete actual
        // peer-attested census; this unit snapshot cannot open the global gate.
    }
    #[test]
    fn changed_durable_lineage_refuses_pre_census_exit_processing() {
        let root = PrivateRoot::new();
        let store = Store::open(&root.0, test_binding(), test_deadline(), &|| Ok(())).unwrap();
        let mut durable = journal(row(Phase::Running, Some(Execution::PossibleRunning)));
        durable.records[0].owner = owner(300);
        store.write(&durable).unwrap();
        let mut cursor = recovery_cursor();
        let before = store.all().unwrap();
        assert!(
            before_census_retained_exit(&store, &mut cursor, &before, test_deadline()).is_err()
        );
        assert!(cursor.pending.is_some());
        assert_eq!(
            store.all().unwrap()[0].records[0].execution,
            Some(Execution::PossibleRunning)
        );
    }
}
