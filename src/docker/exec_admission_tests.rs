use super::*;
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

fn binding() -> Binding {
    Binding {
        boot: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".into(),
        daemon_id: "daemon-fixture".into(),
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
fn owner() -> Owner {
    Owner {
        boot: binding().boot,
        pid: 200,
        start: 90,
    }
}
fn cid() -> String {
    "a".repeat(64)
}
fn nonce(n: usize) -> String {
    format!("{n:032x}")
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
struct Root(std::path::PathBuf);
impl Root {
    fn new() -> Self {
        let p = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "rke-admission-{}",
            crate::storage_identity::Uid::new().as_str()
        ));
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(p)
    }
}
impl Drop for Root {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
#[derive(Clone)]
struct Fake {
    shared: Arc<Mutex<State>>,
    path: std::path::PathBuf,
    binding: Binding,
    alive: bool,
}
struct State {
    calls: usize,
    pending: Vec<String>,
    execs: BTreeMap<String, (String, bool, Option<i64>)>,
    exists: bool,
    lose: bool,
    bad_receipt: bool,
    not_submitted: bool,
    census: Option<Vec<String>>,
}
impl Fake {
    fn new(root: &Root) -> Self {
        Self {
            shared: Arc::new(Mutex::new(State {
                calls: 0,
                pending: vec![],
                execs: BTreeMap::new(),
                exists: true,
                lose: false,
                bad_receipt: false,
                not_submitted: false,
                census: None,
            })),
            path: root.0.clone(),
            binding: binding(),
            alive: true,
        }
    }
    fn complete_late(&self) {
        let mut s = self.shared.lock().unwrap();
        for id in std::mem::take(&mut s.pending) {
            s.execs.insert(id, (cid(), false, None));
        }
    }
    fn calls(&self) -> usize {
        self.shared.lock().unwrap().calls
    }
}
impl Engine for Fake {
    fn binding(&mut self) -> Result<Binding, String> {
        Ok(self.binding.clone())
    }
    fn container(&mut self, input: &str) -> Result<Container, String> {
        let s = self.shared.lock().unwrap();
        if !s.exists {
            return Ok(Container::Absent);
        }
        let id = cid();
        if !id.starts_with(input) {
            return Err("fixture exactCID mismatch".into());
        }
        Ok(Container::Present {
            id,
            execs: s.census.clone().unwrap_or_else(|| {
                s.execs
                    .iter()
                    .filter(|(_, (_, _, exit))| exit.is_none())
                    .map(|(id, _)| id.clone())
                    .collect()
            }),
        })
    }
    fn exec(&mut self, id: &str) -> Result<Exec, String> {
        let s = self.shared.lock().unwrap();
        if !s.exists {
            return Ok(Exec::Absent);
        }
        Ok(match s.execs.get(id) {
            Some((container, running, exit)) => Exec::Present {
                id: id.into(),
                container: container.clone(),
                running: *running,
                exit: *exit,
            },
            None => Exec::Absent,
        })
    }
    fn create(&mut self, container: &str, _: &serde_json::Value) -> Result<String, CreateFailure> {
        // Actual on-disk bytes, not the caller's in-memory model, must already
        // contain the unknown charge before this side effect is invoked.
        let store = Store::open(&self.path, self.binding.clone(), deadline(), &|| Ok(()))?;
        let j = store.read(container)?;
        assert_eq!(j.records.last().unwrap().phase, Phase::UnknownCreate);
        assert!(j.records.last().unwrap().exec.is_none());
        let mut s = self.shared.lock().unwrap();
        if s.not_submitted {
            return Err(CreateFailure::NotSubmitted(
                "sender preflight refused before any Create write".into(),
            ));
        }
        s.calls += 1;
        let id = format!("{:064x}", s.calls + 9000);
        if s.lose {
            s.pending.push(id);
            return Err("fake Create lost before daemon registration".into());
        }
        s.execs.insert(id.clone(), (container.into(), false, None));
        if s.bad_receipt {
            return Ok("short".into());
        }
        Ok(id)
    }
    fn owner_alive(&mut self, _: &Owner) -> Result<bool, String> {
        Ok(self.alive)
    }
}
fn create(root: &Root, engine: &mut Fake, n: usize) -> Result<Created, String> {
    create_inner(
        &root.0,
        engine,
        owner(),
        &cid(),
        &nonce(n),
        &serde_json::json!({}),
        deadline(),
        &|| Ok(()),
    )
}
fn journal(root: &Root) -> Journal {
    Store::open(&root.0, binding(), deadline(), &|| Ok(()))
        .unwrap()
        .read(&cid())
        .unwrap()
}
fn sweep_now(root: &Root, engine: &mut Fake) {
    let store = Store::open(&root.0, binding(), deadline(), &|| Ok(())).unwrap();
    let _lock = store
        .lock(&Store::stripe(&cid()), deadline(), &|| Ok(()))
        .unwrap();
    let mut j = store.read(&cid()).unwrap();
    sweep(&store, &mut j, engine, deadline()).unwrap();
}

#[test]
fn before_post_charge_is_durable_and_valid_receipt_joins_exact_id() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let r = create(&root, &mut engine, 1).unwrap();
    let j = journal(&root);
    assert_eq!(j.records.len(), 1);
    assert_eq!(j.records[0].phase, Phase::Created);
    assert_eq!(j.records[0].exec.as_deref(), Some(r.id.as_str()));
    assert_eq!(engine.calls(), 1);
}
#[test]
fn lost_delayed_create_stays_charged_across_restart_and_empty_census() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    engine.shared.lock().unwrap().lose = true;
    assert!(create(&root, &mut engine, 1).unwrap_err().contains("lost"));
    assert!(engine.shared.lock().unwrap().execs.is_empty());
    // A new Royak process/owner and fresh empty census cannot clear the intent.
    let mut restarted = engine.clone();
    let changed = Owner {
        pid: 201,
        start: 91,
        ..owner()
    };
    for n in 2..102 {
        assert!(create_inner(
            &root.0,
            &mut restarted,
            changed.clone(),
            &cid(),
            &nonce(n),
            &serde_json::json!({}),
            deadline(),
            &|| Ok(())
        )
        .unwrap_err()
        .contains("ambiguous Create"));
    }
    assert_eq!(engine.calls(), 1);
    assert_eq!(journal(&root).records.len(), 1);
    engine.complete_late();
    assert_eq!(engine.shared.lock().unwrap().execs.len(), 1);
    assert!(create(&root, &mut restarted, 102).is_err());
    assert_eq!(engine.calls(), 1);
}
#[test]
fn container404_and_daemon_restart_do_not_erase_unknown_global_tombstone() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    engine.shared.lock().unwrap().lose = true;
    assert!(create(&root, &mut engine, 1).is_err());
    engine.shared.lock().unwrap().exists = false;
    assert!(create(&root, &mut engine, 2).is_err());
    assert_eq!(journal(&root).records.len(), 1);
    engine.shared.lock().unwrap().exists = true;
    engine.binding.sender_start += 1;
    assert!(create(&root, &mut engine, 3)
        .unwrap_err()
        .contains("identity/policy changed"));
    assert_eq!(engine.calls(), 1);
    assert_eq!(journal(&root).records.len(), 1);
}
#[test]
fn malformed_create_receipt_is_not_retried_or_joined_by_nonce() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    engine.shared.lock().unwrap().bad_receipt = true;
    assert!(create(&root, &mut engine, 1).is_err());
    assert!(create(&root, &mut engine, 2).is_err());
    assert_eq!(engine.calls(), 1);
    assert_eq!(journal(&root).records[0].phase, Phase::UnknownCreate);
    assert!(journal(&root).records[0].exec.is_none());
}
#[test]
fn unknown_create_is_not_gc_started_and_never_start_is_one_shot() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let r = create(&root, &mut engine, 1).unwrap();
    transition(&root.0, &r, Phase::NeverStart, deadline()).unwrap();
    assert!(transition(&root.0, &r, Phase::StartUnknown, deadline()).is_err());
    sweep_now(&root, &mut engine);
    assert_eq!(engine.calls(), 1);
    assert_eq!(journal(&root).records.len(), 1);
}
#[test]
fn start_unknown_null_and_container404_keep_capacity_after_owner_dies() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let r = create(&root, &mut engine, 1).unwrap();
    transition(&root.0, &r, Phase::StartUnknown, deadline()).unwrap();
    engine.alive = false;
    sweep_now(&root, &mut engine);
    assert_eq!(journal(&root).records[0].phase, Phase::StartUnknown);
    assert_eq!(engine.calls(), 1);
    engine.shared.lock().unwrap().exists = false;
    sweep_now(&root, &mut engine);
    assert_eq!(journal(&root).records.len(), 1);
}
#[test]
fn numeric_terminal_and404_cannot_erase_possible_running_history() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let r = create(&root, &mut engine, 1).unwrap();
    transition(&root.0, &r, Phase::StartUnknown, deadline()).unwrap();
    engine
        .shared
        .lock()
        .unwrap()
        .execs
        .get_mut(&r.id)
        .unwrap()
        .2 = Some(0);
    sweep_now(&root, &mut engine);
    assert_eq!(journal(&root).records[0].phase, Phase::Terminal);
    engine.shared.lock().unwrap().exists = false;
    let store = Store::open(&root.0, binding(), deadline(), &|| Ok(())).unwrap();
    let mut j = store.read(&cid()).unwrap();
    sweep(&store, &mut j, &mut engine, deadline()).unwrap();
    assert_eq!(journal(&root).records.len(), 1);
    // Container is back in the fake only to model the distinct real proof:
    // exact exec404 followed by fresh exact container200. No clock involved.
    {
        let mut state = engine.shared.lock().unwrap();
        state.exists = true;
        state.execs.remove(&r.id);
    }
    sweep_now(&root, &mut engine);
    assert_eq!(
        journal(&root).records.len(),
        1,
        "metadata absence cannot erase execution accounting"
    );
    // Explicit private serialization MODEL only. The actual producer of this
    // disposition must consume an opaque kernel proof, tested separately.
    let mut j = store.read(&cid()).unwrap();
    j.records[0].execution = Some(Execution::OsDrained);
    store.write(&j).unwrap();
    sweep_now(&root, &mut engine);
    assert!(journal(&root).records.is_empty());
}
#[test]
fn create_sweep_never_signals_orphans_outside_the_fixed_recovery_worker() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let r = create(&root, &mut engine, 1).unwrap();
    transition(&root.0, &r, Phase::StartUnknown, deadline()).unwrap();
    engine
        .shared
        .lock()
        .unwrap()
        .execs
        .get_mut(&r.id)
        .unwrap()
        .1 = true;
    sweep_now(&root, &mut engine);
    assert!(engine.shared.lock().unwrap().execs[&r.id].1);
    engine.alive = false;
    sweep_now(&root, &mut engine);
    assert!(engine.shared.lock().unwrap().execs[&r.id].1);
    assert_eq!(journal(&root).records.len(), 1);
}
#[test]
fn dead_creator_without_start_may_be_never_started_but_metadata_still_counts() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let _r = create(&root, &mut engine, 1).unwrap();
    engine.alive = false;
    sweep_now(&root, &mut engine);
    assert_eq!(journal(&root).records[0].phase, Phase::NeverStart);
    assert_eq!(journal(&root).records.len(), 1);
    assert_eq!(engine.calls(), 1);
}
#[test]
fn missing_binding_nonempty_store_and_corrupt_journal_fail_before_post() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let dir = private_io::Dir::open(&root.0, false).unwrap();
    dir.write("unrecognized", b"old evidence").unwrap();
    assert!(create(&root, &mut engine, 1).is_err());
    assert_eq!(engine.calls(), 0);
    assert_eq!(dir.read("unrecognized").unwrap().unwrap(), b"old evidence");
    dir.remove("unrecognized").unwrap();
    let r = create(&root, &mut engine, 2).unwrap();
    let mut raw = serde_json::to_value(journal(&root)).unwrap();
    raw["records"][0]["owner"]
        .as_object_mut()
        .unwrap()
        .remove("start");
    dir.write(
        &Store::filename(&r.container),
        &serde_json::to_vec(&raw).unwrap(),
    )
    .unwrap();
    assert!(create(&root, &mut engine, 3).is_err());
    assert_eq!(engine.calls(), 1);
}
#[test]
fn independent_process_reopens_durable_unknown_instead_of_resetting_cache() {
    const KEY: &str = "ROYAK_EXEC_ADMISSION_RESTART_FIXTURE";
    if let Some(path) = std::env::var_os(KEY) {
        let root = Root(std::path::PathBuf::from(path));
        let mut engine = Fake::new(&root);
        assert!(create(&root, &mut engine, 2)
            .unwrap_err()
            .contains("ambiguous Create"));
        assert_eq!(engine.calls(), 0);
        std::mem::forget(root);
        return;
    }
    let root = Root::new();
    let mut engine = Fake::new(&root);
    engine.shared.lock().unwrap().lose = true;
    assert!(create(&root, &mut engine, 1).is_err());
    let full = format!(
        "{}::independent_process_reopens_durable_unknown_instead_of_resetting_cache",
        module_path!()
    );
    let test = full.split_once("::").unwrap().1;
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(KEY, &root.0)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(journal(&root).records.len(), 1);
}
#[test]
fn conservative_actual_plus_durable_bound_and_no_unresolved_eviction() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let store = Store::open(&root.0, binding(), deadline(), &|| Ok(())).unwrap();
    let records = (0..PER_CONTAINER - 1)
        .map(|i| Record {
            nonce: nonce(i + 10),
            exec: Some(format!("{:064x}", i + 100)),
            phase: Phase::NeverStart,
            owner: owner(),
            execution: None,
        })
        .collect();
    store
        .write(&Journal {
            version: 1,
            container: cid(),
            records,
            sweep: 0,
        })
        .unwrap();
    {
        let mut state = engine.shared.lock().unwrap();
        state.census = Some(vec!["d".repeat(64)]);
        for i in 0..8 {
            state
                .execs
                .insert(format!("{:064x}", i + 100), (cid(), false, None));
        }
    }
    assert!(create(&root, &mut engine, 1)
        .unwrap_err()
        .contains("metadata guard exhausted"));
    assert_eq!(engine.calls(), 0);
    assert_eq!(journal(&root).records.len(), PER_CONTAINER - 1);
}
#[test]
fn per_cid_stripes_and_global_admission_are_shared_by_distinct_store_handles() {
    let root = Root::new();
    let one = Store::open(&root.0, binding(), deadline(), &|| Ok(())).unwrap();
    let two = Store::open(&root.0, binding(), deadline(), &|| Ok(())).unwrap();
    let held = one
        .lock(&Store::stripe(&cid()), deadline(), &|| Ok(()))
        .unwrap();
    assert!(two
        .lock(&Store::stripe(&cid()), Instant::now(), &|| Ok(()))
        .is_err());
    drop(held);
    assert!(two
        .lock(&Store::stripe(&cid()), deadline(), &|| Ok(()))
        .is_ok());
}

#[test]
fn global_guard_counts_other_container_histories_without_resetting_them() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let store = Store::open(&root.0, binding(), deadline(), &|| Ok(())).unwrap();
    for container in 0..NODE_RECORDS / PER_CONTAINER {
        let records = (0..PER_CONTAINER)
            .map(|i| {
                let n = container * PER_CONTAINER + i + 100;
                Record {
                    nonce: nonce(n),
                    exec: Some(format!("{n:064x}")),
                    phase: Phase::NeverStart,
                    owner: owner(),
                    execution: None,
                }
            })
            .collect();
        store
            .write(&Journal {
                version: 1,
                container: format!("{:064x}", container + 1),
                records,
                sweep: 0,
            })
            .unwrap();
    }
    assert!(create(&root, &mut engine, 1)
        .unwrap_err()
        .contains("metadata guard exhausted"));
    assert_eq!(engine.calls(), 0);
    assert_eq!(
        store
            .all()
            .unwrap()
            .iter()
            .map(|j| j.records.len())
            .sum::<usize>(),
        NODE_RECORDS
    );
}

#[test]
fn malformed_or_duplicated_actual_census_refuses_before_create() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    engine.shared.lock().unwrap().census = Some(vec!["b".repeat(64), "b".repeat(64)]);
    assert!(create(&root, &mut engine, 1).is_err());
    assert_eq!(engine.calls(), 0);
    assert!(journal(&root).records.is_empty());
}

#[test]
fn cancelled_before_post_has_control_flow_no_post_proof_not_ambiguous_rollback() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let flag = std::sync::atomic::AtomicBool::new(false);
    let path = root.0.clone();
    let cancelled = || {
        // Refuse only after observing the actual fsynced unknown intent. This
        // branch is synchronously before Engine::create, not timeout inference.
        if let Ok(raw) = std::fs::read(path.join(Store::filename(&cid()))) {
            let j: Journal = serde_json::from_slice(&raw).unwrap();
            if j.records.iter().any(|r| r.phase == Phase::UnknownCreate) {
                flag.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err("cancelled".into());
            }
        }
        Ok(())
    };
    assert_eq!(
        create_inner(
            &root.0,
            &mut engine,
            owner(),
            &cid(),
            &nonce(1),
            &serde_json::json!({}),
            deadline(),
            &cancelled
        )
        .unwrap_err(),
        "cancelled"
    );
    assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(engine.calls(), 0);
    assert!(journal(&root).records.is_empty());
}

#[test]
fn explicit_no_post_witness_can_retire_a_reserved_but_unsubmitted_start() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let receipt = create(&root, &mut engine, 1).unwrap();
    transition(&root.0, &receipt, Phase::StartUnknown, deadline()).unwrap();
    assert!(transition(&root.0, &receipt, Phase::NeverStart, deadline()).is_err());
    abort_before_post(&root.0, &receipt, deadline()).unwrap();
    assert_eq!(journal(&root).records[0].phase, Phase::NeverStart);
    assert_eq!(engine.calls(), 1);
}

#[test]
fn typed_preflight_no_post_does_not_become_an_ambiguous_create_or_sticky_freeze() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    engine.shared.lock().unwrap().not_submitted = true;
    assert!(create(&root, &mut engine, 1)
        .unwrap_err()
        .contains("before any Create write"));
    assert_eq!(engine.calls(), 0);
    assert!(journal(&root).records.is_empty());
    engine.shared.lock().unwrap().not_submitted = false;
    create(&root, &mut engine, 2).unwrap();
    assert_eq!(engine.calls(), 1);
}

#[test]
fn v3_listener_authority_header_is_quarantined_not_silently_reinterpreted() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let store = Store::open(&root.0, binding(), deadline(), &|| Ok(())).unwrap();
    let old=serde_json::to_vec(&serde_json::json!({"version":1,"binding":{"boot":binding().boot,"daemon_id":"daemon-fixture","peer_pid":100,"peer_start":42,"socket_dev":1,"socket_ino":2},"per_container":PER_CONTAINER,"node_records":NODE_RECORDS,"containers":CONTAINERS})).unwrap();
    store.dir.write("binding.json", &old).unwrap();
    assert!(create(&root, &mut engine, 1).is_err());
    assert_eq!(engine.calls(), 0);
    assert_eq!(store.dir.read("binding.json").unwrap().unwrap(), old);
}

#[test]
fn journal_v1_missing_execution_stays_unknown_after_exact_decode_and_v2_write() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let receipt = create(&root, &mut engine, 1).unwrap();
    transition(&root.0, &receipt, Phase::StartUnknown, deadline()).unwrap();
    let store = Store::open(&root.0, binding(), deadline(), &|| Ok(())).unwrap();
    let mut raw = serde_json::to_value(journal(&root)).unwrap();
    raw["version"] = serde_json::json!(1);
    raw["records"][0]
        .as_object_mut()
        .unwrap()
        .remove("execution");
    let bytes = serde_json::to_vec(&raw).unwrap();
    store.dir.write(&Store::filename(&cid()), &bytes).unwrap();
    let decoded = store.read(&cid()).unwrap();
    assert_eq!(decoded.records[0].execution, None);
    assert_eq!(decoded.records[0].phase, Phase::StartUnknown);
    assert_eq!(
        store.dir.read(&Store::filename(&cid())).unwrap().unwrap(),
        bytes
    );
    store.write(&decoded).unwrap();
    let reopened = store.read(&cid()).unwrap();
    assert_eq!(reopened.version, 2);
    assert_eq!(
        reopened.records[0].execution, None,
        "migration cannot mint NoStart/OsDrained"
    );
}

#[test]
fn old_domain_execution_smuggling_and_contradictory_current_lineage_are_refused() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let receipt = create(&root, &mut engine, 1).unwrap();
    transition(&root.0, &receipt, Phase::StartUnknown, deadline()).unwrap();
    let store = Store::open(&root.0, binding(), deadline(), &|| Ok(())).unwrap();
    let base = serde_json::to_value(journal(&root)).unwrap();
    for (version, phase, execution) in [
        (1, "StartUnknown", "OsDrained"),
        (1, "Created", "NoStart"),
        (2, "StartUnknown", "NoStart"),
        (2, "NeverStart", "OsDrained"),
        (2, "Created", "PossibleRunning"),
    ] {
        let mut raw = base.clone();
        raw["version"] = serde_json::json!(version);
        raw["records"][0]["phase"] = serde_json::json!(phase);
        raw["records"][0]["execution"] = serde_json::json!(execution);
        let bytes = serde_json::to_vec(&raw).unwrap();
        store.dir.write(&Store::filename(&cid()), &bytes).unwrap();
        assert!(store.read(&cid()).is_err(), "{version}/{phase}/{execution}");
        assert_eq!(
            store.dir.read(&Store::filename(&cid())).unwrap().unwrap(),
            bytes
        );
    }
    assert_eq!(
        engine.calls(),
        1,
        "failed disk decode must not submit another command"
    );
}

#[test]
fn os_drained_disposition_and_real_metadata_absence_do_not_need_numeric_exit_fabrication() {
    let root = Root::new();
    let mut engine = Fake::new(&root);
    let receipt = create(&root, &mut engine, 1).unwrap();
    transition(&root.0, &receipt, Phase::StartUnknown, deadline()).unwrap();
    let store = Store::open(&root.0, binding(), deadline(), &|| Ok(())).unwrap();
    let mut raw = store.read(&cid()).unwrap();
    // Private serialization model, NOT an OS proof producer. In production
    // os_drained accepts only an opaque exact retained-pidfd exit proof.
    raw.records[0].execution = Some(Execution::OsDrained);
    store.write(&raw).unwrap();
    engine.shared.lock().unwrap().execs.remove(&receipt.id);
    engine.shared.lock().unwrap().exists = false;
    let mut raw = store.read(&cid()).unwrap();
    assert!(sweep(&store, &mut raw, &mut engine, deadline()).is_err());
    assert_eq!(
        store.read(&cid()).unwrap().records.len(),
        1,
        "CID404 is not metadata absence"
    );
    engine.shared.lock().unwrap().exists = true;
    sweep_now(&root, &mut engine);
    assert!(journal(&root).records.is_empty());
}
