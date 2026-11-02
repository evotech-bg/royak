# Managed backup/restore runtime — NOT IMPLEMENTED / NOT QUALIFIED

Current-source audit of integrated normal N2, index
`88a477b1f7faa32b43875bafcf0598636e9d212edbbe7044b4294f7cf65b0a87`.
This is a source finding, not a real storage run or a replacement acceptance.

What exists: namespace/claim/volume-bound policy and job models, durable
DesiredState/file/Raft validation, a bounded Restic adapter, and isolated tests.
Native856/Linux883 passing units do not establish the following runtime chain.

| Required runtime part | Current authoritative source |
| --- | --- |
| Ordinary managed backup API and dispatcher | No backup/restore handler or Registry mutation in API/spec/main/reconcile. The offline JSON control-state CLI is a different, deliberately restricted path. |
| Real immutable capture source | `src/storage_driver/capture.rs:44–58` has no production constructor; `source_path_for_worker` always returns an error. The live writable mount cannot substitute for a retained immutable snapshot lease. |
| Commit-before-effect ownership and worker | Registry transition methods exist, but ordinary execution does not durably commit and dispatch them. Restic callers are test-only. Existing isolated journal state is not another production cluster authority. |
| Fresh managed-volume restore | Both `Registry::start` for Restore and `Restic::restore_volume` explicitly refuse until genuine new empty writer-free target authority exists. Fixture directory restore is not a managed-volume receipt. |
| Actual control export and recovery | `ControlExportPreview::export_bytes` and `RecoveryIntent::materialize_desired_state` explicitly refuse; `workloads_may_start` returns false. Independent recovery keys, physical data validation and explicit rebind/cutover adapters remain missing. |

The refusals are required safety boundaries, not flags to switch off. In
particular, final CapturePlan already contains completed snapshot/mount facts:
it cannot authorize creating that same snapshot. A durable pre-capture request
and physical effect owner must precede effects, then bind the genuine completed
source into the immutable plan. No path supplied in JSON, metadata phase, old
attach permit or deserialized descriptor may create that authority.

Implementation must also join rooted process/cgroup ownership and the aggregate
operation deadline, revocation, crash/lost-ack reconciliation, retained source
leases and exact once-only resource retirement. Per-command timeouts and tree
hash equality do not prove those properties or application consistency.

The existing linear-LV/cold guards cannot be weakened to accept arbitrary COW
snapshot graphs. Snapshot topology, real filesystem/DRBD consistency boundaries,
readonly/recovery view, freeze/thaw failure ownership and all three declared
consistency modes require an explicit reviewed backend contract before activation.
Cold-first sequencing is not completion of all modes or the full Storage v1 goal.

Detailed source evidence and proposed dependencies, neither implementation nor
execution authorization:

- [Production path audit](.runs/rkq-storage-20261030/agent-normal-n2-backup-production-path-audit-v1/AUDIT.md), SHA256 `022ee2c929eb6969472a9998499cd05978596e05b99af2d757b91595c0ef2843`.
- [Native capture dependency plan](.runs/rkq-storage-20261030/agent-native-backup-capture-dependency-plan-v1/PLAN.md), SHA256 `ce8bddb70d7a769a1723193060e203940c6da57ba25aba3693e50b75ff613b17`.

Root independently read the hard-refusal source paths, ordinary caller search
and both complete notes. No product guard, constructor, API, backend, permission,
limit or historical result was changed by this finding. No VM/storage action
occurred. The original full LVM/DRBD, identities, fencing, replication, PG,
backup/restore/control-recovery and endurance acceptance remains unchanged.
