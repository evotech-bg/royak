# Quorum/mesh closeout remediation — 2026-10-29

Status: **final exact-build short qualification PASS; fresh two-hour soak
completed and NOT QUALIFIED; not production accepted**. All older soak
evidence, including the two failed two-hour attempts, remains unchanged.

## Reproduced mechanisms

The portable long run's four simultaneous Connect disconnects correlate with a
brief unconfirmed Raft leader in generation 22. The exact cause of that historic
event is not recoverable from its limited log/metrics capture alone.

Two independently reproduced async-blocking mechanisms were still present:

- Mesh routing waited for the synchronous world lock, and called blocking
  Docker APIs, on Tokio workers. The new real TCP routing regression failed
  before the fix: a 30 ms timer resumed after **506.191875 ms** while reconcile
  held the lock for 500 ms.
- Durable Raft vote/log/commit/purge IO still performed synchronous fsync on
  Tokio workers. An explicit test-only 500 ms disk delay reproduced a timer
  stall of **520.333041 ms** before the fix.

These explain how healthy-traffic/reconcile contention can delay heartbeat
work. They do not prove that they are the only source of historic or future
quorum loss. Fresh cross-VM/endurance evidence is required.

## Changes

Mesh route snapshots, owned-pod validation and Docker address lookup now run on
the blocking pool, including sealed peer handoff. World guards are not held
over socket awaits. Ownership checks, namespace/service resolution and sealed
transport behavior are retained.

Durable Raft vote, commit, append, conflict truncation and purge IO now run on
the blocking pool. Success still waits for the real fsync. Log replacement is
published in memory only after its durable rewrite succeeds. State-machine and
snapshot work retain their earlier offloading.

The **1000 ms leader lease, election/heartbeat/RPC/Connect timeouts, stream
limits, RBAC, TLS checks and fail-closed decisions are unchanged**. A regression
explicitly rejects absent/stale quorum confirmation at and beyond 1000 ms.
Bounded leadership metadata now exposes quorum-ack age, term/log index and
poller delay; state changes are logged without state payloads or credentials.

Final soak verification records failed assertions, continues through independent
drain/resource stages and only then raises the failed outcome. Unexpected
traffic/drain exceptions also preserve later resource collection. A dedicated
`connect-drain.json`, nine drain samples and hash-bound review are required;
missing evidence cannot qualify. The smoke-only negative-closeout control
deliberately fails final traffic verification without reducing load or changing
the acceptance thresholds. It can never qualify as a full soak.

## Final CLI correction and fresh candidate

An actual missing-private-Docker-socket test reproduced `royak pull` printing
failure but returning **exit 0**. Its original report, fixture and native
binary are retained under `.runs/rkq-cli-exit-20261029/` and
`.runs/royak-native-quorum-before-cli-20261029`.

Pull failures now exit 1; unknown runtimes are rejected rather than silently
falling back to Docker. NeuroPod/light/CRI pull dispatch does not require a
Docker daemon. Seven actual CLI process cases pass without credentials or
network access, including the non-Docker paths with no `curl` in PATH.
The HTTP suite now includes this negative regression, hash-bound by the
coverage join. Native final client SHA-256:
`1e39366f51ac49263c6f2c55cdab95226169bac3e4e85ab91e6368eea57f9da2`.
Native/Linux Rust remain **260/260**. Python is **31+61** after the acceptance
classification regressions below, natively and on Linux.

This final source change supersedes the intermediate artifact below. Final
normal Linux release SHA-256:
`22297fd61a5b954d0d5fafebcba6c03dc24ca114b9d6d8cdd93dbae9cd9183ec`.
The native client is preserved as `.runs/royak-native-quorum-final-20261029`;
its hash is the final native hash above. Old green joins do not qualify this
candidate. The replacement long soak below completed but is not accepted.

### Final exact-build requalification

- All **15 integration suites PASS, zero skips**, in
  `rkq-suites-20261029-172519-c9ae5c`, `rkq-suites-20261029-172520-0ba350`, and
  `rkq-suites-20261029-172521-06302b`. Real rollout/rollback is 110/110; NeuroPod
  uses the actual public pull path with checked failure exit status.
- Local Connect **54/54 ×3 consecutive**: `rkq-20261029-172522-c48087`,
  `rkq-20261029-172639-1ea8a8`, `rkq-20261029-172751-3ce528`.
- Clean real-VM smoke `rkq-soak-20261029-172525-523bd8`: **44/44 PASS**,
  **360.003246 s actual workload**, all five faults, source/fixtures unchanged.
  All 123 raw resource samples are retained, including nine final drain samples;
  sessions have zero active/open connections and retained caches 0/130/0.
  Raw census has zero sampled zombies and a peak of six container tasks.
  Docker/census counts differ in 11/240 paired, non-atomic observations; this
  does not establish a leak or explain every mismatch. Final census is at two
  tasks/container. The long raw review must retain these disagreements, not
  infer safety from thresholds alone. The resource report passes its short
  bounds, not a long-term leak proof. Minimum observed guest free disk is
  12,498,280,448 bytes; Raft ends at 203,779 apparent bytes per node, with
  allocated sizes retained separately. Audit is observed only on used issuers
  1/2; unused follower 3 is absent/null, not zero audit-growth coverage.
  Cleanup verifies inactive/disabled service, no Royak process, no containers,
  WireGuard or owned fault rules on each guest before shutdown. All three owned
  UUIDs independently verified stopped before being booted for the next tests.
- Actual fault/300s/read-only browser check `rkq-20261029-172951-7da4b2`:
  **13/13 PASS**, 528.145 s. Fresh desktop/mobile captures visually inspected;
  current-source local coverage and Connect joins both PASS.
- Full VM Connect **66/66 ×3 consecutive**: `rkq-20261029-173655-914a5d`,
  `rkq-20261029-173835-0d24d1`, `rkq-20261029-174021-8117a1`. These exercise
  actual remote kernel WireGuard, verified TLS, namespace isolation and closure
  of already-open streams on expiry, revoke, RBAC removal, quorum loss and
  process/backend failure. Each exact run has clean owned cleanup.
- Capacity `rkq-20261029-174214-ca5f00`: **30/30 PASS**, all **12 eight-stream
  cycles** stay live, a ninth stream is refused, and one revoke closes all eight
  in every cycle. This is the unchanged limit, not a reduced-load workaround.
- External LB/fault `rkq-20261029-174349-9b1623`: **31/31 PASS**, 290.737 s;
  verified TLS, stable address, occupied VM hard stop, replacement replicas and
  recovered-backend return all pass. All three current short joins PASS.

The first final VM join incorrectly treated the completed focused capacity run
as a missing full Connect report. The raw run/report is unchanged. The join now
classifies it separately and **adds a mandatory capacity gate**, requiring all
12 cycles, exact current fixture/client and clean cleanup. Missing/malformed,
stale or latest failed capacity evidence cannot pass; a focused pass cannot
substitute for any of the three full Connect repeats. Four new regressions
exercise these cases. The first Linux unit-command attempt omitted a writable
temporary directory with its read-only root; four ledger setup tests errored
before execution. The corrected invocation supplies only a private tmpfs, with
the repository still read-only and networking disabled; no product contract or
test assertion was changed for that invocation error.

Full-duration run **`rkq-soak-20261029-175129-343525`** completed
**7200.016167 s actual workload**, 7273.124965 s total, **52/53 checks**.
Launched 17:51:27 Europe/Sofia, final status 19:52:42; exact PID 7998 is gone.
Launch `.runs/soak-launch-20261029-175127-6f0a74.json`, log with `.log` stem.
The exact pinned client, Linux artifact, unchanged current sources/executed
fixtures and normal release provenance match.

**SOAK-004 / NOT QUALIFIED:** after VM 1 reboot, Royak PID 1418's 170 samples
over 5004.417288 s have thread quartile medians **8→18 (+10)**, exceeding the
unchanged **8** limit. First/last counts are 7/18; a final 1192.084478-second
plateau at 18 is not proof of harmless pool retention or of an unbounded leak.
Thread identities/stacks were not captured. RSS median gain is 4,460,544 bytes,
FD gain 7; both pass their bounds but do not establish an allocation cause.
No limit/timeout/lease/TLS adjustment, product fix or new test was made in
closeout. A separate thread-lifetime/idle-retirement diagnostic is needed and
has **not** been launched.

Direct/LB/Connect each pass **97/97 healthy minutes**; Connect has zero failed
responses there, while direct/LB retain five/three within the 99% contract.
All **92,203 unique acknowledged writes** independently match read-only
SQLite and saved JSON; ten extra rows match ambiguous invoked requests. All
11 faults and 16 unique controls pass, without an exactly-once claim.

Raw review has 732 resource observations, seven Royak/14 container incarnations,
zero sampled zombies, peak ten tasks and 29/1456 non-atomic Docker/census
disagreements. Every container incarnation ends at two sampled tasks. Actual
Raft apparent/allocated sizes, CPU, free disk and audit/log growth were reviewed;
unused follower 2 has absent/null audit, not growth coverage. Canonical resources
and all nine final drain samples survive the failed assertion; active/open
sessions are zero and retained caches 8/0/0. Cleanup verifies all guests empty/
disabled before poweroff, and independent ownership checks find all three UUIDs
stopped without rebooting. No exact host test process/listener, ephemeral LB key
or cleanup error file remains. The hash-bound closeout review matches, but is
`passed: false`; the final soak join remains NOT QUALIFIED. Current three short
joins still PASS, including the separate capacity gate. The terminal heartbeat
`royak-quorum-soak` was deleted. See [full raw review and evidence limits](SOAK-RESULTS-2026-10-29.md).
The stateful production gate remains separately NOT QUALIFIED.

## Intermediate quorum candidate — before the final CLI fix

- Native Rust: **260 passed, zero failed/ignored**; includes plaintext/sealed
  route contention and all five durable Raft write operations.
- Linux Rust: **260 passed, zero failed/ignored** in an owned isolated container.
- Python: **31 base + 57 Parallels checks**, including failure-continuation and
  missing/active/unbounded-cache drain negative cases.
- Normal Linux release: `88169a61f5d399cf13c80950ed7a5f65c99954ee0d1e063289c64a30bfb9a9a8`;
  native CLI: `d383f6a3ef3f722a7aa0499793cefc4999a6fed09657256d440ae4e4d77ee564`.
- Real negative-closeout control `rkq-soak-20261029-162353-9d015b`: **expected
  FAILED**, 44/45 checks; only the explicit intentional assertion failed.
  Actual workload 360.004985 s, all five faults, nine successful drain samples,
  zero active/open sessions, resource bounds pass, source/fixtures unchanged,
  cleanup and all three stopped VM identities independently verified. This is
  evidence of failure closeout, not a successful soak.
- Clean smoke `rkq-soak-20261029-165504-cdb1c3`: **44/44 PASS**, all five faults,
  complete drain/resources, cleanup verified and all three VMs stopped.
- Actual fault/300s/read-only browser check `rkq-20261029-163109-88c824`:
  **13/13 PASS**, 535.175 s. Fresh desktop/mobile captures visually inspected.
- All **15 current integration suites PASS with zero skips**. The two targeted
  repeats are `rkq-suites-20261029-170107-017405` (NeuroPod 22.033 s, demo
  344.569 s); the other 13 pass in `rkq-suites-20261029-162324-319b87`.
- Local Connect **54/54 ×3 consecutive**: `rkq-20261029-170108-94448d`,
  `rkq-20261029-170220-44c79e`, `rkq-20261029-170338-9780c7`. Current local
  Connect and coverage joins are PASS, not older best-pass substitutions.
- Full VM Connect **66/66 ×3 consecutive**: `rkq-20261029-170558-bac3d8`,
  `rkq-20261029-170735-45913b`, `rkq-20261029-170917-6fb817`.
- Capacity `rkq-20261029-171207-2438cb`: all **12 eight-stream cycles pass**;
  ninth streams are refused and each revoke closes all eight streams.
- External LB/fault `rkq-20261029-171438-74a576`: **31/31 PASS**, 290.882 s.

Intermediate failures remain visible. The third initial local Connect repeat
`rkq-20261029-163107-fe591e` failed test-tool installation with an actual Alpine
DNS lookup error; it had zero product assertions and clean owned cleanup.
The first integration run `rkq-suites-20261029-162324-319b87` failed NeuroPod's
OCI cache assertion and three demo rolling/rollback checks. Follow-up records
the public-image pull stdout/stderr; demo rollout now uses two distinct cached
versioned Nginx images (1.28-alpine → 1.29-alpine), retaining real replacement
and rollback checks without a moving `latest` network dependency. Repeats are
required; no old failure is relabelled PASS.

VM Connect attempt `rkq-20261029-170244-a45090` failed before preparation
because its caller had not booted the three guests after the clean smoke's
verified shutdown. The exact owned guests were then explicitly booted and SSH/
Docker readiness checked before fresh complete repeats. That failed setup
record remains; no guest pointer or old run was replaced during its failure.

The user subsequently selected stateful apps/volumes for production. The
[separate stateful gate](STATEFUL-PRODUCTION-GATE.md) is **not qualified**;
replicated storage architecture is awaiting an explicit choice. Network and
external-ledger results cannot be substituted for volume durability/fencing.

No commit, push, release, public-demo or host VPN/route changes are part of this
work. Three VM kernels on one Mac and an external ledger do not establish
physical HA, distributed-volume durability, production certificate lifecycle,
full Kubernetes conformance, absence of all smaller/longer-term leaks or
general production readiness. AI suggestions remain a separate evaluation,
not an autonomous infrastructure actuator.
