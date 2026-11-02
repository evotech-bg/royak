# Longer three-VM soak — 2026-10-29

## Current quorum/mesh candidate — completed, NOT QUALIFIED

Run **`rkq-soak-20261029-175129-343525`** completed **7200.016167 s actual
workload**, **7273.124965 s total runner time**. The original result is
**52/53 checks, FAILED**. Its final status was written **2026-10-29 19:52:42
Europe/Sofia**; exact runner PID **7998**, launched 17:51:27, is gone.
Launch record `.runs/soak-launch-20261029-175127-6f0a74.json`, log with the same
stem and `.log`. Exact Linux binary SHA-256 is
`22297fd61a5b954d0d5fafebcba6c03dc24ca114b9d6d8cdd93dbae9cd9183ec`,
pinned native client `.runs/royak-native-quorum-final-20261029` SHA-256 is
`1e39366f51ac49263c6f2c55cdab95226169bac3e4e85ab91e6368eea57f9da2`;
Caddy remains `0d746e47f39d9706883b3633bf419feb25973e6caaa8eabbf5b44421d59e3973`.
Source/fixture hashes, unchanged normal release provenance and all three
artifact hashes match. The additional raw `closeout-review.json` has
`passed: false`, matches its resources/report/drain/cleanup evidence hashes,
and the final strict soak join is **NOT QUALIFIED**. The terminal heartbeat
`royak-quorum-soak` was deleted after closeout; it will not keep polling.

### SOAK-004: post-restart Royak thread growth

The one failed runner assertion is the unchanged same-incarnation resource
bound. VM 1, boot `6c403f90-988f-443a-9728-4b4f72a0a6d9`, Royak PID **1418**,
start tick **779**, has 170 samples over **5004.417288 s**. First/last quartile
thread medians are **8 → 18**, a gain of **10**, above the declared **8** limit.
Its first/last counts are 7/18. The count plateaus at 18 from elapsed
6060.296556 through 7252.381034 (**1192.084478 s**); this does not prove
unbounded leakage, but cannot override a failed predeclared bound.

The same incarnation's RSS medians are 10,317,824 → 14,778,368 bytes
(+4,460,544), FD medians 14 → 21 (+7). Those pass their bounds, but the small
RSS gain is not attributed to a specific allocation. Source uses blocking-pool
offloading; without per-thread identities/stacks and an idle-retirement capture
we cannot establish whether retained pool workers, another worker class or a
leak caused the thread growth. No product fix, threshold/timeout/lease/TLS
relaxation or repeat was performed during closeout.

Per-incarnation review never merges a restart into an older baseline. CPU is
Royak's own Linux utime/stime, not Docker workload CPU:

| VM / PID | Samples / span s | Median RSS gain bytes | FD gain | Thread gain | Mean / peak CPU, % one core |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 / 3952 | 32 / 930.2 | 1,505,280 | 1.5 | 0 | 8.43 / 8.93 |
| 2 / 60798 | 244 / 7222.9 | 1,847,296 | 0 | 5 | 9.01 / 12.80 |
| 3 / 26737 | 132 / 3930.5 | 3,497,984 | 0 | 3 | 7.39 / 11.75 |
| 1 / 26007 | 39 / 1140.1 | 2,617,344 | 3 | 2 | 7.09 / 8.96 |
| 1 / 1418 | 170 / 5004.4 | 4,460,544 | 7 | **10 — FAIL** | 4.91 / 9.93 |
| 3 / 309720 | 39 / 1140.3 | 2,719,744 | 5 | 3 | 6.99 / 8.33 |
| 3 / 1435 | 70 / 2002.1 | 770,048 | -1 | 2 | 1.30 / 1.46 |

A separately authorized follow-up should capture Royak thread identity/state
and lifetime through the same restart/load/idle transition, preserve these
limits, and distinguish bounded pool growth from leaked workers. That test is
**not started** by this monitor.

### Traffic, repeated faults and data

All **11 faults** completed: three pod kills and two each leader SIGKILL,
control partition, occupied-VM hard stop and WireGuard-only interruption.
Every path passes **97/97 complete healthy minutes**. Connect has zero failed
responses in those windows; direct has five and LB three, still within the
unchanged 99% contract (worst minute 99.1701% direct / 99.5885% LB).
Fault and partial/recovery windows are not relabelled healthy or lossless.

| Path | Acknowledged / attempts | Failed or ambiguous |
| --- | ---: | ---: |
| Direct | 32,011 / 32,234 | 223 |
| External LB | 31,894 / 31,904 | 10 |
| Native Connect | 28,298 / 28,663 | 365 |

Independent offline reconciliation checked returned IDs/values and every
acknowledgement against both the saved ledger JSON and a read-only SQLite
connection: **92,203 unique acknowledged writes, zero acknowledged loss or
corruption**. All 28,298 Connect acknowledgements prove a remote VM backend.
The ledger has 92,213 rows; its **10 extra** entries match invoked ambiguous
requests and values. This is not exactly-once delivery. Session opening has
665 successes and 58 separate failed attempts. Sixteen unique control names
are acknowledged in raw history; the runner's final live GET loop checks all
16 on every node and passes. Those complete GET responses were not archived,
so stopped guests were not booted for an invented offline replay.

### Raw resources, drain and cleanup

There are **732 resource observations**, seven Royak and 14 container
incarnations. Four samples are explicitly unavailable during hard stops; two
others observe no Royak process during SIGKILL. Missing is not zero. Census
has **zero sampled zombies**, peak **10 tasks**; every container incarnation's
last observation is two tasks. The final nine drain samples cover all three
nodes and six containers, each at two tasks with no zombies/OOM. All 14
container trends pass their declared bounds.

Docker/census disagree in **29/1456** paired observations. They are sampled
sequentially, not atomically. Census captures Python request threads and brief
runc/sh activity; no persistent zombie accumulation is seen and final counts
return to baseline. Exact inter-instant discrepancies remain visible rather
than asserted to be fully explained or automatically labelled a leak.

Royak RSS peaks are **14,946,304 / 13,815,808 / 15,007,744 bytes** on VM 1/2/3;
FD peaks 29/36/30 and thread peaks 18/18/15. Minimum guest free disk is
**12,436,520,960 bytes**. Actual Raft directories finish at **325,247 apparent
bytes each**, allocated **339,968 / 344,064 / 339,968**. Full sampled Royak log
sizes finish **484,052 / 301,317 / 417,174 bytes**; archived node logs are only
150,000-byte tails. Audit ends at 196,057 bytes on issuer 1 and 159,440 on
issuer 3. First durable grants occur at 27.634413/991.556963 s. The 244 absent
follower-2 observations and 33 pre-first-grant follower-3 observations are
legitimate absent/null, not zero growth or follower-2 audit coverage. No
illegal disappearance is observed; `audit_history_sha256` matches the actual
history. Append growth is bounded for this run; rotation/long-term retention
is not qualified. The unchanged four-case BusyBox/Dash × init/no-init watchdog
component matrix still matches its fixture/source hashes and has clean
cleanup; that is not full Debian-cluster qualification.

After workers stop, the canonical resource report retains three final drain
samples per node despite the failed resource assertion. Connect has **zero
active/open sessions** everywhere, retained cache **8/0/0**. Guest-wide TCP
ESTAB still includes Raft/SSH/control connections, and TIME-WAIT is explicitly
retained; these totals are not called leaked Connect sockets. Live host review
finds no exact runner/Caddy/native client/ledger or owned SSH forwarding
processes and no listener on the 661 observed client/LB ports or ledger address.
The ephemeral LB key and `cleanup.jsonl` are absent.

All three pre-poweroff cleanup records verify inactive/disabled qualification
service, no exact Royak process, **zero containers**, no rkconn WireGuard or
owned fault rules. Ownership-checked UUIDs
`29cbe522-6829-412f-a480-ab52283a1158`,
`1752e81e-a541-4099-a054-842f71f3cc64`, and
`12422c3b-1e89-444b-8faf-426d2da0b15e` independently verify **stopped**, without
being restarted for review. Current coverage/local-Connect/VM joins, including
the mandatory 12-cycle capacity gate, still PASS for this exact artifact.

Residual synchronous mesh/Docker and durable Raft IO were moved off async
workers after real contention/disk-delay regressions. The 1000 ms quorum lease,
limits and TLS checks remain unchanged. Final failure verification now continues
through drain/resources before reporting failure; the real negative control
demonstrates that behavior without relabelling it a successful soak.

The final candidate's short VM smoke is **44/44**, 360.003246 s actual workload,
with nine drain samples, zero active/open sessions, complete resource report
and independently verified cleanup/poweroff. A short pass is not two-hour
acceptance. See [exact candidate and fresh qualification](QUORUM-REMEDIATION-2026-10-29.md).
Stateful volume durability/fencing remains a separate **NOT QUALIFIED**
production gate. Three VMs on one Mac, external application storage and
self-signed lab TLS do not establish physical-host HA, distributed-volume
durability, production certificate lifecycle, full Kubernetes conformance or
absence of every smaller/longer-term leak. All historical failures below and
all original raw reports remain unchanged. No rerun, product/fixture mutation,
commit, push, public-demo or host VPN/route change was made in closeout.

## Historical portable replacement — completed, NOT QUALIFIED

The two-hour workload `rkq-soak-20261029-134929-6648c9` completed **7200.008273
seconds of actual workload**, not the post-cleanup elapsed counter. Total runner
time was 7252.596088 seconds. Its final status was written at **15:50:21
Europe/Sofia**; runner PID 73798 is gone. Launch record:
`.runs/soak-launch-20261029-134927-8cc469.json`.

The original final runner result is **46/47 checks, FAILED**. Independent raw
review is recorded in that run's `closeout-review.json`, with `passed: false`.
The strict latest-full-attempt join `.runs/current-soak-acceptance.json` remains
**NOT QUALIFIED**. No earlier short pass substitutes for this result.

Exact normal-release Linux ARM64 binary:
`c46e57ff0146eb1be31b1f28bc0e3eab78467abd42196c1e5e2b825394462336`.
Native CLI:
`445f8e959a07dc5759237a5f075d1a8867f39323f1006b1cc0b614f9a2b36a91`.
Caddy:
`0d746e47f39d9706883b3633bf419feb25973e6caaa8eabbf5b44421d59e3973`.
Current sources, executed fixtures, build provenance and all three artifact
hashes match. Normal release flags and frozen-source execution are verified.
The required short gates already pass:
256 native/Linux Rust, 85 native/Linux Python checks, all 15 zero-skip suites,
local Connect 54/54 ×3, actual fault/UI 13/13, VM Connect 66/66 ×3, 12 eight-stream
capacity cycles, LB/fault 31/31 and portable VM smoke 43/43. The real BusyBox/Dash
matrix is also clean, including no-init timer cleanup and init hard deadlines.
These shorter results do not substitute for two-hour resource behavior. The
watchdog matrix's current fixture/source hashes were independently checked:
all four BusyBox/Dash × init/no-init cases pass, 320 fast commands, zero final
zombies and no cleanup errors. This is not a full Debian cluster qualification.

### SOAK-003: unsolicited Connect interruption in a healthy minute

Direct and LB each pass **95/95** complete healthy one-minute windows. Connect
passes **94/95**. In elapsed **3240–3300 seconds**, it served **232/236 (98.305%)**,
below the unchanged 99% contract. There are **no empty healthy minutes**; the
runner assertion's broad name does not describe the exact failure.

All four failures are `RemoteDisconnected` at elapsed **3266.800514–3267.034902**,
issuer VM 2 to backend `q-n3`, with no overlapping injected fault. At elapsed
3267.044984, raw Raft telemetry shows VM 2 still leader in generation 22 but
`leaderConfirmed: false`; it is confirmed again at 3269.058521. Connect code
closes active streams when authoritative/quorum leadership is not confirmed.
That is consistent with fail-closed protection, not evidence that protection
should be removed. The cause of the unsolicited confirmation loss is **not
proven**. Nearby direct requests are 27/27 and LB 26/26 successful.

### Data and repeated faults

All three histories were independently checked offline, and the saved ledger
JSON exactly matches the read-only SQLite database: **84,035 acknowledged
writes, zero lost/corrupt acknowledgements**, 84,038 ledger rows. The three
extra rows all correspond to invoked but ambiguous/failed requests; there is
no exactly-once claim.

| Path | Acknowledged / attempts | Failed or ambiguous |
| --- | ---: | ---: |
| Direct | 27,979 / 28,190 | 211 |
| External LB | 27,850 / 27,863 | 13 |
| Native Connect | 28,206 / 28,476 | 270 |

All 28,206 Connect acknowledgements prove a backend on a different VM. Session
opening had 566 successes and 76 separate failed attempts. Sixteen acknowledged
control writes converged. Offline counting confirms **11 completed faults**:
pod kill 3, leader SIGKILL 2, control partition 2, whole-VM hard stop/restart 2,
WireGuard-only loss 2. Both VM restarts changed boot IDs and preserved trusted
TLS identities; final LB rotation includes all three ingresses. WireGuard loss
fails closed; neither isolated minority acknowledged the rejected write.

Final ten-minute responses: direct **2400/2400**, LB **2377/2377**, Connect
**2382/2382**. Across whole-VM hard-stop windows LB served **528/535 (98.69%)**.
Final p50/p95/p99 latency (ms, nearest-rank): direct 221.821/432.792/608.816,
LB 223.791/437.025/588.975, Connect 23.812/323.687/562.331. These closed-loop
one-Mac observations are not a production availability or capacity SLO.

### Raw resources and missing final drain

There are **723 resource samples**, 241 per VM; usable Royak-process samples
are **237 / 240 / 239**, with five unavailable samples and additional missing
process readings during faults. Seven process incarnations and 14 container
incarnations were reviewed separately. No restart is merged into an old trend.

| VM | Royak peak RSS | Peak → final FDs | Peak → final threads | Minimum free disk, bytes |
| --- | ---: | ---: | ---: | ---: |
| 1 | 12.6875 MiB | 31 → 15 | 14 → 14 | 12,616,839,168 |
| 2 | 13.5977 MiB | 34 → 17 | 14 → 13 | 12,726,972,416 |
| 3 | 12.1523 MiB | 43 → 18 | 14 → 8 | 12,729,651,200 |

Actual Royak CPU, calculated from its own CPU ticks by incarnation, has mean
**1.45–7.06% of one core** and maximum interval **9.9943%**; this is not Docker
application CPU. RSS quartile medians still rise: the largest gain is
**2,977,792 bytes**; FD median gain peaks at 7 and thread median gain at 6.
Late growth slows/plateaus in long-lived processes, but allocations are not
attributed. **SOAK-006:** smaller unexplained growth and absent drain preclude
a leak-free claim even though the existing bounds pass offline.

There are **zero observed zombie samples**, peak 10 container tasks, no OOM,
and six final running containers distributed 2/3/1, each at two tasks. The old
hundreds-of-PIDs pattern is not reproduced. **SOAK-005:** Docker PIDs and census
tasks differ in **33/1438** comparisons, at most two consecutive samples and
absolute difference 6. Collection is non-atomic; raw census captures transient
Python threads and `runc:[2:INIT]` tasks. Final counters agree at two tasks.
This is a retained measurement limitation, not an exact reconciliation proof.

The actual Raft directory grows from **107,219 to 325,159 apparent bytes** on
each VM; final allocated bytes are **339,968 / 339,968 / 344,064**. Missing
`/lab/state.json` remains null, not zero. Final logs are **428,124 / 429,654 /
331,730 bytes**. Audit files end at **82,792 / 238,566 / absent**: VM 1 first
issued a grant at elapsed 27.908254, VM 2 at 991.973182. VM 2's 33 earlier
absences are legitimate; VM 3 never issued a grant, so there is **no audit-growth
coverage on VM 3**. Audit history is hash-bound in `closeout-review.json`.
Root free space declines **18.0625 / 1.75 / 17.793 MiB**. Raft/log/audit growth
is retained under real writes; long-term retention/compaction is not qualified.

**SOAK-004:** the continuity assertion aborts verification before final drain,
session/socket/cache queries and `resource-report.json` generation. Therefore
there are **zero drain samples** and no canonical resource report. Its hash in
the review is explicitly null; no report is backfilled. Offline execution of
the unchanged resource checker passes its bounds, but cannot replace missing
drain evidence. Last ordinary guest-wide CLOSE-WAIT counts are **0/1/1** and
ESTAB **4/5/6**; these are not attributed Connect counts. Native clients stopped
without forced-kill leftovers, but graceful session/cache release is unqualified.

### Cleanup and next acceptance boundary

`cleanup-verification.json` proves on all three guests, **before poweroff**:
inactive/disabled service, no exact Royak process, no containers of any kind,
no `rkconn` and no owned fault rules. `cleanup.jsonl` and `lb.key` are absent.
Live host review finds no exact runner/Caddy/SSH/ledger/native-client processes,
no LB listener on 127.0.0.1:63727, and no ledger listener on port 8000.
Ownership-checked UUIDs **29cbe522-6829-412f-a480-ab52283a1158**,
**1752e81e-a541-4099-a054-842f71f3cc64** and
**12422c3b-1e89-444b-8faf-426d2da0b15e** are independently **stopped**. They were
not restarted for review. Cleanup does not retrospectively prove logical drain.

The terminal monitor `royak-portable-soak` is stopped at closeout. No new test,
product/fixture/limit/timeout/TLS change, commit or push was performed. Local
changes, original reports, histories and all intermediate failures are preserved;
the public demo and host VPN/routes were untouched.

Next separately authorized work: diagnose transient unconfirmed leadership and
its Connect interruption without weakening fail-closed behavior; ensure failure
closeout still captures drain/resource evidence; then repeat focused and long
qualification. **This run remains NOT QUALIFIED.** Three VMs on one Mac, an
external ledger and self-signed lab certificates do not establish physical HA,
distributed-volume durability, production certificate lifecycle, full Kubernetes
conformance, or absence of all smaller/long-term leaks.

## Historical original long run — not accepted

Original-run status: **COMPLETED — NOT FULLY ACCEPTED pending replacement endurance**.
The requested workload ran for **7200.016 seconds**; total including setup,
verification and cleanup was **7268.891 seconds**. The original automated runner
passed **51/51**, with unchanged product sources/executed fixtures and successful
cleanup. Independent review of the raw resource series then found sustained
per-container PIDs growth that the automated gate did not assert.

The original `soak-report.json` and `resource-report.json` remain unchanged and
retain their narrower automated PASS. The evidence-bound `closeout-review.json`
records the additional findings. The final canonical
`.runs/current-soak-acceptance.json` is **NOT QUALIFIED** because that closeout
review did not pass. The acceptance join was extended to honor an explicitly
recorded review rather than hide it behind the narrower automated booleans.
No product fix, threshold relaxation or new VM test was performed in closeout.

**Later authorized follow-up:** a separate focused test on 2026-10-29 has now
reproduced zombie `sh`/`sleep` accumulation from the unchanged probe watchdog
on two VMs. Traffic/bare-exec controls remained clean. See the
[exact component diagnosis and remaining remediation gate](PID-DIAGNOSIS-2026-10-29.md).
Subsequent authorized timer/reaper remediation now has a clean frozen-source
component regression; see that report's follow-up section. Fresh real-product
integration/endurance is in progress. None of this rewrites or accepts the
original soak evidence.

**Post-remediation clean smoke:** `rkq-soak-20261029-130136-26895c` passes
43/43 over 360.004 seconds of actual workload and all five faults. Frozen
source/fixtures, audit timing based on actual issuer use, real Raft measurements,
zero observed zombies, 2→2 container task baselines, and empty/disabled guest
cleanup before shutdown are verified. It is not a long-duration replacement.
Intermediate failed/incomplete attempts remain recorded in
[CURRENT-RESULTS.md](CURRENT-RESULTS.md), including interrupted cleanup and the
audit/contamination fixture findings. A fresh two-hour run remains required.

- Original run: `.runs/rkq-soak-20261029-000347-3823a4/`.
- Launch record: `.runs/soak-launch-20261029-000333-bf383d.json`.
- Progress only: `soak-status.json`; final result: `soak-report.json`.
- Strict current long-soak join: `.runs/current-soak-acceptance.json`.
- Thread heartbeat `royak-soak` monitored the existing run without duplicate
  execution and is stopped at this final closeout. Workload finished around
  02:04 Europe/Sofia on 2026-10-29; verification/cleanup finished around 02:05.
- Contract, thresholds and reproduction: [SOAK-CONTRACT.md](parallels/SOAK-CONTRACT.md).
- Requested workload: at least 7200 seconds, plus provisioning/verification/
  cleanup, with repeated faults about every 600 seconds. First long run uses
  300-second warm-up, 60-second baseline and 600-second final healthy window.
- All three guests remain 2 vCPU / 2 GiB RAM, with distinct kernels and Docker
  daemons on one physical Mac. The external LB/ledger are also on that Mac.

## Prior test of the new runner

The six-minute smoke workload in `rkq-soak-20261028-235542-adc0c9` passed
**40/40 checks**, all five actual faults, verified remote Connect writes,
data checking, resource sampling, complete drain and owned VM shutdown.
It explicitly records `long_soak_qualified: false`. After that rehearsal, the
long run also gained per-minute traffic-continuity checks, unique control-write
names per fault cycle, explicit elapsed-workload and telemetry-coverage gates.
Those additions have deterministic tests and were exercised by the completed full
run; the older smoke is not misrepresented as full-duration proof.

Qualification infrastructure tests: **31 existing + 35 Parallels/soak tests
pass**, zero skips. No product Rust/UI source changed for this task.

## Exact product artifacts

- Normal Linux ARM64 release:
  `c1f63362f5f32c5d272d2181a01350ac7e0d62058ae4bb4791a482a3407e0335`.
- Native macOS client:
  `aab3f675485e520fa0a5453256e6412590c79c6443cf7fdaec73c574ae17bbfc`.
- The run manifest binds the sources, fixture files, configuration and artifact
  hashes. The final join additionally checks current binaries/client/Caddy and
  latest-attempt evidence; a smoke or older passing attempt cannot substitute.

## Data and traffic — passed for the measured contract

All three histories were independently rechecked against the saved external
ledger during closeout. **83,969 acknowledged writes** retained the exact ID and
value, with no lost/corrupt acknowledged write. The ledger contains 83,974 rows:
five additional entries can belong to ambiguous requests; no exactly-once claim.

| Path | Acknowledged / attempts | Failed or ambiguous | Overall response success |
| --- | ---: | ---: | ---: |
| External LB | 27,931 / 27,945 | 14 | 99.9499% |
| Direct-node | 27,901 / 28,120 | 219 | 99.2212% |
| Native Connect | 28,137 / 28,420 | 283 | 99.0042% |

All **28,137** acknowledged Connect writes matched an actual backend on a
different VM. There were also **89 failed session-open attempts**, separate
from the application-write denominators, and 584 opened sessions. None of these
failures/ambiguities was hidden or replayed. These closed-loop response ratios
are not a time-based availability SLO or capacity benchmark.

Eleven non-overlapping faults completed: pod kill **3**, leader SIGKILL **2**,
control partition **2**, occupied/recently-serving whole-VM hard stop **2**, and
WireGuard-only loss **2**. Sixteen uniquely named acknowledged control writes
converged on all guests. Both VM restarts had new boot IDs and preserved the
exact trusted TLS identity; final LB rotation included all three ingresses.

Each traffic path passed **95 complete healthy one-minute windows**. Warm-up,
explicit fault windows and their predeclared recovery interval are excluded
from this healthy-window gate, not erased from the histories. Final ten-minute
observation: LB **2393/2393**, direct **2447/2447**, Connect **2377/2377**.
Across the two whole-VM restart windows, LB served **516/523 (98.66%)**.

Final-window latency p50 / p95 / p99, milliseconds (nearest-rank): LB
**223.462 / 439.398 / 667.693**, direct **220.601 / 427.945 / 577.008**, Connect
**21.422 / 300.789 / 538.921**. The fixture uses paced closed-loop clients,
one-Mac networking and an external ledger; do not extrapolate production load.

## Resource review — unresolved finding

### SOAK-001: per-container PIDs accumulation

Docker PIDs increased monotonically within the same container lifetimes and
remained high during the final client drain:

| VM / container | First → final PIDs | Observed span | First/last quartile progression |
| --- | ---: | ---: | --- |
| VM 2, `rk-qualification_web-2`, `0609e45852df` | 3 → **530** | 7223 s, 227 samples | 67.5 → 202.5 → 340 → 468 |
| VM 2, `rk-soak-connect_c1-1`, `5adedab02e9b` | 4 → **466** | 7223 s, 227 samples | 63 → 179.5 → 294 → 415 |
| VM 1, `rk-soak-connect_c0-1`, `acff7c2f88eb` | 1 → **143** | 2025 s, 66 samples | Little application traffic: only 3.06 kB / 252 B network I/O |

The two VM-2 containers still reported 530 and 466 PIDs after Connect sessions
and clients had drained. Container memory also grew (web 13.25 → 19.65 MiB;
Connect 14.01 → 19.55 MiB). This prevents a claim of resource-leak-free endurance.
At original closeout the cause was **not proven**: PIDs alone do not distinguish
live processes, threads or zombies, and the original samples contain no
per-task state/parentage. The later focused diagnosis linked above now reproduces
zombie descendants from the original watchdog under a non-reaping workload
PID 1. It does not retrospectively classify every task in the deleted soak
containers or exclude every other contributor.

The original automated resource gate bounded **Royak-process** RSS/FD/threads,
OOM and container count; it recorded Docker PIDs but did not assert their
same-container growth. That is why automated 51/51 cannot close the broader
user-requested resource-leak question. Raw evidence is retained, hash-bound in
`closeout-review.json`; no counter reset, init injection or workload reduction
was used to hide the accumulation.

### Measurements that did pass

| VM | Royak peak RSS | Peak → final FDs | Peak → final threads | Minimum guest free disk |
| --- | ---: | ---: | ---: | ---: |
| 1 | 13.176 MiB | 34 → 17 | 14 → 14 | 11.927 GiB |
| 2 | 13.023 MiB | 32 → 17 | 14 → 14 | 11.989 GiB |
| 3 | 13.590 MiB | 34 → 19 | 15 → 9 | 11.996 GiB |

The largest first-to-last-quartile median gain in a single Royak process
incarnation was **3.223 MiB RSS / 7 FDs / 5 threads**. Seven incarnations with
sufficient span were evaluated separately; no restart was merged into an old
baseline. These are bounded observations, not evidence of zero growth.
Five resource samples were unavailable during VM restarts; usable process
samples were 224 / 227 / 223 per VM. There was no observed container OOM, no
container-count accumulation, and all three nodes had zero final CLOSE-WAIT.

Container CPU p95 across sampled containers per VM was 1.52% / 1.50% / 1.36%,
with peaks 3.63% / 4.59% / 4.42%. This is container CPU, **not measured Royak
process CPU**. Final audit-file sizes were 160147 / 45738 / 121466 bytes;
Royak logs 482498 / 339456 / 406246 bytes. Root free space declined about
18.566 / 2.648 / 18.555 MiB, still above the declared reserve. Audit/log writes
are expected growth and were not silently deleted/rotated during the run.

### SOAK-002: Raft-state growth instrumentation gap

The sampler checked `/lab/state.json` and encoded absent files as zero. Cluster
mode uses the `/lab/state.json.raft` directory, which was not sampled. The
reported zero therefore cannot establish authoritative-state size or lack of
growth. Root free disk, audit/log sizes and the 16 converged control writes are
real independent observations; Raft-directory size growth remains unqualified.

## Cleanup and disposition

All native clients stopped without forced-kill leftovers. Final open sessions
and active connections were zero on every node; retained closed session counts
were 8 / 0 / 0, below the 256 cache bound. Final pre-cleanup census was exactly
six workload containers, no OOM. The tracked cleanup completed without reported
errors, stopped guest services, removed the exact workload containers/image,
WireGuard and fault rules, and terminated Caddy/management forwards. The
ephemeral LB key was removed. Live host checks found no runner, exact test
Caddy/SSH processes or TCP/8000 ledger listener.

All three exact owned UUIDs were independently verified **stopped** with
Parallels after cleanup, without booting them again. VM disks, private
state/identities and evidence are retained. Guest resources were not separately
reaudited after shutdown; no new VM workload or reproducer was started.

**Next required work:** the focused process/task census has now isolated a
watchdog zombie-cleanup mechanism. With implementation approval, repair that
cleanup and the PID/Raft-size gates, add regression coverage, then repeat actual
Royak integration and the affected endurance qualification. No product code
was changed in closeout or the later diagnosis. Long-soak acceptance stays
NOT QUALIFIED until remediation and new evidence resolve the finding, even
though data/traffic and all original automated assertions passed.

All pre-existing local changes and failed evidence are preserved. Nothing is
committed, pushed, released or applied to the public demo. No host VPN/route or
global Docker cleanup is part of this test. An external ledger is not Royak
distributed-storage durability; a two-hour bounded run is not production
certification or proof of absence of all smaller/longer-term resource leaks.
