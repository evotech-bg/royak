# Security context and HTTP framing — verified fixes, 2026-10-27

## Outcome

**PASS for the bounded current-source local contract:** all 14 integration
suites, all 12 three-daemon fault checks, 202 native Rust tests and 19 Python
oracle/tooling tests pass. This closes QF-003 for the supported Docker security
subset and QF-005 for bounded buffered HTTP response decoding. It is **not**
production certification, full Kubernetes conformance or a zero-downtime claim.

The DevOps/security and Kubernetes best-practice review shaped the fail-closed
security subset, explicit upgrade boundary and actual kernel-level checks. The
performance-testing discipline keeps this closed-loop fault exercise separate
from an uncontrolled performance benchmark; no speedup claim is made.

## Exact current evidence

- Linux binary `.runs/linux-royak-security-http-final`, 9,443,040 bytes;
  SHA-256 `d4b491c3b3cd8997933056f1f3cb953695f35d8a8cf5291d55cbf9521c77bfdf`.
- Targeted first repeat: `.runs/rkq-suites-20261027-000311-87e5ed/`:
  security 13/13, HTTP framing 4/4.
- Full suite: `.runs/rkq-suites-20261027-000446-e9e4ee/`, 799.451 seconds;
  every process exit is zero; no cleanup errors.
- Three-daemon fault run: `.runs/rkq-20261027-000311-fda18b/`, 519.421 seconds,
  default HTTP readiness, final observation 300 seconds.
- Joined machine-readable report: `.runs/current-coverage.json`, **passed=true**.
  The join requires current Rust/Cargo hashes, current test fixtures and current
  fault harness hashes; it uses latest matching evidence, not an older best pass.
- Native `cargo test --bin royak`: **202/202**, repeatedly with normal parallel
  execution (three consecutive final-source runs, plus a final repeat). An
  intermittent ServiceLB fixture bind collision was fixed by retaining and
  transferring the actual bound socket; production listener behavior is unchanged.
- Python checker, ledger, dataset, suite inventory and coverage tests: **19/19**,
  including ResourceWarning-as-error and rejection of cherry-picked old passes.
- Shell syntax and `git diff --check`: pass.

| Integration suite | Passed checks |
| --- | ---: |
| Auth / RBAC / kubectl | 60 |
| ServiceLB / probes | 54 |
| HTTP probe address | 6 |
| Multi-node workload / recovery | 37 |
| Raft | 23, plus 2 setup checks |
| State owner / HA lease | 15 |
| Encrypted mesh | 8 |
| Ingress | 15 |
| Load / chaos | 5 |
| Build → deploy → served marker | 9 |
| NeuroPod experimental | 10; 1 explicit skip: deleted-deployment pod garbage collection |
| Broad demo / functional suite | 110; no skips |
| Actual security constraints | 13 |
| HTTP chunk framing | 4 |

That is 369 named checks plus the two Raft setup checks. Suite success does not
erase the explicit NeuroPod skip or the untested boundaries below. Full suites
used a verified nested overlay2 daemon; the independent three-daemon fault run
used separate vfs-backed daemons. Both remained isolated from the host socket.

## What the two fixes demonstrate

Security settings are typed and inherited, stored in desired state, sent to the
receiving node and mapped into real Docker configuration. The targeted fixture
observed UID 10001/GID 10002, read-only root, empty kernel effective and bounding
capability sets and NoNewPrivs=1. Restarting Royak and recreating the container
preserved its requested identity and restrictions. Unknown security fields and
contradictory settings are rejected; rejecting the supported subset fails the
fixture. The separate fault run checked constrained replacement pods on multiple
daemons after actual failures.

Ingress now returns decoded `hello` from a real chunked upstream, not the chunk
wire framing. Unit coverage adds binary chunks, extensions, trailers, malformed
and truncated bodies, response limits, HEAD and interim responses. Parsing does
not send another network request or replay an ambiguous POST. This path is still
buffered, bounded and not a qualified long-lived streaming/upgrade proxy.

See [SECURITY-HTTP-CONTRACT.md](SECURITY-HTTP-CONTRACT.md) for supported fields,
limits, schema-3 migration, backup behavior and all-node upgrade requirements.
Previously ignored contexts require reapply and inspection; migration does not
retroactively infer them. No real user state or external cluster was migrated.

## Real faults with constrained containers

The harness used three distinct Docker daemon IDs, deleted an application
container, SIGKILLed the leader, partitioned peer control traffic, stopped a
whole node/daemon for 45 seconds and restarted it on its existing disk.

- **12/12 checks passed**; surviving daemons replaced lost replicas before the
  stopped node returned; the final replica count was exactly three.
- **1262/1262 acknowledged application writes** retained exact values in the
  external SQLite ledger. There were 1263 total ledger entries: one request with
  no success acknowledgment had committed. This is not an exactly-once claim.
- **7 acknowledged control ConfigMaps** converged on every node.
- **66 failed/ambiguous requests** retained: 59 failed connections to the stopped
  ingress, four 502s on live ingress endpoints around pod/node loss and three
  503s on the restarted ingress during recovery. QF-002 remains open.
- Final **300-second observation: 780/780** successful requests. At most five
  requests/second from one closed-loop client; not a saturation benchmark.
- Every final/replacement application container had UID/GID 10001, read-only
  root, CapDrop ALL, empty kernel capability sets and NoNewPrivs=1. Safe fields
  are retained in `security.json`, without environment/credential dumps.
- **177 causal diagnostic dataset rows** exported. No model was trained or
  integrated and no predictive/autonomous ML capability is claimed.

| Phase | Successful / attempted |
| --- | ---: |
| Baseline | 61 / 61 |
| Pod deletion | 28 / 31 |
| Leader SIGKILL | 27 / 40 |
| Control-plane partition | 59 / 59 |
| Node outage / restart | 96 / 143 |
| Recovery after node restart | 48 / 51 |
| Final observation | 780 / 780 |

The ledger is outside Royak, not a test of replicated Royak volume durability.
Fault and legacy suites shared the physical machine, so latency comparisons to
earlier runs are not controlled A/B evidence.

## Remaining acceptance boundary

Probe initial delay/period/threshold semantics and timed-out detached-exec
cleanup remain next lifecycle work. QF-002 availability gaps remain. Cross-host
failures, disk-full, whole-cluster backup/restore, 72-hour soak, version skew and
rolling upgrade, general hostile-tenant isolation, complete CNI/CSI/storage and
upstream Kubernetes conformance remain unqualified. NeuroPod is experimental.
The supported security subset is not full Kubernetes Pod Security compliance.

Existing local source changes were preserved, with no reset, stash, commit or
push. All 11 pre-existing source files outside the deliberately changed Rust/
Cargo set match the prior qualification snapshot. Tests never used the public
demo or remote machines. Run-owned containers, volumes and networks were removed
and label-filtered inventories were empty after completion. No global Docker
prune or unrelated data deletion was performed. Host free space temporarily
approached the safety margin and ended at about 3.3 GiB; larger runs need more
capacity.
