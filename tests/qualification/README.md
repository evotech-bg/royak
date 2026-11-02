# Royak qualification lab — first executable slice

This is a **real local integration lab**, not a production certificate. It runs
three Royak/Raft nodes in three separate privileged Docker-in-Docker containers,
with independent Docker daemons and persistent test disks. An external Python
client writes through each node's TLS ingress while faults are injected.

All nodes still share one physical host, kernel, power supply and outer Docker
daemon. Those common failure domains are **not tested** here. Never point the
legacy shell suites at a host containing valuable workloads.

See [CURRENT-RESULTS.md](CURRENT-RESULTS.md) for the latest complete local
qualification, [RESULTS.md](RESULTS.md) for the historical first slice, and
[FINDINGS.md](FINDINGS.md) for open defects and tested fixes.
The current [security/HTTP contract](SECURITY-HTTP-CONTRACT.md) documents the
enforced Docker subset, schema-3 upgrade boundary and buffered proxy limits.
The [probe/topology contract](PROBE-TOPOLOGY-CONTRACT.md) records the health
lifecycle, read-only graph/session boundary and unsupported combinations.

For repository-wide integration tests, use the isolated suite driver:

```sh
python3 -B tests/qualification/suites.py --binary tests/qualification/.runs/linux-royak-qualified
```

`--storage-driver overlay2` is available when the host supports nested overlay
mounts; the driver verifies and records the actual nested storage driver. The
default is `vfs`, which needs more space. No host Docker socket is mounted.

It includes all Linux `test-*.sh` entrypoints, including negative security
contracts that can legitimately make the overall result red. Never run the
legacy broad-cleanup scripts on the host Docker daemon. See
[KUBERNETES-COVERAGE.md](KUBERNETES-COVERAGE.md) for the exact parity boundary.

Recorded skips now fail both the suite runner and the current-evidence join,
even if a child exits zero. NeuroPod uses a mandatory Linux/root real-process
fixture inside the owned node; missing prerequisites fail rather than skip.
The runner installs its ext4/network tools. Read the
[NeuroPod GC contract](NEUROPOD-GC-CONTRACT.md) for ownership, retained data and
legacy migration boundaries. To reproduce its targeted regression:

```sh
python3 -B tests/qualification/suites.py --binary tests/qualification/.runs/linux-royak-neuropod-gc-accepted --storage-driver overlay2 --suite test-neuropod.sh
python3 -B tests/qualification/parallels/get_restic.py --root tests/qualification/.runs/rust-test-tools --platform linux_arm64 --platform linux_amd64
python3 -B tests/qualification/linux_unit.py --release --restic-manifest tests/qualification/.runs/rust-test-tools/restic-build.json
```

The final command compiles and executes all Rust binary tests on Linux in a
separate labelled container and rejects failures/ignored tests. It does not
mount the host Docker socket or reuse the user's Cargo target/cache.
The preceding tool setup requires GnuPG and verifies the pinned release signing
fingerprint, signed archive hashes and actual binary architecture. The runner
selects the Docker daemon's Linux architecture from that manifest. Real backup
tests require this tool: absence is an error, not an ignored test. Use a new
tool directory if changing the selected platforms; existing artifacts are never
silently replaced. Hosted native tests use `get_restic.py --host` separately.

The probe watchdog also has a real shell/process matrix. Pull the two explicit
fixture images, then run:

```sh
docker pull alpine:3.22
docker pull python:3.13-slim
mkdir -p tests/qualification/.runs
python3 -B tests/qualification/watchdog_runtime.py --output tests/qualification/.runs/watchdog-portable.json
```

It checks BusyBox ash and Dash, each with/without Docker init, success/failure
timer cancellation, hard deadlines with nested children, no late writes,
process/zombie baselines and exact owned cleanup. The report binds image IDs,
watchdog and fixture hashes. It is a component regression, not full Debian
cluster qualification. The opt-in qualification workflow retains this evidence.

## Run

### Royak Connect

Read [CONNECT-CONTRACT.md](CONNECT-CONTRACT.md) for the exact Service-scoped
access contract and operator-provisioned WireGuard prerequisites. After building
both the native laptop CLI and the normal Linux release from unchanged sources:

```sh
cargo build --bin royak
python3 -B tests/qualification/run.py build --binary tests/qualification/.runs/linux-royak-connect-current
python3 -B tests/qualification/connect_e2e.py --binary tests/qualification/.runs/linux-royak-connect-current --client target/debug/royak
```

Repeat the entire Connect command three consecutive times without editing the
source, fixture or client. Run all integration suites on that exact Linux
binary, then evaluate the strict latest-attempt gate:

```sh
python3 -B tests/qualification/suites.py --binary tests/qualification/.runs/linux-royak-connect-current --storage-driver overlay2
python3 -B tests/qualification/connect_acceptance.py --binary tests/qualification/.runs/linux-royak-connect-current --client target/debug/royak --output tests/qualification/.runs/current-connect-acceptance.json
```

The gate requires all 15 suites and the latest three matching normal-release
Connect attempts, not an older best pass or diagnostic build. A separate current
fault/300s-observation/live-browser run is required by `coverage_report.py` for
the broader beta regression. No gate establishes cross-host or full Kubernetes
conformance. Desktop users should keep their test machine awake for the entire
run; on macOS, a process-scoped `caffeinate -i` wrapper is suitable.

### General fault lab

Requirements: Docker with privileged container support, at least 5 GiB of Docker
memory and 4 CPUs, Python 3.10+, and space for an isolated Rust build and three
nested Docker disks. The first build needs registry/package-network access.

```sh
python3 -B -m unittest discover -s tests/qualification -p 'test_*.py' -v
python3 -B tests/qualification/run.py build
python3 -B tests/qualification/run.py run --seed 42
```

The first real run found [QF-001](FINDINGS.md): HTTP readiness through BusyBox
wget rejected a healthy IPv4-only application. Current sources fix that target
selection and the default HTTP regression now passes. A historical diagnostic
workaround remains available, but must not replace default-mode acceptance:

```sh
python3 -B tests/qualification/run.py run --seed 42 --probe-mode exec-ipv4
```

An `exec-ipv4` pass must not be represented as an HTTP probe fix.

The build uses the current working sources (including existing local changes),
not just HEAD. It does not use the host's Rust target/cache. The resulting Linux
ELF binary is the ignored `.runs/linux-royak` file. `--binary PATH`
accepts an already-built Linux binary; its SHA-256 is recorded, not assumed to
match the source manifest. On Apple Silicon the Linux build is ARM64.

`--duration 300` adds five minutes after the fault matrix; `--rate 5` sets the
maximum rate of the single, closed-loop client. This is **not a saturation/load
benchmark**: a slow request delays subsequent requests. A 72-hour run is not yet
qualified (streaming/rotation, watchdogs, bounded oracle queries still needed).

Current acceptance also requires real browser evidence. Pass `--ui-check`, a
Node executable via `--node PATH` and, when not resolved normally, the installed
Playwright module via `--playwright-module PATH`. Chromium must be available.
The callback uses the actual recovered cluster and temporary lab credentials,
tests same-origin GET-only interactions and two real polling cycles, and writes
desktop/mobile captures plus `ui-report.json`. Without it, a successful fault
run alone does not satisfy the current coverage join. `topology_ui.cjs` is a
separate, explicitly synthetic UI/error/race regression fixture, not live RBAC
or cluster proof.

## What it checks

1. Three distinct Docker daemon IDs and a three-replica application placed on
   multiple daemons; all three ingresses must work before faults.
2. A real workload container is forcibly deleted.
3. The confirmed Raft leader process receives SIGKILL, then restarts on its
   existing disk. A majority accepts a state write while it is down.
4. The current leader is isolated from peer control-plane TCP/6443 traffic.
   The majority elects a leader; the minority must not acknowledge a write.
   A timeout/504 remains **outcome unknown**, never a definite rejection.
5. One seeded node's outer container and inner Docker daemon stop for 45 seconds
   (`--node-outage`) and restart, preserving disk contents. Before restart, the
   surviving daemons must have replaced the missing replicas. Other application
   endpoints remain exercised; ephemeral external Docker ports are rediscovered.
6. After recovery, every acknowledged ConfigMap must appear with the correct
   value on every node. This is an eventual-convergence check, **not a
   linearizability proof**. Exactly three running application replicas must settle.
7. Every acknowledged application write must retain its exact value in an
   independent SQLite WAL ledger, and its response must match the request.
   At least one write must succeed during each fault; baseline availability
   defaults to 99%. Fault-window availability and P50/P95/P99 are reported,
   not silently promoted to a production SLO.
8. All final/replacement workload containers retain configured UID/GID 10001,
   read-only root, no-new-privileges and empty effective/bounding capability
   sets, checked in Docker configuration and `/proc/1/status`. Safe inspection
   fields are retained in `security.json`; no container environment is exported.

The ledger runs **outside Royak**. Its durability is not evidence of distributed
Royak volumes; host-local volume migration/loss remains outside this claim.

## Evidence and safety

Each run prints its evidence directory under `tests/qualification/.runs/`:

- `manifest.json`: HEAD, dirty-diff hash, source hashes, Linux binary hash,
  image IDs, hardware, topology, seed and explicit non-claims.
- `history.jsonl`: external invocations/responses and control-plane acknowledgements.
- `faults.jsonl`: actual targets, fault start/end and scope.
- `telemetry.jsonl`: timestamped Raft states with injector-ground-truth labels.
- `ledger.json`, `performance.json`, `report.json`: oracle snapshot, per-phase
  measurements and machine-readable pass/failure. Failed runs exit nonzero.
- `node-*.log`: bounded node logs with this run's credentials redacted.

Only exact run-owned resources are removed. Containers, disks and network have
the `royak.qualification=<run-id>` label. No global prune, host process kills,
SSH access, public demo changes, or existing workloads are involved. Published
ports bind only to loopback; TLS verification is disabled solely for ephemeral
lab certificates. DIND is privileged, so run this only on a trusted test machine.
Cleanup also runs on normal exceptions/Ctrl-C. A host crash or SIGKILL of the
driver can leave labeled resources; inspect ownership before removing them.

## ML track

`telemetry.jsonl` is the first **data collection contract**, not a trained model.
Fault labels come from the injector; unavailable CPU/memory measurements are
`null`, never fabricated zeros. External traffic histories provide observed
latency, availability and instance IDs. More telemetry and independent runs are
needed before training.

After a run with traffic, export a causal feature table:

```sh
python3 -B tests/qualification/dataset.py tests/qualification/.runs/RUN_ID
```

`dataset.jsonl` uses only completed requests at or before each sample, within a
trailing ten-second window. Labels stay separate from inference features. The
tests check time leakage, window expiry and missing-data handling. This export
is for diagnosis/recovery research, not a validated failure predictor.

Randomly injected SIGKILLs are not inherently predictable from resource metrics;
these labels support recovery analysis, not a claim of useful failure prediction.
Resource-pressure forecasting needs gradual, measured pressure scenarios first.

Start with a narrowly defined task: predict a resource-pressure incident within
30–60 seconds. Compare against threshold, moving-average and linear-regression
baselines. Split train/test **by complete run and workload**, not adjacent
samples; keep fault labels and future observations out of inference features.
Report precision/recall, false alarms/hour, useful warning time, inference
CPU/RAM and failures under distribution shift. Start in shadow mode: no model
output may bypass quotas, placement constraints, RBAC or deterministic recovery.

## Remaining gates before a bounded production beta

- Repeat this contract on three independent Linux hosts plus an external client;
  require explicit disposable-host inventory and fault authorization. No remote
  provider or SSH provisioning is implemented in this first slice.
- Check operation histories against declared consistency semantics, including
  concurrent create/update/delete, retries and ambiguous acknowledgements.
- Test asymmetric and full network partitions, mesh/ingress faults, latency,
  packet loss, DNS/registry failure and actual daemon/host reboot.
- Bounded disk-full/read-only/fsync/corrupt-state injection, crash recovery,
  snapshots, backup restore and version upgrade/rollback.
- Full namespace/RBAC negative matrix and escaped-container/secret exposure
  review. This smoke lab does not replace the existing security suites.
- Implement and verify probe timing/threshold semantics and timeout cleanup.
- Capacity curve, sustained-load test, 72-hour soak, leak/resource-growth limits,
  recovery deadlines and fault-phase availability thresholds agreed in advance.
- Reproducible signed release, version compatibility, monitoring/alerting,
  incident and restore runbooks. State workload/data-loss limitations explicitly.

Passing this slice means the named local fault contract passed, nothing more.
