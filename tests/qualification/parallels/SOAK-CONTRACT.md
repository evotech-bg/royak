# Three-VM endurance contract

The new soak runner leaves product sources and the previously accepted short
fixtures unchanged. Its evidence is separate: a smoke pass is not a long-soak
pass, and neither is production certification. Only the exact owned Parallels
inventory is used; no public demo, host VPN/routes, public listener or unrelated
Docker/VM cleanup is permitted.

## First long run

- At least **7200 seconds of workload**, excluding provisioning and cleanup.
- Five-minute warm-up, one-minute measured baseline, ten-minute final healthy
  observation. A fault starts about every ten minutes; faults never overlap.
- Constant independent direct-node and external verified-TLS Caddy traffic,
  target 5 requests/second per path (closed loop, not a capacity benchmark).
- Four native laptop-style Connect clients, one persistent TCP/HTTP/1.1 stream
  each at 1 write/second. Sessions renew before their 120-second TTL; the native
  client uses loopback only, a private scoped token file and pre-trusted TLS.
  Each chosen Service has one Ready backend on a different VM. Container IDs
  confirm the remote instance; WireGuard provides the node hop.
- Repeated pod removal, leader SIGKILL, control-plane partition, hard stop of an
  occupied/recently-serving VM, and WireGuard-only interruption. At least two
  cycles of the five faults are required for the long run. Guest-local timed
  rollback protects injected networking changes; management SSH remains usable.
- After failure, fresh sessions can explicitly choose another of the three
  initially trusted issuers. No CA re-pinning, insecure TLS, payload replay or
  retry of an ambiguous application write.

The workload image reuses the prior independent-ledger fixture, enabling
HTTP/1.1 keep-alive only in the new soak fixture. This is needed to exercise
already-open Connect streams; no product timeout or stream limit is changed.

## Data, error and resource evidence

Every application attempt has a distinct ID and digest. Every 200 response must
return the same ID/value and exist unchanged in the external SQLite ledger.
Failures/ambiguities remain in the histories and may include committed writes;
they are not silently retried or counted as data loss. The ledger is outside
the three VMs, not proof of Royak distributed-volume durability or exactly-once
delivery. Acknowledged control writes must converge on all three guests.

Every 30 seconds collect real guest/process/container metrics: Royak RSS, file
descriptors, threads, process-start and boot identities, TCP states, container
counts/OOM, Docker CPU/memory/PIDs, disk reserve and state/audit/log sizes.
Unavailable observations are marked unavailable, never zero. Process trends
are grouped by incarnation; restarts cannot erase an earlier trend by merging
it into a new baseline.

Predeclared bounded growth checks: Royak RSS peak at most 256 MiB, first/last
quartile median gain at most 64 MiB RSS / 32 FDs / 8 threads in an incarnation
with at least eight samples over five minutes; coverage is required for all
three nodes. These are detection bounds, not proof that no smaller leak exists.
Final clients/sessions/sockets must drain, retained session caches stay at most
256 per node, no container OOM occurs, and the six intended workload containers
must not accumulate extra stopped containers. Guest free disk must stay above
2 GiB; the host guard is 20 GiB (60 GiB required to start).

The repaired resource contract is version 2. It reads metadata from each
container's procfs through the guest (no extra exec processes), recording
process state/parent/start identity and task counts. All six probe containers
must use Docker init. For each node, at least one container incarnation must
have eight samples spanning five minutes (one minute in smoke). Same-container
task peak is at most 64 and first/last-quartile median gain at most eight.
A zombie observed at least twice over one second, or any zombie after drain,
fails qualification. Individual transient reaping observations remain visible.

Authoritative `/lab/state.json.raft` is sampled recursively, alongside audit and
Royak logs; absent paths have `present: false` and null size, never zero. Symlinks
are not followed. Raft and logs are always required. Audit is required on each
issuer after its first acknowledged durable grant, using actual Connect history
and the start of each resource sample; it cannot disappear once observed.
Never-used followers retain explicit absent/null observations, not fake zero
sizes or invented audit-growth coverage. Each path has a 64 MiB peak ceiling; median
gain is bounded at 16 MiB for Raft and 32 MiB for audit/log per observed boot.
Apparent regular-file bytes and allocated bytes are retained separately. Royak
CPU comes from its own Linux utime/stime counters, not Docker workload CPU.
These are declared two-hour detection bounds, not capacity/SLO claims or proof
of absence of smaller/longer-term leaks. The final acceptance also requires an
evidence-hash-bound raw-resource closeout review; a legacy RSS-only boolean pass
cannot substitute for this contract.

Healthy baseline/final traffic must have at least 99% successful responses and
at least half the declared offered Connect rate, so a silent/stuck worker cannot
pass on a few successes. Fault windows retain their actual error rates and
latencies. The short LB contract still requires at least 95% through the VM
hard-stop window. No blanket zero-downtime or production SLO is claimed.
Every complete healthy minute must also meet 99% response success and at least
half the offered rate on all three paths. Only explicitly injected fault windows
and their declared 20-second recovery are exempt; at least 60 healthy minute
windows are required. At least 80% of expected per-VM resource samples must be
available. Every acknowledged control-write name is unique per fault cycle.

Final verification continues collecting drain and resource evidence after a
failed assertion or an unexpected traffic/drain exception, but keeps the final
result FAILED. `connect-drain.json` must show all three nodes, successful API
observations, zero active/open sessions and at most 256 retained records per
node. `resource-report.json` must include three successful drain samples per
node after workload workers and the background sampler have stopped. The raw
closeout review also binds the drain report hash. Missing evidence is not zero
and cannot qualify.

Before accepting this failure path, run a separate real 360-second smoke with
`--negative-closeout-control`: all real traffic/faults still run, an intentional
final check remains FAILED, and drain/resource/cleanup evidence must still be
complete. That control is smoke-only and cannot qualify as the long run. A
separate clean smoke and full 7200-second workload remain required.

## Run and observe

Run `soak.py --profile smoke --duration 360` first with the same inventory,
binary, native client and Caddy arguments as the long launch below. A smoke run
is explicitly `long_soak_qualified: false` even when its checks pass.

```sh
python3 -B tests/qualification/parallels/launch_soak.py \
  --inventory tests/qualification/.runs/rkq-vm-20261028-royak/inventory.json \
  --binary tests/qualification/.runs/linux-royak-probe-portable-final-20261029 \
  --client target/debug/royak \
  --caddy tests/qualification/.runs/parallels-tools/caddy --duration 7200
```

The launcher creates a private launch record and log, and keeps macOS awake
while the child runs. `Evidence:` in that log names the exact run directory.
`soak-status.json` is progress only; only `soak-report.json` is final. Do not
launch another test against the same inventory while it runs. A thread
heartbeat may inspect progress and notify only on failure, completion or a
required user action; it must never launch duplicate tests.

The runner stops its clients, LB, forwards, guest services, exact test
containers/image, WireGuard and fault rules, and powers off the exact owned
guests. VM disks, private state and evidence remain for diagnosis. Source,
fixture and binary hashes bind the result; drift or failed cleanup prevents a
pass. The Mac, LB and ledger remain one physical failure domain.

All three guests must be idle with zero containers before the first preparation write. A busy guest
does not authorize stopping its service or replacing another run's `/lab`.
Interrupted cleanup is recorded as a failure. `cleanup-verification.json`
captures each guest while still reachable: disabled/inactive qualification
service, no exact Royak process/workload containers or any residual containers, no test WireGuard interface
or owned fault rules. Only then is shutdown accepted; "VM stopped" alone cannot
hide a service that would restart at boot. Recovery can explicitly select owned
node IDs with repeated `--node`; every selected `/lab` pointer is checked before
the first recovery mutation, and other pointers/resources are preserved.
