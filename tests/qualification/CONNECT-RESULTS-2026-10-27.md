# Royak Connect — local qualification, 2026-10-27

> Historical pre-NeuroPod-GC checkpoint, exact binary `50cf4e27589b…`.
> The [new inclusive zero-skip report](NEUROPOD-GC-RESULTS-2026-10-27.md)
> requalifies Connect and all regressions after the GC work. Counts and the
> earlier named skip below are preserved as historical evidence.

Status: **PASS for the bounded local Connect and beta regression contract**:
54/54 Connect checks in three consecutive complete runs, 53/53 actual
lifecycle/topology/RBAC checks in three runs, all 15 integration suites and a
fresh 13/13 three-daemon fault/300s-observation/live-browser run. This is not
production certification or full Kubernetes conformance.

## Exact tested version

- Normal Linux release: `.runs/linux-royak-connect-published-health`
- Linux SHA-256: `50cf4e27589b06e41adc3fd69dbee8c9f39737c4921c1bb1cbe846aa24f04e04`
- Native laptop client: `target/debug/royak`
- Client SHA-256: `ecff2f6bf51ca76030f674b3bfe0af8773584adac0f251f982f0444ee2aa93b8`
- The adjacent Linux `.build.json` binds all embedded source hashes to this
  binary and confirms no source changes during its build. This is a normal
  release, not a diagnostic/symbols-only build. Run manifests additionally bind
  the current fixtures and client. Nothing was committed, pushed or released.

## Connect evidence

The latest three matching attempts all passed, rather than selecting an older
best pass:

| Evidence bundle | Checks |
| --- | ---: |
| `rkq-20261027-215036-5822f6` | 54/54 |
| `rkq-20261027-215156-494c4f` | 54/54 |
| `rkq-20261027-215314-239961` | 54/54 |

Each run uses three independent Docker daemons and three real Linux kernel
WireGuard interfaces. The issuer and selected application backend are forced
onto different daemons. Actual handshakes and encrypted transfer counters are
recorded; the binary TCP payload spans 256 KiB across multiple bounded frames.
This is real inter-node traffic on one physical host, not cross-host proof.

The complete runs exercise:

- Verified-TLS laptop CLI with no Docker/state access, loopback-only listener,
  wrong-CA/plaintext denial and Ctrl-C session revocation.
- Anonymous/viewer/internal-node-identity denials; namespace, Service-port and
  authenticated-owner binding. Identically named Services and workloads in two
  namespaces return their respective real application markers.
- Already-open idle/live sockets close on TTL expiry (not prematurely), owner
  or administrator revocation, RoleBinding deletion, Role permission removal,
  Service deletion/recreation/change and loss of quorum leadership.
- WireGuard failure closes an active remote stream without ordinary-route
  fallback. NotReady team-a backends never fall through to Ready team-b pods.
  An actual owned backend is removed during rollout; a Ready replacement then
  serves a new stream.
- Eight concurrent authorized remote streams remain live; a ninth is denied.
  One revoke closes all eight. Sixteen grants enforce the per-user bound, and
  272 grant/revoke cycles cannot exhaust admission through closed history.
- Unsafe audit storage denies new access; failed audit writes cannot prevent
  active-session revocation. Exact metadata-only audit records survive restart
  with private file permissions and without credentials or payloads.
- Actual issuer SIGKILL is confirmed before checking client closure; the remote
  socket is released by its bounded lease, and restart never resurrects an ID.

## Fixes found by the tests

1. Slow Docker/peer reconciliation no longer holds the live world write lock.
   It runs on a detached snapshot; only runtime observations merge back if the
   committed generation still matches. Desired changes still require durable
   CAS commit. Concurrent heartbeats, event deltas and pipeline triggers are
   preserved. Receiver-side slow pod deletion also releases its state read lock
   before I/O. A symbolized failing-run stack identified the former remote
   delete/graceful-stop path; it was not diagnosed from timeout counts alone.
   The wider regression then exposed a rollout visibility gap: successful
   replacement probes stayed hidden until after old-pod retirement. Runtime
   health now publishes under a brief generation-checked lock before scheduling
   destructive actions. No desired configuration, event delta or pipeline
   mutation is published by that health checkpoint. A dedicated native test
   verifies Ready visibility during slow retirement and no desired-state leak.
2. State/Raft/ServiceLB/auth inspection does not park async heartbeat workers on
   blocking state locks. Single-worker timer-contention regressions failed
   before the change and pass afterward. No leader-lease weakening was used.
3. Buffered TLS requests and upgraded stream output are explicitly flushed.
   A buffered duplex/backpressure regression catches the missing request flush.
4. Closed runtime sessions may be evicted only after all sockets close; pending
   and live grants remain bounded and protected. Durable audit is independent
   of this admission cache.
5. Probe age is paired with a monotonic timestamp after Docker inspection, not
   before it. An injected slow inspection proves the initial delay cannot be
   shortened by inspection latency.
6. Docker reads resume the same socket after EINTR, retaining partial responses.
   This never replays a Docker operation. Tests preserve true timeout errors.
   Interrupted-read errors were observed during investigation; this is not a
   claim that every historical 503 had one uniquely proven cause.

The fixture also corrected explicit observation failures, bounded CLI startup,
and distinguished graceful SIGTERM from actual process death. Capacity tests
use a stable application separate from the intentionally disrupted rollout and
wait for committed Service configuration to reach every node. Positive TCP
readiness checks the actual application socket; the negative case keeps a live
socket but a failing readiness probe. These changes do not claim an exec-probe
latency SLO. No successful application response or post-upgrade failure is
silently retried. Pre-upgrade recovery 503 attempts remain recorded as failures
with zero application bytes. All failed/diagnostic bundles remain on disk.

## Wider regression

- Native Rust: **239 passed, three consecutive runs**, zero failures/ignored; existing compiler warnings
  remain, so this is not a warning-free build claim.
- Python qualification infrastructure: **30 passed**.
- All 15 integration suites: **15/15 passed**, bundle
  `rkq-suites-20261027-215034-094994`, 1165.324 seconds, no cleanup errors.
- Actual lifecycle/topology/RBAC regression: **53/53 passed three times**:
  that full-suite bundle, `rkq-suites-20261027-215607-636503` and
  `rkq-suites-20261027-220019-cebb0f`. No fixture changes between these runs.
- Fresh three-daemon faults + 300s observation + live browser: **13/13 passed**,
  bundle `rkq-20261027-215451-478e68`, 527.088 seconds including setup/verification.
- Strict current-source acceptance and coverage gates: **both PASS**:
  `.runs/current-connect-acceptance.json` and `.runs/current-coverage.json`.
  The former requires the latest three matching normal-release Connect runs
  and every integration suite, including parent/cleanup status. The latter
  additionally requires current fault/300s-observation/live-browser evidence.
  Older green binaries and diagnostic builds do not substitute for this version.

| Integration suite | Passed checks |
| --- | ---: |
| Lifecycle/topology/RBAC | 53 |
| Auth HTTP / kubectl | 60 |
| ServiceLB + probes | 54 |
| HTTP probe address | 6 |
| Multi-node workloads/healing | 37 |
| Raft | 23 plus 2 setup checks |
| State-owner handoff | 15 |
| Encrypted mesh | 8 |
| Ingress | 15 |
| Load/chaos | 5 |
| Build/image/deploy | 9 |
| Experimental NeuroPod | 10, one explicit GC skip |
| Full demo | 110 |
| Kubernetes security-negative contract | 13 |
| HTTP protocol | 4 |

The fault run retained **2166/2166 acknowledged application writes** with exact
values in the external ledger. It contained 2168 entries: two ambiguous requests
had also committed, which is not proof of exactly-once delivery. **100 failed or
ambiguous requests** remain visible. Seven acknowledged control-plane writes
converged on all three nodes; the isolated minority returned 504, an unknown
outcome rather than a definite rejection.

| Traffic phase | Successful / attempted |
| --- | ---: |
| Baseline | 92/92 |
| Pod deletion | 46/48 |
| Leader SIGKILL | 40/61 |
| Control-plane partition | 82/82 |
| Node stop/restart | 149/223 |
| Final 300-second observation | 1386/1386 |

This single closed-loop client deliberately includes dead ingress endpoints and
is capped at five requests/second; it is not a saturation benchmark or fault
availability SLO. Real headless desktop/mobile browser evidence checks the
recovered three-pod graph, same-origin GET-only traffic, memory-only token,
search/filter/selection, focus through two actual polls, applied scope, and
narrow-screen layout with no script errors. Captures remain in that run's
evidence directory and do not overwrite existing design-review assets.

## Acceptance boundary

This is private, Service-scoped TCP access: laptop verified TLS to the explicitly
trusted issuer, then operator-provisioned WireGuard between Linux nodes. It is
not a public ngrok relay, laptop-wide VPN, pod-IP routing/CNI, UDP support,
automatic WireGuard provisioning or a saturation-tested data plane. A rollout
or fault may refuse a new stream before application bytes; no zero-downtime
claim or automatic byte-replaying reconnect is made. A graceful-shutdown
latency bound is not qualified by the SIGKILL scenario.

All daemons share one host/kernel/power/outer Docker failure domain. Separate
physical Linux machines, long soak, sustained throughput, disaster recovery,
version skew, legacy in-place upgrades and full Kubernetes conformance remain
unqualified. The experimental NeuroPod deleted-workload GC gap remains an
explicit integration skip, not an implemented feature. The external test ledger
does not prove distributed Royak volume durability.

Existing local changes, dashboard review assets, the host VPN/routes and public
demo are preserved. Only labelled, run-owned disposable resources are used.
Final ownership-label inventories contain no remaining qualification containers,
volumes or networks. Failed and superseded evidence bundles are retained,
including the long remote-delete stack, probe-delay failure, graceful-stop
fixture failure and the wider rollout-readiness failure that prompted the final
health-publication fix. No reset, stash, commit, push or release was performed.
