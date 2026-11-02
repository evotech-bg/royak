# Local beta / topology acceptance — 2026-10-27

**PASS for the bounded local beta contract.** Current-source native,
integration, lifecycle, fault/UI and independent review/documentation gates
are complete. This is not production certification or Kubernetes conformance.

## Scope and reproducibility

Read-only live cluster topology, honest session/scope/availability feedback,
Docker probe lifecycle and timed-out exec cleanup. Existing local changes are
preserved. No public demo, external hosts, push, release or public tunnel.
This is one physical host, not production certification or Kubernetes parity.

Linux binary: `.runs/linux-royak-beta-qualified`, SHA-256
`cc27ecde07fc497471b81016c09e4cda4aaaf0e972f26beb236949f29716cb82`.
Embedded Rust/HTML/CSS/JS/sh sources are included in evidence fingerprints.
This includes apply-validation refusal of probes targeting unmodelled
additional/init containers in DaemonSet/Job/CronJob. Prior `beta-final`
(`db645f05…`) is superseded. The `022034-52e1b0` suite run was deliberately
interrupted for that source change; partial results are not accepted.

## Acceptance gates

| Gate | Current evidence |
| --- | --- |
| Native runtime/authorization/graph contracts | 216 Rust tests passed, three consecutive runs with normal parallel execution |
| Qualification/checker/causal-dataset tooling | 21 Python tests passed |
| Synthetic UI correction regressions | Passed auth replacement/memory-only storage, applied/pending scope, namespace paths, unavailable clearing, delayed old-session response, two polls/focus-removal fallback, fit/dependencies, keyboard/filter/list, offline/401, hostile text and 390px layout |
| Actual Docker lifecycle/RBAC regressions | Latest current fixture **53/53 passed** in `022800-a80639` (250.757s); also 49/49 predecessor passed in `022537-81af7e` |
| All 15 Linux integration suites | **15/15 passed**, current-source/current-fixture join; disjoint 8/7 batches plus newest beta fixture repeat |
| Three-daemon fault matrix + 300s soak + real browser | **13/13 passed**, `.runs/rkq-20261027-022538-bc400c`, 532.186s |
| Independent finish review | **ship**, F1–F5 scored resolved; scope is the five fixes, not a new whole-surface audit |
| Documentation preservation | Independent ordinary-extension pass and final-current-capture freshness addendum complete; incumbent identity preserved |

Implementation/support boundaries are in
[PROBE-TOPOLOGY-CONTRACT.md](PROBE-TOPOLOGY-CONTRACT.md).
Supplemental current-binary real focus report:
`rkq-20261027-022538-bc400c/ui-focus-report.json` — three connections, each
through two actual scheduled polls. Error/403/removal states are independently
labelled synthetic browser evidence, not injected backend faults.
The standalone secured-container watchdog regression was rerun on the current
script and passed exit codes, deadline, child/grandchild cleanup, application
survival and fail-closed missing tools. The API/Docker path is separately
covered by the 53-check suite above.

## Integration matrix

The current-source/current-fixture join is `.runs/current-coverage.json`
(`passed: true`). It checks the exact binary, embedded sources, current suite
scripts and their helper dependencies. The 53-check beta repeat supersedes the
49-check helper snapshot in the feature batch; no older green helper is selected.

| Suite | Passing checks | Evidence bundle |
| --- | ---: | --- |
| Authentication/RBAC/kubectl | 60 | `022536-a4da7d` |
| ServiceLB/readiness/updates | 54 | `022536-a4da7d` |
| HTTP probe target | 6 | `022536-a4da7d` |
| Multi-node launch/self-healing | 37 | `022536-a4da7d` |
| Raft state/failover/snapshot | 25 (includes setup) | `022536-a4da7d` |
| State-owner handoff | 15 | `022536-a4da7d` |
| Encrypted HTTP mesh | 8 | `022536-a4da7d` |
| Ingress | 15 | `022536-a4da7d` |
| Load/chaos | 5 | `022537-81af7e` |
| Build → deployed marker | 9 | `022537-81af7e` |
| NeuroPod experimental | 10; 1 explicit GC skip | `022537-81af7e` |
| Demo/full feature script | 110 | `022537-81af7e` |
| Enforced security subset | 13 | `022537-81af7e` |
| HTTP response framing | 4 | `022537-81af7e` |
| Lifecycle/topology/RBAC | 53 | `022800-a80639` |

Bundle prefixes are `.runs/rkq-suites-20261027-`. Native final output is retained
as `.runs/native-beta-qualified-final.log` (216 passed). Python tools passed
21/21. JavaScript syntax, changed shell syntax and `git diff --check` passed.
Existing native unused-import/dead-code warnings are non-blocking and were not
silently represented as a warning-free build. Cloud CI was not dispatched.

## Final current-binary fault and browser evidence

The actual faults were pod deletion, confirmed leader SIGKILL/restart, a
control-plane minority partition, and loss/restart of an entire inner Docker
daemon with its test disk retained. Every fault window served at least one
successful request; this is deliberately weaker than an availability SLO.
Minority writes were not acknowledged (504/outcome unknown), acknowledged
control writes eventually converged, replicas settled to exactly three, and
actual replacement containers retained UID/GID 10001, read-only root,
no-new-privileges and empty effective/bounding capabilities.

- **1539 acknowledged application writes** retained with correct values in
  the external SQLite WAL ledger; 1540 total ledger rows. There were **79
  failed/ambiguous requests**. This does not prove replicated Royak storage.
- Baseline: **76/76**, across all three ingress endpoints.
- Final 300s observation: **949/949**, across all three endpoints; latency
  nearest-rank p50 217.287ms, p95 800.541ms, p99 2163.641ms. A single closed-loop
  client is not a capacity/saturation benchmark.
- Fault windows: pod deletion **30/33**, leader SIGKILL **30/46**, control
  partition **68/68**, entire-node outage **113/169** successful requests.
  The client deliberately addresses every ingress, including the unavailable
  one; these totals are not an external-load-balancer SLO or zero-downtime proof.
- Current real UI: **3 pods, 16 nodes, 10 relationships**, same-origin GET-only
  interactions, applied/staged namespace, keyboard/search/filter/map/list/fit,
  two scheduled polls and no script errors. Full-page 1440px/390px captures
  were opened and validated by the main agent; independent documentation
  freshness review follows the UI verdict's limited scope.
- Causal dataset exported: **198 diagnostic rows**, labels separated from
  features. Missing CPU/memory measurements remain null. No model was trained
  or granted infrastructure action authority.

## Failures retained, not selected away

- `.runs/rkq-suites-20261027-015437-29e492`: new test adapter incorrectly
  expected a Ready condition rather than existing containerStatuses.ready.
  Adapter was corrected without weakening readiness checks; the API now also
  provides a consistent Ready condition. This is not a runtime product pass.
- `.runs/rkq-suites-20261027-015838-b15003`: old goal binary, 14/15 suites;
  demo liveness-log check failed (109 other assertions passed). Diagnostic
  rerun `.runs/rkq-suites-20261027-021449-8d5476` passed. The revised fixture
  waits for the actual failure-threshold message and prints diagnostic logs on
  failure instead of assuming installation/probe work completes in 12 seconds.
  Direct inspection of this owned rerun showed a 12,015.9ms reconcile tick
  (including the existing NetworkPolicy work) and an actual liveness threshold
  restart at tick 4. A 12s total sleep was not a valid threshold deadline for
  that loaded multi-feature fixture; product thresholds were not reduced.
  The stricter diagnostic demo rerun passed all 110 assertions (332.84s).
- `.runs/rkq-20261027-015448-15385c`: earlier goal snapshot passed 13 fault/UI
  checks, retained 1595 acknowledged writes with 84 failed/ambiguous requests.
  Its passing result is historical, not qualification of the final source.

The coverage join selects the latest matching source/binary/fixture attempt,
including failures; it does not choose an older green attempt.

## Safety and completion audit

The final check found no containers, volumes or networks labelled
`royak.qualification` remaining. The owned loopback static server (48188) was
stopped after synthetic tests. Foreign workloads were not cleaned, stopped or
reconfigured. All three terminal suite reports have empty cleanup-error lists;
the fault profile exited zero and its owned resources are absent. No public
demo, remote host, source push/release or user's live state migration occurred.
Fifteen unrelated source modules were also compared with the pre-goal
security/HTTP snapshot and match byte-for-byte, including existing mesh,
persistence, placement, Raft, security, ServiceLB and store changes. Required
probe/API/UI edits were applied without resetting or stashing the dirty tree.

The interactive graph, timing/threshold/startup/incarnation semantics,
process-group timeout cleanup, per-resource scope/secret boundaries, current
source runtime tests, valid real UI captures, independent F1–F5 verdict and
documentation preservation each have separate evidence above. A passing narrow
check is not used as a substitute for the others. Remaining items below are
explicitly outside this bounded local acceptance, not silently called complete.

## Residual limits

- QF-002 fault-window request availability gaps remain open. No zero-downtime
  or arbitrary production availability SLO claim.
- Three Docker daemons still share one host/kernel/failure domain. Cross-host
  faults, disk-full, full-cluster backup/restore, long soak and version-skew are
  not qualified. All nodes must upgrade before relying on the new contracts.
  In-place upgrade of legacy unlabelled pods is also unqualified; immutable
  old-template health is guaranteed only for pods launched by the new code.
  Legacy workloads need a separate unchanged-spec rollout/migration rehearsal.
- Probe scheduling is synchronous and tick/load-bounded. Supported Docker
  handlers/subset only; no hostile exec-session escape guarantee, no init or
  NeuroPod probe support, no full multi-container Job/CronJob API parity.
- Host-local storage is not replicated. NetworkPolicy remains a subset.
  HTTP proxy response handling is bounded/buffered; SSE/WebSocket/CONNECT and
  arbitrary streaming semantics are not qualified by these tests.
- NeuroPod deleted-workload pod-directory GC remains an explicit integration
  skip. Legacy visual contrast/branding drift is not a rebrand authorization.
- Mesh encryption is not a demonstrated full L3 VPN or per-pod identity/mTLS
  system. Royak Connect/ngrok-like access remains a separate proposal.
- Causal dataset export is preparation for ML evaluation, not a trained or
  production-validated model, and adds no autonomous infrastructure actions.
