# Local beta / topology goal — complete, 2026-10-27

Completed only for the bounded local objective below. This does not complete a
full Kubernetes-equivalent product, certify production, or authorize public
networking.

## Original objective

Improve Royak in /Users/ivogergov/Projects/orinetes for a bounded local beta:
implement an interactive live cluster topology graph grounded in actual API/state,
fix remaining known probe lifecycle semantics and timed-out exec cleanup, verify
with native/integration/runtime and UI tests in isolated local resources, preserve
all pre-existing changes, and produce an explicit pass/fail acceptance report with
residual production and Kubernetes parity limits. Do not touch the public demo,
external hosts, or perform publishing/pushing. Completion requires the scoped
implemented behavior to pass its tests, not full Kubernetes equivalence or blanket
production certification.

## Completion audit

- [x] Read-only graph uses actual desired state and local/peer observations.
  Namespace/kind/name identities, independently authorized kinds, missing vs
  unknown resources, conflicting placements, observation age and truncation are
  explicit. No secret/config values, commands or invented traffic edges.
  Evidence: topology unit tests; current 53-check API suite; real fault/UI graph.
- [x] Interactive graph has scope, search/kind/state filters, map/list,
  fit/zoom/reset, stable selection and detail connections. Memory-only token,
  applied/pending scope, unavailable/empty/stale/401/403 and old-session response
  handling are tested. Synthetic UI/error/race evidence is labelled separately.
  Real 1440/390 captures were opened by main and documenter; every selected-pod
  connection survived two actual scheduled polls.
- [x] Probe initial delay/period/consecutive thresholds/startup gating and
  reset by ID + StartedAt are implemented and tested. All regular Deployment
  containers and modelled DaemonSet/Job/CronJob containers participate. Rollout
  snapshot isolation and missing-sidecar healing have actual-container tests.
  Unsupported probe fields, runtimes and target shapes are refused.
- [x] Exec watchdog stops normal child/grandchild delayed writes after timeout
  without killing the application. Actual Docker API regression plus a rerun in
  a non-root/read-only/capability-dropped container passed; missing tools refuse
  execution. Hostile process-session escape is not a containment claim.
- [x] Current native and tool checks: 216 Rust tests (three consecutive runs,
  plus retained final log), 21 Python tests, JavaScript/shell syntax and
  git diff --check passed.
- [x] All 15 Linux integration entrypoints passed for current binary/source/
  fixtures. Latest beta helper is 53/53; no older green helper is substituted.
  One explicit NeuroPod GC skip remains named, not claimed implemented.
- [x] Current three-daemon pod/leader/partition/node fault matrix, 300s soak and
  real browser passed 13/13. Acknowledged writes retained: 1539; failed/ambiguous
  requests: 79. Final soak: 949/949. No zero-downtime, capacity or replicated
  volume claim. Causal diagnostic dataset: 198 rows, no new trained model.
- [x] Impeccable detector ran once; incumbent identity preserved. Independent
  verdict scored F1–F5 resolved, disposition ship for those five fixes only.
  Independent ordinary-extension documentation and current-capture freshness
  addendum are complete; no new DESIGN/sidecar/rebrand was required.
- [x] Owned Docker containers/volumes/networks/images absent after cleanup;
  suite cleanup-error lists empty and no fault cleanup-error log. Owned static
  server 48188 stopped. Existing local changes preserved; no reset/stash,
  push/release, live state migration, public demo or external-host test.

## Authoritative evidence

Linux binary: .runs/linux-royak-beta-qualified
SHA-256: cc27ecde07fc497471b81016c09e4cda4aaaf0e972f26beb236949f29716cb82

- Full acceptance and residual limits: [BETA-RESULTS-2026-10-27.md](BETA-RESULTS-2026-10-27.md).
- Canonical current join: .runs/current-coverage.json (passed true).
- Core eight suites: .runs/rkq-suites-20261027-022536-a4da7d.
- Feature seven suites: .runs/rkq-suites-20261027-022537-81af7e.
- Latest 53-check beta repeat: .runs/rkq-suites-20261027-022800-a80639.
- Current fault/UI/focus/dataset: .runs/rkq-20261027-022538-bc400c.
- Final native output: .runs/native-beta-qualified-final.log.
- Independent review: [TOPOLOGY-REVIEW.md](TOPOLOGY-REVIEW.md).
- Preservation/freshness: [TOPOLOGY-DOCUMENTATION.md](TOPOLOGY-DOCUMENTATION.md).
- Supported/upgrade boundaries: [PROBE-TOPOLOGY-CONTRACT.md](PROBE-TOPOLOGY-CONTRACT.md).
- Older failed/superseded/interrupted runs are retained and explained in the
  acceptance report; the incomplete checkpoint join was not promoted to pass.

## Remaining separate work

QF-002 availability gaps, cross-host failure domains, disk-full/full-cluster
backup restore, long soak, legacy in-place upgrades/version skew, full
NetworkPolicy/CNI/CSI/storage/API parity and other untested production features
remain outside this acceptance. New immutable health guarantees apply to pods
launched by this version, not missing historical metadata on legacy pods.

Royak Connect is a proposal only: service-scoped private access with explicit
authorization, expiry, revocation and audit; later outbound reverse/public relay
requires separate approval/design. The current HTTP mesh is not a routed L3 VPN
or verified per-pod mTLS system. No tunnel or new permissions were activated.

The user confirmed beta operators/students and read-only diagnostics first.
Their comp-first preference is recorded for future landing/showcase surfaces;
this existing Operate dashboard extension was built directly in code.
