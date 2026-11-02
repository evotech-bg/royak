# Findings from the real local lab

## QF-001 — HTTP probe rejects a healthy IPv4-only app (tested fix implemented)

Observed 2026-10-26 on the current dirty working source (binary hash and exact
source hashes are in the run manifest). Evidence run:
`tests/qualification/.runs/rkq-20261026-192722-cf183a/`.

The Python application listens on `0.0.0.0:8000`. On its actual Alpine container:

```text
wget -q -O - http://127.0.0.1:8000/health
=> {"ok": true, ...}
wget -q -O - http://172.20.0.2:8000/health  # from its daemon host
=> {"ok": true, ...}
wget -q -O /dev/null -T 1 http://localhost:8000/health
=> wget: can't connect to remote host: Connection refused
```

`http_check_container` in `src/docker.rs` constructs an URL using `localhost`.
This image has BusyBox wget but no curl. Wget tries the IPv6 localhost address,
while the application binds IPv4, so every readiness check is false despite a
healthy, reachable pod. The lab consequently never reaches ingress readiness.

This is a compatibility defect, not evidence that the application is dead.
A future fix should explicitly define HTTP probe network/host semantics and
cover IPv4-only, IPv6-only, dual-stack and loopback-only listeners. Simply
dropping readiness checks would be unsafe. Probe timing/threshold and timeout
cleanup remain separate, already-known issues.

The harness keeps `--probe-mode http` as its default to catch this regression.
`--probe-mode exec-ipv4` explicitly runs the same health request with Python
against `127.0.0.1`. This allows testing unrelated Raft/mesh/recovery behavior;
its pass **does not close QF-001**. Probe mode is recorded in the manifest.

Resolution on current sources: HTTP probes use the explicit pod interface IP,
with IPv6 URL brackets, instead of resolver-dependent localhost. The real
`test-http-probe-address.sh` regression passed 6/6 in
`rkq-suites-20261026-231310-6725b5`: an IPv4-only app becomes Ready and a healthy
loopback-only app remains NotReady. The complete three-daemon run
`rkq-20261026-230921-b21cb5` passed with default HTTP readiness and no workaround.
IPv6-only network behavior is not qualified; URL formatting is unit-tested.
Probe timing/threshold and timed-out-exec cleanup were separate work; the new
implementation and its current qualification status are recorded as QF-006
below and in `BETA-RESULTS-2026-10-27.md`, not inferred from this older run.

## QF-002 — Fault-window request availability gaps (partially mitigated, open)

Evidence: `tests/qualification/.runs/rkq-20261026-194141-c1eaef/`.
The scoped fault contract passed, with 559 retained acknowledged writes and 67
failed/ambiguous requests. It did **not** demonstrate zero-downtime service.

During the leader process SIGKILL, the unavailable node's ingress failed 16
requests, but the two *other* ingress endpoints also returned five HTTP 502s
each. A pod deletion produced another 502 on each of those surviving endpoints.
During the node outage there were five timeouts on surviving ingress endpoints,
in addition to requests deliberately sent to the stopped node. These are not
all explained by the client's deliberate use of the dead ingress endpoint.

Code-supported contributor: the ingress snapshot fast path in `src/api.rs`
selects one local/remote backend and returns 502 on a proxy error; that request
does not try another healthy backend. Remote mesh availability and stale census
entries therefore matter beyond the failed node's own ingress. This is a
supported contributor, not a complete timing/root-cause investigation.

Before an availability claim: define external load-balancer health handling,
backend quarantine/failure detection, bounded failover and an explicit fault
availability/RTO contract. Do **not** blindly retry arbitrary POST requests:
once a request might have reached a backend, replay can duplicate side effects.
Connection failures before transmission and idempotency-key-protected requests
need different retry rules. Add focused fault regressions for surviving ingress
endpoints, not only eventual replica-count recovery.

Current implementation adds bounded pre-transmission connection failover (up
to three candidates, 500 ms/connect) and two-second transport-failure quarantine
for later requests. It reuses the actual connected socket; there is no discard-
and-reconnect race. After transmission starts, errors are returned without
replaying even a POST. Two real-socket Rust tests cover both paths.

In the new three-daemon run, leader SIGKILL caused no failed requests on the
surviving ingress endpoints, but four surviving-endpoint 502s remained across
pod deletion/node loss. Total failed/ambiguous requests: 62, including deliberate
requests to the dead endpoint. This is not a zero-downtime or controlled A/B
performance result; further endpoint health and protocol work remains.

Latest constrained-workload repeat, `rkq-20261027-000311-fda18b` (2026-10-27):
1262 acknowledged writes retained, 66 failed/ambiguous requests. These include
59 failed connections to the deliberately stopped ingress, four 502s on live
ingress endpoints during pod/node loss, and three 503s on the restarted ingress
during recovery. Final 300-second observation was 780/780 successful. QF-002
therefore remains open; the security/HTTP framing fixes do not establish zero
downtime or an availability SLO.

## QF-003 — Kubernetes container security constraints silently ignored (fixed for explicit Docker subset)

Confirmed in a real isolated Docker daemon on 2026-10-26:
`tests/qualification/.runs/rkq-suites-20261026-231020-777ce3/`.
`test-k8s-negative-contract.sh` submitted a harmless sleeping Alpine Deployment
with `runAsNonRoot: true`, `readOnlyRootFilesystem: true`,
`allowPrivilegeEscalation: false` and `capabilities.drop: [ALL]`.

The API accepted it and created a container, but all four enforcement checks
failed. The suite exits nonzero: 1 passed / 4 failed. `PodSpec` and `ContainerSpec`
in `src/spec.rs` do not model `securityContext`, so these unrecognized fields
are discarded instead of enforcing the requested restrictions or refusing them.

Independent repeat with explicit Docker observations:
`tests/qualification/.runs/rkq-suites-20261026-231225-baf095/`:
UID `0`, `ReadonlyRootfs: false`, `CapDrop: null`, `SecurityOpt: null`.
The final repeat `rkq-suites-20261026-231849-799a16` also specifies numeric
`runAsUser: 10001` (a valid non-root user for this harmless workload) and confirms
the same four failures with UID 0.

This is a **production/security contract blocker**, not a harmless missing
feature: a successful Kubernetes-looking apply can mislead an operator about
the actual privileges of the workload. No exploit or host access was attempted.
Fix must enforce an explicitly supported security-context subset end-to-end
(including remote placements), or fail closed with a clear unsupported-field
error. A rejection is safer but is not Kubernetes feature parity.

Resolution on 2026-10-27: strict typed pod/container security settings are
inherited, persisted, transported to remote nodes and applied to Docker. The
current binary passed all **13** checks in
`rkq-suites-20261027-000311-87e5ed`, including actual UID 10001/GID 10002,
read-only root, empty kernel effective/bounding capability sets, NoNewPrivs=1,
restart/replacement preservation and explicit rejection of contradictory or
unsupported fields. Refusing the supported subset would fail this fixture.
See [SECURITY-HTTP-CONTRACT.md](SECURITY-HTTP-CONTRACT.md) for exact supported
fields, schema-3 upgrade requirements and limitations; full Kubernetes security
context support, hostile multi-tenancy and mixed-version upgrade are not claimed.
The complete current-source repeat `rkq-suites-20261027-000446-e9e4ee` also passed
13/13, and `rkq-20261027-000311-fda18b` verified kernel constraints on all final
replacement pods across separate Docker daemons after its full fault matrix.

## QF-004 — PaaS builds need GNU/BSD tar, not BusyBox tar (dependency finding)

The original broad suite run's build test failed because the minimal lab had
BusyBox tar. `src/docker.rs` invokes `tar --no-xattrs`, which that implementation
does not support. Installing GNU tar in the isolated test environment restores
the declared build prerequisites; `rkq-suites-20261026-232027-2fa08a` passed the
real build-arg → image build → deploy → served-marker contract 9/9.

The suite runner now installs and records GNU tar. Document this optional PaaS
dependency or make context creation portable; do not claim that the source-build
feature needs only the Docker socket. The earlier failure is retained.

## QF-005 — Ingress exposes chunk framing as application payload (fixed for bounded buffered HTTP)

Real regression `rkq-suites-20261026-232348-2a5e18`,
`test-http-protocol.sh`: **3 passed / 1 failed**. A valid HTTP/1.1 chunked
upstream response decodes to `hello` when fetched directly, but the same request
through ingress returns HTTP 200 with body `b'5\r\nhello\r\n0\r\n\r\n'`.

Source-supported cause: `proxy_request_connected` in `src/api.rs` reads the raw
response, removes the `Transfer-Encoding` header, and passes the still-framed
bytes to a new response body. This corrupts a normal API response format; it is
not just a latency or availability measurement. Fix response framing with a real
HTTP parser/streaming path or strict bounded decoding, including trailers and
malformed/truncated chunks. Long-lived streaming/SSE and complete HTTP protocol
semantics remain unqualified too.

Resolution on 2026-10-27: a bounded Hyper HTTP/1 response parser decodes transfer
framing before constructing the outgoing body. The real regression passed
**4/4** in `rkq-suites-20261027-000311-87e5ed`; ingress now returns `hello`, not
chunk wire bytes. Unit tests also cover binary chunks/extensions/trailers,
malformed/truncated bodies, HEAD and interim responses. No backend request is
replayed by parsing. Trailers are consumed rather than forwarded; 32 MiB limits
and explicit unsupported-upgrade behavior apply. This does not qualify a
streaming/SSE/WebSocket proxy. See the [HTTP contract](SECURITY-HTTP-CONTRACT.md).
The full-suite repeat `rkq-suites-20261027-000446-e9e4ee` again passed 4/4.

## QF-006 — Probe lifecycle and detached timeout work (runtime regressions passed)

The earlier loop checked probes per reconcile tick without their independent
initial delays/periods or consecutive thresholds. Exec observation timeout did
not guarantee the exec process and descendants had stopped. These are distinct
from QF-001's address selection.

Current implementation uses monotonic schedules, separate startup/liveness/
readiness counters, reset by container ID + Docker StartedAt, immutable launch
health snapshots during rollout, aggregate regular-container readiness and a
process-group timeout watchdog. Unsupported handlers/fields/runtime and probe
targets are explicitly refused within the documented subset. Missing sidecars
heal after creation grace; normal liveness restarts only the failing container.

Current binary `cc27ecde…` passed the latest **53/53** real Docker/API fixture
in `rkq-suites-20261027-022800-a80639`, including actual startup-failure
restart/reset and unsupported-controller-target refusal. The final overall
current-source full/fault status is not inferred from earlier green attempts.
See [beta report](BETA-RESULTS-2026-10-27.md) and
[support boundaries](PROBE-TOPOLOGY-CONTRACT.md). No hostile process-session
escape containment, real-time scheduler or full Kubernetes probe claim.

## QF-007 — Namespaced URL could reach cluster-scoped resource lists (implemented, runtime regression passed)

The dashboard's broad namespace rewrite exposed a router/auth mismatch:
`/api/v1/namespaces/<ns>/namespaces` could be authorized as a namespace-bound
resource but routed to a global collection. Current entry and route guards
reject namespaced forms of known cluster-scoped resources with 400. The client
rewrites only explicit namespaced resources, leaving namespaces cluster-scoped.
Actual viewer-token regressions cover namespaces/nodes/persistentvolumes;
native tests cover the other known cluster-scoped paths. This is a specific
scope correction, not a blanket proof that every unknown API path is conformant.

UI follow-up F1–F5 (scope routing, ancillary availability, applied/pending
session, focus continuity and offscreen map discovery) were independently scored
resolved, `disposition: ship`, in [TOPOLOGY-REVIEW.md](TOPOLOGY-REVIEW.md).
That verdict is scoped to the five fixes, not production certification.
