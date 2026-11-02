# Probe and read-only topology contract

This describes the bounded Docker implementation, not Kubernetes conformance.
Qualification status and exact evidence live in `CURRENT-RESULTS.md`.

## Health lifecycle

Supported handlers are exec, plain HTTP and TCP, with numeric ports. Exactly
one handler is required. Unknown probe/handler fields, named ports, HTTPS,
custom HTTP host/headers and gRPC are refused rather than silently ignored.
Timeout/period/threshold values must be positive; initial delay may be zero.
Startup/liveness successThreshold must be one. New manifest timeout defaults
to one second; older persisted probes lacking the field retain three seconds.

Docker checks use monotonic time, initial delay, periods, consecutive failures
and successes, a startup gate and container incarnation (ID + StartedAt).
Readiness never restarts an application. Startup/liveness restart only the
failing container. The reconcile loop is synchronous: a period is a minimum
spacing, not a real-time scheduling deadline under load.

All regular Deployment containers participate in aggregate pod readiness.
DaemonSet/Job/CronJob use their currently modelled single regular container.
This does not add full multi-container controller or Kubernetes CronJob API
support. Ordinary init-container and NeuroPod probes are refused.
Probes on additional/init containers in the single-container controllers are
also explicitly refused, not silently treated as working.

The launch contract snapshots expected regular container names and health
settings into an internal Docker label. A rolling update does not apply the
new desired probe settings retroactively to old pods. Corrupt snapshots fail
closed. Disappeared sidecars cause whole-pod replacement after a ten-second
creation grace; a normal liveness restart remains container-local. Existing
probed/multi-container Deployment templates roll once for the new contract.
Upgrade all nodes together; mixed-version remote launch is not qualified.
These immutable-snapshot guarantees apply to pods launched by the new code.
Legacy unlabelled pods use a desired-spec compatibility fallback: their
historical probe/container layout cannot be reconstructed from missing labels.
Do not assume an in-place upgrade preserves that first rollout's old settings.
An unchanged-spec controlled rollout/recreation of legacy workloads and a
separate upgrade rehearsal are required before changing their probes/layout.
The local qualification starts with isolated fresh resources, not an in-place
upgrade of a pre-existing cluster.

Exec uses an isolated process-group watchdog. Missing sh/setsid/sleep or /proc
support fails before user code. Timeout kills the probe group without killing
the application. Actual regression tests require normal children/grandchildren
to stop before a delayed write. This is not containment of hostile commands
deliberately escaping the process group; no untrusted multi-tenant guarantee.
The watchdog uses signal syntax accepted by both BusyBox ash and Debian/Ubuntu
Dash. Timer cancellation reaps its owned sleep immediately, including a signal
arriving between the cancellation check and wait. The explicit container shell
matrix tests success/failure latency, hard deadlines, late writes and zombies
with/without init; it is not a full Debian cluster certification.

Probe containers now require Docker's minimal PID-1 init/reaper. The watchdog
cancels and reaps its own sleep timer on success/failure; init adopts arbitrary
descendants after a hard group kill. Unprobed containers retain their PID-1
behavior. A probe-runtime template version rolls legacy probed workloads;
executing a probe against a container without init fails closed. Probed remote
plans use signed `/royak/v3/create-pod`, which old workers refuse rather than
silently launching without reaping. Docker create/start failure when init is
unavailable is not downgraded to an unsafe fallback. This changes application
PID 1 to Docker init for probed containers and must be included in an upgrade
rehearsal; no live-cluster upgrade qualification is claimed.

## Graph and UI

`GET /royak/v1/topology?namespace=NAME` requires pod-list permission for its
scope. Additional kinds have independent list checks. Secret/config values,
probe commands and bearer tokens are excluded. Stable identities include kind,
namespace and name. Duplicate contradictory placements are Conflict, not two
healthy replicas. Desired routes/selectors are not evidence of successful
traffic. Observations have timestamps/age; the distributed census is not an
atomic cluster snapshot. The API caps nodes/edges and reports truncation.

The dashboard is read-only, uses same-origin GETs and keeps the token only in
memory. It distinguishes applied scope from pending edits; blank token reuses
the retained token. Disconnect removes it. Unauthorized snapshots are cleared;
offline snapshots remain explicitly stale. Unavailable ancillary APIs are not
reported as healthy empty collections. Session epochs reject late responses.
Search, kind/state filters, map/list, fit/zoom/reset, connection detail and
keyboard focus restoration operate without mutation controls. Mobile defaults
to a readable list; a fitted desktop map is not a replacement for the list.

## Royak Connect boundary

Royak Connect is implemented as namespace/Service/port-scoped access with RBAC,
expiry, revocation and termination of already-open streams after rights removal.
The laptop client exposes only a loopback listener, without laptop VPN/routes.
The qualified cross-node path uses kernel WireGuard between the owned Linux VMs;
it fails closed without that path. See `CONNECT-CONTRACT.md` and the exact
current acceptance artifacts. Public/reverse tunnels, per-pod mutual TLS and a
general routed L3 VPN are not implemented or certified by this contract.
