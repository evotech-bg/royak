# Historical Royak Connect incomplete qualification, 2026-10-27

> Superseded by [the completed local acceptance report](CONNECT-RESULTS-2026-10-27.md).
> The text below preserves the earlier red checkpoint and then-required work;
> it is not the status of the currently qualified binary. Failed bundles remain.

Status: implemented locally, **not accepted as a complete beta/production feature**.
The preserved local work has not been committed, released, pushed or applied to
the public demo. No host VPN/routes were changed.

## Current evidence

- 221 Rust tests and 21 Python qualification tests passed after the asynchronous
  state-inspection changes.
- Current Linux binary: `.runs/linux-royak-connect-final`. Its adjacent
  `.build.json` binds the binary hash to all embedded source hashes and verifies
  that those sources did not change during compilation.
- Two current-binary integration runs cover all 15 legacy suites:
  `rkq-suites-20261027-155541-20b4f5` (6/6 passed) and
  `rkq-suites-20261027-155952-999367` (8/9 passed). `test-demo.sh` exited -9
  during the kubectl section after 71 successful checks. It is a failure, not a
  skip or a completed demo pass; the cause is not established. The existing
  NeuroPod deleted-pod GC gap remains an explicit skip in its suite.
- Actual three-daemon, kernel-WireGuard Connect runs prove binary TCP/HTTP to
  a different node, same-name namespace separation, explicit Service/port RBAC,
  authenticated ownership, verified laptop TLS without Docker/state access,
  loopback-only binding, owner/admin revocation, expiry, Role/RoleBinding removal,
  Service deletion/recreation and no ordinary-route fallback after WG failure.
  Already-open sockets are exercised; TTL checks include elapsed time and the
  recorded closure reason. These are passed individual checks, **not a green
  end-to-end report**.
- Run `rkq-20261027-155806-b71757` additionally passed Ready replacement,
  fail-closed unsafe audit storage, revocation despite audit failure and a
  16-session per-user bound, then failed with a timeout.
- Latest run `rkq-20261027-160439-5fd02a` failed when the gateway API returned
  no response during replacement readiness observation. The fixture then
  dereferenced that unavailable response. Thread diagnostics were unavailable.
  Do not infer a proven deadlock, OOM, or a fixed intermittent failure from this
  evidence. Failed bundles remain on disk.

## Fixes and follow-up

The tests found and corrected downward rounding of the remote TTL budget and
blocking state-lock waits on async/Raft workers. Audit writes and normal
Connect state inspections now use blocking workers; active-stream monitoring
does not park an async worker waiting for the reconcile write lock. Quorum and
expiry remain fail-closed; the leader lease was not weakened.

A rollout intentionally keeps the old Ready pod serving. The readiness fault
fixture now explicitly removes owned old/candidate containers before proving
that NotReady replacements cannot be used or confused with the other namespace.

Next required work:

1. Diagnose the intermittent missing gateway response with live process,
   transport and resource evidence; make unavailable API observations explicit
   fixture failures rather than secondary attribute errors. Repeat the entire
   Connect run without selecting an earlier best pass.
2. Complete quorum-loss, process-restart and durable-audit acceptance. Those
   scenarios exist in the fixture but were not reached in a successful full run.
3. Diagnose and rerun `test-demo.sh`; the overall current-source regression join
   is red/incomplete, not the historical pre-Connect beta green.
4. Review closed-session retention/global admission pressure and sustained
   concurrent-stream behavior before broader operator use. The data hop is
   bounded signed/sealed RPC frames over WireGuard, not a benchmarked general
   VPN/data plane.

WireGuard is operator-provisioned on Linux nodes; Royak does not yet install or
manage its peer keys. The laptop uses a Service-scoped TLS client, not a public
ngrok relay or a cluster-wide VPN. Cross-host failure domains, sustained load,
long soak and production certification are not established.
