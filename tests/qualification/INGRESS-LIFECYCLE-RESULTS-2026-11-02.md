# Royak ingress lifecycle fix — prepared, not deployed

Date: 2026-11-02 Europe/Sofia. The final user instruction is **“Засега подготви
поправката без рестарт”**. Preparation is complete; production restart and
deployment are **not authorized**. Royak remains PID3665524 / SHA256fe5b9625…,
NeuroCaddy remains PID3766583 / SHA25666dca7a8…. Both services stayed active.

## Problem and change

The public demo intentionally enables a server-side chaos monkey that removes
a demo container approximately every20 seconds. Earlier direct requests to Royak
returned142 HTTP502 out of4000, including refused/reset connections to a
container address during its removal. This was independent of NeuroCaddy.

The workspace already contained pre-connect failover and a validated HTTP
response decoder. Its policy still returned an error when an established
connection lost its response, and examined only three alternatives. New wire
regressions first failed in three cases: lost GET response, truncated GET body,
and three stale endpoints hiding a live fourth. The existing no-write-replay
case passed. These behavioral failures are retained separately from an initial
test-harness compile error.

The patch now:

- Retries **bodyless GET/HEAD transport failures** against another endpoint.
- Allows another endpoint before a connection is established for other methods;
  once sending can have begun, POST/PUT/PATCH/DELETE are never automatically
  replayed. An uncertain write remains an error for application reconciliation.
- Examines at most8 eligible endpoints, with500ms per-connect and15s overall
  request deadlines. A failed endpoint is quarantined for2 seconds; the retained
  failure map is bounded to1024 entries.
- Preserves query strings while matching ingress routes on the path alone.
- Rejects an incomplete incoming request body before contacting the application.
- Preserves application error statuses instead of replaying them as transport
  failures. Response decoding checks framing, truncation, binary/chunked data,
  interim responses and a32MiB wire-response limit.

Current workspace changes are in `src/api.rs`, with new
`src/ingress_retry_tests.rs`, `src/ingress_lab.rs` and
`tests/qualification/ingress_lifecycle.py`. All other preexisting source files
were preserved. The original dirty API file was reconstructed into a private
snapshot and its SHA256 matched the goal-start baseline; a goal-only patch is
retained without resetting the shared checkout.

## Minimal legacy-source package

The clean server checkout is commit
`485c8fee64d15047cd891773d0dcc576f6d14bdd`. A separate source export under the
ignored run directory carries the ingress backport, leaving the workspace's
unrelated storage/auth/control-plane development out of the release package.
The old forwarding code also needed the bounded standard HTTP response decoder;
the Hyper client feature adds only `want0.3.1` and `try-lock0.2.5` to its lockfile.
No existing locked package version changed. Its non-test main/control-plane
source is unchanged from that server checkout.

Candidate Linux x86_64-musl SHA256:
`ecd96bb1d7a2a60cf79009aa73e9f11311c1968cdf019a376cfb0ccda72cc6ad`.
Ingress test executable SHA256:
`11f8608dfd4601b9b9b808650a89e64dfff06c6c055fd9863555db47a0f66d94`.

The deployed binary is not a byte-reproduced build of the source checkout, so
source provenance alone is not a production-compatibility proof. Additional
checks show that the accepted `watch` flags/defaults match; the help-text diff
is only the executable name. Loading and privately saving a copy of the real
JSON/neural state preserved every existing state section. No live state write,
reconciler, control-plane API or chaos process was started by that check. The
state reader/writer code is unchanged in the final candidate.

## Verification

| Check | Result |
|---|---|
| Current-workspace API tests |41 passed; explicit lab entry skipped in ordinary unit run|
| Legacy-backport native unit suite |148 passed;2 opt-in fixture entries skipped|
| Linux ingress unit tests |22 passed;2 opt-in entries skipped|
| Opt-in state compatibility |Executed separately on a private real-state copy; passed|
| Native and Linux HTTP lifecycle fixtures |Executed separately; passed; all owned children stopped|

Each HTTP lifecycle fixture covers600 healthy mixed requests,300 reads with
lost responses,200 requests around an explicit laboratory membership update,
a held write, an ambiguous write and a malformed incoming body. It checks
method, query, cookie, body digest and backend identity. The explicit lab
publisher is not a claim of automatic production drain.

The Linux backend SQLite snapshot was independently inspected on the host:
**141 acknowledged writes +1 deliberately ambiguous effect,142 unique IDs,
zero duplicate effects, all payload hashes correct**. The incomplete incoming
request returned400 and produced no application effect. The ambiguous write
returned502 after its effect and was not repeated elsewhere.

A separate ingress-only Linux canary routed to the real demo containers while
the existing production services and chaos configuration kept running. The
60-second client trial offered30 requests/s over32 clients and received
**1801/1801 HTTP200, zero transport errors**, with p99317ms and maximum677ms.
Docker recorded4 demo-container kills over the whole canary lifetime, including
setup; this is not an exact count restricted to the60-second measured interval.
The canary issued only GETs and read-only Docker discovery. Its fixed initial
endpoint list deliberately exercised stale endpoints; it did not start the
production control plane or modify membership. It stopped afterward.

These are bounded ingress/read-failover results, not full application, HA,
geographic, automatic-drain or endurance acceptance. The actual production
`watch` entry point has not been started with the candidate. A public c200
site retest remains a deployment-stage gate; no24-hour test or VM run started.

## Deferred deployment and rollback plan

Royak is configured with `--node-id1 --peers2@10.0.0.141:6443 --bootstrap`.
The local status reports leader1; the configured peer's read-only status request
timed out. The legacy source keeps Raft logs/votes in memory. A restart requires
an explicit decision about that peer and the intended membership; this task
neither changes that configuration nor claims quorum is healthy.

The preparation-only plan is in `deploy-plan.json` in the run directory. A
future authorized rollout must refresh current hashes/backups, resolve the
membership issue, qualify control-plane startup/rejoin, install the candidate
atomically, and verify state projections, ingress, public TLS and workload
traffic. Keep chaos active for the final failure test. If service/compatibility
checks fail, restore the previous executable and any specifically changed unit
configuration. Do not automatically overwrite live state with an older backup.

Passive backups exist at:

```
/home/ubuntu/royak-ingress-20261102-8fce85cb/royak.previous
/home/ubuntu/royak-ingress-20261102-8fce85cb/royak.service.previous
```

The unit backup is root-only; private state copies stay on the server. No
production secrets or private keys are included in the delivery bundle.

Evidence and bundle:
`tests/qualification/.runs/ingress-lifecycle-20261102/`. Key files include
`current-goal-only.patch`, `server-checkout-backport.patch`,
`source-snapshot.tar.gz`, `prepared-ingress-fix.tar.gz`, `SHA256SUMS.json`,
`independent-ledger-check.json`, `real-canary-load.json`,
`real-canary-docker-events.log`, `production-closeout.json`, and the unit/wire
logs. No commits, pushes, service restarts or unrelated cleanup occurred.
