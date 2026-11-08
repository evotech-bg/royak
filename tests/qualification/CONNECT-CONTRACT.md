# Royak Connect — local beta access contract

User-approved scope, 2026-10-27: private laptop access to a Service/port in an
explicit namespace, including pods on another local Royak node. Namespace/RBAC,
expiry, explicit revocation and permission removal must close already-open TCP
connections. WireGuard is the node-to-node underlay; the laptop uses a verified
TLS client without VPN/Docker installation. No public relay/tunnel, host default
route changes or dashboard mutation controls.

## Boundaries

- CLI subcommands in the existing Royak binary; listener binds only loopback.
  Credentials come from a private file/environment, never command-line tokens,
  URLs, logs or session metadata. TLS certificate verification is mandatory;
  no insecure-skip-verification fallback. The laptop client does not load local
  cluster state or require the Docker daemon.
- A session names exactly namespace + Service + declared numeric TCP Service
  port, authenticated owner and bounded TTL. It is not arbitrary IP/pod access,
  a namespace-wide VPN, a public URL or permission to mutate workloads.
- Explicit services/connect RBAC permission, scoped by namespace/resourceNames;
  ordinary view/edit roles do not acquire it automatically. Each new connection
  rechecks current rights and current Service configuration. Session ownership
  is checked independently of possession of an opaque session ID.
- Active connections close on expiry, session revoke, rights loss, Service
  deletion/change and process failure. Revocation is fail-closed, including when
  audit storage fails. Sessions are ephemeral and node-affine; restart does not
  resurrect them. Their history is metadata-only, durably audited and bounded.
- In a Raft cluster the issuer is the quorum-confirmed leader, not an arbitrary
  stale follower. Lost quorum/leadership closes its sessions. A standalone
  issuer must own its state file. There is no automatic redirect to a server
  whose TLS identity the laptop has not explicitly trusted.
- Ready backend selection uses actual local inventory/fresh peer census in the
  same namespace, never name-prefix guesses. Service selectors unsupported by
  this implementation must be refused rather than broadened.
- Remote traffic must use a real configured WireGuard interface and a pinned
  node-to-WireGuard-address map. No fallback to the ordinary peer/mesh address.
  Private node operations retain signed, replay-protected, sealed transport;
  they do not accept an admin bearer token as a node identity. No payload replay
  after an ambiguous write. Interface setup in tests stays inside owned Linux
  containers; no VPN configuration on the user's laptop/host.
- Control/audit records exclude bearer tokens, WireGuard private keys, payloads
  and application credentials. Session/connection counts, body sizes, lifetime
  and retained audit history are bounded.
- Limits are 16 active/pending sessions per identity, 8 connections per session
  and 256 retained runtime sessions. Closed sessions with no remaining sockets
  may be evicted to admit new access; their durable audit is independent of this
  cache. An evicted ID returns 404 rather than 410, and neither permits access.
  Audit storage is a private metadata-only JSONL file; it must be rotated before
  the fixed 8 MiB file capacity is reached. No automatic destructive rotation occurs.
- A rollout or fault can refuse a new stream with 503 before HTTP upgrade or
  application bytes. This is not a successful request or zero-downtime guarantee.
  Application bytes are never automatically replayed after a stream opens.

## Required actual E2E evidence

- Laptop-style CLI without Docker/state access; trusted CA succeeds, wrong CA,
  plaintext server and anonymous/viewer/foreign-owner callers fail closed.
- At least two distinct Docker daemons and real WireGuard peers/handshake/data
  counters. Force the only matching Ready backend onto the other node, prove
  binary TCP and HTTP access through Connect, and prove no underlay fallback.
- Same Service name in another namespace cannot be reached with the grant.
  Wrong Service/port, unready backends and direct private-node calls are refused.
- Hold sockets open while TTL expires, owner/admin revokes, and RBAC is removed;
  prove existing sockets close and subsequent opens fail, not merely CLI output.
- Service deletion/recreation/change cannot silently retarget an existing grant;
  backend replacement may serve new TCP connections only after readiness.
- Process/node/WireGuard failure closes streams; no automatic replay of bytes.
- Audit and restart behavior, secret redaction, limits and owned cleanup.
- Native tests and existing auth/state/ServiceLB/multi-node regression suites;
  bind evidence to exact current source, fixture and Linux binary hashes.

## Status

Latest inclusive source qualification, including the zero-skip NeuroPod follow-up:
[NEUROPOD-GC-RESULTS-2026-10-27.md](NEUROPOD-GC-RESULTS-2026-10-27.md).

The bounded local contract is qualified on the exact version in
[CONNECT-RESULTS-2026-10-27.md](CONNECT-RESULTS-2026-10-27.md): three complete
54-check Connect runs, three 53-check lifecycle runs, all 15 integration suites
and fresh fault/300s-observation/live-browser evidence. Real kernel WireGuard
runs inside the isolated Linux test containers. This does not qualify separate
physical machines or imply that Royak provisions WireGuard, keys or public URLs.

## Client and operator setup

The operator must provision an UP kernel WireGuard interface on every participating
Linux node and pin its peers before starting Royak. Private keys stay in the
operator's WireGuard configuration, never in the laptop client or API request.
Set `ROYAK_CONNECT_WG_INTERFACE` to that interface and `ROYAK_CONNECT_WG_PEERS`
to a JSON node-name to private numeric `IPv4:API-port` map. Royak binds its
Connect node sockets to the configured interface and refuses ordinary-route
fallback. Other existing cluster traffic is not automatically moved to WireGuard.

The laptop trusts the issuer's CA and uses its existing private bearer-token file:

```sh
royak connect open --server https://royak.example:6443 \
  --ca-cert /path/to/trusted-ca.pem --token-file /path/to/private-token \
  --namespace team-a --service api --port 80 --local-port 8080 \
  --ttl-seconds 300
```

This is an example address, not a public relay. The selected issuer must be the
current confirmed leader. Token files must be private regular files (0600);
`ROYAK_TOKEN` is an alternative, not a command-line token argument. The client
prints the loopback address and session ID, which are not replacement credentials.
Use `connect list`, `connect revoke` and `connect audit` with the same connection
options. Ctrl-C closes the listener and attempts to revoke the session; process
failure does not provide an automatic byte-replaying reconnect.

The server must expose TLS (for example, the existing `watch --tls` mode).
API and ingress share a private, persistent per-state identity at
`<state-path>.tls.json`. Invalid or unsafe identity storage fails closed; normal
restarts do not rotate it. The first upgrade from ephemeral identities requires
an explicitly authenticated trust update. See the
[TLS/Connect remediation report](TLS-CONNECT-RESULTS-2026-10-28.md) for storage,
upgrade and unqualified certificate-lifecycle boundaries.
The plain HTTP `api` mode is intentionally incompatible with this client.

The cross-node data hop currently uses bounded, signed/sealed RPC data frames
over WireGuard. It is a TCP Service access feature, not a general pod-IP VPN,
UDP tunnel, CNI, automatic mesh installer or a saturation-tested data plane.

Run the owned three-daemon qualification after building both platform binaries:

```sh
cargo build --bin royak
python3 -B tests/qualification/run.py build --binary tests/qualification/.runs/linux-royak-connect-current
python3 -B tests/qualification/connect_e2e.py \
  --binary tests/qualification/.runs/linux-royak-connect-current \
  --client target/debug/royak
```

This creates and removes only labelled, disposable Linux containers and test
disks. Their WireGuard interfaces stay inside the test containers; the laptop's
VPN, routes and public demo are not changed. Only an actual completed report
establishes which acceptance checks passed.
