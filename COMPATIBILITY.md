# Royak ↔ Kubernetes: the honest compatibility ledger

**Scope clarification (2026-10-27):** a working row below means its named Royak
behavior, not complete Kubernetes API/field semantics. The full upstream CNCF
conformance suite has not been run. See the current
[qualification coverage contract](tests/qualification/KUBERNETES-COVERAGE.md)
and [open findings](tests/qualification/FINDINGS.md). In particular,
Docker container `securityContext` now has an enforced, explicitly bounded
subset. Unknown security fields are refused, not silently ignored. See the
[security and upgrade contract](tests/qualification/SECURITY-HTTP-CONTRACT.md);
this is not full Kubernetes security-context or untrusted-tenant qualification.

**Current pre-capture integration (2026-10-31, unreleased and NOT QUALIFIED):**
The current source includes durable, namespace/claim/volume-bound pre-capture
request DATA with replay/cancel/quarantine guards. Its exact source snapshot
passes877 native and904 Linux unit tests with no omissions; full141-input live
source equality is checked after integration. It has no ordinary backup API
dispatcher, genuine physical capture source or managed-volume restore yet.
Disk schema is now9 and current Raft sealing purpose is
`royak-raft-state-v8-precapture-reservations`; older schemas/domains cannot import
reservation history. Preserve state/recovery keys and do not mix node versions,
roll back or assume a qualified rolling upgrade. The prior N2 normal-server
build/size result below is historical, not a measured P3 server artifact.
See [exact source/test boundaries](tests/qualification/BACKUP-PRECAPTURE-RESULTS-2026-10-31.md).

**Earlier normal N2 integration (2026-10-31, unreleased and NOT QUALIFIED):**
The reviewed normal N2 source is now integrated locally. The qualification-only
inherited-FD control thread is excluded from the normal server; its two pure
cases remain test-only. Native storage is still an explicit Linux-root,
clustered-Docker/TLS opt-in, not an enabled distributed-volume guarantee.
Fresh normal-source tests, server footprint, real API recovery and the full
physical/data/backup/endurance gates remain separate requirements.

The exact earlier normal N2 full units pass856native/883Linux with zero runtime
omissions. Normal ARM64 server release compilation succeeds, but its unchanged
10MiB size gate FAILS at17,111,384bytes (16.3187MiB). Runtime storage/backup and
production qualification do not follow from these unit/build results.

That N2 source introduced disk schema8 and the Raft node-directory sealing domain.
Keep the original state and recovery keys; mixed-version writes, rolling
upgrade and rollback after new-domain persistence are not qualified. Old safe
states migrate to explicit unenrolled metadata, not fabricated node authority.
The diagnostic coordinator requires Linux root: macOS/non-root server
exec/log/port-forward diagnostics remain unsupported/fail-closed in this
candidate. Standalone `api` now starts the same fixed recovery producer only
after actual state ownership and local-node registration; that source wiring
does not prove successful readiness. No Ready bypass or proxy fallback exists.
See the [current qualification ledger](tests/qualification/CURRENT-RESULTS.md).

**Storage clarification (2026-10-29):** StatefulSet/PVC checks cover local mounts
and same-node pod recreation only. Distributed data durability, volume node
binding and fenced cross-node handoff are not qualified. See the explicit
[stateful production gate](tests/qualification/STATEFUL-PRODUCTION-GATE.md).
Current separate-kernel VM/network evidence is linked from the
[qualification status](tests/qualification/CURRENT-RESULTS.md); all three guests
still share one physical Mac. Historical row evidence below is not a current
production or complete Kubernetes-conformance claim.

**Storage identity update (2026-10-30, unreleased working tree):** schema4
persists server-owned namespace/PVC/PV UIDs, rotates them on recreation, and
exposes namespace-scoped claim GET/list/watch plus reciprocal UID-bearing
claimRef. Watches reauthorize every two-second snapshot and cannot retarget a
replacement namespace. Claimed PV deletion and unsafe legacy host-path Delete
reclaim/cascade return conflict without deleting data. This refusal is not a
replicated-volume/fencing implementation. Native HTTPS/Raft/CLI evidence and
remaining backend/backup gates are in the stateful production ledger above.

The later lifecycle slice adds the optional `royak/drbd-lvm` metadata contract:
unwritable PendingProvision intents, single-writer/epoch state and strict
receipt/restore boundaries. The physical driver and per-pod mount adapter are
**not yet enabled**. Such claims stay Pending with an explicit reason, reject
user-supplied paths/RWX/adoption, and do not represent working distributed
volumes. The new PV status/annotations are Royak extensions, not a claim of
complete Kubernetes volume-source/CSI semantics. Linux VM metadata tests do
not close the separate replicated-storage/fencing/backup production gate.

A separate Linux-root-only maintenance helper now qualifies constrained fresh
LVM allocation and blank-only removal on the three owned test data disks,
including genuine helper-process interruption/replay without changing the LV
UUID. It never adopts old volumes or grants pod access. The subsequent
journalled closed-Secondary DRBD component passes real three-VM lifecycle and
negative tests, but has no initialized data generation/writer/filesystem. This
optional driver now also requires nftables for an allocation-owned atomic
encrypted-only endpoint guard; real guest route/interface-loss packet probes,
foreign/changed guard refusal and backing-holder refusal pass locally. Node
root is trusted and the default Royak runtime does not install this backend.
This is **not** the Core controller/mount/fencing integration; native claims remain Pending.
See the stateful gate for exact artifact hashes, negative tests and limits.

Current development source also introduces schema5 host-access permits and a
v4 sensitive launch contract. Direct host paths, dangerous added capabilities
and legacy raw-directory StatefulSet templates need separate cluster-scoped
`use hostaccess` approval; old loaded instances need explicit readmission and
retain their old physical path. Actual containers now carry server-created,
namespace-incarnation-bound runtime labels; host-capable Pod access needs the
same separate host permission, including live stream reauthorization. Legacy
owned containers without the contract are stopped/removed without deleting
their host volumes. The bounded real-VM authorization checks pass, but resource
hardening, cross-host log forwarding and mount races remain unqualified. This
is not runtime/production qualification. Native managed PVC/VCT/controller work is still required by the
full storage goal. Upgrade all nodes together; do not mix new state with old binaries.

Every row below was **verified live** against `royak v0.4.0-beta.1` (2026-07-06) — by the CI
suites or by hand with the commands shown. Rows on namespaces, auth/RBAC, durability, multi-node
placement and Raft were re-verified on 2026-10-25 after the auth/persistence/consensus rework
(`test-demo.sh`, `test-multinode.sh`, `test-raft-cluster.sh`, `test-ha-lease.sh`, run against
real Docker). ServiceLB, probe and auth rows were re-verified the same day with
`test-servicelb-probes.sh` and `test-auth-http.sh`. Those re-verified rows describe the current
source, which is **not yet in a published release** (the latest is `v0.4.0-beta.1`). The cluster
suites run three processes on one host against one Docker daemon, so multi-node rows are 🟡, not
"verified across machines". Nothing here is copied from wishes.

Legend: ✅ works · 🟡 partial · ❌ not yet (→ [ROADMAP.md](ROADMAP.md))

## Workloads

| Kubernetes native | Status | Verified behaviour |
|---|---|---|
| Deployment (create/scale/delete) | ✅ | Full lifecycle, CPU/mem limits enforced in Docker |
| Rolling update | ✅ | maxSurge=1, readiness gates, auto-rollback on timeout |
| Rollback | ✅ | Works even after rollout completes |
| DaemonSet | ✅ | One pod per node (`rk-ds-*`); single-node verified live, multi-node in suite |
| Job | ✅ | Runs to completion, `completions` honoured |
| CronJob | ✅ | Cron schedule parsed and ticked by the reconcile loop |
| Init containers | ✅ | Run before main containers, verified live |
| Multi-container pods (sidecars) | ✅ | Verified live via `examples/sidecar.yaml` |
| Bare `Pod` kind | ✅ | Accepted — becomes a single-replica deployment, container verified running |
| ReplicaSet | 🟡 | Accepted with Deployment semantics (replicas + template; no separate RS object or ownership chain) |
| StatefulSet | 🟡 | Ordered startup (one ordinal per tick, lowest-missing first), stable names (`rk-db-1…N`), per-ordinal local volumes from `volumeClaimTemplates`, highest-first scale-down and same-node data reuse verified live. No distributed-volume recovery/fencing, headless-service per-pod DNS subdomains or partitioned rolling updates |

## Configuration & storage

| Kubernetes native | Status | Verified behaviour |
|---|---|---|
| ConfigMap + `envFrom` | ✅ | Injected per-container; hot-reload triggers rolling restart |
| `env[].valueFrom` (`configMapKeyRef` / `secretKeyRef`) | ✅ | Resolved at pod creation on whichever node runs the pod; a missing required key fails the pod create, `optional: true` skips it. Verified on pods placed by other nodes |
| Container `command` + `args` | ✅ | `args` alone become the Docker `Cmd`; `command` maps to `Cmd` too (the image `ENTRYPOINT` is kept — differs from Kubernetes) |
| Secret (encrypted at rest) | ✅ | AES-256-GCM on disk, `envFrom` injection |
| PersistentVolume / PVC / StorageClass | 🟡 | Provision → bind → real local Docker bind-mounts, verified in-container. Not replicated storage; no durable node/attachment identity, enforced cross-node fencing or complete capacity/access-mode semantics |
| `emptyDir` volumes | ✅ | Writable scratch mount, verified live |
| hostPath-style volumes | ✅ | Via PV `hostPath` or container `volumes` |
| ConfigMap/Secret mounted **as volumes** | ✅ | Keys projected as files (secrets 0600) and bind-mounted, verified in-container. Note: `ROYAK_DATA_DIR` (default `~/.royak`) must be a VM-shared path on macOS |
| ResourceQuota | ✅ | Namespace-level pods/cpu/memory/services caps enforced |
| LimitRange | ✅ | Namespace default limits/requests applied to deployments without their own, verified in Docker HostConfig |

Working-tree storage hardening (2026-10-30, native component checks only): PV/PVC
binding compares byte capacity and checks reciprocal namespace ownership before
mount planning. Reapplying a PV preserves Bound/Released state; a bound claim's
size/class/mode and StorageClass provisioning/retention settings are immutable.
Expansion is refused rather than advertised without allocating disk. Dynamic
host-path claim recreation uses a fresh random data path, retaining old Retain
data. This is not a durable attachment/claim UID or replicated-volume guarantee.
Quantities support positive integral bytes and K..E / Ki..Ei suffixes, not the
complete Kubernetes Quantity grammar; multiple/unknown access modes and unknown
provisioners fail closed. Legacy RWO/RWX labels still do not enforce fencing.

`royak apply` rejects the whole offline multi-document input before reconcile or
save if any document fails admission, returning a nonzero status. Offline
`royak backup` exports only an existing unowned non-Raft desired-state file,
never overwrites a destination, and is **not** a volume or running-cluster backup.
The optional replicated-storage/backup engine is still under implementation;
see the [stateful acceptance ledger](tests/qualification/STATEFUL-PRODUCTION-GATE.md).

## Networking

| Kubernetes native | Status | Verified behaviour |
|---|---|---|
| Service (ClusterIP) + DNS | ✅ | Pod→service name resolution via Docker network aliases |
| Service `NodePort` | ✅ | ServiceLB (userspace, klipper-lb-style): pods publish targetPort to ephemeral host ports, Royak listens on nodePort and round-robins. Works on macOS too. Verified live (`test-servicelb-probes.sh`): traffic only to Ready pods (none before Ready; a pod that loses readiness drops out; 1 Ready + 1 NotReady → only the Ready one answers); selector and targetPort changes on the same nodePort reach new connections within seconds without a restart, while open connections keep their backend; delete frees the port; delete + recreate never serves the old route; same-named Services in two namespaces keep their own backends; a nodePort another Service holds is rejected at apply. When a Service starts targeting a port a running pod does not publish, that pod is replaced by a readiness-gated rollout first (Docker binds ports only at create). Limit: forwards to this node's pods only |
| Service `LoadBalancer` | ✅ | ServiceLB binds the service port on the node (single-node external IP = the node); same readiness gating as NodePort, verified live |
| Ingress (live reverse proxy) | 🟡 | Async, TLS, Host+path routing; buffered HTTP response decoding, including chunked bodies. 32 MiB response limit; trailers are consumed, not forwarded. Long-lived SSE, WebSocket proxying and complete HTTP protocol semantics are not qualified. See the current qualification report for local runtime evidence |
| NetworkPolicy | ✅ | Real L4 enforcement: `egress` port allow-lists, `denyAll`, and `internal` apply iptables DROP rules inside each pod's netns (NET_ADMIN helper). Verified live: denied port dropped, allowed port + DNS reachable. Enforcement applies ~10-15s after the pod starts (the iptables helper image/apk load), so there is a brief window before rules take effect — noted for beta. `ingress` allow works by namespace-network membership. Requires a host kernel that can init iptables inside a nested container netns (native Linux + Colima do; some hosted CI runners, e.g. GitHub-hosted, do not — enforcement degrades to membership-based audit there) |
| IngressClass | ✅ | `IngressClass` kind accepted; `ingressClassName` read, stored and round-tripped. Single built-in controller serves every Ingress (a foreign class is noted, not silently dropped). Verified live |
| Cross-node pod→service traffic | ✅ | Mesh proxy (TCP), **AES-256-GCM encrypted** on the node→node hop (per-frame random nonce, key from cluster secret). Mesh 8/8 + encrypted-mesh 8/8 verified live — on Linux and, via `test-mesh-macos.sh`, inside a container on macOS. Frame codec also unit-tested |
| Cross-node pod-to-pod IP traffic | 🟡 | Service traffic is encrypted (above). Raw pod-IP peering across hosts still relies on the proxy, not a routed encrypted L3 (WireGuard) — that L3 story is v0.5 |

## Policy & auth

| Kubernetes native | Status | Verified behaviour |
|---|---|---|
| Namespaces | ✅ | Every object is identified by namespace + name: the same name coexists in two namespaces, and scale/PATCH/delete in one never touch the other (verified with real traffic, across restart). A body namespace that differs from the URL's is rejected (400). Pods get per-namespace Docker networks |
| Container / pod `securityContext` | 🟡 | Docker subset: pod UID/GID/non-root defaults with per-container overrides; container read-only root filesystem, no-new-privileges, capability add/drop, and `privileged: false`. Unknown fields and privileged mode are refused. Persisted and transported to remote Docker placements; NeuroPod refuses this contract. See the security/upgrade contract for migration and version-skew limits |
| Authentication | ✅ | Bearer tokens only (`ROYAK_TOKEN`, a `ROYAK_TOKEN_FILE` table of token/user/groups, or a generated `~/.royak/admin.token`). Anonymous calls get 401; `x-royak-role` grants nothing. Health endpoints and the opt-in demo sandbox stay public. `ROYAK_AUTH=insecure-dev` disables auth explicitly (with a warning). Tokens are never logged. No client-certificate or OIDC auth |
| RBAC enforcement | ✅ | Deny-by-default, one central check for reads, list/watch, writes, scale, PATCH, delete, exec, logs and port-forward requests. Native `Role`/`ClusterRole`/`RoleBinding`/`ClusterRoleBinding` (users and groups) + built-in `view`/`edit`/`admin`/`cluster-admin`, plus Royak `RbacRole`. Verified via HTTP and kubectl: viewer reads 200 / writes 403; a namespace-bound deployer writes only in its namespace; multi-document bodies are authorized per document |
| Node-to-node authentication | ✅ | Every inter-node request **and** response is HMAC-SHA256-signed with the shared `ROYAK_CLUSTER_SECRET` (method, path, timestamp ±30 s, nonce with replay cache, node name, body hash). Unsigned, forged, stale, replayed or re-targeted requests get 401; an admin bearer token is not a node identity. Request and response bodies are AES-256-GCM-sealed with a key derived from the same secret (unsealed bodies are refused). Peer mesh connections must be sealed |
| ServiceAccount | 🟡 | Accepted as a manifest and usable as an RBAC subject via RoleBinding; no auto-mounted tokens (Royak pods get their own CA-signed identity cert + token injected as env, though these identities are not yet verified on the live path) |
| Admission webhooks (validating) | ✅ | `ValidatingWebhookConfiguration` with `clientConfig.url` — Royak POSTs an AdmissionReview and honours allow/deny + failurePolicy. Verified live (allowed 201 / denied 403). No CA-bundle/mutating webhooks yet |

## kubectl

Tested with kubectl **v1.36** (v1.33 in the integration-suite sandbox) against `royak watch --tls` with a bearer token —
kubectl does not send a token over plain HTTP:

| Command | Status | Notes |
|---|---|---|
| `kubectl get` (pods, deployments, namespaces, configmaps…) | ✅ | K8s table format |
| `kubectl describe` | ✅ | |
| `kubectl delete` | ✅ | |
| `kubectl get -w` (watch) | ✅ | Streaming verified |
| `kubectl apply` — **create** | ✅ | Native, no `--validate=false` |
| `kubectl apply --server-side` — **update existing** | ✅ | Full object PATCH lands on the apply path; verified live (replicas change persisted write-through) |
| `kubectl apply` (client-side) — update existing | ✅ | Full strategic-merge path: rich field schemas served, last-applied annotation stored and surfaced, partial patches merged server-side. `created` → `configured` verified live |
| `kubectl scale` | ✅ | `/scale` subresource GET+PATCH; persisted before the ack |
| `kubectl logs` | ✅ | Log subresource served from Docker logs |
| `kubectl get events` | 🟡 | Events (pod created, rollout, probe failures, back-off…) with RFC 3339 timestamps. Kept in the memory of the server that observed them — not persisted or replicated, gone after a restart. No server-side table, so the default view shows only NAME/AGE; use `-o custom-columns=…` or `-o json` |
| `kubectl exec` (non-interactive) | ✅ | WebSocket channel protocol (v4/v5): stdout, stderr and exit status verified live with kubectl v1.36 |
| `kubectl exec -i` / `-it` (interactive + TTY) | ✅ | Full duplex WebSocket bridge: stdin, TTY (verified `/dev/pts/0`), window resize. Verified live with kubectl v1.36 |
| `kubectl port-forward` | 🟡 | kubectl 1.36 tunnels SPDY-over-WebSocket, which we don't decode; the clean `channel.k8s.io` WS path is served. Guaranteed path: **`royak port-forward <pod> <local>:<remote>`**, verified live (HTTP 200 through the tunnel). macOS reaches the pod via its published host port |
| k9s | ✅ | Browsing, logs, and interactive exec work; port-forward inherits the kubectl SPDY caveat |

## Operations

| Kubernetes native | Status | Verified behaviour |
|---|---|---|
| Liveness/readiness probes | 🟡 | Docker `httpGet` (plain HTTP), `tcpSocket` and `exec`. Monotonic initial delay/period, consecutive failure/success thresholds, actual container-incarnation reset, aggregate sidecar readiness and container-local liveness restart have real API/Docker regressions. New manifest timeout defaults to 1s; legacy stored probes without it retain 3s. Exec timeout kills its isolated process group; missing required tools fail closed. Unknown handler fields, HTTPS/custom host, named ports and gRPC are refused. Periods are minimum spacing in a synchronous reconcile loop, not real-time deadlines; TCP dials the pod IP from inside its namespace. Supported workload/runtime and upgrade boundaries: [probe/topology contract](tests/qualification/PROBE-TOPOLOGY-CONTRACT.md), current qualification status: [results](tests/qualification/CURRENT-RESULTS.md) |
| Startup probes | 🟡 | Gate both readiness and liveness; their initial delays start after startup succeeds. Failure-threshold restart and timer/counter reset have actual-container regression coverage. Same supported Docker subset and synchronous-loop limits as above; ordinary init-container and NeuroPod probes are refused |
| CrashLoopBackOff | ✅ | Stops after 5 rapid failures, resets when healthy |
| HPA | ✅ | Scales on real Docker CPU stats |
| Graceful shutdown | ✅ | SIGTERM/SIGINT stop the server within ~0.1 s (state is already durable); containers preserved |
| API write durability | ✅ | One commit path for apply, PATCH, scale, delete and reconcile changes: atomic write + fsync **before** the ack; a failed write is an error (503 "change NOT applied"), never a silent success. Verified with SIGKILL right after the ack. Corrupt or unreadable state stops the server instead of starting an empty cluster. Current unreleased schema is 4; migration preserves the source-version backup (`.v1.bak` / `.v2.bak` / `.v3.bak`). Read the [upgrade contract](tests/qualification/SECURITY-HTTP-CONTRACT.md); mixed-version operation/downgrade is not qualified |
| Single writer per state file | ✅ | An exclusive lock held for the process life: a second server on the same file is a read-only standby (writes get 421, not applied) and takes over the moment the owner dies; offline CLI writes are refused while a server owns the state |
| HA control plane (Raft) | 🟡 | openraft **is the live write path** in cluster mode (`--node-id`/`--peers`/`--bootstrap`): every desired-state change commits on a quorum before it is acknowledged; durable log and vote; snapshots with install on lagging nodes and restore from disk. Only a quorum-confirmed leader schedules. Verified through the public API (`test-raft-cluster.sh`): leader SIGKILL → new leader, writes and scale continue, restarted node catches up; a minority node answers 504 "outcome unknown" and schedules nothing; after heal all nodes agree and a retry succeeds; delete propagates (404 on every node); 200 writes while a follower is down → snapshot install → restart restores from disk. 🟡 because it is verified with three processes on **one host**, not across machines |
| Multi-node placement + self-healing | 🟡 | One scheduler (the confirmed leader) places pods on any Ready node through signed RPC; the full workload contract travels (command/args, env + key refs, limits, ports, probes, namespace). Remote nodes refuse host-local volumes (409) and unavailable images (503). Killed pods and lost nodes are replaced without over-provisioning. Same one-host caveat; host-local volumes are not replicated |
| Prometheus `/metrics` | ✅ | |
| Dashboard | ✅ | Built-in read-only live topology with per-resource RBAC, namespace scope, search/kind/state filters, map/list, fit/zoom, keyboard-preserved detail connections and mobile list. Desired links differ from observed placement; no secret/config values or invented traffic edges. Tokens stay in memory; unavailable/unauthorized/stale states are labelled. See the current local UI/runtime [acceptance report](tests/qualification/BETA-RESULTS-2026-10-27.md); no mutation or VPN/tunnel controls |
| Traffic observability | ✅ | Flow tap on ServiceLB/ingress/mesh: source→service, bytes ↑↓, duration, top-talkers. `royak flows` / `GET /royak/v1/flows`. Metadata only (no payload capture). Verified live |
| Port-forward (native CLI) | ✅ | `royak port-forward pod 8080:80` — local→pod TCP tunnel, verified live |
| Operators + CustomResources | ✅ | Auto-provision + lifecycle hooks (Royak's own shape, not full CRD API) |

## Beyond Kubernetes (Royak-specific)

Pipelines (CI/CD DAGs), Functions (invoke), Guards (declarative auto-remediation), neural anomaly
detection, MCP server for AI assistants, NeuroPod experimental Docker-free runtime.

**Build from source (PaaS).** A pipeline stage with `action: build` turns a git context (a
registered repository or a path) into an image via the Docker Engine `/build` API, which a later
`action: apply` stage deploys — so `git push → webhook → build → deploy → live app` works end to
end, no external CI or registry required. Dockerfile + build-args (`args:` on the stage → Docker
`buildargs`) today; Nixpacks-style auto-detection (no Dockerfile) is not yet implemented. Runtime
env/config/secrets for the deployed app use ordinary `env`/`envFrom` (ConfigMap/Secret). Verified
live by `test-build.sh`: the deployed container serves a marker written **from a build-arg**,
proving the build ran, the arg flowed through, and the built image is the one deployed.

---

Found a row that doesn't match reality? That's a bug in this document — please open an issue.
