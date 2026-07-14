# Royak ↔ Kubernetes: the honest compatibility ledger

Every row below was **verified live** against `royak v0.4.0-beta.1` (2026-07-06) — by the CI
suites (85 unit + 72 integration + multi-node + HA + mesh + ingress + load) or by hand with the
commands shown. Nothing here is copied from wishes.

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
| StatefulSet | ✅ | Ordered startup (one ordinal per tick, lowest-missing first), stable names (`rk-db-1…N`), per-ordinal volumes from `volumeClaimTemplates`, highest-first scale-down, data survives pod recreation — all verified live. Limits: no headless-service per-pod DNS subdomains, no partitioned rolling updates |

## Configuration & storage

| Kubernetes native | Status | Verified behaviour |
|---|---|---|
| ConfigMap + `envFrom` | ✅ | Injected per-container; hot-reload triggers rolling restart |
| Secret (encrypted at rest) | ✅ | AES-256-GCM on disk, `envFrom` injection |
| PersistentVolume / PVC / StorageClass | ✅ | Provision → bind → real Docker bind-mounts, verified in-container |
| `emptyDir` volumes | ✅ | Writable scratch mount, verified live |
| hostPath-style volumes | ✅ | Via PV `hostPath` or container `volumes` |
| ConfigMap/Secret mounted **as volumes** | ✅ | Keys projected as files (secrets 0600) and bind-mounted, verified in-container. Note: `ROYAK_DATA_DIR` (default `~/.royak`) must be a VM-shared path on macOS |
| ResourceQuota | ✅ | Namespace-level pods/cpu/memory/services caps enforced |
| LimitRange | ✅ | Namespace default limits/requests applied to deployments without their own, verified in Docker HostConfig |

## Networking

| Kubernetes native | Status | Verified behaviour |
|---|---|---|
| Service (ClusterIP) + DNS | ✅ | Pod→service name resolution via Docker network aliases |
| Service `NodePort` | ✅ | ServiceLB (userspace, klipper-lb-style): pods publish targetPort to ephemeral host ports, Royak listens on nodePort and round-robins. Works on macOS too. Limit: pods created *before* the NodePort service need a re-apply/scale to publish the port |
| Service `LoadBalancer` | ✅ | ServiceLB binds the service port on the node (single-node external IP = the node), verified live |
| Ingress (live reverse proxy) | ✅ | Async, streaming, TLS, Host+path routing. 15/15 verified live — on Linux and, via `test-mesh-macos.sh`, inside a container on macOS |
| NetworkPolicy | ✅ | Real L4 enforcement: `egress` port allow-lists, `denyAll`, and `internal` apply iptables DROP rules inside each pod's netns (NET_ADMIN helper). Verified live: denied port dropped, allowed port + DNS reachable. Enforcement applies ~10-15s after the pod starts (the iptables helper image/apk load), so there is a brief window before rules take effect — noted for beta. `ingress` allow works by namespace-network membership. Requires a host kernel that can init iptables inside a nested container netns (native Linux + Colima do; some hosted CI runners, e.g. GitHub-hosted, do not — enforcement degrades to membership-based audit there) |
| IngressClass | ✅ | `IngressClass` kind accepted; `ingressClassName` read, stored and round-tripped. Single built-in controller serves every Ingress (a foreign class is noted, not silently dropped). Verified live |
| Cross-node pod→service traffic | ✅ | Mesh proxy (TCP), **AES-256-GCM encrypted** on the node→node hop (per-frame random nonce, key from cluster secret). Mesh 8/8 + encrypted-mesh 8/8 verified live — on Linux and, via `test-mesh-macos.sh`, inside a container on macOS. Frame codec also unit-tested |
| Cross-node pod-to-pod IP traffic | 🟡 | Service traffic is encrypted (above). Raw pod-IP peering across hosts still relies on the proxy, not a routed encrypted L3 (WireGuard) — that L3 story is v0.5 |

## Policy & auth

| Kubernetes native | Status | Verified behaviour |
|---|---|---|
| Namespaces | ✅ | Isolation via per-namespace Docker networks |
| RBAC enforcement | 🟡 | Native `Role`/`ClusterRole`/`RoleBinding` accepted; the verb+resource+namespace check runs on API writes (subject GET 200 / POST 403 verified), plus Royak's own `RbacRole`. But the caller's role is **self-asserted** via the `x-royak-role` header (defaults to `admin`) and is **open-by-default** — it authorizes a stated role, it does not authenticate the caller |
| ServiceAccount | 🟡 | Accepted as a manifest and usable as an RBAC subject via RoleBinding; no auto-mounted tokens (Royak pods get their own CA-signed identity cert + token injected as env, though these identities are not yet verified on the live path) |
| Admission webhooks (validating) | ✅ | `ValidatingWebhookConfiguration` with `clientConfig.url` — Royak POSTs an AdmissionReview and honours allow/deny + failurePolicy. Verified live (allowed 201 / denied 403). No CA-bundle/mutating webhooks yet |

## kubectl

Tested with kubectl **v1.36** against `royak api`:

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
| `kubectl get events` | ✅ | Cluster events listed (timestamps are coarse) |
| `kubectl exec` (non-interactive) | ✅ | WebSocket channel protocol (v4/v5): stdout, stderr and exit status verified live with kubectl v1.36 |
| `kubectl exec -i` / `-it` (interactive + TTY) | ✅ | Full duplex WebSocket bridge: stdin, TTY (verified `/dev/pts/0`), window resize. Verified live with kubectl v1.36 |
| `kubectl port-forward` | 🟡 | kubectl 1.36 tunnels SPDY-over-WebSocket, which we don't decode; the clean `channel.k8s.io` WS path is served. Guaranteed path: **`royak port-forward <pod> <local>:<remote>`**, verified live (HTTP 200 through the tunnel). macOS reaches the pod via its published host port |
| k9s | ✅ | Browsing, logs, and interactive exec work; port-forward inherits the kubectl SPDY caveat |

## Operations

| Kubernetes native | Status | Verified behaviour |
|---|---|---|
| Liveness/readiness probes → restart | ✅ | HTTP + exec probes; failure → restart verified |
| Startup probes | ✅ | Gate liveness until the pod reports started (K8s semantics), verified live |
| CrashLoopBackOff | ✅ | Stops after 5 rapid failures, resets when healthy |
| HPA | ✅ | Scales on real Docker CPU stats |
| Graceful shutdown | ✅ | SIGTERM saves state atomically, containers preserved |
| API write durability | ✅ | Mutations persisted to disk **before** the 201 ack (write-through); verified with kill -9 immediately after ack |
| HA control plane (Raft) | 🟡 | openraft is integrated and exercised: real 3-node consensus over HTTP — election, replication through the leader, and leader failover verified live (`test-raft-cluster.sh`). In-process chaos test proves the invariant: partition to a minority → no quorum → writes do NOT commit; heal → commit resumes; no committed op lost across a leader kill. Enable with `--node-id`/`--peers`/`--bootstrap`. **Not yet the live write path:** normal `apply`/`scale`/reconcile writes still go through the single-writer file lease — only the dedicated `/royak/v1/raft/scale` endpoint currently proposes a command through consensus. Routing the reconcile write path through Raft is the v0.4 milestone |
| Prometheus `/metrics` | ✅ | |
| Dashboard | ✅ | Built-in web UI |
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
