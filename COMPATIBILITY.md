# Royak ↔ Kubernetes: the honest compatibility ledger

Every row below was **verified live** against `royak v0.4.0-beta.1` (2026-07-06) — by the CI
suites or by hand with the commands shown. Rows on namespaces, auth/RBAC, durability, multi-node
placement and Raft were re-verified on 2026-10-25 after the auth/persistence/consensus rework
(`test-demo.sh`, `test-multinode.sh`, `test-raft-cluster.sh`, `test-ha-lease.sh`, run against
real Docker). Nothing here is copied from wishes.

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
| `env[].valueFrom` (`configMapKeyRef` / `secretKeyRef`) | ✅ | Resolved at pod creation on whichever node runs the pod; a missing required key fails the pod create, `optional: true` skips it. Verified on pods placed by other nodes |
| Container `command` + `args` | ✅ | `args` alone become the Docker `Cmd`; `command` maps to `Cmd` too (the image `ENTRYPOINT` is kept — differs from Kubernetes) |
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
| Namespaces | ✅ | Every object is identified by namespace + name: the same name coexists in two namespaces, and scale/PATCH/delete in one never touch the other (verified with real traffic, across restart). A body namespace that differs from the URL's is rejected (400). Pods get per-namespace Docker networks |
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
| Liveness/readiness probes → restart | ✅ | HTTP + exec probes; failure → restart verified |
| Startup probes | ✅ | Gate liveness until the pod reports started (K8s semantics), verified live |
| CrashLoopBackOff | ✅ | Stops after 5 rapid failures, resets when healthy |
| HPA | ✅ | Scales on real Docker CPU stats |
| Graceful shutdown | ✅ | SIGTERM/SIGINT stop the server within ~0.1 s (state is already durable); containers preserved |
| API write durability | ✅ | One commit path for apply, PATCH, scale, delete and reconcile changes: atomic write + fsync **before** the ack; a failed write is an error (503 "change NOT applied"), never a silent success. Verified with SIGKILL right after the ack. Corrupt or unreadable state stops the server instead of starting an empty cluster; old state files are migrated with a `.v1.bak` backup |
| Single writer per state file | ✅ | An exclusive lock held for the process life: a second server on the same file is a read-only standby (writes get 421, not applied) and takes over the moment the owner dies; offline CLI writes are refused while a server owns the state |
| HA control plane (Raft) | 🟡 | openraft **is the live write path** in cluster mode (`--node-id`/`--peers`/`--bootstrap`): every desired-state change commits on a quorum before it is acknowledged; durable log and vote; snapshots with install on lagging nodes and restore from disk. Only a quorum-confirmed leader schedules. Verified through the public API (`test-raft-cluster.sh`): leader SIGKILL → new leader, writes and scale continue, restarted node catches up; a minority node answers 504 "outcome unknown" and schedules nothing; after heal all nodes agree and a retry succeeds; delete propagates (404 on every node); 200 writes while a follower is down → snapshot install → restart restores from disk. 🟡 because it is verified with three processes on **one host**, not across machines |
| Multi-node placement + self-healing | 🟡 | One scheduler (the confirmed leader) places pods on any Ready node through signed RPC; the full workload contract travels (command/args, env + key refs, limits, ports, probes, namespace). Remote nodes refuse host-local volumes (409) and unavailable images (503). Killed pods and lost nodes are replaced without over-provisioning. Same one-host caveat; host-local volumes are not replicated |
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
