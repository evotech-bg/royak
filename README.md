# Royak

**A swarm of containers. One tiny binary.**

> **⚠️ BETA — use at your own risk.** Royak is in public beta. It is great for learning, demos,
> homelabs and edge boxes. It is **not** ready to carry your production. We test every feature in
> CI (unit + integration + multi-node + chaos suites), but our testing is not a substitute for
> yours: **evaluate Royak against your own workloads before relying on it.** The software is
> provided as-is, without warranty of any kind (see [LICENSE](LICENSE)). Every known gap is listed
> in [Limitations](#limitations) and scheduled in [ROADMAP.md](ROADMAP.md) — nothing is swept under a rug.

Royak (*рояк* — Bulgarian for "swarm") manages Docker containers the way Kubernetes does —
deployments, scaling, rolling updates, RBAC, services — in a single Rust binary (~8.9 MB)
instead of a control plane you have to babysit.

🌐 **Website:** https://evotech-bg.github.io/royak/
📋 **What works vs. Kubernetes, tested:** [COMPATIBILITY.md](COMPATIBILITY.md)

## Getting Started

**Platforms:** Linux (x86_64, aarch64) and macOS (Apple silicon, Intel). Windows is not supported —
Royak talks to Docker over a Unix socket.

**Prerequisites:** Docker running (Docker Desktop, Colima or OrbStack — `DOCKER_HOST` is honoured).

**Option A — download a pre-built beta binary** from [Releases](https://github.com/evotech-bg/royak/releases),
`tar -xzf`, done. The latest published release is `v0.4.0-beta.1`; features described here that
landed after it (Raft on the write path, auth/RBAC rework, readiness-aware ServiceLB, tcpSocket
probes) are only in the source until the next release.

**Option B — build from source** (Rust toolchain required):

```bash
# Build
git clone https://github.com/evotech-bg/royak.git
cd royak
cargo build --release

# Deploy nginx with 2 replicas
./target/release/royak apply examples/nginx.yaml

# See your pods (queries Docker for real state)
./target/release/royak get pods

# See deployments with READY count
./target/release/royak get deployments

# Scale to 5 replicas
./target/release/royak scale web 5

# Export deployment as YAML (K8s workflow: get → edit → apply)
./target/release/royak get deployment/web -o yaml

# Delete
./target/release/royak delete deployment/web
```

Total time: under 2 minutes.

## Examples

```
examples/
  nginx.yaml              # simple deploy (2 replicas)
  nginx-with-limits.yaml  # deploy + service + configmap + resource limits
  rolling-update.yaml     # deploy → change image → rollback
  rbac-roles.yaml         # admin, viewer, deployer roles
  redis-operator.yaml     # operator + custom resource (auto-provision)
  guard.yaml              # auto-remediation (crash → restart, high CPU → scale)
```

Each file has comments explaining what it does and how to use it.

## What it does

```bash
# Deploy with resource limits (CPU/memory enforced in Docker)
royak apply examples/nginx-with-limits.yaml

# Rolling update (change image, re-apply)
royak apply deployment-v2.yaml
# → [rollout] web: nginx:alpine → nginx:latest (1/3 done)
# → [rollout] web: COMPLETE

# Rollback (works even after rollout completes)
royak rollback web

# Pipe from stdin (works with Helm)
helm template ./chart | royak apply -

# Export any resource as YAML or JSON
royak get deployment/web -o yaml
royak get service/web-svc -o json

# kubectl-compatible API server over TLS (with background reconcile loop).
# Every API call needs a bearer token: ROYAK_TOKEN / ROYAK_TOKEN_FILE, or the
# admin token generated at ~/.royak/admin.token. The kubeconfig carries it.
royak watch --tls
KUBECONFIG=~/.kube/royak.yaml kubectl get pods
```

## Features

| Feature | What it does |
|---------|-------------|
| **Deployments** | Create, scale, delete. Resource limits (CPU/memory) enforced in Docker |
| **StatefulSets** | Ordered startup, stable pod identity and per-ordinal local volumes (`volumeClaimTemplates`); same-node pod recreation tested, not cross-node data recovery |
| **Rolling Updates** | Readiness-gated replacement, maxSurge=1 and auto-rollback on timeout; the local fault tests do not establish a blanket zero-downtime SLO |
| **Rollback** | Reverse rolling update — works even after rollout completes |
| **Services** | `kind: Service` with selector + ports. ClusterIP with pod→svc DNS; NodePort and LoadBalancer served by the built-in ServiceLB (userspace LB, works on macOS too): it forwards only to Ready pods, and Service changes (selector, targetPort, delete/recreate) reach the running listener without a restart |
| **Health probes** | Supported Docker `httpGet`/`tcpSocket`/`exec` handlers with monotonic initial delays/periods, consecutive thresholds, startup gate, incarnation reset and process-group exec timeout cleanup; one readiness model for API/ingress/ServiceLB. See the strict [supported subset](tests/qualification/PROBE-TOPOLOGY-CONTRACT.md) |
| **Read-only cluster map** | Actual resources, ownership/placement and declared routing/dependencies, with per-resource RBAC, namespace/search/state filters, map/list, fit/zoom and keyboard-preserved detail; no secret values, invented traffic or mutation/tunnel controls |
| **ConfigMaps/Secrets** | `envFrom` env injection AND file projection as volumes (secrets 0600) |
| **Auth + RBAC** | Identity only from a verified bearer token (`ROYAK_TOKEN`, a `ROYAK_TOKEN_FILE` table, or a generated admin token); no anonymous access, no role headers. Native `Role`/`ClusterRole`/`RoleBinding`/`ClusterRoleBinding` (+ built-in `view`/`edit`/`admin`) and Royak `RbacRole`, deny-by-default, checked centrally on every read, write, scale, PATCH, exec, logs, watch and port-forward. `ROYAK_AUTH=insecure-dev` is the explicit opt-out |
| **Admission webhooks** | `ValidatingWebhookConfiguration` — Royak calls your webhook URL and honours allow/deny |
| **Operators** | `kind: Operator` + `kind: CustomResource` — auto-provision, lifecycle hooks |
| **Guards** | Auto-remediation: pod_crash → restart, high_memory → scale_up |
| **CrashLoopBackOff** | Stops recreating after 5 rapid failures. Resets when healthy |
| **YAML Export** | `get deployment/web -o yaml` — full round-trip: get → edit → apply |
| **kubectl API** | `get`/`describe`/`delete`/`watch`/`logs`/`scale`/`exec` (incl. `-it` TTY)/`get events` + `apply` incl. client-side updates |
| **Stdin Pipe** | `cat file.yaml \| royak apply -` or `helm template \| royak apply -` |
| **HPA** | Auto-scaling based on real Docker CPU stats |
| **Pipelines** | CI/CD with DAG dependencies, git triggers, matrix builds, and `action: build` (git source → image → deploy, PaaS-style — no external CI/registry) |
| **Ingress** | Live reverse proxy — async, streaming, binary-safe, TLS, path-based routing |
| **Multi-node** | `--node-id`/`--peers`: one cluster over HMAC-signed node RPC (signed requests *and* responses, replay-protected, TLS with `--tls`); pods placed on any node carry the full workload contract (command/args, env incl. configMap/secret refs, limits, ports, probes, namespace) |
| **Raft HA** | Every desired-state write (apply, PATCH, scale, delete, reconcile changes) commits through openraft with a quorum before it is acknowledged; durable log + vote, snapshots. Minority side answers 504 "outcome unknown" and stops scheduling |
| **Durable state** | Single node: atomic fsync'd writes before any change is acknowledged; corrupt state refuses to start instead of becoming an empty cluster; an exclusive owner lock makes a second process a read-only standby |
| **Encryption** | AES-256-GCM for secrets at rest and for mesh traffic between nodes |
| **MCP Server** | 13 tools for AI assistant integration (deploy, scale, exec, top...) |

## Deploy from source (PaaS)

Royak doesn't just deploy existing images — a pipeline `build` stage turns a git
repo with a Dockerfile into an image and deploys it, so `git push` becomes a live
app. No external CI, no registry. It's a Heroku/Coolify-style flow inside the one
binary.

```yaml
# ship.yaml — apply once
apiVersion: royak/v1
kind: Repository
metadata: { name: myapp }
spec:
  url: https://github.com/you/myapp    # or path: ./myapp for a local checkout
  branch: main
  pipeline: ship                        # auto-triggered on new commits
---
apiVersion: royak/v1
kind: Pipeline
metadata: { name: ship }
spec:
  stages:
    - name: build
      action: build
      context: myapp                    # the repo above (or a path)
      dockerfile: Dockerfile            # optional (default: Dockerfile)
      tag: royak-myapp:v1
      args:                             # optional build-time ARGs
        - { name: NODE_ENV, value: production }
    - name: deploy
      action: apply
      file: app.yaml                    # the manifests below
      dependsOn: build
```

**How the deploy is triggered — three ways:**

| Trigger | How | When |
| --- | --- | --- |
| Webhook | `POST /hooks/repo/myapp` with `Authorization: Bearer <token>` | instant build + deploy from CI or a relay. GitHub/GitLab cannot add a bearer header and their signed webhooks (`X-Hub-Signature-256`) are not verified yet — use git-watch for push-to-deploy |
| Git-watch | the reconcile loop polls the repo each `--interval` tick (`git ls-remote` / `git rev-parse`) | a new commit auto-triggers the linked pipeline |
| Manual | `royak pipeline run ship` | force a run |

**Runtime env, config and secrets** for the deployed app are ordinary Kubernetes
manifests that the `deploy` stage applies — `env`, `envFrom` from a ConfigMap or
Secret (secrets are AES-256-GCM encrypted at rest):

```yaml
# app.yaml
apiVersion: v1
kind: Secret
metadata: { name: app-secrets }
stringData:
  DATABASE_URL: postgres://user:pass@db:5432/app
---
apiVersion: v1
kind: ConfigMap
metadata: { name: app-config }
data:
  LOG_LEVEL: info
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: web }
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: web
          image: royak-myapp:v1        # ← the tag the build stage produced
          env:
            - { name: PORT, value: "8080" }
          envFrom:
            - secretRef: { name: app-secrets }
            - configMapRef: { name: app-config }
```

`git push` → webhook → **build** (clone + `docker build`, with your build-args) →
**deploy** (apply the manifests, env and secrets injected) → live app.

> Build inputs today are Dockerfile + build-args. Nixpacks-style auto-detection
> (no Dockerfile) and a one-click service catalog are not yet implemented.

## Architecture

```
src/main.rs          ~2,600 lines   CLI, state persistence, YAML export
src/reconcile.rs     ~4,700 lines   Reconcile loop, operators, strategies
src/api.rs           ~2,400 lines   kubectl REST API, RBAC, describe/exec/top
src/brain.rs         ~1,300 lines   Anomaly detection (z-score), prediction (linreg)
src/runtime.rs       ~1,000 lines   Docker, Light (OCI), CRI runtimes
src/raft_node.rs       ~770 lines   openraft integration (storage, transports)
src/net_security.rs    ~540 lines   Cluster CA, mTLS, pod identity, ACME
src/docker.rs          ~540 lines   Docker Unix socket client
src/spec.rs            ~520 lines   YAML parser (22+ resource types)
src/cluster_mesh.rs    ~480 lines   Cross-node service mesh proxy
src/neural_state.rs    ~400 lines   Binary state persistence
src/microvm.rs         ~310 lines   Apple Virtualization.framework MicroVM
src/consensus.rs       ~240 lines   Command log + ConsensusBackend trait
mcp/royak.py           ~310 lines   MCP server
```

Binary (release build, measured 2026-10-25 on this source): **8,877,376 bytes (8.5 MiB)** on
macOS arm64 (rustc 1.94); **9,246,360 bytes (8.8 MiB)** static musl on Linux aarch64 (rustc 1.90).

## How it works

Every 5 seconds, the reconcile loop:
1. Reads desired state (from YAML specs stored in memory)
2. Reads actual state (from Docker API)
3. Diffs them
4. Takes action (create, start, stop, remove containers)

This is what Kubernetes does with etcd, kubelet, kube-proxy, and a control plane.

## Test suite

```bash
cargo test --bin royak      # unit tests
./test-demo.sh              # single-node integration tests (needs Docker)
./test-multinode.sh         # 3 local nodes: signed census, remote workload contract, self-healing, node loss
./test-raft-cluster.sh      # 3 local nodes: failover, catch-up, minority partition, delete propagation, snapshots
./test-ha-lease.sh          # single writer: state owner lock, read-only standby, takeover
./test-servicelb-probes.sh  # ServiceLB readiness gating, live Service changes, tcpSocket/httpGet/exec probes
./test-auth-http.sh         # auth through the real API: malformed paths, trigger shadowing, exec RBAC, kubectl
./test-mesh.sh              # cross-node mesh proxy tests (Linux only, see note)
./test-ingress.sh           # ingress live proxy tests (Linux only, see note)
./test-load.sh              # load + chaos (10 deploys × 2 replicas, pod-kill respawn)
./test-neuropod.sh          # NeuroPod smoke tests (EXPERIMENTAL)
```

> **Note:** the cluster suites run three processes on one host against one Docker daemon, so a
> "remote" pod is one created by another node's process, not on another machine.
>
> **Note:** the mesh and ingress suites forward traffic to container IPs, which are host-routable
> only on **Linux**. On macOS run `./test-mesh-macos.sh` — it builds a Linux binary and runs the
> suites inside a container where IPs are routable (verified: mesh 8/8, ingress 15/15, encrypted
> mesh 8/8). The old note (host can't reach container IPs on macOS Docker
> Desktop/Colima/OrbStack run containers inside a VM) those two suites fail with connect timeouts.
> CI runs them on Ubuntu.

Unit tests cover: YAML parser edges, neural brain (identity, encrypt/decrypt, training convergence,
anomaly detection, weight persistence), neural state KV + save/load + corruption paths, pod-token
HMAC verify, AES-256-GCM secret encryption, schema-version migration, atomic state writes, OpenAPI
v3 spec generation, token auth + RBAC decisions, node request/response signing, state owner lock,
Raft state machine (single-node apply, 3-node election + replication over in-process and HTTP
transports), probe validation and storage, ServiceLB routing (readiness filter, live route swap
without rebinding or cutting open connections, port conflicts), publish-aware rollout.

For the current source's real local fault/regression evidence, read
[qualification results](tests/qualification/CURRENT-RESULTS.md). Use the
[isolated suite driver](tests/qualification/README.md) for broad shell suites;
their cleanup must not run against a host containing valuable workloads.
The [security/HTTP contract](tests/qualification/SECURITY-HTTP-CONTRACT.md)
defines the Docker securityContext subset, **schema-3 state upgrade boundary**
and buffered ingress limits. Update all nodes before using constrained
workloads; mixed-version upgrades are not qualified. Reapply previously ignored
security contexts and inspect replacement containers rather than assuming
migration retroactively enforces them.

Integration tests cover: deploy, service + DNS (pod→svc hostname), RBAC enforcement (403), scale
up/down, logs, rolling update, rollback, stdin pipe, delete, state persistence, namespace, Secrets
(AES-256 at rest), ConfigMap, HPA, NetworkPolicy, ResourceQuota, Canary, Pipeline,
Operator+CustomResource, Functions (invoke), Job, Ingress, Guard, Brain, Dashboard + /metrics,
kubectl compatibility (get/apply/delete), graceful shutdown, CrashLoopBackOff, health-probe restart.

## Limitations

**Beta means beta.** Royak is an MVP of a vision — for learning, demos, edge/homelab and small
deployments. Here is the honest ledger:

- **Probes remain a Docker subset.** `periodSeconds`, `initialDelaySeconds` and consecutive
  thresholds are honoured, but execution occurs within synchronous reconcile ticks (default 5 s);
  tick/load delays are possible, not a real-time deadline guarantee. `httpGet`
  and `tcpSocket` probes run *inside* the pod (`curl`/`wget`, `nc`/`bash`); an image without those
  tools is reported NotReady with a log line, never silently Ready. Named probe ports and gRPC
  probes are rejected at apply.
- **ServiceLB forwards to this node's pods only**, through ports Docker publishes when the pod is
  created: when a Service starts targeting a port a running pod does not publish, the pod is
  replaced through the normal readiness-gated rollout before it receives traffic.
- **Physical failure domains remain unqualified.** Legacy cluster suites share a Docker daemon;
  the newer qualification lab exercises three separate Linux VM kernels and Docker daemons,
  real WireGuard and guest faults, still on one Mac. See the exact
  [current results](tests/qualification/CURRENT-RESULTS.md); this is not physical-host HA.
- **Host-local storage is not distributed.** Pods with hostPath/PVC volumes are placed on the
  scheduling (leader) node only — a remote node refuses them (409). There is no durable volume
  node binding, replication or fenced attachment handoff; after leader/node change the same
  logical path can resolve to a different local directory. Do not rely on it for stateful
  failover or acknowledged-data durability. Requested stateful production support has a
  separate, currently unqualified [storage gate](tests/qualification/STATEFUL-PRODUCTION-GATE.md).
- **No node cordon/drain/join commands.** Nodes are declared with `--peers`; `royak node drain`
  and `node join` exit with an error.
- **Ambiguous outcomes are reported as such.** A write the leader could not commit within 5 s
  returns 504 "outcome unknown" (it may still commit once a quorum returns; re-read before
  retrying). A leader lost mid-write can return 421 for a write that later commits.
- **A newly elected scheduler waits for the census** (every configured peer reported, or 15 s)
  before placing pods, so recovery right after a failover is slower. Other nodes also learn about
  a peer's pods through that poll: `logs`/`get` for a pod that started seconds ago on another
  node can briefly return 404.
- **The mesh port is fixed (`:6550`)**, so only one node per host binds it; sealed peer frames
  are encrypted and authenticated but a captured frame can be replayed.
- **Canary strategy** is parsed and scheduled with weighted steps, but traffic splitting at the
  service layer still needs a proxy integration.
- **`kubectl port-forward` uses SPDY-over-WebSocket in kubectl 1.36, which Royak doesn't decode.**
  Use `royak port-forward <pod> <local>:<remote>` for a guaranteed local→pod tunnel (verified).
  `kubectl exec` — including interactive `-i`/`-it` with a TTY — works over WebSocket.
- **No Helm engine.** Use `helm template ./chart | royak apply -`.
- **NeuroPod runtime (`--runtime neuropod`) is EXPERIMENTAL.** OCI pull and basic pod lifecycle
  work on Linux with root (network namespaces); the macOS path uses Apple Virtualization.framework
  but is not end-to-end wired. Deleting a deployment does not remove its NeuroPods yet (no GC).
- **Anomaly/prediction is statistical** (z-scores, linear regression) in the public path; the
  neural brain trains via backprop but is a monitor, not the decision-maker in the reconcile loop.
  Autoscaling is **reactive on real Docker CPU stats**; the load-prediction (`[PREDICT]`) line is
  logged for observability only and does not itself drive replica counts.
- **Node-to-node mesh is AES-256-GCM encrypted** (symmetric, shared cluster secret — see
  `mesh_crypto.rs`). A cluster CA also mints a per-pod certificate + identity token and injects it
  into each container (`ROYAK_POD_TOKEN`), but these identities are **issued, not yet verified**:
  `verify_pod_token` and the `mtls` NetworkPolicy flag are not enforced on the live path, so the
  mesh is encrypted transport, not per-pod mutual-TLS authentication.
- **Runtime-only state.** Pipeline run history and the issued cluster CA material are not part of
  the replicated desired state.
- **`command` maps to Docker `Cmd`** (the image's `ENTRYPOINT` is kept), and `envFrom` values
  override literal `env` with the same name.

## Roadmap

The gaps above are designed, scoped and scheduled in [ROADMAP.md](ROADMAP.md):

- **v0.4 (current)** — openraft consensus on the live write path, durable log/vote, snapshots (in source, not yet in a published release — `v0.4.0-beta.1` predates it); multi-machine verification next.
- **v0.5** — WireGuard mesh replacing the proxy MVP for cross-node pod traffic.
- **Post-v1.0** — eBPF/XDP data path (Cilium-style).

## Built by

**Ivo Gergov** and **Velko** — Evo Tech Labs

## License

MIT
