# Royak

**A swarm of containers. One tiny binary.**

> **⚠️ BETA — use at your own risk.** Royak is in public beta. It is great for learning, demos,
> homelabs and edge boxes. It is **not** ready to carry your production. We test every feature in
> CI (unit + integration + multi-node + chaos suites), but our testing is not a substitute for
> yours: **evaluate Royak against your own workloads before relying on it.** The software is
> provided as-is, without warranty of any kind (see [LICENSE](LICENSE)). Every known gap is listed
> in [Limitations](#limitations) and scheduled in [ROADMAP.md](ROADMAP.md) — nothing is swept under a rug.

Royak (*рояк* — Bulgarian for "swarm") manages Docker containers the way Kubernetes does —
deployments, scaling, rolling updates, RBAC, services — in a single ~5.2 MB Rust binary
instead of a control plane you have to babysit.

🌐 **Website:** https://evotech-bg.github.io/royak/
📋 **What works vs. Kubernetes, tested:** [COMPATIBILITY.md](COMPATIBILITY.md)

## Getting Started

**Platforms:** Linux (x86_64, aarch64) and macOS (Apple silicon, Intel). Windows is not supported —
Royak talks to Docker over a Unix socket.

**Prerequisites:** Docker running (Docker Desktop, Colima or OrbStack — `DOCKER_HOST` is honoured).

**Option A — download a pre-built beta binary** from [Releases](https://github.com/evotech-bg/royak/releases),
`tar -xzf`, done.

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

# kubectl-compatible API server (with background reconcile loop)
royak api
kubectl --server=http://localhost:6443 get pods
```

## Features

| Feature | What it does |
|---------|-------------|
| **Deployments** | Create, scale, delete. Resource limits (CPU/memory) enforced in Docker |
| **StatefulSets** | Ordered startup, stable pod identity, per-ordinal volumes (`volumeClaimTemplates`) — data survives pod recreation |
| **Rolling Updates** | Zero-downtime. maxSurge=1, readiness checks, auto-rollback on timeout |
| **Rollback** | Reverse rolling update — works even after rollout completes |
| **Services** | `kind: Service` with selector + ports. ClusterIP with pod→svc DNS; NodePort served by the built-in ServiceLB (userspace LB, works on macOS too) |
| **ConfigMaps/Secrets** | `envFrom` env injection AND file projection as volumes (secrets 0600) |
| **RBAC** | Native `Role`/`ClusterRole`/`RoleBinding`/`ServiceAccount` + Royak `RbacRole` — enforced on all API writes |
| **Admission webhooks** | `ValidatingWebhookConfiguration` — Royak calls your webhook URL and honours allow/deny |
| **Operators** | `kind: Operator` + `kind: CustomResource` — auto-provision, lifecycle hooks |
| **Guards** | Auto-remediation: pod_crash → restart, high_memory → scale_up |
| **CrashLoopBackOff** | Stops recreating after 5 rapid failures. Resets when healthy |
| **YAML Export** | `get deployment/web -o yaml` — full round-trip: get → edit → apply |
| **kubectl API** | `get`/`describe`/`delete`/`watch`/`logs`/`scale`/`exec` (incl. `-it` TTY)/`get events` + `apply` incl. client-side updates |
| **Stdin Pipe** | `cat file.yaml \| royak apply -` or `helm template \| royak apply -` |
| **HPA** | Auto-scaling based on real Docker CPU stats |
| **Pipelines** | CI/CD with DAG dependencies, git triggers, matrix builds |
| **Ingress** | Live reverse proxy — async, streaming, binary-safe, TLS, path-based routing |
| **Multi-node** | UDP autodiscovery, pod distribution, heartbeat monitoring, cross-node mesh proxy |
| **HA leader lease** | File-based election, automatic failover (15s TTL) |
| **Raft (in progress)** | openraft integrated: election + log replication proven in tests; live write path lands next |
| **Encryption** | AES-256-GCM for secrets at rest and inter-node communication |
| **MCP Server** | 13 tools for AI assistant integration (deploy, scale, exec, top...) |

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

Binary: **~5.2 MB** | ~16,000 lines of Rust

## How it works

Every 5 seconds, the reconcile loop:
1. Reads desired state (from YAML specs stored in memory)
2. Reads actual state (from Docker API)
3. Diffs them
4. Takes action (create, start, stop, remove containers)

This is what Kubernetes does with etcd, kubelet, kube-proxy, and a control plane.

## Test suite

```bash
cargo test --bin royak      # 85 unit tests
./test-demo.sh              # 88 integration tests (needs Docker)
./test-multinode.sh         # multi-node sync tests (2-process localhost)
./test-ha-lease.sh          # HA leader-lease tests (election + failover + release)
./test-mesh.sh              # cross-node mesh proxy tests (Linux only, see note)
./test-ingress.sh           # ingress live proxy tests (Linux only, see note)
./test-load.sh              # load + chaos (10 deploys × 2 replicas, pod-kill respawn)
./test-neuropod.sh          # NeuroPod smoke tests (EXPERIMENTAL)
```

> **Note:** the mesh and ingress suites forward traffic to container IPs, which are host-routable
> only on **Linux**. On macOS run `./test-mesh-macos.sh` — it builds a Linux binary and runs the
> suites inside a container where IPs are routable (verified: mesh 8/8, ingress 15/15, encrypted
> mesh 8/8). The old note (host can't reach container IPs on macOS Docker
> Desktop/Colima/OrbStack run containers inside a VM) those two suites fail with connect timeouts.
> CI runs them on Ubuntu.

Unit tests cover: YAML parser edges, neural brain (identity, encrypt/decrypt, training convergence,
anomaly detection, weight persistence), neural state KV + save/load + corruption paths, pod-token
HMAC verify, AES-256-GCM secret encryption, schema-version migration, atomic state writes, OpenAPI
v3 spec generation, leader-lease acquisition/renewal/takeover/release, Raft state machine
(single-node apply, 3-node election + replication over in-process and HTTP transports).

Integration tests cover: deploy, service + DNS (pod→svc hostname), RBAC enforcement (403), scale
up/down, logs, rolling update, rollback, stdin pipe, delete, state persistence, namespace, Secrets
(AES-256 at rest), ConfigMap, HPA, NetworkPolicy, ResourceQuota, Canary, Pipeline,
Operator+CustomResource, Functions (invoke), Job, Ingress, Guard, Brain, Dashboard + /metrics,
kubectl compatibility (get/apply/delete), graceful shutdown, CrashLoopBackOff, health-probe restart.

## Limitations

**Beta means beta.** Royak is an MVP of a vision — for learning, demos, edge/homelab and small
deployments. Here is the honest ledger:

- **Single-writer control plane with file-based leader lease.** Multiple `watch` instances pointed
  at the same state path compete for a lease file; one becomes leader, the rest stand by. If the
  leader crashes, the next standby takes over after a 15-second lease TTL. This is a practical HA
  guarantee for single-host or shared-filesystem setups — **not** a Raft/Paxos replacement.
- **Raft consensus is integrated but not live yet.** openraft phases 1–2 are done: leader election
  and log replication are proven in tests over in-process and HTTP transports. Phase 3 — routing
  the live reconcile write path through Raft — is the next milestone (see ROADMAP).
- **Multi-node works for basic cases but is not battle-tested at scale.** Node join/drain commands
  exist; split-brain behavior across independent disks and large-cluster convergence are not yet
  exercised by the test suite.
- **Canary strategy** is parsed and scheduled with weighted steps, but traffic splitting at the
  service layer still needs a proxy integration.
- **`kubectl port-forward` uses SPDY-over-WebSocket in kubectl 1.36, which Royak doesn't decode.**
  Use `royak port-forward <pod> <local>:<remote>` for a guaranteed local→pod tunnel (verified).
  `kubectl exec` — including interactive `-i`/`-it` with a TTY — works over WebSocket.
- **No Helm engine.** Use `helm template ./chart | royak apply -`.
- **No port-forward.** Exec is one-shot (run command, get output).
- **NeuroPod runtime (`--runtime neuropod`) is EXPERIMENTAL.** OCI pull and basic pod lifecycle
  work on Linux with root (network namespaces); the macOS path uses Apple Virtualization.framework
  but is not end-to-end wired.
- **Anomaly/prediction is statistical** (z-scores, linear regression) in the public path; the
  neural brain trains via backprop but is a monitor, not the decision-maker in the reconcile loop.
- **State is JSON + binary neural.** Writes are atomic (write-tmp, rename) with a Unix `flock`
  guard. No distributed consensus on the live path yet — source of truth is whichever node writes
  last.

## Roadmap

The gaps above are designed, scoped and scheduled in [ROADMAP.md](ROADMAP.md):

- **v0.4 (current)** — real HA: openraft-backed consensus on the live write path, snapshots, log compaction.
- **v0.5** — WireGuard mesh replacing the proxy MVP for cross-node pod traffic.
- **Post-v1.0** — eBPF/XDP data path (Cilium-style).

## Built by

**Ivo Gergov** and **Velko** — Evo Tech Labs

## License

MIT
