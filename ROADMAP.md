# Royak Roadmap

This document is the authoritative source for what Royak **does today** vs. what's planned, with the **why** and the **how** for each gap. It exists so the project's intent is public and reviewable — not reverse-engineered from commits.

Versioning tracks the git tag cadence, not calendar time. Items move forward when tests prove them, not when a clock ticks.

---

## Current state — v0.4-beta

What's working end-to-end, covered by the test suite:

- Container orchestration on Docker (single node): deploy, scale, rolling update, rollback, health probes, CrashLoopBackOff detection.
- 22+ K8s resource kinds with YAML/JSON parsing (Deployment, Service, ConfigMap, Secret, HPA, NetworkPolicy, ResourceQuota, Ingress, Operator, CustomResource, Pipeline, Function, Job, CronJob, DaemonSet, RbacRole, Guard, PV, PVC, StorageClass, Namespace).
- Service DNS: pod-to-service name resolution via Docker network aliases (single node).
- Leader lease HA: file-based election with 15s TTL and automatic failover when the leader crashes. Single-writer guarantee on shared state.
- mTLS cluster CA with per-pod certificate issuance.
- AES-256-GCM encrypted Secrets at rest.
- RBAC enforcement at the API layer (403 on unauthorized verb+resource+namespace).
- kubectl compatibility: discovery, get, describe, delete, watch, **and native apply for creation** (full OpenAPI v3 operation IDs — no `--validate=false`). ✅ landed in v0.3. Client-side apply updates (strategic merge + last-applied annotations + full field schemas) ✅ landed in v0.4-beta.
- Cross-node mesh proxy (MVP): pods on node B reach services on node A through per-node proxies. ✅ landed in v0.3
- Ingress as a live reverse proxy: async, streaming, binary-safe, TLS, Host+path routing. ✅ landed in v0.3
- openraft integration, phases 1–2: single-node command flow + leader election and log replication across 3 nodes, proven over in-process and HTTP transports. ✅ landed in v0.4
- Multi-node state sync via HTTP POST + pull on join (UDP discovery optional).
- Prometheus `/metrics`, Kubernetes-compat `/openapi/v3`, built-in dashboard.
- Test coverage: 88 unit + 100 integration + multi-node + HA lease + mesh + ingress + NeuroPod + load suites.

## Known limits

| What's not in v0.4-beta | Why it matters | Planned in |
|---|---|---|
| Raft on the live write path | Election + replication are proven in tests, but the reconcile loop still mutates state directly. A partition across independent disks can still split-brain. | v0.4 final (phase 3) |
| Raft snapshots + log compaction | Long-running clusters need bounded log growth. | v0.4.x |
| kubectl `exec -it` (interactive TTY) + `port-forward` | Non-interactive exec works over WebSocket; interactive stdin/TTY streaming and port-forward stream pairs are the remaining kubectl gaps. | v0.4.x |
| WireGuard L3 mesh | Cross-node **service** traffic is now AES-256-GCM encrypted on the proxy hop (v0.4-beta). A routed encrypted L3 (raw pod-IP peering across hosts via WireGuard) is still v0.5. | v0.5 |
| Native Helm engine | Today: `helm template \| royak apply -`. | v0.5 |
| Canary traffic splitting at service layer | Parsed and scheduled; needs proxy integration. | v0.5 |
| Multi-node ServiceLB | NodePort + LoadBalancer ✅ shipped (single-node, klipper-lb-style); multi-node external IP pools pending. | v0.5 |

---

## v0.3 plan — cross-node networking + native kubectl ✅ SHIPPED

Goal: make "multi-node" mean something pods can rely on, not just control-plane state sync.

### Cross-node pod networking

Three options evaluated. We'll land (1) as an MVP in v0.3 and migrate to (2) before v1.0. (3) is aspirational.

#### 1. Proxy-based service mesh (v0.3 MVP)

**How it works.** Every node runs a small TCP/HTTP proxy on a well-known port (default 6550). Each pod's `/etc/hosts` is injected with an entry mapping every cluster service to the local node's proxy IP. When a pod hits `curl http://my-svc`, the request lands on the local proxy, which consults the node-to-pod map in shared state and forwards to the node actually running a matching pod. The target node's proxy terminates the connection and hands it to the local pod over the Docker-native namespace network that already works today.

**Pros.** Userspace, no kernel changes, no CNI plugin dance, no root required on non-Linux. Works with our existing Docker-per-namespace isolation. Easy to reason about.

**Cons.** Every cross-node call is double-proxied (source pod → source node proxy → target node proxy → target pod). Latency overhead ~200µs per hop in typical conditions. No UDP support in MVP (only TCP). Not transparent to pods that use IP-based peering.

**Design.**
```
src/cluster_mesh.rs       — the proxy server + router
  pub struct NodeProxy { listen: u16, state: Arc<RwLock<DesiredWorld>> }
  impl NodeProxy {
      pub fn run(self) -> Result<(), io::Error>;      // blocking accept loop
      pub fn route(&self, svc: &str) -> Option<Endpoint>;
  }
  pub struct Endpoint { pub node: String, pub addr: SocketAddr }

  // Host address resolution: state.nodes[node].address (from join_cluster)
  // Pod endpoint resolution: state.deployments[dep].pods[i] → node, internal_ip
```

**Test plan.** `test-crossnode.sh` starts 2 `watch` processes on separate ports with shared state. Deploys a service whose single pod lands on node A. From a pod on node B, `curl http://svc-name` reaches the pod — verified by HTTP 200 and matching log line. Latency budget: <10 ms end-to-end for HTTP on localhost.

**Out of scope for MVP.** Encryption (v0.4 via WireGuard). UDP traffic. Raw TCP port forwarding between arbitrary pods (only services).

#### 2. WireGuard mesh (v0.4 — replacement for MVP)

Each node generates a WireGuard key pair at startup, publishes its public key in the shared state, and pulls peer keys. A local `wg0` interface is brought up with one peer per other node. Pods get an IP in the cluster CIDR routed through `wg0`; all cross-node traffic is authenticated + encrypted at kernel level.

Crate evaluation:
- **boringtun-cli** (Cloudflare, userspace WG in Rust): no root needed, ~5k LOC dep.
- **wireguard-rs** (manual): more control, more work.

Preference: boringtun-cli for the pure-Rust story. No native code dependency. Fits the "one binary" narrative.

Open question: on macOS we can't ship a kernel module, but the Virtualization.framework path (NeuroPod MicroVM) has its own kernel and WG is routine in Linux 5.6+. Acceptable.

**Test plan.** Same scenario as (1) but with kernel-level routing and `wg show` as witness. Benchmark: throughput ≥ 90% of loopback inside a pod on the same host; latency < 1.5 ms cross-node on LAN.

#### 3. eBPF / XDP data path (aspirational, post-v1.0)

Cilium-style. Not committed. Documented so future-us doesn't re-discover the target.

### kubectl apply without `--validate=false`

Root cause: kubectl v1.32 resolves GVK → path by scanning OpenAPI v3 operations. Our operations have `x-kubernetes-group-version-kind` but are missing the full operation IDs (`createNamespacedConfigMap`, `readNamespacedConfigMap`, etc.) and response schemas that kubectl's validator expects.

Plan: fill in the operation scaffolding from a compact generator. ~400 lines of Rust generating the spec, driven by a small table of (group, version, kind, plural, namespaced). Targeting 100% compatibility for the 22 kinds we support.

Estimated effort: one focused session.

### Ingress as live proxy

Parse already works. Add a hyper-based reverse proxy module, wired into the ingress reconcile path, that listens on 80/443 and forwards by `Host` header + path. TLS cert from the ACME integration that already exists as stubs in `net_security.rs`.

Estimated effort: 1-2 sessions.

---

## v0.4 plan — real HA with consensus (phases 1–2 ✅ done, phase 3 in progress)

Goal: the word "HA" means the same thing in Royak as in etcd.

### The problem with the current lease

The file lease in v0.2 is a practical single-writer guarantee under one of these conditions:
- Both instances see the same filesystem (same host, or a shared NFS/FUSE mount).
- Both instances can update a shared JSON file with atomic rename semantics.

Under a network partition between instances on different hosts with separate disks, the lease cannot detect the other side. A 3-host cluster without shared storage can elect two leaders simultaneously — split-brain. That's unsafe for anything that cares about correctness.

### Solution: integrate a proper Raft library

We will not write Raft. There are two serious Rust options:

- **`openraft`** (Databend): async-first, type-parameterised on state machine, active development, used in Databend. API is heavier but flexible.
- **`async-raft`** (older, forked into openraft): simpler surface, less active.

Preference: **openraft**. Generic state machine fits our `DesiredWorld` naturally, and the crate handles log replication, snapshots, leader election, membership changes — all the hard parts.

### Integration design

```
src/consensus.rs            — new module
  pub struct ConsensusNode {
      raft: openraft::Raft<...>,
      world: Arc<RwLock<DesiredWorld>>,
  }

  // openraft wants a state-machine trait; we implement it as:
  //   apply(Command) -> Result<Response>
  //   where Command is an enum over our apply/delete/scale operations,
  //   and Response is the reconcile log line.

  impl RaftStorage for RoyakStore { /* persists to state.json.nrns */ }
  impl RaftNetwork for HttpTransport   { /* reuses /royak/v1/raft/* */ }
```

The reconcile loop moves from "read state, mutate state, save state" to "propose Command on Raft, apply on commit, mutate state". Read ops stay local (followers can serve reads).

### Migration path

1. **v0.3.x** ✅ — introduce `consensus.rs` as a no-op shim that wraps the current single-writer flow. Add the module to the build, write trait-level unit tests.
2. **v0.4.0** — integrate openraft:
   - **Phase 1 ✅** — openraft wired to our `Command` state machine, single-node command flow proven (`client_write` → log → apply → `DesiredWorld` mutation).
   - **Phase 2 ✅** — network transports: in-process registry for distributed invariant tests + HTTP transport on `/royak/v1/raft/*`. 3-node election and log replication pass in the unit suite.
   - **Phase 3 (in progress)** — route the live reconcile write path through `backend.propose(cmd)`; lease file becomes single-node fallback. Add CLI: `royak cluster bootstrap <peers...>` to initialise a quorum.
3. **v0.4.1** — snapshots + log compaction.

### Test plan

- Unit: state-machine apply/rollback, command serialization roundtrip.
- Integration: 3-node cluster on localhost (with `--port` flag we already have). Kill leader, assert re-election. Isolate one node, assert it can't commit. Heal partition, assert it catches up.
- Chaos: randomised kill/restart of 1 of 3 nodes under load; assert no committed operation is lost.

Estimated effort: 3-4 dedicated sessions.

---

## What's NOT on this roadmap

Things that look reasonable but are out of scope for clarity:

- Custom CNI replacing Docker networks. Docker-per-namespace works; re-implementing CNI for single-node is churn.
- Replacing Docker with containerd directly. The NeuroPod experimental path already explores OCI without Docker. If we commit to that, it's a v0.5 consolidation, not a v0.3/v0.4 item.
- Web UI beyond the current dashboard. The dashboard covers the demo; a full React app is not differentiating.
- AI-driven scheduling replacing the reconcile loop. The brain module is deliberately a monitor + anomaly detector, not the decision-maker. Changing that is research, not engineering.

---

## How to contribute to this roadmap

If you care about one of these items, open an issue with:
- The specific scenario you want to work (e.g., "5-node staging cluster on LAN, all on Ubuntu 22.04").
- Success criteria you'd measure (throughput, failover time, latency).
- Whether you can help test.

The roadmap serves real users, not aesthetics.
