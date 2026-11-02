# Kubernetes behavior coverage — not conformance certification

Royak implements a Kubernetes-shaped subset with additional Royak-specific
features. Accepting a `kind`, parsing YAML, or passing the local suites does not
establish complete Kubernetes semantics. This contract keeps those separate.

Official Kubernetes software conformance uses the upstream versioned
`[Conformance]` E2E tests; a certification run must not skip conformance tests.
See the [CNCF instructions](https://github.com/cncf/k8s-conformance/blob/master/instructions.md)
and [program](https://www.cncf.io/training/certification/software-conformance/).
That complete official suite has **not** been run against Royak here. No claim
of Kubernetes certification or full drop-in compatibility is made.

## Local acceptance matrix

Read actual exits/skips in the latest `.runs/rkq-suites-*/report.json`; a suite
name in this table is a test location, not a claim that its latest run passed.

| Area | Real test coverage | Important boundary |
| --- | --- | --- |
| Deployment lifecycle, scale, rolling update, rollback | `test-demo.sh`, `test-load.sh`, `test-multinode.sh` | No separate ReplicaSet controller/ownership-chain parity; command maps to Docker Cmd, not Kubernetes ENTRYPOINT replacement |
| DaemonSet, Job, CronJob, init/sidecars, StatefulSet | `test-demo.sh` | Tests named behaviors, not the complete controller API; StatefulSet storage is host-local, not cross-node replicated storage |
| ConfigMap/Secret/env/volumes, quota, limits | `test-demo.sh`, `test-multinode.sh` | Docker runtime subset; security/placement fields must be evaluated separately |
| Namespace identity and RBAC | `test-auth-http.sh`, `test-multinode.sh` | Token auth and the implemented RBAC rules; no demonstrated OIDC/client-certificate or native ServiceAccount-token lifecycle parity |
| HTTP/TCP/exec readiness, ServiceLB updates | `test-servicelb-probes.sh`, `test-http-probe-address.sh`, `test-beta-lifecycle-topology.sh` | New timing/threshold/startup/incarnation and process-group timeout contracts require the current beta fixture; synchronous ticks are not real-time deadlines. Supported Docker subset only; no hostile session-escape guarantee. See [probe contract](PROBE-TOPOLOGY-CONTRACT.md) |
| Ingress/mesh encryption and routing | `test-ingress.sh`, `test-mesh.sh`, `test-http-protocol.sh`, three-daemon fault harness | Backend failover is safe only before transmission; ambiguous POSTs are not replayed; chunked bodies are decoded in a bounded buffered response path, not a qualified streaming/SSE/upgrade path; not a complete CNI/routed pod-IP model |
| ClusterIP/DNS, NodePort/LoadBalancer | `test-demo.sh`, `test-servicelb-probes.sh` | Docker aliases and userspace listeners, not a general Kubernetes cluster-network implementation; ServiceLB uses local-node backends |
| NetworkPolicy | `test-demo.sh` | Current Royak policy shape/subset; documented rule-activation window and kernel-dependent enforcement mean no full Kubernetes NetworkPolicy equivalence claim |
| kubectl apply/get/scale/logs/exec/watch | `test-auth-http.sh`, `test-demo.sh` | Tool/API compatibility is not full API-server semantics; native port-forward differs from modern kubectl SPDY-over-WebSocket |
| Durable API state, single writer, Raft | `test-ha-lease.sh`, `test-raft-cluster.sh`, three-daemon fault harness | Named crash/partition checks; not a full concurrent-operation linearizability proof, full-cluster disaster recovery or cross-host result |
| HPA/metrics/events | `test-demo.sh` | CPU-driven local behavior; events are node-local and volatile; no full autoscaling/v2/custom-metrics qualification |
| Container security restrictions | `test-k8s-negative-contract.sh`, constrained three-daemon fault workload | Enforced Docker UID/GID/non-root, read-only root, no-new-privileges and capability subset; unknown security fields/privileged true refused. No fsGroup/SELinux/seccomp or NeuroPod support. See [security and upgrade contract](SECURITY-HTTP-CONTRACT.md) |
| PaaS build/pipelines and NeuroPod | `test-build.sh`, `test-neuropod.sh` | Royak-specific capabilities; NeuroPod remains experimental, not evidence of Kubernetes equivalence |
| Read-only cluster topology | `test-beta-lifecycle-topology.sh`, `topology_ui.cjs`, fault harness `--ui-check` | Actual metadata/observations and independently authorized reference edges, not invented mesh flows; synthetic UI and real API evidence are labelled separately; no mutation/tunnel controls |

## Explicit unqualified/missing areas

The current `PodSpec`/`ContainerSpec` model a strict supported securityContext
subset, not affinity, tolerations or the broad pod placement contract. Unknown
fields inside securityContext are rejected; unrelated unsupported fields can
still be discarded during deserialization. A production beta must not imply
all Kubernetes constraints work merely because apply returns success.

Other areas not established by this qualification include CSI and replicated
storage, CNI networking, PodDisruptionBudget behavior, full CRD/operator API
semantics, admission/field-ownership/finalizer equivalence, full dual-stack
networking, upgrades/version skew, disk-full and backup restore, and every
feature not named in a verified test. Some are absent and some are partial;
neither should be promoted to "supported" without source and runtime evidence.

HTTP probes now target the pod interface rather than resolver-dependent
localhost, consistent with the documented
[Kubernetes probe target](https://kubernetes.io/docs/concepts/workloads/pods/probes/).
This is one corrected behavior, not a claim of complete probe conformance.

## How to run the bounded local contract

```sh
python3 -B tests/qualification/run.py build --binary tests/qualification/.runs/linux-royak-qualified
python3 -B tests/qualification/suites.py --binary tests/qualification/.runs/linux-royak-qualified
python3 -B tests/qualification/run.py run --binary tests/qualification/.runs/linux-royak-qualified --duration 300
```

The suite driver runs all 11 existing integration suites plus four new
regressions inside its own Docker daemon; broad legacy cleanup cannot reach the
host daemon. It snapshots the current working files, records the binary/source
hashes and tools, retains failures/skips, and refuses unsafe disk-space margins.
The second command requires actual enforcement of its supported security subset,
not rejection as a substitute for support. The final command uses default HTTP
readiness, with no IPv4 exec workaround, and constrained application containers.

Local contracts remain one physical failure domain. A full Kubernetes-equivalent
product is a substantially larger, separate implementation/qualification target.
