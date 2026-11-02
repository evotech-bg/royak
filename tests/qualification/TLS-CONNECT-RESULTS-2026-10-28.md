# TLS and Connect VM remediation — 2026-10-28

Status: **PASS for the bounded local and three-VM remediation contract**.
All three canonical acceptance joins are PASS for the current source, fixtures,
Linux artifact and native client. This report is not a production,
Kubernetes-conformance or independent-hardware certificate.

## Product changes and demonstrated causes

- **VMF-001:** the focused pre-fix three-VM reproducer
  `rkq-20261028-225625-e40ad6/capacity-report.json` failed on its second
  eight-stream cycle. The issuer audit recorded `Interrupted system call`;
  guest diagnostics showed running, non-OOM workloads. Connect now treats an
  interrupted backend read as an empty, non-EOF frame. The preceding write is
  not replayed; the next normal exchange can receive pending bytes. Genuine
  EOF and hard read errors retain their existing failure behavior.
- **VMF-002:** API and ingress previously generated unrelated, ephemeral TLS
  certificates. Each state file now has one durable identity at
  `<state-path>.tls.json`, shared by both listeners and preserved on restart.
  A private lock serializes creation; the key/certificate pair is validated,
  written privately and atomically, and synced before use. Corrupt, mismatched,
  symlinked, non-regular or non-private identity storage fails closed rather
  than silently rotating or falling back to plaintext. Keys are not in Raft
  state or API objects.

The eight-stream limit, 5 ms backend read timeout, 2 s node RPC deadline and
3 s remote lease have **not** been increased. TLS verification has not been
disabled, and the LB does not re-pin certificates after restart.

## Current-source artifact

Linux ARM64 normal release:
`c1f63362f5f32c5d272d2181a01350ac7e0d62058ae4bb4791a482a3407e0335`.
Its adjacent `linux-royak-vm-remediation-final.build.json` binds the complete
embedded source inventory and records unchanged sources during the build and
`debug_symbols: false`.
Native macOS client:
`aab3f675485e520fa0a5453256e6412590c79c6443cf7fdaec73c574ae17bbfc`.

## Qualification evidence

Completed so far:

- Native Rust: 254/254 in three repeated runs, zero failures/ignores/filters;
  logs `native-vm-remediation-{1,2,3}.log` in `.runs/`.
- Linux Rust: 254 passed, 0 failed, 0 ignored in
  `rkq-unit-20261028-230026-96f998`.
- Python qualification infrastructure: 31 existing plus 17 VM/LB tests pass.
- Focused real-VM capacity: 30/30 checks in
  `rkq-20261028-230623-87b9c8/capacity-report.json`: 12 cycles of eight live
  remote streams, ninth refused, revoke closes all eight.
- Full VM Connect: 66/66 in each of three consecutive runs:
  `rkq-20261028-230801-3fcef5`, `rkq-20261028-231011-e43013`,
  `rkq-20261028-231209-ff6a9c`. Includes the original actual socket/permission
  contract, three API/ingress identity comparisons, unchanged client trust after
  issuer restart and explicit direct-TCP namespace policy tests.
- Local three-daemon Connect: 54/54 in each of three consecutive runs:
  `rkq-20261028-230852-be7fbd`, `rkq-20261028-231034-c7bcdf`,
  `rkq-20261028-231230-c85986`.
- All 15 Linux integration suites pass with empty skip lists and successful
  parent/cleanup results. Groups:
  `rkq-suites-20261028-230623-6fced0` (4 suites) and
  `rkq-suites-20261028-230843-e7d41d` (11 suites). Includes actual NeuroPod GC
  26/26 and lifecycle/topology/RBAC 53/53. An earlier parallel provisioning
  attempt `rkq-suites-20261028-230623-ca4701` could not allocate its subnet and
  ran no suites; retained as a lab setup failure, then rerun with staggered
  provisioning. No product assertion or acceptance threshold was weakened.
- Fresh three-daemon fault/300-second observation/live-browser regression:
  13/13 in `rkq-20261028-230901-d5596b`, 534.058 seconds total. All 1937
  acknowledged application writes retained in the external ledger; 84
  failed/ambiguous requests are visible. Final observation: 1289/1289 successes.
  Seven acknowledged control writes converged. Real desktop/mobile screenshots
  were inspected; the actual three recovered pods, placement, permissions,
  read-only interactions and two real polling updates passed.

- External verified-TLS Caddy LB and real three-VM fault matrix: **31/31** in
  `rkq-20261028-231403-d8c3fc/lb-report.json`, 289.257 seconds. VM 1 had an
  actual running application replica and a successful LB response in the
  preceding three seconds before the Parallels hard stop. Survivors replaced
  its replicas before return, and a new kernel boot ID proved a real restart.
  The exact trusted API/ingress certificate survived the restart; all three
  ingresses rejoined final LB rotation without trust updates.
  - LB baseline: 81/81; whole-VM restart phase: **254/255 (99.61%)**;
    final 60-second observation: **221/221**. These bounded windows are not an
    availability SLO or a zero-downtime claim. The predeclared 99% baseline/final
    and 95% restart-window thresholds were not changed.
  - All **1062** acknowledged LB writes and **950** acknowledged direct-node
    writes retained exactly. **3** LB and **99** direct requests were
    failed/ambiguous; the external ledger has 2013 rows, including one possible
    ambiguous commit. No exactly-once or distributed-volume claim.
  - Seven acknowledged control writes converged; final replica count is three.
    Non-root UID/GID 10001, read-only root, dropped capabilities and
    no-new-privileges survived replacement/restart.

Canonical current joins:

- `.runs/current-connect-acceptance.json`: PASS, latest three local Connect
  repetitions and all 15 current-source suites.
- `.runs/current-coverage.json`: PASS, all suites plus fresh fault/UI evidence.
- `.runs/current-vm-acceptance.json`: PASS, latest three full VM Connect attempts
  and latest full LB fault attempt, all cleanup successful.

An older passing attempt cannot replace a newer matching failure. The focused
capacity report is deliberately separate from full Connect acceptance. Earlier
pre-fix and incomplete attempts remain preserved, not relabeled as passes.

## Upgrade and trust boundary

The former ephemeral private key cannot be recovered during upgrade. First
start of this version therefore establishes a new persistent identity; existing
operators/LBs need one explicitly authenticated trust update. Subsequent tested
process/VM restarts must preserve the exact leaf and require no trust change.
The existing localhost/127.0.0.1/royak SANs remain unchanged. Custom DNS/IP
issuance, public PKI, rotation/renewal and certificate-expiry operation are not
qualified by this change. Back up the private identity alongside node state.

## Scope and exclusions

The real network tests use three Ubuntu ARM64 guests, each 2 vCPU / 2 GiB RAM,
with separate kernels, machine/boot identities and Docker daemons. They share
one physical Mac and are not independent physical failure domains.

The external Caddy application LB is loopback-only on the Mac and verifies
each guest's TLS identity. It is not a production HA LB and does not balance
issuer-affine Connect sessions. Its external SQLite ledger tests acknowledged
application writes, not Royak distributed-volume durability or exactly-once
delivery. Namespace objects alone do not imply default-deny networking; direct
TCP isolation is tested with the supported explicit denyAll policy.

Pre-existing local changes and earlier failed evidence are preserved. No
commit, push, release, public-demo update, host VPN/route change or global
Docker cleanup is part of this work.

Final cleanup verified zero guest containers, no test WireGuard interface or
partition rules, and an inactive qualification service on every VM. Caddy,
management forwards, external ledger listeners and all owned local DIND
containers/volumes/networks are gone. The ephemeral LB private key was removed.
All three exact owned VM UUIDs were gracefully powered off and their stopped
state verified. VM disks, private state/identity and evidence remain retained;
see the private inventory's `final-cleanup.json` and `final-power-state.json`.
