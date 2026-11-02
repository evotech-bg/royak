# Security and HTTP contract — current source, 2026-10-27

## Docker security context

Supported pod defaults: `runAsUser`, `runAsGroup`, `runAsNonRoot`.
Supported container overrides: those three plus `readOnlyRootFilesystem`,
`allowPrivilegeEscalation`, `capabilities.add/drop` and `privileged: false`.
Container identity settings override pod defaults, including an explicit false.
The effective settings are stored in desired state, included in the launch
plan and sent to the receiving Docker node. Where Royak already supports init
containers and sidecars, they use the same security mapping as main containers.

Docker receives the requested numeric user/group, `ReadonlyRootfs`,
`no-new-privileges:true` and capability sets. A non-root request without an
explicit UID requires a provably nonzero numeric image USER; named, root or
unknown image users fail closed. The inspected numeric UID is pinned on create.
UID/GID 4294967295, non-root with UID 0, unknown capabilities, privileged true,
and no-privilege-escalation with SYS_ADMIN/ALL addition are refused.

Unknown fields within a securityContext are rejected. In particular fsGroup,
SELinux, seccompProfile and other Kubernetes security fields are not implemented.
This does not make every other unsupported PodSpec field strict. No claim of
Pod Security Standards compliance or safe arbitrary hostile multi-tenancy is
made. Experimental NeuroPod refuses security contexts rather than ignoring
them. NetworkPolicy's separate enforcement limitations still apply.

## State and upgrade boundary

The earlier storage-identity stage used **schema 4**; current development is
**schema 5** with the host-access boundary below. Loading schema3
retains `.v3.bak`, schema2 retains `.v2.bak`, and older migrations retain
`.v1.bak`; a source-version backup does not overwrite another version's backup.
Schema4 adds durable server-owned namespace/claim/PV incarnations. Legacy
migration assigns deterministic identities across Raft peers but never grants
managed-backend authority over existing host paths. Missing/malformed current
identities fail closed instead of silently regenerating them. Real native
HTTPS and three-process Raft tests cover stable UIDs across restart/failover,
new UIDs on recreation, actual previous-binary refusal of the new protected
snapshot, and unchanged source bytes on refused offline downgrade.

The later schema4 lifecycle extension is nested under the strict storage
identity object. The earlier UID-only working binary refuses that unknown
authority too. Managed records carry immutable namespace/claim/volume identity,
single-writer intent and monotonic epoch; generic manifests cannot fabricate a
ready mount. Old-schema/envelope migration, legacy restore and fresh Raft seed
bootstrap cannot import or discard managed volume/attachment state. These
refusals are not the final explicit recovery protocol. Backend receipt
construction is currently test-only; no physical driver/mount/fencing API is
enabled, so new native claims remain Pending rather than granting disk access.

The new `storage-driver` CLI is a separate Linux-root operator maintenance
boundary, not an HTTP or namespace-authorized storage API. It requires trusted
private configuration and pins physical serial/PV/VG and request identities;
it can prepare fresh journal-owned backing LVs and remove them while
independently proven zero/unformatted. The next component can also create DRBD
metadata and activate only a closed Secondary with exact journal/kernel identity,
WireGuard checks and an allocation-owned atomic nftables INPUT/OUTPUT boundary.
It refuses foreign/changed guard policy and any backing block holder before
offline metadata IO; it cannot promote, initialize a data generation,
format/mount, construct a Core backend receipt or grant a pod access. Automatic controller
integration must bind committed identity/epoch/boot/writer authority and run
bounded isolated helpers; direct kernel IO cannot safely block an API worker.
The nftables boundary is tested against real guest route/interface loss and
unencrypted inbound probes; it does not protect against malicious node root.
Complete host-access runtime/resource qualification and controller boot-bound
activation remain required before application writers are enabled.

### Host access — development contract, incomplete runtime qualification

Current source requires cluster-scoped `use hostaccess` in addition to workload
rights for direct hostPath, added capabilities other than NET_BIND_SERVICE and
legacy raw-directory StatefulSet templates. Namespace RoleBindings do not grant
that cluster authority. Full-object and merged PATCH commits check the actual
commit-base permissions. Desired and launch permits are server-issued and bind
namespace incarnation and exact configuration; client fields are not authority.
Reserved control/storage/runtime paths remain forbidden public mounts even to
this role. Claim paths are a separate UID-bearing host-local source, not a
native verified backend grant.

Files are now schema5; the new Raft crypto purpose and v4 sensitive launch
endpoint/purpose refuse unsafe downgrade. Legacy host/VCT state without permits
requires explicit re-apply; legacy VCT paths are preserved, not moved to empty
directories. The native claim controller must still replace that legacy mode.
Actual Docker containers now have an immutable server-created runtime label
bound to the namespace incarnation and whole-Pod host capability (including
init containers). Exec, logs and port-forward check it, not the latest desired
template; unknown/obsolete contracts fail closed. Existing owned legacy Pods
are retired without volume deletion, never silently granted authority. Foreign
cluster/node containers are not adopted. Open streams recheck namespace/RBAC
and host permission every second; an unavailable check fails closed after a
two-second observation bound. This is not a hard real-time revocation promise.
Shutting down the actual Docker sockets unblocks idle readers; cancelling a
port-forward also aborts its child TCP pumps. Commands already executed cannot
be rolled back, and arbitrary background processes are not claimed killed by
closing an exec transport.

Forwarded logs use signed/sealed `/royak/v2/pod-logs` with verified caller and
namespace UID. The receiver checks current RBAC and its actual container;
legacy caller-free forwarding fails conflict. This cross-host path is
implemented but not qualified by the independent per-VM runtime tests.

Real VM authorization, legacy retirement and symlink/bind refusal checks pass
(48 per VM). **Full runtime security remains unqualified:** unbounded internal
exec channels/session admission, per-thread attribution/endurance, mount races
and complete hostile-tenant Docker isolation remain open. Node root/Docker
administration is trusted. Do not enable production writers from these checks.

Upgrade **all cluster nodes** before admitting these constrained workloads.
Constrained launch plans use `/royak/v2/create-pod`, so older workers cannot
silently accept them through the old launch route. Replicated constrained state
also uses a new sealing purpose. All schema4 replicated state now uses a further
storage-identity AEAD domain, which older binaries cannot authenticate. These
safeguards are not a qualified rolling
upgrade/version-negotiation protocol: mixed-version clusters and downgrade are
not supported by this slice. Older binaries cannot read schema4;
do not bypass that barrier by manually lowering the schema version. A rollback
requires a deliberate compatible backup/restore plan and can lose newer changes.

Previously accepted-but-ignored security contexts in old manifests are **not
retroactively inferred** from the raw manifest on migration. Reapply those
manifests with the new binary, then inspect the actual replacement containers.
No user cluster state was migrated as part of this local test work.

## Buffered ingress HTTP response decoding

The raw upstream response is parsed with Hyper's HTTP/1 parser in an in-memory
transport. The parser's synthetic request is never sent to an application;
network requests are not replayed by this decoding step. Chunk framing and
extensions are decoded, binary payloads preserved, malformed/truncated chunks
rejected, and hop-by-hop plus Connection-nominated headers removed. Interim
responses and HEAD response semantics have unit coverage.

Bounds: 32 MiB raw response and decoded body, 64 KiB header buffer, 100 headers,
five-second decoding deadline (separate from the existing network timeout).
Encrypted mesh buffering is bounded too. Trailers are parsed but neither
forwarded nor promoted to ordinary headers. Unsupported transfer codings and
protocol upgrade responses are rejected. This remains a buffered proxy, not a
qualified streaming/SSE/WebSocket/CONNECT implementation.

Pre-transmission connection failover remains bounded; a POST with an ambiguous
outcome after transmission starts is never retried at another backend.

## Runtime regression fixtures

`test-k8s-negative-contract.sh` checks actual Docker configuration and kernel
UID/GID, effective/bounding capability sets and NoNewPrivs; then restarts Royak
and removes the pod to check persisted enforcement on its replacement. It also
requires explicit rejection of contradictory and unsupported security fields.
`test-http-protocol.sh` compares a real chunked upstream with the ingress body.
The three-daemon qualification workload runs non-root, with read-only root,
no privilege escalation and all capabilities dropped throughout real faults.

See [CURRENT-RESULTS.md](CURRENT-RESULTS.md) for completed current evidence and
remaining qualification boundaries. Historical failures are retained.
