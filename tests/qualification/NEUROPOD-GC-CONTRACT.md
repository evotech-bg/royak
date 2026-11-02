# NeuroPod Deployment garbage collection — local Linux contract

Qualification status: **accepted for this bounded local Linux contract**.
See [the exact zero-skip qualification report](NEUROPOD-GC-RESULTS-2026-10-27.md):
three 26-check real NeuroPod runs, all 15 integration suites with no skips, Linux
and native Rust tests, current Connect and fault/UI regression. The earlier
Connect report and its named GC skip remain historical evidence only.

## Ownership and scope

New Deployment-managed NeuroPods persist explicit cluster ID, node name,
canonical state-file path, namespace, Deployment name and creation generation.
GC only considers an exact pod-name/ordinal match belonging to that scope and
not a newer generation. A name prefix alone is never ownership. Unmarked legacy
pods, directly created unmanaged NeuroPods, foreign scopes, corrupt metadata and
symlinked inventory entries are not adopted or recursively deleted.

Deleting a Deployment or reducing replicas reclaims its no-longer-desired local
pods. This is the experimental Linux/root runtime, with a private OverlayFS
rootfs and loop-mounted ext4 data disk, not a Docker GC implementation. Private
network names use the complete pod identity, not a shared namespace/name prefix.
Address allocation does not reuse a currently recorded peer address.

## Reclamation order

1. Re-read and validate ownership/metadata before acting.
2. Identify the actual process using PID, Linux start ticks and boot ID. Open a
   pidfd and confirm identity before signalling it; a recycled PID is not killed.
   The namespace supervisor uses kill-child behavior so its workload descendants
   do not outlive its shutdown. Process identity remains available after a
   controller restart.
   A kernel with pidfd-open/signal support is required; cleanup fails closed
   rather than falling back to an unsafe numeric-PID kill when unavailable.
3. Unmount exact pod mounts deepest-first. No lazy detach and no recursive
   filesystem deletion underneath live mounts; cleanup errors remain visible and
   are retried on subsequent reconciliation.
4. Remove the recorded, validated pod network namespace and veth. The shared
   bridge and other pods/networks are preserved.
5. Retain `data.img` and ownership metadata under
   `~/.royak/retained-neuropod-data/<pod>/<unique-id>/`, then remove ephemeral pod
   state. Shared image cache is not removed.

Persistent disk retention is intentional, not a mounted runtime leak. There is
no automatic retention purge, destructive disk deletion or automatic reattach to
a newly created pod. Recovery/retention disposal is an explicit operator action;
recreating the same pod name creates a fresh data disk. Old unmarked pods require
operator inspection/migration rather than inferred adoption.

## Evidence and limits

`test-neuropod.sh` runs the real-process fixture only inside the owned Linux/root
qualification node. Unsupported platforms or missing prerequisites fail; they do
not pass via skips. The suite runner and current-evidence join reject recorded
skips even when the child command exits zero.

The fixture exercises real OCI pull without a Docker socket, working processes,
private mounts/network namespaces, scale-down/up, data readback from retained
ext4 disks, Deployment deletion after controller restart, same-name namespaces,
foreign/unowned/symlink preservation, stale-PID safety and repeated GC ticks.
Native tests additionally cover scope/generation/path validation and retention.

This does not qualify hostile-root workload containment, rootless/macOS
NeuroPod, full Kubernetes semantics, cross-host volumes, automatic disk recovery,
arbitrary crash points during initial provisioning or long-term retention policy.
NeuroPod still refuses unsupported securityContext and health-probe contracts.
Dead-but-still-desired pod state/data is preserved; this GC change does not add
an automatic data-destructive restart policy.
