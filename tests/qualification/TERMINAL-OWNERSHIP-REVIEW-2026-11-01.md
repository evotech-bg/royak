# Terminal ownership review — Source61, not runtime qualification

This review concerns the immutable, unpromoted Source61 capture, not a
successful current binary or a measured explanation of the older soak's
thread growth. Source61's full native compilation actually failed with E0275
at the real work-queue sender's Send/Sync proof. Its source index is
`5fff02ddbd4cb4c8da88cf8f1e79fe93d844dc8e5adb550fc0c90a419d4cba23`;
the actual raw compiler log remains
`6c8e1e06bc0bb3fe7baed6c9756bc6f94d31376984aefefb2ec9e5ccc03a36f4`.

Root and two independent source reviewers confirmed concrete strong-reference
cycles, not merely a hypothesis about the compiler:

| Stored forward reference | Stored return reference |
| --- | --- |
| `PreparedTerminalPlan.round → RegisteredDrainRound` | `RegisteredDrainRound.plan → PreparedTerminalPlan` |
| `ManagedPodOperation.containers → OwnedManagedContainer` | `OwnedManagedContainer.operation → ManagedPodOperation` |
| `ManagedPodOperation.terminal_plan → PreparedTerminalPlan` | `PreparedTerminalPlan.operation → ManagedPodOperation` |
| `RegisteredDrainRound.metadata → PreparedTerminalMetadata` | `PreparedTerminalMetadata.round → RegisteredDrainRound` |

The diagnostic also exposes this longer cycle:

`ClosedDescriptor.permission → VerifiedTerminalEffect.request.round →
RegisteredDrainRound.plan.operation → ManagedPodOperation.containers →
OwnedManagedContainer.process → OriginalProcessPin.namespace_close →
ClosedDescriptor`.

These are actual Arc/value fields. `CloseState::Closed` does not remove the
stored permission. The successful legacy terminal tail in
`native_runtime_terminal.rs:744` changes `retired`, controller mode and
`consumer.pending=None`; it does not sever the table's references. The managed
launch tail at `native_runtime_consumer.rs:800` explicitly retains
history/CIDs/FDs/leases. No successful-retirement `take/clear/remove` for these
specific backedges was found in the reviewed terminal/process/consumer/commit
sources. A retired flag does not by itself make a strong cycle reclaimable.

This is **not** evidence of unbounded observed runtime growth. The current
book is intentionally statically rooted and rejects a full 128-operation
history; admission bounds and the existing policy of retaining UNKNOWN owners
must not be silently removed. Exact live heap/FD cost, useful lifetime and
successful-terminal reclamation remain to be measured and designed. Changing
an Arc to Weak alone also does not cut the compiler's auto-trait traversal,
and could weaken genuine-owner/UNKNOWN lifetime semantics.

## Separate successor being implemented

The first narrow change removes the descriptor's full live-permission
backedge. A private finite shared cell retains the actual original
CoreObservation, one-use state and immutable original request facts. It is
created only by the existing real permission producer. The descriptor roots
that SAME cell, not a new grant, decoded receipt, copied spent Boolean or
opaque live-owner facade. The original non-Clone live permission remains
owned across prepare, rooting, physical close and result recording, and is
borrowed for both operations. Exact cell identity is required before consume.

All original current-round/Core/resource/deadline and one-use checks, the
root-before-consume order, sole close call, raw close-state-before-evidence
order and error/UNKNOWN behavior must remain. Actual request/Core history is
retained as finite data, not authority and not the whole mutable owner graph.
There is a new per-permission Arc allocation and any immutable-fact copy cost;
no budget-fit, compile-depth, resource-reclamation or leak-free claim follows.
The other cycles above stay separate findings. No successful-known owner or
UNKNOWN evidence is discarded to make a check pass.

Acceptance still requires unchanged old regression bodies, the full actual
native inventory/execution at the existing compiler limit, Linux/frontend and
normal-release/size/resource gates, real three-VM storage/replication/restore
fault tests, and exact-build endurance with genuine resource/idle attribution.
The stage is not permission to enable an incomplete physical pipeline. Full
Royak Storage v1 and stateful production remain NOT QUALIFIED.

## Exact reviewed Source61 leaves

- `native_runtime_terminal.rs`: `9a0c8db60dacd84c86218d3592136df07e7e51e414c101aee0ad95b9dcebed5a`
- `native_terminal_process.rs`: `aadae0802149009229579c938fa039dd3fdded639bae03efa8990565eab3ffbb`
- `native_terminal_commit.rs`: `7ea8fe4930ae7c64e78ecbd92944d8c5fad85d0d3a6ce06c7230a1fb41c45a86`
- `native_runtime_consumer.rs`: `b57a5ca4e962c8163bce66b28631f305722379559d53c05192ca637d28481aff`

The original source, raw failure, retained owned HOME and prior successes and
failures are preserved. No VM, Docker, demo, host network, compiler-limit,
runtime resource or TLS change is part of this static review.
