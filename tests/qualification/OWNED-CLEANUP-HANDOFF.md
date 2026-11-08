# Owned cleanup and diagnostic handoff

This is a qualification-harness boundary, not a production networking pass or
a storage/fencing capability. All existing failed reports and raw snapshots
remain immutable. The complete Storage v1, replication, writer/fencing,
PostgreSQL, backup/recovery and endurance goal remains required.

## Observed problem

Actual observer attempt5 completed all three retained Watch/SSH owners and the
first node's two exact cleanup effects. Its owned cleanup was verified, but
strict full network equality was false: the guests acquired the two observed
ULA/SLAAC prefix/local-route pairs. The host raised a qualification assertion
after node1 and therefore needed a separate exact recovery for node2/node3.
All three were subsequently independently raw-reviewed and stopped; closeout
SHA256 `f5e78ca55c91ff96a5a74f9df94823a4623e2d67ac99d3d1ff67d7fbdc194061`.

The pinned classifier already distinguishes these results. Its successful
`postdelete` return proves exact prior Docker descriptors/interfaces, no owned
WG, independently idle runtime state, unchanged unrelated IPv4/NFT structure,
monotonic typed counters, and only narrowly typed RA/SLAAC additions/countdowns.
It explicitly does **not** prove RA packet origin or full network equality.
The original full comparator also includes route expiry values. An extra IPv6
startup wait cannot guarantee identical expiry values across a longer test.

## Required separation

1. Continue final evidence collection and known owned cleanup only after each
   actual command is terminal and each unchanged classifier returns
   `owned_cleanup_verified=true`. A strict-network false result remains a
   qualification finding; it is not itself a lost process owner.
2. Any unknown child/owner, nonzero command, missing/corrupt evidence, classifier
   error, foreign/unrelated change, or owned-cleanup false still stops further
   effects. No signal, retry, adoption or automatic cleanup may turn UNKNOWN
   into a known result.
3. Require all three original Watch/SSH Finish/reap receipts, final independent
   kernel/process/cgroup census and exact owned VM closeout. Confirm actual
   stopped UUID/Home/device/inode identities. Stopped status alone is not the
   proof that earlier processes/resources were drained.
4. Report `FAILED`, `qualification_passed=false` and exit1 when strict network
   equality is false. A separate `cleanup_completed=true` may describe proven
   resource closure. Do not set the old `completed`/PASS fields from cleanup.
5. A new immutable Root review has scope `OWNERSHIP_QUIESCENCE_ONLY`. It binds
   exact source/run/observer/boot and every literal input hash, replays all
   three actual raw histories, lists the actual route/counter differences and
   preserves the original failed disposition. No generic ignore/allow flag or
   unverified summary substitutes for those joins.
6. A later storage diagnostic may consume that closed ownership proof only
   with independent fresh boot/Core admission and exact existing pool history.
   Both host and each guest/newboot helper must replay their applicable raw
   evidence and review hashes under the unchanged budgets. This is not a lease,
   grant, reconstructed dispatcher owner, mount receipt or writer fence.

## Temporary inspect copies

The successful fixed inspect copies from attempt5 remain at the old target;
the next installer correctly requires a NEW O_EXCL destination. They must not
be reused or silently overwritten. A separate explicit Root operation may
archive only the exact completed copies, after all-three current ownership,
receipt/inode/hash/mode and no-opener admissions. Preserve the binaries and
original receipts; use same-filesystem fd-anchored `renameat2(NOREPLACE)`, no
copy/unlink/overwrite fallback. Any partial/unknown result remains held and
cannot be retried or adopted. This helper creates no replacement or authority.

New source packages implementing this contract require independent full
review, negative/source tests and actual qualification. This document does not
claim that implementation or the final Storage v1 acceptance is complete.
