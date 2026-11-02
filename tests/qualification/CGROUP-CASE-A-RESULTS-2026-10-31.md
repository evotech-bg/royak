# Original cgroup controls — bounded Case A result

Status: **kernel DATA reviewed; full teardown/storage production NOT QUALIFIED**.

On 2026-10-31, Root executed one new empty-leaf test on each of the three owned,
user-confirmed dedicated Royak VMs. Fresh all-three ownership, original creation
receipts, current boot/pool/guards, idle service and cgroup admissions preceded
any guest mkdir. Public demo, host mounts/VPN/routes and unrelated resources
were not touched. No VM lifecycle or storage/mount/network/Watch action occurred.

The exact run is `.runs/rkq-storage-20261030/root-current-cgroup-case-a-attempt1`,
token `3952549f7074f76be233c4f9dabbe1c4`, report SHA256
`e3d3af52c82aa9d00552e80f1652ce54fd2dfd30dbc48690ad5b5e968b7f8bb3`.
Original tool61289 ended with exit0. Independent stdlib-only stored-data review
on Python3.14.6 and3.9.6 joined the exact source and raw receipts; both exited0.
Raw corpus SHA256 is
`65e8bc311e030ea4e066b31d6aa40a1adf6e7d0e399555ec170e2591fce42e64`.
Detailed local review: `.runs/rkq-storage-20261030/root-current-cgroup-case-a-review-v1/`.

## Observations

- All21 original host clients have complete stdout/stderr hashes, both PIPE EOF
  and actual parent wait receipts. Six initial service-query children also have
  exact receipts; Case A actions themselves created no child or thread.
- Each node created and removed one empty leaf, retaining nine independently
  opened original controls: cold, full-prefetched and prefix-prefetched triplets.
- All27 post-rmdir production reads returned actual ENODEV with zero bytes;
  all9 later ordinary prefix continuations did too. There are63 complete read
  records,43 positive control bytes per node and no recorded position-relation
  findings. The continuation is after pread, not an untouched-cache control.
- All39 retained roles (13/node) have once-only consumed close and immediate
  EBADF receipts. No retry, signal, stale-PID/FD adoption or force cleanup ran.
- The original dev32/inode5791 empty root and64PID/256MiB/1CPU policy remained
  unchanged. All VMs remained running in their admitted boots.

Four visible census samples per node recorded155/154/158 tasks and118/117/118
processes, with no sampled zombies. Per-task FD-directory entry sums were
1025→1026→1036→1036;1025→1026→1036→1036;1087→1088→1098→1098. The +1 and +10
fit the fixture's evidence FD then leaf+nine controls. This is not a leak or
unique-file count; the13 original-role closes are separate evidence. Kernel FD
counts remain typed N/A (92/91/91 tasks), never missing encoded as zero.
Diagnostic ancestor references remain visible in the records but are excluded
from the nonancestor-private-reference list. No foreign/nonancestor private
references were observed; hidden-namespace absence is not universally proved.

## Boundaries and next gates

The review joins returned outer raw DATA and the executed frozen source.
Guest `rmdir.actual.json`, per-syscall event files and close-journal disk contents
were not separately retrieved or durability-compared. Source180s/20s fences are
not an independently measured common-clock duration or hard cancellation proof.
No new guest census was run after SSH exit; client termination and the
child/thread-free source path are distinct from a fresh process census.

Case B remains mandatory: replacement-path refusal, populated-rmdir refusal,
one genuine original child/PIDFD and natural exit/EOF/reap/drain. This Case A
result cannot mint Docker teardown, native/Core, volume or storage authority.
Replication, PostgreSQL acknowledgements, fencing/failover, backup/restore,
endurance, eight volumes,1GiB,10MiB and physical-HA gates remain open. Three VMs
on one Mac are not independent physical failure domains or Kubernetes conformance.
