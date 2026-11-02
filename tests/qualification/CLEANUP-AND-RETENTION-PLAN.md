# Owned test environment — cleanup and retention plan

Status: planned closeout, not permission for broad deletion and not a cleanup
PASS. All local/concurrent source changes and all historical failure evidence
remain preserved. The public demo, host VPN/routes and foreign resources are
out of scope. No commit, push or publication is authorized.

## Keep until the final dependent gates have closed

- Current and historical exact source snapshots, binaries, link maps, raw
  reports, execution receipts, source/fixture indexes and failure histories.
- Build artifacts that current qualification joins still reference. In
  particular, do not assume every file under `target` is disposable while a
  receipt depends on its original identity or content.
- Untracked implementation and test files: Git's untracked state does not make
  them temporary. Never use broad Git cleanup or repository reset.
- Retained UNKNOWN resources until the separate exact-run recovery decision
  is explicit. A later recovery record must not rewrite the original failure
  into a successful cleanup.

## Completed exact cleanup — 2026-11-01 14:50 UTC

Native81's separate temporary HOME was also removed by its original bounded
cleanup path only after real full1479/0 and strict-v4 success. Original inode
660445176, empty pre/post observations, two actual closes, fresh named absence,
empty fixtures and all six clients+driver absence are independently joined.
This does not authorize removal of native binaries/caches/history or any of
the other retained Docker/VM resources. [Native81 scope](.runs/rkq-storage-20261030/root-cold-prepared-close-corrected-runner-source-v1/RESULT.md).

The user separately approved the old diagnostic driver77052/start15:10:48,
exact exited rkq-build-813dae19 container and its target/cargo volumes. Fresh
identity/daemon/terminal-descriptor/volume/attachment checks preceded all
effects. One exact SIGTERM ended the parked driver; nonforce exact removals
and independent absence checks succeeded. All111 original diagnostic files,
including binary/map/logs/UNKNOWN, retain content and filesystem identities.
No current dependency cache, VM, source, demo, host network or foreign resource
was changed. [Separate recovery closeout](.runs/rkq-storage-20261030/root-source71-thin-map-diagnostic-source-v1/RECOVERY-RESULT.md).
The earlier read-only inventory below remains historical; its then-pending
recovery is resolved only for these exact resources, not a general cleanup.

A14:51UTC read-only qualification-label census still shows eight other exited
test containers (one prior build, seven backup fixtures) and two volumes for
that other build. This label/name listing is an inventory clue, not full-ID
ownership/dependency proof or removal authority. None was touched. These stay
separate from the completed exact813dae19 cleanup and require their own checks.

## Remove only after exact identity and ownership checks

For each resource, record its run, exact identity, expected state and dependent
evidence before acting. Check all prerequisites before the first removal.

1. Drain native clients, Connect sessions/sockets and workers; verify the real
   final drain and bounded cache, not just the test process's exit code.
2. Release exact test processes using PID, start time and arguments; handle
   stopped/changed processes without signalling a reused PID.
3. Remove only the confirmed test containers/volumes after proving no foreign
   attachment. Do not force-remove, use broad name prefixes or prune shared
   Docker state.
4. Inside the three owned VMs, close test storage/mounts and services and
   verify exact process/container/interface/fault-rule absence. Retain volumes
   required for recovery or evidence. Only then stop the three owned VM UUIDs.
   Do not wake stopped VMs merely to repeat a final check.
5. Remove exact owned test credentials and listeners once no test depends on
   them. Never publish raw keys or credentials in source/evidence summaries.
6. Recheck absence independently and retain the cleanup receipts. A missing
   or ambiguous observation is not zero and is not a cleanup PASS.

Owned VM UUIDs (not authority to operate on any other VM):

- `29cbe522-6829-412f-a480-ab52283a1158`
- `1752e81e-a541-4099-a054-842f71f3cc64`
- `12422c3b-1e89-444b-8faf-426d2da0b15e`

## Read-only inventory — 2026-11-01 approximately 13:56 UTC

This is a point-in-time observation, not a reusable destructive-action permit.

- `.runs`: 29,143,292 KiB; `target`: 27,450,712 KiB. Do not add these to a source
  commit. Both contain current qualification dependencies, not merely junk.
- Filesystem-reported available space: 160,765,384 KiB. This is the raw `df`
  view, not an APFS important-usage/purgeable-space estimate.
- The original diagnostic driver PID `77052`, start `2026-11-01 15:10:48`
  Europe/Sofia, still has its exact original arguments. It is retained after
  the capture failure; it is not an active compiler.
- Diagnostic container
  `1640e66bd8ae1acaae279a104bc6594beff09d021e3399aab5b5e7a19342d373`
  (`rkq-build-813dae19`) is exited, PID0, exit0, OOM false, finished
  `2026-11-01T13:18:07.180500278Z`. Its qualification label and two volume
  mounts match the exact run. Both volume attachment listings contain only
  this same exited container.
- Volumes `rkq-build-813dae19-target` and `rkq-build-813dae19-cargo` retain the
  same `royak.qualification=rkq-build-813dae19` label. Separate exact recovery
  approval is pending; no signal, container removal or volume removal occurred.
- Thirty tracked modified files and the untracked implementation/test files
  remain. No source cleanup, cache removal or VM action occurred in this check.

## Archive after final gates, not before

A reviewed retention manifest may later separate reproducible caches from
source/binaries/raw evidence. Archive with per-file content hashes and verify
restoration before removing an original archive candidate. A restored archive
does not recreate the old live inode identity; do not claim old identity-bound
receipts apply to the restored files. Keep negative runs and clear result
limitations. Do not silently delete evidence to make the workspace look clean.
