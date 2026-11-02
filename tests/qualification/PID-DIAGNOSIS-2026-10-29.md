# Focused PID-growth diagnosis — 2026-10-29

## Latest portable runtime follow-up

The earlier Alpine-only fix exposed a separate real Dash issue: its kill
builtin rejects the old `--` separator for negative process-group operands, so
the requested one-second deadline returned success after 3.131 seconds. Evidence
is retained in `.runs/watchdog-dash-preportable-failure.json`. The portable
watchdog removes that separator and immediately kills/reaps its owned timer
child on cancellation, closing the trap-before-wait race too.

Current watchdog SHA256 is
`d8c229778691b5d82e866e8f73073d81450a38b38b4d4d89238fb6edbed91c66`.
`.runs/watchdog-portable-20261029.json` passes all four real BusyBox/Dash ×
init/no-init cases: 320 fast commands, correct hard deadlines, no late writes,
and unchanged zero-zombie process baselines. Both no-init cases remain 1→1;
init cases remain 2→2. The real VM primitive repeat
`rkq-pid-20261029-132229-dd2887` passes all 12 scenarios on VM 2/3 with frozen
sources and exact container cleanup. A separate direct Ubuntu/Dash check passes
40 successes, 40 failures and three timeouts (fast max 0.205 s, timeout max
1.141 s). These are component proofs, not full Debian-cluster certification.

The exact new artifact now passes all short local/three-VM gates; the replacement
long soak `rkq-soak-20261029-134929-6648c9` is running and not accepted yet.
All intermediate diagnosis/remediation results below remain historical evidence.

## Authorized remediation follow-up

The later frozen-source regression
`.runs/rkq-pid-20261029-123417-41a3f4/report.json` passes all **12 scenarios on
each of VM 2/3**, with unchanged source/fixtures and no cleanup errors. Successful
and failed watchdog commands (40 each per VM) leave **zero zombies/task gain
without init**, proving the timer cleanup itself is fixed rather than masked.
The shipped init path also leaves zero zombies/task gain after successful,
timed-out, nested-child, background-child and concurrent isolated probes.
No late write occurs; the application remains healthy. The no-init hard-timeout
negative control still produces six zombies after three kills on each VM:
arbitrary hard-killed grandchildren require a reaper, not a shell promise.

Royak now requests Docker init only for configured probe containers, fails
probe execution without it, versions their template to roll old containers,
and uses signed v3 remote launch plans without fallback to old workers.
Unprobed containers retain their PID-1 contract. The new resource contract
measures actual process state/tasks and the authoritative Raft directory.
**Actual Royak API integration and fresh endurance are still separate pending
gates.** This component regression does not qualify the previous long soak.

The first post-fix trial (`rkq-pid-20261029-122846-77ade7`) is retained as
**unaccepted** because a sampler source edit occurred during execution, despite
clean behavioral results. It is not substituted for the frozen-source repeat.
Both runs restored the two owned VMs to stopped and left old `/lab` pointers
unchanged; VM 1 was not started by these component tests.

## Historical original-watchdog diagnosis

**Confirmed component failure: the original Royak probe watchdog can leave
zombie descendants under a workload PID 1 that does not reap orphaned children.**
At this original diagnosis no product fix or new endurance pass was claimed. The prior long-soak acceptance
remains **NOT QUALIFIED** pending remediation and fresh affected qualification.

## Exact evidence and scope

Run: `.runs/rkq-pid-20261029-101807-31de5e/report.json`, with full per-node
process/task censuses in `node-2.json` and `node-3.json`. Seven comparisons were
executed on each of two actual owned Ubuntu ARM64 VMs, with distinct boot IDs,
kernel `6.8.0-147-generic` and the same Python image:
`sha256:8bcfa47b04b853a17aaf909362b847b2112fd6ec4105ea553ef9a43bafbb5916`.

The workload is the same HTTP fixture with the soak's HTTP/1.1 setting. Each
case starts a fresh container at 64 MiB / 250m, UID/GID restrictions inherited
from the image/run configuration, read-only root, dropped capabilities,
no-new-privileges and **network none**. HTTP control traffic stays on that
container's loopback. There is no LB, Connect tunnel or public target in this
focused experiment. The third VM was never started.

The watchdog's bytes are unchanged and hash to
`d78b61ceb7dbe3d15a97520ae9a3795d472d5d16fff6ac7c30027f9e7ca24f5f`,
the same source hash embedded in the original normal Linux build used for the
soak. The probe variants replay `src/docker.rs::probe_exec`'s exact Docker API
create / detached start / inspect-poll sequence, 1-second watchdog and 3-second
completion deadline. **The Royak binary/controller itself is not run by this
diagnostic**; this is component-level causal evidence, not a full integration
requalification. Source/fixture hashes stayed unchanged during the run.

## Results

Numbers are additional zombies after completion and a two-second drain, with
the census process excluded. Docker PIDs independently matches the process
census in the final snapshots.

| Case | Work per VM | VM 2 | VM 3 |
| --- | --- | ---: | ---: |
| Idle application | 3 seconds | 0 | 0 |
| Direct HTTP/1.1 persistent + connection-churn traffic | 200 valid health responses | 0 | 0 |
| Plain foreground Docker exec | 40 × `true` | 0 | 0 |
| Plain detached Docker exec API | 40 × `true` | 0 | 0 |
| Original watchdog, successful command | 40 × `true`, all exit 0 | **20** | **23** |
| Original watchdog, timed-out command | 3 × `sleep 3`, all exit 137 | **6** | **6** |
| Original watchdog with diagnostic `--init` control | 40 × `true`, all exit 0 | 0 | 0 |

Successful watchdog cases grew from **1 → 21** and **1 → 24** Docker PIDs.
Every leftover is a single-thread `sh` or `sleep` process in Linux **Z state**,
adopted by **PPID 1**. Timeout cases grew **1 → 7** on both VMs. Application
PID 1 stayed alive and no OOM occurred. The init controls stayed **2 → 2**.

This rules out ordinary application traffic and bare detached Docker exec as
sufficient causes in this controlled fixture. The variable success-path count
is consistent with a cleanup race. The source cancels a process group while
using shell/timer descendants; the observed failure is that not all completed
descendants are reaped before they become the application's responsibility.
The exact scheduling of each shell/sleep descendant is not traced here.

`--init` is a diagnostic control that reaps adopted children, **not an applied
product fix**. The required correction should make probe supervision/cleanup
robust without assuming every workload supplies a child reaper, and must keep
the existing process-group isolation and timeouts. Clamping PIDs or reducing
probe frequency is not demonstrated remediation.

This establishes a mechanism capable of explaining the soak's growth. It does
not retrospectively identify the state of all 530 tasks in the deleted soak
container or exclude every other long-run leak. A fixed full integration and
endurance run are still required.

## Raft telemetry follow-up

Read-only inspection of the retained old `/lab` state found
`/lab/state.json.raft` at **325159 apparent bytes** on each inspected VM (2/3).
The old `/lab` link was unchanged by this diagnostic. This confirms the actual
directory to instrument; a post-run size does **not** recover the missing soak
time series or close SOAK-002. No state files were modified or removed.

## Cleanup and next gate

Both node experiments completed, with no diagnostic cleanup errors. All exact,
label-verified diagnostic containers were removed. VM 2/3 returned to their
original stopped state; live Parallels checks also confirmed untouched VM 1 is
stopped. No cluster service, `/lab` pointer, host route/VPN, public demo or
product source was changed. Small diagnostic copies/evidence remain retained.

The next gate requested at this checkpoint was authorized implementation,
successful/failed no-init cleanup regressions, explicit reaping for hard-killed
descendants, repaired Raft/PID gates, actual Royak probe integration and affected
e2e before a new long soak. The later component follow-up above does not convert
the original failed evidence into a product PASS.
