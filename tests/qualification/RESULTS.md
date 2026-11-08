# First real qualification slice — 2026-10-26

Status: **the explicitly scoped local fault contract passed; production
qualification remains open**. No Royak Rust source was changed by this slice.
Existing local modifications were preserved byte-for-byte in the tracked diff.

## Verification

- `cargo test --bin royak`: **191 passed, 0 failed**.
- Qualification checker/ledger/dataset tests: **16 passed, 0 failed**.
- Linux binary built from the current working sources in an isolated build.
- Complete real fault run: **11 checks passed**, 262.918 seconds, seed 42.
- Three independent Docker daemons on one physical host; an external process
  drove traffic through all three ingresses. No mocks in the fault run.
- Actual faults: workload container removal, leader process SIGKILL,
  control-plane partition, 45-second daemon/node outage and disk-preserving restart.
- The surviving daemons hosted all three application replicas before the
  stopped node returned. Final replica distribution: **0 / 1 / 2**, exactly 3.
- **559/559 acknowledged application writes** retained with exact values in the
  independent external ledger; **67 failed/ambiguous requests** were not hidden.
- **7 acknowledged control-plane ConfigMaps** converged with correct values on
  every node after the faults. This is not a linearizability proof.
- The isolated minority's API remained reachable, but its write returned 504
  (unknown outcome, not acknowledged). The majority continued writing.
- Exported **78 causal diagnostic dataset rows**. No model was trained or given
  control authority. CPU/memory values are missing, not synthetic zeros.
- All run-owned containers, volumes and the network were removed afterwards.

## Availability is a separate result

The client deliberately sent traffic to *every* ingress, including the failed
one; there was no external health-aware load balancer or automatic client retry.
The following are measurements of this contract, not a production SLO:

| Phase | Successful / attempted requests |
| --- | ---: |
| Healthy baseline | 68 / 68 |
| Pod deletion | 29 / 31 |
| Leader process SIGKILL | 22 / 48 |
| Control-plane partition | 68 / 68 |
| Node outage / restart | 63 / 99 |
| Recovery after node restart | 38 / 41 |
| Final 30-second observation | 60 / 60 |

Some failures occurred on surviving ingress endpoints too; see **QF-002** in
[FINDINGS.md](FINDINGS.md). Data retention and self-healing are promising, but
zero-downtime behavior has not been demonstrated.

## Open regression and non-claims

The default HTTP probe run failed on a healthy IPv4-only application (**QF-001**).
The complete fault run used explicit `--probe-mode exec-ipv4`; this is a recorded
workaround, not a fix or waiver of the HTTP probe issue. The manual CI workflow
retains the default HTTP check and independently runs the workaround matrix;
it has been added locally but has not been run on GitHub in this turn.

Not established: cross-host behavior, distributed volume durability, full
security qualification, crash/backup/restore of the entire cluster, disk-full
behavior, capacity limits, long-duration soak, or ML predictive value. The ledger
is external to Royak; these checks do not prove Royak volume durability.

## Exact evidence

Ignored local bundle: `tests/qualification/.runs/rkq-20261026-194141-c1eaef/`.
Keep it when sharing this result; it is deliberately not committed with source.

- HEAD: `95b42449be71797c82dcefbf265d0c83c0252e27` plus existing dirty sources.
- Original and final tracked-diff SHA-256:
  `f7026e07af66d779aae8676eae8e96153833e7c36a181fc429ffc127aeb2fc47`.
- Linux binary SHA-256:
  `12aedd5541242acdb0bf2fa199c9a117d6c69cf04ad2cd8ab2629d28efb439fb`.
- `report.json` SHA-256:
  `39e9119dc265b8fb40ca5ad3ae746d83972d6ff6608cbfa529e7edfab3240727`.

Manifest, operation/fault histories, per-phase latency measurements, bounded
redacted logs, oracle snapshot and dataset are all in that bundle. Earlier failed
or interrupted attempts are retained separately, including the HTTP regression.
