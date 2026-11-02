# Open-beta development checkpoint — 2026-11-02

This checkpoint publishes source, regression tests and qualification tooling.
It is not a production-readiness claim or permission to deploy the public demo.
Raw local runs, VM disks, credentials and build caches are excluded from Git.

## Latest actual native storage experiment

One approved experiment used three dedicated Linux ARM64 VMs on one Mac,
LINSTOR/DRBD over WireGuard, and PostgreSQL16.15. Three diskful replicas
synchronized;129 fsync-acknowledged raw records and the full540909568-byte
device hash matched on sequential writers. A simultaneous second Primary
was refused. PostgreSQL1000 rows on n1,100 additional rows on n2, and all1100
rows on n3 were verified with the same database system identifier.

Overall result: **FAILED**, not a full acceptance pass. After7 of19 certificate
negative checks, the Satellite2 no-client-certificate TLS probe timed out
during handshake. The subsequent180-second management phase did not run.
No TLS verification, quorum rule or timeout was relaxed. No automatic retry.
Exact root cause is not established. This native backend witness does not
prove the full Royak managed-volume/fault/backup/restore integration.

All three original workers exited; temporary resource includes and25 guest/
23 host credential files were removed. Independent final checks found no
active test processes, containers, DRBD resources or WireGuard interfaces.
Original configuration was archived; the approved usage-survey opt-out remains.
Old test volumes and raw failure evidence remain local, unchanged.

## Remaining release and qualification boundaries

- Stateful storage and backup/restore remain experimental and not qualified
  for automatic production failover or acknowledged-data durability.
- The previous two-hour networking soak completed7200.016s of traffic and
  52/53 checks; thread median growth8->18 exceeded the unchanged+8 gate.
  This is not relabelled as a successful endurance run.
- The latest recorded normal6GiB/fat-LTO release build failed for memory;
  a newer source candidate's native unit results are not a Linux release pass.
- Short native backend RSS growth is not a leak-free or whole-fit result.
- Three VMs on one Mac do not demonstrate physical-host HA.
- Current CI on this PR must be evaluated independently; historical test
  counts do not establish that this exact checkpoint passes all release gates.

Public-demo deployment is a separate step requiring an exact verified build,
backup of the current deployment, a smoke check and rollback. This checkpoint
does not create a release tag or perform deployment.
