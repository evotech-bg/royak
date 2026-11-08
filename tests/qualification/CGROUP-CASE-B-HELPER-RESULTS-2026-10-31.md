# Case B helper — bounded build/pure-test result, not kernel acceptance

## Native-v3 successor — 05:54 UTC

The iterator-lifetime fix is now compiled in a NEW exact standalone Linux
ARM64 helper. Original session92710 exits0. Full unfiltered Rust suite:9 direct
named successes,0failed/ignored/measured/filtered; the24 unchanged Python
cases also pass separately on3.14 and3.9. This is build/pure-test acceptance,
NOT execution of the helper kernel mode or proof that the VM failure is fixed.

Recipe `f2c3ebb5` /seal `c526ce2a` is an exact11-literal successor, with the
builder, owner, parser, comparator and both Python test files unchanged. Root
verified13 recipe members/76 support pins and the actual161-file source graph
`f9b7abbc`. Same normal release, locked Cargo inputs,6GiB RAM/6GiB combined,
3CPU and1800s original budget. Actual container execution was
05:53:44.480331564Z–05:54:27.045951763Z; no OOM, privileged mode, added device,
capability, port or profile override. The unused `began_ns` warning remains.

Actual helper725,016 bytes, ELF64 little-endian ARM64, SHA256
`eebc8eb720796a73560200201850cd47e3f1557f41ed3b9db549166e6686c725`.
Independent Rootfb140e joins29 actual operation receipts, raw test names,
source/build/ELF hashes, all-three cleanup preflights before nonforce deletion,
and a separate four-object name/fullID absence check. No retained build client.

Evidence under `.runs/rkq-storage-20261030/`:

- `root-case-b-native-v3-build-review-v1/review.json`:
  `70cbd7c1d6aca9c10aa52cc5d8d3bd7f3b80fbbe08fa2060feac2f124358f321`
- `root-case-b-native-v3-build-attempt1/report.json`:
  `d155822d690dec14cd659536f86c0e4e74661d9de16a9b08500c730eb5b4da2b`
- `rkq-case-b-native-v3-helper.build.log`:
  `b215156f69215cbff474fc0881345d84dd3557700ec2ac599edd99f36f7b6b6d`
- `root-case-b-native-v3-build-absence-attempt1/report.json`:
  `b545a475a700ca7f754572160e9e16d9bfa9ad5d42ae29ce95b583f0b80ab91c`

The first v2 VM attempt99823 remains retained/FAILED-UNKNOWN; no signal, retry,
recovery or VM cleanup was performed. Controlled exact-process cleanup approval
is pending. The entire storage/replication/backup/production goal remains OPEN.

## Historical native-v2 build — preserved

2026-10-31 05:10 UTC: the exact standalone Linux ARM64 qualification helper
build and its complete pure-test suite PASS. This is not yet the real Case B
test on the three VMs, and is not Royak server or stateful-production acceptance.

The sealed recipe `4caa2d22` uses the actual materialized161-file source graph
`9cf7b374`, with the155 cp9 files, Cargo manifest/lock and release profile
unchanged. Root verified12 recipe members/58 support pins and the five complete
literal substitutions from the reviewed normal builder. All24 Python source/
fake-handle cases pass separately on Python3.14 and3.9 with no omissions.

Actual original session77126 exits0. The compiler container ran from
05:09:27.442465595Z to05:10:10.621769463Z, with the unchanged1800s original
budget,3CPU,6GiB RAM/6GiB combined (no extra swap), rustc/cargo1.90.0,
aarch64-unknown-linux-musl, ordinary release flags and no environment profile
override. The raw log has one complete9-test summary:9 direct named successes,
0failed/ignored/measured/filtered and no inferred names. The exact `sh -ec`
overall0 proves both build and test commands succeeded; separate per-command
exit receipts were not recorded. The only compiler warning is unused
`began_ns`; it remains visible and was not suppressed. No helper main or kernel
mode was invoked by these pure tests.

Actual helper:725,016 bytes, ELF64 little-endian ARM64,
SHA256 `1e6693f0cac860979a0f4938cfae69d9cf5feb7d4011e771f52b89d46a49f167`.
This small helper is not evidence that the Royak server meets its10MiB gate.
Its complete encoded guest capsule still needs independent measurement/binding.

The one exact compiler container and two owned volumes were removed nonforce
only after all three owner/terminal preflights. A separate original-owned
read-only closeout verifies the exact container name/fullID and both volume
names absent. There are no retained build clients or UNKNOWN owners. Docker
Mounts order differed between snapshots; the previously approved unique-
Destination/full-row comparator verifies every field, without normalizing any
other array. Two manual read-only review assertions were corrected (raw Mounts
order and copied PATH components); both failures remain in the Root review and
did not rerun a build, alter limits or rewrite original evidence.

Exact evidence, under `.runs/rkq-storage-20261030/`:

- `root-case-b-native-v2-build-review-v1/review.json`:
  `2381d84e76a2cd6cbb86e7d244ca60a43019d8fb7181dbacfdf2d9c1670b0916`
- `root-case-b-native-v2-build-attempt1/report.json`:
  `5cc141d66e73536f988ee2a3ed6b9847a6553320e9ddc8ab2029d437a0f51c1e`
- `rkq-case-b-native-v2-helper.build.log`:
  `ab6dbfa25b8401b92ea99a4e304f1328edf2038d69d919b8dcc48d8a90d0b11f`
- `root-case-b-native-v2-build-absence-attempt1/report.json`:
  `47c7dc065e3f2e68e94e0480f1f7314af9e5d4419eb7001a606470693b4f3f78`

Real all-three-VM Case B, helper-to-Watch permission, OwnedMounted integration,
replication/fencing/PostgreSQL data, backup/fresh restore/control recovery,
8volumes/1GiB, normal server size and endurance remain OPEN. Original failures
and earlier results are preserved. No public demo, host routes/VPN or unrelated
VM/Docker resource was touched; nothing was committed or published.
