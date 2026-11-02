# NeuroPod GC and zero-skip local qualification — 2026-10-27

Status: **PASS — all 15 Linux integration suites passed with zero skips**,
including NeuroPod 26/26 in three complete runs. Both strict current-source
acceptance joins are green, including the fresh fault/300s-observation/browser
run. This is bounded local qualification, not production certification.

## Exact version

- Normal Linux release: `.runs/linux-royak-neuropod-gc-accepted`
- Linux SHA-256: `726eb0870656be51776da401324da8ef9adc83370c81b8f628bb86cf6e9d2124`
- Native laptop client SHA-256: `5bf5fee0229062974f267f977c3d4eb38501dded8118a5fba5229758ed41a91a`
- Adjacent `.build.json`: normal release, no diagnostic-symbol flags, all
  embedded source hashes recorded and unchanged during compilation. These are
  preserved working-tree sources, not a new release/tag or a pushed commit.

## What changed

The former skip is replaced with a mandatory real-runtime fixture, not a weaker
directory-only assertion. New Deployment-managed NeuroPods durably record
cluster/node/state-file/namespace/Deployment/generation ownership, network state,
and PID/start-ticks/boot-ID process identity. Deletion and scale-down stop the
owned namespace supervisor/descendants, unmount exact pod resources, remove its
validated netns/veth, retain the data disk and remove ephemeral pod state. PID
reuse cannot redirect GC onto an unrelated process. Unknown/legacy/foreign or
symlinked records are not adopted. New disks and control metadata are private.

The actual Linux test exposed an older startup defect hidden by the directory
smoke check: Alpine exited because `/dev/null` was absent. Managed private
rootfs startup now provides minimal devices. The test requires live processes
and real descendants before accepting startup. Namespace-similar network names
are derived from full pod identities, and free-address allocation handles holes
after GC without colliding with a surviving peer on scale-up.

`data.img` is retained under `~/.royak/retained-neuropod-data/<pod>/<unique-id>/`
with ownership metadata. The test remounts the retained ext4 disk read-only and
reads the actual application-written marker. Loop detachment is checked using
the existing retained file, not a vacuously missing old path. Shared image cache,
the other namespace and an unrelated live process remain untouched.

The runner and current-evidence join now reject recorded skips even if the child
exits zero. Unsupported NeuroPod test environments fail explicitly. The CI
NeuroPod job uses the same owned Linux/musl suite instead of a rootless smoke
test that could pass by skipping. CI YAML syntax was checked locally; no hosted
CI execution, commit, push, public-demo or host VPN change was performed.

## Actual verification

| Check | Result |
| --- | --- |
| Real NeuroPod GC/lifecycle | 26/26, three current-source runs; zero skips |
| All Linux integration suites | 15/15; zero skips and no cleanup errors |
| Connect, real kernel WireGuard across distinct daemons | 54/54, three complete runs |
| Actual lifecycle/topology/RBAC regression | 53/53 |
| Native Rust | 248 passed, three runs; zero failed/ignored |
| Linux Rust in separate owned container | 248 passed; zero failed/ignored |
| Python qualification infrastructure | 31 passed; zero skips |
| Current fault/300s observation/live browser | 13/13; zero skipped checks |

Compiler warnings inherited from earlier code remain; this is not a warning-free
or full-lint claim. Test counts overlap (for example lifecycle is one integration
suite); they must not be added together as distinct product capabilities.

### Evidence bundles

- NeuroPod runs: `rkq-suites-20261027-231414-ae4770`,
  `rkq-suites-20261027-231739-678277`, `rkq-suites-20261027-231804-66428f`.
- Full integration union: the first bundle above (11 suites), plus
  `rkq-suites-20261027-231534-ad7194` (4 suites). Both parents passed. Every
  required entrypoint has current source/fixture/binary evidence and no skips.
- Connect: `rkq-20261027-231535-10099b`, `rkq-20261027-231642-95b42f`,
  `rkq-20261027-231804-7216aa` (latest three matching attempts, all passed).
- Linux Rust: `rkq-unit-20261027-231649-5a0c34/unit-report.json` and its full
  `cargo-test.log`; source hashes remained unchanged during the run.
- New fault/UI bundle: `rkq-20261027-232027-2ce5f4`, 13/13 passed in 530.316s.
- Strict `.runs/current-connect-acceptance.json` and
  `.runs/current-coverage.json`: both PASS. All selected suite `skip_lines`
  arrays are empty. Older greens do not replace current-source evidence.

The fault run retained **2152/2152 acknowledged application writes** with exact
values in the external SQLite ledger. **99 failed/ambiguous requests** remain
recorded; the final 300-second observation was **1367/1367** successful requests.
Seven acknowledged control writes converged on all three nodes. This is not
distributed Royak volume durability, a saturation benchmark or zero downtime.

Actual headless desktop/mobile browser checks passed for the recovered cluster,
including same-origin GET-only interactions, memory-only token, selection/search,
scope handling, focus through two real polls and no script errors. Captures were
also inspected and remain in the run evidence; existing design-review assets
were not overwritten. Final labelled-resource inventories contain no remaining
qualification containers, volumes or networks, and no cleanup errors were found.

The failed process-start investigations remain in
`rkq-suites-20261027-230001-cb5c66` and `rkq-suites-20261027-230134-e1901c`.
The intermediate 25-check pass is retained as historical evidence only, not
substituted for the final three 26-check runs.

## Acceptance boundary and data safety

See [NEUROPOD-GC-CONTRACT.md](NEUROPOD-GC-CONTRACT.md) for the precise contract.
Docker provides the disposable Linux test environment; NeuroPod itself uses an
invalid Docker socket, real OCI pull, processes, OverlayFS, ext4 loop mounts and
Linux network namespaces. This is not a mock process or a Docker workload passed
off as NeuroPod.

GC is qualified for newly explicitly managed Deployment pods. Old unmarked or
directly-created unmanaged pods are preserved for operator inspection/migration,
not guessed from names. Retention is not automatic restore or a destructive
purge policy; recreating a pod uses fresh data unless an operator explicitly
recovers it. Dead-but-still-desired pod data is preserved, not reset by this GC.

NeuroPod remains experimental and does not gain hostile-root containment,
rootless/macOS runtime qualification, unsupported health/security contracts,
full Kubernetes semantics, distributed volumes, long soak, power-loss/disaster
recovery certification or cross-host failure-domain proof. Current fault tests
still share one physical host. Existing local changes and review assets remain
preserved; only exact labelled test resources are reclaimed by the harness.
