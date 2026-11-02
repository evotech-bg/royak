# Normal N2 footprint — exact map, size gate still FAILED

The normal ARM64 server is17,111,384bytes (16.3187MiB), above the unchanged
10,485,760-byte gate by6,625,624. The ordinary release build is retained; no
profile, feature, panic policy, compression, splitting or threshold change was
used to turn that result green. Full Storage v1 remains NOT QUALIFIED.

## Actual diagnostic and its boundary

A separate same-source release build adds only diagnostic linker-map output
and bounded map validation/copy. Original77965 exits0; raw compile4m17s.
Both full binary SHA256 and all section records match the true ordinary build:
`6d73c112a881e2de42ab1023ab0c9e625e45f9ec39ec8714aae4253d57ba82fb`.
Thus this map describes the actual current17,111,384-byte artifact, not a
different debug build. It remains DIAGNOSTIC_NOT_QUALIFICATION.

Map10,860,925bytes, SHA256
`e47eaa10282014998cfabde344a50bb5fbcbf4574e057805b39bb65cd88a1650`.
Root independently joins28 original operation receipts, source159/live140 and
the342 unit evidence files, exact source/owned mounts, actual3CPU/6GiB RAM+
6GiB combined/noOOM and known-terminal nonforce cleanup. Six fresh read-only
identity/ID/name/volume queries with complete original EOF/wait/raw receipts
confirm all new diagnostic Docker resources gone. Actual retained diagnostics
including report total28,310,769bytes, below200MiB; no truncation or cleanup of
old evidence. Nine support cases pass on each Python3.14/3.9, not product tests.

## What the map actually establishes

The entire14,040,432-byte text extent is accounted without overlap:
15,457 input sections total14,039,004bytes plus1,428 explicit fill bytes.
No unaccounted text bytes remain. There are no debug sections in the baseline.

The largest single linked input section is103,008bytes (CLI subcommand
construction). Several other large sections are ordinary Core/API/state and
typed protocol code. Grouped normalized legacy names show many different
generic instantiations, not a single recoverable concrete type or one function.

| Literal-name filter | Linked input-section bytes |
| --- | ---: |
| Names containing serde | 2,915,836 |
| Names containing Hyper | 170,060 |
| Names containing OpenRaft | 438,584 |
| Names containing Royak | 6,296,304 |

These filters overlap and MUST NOT be summed. They are not exclusive crate
ownership, inlined-source attribution, CPU hotness or a promise of removable
bytes. In particular, a small direct Hyper-name total does not bound all
transport code inlined into callers. This evidence supports targeted experiments,
not an unmeasured TLS/serialization redesign or a six-megabyte saving claim.

## Next implementation/acceptance decision

Source audits identified narrowly scoped experiments: exact typed enrollment
history checks instead of whole-identity JSON reflection, existing admission
parser reuse, and measurement-gated codec/HTTP instantiation sharing. None is
adopted or counted as a saving. A changed candidate must preserve strict raw
parsing/guard order, wire/hash formats, TLS/upgrades, ownership and resource
semantics, then pass full suites and a new ordinary release measurement.
The prior zero-saving supervisor experiment remains NOT_ADOPTED.

The10MiB gate is still FAILED. If preserving full functionality requires a
broader architecture or a different product budget, that requires an explicit
decision; it is not a silent acceptance change. Actual storage replication,
fencing, PG durability, all backup modes/fresh restore/control recovery and
endurance remain separate full-goal requirements. Old VM stop approval is
still pending; no VM was operated in this diagnostic.

- [Exact Root closeout](.runs/rkq-storage-20261030/root-normal-n2-linkmap-review-v1/review.json).
- [Reproducible text accounting](.runs/rkq-storage-20261030/root-normal-n2-linkmap-review-v1/attribution.json).
- [Managed backup runtime gaps](BACKUP-RUNTIME-GAPS-2026-10-31.md).

Method references: [Cargo final-target arguments](https://doc.rust-lang.org/cargo/commands/cargo-rustc.html),
[rustc linker argument](https://doc.rust-lang.org/rustc/codegen-options/index.html#link-arg),
[GNU linker-map output](https://sourceware.org/binutils/docs/ld/Options.html).
