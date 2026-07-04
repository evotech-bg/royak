# Contributing to Royak

Thanks for considering it. Royak is a beta with a small, honest surface — contributions
that keep it honest are the most valuable kind.

## Ground rules

1. **Tests are the contract.** If you change behaviour, change or add the test that proves
   it. `cargo test --bin royak` must pass; the integration suites (`test-demo.sh` etc.)
   must pass on Linux. CI runs all of them.
2. **The ledger stays true.** If your change makes a ❌ row in
   [COMPATIBILITY.md](COMPATIBILITY.md) work — flip the row *in the same PR*, with the
   verification you ran. If you find a row that overstates reality, that's a bug report
   we want most of all.
3. **One binary, small dependency budget.** New crates need a reason. The release binary
   should stay in single-digit megabytes.
4. **No silent scope changes.** Features come with a ROADMAP.md entry or an issue first,
   so intent is public and reviewable.

## Getting started

```bash
git clone https://github.com/evotech-bg/royak
cd royak
cargo build --release
cargo test --bin royak      # unit tests, no Docker needed
./test-demo.sh              # integration suite (needs Docker; Linux or macOS)
```

Note: `test-mesh.sh` and `test-ingress.sh` need Linux (host-routable container IPs) —
CI covers them on Ubuntu if you're on a Mac.

## Good first contributions

Anything in the [Known limits table](ROADMAP.md#known-limits), or any ❌ row in the
compatibility ledger. Open an issue describing the scenario you want to make work,
success criteria you'd measure, and whether you can help test — then go for it.
