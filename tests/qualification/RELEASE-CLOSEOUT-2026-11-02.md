# Release-path closeout — 2026-11-02

Status: **BLOCKED, not a successful Linux release or production qualification.**

## This bounded correction

The hosted CI build now uses the lockfile, builds the release once per matrix
runner, verifies ELF/Mach-O format and runner architecture, preserves the
unchanged 10 MiB size limit, and checks the actual exit codes of both `brain`
and `demo`. Matching output followed by a crash is rejected. Smoke execution
uses a disposable working directory and does not inherit Royak state/log
configuration. Binary mutation during smoke is rejected.

A successful compilation's binary, SHA256 and smoke report are retained for
seven days through the pinned artifact action. A failed compilation cannot
upload an older binary from the build cache as the current release. A failed
smoke remains a failed job; an uploaded artifact alone does not authorize use.
The compiler profile, TLS, quorum and existing qualification thresholds have
not changed. This does not solve or waive the historical 6 GiB build failure.

Local checks actually executed: 13 release-verifier tests (including a real
child process printing the expected marker then exiting 9), 3 one-off-build
preflight-refusal tests, 6 checkout ownership tests, and 29 storage scope/
capacity guard tests: **51 passed, zero skipped**. Workflow YAML parsing,
hosted runner/artifact-guard inspection and `git diff --check` passed. These
are bounded tooling tests, not a fresh compilation or a full Royak e2e run.

## Current external blocker

Fresh GitHub API inspection of run 41485177342 on commit
8f8b50bd383fd374a6b11461f313c27cd4b244dc confirms the annotation:
"The job was not started because your account is locked due to a billing issue."
The latest code-quality job also has zero steps. PR 14 remains open and
mergeable, with failing checks. Repeating the same job cannot fix the account.
An organization billing administrator must resolve the lock with GitHub.

The earlier self-hosted queues remain cancelled; no runner-group permission
change, new local compiler, VM test, deployment, merge or release was performed
for this correction. The public demo and unrelated resources were untouched.

## Not closed by this correction

- Exact current Linux release compilation, size, smoke and full CI execution.
- The native storage experiment's adversarial Satellite TLS handshake stall.
- Historical long-run thread growth and a new qualified endurance result.
- Royak-integrated volume failure recovery and backup/restore qualification.

Keep the existing stateful-production gate and historical failures unchanged.
After billing is resolved, the normal hosted CI must actually execute; only
then can its compiler/test output determine the next release correction.
