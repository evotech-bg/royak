# Royak self-hosted runner smoke

`.github/workflows/self-hosted-smoke.yml` targets only these cumulative labels:
`self-hosted`, `macOS`, `ARM64`, `evotech-bg`.

This is **runner/syntax/small local-guard verification**, not compilation,
Linux integration tests or release qualification. Existing hosted CI remains
separate; a green smoke job does not replace its build/security checks.

- Trusted repository push to the named project branch/main, or manual dispatch
  on those same refs only. No pull_request/pull_request_target execution.
- Read-only GitHub token, no persisted checkout credentials, pinned checkout.
- Unique run/attempt checkout; cleanup only after exact path/marker validation.
- Existing Python>=3.11, Node and Cargo required; no tool installation.
- Python/shell/JS syntax, locked Cargo metadata,35 pure local ownership/capacity
  guards. No cargo compilation/test, Docker, Parallels, guest SSH or deployment.
- No actions/cache, target directory or growing build cache.

## Organization access prerequisite

The supplied runner97 is in group Default. Its observed settings are
All repositories / All workflows / public repositories disabled. Royak is
public. Enabling public access on this shared group without further restriction
would expose the host to more repositories than just Royak. Do not do this as
an implicit side effect. Prefer a separately approved Royak-only runner group
and trusted workflow allowlist, or an explicitly approved restriction of the
existing group's repository access. Changing Default can affect other projects.

Current API credentials cannot administer runner groups (403); browser access
showed the settings, but no permission change has been applied. GitHub also
reports an organization billing lock; the smoke run must be observed to learn
whether scheduling is available. Do not infer success from Idle or YAML alone.
