# Security Policy

Royak is a container orchestrator — it talks to your Docker socket, holds encrypted secrets,
and issues mTLS certificates. Security reports get priority over everything else.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately via [GitHub Security Advisories](https://github.com/evotech-bg/royak/security/advisories/new)
("Report a vulnerability" on the repo's Security tab).

Include what you can: affected version/commit, reproduction steps, impact assessment.
You'll get an acknowledgement within a few days. Fixes for confirmed issues in supported
versions ship as fast as we can build and test them, and reporters are credited in the
release notes unless they prefer otherwise.

## Scope notes for beta

Royak is in public beta and **not hardened for hostile multi-tenant environments**. What the
current trust model is — and is not:

- **API access needs a bearer token.** Identity comes only from a verified token (`ROYAK_TOKEN`,
  the `ROYAK_TOKEN_FILE` table, or the generated `~/.royak/admin.token`, mode 0600); RBAC is
  deny-by-default. `ROYAK_AUTH=insecure-dev` turns authentication off and must never be exposed.
  Tokens are static: there is no expiry, rotation or revocation other than editing the token
  table and restarting. Use `--tls` whenever the API leaves the host (the default certificate is
  self-signed; kubectl gets its CA through the generated kubeconfig).
- **Nodes trust each other through one shared secret.** Every inter-node request and response is
  HMAC-SHA256-signed with `ROYAK_CLUSTER_SECRET` (≥32 chars, same on every node), time-bounded
  (±30 s) and replay-checked. Anyone holding the secret is a node. Every node-RPC body (census,
  pod logs, pod launch plans, Raft messages) is also sealed with AES-256-GCM under a key derived
  from the same secret, so it stays confidential with or without `--tls`. Node RPC over `--tls`
  does NOT verify the peer's self-signed certificate: identity comes from the HMAC and
  confidentiality from the sealing; HTTP headers (paths, node names, timing) are not hidden.
- **Mesh traffic between nodes** is AES-256-GCM encrypted with a key derived from the cluster
  secret; in cluster mode a node accepts only sealed peer connections. It is a symmetric
  static-key scheme (no forward secrecy or rotation) and a captured sealed frame can be replayed;
  a routed encrypted L3 (WireGuard) is on the [roadmap](ROADMAP.md).
- **Per-pod identities are issued, not enforced.** Pods get a CA-signed certificate and token,
  but no live path verifies them yet.
- Royak requires access to the Docker socket, which is root-equivalent on the host. Deploy
  accordingly.

## Supported versions

| Version | Supported |
|---|---|
| latest beta tag | ✅ |
| anything older | ❌ — upgrade first |
