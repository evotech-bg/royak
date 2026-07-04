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

Royak is in public beta and **not hardened for hostile multi-tenant environments**. In
particular: whoever can reach the API port can act with the RBAC role their token maps to;
cross-node service traffic through the mesh proxy is AES-256-GCM encrypted when a cluster secret is set (per-frame nonce, key from ROYAK_CLUSTER_SECRET or a per-host ~/.royak/cluster.secret). Without one it fails SAFE to plaintext with a warning — there is no shipped default key. This is a symmetric static-key scheme (no forward secrecy or rotation), not a WireGuard replacement; a routed encrypted L3 for raw pod-IP peering (WireGuard) is on the [roadmap](ROADMAP.md); and Royak requires
access to the Docker socket, which is root-equivalent on the host. Deploy accordingly.

## Supported versions

| Version | Supported |
|---|---|
| latest beta tag | ✅ |
| anything older | ❌ — upgrade first |
