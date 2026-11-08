# Royak

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Confirmed by the user: beta cluster operators and DevOps students. Operators
need to understand actual resources, placement, routing and failures; students
need to see how reconciliation and container orchestration work.

## Product Purpose

Royak is a lightweight Rust container orchestrator with Kubernetes-shaped API
support. The user requests an interactive live cluster map and continued local
beta hardening. The map's first version is read-only diagnostics with search,
filters and details, not destructive cluster controls.

## Operating Context

An existing web dashboard is embedded in the Rust binary. The current work is
local; the public demo and external hosts must not be modified. Existing local
changes must be preserved. Cluster data is protected by the existing token/RBAC
gate. Mesh and port-forward exist; broader VPN/public relay functionality is
under discussion and is not authorized for public activation.

## Capabilities and Constraints

Preserve the existing dashboard and API contracts. Distinguish desired,
observed, stale, missing and unauthorized data. A missing permission must not
look like an empty healthy cluster. Never display secret values in topology.
The graph must also be usable without dragging, using keyboard and list/detail
views. Full Kubernetes equivalence and blanket production readiness are not
established by local tests.

## Evidence on Hand

Current repository and `tests/qualification/` contain actual local Rust,
integration and fault evidence, plus explicit limitations. Reverify current
source changes before making new qualification claims.

## Brand Commitments

Preserve the Royak name and the incumbent dashboard identity; this request is
an extension, not a rebrand. No invented production, customer or benchmark claims.
