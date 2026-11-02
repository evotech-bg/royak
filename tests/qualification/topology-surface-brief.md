# Dashboard topology extension

Mode: Operate. Audience: confirmed beta operators and DevOps students.
Primary task: find a resource, follow its declared/observed relationships and
understand why a workload is not ready, without mutating the cluster.

## Direction contract

THESIS: Keep the existing Royak dashboard and make cluster relationships
inspectable. A stable node-link map is for following paths, not a decorative
force-directed hairball. Tables remain a complete alternative.

OWN-WORLD: Inherit the incumbent dark navy ground, slate panels, system UI type
and restrained indigo/cyan selection. Status labels accompany colour; amber is
unknown/degraded and red is failure/missing. No rebrand or replacement hero.

STORY: Authenticate in memory, choose namespace scope, find a resource, select
it and inspect typed incoming/outgoing relationships and their evidence. Failed
permission/data checks never become a healthy empty view.

FIRST VIEWPORT: A topology section below the existing header and above metrics:
scope/auth controls, a compact search/kind/status toolbar, then a stable layered
map and an adjacent detail panel. The signature interaction highlights one
resource's neighbours without moving the whole map. Selection survives polling.

FORM: Local extension of the established dashboard, no concept roll required.
Code-first operational screen; the user's comp-first preference applies to
future landing/showcase surfaces, not this dashboard.

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance

## Interaction contract

- Read-only. Search and filters are reversible; no confirmation is needed.
- Nodes use namespace + kind + name identity. Name collisions remain distinct.
- Graph is capped and reports truncation; users can narrow namespace/search.
- List view exposes every visible relationship in words. Enter/Space select;
  all controls use native keyboard semantics. No drag-only interaction.
- Narrow screens default to list/detail; the map is optional, not squeezed.
- Loading, empty, no matches, 401, 403, partial, stale/offline and removed
  selection are distinct. Polling does not replace focused controls.
- Data timestamp and source/evidence are visible. Desired service/ingress
  links are not claims of successful traffic. Reference-only nodes say Unknown.
- Token never enters URL, persistent storage, source, logs or screenshots.
- Acceptance: real API/RBAC and browser tests at desktop/narrow widths, search,
  filters, selection/keyboard, empty/error/partial/stale states, no XSS from names
  or facts, no forbidden namespace or secret value in data/DOM.
