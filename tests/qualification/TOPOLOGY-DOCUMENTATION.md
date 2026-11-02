# Topology extension — documentation pass

Date: 2026-10-27. Scope: ordinary local Operate extension of the existing Royak
dashboard, not a new visual world, rebrand or production qualification.

## Outcome

The source-level extension preserves the incumbent dashboard system. No
`DESIGN.md`, design sidecar, new metaphor, token taxonomy or identity was created.
The only file written by this pass is this report. Existing implementation and
dirty workspace changes were preserved; context loading and the detector were
not rerun.

This documents the corrected source inspected below. It does **not** close the
finish review: the existing real desktop/mobile screenshots predate F1–F5, and
the final current-source Linux rebuild, real captures and reviewer verdict were
still pending at this pass. The generic FINISH wording in the surface brief and
the initial review's expectation of a new `DESIGN.md` do not override the
ordinary-extension preservation rule. Those files were not repaired as a side
effect of documentation.

## Evidence checked

- `PRODUCT.md`: confirmed beta operators/students, read-only diagnostics,
  permission/data honesty, no secrets, keyboard/list alternative, local scope.
- `.impeccable/surfaces/src-dashboard-html.md`: Operate mode and the inherited
  THESIS, OWN-WORLD, STORY, FIRST VIEWPORT, FORM and interaction contract.
- `src/dashboard.html`: global/base styles, header, incumbent metric/table/event
  panels, topology controls, desktop/narrow layout, focus styles, reduced motion
  and corrected ancillary availability/session-epoch handling.
- `src/dashboard.css`: the locally served generated utility stylesheet; type,
  colour, spacing and responsive classes actually present, not hypothetical
  design tokens.
- `src/dashboard-topology.js`: deterministic six-lane map, selection/neighbour
  emphasis, list/detail equivalence, scope/auth feedback, explicit resource
  routing, keyed detail-focus restoration, polling states and Fit map.
- `git show HEAD:src/dashboard.html`: incumbent baseline comparison. Navy ground,
  slate cards, 12px panel corners, the Royak wordmark, system/workhorse type and
  metric/table hierarchy already existed before this extension.
- `tests/qualification/TOPOLOGY-REVIEW.md`: initial `disposition: fix`, material
  findings F1–F5, kept incumbent qualities and the review's stated limitations.
- `tests/qualification/topology_ui.cjs`: synthetic regression assertions covering
  explicit namespace paths, availability clearing, staged/applied session state,
  detail focus across two polls/removal, Fit map/dependencies, keyboard, filters,
  offline/401 distinction, hostile strings and 390px layout. The parent workflow
  reports this fixture passed after correction; this documenter inspected the
  fixture but did not independently run it. Synthetic responses are not real
  cluster/RBAC/runtime evidence.
- `.impeccable/review/desktop.png` and `mobile.png`: both opened and visually
  checked. They are real populated dashboard captures at 1440px and 390px,
  respectively, but **pre-correction**: no applied-session line, Fit map action
  or navigation cue is shown. They establish incumbent visual continuity only,
  not final corrected visual acceptance.
- `.impeccable/config.json`: comp-first preference is recorded for applicable
  future surfaces; this operational extension remains code-led per its brief.

## Five-line system summary

1. Palette: existing dark navy ground (`#0a0e1a`), slate panels (`#111827`) and light text; restrained indigo/cyan identity remains.
2. Type ramp: incumbent 30px wordmark, 24px metrics and 18px panel headings; topology uses 20px section, 16px detail, 13px body/control and 11–12px metadata text, with mono resource identifiers where already used.
3. Layout/form: flat bordered panels with 12px outer corners; 8px map viewport and 6px topology controls; desktop map/detail adjacency becomes a complete list/detail stack at 800px and below.
4. Existing task rule: status always has words and evidence; green/amber/red are supporting signals, declared links do not certify traffic, and unknown/unavailable is not healthy empty.
5. Existing interaction rule: stable positions and selection, reversible search/filtering, visible applied versus pending scope, keyboard-operable native controls, optional fit/scroll map and a readable list alternative; no invented named visual doctrine.

These values describe the observed extension and baseline, not a newly approved
global token standard. No visual value was recorded to legitimise a review defect.

## Source correction versus acceptance boundary

| Finding | Correction visible in inspected source | Evidence still required for finish |
| --- | --- | --- |
| F1 | Explicit core/apps namespaced resource matching leaves the namespaces endpoint cluster-scoped. | Current rebuilt real request-path/RBAC verification for cluster-wide and namespace-limited sessions. |
| F2 | Events distinguish unavailable from empty; unavailable Brain/security fields clear; refresh checks its starting session epoch. | Real populated-to-failure/disconnect/scope-token replacement checks and fresh captures of relevant states. |
| F3 | Applied scope/token-retention text and edited-but-unapplied feedback are present; blank-token reuse is explained. | Current rendered pending/applied/replacement-session review, without exposing credentials. |
| F4 | Detail connections carry selection/edge identity; polling restores focus or moves to a deliberate announced fallback. | Current real polls and relation-removal keyboard check, with reviewer scoring at its proper scope. |
| F5 | Initial desktop fit, named Fit map control, overflow/navigation instruction and narrow list default are present. | Fresh 1440px/390px captures; Dependencies/lower-row discoverability and label readability reviewed after rebuild. |

The source checks above are not an independent `ship` verdict. A successful
synthetic browser run cannot establish the actual Linux binary contains the
same assets, nor that a corrected layout reaches the intended visual quality.
After rebuild, capture from the document top, confirm each file is complete and
settled, and return the same viewports to the finish reviewer for resolved /
partial / unresolved scoring. Error/partial/stale state claims need their own
appropriate real evidence; the old populated screenshots cannot establish them.

## Freshness fingerprints

SHA-256 of source inspected by this documentation pass:

```text
c9fe406c01fb7c8687b3e8813ee663e8bd74d9a85273e862408a8d5d81e38ebb  src/dashboard.html
56ed21f38160885facafdfcf26543ba13e59592f19330c7f4ed31cf31c2fca3b  src/dashboard.css
5a218827336f13cd548ac9959bac9c19ff59e7a8c3ff09217d4c6d67a040a123  src/dashboard-topology.js
```

Pre-correction review image fingerprints (not final evidence):

```text
39db1805e1135f6f2793a61d81350e312c36f5203df5283df04fff20ede239d9  .impeccable/review/desktop.png
569d2c41da7341cf1879543f04c59697d8fa7c41deb8e9945cfa035a9aeb1a9c  .impeccable/review/mobile.png
```

If any inspected asset changes after the freeze/rebuild, this report's source
comparison must be rechecked; timestamps alone do not bind a capture to source.

## Not canonized or repaired

The existing review reports legacy gradient wordmark treatment, the Inter
declaration, low-contrast ancillary slate labels and generated-selector
combinations as inherited identity/drift. The baseline confirms the wordmark,
font declaration and ancillary slate usage predate this extension. Existing
event glyph icons and system-font display treatment are not promoted into
recommended future patterns. Generated utilities are implementation output,
not a reason to declare absent styles intentional. None of this drift was
repaired or turned into a design-system rule under this narrow write boundary.

Royak Connect/VPN/public relay remains a proposal, not an activated capability.
Future landing/showcase work and its comp-first process are separate. This pass
used no external services or public demo and makes no production-readiness,
Kubernetes-conformance, customer or benchmark claim.

## Closeout / freshness addendum — 2026-10-27

This addendum supersedes the earlier **pending rebuild/captures/verdict** status,
without rewriting its historical evidence boundary. The old `.impeccable/review/`
images remain pre-correction; they are not silently relabelled as final evidence.

Independently checked final evidence bundle:
`tests/qualification/.runs/rkq-20261027-022538-bc400c/`.

- Rehashed all three UI source files: their SHA-256 values exactly match the
  fingerprints above and this run's `manifest.json` source map. No UI source
  change occurred during this documentation closeout.
- Rehashed `tests/qualification/.runs/linux-royak-beta-qualified`: binary SHA-256
  is `cc27ecde07fc497471b81016c09e4cda4aaaf0e972f26beb236949f29716cb82`,
  matching the run manifest and supplemental focus report. The similarly named
  `linux-royak-beta-final` is not the identified qualified binary.
- Parsed `report.json`: `passed: true`, 13/13 checks passed. The manifest explicitly
  identifies single-host, three-independent-Docker-daemon scope and
  `production_ready: false`.
- Inspected `ui-report.json` and `ui.log`: real recovered three-daemon API,
  `synthetic: false`, three pods, 16 graph resources and 10 relationships; the
  browser report passes its recorded read-only/session/interaction/layout checks.
- Inspected `ui-focus-report.json`: real same-origin recovered-node evidence,
  three detail connections each checked through two scheduled polls,
  `passed: true`, `synthetic: false`, no credentials exported. This is inspected
  execution evidence, not a documenter-run browser test.
- Opened the current bundle's `topology-desktop.png` (1440×1788) and
  `topology-mobile.png` (390×3391). Both are valid populated full-page captures
  beginning at the document top, with no blank/black/wrong-section region. They
  show the corrected applied-scope/token-reuse text, Fit map control and map
  navigation cue. Desktop exposes lanes through Dependencies and adjacent
  detail; mobile retains the readable list/detail stack with dependency rows.
  Incumbent header, navy/slate panels, typography and lower dashboard remain.
- Read the appended verdict in `TOPOLOGY-REVIEW.md`: F1–F5 are all resolved,
  `disposition: ship`, **for those five fixes only**. The reviewer used corrected
  captures from `rkq-20261027-021843-55562c` with the unchanged UI hashes, plus
  the current-run focus supplement. This documenter separately opened the newer
  current-binary captures named above; it does not enlarge the review's scope.

Current real capture SHA-256 values:

```text
b275e98f008e8c72350b88d3b6344ede8292dba3011b87d6a2d35f81018c0912  rkq-20261027-022538-bc400c/topology-desktop.png
20fcec26164c2f2de143f53b7d85688aaa20470ee35e98a4a4f757ae6040dc2f  rkq-20261027-022538-bc400c/topology-mobile.png
```

Supplemental unavailable, pending, offline, forbidden and removed-connection
behavior is synthetic fixture evidence in `topology_ui.cjs` and
`tests/qualification/.runs/topology-ui-synthetic-*.png`; those captures are not
real backend faults. Real recovered-cluster captures and real focus polling are
separately identified above. The bounded reviewer verdict does not become a new
whole-surface audit, broad accessibility certification or production audit.

The coordinating workflow also reports 216 native tests, 21 Python tests and 53
real lifecycle checks passing; the native log was inspected here and records
216 passed. The Python/lifecycle counts are coordination context, not rerun or
independently qualified by this documenter. The separate final feature-suite
batch was still finishing when this addendum was requested; this documentation
pass neither blocks on nor declares that broader batch complete.

The ordinary-extension documentation and bounded F1–F5 review are now closed at
the stated evidence scope. No implementation, identity, DESIGN.md or sidecar
change was made; the previously listed legacy drift remains uncanonized and
unrepaired. No in-place legacy-cluster upgrade or public tunnel was certified.
Connect/VPN/public relay remains proposed. No public demo or external service
was used by this pass.
