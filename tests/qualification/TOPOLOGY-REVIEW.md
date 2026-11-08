disposition: fix

Review basis: independent file-and-screenshot review using the equivalent shipped finish-reviewer contract; no browser was run and no implementation file was edited. No approved comp, critique-reference comp or QUALITY BAR board exists for this code-led local extension; those inputs are not applicable. `DESIGN.md` has not yet been produced by the post-review documenter.

## persistence

Pass for the review stage: `PRODUCT.md` and `.impeccable/surfaces/src-dashboard-html.md` persist the audience, read-only boundary, incumbent identity and interaction promises. FORM explicitly records a local extension, for which the new-work flow does not require a concept roll. Comp-phase state and image-asset provenance are not applicable. Final documentation remains due after correction/review.

Both required captures exist and are valid: `.impeccable/review/desktop.png` is a 1440-wide full-page dashboard capture and `mobile.png` is a 390-wide full-page capture. They show the document top, actual populated cluster content, a selected pod and its evidence; neither is blank or a wrong-section capture. The corresponding live-run captures are byte-size-identical. `ui-report.json` reports a recovered three-daemon source, 16 nodes, 10 relationships, keyboard/search checks and no script errors. That report is supporting evidence, not my own browser execution; error/partial/stale states have no supplied screenshots.

## fidelity

| Element / promise | Classification | Evidence |
| --- | --- | --- |
| TYPE | match | Incumbent workhorse/system UI typography and weight hierarchy are retained; no replacement display treatment. |
| MATERIAL | match | Flat navy/slate operational panels and native controls; no invented physical material or raster obligation. |
| GROUND | match | Incumbent dark navy ground and slate panels remain visible in both the comparison and final captures. |
| THESIS: inspect actual relationships without mutation | match | Search, kind/state controls, resource map and detail evidence are present; the supplied live report states same-origin GET-only traffic. |
| OWN-WORLD: incumbent identity and labelled status | match | Existing Royak header, panels and lower dashboard remain; selected links/nodes use indigo and each resource includes a text status. |
| STORY: authenticate, apply namespace, inspect evidence | contradicted | Namespace text can differ from the applied in-memory namespace without a pending/applied cue; blank token submission silently retains the prior token. The generic session path rewriter also rewrites the cluster-scoped namespaces endpoint. |
| FIRST VIEWPORT: map plus adjacent detail, stable selection | adaptation / contradicted | Desktop adjacency and selected-neighbour highlighting match. Narrow list/detail stacking is the explicitly required accessibility adaptation. The 1270px graph exceeds its desktop viewport: Node cards are clipped and Dependencies is entirely offscreen with no visible overflow instruction or fit control. |
| FORM: local code-first extension | match | No new visual world or marketing structure was introduced; a concept tournament would be outside this brief. |
| Keyboard continuity during polling | contradicted | `render()` captures only `data-topo-id` focus; `detail()` replaces its children on every poll, including focused connection buttons that lack that identity. |
| Honest unavailable/empty/stale states | contradicted | Topology has explicit error messages, but the shared authenticated dashboard treats an unavailable Events response as “No events” and can retain prior Brain/security values when Brain becomes unavailable. |
| Read-only evidence and truth | match at supplied scope | The captures name routing as declared rather than successful traffic, show observation time and per-connection evidence, and contain no token text. Backend authorization completeness is outside this visual review. |

The first desktop viewport communicates the map mechanism, not a new hero. The mobile viewport prioritizes authentication/filtering and then a scrollable list, as the contract allows. Large-graph behavior beyond the 16-resource capture is source-reviewed only, not interactively verified here.

## ceiling

No QUALITY BAR board exists; the governing ceiling is the incumbent operational system plus the explicit interaction contract. Its precision is not yet reached: applied scope, keyboard continuity, data availability and graph navigation need the fixes below. The detector's legacy gradient wordmark, Inter declaration, slate label contrast and generated-selector combinations are pre-existing identity/drift, not grounds for a rebrand in this extension. No new raster, ornamental material, or animated spectacle is required.

## material_fixes

1. **F1 — Correct namespace routing (STORY / truth):** replace the broad `RoyakSession.path` prefix substitution at `src/dashboard-topology.js:14–15` with explicit namespaced-resource routing; `/api/v1/namespaces` must remain cluster-scoped, and a denied cluster-scoped count must show unavailable, never infer scope from an invalid nested URL. Verify cluster-wide and namespace-limited sessions against actual request paths.
2. **F2 — Keep ancillary availability honest (state contract):** at `src/dashboard.html:275–318`, distinguish an unavailable/unauthorized Events response from a successful empty list and either clear Brain/security values or visibly mark their retained snapshot stale when Brain fails; guard the whole multi-request dashboard refresh with its starting session epoch so an obsolete refresh cannot overwrite the new session's loading/availability presentation. Verify failure after a populated success, disconnect and scope/token replacement; this finding is source-backed, not screenshot-confirmed behavior.
3. **F3 — Expose applied versus staged authentication scope (STORY):** at `src/dashboard-topology.js:126–130` and `src/dashboard.html:84–90`, display the currently applied namespace and whether a token is retained (never its value), and mark edited-but-unapplied scope/token input as pending; a blank token meaning “keep current token” must be explained. Existing data must remain explicitly tied to the applied scope until submission, then clear as it does now. Verify edits without submission and reconnect with a replacement token.
4. **F4 — Preserve keyboard focus through polling (interaction contract):** at `src/dashboard-topology.js:30–46,70–100`, retain connection controls keyed by selected resource and edge, or capture/restore their complete focus identity when rebuilding; do not drop a focused neighbour button to document/body on a five-second refresh. Verify keyboard focus in each detail connection across two real polls, including removal of the focused relation with a deliberate fallback.
5. **F5 — Make offscreen map resources discoverable (FIRST VIEWPORT / coverage):** the desktop capture clips Node cards and hides Dependencies because `src/dashboard-topology.js:78–95` renders a fixed 1270px stage inside `src/dashboard.html:36–37`; add a clearly named Fit map action or fit the initial zoom to the available width, plus an explicit horizontal/vertical navigation cue when overflow remains. Preserve readable labels, optional keyboard scrolling and the complete list alternative; do not shrink the narrow-screen default into a tiny graph. Verify a Dependencies resource and a lower-row resource are findable at 1440 and 390 widths.

## keep

Keep the incumbent Royak identity, read-only/session boundary, memory-only token, labelled evidence rather than traffic claims, deterministic node placement, selected-neighbour emphasis and narrow-screen list/detail alternative.

---

Verdict pass: scoring F1–F5 only, not a new whole-surface audit. Both corrected immutable captures in `tests/qualification/.runs/rkq-20261027-021843-55562c/` were opened and are valid, populated, top-of-document captures at 1440 and 390 widths. Their UI source hashes match the current HTML/CSS/JS and the supplied packet. The four supplemental `topology-ui-synthetic-{unavailable,pending,offline,forbidden}.png` captures were also opened; they are explicitly synthetic UI-state evidence, not backend-failure evidence. No browser or detector was run by this reviewer.

## verdict

- **F1 — resolved:** current `RoyakSession.path` uses explicit core/apps resource allowlists and leaves `/api/v1/namespaces` cluster-scoped; the dashboard label now says “Namespaces (cluster)” and unavailable counts use an em dash. The synthetic fixture asserts namespaced pod routing and the absence of the invalid nested namespaces path. The real capture shows the separately labelled cluster count.
- **F2 — resolved:** the unavailable-state capture visibly says “Events unavailable in this scope” and clears Brain/security values to em dashes instead of retaining the populated values visible in the pending-state capture. Current dashboard source guards every post-await presentation update with the refresh's starting session epoch. The synthetic fixture covers success-to-unavailable and a delayed prior-session response after disconnect. The forbidden-state capture's fresh ancillary values are permitted by that fixture and are not evidence of stale forbidden data.
- **F3 — resolved:** both real captures visibly identify “Applied scope: qualification” and explain retained-token/blank-input reuse. The synthetic pending capture explicitly distinguishes edited “pending” input from applied “lab” data and tells the user to apply it; the fixture checks replacement-token use and input clearing.
- **F4 — resolved:** detail connections now carry a stable selected-resource/edge key, polling restores that key, and removed connections deliberately focus the detail panel with an explanatory status. The immutable live `ui-report.json` records two-poll focus continuity; the current-binary `rkq-20261027-022538-bc400c/ui-focus-report.json` additionally reports all three selected-pod connections checked through two scheduled polls each, without exporting credentials. The synthetic fixture explicitly checks the removed-connection fallback. These are inspected evidence reports and source, not reviewer-executed interactions.
- **F5 — resolved:** the real desktop capture visibly includes the complete horizontal lane sequence through Dependencies and a named “Fit map” control. Both real captures provide explicit horizontal/vertical/arrow-key navigation guidance and explain List view as the readable alternative; the mobile capture still defaults to list/detail and shows lower dependency rows. Current source fits the initial desktop snapshot and supports explicit re-fitting; the synthetic fixture checks Dependencies bounds after fitting and dependency selection through the mobile list.

Fix-batch regressions observed within these five findings: none.

## remaining

Clear for F1–F5. This ship verdict covers the five scored UI fixes only. It does not close the separately running final-current-binary fault/runtime qualification, establish backend failure behavior from synthetic captures, or assert a new whole-surface audit. The supplied desktop/mobile captures are from unchanged current UI assets in an earlier backend run; the current-binary supplemental focus evidence is separately identified above.

disposition: ship
