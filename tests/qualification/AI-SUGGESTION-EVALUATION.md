# Royak typed AI suggestions — evaluation proposal

Status: **researched/proposed, not integrated or model-validated**. Reliability
qualification comes first. No cluster data has been sent to a model/provider,
no paid API calls made, no model downloaded/trained and no credentials searched.

## What Jev can supply

The official [System One documentation](https://docs.typesafe.ai/concepts/system-one)
describes typed decisions over supplied state, not generated YAML/code or
explanations. Choice selects a declared option, Score rates an ordered rubric,
and Noul estimates a yes/no probability. This is a plausible fit for ranking a
small, precomputed set of Royak suggestions; usefulness remains unmeasured.

The [model reference](https://docs.typesafe.ai/models), checked 2026-10-29,
states that all accounts use the same weights, without customer fine-tuning or
LoRA. Domain behavior is specified through state/questions/criteria. Its listed
stable version is `jev-1.14.0`; an evaluation should pin a version, not rely on
a moving alias. The reviewed integration is the hosted
[System One API](https://docs.typesafe.ai/api/system-one). This is not evidence
of a small local model trained only on Royak, or an available self-hosted
weights/license package. Local-only operation is a separate model choice.

The [confidence documentation](https://docs.typesafe.ai/confidence) explains
that Choice/Score confidence summarizes the output distribution. It is not a
security authorization or a guarantee that the selected answer is correct.

## First bounded use case

Read-only namespace Service diagnostics, not general cluster administration:

| Candidate | Deterministic eligibility evidence |
| --- | --- |
| `NO_ACTION` | Existing internal Service already matches observed intent |
| `WAIT` | Rollout/probe/endpoint observations are still converging |
| `FIX_SELECTOR` | A particular existing Service selector mismatches the intended pods |
| `CREATE_INTERNAL_SERVICE` | Named ready deployment/port has no matching internal Service and intent is explicit |
| `ASK_HUMAN` | Intent, ownership, telemetry or candidate scope is ambiguous |

Code constructs candidate IDs and exact parameters from validated visible
resources. The model cannot invent names, ports, permissions, public exposure,
arbitrary manifests or actions outside that candidate set. A missing Service is
not alone proof that one should be created. Initially show only a suggestion;
no provider response causes an infrastructure mutation.

Input is an explicitly granted, masked namespace snapshot: generation/time,
deployment/pod/Service topology, ready counts, port declarations, diagnostic
codes and relevant user intent. Do not send Secrets, tokens, environment values,
raw logs, credentials, hidden namespaces or arbitrary workload-supplied
instructions. Workload names/descriptions are untrusted data, not policy.

Output is a candidate ID, its probability distribution and optional atomic
evidence-sufficiency/risk judgments. Explanations are assembled from cited
observed facts and deterministic templates, not invented model reasoning.
Provider timeout/error/malformed output or stale/missing evidence results in
`ASK_HUMAN`/unavailable suggestions; the orchestrator must operate independently.

If a later, separately approved apply workflow is built: display the exact diff,
require human approval bound to namespace/candidate/parameters/snapshot hash,
recheck current RBAC and preconditions, reject drift, apply once, audit outcome.
The model never grants its own permissions or relaxes admission/network policy.

## Evidence before choosing a model

1. Establish a deterministic rule baseline on the same facts/candidates. If
   simple rules already solve the decision, a model must add measured value.
2. Create human-reviewed cases from real diagnostic/fault scenarios, including
   healthy/no-op, converging rollout, stale observations, same names in distinct
   namespaces, missing telemetry, ambiguous intent and adversarial metadata.
3. Split by scenario family/topology/incident/version, not shuffled copies of
   the same fixture. Keep a genuinely unseen test set and separately test OOD.
4. Compare rules, pinned Jev and any local specialist on candidate correctness,
   unsafe-suggestion rate, no-op false positives, abstention/coverage, probability
   calibration, latency, provider-failure behavior and resource/cost budgets.
5. Set thresholds from held-out outcomes and asymmetric error costs; do not
   equate a convenient 0.9 output with 90% operational correctness. Report sample
   sizes/uncertainty and keep unknown cases routed to a human.
6. Shadow/read-only pilot first. Preserve a frozen regression set and requalify
   on model/data/schema changes. No neural improvement claim from rule-only or
   synthetic smoke results.

The closed action space simplifies schema validation and evaluation. It does
not make workload intent, causal diagnosis or calibrated abstention trivial.
For a small local Royak-only model, data/labels and a baseline come before model
training; Jev's hosted results cannot substitute for local-model evidence.
