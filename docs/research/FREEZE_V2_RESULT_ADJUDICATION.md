# AgentGuard Freeze v2 Result Adjudication

## 1. Governance Boundary

This document is post-freeze human governance. It records the Owner / Research
Lead adjudication of the completed AG-LINEAGE-PREREG-v1.0 Freeze v2 experiment.
It is not part of the preregistered scientific tree and does not modify the
frozen experiment. The frozen scientific identity remains commit
`8b672157646a23c824eac2842cab804e2f527d9c` (tag
`agentguard-lineage-freezev2-prereg-v1.0-freeze-8b67215`).

## 2. Experiment Record Decision

EXPERIMENT_RECORD: ACCEPTED

Acceptance is based narrowly on: exact-head validation (self-hosted run
`35533913817`, success); 9-component binding verification; deterministic seed
verification (`f5945ddf…` recomputed identical); manifest verification
(`8e6b5a4f…`, 10,800 trials); complete execution (3,600/3,600 blocks, 0
invalid, 0 failures); evidence-integrity audit PASS (28,800 chain records,
47,200 files, 0 failures); frozen analysis lineage; end-to-end
reproducibility audit PASS; scientific custody verification (dual copies,
transport hash `9fc6cf7f…` verified).

Accepting the record does NOT mean accepting the research thesis.

## 3. Repository Claim State

RESEARCH_CLAIM: NOT_VALIDATED

This document does not promote or rewrite that repository-level claim state.
The clarification record's pre-execution boundary values remain historically
intact.

## 4. Specific Thesis Adjudication

AGENTGUARD_SPECIFIC_DIFFERENTIATION_THESIS: FALSIFIED_WITHIN_PROTOCOL

Frozen predicates: H1 = true, H2 = true, H3 = true (2,800 matching gap-pair
trial identities), H4 = false; B4 completion noninferior = true; frozen
specific differentiation-thesis falsification field = true.

Frozen criterion: H2 pass AND B4 completion noninferior (margin -0.05) AND
H4 fail.

## 5. What the Adjudication Means

Within AG-LINEAGE-PREREG-v1.0 and the retained Freeze v2 corpus, the
preregistered AgentGuard-specific differentiation criterion was not
demonstrated and the frozen falsification predicate evaluated true.

## 6. What the Adjudication Does NOT Mean

Explicitly excluded: system execution failure; demonstrated AgentGuard
unsafety; universal A1/B4 equivalence; proof that AgentGuard can never
differentiate; real-provider conclusions; production conclusions; universal
safety claims; impossibility claims.

## 7. Key Observed Results

Corpus-scoped wording only: retained logical trials: 10,800; harness-invalid
trials: 0; A1 retained trials: 3,600; B4 retained trials: 3,600; A1 primary
violations: 0; B4 primary violations: 0; H3 matched gap pairs: 2,800; A1 vs B4
completion difference point estimate: 0.0; completion exact McNemar p-value:
1.0; A1-B4 slot-hold median difference: +0.026 seconds; slot-hold ratio: 6.45,
favoring B4 on that burden measure; operator mean difference: 0.0.

## 8. Publication Governance

PUBLICATION_STATUS:
ELIGIBLE_FOR_TECHNICAL_REPORT_OR_NEGATIVE_RESULT_PUBLICATION

This is a governance eligibility statement, not a statement that a paper has
been published or accepted. Suitable current-scope publication forms include:
audit-grade technical report; negative/null-result research note; full
manuscript with appropriate framing and limitations. Production or
real-provider claims require additional evidence.

## 9. Follow-Up Research

Any follow-up experiment must be a NEW experimental generation with: new
research question/hypothesis as appropriate; new preregistration; new freeze;
new seed/manifest binding; separate execution and analysis. Freeze v2 must
remain unchanged historical evidence.

## 10. Final Adjudication

EXPERIMENT_RECORD = ACCEPTED

RESEARCH_CLAIM = NOT_VALIDATED

AGENTGUARD_SPECIFIC_DIFFERENTIATION_THESIS = FALSIFIED_WITHIN_PROTOCOL

PUBLICATION_STATUS =
ELIGIBLE_FOR_TECHNICAL_REPORT_OR_NEGATIVE_RESULT_PUBLICATION

These fields have distinct meanings and must not be collapsed into a single
"success/failure" label.
