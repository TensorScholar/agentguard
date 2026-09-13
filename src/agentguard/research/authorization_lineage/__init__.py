"""Authorization-lineage comparative experiment implementation.

This package is research-only and bound to AG-LINEAGE-PREREG-v1.0. Importing it does not alter
AgentGuard production enforcement paths.
"""

from .analysis import (
    ConfirmatoryCorpusError,
    analyze_confirmatory_study,
    analyze_trial,
    build_confirmatory_manifest,
    manifest_sha256,
    master_seed,
    summarize,
    validate_confirmatory_corpus,
    validate_confirmatory_manifest,
)
from .arms import A0Arm, A1Arm, B4Arm
from .confirmatory import (
    ConfirmatoryEvidenceError,
    TrialExecutionEvidence,
    authoritative_confirmatory_corpus,
    block_sequence_filename,
    derive_authoritative_trial,
    run_confirmatory_block,
    validate_block_execution,
    validate_execution_sequences,
    verify_supplied_analysis,
)
from .harness import DevTrialHarness
from .models import A0_SHA, PREREG_SHA256, PROTOCOL_ID, Arm, ProviderStratum, Schedule, TrialSpec
from .provider import IndependentEffectOracleReader, SimulatedProvider
from .statistics import (
    analyze_study,
    exact_binomial_interval,
    exact_mcnemar_pvalue,
    holm_adjust,
    safety_cell_reports,
)
from .trace import (
    HarnessInvalidReason,
    build_forensic_bundle,
    validate_trace,
    write_forensic_bundle,
)

__all__ = [
    "A0Arm",
    "A0_SHA",
    "A1Arm",
    "Arm",
    "B4Arm",
    "ConfirmatoryCorpusError",
    "ConfirmatoryEvidenceError",
    "DevTrialHarness",
    "HarnessInvalidReason",
    "IndependentEffectOracleReader",
    "PREREG_SHA256",
    "PROTOCOL_ID",
    "ProviderStratum",
    "Schedule",
    "SimulatedProvider",
    "TrialExecutionEvidence",
    "TrialSpec",
    "analyze_confirmatory_study",
    "analyze_study",
    "analyze_trial",
    "authoritative_confirmatory_corpus",
    "block_sequence_filename",
    "build_confirmatory_manifest",
    "build_forensic_bundle",
    "derive_authoritative_trial",
    "exact_binomial_interval",
    "exact_mcnemar_pvalue",
    "holm_adjust",
    "manifest_sha256",
    "master_seed",
    "run_confirmatory_block",
    "safety_cell_reports",
    "summarize",
    "validate_block_execution",
    "validate_confirmatory_corpus",
    "validate_confirmatory_manifest",
    "validate_execution_sequences",
    "validate_trace",
    "verify_supplied_analysis",
    "write_forensic_bundle",
]
