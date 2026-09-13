"""Authorization-lineage comparative experiment implementation.

This package is research-only and bound to AG-LINEAGE-PREREG-v1.0. Importing it does not alter
AgentGuard production enforcement paths.
"""

from .analysis import analyze_trial, build_confirmatory_manifest, master_seed, summarize
from .arms import A0Arm, A1Arm, B4Arm
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
    "DevTrialHarness",
    "HarnessInvalidReason",
    "IndependentEffectOracleReader",
    "PREREG_SHA256",
    "PROTOCOL_ID",
    "ProviderStratum",
    "Schedule",
    "SimulatedProvider",
    "TrialSpec",
    "analyze_study",
    "analyze_trial",
    "build_confirmatory_manifest",
    "build_forensic_bundle",
    "exact_binomial_interval",
    "exact_mcnemar_pvalue",
    "holm_adjust",
    "master_seed",
    "safety_cell_reports",
    "summarize",
    "validate_trace",
    "write_forensic_bundle",
]
