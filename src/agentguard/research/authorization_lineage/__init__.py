"""Authorization-lineage comparative experiment implementation.

This package is research-only and bound to AG-LINEAGE-PREREG-v1.0. Importing it does not alter
AgentGuard production enforcement paths.
"""

from .analysis import analyze_trial, build_confirmatory_manifest, master_seed, summarize
from .arms import A0Arm, A1Arm, B4Arm
from .harness import DevTrialHarness
from .models import A0_SHA, PREREG_SHA256, PROTOCOL_ID, Arm, ProviderStratum, Schedule, TrialSpec
from .provider import IndependentEffectOracleReader, SimulatedProvider

__all__ = [
    "A0Arm",
    "A0_SHA",
    "A1Arm",
    "Arm",
    "B4Arm",
    "DevTrialHarness",
    "IndependentEffectOracleReader",
    "PREREG_SHA256",
    "PROTOCOL_ID",
    "ProviderStratum",
    "Schedule",
    "SimulatedProvider",
    "TrialSpec",
    "analyze_trial",
    "build_confirmatory_manifest",
    "master_seed",
    "summarize",
]
