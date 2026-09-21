"""Authorization-lineage comparative experiment implementation.

Research-only code bound to AG-LINEAGE-PREREG-v1.0. DEV helpers remain available, but only the
canonical study/session path can emit a ConfirmatoryReport.
"""

from .analysis import (
    ConfirmatoryCorpusError,
    analyze_confirmatory_study,
    analyze_trial,
    build_confirmatory_manifest,
    create_confirmatory_session,
    manifest_sha256,
    master_seed,
    summarize,
    validate_confirmatory_corpus,
    validate_confirmatory_manifest,
)
from .arms import A0Arm, A1Arm, B4Arm
from .canonical import (
    CanonicalStudySession,
    ConfirmatoryReport,
    ConfirmatorySessionError,
    ConfirmatoryStudyInvalidError,
    ReplacementExhaustedError,
    ReplacementRequiredError,
    canonical_trial_identity,
    trial_identity_sha256,
)
from .harness import DevTrialHarness
from .models import A0_SHA, PREREG_SHA256, PROTOCOL_ID, Arm, ProviderStratum, Schedule, TrialSpec
from .preflight import preflight_digest, run_confirmatory_preflight
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
    "CanonicalStudySession",
    "ConfirmatoryCorpusError",
    "ConfirmatoryReport",
    "ConfirmatorySessionError",
    "ConfirmatoryStudyInvalidError",
    "DevTrialHarness",
    "HarnessInvalidReason",
    "IndependentEffectOracleReader",
    "PREREG_SHA256",
    "PROTOCOL_ID",
    "ProviderStratum",
    "ReplacementExhaustedError",
    "ReplacementRequiredError",
    "Schedule",
    "SimulatedProvider",
    "TrialSpec",
    "analyze_confirmatory_study",
    "analyze_study",
    "analyze_trial",
    "build_confirmatory_manifest",
    "build_forensic_bundle",
    "canonical_trial_identity",
    "create_confirmatory_session",
    "exact_binomial_interval",
    "exact_mcnemar_pvalue",
    "holm_adjust",
    "manifest_sha256",
    "master_seed",
    "preflight_digest",
    "run_confirmatory_preflight",
    "safety_cell_reports",
    "summarize",
    "trial_identity_sha256",
    "validate_confirmatory_corpus",
    "validate_confirmatory_manifest",
    "validate_trace",
    "write_forensic_bundle",
]
