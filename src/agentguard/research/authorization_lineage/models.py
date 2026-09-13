from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Final


PROTOCOL_ID: Final = "AG-LINEAGE-PREREG-v1.0"
A0_SHA: Final = "7e5659a26ee232e2a7352a20b2b3bd87a1b4e0cf"
PREREG_SHA256: Final = "5d217f2d531e05c74fe99236e19c509370ebda31e2130998dca7b0ca9473fe9e"


class Arm(str, Enum):
    A0 = "A0"
    A1 = "A1"
    B4 = "B4"


class ProviderStratum(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"


class Schedule(str, Enum):
    S0 = "S0"
    S1 = "S1"
    S2 = "S2"
    S3 = "S3"
    S4 = "S4"
    S5 = "S5"
    S6 = "S6"
    S7 = "S7"
    S8 = "S8"
    S9 = "S9"
    S10 = "S10"
    S11 = "S11"


APPLICABLE_STRATA: Final[dict[Schedule, tuple[ProviderStratum, ...]]] = {
    Schedule.S0: tuple(ProviderStratum),
    Schedule.S1: (ProviderStratum.P2,),
    Schedule.S2: (ProviderStratum.P2,),
    Schedule.S3: tuple(ProviderStratum),
    Schedule.S4: tuple(ProviderStratum),
    Schedule.S5: (ProviderStratum.P2,),
    Schedule.S6: (ProviderStratum.P2,),
    Schedule.S7: tuple(ProviderStratum),
    Schedule.S8: tuple(ProviderStratum),
    Schedule.S9: tuple(ProviderStratum),
    Schedule.S10: tuple(ProviderStratum),
    Schedule.S11: tuple(ProviderStratum),
}


class SlotState(str, Enum):
    AVAILABLE = "available"
    RESERVED = "reserved"
    DISPATCHING = "dispatching"
    CONFIRMED_EFFECT = "confirmed_effect"
    CONFIRMED_NO_EFFECT = "confirmed_no_effect"
    UNKNOWN = "unknown"


class AttemptState(str, Enum):
    RESERVED = "reserved"
    DISPATCHING = "dispatching"
    CONFIRMED_EFFECT = "confirmed_effect"
    CONFIRMED_NO_EFFECT = "confirmed_no_effect"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class TrialSpec:
    trial_id: str
    arm: Arm
    provider: ProviderStratum
    schedule: Schedule
    replicate: int
    block_seed: str
    alpha: str
    effect_key: str

    def __post_init__(self) -> None:
        if self.replicate < 0:
            raise ValueError("replicate must be non-negative")
        if self.provider not in APPLICABLE_STRATA[self.schedule]:
            raise ValueError("schedule/provider pair is outside preregistered matrix")
        if not self.trial_id or not self.alpha or not self.effect_key:
            raise ValueError("trial identifiers must be non-empty")


@dataclass(frozen=True)
class ProviderEvidence:
    attempt_id: str
    status: str
    authoritative: bool
    no_effect_certified: bool = False
    predecessor_fenced: bool = False


@dataclass(frozen=True)
class TrialObservation:
    trial_id: str
    arm: Arm
    provider: ProviderStratum
    schedule: Schedule
    alpha: str
    effect_key: str
    root_or_slot_allocations: int
    independent_live_slots_max: int
    receipts_or_tickets: int
    credentials: int
    provider_sends: int
    attempts: int
    successor_admitted_while_predecessor_potentially_effectful: bool
    stale_reconciler_commit_accepted: bool
    legitimate_completion: bool
    unresolved: bool
    operator_interventions: int
    reconciliation_calls: int
    slot_hold_seconds: float
    duration_seconds: float
    harness_invalid: bool = False
    harness_invalid_reason: str | None = None


@dataclass(frozen=True)
class AnalyzedTrial:
    observation: TrialObservation
    oracle_effect_count: int
    lineage_budget_violation: bool
    external_effect_violation: bool
    unsafe_successor_violation: bool

    @property
    def primary_violation(self) -> bool:
        return (
            self.lineage_budget_violation
            or self.external_effect_violation
            or self.unsafe_successor_violation
        )
