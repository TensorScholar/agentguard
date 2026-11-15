from __future__ import annotations

from enum import Enum


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class EnforcementMode(str, Enum):
    OBSERVE = "observe"
    ENFORCE = "enforce"


class ProvenanceLabel(str, Enum):
    TRUSTED_SYSTEM_INSTRUCTION = "trusted_system_instruction"
    AUTHENTICATED_USER_INPUT = "authenticated_user_input"
    INTERNAL_DATABASE = "internal_database"
    EXTERNAL_WEB_CONTENT = "external_web_content"
    EXTERNAL_EMAIL = "external_email"
    THIRD_PARTY_DOCUMENT = "third_party_document"
    TOOL_OUTPUT = "tool_output"
    PERSISTENT_MEMORY = "persistent_memory"
    OTHER_AGENT_MESSAGE = "other_agent_message"
    UNVERIFIED = "unverified"


class FieldReleaseType(str, Enum):
    HUMAN_ENDORSEMENT = "human_endorsement"
    SYSTEM_ATTESTATION = "system_attestation"
    VERIFIED_TRANSFORMATION = "verified_transformation"


class ReversibilityMode(str, Enum):
    REVERSIBLE = "reversible"
    COMPENSATABLE = "compensatable"
    IRREVERSIBLE = "irreversible"


class PreparedExecutionStatus(str, Enum):
    PREPARED = "prepared"
    COMMITTED = "committed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class PolicyIntelligenceFindingType(str, Enum):
    OVERPRIVILEGED_CAPABILITY = "overprivileged_capability"
    OVERPRIVILEGED_PROTOCOL = "overprivileged_protocol"
    OVERPRIVILEGED_SERVER = "overprivileged_server"
    OVERPRIVILEGED_TOOL = "overprivileged_tool"
    OVERPRIVILEGED_OPERATION = "overprivileged_operation"
    OVERPRIVILEGED_RESOURCE_TYPE = "overprivileged_resource_type"
    OVERPRIVILEGED_RESOURCE_ID = "overprivileged_resource_id"
    EXCESS_CALL_BUDGET = "excess_call_budget"
    UNNEEDED_DELEGATION = "unneeded_delegation"


class AuditEventType(str, Enum):
    AUTHORIZATION_REQUESTED = "authorization.requested"
    AUTHORIZATION_DECIDED = "authorization.decided"
    APPROVAL_REQUESTED = "approval.requested"
    APPROVAL_GRANTED = "approval.granted"
    CREDENTIAL_REQUESTED = "credential.requested"
    CREDENTIAL_ISSUED = "credential.issued"
    EXECUTION_STARTED = "execution.started"
    EXECUTION_SUCCEEDED = "execution.succeeded"
    EXECUTION_FAILED = "execution.failed"
    EXECUTION_UNKNOWN = "execution.unknown"
    RECEIPT_REJECTED = "receipt.rejected"
    RECEIPT_CONSUMED = "receipt.consumed"
    EXECUTION_RECONCILIATION_STARTED = "execution.reconciliation.started"
    EXECUTION_RECONCILED = "execution.reconciliation.resolved"
    EXECUTION_ATTESTATION_ISSUED = "execution.attestation.issued"
    AUTHORITY_GRANTED = "authority.granted"
    AUTHORITY_DELEGATED = "authority.delegated"
    AUTHORITY_REVOKED = "authority.revoked"
    CAPABILITY_LEASE_ISSUED = "authority.lease.issued"
    CAPABILITY_LEASE_CONSUMED = "authority.lease.consumed"
    FIELD_RELEASE_CONSUMED = "field.release.consumed"
    EXECUTION_PREPARED = "execution.prepared"
    EXECUTION_PREPARE_CANCELLED = "execution.prepare.cancelled"
    EXECUTION_COMMITTED = "execution.committed"
    CAUSAL_CONTEXT_BOUND = "execution.causal_context.bound"


class ExecutionState(str, Enum):
    RESERVED = "reserved"
    DISPATCHING = "dispatching"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNKNOWN = "unknown"


class ExecutionStatus(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class ReconciliationStatus(str, Enum):
    CONFIRMED_SUCCEEDED = "confirmed_succeeded"
    CONFIRMED_FAILED = "confirmed_failed"
    STILL_UNKNOWN = "still_unknown"
    UNSUPPORTED = "unsupported"
    CONFLICT = "conflict"


class EvidenceTrustLevel(str, Enum):
    DECISIONLOCK_SIGNED = "decisionlock_signed"
    PROVIDER_CORRELATED = "provider_correlated"
    PROVIDER_VERIFIED = "provider_verified"


class AuthorityGrantStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"


class CapabilityLeaseStatus(str, Enum):
    ACTIVE = "active"
    EXHAUSTED = "exhausted"
    REVOKED = "revoked"
    EXPIRED = "expired"
