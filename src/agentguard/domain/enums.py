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
