from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from decisionlock.domain import (
    Action,
    ActionIntent,
    EffectProjection,
    Principal,
    ProvenanceLabel,
    Resource,
)
from decisionlock.risk import classify_tool_definition


def intent_from_tools_call(
    message: dict[str, Any],
    *,
    principal: Principal,
    server: str,
    trace_id: str | None = None,
    request_id: str | None = None,
    provenance: tuple[ProvenanceLabel, ...] = (ProvenanceLabel.UNVERIFIED,),
    provenance_verified: bool = False,
    tool_schema: dict[str, Any] | None = None,
    resource: Resource | None = None,
) -> ActionIntent:
    params = message.get("params")
    if not isinstance(params, dict):
        raise TypeError("tools/call params must be an object")
    name = params.get("name")
    arguments = params.get("arguments", {})
    if not isinstance(name, str) or not name:
        raise ValueError("tools/call params.name is required")
    if not isinstance(arguments, dict):
        raise TypeError("tools/call arguments must be an object")
    resolved_request_id = request_id or str(message.get("id") or uuid4().hex)
    schema = tool_schema if tool_schema is not None else {}
    input_schema = schema.get("inputSchema", schema)
    # Pass the full provider-declared tool metadata to the classifier, not just the
    # input schema. The classifier reads name, description and schemas; discarding
    # the description here made every tool whose capability is only inferable from
    # its description classify as `unknown`, which a default-deny
    # `unknown_capability` then rejects.
    tool_metadata: dict[str, Any] = {"name": name, "inputSchema": input_schema}
    description = schema.get("description")
    if isinstance(description, str) and description:
        tool_metadata["description"] = description
    output_schema = schema.get("outputSchema")
    if isinstance(output_schema, dict):
        tool_metadata["outputSchema"] = output_schema
    capabilities, _, _ = classify_tool_definition(tool_metadata)
    projected_capabilities = frozenset(capability.value for capability in capabilities)
    return ActionIntent(
        request_id=resolved_request_id,
        trace_id=trace_id or "trc_" + uuid4().hex,
        principal=principal,
        action=Action(
            protocol="mcp",
            server=server,
            tool=name,
            operation="call",
            capabilities=projected_capabilities,
        ),
        resource=resource,
        provenance=provenance,
        provenance_verified=provenance_verified,
        effects=EffectProjection(),
        arguments=arguments,
        tool_schema=schema,
        requested_at=datetime.now(UTC),
    )
