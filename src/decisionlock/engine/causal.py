from __future__ import annotations

from decisionlock.domain import (
    ActionIntent,
    CausalExecutionGraph,
    CausalGraphNode,
    FieldIntegrityBinding,
    ProvenanceLabel,
)
from decisionlock.domain.policy import CausalConstraint, PolicyRule
from decisionlock.engine.canonical import digest
from decisionlock.ports import ExecutionRepository

MAX_CAUSAL_PARENTS = 16
MAX_CAUSAL_DEPTH = 64


class CausalIntegrityError(ValueError):
    pass


def _aggregate_constraints(matched_rules: tuple[PolicyRule, ...]) -> CausalConstraint | None:
    constraints = [rule.causal for rule in matched_rules if rule.causal is not None]
    if not constraints:
        return None
    maximum_depths = [item.maximum_depth for item in constraints if item.maximum_depth is not None]
    return CausalConstraint(
        denied_labels=frozenset().union(*(item.denied_labels for item in constraints)),
        maximum_depth=min(maximum_depths) if maximum_depths else None,
        require_parent_if_tool_output=any(
            item.require_parent_if_tool_output for item in constraints
        ),
    )


def validate_causal_context(
    intent: ActionIntent,
    matched_rules: tuple[PolicyRule, ...],
    executions: ExecutionRepository,
    field_binding: FieldIntegrityBinding,
) -> tuple[str, int, frozenset[ProvenanceLabel]]:
    parent_ids = intent.causal_parent_execution_ids
    if len(parent_ids) > MAX_CAUSAL_PARENTS:
        raise CausalIntegrityError("causal.parent_limit_exceeded")
    if len(set(parent_ids)) != len(parent_ids):
        raise CausalIntegrityError("causal.parent_duplicate")

    parent_records = []
    inherited_labels: frozenset[ProvenanceLabel] = frozenset()
    parent_depth = -1
    for execution_id in parent_ids:
        record = executions.get_execution(execution_id)
        if record is None:
            raise CausalIntegrityError("causal.parent_missing")
        if record.tenant_id is not None and record.tenant_id != intent.principal.tenant_id:
            raise CausalIntegrityError("causal.parent_tenant_mismatch")
        if record.state.value in {"reserved", "dispatching"}:
            raise CausalIntegrityError("causal.parent_not_terminal")
        parent_records.append(record)
        inherited_labels = inherited_labels | record.causal_labels
        parent_depth = max(parent_depth, record.causal_depth)

    depth = parent_depth + 1 if parent_records else 0
    if depth > MAX_CAUSAL_DEPTH:
        raise CausalIntegrityError("causal.depth_exceeded")
    labels = inherited_labels | field_binding.labels

    constraint = _aggregate_constraints(matched_rules)
    if constraint is not None:
        if constraint.maximum_depth is not None and depth > constraint.maximum_depth:
            raise CausalIntegrityError("causal.policy_depth_exceeded")
        if labels & constraint.denied_labels:
            raise CausalIntegrityError("causal.denied_ancestry")
        if (
            constraint.require_parent_if_tool_output
            and ProvenanceLabel.TOOL_OUTPUT in field_binding.labels
            and not parent_records
        ):
            raise CausalIntegrityError("causal.tool_output_parent_required")

    payload = {
        "parents": [
            {
                "execution_id": record.execution_id,
                "causal_digest": record.causal_digest,
                "causal_depth": record.causal_depth,
                "causal_labels": record.causal_labels,
            }
            for record in sorted(parent_records, key=lambda item: item.execution_id)
        ],
        "depth": depth,
        "labels": labels,
        "tenant_id": intent.principal.tenant_id,
        "request_id": intent.request_id,
    }
    return digest(payload), depth, labels


def build_causal_execution_graph(
    root_execution_id: str, executions: ExecutionRepository
) -> CausalExecutionGraph:
    """Reconstruct a secret-minimized, integrity-checked declared causal ancestry graph."""

    nodes: dict[str, CausalGraphNode] = {}
    visiting: set[str] = set()

    def visit(execution_id: str, traversal_depth: int = 0) -> None:
        if traversal_depth > MAX_CAUSAL_DEPTH:
            raise CausalIntegrityError("causal.graph_depth_exceeded")
        if execution_id in nodes:
            return
        if execution_id in visiting:
            raise CausalIntegrityError("causal.graph_cycle")
        record = executions.get_execution(execution_id)
        if record is None:
            raise CausalIntegrityError("causal.graph_execution_missing")
        visiting.add(execution_id)
        for parent_id in record.causal_parent_execution_ids:
            visit(parent_id, traversal_depth + 1)
        visiting.remove(execution_id)
        nodes[execution_id] = CausalGraphNode(
            execution_id=record.execution_id,
            parent_execution_ids=record.causal_parent_execution_ids,
            intent_digest=record.intent_digest,
            causal_digest=record.causal_digest,
            causal_depth=record.causal_depth,
            labels=record.causal_labels,
            tenant_id=record.tenant_id,
            state=record.state,
        )

    visit(root_execution_id)
    ordered = tuple(nodes[key] for key in sorted(nodes))
    return CausalExecutionGraph(
        root_execution_id=root_execution_id,
        nodes=ordered,
        graph_digest=digest(
            {
                "root_execution_id": root_execution_id,
                "nodes": ordered,
            }
        ),
    )
