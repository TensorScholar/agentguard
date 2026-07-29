from __future__ import annotations
from agentguard.domain import Effect
from agentguard.domain.policy import ActionMatcher, PolicyDefaults, PolicyDocument, PolicyMetadata, PolicyRule

def migrate_policy_v1(raw:dict)->PolicyDocument:
    rules=[]
    for index,name in enumerate(raw.get("denied_tools",[]) or []):
        rules.append(PolicyRule(id=f"legacy-deny-tool-{index+1}",priority=1000,effect=Effect.DENY,action=ActionMatcher(tools=frozenset({str(name)})),reason_code="legacy.tool.denied"))
    allowed=raw.get("allowed_tools",[]) or []
    for index,name in enumerate(allowed):
        rules.append(PolicyRule(id=f"legacy-allow-tool-{index+1}",priority=100,effect=Effect.ALLOW,action=ActionMatcher(tools=frozenset({str(name)})),reason_code="legacy.tool.allowed"))
    return PolicyDocument(metadata=PolicyMetadata(id="migrated-policy-v1",revision=1),defaults=PolicyDefaults(),rules=tuple(rules))
