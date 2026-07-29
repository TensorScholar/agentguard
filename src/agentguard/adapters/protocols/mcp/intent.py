from __future__ import annotations
from datetime import datetime, timezone
from uuid import uuid4
from agentguard.domain import Action, ActionIntent, EffectProjection, Principal, ProvenanceLabel

def intent_from_tools_call(message:dict,*,principal:Principal,server:str,trace_id:str|None=None,provenance:tuple[ProvenanceLabel,...]=(ProvenanceLabel.UNVERIFIED,),provenance_verified:bool=False,tool_schema:dict|None=None)->ActionIntent:
    params=message.get("params")
    if not isinstance(params,dict): raise ValueError("tools/call params must be an object")
    name=params.get("name"); arguments=params.get("arguments",{})
    if not isinstance(name,str) or not name: raise ValueError("tools/call params.name is required")
    if not isinstance(arguments,dict): raise ValueError("tools/call arguments must be an object")
    request_id=str(message.get("id") or uuid4().hex)
    return ActionIntent(request_id=request_id,trace_id=trace_id or "trc_"+uuid4().hex,principal=principal,
      action=Action(protocol="mcp",server=server,tool=name,operation="call"),provenance=provenance,
      provenance_verified=provenance_verified,effects=EffectProjection(),arguments=arguments,
      tool_schema=tool_schema or {},requested_at=datetime.now(timezone.utc))
