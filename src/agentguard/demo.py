from __future__ import annotations

import json
import shutil
from pathlib import Path

import yaml

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.evidence import build_bundle
from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.application import AgentGuardService
from agentguard.compatibility.v1_demo import write_demo
from agentguard.domain import ActionIntent, CredentialRequest, PolicyDocument
from agentguard.engine.execution import ExecutionGuardError, authorize_execution
from agentguard.security.files import secure_atomic_write

RESOURCE_ROOT = Path(__file__).parent / "resources"


def create_demo(output: Path, force: bool = False) -> None:
    if output.exists():
        if not force:
            raise FileExistsError(output)
        shutil.rmtree(output)
    output.mkdir(parents=True)
    raw_policy = yaml.safe_load((RESOURCE_ROOT / "default_policy_v2.yaml").read_text())
    policy = PolicyDocument.model_validate_json(json.dumps(raw_policy))
    intent = ActionIntent.model_validate_json((RESOURCE_ROOT / "demo-intent.json").read_text())
    signer = Ed25519Signer.generate()
    signer.save_private(output / "private.pem")
    signer.save_public(output / "public.pem")
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    state = SQLiteState(output / "audit.sqlite")
    broker = MockCredentialBroker()
    service = AgentGuardService(signer, verifier, state, broker.verifier)
    receipt = service.authorize(intent, policy)
    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    request = CredentialRequest(
        request_id="cred_" + intent.request_id,
        trace_id=intent.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=30,
        tenant_id=ceiling.tenant_id,
    )
    grant = service.request_credential(intent, receipt, request, broker)
    authorize_execution(
        intent,
        receipt,
        grant,
        verifier,
        state,
        broker_grant_verifier=broker.verifier,
        current_policy=policy,
    )

    mutated = intent.model_copy(update={"arguments": {**intent.arguments, "amount_minor": 85000}})
    mutation_result = "unexpected_allow"
    try:
        authorize_execution(
            mutated,
            receipt,
            grant,
            verifier,
            SQLiteState(output / "mutation.sqlite"),
            broker_grant_verifier=broker.verifier,
            current_policy=policy,
        )
    except ExecutionGuardError as exc:
        mutation_result = str(exc)

    excessive_scope_result = "unexpected_allow"
    inflated_grant = broker.attest_for_testing(
        grant.model_copy(update={"scopes": grant.scopes | {"payments:admin"}})
    )
    try:
        authorize_execution(
            intent,
            receipt,
            inflated_grant,
            verifier,
            SQLiteState(output / "scope-inflation.sqlite"),
            broker_grant_verifier=broker.verifier,
            current_policy=policy,
        )
    except ExecutionGuardError as exc:
        excessive_scope_result = str(exc)

    replay_result = "unexpected_allow"
    try:
        authorize_execution(
            intent,
            receipt,
            grant,
            verifier,
            state,
            broker_grant_verifier=broker.verifier,
            current_policy=policy,
        )
    except ExecutionGuardError as exc:
        replay_result = str(exc)

    files = [
        ("policy.yaml", yaml.safe_dump(policy.model_dump(mode="json"), sort_keys=False)),
        ("intent.json", intent.model_dump_json(indent=2)),
        ("receipt.json", receipt.model_dump_json(indent=2)),
        ("grant.json", grant.model_dump_json(indent=2)),
    ]
    for name, value in files:
        secure_atomic_write(output / name, (value + "\n").encode("utf-8"), mode=0o600)
    results = {
        "happy_path": "authorized",
        "argument_mutation": mutation_result,
        "excessive_scope": excessive_scope_result,
        "replay": replay_result,
        "audit": state.verify(),
    }
    secure_atomic_write(
        output / "results.json",
        (json.dumps(results, indent=2) + "\n").encode("utf-8"),
        mode=0o600,
    )
    build_bundle(
        output / "evidence",
        {
            "intent.json": intent,
            "receipt.json": receipt,
            "grant.json": grant,
            "results.json": results,
        },
        signer=signer,
    )
    write_demo(output / "v1-compat")
    secure_atomic_write(
        output / "README.md",
        (
            "# AgentGuard meeting demo\n\n"
            "Shows a scoped authorization, opaque broker grant, argument-mutation rejection, "
            "scope-inflation rejection, replay rejection, and verifiable evidence.\n"
        ).encode("utf-8"),
        mode=0o600,
    )


__all__ = ["create_demo", "write_demo"]
