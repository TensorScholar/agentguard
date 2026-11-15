from __future__ import annotations

import json
from datetime import UTC, datetime

from typer.testing import CliRunner

from decisionlock.adapters.broker import MockCredentialBroker
from decisionlock.adapters.crypto import Ed25519Signer, Ed25519Verifier
from decisionlock.adapters.executor import DeterministicFakeExecutor
from decisionlock.adapters.storage.sqlite import SQLiteState
from decisionlock.application import DecisionLockService
from decisionlock.cli.app import app
from decisionlock.domain import (
    CredentialRequest,
    EvidenceTrustLevel,
    ReconciliationEvidence,
    ReconciliationStatus,
)
from decisionlock.engine.canonical import digest

runner = CliRunner()


def _create_unknown(intent, policy, workspace, state_path):
    signer = Ed25519Signer.load_private(workspace / "decision-private.pem")
    verifier = Ed25519Verifier({signer.key_id: signer.public_key()})
    broker = MockCredentialBroker()
    state = SQLiteState(state_path)
    service = DecisionLockService(signer, verifier, state, broker.verifier)
    receipt = service.authorize(intent, policy)
    ceiling = receipt.credential_ceiling
    request = CredentialRequest(
        request_id="cli-phase5c-credential",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=30,
        tenant_id=ceiling.tenant_id,
    )
    grant = service.request_credential(intent, receipt, request, broker)
    return service.execute_protected(
        intent,
        receipt,
        grant,
        DeterministicFakeExecutor(mode="unknown"),
        current_policy=policy,
    ).execution_id


def test_attestation_and_reconciliation_cli_round_trip(tmp_path, intent, policy):
    workspace = tmp_path / "workspace"
    init = runner.invoke(app, ["init", "--output", str(workspace)])
    assert init.exit_code == 0, init.stdout
    assert (workspace / "attestation-private.pem").exists()
    assert (workspace / "authority-private.pem").exists()

    state_path = tmp_path / "state.sqlite"
    execution_id = _create_unknown(intent, policy, workspace, state_path)

    first_attestation = tmp_path / "before.json"
    result = runner.invoke(
        app,
        [
            "attest-execution",
            "--execution-id",
            execution_id,
            "--state",
            str(state_path),
            "--key",
            str(workspace / "attestation-private.pem"),
            "--output",
            str(first_attestation),
        ],
    )
    assert result.exit_code == 0, result.stdout

    verify = runner.invoke(
        app,
        [
            "verify-attestation",
            str(first_attestation),
            "--public-key",
            str(workspace / "attestation-public.pem"),
        ],
    )
    assert verify.exit_code == 0, verify.stdout
    assert '"ok": true' in verify.stdout.lower()

    provider_verified = ReconciliationEvidence(
        status=ReconciliationStatus.CONFIRMED_SUCCEEDED,
        source="provider-status-api",
        evidence_digest=digest({"provider": "success"}),
        observed_at=datetime.now(UTC),
        trust_level=EvidenceTrustLevel.PROVIDER_VERIFIED,
    )
    evidence_path = tmp_path / "evidence.json"
    evidence_path.write_text(provider_verified.model_dump_json(), encoding="utf-8")
    rejected = runner.invoke(
        app,
        [
            "reconcile-execution",
            "--execution-id",
            execution_id,
            "--evidence",
            str(evidence_path),
            "--state",
            str(state_path),
            "--key",
            str(workspace / "decision-private.pem"),
        ],
    )
    assert rejected.exit_code != 0
    assert "file-supplied evidence cannot assert" in rejected.output

    manual_evidence = ReconciliationEvidence(
        status=ReconciliationStatus.STILL_UNKNOWN,
        source="manual-observation",
        evidence_digest=digest({"manual": "still-unknown"}),
        observed_at=datetime.now(UTC),
        trust_level=EvidenceTrustLevel.DECISIONLOCK_SIGNED,
    )
    evidence_path.write_text(manual_evidence.model_dump_json(), encoding="utf-8")
    reconcile = runner.invoke(
        app,
        [
            "reconcile-execution",
            "--execution-id",
            execution_id,
            "--evidence",
            str(evidence_path),
            "--state",
            str(state_path),
            "--key",
            str(workspace / "decision-private.pem"),
        ],
    )
    assert reconcile.exit_code == 0, reconcile.stdout
    assert "still_unknown" in reconcile.stdout

    second_attestation = tmp_path / "after.json"
    result = runner.invoke(
        app,
        [
            "attest-execution",
            "--execution-id",
            execution_id,
            "--state",
            str(state_path),
            "--key",
            str(workspace / "attestation-private.pem"),
            "--output",
            str(second_attestation),
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(second_attestation.read_text())
    assert payload["payload"]["resolution"]["status"] == "still_unknown"
    assert payload["payload"]["previous_attestation_digest"] is not None


def test_authority_cli_issues_grant_lease_and_reference(tmp_path, intent):
    workspace = tmp_path / "workspace"
    assert runner.invoke(app, ["init", "--output", str(workspace)]).exit_code == 0
    state_path = tmp_path / "state.sqlite"
    principal_path = tmp_path / "principal.json"
    scope_path = tmp_path / "scope.json"
    principal_path.write_text(intent.principal.model_dump_json(), encoding="utf-8")
    scope_path.write_text(
        json.dumps(
            {
                "capabilities": ["financial_mutation"],
                "protocols": ["mcp"],
                "servers": ["customer-operations"],
                "tools": ["refund.create"],
                "operations": ["call"],
                "resource_types": ["order"],
                "resource_ids": ["order-1042"],
                "maximum_calls": 2,
                "delegable": True,
                "maximum_delegation_depth": 1,
            }
        ),
        encoding="utf-8",
    )
    grant_path = tmp_path / "grant.json"
    issue = runner.invoke(
        app,
        [
            "authority-issue-root",
            "--principal",
            str(principal_path),
            "--scope",
            str(scope_path),
            "--state",
            str(state_path),
            "--key",
            str(workspace / "authority-private.pem"),
            "--output",
            str(grant_path),
        ],
    )
    assert issue.exit_code == 0, issue.stdout
    grant_id = json.loads(grant_path.read_text())["grant_id"]

    lease_path = tmp_path / "lease.json"
    lease = runner.invoke(
        app,
        [
            "authority-lease",
            "--grant-id",
            grant_id,
            "--holder",
            str(principal_path),
            "--maximum-uses",
            "1",
            "--state",
            str(state_path),
            "--key",
            str(workspace / "authority-private.pem"),
            "--output",
            str(lease_path),
        ],
    )
    assert lease.exit_code == 0, lease.stdout
    lease_id = json.loads(lease_path.read_text())["lease_id"]

    reference_path = tmp_path / "reference.json"
    reference = runner.invoke(
        app,
        [
            "authority-reference",
            "--grant-id",
            grant_id,
            "--lease-id",
            lease_id,
            "--state",
            str(state_path),
            "--key",
            str(workspace / "authority-private.pem"),
            "--output",
            str(reference_path),
        ],
    )
    assert reference.exit_code == 0, reference.stdout
    value = json.loads(reference_path.read_text())
    assert value["grant_id"] == grant_id
    assert value["lease_id"] == lease_id
    assert value["chain_digest"].startswith("sha256:")
