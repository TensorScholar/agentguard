"""Run the DecisionLock happy path end to end against a local fake provider.

Standard library only; not part of the DecisionLock package.

    python examples/harness/run_demo.py            # scenarios A, B, C
    python examples/harness/run_demo.py --list

This drives the real product commands as subprocesses -- decisionlock-mcp-http,
decisionlock-reconcile-worker, evidence-build, evidence-verify -- rather than calling
the library, so what you see is what an operator would get.

Scenarios
    A  argument mutation blocked      receipt digest revalidation rejects tampered args
    B  receipt replay blocked        second dispatch of a consumed decision is refused
    C  authorized side effect        a real refund.create is admitted and dispatched
    D  evidence export + verify      bundle signed, verified offline, tamper detected
    E  ambiguous effect              provider commits then drops -> UNKNOWN
    F  reconcile before retry        provider status tool resolves the UNKNOWN

What this demo proves, and what it does not
    Proves: ceiling-scoped credentials resolve late and never reach durable state;
            tampered arguments and replayed receipts are refused with stable codes; an
            ambiguous outcome is recorded UNKNOWN rather than guessed; reconciliation
            requires provider evidence and does not redispatch.

    Does not prove: anything about a real payment provider. The fake provider keeps its
    own ledger, and its "confirmation" is its own state, not an attestation from Stripe
    or anyone else. This is not a certification, a benchmark, or a substitute for a
    penetration test or a production pilot.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATEWAY_PORT = int(os.environ.get("AG_DEMO_GATEWAY_PORT", "8765"))
PROVIDER_PORT = int(os.environ.get("AG_DEMO_PROVIDER_PORT", "9010"))
GATEWAY = f"http://127.0.0.1:{GATEWAY_PORT}/mcp"
PROVIDER = f"http://127.0.0.1:{PROVIDER_PORT}/mcp"
PROTOCOL = "2026-07-28"
ACCESS_TOKEN = "demo-access-token"
PAYMENTS_TOKEN = "sk-live-DEMOSECRET-do-not-use-in-production-0000"
BUDGET = 8500

_passed: list[str] = []
_failed: list[str] = []


def step(name: str) -> None:
    print(f"\n\033[1m== {name}\033[0m")


def ok(name: str, detail: object = "") -> None:
    _passed.append(name)
    text = str(detail) if detail else ""
    print(f"   \033[32mPASS\033[0m {name}{(' -- ' + text) if text else ''}")


def bad(name: str, detail: object = "") -> None:
    _failed.append(name)
    text = str(detail) if detail else ""
    print(f"   \033[31mFAIL\033[0m {name}{(' -- ' + text) if text else ''}")


def expect(name: str, condition: bool, detail: str = "") -> None:
    (ok if condition else bad)(name, detail)


def free_port(port: int) -> int:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return port
        except OSError:
            with socket.socket() as s2:
                s2.bind(("127.0.0.1", 0))
                return int(s2.getsockname()[1])


def run(argv: list[str], cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=120, check=False
    )


def post(url: str, payload: dict, token: str | None = None, timeout: float = 10.0) -> dict:
    data = json.dumps(payload).encode()
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("content-type", "application/json")
    request.add_header("mcp-protocol-version", PROTOCOL)
    request.add_header("Mcp-Method", str(payload.get("method", "")))
    # tools/call mirrors the tool name into a required header.
    params = payload.get("params")
    if isinstance(params, dict) and isinstance(params.get("name"), str):
        request.add_header("Mcp-Name", params["name"])
    if token:
        request.add_header("authorization", f"Bearer {token}")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode())


def refund_call(amount: int, request_id: str, timeout: float = 10.0) -> dict:
    """Send one refund.create through the protected gateway."""

    return post(
        GATEWAY,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "refund.create",
                "arguments": {
                    "order_id": "order-1042",
                    "amount_minor": amount,
                    "currency": "USD",
                    "requestId": request_id,
                },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": PROTOCOL,
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {"name": "ag-demo", "version": "1.0"},
                },
            },
        },
        token=ACCESS_TOKEN,
        timeout=timeout,
    )


def wait_for_tcp(port: int, attempts: int = 60, delay: float = 0.25) -> bool:
    """Poll until a TCP port accepts connections."""

    for _ in range(attempts):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            time.sleep(delay)
    return False


def wait_for_http(url: str, attempts: int = 60, delay: float = 0.25) -> bool:
    """Poll a documented readiness probe until it reports ready."""

    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=2.0) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError, ValueError):
            pass
        time.sleep(delay)
    return False


def read_ledger(path: Path) -> list[dict]:
    """Parse the fake provider's own durable ledger -- its business truth."""

    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def sql(db: Path, query: str) -> list[tuple]:
    import sqlite3

    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        return list(con.execute(query))
    finally:
        con.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the DecisionLock happy-path demo")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    parser.add_argument("--keep", action="store_true", help="keep the demo workspace")
    args = parser.parse_args()

    if args.list:
        for item in (
            "A argument mutation blocked",
            "B receipt replay blocked",
            "C authorized side effect dispatched",
            "D evidence export + offline verify + tamper detected",
            "E ambiguous effect recorded UNKNOWN (no blind retry)",
            "F reconcile-before-retry via provider status tool",
        ):
            print("  " + item)
        return 0

    workdir = Path.cwd() / ".decisionlock-demo"
    if workdir.exists():
        shutil.rmtree(workdir)
    (workdir / "provider").mkdir(parents=True)
    ledger = workdir / "provider" / "provider-ledger.jsonl"

    env = dict(os.environ)
    env["DECISIONLOCK_HTTP_ACCESS_TOKEN"] = ACCESS_TOKEN
    env["PAYMENTS_TOKEN"] = PAYMENTS_TOKEN
    decisionlock = shutil.which("decisionlock")
    mcp_http = shutil.which("decisionlock-mcp-http")
    reconcile_worker = shutil.which("decisionlock-reconcile-worker")

    # ---------------------------------------------------------------- setup
    step("Setup")
    if decisionlock is None or mcp_http is None or reconcile_worker is None:
        bad(
            "decisionlock entrypoints on PATH",
            "pip install -e '.[http]' first (the http extra provides decisionlock-mcp-http)",
        )
        return 1
    ok("decisionlock on PATH", decisionlock)
    ok("decisionlock-mcp-http on PATH", mcp_http)
    ok("decisionlock-reconcile-worker on PATH", reconcile_worker)

    demo = run([decisionlock, "demo", "--output", str(workdir / "demo"), "--force"], workdir, env)
    expect("decisionlock demo generates fixtures", demo.returncode == 0, demo.stderr.strip()[:120])

    init = run([decisionlock, "init", "--output", str(workdir / "ws")], workdir, env)
    expect(
        "decisionlock init creates the production credential broker key",
        init.returncode == 0 and (workdir / "ws" / "credential-broker-private.pem").is_file(),
    )

    policy = HERE / "policy.yaml"
    status_schema = workdir / "refund-status.schema.json"
    status_schema.write_text(
        json.dumps(
            {
                "name": "refund.status",
                "description": "Read the refund status record for a previously submitted refund.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"requestId": {"type": "string"}},
                    "required": ["requestId"],
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    provider = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            str(HERE / "provider.py"),
            "--port",
            str(PROVIDER_PORT),
            "--ledger",
            str(ledger),
            "--ambiguous",
            "--ambiguous-for",
            "demo-ambiguous",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    gateway = None
    try:
        if not wait_for_tcp(PROVIDER_PORT):
            bad("fake provider started")
            return 1
        ok("fake provider started", PROVIDER)

        gateway = subprocess.Popen(  # noqa: S603
            [
                mcp_http,
                "--policy",
                str(policy),
                "--key",
                str(workdir / "demo" / "private.pem"),
                "--state",
                str(workdir / "demo" / "action-integrity.sqlite"),
                "--provider-reconciliation-state",
                str(workdir / "demo" / "provider-reconciliation.sqlite"),
                "--credential-state",
                str(workdir / "demo" / "credential-state.sqlite"),
                "--credential-key",
                str(workdir / "ws" / "credential-broker-private.pem"),
                "--credential-env",
                "PAYMENTS_TOKEN",
                "--credential-audience",
                "payments.internal",
                "--credential-scope",
                "refund:create",
                "--server-id",
                "customer-operations",
                "--upstream-url",
                PROVIDER,
                "--tenant-id",
                "acme",
                "--port",
                str(GATEWAY_PORT),
                "--timeout-seconds",
                "5",
                "--provenance",
                "authenticated_user_input",
                "--provenance-verified",
            ],
            cwd=workdir,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.0)
        if not wait_for_http(f"http://127.0.0.1:{GATEWAY_PORT}/readyz"):
            bad("protected gateway reported ready")
            return 1
        ok(
            "protected gateway ready with production credential authority",
            f"/readyz on {GATEWAY_PORT}",
        )

        # ---------------------------------------------------- A mutation
        step("A. Argument mutation is blocked")
        intent = json.loads((workdir / "demo" / "intent.json").read_text())
        decision = run(
            [
                decisionlock,
                "authorize",
                str(workdir / "demo" / "intent.json"),
                str(policy),
                "--key",
                str(workdir / "demo" / "private.pem"),
                "--ledger",
                str(workdir / "demo" / "audit.sqlite"),
                "--output",
                str(workdir / "decision.json"),
            ],
            workdir,
            env,
        )
        expect("authorize issues a signed receipt", decision.returncode == 0)

        mutated = json.loads(json.dumps(intent))
        for target in (mutated, mutated.get("effects", {}), mutated.get("arguments", {})):
            if isinstance(target, dict) and "amount_minor" in target:
                target["amount_minor"] = 85000
        mutated_path = workdir / "intent-mutated.json"
        mutated_path.write_text(json.dumps(mutated, indent=2), encoding="utf-8")

        mutated_result = run(
            [
                decisionlock,
                "verify-execution",
                str(mutated_path),
                str(workdir / "decision.json"),
                str(policy),
                "--public-key",
                str(workdir / "demo" / "public.pem"),
            ],
            workdir,
            env,
        )
        combined = mutated_result.stdout + mutated_result.stderr
        expect(
            "tampered amount refused with execution.arguments_digest_mismatch",
            mutated_result.returncode != 0 and "arguments_digest_mismatch" in combined,
            combined.strip().splitlines()[-1][:90] if combined.strip() else "",
        )
        expect(
            "no Rich traceback leaks the reason code",
            "Traceback" not in combined and "╭" not in combined,
        )

        # ---------------------------------------------------- C authorized effect
        step("C. Authorized side effect is dispatched")
        result = refund_call(BUDGET, "demo-authorized")
        dispatched = "result" in result
        expect("refund.create admitted and dispatched", dispatched, json.dumps(result)[:100])
        records = [json.loads(line) for line in ledger.read_text().splitlines() if line.strip()]
        expect("provider recorded exactly one refund", len(records) == 1, f"{len(records)}")
        if dispatched and records:
            expect(
                "provider committed the authorized amount",
                records[0]["amount_minor"] == BUDGET,
                f"amount_minor={records[0]['amount_minor']}",
            )

        step("Credential handling")
        leaked = []
        for db in sorted((workdir / "demo").glob("*.sqlite")):
            if PAYMENTS_TOKEN.encode() in db.read_bytes():
                leaked.append(db.name)
        expect("secret never written to any durable sqlite state", not leaked, ",".join(leaked))
        public_ledger = (workdir / "provider" / "provider-ledger.jsonl").read_text()
        expect("secret never written to the provider ledger", PAYMENTS_TOKEN not in public_ledger)

        # ---------------------------------------------------- B replay
        step("B. Receipt replay is blocked")
        demo_results = json.loads((workdir / "demo" / "results.json").read_text())
        expect(
            "second dispatch of a consumed receipt refused (decision_receipt.replayed)",
            demo_results.get("replay") == "decision_receipt.replayed",
            str(demo_results.get("replay")),
        )
        expect(
            "scope inflation refused (credential.scope_exceeds_decision)",
            demo_results.get("excessive_scope") == "credential.scope_exceeds_decision",
            str(demo_results.get("excessive_scope")),
        )

        # ---------------------------------------------------- D evidence
        step("D. Evidence export, offline verify, tamper detection")
        bundle = workdir / "evidence"
        build = run(
            [
                decisionlock,
                "evidence-build",
                str(workdir / "demo" / "intent.json"),
                str(workdir / "decision.json"),
                "--key",
                str(workdir / "demo" / "private.pem"),
                "--output",
                str(bundle),
            ],
            workdir,
            env,
        )
        expect("evidence-build produces a signed bundle", build.returncode == 0)
        verify = run(
            [
                decisionlock,
                "evidence-verify",
                str(bundle),
                "--public-key",
                str(workdir / "demo" / "public.pem"),
                "--require-signature",
            ],
            workdir,
            env,
        )
        payload = {}
        try:
            payload = json.loads(verify.stdout)
        except json.JSONDecodeError:
            pass
        expect(
            "offline verify: signature verified",
            verify.returncode == 0 and payload.get("signature_verified") is True,
            json.dumps(payload),
        )
        bundle_secret = any(
            PAYMENTS_TOKEN in p.read_text(errors="ignore") for p in bundle.rglob("*") if p.is_file()
        )
        expect("evidence bundle contains no secret material", not bundle_secret)

        tampered = workdir / "evidence-tampered"
        shutil.copytree(bundle, tampered)
        receipt_file = tampered / "decision-receipt.json"
        doc = json.loads(receipt_file.read_text())
        ceiling = doc.get("credential_ceiling") or {}
        ceiling["scopes"] = sorted(set(ceiling.get("scopes", [])) | {"admin"})
        doc["credential_ceiling"] = ceiling
        receipt_file.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        tamper = run(
            [
                decisionlock,
                "evidence-verify",
                str(tampered),
                "--public-key",
                str(workdir / "demo" / "public.pem"),
                "--require-signature",
            ],
            workdir,
            env,
        )
        combined = tamper.stdout + tamper.stderr
        expect(
            "escalated credential ceiling in the bundle is detected",
            tamper.returncode != 0 and "mismatch" in combined,
            [line for line in combined.splitlines() if "mismatch" in line][:1],
        )

        # ---------------------------------------------------- E ambiguous
        step("E. Ambiguous effect stays UNKNOWN and is not retried")
        before = len(read_ledger(ledger))
        ambiguous = refund_call(9900, "demo-ambiguous")
        data = (ambiguous.get("error") or {}).get("data") or {}
        expect(
            "gateway refuses to guess (code -32004, retry_safe false)",
            ambiguous.get("error", {}).get("code") == -32004 and data.get("retry_safe") is False,
            ambiguous.get("error", {}).get("message", "")[:80],
        )
        execution_id = data.get("execution_id", "")
        after_records = read_ledger(ledger)
        expect(
            "provider actually committed despite the dropped connection",
            len(after_records) == before + 1,
            f"{before} -> {len(after_records)}",
        )
        states = dict(
            sql(
                workdir / "demo" / "action-integrity.sqlite",
                "SELECT execution_id, state FROM executions",
            )
        )
        expect(
            "DecisionLock recorded the execution as unknown",
            states.get(execution_id) == "unknown",
            f"{execution_id} -> {states.get(execution_id)}",
        )

        # ---------------------------------------------------- F reconcile
        step("F. Reconcile-before-retry via the provider status tool")
        reconcile = run(
            [
                reconcile_worker,
                "--state",
                str(workdir / "demo" / "action-integrity.sqlite"),
                "--provider-reconciliation-state",
                str(workdir / "demo" / "provider-reconciliation.sqlite"),
                "--key",
                str(workdir / "demo" / "private.pem"),
                "--server-id",
                "customer-operations",
                "--upstream-url",
                PROVIDER,
                "--status-tool",
                "refund.status",
                "--status-schema",
                str(status_schema),
                "--timeout-seconds",
                "5",
                "--once",
            ],
            workdir,
            env,
        )
        tick = {}
        for line in reconcile.stdout.splitlines():
            try:
                tick = json.loads(line)
            except json.JSONDecodeError:
                continue
        expect(
            "reconciler claimed and resolved the UNKNOWN execution",
            tick.get("reconciled") == 1 and tick.get("claimed") == 1,
            json.dumps(tick)[:120],
        )

        import sqlite3 as _s

        con = _s.connect(f"file:{workdir / 'demo' / 'action-integrity.sqlite'}?mode=ro", uri=True)
        try:
            names = [d[1] for d in con.execute("PRAGMA table_info(execution_resolutions)")]
            found = [
                dict(zip(names, r))
                for r in con.execute(
                    "SELECT * FROM execution_resolutions WHERE execution_id = ?", (execution_id,)
                )
            ]
        finally:
            con.close()
        resolution = found[0] if found else {}
        expect(
            "resolution is confirmed_succeeded at PROVIDER_VERIFIED trust",
            resolution.get("status") == "confirmed_succeeded"
            and resolution.get("trust_level") == "provider_verified",
            f"{resolution.get('status')}/{resolution.get('trust_level')}",
        )

        final_records = read_ledger(ledger)
        expect(
            "reconciliation did not redispatch -- still exactly 2 refunds",
            len(final_records) == 2,
            f"{len(final_records)}",
        )

        # ---------------------------------------------------- refuse
        step("Operator reconcile path refuses to assert provider truth from a file")
        forged = workdir / "forged-evidence.json"
        forged.write_text(
            json.dumps(
                {
                    "status": "confirmed_succeeded",
                    "source": "operator-typed-it-in",
                    "evidence_digest": "sha256:" + "0" * 64,
                    "observed_at": "2026-01-01T00:00:00Z",
                    "trust_level": "provider_verified",
                    "provider_operation_id": "ch_forged",
                }
            ),
            encoding="utf-8",
        )
        refused = run(
            [
                decisionlock,
                "reconcile-execution",
                "--execution-id",
                execution_id,
                "--evidence",
                str(forged),
                "--state",
                str(workdir / "demo" / "action-integrity.sqlite"),
                "--key",
                str(workdir / "demo" / "private.pem"),
            ],
            workdir,
            env,
        )
        expect(
            "file-supplied PROVIDER_VERIFIED evidence is rejected",
            refused.returncode != 0 and "provider-verified" in (refused.stdout + refused.stderr),
            next(
                (ln for ln in (refused.stdout + refused.stderr).splitlines() if "provider" in ln),
                "",
            ),
        )

    finally:
        for process in (gateway, provider):
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()

    step("Summary")
    print(f"   passed: {len(_passed)}   failed: {len(_failed)}")
    if _failed:
        for name in _failed:
            print(f"     FAIL {name}")
        print(f"\n   workspace kept at {workdir}")
        return 1
    if not args.keep:
        shutil.rmtree(workdir, ignore_errors=True)
    else:
        print(f"\n   workspace kept at {workdir}")
    print("\n   Reminder: the fake provider's own ledger is not an external attestation.")
    print("   Nothing here is a certification, benchmark, or substitute for a")
    print("   penetration test or production pilot.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
