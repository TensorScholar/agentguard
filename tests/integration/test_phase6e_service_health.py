from __future__ import annotations

from types import SimpleNamespace

from starlette.testclient import TestClient

from decisionlock.adapters.protocols.mcp.http_server import create_protected_mcp_http_app


class FakeSender:
    def close(self) -> None:
        return None


class FakeForwarder:
    async def close(self) -> None:
        return None


class FakeGateway:
    def __init__(self) -> None:
        self.binding = SimpleNamespace(
            upstream_url="https://provider.example/mcp",
            server_id="provider",
        )
        self.sender = FakeSender()
        self.max_message_bytes = 1024


def _app(probe):
    return create_protected_mcp_http_app(
        FakeGateway(),  # type: ignore[arg-type]
        allowed_hosts=frozenset({"testserver"}),
        stream_forwarder=FakeForwarder(),  # type: ignore[arg-type]
        readiness_probe=probe,
    )


def test_liveness_is_process_only_while_readiness_reports_dependency_state() -> None:
    with TestClient(_app(lambda: False)) as client:
        live = client.get("/livez")
        ready = client.get("/readyz")
        assert live.status_code == 200
        assert live.json() == {"ok": True}
        assert ready.status_code == 503
        assert ready.json() == {"ok": False}


def test_readiness_success_and_probe_exception_are_explicit() -> None:
    with TestClient(_app(lambda: True)) as client:
        response = client.get("/readyz")
        assert response.status_code == 200
        assert response.json() == {"ok": True}

    def broken() -> bool:
        raise RuntimeError("database unavailable")

    with TestClient(_app(broken)) as client:
        response = client.get("/readyz")
        assert response.status_code == 503
        assert response.json() == {"ok": False}


def test_legacy_health_endpoint_remains_compatible() -> None:
    with TestClient(_app(None)) as client:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {
            "ok": True,
            "transport": "streamable_http",
            "protocol": "2026-07-28",
            "server_id": "provider",
        }
        assert client.get("/readyz").status_code == 200
