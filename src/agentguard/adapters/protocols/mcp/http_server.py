from __future__ import annotations

import hmac
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from .http_gateway import MCPProtectedHTTPGateway
from .http_gateway_types import GatewayResponse, HTTPExchangeResponse, UpstreamTransportError
from .http_security import HTTPTransportSecurityError, validate_host, validate_origin
from .modern import (
    ModernMCPValidationError,
    canonical_standard_headers,
    parse_json_object,
    validate_modern_request_headers,
)


class HTTPXUpstreamSender:
    """Fixed-destination sender without ambient client headers, auth, redirects, or proxies."""

    def __init__(
        self,
        upstream_url: str,
        *,
        timeout_seconds: float = 30.0,
        max_response_bytes: int = 4_000_000,
    ) -> None:
        if timeout_seconds <= 0 or max_response_bytes < 1:
            raise ValueError("invalid upstream transport limits")
        self.upstream_url = upstream_url
        self.max_response_bytes = max_response_bytes
        self._client = httpx.Client(
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
            trust_env=False,
        )

    def send(self, body: bytes, headers: Any) -> HTTPExchangeResponse:
        try:
            with self._client.stream(
                "POST",
                self.upstream_url,
                content=body,
                headers=dict(headers),
            ) as response:
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_bytes():
                    size += len(chunk)
                    if size > self.max_response_bytes:
                        raise UpstreamTransportError("mcp_http.upstream_response_too_large")
                    chunks.append(chunk)
                return HTTPExchangeResponse(
                    status_code=response.status_code,
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body=b"".join(chunks),
                )
        except UpstreamTransportError:
            raise
        except httpx.RequestError as exc:
            raise UpstreamTransportError("mcp_http.upstream_request_failed") from exc

    def close(self) -> None:
        self._client.close()


class HTTPXStreamForwarder:
    def __init__(self, upstream_url: str, *, timeout_seconds: float = 30.0) -> None:
        timeout = httpx.Timeout(timeout_seconds, read=None)
        self.upstream_url = upstream_url
        self._client = httpx.AsyncClient(timeout=timeout, follow_redirects=False, trust_env=False)

    async def open(self, body: bytes, headers: dict[str, str]) -> httpx.Response:
        request = self._client.build_request(
            "POST",
            self.upstream_url,
            content=body,
            headers=headers,
        )
        try:
            return await self._client.send(request, stream=True)
        except httpx.RequestError as exc:
            raise UpstreamTransportError("mcp_http.upstream_stream_failed") from exc

    async def close(self) -> None:
        await self._client.aclose()


def create_protected_mcp_http_app(
    gateway: MCPProtectedHTTPGateway,
    *,
    allowed_hosts: frozenset[str],
    allowed_origins: frozenset[str] = frozenset(),
    require_origin: bool = False,
    access_token: str | None = None,
    stream_forwarder: HTTPXStreamForwarder | None = None,
    readiness_probe: Callable[[], bool] | None = None,
) -> Starlette:
    if not allowed_hosts:
        raise ValueError("at least one allowed Host is required")
    forwarder = stream_forwarder or HTTPXStreamForwarder(gateway.binding.upstream_url)

    async def health(_: Request) -> Response:
        return JSONResponse(
            {
                "ok": True,
                "transport": "streamable_http",
                "protocol": "2026-07-28",
                "server_id": gateway.binding.server_id,
            }
        )

    async def live(_: Request) -> Response:
        return JSONResponse({"ok": True})

    async def ready(_: Request) -> Response:
        if readiness_probe is None:
            return JSONResponse({"ok": True})
        try:
            is_ready = bool(await run_in_threadpool(readiness_probe))
        except Exception:
            is_ready = False
        return JSONResponse({"ok": is_ready}, status_code=200 if is_ready else 503)

    async def mcp(request: Request) -> Response:
        security_error = _validate_request_security(
            request,
            allowed_hosts=allowed_hosts,
            allowed_origins=allowed_origins,
            require_origin=require_origin,
            access_token=access_token,
        )
        if security_error is not None:
            return security_error
        content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            return JSONResponse({"error": "content_type_required"}, status_code=415)
        body = await _read_bounded_body(request, gateway.max_message_bytes)
        if body is None:
            return JSONResponse({"error": "request_too_large"}, status_code=413)
        try:
            message = parse_json_object(body, max_bytes=gateway.max_message_bytes)
            validate_modern_request_headers(message, request.headers)
        except ModernMCPValidationError:
            result = gateway.handle(body, request.headers)
            return _gateway_response(result)

        if message.get("method") == "subscriptions/listen":
            return await _stream_subscription(message, body, forwarder)
        result = await run_in_threadpool(gateway.handle, body, request.headers)
        return _gateway_response(result)

    @asynccontextmanager
    async def lifespan(_: Starlette) -> AsyncIterator[None]:
        try:
            yield
        finally:
            await forwarder.close()
            sender = gateway.sender
            close = getattr(sender, "close", None)
            if callable(close):
                close()

    return Starlette(
        routes=[
            Route("/healthz", health, methods=["GET"]),
            Route("/livez", live, methods=["GET"]),
            Route("/readyz", ready, methods=["GET"]),
            Route("/mcp", mcp, methods=["POST"]),
        ],
        lifespan=lifespan,
    )


def _validate_request_security(
    request: Request,
    *,
    allowed_hosts: frozenset[str],
    allowed_origins: frozenset[str],
    require_origin: bool,
    access_token: str | None,
) -> Response | None:
    try:
        validate_host(request.headers.get("host", ""), allowed_hosts)
        validate_origin(
            request.headers.get("origin"),
            allowed_origins,
            browser_reachable=require_origin,
        )
    except HTTPTransportSecurityError as exc:
        return JSONResponse({"error": str(exc)}, status_code=403)
    if access_token is None:
        return None
    authorization = request.headers.get("authorization", "")
    expected = f"Bearer {access_token}"
    if not hmac.compare_digest(authorization, expected):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return None


async def _read_bounded_body(request: Request, max_bytes: int) -> bytes | None:
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > max_bytes:
            return None
        chunks.append(chunk)
    return b"".join(chunks)


async def _stream_subscription(
    message: dict[str, Any],
    body: bytes,
    forwarder: HTTPXStreamForwarder,
) -> Response:
    if message.get("id") is None:
        return JSONResponse(
            {"error": "subscriptions/listen requires a request id"}, status_code=400
        )
    try:
        response = await forwarder.open(body, canonical_standard_headers(message))
    except UpstreamTransportError:
        return JSONResponse({"error": "upstream_stream_unavailable"}, status_code=502)
    content_type = response.headers.get("content-type", "").lower()
    if "text/event-stream" not in content_type:
        payload = await response.aread()
        await response.aclose()
        return Response(
            payload,
            status_code=response.status_code,
            headers={"content-type": response.headers.get("content-type", "application/json")},
        )

    async def iterator() -> AsyncIterator[bytes]:
        try:
            async for chunk in response.aiter_bytes():
                yield chunk
        finally:
            await response.aclose()

    headers = {"content-type": response.headers.get("content-type", "text/event-stream")}
    cache_control = response.headers.get("cache-control")
    if cache_control is not None:
        headers["cache-control"] = cache_control
    return StreamingResponse(
        iterator(),
        status_code=response.status_code,
        headers=headers,
        media_type=None,
    )


def _gateway_response(result: GatewayResponse) -> Response:
    return Response(
        result.body,
        status_code=result.status_code,
        headers=result.headers,
        media_type=None,
    )
