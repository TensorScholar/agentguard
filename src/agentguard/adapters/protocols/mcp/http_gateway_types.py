from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Protocol


@dataclass(frozen=True)
class HTTPExchangeResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes


@dataclass(frozen=True)
class GatewayResponse:
    status_code: int
    headers: dict[str, str]
    body: bytes


class UpstreamTransportError(RuntimeError):
    pass


class HTTPUpstreamSender(Protocol):
    def send(self, body: bytes, headers: Mapping[str, str]) -> HTTPExchangeResponse: ...
