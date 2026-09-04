from __future__ import annotations

import ipaddress
from pathlib import Path


class ServiceDeploymentError(ValueError):
    pass


def loopback_listener(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_http_service_deployment(
    *,
    listen_host: str,
    explicit_allowed_hosts: tuple[str, ...],
    allowed_origins: tuple[str, ...],
    require_origin: bool,
    access_token: str | None,
    tls_certfile: Path | None,
    tls_keyfile: Path | None,
) -> None:
    if not listen_host.strip():
        raise ServiceDeploymentError("service.listen_host_required")
    if require_origin and not allowed_origins:
        raise ServiceDeploymentError("service.origin_allowlist_required")
    if (tls_certfile is None) != (tls_keyfile is None):
        raise ServiceDeploymentError("service.tls_cert_key_pair_required")
    if tls_certfile is not None and not tls_certfile.is_file():
        raise ServiceDeploymentError("service.tls_certfile_missing")
    if tls_keyfile is not None and not tls_keyfile.is_file():
        raise ServiceDeploymentError("service.tls_keyfile_missing")

    if loopback_listener(listen_host):
        return

    if access_token is None or not access_token.strip():
        raise ServiceDeploymentError("service.remote_auth_required")
    if not explicit_allowed_hosts:
        raise ServiceDeploymentError("service.remote_host_allowlist_required")
    if tls_certfile is None or tls_keyfile is None:
        raise ServiceDeploymentError("service.remote_tls_required")
    if "*" in explicit_allowed_hosts:
        raise ServiceDeploymentError("service.remote_wildcard_host_forbidden")
