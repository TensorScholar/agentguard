from __future__ import annotations

from pathlib import Path

import pytest

from decisionlock.service_deployment import (
    ServiceDeploymentError,
    loopback_listener,
    validate_http_service_deployment,
)


def _validate(
    *,
    host: str = "127.0.0.1",
    allowed_hosts: tuple[str, ...] = (),
    allowed_origins: tuple[str, ...] = (),
    require_origin: bool = False,
    token: str | None = None,
    cert: Path | None = None,
    key: Path | None = None,
) -> None:
    validate_http_service_deployment(
        listen_host=host,
        explicit_allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
        require_origin=require_origin,
        access_token=token,
        tls_certfile=cert,
        tls_keyfile=key,
    )


def test_loopback_detection_is_explicit() -> None:
    assert loopback_listener("localhost") is True
    assert loopback_listener("127.0.0.1") is True
    assert loopback_listener("::1") is True
    assert loopback_listener("0.0.0.0") is False
    assert loopback_listener("gateway.internal") is False


def test_loopback_listener_preserves_secure_local_default() -> None:
    _validate()


def test_remote_listener_requires_auth_then_explicit_host_allowlist(tmp_path) -> None:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("certificate")
    key.write_text("key")

    with pytest.raises(ServiceDeploymentError, match="service.remote_auth_required"):
        _validate(host="0.0.0.0", cert=cert, key=key)
    with pytest.raises(ServiceDeploymentError, match="service.remote_host_allowlist_required"):
        _validate(host="0.0.0.0", token="secret", cert=cert, key=key)


def test_remote_listener_requires_tls_and_forbids_wildcard_host(tmp_path) -> None:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("certificate")
    key.write_text("key")

    with pytest.raises(ServiceDeploymentError, match="service.remote_tls_required"):
        _validate(host="0.0.0.0", token="secret", allowed_hosts=("decisionlock.example",))
    with pytest.raises(ServiceDeploymentError, match="service.remote_wildcard_host_forbidden"):
        _validate(
            host="0.0.0.0",
            token="secret",
            allowed_hosts=("*",),
            cert=cert,
            key=key,
        )


def test_remote_listener_accepts_explicit_authenticated_tls_configuration(tmp_path) -> None:
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("certificate")
    key.write_text("key")
    _validate(
        host="0.0.0.0",
        token="secret",
        allowed_hosts=("decisionlock.example",),
        cert=cert,
        key=key,
    )


def test_tls_pair_files_and_browser_origin_are_fail_closed(tmp_path) -> None:
    cert = tmp_path / "cert.pem"
    cert.write_text("certificate")
    missing_key = tmp_path / "missing-key.pem"

    with pytest.raises(ServiceDeploymentError, match="service.tls_cert_key_pair_required"):
        _validate(cert=cert)
    with pytest.raises(ServiceDeploymentError, match="service.tls_keyfile_missing"):
        _validate(cert=cert, key=missing_key)
    with pytest.raises(ServiceDeploymentError, match="service.origin_allowlist_required"):
        _validate(require_origin=True)


def test_blank_listener_and_blank_remote_token_are_rejected(tmp_path) -> None:
    with pytest.raises(ServiceDeploymentError, match="service.listen_host_required"):
        _validate(host=" ")

    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("certificate")
    key.write_text("key")
    with pytest.raises(ServiceDeploymentError, match="service.remote_auth_required"):
        _validate(
            host="0.0.0.0",
            token="   ",
            allowed_hosts=("decisionlock.example",),
            cert=cert,
            key=key,
        )
