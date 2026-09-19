"""Tests for Docker host-port bindings used by the Burp upstream proxy entrypoint."""

from __future__ import annotations

from unittest.mock import MagicMock
from uuid import UUID

import pytest

from strix.runtime.docker_client import (
    StrixDockerSandboxClient,
    _docker_container_name,
    _docker_container_name_matches_scan,
    _docker_container_name_prefix,
    _docker_port_bindings,
)


def test_docker_port_bindings_default_to_random_host_port() -> None:
    bindings = _docker_port_bindings((48080, 48081))

    assert bindings == {
        "48080/tcp": ("127.0.0.1", None),
        "48081/tcp": ("127.0.0.1", None),
    }


def test_docker_port_bindings_honor_fixed_host_port_override() -> None:
    bindings = _docker_port_bindings((48080, 48081), {48081: 8081})

    assert bindings == {
        "48080/tcp": ("127.0.0.1", None),
        "48081/tcp": ("127.0.0.1", 8081),
    }


def test_docker_container_name_uses_scan_id_and_session_suffix() -> None:
    assert _docker_container_name_prefix("example-com_abcd") == "strix-example-com_abcd-"
    assert _docker_container_name_matches_scan("strix-example-com_abcd-01234567", "example-com_abcd")
    assert not _docker_container_name_matches_scan(
        "strix-example-com_abcd-other-01234567", "example-com_abcd"
    )
    assert (
        _docker_container_name(
            "example-com_abcd",
            UUID("01234567-89ab-cdef-0123-456789abcdef"),
        )
        == "strix-example-com_abcd-01234567"
    )


def test_docker_container_name_sanitizes_and_bounds_scan_id() -> None:
    name = _docker_container_name(
        "https://user:password@example.com/path?api_key=secret#fragment",
        UUID("fedcba98-7654-3210-fedc-ba9876543210"),
    )

    assert name == "strix-example.com-fedcba98"
    assert len(name) <= 63

    long_name = _docker_container_name("target" * 100, UUID(int=0))
    assert len(long_name) == 63


@pytest.mark.asyncio
async def test_create_container_passes_target_aligned_name_to_docker() -> None:
    client = StrixDockerSandboxClient.__new__(StrixDockerSandboxClient)
    client.docker_client = MagicMock()
    client.docker_client.containers.create.return_value = MagicMock(short_id="abc123")
    client.image_exists = lambda _image: True
    client.strix_bind_mounts = []
    client.strix_exposed_port_bindings = {}
    client.strix_scan_id = "example-com_abcd"

    await client._create_container(
        "ghcr.io/usestrix/strix-sandbox:1.3.0",
        session_id=UUID("01234567-89ab-cdef-0123-456789abcdef"),
    )

    create_kwargs = client.docker_client.containers.create.call_args.kwargs
    assert create_kwargs["name"] == "strix-example-com_abcd-01234567"
    assert create_kwargs["labels"] == {"strix-run-id": "example-com_abcd"}
