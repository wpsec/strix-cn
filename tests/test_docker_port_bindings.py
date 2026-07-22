"""Tests for Docker host-port bindings used by the Burp upstream proxy entrypoint."""

from __future__ import annotations

from strix.runtime.docker_client import _docker_port_bindings


def test_docker_port_bindings_default_to_random_host_port() -> None:
    bindings = _docker_port_bindings((48080,))

    assert bindings == {"48080/tcp": ("127.0.0.1", None)}


def test_docker_port_bindings_honor_fixed_host_port_override() -> None:
    bindings = _docker_port_bindings((48080,), {48080: 8081})

    assert bindings == {"48080/tcp": ("127.0.0.1", 8081)}
