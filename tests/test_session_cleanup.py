"""Tests for Docker sandbox cleanup after normal and abnormal exits."""

from __future__ import annotations

import logging

import pytest

from strix.runtime import session_manager


class _FakeDockerClient:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeClient:
    def __init__(self, docker_client: _FakeDockerClient) -> None:
        self.docker_client = docker_client
        self.deleted_session: object | None = None

    async def delete(self, session: object) -> None:
        self.deleted_session = session


@pytest.mark.asyncio
async def test_cleanup_deletes_cached_session_and_closes_docker_client() -> None:
    scan_id = "scan-cleanup"
    session = object()
    docker_client = _FakeDockerClient()
    client = _FakeClient(docker_client)
    session_manager._SESSION_CACHE[scan_id] = {
        "client": client,
        "session": session,
    }

    await session_manager.cleanup(scan_id)

    assert client.deleted_session is session
    assert docker_client.closed is True
    assert scan_id not in session_manager._SESSION_CACHE


@pytest.mark.asyncio
async def test_cleanup_cache_miss_does_not_reconnect_to_docker() -> None:
    await session_manager.cleanup("scan-without-cache")


@pytest.mark.asyncio
async def test_cleanup_logs_delete_failure_and_closes_docker_client(
    caplog: pytest.LogCaptureFixture,
) -> None:
    scan_id = "scan-delete-failure"
    docker_client = _FakeDockerClient()

    class _FailingClient(_FakeClient):
        async def delete(self, _session: object) -> None:
            raise RuntimeError("Docker API unavailable")

    session_manager._SESSION_CACHE[scan_id] = {
        "client": _FailingClient(docker_client),
        "session": object(),
    }

    with caplog.at_level(logging.ERROR, logger="strix.runtime.session_manager"):
        await session_manager.cleanup(scan_id)

    assert docker_client.closed is True
    assert "container may need manual reaping" in caplog.text
    assert scan_id not in session_manager._SESSION_CACHE
