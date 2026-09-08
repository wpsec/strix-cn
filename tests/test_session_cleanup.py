"""Tests for Docker sandbox cleanup after normal and abnormal exits."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from strix.runtime import session_manager


class _FakeContainer:
    def __init__(self, scan_id: str, short_id: str) -> None:
        self.labels = {"com.strix.managed": "true", "com.strix.scan_id": scan_id}
        self.short_id = short_id
        self.removed_with_force: bool | None = None

    def remove(self, *, force: bool = False) -> None:
        self.removed_with_force = force


class _FakeContainers:
    def __init__(self, containers: list[_FakeContainer]) -> None:
        self._containers = containers
        self.filters: dict[str, Any] | None = None

    def list(self, *, all: bool, filters: dict[str, Any]) -> list[_FakeContainer]:
        assert all is True
        self.filters = filters
        return self._containers


class _FakeDockerClient:
    def __init__(self, containers: list[_FakeContainer]) -> None:
        self.containers = _FakeContainers(containers)
        self.closed = False

    def close(self) -> None:
        self.closed = True


def _write_run_record(root: Path, run_name: str, record: dict[str, Any]) -> None:
    run_dir = root / "strix_runs" / run_name
    run_dir.mkdir(parents=True)
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")


def _docker_settings() -> SimpleNamespace:
    return SimpleNamespace(runtime=SimpleNamespace(backend="docker"))


def test_reap_stale_sessions_removes_only_terminal_or_dead_owner_runs(
    monkeypatch: Any,
    tmp_path: Path,
) -> None:
    _write_run_record(tmp_path, "completed-run", {"status": "completed"})
    _write_run_record(tmp_path, "live-run", {"status": "running", "process_id": 123})
    _write_run_record(tmp_path, "dead-run", {"status": "running", "process_id": 456})
    _write_run_record(tmp_path, "unknown-owner", {"status": "running"})

    containers = [
        _FakeContainer("completed-run", "container-completed"),
        _FakeContainer("live-run", "container-live"),
        _FakeContainer("dead-run", "container-dead"),
        _FakeContainer("unknown-owner", "container-unknown"),
        _FakeContainer("missing-run-record", "container-missing"),
    ]
    client = _FakeDockerClient(containers)
    monkeypatch.setattr(session_manager, "load_settings", _docker_settings)
    monkeypatch.setattr(session_manager, "_docker_client_for_cleanup", lambda: client)
    monkeypatch.setattr(session_manager, "_pid_is_alive", lambda pid: pid == 123)

    removed = session_manager.reap_stale_docker_sessions(cwd=tmp_path)

    assert removed == 2
    assert containers[0].removed_with_force is True
    assert containers[1].removed_with_force is None
    assert containers[2].removed_with_force is True
    assert containers[3].removed_with_force is None
    assert containers[4].removed_with_force is None
    assert client.closed is True


def test_sync_process_exit_cleanup_targets_one_scan(
    monkeypatch: Any,
) -> None:
    container = _FakeContainer("scan-one", "container-one")
    client = _FakeDockerClient([container])
    monkeypatch.setattr(session_manager, "load_settings", _docker_settings)
    monkeypatch.setattr(session_manager, "_docker_client_for_cleanup", lambda: client)

    session_manager.cleanup_persisted_docker_session_sync("scan-one")

    assert container.removed_with_force is True
    assert client.containers.filters == {
        "label": [
            "com.strix.managed=true",
            "com.strix.scan_id=scan-one",
        ]
    }
    assert client.closed is True


@pytest.mark.asyncio
async def test_async_cleanup_falls_back_to_label_reaping_after_delete_failure(
    monkeypatch: Any,
) -> None:
    deleted_by_fallback: list[str] = []

    class _FailingClient:
        async def delete(self, _session: object) -> None:
            raise RuntimeError("Docker API unavailable")

    async def _fallback(scan_id: str) -> None:
        deleted_by_fallback.append(scan_id)

    scan_id = "scan-delete-failure"
    session_manager._SESSION_CACHE[scan_id] = {
        "client": _FailingClient(),
        "session": object(),
    }
    monkeypatch.setattr(session_manager, "_cleanup_persisted_docker_sessions", _fallback)

    try:
        await session_manager.cleanup(scan_id)
    finally:
        session_manager._SESSION_CACHE.pop(scan_id, None)

    assert deleted_by_fallback == [scan_id]
