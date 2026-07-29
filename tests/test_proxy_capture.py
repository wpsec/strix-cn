"""Tests for Caido proxy-capture polling helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from caido_sdk_client.types import Project, ProjectStatus

from strix.runtime import proxy_capture


def _project(
    *,
    id: str,
    name: str,
    temporary: bool = True,
    read_only: bool = False,
) -> Project:
    now = datetime.now(UTC)
    return Project(
        id=id,
        name=name,
        path=f"/projects/{id}",
        status=ProjectStatus.READY,
        temporary=temporary,
        created_at=now,
        updated_at=now,
        version="0.56.0",
        size=0,
        read_only=read_only,
    )


@dataclass
class _FakeConnection:
    edges: list[Any]
    page_info: Any


class _FakeRequestBuilder:
    def __init__(self, connection: _FakeConnection) -> None:
        self.connection = connection
        self.first_limit: int | None = None
        self.order_by: tuple[str, str] | None = None
        self.scope_id: str | None = None

    def first(self, limit: int) -> _FakeRequestBuilder:
        self.first_limit = limit
        return self

    def descending(self, resource: str, field: str) -> _FakeRequestBuilder:
        self.order_by = (resource, field)
        return self

    def scope(self, scope_id: str) -> _FakeRequestBuilder:
        self.scope_id = scope_id
        return self

    async def execute(self) -> _FakeConnection:
        return self.connection


class _FakeRequestSDK:
    def __init__(self, builder: _FakeRequestBuilder) -> None:
        self.builder = builder

    def list(self) -> _FakeRequestBuilder:
        return self.builder


class _FakeProjectSDK:
    def __init__(self, projects: list[Project]) -> None:
        self.projects = projects
        self.selected_ids: list[str] = []

    async def list(self) -> list[Project]:
        return list(self.projects)

    async def select(self, project_id: str) -> Project:
        self.selected_ids.append(project_id)
        return next(project for project in self.projects if project.id == project_id)


class _FakeClient:
    def __init__(self, project_sdk: _FakeProjectSDK, request_sdk: _FakeRequestSDK) -> None:
        self.project = project_sdk
        self.request = request_sdk
        self.connected = False
        self.closed = False

    async def connect(self) -> None:
        self.connected = True

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_fetch_proxy_capture_snapshot_selects_strix_project_before_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _FakeConnection(
        edges=[
            SimpleNamespace(
                node=SimpleNamespace(
                    request=SimpleNamespace(
                        id="req-9",
                        method="POST",
                        host="app.example.com",
                        path="/api/orders",
                    ),
                    response=SimpleNamespace(status_code=201),
                ),
            ),
        ],
        page_info=SimpleNamespace(has_next_page=False),
    )
    builder = _FakeRequestBuilder(connection)
    project_sdk = _FakeProjectSDK([_project(id="proj_existing", name="sandbox")])
    fake_client = _FakeClient(project_sdk, _FakeRequestSDK(builder))

    monkeypatch.setattr(proxy_capture, "_login_as_guest", lambda _host_url: "token")
    monkeypatch.setattr(proxy_capture, "Client", lambda *_args, **_kwargs: fake_client)

    async def _count_requests(*_args: Any, **_kwargs: Any) -> int:
        return 14

    monkeypatch.setattr(proxy_capture, "_count_requests", _count_requests)

    snapshot = await proxy_capture.fetch_proxy_capture_snapshot(
        "http://127.0.0.1:52124",
        scope_id="scope-1",
        recent_limit=10,
    )

    assert fake_client.connected is True
    assert fake_client.closed is True
    assert project_sdk.selected_ids == ["proj_existing"]
    assert builder.first_limit == 10
    assert builder.order_by == ("req", "created_at")
    assert builder.scope_id == "scope-1"
    assert snapshot.recent_request_count == 1
    assert snapshot.latest_request_id == "req-9"
    assert snapshot.latest_method == "POST"
    assert snapshot.latest_host == "app.example.com"
    assert snapshot.latest_path == "/api/orders"
    assert snapshot.latest_status_code == 201
    assert snapshot.total_request_count == 14


@pytest.mark.asyncio
async def test_fetch_proxy_capture_snapshot_fails_when_strix_project_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = _FakeConnection(edges=[], page_info=SimpleNamespace(has_next_page=False))
    fake_client = _FakeClient(_FakeProjectSDK([]), _FakeRequestSDK(_FakeRequestBuilder(connection)))

    monkeypatch.setattr(proxy_capture, "_login_as_guest", lambda _host_url: "token")
    monkeypatch.setattr(proxy_capture, "Client", lambda *_args, **_kwargs: fake_client)

    with pytest.raises(RuntimeError, match="sandbox"):
        await proxy_capture.fetch_proxy_capture_snapshot("http://127.0.0.1:52124")

    assert fake_client.connected is True
    assert fake_client.closed is True
