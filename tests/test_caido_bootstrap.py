"""Tests for Caido bootstrap project recovery behavior."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from caido_sdk_client.errors.base import BaseError
from caido_sdk_client.errors.form import NameTakenUserError
from caido_sdk_client.types import Project, ProjectStatus

from strix.runtime import caido_bootstrap


def _project(
    *,
    id: str,
    name: str,
    temporary: bool = True,
    read_only: bool = False,
    updated_offset_seconds: int = 0,
) -> Project:
    now = datetime.now(UTC) + timedelta(seconds=updated_offset_seconds)
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
class _FakeProjectSDK:
    create_plan: list[Any]
    projects: list[Project] = field(default_factory=list)
    selected_ids: list[str] = field(default_factory=list)
    deleted_ids: list[str] = field(default_factory=list)
    delete_failures: dict[str, Exception] = field(default_factory=dict)

    async def create(self, _options: Any) -> Project:
        if not self.create_plan:
            raise AssertionError("Unexpected project.create call")
        outcome = self.create_plan.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    async def list(self) -> list[Project]:
        return list(self.projects)

    async def select(self, project_id: str) -> Project:
        self.selected_ids.append(project_id)
        for project in self.projects:
            if project.id == project_id:
                return project
        for outcome in self.create_plan:
            if isinstance(outcome, Project) and outcome.id == project_id:
                return outcome
        return _project(id=project_id, name="selected")

    async def delete(self, project_id: str) -> None:
        if project_id in self.delete_failures:
            raise self.delete_failures[project_id]
        self.deleted_ids.append(project_id)
        self.projects = [project for project in self.projects if project.id != project_id]


class _FakeClient:
    def __init__(self, project_sdk: _FakeProjectSDK) -> None:
        self.project = project_sdk
        self.connected = False
        self.closed = False

    async def connect(self) -> None:
        self.connected = True

    async def aclose(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_bootstrap_caido_reuses_existing_temporary_sandbox_project(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    existing = _project(id="proj_existing", name="sandbox")
    project_sdk = _FakeProjectSDK(
        create_plan=[NameTakenUserError("sandbox")],
        projects=[existing],
    )
    fake_client = _FakeClient(project_sdk)

    async def _login_as_guest(*_args: Any, **_kwargs: Any) -> str:
        return "token"

    monkeypatch.setattr(caido_bootstrap, "_login_as_guest", _login_as_guest)
    monkeypatch.setattr(
        caido_bootstrap,
        "Client",
        lambda *_args, **_kwargs: fake_client,
    )

    client = await caido_bootstrap.bootstrap_caido(
        session=object(),
        host_url="http://127.0.0.1:8081",
        container_url="http://127.0.0.1:48080",
    )

    assert client is fake_client
    assert fake_client.connected is True
    assert fake_client.closed is False
    assert project_sdk.selected_ids == ["proj_existing"]
    assert project_sdk.deleted_ids == []


@pytest.mark.asyncio
async def test_bootstrap_caido_deletes_stale_temporary_projects_then_retries_create(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stale = _project(id="proj_old", name="old-temp", updated_offset_seconds=-60)
    created = _project(id="proj_new", name="sandbox")
    project_sdk = _FakeProjectSDK(
        create_plan=[BaseError("project limit"), created],
        projects=[stale],
    )
    fake_client = _FakeClient(project_sdk)

    async def _login_as_guest(*_args: Any, **_kwargs: Any) -> str:
        return "token"

    monkeypatch.setattr(caido_bootstrap, "_login_as_guest", _login_as_guest)
    monkeypatch.setattr(
        caido_bootstrap,
        "Client",
        lambda *_args, **_kwargs: fake_client,
    )

    client = await caido_bootstrap.bootstrap_caido(
        session=object(),
        host_url="http://127.0.0.1:8081",
        container_url="http://127.0.0.1:48080",
    )

    assert client is fake_client
    assert project_sdk.deleted_ids == ["proj_old"]
    assert project_sdk.selected_ids == ["proj_new"]
    assert fake_client.closed is False


@pytest.mark.asyncio
async def test_bootstrap_caido_closes_client_when_project_recovery_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project_sdk = _FakeProjectSDK(
        create_plan=[BaseError("project limit")],
        projects=[],
    )
    fake_client = _FakeClient(project_sdk)

    async def _login_as_guest(*_args: Any, **_kwargs: Any) -> str:
        return "token"

    monkeypatch.setattr(caido_bootstrap, "_login_as_guest", _login_as_guest)
    monkeypatch.setattr(
        caido_bootstrap,
        "Client",
        lambda *_args, **_kwargs: fake_client,
    )

    with pytest.raises(BaseError, match="project limit"):
        await caido_bootstrap.bootstrap_caido(
            session=object(),
            host_url="http://127.0.0.1:8081",
            container_url="http://127.0.0.1:48080",
        )

    assert fake_client.closed is True


@pytest.mark.asyncio
async def test_bootstrap_caido_skips_undeletable_temporary_project_and_tries_next(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    locked = _project(id="proj_locked", name="locked-temp", updated_offset_seconds=-120)
    stale = _project(id="proj_stale", name="stale-temp", updated_offset_seconds=-60)
    created = _project(id="proj_new", name="sandbox")
    project_sdk = _FakeProjectSDK(
        create_plan=[BaseError("project limit"), created],
        projects=[locked, stale],
        delete_failures={"proj_locked": BaseError("cannot delete locked project")},
    )
    fake_client = _FakeClient(project_sdk)

    async def _login_as_guest(*_args: Any, **_kwargs: Any) -> str:
        return "token"

    monkeypatch.setattr(caido_bootstrap, "_login_as_guest", _login_as_guest)
    monkeypatch.setattr(
        caido_bootstrap,
        "Client",
        lambda *_args, **_kwargs: fake_client,
    )

    client = await caido_bootstrap.bootstrap_caido(
        session=object(),
        host_url="http://127.0.0.1:8081",
        container_url="http://127.0.0.1:48080",
    )

    assert client is fake_client
    assert project_sdk.deleted_ids == ["proj_stale"]
    assert project_sdk.selected_ids == ["proj_new"]


@pytest.mark.asyncio
async def test_bootstrap_caido_configures_host_bridge_upstream_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = _project(id="proj_new", name="sandbox")
    project_sdk = _FakeProjectSDK(create_plan=[created], projects=[])
    fake_client = _FakeClient(project_sdk)
    graphql_calls: list[tuple[str, dict[str, Any]]] = []

    async def _login_as_guest(*_args: Any, **_kwargs: Any) -> str:
        return "token"

    async def _graphql(
        _host_url: str,
        _access_token: str,
        query: str,
        *,
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = variables or {}
        graphql_calls.append((query, payload))
        if "upstreamProxiesHttp" in query:
            if len([call for call in graphql_calls if "upstreamProxiesHttp" in call[0]]) == 1:
                return {
                    "upstreamProxiesHttp": [
                        {
                            "id": "stale",
                            "enabled": True,
                            "connection": {
                                "host": "host.docker.internal",
                                "port": 17171,
                                "isTLS": False,
                                "SNI": None,
                            },
                            "allowlist": [],
                            "denylist": [],
                        },
                        {
                            "id": "corp",
                            "enabled": True,
                            "connection": {
                                "host": "corp-proxy",
                                "port": 8080,
                                "isTLS": False,
                                "SNI": None,
                            },
                            "allowlist": [],
                            "denylist": [],
                        },
                    ]
                }
            return {
                "upstreamProxiesHttp": [
                    {
                        "id": "corp",
                        "enabled": True,
                        "connection": {
                            "host": "corp-proxy",
                            "port": 8080,
                            "isTLS": False,
                            "SNI": None,
                        },
                        "allowlist": [],
                        "denylist": [],
                    },
                    {
                        "id": "bridge",
                        "enabled": True,
                        "connection": {
                            "host": "host.docker.internal",
                            "port": 18081,
                            "isTLS": False,
                            "SNI": None,
                        },
                        "allowlist": [],
                        "denylist": [],
                    },
                ]
            }
        if "deleteUpstreamProxyHttp" in query:
            return {"deleteUpstreamProxyHttp": {"deletedId": payload["id"]}}
        if "createUpstreamProxyHttp" in query:
            return {"createUpstreamProxyHttp": {"proxy": {"id": "bridge"}}}
        if "rankUpstreamProxyHttp" in query:
            return {"rankUpstreamProxyHttp": {"proxy": {"id": payload["id"]}}}
        raise AssertionError(f"Unexpected GraphQL query: {query}")

    monkeypatch.setattr(caido_bootstrap, "_login_as_guest", _login_as_guest)
    monkeypatch.setattr(caido_bootstrap, "_graphql", _graphql)
    monkeypatch.setattr(
        caido_bootstrap,
        "Client",
        lambda *_args, **_kwargs: fake_client,
    )

    client = await caido_bootstrap.bootstrap_caido(
        session=object(),
        host_url="http://127.0.0.1:8081",
        container_url="http://127.0.0.1:48080",
        upstream_proxy=caido_bootstrap.UpstreamProxyHttpConfig(
            host="host.docker.internal",
            port=18081,
        ),
    )

    assert client is fake_client
    delete_call = next(call for call in graphql_calls if "deleteUpstreamProxyHttp" in call[0])
    assert delete_call[1] == {"id": "stale"}
    create_call = next(call for call in graphql_calls if "createUpstreamProxyHttp" in call[0])
    assert create_call[1]["input"]["connection"] == {
        "host": "host.docker.internal",
        "port": 18081,
        "isTLS": False,
    }
    rank_call = next(call for call in graphql_calls if "rankUpstreamProxyHttp" in call[0])
    assert rank_call[1] == {"id": "bridge", "input": {"beforeId": "corp"}}


@pytest.mark.asyncio
async def test_bootstrap_caido_updates_existing_matching_upstream_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = _project(id="proj_new", name="sandbox")
    project_sdk = _FakeProjectSDK(create_plan=[created], projects=[])
    fake_client = _FakeClient(project_sdk)
    graphql_calls: list[tuple[str, dict[str, Any]]] = []

    async def _login_as_guest(*_args: Any, **_kwargs: Any) -> str:
        return "token"

    async def _graphql(
        _host_url: str,
        _access_token: str,
        query: str,
        *,
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = variables or {}
        graphql_calls.append((query, payload))
        if "upstreamProxiesHttp" in query:
            return {
                "upstreamProxiesHttp": [
                    {
                        "id": "bridge",
                        "enabled": False,
                        "connection": {
                            "host": "host.docker.internal",
                            "port": 18081,
                            "isTLS": False,
                            "SNI": None,
                        },
                        "allowlist": ["old"],
                        "denylist": ["old"],
                    }
                ]
            }
        if "updateUpstreamProxyHttp" in query:
            return {"updateUpstreamProxyHttp": {"proxy": {"id": payload["id"]}}}
        raise AssertionError(f"Unexpected GraphQL query: {query}")

    monkeypatch.setattr(caido_bootstrap, "_login_as_guest", _login_as_guest)
    monkeypatch.setattr(caido_bootstrap, "_graphql", _graphql)
    monkeypatch.setattr(
        caido_bootstrap,
        "Client",
        lambda *_args, **_kwargs: fake_client,
    )

    client = await caido_bootstrap.bootstrap_caido(
        session=object(),
        host_url="http://127.0.0.1:8081",
        container_url="http://127.0.0.1:48080",
        upstream_proxy=caido_bootstrap.UpstreamProxyHttpConfig(
            host="host.docker.internal",
            port=18081,
        ),
    )

    assert client is fake_client
    assert any("updateUpstreamProxyHttp" in query for query, _vars in graphql_calls)
    assert not any("createUpstreamProxyHttp" in query for query, _vars in graphql_calls)
    assert not any("deleteUpstreamProxyHttp" in query for query, _vars in graphql_calls)
