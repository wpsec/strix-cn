"""Caido client bootstrap.

The Caido CLI runs as an in-container sidecar listening on
``127.0.0.1:48080`` *inside* the sandbox. We grab a guest token by
``session.exec()``-ing curl from inside the container, then construct
a host-side :class:`caido_sdk_client.Client` against the runtime's
exposed-port URL for all subsequent SDK calls.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib import request as urllib_request

from caido_sdk_client import Client, TokenAuthOptions
from caido_sdk_client.errors.base import BaseError
from caido_sdk_client.errors.form import NameTakenUserError
from caido_sdk_client.types import CreateProjectOptions, Project


if TYPE_CHECKING:
    from agents.sandbox.session import BaseSandboxSession


logger = logging.getLogger(__name__)


_LOGIN_AS_GUEST_BODY = (
    '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}'
)
_STRIX_PROJECT_NAME = "sandbox"
_UPSTREAM_PROXIES_HTTP_QUERY = """
query {
  upstreamProxiesHttp {
    id
    enabled
    connection {
      host
      port
      isTLS
      SNI
    }
    allowlist
    denylist
  }
}
"""
_CREATE_UPSTREAM_PROXY_HTTP_MUTATION = """
mutation($input: CreateUpstreamProxyHttpInput!) {
  createUpstreamProxyHttp(input: $input) {
    proxy {
      id
    }
  }
}
"""
_UPDATE_UPSTREAM_PROXY_HTTP_MUTATION = """
mutation($id: ID!, $input: UpdateUpstreamProxyHttpInput!) {
  updateUpstreamProxyHttp(id: $id, input: $input) {
    proxy {
      id
    }
  }
}
"""
_DELETE_UPSTREAM_PROXY_HTTP_MUTATION = """
mutation($id: ID!) {
  deleteUpstreamProxyHttp(id: $id) {
    deletedId
  }
}
"""
_RANK_UPSTREAM_PROXY_HTTP_MUTATION = """
mutation($id: ID!, $input: RankInput!) {
  rankUpstreamProxyHttp(id: $id, input: $input) {
    proxy {
      id
    }
  }
}
"""


@dataclass(slots=True, frozen=True)
class UpstreamProxyHttpConfig:
    host: str
    port: int
    is_tls: bool = False


async def _login_as_guest(
    session: BaseSandboxSession,
    *,
    container_url: str,
    attempts: int = 10,
) -> str:
    """``session.exec`` curl to fetch a guest token; retry until ready.

    Caido's GraphQL listener may not be up the instant the container
    starts. The retry loop also doubles as the Caido readiness probe —
    no separate TCP healthcheck needed.
    """
    last_err: str | None = None
    for i in range(1, attempts + 1):
        result = await session.exec(
            "curl",
            "-fsS",
            "-X",
            "POST",
            "-H",
            "Content-Type: application/json",
            "-d",
            _LOGIN_AS_GUEST_BODY,
            f"{container_url}/graphql",
            timeout=15,
        )
        if result.ok():
            try:
                payload = json.loads(result.stdout)
                token = (
                    payload.get("data", {})
                    .get("loginAsGuest", {})
                    .get("token", {})
                    .get("accessToken")
                )
                if token:
                    return str(token)
                last_err = f"loginAsGuest returned no token: {payload}"
            except json.JSONDecodeError as exc:
                last_err = f"unparseable response: {exc}: {result.stdout!r}"
        else:
            stderr = result.stderr.decode("utf-8", errors="replace")[:200]
            last_err = f"curl exit {result.exit_code}: {stderr}"
        logger.debug("loginAsGuest attempt %d/%d failed: %s", i, attempts, last_err)
        await asyncio.sleep(min(2.0 * i, 8.0))

    raise RuntimeError(f"loginAsGuest failed after {attempts} attempts: {last_err}")


async def bootstrap_caido(
    session: BaseSandboxSession,
    *,
    host_url: str,
    container_url: str,
    upstream_proxy: UpstreamProxyHttpConfig | None = None,
) -> Client:
    """Connect to the in-container Caido sidecar and select a writable project."""
    logger.info("Bootstrapping Caido client (host=%s, container=%s)", host_url, container_url)

    access_token = await _login_as_guest(session, container_url=container_url)

    client = Client(host_url, auth=TokenAuthOptions(token=access_token))
    await client.connect()

    try:
        project = await _create_or_recover_project(client, project_name=_STRIX_PROJECT_NAME)
    except BaseException:
        # The connected client never reaches the session bundle if project
        # setup fails, so close it here to avoid leaking the transport.
        with contextlib.suppress(Exception):
            await client.aclose()
        raise
    if upstream_proxy is not None:
        await _ensure_upstream_proxy_http(
            host_url,
            access_token,
            proxy=upstream_proxy,
        )
    logger.info("Caido project selected: %s", project.id)
    return client


async def _create_or_recover_project(client: Client, *, project_name: str) -> Project:
    try:
        return await _create_and_select_project(client, project_name=project_name)
    except NameTakenUserError as exc:
        logger.warning("Caido project %s already exists; attempting reuse", project_name)
        existing = await _select_existing_project(client, project_name=project_name)
        if existing is not None:
            return existing
        raise exc
    except BaseError as exc:
        logger.warning("Caido project bootstrap failed for %s: %s", project_name, exc)
        existing = await _select_existing_project(client, project_name=project_name)
        if existing is not None:
            return existing

        projects = await client.project.list()
        cleanup_candidates = _temporary_cleanup_candidates(projects, project_name=project_name)
        for stale_project in cleanup_candidates:
            logger.warning(
                "Deleting stale temporary Caido project %s (%s) before retrying bootstrap",
                stale_project.name,
                stale_project.id,
            )
            try:
                await client.project.delete(stale_project.id)
            except BaseError as delete_exc:
                logger.warning(
                    "Failed to delete stale temporary Caido project %s (%s): %s",
                    stale_project.name,
                    stale_project.id,
                    delete_exc,
                )
                continue
            try:
                return await _create_and_select_project(client, project_name=project_name)
            except NameTakenUserError:
                existing = await _select_existing_project(client, project_name=project_name)
                if existing is not None:
                    return existing
            except BaseError as retry_exc:
                logger.warning(
                    "Caido project bootstrap retry still failing after deleting %s: %s",
                    stale_project.id,
                    retry_exc,
                )
                exc = retry_exc
                continue
        raise exc


async def _create_and_select_project(client: Client, *, project_name: str) -> Project:
    project = await client.project.create(
        CreateProjectOptions(name=project_name, temporary=True),
    )
    await client.project.select(project.id)
    return project


async def _select_existing_project(client: Client, *, project_name: str) -> Project | None:
    projects = await client.project.list()
    candidates = [
        project
        for project in projects
        if project.name == project_name and project.temporary and not project.read_only
    ]
    if not candidates:
        return None

    project = max(candidates, key=lambda item: (item.updated_at, item.created_at, str(item.id)))
    await client.project.select(project.id)
    logger.warning("Reusing existing temporary Caido project %s (%s)", project.name, project.id)
    return project


def _temporary_cleanup_candidates(
    projects: list[Project], *, project_name: str
) -> list[Project]:
    candidates = [
        project
        for project in projects
        if getattr(project, "temporary", False)
        and not getattr(project, "read_only", False)
        and getattr(project, "name", "") != project_name
    ]
    return sorted(candidates, key=lambda item: (item.updated_at, item.created_at, str(item.id)))


async def _ensure_upstream_proxy_http(
    host_url: str,
    access_token: str,
    *,
    proxy: UpstreamProxyHttpConfig,
) -> None:
    proxies = await _graphql(host_url, access_token, _UPSTREAM_PROXIES_HTTP_QUERY)
    current = proxies.get("upstreamProxiesHttp") or []
    exact_match: dict[str, Any] | None = None
    stale_ids: list[str] = []
    for item in current:
        if _proxy_connection_matches(item, proxy):
            exact_match = item
            continue
        if _proxy_connection_is_stale_bridge(item, proxy):
            stale_ids.append(str(item["id"]))

    for stale_id in stale_ids:
        await _graphql(
            host_url,
            access_token,
            _DELETE_UPSTREAM_PROXY_HTTP_MUTATION,
            variables={"id": stale_id},
        )

    proxy_input = {
        "enabled": True,
        "connection": {
            "host": proxy.host,
            "port": proxy.port,
            "isTLS": proxy.is_tls,
        },
        "allowlist": [],
        "denylist": [],
    }
    if exact_match is None:
        created = await _graphql(
            host_url,
            access_token,
            _CREATE_UPSTREAM_PROXY_HTTP_MUTATION,
            variables={"input": proxy_input},
        )
        proxy_id = str(created["createUpstreamProxyHttp"]["proxy"]["id"])
    else:
        proxy_id = str(exact_match["id"])
        await _graphql(
            host_url,
            access_token,
            _UPDATE_UPSTREAM_PROXY_HTTP_MUTATION,
            variables={
                "id": proxy_id,
                "input": proxy_input,
            },
        )

    ordered = await _graphql(host_url, access_token, _UPSTREAM_PROXIES_HTTP_QUERY)
    ordered_proxies = ordered.get("upstreamProxiesHttp") or []
    if ordered_proxies and str(ordered_proxies[0]["id"]) != proxy_id:
        await _graphql(
            host_url,
            access_token,
            _RANK_UPSTREAM_PROXY_HTTP_MUTATION,
            variables={
                "id": proxy_id,
                "input": {"beforeId": str(ordered_proxies[0]["id"])},
            },
        )
    logger.info(
        "Configured Caido upstream HTTP proxy bridge: %s:%s",
        proxy.host,
        proxy.port,
    )


def _proxy_connection_matches(item: dict[str, Any], proxy: UpstreamProxyHttpConfig) -> bool:
    connection = item.get("connection") or {}
    return (
        str(connection.get("host", "")) == proxy.host
        and int(connection.get("port", 0) or 0) == proxy.port
        and bool(connection.get("isTLS")) is proxy.is_tls
    )


def _proxy_connection_is_stale_bridge(item: dict[str, Any], proxy: UpstreamProxyHttpConfig) -> bool:
    connection = item.get("connection") or {}
    return (
        str(connection.get("host", "")) == proxy.host
        and bool(connection.get("isTLS")) is proxy.is_tls
    )


async def _graphql(
    host_url: str,
    access_token: str,
    query: str,
    *,
    variables: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return await asyncio.to_thread(
        _graphql_sync,
        host_url,
        access_token,
        query,
        variables or {},
    )


def _graphql_sync(
    host_url: str,
    access_token: str,
    query: str,
    variables: dict[str, Any],
) -> dict[str, Any]:
    base_url = host_url.rstrip("/")
    body = json.dumps({"query": query, "variables": variables}).encode("utf-8")
    req = urllib_request.Request(
        f"{base_url}/graphql",
        data=body,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib_request.urlopen(req, timeout=20) as resp:  # noqa: S310  # nosec B310
        payload = json.loads(resp.read())
    errors = payload.get("errors") or []
    if errors:
        message = errors[0].get("message") or "unknown GraphQL error"
        raise RuntimeError(f"Caido GraphQL 调用失败: {message}")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("Caido GraphQL 返回缺少 data 字段")
    return data
