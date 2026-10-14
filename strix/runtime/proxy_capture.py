"""Host-side polling helpers for Caido-captured proxy traffic."""

from __future__ import annotations

import asyncio
import contextlib
import json
import urllib.request
from dataclasses import dataclass
from typing import Any

from caido_sdk_client import Client, TokenAuthOptions

from strix.runtime.caido_bootstrap import select_strix_project


_LOGIN_AS_GUEST_BODY = (
    '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}'
)


@dataclass(slots=True, frozen=True)
class ProxyCaptureSnapshot:
    recent_request_count: int
    recent_request_has_more: bool
    latest_request_id: str | None
    latest_request_created_at: str | None = None
    latest_method: str | None = None
    latest_host: str | None = None
    latest_path: str | None = None
    latest_status_code: int | None = None
    latest_request_source: str | None = None
    latest_request_category: str | None = None
    latest_operator_request_id: str | None = None
    latest_operator_request_source: str | None = None
    latest_operator_method: str | None = None
    latest_operator_host: str | None = None
    latest_operator_path: str | None = None
    latest_operator_status_code: int | None = None
    total_request_count: int = 0
    operator_request_count: int = 0
    replay_request_count: int = 0
    unclassified_request_count: int = 0
    endpoint_request_counts: tuple[tuple[str, int], ...] = ()


@dataclass(slots=True, frozen=True)
class _ProxyRequestInventory:
    total_request_count: int
    operator_request_count: int
    replay_request_count: int
    unclassified_request_count: int
    endpoint_request_counts: tuple[tuple[str, int], ...]
    latest_operator_edge: Any | None


class ProxyCapturePoller:
    """Persistent Caido poller for the TUI proxy monitor thread."""

    def __init__(self, host_url: str) -> None:
        self.host_url = host_url
        self._client: Client | None = None
        self._project_selected = False

    async def fetch_snapshot(
        self,
        *,
        scope_id: str | None = None,
        recent_limit: int = 10,
        total_page_size: int = 200,
    ) -> ProxyCaptureSnapshot:
        client = await self._ensure_client()
        try:
            return await _fetch_proxy_capture_snapshot_with_client(
                client,
                scope_id=scope_id,
                recent_limit=recent_limit,
                total_page_size=total_page_size,
            )
        except Exception:
            await self._reset_client()
            raise

    async def aclose(self) -> None:
        await self._reset_client()

    async def _ensure_client(self) -> Client:
        client = self._client
        if client is None:
            token = await asyncio.to_thread(_login_as_guest, self.host_url)
            client = Client(self.host_url, auth=TokenAuthOptions(token=token))
            try:
                await client.connect()
            except BaseException:
                with contextlib.suppress(Exception):
                    await client.aclose()
                raise
            self._client = client
        if not self._project_selected:
            await select_strix_project(client)
            self._project_selected = True
        return client

    async def _reset_client(self) -> None:
        client = self._client
        self._client = None
        self._project_selected = False
        if client is None:
            return
        with contextlib.suppress(Exception):
            await client.aclose()


def _login_as_guest(host_url: str) -> str:
    request = urllib.request.Request(  # noqa: S310
        f"{host_url.rstrip('/')}/graphql",
        data=_LOGIN_AS_GUEST_BODY.encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310  # nosec B310
        payload = json.loads(response.read())
    return str(payload["data"]["loginAsGuest"]["token"]["accessToken"])


async def fetch_proxy_capture_snapshot(
    host_url: str,
    *,
    scope_id: str | None = None,
    recent_limit: int = 10,
    total_page_size: int = 200,
) -> ProxyCaptureSnapshot:
    poller = ProxyCapturePoller(host_url)
    try:
        return await poller.fetch_snapshot(
            scope_id=scope_id,
            recent_limit=recent_limit,
            total_page_size=total_page_size,
        )
    finally:
        await poller.aclose()


async def _fetch_proxy_capture_snapshot_with_client(
    client: Client,
    *,
    scope_id: str | None,
    recent_limit: int,
    total_page_size: int,
) -> ProxyCaptureSnapshot:
    builder = client.request.list().first(max(1, recent_limit)).descending("req", "created_at")
    if scope_id:
        builder = builder.scope(scope_id)
    connection = await builder.execute()
    inventory = await _request_inventory(
        client,
        scope_id=scope_id,
        page_size=max(1, total_page_size),
    )

    edges = list(getattr(connection, "edges", []) or [])
    latest = edges[0] if edges else None
    latest_node = getattr(latest, "node", None) if latest is not None else None
    latest_request = getattr(latest_node, "request", None)
    latest_response = getattr(latest_node, "response", None)
    latest_operator_node = (
        getattr(inventory.latest_operator_edge, "node", None)
        if inventory.latest_operator_edge is not None
        else None
    )
    latest_operator_request = getattr(latest_operator_node, "request", None)
    latest_operator_response = getattr(latest_operator_node, "response", None)

    return ProxyCaptureSnapshot(
        recent_request_count=len(edges),
        recent_request_has_more=_has_next_page(connection),
        latest_request_id=_string_or_none(getattr(latest_request, "id", None)),
        latest_request_created_at=_string_or_none(
            getattr(getattr(latest_request, "created_at", None), "isoformat", lambda: None)()
        ),
        latest_method=_string_or_none(getattr(latest_request, "method", None)),
        latest_host=_string_or_none(getattr(latest_request, "host", None)),
        latest_path=_string_or_none(getattr(latest_request, "path", None)),
        latest_status_code=_int_or_none(getattr(latest_response, "status_code", None)),
        latest_request_source=_request_source_value(latest_request),
        latest_request_category=_request_source_category(latest_request),
        latest_operator_request_id=_string_or_none(getattr(latest_operator_request, "id", None)),
        latest_operator_request_source=_request_source_value(latest_operator_request),
        latest_operator_method=_string_or_none(getattr(latest_operator_request, "method", None)),
        latest_operator_host=_string_or_none(getattr(latest_operator_request, "host", None)),
        latest_operator_path=_string_or_none(getattr(latest_operator_request, "path", None)),
        latest_operator_status_code=_int_or_none(
            getattr(latest_operator_response, "status_code", None)
        ),
        total_request_count=inventory.total_request_count,
        operator_request_count=inventory.operator_request_count,
        replay_request_count=inventory.replay_request_count,
        unclassified_request_count=inventory.unclassified_request_count,
        endpoint_request_counts=inventory.endpoint_request_counts,
    )


async def _request_inventory(
    client: Client,
    *,
    scope_id: str | None = None,
    page_size: int = 200,
) -> _ProxyRequestInventory:
    builder = client.request.list().first(max(1, page_size)).descending("req", "created_at")
    if scope_id:
        builder = builder.scope(scope_id)

    connection = await builder.execute()
    edges = list(getattr(connection, "edges", []) or [])
    total = len(edges)
    operator_count = 0
    replay_count = 0
    unclassified_count = 0
    endpoint_counts: dict[str, int] = {}
    latest_operator_edge = None
    operator_count, replay_count, unclassified_count, latest_operator_edge = (
        _accumulate_request_inventory(
            endpoint_counts,
            edges,
            operator_count=operator_count,
            replay_count=replay_count,
            unclassified_count=unclassified_count,
            latest_operator_edge=latest_operator_edge,
        )
    )

    while _has_next_page(connection):
        next_page = await connection.next()
        if next_page is None:
            break
        connection = next_page
        edges = list(getattr(connection, "edges", []) or [])
        total += len(edges)
        operator_count, replay_count, unclassified_count, latest_operator_edge = (
            _accumulate_request_inventory(
                endpoint_counts,
                edges,
                operator_count=operator_count,
                replay_count=replay_count,
                unclassified_count=unclassified_count,
                latest_operator_edge=latest_operator_edge,
            )
        )

    return _ProxyRequestInventory(
        total_request_count=total,
        operator_request_count=operator_count,
        replay_request_count=replay_count,
        unclassified_request_count=unclassified_count,
        endpoint_request_counts=tuple(sorted(endpoint_counts.items())),
        latest_operator_edge=latest_operator_edge,
    )


async def _count_requests(
    client: Client,
    *,
    scope_id: str | None = None,
    page_size: int = 200,
) -> int:
    inventory = await _request_inventory(client, scope_id=scope_id, page_size=page_size)
    return inventory.total_request_count


def _accumulate_request_inventory(
    endpoint_counts: dict[str, int],
    edges: list[Any],
    *,
    operator_count: int,
    replay_count: int,
    unclassified_count: int,
    latest_operator_edge: Any | None,
) -> tuple[int, int, int, Any | None]:
    for edge in edges:
        node = getattr(edge, "node", None)
        request = getattr(node, "request", None)
        category = _request_source_category(request)
        if category == "operator":
            operator_count += 1
            if latest_operator_edge is None:
                latest_operator_edge = edge
        elif category == "replay":
            replay_count += 1
        else:
            unclassified_count += 1
        if category != "operator":
            continue
        method = _clean_endpoint_part(getattr(request, "method", None), max_length=16)
        host = _clean_endpoint_part(getattr(request, "host", None), max_length=255)
        path = _clean_endpoint_part(getattr(request, "path", None), max_length=512)
        if not method or not host or not path or _is_static_asset_request(method, path):
            continue
        if not path.startswith("/"):
            path = f"/{path}"
        endpoint = f"{method.upper()} {host}{path}"
        endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1
    return operator_count, replay_count, unclassified_count, latest_operator_edge


def _request_source_value(request: Any) -> str | None:
    if request is None or not hasattr(request, "source"):
        return None
    source = getattr(request, "source", None)
    if source is None:
        return None
    value = getattr(source, "value", source)
    cleaned = _clean_endpoint_part(value, max_length=32).lower()
    return cleaned or None


def _request_source_category(request: Any) -> str:
    if request is None or not hasattr(request, "source"):
        return "unclassified"
    source = _request_source_value(request)
    # Empty source marks ordinary proxy traffic; feature-generated traffic has an explicit source.
    if source in {None, "intercept"}:
        return "operator"
    if source == "replay":
        return "replay"
    return "unclassified"


def _clean_endpoint_part(value: Any, *, max_length: int) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())[:max_length]


def _is_static_asset_request(method: str, path: str) -> bool:
    if method.upper() != "GET":
        return False
    clean_path = path.split("?", 1)[0].casefold()
    return clean_path.endswith(
        (
            ".avif",
            ".bmp",
            ".css",
            ".eot",
            ".gif",
            ".ico",
            ".jpeg",
            ".jpg",
            ".js",
            ".map",
            ".otf",
            ".png",
            ".svg",
            ".ttf",
            ".webp",
            ".woff",
            ".woff2",
        )
    )


def _has_next_page(connection: Any) -> bool:
    page_info = getattr(connection, "page_info", None) or getattr(connection, "pageInfo", None)
    if page_info is None:
        return False
    return bool(
        getattr(page_info, "has_next_page", None)
        or getattr(page_info, "hasNextPage", None)
        or False
    )


def _string_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
