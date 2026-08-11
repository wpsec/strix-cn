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
    total_request_count: int = 0
    endpoint_request_counts: tuple[tuple[str, int], ...] = ()


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
    total_request_count, endpoint_request_counts = await _request_inventory(
        client,
        scope_id=scope_id,
        page_size=max(1, total_page_size),
    )

    edges = list(getattr(connection, "edges", []) or [])
    latest = edges[0] if edges else None
    latest_node = getattr(latest, "node", None) if latest is not None else None
    latest_request = getattr(latest_node, "request", None)
    latest_response = getattr(latest_node, "response", None)

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
        total_request_count=total_request_count,
        endpoint_request_counts=endpoint_request_counts,
    )


async def _request_inventory(
    client: Client,
    *,
    scope_id: str | None = None,
    page_size: int = 200,
) -> tuple[int, tuple[tuple[str, int], ...]]:
    builder = client.request.list().first(max(1, page_size)).descending("req", "created_at")
    if scope_id:
        builder = builder.scope(scope_id)

    connection = await builder.execute()
    edges = list(getattr(connection, "edges", []) or [])
    total = len(edges)
    endpoint_counts: dict[str, int] = {}
    _accumulate_endpoint_counts(endpoint_counts, edges)

    while _has_next_page(connection):
        next_page = await connection.next()
        if next_page is None:
            break
        connection = next_page
        edges = list(getattr(connection, "edges", []) or [])
        total += len(edges)
        _accumulate_endpoint_counts(endpoint_counts, edges)

    return total, tuple(sorted(endpoint_counts.items()))


async def _count_requests(
    client: Client,
    *,
    scope_id: str | None = None,
    page_size: int = 200,
) -> int:
    total, _ = await _request_inventory(client, scope_id=scope_id, page_size=page_size)
    return total


def _accumulate_endpoint_counts(endpoint_counts: dict[str, int], edges: list[Any]) -> None:
    for edge in edges:
        node = getattr(edge, "node", None)
        request = getattr(node, "request", None)
        method = _clean_endpoint_part(getattr(request, "method", None), max_length=16)
        host = _clean_endpoint_part(getattr(request, "host", None), max_length=255)
        path = _clean_endpoint_part(getattr(request, "path", None), max_length=512)
        if not method or not host or not path or _is_static_asset_request(method, path):
            continue
        if not path.startswith("/"):
            path = f"/{path}"
        endpoint = f"{method.upper()} {host}{path}"
        endpoint_counts[endpoint] = endpoint_counts.get(endpoint, 0) + 1


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
