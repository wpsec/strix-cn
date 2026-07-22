"""Host-side polling helpers for Caido-captured proxy traffic."""

from __future__ import annotations

import asyncio
import json
import urllib.request
from dataclasses import dataclass
from typing import Any

from caido_sdk_client import Client, TokenAuthOptions


_LOGIN_AS_GUEST_BODY = (
    '{"query":"mutation LoginAsGuest { loginAsGuest { token { accessToken } } }"}'
)


@dataclass(slots=True, frozen=True)
class ProxyCaptureSnapshot:
    recent_request_count: int
    recent_request_has_more: bool
    latest_request_id: str | None
    latest_method: str | None
    latest_host: str | None
    latest_path: str | None
    latest_status_code: int | None


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
) -> ProxyCaptureSnapshot:
    token = await asyncio.to_thread(_login_as_guest, host_url)
    client = Client(host_url, auth=TokenAuthOptions(token=token))
    await client.connect()

    try:
        builder = client.request.list().first(max(1, recent_limit)).descending("req", "created_at")
        if scope_id:
            builder = builder.scope(scope_id)
        connection = await builder.execute()
    finally:
        await client.aclose()

    edges = list(getattr(connection, "edges", []) or [])
    latest = edges[0] if edges else None
    latest_node = getattr(latest, "node", None) if latest is not None else None
    latest_request = getattr(latest_node, "request", None)
    latest_response = getattr(latest_node, "response", None)

    return ProxyCaptureSnapshot(
        recent_request_count=len(edges),
        recent_request_has_more=_has_next_page(connection),
        latest_request_id=_string_or_none(getattr(latest_request, "id", None)),
        latest_method=_string_or_none(getattr(latest_request, "method", None)),
        latest_host=_string_or_none(getattr(latest_request, "host", None)),
        latest_path=_string_or_none(getattr(latest_request, "path", None)),
        latest_status_code=_int_or_none(getattr(latest_response, "status_code", None)),
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
