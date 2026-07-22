"""Tests for the shared Caido client lifecycle and proxy call serialization.

Covers the caching + serialization guarantees of ``caido_api.call_with_client``
(the sandbox-imported path) and ``proxy.tools._call`` (the host-side path). The
Caido GraphQL transport is not concurrency-safe, so both paths must run one
call at a time against the shared client.
"""

from __future__ import annotations

import asyncio
import json
from typing import TYPE_CHECKING, Any, cast

import pytest

from strix.tools.proxy import caido_api, tools


if TYPE_CHECKING:
    from collections.abc import Iterator


class _FakeClient:
    def __init__(self, name: str) -> None:
        self.name = name
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _clear_cache() -> Iterator[None]:
    caido_api._CLIENT_CACHE.clear()
    yield
    caido_api._CLIENT_CACHE.clear()


async def test_call_with_client_reuses_cached_client(monkeypatch: pytest.MonkeyPatch) -> None:
    cached = _FakeClient("cached")
    caido_api._CLIENT_CACHE["default"] = cast("Any", cached)

    async def _new() -> Any:
        raise AssertionError("_new_client must not run when a client is cached")

    monkeypatch.setattr(caido_api, "_new_client", _new)

    seen: dict[str, Any] = {}

    async def fn(client: Any) -> str:
        seen["client"] = client
        return "ok"

    assert await caido_api.call_with_client(fn) == "ok"
    assert seen["client"] is cached


async def test_call_with_client_creates_and_caches_when_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created = _FakeClient("fresh")

    async def _new() -> Any:
        return created

    monkeypatch.setattr(caido_api, "_new_client", _new)

    seen: dict[str, Any] = {}

    async def fn(client: Any) -> str:
        seen["client"] = client
        return "ok"

    assert await caido_api.call_with_client(fn) == "ok"
    assert seen["client"] is created
    assert caido_api._CLIENT_CACHE["default"] is created


async def test_failed_init_does_not_poison_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _new() -> Any:
        raise ConnectionRefusedError("caido not up yet")

    monkeypatch.setattr(caido_api, "_new_client", _new)

    async def fn(_client: Any) -> str:
        return "unreachable"

    with pytest.raises(ConnectionRefusedError):
        await caido_api.call_with_client(fn)
    assert "default" not in caido_api._CLIENT_CACHE


async def test_call_with_client_propagates_errors() -> None:
    cached = _FakeClient("cached")
    caido_api._CLIENT_CACHE["default"] = cast("Any", cached)

    async def fn(_client: Any) -> str:
        raise ValueError("Invalid HTTPQL filter")

    with pytest.raises(ValueError, match="Invalid HTTPQL"):
        await caido_api.call_with_client(fn)
    assert caido_api._CLIENT_CACHE["default"] is cached


async def test_call_with_client_serializes_concurrent_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caido_api._CLIENT_CACHE["default"] = cast("Any", _FakeClient("shared"))

    async def _new() -> Any:
        raise AssertionError("no new client expected")

    monkeypatch.setattr(caido_api, "_new_client", _new)

    state = {"active": 0, "max": 0}

    async def fn(_client: Any) -> str:
        state["active"] += 1
        state["max"] = max(state["max"], state["active"])
        await asyncio.sleep(0.01)
        state["active"] -= 1
        return "ok"

    await asyncio.gather(*(caido_api.call_with_client(fn) for _ in range(6)))
    assert state["max"] == 1


async def test_host_call_serializes_concurrent_calls() -> None:
    client = _FakeClient("host")
    state = {"active": 0, "max": 0}

    async def fn(_client: Any) -> str:
        state["active"] += 1
        state["max"] = max(state["max"], state["active"])
        await asyncio.sleep(0.01)
        state["active"] -= 1
        return "ok"

    await asyncio.gather(*(tools._call(cast("Any", client), fn) for _ in range(6)))
    assert state["max"] == 1


class _Ctx:
    def __init__(self, context: Any) -> None:
        self.context = context
        self.tool_name = "proxy_test"


def test_ctx_client_returns_client_when_present() -> None:
    client = _FakeClient("host")
    got = tools._ctx_client(cast("Any", _Ctx({"caido_client": client})))
    assert got is client


def test_ctx_client_returns_none_without_client() -> None:
    assert tools._ctx_client(cast("Any", _Ctx({}))) is None
    assert tools._ctx_client(cast("Any", _Ctx(None))) is None


def test_ctx_scope_id_returns_scope_when_present() -> None:
    assert tools._ctx_scope_id(cast("Any", _Ctx({"caido_scope_id": "scope-1"}))) == "scope-1"


def test_ctx_scope_patterns_returns_allow_and_deny_lists() -> None:
    allow, deny = tools._ctx_scope_patterns(
        cast(
            "Any",
            _Ctx({"caido_scope_allowlist": ["app.example.com"], "caido_scope_denylist": ["*.google.com"]}),
        )
    )
    assert allow == ["app.example.com"]
    assert deny == ["*.google.com"]


def test_coerce_sitemap_entry_id_accepts_numeric_string() -> None:
    value, error = caido_api._coerce_sitemap_entry_id("42", field_name="parent_id")
    assert value == 42
    assert error is None


def test_coerce_sitemap_entry_id_rejects_request_style_id() -> None:
    value, error = caido_api._coerce_sitemap_entry_id("req_123", field_name="parent_id")
    assert value is None
    assert error is not None
    assert "数字型 sitemap 条目 ID" in error


async def test_list_sitemap_with_client_rejects_invalid_parent_id_without_querying() -> None:
    class _GraphQL:
        def __init__(self) -> None:
            self.called = False

        async def query(self, *_args: Any, **_kwargs: Any) -> Any:
            self.called = True
            raise AssertionError("query should not run for invalid parent_id")

    class _SitemapClient:
        def __init__(self) -> None:
            self.graphql = _GraphQL()

    client = _SitemapClient()

    result = await caido_api.list_sitemap_with_client(cast("Any", client), parent_id="req_123")

    assert result["success"] is False
    assert "数字型 sitemap 条目 ID" in result["error"]
    assert client.graphql.called is False


async def test_list_requests_defaults_to_context_scope_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient("host")
    captured: dict[str, Any] = {}

    class _PageInfo:
        has_next_page = False
        has_previous_page = False
        start_cursor = None
        end_cursor = None

    class _Connection:
        edges: list[Any] = []
        page_info = _PageInfo()

    async def _list_requests_with_client(
        _client: Any,
        *,
        httpql_filter: str | None = None,
        first: int = 50,
        after: str | None = None,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
        scope_id: str | None = None,
    ) -> Any:
        captured["scope_id"] = scope_id
        return _Connection()

    monkeypatch.setattr(caido_api, "list_requests_with_client", _list_requests_with_client)

    payload = await tools.list_requests.on_invoke_tool(
        cast("Any", _Ctx({"caido_client": client, "caido_scope_id": "scope-1"})),
        json.dumps({}),
    )

    assert json.loads(payload)["success"] is True
    assert captured["scope_id"] == "scope-1"


async def test_repeat_request_blocks_out_of_scope_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _FakeClient("host")

    class _Request:
        host = "api.google.com"
        raw = b"GET / HTTP/1.1\r\nHost: api.google.com\r\n\r\n"

    class _RequestResult:
        request = _Request()

    async def _get_request_with_client(_client: Any, _request_id: str, *, part: str = "request") -> Any:
        return _RequestResult()

    monkeypatch.setattr(caido_api, "get_request_with_client", _get_request_with_client)

    payload = await tools.repeat_request.on_invoke_tool(
        cast(
            "Any",
            _Ctx(
                {
                    "caido_client": client,
                    "caido_scope_allowlist": ["app.example.com"],
                    "caido_scope_denylist": ["google.com", "*.google.com"],
                }
            ),
        ),
        json.dumps({"request_id": "req-1"}),
    )

    result = json.loads(payload)
    assert result["success"] is False
    assert "不在当前 Strix 代理作用域内" in result["error"]
