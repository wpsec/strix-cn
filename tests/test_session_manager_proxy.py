"""Tests for Burp upstream proxy metadata derived by session_manager."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from strix.runtime import session_manager


def test_burp_upstream_metadata_accepts_loopback_docker_endpoint(
    monkeypatch: object,
) -> None:
    monkeypatch.delenv("STRIX_DOCKER_SANDBOX_NETWORK", raising=False)

    url, reason = session_manager._burp_upstream_metadata(
        backend_name="docker",
        host_proxy_url="http://127.0.0.1:52123",
    )

    assert url == "http://127.0.0.1:52123"
    assert reason is None


def test_burp_upstream_metadata_rejects_custom_sandbox_network(
    monkeypatch: object,
) -> None:
    monkeypatch.setenv("STRIX_DOCKER_SANDBOX_NETWORK", "strix-net")

    url, reason = session_manager._burp_upstream_metadata(
        backend_name="docker",
        host_proxy_url="http://127.0.0.1:52123",
    )

    assert url is None
    assert reason == "当前自定义 sandbox network 模式未暴露可供 Burp 直连的本地代理端口"


def test_burp_upstream_metadata_rejects_non_loopback_host(
    monkeypatch: object,
) -> None:
    monkeypatch.delenv("STRIX_DOCKER_SANDBOX_NETWORK", raising=False)

    url, reason = session_manager._burp_upstream_metadata(
        backend_name="docker",
        host_proxy_url="http://192.168.1.20:52123",
    )

    assert url is None
    assert reason == "当前运行模式未提供仅本机可访问的 Burp 上游代理端口"


def test_burp_upstream_metadata_rejects_non_docker_backend(
    monkeypatch: object,
) -> None:
    monkeypatch.delenv("STRIX_DOCKER_SANDBOX_NETWORK", raising=False)

    url, reason = session_manager._burp_upstream_metadata(
        backend_name="remote",
        host_proxy_url="http://127.0.0.1:52123",
    )

    assert url is None
    assert reason == "当前 runtime backend 未提供可供 Burp 直连的本地代理端口"


def test_assert_burp_port_available_rejects_occupied_loopback_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _OccupiedSocket:
        def __enter__(self) -> "_OccupiedSocket":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            return None

        def connect_ex(self, _address: tuple[str, int]) -> int:
            return 0

    monkeypatch.setattr(session_manager.socket, "socket", lambda *_args, **_kwargs: _OccupiedSocket())

    with pytest.raises(RuntimeError, match=r"127\.0\.0\.1:8081 已被占用"):
        session_manager._assert_burp_port_available(
            backend_name="docker",
            burp_port=8081,
        )


@pytest.mark.asyncio
async def test_create_or_reuse_rejects_occupied_burp_port_before_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend_called = False

    async def _backend(**_kwargs: object) -> tuple[object, object]:
        nonlocal backend_called
        backend_called = True
        return object(), object()

    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: _backend)
    monkeypatch.setattr(
        session_manager,
        "_assert_burp_port_available",
        lambda **_kwargs: (_ for _ in ()).throw(
            RuntimeError("Burp 监听端口 127.0.0.1:8081 已被占用。")
        ),
    )

    with pytest.raises(RuntimeError, match=r"127\.0\.0\.1:8081 已被占用"):
        await session_manager.create_or_reuse(
            "scan-port-conflict",
            image="ghcr.io/usestrix/strix-sandbox:1.0.0",
            local_sources=[],
            burp_port=8081,
        )

    assert backend_called is False


@pytest.mark.asyncio
async def test_create_or_reuse_bootstraps_caido_with_host_bridge_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "scan-host-bridge"
    captured: dict[str, object] = {}

    class _FakeSession:
        async def resolve_exposed_port(self, port: int) -> object:
            if port == 48080:
                return SimpleNamespace(host="127.0.0.1", port=52123, tls=False)
            if port == 48081:
                return SimpleNamespace(host="127.0.0.1", port=8081, tls=False)
            raise AssertionError(f"unexpected port {port}")

    class _FakeClient:
        def __init__(self) -> None:
            self.deleted = False
            self.docker_client = None

        async def delete(self, _session: object) -> None:
            self.deleted = True

    async def _backend(**_kwargs: object) -> tuple[object, object]:
        return _FakeClient(), _FakeSession()

    class _FakeBridge:
        def __init__(self) -> None:
            self.released = False

        def upstream_config(self) -> object:
            return SimpleNamespace(host="host.docker.internal", port=18081, is_tls=False)

    fake_bridge = _FakeBridge()

    async def _bootstrap_caido(
        _session: object,
        *,
        host_url: str,
        container_url: str,
        upstream_proxy: object | None = None,
    ) -> object:
        captured["host_url"] = host_url
        captured["container_url"] = container_url
        captured["upstream_proxy"] = upstream_proxy
        return object()

    async def _release_bridge(proxy: object) -> None:
        captured["released"] = proxy

    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: _backend)
    monkeypatch.setattr(
        session_manager,
        "_assert_burp_port_available",
        lambda **_kwargs: None,
    )
    async def _acquire_bridge() -> object:
        return fake_bridge

    monkeypatch.setattr(
        session_manager,
        "acquire_shared_host_bridge_proxy",
        _acquire_bridge,
    )
    monkeypatch.setattr(session_manager, "release_shared_host_bridge_proxy", _release_bridge)
    monkeypatch.setattr(session_manager, "bootstrap_caido", _bootstrap_caido)
    session_manager._SESSION_CACHE.pop(scan_id, None)

    bundle = await session_manager.create_or_reuse(
        scan_id,
        image="ghcr.io/usestrix/strix-sandbox:1.0.0",
        local_sources=[],
        burp_port=8081,
    )
    try:
        assert bundle["host_bridge_proxy"] is fake_bridge
        assert bundle["caido_url"] == "http://127.0.0.1:8081"
        assert bundle["caido_ui_url"] == "http://127.0.0.1:52123"
        assert captured["host_url"] == "http://127.0.0.1:52123"
        assert captured["container_url"] == "http://127.0.0.1:48080"
        assert captured["upstream_proxy"].host == "host.docker.internal"
        assert captured["upstream_proxy"].port == 18081
        assert captured["upstream_proxy"].is_tls is False
    finally:
        await session_manager.cleanup(scan_id)

    assert captured["released"] is fake_bridge
