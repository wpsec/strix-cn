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


@pytest.mark.asyncio
async def test_ensure_container_proxy_listener_keeps_dedicated_proxy_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _accepts(_session: object, port: int) -> bool:
        return port == 48081

    started = False

    async def _start(_session: object, *, listen_port: int, target_port: int) -> None:  # noqa: ARG001
        nonlocal started
        started = True

    monkeypatch.setattr(session_manager, "_container_port_accepts_connections", _accepts)
    monkeypatch.setattr(session_manager, "_start_container_proxy_compat_shim", _start)

    await session_manager._ensure_container_proxy_listener(object())

    assert started is False


@pytest.mark.asyncio
async def test_ensure_container_proxy_listener_starts_compat_shim_for_legacy_single_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy_checks = [False, True]
    started: dict[str, int] = {}

    async def _accepts(_session: object, port: int) -> bool:
        if port == 48081:
            return proxy_checks.pop(0)
        if port == 48080:
            return True
        raise AssertionError(f"unexpected port {port}")

    async def _start(_session: object, *, listen_port: int, target_port: int) -> None:
        started["listen_port"] = listen_port
        started["target_port"] = target_port

    monkeypatch.setattr(session_manager, "_container_port_accepts_connections", _accepts)
    monkeypatch.setattr(session_manager, "_start_container_proxy_compat_shim", _start)

    await session_manager._ensure_container_proxy_listener(object())

    assert started == {
        "listen_port": 48081,
        "target_port": 48080,
    }


@pytest.mark.asyncio
async def test_ensure_container_proxy_listener_fails_without_proxy_or_ui_listener(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _accepts(_session: object, _port: int) -> bool:
        return False

    monkeypatch.setattr(session_manager, "_container_port_accepts_connections", _accepts)

    with pytest.raises(RuntimeError, match="既没有独立代理端口，也没有可回退的单端口监听"):
        await session_manager._ensure_container_proxy_listener(object())


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
async def test_cleanup_reclaims_persisted_labeled_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "scan-persisted"
    captured: dict[str, object] = {}

    class _Container:
        short_id = "container-1"

        def remove(self, *, force: bool) -> None:
            captured["force"] = force

    class _Containers:
        def list(self, *, all: bool, filters: dict[str, object]) -> list[_Container]:
            captured["all"] = all
            captured["filters"] = filters
            return [_Container()]

    class _DockerClient:
        containers = _Containers()

        def close(self) -> None:
            captured["closed"] = True

    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    monkeypatch.setattr(
        session_manager,
        "_docker_client_for_cleanup",
        lambda: _DockerClient(),
    )
    session_manager._SESSION_CACHE.pop(scan_id, None)

    await session_manager.cleanup(scan_id)

    assert captured["all"] is True
    assert captured["force"] is True
    assert captured["closed"] is True
    assert captured["filters"] == {
        "label": [
            "com.strix.managed=true",
            "com.strix.scan_id=scan-persisted",
        ]
    }


@pytest.mark.asyncio
async def test_create_or_reuse_deletes_session_when_endpoint_resolution_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "scan-endpoint-failure"

    class _FakeSession:
        async def resolve_exposed_port(self, port: int) -> object:
            if port == 48080:
                return SimpleNamespace(host="127.0.0.1", port=52123, tls=False)
            raise RuntimeError("proxy endpoint unavailable")

    class _FakeDockerClient:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class _FakeClient:
        def __init__(self) -> None:
            self.deleted = False
            self.docker_client = _FakeDockerClient()

        async def delete(self, _session: object) -> None:
            self.deleted = True

    client = _FakeClient()
    session = _FakeSession()

    async def _backend(**_kwargs: object) -> tuple[_FakeClient, _FakeSession]:
        return client, session

    monkeypatch.setattr(
        session_manager,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(backend="docker")),
    )
    monkeypatch.setattr(session_manager, "get_backend", lambda _name: _backend)
    monkeypatch.setattr(session_manager, "_assert_burp_port_available", lambda **_kwargs: None)
    session_manager._SESSION_CACHE.pop(scan_id, None)

    with pytest.raises(RuntimeError, match="proxy endpoint unavailable"):
        await session_manager.create_or_reuse(
            scan_id,
            image="ghcr.io/usestrix/strix-sandbox:1.0.0",
            local_sources=[],
            burp_port=8081,
        )

    assert client.deleted is True
    assert client.docker_client.closed is True
    assert scan_id not in session_manager._SESSION_CACHE


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


@pytest.mark.asyncio
async def test_refresh_bundle_caido_client_replaces_bundle_and_shared_ref(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _FakeClient:
        def __init__(self, name: str) -> None:
            self.name = name
            self.closed = False

        async def aclose(self) -> None:
            self.closed = True

    stale = _FakeClient("stale")
    fresh = _FakeClient("fresh")
    captured: dict[str, object] = {}

    async def _bootstrap_caido(
        session: object,
        *,
        host_url: str,
        container_url: str,
        upstream_proxy: object | None = None,
    ) -> object:
        captured["session"] = session
        captured["host_url"] = host_url
        captured["container_url"] = container_url
        captured["upstream_proxy"] = upstream_proxy
        return fresh

    monkeypatch.setattr(session_manager, "bootstrap_caido", _bootstrap_caido)

    bundle = {
        "session": object(),
        "caido_client": stale,
        "caido_client_ref": {"client": stale},
        "caido_host_url": "http://127.0.0.1:52123",
        "caido_container_url": "http://127.0.0.1:48080",
        "caido_upstream_proxy": SimpleNamespace(host="host.docker.internal", port=18081, is_tls=False),
    }

    refreshed = await session_manager.refresh_bundle_caido_client(
        bundle,
        expected_client=stale,
    )

    assert refreshed is fresh
    assert bundle["caido_client"] is fresh
    assert bundle["caido_client_ref"]["client"] is fresh
    assert stale.closed is True
    assert captured["host_url"] == "http://127.0.0.1:52123"
    assert captured["container_url"] == "http://127.0.0.1:48080"
