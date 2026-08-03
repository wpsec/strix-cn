"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import contextlib
import errno
import ipaddress
import logging
import os
import shutil
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from agents.sandbox.entries import BaseEntry, LocalDir
from agents.sandbox.manifest import Environment, Manifest

from strix.config import load_settings
from strix.runtime.backends import get_backend
from strix.runtime.caido_bootstrap import UpstreamProxyHttpConfig, bootstrap_caido
from strix.runtime.host_bridge_proxy import (
    HostBridgeProxyServer,
    acquire_shared_host_bridge_proxy,
    release_shared_host_bridge_proxy,
)
from strix.runtime.local_dir_staging import stage_symlink_safe_dir


logger = logging.getLogger(__name__)


# In-container Caido sidecar ports. The UI/GraphQL API and proxy listener are
# split so Burp can talk to a dedicated proxy port instead of Caido's mixed
# UI/proxy traffic splitter.
_CONTAINER_CAIDO_UI_PORT = 48080
_CONTAINER_CAIDO_PROXY_PORT = 48081


_SESSION_CACHE: dict[str, dict[str, Any]] = {}
_STRIX_MANAGED_LABEL = "com.strix.managed"
_STRIX_SCAN_LABEL = "com.strix.scan_id"

# Manifest root inside the container; entry keys hang off this path.
_WORKSPACE_ROOT = "/workspace"
_DOCKER_SANDBOX_NETWORK_ENV = "STRIX_DOCKER_SANDBOX_NETWORK"


def _is_loopback_host(host: str) -> bool:
    if not host:
        return False
    normalized = host.strip().strip("[]")
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def _burp_upstream_metadata(
    *,
    backend_name: str,
    host_proxy_url: str,
) -> tuple[str | None, str | None]:
    if backend_name != "docker":
        return None, "当前 runtime backend 未提供可供 Burp 直连的本地代理端口"

    if os.environ.get(_DOCKER_SANDBOX_NETWORK_ENV, "").strip():
        return None, "当前自定义 sandbox network 模式未暴露可供 Burp 直连的本地代理端口"

    parsed = urlparse(host_proxy_url)
    if not _is_loopback_host(parsed.hostname or ""):
        return None, "当前运行模式未提供仅本机可访问的 Burp 上游代理端口"

    return host_proxy_url, None


def _caido_ui_metadata(*, host_ui_url: str) -> str | None:
    parsed = urlparse(host_ui_url)
    if not _is_loopback_host(parsed.hostname or ""):
        return None
    return host_ui_url


def _assert_burp_port_available(*, backend_name: str, burp_port: int | None) -> None:
    if backend_name != "docker" or not burp_port:
        return

    if os.environ.get(_DOCKER_SANDBOX_NETWORK_ENV, "").strip():
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.settimeout(0.2)
        result = probe.connect_ex(("127.0.0.1", burp_port))
        if result == 0:
            raise RuntimeError(
                f"Burp 监听端口 127.0.0.1:{burp_port} 已被占用。"
                "请关闭占用该端口的 Strix/其他程序，或改用新的 --burp-port 后重试。"
            )
        if result not in {
            errno.ECONNREFUSED,
            errno.ETIMEDOUT,
            errno.EHOSTUNREACH,
            errno.ENETUNREACH,
            errno.EADDRNOTAVAIL,
        }:
            logger.debug(
                "Burp port probe for 127.0.0.1:%s returned errno=%s; continuing startup",
                burp_port,
                result,
            )


def _docker_client_for_cleanup() -> Any:
    import docker

    return docker.from_env()


async def _cleanup_persisted_docker_sessions(scan_id: str) -> None:
    """Remove labeled Strix containers when the process-local cache is gone."""
    try:
        docker_client = _docker_client_for_cleanup()
    except Exception:  # noqa: BLE001
        logger.debug("cleanup(%s): Docker client unavailable", scan_id, exc_info=True)
        return

    try:
        containers = docker_client.containers.list(
            all=True,
            filters={
                "label": [
                    f"{_STRIX_MANAGED_LABEL}=true",
                    f"{_STRIX_SCAN_LABEL}={scan_id}",
                ]
            },
        )
        for container in containers:
            try:
                container.remove(force=True)
                logger.info(
                    "Removed persisted Strix sandbox for scan %s (container=%s)",
                    scan_id,
                    getattr(container, "short_id", "?"),
                )
            except Exception:  # noqa: BLE001
                logger.exception(
                    "cleanup(%s): persisted container removal failed",
                    scan_id,
                )
    except Exception:  # noqa: BLE001
        logger.debug("cleanup(%s): persisted container lookup failed", scan_id, exc_info=True)
    finally:
        with contextlib.suppress(Exception):
            docker_client.close()


async def _cleanup_partial_session(
    *,
    scan_id: str,
    client: Any | None,
    session: Any | None,
    caido_client: Any | None,
    host_bridge_proxy: Any | None,
) -> None:
    """Best-effort teardown for a session that never reached the cache."""
    if caido_client is not None:
        with contextlib.suppress(Exception):
            await caido_client.aclose()

    if host_bridge_proxy is not None:
        with contextlib.suppress(Exception):
            await release_shared_host_bridge_proxy(host_bridge_proxy)

    if client is None or session is None:
        return

    try:
        await client.delete(session)
    except Exception:  # noqa: BLE001
        logger.exception(
            "cleanup(%s): partially-created session deletion failed",
            scan_id,
        )
    finally:
        docker_client = getattr(client, "docker_client", None)
        if docker_client is not None:
            with contextlib.suppress(Exception):
                docker_client.close()


def build_session_entries(
    local_sources: list[dict[str, Any]],
) -> tuple[dict[str | Path, BaseEntry], list[dict[str, Any]], list[Path]]:
    """Split local sources into copied manifest entries and host bind mounts.

    Sources flagged ``mount`` are bind-mounted read-only at
    ``/workspace/<workspace_subdir>`` (not added to the manifest, so the SDK
    does not stream them in file-by-file). Every other source becomes a
    ``LocalDir`` entry copied into the container as before. Trees containing
    symlinks (which the SDK's ``LocalDir`` walker refuses outright) are first
    staged into a symlink-safe temp copy; those temp dirs are returned so the
    caller can remove them once the upload completes.
    """
    entries: dict[str | Path, BaseEntry] = {}
    bind_mounts: list[dict[str, Any]] = []
    staged_dirs: list[Path] = []
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        resolved = Path(host_path).expanduser().resolve()
        if src.get("mount"):
            bind_mounts.append(
                {
                    "source": str(resolved),
                    "target": f"{_WORKSPACE_ROOT}/{ws_subdir}",
                    "read_only": True,
                }
            )
        else:
            upload_path, staged = stage_symlink_safe_dir(resolved)
            if staged is not None:
                staged_dirs.append(staged)
            entries[ws_subdir] = LocalDir(src=upload_path)
    return entries, bind_mounts, staged_dirs


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, Any]],
    burp_port: int | None = None,
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry exposes its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container — copied in, or
    bind-mounted read-only when the entry is flagged ``mount``.
    """
    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        logger.info("Reusing existing sandbox session for scan %s", scan_id)
        return cached

    entries, bind_mounts, staged_dirs = build_session_entries(local_sources)

    # Caido runs as an in-container sidecar; HTTP(S) traffic from any
    # process started via ``session.exec`` (the SDK's Shell tool, etc.)
    # picks up these env vars automatically. ``NO_PROXY`` keeps the
    # agent-browser CDP daemon's localhost traffic from looping back
    # through Caido.
    container_caido_proxy_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PROXY_PORT}"
    container_caido_ui_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_UI_PORT}"
    manifest = Manifest(
        entries=entries,
        environment=Environment(
            value={
                "PYTHONUNBUFFERED": "1",
                "HOST_GATEWAY": "host.docker.internal",
                "http_proxy": container_caido_proxy_url,
                "https_proxy": container_caido_proxy_url,
                "ALL_PROXY": container_caido_proxy_url,
                "NO_PROXY": "localhost,127.0.0.1",
            },
        ),
    )

    backend_name = load_settings().runtime.backend
    backend = get_backend(backend_name)
    _assert_burp_port_available(backend_name=backend_name, burp_port=burp_port)

    logger.info(
        "Creating sandbox session for scan %s (backend=%s, image=%s)",
        scan_id,
        backend_name,
        image,
    )
    client: Any | None = None
    session: Any | None = None
    caido_client: Any | None = None
    host_bridge_proxy: HostBridgeProxyServer | None = None
    try:
        backend_kwargs: dict[str, Any] = {
            "image": image,
            "manifest": manifest,
            "exposed_ports": (_CONTAINER_CAIDO_UI_PORT, _CONTAINER_CAIDO_PROXY_PORT),
            "bind_mounts": bind_mounts,
            "exposed_port_bindings": {
                _CONTAINER_CAIDO_PROXY_PORT: burp_port,
            }
            if burp_port
            else None,
        }
        if backend_name == "docker":
            backend_kwargs["scan_id"] = scan_id
        client, session = await backend(
            **backend_kwargs,
        )
        caido_ui_endpoint = await session.resolve_exposed_port(_CONTAINER_CAIDO_UI_PORT)
        ui_scheme = "https" if caido_ui_endpoint.tls else "http"
        host_caido_ui_url = f"{ui_scheme}://{caido_ui_endpoint.host}:{caido_ui_endpoint.port}"

        caido_proxy_endpoint = await session.resolve_exposed_port(_CONTAINER_CAIDO_PROXY_PORT)
        proxy_scheme = "https" if caido_proxy_endpoint.tls else "http"
        host_caido_proxy_url = (
            f"{proxy_scheme}://{caido_proxy_endpoint.host}:{caido_proxy_endpoint.port}"
        )
        logger.debug(
            "Caido host endpoints resolved: ui=%s proxy=%s",
            host_caido_ui_url,
            host_caido_proxy_url,
        )
        burp_upstream_url, burp_upstream_unavailable_reason = _burp_upstream_metadata(
            backend_name=backend_name,
            host_proxy_url=host_caido_proxy_url,
        )
        caido_ui_url = _caido_ui_metadata(host_ui_url=host_caido_ui_url)
        upstream_proxy: UpstreamProxyHttpConfig | None = None
        if backend_name == "docker":
            host_bridge_proxy = await acquire_shared_host_bridge_proxy()
            upstream_proxy = host_bridge_proxy.upstream_config()

        caido_client = await bootstrap_caido(
            session,
            host_url=host_caido_ui_url,
            container_url=container_caido_ui_url,
            upstream_proxy=upstream_proxy,
        )
    except BaseException:
        await _cleanup_partial_session(
            scan_id=scan_id,
            client=client,
            session=session,
            caido_client=caido_client,
            host_bridge_proxy=host_bridge_proxy,
        )
        raise
    finally:
        for staged in staged_dirs:
            shutil.rmtree(staged, ignore_errors=True)

    bundle = {
        "client": client,
        "session": session,
        "caido_client": caido_client,
        "caido_client_ref": {"client": caido_client},
        "caido_host_url": host_caido_ui_url,
        "caido_container_url": container_caido_ui_url,
        "caido_upstream_proxy": upstream_proxy,
        "caido_url": burp_upstream_url,
        "caido_ui_url": caido_ui_url,
        "burp_upstream_unavailable_reason": burp_upstream_unavailable_reason,
        "host_bridge_proxy": host_bridge_proxy,
    }
    _SESSION_CACHE[scan_id] = bundle
    logger.info("Sandbox session for scan %s ready and cached", scan_id)
    return bundle


async def cleanup(scan_id: str) -> None:
    """Tear down ``scan_id``'s container and drop its cache entry.

    Best-effort: any error during ``client.delete`` is logged and
    swallowed. If the process-local cache is gone, labeled Docker
    containers are also looked up by ``scan_id`` so a later cleanup can
    reclaim a session left behind by an interrupted process.
    """
    bundle = _SESSION_CACHE.pop(scan_id, None)
    if bundle is None:
        logger.debug("cleanup(%s): no cached session", scan_id)
        try:
            backend_name = load_settings().runtime.backend
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): unable to resolve runtime backend", scan_id, exc_info=True)
            return
        if backend_name == "docker":
            await _cleanup_persisted_docker_sessions(scan_id)
        return

    caido_client = bundle.get("caido_client")
    if caido_client is not None:
        try:
            await caido_client.aclose()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): caido_client.aclose() raised", scan_id, exc_info=True)

    host_bridge_proxy = bundle.get("host_bridge_proxy")
    if host_bridge_proxy is not None:
        try:
            await release_shared_host_bridge_proxy(host_bridge_proxy)
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): host bridge proxy release raised", scan_id, exc_info=True)

    client = bundle["client"]
    try:
        await client.delete(bundle["session"])
        logger.info("Cleaned up sandbox session for scan %s", scan_id)
    except Exception:
        logger.exception(
            "cleanup(%s): client.delete raised; container may need manual reaping",
            scan_id,
        )

    docker_client = getattr(client, "docker_client", None)
    if docker_client is not None:
        try:
            docker_client.close()
        except Exception:  # noqa: BLE001
            logger.debug("cleanup(%s): docker_client.close() raised", scan_id, exc_info=True)


async def refresh_bundle_caido_client(
    bundle: dict[str, Any],
    *,
    expected_client: Any | None = None,
) -> Any:
    """Re-bootstrap a session bundle's Caido client after a transport failure."""
    current_client = bundle.get("caido_client")
    if expected_client is not None and current_client is not None and current_client is not expected_client:
        client_ref = bundle.get("caido_client_ref")
        if isinstance(client_ref, dict):
            client_ref["client"] = current_client
        return current_client

    host_url = bundle.get("caido_host_url")
    container_url = bundle.get("caido_container_url")
    session = bundle.get("session")
    if not isinstance(host_url, str) or not isinstance(container_url, str) or session is None:
        raise RuntimeError("Caido refresh metadata missing from session bundle")

    new_client = await bootstrap_caido(
        session,
        host_url=host_url,
        container_url=container_url,
        upstream_proxy=bundle.get("caido_upstream_proxy"),
    )
    bundle["caido_client"] = new_client
    client_ref = bundle.get("caido_client_ref")
    if isinstance(client_ref, dict):
        client_ref["client"] = new_client
    if current_client is not None and current_client is not new_client:
        with contextlib.suppress(Exception):
            await current_client.aclose()
    return new_client
