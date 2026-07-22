"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import contextlib
import ipaddress
import logging
import os
import shutil
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


# In-container Caido sidecar port (matches the image's caido-cli bind).
_CONTAINER_CAIDO_PORT = 48080


_SESSION_CACHE: dict[str, dict[str, Any]] = {}

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
    host_caido_url: str,
) -> tuple[str | None, str | None]:
    if backend_name != "docker":
        return None, "当前 runtime backend 未提供可供 Burp 直连的本地代理端口"

    if os.environ.get(_DOCKER_SANDBOX_NETWORK_ENV, "").strip():
        return None, "当前自定义 sandbox network 模式未暴露可供 Burp 直连的本地代理端口"

    parsed = urlparse(host_caido_url)
    if not _is_loopback_host(parsed.hostname or ""):
        return None, "当前运行模式未提供仅本机可访问的 Burp 上游代理端口"

    return host_caido_url, None


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
    container_caido_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PORT}"
    manifest = Manifest(
        entries=entries,
        environment=Environment(
            value={
                "PYTHONUNBUFFERED": "1",
                "HOST_GATEWAY": "host.docker.internal",
                "http_proxy": container_caido_url,
                "https_proxy": container_caido_url,
                "ALL_PROXY": container_caido_url,
                "NO_PROXY": "localhost,127.0.0.1",
            },
        ),
    )

    backend_name = load_settings().runtime.backend
    backend = get_backend(backend_name)

    logger.info(
        "Creating sandbox session for scan %s (backend=%s, image=%s)",
        scan_id,
        backend_name,
        image,
    )
    try:
        client, session = await backend(
            image=image,
            manifest=manifest,
            exposed_ports=(_CONTAINER_CAIDO_PORT,),
            bind_mounts=bind_mounts,
            exposed_port_bindings={_CONTAINER_CAIDO_PORT: burp_port} if burp_port else None,
        )
    finally:
        for staged in staged_dirs:
            shutil.rmtree(staged, ignore_errors=True)

    caido_endpoint = await session.resolve_exposed_port(_CONTAINER_CAIDO_PORT)
    scheme = "https" if caido_endpoint.tls else "http"
    host_caido_url = f"{scheme}://{caido_endpoint.host}:{caido_endpoint.port}"
    logger.debug("Caido host endpoint resolved: %s", host_caido_url)
    burp_upstream_url, burp_upstream_unavailable_reason = _burp_upstream_metadata(
        backend_name=backend_name,
        host_caido_url=host_caido_url,
    )
    host_bridge_proxy: HostBridgeProxyServer | None = None
    try:
        upstream_proxy: UpstreamProxyHttpConfig | None = None
        if backend_name == "docker":
            host_bridge_proxy = await acquire_shared_host_bridge_proxy()
            upstream_proxy = host_bridge_proxy.upstream_config()

        caido_client = await bootstrap_caido(
            session,
            host_url=host_caido_url,
            container_url=container_caido_url,
            upstream_proxy=upstream_proxy,
        )
    except Exception:
        if host_bridge_proxy is not None:
            await release_shared_host_bridge_proxy(host_bridge_proxy)
        with contextlib.suppress(Exception):
            await client.delete(session)
        raise

    bundle = {
        "client": client,
        "session": session,
        "caido_client": caido_client,
        "caido_url": burp_upstream_url,
        "burp_upstream_unavailable_reason": burp_upstream_unavailable_reason,
        "host_bridge_proxy": host_bridge_proxy,
    }
    _SESSION_CACHE[scan_id] = bundle
    logger.info("Sandbox session for scan %s ready and cached", scan_id)
    return bundle


async def cleanup(scan_id: str) -> None:
    """Tear down ``scan_id``'s container and drop its cache entry.

    Best-effort: any error during ``client.delete`` is logged and
    swallowed. We never want a cleanup failure to prevent the next
    scan from starting; the worst case is a stranded container that
    Docker's normal reaping will catch on next ``docker prune``.
    """
    bundle = _SESSION_CACHE.pop(scan_id, None)
    if bundle is None:
        logger.debug("cleanup(%s): no cached session", scan_id)
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
