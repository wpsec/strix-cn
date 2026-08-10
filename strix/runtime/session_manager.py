"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import errno
import ipaddress
import logging
import os
import shlex
import socket
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from agents.sandbox.entries import BaseEntry, LocalDir
from agents.sandbox.manifest import Environment, Manifest

from strix.config import load_settings
from strix.runtime.backends import backend_supports_bind_mounts, get_backend
from strix.runtime.caido_bootstrap import UpstreamProxyHttpConfig, bootstrap_caido
from strix.runtime.host_bridge_proxy import (
    HostBridgeProxyServer,
    acquire_shared_host_bridge_proxy,
    release_shared_host_bridge_proxy,
)

if TYPE_CHECKING:
    from strix.runtime.status import StatusSink


logger = logging.getLogger(__name__)


# In-container Caido sidecar ports. The UI/GraphQL API and proxy listener are
# split so Burp can talk to a dedicated proxy port instead of Caido's mixed
# UI/proxy traffic splitter.
_CONTAINER_CAIDO_UI_PORT = 48080
_CONTAINER_CAIDO_PROXY_PORT = 48081


_SESSION_CACHE: dict[str, dict[str, Any]] = {}
_STRIX_MANAGED_LABEL = "com.strix.managed"
_STRIX_SCAN_LABEL = "com.strix.scan_id"
_CONTAINER_PROXY_COMPAT_LOG = "/tmp/strix-caido-proxy-compat.log"
_CONTAINER_PROXY_COMPAT_PID = "/tmp/strix-caido-proxy-compat.pid"

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


def _result_stream_text(stream: Any) -> str:
    if isinstance(stream, bytes):
        return stream.decode("utf-8", errors="replace")
    if isinstance(stream, str):
        return stream
    return str(stream or "")


async def _container_port_accepts_connections(session: Any, port: int) -> bool:
    exec_command = getattr(session, "exec", None)
    if not callable(exec_command):
        return False

    script = (
        "import socket, sys\n"
        f"sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "sock.settimeout(0.25)\n"
        f"result = sock.connect_ex(('127.0.0.1', {port}))\n"
        "sock.close()\n"
        "sys.exit(0 if result == 0 else 1)\n"
    )
    result = await exec_command("python3", "-c", script, timeout=10)
    return bool(result.ok())


async def _start_container_proxy_compat_shim(
    session: Any,
    *,
    listen_port: int,
    target_port: int,
) -> None:
    exec_command = getattr(session, "exec", None)
    if not callable(exec_command):
        raise RuntimeError("当前 sandbox session 不支持 exec，无法启动 Caido 兼容代理")

    shim_script = _container_proxy_compat_shim_script(
        listen_port=listen_port,
        target_port=target_port,
    )
    payload = base64.b64encode(shim_script.encode("utf-8")).decode("ascii")
    python_command = (
        "import base64; "
        f"exec(compile(base64.b64decode({payload!r}), "
        "'_strix_caido_proxy_compat.py', 'exec'))"
    )
    shell_command = (
        f"nohup python3 -c {shlex.quote(python_command)} "
        f">{shlex.quote(_CONTAINER_PROXY_COMPAT_LOG)} 2>&1 < /dev/null & "
        f"echo $! > {shlex.quote(_CONTAINER_PROXY_COMPAT_PID)}"
    )
    result = await exec_command("sh", "-lc", shell_command, timeout=15)
    if result.ok():
        return

    stderr = _result_stream_text(getattr(result, "stderr", "")).strip()
    stdout = _result_stream_text(getattr(result, "stdout", "")).strip()
    detail = stderr or stdout or f"exit={result.exit_code}"
    raise RuntimeError(f"启动 Caido 旧镜像兼容代理失败：{detail}")


def _container_proxy_compat_shim_script(
    *,
    listen_port: int,
    target_port: int,
) -> str:
    # Bind on 0.0.0.0 so Docker's published host port can reach the shim.
    # The upstream Caido mixed-mode listener stays on loopback inside the
    # container, so only the compatibility layer is exposed externally.
    return f"""
import socket
import threading

LISTEN = ("0.0.0.0", {listen_port})
TARGET = ("127.0.0.1", {target_port})


def pipe(reader, writer):
    try:
        while True:
            data = reader.recv(65536)
            if not data:
                break
            writer.sendall(data)
    except Exception:
        pass
    finally:
        try:
            writer.shutdown(socket.SHUT_WR)
        except Exception:
            pass
        try:
            reader.close()
        except Exception:
            pass
        try:
            writer.close()
        except Exception:
            pass


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(LISTEN)
server.listen(128)

while True:
    client, _ = server.accept()
    try:
        upstream = socket.create_connection(TARGET, timeout=10)
    except Exception:
        client.close()
        continue
    threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
    threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()
""".strip()


async def _ensure_container_proxy_listener(
    session: Any,
    *,
    proxy_port: int = _CONTAINER_CAIDO_PROXY_PORT,
    ui_port: int = _CONTAINER_CAIDO_UI_PORT,
) -> None:
    if await _container_port_accepts_connections(session, proxy_port):
        return

    if not await _container_port_accepts_connections(session, ui_port):
        raise RuntimeError(
            "Caido 代理监听未就绪：容器内既没有独立代理端口，也没有可回退的单端口监听"
        )

    logger.warning(
        "Caido sandbox image is using legacy single-port mode; enabling proxy compatibility shim %s -> %s",
        proxy_port,
        ui_port,
    )
    await _start_container_proxy_compat_shim(
        session,
        listen_port=proxy_port,
        target_port=ui_port,
    )

    for _attempt in range(10):
        if await _container_port_accepts_connections(session, proxy_port):
            logger.info(
                "Enabled Caido proxy compatibility shim inside sandbox: %s -> %s",
                proxy_port,
                ui_port,
            )
            return
        await asyncio.sleep(0.2)

    raise RuntimeError(
        "Caido 旧镜像兼容代理启动后仍未监听独立代理端口，请更新 sandbox image 后重试"
    )


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

_PROTECTED_METADATA_NAMES = (".git", ".agents", ".codex")


def _host_identity_env() -> dict[str, str]:
    # Read the platform through a local so it is not narrowed to whichever OS is
    # type-checking: comparing sys.platform directly makes one of these branches
    # statically dead, and which one flips between Linux and macOS.
    platform_name: str = sys.platform
    if platform_name != "linux":
        return {}
    # Bind-mount ownership only needs mapping on Linux, where the container uid
    # must match the host's.
    return {"STRIX_HOST_UID": str(os.getuid()), "STRIX_HOST_GID": str(os.getgid())}


def build_bind_mounts(local_sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
    bind_mounts: list[dict[str, Any]] = []
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        resolved = Path(host_path).expanduser().resolve()
        target = f"{_WORKSPACE_ROOT}/{ws_subdir}"
        bind_mounts.append({"source": str(resolved), "target": target, "read_only": False})
        if src.get("protect_metadata"):
            bind_mounts.extend(_metadata_mounts(resolved, target))
    return bind_mounts


def build_manifest_entries(local_sources: list[dict[str, Any]]) -> dict[str | Path, BaseEntry]:
    entries: dict[str | Path, BaseEntry] = {}
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        entries[ws_subdir] = LocalDir(src=Path(host_path).expanduser().resolve())
    return entries


def _metadata_mounts(tree: Path, target: str) -> list[dict[str, Any]]:
    mounts: list[dict[str, Any]] = []
    for name in _PROTECTED_METADATA_NAMES:
        metadata = tree / name
        if not metadata.is_dir() and not metadata.is_file():
            continue
        if not metadata.resolve().is_relative_to(tree):
            continue
        mounts.append({"source": str(metadata), "target": f"{target}/{name}", "read_only": True})
        gitdir = _gitdir_from_pointer(metadata) if metadata.is_file() else None
        if gitdir is not None and gitdir.exists() and gitdir.is_relative_to(tree):
            relative = gitdir.relative_to(tree).as_posix()
            mounts.append(
                {"source": str(gitdir), "target": f"{target}/{relative}", "read_only": True}
            )
    return mounts


def _gitdir_from_pointer(git_file: Path) -> Path | None:
    try:
        content = git_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in content.splitlines():
        prefix, _, value = line.partition(":")
        if prefix.strip() == "gitdir" and value.strip():
            candidate = Path(value.strip()).expanduser()
            if not candidate.is_absolute():
                candidate = git_file.parent / candidate
            return candidate.resolve()
    return None


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, Any]],
    burp_port: int | None = None,
    status_sink: StatusSink | None = None,
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry exposes its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container.
    """

    def report(phase: str) -> None:
        if status_sink is not None:
            status_sink(phase)

    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        logger.info("Reusing existing sandbox session for scan %s", scan_id)
        return cached

    backend_name = load_settings().runtime.backend
    backend = get_backend(backend_name)

    if backend_supports_bind_mounts(backend_name):
        bind_mounts = build_bind_mounts(local_sources)
        entries: dict[str | Path, BaseEntry] = {}
    else:
        bind_mounts = []
        entries = build_manifest_entries(local_sources)

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
                **_host_identity_env(),
                "http_proxy": container_caido_proxy_url,
                "https_proxy": container_caido_proxy_url,
                "ALL_PROXY": container_caido_proxy_url,
                "NO_PROXY": "localhost,127.0.0.1",
            },
        ),
    )

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
    upstream_proxy: UpstreamProxyHttpConfig | None = None
    host_caido_ui_url = ""
    host_caido_proxy_url = ""
    burp_upstream_url: str | None = None
    burp_upstream_unavailable_reason: str | None = None
    caido_ui_url: str | None = None
    try:
        report("Starting sandbox container")
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
        report("Setting up the proxy")
        burp_upstream_url, burp_upstream_unavailable_reason = _burp_upstream_metadata(
            backend_name=backend_name,
            host_proxy_url=host_caido_proxy_url,
        )
        caido_ui_url = _caido_ui_metadata(host_ui_url=host_caido_ui_url)
        if backend_name == "docker":
            host_bridge_proxy = await acquire_shared_host_bridge_proxy()
            upstream_proxy = host_bridge_proxy.upstream_config()

        caido_client = await bootstrap_caido(
            session,
            host_url=host_caido_ui_url,
            container_url=container_caido_ui_url,
            upstream_proxy=upstream_proxy,
        )
        if backend_name == "docker" and callable(getattr(session, "exec", None)):
            await _ensure_container_proxy_listener(session)
    except BaseException:
        await _cleanup_partial_session(
            scan_id=scan_id,
            client=client,
            session=session,
            caido_client=caido_client,
            host_bridge_proxy=host_bridge_proxy,
        )
        raise
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
