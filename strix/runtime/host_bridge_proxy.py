"""Host-side HTTP proxy used as a Caido upstream bridge for Docker sandboxes.

When Caido runs inside Docker, it may not inherit the host's VPN/private-route
reachability. This local bridge lets Caido tunnel outbound HTTP(S) traffic back
through the host network stack while still keeping Burp -> Strix capture local.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from dataclasses import dataclass
from urllib.parse import urlsplit


logger = logging.getLogger(__name__)

_DEFAULT_LISTEN_HOST = "127.0.0.1"
_DEFAULT_CAIDO_HOST = "host.docker.internal"
_LISTEN_HOST_ENV = "STRIX_CAIDO_BRIDGE_HOST"
_LISTEN_PORT_ENV = "STRIX_CAIDO_BRIDGE_PORT"

_SHARED_PROXY: "HostBridgeProxyServer | None" = None
_SHARED_PROXY_LOCK = asyncio.Lock()


@dataclass(slots=True, frozen=True)
class HostBridgeUpstreamConfig:
    host: str
    port: int
    is_tls: bool = False


@dataclass(slots=True)
class HostBridgeProxyServer:
    listen_host: str
    listen_port: int
    caido_host: str
    caido_port: int
    _server: asyncio.AbstractServer
    _ref_count: int = 1

    def upstream_config(self) -> HostBridgeUpstreamConfig:
        return HostBridgeUpstreamConfig(
            host=self.caido_host,
            port=self.caido_port,
            is_tls=False,
        )

    async def aclose(self) -> None:
        self._server.close()
        await self._server.wait_closed()


def _configured_listen_host() -> str:
    value = os.environ.get(_LISTEN_HOST_ENV, "").strip()
    return value or _DEFAULT_LISTEN_HOST


def _configured_listen_port() -> int:
    value = os.environ.get(_LISTEN_PORT_ENV, "").strip()
    if not value:
        return 0
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(f"{_LISTEN_PORT_ENV} 必须是整数端口") from exc
    if not 0 <= port <= 65535:
        raise ValueError(f"{_LISTEN_PORT_ENV} 端口超出范围: {port}")
    return port


async def start_host_bridge_proxy_server(
    *,
    listen_host: str | None = None,
    listen_port: int | None = None,
    caido_host: str = _DEFAULT_CAIDO_HOST,
) -> HostBridgeProxyServer:
    host = listen_host or _configured_listen_host()
    port = _configured_listen_port() if listen_port is None else listen_port
    server = await asyncio.start_server(_handle_client, host, port)
    sock = next(iter(server.sockets or ()), None)
    if sock is None:
        server.close()
        await server.wait_closed()
        raise RuntimeError("宿主机中继代理未分配到监听 socket")
    actual_port = int(sock.getsockname()[1])
    logger.info(
        "Started host bridge proxy for Caido: listen=%s:%s caido=%s:%s",
        host,
        actual_port,
        caido_host,
        actual_port,
    )
    return HostBridgeProxyServer(
        listen_host=host,
        listen_port=actual_port,
        caido_host=caido_host,
        caido_port=actual_port,
        _server=server,
    )


async def acquire_shared_host_bridge_proxy() -> HostBridgeProxyServer:
    global _SHARED_PROXY
    async with _SHARED_PROXY_LOCK:
        if _SHARED_PROXY is None:
            _SHARED_PROXY = await start_host_bridge_proxy_server()
        else:
            _SHARED_PROXY._ref_count += 1
        return _SHARED_PROXY


async def release_shared_host_bridge_proxy(proxy: HostBridgeProxyServer) -> None:
    global _SHARED_PROXY
    should_close = False
    async with _SHARED_PROXY_LOCK:
        if _SHARED_PROXY is proxy:
            proxy._ref_count = max(proxy._ref_count - 1, 0)
            if proxy._ref_count == 0:
                _SHARED_PROXY = None
                should_close = True
    if should_close:
        logger.info(
            "Stopping host bridge proxy for Caido: listen=%s:%s",
            proxy.listen_host,
            proxy.listen_port,
        )
        await proxy.aclose()


async def _handle_client(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
) -> None:
    try:
        request_line = await client_reader.readline()
        if not request_line:
            return
        method, target, version = _parse_request_line(request_line)
        headers = await _read_headers(client_reader)
        if method.upper() == "CONNECT":
            await _handle_connect_tunnel(
                client_reader,
                client_writer,
                target=target,
            )
            return
        await _handle_plain_http(
            client_reader,
            client_writer,
            method=method,
            target=target,
            version=version,
            headers=headers,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("Host bridge proxy request failed", exc_info=True)
        await _write_bad_gateway(client_writer, str(exc))
    finally:
        with contextlib.suppress(Exception):
            client_writer.close()
            await client_writer.wait_closed()


def _parse_request_line(line: bytes) -> tuple[str, str, str]:
    try:
        method, target, version = line.decode("latin1").rstrip("\r\n").split(" ", 2)
    except ValueError as exc:
        raise ValueError("无效的代理请求行") from exc
    if not method or not target or not version:
        raise ValueError("代理请求行缺少必要字段")
    return method, target, version


async def _read_headers(reader: asyncio.StreamReader) -> list[bytes]:
    headers: list[bytes] = []
    while True:
        line = await reader.readline()
        if line in (b"", b"\r\n", b"\n"):
            return headers
        headers.append(line)


async def _handle_connect_tunnel(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    *,
    target: str,
) -> None:
    host, port = _split_connect_target(target)
    remote_reader, remote_writer = await asyncio.open_connection(host, port)
    try:
        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()
        await asyncio.gather(
            _pipe_stream(client_reader, remote_writer),
            _pipe_stream(remote_reader, client_writer),
        )
    finally:
        with contextlib.suppress(Exception):
            remote_writer.close()
            await remote_writer.wait_closed()


async def _handle_plain_http(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    *,
    method: str,
    target: str,
    version: str,
    headers: list[bytes],
) -> None:
    parsed = urlsplit(target)
    host = parsed.hostname or _host_from_headers(headers)
    if not host:
        raise ValueError("无法从代理请求中解析目标主机")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    remote_reader, remote_writer = await asyncio.open_connection(host, port)
    try:
        remote_writer.write(f"{method} {path} {version}\r\n".encode("latin1"))
        for header in headers:
            if header.lower().startswith(b"proxy-connection:"):
                continue
            remote_writer.write(header)
        remote_writer.write(b"\r\n")
        await remote_writer.drain()
        await asyncio.gather(
            _pipe_stream(client_reader, remote_writer),
            _pipe_stream(remote_reader, client_writer),
        )
    finally:
        with contextlib.suppress(Exception):
            remote_writer.close()
            await remote_writer.wait_closed()


def _split_connect_target(target: str) -> tuple[str, int]:
    if ":" not in target:
        raise ValueError("CONNECT 目标缺少端口")
    host, port = target.rsplit(":", 1)
    return host.strip(), int(port)


def _host_from_headers(headers: list[bytes]) -> str | None:
    for header in headers:
        if not header.lower().startswith(b"host:"):
            continue
        value = header.split(b":", 1)[1].strip().decode("latin1")
        if not value:
            return None
        return value.rsplit(":", 1)[0] if ":" in value else value
    return None


async def _pipe_stream(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception:
        logger.debug("Host bridge proxy stream copy aborted", exc_info=True)
    finally:
        with contextlib.suppress(Exception):
            writer.close()


async def _write_bad_gateway(writer: asyncio.StreamWriter, message: str) -> None:
    payload = message.encode("utf-8", errors="replace")
    writer.write(
        b"HTTP/1.1 502 Bad Gateway\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        + f"Content-Length: {len(payload)}\r\n".encode("ascii")
        + b"Connection: close\r\n\r\n"
        + payload
    )
    with contextlib.suppress(Exception):
        await writer.drain()
