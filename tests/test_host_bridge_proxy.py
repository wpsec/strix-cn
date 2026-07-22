"""Tests for the host-side bridge proxy used by Docker Caido sessions."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from strix.runtime import host_bridge_proxy


@dataclass
class _FakeSocket:
    port: int

    def getsockname(self) -> tuple[str, int]:
        return ("127.0.0.1", self.port)


class _FakeServer:
    def __init__(self, port: int = 18081) -> None:
        self.sockets = [_FakeSocket(port)]
        self.closed = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class _FakeWriter:
    def __init__(self) -> None:
        self.buffer = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.buffer.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def _reader(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


@pytest.mark.asyncio
async def test_host_bridge_proxy_connect_tunnel_round_trips_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_reader = _reader(b"GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
    client_writer = _FakeWriter()
    remote_reader = _reader(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
    remote_writer = _FakeWriter()

    async def _open_connection(host: str, port: int) -> tuple[asyncio.StreamReader, _FakeWriter]:
        assert host == "127.0.0.1"
        assert port == 8443
        return remote_reader, remote_writer

    monkeypatch.setattr(asyncio, "open_connection", _open_connection)

    await host_bridge_proxy._handle_connect_tunnel(
        client_reader,
        client_writer,
        target="127.0.0.1:8443",
    )

    response = client_writer.buffer.decode("latin1")
    assert "HTTP/1.1 200 Connection Established" in response
    assert "HTTP/1.1 204 No Content" in response
    assert remote_writer.buffer.decode("latin1") == "GET /probe HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"


@pytest.mark.asyncio
async def test_host_bridge_proxy_rewrites_absolute_form_http_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_reader = _reader(b"body=1")
    client_writer = _FakeWriter()
    remote_reader = _reader(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    remote_writer = _FakeWriter()

    async def _open_connection(host: str, port: int) -> tuple[asyncio.StreamReader, _FakeWriter]:
        assert host == "127.0.0.1"
        assert port == 8088
        return remote_reader, remote_writer

    monkeypatch.setattr(asyncio, "open_connection", _open_connection)

    await host_bridge_proxy._handle_plain_http(
        client_reader,
        client_writer,
        method="POST",
        target="http://127.0.0.1:8088/hello?x=1",
        version="HTTP/1.1",
        headers=[
            b"Host: 127.0.0.1:8088\r\n",
            b"Proxy-Connection: Keep-Alive\r\n",
            b"Content-Length: 6\r\n",
        ],
    )

    forwarded = remote_writer.buffer.decode("latin1")
    assert forwarded.startswith("POST /hello?x=1 HTTP/1.1\r\n")
    assert "Proxy-Connection: Keep-Alive" not in forwarded
    assert forwarded.endswith("\r\nbody=1")
    assert client_writer.buffer.decode("latin1").startswith("HTTP/1.1 200 OK")

@pytest.mark.asyncio
async def test_shared_host_bridge_proxy_is_reference_counted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created_servers: list[_FakeServer] = []

    async def _start_server(
        _handler: object,
        host: str,
        port: int,
    ) -> _FakeServer:
        assert host == "127.0.0.1"
        assert port == 0
        server = _FakeServer(port=18081 + len(created_servers))
        created_servers.append(server)
        return server

    monkeypatch.setattr(asyncio, "start_server", _start_server)
    host_bridge_proxy._SHARED_PROXY = None
    try:
        first = await host_bridge_proxy.acquire_shared_host_bridge_proxy()
        second = await host_bridge_proxy.acquire_shared_host_bridge_proxy()
        assert first is second
        assert first._ref_count == 2
        await host_bridge_proxy.release_shared_host_bridge_proxy(first)
        await host_bridge_proxy.release_shared_host_bridge_proxy(second)
        replacement = await host_bridge_proxy.acquire_shared_host_bridge_proxy()
        assert replacement is not first
    finally:
        await host_bridge_proxy.release_shared_host_bridge_proxy(replacement)
        host_bridge_proxy._SHARED_PROXY = None
