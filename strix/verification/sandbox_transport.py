"""Dependency-free HTTP transport copied into a verification sandbox."""

# ruff: noqa: RUF001, T201

from __future__ import annotations

import http.client
import json
import os
import ssl
import sys
from pathlib import Path
from urllib.parse import urlencode, urlsplit


MAX_RESPONSE_BYTES = 512 * 1024
REQUEST_TIMEOUT_SECONDS = 20


def _environment_value(*names: str) -> str:
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def _host_matches_no_proxy(host: str, port: int, raw_no_proxy: str) -> bool:
    for item in raw_no_proxy.split(","):
        candidate = item.strip().lower()
        if not candidate:
            continue
        if candidate == "*":
            return True
        candidate_host = candidate
        candidate_port: int | None = None
        if candidate.count(":") == 1:
            candidate_host, raw_port = candidate.rsplit(":", 1)
            if raw_port.isdigit():
                candidate_port = int(raw_port)
        candidate_host = candidate_host.lstrip(".")
        if candidate_port is not None and candidate_port != port:
            continue
        if host == candidate_host or host.endswith(f".{candidate_host}"):
            return True
    return False


def _proxy_for(scheme: str, host: str, port: int) -> tuple[str, str, int] | None:
    no_proxy = _environment_value("no_proxy", "NO_PROXY")
    if no_proxy and _host_matches_no_proxy(host.lower(), port, no_proxy):
        return None
    raw_proxy = _environment_value(
        f"{scheme}_proxy",
        f"{scheme.upper()}_PROXY",
        "all_proxy",
        "ALL_PROXY",
    )
    if not raw_proxy:
        return None
    proxy_url = raw_proxy if "://" in raw_proxy else f"http://{raw_proxy}"
    parsed = urlsplit(proxy_url)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
        raise ValueError("sandbox 只支持不带认证信息的 HTTP(S) 代理")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or not parsed.hostname:
        raise ValueError("sandbox 代理地址格式无效")
    proxy_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not 1 <= proxy_port <= 65535:
        raise ValueError("sandbox 代理端口无效")
    return parsed.scheme, parsed.hostname, proxy_port


def _request_path(request: dict[str, object]) -> str:
    path = str(request.get("path") or "/")
    raw_query = request.get("query") or []
    if not isinstance(raw_query, list):
        raise TypeError("验证请求 Query 格式无效")
    query: list[tuple[str, str]] = []
    for item in raw_query:
        if not isinstance(item, list) or len(item) != 2:
            raise TypeError("验证请求 Query 格式无效")
        query.append((str(item[0]), str(item[1])))
    if query:
        path = f"{path}?{urlencode(query, doseq=True)}"
    return path


def _connection_and_target(
    scheme: str,
    host: str,
    port: int,
    path: str,
) -> tuple[http.client.HTTPConnection | http.client.HTTPSConnection, str]:
    proxy = _proxy_for(scheme, host, port)
    connection: http.client.HTTPConnection | http.client.HTTPSConnection
    if proxy is None:
        if scheme == "https":
            return http.client.HTTPSConnection(host, port, timeout=REQUEST_TIMEOUT_SECONDS), path
        return http.client.HTTPConnection(host, port, timeout=REQUEST_TIMEOUT_SECONDS), path

    proxy_scheme, proxy_host, proxy_port = proxy
    if scheme == "https":
        connection = http.client.HTTPSConnection(
            proxy_host,
            proxy_port,
            timeout=REQUEST_TIMEOUT_SECONDS,
            context=ssl.create_default_context(),
        )
        connection.set_tunnel(host, port)
        return connection, path
    if proxy_scheme == "https":
        connection = http.client.HTTPSConnection(
            proxy_host,
            proxy_port,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    else:
        connection = http.client.HTTPConnection(
            proxy_host,
            proxy_port,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    return connection, f"http://{host}:{port}{path}"


def _send(item: dict[str, object]) -> dict[str, object]:
    request = item["request"]
    if not isinstance(request, dict):
        raise TypeError("验证请求格式无效")

    body = str(request.get("body") or "").encode("utf-8")
    raw_headers = request.get("headers") or {}
    if not isinstance(raw_headers, dict):
        raise TypeError("验证请求 Header 格式无效")
    headers = {
        str(name): str(value)
        for name, value in raw_headers.items()
        if str(name).lower()
        not in {"content-length", "transfer-encoding", "connection", "proxy-connection"}
    }
    host = str(request.get("host") or "")
    port = int(request.get("port") or 443)
    if not any(name.lower() == "host" for name in headers):
        headers["Host"] = host if port in {80, 443} else f"{host}:{port}"
    headers["Content-Length"] = str(len(body))
    path = _request_path(request)

    scheme = str(request.get("scheme") or "").lower()
    connection: http.client.HTTPConnection | http.client.HTTPSConnection | None = None
    if scheme not in {"http", "https"}:
        return {"id": item["id"], "error": f"不支持的 Scheme：{scheme}"}
    try:
        connection, request_target = _connection_and_target(scheme, host, port, path)
        connection.request(
            str(request.get("method") or "GET"),
            request_target,
            body=body,
            headers=headers,
        )
        response = connection.getresponse()
        raw_body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw_body) > MAX_RESPONSE_BYTES:
            raw_body = raw_body[:MAX_RESPONSE_BYTES]
        return {
            "id": item["id"],
            "status_code": response.status,
            "headers": dict(response.getheaders()),
            "body": raw_body.decode("utf-8", errors="replace"),
        }
    except (OSError, http.client.HTTPException, ValueError) as exc:
        return {"id": item["id"], "error": f"请求执行失败：{exc}"}
    finally:
        if connection is not None:
            connection.close()


def main() -> None:
    with Path(sys.argv[1]).open(encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise TypeError("验证输入不是对象")
    requests = payload.get("requests", [])
    if not isinstance(requests, list):
        raise TypeError("验证请求列表格式无效")
    results = [_send(item) for item in requests]
    print(json.dumps({"results": results}, ensure_ascii=False, separators=(",", ":")))


if __name__ == "__main__":
    try:
        main()
    except (OSError, TypeError, ValueError) as exc:
        print(f"验证传输程序失败：{exc}", file=sys.stderr)
        raise SystemExit(1) from exc
