"""Burp Raw HTTP and cURL request parsing for verification runs."""

# ruff: noqa: RUF001

from __future__ import annotations

import copy
import json
import re
import shlex
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from strix.verification.models import CanonicalRequest


class RequestParseError(ValueError):
    """Raised when a request cannot be safely normalized."""


_AUTH_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)
_FIELD_NAME_RE = re.compile(
    r"(?i)(?:id|uuid|key|url|uri|path|file|name|query|search|redirect|callback)"
)


def parse_request_file(path: str | Path, *, scheme: str | None = None) -> CanonicalRequest:
    request_path = Path(path).expanduser()
    try:
        text = request_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise RequestParseError(f"无法读取请求文件 {request_path}: {exc}") from exc
    return parse_request_text(text, scheme=scheme)


def parse_request_text(text: str, *, scheme: str | None = None) -> CanonicalRequest:
    if not isinstance(text, str) or not text.strip():
        raise RequestParseError("请求内容不能为空")
    stripped = text.lstrip()
    if stripped.startswith(("curl ", "curl\n")):
        return _parse_curl(stripped, scheme=scheme)
    return _parse_raw_http(text, scheme=scheme)


def _parse_raw_http(text: str, *, scheme: str | None) -> CanonicalRequest:
    normalized = text.replace("\r\n", "\n")
    head, separator, body = normalized.partition("\n\n")
    lines = head.split("\n")
    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2 or len(parts) > 3 or "/" not in (parts[2] if len(parts) == 3 else "HTTP/1.1"):
        raise RequestParseError("请求首行格式无效，期望 METHOD /path HTTP/1.1")
    method = parts[0].upper()
    target = parts[1]
    headers = _parse_headers(lines[1:])
    return _build_request(method, target, headers, body if separator else "", scheme=scheme)


def _parse_headers(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        if not line.strip():
            continue
        if line[:1].isspace():
            raise RequestParseError("不支持折叠 Header")
        if ":" not in line:
            raise RequestParseError(f"无法解析 Header：{line[:80]}")
        name, value = line.split(":", 1)
        name = name.strip()
        if not name or any(ord(char) < 0x20 for char in name):
            raise RequestParseError("Header 名称无效")
        if "\r" in value or "\n" in value:
            raise RequestParseError("Header 值不能包含换行")
        headers[name] = value.strip()
    return headers


def _build_request(
    method: str,
    target: str,
    headers: dict[str, str],
    body: str,
    *,
    scheme: str | None,
) -> CanonicalRequest:
    parsed = urlsplit(target)
    host_header = _header_value(headers, "host")
    if parsed.scheme and parsed.netloc:
        resolved_scheme = parsed.scheme.lower()
        if resolved_scheme not in {"http", "https"}:
            raise RequestParseError("Scheme 只支持 http 或 https")
        if parsed.username is not None or parsed.password is not None:
            raise RequestParseError("URL 中不允许携带账号或密码")
        host = parsed.hostname or ""
        try:
            port = parsed.port or (443 if resolved_scheme == "https" else 80)
        except ValueError as exc:
            raise RequestParseError("URL 端口无效") from exc
        if host_header:
            header_host, header_port = _split_host_header(host_header, resolved_scheme)
            if header_host != host.lower() or header_port != port:
                raise RequestParseError("请求 URL 与 Host Header 不一致，已阻止执行")
    else:
        if not host_header:
            raise RequestParseError("请求缺少 Host，无法确定目标")
        try:
            host, port = _split_host_header(host_header, scheme)
        except ValueError as exc:
            raise RequestParseError("Host 端口无效") from exc
        if scheme is None:
            raise RequestParseError("请求缺少 Scheme，请明确使用 HTTP 还是 HTTPS")
        resolved_scheme = scheme.lower()
        if resolved_scheme not in {"http", "https"}:
            raise RequestParseError("Scheme 只支持 http 或 https")

    if not host or any(char.isspace() for char in host):
        raise RequestParseError("目标 Host 无效")
    path = parsed.path or "/"
    query = parse_qsl(parsed.query, keep_blank_values=True)
    return CanonicalRequest(
        method=method,
        scheme=resolved_scheme,
        host=host.lower().strip("[]"),
        port=port,
        path=path,
        query=query,
        headers=headers,
        body=body,
    )


def _split_host_header(value: str, scheme: str | None) -> tuple[str, int]:
    host_header = value.strip()
    if host_header.startswith("["):
        closing = host_header.find("]")
        if closing < 0:
            raise ValueError("IPv6 Host 缺少右括号")
        host = host_header[1:closing]
        suffix = host_header[closing + 1 :]
        if suffix and not suffix.startswith(":"):
            raise ValueError("Host 端口无效")
        port = int(suffix[1:]) if suffix[1:].isdigit() else None
    else:
        host_part, separator, port_part = host_header.rpartition(":")
        if separator and port_part.isdigit():
            host = host_part
            port = int(port_part)
        elif separator:
            raise ValueError("Host 端口无效")
        else:
            host = host_header
            port = None
    resolved_scheme = (scheme or "").lower()
    if resolved_scheme not in {"", "http", "https"}:
        raise ValueError("Scheme 只支持 http 或 https")
    resolved_port = port or (443 if resolved_scheme == "https" else 80)
    if not host or not 1 <= resolved_port <= 65535:
        raise ValueError("Host 端口无效")
    return host.strip("[]").lower(), resolved_port


def _parse_curl(  # noqa: PLR0912, PLR0915
    text: str,
    *,
    scheme: str | None,
) -> CanonicalRequest:
    try:
        tokens = shlex.split(text, posix=True)
    except ValueError as exc:
        raise RequestParseError(f"cURL 引号格式无效：{exc}") from exc
    if not tokens or tokens[0] != "curl":
        raise RequestParseError("不是有效的 cURL 请求")

    method: str | None = None
    url: str | None = None
    headers: dict[str, str] = {}
    body: str | None = None
    form_parts: list[str] = []
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in {"-X", "--request"}:
            index += 1
            method = tokens[index].upper()
        elif token in {"-H", "--header"}:
            index += 1
            if ":" not in tokens[index]:
                raise RequestParseError("cURL Header 缺少冒号")
            name, value = tokens[index].split(":", 1)
            headers[name.strip()] = value.strip()
        elif token in {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode"}:
            index += 1
            body = tokens[index]
            if method is None:
                method = "POST"
        elif token in {"-F", "--form"}:
            index += 1
            form_parts.append(tokens[index])
            if method is None:
                method = "POST"
        elif token in {"-b", "--cookie"}:
            index += 1
            headers["Cookie"] = tokens[index]
        elif token in {"--url"}:
            index += 1
            url = tokens[index]
        elif token.startswith("-"):
            if token in {"--compressed", "-k", "--insecure", "--http1.1", "--globoff"}:
                pass
            else:
                raise RequestParseError(f"暂不支持的 cURL 参数：{token}")
        elif url is None:
            url = token
        else:
            raise RequestParseError(f"无法识别的 cURL 参数：{token}")
        index += 1

    if not url:
        raise RequestParseError("cURL 请求缺少 URL")
    if form_parts and body is not None:
        raise RequestParseError("cURL 不能同时使用 --form 和 --data")
    if form_parts:
        body, boundary = _build_curl_multipart(form_parts, headers)
        if _header_value(headers, "content-type") is None:
            headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"
    parsed = urlsplit(url)
    if not parsed.scheme and scheme is None:
        raise RequestParseError("cURL URL 缺少 Scheme")
    final_scheme = parsed.scheme or scheme
    request = _build_request(
        method or "GET",
        url,
        headers,
        body or "",
        scheme=final_scheme,
    )
    if "host" not in {name.lower() for name in request.headers}:
        request.headers["Host"] = request.host
    return request


def _build_curl_multipart(forms: list[str], headers: dict[str, str]) -> tuple[str, str]:
    content_type = _header_value(headers, "content-type") or ""
    boundary_match = re.search(r"boundary=([^;]+)", content_type, re.I)
    boundary = boundary_match.group(1).strip('"') if boundary_match else "strix-curl-boundary"
    chunks: list[str] = []
    for form in forms:
        if "=" not in form:
            raise RequestParseError("cURL --form 字段缺少名称")
        name, value = form.split("=", 1)
        name = name.strip()
        if not name:
            raise RequestParseError("cURL --form 字段名称不能为空")
        options = value.split(";")
        content = options[0]
        filename = Path(content[1:]).name if content.startswith("@") else None
        if filename:
            content = "<local-file-omitted>"
        chunks.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"')
        if filename:
            chunks[-1] += f'; filename="{filename}"'
        chunks.append(f"\r\n\r\n{content}\r\n")
    chunks.append(f"--{boundary}--\r\n")
    return "".join(chunks), boundary


def _header_value(headers: dict[str, str], name: str) -> str | None:
    normalized = name.lower()
    return next((value for key, value in headers.items() if key.lower() == normalized), None)


def _content_type(request: CanonicalRequest) -> str:
    return _header_value(request.headers, "content-type") or ""


def _body_json(request: CanonicalRequest) -> Any | None:
    if "json" not in _content_type(request).lower():
        return None
    try:
        return json.loads(request.body)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None


def list_candidate_fields(request: CanonicalRequest) -> list[str]:
    """Return simple, user-relevant mutation paths in deterministic order."""
    fields: list[str] = []
    for name, _value in request.query:
        fields.append(f"query.{name}")
    body_json = _body_json(request)
    if isinstance(body_json, dict):
        fields.extend(f"body.{name}" for name in body_json)
    elif "application/x-www-form-urlencoded" in _content_type(request).lower():
        for name, _value in parse_qsl(request.body, keep_blank_values=True):
            fields.append(f"form.{name}")
    fields.extend(
        f"header.{name}"
        for name in request.headers
        if name.lower() not in _AUTH_HEADERS and name.lower() in {"referer", "origin"}
    )
    cookies = _header_value(request.headers, "cookie") or ""
    for cookie in cookies.split(";"):
        if "=" in cookie:
            name, _value = cookie.split("=", 1)
            if name.strip():
                fields.append(f"cookie.{name.strip()}")
    return fields


def prioritize_fields(fields: list[str], issue: str) -> list[str]:
    words = set(re.findall(r"[A-Za-z0-9_-]+", issue.lower()))

    def score(field: str) -> tuple[int, str]:
        name = field.rsplit(".", 1)[-1].lower()
        issue_match = 0 if name in words else 1
        semantic = 0 if _FIELD_NAME_RE.search(name) else 1
        return issue_match + semantic, field

    return sorted(dict.fromkeys(fields), key=score)


def get_field(request: CanonicalRequest, field: str) -> str | None:
    location, _, name = field.partition(".")
    if location == "query":
        return next((value for key, value in request.query if key == name), None)
    if location == "header":
        return _header_value(request.headers, name)
    if location == "cookie":
        cookies = _parse_cookie(_header_value(request.headers, "cookie") or "")
        return cookies.get(name)
    if location == "form":
        return next(
            (
                value
                for key, value in parse_qsl(request.body, keep_blank_values=True)
                if key == name
            ),
            None,
        )
    if location == "body":
        payload = _body_json(request)
        if isinstance(payload, dict):
            value = payload.get(name)
            return str(value) if value is not None else None
    return None


def set_field(request: CanonicalRequest, field: str, value: str) -> CanonicalRequest:
    result = copy.deepcopy(request)
    location, _, name = field.partition(".")
    if location == "query":
        replaced = False
        query: list[tuple[str, str]] = []
        for key, current in result.query:
            if key == name and not replaced:
                query.append((key, value))
                replaced = True
            else:
                query.append((key, current))
        if not replaced:
            query.append((name, value))
        result.query = query
    elif location == "header":
        result.headers[name] = value
    elif location == "cookie":
        cookies = _parse_cookie(_header_value(result.headers, "cookie") or "")
        cookies[name] = value
        _set_header(
            result.headers,
            "Cookie",
            "; ".join(f"{key}={item}" for key, item in cookies.items()),
        )
    elif location == "form":
        form = parse_qsl(result.body, keep_blank_values=True)
        result.body = urlencode([(key, value if key == name else current) for key, current in form])
    elif location == "body":
        payload = _body_json(result)
        if not isinstance(payload, dict):
            raise RequestParseError(f"无法修改请求字段：{field}")
        payload[name] = value
        result.body = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    else:
        raise RequestParseError(f"不支持的请求字段：{field}")
    return result


def remove_authentication(request: CanonicalRequest) -> CanonicalRequest:
    result = copy.deepcopy(request)
    result.headers = {
        name: value for name, value in result.headers.items() if name.lower() not in _AUTH_HEADERS
    }
    return result


def _parse_cookie(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for part in value.split(";"):
        if "=" in part:
            name, item = part.split("=", 1)
            result[name.strip()] = item.strip()
    return result


def _set_header(headers: dict[str, str], name: str, value: str) -> None:
    for key in list(headers):
        if key.lower() == name.lower():
            del headers[key]
    headers[name] = value


def replace_multipart_marker(request: CanonicalRequest, marker: str) -> CanonicalRequest:
    result = copy.deepcopy(request)
    content_type = _content_type(result)
    match = re.search(r"boundary=([^;]+)", content_type, re.I)
    if not match:
        raise RequestParseError("multipart 请求缺少 boundary")
    boundary = re.escape(match.group(1).strip('"'))
    pattern = re.compile(
        rf"(filename=\"[^\"]+\"[\s\S]*?\r?\n\r?\n)([\s\S]*?)(?=\r?\n--{boundary})",
        re.I,
    )
    updated, count = pattern.subn(rf"\g<1>{marker}", result.body, count=1)
    if count == 0:
        raise RequestParseError("multipart 请求未找到文件内容")
    result.body = updated
    return result


def request_with_query(request: CanonicalRequest) -> str:
    return urlunsplit(
        (
            request.scheme,
            request.host if request.port in {80, 443} else f"{request.host}:{request.port}",
            request.path,
            urlencode(request.query, doseq=True),
            "",
        )
    )
