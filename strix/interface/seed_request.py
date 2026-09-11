"""Prepare an operator-supplied HTTP request as a focused red-team seed."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from strix.verification.request import RequestParseError, parse_request_file


SEED_REQUEST_WORKSPACE_PATH = "/workspace/.strix/seed-request.txt"
_MAX_TCP_PORT = 65535


def prepare_seed_request(
    path: str,
    workspace_files: list[dict[str, str]],
) -> tuple[dict[str, Any], dict[str, str]]:
    """Validate and describe a request without putting its contents in prompts.

    The raw request is staged as read-only data for the sandbox. Only bounded
    routing and shape metadata is returned to the scan configuration so headers,
    cookies, and body values do not get persisted in ``run.json``.
    """
    request_path = Path(path).expanduser()
    if not request_path.is_file():
        raise ValueError(f"请求文件不存在：{path}")
    try:
        request = parse_request_file(request_path)
    except RequestParseError as exc:
        raise ValueError(f"单请求种子解析失败：{exc}") from exc

    if any(
        workspace_file.get("workspace_path") == SEED_REQUEST_WORKSPACE_PATH
        for workspace_file in workspace_files
    ):
        raise ValueError(
            f"请求种子保留路径 {SEED_REQUEST_WORKSPACE_PATH} 已被 --workspace-file 占用"
        )

    metadata: dict[str, Any] = {
        "workspace_path": SEED_REQUEST_WORKSPACE_PATH,
        "target_origin": _request_origin(request.scheme, request.host, request.port),
        "scheme": request.scheme,
        "host": request.host,
        "port": request.port,
        "method": request.method,
        "path": request.path or "/",
        "query_keys": [name for name, _value in request.query],
    }
    workspace_file = {
        "source_path": str(request_path.resolve()),
        "workspace_path": SEED_REQUEST_WORKSPACE_PATH,
    }
    return metadata, workspace_file


def validate_seed_scope(seed_request: dict[str, Any], targets: list[dict[str, Any]]) -> None:
    """Require the seed authority to match one explicitly authorized target."""
    seed_authority = _authority(
        str(seed_request.get("scheme") or ""),
        str(seed_request.get("host") or ""),
        seed_request.get("port"),
    )
    if seed_authority is None:
        raise ValueError("单请求种子缺少有效的目标 Authority")

    for target in targets:
        details = target.get("details") or {}
        target_type = target.get("type")
        if (
            target_type == "ip_address"
            and str(details.get("target_ip") or "").lower() == seed_authority[0]
        ):
            return
        if (
            target_type == "web_application"
            and _url_authority(str(details.get("target_url") or "")) == seed_authority
        ):
            return
        if target_type == "api_spec" and any(
            _url_authority(str(base_url)) == seed_authority
            for base_url in details.get("base_urls") or []
        ):
            return

    raise ValueError(
        "单请求种子的 Host/端口不在 --target 或 --target-list 授权范围内；"
        "请显式提供匹配的目标，避免请求数据包扩大测试范围。"
    )


def _request_origin(scheme: str, host: str, port: int) -> str:
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    return urlunsplit((scheme, netloc, "/", "", ""))


def _authority(scheme: str, host: str, port: Any) -> tuple[str, int] | None:
    if scheme not in {"http", "https"} or not host:
        return None
    try:
        resolved_port = int(port)
    except (TypeError, ValueError):
        return None
    if not 1 <= resolved_port <= _MAX_TCP_PORT:
        return None
    return host.lower().strip("[]"), resolved_port


def _url_authority(value: str) -> tuple[str, int] | None:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None
    return _authority(parsed.scheme, parsed.hostname, port)
