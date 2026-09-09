"""Deterministic verification plan generation from a request and issue text."""

# ruff: noqa: RUF001

from __future__ import annotations

import ipaddress
import re
import secrets
from typing import TYPE_CHECKING
from urllib.parse import urlsplit


if TYPE_CHECKING:
    from collections.abc import Iterable

from strix.verification.models import (
    VerificationAssertion,
    VerificationCase,
    VerificationPlan,
    VerificationProbe,
    request_shape_sha256,
)
from strix.verification.request import list_candidate_fields, prioritize_fields


class VerificationPlanError(ValueError):
    """Raised when an issue cannot be converted into a safe verification plan."""


_TYPE_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "idor_bola",
        ("idor", "bola", "越权", "其他用户", "他人订单", "对象级授权", "水平越权"),
    ),
    (
        "sqli",
        ("sql 注入", "sql注入", "sqli", "数据库注入", "注入数据库"),
    ),
    (
        "ssrf",
        ("ssrf", "服务端请求伪造", "服务端访问", "回调地址", "远程地址"),
    ),
    (
        "command_injection",
        ("命令注入", "command injection", "rce", "远程代码执行", "执行命令"),
    ),
    (
        "file_upload",
        ("文件上传", "上传文件", "任意文件", "file upload", "upload"),
    ),
    (
        "authz_bypass",
        ("认证绕过", "授权绕过", "未授权", "访问控制", "权限校验", "未登录访问"),
    ),
)


def infer_vulnerability_type(issue: str) -> str | None:
    """Infer one supported verification type without sending a request."""
    normalized = issue.casefold()
    for vulnerability_type, markers in _TYPE_MARKERS:
        if any(marker.casefold() in normalized for marker in markers):
            return vulnerability_type
    return None


def _first_field(fields: Iterable[str], *, preferred: tuple[str, ...] = ()) -> str | None:
    values = list(fields)
    for preferred_name in preferred:
        for field in values:
            if preferred_name in field.casefold():
                return field
    return values[0] if values else None


def _extract_url(issue: str) -> str | None:
    match = re.search(r"https?://[^\s\"'<>]+", issue)
    return match.group(0).rstrip(".,)") if match else None


def _is_safe_canary(url: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    hostname = parsed.hostname.casefold().rstrip(".")
    if hostname in {"localhost", "metadata.google.internal"} or hostname.endswith(".local"):
        return False
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return True
    return not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
    )


def _probe(
    probe_id: str,
    title: str,
    description: str,
    *,
    field: str | None = None,
    value: str | None = None,
    action: str = "set",
    secondary: bool = False,
    side_effect: bool = False,
    cleanup: bool = False,
) -> VerificationProbe:
    return VerificationProbe(
        probe_id=probe_id,
        title=title,
        description=description,
        field=field,
        value=value,
        action=action,
        requires_secondary_identity=secondary,
        requires_side_effect_approval=side_effect,
        cleanup_required=cleanup,
    )


def _assertions(vulnerability_type: str) -> list[VerificationAssertion]:
    descriptions = {
        "sqli": "真值和假值探针必须产生可重复的状态码或响应差异，并有数据库错误或状态差异支撑。",
        "idor_bola": "使用当前身份访问第二身份对象时，不能继续返回受保护的非空成功响应。",
        "authz_bypass": "移除认证信息后，受保护资源必须返回未授权结果。",
        "ssrf": "服务端只能访问允许的受控 Canary，不能访问本机、内网或云元数据地址。",
        "command_injection": (
            "响应必须包含固定身份确认 marker，不能以写文件、联网或持久化作为证据。"
        ),
        "file_upload": "上传 marker 只有在存在可靠清理动作时才允许作为证据。",
    }
    description = descriptions.get(vulnerability_type)
    if description is None:
        return []
    return [
        VerificationAssertion(
            assertion_id=f"{vulnerability_type}-evidence",
            description=description,
        )
    ]


def build_verification_plan(  # noqa: PLR0912, PLR0915
    case: VerificationCase,
) -> VerificationPlan:
    issue = case.issue_description.strip()
    if not issue:
        raise VerificationPlanError("请提供一句漏洞描述")

    vulnerability_type = infer_vulnerability_type(issue)
    safe_issue = issue
    fields = prioritize_fields(list_candidate_fields(case.request), issue)
    request_hash = request_shape_sha256(case.request)
    if vulnerability_type is None:
        plan = VerificationPlan(
            schema_version=1,
            vulnerability_type="unknown",
            issue_description=safe_issue,
            request_template=case.request.to_dict(redact=False),
            request_shape_sha256=request_hash,
            target_fields=fields[:5],
            probes=[],
            max_requests=0,
            requires_side_effect_approval=False,
            blocked_reason=(
                "无法从描述中识别首版支持的漏洞类型。请在描述中补充 SQL 注入、IDOR、"
                "认证/授权绕过、SSRF、命令注入或文件上传等关键词。"
            ),
        )
        plan.finalize_hash()
        return plan

    probes: list[VerificationProbe] = []
    blocked_reason: str | None = None
    requires_side_effect_approval = case.request.method.upper() not in {"GET", "HEAD", "OPTIONS"}

    if vulnerability_type == "sqli":
        field = _first_field(fields, preferred=("query.", "body.", "form."))
        if field is None:
            blocked_reason = "请求中没有可安全变异的 Query、JSON 或表单字段"
        else:
            probes.extend(
                [
                    _probe(
                        "sqli-boolean-true",
                        "SQL 注入布尔真值探针",
                        "向指定字段加入低副作用的布尔条件，并与原始响应进行差异比较。",
                        field=field,
                        value="' OR '1'='1",
                    ),
                    _probe(
                        "sqli-boolean-false",
                        "SQL 注入布尔假值探针",
                        "向指定字段加入低副作用的反向布尔条件，作为对照。",
                        field=field,
                        value="' OR '1'='2",
                    ),
                ]
            )
    elif vulnerability_type == "idor_bola":
        field = _first_field(fields, preferred=("id", "uuid", "order", "user", "account"))
        if field is None:
            blocked_reason = "请求中没有可识别的对象标识字段"
        else:
            probes.append(
                _probe(
                    "idor-secondary-object",
                    "第二身份对象访问探针",
                    "使用第二个授权请求中的对象标识替换当前请求字段，并比较权限边界。",
                    field=field,
                    action="secondary_value",
                    secondary=True,
                )
            )
            if not case.supporting_requests:
                blocked_reason = "IDOR/BOLA 验证需要第二个授权身份的请求包"
    elif vulnerability_type == "authz_bypass":
        if not any(name.lower() in {"authorization", "cookie"} for name in case.request.headers):
            blocked_reason = "请求中没有可移除的认证信息"
        else:
            probes.append(
                _probe(
                    "authz-remove-credentials",
                    "移除认证信息探针",
                    "移除 Authorization 和 Cookie 后重放一次，检查服务端是否仍返回受保护资源。",
                    action="remove_authentication",
                )
            )
    elif vulnerability_type == "ssrf":
        canary = _extract_url(issue)
        field = _first_field(fields, preferred=("url", "uri", "redirect", "callback", "path"))
        if not canary:
            blocked_reason = "SSRF 验证需要在描述中提供受控 Canary URL"
        elif not _is_safe_canary(canary):
            blocked_reason = "Canary 地址必须是受控的公网地址，禁止云元数据、内网和本机地址"
        elif field is None:
            blocked_reason = "请求中没有可识别的 URL、URI 或回调字段"
        else:
            probes.append(
                _probe(
                    "ssrf-controlled-canary",
                    "受控 Canary 请求探针",
                    "将指定 URL 字段替换为用户提供的受控 Canary 地址；不访问云元数据或内网地址。",
                    field=field,
                    value=canary,
                )
            )
    elif vulnerability_type == "command_injection":
        field = _first_field(fields, preferred=("command", "cmd", "query", "name", "path"))
        if field is None:
            blocked_reason = "请求中没有可变异的输入字段"
        else:
            probes.append(
                _probe(
                    "command-identity",
                    "命令执行身份探针",
                    "仅使用身份确认命令判断是否存在命令执行，不写入文件、不联网。",
                    field=field,
                    value=";id",
                )
            )
    elif vulnerability_type == "file_upload":
        if (
            "multipart/form-data"
            not in " ".join(
                value
                for name, value in case.request.headers.items()
                if name.lower() == "content-type"
            ).lower()
        ):
            blocked_reason = "文件上传验证需要 multipart/form-data 请求"
        else:
            marker = f"strix-verify-{secrets.token_hex(8)}"
            probes.append(
                _probe(
                    "upload-benign-marker",
                    "无害文件 marker 探针",
                    "上传随机命名的纯文本 marker；当前版本没有可靠清理动作，因此默认阻断执行。",
                    action="multipart_marker",
                    value=marker,
                    side_effect=True,
                    cleanup=True,
                )
            )
            blocked_reason = "当前请求没有可靠的清理动作，已阻止上传 marker 探针"

    if len(probes) > 20:
        probes = probes[:20]
    plan = VerificationPlan(
        schema_version=1,
        vulnerability_type=vulnerability_type,
        issue_description=safe_issue,
        request_template=case.request.to_dict(redact=False),
        request_shape_sha256=request_hash,
        target_fields=fields[:10],
        probes=probes,
        assertions=_assertions(vulnerability_type),
        max_requests=min(
            20,
            len(probes) + (1 if case.request.method.upper() in {"GET", "HEAD", "OPTIONS"} else 0),
        ),
        requires_side_effect_approval=requires_side_effect_approval
        or any(probe.requires_side_effect_approval for probe in probes),
        blocked_reason=blocked_reason,
    )
    plan.finalize_hash()
    return plan
