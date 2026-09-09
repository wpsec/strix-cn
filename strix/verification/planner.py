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

from strix.verification.intent import (
    SUPPORTED_VULNERABILITY_TYPES,
    VerificationIntent,
)
from strix.verification.models import (
    VerificationAssertion,
    VerificationCase,
    VerificationPlan,
    VerificationProbe,
    request_shape_sha256,
)
from strix.verification.request import get_field, list_candidate_fields, prioritize_fields


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
    pair_id: str = "",
    role: str = "",
    rationale: str = "",
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
        pair_id=pair_id,
        role=role,
        rationale=rationale,
    )


def _sqli_variants(original_value: str) -> tuple[tuple[str, str, str], ...]:
    base = original_value or "1"
    return (
        (
            "boolean",
            f"{base}' OR '1'='1",
            f"{base}' AND '1'='2",
        ),
        (
            "numeric",
            f"{base} OR 1=1",
            f"{base} AND 1=2",
        ),
        (
            "parenthesized",
            f"{base}') OR ('1'='1",
            f"{base}') AND ('1'='2",
        ),
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


def _oracle_kind(vulnerability_type: str) -> str:
    return {
        "sqli": "response_difference",
        "idor_bola": "authorization_boundary",
        "authz_bypass": "authorization_boundary",
        "command_injection": "identity_marker",
        "ssrf": "canary_echo",
        "file_upload": "canary_echo",
    }.get(vulnerability_type, "response_difference")


def _build_plan_from_intent(  # noqa: PLR0912, PLR0915
    case: VerificationCase,
    intent: VerificationIntent,
) -> VerificationPlan:
    """Turn model output into a plan after enforcing request-local invariants."""
    candidate_fields = list_candidate_fields(case.request)
    candidates = set(candidate_fields)
    invalid_targets = [field for field in intent.target_fields if field not in candidates]
    if invalid_targets:
        raise VerificationPlanError("验证意图引用了请求中不存在的目标字段")
    if intent.vulnerability_type not in SUPPORTED_VULNERABILITY_TYPES:
        raise VerificationPlanError(f"验证意图包含不支持的漏洞类型：{intent.vulnerability_type}")
    expected_oracle = _oracle_kind(intent.vulnerability_type)
    if intent.oracle_kind != expected_oracle:
        raise VerificationPlanError(
            f"{intent.vulnerability_type} 只能使用 {expected_oracle} 判定器"
        )

    probes: list[VerificationProbe] = []
    blocked_reasons: list[str] = []
    requires_side_effect_approval = case.request.method.upper() not in {
        "GET",
        "HEAD",
        "OPTIONS",
    }
    for index, proposed in enumerate(intent.probes, start=1):
        if proposed.field is not None and proposed.field not in candidates:
            raise VerificationPlanError("验证意图引用了请求中不存在的探针字段")
        if proposed.action in {"set", "secondary_value"} and proposed.field is None:
            raise VerificationPlanError("字段变异探针缺少目标字段")
        requires_secondary = proposed.action == "secondary_value"
        side_effect = proposed.action in {"multipart_marker"}
        cleanup = proposed.action == "multipart_marker"
        probes.append(
            _probe(
                f"intent-{index}",
                f"描述驱动探针 {index}",
                proposed.rationale or "由漏洞描述和请求结构生成的验证探针。",
                field=proposed.field,
                value=proposed.value,
                action=proposed.action,
                secondary=requires_secondary,
                side_effect=side_effect,
                cleanup=cleanup,
                pair_id=proposed.pair_id,
                role=proposed.role,
                rationale=proposed.rationale,
            )
        )

    if intent.vulnerability_type == "idor_bola" and not any(
        probe.requires_secondary_identity for probe in probes
    ):
        blocked_reasons.append("IDOR/BOLA 意图必须包含第二身份对象替换探针")
    if (
        intent.vulnerability_type == "idor_bola"
        and any(probe.requires_secondary_identity for probe in probes)
        and not case.supporting_requests
    ):
        blocked_reasons.append("IDOR/BOLA 验证需要第二个授权身份的请求包")
    if intent.vulnerability_type == "sqli":
        pairs = {
            probe.pair_id for probe in probes if probe.pair_id and probe.role in {"true", "false"}
        }
        complete_pairs = {
            pair_id
            for pair_id in pairs
            if {probe.role for probe in probes if probe.pair_id == pair_id} >= {"true", "false"}
        }
        has_error_probe = any(probe.role == "error" for probe in probes)
        if not complete_pairs and not has_error_probe:
            blocked_reasons.append("SQL 注入意图必须包含同一对照组的真/假探针，或单独的错误型探针")
        if any(probe.role == "delay" for probe in probes):
            blocked_reasons.append("延时盲注探针可能造成目标负载，已阻断执行")
    if intent.vulnerability_type == "authz_bypass" and not any(
        probe.action == "remove_authentication" for probe in probes
    ):
        blocked_reasons.append("认证/授权绕过意图必须包含移除认证信息探针")
    if intent.vulnerability_type == "ssrf" and not any(probe.action == "set" for probe in probes):
        blocked_reasons.append("SSRF 意图必须包含 URL 字段替换探针")
    if intent.vulnerability_type == "command_injection" and not any(
        probe.action == "set" for probe in probes
    ):
        blocked_reasons.append("命令注入意图必须包含输入字段探针")
    if intent.vulnerability_type == "ssrf":
        for probe in probes:
            if probe.action != "set" or not probe.value:
                continue
            if not _is_safe_canary(probe.value):
                blocked_reasons.append(
                    "SSRF 探针必须使用描述中提供的受控公网 Canary，禁止内网、本机和云元数据地址"
                )
                break
    if intent.vulnerability_type == "file_upload":
        if not any(probe.action == "multipart_marker" for probe in probes):
            blocked_reasons.append("文件上传验证需要 multipart marker 探针")
        else:
            blocked_reasons.append("当前请求没有可靠的清理动作，已阻止上传 marker 探针")
    if not probes:
        blocked_reasons.append(intent.rationale or "模型未生成足够信息来执行验证")

    target_fields = list(
        dict.fromkeys(
            (*intent.target_fields, *[probe.field for probe in probes if probe.field is not None])
        )
    )
    assertions = _assertions(intent.vulnerability_type)
    if intent.oracle_description:
        assertions.append(
            VerificationAssertion(
                assertion_id="intent-oracle",
                description=intent.oracle_description,
            )
        )
    plan = VerificationPlan(
        schema_version=2,
        vulnerability_type=intent.vulnerability_type,
        issue_description=case.issue_description.strip(),
        request_template=case.request.to_dict(redact=False),
        request_shape_sha256=request_shape_sha256(case.request),
        target_fields=target_fields[:10],
        probes=probes[:20],
        assertions=assertions,
        max_requests=min(20, len(probes[:20]) + 1),
        requires_side_effect_approval=requires_side_effect_approval
        or any(probe.requires_side_effect_approval for probe in probes),
        blocked_reason="；".join(dict.fromkeys(blocked_reasons)) or None,
        planner_source=intent.source,
        intent_rationale=intent.rationale,
        intent_confidence=intent.confidence,
        oracle_kind=intent.oracle_kind,
    )
    plan.finalize_hash()
    return plan


def build_verification_plan(  # noqa: PLR0912, PLR0915
    case: VerificationCase,
    *,
    intent: VerificationIntent | None = None,
) -> VerificationPlan:
    issue = case.issue_description.strip()
    if not issue:
        raise VerificationPlanError("请提供一句漏洞描述")

    if intent is not None:
        if intent.rationale and intent.vulnerability_type not in SUPPORTED_VULNERABILITY_TYPES:
            raise VerificationPlanError("验证意图类型不受支持")
        return _build_plan_from_intent(case, intent)

    vulnerability_type = infer_vulnerability_type(issue)
    safe_issue = issue
    fields = prioritize_fields(list_candidate_fields(case.request), issue)
    request_hash = request_shape_sha256(case.request)
    if vulnerability_type is None:
        plan = VerificationPlan(
            schema_version=2,
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
            oracle_kind="response_difference",
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
            original_value = get_field(case.request, field) or ""
            for variant_name, true_value, false_value in _sqli_variants(original_value):
                probes.extend(
                    [
                        _probe(
                            f"sqli-{variant_name}-true",
                            f"SQL 注入{variant_name}真值探针",
                            "向指定字段加入低副作用的真值条件，并与原始响应进行差异比较。",
                            field=field,
                            value=true_value,
                            pair_id=f"sqli-{variant_name}",
                            role="true",
                        ),
                        _probe(
                            f"sqli-{variant_name}-false",
                            f"SQL 注入{variant_name}假值探针",
                            "向指定字段加入低副作用的假值条件，作为对照。",
                            field=field,
                            value=false_value,
                            pair_id=f"sqli-{variant_name}",
                            role="false",
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
        schema_version=2,
        vulnerability_type=vulnerability_type,
        issue_description=safe_issue,
        request_template=case.request.to_dict(redact=False),
        request_shape_sha256=request_hash,
        target_fields=fields[:10],
        probes=probes,
        assertions=_assertions(vulnerability_type),
        max_requests=min(
            20,
            len(probes) + 1,
        ),
        requires_side_effect_approval=requires_side_effect_approval
        or any(probe.requires_side_effect_approval for probe in probes),
        blocked_reason=blocked_reason,
        oracle_kind=_oracle_kind(vulnerability_type),
    )
    plan.finalize_hash()
    return plan
