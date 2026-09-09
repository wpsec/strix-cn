"""Build bounded verification plans from validated semantic intent."""

# ruff: noqa: RUF001

from __future__ import annotations

import ipaddress
from dataclasses import replace
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from strix.verification.intent import (
    SUPPORTED_ORACLES,
    SUPPORTED_STRATEGIES,
    VerificationIntent,
)
from strix.verification.models import (
    VerificationAssertion,
    VerificationCase,
    VerificationPlan,
    VerificationProbe,
    request_shape_sha256,
)
from strix.verification.request import list_candidate_fields


if TYPE_CHECKING:
    from collections.abc import Iterable


class VerificationPlanError(ValueError):
    """Raised when an intent cannot be converted into a safe plan."""


_STRATEGY_ACTIONS: dict[str, frozenset[str]] = {
    "field_mutation": frozenset({"set"}),
    "paired_field_mutation": frozenset({"set"}),
    "secondary_identity": frozenset({"secondary_value"}),
    "remove_authentication": frozenset({"remove_authentication"}),
    "controlled_canary": frozenset({"set"}),
    "identity_marker": frozenset({"set"}),
    "multipart_marker": frozenset({"multipart_marker"}),
}
_STRATEGY_ORACLES: dict[str, frozenset[str]] = {
    "field_mutation": frozenset({"response_difference"}),
    "paired_field_mutation": frozenset({"response_difference"}),
    "secondary_identity": frozenset({"authorization_boundary"}),
    "remove_authentication": frozenset({"authorization_boundary"}),
    "controlled_canary": frozenset({"canary_echo"}),
    "identity_marker": frozenset({"identity_marker"}),
    "multipart_marker": frozenset({"canary_echo"}),
}


def _is_safe_canary(url: str) -> bool:
    if any(char.isspace() or ord(char) < 0x20 for char in url):
        return False
    parsed = urlsplit(url)
    valid = not (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
    )
    try:
        port = parsed.port
    except ValueError:
        valid = False
        port = None
    if port is not None and not 1 <= port <= 65535:
        valid = False
    hostname = (parsed.hostname or "").casefold().rstrip(".")
    if hostname in {"localhost", "metadata.google.internal"} or hostname.endswith(
        (".local", ".localhost", ".internal")
    ):
        valid = False
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return valid
    return valid and not (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    )


def _probe(
    probe_id: str,
    proposed: object,
    *,
    field: str | None,
    value: str | None,
    action: str,
    secondary: bool = False,
    side_effect: bool = False,
    cleanup: bool = False,
) -> VerificationProbe:
    rationale = getattr(proposed, "rationale", "") or "由漏洞描述和请求结构生成的验证探针。"
    role = getattr(proposed, "role", "")
    pair_id = getattr(proposed, "pair_id", "")
    return VerificationProbe(
        probe_id=probe_id,
        title=f"描述驱动探针 {probe_id.removeprefix('intent-')}",
        description=rationale,
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


def _has_complete_pair(probes: Iterable[VerificationProbe]) -> bool:
    pair_roles: dict[str, set[str]] = {}
    for probe in probes:
        if probe.pair_id and probe.role in {"true", "false"}:
            pair_roles.setdefault(probe.pair_id, set()).add(probe.role)
    return any({"true", "false"} <= roles for roles in pair_roles.values())


def _strategy_blockers(
    strategy: str,
    intent: VerificationIntent,
    case: VerificationCase,
    probes: list[VerificationProbe],
) -> list[str]:
    blockers: list[str] = []
    if strategy == "paired_field_mutation" and not (
        _has_complete_pair(probes) or any(probe.role == "error" for probe in probes)
    ):
        blockers.append("成对字段变异必须包含同一对照组的真值和假值，或异常响应探针")
    if any(probe.role == "delay" for probe in probes):
        blockers.append("耗时型探针可能造成目标负载，已阻断执行")
    if strategy == "secondary_identity" and not case.supporting_requests:
        blockers.append("跨身份验证需要第二个授权身份的请求包")
    if strategy == "remove_authentication" and not any(
        probe.action == "remove_authentication" for probe in probes
    ):
        blockers.append("认证边界验证缺少移除认证信息动作")
    if strategy == "controlled_canary":
        if not probes:
            blockers.append("受控 Canary 验证缺少 URL 字段探针")
        elif not case.controlled_canary_url:
            blockers.append("受控 Canary 必须由操作员通过 --canary-url 提供")
        elif not _is_safe_canary(case.controlled_canary_url):
            blockers.append("Canary 必须是受控公网地址，禁止本机、内网和云元数据地址")
    if strategy == "identity_marker" and not intent.oracle_marker:
        blockers.append("身份确认验证缺少响应 marker")
    if strategy == "multipart_marker":
        blockers.append("当前验证链路没有可靠的 multipart 清理动作，已阻断 marker 上传")
    if not probes:
        blockers.append(intent.rationale or "模型未生成可执行验证探针")
    return blockers


def _blocked_plan(case: VerificationCase, reason: str) -> VerificationPlan:
    plan = VerificationPlan(
        schema_version=2,
        vulnerability_type="unclassified",
        issue_description=case.issue_description.strip(),
        request_template=case.request.to_dict(redact=False),
        request_shape_sha256=request_shape_sha256(case.request),
        target_fields=list_candidate_fields(case.request)[:10],
        probes=[],
        max_requests=0,
        requires_side_effect_approval=False,
        blocked_reason=reason,
        planner_source="none",
        intent_rationale=reason,
        oracle_kind="response_difference",
        strategy_kind="unplanned",
    )
    plan.finalize_hash()
    return plan


def _build_plan_from_intent(
    case: VerificationCase,
    intent: VerificationIntent,
) -> VerificationPlan:
    """Turn model output into a plan using capability, not vulnerability names."""
    candidate_fields = list_candidate_fields(case.request)
    candidates = set(candidate_fields)
    strategy = intent.strategy_kind
    if strategy not in SUPPORTED_STRATEGIES:
        raise VerificationPlanError(f"验证意图包含不支持的验证能力：{strategy}")
    if intent.oracle_kind not in SUPPORTED_ORACLES:
        raise VerificationPlanError(f"验证意图包含不支持的判定器：{intent.oracle_kind}")
    if intent.oracle_kind not in _STRATEGY_ORACLES[strategy]:
        raise VerificationPlanError(f"{strategy} 不能使用 {intent.oracle_kind} 判定器")

    allowed_actions = _STRATEGY_ACTIONS[strategy]
    probes: list[VerificationProbe] = []
    safe_methods = {"GET", "HEAD", "OPTIONS"}
    requires_side_effect_approval = any(
        request.method.upper() not in safe_methods
        for request in (case.request, *case.supporting_requests)
    )
    for index, proposed in enumerate(intent.probes, start=1):
        if proposed.action not in allowed_actions:
            raise VerificationPlanError(f"验证能力 {strategy} 不允许执行动作：{proposed.action}")
        if proposed.field is not None and proposed.field not in candidates:
            raise VerificationPlanError("验证意图引用了请求中不存在的探针字段")
        if proposed.action in {"set", "secondary_value"} and proposed.field is None:
            raise VerificationPlanError("字段变异探针缺少目标字段")
        probes.append(
            _probe(
                f"intent-{index}",
                proposed,
                field=proposed.field,
                value=proposed.value,
                action=proposed.action,
                secondary=proposed.action == "secondary_value",
                side_effect=proposed.action == "multipart_marker",
                cleanup=proposed.action == "multipart_marker",
            )
        )

    if (
        strategy == "controlled_canary"
        and case.controlled_canary_url
        and _is_safe_canary(case.controlled_canary_url)
    ):
        probes = [replace(probe, value=case.controlled_canary_url) for probe in probes]

    blocked_reasons = _strategy_blockers(strategy, intent, case, probes)

    target_fields = list(
        dict.fromkeys(
            (*intent.target_fields, *[probe.field for probe in probes if probe.field is not None])
        )
    )
    assertions = (
        [
            VerificationAssertion(
                assertion_id="intent-oracle",
                description=intent.oracle_description,
            )
        ]
        if intent.oracle_description
        else []
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
        max_requests=min(
            20,
            len(probes[:20]) + 1 + (1 if strategy == "secondary_identity" else 0),
        ),
        requires_side_effect_approval=requires_side_effect_approval
        or any(probe.requires_side_effect_approval for probe in probes),
        blocked_reason="；".join(dict.fromkeys(blocked_reasons)) or None,
        planner_source=intent.source,
        intent_rationale=intent.rationale,
        intent_confidence=intent.confidence,
        oracle_kind=intent.oracle_kind,
        strategy_kind=strategy,
        oracle_marker=intent.oracle_marker,
    )
    plan.finalize_hash()
    return plan


def build_verification_plan(
    case: VerificationCase,
    *,
    intent: VerificationIntent | None = None,
) -> VerificationPlan:
    issue = case.issue_description.strip()
    if not issue:
        raise VerificationPlanError("请提供一句漏洞描述")
    if intent is None:
        return _blocked_plan(
            case,
            "未生成描述驱动验证意图；请通过 CLI 使用已配置的 Strix LLM 生成验证计划",
        )
    return _build_plan_from_intent(case, intent)


__all__ = [
    "VerificationPlanError",
    "build_verification_plan",
]
