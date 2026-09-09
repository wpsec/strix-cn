"""Bounded direct HTTP execution and generic response oracles."""

# ruff: noqa: RUF001

from __future__ import annotations

import hashlib
import http.client
import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

from strix.verification.models import (
    CanonicalRequest,
    ProbeResult,
    VerificationPlan,
    VerificationResult,
    VerificationStatus,
    render_raw_request,
    request_shape_sha256,
)
from strix.verification.request import (
    get_field,
    remove_authentication,
    replace_multipart_marker,
    set_field,
)


logger = logging.getLogger(__name__)
_MAX_RESPONSE_BYTES = 512 * 1024
_REQUEST_TIMEOUT_SECONDS = 20


class VerificationExecutionError(RuntimeError):
    """Raised when a verification request cannot be safely executed."""


@dataclass(slots=True)
class HttpObservation:
    status_code: int
    headers: dict[str, str]
    body: str


def _headers_without_framing(headers: dict[str, str]) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in {"content-length", "transfer-encoding", "connection"}
    }


def send_request(request: CanonicalRequest) -> HttpObservation:
    """Send exactly one request without following redirects or using env proxies."""
    body = request.body.encode("utf-8")
    headers = _headers_without_framing(request.headers)
    if not any(name.lower() == "host" for name in headers):
        headers["Host"] = (
            request.host if request.port in {80, 443} else f"{request.host}:{request.port}"
        )
    headers["Content-Length"] = str(len(body))
    path = request.path or "/"
    if request.query:
        path = f"{path}?{urlencode(request.query, doseq=True)}"

    connection: http.client.HTTPConnection | http.client.HTTPSConnection
    if request.scheme == "https":
        connection = http.client.HTTPSConnection(
            request.host,
            request.port,
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
    elif request.scheme == "http":
        connection = http.client.HTTPConnection(
            request.host,
            request.port,
            timeout=_REQUEST_TIMEOUT_SECONDS,
        )
    else:
        raise VerificationExecutionError(f"不支持的 Scheme：{request.scheme}")

    try:
        connection.request(request.method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw_body = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw_body) > _MAX_RESPONSE_BYTES:
            raw_body = raw_body[:_MAX_RESPONSE_BYTES]
        return HttpObservation(
            status_code=response.status,
            headers=dict(response.getheaders()),
            body=raw_body.decode("utf-8", errors="replace"),
        )
    except (OSError, http.client.HTTPException) as exc:
        raise VerificationExecutionError(f"请求执行失败：{exc}") from exc
    finally:
        connection.close()


def _apply_probe(
    request: CanonicalRequest,
    probe: Any,
    *,
    secondary: CanonicalRequest | None,
) -> CanonicalRequest:
    action = probe.action
    if action == "remove_authentication":
        return remove_authentication(request)
    if action == "multipart_marker":
        if not probe.value:
            raise VerificationExecutionError("multipart marker 缺失")
        return replace_multipart_marker(request, probe.value)
    if not probe.field:
        raise VerificationExecutionError(f"探针 {probe.probe_id} 缺少目标字段")
    value = probe.value or ""
    if action == "secondary_value":
        if secondary is None:
            raise VerificationExecutionError("缺少第二身份请求")
        secondary_value = get_field(secondary, probe.field)
        if secondary_value is None:
            raise VerificationExecutionError(f"第二身份请求缺少字段：{probe.field}")
        value = secondary_value
    return set_field(request, probe.field, value)


def _fingerprint(observation: HttpObservation) -> str:
    payload = f"{observation.status_code}\n{observation.body}".encode("utf-8", errors="replace")
    return hashlib.sha256(payload).hexdigest()


def _responses_differ(first: HttpObservation, second: HttpObservation) -> bool:
    if first.status_code != second.status_code:
        return True
    return first.body != second.body


def _responses_match(first: HttpObservation, second: HttpObservation) -> bool:
    if first.status_code != second.status_code:
        return False
    if first.body == second.body:
        return True
    try:
        return bool(json.loads(first.body) == json.loads(second.body))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False


def _response_label(observation: HttpObservation | None) -> str:
    if observation is None:
        return "未获得响应"
    return f"HTTP {observation.status_code} / {len(observation.body.encode('utf-8'))} bytes"


def _effective_oracle_kind(plan: VerificationPlan) -> str:
    if plan.schema_version >= 2:
        return plan.oracle_kind
    if plan.oracle_marker:
        return "identity_marker"
    if any(
        probe.requires_secondary_identity or probe.action == "remove_authentication"
        for probe in plan.probes
    ):
        return "authorization_boundary"
    return plan.oracle_kind or "response_difference"


def _probe_result(
    probe: Any,
    request: CanonicalRequest,
    observation: HttpObservation,
) -> ProbeResult:
    probe_id = probe if isinstance(probe, str) else probe.probe_id
    return ProbeResult(
        probe_id=probe_id,
        status="observed",
        response_status=observation.status_code,
        response_length=len(observation.body.encode("utf-8")),
        response_sha256=_fingerprint(observation),
        response_summary=observation.body[:2048],
        request=render_raw_request(request),
    )


def _response_difference_oracle(
    plan: VerificationPlan,
    observations: dict[str, HttpObservation],
) -> tuple[VerificationStatus, str]:
    control = observations.get("control")
    if control is None:
        return "inconclusive", "缺少控制响应，无法确认响应差异"

    pair_map: dict[str, dict[str, str]] = {}
    for probe in plan.probes:
        if probe.pair_id and probe.role in {"true", "false"}:
            pair_map.setdefault(probe.pair_id, {})[probe.role] = probe.probe_id

    evidence: list[str] = []
    for pair_id, pair in pair_map.items():
        true_id = pair.get("true")
        false_id = pair.get("false")
        if not true_id or not false_id:
            continue
        true_response = observations.get(true_id)
        false_response = observations.get(false_id)
        if true_response is None or false_response is None:
            continue
        differs = _responses_differ(true_response, false_response)
        control_aligned = _responses_match(control, true_response) or _responses_match(
            control, false_response
        )
        evidence.append(
            f"{pair_id}: 真值 {_response_label(true_response)}，"
            f"假值 {_response_label(false_response)}"
        )
        if differs and control_aligned:
            return "verified_vulnerable", "成对探针产生了可复现的响应差异；" + "；".join(evidence)

    for probe in plan.probes:
        if probe.probe_id == "control" or probe.role in {"true", "false"}:
            continue
        response = observations.get(probe.probe_id)
        if response is None:
            continue
        if _responses_differ(control, response):
            evidence.append(f"{probe.probe_id}: {_response_label(response)}")

    details = "；".join(evidence) or "未获得完整对照响应"
    if evidence:
        return (
            "inconclusive",
            "观察到响应差异，但没有成对对照或明确证据 marker，不能确认漏洞；" + details,
        )
    return (
        "not_reproduced",
        f"未观察到足以确认问题的响应差异；控制 {_response_label(control)}；{details}",
    )


def _secondary_identity_oracle(
    plan: VerificationPlan,
    observations: dict[str, HttpObservation],
) -> tuple[VerificationStatus, str]:
    control = observations.get("control")
    secondary = observations.get("secondary-control")
    if secondary is None:
        return "inconclusive", "缺少第二身份控制响应，无法确认对象边界"
    if control is not None and _responses_match(control, secondary):
        return "inconclusive", "主身份和第二身份返回相同对象，无法确认越权"
    for probe in plan.probes:
        observation = observations.get(probe.probe_id)
        if (
            observation
            and 200 <= observation.status_code < 300
            and observation.body.strip()
            and _responses_match(observation, secondary)
        ):
            return (
                "verified_vulnerable",
                f"边界探针 {probe.probe_id} 返回了第二身份可取得的对象响应",
            )
    return "not_reproduced", "未观察到主身份取得第二身份对象响应的证据"


def _remove_authentication_oracle(
    plan: VerificationPlan,
    observations: dict[str, HttpObservation],
) -> tuple[VerificationStatus, str]:
    control = observations.get("control")
    if control is None or not (200 <= control.status_code < 300 and control.body.strip()):
        return "inconclusive", "控制请求没有成功响应，无法确认移除认证后的边界"
    tested = [
        (probe, observations.get(probe.probe_id))
        for probe in plan.probes
        if probe.probe_id != "control"
    ]
    for probe, observation in tested:
        if observation and 200 <= observation.status_code < 300 and observation.body.strip():
            return "verified_vulnerable", f"边界探针 {probe.probe_id} 仍返回非空成功响应"
    return "not_reproduced", "未观察到越过授权边界的成功响应"


def _authorization_oracle(
    plan: VerificationPlan,
    observations: dict[str, HttpObservation],
) -> tuple[VerificationStatus, str]:
    strategy = plan.strategy_kind
    if plan.schema_version < 2:
        strategy = (
            "secondary_identity"
            if any(probe.requires_secondary_identity for probe in plan.probes)
            else "remove_authentication"
        )
    if strategy == "secondary_identity":
        return _secondary_identity_oracle(plan, observations)
    return _remove_authentication_oracle(plan, observations)


def _marker_oracle(
    plan: VerificationPlan,
    observations: dict[str, HttpObservation],
) -> tuple[VerificationStatus, str]:
    marker = plan.oracle_marker
    if not marker:
        return "inconclusive", "计划没有提供可验证的响应 marker"
    control = observations.get("control")
    if control and marker in control.body:
        return "inconclusive", "控制响应已经包含该 marker，不能将其归因于探针"
    for probe in plan.probes:
        response = observations.get(probe.probe_id)
        if response and marker in response.body:
            return "verified_vulnerable", f"响应包含计划指定的 marker：{marker}"
    return "not_reproduced", "未观察到计划指定的响应 marker"


def _canary_oracle(
    plan: VerificationPlan,
    observations: dict[str, HttpObservation],
    probe_values: dict[str, str | None],
) -> tuple[VerificationStatus, str]:
    for probe in plan.probes:
        value = probe_values.get(probe.probe_id)
        response = observations.get(probe.probe_id)
        if value and response and value in response.body:
            return "inconclusive", "响应仅回显了 Canary，不能证明服务端发起了出站请求"
    return "inconclusive", "未观察到足以证明出站请求的 Canary 证据"


def _run_oracle(
    plan: VerificationPlan,
    observations: dict[str, HttpObservation],
    *,
    probe_values: dict[str, str | None],
) -> tuple[VerificationStatus, str]:
    oracle_kind = _effective_oracle_kind(plan)
    if oracle_kind == "response_difference":
        return _response_difference_oracle(plan, observations)
    if oracle_kind == "authorization_boundary":
        return _authorization_oracle(plan, observations)
    if oracle_kind == "identity_marker":
        return _marker_oracle(plan, observations)
    if oracle_kind == "canary_echo":
        return _canary_oracle(plan, observations, probe_values)
    return "inconclusive", f"不支持的响应判定器：{oracle_kind}"


def _assess(
    plan: VerificationPlan,
    probes: list[ProbeResult],
    observations: dict[str, HttpObservation],
    *,
    probe_values: dict[str, str | None],
) -> tuple[VerificationStatus, str]:
    if not probes:
        return "inconclusive", "没有可执行的验证探针"
    if any(result.error for result in probes):
        return "inconclusive", "部分验证请求执行失败，无法形成完整证据"
    return _run_oracle(plan, observations, probe_values=probe_values)


def execute_plan(
    plan: VerificationPlan,
    request: CanonicalRequest,
    *,
    run_name: str,
    approved: bool,
    side_effect_approved: bool = False,
    secondary: CanonicalRequest | None = None,
    baseline_run: str | None = None,
) -> VerificationResult:
    """Execute a plan only after approval and shape validation."""
    if request_shape_sha256(request) != plan.request_shape_sha256:
        return VerificationResult(
            status="blocked",
            vulnerability_type=plan.vulnerability_type,
            plan_sha256=plan.plan_sha256,
            run_name=run_name,
            summary="修复后的请求结构与原验证计划不一致，已阻止执行。",
            baseline_run=baseline_run,
        )
    if plan.blocked_reason:
        needs_secondary = plan.strategy_kind == "secondary_identity" or any(
            probe.requires_secondary_identity for probe in plan.probes
        )
        status: VerificationStatus = "needs_secondary_identity" if needs_secondary else "blocked"
        return VerificationResult(
            status=status,
            vulnerability_type=plan.vulnerability_type,
            plan_sha256=plan.plan_sha256,
            run_name=run_name,
            summary=plan.blocked_reason,
            baseline_run=baseline_run,
        )
    if not approved:
        return VerificationResult(
            status="waiting_confirmation",
            vulnerability_type=plan.vulnerability_type,
            plan_sha256=plan.plan_sha256,
            run_name=run_name,
            summary="验证计划已生成，等待用户确认；未发送请求。",
            baseline_run=baseline_run,
        )
    if plan.requires_side_effect_approval and not side_effect_approved:
        return VerificationResult(
            status="blocked",
            vulnerability_type=plan.vulnerability_type,
            plan_sha256=plan.plan_sha256,
            run_name=run_name,
            summary="该计划包含可能产生业务副作用的请求，需要额外确认后才会执行。",
            baseline_run=baseline_run,
        )
    if any(probe.requires_secondary_identity for probe in plan.probes) and secondary is None:
        return VerificationResult(
            status="needs_secondary_identity",
            vulnerability_type=plan.vulnerability_type,
            plan_sha256=plan.plan_sha256,
            run_name=run_name,
            summary="该验证需要第二身份请求包，当前未提供。",
            baseline_run=baseline_run,
        )

    observations: dict[str, HttpObservation] = {}
    results: list[ProbeResult] = []
    if len(results) < plan.max_requests:
        try:
            control = send_request(request)
            observations["control"] = control
            results.append(_probe_result("control", request, control))
        except VerificationExecutionError as exc:
            results.append(ProbeResult(probe_id="control", status="error", error=str(exc)))

    if (
        any(probe.requires_secondary_identity for probe in plan.probes)
        and len(results) < plan.max_requests
        and secondary is not None
    ):
        try:
            secondary_observation = send_request(secondary)
            observations["secondary-control"] = secondary_observation
            results.append(_probe_result("secondary-control", secondary, secondary_observation))
        except VerificationExecutionError as exc:
            results.append(
                ProbeResult(
                    probe_id="secondary-control",
                    status="error",
                    error=str(exc),
                )
            )

    for probe in plan.probes:
        if len(results) >= plan.max_requests:
            break
        try:
            mutated = _apply_probe(request, probe, secondary=secondary)
            observation = send_request(mutated)
            observations[probe.probe_id] = observation
            results.append(_probe_result(probe, mutated, observation))
        except (VerificationExecutionError, ValueError) as exc:
            results.append(ProbeResult(probe_id=probe.probe_id, status="error", error=str(exc)))

    status, summary = _assess(
        plan,
        results,
        observations,
        probe_values={probe.probe_id: probe.value for probe in plan.probes},
    )
    return VerificationResult(
        status=status,
        vulnerability_type=plan.vulnerability_type,
        plan_sha256=plan.plan_sha256,
        run_name=run_name,
        summary=summary,
        evidence=results,
        baseline_run=baseline_run,
    )


def compare_results(
    baseline: VerificationResult,
    current: VerificationResult,
) -> tuple[str, str]:
    if baseline.status != "verified_vulnerable":
        return "inconclusive", "历史基线没有确认漏洞，不能据此判定修复成功。"
    if current.status == "not_reproduced":
        return "fixed", "修复后使用相同验证计划未再次复现。"
    if current.status == "verified_vulnerable":
        return "still_vulnerable", "修复后使用相同验证计划仍然复现。"
    return "inconclusive", "修复后证据不足，无法判定已修复。"
