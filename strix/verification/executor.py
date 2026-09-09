"""Bounded, direct HTTP execution for verification plans."""

# ruff: noqa: RUF001

from __future__ import annotations

import hashlib
import http.client
import json
import logging
import re
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
_DB_ERROR_RE = re.compile(r"(?i)(sql syntax|mysql|postgres|sqlite|odbc|ora-\d+|syntax error)")
_IDENTITY_RE = re.compile(r"(?i)\b(uid|gid)=\d+|\bwhoami\b|\b(root|www-data|application)\b")


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
    headers.setdefault(
        "Host",
        request.host if request.port in {80, 443} else f"{request.host}:{request.port}",
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
            raise VerificationExecutionError("文件上传 marker 缺失")
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


def _json_shape(value: Any) -> Any:
    if isinstance(value, dict):
        entries = ((str(key), _json_shape(item)) for key, item in value.items())
        return ("object", tuple(sorted(entries)))
    if isinstance(value, list):
        return ("array", len(value), tuple(_json_shape(item) for item in value[:3]))
    if isinstance(value, bool):
        return ("boolean",)
    if isinstance(value, (int, float)):
        return ("number",)
    if value is None:
        return ("null",)
    return ("string", len(str(value)))


def _responses_differ(first: HttpObservation, second: HttpObservation) -> bool:
    if first.status_code == second.status_code and first.body == second.body:
        return False
    if first.status_code != second.status_code:
        return True
    if abs(len(first.body) - len(second.body)) > 32:
        return True
    try:
        return bool(_json_shape(json.loads(first.body)) != _json_shape(json.loads(second.body)))
    except (TypeError, ValueError, json.JSONDecodeError):
        return False


def _response_label(observation: HttpObservation | None) -> str:
    if observation is None:
        return "未获得响应"
    return f"HTTP {observation.status_code} / {len(observation.body.encode('utf-8'))} bytes"


def _effective_oracle_kind(plan: VerificationPlan) -> str:
    if plan.schema_version >= 2:
        return plan.oracle_kind
    return {
        "sqli": "response_difference",
        "idor_bola": "authorization_boundary",
        "authz_bypass": "authorization_boundary",
        "command_injection": "identity_marker",
        "ssrf": "canary_echo",
        "file_upload": "canary_echo",
    }.get(plan.vulnerability_type, plan.oracle_kind)


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


def _assess(  # noqa: PLR0911, PLR0912, PLR0915
    plan: VerificationPlan,
    probes: list[ProbeResult],
    observations: dict[str, HttpObservation],
    *,
    issue_description: str,
    probe_values: dict[str, str | None],
) -> tuple[VerificationStatus, str]:
    vulnerability_type = plan.vulnerability_type
    oracle_kind = _effective_oracle_kind(plan)
    if not probes:
        return "inconclusive", "没有可执行的验证探针"
    if any(result.error for result in probes):
        return "inconclusive", "部分验证请求执行失败，无法形成完整证据"

    if oracle_kind == "response_difference" and vulnerability_type == "sqli":
        control_response = observations.get("control")
        pairs: dict[str, dict[str, str]] = {}
        for probe in plan.probes:
            role = probe.role
            pair_id = probe.pair_id
            if not pair_id or role not in {"true", "false"}:
                legacy_match = re.fullmatch(r"sqli-(.+)-(true|false)", probe.probe_id)
                if legacy_match:
                    pair_id = pair_id or legacy_match.group(1)
                    role = role or legacy_match.group(2)
            if pair_id and role in {"true", "false"}:
                pairs.setdefault(pair_id, {})[role] = probe.probe_id
        evidence_lines: list[str] = []
        for pair_id, pair in pairs.items():
            true_probe_id = pair.get("true")
            false_probe_id = pair.get("false")
            if not true_probe_id or not false_probe_id:
                continue
            true_response = observations.get(true_probe_id)
            false_response = observations.get(false_probe_id)
            if not true_response or not false_response:
                continue
            evidence_lines.append(
                f"{pair_id}: 真值 {_response_label(true_response)}，"
                f"假值 {_response_label(false_response)}"
            )
            differs = _responses_differ(true_response, false_response)
            database_error = _DB_ERROR_RE.search(true_response.body) or _DB_ERROR_RE.search(
                false_response.body
            )
            same_body_as_control = control_response is not None and control_response.body in {
                true_response.body,
                false_response.body,
            }
            status_split_around_control = control_response is not None and (
                (true_response.status_code == control_response.status_code)
                and (false_response.status_code != control_response.status_code)
            )
            control_aligned = same_body_as_control or status_split_around_control
            if differs and (database_error or control_aligned):
                return (
                    "verified_vulnerable",
                    "基线、真值和假值请求产生了可复现的数据库响应差异；"
                    + "；".join(evidence_lines),
                )
        for probe in plan.probes:
            if probe.role != "error":
                continue
            response = observations.get(probe.probe_id)
            if response is None:
                continue
            evidence_lines.append(f"错误型探针：{_response_label(response)}")
            if _DB_ERROR_RE.search(response.body):
                return (
                    "verified_vulnerable",
                    "错误型探针触发了数据库错误响应；" + "；".join(evidence_lines),
                )
        baseline = _response_label(control_response)
        details = "；".join(evidence_lines) or "未获得完整的真值/假值响应"
        return (
            "not_reproduced",
            f"未观察到足以确认 SQL 注入的响应差异；基线 {baseline}；{details}",
        )

    if oracle_kind == "authorization_boundary" and vulnerability_type in {
        "idor_bola",
        "authz_bypass",
    }:
        for result in probes:
            if result.probe_id == "control":
                continue
            observation = observations.get(result.probe_id)
            if observation and 200 <= observation.status_code < 300 and observation.body.strip():
                if vulnerability_type == "idor_bola":
                    return "verified_vulnerable", "受保护对象在不同身份边界下仍返回了非空响应"
                return "verified_vulnerable", "移除认证信息后仍返回了非空成功响应"
        return "not_reproduced", "未观察到未授权成功访问"

    if oracle_kind == "identity_marker" and vulnerability_type == "command_injection":
        for result in probes:
            if result.probe_id == "control":
                continue
            if _IDENTITY_RE.search(result.response_summary):
                return "verified_vulnerable", "响应包含受控身份确认结果"
        return "not_reproduced", "未观察到身份确认结果"

    if oracle_kind == "canary_echo" and vulnerability_type == "file_upload":
        for probe in plan.probes:
            if probe.action != "multipart_marker":
                continue
            marker = probe_values.get(probe.probe_id)
            response = observations.get(probe.probe_id)
            if marker and response and marker in response.body:
                return "verified_vulnerable", "响应中返回了上传 marker，可继续复核对象访问边界"
        return "inconclusive", "上传请求已执行，但响应未提供可确认的 marker 证据"

    if oracle_kind == "canary_echo" and vulnerability_type == "ssrf":
        for probe in plan.probes:
            if probe.action != "set":
                continue
            canary = probe_values.get(probe.probe_id)
            response = observations.get(probe.probe_id)
            if canary and response and canary in response.body:
                return "verified_vulnerable", "响应包含受控 Canary 地址"
        return "inconclusive", "未观察到受控 Canary 命中证据"

    return "inconclusive", f"未支持的验证类型：{issue_description[:80]}"


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
        status: VerificationStatus = (
            "needs_secondary_identity" if "第二" in plan.blocked_reason else "blocked"
        )
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
        issue_description=plan.issue_description,
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
