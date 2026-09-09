"""Bounded, direct HTTP execution for verification plans."""

# ruff: noqa: RUF001

from __future__ import annotations

import hashlib
import http.client
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


def _probe_result(
    probe: Any,
    request: CanonicalRequest,
    observation: HttpObservation,
) -> ProbeResult:
    return ProbeResult(
        probe_id=probe.probe_id,
        status="observed",
        response_status=observation.status_code,
        response_length=len(observation.body.encode("utf-8")),
        response_sha256=_fingerprint(observation),
        response_summary=observation.body[:2048],
        request=render_raw_request(request),
    )


def _assess(  # noqa: PLR0911, PLR0912
    vulnerability_type: str,
    probes: list[ProbeResult],
    observations: dict[str, HttpObservation],
    *,
    issue_description: str,
    probe_values: dict[str, str | None],
) -> tuple[VerificationStatus, str]:
    if not probes:
        return "inconclusive", "没有可执行的验证探针"
    if any(result.error for result in probes):
        return "inconclusive", "部分验证请求执行失败，无法形成完整证据"

    if vulnerability_type == "sqli":
        true_response = observations.get("sqli-boolean-true")
        false_response = observations.get("sqli-boolean-false")
        if true_response and false_response:
            differs = (
                true_response.status_code != false_response.status_code
                or abs(len(true_response.body) - len(false_response.body)) > 32
            )
            if differs and (
                _DB_ERROR_RE.search(true_response.body)
                or true_response.status_code != false_response.status_code
            ):
                return "verified_vulnerable", "真值与假值探针产生了可重复的数据库响应差异"
        return "not_reproduced", "未观察到足以确认 SQL 注入的响应差异"

    if vulnerability_type in {"idor_bola", "authz_bypass"}:
        for result in probes:
            observation = observations.get(result.probe_id)
            if observation and 200 <= observation.status_code < 300 and observation.body.strip():
                if vulnerability_type == "idor_bola":
                    return "verified_vulnerable", "受保护对象在不同身份边界下仍返回了非空响应"
                return "verified_vulnerable", "移除认证信息后仍返回了非空成功响应"
        return "not_reproduced", "未观察到未授权成功访问"

    if vulnerability_type == "command_injection":
        for result in probes:
            if _IDENTITY_RE.search(result.response_summary):
                return "verified_vulnerable", "响应包含受控身份确认结果"
        return "not_reproduced", "未观察到身份确认结果"

    if vulnerability_type == "file_upload":
        marker = probe_values.get("upload-benign-marker")
        response = observations.get("upload-benign-marker")
        if marker and response and marker in response.body:
            return "verified_vulnerable", "响应中返回了上传 marker，可继续复核对象访问边界"
        return "inconclusive", "上传请求已执行，但响应未提供可确认的 marker 证据"

    if vulnerability_type == "ssrf":
        canary = probe_values.get("ssrf-controlled-canary")
        response = observations.get("ssrf-controlled-canary")
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
    safe_method = request.method.upper() in {"GET", "HEAD", "OPTIONS"}
    if safe_method and len(results) < plan.max_requests:
        try:
            control = send_request(request)
            observations["control"] = control
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
        plan.vulnerability_type,
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
