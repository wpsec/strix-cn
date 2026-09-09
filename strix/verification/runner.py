"""Persistence and lifecycle orchestration for verification runs."""

# ruff: noqa: RUF001

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from strix.core.paths import run_dir_for
from strix.report.writer import read_run_record, safe_fence, write_run_record
from strix.verification.executor import compare_results, execute_plan
from strix.verification.models import (
    CanonicalRequest,
    ProbeResult,
    VerificationAssertion,
    VerificationCase,
    VerificationPlan,
    VerificationProbe,
    VerificationResult,
    render_raw_request,
)
from strix.verification.planner import build_verification_plan
from strix.verification.request import parse_request_file


VERIFICATION_POLICY_VERSION = "verification-v1"


def _run_name() -> str:
    return datetime.now(UTC).strftime("verify-%Y%m%d-%H%M%S-%f")


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _validate_run_name(run_name: str) -> None:
    if not run_name or Path(run_name).name != run_name or run_name in {".", ".."}:
        raise ValueError("验证运行名无效")


def _request_from_template(template: dict[str, Any]) -> CanonicalRequest:
    raw_query = template.get("query")
    query = (
        [
            (str(item[0]), str(item[1]))
            for item in raw_query
            if isinstance(item, list) and len(item) == 2
        ]
        if isinstance(raw_query, list)
        else []
    )
    raw_headers = template.get("headers")
    headers = (
        {str(name): str(value) for name, value in raw_headers.items()}
        if isinstance(raw_headers, dict)
        else {}
    )
    return CanonicalRequest(
        method=str(template.get("method") or "GET"),
        scheme=str(template.get("scheme") or "https"),
        host=str(template.get("host") or ""),
        port=int(template.get("port") or 443),
        path=str(template.get("path") or "/"),
        query=query,
        headers=headers,
        body=str(template.get("body") or ""),
    )


def _same_authority(first: object, second: object) -> bool:
    return all(
        getattr(first, name, None) == getattr(second, name, None)
        for name in ("scheme", "host", "port")
    )


def _load_plan(run_dir: Path) -> VerificationPlan:
    try:
        data = json.loads((run_dir / "verification-plan.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"验证计划无法读取：{exc}") from exc
    try:
        plan = VerificationPlan(
            schema_version=int(data["schema_version"]),
            vulnerability_type=str(data["vulnerability_type"]),
            issue_description=str(data["issue_description"]),
            request_template=dict(data["request_template"]),
            request_shape_sha256=str(data["request_shape_sha256"]),
            target_fields=[str(item) for item in data.get("target_fields", [])],
            probes=[
                VerificationProbe(**dict(item))
                for item in data.get("probes", [])
                if isinstance(item, dict)
            ],
            assertions=[
                VerificationAssertion(**dict(item))
                for item in data.get("assertions", [])
                if isinstance(item, dict)
            ],
            max_requests=int(data.get("max_requests", 0)),
            requires_side_effect_approval=bool(data.get("requires_side_effect_approval", False)),
            blocked_reason=data.get("blocked_reason"),
            plan_sha256=str(data.get("plan_sha256", "")),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"验证计划格式无效：{exc}") from exc
    if not plan.plan_sha256 or plan.plan_sha256 != plan.finalize_hash():
        raise ValueError("验证计划完整性校验失败，请重新生成计划")
    return plan


def _load_result(run_dir: Path) -> VerificationResult:
    try:
        data = json.loads((run_dir / "verification-result.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"验证结果无法读取：{exc}") from exc
    try:
        return VerificationResult(
            status=str(data["status"]),  # type: ignore[arg-type]
            vulnerability_type=str(data["vulnerability_type"]),
            plan_sha256=str(data["plan_sha256"]),
            run_name=str(data["run_name"]),
            summary=str(data.get("summary", "")),
            evidence=[
                ProbeResult(**dict(item))
                for item in data.get("evidence", [])
                if isinstance(item, dict)
            ],
            baseline_run=data.get("baseline_run"),
            comparison=data.get("comparison"),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"验证结果格式无效：{exc}") from exc


def _render_report(
    *,
    run_name: str,
    plan: VerificationPlan,
    result: VerificationResult,
) -> str:
    lines = [
        "# 漏洞验证报告",
        "",
        f"- 运行：`{run_name}`",
        f"- 验证类型：`{plan.vulnerability_type}`",
        f"- 验证状态：`{result.status}`",
        f"- 目标：`{plan.request_template.get('scheme')}://"
        f"{plan.request_template.get('host')}:{plan.request_template.get('port')}`",
        "",
        "## 原始 Burp 请求",
        "",
    ]
    original_request = render_raw_request(_request_from_template(plan.request_template))
    original_fence = safe_fence(original_request)
    lines.extend([f"{original_fence}http", original_request, original_fence, ""])
    lines.extend(
        [
        "## 问题描述",
        "",
        plan.issue_description,
        "",
        "## 验证计划",
        "",
        f"- 目标字段：{', '.join(plan.target_fields) or '未识别'}",
        f"- 预计请求数：{plan.max_requests}",
        f"- 计划哈希：`{plan.plan_sha256}`",
        f"- 副作用确认：{'需要' if plan.requires_side_effect_approval else '不需要'}",
        "",
        ]
    )
    if plan.blocked_reason:
        lines.extend(["## 阻断原因", "", plan.blocked_reason, ""])
    lines.extend(["## 证据要求", ""])
    if plan.assertions:
        lines.extend(f"- {assertion.description}" for assertion in plan.assertions)
    else:
        lines.append("没有可用的证据要求。")
    lines.append("")
    lines.extend(["## 验证结论", "", result.summary, ""])
    if result.comparison:
        lines.extend(["## 修复复测对比", "", result.comparison, ""])
    lines.extend(["## 证据摘要", ""])
    if not result.evidence:
        lines.append("没有已执行的请求。")
    for evidence in result.evidence:
        lines.extend(
            [
                f"### {evidence.probe_id}",
                "",
                f"- 执行状态：`{evidence.status}`",
                f"- 响应状态码：`{evidence.response_status or '未获得'}`",
                f"- 响应长度：`{evidence.response_length}`",
                f"- 响应指纹：`{evidence.response_sha256 or '未获得'}`",
                "- 证据：",
                evidence.evidence or evidence.response_summary or evidence.error or "未提供",
                "",
            ]
        )
        if evidence.request:
            evidence_fence = safe_fence(evidence.request)
            lines.extend(
                [
                    "- 可复制到 Burp Repeater 的请求：",
                    "",
                    f"{evidence_fence}http",
                    evidence.request,
                    evidence_fence,
                    "",
                ]
            )
    lines.extend(
        [
            "## 复测方式",
            "",
            f"`strix --verify --baseline {run_name} --request ./request-after-fix.txt`",
            "",
            "报告中的请求保留完整 Header、Token、Cookie 和 Body，可直接复制到 Burp Repeater 复现。",
            "",
        ]
    )
    return "\n".join(lines)


def _persist(
    *,
    run_name: str,
    plan: VerificationPlan,
    result: VerificationResult,
    baseline_run: str | None,
) -> Path:
    run_dir = run_dir_for(run_name)
    run_dir.mkdir(parents=True, exist_ok=True)
    _write_json(run_dir / "verification-plan.json", plan.to_dict())
    _write_json(run_dir / "verification-result.json", result.to_dict())
    with (run_dir / "verification-evidence.jsonl").open("w", encoding="utf-8") as handle:
        for evidence in result.evidence:
            handle.write(json.dumps(evidence.to_dict(), ensure_ascii=False) + "\n")
    (run_dir / "penetration_test_report.md").write_text(
        _render_report(run_name=run_name, plan=plan, result=result),
        encoding="utf-8",
    )
    record: dict[str, Any] = {
        "run_id": run_name,
        "run_name": run_name,
        "start_time": datetime.now(UTC).isoformat(),
        "end_time": datetime.now(UTC).isoformat(),
        "status": (
            "completed" if result.status not in {"waiting_confirmation", "running"} else "running"
        ),
        "mode": "verify",
        "policy_version": VERIFICATION_POLICY_VERSION,
        "targets_info": [],
        "scan_mode": "verification",
        "verification_plan_sha256": plan.plan_sha256,
        "verification_status": result.status,
        "verification_baseline_run": baseline_run,
        "verification_type": plan.vulnerability_type,
        "verification_issue": plan.issue_description,
    }
    write_run_record(run_dir, record)
    return run_dir


def run_verification_case(
    *,
    request_file: str,
    issue: str | None,
    run_name: str | None = None,
    baseline_run: str | None = None,
    approved: bool = False,
    side_effect_approved: bool = False,
    secondary_request_file: str | None = None,
    scheme: str | None = None,
    secondary_scheme: str | None = None,
) -> tuple[Path, VerificationPlan, VerificationResult]:
    """Build or load a plan, execute it when approved, and persist artifacts."""
    selected_run_name = run_name or _run_name()
    _validate_run_name(selected_run_name)
    request = parse_request_file(request_file, scheme=scheme)
    secondary = (
        parse_request_file(secondary_request_file, scheme=secondary_scheme)
        if secondary_request_file
        else None
    )
    if secondary is not None and not _same_authority(request, secondary):
        raise ValueError("第二身份请求必须使用与主请求相同的 Scheme、Host 和 Port")

    if baseline_run:
        _validate_run_name(baseline_run)
        baseline_dir = run_dir_for(baseline_run)
        if not baseline_dir.is_dir():
            raise ValueError(f"找不到基线运行：{baseline_run}")
        plan = _load_plan(baseline_dir)
        baseline_result = _load_result(baseline_dir)
        if baseline_result.plan_sha256 != plan.plan_sha256:
            raise ValueError("历史验证结果与验证计划不匹配")
        result = execute_plan(
            plan,
            request,
            run_name=selected_run_name,
            approved=approved,
            side_effect_approved=side_effect_approved,
            secondary=secondary,
            baseline_run=baseline_run,
        )
        if approved and result.status not in {
            "blocked",
            "needs_secondary_identity",
            "waiting_confirmation",
        }:
            comparison_status, comparison = compare_results(baseline_result, result)
            result.status = comparison_status  # type: ignore[assignment]
            result.comparison = comparison
            result.summary = comparison
    else:
        if issue is None:
            raise ValueError("首次验证需要提供 --issue 或在交互界面输入问题描述")
        plan = build_verification_plan(
            VerificationCase(
                request=request,
                issue_description=issue,
                supporting_requests=[secondary] if secondary else [],
            )
        )
        result = execute_plan(
            plan,
            request,
            run_name=selected_run_name,
            approved=approved,
            side_effect_approved=side_effect_approved,
            secondary=secondary,
        )

    run_dir = _persist(
        run_name=selected_run_name,
        plan=plan,
        result=result,
        baseline_run=baseline_run,
    )
    return run_dir, plan, result


def load_verification_run(
    run_name: str,
) -> tuple[VerificationPlan, VerificationResult, dict[str, Any]]:
    _validate_run_name(run_name)
    run_dir = run_dir_for(run_name)
    return _load_plan(run_dir), _load_result(run_dir), read_run_record(run_dir)
