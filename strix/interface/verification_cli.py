"""CLI workflow for the simplified single-request verification mode."""

# ruff: noqa: RUF001

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm

from strix.verification.planner import VerificationPlanError
from strix.verification.request import RequestParseError, parse_request_text
from strix.verification.runner import run_verification_case


def _read_request_interactively(console: Console) -> str:
    console.print(
        "请粘贴 Burp Raw HTTP 或 Copy as cURL 请求。\n输入单独一行 `__STRIX_END__` 结束：",
    )
    lines: list[str] = []
    while True:
        line = console.input()
        if line == "__STRIX_END__":
            break
        lines.append(line)
    if not "\n".join(lines).strip():
        raise ValueError("请求内容不能为空")
    return "\n".join(lines)


def _read_request_file_or_prompt(args: Any, console: Console) -> str:
    request_path = getattr(args, "verification_request", None)
    if request_path:
        return str(Path(request_path).read_text(encoding="utf-8"))
    if getattr(args, "non_interactive", False):
        raise ValueError("非交互漏洞验证模式需要 --request <Burp请求文件>")
    return _read_request_interactively(console)


def _issue_or_prompt(args: Any, console: Console) -> str | None:
    issue = getattr(args, "verification_issue", None)
    if issue:
        return str(issue).strip()
    if getattr(args, "verification_baseline", None):
        return None
    if getattr(args, "non_interactive", False):
        raise ValueError("首次漏洞验证需要 --issue <问题描述>")
    issue = console.input("请用一句话描述你怀疑的漏洞：").strip()
    if not issue:
        raise ValueError("漏洞描述不能为空")
    return issue


def _resolve_scheme(
    request_text: str,
    *,
    console: Console,
    non_interactive: bool,
) -> str | None:
    try:
        parse_request_text(request_text)
    except RequestParseError as exc:
        if "缺少 Scheme" not in str(exc):
            raise
        if non_interactive:
            raise
        scheme = console.input("请求中缺少 Scheme，请输入 http 或 https：").strip().lower()
        if scheme not in {"http", "https"}:
            raise ValueError("Scheme 只支持 http 或 https") from exc
        parse_request_text(request_text, scheme=scheme)
        return scheme
    return None


def _plan_text(plan: Any) -> str:
    fields = "、".join(plan.target_fields) or "未识别"
    probes = "\n".join(f"- {probe.title}：{probe.description}" for probe in plan.probes)
    return "\n".join(
        [
            f"识别类型：{plan.vulnerability_type}",
            f"目标字段：{fields}",
            f"预计请求数：{plan.max_requests}",
            f"副作用确认：{'需要' if plan.requires_side_effect_approval else '不需要'}",
            "",
            "验证动作：",
            probes or "- 无可执行验证动作",
            "",
            "证据要求：",
            "\n".join(f"- {item.description}" for item in plan.assertions) or "- 无法生成证据要求",
            *(["", f"阻断原因：{plan.blocked_reason}"] if plan.blocked_reason else []),
        ]
    )


def _result_text(result: Any, run_dir: Path) -> str:
    return "\n".join(
        [
            f"验证结论：{result.status}",
            result.summary,
            "",
            f"运行目录：{run_dir}",
            f"验证报告：{run_dir / 'penetration_test_report.md'}",
        ]
    )


def _write_temp_request(text: str) -> Path:
    handle, temporary_name = tempfile.mkstemp(prefix="strix-verify-request-", suffix=".txt")
    path = Path(temporary_name)
    os.close(handle)
    path.write_text(text, encoding="utf-8")
    return path


async def run_verification_cli(args: Any) -> int:  # noqa: PLR0912
    console = Console()
    temporary_requests: list[Path] = []
    try:
        request_text = _read_request_file_or_prompt(args, console)
        request_path = getattr(args, "verification_request", None)
        if request_path is None:
            temporary_request = _write_temp_request(request_text)
            temporary_requests.append(temporary_request)
            request_path = str(temporary_request)
        request_scheme = _resolve_scheme(
            request_text,
            console=console,
            non_interactive=bool(getattr(args, "non_interactive", False)),
        )
        issue = _issue_or_prompt(args, console)
        approved = bool(getattr(args, "verification_approve", False))
        side_effect_approved = approved
        secondary_path: str | None = None
        secondary_scheme: str | None = None
        if secondary_path:
            secondary_text = Path(secondary_path).read_text(encoding="utf-8")
            secondary_scheme = _resolve_scheme(
                secondary_text,
                console=console,
                non_interactive=bool(getattr(args, "non_interactive", False)),
            )
        run_dir, plan, result = run_verification_case(
            request_file=request_path,
            issue=issue,
            baseline_run=getattr(args, "verification_baseline", None),
            approved=approved,
            side_effect_approved=side_effect_approved,
            secondary_request_file=secondary_path,
            scheme=request_scheme,
            secondary_scheme=secondary_scheme,
        )
        plan_displayed = False
        if not getattr(args, "non_interactive", False) and result.status in {
            "waiting_confirmation",
            "blocked",
            "needs_secondary_identity",
        }:
            console.print(Panel(_plan_text(plan), title="漏洞验证计划", border_style="yellow"))
            plan_displayed = True
        if (
            result.status == "needs_secondary_identity"
            and not getattr(args, "non_interactive", False)
            and not secondary_path
        ):
            secondary_text = _read_request_interactively(
                console,
            )
            secondary_request = _write_temp_request(secondary_text)
            temporary_requests.append(secondary_request)
            secondary_path = str(secondary_request)
            secondary_scheme = _resolve_scheme(
                secondary_text,
                console=console,
                non_interactive=False,
            )
            run_dir, plan, result = run_verification_case(
                request_file=request_path,
                issue=issue,
                baseline_run=getattr(args, "verification_baseline", None),
                approved=False,
                side_effect_approved=False,
                secondary_request_file=secondary_path,
                scheme=request_scheme,
                secondary_scheme=secondary_scheme,
            )
            plan_displayed = False
        if (
            not approved
            and result.status == "waiting_confirmation"
            and not getattr(args, "non_interactive", False)
        ):
            if not plan_displayed:
                console.print(Panel(_plan_text(plan), title="漏洞验证计划", border_style="yellow"))
            if Confirm.ask("确认执行以上验证动作？", default=False):
                side_effect_approved = True
                if plan.requires_side_effect_approval:
                    side_effect_approved = Confirm.ask(
                        "该计划可能产生业务副作用，仍然继续？",
                        default=False,
                    )
                run_dir, plan, result = run_verification_case(
                    request_file=request_path,
                    issue=issue,
                    baseline_run=getattr(args, "verification_baseline", None),
                    approved=True,
                    side_effect_approved=side_effect_approved,
                    secondary_request_file=secondary_path,
                    scheme=request_scheme,
                    secondary_scheme=secondary_scheme,
                )
        console.print(Panel(_result_text(result, run_dir), title="漏洞验证结果"))
        if result.status in {"verified_vulnerable", "still_vulnerable"}:
            return 2
        if result.status in {"blocked", "needs_secondary_identity", "inconclusive"}:
            return 1
        return 0  # noqa: TRY300
    except (OSError, ValueError, VerificationPlanError) as exc:
        console.print(Panel(str(exc), title="漏洞验证失败", border_style="red"))
        return 1
    finally:
        for temporary_request in temporary_requests:
            if temporary_request.exists():
                temporary_request.unlink(missing_ok=True)


__all__ = ["run_verification_cli"]
