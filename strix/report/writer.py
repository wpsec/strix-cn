"""Artifact writers for Strix scan reports."""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from pygments.lexers import PythonLexer, get_lexer_by_name, guess_lexer
from pygments.lexers.special import TextLexer
from pygments.util import ClassNotFound

from strix.core.paths import run_record_path


if TYPE_CHECKING:
    from pygments.lexer import Lexer

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_LABELS_ZH = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}
_FIX_EFFORT_LABELS_ZH = {
    "trivial": "极低",
    "low": "低",
    "medium": "中",
    "high": "高",
}
_STATUS_LABELS_ZH = {
    "running": "进行中",
    "completed": "已完成",
    "stopped": "已停止",
    "failed": "失败",
    "interrupted": "已中断",
}

_FENCE_RE = re.compile(r"^```([^\n`]*)\r?\n(.*?)\r?\n?```$", re.DOTALL)
_BACKTICK_RUN = re.compile(r"`+")


def safe_fence(content: str) -> str:
    """Return a backtick fence that ``content`` cannot break out of."""
    longest = max((len(m.group()) for m in _BACKTICK_RUN.finditer(content)), default=0)
    return "`" * max(3, longest + 1)


def parse_fenced_code(raw: str) -> tuple[str | None, str]:
    """Split an optionally fenced code string into ``(language, code)``."""
    match = _FENCE_RE.match(raw.strip())
    if not match:
        return None, raw
    info = match.group(1).strip()
    language = info.split()[0] if info else None
    return (language or None), match.group(2)


def resolve_lexer(language: str | None, code: str) -> Lexer:
    """Pick a pygments lexer for ``code``."""
    if language:
        try:
            return get_lexer_by_name(language)
        except ClassNotFound:
            pass
    try:
        lexer = guess_lexer(code)
    except ClassNotFound:
        return cast("Lexer", PythonLexer())
    if isinstance(lexer, TextLexer):
        return cast("Lexer", PythonLexer())
    return lexer


def guess_language_name(code: str) -> str:
    """Return a markdown fence tag for ``code``."""
    try:
        lexer = guess_lexer(code)
    except ClassNotFound:
        return "python"
    if isinstance(lexer, TextLexer) or not lexer.aliases:
        return "python"
    return str(lexer.aliases[0])


def read_run_record(run_dir: Path) -> dict[str, Any]:
    path = run_record_path(run_dir)
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"run.json at {path} is unreadable: {exc}") from exc
    if not isinstance(data, dict):
        raise TypeError(f"run.json at {path} is not an object")
    return data


def write_run_record(run_dir: Path, run_record: dict[str, Any]) -> None:
    _atomic_write_text(
        run_record_path(run_dir),
        json.dumps(run_record, ensure_ascii=False, indent=2, default=str),
    )


def _escape_inline(value: Any) -> str:
    text = str(value or "未提供").strip()
    return re.sub(r"([\\`*_{}\[\]()<>#+.!|\-])", r"\\\1", text)


def _target_labels(run_record: dict[str, Any]) -> list[str]:
    targets = run_record.get("targets_info")
    if not isinstance(targets, list):
        return []
    labels: list[str] = []
    for target in targets:
        if isinstance(target, dict):
            value = target.get("original") or target.get("canonical") or target.get("display")
        else:
            value = target
        if value:
            labels.append(str(value).strip())
    return labels


def _extract_final_section(final_scan_result: str, title: str) -> str:
    pattern = re.compile(
        rf"^#\s+{re.escape(title)}\s*$([\s\S]*?)(?=^#\s+|\Z)",
        re.MULTILINE,
    )
    match = pattern.search(final_scan_result)
    if not match:
        return final_scan_result.strip() or "未提供。"
    content = match.group(1).strip()
    return content or "未提供。"


def _relevel_markdown_headings(markdown: str, level_delta: int = 2) -> str:
    lines: list[str] = []
    in_fence = False
    for line in markdown.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
        if not in_fence:
            match = re.match(r"^(\s*)(#{1,6})(\s+.*)$", line)
            if match:
                heading_level = min(6, len(match.group(2)) + level_delta)
                line = f"{match.group(1)}{'#' * heading_level}{match.group(3)}"
        lines.append(line)
    return "\n".join(lines).strip()


def render_complete_report(
    final_scan_result: str,
    *,
    run_record: dict[str, Any] | None = None,
    vulnerability_reports: list[dict[str, Any]] | None = None,
) -> str:
    """Render one delivery-ready report with cover, TOC, summary, and findings."""
    record = run_record or {}
    reports = list(vulnerability_reports or [])
    targets = _target_labels(record)
    run_name = record.get("run_name") or record.get("scan_id") or "未命名运行"
    status = _STATUS_LABELS_ZH.get(str(record.get("status") or "").lower(), "未提供")
    generated_at = record.get("end_time") or record.get("start_time") or "未提供"
    scan_mode = record.get("scan_mode") or "未提供"
    severity_counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info")}
    for report in reports:
        severity = str(report.get("severity") or "info").strip().lower()
        severity_counts[severity if severity in severity_counts else "info"] += 1

    summary = _extract_final_section(final_scan_result, "执行摘要")
    methodology = _extract_final_section(final_scan_result, "测试方法")
    technical_analysis = _extract_final_section(final_scan_result, "技术分析")
    recommendations = _extract_final_section(final_scan_result, "修复建议")

    sorted_reports = sorted(
        reports,
        key=lambda report: (
            _SEVERITY_ORDER.get(str(report.get("severity") or "").lower(), 5),
            str(report.get("id") or ""),
        ),
    )
    lines = [
        '<div align="center">',
        "",
        "<h1>安全渗透测试报告</h1>",
        "",
        "<p><strong>交付版 · 机密</strong></p>",
        "",
        "仅限授权人员阅览",
        "",
        "</div>",
        "",
        "---",
        "",
        "## 报告信息",
        "",
        "| 项目 | 内容 |",
        "| --- | --- |",
        f"| 报告名称 | {_escape_inline(run_name)} |",
        f"| 测试目标 | {_escape_inline('、'.join(targets) if targets else '未提供')} |",
        f"| 测试模式 | {_escape_inline(scan_mode)} |",
        f"| 报告状态 | {status} |",
        f"| 生成时间 | {_escape_inline(generated_at)} |",
        "",
        "---",
        "",
        "## 目录",
        "",
        "1. [执行摘要](#executive-summary)",
        "2. [测试范围与方法](#scope-and-methodology)",
        "3. [风险概览](#risk-overview)",
        "4. [漏洞详情](#finding-details)",
        "5. [修复建议](#remediation)",
        "6. [附录：交付物说明](#appendix-deliverables)",
        "",
    ]
    if sorted_reports:
        lines.extend(["**漏洞索引：**", ""])
        for report in sorted_reports:
            report_id = str(report.get("id") or "unknown")
            report_title = _escape_inline(report.get("title") or "未命名漏洞")
            anchor = re.sub(r"[^a-z0-9-]", "", report_id.lower())
            lines.append(f"- [{report_id} · {report_title}](#{anchor})")
        lines.append("")
    lines.extend(
        [
            '<a id="executive-summary"></a>',
            "## 1. 执行摘要",
            "",
            summary,
            "",
            '<a id="scope-and-methodology"></a>',
            "## 2. 测试范围与方法",
            "",
            f"**测试目标：** {_escape_inline('、'.join(targets) if targets else '未提供')}",
            "",
            methodology,
            "",
            "### 技术分析",
            "",
            technical_analysis,
            "",
            '<a id="risk-overview"></a>',
            "## 3. 风险概览",
            "",
            "| 严重性 | 数量 |",
            "| --- | ---: |",
            f"| 严重 | {severity_counts['critical']} |",
            f"| 高危 | {severity_counts['high']} |",
            f"| 中危 | {severity_counts['medium']} |",
            f"| 低危 | {severity_counts['low']} |",
            f"| 信息 | {severity_counts['info']} |",
            f"| **合计** | **{len(reports)}** |",
            "",
            '<a id="finding-details"></a>',
            "## 4. 漏洞详情",
            "",
        ]
    )

    if not reports:
        lines.extend(["本次运行没有已落盘的漏洞报告。", ""])
    else:
        for report in sorted_reports:
            report_id = str(report.get("id") or "unknown")
            title = _escape_inline(report.get("title") or "未命名漏洞")
            finding_body = render_vulnerability_md(report).splitlines()
            if finding_body and finding_body[0].startswith("# "):
                finding_body = finding_body[1:]
            lines.extend(
                [
                    f'<a id="{re.sub(r"[^a-z0-9-]", "", report_id.lower())}"></a>',
                    f"### {report_id} · {title}",
                    "",
                    _relevel_markdown_headings("\n".join(finding_body)),
                    "",
                ]
            )

    lines.extend(
        [
            '<a id="remediation"></a>',
            "## 5. 修复建议",
            "",
            recommendations,
            "",
            '<a id="appendix-deliverables"></a>',
            "## 6. 附录：交付物说明",
            "",
            "本目录同时保留以下机器可读或分项文件，供复核和系统导入使用：",
            "",
            "- `penetration_test_report.md`：本交付版完整报告。",
            "- `vulnerabilities/`：按漏洞编号拆分的明细文件。",
            "- `vulnerabilities.csv`：漏洞清单，便于表格导入。",
            "- `vulnerabilities.json`：结构化漏洞数据。",
            "- `findings.sarif`：SARIF 2.1.0 格式结果。",
            "",
            "### 报告使用说明",
            "",
            "本报告中的漏洞结论以对应证据和前提假设为边界。对于需要特定浏览器渲染、权限或网络条件的结论，应在交付复核阶段重新验证。",
            "",
        ]
    )
    return "\n".join(lines)


def write_executive_report(
    run_dir: Path,
    final_scan_result: str,
    *,
    run_record: dict[str, Any] | None = None,
    vulnerability_reports: list[dict[str, Any]] | None = None,
) -> None:
    path = run_dir / "penetration_test_report.md"
    with path.open("w", encoding="utf-8") as f:
        record = dict(run_record or {})
        record.setdefault("end_time", datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"))
        f.write(
            render_complete_report(
                final_scan_result,
                run_record=record,
                vulnerability_reports=vulnerability_reports,
            )
        )
        f.write("\n")
    logger.info("Saved final penetration test report to: %s", path)


def write_vulnerabilities(
    run_dir: Path,
    vulnerability_reports: list[dict[str, Any]],
    saved_vuln_ids: set[str],
) -> int:
    vuln_dir = run_dir / "vulnerabilities"
    vuln_dir.mkdir(exist_ok=True)

    new_reports = [r for r in vulnerability_reports if r["id"] not in saved_vuln_ids]

    for report in new_reports:
        _atomic_write_text(
            vuln_dir / f"{report['id']}.md",
            render_vulnerability_md(report),
        )
        saved_vuln_ids.add(report["id"])

    sorted_reports = sorted(
        vulnerability_reports,
        key=lambda r: (_SEVERITY_ORDER.get(r["severity"], 5), r["timestamp"]),
    )
    csv_path = run_dir / "vulnerabilities.csv"
    csv_buf = io.StringIO()
    fieldnames = ["id", "title", "severity", "timestamp", "file"]
    csv_writer = csv.DictWriter(csv_buf, fieldnames=fieldnames, lineterminator="\r\n")
    csv_writer.writeheader()
    for report in sorted_reports:
        csv_writer.writerow(
            {
                "id": report["id"],
                "title": report["title"],
                "severity": report["severity"].upper(),
                "timestamp": report["timestamp"],
                "file": f"vulnerabilities/{report['id']}.md",
            },
        )
    _atomic_write_text(csv_path, csv_buf.getvalue())

    _atomic_write_text(
        run_dir / "vulnerabilities.json",
        json.dumps(vulnerability_reports, ensure_ascii=False, indent=2, default=str),
    )

    if new_reports:
        logger.info(
            "Saved %d new vulnerability report(s) to: %s",
            len(new_reports),
            vuln_dir,
        )
    logger.info("Updated vulnerability index: %s", csv_path)
    return len(new_reports)


def _atomic_write_text(path: Path, payload: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as tmp:
        tmp.write(payload)
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def render_vulnerability_md(report: dict[str, Any]) -> str:  # noqa: PLR0912, PLR0915
    severity = _SEVERITY_LABELS_ZH.get(
        str(report.get("severity", "")).strip().lower(),
        str(report.get("severity", "未知")) or "未知",
    )
    lines: list[str] = [
        f"# {report.get('title', '未命名漏洞')}\n",
        f"**编号：** {report.get('id', 'unknown')}",
        f"**严重性：** {severity}",
        f"**发现时间：** {report.get('timestamp', 'unknown')}",
    ]

    dep_meta = report.get("dependency_metadata") or {}
    metadata: list[tuple[str, Any]] = [
        ("目标", report.get("target")),
        ("组件", dep_meta.get("package_name")),
        ("组件生态", dep_meta.get("package_ecosystem")),
        ("当前版本", dep_meta.get("installed_version")),
        ("修复版本", dep_meta.get("fixed_version")),
        ("引入来源", dep_meta.get("introduced_by")),
        ("依赖链", dep_meta.get("dependency_path")),
        ("清单文件", dep_meta.get("manifest_path")),
        ("可达性级别", dep_meta.get("reachability")),
        ("接口", report.get("endpoint")),
        ("请求方法", report.get("method")),
        ("CVE", report.get("cve")),
        ("CWE", report.get("cwe")),
    ]
    cvss = report.get("cvss")
    if cvss is not None:
        metadata.append(("CVSS", cvss))
    if report.get("fix_effort"):
        fix_effort = _FIX_EFFORT_LABELS_ZH.get(
            str(report["fix_effort"]).strip().lower(),
            str(report["fix_effort"]),
        )
        metadata.append(("修复成本", fix_effort))
    for label, value in metadata:
        if value:
            lines.append(f"**{label}：** {value}")

    lines.append("")
    lines.append("## 漏洞描述\n")
    lines.append(report.get("description") or "未提供漏洞描述。")
    lines.append("")

    if report.get("evidence"):
        lines.append("## 证据\n")
        lines.append(str(report["evidence"]))
        lines.append("")

    if dep_meta.get("reachability_evidence"):
        lines.append("## Reachability 证据\n")
        lines.append(str(dep_meta["reachability_evidence"]))
        lines.append("")

    if report.get("validation_evidence"):
        lines.append("## 运行时验证\n")
        lines.append(str(report["validation_evidence"]))
        lines.append("")

    if report.get("impact"):
        lines.append("## 影响\n")
        lines.append(str(report["impact"]))
        lines.append("")

    if report.get("technical_analysis"):
        lines.append("## 技术分析\n")
        lines.append(str(report["technical_analysis"]))
        lines.append("")

    if report.get("poc_description") or report.get("poc_script_code"):
        lines.append("## 概念验证\n")
        if report.get("poc_description"):
            lines.append(str(report["poc_description"]))
            lines.append("")
        if report.get("poc_script_code"):
            language, code = parse_fenced_code(str(report["poc_script_code"]))
            fence_lang = language or guess_language_name(code)
            fence = safe_fence(code)
            lines.append(f"{fence}{fence_lang}")
            lines.append(code)
            lines.append(fence)
            lines.append("")

    if report.get("code_locations"):
        lines.append("## 代码分析\n")
        for i, loc in enumerate(report["code_locations"]):
            file_ref = loc.get("file", "unknown")
            line_ref = ""
            if loc.get("start_line") is not None:
                if loc.get("end_line") and loc["end_line"] != loc["start_line"]:
                    line_ref = f"（第 {loc['start_line']}-{loc['end_line']} 行）"
                else:
                    line_ref = f"（第 {loc['start_line']} 行）"
            lines.append(f"**位置 {i + 1}：** `{file_ref}`{line_ref}")
            if loc.get("label"):
                lines.append(f"  {loc['label']}")
            if loc.get("snippet"):
                snippet = str(loc["snippet"])
                fence = safe_fence(snippet)
                lines.append(f"  {fence}")
                lines.extend(f"  {ln}" for ln in snippet.splitlines())
                lines.append(f"  {fence}")
            if loc.get("fix_before") or loc.get("fix_after"):
                lines.append("\n  **建议修复：**")
                lines.append("```diff")
                if loc.get("fix_before"):
                    lines.extend(f"- {ln}" for ln in str(loc["fix_before"]).splitlines())
                if loc.get("fix_after"):
                    lines.extend(f"+ {ln}" for ln in str(loc["fix_after"]).splitlines())
                lines.append("```")
            lines.append("")

    if report.get("remediation_steps"):
        lines.append("## 修复建议\n")
        lines.append(str(report["remediation_steps"]))
        lines.append("")

    if report.get("assumptions"):
        lines.append("## 前提假设\n")
        lines.append(str(report["assumptions"]))
        lines.append("")

    return "\n".join(lines)
