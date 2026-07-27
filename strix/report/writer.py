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

_FENCE_RE = re.compile(r"^```([^\n`]*)\r?\n(.*?)\r?\n?```$", re.DOTALL)
_BACKTICK_RUN = re.compile(r"`+")


def safe_fence(content: str) -> str:
    """Return a backtick fence that ``content`` cannot break out of.

    Per CommonMark a fenced code block is closed only by a run of backticks at
    least as long as the opening fence. LLM-authored, attacker-influenced values
    (PoC scripts, code snippets) may contain their own ``` runs, so we open with
    a fence one backtick longer than the longest run inside ``content`` (never
    fewer than three). Everything in ``content`` then renders verbatim.
    """
    longest = max((len(m.group()) for m in _BACKTICK_RUN.finditer(content)), default=0)
    return "`" * max(3, longest + 1)


def parse_fenced_code(raw: str) -> tuple[str | None, str]:
    """Split an optionally fenced code string into ``(language, code)``.

    Agent-generated code fields (e.g. ``poc_script_code``) are stored wrapped in
    a markdown fence carrying the language, like ``` ```python\n...\n``` ```.
    Return the fence's language tag and the inner code, or ``(None, raw)`` when
    the value isn't fenced.
    """
    match = _FENCE_RE.match(raw.strip())
    if not match:
        return None, raw
    info = match.group(1).strip()
    language = info.split()[0] if info else None
    return (language or None), match.group(2)


def resolve_lexer(language: str | None, code: str) -> Lexer:
    """Pick a pygments lexer for ``code``.

    Prefer the explicit fence ``language`` when it names a known lexer, otherwise
    auto-detect from the source. Fall back to Python when detection is
    inconclusive, since legacy (unfenced) PoC scripts are Python.
    """
    if language:
        try:
            return get_lexer_by_name(language)
        except ClassNotFound:
            pass
    try:
        lexer = guess_lexer(code)
    except ClassNotFound:
        return cast("Lexer", PythonLexer())
    # ``guess_lexer`` returns the plain-text lexer when it can't detect anything.
    if isinstance(lexer, TextLexer):
        return cast("Lexer", PythonLexer())
    return lexer


def guess_language_name(code: str) -> str:
    """Return a markdown fence tag for ``code``, defaulting to ``python`` when
    auto-detection is inconclusive."""
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


def write_executive_report(run_dir: Path, final_scan_result: str) -> None:
    path = run_dir / "penetration_test_report.md"
    with path.open("w", encoding="utf-8") as f:
        f.write("# 安全渗透测试报告\n\n")
        f.write(f"**生成时间：** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        f.write(f"{final_scan_result}\n")
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

    if report.get("impact"):
        lines.append("## 影响\n")
        lines.append(str(report["impact"]))
        lines.append("")

    if report.get("technical_analysis"):
        lines.append("## 技术分析\n")
        lines.append(str(report["technical_analysis"]))
        lines.append("")

    if report.get("poc_description") or report.get("poc_script_code"):
        lines.append("## Proof of Concept\n")
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
