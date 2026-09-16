"""Strix 扫描报告 artifact writer。"""

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

_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

_FENCE_RE = re.compile(r"^```([^\n`]*)\r?\n(.*?)\r?\n?```$", re.DOTALL)
_BACKTICK_RUN = re.compile(r"`+")


def csv_safe(value: object) -> str:
    """Return ``value`` as a CSV cell that cannot be interpreted as a formula."""
    text = str(value)
    if text.startswith(_CSV_FORMULA_PREFIXES):
        return "'" + text
    return text


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
    atomic_write_text(
        run_record_path(run_dir),
        json.dumps(run_record, ensure_ascii=False, indent=2, default=str),
    )


def write_executive_report(run_dir: Path, final_scan_result: str) -> None:
    """Write the upstream executive report, with localized headings."""
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
        atomic_write_text(
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
                "id": csv_safe(report["id"]),
                "title": csv_safe(report["title"]),
                "severity": csv_safe(report["severity"].upper()),
                "timestamp": csv_safe(report["timestamp"]),
                "file": csv_safe(f"vulnerabilities/{report['id']}.md"),
            },
        )
    atomic_write_text(csv_path, csv_buf.getvalue())

    atomic_write_text(
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


def atomic_write_text(path: Path, payload: str) -> None:
    """Write *payload* via a sibling temp file and an atomic rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        newline="",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as tmp:
        tmp.write(payload)
        tmp_path = Path(tmp.name)
    tmp_path.replace(path)


def _attack_chain_nodes(report: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Normalize an ordered attack path for a renderer without changing report data."""
    raw = report.get("attack_chain")

    nodes: list[tuple[str, str, str]] = []
    if isinstance(raw, list):
        for index, item in enumerate(raw, 1):
            if isinstance(item, str):
                label = " ".join(item.split())
                if label:
                    nodes.append((f"步骤 {index}", label, ""))
                continue
            if not isinstance(item, dict):
                continue
            kind = str(item.get("type") or item.get("kind") or f"步骤 {index}").strip()
            label = str(
                item.get("label")
                or item.get("name")
                or item.get("step")
                or item.get("from")
                or item.get("to")
                or ""
            ).strip()
            if not label:
                endpoint = str(item.get("endpoint") or item.get("path") or "").strip()
                method = str(item.get("method") or "").strip()
                label = f"{method} {endpoint}".strip()
            details: list[str] = []
            for key in (
                "method",
                "action",
                "detail",
                "observation",
                "result",
                "evidence",
                "hypothesis",
            ):
                value = item.get(key)
                if value and str(value).strip() != label:
                    details.append(" ".join(str(value).split()))
            if not label and details:
                label, *details = details
            if label:
                nodes.append((kind, " ".join(label.split()), "；".join(details)))

    if not nodes:
        endpoint = str(report.get("endpoint") or "").strip()
        method = str(report.get("method") or "").strip()
        if endpoint:
            nodes.append(("入口", f"{method} {endpoint}".strip(), ""))
    return nodes


_CHAIN_STAGE_LABELS = {
    "entry_point": "入口点",
    "entry": "入口点",
    "入口点": "入口点",
    "trust_boundary": "信任边界",
    "信任边界": "信任边界",
    "input_tampering": "输入篡改",
    "输入篡改": "输入篡改",
    "aggregation_point": "汇聚点",
    "aggregation": "汇聚点",
    "sink": "汇聚点",
    "汇聚点": "汇聚点",
    "verification": "验证确认",
    "validation": "验证确认",
    "verification_confirmation": "验证确认",
    "验证确认": "验证确认",
    "blocked": "阻断点",
    "blocking_point": "阻断点",
    "阻断点": "阻断点",
}
_CHAIN_STAGE_ORDER = ("入口点", "信任边界", "输入篡改", "汇聚点", "验证确认", "阻断点")
_STRUCTURED_CHAIN_KEYS = frozenset(
    {
        "source",
        "route",
        "framework",
        "child_apps",
        "fallback",
        "redirect_chain",
        "chunks",
        "sensitive_route",
        "sensitive_function",
        "backend_api",
        "comparison_tests",
        "attempt",
        "block_reason",
    }
)


def _chain_stage(value: Any) -> str | None:
    normalized = str(value or "").strip().lower().replace("-", "_").replace(" ", "_")
    return _CHAIN_STAGE_LABELS.get(normalized)


def _has_structured_attack_chain(raw: Any) -> bool:
    if not isinstance(raw, list):
        return False
    for item in raw:
        if not isinstance(item, dict):
            continue
        if _chain_stage(item.get("type") or item.get("kind")):
            return True
        if _STRUCTURED_CHAIN_KEYS.intersection(item):
            return True
    return False


def _chain_value(item: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = item.get(key)
        if value is None:
            continue
        if isinstance(value, str | list | dict) and not value:
            continue
        return value
    return None


def _chain_text(value: Any, *, separator: str = " / ") -> str:
    if isinstance(value, list | tuple):
        return separator.join(
            _chain_text(item, separator=separator) for item in value if item is not None
        )
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)
    return str(value).strip()


def _append_chain_field(lines: list[str], label: str, value: Any) -> None:
    if value is None:
        return
    text = _chain_text(value)
    if not text:
        return
    if "\n" not in text:
        lines.append(f" {label}: {text}")
        return
    lines.append(f" {label}:")
    lines.extend(f"   {line}" for line in text.splitlines())


def _append_chain_tests(lines: list[str], value: Any) -> None:
    if not isinstance(value, list) or not value:
        return
    lines.append(" 对照测试:")
    for test in value:
        if isinstance(test, str):
            lines.append(f"   - {test}")
            continue
        if not isinstance(test, dict):
            continue
        kind = _chain_text(_chain_value(test, "kind", "type", "label", "name")) or "测试"
        parameter = _chain_text(_chain_value(test, "parameter", "field", "param"))
        value_text = _chain_text(_chain_value(test, "value", "input", "payload"))
        result = _chain_text(_chain_value(test, "result", "response", "observed", "outcome"))
        evidence = _chain_text(_chain_value(test, "evidence", "evidence_ref", "request_id"))
        subject = " ".join(part for part in (parameter, "=", value_text) if part)
        detail = f"{kind} {subject}".strip()
        if result:
            detail += f" → {result}"
        if evidence:
            detail += f"  证据: {evidence}"
        lines.append(f"   - {detail}")


def _append_chain_items(
    lines: list[str],
    value: Any,
    *,
    fallback: bool = False,
    has_following: bool = False,
) -> None:
    if not isinstance(value, list) or not value:
        return
    for index, child in enumerate(value):
        if isinstance(child, str):
            path = child.strip()
            function = ""
            source = ""
        elif isinstance(child, dict):
            path = _chain_text(_chain_value(child, "path", "prefix", "route", "name", "id"))
            function = _chain_text(
                _chain_value(child, "function", "feature", "description", "label")
            )
            source = _chain_text(_chain_value(child, "source", "code_source", "location"))
        else:
            continue
        if not path and not function:
            continue
        connector = "└──" if index == len(value) - 1 and not has_following else "├──"
        if fallback:
            connector = "└──"
        detail = "   ".join(part for part in (path, function) if part)
        if source:
            detail += f"   来源: {source}"
        lines.append(f"   {connector} {detail}")


def _append_chain_chunks(lines: list[str], value: Any) -> None:
    if not isinstance(value, list) or not value:
        return
    for index, chunk in enumerate(value):
        if isinstance(chunk, str):
            chunk_id, filename, source = chunk, "", ""
        elif isinstance(chunk, dict):
            chunk_id = _chain_text(_chain_value(chunk, "id", "chunk_id", "name"))
            filename = _chain_text(_chain_value(chunk, "file", "filename", "chunk_file", "path"))
            source = _chain_text(_chain_value(chunk, "source", "location", "code_source"))
        else:
            continue
        if not chunk_id and not filename:
            continue
        connector = "└──" if index == len(value) - 1 else "├──"
        target = " → ".join(part for part in (chunk_id, filename) if part)
        if source:
            target += f"   来源: {source}"
        lines.append(f"   {connector} {target}")


def _chain_evidence(item: dict[str, Any]) -> Any:
    evidence = _chain_value(item, "evidence", "evidence_ref")
    if evidence is not None:
        return evidence
    request_ids = item.get("http_exchange_ids")
    if isinstance(request_ids, list):
        return " / ".join(f"req {request_id}" for request_id in request_ids)
    if isinstance(request_ids, str) and request_ids.strip():
        return f"req {request_ids.strip()}"
    return None


def _structured_attack_chain(  # noqa: PLR0912, PLR0915
    report: dict[str, Any],
) -> list[str]:
    raw = report.get("attack_chain")
    if not isinstance(raw, list):
        return []

    grouped: dict[str, list[dict[str, Any]]] = {stage: [] for stage in _CHAIN_STAGE_ORDER}
    for item in raw:
        if not isinstance(item, dict):
            continue
        stage = _chain_stage(item.get("type") or item.get("kind"))
        if stage:
            grouped[stage].append(item)

    lines = ["## 攻击链路\n", "```text", "攻击链路视图"]
    for stage_index, stage in enumerate(_CHAIN_STAGE_ORDER):
        is_placeholder = not grouped[stage]
        stage_items = grouped[stage] or [{"label": "待补充"}]
        for item_index, item in enumerate(stage_items):
            if stage_index or item_index:
                lines.extend(["    |", "    v"])
            title = _chain_text(
                _chain_value(item, "title", "label", "name", "step", "action")
            ) or "待补充"
            lines.append(f"[{stage}] {title}")

            _append_chain_field(lines, "来源", _chain_value(item, "source", "origin"))
            _append_chain_field(
                lines,
                "接口/路由",
                _chain_value(item, "route", "interface", "endpoint", "path"),
            )
            parameters = _chain_value(item, "parameters", "parameter", "params")
            if stage != "汇聚点" or not isinstance(parameters, list):
                _append_chain_field(lines, "参数", parameters)

            if stage == "信任边界":
                _append_chain_field(lines, "框架", _chain_value(item, "framework"))
                _append_chain_field(
                    lines,
                    "子应用清单来源",
                    _chain_value(
                        item,
                        "child_apps_source",
                        "app_manifest_source",
                        "manifest_source",
                    ),
                )
                fallback = _chain_value(item, "fallback", "catch_all", "fallback_route")
                child_apps = _chain_value(item, "child_apps", "children")
                _append_chain_items(lines, child_apps, has_following=bool(fallback))
                if isinstance(fallback, dict):
                    _append_chain_items(lines, [fallback], fallback=True)
                elif fallback:
                    lines.append(f"   └── {_chain_text(fallback)}")

            if stage == "输入篡改":
                redirect_chain = _chain_value(item, "redirect_chain", "jump_chain")
                _append_chain_field(lines, "跳转链", redirect_chain)
                _append_chain_field(
                    lines,
                    "敏感路由",
                    _chain_value(item, "sensitive_route", "sensitive_routes", "sensitive_endpoint"),
                )
                _append_chain_field(
                    lines,
                    "路由声明来源",
                    _chain_value(item, "route_declaration_source", "route_source"),
                )
                _append_chain_field(
                    lines,
                    "动态加载清单来源",
                    _chain_value(item, "dynamic_load_source", "dynamic_load_manifest_source"),
                )
                _append_chain_chunks(lines, _chain_value(item, "chunks", "dynamic_chunks"))
                _append_chain_field(lines, "敏感函数", _chain_value(item, "sensitive_function"))
                _append_chain_field(
                    lines,
                    "函数定义来源",
                    _chain_value(item, "function_definition_source", "function_source"),
                )
                _append_chain_field(lines, "参数来源", _chain_value(item, "parameter_source"))
                _append_chain_field(lines, "编码/转义", _chain_value(item, "encoding", "escaping"))

            if stage == "汇聚点":
                _append_chain_field(lines, "后端接口", _chain_value(item, "backend_api", "api"))
                _append_chain_field(lines, "方法", _chain_value(item, "method"))
                params = _chain_value(
                    item,
                    "parameters_detail",
                    "parameter_details",
                    "params_detail",
                    "parameters",
                )
                if isinstance(params, list):
                    lines.append(" 参数:")
                    for param in params:
                        if isinstance(param, str):
                            lines.append(f"   - {param}")
                        elif isinstance(param, dict):
                            name = _chain_text(_chain_value(param, "name", "parameter", "key"))
                            position = _chain_text(_chain_value(param, "position", "in"))
                            encoding = _chain_text(_chain_value(param, "encoding", "format"))
                            source = _chain_text(_chain_value(param, "source", "location"))
                            parts = [name]
                            if position:
                                parts.append(f"位置: {position}")
                            if encoding:
                                parts.append(f"编码: {encoding}")
                            if source:
                                parts.append(f"来源: {source}")
                            lines.append(f"   - {'  '.join(part for part in parts if part)}")
                _append_chain_field(lines, "认证", _chain_value(item, "authentication", "auth"))
                _append_chain_field(lines, "说明", _chain_value(item, "description", "detail"))

            if stage == "验证确认":
                _append_chain_tests(
                    lines,
                    _chain_value(
                        item,
                        "comparison_tests",
                        "comparison",
                        "comparisons",
                        "tests",
                        "control_tests",
                    ),
                )
                _append_chain_field(lines, "变体", _chain_value(item, "variants", "variant"))
                _append_chain_field(lines, "结论", _chain_value(item, "conclusion"))
                _append_chain_field(lines, "排除项", _chain_value(item, "exclusions", "excluded"))
                if is_placeholder:
                    lines.extend(
                        [
                            " 对照测试: 待补充",
                            " 变体: 待补充",
                            " 结论: 待补充",
                            " 排除项: 待补充",
                        ]
                    )

            if stage == "阻断点":
                _append_chain_field(
                    lines,
                    "尝试手法",
                    _chain_value(item, "attempt", "technique", "payload"),
                )
                _append_chain_field(
                    lines,
                    "响应特征",
                    _chain_value(item, "response_features", "response_feature", "response"),
                )
                _append_chain_field(
                    lines,
                    "阻断原因",
                    _chain_value(item, "block_reason", "blocking_reason", "reason"),
                )
                _append_chain_field(lines, "本轮结果", _chain_value(item, "round_result", "result"))
                if is_placeholder:
                    lines.extend(
                        [
                            " 尝试手法: 待补充",
                            " 响应特征: 待补充",
                            " 阻断原因: 待补充",
                            " 本轮结果: 待补充",
                        ]
                    )

            # Keep legacy agent-authored observations visible when the new
            # structured fields were not populated for a node.
            _append_chain_field(
                lines,
                "说明",
                _chain_value(item, "observation", "observed", "observed_result", "hypothesis"),
            )
            _append_chain_field(lines, "证据", _chain_evidence(item))

    lines.extend(["```", ""])
    return lines


def render_attack_chain(report: dict[str, Any]) -> list[str]:
    """Render a Burp URL-view-like vertical path, never as a markdown table."""
    if _has_structured_attack_chain(report.get("attack_chain")):
        return _structured_attack_chain(report)
    nodes = _attack_chain_nodes(report)
    if not nodes:
        return []
    lines = ["## 攻击链路\n", "```text", "攻击链路视图"]
    for index, (kind, label, detail) in enumerate(nodes):
        if index:
            lines.extend(["    |", "    v"])
        lines.append(f"[{kind}] {label}")
        if detail:
            lines.append(f"  {detail}")
    lines.extend(["```", ""])
    return lines


def _http_materials(report: dict[str, Any]) -> list[tuple[str | None, str | None, str | None]]:
    """Return raw HTTP request/response pairs without combining or redacting them."""
    materials: list[tuple[str | None, str | None, str | None]] = []
    exchanges = report.get("http_exchanges")
    if isinstance(exchanges, list):
        for exchange in exchanges:
            if not isinstance(exchange, dict):
                continue
            request = exchange.get("request")
            response = exchange.get("response")
            if not isinstance(request, str):
                request = None
            if not isinstance(response, str):
                response = None
            request_id = exchange.get("request_id") or exchange.get("evidence")
            materials.append(
                (str(request_id) if request_id is not None else None, request, response)
            )

    explicit_request = report.get("http_request") or report.get("request")
    explicit_response = (
        report.get("http_response")
        or report.get("burp_response")
        or report.get("response")
    )
    # ``burp_request`` is intentionally left on the legacy request-only
    # renderer. It becomes the request half of this section only when a
    # response (or an explicit HTTP request field) is also present.
    request = explicit_request
    if not request and explicit_response:
        request = report.get("burp_request")
    response = explicit_response
    if isinstance(request, str) or isinstance(response, str):
        materials.insert(
            0,
            (
                None,
                request if isinstance(request, str) else None,
                response if isinstance(response, str) else None,
            ),
        )
    return [item for item in materials if item[1] or item[2]]


def render_http_materials(report: dict[str, Any]) -> list[str]:
    """Render request and response as independent, lossless code blocks."""
    materials = _http_materials(report)
    if not materials:
        return []
    lines = ["## HTTP 证据\n"]
    for index, (request_id, request, response) in enumerate(materials, 1):
        if len(materials) > 1:
            title = f"### Exchange {request_id or index}"
            lines.extend([title, ""])
        if request:
            fence = safe_fence(request)
            lines.extend(["### Request", "", f"{fence}http", request, fence, ""])
        if response:
            fence = safe_fence(response)
            lines.extend(["### Response", "", f"{fence}http", response, fence, ""])
    return lines


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
        ("接口", report.get("endpoint")),
        ("请求方法", report.get("method")),
        ("CVE", report.get("cve")),
        ("CWE", report.get("cwe")),
    ]
    cvss = report.get("cvss")
    if cvss is not None:
        metadata.append(("CVSS", cvss))
    advisory_cvss = dep_meta.get("advisory_cvss")
    if advisory_cvss is not None and advisory_cvss != cvss:
        metadata.append(("公告 CVSS", advisory_cvss))
    if dep_meta.get("contextual_cvss_vector"):
        metadata.append(("情境化 CVSS 向量", dep_meta["contextual_cvss_vector"]))
    if report.get("confidence"):
        metadata.append(("置信度", str(report["confidence"]).title()))
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
    lines.append(report.get("description") or "报告未提供漏洞描述。")
    lines.append("")

    lines.extend(render_attack_chain(report))

    if report.get("evidence"):
        lines.append("## 证据\n")
        lines.append(str(report["evidence"]))
        lines.append("")

    if report.get("impact"):
        lines.append("## 影响\n")
        lines.append(str(report["impact"]))
        lines.append("")

    if report.get("counterevidence"):
        lines.append("## 反证\n")
        lines.append(str(report["counterevidence"]))
        lines.append("")

    if report.get("confidence_rationale"):
        lines.append("## 置信度依据\n")
        lines.append(str(report["confidence_rationale"]))
        lines.append("")

    if report.get("severity_change_conditions"):
        lines.append("## 严重度变化条件\n")
        lines.append(str(report["severity_change_conditions"]))
        lines.append("")

    if report.get("technical_analysis"):
        lines.append("## 技术分析\n")
        lines.append(str(report["technical_analysis"]))
        lines.append("")

    if dep_meta.get("contextual_cvss_reasoning"):
        lines.append("## 情境化 CVSS\n")
        lines.append(str(dep_meta["contextual_cvss_reasoning"]))
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

    http_materials = render_http_materials(report)
    if http_materials:
        lines.extend(http_materials)
    elif isinstance(report.get("burp_request"), str) and report["burp_request"].strip():
        burp_request = report["burp_request"]
        request = burp_request
        fence = safe_fence(request)
        lines.append("## Burp 复现数据包\n")
        lines.append(f"{fence}http")
        lines.append(request)
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

    if report.get("fix_verification"):
        lines.append("## 修复验证\n")
        lines.append(str(report["fix_verification"]))
        lines.append("")

    if report.get("assumptions"):
        lines.append("## 前提假设\n")
        lines.append(str(report["assumptions"]))
        lines.append("")

    lines.extend(render_update_history(report.get("update_history")))
    return "\n".join(lines)


def render_update_history(history: Any) -> list[str]:
    """Render the audit trail of every revision a report has received."""
    if not isinstance(history, list):
        return []
    entries: list[dict[str, Any]] = [
        cast("dict[str, Any]", entry) for entry in history if isinstance(entry, dict)
    ]
    if not entries:
        return []

    lines = ["## 更新历史\n"]
    for entry in entries:
        author = str(entry.get("agent_name") or entry.get("agent_id") or "代理")
        raw_fields = entry.get("fields")
        fields: list[Any] = raw_fields if isinstance(raw_fields, list) else []
        changed = "、".join(str(field) for field in fields)
        timestamp = str(entry.get("timestamp") or "未知")
        lines.append(f"**{timestamp}** — {author} 更新：{changed}")
        raw_dropped = entry.get("dropped_fields")
        if isinstance(raw_dropped, list) and raw_dropped:
            dropped = "、".join(str(field) for field in raw_dropped)
            lines.append(f"  因新证据被替换：{dropped}")
        for key, label in (
            ("previous_severity", "严重性"),
            ("previous_cvss", "CVSS"),
            ("previous_confidence", "置信度"),
        ):
            if entry.get(key) is not None:
                lines.append(f"  原{label}：{entry[key]}")
        if entry.get("reason"):
            lines.append(f"  原因：{entry['reason']}")
        lines.append("")
    return lines
