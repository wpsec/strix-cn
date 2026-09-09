"""Structured discovery and reproduction evidence for vulnerability reports."""

from __future__ import annotations

from typing import Any


DISCOVERY_TRACE_FIELDS = (
    "stage",
    "source",
    "location",
    "observation",
    "inference",
    "evidence",
)
ENDPOINT_MATRIX_FIELDS = (
    "method",
    "path",
    "purpose",
    "baseline",
    "variant",
    "result",
    "evidence",
)
REPRODUCTION_REQUEST_FIELDS = (
    "name",
    "purpose",
    "request",
    "expected_response",
    "observed_response",
    "notes",
)
STRUCTURED_EVIDENCE_FIELDS = (
    "discovery_trace",
    "endpoint_matrix",
    "reproduction_requests",
)

_ROW_FIELDS = {
    "discovery_trace": DISCOVERY_TRACE_FIELDS,
    "endpoint_matrix": ENDPOINT_MATRIX_FIELDS,
    "reproduction_requests": REPRODUCTION_REQUEST_FIELDS,
}
_MAX_ROWS = 100
_MAX_CELL_LENGTH = 12_000


def normalize_evidence_rows(
    value: Any,
    field_name: str,
) -> tuple[list[dict[str, str]] | None, list[str]]:
    """Keep structured evidence bounded and JSON-compatible.

    The report tool receives model-authored dictionaries. Restricting the stored
    shape here keeps renderers deterministic and prevents a large nested object
    from turning a finding into an unbounded artifact.
    """
    if value is None:
        return None, []
    if not isinstance(value, list):
        return None, [f"{field_name} 必须是对象数组"]

    fields = _ROW_FIELDS.get(field_name)
    if fields is None:
        return None, [f"不支持的结构化证据字段：{field_name}"]

    rows: list[dict[str, str]] = []
    errors: list[str] = []
    if len(value) > _MAX_ROWS:
        errors.append(f"{field_name} 最多允许 {_MAX_ROWS} 条记录")

    for index, item in enumerate(value[:_MAX_ROWS]):
        if not isinstance(item, dict):
            errors.append(f"{field_name}[{index}] 必须是对象")
            continue
        row: dict[str, str] = {}
        for key in fields:
            raw = item.get(key)
            if raw in (None, ""):
                continue
            if isinstance(raw, (dict, list)):
                errors.append(f"{field_name}[{index}].{key} 必须是字符串")
                continue
            text = str(raw).strip()
            if text:
                row[key] = text[:_MAX_CELL_LENGTH]
        if row:
            rows.append(row)

    return rows or None, errors


def _inline(value: Any, fallback: str = "未提供") -> str:
    text = str(value or "").strip() or fallback
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", " ")
    )


def _fence(value: str) -> str:
    longest = 0
    run = ""
    for char in value:
        if char == "`":
            run += char
            longest = max(longest, len(run))
        else:
            run = ""
    return "`" * max(3, longest + 1)


def _rows(report: dict[str, Any], field_name: str) -> list[dict[str, Any]]:
    raw = report.get(field_name)
    if not isinstance(raw, list):
        return []
    return [row for row in raw if isinstance(row, dict)]


def render_discovery_trace(report: dict[str, Any]) -> list[str]:
    rows = _rows(report, "discovery_trace")
    if not rows:
        return ["未提供结构化发现过程。"]

    lines = [
        "| 阶段 | 来源 | 位置 | 观察 | 推断 | 证据 |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                _inline(row.get(field))
                for field in DISCOVERY_TRACE_FIELDS
            )
            + " |"
        )
    return lines


def render_endpoint_matrix(report: dict[str, Any]) -> list[str]:
    rows = _rows(report, "endpoint_matrix")
    if not rows:
        return ["未提供接口验证矩阵。"]

    lines = [
        "| 方法 | 路径 | 用途 | 基线结果 | 验证变体 | 结果 | 证据 |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        lines.append(
            "| "
            + " | ".join(_inline(row.get(field)) for field in ENDPOINT_MATRIX_FIELDS)
            + " |"
        )
    return lines


def render_reproduction_requests(report: dict[str, Any]) -> list[str]:
    rows = _rows(report, "reproduction_requests")
    if not rows and report.get("request"):
        rows = [
            {
                "name": "主验证请求",
                "purpose": "报告中的主验证请求",
                "request": report.get("request"),
                "observed_response": report.get("response"),
            }
        ]
    if not rows:
        return ["未提供可直接复制到 Burp Repeater 的 HTTP 请求。"]

    lines: list[str] = []
    for index, row in enumerate(rows, start=1):
        lines.extend(
            [
                f"### {index}. {_inline(row.get('name'), '验证请求')}",
                "",
                f"用途：{_inline(row.get('purpose'))}",
                "",
            ]
        )
        request = str(row.get("request") or "").strip()
        if request:
            fence = _fence(request)
            lines.extend([f"{fence}http", request, fence, ""])
        else:
            lines.extend(["请求：未提供。", ""])
        expected = row.get("expected_response")
        if expected:
            lines.extend(["预期响应：", "", str(expected).strip(), ""])
        observed = row.get("observed_response")
        if observed:
            lines.extend(["实际响应摘要：", "", str(observed).strip(), ""])
        notes = row.get("notes")
        if notes:
            lines.extend([f"说明：{_inline(notes)}", ""])
    return lines[:-1] if lines and lines[-1] == "" else lines


def render_structured_evidence_markdown(report: dict[str, Any]) -> list[str]:
    """Render the same evidence blocks for Markdown and HTML report consumers."""
    return [
        "### 发现入口与推理链",
        "",
        *render_discovery_trace(report),
        "",
        "### 接口验证矩阵",
        "",
        *render_endpoint_matrix(report),
        "",
        "### Burp Repeater 复现请求",
        "",
        *render_reproduction_requests(report),
    ]
