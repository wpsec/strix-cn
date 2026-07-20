"""Tests for strix.report.writer artifact helpers."""

from __future__ import annotations

import csv
import json
from typing import TYPE_CHECKING, Any

import pytest

from strix.report.writer import (
    read_run_record,
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
    assert "## 利用方式" in md
    assert "## 修复建议" in md
    assert "**接口：** /api/login" in md


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
    assert "# 安全渗透测试报告" in content
    assert "**生成时间：**" in content
    assert "Scan complete. No critical issues." in content
