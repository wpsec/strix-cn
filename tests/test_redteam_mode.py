"""Regression tests for the red-team validation policy and artifacts."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
from agents.tool import FunctionTool

from strix.agents import factory
from strix.agents.prompt import render_system_prompt
from strix.redteam.attack_chain import build_attack_chain
from strix.redteam.depth import RedTeamDepthController, RedTeamDepthError
from strix.redteam.policy import (
    assess_action_risk,
    classify_test_priority,
    is_attack_chain_eligible,
    should_ignore,
)
from strix.report.html_report import render_html_report
from strix.report.state import ReportState
from strix.report.writer import (
    render_complete_report,
    render_vulnerability_md,
    write_vulnerabilities,
)
from strix.tools.mcp import agent_tools as mcp_agent_tools
from strix.tools.proxy import tools as proxy_tools
from strix.tools.reporting.tool import _calculate_cvss4


@pytest.mark.parametrize(
    ("vulnerability_type", "expected_ignore"),
    [
        ("RCE", False),
        ("writable_file_upload", True),
        ("堆叠查询 SQL 注入", False),
        ("反序列化", False),
        ("可窃取元数据的 SSRF", False),
        ("存储型 XSS", True),
        ("CSRF", True),
        ("缺少安全头", True),
        ("unknown finding", True),
    ],
)
def test_redteam_chain_projection_keeps_unknown_and_low_value_out(
    vulnerability_type: str, expected_ignore: bool
) -> None:
    assert should_ignore(vulnerability_type, mode="redteam") is expected_ignore


def test_privilege_category_requires_concrete_impact() -> None:
    assert should_ignore("权限获取", mode="redteam", impact="可能影响权限")
    assert not should_ignore("权限获取", mode="redteam", impact="验证得到未授权身份: id 输出")


@pytest.mark.parametrize(
    ("vulnerability_type", "impact", "expected_ignore"),
    [
        ("认证绕过", "验证获得 authenticated session", False),
        ("IDOR/BOLA", "验证越权读取单个测试对象", False),
        ("存储桶未授权访问", "验证未授权读取一个测试对象", False),
        ("存储桶可写", "验证未授权写入随机 marker 并已清理", False),
        ("高影响业务逻辑", "验证未授权业务操作被执行", False),
        ("凭据材料可访问", "响应返回 password 字段并完成测试身份验证", False),
        ("凭据材料可访问", "可能存在 token 文件", True),
        ("存储桶未授权访问", "发现 bucket object", True),
        ("IDOR/BOLA", "potential unauthorized access", True),
    ],
)
def test_redteam_expanded_scope_requires_concrete_safe_impact(
    vulnerability_type: str, impact: str, expected_ignore: bool
) -> None:
    assert should_ignore(vulnerability_type, mode="redteam", impact=impact) is expected_ignore


def test_normal_mode_preserves_existing_report_selection() -> None:
    assert should_ignore("未知类型", mode="normal") is False


@pytest.mark.parametrize(
    ("vulnerability_type", "impact", "priority"),
    [
        ("证书无效", None, "low"),
        ("验证码绕过", "普通表单提交被接受", "low"),
        ("验证码绕过", "绕过后成功登录后台", "high"),
        ("未知业务问题", None, "normal"),
        ("认证绕过", "成功登录后台并访问管理接口", "high"),
    ],
)
def test_redteam_priority_guides_without_becoming_a_gate(
    vulnerability_type: str, impact: str | None, priority: str
) -> None:
    result = classify_test_priority(vulnerability_type, impact=impact)
    assert result["priority"] == priority


def test_redteam_action_policy_is_independent_of_finding_type() -> None:
    assert assess_action_risk("POST", "https://target.test/api/unknown", mode="redteam")[
        "allowed"
    ] is True
    assert assess_action_risk("DELETE", "https://target.test/api/item", mode="redteam")[
        "allowed"
    ] is False


def test_redteam_action_policy_checks_operation_semantics_without_blocking_host_names() -> None:
    assert assess_action_risk(
        "POST", "https://delete.example/api/item", mode="redteam"
    )["allowed"] is True
    assert assess_action_risk(
        "POST",
        "https://target.test/api/item",
        body='{"operation":"delete","id":"test-object"}',
        mode="redteam",
    )["allowed"] is False
    assert assess_action_risk(
        "POST",
        "https://target.test/api/item",
        body='{"operation":"delete","dry_run":true}',
        mode="redteam",
    )["allowed"] is True


def test_high_impact_unknown_and_natural_language_findings_can_enter_chain() -> None:
    assert is_attack_chain_eligible(
        "unknown finding", severity="high", impact="返回其他租户账单"
    )
    assert is_attack_chain_eligible(
        "IDOR", severity="high", impact="访问管理员接口"
    )


def test_redteam_skip_only_accepts_low_priority_checks() -> None:
    state = ReportState(run_name="redteam-skip-policy")
    state.set_scan_config({"mode": "redteam", "targets": [], "scan_mode": "quick"})

    with pytest.raises(ValueError, match="只有低优先级检查"):
        state.record_redteam_skip(
            vulnerability_type="认证绕过",
            reason="暂缓",
        )


def test_mcp_scope_checks_nested_urls_and_requires_scope_for_target_urls() -> None:
    assert mcp_agent_tools._mcp_scope_error(
        {"caido_scope_allowlist": ["target.test"]},
        {"request": {"url": "https://evil.test/api"}},
    )
    assert mcp_agent_tools._mcp_scope_error(
        {},
        {"request": {"url": "https://target.test/api"}},
    )
    assert mcp_agent_tools._mcp_scope_error(
        {"caido_scope_allowlist": ["target.test"]},
        {"path": "./fixture.json"},
    ) is None


def test_attack_chain_uses_structured_http_evidence_and_explicit_edges() -> None:
    reports = [
        {
            "id": "vuln-0001",
            "title": "Verified RCE",
            "severity": "high",
            "vulnerability_type": "rce",
            "evidence": "identity proof",
            "reproduction_requests": [
                {
                    "request": "POST /probe HTTP/1.1",
                    "observed_response": "uid=1000(app)",
                }
            ],
        },
        {
            "id": "vuln-0002",
            "title": "Verified admin access",
            "severity": "high",
            "vulnerability_type": "authentication bypass",
            "impact": "访问管理员接口",
            "evidence": "admin response",
            "attack_chain_parent_id": "vuln-0001",
            "reproduction_requests": [
                {
                    "request": "GET /admin HTTP/1.1",
                    "observed_response": "HTTP/1.1 200 OK",
                }
            ],
        },
    ]

    chain = build_attack_chain(reports)
    assert chain["nodes"][0]["request"] == "POST /probe HTTP/1.1"
    assert chain["nodes"][0]["response"] == "uid=1000(app)"
    assert chain["edges"] == [
        {
            "source": "vuln-0001",
            "target": "vuln-0002",
            "relationship": "prerequisite",
        }
    ]


def test_hydrated_backfilled_evidence_rewrites_legacy_markdown(tmp_path: Any) -> None:
    run_dir = tmp_path / "run"
    vuln_dir = run_dir / "vulnerabilities"
    vuln_dir.mkdir(parents=True)
    report = {
        "id": "vuln-0001",
        "title": "Legacy finding",
        "severity": "high",
        "timestamp": "2026-01-01T00:00:00Z",
        "reproduction_requests": [
            {
                "request": "POST /legacy HTTP/1.1",
                "observed_response": "HTTP/1.1 200 OK",
            }
        ],
    }
    (run_dir / "vulnerabilities.json").write_text(
        json.dumps([report]), encoding="utf-8"
    )
    (vuln_dir / "vuln-0001.md").write_text("stale report", encoding="utf-8")

    state = ReportState(run_name="legacy-hydration")
    state._run_dir = run_dir
    state.hydrate_from_run_dir()
    assert "vuln-0001" not in state._saved_vuln_ids

    write_vulnerabilities(run_dir, state.vulnerability_reports, state._saved_vuln_ids)
    assert "POST /legacy HTTP/1.1" in (vuln_dir / "vuln-0001.md").read_text(
        encoding="utf-8"
    )


def test_resuming_stale_redteam_policy_is_rejected() -> None:
    state = ReportState(run_name="stale-redteam")
    state._hydrated_from_disk = True
    state.run_record.update({"mode": "redteam", "policy_version": "redteam-v1"})

    with pytest.raises(ValueError, match="策略版本不受支持"):
        state.set_scan_config({"mode": "redteam", "targets": []})


def test_cvss4_vector_is_calculated_without_relabeling_cvss31() -> None:
    score, severity = _calculate_cvss4(
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    )
    assert score == 9.3
    assert severity == "critical"


def test_depth_controller_records_complete_credential_proofs() -> None:
    identity = RedTeamDepthController.identity_command("whoami")
    assert identity.proof == "whoami"

    marker = RedTeamDepthController.upload_marker("authorized-target")
    assert marker.cleanup_required is True
    assert marker.proof.startswith("redteam-proof-")

    query = RedTeamDepthController.sql_probe(
        "authorized-target", "SELECT 1; SELECT current_user"
    )
    assert query.proof == "SELECT 1; SELECT current_user"

    with pytest.raises(RedTeamDepthError):
        RedTeamDepthController.identity_command("sh -c whoami")
    with pytest.raises(RedTeamDepthError):
        RedTeamDepthController.sql_probe("authorized-target", "SELECT 1; DROP TABLE audit")
    with pytest.raises(RedTeamDepthError):
        RedTeamDepthController.ssrf_canary("authorized-target", "https://example.com/metadata")

    credential = RedTeamDepthController.credential_observation(
        "authorized-target",
        "test API token",
        "test-token-value",
        source_location="GET /api/config -> data.access_token",
        validation_status="validated against the authorized test endpoint",
    )
    assert "value=test-token-value" in credential.proof
    assert "source_location=GET /api/config -> data.access_token" in credential.proof
    assert "validation_status=validated against the authorized test endpoint" in credential.proof
    with pytest.raises(RedTeamDepthError):
        RedTeamDepthController.credential_observation(
            "authorized-target",
            "test API token",
            "",
        )


def test_redteam_prompt_is_versioned_and_safe() -> None:
    prompt = render_system_prompt(mode="redteam", scan_mode="quick", is_root=True)
    assert "REDTEAM SPECIAL MODE IS ACTIVE" in prompt
    assert "redteam-v5" in prompt
    assert "Never create or deploy Webshells" in prompt
    assert "reverse-shell" in prompt
    assert "exact field or file location" in prompt
    assert "Unknown categories remain testable" in prompt
    assert "Every observed finding must be reported" in prompt


@pytest.mark.asyncio
async def test_shell_network_requests_are_blocked_before_transport() -> None:
    captured: dict[str, str] = {}

    async def invoke(_ctx: object, raw_input: str) -> str:
        captured["raw_input"] = raw_input
        return "sent"

    tool = FunctionTool(
        name="exec_command",
        description="test",
        params_json_schema={"type": "object", "properties": {}},
        on_invoke_tool=invoke,
    )
    wrapped = factory._wrap_exec_command(tool)
    result = await wrapped.on_invoke_tool(
        cast("Any", SimpleNamespace(context={"security_mode": "redteam"})),
        json.dumps({"cmd": "python3 -c 'import requests; requests.get(\"https://target\")'"}),
    )
    assert "禁止通过 Shell 直接发起网络请求" in result
    assert captured == {}


@pytest.mark.asyncio
async def test_proxy_replay_does_not_deny_unknown_type_before_client_lookup() -> None:
    result = await proxy_tools.repeat_request.on_invoke_tool(
        cast(
            "Any",
            SimpleNamespace(
                context={"security_mode": "redteam"},
                tool_name="repeat_request",
                run_config=None,
            ),
        ),
        json.dumps({"request_id": "request-1"}),
    )
    parsed = json.loads(result)
    assert parsed["success"] is False
    assert "红队专项策略" not in parsed["error"]


@pytest.mark.asyncio
async def test_mcp_target_action_does_not_deny_unknown_type_before_dispatch() -> None:
    result = await mcp_agent_tools.call_mcp.on_invoke_tool(
        cast(
            "Any",
            SimpleNamespace(
                context={"security_mode": "redteam"},
                tool_name="call_mcp",
                run_config=None,
            ),
        ),
        json.dumps(
            {
                "connection": "target-mcp",
                "tool": "send_request",
                "arguments": {},
            }
        ),
    )
    assert isinstance(result, str)
    assert "红队专项策略" not in result


def test_report_state_persists_all_findings_and_builds_separate_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = ReportState(run_name="redteam-test")
    state.set_scan_config({"mode": "redteam", "targets": [], "scan_mode": "quick"})
    monkeypatch.setattr(state, "save_run_data", lambda: None)

    low_report_id = state.add_vulnerability_report(
        "observed xss",
        "high",
        vulnerability_type="stored xss",
        evidence="observed marker in response",
    )
    assert low_report_id == "vuln-0001"
    low_report = state.vulnerability_reports[0]
    assert low_report["vulnerability_type_raw"] == "stored xss"
    assert low_report["redteam_policy"]["priority"] == "low"

    report_id = state.add_vulnerability_report(
        "Verified RCE",
        "high",
        vulnerability_type="RCE",
        evidence="uid=1000",
        validation_evidence="whoami returned uid=1000",
        permission_proof="identity boundary unchanged",
        request="Authorization: Bearer placeholder-value\nGET /run",
        response='{"token":"placeholder-value","ok":true}',
    )
    assert report_id == "vuln-0002"
    assert len(state.vulnerability_reports) == 2
    assert "placeholder-value" in json.dumps(state.vulnerability_reports)
    assert len(build_attack_chain(state.vulnerability_reports)["nodes"]) == 1

    markdown = render_complete_report(
        "# 执行摘要\n\n已完成",
        run_record={"mode": "redteam", "policy_version": "redteam-v5"},
        vulnerability_reports=state.vulnerability_reports,
    )
    html = render_html_report(
        final_scan_result="# 执行摘要\n\n已完成",
        run_record={"mode": "redteam", "policy_version": "redteam-v5"},
        vulnerability_reports=state.vulnerability_reports,
    )
    assert "observed xss" in markdown
    assert "已落盘，暂未纳入攻击链" in markdown
    assert "observed xss" in html

    skip = state.record_redteam_skip(
        vulnerability_type="证书无效",
        reason="低价值传输配置检查，当前优先验证认证和授权边界",
        target="https://staging.example.invalid",
    )
    assert skip["status"] == "not_executed"
    assert state.run_record["redteam_skipped_tests"][0]["reason"].startswith("低价值")
    markdown = render_complete_report(
        "# 执行摘要\n\n已完成",
        run_record=state.run_record,
        vulnerability_reports=state.vulnerability_reports,
    )
    assert "效率策略跳过项" in markdown
    assert "低价值传输配置检查" in markdown


def test_normal_mode_preserves_report_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    state = ReportState(run_name="normal-evidence")
    state.set_scan_config({"mode": "normal", "targets": [], "scan_mode": "quick"})
    monkeypatch.setattr(state, "save_run_data", lambda: None)

    report_id = state.add_vulnerability_report(
        "Verified RCE",
        "high",
        vulnerability_type="RCE",
        request="Authorization: Bearer normal-mode-value\nGET /run",
        response='{"password":"normal-mode-value","ok":true}',
        evidence="response contained the authorized test value",
        poc_script_code="print('normal-mode-proof')",
    )

    assert report_id == "vuln-0001"
    serialized = json.dumps(state.vulnerability_reports)
    assert "normal-mode-value" in serialized
    assert "normal-mode-proof" in serialized

    html = render_html_report(
        final_scan_result="# 执行摘要\n\n已验证",
        run_record={"mode": "normal"},
        vulnerability_reports=state.vulnerability_reports,
    )
    assert "normal-mode-value" in html
    assert "normal-mode-proof" in html


def test_credential_provenance_records_complete_acquisition_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = ReportState(run_name="credential-provenance")
    state.set_scan_config({"mode": "redteam", "targets": [], "scan_mode": "quick"})
    monkeypatch.setattr(state, "save_run_data", lambda: None)

    report_id = state.add_vulnerability_report(
        "Credential material observed",
        "high",
        vulnerability_type="credential_exposure_observed",
        impact="响应返回 password 字段并完成测试身份验证",
        evidence="response field contained credential-shaped material",
        validation_evidence="observed, not validated",
        credential_provenance={
            "material_type": "Bearer token",
            "source": "HTTP response",
            "source_location": "GET /api/config -> data.access_token",
            "acquisition_method": "从响应 JSON 字段读取原始值",
            "validation_status": "validated_against_authorized_test_endpoint",
            "fingerprint": "sha256:" + "b" * 64,
            "length": "384",
            "raw_value": "must-not-be-stored",
        },
    )

    assert report_id == "vuln-0001"
    report = state.vulnerability_reports[0]
    provenance = report["credential_provenance"]
    assert provenance["source_location"] == "GET /api/config -> data.access_token"
    assert provenance["validation_status"] == "validated_against_authorized_test_endpoint"
    assert provenance["raw_value"] == "must-not-be-stored"

    markdown = render_complete_report(
        "# 执行摘要\n\n已观察",
        run_record={"mode": "redteam", "policy_version": "redteam-v3"},
        vulnerability_reports=state.vulnerability_reports,
    )
    html = render_html_report(
        final_scan_result="# 执行摘要\n\n已观察",
        run_record={"mode": "redteam", "policy_version": "redteam-v3"},
        vulnerability_reports=state.vulnerability_reports,
    )
    assert "凭据材料获取过程" in markdown
    assert "GET /api/config -> data.access_token" in markdown
    assert "validated_against_authorized_test_endpoint" in html
    assert "must-not-be-stored" in markdown
    assert "must-not-be-stored" in html


def test_attack_chain_and_delivery_renderers_filter_and_preserve_redteam_evidence() -> None:
    report = {
        "id": "vuln-0001",
        "title": "Verified upload",
        "severity": "high",
        "vulnerability_type": "writable_file_upload",
        "impact": "验证未授权写入随机 marker 并已清理",
        "evidence": "marker persisted",
        "request": "Cookie: session=placeholder-value",
        "response": "HTTP/1.1 201 Created",
    }
    chain = build_attack_chain([report])
    assert "placeholder-value" in chain["nodes"][0]["request"]

    redteam_record = {
        "run_name": "redteam-test",
        "mode": "redteam",
        "policy_version": "redteam-v3",
        "targets_info": [{"original": "https://staging.example.invalid"}],
    }
    markdown = render_complete_report(
        "# 执行摘要\n\n已验证",
        run_record=redteam_record,
        vulnerability_reports=[report],
    )
    html = render_html_report(
        final_scan_result="# 执行摘要\n\n已验证",
        run_record=redteam_record,
        vulnerability_reports=[report],
    )
    assert "红队专项安全验证报告" in markdown
    for heading in (
        "一、漏洞名称",
        "二、漏洞等级与 CVSS 4.0",
        "三、漏洞位置",
        "四、漏洞描述",
        "五、漏洞定位过程",
        "六、安全验证过程",
        "七、漏洞根因",
        "八、漏洞影响",
        "九、修复建议",
        "十、复测方案",
        "十一、证据限制与待确认事项",
    ):
        assert heading in markdown
    assert "CVSS 4.0：未计算真实 CVSS 4.0" in markdown
    assert "攻击链路图" in html
    assert "placeholder-value" in markdown
    assert "placeholder-value" in html
    assert "AI 黑盒测试发现" not in markdown
    assert "最终确认利用" not in markdown
    assert "## 十一、证据限制与待确认事项" in render_vulnerability_md(report, redteam=True)
