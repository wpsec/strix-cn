"""Regression tests for the red-team validation policy and artifacts."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, cast

import pytest
from agents.tool import FunctionTool

from strix.agents import factory
from strix.agents.prompt import render_system_prompt
from strix.redteam.attack_chain import build_attack_chain, redact_sensitive_text
from strix.redteam.depth import RedTeamDepthController, RedTeamDepthError
from strix.redteam.policy import should_ignore
from strix.report.html_report import render_html_report
from strix.report.state import ReportState
from strix.report.writer import render_complete_report, render_vulnerability_md
from strix.tools.mcp import agent_tools as mcp_agent_tools
from strix.tools.proxy import tools as proxy_tools
from strix.tools.reporting.tool import _calculate_cvss4


@pytest.mark.parametrize(
    ("vulnerability_type", "expected_ignore"),
    [
        ("RCE", False),
        ("writable_file_upload", False),
        ("堆叠查询 SQL 注入", False),
        ("反序列化", False),
        ("可窃取元数据的 SSRF", False),
        ("存储型 XSS", True),
        ("CSRF", True),
        ("缺少安全头", True),
        ("unknown finding", True),
    ],
)
def test_redteam_policy_is_allowlist_and_fail_closed(
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
        ("凭据材料可访问", "材料已脱敏，仅记录 sha256 指纹", False),
        ("凭据材料可访问", "发现 token 文件", True),
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


def test_depth_controller_only_constructs_safe_proofs() -> None:
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
        "sha256:" + "a" * 64,
    )
    assert "value=[REDACTED]" in credential.proof
    assert "sha256:" + "a" * 64 in credential.proof
    with pytest.raises(RedTeamDepthError):
        RedTeamDepthController.credential_observation(
            "authorized-target",
            "test API token",
            "actual-secret-value",
        )


def test_redteam_prompt_is_versioned_and_safe() -> None:
    prompt = render_system_prompt(mode="redteam", scan_mode="quick", is_root=True)
    assert "REDTEAM SPECIAL MODE IS ACTIVE" in prompt
    assert "redteam-v2" in prompt
    assert "Never create or deploy Webshells" in prompt
    assert "reverse-shell" in prompt


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
async def test_proxy_replay_denies_unknown_type_before_client_lookup() -> None:
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
    assert parsed["skipped"] is True
    assert "未发送请求" in parsed["error"]


@pytest.mark.asyncio
async def test_mcp_target_action_denies_unknown_type_before_dispatch() -> None:
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
    assert result["skipped"] is True
    assert "未发送请求" in result["error"]


def test_report_state_filters_and_builds_redteam_chain(monkeypatch: pytest.MonkeyPatch) -> None:
    state = ReportState(run_name="redteam-test")
    state.set_scan_config({"mode": "redteam", "targets": [], "scan_mode": "quick"})
    monkeypatch.setattr(state, "save_run_data", lambda: None)

    assert (
        state.add_vulnerability_report(
            "ignored xss",
            "high",
            vulnerability_type="stored xss",
            evidence="should not persist",
        )
        == ""
    )
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
    assert report_id == "vuln-0001"
    assert len(state.vulnerability_reports) == 1
    assert "placeholder-value" not in json.dumps(state.vulnerability_reports)


def test_attack_chain_and_delivery_renderers_filter_and_redact() -> None:
    report = {
        "id": "vuln-0001",
        "title": "Verified upload",
        "severity": "high",
        "vulnerability_type": "writable_file_upload",
        "evidence": "marker persisted",
        "request": "Cookie: session=placeholder-value",
        "response": "HTTP/1.1 201 Created",
    }
    chain = build_attack_chain([report])
    assert chain["nodes"][0]["request"].find("placeholder-value") == -1

    redteam_record = {
        "run_name": "redteam-test",
        "mode": "redteam",
        "policy_version": "redteam-v2",
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
    assert "红队专项攻击链报告" in markdown
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
    assert "CVSS 4.0：未提供真实 CVSS 4.0" in markdown
    assert "攻击链路图" in html
    assert "placeholder-value" not in markdown
    assert "placeholder-value" not in html
    assert "AI 黑盒测试发现" not in markdown
    assert "最终确认利用" not in markdown
    assert "## 十一、证据限制与待确认事项" in render_vulnerability_md(report, redteam=True)


def test_sensitive_text_redaction_is_bounded() -> None:
    redacted = redact_sensitive_text("Authorization: Bearer placeholder-value\n" + "x" * 100)
    assert "placeholder-value" not in redacted
    assert len(redacted) <= 16_000
