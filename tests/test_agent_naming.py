"""Tests for specialist agent naming and localized agent-facing strings."""

from __future__ import annotations

from rich.text import Text

from strix.core.agent_naming import normalize_agent_name
from strix.interface.tui.renderers.agents_graph_renderer import (
    CreateAgentRenderer,
    StopAgentRenderer,
    ViewAgentGraphRenderer,
)
from strix.tools.agents_graph.tools import _render_completion_report


def _plain(static: object) -> str:
    content = static.content  # type: ignore[attr-defined]
    return content.plain if isinstance(content, Text) else str(content)


def test_normalize_agent_name_localizes_common_english_specialists() -> None:
    assert normalize_agent_name("XSS Specialist") == "XSS专家"
    assert normalize_agent_name("SQLi Validator") == "SQL注入验证专家"
    assert normalize_agent_name("Auth Specialist") == "鉴权专家"
    assert normalize_agent_name("source-code reviewer") == "源码审计专家"
    assert normalize_agent_name("鉴权专家") == "鉴权专家"
    assert normalize_agent_name("") == "专家代理"


def test_completion_report_uses_chinese_headings_and_localized_name() -> None:
    report = _render_completion_report(
        agent_name="Auth Specialist",
        agent_id="abcd1234",
        task="检查登录与会话逻辑",
        success=True,
        result_summary="已完成鉴权流程审计。",
        findings=["发现会话固定风险。"],
        recommendations=["继续验证找回密码流程。"],
    )

    assert "来自 鉴权专家 (abcd1234) 的完成报告" in report
    assert "状态: 成功" in report
    assert "任务: 检查登录与会话逻辑" in report
    assert "总结:" in report
    assert "发现:" in report
    assert "建议:" in report


def test_agent_renderers_use_chinese_labels_and_localized_names() -> None:
    created = _plain(
        CreateAgentRenderer.render(
            {"args": {"name": "Auth Specialist", "task": "检查登录"}, "status": "running"}
        )
    )
    viewing = _plain(ViewAgentGraphRenderer.render({"status": "running"}))
    stopping = _plain(
        StopAgentRenderer.render(
            {"args": {"target_agent_id": "abcd1234", "cascade": True}, "status": "running"}
        )
    )

    assert "创建子专家" in created
    assert "鉴权专家" in created
    assert "查看代理图" in viewing
    assert "停止" in stopping
    assert "及其子代理" in stopping
