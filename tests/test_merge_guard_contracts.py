"""High-signal merge-gate contracts for upstream syncs.

These tests intentionally duplicate a small set of user-visible guarantees.
If they fail after an upstream merge, treat the branch as feature-regressed
even when the broader suite still passes.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import pytest
from agents.tool import CustomTool

from strix.agents import factory
from strix.agents.prompt import render_system_prompt
from strix.core.inputs import build_scope_context
from strix.interface.utils import build_target_summary_text, build_tui_stats_text
from strix.report.state import ProxyCaptureState


class _ReportState:
    def __init__(
        self,
        *,
        burp_workflow_phase: str,
        proxy_feature_request_count: int,
        proxy_capture_state: ProxyCaptureState,
    ) -> None:
        self.vulnerability_reports: list[dict[str, Any]] = []
        self.run_record = {"llm_usage": {}}
        self.caido_url = None
        self.caido_ui_url = None
        self.burp_upstream_unavailable_reason = None
        self.proxy_capture_state = proxy_capture_state
        self.proxy_capture_error = None
        self.burp_workflow_phase = burp_workflow_phase
        self.proxy_feature_request_count = proxy_feature_request_count

    def get_total_llm_usage(self) -> dict[str, Any]:
        return {}


def test_merge_guard_passive_proxy_scope_contract() -> None:
    scope = build_scope_context({"burp_port": 8081})

    assert scope["proxy_passive_mode"] is True
    assert scope["scope_source"] == "burp_upstream_proxy"
    assert scope["proxy_scope_allowlist"] == ["*"]
    assert "caido.io" in scope["proxy_scope_denylist"]
    assert "*.caido.io" in scope["proxy_scope_denylist"]


def test_merge_guard_passive_proxy_prompt_contract_forbids_workspace_edits() -> None:
    scope = build_scope_context({"burp_port": 8081})

    prompt = render_system_prompt(
        scan_mode="deep",
        is_root=True,
        is_whitebox=False,
        system_prompt_context=scope,
    )

    assert "SYSTEM-VERIFIED OPERATION MODE" in prompt
    assert "PASSIVE PROXY FEATURE-BATCH COORDINATION" in prompt
    assert "Use proxy-history tools" in prompt
    assert "WORKSPACE FILE EDITING CONSTRAINTS" in prompt
    assert "Do not use `apply_patch`" in prompt


def test_merge_guard_keeps_passive_proxy_endpoint_coverage_tools() -> None:
    tool_names = {tool.name for tool in factory._BASE_TOOLS}

    assert "get_endpoint_coverage" in tool_names
    assert "mark_endpoint_not_applicable" in tool_names


@pytest.mark.asyncio
async def test_merge_guard_non_whitebox_blocks_apply_patch() -> None:
    async def invoke(_ctx: Any, _inp: str) -> str:
        return "should-not-run"

    toolset = SimpleNamespace(
        apply_patch=CustomTool(name="apply_patch", description="patch", on_invoke_tool=invoke)
    )
    factory._configure_filesystem_tools(
        toolset,
        chat_completions=False,
        allow_workspace_edits=False,
    )

    result = await toolset.apply_patch.on_invoke_tool(cast("Any", None), "*** Begin Patch\n")

    assert "不是白盒源码审计场景" in result
    assert "禁止修改 /workspace 文件" in result


def test_merge_guard_burp_summary_and_stats_stay_chinese() -> None:
    summary = build_target_summary_text([], burp_port=8081).plain
    stats = build_tui_stats_text(
        _ReportState(
            burp_workflow_phase="capture",
            proxy_feature_request_count=12,
            proxy_capture_state=ProxyCaptureState(total_request_count=42),
        )
    ).plain

    assert "Burp 被动模式" in summary
    assert "仅基于 Burp 转发流量建立作用域" in summary
    assert "发送“开始测试”" in summary
    assert "工作流: 功能点采集" in stats
    assert "操作: 发送“开始测试”启动当前功能点分析" in stats
    assert "代理捕获: 累计 42 条" in stats
