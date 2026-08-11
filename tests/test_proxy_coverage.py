"""Regression tests for passive-proxy endpoint coverage enforcement."""

from __future__ import annotations

import json
from typing import Any

import pytest
from agents.tool_context import ToolContext

from strix.core.agents import AgentCoordinator
from strix.runtime.proxy_coverage import (
    assign_proxy_coverage,
    begin_proxy_coverage,
    mark_proxy_endpoint_not_applicable,
    unresolved_proxy_endpoints,
)
from strix.tools.agents_graph.tools import create_agent, wait_for_agents
from strix.tools.finish.tool import finish_scan
from strix.tools.proxy.coverage import mark_endpoint_not_applicable
from strix.tools.respond.tool import respond_to_user


def _coverage_ref() -> dict[str, Any]:
    coverage: dict[str, Any] = {}
    begin_proxy_coverage(
        coverage,
        batch_id="req-9:9",
        endpoint_request_counts={
            "POST app.example.com/api/upload": 2,
            "GET app.example.com/api/users": 4,
        },
    )
    return coverage


def test_mapping_agent_does_not_claim_test_coverage() -> None:
    coverage = _coverage_ref()

    assigned = assign_proxy_coverage(
        coverage,
        agent_id="mapper",
        agent_name="当前功能点攻击面分析专家",
        task="覆盖 POST app.example.com/api/upload 和 GET app.example.com/api/users",
    )

    assert assigned == []
    assert unresolved_proxy_endpoints(coverage) == [
        "GET app.example.com/api/users",
        "POST app.example.com/api/upload",
    ]


def test_specialist_assignment_and_explicit_skip_close_manifest() -> None:
    coverage = _coverage_ref()

    assigned = assign_proxy_coverage(
        coverage,
        agent_id="upload-agent",
        agent_name="文件上传专家",
        task="测试 POST app.example.com/api/upload 的文件类型与路径校验",
    )
    skipped = mark_proxy_endpoint_not_applicable(
        coverage,
        endpoint="GET app.example.com/api/users",
        reason="该接口无输入且已由明确的只读范围排除规则覆盖",
    )

    assert assigned == ["POST app.example.com/api/upload"]
    assert skipped is True
    assert unresolved_proxy_endpoints(
        coverage,
        agent_statuses={"upload-agent": "completed"},
    ) == []


@pytest.mark.asyncio
async def test_create_agent_registers_endpoint_coverage_from_task() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root Agent", parent_id=None)
    coverage = _coverage_ref()

    async def spawn_child_agent(**_kwargs: Any) -> dict[str, Any]:
        await coordinator.register(
            "sql-agent",
            "SQL 注入专家",
            parent_id="root",
            task="测试 GET app.example.com/api/users 的 id 参数",
        )
        return {"success": True, "agent_id": "sql-agent"}

    ctx = ToolContext(
        context={
            "coordinator": coordinator,
            "agent_id": "root",
            "parent_id": None,
            "spawn_child_agent": spawn_child_agent,
            "proxy_feature_coverage_ref": coverage,
        },
        tool_name="create_agent",
        tool_call_id="call-create",
        tool_arguments="{}",
    )
    raw = await create_agent.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "name": "SQL 注入专家",
                "task": "测试 GET app.example.com/api/users 的 id 参数",
                "skills": ["sql_injection"],
            }
        ),
    )

    result = json.loads(raw)
    assert result["covered_endpoints"] == ["GET app.example.com/api/users"]
    assert result["unresolved_endpoints"] == ["POST app.example.com/api/upload"]


@pytest.mark.asyncio
async def test_root_cannot_park_with_uncovered_endpoints_and_no_active_children() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root Agent", parent_id=None)
    coverage = _coverage_ref()
    context = {
        "coordinator": coordinator,
        "agent_id": "root",
        "parent_id": None,
        "interactive": True,
        "proxy_feature_coverage_ref": coverage,
    }

    wait_ctx = ToolContext(
        context=context,
        tool_name="wait_for_agents",
        tool_call_id="call-wait",
        tool_arguments="{}",
    )
    wait_raw = await wait_for_agents.on_invoke_tool(wait_ctx, "{}")
    respond_ctx = ToolContext(
        context=context,
        tool_name="respond_to_user",
        tool_call_id="call-respond",
        tool_arguments="{}",
    )
    respond_raw = await respond_to_user.on_invoke_tool(
        respond_ctx,
        json.dumps({"message": "本轮完成"}),
    )

    assert json.loads(wait_raw)["wait_outcome"] == "coverage_incomplete"
    assert json.loads(respond_raw)["wait_outcome"] == "coverage_incomplete"
    assert coordinator.statuses["root"] == "running"


@pytest.mark.asyncio
async def test_root_can_close_non_applicable_endpoint_with_exact_manifest_value() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root Agent", parent_id=None)
    coverage = _coverage_ref()
    ctx = ToolContext(
        context={
            "coordinator": coordinator,
            "agent_id": "root",
            "parent_id": None,
            "proxy_feature_coverage_ref": coverage,
        },
        tool_name="mark_endpoint_not_applicable",
        tool_call_id="call-skip",
        tool_arguments="{}",
    )

    raw = await mark_endpoint_not_applicable.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "endpoint": "GET app.example.com/api/users",
                "reason": "该接口没有任何输入参数，且响应为固定健康检查内容",
            }
        ),
    )

    result = json.loads(raw)
    assert result["success"] is True
    assert result["pending"] == 1


@pytest.mark.asyncio
async def test_finish_scan_is_blocked_while_endpoint_coverage_is_incomplete() -> None:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root Agent", parent_id=None)
    coverage = _coverage_ref()
    ctx = ToolContext(
        context={
            "coordinator": coordinator,
            "agent_id": "root",
            "parent_id": None,
            "proxy_feature_coverage_ref": coverage,
        },
        tool_name="finish_scan",
        tool_call_id="call-finish",
        tool_arguments="{}",
    )
    raw = await finish_scan.on_invoke_tool(
        ctx,
        json.dumps(
            {
                "executive_summary": "x",
                "methodology": "x",
                "technical_analysis": "x",
                "recommendations": "x",
            }
        ),
    )

    result = json.loads(raw)
    assert result["success"] is False
    assert result["scan_completed"] is False
    assert len(result["unresolved_endpoints"]) == 2
