from __future__ import annotations

import argparse
import asyncio
import os
from pathlib import Path

import pytest

from strix.config import apply_config_override, loader
from strix.config.settings import DEFAULT_MAX_TURNS
from strix.interface.tui.backend.controller import TuiController
from strix.report.state import ProxyCaptureState


def args() -> argparse.Namespace:
    return argparse.Namespace(
        needs_setup=True,
        targets_info=[],
        instruction=None,
        scan_mode="deep",
        max_budget_usd=None,
        max_turns=DEFAULT_MAX_TURNS,
        scope_mode="auto",
        diff_base=None,
        local_sources=[],
        diff_scope={"active": False},
        user_explicit_instruction=None,
        run_name=None,
        burp_port=None,
    )


class PassiveProxyReportState:
    def __init__(
        self,
        *,
        recent_request_count: int = 1,
        recent_request_has_more: bool = False,
        latest_request_id: str | None = "req-1",
        latest_method: str | None = "GET",
        latest_host: str | None = "app.example.com",
        latest_path: str | None = "/api/orders",
        latest_status_code: int | None = 200,
        total_request_count: int = 1,
    ) -> None:
        self.run_record = {"status": "running"}
        self.caido_url = "http://127.0.0.1:8082"
        self.proxy_capture_error = None
        self.proxy_capture_state = ProxyCaptureState(
            recent_request_count=recent_request_count,
            recent_request_has_more=recent_request_has_more,
            latest_request_id=latest_request_id,
            latest_method=latest_method,
            latest_host=latest_host,
            latest_path=latest_path,
            latest_status_code=latest_status_code,
            total_request_count=total_request_count,
        )

    def get_total_llm_usage(self) -> dict[str, int]:
        return {}


@pytest.fixture(autouse=True)
def isolated_config(tmp_path: Path) -> None:
    for key in (
        "STRIX_LLM",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "LLM_API_KEY",
        "LLM_API_BASE",
        "AZURE_API_KEY",
        "AZURE_API_BASE",
        "AZURE_API_VERSION",
    ):
        os.environ.pop(key, None)
    apply_config_override(tmp_path / "config.json")


@pytest.mark.asyncio
async def test_setup_state_is_serializable() -> None:
    controller = TuiController(args())
    await controller.handle("setup.add_target", {"target": "https://example.com"})
    await controller.handle("setup.set_instruction", {"instruction": "focus on auth"})
    snapshot = controller.snapshot()
    assert snapshot["targets"] == ["https://example.com"]
    assert snapshot["instruction"] == "focus on auth"
    assert snapshot["scan_state"] == "setup"
    assert snapshot["scan_mode"] == "deep"
    assert snapshot["max_budget_usd"] is None
    assert snapshot["max_turns"] == 500
    assert snapshot["scope_mode"] == "auto"
    assert snapshot["diff_base"] is None


@pytest.mark.asyncio
async def test_setup_instruction_starts_from_cli_and_can_be_cleared() -> None:
    setup_args = args()
    setup_args.instruction = "  CLI instruction  "
    controller = TuiController(setup_args)

    assert controller.snapshot()["instruction"] == "CLI instruction"

    result = await controller.handle("setup.set_instruction", {"instruction": ""})

    assert result == {"instruction": ""}
    assert controller.snapshot()["instruction"] == ""


@pytest.mark.asyncio
async def test_setup_controls_reject_changes_after_start() -> None:
    controller = TuiController(args())
    controller.setup_mode = False
    controller.scan_started = True

    with pytest.raises(RuntimeError, match="can no longer be changed"):
        await controller.handle("setup.add_target", {"target": "https://example.com"})


@pytest.mark.asyncio
async def test_large_target_list_reports_truncated_snapshot_count() -> None:
    controller = TuiController(args())

    for index in range(20):
        await controller.handle("setup.add_target", {"target": f"https://target-{index}.example"})
    added = await controller.handle("setup.add_target", {"target": "https://last.example"})
    snapshot = controller.snapshot()

    assert added == {"target": "https://last.example", "total": 21}
    assert snapshot["target_count"] == 21
    # The snapshot only carries a bounded prefix of the list.
    assert len(snapshot["targets"]) == 16


def test_state_populates_model_warning_for_non_frontier_model() -> None:
    os.environ["STRIX_LLM"] = "openai/gpt-3.5-turbo"
    loader._cached = None

    warning = TuiController(args()).snapshot()["model_warning"]

    assert "openai/gpt-3.5-turbo" in warning
    assert "not a recommended frontier model" in warning


def test_setup_restores_prepared_cli_targets() -> None:
    setup_args = args()
    setup_args.targets_info = [
        {"type": "web", "details": {}, "original": "https://example.com"},
        {"type": "local_code", "details": {}, "original": "/workspace/source"},
    ]

    controller = TuiController(setup_args)

    assert controller.snapshot()["targets"] == ["https://example.com", "/workspace/source"]


def test_snapshot_exposes_passive_proxy_mode_without_explicit_targets() -> None:
    runtime_args = args()
    runtime_args.burp_port = 8081

    controller = TuiController(runtime_args)

    assert controller.snapshot()["passive_proxy_mode"] is True
    assert controller.snapshot()["passive_proxy_phase"] == "capture"


def test_snapshot_clears_passive_proxy_mode_when_targets_exist() -> None:
    runtime_args = args()
    runtime_args.burp_port = 8081
    runtime_args.targets_info = [
        {"type": "web", "details": {}, "original": "https://example.com"},
    ]

    controller = TuiController(runtime_args)

    assert controller.snapshot()["passive_proxy_mode"] is False


def test_snapshot_exposes_proxy_capture_summary_fields() -> None:
    runtime_args = args()
    runtime_args.burp_port = 8081
    controller = TuiController(
        runtime_args,
        report_state=PassiveProxyReportState(
            recent_request_count=7,
            recent_request_has_more=True,
            latest_request_id="req-31",
            latest_method="POST",
            latest_host="app.example.com",
            latest_path="/api/login",
            latest_status_code=403,
            total_request_count=31,
        ),
    )

    snapshot = controller.snapshot()

    assert snapshot["proxy_recent_request_count"] == 7
    assert snapshot["proxy_recent_request_has_more"] is True
    assert snapshot["proxy_latest_method"] == "POST"
    assert snapshot["proxy_latest_host"] == "app.example.com"
    assert snapshot["proxy_latest_path"] == "/api/login"
    assert snapshot["proxy_latest_status_code"] == 403
    assert snapshot["proxy_total_request_count"] == 31


@pytest.mark.asyncio
async def test_start_validates_model_before_callback() -> None:
    started = False

    async def start(_verify: bool = True) -> None:
        nonlocal started
        started = True

    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})
    with pytest.raises(ValueError, match="No model configured"):
        await controller.handle("setup.start", {})
    assert started is False


@pytest.mark.asyncio
async def test_start_launches_with_a_configured_model() -> None:
    started = False

    async def start(_verify: bool = True) -> None:
        nonlocal started
        started = True

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})

    result = await controller.handle("setup.start", {})

    assert result == {"started": True}
    assert started is True


@pytest.mark.asyncio
async def test_start_without_target_requires_mount_consent() -> None:
    started = False

    async def start(_verify: bool = True) -> None:
        nonlocal started
        started = True

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)

    # Mounting the working directory is never silent.
    with pytest.raises(ValueError, match="No target set"):
        await controller.handle("setup.start", {"verify": False})
    assert started is False
    assert controller.targets == []
    assert controller.workspace_mount is None


@pytest.mark.asyncio
async def test_target_less_start_enters_live_view_and_waits_for_the_mount() -> None:
    """Nothing is prepared until the live-view confirmation is answered."""
    started = False

    async def start(_verify: bool = True) -> None:
        nonlocal started
        started = True

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)

    result = await controller.handle("setup.start", {"verify": False, "mount_working_dir": True})

    assert result == {"started": True}
    # The live view is up so the prompt can be shown there, but the scan has not
    # been prepared and nothing is mounted yet.
    assert started is False
    assert controller.setup_mode is False
    assert controller.scan_state == "preparing"
    assert controller.pending_workspace_mount == str(Path.cwd())
    assert controller.workspace_mount is None
    assert controller.snapshot()["pending_mount"] == str(Path.cwd())


@pytest.mark.asyncio
async def test_confirming_the_mount_starts_the_scan_without_a_target() -> None:
    started = False
    seen_verify: bool | None = None

    async def start(verify: bool = True) -> None:
        nonlocal started, seen_verify
        started = True
        seen_verify = verify

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.start", {"verify": False, "mount_working_dir": True})

    result = await controller.handle("setup.confirm_mount", {"approved": True})

    assert result == {"approved": True}
    assert started is True
    # Launched optimistically, and mounted as a workspace: the scan genuinely
    # has no target, so the instruction is the only source of truth.
    assert seen_verify is False
    assert controller.workspace_mount == str(Path.cwd())
    assert controller.targets == []
    assert controller.scan_state == "running"
    assert controller.snapshot()["pending_mount"] == ""


@pytest.mark.asyncio
async def test_declining_the_mount_runs_without_one() -> None:
    started: list[bool] = []

    async def start(verify: bool = True) -> None:
        started.append(verify)

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.start", {"verify": False, "mount_working_dir": True})

    result = await controller.handle("setup.confirm_mount", {"approved": False})

    assert result == {"approved": False}
    # Declining skips the directory; it does not abandon the scan.
    assert started == [False]
    assert controller.workspace_mount is None
    assert controller.pending_workspace_mount is None
    assert controller.setup_mode is False
    assert controller.scan_started is True
    assert controller.scan_state == "running"


@pytest.mark.asyncio
async def test_approving_the_mount_runs_with_it() -> None:
    started: list[bool] = []

    async def start(verify: bool = True) -> None:
        started.append(verify)

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.start", {"verify": False, "mount_working_dir": True})

    result = await controller.handle("setup.confirm_mount", {"approved": True})

    assert result == {"approved": True}
    assert started == [False]
    assert controller.workspace_mount == str(Path.cwd())
    assert controller.scan_state == "running"


@pytest.mark.asyncio
async def test_confirm_mount_requires_a_pending_request() -> None:
    controller = TuiController(args())

    with pytest.raises(RuntimeError, match="No mount confirmation is pending"):
        await controller.handle("setup.confirm_mount", {"approved": True})


def test_snapshot_exposes_working_directory() -> None:
    controller = TuiController(args())

    assert controller.snapshot()["working_dir"] == str(Path.cwd())
    assert controller.snapshot()["pending_mount"] == ""


@pytest.mark.asyncio
async def test_start_forwards_verify_flag_by_default() -> None:
    seen_verify: bool | None = None

    async def start(verify: bool = True) -> None:
        nonlocal seen_verify
        seen_verify = verify

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})

    # A named target keeps the upfront model check.
    await controller.handle("setup.start", {})

    assert seen_verify is True


@pytest.mark.asyncio
async def test_start_rejects_concurrent_and_repeated_submissions() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def start(_verify: bool = True) -> None:
        entered.set()
        await release.wait()

    os.environ["STRIX_LLM"] = "anthropic/claude-sonnet-4"
    os.environ["ANTHROPIC_API_KEY"] = "test-key"
    loader._cached = None
    controller = TuiController(args(), on_start=start)
    await controller.handle("setup.add_target", {"target": "https://example.com"})

    first_start = asyncio.create_task(controller.handle("setup.start", {}))
    await entered.wait()
    with pytest.raises(RuntimeError, match="already starting or running"):
        await controller.handle("setup.start", {})
    release.set()
    await first_start
    with pytest.raises(RuntimeError, match="already starting or running"):
        await controller.handle("setup.start", {})


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["completed", "failed", "crashed", "stopped"])
async def test_stop_rejects_terminal_agents(status: str) -> None:
    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def cancel_descendants_graceful(self, agent_id: str) -> bool:
            self.calls.append(agent_id)
            return True

    coordinator = Coordinator()
    controller = TuiController(args(), coordinator=coordinator)
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("agent-1", name="Agent", status=status)

    with pytest.raises(RuntimeError, match=f"cannot be stopped while {status}"):
        await controller.handle("agent.stop", {"agent_id": "agent-1"})

    assert coordinator.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["running", "waiting", "budget_paused"])
async def test_stop_allows_active_agents(status: str) -> None:
    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[str] = []

        async def cancel_descendants_graceful(self, agent_id: str) -> bool:
            self.calls.append(agent_id)
            return True

    coordinator = Coordinator()
    controller = TuiController(args(), coordinator=coordinator)
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("agent-1", name="Agent", status=status)

    result = await controller.handle("agent.stop", {"agent_id": "agent-1"})

    assert result == {"stopped": True}
    assert coordinator.calls == ["agent-1"]


@pytest.mark.asyncio
async def test_stop_handles_coordinator_rejection_after_stale_active_projection() -> None:
    class Coordinator:
        async def cancel_descendants_graceful(self, _agent_id: str) -> bool:
            return False

    controller = TuiController(args(), coordinator=Coordinator())
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("agent-1", name="Agent", status="running")

    with pytest.raises(RuntimeError, match="no longer active"):
        await controller.handle("agent.stop", {"agent_id": "agent-1"})


@pytest.mark.asyncio
async def test_passive_proxy_waiting_ignores_single_character_message() -> None:
    runtime_args = args()
    runtime_args.burp_port = 8081

    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, str]]] = []

        async def send(self, agent_id: str, payload: dict[str, str]) -> bool:
            self.calls.append((agent_id, payload))
            return True

    coordinator = Coordinator()
    controller = TuiController(runtime_args, coordinator=coordinator)
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("root", name="Root Agent", status="waiting")

    result = await controller.handle("agent.send_message", {"agent_id": "root", "message": "k"})

    assert result == {"sent": False, "ignored": True}
    assert coordinator.calls == []
    assert controller.snapshot()["messages"][-1]["text"].startswith("已忽略等待态下的单字符输入")


@pytest.mark.asyncio
async def test_passive_proxy_waiting_allows_meaningful_message() -> None:
    runtime_args = args()
    runtime_args.burp_port = 8081

    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, str]]] = []

        async def send(self, agent_id: str, payload: dict[str, str]) -> bool:
            self.calls.append((agent_id, payload))
            return True

    coordinator = Coordinator()
    controller = TuiController(
        runtime_args,
        coordinator=coordinator,
        report_state=PassiveProxyReportState(),
    )
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("root", name="Root Agent", status="waiting")

    result = await controller.handle(
        "agent.send_message",
        {"agent_id": "root", "message": "当前功能点流量已采集完成，请继续分析"},
    )

    assert result == {"sent": True, "handled": True, "agent_id": "root"}
    assert controller.snapshot()["passive_proxy_phase"] == "testing"
    assert coordinator.calls == [
        (
            "root",
            {
                "from": "user",
                "content": (
                    "当前功能点的手工操作与 Burp 流量采集已完成，现在开始测试。\n"
                    "你必须先创建或复用一个名为“当前功能点攻击面分析专家”的子 agent。\n"
                    "该专家必须检查本轮完整 Burp 请求、站点地图、认证态、方法、路径、参数、表单与响应特征，输出当前功能点的接口清单、参数面与适用漏洞类别。\n"
                    "映射完成前不要只创建一个窄漏洞专家；映射完成后再按 endpoint 和漏洞类别创建不重叠的测试子 agent，覆盖当前功能点全部相关请求。\n"
                    "确认漏洞后必须创建正式漏洞报告，不要只在 agent_finish 中口头描述。\n"
                    "本轮仅基于当前功能点已采集的流量与站点地图开展测试，不要把之后新进入 Burp 的其他功能点流量自动并入本轮。\n"
                    "本轮结束后请停回等待态，等待操作者发送“下一功能点”。\n"
                    "操作者补充关注点：当前功能点流量已采集完成，请继续分析"
                ),
                "type": "instruction",
            },
        )
    ]


@pytest.mark.asyncio
async def test_passive_proxy_start_test_command_rewrites_message_and_routes_to_root() -> None:
    runtime_args = args()
    runtime_args.burp_port = 8081

    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, str]]] = []

        async def send(self, agent_id: str, payload: dict[str, str]) -> bool:
            self.calls.append((agent_id, payload))
            return True

    coordinator = Coordinator()
    controller = TuiController(
        runtime_args,
        coordinator=coordinator,
        report_state=PassiveProxyReportState(),
    )
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("root", name="Root Agent", status="waiting")
    controller.live_view.upsert_agent(
        "child",
        name="Mapper",
        parent_id="root",
        status="completed",
    )

    result = await controller.handle(
        "agent.send_message",
        {"agent_id": "child", "message": "开始测试，重点看越权和鉴权"},
    )

    assert result == {"sent": True, "handled": True, "agent_id": "root"}
    assert controller.snapshot()["passive_proxy_phase"] == "testing"
    assert coordinator.calls[0][0] == "root"
    assert "当前功能点攻击面分析专家" in coordinator.calls[0][1]["content"]
    assert "操作者补充关注点：重点看越权和鉴权" in coordinator.calls[0][1]["content"]


@pytest.mark.asyncio
async def test_passive_proxy_start_test_is_blocked_until_any_traffic_exists() -> None:
    runtime_args = args()
    runtime_args.burp_port = 8081

    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, str]]] = []

        async def send(self, agent_id: str, payload: dict[str, str]) -> bool:
            self.calls.append((agent_id, payload))
            return True

    coordinator = Coordinator()
    controller = TuiController(
        runtime_args,
        coordinator=coordinator,
        report_state=PassiveProxyReportState(
            recent_request_count=0,
            latest_request_id=None,
            latest_method=None,
            latest_host=None,
            latest_path=None,
            latest_status_code=None,
            total_request_count=0,
        ),
    )
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("root", name="Root Agent", status="waiting")

    result = await controller.handle(
        "agent.send_message",
        {"agent_id": "root", "message": "开始测试"},
    )

    assert result == {"sent": False, "handled": True, "ignored": True}
    assert controller.snapshot()["passive_proxy_phase"] == "capture"
    assert coordinator.calls == []
    assert "当前还没有捕获到任何 Burp 流量" in controller.snapshot()["messages"][-1]["text"]


@pytest.mark.asyncio
async def test_passive_proxy_next_feature_switches_back_to_capture_without_waking_root() -> None:
    runtime_args = args()
    runtime_args.burp_port = 8081

    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, str]]] = []

        async def send(self, agent_id: str, payload: dict[str, str]) -> bool:
            self.calls.append((agent_id, payload))
            return True

    coordinator = Coordinator()
    controller = TuiController(
        runtime_args,
        coordinator=coordinator,
        report_state=PassiveProxyReportState(
            recent_request_count=3,
            latest_request_id="req-3",
            total_request_count=3,
        ),
    )
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("root", name="Root Agent", status="waiting")

    await controller.handle(
        "agent.send_message",
        {"agent_id": "root", "message": "开始测试"},
    )
    coordinator.calls.clear()

    result = await controller.handle(
        "agent.send_message",
        {"agent_id": "root", "message": "下一功能点"},
    )

    assert result == {"sent": False, "handled": True, "ignored": True}
    assert controller.snapshot()["passive_proxy_phase"] == "capture"
    assert coordinator.calls == []
    assert "已切换到下一功能点采集阶段" in controller.snapshot()["messages"][-1]["text"]


@pytest.mark.asyncio
async def test_passive_proxy_start_test_requires_new_traffic_after_next_feature() -> None:
    runtime_args = args()
    runtime_args.burp_port = 8081

    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, str]]] = []

        async def send(self, agent_id: str, payload: dict[str, str]) -> bool:
            self.calls.append((agent_id, payload))
            return True

    report_state = PassiveProxyReportState(
        recent_request_count=3,
        latest_request_id="req-3",
        total_request_count=3,
    )
    coordinator = Coordinator()
    controller = TuiController(runtime_args, coordinator=coordinator, report_state=report_state)
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("root", name="Root Agent", status="waiting")

    first = await controller.handle(
        "agent.send_message",
        {"agent_id": "root", "message": "开始测试"},
    )
    assert first == {"sent": True, "handled": True, "agent_id": "root"}

    await controller.handle(
        "agent.send_message",
        {"agent_id": "root", "message": "下一功能点"},
    )
    coordinator.calls.clear()

    blocked = await controller.handle(
        "agent.send_message",
        {"agent_id": "root", "message": "开始测试"},
    )

    assert blocked == {"sent": False, "handled": True, "ignored": True}
    assert controller.snapshot()["passive_proxy_phase"] == "capture"
    assert coordinator.calls == []
    assert "当前还没有捕获到下一功能点的新流量" in controller.snapshot()["messages"][-1]["text"]

    report_state.proxy_capture_state = ProxyCaptureState(
        recent_request_count=2,
        recent_request_has_more=False,
        latest_request_id="req-5",
        latest_method="POST",
        latest_host="app.example.com",
        latest_path="/api/orders/confirm",
        latest_status_code=200,
        total_request_count=5,
    )

    resumed = await controller.handle(
        "agent.send_message",
        {"agent_id": "root", "message": "开始测试"},
    )

    assert resumed == {"sent": True, "handled": True, "agent_id": "root"}
    assert controller.snapshot()["passive_proxy_phase"] == "testing"
    assert coordinator.calls[0][0] == "root"


@pytest.mark.asyncio
async def test_passive_proxy_next_feature_is_blocked_while_children_are_active() -> None:
    runtime_args = args()
    runtime_args.burp_port = 8081

    class Coordinator:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict[str, str]]] = []

        async def send(self, agent_id: str, payload: dict[str, str]) -> bool:
            self.calls.append((agent_id, payload))
            return True

    coordinator = Coordinator()
    controller = TuiController(
        runtime_args,
        coordinator=coordinator,
        report_state=PassiveProxyReportState(),
    )
    controller.set_runtime(scan_loop=asyncio.get_running_loop())
    controller.live_view.upsert_agent("root", name="Root Agent", status="waiting")

    await controller.handle(
        "agent.send_message",
        {"agent_id": "root", "message": "开始测试"},
    )
    controller.live_view.upsert_agent(
        "mapper",
        name="当前功能点攻击面分析专家",
        parent_id="root",
        status="running",
    )
    coordinator.calls.clear()

    result = await controller.handle(
        "agent.send_message",
        {"agent_id": "root", "message": "下一功能点"},
    )

    assert result == {"sent": False, "handled": True, "ignored": True}
    assert controller.snapshot()["passive_proxy_phase"] == "testing"
    assert coordinator.calls == []
    assert "当前功能点仍在测试中" in controller.snapshot()["messages"][-1]["text"]


@pytest.mark.asyncio
async def test_unknown_command_is_rejected() -> None:
    controller = TuiController(args())
    with pytest.raises(ValueError, match="Unknown command"):
        await controller.handle("nope", {})


def test_messages_are_sanitized_and_agents_are_collection_only() -> None:
    controller = TuiController(args())
    controller.add_message("replace\x1b]52;c;Y2xpcA==\x07 key\x85")
    for index in range(40):
        controller.live_view.upsert_agent(f"agent-{index}", name=f"Agent {index}")

    snapshot = controller.snapshot()

    assert "agents" not in snapshot
    assert [message["text"] for message in snapshot["messages"]] == ["replace key"]
    assert len(controller.collection("agents")) == 40


@pytest.mark.asyncio
async def test_existing_viewer_is_reopened_and_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    opened: list[str] = []

    class ViewerServer:
        shutdown_called = False
        close_called = False

        def shutdown(self) -> None:
            self.shutdown_called = True

        def server_close(self) -> None:
            self.close_called = True

    controller = TuiController(args())
    controller.viewer_status = "running"
    controller.viewer_url = "http://127.0.0.1:1234/?token=test"
    server = ViewerServer()
    controller._viewer_httpd = server
    monkeypatch.setattr("strix.interface.tui.backend.controller.webbrowser.open", opened.append)

    result = await controller.handle("viewer.open", {})
    controller.close_viewer()

    assert result == {"status": "running", "url": controller.viewer_url}
    assert opened == [controller.viewer_url]
    assert server.shutdown_called is True
    assert server.close_called is True
