"""Tests for manual Burp feature-workflow delegation safeguards."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from strix.interface.tui.app import StrixTUIApp
from strix.runtime.proxy_capture import ProxyCaptureSnapshot


def test_feature_test_start_message_requires_specialist_coordination() -> None:
    snapshot = ProxyCaptureSnapshot(
        recent_request_count=6,
        recent_request_has_more=True,
        latest_request_id="req-18",
        latest_method="POST",
        latest_host="app.example.com",
        latest_path="/api/orders/submit",
        latest_status_code=403,
    )

    message = StrixTUIApp._feature_test_start_message(snapshot)

    assert "view_agent_graph" in message
    assert "send_message_to_agent" in message
    assert "create_todo / update_todo" in message
    assert "攻击面分析专家" in message
    assert "全部请求" in message
    assert "create_vulnerability_report" in message
    assert "不得只创建一个窄任务专家" in message
    assert "POST app.example.com/api/orders/submit [403]" in message


def test_feature_workflow_delegation_nudge_message_demands_child_agent() -> None:
    snapshot = ProxyCaptureSnapshot(
        recent_request_count=10,
        recent_request_has_more=True,
        latest_request_id="req-53",
        latest_method="POST",
        latest_host="app-sit.example.com",
        latest_path="/api/login",
        latest_status_code=403,
    )

    message = StrixTUIApp._feature_workflow_delegation_nudge_message(snapshot)

    assert "view_agent_graph" in message
    assert "create_agent" in message
    assert "攻击面分析专家" in message
    assert "全部请求" in message


def test_feature_workflow_dispatch_nudge_requires_batch_specialists() -> None:
    snapshot = ProxyCaptureSnapshot(
        recent_request_count=10,
        recent_request_has_more=True,
        latest_request_id="req-53",
        latest_method="POST",
        latest_host="app-sit.example.com",
        latest_path="/api/login",
        latest_status_code=403,
    )

    message = StrixTUIApp._feature_workflow_delegation_nudge_message(
        snapshot,
        phase="dispatch",
    )

    assert "攻击面分析专家已经完成映射" in message
    assert "批量" in message
    assert "create_vulnerability_report" in message
    assert "wait_for_message" in message


def test_should_nudge_feature_workflow_delegation_when_root_has_no_children() -> None:
    app = SimpleNamespace(
        _manual_burp_workflow=True,
        scan_config={"burp_port": 8081},
        _burp_workflow_phase="testing",
        live_view=SimpleNamespace(agents={"root": {"parent_id": None, "status": "running"}}),
        _feature_test_started_at_monotonic=100.0,
        _feature_workflow_active_batch_key="req-53",
        _feature_workflow_last_nudged_batch_key="",
        _feature_workflow_last_nudge_at_monotonic=0.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_DELAY_SECONDS=8.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_COOLDOWN_SECONDS=20.0,
    )

    assert (
        StrixTUIApp._should_nudge_feature_workflow_delegation(  # type: ignore[arg-type]
            app, "root", now_monotonic=109.0
        )
        is True
    )


def test_should_nudge_when_only_narrow_specialist_exists() -> None:
    app = SimpleNamespace(
        _manual_burp_workflow=True,
        scan_config={"burp_port": 8081},
        _burp_workflow_phase="testing",
        live_view=SimpleNamespace(
            agents={
                "root": {"parent_id": None, "status": "running"},
                "child": {
                    "parent_id": "root",
                    "status": "running",
                    "name": "XSS 专家",
                },
            }
        ),
        _feature_test_started_at_monotonic=100.0,
        _feature_workflow_active_batch_key="req-53",
        _feature_workflow_last_nudged_batch_key="",
        _feature_workflow_last_nudge_at_monotonic=0.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_DELAY_SECONDS=8.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_COOLDOWN_SECONDS=20.0,
    )

    assert (
        StrixTUIApp._should_nudge_feature_workflow_delegation(  # type: ignore[arg-type]
            app, "root", now_monotonic=109.0
        )
        is True
    )


def test_should_wait_for_mapping_before_dispatch_nudge() -> None:
    app = SimpleNamespace(
        _manual_burp_workflow=True,
        scan_config={"burp_port": 8081},
        _burp_workflow_phase="testing",
        live_view=SimpleNamespace(
            agents={
                "root": {"parent_id": None, "status": "running"},
                "mapper": {
                    "parent_id": "root",
                    "status": "running",
                    "name": "当前功能点攻击面分析专家",
                },
            }
        ),
        _feature_test_started_at_monotonic=100.0,
        _feature_workflow_active_batch_key="req-53",
        _feature_workflow_last_nudged_batch_key="",
        _feature_workflow_last_nudge_at_monotonic=0.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_DELAY_SECONDS=8.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_COOLDOWN_SECONDS=20.0,
    )

    assert (
        StrixTUIApp._should_nudge_feature_workflow_delegation(  # type: ignore[arg-type]
            app, "root", now_monotonic=109.0
        )
        is False
    )


def test_should_nudge_batch_dispatch_after_mapping_finishes() -> None:
    app = SimpleNamespace(
        _manual_burp_workflow=True,
        scan_config={"burp_port": 8081},
        _burp_workflow_phase="testing",
        live_view=SimpleNamespace(
            agents={
                "root": {"parent_id": None, "status": "running"},
                "mapper": {
                    "parent_id": "root",
                    "status": "completed",
                    "name": "当前功能点攻击面分析专家",
                },
            }
        ),
        _feature_test_started_at_monotonic=100.0,
        _feature_workflow_active_batch_key="req-53",
        _feature_workflow_last_nudged_batch_key="req-53:mapping",
        _feature_workflow_last_nudge_at_monotonic=110.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_DELAY_SECONDS=8.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_COOLDOWN_SECONDS=20.0,
    )

    assert (
        StrixTUIApp._should_nudge_feature_workflow_delegation(  # type: ignore[arg-type]
            app, "root", now_monotonic=120.0
        )
        is True
    )


def test_no_dispatch_nudge_when_mapping_and_specialist_exist() -> None:
    app = SimpleNamespace(
        _manual_burp_workflow=True,
        scan_config={"burp_port": 8081},
        _burp_workflow_phase="testing",
        live_view=SimpleNamespace(
            agents={
                "root": {"parent_id": None, "status": "running"},
                "mapper": {
                    "parent_id": "root",
                    "status": "completed",
                    "name": "当前功能点攻击面分析专家",
                },
                "xss": {
                    "parent_id": "root",
                    "status": "running",
                    "name": "XSS 专家",
                },
            }
        ),
        _feature_test_started_at_monotonic=100.0,
        _feature_workflow_active_batch_key="req-53",
        _feature_workflow_last_nudged_batch_key="",
        _feature_workflow_last_nudge_at_monotonic=0.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_DELAY_SECONDS=8.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_COOLDOWN_SECONDS=20.0,
    )

    assert (
        StrixTUIApp._should_nudge_feature_workflow_delegation(  # type: ignore[arg-type]
            app, "root", now_monotonic=109.0
        )
        is False
    )


def test_should_not_nudge_same_feature_batch_again_within_cooldown() -> None:
    app = SimpleNamespace(
        _manual_burp_workflow=True,
        scan_config={"burp_port": 8081},
        _burp_workflow_phase="testing",
        live_view=SimpleNamespace(agents={"root": {"parent_id": None, "status": "running"}}),
        _feature_test_started_at_monotonic=100.0,
        _feature_workflow_active_batch_key="req-53",
        _feature_workflow_last_nudged_batch_key="req-53:mapping",
        _feature_workflow_last_nudge_at_monotonic=110.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_DELAY_SECONDS=8.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_COOLDOWN_SECONDS=20.0,
    )

    assert (
        StrixTUIApp._should_nudge_feature_workflow_delegation(  # type: ignore[arg-type]
            app, "root", now_monotonic=120.0
        )
        is False
    )


def test_should_not_nudge_same_feature_batch_again_after_cooldown() -> None:
    app = SimpleNamespace(
        _manual_burp_workflow=True,
        scan_config={"burp_port": 8081},
        _burp_workflow_phase="testing",
        live_view=SimpleNamespace(agents={"root": {"parent_id": None, "status": "running"}}),
        _feature_test_started_at_monotonic=100.0,
        _feature_workflow_active_batch_key="req-53",
        _feature_workflow_last_nudged_batch_key="req-53:mapping",
        _feature_workflow_last_nudge_at_monotonic=110.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_DELAY_SECONDS=8.0,
        FEATURE_WORKFLOW_CHILD_AGENT_NUDGE_COOLDOWN_SECONDS=20.0,
    )

    assert (
        StrixTUIApp._should_nudge_feature_workflow_delegation(  # type: ignore[arg-type]
            app, "root", now_monotonic=999.0
        )
        is False
    )


def test_stop_feature_workflow_agents_only_stops_children(monkeypatch) -> None:
    class _Future:
        def add_done_callback(self, _callback) -> None:
            return

    seen: list[str] = []

    async def _cancel_children_graceful(agent_id: str) -> None:
        seen.append(agent_id)

    monkeypatch.setattr(
        "strix.interface.tui.app.asyncio.run_coroutine_threadsafe",
        lambda coro, _loop: (_ := asyncio.run(coro), _Future())[1],
    )
    app = SimpleNamespace(
        _scan_loop=SimpleNamespace(is_closed=lambda: False),
        coordinator=SimpleNamespace(cancel_children_graceful=_cancel_children_graceful),
        _log_async_action_failure=lambda _future: None,
    )

    assert StrixTUIApp._stop_feature_workflow_agents(app, "root") is True  # type: ignore[arg-type]
    assert seen == ["root"]
