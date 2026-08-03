"""Tests for TUI proxy-traffic monitor helpers."""

from __future__ import annotations

from types import SimpleNamespace

from strix.interface.tui.app import StrixTUIApp
from strix.runtime.proxy_capture import ProxyCaptureSnapshot


class _ImmediateFuture:
    def __init__(self, value: object) -> None:
        self._value = value

    def result(self, timeout: float | None = None) -> object:  # noqa: ARG002
        return self._value


def test_should_auto_resume_from_proxy_when_new_request_arrives() -> None:
    app = SimpleNamespace(
        scan_config={"burp_port": 8082},
        _last_proxy_notified_request_id="req-1",
        _manual_burp_workflow=False,
    )
    snapshot = ProxyCaptureSnapshot(
        recent_request_count=3,
        recent_request_has_more=False,
        latest_request_id="req-2",
        latest_method="POST",
        latest_host="app.example.com",
        latest_path="/api/login",
        latest_status_code=200,
    )

    assert StrixTUIApp._should_auto_resume_from_proxy(app, snapshot) is True  # type: ignore[arg-type]


def test_should_not_auto_resume_in_manual_burp_workflow() -> None:
    app = SimpleNamespace(
        scan_config={"burp_port": 8082},
        _last_proxy_notified_request_id="req-1",
        _manual_burp_workflow=True,
    )
    snapshot = ProxyCaptureSnapshot(
        recent_request_count=3,
        recent_request_has_more=False,
        latest_request_id="req-2",
        latest_method="POST",
        latest_host="app.example.com",
        latest_path="/api/login",
        latest_status_code=200,
    )

    assert StrixTUIApp._should_auto_resume_from_proxy(app, snapshot) is False  # type: ignore[arg-type]


def test_should_not_auto_resume_without_new_request_or_burp_mode() -> None:
    snapshot = ProxyCaptureSnapshot(
        recent_request_count=1,
        recent_request_has_more=False,
        latest_request_id="req-1",
        latest_method="GET",
        latest_host="app.example.com",
        latest_path="/health",
        latest_status_code=200,
    )

    same_request_app = SimpleNamespace(
        scan_config={"burp_port": 8082},
        _last_proxy_notified_request_id="req-1",
        _manual_burp_workflow=False,
    )
    no_burp_app = SimpleNamespace(
        scan_config={},
        _last_proxy_notified_request_id=None,
        _manual_burp_workflow=False,
    )

    assert StrixTUIApp._should_auto_resume_from_proxy(same_request_app, snapshot) is False  # type: ignore[arg-type]
    assert StrixTUIApp._should_auto_resume_from_proxy(no_burp_app, snapshot) is False  # type: ignore[arg-type]


def test_proxy_resume_message_mentions_recent_capture_count() -> None:
    snapshot = ProxyCaptureSnapshot(
        recent_request_count=10,
        recent_request_has_more=True,
        latest_request_id="req-10",
        latest_method="POST",
        latest_host="app.example.com",
        latest_path="/api/orders",
        latest_status_code=200,
    )

    message = StrixTUIApp._proxy_resume_message(snapshot)

    assert "Burp 代理流量" in message
    assert "10+" in message
    assert "重新检查代理历史、站点地图和代理图" in message
    assert "代理图" in message
    assert "send_message_to_agent" in message


def test_feature_test_start_message_scopes_current_feature_and_waits_after_completion() -> None:
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

    assert "当前功能点的手工点击和流量采集已完成" in message
    assert "只基于本轮最新 Burp 捕获流量" in message
    assert "wait_for_message" in message
    assert "POST app.example.com/api/orders/submit [403]" in message


def test_waiting_placeholder_message_guides_burp_capture_phase() -> None:
    app = SimpleNamespace(
        scan_config={"burp_port": 8081},
        _burp_workflow_phase="capture",
        live_view=SimpleNamespace(agents={"root": {"status": "waiting"}}),
    )

    message = StrixTUIApp._waiting_placeholder_message(app, "root")  # type: ignore[arg-type]

    assert message == "代理已就绪，正在等待你采集当前功能点。采集完成后按 Ctrl+T 开始测试。"


def test_waiting_placeholder_message_falls_back_for_non_burp_waiting_agent() -> None:
    app = SimpleNamespace(
        scan_config={},
        _burp_workflow_phase="idle",
        live_view=SimpleNamespace(agents={"root": {"status": "waiting"}}),
    )

    message = StrixTUIApp._waiting_placeholder_message(app, "root")  # type: ignore[arg-type]

    assert message == "代理当前处于等待状态，等待新的消息或输入。"


def test_no_activity_placeholder_message_reports_stopped_agent_truthfully() -> None:
    app = SimpleNamespace(
        live_view=SimpleNamespace(agents={"root": {"status": "stopped"}}),
        _waiting_placeholder_message=lambda _agent_id: None,
    )

    message = StrixTUIApp._no_activity_placeholder_message(app, "root")  # type: ignore[arg-type]

    assert message == "代理已停止，当前会话不会继续处理新的测试任务。"


def test_select_root_agent_for_proxy_resume_accepts_waiting_and_running_root() -> None:
    parent_of = {"root": None, "child": "root"}

    assert StrixTUIApp._select_root_agent_for_proxy_resume(parent_of, {"root": "waiting"}) == (
        "root",
        "waiting",
    )
    assert StrixTUIApp._select_root_agent_for_proxy_resume(parent_of, {"root": "running"}) == (
        "root",
        "running",
    )


def test_select_root_agent_for_proxy_resume_ignores_completed_root() -> None:
    parent_of = {"root": None, "child": "root"}

    assert StrixTUIApp._select_root_agent_for_proxy_resume(parent_of, {"root": "completed"}) == (
        None,
        None,
    )


def test_root_agent_helpers_accept_four_value_graph_snapshot(monkeypatch) -> None:
    snapshot = (
        {"root": None, "child": "root"},
        {"root": "waiting", "child": "running"},
        {"root": "Strix", "child": "SQLi"},
        {"root": "", "child": ""},
    )
    monkeypatch.setattr(
        "strix.interface.tui.app.asyncio.run_coroutine_threadsafe",
        lambda _coro, _loop: _ImmediateFuture(snapshot),
    )
    app = SimpleNamespace(
        _scan_loop=SimpleNamespace(is_closed=lambda: False),
        coordinator=SimpleNamespace(graph_snapshot=lambda: None),
        _select_root_agent_for_proxy_resume=StrixTUIApp._select_root_agent_for_proxy_resume,
    )

    assert StrixTUIApp._root_agent_for_proxy_resume(app) == ("root", "waiting")  # type: ignore[arg-type]
    assert StrixTUIApp._root_agent_for_feature_workflow(app) == ("root", "waiting")  # type: ignore[arg-type]


def test_root_agent_helpers_prefer_synchronized_live_graph() -> None:
    app = SimpleNamespace(
        live_view=SimpleNamespace(
            agents={
                "root": {"parent_id": None, "status": "waiting"},
                "child": {"parent_id": "root", "status": "running"},
            }
        ),
        _scan_loop=SimpleNamespace(is_closed=lambda: False),
    )

    assert StrixTUIApp._root_agent_for_proxy_resume(app) == ("root", "waiting")  # type: ignore[arg-type]
    assert StrixTUIApp._root_agent_for_feature_workflow(app) == ("root", "waiting")  # type: ignore[arg-type]


def test_root_agent_for_feature_workflow_ignores_stopped_root(monkeypatch) -> None:
    snapshot = (
        {"root": None},
        {"root": "stopped"},
        {"root": "Strix"},
        {"root": ""},
    )
    monkeypatch.setattr(
        "strix.interface.tui.app.asyncio.run_coroutine_threadsafe",
        lambda _coro, _loop: _ImmediateFuture(snapshot),
    )
    app = SimpleNamespace(
        _scan_loop=SimpleNamespace(is_closed=lambda: False),
        coordinator=SimpleNamespace(graph_snapshot=lambda: None),
    )

    assert StrixTUIApp._root_agent_for_feature_workflow(app) == (None, None)  # type: ignore[arg-type]


def test_waiting_placeholder_distinguishes_completed_feature_from_active_children() -> None:
    app = SimpleNamespace(
        scan_config={"burp_port": 8081},
        _burp_workflow_phase="testing",
        live_view=SimpleNamespace(
            agents={
                "root": {"status": "waiting"},
                "child": {"parent_id": "root", "status": "completed"},
            }
        ),
    )
    message = StrixTUIApp._waiting_placeholder_message(app, "root")  # type: ignore[arg-type]
    assert "等待下一功能点" in message

    app.live_view.agents["child"]["status"] = "running"
    message = StrixTUIApp._waiting_placeholder_message(app, "root")  # type: ignore[arg-type]
    assert "等待运行中的子 agent" in message


def test_should_dispatch_proxy_resume_immediately_for_waiting_root() -> None:
    app = SimpleNamespace(
        scan_config={"burp_port": 8082},
        _last_proxy_notified_request_id="req-1",
        _last_proxy_resume_dispatched_at=100.0,
        PROXY_RESUME_RUNNING_COOLDOWN_SECONDS=8.0,
    )
    snapshot = ProxyCaptureSnapshot(
        recent_request_count=2,
        recent_request_has_more=False,
        latest_request_id="req-2",
        latest_method="GET",
        latest_host="app.example.com",
        latest_path="/profile",
        latest_status_code=200,
    )

    assert (
        StrixTUIApp._should_dispatch_proxy_resume(  # type: ignore[arg-type]
            app, snapshot, "waiting", now_monotonic=101.0
        )
        is True
    )


def test_should_dispatch_proxy_resume_throttles_running_root_until_cooldown() -> None:
    app = SimpleNamespace(
        scan_config={"burp_port": 8082},
        _last_proxy_notified_request_id="req-1",
        _last_proxy_resume_dispatched_at=100.0,
        PROXY_RESUME_RUNNING_COOLDOWN_SECONDS=8.0,
    )
    snapshot = ProxyCaptureSnapshot(
        recent_request_count=4,
        recent_request_has_more=False,
        latest_request_id="req-2",
        latest_method="POST",
        latest_host="app.example.com",
        latest_path="/api/login",
        latest_status_code=200,
    )

    assert (
        StrixTUIApp._should_dispatch_proxy_resume(  # type: ignore[arg-type]
            app, snapshot, "running", now_monotonic=105.0
        )
        is False
    )
    assert (
        StrixTUIApp._should_dispatch_proxy_resume(  # type: ignore[arg-type]
            app, snapshot, "running", now_monotonic=108.0
        )
        is True
    )
