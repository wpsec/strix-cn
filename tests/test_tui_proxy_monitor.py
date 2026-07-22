"""Tests for TUI proxy-traffic monitor helpers."""

from __future__ import annotations

from types import SimpleNamespace

from strix.interface.tui.app import StrixTUIApp
from strix.runtime.proxy_capture import ProxyCaptureSnapshot


def test_should_auto_resume_from_proxy_when_new_request_arrives() -> None:
    app = SimpleNamespace(
        scan_config={"burp_port": 8082},
        _last_proxy_notified_request_id="req-1",
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
    )
    no_burp_app = SimpleNamespace(
        scan_config={},
        _last_proxy_notified_request_id=None,
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
    assert "重新检查代理历史和站点地图" in message
