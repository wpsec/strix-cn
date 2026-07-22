"""Tests for Burp upstream proxy status rendered in CLI/TUI stats."""

from __future__ import annotations

from typing import Any

from strix.interface.utils import (
    build_live_stats_text,
    build_target_summary_text,
    build_tui_stats_text,
)
from strix.report.state import ProxyCaptureState


class _ReportState:
    def __init__(
        self,
        *,
        caido_url: str | None = None,
        caido_ui_url: str | None = None,
        unavailable_reason: str | None = None,
        proxy_capture_state: ProxyCaptureState | None = None,
    ) -> None:
        self.vulnerability_reports: list[dict[str, Any]] = []
        self.run_record = {"llm_usage": {}}
        self.caido_url = caido_url
        self.caido_ui_url = caido_ui_url
        self.burp_upstream_unavailable_reason = unavailable_reason
        self.proxy_capture_state = proxy_capture_state or ProxyCaptureState()
        self.proxy_capture_error = None

    def get_total_llm_usage(self) -> dict[str, Any]:
        return {}


def test_live_stats_show_burp_upstream_endpoint_without_scheme() -> None:
    text = build_live_stats_text(
        _ReportState(
            caido_url="http://127.0.0.1:52123",
            caido_ui_url="http://127.0.0.1:52124",
        )
    ).plain

    assert "Burp 上游代理: 127.0.0.1:52123" in text
    assert "仅本机可访问" in text
    assert "Caido 工作台: 127.0.0.1:52124" in text
    assert "http://127.0.0.1:52123" not in text


def test_stats_show_recent_proxy_capture_summary() -> None:
    report_state = _ReportState(
        proxy_capture_state=ProxyCaptureState(
            recent_request_count=10,
            recent_request_has_more=True,
            latest_method="POST",
            latest_host="taxdev-sit.eytax.com.cn",
            latest_path="/bscapi/lite/level/getCurrentLevel",
            latest_status_code=200,
        )
    )

    live_text = build_live_stats_text(report_state).plain
    tui_text = build_tui_stats_text(report_state).plain

    assert "代理捕获: 最近 10+ 条" in live_text
    assert "最近流量: POST taxdev-sit.eytax.com.cn/bscapi/lite/level/getCurrentLevel [200]" in live_text
    assert "代理捕获: 最近 10+ 条" in tui_text


def test_tui_stats_show_unavailable_reason_without_fake_endpoint() -> None:
    text = build_tui_stats_text(
        _ReportState(
            unavailable_reason="当前自定义 sandbox network 模式未暴露可供 Burp 直连的本地代理端口"
        )
    ).plain

    assert "Burp 上游代理:" in text
    assert "sandbox network 模式" in text
    assert "127.0.0.1:" not in text


def test_target_summary_shows_burp_passive_mode_without_targets() -> None:
    text = build_target_summary_text([], burp_port=8081).plain

    assert "Burp 被动模式" in text
    assert "仅基于 Burp 转发流量建立作用域" in text
