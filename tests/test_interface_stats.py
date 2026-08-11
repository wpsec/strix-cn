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
        burp_workflow_phase: str = "",
        proxy_feature_request_count: int = 0,
    ) -> None:
        self.vulnerability_reports: list[dict[str, Any]] = []
        self.run_record = {"llm_usage": {}}
        self.caido_url = caido_url
        self.caido_ui_url = caido_ui_url
        self.burp_upstream_unavailable_reason = unavailable_reason
        self.proxy_capture_state = proxy_capture_state or ProxyCaptureState()
        self.proxy_capture_error = None
        self.burp_workflow_phase = burp_workflow_phase
        self.proxy_feature_request_count = proxy_feature_request_count

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
            latest_host="app-sit.example.com",
            latest_path="/api/levels/current",
            latest_status_code=200,
            total_request_count=37,
        )
    )

    live_text = build_live_stats_text(report_state).plain
    tui_text = build_tui_stats_text(report_state).plain

    assert "代理捕获: 累计 37 条" in live_text
    assert "最近批次: 10+ 条" in live_text
    assert "最近流量: POST app-sit.example.com/api/levels/current [200]" in live_text
    assert "代理捕获: 累计 37 条" in tui_text
    assert "最近批次: 10+ 条" in tui_text


def test_tui_stats_show_burp_workflow_phase() -> None:
    text = build_tui_stats_text(
        _ReportState(
            burp_workflow_phase="capture",
            proxy_feature_request_count=12,
            proxy_capture_state=ProxyCaptureState(total_request_count=42),
        )
    ).plain

    assert "工作流: 功能点采集" in text
    assert "操作: 发送“开始测试”启动当前功能点分析" in text
    assert "代理捕获: 累计 42 条" in text
    assert "当前功能: 12 条" in text


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
    assert "发送“开始测试”" in text
