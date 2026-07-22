"""Tests for Burp upstream proxy status rendered in CLI/TUI stats."""

from __future__ import annotations

from typing import Any

from strix.interface.utils import (
    build_live_stats_text,
    build_target_summary_text,
    build_tui_stats_text,
)


class _ReportState:
    def __init__(
        self,
        *,
        caido_url: str | None = None,
        unavailable_reason: str | None = None,
    ) -> None:
        self.vulnerability_reports: list[dict[str, Any]] = []
        self.run_record = {"llm_usage": {}}
        self.caido_url = caido_url
        self.burp_upstream_unavailable_reason = unavailable_reason

    def get_total_llm_usage(self) -> dict[str, Any]:
        return {}


def test_live_stats_show_burp_upstream_endpoint_without_scheme() -> None:
    text = build_live_stats_text(_ReportState(caido_url="http://127.0.0.1:52123")).plain

    assert "Burp 上游代理: 127.0.0.1:52123" in text
    assert "仅本机可访问" in text
    assert "http://127.0.0.1:52123" not in text


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
