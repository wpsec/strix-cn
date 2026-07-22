"""Tests for Burp/caido proxy metadata persisted by ReportState."""

from __future__ import annotations

import json
from pathlib import Path

import strix.report.state as report_state_module
from strix.report.state import ProxyCaptureState, ReportState


def _patch_run_dir(monkeypatch: object, tmp_path: Path) -> None:
    monkeypatch.setattr(report_state_module, "run_dir_for", lambda _run_name: tmp_path / "run")


def test_caido_url_round_trips_via_run_record(
    monkeypatch: object,
    tmp_path: Path,
) -> None:
    _patch_run_dir(monkeypatch, tmp_path)

    state = ReportState(run_name="run")
    state.set_scan_config({"targets": [], "scan_mode": "deep"})
    state.set_caido_connection(
        "http://127.0.0.1:52123",
        ui_url="http://127.0.0.1:52124",
    )
    state.set_proxy_scope("scope-1", scope_name="strix-proxy-scope-run")
    state.update_proxy_capture_state(
        ProxyCaptureState(
            recent_request_count=3,
            recent_request_has_more=True,
            latest_request_id="req-3",
            latest_method="POST",
            latest_host="app.example.com",
            latest_path="/api/login",
            latest_status_code=200,
        ),
        persist=True,
    )

    payload = json.loads((tmp_path / "run" / "run.json").read_text(encoding="utf-8"))
    assert payload["caido_url"] == "http://127.0.0.1:52123"
    assert payload["caido_ui_url"] == "http://127.0.0.1:52124"
    assert payload["proxy_scope_id"] == "scope-1"
    assert payload["proxy_scope_name"] == "strix-proxy-scope-run"
    assert payload["proxy_capture"]["latest_request_id"] == "req-3"
    assert payload["proxy_capture"]["recent_request_has_more"] is True

    restored = ReportState(run_name="run")
    _patch_run_dir(monkeypatch, tmp_path)
    restored.hydrate_from_run_dir()

    assert restored.caido_url == "http://127.0.0.1:52123"
    assert restored.caido_ui_url == "http://127.0.0.1:52124"
    assert restored.proxy_scope_id == "scope-1"
    assert restored.proxy_scope_name == "strix-proxy-scope-run"
    assert restored.proxy_capture_state.latest_request_id == "req-3"
    assert restored.proxy_capture_state.recent_request_count == 3
    assert restored.burp_upstream_unavailable_reason is None


def test_set_scan_config_clears_stale_caido_url(
    monkeypatch: object,
    tmp_path: Path,
) -> None:
    _patch_run_dir(monkeypatch, tmp_path)

    state = ReportState(run_name="run")
    state.set_scan_config({"targets": [], "scan_mode": "deep"})
    state.set_caido_connection(
        "http://127.0.0.1:52123",
        ui_url="http://127.0.0.1:52124",
        unavailable_reason="当前运行模式未提供仅本机可访问的 Burp 上游代理端口",
    )
    state.set_proxy_scope("scope-1", scope_name="strix-proxy-scope-run")
    state.update_proxy_capture_state(
        ProxyCaptureState(recent_request_count=1, latest_request_id="req-1"),
    )

    state.set_scan_config({"targets": [], "scan_mode": "deep"})
    state.save_run_data()

    payload = json.loads((tmp_path / "run" / "run.json").read_text(encoding="utf-8"))
    assert state.caido_url is None
    assert state.caido_ui_url is None
    assert state.burp_upstream_unavailable_reason is None
    assert state.proxy_scope_id is None
    assert state.proxy_scope_name is None
    assert state.proxy_capture_state.recent_request_count == 0
    assert "caido_url" not in payload
    assert "caido_ui_url" not in payload
    assert "proxy_scope_id" not in payload
    assert "proxy_scope_name" not in payload
    assert "proxy_capture" not in payload
