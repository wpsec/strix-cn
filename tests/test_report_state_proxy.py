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
            latest_request_created_at="2026-08-11T10:36:42+08:00",
            latest_method="POST",
            latest_host="app.example.com",
            latest_path="/api/login",
            latest_status_code=200,
            latest_request_source="replay",
            latest_request_category="replay",
            latest_operator_request_id="req-2",
            latest_operator_request_source="intercept",
            latest_operator_method="GET",
            latest_operator_host="app.example.com",
            latest_operator_path="/api/profile",
            latest_operator_status_code=200,
            total_request_count=27,
            operator_request_count=2,
            replay_request_count=25,
            unclassified_request_count=0,
            endpoint_request_counts=(("GET app.example.com/api/profile", 2),),
        ),
        persist=True,
    )

    payload = json.loads((tmp_path / "run" / "run.json").read_text(encoding="utf-8"))
    assert payload["caido_url"] == "http://127.0.0.1:52123"
    assert payload["caido_ui_url"] == "http://127.0.0.1:52124"
    assert payload["proxy_scope_id"] == "scope-1"
    assert payload["proxy_scope_name"] == "strix-proxy-scope-run"
    assert payload["proxy_capture"]["latest_request_id"] == "req-3"
    assert payload["proxy_capture"]["latest_request_created_at"] == "2026-08-11T10:36:42+08:00"
    assert payload["proxy_capture"]["recent_request_has_more"] is True
    assert payload["proxy_capture"]["total_request_count"] == 27
    assert payload["proxy_capture"]["operator_request_count"] == 2
    assert payload["proxy_capture"]["replay_request_count"] == 25
    assert payload["proxy_capture"]["latest_request_source"] == "replay"
    assert payload["proxy_capture"]["latest_request_category"] == "replay"
    assert payload["proxy_capture"]["latest_operator_request_id"] == "req-2"
    assert payload["proxy_capture"]["endpoint_request_counts"] == [
        ["GET app.example.com/api/profile", 2],
    ]

    restored = ReportState(run_name="run")
    _patch_run_dir(monkeypatch, tmp_path)
    restored.hydrate_from_run_dir()

    assert restored.caido_url == "http://127.0.0.1:52123"
    assert restored.caido_ui_url == "http://127.0.0.1:52124"
    assert restored.proxy_scope_id == "scope-1"
    assert restored.proxy_scope_name == "strix-proxy-scope-run"
    assert restored.proxy_capture_state.latest_request_id == "req-3"
    assert restored.proxy_capture_state.latest_request_created_at == "2026-08-11T10:36:42+08:00"
    assert restored.proxy_capture_state.recent_request_count == 3
    assert restored.proxy_capture_state.total_request_count == 27
    assert restored.proxy_capture_state.operator_request_count == 2
    assert restored.proxy_capture_state.replay_request_count == 25
    assert restored.proxy_capture_state.latest_request_source == "replay"
    assert restored.proxy_capture_state.latest_request_category == "replay"
    assert restored.proxy_capture_state.latest_operator_request_id == "req-2"
    assert restored.proxy_capture_state.endpoint_request_counts == (
        ("GET app.example.com/api/profile", 2),
    )
    assert restored.burp_upstream_unavailable_reason is None

    legacy_payload = dict(payload)
    legacy_payload["proxy_capture"] = {
        "total_request_count": 3,
        "endpoint_request_counts": [["POST app.example.com/api/login", 3]],
    }
    (tmp_path / "run" / "run.json").write_text(
        json.dumps(legacy_payload),
        encoding="utf-8",
    )
    legacy_restored = ReportState(run_name="run")
    legacy_restored.hydrate_from_run_dir()

    assert legacy_restored.proxy_capture_state.total_request_count == 3
    assert legacy_restored.proxy_capture_state.unclassified_request_count == 3
    assert legacy_restored.proxy_capture_state.endpoint_request_counts == ()


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


def test_proxy_feature_boundary_epoch_advances_on_switch() -> None:
    from strix.report.state import ReportState

    state = ReportState()
    start = state.proxy_batch_epoch
    state.set_proxy_feature_boundary(captured_before="2026-09-04T10:00:00", captured_after=None)
    assert state.proxy_batch_epoch == start + 1
    state.clear_proxy_feature_boundary()
    assert state.proxy_batch_epoch == start + 2
