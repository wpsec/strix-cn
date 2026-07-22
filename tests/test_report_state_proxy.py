"""Tests for Burp/caido proxy metadata persisted by ReportState."""

from __future__ import annotations

import json
from pathlib import Path

import strix.report.state as report_state_module
from strix.report.state import ReportState


def _patch_run_dir(monkeypatch: object, tmp_path: Path) -> None:
    monkeypatch.setattr(report_state_module, "run_dir_for", lambda _run_name: tmp_path / "run")


def test_caido_url_round_trips_via_run_record(
    monkeypatch: object,
    tmp_path: Path,
) -> None:
    _patch_run_dir(monkeypatch, tmp_path)

    state = ReportState(run_name="run")
    state.set_scan_config({"targets": [], "scan_mode": "deep"})
    state.set_caido_connection("http://127.0.0.1:52123")

    payload = json.loads((tmp_path / "run" / "run.json").read_text(encoding="utf-8"))
    assert payload["caido_url"] == "http://127.0.0.1:52123"

    restored = ReportState(run_name="run")
    _patch_run_dir(monkeypatch, tmp_path)
    restored.hydrate_from_run_dir()

    assert restored.caido_url == "http://127.0.0.1:52123"
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
        unavailable_reason="当前运行模式未提供仅本机可访问的 Burp 上游代理端口",
    )

    state.set_scan_config({"targets": [], "scan_mode": "deep"})
    state.save_run_data()

    payload = json.loads((tmp_path / "run" / "run.json").read_text(encoding="utf-8"))
    assert state.caido_url is None
    assert state.burp_upstream_unavailable_reason is None
    assert "caido_url" not in payload
