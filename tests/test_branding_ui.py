"""Tests for user-facing branding text in CLI and TUI."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from rich.text import Text

import strix.core.agents as core_agents
from strix.interface import branding
from strix.interface.cli import _build_branding_text
from strix.interface.tui.app import QuitScreen, SplashScreen, StrixTUIApp


def test_branding_items_include_version_and_github(monkeypatch) -> None:
    monkeypatch.setattr(branding, "get_package_version", lambda: "9.9.9")
    monkeypatch.setattr(branding, "get_project_repository", lambda: "github.com/wpsec/strix-cn")
    monkeypatch.setattr(branding, "get_repository_label", lambda: "GitHub")

    items = branding.branding_items()

    assert ("版本", "v9.9.9") in items
    assert ("GitHub", "github.com/wpsec/strix-cn") in items


def test_cli_branding_text_includes_version_and_github(monkeypatch) -> None:
    monkeypatch.setattr(branding, "get_package_version", lambda: "2.3.4")
    monkeypatch.setattr(branding, "get_project_repository", lambda: "github.com/wpsec/strix-cn")
    monkeypatch.setattr(branding, "get_repository_label", lambda: "GitHub")

    text = _build_branding_text()

    assert isinstance(text, Text)
    assert "版本  v2.3.4" in text.plain
    assert "GitHub  github.com/wpsec/strix-cn" in text.plain


def test_tui_branding_texts_include_github_and_version(monkeypatch) -> None:
    monkeypatch.setattr(branding, "get_package_version", lambda: "3.4.5")
    monkeypatch.setattr(branding, "get_project_repository", lambda: "github.com/wpsec/strix-cn")
    monkeypatch.setattr(branding, "get_repository_label", lambda: "GitHub")

    splash_text = SplashScreen()._build_url_text().plain
    quit_meta = QuitScreen._build_meta_text()

    assert "strix.ai" in splash_text
    assert "GitHub github.com/wpsec/strix-cn" in splash_text
    assert "版本 v3.4.5" in quit_meta
    assert "GitHub github.com/wpsec/strix-cn" in quit_meta


def test_tui_app_initializes_cached_version(monkeypatch) -> None:
    class _FakeReportState:
        def __init__(self, run_name: str) -> None:
            self.run_name = run_name
            self.proxy_capture_state = SimpleNamespace(total_request_count=0)
            self.vulnerability_reports: list[dict[str, str]] = []

        def hydrate_from_run_dir(self) -> None:
            return

        def set_scan_config(self, scan_config) -> None:
            self.scan_config = scan_config

        def save_run_data(self) -> None:
            return

        def get_run_dir(self) -> Path:
            return Path(".")

    class _FakeLiveView:
        def __init__(self) -> None:
            self.agents: dict[str, dict[str, str]] = {}

        def hydrate_from_run_dir(self, _run_dir: Path) -> None:
            return

    class _FakeAgentCoordinator:
        pass

    monkeypatch.setattr("strix.interface.tui.app.get_package_version", lambda: "7.8.9")
    monkeypatch.setattr("strix.interface.tui.app.ReportState", _FakeReportState)
    monkeypatch.setattr("strix.interface.tui.app.TuiLiveView", _FakeLiveView)
    monkeypatch.setattr("strix.interface.tui.app.set_global_report_state", lambda _state: None)
    monkeypatch.setattr(StrixTUIApp, "_setup_cleanup_handlers", lambda self: None)
    monkeypatch.setattr(core_agents, "AgentCoordinator", _FakeAgentCoordinator)

    args = SimpleNamespace(
        run_name="test-run",
        targets_info=[],
        instruction=None,
        diff_scope=None,
        scan_mode="deep",
        non_interactive=False,
        local_sources=[],
        scope_mode="auto",
        diff_base=None,
        burp_port=None,
        user_explicit_instruction=None,
    )

    app = StrixTUIApp(args)

    assert app._version == "7.8.9"


def test_normalize_repository_url_supports_https_and_ssh() -> None:
    assert (
        branding._normalize_repository_url("https://github.com/wpsec/strix-cn.git")
        == "github.com/wpsec/strix-cn"
    )
    assert (
        branding._normalize_repository_url("git@github.com:wpsec/strix-cn.git")
        == "github.com/wpsec/strix-cn"
    )
