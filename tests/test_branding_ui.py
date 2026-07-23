"""Tests for user-facing branding text in CLI and TUI."""

from __future__ import annotations

from rich.text import Text

from strix.interface import branding
from strix.interface.cli import _build_branding_text
from strix.interface.tui.app import QuitScreen, SplashScreen


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


def test_normalize_repository_url_supports_https_and_ssh() -> None:
    assert (
        branding._normalize_repository_url("https://github.com/wpsec/strix-cn.git")
        == "github.com/wpsec/strix-cn"
    )
    assert (
        branding._normalize_repository_url("git@github.com:wpsec/strix-cn.git")
        == "github.com/wpsec/strix-cn"
    )
