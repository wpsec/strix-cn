"""Tests for localized user-facing strings in the Go TUI era."""

from __future__ import annotations

import importlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from rich.text import Text

from strix.interface import interactive
from strix.interface.tui.runtime import GoTuiPreActivationError
from strix.interface.utils import build_target_summary_text

main_module = importlib.import_module("strix.interface.main")


def _flatten_printed(items: list[object]) -> str:
    parts: list[str] = []
    for item in items:
        if isinstance(item, Text):
            parts.append(item.plain)
        else:
            parts.append(str(item))
    return "".join(parts)


def test_build_target_summary_text_uses_chinese_for_burp_passive_mode() -> None:
    text = build_target_summary_text([], burp_port=8081).plain
    assert "目标" in text
    assert "Burp 被动模式" in text
    assert "仅基于 Burp 转发流量建立作用域" in text


@pytest.mark.asyncio
async def test_run_tui_wraps_pre_activation_error_in_chinese(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _raise(_args: object) -> None:
        raise GoTuiPreActivationError("sidecar crashed before activation")

    monkeypatch.setattr("strix.interface.tui.runtime.run_go_tui", _raise)

    with pytest.raises(interactive.InteractiveSetupUnavailableError) as exc:
        await interactive.run_tui(SimpleNamespace())

    assert str(exc.value) == "交互界面启动失败：sidecar crashed before activation"


def test_display_completion_message_uses_chinese_labels_and_resume_hint(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    printed: list[object] = []

    class _FakeConsole:
        def print(self, *args: object) -> None:
            printed.extend(args)

    report_state = SimpleNamespace(
        run_record={"status": "stopped"},
        total_requests=0,
        vulnerabilities=[],
        vulnerability_reports=[],
        completed_agents=0,
        active_agents=0,
        failed_agents=0,
        total_estimated_cost=0.0,
    )

    monkeypatch.setattr(main_module, "Console", lambda: _FakeConsole())
    monkeypatch.setattr(main_module, "Panel", lambda content, **_kwargs: content)
    monkeypatch.setattr("strix.report.state.get_global_report_state", lambda: report_state)

    args = SimpleNamespace(
        targets_info=[{"original": "https://app.example.com"}],
        run_name="pentest_demo",
        non_interactive=True,
    )
    main_module.display_completion_message(args, tmp_path / "results")

    plain = _flatten_printed(printed)
    assert "本次会话已结束" in plain
    assert "目标" in plain
    assert "输出目录" in plain
    assert "查看" in plain
    assert "继续运行" in plain
    assert "strix --resume pentest_demo" in plain
