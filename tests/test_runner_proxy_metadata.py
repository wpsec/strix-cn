"""Tests for Burp proxy metadata flowing from the runtime bundle into ReportState."""

from __future__ import annotations

import types
from typing import Any

import pytest

import strix.report.state as report_state_module
import strix.tools.notes.tools as notes_tools
import strix.tools.todo.tools as todo_tools
from strix.core import runner
from strix.core.agents import AgentCoordinator
from strix.report.state import ReportState


def _patch_runner_scaffold(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
    *,
    runtime_bundle: dict[str, Any],
) -> None:
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)
    monkeypatch.setattr(report_state_module, "run_dir_for", lambda _run_name: tmp_path)

    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="openai/gpt-4o",
            reasoning_effort="high",
            force_required_tool_choice=False,
            timeout=300,
        ),
        runtime=types.SimpleNamespace(max_context_images=3),
    )
    monkeypatch.setattr(runner, "load_settings", lambda: settings)
    monkeypatch.setattr(runner, "configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(runner, "uses_chat_completions_tool_schema", lambda *_args: False)

    monkeypatch.setattr(todo_tools, "hydrate_todos_from_disk", lambda _state_dir: None)
    monkeypatch.setattr(notes_tools, "hydrate_notes_from_disk", lambda _state_dir: None)

    async def _create_or_reuse(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return runtime_bundle

    async def _cleanup(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(runner.session_manager, "create_or_reuse", _create_or_reuse)
    monkeypatch.setattr(runner.session_manager, "cleanup", _cleanup)

    monkeypatch.setattr(runner, "build_root_task", lambda _scan_config: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _scan_config: {"scope": "built-in"})
    monkeypatch.setattr(runner, "make_model_settings", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(runner, "build_strix_agent", lambda **_kwargs: object())
    monkeypatch.setattr(runner, "make_child_factory", lambda **_kwargs: lambda **_k: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db: object())

    async def _return_none(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(runner, "run_agent_loop", _return_none)


@pytest.mark.asyncio
async def test_runner_persists_burp_proxy_metadata_into_report_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    _patch_runner_scaffold(
        monkeypatch,
        tmp_path,
        runtime_bundle={
            "client": object(),
            "session": object(),
            "caido_client": None,
            "caido_url": "http://127.0.0.1:52123",
            "burp_upstream_unavailable_reason": None,
        },
    )

    report_state = ReportState(run_name="scan-burp")
    report_state.set_scan_config({"targets": [], "scan_mode": "deep"})
    report_state_module.set_global_report_state(report_state)

    try:
        await runner.run_strix_scan(
            scan_config={"targets": [], "scan_mode": "deep"},
            scan_id="scan-burp",
            image="img",
            coordinator=AgentCoordinator(),
        )
    finally:
        report_state_module._global_report_state = None

    assert report_state.caido_url == "http://127.0.0.1:52123"
    assert report_state.run_record["caido_url"] == "http://127.0.0.1:52123"
    assert report_state.burp_upstream_unavailable_reason is None
