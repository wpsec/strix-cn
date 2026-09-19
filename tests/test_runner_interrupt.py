from __future__ import annotations

import asyncio
import types
from typing import Any

import pytest
from agents import ModelSettings

import strix.tools.notes.tools as notes_tools
import strix.tools.todo.tools as todo_tools
from strix.core import runner
from strix.core.agents import AgentCoordinator
from strix.runtime import session_manager


def _wire_runner(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> dict[str, Any]:
    monkeypatch.setattr(runner, "run_dir_for", lambda _scan_id: tmp_path)
    monkeypatch.setattr(runner, "runtime_state_dir", lambda _run_dir: tmp_path)
    monkeypatch.setattr(runner, "setup_scan_logging", lambda _run_dir: lambda: None)
    monkeypatch.setattr(runner, "set_scan_id", lambda _scan_id: None)

    settings = types.SimpleNamespace(
        llm=types.SimpleNamespace(
            model="openai/gpt-4o",
            reasoning_effort="high",
            force_required_tool_choice=False,
            timeout=300,
            prompt_cache=True,
            extra_headers=None,
        ),
        runtime=types.SimpleNamespace(max_context_images=3),
    )
    monkeypatch.setattr(runner, "load_settings", lambda: settings)
    monkeypatch.setattr(runner, "configure_sdk_model_defaults", lambda _settings: None)
    monkeypatch.setattr(
        runner, "uses_chat_completions_tool_schema", lambda _model, _settings: False
    )
    monkeypatch.setattr(todo_tools, "hydrate_todos_from_disk", lambda _state_dir: None)
    monkeypatch.setattr(notes_tools, "hydrate_notes_from_disk", lambda _state_dir: None)

    created: dict[str, Any] = {}

    async def _create_or_reuse(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        created.update(_kwargs)
        return {"client": object(), "session": object(), "caido_client": None}

    async def _cleanup(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(session_manager, "create_or_reuse", _create_or_reuse)
    monkeypatch.setattr(session_manager, "cleanup", _cleanup)
    monkeypatch.setattr(runner, "build_root_task", lambda _scan_config: "task")
    monkeypatch.setattr(runner, "build_scope_context", lambda _scan_config: {})
    monkeypatch.setattr(runner, "make_model_settings", lambda *_a, **_k: ModelSettings())
    monkeypatch.setattr(runner, "build_strix_agent", lambda **_kwargs: object())
    monkeypatch.setattr(runner, "make_child_factory", lambda **_kwargs: lambda **_k: object())
    monkeypatch.setattr(runner, "open_agent_session", lambda _root_id, _db: object())
    return created


def _root_status(coordinator: AgentCoordinator) -> str:
    roots = [aid for aid, parent in coordinator.parent_of.items() if parent is None]
    assert len(roots) == 1
    return coordinator.statuses[roots[0]]


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, asyncio.CancelledError])
@pytest.mark.asyncio
async def test_user_interrupt_leaves_the_root_running_for_resume(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any, interrupt: type[BaseException]
) -> None:
    created = _wire_runner(monkeypatch, tmp_path)

    async def _interrupt(*_args: Any, **_kwargs: Any) -> None:
        raise interrupt()

    monkeypatch.setattr(runner, "run_agent_loop", _interrupt)
    coordinator = AgentCoordinator()

    with pytest.raises(interrupt):
        await runner.run_strix_scan(
            scan_config={"targets": [], "scan_mode": "deep"},
            scan_id="scan-test",
            image="img",
            coordinator=coordinator,
        )

    assert _root_status(coordinator) == "running"
    assert created["persistent_workspace"] == tmp_path / "workspace"
    assert created["allow_stale_reap"] is False
    assert (tmp_path / "workspace").is_dir()


@pytest.mark.asyncio
async def test_a_real_crash_still_marks_root_failed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _wire_runner(monkeypatch, tmp_path)

    async def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr(runner, "run_agent_loop", _boom)
    coordinator = AgentCoordinator()

    with pytest.raises(RuntimeError, match="boom"):
        await runner.run_strix_scan(
            scan_config={"targets": [], "scan_mode": "deep"},
            scan_id="scan-test",
            image="img",
            coordinator=coordinator,
        )

    assert _root_status(coordinator) == "failed"


@pytest.mark.asyncio
async def test_cancellation_waits_for_sandbox_cleanup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Any
) -> None:
    _wire_runner(monkeypatch, tmp_path)
    cleanup_started = asyncio.Event()
    release_cleanup = asyncio.Event()
    cleanup_finished = asyncio.Event()

    async def _return_without_agent_loop(*_args: Any, **_kwargs: Any) -> None:
        return None

    async def _cleanup(*_args: Any, **_kwargs: Any) -> None:
        cleanup_started.set()
        await release_cleanup.wait()
        cleanup_finished.set()

    monkeypatch.setattr(runner, "run_agent_loop", _return_without_agent_loop)
    monkeypatch.setattr(session_manager, "cleanup", _cleanup)

    task = asyncio.create_task(
        runner.run_strix_scan(
            scan_config={"targets": [], "scan_mode": "deep"},
            scan_id="scan-cancel-cleanup",
            image="img",
            coordinator=AgentCoordinator(),
        )
    )
    await asyncio.wait_for(cleanup_started.wait(), timeout=5.0)

    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    assert not cleanup_finished.is_set()

    release_cleanup.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert cleanup_finished.is_set()
