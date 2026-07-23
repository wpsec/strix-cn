"""Tests for TUI exit-time sandbox cleanup."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from strix.interface.tui.app import StrixTUIApp


def test_fire_sandbox_cleanup_waits_for_cleanup_completion() -> None:
    coordinator = SimpleNamespace(mark_shutting_down=MagicMock())
    loop = SimpleNamespace(is_closed=MagicMock(return_value=False))
    cleanup_future = SimpleNamespace(result=MagicMock())
    app = SimpleNamespace(
        coordinator=coordinator,
        _scan_loop=loop,
        scan_config={"run_name": "scan-123"},
    )

    def _run_coroutine_threadsafe(coro: object, _loop: object) -> object:
        close = getattr(coro, "close", None)
        if callable(close):
            close()
        return cleanup_future

    with patch(
        "strix.interface.tui.app.asyncio.run_coroutine_threadsafe",
        side_effect=_run_coroutine_threadsafe,
    ) as run_coroutine_threadsafe:
        cleaned = StrixTUIApp._fire_sandbox_cleanup(app, wait=True)  # type: ignore[arg-type]

    assert cleaned is True
    coordinator.mark_shutting_down.assert_called_once_with()
    run_coroutine_threadsafe.assert_called_once()
    cleanup_future.result.assert_called_once_with(timeout=5.0)


def test_cleanup_before_exit_stops_and_joins_running_scan_thread() -> None:
    scan_thread = MagicMock()
    scan_thread.is_alive.side_effect = [True, True]
    app = SimpleNamespace(
        _stop_proxy_monitor_thread=MagicMock(),
        _scan_thread=scan_thread,
        _scan_stop_event=SimpleNamespace(set=MagicMock()),
        _fire_sandbox_cleanup=MagicMock(return_value=True),
        report_state=SimpleNamespace(cleanup=MagicMock()),
    )

    StrixTUIApp._cleanup_before_exit(app)  # type: ignore[arg-type]

    app._stop_proxy_monitor_thread.assert_called_once_with()
    app._scan_stop_event.set.assert_called_once_with()
    app._fire_sandbox_cleanup.assert_called_once_with(wait=True)
    scan_thread.join.assert_called_once_with(timeout=1)
    app.report_state.cleanup.assert_called_once_with()


@pytest.mark.asyncio
async def test_action_custom_quit_runs_exit_cleanup_before_exiting() -> None:
    app = SimpleNamespace(
        _cleanup_before_exit=MagicMock(),
        exit=MagicMock(),
    )

    await StrixTUIApp.action_custom_quit(app)  # type: ignore[arg-type]

    app._cleanup_before_exit.assert_called_once_with()
    app.exit.assert_called_once_with()
