"""Tests for the TUI terminal copy mode toggle."""

from __future__ import annotations

from typing import Any

from strix.interface.tui.app import StrixTUIApp, _set_driver_mouse_support


class _FakeDriver:
    def __init__(self) -> None:
        self.enabled_calls = 0
        self.disabled_calls = 0

    def _enable_mouse_support(self) -> None:
        self.enabled_calls += 1

    def _disable_mouse_support(self) -> None:
        self.disabled_calls += 1


class _DummyApp:
    def __init__(self, driver: Any) -> None:
        self.show_splash = False
        self._driver = driver
        self.terminal_copy_mode = False
        self.cleared = 0
        self.notifications: list[tuple[str, dict[str, Any]]] = []

    def clear_selection(self) -> None:
        self.cleared += 1

    def notify(self, message: str, **kwargs: Any) -> None:
        self.notifications.append((message, kwargs))


def test_set_driver_mouse_support_toggles_private_driver_methods() -> None:
    driver = _FakeDriver()

    assert _set_driver_mouse_support(driver, enabled=False) is True
    assert _set_driver_mouse_support(driver, enabled=True) is True
    assert driver.disabled_calls == 1
    assert driver.enabled_calls == 1


def test_action_toggle_terminal_copy_mode_switches_between_copy_and_interaction() -> None:
    driver = _FakeDriver()
    app = _DummyApp(driver)

    StrixTUIApp.action_toggle_terminal_copy_mode(app)  # type: ignore[arg-type]

    assert app.terminal_copy_mode is True
    assert driver.disabled_calls == 1
    assert app.cleared == 1
    assert "终端复制模式已开启" in app.notifications[-1][0]

    StrixTUIApp.action_toggle_terminal_copy_mode(app)  # type: ignore[arg-type]

    assert app.terminal_copy_mode is False
    assert driver.enabled_calls == 1
    assert app.cleared == 2
    assert "已返回交互模式" in app.notifications[-1][0]


def test_action_toggle_terminal_copy_mode_warns_when_driver_cannot_toggle() -> None:
    app = _DummyApp(driver=object())

    StrixTUIApp.action_toggle_terminal_copy_mode(app)  # type: ignore[arg-type]

    assert app.terminal_copy_mode is False
    assert app.cleared == 0
    assert app.notifications[-1][0] == "当前终端不支持切换复制模式"
    assert app.notifications[-1][1]["severity"] == "warning"
