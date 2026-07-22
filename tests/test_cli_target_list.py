"""Tests for CLI target-list argument parsing."""

from __future__ import annotations

import importlib
import sys
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path


cli_main: Any = importlib.import_module("strix.interface.main")


def _stub_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        cli_main,
        "load_settings",
        lambda: SimpleNamespace(runtime=SimpleNamespace(max_local_copy_mb=1024)),
    )


def test_parse_arguments_accepts_target_list_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text(
        "https://test1.com/\n"
        "\n"
        "http://test2.com:5789/\n",
        encoding="utf-8",
    )
    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["strix", "--target-list", str(target_list), "-n"])

    args = cli_main.parse_arguments()

    assert [target["original"] for target in args.targets_info] == [
        "https://test1.com/",
        "http://test2.com:5789/",
    ]
    assert [target["type"] for target in args.targets_info] == [
        "web_application",
        "web_application",
    ]


def test_parse_arguments_combines_target_and_target_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text("http://test2.com:5789/\n", encoding="utf-8")
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "-t", "https://test1.com/", "--target-list", str(target_list)],
    )

    args = cli_main.parse_arguments()

    assert [target["original"] for target in args.targets_info] == [
        "https://test1.com/",
        "http://test2.com:5789/",
    ]


def test_parse_arguments_accepts_burp_port(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "-t", "https://test1.com/", "--burp-port", "8081", "-n"],
    )

    args = cli_main.parse_arguments()

    assert args.burp_port == 8081


def test_parse_arguments_accepts_burp_port_without_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _stub_settings(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["strix", "--burp-port", "8081", "-n"])

    args = cli_main.parse_arguments()

    assert args.burp_port == 8081
    assert args.targets_info == []


def test_parse_arguments_rejects_resume_with_target_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text("https://test1.com/\n", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--resume", "old-run", "--target-list", str(target_list)],
    )

    with pytest.raises(SystemExit):
        cli_main.parse_arguments()

    assert "不能将 --resume 与 --target/--target-list/--mount 同时使用" in capsys.readouterr().err


def test_help_output_is_localized(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli_main.parse_arguments()

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "Strix 多代理网络安全渗透测试工具" in help_text
    assert "扫描模式" in help_text
    assert "自定义指令" in help_text
    assert "--burp-port" in help_text
    assert "strix --burp-port 8081" in help_text
