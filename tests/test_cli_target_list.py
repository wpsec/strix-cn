"""Tests for CLI argument parsing around targets, resume, and Burp mode."""

from __future__ import annotations

import importlib
import json
import sys
from typing import TYPE_CHECKING, Any

import pytest


if TYPE_CHECKING:
    from pathlib import Path


cli_args: Any = importlib.import_module("strix.interface.cli_args")


def test_parse_arguments_accepts_target_list_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target_list = tmp_path / "targets.txt"
    target_list.write_text(
        "https://test1.com/\n\nhttp://test2.com:5789/\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["strix", "--target-list", str(target_list), "-n"])

    args = cli_args.parse_arguments()

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
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "-t", "https://test1.com/", "--target-list", str(target_list)],
    )

    args = cli_args.parse_arguments()

    assert [target["original"] for target in args.targets_info] == [
        "https://test1.com/",
        "http://test2.com:5789/",
    ]


def test_parse_arguments_accepts_burp_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "-t", "https://test1.com/", "--burp-port", "8081", "-n"],
    )

    args = cli_args.parse_arguments()

    assert args.burp_port == 8081


def test_parse_arguments_accepts_burp_port_without_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--burp-port", "8081", "-n"])

    args = cli_args.parse_arguments()

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
        cli_args.parse_arguments()

    assert "不能将 --resume 与 --target/--target-list/--mount 同时使用" in capsys.readouterr().err


def test_help_output_is_localized(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["strix", "--help"])

    with pytest.raises(SystemExit) as exc:
        cli_args.parse_arguments()

    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "Strix 多代理网络安全渗透测试工具" in help_text
    assert "扫描模式" in help_text
    assert "自定义指令" in help_text
    assert "--burp-port" in help_text
    assert "strix --burp-port 8081" in help_text


def _write_run_record(runs_dir: Path, run_name: str, record: dict[str, Any]) -> None:
    """Write a resumable run: its record plus the agent snapshot resume needs."""
    run_dir = runs_dir / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run.json").write_text(json.dumps(record), encoding="utf-8")
    state_dir = run_dir / ".state"
    state_dir.mkdir(exist_ok=True)
    (state_dir / "agents.json").write_text("{}", encoding="utf-8")


def test_resume_restores_a_target_less_workspace_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A run that only mounted a working directory is resumable."""
    work = tmp_path / "project"
    work.mkdir()
    monkeypatch.chdir(tmp_path)
    _write_run_record(
        tmp_path / "strix_runs",
        "pentest_abcd",
        {
            "run_name": "pentest_abcd",
            "targets_info": [],
            "local_sources": [],
            "workspace_mount": str(work),
            "instruction": "audit the auth flow",
            "scan_mode": "deep",
        },
    )
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "pentest_abcd"])

    args = cli_args.parse_arguments()

    assert args.targets_info == []
    assert args.workspace_mount == str(work)
    assert args.local_sources == [
        {"source_path": str(work), "workspace_subdir": "project", "protect_metadata": True}
    ]
    assert args.instruction == "audit the auth flow"


def test_resume_reports_a_missing_workspace_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run_record(
        tmp_path / "strix_runs",
        "pentest_abcd",
        {
            "run_name": "pentest_abcd",
            "targets_info": [],
            "local_sources": [],
            "workspace_mount": str(tmp_path / "deleted"),
        },
    )
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "pentest_abcd"])

    with pytest.raises(SystemExit):
        cli_args.parse_arguments()

    error = capsys.readouterr().err
    assert "工作目录" in error
    assert "不存在" in error


def test_resume_still_requires_targets_or_a_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    _write_run_record(
        tmp_path / "strix_runs",
        "pentest_abcd",
        {"run_name": "pentest_abcd", "targets_info": [], "local_sources": []},
    )
    monkeypatch.setattr(sys, "argv", ["strix", "--resume", "pentest_abcd"])

    with pytest.raises(SystemExit):
        cli_args.parse_arguments()

    assert "run.json 中缺少 targets_info" in capsys.readouterr().err
