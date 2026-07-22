"""Tests for persisting and restoring the Burp upstream proxy port on resume."""

from __future__ import annotations

import importlib
from types import SimpleNamespace
from typing import Any

import pytest


cli_main: Any = importlib.import_module("strix.interface.main")


class _Parser:
    def error(self, message: str) -> None:
        raise AssertionError(message)


def test_load_resume_state_restores_persisted_burp_port(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    monkeypatch.setattr(cli_main, "run_dir_for", lambda _run_name: tmp_path)
    monkeypatch.setattr(
        cli_main,
        "read_run_record",
        lambda _run_dir: {
            "targets_info": [
                {
                    "type": "web_application",
                    "details": {"target_url": "https://example.com"},
                    "original": "https://example.com",
                }
            ],
            "burp_port": 8081,
            "scan_mode": "deep",
        },
    )
    (tmp_path / "run.json").write_text("{}", encoding="utf-8")

    args = SimpleNamespace(
        resume="demo-run",
        targets_info=[],
        instruction=None,
        local_sources=[],
        diff_scope=None,
        scan_mode="deep",
        burp_port=None,
    )

    cli_main._load_resume_state(args, _Parser())

    assert args.burp_port == 8081


def test_load_resume_state_keeps_explicit_burp_port_override(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    monkeypatch.setattr(cli_main, "run_dir_for", lambda _run_name: tmp_path)
    monkeypatch.setattr(
        cli_main,
        "read_run_record",
        lambda _run_dir: {
            "targets_info": [
                {
                    "type": "web_application",
                    "details": {"target_url": "https://example.com"},
                    "original": "https://example.com",
                }
            ],
            "burp_port": 8081,
            "scan_mode": "deep",
        },
    )
    (tmp_path / "run.json").write_text("{}", encoding="utf-8")

    args = SimpleNamespace(
        resume="demo-run",
        targets_info=[],
        instruction=None,
        local_sources=[],
        diff_scope=None,
        scan_mode="deep",
        burp_port=9091,
    )

    cli_main._load_resume_state(args, _Parser())

    assert args.burp_port == 9091


def test_load_resume_state_allows_empty_targets_for_burp_passive_mode(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Any,
) -> None:
    monkeypatch.setattr(cli_main, "run_dir_for", lambda _run_name: tmp_path)
    monkeypatch.setattr(
        cli_main,
        "read_run_record",
        lambda _run_dir: {
            "targets_info": [],
            "burp_port": 8081,
            "scan_mode": "deep",
        },
    )
    (tmp_path / "run.json").write_text("{}", encoding="utf-8")

    args = SimpleNamespace(
        resume="demo-run",
        targets_info=[],
        instruction=None,
        local_sources=[],
        diff_scope=None,
        scan_mode="deep",
        burp_port=None,
    )

    cli_main._load_resume_state(args, _Parser())

    assert args.targets_info == []
    assert args.burp_port == 8081
