"""Tests for run directory naming."""

from __future__ import annotations

from datetime import datetime

import pytest

import strix.interface.utils as interface_utils


class _FrozenDateTime(datetime):
    @classmethod
    def now(cls, tz: object | None = None) -> "_FrozenDateTime":
        return cls(2026, 7, 27, 11, 58, 3, 456789)


def test_generate_run_name_uses_timestamp_for_passive_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(interface_utils, "datetime", _FrozenDateTime)

    assert interface_utils.generate_run_name() == "pentest_20260727_115803_456789"
    assert interface_utils.generate_run_name([]) == "pentest_20260727_115803_456789"


def test_generate_run_name_keeps_target_slug_for_targeted_scans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(interface_utils.secrets, "token_hex", lambda _n: "abcd")

    targets_info = [
        {
            "type": "repository",
            "details": {"target_repo": "https://github.com/example/strix-cn.git"},
            "original": "https://github.com/example/strix-cn.git",
        }
    ]

    assert interface_utils.generate_run_name(targets_info) == "strix-cn_abcd"
