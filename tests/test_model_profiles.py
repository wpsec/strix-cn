"""Tests for user-supplied model capability profiles."""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING

import pytest

from strix.config import model_profiles
from strix.core.inputs import make_model_settings
from strix.llm import context_budget


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _clear_profile_caches() -> object:
    model_profiles._load_profiles.cache_clear()
    yield
    model_profiles._load_profiles.cache_clear()


def _write_profiles(tmp_path: Path, data: object) -> Path:
    path = tmp_path / "model-profiles.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_profile_lookup_normalizes_slugs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_profiles(
        tmp_path,
        {"DashScope/Qwen3.8-Flash": {"max_input_tokens": 32768, "max_output_tokens": 8192}},
    )
    monkeypatch.setenv("STRIX_MODEL_PROFILES", str(path))
    profile = model_profiles.get_profile("anthropic/qwen3.8-flash")
    assert profile is not None
    assert profile.max_input_tokens == 32768
    assert profile.max_output_tokens == 8192


def test_per_mtok_pricing_is_converted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_profiles(
        tmp_path,
        {"qwen3.8-flash": {"input_cost_per_mtok": 1.0, "output_cost_per_mtok": 4.0}},
    )
    monkeypatch.setenv("STRIX_MODEL_PROFILES", str(path))
    cost = model_profiles.estimate_cost(
        "openai/qwen3.8-flash", {"prompt_tokens": 1_000_000, "completion_tokens": 500_000}
    )
    assert cost == pytest.approx(3.0)


def test_unknown_fields_are_dropped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_profiles(
        tmp_path,
        {"qwen3.8-flash": {"context_window": 128, "supports_reasoning": True, "bogus": 1}},
    )
    monkeypatch.setenv("STRIX_MODEL_PROFILES", str(path))
    profile = model_profiles.get_profile("qwen3.8-flash")
    assert profile is not None
    assert profile.max_input_tokens == 128
    assert profile.max_output_tokens is None  # supports_reasoning never became behavior


def test_missing_file_keeps_previous_behavior(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STRIX_MODEL_PROFILES", "/nonexistent/model-profiles.json")
    assert model_profiles.get_profile("anything") is None
    assert model_profiles.estimate_cost("anything", {"prompt_tokens": 10}) is None


def test_broken_json_warns_and_degrades(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "model-profiles.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv("STRIX_MODEL_PROFILES", str(path))
    assert model_profiles.get_profile("anything") is None


def test_invalid_entries_are_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_profiles(
        tmp_path,
        {
            "good": {"max_input_tokens": 4096},
            "bad": {"max_input_tokens": -1, "max_output_tokens": "big"},
            "empty": {},
            "scalar": 5,
        },
    )
    monkeypatch.setenv("STRIX_MODEL_PROFILES", str(path))
    assert model_profiles.get_profile("good") is not None
    assert model_profiles.get_profile("bad") is None
    assert model_profiles.get_profile("empty") is None
    assert model_profiles.get_profile("scalar") is None


def test_edited_file_is_picked_up(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_profiles(tmp_path, {"m": {"max_input_tokens": 100}})
    monkeypatch.setenv("STRIX_MODEL_PROFILES", str(path))
    assert model_profiles.get_profile("m") is not None
    assert model_profiles.get_profile("m").max_output_tokens is None  # type: ignore[union-attr]
    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 10**9))
    _write_profiles(tmp_path, {"m": {"max_input_tokens": 100, "max_output_tokens": 50}})
    os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 2 * 10**9))
    assert model_profiles.get_profile("m").max_output_tokens == 50  # type: ignore[union-attr]


def test_context_budget_prefers_profile(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = _write_profiles(tmp_path, {"qwen3.8-flash": {"max_input_tokens": 65536}})
    monkeypatch.setenv("STRIX_MODEL_PROFILES", str(path))
    context_budget._model_info.cache_clear()
    try:
        assert context_budget.context_window("anthropic/qwen3.8-flash") == 65536
    finally:
        context_budget._model_info.cache_clear()


def test_make_model_settings_applies_profiled_output_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _write_profiles(tmp_path, {"qwen3.8-flash": {"max_tokens": 16384}})
    monkeypatch.setenv("STRIX_MODEL_PROFILES", str(path))
    settings = make_model_settings(None, model_name="anthropic/qwen3.8-flash")
    assert settings.max_tokens == 16384
    unprofiled = make_model_settings(None, model_name="anthropic/unknown-model")
    assert unprofiled.max_tokens is None
