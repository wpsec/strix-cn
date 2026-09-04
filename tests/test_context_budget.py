"""Tests for model-aware token budgets."""

from __future__ import annotations

from typing import TYPE_CHECKING

import litellm

from strix.config import load_settings
from strix.llm import context_budget


if TYPE_CHECKING:
    import pytest


def test_context_window_known_model() -> None:
    # gpt-4o is mapped by LiteLLM at 128k input tokens.
    assert context_budget.context_window("gpt-4o") == 128_000


def test_context_window_strips_provider_prefix() -> None:
    assert context_budget.context_window("openai/gpt-4o") == 128_000


def test_context_window_chatgpt_prefix_skips_provider_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context_budget._model_info.cache_clear()
    calls: list[str] = []

    def _model_info(model: str) -> dict[str, int]:
        calls.append(model)
        return {"max_input_tokens": 1_050_000, "max_output_tokens": 128_000}

    monkeypatch.setattr("litellm.get_model_info", _model_info)
    try:
        assert context_budget.context_window("chatgpt/gpt-5.6-luna") == 1_050_000
        assert calls == ["gpt-5.6-luna"]
    finally:
        context_budget._model_info.cache_clear()


def test_context_window_unmapped_uses_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    context_budget._model_info.cache_clear()

    def _raise(_model: str) -> dict[str, int]:
        raise ValueError("This model isn't mapped yet.")

    monkeypatch.setattr("litellm.get_model_info", _raise)
    expected = load_settings().context.fallback_context_tokens
    assert context_budget.context_window("totally-made-up-model") == expected
    context_budget._model_info.cache_clear()


def test_count_tokens_fallback_on_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _raise(**_kwargs: object) -> int:
        raise RuntimeError("no tokenizer")

    monkeypatch.setattr("litellm.token_counter", _raise)
    # Falls back to UTF-8 byte length (upper bound on tokens).
    assert context_budget.count_tokens("weird-model", "x" * 400) == 400
    assert context_budget.count_tokens("weird-model", "😀" * 10) == 40


def test_count_tokens_empty_is_zero() -> None:
    assert context_budget.count_tokens("gpt-4o", "") == 0


def test_suffix_match_recovers_provider_prefixed_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Strix rewrites bare names to anthropic/<slug> on Anthropic-protocol
    # gateways; the map keys the same model under another provider, so the
    # lookup must follow the slug instead of losing the real window.
    context_budget._model_info.cache_clear()
    monkeypatch.setattr(
        litellm,
        "model_cost",
        {
            "dashscope/qwen3.8-max": {
                "max_input_tokens": 991808,
                "max_output_tokens": 131072,
            },
        },
    )
    monkeypatch.setattr(context_budget, "_safe_get_model_info", lambda _m: None)
    try:
        info = context_budget._model_info("anthropic/qwen3.8-max")
        assert info["max_input_tokens"] == 991808
        assert info["max_output_tokens"] == 131072
    finally:
        context_budget._model_info.cache_clear()


def test_suffix_match_declines_ambiguous_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context_budget._model_info.cache_clear()
    monkeypatch.setattr(
        litellm,
        "model_cost",
        {
            "providerA/same-slug": {"max_input_tokens": 100_000, "max_output_tokens": 8192},
            "providerB/same-slug": {"max_input_tokens": 32_000, "max_output_tokens": 8192},
        },
    )
    monkeypatch.setattr(context_budget, "_safe_get_model_info", lambda _m: None)
    try:
        assert context_budget._model_info("anthropic/same-slug") == {
            "max_input_tokens": 0,
            "max_output_tokens": 0,
        }
    finally:
        context_budget._model_info.cache_clear()


def test_suffix_match_accepts_majority_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context_budget._model_info.cache_clear()
    monkeypatch.setattr(
        litellm,
        "model_cost",
        {
            "dashscope/qwen3.8-max": {"max_input_tokens": 991808, "max_output_tokens": 131072},
            "qwencloud/qwen3.8-max": {"max_input_tokens": 991808, "max_output_tokens": 131072},
            "novita/qwen/qwen3.8-max": {"max_input_tokens": 1000000, "max_output_tokens": 8192},
        },
    )
    monkeypatch.setattr(context_budget, "_safe_get_model_info", lambda _m: None)
    try:
        info = context_budget._model_info("anthropic/qwen3.8-max")
        assert info == {"max_input_tokens": 991808, "max_output_tokens": 131072}
    finally:
        context_budget._model_info.cache_clear()


def test_suffix_match_declines_tie(monkeypatch: pytest.MonkeyPatch) -> None:
    context_budget._model_info.cache_clear()
    monkeypatch.setattr(
        litellm,
        "model_cost",
        {
            "providerA/tied-slug": {"max_input_tokens": 64_000, "max_output_tokens": 4096},
            "providerB/tied-slug": {"max_input_tokens": 128_000, "max_output_tokens": 8192},
        },
    )
    monkeypatch.setattr(context_budget, "_safe_get_model_info", lambda _m: None)
    try:
        assert context_budget._model_info("anthropic/tied-slug") == {
            "max_input_tokens": 0,
            "max_output_tokens": 0,
        }
    finally:
        context_budget._model_info.cache_clear()
