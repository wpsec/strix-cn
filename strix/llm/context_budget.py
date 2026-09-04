"""Model-aware token budgets, resolved from LiteLLM model metadata with a
large configurable fallback for models LiteLLM doesn't map.
"""

from __future__ import annotations

import logging
from collections import Counter
from functools import lru_cache
from typing import Any

from strix.config import load_settings


logger = logging.getLogger(__name__)

# LiteLLM keys models without the routing prefix users type (``openai/``,
# ``litellm/``, ``ollama/`` ...). Strip a leading provider segment on lookup.
_STRIPPABLE_PREFIXES = (
    "openai/",
    "chatgpt/",
    "litellm/",
    "any-llm/",
    "ollama/",
    "ollama_chat/",
)

_DEFAULT_OUTPUT_TOKENS = 8_192


def _lookup_key(model: str) -> str:
    for prefix in _STRIPPABLE_PREFIXES:
        if model.startswith(prefix):
            return model[len(prefix) :]
    return model


def _safe_get_model_info(model: str) -> dict[str, Any] | None:
    try:
        import litellm

        return dict(litellm.get_model_info(model))
    except Exception:  # noqa: BLE001 - unmapped models raise; caller falls back.
        return None


def _suffix_match(slug: str) -> dict[str, int] | None:
    """Resolve a bare model slug through any provider's map entry.

    Strix's Anthropic-protocol routing re-prefixes names the map keys under a
    different provider (``dashscope/qwen3.8-max`` becomes
    ``anthropic/qwen3.8-max`` at the wire layer), which would otherwise lose
    real window metadata to the coarse fallback. One slug is often sold by
    several providers with near-identical windows and one outlier; accept the
    majority value, and keep the honest fallback when no value clearly wins.
    """
    if not slug:
        return None
    try:
        import litellm

        model_cost = litellm.model_cost
    except Exception:  # noqa: BLE001 - litellm import may fail; caller falls back.
        return None
    counts: Counter[tuple[int, int]] = Counter()
    for key, entry in model_cost.items():
        if not key.endswith(f"/{slug}") or not isinstance(entry, dict):
            continue
        counts[
            (
                int(entry.get("max_input_tokens") or entry.get("max_tokens") or 0),
                int(entry.get("max_output_tokens") or 0),
            )
        ] += 1
    if not counts:
        return None
    ranked = counts.most_common(2)
    best_count = ranked[0][1]
    runner_count = ranked[1][1] if len(ranked) > 1 else 0
    if len(ranked) > 1 and (best_count < 2 or best_count <= runner_count):
        return None
    max_input_tokens, max_output_tokens = ranked[0][0]
    return {
        "max_input_tokens": max_input_tokens,
        "max_output_tokens": max_output_tokens,
    }


@lru_cache(maxsize=128)
def _model_info(model: str) -> dict[str, int]:
    lookup_key = _lookup_key(model)
    # Provider-qualified ChatGPT lookups may start a synchronous device-login
    # poll. LiteLLM keys the metadata by the underlying model slug.
    candidates = (lookup_key,) if model.startswith("chatgpt/") else (model, lookup_key)
    for candidate in candidates:
        info = _safe_get_model_info(candidate)
        if info is not None:
            return {
                "max_input_tokens": int(
                    info.get("max_input_tokens") or info.get("max_tokens") or 0
                ),
                "max_output_tokens": int(info.get("max_output_tokens") or 0),
            }
    resolved = _suffix_match(lookup_key.rsplit("/", 1)[-1])
    if resolved is not None:
        return resolved
    logger.debug("No LiteLLM model info for %r; using configured fallbacks", model)
    return {"max_input_tokens": 0, "max_output_tokens": 0}


def context_window(model: str) -> int:
    """Input token capacity for ``model`` (configured fallback when unmapped)."""
    resolved = _model_info(model)["max_input_tokens"]
    return resolved or load_settings().context.fallback_context_tokens


def output_limit(model: str) -> int:
    """Max output tokens for ``model`` (a conservative default when unmapped)."""
    return _model_info(model)["max_output_tokens"] or _DEFAULT_OUTPUT_TOKENS


def count_tokens(model: str, text: str) -> int:
    """Token count for ``text`` under ``model``.

    Falls back to UTF-8 byte length (a guaranteed upper bound) when LiteLLM
    can't count, so budget checks stay conservative.
    """
    if not text:
        return 0
    try:
        import litellm

        return int(litellm.token_counter(model=_lookup_key(model), text=text))
    except Exception:  # noqa: BLE001 - tokenizer may be unavailable for some models.
        return len(text.encode("utf-8"))
