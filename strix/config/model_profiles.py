"""User-supplied model capability profiles (strix-cn extension).

Domestic gateways publish models LiteLLM's cost map doesn't carry, and the
same slug differs per provider (qwen3.8-max is 991808 tokens on DashScope and
1000000 on Novita). Only the operator knows which gateway they are talking
to, so these numbers are user data, not build-time data: the file is optional
and reading it is the ONLY new behavior -- without one every consumer keeps
its previous fallback chain. Three consumers consult profiles ahead of the
coarse fallbacks: the context budget, the Anthropic ``max_tokens`` cap, and
cost estimation.

This deliberately does NOT register into ``litellm.model_cost``: that map
drives behavior beyond numbers (tokenizer choice, reasoning support), and a
user filling in a window size must not silently change how requests are
constructed.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


logger = logging.getLogger(__name__)

DEFAULT_PROFILE_PATH = Path.home() / ".strix" / "model-profiles.json"

# per-million-token spellings are what vendor pricing pages print.
_TOKEN_SCALE = 1_000_000.0

_FIELD_ALIASES = {
    "max_input_tokens": ("max_input_tokens", "context_window"),
    "max_output_tokens": ("max_output_tokens", "max_tokens"),
    "input_cost_per_token": ("input_cost_per_token",),
    "output_cost_per_token": ("output_cost_per_token",),
    "input_cost_per_mtok": ("input_cost_per_mtok",),
    "output_cost_per_mtok": ("output_cost_per_mtok",),
}
_ALL_KEYS = {key for keys in _FIELD_ALIASES.values() for key in keys}


@dataclass(frozen=True)
class ModelProfile:
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    input_cost_per_token: float | None = None
    output_cost_per_token: float | None = None

    @property
    def empty(self) -> bool:
        return not any(
            (
                self.max_input_tokens,
                self.max_output_tokens,
                self.input_cost_per_token,
                self.output_cost_per_token,
            )
        )


def _normalize_slug(model: str) -> str:
    name = (model or "").strip().casefold()
    for prefix in ("litellm/", "any-llm/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name.rsplit("/", 1)[-1] if "/" in name else name


def _positive_int(entry: dict[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = entry.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0:
            return value
    return None


def _cost_per_token(entry: dict[str, Any], token_key: str, mtok_key: str) -> float | None:
    value = entry.get(token_key)
    if isinstance(value, int | float) and not isinstance(value, bool) and value > 0:
        return float(value)
    value = entry.get(mtok_key)
    if isinstance(value, int | float) and not isinstance(value, bool) and value > 0:
        return float(value) / _TOKEN_SCALE
    return None


def _parse_entry(slug: str, raw: Any) -> ModelProfile | None:
    if not isinstance(raw, dict):
        logger.warning("model profile %r ignored: expected an object", slug)
        return None
    unknown = set(raw) - _ALL_KEYS
    if unknown:
        # Unknown fields are dropped, not applied: the profile must never
        # reach into LiteLLM request-construction behavior by accident.
        logger.warning("model profile %r ignoring unknown fields: %s", slug, sorted(unknown))
    profile = ModelProfile(
        max_input_tokens=_positive_int(raw, _FIELD_ALIASES["max_input_tokens"]),
        max_output_tokens=_positive_int(raw, _FIELD_ALIASES["max_output_tokens"]),
        input_cost_per_token=_cost_per_token(raw, "input_cost_per_token", "input_cost_per_mtok"),
        output_cost_per_token=_cost_per_token(raw, "output_cost_per_token", "output_cost_per_mtok"),
    )
    return None if profile.empty else profile


def _profile_path() -> Path:
    override = os.environ.get("STRIX_MODEL_PROFILES", "").strip()
    return Path(override) if override else DEFAULT_PROFILE_PATH


@lru_cache(maxsize=4)
def _load_profiles(path_str: str, mtime_ns: int) -> dict[str, ModelProfile]:
    del mtime_ns  # part of the cache key so an edited file reloads
    path = Path(path_str)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("model profiles at %s unusable: %s", path, exc)
        return {}
    if not isinstance(data, dict):
        logger.warning("model profiles at %s must be a JSON object", path)
        return {}
    profiles: dict[str, ModelProfile] = {}
    for raw_key, raw_value in data.items():
        slug = _normalize_slug(str(raw_key))
        if not slug:
            continue
        profile = _parse_entry(slug, raw_value)
        if profile is not None:
            profiles[slug] = profile
    return profiles


def _profiles() -> dict[str, ModelProfile]:
    path = _profile_path()
    try:
        stamp = path.stat().st_mtime_ns
    except OSError:
        stamp = 0
    return _load_profiles(str(path), stamp)


def get_profile(model: str | None) -> ModelProfile | None:
    if not model:
        return None
    return _profiles().get(_normalize_slug(model))


def estimate_cost(model: str | None, usage: dict[str, Any] | None) -> float | None:
    """Token-count cost from profile pricing; the map-based estimate wins upstream."""
    profile = get_profile(model)
    if profile is None or usage is None:
        return None
    prompt_tokens = usage.get("prompt_tokens") or 0
    completion_tokens = usage.get("completion_tokens") or 0
    if not isinstance(prompt_tokens, int) or not isinstance(completion_tokens, int):
        return None
    input_cost = profile.input_cost_per_token
    output_cost = profile.output_cost_per_token
    if input_cost is None and output_cost is None:
        return None
    total = (prompt_tokens or 0) * (input_cost or 0.0) + (completion_tokens or 0) * (
        output_cost or 0.0
    )
    return float(total) if total > 0 else None
