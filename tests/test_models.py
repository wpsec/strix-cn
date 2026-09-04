"""Tests for LLM model recommendation helpers."""

from __future__ import annotations

import pytest
from agents.extensions.models.litellm_model import LitellmModel
from agents.model_settings import ModelSettings

from strix.config.models import (
    RECOMMENDED_MODEL_NAMES,
    StrixProvider,
    _NonStreamingModel,
    _TurnGuardModel,
    is_anthropic_protocol_base,
    is_recommended_or_frontier_model,
    normalize_model_for_endpoint,
    request_timeout_extra_args,
    routes_through_litellm,
    supports_strict_tool_schemas,
    validate_provider_route_config,
)
from strix.config.settings import LlmSettings, Settings


@pytest.mark.parametrize("model_name", RECOMMENDED_MODEL_NAMES)
def test_recommended_models_are_accepted(model_name: str) -> None:
    assert is_recommended_or_frontier_model(model_name)


def test_request_timeout_extra_args_positive() -> None:
    assert request_timeout_extra_args(300) == {"timeout": 300}
    assert request_timeout_extra_args(10) == {"timeout": 10}


def test_request_timeout_extra_args_survives_model_settings_json_dump() -> None:
    """The Chat Completions and LiteLLM paths pydantic-serialize ModelSettings for
    their tracing span; a non-JSON-serializable timeout fails every turn there."""
    settings = ModelSettings(extra_args=request_timeout_extra_args(300))
    assert settings.to_json_dict()["extra_args"] == {"timeout": 300}


@pytest.mark.parametrize("value", [None, 0, -1])
def test_request_timeout_extra_args_disabled(value: float | None) -> None:
    assert request_timeout_extra_args(value) is None


def test_recommended_models_are_matched_case_insensitively() -> None:
    assert is_recommended_or_frontier_model("Vertex_AI/Gemini-3-Pro-Preview")


@pytest.mark.parametrize(
    "model_name",
    [
        "gpt-5.5",
        "chatgpt/gpt-5.4",
        "litellm/openai/gpt-5.4-pro",
        "azure_ai/gpt-5.5-pro",
        "bedrock_mantle/openai.gpt-5.5",
        "anthropic/claude-opus-5",
        "anthropic/claude-opus-4-8",
        "anthropic.claude-opus-4-8",
        "anthropic/claude-opus-4-7",
        "anthropic/claude-fable-5",
        "anthropic/claude-sonnet-5",
        "vertex_ai/claude-sonnet-5@default",
        "vertex_ai/claude-sonnet-4-6@default",
        "any-llm/anthropic/claude-sonnet-4-6",
        "vertex_ai/gemini-3.1-pro-preview",
        "openrouter/google/gemini-3.1-pro-preview",
        "deepseek/deepseek-v4-pro",
        "deepseek/deepseek-r1-0528",
        "deepseek/deepseek-reasoner",
        "dashscope/qwen3-max-2026-01-23",
        "qwen3.7-max",
        "dashscope/qwen3.8-max",
        "moonshot/kimi-k2.6",
        "kimi-k2.7-code",
        "moonshot/kimi-k3",
        "anthropic/claude-fable-5-1",
        "vertex_ai/claude-fable-5-1@default",
        "gemini/gemini-3.7-flash",
        "glm-5.3",
        "zai/glm-5.3-flash",
        "openrouter/z-ai/glm-5.3",
        "novita/zai-org/glm-5.2",
    ],
)
def test_frontier_model_families_are_accepted(model_name: str) -> None:
    assert is_recommended_or_frontier_model(model_name)


@pytest.mark.parametrize(
    "model_name",
    [
        "",
        "openai/gpt-4.1",
        "anthropic/claude-3-5-sonnet-latest",
        "ollama/llama3.1",
        "deepseek/deepseek-chat",
        "custom-ollama/gpt-5-mini-local",
        "custom-provider/claude-opus-4-local",
        "xai/grok-4.5",
        "openrouter/x-ai/grok-4",
        "mistral/mistral-medium-3-5",
        "mistral/magistral-medium-latest",
        "zai/glm-4.7",
        "openrouter/z-ai/glm-5",
        "custom-provider/glm-5.3-local",
    ],
)
def test_non_frontier_models_are_rejected(model_name: str) -> None:
    assert not is_recommended_or_frontier_model(model_name)


def _settings(*, api_key: str | None, api_base: str | None) -> Settings:
    return Settings(
        llm=LlmSettings(
            model="deepseek/deepseek-v4-pro",
            api_key=api_key,
            api_base=api_base,
        )
    )


def test_aliyun_plan_key_rejects_workspace_endpoint() -> None:
    settings = _settings(
        api_key="sk-sp-demo",
        api_base="https://ws-r7decpdut5x0sanx.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
    )

    with pytest.raises(ValueError, match="sk-sp-"):
        validate_provider_route_config(settings)


def test_aliyun_workspace_key_rejects_token_plan_endpoint() -> None:
    settings = _settings(
        api_key="sk-ws-demo",
        api_base="https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
    )

    with pytest.raises(ValueError, match="Token Plan"):
        validate_provider_route_config(settings)


def test_aliyun_plan_key_accepts_token_plan_endpoint() -> None:
    settings = _settings(
        api_key="sk-sp-demo",
        api_base="https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
    )

    validate_provider_route_config(settings)


def test_aliyun_workspace_key_accepts_workspace_endpoint() -> None:
    settings = _settings(
        api_key="sk-ws-demo",
        api_base="https://ws-r7decpdut5x0sanx.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
    )

    validate_provider_route_config(settings)


ALIYUN_ANTHROPIC_BASE = "https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic"
ALIYUN_COMPAT_BASE = "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1"


@pytest.mark.parametrize(
    "api_base",
    [
        ALIYUN_ANTHROPIC_BASE,
        ALIYUN_ANTHROPIC_BASE + "/",
        "https://token-plan.cn-beijing.maas.aliyuncs.com/apps/anthropic/v1/messages",
        "https://gateway.example.com/api/Anthropic",
    ],
)
def test_anthropic_protocol_base_is_detected(api_base: str) -> None:
    assert is_anthropic_protocol_base(api_base)


@pytest.mark.parametrize(
    "api_base",
    [
        None,
        "",
        ALIYUN_COMPAT_BASE,
        "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "https://api.v1.example.com",
    ],
)
def test_openai_compatible_base_is_not_flagged_as_anthropic(api_base: str | None) -> None:
    assert not is_anthropic_protocol_base(api_base)


def test_bare_model_follows_anthropic_endpoint_protocol() -> None:
    assert (
        normalize_model_for_endpoint("qwen3.8-flash", ALIYUN_ANTHROPIC_BASE)
        == "anthropic/qwen3.8-flash"
    )


@pytest.mark.parametrize(
    "model_name",
    ["qwen3.8-flash", "openai/qwen3.8-flash", "litellm/anthropic/qwen3.8-flash", "  "],
)
def test_bare_model_on_openai_base_keeps_route(model_name: str) -> None:
    assert normalize_model_for_endpoint(model_name, ALIYUN_COMPAT_BASE) == model_name


@pytest.mark.parametrize("model_name", ["openai/qwen3.8-flash", "anthropic/qwen3.8-flash"])
def test_explicit_prefix_wins_over_endpoint_protocol(model_name: str) -> None:
    assert normalize_model_for_endpoint(model_name, ALIYUN_ANTHROPIC_BASE) == model_name


@pytest.mark.parametrize("model_name", [None, ""])
def test_empty_model_name_passes_through(model_name: str | None) -> None:
    assert normalize_model_for_endpoint(model_name, ALIYUN_ANTHROPIC_BASE) == model_name


@pytest.mark.parametrize(
    "model_name",
    [
        "anthropic/claude-sonnet-4-6",
        "bedrock/anthropic.claude-opus-4-8-v1:0",
        "vertex_ai/claude-sonnet-5",
        "Sonnet-5",
    ],
)
def test_claude_routes_reject_strict_tool_schemas(model_name: str) -> None:
    assert not supports_strict_tool_schemas(model_name)


@pytest.mark.parametrize(
    "model_name",
    ["openai/gpt-5.4", "gpt-5.4", "gemini/gemini-3.1-pro-preview", "deepseek/deepseek-v4"],
)
def test_other_routes_keep_strict_tool_schemas(model_name: str) -> None:
    assert supports_strict_tool_schemas(model_name)


@pytest.mark.parametrize(
    ("model_name", "litellm"),
    [
        ("claude-sonnet-4-5", False),
        ("openai/claude-sonnet-4-5", False),
        ("any-llm/anthropic/claude-sonnet-4-5", False),
        ("anthropic/claude-sonnet-4-5", True),
        ("litellm/anthropic/claude-sonnet-4-5", True),
        ("bedrock/anthropic.claude-sonnet-4-5-20250929-v1:0", True),
        ("ollama/llama3", True),
    ],
)
def test_routes_through_litellm_matches_the_provider(
    monkeypatch: pytest.MonkeyPatch, model_name: str, litellm: bool
) -> None:
    """The helper must agree with what StrixProvider actually builds.

    Callers use it to decide whether a LiteLLM-only request field is safe to
    attach; on the SDK's own clients such a field raises TypeError mid-turn, so
    drift here breaks every request on that route.
    """
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    assert routes_through_litellm(model_name) is litellm
    try:
        model = StrixProvider().get_model(model_name)
    except ImportError:
        # any-llm's client is an optional dependency; reaching it at all already
        # proves the route is not LiteLLM's.
        assert not litellm
        return
    while isinstance(model, _NonStreamingModel | _TurnGuardModel):
        model = model._inner
    assert isinstance(model, LitellmModel) is litellm
