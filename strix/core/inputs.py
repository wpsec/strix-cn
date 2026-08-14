"""Pure input builders for Strix scan runs."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from agents.model_settings import ModelSettings
from openai.types.shared import Reasoning

from strix.config.models import (
    DEFAULT_MODEL_RETRY,
    OPENROUTER_ATTRIBUTION_HEADERS,
    bedrock_route_supports_prompt_caching,
    is_bedrock_route,
    is_claude_model,
    is_known_openai_bare_model,
    is_openrouter_model,
    model_supports_reasoning,
    request_timeout_extra_args,
)
from strix.core.sessions import scrub_images_from_items
from strix.core.proxy_scope import build_proxy_scope_constraints


if TYPE_CHECKING:
    from strix.config.settings import ReasoningEffort


_CONTAINER_IMAGE_TARGET_TYPES = frozenset({"container_image", "docker_image", "image"})


def _accepts_required_tool_choice(model_name: str | None) -> bool:
    name = (model_name or "").strip().lower()
    for prefix in ("litellm/", "any-llm/"):
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name.startswith("openai/") or is_known_openai_bare_model(name)


def _render_diff_scope(diff_scope: dict[str, Any]) -> list[str]:
    """Render pull-request diff-scope constraints as root-task lines."""
    if not diff_scope.get("active"):
        return []
    parts: list[str] = [
        "\n\nScope Constraints:",
        "- Pull request diff-scope mode is active. Prioritize changed files "
        "and use other files only for context.",
    ]
    for repo_scope in diff_scope.get("repos", []) or []:
        label = repo_scope.get("workspace_subdir") or repo_scope.get("source_path") or "repository"
        changed = repo_scope.get("analyzable_files_count", 0)
        deleted = repo_scope.get("deleted_files_count", 0)
        parts.append(f"- {label}: {changed} changed file(s) in primary scope")
        if deleted:
            parts.append(f"- {label}: {deleted} deleted file(s) are context-only")
    return parts


def _render_api_spec(details: dict[str, Any]) -> list[str]:
    """Render an API spec target as root-task lines.

    The spec itself is in the workspace, so the task points at the file and lets
    the agent read the contract rather than restating a parsed summary of it.
    """
    title = details.get("spec_title") or details.get("target_spec", "API")
    workspace_path = details.get("workspace_path", "")
    lines = [
        f"- {title} ({details.get('spec_format', 'api')} specification"
        + (f", available at: {workspace_path}" if workspace_path else "")
        + ")"
    ]
    if base_urls := details.get("base_urls") or []:
        lines.append("  - Base URL(s): " + ", ".join(base_urls))
    lines.append(
        "  - Read the specification and test every operation it declares, using "
        "its declared parameters, request bodies, and auth. Endpoints in the "
        "specification are in scope even when nothing links to them. Load the "
        "`api_spec_testing` skill for the methodology, or spawn a specialist "
        "with it."
    )
    return lines


def _container_image_target_value(target: dict[str, Any]) -> str:
    details = target.get("details") or {}
    for key in ("target_image", "image", "image_name", "image_ref", "target_ref"):
        value = details.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    original = target.get("original", "")
    if isinstance(original, str):
        return original.strip()
    return ""


def build_root_task(scan_config: dict[str, Any]) -> str:
    targets = scan_config.get("targets", []) or []
    burp_port = scan_config.get("burp_port")
    diff_scope = scan_config.get("diff_scope") or {}
    user_instructions = scan_config.get("user_instructions", "") or ""
    proxy_scope = build_proxy_scope_constraints(scan_config)

    sections: dict[str, list[str]] = {
        "Container Images": [],
        "Repositories": [],
        "Local Codebases": [],
        "URLs": [],
        "IP Addresses": [],
        "API Specifications": [],
    }

    for target in targets:
        ttype = target.get("type")
        details = target.get("details") or {}
        workspace_subdir = details.get("workspace_subdir")
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else "/workspace"

        if ttype in _CONTAINER_IMAGE_TARGET_TYPES:
            image = _container_image_target_value(target)
            sections["Container Images"].append(
                f"- {image or 'unknown image'} (container image target; /workspace may be empty unless a separate code target is also provided)"
            )
        elif ttype == "repository":
            url = details.get("target_repo", "")
            cloned = details.get("cloned_repo_path")
            sections["Repositories"].append(
                f"- {url} (available at: {workspace_path})" if cloned else f"- {url}",
            )
        elif ttype == "local_code":
            path = details.get("target_path", "unknown")
            sections["Local Codebases"].append(
                f"- {path} (available at: {workspace_path}; "
                "this is the user's real directory, mounted live and writable — "
                ".git/.agents/.codex are read-only)"
            )
        elif ttype == "web_application":
            sections["URLs"].append(f"- {details.get('target_url', '')}")
        elif ttype == "ip_address":
            sections["IP Addresses"].append(f"- {details.get('target_ip', '')}")
        elif ttype == "api_spec":
            sections["API Specifications"].extend(_render_api_spec(details))

    parts: list[str] = []
    for label, items in sections.items():
        if items:
            parts.append(f"\n\n{label}:")
            parts.extend(items)

    if not targets and burp_port is not None:
        parts.append("\n\nPassive Proxy Mode:")
        parts.append("- No static target list was provided for this run.")
        parts.append(
            "- Observe only HTTP(S) traffic captured through the configured Burp upstream proxy."
        )
        parts.append(
            "- Derive in-scope hosts, URLs, sessions, and workflows only from captured proxy history."
        )
        parts.append(
            "- Do not invent, broaden, or probe unrelated hosts that have not appeared in observed traffic."
        )
        parts.append(
            "- Treat each observed hostname as individually scoped; do not widen one host into sibling hosts or a whole parent domain unless the operator explicitly listed that broader scope."
        )
        parts.append("- Prioritize authenticated traffic and operator-driven workflows captured from Burp.")
        if proxy_scope["proxy_scope_denylist"]:
            parts.append(
                f"- Ignore known proxy/browser noise domains: {', '.join(proxy_scope['proxy_scope_denylist'])}."
            )
    elif burp_port is not None and proxy_scope["proxy_scope_allowlist"]:
        parts.append("\n\nBurp Proxy Scope:")
        parts.append(
            "- Only test proxy traffic whose hostname matches the Strix-side scope allowlist derived from explicit targets."
        )
        for pattern in proxy_scope["proxy_scope_allowlist"]:
            parts.append(f"- Allowed host pattern: {pattern}")
    # A workspace mount is a directory to work in, not an asset to test. It is
    # listed apart from the targets so it never reads as scope.
    if workspace_mount := scan_config.get("workspace_mount") or "":
        subdir = scan_config.get("workspace_subdir") or ""
        workspace_path = f"/workspace/{subdir}" if subdir else "/workspace"
        parts.append("\n\nWorking Directory:")
        parts.append(
            f"- {workspace_mount} (available at: {workspace_path}; "
            "this is the user's real directory, mounted live and writable — "
            ".git/.agents/.codex are read-only)"
        )
        parts.append(
            "- No scan target was set. This directory is where you work, not a "
            "target to assess: the instructions below are the only source of "
            "truth for what to do."
        )
    elif not parts and user_instructions:
        # Neither a target nor a directory, but there is an instruction: the user
        # declined the mount, so the instruction is all there is. Say so, or the
        # agent goes looking for a scope that was never given.
        parts.append(
            "\n\nNo scan target and no working directory were provided. The "
            "instructions below are the only source of truth for what to do; "
            "work from them and from what you can reach yourself."
        )

    parts.extend(_render_diff_scope(diff_scope))

    if scan_config.get("credential_auth_available"):
        parts.append("\n\nAuthorized Login Credentials:")
        parts.append(
            "- A platform-supplied target account is available inside the sandbox as "
            "`STRIX_TARGET_USERNAME` and `STRIX_TARGET_PASSWORD`."
        )
        parts.append(
            "- Use it to establish an authenticated session and cover authenticated "
            "application surfaces. Never print, echo, log, persist, report, or send "
            "either value in an agent message."
        )
        if scan_config.get("allow_credential_attacks"):
            parts.append(
                "- The operator explicitly authorized credential-attack validation "
                "for this run; keep attempts bounded to in-scope authentication endpoints."
            )
        else:
            parts.append(
                "- These credentials authorize ordinary login only. Do not perform "
                "brute force, password spraying, credential stuffing, or repeated-password tests."
            )

    task = " ".join(parts)
    if user_instructions:
        task = f"{task}\n\nSpecial instructions: {user_instructions}"
    return task


def build_scope_context(scan_config: dict[str, Any]) -> dict[str, Any]:
    targets = scan_config.get("targets", []) or []
    proxy_scope = build_proxy_scope_constraints(scan_config)
    if not targets and scan_config.get("burp_port") is not None:
        return {
            "scope_source": "burp_upstream_proxy",
            "authorization_source": "operator_routed_proxy_traffic",
            "authorized_targets": [],
            "container_image_targets": [],
            "proxy_passive_mode": True,
            "target_credentials_available": bool(
                scan_config.get("credential_auth_available", False)
            ),
            "allow_credential_attacks": bool(
                scan_config.get("allow_credential_attacks", False)
            ),
            **proxy_scope,
            "user_instructions_do_not_expand_scope": True,
        }

    authorized: list[dict[str, str]] = []
    container_images: list[str] = []
    value_keys = {
        "container_image": "target_image",
        "docker_image": "target_image",
        "image": "target_image",
        "repository": "target_repo",
        "local_code": "target_path",
        "web_application": "target_url",
        "ip_address": "target_ip",
        "api_spec": "target_spec",
    }
    for target in targets:
        ttype = target.get("type", "unknown")
        details = target.get("details") or {}
        if ttype in _CONTAINER_IMAGE_TARGET_TYPES:
            value = _container_image_target_value(target)
        else:
            key = value_keys.get(ttype)
            value = details.get(key, "") if key is not None else target.get("original", "")

        workspace_subdir = details.get("workspace_subdir")
        workspace_path = f"/workspace/{workspace_subdir}" if workspace_subdir else ""
        authorized.append(
            {"type": ttype, "value": value, "workspace_path": workspace_path},
        )
        if ttype in _CONTAINER_IMAGE_TARGET_TYPES and value:
            container_images.append(value)

        # An API spec authorizes the hosts it declares as in-scope web targets
        # so the agent can exercise every endpoint without expanding scope.
        if ttype == "api_spec":
            authorized.extend(
                {"type": "web_application", "value": base_url, "workspace_path": ""}
                for base_url in details.get("base_urls") or []
            )

    return {
        "scope_source": "system_scan_config",
        "authorization_source": "strix_platform_verified_targets",
        "authorized_targets": authorized,
        "container_image_targets": container_images,
        "target_credentials_available": bool(
            scan_config.get("credential_auth_available", False)
        ),
        "allow_credential_attacks": bool(
            scan_config.get("allow_credential_attacks", False)
        ),
        **proxy_scope,
        "user_instructions_do_not_expand_scope": True,
    }


def make_model_settings(
    reasoning_effort: ReasoningEffort | None,
    *,
    model_name: str,
    force_required_tool_choice: bool = False,
    request_timeout: float | None = None,
    prompt_cache: bool = True,
    extra_headers: dict[str, str] | None = None,
    has_tools: bool = True,
) -> ModelSettings:
    # Azure OpenAI rejects any request that carries ``parallel_tool_calls``
    # without ``tools``, so tool-less requests must omit it entirely.
    headers = _request_headers(model_name, extra_headers)
    model_settings = ModelSettings(
        parallel_tool_calls=False if has_tools else None,
        retry=DEFAULT_MODEL_RETRY,
        include_usage=True,
        extra_args=request_timeout_extra_args(request_timeout),
        extra_headers=headers,
    )
    if reasoning_effort == "max":
        # ``max`` is an explicit pass-through mode for frontier providers that
        # may not yet exist in LiteLLM's local capability map.
        model_settings = model_settings.resolve(
            _reasoning_settings(reasoning_effort, model_settings.extra_args),
        )
    elif (
        reasoning_effort is not None
        and reasoning_effort != "none"
        and model_supports_reasoning(model_name)
    ):
        model_settings = model_settings.resolve(
            _reasoning_settings(reasoning_effort, model_settings.extra_args),
        )
    if force_required_tool_choice and _accepts_required_tool_choice(model_name):
        model_settings = model_settings.resolve(ModelSettings(tool_choice="required"))

    cache_extra_args = _prompt_cache_extra_args(model_name) if prompt_cache else None
    if cache_extra_args:
        model_settings = model_settings.resolve(
            ModelSettings(
                extra_args={**(model_settings.extra_args or {}), **cache_extra_args},
            ),
        )
    return model_settings


def _request_headers(
    model_name: str, extra_headers: dict[str, str] | None
) -> dict[str, str] | None:
    headers: dict[str, str] = {}
    if is_openrouter_model(model_name):
        headers.update(OPENROUTER_ATTRIBUTION_HEADERS)
    if extra_headers:
        headers.update(extra_headers)
    return headers or None


def _reasoning_settings(
    effort: ReasoningEffort,
    extra_args: dict[str, Any] | None,
) -> ModelSettings:
    """``max`` is not in the OpenAI SDK's ``Reasoning.effort`` enum, so send it as
    a raw body field instead — also keeping it clear of LiteLLM's DeepSeek mapping,
    which collapses every ``reasoning_effort`` level to plain thinking-enabled.
    Providers that don't support ``max`` reject the request.
    """
    if effort != "max":
        return ModelSettings(reasoning=Reasoning(effort=effort))
    return ModelSettings(
        extra_args={**(extra_args or {}), "extra_body": {"reasoning_effort": "max"}},
    )


def _prompt_cache_extra_args(model_name: str) -> dict[str, Any] | None:
    """LiteLLM ``cache_control_injection_points`` for Claude prompt caching.

    System prompt + rolling last-message breakpoint everywhere; ``tool_config``
    only on Bedrock Converse (the only route whose LiteLLM transform consumes
    it — elsewhere it leaks onto the wire and native Anthropic 400s). Unmapped
    Bedrock models get no points at all: Bedrock rejects the passed-through
    field outright.
    """
    if not is_claude_model(model_name):
        return None
    if is_bedrock_route(model_name) and not bedrock_route_supports_prompt_caching(model_name):
        return None

    points: list[dict[str, Any]] = [{"location": "message", "role": "system"}]
    if is_bedrock_route(model_name):
        points.append({"location": "tool_config"})
    points.append({"location": "message", "index": -1})
    return {"cache_control_injection_points": points}


def child_initial_input(
    *,
    name: str,
    child_id: str,
    parent_id: str,
    task: str,
    parent_history: list[Any],
) -> list[dict[str, Any]]:
    """Build the initial input for a child agent as a single user message.

    Collapsing the inherited-context block, the identity line, and the task into
    one ``{"role": "user"}`` message keeps providers that require strictly
    alternating roles (e.g. Perplexity, llama.cpp) from rejecting consecutive
    user messages.
    """
    parts: list[str] = []
    if parent_history:
        rendered = json.dumps(
            scrub_images_from_items(parent_history),
            ensure_ascii=False,
            default=str,
        )
        parts.append(
            "== Inherited context from parent (background only) ==\n"
            f"{rendered}\n"
            "== End of inherited context ==\n"
            "Use the above as background only; do not continue the "
            "parent's work. Your task follows.",
        )
    parts.append(
        f"You are agent {name} ({child_id}); your parent is {parent_id}. "
        "Maintain your own identity. Call agent_finish when your task "
        "is complete.",
    )
    parts.append(task)
    return [{"role": "user", "content": "\n\n".join(parts)}]
