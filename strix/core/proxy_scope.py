"""Proxy scope helpers for passive Burp/Caido workflows."""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatchcase
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from strix.tools.proxy import caido_api


if TYPE_CHECKING:
    from caido_sdk_client import Client as CaidoClient


_NOISE_ROOT_DOMAINS = (
    "caido.io",
    "google.com",
    "googleapis.com",
    "oast.site",
    "pdtm.sh",
)


@dataclass(slots=True, frozen=True)
class ProxyScopeDefinition:
    scope_id: str
    scope_name: str
    allowlist: tuple[str, ...]
    denylist: tuple[str, ...]


def build_proxy_scope_constraints(scan_config: dict[str, Any]) -> dict[str, Any]:
    burp_port = scan_config.get("burp_port")
    if burp_port is None:
        return {
            "proxy_scope_enforced": False,
            "proxy_scope_allowlist": [],
            "proxy_scope_denylist": [],
        }

    allowlist = _dedupe_patterns(_extract_target_host_patterns(scan_config.get("targets") or []))
    denylist = _default_noise_denylist()
    return {
        "proxy_scope_enforced": bool(allowlist or denylist),
        "proxy_scope_allowlist": allowlist,
        "proxy_scope_denylist": denylist,
    }


def host_matches_scope(
    host: str,
    *,
    allowlist: list[str] | tuple[str, ...] | None = None,
    denylist: list[str] | tuple[str, ...] | None = None,
) -> bool:
    normalized = _normalize_host(host)
    if not normalized:
        return False

    deny_patterns = tuple(denylist or ())
    if any(_pattern_matches(normalized, pattern) for pattern in deny_patterns):
        return False

    allow_patterns = tuple(allowlist or ())
    if not allow_patterns:
        return True
    return any(_pattern_matches(normalized, pattern) for pattern in allow_patterns)


async def ensure_caido_proxy_scope(
    client: "CaidoClient",
    *,
    scan_id: str,
    allowlist: list[str] | None = None,
    denylist: list[str] | None = None,
) -> ProxyScopeDefinition | None:
    desired_allowlist = tuple(_dedupe_patterns(allowlist or []))
    desired_denylist = tuple(_dedupe_patterns(denylist or []))
    if not desired_allowlist and not desired_denylist:
        return None

    scope_name = f"strix-proxy-scope-{scan_id}"
    scopes = await caido_api.scope_list(client)
    existing = next((scope for scope in scopes if getattr(scope, "name", "") == scope_name), None)

    if existing is None:
        scope = await caido_api.scope_create(
            client,
            name=scope_name,
            allowlist=list(desired_allowlist),
            denylist=list(desired_denylist),
        )
    else:
        current_allowlist = tuple(_dedupe_patterns(getattr(existing, "allowlist", []) or []))
        current_denylist = tuple(_dedupe_patterns(getattr(existing, "denylist", []) or []))
        if current_allowlist != desired_allowlist or current_denylist != desired_denylist:
            scope = await caido_api.scope_update(
                client,
                str(existing.id),
                name=scope_name,
                allowlist=list(desired_allowlist),
                denylist=list(desired_denylist),
            )
        else:
            scope = existing

    return ProxyScopeDefinition(
        scope_id=str(scope.id),
        scope_name=scope_name,
        allowlist=desired_allowlist,
        denylist=desired_denylist,
    )


def _extract_target_host_patterns(targets: list[dict[str, Any]]) -> list[str]:
    patterns: list[str] = []
    for target in targets:
        ttype = target.get("type")
        details = target.get("details") or {}
        if ttype == "web_application":
            value = str(details.get("target_url") or "").strip()
            host = _host_from_urlish(value)
            if host:
                patterns.append(host)
        elif ttype == "ip_address":
            value = _normalize_host(str(details.get("target_ip") or ""))
            if value:
                patterns.append(value)
    return patterns


def _host_from_urlish(value: str) -> str | None:
    raw = value.strip()
    if not raw:
        return None
    candidate = raw if "://" in raw else f"https://{raw}"
    parsed = urlparse(candidate)
    return _normalize_host(parsed.hostname or raw)


def _default_noise_denylist() -> list[str]:
    patterns: list[str] = []
    for root in _NOISE_ROOT_DOMAINS:
        patterns.append(root)
        patterns.append(f"*.{root}")
    return patterns


def _normalize_host(host: str) -> str:
    return host.strip().lower().strip(".").strip("[]")


def _pattern_matches(host: str, pattern: str) -> bool:
    normalized_pattern = pattern.strip().lower()
    if not normalized_pattern:
        return False
    return fnmatchcase(host, normalized_pattern)


def _dedupe_patterns(patterns: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for pattern in patterns:
        normalized = pattern.strip().lower()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


__all__ = [
    "ProxyScopeDefinition",
    "build_proxy_scope_constraints",
    "ensure_caido_proxy_scope",
    "host_matches_scope",
]
