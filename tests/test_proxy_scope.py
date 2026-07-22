"""Tests for Strix-managed proxy scope constraints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from strix.core import proxy_scope


def test_build_proxy_scope_constraints_for_passive_mode_adds_noise_denylist() -> None:
    constraints = proxy_scope.build_proxy_scope_constraints({"burp_port": 8081})

    assert constraints["proxy_scope_enforced"] is True
    assert "caido.io" in constraints["proxy_scope_denylist"]
    assert "*.caido.io" in constraints["proxy_scope_denylist"]
    assert "googleapis.com" in constraints["proxy_scope_denylist"]
    assert "*.oast.site" in constraints["proxy_scope_denylist"]
    assert constraints["proxy_scope_allowlist"] == []


def test_build_proxy_scope_constraints_uses_exact_target_hosts() -> None:
    constraints = proxy_scope.build_proxy_scope_constraints(
        {
            "burp_port": 8081,
            "targets": [
                {
                    "type": "web_application",
                    "details": {"target_url": "https://app.example.com/login"},
                },
                {"type": "ip_address", "details": {"target_ip": "10.0.0.8"}},
                {
                    "type": "web_application",
                    "details": {"target_url": "app.example.com"},
                },
            ],
        }
    )

    assert constraints["proxy_scope_allowlist"] == ["app.example.com", "10.0.0.8"]
    assert "*.example.com" not in constraints["proxy_scope_allowlist"]


def test_host_matches_scope_applies_allowlist_and_denylist() -> None:
    assert proxy_scope.host_matches_scope(
        "app.example.com",
        allowlist=["app.example.com"],
        denylist=["google.com", "*.google.com"],
    )
    assert not proxy_scope.host_matches_scope(
        "api.google.com",
        allowlist=["app.example.com", "api.google.com"],
        denylist=["google.com", "*.google.com"],
    )
    assert not proxy_scope.host_matches_scope(
        "other.example.com",
        allowlist=["app.example.com"],
        denylist=[],
    )


@dataclass
class _FakeScope:
    id: str
    name: str
    allowlist: list[str]
    denylist: list[str]


@pytest.mark.asyncio
async def test_ensure_caido_proxy_scope_creates_when_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: dict[str, Any] = {}

    async def _scope_list(_client: object) -> list[_FakeScope]:
        return []

    async def _scope_create(
        _client: object,
        *,
        name: str,
        allowlist: list[str] | None = None,
        denylist: list[str] | None = None,
    ) -> _FakeScope:
        created["name"] = name
        created["allowlist"] = list(allowlist or [])
        created["denylist"] = list(denylist or [])
        return _FakeScope(
            id="scope-1",
            name=name,
            allowlist=list(allowlist or []),
            denylist=list(denylist or []),
        )

    monkeypatch.setattr(proxy_scope.caido_api, "scope_list", _scope_list)
    monkeypatch.setattr(proxy_scope.caido_api, "scope_create", _scope_create)

    scope = await proxy_scope.ensure_caido_proxy_scope(
        object(),
        scan_id="scan-1",
        allowlist=["app.example.com"],
        denylist=["*.google.com"],
    )

    assert scope is not None
    assert scope.scope_id == "scope-1"
    assert created["name"] == "strix-proxy-scope-scan-1"
    assert created["allowlist"] == ["app.example.com"]
    assert created["denylist"] == ["*.google.com"]


@pytest.mark.asyncio
async def test_ensure_caido_proxy_scope_updates_existing_when_patterns_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    updated: dict[str, Any] = {}

    async def _scope_list(_client: object) -> list[_FakeScope]:
        return [
            _FakeScope(
                id="scope-1",
                name="strix-proxy-scope-scan-1",
                allowlist=["old.example.com"],
                denylist=[],
            )
        ]

    async def _scope_update(
        _client: object,
        scope_id: str,
        *,
        name: str,
        allowlist: list[str] | None = None,
        denylist: list[str] | None = None,
    ) -> _FakeScope:
        updated["scope_id"] = scope_id
        updated["name"] = name
        updated["allowlist"] = list(allowlist or [])
        updated["denylist"] = list(denylist or [])
        return _FakeScope(
            id=scope_id,
            name=name,
            allowlist=list(allowlist or []),
            denylist=list(denylist or []),
        )

    monkeypatch.setattr(proxy_scope.caido_api, "scope_list", _scope_list)
    monkeypatch.setattr(proxy_scope.caido_api, "scope_update", _scope_update)

    scope = await proxy_scope.ensure_caido_proxy_scope(
        object(),
        scan_id="scan-1",
        allowlist=["app.example.com"],
        denylist=["*.google.com"],
    )

    assert scope is not None
    assert updated["scope_id"] == "scope-1"
    assert updated["allowlist"] == ["app.example.com"]
    assert updated["denylist"] == ["*.google.com"]
