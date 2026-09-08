"""Safe validation primitives for the red-team mode.

This module validates proof intents before an integration supplies its own
authorized transport.  It intentionally has no shell, socket, or HTTP client
dependency, so importing it cannot create a target-side side effect.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlparse


if TYPE_CHECKING:
    from collections.abc import Iterable


ValidationKind = Literal["rce_identity", "writable_file_upload", "sqli", "ssrf_canary"]

SAFE_IDENTITY_COMMANDS = frozenset({"id", "whoami"})
_MUTATING_SQL = re.compile(
    r"(?i)\b(?:insert|update|delete|drop|alter|truncate|create|grant|revoke|copy|load)\b"
)
_READ_ONLY_SQL = re.compile(r"(?is)^\s*(?:select|with|explain)\b")
_SAFE_CANARY_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})


@dataclass(frozen=True, slots=True)
class SafeValidationRequest:
    kind: ValidationKind
    target: str
    proof: str
    cleanup_required: bool = False


class RedTeamDepthError(ValueError):
    """Raised when a requested proof exceeds the safe validation contract."""


class RedTeamDepthController:
    """Construct safe proof requests without executing them."""

    @staticmethod
    def identity_command(command: str) -> SafeValidationRequest:
        normalized = command.strip()
        if normalized not in SAFE_IDENTITY_COMMANDS:
            raise RedTeamDepthError("RCE 验证只允许使用 id 或 whoami")
        return SafeValidationRequest(
            kind="rce_identity",
            target="authorized-target",
            proof=normalized,
        )

    @staticmethod
    def upload_marker(target: str, marker: str | None = None) -> SafeValidationRequest:
        value = marker or f"redteam-proof-{uuid.uuid4().hex}"
        if not re.fullmatch(r"redteam-proof-[0-9a-f]{32}", value):
            raise RedTeamDepthError("文件上传验证必须使用随机 marker")
        return SafeValidationRequest(
            kind="writable_file_upload",
            target=target,
            proof=value,
            cleanup_required=True,
        )

    @staticmethod
    def sql_probe(target: str, query: str) -> SafeValidationRequest:
        statements = [statement.strip() for statement in query.split(";") if statement.strip()]
        if not statements or any(
            _MUTATING_SQL.search(statement) or not _READ_ONLY_SQL.match(statement)
            for statement in statements
        ):
            raise RedTeamDepthError("SQL 验证只允许无副作用的 SELECT/WITH/EXPLAIN 查询")
        return SafeValidationRequest(kind="sqli", target=target, proof="; ".join(statements))

    @staticmethod
    def ssrf_canary(
        target: str,
        canary_url: str,
        *,
        allowed_hosts: Iterable[str] = (),
    ) -> SafeValidationRequest:
        parsed = urlparse(canary_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise RedTeamDepthError("SSRF 验证必须使用有效的 Canary URL")
        hostname = parsed.hostname.lower()
        if hostname in {"169.254.169.254", "metadata.google.internal"}:
            raise RedTeamDepthError("禁止访问云凭据元数据端点")
        configured_hosts = {
            host.strip().lower().rstrip(".")
            for host in allowed_hosts
            if host.strip()
        }
        is_local_stub = hostname in _SAFE_CANARY_HOSTS
        is_reserved_canary = hostname.endswith(".canary.invalid")
        if hostname not in configured_hosts and not is_local_stub and not is_reserved_canary:
            raise RedTeamDepthError("SSRF 验证只能访问本地 Stub、保留 Canary 域名或显式授权主机")
        return SafeValidationRequest(kind="ssrf_canary", target=target, proof=canary_url)
