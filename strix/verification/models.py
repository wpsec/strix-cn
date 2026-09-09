"""Data models and request/response helpers for verification runs."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlunsplit


VerificationStatus = Literal[
    "plan_ready",
    "waiting_confirmation",
    "running",
    "verified_vulnerable",
    "not_reproduced",
    "inconclusive",
    "blocked",
    "needs_secondary_identity",
    "fixed",
    "still_vulnerable",
]

_SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-access-token",
        "x-csrf-token",
        "x-xsrf-token",
    }
)
_SENSITIVE_KEY_RE = re.compile(
    r"(?:token|secret|password|passwd|api[_-]?key|authorization|cookie|session|jwt)", re.I
)
_BEARER_RE = re.compile(r"(bearer\s+)[A-Za-z0-9._~+/=-]+", re.I)
_SECRET_RE = re.compile(
    r"(token|secret|password|api[_-]?key)(\s*[:=]\s*)[^,;\s]+",
    re.I,
)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def redact_text(value: str, *, limit: int = 4096) -> str:
    """Redact common credential material before it reaches an artifact."""
    cleaned = _CONTROL_RE.sub(" ", value)
    cleaned = _BEARER_RE.sub(r"\1<redacted>", cleaned)
    cleaned = _SECRET_RE.sub(r"\1\2<redacted>", cleaned)
    return cleaned[:limit]


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name: "<redacted>" if name.lower() in _SENSITIVE_HEADERS else redact_text(value)
        for name, value in headers.items()
    }


def _redact_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "<redacted>" if _SENSITIVE_KEY_RE.search(str(key)) else _redact_json(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json(item) for item in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_body(body: str, content_type: str = "") -> str:
    if not body:
        return ""
    if "json" in content_type.lower():
        try:
            return json.dumps(
                _redact_json(json.loads(body)),
                ensure_ascii=False,
                separators=(",", ":"),
            )
        except (TypeError, ValueError, json.JSONDecodeError):
            pass
    return redact_text(body)


@dataclass(slots=True)
class CanonicalRequest:
    method: str
    scheme: str
    host: str
    port: int
    path: str
    query: list[tuple[str, str]] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    @property
    def url(self) -> str:
        query = urlencode(self.query, doseq=True)
        netloc = self.host
        default_port = 443 if self.scheme == "https" else 80
        if self.port != default_port:
            netloc = f"{netloc}:{self.port}"
        return urlunsplit((self.scheme, netloc, self.path or "/", query, ""))

    def to_dict(self, *, redact: bool = False) -> dict[str, Any]:
        content_type = next(
            (value for name, value in self.headers.items() if name.lower() == "content-type"),
            "",
        )
        return {
            "method": self.method,
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "path": redact_text(self.path or "/") if redact else self.path or "/",
            "query": [
                [
                    name,
                    ("<redacted>" if _SENSITIVE_KEY_RE.search(name) else redact_text(value))
                    if redact
                    else value,
                ]
                for name, value in self.query
            ],
            "headers": redact_headers(self.headers) if redact else dict(self.headers),
            "body": redact_body(self.body, content_type) if redact else self.body,
        }


def render_raw_request(request: CanonicalRequest) -> str:
    """Render a canonical request as a Burp-compatible raw HTTP request."""
    target = request.path or "/"
    if request.query:
        target = f"{target}?{urlencode(request.query, doseq=True)}"
    headers = dict(request.headers)
    if not any(name.lower() == "host" for name in headers):
        headers["Host"] = request.host if request.port in {80, 443} else f"{request.host}:{request.port}"
    lines = [f"{request.method} {target} HTTP/1.1"]
    lines.extend(f"{name}: {value}" for name, value in headers.items())
    return "\r\n".join(lines) + "\r\n\r\n" + request.body


@dataclass(slots=True)
class VerificationCase:
    request: CanonicalRequest
    issue_description: str
    baseline_run: str | None = None
    supporting_requests: list[CanonicalRequest] = field(default_factory=list)


@dataclass(slots=True)
class VerificationProbe:
    probe_id: str
    title: str
    description: str
    field: str | None = None
    value: str | None = None
    action: str = "set"
    requires_secondary_identity: bool = False
    requires_side_effect_approval: bool = False
    cleanup_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class VerificationAssertion:
    assertion_id: str
    description: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(slots=True)
class VerificationPlan:
    schema_version: int
    vulnerability_type: str
    issue_description: str
    request_template: dict[str, Any]
    request_shape_sha256: str
    target_fields: list[str]
    probes: list[VerificationProbe]
    max_requests: int
    requires_side_effect_approval: bool
    blocked_reason: str | None = None
    plan_sha256: str = ""
    assertions: list[VerificationAssertion] = field(default_factory=list)

    def payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "vulnerability_type": self.vulnerability_type,
            "issue_description": self.issue_description,
            "request_template": self.request_template,
            "request_shape_sha256": self.request_shape_sha256,
            "target_fields": self.target_fields,
            "probes": [probe.to_dict() for probe in self.probes],
            "assertions": [assertion.to_dict() for assertion in self.assertions],
            "max_requests": self.max_requests,
            "requires_side_effect_approval": self.requires_side_effect_approval,
            "blocked_reason": self.blocked_reason,
        }

    def finalize_hash(self) -> str:
        encoded = json.dumps(
            self.payload(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        self.plan_sha256 = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        return self.plan_sha256

    def to_dict(self) -> dict[str, Any]:
        payload = self.payload()
        payload["plan_sha256"] = self.plan_sha256 or self.finalize_hash()
        return payload


@dataclass(slots=True)
class ProbeResult:
    probe_id: str
    status: str
    response_status: int | None = None
    response_length: int = 0
    response_sha256: str | None = None
    response_summary: str = ""
    evidence: str = ""
    error: str | None = None
    request: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class VerificationResult:
    status: VerificationStatus
    vulnerability_type: str
    plan_sha256: str
    run_name: str
    summary: str
    evidence: list[ProbeResult] = field(default_factory=list)
    baseline_run: str | None = None
    comparison: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "vulnerability_type": self.vulnerability_type,
            "plan_sha256": self.plan_sha256,
            "run_name": self.run_name,
            "summary": self.summary,
            "evidence": [item.to_dict() for item in self.evidence],
            "baseline_run": self.baseline_run,
            "comparison": self.comparison,
        }


def _shape_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _shape_json(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [_shape_json(item) for item in value]
    if value is None:
        return "<null>"
    if isinstance(value, bool):
        return "<bool>"
    if isinstance(value, (int, float)):
        return "<number>"
    return "<string>"


def _request_shape(request: CanonicalRequest) -> dict[str, Any]:
    content_type = next(
        (value for name, value in request.headers.items() if name.lower() == "content-type"),
        "",
    )
    body_shape: Any = "<body>" if request.body else ""
    if "json" in content_type.lower():
        try:
            body_shape = _shape_json(json.loads(request.body))
        except (TypeError, ValueError, json.JSONDecodeError):
            body_shape = "<invalid-json-body>"
    elif "application/x-www-form-urlencoded" in content_type.lower():
        body_shape = [name for name, _value in parse_qsl(request.body, keep_blank_values=True)]
    return {
        "method": request.method,
        "scheme": request.scheme,
        "host": request.host,
        "port": request.port,
        "path": request.path or "/",
        "query": [name for name, _value in request.query],
        "headers": sorted(
            (
                name.lower(),
                value.lower() if name.lower() == "content-type" else "<present>",
            )
            for name, value in request.headers.items()
        ),
        "body": body_shape,
    }


def request_shape_sha256(request: CanonicalRequest) -> str:
    payload = _request_shape(request)
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def redact_response_body(body: str, content_type: str = "") -> str:
    return redact_body(body, content_type)[:2048]
