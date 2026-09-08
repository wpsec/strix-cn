"""Attack-chain projection and evidence redaction for red-team reports."""

from __future__ import annotations

import re
from typing import Any

from strix.redteam.policy import normalize_vulnerability_type, should_ignore


_SENSITIVE_HEADER = re.compile(
    r"(?im)^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"x-api-key|api-key|x-auth-token|x-csrf-token)\s*:\s*)([^\r\n]*)$"
)
_SENSITIVE_JSON = re.compile(
    r'(?i)(["\'](?:password|passwd|secret|token|api[_-]?key|access[_-]?token)'
    r'["\']\s*:\s*["\'])([^"\']*)(["\'])'
)
_SENSITIVE_QUERY = re.compile(
    r"(?i)([?&](?:token|secret|password|passwd|api[_-]?key|access_token)=)([^&#\s]+)"
)
_MAX_EVIDENCE_CHARS = 16_000


def redact_sensitive_text(value: object, *, max_chars: int = _MAX_EVIDENCE_CHARS) -> str:
    """Redact common credential-bearing fields before report persistence."""
    text = str(value or "")
    text = _SENSITIVE_HEADER.sub(r"\1[REDACTED]", text)
    text = _SENSITIVE_JSON.sub(r"\1[REDACTED]\3", text)
    text = _SENSITIVE_QUERY.sub(r"\1[REDACTED]", text)
    if len(text) > max_chars:
        text = f"{text[:max_chars]}\n[证据已截断]"
    return text


def build_attack_chain(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a stable, evidence-linked chain from eligible findings."""
    eligible = [
        report
        for report in reports
        if str(report.get("severity") or "").lower() in {"critical", "high"}
        and normalize_vulnerability_type(report.get("vulnerability_type")) is not None
        and not should_ignore(
            str(report.get("vulnerability_type") or ""),
            mode="redteam",
            impact=report.get("impact"),
        )
        and any(
            str(report.get(field) or "").strip()
            for field in ("evidence", "validation_evidence", "permission_proof")
        )
    ]
    eligible.sort(key=lambda report: (str(report.get("timestamp") or ""), str(report.get("id"))))

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    for index, report in enumerate(eligible, start=1):
        node_id = str(report.get("id") or f"finding-{index}")
        nodes.append(
            {
                "id": node_id,
                "vulnerability_type": normalize_vulnerability_type(
                    report.get("vulnerability_type")
                ),
                "title": redact_sensitive_text(report.get("title"), max_chars=512),
                "severity": str(report.get("severity") or "").lower(),
                "evidence": redact_sensitive_text(
                    report.get("validation_evidence") or report.get("evidence")
                ),
                "permission_proof": redact_sensitive_text(report.get("permission_proof")),
                "request": redact_sensitive_text(report.get("request")),
                "response": redact_sensitive_text(report.get("response")),
            }
        )
        if index > 1:
            edges.append(
                {
                    "source": str(eligible[index - 2].get("id") or f"finding-{index - 1}"),
                    "target": node_id,
                    "relationship": "validated_after",
                }
            )
    return {"nodes": nodes, "edges": edges}


def redact_report_evidence(report: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow report copy with evidence-bearing fields redacted."""
    sanitized = dict(report)
    for field in (
        "evidence",
        "validation_evidence",
        "poc_script_code",
        "permission_proof",
        "request",
        "response",
    ):
        if field in sanitized and sanitized[field] not in (None, ""):
            sanitized[field] = redact_sensitive_text(sanitized[field])
    return sanitized
