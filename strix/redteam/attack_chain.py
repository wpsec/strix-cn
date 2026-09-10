"""Attack-chain projection and evidence handling for red-team reports."""

from __future__ import annotations

from typing import Any

from strix.redteam.policy import is_attack_chain_eligible, normalize_vulnerability_type
from strix.report.evidence import report_request_evidence, report_response_evidence


def _has_complete_chain_evidence(report: dict[str, Any]) -> bool:
    _, request_source = report_request_evidence(report)
    _, response_source = report_response_evidence(report)
    if request_source == "missing" or response_source == "missing":
        return False
    return bool(
        any(
            str(report.get(field) or "").strip()
            for field in ("evidence", "validation_evidence", "permission_proof")
        )
    )


def build_attack_chain(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a stable, evidence-linked chain from eligible findings."""
    eligible = [
        report
        for report in reports
        if is_attack_chain_eligible(
            report.get("vulnerability_type") or report.get("vulnerability_type_raw"),
            severity=report.get("severity"),
            impact=report.get("impact"),
        )
        and _has_complete_chain_evidence(report)
    ]
    eligible.sort(key=lambda report: (str(report.get("timestamp") or ""), str(report.get("id"))))

    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    eligible_ids = {
        str(report.get("id"))
        for report in eligible
        if str(report.get("id") or "").strip()
    }
    for index, report in enumerate(eligible, start=1):
        node_id = str(report.get("id") or f"finding-{index}")
        request, request_source = report_request_evidence(report)
        response, response_source = report_response_evidence(report)
        nodes.append(
            {
                "id": node_id,
                "vulnerability_type": normalize_vulnerability_type(
                    report.get("vulnerability_type") or report.get("vulnerability_type_raw")
                ),
                "title": str(report.get("title") or ""),
                "severity": str(report.get("severity") or "").lower(),
                "evidence": str(
                    report.get("validation_evidence") or report.get("evidence") or ""
                ),
                "permission_proof": str(report.get("permission_proof") or ""),
                "request": request,
                "request_source": request_source,
                "response": response,
                "response_source": response_source,
                "credential_provenance": dict(report.get("credential_provenance") or {})
                if isinstance(report.get("credential_provenance"), dict)
                else {},
            }
        )
        parent_id = str(report.get("attack_chain_parent_id") or "").strip()
        if parent_id and parent_id in eligible_ids and parent_id != node_id:
            edges.append(
                {
                    "source": parent_id,
                    "target": node_id,
                    "relationship": "prerequisite",
                }
            )
    return {"nodes": nodes, "edges": edges}
