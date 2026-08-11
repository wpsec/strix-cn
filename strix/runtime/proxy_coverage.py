"""Machine-enforced endpoint coverage for passive-proxy test batches."""

from __future__ import annotations

from typing import Any


_ACTIVE_OR_COMPLETED_AGENT_STATUSES = frozenset(
    {"running", "waiting", "budget_paused", "completed"}
)


def begin_proxy_coverage(
    coverage_ref: dict[str, Any],
    *,
    batch_id: str,
    endpoint_request_counts: dict[str, int],
) -> None:
    endpoints = {
        endpoint: {
            "request_count": max(1, int(request_count)),
            "assigned_agents": {},
            "skip_reason": None,
        }
        for endpoint, request_count in sorted(endpoint_request_counts.items())
        if endpoint and int(request_count) > 0
    }
    coverage_ref.clear()
    coverage_ref.update(
        {
            "active": bool(endpoints),
            "batch_id": batch_id,
            "endpoints": endpoints,
        }
    )


def clear_proxy_coverage(coverage_ref: dict[str, Any]) -> None:
    coverage_ref.clear()
    coverage_ref.update({"active": False, "batch_id": None, "endpoints": {}})


def assign_proxy_coverage(
    coverage_ref: dict[str, Any],
    *,
    agent_id: str,
    agent_name: str,
    task: str,
) -> list[str]:
    if not coverage_ref.get("active") or _is_mapping_agent(agent_name):
        return []
    endpoints = coverage_ref.get("endpoints")
    if not isinstance(endpoints, dict):
        return []

    assigned: list[str] = []
    for endpoint, raw_entry in endpoints.items():
        if not isinstance(endpoint, str) or not isinstance(raw_entry, dict):
            continue
        if not _task_mentions_endpoint(task, endpoint, endpoints):
            continue
        agents = raw_entry.setdefault("assigned_agents", {})
        if not isinstance(agents, dict):
            agents = {}
            raw_entry["assigned_agents"] = agents
        agents[agent_id] = agent_name
        assigned.append(endpoint)
    return assigned


def mark_proxy_endpoint_not_applicable(
    coverage_ref: dict[str, Any],
    *,
    endpoint: str,
    reason: str,
) -> bool:
    endpoints = coverage_ref.get("endpoints")
    if not coverage_ref.get("active") or not isinstance(endpoints, dict):
        return False
    entry = endpoints.get(endpoint)
    if not isinstance(entry, dict):
        return False
    entry["skip_reason"] = reason.strip()
    return True


def unresolved_proxy_endpoints(
    coverage_ref: dict[str, Any] | None,
    *,
    agent_statuses: dict[str, str] | None = None,
) -> list[str]:
    if not isinstance(coverage_ref, dict) or not coverage_ref.get("active"):
        return []
    endpoints = coverage_ref.get("endpoints")
    if not isinstance(endpoints, dict):
        return []

    unresolved: list[str] = []
    for endpoint, raw_entry in endpoints.items():
        if not isinstance(endpoint, str) or not isinstance(raw_entry, dict):
            continue
        if str(raw_entry.get("skip_reason") or "").strip():
            continue
        assigned_agents = raw_entry.get("assigned_agents")
        if (
            isinstance(assigned_agents, dict)
            and assigned_agents
            and (
                agent_statuses is None
                or any(
                    agent_statuses.get(str(agent_id))
                    in _ACTIVE_OR_COMPLETED_AGENT_STATUSES
                    for agent_id in assigned_agents
                )
            )
        ):
            continue
        unresolved.append(endpoint)
    return unresolved


def proxy_coverage_counts(
    coverage_ref: dict[str, Any] | None,
    *,
    agent_statuses: dict[str, str] | None = None,
) -> tuple[int, int, int]:
    if not isinstance(coverage_ref, dict) or not coverage_ref.get("active"):
        return 0, 0, 0
    endpoints = coverage_ref.get("endpoints")
    if not isinstance(endpoints, dict):
        return 0, 0, 0
    total = sum(1 for endpoint in endpoints if isinstance(endpoint, str))
    pending = len(unresolved_proxy_endpoints(coverage_ref, agent_statuses=agent_statuses))
    return total, total - pending, pending


def _is_mapping_agent(agent_name: str) -> bool:
    normalized = agent_name.casefold().replace(" ", "")
    return "攻击面" in normalized or "attacksurface" in normalized or "mapping" in normalized


def _task_mentions_endpoint(task: str, endpoint: str, endpoints: dict[str, Any]) -> bool:
    if endpoint in task:
        return True
    method, separator, target = endpoint.partition(" ")
    if not separator:
        return False
    slash = target.find("/")
    if slash < 0:
        return False
    method_path = f"{method} {target[slash:]}"
    if method_path not in task:
        return False
    matching = 0
    for candidate in endpoints:
        if not isinstance(candidate, str):
            continue
        candidate_method, candidate_separator, candidate_target = candidate.partition(" ")
        candidate_slash = candidate_target.find("/")
        if not candidate_separator or candidate_slash < 0:
            continue
        if f"{candidate_method} {candidate_target[candidate_slash:]}" == method_path:
            matching += 1
    return matching == 1
