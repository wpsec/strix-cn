"""Agent tools for closing passive-proxy endpoint coverage gaps."""

from __future__ import annotations

import json

from agents import RunContextWrapper, function_tool

from strix.runtime.proxy_coverage import (
    mark_proxy_endpoint_not_applicable,
    proxy_coverage_counts,
    unresolved_proxy_endpoints,
)


def _context(ctx: RunContextWrapper) -> dict[str, object]:
    return ctx.context if isinstance(ctx.context, dict) else {}


@function_tool(timeout=30)
async def get_endpoint_coverage(ctx: RunContextWrapper) -> str:
    """Show the frozen passive-proxy endpoint manifest and its coverage state.

    Root agents should call this after attack-surface mapping and again before
    yielding. An endpoint is covered when a non-mapping specialist task names
    it, or when ``mark_endpoint_not_applicable`` records a concrete reason.
    """
    inner = _context(ctx)
    coverage_ref = inner.get("proxy_feature_coverage_ref")
    if not isinstance(coverage_ref, dict) or not coverage_ref.get("active"):
        return json.dumps(
            {"success": True, "active": False, "total": 0, "resolved": 0, "pending": 0},
            ensure_ascii=False,
        )
    total, resolved, pending = proxy_coverage_counts(coverage_ref)
    return json.dumps(
        {
            "success": True,
            "active": True,
            "batch_id": coverage_ref.get("batch_id"),
            "total": total,
            "resolved": resolved,
            "pending": pending,
            "unresolved_endpoints": unresolved_proxy_endpoints(coverage_ref),
            "endpoints": coverage_ref.get("endpoints", {}),
        },
        ensure_ascii=False,
        default=str,
    )


@function_tool(timeout=30)
async def mark_endpoint_not_applicable(
    ctx: RunContextWrapper,
    endpoint: str,
    reason: str,
) -> str:
    """Close one frozen endpoint without a test specialist, with a concrete reason.

    Use only when the endpoint is demonstrably non-testable or out of scope,
    such as a health check with no input or an explicitly excluded asset. Low
    priority is not a valid reason. The endpoint must exactly match the frozen
    manifest. This tool is root-only.

    Args:
        endpoint: Exact ``METHOD host/path`` value from ``get_endpoint_coverage``.
        reason: Specific technical reason the endpoint requires no active test.
    """
    inner = _context(ctx)
    if inner.get("parent_id") is not None:
        return json.dumps(
            {"success": False, "error": "仅 Root Agent 可以关闭 endpoint 覆盖项"},
            ensure_ascii=False,
        )
    normalized_reason = reason.strip()
    if len(normalized_reason) < 12:
        return json.dumps(
            {"success": False, "error": "不适用理由必须具体说明，且不少于 12 个字符"},
            ensure_ascii=False,
        )
    coverage_ref = inner.get("proxy_feature_coverage_ref")
    if not isinstance(coverage_ref, dict):
        return json.dumps(
            {"success": False, "error": "当前没有可用的 endpoint 覆盖清单"},
            ensure_ascii=False,
        )
    if not mark_proxy_endpoint_not_applicable(
        coverage_ref,
        endpoint=endpoint.strip(),
        reason=normalized_reason,
    ):
        return json.dumps(
            {"success": False, "error": "endpoint 不在当前冻结清单中"},
            ensure_ascii=False,
        )
    total, resolved, pending = proxy_coverage_counts(coverage_ref)
    return json.dumps(
        {
            "success": True,
            "endpoint": endpoint.strip(),
            "total": total,
            "resolved": resolved,
            "pending": pending,
            "unresolved_endpoints": unresolved_proxy_endpoints(coverage_ref),
        },
        ensure_ascii=False,
    )
