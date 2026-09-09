"""Regression tests for scan-wide Token limits and priority admission."""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING
from unittest.mock import MagicMock, patch

import pytest
from agents.usage import Usage

from strix.core.hooks import (
    ReportUsageHooks,
    TokenLimitExceededError,
    TokenReserveExceededError,
)
from strix.core.token_budget import TokenBudgetPlan, normalize_token_limit
from strix.interface import cli_args
from strix.report.state import ReportState
from strix.report.usage import LLMUsageLedger


if TYPE_CHECKING:
    from pathlib import Path


def _usage(input_tokens: int = 100, output_tokens: int = 25) -> Usage:
    usage = Usage()
    usage.requests = 1
    usage.input_tokens = input_tokens
    usage.output_tokens = output_tokens
    usage.total_tokens = input_tokens + output_tokens
    return usage


@pytest.mark.parametrize(
    "value",
    [0, -1, False, "0", "-10", "not-a-number", "100X", "1.5"],
)
def test_token_limit_requires_positive_integer(value: object) -> None:
    with pytest.raises(ValueError):
        normalize_token_limit(value)


def test_empty_token_limit_is_unlimited() -> None:
    assert normalize_token_limit(None) is None
    assert normalize_token_limit("") is None
    plan = TokenBudgetPlan()

    admitted, reason = plan.admit_task(task_id="task-1", priority="P3", estimated_tokens=10**9)

    assert admitted is True
    assert reason == "unlimited"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("100K", 100_000),
        ("100M", 100_000_000),
        ("1.5G", 1_500_000_000),
        ("2T", 2_000_000_000_000),
        ("3B", 3_000_000_000),
    ],
)
def test_token_limit_accepts_human_readable_suffixes(value: str, expected: int) -> None:
    assert normalize_token_limit(value) == expected


def test_priority_admission_preserves_twenty_percent_reserve() -> None:
    plan = TokenBudgetPlan(limit=100)

    blocked, blocked_reason = plan.admit_task(
        task_id="medium-before-high-risk",
        priority="P2",
        estimated_tokens=80,
    )
    p0, _ = plan.admit_task(task_id="scope", priority="P0", estimated_tokens=10)
    plan.mark_task_completed("scope")
    plan.mark_priority_completed("P0")
    high_risk, _ = plan.admit_task(task_id="validation", priority="P1", estimated_tokens=20)
    plan.mark_task_completed("validation")
    plan.mark_priority_completed("P1")
    admitted, _ = plan.admit_task(
        task_id="medium",
        priority="P2",
        estimated_tokens=80,
        details={"task": "中危接口测试", "skills": ["xss"]},
    )
    plan.mark_task_completed("medium")
    plan.mark_priority_completed("P2")
    plan.record_usage(80)
    skipped, reason = plan.admit_task(task_id="low", priority="P3", estimated_tokens=1)

    assert blocked is False
    assert blocked_reason == "priority_gate_closed:P0_P1_incomplete"
    assert p0 is True
    assert admitted is True
    assert skipped is False
    assert reason == "insufficient_token_budget"
    assert high_risk is True
    assert plan.skipped_tasks[-1]["task_id"] == "low"
    assert next(task for task in plan.planned_tasks if task["task_id"] == "medium")["skills"] == [
        "xss"
    ]


def test_failed_task_releases_its_estimate() -> None:
    plan = TokenBudgetPlan(limit=100)
    plan.admit_task(task_id="broken", priority="P0", estimated_tokens=90)
    plan.mark_task_failed("broken", "child_spawn_failed")

    admitted, _ = plan.admit_task(task_id="replacement", priority="P0", estimated_tokens=90)

    assert admitted is True
    assert plan.planned_tasks[0]["status"] == "failed"


def test_small_budget_still_admits_one_high_risk_task() -> None:
    plan = TokenBudgetPlan(limit=100)

    admitted, _ = plan.admit_task(task_id="critical-path", priority="P0", estimated_tokens=200)
    second, _ = plan.admit_task(task_id="second-path", priority="P0", estimated_tokens=1)

    assert admitted is True
    assert second is False


def test_completed_task_releases_its_estimate_for_later_admission() -> None:
    plan = TokenBudgetPlan(limit=100)
    plan.admit_task(task_id="scope", priority="P0", estimated_tokens=10)
    plan.mark_task_completed("scope")
    plan.mark_priority_completed("P0")
    plan.admit_task(task_id="validation", priority="P1", estimated_tokens=10)
    plan.mark_task_completed("validation")
    plan.mark_priority_completed("P1")
    plan.admit_task(task_id="medium", priority="P2", estimated_tokens=50)
    plan.mark_task_completed("medium")

    admitted, _ = plan.admit_task(task_id="another-medium", priority="P2", estimated_tokens=30)

    assert admitted is True


def test_exhaustion_marker_does_not_inflate_effective_usage() -> None:
    plan = TokenBudgetPlan(limit=100)
    plan.record_usage(25)
    plan.mark_exhausted()

    assert plan.tokens_used == 25
    assert plan.is_exhausted is True


def test_missing_usage_uses_conservative_estimate() -> None:
    ledger = LLMUsageLedger()
    ledger.record(agent_id="agent-1", usage=None, fallback_tokens=4096)

    record = ledger.to_record()
    assert record["effective_total_tokens"] == 4096
    assert record["estimated_tokens"] == 4096


def _token_state(tokens: int) -> MagicMock:
    state = MagicMock()
    state.get_total_llm_cost.return_value = 0.0
    state.get_total_llm_tokens.return_value = tokens
    state.record_sdk_usage = MagicMock()
    return state


def _context(*, parent_id: str | None = None, priority: str = "P2") -> MagicMock:
    context = MagicMock()
    context.context = {
        "agent_id": "agent-1",
        "parent_id": parent_id,
        "task_priority": priority,
    }
    return context


@pytest.mark.asyncio
async def test_token_limit_stops_scan_wide_work() -> None:
    hooks = ReportUsageHooks(model="test-model", token_limit=100)
    state = _token_state(100)

    with (
        patch("strix.core.hooks.get_global_report_state", return_value=state),
        pytest.raises(TokenLimitExceededError),
    ):
        await hooks.on_llm_start(_context(parent_id=None, priority="P0"), MagicMock(), None, [])


@pytest.mark.asyncio
async def test_unlimited_token_limit_does_not_intercept_model_calls() -> None:
    hooks = ReportUsageHooks(model="test-model")
    state = _token_state(10**9)

    with patch("strix.core.hooks.get_global_report_state", return_value=state):
        await hooks.on_llm_start(_context(parent_id="root", priority="P3"), MagicMock(), None, [])
        await hooks.on_llm_end(_context(parent_id="root", priority="P3"), MagicMock(), MagicMock())


@pytest.mark.asyncio
async def test_token_reserve_stops_low_priority_child_but_allows_validation() -> None:
    hooks = ReportUsageHooks(model="test-model", token_limit=100)
    state = _token_state(80)

    with (
        patch("strix.core.hooks.get_global_report_state", return_value=state),
        pytest.raises(TokenReserveExceededError),
    ):
        await hooks.on_llm_end(_context(parent_id="root", priority="P2"), MagicMock(), MagicMock())

    state.get_total_llm_tokens.return_value = 80
    with patch("strix.core.hooks.get_global_report_state", return_value=state):
        await hooks.on_llm_end(_context(parent_id="root", priority="P1"), MagicMock(), MagicMock())


def test_report_state_persists_effective_tokens_and_resume_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="token-run")
    state.set_scan_config({"targets": [], "token_limit": 500, "scan_mode": "deep"})
    state.record_sdk_usage(agent_id="agent-1", usage=_usage(400, 100))
    state.mark_token_limit_exhausted()

    restored = ReportState(run_name="token-run")
    restored.hydrate_from_run_dir()
    restored.set_scan_config({"targets": [], "token_limit": 500, "scan_mode": "deep"})

    assert state.run_record["tokens_used"] == 500
    assert state.run_record["token_limit_status"] == "exhausted"  # noqa: S105
    assert state.run_record["token_limit"] == 500
    assert restored.get_total_llm_tokens() == 500
    assert restored.token_limit_exhausted is True

    extended = ReportState(run_name="token-run")
    extended.hydrate_from_run_dir()
    extended.set_scan_config({"targets": [], "token_limit": 800, "scan_mode": "deep"})

    assert extended.get_total_llm_tokens() == 500
    assert extended.token_limit_exhausted is False
    assert extended.run_record["token_limit"] == 800
    assert extended.run_record["tokens_remaining"] == 300


def test_token_exhaustion_writes_incomplete_executive_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name="exhausted-run")
    state.set_scan_config({"targets": [], "token_limit": 100, "scan_mode": "deep"})
    state.record_sdk_usage(agent_id="agent-1", usage=_usage(80, 20))
    state.mark_token_limit_exhausted()
    state.finalize_token_limit_report()

    report_path = tmp_path / "strix_runs" / "exhausted-run" / "penetration_test_report.md"
    report = report_path.read_text(encoding="utf-8")
    assert "报告不完整" in report or "Token 限制与覆盖边界" in report
    assert state.run_record["status"] == "token_limit_exhausted"


def test_cli_accepts_token_limit_and_rejects_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--target", "https://example.com", "--token-limit", "123"],
    )
    assert cli_args.parse_arguments().token_limit == 123

    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--target", "https://example.com", "--token-limit", "100M"],
    )
    assert cli_args.parse_arguments().token_limit == 100_000_000

    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--target", "https://example.com", "--token-limit", "0"],
    )
    with pytest.raises(SystemExit):
        cli_args.parse_arguments()
