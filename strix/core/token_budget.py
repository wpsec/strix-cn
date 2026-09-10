"""Scan-wide Token planning and admission control."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from typing import Any, Literal


TokenPriority = Literal["P0", "P1", "P2", "P3"]

TOKEN_RESERVE_RATIO = 0.20
DEFAULT_TOKEN_ESTIMATE_PER_REQUEST = 4_096
DEFAULT_TASK_ESTIMATE_TOKENS = 16_384
TOKEN_PRIORITIES: tuple[TokenPriority, ...] = ("P0", "P1", "P2", "P3")
_TOKEN_LIMIT_RE = re.compile(r"^(?P<number>\d+(?:\.\d+)?)(?P<suffix>[kmgtb]?)$", re.IGNORECASE)
_TOKEN_LIMIT_MULTIPLIERS = {
    "k": 1_000,
    "m": 1_000_000,
    "g": 1_000_000_000,
    "t": 1_000_000_000_000,
    "b": 1_000_000_000,
}
_TOKEN_LIMIT_ERROR = "token_limit 必须是大于 0 的整数，或带 K/M/G/T/B 后缀的数量"


def normalize_token_limit(value: Any) -> int | None:
    """Normalize a scan-wide Token limit, accepting values such as ``100M``."""
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    if isinstance(value, bool):
        raise ValueError(_TOKEN_LIMIT_ERROR)  # noqa: TRY004
    if isinstance(value, int):
        limit = value
    elif isinstance(value, str):
        raw_value = value.strip()
        match = _TOKEN_LIMIT_RE.fullmatch(raw_value)
        if match is None:
            raise ValueError(_TOKEN_LIMIT_ERROR)
        number = match.group("number")
        suffix = match.group("suffix").lower()
        try:
            if suffix:
                limit_decimal = Decimal(number) * _TOKEN_LIMIT_MULTIPLIERS[suffix]
                if limit_decimal != limit_decimal.to_integral_value():
                    raise ValueError(_TOKEN_LIMIT_ERROR)
                limit = int(limit_decimal)
            else:
                if "." in number:
                    raise ValueError(_TOKEN_LIMIT_ERROR)
                limit = int(number)
        except (InvalidOperation, ValueError) as exc:
            raise ValueError(_TOKEN_LIMIT_ERROR) from exc
    elif isinstance(value, float) and math.isfinite(value) and value.is_integer():
        limit = int(value)
    else:
        raise ValueError(_TOKEN_LIMIT_ERROR)
    if limit <= 0:
        raise ValueError(_TOKEN_LIMIT_ERROR)
    return limit


def normalize_token_priority(value: Any) -> TokenPriority:
    priority = str(value or "P2").strip().upper()
    if priority not in TOKEN_PRIORITIES:
        raise ValueError(f"任务优先级必须是 P0、P1、P2 或 P3: {value!r}")
    return priority


def normalize_task_estimate(value: Any) -> int:
    if value is None or value == "":
        return DEFAULT_TASK_ESTIMATE_TOKENS
    if isinstance(value, bool):
        raise ValueError("estimated_tokens 必须是大于 0 的整数")  # noqa: TRY004
    try:
        estimate = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("estimated_tokens 必须是大于 0 的整数") from exc
    if estimate <= 0:
        raise ValueError("estimated_tokens 必须是大于 0 的整数")
    return estimate


@dataclass
class TokenBudgetPlan:
    """Mutable scan-wide Token plan shared by all agents in one run."""

    limit: int | None = None
    reserve_ratio: float = TOKEN_RESERVE_RATIO
    tokens_used: int = 0
    estimated_tokens: int = 0
    status: str = "unlimited"
    completed_priorities: list[str] = field(default_factory=list)
    skipped_tasks: list[dict[str, Any]] = field(default_factory=list)
    planned_tasks: list[dict[str, Any]] = field(default_factory=list)
    stop_reason: str | None = None
    enforce_priority_phases: bool = False

    def __post_init__(self) -> None:
        self.limit = normalize_token_limit(self.limit)
        self.tokens_used = max(0, int(self.tokens_used or 0))
        self.estimated_tokens = max(0, int(self.estimated_tokens or 0))
        self._refresh_status()

    @property
    def reserve_tokens(self) -> int:
        if self.limit is None:
            return 0
        return math.ceil(self.limit * self.reserve_ratio)

    @property
    def tokens_remaining(self) -> int | None:
        if self.limit is None:
            return None
        return max(self.limit - self.tokens_used, 0)

    @property
    def is_exhausted(self) -> bool:
        return self.status == "exhausted" or (
            self.limit is not None and self.tokens_used >= self.limit
        )

    def _refresh_status(self) -> None:
        if self.limit is None:
            self.status = "unlimited"
        elif self.tokens_used >= self.limit:
            self.status = "exhausted"
            self.stop_reason = self.stop_reason or "token_limit_exhausted"
        elif self.tokens_used >= self.limit - self.reserve_tokens:
            self.status = "wrap_up"
        elif self.tokens_used > 0:
            self.status = "active"
        else:
            self.status = "planned"

    def record_usage(self, tokens: int, *, estimated: bool = False) -> None:
        amount = max(0, int(tokens or 0))
        if amount == 0:
            return
        self.tokens_used += amount
        if estimated:
            self.estimated_tokens += amount
        self._refresh_status()

    def admit_task(
        self,
        *,
        task_id: str,
        priority: Any,
        estimated_tokens: Any = None,
        mandatory: bool = False,
        details: dict[str, Any] | None = None,
    ) -> tuple[bool, str]:
        normalized_priority = normalize_token_priority(priority)
        estimate = normalize_task_estimate(estimated_tokens)
        task: dict[str, Any] = {
            "task_id": task_id,
            "priority": normalized_priority,
            "estimated_tokens": estimate,
            "mandatory": bool(mandatory),
            "status": "admitted",
        }
        if details:
            task.update(
                {
                    key: value
                    for key, value in details.items()
                    if key not in {"status", "reason"} and value not in (None, "", [])
                }
            )

        if self.enforce_priority_phases or self.limit is not None:
            priority_gate_reason = self._priority_gate_reason(normalized_priority)
            if priority_gate_reason is not None:
                task["status"] = "skipped"
                task["reason"] = priority_gate_reason
                self.skipped_tasks.append(task)
                return False, priority_gate_reason

        if self.limit is None:
            reason = "unlimited"
            self.planned_tasks.append(task)
            return True, reason

        committed_tokens = sum(
            int(item.get("estimated_tokens", 0) or 0)
            for item in self.planned_tasks
            if item.get("status") in {"admitted", "running"}
        )

        # P0/P1 are the high-risk discovery and validation lanes. They may use
        # the reserve when the remaining quota is too small for any other safe
        # work; P2/P3 must leave the reserve for validation and reporting.
        protected_limit = self.limit
        if normalized_priority in {"P2", "P3"} and not mandatory:
            protected_limit = max(self.limit - self.reserve_tokens, 0)

        projected_tokens = self.tokens_used + committed_tokens + estimate
        high_risk_lane = normalized_priority in {"P0", "P1"} or mandatory
        has_available_tokens = self.tokens_used + committed_tokens < self.limit
        if projected_tokens > protected_limit and not (high_risk_lane and has_available_tokens):
            task["status"] = "skipped"
            task["reason"] = "insufficient_token_budget"
            self.skipped_tasks.append(task)
            return False, "insufficient_token_budget"

        self.planned_tasks.append(task)
        return True, "admitted"

    def _priority_gate_reason(self, priority: TokenPriority) -> str | None:
        """Keep lower-risk work behind completed higher-risk phases."""
        active_priorities = {
            item.get("priority")
            for item in self.planned_tasks
            if item.get("status") in {"admitted", "running"}
        }
        completed = set(self.completed_priorities)
        if priority == "P1" and (
            "P0" not in completed or bool(active_priorities & {"P0"})
        ):
            return "priority_gate_closed:P0_incomplete"
        if priority == "P2" and (
            not {"P0", "P1"}.issubset(completed)
            or bool(active_priorities & {"P0", "P1"})
        ):
            return "priority_gate_closed:P0_P1_incomplete"
        if priority == "P3" and (
            not {"P0", "P1", "P2"}.issubset(completed)
            or bool(active_priorities & {"P0", "P1", "P2"})
        ):
            return "priority_gate_closed:P0_P1_P2_incomplete"
        return None

    def mark_task_completed(self, task_id: str) -> None:
        """Release an admitted task's estimate after its child reports back."""
        for task in reversed(self.planned_tasks):
            if task.get("task_id") == task_id and task.get("status") in {
                "admitted",
                "running",
            }:
                task["status"] = "completed"
                return

    def mark_task_failed(self, task_id: str, reason: str = "task_failed") -> None:
        """Release an admitted estimate when its child cannot continue."""
        for task in reversed(self.planned_tasks):
            if task.get("task_id") == task_id and task.get("status") in {
                "admitted",
                "running",
            }:
                task["status"] = "failed"
                task["reason"] = str(reason or "task_failed")[:500]
                return

    def mark_priority_completed(self, priority: Any) -> None:
        normalized_priority = normalize_token_priority(priority)
        if normalized_priority not in self.completed_priorities:
            self.completed_priorities.append(normalized_priority)
            self.completed_priorities.sort(key=TOKEN_PRIORITIES.index)

    def mark_exhausted(self, reason: str = "token_limit_exhausted") -> None:
        if self.limit is None:
            return
        self.status = "exhausted"
        self.stop_reason = reason

    def mark_completed(self) -> None:
        if self.limit is not None and not self.is_exhausted:
            self.status = "completed"

    def to_record(self) -> dict[str, Any]:
        return {
            "token_limit": self.limit,
            "priority_phase_gating": self.enforce_priority_phases,
            "tokens_used": self.tokens_used,
            "tokens_remaining": self.tokens_remaining,
            "token_limit_status": self.status,
            "completed_priorities": list(self.completed_priorities),
            "skipped_tasks": list(self.skipped_tasks[-200:]),
            "planned_tasks": list(self.planned_tasks[-500:]),
            "stop_reason": self.stop_reason,
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> TokenBudgetPlan:
        usage = record.get("llm_usage")
        usage_record = usage if isinstance(usage, dict) else {}
        effective_tokens = usage_record.get("effective_total_tokens")
        if effective_tokens is None:
            effective_tokens = usage_record.get("total_tokens", 0)
        recorded_tokens = record.get("tokens_used", effective_tokens)
        if not isinstance(recorded_tokens, int):
            recorded_tokens = 0
        plan = cls(
            limit=record.get("token_limit"),
            enforce_priority_phases=bool(record.get("priority_phase_gating", False)),
            tokens_used=recorded_tokens,
            estimated_tokens=usage_record.get("estimated_tokens", 0),
        )
        status = record.get("token_limit_status")
        if isinstance(status, str) and status:
            plan.status = status
        completed = record.get("completed_priorities")
        if isinstance(completed, list):
            plan.completed_priorities = [
                priority
                for priority in completed
                if priority in TOKEN_PRIORITIES
            ]
        skipped = record.get("skipped_tasks")
        if isinstance(skipped, list):
            plan.skipped_tasks = [item for item in skipped if isinstance(item, dict)]
        planned = record.get("planned_tasks")
        if isinstance(planned, list):
            plan.planned_tasks = [item for item in planned if isinstance(item, dict)]
        reason = record.get("stop_reason")
        plan.stop_reason = reason if isinstance(reason, str) and reason else None
        return plan
