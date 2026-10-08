"""SDK run hooks used by Strix orchestration."""

from __future__ import annotations

import logging
import math
from typing import TYPE_CHECKING, Any

from agents.lifecycle import RunHooks

from strix.core.token_budget import (
    DEFAULT_TOKEN_ESTIMATE_PER_REQUEST,
    TOKEN_RESERVE_RATIO,
    normalize_token_limit,
    normalize_token_priority,
)
from strix.core.agents import BudgetPolicy, coordinator_from_context
from strix.report.state import get_global_report_state


if TYPE_CHECKING:
    from agents import RunContextWrapper
    from agents.agent import Agent
    from agents.items import ModelResponse, TResponseInputItem


logger = logging.getLogger(__name__)


LLM_TURN_KEY = "llm_turn"

# ``BudgetPolicy`` decides what happens when the accumulated LLM cost reaches
# ``max_budget_usd``.
#
# ``stop``: the agents are warned as the limit approaches, sub-agents are cut at
# a reserve so the root can write its report, and the scan ends at the limit.
#
# ``pause``: the agents are never told a limit exists. Every agent parks right
# before its next LLM call once the limit is reached (or an operator pauses the
# scan), keeping its session, context and sandbox alive, and continues with that
# same call when the operator raises the limit or resumes.
__all__ = [
    "LLM_TURN_KEY",
    "BudgetExceededError",
    "BudgetPausedError",
    "BudgetPolicy",
    "ReportUsageHooks",
    "SubagentBudgetReservedError",
    "recomputed_budget_flags",
]

_STAGE_LABELS: tuple[str, ...] = ("NOTICE", "URGENT", "CRITICAL")
_TURN_WARN_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
_ROOT_BUDGET_WARN_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
_SUBAGENT_BUDGET_WARN_BANDS: tuple[float, ...] = (0.75, 0.80, 0.85)
_SUBAGENT_BUDGET_RESERVE = 0.90
_TOKEN_WARN_BANDS: tuple[float, ...] = (0.70, 0.85, 0.95)
_IMAGE_TOKEN_RESERVATION = 4_096


class BudgetExceededError(RuntimeError):
    """Raised when the accumulated LLM cost reaches the configured budget."""


class TokenLimitExceededError(BudgetExceededError):
    """Raised when effective scan-wide Tokens reach the configured limit."""


class SubagentBudgetReservedError(RuntimeError):
    """Raised to stop a single sub-agent once the reserve threshold is crossed."""


class TokenReserveExceededError(SubagentBudgetReservedError):
    """Raised when ordinary sub-agent work would consume the reporting reserve."""


class BudgetPausedError(RuntimeError):
    """Raised to park one agent until the scan budget is raised or the pause lifted.

    ``resume_epoch`` is the coordinator's ``resume_epoch`` at the moment the agent
    decided to park; the agent waits for a resume newer than that.
    """

    def __init__(self, message: str, *, resume_epoch: int = 0) -> None:
        super().__init__(message)
        self.resume_epoch = resume_epoch


def _token_budget_text(value: Any) -> tuple[str, int]:
    """Serialize request text without expanding image payloads into base64."""
    if isinstance(value, str):
        return value, 0
    if isinstance(value, bytes):
        return "[binary content]", 0
    if isinstance(value, list | tuple):
        parts: list[str] = []
        images = 0
        for item in value:
            text, item_images = _token_budget_text(item)
            if text:
                parts.append(text)
            images += item_images
        return "\n".join(parts), images
    if isinstance(value, dict):
        item_type = str(value.get("type") or "").lower()
        if item_type in {"image", "image_url", "input_image", "output_image"}:
            return "[image]", 1
        parts = []
        images = 0
        for key, item in value.items():
            if key in {"data", "b64_json", "id", "call_id"}:
                continue
            text, item_images = _token_budget_text(item)
            if text:
                parts.append(text)
            images += item_images
        return "\n".join(parts), images
    if isinstance(value, int | float | bool):
        return str(value), 0
    return str(value), 0


def _validate_budget(max_budget_usd: float | None) -> None:
    if max_budget_usd is not None and (not math.isfinite(max_budget_usd) or max_budget_usd <= 0):
        raise ValueError("max_budget_usd must be a finite number greater than 0")


def recomputed_budget_flags(
    cost: float,
    max_budget_usd: float | None,
    *,
    interactive: bool,
    budget_policy: BudgetPolicy = "stop",
) -> tuple[bool, bool]:
    """Return the (budget_stopped, reserve_stopped) flags a resumed scan should carry."""
    if max_budget_usd is None:
        return False, False
    if interactive or budget_policy == "pause":
        return False, False
    budget_stopped = cost >= max_budget_usd
    reserve_stopped = cost >= max_budget_usd * _SUBAGENT_BUDGET_RESERVE
    return budget_stopped, reserve_stopped


def _crossed_stage(fraction: float, bands: tuple[float, ...]) -> int | None:
    crossed: int | None = None
    for index, band in enumerate(bands):
        if fraction >= band:
            crossed = index
    return crossed


_ROOT_DIRECTIVES: tuple[str, ...] = (
    (
        "As the root agent, begin planning your wind-down of the whole scan: avoid "
        "starting large new lines of investigation, and keep your required objectives on "
        "track so you can call finish_scan comfortably before the limit."
    ),
    (
        "As the root agent, prioritize wrapping up the whole scan now: stop opening new "
        "lines of investigation, close out only what is essential, and move toward calling "
        "finish_scan to compile and deliver the final report."
    ),
    (
        "As the root agent, STOP all other work on the whole scan and finish immediately: "
        "secure your findings and call finish_scan now — anything left unfinished when the "
        "limit is hit is discarded."
    ),
)
_SUBAGENT_DIRECTIVES: tuple[str, ...] = (
    (
        "As a sub-agent, begin planning your wind-down: avoid starting large new subtasks, "
        "and if you are close to a confirmed, validated vulnerability, drive it to a result "
        "you can report."
    ),
    (
        "As a sub-agent, prioritize wrapping up your task now: report any confirmed, "
        "validated vulnerability, finish work that is nearly done rather than starting "
        "anything new, and prepare to call agent_finish."
    ),
    (
        "As a sub-agent, STOP all other work and finish immediately: report any confirmed "
        "vulnerability right now and call agent_finish to hand your results back to your "
        "parent before you are cut off."
    ),
)


def _wrapup_directive(context: RunContextWrapper[dict[str, Any]], stage: int) -> str:
    is_root = context.context.get("parent_id") is None
    directives = _ROOT_DIRECTIVES if is_root else _SUBAGENT_DIRECTIVES
    return directives[stage]


def _urgency(stage: int) -> str:
    return _STAGE_LABELS[stage]


class ReportUsageHooks(RunHooks[dict[str, Any]]):
    """Persist SDK-native usage and warn/stop as turn and cost budgets are consumed."""

    def __init__(
        self,
        *,
        model: str,
        max_budget_usd: float | None = None,
        token_limit: int | None = None,
        max_turns: int | None = None,
        interactive: bool = False,
        budget_policy: BudgetPolicy = "stop",
    ) -> None:
        _validate_budget(max_budget_usd)
        if max_turns is not None and max_turns <= 0:
            raise ValueError("max_turns must be a positive integer")
        if budget_policy not in ("stop", "pause"):
            raise ValueError(f"unknown budget_policy: {budget_policy!r}")
        self._model = model
        self._max_budget_usd = max_budget_usd
        self._budget_increment = max_budget_usd
        self._token_limit = normalize_token_limit(token_limit)
        self._max_turns = max_turns
        self._interactive = interactive
        self._budget_policy: BudgetPolicy = budget_policy
        self._token_reservations: dict[str, int] = {}

    @property
    def max_budget_usd(self) -> float | None:
        return self._max_budget_usd

    @property
    def budget_policy(self) -> BudgetPolicy:
        return self._budget_policy

    def set_max_budget_usd(self, max_budget_usd: float | None) -> None:
        """Replace the scan's cost limit; ``None`` removes it."""
        _validate_budget(max_budget_usd)
        self._max_budget_usd = max_budget_usd

    def extend_budget(self) -> None:
        if self._max_budget_usd is None or self._budget_increment is None:
            return
        self._max_budget_usd += self._budget_increment

    async def on_llm_start(
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],  # noqa: ARG002
        system_prompt: str | None,
        input_items: list[TResponseInputItem],
    ) -> None:
        if self._budget_policy == "pause":
            self._pause_if_limited(context)
        context.context[LLM_TURN_KEY] = int(context.context.get(LLM_TURN_KEY, 0)) + 1
        try:
            self._maybe_warn_turns(context, input_items)
            self._maybe_warn_budget(context, input_items)
            self._maybe_warn_token_budget(context, input_items)
            self._check_token_budget_before_llm(context, system_prompt, input_items)
        except (TokenLimitExceededError, TokenReserveExceededError):
            raise
        except Exception:
            logger.exception("budget/turn warning injection failed")

    def _task_priority(self, context: RunContextWrapper[dict[str, Any]]) -> str:
        try:
            return normalize_token_priority(context.context.get("task_priority", "P2"))
        except (TypeError, ValueError):
            return "P2"

    def _check_token_budget_before_llm(
        self,
        context: RunContextWrapper[dict[str, Any]],
        system_prompt: str | None,
        input_items: list[TResponseInputItem],
    ) -> None:
        if self._token_limit is None:
            return
        report_state = get_global_report_state()
        if report_state is None:
            return
        reservation_key = self._reservation_key(context)
        reserved_elsewhere = sum(self._token_reservations.values()) - self._token_reservations.get(
            reservation_key, 0
        )
        used = report_state.get_total_llm_tokens() + reserved_elsewhere
        if used >= self._token_limit:
            raise TokenLimitExceededError(
                f"Scan Token limit of {self._token_limit} reached or reserved (used {used})"
            )
        is_root = context.context.get("parent_id") is None
        is_high_risk = is_root or self._task_priority(context) in {"P0", "P1"}
        reserve_limit = int(self._token_limit * (1 - TOKEN_RESERVE_RATIO))
        if not is_high_risk and used >= reserve_limit:
            raise TokenReserveExceededError(
                f"Ordinary sub-agent work reached the Token discovery limit: used {used} "
                f"of {self._token_limit}; the final 20% is reserved for high-risk "
                "validation and reporting"
            )

        request_reservation = self._estimate_request_tokens(system_prompt, input_items)
        projected = used + request_reservation
        if projected > self._token_limit:
            raise TokenLimitExceededError(
                f"The next LLM request is estimated to need {request_reservation} Tokens; "
                f"only {self._token_limit - used} remain under the scan limit"
            )
        if not is_high_risk and projected > reserve_limit:
            raise TokenReserveExceededError(
                "The next ordinary sub-agent request would consume the final 20% reserved "
                "for high-risk validation and reporting"
            )
        self._token_reservations[reservation_key] = request_reservation

    def _estimate_request_tokens(
        self,
        system_prompt: str | None,
        input_items: list[TResponseInputItem],
    ) -> int:
        """Reserve prompt, tool-schema overhead, and the model's output window."""
        try:
            from strix.llm.context_budget import count_tokens, output_limit
        except Exception:
            logger.exception("could not load Token reservation estimators")
            input_text, image_count = _token_budget_text(input_items)
            prompt = "\n".join((system_prompt or "", input_text))
            return (
                len(prompt.encode("utf-8"))
                + image_count * _IMAGE_TOKEN_RESERVATION
                + DEFAULT_TOKEN_ESTIMATE_PER_REQUEST * 3
            )

        input_text, image_count = _token_budget_text(input_items)
        prompt = "\n".join((system_prompt or "", input_text))
        try:
            prompt_tokens = count_tokens(self._model, prompt)
        except Exception:
            logger.exception("could not count prompt Tokens for the next LLM request")
            prompt_tokens = len(prompt.encode("utf-8"))
        try:
            max_output_tokens = output_limit(self._model)
        except Exception:
            logger.exception("could not resolve the model output Token limit")
            max_output_tokens = DEFAULT_TOKEN_ESTIMATE_PER_REQUEST * 2
        return (
            prompt_tokens
            + image_count * _IMAGE_TOKEN_RESERVATION
            + DEFAULT_TOKEN_ESTIMATE_PER_REQUEST
            + max_output_tokens
        )

    @staticmethod
    def _reservation_key(context: RunContextWrapper[dict[str, Any]]) -> str:
        context_data = context.context if isinstance(context.context, dict) else {}
        agent_id = context_data.get("agent_id")
        if isinstance(agent_id, str) and agent_id:
            return agent_id
        return f"context:{id(context)}"

    def release_token_reservation(self, agent_id: str) -> None:
        """Release a pending estimate after an LLM call or its run cycle ends."""
        self._token_reservations.pop(agent_id, None)

    def _pause_if_limited(self, context: RunContextWrapper[dict[str, Any]]) -> None:
        """Park the agent before a paid call when the scan is at its limit or paused."""
        coordinator = coordinator_from_context(context.context)
        epoch = coordinator.resume_epoch if coordinator is not None else 0
        if coordinator is not None and coordinator.budget_paused:
            raise BudgetPausedError(
                "scan paused; waiting for the operator to resume", resume_epoch=epoch
            )
        if self._max_budget_usd is None:
            return
        report_state = get_global_report_state()
        if report_state is None:
            return
        cost = report_state.get_total_llm_cost()
        if cost >= self._max_budget_usd:
            raise BudgetPausedError(
                f"Scan budget of ${self._max_budget_usd:.2f} reached (spent ${cost:.4f}); "
                "pausing until the operator raises the limit",
                resume_epoch=epoch,
            )

    def _maybe_warn_token_budget(
        self,
        context: RunContextWrapper[dict[str, Any]],
        input_items: list[TResponseInputItem],
    ) -> None:
        if self._token_limit is None:
            return
        report_state = get_global_report_state()
        if report_state is None:
            return
        used = report_state.get_total_llm_tokens()
        stage = _crossed_stage(used / self._token_limit, _TOKEN_WARN_BANDS)
        if stage is None:
            return
        remaining = max(self._token_limit - used, 0)
        pct = round(100 * used / self._token_limit)
        input_items.append(
            {
                "role": "user",
                "content": (
                    f"[{_urgency(stage)}] Scan Token budget: {used}/{self._token_limit} "
                    f"used ({pct}%), about {remaining} remain. Current task priority is "
                    f"{self._task_priority(context)}. Finish serious/high-risk discovery, "
                    "validation and reporting before starting medium/low-risk breadth work."
                ),
            }
        )

    def _maybe_warn_turns(
        self,
        context: RunContextWrapper[dict[str, Any]],
        input_items: list[TResponseInputItem],
    ) -> None:
        if not self._max_turns:
            return
        usage = getattr(context, "usage", None)
        requests = getattr(usage, "requests", None)
        if not isinstance(requests, int):
            return
        turns_used = requests + 1
        stage = _crossed_stage(turns_used / self._max_turns, _TURN_WARN_BANDS)
        if stage is None:
            return
        remaining = max(self._max_turns - turns_used, 0)
        pct = round(100 * turns_used / self._max_turns)
        content = (
            f"[{_urgency(stage)}] Turn budget: {turns_used}/{self._max_turns} used ({pct}%). "
            f"About {remaining} turn(s) remain before this agent is force-stopped and any "
            f"in-progress work is discarded. {_wrapup_directive(context, stage)}"
        )
        input_items.append({"role": "user", "content": content})

    def _maybe_warn_budget(
        self,
        context: RunContextWrapper[dict[str, Any]],
        input_items: list[TResponseInputItem],
    ) -> None:
        if self._max_budget_usd is None or self._budget_policy == "pause":
            return
        report_state = get_global_report_state()
        if report_state is None:
            return
        cost = report_state.get_total_llm_cost()
        is_root = context.context.get("parent_id") is None
        if self._interactive:
            bands = _ROOT_BUDGET_WARN_BANDS
        else:
            bands = _ROOT_BUDGET_WARN_BANDS if is_root else _SUBAGENT_BUDGET_WARN_BANDS
        stage = _crossed_stage(cost / self._max_budget_usd, bands)
        if stage is None:
            return
        pct = round(100 * cost / self._max_budget_usd)
        reserve_pct = round(_SUBAGENT_BUDGET_RESERVE * 100)
        if self._interactive:
            content = (
                f"[{_urgency(stage)}] Scan cost budget: ${cost:.2f}/${self._max_budget_usd:.2f} "
                f"spent ({pct}%). This budget is shared across every agent in the scan; when it "
                "is reached all agents are paused until the user chooses to continue. "
                f"{_wrapup_directive(context, stage)}"
            )
        elif is_root:
            content = (
                f"[{_urgency(stage)}] Scan cost budget: ${cost:.2f}/${self._max_budget_usd:.2f} "
                f"spent ({pct}%). This budget is shared across every agent in the scan; when it "
                "is reached the whole scan is stopped immediately, and sub-agents are stopped at "
                f"{reserve_pct}% to reserve the remainder for your final report. "
                f"{_wrapup_directive(context, stage)}"
            )
        else:
            content = (
                f"[{_urgency(stage)}] Scan cost budget: ${cost:.2f}/${self._max_budget_usd:.2f} "
                f"spent ({pct}%). This budget is shared across every agent in the scan; "
                f"sub-agents are stopped at {reserve_pct}% to leave the remainder for the root "
                f"agent's final report. {_wrapup_directive(context, stage)}"
            )
        input_items.append({"role": "user", "content": content})

    async def on_llm_end(  # noqa: PLR0912
        self,
        context: RunContextWrapper[dict[str, Any]],
        agent: Agent[dict[str, Any]],
        response: ModelResponse,
    ) -> None:
        reservation_key = self._reservation_key(context)
        report_state = get_global_report_state()
        if report_state is None:
            self._token_reservations.pop(reservation_key, None)
            return

        ctx = context.context if isinstance(context.context, dict) else {}
        agent_name = getattr(agent, "name", None)
        if not isinstance(agent_name, str):
            agent_name = None
        agent_id = ctx.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            agent_id = agent_name or "unknown"

        try:
            report_state.record_sdk_usage(
                agent_id=agent_id,
                agent_name=agent_name,
                model=self._model,
                usage=response.usage,
                fallback_tokens=DEFAULT_TOKEN_ESTIMATE_PER_REQUEST,
            )
        except Exception:
            logger.exception("failed to record SDK usage for agent %s", agent_id)
        finally:
            self._token_reservations.pop(reservation_key, None)

        if self._token_limit is not None:
            tokens = report_state.get_total_llm_tokens()
            pending = sum(self._token_reservations.values())
            projected = tokens + pending
            if projected >= self._token_limit:
                raise TokenLimitExceededError(
                    f"Scan Token limit of {self._token_limit} reached or reserved "
                    f"(used {tokens}, reserved {pending})"
                )
            is_root = ctx.get("parent_id") is None
            if not is_root and self._task_priority(context) not in {"P0", "P1"}:
                reserve_limit = int(self._token_limit * (1 - TOKEN_RESERVE_RATIO))
                if projected >= reserve_limit:
                    raise TokenReserveExceededError(
                        f"Ordinary sub-agent work reached the Token discovery limit: "
                        f"used or reserved {projected} of {self._token_limit}; "
                        "the final 20% is reserved "
                        "for high-risk validation and reporting"
                    )
        if self._budget_policy == "pause":
            # The finished call is paid for and its tool calls still run for free;
            # the agent parks before its next call, in ``on_llm_start``.
            return

        if self._max_budget_usd is not None:
            cost = report_state.get_total_llm_cost()
            if cost >= self._max_budget_usd:
                if self._interactive:
                    raise BudgetPausedError(
                        f"Scan budget of ${self._max_budget_usd:.2f} reached "
                        f"(spent ${cost:.4f}); pausing until the user continues"
                    )
                raise BudgetExceededError(
                    f"Token budget of ${self._max_budget_usd:.2f} exceeded (spent ${cost:.4f})"
                )
            is_root = ctx.get("parent_id") is None
            if not self._interactive and not is_root:
                reserve_limit = self._max_budget_usd * _SUBAGENT_BUDGET_RESERVE
                if cost >= reserve_limit:
                    raise SubagentBudgetReservedError(
                        f"Sub-agent budget reserve reached: spent ${cost:.4f} of "
                        f"${self._max_budget_usd:.2f} "
                        f"(>= {round(_SUBAGENT_BUDGET_RESERVE * 100)}% reserve); stopping this "
                        "sub-agent so the root agent can finish the scan."
                    )
