"""Description-driven verification intent planning."""

# ruff: noqa: E501, RUF001, TRY300, TRY301

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from agents.models.interface import ModelTracing
from openai.types.responses import ResponseOutputMessage

from strix.config import load_settings
from strix.config.models import StrixProvider, configure_sdk_model_defaults
from strix.core.inputs import make_model_settings
from strix.report.state import get_global_report_state
from strix.verification.models import redact_text
from strix.verification.request import get_field, list_candidate_fields


if TYPE_CHECKING:
    from strix.verification.models import VerificationCase


logger = logging.getLogger(__name__)

SUPPORTED_VULNERABILITY_TYPES = frozenset(
    {
        "idor_bola",
        "sqli",
        "ssrf",
        "command_injection",
        "file_upload",
        "authz_bypass",
    }
)
SUPPORTED_ACTIONS = frozenset(
    {"set", "remove_authentication", "secondary_value", "multipart_marker"}
)
SUPPORTED_ORACLES = frozenset(
    {"response_difference", "authorization_boundary", "identity_marker", "canary_echo"}
)
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_DANGEROUS_MARKER_RE = re.compile(
    r"(?i)(?:union\s+select|information_schema|drop\s+table|delete\s+from|"
    r"insert\s+into|update\s+\w+\s+set|rm\s+-rf|wget\s+|curl\s+|"
    r"(?:bash|sh|powershell)\s+-c|nc\s+-|/etc/passwd)"
)


class IntentGenerationError(ValueError):
    """Raised when a description cannot be converted into a safe intent."""


@dataclass(frozen=True, slots=True)
class IntentProbe:
    """One model-proposed mutation after local validation."""

    field: str | None
    value: str | None
    action: str
    role: str = ""
    pair_id: str = ""
    rationale: str = ""


@dataclass(frozen=True, slots=True)
class VerificationIntent:
    """Validated semantic instructions consumed by the deterministic planner."""

    vulnerability_type: str
    target_fields: tuple[str, ...]
    probes: tuple[IntentProbe, ...]
    oracle_kind: str
    oracle_description: str
    rationale: str
    confidence: float
    source: str = "llm"


INTENT_SYSTEM_PROMPT = """你是 Strix 的漏洞验证计划器。你的工作是把漏洞描述和一个脱敏后的 HTTP 请求结构转换为“受约束的验证意图”，供本地确定性执行器执行。

必须遵守：
1. 只根据问题描述和请求结构选择漏洞类型、目标字段、验证动作和响应判定方式；不要臆造不存在的字段。
2. target_fields 和 probes[].field 只能使用输入中的 candidate_fields；字段路径必须逐字匹配。
3. 只能使用支持的漏洞类型和动作。set 只能修改一个已有字段；remove_authentication、secondary_value、multipart_marker 的语义由本地执行器实现。
4. 只生成低副作用验证载荷。禁止数据提取、联合查询、读文件、执行 shell、联网、写文件、删除/修改业务数据和持久化。
5. SQL 注入只允许布尔真/假或错误差异验证，不要生成 UNION、时间盲注、读取系统表或数据内容的载荷。
6. 如果信息不足，返回空 probes，并在 rationale 中说明阻断原因；不要用猜测填充字段。
7. 输出严格为一个 JSON 对象，不要 Markdown、解释文字或代码围栏。

JSON 格式：
{
  "vulnerability_type": "sqli|idor_bola|ssrf|command_injection|file_upload|authz_bypass",
  "target_fields": ["body.ids[0]"],
  "probes": [
    {"field":"body.ids[0]", "value":"...", "action":"set", "role":"true", "pair_id":"pair-1", "rationale":"..."}
  ],
  "oracle_kind": "response_difference|authorization_boundary|identity_marker|canary_echo",
  "oracle_description": "...",
  "rationale": "...",
  "confidence": 0.0
}
"""


def _extract_response_text(response: Any) -> str:
    parts: list[str] = []
    for item in getattr(response, "output", []):
        if not isinstance(item, ResponseOutputMessage):
            continue
        for chunk in item.content:
            text = getattr(chunk, "text", None)
            if text:
                parts.append(text)
    return "".join(parts)


def _parse_json_object(text: str) -> dict[str, Any]:
    cleaned = text.strip()
    if cleaned.startswith(chr(96) * 3):
        cleaned = re.sub(
            r"^\x60\x60\x60(?:json)?\s*|\s*\x60\x60\x60$",
            "",
            cleaned,
            flags=re.I,
        )
    try:
        value = json.loads(cleaned)
    except json.JSONDecodeError:
        start = cleaned.find("{")
        end = cleaned.rfind("}")
        if start < 0 or end <= start:
            raise IntentGenerationError("验证计划模型没有返回 JSON 对象") from None
        try:
            value = json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError as exc:
            raise IntentGenerationError("验证计划模型返回的 JSON 无法解析") from exc
    if not isinstance(value, dict):
        raise IntentGenerationError("验证计划模型返回的内容不是 JSON 对象")
    return value


def _bounded_text(value: Any, *, name: str, limit: int) -> str:
    if not isinstance(value, str):
        raise IntentGenerationError(f"模型返回的 {name} 必须是字符串")
    cleaned = _CONTROL_RE.sub(" ", value).strip()
    if len(cleaned) > limit:
        raise IntentGenerationError(f"模型返回的 {name} 超过长度限制")
    return cleaned


def _validate_probe(
    raw: Any,
    *,
    candidates: set[str],
    index: int,
) -> IntentProbe:
    if not isinstance(raw, dict):
        raise IntentGenerationError(f"模型返回的第 {index} 个探针格式无效")
    action = _bounded_text(raw.get("action", "set"), name="探针动作", limit=32)
    if action not in SUPPORTED_ACTIONS:
        raise IntentGenerationError(f"模型返回了不支持的探针动作：{action}")

    raw_field = raw.get("field")
    field = None if raw_field is None else _bounded_text(raw_field, name="探针字段", limit=256)
    if action in {"set", "secondary_value"}:
        if field is None or field not in candidates:
            raise IntentGenerationError("模型探针字段不在请求字段白名单中")
    elif field is not None and field not in candidates:
        raise IntentGenerationError("模型探针字段不在请求字段白名单中")

    raw_value = raw.get("value")
    value = None if raw_value is None else _bounded_text(raw_value, name="探针值", limit=4096)
    if action == "set" and value is None:
        raise IntentGenerationError("set 探针必须提供值")
    if value and _DANGEROUS_MARKER_RE.search(value):
        raise IntentGenerationError("模型探针包含被禁止的数据提取或命令执行内容")
    if (
        field
        and field.startswith("header.")
        and value
        and any(marker in value for marker in "\r\n")
    ):
        raise IntentGenerationError("Header 探针值不能包含换行")
    if (
        field
        and field.startswith("cookie.")
        and value
        and any(marker in value for marker in "\r\n;")
    ):
        raise IntentGenerationError("Cookie 探针值包含非法分隔符")

    role = _bounded_text(raw.get("role", ""), name="探针角色", limit=32)
    if role not in {"", "true", "false", "control", "secondary", "marker"}:
        raise IntentGenerationError(f"模型返回了不支持的探针角色：{role}")
    pair_id = _bounded_text(raw.get("pair_id", ""), name="探针对照组", limit=64)
    rationale = _bounded_text(raw.get("rationale", ""), name="探针理由", limit=500)
    return IntentProbe(
        field=field,
        value=value,
        action=action,
        role=role,
        pair_id=pair_id,
        rationale=rationale,
    )


def parse_intent_response(
    text: str,
    *,
    candidate_fields: list[str],
) -> VerificationIntent:
    """Parse and validate model output without permitting executable input."""
    data = _parse_json_object(text)
    vulnerability_type = _bounded_text(
        data.get("vulnerability_type", ""), name="漏洞类型", limit=64
    )
    if vulnerability_type not in SUPPORTED_VULNERABILITY_TYPES:
        raise IntentGenerationError(f"模型返回了不支持的漏洞类型：{vulnerability_type}")

    candidates = set(candidate_fields)
    raw_fields = data.get("target_fields", [])
    if not isinstance(raw_fields, list):
        raise IntentGenerationError("模型返回的 target_fields 必须是数组")
    target_fields = tuple(
        _bounded_text(item, name="目标字段", limit=256) for item in raw_fields[:10]
    )
    if any(item not in candidates for item in target_fields):
        raise IntentGenerationError("模型返回的目标字段不在请求字段白名单中")

    raw_probes = data.get("probes", [])
    if not isinstance(raw_probes, list):
        raise IntentGenerationError("模型返回的 probes 必须是数组")
    if len(raw_probes) > 20:
        raise IntentGenerationError("模型返回的探针数量超过 20 个上限")
    probes = tuple(
        _validate_probe(item, candidates=candidates, index=index)
        for index, item in enumerate(raw_probes, start=1)
    )
    oracle_kind = _bounded_text(data.get("oracle_kind", ""), name="判定器类型", limit=64)
    if oracle_kind not in SUPPORTED_ORACLES:
        raise IntentGenerationError(f"模型返回了不支持的判定器：{oracle_kind}")
    oracle_description = _bounded_text(
        data.get("oracle_description", ""), name="判定器说明", limit=1000
    )
    rationale = _bounded_text(data.get("rationale", ""), name="计划理由", limit=2000)
    try:
        confidence = float(data.get("confidence", 0.0))
    except (TypeError, ValueError) as exc:
        raise IntentGenerationError("模型返回的 confidence 无效") from exc
    if not 0.0 <= confidence <= 1.0:
        raise IntentGenerationError("模型返回的 confidence 必须在 0 到 1 之间")
    return VerificationIntent(
        vulnerability_type=vulnerability_type,
        target_fields=target_fields,
        probes=probes,
        oracle_kind=oracle_kind,
        oracle_description=oracle_description,
        rationale=rationale,
        confidence=confidence,
    )


def _candidate_context(case: VerificationCase) -> dict[str, Any]:
    fields = list_candidate_fields(case.request)

    def safe_current_value(path: str) -> str | None:
        value = get_field(case.request, path)
        if value is None:
            return None
        if path.startswith(("cookie.", "header.")) or re.search(
            r"(?i)(token|secret|password|passwd|authorization|cookie|session|key)",
            path,
        ):
            return "<redacted>"
        return redact_text(value)

    return {
        "request": case.request.to_dict(redact=True),
        "candidate_fields": [
            {
                "path": path,
                "current_value": safe_current_value(path),
            }
            for path in fields
        ],
        "supporting_request_count": len(case.supporting_requests),
    }


async def infer_verification_intent(case: VerificationCase) -> VerificationIntent:
    """Ask the configured Strix model for a bounded intent and validate it locally."""
    settings = load_settings()
    model_name = (settings.llm.model or "").strip()
    if not model_name:
        raise IntentGenerationError(
            "漏洞验证需要配置 STRIX_LLM；模型负责理解描述，执行器不会用固定漏洞模板猜测"
        )

    user_input = (
        "问题描述：\n"
        + redact_text(case.issue_description.strip())[:2000]
        + "\n\n脱敏请求结构：\n"
        + json.dumps(_candidate_context(case), ensure_ascii=False, indent=2)
    )
    try:
        configure_sdk_model_defaults(settings)
        model = StrixProvider().get_model(model_name)
        response = await model.get_response(
            system_instructions=INTENT_SYSTEM_PROMPT,
            input=user_input,
            model_settings=make_model_settings(
                settings.llm.reasoning_effort,
                model_name=model_name,
                request_timeout=settings.llm.timeout,
                has_tools=False,
            ),
            tools=[],
            output_schema=None,
            handoffs=[],
            tracing=ModelTracing.DISABLED,
            previous_response_id=None,
            conversation_id=None,
            prompt=None,
        )
        report_state = get_global_report_state()
        if report_state is not None:
            report_state.record_sdk_usage(
                agent_id="verification-planner",
                agent_name="verification-planner",
                model=model_name,
                usage=response.usage,
            )
        content = _extract_response_text(response)
        if not content:
            raise IntentGenerationError("验证计划模型没有返回内容")
        intent = parse_intent_response(
            content,
            candidate_fields=list_candidate_fields(case.request),
        )
        logger.info(
            "Verification intent generated: type=%s fields=%s probes=%d confidence=%.2f",
            intent.vulnerability_type,
            intent.target_fields,
            len(intent.probes),
            intent.confidence,
        )
        return intent
    except IntentGenerationError:
        raise
    except Exception as exc:
        logger.exception("Verification intent generation failed")
        raise IntentGenerationError(f"验证计划模型调用失败：{exc}") from exc


__all__ = [
    "SUPPORTED_ACTIONS",
    "SUPPORTED_ORACLES",
    "SUPPORTED_VULNERABILITY_TYPES",
    "IntentGenerationError",
    "IntentProbe",
    "VerificationIntent",
    "infer_verification_intent",
    "parse_intent_response",
]
