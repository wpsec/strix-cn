"""Tests for the bounded single-case vulnerability verification workflow."""

# ruff: noqa: RUF001

from __future__ import annotations

import asyncio
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlsplit

import pytest


if TYPE_CHECKING:
    from pathlib import Path

from strix.interface import cli_args, verification_cli
from strix.verification import (
    IntentGenerationError,
    IntentProbe,
    VerificationCase,
    VerificationIntent,
    VerificationResult,
    build_verification_plan,
    compare_results,
    executor,
    parse_intent_response,
    parse_request_text,
)
from strix.verification.executor import HttpObservation, execute_plan
from strix.verification.models import redact_response_body, request_shape_sha256
from strix.verification.request import get_field, list_candidate_fields, set_field
from strix.verification.runner import run_verification_case


def test_raw_and_curl_requests_preserve_replay_credentials() -> None:
    raw = """GET /orders?orderId=42 HTTP/1.1
Host: app.test
Authorization: Bearer raw-secret
Cookie: session=secret-cookie

"""
    with pytest.raises(ValueError, match="缺少 Scheme"):
        parse_request_text(raw)

    request = parse_request_text(raw, scheme="https")
    assert request.url == "https://app.test/orders?orderId=42"
    assert request.to_dict()["headers"]["Authorization"] == "Bearer raw-secret"
    assert "raw-secret" in json.dumps(request.to_dict())
    assert request.to_dict(redact=True)["headers"]["Authorization"] == "<redacted>"

    browser_raw = """POST /api/MedicareDict/GetItemList HTTP/1.1
Host: ygt.arrmyy.cn:4443
Content-Type: application/json
Origin: https://ygt.arrmyy.cn:4443
Referer: https://ygt.arrmyy.cn:4443/
X-Requested-With: XMLHttpRequest
Content-Length: 42

{"RegId":"1","PatId":"1","ids":["1"]}
"""
    inferred = parse_request_text(browser_raw)
    assert inferred.scheme == "https"
    assert inferred.url == "https://ygt.arrmyy.cn:4443/api/MedicareDict/GetItemList"
    assert "body.ids[0]" in list_candidate_fields(inferred)
    mutated = set_field(inferred, "body.ids[0]", "1' OR '1'='1")
    assert get_field(mutated, "body.ids[0]") == "1' OR '1'='1"
    assert "\"ids\":[\"1' OR '1'='1\"]" in mutated.body

    query_secret = parse_request_text(
        "GET https://app.test/search?access_token=query-secret HTTP/1.1\nHost: app.test\n\n"
    )
    assert "query-secret" in json.dumps(query_secret.to_dict())
    assert "response-secret" not in redact_response_body(
        '{"access_token":"response-secret"}',
        "application/json",
    )

    curl = parse_request_text(
        "curl 'https://app.test/search?q=one' "
        "-H 'Authorization: Bearer curl-secret' "
        "-H 'Content-Type: application/json' "
        "--data-raw '{\"id\":1}'"
    )
    assert curl.method == "POST"
    assert curl.scheme == "https"
    assert curl.body == '{"id":1}'
    assert curl.to_dict()["headers"]["Authorization"] == "Bearer curl-secret"

    multipart = parse_request_text("curl 'https://app.test/upload' -F 'file=@sample.txt'")
    assert multipart.method == "POST"
    assert "multipart/form-data" in multipart.headers["Content-Type"]
    assert 'filename="sample.txt"' in multipart.body

    with pytest.raises(ValueError, match="URL 与 Host"):
        parse_request_text("GET https://app.test/search HTTP/1.1\nHost: other.test\n\n")

    changed_value = parse_request_text(
        "GET /orders?orderId=43 HTTP/1.1\n"
        "Host: app.test\n"
        "Authorization: Bearer changed-secret\n"
        "Cookie: session=changed-cookie\n\n",
        scheme="https",
    )
    assert request_shape_sha256(request) == request_shape_sha256(changed_value)


def test_planner_requires_model_intent_and_applies_generic_capability_limits() -> None:
    request = parse_request_text(
        "GET https://app.test/orders?orderId=42 HTTP/1.1\n"
        "Host: app.test\n"
        "Cookie: session=test-session\n\n"
    )
    unplanned = build_verification_plan(
        VerificationCase(request=request, issue_description="读取其他用户订单")
    )
    assert unplanned.vulnerability_type == "unclassified"
    assert unplanned.probes == []
    assert unplanned.blocked_reason is not None

    secondary_intent = VerificationIntent(
        vulnerability_type="对象访问边界问题",
        strategy_kind="secondary_identity",
        target_fields=("query.orderId",),
        probes=(
            IntentProbe(
                field="query.orderId",
                value=None,
                action="secondary_value",
            ),
        ),
        oracle_kind="authorization_boundary",
        oracle_description="第二身份请求不应读取越权对象。",
        rationale="需要第二身份请求进行对照。",
        confidence=0.8,
    )
    secondary_plan = build_verification_plan(
        VerificationCase(request=request, issue_description="读取其他用户订单"),
        intent=secondary_intent,
    )
    assert secondary_plan.probes[0].requires_secondary_identity is True
    assert secondary_plan.blocked_reason is not None

    canary_intent = VerificationIntent(
        vulnerability_type="服务端请求边界问题",
        strategy_kind="controlled_canary",
        target_fields=("query.url",),
        probes=(
            IntentProbe(
                field="query.url",
                value="http://127.0.0.1:80",
                action="set",
            ),
        ),
        oracle_kind="canary_echo",
        oracle_description="响应应出现受控 Canary。",
        rationale="需要验证 URL 字段的出站请求边界。",
        confidence=0.7,
    )
    canary_plan = build_verification_plan(
        VerificationCase(
            request=parse_request_text(
                "GET https://app.test/fetch?url=https://example.test HTTP/1.1\nHost: app.test\n\n"
            ),
            issue_description="验证 URL 字段的出站请求边界",
            controlled_canary_url="http://127.0.0.1:80",
        ),
        intent=canary_intent,
    )
    assert canary_plan.blocked_reason is not None
    assert "内网" in canary_plan.blocked_reason

    upload_intent = VerificationIntent(
        vulnerability_type="文件处理边界问题",
        strategy_kind="multipart_marker",
        target_fields=(),
        probes=(
            IntentProbe(
                field=None,
                value="strix-verification-marker",
                action="multipart_marker",
            ),
        ),
        oracle_kind="canary_echo",
        oracle_description="响应应出现受控 marker。",
        rationale="需要验证 multipart 内容处理边界。",
        confidence=0.6,
    )
    upload_plan = build_verification_plan(
        VerificationCase(
            request=parse_request_text(
                "POST https://app.test/upload HTTP/1.1\n"
                "Host: app.test\n"
                "Content-Type: multipart/form-data; boundary=demo\n\n"
                '--demo\nContent-Disposition: form-data; name="file"; filename="a.txt"\n\n'
                "body\n--demo--\n"
            ),
            issue_description="验证 multipart 内容处理边界",
        ),
        intent=upload_intent,
    )
    assert upload_plan.probes[0].cleanup_required is True
    assert upload_plan.blocked_reason is not None


def test_single_field_difference_is_not_reported_as_confirmed_vulnerability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = parse_request_text("GET https://app.test/search?q=hello HTTP/1.1\nHost: app.test\n\n")
    plan = build_verification_plan(
        VerificationCase(request=request, issue_description="验证输入字段边界"),
        intent=VerificationIntent(
            vulnerability_type="输入处理边界问题",
            strategy_kind="field_mutation",
            target_fields=("query.q",),
            probes=(IntentProbe(field="query.q", value="probe", action="set"),),
            oracle_kind="response_difference",
            oracle_description="记录输入变异后的响应差异。",
            rationale="单字段变异只能作为诊断证据。",
            confidence=0.5,
        ),
    )
    observations = iter(
        [
            HttpObservation(200, {}, "normal"),
            HttpObservation(400, {}, "invalid input"),
        ]
    )
    monkeypatch.setattr(executor, "send_request", lambda _request: next(observations))
    result = execute_plan(plan, request, run_name="verify-single-field", approved=True)
    assert result.status == "inconclusive"
    assert "不能确认漏洞" in result.summary


def test_blocked_secondary_strategy_has_explicit_secondary_status() -> None:
    request = parse_request_text(
        "GET https://app.test/orders?orderId=42 HTTP/1.1\nHost: app.test\n\n"
    )
    plan = build_verification_plan(
        VerificationCase(request=request, issue_description="验证对象边界"),
        intent=VerificationIntent(
            vulnerability_type="对象访问边界问题",
            strategy_kind="secondary_identity",
            target_fields=("query.orderId",),
            probes=(
                IntentProbe(
                    field="query.orderId",
                    value=None,
                    action="secondary_value",
                ),
            ),
            oracle_kind="authorization_boundary",
            oracle_description="需要第二身份作为对象对照。",
            rationale="第二身份请求缺失。",
            confidence=0.8,
        ),
    )
    result = execute_plan(plan, request, run_name="verify-secondary-blocked", approved=True)
    assert result.status == "needs_secondary_identity"


def test_control_alignment_includes_status_code(monkeypatch: pytest.MonkeyPatch) -> None:
    request = parse_request_text("GET https://app.test/items?id=1 HTTP/1.1\nHost: app.test\n\n")
    plan = build_verification_plan(
        VerificationCase(request=request, issue_description="验证成对响应边界"),
        intent=VerificationIntent(
            vulnerability_type="输入处理边界问题",
            strategy_kind="paired_field_mutation",
            target_fields=("query.id",),
            probes=(
                IntentProbe(
                    field="query.id",
                    value="true",
                    action="set",
                    role="true",
                    pair_id="pair-1",
                ),
                IntentProbe(
                    field="query.id",
                    value="false",
                    action="set",
                    role="false",
                    pair_id="pair-1",
                ),
            ),
            oracle_kind="response_difference",
            oracle_description="成对响应需要稳定对照。",
            rationale="验证成对响应。",
            confidence=0.8,
        ),
    )
    observations = iter(
        [
            HttpObservation(200, {}, "same"),
            HttpObservation(500, {}, "same"),
            HttpObservation(200, {}, "different"),
        ]
    )
    monkeypatch.setattr(executor, "send_request", lambda _request: next(observations))
    result = execute_plan(plan, request, run_name="verify-status-alignment", approved=True)
    assert result.status == "inconclusive"


def test_delay_probe_is_blocked_for_every_strategy() -> None:
    request = parse_request_text("GET https://app.test/items?id=1 HTTP/1.1\nHost: app.test\n\n")
    plan = build_verification_plan(
        VerificationCase(request=request, issue_description="验证输入处理边界"),
        intent=VerificationIntent(
            vulnerability_type="输入处理边界问题",
            strategy_kind="field_mutation",
            target_fields=("query.id",),
            probes=(
                IntentProbe(
                    field="query.id",
                    value="probe",
                    action="set",
                    role="delay",
                ),
            ),
            oracle_kind="response_difference",
            oracle_description="不执行耗时型探针。",
            rationale="描述包含耗时验证要求。",
            confidence=0.7,
        ),
    )
    assert plan.blocked_reason is not None
    assert "耗时型" in plan.blocked_reason


def test_identity_marker_already_in_control_response_is_not_confirmed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = parse_request_text("GET https://app.test/items?id=1 HTTP/1.1\nHost: app.test\n\n")
    plan = build_verification_plan(
        VerificationCase(request=request, issue_description="验证身份确认"),
        intent=VerificationIntent(
            vulnerability_type="输入处理边界问题",
            strategy_kind="identity_marker",
            target_fields=("query.id",),
            probes=(IntentProbe(field="query.id", value="probe", action="set"),),
            oracle_kind="identity_marker",
            oracle_marker="stable-marker",
            oracle_description="响应需要包含受控身份 marker。",
            rationale="验证响应 marker。",
            confidence=0.8,
        ),
    )
    observations = iter(
        [
            HttpObservation(200, {}, "stable-marker in baseline"),
            HttpObservation(200, {}, "stable-marker in probe"),
        ]
    )
    monkeypatch.setattr(executor, "send_request", lambda _request: next(observations))
    result = execute_plan(plan, request, run_name="verify-marker-baseline", approved=True)
    assert result.status == "inconclusive"


def test_send_request_preserves_case_insensitive_host_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class FakeConnection:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def request(
            self,
            _method: str,
            _path: str,
            *,
            body: bytes,
            headers: dict[str, str],
        ) -> None:
            captured["body"] = body
            captured["headers"] = headers

        def getresponse(self) -> Any:
            class Response:
                status = 200

                def read(self, _limit: int) -> bytes:
                    return b"ok"

                def getheaders(self) -> list[tuple[str, str]]:
                    return []

            return Response()

        def close(self) -> None:
            pass

    request = parse_request_text("GET https://app.test/items HTTP/1.1\nhOsT: app.test\n\n")
    monkeypatch.setattr(executor.http.client, "HTTPSConnection", FakeConnection)
    executor.send_request(request)
    headers = captured["headers"]
    assert [name for name in headers if name.lower() == "host"] == ["hOsT"]


def test_secondary_identity_requires_matching_control_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = parse_request_text(
        "GET https://app.test/orders?orderId=42 HTTP/1.1\n"
        "Host: app.test\n"
        "Cookie: session=primary\n\n"
    )
    secondary = parse_request_text(
        "GET https://app.test/orders?orderId=99 HTTP/1.1\n"
        "Host: app.test\n"
        "Cookie: session=secondary\n\n"
    )
    intent = VerificationIntent(
        vulnerability_type="对象访问边界问题",
        strategy_kind="secondary_identity",
        target_fields=("query.orderId",),
        probes=(
            IntentProbe(
                field="query.orderId",
                value=None,
                action="secondary_value",
            ),
        ),
        oracle_kind="authorization_boundary",
        oracle_description="主身份不应取得第二身份对象。",
        rationale="用第二身份响应作为对象对照。",
        confidence=0.9,
    )
    plan = build_verification_plan(
        VerificationCase(
            request=request,
            issue_description="验证对象访问边界",
            supporting_requests=[secondary],
        ),
        intent=intent,
    )
    assert plan.blocked_reason is None
    assert plan.max_requests == 3
    observations = iter(
        [
            HttpObservation(200, {}, '{"id":42}'),
            HttpObservation(200, {}, '{"id":99}'),
            HttpObservation(200, {}, '{"id":99}'),
        ]
    )
    monkeypatch.setattr(executor, "send_request", lambda _request: next(observations))
    result = execute_plan(
        plan,
        request,
        run_name="verify-secondary",
        approved=True,
        secondary=secondary,
    )
    assert result.status == "verified_vulnerable"
    assert [item.probe_id for item in result.evidence] == [
        "control",
        "secondary-control",
        "intent-1",
    ]


def test_description_driven_intent_uses_request_field_allow_list() -> None:
    request = parse_request_text(
        "POST https://app.test/items HTTP/1.1\n"
        "Host: app.test\n"
        "Content-Type: application/json\n"
        "Cookie: session=secret-cookie\n\n"
        '{"ids":["1"],"note":"hello"}'
    )
    raw_intent = json.dumps(
        {
            "vulnerability_type": "sqli",
            "strategy_kind": "paired_field_mutation",
            "target_fields": ["body.ids[0]"],
            "probes": [
                {
                    "field": "body.ids[0]",
                    "value": "1' OR '1'='1",
                    "action": "set",
                    "role": "true",
                    "pair_id": "boolean-check",
                },
                {
                    "field": "body.ids[0]",
                    "value": "1' AND '1'='2",
                    "action": "set",
                    "role": "false",
                    "pair_id": "boolean-check",
                },
            ],
            "oracle_kind": "response_difference",
            "oracle_description": "真值和假值的响应结构应产生稳定差异。",
            "rationale": "描述指向 ids 数组中的对象筛选值。",
            "confidence": 0.91,
        },
        ensure_ascii=False,
    )
    intent = parse_intent_response(
        raw_intent,
        candidate_fields=["body.ids[0]", "body.note", "cookie.session"],
    )
    plan = build_verification_plan(
        VerificationCase(request=request, issue_description="ids 存在 SQL 注入"),
        intent=intent,
    )
    assert plan.planner_source == "llm"
    assert plan.target_fields == ["body.ids[0]"]
    assert plan.probes[0].pair_id == "boolean-check"
    assert plan.probes[0].role == "true"
    assert plan.max_requests == 3
    assert "secret-cookie" not in json.dumps(
        {"request": request.to_dict(redact=True), "intent": intent.rationale}
    )


def test_description_driven_intent_rejects_unknown_fields_and_exfiltration() -> None:
    base = {
        "vulnerability_type": "sqli",
        "strategy_kind": "paired_field_mutation",
        "target_fields": ["body.ids[0]"],
        "oracle_kind": "response_difference",
        "oracle_description": "响应差异",
        "rationale": "需要对照测试",
        "confidence": 0.8,
    }
    unknown_field = dict(
        base,
        probes=[
            {
                "field": "body.missing",
                "value": "1",
                "action": "set",
            }
        ],
    )
    with pytest.raises(IntentGenerationError, match="白名单"):
        parse_intent_response(
            json.dumps(unknown_field),
            candidate_fields=["body.ids[0]"],
        )

    exfiltration = dict(
        base,
        probes=[
            {
                "field": "body.ids[0]",
                "value": "1 UNION SELECT password FROM users",
                "action": "set",
            }
        ],
    )
    with pytest.raises(IntentGenerationError, match="禁止"):
        parse_intent_response(
            json.dumps(exfiltration),
            candidate_fields=["body.ids[0]"],
        )


def test_exception_role_is_supported_and_expensive_probe_is_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = parse_request_text("GET https://app.test/items?id=1 HTTP/1.1\nHost: app.test\n\n")
    intent = parse_intent_response(
        json.dumps(
            {
                "vulnerability_type": "sqli",
                "strategy_kind": "paired_field_mutation",
                "target_fields": ["query.id"],
                "probes": [
                    {
                        "field": "query.id",
                        "value": "1'",
                        "action": "set",
                        "role": "error",
                    }
                ],
                "oracle_kind": "response_difference",
                "oracle_description": "检查数据库错误响应",
                "rationale": "模型选择错误型 SQL 注入验证。",
                "confidence": 0.8,
            }
        ),
        candidate_fields=["query.id"],
    )
    plan = build_verification_plan(
        VerificationCase(request=request, issue_description="id 存在 SQL 注入"),
        intent=intent,
    )
    assert plan.probes[0].role == "error"
    assert plan.blocked_reason is None
    observations = iter(
        [
            HttpObservation(200, {}, "normal"),
            HttpObservation(500, {}, "database syntax error"),
        ]
    )
    monkeypatch.setattr(executor, "send_request", lambda _request: next(observations))
    result = execute_plan(plan, request, run_name="verify-error", approved=True)
    assert result.status == "inconclusive"

    delay_intent = parse_intent_response(
        json.dumps(
            {
                "vulnerability_type": "sqli",
                "strategy_kind": "paired_field_mutation",
                "target_fields": ["query.id"],
                "probes": [
                    {
                        "field": "query.id",
                        "value": "1",
                        "action": "set",
                        "role": "delay",
                    }
                ],
                "oracle_kind": "response_difference",
                "oracle_description": "检查响应时间差异",
                "rationale": "描述提到了延时。",
                "confidence": 0.5,
            }
        ),
        candidate_fields=["query.id"],
    )
    delay_plan = build_verification_plan(
        VerificationCase(request=request, issue_description="id 存在 SQL 注入"),
        intent=delay_intent,
    )
    assert delay_plan.blocked_reason is not None
    assert "耗时型" in delay_plan.blocked_reason


def test_verify_cli_is_a_small_mutually_exclusive_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request_file = tmp_path / "request.txt"
    request_file.write_text(
        "GET https://app.test/search?q=hello HTTP/1.1\nHost: app.test\n\n",
        encoding="utf-8",
    )
    secondary_file = tmp_path / "secondary.txt"
    secondary_file.write_text(
        "GET https://app.test/search?q=other HTTP/1.1\nHost: app.test\n\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "strix",
            "--verify",
            "--request",
            str(request_file),
            "--issue",
            "疑似 SQL 注入",
            "--secondary-request",
            str(secondary_file),
            "-n",
            "--yes",
        ],
    )
    args = cli_args.parse_arguments()
    assert args.mode == "verify"
    assert args.verification_request == str(request_file)
    assert args.verification_secondary_request == str(secondary_file)
    assert args.verification_approve is True

    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--verify", "--target", "https://app.test", "-n"],
    )
    with pytest.raises(SystemExit):
        cli_args.parse_arguments()


def test_cli_persists_model_planning_failure_as_blocked_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request_file = tmp_path / "request.txt"
    request_file.write_text(
        "GET https://app.test/search?q=hello HTTP/1.1\nHost: app.test\n\n",
        encoding="utf-8",
    )

    async def fail_intent(_case: VerificationCase) -> VerificationIntent:
        raise IntentGenerationError("模型返回了不支持的验证能力")

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(verification_cli, "infer_verification_intent", fail_intent)
    result = asyncio.run(
        verification_cli.run_verification_cli(
            SimpleNamespace(
                verification_request=str(request_file),
                verification_secondary_request=None,
                verification_canary_url=None,
                verification_issue="验证输入字段边界",
                verification_baseline=None,
                verification_approve=True,
                non_interactive=True,
            )
        )
    )
    assert result == 1
    reports = list((tmp_path / "strix_runs").glob("verify-*/penetration_test_report.md"))
    assert len(reports) == 1
    report = reports[0].read_text(encoding="utf-8")
    assert "模型返回了不支持的验证能力" in report
    assert "没有已执行的请求" in report


def test_plan_confirmation_precedes_network_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    request = parse_request_text("GET https://app.test/search?q=hello HTTP/1.1\nHost: app.test\n\n")
    plan = build_verification_plan(
        VerificationCase(request=request, issue_description="验证输入字段的响应边界"),
        intent=VerificationIntent(
            vulnerability_type="输入处理边界问题",
            strategy_kind="field_mutation",
            target_fields=("query.q",),
            probes=(IntentProbe(field="query.q", value="probe", action="set"),),
            oracle_kind="response_difference",
            oracle_description="探针响应应与控制响应进行比较。",
            rationale="验证计划需要用户确认后执行。",
            confidence=0.5,
        ),
    )

    def fail_if_called(_request: object) -> object:
        raise AssertionError("未确认计划时不应发送请求")

    monkeypatch.setattr(executor, "send_request", fail_if_called)
    result = execute_plan(plan, request, run_name="verify-test", approved=False)
    assert result.status == "waiting_confirmation"
    assert result.evidence == []


def test_non_idempotent_request_requires_separate_side_effect_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = parse_request_text(
        "POST https://app.test/search HTTP/1.1\n"
        "Host: app.test\n"
        "Content-Type: application/json\n\n"
        '{"cmd":"hello"}'
    )
    plan = build_verification_plan(
        VerificationCase(request=request, issue_description="验证 cmd 字段的输入处理边界"),
        intent=VerificationIntent(
            vulnerability_type="输入处理边界问题",
            strategy_kind="field_mutation",
            target_fields=("body.cmd",),
            probes=(IntentProbe(field="body.cmd", value="probe", action="set"),),
            oracle_kind="response_difference",
            oracle_description="探针响应应与控制响应进行比较。",
            rationale="POST 请求需要额外副作用确认。",
            confidence=0.5,
        ),
    )
    monkeypatch.setattr(executor, "send_request", lambda _request: pytest.fail("不应执行"))
    result = execute_plan(plan, request, run_name="verify-side-effect", approved=True)
    assert result.status == "blocked"
    assert "副作用" in result.summary


def test_command_injection_verification_uses_local_http_fixture() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            command = parse_qs(urlsplit(self.path).query).get("cmd", [""])[0]
            body = b"uid=1000(test)" if command == ";id" else b"normal response"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except PermissionError as exc:
        pytest.skip(f"当前测试沙箱禁止绑定本地端口：{exc}")
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_port
        request = parse_request_text(
            f"GET http://127.0.0.1:{port}/verify?cmd=hello HTTP/1.1\nHost: 127.0.0.1:{port}\n\n"
        )
        plan = build_verification_plan(
            VerificationCase(request=request, issue_description="验证 cmd 字段的身份确认边界"),
            intent=VerificationIntent(
                vulnerability_type="输入处理边界问题",
                strategy_kind="identity_marker",
                target_fields=("query.cmd",),
                probes=(IntentProbe(field="query.cmd", value=";id", action="set"),),
                oracle_kind="identity_marker",
                oracle_marker="uid=1000(test)",
                oracle_description="响应应包含模型指定的身份确认 marker。",
                rationale="使用低风险 marker 检查响应证据。",
                confidence=0.8,
            ),
        )
        result = execute_plan(
            plan,
            request,
            run_name="verify-local",
            approved=True,
            side_effect_approved=True,
        )
        assert result.status == "verified_vulnerable"
        assert result.evidence
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_sqli_verification_preserves_json_array_and_records_baseline() -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length))
            value = payload["ids"][0]
            if " OR '1'='1" in value:
                body = b'{"items":[{"id":1}]}'
            elif " AND '1'='2" in value:
                body = b'{"items":[]}'
            else:
                body = b'{"items":[{"id":1}]}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: object) -> None:
            return

    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    except PermissionError as exc:
        pytest.skip(f"当前测试沙箱禁止绑定本地端口：{exc}")
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_port
        request = parse_request_text(
            f"POST http://127.0.0.1:{port}/items HTTP/1.1\n"
            f"Host: 127.0.0.1:{port}\n"
            "Content-Type: application/json\n\n"
            '{"RegId":"1","PatId":"1","ids":["1"]}'
        )
        intent = VerificationIntent(
            vulnerability_type="sqli",
            strategy_kind="paired_field_mutation",
            target_fields=("body.ids[0]",),
            probes=(
                IntentProbe(
                    field="body.ids[0]",
                    value="1' OR '1'='1",
                    action="set",
                    role="true",
                    pair_id="model-boolean",
                ),
                IntentProbe(
                    field="body.ids[0]",
                    value="1' AND '1'='2",
                    action="set",
                    role="false",
                    pair_id="model-boolean",
                ),
            ),
            oracle_kind="response_difference",
            oracle_description="真值和假值的响应结构应产生稳定差异。",
            rationale="描述指向 ids 数组中的筛选值。",
            confidence=0.9,
        )
        plan = build_verification_plan(
            VerificationCase(request=request, issue_description="ids 存在 SQL 注入"),
            intent=intent,
        )
        assert plan.target_fields[0] == "body.ids[0]"
        assert plan.planner_source == "llm"
        assert plan.max_requests == 3
        result = execute_plan(
            plan,
            request,
            run_name="verify-sqli-array",
            approved=True,
            side_effect_approved=True,
        )
        assert result.status == "verified_vulnerable"
        assert [item.probe_id for item in result.evidence][:3] == [
            "control",
            "intent-1",
            "intent-2",
        ]
        probe_request = result.evidence[1].request or ""
        assert "\"ids\":[\"1' OR '1'='1\"]" in probe_request
        rendered_body = probe_request.split("\r\n\r\n", 1)[1].encode("utf-8")
        rendered_length = next(
            int(line.split(":", 1)[1].strip())
            for line in probe_request.split("\r\n")
            if line.lower().startswith("content-length:")
        )
        assert rendered_length == len(rendered_body)
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_runner_persists_replayable_artifacts_and_retest_comparison(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    request_file = tmp_path / "request.txt"
    request_file.write_text(
        "GET https://app.test/search?q=hello HTTP/1.1\n"
        "Host: app.test\n"
        "Authorization: Bearer top-secret\n\n",
        encoding="utf-8",
    )
    run_dir, _plan, result = run_verification_case(
        request_file=str(request_file),
        issue="无法确认问题，token=top-secret",
    )
    assert result.status == "blocked"
    assert (run_dir / "verification-plan.json").is_file()
    assert (run_dir / "verification-result.json").is_file()
    assert (run_dir / "verification-evidence.jsonl").is_file()
    artifacts = "\n".join(
        path.read_text(encoding="utf-8") for path in run_dir.iterdir() if path.is_file()
    )
    assert "top-secret" in artifacts
    assert "Authorization: Bearer top-secret" in artifacts
    assert "原始 Burp 请求" in artifacts

    baseline = VerificationResult(
        status="verified_vulnerable",
        vulnerability_type="sqli",
        plan_sha256="plan",
        run_name="baseline",
        summary="confirmed",
    )
    fixed = VerificationResult(
        status="not_reproduced",
        vulnerability_type="sqli",
        plan_sha256="plan",
        run_name="after-fix",
        summary="not reproduced",
    )
    assert compare_results(baseline, fixed) == ("fixed", "修复后使用相同验证计划未再次复现。")


def test_runner_reuses_plan_for_fixed_retest_without_requiring_same_values(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    before = tmp_path / "before.txt"
    before.write_text(
        "GET https://app.test/search?cmd=hello HTTP/1.1\nHost: app.test\n\n",
        encoding="utf-8",
    )
    observations = iter(
        [
            HttpObservation(200, {"Content-Type": "text/plain"}, "normal"),
            HttpObservation(200, {"Content-Type": "text/plain"}, "uid=1000(test)"),
        ]
    )
    monkeypatch.setattr(executor, "send_request", lambda _request: next(observations))
    baseline_dir, _plan, baseline_result = run_verification_case(
        request_file=str(before),
        issue="验证 cmd 字段的身份确认边界",
        run_name="baseline",
        approved=True,
        intent=VerificationIntent(
            vulnerability_type="输入处理边界问题",
            strategy_kind="identity_marker",
            target_fields=("query.cmd",),
            probes=(IntentProbe(field="query.cmd", value=";id", action="set"),),
            oracle_kind="identity_marker",
            oracle_marker="uid=1000(test)",
            oracle_description="响应应包含模型指定的身份确认 marker。",
            rationale="复用同一验证计划进行修复后复测。",
            confidence=0.8,
        ),
    )
    assert baseline_result.status == "verified_vulnerable"
    assert baseline_dir.name == "baseline"

    after = tmp_path / "after.txt"
    after.write_text(
        "GET https://app.test/search?cmd=safe HTTP/1.1\nHost: app.test\n\n",
        encoding="utf-8",
    )
    observations = iter(
        [
            HttpObservation(200, {"Content-Type": "text/plain"}, "normal"),
            HttpObservation(403, {"Content-Type": "text/plain"}, "blocked"),
        ]
    )
    _run_dir, _plan, retest_result = run_verification_case(
        request_file=str(after),
        issue=None,
        run_name="after-fix",
        baseline_run="baseline",
        approved=True,
    )
    assert retest_result.status == "fixed"
