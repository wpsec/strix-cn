"""Tests for the bounded single-case vulnerability verification workflow."""

# ruff: noqa: RUF001

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlsplit

import pytest


if TYPE_CHECKING:
    from pathlib import Path

from strix.interface import cli_args
from strix.verification import (
    VerificationCase,
    VerificationResult,
    build_verification_plan,
    compare_results,
    executor,
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
    assert '"ids":["1\' OR \'1\'=\'1"]' in mutated.body

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


def test_planner_infers_supported_types_and_blocks_unsafe_boundaries() -> None:
    request = parse_request_text(
        "GET https://app.test/orders?orderId=42 HTTP/1.1\n"
        "Host: app.test\n"
        "Cookie: session=test-session\n\n"
    )
    idor_plan = build_verification_plan(
        VerificationCase(request=request, issue_description="疑似 IDOR，读取其他用户订单")
    )
    assert idor_plan.vulnerability_type == "idor_bola"
    assert idor_plan.probes[0].requires_secondary_identity is True
    assert idor_plan.blocked_reason is not None

    ssrf_plan = build_verification_plan(
        VerificationCase(
            request=parse_request_text(
                "GET https://app.test/fetch?url=https://example.test HTTP/1.1\nHost: app.test\n\n"
            ),
            issue_description="疑似 SSRF，使用 http://127.0.0.1:80 作为 Canary",
        )
    )

    assert ssrf_plan.blocked_reason is not None
    assert "内网" in ssrf_plan.blocked_reason

    upload_plan = build_verification_plan(
        VerificationCase(
            request=parse_request_text(
                "POST https://app.test/upload HTTP/1.1\n"
                "Host: app.test\n"
                "Content-Type: multipart/form-data; boundary=demo\n\n"
                '--demo\nContent-Disposition: form-data; name="file"; filename="a.txt"\n\n'
                "body\n--demo--\n"
            ),
            issue_description="疑似文件上传漏洞",
        )
    )
    assert upload_plan.probes[0].cleanup_required is True
    assert upload_plan.blocked_reason is not None


def test_verify_cli_is_a_small_mutually_exclusive_entrypoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request_file = tmp_path / "request.txt"
    request_file.write_text(
        "GET https://app.test/search?q=hello HTTP/1.1\nHost: app.test\n\n",
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
            "-n",
            "--yes",
        ],
    )
    args = cli_args.parse_arguments()
    assert args.mode == "verify"
    assert args.verification_request == str(request_file)
    assert args.verification_approve is True

    monkeypatch.setattr(
        sys,
        "argv",
        ["strix", "--verify", "--target", "https://app.test", "-n"],
    )
    with pytest.raises(SystemExit):
        cli_args.parse_arguments()


def test_plan_confirmation_precedes_network_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    request = parse_request_text("GET https://app.test/search?q=hello HTTP/1.1\nHost: app.test\n\n")
    plan = build_verification_plan(
        VerificationCase(request=request, issue_description="疑似命令注入")
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
        VerificationCase(request=request, issue_description="疑似命令注入 cmd")
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
            VerificationCase(request=request, issue_description="疑似命令注入 cmd")
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
        plan = build_verification_plan(
            VerificationCase(request=request, issue_description="ids 存在 SQL 注入")
        )
        assert plan.target_fields[0] == "body.ids[0]"
        assert plan.max_requests == 7
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
            "sqli-boolean-true",
            "sqli-boolean-false",
        ]
        assert '"ids":["1\' OR \'1\'=\'1"]' in result.evidence[1].request
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
        issue="疑似命令注入 cmd",
        run_name="baseline",
        approved=True,
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
