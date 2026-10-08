#!/usr/bin/env python3
"""
Strix Agent Interface
"""

import argparse
import asyncio
import contextlib
import logging
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import codex, load_settings, persist_current
from strix.core.paths import RUNS_DIR_NAME, run_dir_for
from strix.interface.cli_args import (
    FAIL_ON_SEVERITIES,
    ResumeError,
    load_resume_state,
    parse_arguments,
    resume_run_list_message,
    terminal_attached,
)
from strix.interface.environment import (
    check_docker_installed,
    pull_docker_image,
    validate_environment,
)
from strix.interface.interactive import (
    InteractiveInterfaceExitedError,
    InteractiveSetupUnavailableError,
    run_tui,
)
from strix.interface.scan_setup import (
    ModelConnectionError,
    preflight_model_connection,
    preflight_request,
    prepare_run,
    telemetry_start,
)
from strix.interface.update_check import (
    is_binary_install,
    notify_update,
    prompt_update_if_available,
    restart_after_update,
    start_background_check,
)
from strix.interface.utils import (
    build_final_stats_text,
)
from strix.llm.warmup import start_import_warmup, wait_for_import_warmup
from strix.telemetry import posthog, report_error, scarf, set_scan_phase
from strix.telemetry.logging import setup_console_logging


BEDROCK_MODEL_PREFIX = "bedrock/"
BEDROCK_MISSING_MODULE_ERROR = "No module named 'boto3'"
BEDROCK_EXTRA_HINT = (
    'Bedrock support is optional. Install it with: pipx install "strix-agent[bedrock]"'
)
VERTEX_MODEL_MARKER = "vertex"
VERTEX_MISSING_MODULE_ERROR = "No module named 'google"
VERTEX_EXTRA_HINT = (
    'Vertex AI 支持是可选依赖。可通过以下命令安装：pipx install "strix-agent[vertex]"'
)
SOCKS_PROXY_MISSING_MODULE_ERROR = "Using SOCKS proxy, but the 'socksio' package is not installed"
SOCKS_PROXY_HINT = (
    "检测到当前环境正在使用 SOCKS 代理，但缺少 `socksio` 依赖。\n"
    "如果你当前是在源码仓库里运行，请执行：`python -m pip install -e .`\n"
    "如果你只想先快速补齐当前虚拟环境，也可以执行：`python -m pip install socksio`\n"
    "如果你并不需要 SOCKS 代理，可临时 `unset all_proxy ALL_PROXY` 后重试。"
)


logger = logging.getLogger(__name__)

_RESUME_TOKEN_INCREMENT = 200_000_000

_ROOT_SUBCOMMAND_HELP = """
Additional commands:
  strix cloud ...          Use the managed Strix platform
  strix auth ...           Manage model-subscription sign-in
  strix view [RUN]         View a completed or running scan
  strix completions SHELL  Generate zsh, bash, or fish tab completion
"""


def _exception_messages(exc: BaseException) -> tuple[str, ...]:
    messages: list[str] = []
    seen: set[int] = set()
    stack: list[BaseException] = [exc]
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        messages.append(str(current))
        if current.__cause__ is not None:
            stack.append(current.__cause__)
        if current.__context__ is not None:
            stack.append(current.__context__)
    return tuple(messages)


def _provider_import_hint(exc: BaseException, model: str) -> str | None:
    """Return an install hint when *exc* is a missing provider dependency.

    Bedrock and Vertex AI ship as optional extras: Bedrock needs ``boto3`` and
    Vertex AI needs ``google-auth``. When either is absent, litellm may raise an
    ``ImportError``/``ModuleNotFoundError`` directly or wrap it in a connection
    error. Map the missing module back to the matching extra so the user knows
    what to install. Returns ``None`` for any unrelated error.
    """
    model_name = model.lower()
    messages = _exception_messages(exc)
    if any(
        BEDROCK_MISSING_MODULE_ERROR in message for message in messages
    ) and model_name.startswith(BEDROCK_MODEL_PREFIX):
        return BEDROCK_EXTRA_HINT
    if (
        any(VERTEX_MISSING_MODULE_ERROR in message for message in messages)
        and VERTEX_MODEL_MARKER in model_name
    ):
        return VERTEX_EXTRA_HINT
    if any(SOCKS_PROXY_MISSING_MODULE_ERROR in message for message in messages):
        return SOCKS_PROXY_HINT
    return None


def _suggested_resume_token_limit(report_state: Any) -> str:
    """Return a resume cap that adds 200M tokens to the persisted budget/usage."""
    from strix.core.token_budget import normalize_token_limit

    run_record = getattr(report_state, "run_record", None)
    if not isinstance(run_record, dict):
        run_record = {}

    try:
        persisted_limit = normalize_token_limit(run_record.get("token_limit")) or 0
    except ValueError:
        logger.debug(
            "Could not parse persisted token limit for resume hint",
            exc_info=True,
        )
        persisted_limit = 0

    get_total_tokens = getattr(report_state, "get_total_llm_tokens", None)
    try:
        tokens_used = (
            get_total_tokens()
            if callable(get_total_tokens)
            else run_record.get("tokens_used", 0)
        )
    except Exception:
        logger.debug("Could not read token usage for resume hint", exc_info=True)
        tokens_used = run_record.get("tokens_used", 0)
    if isinstance(tokens_used, bool) or not isinstance(tokens_used, int):
        tokens_used = 0

    # --token-limit is a total cap, so exceed both the prior cap and recorded usage.
    suggested_limit = max(persisted_limit, tokens_used) + _RESUME_TOKEN_INCREMENT
    for suffix, divisor in (
        ("T", 1_000_000_000_000),
        ("G", 1_000_000_000),
        ("M", 1_000_000),
        ("K", 1_000),
    ):
        if suggested_limit % divisor == 0:
            return f"{suggested_limit // divisor}{suffix}"
    return str(suggested_limit)
def _subscription_error_hint(exc: BaseException) -> str | None:
    """Return an actionable hint for a known ChatGPT-subscription error, or None."""
    if not codex.subscription_model(load_settings().llm.model):
        return None
    joined = " ".join(_exception_messages(exc)).lower()
    if "not supported when using codex with a chatgpt account" in joined:
        return (
            "当前订阅不支持这个模型。"
            "请把 STRIX_LLM 调整为你的套餐可用模型，例如 `chatgpt/gpt-5.4`。"
        )
    if (
        "error code: 401" in joined
        or "http 401" in joined
        or "unauthorized" in joined
        or "invalid_grant" in joined
    ):
        return "当前 ChatGPT 登录态已过期或被撤销，请重新登录：\n  strix auth login chatgpt"
    return None


async def warm_up_llm() -> None:
    from strix.config.models import (
        configure_sdk_model_defaults,
        is_known_openai_bare_model,
    )

    console = Console()
    logger.info("Warming up LLM connection")

    raw_model = ""
    try:
        settings = load_settings()
        configure_sdk_model_defaults(settings)
        llm = settings.llm
        raw_model = (llm.model or "").strip()
        if (
            raw_model
            and "/" not in raw_model
            and not is_known_openai_bare_model(raw_model)
            and not llm.api_base
        ):
            warn_text = Text()
            warn_text.append("未知模型名", style="bold yellow")
            warn_text.append("\n\n", style="white")
            warn_text.append(f"'{raw_model}'", style="bold cyan")
            warn_text.append(
                " 不是已知的 OpenAI 模型。未带 provider 前缀的裸模型名会默认路由到 OpenAI。\n"
                "如果你想使用非 OpenAI 提供商，请改用 `",
                style="white",
            )
            warn_text.append("<provider>/<model>", style="bold cyan")
            warn_text.append(
                "` 形式，例如 `anthropic/claude-opus-4-7`、`deepseek/deepseek-v4-pro`。",
                style="white",
            )
            console.print(
                Panel(
                    warn_text,
                    title="[bold white]STRIX",
                    title_align="left",
                    border_style="yellow",
                    padding=(1, 2),
                ),
            )
            sys.exit(1)

        await preflight_model_connection(raw_model, settings=settings)
        logger.info("LLM warm-up succeeded for model %s", (llm.model or "").strip())

        if settings.dedupe.model:
            from strix.report.dedupe import resolve_dedupe_model

            dedupe_model = settings.dedupe.model.strip()
            raw_model = dedupe_model
            deduper = resolve_dedupe_model(settings.dedupe, dedupe_model)
            # A dedicated dedupe model may route to another provider, which must
            # never receive the main endpoint's headers; it has its own
            # DEDUPE_LLM_EXTRA_HEADERS.
            await preflight_request(
                deduper,
                model_name=dedupe_model,
                extra_headers=settings.dedupe.extra_headers,
                timeout=llm.preflight_timeout,
                api_base_setting="DEDUPE_LLM_API_BASE",
            )
            logger.info("LLM warm-up succeeded for dedupe model %s", dedupe_model)

    except ModelConnectionError:
        logger.debug("Model route warm-up failed", exc_info=True)
        raise
    except Exception as exc:
        logger.debug("LLM warm-up failed", exc_info=True)
        raise ModelConnectionError(raw_model, exc) from exc


def display_completion_message(args: argparse.Namespace, results_path: Path) -> None:
    from strix.report.state import get_global_report_state

    console = Console()
    report_state = get_global_report_state()

    scan_completed = False
    if report_state:
        scan_completed = report_state.run_record.get("status") == "completed"

    completion_text = Text()
    if scan_completed:
        completion_text.append("渗透测试已完成", style="bold #22c55e")
    else:
        completion_text.append("本次会话已结束", style="bold #eab308")

    target_text = Text()
    target_text.append("目标", style="dim")
    target_text.append("  ")
    if len(args.targets_info) == 1:
        target_text.append(args.targets_info[0]["original"], style="bold white")
    else:
        target_text.append(f"{len(args.targets_info)} 个目标", style="bold white")
        for target_info in args.targets_info:
            target_text.append("\n        ")
            target_text.append(target_info["original"], style="white")

    stats_text = build_final_stats_text(report_state)

    panel_parts: list[Text | str] = [completion_text, "\n\n", target_text]

    if stats_text.plain:
        panel_parts.extend(["\n", stats_text])

    results_text = Text()
    results_text.append("\n")
    results_text.append("输出目录", style="dim")
    results_text.append("  ")
    results_text.append(str(results_path), style="#60a5fa")
    panel_parts.extend(["\n", results_text])

    view_text = Text()
    view_text.append("\n")
    view_text.append("查看", style="dim")
    view_text.append("    ")
    view_text.append(f"strix view {args.run_name}", style="#22c55e")
    panel_parts.extend(["\n", view_text])

    if not scan_completed:
        resume_text = Text()
        resume_text.append("\n")
        resume_text.append("继续运行", style="dim")
        resume_text.append("  ")
        resume_text.append(f"strix --resume {args.run_name}", style="#22c55e")
        panel_parts.extend(["\n", resume_text])

        token_resume_text = Text()
        token_resume_text.append("\n")
        token_resume_text.append("追加 Token", style="dim")
        token_resume_text.append("  ")
        token_resume_text.append(
            "strix --resume "
            f"{args.run_name} --token-limit {_suggested_resume_token_limit(report_state)}",
            style="#22c55e",
        )
        panel_parts.extend(["\n", token_resume_text])

    panel_content = Text.assemble(*panel_parts)

    border_style = "#22c55e" if scan_completed else "#eab308"

    panel = Panel(
        panel_content,
        title="[bold white]STRIX",
        title_align="left",
        border_style=border_style,
        padding=(1, 2),
    )

    console.print("\n")
    console.print(panel)
    console.print()
    console.print(
        "[#60a5fa]strix.ai[/]  [dim]·[/]  "
        "[#60a5fa]docs.strix.ai[/]  [dim]·[/]  "
        "[#60a5fa]discord.gg/strix-ai[/]"
    )
    console.print()
    if not args.non_interactive:
        notify_update(console)


def findings_fail_build(reports: list[dict[str, Any]], fail_on: str | None) -> bool:
    """Whether headless findings should exit 2 under the ``--fail-on`` threshold.

    With no threshold any finding fails. Otherwise a finding fails when its
    severity is at or above the threshold. A severity outside the known scale
    fails too, so a gate never passes on a value it cannot rank. ``none`` is a
    known level below ``info`` and only fails without a threshold.
    """
    if not reports:
        return False
    if fail_on is None:
        return True
    threshold = FAIL_ON_SEVERITIES.index(fail_on)
    for report in reports:
        severity = str(report.get("severity") or "").strip().lower()
        if severity == "none":
            continue
        if severity not in FAIL_ON_SEVERITIES:
            return True
        if FAIL_ON_SEVERITIES.index(severity) <= threshold:
            return True
    return False


def _print_error_panel(title: str, message: str) -> None:
    console = Console()
    error_text = Text()
    error_text.append(title, style="bold red")
    error_text.append("\n\n", style="white")
    error_text.append(message, style="white")
    panel = Panel(
        error_text,
        title="[bold white]STRIX",
        title_align="left",
        border_style="red",
        padding=(1, 2),
    )
    console.print("\n")
    console.print(panel)
    console.print()


def _print_model_connection_error(exc: BaseException, model_name: str | None = None) -> None:
    console = Console()
    error_text = Text()
    sub_hint = _subscription_error_hint(exc)
    if sub_hint is not None:
        border_style = "yellow"
        error_text.append("当前订阅不可用", style="bold yellow")
        error_text.append("\n\n", style="white")
        error_text.append(f"{sub_hint}\n", style="white")
        error_text.append(f"\n错误详情：{exc}", style="dim white")
    else:
        border_style = "red"
        error_text.append("LLM 连接失败", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("无法与语言模型建立连接。\n", style="white")
        error_text.append("请检查配置后重试。\n", style="white")
        if model_name:
            hint = _provider_import_hint(exc, model_name)
            if hint is not None:
                error_text.append(f"\n{hint}\n", style="bold yellow")
        error_text.append(f"\n错误：{exc}", style="dim white")

    panel = Panel(
        error_text,
        title="[bold white]STRIX",
        title_align="left",
        border_style=border_style,
        padding=(1, 2),
    )
    console.print("\n")
    console.print(panel)
    console.print()


def _print_cli_error(message: str) -> None:
    Console(stderr=True, soft_wrap=True).print(
        f"strix: error: {message}", markup=False, highlight=False
    )


HEADLESS_HINT = "If Strix runs without a terminal (CI, nohup, pipes), pass -n to run headless."


def _fall_back_to_headless(args: argparse.Namespace) -> None:
    """Run headless when there is no terminal for the TUI to attach to.

    CI jobs, ``nohup``, pipes and cron have no tty; the Go TUI exits as soon
    as it tries to take over the screen. With a target the scan can still run
    as if ``-n`` was given. Without one the start screen is the only way to
    enter a target, so stop with the fix instead. A bare ``--resume`` is left
    to the picker, which already explains itself without a terminal.
    """
    if args.non_interactive or args.resume_picker or terminal_attached():
        return
    if args.needs_setup:
        report_error("no_terminal_for_setup")
        _print_error_panel(
            "NO TERMINAL ATTACHED",
            "The interactive interface needs a terminal and no target was given.\n"
            "Pass -t <target> -n to run headless.",
        )
        sys.exit(1)
    args.non_interactive = True
    Console().print("No terminal attached, running headless (same as -n).", style="dim")


def _pick_run_to_resume(args: argparse.Namespace) -> None:
    """A bare --resume: let the user pick a run, then load it like --resume <name>."""
    from strix.interface.resume_picker import PickerUnavailableError, pick_run
    from strix.report.runs import list_run_summaries

    try:
        chosen = pick_run(list_run_summaries(), runs_dir=RUNS_DIR_NAME)
    except PickerUnavailableError as exc:
        _print_cli_error(resume_run_list_message(f"{exc}."))
        sys.exit(2)
    if chosen is None:
        Console().print("No run selected.", style="dim")
        sys.exit(0)
    args.resume = chosen.run_name
    try:
        load_resume_state(args)
    except ResumeError as exc:
        _print_cli_error(str(exc))
        sys.exit(2)


def _bootstrap_scan(args: argparse.Namespace) -> None:
    """Warm up the model and prepare the run before the interface starts.

    Start-screen launches skip this: they verify the model and prepare the
    run once the user has entered a target.
    """
    set_scan_phase("preflight")
    try:
        asyncio.run(warm_up_llm())
    except ModelConnectionError as exc:
        report_error("model_connection_failed", exc)
        _print_model_connection_error(exc, exc.model_name)
        sys.exit(1)
    persist_current()
    try:
        prepare_run(args)
    except ValueError as e:
        report_error("scan_preparation_failed", e)
        _print_error_panel("准备扫描失败", str(e))
        sys.exit(1)
    telemetry_start(args)


def _force_utf8_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(ValueError, OSError):
            reconfigure(encoding="utf-8")


def main() -> None:
    if sys.platform == "win32":
        _force_utf8_streams()
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    setup_console_logging()

    if len(sys.argv) == 2 and sys.argv[1] in ("-h", "--help"):
        try:
            parse_arguments()
        except SystemExit as exc:
            Console().print(_ROOT_SUBCOMMAND_HELP.strip(), markup=False)
            raise SystemExit(exc.code) from None

    # `strix view [<run>]` is a viewer-only subcommand, dispatched before the
    # scan argument parser (which requires a target) and before any scan setup.
    if len(sys.argv) > 1 and sys.argv[1] == "view":
        from strix.interface.viewer.cli import run_view

        run_view(sys.argv[2:])
        return

    # `strix auth …` manages model-subscription sign-in and exits; it needs no
    # target, Docker, or scan setup.
    if len(sys.argv) > 1 and sys.argv[1] == "auth":
        from strix.interface.auth_cli import run_auth

        sys.exit(run_auth(sys.argv[2:]))

    # Generate native shell completion scripts before scan argument parsing.
    if len(sys.argv) > 1 and sys.argv[1] in ("completion", "completions"):
        from strix.interface.completions import run_completions

        sys.exit(run_completions(sys.argv[2:]))

    # `strix cloud …` drives the managed platform (app.strix.ai) and exits;
    # it needs no target, Docker, or scan setup.
    if len(sys.argv) > 1 and sys.argv[1] == "cloud":
        from strix.interface.cloud import run_cloud

        sys.exit(run_cloud(sys.argv[2:]))

    start_import_warmup()

    args = parse_arguments()
    _fall_back_to_headless(args)

    start_background_check()
    if not args.non_interactive and prompt_update_if_available(Console()):
        if is_binary_install() and sys.platform != "win32":
            restart_after_update()
        sys.exit(0)

    if args.resume_picker:
        _pick_run_to_resume(args)

    check_docker_installed()
    pull_docker_image()
    validate_environment()
    wait_for_import_warmup()

    if args.non_interactive or not args.needs_setup:
        _bootstrap_scan(args)

    from strix.report.state import get_global_report_state

    exit_reason = "user_exit"
    try:
        if args.non_interactive:
            from strix.interface.cli import run_cli

            asyncio.run(run_cli(args))
            exit_reason = "agent_stopped"
        else:
            asyncio.run(run_tui(args))
    except InteractiveSetupUnavailableError as exc:
        exit_reason = "error"
        report_error("interactive_setup_unavailable", exc)
        _print_error_panel("交互界面不可用", str(exc))
        sys.exit(1)
    except InteractiveInterfaceExitedError as exc:
        exit_reason = "error"
        report_error("interactive_interface_exited", exc)
        _print_error_panel("INTERACTIVE INTERFACE STOPPED", f"{exc}.\n{HEADLESS_HINT}")
        sys.exit(1)
    except KeyboardInterrupt:
        exit_reason = "interrupted"
    except Exception as exc:
        exit_reason = "error"
        report_error("unhandled_exception", exc)
        raise
    finally:
        report_state = get_global_report_state()
        if report_state:
            status = {"interrupted": "interrupted", "error": "failed"}.get(
                exit_reason,
                "stopped",
            )
            report_state.cleanup(status=status)
            # Best-effort beacons on the way out. They reach the network, so a
            # second Ctrl-C lands here; abandon them rather than trading a clean
            # exit for a traceback.
            with contextlib.suppress(KeyboardInterrupt, Exception):
                posthog.end(report_state, exit_reason=exit_reason)
                scarf.end(report_state, exit_reason=exit_reason)

    if not args.run_name:
        # Setup mode where the user quit before starting a scan: nothing ran.
        notify_update(Console())
        return

    results_path = run_dir_for(args.run_name)

    display_completion_message(args, results_path)

    if args.non_interactive:
        report_state = get_global_report_state()
        if report_state and findings_fail_build(report_state.vulnerability_reports, args.fail_on):
            sys.exit(2)


if __name__ == "__main__":
    main()
