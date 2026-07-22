#!/usr/bin/env python3
"""
Strix Agent Interface
"""

import argparse
import asyncio
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

from agents.model_settings import ModelSettings
from agents.models.interface import ModelTracing
from docker.errors import DockerException
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import (
    apply_config_override,
    load_settings,
    persist_current,
)
from strix.config.models import (
    RECOMMENDED_MODEL_NAMES,
    StrixProvider,
    configure_sdk_model_defaults,
    is_known_openai_bare_model,
    is_recommended_or_frontier_model,
)
from strix.core.paths import run_dir_for, runtime_state_dir
from strix.interface.cli import run_cli
from strix.interface.tui import run_tui
from strix.interface.utils import (
    assign_workspace_subdirs,
    build_final_stats_text,
    build_mount_targets_info,
    build_target_summary_text,
    check_docker_connection,
    clone_repository,
    collect_local_sources,
    dedupe_local_targets,
    find_oversized_local_targets,
    generate_run_name,
    image_exists,
    infer_target_type,
    is_whitebox_scan,
    process_pull_line,
    read_target_list_file,
    resolve_diff_scope_context,
    rewrite_localhost_targets,
    validate_config_file,
)
from strix.report.state import get_global_report_state
from strix.report.writer import read_run_record, write_run_record
from strix.telemetry import posthog, scarf
from strix.telemetry.logging import configure_dependency_logging


HOST_GATEWAY_HOSTNAME = "host.docker.internal"
BEDROCK_MODEL_PREFIX = "bedrock/"
BEDROCK_MISSING_MODULE_ERROR = "No module named 'boto3'"
BEDROCK_EXTRA_HINT = (
    'Bedrock 支持是可选依赖。可通过以下命令安装：pipx install "strix-agent[bedrock]"'
)
VERTEX_MODEL_MARKER = "vertex"
VERTEX_MISSING_MODULE_ERROR = "No module named 'google"
VERTEX_EXTRA_HINT = (
    'Vertex AI 支持是可选依赖。可通过以下命令安装：pipx install "strix-agent[vertex]"'
)


import logging  # noqa: E402


logger = logging.getLogger(__name__)


def validate_environment() -> None:
    logger.info("Validating environment")
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    settings = load_settings()

    if not settings.llm.model:
        missing_required_vars.append("STRIX_LLM")

    if not settings.llm.api_key:
        missing_optional_vars.append("LLM_API_KEY")

    if not settings.llm.api_base:
        missing_optional_vars.append("LLM_API_BASE")

    if not settings.integrations.perplexity_api_key:
        missing_optional_vars.append("PERPLEXITY_API_KEY")

    if missing_required_vars:
        error_text = Text()
        error_text.append("缺少必需环境变量", style="bold red")
        error_text.append("\n\n", style="white")

        for var in missing_required_vars:
            error_text.append(f"• {var}", style="bold yellow")
            error_text.append(" 未设置\n", style="white")

        if missing_optional_vars:
            error_text.append("\n可选环境变量：\n", style="dim white")
            for var in missing_optional_vars:
                error_text.append(f"• {var}", style="dim yellow")
                error_text.append(" 未设置\n", style="dim white")

        error_text.append("\n必需环境变量：\n", style="white")
        for var in missing_required_vars:
            if var == "STRIX_LLM":
                error_text.append("• ", style="white")
                error_text.append("STRIX_LLM", style="bold cyan")
                error_text.append(
                    " - 要使用的模型名，例如 `openai/gpt-5.4` 或 "
                    "`anthropic/claude-opus-4-7`\n",
                    style="white",
                )

        if missing_optional_vars:
            error_text.append("\n可选环境变量：\n", style="white")
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_KEY", style="bold cyan")
                    error_text.append(
                        " - LLM 提供商的 API Key"
                        "（本地模型、Vertex AI、AWS 等场景通常不需要）\n",
                        style="white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append("• ", style="white")
                    error_text.append("LLM_API_BASE", style="bold cyan")
                    error_text.append(
                        " - 自定义 API base URL，适用于本地模型或兼容网关"
                        "（如 Ollama、LM Studio）\n",
                        style="white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append("• ", style="white")
                    error_text.append("PERPLEXITY_API_KEY", style="bold cyan")
                    error_text.append(
                        " - Perplexity AI Web 搜索的 API Key（启用实时研究）\n",
                        style="white",
                    )
                elif var == "STRIX_REASONING_EFFORT":
                    error_text.append("• ", style="white")
                    error_text.append("STRIX_REASONING_EFFORT", style="bold cyan")
                    error_text.append(
                        " - 推理强度等级：none、minimal、low、medium、high、xhigh"
                        "（默认：high）\n",
                        style="white",
                    )

        error_text.append("\n示例配置：\n", style="white")
        error_text.append("export STRIX_LLM='openai/gpt-5.4'\n", style="dim white")

        if missing_optional_vars:
            for var in missing_optional_vars:
                if var == "LLM_API_KEY":
                    error_text.append(
                        "export LLM_API_KEY='your-api-key-here'  "
                        "# 本地模型、Vertex AI、AWS 等场景通常不需要\n",
                        style="dim white",
                    )
                elif var == "LLM_API_BASE":
                    error_text.append(
                        "export LLM_API_BASE='http://localhost:11434'  "
                        "# 仅本地模型或兼容网关需要\n",
                        style="dim white",
                    )
                elif var == "PERPLEXITY_API_KEY":
                    error_text.append(
                        "export PERPLEXITY_API_KEY='your-perplexity-key-here'\n",
                        style="dim white",
                    )
                elif var == "STRIX_REASONING_EFFORT":
                    error_text.append(
                        "export STRIX_REASONING_EFFORT='high'\n",
                        style="dim white",
                    )

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )

        logger.error("Missing required env vars: %s", missing_required_vars)
        console.print("\n")
        console.print(panel)
        console.print()
        sys.exit(1)
    logger.info(
        "Environment OK (optional missing: %s)",
        missing_optional_vars or "none",
    )


def check_docker_installed() -> None:
    if shutil.which("docker") is None:
        logger.error("Docker CLI not found in PATH")
        console = Console()
        error_text = Text()
        error_text.append("未安装 Docker", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("在当前 PATH 中未找到 `docker` 命令。\n", style="white")
        error_text.append(
            "请先安装 Docker，并确保终端可以直接调用 `docker`。\n\n",
            style="white",
        )

        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print("\n", panel, "\n")
        sys.exit(1)
    logger.debug("Docker CLI present")


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
    return None


async def warm_up_llm(show_model_warning: bool = True) -> None:
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

        if show_model_warning and raw_model and not is_recommended_or_frontier_model(raw_model):
            warn_text = Text()
            warn_text.append("模型质量提示", style="bold yellow")
            warn_text.append("\n\n", style="white")
            warn_text.append(f"'{raw_model}'", style="bold cyan")
            warn_text.append(
                " 不是 Strix 当前推荐的前沿模型。\n更适合安全扫描的模型包括：\n",
                style="white",
            )
            for recommended_model in RECOMMENDED_MODEL_NAMES:
                warn_text.append(f"• {recommended_model}\n", style="bold cyan")
            warn_text.append(
                "\n你仍然可以继续运行，但较弱的模型可能会漏报漏洞，或降低分析质量。",
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

        model = StrixProvider().get_model(raw_model)
        await asyncio.wait_for(
            model.get_response(
                system_instructions="You are a helpful assistant.",
                input="Reply with just 'OK'.",
                model_settings=ModelSettings(),
                tools=[],
                output_schema=None,
                handoffs=[],
                tracing=ModelTracing.DISABLED,
                previous_response_id=None,
                conversation_id=None,
                prompt=None,
            ),
            timeout=llm.timeout,
        )
        logger.info("LLM warm-up succeeded for model %s", (llm.model or "").strip())

    except Exception as e:
        logger.exception("LLM warm-up failed")
        error_text = Text()
        error_text.append("LLM 连接失败", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("无法与语言模型建立连接。\n", style="white")
        error_text.append("请检查配置后重试。\n", style="white")
        hint = _provider_import_hint(e, raw_model)
        if hint is not None:
            error_text.append(f"\n{hint}\n", style="bold yellow")
        error_text.append(f"\n错误：{e}", style="dim white")

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
        sys.exit(1)


def get_version() -> str:
    try:
        from importlib.metadata import version

        return version("strix-agent")
    except Exception:
        return "unknown"


def _positive_budget(value: str) -> float:
    try:
        budget = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid float value: {value!r}") from exc
    import math

    if not math.isfinite(budget) or budget <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than 0")
    return budget


def _tcp_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("端口必须是整数。") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("端口必须在 1 到 65535 之间。")
    return port


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Strix 多代理网络安全渗透测试工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例：
  # Web 应用渗透测试
  strix --target https://example.com

  # GitHub 仓库分析
  strix --target https://github.com/user/repo
  strix --target git@github.com:user/repo.git

  # 本地代码分析
  strix --target ./my-project

  # 大型本地仓库（只读挂载，不逐文件复制）
  strix --mount ./huge-monorepo

  # 域名渗透测试
  strix --target example.com

  # IP 地址渗透测试
  strix --target 192.168.1.42

  # 多目标联合测试（例如源码 + 已部署应用的白盒测试）
  strix --target https://github.com/user/repo --target https://example.com
  strix --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # 从文件读取目标，每行一个，忽略空行和注释行
  strix --target-list ./targets.txt

  # 自定义指令（内联）
  strix --target example.com --instruction "重点测试认证相关漏洞"

  # 自定义指令（来自文件）
  strix --target example.com --instruction-file ./instructions.txt
  strix --target https://app.com --instruction-file /path/to/detailed_instructions.md

  # 固定 Burp 上游代理端口
  strix --target https://example.com --burp-port 8081

  # Burp 被动代理模式（不预设静态目标）
  strix --burp-port 8081
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"strix {get_version()}",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        action="append",
        help="要测试的目标（URL、仓库、本地目录路径、域名或 IP 地址）。"
        "多目标扫描时可重复指定。"
        "新任务必须至少提供 --target、--target-list、--mount 或 --burp-port 之一。",
    )
    parser.add_argument(
        "--target-list",
        type=str,
        action="append",
        metavar="PATH",
        help="目标列表文件路径。每个非空、非注释行视为一个目标。"
        "可重复指定，也可与 --target 混用。",
    )
    parser.add_argument(
        "--mount",
        type=str,
        action="append",
        metavar="PATH",
        help="将本地目录以只读方式挂载到沙箱，而不是逐文件复制。"
        "适合过大、无法流式复制进容器的大型仓库。"
        "可重复指定。",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="为本次渗透测试补充自定义指令。"
        "可以指定重点漏洞类型（如“重点测试 IDOR 和 XSS”）、"
        "测试方法（如“重点覆盖认证流程”）、"
        "测试凭据，或关注区域（如“重点检查登录 API”）。",
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help="包含详细自定义测试指令的文件路径。"
        "适合较长或较复杂的说明，例如 `--instruction-file ./detailed_instructions.txt`。",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help="以非交互模式运行（不启动 TUI，任务完成后直接退出）。默认使用带 TUI 的交互模式。",
    )

    parser.add_argument(
        "-m",
        "--scan-mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="deep",
        help=(
            "扫描模式："
            "`quick` 用于快速 CI/CD 检查，"
            "`standard` 用于常规测试，"
            "`deep` 用于深入安全审计（默认）。"
        ),
    )

    parser.add_argument(
        "--scope-mode",
        type=str,
        choices=["auto", "diff", "full"],
        default="auto",
        help=(
            "代码目标的范围模式："
            "`auto` 会在 CI/无头运行中自动启用 PR diff-scope，"
            "`diff` 强制只看变更文件，"
            "`full` 关闭 diff-scope。"
        ),
    )

    parser.add_argument(
        "--diff-base",
        type=str,
        help=(
            "用于对比的目标分支或提交，例如 `origin/main`。"
            "默认使用仓库默认分支。"
        ),
    )

    parser.add_argument(
        "--config",
        type=str,
        help="自定义配置文件（JSON）路径，用于替代 `~/.strix/cli-config.json`",
    )

    parser.add_argument(
        "--max-budget-usd",
        type=_positive_budget,
        default=None,
        help="LLM 最大成本上限（美元，需大于 0）。达到上限后任务会安全停止。",
    )

    parser.add_argument(
        "--burp-port",
        type=_tcp_port,
        metavar="PORT",
        help="将 Burp 上游代理入口固定绑定到本机端口。未指定时默认使用随机本机端口。",
    )

    parser.add_argument(
        "--resume",
        type=str,
        metavar="RUN_NAME",
        help=(
            "按历史运行名恢复之前的扫描（即 `./strix_runs/` 下的目录名）。"
            "会恢复根代理与所有未结束子代理的完整 LLM 历史和代理拓扑，"
            "并跳过新的 run-name 生成。"
        ),
    )

    args = parser.parse_args()

    if args.instruction and args.instruction_file:
        parser.error("不能同时指定 --instruction 和 --instruction-file，请二选一。")

    if args.instruction_file:
        instruction_path = Path(args.instruction_file)
        try:
            with instruction_path.open(encoding="utf-8") as f:
                args.instruction = f.read().strip()
                if not args.instruction:
                    parser.error(f"指令文件 '{instruction_path}' 为空")
        except Exception as e:
            parser.error(f"读取指令文件 '{instruction_path}' 失败：{e}")

    args.user_explicit_instruction = args.instruction if args.resume else None

    if args.resume:
        if args.target or args.target_list or args.mount:
            parser.error(
                "不能将 --resume 与 --target/--target-list/--mount 同时使用。"
                "--resume 会直接接续上一次运行，包括原始目标列表。"
            )
        _load_resume_state(args, parser)
        agents_path = runtime_state_dir(run_dir_for(args.resume)) / "agents.json"
        if not agents_path.exists():
            parser.error(
                f"--resume {args.resume}：缺少 {agents_path}。该运行虽然已落盘，"
                f"但还没走到首次代理快照阶段，因此没有可恢复的状态。"
                f"请改用新的 --run-name，或去掉 --resume 重新开始。"
            )
    else:
        if not args.target and not args.target_list and not args.mount and args.burp_port is None:
            parser.error(
                "必须至少提供以下参数之一：-t/--target、--target-list、--mount 或 --burp-port"
                "（也可使用 --resume <run_name> 恢复之前的扫描）"
            )
        args.targets_info = []
        targets = list(args.target or [])
        for target_list_path in args.target_list or []:
            try:
                targets.extend(read_target_list_file(target_list_path))
            except ValueError as e:
                parser.error(str(e))

        for target in targets:
            try:
                target_type, target_dict = infer_target_type(target)

                if target_type == "local_code":
                    display_target = target_dict.get("target_path", target)
                else:
                    display_target = target

                args.targets_info.append(
                    {"type": target_type, "details": target_dict, "original": display_target}
                )
            except ValueError:
                parser.error(f"无效目标：'{target}'")

        try:
            args.targets_info.extend(build_mount_targets_info(args.mount or []))
        except ValueError as e:
            parser.error(str(e))

        args.targets_info = dedupe_local_targets(args.targets_info)

        assign_workspace_subdirs(args.targets_info)
        rewrite_localhost_targets(args.targets_info, HOST_GATEWAY_HOSTNAME)

        max_local_copy_mb = load_settings().runtime.max_local_copy_mb
        max_copy_bytes = max_local_copy_mb * 1024 * 1024
        oversized = find_oversized_local_targets(args.targets_info, max_copy_bytes)
        if oversized:
            details = "; ".join(
                f"{path} ({size / (1024 * 1024):.0f} MB)" for path, size in oversized
            )
            parser.error(
                f"本地目标过大，无法以流式复制方式送入沙箱：{details}。"
                f"当前限制为 {max_local_copy_mb} MB"
                f"（可通过 STRIX_MAX_LOCAL_COPY_MB 调整）。"
                "请改用 --mount <path> 以只读挂载目录。"
            )

    return args


def _persist_run_record(args: argparse.Namespace) -> None:
    run_dir = run_dir_for(args.run_name)
    run_dir.mkdir(parents=True, exist_ok=True)
    run_record = {
        "run_id": args.run_name,
        "run_name": args.run_name,
        "status": "running",
        "start_time": datetime.now(UTC).isoformat(),
        "end_time": None,
        "targets_info": args.targets_info,
        "scan_mode": args.scan_mode,
        "instruction": args.instruction,
        "non_interactive": args.non_interactive,
        "local_sources": getattr(args, "local_sources", []),
        "diff_scope": getattr(args, "diff_scope", {"active": False}),
        "scope_mode": args.scope_mode,
        "diff_base": args.diff_base,
        "burp_port": args.burp_port,
    }
    write_run_record(run_dir, run_record)


def _load_resume_state(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Populate ``args.targets_info`` and friends from a prior run's run.json."""
    run_dir = run_dir_for(args.resume)
    state_path = run_dir / "run.json"
    if not state_path.exists():
        parser.error(
            f"--resume {args.resume}：找不到对应运行"
            f"（缺少 {state_path}；如需重新开始，请去掉 --resume）"
        )
    try:
        state = read_run_record(run_dir)
    except RuntimeError as exc:
        parser.error(f"--resume {args.resume}：run.json 无法读取：{exc}")

    persisted_burp_port = state.get("burp_port")
    args.targets_info = state.get("targets_info") or []
    if not args.targets_info and persisted_burp_port is None:
        parser.error(f"--resume {args.resume}：run.json 中缺少 targets_info")

    for target in args.targets_info:
        if not isinstance(target, dict):
            continue
        details = target.get("details") or {}
        if target.get("type") != "repository":
            continue
        cloned = details.get("cloned_repo_path")
        if not cloned:
            continue
        if not Path(cloned).expanduser().exists():
            parser.error(
                f"--resume {args.resume}：历史克隆目录 {cloned} 不存在。"
                "它可能在两次运行之间被删除。请使用新的 --run-name 重新克隆，"
                "或先恢复该目录后再继续。"
            )

    if args.instruction is None:
        args.instruction = state.get("instruction")
    if state.get("local_sources"):
        args.local_sources = state.get("local_sources")
    if state.get("diff_scope"):
        args.diff_scope = state.get("diff_scope")
    if args.burp_port is None and persisted_burp_port is not None:
        args.burp_port = persisted_burp_port
    persisted_scan_mode = state.get("scan_mode")
    if persisted_scan_mode and args.scan_mode == "deep":
        args.scan_mode = persisted_scan_mode


def display_completion_message(args: argparse.Namespace, results_path: Path) -> None:
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

    target_text = build_target_summary_text(
        args.targets_info,
        burp_port=getattr(args, "burp_port", None),
    )

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

    if not scan_completed:
        resume_text = Text()
        resume_text.append("\n")
        resume_text.append("继续运行", style="dim")
        resume_text.append("  ")
        resume_text.append(f"strix --resume {args.run_name}", style="#22c55e")
        panel_parts.extend(["\n", resume_text])

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


def _local_sandbox_build_tag(image: str) -> str | None:
    reference = image.strip()
    if not reference:
        return None

    name_part = reference.split("@", 1)[0]
    if "/" in name_part:
        return None

    repository, _, tag = name_part.partition(":")
    if repository != "strix-sandbox":
        return None

    return tag or "dev"


def pull_docker_image() -> None:
    console = Console()
    client = check_docker_connection()

    image = load_settings().runtime.image

    if image_exists(client, image):
        logger.debug("Docker image already present locally: %s", image)
        return

    local_sandbox_tag = _local_sandbox_build_tag(str(image))
    if local_sandbox_tag is not None:
        logger.error("Configured local sandbox image is missing: %s", image)
        console.print()
        error_text = Text()
        error_text.append("本地镜像未找到", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append(f"当前配置的镜像是：{image}\n\n", style="white")
        error_text.append(
            "这看起来是一个本地构建的 Strix sandbox 镜像标签，但当前 Docker 本地并不存在它。\n",
            style="white",
        )
        error_text.append(
            "请先在仓库根目录执行以下命令之一：\n",
            style="white",
        )
        error_text.append(
            f"1. 轻量覆盖构建：./scripts/docker-overlay.sh {local_sandbox_tag}\n",
            style="bold white",
        )
        error_text.append(
            f"2. 完整重建镜像：./scripts/docker.sh {local_sandbox_tag}\n",
            style="bold white",
        )
        error_text.append(
            "如果当前分支只改了 containers/docker-entrypoint.sh 等少量沙箱文件，优先使用轻量覆盖构建即可。\n\n",
            style="white",
        )
        error_text.append(
            "构建完成后重新运行当前命令；如果你想改回默认发布镜像，"
            "请将 STRIX_IMAGE 设为 ghcr.io/usestrix/strix-sandbox:1.0.0。",
            style="white",
        )
        panel = Panel(
            error_text,
            title="[bold white]STRIX",
            title_align="left",
            border_style="red",
            padding=(1, 2),
        )
        console.print(panel, "\n")
        sys.exit(1)

    logger.info("Pulling docker image: %s", image)
    console.print()
    console.print(f"[dim]正在拉取镜像[/] {image}")
    console.print("[dim yellow]首次运行时才会出现，可能需要几分钟，请稍候...[/]")
    console.print()

    with console.status("[bold cyan]正在下载镜像层...", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(image, stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

        except DockerException as e:
            logger.exception("Failed to pull docker image %s", image)
            console.print()
            error_text = Text()
            error_text.append("拉取镜像失败", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(f"无法下载镜像：{image}\n", style="white")
            error_text.append(str(e), style="dim red")

            panel = Panel(
                error_text,
                title="[bold white]STRIX",
                title_align="left",
                border_style="red",
                padding=(1, 2),
            )
            console.print(panel, "\n")
            sys.exit(1)

    logger.info("Docker image %s ready", image)
    success_text = Text()
    success_text.append("Docker 镜像已就绪", style="#22c55e")
    console.print(success_text)
    console.print()


def main() -> None:
    configure_dependency_logging()

    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    args = parse_arguments()

    if args.config:
        apply_config_override(validate_config_file(args.config))

    check_docker_installed()
    pull_docker_image()

    validate_environment()
    asyncio.run(warm_up_llm(show_model_warning=args.non_interactive))

    persist_current()

    args.run_name = args.resume or generate_run_name(args.targets_info)

    if not args.resume:
        for target_info in args.targets_info:
            if target_info["type"] == "repository":
                repo_url = target_info["details"]["target_repo"]
                dest_name = target_info["details"].get("workspace_subdir")
                cloned_path = clone_repository(repo_url, args.run_name, dest_name)
                target_info["details"]["cloned_repo_path"] = cloned_path

        args.local_sources = collect_local_sources(args.targets_info)
        try:
            diff_scope = resolve_diff_scope_context(
                local_sources=args.local_sources,
                scope_mode=args.scope_mode,
                diff_base=args.diff_base,
                non_interactive=args.non_interactive,
            )
        except ValueError as e:
            console = Console()
            error_text = Text()
            error_text.append("Diff scope 解析失败", style="bold red")
            error_text.append("\n\n", style="white")
            error_text.append(str(e), style="white")

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
            sys.exit(1)

        args.diff_scope = diff_scope.metadata
        if diff_scope.instruction_block:
            if args.instruction:
                args.instruction = f"{diff_scope.instruction_block}\n\n{args.instruction}"
            else:
                args.instruction = diff_scope.instruction_block

        _persist_run_record(args)

    _telemetry_start_kwargs = {
        "model": load_settings().llm.model,
        "scan_mode": args.scan_mode,
        "is_whitebox": is_whitebox_scan(args.targets_info),
        "interactive": not args.non_interactive,
        "has_instructions": bool(args.instruction),
    }
    posthog.start(**_telemetry_start_kwargs)
    scarf.start(**_telemetry_start_kwargs)

    exit_reason = "user_exit"
    try:
        if args.non_interactive:
            asyncio.run(run_cli(args))
        else:
            asyncio.run(run_tui(args))
    except KeyboardInterrupt:
        exit_reason = "interrupted"
    except Exception:
        exit_reason = "error"
        posthog.error("unhandled_exception")
        scarf.error("unhandled_exception")
        raise
    finally:
        report_state = get_global_report_state()
        if report_state:
            status = {"interrupted": "interrupted", "error": "failed"}.get(
                exit_reason,
                "stopped",
            )
            report_state.cleanup(status=status)
            posthog.end(report_state, exit_reason=exit_reason)
            scarf.end(report_state, exit_reason=exit_reason)

    results_path = run_dir_for(args.run_name)
    display_completion_message(args, results_path)

    if args.non_interactive:
        report_state = get_global_report_state()
        if report_state and report_state.vulnerability_reports:
            sys.exit(2)


if __name__ == "__main__":
    main()
