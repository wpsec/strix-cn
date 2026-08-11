"""Command-line argument parsing for the ``strix`` scan entrypoint."""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from strix.config import apply_config_override
from strix.config.settings import DEFAULT_MAX_TURNS
from strix.core.paths import run_dir_for, runtime_state_dir
from strix.interface.scan_setup import attach_workspace_mount, build_targets_info
from strix.interface.update_check import self_update
from strix.interface.utils import (
    check_mountable_dir,
    collect_local_sources,
    validate_config_file,
)


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


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid int value: {value!r}") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("必须是大于 0 的整数")
    return parsed


def _tcp_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("端口必须是整数。") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("端口必须在 1 到 65535 之间。")
    return port


def _read_target_password(parser: argparse.ArgumentParser) -> str:
    try:
        if sys.stdin.isatty():
            password = getpass.getpass("目标账户密码：")
        else:
            password = sys.stdin.readline().rstrip("\r\n")
    except (EOFError, OSError) as exc:
        parser.error(f"无法从标准输入读取目标账户密码：{exc}")
    if not password:
        parser.error("目标账户密码不能为空。")
    if "\x00" in password:
        parser.error("目标账户密码不能包含 NUL 字符。")
    return password


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

  # API 规格测试（OpenAPI/Swagger 文件或 Postman collection 导出）
  strix --target ./openapi.yaml --target https://api.example.com
  strix --target ./collection.postman_collection.json

  # 通过 id 实时拉取 Postman collection（需要 POSTMAN_API_KEY）
  strix --target postman://<collection-uuid> --target https://api.example.com
  strix --target "postman://<collection-uuid>?env=<environment-uuid>"

  # 保留兼容参数：把大型本地目录作为代码目标挂载
  strix --mount ./huge-monorepo

  # 固定 Burp 上游代理入口
  strix --target https://example.com --burp-port 8081
  strix --burp-port 8081

  # 域名渗透测试
  strix --target example.com

  # IP 地址渗透测试
  strix --target 192.168.1.42

  # 多目标联合测试（例如源码 + 已部署应用的白盒测试）
  strix --target https://github.com/user/repo --target https://example.com
  strix --target ./my-project --target https://staging.example.com --target https://prod.example.com

  # 从文件读取目标，每行一个，忽略空行和注释
  strix --target-list ./targets.txt

  # 自定义指令（内联）
  strix --target example.com --instruction "重点测试认证漏洞"

  # 自定义指令（来自文件）
  strix --target example.com --instruction-file ./instructions.txt
  strix --target https://app.com --instruction-file /path/to/detailed_instructions.md

  # 使用已授权登录账户（密码从终端安全读取，不写入命令行和报告）
  strix --target https://app.com --auth-username '<username>' --auth-password-stdin
        """,
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"strix {get_version()}",
    )

    parser.add_argument(
        "--update",
        action="store_true",
        help="更新 strix 并退出。独立二进制安装会尝试自更新；"
        "pip/pipx/uv 安装则只提示对应升级命令。",
    )

    parser.add_argument(
        "-t",
        "--target",
        type=str,
        action="append",
        help="要测试的目标：URL、仓库、本地目录、域名、IP、API 规格文件"
        "（OpenAPI/Swagger .json/.yaml 或 Postman collection 导出），"
        "或 Postman collection id（postman://<collection-uuid>[?env=<environment-uuid>]，"
        "需要 POSTMAN_API_KEY）。本地目录会以可写挂载方式进入沙箱。"
        "可重复指定。新任务需提供 --target、--target-list、--mount 或 --burp-port 之一。",
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
        help="兼容参数：将本地目录作为代码目标挂载到沙箱。"
        "当前本地代码目标本就走挂载模式，此参数主要保留现有使用习惯。",
    )
    parser.add_argument(
        "--burp-port",
        type=_tcp_port,
        metavar="PORT",
        help="将 Burp 上游代理入口固定绑定到本机端口。"
        "可单独使用，进入 Burp 被动代理模式。",
    )
    parser.add_argument(
        "--instruction",
        type=str,
        help="为本次渗透测试补充自定义指令，例如重点漏洞类型、测试方法或关注区域。"
        "登录凭据请使用 --auth-username 与 --auth-password-stdin，避免泄露到运行记录。",
    )

    parser.add_argument(
        "--instruction-file",
        type=str,
        help="包含详细测试指令的文件路径，适合较长或较复杂的说明。",
    )

    parser.add_argument(
        "--auth-username",
        type=str,
        metavar="USERNAME",
        help="已授权目标登录账户。必须与 --auth-password-stdin 一起使用；"
        "账户值不会写入报告或 Agent Prompt。",
    )
    parser.add_argument(
        "--auth-password-stdin",
        action="store_true",
        help="从 TTY 隐藏输入或标准输入读取一行目标账户密码。"
        "密码仅注入本次沙箱内存环境，不写入命令行、运行记录或 Prompt。",
    )
    parser.add_argument(
        "--allow-credential-attacks",
        action="store_true",
        help="显式授权本次测试执行弱口令、密码喷洒或登录重试测试。"
        "默认仅允许使用提供的账户正常登录，不允许口令攻击。",
    )

    parser.add_argument(
        "-n",
        "--non-interactive",
        action="store_true",
        help="以非交互模式运行（不启动 TUI，任务完成后直接退出）。",
    )

    parser.add_argument(
        "-m",
        "--scan-mode",
        type=str,
        choices=["quick", "standard", "deep"],
        default="deep",
        help=(
            "扫描模式：quick 用于快速 CI/CD 检查，standard 用于常规测试，"
            "deep 用于深入安全审计（默认）。"
        ),
    )

    parser.add_argument(
        "--scope-mode",
        type=str,
        choices=["auto", "diff", "full"],
        default="auto",
        help=(
            "代码目标的范围模式：auto 在 CI/无头运行中自动启用 PR diff-scope，"
            "diff 强制只看变更文件，full 关闭 diff-scope。"
        ),
    )

    parser.add_argument(
        "--diff-base",
        type=str,
        help="用于对比的目标分支或提交，例如 origin/main。",
    )

    parser.add_argument(
        "--config",
        type=str,
        help="自定义配置文件（JSON）路径，用于替代 ~/.strix/cli-config.json",
    )

    parser.add_argument(
        "--max-budget",
        "--max-budget-usd",
        dest="max_budget_usd",
        metavar="USD",
        type=_positive_budget,
        default=None,
        help=(
            "LLM 最大成本上限（美元，需大于 0）。达到阈值后任务会安全停止；"
            "接近预算时会向所有代理发送渐进式收尾提醒。"
        ),
    )

    parser.add_argument(
        "--max-turns",
        dest="max_turns",
        metavar="N",
        type=_positive_int,
        default=DEFAULT_MAX_TURNS,
        help=(
            "每个代理允许的最大 turns 数（需大于 0，默认 %(default)s）。"
            "达到上限后代理会被强制停止；接近上限时会收到渐进式收尾提醒。"
        ),
    )

    parser.add_argument(
        "--resume",
        type=str,
        metavar="RUN_NAME",
        help="按历史运行名恢复之前的扫描（即 ./strix_runs/ 下的目录名）。",
    )

    args = parser.parse_args()
    # Startup-resolved state lives alongside the parsed flags. The full schema
    # is established here so downstream code reads attributes directly.
    args.needs_setup = False
    args.targets_info = []
    args.local_sources = []
    args.diff_scope = {"active": False}
    args.run_name = None
    args.workspace_mount = None
    args.workspace_subdir = None
    args.target_credentials = None

    if args.config:
        apply_config_override(validate_config_file(args.config))

    if args.update:
        sys.exit(0 if self_update() else 1)

    if bool(args.auth_username) != bool(args.auth_password_stdin):
        parser.error("--auth-username 与 --auth-password-stdin 必须同时使用。")
    if args.auth_username is not None:
        username = args.auth_username.strip()
        if not username:
            parser.error("--auth-username 不能为空。")
        args.target_credentials = {
            "username": username,
            "password": _read_target_password(parser),
        }
        args.auth_username = None
        args.auth_password_stdin = False

    if args.instruction and args.instruction_file:
        parser.error(
            "Cannot specify both --instruction and --instruction-file. Use one or the other."
        )

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
    # What the user actually asked for, kept apart from args.instruction because
    # prepare_run prepends the diff-scope preamble to that. This is the text the
    # transcript shows as their opening message.
    args.user_instruction = args.instruction or None

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
                f"--resume {args.resume}：缺少 {agents_path}。"
                "该运行虽然已落盘，但还没走到首次代理快照阶段，因此没有可恢复的状态。"
            )
    else:
        mount_targets = list(args.mount or [])
        if mount_targets:
            args.target = list(args.target or []) + mount_targets

        if not args.target and not args.target_list and args.burp_port is None:
            if args.non_interactive:
                parser.error(
                    "必须至少提供以下参数之一：-t/--target、--target-list、--mount 或 --burp-port"
                    "（也可使用 --resume <run_name> 恢复之前的扫描）"
                )
            args.needs_setup = True
            return args

        try:
            build_targets_info(args)
        except ValueError as e:
            parser.error(str(e))

    return args


def _load_resume_state(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    """Populate ``args.targets_info`` and friends from a prior run's run.json."""
    from strix.report.writer import read_run_record

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

    args.targets_info = state.get("targets_info") or []
    # A target-less run has no targets_info at all. It is driven by its
    # instruction, over a mounted working directory or over nothing when the
    # mount was declined, so either of those is enough to resume it.
    workspace_mount = state.get("workspace_mount") or None
    persisted_burp_port = state.get("burp_port")
    if (
        not args.targets_info
        and not workspace_mount
        and persisted_burp_port is None
        and not state.get("user_instruction")
    ):
        parser.error(f"--resume {args.resume}：run.json 中缺少可恢复的目标或指令信息")

    for target in args.targets_info:
        if not isinstance(target, dict):
            continue
        details = target.get("details") or {}
        if target.get("type") == "local_code" and details.get("target_path"):
            try:
                check_mountable_dir(Path(details["target_path"]).expanduser())
            except ValueError as exc:
                parser.error(f"--resume {args.resume}：{exc}")
            continue
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
    if not getattr(args, "user_instruction", None):
        args.user_instruction = state.get("user_instruction") or None
    args.local_sources = collect_local_sources(args.targets_info)
    args.workspace_mount = workspace_mount
    if workspace_mount:
        if not Path(workspace_mount).expanduser().is_dir():
            parser.error(
                f"--resume {args.resume}：工作目录 {workspace_mount} 不存在。"
                "请先恢复该目录，或重新开始新的运行。"
            )
        attach_workspace_mount(args)
    if state.get("diff_scope"):
        args.diff_scope = state.get("diff_scope")
    if args.burp_port is None and persisted_burp_port is not None:
        args.burp_port = persisted_burp_port
    persisted_scan_mode = state.get("scan_mode")
    if persisted_scan_mode and args.scan_mode == "deep":
        args.scan_mode = persisted_scan_mode
