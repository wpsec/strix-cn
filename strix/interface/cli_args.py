"""Command-line argument parsing for the ``strix`` scan entrypoint."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from strix.config import apply_config_override, load_settings
from strix.config.settings import DEFAULT_MAX_TURNS
from strix.core.paths import run_dir_for, runtime_state_dir
from strix.core.token_budget import normalize_token_limit
from strix.interface.scan_setup import attach_workspace_mount, build_targets_info
from strix.interface.update_check import self_update
from strix.interface.utils import (
    check_mountable_dir,
    collect_local_sources,
    resolve_workspace_files,
    validate_config_file,
)
from strix.redteam.policy import POLICY_VERSION, normalize_mode


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


def _positive_token_limit(value: str) -> int:
    try:
        parsed = normalize_token_limit(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    if parsed is None:
        raise argparse.ArgumentTypeError("token_limit 不能为空")
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

  # 额外文件放入沙箱 workspace
  strix --target ./my-project --workspace-file ./wordlist.txt
  strix --target https://app.com --workspace-file ./openapi.yaml:specs/openapi.yaml
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
        help="目标列表文件路径。每个非空、非注释行视为一个目标。可重复指定，也可与 --target 混用。",
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
        help="将 Burp 上游代理入口固定绑定到本机端口。可单独使用，进入 Burp 被动代理模式。",
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
        "--request",
        dest="verification_request",
        metavar="PATH",
        help="漏洞验证模式使用的 Burp Raw HTTP 或 Copy as cURL 请求文件。",
    )
    parser.add_argument(
        "--secondary-request",
        dest="verification_secondary_request",
        metavar="PATH",
        help="漏洞验证模式使用的第二授权身份请求文件，用于跨身份对象边界对照。",
    )
    parser.add_argument(
        "--canary-url",
        dest="verification_canary_url",
        metavar="URL",
        help="漏洞验证模式使用的操作员控制 Canary 地址，不接受模型自行指定的目标地址。",
    )
    parser.add_argument(
        "--issue",
        dest="verification_issue",
        metavar="TEXT|@FILE",
        help="漏洞验证模式的问题描述；使用 @文件路径可从文件读取。",
    )
    parser.add_argument(
        "--baseline",
        dest="verification_baseline",
        metavar="RUN_NAME",
        help="漏洞验证模式使用的历史运行名，用于修复后复测。",
    )
    parser.add_argument(
        "--yes",
        dest="verification_approve",
        action="store_true",
        help="非交互漏洞验证模式确认执行当前验证计划。",
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
        "--workspace-file",
        type=str,
        action="append",
        metavar="PATH[:DEST]",
        help="Place a file from this machine into the sandbox workspace before the scan "
        "starts, for example a wordlist, an API specification, or notes. Repeat the option "
        "for more files. DEST is the path inside /workspace and defaults to the file name "
        "(for example '--workspace-file ./wordlist.txt:lists/wordlist.txt'). The file is "
        "read-only inside the sandbox and lands outside every target directory.",
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

    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--red",
        dest="redteam",
        action="store_true",
        help="启用红队专项模式：仅验证白名单高风险类型，并生成攻击链报告。",
    )
    mode_group.add_argument(
        "--verify",
        dest="verify",
        action="store_true",
        help="启用漏洞验证模式：根据 Burp 请求和自然语言描述复现或复测单个漏洞。",
    )
    mode_group.add_argument(
        "--mode",
        choices=["normal", "redteam", "verify"],
        default=None,
        help="安全策略模式：normal、redteam 或 verify。默认读取 STRIX_MODE 或配置文件。",
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
        "--mcp-config",
        type=str,
        metavar="PATH",
        help="Path to an MCP servers JSON file to use instead of ~/.strix/mcp-servers.json.",
    )

    parser.add_argument(
        "--mcp-server",
        dest="mcp_server",
        action="append",
        metavar="NAME",
        help="Use only this MCP connection for the run, by its config name "
        "(repeatable). Every other configured connection is skipped.",
    )

    parser.add_argument(
        "--mcp-exclude",
        dest="mcp_exclude",
        action="append",
        metavar="NAME",
        help="Skip this MCP connection for the run, by its config name (repeatable).",
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
        "--token-limit",
        dest="token_limit",
        metavar="N[K/M/G/T/B]",
        type=_positive_token_limit,
        default=None,
        help=(
            "扫描级有效 Token 上限（需大于 0，支持 100M、1.5G 等后缀）。配置后优先测试严重/高危漏洞；"
            "未配置表示不限制扫描 Token。"
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
    args.mode_explicit = "redteam" if args.redteam else ("verify" if args.verify else args.mode)

    if args.config:
        apply_config_override(validate_config_file(args.config))

    try:
        configured_mode = normalize_mode(load_settings().security.mode)
    except (AttributeError, ValueError) as exc:
        parser.error(f"安全策略模式配置无效：{exc}")
    args.mode = normalize_mode(args.mode_explicit or configured_mode)

    has_verification_args = any(
        (
            args.verification_request,
            args.verification_secondary_request,
            args.verification_canary_url,
            args.verification_issue,
            args.verification_baseline,
            args.verification_approve,
        )
    )
    if args.mode != "verify" and has_verification_args:
        parser.error(
            "--request、--secondary-request、--canary-url、--issue、"
            "--baseline 和 --yes 只能用于 --verify。"
        )

    if args.mode == "verify":
        if args.redteam or args.burp_port is not None:
            parser.error("漏洞验证模式不能与 --red 或 --burp-port 同时使用。")
        if args.target or args.target_list or args.mount:
            parser.error("漏洞验证模式使用 --request，不支持 --target/--target-list/--mount。")
        if args.resume:
            parser.error("漏洞验证模式使用 --baseline 复测，不支持 --resume。")
        if args.verification_baseline and args.verification_issue:
            parser.error("使用 --baseline 复测时不需要再次提供 --issue。")
        if args.verification_issue and args.verification_issue.startswith("@"):
            issue_path = Path(args.verification_issue[1:]).expanduser()
            try:
                args.verification_issue = issue_path.read_text(encoding="utf-8").strip()
            except (OSError, UnicodeDecodeError) as exc:
                parser.error(f"读取漏洞描述失败：{exc}")
        if not args.verification_request:
            if args.non_interactive:
                parser.error("漏洞验证模式需要 --request <Burp请求文件>。")
        else:
            request_path = Path(args.verification_request).expanduser()
            if not request_path.is_file():
                parser.error(f"请求文件不存在：{args.verification_request}")
            args.verification_request = str(request_path)
        if args.verification_secondary_request:
            secondary_path = Path(args.verification_secondary_request).expanduser()
            if not secondary_path.is_file():
                parser.error(
                    f"第二身份请求文件不存在：{args.verification_secondary_request}"
                )
            args.verification_secondary_request = str(secondary_path)
        if args.non_interactive and not args.verification_baseline and not args.verification_issue:
            parser.error("首次漏洞验证模式需要 --issue <问题描述>。")
        if args.verification_approve and not args.non_interactive:
            parser.error("--yes 只能用于非交互模式。")

    if args.mcp_config:
        mcp_config_path = Path(args.mcp_config).expanduser()
        if not mcp_config_path.is_file():
            parser.error(f"--mcp-config file not found: {args.mcp_config}")
        # The MCP loader reads this env var as its config-path override, so
        # setting it here makes the flag win over the default location.
        os.environ["STRIX_MCP_CONFIG"] = str(mcp_config_path)

    # The MCP loader reads these as its per-run include/exclude selection.
    if args.mcp_server:
        os.environ["STRIX_MCP_ONLY"] = ",".join(args.mcp_server)
    if args.mcp_exclude:
        os.environ["STRIX_MCP_EXCLUDE"] = ",".join(args.mcp_exclude)

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

    try:
        args.workspace_files = resolve_workspace_files(getattr(args, "workspace_file", None))
    except ValueError as error:
        parser.error(f"--workspace-file: {error}")

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

        if args.mode == "verify":
            return args

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
    except (RuntimeError, TypeError) as exc:
        parser.error(f"--resume {args.resume}：run.json 无法读取：{exc}")

    try:
        persisted_mode = normalize_mode(state.get("mode", "normal"))
    except ValueError as exc:
        parser.error(f"--resume {args.resume}：历史安全策略模式无效：{exc}")
    explicit_mode = getattr(args, "mode_explicit", None)
    if explicit_mode is not None and explicit_mode != persisted_mode:
        parser.error(
            f"--resume {args.resume}：不能将模式从 {persisted_mode} 改为 {explicit_mode}。"
            "恢复扫描必须沿用历史运行模式。"
        )
    if persisted_mode == "redteam" and state.get("policy_version") != POLICY_VERSION:
        parser.error(
            f"--resume {args.resume}：历史红队专项策略版本不受支持；"
            "策略已变更，请新建扫描以重新确认授权范围。"
        )
    args.mode = persisted_mode

    from strix.core.token_budget import normalize_token_limit

    try:
        persisted_token_limit = normalize_token_limit(state.get("token_limit"))
    except ValueError as exc:
        parser.error(f"--resume {args.resume}：历史 token_limit 无效：{exc}")
    requested_token_limit = getattr(args, "token_limit", None)
    if requested_token_limit is None:
        args.token_limit = persisted_token_limit
    elif persisted_token_limit is not None and requested_token_limit < persisted_token_limit:
        parser.error(
            "--resume 不允许降低历史 token_limit；"
            "如需追加额度，请显式提供更大的 --token-limit。"
        )

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

    # Replace the workspace files the run started with, unless this resume names
    # its own. The persisted record is revalidated like a fresh flag, so an
    # edited run.json cannot widen what a resume places. A file deleted between
    # runs is dropped rather than fatal: it is context for the agent, not scope.
    if not getattr(args, "workspace_files", None):
        restored = [
            f"{source_path}:{workspace_path}"
            for workspace_file in state.get("workspace_files") or []
            if isinstance(workspace_file, dict)
            and (source_path := Path(str(workspace_file.get("source_path") or ""))).is_file()
            and (workspace_path := str(workspace_file.get("workspace_path") or ""))
        ]
        try:
            args.workspace_files = resolve_workspace_files(restored)
        except ValueError as error:
            parser.error(f"--resume {args.resume}: invalid workspace file: {error}")
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
