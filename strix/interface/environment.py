"""Startup environment validation and Docker image management."""

import logging
import shutil
import sys

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import codex, load_settings
from strix.interface.utils import check_docker_connection, image_exists, process_pull_line


logger = logging.getLogger(__name__)


def validate_environment() -> None:
    logger.info("Validating environment")
    console = Console()
    missing_required_vars = []
    missing_optional_vars = []

    settings = load_settings()

    if codex.subscription_model(settings.llm.model):
        if not codex.is_authenticated():
            console.print(
                f"[red]STRIX_LLM={settings.llm.model} uses your ChatGPT subscription, "
                "but you're not signed in.[/] Run [cyan]strix auth login chatgpt[/] first."
            )
            sys.exit(1)
        logger.info("Environment OK (ChatGPT subscription)")
        return

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
                if var == "LLM_API_BASE":
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
                        " - 推理强度等级：none、minimal、low、medium、high、xhigh、"
                        "max（默认：high）\n",
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

        logger.debug("Missing required env vars: %s", missing_required_vars)
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
        logger.debug("Docker CLI not found in PATH")
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
    from docker.errors import DockerException

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
        error_text.append("请先在仓库根目录执行以下命令之一：\n", style="white")
        error_text.append(
            f"1. 轻量覆盖构建：./scripts/docker-overlay.sh {local_sandbox_tag}\n",
            style="bold white",
        )
        error_text.append(
            f"2. 完整重建镜像：./scripts/docker.sh {local_sandbox_tag}\n",
            style="bold white",
        )
        error_text.append(
            "如果当前分支只改了少量沙箱文件，优先使用轻量覆盖构建即可。\n\n",
            style="white",
        )
        error_text.append(
            "构建完成后重新运行当前命令；如果你想改回默认发布镜像，"
            "请将 STRIX_IMAGE 设为 ghcr.io/usestrix/strix-sandbox:1.3.0。",
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

    with console.status("[bold cyan]Downloading image layers...", spinner="dots") as status:
        try:
            layers_info: dict[str, str] = {}
            last_update = ""

            for line in client.api.pull(image, stream=True, decode=True):
                last_update = process_pull_line(line, layers_info, status, last_update)

        except DockerException as e:
            logger.debug("Failed to pull docker image %s", image, exc_info=True)
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
