import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import docker
from docker.errors import DockerException, ImageNotFound
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.config import load_settings


logger = logging.getLogger(__name__)


def get_severity_color(severity: str) -> str:
    severity_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#65a30d",
        "info": "#0284c7",
    }
    return severity_colors.get(severity, "#6b7280")


def get_cvss_color(cvss_score: float) -> str:
    if cvss_score >= 9.0:
        return "#dc2626"
    if cvss_score >= 7.0:
        return "#ea580c"
    if cvss_score >= 4.0:
        return "#d97706"
    if cvss_score >= 0.1:
        return "#65a30d"
    return "#6b7280"


def format_token_count(count: float | None) -> str:
    value = int(count or 0)
    if value >= 1_000_000:
        return f"{value / 1_000_000:.1f}M"
    if value >= 1_000:
        return f"{value / 1_000:.1f}K"
    return str(value)


def format_vulnerability_report(report: dict[str, Any]) -> Text:  # noqa: PLR0915
    field_style = "bold #4ade80"

    text = Text()

    title = report.get("title", "")
    if title:
        text.append("漏洞报告", style="bold #ea580c")
        text.append("\n\n")
        text.append("标题：", style=field_style)
        text.append(title)

    severity = report.get("severity", "")
    if severity:
        text.append("\n\n")
        text.append("严重度：", style=field_style)
        severity_color = get_severity_color(severity.lower())
        text.append(severity.upper(), style=f"bold {severity_color}")

    cvss = report.get("cvss")
    if cvss is not None:
        text.append("\n\n")
        text.append("CVSS 分数：", style=field_style)
        cvss_color = get_cvss_color(cvss)
        text.append(f"{cvss:.1f}", style=f"bold {cvss_color}")

    target = report.get("target")
    if target:
        text.append("\n\n")
        text.append("目标：", style=field_style)
        text.append(target)

    endpoint = report.get("endpoint")
    if endpoint:
        text.append("\n\n")
        text.append("接口：", style=field_style)
        text.append(endpoint)

    method = report.get("method")
    if method:
        text.append("\n\n")
        text.append("方法：", style=field_style)
        text.append(method)

    cve = report.get("cve")
    if cve:
        text.append("\n\n")
        text.append("CVE: ", style=field_style)
        text.append(cve)

    cvss_breakdown = report.get("cvss_breakdown", {})
    if cvss_breakdown:
        text.append("\n\n")
        cvss_parts = []
        if cvss_breakdown.get("attack_vector"):
            cvss_parts.append(f"AV:{cvss_breakdown['attack_vector']}")
        if cvss_breakdown.get("attack_complexity"):
            cvss_parts.append(f"AC:{cvss_breakdown['attack_complexity']}")
        if cvss_breakdown.get("privileges_required"):
            cvss_parts.append(f"PR:{cvss_breakdown['privileges_required']}")
        if cvss_breakdown.get("user_interaction"):
            cvss_parts.append(f"UI:{cvss_breakdown['user_interaction']}")
        if cvss_breakdown.get("scope"):
            cvss_parts.append(f"S:{cvss_breakdown['scope']}")
        if cvss_breakdown.get("confidentiality"):
            cvss_parts.append(f"C:{cvss_breakdown['confidentiality']}")
        if cvss_breakdown.get("integrity"):
            cvss_parts.append(f"I:{cvss_breakdown['integrity']}")
        if cvss_breakdown.get("availability"):
            cvss_parts.append(f"A:{cvss_breakdown['availability']}")
        if cvss_parts:
            text.append("CVSS 向量：", style=field_style)
            text.append("/".join(cvss_parts), style="dim")

    description = report.get("description")
    if description:
        text.append("\n\n")
        text.append("漏洞描述", style=field_style)
        text.append("\n")
        text.append(description)

    impact = report.get("impact")
    if impact:
        text.append("\n\n")
        text.append("影响", style=field_style)
        text.append("\n")
        text.append(impact)

    technical_analysis = report.get("technical_analysis")
    if technical_analysis:
        text.append("\n\n")
        text.append("技术分析", style=field_style)
        text.append("\n")
        text.append(technical_analysis)

    poc_description = report.get("poc_description")
    if poc_description:
        text.append("\n\n")
        text.append("PoC 说明", style=field_style)
        text.append("\n")
        text.append(poc_description)

    poc_script_code = report.get("poc_script_code")
    if poc_script_code:
        text.append("\n\n")
        text.append("PoC 代码", style=field_style)
        text.append("\n")
        text.append(poc_script_code, style="dim")

    code_locations = report.get("code_locations")
    if code_locations:
        text.append("\n\n")
        text.append("代码位置", style=field_style)
        for i, loc in enumerate(code_locations):
            text.append("\n\n")
            text.append(f"  位置 {i + 1}：", style="dim")
            text.append(loc.get("file", "unknown"), style="bold")
            start = loc.get("start_line")
            end = loc.get("end_line")
            if start is not None:
                if end and end != start:
                    text.append(f":{start}-{end}")
                else:
                    text.append(f":{start}")
            if loc.get("label"):
                text.append(f"\n  {loc['label']}", style="italic dim")
            if loc.get("snippet"):
                text.append("\n  ")
                text.append(loc["snippet"], style="dim")
            if loc.get("fix_before") or loc.get("fix_after"):
                text.append("\n  修复建议：")
                if loc.get("fix_before"):
                    text.append("\n  - ", style="dim")
                    text.append(loc["fix_before"], style="dim")
                if loc.get("fix_after"):
                    text.append("\n  + ", style="dim")
                    text.append(loc["fix_after"], style="dim")

    remediation_steps = report.get("remediation_steps")
    if remediation_steps:
        text.append("\n\n")
        text.append("修复建议", style=field_style)
        text.append("\n")
        text.append(remediation_steps)

    return text


def _build_vulnerability_stats(stats_text: Text, report_state: Any) -> None:
    vuln_count = len(report_state.vulnerability_reports)

    if vuln_count > 0:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for report in report_state.vulnerability_reports:
            severity = report.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        stats_text.append("漏洞  ", style="bold red")

        severity_parts = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts[severity]
            if count > 0:
                severity_color = get_severity_color(severity)
                severity_text = Text()
                severity_text.append(f"{severity.upper()}: ", style=severity_color)
                severity_text.append(str(count), style=f"bold {severity_color}")
                severity_parts.append(severity_text)

        for i, part in enumerate(severity_parts):
            stats_text.append(part)
            if i < len(severity_parts) - 1:
                stats_text.append(" | ", style="dim white")

        stats_text.append("（总计：", style="dim white")
        stats_text.append(str(vuln_count), style="bold yellow")
        stats_text.append("）", style="dim white")
        stats_text.append("\n")
    else:
        stats_text.append("漏洞  ", style="bold #22c55e")
        stats_text.append("0", style="bold white")
        stats_text.append("（未发现可利用漏洞）", style="dim green")
        stats_text.append("\n")


def _llm_usage(report_state: Any) -> dict[str, Any]:
    if hasattr(report_state, "get_total_llm_usage"):
        usage = report_state.get_total_llm_usage()
        return usage if isinstance(usage, dict) else {}
    usage = getattr(report_state, "run_record", {}).get("llm_usage")
    return usage if isinstance(usage, dict) else {}


def _int_stat(usage: dict[str, Any], key: str) -> int:
    try:
        return max(0, int(usage.get(key) or 0))
    except (TypeError, ValueError):
        return 0


def _float_stat(usage: dict[str, Any], key: str) -> float:
    try:
        value = float(usage.get(key) or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return value if value > 0 else 0.0


def _detail_value(usage: dict[str, Any], detail_key: str, value_key: str) -> int:
    details = usage.get(detail_key)
    if isinstance(details, list):
        details = details[0] if details and isinstance(details[0], dict) else {}
    if not isinstance(details, dict):
        return 0
    return _int_stat(details, value_key)


def _build_llm_usage_stats(
    stats_text: Text,
    report_state: Any,
    *,
    live: bool = False,
) -> None:
    usage = _llm_usage(report_state)
    if not usage or _int_stat(usage, "requests") <= 0:
        stats_text.append("\n")
        stats_text.append("成本 ", style="dim")
        stats_text.append("$0.0000 ", style="#fbbf24")
        stats_text.append("· ", style="dim white")
        stats_text.append("Tokens ", style="dim")
        stats_text.append("0", style="white")
        return

    input_tokens = _int_stat(usage, "input_tokens")
    output_tokens = _int_stat(usage, "output_tokens")
    cached_tokens = _detail_value(usage, "input_tokens_details", "cached_tokens")
    cost = _float_stat(usage, "cost")

    stats_text.append("\n")
    stats_text.append("输入 Tokens ", style="dim")
    stats_text.append(format_token_count(input_tokens), style="white")

    if live or cached_tokens > 0:
        stats_text.append("  ·  ", style="dim white")
        stats_text.append("缓存 Tokens ", style="dim")
        stats_text.append(format_token_count(cached_tokens), style="white")

    separator = "\n" if live else "  ·  "
    stats_text.append(separator, style="dim white")
    stats_text.append("输出 Tokens ", style="dim")
    stats_text.append(format_token_count(output_tokens), style="white")

    if live or cost > 0:
        stats_text.append("  ·  ", style="dim white")
        stats_text.append("成本 ", style="dim")
        stats_text.append(f"${cost:.4f}", style="#fbbf24")


def _format_burp_upstream_endpoint(caido_url: str) -> str:
    parsed = urlparse(caido_url)
    host = parsed.hostname or caido_url
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if parsed.port is not None:
        return f"{host}:{parsed.port}"
    return host


def build_target_summary_text(
    targets_info: list[dict[str, Any]] | None,
    *,
    burp_port: int | None = None,
) -> Text:
    target_text = Text()
    target_text.append("目标", style="dim")
    target_text.append("  ")

    targets = targets_info or []
    if not targets and burp_port is not None:
        target_text.append("Burp 被动模式", style="bold white")
        target_text.append("\n        ")
        target_text.append("仅基于 Burp 转发流量建立作用域", style="white")
        return target_text

    if len(targets) == 1:
        target_text.append(targets[0]["original"], style="bold white")
        return target_text

    target_text.append(f"{len(targets)} 个目标", style="bold white")
    for target_info in targets:
        target_text.append("\n        ")
        target_text.append(target_info["original"], style="white")
    return target_text


def _append_burp_upstream_status(stats_text: Text, report_state: Any) -> None:
    caido_url = getattr(report_state, "caido_url", None)
    unavailable_reason = getattr(report_state, "burp_upstream_unavailable_reason", None)

    if isinstance(caido_url, str) and caido_url:
        stats_text.append("\n")
        stats_text.append("Burp 上游代理: ", style="bold white")
        stats_text.append(_format_burp_upstream_endpoint(caido_url), style="white")
        stats_text.append("\n")
        stats_text.append("仅本机可访问", style="dim white")
        return

    if isinstance(unavailable_reason, str) and unavailable_reason:
        stats_text.append("\n")
        stats_text.append("Burp 上游代理: ", style="bold white")
        stats_text.append(unavailable_reason, style="dim white")


def build_final_stats_text(report_state: Any) -> Text:
    stats_text = Text()
    if not report_state:
        return stats_text

    _build_vulnerability_stats(stats_text, report_state)
    _build_llm_usage_stats(stats_text, report_state)

    return stats_text


def build_live_stats_text(report_state: Any) -> Text:
    stats_text = Text()
    if not report_state:
        return stats_text

    model = load_settings().llm.model or "unknown"
    stats_text.append("模型 ", style="dim")
    stats_text.append(str(model), style="white")
    stats_text.append("\n")

    vuln_count = len(report_state.vulnerability_reports)
    stats_text.append("漏洞 ", style="dim")
    stats_text.append(f"{vuln_count}", style="white")
    stats_text.append("\n")
    if vuln_count > 0:
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for report in report_state.vulnerability_reports:
            severity = report.get("severity", "").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        severity_parts = []
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts[severity]
            if count > 0:
                severity_color = get_severity_color(severity)
                severity_text = Text()
                severity_text.append(f"{severity.upper()}: ", style=severity_color)
                severity_text.append(str(count), style=f"bold {severity_color}")
                severity_parts.append(severity_text)

        for i, part in enumerate(severity_parts):
            stats_text.append(part)
            if i < len(severity_parts) - 1:
                stats_text.append(" | ", style="dim white")

        stats_text.append("\n")

    _build_llm_usage_stats(stats_text, report_state, live=True)
    _append_burp_upstream_status(stats_text, report_state)

    return stats_text


def build_tui_stats_text(report_state: Any) -> Text:
    stats_text = Text()
    if not report_state:
        return stats_text

    model = load_settings().llm.model or "unknown"
    stats_text.append(str(model), style="white")

    usage = _llm_usage(report_state)
    if usage and _int_stat(usage, "total_tokens") > 0:
        stats_text.append("\n")
        stats_text.append(
            f"{format_token_count(_int_stat(usage, 'total_tokens'))} tokens",
            style="white",
        )
        cost = _float_stat(usage, "cost")
        if cost > 0:
            stats_text.append(" · ", style="white")
            stats_text.append(f"${cost:.2f}", style="white")

    _append_burp_upstream_status(stats_text, report_state)

    return stats_text


def _slugify_for_run_name(text: str, max_length: int = 32) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9]+", "-", text)
    text = text.strip("-")
    if len(text) > max_length:
        text = text[:max_length].rstrip("-")
    return text or "pentest"


def _derive_target_label_for_run_name(targets_info: list[dict[str, Any]] | None) -> str:  # noqa: PLR0911
    if not targets_info:
        return "pentest"

    first = targets_info[0]
    target_type = first.get("type")
    details = first.get("details", {}) or {}
    original = first.get("original", "") or ""

    if target_type == "web_application":
        url = details.get("target_url", original)
        try:
            parsed = urlparse(url)
            return str(parsed.netloc or parsed.path or url)
        except Exception:
            return str(url)

    if target_type == "repository":
        repo = details.get("target_repo", original)
        parsed = urlparse(repo)
        path = parsed.path or repo
        name = path.rstrip("/").split("/")[-1] or path
        if name.endswith(".git"):
            name = name[:-4]
        return str(name)

    if target_type == "local_code":
        path_str = details.get("target_path", original)
        try:
            return str(Path(path_str).name or path_str)
        except Exception:
            return str(path_str)

    if target_type == "ip_address":
        return str(details.get("target_ip", original) or original)

    return str(original or "pentest")


def generate_run_name(targets_info: list[dict[str, Any]] | None = None) -> str:
    base_label = _derive_target_label_for_run_name(targets_info)
    slug = _slugify_for_run_name(base_label)

    random_suffix = secrets.token_hex(2)

    return f"{slug}_{random_suffix}"


_SUPPORTED_SCOPE_MODES = {"auto", "diff", "full"}
_MAX_FILES_PER_SECTION = 120


@dataclass
class DiffEntry:
    status: str
    path: str
    old_path: str | None = None
    similarity: int | None = None


@dataclass
class RepoDiffScope:
    source_path: str
    workspace_subdir: str | None
    base_ref: str
    merge_base: str
    added_files: list[str]
    modified_files: list[str]
    renamed_files: list[dict[str, Any]]
    deleted_files: list[str]
    analyzable_files: list[str]
    truncated_sections: dict[str, bool] = field(default_factory=dict)

    def to_metadata(self) -> dict[str, Any]:
        return {
            "source_path": self.source_path,
            "workspace_subdir": self.workspace_subdir,
            "base_ref": self.base_ref,
            "merge_base": self.merge_base,
            "added_files": self.added_files,
            "modified_files": self.modified_files,
            "renamed_files": self.renamed_files,
            "deleted_files": self.deleted_files,
            "analyzable_files": self.analyzable_files,
            "added_files_count": len(self.added_files),
            "modified_files_count": len(self.modified_files),
            "renamed_files_count": len(self.renamed_files),
            "deleted_files_count": len(self.deleted_files),
            "analyzable_files_count": len(self.analyzable_files),
            "truncated_sections": self.truncated_sections,
        }


@dataclass
class DiffScopeResult:
    active: bool
    mode: str
    instruction_block: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def _run_git_command(
    repo_path: Path, args: list[str], check: bool = True
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["git", "-C", str(repo_path), *args],  # noqa: S607
        capture_output=True,
        text=True,
        check=check,
    )


def _run_git_command_raw(
    repo_path: Path, args: list[str], check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(  # noqa: S603
        ["git", "-C", str(repo_path), *args],  # noqa: S607
        capture_output=True,
        check=check,
    )


def _is_ci_environment(env: dict[str, str]) -> bool:
    return any(
        env.get(key)
        for key in (
            "CI",
            "GITHUB_ACTIONS",
            "GITLAB_CI",
            "JENKINS_URL",
            "BUILDKITE",
            "CIRCLECI",
        )
    )


def _is_pr_environment(env: dict[str, str]) -> bool:
    return any(
        env.get(key)
        for key in (
            "GITHUB_BASE_REF",
            "GITHUB_HEAD_REF",
            "CI_MERGE_REQUEST_TARGET_BRANCH_NAME",
            "GITLAB_MERGE_REQUEST_TARGET_BRANCH_NAME",
            "SYSTEM_PULLREQUEST_TARGETBRANCH",
        )
    )


def _is_git_repo(repo_path: Path) -> bool:
    result = _run_git_command(repo_path, ["rev-parse", "--is-inside-work-tree"], check=False)
    return result.returncode == 0 and result.stdout.strip().lower() == "true"


def _is_repo_shallow(repo_path: Path) -> bool:
    result = _run_git_command(repo_path, ["rev-parse", "--is-shallow-repository"], check=False)
    if result.returncode == 0:
        value = result.stdout.strip().lower()
        if value in {"true", "false"}:
            return value == "true"

    git_meta = repo_path / ".git"
    if git_meta.is_dir():
        return (git_meta / "shallow").exists()
    if git_meta.is_file():
        try:
            content = git_meta.read_text(encoding="utf-8").strip()
        except OSError:
            return False
        if content.startswith("gitdir:"):
            git_dir = content.split(":", 1)[1].strip()
            resolved = (repo_path / git_dir).resolve()
            return (resolved / "shallow").exists()
    return False


def _git_ref_exists(repo_path: Path, ref: str) -> bool:
    result = _run_git_command(repo_path, ["rev-parse", "--verify", "--quiet", ref], check=False)
    return result.returncode == 0


def _resolve_origin_head_ref(repo_path: Path) -> str | None:
    result = _run_git_command(
        repo_path, ["symbolic-ref", "--quiet", "refs/remotes/origin/HEAD"], check=False
    )
    if result.returncode != 0:
        return None
    ref = result.stdout.strip()
    return ref or None


def _extract_branch_name(ref: str | None) -> str | None:
    if not ref:
        return None
    value = ref.strip()
    if not value:
        return None
    return value.split("/")[-1]


def _extract_github_base_sha(env: dict[str, str]) -> str | None:
    event_path = env.get("GITHUB_EVENT_PATH", "").strip()
    if not event_path:
        return None

    path = Path(event_path)
    if not path.exists():
        return None

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None

    base_sha = payload.get("pull_request", {}).get("base", {}).get("sha")
    if isinstance(base_sha, str) and base_sha.strip():
        return base_sha.strip()
    return None


def _resolve_default_branch_name(repo_path: Path, env: dict[str, str]) -> str | None:
    github_base_ref = env.get("GITHUB_BASE_REF", "").strip()
    if github_base_ref:
        return github_base_ref

    origin_head = _resolve_origin_head_ref(repo_path)
    if origin_head:
        branch = _extract_branch_name(origin_head)
        if branch:
            return branch

    if _git_ref_exists(repo_path, "refs/remotes/origin/main"):
        return "main"
    if _git_ref_exists(repo_path, "refs/remotes/origin/master"):
        return "master"

    return None


def _resolve_base_ref(repo_path: Path, diff_base: str | None, env: dict[str, str]) -> str:
    if diff_base and diff_base.strip():
        return diff_base.strip()

    github_base_ref = env.get("GITHUB_BASE_REF", "").strip()
    if github_base_ref:
        github_candidate = f"refs/remotes/origin/{github_base_ref}"
        if _git_ref_exists(repo_path, github_candidate):
            return github_candidate

    github_base_sha = _extract_github_base_sha(env)
    if github_base_sha and _git_ref_exists(repo_path, github_base_sha):
        return github_base_sha

    origin_head = _resolve_origin_head_ref(repo_path)
    if origin_head and _git_ref_exists(repo_path, origin_head):
        return origin_head

    if _git_ref_exists(repo_path, "refs/remotes/origin/main"):
        return "refs/remotes/origin/main"

    if _git_ref_exists(repo_path, "refs/remotes/origin/master"):
        return "refs/remotes/origin/master"

    raise ValueError(
        "无法为 diff-scope 解析基准引用。请显式传入 --diff-base "
        "（例如：--diff-base origin/main）。"
    )


def _get_current_branch_name(repo_path: Path) -> str | None:
    result = _run_git_command(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"], check=False)
    if result.returncode != 0:
        return None
    branch_name = result.stdout.strip()
    if not branch_name or branch_name == "HEAD":
        return None
    return branch_name


def _parse_name_status_z(raw_output: bytes) -> list[DiffEntry]:
    if not raw_output:
        return []

    tokens = [
        token.decode("utf-8", errors="replace") for token in raw_output.split(b"\x00") if token
    ]
    entries: list[DiffEntry] = []
    index = 0

    while index < len(tokens):
        token = tokens[index]
        status_raw = token
        status_code = status_raw[:1]
        similarity: int | None = None
        if len(status_raw) > 1 and status_raw[1:].isdigit():
            similarity = int(status_raw[1:])

        if status_code in {"R", "C"} and index + 2 < len(tokens):
            old_path = tokens[index + 1]
            new_path = tokens[index + 2]
            entries.append(
                DiffEntry(
                    status=status_code,
                    path=new_path,
                    old_path=old_path,
                    similarity=similarity,
                )
            )
            index += 3
            continue

        if index + 1 < len(tokens):
            path = tokens[index + 1]
            entries.append(DiffEntry(status=status_code, path=path, similarity=similarity))
            index += 2
            continue

        break

    return entries


def _append_unique(container: list[str], seen: set[str], path: str) -> None:
    if path and path not in seen:
        seen.add(path)
        container.append(path)


def _classify_diff_entries(entries: list[DiffEntry]) -> dict[str, Any]:
    added_files: list[str] = []
    modified_files: list[str] = []
    deleted_files: list[str] = []
    renamed_files: list[dict[str, Any]] = []
    analyzable_files: list[str] = []
    analyzable_seen: set[str] = set()
    modified_seen: set[str] = set()

    for entry in entries:
        path = entry.path
        if not path:
            continue

        if entry.status == "D":
            deleted_files.append(path)
            continue

        if entry.status == "A":
            added_files.append(path)
            _append_unique(analyzable_files, analyzable_seen, path)
            continue

        if entry.status == "M":
            _append_unique(modified_files, modified_seen, path)
            _append_unique(analyzable_files, analyzable_seen, path)
            continue

        if entry.status == "R":
            renamed_files.append(
                {
                    "old_path": entry.old_path,
                    "new_path": path,
                    "similarity": entry.similarity,
                }
            )
            _append_unique(analyzable_files, analyzable_seen, path)
            if entry.similarity is None or entry.similarity < 100:
                _append_unique(modified_files, modified_seen, path)
            continue

        if entry.status == "C":
            _append_unique(modified_files, modified_seen, path)
            _append_unique(analyzable_files, analyzable_seen, path)
            continue

        _append_unique(modified_files, modified_seen, path)
        _append_unique(analyzable_files, analyzable_seen, path)

    return {
        "added_files": added_files,
        "modified_files": modified_files,
        "deleted_files": deleted_files,
        "renamed_files": renamed_files,
        "analyzable_files": analyzable_files,
    }


def _truncate_file_list(
    files: list[str], max_files: int = _MAX_FILES_PER_SECTION
) -> tuple[list[str], bool]:
    if len(files) <= max_files:
        return files, False
    return files[:max_files], True


def build_diff_scope_instruction(scopes: list[RepoDiffScope]) -> str:
    lines = [
        "用户当前请求的是一次 Pull Request 变更审查。",
        "指令：请优先围绕下列变更文件开展分析。你可以为获取上下文而参考仓库中的其他文件"
        "（如 import、定义、调用点），但只有与这些变更直接相关的问题才应纳入报告。",
        "对于新增文件，请审阅整个文件内容。",
        "对于修改文件，请优先关注发生变更的区域。",
    ]

    for scope in scopes:
        repo_name = scope.workspace_subdir or Path(scope.source_path).name or "repository"
        lines.append("")
        lines.append(f"仓库范围：{repo_name}")
        lines.append(f"基准引用：{scope.base_ref}")
        lines.append(f"Merge base：{scope.merge_base}")

        focus_files, focus_truncated = _truncate_file_list(scope.analyzable_files)
        scope.truncated_sections["analyzable_files"] = focus_truncated
        if focus_files:
            lines.append("主要关注（需要分析的变更文件）：")
            lines.extend(f"- {path}" for path in focus_files)
            if focus_truncated:
                lines.append(f"- ...（还有 {len(scope.analyzable_files) - len(focus_files)} 个文件）")
        else:
            lines.append("主要关注：未检测到可分析的变更文件。")

        added_files, added_truncated = _truncate_file_list(scope.added_files)
        scope.truncated_sections["added_files"] = added_truncated
        if added_files:
            lines.append("新增文件（请审阅整个文件）：")
            lines.extend(f"- {path}" for path in added_files)
            if added_truncated:
                lines.append(f"- ...（还有 {len(scope.added_files) - len(added_files)} 个文件）")

        modified_files, modified_truncated = _truncate_file_list(scope.modified_files)
        scope.truncated_sections["modified_files"] = modified_truncated
        if modified_files:
            lines.append("修改文件（请重点关注变更区域）：")
            lines.extend(f"- {path}" for path in modified_files)
            if modified_truncated:
                lines.append(f"- ...（还有 {len(scope.modified_files) - len(modified_files)} 个文件）")

        if scope.renamed_files:
            rename_lines = []
            for rename in scope.renamed_files:
                old_path = rename.get("old_path") or "unknown"
                new_path = rename.get("new_path") or "unknown"
                similarity = rename.get("similarity")
                if isinstance(similarity, int):
                    rename_lines.append(f"- {old_path} -> {new_path}（相似度 {similarity}%）")
                else:
                    rename_lines.append(f"- {old_path} -> {new_path}")
            lines.append("重命名文件：")
            lines.extend(rename_lines)

        deleted_files, deleted_truncated = _truncate_file_list(scope.deleted_files)
        scope.truncated_sections["deleted_files"] = deleted_truncated
        if deleted_files:
            lines.append("注意：以下文件已删除（仅供上下文参考，不作为分析对象）：")
            lines.extend(f"- {path}" for path in deleted_files)
            if deleted_truncated:
                lines.append(f"- ...（还有 {len(scope.deleted_files) - len(deleted_files)} 个文件）")

    return "\n".join(lines).strip()


def _should_activate_auto_scope(
    local_sources: list[dict[str, str]], non_interactive: bool, env: dict[str, str]
) -> bool:
    if not local_sources:
        return False
    if not non_interactive:
        return False
    if not _is_ci_environment(env):
        return False
    if _is_pr_environment(env):
        return True

    for source in local_sources:
        source_path = source.get("source_path")
        if not source_path:
            continue
        repo_path = Path(source_path)
        if not _is_git_repo(repo_path):
            continue
        current_branch = _get_current_branch_name(repo_path)
        default_branch = _resolve_default_branch_name(repo_path, env)
        if current_branch and default_branch and current_branch != default_branch:
            return True
    return False


def _resolve_repo_diff_scope(
    source: dict[str, str], diff_base: str | None, env: dict[str, str]
) -> RepoDiffScope:
    source_path = source.get("source_path", "")
    workspace_subdir = source.get("workspace_subdir")
    repo_path = Path(source_path)

    if not _is_git_repo(repo_path):
        raise ValueError(f"源码路径不是 Git 仓库：{source_path}")

    if _is_repo_shallow(repo_path):
        raise ValueError(
            "diff-scope 需要完整 Git 历史。请在 CI 配置中设置 `fetch-depth: 0`。"
        )

    base_ref = _resolve_base_ref(repo_path, diff_base, env)
    merge_base_result = _run_git_command(repo_path, ["merge-base", base_ref, "HEAD"], check=False)
    if merge_base_result.returncode != 0:
        stderr = merge_base_result.stderr.strip()
        raise ValueError(
            f"无法为 '{source_path}' 与 '{base_ref}' 计算 merge-base。"
            f"{stderr or '请确认已拉取并可访问基准分支历史。'}"
        )

    merge_base = merge_base_result.stdout.strip()
    if not merge_base:
        raise ValueError(
            f"无法为 '{source_path}' 与 '{base_ref}' 计算 merge-base。"
            "请确认已拉取并可访问基准分支历史。"
        )

    diff_result = _run_git_command_raw(
        repo_path,
        [
            "diff",
            "--name-status",
            "-z",
            "--find-renames",
            "--find-copies",
            f"{merge_base}...HEAD",
        ],
        check=False,
    )
    if diff_result.returncode != 0:
        stderr = diff_result.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(
            f"无法解析 '{source_path}' 的变更文件。"
            f"{stderr or '请确认仓库具有足够历史以支持 diff-scope。'}"
        )

    entries = _parse_name_status_z(diff_result.stdout)
    classified = _classify_diff_entries(entries)

    return RepoDiffScope(
        source_path=source_path,
        workspace_subdir=workspace_subdir,
        base_ref=base_ref,
        merge_base=merge_base,
        added_files=classified["added_files"],
        modified_files=classified["modified_files"],
        renamed_files=classified["renamed_files"],
        deleted_files=classified["deleted_files"],
        analyzable_files=classified["analyzable_files"],
    )


def resolve_diff_scope_context(
    local_sources: list[dict[str, str]],
    scope_mode: str,
    diff_base: str | None,
    non_interactive: bool,
    env: dict[str, str] | None = None,
) -> DiffScopeResult:
    if scope_mode not in _SUPPORTED_SCOPE_MODES:
        raise ValueError(f"不支持的 scope mode：{scope_mode}")

    env_map = dict(os.environ if env is None else env)

    if scope_mode == "full":
        return DiffScopeResult(
            active=False,
            mode=scope_mode,
            metadata={"active": False, "mode": scope_mode},
        )

    if scope_mode == "auto":
        should_activate = _should_activate_auto_scope(local_sources, non_interactive, env_map)
        if not should_activate:
            return DiffScopeResult(
                active=False,
                mode=scope_mode,
                metadata={"active": False, "mode": scope_mode},
            )

    if not local_sources:
        raise ValueError("当前已启用 diff-scope，但没有提供本地仓库目标。")

    repo_scopes: list[RepoDiffScope] = []
    skipped_non_git: list[str] = []
    skipped_diff_scope: list[str] = []
    for source in local_sources:
        source_path = source.get("source_path")
        if not source_path:
            continue
        if not _is_git_repo(Path(source_path)):
            skipped_non_git.append(source_path)
            continue
        try:
            repo_scopes.append(_resolve_repo_diff_scope(source, diff_base, env_map))
        except ValueError as e:
            if scope_mode == "auto":
                skipped_diff_scope.append(f"{source_path} (diff-scope skipped: {e})")
                continue
            raise

    if not repo_scopes:
        if scope_mode == "auto":
            metadata: dict[str, Any] = {"active": False, "mode": scope_mode}
            if skipped_non_git:
                metadata["skipped_non_git_sources"] = skipped_non_git
            if skipped_diff_scope:
                metadata["skipped_diff_scope_sources"] = skipped_diff_scope
            return DiffScopeResult(active=False, mode=scope_mode, metadata=metadata)

        raise ValueError(
            "当前已启用 diff-scope，但没有发现 Git 仓库。"
            "如需关闭本次 diff-scope，请使用 --scope-mode full。"
        )

    instruction_block = build_diff_scope_instruction(repo_scopes)
    metadata = {
        "active": True,
        "mode": scope_mode,
        "repos": [scope.to_metadata() for scope in repo_scopes],
        "total_repositories": len(repo_scopes),
        "total_analyzable_files": sum(len(scope.analyzable_files) for scope in repo_scopes),
        "total_deleted_files": sum(len(scope.deleted_files) for scope in repo_scopes),
    }
    if skipped_non_git:
        metadata["skipped_non_git_sources"] = skipped_non_git
    if skipped_diff_scope:
        metadata["skipped_diff_scope_sources"] = skipped_diff_scope

    return DiffScopeResult(
        active=True,
        mode=scope_mode,
        instruction_block=instruction_block,
        metadata=metadata,
    )


def _is_http_git_repo(url: str) -> bool:
    check_url = f"{url.rstrip('/')}/info/refs?service=git-upload-pack"
    try:
        req = Request(check_url, headers={"User-Agent": "git/strix"})  # noqa: S310
        with urlopen(req, timeout=10) as resp:  # noqa: S310  # nosec B310
            return "x-git-upload-pack-advertisement" in resp.headers.get("Content-Type", "")
    except HTTPError as e:
        return e.code == 401
    except (URLError, OSError, ValueError):
        return False


def infer_target_type(target: str) -> tuple[str, dict[str, str]]:  # noqa: PLR0911
    if not target or not isinstance(target, str):
        raise ValueError("目标必须是非空字符串")

    target = target.strip()

    if target.startswith("git@"):
        return "repository", {"target_repo": target}

    if target.startswith("git://"):
        return "repository", {"target_repo": target}

    parsed = urlparse(target)
    if parsed.scheme in ("http", "https"):
        if parsed.username or parsed.password:
            return "repository", {"target_repo": target}
        if parsed.path.rstrip("/").endswith(".git"):
            return "repository", {"target_repo": target}
        if parsed.query or parsed.fragment:
            return "web_application", {"target_url": target}
        path_segments = [s for s in parsed.path.split("/") if s]
        if len(path_segments) >= 2 and _is_http_git_repo(target):
            return "repository", {"target_repo": target}
        return "web_application", {"target_url": target}

    try:
        ip_obj = ipaddress.ip_address(target)
    except ValueError:
        pass
    else:
        return "ip_address", {"target_ip": str(ip_obj)}

    path = Path(target).expanduser()
    try:
        if path.exists():
            if path.is_dir():
                return "local_code", {"target_path": str(path.resolve())}
            raise ValueError(f"路径存在但不是目录：{target}")
    except (OSError, RuntimeError) as e:
        raise ValueError(f"无效路径：{target} - {e!s}") from e

    if target.endswith(".git"):
        return "repository", {"target_repo": target}

    if "/" in target:
        host_part, _, path_part = target.partition("/")
        if "." in host_part and not host_part.startswith(".") and path_part:
            full_url = f"https://{target}"
            if _is_http_git_repo(full_url):
                return "repository", {"target_repo": full_url}
            return "web_application", {"target_url": full_url}

    if "." in target and "/" not in target and not target.startswith("."):
        parts = target.split(".")
        if len(parts) >= 2 and all(p and p.strip() for p in parts):
            return "web_application", {"target_url": f"https://{target}"}

    raise ValueError(
        f"无效目标：{target}\n"
        "目标必须符合以下任一形式：\n"
        "- 合法 URL（http:// 或 https://）\n"
        "- Git 仓库 URL（https://host/org/repo 或 git@host:org/repo.git）\n"
        "- 本地目录路径\n"
        "- 域名（如 example.com）\n"
        "- IP 地址（如 192.168.1.10）"
    )


def read_target_list_file(path_str: str) -> list[str]:
    """Read scan targets from a file, one target per non-empty, non-comment line."""
    if not path_str or not path_str.strip():
        raise ValueError("--target-list 路径不能为空。")

    path = Path(path_str).expanduser()
    if not path.is_file():
        raise ValueError(f"目标列表文件 '{path_str}' 不存在。")

    try:
        targets = [
            target
            for line in path.read_text(encoding="utf-8").splitlines()
            if (target := line.strip()) and not target.startswith("#")
        ]
    except UnicodeDecodeError as e:
        raise ValueError(f"目标列表文件 '{path_str}' 必须是有效的 UTF-8 文本：{e!s}") from e
    except OSError as e:
        raise ValueError(f"读取目标列表文件 '{path_str}' 失败：{e!s}") from e

    targets = [target for target in targets if target]
    if not targets:
        raise ValueError(f"目标列表文件 '{path_str}' 为空。")
    return targets


def sanitize_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9._-]", "-", name.strip())
    return sanitized or "target"


def derive_repo_base_name(repo_url: str) -> str:
    if repo_url.endswith("/"):
        repo_url = repo_url[:-1]

    if ":" in repo_url and repo_url.startswith("git@"):
        path_part = repo_url.split(":", 1)[1]
    else:
        path_part = urlparse(repo_url).path or repo_url

    candidate = path_part.split("/")[-1]
    if candidate.endswith(".git"):
        candidate = candidate[:-4]

    return sanitize_name(candidate or "repository")


def derive_local_base_name(path_str: str) -> str:
    try:
        base = Path(path_str).resolve().name
    except (OSError, RuntimeError):
        base = Path(path_str).name
    return sanitize_name(base or "workspace")


def assign_workspace_subdirs(targets_info: list[dict[str, Any]]) -> None:
    name_counts: dict[str, int] = {}

    for target in targets_info:
        target_type = target["type"]
        details = target["details"]

        base_name: str | None = None
        if target_type == "repository":
            base_name = derive_repo_base_name(details["target_repo"])
        elif target_type == "local_code":
            base_name = derive_local_base_name(details.get("target_path", "local"))

        if base_name is None:
            continue

        count = name_counts.get(base_name, 0) + 1
        name_counts[base_name] = count

        workspace_subdir = base_name if count == 1 else f"{base_name}-{count}"

        details["workspace_subdir"] = workspace_subdir


def is_whitebox_scan(targets_info: list[dict[str, Any]]) -> bool:
    """True iff any target is a local source tree (whitebox / source-aware)."""
    return any(t.get("type") == "local_code" for t in targets_info or [])


def collect_local_sources(targets_info: list[dict[str, Any]]) -> list[dict[str, Any]]:
    local_sources: list[dict[str, Any]] = []

    for target_info in targets_info:
        details = target_info["details"]
        workspace_subdir = details.get("workspace_subdir")

        if target_info["type"] == "local_code" and "target_path" in details:
            local_sources.append(
                {
                    "source_path": details["target_path"],
                    "workspace_subdir": workspace_subdir,
                    "mount": bool(details.get("mount", False)),
                }
            )

        elif target_info["type"] == "repository" and "cloned_repo_path" in details:
            local_sources.append(
                {
                    "source_path": details["cloned_repo_path"],
                    "workspace_subdir": workspace_subdir,
                    "mount": False,
                }
            )

    return local_sources


def directory_size_bytes(path: Path) -> int:
    """Total size in bytes of regular files under ``path`` (symlinks not followed).

    Best-effort: files that disappear or can't be stat'd mid-walk are skipped.
    Used as a cheap (stat-only) pre-flight to estimate the cost of streaming a
    local target into the sandbox before we actually try to copy it.

    Directories that can't be listed (e.g. permission denied) are logged and
    skipped rather than silently dropped — so an under-count is at least
    visible — but the returned total then excludes their contents.
    """

    def _on_walk_error(error: OSError) -> None:
        logger.warning("Could not read %s while measuring size: %s", error.filename, error)

    total = 0
    for root, _dirs, files in os.walk(path, followlinks=False, onerror=_on_walk_error):
        for name in files:
            file_path = os.path.join(root, name)  # noqa: PTH118
            try:
                if os.path.islink(file_path):  # noqa: PTH114
                    continue
                total += os.path.getsize(file_path)  # noqa: PTH202
            except OSError:
                continue
    return total


def find_oversized_local_targets(
    targets_info: list[dict[str, Any]], max_bytes: int
) -> list[tuple[str, int]]:
    """Return ``(path, size_bytes)`` for non-mounted local targets over ``max_bytes``.

    Mounted targets are bind-mounted rather than copied, so their size is
    irrelevant and they are excluded. A ``max_bytes`` of zero or less disables
    the check entirely (returns no targets).
    """
    if max_bytes <= 0:
        return []
    oversized: list[tuple[str, int]] = []
    for target in targets_info:
        if target.get("type") != "local_code":
            continue
        details = target.get("details") or {}
        if details.get("mount"):
            continue
        target_path = details.get("target_path")
        if not target_path:
            continue
        size = directory_size_bytes(Path(target_path))
        if size > max_bytes:
            oversized.append((target_path, size))
    return oversized


def build_mount_targets_info(mount_paths: list[str]) -> list[dict[str, Any]]:
    """Build ``targets_info`` entries for ``--mount`` directories.

    Each path must be an existing local directory; it is bind-mounted into the
    sandbox (read-only) instead of being copied file-by-file. Raises
    ``ValueError`` for an empty path, or one that does not exist or is not a
    directory.
    """
    targets_info: list[dict[str, Any]] = []
    for raw in mount_paths:
        if not raw or not raw.strip():
            raise ValueError("--mount 路径不能为空。")
        path = Path(raw).expanduser()
        try:
            resolved = path.resolve()
            is_dir = resolved.is_dir()
        except (OSError, RuntimeError) as e:
            raise ValueError(f"无效的挂载路径 '{raw}'：{e!s}") from e
        if not is_dir:
            raise ValueError(
                f"挂载路径 '{raw}' 不是现有目录。"
                "--mount 只能接收本地目录路径。"
            )
        targets_info.append(
            {
                "type": "local_code",
                "details": {"target_path": str(resolved), "mount": True},
                "original": str(resolved),
            }
        )
    return targets_info


def dedupe_local_targets(targets_info: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Collapse local_code targets that resolve to the same path.

    When a directory is supplied both as a copied ``--target`` and via
    ``--mount`` (or as duplicate values of either), keep one entry and prefer
    the bind-mounted one — so the same tree is never both streamed in and
    mounted. Order is preserved; non-local targets pass through untouched.
    """
    result: list[dict[str, Any]] = []
    index_by_path: dict[str, int] = {}
    for target in targets_info:
        details = target.get("details") or {}
        path = details.get("target_path")
        if target.get("type") != "local_code" or not path:
            result.append(target)
            continue
        existing = index_by_path.get(path)
        if existing is None:
            index_by_path[path] = len(result)
            result.append(target)
        elif details.get("mount") and not (result[existing].get("details") or {}).get("mount"):
            result[existing] = target  # bind mount supersedes the copied entry
    return result


def _is_localhost_host(host: str) -> bool:
    host_lower = host.lower().strip("[]")

    if host_lower in ("localhost", "0.0.0.0", "::1"):  # nosec B104
        return True

    try:
        ip = ipaddress.ip_address(host_lower)
        if isinstance(ip, ipaddress.IPv4Address):
            return ip.is_loopback  # 127.0.0.0/8
        if isinstance(ip, ipaddress.IPv6Address):
            return ip.is_loopback  # ::1
    except ValueError:
        pass

    return False


def rewrite_localhost_targets(targets_info: list[dict[str, Any]], host_gateway: str) -> None:
    from yarl import URL

    for target_info in targets_info:
        target_type = target_info.get("type")
        details = target_info.get("details", {})

        if target_type == "web_application":
            target_url = details.get("target_url", "")
            try:
                url = URL(target_url)
            except (ValueError, TypeError):
                continue

            if url.host and _is_localhost_host(url.host):
                details["target_url"] = str(url.with_host(host_gateway))

        elif target_type == "ip_address":
            target_ip = details.get("target_ip", "")
            if target_ip and _is_localhost_host(target_ip):
                details["target_ip"] = host_gateway


def clone_repository(repo_url: str, run_name: str, dest_name: str | None = None) -> str:
    console = Console()

    git_executable = shutil.which("git")
    if git_executable is None:
        raise FileNotFoundError("Git executable not found in PATH")

    temp_dir = Path(tempfile.gettempdir()) / "strix_repos" / run_name
    temp_dir.mkdir(parents=True, exist_ok=True)

    if dest_name:
        repo_name = dest_name
    else:
        repo_name = Path(repo_url).stem if repo_url.endswith(".git") else Path(repo_url).name

    clone_path = temp_dir / repo_name

    if clone_path.exists():
        shutil.rmtree(clone_path)

    try:
        with console.status(f"[bold cyan]正在克隆仓库 {repo_url}...", spinner="dots"):
            subprocess.run(  # noqa: S603
                [
                    git_executable,
                    "clone",
                    repo_url,
                    str(clone_path),
                ],
                capture_output=True,
                text=True,
                check=True,
            )

        return str(clone_path.absolute())

    except subprocess.CalledProcessError as e:
        error_text = Text()
        error_text.append("仓库克隆失败", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append(f"无法克隆仓库：{repo_url}\n", style="white")
        error_text.append(
            f"错误：{e.stderr if hasattr(e, 'stderr') and e.stderr else str(e)}",
            style="dim red",
        )

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
    except FileNotFoundError:
        error_text = Text()
        error_text.append("未找到 Git", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("当前环境未安装 Git，或 Git 不在 PATH 中。\n", style="white")
        error_text.append("请先安装 Git 后再克隆仓库。\n", style="white")

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


def check_docker_connection() -> Any:
    try:
        return docker.from_env()
    except DockerException:
        console = Console()
        error_text = Text()
        error_text.append("Docker 不可用", style="bold red")
        error_text.append("\n\n", style="white")
        error_text.append("无法连接到 Docker daemon。\n", style="white")
        error_text.append(
            "请确认 Docker Desktop 已安装并正在运行，然后重新执行 strix。\n",
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
        raise RuntimeError("Docker not available") from None


def image_exists(client: Any, image_name: str) -> bool:
    try:
        client.images.get(image_name)
    except ImageNotFound:
            return False
    else:
        return True


def update_layer_status(layers_info: dict[str, str], layer_id: str, layer_status: str) -> None:
    if "Pull complete" in layer_status or "Already exists" in layer_status:
        layers_info[layer_id] = "✓"
    elif "Downloading" in layer_status:
        layers_info[layer_id] = "↓"
    elif "Extracting" in layer_status:
        layers_info[layer_id] = "📦"
    elif "Waiting" in layer_status:
        layers_info[layer_id] = "⏳"
    else:
        layers_info[layer_id] = "•"


def process_pull_line(
    line: dict[str, Any], layers_info: dict[str, str], status: Any, last_update: str
) -> str:
    if "id" in line and "status" in line:
        layer_id = line["id"]
        update_layer_status(layers_info, layer_id, line["status"])

        completed = sum(1 for v in layers_info.values() if v == "✓")
        total = len(layers_info)

        if total > 0:
            update_msg = f"[bold cyan]进度：{completed}/{total} 层已完成"
            if update_msg != last_update:
                status.update(update_msg)
                return update_msg

    elif "status" in line and "id" not in line:
        global_status = line["status"]
        if "Pulling from" in global_status:
            status.update("[bold cyan]正在获取镜像清单...")
        elif "Digest:" in global_status:
            status.update("[bold cyan]正在校验镜像...")
        elif "Status:" in global_status:
            status.update("[bold cyan]正在收尾...")

    return last_update


def validate_config_file(config_path: str) -> Path:
    console = Console()
    path = Path(config_path)

    if not path.exists():
        console.print(f"[bold red]错误：[/]未找到配置文件：{config_path}")
        sys.exit(1)

    if path.suffix != ".json":
        console.print("[bold red]错误：[/]配置文件必须是 `.json` 文件")
        sys.exit(1)

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]错误：[/]配置文件中的 JSON 无效：{e}")
        sys.exit(1)

    if not isinstance(data, dict):
        console.print("[bold red]错误：[/]配置文件内容必须是 JSON 对象")
        sys.exit(1)

    if "env" not in data or not isinstance(data.get("env"), dict):
        console.print("[bold red]错误：[/]配置文件必须包含 `env` 对象")
        sys.exit(1)

    return path
