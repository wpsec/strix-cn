"""User-facing Strix branding helpers shared by CLI and TUI."""

from __future__ import annotations

import configparser
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as pkg_version
from pathlib import Path
from urllib.parse import urlparse


STRIX_WEBSITE = "strix.ai"
DEFAULT_PROJECT_REPOSITORY = "github.com/usestrix/strix"


def get_package_version() -> str:
    try:
        return pkg_version("strix-agent")
    except PackageNotFoundError:
        return "dev"


def _find_repo_root() -> Path | None:
    for parent in Path(__file__).resolve().parents:
        if (parent / ".git").exists():
            return parent
    return None


def _origin_remote_url() -> str | None:
    repo_root = _find_repo_root()
    if repo_root is None:
        return None
    config_path = repo_root / ".git" / "config"
    parser = configparser.ConfigParser()
    try:
        with config_path.open(encoding="utf-8") as handle:
            parser.read_file(handle)
    except (OSError, configparser.Error):
        return None
    return parser.get('remote "origin"', "url", fallback="").strip() or None


def _normalize_repository_url(url: str) -> str | None:
    normalized = url.strip()
    if not normalized:
        return None
    if normalized.startswith("git@"):
        _, _, remainder = normalized.partition("@")
        host, _, path = remainder.partition(":")
        path = path.removesuffix(".git").strip("/")
        if host and path:
            return f"{host}/{path}"
        return None
    parsed = urlparse(normalized)
    host = parsed.hostname or ""
    path = parsed.path.removesuffix(".git").strip("/")
    if host and path:
        return f"{host}/{path}"
    return None


def get_project_repository() -> str:
    origin_url = _origin_remote_url()
    if origin_url:
        normalized = _normalize_repository_url(origin_url)
        if normalized:
            return normalized
    return DEFAULT_PROJECT_REPOSITORY


def get_repository_label() -> str:
    if get_project_repository().startswith("github.com/"):
        return "GitHub"
    return "仓库"


def branding_items(
    *, include_website: bool = True, include_github: bool = True
) -> tuple[tuple[str, str], ...]:
    items: list[tuple[str, str]] = [("版本", f"v{get_package_version()}")]
    if include_website:
        items.append(("官网", STRIX_WEBSITE))
    if include_github:
        items.append((get_repository_label(), get_project_repository()))
    return tuple(items)
