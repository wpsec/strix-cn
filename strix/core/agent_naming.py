"""Helpers for keeping specialist agent names user-facing and localized."""

from __future__ import annotations

import re


_DEFAULT_AGENT_NAME = "专家代理"
_ROLE_SUFFIXES = (
    "验证专家",
    "测试专家",
    "分析专家",
    "研究专家",
    "审计专家",
    "调查专家",
    "排查专家",
    "专家",
    "助手",
    "代理",
)
_PHRASE_REPLACEMENTS = (
    ("sql injection", "SQL注入"),
    ("command injection", "命令注入"),
    ("path traversal", "路径穿越"),
    ("file upload", "文件上传"),
    ("file read", "文件读取"),
    ("file inclusion", "文件包含"),
    ("source code", "源码"),
    ("code review", "代码审计"),
    ("auth bypass", "鉴权绕过"),
    ("access control", "访问控制"),
    ("race condition", "竞态条件"),
    ("prototype pollution", "原型污染"),
)
_WORD_REPLACEMENTS = (
    ("sqli", "SQL注入"),
    ("xss", "XSS"),
    ("ssrf", "SSRF"),
    ("csrf", "CSRF"),
    ("xxe", "XXE"),
    ("idor", "越权"),
    ("jwt", "JWT"),
    ("cors", "CORS"),
    ("rce", "RCE"),
    ("lfi", "文件读取"),
    ("rfi", "远程文件包含"),
    ("auth", "鉴权"),
    ("oauth", "OAuth"),
    ("login", "登录"),
    ("session", "会话"),
    ("api", "API"),
    ("proxy", "代理"),
    ("recon", "侦察"),
    ("review", "审计"),
    ("audit", "审计"),
    ("source", "源码"),
    ("code", "代码"),
    ("flow", "流程"),
    ("specialist", "专家"),
    ("expert", "专家"),
    ("validator", "验证专家"),
    ("tester", "测试专家"),
    ("analyst", "分析专家"),
    ("researcher", "研究专家"),
    ("reviewer", "审计专家"),
    ("investigator", "调查专家"),
    ("hunter", "排查专家"),
    ("assistant", "助手"),
    ("agent", "代理"),
)


def _contains_cjk(text: str) -> bool:
    return any("\u4e00" <= char <= "\u9fff" for char in text)


def normalize_agent_name(name: str | None) -> str:
    cleaned = re.sub(r"\s+", " ", str(name or "").strip())
    if not cleaned:
        return _DEFAULT_AGENT_NAME

    normalized = cleaned.replace("_", " ").replace("-", " ")
    for source, target in _PHRASE_REPLACEMENTS:
        normalized = re.sub(rf"(?i)\b{re.escape(source)}\b", target, normalized)
    for source, target in _WORD_REPLACEMENTS:
        normalized = re.sub(rf"(?i)\b{re.escape(source)}\b", target, normalized)

    normalized = re.sub(r"\s+", " ", normalized).strip()
    for suffix in _ROLE_SUFFIXES:
        normalized = normalized.replace(f" {suffix}", suffix)
    normalized = re.sub(r"(专家|代理|助手){2,}", r"\1", normalized)
    normalized = re.sub(r"(验证专家|测试专家|分析专家|研究专家|审计专家|调查专家|排查专家)专家", r"\1", normalized)
    normalized = normalized.strip()
    if not normalized:
        return _DEFAULT_AGENT_NAME

    if _contains_cjk(normalized):
        return normalized

    if any(normalized.endswith(suffix) for suffix in _ROLE_SUFFIXES):
        return normalized
    return f"{normalized}专家"
