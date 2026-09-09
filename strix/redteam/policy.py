"""Policy primitives for the authorized red-team validation mode.

The policy is deliberately fail-closed for red-team runs.  A missing or
unrecognised vulnerability type cannot authorize a network action, and a
privilege-impact claim must carry an explicit impact description.
"""

from __future__ import annotations

import re
from typing import Literal


SecurityMode = Literal["normal", "redteam", "verify"]

NORMAL_MODE: SecurityMode = "normal"
REDTEAM_MODE: SecurityMode = "redteam"
VERIFY_MODE: SecurityMode = "verify"
POLICY_VERSION = "redteam-v3"

_PRIVILEGE_IMPACT_MARKERS = (
    "未授权身份",
    "权限提升",
    "权限边界",
    "提权",
    "unauthorized identity",
    "privilege escalation",
    "privilege acquisition",
    "authorization bypass",
    "whoami",
    "id command",
)
_SPECULATIVE_IMPACT_MARKERS = (
    "可能",
    "推测",
    "猜测",
    "potential",
    "possibly",
    "suspected",
    "could be",
)
_ACCESS_IMPACT_MARKERS = (
    "未授权访问",
    "未授权读取",
    "未授权写入",
    "未授权业务操作",
    "越权",
    "对象级授权",
    "unauthorized access",
    "unauthorized read",
    "unauthorized write",
    "unauthorized business action",
    "admin access",
    "authenticated session",
    "获取管理员权限",
)
_CREDENTIAL_OBSERVATION_MARKERS = (
    "password",
    "token",
    "api key",
    "apikey",
    "secret",
    "凭据",
    "口令",
    "密钥",
)

_TYPE_ALIASES: dict[str, str] = {
    "rce": "rce",
    "remote code execution": "rce",
    "远程代码执行": "rce",
    "command injection": "rce",
    "os command injection": "rce",
    "可写文件上传": "writable_file_upload",
    "文件上传": "writable_file_upload",
    "unrestricted file upload": "writable_file_upload",
    "file upload": "writable_file_upload",
    "writable file upload": "writable_file_upload",
    "stacked sql injection": "stacked_query_sqli",
    "stacked query sql injection": "stacked_query_sqli",
    "stacked query sqli": "stacked_query_sqli",
    "堆叠查询 sql 注入": "stacked_query_sqli",
    "堆叠查询sql注入": "stacked_query_sqli",
    "deserialization": "deserialization",
    "反序列化": "deserialization",
    "ssrf": "ssrf_metadata",
    "ssrf metadata": "ssrf_metadata",
    "metadata ssrf": "ssrf_metadata",
    "ssrf 元数据": "ssrf_metadata",
    "可窃取元数据的ssrf": "ssrf_metadata",
    "可窃取元数据的 ssrf": "ssrf_metadata",
    "metadata capable ssrf": "ssrf_metadata",
    "authentication bypass": "authentication_bypass",
    "认证绕过": "authentication_bypass",
    "authorization bypass": "authorization_bypass",
    "access control bypass": "authorization_bypass",
    "越权": "authorization_bypass",
    "未授权访问": "authorization_bypass",
    "idor": "idor_bola",
    "bola": "idor_bola",
    "idor bola": "idor_bola",
    "broken object level authorization": "idor_bola",
    "对象级授权": "idor_bola",
    "object level authorization": "idor_bola",
    "exposed admin function": "exposed_admin_function",
    "admin function exposure": "exposed_admin_function",
    "管理功能暴露": "exposed_admin_function",
    "cloud storage unauthorized access": "cloud_storage_unauthorized_access",
    "bucket unauthorized access": "cloud_storage_unauthorized_access",
    "云存储未授权访问": "cloud_storage_unauthorized_access",
    "存储桶未授权访问": "cloud_storage_unauthorized_access",
    "对象存储未授权访问": "cloud_storage_unauthorized_access",
    "cloud storage writable": "cloud_storage_writable",
    "writable bucket": "cloud_storage_writable",
    "云存储可写": "cloud_storage_writable",
    "存储桶可写": "cloud_storage_writable",
    "business logic unauthorized action": "business_logic_unauthorized_action",
    "高影响业务逻辑": "business_logic_unauthorized_action",
    "未授权业务操作": "business_logic_unauthorized_action",
    "credential exposure observed": "credential_exposure_observed",
    "credential material exposure": "credential_exposure_observed",
    "凭据材料可访问": "credential_exposure_observed",
    "凭据暴露": "credential_exposure_observed",
    "privilege acquisition": "privilege_acquisition",
    "privilege escalation": "privilege_acquisition",
    "unauthorized access": "authorization_bypass",
    "privilege acquisition vulnerability": "privilege_acquisition",
    "权限获取": "privilege_acquisition",
    "可获取到权限的漏洞": "privilege_acquisition",
    "可获取权限": "privilege_acquisition",
    "权限提升": "privilege_acquisition",
}

_BLACKLISTED_TYPES = frozenset(
    {
        "xss",
        "dom_xss",
        "reflected_xss",
        "stored_xss",
        "csrf",
        "clickjacking",
        "weak_tls",
        "tls_weakness",
        "sensitive_information_disclosure",
        "path_traversal",
        "missing_security_headers",
    }
)

_BLACKLIST_ALIASES: dict[str, str] = {
    "xss": "xss",
    "dom xss": "dom_xss",
    "dom-based xss": "dom_xss",
    "dom型xss": "dom_xss",
    "xss dom": "dom_xss",
    "reflected xss": "reflected_xss",
    "反射型 xss": "reflected_xss",
    "反射型xss": "reflected_xss",
    "stored xss": "stored_xss",
    "xss stored": "stored_xss",
    "存储型 xss": "stored_xss",
    "存储型xss": "stored_xss",
    "csrf": "csrf",
    "clickjacking": "clickjacking",
    "点击劫持": "clickjacking",
    "weak tls": "weak_tls",
    "ssl/tls 弱加密": "weak_tls",
    "ssl/tls弱加密": "weak_tls",
    "ssl tls weak encryption": "weak_tls",
    "weak ssl tls encryption": "weak_tls",
    "tls weakness": "tls_weakness",
    "path traversal": "path_traversal",
    "路径遍历": "path_traversal",
    "sensitive information disclosure": "sensitive_information_disclosure",
    "sensitive data exposure": "sensitive_information_disclosure",
    "information disclosure": "sensitive_information_disclosure",
    "sensitive information leak": "sensitive_information_disclosure",
    "敏感信息泄露": "sensitive_information_disclosure",
    "missing security headers": "missing_security_headers",
    "缺少安全头": "missing_security_headers",
    "missing security header": "missing_security_headers",
}


def normalize_mode(value: object) -> SecurityMode:
    """Normalize a configured security mode or reject an invalid value."""
    mode = str(value or NORMAL_MODE).strip().lower()
    if mode not in {NORMAL_MODE, REDTEAM_MODE, VERIFY_MODE}:
        raise ValueError("mode 必须是 normal、redteam 或 verify")
    return mode


def _normalize_label(value: object) -> str:
    text = str(value or "").strip().lower()
    text = re.sub(r"[\s/_:-]+", " ", text)
    return text


def normalize_vulnerability_type(value: object) -> str | None:
    """Return a canonical type, a canonical blacklist type, or ``None``."""
    normalized = _normalize_label(value)
    if not normalized:
        return None
    if normalized in _BLACKLIST_ALIASES:
        return _BLACKLIST_ALIASES[normalized]
    if normalized in _TYPE_ALIASES:
        return _TYPE_ALIASES[normalized]
    compact = normalized.replace(" ", "")
    if "xss" in compact:
        if "dom" in compact or "dom型" in compact:
            return "dom_xss"
        if "reflect" in compact or "反射" in compact:
            return "reflected_xss"
        if "stor" in compact or "存储" in compact:
            return "stored_xss"
        return "xss"
    if compact in {"domxss", "dom型xss"}:
        return "dom_xss"
    if compact in {"reflectedxss", "反射型xss"}:
        return "reflected_xss"
    if compact in {"storedxss", "存储型xss"}:
        return "stored_xss"
    if compact in {"pathtraversal", "路径遍历"}:
        return "path_traversal"
    if compact in {"csrf"} or "跨站请求伪造" in compact:
        return "csrf"
    if compact in {"clickjacking", "点击劫持"} or "frame" in compact:
        return "clickjacking"
    if "tls" in compact or "ssl" in compact:
        return "weak_tls"
    if "header" in compact and ("security" in compact or "安全" in compact):
        return "missing_security_headers"
    if "traversal" in compact or "路径遍历" in compact:
        return "path_traversal"
    if "disclosure" in compact or "泄露" in compact or "泄漏" in compact:
        return "sensitive_information_disclosure"
    return None


def has_verified_privilege_impact(impact: object) -> bool:
    """Whether a report describes a concrete identity or privilege result."""
    text = str(impact or "").strip().lower()
    return (
        bool(text)
        and not any(marker in text for marker in _SPECULATIVE_IMPACT_MARKERS)
        and any(marker in text for marker in _PRIVILEGE_IMPACT_MARKERS)
    )


def has_verified_access_impact(impact: object) -> bool:
    """Whether access-control or resource-access impact is concretely shown."""
    text = str(impact or "").strip().lower()
    return (
        bool(text)
        and not any(marker in text for marker in _SPECULATIVE_IMPACT_MARKERS)
        and any(marker in text for marker in _ACCESS_IMPACT_MARKERS)
    )


def has_credential_observation(impact: object) -> bool:
    """Whether the impact describes an observed credential material access."""
    text = str(impact or "").strip().lower()
    return bool(text) and not any(marker in text for marker in _SPECULATIVE_IMPACT_MARKERS) and any(
        marker in text for marker in _CREDENTIAL_OBSERVATION_MARKERS
    )


def should_ignore(
    vuln_type: str,
    *,
    mode: SecurityMode = NORMAL_MODE,
    impact: str | None = None,
) -> bool:
    """Return whether a test intent or finding must be discarded.

    Normal mode retains existing behaviour.  Red-team mode permits only known
    allowlisted types; unknown types and privilege claims without a concrete
    impact proof are rejected.
    """
    resolved_mode = normalize_mode(mode)
    if resolved_mode in {NORMAL_MODE, VERIFY_MODE}:
        return False

    normalized = normalize_vulnerability_type(vuln_type)
    if normalized is None or normalized in _BLACKLISTED_TYPES:
        return True
    if normalized == "privilege_acquisition" and not has_verified_privilege_impact(impact):
        return True
    if normalized in {
        "authentication_bypass",
        "authorization_bypass",
        "idor_bola",
        "exposed_admin_function",
        "cloud_storage_unauthorized_access",
        "cloud_storage_writable",
        "business_logic_unauthorized_action",
    } and not has_verified_access_impact(impact):
        return True
    if normalized == "credential_exposure_observed" and not has_credential_observation(impact):
        return True
    return normalized not in {
        "rce",
        "writable_file_upload",
        "stacked_query_sqli",
        "deserialization",
        "ssrf_metadata",
        "privilege_acquisition",
        "authentication_bypass",
        "authorization_bypass",
        "idor_bola",
        "exposed_admin_function",
        "cloud_storage_unauthorized_access",
        "cloud_storage_writable",
        "business_logic_unauthorized_action",
        "credential_exposure_observed",
    }


def policy_context(mode: SecurityMode) -> dict[str, object]:
    """Return non-secret prompt/context metadata for a scan."""
    resolved_mode = normalize_mode(mode)
    return {
        "security_mode": resolved_mode,
        "redteam_policy_version": POLICY_VERSION if resolved_mode == REDTEAM_MODE else None,
        "redteam_fail_closed": resolved_mode == REDTEAM_MODE,
        "verification_mode": resolved_mode == VERIFY_MODE,
    }
