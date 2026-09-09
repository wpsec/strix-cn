"""Policy primitives for the authorized red-team validation mode.

Red-team policy has two separate jobs: guide the agent toward useful tests and
protect the target from unsafe actions.  A vulnerability label is evidence
classification, not an authorization capability.  Unknown labels therefore
remain testable and reportable; only the action boundary can deny a request.
"""

from __future__ import annotations

import re
from typing import Literal


SecurityMode = Literal["normal", "redteam", "verify"]

NORMAL_MODE: SecurityMode = "normal"
REDTEAM_MODE: SecurityMode = "redteam"
VERIFY_MODE: SecurityMode = "verify"
POLICY_VERSION = "redteam-v4"

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
    "成功登录",
    "登录后台",
    "登录成功",
    "找回密码",
    "重置密码",
    "敏感数据",
    "sensitive data",
    "default credential",
    "默认凭据",
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
    "sql injection": "sqli",
    "sqli": "sqli",
    "sql 注入": "sqli",
    "sql注入": "sqli",
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
    "authentication or authorization bypass": "authentication_or_authorization_bypass",
    "认证或授权绕过": "authentication_or_authorization_bypass",
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
    "default credentials": "default_credentials",
    "默认凭据": "default_credentials",
    "session issue": "session_management",
    "session management": "session_management",
    "会话问题": "session_management",
    "file read": "file_read_write",
    "file write": "file_read_write",
    "file read write": "file_read_write",
    "文件读取": "file_read_write",
    "文件写入": "file_read_write",
    "文件读写": "file_read_write",
    "invalid certificate": "invalid_certificate",
    "certificate invalid": "invalid_certificate",
    "证书无效": "invalid_certificate",
    "banner": "banner_disclosure",
    "服务版本暴露": "banner_disclosure",
    "captcha bypass": "captcha_bypass",
    "验证码绕过": "captcha_bypass",
    "rate limit bypass": "rate_limit_bypass",
    "限流绕过": "rate_limit_bypass",
    "cors": "cors_misconfiguration",
    "跨域配置": "cors_misconfiguration",
    "open redirect": "open_redirect",
    "开放重定向": "open_redirect",
}

_LOW_PRIORITY_TYPES = frozenset(
    {
        "invalid_certificate",
        "weak_tls",
        "tls_weakness",
        "banner_disclosure",
        "missing_security_headers",
        "clickjacking",
        "xss",
        "dom_xss",
        "reflected_xss",
        "stored_xss",
    }
)

_LOW_PRIORITY_ALIASES: dict[str, str] = {
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

_CONDITIONAL_PRIORITY_TYPES = frozenset(
    {
        "captcha_bypass",
        "rate_limit_bypass",
        "cors_misconfiguration",
        "csrf",
        "open_redirect",
        "writable_file_upload",
        "path_traversal",
    }
)

_HIGH_PRIORITY_TYPES = frozenset(
    {
        "rce",
        "injection",
        "sqli",
        "stacked_query_sqli",
        "deserialization",
        "ssrf_metadata",
        "authentication_bypass",
        "authorization_bypass",
        "authentication_or_authorization_bypass",
        "idor_bola",
        "exposed_admin_function",
        "cloud_storage_unauthorized_access",
        "cloud_storage_writable",
        "business_logic_unauthorized_action",
        "credential_exposure_observed",
        "privilege_acquisition",
        "default_credentials",
        "session_management",
        "sensitive_information_disclosure",
        "file_read_write",
    }
)

_ATTACK_CHAIN_TYPES = _HIGH_PRIORITY_TYPES | _CONDITIONAL_PRIORITY_TYPES
_DESTRUCTIVE_ACTION_MARKERS = (
    "delete",
    "destroy",
    "drop",
    "purge",
    "shutdown",
    "terminate",
    "wipe",
    "删除",
    "销毁",
    "清空",
    "停机",
)


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
    """Return a canonical type or ``None`` when classification is unavailable."""
    normalized = _normalize_label(value)
    if not normalized:
        return None
    if normalized in _LOW_PRIORITY_ALIASES:
        return _LOW_PRIORITY_ALIASES[normalized]
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
    if "injection" in compact or "注入" in compact:
        return "injection"
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
    if "captcha" in compact or "验证码" in compact:
        return "captcha_bypass"
    if "rate" in compact and "limit" in compact:
        return "rate_limit_bypass"
    if "cors" in compact or "跨域" in compact:
        return "cors_misconfiguration"
    if "redirect" in compact or "重定向" in compact:
        return "open_redirect"
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


def assess_action_risk(
    method: object,
    url: object,
    *,
    mode: SecurityMode = NORMAL_MODE,
) -> dict[str, object]:
    """Apply the red-team action boundary independently of finding labels.

    Ordinary in-scope requests remain allowed even when their finding type is
    unknown.  Clearly destructive HTTP actions are denied in red-team mode;
    scope enforcement is performed by the proxy layer because it owns the
    authoritative target patterns.
    """
    resolved_mode = normalize_mode(mode)
    if resolved_mode != REDTEAM_MODE:
        return {"allowed": True, "risk": "unrestricted", "reason": "非红队专项模式"}
    method_text = str(method or "").strip().upper()
    url_text = str(url or "").strip().lower()
    is_dry_run = any(marker in url_text for marker in ("dry-run", "dry_run", "preview"))
    path_is_destructive = any(
        (
            re.search(rf"(?<![a-z]){re.escape(marker)}(?![a-z])", url_text) is not None
            if marker.isascii()
            else marker in url_text
        )
        for marker in _DESTRUCTIVE_ACTION_MARKERS
    )
    if method_text == "DELETE" or (path_is_destructive and not is_dry_run):
        return {
            "allowed": False,
            "risk": "destructive",
            "reason": "红队专项策略拒绝不可逆或明显破坏性操作；请改用 dry-run 或单个可清理测试对象",
        }
    return {
        "allowed": True,
        "risk": "bounded",
        "reason": "请求未命中破坏性动作边界，仍需通过目标作用域检查",
    }


def classify_test_priority(
    vulnerability_type: object,
    *,
    impact: str | None = None,
) -> dict[str, object]:
    """Classify testing value without authorizing or rejecting a request.

    The result is intentionally advisory.  An unknown type gets normal
    priority so the agent can still test it when the action is safe and in
    scope.  Conditional types become high priority only when their impact
    reaches authentication, authorization, or sensitive data.
    """
    normalized = normalize_vulnerability_type(vulnerability_type)
    if normalized in _LOW_PRIORITY_TYPES:
        return {
            "priority": "low",
            "reason": "效率策略：低价值配置或展示类问题，默认延后验证",
            "canonical_type": normalized,
        }
    if normalized in _CONDITIONAL_PRIORITY_TYPES:
        escalated = has_verified_access_impact(impact) or has_verified_privilege_impact(impact)
        return {
            "priority": "high" if escalated else "low",
            "reason": (
                "条件升级：影响认证、授权或敏感数据访问"
                if escalated
                else "效率策略：除非影响认证、授权或敏感数据，否则延后验证"
            ),
            "canonical_type": normalized,
        }
    if normalized in _HIGH_PRIORITY_TYPES:
        return {
            "priority": "high",
            "reason": "专项策略：可能形成权限获取或高影响攻击链",
            "canonical_type": normalized,
        }
    if has_verified_access_impact(impact) or has_verified_privilege_impact(impact):
        return {
            "priority": "high",
            "reason": "影响证明显示该问题可能形成权限或敏感数据攻击链",
            "canonical_type": normalized,
        }
    return {
        "priority": "normal",
        "reason": "未分类问题：保留测试和报告资格，由请求风险及目标范围决定是否执行",
        "canonical_type": normalized,
    }


def is_attack_chain_eligible(
    vulnerability_type: object,
    *,
    severity: str | None = None,
    impact: str | None = None,
) -> bool:
    """Return whether a finding may enter the red-team attack-chain view."""
    if str(severity or "").strip().lower() not in {"critical", "high"}:
        return False
    normalized = normalize_vulnerability_type(vulnerability_type)
    if normalized not in _ATTACK_CHAIN_TYPES:
        return False
    if normalized in _LOW_PRIORITY_TYPES:
        return False
    if normalized in {"privilege_acquisition"} and not has_verified_privilege_impact(impact):
        return False
    if normalized in {
        "authentication_bypass",
        "authorization_bypass",
        "authentication_or_authorization_bypass",
        "idor_bola",
        "exposed_admin_function",
        "cloud_storage_unauthorized_access",
        "cloud_storage_writable",
        "business_logic_unauthorized_action",
        "default_credentials",
        "session_management",
        "captcha_bypass",
        "rate_limit_bypass",
        "cors_misconfiguration",
        "csrf",
        "open_redirect",
        "path_traversal",
        "writable_file_upload",
        "sensitive_information_disclosure",
        "file_read_write",
    } and not (has_verified_access_impact(impact) or has_verified_privilege_impact(impact)):
        return False
    if normalized == "credential_exposure_observed" and not has_credential_observation(impact):
        return False
    return True


def should_ignore(
    vuln_type: str,
    *,
    mode: SecurityMode = NORMAL_MODE,
    impact: str | None = None,
) -> bool:
    """Compatibility helper for the attack-chain projection only.

    This function must not be used to gate network actions or report writes.
    Call :func:`classify_test_priority` for scheduling and
    :func:`is_attack_chain_eligible` for the final chain projection.
    """
    if normalize_mode(mode) in {NORMAL_MODE, VERIFY_MODE}:
        return False
    return not is_attack_chain_eligible(vuln_type, severity="high", impact=impact)


def policy_context(mode: SecurityMode) -> dict[str, object]:
    """Return non-secret prompt/context metadata for a scan."""
    resolved_mode = normalize_mode(mode)
    return {
        "security_mode": resolved_mode,
        "redteam_policy_version": POLICY_VERSION if resolved_mode == REDTEAM_MODE else None,
        "redteam_fail_closed": False,
        "redteam_action_policy": "scope-and-action-risk",
        "redteam_priority_policy": "impact-aware",
        "verification_mode": resolved_mode == VERIFY_MODE,
    }
