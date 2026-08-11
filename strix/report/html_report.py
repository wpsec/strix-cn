"""Self-contained HTML delivery report with the local Viewer visual language."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from html import escape
from typing import Any

from markdown_it import MarkdownIt


_MARKDOWN = MarkdownIt("commonmark", {"html": False, "linkify": False, "typographer": False})
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}


def _text(value: Any, fallback: str = "未提供") -> str:
    rendered = str(value or "").strip()
    return rendered or fallback


def _html(value: Any, fallback: str = "未提供") -> str:
    return escape(_text(value, fallback), quote=True)


def _markdown(value: Any, fallback: str = "未提供。") -> str:
    source = _text(value, fallback)
    return _MARKDOWN.render(source)


def _section(final_scan_result: str | None, title: str, fallback: str) -> str:
    if not final_scan_result:
        return fallback
    pattern = re.compile(
        rf"^#{{1,6}}\s+(?:\d+\.\s+)?{re.escape(title)}\s*$"
        rf"([\s\S]*?)(?=^#{{1,6}}\s+|\Z)",
        re.MULTILINE,
    )
    match = pattern.search(final_scan_result)
    return _text(match.group(1) if match else "", fallback)


def _targets(run_record: dict[str, Any]) -> list[str]:
    raw_targets = run_record.get("targets_info")
    if not isinstance(raw_targets, list):
        return []
    result: list[str] = []
    for target in raw_targets:
        if isinstance(target, dict):
            value = target.get("original") or target.get("canonical") or target.get("display")
        else:
            value = target
        if value:
            result.append(str(value).strip())
    return result


def _metadata(report: dict[str, Any]) -> str:
    dependency = report.get("dependency_metadata")
    dep = dependency if isinstance(dependency, dict) else {}
    fields = [
        ("目标", report.get("target")),
        ("接口", report.get("endpoint")),
        ("请求方法", report.get("method")),
        ("CVE", report.get("cve")),
        ("CWE", report.get("cwe")),
        ("CVSS", report.get("cvss")),
        ("组件", dep.get("package_name")),
        ("当前版本", dep.get("installed_version")),
        ("修复版本", dep.get("fixed_version")),
        ("清单文件", dep.get("manifest_path")),
    ]
    rows = [
        f'<div><dt>{escape(label)}</dt><dd>{_html(value)}</dd></div>'
        for label, value in fields
        if value not in (None, "", [])
    ]
    return "".join(rows) or "<div><dt>编号</dt><dd>无补充元数据</dd></div>"


def _finding_sections(report: dict[str, Any]) -> str:
    fields = [
        ("结论速览", report.get("description")),
        ("影响", report.get("impact")),
        ("技术细节", report.get("technical_analysis")),
        ("证据", report.get("evidence")),
        ("运行时验证", report.get("validation_evidence")),
        ("复现说明", report.get("poc_description")),
        ("概念验证", report.get("poc_script_code")),
        ("如何修复", report.get("remediation_steps")),
        ("前提假设", report.get("assumptions")),
    ]
    sections = [
        f'<section class="finding-section"><h4>{escape(title)}</h4>'
        f'<div class="prose">{_markdown(value)}</div></section>'
        for title, value in fields
        if value not in (None, "", [])
    ]
    return "".join(sections) or (
        '<section class="finding-section"><h4>结论速览</h4>'
        '<div class="prose"><p>该问题没有补充说明。</p></div></section>'
    )


def _finding_card(report: dict[str, Any], *, initially_open: bool) -> str:
    severity = str(report.get("severity") or "info").strip().lower()
    if severity not in _SEVERITY_LABELS:
        severity = "info"
    report_id = _text(report.get("id"), "unknown")
    endpoint = " ".join(
        part for part in (_text(report.get("method"), ""), _text(report.get("endpoint"), "")) if part
    )
    open_attr = " open" if initially_open else ""
    return f"""
<details class="finding severity-{severity}" id="{escape(report_id, quote=True)}"{open_attr}>
  <summary>
    <span class="severity-dot"></span>
    <span class="finding-heading">
      <span class="finding-id">{escape(report_id)}</span>
      <strong>{_html(report.get("title"), "未命名问题")}</strong>
      {f'<small>{escape(endpoint)}</small>' if endpoint else ''}
    </span>
    <span class="severity-badge">{_SEVERITY_LABELS[severity]}</span>
    <span class="disclosure">+</span>
  </summary>
  <div class="finding-body">
    <main>{_finding_sections(report)}</main>
    <aside><dl>{_metadata(report)}</dl></aside>
  </div>
</details>
"""


def render_html_report(
    *,
    final_scan_result: str | None,
    run_record: dict[str, Any],
    vulnerability_reports: list[dict[str, Any]],
) -> str:
    """Render a portable, offline report. All target-authored content is escaped."""
    reports = sorted(
        vulnerability_reports,
        key=lambda item: (
            _SEVERITY_ORDER.get(str(item.get("severity") or "info").lower(), 5),
            str(item.get("id") or ""),
        ),
    )
    counts = {severity: 0 for severity in _SEVERITY_LABELS}
    for report in reports:
        severity = str(report.get("severity") or "info").lower()
        counts[severity if severity in counts else "info"] += 1

    status = str(run_record.get("status") or "running").lower()
    finished = status == "completed" and bool(final_scan_result)
    status_label = "最终报告" if finished else "进行中 · 草稿"
    targets = _targets(run_record)
    target_label = "、".join(targets) if targets else "Burp 被动代理采集范围"
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    summary = _section(
        final_scan_result,
        "执行摘要",
        f"测试仍在进行中，当前已确认 {len(reports)} 个安全问题。最终结论将在结束测试后生成。",
    )
    methodology = _section(
        final_scan_result,
        "测试方法",
        "基于已授权范围、代理流量和多代理专项验证持续开展测试。",
    )
    technical = _section(
        final_scan_result,
        "技术分析",
        "当前展示已落盘问题，技术结论会随测试进展持续更新。",
    )
    recommendations = _section(
        final_scan_result,
        "修复建议",
        "优先处理已确认的高风险问题，并在修复后执行针对性复测。",
    )
    cards = "".join(
        _finding_card(report, initially_open=index == 0) for index, report in enumerate(reports)
    )
    if not cards:
        cards = '<div class="empty">当前尚未落盘任何安全问题。</div>'

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; font-src data:; base-uri 'none'; form-action 'none'">
<title>Strix 安全测试报告 · {_html(run_record.get('run_name'), '未命名运行')}</title>
<style>
:root{{--bg:#050505;--panel:#0b0b0b;--panel2:#111;--line:#252525;--text:#f5f5f4;--muted:#8b8b88;--green:#34d399;--red:#ef4444;--orange:#f97316;--yellow:#eab308;--blue:#60a5fa;--gray:#a3a3a3}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:radial-gradient(circle at 80% -10%,#173a2d55,transparent 32rem),var(--bg);color:var(--text);font:14px/1.65 "Avenir Next","PingFang SC","Microsoft YaHei",sans-serif}}
a{{color:inherit}}.layout{{display:grid;grid-template-columns:250px minmax(0,1fr);min-height:100vh}}.rail{{position:sticky;top:0;height:100vh;padding:28px 22px;border-right:1px solid var(--line);background:#050505ee}}
.brand{{display:flex;align-items:center;gap:10px;font-weight:700;font-size:18px}}.mark{{display:grid;place-items:center;width:28px;height:28px;border-radius:9px;background:linear-gradient(135deg,var(--green),#0891b2);color:#00140d}}
.local{{margin-left:auto;padding:2px 8px;border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:11px}}.rail p{{color:var(--muted);font-size:12px}}nav{{display:grid;gap:5px;margin-top:30px}}nav a{{padding:9px 11px;border-radius:8px;text-decoration:none;color:var(--muted)}}nav a:hover{{background:#ffffff0d;color:white}}
.confidential{{position:absolute;bottom:24px;color:#555;font-size:11px;letter-spacing:.08em;text-transform:uppercase}}.content{{width:min(1180px,100%);margin:0 auto;padding:64px 48px 100px}}.eyebrow{{color:var(--green);font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase}}
h1{{max-width:850px;margin:12px 0 18px;font-size:clamp(34px,5vw,64px);line-height:1.04;letter-spacing:-.045em}}.subtitle{{max-width:850px;color:#b6b6b2;font-size:17px}}.meta{{display:flex;flex-wrap:wrap;gap:9px;margin-top:25px}}.chip{{padding:6px 10px;border:1px solid var(--line);border-radius:999px;background:#ffffff08;color:#b7b7b2;font-size:12px}}
.metrics{{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin:42px 0}}.metric{{padding:18px;border:1px solid var(--line);border-radius:13px;background:linear-gradient(145deg,#ffffff0a,#ffffff03)}}.metric strong{{display:block;font-size:28px;line-height:1.1}}.metric span{{color:var(--muted);font-size:12px}}.critical strong{{color:var(--red)}}.high strong{{color:var(--orange)}}.medium strong{{color:var(--yellow)}}.low strong{{color:var(--blue)}}
.section{{scroll-margin-top:24px;margin-top:54px}}h2{{margin:0 0 16px;font-size:22px;letter-spacing:-.02em}}.narrative{{padding:24px;border:1px solid var(--line);border-radius:14px;background:#ffffff06}}.prose{{color:#c9c9c5}}.prose p:first-child{{margin-top:0}}.prose p:last-child{{margin-bottom:0}}.prose h1,.prose h2,.prose h3{{font-size:16px;letter-spacing:0}}.prose pre{{overflow:auto;padding:14px;border:1px solid var(--line);border-radius:9px;background:#020202;color:#d4d4d4}}.prose code{{font-family:"SFMono-Regular",Consolas,monospace;color:#d1fae5}}.prose :not(pre)>code{{padding:2px 5px;border-radius:5px;background:#ffffff0d}}.prose blockquote{{margin-left:0;padding-left:15px;border-left:2px solid var(--green);color:#aaa}}.prose table{{width:100%;border-collapse:collapse}}.prose th,.prose td{{padding:8px;border:1px solid var(--line);text-align:left}}
.finding{{margin:10px 0;border:1px solid var(--line);border-radius:13px;background:var(--panel);overflow:hidden}}.finding summary{{display:flex;align-items:center;gap:12px;padding:17px 18px;cursor:pointer;list-style:none}}.finding summary::-webkit-details-marker{{display:none}}.severity-dot{{width:9px;height:9px;border-radius:50%;background:var(--gray);box-shadow:0 0 16px currentColor}}.finding-heading{{display:grid;min-width:0;flex:1}}.finding-heading strong{{font-size:15px}}.finding-heading small,.finding-id{{color:#686865;font:11px/1.5 "SFMono-Regular",Consolas,monospace}}.severity-badge{{padding:3px 9px;border:1px solid currentColor;border-radius:999px;font-size:11px;font-weight:700}}.disclosure{{color:#666;font-size:20px;transition:transform .2s}}details[open] .disclosure{{transform:rotate(45deg)}}
.severity-critical .severity-dot,.severity-critical .severity-badge{{color:var(--red);background:#ef444422}}.severity-high .severity-dot,.severity-high .severity-badge{{color:var(--orange);background:#f9731622}}.severity-medium .severity-dot,.severity-medium .severity-badge{{color:var(--yellow);background:#eab30822}}.severity-low .severity-dot,.severity-low .severity-badge{{color:var(--blue);background:#60a5fa22}}.severity-info .severity-dot,.severity-info .severity-badge{{color:var(--gray);background:#a3a3a322}}
.finding-body{{display:grid;grid-template-columns:minmax(0,1fr) 280px;gap:30px;padding:10px 20px 25px;border-top:1px solid var(--line)}}.finding-section{{padding-top:20px}}.finding-section h4{{margin:0 0 8px;font-size:14px}}.finding-body aside{{border-left:1px solid var(--line);padding:20px 0 0 22px}}dl{{margin:0}}dl div{{margin-bottom:14px}}dt{{color:#666;font-size:11px}}dd{{margin:2px 0 0;overflow-wrap:anywhere;color:#d4d4d0;font-family:"SFMono-Regular",Consolas,monospace;font-size:12px}}.empty{{padding:32px;border:1px dashed #333;border-radius:12px;color:var(--muted);text-align:center}}footer{{margin-top:70px;padding-top:20px;border-top:1px solid var(--line);color:#5f5f5c;font-size:11px}}
@media(max-width:850px){{.layout{{display:block}}.rail{{position:relative;height:auto;border-right:0;border-bottom:1px solid var(--line)}}.rail nav,.confidential{{display:none}}.content{{padding:38px 18px 70px}}.metrics{{grid-template-columns:repeat(2,1fr)}}.finding-body{{grid-template-columns:1fr}}.finding-body aside{{border-left:0;border-top:1px solid var(--line);padding-left:0}}}}
@media print{{:root{{--bg:#fff;--panel:#fff;--panel2:#fff;--line:#ddd;--text:#111;--muted:#555}}body{{background:white;color:#111}}.layout{{display:block}}.rail{{display:none}}.content{{width:100%;padding:0}}.narrative,.metric,.finding{{background:white;break-inside:avoid}}.prose,dd,.subtitle{{color:#333}}details{{break-inside:avoid}}footer{{color:#666}}}}
</style>
</head>
<body>
<div class="layout">
  <aside class="rail"><div class="brand"><span class="mark">S</span>Strix<span class="local">本地报告</span></div><p>授权安全测试交付物</p><nav><a href="#overview">测试总览</a><a href="#analysis">技术分析</a><a href="#findings">问题详情 · {len(reports)}</a><a href="#remediation">修复建议</a></nav><div class="confidential">Confidential · Local only</div></aside>
  <main class="content">
    <header id="overview"><div class="eyebrow">{status_label}</div><h1>安全渗透测试报告</h1><p class="subtitle">{escape(target_label)}</p><div class="meta"><span class="chip">运行：{_html(run_record.get('run_name'), '未命名')}</span><span class="chip">模式：{_html(run_record.get('scan_mode'))}</span><span class="chip">生成：{generated_at}</span></div></header>
    <div class="metrics"><div class="metric"><strong>{len(reports)}</strong><span>问题总数</span></div><div class="metric critical"><strong>{counts['critical']}</strong><span>严重</span></div><div class="metric high"><strong>{counts['high']}</strong><span>高危</span></div><div class="metric medium"><strong>{counts['medium']}</strong><span>中危</span></div><div class="metric low"><strong>{counts['low'] + counts['info']}</strong><span>低危 / 信息</span></div></div>
    <section class="section"><h2>执行摘要</h2><div class="narrative prose">{_markdown(summary)}</div></section>
    <section class="section"><h2>测试范围与方法</h2><div class="narrative prose">{_markdown(methodology)}</div></section>
    <section class="section" id="analysis"><h2>技术分析</h2><div class="narrative prose">{_markdown(technical)}</div></section>
    <section class="section" id="findings"><h2>问题详情</h2>{cards}</section>
    <section class="section" id="remediation"><h2>分级修复建议</h2><div class="narrative prose">{_markdown(recommendations)}</div></section>
    <footer>本报告由 Strix 本地运行生成。单漏洞 Markdown、JSON、CSV 与 SARIF 文件保留在同一运行目录中，供复核和系统导入。</footer>
  </main>
</div>
</body>
</html>
"""
