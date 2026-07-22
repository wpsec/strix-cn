"""Tests for localized user-facing TUI strings."""

from __future__ import annotations

from rich.text import Text

from strix.interface.tui.app import StrixTUIApp
from strix.interface.tui.renderers.finish_renderer import FinishScanRenderer
from strix.interface.tui.renderers.load_skill_renderer import LoadSkillRenderer
from strix.interface.tui.renderers.notes_renderer import CreateNoteRenderer, ListNotesRenderer
from strix.interface.tui.renderers.reporting_renderer import (
    CreateDependencyReportRenderer,
    CreateVulnerabilityReportRenderer,
)
from strix.interface.tui.renderers.todo_renderer import CreateTodoRenderer, ListTodosRenderer


def _plain(static: object) -> str:
    content = static.content  # type: ignore[attr-defined]
    return content.plain if isinstance(content, Text) else str(content)


def test_todo_renderers_use_chinese_labels() -> None:
    created = _plain(CreateTodoRenderer.render({"result": None}))
    listed = _plain(ListTodosRenderer.render({"result": {"success": True, "todos": []}}))

    assert "待办事项" in created
    assert "正在创建..." in created
    assert "待办列表" in listed
    assert "暂无待办事项" in listed


def test_note_renderers_use_chinese_labels() -> None:
    created = _plain(
        CreateNoteRenderer.render({"args": {"title": "", "content": "", "category": "plan"}})
    )
    listed = _plain(ListNotesRenderer.render({"result": {"success": True, "total_count": 0}}))

    assert "笔记" in created
    assert "正在记录..." in created
    assert "笔记列表" in listed
    assert "暂无笔记" in listed


def test_reporting_renderers_use_chinese_labels() -> None:
    vulnerability = _plain(
        CreateVulnerabilityReportRenderer.render(
            {
                "args": {
                    "title": "存在 SSRF",
                    "description": "描述",
                    "impact": "影响",
                    "target": "https://example.com",
                    "technical_analysis": "分析",
                    "poc_description": "步骤",
                    "poc_script_code": "print(1)",
                    "remediation_steps": "修复",
                },
                "result": {"severity": "high", "cvss_score": 8.1},
            }
        )
    )
    dependency = _plain(
        CreateDependencyReportRenderer.render(
            {
                "args": {
                    "title": "CVE-2024-0001 in demo",
                    "description": "描述",
                    "impact": "影响",
                    "target": "repo/package.json",
                    "technical_analysis": "分析",
                    "remediation_steps": "升级",
                    "assumptions": "假设",
                    "package_name": "demo",
                    "package_ecosystem": "npm",
                    "installed_version": "1.0.0",
                    "fixed_version": "1.0.1",
                    "advisory_cvss": 7.5,
                    "fix_effort": "low",
                },
                "result": {"severity": "high"},
            }
        )
    )

    assert "漏洞报告" in vulnerability
    assert "标题：" in vulnerability
    assert "技术分析" in vulnerability
    assert "依赖漏洞（SCA）报告" in dependency
    assert "依赖包：" in dependency
    assert "修复成本：" in dependency


def test_finish_and_load_skill_renderers_use_chinese_labels() -> None:
    finish = _plain(FinishScanRenderer.render({"args": {}}))
    load_skill = _plain(LoadSkillRenderer.render({"args": {}, "result": None}))

    assert "渗透测试已完成" in finish
    assert "正在生成最终报告..." in finish
    assert "正在加载 skill" in load_skill
    assert "正在加载..." in load_skill


def test_tui_bindings_include_terminal_copy_mode_toggle() -> None:
    assert any(binding.key == "f2" for binding in StrixTUIApp.BINDINGS)
