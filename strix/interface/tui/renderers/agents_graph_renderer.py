from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from strix.core.agent_naming import normalize_agent_name

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


@register_tool_renderer
class ViewAgentGraphRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "view_agent_graph"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        status = tool_data.get("status", "unknown")

        text = Text()
        text.append("◇ ", style="#a78bfa")
        text.append("查看代理图", style="dim")

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)


@register_tool_renderer
class CreateAgentRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "create_agent"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")

        task = args.get("task", "")
        name = normalize_agent_name(args.get("name", "专家代理"))

        text = Text()
        text.append("◈ ", style="#a78bfa")
        text.append("创建子专家 ", style="dim")
        text.append(name, style="bold #a78bfa")

        if task:
            text.append("\n  ")
            text.append(task, style="dim")

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)


@register_tool_renderer
class SendMessageToAgentRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "send_message_to_agent"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")

        message = args.get("message", "")
        target_agent_id = args.get("target_agent_id", "")

        text = Text()
        text.append("→ ", style="#60a5fa")
        if target_agent_id:
            text.append(f"发送给 {target_agent_id}", style="dim")
        else:
            text.append("发送消息", style="dim")

        if message:
            text.append("\n  ")
            text.append(message, style="dim")

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)


@register_tool_renderer
class AgentFinishRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "agent_finish"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})

        result_summary = args.get("result_summary", "")
        findings = args.get("findings", [])
        success = args.get("success", True)

        text = Text()

        if success:
            text.append("◆ ", style="#22c55e")
            text.append("代理已完成", style="bold #22c55e")
        else:
            text.append("◆ ", style="#ef4444")
            text.append("代理失败", style="bold #ef4444")

        if result_summary:
            text.append("\n  ")
            text.append(result_summary, style="bold")

            if findings and isinstance(findings, list):
                for finding in findings:
                    text.append("\n  • ")
                    text.append(str(finding), style="dim")
        else:
            text.append("\n  ")
            text.append("正在结束任务...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class WaitForMessageRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "wait_for_message"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        status = tool_data.get("status", "unknown")

        reason = args.get("reason", "")

        text = Text()
        text.append("○ ", style="#6b7280")
        text.append("等待中", style="dim")

        if reason:
            text.append("\n  ")
            text.append(reason, style="dim")

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)


@register_tool_renderer
class StopAgentRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "stop_agent"
    css_classes: ClassVar[list[str]] = ["tool-call", "agents-graph-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        args = tool_data.get("args", {})
        result = tool_data.get("result")
        status = tool_data.get("status", "unknown")

        target_agent_id = args.get("target_agent_id", "")
        cascade = args.get("cascade", True)
        reason = args.get("reason", "")

        text = Text()
        text.append("◼ ", style="#ef4444")
        text.append("停止", style="dim")
        if target_agent_id:
            text.append(f" {target_agent_id}", style="bold #ef4444")
        if cascade:
            text.append(" 及其子代理", style="dim italic")

        if reason:
            text.append("\n  ")
            text.append(reason, style="dim")

        if isinstance(result, dict) and result.get("success") is False and result.get("error"):
            text.append("\n  ")
            text.append(str(result["error"]), style="#ef4444")

        css_classes = cls.get_css_classes(status)
        return Static(text, classes=css_classes)
