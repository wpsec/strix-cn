from typing import Any, ClassVar

from rich.text import Text
from textual.widgets import Static

from .base_renderer import BaseToolRenderer
from .registry import register_tool_renderer


STATUS_MARKERS: dict[str, str] = {
    "pending": "[ ]",
    "in_progress": "[~]",
    "done": "[•]",
}


def _format_todo_lines(text: Text, result: dict[str, Any]) -> None:
    todos = result.get("todos")
    if not isinstance(todos, list) or not todos:
        text.append("\n  ")
        text.append("暂无待办事项", style="dim")
        return

    for todo in todos:
        status = todo.get("status", "pending")
        marker = STATUS_MARKERS.get(status, STATUS_MARKERS["pending"])

        title = todo.get("title", "").strip() or "（未命名）"

        text.append("\n  ")
        text.append(marker)
        text.append(" ")

        if status == "done":
            text.append(title, style="dim strike")
        elif status == "in_progress":
            text.append(title, style="italic")
        else:
            text.append(title)


@register_tool_renderer
class CreateTodoRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "create_todo"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📋 ")
        text.append("待办事项", style="bold #a78bfa")

        if isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif result and isinstance(result, dict):
            if result.get("success"):
                _format_todo_lines(text, result)
            else:
                error = result.get("error", "创建待办事项失败")
                text.append("\n  ")
                text.append(error, style="#ef4444")
        else:
            text.append("\n  ")
            text.append("正在创建...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class ListTodosRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "list_todos"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📋 ")
        text.append("待办列表", style="bold #a78bfa")

        if isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif result and isinstance(result, dict):
            if result.get("success"):
                _format_todo_lines(text, result)
            else:
                error = result.get("error", "获取待办列表失败")
                text.append("\n  ")
                text.append(error, style="#ef4444")
        else:
            text.append("\n  ")
            text.append("正在加载...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class UpdateTodoRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "update_todo"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📋 ")
        text.append("待办事项已更新", style="bold #a78bfa")

        if isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif result and isinstance(result, dict):
            if result.get("success"):
                _format_todo_lines(text, result)
            else:
                error = result.get("error", "更新待办事项失败")
                text.append("\n  ")
                text.append(error, style="#ef4444")
        else:
            text.append("\n  ")
            text.append("正在更新...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class MarkTodoDoneRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "mark_todo_done"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📋 ")
        text.append("待办事项已完成", style="bold #a78bfa")

        if isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif result and isinstance(result, dict):
            if result.get("success"):
                _format_todo_lines(text, result)
            else:
                error = result.get("error", "标记待办事项完成失败")
                text.append("\n  ")
                text.append(error, style="#ef4444")
        else:
            text.append("\n  ")
            text.append("正在标记为完成...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class MarkTodoPendingRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "mark_todo_pending"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📋 ")
        text.append("待办事项已重新打开", style="bold #f59e0b")

        if isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif result and isinstance(result, dict):
            if result.get("success"):
                _format_todo_lines(text, result)
            else:
                error = result.get("error", "重新打开待办事项失败")
                text.append("\n  ")
                text.append(error, style="#ef4444")
        else:
            text.append("\n  ")
            text.append("正在重新打开...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)


@register_tool_renderer
class DeleteTodoRenderer(BaseToolRenderer):
    tool_name: ClassVar[str] = "delete_todo"
    css_classes: ClassVar[list[str]] = ["tool-call", "todo-tool"]

    @classmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        result = tool_data.get("result")

        text = Text()
        text.append("📋 ")
        text.append("待办事项已移除", style="bold #94a3b8")

        if isinstance(result, str) and result.strip():
            text.append("\n  ")
            text.append(result.strip(), style="dim")
        elif result and isinstance(result, dict):
            if result.get("success"):
                _format_todo_lines(text, result)
            else:
                error = result.get("error", "移除待办事项失败")
                text.append("\n  ")
                text.append(error, style="#ef4444")
        else:
            text.append("\n  ")
            text.append("正在移除...", style="dim")

        css_classes = cls.get_css_classes("completed")
        return Static(text, classes=css_classes)
