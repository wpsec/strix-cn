from abc import ABC, abstractmethod
from typing import Any, ClassVar

from textual.widgets import Static


class BaseToolRenderer(ABC):
    tool_name: ClassVar[str] = ""
    css_classes: ClassVar[list[str]] = ["tool-call"]

    @classmethod
    @abstractmethod
    def render(cls, tool_data: dict[str, Any]) -> Static:
        pass

    @classmethod
    def status_icon(cls, status: str) -> tuple[str, str]:
        icons = {
            "running": ("● 进行中...", "#f59e0b"),
            "completed": ("✓ 已完成", "#22c55e"),
            "failed": ("✗ 失败", "#dc2626"),
            "error": ("✗ 错误", "#dc2626"),
        }
        return icons.get(status, ("○ 未知", "dim"))

    @classmethod
    def get_css_classes(cls, status: str) -> str:
        base_classes = cls.css_classes.copy()
        base_classes.append(f"status-{status}")
        return " ".join(base_classes)
