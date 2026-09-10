"""Report/finding helpers.

Keep this package initializer lazy.  Report evidence and red-team projections
are also useful as standalone modules, and importing state here would make
those modules re-enter the package while it is still being initialized.
"""

from importlib import import_module
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from strix.report.state import ReportState, get_global_report_state, set_global_report_state
    from strix.report.dedupe import check_duplicate

__all__ = [
    "ReportState",
    "check_duplicate",
    "get_global_report_state",
    "set_global_report_state",
]


def __getattr__(name: str) -> Any:
    if name in {"ReportState", "get_global_report_state", "set_global_report_state"}:
        module = import_module("strix.report.state")
        return getattr(module, name)
    if name == "check_duplicate":
        return import_module("strix.report.dedupe").check_duplicate
    raise AttributeError(name)
