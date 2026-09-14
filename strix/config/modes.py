"""Supported Strix run modes."""

from __future__ import annotations

from typing import Literal


SecurityMode = Literal["normal", "verify"]
NORMAL_MODE: SecurityMode = "normal"
VERIFY_MODE: SecurityMode = "verify"


def normalize_mode(value: object) -> SecurityMode:
    """Normalize a configured mode or reject an unsupported value."""
    mode = str(value or NORMAL_MODE).strip().lower()
    if mode not in {NORMAL_MODE, VERIFY_MODE}:
        raise ValueError("mode 必须是 normal 或 verify")
    return mode
