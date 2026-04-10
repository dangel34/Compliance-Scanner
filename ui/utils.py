"""
Shared utilities for the Compliance Scanner UI.

Establishes PROJECT_ROOT on sys.path so that all ui sub-modules can
import from core without repeating the path-setup boilerplate.
"""
from __future__ import annotations

import html as _html
import os
import re
import sys
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Path setup — done once here, inherited by every module that imports utils
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

# ---------------------------------------------------------------------------
# Type alias used across all ui modules
# ---------------------------------------------------------------------------
RunResult = Dict[str, Any]

# ---------------------------------------------------------------------------
# String helpers
# ---------------------------------------------------------------------------

# Compiled once — matches ASCII control characters that are unsafe in UI/PDF
_CTRL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _safe_str(value: Any, max_len: int = 512) -> str:
    """
    Coerce *value* to a plain string, strip control characters, and cap length.
    Used everywhere user-supplied JSON data is read so that malformed or
    adversarial content cannot propagate into the UI or PDF renderer.
    """
    s = str(value) if value is not None else ""
    return _CTRL_CHARS.sub("", s)[:max_len]


def _escape_xml(value: str) -> str:
    """HTML/XML-escape a string for safe embedding in ReportLab Paragraph markup."""
    return _html.escape(str(value))


def format_os_name(os_name: str) -> str:
    return os_name.replace("_", " ").title()


# ---------------------------------------------------------------------------
# Rule status helper
# ---------------------------------------------------------------------------

def get_rule_status(result: RunResult) -> str:
    if result is None:
        return "NOT_RUN"
    if "error" in result:
        return "ERROR"
    checks = result.get("checks", [])
    if not checks:
        return "SKIP"
    statuses = [c.get("status") for c in checks]
    if all(s == "PASS" for s in statuses):
        return "PASS"
    if all(s == "FAIL" for s in statuses):
        return "FAIL"
    return "PARTIAL"
