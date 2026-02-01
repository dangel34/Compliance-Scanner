# Core compliance engine: OS detection, scanners, rule runner
from .scanner_init import os_scan, get_scanner

__all__ = ["os_scan", "get_scanner", "RuleRunner"]

def __getattr__(name):
    if name == "RuleRunner":
        from .rule_runner import RuleRunner
        return RuleRunner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
