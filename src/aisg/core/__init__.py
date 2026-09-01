"""
core/__init__.py
----------------
Public API for the core package.
"""

from aisg.core.base import (
    Action,
    CheckResult,
    Finding,
    GuardrailBase,
    GuardrailStage,
    PipelineResult,
    Severity,
)
from aisg.core.exceptions import GuardrailBlockedError, GuardrailConfigError, PolicyViolationError
from aisg.core.pipeline import GuardrailPipeline
from aisg.core.registry import REGISTRY, register_guard

__all__ = [
    "GuardrailBase",
    "CheckResult",
    "PipelineResult",
    "Finding",
    "Severity",
    "Action",
    "GuardrailStage",
    "GuardrailBlockedError",
    "GuardrailConfigError",
    "PolicyViolationError",
    "GuardrailPipeline",
    "REGISTRY",
    "register_guard",
]
