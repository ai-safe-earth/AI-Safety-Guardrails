"""
__init__.py
-----------
AI Safety Guardrails — public API surface.

Runtime guardrails (use in your application):
    from guardrails import GuardrailPipeline
    from guardrails import PIIDetector, PromptInjectionGuard
    from guardrails import ToxicityFilter
    from guardrails import ToolPolicyGuard, ToolPolicy
    from guardrails import EUAIActCompliance, RiskTier
    from guardrails import AuditLogger

Static code analyzer (use in CI / pre-commit):
    from guardrails import EUAIActCodeAnalyzer, ScanReport
    from guardrails import TerminalReporter, JSONReporter, SARIFReporter
    # or via CLI: euaiact-lint src/
"""

import importlib

from aisg.core.base import (
    Action,
    CheckResult,
    Finding,
    GuardrailBase,
    GuardrailStage,
    PipelineResult,
    Severity,
)
from aisg.core.exceptions import (
    GuardrailBlockedError,
    GuardrailConfigError,
    PolicyViolationError,
)
from aisg.core.pipeline import GuardrailPipeline

# Input modules
from aisg.modules.input.pii_detector import PIIDetector, PIIRestorer
from aisg.modules.input.prompt_injection import PromptInjectionGuard
from aisg.modules.input.rate_limiter import RateLimiter

# LLM judges (the base class; concrete judges need their provider SDK)
from aisg.modules.llm_judges.base import LLMJudgeBase

# Output modules
from aisg.modules.output.ai_disclosure import AIDisclosureGuard
from aisg.modules.output.llm_output_filter import LLMOutputFilter
from aisg.modules.output.manipulation import ManipulationGuard
from aisg.modules.output.toxicity import ToxicityFilter

# Policy — static code analyzer
from aisg.modules.policy.code_analyzer.analyzer import EUAIActCodeAnalyzer, ScanReport
from aisg.modules.policy.code_analyzer.reporters import (
    JSONReporter,
    MarkdownReporter,
    SARIFReporter,
    TerminalReporter,
)

# Policy — runtime guardrails
from aisg.modules.policy.eu_ai_act import EUAIActCompliance, RiskTier
from aisg.modules.policy.nist_ai_rmf import ImpactLevel, NISTAIRMFCompliance

# Processing modules
from aisg.modules.processing.llm_tool_filter import LLMToolFilter
from aisg.modules.processing.tool_policy import ToolPolicy, ToolPolicyGuard

# Observability is imported on first use (PEP 562). `otel.py` pulls in the
# OpenTelemetry SDK, about a quarter of a second that every `aisg` CLI run and every
# agent hook would otherwise pay before doing anything; `otel.py` still guards the
# optional dependency itself. Guards stay eager: `@register_guard` fills the registry
# `GuardrailPipeline.from_config` reads, and a lazy guard would be an unregistered name.
_LAZY_ATTRIBUTES = {
    "AuditLogger": ("aisg.modules.observability.audit_logger", "AuditLogger"),
    "TelemetryProvider": ("aisg.modules.observability.otel", "TelemetryProvider"),
}


def __getattr__(name: str):
    target = _LAZY_ATTRIBUTES.get(name)
    if target is None:
        raise AttributeError(f"module 'aisg' has no attribute {name!r}")
    module = importlib.import_module(target[0])
    value = getattr(module, target[1])
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))


__version__ = "0.1.0"
__all__ = [
    # Pipeline
    "GuardrailPipeline",
    # Base types
    "GuardrailBase",
    "CheckResult",
    "PipelineResult",
    "Finding",
    "Severity",
    "Action",
    "GuardrailStage",
    # Exceptions
    "GuardrailBlockedError",
    "GuardrailConfigError",
    "PolicyViolationError",
    # Input
    "PIIDetector",
    "PIIRestorer",
    "PromptInjectionGuard",
    "RateLimiter",
    # Processing
    "ToolPolicyGuard",
    "ToolPolicy",
    "LLMToolFilter",
    # Output
    "ToxicityFilter",
    "LLMOutputFilter",
    "ManipulationGuard",
    "AIDisclosureGuard",
    # LLM judges
    "LLMJudgeBase",
    # Policy — runtime
    "EUAIActCompliance",
    "RiskTier",
    "NISTAIRMFCompliance",
    "ImpactLevel",
    # Policy — static analyzer
    "EUAIActCodeAnalyzer",
    "ScanReport",
    "TerminalReporter",
    "JSONReporter",
    "SARIFReporter",
    "MarkdownReporter",
    # Observability
    "AuditLogger",
    "TelemetryProvider",
]
