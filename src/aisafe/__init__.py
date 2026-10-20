"""
__init__.py
-----------
AnyAISafe — public API surface.

Runtime guardrails (use in your application):
    from aisafe import GuardrailPipeline
    from aisafe import PIIDetector, PromptInjectionGuard
    from aisafe import ToxicityFilter
    from aisafe import ToolPolicyGuard, ToolPolicy
    from aisafe import EUAIActCompliance, RiskTier
    from aisafe import AuditLogger

Static code analyzer (use in CI / pre-commit):
    from aisafe import EUAIActCodeAnalyzer, ScanReport
    from aisafe import TerminalReporter, JSONReporter, SARIFReporter
    # or via CLI: aisafe lint src/
"""

import importlib

from aisafe.core.base import (
    Action,
    CheckResult,
    Finding,
    GuardrailBase,
    GuardrailStage,
    PipelineResult,
    Severity,
)
from aisafe.core.exceptions import (
    GuardrailBlockedError,
    GuardrailConfigError,
    PolicyViolationError,
)
from aisafe.core.pipeline import GuardrailPipeline

# Input modules
from aisafe.modules.input.pii_detector import PIIDetector, PIIRestorer
from aisafe.modules.input.prompt_injection import PromptInjectionGuard
from aisafe.modules.input.rate_limiter import RateLimiter

# LLM judges (the base class; concrete judges need their provider SDK)
from aisafe.modules.llm_judges.base import LLMJudgeBase

# Output modules
from aisafe.modules.output.ai_disclosure import AIDisclosureGuard
from aisafe.modules.output.llm_output_filter import LLMOutputFilter
from aisafe.modules.output.manipulation import ManipulationGuard
from aisafe.modules.output.toxicity import ToxicityFilter

# Policy — static code analyzer
from aisafe.modules.policy.code_analyzer.analyzer import EUAIActCodeAnalyzer, ScanReport
from aisafe.modules.policy.code_analyzer.reporters import (
    JSONReporter,
    MarkdownReporter,
    SARIFReporter,
    TerminalReporter,
)

# Policy — runtime guardrails
from aisafe.modules.policy.eu_ai_act import EUAIActCompliance, RiskTier
from aisafe.modules.policy.nist_ai_rmf import ImpactLevel, NISTAIRMFCompliance

# Processing modules
from aisafe.modules.processing.llm_tool_filter import LLMToolFilter
from aisafe.modules.processing.tool_policy import ToolPolicy, ToolPolicyGuard

# Observability is imported on first use (PEP 562). `otel.py` pulls in the
# OpenTelemetry SDK, about a quarter of a second that every `aisafe` CLI run and every
# agent hook would otherwise pay before doing anything; `otel.py` still guards the
# optional dependency itself. Guards stay eager: `@register_guard` fills the registry
# `GuardrailPipeline.from_config` reads, and a lazy guard would be an unregistered name.
_LAZY_ATTRIBUTES = {
    "AuditLogger": ("aisafe.modules.observability.audit_logger", "AuditLogger"),
    "TelemetryProvider": ("aisafe.modules.observability.otel", "TelemetryProvider"),
}


def __getattr__(name: str):
    target = _LAZY_ATTRIBUTES.get(name)
    if target is None:
        raise AttributeError(f"module 'aisafe' has no attribute {name!r}")
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
