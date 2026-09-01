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

from core.base import (
    Action,
    CheckResult,
    Finding,
    GuardrailBase,
    GuardrailStage,
    PipelineResult,
    Severity,
)
from core.exceptions import (
    GuardrailBlockedError,
    GuardrailConfigError,
    PolicyViolationError,
)
from core.pipeline import GuardrailPipeline

# Input modules
from modules.input.pii_detector import PIIDetector
from modules.input.prompt_injection import PromptInjectionGuard

# Observability
from modules.observability.audit_logger import AuditLogger

# Output modules
from modules.output.toxicity import ToxicityFilter

# Policy — static code analyzer
from modules.policy.code_analyzer.analyzer import EUAIActCodeAnalyzer, ScanReport
from modules.policy.code_analyzer.reporters import (
    JSONReporter,
    MarkdownReporter,
    SARIFReporter,
    TerminalReporter,
)

# Policy — runtime guardrails
from modules.policy.eu_ai_act import EUAIActCompliance, RiskTier
from modules.policy.nist_ai_rmf import ImpactLevel, NISTAIRMFCompliance

# Processing modules
from modules.processing.tool_policy import ToolPolicy, ToolPolicyGuard

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
    "PromptInjectionGuard",
    # Processing
    "ToolPolicyGuard",
    "ToolPolicy",
    # Output
    "ToxicityFilter",
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
]
