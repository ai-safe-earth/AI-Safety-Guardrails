"""
modules/policy/nist_ai_rmf.py
------------------------------
NIST AI Risk Management Framework (AI RMF 1.0) compliance guardrail.
Published January 2023. https://doi.org/10.6028/NIST.AI.100-1

The AI RMF organises AI risk management into four core functions:

    GOVERN  — Policies, accountability, and culture for AI risk management
    MAP     — Categorise and contextualise AI risks
    MEASURE — Analyse and assess identified risks
    MANAGE  — Prioritise and treat risks; monitor residual risk

This guardrail performs runtime content checks aligned with the subcategories
most relevant to live inference:

    GOVERN 1.1  — AI policies exist and are communicated
    GOVERN 1.7  — Processes ensure AI transparency and explainability
    MAP 1.1     — Context established; intended use documented
    MAP 2.2     — Harmful bias sources identified
    MAP 5.1     — Likelihood and magnitude of harms assessed
    MEASURE 2.5 — Fairness and bias of AI outputs evaluated
    MEASURE 2.6 — AI system performance evaluated and documented
    MANAGE 1.3  — Responses to identified risks are prioritised
    MANAGE 2.4  — Mechanisms to monitor AI in deployment

Impact levels (AI RMF Playbook — Risk Tolerance):
    CRITICAL  — Potential for widespread or irreversible harm
    HIGH      — Significant harm to individuals or groups
    MODERATE  — Limited, recoverable harm
    LOW       — Minimal expected harm

Usage:
    guard = NISTAIRMFCompliance(
        impact_level=ImpactLevel.HIGH,
        system_name="my-system-v1",
        operator_name="Acme Corp",
        enable_audit_log=True,
        human_oversight_callback=my_review_fn,
    )

    result = await guard.check(content, context)
"""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from core.base import Action, CheckResult, Finding, GuardrailBase, GuardrailStage, Severity
from core.registry import register_guard

# ---------------------------------------------------------------------------
# Impact Level Enum  (AI RMF Playbook — Risk Tolerance tiers)
# ---------------------------------------------------------------------------


class ImpactLevel(str, Enum):
    CRITICAL = "critical"  # Widespread / irreversible harm
    HIGH = "high"  # Significant harm to individuals or groups
    MODERATE = "moderate"  # Limited, recoverable harm
    LOW = "low"  # Minimal expected harm


# ---------------------------------------------------------------------------
# High-harm domain patterns  (MAP 1.1, MAP 5.1)
# Checks whether content touches domains where AI errors cause serious harm.
# ---------------------------------------------------------------------------

HIGH_HARM_DOMAIN_PATTERNS = [
    (
        re.compile(
            r"(medical (diagnosis|triage|treatment|prescription)|clinical decision|patient outcome)",
            re.I,
        ),
        "MAP 5.1 — Healthcare AI: errors may cause direct physical harm",
    ),
    (
        re.compile(
            r"(credit (scor|rating|decision)|loan (approval|denial)|insurance (underwriting|pricing))",
            re.I,
        ),
        "MAP 5.1 — Financial AI: errors may cause economic harm and discrimination",
    ),
    (
        re.compile(
            r"(hire|hiring|recruitment|job (applicant|candidate)|employment decision).{0,50}(AI|automated|model|algorithm)"
            r"|(AI|automated|model|algorithm).{0,50}(hire|hiring|recruitment|job (applicant|candidate)|employment decision)",
            re.I,
        ),
        "MAP 5.1 — Employment AI: errors may cause discriminatory outcomes",
    ),
    (
        re.compile(r"(law enforcement|police|criminal justice|sentencing|recidivism|parole)", re.I),
        "MAP 5.1 — Criminal justice AI: high potential for civil-rights harm",
    ),
    (
        re.compile(
            r"(critical infrastructure|power grid|water supply|transport safety|nuclear)", re.I
        ),
        "MAP 5.1 — Critical infrastructure: system failures may cascade",
    ),
    (
        re.compile(r"(asylum|immigration|border control|visa decision|deportation)", re.I),
        "MAP 5.1 — Immigration AI: errors may cause irreversible harm to individuals",
    ),
    (
        re.compile(r"(child welfare|child protective services|foster care|custody decision)", re.I),
        "MAP 5.1 — Child welfare AI: errors may cause serious harm to minors",
    ),
    (
        re.compile(
            r"(autonomous (weapon|lethal|strike|targeting)|military AI|drone targeting)", re.I
        ),
        "MAP 5.1 — Lethal autonomous weapon: critical safety and ethical concern",
    ),
]


# ---------------------------------------------------------------------------
# Bias / fairness risk patterns  (MAP 2.2, MEASURE 2.5)
# ---------------------------------------------------------------------------

BIAS_RISK_PATTERNS = [
    (
        re.compile(
            r"(predict|score|rank|classify|segment).{0,40}(race|ethnicity|gender|religion|nationality|disability|age group)",
            re.I,
        ),
        "MEASURE 2.5 — Model uses protected attributes; fairness evaluation required",
    ),
    (
        re.compile(
            r"(demographic|protected (class|group|attribute)).{0,30}(feature|variable|input|factor)",
            re.I,
        ),
        "MAP 2.2 — Protected characteristics as model inputs; bias evaluation required",
    ),
    (
        re.compile(
            r"(disparate impact|differential treatment|discriminatory (outcome|result|pattern))",
            re.I,
        ),
        "MEASURE 2.5 — Content references potential discriminatory AI outcomes",
    ),
]


# ---------------------------------------------------------------------------
# Transparency / explainability patterns  (GOVERN 1.7)
# Flags when AI output claims certainty without supporting explanation.
# ---------------------------------------------------------------------------

OPACITY_PATTERNS = [
    (
        re.compile(
            r"\b(the (AI|model|algorithm|system) (decided|determined|concluded|predicts)).{0,60}"
            r"(without|no (explanation|reason|justification|rationale))",
            re.I,
        ),
        "GOVERN 1.7 — AI decision without explanation undermines transparency",
    ),
    (
        re.compile(
            r"(black.?box|unexplainable|uninterpretable).{0,30}(decision|output|result|model)", re.I
        ),
        "GOVERN 1.7 — Reference to opaque/unexplainable AI decision",
    ),
    (
        re.compile(
            r"(fully automated|no human (review|oversight|involvement)).{0,50}"
            r"(high.?risk|consequential|life.?affecting|critical|irreversible)",
            re.I,
        ),
        "MANAGE 2.4 — Fully automated consequential decision; human oversight recommended",
    ),
]


# ---------------------------------------------------------------------------
# Deceptive AI / trust patterns  (GOVERN 1.1)
# ---------------------------------------------------------------------------

DECEPTION_PATTERNS = [
    (
        re.compile(
            r"(pretend|claim|act).{0,20}(you are|to be).{0,20}(human|not an AI|a person|real person)",
            re.I,
        ),
        "GOVERN 1.1 — Instruction to deceive users about AI nature",
    ),
    (
        re.compile(
            r"(hide|conceal|do not (disclose|reveal|mention)).{0,50}(AI|model|automated|algorithm)",
            re.I,
        ),
        "GOVERN 1.1 — Instruction to conceal AI involvement",
    ),
]


# ---------------------------------------------------------------------------
# Audit record  (MANAGE 2.4 monitoring)
# ---------------------------------------------------------------------------


@dataclass
class NISTAuditEvent:
    """Structured audit record aligned with NIST AI RMF MANAGE 2.4 monitoring."""

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )
    system_name: str = ""
    operator_name: str = ""
    impact_level: str = ""
    stage: str = ""
    action_taken: str = ""
    rmf_functions_triggered: list = field(default_factory=list)
    findings_count: int = 0
    user_id: str = ""
    session_id: str = ""
    content_hash: str = ""
    metadata: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


# ---------------------------------------------------------------------------
# Main guardrail
# ---------------------------------------------------------------------------


@register_guard("nist_ai_rmf")
class NISTAIRMFCompliance(GuardrailBase):
    """
    NIST AI Risk Management Framework (AI RMF 1.0) compliance guardrail.

    Checks live content against patterns associated with high-harm domains,
    bias risks, opacity, and deceptive AI behaviour.

    Config:
        impact_level:               ImpactLevel or string ("critical","high","moderate","low")
        system_name:                Identifier for the AI system under evaluation
        operator_name:              Responsible operator / organisation name
        enable_audit_log:           Write MANAGE 2.4 monitoring logs (default: True for critical/high)
        audit_log_path:             Path for JSONL audit log (default: "audit/nist_ai_rmf.jsonl")
        human_oversight_callback:   async fn(content, context) -> bool for human-in-the-loop gate
        transparency_disclosure:    Text appended to outputs to signal AI involvement (GOVERN 1.7)
        check_high_harm_domains:    Run MAP 5.1 domain checks (default: True)
        check_bias_risk:            Run MAP 2.2 / MEASURE 2.5 bias checks (default: True)
        check_opacity:              Run GOVERN 1.7 opacity checks (default: True)
        check_deception:            Run GOVERN 1.1 deception checks (default: True)
        strict_mode:                Block on CRITICAL findings (default: True)
    """

    name = "nist_ai_rmf"
    stage = GuardrailStage.POLICY
    description = "NIST AI Risk Management Framework (AI RMF 1.0) compliance checks."

    def setup(
        self,
        impact_level: ImpactLevel | str = ImpactLevel.MODERATE,
        system_name: str = "ai-system",
        operator_name: str = "Operator",
        enable_audit_log: bool | None = None,
        audit_log_path: str = "audit/nist_ai_rmf.jsonl",
        human_oversight_callback: Callable | None = None,
        transparency_disclosure: str | None = None,
        check_high_harm_domains: bool = True,
        check_bias_risk: bool = True,
        check_opacity: bool = True,
        check_deception: bool = True,
        strict_mode: bool = True,
        **kwargs,
    ):
        if isinstance(impact_level, str):
            impact_level = ImpactLevel(impact_level.lower())
        self.impact_level = impact_level
        self.system_name = system_name
        self.operator_name = operator_name

        # MANAGE 2.4 — monitoring logs; default on for critical/high
        self.enable_audit_log = (
            enable_audit_log
            if enable_audit_log is not None
            else (impact_level in (ImpactLevel.CRITICAL, ImpactLevel.HIGH))
        )
        self.audit_log_path = Path(audit_log_path)
        self.human_oversight_callback = human_oversight_callback

        # GOVERN 1.7 — transparency disclosure
        self.transparency_disclosure = transparency_disclosure or (
            f"[This response was generated by an AI system operated by {operator_name}. "
            "For questions about this AI system, contact your operator.]"
            if impact_level in (ImpactLevel.CRITICAL, ImpactLevel.HIGH)
            else None
        )

        self.check_high_harm_domains = check_high_harm_domains
        self.check_bias_risk = check_bias_risk
        self.check_opacity = check_opacity
        self.check_deception = check_deception
        self.strict_mode = strict_mode

        if self.enable_audit_log:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    async def check(self, content: str, context: dict) -> CheckResult:
        findings: list[Finding] = []
        rmf_functions_triggered: set[str] = set()
        stage = context.get("guardrail_stage", "input")

        # --- MAP 5.1 / MAP 1.1: High-harm domain detection ---
        if self.check_high_harm_domains:
            for pattern, description in HIGH_HARM_DOMAIN_PATTERNS:
                if pattern.search(content):
                    findings.append(
                        Finding(
                            guard_name=self.name,
                            severity=Severity.HIGH,
                            category="nist_rmf_high_harm_domain",
                            description=description,
                            metadata={"rmf_function": "MAP", "subcategory": "MAP 5.1"},
                        )
                    )
                    rmf_functions_triggered.add("MAP")

        # --- MAP 2.2 / MEASURE 2.5: Bias and fairness risk ---
        if self.check_bias_risk:
            for pattern, description in BIAS_RISK_PATTERNS:
                if pattern.search(content):
                    findings.append(
                        Finding(
                            guard_name=self.name,
                            severity=Severity.MEDIUM,
                            category="nist_rmf_bias_risk",
                            description=description,
                            metadata={"rmf_function": "MEASURE", "subcategory": "MEASURE 2.5"},
                        )
                    )
                    rmf_functions_triggered.update({"MAP", "MEASURE"})

        # --- GOVERN 1.7 / MANAGE 2.4: Opacity and lack of oversight ---
        if self.check_opacity:
            for pattern, description in OPACITY_PATTERNS:
                if pattern.search(content):
                    findings.append(
                        Finding(
                            guard_name=self.name,
                            severity=Severity.MEDIUM,
                            category="nist_rmf_opacity",
                            description=description,
                            metadata={"rmf_function": "GOVERN", "subcategory": "GOVERN 1.7"},
                        )
                    )
                    rmf_functions_triggered.update({"GOVERN", "MANAGE"})

        # --- GOVERN 1.1: Deception / hidden AI nature ---
        if self.check_deception:
            for pattern, description in DECEPTION_PATTERNS:
                if pattern.search(content):
                    findings.append(
                        Finding(
                            guard_name=self.name,
                            severity=Severity.CRITICAL,
                            category="nist_rmf_deception",
                            description=description,
                            metadata={"rmf_function": "GOVERN", "subcategory": "GOVERN 1.1"},
                        )
                    )
                    rmf_functions_triggered.add("GOVERN")

        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        has_critical = bool(critical_findings)

        # --- MANAGE 1.3: Human oversight gate for critical/high impact ---
        if (
            self.impact_level in (ImpactLevel.CRITICAL, ImpactLevel.HIGH)
            and self.human_oversight_callback
        ):
            needs_oversight = any(
                f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings
            )
            if needs_oversight:
                findings.append(
                    Finding(
                        guard_name=self.name,
                        severity=Severity.MEDIUM,
                        category="nist_rmf_human_oversight",
                        description="MANAGE 1.3 — Human oversight required for this high-impact AI interaction.",
                        metadata={"rmf_function": "MANAGE", "subcategory": "MANAGE 1.3"},
                    )
                )
                rmf_functions_triggered.add("MANAGE")

                approved = await self.human_oversight_callback(content, context)
                if not approved:
                    await self._write_audit_log(
                        content,
                        findings,
                        "blocked_human_oversight",
                        rmf_functions_triggered,
                        context,
                    )
                    return CheckResult(
                        passed=False,
                        action=Action.HUMAN,
                        findings=findings,
                        sanitized_content=content,
                        rejection_message="This request requires human review before proceeding (NIST AI RMF MANAGE 1.3).",
                    )

        # --- MANAGE 2.4: Write monitoring log ---
        if self.enable_audit_log:
            action_label = "blocked" if (has_critical and self.strict_mode) else "allowed"
            await self._write_audit_log(
                content, findings, action_label, rmf_functions_triggered, context
            )

        # --- Block on critical findings (GOVERN 1.1 deception) ---
        if has_critical and self.strict_mode:
            return CheckResult(
                passed=False,
                action=Action.BLOCK,
                findings=findings,
                sanitized_content=content,
                rejection_message=(
                    "This request was blocked: it contains content that violates AI trustworthiness "
                    "requirements under the NIST AI Risk Management Framework (AI RMF 1.0)."
                ),
            )

        # --- GOVERN 1.7: Append transparency disclosure on output stage ---
        sanitized = content
        if self.transparency_disclosure and stage == "output":
            sanitized = f"{content}\n\n{self.transparency_disclosure}"

        return CheckResult(
            passed=True,
            action=Action.ALLOW if not findings else Action.FLAG,
            findings=findings,
            sanitized_content=sanitized,
            metadata={
                "impact_level": self.impact_level.value,
                "system_name": self.system_name,
                "nist_ai_rmf_checked": True,
                "rmf_functions_triggered": sorted(rmf_functions_triggered),
            },
        )

    async def _write_audit_log(
        self,
        content: str,
        findings: list[Finding],
        action: str,
        rmf_functions: set[str],
        context: dict,
    ) -> None:
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        event = NISTAuditEvent(
            system_name=self.system_name,
            operator_name=self.operator_name,
            impact_level=self.impact_level.value,
            stage=context.get("guardrail_stage", "unknown"),
            action_taken=action,
            rmf_functions_triggered=sorted(rmf_functions),
            findings_count=len(findings),
            user_id=context.get("user_id", "anonymous"),
            session_id=context.get("session_id", ""),
            content_hash=content_hash,
            metadata={"finding_categories": list({f.category for f in findings})},
        )
        try:
            with open(self.audit_log_path, "a") as f:
                f.write(event.to_json() + "\n")
        except Exception:
            pass  # Audit log failure must not block the application

    def compliance_summary(self) -> dict:
        """Human-readable summary of active NIST AI RMF controls."""
        return {
            "framework": "NIST AI Risk Management Framework (AI RMF 1.0)",
            "published": "2023-01-26",
            "system_name": self.system_name,
            "operator": self.operator_name,
            "impact_level": self.impact_level.value,
            "checks_implemented": {
                "GOVERN 1.1 — Deception / hidden AI nature": self.check_deception,
                "GOVERN 1.7 — Transparency disclosure": bool(self.transparency_disclosure),
                "MAP 5.1   — High-harm domain detection": self.check_high_harm_domains,
                "MAP 2.2   — Bias / protected attribute detection": self.check_bias_risk,
                "MEASURE 2.5 — Fairness risk flagging": self.check_bias_risk,
                "MANAGE 1.3 — Human oversight gate": bool(self.human_oversight_callback),
                "MANAGE 2.4 — Monitoring / audit log": self.enable_audit_log,
            },
            "audit_log_path": str(self.audit_log_path),
        }
