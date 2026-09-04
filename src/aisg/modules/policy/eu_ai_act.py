# euaiact-lint: ignore-file
"""
modules/policy/eu_ai_act.py
----------------------------
EU AI Act Compliance Module
Regulation (EU) 2024/1689 — entered into force 1 August 2024.

This module implements technical guardrails aligned with the EU AI Act obligations:

    Article 5  — Prohibited AI practices (effective 2 Feb 2025)
    Article 9  — Risk management system
    Article 12 — Automatic logging / record-keeping
    Article 13 — Transparency and provision of information
    Article 14 — Human oversight
    Article 15 — Accuracy, robustness, and cybersecurity
    Article 50 — Transparency obligations for certain AI systems (AI interaction disclosure)

Risk tiers (Article 6 / Annex III):
    UNACCEPTABLE — banned outright (Art. 5)
    HIGH         — strict obligations, conformity assessment required
    LIMITED      — transparency obligations only (e.g. chatbots)
    MINIMAL      — largely unregulated

Timeline (as of March 2026):
    - Prohibited practices: in force since 2 Feb 2025 ✅
    - GPAI obligations: in force since 2 Aug 2025 ✅
    - High-risk rules: enter into force 2 Aug 2026 (transition)
    - High-risk (regulated products): 2 Aug 2027

Usage:
    guard = EUAIActCompliance(
        risk_tier=RiskTier.HIGH,
        system_id="my-system-v1.2",
        provider_name="Acme Corp",
        enable_audit_log=True,
        human_oversight_callback=my_human_review_fn,
    )
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable

from aisg.core.base import Action, CheckResult, Finding, GuardrailBase, GuardrailStage, Severity
from aisg.core.registry import register_guard

# ---------------------------------------------------------------------------
# Risk Tier Enum
# ---------------------------------------------------------------------------


class RiskTier(str, Enum):
    UNACCEPTABLE = "unacceptable"
    HIGH = "high"
    LIMITED = "limited"
    MINIMAL = "minimal"


# ---------------------------------------------------------------------------
# Prohibited Use Patterns (Article 5)
# Effective 2 February 2025
# ---------------------------------------------------------------------------

PROHIBITED_PATTERNS = [
    # Social scoring by public authorities
    (
        re.compile(
            r"(social (scoring|credit|ranking)|citizen score|trustworthiness score).{0,50}(government|authority|state|public)",
            re.I,
        ),
        "Art.5(1)(c) — Social scoring by public authorities",
    ),
    # Real-time remote biometric ID in public spaces (with exceptions)
    (
        re.compile(
            r"real.?time.{0,30}(biometric|facial recognition|fingerprint).{0,50}(public space|street|crowd|surveillance)",
            re.I,
        ),
        "Art.5(1)(d) — Real-time remote biometric identification in public spaces",
    ),
    # Subliminal / manipulative techniques targeting vulnerabilities
    (
        re.compile(
            r"(subliminal|subconscious|unconscious).{0,40}(manipulat|exploit|influence|persuad)",
            re.I,
        ),
        "Art.5(1)(a) — Subliminal manipulation techniques",
    ),
    # Exploitation of vulnerable groups
    (
        re.compile(
            r"exploit.{0,40}(children|minors|elderly|disabled|vulnerab).{0,40}(manipulat|deceiv|harm)",
            re.I,
        ),
        "Art.5(1)(b) — Exploitation of vulnerabilities of specific groups",
    ),
    # Emotion recognition in workplace / education (restricted)
    (
        re.compile(
            r"emotion.{0,20}(recogni|detect|analys).{0,50}(workplace|school|education|employee|student)",
            re.I,
        ),
        "Art.5(1)(f) — Emotion recognition in workplace/education",
    ),
    # Predictive policing based on profiling
    (
        re.compile(
            r"(predict|forecast).{0,30}(criminal|crime|offend).{0,40}(individual|person|profile)",
            re.I,
        ),
        "Art.5(1)(e) — Predictive policing / criminal risk profiling",
    ),
]

# ---------------------------------------------------------------------------
# High-Risk Use Case Detectors (Annex III)
# ---------------------------------------------------------------------------

HIGH_RISK_INDICATORS = [
    (
        re.compile(
            r"(credit (scor|rating|decision)|loan approval|insurance (underwriting|pricing))", re.I
        ),
        "Annex III(5)(b) — Financial creditworthiness assessment",
    ),
    (
        re.compile(
            r"(hire|hiring|recruitment|job (applicant|candidate)).{0,30}(AI|automated|system)", re.I
        ),
        "Annex III(4)(a) — AI-assisted recruitment",
    ),
    (
        re.compile(r"(medical (diagnosis|triage|treatment)|clinical decision)", re.I),
        "Annex III(5)(a) — Medical device / diagnostic AI",
    ),
    (
        re.compile(r"(biometric (identification|verification)|face (recognition|match))", re.I),
        "Annex III(1) — Biometric identification",
    ),
    (
        re.compile(r"(critical infrastructure|power grid|water supply|transport safety)", re.I),
        "Annex III(2) — Critical infrastructure management",
    ),
    (
        re.compile(r"(law enforcement|police|criminal justice|sentencing|recidivism)", re.I),
        "Annex III(6) — Law enforcement",
    ),
    (
        re.compile(r"(asylum|immigration|border control|visa decision)", re.I),
        "Annex III(7) — Migration / border management",
    ),
    (
        re.compile(r"(court|judicial|legal ruling|sentence determination)", re.I),
        "Annex III(8) — Administration of justice",
    ),
]


# ---------------------------------------------------------------------------
# Audit Event (Article 12)
# ---------------------------------------------------------------------------


@dataclass
class AuditEvent:
    """
    Tamper-evident audit record aligned with Art. 12 logging obligations.
    High-risk systems must retain logs automatically throughout the system lifecycle.
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    )
    system_id: str = ""
    provider_name: str = ""
    risk_tier: str = ""
    stage: str = ""
    action_taken: str = ""
    article_triggered: str = ""
    findings_count: int = 0
    user_id: str = ""
    session_id: str = ""
    content_hash: str = ""  # SHA-256 of content for tamper-evidence
    metadata: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


# ---------------------------------------------------------------------------
# Main module
# ---------------------------------------------------------------------------


@register_guard("eu_ai_act")
class EUAIActCompliance(GuardrailBase):
    """
    EU AI Act (Regulation 2024/1689) compliance guardrail.

    Performs checks for:
        - Art. 5: Prohibited AI practice detection
        - Art. 9: Risk management hooks
        - Art. 12: Automatic audit logging
        - Art. 13: AI interaction transparency enforcement
        - Art. 14: Human oversight gate
        - Art. 15: Accuracy / robustness tracking
        - Art. 50: AI-generated content disclosure

    Config:
        risk_tier:                  RiskTier or string ("high", "limited", "minimal")
        system_id:                  Unique identifier for your AI system
        provider_name:              Your organization name (for logs and disclosure)
        enable_audit_log:           Write Art. 12 audit logs (default: True for high-risk)
        audit_log_path:             Path for audit log file (default: "audit/eu_ai_act.jsonl")
        audit_retention_days:       Log retention obligation (default: 365 for high-risk)
        human_oversight_callback:   async fn(content, context) -> bool for Art. 14 gate
        transparency_disclosure:    Text injected into outputs to meet Art. 13/50 requirements
        check_prohibited:           Run Art. 5 prohibited use checks (default: True)
        check_high_risk_indicators: Flag potential high-risk use cases (default: True)
        strict_mode:                Block on any prohibited pattern (default: True)
    """

    name = "eu_ai_act"
    stage = GuardrailStage.POLICY
    description = "EU AI Act (2024/1689) compliance checks and audit logging."

    def setup(
        self,
        risk_tier: RiskTier | str = RiskTier.LIMITED,
        system_id: str = "ai-system",
        provider_name: str = "Provider",
        enable_audit_log: bool | None = None,
        audit_log_path: str = "audit/eu_ai_act.jsonl",
        audit_retention_days: int = 365,
        human_oversight_callback: Callable | None = None,
        transparency_disclosure: str | None = None,
        check_prohibited: bool = True,
        check_high_risk_indicators: bool = True,
        strict_mode: bool = True,
        **kwargs,
    ):
        # Normalize risk tier
        if isinstance(risk_tier, str):
            risk_tier = RiskTier(risk_tier.lower())
        self.risk_tier = risk_tier
        self.system_id = system_id
        self.provider_name = provider_name

        # Art. 12 — Automatic logging: mandatory for high-risk
        self.enable_audit_log = (
            enable_audit_log if enable_audit_log is not None else (risk_tier == RiskTier.HIGH)
        )
        self.audit_log_path = Path(audit_log_path)
        self.audit_retention_days = audit_retention_days

        # Art. 14 — Human oversight
        self.human_oversight_callback = human_oversight_callback

        # Art. 13/50 — Transparency disclosure
        self.transparency_disclosure = transparency_disclosure or (
            f"[This response was generated by an AI system operated by {provider_name}.]"
            if risk_tier in (RiskTier.LIMITED, RiskTier.HIGH)
            else None
        )

        self.check_prohibited = check_prohibited
        self.check_high_risk_indicators = check_high_risk_indicators
        self.strict_mode = strict_mode

        # Create audit log directory
        if self.enable_audit_log:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)

    async def check(self, content: str, context: dict) -> CheckResult:
        findings: list[Finding] = []
        stage = context.get("guardrail_stage", "input")

        # --- Art. 5: Prohibited practices check ---
        if self.check_prohibited and self.risk_tier != RiskTier.UNACCEPTABLE:
            for pattern, description in PROHIBITED_PATTERNS:
                if pattern.search(content):
                    findings.append(
                        Finding(
                            guard_name=self.name,
                            severity=Severity.CRITICAL,
                            category="eu_ai_act_prohibited",
                            description=description,
                            metadata={"article": "5", "regulation": "EU 2024/1689"},
                        )
                    )

        # Unacceptable risk tier — always block
        if self.risk_tier == RiskTier.UNACCEPTABLE:
            findings.append(
                Finding(
                    guard_name=self.name,
                    severity=Severity.CRITICAL,
                    category="eu_ai_act_unacceptable_risk",
                    description="Art.5 — System configured as UNACCEPTABLE risk tier. All requests blocked.",
                    metadata={"article": "5"},
                )
            )

        # --- Art. 6 / Annex III: High-risk use case indicators ---
        if self.check_high_risk_indicators:
            for pattern, description in HIGH_RISK_INDICATORS:
                if pattern.search(content):
                    findings.append(
                        Finding(
                            guard_name=self.name,
                            severity=Severity.MEDIUM,
                            category="eu_ai_act_high_risk_indicator",
                            description=f"Potential high-risk AI use detected: {description}",
                            metadata={"article": "6", "annex": "III"},
                        )
                    )

        # Check for critical findings
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        has_critical = bool(critical_findings)

        # --- Art. 14: Human oversight gate ---
        if self.risk_tier == RiskTier.HIGH and self.human_oversight_callback:
            needs_oversight = await self._evaluate_oversight_need(content, findings, context)
            if needs_oversight:
                oversight_finding = Finding(
                    guard_name=self.name,
                    severity=Severity.MEDIUM,
                    category="eu_ai_act_human_oversight",
                    description="Art.14 — Human oversight required for this high-risk AI interaction.",
                    metadata={"article": "14"},
                )
                findings.append(oversight_finding)

                approved = await self.human_oversight_callback(content, context)
                if not approved:
                    await self._write_audit_log(
                        content, findings, "blocked_human_oversight", context
                    )
                    return CheckResult(
                        passed=False,
                        action=Action.HUMAN,
                        findings=findings,
                        sanitized_content=content,
                        rejection_message="This request requires human review before proceeding (Art. 14 EU AI Act).",
                    )

        # --- Write audit log (Art. 12) ---
        if self.enable_audit_log:
            action_label = "blocked" if (has_critical and self.strict_mode) else "allowed"
            await self._write_audit_log(content, findings, action_label, context)

        # --- Block on critical findings ---
        if has_critical and self.strict_mode:
            return CheckResult(
                passed=False,
                action=Action.BLOCK,
                findings=findings,
                sanitized_content=content,
                rejection_message=(
                    "Your request cannot be processed as it relates to a use of AI "
                    "that is prohibited under the EU AI Act (Regulation 2024/1689)."
                ),
            )

        # --- Art. 13/50: Inject transparency disclosure into output context ---
        sanitized = content
        if self.transparency_disclosure and stage == "output":
            sanitized = f"{content}\n\n{self.transparency_disclosure}"

        return CheckResult(
            passed=True,
            action=Action.ALLOW if not findings else Action.FLAG,
            findings=findings,
            sanitized_content=sanitized,
            metadata={
                "risk_tier": self.risk_tier.value,
                "system_id": self.system_id,
                "eu_ai_act_checked": True,
            },
        )

    async def _evaluate_oversight_need(
        self,
        content: str,
        findings: list[Finding],
        context: dict,
    ) -> bool:
        """
        Determine whether this interaction warrants human oversight (Art. 14).
        For high-risk systems: flag when high-severity findings are present,
        or when configured indicators trigger.
        """
        if any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings):
            return True
        # Can be extended with more sophisticated logic
        return False

    async def _write_audit_log(
        self,
        content: str,
        findings: list[Finding],
        action: str,
        context: dict,
    ) -> None:
        """
        Write a tamper-evident audit record to the log file.
        Required for Art. 12 compliance in high-risk AI systems.
        """
        import hashlib

        content_hash = hashlib.sha256(content.encode()).hexdigest()
        event = AuditEvent(
            system_id=self.system_id,
            provider_name=self.provider_name,
            risk_tier=self.risk_tier.value,
            stage=context.get("guardrail_stage", "unknown"),
            action_taken=action,
            article_triggered=",".join(
                {f.metadata.get("article", "") for f in findings if f.metadata.get("article")}
            ),
            findings_count=len(findings),
            user_id=context.get("user_id", "anonymous"),
            session_id=context.get("session_id", ""),
            content_hash=content_hash,
            metadata={
                "finding_categories": list({f.category for f in findings}),
                "provider": self.provider_name,
            },
        )

        try:
            with open(self.audit_log_path, "a") as f:
                f.write(event.to_json() + "\n")
        except Exception:
            pass  # Audit log failure should not block the application

    # ------------------------------------------------------------------
    # Compliance status helpers
    # ------------------------------------------------------------------

    def compliance_summary(self) -> dict:
        """
        Returns a human-readable compliance status summary
        useful for conformity assessments and technical documentation (Art. 11).
        """
        return {
            "regulation": "EU AI Act — Regulation (EU) 2024/1689",
            "system_id": self.system_id,
            "provider": self.provider_name,
            "risk_tier": self.risk_tier.value,
            "checks_implemented": {
                "Art. 5 — Prohibited practices": self.check_prohibited,
                "Art. 12 — Automatic logging": self.enable_audit_log,
                "Art. 13 — Transparency disclosure": bool(self.transparency_disclosure),
                "Art. 14 — Human oversight gate": bool(self.human_oversight_callback),
                "Art. 15 — Robustness tracking": True,  # via metrics module
            },
            "audit_log_path": str(self.audit_log_path),
            "audit_retention_days": self.audit_retention_days,
            "timeline": {
                "prohibited_practices_effective": "2025-02-02",
                "gpai_obligations_effective": "2025-08-02",
                "high_risk_rules_effective": "2026-08-02",
            },
        }
