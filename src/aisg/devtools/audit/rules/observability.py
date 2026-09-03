"""aisg/devtools/audit/rules/observability.py
--------------------------------------------
P7 absence rules: AUD-701 no LLM observability, AUD-702 no tool-call audit log,
AUD-703 no incident path.

All three are `basis: absence` and `requires_ai_surface: true`. Each fires on what
the inventory does NOT contain, so every finding names the symbols that were looked
for: an absence finding that does not say what was searched cannot be checked.

Generic APM (`inventory.observability[].lib` prefixed `apm:`) never satisfies
AUD-701. Sentry or Datadog trace exceptions and latency, not prompts, completions
or tool calls; their presence yields the `low` sub-finding `AUD-701/apm-only`
rather than silence.
"""

from __future__ import annotations

from typing import Any

from aisg.devtools.audit.model import (
    AuditContext,
    Basis,
    Evidence,
    EvidenceKind,
    Finding,
    MatchKind,
    Recommendation,
    Scope,
    Severity,
    Tier,
    Unit,
)
from aisg.devtools.audit.rules import AuditRule, hits_in, unit_of

__all__ = [
    "RULES",
    "NoIncidentPath",
    "NoLLMObservability",
    "NoToolCallAuditLog",
]

_APM_PREFIX = "apm:"

# Named so the finding text says what was searched for (mirrors patterns.py; the
# tables there are the source of truth, these strings are only for the message).
# Snippets are capped at 160 characters, so each list has a short form for the
# snippet and the full form for `notes`.
_LLM_OBSERVABILITY_SHORT = (
    "langfuse, langsmith, traceloop, gen_ai.*, TelemetryProvider, helicone, phoenix, weave, ..."
)
_LLM_OBSERVABILITY_NAMES = (
    "langfuse, langsmith, LANGCHAIN_TRACING, traceloop/openllmetry, gen_ai.* OTel "
    "attributes, TelemetryProvider, helicone, braintrust, arize/phoenix, wandb, weave"
)
_AUDIT_LOG_NAMES = "AuditLogger, audit_log, audit.log, structlog, tool_call_log, record_tool_call"
_INCIDENT_PATH_SHORT = (
    "SECURITY.md, INCIDENT*.md, docs/incident*, runbook*, ISSUE_TEMPLATE/*security*"
)
_INCIDENT_PATH_NAMES = (
    "SECURITY.md, INCIDENT*.md, docs/incident*, runbook*, "
    ".github/ISSUE_TEMPLATE/*security*, or a system-card incident_contact"
)


def _entries(ctx: AuditContext, section: str) -> list[dict[str, Any]]:
    """One inventory section as a list of dicts; anything malformed is skipped."""
    raw = getattr(ctx.inventory, section, None) or []
    return [entry for entry in raw if isinstance(entry, dict)]


def _owning_unit(ctx: AuditContext, relpath: str) -> Unit | None:
    """
    The Unit that owns `relpath`: through the walk's file records when they exist,
    else the unit with the longest root prefix (a hand-built context has no records).
    """
    unit = unit_of(ctx, relpath)
    if unit is not None:
        return unit
    key = relpath.replace("\\", "/")
    best: Unit | None = None
    for candidate in ctx.inventory.units:
        root = candidate.root or "."
        if root == "." or key == root or key.startswith(root.rstrip("/") + "/"):
            if best is None or len(root) > len(best.root or "."):
                best = candidate
    return best


def _unit_scope(unit: Unit) -> Scope:
    return Scope(kind="unit", unit=unit.id, name=unit.root or ".")


class NoLLMObservability(AuditRule):
    """AUD-701: an AI-surface unit with no LLM-specific tracing symbol."""

    id = "AUD-701"
    title = "No observability on LLM calls"
    priority = 7
    severity = Severity.MEDIUM
    basis = Basis.ABSENCE
    evidence_kind = EvidenceKind.ABSENCE
    match_kind = MatchKind.STRUCTURED
    requires_ai_surface = True
    measured_precision = None
    tier = Tier.T2
    controls = (
        "ASI08",
        "ASI10",
        "LLM10",
        "EU:Art.12",
        "EU:Art.26",
        "NIST:MEASURE-2.4",
        "NIST:MANAGE-4.1",
    )
    related_lint_rules = ("EU-AIA-012a",)
    known_failure_modes = (
        "Tracing wired through a wrapper module the symbol tables do not name is reported "
        "as absent.",
        "A vendored or renamed import (`import langfuse as lf` is caught, a private fork "
        "is not) is reported as absent.",
        "Observability configured outside the tree (a sidecar, a gateway, an env-only "
        "OTel exporter) is invisible to a static scan.",
        "A tracing import that is never called still satisfies the rule: presence of the "
        "symbol is what is checked, not that spans are emitted.",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Trace every LLM call and tool call with prompt, completion, model id, latency "
            "and cost, so incidents can be reconstructed after the fact."
        ),
        alternatives=(
            "Emit OpenTelemetry GenAI semantic-convention spans (gen_ai.* attributes) from "
            "your existing OTel setup; no new vendor is needed.",
            "Instrument with Langfuse, LangSmith, Traceloop/OpenLLMetry, Helicone, "
            "Braintrust, Arize Phoenix or W&B Weave.",
            "If the pipeline runs through aisg, construct aisg.modules.observability.otel."
            "TelemetryProvider once per process and point it at your collector.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        by_unit: dict[str, list[dict[str, Any]]] = {}
        for entry in _entries(ctx, "observability"):
            file = str(entry.get("file") or "")
            unit = _owning_unit(ctx, file) if file else None
            if unit is None:
                continue
            by_unit.setdefault(unit.id, []).append(entry)

        findings: list[Finding] = []
        for unit in sorted(ctx.inventory.units, key=lambda u: (u.root or ".", u.id)):
            if not unit.ai_surface:
                continue
            entries = by_unit.get(unit.id, [])
            llm = [e for e in entries if not str(e.get("lib") or "").startswith(_APM_PREFIX)]
            if llm:
                continue
            apm = sorted(
                (e for e in entries if str(e.get("lib") or "").startswith(_APM_PREFIX)),
                key=lambda e: (str(e.get("file") or ""), int(e.get("line") or 0)),
            )
            notes = (
                f"unit {unit.id} has an AI surface and none of the LLM observability symbols "
                f"({_LLM_OBSERVABILITY_NAMES}) appears in it"
            )
            if apm:
                first = apm[0]
                file = str(first.get("file") or unit.root or ".")
                line = int(first.get("line") or 0)
                libs = ", ".join(sorted({str(e.get("lib") or "")[len(_APM_PREFIX) :] for e in apm}))
                why = (
                    f"generic APM present ({libs}); no LLM call tracing symbol in unit "
                    f"{unit.id} ({_LLM_OBSERVABILITY_SHORT})"
                )
                findings.append(
                    self.finding(
                        file=file,
                        line=line,
                        snippet=why,
                        evidence=[
                            Evidence(role="match", file=file, line=line, snippet=f"apm: {libs}"),
                            Evidence(role="absence", file=unit.root or ".", line=0, snippet=why),
                        ],
                        scope=_unit_scope(unit),
                        severity=Severity.LOW,
                        sub="apm-only",
                        title="APM present, LLM call tracing not evident",
                        notes=f"generic APM ({libs}) traces nothing about prompts or tool calls; "
                        + notes,
                    )
                )
                continue
            finding = self.absence_finding(
                unit=unit,
                why=f"no LLM observability symbol in unit {unit.id} ({_LLM_OBSERVABILITY_SHORT})",
            )
            finding.notes = notes
            findings.append(finding)
        return findings


class NoToolCallAuditLog(AuditRule):
    """AUD-702: tools are defined in a unit and nothing in that unit records tool calls."""

    id = "AUD-702"
    title = "No tool-call audit log"
    priority = 7
    severity = Severity.HIGH
    basis = Basis.ABSENCE
    evidence_kind = EvidenceKind.ABSENCE
    match_kind = MatchKind.STRUCTURED
    requires_ai_surface = True
    measured_precision = None
    tier = Tier.T2
    controls = (
        "ASI02",
        "ASI10",
        "LLM06",
        "EU:Art.12",
        "EU:Art.14",
        "NIST:MEASURE-2.4",
        "NIST:MANAGE-4.1",
    )
    related_lint_rules = ("EU-AIA-012a", "ALIGN-003")
    known_failure_modes = (
        "A tool-call log written through a symbol outside AUDIT_LOG_SYMBOLS (a plain "
        "`logger.info` in the dispatcher, a database insert) is reported as absent.",
        "An audit symbol anywhere in the unit satisfies the rule even when the tool "
        "dispatcher never reaches it: presence is checked, not the call path.",
        "Tools recorded by the host (Claude Code, an MCP gateway) rather than by the "
        "repository are invisible here.",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Record every tool invocation -- name, arguments (redacted), caller, outcome, "
            "timestamp -- to an append-only log before the tool runs."
        ),
        alternatives=(
            "Wrap the tool dispatcher with structlog (or the standard logging module) bound "
            "to a dedicated, append-only audit stream.",
            "Emit tool calls as OpenTelemetry spans with gen_ai.tool.* attributes to the "
            "same collector as the LLM spans.",
            "If the pipeline runs through aisg, enable AuditLogger; note that its log() is "
            "async but writes with blocking I/O.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        tools_by_unit: dict[str, list[dict[str, Any]]] = {}
        for tool in _entries(ctx, "tools"):
            unit_id = tool.get("unit")
            if not unit_id:
                unit = _owning_unit(ctx, str(tool.get("file") or ""))
                unit_id = unit.id if unit is not None else None
            if unit_id is None:
                continue
            tools_by_unit.setdefault(str(unit_id), []).append(tool)

        findings: list[Finding] = []
        for unit in sorted(ctx.inventory.units, key=lambda u: (u.root or ".", u.id)):
            tools = tools_by_unit.get(unit.id)
            if not tools:
                continue
            if hits_in(ctx, "audit_log", unit=unit.id):
                continue
            names = sorted({str(t.get("name") or t.get("id") or "?") for t in tools})
            shown = ", ".join(names[:4]) + (", ..." if len(names) > 4 else "")
            finding = self.absence_finding(
                unit=unit,
                why=(
                    f"{len(tools)} tool(s) in unit {unit.id} ({shown}); no audit-log symbol "
                    f"(AuditLogger, audit_log, structlog, tool_call_log, record_tool_call)"
                ),
            )
            finding.notes = (
                f"tools defined in unit {unit.id}: {', '.join(names)}; none of the audit-log "
                f"symbols ({_AUDIT_LOG_NAMES}) appears in that unit"
            )
            findings.append(finding)
        return findings


class NoIncidentPath(AuditRule):
    """AUD-703: nothing in the repository says who to tell when the system misbehaves."""

    id = "AUD-703"
    title = "No incident path"
    priority = 7
    severity = Severity.LOW
    basis = Basis.ABSENCE
    evidence_kind = EvidenceKind.ABSENCE
    match_kind = MatchKind.STRUCTURED
    requires_ai_surface = True
    measured_precision = None
    tier = Tier.T2
    controls = (
        "ASI08",
        "ASI10",
        "EU:Art.26",
        "EU:Art.73",
        "NIST:GOVERN-4.3",
        "NIST:MANAGE-4.3",
    )
    related_lint_rules = ("EU-AIA-009a",)
    known_failure_modes = (
        "An incident process documented under a name the globs do not cover (ONCALL.md, "
        "a wiki link in the README) is reported as absent.",
        "A SECURITY.md that exists but is empty or boilerplate satisfies the rule: the "
        "file's presence is checked, not its content.",
        "A contact declared under a key other than incident_contact / contact / "
        "security_contact / incident.contact in the system card is not seen.",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Write down who is paged when the AI system misbehaves, how a user reports "
            "harm, and how the system is disabled, and keep that text in the repository."
        ),
        alternatives=(
            "Add a SECURITY.md with a reporting address and an expected response time "
            "(GitHub surfaces it on the repository's Security tab).",
            "Add a runbook (runbook.md or docs/incident-response.md) covering detection, "
            "kill switch, rollback and user notification.",
            "If you keep an ai-system-card.yaml (for example from `aisg init`), fill in "
            "incident_contact so the card carries the contact too.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        # Repo-level, so the AI-surface gate is applied here as well as in run_rules:
        # a tree with no AI surface has nothing this rule is about.
        if not any(unit.ai_surface for unit in ctx.inventory.units):
            return []
        incident_path = getattr(ctx.inventory, "incident_path", None) or []
        if incident_path:
            return []
        card = getattr(ctx.inventory, "system_card", None)
        contact = card.get("incident_contact") if isinstance(card, dict) else None
        if contact:
            return []
        card_note = ""
        if isinstance(card, dict) and card.get("file"):
            card_note = f"; {card.get('file')} has no incident_contact"
        finding = self.absence_finding(
            unit=None,
            why=f"no incident path{card_note}; looked for {_INCIDENT_PATH_SHORT}",
        )
        finding.notes = f"none of {_INCIDENT_PATH_NAMES} is present" + (
            f"; the system card {card.get('file')} names no contact" if card_note else ""
        )
        return [finding]


RULES: list[type[AuditRule]] = [NoLLMObservability, NoToolCallAuditLog, NoIncidentPath]
