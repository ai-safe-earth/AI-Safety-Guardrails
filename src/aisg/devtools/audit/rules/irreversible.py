"""aisg/devtools/audit/rules/irreversible.py
-----------------------------------------
P2 rules AUD-201..AUD-203: tools that cannot be undone. An irreversible tool with no
human gate on its call path, a gate that exists but is inert or bypassed, and an
irreversible tool with no dry-run or idempotency affordance.

Tools come through `blast_radius.iter_tools` (AST tier first, grep tier for the rest).
Gates come from `pyfacts.gates` / `pyfacts.fail_open` on the AST tier and from the
`gate_bypass` grep table otherwise; deep evidence wins at the same (file, line).
MCP-served tools are never inspected here: their gates live in the server process.
"""

from __future__ import annotations

import re
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
)
from aisg.devtools.audit.rules import AuditRule, file_text, hits_in
from aisg.devtools.audit.rules.blast_radius import (
    ToolRef,
    deep_covers,
    iter_tools,
    line_text,
    unit_id_of,
    unit_scope,
    window_text,
)

__all__ = ["RULES", "InertGate", "IrreversibleUngated", "NoDryRun", "DRY_RUN_SYMBOLS"]

_TOOL_WINDOW = 40

# Names that mark a rehearsal or a replay-safe call. Matched as a prefix after a
# non-identifier character, so `dry_run_mode` and `previewOnly` count and `undry_run`
# does not; `Idempotency-Key` is the HTTP header spelling.
DRY_RUN_SYMBOLS: tuple[str, ...] = (
    "dry_run",
    "dryRun",
    "idempotency_key",
    "idempotencyKey",
    "Idempotency-Key",
    "preview",
    "plan_only",
    "confirm",
)
_DRY_RUN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:" + "|".join(re.escape(s) for s in DRY_RUN_SYMBOLS) + r")"
)


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (f.location[0], f.location[1], f.sub or ""))


def _irreversible(tool: ToolRef) -> bool:
    return "irreversible" in tool.capabilities


def _function_scope(ctx: AuditContext, file: str, function: Any) -> Scope:
    if function:
        return Scope(kind="function", unit=unit_id_of(ctx, file), name=f"{file}::{function}")
    return Scope(kind="file", unit=unit_id_of(ctx, file), name=file)


# ---------------------------------------------------------------------------
# AUD-201 Irreversible tool with no approval gate
# ---------------------------------------------------------------------------


class IrreversibleUngated(AuditRule):
    id = "AUD-201"
    title = "Irreversible tool with no approval gate"
    priority = 2
    severity = Severity.CRITICAL
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.AST
    tier = Tier.T2
    controls = ("ASI02", "ASI09", "LLM06", "EU:Art.14", "NIST:MANAGE-2.4")
    related_lint_rules = ("EU-AIA-014a", "EU-AIA-014b", "ALIGN-003")
    known_failure_modes = (
        "Name-based capability detection: a tool called `do_thing()` that sends mail or "
        "deletes rows is missed, and a tool called `delete_draft` that only touches local "
        "state is reported.",
        "MCP-served tools are not inspected; their gates live in the server process and "
        "`aisg audit` never talks to it.",
        "AST tier: the gate join follows three call levels from the tool body; a gate deeper "
        "than that, or one applied by the framework at dispatch time, reads as absent.",
        "Grep tier: any APPROVAL_SYMBOLS name in the same unit counts as a gate for every "
        "tool in it, so a gate on one tool hides the others; a gate in another unit is "
        "not seen.",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Put a human approval step on the call path of every tool whose effect cannot "
            "be undone."
        ),
        alternatives=(
            "Return a pending action from the tool and have a separate, human-triggered step "
            "execute it (two-phase commit: propose, then approve).",
            "LangGraph: `interrupt_before` the tool node with a checkpointer; OpenAI Agents "
            "SDK / Anthropic tool use: check `needs_approval` and resume only on an explicit "
            "approve.",
            "Route the action through a ticket, PR or review queue the agent can open but "
            "not merge.",
            "aisg: register the tool with ToolPolicyGuard(require_approval=True, "
            "approval_callback=...) so a denied or timed-out approval is Action.HUMAN, not "
            "a pass.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        joins: dict[str, Any] = {}
        if ctx.pyfacts is not None:
            joins = dict(getattr(ctx.pyfacts, "tool_gate_join", None) or {})
        for tool in iter_tools(ctx):
            if not _irreversible(tool):
                continue
            if tool.deep:
                gate = joins.get(tool.name)
                if gate is not None:
                    # A live gate is a gate; an inert one is AUD-202's finding, not this one.
                    continue
                notes = (
                    f"tool {tool.name} ({tool.kind}) is irreversible; no APPROVAL_SYMBOLS gate "
                    "on its call path (three levels from the tool body)"
                )
            else:
                if tool.gated:
                    continue
                if hits_in(ctx, "approval", unit=tool.unit):
                    continue
                notes = (
                    f"tool {tool.name} ({tool.kind}) is irreversible; no APPROVAL_SYMBOLS name "
                    "within 60 lines of it or anywhere in its unit"
                )
            findings.append(
                self.finding(
                    file=tool.file,
                    line=tool.line,
                    snippet=tool.snippet(ctx),
                    evidence=tool.evidence(ctx),
                    scope=unit_scope(ctx, tool.unit, tool.file),
                    match_kind=tool.match_kind,
                    notes=notes,
                )
            )
        return _sorted(findings)


# ---------------------------------------------------------------------------
# AUD-202 Inert or bypassed gate
# ---------------------------------------------------------------------------


class InertGate(AuditRule):
    id = "AUD-202"
    title = "Inert or bypassed gate"
    priority = 2
    severity = Severity.CRITICAL
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.AST
    tier = Tier.T2
    controls = ("ASI09", "ASI02", "LLM06", "EU:Art.14", "NIST:MANAGE-2.4")
    related_lint_rules = ("EU-AIA-014a", "ALIGN-003")
    known_failure_modes = (
        "Cannot verify a callback that exists but always returns true; that is what "
        "`aisg measure` and a runtime drill are for.",
        "AST tier: only the shapes pydeep knows (`require_approval=True` without "
        "`approval_callback`, `interrupt_before` without a checkpointer, a GATE_BYPASS "
        "literal, an approval call inside a swallowing `except`) are recognised.",
        "Grep tier: a GATE_BYPASS literal in a test or a fixture reads the same as one in "
        "production code.",
        "MCP-served tools are not inspected; a gate switched off in the server's own config "
        "is not seen.",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary="Make the gate fail closed: no callback, no checkpointer or a swallowed error means deny.",
        alternatives=(
            "Pass a real `approval_callback` (or `approver`) and treat a missing one as a "
            "configuration error at startup, not at call time.",
            "LangGraph: compile the graph with a checkpointer whenever `interrupt_before` is "
            "set; without one the interrupt never pauses.",
            "Remove `auto_approve=True` / `human_in_the_loop=False` / `--yes` from production "
            "paths and keep them behind an explicit test-only flag.",
            "aisg: ToolPolicyGuard with `fail_open=False` so an exception in the approval "
            "path returns Action.HUMAN instead of passing.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        deep_lines: set[tuple[str, int]] = set()
        pyfacts = ctx.pyfacts
        if pyfacts is not None:
            for gate in getattr(pyfacts, "gates", None) or []:
                reason = getattr(gate, "inert_reason", None)
                if not reason:
                    continue
                self._deep(ctx, findings, deep_lines, gate, str(reason))
            for gate in getattr(pyfacts, "fail_open", None) or []:
                reason = str(getattr(gate, "inert_reason", None) or "exception swallowed")
                self._deep(ctx, findings, deep_lines, gate, f"fails open: {reason}")
        grep_seen: set[tuple[str, int]] = set()
        for hit in hits_in(ctx, "gate_bypass"):
            key = (hit.file, hit.line)
            if key in deep_lines or key in grep_seen:
                continue
            if deep_covers(ctx, hit.file):
                continue
            grep_seen.add(key)
            findings.append(
                self.finding(
                    file=hit.file,
                    line=hit.line,
                    snippet=hit.snippet,
                    scope=Scope(kind="file", unit=hit.unit, name=hit.file),
                    match_kind=MatchKind.GREP,
                    notes="GATE_BYPASS literal; the gate it switches off is not resolved",
                )
            )
        return _sorted(findings)

    def _deep(
        self,
        ctx: AuditContext,
        findings: list[Finding],
        deep_lines: set[tuple[str, int]],
        gate: Any,
        reason: str,
    ) -> None:
        file = str(getattr(gate, "file", "") or "").replace("\\", "/")
        line = int(getattr(gate, "line", 0) or 0)
        if (file, line) in deep_lines:
            return
        deep_lines.add((file, line))
        symbol = str(getattr(gate, "symbol", "") or "gate")
        snippet = line_text(ctx, file, line) or f"{symbol}: {reason}"
        findings.append(
            self.finding(
                file=file,
                line=line,
                snippet=snippet,
                evidence=[Evidence(role="match", file=file, line=line, snippet=snippet)],
                scope=_function_scope(ctx, file, getattr(gate, "function", None)),
                notes=f"{symbol}: {reason}",
            )
        )


# ---------------------------------------------------------------------------
# AUD-203 No dry-run / idempotency on an irreversible tool
# ---------------------------------------------------------------------------


class NoDryRun(AuditRule):
    id = "AUD-203"
    title = "Irreversible tool without a dry-run or idempotency affordance"
    priority = 2
    severity = Severity.MEDIUM
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.AST
    tier = Tier.T3
    controls = ("ASI02", "LLM06", "NIST:MANAGE-2.3")
    related_lint_rules = ("EU-AIA-015a",)
    known_failure_modes = (
        "Name-based: a rehearsal mode under another name (`simulate`, `what_if`, `noop`) is "
        'reported, and a `confirm` that appears in a string ("confirmation sent") '
        "satisfies the rule without gating anything.",
        f"Grep tier: only the {_TOOL_WINDOW} lines after the tool schema and after a same-file "
        "definition of its name are searched; a flag handled by a helper elsewhere is missed.",
        "MCP-served tools are not inspected; the affordance, if any, lives in the server.",
    )
    recommendation = Recommendation(
        tier=Tier.T3,
        summary=(
            "Give every irreversible tool a rehearsal path and make repeated calls safe to replay."
        ),
        alternatives=(
            "Add a `dry_run: bool` parameter that returns what would happen without doing it, "
            "and default the agent to it until a human flips it.",
            "Accept an `idempotency_key` (or send the `Idempotency-Key` header) so a retried "
            "call does not send twice, charge twice or delete twice.",
            "Split the tool into `plan_<action>` (pure) and `apply_<action>` (effectful) and "
            "expose only the plan step to the model by default.",
            "aisg: put ToolPolicyGuard in front of the tool and keep the apply step behind an "
            "approval callback while the plan step runs freely.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        for tool in iter_tools(ctx):
            if not _irreversible(tool):
                continue
            if self._has_affordance(ctx, tool):
                continue
            findings.append(
                self.finding(
                    file=tool.file,
                    line=tool.line,
                    snippet=tool.snippet(ctx),
                    evidence=tool.evidence(ctx),
                    scope=unit_scope(ctx, tool.unit, tool.file),
                    match_kind=tool.match_kind,
                    notes=f"tool {tool.name} ({tool.kind}) is irreversible; none of "
                    f"{', '.join(DRY_RUN_SYMBOLS)} in its body or signature",
                )
            )
        return _sorted(findings)

    @staticmethod
    def _has_affordance(ctx: AuditContext, tool: ToolRef) -> bool:
        for symbol in tool.body_symbols:
            if _DRY_RUN_RE.search(str(symbol)):
                return True
        texts = [window_text(ctx, tool.file, tool.line, _TOOL_WINDOW)]
        for file, start, end in tool.spans:
            texts.append(window_text(ctx, file, start, max(end - start + 1, 1)))
        if not tool.spans:
            # Grep tier: the schema and the implementation are usually far apart, so also
            # look at the window after a same-file definition of the tool's own name.
            for line in _definition_lines(ctx, tool.file, tool.name):
                texts.append(window_text(ctx, tool.file, line, _TOOL_WINDOW))
        return any(_DRY_RUN_RE.search(text) for text in texts if text)


def _definition_lines(ctx: AuditContext, relpath: str, name: str) -> list[int]:
    """1-based lines where `name` is defined as a function in `relpath` (text match)."""
    text = file_text(ctx, relpath)
    if text is None:
        return []
    rx = re.compile(
        r"^\s*(?:async\s+)?(?:def|function|func)\s+" + re.escape(name) + r"\s*[(<]"
        r"|^\s*(?:const|let|var)\s+" + re.escape(name) + r"\s*=",
        re.M,
    )
    return [text.count("\n", 0, m.start()) + 1 for m in rx.finditer(text)]


RULES = [IrreversibleUngated, InertGate, NoDryRun]
