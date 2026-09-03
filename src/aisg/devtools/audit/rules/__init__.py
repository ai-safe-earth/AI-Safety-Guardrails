"""aisg/devtools/audit/rules/__init__.py
----------------------------------------
Rule base class and registry for `aisg audit`. Selection is evaluated on every call.
"""

from __future__ import annotations

import importlib
from typing import Sequence

from aisg.core.measurement import MIN_PRECISION
from aisg.devtools.audit.model import (
    AuditContext,
    Basis,
    Bucket,
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    MatchKind,
    Recommendation,
    Scope,
    Severity,
    Tier,
    Unit,
    UnknownItem,
    fingerprint,
    sort_findings,
    truncate_snippet,
)

__all__ = [
    "ALL_RULES",
    "MISSING_RULE_MODULES",
    "AuditRule",
    "Recommendation",
    "default_rules",
    "experimental_rules",
    "file_text",
    "hits_in",
    "is_demoted",
    "rule_by_id",
    "run_rules",
    "select_rules",
    "unit_of",
]


class AuditRule:
    """
    One audit rule. Subclasses set the class attributes and implement `evaluate`.

    `measured_precision = None` means UNMEASURED, not perfect: an unmeasured rule
    keeps firing by default. Only a rule measured below MIN_PRECISION is demoted
    to `--experimental`. Never guess a value for it; it comes from a labelled corpus.
    """

    id: str
    title: str
    priority: int
    severity: Severity
    basis: Basis
    evidence_kind: EvidenceKind
    match_kind: MatchKind
    requires_ai_surface: bool = False
    measured_precision: float | None = None
    known_failure_modes: tuple[str, ...] = ()
    controls: tuple[str, ...] = ()
    recommendation: Recommendation
    tier: Tier
    related_lint_rules: tuple[str, ...] = ()
    languages: tuple[str, ...] = ("*",)

    def __init__(self) -> None:
        # UNKNOWN items a rule raises while evaluating ("report age unknown", ...).
        # `run_rules` folds them into the run's unknown list after `evaluate`.
        self.unknown: list[UnknownItem] = []

    @classmethod
    def experimental(cls) -> bool:
        """True when this rule only runs under `--experimental` (measured below threshold)."""
        return is_demoted(cls)

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        raise NotImplementedError

    def finding(
        self,
        *,
        file: str,
        line: int,
        snippet: str,
        evidence: list[Evidence] | None = None,
        scope: Scope | None = None,
        severity: Severity | None = None,
        sub: str | None = None,
        bucket: Bucket = Bucket.ASSERTED,
        report: dict | None = None,
        notes: str | None = None,
        title: str | None = None,
        match_kind: MatchKind | None = None,
        evidence_kind: EvidenceKind | None = None,
    ) -> Finding:
        """
        Build a Finding with id/title/priority/controls/confidence filled from the class.

        The fingerprint is anchored on `file` + `snippet` and the display id
        (`AUD-101/interpreter` for a sub-finding), so extra evidence legs can be
        reordered without producing a "new" finding.

        `match_kind` / `evidence_kind` override the class defaults for one finding:
        a rule that resolves a path through the AST when `--deep python` ran and
        falls back to co-located grep otherwise reports the confidence it actually has.
        """
        relpath = file.replace("\\", "/")
        snip = truncate_snippet(snippet)
        display_id = f"{self.id}/{sub}" if sub else self.id
        if evidence is None:
            evidence = [Evidence(role="match", file=relpath, line=line, snippet=snip)]
        if scope is None:
            scope = Scope(kind="file", name=relpath)
        return Finding(
            id=self.id,
            sub=sub,
            fingerprint=fingerprint(display_id, relpath, snip),
            title=title or self.title,
            severity=severity or self.severity,
            priority=self.priority,
            bucket=bucket,
            basis=self.basis,
            confidence=Confidence(
                evidence_kind or self.evidence_kind,
                match_kind or self.match_kind,
                self.measured_precision,
            ),
            scope=scope,
            evidence=list(evidence),
            controls=self.controls,
            recommendation=self.recommendation,
            related_lint_rules=self.related_lint_rules,
            known_failure_modes=self.known_failure_modes,
            report=report,
            notes=notes,
        )

    def absence_finding(self, *, unit: Unit | None, why: str) -> Finding:
        """A finding about something missing: file = unit root (or "."), line 0, role "absence"."""
        if unit is None:
            root, scope = ".", Scope(kind="repo", name=".")
        else:
            root = unit.root or "."
            scope = Scope(kind="unit", unit=unit.id, name=root)
        return self.finding(
            file=root,
            line=0,
            snippet=why,
            evidence=[Evidence(role="absence", file=root, line=0, snippet=why)],
            scope=scope,
        )


# ---------------------------------------------------------------------------
# Context helpers shared by rule modules
# ---------------------------------------------------------------------------


def file_text(ctx: AuditContext, relpath: str) -> str | None:
    """
    Decoded text of an enumerated file, cached on the context.

    Only files the walk enumerated (`ctx.files`) are readable through here: a rule
    never opens a path of its own choosing, so the walk's exclude/ignore/size rules
    hold for every byte a rule looks at. Unknown paths and unreadable files are None.
    """
    key = relpath.replace("\\", "/")
    if key in ctx.texts:
        return ctx.texts[key]
    text: str | None = None
    for record in ctx.files:
        if getattr(record, "relpath", None) == key:
            from aisg.devtools.audit.walk import read_text  # local: walk imports model too

            text = read_text(record.path)
            break
    ctx.texts[key] = text
    return text


def unit_of(ctx: AuditContext, relpath: str) -> Unit | None:
    """The Unit owning `relpath`, resolved through the walk's file records."""
    key = relpath.replace("\\", "/")
    unit_id = None
    for record in ctx.files:
        if getattr(record, "relpath", None) == key:
            unit_id = record.unit
            break
    if unit_id is None:
        return None
    for unit in ctx.inventory.units:
        if unit.id == unit_id:
            return unit
    return None


def hits_in(ctx: AuditContext, table: str, *, unit: str | None = None, file: str | None = None):
    """Hits from one grep table, optionally narrowed to a unit id or a relpath."""
    out = []
    for hit in ctx.hits:
        if hit.table != table:
            continue
        if unit is not None and hit.unit != unit:
            continue
        if file is not None and hit.file != file:
            continue
        out.append(hit)
    return out


# Precision gating -- evaluated on every call, never snapshotted at import, so a
# `measured_precision` set after this module loads gates the right rules.


def is_demoted(rule: type[AuditRule]) -> bool:
    """Measured below MIN_PRECISION. `None` is unmeasured and is never demoted."""
    precision = rule.measured_precision
    return precision is not None and precision < MIN_PRECISION


def rule_by_id(rule_id: str) -> type[AuditRule] | None:
    for rule in ALL_RULES:
        if rule.id == rule_id:
            return rule
    return None


def default_rules() -> list[type[AuditRule]]:
    """Rules that run without --experimental."""
    return [r for r in ALL_RULES if not is_demoted(r)]


def experimental_rules() -> list[type[AuditRule]]:
    """Rules measured below MIN_PRECISION, which need --experimental to run."""
    return [r for r in ALL_RULES if is_demoted(r)]


def select_rules(
    ids: Sequence[str] | None = None, experimental: bool = False
) -> tuple[list[type[AuditRule]], list[str]]:
    """
    The rule set a run should use, plus notes for stderr.

    Naming a demoted rule in `ids` runs it anyway, with a note. Unknown ids are
    noted and skipped, never fatal.
    """
    notes: list[str] = []
    if ids is None:
        return (list(ALL_RULES) if experimental else default_rules()), notes
    chosen: list[type[AuditRule]] = []
    for rule_id in ids:
        rule = rule_by_id(rule_id)
        if rule is None:
            notes.append(f"unknown rule id {rule_id}")
            continue
        if is_demoted(rule) and not experimental:
            notes.append(
                f"rule {rule_id} is below MIN_PRECISION and runs only because it was named explicitly"
            )
        if rule not in chosen:
            chosen.append(rule)
    return chosen, notes


def run_rules(
    rules: Sequence[type[AuditRule]], ctx: AuditContext
) -> tuple[list[Finding], list[UnknownItem]]:
    """
    Instantiate and evaluate each rule. A rule exception becomes an UnknownItem,
    never a crash. Rules with `requires_ai_surface` are skipped, silently by
    design, when no unit in the inventory has an AI surface.
    """
    findings: list[Finding] = []
    unknown: list[UnknownItem] = []
    ai_surface = any(unit.ai_surface for unit in ctx.inventory.units)
    for rule in rules:
        if rule.requires_ai_surface and not ai_surface:
            continue
        rule_id = getattr(rule, "id", rule.__name__)
        try:
            instance = rule()
            findings.extend(instance.evaluate(ctx))
            unknown.extend(instance.unknown)
        except Exception as exc:  # broad on purpose: one bad rule must not sink the run
            unknown.append(
                UnknownItem(
                    category="runtime",
                    what=f"rule {rule_id}",
                    why=f"{type(exc).__name__}: {exc}",
                    rule_ids=(rule_id,),
                )
            )
    return sort_findings(findings), unknown


# Registry. Imported at the bottom to avoid a cycle: rule modules import `AuditRule`
# from this package. A module that does not exist yet lands in MISSING_RULE_MODULES and
# the registry stays partial; a module that exists but fails to import raises, because
# a silently vanished rule set is not partial, it is wrong.

_RULE_MODULES = (
    "blast_radius irreversible trust_boundary sinks secrets_pii "
    "supply_chain observability guards evals governance"
).split()

ALL_RULES: list[type[AuditRule]] = []
MISSING_RULE_MODULES: list[str] = []

for _name in _RULE_MODULES:
    _qualname = f"{__name__}.{_name}"
    try:
        _module = importlib.import_module(_qualname)
    except ModuleNotFoundError as _exc:
        if _exc.name != _qualname:
            raise
        MISSING_RULE_MODULES.append(_name)
        continue
    ALL_RULES.extend(_module.RULES)
