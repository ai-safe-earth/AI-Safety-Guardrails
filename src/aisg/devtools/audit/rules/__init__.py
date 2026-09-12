# aisg-audit: ignore-file
"""aisg/devtools/audit/rules/__init__.py
----------------------------------------
Rule base class and registry for `aisg audit`. Selection is evaluated on every call.
"""

from __future__ import annotations

import importlib
from typing import NamedTuple, Sequence

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
    Package,
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
    "ALSO_CAP",
    "ALSO_ROLE",
    "MISSING_RULE_MODULES",
    "NOT_ATTRIBUTED",
    "SUBSYSTEMS",
    "SUBSYSTEM_OF_RULE",
    "AuditRule",
    "Candidate",
    "Package",
    "Recommendation",
    "SiteRef",
    "Subsystem",
    "default_rules",
    "emit_groups",
    "experimental_rules",
    "file_text",
    "group_scope",
    "grouped_evidence",
    "hits_in",
    "is_demoted",
    "more_sites",
    "rule_by_id",
    "run_rules",
    "select_rules",
    "subsystem_of",
    "unit_of",
]


# ---------------------------------------------------------------------------
# Subsystems: where a finding sits on the system map
# ---------------------------------------------------------------------------


class Subsystem(NamedTuple):
    """One box on the system map. `inventory_keys` are the Inventory sections it summarises."""

    key: str
    title: str
    inventory_keys: tuple[str, ...]


# Two rows of five. The first row is the data flow (drawn with arrows), the second the
# foundations under it. Order matters: it is the drawing order.
SUBSYSTEMS: tuple[Subsystem, ...] = (
    Subsystem("data_in", "Data in", ("data_sources", "ingress")),
    Subsystem("runtime", "Host and agent runtime", ("hosts", "loops")),
    Subsystem("model", "Model calls and prompts", ("llm_calls", "models")),
    Subsystem("tools", "Tools and actions", ("tools", "external_actions", "mcp")),
    Subsystem("sinks", "Output sinks", ("sinks",)),
    Subsystem("secrets", "Secrets and personal data", ("secrets",)),
    Subsystem("supply", "Supply chain", ("models", "mcp", "ci")),
    Subsystem("guardrails", "Guardrails", ("guardrails",)),
    Subsystem("observability", "Observability", ("observability",)),
    Subsystem("governance", "Evals and governance", ("evals", "system_card", "incident_path")),
)

# The box for anything that cannot be placed: a finding with an id outside the
# registry, and every UNKNOWN item that names no rule. Always drawn, never dropped.
NOT_ATTRIBUTED = "not_attributed"

# Every rule id maps to exactly one subsystem; a test pins the key set against ALL_RULES.
SUBSYSTEM_OF_RULE: dict[str, str] = {
    "AUD-101": "runtime",
    "AUD-102": "runtime",
    "AUD-107": "runtime",
    "AUD-108": "runtime",
    "AUD-301": "data_in",
    "AUD-302": "model",
    "AUD-303": "model",
    "AUD-103": "tools",
    "AUD-104": "tools",
    "AUD-105": "tools",
    "AUD-201": "tools",
    "AUD-202": "tools",
    "AUD-203": "tools",
    "AUD-401": "tools",
    "AUD-402": "tools",
    "AUD-403": "tools",
    "AUD-405": "tools",
    "AUD-406": "tools",
    "AUD-404": "sinks",
    "AUD-106": "secrets",
    "AUD-501": "secrets",
    "AUD-502": "secrets",
    "AUD-503": "secrets",
    "AUD-504": "secrets",
    "AUD-505": "secrets",
    "AUD-601": "supply",
    "AUD-602": "supply",
    "AUD-603": "supply",
    "AUD-604": "supply",
    "AUD-605": "supply",
    "AUD-606": "supply",
    "AUD-802": "guardrails",
    "AUD-803": "guardrails",
    "AUD-804": "guardrails",
    "AUD-805": "guardrails",
    "AUD-701": "observability",
    "AUD-702": "observability",
    "AUD-703": "governance",
    "AUD-801": "governance",
    "AUD-901": "governance",
    "AUD-902": "governance",
    "AUD-903": "governance",
    "AUD-904": "governance",
    "AUD-1001": "governance",
    "AUD-1002": "governance",
    "AUD-1003": "governance",
}


def subsystem_of(finding_id: str) -> str:
    """Subsystem key for a finding or rule id; a sub-finding (`AUD-101/docs`) follows its parent."""
    parent = finding_id.split("/", 1)[0]
    return SUBSYSTEM_OF_RULE.get(parent, NOT_ATTRIBUTED)


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


# ---------------------------------------------------------------------------
# Grouping: one decision is one finding
# ---------------------------------------------------------------------------
# A rule that reports every occurrence of a repeated fact buries the document it
# feeds. A library supporting many providers named a floating model id 282 times in
# one audit; that is one row of work per id, not 282 rows. So a rule with a natural
# grouping key emits one finding per group: the first site by path is the anchor and
# carries the fingerprint, up to ALSO_CAP further sites ride along as `also` evidence,
# and the rest are counted in the notes so the reader knows the list is cut rather
# than complete.
#
# The count is never dropped silently, and grouping never merges two different
# decisions: the key always separates what a person would fix separately (the model
# id, the guard, the credential name).
ALSO_CAP = 8
ALSO_ROLE = "also"


class SiteRef(NamedTuple):
    """One location of a grouped finding: the anchor or an `also` entry."""

    file: str
    line: int
    snippet: str


class Candidate(NamedTuple):
    """A site plus what the finding built from it would say; the group's anchor decides."""

    site: SiteRef
    unit: Unit | None
    notes: str
    sub: str | None = None
    evidence_kind: EvidenceKind | None = None
    match_kind: MatchKind | None = None
    severity: Severity | None = None

    @property
    def order(self) -> tuple[str, int, str]:
        return (self.site.file, self.site.line, self.site.snippet)


def grouped_evidence(sites: Sequence[SiteRef]) -> tuple[list[Evidence], int]:
    """
    The anchor as `match` evidence plus up to `ALSO_CAP` further sites as `also`
    evidence, in the order given. Returns the evidence and how many sites were cut.
    """
    anchor, extra = sites[0], list(sites[1:])
    evidence = [Evidence(role="match", file=anchor.file, line=anchor.line, snippet=anchor.snippet)]
    evidence.extend(
        Evidence(role=ALSO_ROLE, file=site.file, line=site.line, snippet=site.snippet)
        for site in extra[:ALSO_CAP]
    )
    return evidence, max(0, len(extra) - ALSO_CAP)


def more_sites(notes: str, overflow: int) -> str:
    if overflow <= 0:
        return notes
    return f"{notes}; +{overflow} more site{'s' if overflow != 1 else ''}"


def group_scope(unit: Unit | None, anchor_file: str) -> Scope:
    """A grouped finding is about a unit; without one it falls back to the anchor file."""
    if unit is None:
        return Scope(kind="file", name=anchor_file)
    return Scope(kind="unit", unit=unit.id, name=unit.root or ".")


def emit_groups(rule: AuditRule, groups: dict) -> list[Finding]:
    """
    One finding per group. Candidates are sorted by (file, line, snippet) so the anchor,
    and with it the fingerprint, is the first site by path regardless of insertion
    order; a site seen twice for the same group is listed once.
    """
    findings: list[Finding] = []
    for candidates in groups.values():
        ordered: list[Candidate] = []
        seen: set[tuple[str, int]] = set()
        for candidate in sorted(candidates, key=lambda c: c.order):
            key = (candidate.site.file, candidate.site.line)
            if key in seen:
                continue
            seen.add(key)
            ordered.append(candidate)
        if not ordered:
            continue
        anchor = ordered[0]
        evidence, overflow = grouped_evidence([c.site for c in ordered])
        findings.append(
            rule.finding(
                file=anchor.site.file,
                line=anchor.site.line,
                snippet=anchor.site.snippet,
                evidence=evidence,
                scope=group_scope(anchor.unit, anchor.site.file),
                sub=anchor.sub,
                severity=anchor.severity,
                evidence_kind=anchor.evidence_kind,
                match_kind=anchor.match_kind,
                notes=more_sites(anchor.notes, overflow),
            )
        )
    return sorted(
        findings,
        key=lambda f: (f.evidence[0].file, f.evidence[0].line, f.sub or "", f.notes or ""),
    )


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
