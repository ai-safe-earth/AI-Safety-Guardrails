"""aisg/devtools/audit/lint_bridge.py
------------------------------------
Run the curated EU AI Act and misalignment lint rules in-process over the files the
walk already read, and hand their hits to the P11 rules as EVIDENCE.

The bridge never emits a finding of its own. A lint hit becomes an `Evidence(role=
"lint")` leg on the AUD-11xx finding whose site covers it, or the anchor of a new
candidate in the same group when no P11 site of its own exists in that file. Two
analyzers run, one per tool, so each honours only its own `ignore-file` marker and
line directives: a target's explicit suppressions are respected, and the count of
suppressed hits is kept so a reader can see what was silenced.

Why in-process over walk text rather than the linter's path API: the public API
re-reads every file and knows nothing of the walk's excludes, size limit or ignore
marker; `EUAIActCodeAnalyzer.scan_source` is the one seam that takes text.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from aisg.devtools.audit.model import truncate_snippet

__all__ = ["EU_RULE_IDS", "MISALIGN_RULE_IDS", "LintFacts", "LintHit", "lint_hits", "run_lint"]

# The lint rules whose hits feed a P11 rule (design 03, section 3.1). Nothing else runs:
# the audit is not a second linter, and every one of these has a P11 reading.
EU_RULE_IDS: tuple[str, ...] = (
    "EU-AIA-005a",
    "EU-AIA-005b",
    "EU-AIA-005c",
    "EU-AIA-013a",
    "EU-AIA-013b",
    "EU-AIA-014a",
    "EU-AIA-014b",
    "EU-AIA-050a",
    "EU-AIA-050b",
    "EU-GDPR-001",
)
MISALIGN_RULE_IDS: tuple[str, ...] = ("ALIGN-008",)


@dataclass(frozen=True)
class LintHit:
    rule_id: str
    file: str
    line: int
    snippet: str
    title: str


@dataclass
class LintFacts:
    """What the bridge established: hits per rule id, files skipped by a marker, and how
    many hits a line directive silenced (per tool)."""

    by_rule: dict[str, list[LintHit]] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    suppressed: int = 0
    errors: list[str] = field(default_factory=list)

    def hits(self, *rule_ids: str) -> list[LintHit]:
        out: list[LintHit] = []
        for rule_id in rule_ids:
            out.extend(self.by_rule.get(rule_id, ()))
        return sorted(out, key=lambda h: (h.file, h.line, h.rule_id))


def _select(rules: Iterable[Any], ids: Sequence[str]) -> list[Any]:
    wanted = set(ids)
    return [rule for rule in rules if getattr(rule, "rule_id", "") in wanted]


def _analyzers() -> list[Any]:
    from aisg.devtools.misalignment.rules import MISALIGNMENT_RULES
    from aisg.modules.policy.code_analyzer.analyzer import EUAIActCodeAnalyzer
    from aisg.modules.policy.code_analyzer.rules import ALL_RULES

    return [
        EUAIActCodeAnalyzer(rules=_select(ALL_RULES, EU_RULE_IDS), tool="euaiact-lint"),
        EUAIActCodeAnalyzer(
            rules=_select(MISALIGNMENT_RULES, MISALIGN_RULE_IDS), tool="misalignment-check"
        ),
    ]


def run_lint(records: Sequence[Any], texts: dict[str, str | None]) -> LintFacts:
    """
    The curated rules over every `lang == "python"` record whose text is in `texts`
    (relpath -> decoded text, None for unreadable). Pure AST and regex: no network, no
    subprocess, no model.
    """
    from aisg.modules.policy.code_analyzer.analyzer import ScanReport

    facts = LintFacts()
    analyzers = _analyzers()
    for record in records:
        if getattr(record, "lang", None) != "python":
            continue
        relpath = str(getattr(record, "relpath", "") or "").replace("\\", "/")
        text = texts.get(relpath)
        if not text:
            continue
        for analyzer in analyzers:
            report = ScanReport(tool=analyzer.tool)
            try:
                analyzer.scan_source(text, relpath, report)
            except Exception as exc:  # the bridge is evidence, never a crash
                facts.errors.append(f"{relpath}: {type(exc).__name__}: {exc}")
                continue
            facts.skipped.extend(f for f in report.skipped_files if f not in facts.skipped)
            facts.suppressed += int(report.suppressed_count)
            seen: set[tuple[str, int]] = set()
            for finding in report.findings:
                # A rule with both an AST and a text check reports one line twice.
                if (finding.rule_id, int(finding.line)) in seen:
                    continue
                seen.add((finding.rule_id, int(finding.line)))
                facts.by_rule.setdefault(finding.rule_id, []).append(
                    LintHit(
                        rule_id=finding.rule_id,
                        file=relpath,
                        line=int(finding.line),
                        snippet=truncate_snippet(str(finding.snippet or "").strip()),
                        title=str(finding.title or ""),
                    )
                )
    return facts


def lint_hits(ctx: Any, *rule_ids: str) -> list[LintHit]:
    """The hits for `rule_ids` on a context, or none when the bridge did not run."""
    facts = getattr(ctx, "lint", None)
    if not isinstance(facts, LintFacts):
        return []
    return facts.hits(*rule_ids)
