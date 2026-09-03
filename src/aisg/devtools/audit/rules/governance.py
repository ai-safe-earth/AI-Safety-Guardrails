# aisg-audit: ignore-file
"""aisg/devtools/audit/rules/governance.py
-----------------------------------------
P10 governance rules: AUD-1001 (no system card), AUD-1002 (risk tier
undetermined) and AUD-1003 (Annex III keywords without a card category).

None of these is a legal finding. A system card is what the operator asserts;
risk classification under Art. 6 / Annex III is a legal determination made by
the operator, not a tool output. The rules report what the card says and what
the prompts mention, and nothing more.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any

from aisg.devtools.audit import patterns
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
    UnknownCategory,
    UnknownItem,
)
from aisg.devtools.audit.rules import AuditRule, file_text, hits_in

__all__ = [
    "RULES",
    "NoSystemCard",
    "RiskTierUndetermined",
    "AnnexKeywordsWithoutCategory",
    "LEGAL_CAVEAT",
]

LEGAL_CAVEAT = (
    "Risk classification under Art. 6 / Annex III is a legal determination made by the "
    "operator, not a tool output. This finding reports what the card says; it does not "
    "classify the system."
)

_KEYWORD_CAVEAT = (
    "Keyword presence is not a classification: the words below appear in prompt material "
    "and the card names no Annex III category. Whether the system falls under Annex III "
    "is a legal determination made by the operator, not a tool output."
)

# Values that mean "not determined" for a card field, after lower/strip.
_UNSET_VALUES = frozenset({"", "unknown", "null", "none", "n/a", "na", "tbd"})

_RISK_TIER_LINE_RE = re.compile(r"^\s*risk_tier\s*:", re.M)

# Doc files where Annex III words are prose about the project, not prompt material.
_PROSE_BASENAMES = re.compile(r"^(readme|changelog|contributing|license|licence)(\.|$)", re.I)

_COMMENT_RE = re.compile(r"^\s*#")


def _basename(relpath: str) -> str:
    return PurePosixPath(relpath).name


def _unset(value: Any) -> bool:
    if value is None:
        return True
    text = str(value).strip().lower()
    return text in _UNSET_VALUES or text.startswith("todo")


def _card(ctx: AuditContext) -> dict[str, Any] | None:
    card = getattr(ctx.inventory, "system_card", None)
    return card if isinstance(card, dict) else None


def _card_shaped_files(ctx: AuditContext) -> list[str]:
    """Enumerated files whose path matches a system-card glob (patterns.SYSTEM_CARD_GLOBS)."""
    table = getattr(patterns, "SYSTEM_CARD_GLOBS", None) or []
    out: list[str] = []
    for record in ctx.files or []:
        relpath = str(getattr(record, "relpath", "") or "")
        if relpath and any(rx.search(relpath) for _glob, rx in table):
            out.append(relpath)
    return sorted(out)


def _keyword_table() -> list[tuple[str, re.Pattern[str]]]:
    """patterns.ANNEX_III_KEYWORDS as (key, regex) pairs whatever container it ships in."""
    table = getattr(patterns, "ANNEX_III_KEYWORDS", None) or []
    if isinstance(table, dict):
        return list(table.items())
    return [(str(key), rx) for key, rx in table]


def _keyword_keys() -> frozenset[str]:
    return frozenset(key for key, _rx in _keyword_table())


def _keyword_hits(text: str) -> list[str]:
    """Annex III keyword keys present in `text`, in patterns order."""
    return [key for key, regex in _keyword_table() if regex.search(text)]


# ---------------------------------------------------------------------------
# AUD-1001  No system card
# ---------------------------------------------------------------------------


class NoSystemCard(AuditRule):
    id = "AUD-1001"
    title = "No system card"
    priority = 10
    severity = Severity.LOW
    basis = Basis.ABSENCE
    evidence_kind = EvidenceKind.ABSENCE
    match_kind = MatchKind.STRUCTURED
    requires_ai_surface = True
    tier = Tier.T2
    controls = ("EU:Art.11", "EU:Art.13", "NIST:GOVERN-1.2", "NIST:MAP-1.1")
    related_lint_rules = ("EU-AIA-011a",)
    known_failure_modes = (
        "only files matching patterns.SYSTEM_CARD_GLOBS are recognised as a card; a card "
        "under another name or in a wiki is reported as absent",
        "a card that exists but fails to parse is an UNKNOWN item, not a finding",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Write down what the system is for, who operates it, which model it runs, and "
            "how to report an incident: `aisg init` writes ai-system-card.yaml with those "
            "fields and the risk-tier caveat."
        ),
        alternatives=(
            "aisg init --defaults, then fill in the fields it leaves as unknown",
            "a model card from the Hugging Face model-card template committed as MODEL_CARD.md",
            "Google's Model Card Toolkit output committed next to the model config",
            "an Annex IV technical-documentation outline written by hand in docs/",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        # `run_rules` gates on the AI surface too; repeated here so `evaluate` stands alone.
        if not any(getattr(u, "ai_surface", False) for u in (ctx.inventory.units or [])):
            return []
        if _card(ctx) is not None:
            return []
        present = _card_shaped_files(ctx)
        if present:
            # discover found a card-shaped file and could not read it; that is an
            # UNKNOWN (discover records the parse error), not an absence.
            self.unknown.append(
                UnknownItem(
                    category=UnknownCategory.REPORTS,
                    what="system card unreadable",
                    why=f"{present[0]} matches a system-card path but yielded no card",
                    how_to_resolve="Fix the YAML/Markdown so the card parses, or run `aisg init`.",
                    file=present[0],
                    rule_ids=(self.id,),
                )
            )
            return []
        why = (
            "no system card found (ai-system-card.yaml, model_card.md, MODEL_CARD.md, "
            "system-card*); the audit has no operator statement of purpose, model, risk "
            "tier or incident contact to compare the code against"
        )
        return [self.absence_finding(unit=None, why=why)]


# ---------------------------------------------------------------------------
# AUD-1002  Risk tier undetermined
# ---------------------------------------------------------------------------


class RiskTierUndetermined(AuditRule):
    id = "AUD-1002"
    title = "Risk tier undetermined"
    priority = 10
    severity = Severity.INFO
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CONFIG
    match_kind = MatchKind.STRUCTURED
    tier = Tier.T2
    controls = ("EU:Art.6", "EU:Art.9", "NIST:MAP-1.1", "NIST:MAP-5.1")
    related_lint_rules = ("EU-AIA-011a", "EU-AIA-009a")
    known_failure_modes = (
        "a card that spells the tier in a way the audit does not recognise as unset "
        "(a placeholder word other than unknown / todo / tbd) is treated as determined",
        "the value is read as written; the audit cannot tell whether it is right",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Have the operator record the risk tier in the system card, with the Annex III "
            "category when one applies. The tier is a legal determination the operator makes; "
            "the card is where it is written down."
        ),
        alternatives=(
            "aisg init and answer the risk-tier prompt after the operator's legal review",
            "set risk_tier in ai-system-card.yaml by hand with a link to the review",
            "the EU AI Act compliance checker questionnaire, with its output committed",
            "a signed-off risk assessment in docs/ that the card points to",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        card = _card(ctx)
        if card is None:
            return []
        tier = card.get("risk_tier")
        if not _unset(tier):
            return []
        relpath = str(card.get("file") or ".")
        text = file_text(ctx, relpath) if relpath != "." else None
        line = 0
        snippet = f"risk_tier: {tier if tier not in (None, '') else '(unset)'}"
        if text:
            match = _RISK_TIER_LINE_RE.search(text)
            if match is not None:
                line = text.count("\n", 0, match.start()) + 1
                snippet = text[match.start() : text.find("\n", match.start())].strip() or snippet
        return [
            self.finding(
                file=relpath,
                line=line,
                snippet=snippet,
                evidence=[Evidence(role="card", file=relpath, line=line, snippet=snippet)],
                scope=Scope(kind="repo", name="."),
                notes=LEGAL_CAVEAT,
            )
        ]


# ---------------------------------------------------------------------------
# AUD-1003  Annex III keywords without a card category
# ---------------------------------------------------------------------------


class AnnexKeywordsWithoutCategory(AuditRule):
    id = "AUD-1003"
    title = "Annex III keywords in prompt material, no category on the card"
    priority = 10
    severity = Severity.INFO
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    tier = Tier.T2
    controls = ("EU:Art.6", "EU:Art.11", "NIST:MAP-1.1", "NIST:MAP-5.1")
    related_lint_rules = ("EU-AIA-005a", "EU-AIA-005b", "EU-AIA-005c", "EU-AIA-011a")
    known_failure_modes = (
        "keywords are matched as words; a prompt about a hiring committee for a film "
        "festival trips the same regex as a recruitment screener",
        "only prompt templates, prompt-assembly strings and card-adjacent docs are scanned; "
        "README, CHANGELOG and CONTRIBUTING never count",
        "two distinct keywords are required, so a single-domain prompt is not reported",
        "a card with a category set is not compared against the keywords",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "If the prompts serve one of the Annex III domains they mention, have the operator "
            "record the category on the system card; if they do not, say so in the card's notes "
            "so the next reader does not have to guess."
        ),
        alternatives=(
            "aisg init, then set annex_iii_category after the operator's legal review",
            "set annex_iii_category in ai-system-card.yaml by hand, or `none` with a reason",
            "a documented use-case scoping review in docs/ that lists the domains served",
            "aisg lint, whose EU-AIA-005 rules flag the same domains in Python code paths",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        card = _card(ctx)
        if card is not None and not _unset(card.get("annex_iii_category")):
            return []
        # (file, line, key) -> role ; role is "ast" for pydeep-derived sightings.
        sightings: dict[tuple[str, int, str], str] = {}
        deep_lines = self._deep_lines(ctx)
        known_keys = _keyword_keys()

        for hit in hits_in(ctx, "annex_iii"):
            relpath = hit.file.replace("\\", "/")
            name = _basename(relpath)
            if _PROSE_BASENAMES.match(name):
                continue
            snippet = str(getattr(hit, "snippet", "") or "")
            if name.lower().endswith((".yaml", ".yml")) and _COMMENT_RE.match(snippet):
                continue
            keys = _keyword_hits(snippet) or [str(getattr(hit, "key", ""))]
            for key in keys:
                if key in known_keys:
                    sightings.setdefault((relpath, int(hit.line), key), "grep")

        for hit in hits_in(ctx, "prompt_assembly"):
            relpath = hit.file.replace("\\", "/")
            if relpath.endswith(".py") and (relpath, int(hit.line)) in deep_lines:
                continue  # deep evidence for the same (file, line) wins below
            snippet = str(getattr(hit, "snippet", "") or "")
            for key in _keyword_hits(snippet):
                sightings.setdefault((relpath, int(hit.line), key), "grep")

        for relpath, line in sorted(deep_lines):
            text = file_text(ctx, relpath)
            if not text:
                continue
            lines = text.splitlines()
            if not 1 <= line <= len(lines):
                continue
            for key in _keyword_hits(lines[line - 1]):
                sightings[(relpath, line, key)] = "ast"

        keys_seen = sorted({key for (_f, _l, key) in sightings})
        if len(keys_seen) < 2:
            return []
        # One evidence leg per keyword: its first sighting in (file, line, key) order.
        first: dict[str, tuple[str, int, str]] = {}
        for (relpath, line, key), role in sorted(sightings.items()):
            first.setdefault(key, (relpath, line, role))
        evidence = [
            Evidence(role=role, file=relpath, line=line, snippet=f"annex_iii keyword: {key}")
            for key, (relpath, line, role) in sorted(first.items(), key=lambda kv: (kv[1], kv[0]))
        ]
        anchor_file, anchor_line, _role = min(first.values())
        any_ast = any(role == "ast" for _f, _l, role in first.values())
        categories = sorted(
            {
                str(patterns.ANNEX_III_CATEGORY_BY_KEYWORD.get(key, ""))
                for key in keys_seen
                if patterns.ANNEX_III_CATEGORY_BY_KEYWORD.get(key)
            }
        )
        card_note = (
            "no system card" if card is None else f"card {card.get('file')} names no category"
        )
        summary = f"{len(keys_seen)} Annex III keywords ({', '.join(keys_seen)}); {card_note}"
        if categories:
            summary += f"; categories those words map to: {', '.join(categories)}"
        # The finding's own snippet only feeds the fingerprint; the summary travels in notes
        # so a renderer shows it next to the caveat.
        return [
            self.finding(
                file=anchor_file,
                line=anchor_line,
                snippet=summary,
                evidence=evidence,
                scope=Scope(kind="repo", name="."),
                notes=f"{summary}. {_KEYWORD_CAVEAT}",
                match_kind=MatchKind.AST if any_ast else MatchKind.GREP,
            )
        ]

    @staticmethod
    def _deep_lines(ctx: AuditContext) -> set[tuple[str, int]]:
        facts = ctx.pyfacts
        if facts is None:
            return set()
        out: set[tuple[str, int]] = set()
        for assembly in getattr(facts, "prompt_assemblies", None) or []:
            relpath = str(getattr(assembly, "file", "") or "").replace("\\", "/")
            line = int(getattr(assembly, "line", 0) or 0)
            if relpath and line > 0:
                out.add((relpath, line))
        return out


RULES = [NoSystemCard, RiskTierUndetermined, AnnexKeywordsWithoutCategory]
