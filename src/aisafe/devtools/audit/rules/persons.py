# aisafe-audit: ignore-file
"""aisafe/devtools/audit/rules/persons.py
--------------------------------------
P11 "persons and manipulation": AUD-1101..1107. Where the code or the prompts touch
PEOPLE -- a behavioural profile bound into a prompt, emotion or biometric inference,
scoring or automated decisions about persons, an engagement objective, a concealed AI
nature, no control on the response path, no recorded prompt review.

Three evidence tiers feed one finding per decision: the grep tier (`person_signal` hits
and the `person_signal_candidate` hits a pydeep prompt literal promotes), the AST tier
(`PyFacts.prompt_assemblies` and `prompt_literals`) and the lint tier (`ctx.lint`, the
curated EU AI Act and misalignment rules run in-process); lint hits are `role: lint`
legs, never findings of their own. Every rule tolerates `ctx.pyfacts is None` and
`ctx.lint is None`.

None of this is a legal finding. The rules report what the prompts and the code say;
whether a practice falls under Art. 5, Art. 50 or Annex III is a legal determination
made by the operator, not a tool output.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from aisafe.devtools.audit import patterns, vocab
from aisafe.devtools.audit import persons_patterns as pp
from aisafe.devtools.audit.lint_bridge import LintHit, lint_hits
from aisafe.devtools.audit.model import (
    AuditContext,
    Basis,
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
)
from aisafe.devtools.audit.rules import (
    AuditRule,
    Candidate,
    SiteRef,
    emit_groups,
    file_text,
    hits_in,
    unit_of,
)

__all__ = [
    "RULES",
    "AIDisclosureAbsent",
    "AffectInference",
    "EngagementObjective",
    "NoManipulationControl",
    "PersonProfileInPrompt",
    "PersonScoring",
    "PromptAuditNotRecorded",
    "LEGAL_CAVEAT",
]

LEGAL_CAVEAT = (
    "Whether this practice falls under Art. 5, Art. 50 or Annex III of Regulation (EU) "
    "2024/1689 is a legal determination made by the operator, not a tool output. The "
    "finding reports what the code and the prompts say."
)

_WINDOW = 40
_FUNCTION_WINDOW = 60
_LINT_ROLE = "lint"
_PROFILE_KINDS = frozenset({"profile_sdk", "profile_name", "profile_placeholder"})
_SIGNAL_KINDS_1106 = _PROFILE_KINDS | {"engagement", "persona"}
# Every kind that says the system touches people; the disclosure, control and review
# symbols are the answers to those, not signals of their own.
_PERSON_KINDS = _SIGNAL_KINDS_1106 | {
    "affect",
    "biometric_cat",
    "scoring",
    "objective_code",
    "vulnerable",
}


# ---------------------------------------------------------------------------
# Signals: grep hits, promoted candidates, prompt literals
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Signal:
    file: str
    line: int
    kind: str
    key: str
    symbol: str
    unit: str | None
    promoted: bool = False  # a candidate a prompt literal or an assembly vouched for


@dataclass
class _Facts:
    signals: list[_Signal] = field(default_factory=list)
    literals: list[Any] = field(default_factory=list)  # pydeep.PromptLiteral
    assemblies: list[Any] = field(default_factory=list)  # pydeep.Assembly

    def by_kind(self, *kinds: str) -> list[_Signal]:
        wanted = set(kinds)
        return [s for s in self.signals if s.kind in wanted]

    def in_unit(self, unit_id: str | None, *kinds: str) -> list[_Signal]:
        return [s for s in self.by_kind(*kinds) if s.unit == unit_id]

    def literal_at(self, file: str, line: int) -> Any | None:
        for literal in self.literals:
            if _posix(literal.file) == file and literal.line <= line <= literal.end_line:
                return literal
        return None


def _posix(path: Any) -> str:
    return str(path).replace("\\", "/")


def _facts(ctx: AuditContext) -> _Facts:
    cache = getattr(ctx, "cache", None)
    if isinstance(cache, dict) and "persons.facts" in cache:
        return cache["persons.facts"]
    facts = _Facts()
    pyfacts = ctx.pyfacts
    facts.literals = list(getattr(pyfacts, "prompt_literals", None) or [])
    facts.assemblies = list(getattr(pyfacts, "prompt_assemblies", None) or [])
    for hit in hits_in(ctx, "person_signal"):
        facts.signals.append(
            _Signal(hit.file, hit.line, pp.kind_of(hit.key), hit.key, hit.snippet, hit.unit)
        )
    for hit in hits_in(ctx, "person_signal_candidate"):
        kind = pp.kind_of(hit.key)
        promoted = facts.literal_at(hit.file, hit.line) is not None
        if not promoted and kind == "profile_name":
            promoted = _named_in_assembly(facts, hit.file, hit.line, hit.snippet)
        if promoted:
            facts.signals.append(
                _Signal(hit.file, hit.line, kind, hit.key, hit.snippet, hit.unit, promoted=True)
            )
    facts.signals.sort(key=lambda s: (s.file, s.line, s.kind, s.key))
    if isinstance(cache, dict):
        cache["persons.facts"] = facts
    return facts


def _named_in_assembly(facts: _Facts, file: str, line: int, snippet: str) -> bool:
    """A profile-named identifier on `line` that a prompt assembly within the window reads."""
    names = {
        tok
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", snippet)
        if pp.PROFILE_NAME_RE.search(tok)
    }
    if not names:
        return False
    for assembly in facts.assemblies:
        if _posix(assembly.file) != file or not (line <= assembly.line <= line + _WINDOW):
            continue
        if names & set(assembly.source_names):
            return True
    return False


def _line(ctx: AuditContext, file: str, line: int, fallback: str = "") -> str:
    text = file_text(ctx, file)
    if not text or line < 1:
        return fallback
    lines = text.split("\n")
    if line > len(lines):
        return fallback
    return lines[line - 1].rstrip("\r").strip() or fallback


def _row_regex(key: str) -> re.Pattern[str] | None:
    for row_key, rx in pp.PERSON_SIGNAL_PATTERNS:
        if row_key == key:
            return rx
    return None


def _is_mention(ctx: AuditContext, signal: _Signal) -> bool:
    """A quoted or discussed phrase in prompt material: `Explain how we detect social
    scoring` is a mention of the practice, not an instruction to perform it."""
    rx = _row_regex(signal.key)
    line = _line(ctx, signal.file, signal.line)
    if rx is None or not line:
        return False
    match = rx.search(line)
    if match is None:
        return False
    if _is_code_file(signal.file):
        # A prompt literal in code is quoted by nature; only a discussion cue in the
        # window around the match makes it a mention there.
        before = line[max(0, match.start() - 80) : match.start()]
        after = line[match.end() : match.end() + 80]
        return bool(
            patterns.DISCUSSION_CUES.search(before) or patterns.DISCUSSION_CUES.search(after)
        )
    return patterns.is_mention(line, match.start(), match.end())


_CODE_EXTS = frozenset(
    {
        ".py",
        ".pyi",
        ".ts",
        ".tsx",
        ".js",
        ".jsx",
        ".mjs",
        ".go",
        ".java",
        ".kt",
        ".rb",
        ".rs",
        ".cs",
        ".php",
        ".swift",
        ".scala",
    }
)


def _is_code_file(relpath: str) -> bool:
    return "." + relpath.rsplit(".", 1)[-1].lower() in _CODE_EXTS if "." in relpath else False


def _literal_text(ctx: AuditContext, literal: Any) -> str:
    text = file_text(ctx, _posix(literal.file))
    if not text:
        return ""
    lines = text.split("\n")
    return "\n".join(lines[literal.line - 1 : literal.end_line])


def _window_text(ctx: AuditContext, file: str, line: int, span: int) -> str:
    text = file_text(ctx, file)
    if not text:
        return ""
    lines = text.split("\n")
    return "\n".join(lines[max(0, line - 1) : line - 1 + span])


# A quoted string on a code line is UI text (a reason, a message), not the decision; the
# identifiers around it are what say whether a person is decided about.
_STRING_LITERAL_RE = re.compile(r"""[rbfuRBFU]{0,2}(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')""")
_DECISION_VERB_RE = re.compile(
    r"\b(?:approve|reject|deny|hire|fire|terminate|accept|grant|disqualify|eligib\w*|score|rank)\w*\b",
    re.I,
)


def _decides_about_a_person(window: str) -> bool:
    """The lint rule EU-AIA-014a fires on any function that approves, rejects, scores or
    ranks something; it is a decision about a PERSON here only when the person noun sits
    in the signature (`def approve_tenant(applicant)`) or on a code line that also carries
    a decision verb. Comments and docstrings do not count."""
    lines = window.split("\n")
    if not lines:
        return False
    if pp.PERSON_NOUN.search(_STRING_LITERAL_RE.sub(" ", lines[0])):
        return True
    in_doc = False
    for line in lines[1:]:
        stripped = line.strip()
        if stripped.count('"""') % 2 == 1 or stripped.count("'''") % 2 == 1:
            in_doc = not in_doc
            continue
        if in_doc or stripped.startswith("#"):
            continue
        code = _STRING_LITERAL_RE.sub(" ", stripped.split("#", 1)[0])
        if _DECISION_VERB_RE.search(code) and pp.PERSON_NOUN.search(code):
            return True
    return False


def _owning_unit(ctx: AuditContext, relpath: str) -> Unit | None:
    unit = unit_of(ctx, relpath)
    if unit is not None:
        return unit
    key = _posix(relpath)
    best: Unit | None = None
    for candidate in ctx.inventory.units:
        root = candidate.root or "."
        if root == "." or key == root or key.startswith(root.rstrip("/") + "/"):
            if best is None or len(root) > len(best.root or "."):
                best = candidate
    return best


def _unit_id(ctx: AuditContext, relpath: str) -> str | None:
    unit = _owning_unit(ctx, relpath)
    return unit.id if unit is not None else None


def _candidate(
    ctx: AuditContext,
    signal_or_file: _Signal | str,
    line: int | None = None,
    *,
    notes: str,
    sub: str | None = None,
    severity: Severity | None = None,
    snippet: str | None = None,
) -> Candidate:
    if isinstance(signal_or_file, _Signal):
        file, line_no = signal_or_file.file, signal_or_file.line
        fallback = signal_or_file.symbol
    else:
        file, line_no = signal_or_file, int(line or 0)
        fallback = ""
    text = snippet if snippet is not None else _line(ctx, file, line_no, fallback)
    return Candidate(
        site=SiteRef(file, line_no, text or fallback or "(no text)"),
        unit=_owning_unit(ctx, file),
        notes=notes,
        sub=sub,
        severity=severity,
    )


def _attach_lint_legs(
    findings: list[Finding], legs: dict[tuple[str | None, str | None], list[LintHit]]
) -> None:
    """Append `role: lint` evidence to each grouped finding, deduped by (file, line)."""
    for finding in findings:
        unit_id = finding.scope.unit
        key = (unit_id, finding.sub)
        hits = legs.get(key) or []
        # A lint hit on a grep site's own line still carries its rule id, so only lint
        # legs dedupe against each other.
        seen = {(e.file, e.line) for e in finding.evidence if e.role == _LINT_ROLE}
        for hit in sorted(hits, key=lambda h: (h.file, h.line, h.rule_id)):
            if (hit.file, hit.line) in seen:
                continue
            seen.add((hit.file, hit.line))
            finding.evidence.append(
                Evidence(
                    role=_LINT_ROLE,
                    file=hit.file,
                    line=hit.line,
                    snippet=f"{hit.rule_id}: {hit.title}",
                )
            )


def _split_lint(
    ctx: AuditContext, facts: _Facts, hits: list[LintHit], kinds: tuple[str, ...]
) -> tuple[list[LintHit], list[LintHit]]:
    """(anchors, legs): a lint hit in a file that already carries a grep signal of one of
    `kinds` is a leg on that file's finding; one with no P11 site of its own in the file
    anchors a candidate, so the lint tier alone still produces the finding."""
    covered = {s.file for s in facts.by_kind(*kinds)}
    anchors = [h for h in hits if h.file not in covered]
    legs = [h for h in hits if h.file in covered]
    return anchors, legs


def _legs_by_group(ctx: AuditContext, hits: list[LintHit], sub: str | None) -> dict:
    out: dict[tuple[str | None, str | None], list[LintHit]] = {}
    for hit in hits:
        out.setdefault((_unit_id(ctx, hit.file), sub), []).append(hit)
    return out


def _lint_by_group(ctx: AuditContext, rule_ids: tuple[str, ...], sub: str | None) -> dict:
    out: dict[tuple[str | None, str | None], list[LintHit]] = {}
    for hit in lint_hits(ctx, *rule_ids):
        out.setdefault((_unit_id(ctx, hit.file), sub), []).append(hit)
    return out


def _has_ai_surface(ctx: AuditContext) -> bool:
    return any(getattr(u, "ai_surface", False) for u in (ctx.inventory.units or []))


def _unit_has(ctx: AuditContext, unit_id: str, section: str) -> bool:
    for entry in getattr(ctx.inventory, section, None) or []:
        if isinstance(entry, dict) and entry.get("unit") == unit_id:
            return True
    return False


# ---------------------------------------------------------------------------
# AUD-1101  Person profile bound into a prompt
# ---------------------------------------------------------------------------


class PersonProfileInPrompt(AuditRule):
    id = "AUD-1101"
    title = "Person profile bound into a prompt"
    priority = 11
    severity = Severity.MEDIUM
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    requires_ai_surface = True
    tier = Tier.T2
    controls = (
        "GDPR:Art.22",
        "GDPR:Art.9",
        "GDPR:Art.5",
        "EU:Art.5(1)(a)",
        "EU:Art.10",
        "LLM02",
        "NIST:MAP-5.1",
        "NIST:MEASURE-2.11",
    )
    related_lint_rules = ("EU-GDPR-001",)
    known_failure_modes = (
        "the NAME is the signal: a `preferences` variable may hold a UI theme, and a profile "
        "fetched at runtime under a neutral name is missed",
        "`conversation_history` and the other transcript names are excluded by design",
        "grouped per unit, sub-finding and file, anchored on the first site by path",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Pass the model only the fields the task needs. A behavioural profile in the prompt "
            "is personal data processed for a new purpose; drop it, reduce it, or pseudonymise "
            "it and document the lawful basis."
        ),
        alternatives=(
            "drop the profile from the prompt and pass only the fields the task needs",
            'pseudonymise with PIIDetector(action="tokenize") and restore on output',
            "document the lawful basis and purpose in a DPIA next to the prompt",
            "Microsoft Presidio or LLM Guard Anonymize on the ingress path",
        ),
        package=Package(
            mechanism="detector",
            symbols=("PIIDetector", "ManipulationGuard"),
            same_control=False,
            leaves_open=(
                'PIIDetector(action="tokenize") removes the entity types it knows from the '
                "prompt; a behavioural profile has no entity type and stays in the prompt until "
                "it is left out or reduced by hand. ManipulationGuard reads the response, not "
                "the profile."
            ),
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not _has_ai_surface(ctx):
            return []
        facts = _facts(ctx)
        groups: dict[tuple[str | None, str | None, str], list[Candidate]] = {}

        def add(file: str, line: int, notes: str, name_hint: str) -> None:
            sub = "sensitive" if pp.SENSITIVE_PROFILE_RE.search(name_hint) else None
            cand = _candidate(
                ctx,
                file,
                line,
                notes=f"{notes}. {LEGAL_CAVEAT}",
                sub=sub,
                severity=Severity.HIGH if sub else None,
            )
            groups.setdefault((cand.unit.id if cand.unit else None, sub, file), []).append(cand)

        for hit in hits_in(ctx, "profile_to_prompt"):
            add(
                hit.file,
                hit.line,
                f"profile `{hit.key}` read above is bound into the prompt assembled here",
                hit.key + " " + hit.snippet,
            )
        for assembly in facts.assemblies:
            names = [
                n
                for n in assembly.source_names
                if pp.PROFILE_NAME_RE.search(n) and not pp.is_history_name(n)
            ]
            if names:
                add(
                    _posix(assembly.file),
                    int(assembly.line),
                    f"prompt assembly reads profile variable(s) {', '.join(sorted(names))}",
                    " ".join(names),
                )
        for signal in facts.by_kind("profile_placeholder"):
            add(
                signal.file,
                signal.line,
                f"prompt template placeholder {signal.symbol} binds a person profile",
                signal.symbol + " " + _line(ctx, signal.file, signal.line),
            )
        findings = emit_groups(self, groups)
        legs = _lint_by_group(ctx, ("EU-GDPR-001",), None)
        _attach_lint_legs(findings, legs)
        return findings


# ---------------------------------------------------------------------------
# AUD-1102  Emotion or biometric inference on persons
# ---------------------------------------------------------------------------


class AffectInference(AuditRule):
    id = "AUD-1102"
    title = "Emotion or biometric inference on persons"
    priority = 11
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    requires_ai_surface = True
    tier = Tier.T3
    controls = (
        "EU:Art.5(1)(f)",
        "EU:Art.5(1)(g)",
        "EU:Art.6",
        "GDPR:Art.9",
        "NIST:MAP-5.1",
        "NIST:MEASURE-2.11",
    )
    related_lint_rules = ("EU-AIA-005b", "EU-AIA-005c")
    known_failure_modes = (
        "text-only sentiment analysis is not counted: the EU definition of emotion "
        "recognition rests on biometric data",
        "a library imported for a demo counts as use; DetectFaces without Emotions does not",
        "whether the inference happens in a workplace or an education setting is read from "
        "the lint rule's words (employee, student), not from the deployment",
    )
    recommendation = Recommendation(
        tier=Tier.T3,
        summary=(
            "Remove the inference or restrict it to a documented, lawful use with a legal basis "
            "and an Annex III review; emotion recognition at work or in education and biometric "
            "categorisation of protected characteristics are listed practices under Art. 5."
        ),
        alternatives=(
            "remove the inference or restrict it to a medical or safety use with a documented legal basis",
            "replace emotion inference with explicit, user-stated preferences",
            "an Annex III conformity review before deployment",
            "aisafe: nothing here applies; the control is removing or scoping the inference",
        ),
        package=Package(mechanism="none"),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not _has_ai_surface(ctx):
            return []
        facts = _facts(ctx)
        groups: dict[tuple[str | None, str | None], list[Candidate]] = {}
        for signal in facts.by_kind("affect"):
            cand = _candidate(
                ctx,
                signal,
                notes=f"emotion or affect inference signal ({signal.key}). {LEGAL_CAVEAT}",
            )
            groups.setdefault((cand.unit.id if cand.unit else None, None), []).append(cand)
        for signal in facts.by_kind("biometric_cat"):
            cand = _candidate(
                ctx,
                signal,
                notes=(
                    "inference of a protected characteristic from a person "
                    f"({signal.symbol}). {LEGAL_CAVEAT}"
                ),
                sub="categorisation",
                severity=Severity.CRITICAL,
            )
            groups.setdefault((cand.unit.id if cand.unit else None, "categorisation"), []).append(
                cand
            )
        anchors_005c, legs_005c = _split_lint(
            ctx, facts, lint_hits(ctx, "EU-AIA-005c"), ("affect",)
        )
        for hit in anchors_005c:
            cand = _candidate(
                ctx,
                hit.file,
                hit.line,
                notes=(
                    "affect inference where people work or study (EU-AIA-005c). " + LEGAL_CAVEAT
                ),
                sub="workplace",
                severity=Severity.CRITICAL,
                snippet=hit.snippet,
            )
            groups.setdefault((cand.unit.id if cand.unit else None, "workplace"), []).append(cand)
        findings = emit_groups(self, groups)
        legs = _lint_by_group(ctx, ("EU-AIA-005b",), None)
        for key, hits in _legs_by_group(ctx, legs_005c, None).items():
            legs.setdefault(key, []).extend(hits)
        _attach_lint_legs(findings, legs)
        return findings


# ---------------------------------------------------------------------------
# AUD-1103  Scoring, ranking or automated decision about persons
# ---------------------------------------------------------------------------


class PersonScoring(AuditRule):
    id = "AUD-1103"
    title = "Scoring, ranking or automated decision about persons"
    priority = 11
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    requires_ai_surface = True
    tier = Tier.T2
    controls = (
        "EU:Art.5(1)(c)",
        "EU:Art.6",
        "GDPR:Art.22",
        "EU:Art.14",
        "NIST:MAP-5.1",
        "NIST:MEASURE-2.11",
        "NIST:GOVERN-1.1",
    )
    related_lint_rules = ("EU-AIA-005a", "EU-AIA-014a", "EU-AIA-014b")
    known_failure_modes = (
        "credit scoring is an Annex III use, not a prohibited one; the finding says what "
        "co-occurred and the card decides the category",
        "a risk score of a transaction is not a person score: the person noun is required on "
        "the same line or inside the same prompt literal",
        "`approve_refund` is not a decision about a person; a decision function is reported "
        "only when its body names a person and no review symbol",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Put a human review step before any score, rank or decision about a person takes "
            "effect, log the recommendation beside the decision, and record the use on the "
            "system card."
        ),
        alternatives=(
            "a human review step before any decision about a person takes effect, logged beside the recommendation",
            "ToolPolicyGuard(require_approval=[...], approval_callback=...) when the decision is a tool",
            "a confidence threshold routing low-confidence cases to review",
            "Fairlearn or AIF360 evaluation of the scoring model",
        ),
        package=Package(
            mechanism="gate",
            symbols=("ToolPolicyGuard",),
            same_control=False,
            leaves_open=(
                "ToolPolicyGuard gates only a decision dispatched through run_processing as a "
                "tool call with a real approval_callback. A score computed and acted on in plain "
                "code is not on that path."
            ),
        ),
    )

    def _person_nearby(self, ctx: AuditContext, facts: _Facts, signal: _Signal) -> bool:
        if pp.PERSON_NOUN.search(_line(ctx, signal.file, signal.line)):
            return True
        literal = facts.literal_at(signal.file, signal.line)
        return (
            literal is not None and pp.PERSON_NOUN.search(_literal_text(ctx, literal)) is not None
        )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not _has_ai_surface(ctx):
            return []
        facts = _facts(ctx)
        groups: dict[tuple[str | None, str | None], list[Candidate]] = {}
        for signal in facts.by_kind("scoring"):
            if _is_mention(ctx, signal) or not self._person_nearby(ctx, facts, signal):
                continue
            cand = _candidate(
                ctx,
                signal,
                notes=f"prompt material scores or ranks persons ({signal.symbol}). {LEGAL_CAVEAT}",
                sub="scoring",
            )
            groups.setdefault((cand.unit.id if cand.unit else None, "scoring"), []).append(cand)
        anchors_005a, legs_005a = _split_lint(
            ctx, facts, lint_hits(ctx, "EU-AIA-005a"), ("scoring",)
        )
        for hit in anchors_005a:
            cand = _candidate(
                ctx,
                hit.file,
                hit.line,
                notes=f"social-scoring language in code (EU-AIA-005a). {LEGAL_CAVEAT}",
                sub="scoring",
                snippet=hit.snippet,
            )
            groups.setdefault((cand.unit.id if cand.unit else None, "scoring"), []).append(cand)
        for hit in lint_hits(ctx, "EU-AIA-014a"):
            window = _window_text(ctx, hit.file, hit.line, _FUNCTION_WINDOW)
            if not _decides_about_a_person(window) or pp.REVIEW_RE.search(window):
                continue
            if vocab.APPROVAL_SYMBOLS.search(window):
                continue
            cand = _candidate(
                ctx,
                hit.file,
                hit.line,
                notes=(
                    "an automated decision function names a person and no review or approval "
                    "symbol in its body (EU-AIA-014a). " + LEGAL_CAVEAT
                ),
                sub="decision",
                snippet=hit.snippet,
            )
            groups.setdefault((cand.unit.id if cand.unit else None, "decision"), []).append(cand)
        findings = emit_groups(self, groups)
        legs = _lint_by_group(ctx, ("EU-AIA-014b",), "decision")
        for key, hits in _legs_by_group(ctx, legs_005a, "scoring").items():
            legs.setdefault(key, []).extend(hits)
        _attach_lint_legs(findings, legs)
        return findings


# ---------------------------------------------------------------------------
# AUD-1104  Engagement or retention objective in prompt or code
# ---------------------------------------------------------------------------


class EngagementObjective(AuditRule):
    id = "AUD-1104"
    title = "Engagement or retention objective in prompt or code"
    priority = 11
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    requires_ai_surface = True
    tier = Tier.T2
    controls = (
        "EU:Art.5(1)(a)",
        "EU:Art.5(1)(b)",
        "LLM09",
        "NIST:GOVERN-1.1",
        "NIST:MAP-5.1",
        "NIST:MEASURE-2.11",
    )
    related_lint_rules = ("ALIGN-008",)
    known_failure_modes = (
        "a product-analytics dashboard that computes engagement is not an objective: the rule "
        "needs an imperative (maximise, keep, increase) or an objective assignment",
        "the vulnerable sub-finding rests on two regex co-occurrences in one file or prompt "
        "literal; a reading app for children with a streak feature is reported CRITICAL, and "
        "the finding says what co-occurred",
        "a prompt that discusses engagement tactics in order to avoid them is a mention when "
        "a discussion cue sits within 80 characters; without one it is reported",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Rewrite the objective as task completion and the user's own stated goals, and "
            "remove streak, scarcity and variable-reward mechanics from the model's instructions."
        ),
        alternatives=(
            "rewrite the prompt objective as task completion and user-stated goals",
            "remove streak, scarcity and variable-reward mechanics from the LLM-facing instructions",
            "aisafe ManipulationGuard on the output stage, FLAG, then aisafe measure",
            "an independent review of ranking objectives recorded on the system card",
        ),
        package=Package(
            mechanism="detector",
            symbols=("ManipulationGuard",),
            same_control=False,
            leaves_open=(
                "ManipulationGuard flags influence tactics in the response text; it does not see "
                "the objective in the prompt, which is removed or rewritten by hand."
            ),
        ),
    )

    def _vulnerable_nearby(self, ctx: AuditContext, facts: _Facts, signal: _Signal) -> str | None:
        """The vulnerable-group word that co-occurs with the objective, in the same prompt
        literal when there is one, else anywhere in the same file's signals."""
        literal = facts.literal_at(signal.file, signal.line)
        if literal is not None:
            match = pp.VULNERABLE_GROUP.search(_literal_text(ctx, literal))
            return match.group(0) if match else None
        for other in facts.by_kind("vulnerable"):
            if other.file == signal.file:
                return other.symbol
        return None

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not _has_ai_surface(ctx):
            return []
        facts = _facts(ctx)
        groups: dict[tuple[str | None, str | None], list[Candidate]] = {}
        for signal in facts.by_kind("engagement", "objective_code"):
            if signal.kind == "engagement" and _is_mention(ctx, signal):
                continue
            word = self._vulnerable_nearby(ctx, facts, signal)
            sub = "vulnerable" if word else None
            what = (
                "an engagement or retention objective in prompt material"
                if signal.kind == "engagement"
                else "an objective or reward variable optimises engagement"
            )
            notes = f"{what} ({signal.symbol})"
            if word:
                notes += f"; a vulnerable group is named alongside ({word})"
            cand = _candidate(
                ctx,
                signal,
                notes=f"{notes}. {LEGAL_CAVEAT}",
                sub=sub,
                severity=Severity.CRITICAL if sub else None,
            )
            groups.setdefault((cand.unit.id if cand.unit else None, sub), []).append(cand)
        findings = emit_groups(self, groups)
        legs = {}
        for hit in lint_hits(ctx, "ALIGN-008"):
            unit_id = _unit_id(ctx, hit.file)
            for finding in findings:
                if finding.scope.unit == unit_id:
                    legs.setdefault((unit_id, finding.sub), []).append(hit)
        _attach_lint_legs(findings, legs)
        return findings


# ---------------------------------------------------------------------------
# AUD-1105  AI nature concealed or no disclosure on the response path
# ---------------------------------------------------------------------------


class AIDisclosureAbsent(AuditRule):
    id = "AUD-1105"
    title = "AI nature concealed or no disclosure on the response path"
    priority = 11
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    requires_ai_surface = True
    tier = Tier.T2
    controls = (
        "EU:Art.50(1)",
        "EU:Art.50(2)",
        "EU:Art.5(1)(a)",
        "LLM09",
        "NIST:GOVERN-1.1",
        "NIST:GOVERN-1.7",
    )
    related_lint_rules = ("EU-AIA-013a", "EU-AIA-013b", "EU-AIA-050a", "EU-AIA-050b")
    known_failure_modes = (
        "a named persona (Ava) is not concealment; the regex needs a human claim or a "
        "concealment verb",
        "a disclosure delivered by the UI rather than the code is reported as absent",
        "the no-disclosure sub-finding is unit-level and LOW: it says no disclosure symbol was "
        "found, not that none is shown",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Delete any instruction to claim humanity and state the AI nature at first "
            "interaction and whenever asked; AIDisclosureGuard flags a response that claims to "
            "be human and can append the disclosure on the output stage."
        ),
        alternatives=(
            "delete the instruction and state the AI nature at first interaction",
            'aisafe AIDisclosureGuard(disclosure=..., append_when="on_claim")',
            "NeMo Guardrails AI-identity flow",
            "a UI banner at session start plus a disclosure on every channel the bot speaks through",
        ),
        package=Package(
            mechanism="detector",
            symbols=("AIDisclosureGuard",),
            same_control=True,
            leaves_open=(
                "AIDisclosureGuard flags a response that claims to be human and can append the "
                "disclosure text on the output stage; a prompt that instructs the model to claim "
                "humanity is deleted by hand, and disclosure shown by the UI is outside the guard."
            ),
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not _has_ai_surface(ctx):
            return []
        facts = _facts(ctx)
        groups: dict[tuple[str | None, str | None], list[Candidate]] = {}
        for signal in facts.by_kind("persona"):
            if _is_mention(ctx, signal):
                continue
            cand = _candidate(
                ctx,
                signal,
                notes=f"prompt material conceals the AI nature ({signal.symbol}). {LEGAL_CAVEAT}",
                sub="persona",
            )
            groups.setdefault((cand.unit.id if cand.unit else None, "persona"), []).append(cand)
        anchors_013b, legs_013b = _split_lint(
            ctx, facts, lint_hits(ctx, "EU-AIA-013b"), ("persona",)
        )
        for hit in anchors_013b:
            cand = _candidate(
                ctx,
                hit.file,
                hit.line,
                notes=f"a quoted instruction hides the AI nature (EU-AIA-013b). {LEGAL_CAVEAT}",
                sub="persona",
                snippet=hit.snippet,
            )
            groups.setdefault((cand.unit.id if cand.unit else None, "persona"), []).append(cand)
        for hit in lint_hits(ctx, "EU-AIA-050a", "EU-AIA-050b"):
            cand = _candidate(
                ctx,
                hit.file,
                hit.line,
                notes=f"generated content without a label ({hit.rule_id}). {LEGAL_CAVEAT}",
                sub="synthetic",
                severity=Severity.LOW,
                snippet=hit.snippet,
            )
            groups.setdefault((cand.unit.id if cand.unit else None, "synthetic"), []).append(cand)
        findings = emit_groups(self, groups)

        # Unit-level absence: a user-facing unit with model calls and no disclosure symbol.
        disclosed_units = {s.unit for s in facts.by_kind("disclosure")}
        for unit in ctx.inventory.units:
            if not getattr(unit, "ai_surface", False):
                continue
            if not (_unit_has(ctx, unit.id, "ingress") and _unit_has(ctx, unit.id, "llm_calls")):
                continue
            if unit.id in disclosed_units:
                continue
            why = (
                f"unit {unit.id} takes user input and calls a model, and no disclosure symbol "
                "(an AI-assistant statement, transparency_disclosure, ai_disclosure_output) "
                "appears in its code, config or prompt files"
            )
            finding = self.absence_finding(unit=unit, why=why)
            finding.sub = "no-disclosure"
            finding.severity = Severity.LOW
            finding.notes = f"{why}. {LEGAL_CAVEAT}"
            finding.fingerprint = _refingerprint(finding)
            findings.append(finding)
        legs = _lint_by_group(ctx, ("EU-AIA-013a",), "no-disclosure")
        for key, hits in _legs_by_group(ctx, legs_013b, "persona").items():
            legs.setdefault(key, []).extend(hits)
        _attach_lint_legs(findings, legs)
        return findings


def _refingerprint(finding: Finding) -> str:
    from aisafe.devtools.audit.model import fingerprint

    display = f"{finding.id}/{finding.sub}" if finding.sub else finding.id
    return fingerprint(display, finding.evidence[0].file, finding.evidence[0].snippet)


# ---------------------------------------------------------------------------
# AUD-1106  No manipulation control on the response path
# ---------------------------------------------------------------------------


class NoManipulationControl(AuditRule):
    id = "AUD-1106"
    title = "No manipulation control on the response path"
    priority = 11
    severity = Severity.MEDIUM
    basis = Basis.ABSENCE
    evidence_kind = EvidenceKind.ABSENCE
    match_kind = MatchKind.STRUCTURED
    requires_ai_surface = True
    tier = Tier.T2
    controls = ("EU:Art.5(1)(a)", "EU:Art.15", "LLM09", "NIST:MEASURE-2.7", "NIST:MANAGE-2.4")
    related_lint_rules = ()
    known_failure_modes = (
        "a control outside the tree (a gateway, vendor moderation) is invisible",
        "presence of the symbol is checked, not that it sits on the response path",
        "fires only in a unit that also carries a profile, engagement or persona signal, so a "
        "neutral assistant without one is not reported here",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Put a manipulation and disclosure control on the output stage and measure it: "
            "ManipulationGuard flags influence tactics, AIDisclosureGuard flags human claims."
        ),
        alternatives=(
            "aisafe ManipulationGuard and AIDisclosureGuard on output, then aisafe measure",
            "LLM Guard output scanners for banned topics plus a judge",
            "NeMo Guardrails output rails",
            "a human-reviewed sample of transcripts per week",
        ),
        package=Package(
            mechanism="detector",
            symbols=("ManipulationGuard", "AIDisclosureGuard"),
            same_control=True,
            leaves_open=(
                "Both guards are regex tables with an optional judge and ship UNMEASURED; they "
                "lower the odds that a manipulative response reaches the user and do nothing "
                "about the prompt or the ranking logic that produced it."
            ),
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not _has_ai_surface(ctx):
            return []
        facts = _facts(ctx)
        controlled = {s.unit for s in facts.by_kind("manipulation_control")}
        findings: list[Finding] = []
        for unit in ctx.inventory.units:
            if not getattr(unit, "ai_surface", False):
                continue
            if not (_unit_has(ctx, unit.id, "ingress") and _unit_has(ctx, unit.id, "llm_calls")):
                continue
            signals = facts.in_unit(unit.id, *_SIGNAL_KINDS_1106)
            if not signals or unit.id in controlled:
                continue
            kinds = sorted({s.kind for s in signals})
            why = (
                f"unit {unit.id} takes user input, calls a model and carries person signals "
                f"({', '.join(kinds)}), and no manipulation or disclosure control symbol appears "
                "in its code or config"
            )
            finding = self.absence_finding(unit=unit, why=why)
            finding.notes = f"{why}. {LEGAL_CAVEAT}"
            findings.append(finding)
        return findings


# ---------------------------------------------------------------------------
# AUD-1107  Prompt and algorithm audit not recorded
# ---------------------------------------------------------------------------


class PromptAuditNotRecorded(AuditRule):
    id = "AUD-1107"
    title = "Prompt and algorithm audit not recorded"
    priority = 11
    severity = Severity.INFO
    basis = Basis.ABSENCE
    evidence_kind = EvidenceKind.ABSENCE
    match_kind = MatchKind.STRUCTURED
    requires_ai_surface = True
    tier = Tier.T2
    controls = (
        "EU:Art.9",
        "EU:Art.11",
        "EU:Art.26",
        "NIST:GOVERN-1.1",
        "NIST:GOVERN-1.2",
        "NIST:MAP-1.1",
    )
    related_lint_rules = ("EU-AIA-011a",)
    known_failure_modes = (
        "the card records a claim; a review kept in a ticket system is reported as absent",
        "a reviewed_at older than the newest prompt file is not detected here",
        "silent without a card: AUD-1001 owns that absence",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Record on the system card who reviewed the prompts, the ranking and the "
            "personalisation logic for manipulation and profiling, and when: `aisafe init` "
            "writes the prompt_audit block with placeholders."
        ),
        alternatives=(
            "aisafe init, then fill prompt_audit with reviewer and date",
            "a PROMPT_REVIEW.md next to the prompts naming reviewer, date and scope",
            "a ticket per prompt change linked from the card",
            "an external review of ranking and personalisation logic",
        ),
        package=Package(
            mechanism="document",
            symbols=("aisafe init",),
            same_control=False,
            leaves_open=(
                "aisafe init writes the prompt_audit block with placeholders; the review it records "
                "is done by a person, and whether it was thorough is not something the tool can "
                "check."
            ),
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not _has_ai_surface(ctx):
            return []
        card = getattr(ctx.inventory, "system_card", None)
        if not isinstance(card, dict):
            return []
        facts = _facts(ctx)
        affected = card.get("affected_persons")
        if not facts.by_kind(*_PERSON_KINDS) and vocab.is_unset(affected):
            return []
        block = card.get("prompt_audit")
        if isinstance(block, dict) and not (
            vocab.is_unset(block.get("reviewed_at")) or vocab.is_unset(block.get("reviewer"))
        ):
            return []
        relpath = str(card.get("file") or "ai-system-card.yaml")
        if block is None:
            why = f"{relpath} has no prompt_audit block"
        else:
            why = f"{relpath} has a prompt_audit block with reviewer or reviewed_at unset"
        why += (
            "; the tree carries person signals or the card names affected persons, and nobody is "
            "recorded as having reviewed the prompts, ranking and personalisation for manipulation "
            "and profiling"
        )
        finding = self.finding(
            file=relpath,
            line=0,
            snippet=why,
            evidence=[Evidence(role="absence", file=relpath, line=0, snippet=why)],
            scope=Scope(kind="repo", name="."),
            notes=f"{why}. {LEGAL_CAVEAT}",
        )
        return [finding]


RULES = [
    PersonProfileInPrompt,
    AffectInference,
    PersonScoring,
    EngagementObjective,
    AIDisclosureAbsent,
    NoManipulationControl,
    PromptAuditNotRecorded,
]
