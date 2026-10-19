"""aisg/devtools/attest.py
-----------------------
`aisg attest` -- the deterministic half of "declaring" a system: evaluate the level
criteria against the documents the other commands wrote, and let a named owner sign the
result.

    aisg attest . --owner "J. Doe <risk owner>"            # writes .aisg-audit/attestation.{json,md}
    aisg attest . --owner "J. Doe <risk owner>" --html     # plus attestation.html
    aisg attest . --check --require-level 2                # CI: exit 1 when level 2 is not reached

Levels are rows of criteria in `attest-levels.yaml` (shipped in the wheel, mirrored at
`config/`): 0 audited, 1 triaged, 2 measured, 3 governed. The level reached is the highest
N such that every criterion of levels 0..N is met. Each criterion names the data it read
and what is missing, so a reader can see why a level was or was not reached.

What this is not: a compliance verdict. The statement says the owner states that the
tree at a commit meets the listed criteria on a date; the tool checked those criteria and
nothing else, and the document says so. No model is called, nothing is installed, no
socket is opened; `walk.git_meta` (read-only `git rev-parse` / `git status`) is the only
subprocess. The accepted risks are the baseline's reasons, copied, never edited: the only
way a risk becomes accepted is `aisg audit --amend-baseline --accept`.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Sequence

from aisg.devtools._config import apply_tool_config
from aisg.devtools.audit import vocab, walk
from aisg.devtools.audit.baseline import BaselineDocument, BaselineError, read_baseline
from aisg.devtools.audit.model import DISCLAIMER as AUDIT_DISCLAIMER
from aisg.devtools.audit.model import SCHEMA_VERSION, redact
from aisg.devtools.audit.patterns import OWN_HTML_MARKER_LINE
from aisg.devtools.audit.report import BANNED_PHRASES, tool_version

__all__ = [
    "CRITERION_KINDS",
    "DISCLAIMER",
    "NOT_CONFIGURABLE",
    "TEMPLATES",
    "AttestError",
    "Criterion",
    "CriterionResult",
    "Inputs",
    "Levels",
    "badge",
    "build_document",
    "build_parser",
    "check_templates",
    "evaluate",
    "evaluate_all",
    "level_reached",
    "load_inputs",
    "load_levels",
    "main",
    "render_html",
    "render_markdown",
    "validate_owner",
]

KIND = "attestation"
TOOL_NAME = "aisg-attest"
PROG = "aisg attest"
CONFIG_SECTION = "aisg-attest"

DEFAULT_REPORT = ".aisg-audit/audit-report-after.json"
FALLBACK_REPORT = ".aisg-audit/audit-report.json"
DEFAULT_BASELINE = ".aisg-audit/audit-baseline.json"
DEFAULT_MEASURE = ".aisg-audit/measure-report.json"
DEFAULT_PROBE = ".aisg-audit/probe-report.json"
DEFAULT_DECISION = ".aisg-audit/decision.json"
DEFAULT_CARD = "ai-system-card.yaml"
DEFAULT_OUT_DIR = ".aisg-audit"
LEVELS_FILE = "attest-levels.yaml"
LEVELS_KIND = "attest-levels"

# `owner` is an act of signing and `check` decides whether anything is written: neither
# may come from a pyproject default.
NOT_CONFIGURABLE: frozenset[str] = frozenset({"owner", "check"})

EXIT_OK = 0
EXIT_NOT_MET = 1
EXIT_FATAL = 2
EXIT_INTERRUPTED = 130

CRITERION_KINDS: tuple[str, ...] = (
    "report_present",
    "report_names_head",
    "unknown_listed",
    "no_open_findings_at_or_above",
    "external_tools_attempted",
    "accepted_reasons_present",
    "document_present",
    "measure_thresholds",
    "probe_passing_if_present",
    "rules_closed",
    "card_fields_set",
    "card_section_fresh",
    "accepted_risks_owned",
    "tree_clean",
)
DOCUMENTS: tuple[str, ...] = ("measure", "probe", "decision")
_SEVERITIES = ("info", "low", "medium", "high", "critical")
_OWNER_MAX = 200
_OWNER_BAD_RE = re.compile(r"[\x00-\x1f\x7f]")
_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")

# ---------------------------------------------------------------------------
# Fixed strings: everything a renderer emits is here, so `check_templates` can scan them.
# ---------------------------------------------------------------------------

DISCLAIMER = (
    AUDIT_DISCLAIMER
    + " An attestation is a statement by the named owner; the tool checked the listed "
    "criteria and nothing else."
)
_T_STATEMENT = (
    "{owner} states that {path} at commit {sha} meets the AISG level {level} ({name}) "
    "criteria on {date}."
)
_T_STATEMENT_NONE = (
    "{owner} states that {path} at commit {sha} was checked against the AISG level criteria "
    "on {date} and reaches no level: the level 0 criteria are not all met."
)
_T_NO_OWNER = "(no owner: --check run)"
_T_NO_SHA = "an unknown commit"
_T_TITLE = "aisg attest"
_T_MD_H1 = "# aisg attest"
_T_LEVEL_LINE = "level reached: {level} ({name})"
_T_LEVEL_NONE = "level reached: none"
_T_CRITERIA = "Criteria"
_T_INPUTS = "Inputs"
_T_ACCEPTED = "Accepted risks"
_T_RESIDUAL = "Residual"
_T_UNKNOWN = "UNKNOWN"
_T_NEXT_REVIEW = "next review by: {date}"
_T_CRITERIA_HEADER = "| id | level | met | evidence | missing |"
_T_TABLE_RULE_5 = "|---|---|---|---|---|"
_T_INPUTS_HEADER = "| kind | file | generated_at | age (days) |"
_T_TABLE_RULE_4 = "|---|---|---|---|"
_T_ACCEPTED_HEADER = "| fingerprint | rule | file | reason | owner |"
_T_RESIDUAL_LINE = "open findings: {open}; accepted: {accepted}; by severity: {items}"
_T_UNKNOWN_ITEM = "[{category}] {what}: {why}"
_T_UNKNOWN_NONE = "(none listed)"
_T_ACCEPTED_NONE = "(no accepted risks)"
_T_YES = "yes"
_T_NO = "no"
_T_DASH = "-"
_T_ABSENT = "absent"
_T_MISSING_NONE = ""
_T_BADGE_LABEL = "aisg"
_T_BADGE_LEVEL = "level {level} ({date})"
_T_BADGE_NONE = "no level ({date})"
_T_HTML_TITLE = "aisg attest: {path}"
_T_HTML_H1 = "Attestation"

TEMPLATES: tuple[str, ...] = (
    DISCLAIMER,
    _T_STATEMENT,
    _T_STATEMENT_NONE,
    _T_NO_OWNER,
    _T_NO_SHA,
    _T_TITLE,
    _T_MD_H1,
    _T_LEVEL_LINE,
    _T_LEVEL_NONE,
    _T_CRITERIA,
    _T_INPUTS,
    _T_ACCEPTED,
    _T_RESIDUAL,
    _T_UNKNOWN,
    _T_NEXT_REVIEW,
    _T_CRITERIA_HEADER,
    _T_TABLE_RULE_5,
    _T_INPUTS_HEADER,
    _T_TABLE_RULE_4,
    _T_ACCEPTED_HEADER,
    _T_RESIDUAL_LINE,
    _T_UNKNOWN_ITEM,
    _T_UNKNOWN_NONE,
    _T_ACCEPTED_NONE,
    _T_YES,
    _T_NO,
    _T_DASH,
    _T_ABSENT,
    _T_BADGE_LABEL,
    _T_BADGE_LEVEL,
    _T_BADGE_NONE,
    _T_HTML_TITLE,
    _T_HTML_H1,
)

_BANNED_WORD_RE = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)


def check_templates() -> list[str]:
    """Banned phrases (and the one banned word) present in this module's fixed strings."""
    found: list[str] = []
    for template in TEMPLATES:
        lowered = template.lower()
        for phrase in BANNED_PHRASES:
            if phrase in lowered:
                found.append(phrase)
        if _BANNED_WORD_RE.search(template):
            found.append(_BANNED_WORD_RE.pattern)
    return sorted(set(found))


class AttestError(Exception):
    """A fatal condition: the message is one line; `main` maps it to exit 2."""


# ---------------------------------------------------------------------------
# Levels (the criteria data)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Criterion:
    id: str
    level: int
    kind: str
    params: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class Level:
    level: int
    name: str
    criteria: tuple[Criterion, ...]


@dataclass(frozen=True)
class Levels:
    review_interval_days: int
    levels: tuple[Level, ...]
    source: str

    def criteria(self) -> list[Criterion]:
        return [c for level in self.levels for c in level.criteria]

    def name_of(self, level: int) -> str:
        for entry in self.levels:
            if entry.level == level:
                return entry.name
        return ""


def default_levels_path() -> Path:
    from aisg.config import preset_path

    return preset_path(LEVELS_FILE)


def load_levels(path: Path | None = None) -> Levels:
    """Parse and validate the criteria file. Raises AttestError on any shape problem."""
    try:
        import yaml
    except ModuleNotFoundError as exc:  # pragma: no cover - pyyaml is a core dependency
        raise AttestError("pyyaml is required: pip install pyyaml") from exc
    source = Path(path) if path is not None else default_levels_path()
    try:
        data = yaml.safe_load(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AttestError(f"criteria {source.as_posix()}: {exc.strerror or exc}") from exc
    except yaml.YAMLError as exc:
        raise AttestError(f"criteria {source.as_posix()}: not valid YAML ({exc})") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA_VERSION:
        raise AttestError(f"criteria {source.as_posix()}: schema is not {SCHEMA_VERSION}")
    if data.get("kind") != LEVELS_KIND:
        raise AttestError(f"criteria {source.as_posix()}: kind is not {LEVELS_KIND}")
    interval = data.get("review_interval_days", 90)
    if isinstance(interval, bool) or not isinstance(interval, int) or interval <= 0:
        raise AttestError(
            f"criteria {source.as_posix()}: review_interval_days must be a positive integer"
        )
    raw_levels = data.get("levels")
    if not isinstance(raw_levels, list) or not raw_levels:
        raise AttestError(f"criteria {source.as_posix()}: levels must be a non-empty list")
    levels: list[Level] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_levels):
        if not isinstance(raw, dict) or raw.get("level") != index:
            raise AttestError(
                f"criteria {source.as_posix()}: levels must be contiguous from 0; entry {index} is not level {index}"
            )
        name = str(raw.get("name") or "")
        if not name or not name.isascii() or not re.fullmatch(r"[a-z][a-z0-9_-]*", name):
            raise AttestError(
                f"criteria {source.as_posix()}: level {index} needs an ASCII lowercase name"
            )
        criteria: list[Criterion] = []
        for item in raw.get("criteria") or []:
            if not isinstance(item, dict) or not item.get("id") or not item.get("kind"):
                raise AttestError(
                    f"criteria {source.as_posix()}: level {index} has a criterion without id or kind"
                )
            cid, kind = str(item["id"]), str(item["kind"])
            if cid in seen_ids:
                raise AttestError(f"criteria {source.as_posix()}: duplicate criterion id {cid}")
            if kind not in CRITERION_KINDS:
                raise AttestError(f"criteria {source.as_posix()}: {cid} has unknown kind {kind!r}")
            seen_ids.add(cid)
            params = {k: v for k, v in item.items() if k not in ("id", "kind")}
            criteria.append(Criterion(cid, index, kind, params))
        if not criteria:
            raise AttestError(f"criteria {source.as_posix()}: level {index} has no criteria")
        levels.append(Level(index, name, tuple(criteria)))
    return Levels(int(interval), tuple(levels), source.as_posix())


def validate_levels(levels: Levels, rule_ids: set[str], card_defaults: dict[str, Any]) -> list[str]:
    """Problems a criteria file can carry beyond its shape: a rule id the registry does not
    know, a card field path the default card does not have. Empty means none."""
    problems: list[str] = []
    for criterion in levels.criteria():
        for rule in criterion.params.get("rules") or []:
            if str(rule) not in rule_ids:
                problems.append(f"{criterion.id}: rule {rule} is not in the registry")
        fields = list(criterion.params.get("fields") or [])
        if criterion.kind == "card_fields_set":
            for path in fields:
                if _resolve(card_defaults, str(path), missing=_MISSING) is _MISSING:
                    problems.append(f"{criterion.id}: card field {path} is not on the default card")
        if criterion.kind == "card_section_fresh":
            section = str(criterion.params.get("section") or "")
            block = card_defaults.get(section)
            if not isinstance(block, dict):
                problems.append(
                    f"{criterion.id}: card section {section} is not on the default card"
                )
            else:
                date_field = criterion.params.get("date_field")
                if date_field and str(date_field) not in block:
                    problems.append(
                        f"{criterion.id}: card field {section}.{date_field} is not on the default card"
                    )
                for path in fields:
                    if str(path) not in block:
                        problems.append(
                            f"{criterion.id}: card field {section}.{path} is not on the default card"
                        )
    return problems


_MISSING = object()


def _resolve(data: Any, dotted: str, missing: Any = None) -> Any:
    current = data
    for part in dotted.split("."):
        if not isinstance(current, dict) or part not in current:
            return missing
        current = current[part]
    return current


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------


@dataclass
class Document:
    kind: str
    path: str | None
    body: dict[str, Any] | None
    note: str = ""

    @property
    def present(self) -> bool:
        return self.body is not None

    @property
    def generated_at(self) -> str | None:
        if self.body is None:
            return None
        value = self.body.get("generated_at")
        return value if isinstance(value, str) else None


@dataclass
class Inputs:
    root: Path
    report: Document
    baseline: BaselineDocument | None
    baseline_path: str | None
    measure: Document
    probe: Document
    decision: Document
    card: Document
    head: str | None
    dirty: bool
    notes: list[str] = field(default_factory=list)

    def document(self, name: str) -> Document:
        return {"measure": self.measure, "probe": self.probe, "decision": self.decision}[name]

    def accepted(self) -> dict[str, str]:
        return dict(self.baseline.accepted) if self.baseline is not None else {}

    def findings(self) -> list[dict[str, Any]]:
        body = self.report.body or {}
        return [f for f in body.get("findings") or [] if isinstance(f, dict)]

    def open_findings(self) -> list[dict[str, Any]]:
        accepted = self.accepted()
        return [f for f in self.findings() if str(f.get("fingerprint") or "") not in accepted]


def _read_json(path: Path, what: str) -> dict[str, Any] | None:
    """A JSON object, None when the file is absent; an unreadable or non-object file is fatal."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise AttestError(f"{what} {path.as_posix()}: {exc.strerror or exc}") from exc
    except json.JSONDecodeError as exc:
        raise AttestError(f"{what} {path.as_posix()}: not valid JSON ({exc})") from exc
    if not isinstance(data, dict):
        raise AttestError(f"{what} {path.as_posix()}: not a JSON object")
    return data


def _document(root: Path, rel: str, kind: str, expect_kind: str | None) -> Document:
    body = _read_json(root / rel, f"{kind} document")
    if body is None:
        return Document(kind, None, None)
    if body.get("schema") != SCHEMA_VERSION:
        raise AttestError(f"{kind} document {rel}: schema is not {SCHEMA_VERSION}")
    if expect_kind is not None and body.get("kind") != expect_kind:
        raise AttestError(f"{kind} document {rel}: kind is not {expect_kind}")
    return Document(kind, rel, body)


def load_inputs(
    root: Path,
    *,
    report: str = DEFAULT_REPORT,
    baseline: str = DEFAULT_BASELINE,
    measure: str = DEFAULT_MEASURE,
    probe: str = DEFAULT_PROBE,
    decision: str = DEFAULT_DECISION,
    card: str = DEFAULT_CARD,
) -> Inputs:
    """Read every input. The audit report is required (the default falls back to the survey
    report with a note); every other document is recorded as absent when missing."""
    root = Path(root).resolve()
    notes: list[str] = []
    report_doc = _document(root, report, "audit", "audit")
    if not report_doc.present and report == DEFAULT_REPORT and (root / FALLBACK_REPORT).is_file():
        report_doc = _document(root, FALLBACK_REPORT, "audit", "audit")
        notes.append(f"no {DEFAULT_REPORT}; using the survey report {FALLBACK_REPORT}")
    if not report_doc.present:
        raise AttestError(
            f"no audit report at {report}; run `aisg audit . --format json -o {report}` first"
        )

    baseline_doc: BaselineDocument | None = None
    baseline_path: str | None = None
    if (root / baseline).is_file():
        try:
            baseline_doc = read_baseline(root / baseline)
            baseline_path = baseline
        except BaselineError as exc:
            raise AttestError(f"baseline {baseline}: {exc}") from exc

    measure_doc = _document(root, measure, "measure", None)
    probe_doc = _document(root, probe, "probe", None)
    decision_doc = _document(root, decision, "decision", "decision")

    card_doc = Document("card", None, None)
    card_path = root / card
    if card_path.is_file():
        from aisg.devtools.audit.discover import read_system_card

        body = read_system_card(card_path)
        if body is None:
            raise AttestError(f"card {card}: not a readable YAML mapping")
        card_doc = Document("card", card, body)

    head, dirty = walk.git_meta(root)
    return Inputs(
        root=root,
        report=report_doc,
        baseline=baseline_doc,
        baseline_path=baseline_path,
        measure=measure_doc,
        probe=probe_doc,
        decision=decision_doc,
        card=card_doc,
        head=head,
        dirty=dirty,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Criteria evaluation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CriterionResult:
    id: str
    level: int
    met: bool
    evidence: str
    missing: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "level": self.level,
            "met": self.met,
            "evidence": self.evidence,
            "missing": self.missing,
        }


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            parsed = datetime.strptime(text[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _age_days(stamp: Any, now: datetime) -> int | None:
    then = _parse_iso(stamp)
    if then is None:
        return None
    return max(0, (now - then).days)


def _rank(severity: Any) -> int:
    try:
        return _SEVERITIES.index(str(severity).lower())
    except ValueError:
        return -1


def _short(sha: str | None) -> str:
    return sha[:7] if sha else _T_NO_SHA


def _result(criterion: Criterion, met: bool, evidence: str, missing: str = "") -> CriterionResult:
    return CriterionResult(
        criterion.id,
        criterion.level,
        met,
        redact(evidence).encode("ascii", "replace").decode("ascii"),
        redact(missing).encode("ascii", "replace").decode("ascii") if not met else _T_MISSING_NONE,
    )


def _report_present(
    c: Criterion, inputs: Inputs, now: datetime, owner: str | None
) -> CriterionResult:
    doc = inputs.report
    max_age = c.params.get("max_age_days")
    age = _age_days(doc.generated_at, now)
    if age is None:
        return _result(
            c, False, f"report {doc.path}", "the report carries no readable generated_at"
        )
    evidence = f"report {doc.path}, {age} day(s) old"
    if isinstance(max_age, int) and age > max_age:
        return _result(c, False, evidence, f"report is {age} day(s) old, the limit is {max_age}")
    return _result(c, True, evidence)


def _report_names_head(
    c: Criterion, inputs: Inputs, now: datetime, owner: str | None
) -> CriterionResult:
    target = (inputs.report.body or {}).get("target") or {}
    named = str(target.get("git_sha") or "") if isinstance(target, dict) else ""
    if inputs.head is None:
        return _result(
            c,
            False,
            f"report names {_short(named or None)}",
            "HEAD is unknown: not a git checkout, or git is not on PATH",
        )
    if not named:
        return _result(
            c,
            False,
            f"HEAD is {_short(inputs.head)}",
            "the report names no commit (target.git_sha)",
        )
    if named != inputs.head:
        return _result(
            c,
            False,
            f"report names {_short(named)}, HEAD is {_short(inputs.head)}",
            "the report was produced at another commit; re-run the audit",
        )
    return _result(c, True, f"report names {_short(named)} = HEAD")


def _unknown_listed(
    c: Criterion, inputs: Inputs, now: datetime, owner: str | None
) -> CriterionResult:
    body = inputs.report.body or {}
    items = body.get("unknown")
    if not isinstance(items, list):
        return _result(
            c,
            False,
            "report has no unknown list",
            "the report does not list what it could not establish",
        )
    return _result(c, True, f"{len(items)} UNKNOWN item(s) listed")


def _no_open_findings(
    c: Criterion, inputs: Inputs, now: datetime, owner: str | None
) -> CriterionResult:
    floor = _rank(c.params.get("severity", "high"))
    accepted = inputs.accepted()
    counted = [f for f in inputs.findings() if _rank(f.get("severity")) >= floor]
    open_ = [f for f in counted if str(f.get("fingerprint") or "") not in accepted]
    evidence = f"{len(counted)} finding(s) at or above {c.params.get('severity', 'high')}, {len(counted) - len(open_)} accepted with a reason"
    if open_:
        ids = ", ".join(
            str(f.get("id")) + (f"/{f['sub']}" if f.get("sub") else "") for f in open_[:5]
        )
        more = f" (+{len(open_) - 5} more)" if len(open_) > 5 else ""
        return _result(c, False, evidence, f"{len(open_)} open: {ids}{more}")
    return _result(c, True, evidence)


def _external_tools_attempted(
    c: Criterion, inputs: Inputs, now: datetime, owner: str | None
) -> CriterionResult:
    tools = (inputs.report.body or {}).get("external_tools") or []
    skipped = [
        str(t.get("name"))
        for t in tools
        if isinstance(t, dict) and t.get("status") == "skipped_by_flag"
    ]
    if skipped:
        return _result(
            c,
            False,
            f"{len(tools)} external tool(s) listed",
            f"skipped by flag: {', '.join(skipped)}; run the audit without --no-external",
        )
    return _result(c, True, f"{len(tools)} external tool(s) listed, none skipped by flag")


def _accepted_reasons_present(
    c: Criterion, inputs: Inputs, now: datetime, owner: str | None
) -> CriterionResult:
    if inputs.baseline is None:
        return _result(
            c,
            False,
            "no baseline",
            f"no baseline at {DEFAULT_BASELINE}; write one with aisg audit --write-baseline",
        )
    total = len(inputs.baseline.fingerprints)
    reasoned = len(inputs.baseline.accepted)
    bare = total - reasoned
    evidence = f"{total} fingerprint(s) in the baseline, {reasoned} with a reason"
    if bare > 0:
        return _result(
            c,
            False,
            evidence,
            f"{bare} fingerprint(s) without a reason are suppressions, not acceptances; aisg audit --amend-baseline --accept",
        )
    return _result(c, True, evidence)


def _document_present(
    c: Criterion, inputs: Inputs, now: datetime, owner: str | None
) -> CriterionResult:
    name = str(c.params.get("document") or "")
    if name not in DOCUMENTS:
        return _result(c, False, "", f"unknown document kind {name!r}")
    doc = inputs.document(name)
    if not doc.present:
        return _result(
            c, False, f"no {name} document", f"no {name} document under {DEFAULT_OUT_DIR}/"
        )
    age = _age_days(doc.generated_at, now)
    max_age = c.params.get("max_age_days")
    if age is None:
        return _result(
            c, False, f"{name} document {doc.path}", "the document carries no readable generated_at"
        )
    evidence = f"{name} document {doc.path}, {age} day(s) old"
    if isinstance(max_age, int) and age > max_age:
        return _result(c, False, evidence, f"document is {age} day(s) old, the limit is {max_age}")
    return _result(c, True, evidence)


def _measure_thresholds(
    c: Criterion, inputs: Inputs, now: datetime, owner: str | None
) -> CriterionResult:
    doc = inputs.measure
    if not doc.present:
        return _result(
            c, False, "no measure document", f"no measure report under {DEFAULT_OUT_DIR}/"
        )
    guards = [g for g in (doc.body or {}).get("guards") or [] if isinstance(g, dict)]
    over = [str(g.get("name")) for g in guards if g.get("threshold_failures")]
    unavailable = [str(g.get("name")) for g in guards if g.get("unavailable")]
    evidence = f"{len(guards)} guard(s) in {doc.path}"
    if not guards:
        return _result(c, False, evidence, "the measure report lists no guard")
    missing: list[str] = []
    if over:
        missing.append(f"over a declared threshold: {', '.join(over)}")
    if unavailable:
        missing.append(f"unavailable (not exercised): {', '.join(unavailable)}")
    if missing:
        return _result(c, False, evidence, "; ".join(missing))
    return _result(c, True, evidence + ", none over a threshold, none unavailable")


def _probe_passing_if_present(
    c: Criterion, inputs: Inputs, now: datetime, owner: str | None
) -> CriterionResult:
    doc = inputs.probe
    if not doc.present:
        return _result(c, True, "no probe report (the criterion applies only when one exists)")
    summary = (doc.body or {}).get("summary") or {}
    failed = int(summary.get("failed") or 0)
    errors = int(summary.get("errors") or 0)
    evidence = f"probe {doc.path}: sent {summary.get('sent', 0)}, failed {failed}, errors {errors}"
    if failed or errors:
        return _result(
            c, False, evidence, "a probe case got through or never reached a working endpoint"
        )
    return _result(c, True, evidence)


def _rules_closed(
    c: Criterion, inputs: Inputs, now: datetime, owner: str | None
) -> CriterionResult:
    wanted = {str(r) for r in c.params.get("rules") or []}
    open_ids = sorted(
        {str(f.get("id")) for f in inputs.open_findings() if str(f.get("id")) in wanted}
    )
    evidence = f"rules {', '.join(sorted(wanted))}"
    if open_ids:
        return _result(c, False, evidence, f"open: {', '.join(open_ids)}")
    return _result(c, True, evidence + ": no open finding")


def _card_fields_set(
    c: Criterion, inputs: Inputs, now: datetime, owner: str | None
) -> CriterionResult:
    if not inputs.card.present:
        return _result(c, False, "no system card", f"no {DEFAULT_CARD}; aisg init writes one")
    unset = [
        str(p)
        for p in c.params.get("fields") or []
        if vocab.is_unset(_resolve(inputs.card.body, str(p)))
    ]
    evidence = f"card {inputs.card.path}"
    if unset:
        return _result(c, False, evidence, f"unset or placeholder: {', '.join(unset)}")
    return _result(c, True, evidence + ": every listed field is set")


def _card_section_fresh(
    c: Criterion, inputs: Inputs, now: datetime, owner: str | None
) -> CriterionResult:
    if not inputs.card.present:
        return _result(c, False, "no system card", f"no {DEFAULT_CARD}; aisg init writes one")
    section = str(c.params.get("section") or "")
    block = (inputs.card.body or {}).get(section)
    if not isinstance(block, dict):
        return _result(c, False, f"card {inputs.card.path}", f"no {section} block on the card")
    fields = [str(p) for p in c.params.get("fields") or []]
    unset = [f for f in fields if vocab.is_unset(block.get(f))]
    if unset:
        return _result(
            c,
            False,
            f"card {inputs.card.path}",
            f"{section}: unset or placeholder: {', '.join(unset)}",
        )
    max_age = c.params.get("max_age_days")
    raw_date_field = c.params.get("date_field")
    date_field = str(raw_date_field) if raw_date_field else None
    if date_field is not None and isinstance(max_age, int):
        age = _age_days(block.get(date_field), now)
        if age is None:
            return _result(
                c,
                False,
                f"card {inputs.card.path}",
                f"{section}.{date_field} is not a readable date",
            )
        if age > max_age:
            return _result(
                c,
                False,
                f"{section}.{date_field} is {age} day(s) old",
                f"older than {max_age} days; review again",
            )
        return _result(c, True, f"{section} reviewed {age} day(s) ago by {block.get('reviewer')}")
    return _result(c, True, f"{section}: every listed field is set")


def _accepted_risks_owned(
    c: Criterion, inputs: Inputs, now: datetime, owner: str | None
) -> CriterionResult:
    accepted = inputs.accepted()
    if not accepted:
        return _result(c, True, "no accepted risks")
    if not owner:
        return _result(
            c,
            False,
            f"{len(accepted)} accepted risk(s)",
            "no owner given; pass --owner so each accepted risk is owned",
        )
    return _result(c, True, f"{len(accepted)} accepted risk(s), each owned by {owner}")


def _tree_clean(c: Criterion, inputs: Inputs, now: datetime, owner: str | None) -> CriterionResult:
    if inputs.head is None:
        return _result(c, False, "no git HEAD", "not a git checkout, or git is not on PATH")
    if inputs.dirty:
        return _result(
            c,
            False,
            f"HEAD {_short(inputs.head)}, working tree has uncommitted changes",
            "the working tree has uncommitted changes; commit or stash before attesting a governed level",
        )
    return _result(c, True, f"HEAD {_short(inputs.head)}, working tree has no uncommitted changes")


_EVALUATORS: dict[str, Callable[[Criterion, Inputs, datetime, str | None], CriterionResult]] = {
    "report_present": _report_present,
    "report_names_head": _report_names_head,
    "unknown_listed": _unknown_listed,
    "no_open_findings_at_or_above": _no_open_findings,
    "external_tools_attempted": _external_tools_attempted,
    "accepted_reasons_present": _accepted_reasons_present,
    "document_present": _document_present,
    "measure_thresholds": _measure_thresholds,
    "probe_passing_if_present": _probe_passing_if_present,
    "rules_closed": _rules_closed,
    "card_fields_set": _card_fields_set,
    "card_section_fresh": _card_section_fresh,
    "accepted_risks_owned": _accepted_risks_owned,
    "tree_clean": _tree_clean,
}
assert set(_EVALUATORS) == set(CRITERION_KINDS)


def evaluate(
    criterion: Criterion, inputs: Inputs, now: datetime, owner: str | None = None
) -> CriterionResult:
    return _EVALUATORS[criterion.kind](criterion, inputs, now, owner)


def evaluate_all(
    levels: Levels, inputs: Inputs, now: datetime, owner: str | None = None
) -> list[CriterionResult]:
    return [evaluate(c, inputs, now, owner) for c in levels.criteria()]


def level_reached(levels: Levels, results: Sequence[CriterionResult]) -> int | None:
    """The highest N with every criterion of levels 0..N met; None when level 0 is not met."""
    met_by_level: dict[int, bool] = {}
    for result in results:
        met_by_level[result.level] = met_by_level.get(result.level, True) and result.met
    reached: int | None = None
    for level in levels.levels:
        if met_by_level.get(level.level, False):
            reached = level.level
        else:
            break
    return reached


# ---------------------------------------------------------------------------
# The documents
# ---------------------------------------------------------------------------


def validate_owner(owner: str | None) -> str:
    text = (owner or "").strip()
    if not text:
        raise AttestError(
            '--owner is required to write an attestation: a person signs, e.g. --owner "J. Doe <risk owner>"'
        )
    if not text.isascii() or _OWNER_BAD_RE.search(text):
        raise AttestError("--owner must be printable ASCII")
    if len(text) > _OWNER_MAX:
        raise AttestError(f"--owner is longer than {_OWNER_MAX} characters")
    return text


def _accepted_risks(inputs: Inputs, owner: str | None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    if inputs.baseline is None:
        return out
    for fingerprint, reason in sorted(inputs.baseline.accepted.items()):
        entry = inputs.baseline.index.get(fingerprint) or {}
        out.append(
            {
                "fingerprint": fingerprint,
                "rule": entry.get("rule"),
                "file": entry.get("file"),
                "reason": reason,
                "owner": owner,
            }
        )
    return out


def _inputs_block(inputs: Inputs, now: datetime) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    def row(kind: str, path: str | None, stamp: str | None) -> dict[str, Any]:
        return {
            "kind": kind,
            "file": path,
            "generated_at": stamp,
            "age_days": _age_days(stamp, now),
        }

    rows.append(row("audit", inputs.report.path, inputs.report.generated_at))
    rows.append(
        row(
            "baseline",
            inputs.baseline_path,
            inputs.baseline.generated_at if inputs.baseline else None,
        )
    )
    for name in DOCUMENTS:
        doc = inputs.document(name)
        rows.append(row(name, doc.path, doc.generated_at))
    rows.append(row("card", inputs.card.path, None))
    return rows


def build_document(
    inputs: Inputs,
    levels: Levels,
    results: Sequence[CriterionResult],
    owner: str | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The attestation, keys in the documented order."""
    stamp_dt = now or datetime.now(timezone.utc)
    generated_at = stamp_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    date = stamp_dt.strftime("%Y-%m-%d")
    reached = level_reached(levels, results)
    name = levels.name_of(reached) if reached is not None else None
    who = owner or _T_NO_OWNER
    path = inputs.root.name or inputs.root.as_posix()
    if reached is None:
        statement = _T_STATEMENT_NONE.format(
            owner=who, path=path, sha=_short(inputs.head), date=date
        )
    else:
        statement = _T_STATEMENT.format(
            owner=who, path=path, sha=_short(inputs.head), level=reached, name=name, date=date
        )
    accepted = _accepted_risks(inputs, owner)
    findings = inputs.findings()
    by_severity = ((inputs.report.body or {}).get("summary") or {}).get("by_severity") or {}
    unknown = [u for u in (inputs.report.body or {}).get("unknown") or [] if isinstance(u, dict)]
    next_review = (stamp_dt + timedelta(days=levels.review_interval_days)).strftime("%Y-%m-%d")
    return {
        "schema": SCHEMA_VERSION,
        "kind": KIND,
        "tool": {"name": TOOL_NAME, "version": tool_version()},
        "target": {"path": inputs.root.as_posix(), "git_sha": inputs.head, "dirty": inputs.dirty},
        "generated_at": generated_at,
        "owner": owner,
        "level": {
            "reached": reached,
            "name": name,
            "statement": statement,
            "criteria": [r.to_dict() for r in results],
        },
        "inputs": _inputs_block(inputs, stamp_dt),
        "accepted_risks": accepted,
        "unknown": unknown,
        "residual": {
            "findings_by_severity": {k: int(v) for k, v in by_severity.items()}
            if isinstance(by_severity, dict)
            else {},
            "open": len(inputs.open_findings()),
            "accepted": len(findings) - len(inputs.open_findings()),
        },
        "next_review_by": next_review,
        "notes": list(inputs.notes),
        "disclaimer": DISCLAIMER,
    }


def badge(doc: dict[str, Any]) -> dict[str, Any]:
    """A shields.io endpoint document. Never green, never red: a level is a list of criteria
    met on a date, not a grade."""
    level = doc["level"]["reached"]
    date = str(doc["generated_at"])[:10]
    if level is None or level == 0:
        message = (
            _T_BADGE_NONE.format(date=date)
            if level is None
            else _T_BADGE_LEVEL.format(level=0, date=date)
        )
        color = "lightgrey"
    else:
        message = _T_BADGE_LEVEL.format(level=level, date=date)
        color = "informational"
    return {"schemaVersion": 1, "label": _T_BADGE_LABEL, "message": message, "color": color}


def _ascii(text: Any) -> str:
    return str(text).encode("ascii", "replace").decode("ascii")


def _level_line(doc: dict[str, Any]) -> str:
    level = doc["level"]
    if level["reached"] is None:
        return _T_LEVEL_NONE
    return _T_LEVEL_LINE.format(level=level["reached"], name=level["name"])


def _residual_line(doc: dict[str, Any]) -> str:
    residual = doc["residual"]
    items = ", ".join(f"{k} {v}" for k, v in residual["findings_by_severity"].items()) or _T_DASH
    return _T_RESIDUAL_LINE.format(
        open=residual["open"], accepted=residual["accepted"], items=items
    )


def render_markdown(doc: dict[str, Any]) -> str:
    lines = [
        _T_MD_H1,
        "",
        f"> {doc['disclaimer']}",
        "",
        doc["level"]["statement"],
        "",
        _level_line(doc),
        "",
    ]
    lines += [f"## {_T_CRITERIA}", "", _T_CRITERIA_HEADER, _T_TABLE_RULE_5]
    for c in doc["level"]["criteria"]:
        lines.append(
            f"| {c['id']} | {c['level']} | {_T_YES if c['met'] else _T_NO} | {_ascii(c['evidence']) or _T_DASH} | {_ascii(c['missing']) or _T_DASH} |"
        )
    lines += ["", f"## {_T_INPUTS}", "", _T_INPUTS_HEADER, _T_TABLE_RULE_4]
    for row in doc["inputs"]:
        lines.append(
            f"| {row['kind']} | {row['file'] or _T_ABSENT} | {row['generated_at'] or _T_DASH} | "
            f"{row['age_days'] if row['age_days'] is not None else _T_DASH} |"
        )
    lines += ["", f"## {_T_ACCEPTED}", ""]
    if doc["accepted_risks"]:
        lines += [_T_ACCEPTED_HEADER, _T_TABLE_RULE_5]
        for risk in doc["accepted_risks"]:
            lines.append(
                f"| {risk['fingerprint']} | {risk['rule'] or _T_DASH} | {risk['file'] or _T_DASH} | "
                f"{_ascii(risk['reason'])} | {risk['owner'] or _T_DASH} |"
            )
    else:
        lines.append(_T_ACCEPTED_NONE)
    lines += ["", f"## {_T_RESIDUAL}", "", _residual_line(doc), "", f"## {_T_UNKNOWN}", ""]
    if doc["unknown"]:
        for item in doc["unknown"]:
            lines.append(
                "- "
                + _ascii(
                    _T_UNKNOWN_ITEM.format(
                        category=item.get("category"), what=item.get("what"), why=item.get("why")
                    )
                )
            )
    else:
        lines.append(_T_UNKNOWN_NONE)
    lines += ["", _T_NEXT_REVIEW.format(date=doc["next_review_by"]), ""]
    for note in doc.get("notes") or []:
        lines.append(f"note: {_ascii(note)}")
    return "\n".join(lines).rstrip("\n") + "\n"


def render_html(doc: dict[str, Any]) -> str:
    from aisg.devtools.audit.html import _CSS, _esc

    def table(header: Sequence[str], rows: Sequence[Sequence[Any]]) -> list[str]:
        out = [
            "<table>",
            "<thead><tr>" + "".join(f"<th>{_esc(h)}</th>" for h in header) + "</tr></thead>",
            "<tbody>",
        ]
        for row in rows:
            out.append("<tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in row) + "</tr>")
        out += ["</tbody>", "</table>"]
        return out

    level = doc["level"]
    parts = [
        OWN_HTML_MARKER_LINE,
        "<!doctype html>",
        '<html lang="en"><head><meta charset="utf-8">',
        f"<title>{_esc(_T_HTML_TITLE.format(path=doc['target']['path']))}</title>",
        f"<style>{_CSS}</style></head><body>",
        f"<h1>{_esc(_T_HTML_H1)}</h1>",
        f'<p class="disclaimer">{_esc(doc["disclaimer"])}</p>',
        f"<p><strong>{_esc(level['statement'])}</strong></p>",
        f"<p>{_esc(_level_line(doc))}</p>",
        f"<h2>{_esc(_T_CRITERIA)}</h2>",
    ]
    parts += table(
        ("id", "level", "met", "evidence", "missing"),
        [
            (
                c["id"],
                c["level"],
                _T_YES if c["met"] else _T_NO,
                c["evidence"] or _T_DASH,
                c["missing"] or _T_DASH,
            )
            for c in level["criteria"]
        ],
    )
    parts.append(f"<h2>{_esc(_T_INPUTS)}</h2>")
    parts += table(
        ("kind", "file", "generated_at", "age (days)"),
        [
            (
                r["kind"],
                r["file"] or _T_ABSENT,
                r["generated_at"] or _T_DASH,
                r["age_days"] if r["age_days"] is not None else _T_DASH,
            )
            for r in doc["inputs"]
        ],
    )
    parts.append(f"<h2>{_esc(_T_ACCEPTED)}</h2>")
    if doc["accepted_risks"]:
        parts += table(
            ("fingerprint", "rule", "file", "reason", "owner"),
            [
                (
                    r["fingerprint"],
                    r["rule"] or _T_DASH,
                    r["file"] or _T_DASH,
                    r["reason"],
                    r["owner"] or _T_DASH,
                )
                for r in doc["accepted_risks"]
            ],
        )
    else:
        parts.append(f"<p>{_esc(_T_ACCEPTED_NONE)}</p>")
    parts += [
        f"<h2>{_esc(_T_RESIDUAL)}</h2>",
        f"<p>{_esc(_residual_line(doc))}</p>",
        f"<h2>{_esc(_T_UNKNOWN)}</h2>",
    ]
    if doc["unknown"]:
        parts.append("<ul>")
        for item in doc["unknown"]:
            parts.append(
                f"<li>{_esc(_T_UNKNOWN_ITEM.format(category=item.get('category'), what=item.get('what'), why=item.get('why')))}</li>"
            )
        parts.append("</ul>")
    else:
        parts.append(f"<p>{_esc(_T_UNKNOWN_NONE)}</p>")
    parts.append(f"<p>{_esc(_T_NEXT_REVIEW.format(date=doc['next_review_by']))}</p>")
    for note in doc.get("notes") or []:
        parts.append(f'<p class="note">{_esc(note)}</p>')
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"


def write_outputs(doc: dict[str, Any], out_dir: Path, *, html: bool) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    targets: list[tuple[str, str]] = [
        ("attestation.json", json.dumps(doc, indent=2, ensure_ascii=True) + "\n"),
        ("attestation.md", render_markdown(doc)),
        ("badge.json", json.dumps(badge(doc), indent=2, ensure_ascii=True) + "\n"),
    ]
    if html:
        targets.append(("attestation.html", render_html(doc)))
    for name, text in targets:
        path = out_dir / name
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        written.append(path)
    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Evaluate the AISG level criteria against the audit, baseline, measure, probe and "
            "decision documents, and write an attestation a named owner signs. The level is a "
            "list of criteria met on a date; it is not a compliance verdict."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes: 0 written (or --check met), 1 --check not met, 2 fatal, 130 interrupted.\n"
            "Defaults may be set in [tool.aisg-attest] of pyproject.toml, except --owner and --check."
        ),
    )
    p.add_argument("path", nargs="?", default=".", help="repository root (default: .)")
    p.add_argument(
        "--report",
        default=DEFAULT_REPORT,
        help=f"audit report JSON (default: {DEFAULT_REPORT}, falls back to {FALLBACK_REPORT})",
    )
    p.add_argument(
        "--baseline", default=DEFAULT_BASELINE, help=f"audit baseline (default: {DEFAULT_BASELINE})"
    )
    p.add_argument(
        "--measure", default=DEFAULT_MEASURE, help=f"measure report (default: {DEFAULT_MEASURE})"
    )
    p.add_argument(
        "--probe", default=DEFAULT_PROBE, help=f"probe report (default: {DEFAULT_PROBE})"
    )
    p.add_argument(
        "--decision",
        default=DEFAULT_DECISION,
        help=f"decision document (default: {DEFAULT_DECISION})",
    )
    p.add_argument("--card", default=DEFAULT_CARD, help=f"system card (default: {DEFAULT_CARD})")
    p.add_argument(
        "--owner",
        default=None,
        metavar="NAME",
        help='who signs, e.g. "J. Doe <risk owner>" (required unless --check)',
    )
    p.add_argument(
        "--level-criteria",
        default=None,
        metavar="PATH",
        help="criteria YAML (default: the packaged attest-levels.yaml)",
    )
    p.add_argument(
        "--out-dir",
        default=DEFAULT_OUT_DIR,
        metavar="DIR",
        help=f"where the documents go (default: {DEFAULT_OUT_DIR})",
    )
    p.add_argument("--html", action="store_true", help="also write attestation.html")
    p.add_argument(
        "--check",
        action="store_true",
        help="evaluate only, write nothing; with --require-level, exit 1 when not reached",
    )
    p.add_argument(
        "--require-level",
        type=int,
        default=None,
        metavar="N",
        help="with --check: the level that must be reached",
    )
    p.add_argument("--quiet", "-q", action="store_true", help="only the level line on stdout")
    p.add_argument(
        "--debug", action="store_true", help="tracebacks on fatal errors; self-check the templates"
    )
    return p


def _registry_rule_ids() -> set[str]:
    from aisg.devtools.audit.rules import ALL_RULES

    return {rule.id for rule in ALL_RULES}


def _card_defaults() -> dict[str, Any]:
    from aisg.devtools.system_card import DEFAULT_CARD as CARD

    return CARD


def run(args: argparse.Namespace) -> int:
    levels = load_levels(Path(args.level_criteria) if args.level_criteria else None)
    problems = validate_levels(levels, _registry_rule_ids(), _card_defaults())
    if problems:
        raise AttestError("criteria " + levels.source + ": " + "; ".join(problems))
    # `--check` may run unsigned; anything that is written needs a validated owner.
    owner = validate_owner(args.owner) if (args.owner or not args.check) else None
    root = Path(args.path)
    if not root.is_dir():
        raise AttestError(f"path is not a directory: {args.path}")
    inputs = load_inputs(
        root,
        report=args.report,
        baseline=args.baseline,
        measure=args.measure,
        probe=args.probe,
        decision=args.decision,
        card=args.card,
    )
    for note in inputs.notes:
        print(f"{PROG}: {note}", file=sys.stderr)
    now = datetime.now(timezone.utc)
    results = evaluate_all(levels, inputs, now, owner)
    doc = build_document(inputs, levels, results, owner, now)
    reached = doc["level"]["reached"]

    if args.check:
        sys.stdout.write(_level_line(doc) + "\n")
        if not args.quiet:
            for result in results:
                mark = _T_YES if result.met else _T_NO
                line = f"  {result.id:<16} met: {mark:<3} {result.evidence}"
                if result.missing:
                    line += f" | missing: {result.missing}"
                sys.stdout.write(line + "\n")
        if args.require_level is not None and (reached is None or reached < args.require_level):
            print(f"{PROG}: level {args.require_level} not reached", file=sys.stderr)
            return EXIT_NOT_MET
        return EXIT_OK

    written = write_outputs(doc, inputs.root / args.out_dir, html=args.html)
    sys.stdout.write(_level_line(doc) + "\n")
    if not args.quiet:
        sys.stdout.write(doc["level"]["statement"] + "\n")
        for path in written:
            sys.stdout.write(f"written: {path.as_posix()}\n")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    apply_tool_config(parser, CONFIG_SECTION, exclude=NOT_CONFIGURABLE)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.debug:
        leaked = check_templates()
        if leaked:
            print(f"{PROG}: template self-check failed: {leaked}", file=sys.stderr)
            return EXIT_FATAL
    try:
        return run(args)
    except AttestError as exc:
        print(f"{PROG}: {exc}", file=sys.stderr)
        return EXIT_FATAL
    except KeyboardInterrupt:
        print(f"{PROG}: interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except Exception as exc:  # the CLI maps every failure to exit 2
        if args.debug:
            import traceback

            traceback.print_exc()
        print(f"{PROG}: fatal: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_FATAL


if __name__ == "__main__":
    sys.exit(main())
