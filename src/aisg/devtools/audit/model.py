"""aisg/devtools/audit/model.py
----------------------------
Dataclasses, enums, constants, fingerprinting, redaction and sorting for `aisg audit`.

This module knows nothing about source code, regex tables or rules. It is the shared
vocabulary every other audit module imports: what a finding is, how it serialises, how
it is identified across runs, and how secrets are kept out of the report.

Honesty rules carried by the types here:

- `Confidence.precision is None` means UNMEASURED. It never means good, and an
  unmeasured rule still fires.
- `Bucket.MEASURED` is reserved for output of an external tool that ran during this
  audit. Everything the audit's own rules produce, and everything read from a report on
  disk, is ASSERTED. What could not be established is UNKNOWN.
- `DISCLAIMER` is emitted on every report; the risk tier is a legal determination made
  by the operator, not a tool output.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

__all__ = [
    "SCHEMA_VERSION",
    "DISCLAIMER",
    "DEFAULT_REPORT",
    "TRIFECTA_RULE_ID",
    "SEVERITY_ORDER",
    "SCOPE_KINDS",
    "FINDING_KEYS",
    "INVENTORY_KEYS",
    "REPORT_KEYS",
    "REDACT_PATTERNS",
    "Severity",
    "Bucket",
    "Basis",
    "EvidenceKind",
    "MatchKind",
    "Tier",
    "Status",
    "UnknownCategory",
    "Confidence",
    "Evidence",
    "Scope",
    "Hit",
    "Recommendation",
    "Finding",
    "UnknownItem",
    "ExternalToolResult",
    "Unit",
    "Inventory",
    "ReportRecord",
    "Report",
    "AuditContext",
    "fingerprint",
    "redact",
    "truncate_snippet",
    "sort_findings",
    "now_iso",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "aisg/1"

DISCLAIMER = (
    "This report lists observations about a codebase. "
    "Not an assessment of compliance with any regulation. "
    "Risk classification under the EU AI Act is a legal determination made by the "
    "operator, not a tool output. "
    "Every rule in this report is UNMEASURED: no precision figure exists for it yet. "
    "Absence of a finding is not evidence of safety."
)

DEFAULT_REPORT = "audit-report.json"

# The lethal-trifecta rule is pinned to the top of every finding list.
TRIFECTA_RULE_ID = "AUD-301"

SNIPPET_LIMIT = 160

SCOPE_KINDS = frozenset({"unit", "function", "file", "repo"})


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Blast-radius severity of a finding. Never adjusted by confidence."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    def rank(self) -> int:
        """Numeric rank, highest for CRITICAL and 0 for INFO."""
        return _SEVERITY_RANK[self]


SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)
_SEVERITY_RANK: dict[Severity, int] = {
    sev: len(SEVERITY_ORDER) - 1 - index for index, sev in enumerate(SEVERITY_ORDER)
}


class Bucket(str, Enum):
    """Where a finding's evidence came from."""

    MEASURED = "measured"  # an external tool ran during this audit and produced it
    ASSERTED = "asserted"  # our own regex/AST rule, a system-card claim, or a report on disk
    UNKNOWN = "unknown"  # could not be established


class Basis(str, Enum):
    PRESENCE = "presence"
    ABSENCE = "absence"
    MEASURED = "measured"


class EvidenceKind(str, Enum):
    CODE = "code"
    CONFIG = "config"
    ABSENCE = "absence"
    TOOL_OUTPUT = "tool_output"
    REPORT = "report"


class MatchKind(str, Enum):
    GREP = "grep"
    STRUCTURED = "structured"
    AST = "ast"
    EXTERNAL = "external"


class Tier(str, Enum):
    T1 = "T1"
    T2 = "T2"
    T3 = "T3"


class Status(str, Enum):
    """Outcome of an external-tool adapter."""

    RAN = "ran"
    NOT_ON_PATH = "not_on_path"
    NOT_APPLICABLE = "not_applicable"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED_BY_FLAG = "skipped_by_flag"
    SKIPPED_NEEDS_FLAG = "skipped_needs_flag"


class UnknownCategory(str, Enum):
    TOOLS = "tools"  # adapter not on PATH / failed / timed out
    DEEP = "deep"  # deep analysis unavailable or failed for a file or a language
    REPORTS = "reports"  # on-disk report unreadable, wrong schema, age unknown
    RUNTIME = "runtime"  # anything the audit cannot establish statically


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _plain(obj: Any) -> Any:
    """Recursively turn enums, dataclasses, paths and containers into JSON-ready values."""
    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        return obj.to_dict()
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _plain(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(obj, dict):
        return {str(k): _plain(v) for k, v in obj.items()}
    if isinstance(obj, (set, frozenset)):
        try:
            return [_plain(v) for v in sorted(obj)]
        except TypeError:
            return [_plain(v) for v in obj]
    if isinstance(obj, (list, tuple)):
        return [_plain(v) for v in obj]
    return obj


def _posix(relpath: str) -> str:
    return str(relpath).replace("\\", "/")


# ---------------------------------------------------------------------------
# Time
# ---------------------------------------------------------------------------


def now_iso() -> str:
    """Current UTC time as ISO 8601 'YYYY-MM-DDTHH:MM:SSZ'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

# Ordered: the most specific prefix first. Group 1 of each pattern is the recognisable
# prefix that survives redaction; the whole match is the token. Every token is rendered
# as "<redacted:PREFIX...LAST4>". The table is deliberately small and local -- the full
# secret catalogue lives in patterns.py, which calls redact() on its own hits.
REDACT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("anthropic", re.compile(r"\b(sk-ant-)[A-Za-z0-9_\-]{20,}")),
    ("openai", re.compile(r"\b(sk-)[A-Za-z0-9_\-]{20,}")),
    ("github_pat", re.compile(r"\b(github_pat_)[A-Za-z0-9_]{20,}")),
    ("github", re.compile(r"\b(gh[pousr]_)[A-Za-z0-9]{20,}")),
    ("aws", re.compile(r"\b((?:AKIA|ASIA))[0-9A-Z]{16}\b")),
    ("slack", re.compile(r"\b(xox[abpors]-)[A-Za-z0-9\-]{10,}")),
    ("google", re.compile(r"\b(AIza)[0-9A-Za-z_\-]{35}")),
)

_BEARER_RE = re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9_\-.=+/]{20,})")

_KEY_NAME = (
    r"[A-Za-z0-9_.\-]*"
    r"(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|access[_\-]?key|"
    r"private[_\-]?key|credential|authorization)"
    r"[A-Za-z0-9_.\-]*"
)
_KV_RE = re.compile(
    r"(?i)(?P<key>\b" + _KEY_NAME + r")(?P<sep>[\"']?\s*[:=]\s*)"
    r"(?:(?P<q>[\"'])(?P<qval>[^\"'\s]{8,})(?P=q)"
    r"|(?P<bval>[A-Za-z0-9_\-+/=]{8,})(?![A-Za-z0-9_\-+/=(\[.]))"
)
# Key names where "token" means tokenisation, not a credential.
_KV_KEY_EXCLUDE = re.compile(r"tokens\b|tokeniz|token_?count|token_?limit|token_?budget", re.I)
# Values that are references or placeholders, never a secret worth hiding.
_KV_VALUE_SKIP = ("$", "{", "%", "<")

_NEAR_RE = re.compile(
    r"(?i)(?P<lead>(?:key|secret|token|password|passwd|credential)s?\b[^\n]{0,24}?)"
    r"(?P<val>\b(?:[A-Fa-f0-9]{32,}|(?=[A-Za-z0-9+/]*\d)[A-Za-z0-9+/]{32,}={0,2})\b)"
)


def _mask(prefix: str, token: str) -> str:
    return f"<redacted:{prefix}...{token[-4:]}>"


def _redact_prefixed(match: re.Match[str]) -> str:
    return _mask(match.group(1), match.group(0))


def _redact_bearer(match: re.Match[str]) -> str:
    return match.group(1) + _mask("", match.group(2))


def _redact_kv(match: re.Match[str]) -> str:
    if _KV_KEY_EXCLUDE.search(match.group("key")):
        return match.group(0)
    quoted = match.group("qval")
    if quoted is not None:
        if quoted.startswith(_KV_VALUE_SKIP):
            return match.group(0)
        quote = match.group("q")
        return match.group("key") + match.group("sep") + quote + _mask("", quoted) + quote
    return match.group("key") + match.group("sep") + _mask("", match.group("bval"))


def _redact_near(match: re.Match[str]) -> str:
    return match.group("lead") + _mask("", match.group("val"))


def redact(snippet: str) -> str:
    """Replace every secret-shaped token in `snippet` with "<redacted:PREFIX...LAST4>".

    Idempotent: a redacted token never matches again.
    """
    if not snippet:
        return snippet
    out = snippet
    for _name, pattern in REDACT_PATTERNS:
        out = pattern.sub(_redact_prefixed, out)
    out = _BEARER_RE.sub(_redact_bearer, out)
    out = _KV_RE.sub(_redact_kv, out)
    out = _NEAR_RE.sub(_redact_near, out)
    return out


def _normalise_ws(text: str) -> str:
    return " ".join(str(text).split())


def truncate_snippet(snippet: str, limit: int = SNIPPET_LIMIT) -> str:
    """Whitespace-normalise, redact, then cut to `limit` characters.

    Redaction runs before truncation so a cut can never expose a partial secret.
    """
    out = redact(_normalise_ws(snippet))
    if len(out) <= limit:
        return out
    if limit <= 3:
        return out[:limit]
    return out[: limit - 3] + "..."


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b")


def _strip_ident_digits(match: re.Match[str]) -> str:
    return re.sub(r"\d", "", match.group(0))


def _norm(snippet: str) -> str:
    """Collapse whitespace and strip digits from identifiers of three or more characters.

    `foo1` and `foo2` normalise to `foo`, so a renamed local or a renumbered line does
    not create a "new" finding. Pure numbers such as `4096` are not identifiers and
    survive intact.
    """
    return _IDENT_RE.sub(_strip_ident_digits, _normalise_ws(snippet))


def fingerprint(rule_id: str, relpath: str, snippet: str) -> str:
    """Stable 16-hex-char identity of a finding across runs and line renumbering."""
    payload = f"{rule_id}|{_posix(relpath)}|{_norm(snippet)}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Confidence:
    """How a finding was produced. `precision is None` is UNMEASURED and still fires."""

    evidence_kind: EvidenceKind
    match_kind: MatchKind
    precision: float | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_kind", EvidenceKind(self.evidence_kind))
        object.__setattr__(self, "match_kind", MatchKind(self.match_kind))

    @property
    def label(self) -> str:
        return "UNMEASURED" if self.precision is None else "MEASURED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_kind": self.evidence_kind.value,
            "match_kind": self.match_kind.value,
            "precision": self.precision,
            "label": self.label,
        }


@dataclass(frozen=True)
class Evidence:
    """One location backing a finding. The snippet is always redacted and <= 160 chars."""

    role: str
    file: str
    line: int
    snippet: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "file", _posix(self.file))
        object.__setattr__(self, "snippet", truncate_snippet(self.snippet))

    def to_dict(self) -> dict[str, Any]:
        return {"role": self.role, "file": self.file, "line": self.line, "snippet": self.snippet}


@dataclass(frozen=True)
class Scope:
    kind: str  # unit | function | file | repo
    unit: str | None = None
    name: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in SCOPE_KINDS:
            raise ValueError(f"scope kind {self.kind!r} not in {sorted(SCOPE_KINDS)}")

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "unit": self.unit, "name": self.name}


@dataclass(frozen=True)
class Hit:
    """A raw grep hit: which table and key matched where. Snippet is the raw line."""

    file: str
    line: int
    col: int
    snippet: str
    table: str
    key: str
    unit: str | None = None
    lang: str | None = None


@dataclass(frozen=True)
class Recommendation:
    tier: Tier
    summary: str
    alternatives: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "tier", Tier(self.tier))
        object.__setattr__(self, "alternatives", tuple(self.alternatives))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value,
            "summary": self.summary,
            "alternatives": list(self.alternatives),
        }


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

FINDING_KEYS: tuple[str, ...] = (
    "id",
    "rule_id",
    "sub",
    "fingerprint",
    "title",
    "severity",
    "priority",
    "bucket",
    "basis",
    "confidence",
    "scope",
    "evidence",
    "controls",
    "recommendation",
    "related_lint_rules",
    "known_failure_modes",
    "suppressed",
    "gitignored",
)


@dataclass(kw_only=True)
class Finding:
    """One audit observation. Keyword-only: the field list is long and order-sensitive.

    `fingerprint` is computed from `display_id` (so a sub-finding never collides with its
    parent), the first evidence file and snippet when left empty. Set `sub` at
    construction time; changing it afterwards leaves the fingerprint stale.
    """

    id: str
    fingerprint: str = ""
    title: str
    severity: Severity
    priority: int
    bucket: Bucket
    basis: Basis
    confidence: Confidence
    scope: Scope
    evidence: list[Evidence] = field(default_factory=list)
    controls: tuple[str, ...] = ()
    recommendation: Recommendation
    related_lint_rules: tuple[str, ...] = ()
    known_failure_modes: tuple[str, ...] = ()
    suppressed: bool = False
    gitignored: bool = False
    # Extensions beyond the section 3.1 core.
    sub: str | None = None  # sub-finding kind: "inert", "apm-only", "interpreter", "docs"
    report: dict[str, Any] | None = None  # file/schema/generated_at/age_source/age_days
    baseline_status: str | None = None  # "new" | "unchanged"
    notes: str | None = None

    def __post_init__(self) -> None:
        self.severity = Severity(self.severity)
        self.bucket = Bucket(self.bucket)
        self.basis = Basis(self.basis)
        self.priority = int(self.priority)
        self.evidence = list(self.evidence)
        self.controls = tuple(self.controls)
        self.related_lint_rules = tuple(self.related_lint_rules)
        self.known_failure_modes = tuple(self.known_failure_modes)
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    @property
    def display_id(self) -> str:
        return f"{self.id}/{self.sub}" if self.sub else self.id

    @property
    def location(self) -> tuple[str, int]:
        """(file, line) of the first evidence entry, or ("", 0) for absence findings."""
        if self.evidence:
            first = self.evidence[0]
            return first.file, int(first.line)
        return "", 0

    def compute_fingerprint(self) -> str:
        if self.evidence:
            first = self.evidence[0]
            return fingerprint(self.display_id, first.file, first.snippet)
        return fingerprint(self.display_id, self.scope.name or "", "")

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.display_id,
            "rule_id": self.id,
            "sub": self.sub,
            "fingerprint": self.fingerprint,
            "title": self.title,
            "severity": self.severity.value,
            "priority": self.priority,
            "bucket": self.bucket.value,
            "basis": self.basis.value,
            "confidence": _plain(self.confidence),
            "scope": _plain(self.scope),
            "evidence": [_plain(e) for e in self.evidence],
            "controls": list(self.controls),
            "recommendation": _plain(self.recommendation),
            "related_lint_rules": list(self.related_lint_rules),
            "known_failure_modes": list(self.known_failure_modes),
            "suppressed": self.suppressed,
            "gitignored": self.gitignored,
        }
        if self.report is not None:
            out["report"] = _plain(self.report)
        if self.baseline_status is not None:
            out["baseline_status"] = self.baseline_status
        if self.notes is not None:
            out["notes"] = self.notes
        return out


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Sort by (priority, severity rank desc, file, line); AUD-301 is pinned first."""

    def key(f: Finding) -> tuple[int, int, int, str, int]:
        file, line = f.location
        pinned = 0 if f.id == TRIFECTA_RULE_ID else 1
        return (pinned, f.priority, -Severity(f.severity).rank(), file, line)

    return sorted(findings, key=key)


# ---------------------------------------------------------------------------
# Unknown items and external tools
# ---------------------------------------------------------------------------


@dataclass
class UnknownItem:
    """Something the audit could not establish. Never a pass, never silent."""

    category: UnknownCategory
    what: str
    why: str
    how_to_resolve: str | None = None
    file: str | None = None
    rule_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self.category = UnknownCategory(self.category)
        self.rule_ids = tuple(self.rule_ids)
        if self.file is not None:
            self.file = _posix(self.file)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "category": self.category.value,
            "what": self.what,
            "why": self.why,
        }
        if self.how_to_resolve is not None:
            out["how_to_resolve"] = self.how_to_resolve
        if self.file is not None:
            out["file"] = self.file
        if self.rule_ids:
            out["rule_ids"] = list(self.rule_ids)
        return out


@dataclass
class ExternalToolResult:
    """What one adapter did. `network` is always emitted so a reader can see who talks out."""

    name: str
    status: Status
    network: bool
    version: str | None = None
    duration_ms: int | None = None
    findings: int = 0
    argv: tuple[str, ...] = ()
    flag: str | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        self.status = Status(self.status)
        self.network = bool(self.network)
        self.argv = tuple(self.argv)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "status": self.status.value,
            "network": self.network,
        }
        for key in ("version", "duration_ms", "findings", "argv", "flag", "error"):
            value = getattr(self, key)
            if value is None:
                continue
            out[key] = _plain(value)
        return out


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


@dataclass
class Unit:
    """A deployable unit: the nearest manifest above a file."""

    id: str
    root: str
    manifest: str | None
    language: str
    ai_surface: bool = False

    def __post_init__(self) -> None:
        self.root = _posix(self.root)
        if self.manifest is not None:
            self.manifest = _posix(self.manifest)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "root": self.root,
            "manifest": self.manifest,
            "language": self.language,
            "ai_surface": self.ai_surface,
        }


@dataclass
class ReportRecord:
    """An on-disk `aisg measure` / `aisg probe` report as read by the audit.

    Reading a report is not measuring: findings derived from one are ASSERTED and carry
    the report's age so a stale file is never rendered as fresh evidence.
    """

    kind: str  # "measure" | "probe"
    file: str
    schema: str | None
    generated_at: str | None = None
    age_source: str = "unknown"  # generated_at | mtime | git | unknown
    age_days: int | None = None
    models: list[str] = field(default_factory=list)
    config_digest: str | None = None
    body: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.file = _posix(self.file)
        self.models = list(self.models)

    def to_dict(self) -> dict[str, Any]:
        """Inventory shape (section 2 `reports[]`); the body is deliberately left out."""
        return {
            "kind": self.kind,
            "file": self.file,
            "schema": self.schema,
            "generated_at": self.generated_at,
            "age_source": self.age_source,
            "age_days": self.age_days,
            "models": list(self.models),
            "config_digest": self.config_digest,
        }

    def finding_report(self) -> dict[str, Any]:
        """The `report` block a report-derived finding carries."""
        return {
            "file": self.file,
            "schema": self.schema,
            "generated_at": self.generated_at,
            "age_source": self.age_source,
            "age_days": self.age_days,
        }


INVENTORY_KEYS: tuple[str, ...] = (
    "schema",
    "kind",
    "target",
    "units",
    "languages",
    "llm_calls",
    "models",
    "frameworks",
    "tools",
    "mcp",
    "hosts",
    "data_sources",
    "ingress",
    "external_actions",
    "sinks",
    "guardrails",
    "observability",
    "evals",
    "reports",
    "system_card",
    "secrets",
    "loops",
    "ci",
    "incident_path",
    "unknown",
)


@dataclass
class Inventory:
    """What discovery found. Entries are plain dicts in the section 2 shapes."""

    target: dict[str, Any] = field(default_factory=dict)
    units: list[Unit] = field(default_factory=list)
    languages: dict[str, int] = field(default_factory=dict)
    llm_calls: list[dict[str, Any]] = field(default_factory=list)
    models: list[dict[str, Any]] = field(default_factory=list)
    frameworks: list[dict[str, Any]] = field(default_factory=list)
    tools: list[dict[str, Any]] = field(default_factory=list)
    mcp: dict[str, Any] = field(default_factory=lambda: {"configs": [], "servers": []})
    hosts: list[dict[str, Any]] = field(default_factory=list)
    data_sources: list[dict[str, Any]] = field(default_factory=list)
    ingress: list[dict[str, Any]] = field(default_factory=list)
    external_actions: list[dict[str, Any]] = field(default_factory=list)
    sinks: list[dict[str, Any]] = field(default_factory=list)
    guardrails: list[dict[str, Any]] = field(default_factory=list)
    observability: list[dict[str, Any]] = field(default_factory=list)
    evals: list[dict[str, Any]] = field(default_factory=list)
    reports: list[Any] = field(default_factory=list)  # ReportRecord or dict
    system_card: dict[str, Any] | None = None
    secrets: dict[str, Any] = field(default_factory=dict)
    loops: list[dict[str, Any]] = field(default_factory=list)
    ci: list[dict[str, Any]] = field(default_factory=list)
    incident_path: list[str] = field(default_factory=list)
    unknown: list[UnknownItem] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"schema": SCHEMA_VERSION, "kind": "inventory"}
        for key in INVENTORY_KEYS[2:]:
            out[key] = _plain(getattr(self, key))
        return out


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

REPORT_KEYS: tuple[str, ...] = (
    "schema",
    "kind",
    "tool",
    "target",
    "generated_at",
    "disclaimer",
    "summary",
    "findings",
    "measured",
    "reports",
    "unknown",
    "external_tools",
    "baseline",
    "inventory",
    "rules",
)


@dataclass
class Report:
    """The audit document. `to_dict()` emits the section 3.2 keys in that exact order."""

    tool: dict[str, Any] = field(default_factory=dict)
    target: dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(default_factory=now_iso)
    summary: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    measured: list[dict[str, Any]] = field(default_factory=list)
    reports: list[dict[str, Any]] = field(default_factory=list)
    unknown: list[UnknownItem] = field(default_factory=list)
    external_tools: list[ExternalToolResult] = field(default_factory=list)
    baseline: dict[str, Any] | None = None
    inventory: Inventory | dict[str, Any] | None = None
    rules: list[dict[str, Any]] = field(default_factory=list)
    disclaimer: str = DISCLAIMER

    def to_dict(self) -> dict[str, Any]:
        inventory = self.inventory
        return {
            "schema": SCHEMA_VERSION,
            "kind": "audit",
            "tool": _plain(self.tool),
            "target": _plain(self.target),
            "generated_at": self.generated_at,
            "disclaimer": self.disclaimer,
            "summary": _plain(self.summary),
            "findings": [_plain(f) for f in self.findings],
            "measured": _plain(self.measured),
            "reports": _plain(self.reports),
            "unknown": [_plain(u) for u in self.unknown],
            "external_tools": [_plain(t) for t in self.external_tools],
            "baseline": _plain(self.baseline),
            "inventory": {} if inventory is None else _plain(inventory),
            "rules": _plain(self.rules),
        }


# ---------------------------------------------------------------------------
# Run context
# ---------------------------------------------------------------------------


@dataclass
class AuditContext:
    """Mutable bag passed through walk -> discover -> pydeep -> rules -> adapters."""

    root: Path
    inventory: Inventory
    pyfacts: object | None = None
    hits: list[Hit] = field(default_factory=list)
    options: object | None = None
    unknown: list[UnknownItem] = field(default_factory=list)
    external: list[ExternalToolResult] = field(default_factory=list)
    files: list[Any] = field(default_factory=list)
    reports: list[ReportRecord] = field(default_factory=list)
    # discover.ConfigFacts: the structured host/MCP/CI/env records behind the
    # inventory's plain-dict sections. Typed loosely to keep model.py free of
    # imports from the modules that build it.
    config_facts: object | None = None
    # relpath -> decoded text, filled lazily by `rules.file_text()` so rules that
    # need a window of source share one read per file.
    texts: dict[str, str | None] = field(default_factory=dict, repr=False, compare=False)
