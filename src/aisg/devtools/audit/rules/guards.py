"""aisg/devtools/audit/rules/guards.py
-------------------------------------
P8 guard rules: AUD-801 guard present but unmeasured, AUD-802 guard configured
fail-open, AUD-803 reported guard below threshold, AUD-804 LLM judge without
credentials or timeout, AUD-805 keyword-only content filter.

Reading a report is not measuring. AUD-803 findings come from a `measure-report.json`
already on disk, so they are ASSERTED with `evidence_kind: report` and carry the
report's age; the renderer shows them as `[REPORTED <age>]`. The rule compares the
report's `threshold_failures` and `false_positive_rate` only -- `aisg measure`
emits no other per-guard rate that a rule may read.

Every rule here tolerates an empty or partial context: the inventory sections it
reads may be empty, `ctx.pyfacts` / `ctx.config_facts` may be None, and a file the
walk did not enumerate simply has no text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

import yaml

from aisg.core.measurement import Thresholds
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
    UnknownCategory,
    UnknownItem,
)
from aisg.devtools.audit.rules import AuditRule, file_text, unit_of

__all__ = [
    "RULES",
    "GuardFailOpen",
    "GuardReportedBelowThreshold",
    "GuardUnmeasured",
    "KeywordOnlyFilter",
    "LLMJudgeWithoutCredentialsOrTimeout",
]

# Registry name -> class name for the guards this package ships (`@register_guard`).
# A Python file naming either form is treated as wiring that guard.
_GUARD_CLASSES: dict[str, str] = {
    "eu_ai_act": "EUAIActCompliance",
    "llm_input_filter": "LLMInputFilter",
    "llm_output_filter": "LLMOutputFilter",
    "llm_tool_filter": "LLMToolFilter",
    "nemo_rails": "NemoRailsGuard",
    "nist_ai_rmf": "NISTAIRMFCompliance",
    "pii_detector": "PIIDetector",
    "pii_restorer": "PIIRestorer",
    "prompt_injection": "PromptInjectionGuard",
    "rate_limiter": "RateLimiter",
    "tool_policy": "ToolPolicyGuard",
    "toxicity_output": "ToxicityFilter",
}
_PRESET_SECTIONS = ("input", "processing", "output", "policy")
_PRESET_LIB = "aisg_preset"
_AISG_LIB = "aisg"
_CONFIG_EXTS = frozenset({".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".env"})
_CODE_LANGS_EXCLUDED = frozenset({"config", "other"})

_JUDGE_RE = re.compile(
    r"(?:\b(?:use_)?llm_judge\s*[:=]\s*[Tt]rue\b"
    r"|\bLLMJudge\w*\s*\("
    r"|\b(?:ClaudeJudge|OpenAIModerationJudge|LlamaGuardJudge|CachedJudge)\s*\("
    r"|\bLLM(?:Input|Output|Tool)Filter\s*\()"
)
_API_KEY_RE = re.compile(r"\b[A-Za-z0-9_]*_API_KEY\b", re.I)
_TIMEOUT_RE = re.compile(r"timeout", re.I)
_QUOTED_RE = re.compile(r"""["'][^"'\n]+["']""")
_MIN_KEYWORDS = 5
_LITERAL_WINDOW = 200


@dataclass(frozen=True)
class _GuardSite:
    name: str
    file: str
    line: int
    enabled: bool


def _entries(ctx: AuditContext, section: str) -> list[dict[str, Any]]:
    raw = getattr(ctx.inventory, section, None) or []
    return [entry for entry in raw if isinstance(entry, dict)]


def _hits(ctx: AuditContext, table: str, *, unit: str | None = None):
    out = []
    for hit in ctx.hits or []:
        if hit.table != table:
            continue
        if unit is not None and hit.unit != unit:
            continue
        out.append(hit)
    return sorted(out, key=lambda h: (h.file, h.line, h.key))


def _owning_unit(ctx: AuditContext, relpath: str) -> Unit | None:
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


def _unit_files(ctx: AuditContext, unit: Unit | None, *, code_only: bool) -> list[str]:
    """Relpaths the walk enumerated for `unit` (every file when the unit is unknown)."""
    out: list[str] = []
    for record in ctx.files or []:
        relpath = getattr(record, "relpath", None)
        if not relpath:
            continue
        if unit is not None and getattr(record, "unit", None) != unit.id:
            continue
        if code_only and getattr(record, "lang", "other") in _CODE_LANGS_EXCLUDED:
            continue
        out.append(relpath)
    return sorted(out)


def _line(text: str | None, number: int) -> str:
    if not text or number < 1:
        return ""
    lines = text.splitlines()
    return lines[number - 1].strip() if number <= len(lines) else ""


def _line_of(text: str, pattern: re.Pattern[str]) -> int:
    match = pattern.search(text)
    return text.count("\n", 0, match.start()) + 1 if match else 0


def _is_config(relpath: str) -> bool:
    name = PurePosixPath(relpath).name
    return PurePosixPath(relpath).suffix.lower() in _CONFIG_EXTS or name.startswith(".env")


def _preset_guards(text: str, relpath: str) -> list[_GuardSite]:
    """
    Guard blocks in an aisg preset: `<section>: <name>: {enabled: ...}` for the four
    stage sections. YAML that does not parse falls back to the guard-name line regex,
    with `enabled` assumed true (a parse failure is not evidence of anything).
    """
    sites: list[_GuardSite] = []
    data: Any = None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        data = None
    if isinstance(data, dict):
        for section in _PRESET_SECTIONS:
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for name, cfg in block.items():
                if not isinstance(name, str) or not isinstance(cfg, dict):
                    continue
                enabled = cfg.get("enabled", True) is not False
                line = _line_of(text, re.compile(rf"^\s+{re.escape(name)}:\s*$", re.M))
                sites.append(_GuardSite(name, relpath, line, enabled))
    else:
        for name in _GUARD_CLASSES:
            line = _line_of(text, re.compile(rf"^\s+{re.escape(name)}:\s*$", re.M))
            if line:
                sites.append(_GuardSite(name, relpath, line, True))
    return sorted(sites, key=lambda s: (s.line, s.name))


def _python_guards(text: str, relpath: str) -> list[_GuardSite]:
    """Guards a Python file names, by registry name or class name."""
    sites: list[_GuardSite] = []
    for name, klass in _GUARD_CLASSES.items():
        pattern = re.compile(rf"\b(?:{re.escape(name)}|{re.escape(klass)})\b")
        line = _line_of(text, pattern)
        if line:
            sites.append(_GuardSite(name, relpath, line, True))
    return sorted(sites, key=lambda s: (s.line, s.name))


def _guard_sites(ctx: AuditContext) -> list[_GuardSite]:
    """Every guard the tree wires, from the files carrying a `guardrails[]` entry."""
    sites: list[_GuardSite] = []
    seen: set[str] = set()
    for entry in _entries(ctx, "guardrails"):
        file = str(entry.get("file") or "")
        lib = str(entry.get("lib") or "")
        if not file or file in seen or lib not in (_PRESET_LIB, _AISG_LIB):
            continue
        seen.add(file)
        text = file_text(ctx, file) or ""
        if lib == _PRESET_LIB:
            sites.extend(_preset_guards(text, file))
        else:
            sites.extend(_python_guards(text, file))
    return sites


def _measure_reports(ctx: AuditContext) -> list[Any]:
    return sorted(
        (r for r in ctx.reports or [] if getattr(r, "kind", None) == "measure"),
        key=lambda r: getattr(r, "file", ""),
    )


def _report_guards(record: Any) -> list[dict[str, Any]]:
    body = getattr(record, "body", None)
    guards = body.get("guards") if isinstance(body, dict) else None
    if isinstance(guards, dict):
        return [dict(v, name=k) for k, v in guards.items() if isinstance(v, dict)]
    if isinstance(guards, list):
        return [g for g in guards if isinstance(g, dict)]
    return []


def _named(name: str, texts: list[str]) -> bool:
    pattern = re.compile(rf"\b{re.escape(name)}\b", re.I)
    return any(pattern.search(text) for text in texts)


class GuardUnmeasured(AuditRule):
    """AUD-801: a guard is wired and nothing in the tree reports what it catches or breaks."""

    id = "AUD-801"
    title = "Guard present but unmeasured"
    priority = 8
    severity = Severity.MEDIUM
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.STRUCTURED
    measured_precision = None
    tier = Tier.T2
    controls = (
        "ASI01",
        "LLM01",
        "EU:Art.9",
        "EU:Art.15",
        "NIST:MEASURE-2.5",
        "NIST:MEASURE-2.7",
    )
    related_lint_rules = ("EU-AIA-009a", "EU-AIA-015a")
    known_failure_modes = (
        "A measurement kept outside the tree (a dashboard, a CI artifact that is not "
        "committed) is not seen, so a measured guard is reported as unmeasured.",
        "A measure report that names the guard satisfies the rule regardless of its age "
        "or of whether the guard's configuration changed since; AUD-903 covers age.",
        "For a third-party guard library the check is only that an eval file or report "
        "mentions the library name at all.",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Measure each guard against an attack corpus AND a benign corpus, commit the "
            "report, and re-run it when the guard or its configuration changes."
        ),
        alternatives=(
            "Run `aisg measure` against the preset and commit measure-report.json next to it.",
            "Write a promptfoo / deepeval / inspect_ai suite that sends both attack and "
            "benign cases through the guard and asserts on block rates.",
            "Replay a labelled sample of production traffic through the guard offline and "
            "record the block rate on each class in the repository.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        reports = _measure_reports(ctx)
        report_names = {
            str(g.get("name") or "").lower() for r in reports for g in _report_guards(r)
        }
        report_names.discard("")
        eval_texts: list[str] = []
        for entry in _entries(ctx, "evals"):
            text = file_text(ctx, str(entry.get("file") or "")) if entry.get("file") else None
            if text:
                eval_texts.append(text)

        findings: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        guard_sites = _guard_sites(ctx)
        sites_by_file: dict[str, list[_GuardSite]] = {}
        for site in guard_sites:
            sites_by_file.setdefault(site.file, []).append(site)

        for entry in sorted(
            _entries(ctx, "guardrails"),
            key=lambda e: (str(e.get("file") or ""), int(e.get("line") or 0), str(e.get("lib"))),
        ):
            file = str(entry.get("file") or "")
            lib = str(entry.get("lib") or "")
            line = int(entry.get("line") or 0)
            if not file or not lib:
                continue
            text = file_text(ctx, file)
            kind = EvidenceKind.CONFIG if _is_config(file) else EvidenceKind.CODE
            if lib in (_PRESET_LIB, _AISG_LIB) and sites_by_file.get(file):
                for site in sites_by_file[file]:
                    if not site.enabled:
                        continue
                    if site.name in report_names or _named(site.name, eval_texts):
                        continue
                    key = (file, site.line, site.name)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        self.finding(
                            file=file,
                            line=site.line,
                            snippet=_line(text, site.line) or f"{site.name}:",
                            evidence_kind=kind,
                            notes=(
                                f"guard {site.name} is wired in {file}; no measure report "
                                "and no eval file in the tree names it"
                            ),
                        )
                    )
                continue
            if lib == _AISG_LIB:
                if reports or _named(_AISG_LIB, eval_texts):
                    continue
                note = (
                    f"aisg imported in {file} without naming a guard; the tree holds no "
                    "measure report and no eval file mentions aisg"
                )
            elif lib == _PRESET_LIB:
                continue
            else:
                if _named(lib, eval_texts) or any(lib in n for n in report_names):
                    continue
                note = f"guard library {lib} is used in {file}; no report or eval file names it"
            key = (file, line, lib)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                self.finding(
                    file=file,
                    line=line,
                    snippet=_line(text, line) or lib,
                    evidence_kind=kind,
                    match_kind=MatchKind.GREP,
                    notes=note,
                )
            )
        return sorted(findings, key=lambda f: (f.evidence[0].file, f.evidence[0].line, f.notes))


class GuardFailOpen(AuditRule):
    """AUD-802: a guard that lets traffic through when it fails."""

    id = "AUD-802"
    title = "Guard configured fail-open"
    priority = 8
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    measured_precision = None
    tier = Tier.T1
    controls = (
        "ASI01",
        "ASI08",
        "LLM01",
        "LLM05",
        "EU:Art.15",
        "NIST:MEASURE-2.7",
        "NIST:MANAGE-2.3",
    )
    related_lint_rules = ("ALIGN-001", "ALIGN-002", "ALIGN-004")
    known_failure_modes = (
        "`fail_open=True` on an object that is not a guard (an HTTP client, a feature "
        "flag) matches the grep tier.",
        "A guard call whose exception is swallowed through a helper (`safe_call(guard)`) "
        "or a decorator is not seen by the AST tier.",
        "A fail-open default that lives inside the guard library, with nothing set in this "
        "tree, is invisible: only explicit configuration and explicit swallowing are found.",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Fail closed: when a guard raises or times out, reject the request (or route it "
            "to a human) and record the failure; never treat an error as a pass."
        ),
        alternatives=(
            "Let the guard's exception propagate to a handler that returns a refusal and "
            "logs the failure with the request id.",
            "Keep a fail-open path only for guards whose remit is low-stakes, and gate "
            "high-risk tools (email, payments, shell, deploy) to fail closed regardless.",
            "If the pipeline runs through aisg, set `pipeline.fail_open: false` in the "
            "preset and keep LLMToolFilter.high_risk_fail_closed on.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        sites: dict[tuple[str, int], tuple[MatchKind, str, str]] = {}
        for hit in _hits(ctx, "fail_open"):
            sites[(hit.file, hit.line)] = (
                MatchKind.GREP,
                hit.snippet,
                f"{hit.key} set in {hit.file}",
            )
        for site in getattr(ctx.pyfacts, "fail_open", None) or []:
            file = str(getattr(site, "file", "") or "")
            if not file:
                continue
            key = (file, int(getattr(site, "line", 0) or 0))
            where = getattr(site, "function", None) or "<module>"
            reason = getattr(site, "inert_reason", None) or "exception swallowed"
            sites[key] = (
                MatchKind.AST,
                f"try/except around a guard call in {where}: {reason}",
                f"a guard call in {where} ({file}) has its exception swallowed",
            )
        covered = {file for file, _line in sites}
        for entry in _entries(ctx, "guardrails"):
            file = str(entry.get("file") or "")
            if not file or entry.get("fail_open") is not True or file in covered:
                continue
            lib = str(entry.get("lib") or "guard")
            sites[(file, int(entry.get("line") or 0))] = (
                MatchKind.STRUCTURED,
                f"guardrail {lib} in a file that configures fail_open",
                f"inventory marks the {lib} guardrail in {file} fail-open",
            )

        findings: list[Finding] = []
        for (file, line), (kind, snippet, note) in sorted(sites.items()):
            findings.append(
                self.finding(
                    file=file,
                    line=line,
                    snippet=snippet,
                    match_kind=kind,
                    evidence_kind=EvidenceKind.CONFIG if _is_config(file) else EvidenceKind.CODE,
                    notes=note,
                )
            )
        return findings


class GuardReportedBelowThreshold(AuditRule):
    """AUD-803: a measure report on disk says a guard breaks more benign traffic than allowed."""

    id = "AUD-803"
    title = "Reported guard below threshold"
    priority = 8
    severity = Severity.HIGH
    basis = Basis.MEASURED
    evidence_kind = EvidenceKind.REPORT
    match_kind = MatchKind.STRUCTURED
    measured_precision = None
    tier = Tier.T1
    controls = (
        "ASI01",
        "LLM01",
        "EU:Art.9",
        "EU:Art.15",
        "NIST:MEASURE-2.5",
        "NIST:MANAGE-1.3",
    )
    related_lint_rules = ("ALIGN-004",)
    known_failure_modes = (
        "The report describes the guard as it was when `aisg measure` ran; a guard "
        "re-tuned since is still reported from the old numbers (the age is shown).",
        "A guard the report names but no preset in the tree references cannot be told "
        "apart from a guard that was removed; the finding says so in its notes.",
        "`threshold_failures` is read as written by the report; a report edited by hand "
        "is trusted as much as a generated one.",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Re-tune or replace the guard until it stays under the false-positive budget on "
            "the benign corpus, then re-run the measurement and commit the new report."
        ),
        alternatives=(
            "Narrow the guard's patterns to the attack shapes it is meant to catch and add "
            "the benign cases it broke to its regression corpus.",
            "Demote the guard from BLOCK to FLAG for the failing family and route flagged "
            "traffic to review instead of rejecting it.",
            "If the guard is an aisg guard, lower its `sensitivity` or disable the failing "
            "family in the preset, then re-run `aisg measure`.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        max_fpr = Thresholds().max_false_positive_rate
        # One site per guard name: the first enabled one wins, so a guard switched off in
        # a preset but constructed directly in code still counts as wired.
        wired: dict[str, _GuardSite] = {}
        for site in _guard_sites(ctx):
            current = wired.get(site.name)
            if current is None or (site.enabled and not current.enabled):
                wired[site.name] = site

        findings: list[Finding] = []
        for record in _measure_reports(ctx):
            report_file = str(getattr(record, "file", "") or "")
            for guard in sorted(_report_guards(record), key=lambda g: str(g.get("name") or "")):
                name = str(guard.get("name") or "")
                if not name:
                    self.unknown.append(
                        UnknownItem(
                            category=UnknownCategory.REPORTS,
                            what=f"guard entry in {report_file}",
                            why="the entry has no name, so it cannot be tied to a guard",
                            how_to_resolve="regenerate the report with `aisg measure`",
                            file=report_file,
                            rule_ids=(self.id,),
                        )
                    )
                    continue
                raw_failures = guard.get("threshold_failures")
                failures = (
                    [str(f) for f in raw_failures if f] if isinstance(raw_failures, list) else []
                )
                fpr = guard.get("false_positive_rate")
                over = isinstance(fpr, (int, float)) and not isinstance(fpr, bool) and fpr > max_fpr
                if not failures and not over:
                    continue
                site = wired.get(name)
                if site is not None and not site.enabled:
                    continue
                reasons = list(failures)
                if over and not any(
                    "false-positive" in f or "false_positive" in f for f in reasons
                ):
                    reasons.append(f"false-positive rate {fpr:.3f} > {max_fpr}")
                if site is not None:
                    status = f"still wired in {site.file}"
                    evidence = [
                        Evidence(
                            role="report",
                            file=report_file,
                            line=0,
                            snippet=f"{name}: {reasons[0]}",
                        ),
                        Evidence(
                            role="config",
                            file=site.file,
                            line=site.line,
                            snippet=_line(file_text(ctx, site.file), site.line) or name,
                        ),
                    ]
                else:
                    status = (
                        "no guard config in the tree names this guard, so whether it is "
                        "still wired cannot be told from the tree"
                    )
                    evidence = [
                        Evidence(
                            role="report",
                            file=report_file,
                            line=0,
                            snippet=f"{name}: {reasons[0]}",
                        )
                    ]
                findings.append(
                    self.finding(
                        file=report_file,
                        line=0,
                        snippet=f"{name}: {reasons[0]}",
                        evidence=evidence,
                        scope=Scope(kind="file", name=report_file),
                        report=record.finding_report(),
                        notes=f"{name}: " + "; ".join(reasons) + f"; {status}",
                    )
                )
        return findings


class LLMJudgeWithoutCredentialsOrTimeout(AuditRule):
    """AUD-804: an LLM judge is switched on with no credential binding or no timeout in reach."""

    id = "AUD-804"
    title = "LLM judge without credentials or timeout"
    priority = 8
    severity = Severity.MEDIUM
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CONFIG
    match_kind = MatchKind.GREP
    measured_precision = None
    tier = Tier.T1
    controls = (
        "ASI08",
        "LLM10",
        "EU:Art.15",
        "NIST:MEASURE-2.7",
        "NIST:MANAGE-2.3",
    )
    related_lint_rules = ("ALIGN-002",)
    known_failure_modes = (
        "Credentials injected by the platform (a secrets manager, an IAM role, a "
        "workload identity) never appear in the tree, so the judge is reported as "
        "credential-less.",
        "Any `*_API_KEY` binding in the unit counts, even one for an unrelated service.",
        "Any `timeout` token in the judge's file or a loop-cap hit in the unit counts as a "
        "timeout, whether or not it applies to the judge call.",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "A judge that cannot reach its model is not a guard: declare the credential it "
            "needs, bound its call with a timeout, and decide what happens when it fails."
        ),
        alternatives=(
            "Declare the judge's key in .env.example and fail startup when it is unset, "
            "instead of discovering the gap on the first request.",
            "Wrap the judge call in a hard timeout (asyncio.wait_for or the client's "
            "timeout option) and treat a timeout as a failed check, not a pass.",
            "If the judge is an aisg LLM judge, set `timeout` on it and keep fail_open off; "
            "with no credentials it otherwise costs seconds per request and lets traffic "
            "through.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        judge_files: list[str] = []
        for entry in _entries(ctx, "guardrails"):
            file = str(entry.get("file") or "")
            lib = str(entry.get("lib") or "")
            if file and lib in (_PRESET_LIB, _AISG_LIB) and file not in judge_files:
                judge_files.append(file)

        cred_cache: dict[str | None, bool] = {}
        timeout_cache: dict[str | None, bool] = {}
        findings: list[Finding] = []
        for file in sorted(judge_files):
            text = file_text(ctx, file)
            if not text:
                continue
            for match in _JUDGE_RE.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                unit = _owning_unit(ctx, file)
                unit_id = unit.id if unit is not None else None
                if unit_id not in cred_cache:
                    cred_cache[unit_id] = self._has_credentials(ctx, unit)
                if unit_id not in timeout_cache:
                    timeout_cache[unit_id] = self._has_timeout(ctx, unit, judge_files)
                has_creds = cred_cache[unit_id]
                has_timeout = timeout_cache[unit_id] or bool(_TIMEOUT_RE.search(text))
                if has_creds and has_timeout:
                    continue
                missing = []
                if not has_creds:
                    missing.append("no *_API_KEY binding in the unit's env or config files")
                if not has_timeout:
                    missing.append("no timeout in the judge's file or unit")
                findings.append(
                    self.finding(
                        file=file,
                        line=line,
                        snippet=_line(text, line) or match.group(0),
                        sub="no-credentials" if not has_creds else "no-timeout",
                        evidence_kind=EvidenceKind.CONFIG
                        if _is_config(file)
                        else EvidenceKind.CODE,
                        notes="; ".join(missing),
                    )
                )
        return findings

    @staticmethod
    def _has_credentials(ctx: AuditContext, unit: Unit | None) -> bool:
        for binding in getattr(ctx.config_facts, "env", None) or []:
            name = str(getattr(binding, "name", "") or "")
            if not _API_KEY_RE.fullmatch(name):
                continue
            owner = _owning_unit(ctx, str(getattr(binding, "file", "") or ""))
            if unit is None or owner is None or owner.id == unit.id:
                return True
        for relpath in _unit_files(ctx, unit, code_only=False):
            if not (_is_config(relpath) or relpath.endswith(".py")):
                continue
            text = file_text(ctx, relpath)
            if text and _API_KEY_RE.search(text):
                return True
        return False

    @staticmethod
    def _has_timeout(ctx: AuditContext, unit: Unit | None, judge_files: list[str]) -> bool:
        unit_id = unit.id if unit is not None else None
        if any(hit.key == "timeout" for hit in _hits(ctx, "loop_cap", unit=unit_id)):
            return True
        for relpath in judge_files:
            if unit is not None and _owning_unit(ctx, relpath) is not unit:
                continue
            text = file_text(ctx, relpath)
            if text and _TIMEOUT_RE.search(text):
                return True
        return False


class KeywordOnlyFilter(AuditRule):
    """AUD-805: a word list stands in for a content guard."""

    id = "AUD-805"
    title = "Keyword-only content filter"
    priority = 8
    severity = Severity.LOW
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    measured_precision = None
    tier = Tier.T2
    controls = (
        "ASI01",
        "LLM01",
        "LLM05",
        "EU:Art.15",
        "NIST:MEASURE-2.7",
    )
    related_lint_rules = ("EU-AIA-015a",)
    known_failure_modes = (
        "Whether the tested operand is user or model content is not traced; a banned-word "
        "list checked against a config value is reported the same way.",
        "A word list used alongside a classifier that is not in GUARDRAIL_LIBS (a "
        "hand-rolled model, a hosted API) is still reported as keyword-only.",
        "A list built at runtime, loaded from a file, or shorter than five words is not seen.",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "A word list catches the words on it and nothing else; pair it with a "
            "classifier or a moderation endpoint and measure both on benign traffic."
        ),
        alternatives=(
            "Call a moderation endpoint (OpenAI moderations, Azure AI Content Safety, "
            "Llama Guard) and keep the word list only as a fast pre-filter.",
            "Run a local classifier (a fine-tuned toxicity model via Detoxify or "
            "Presidio for PII) and measure its false-positive rate on your own traffic.",
            "If the pipeline runs through aisg, enable toxicity_output / pii_detector and "
            "run `aisg measure` so the trade is on record.",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        guarded_units: set[str | None] = set()
        for entry in _entries(ctx, "guardrails"):
            unit = _owning_unit(ctx, str(entry.get("file") or ""))
            guarded_units.add(unit.id if unit is not None else None)

        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        for hit in _hits(ctx, "keyword_filter"):
            if (hit.file, hit.line) in seen:
                continue
            unit = _owning_unit(ctx, hit.file)
            unit_id = unit.id if unit is not None else None
            if unit_id in guarded_units or (unit_id is not None and None in guarded_units):
                continue
            name = hit.key.split(":", 1)[1] if ":" in hit.key else hit.key
            text = file_text(ctx, hit.file)
            if text is None or _literal_words(text, hit.line) < _MIN_KEYWORDS:
                continue
            if not self._is_tested(ctx, unit, hit.file, name):
                continue
            seen.add((hit.file, hit.line))
            findings.append(
                self.finding(
                    file=hit.file,
                    line=hit.line,
                    snippet=hit.snippet,
                    notes=(
                        f"list {name} is used as a membership test and no guardrail library "
                        "is imported in the unit"
                    ),
                )
            )
        return findings

    @staticmethod
    def _is_tested(ctx: AuditContext, unit: Unit | None, file: str, name: str) -> bool:
        pattern = re.compile(
            rf"(?:\bin\s+{re.escape(name)}\b"
            rf"|\b{re.escape(name)}\s*\.\s*(?:includes|some|has|contains|Contains|count)\s*\()"
        )
        candidates = [file] + [f for f in _unit_files(ctx, unit, code_only=True) if f != file]
        for relpath in candidates:
            text = file_text(ctx, relpath)
            if text and pattern.search(text):
                return True
        return False


def _literal_words(text: str, line: int) -> int:
    """Quoted tokens inside the bracketed literal that opens on `line`."""
    lines = text.splitlines()
    if line < 1 or line > len(lines):
        return 0
    depth = 0
    opened = False
    collected: list[str] = []
    for raw in lines[line - 1 : line - 1 + _LITERAL_WINDOW]:
        collected.append(raw)
        for ch in raw:
            if ch in "[{(":
                depth += 1
                opened = True
            elif ch in "]})":
                depth -= 1
        if opened and depth <= 0:
            break
    return len(_QUOTED_RE.findall("\n".join(collected)))


RULES: list[type[AuditRule]] = [
    GuardUnmeasured,
    GuardFailOpen,
    GuardReportedBelowThreshold,
    LLMJudgeWithoutCredentialsOrTimeout,
    KeywordOnlyFilter,
]
