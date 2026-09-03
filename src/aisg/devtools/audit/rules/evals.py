# aisg-audit: ignore-file
"""aisg/devtools/audit/rules/evals.py
------------------------------------
P9 evaluation-loop rules: AUD-901 (no evals in CI), AUD-902 (probe report shows
cases that failed, were inconclusive, errored or were skipped), AUD-903 (model
changed since the last report) and AUD-904 (eval config without benign traffic).

Honesty rules that hold here:

- A report read from disk is ASSERTED and carries its age. Reading a file is not
  measuring; only an external tool that ran during this audit is MEASURED.
- A report whose age cannot be established, or that carries no `models` list,
  yields an UnknownItem and no finding -- never a silent pass.
- Every finding describes evidence (counts, ages, names). None of them is a verdict.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

from aisg.devtools.audit.model import (
    AuditContext,
    Basis,
    Evidence,
    EvidenceKind,
    Finding,
    MatchKind,
    Recommendation,
    ReportRecord,
    Scope,
    Severity,
    Tier,
    UnknownCategory,
    UnknownItem,
)
from aisg.devtools.audit.rules import AuditRule, file_text, hits_in

__all__ = [
    "RULES",
    "NoEvalsInCI",
    "ProbeReportFailures",
    "StaleReport",
    "NoBenignCorpus",
]

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# Task runners that count as "wired into the build" next to CI workflows (DESIGN P9).
_RUNNER_BASENAMES = frozenset(
    {
        "makefile",
        "gnumakefile",
        "package.json",
        "tox.ini",
        "noxfile.py",
        "justfile",
        "taskfile.yml",
        "taskfile.yaml",
    }
)

# A benign corpus announces itself by one of these words in an eval config or in a
# file name under an eval directory. Word match only; a differently labelled benign
# set is a known failure mode, recorded on the rule.
_BENIGN_TEXT_RE = re.compile(r"\bbenign\b|\bmust_survive\b", re.I)
_BENIGN_NAME_RE = re.compile(r"benign|allow|must_survive", re.I)
_EVAL_DIR_RE = re.compile(r"(?:^|/)evals?/")

# Probe summary buckets in the order they are reported, with the severity each one
# carries. The keys are exactly the ones `probe.py` emits under `summary`.
_PROBE_BUCKETS: tuple[tuple[str, Severity, str], ...] = (
    (
        "failed",
        Severity.HIGH,
        "A failed case means the detector found its marker in the response: the attack "
        "got through.",
    ),
    (
        "inconclusive",
        Severity.MEDIUM,
        "An inconclusive case reflected most of the payload back; the marker in the "
        "response does not show the model followed it.",
    ),
    (
        "errors",
        Severity.MEDIUM,
        "An errored case never reached a working endpoint (non-2xx, timeout or transport "
        "error); it was not tested.",
    ),
    (
        "skipped",
        Severity.LOW,
        "A skipped case was never sent. system_prompt_extraction cases need "
        "`aisg probe --system-canary <token>` with the token planted in the target's "
        "system prompt.",
    ),
)


def _basename(relpath: str) -> str:
    return PurePosixPath(relpath).name


def _reports(ctx: AuditContext) -> list[ReportRecord]:
    """On-disk reports the audit read, unique by file, sorted by file.

    `ctx.reports` is what main.py fills; the inventory copy is the fallback so a
    hand-built context with only an inventory still works. Only ReportRecord-shaped
    entries are used: a plain dict in `inventory.reports` has no body to read.
    """
    seen: set[str] = set()
    out: list[ReportRecord] = []
    candidates = list(ctx.reports or []) + list(getattr(ctx.inventory, "reports", None) or [])
    for record in candidates:
        if not isinstance(record, ReportRecord):
            continue
        if record.file in seen:
            continue
        seen.add(record.file)
        out.append(record)
    return sorted(out, key=lambda r: r.file)


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def _json_key_line(text: str | None, key: str, *, after: str | None = None) -> int:
    """1-based line of `"key"` in a JSON text, searched after `"after"` when given; 0 if unknown."""
    if not text:
        return 0
    start = 0
    if after is not None:
        anchor = re.search(r'"' + re.escape(after) + r'"\s*:', text)
        if anchor is None:
            return 0
        start = anchor.end()
    match = re.compile(r'"' + re.escape(key) + r'"\s*:').search(text, start)
    if match is None:
        return 0
    return text.count("\n", 0, match.start()) + 1


def _eval_line(ctx: AuditContext, relpath: str) -> int:
    """First `eval_tool` grep hit line in a file, or 0 when the hits are unavailable."""
    lines = [hit.line for hit in hits_in(ctx, "eval_tool", file=relpath)]
    return min(lines) if lines else 0


def _eval_entries(ctx: AuditContext) -> list[dict[str, Any]]:
    entries = [e for e in (ctx.inventory.evals or []) if isinstance(e, dict) and e.get("file")]
    return sorted(entries, key=lambda e: (str(e.get("file")), str(e.get("tool", ""))))


def _has_ai_surface(ctx: AuditContext) -> bool:
    """`run_rules` gates on this too; absence rules repeat it so `evaluate` stands alone."""
    return any(getattr(unit, "ai_surface", False) for unit in (ctx.inventory.units or []))


def _known_model(model: str, inventory_models: list[str]) -> bool:
    """A report model is known when an inventory model id equals it or differs only by a suffix."""
    for known in inventory_models:
        if model == known:
            return True
        if known.startswith(model + "-") or model.startswith(known + "-"):
            return True
    return False


# ---------------------------------------------------------------------------
# AUD-901  No evals in CI
# ---------------------------------------------------------------------------


class NoEvalsInCI(AuditRule):
    id = "AUD-901"
    title = "No evals in CI"
    priority = 9
    severity = Severity.HIGH
    basis = Basis.ABSENCE
    evidence_kind = EvidenceKind.ABSENCE
    match_kind = MatchKind.STRUCTURED
    requires_ai_surface = True
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
        "an eval tool invoked from a script the audit does not recognise as a runner is "
        "reported as absent",
        "a CI workflow that names an eval tool without running it (a comment, a disabled "
        "job) counts as wired",
        "only the eval tools in patterns.EVAL_TOOLS are recognised",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Run an attack-plus-benign eval on every change: add `aisg measure` or "
            "`aisg probe` to the CI workflow and fail the job on regressions."
        ),
        alternatives=(
            "aisg measure --config <preset> in a CI step, with the report committed",
            "promptfoo eval in a GitHub Actions job (npx promptfoo eval -c promptfooconfig.yaml)",
            "deepeval or ragas test cases run by pytest in the existing test job",
            "inspect_ai or garak invoked from tox.ini / noxfile.py so the runner is versioned",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        if not _has_ai_surface(ctx):
            return []
        entries = _eval_entries(ctx)
        wired = any(
            bool(e.get("in_ci")) or _basename(str(e.get("file"))).lower() in _RUNNER_BASENAMES
            for e in entries
        )
        if not wired:
            wired = any(
                isinstance(row, dict) and bool(row.get("runs_evals"))
                for row in (ctx.inventory.ci or [])
            )
        if wired:
            return []
        if entries:
            tools = sorted({str(e.get("tool", "")) for e in entries if e.get("tool")})
            why = (
                f"eval tool(s) {', '.join(tools)} referenced in {len(entries)} file(s), none "
                "of them a CI workflow, Makefile, package.json script, tox.ini or noxfile.py"
            )
        else:
            why = (
                "no eval tool (promptfoo, deepeval, ragas, inspect_ai, garak, pyrit, giskard, "
                "lm_eval, evals/, aisg measure, aisg probe) referenced from CI or a task runner"
            )
        evidence = [Evidence(role="absence", file=".", line=0, snippet=why)]
        for entry in entries:
            relpath = str(entry.get("file"))
            evidence.append(
                Evidence(
                    role="eval",
                    file=relpath,
                    line=_eval_line(ctx, relpath),
                    snippet=f"{entry.get('tool', 'eval tool')} referenced outside CI",
                )
            )
        return [
            self.finding(
                file=".",
                line=0,
                snippet=why,
                evidence=evidence,
                scope=Scope(kind="repo", name="."),
            )
        ]


# ---------------------------------------------------------------------------
# AUD-902  Probe report shows failed / inconclusive / errored / skipped cases
# ---------------------------------------------------------------------------


class ProbeReportFailures(AuditRule):
    id = "AUD-902"
    title = "Probe report shows failed, inconclusive, errored or skipped cases"
    priority = 9
    severity = Severity.HIGH
    basis = Basis.MEASURED
    evidence_kind = EvidenceKind.REPORT
    match_kind = MatchKind.STRUCTURED
    tier = Tier.T2
    controls = (
        "ASI01",
        "ASI02",
        "LLM01",
        "LLM07",
        "EU:Art.15",
        "NIST:MEASURE-2.7",
        "NIST:MANAGE-2.2",
    )
    related_lint_rules = ("EU-AIA-015a", "EU-AIA-009a")
    known_failure_modes = (
        "the report is read from disk: it describes the endpoint at the time it was "
        "generated, not the one running now (see the REPORTED age)",
        "a hand-edited summary block is taken at face value",
        "summary counts are trusted over the cases list",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Re-run `aisg probe` against the current endpoint, fix the guard or the endpoint "
            "behind every failed case, and pass --system-canary so extraction cases run."
        ),
        alternatives=(
            "aisg probe <url> --system-canary <token>, then aisg measure on the guard config",
            "garak or pyrit red-team runs against the same endpoint",
            "promptfoo red-team plugins for the same attack families in the eval config",
            "a hand-written regression suite that replays the failed cases through pytest",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        for record in _reports(ctx):
            if record.kind != "probe":
                continue
            body = record.body if isinstance(record.body, dict) else {}
            summary = body.get("summary")
            if not isinstance(summary, dict):
                summary = self._summary_from_cases(body)
            if summary is None:
                self.unknown.append(
                    UnknownItem(
                        category=UnknownCategory.REPORTS,
                        what="probe report summary",
                        why="no summary block and no cases list to count",
                        how_to_resolve="Regenerate the report with `aisg probe`.",
                        file=record.file,
                        rule_ids=(self.id,),
                    )
                )
                continue
            sent = _int(summary.get("sent"))
            text = file_text(ctx, record.file)
            for key, severity, note in _PROBE_BUCKETS:
                count = _int(summary.get(key))
                if count is None:
                    self.unknown.append(
                        UnknownItem(
                            category=UnknownCategory.REPORTS,
                            what=f"probe report summary.{key}",
                            why="missing or not an integer",
                            file=record.file,
                            rule_ids=(self.id,),
                        )
                    )
                    continue
                if count <= 0:
                    continue
                of = f" of {sent} sent" if sent is not None else ""
                snippet = f'"{key}": {count}{of} probe case(s)'
                line = _json_key_line(text, key, after="summary")
                findings.append(
                    self.finding(
                        file=record.file,
                        line=line,
                        snippet=snippet,
                        evidence=[
                            Evidence(role="report", file=record.file, line=line, snippet=snippet)
                        ],
                        scope=Scope(kind="repo", name="."),
                        severity=severity,
                        sub=key,
                        report=record.finding_report(),
                        notes=note,
                    )
                )
        return findings

    @staticmethod
    def _summary_from_cases(body: dict[str, Any]) -> dict[str, int] | None:
        cases = body.get("cases")
        if not isinstance(cases, list):
            return None
        counts = {"sent": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0, "inconclusive": 0}
        for case in cases:
            if not isinstance(case, dict):
                continue
            status = str(case.get("status", ""))
            counts["sent"] += 1
            key = "errors" if status == "error" else status
            if key in counts and key != "sent":
                counts[key] += 1
        return counts


# ---------------------------------------------------------------------------
# AUD-903  Model changed since last report
# ---------------------------------------------------------------------------


class StaleReport(AuditRule):
    id = "AUD-903"
    title = "Model changed since last report"
    priority = 9
    severity = Severity.MEDIUM
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.REPORT
    match_kind = MatchKind.STRUCTURED
    tier = Tier.T2
    controls = ("EU:Art.9", "EU:Art.15", "NIST:MEASURE-2.5", "NIST:MANAGE-4.1")
    related_lint_rules = ("EU-AIA-009a", "EU-AIA-011a")
    known_failure_modes = (
        "in a fresh clone every file's mtime is the checkout time, so a report dated by "
        "generated_at looks older than every model-bearing file",
        "model ids are compared as strings with a date/version suffix tolerated; a judge "
        "model named in a measure config is compared with the application's model ids",
        "a probe report never names a model (a black-box probe cannot see one), so only its "
        "age is compared",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Regenerate the report against the current model and config: `aisg measure` / "
            "`aisg probe` write generated_at, models and config_digest so the next audit can "
            "tell what was measured."
        ),
        alternatives=(
            "aisg measure --config <preset> and aisg probe <url> on every model or config change",
            "a CI job that fails when the committed report predates the model-bearing files",
            "promptfoo eval with the model id in the provider string and the results committed",
            "a changelog entry per model change that links the eval run it was measured with",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        findings: list[Finding] = []
        reports = _reports(ctx)
        # A report's own `models` list is scanned like any other file, so the report is a
        # model-bearing file in the inventory. Comparing a report with itself proves nothing.
        report_files = {record.file for record in reports}
        entries = [
            m
            for m in (ctx.inventory.models or [])
            if isinstance(m, dict) and m.get("file") and str(m.get("file")) not in report_files
        ]
        inventory_models = [str(m.get("model")) for m in entries if m.get("model")]
        model_files = sorted({str(m.get("file")) for m in entries})
        newest = self._newest_model_file(ctx, model_files)
        for record in reports:
            findings.extend(self._check_models(ctx, record, inventory_models, entries))
            findings.extend(self._check_age(ctx, record, model_files, newest, entries))
        return findings

    # -- models -------------------------------------------------------------

    def _check_models(
        self,
        ctx: AuditContext,
        record: ReportRecord,
        inventory_models: list[str],
        entries: list[dict[str, Any]],
    ) -> list[Finding]:
        body = record.body if isinstance(record.body, dict) else {}
        target = body.get("target")
        has_key = "models" in body or (isinstance(target, dict) and "models" in target)
        if not has_key:
            self.unknown.append(
                UnknownItem(
                    category=UnknownCategory.REPORTS,
                    what="report models unknown",
                    why="the report carries no models list, so model drift cannot be checked",
                    how_to_resolve="Regenerate the report with a version of aisg that writes models.",
                    file=record.file,
                    rule_ids=(self.id,),
                )
            )
            return []
        # An empty list is the report saying it names no model (a probe never does);
        # there is nothing to compare, and nothing unknown about it.
        missing = sorted(m for m in record.models if not _known_model(m, inventory_models))
        if not missing:
            return []
        have = ", ".join(sorted(set(inventory_models))) or "no model id"
        snippet = f"report names {', '.join(missing)}; inventory has {have}"
        line = _json_key_line(file_text(ctx, record.file), "models")
        evidence = [Evidence(role="report", file=record.file, line=line, snippet=snippet)]
        for entry in sorted(entries, key=lambda m: (str(m.get("file")), int(m.get("line") or 0))):
            evidence.append(
                Evidence(
                    role="model",
                    file=str(entry.get("file")),
                    line=int(entry.get("line") or 0),
                    snippet=f"model id {entry.get('model')}",
                )
            )
        return [
            self.finding(
                file=record.file,
                line=line,
                snippet=snippet,
                evidence=evidence,
                scope=Scope(kind="repo", name="."),
                sub="models",
                report=record.finding_report(),
            )
        ]

    # -- age ----------------------------------------------------------------

    def _newest_model_file(
        self, ctx: AuditContext, model_files: list[str]
    ) -> tuple[str, int, str] | None:
        """(relpath, age_days, source) of the most recently changed model-bearing file."""
        from aisg.devtools.audit.walk import file_age  # local: walk imports model too

        now = datetime.now(timezone.utc)
        best: tuple[str, int, str] | None = None
        for relpath in model_files:
            when, source = file_age(ctx.root / relpath, ctx.root)
            if when is None:
                continue
            days = max(0, (now - when).days)
            if best is None or days < best[1]:
                best = (relpath, days, source)
        if best is None and model_files:
            self.unknown.append(
                UnknownItem(
                    category=UnknownCategory.REPORTS,
                    what="model file age unknown",
                    why="no mtime and no git history for any model-bearing file",
                    file=model_files[0],
                    rule_ids=(self.id,),
                )
            )
        return best

    def _check_age(
        self,
        ctx: AuditContext,
        record: ReportRecord,
        model_files: list[str],
        newest: tuple[str, int, str] | None,
        entries: list[dict[str, Any]],
    ) -> list[Finding]:
        if record.age_days is None or record.age_source == "unknown":
            self.unknown.append(
                UnknownItem(
                    category=UnknownCategory.REPORTS,
                    what="report age unknown",
                    why="no generated_at, mtime and git both unavailable",
                    how_to_resolve="Regenerate the report; a report of unknown age is not evidence.",
                    file=record.file,
                    rule_ids=(self.id,),
                )
            )
            return []
        if not model_files or newest is None:
            return []
        relpath, file_days, source = newest
        if record.age_days <= file_days:
            return []
        snippet = (
            f"report is {record.age_days}d old ({record.age_source}); {relpath} changed "
            f"{file_days}d ago ({source})"
        )
        line = _json_key_line(file_text(ctx, record.file), "generated_at")
        model_line = min(
            (int(m.get("line") or 0) for m in entries if str(m.get("file")) == relpath),
            default=0,
        )
        return [
            self.finding(
                file=record.file,
                line=line,
                snippet=snippet,
                evidence=[
                    Evidence(role="report", file=record.file, line=line, snippet=snippet),
                    Evidence(
                        role="model",
                        file=relpath,
                        line=model_line,
                        snippet=f"model-bearing file changed {file_days}d ago ({source})",
                    ),
                ],
                scope=Scope(kind="repo", name="."),
                sub="age",
                report=record.finding_report(),
            )
        ]


# ---------------------------------------------------------------------------
# AUD-904  No benign corpus
# ---------------------------------------------------------------------------


class NoBenignCorpus(AuditRule):
    id = "AUD-904"
    title = "Eval config without benign traffic"
    priority = 9
    severity = Severity.MEDIUM
    basis = Basis.ABSENCE
    evidence_kind = EvidenceKind.CONFIG
    match_kind = MatchKind.STRUCTURED
    tier = Tier.T2
    controls = ("LLM01", "EU:Art.15", "NIST:MEASURE-2.5", "NIST:MEASURE-2.6")
    related_lint_rules = ("EU-AIA-015a", "EU-AIA-009a")
    known_failure_modes = (
        "benign traffic is recognised by the words benign / must_survive in an eval config "
        "or by benign / allow / must_survive in a file name under an eval directory; a "
        "benign set labelled otherwise is missed",
        "a CI workflow that only invokes the eval tool never carries benign cases itself; "
        "it is listed as evidence, not as the missing corpus",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Add benign cases the guard must let through, next to the attack cases: an eval "
            "with attacks only makes 'block everything' the optimal guard."
        ),
        alternatives=(
            "aisg measure, which scores every guard against benign_traffic.yaml as well",
            "promptfoo tests tagged benign with icontains / equals assertions on the expected answer",
            "deepeval or ragas cases built from real, consented user traffic",
            "an evals/benign/ directory of must-survive prompts replayed in CI",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        # Probe / measure reports live in `inventory.reports`, never in `evals[]`:
        # discovery excludes them, so every entry here is an eval config or CI step.
        entries = _eval_entries(ctx)
        if not entries:
            return []
        if any(bool(e.get("has_benign")) for e in entries):
            return []
        for entry in entries:
            text = file_text(ctx, str(entry.get("file")))
            if text and _BENIGN_TEXT_RE.search(text):
                return []
        for record in ctx.files or []:
            relpath = str(getattr(record, "relpath", "") or "")
            if _EVAL_DIR_RE.search(relpath) and _BENIGN_NAME_RE.search(_basename(relpath)):
                return []
        tools = sorted({str(e.get("tool", "")) for e in entries if e.get("tool")})
        why = (
            f"{len(entries)} eval config(s) reference {', '.join(tools)}; none carries benign "
            "traffic (no benign / must_survive cases, no benign file under an eval directory)"
        )
        # Anchor the finding on a config file rather than a CI workflow when there is one.
        anchor = next(
            (e for e in entries if not e.get("in_ci")),
            entries[0],
        )
        anchor_file = str(anchor.get("file"))
        anchor_line = _eval_line(ctx, anchor_file)
        evidence = [Evidence(role="absence", file=anchor_file, line=anchor_line, snippet=why)]
        for entry in entries:
            relpath = str(entry.get("file"))
            evidence.append(
                Evidence(
                    role="eval",
                    file=relpath,
                    line=_eval_line(ctx, relpath),
                    snippet=f"{entry.get('tool', 'eval tool')} referenced; no benign cases",
                )
            )
        return [
            self.finding(
                file=anchor_file,
                line=anchor_line,
                snippet=why,
                evidence=evidence,
                scope=Scope(kind="repo", name="."),
            )
        ]


RULES = [NoEvalsInCI, ProbeReportFailures, StaleReport, NoBenignCorpus]
