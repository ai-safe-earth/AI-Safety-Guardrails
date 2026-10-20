"""aisafe/devtools/fleet.py
----------------------
`aisafe fleet LIST`: audit many repositories, one `aisafe audit` subprocess each, and aggregate
what came back.

    aisafe fleet fleet.yaml                          # .aisafe-fleet/fleet-report.{json,csv,md}
    aisafe fleet bench/corpus.yaml --jobs 4 --proposal
    aisafe fleet repos.csv --fail-on-findings        # a team gating its own repositories

`LIST` is a YAML file (`repos: [{name, url | path, sha?, branch?}]`, the shape of
`bench/corpus.yaml`, so the bench corpus is a valid fleet list) or a CSV with the header
`name,url,sha` (`path` instead of `url` for a local checkout). The operator writes the
list; the fleet never searches for targets, because a tool that chose what to crawl would
be both a crawler and a judge of what it crawled.

Per repository: clone (or use the local path in place), then run
`python -m aisafe.cli audit . --format json --no-external --fail-on <level> -o <out>/<name>/
audit-report.json` with the clone as the working directory, so the target's own
`[tool.aisafe-audit]` applies as it does under the skill. A subprocess, because a wall-clock
cap cannot interrupt an in-process audit and one pathological repository must not take the
fleet down. Nothing is copied out of the per-repo report but counts, names and a path to
it: no evidence snippet reaches the fleet documents.

Exit codes: 0 when every listed repository was audited (findings in other people's
repositories are the survey's content, not its failure), 1 when at least one could not be
(clone failed, timeout, fatal audit): an incomplete survey must not look complete. 2 is a
fleet-level fatal (unreadable list, `git` missing, `--out` unwritable). `--fail-on-findings`
adds exit 1 when any repository's own audit exit code is 1.

The fleet never pushes, never opens a pull request and never writes into a clone.
`--proposal` writes `<out>/<name>/proposal.md`, a PR body a person can use after reading it.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Sequence

from aisafe.devtools._config import apply_tool_config
from aisafe.devtools._git import GitError, fetch_pinned, git_available
from aisafe.devtools.audit.model import DISCLAIMER, SCHEMA_VERSION, redact
from aisafe.devtools.audit.patterns import LANG_BY_EXT, is_protected_path
from aisafe.devtools.audit.report import BANNED_PHRASES, tool_version

__all__ = [
    "CSV_COLUMNS",
    "EXIT_FATAL",
    "EXIT_INCOMPLETE",
    "EXIT_INTERRUPTED",
    "EXIT_OK",
    "STATUSES",
    "TEMPLATES",
    "FleetError",
    "FleetOptions",
    "RepoResult",
    "Target",
    "audit_argv",
    "build_parser",
    "build_report",
    "check_templates",
    "main",
    "read_list",
    "render_csv",
    "render_markdown",
    "render_proposal",
    "run_fleet",
    "summarise",
]

KIND = "fleet"
TOOL_NAME = "aisafe-fleet"
PROG = "aisafe fleet"
CONFIG_SECTION = "aisafe-fleet"

DEFAULT_OUT = ".aisafe-fleet"
DEFAULT_JOBS = 1
DEFAULT_TIMEOUT = 600.0
DEFAULT_FAIL_ON = "high"
FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "info", "never")

EXIT_OK = 0
EXIT_INCOMPLETE = 1
EXIT_FATAL = 2
EXIT_INTERRUPTED = 130

STATUS_OK = "ok"
STATUS_CLONE_FAILED = "clone_failed"
STATUS_TIMEOUT = "timeout"
STATUS_FATAL = "fatal"
STATUSES: tuple[str, ...] = (STATUS_OK, STATUS_CLONE_FAILED, STATUS_TIMEOUT, STATUS_FATAL)

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
CSV_COLUMNS: tuple[str, ...] = (
    "name",
    "url",
    "sha",
    "status",
    "duration_s",
    "exit_code",
    "findings",
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "unknown_items",
    "languages",
    "providers",
    "frameworks",
    "tools",
    "mcp_servers",
    "hosts",
    "report",
)
_ERROR_CHARS = 400

# ---------------------------------------------------------------------------
# Fixed strings (scanned by `check_templates`)
# ---------------------------------------------------------------------------

_T_MD_H1 = "# aisafe fleet"
_T_MD_COUNTS = "{repos} repositories listed, {completed} audited, {failed} not audited."
_T_MD_TABLE_HEADER = (
    "| name | status | findings | critical | high | medium | low | info | UNKNOWN | exit | report |"
)
_T_MD_TABLE_RULE = "|---|---|---|---|---|---|---|---|---|---|---|"
_T_MD_NOT_AUDITED = "## Not audited"
_T_MD_NOT_AUDITED_NONE = "(every listed repository was audited)"
_T_MD_RULES = "## Rule frequency"
_T_MD_RULES_HEADER = "| rule | repositories | findings |"
_T_MD_RULES_RULE = "|---|---|---|"
_T_MD_NOTE = (
    "Counts come from each repository's own audit report (`report` column), which is the "
    "authoritative document; the fleet copies no evidence snippet."
)
_T_PROPOSAL_H1 = "# AI safety audit: {name}"
_T_PROPOSAL_TARGET = "Target: {location} at commit {sha}; audited {generated_at} with {tool}."
_T_PROPOSAL_SEVERITY = "## Findings by severity"
_T_PROPOSAL_SEVERITY_HEADER = "| severity | count |"
_T_PROPOSAL_PLAN = "## Plan (blast-radius order)"
_T_PROPOSAL_PLAN_HEADER = (
    "| # | rule | title | file:line | who | mechanism | same_control | leaves_open |"
)
_T_PROPOSAL_PLAN_RULE = "|---|---|---|---|---|---|---|---|"
_T_PROPOSAL_DECIDE = "## Decide"
_T_PROPOSAL_DECIDE_NOTE = (
    "One row per plan row, to be filled by the repository's owners: `aisafe decide` prices "
    "each control against declared budgets, and the ai-safety-audit skill walks the rows "
    "one approval at a time."
)
_T_PROPOSAL_DECIDE_HEADER = "| # | decision (apply / defer / accept) | reason |"
_T_PROPOSAL_DECIDE_RULE = "|---|---|---|"
_T_PROPOSAL_UNKNOWN = "## UNKNOWN"
_T_PROPOSAL_UNKNOWN_NONE = "(none listed)"
_T_PROPOSAL_COMMAND = "## How this was produced"
_T_PROPOSAL_APPLY = "## How to apply"
_T_PROPOSAL_APPLY_TEXT = (
    "Run the ai-safety-audit skill in a checkout of this repository; it applies one row per "
    "approval, re-audits after each diff and renders the after document. This proposal was "
    "produced by `aisafe fleet`, which never pushes, never opens a pull request and never "
    "writes into the repository. A person decides what to do with it."
)
_T_WHO_PACKAGE = "package"
_T_WHO_YOU = "you"
_T_WHO_APPROVAL = "you, approval needed"
_T_DASH = "-"
_T_NO_FINDINGS = "(no findings)"
_T_ABSENCE = "(absence: no file)"

TEMPLATES: tuple[str, ...] = (
    DISCLAIMER,
    _T_MD_H1,
    _T_MD_COUNTS,
    _T_MD_TABLE_HEADER,
    _T_MD_NOT_AUDITED,
    _T_MD_NOT_AUDITED_NONE,
    _T_MD_RULES,
    _T_MD_RULES_HEADER,
    _T_MD_NOTE,
    _T_PROPOSAL_H1,
    _T_PROPOSAL_TARGET,
    _T_PROPOSAL_SEVERITY,
    _T_PROPOSAL_SEVERITY_HEADER,
    _T_PROPOSAL_PLAN,
    _T_PROPOSAL_PLAN_HEADER,
    _T_PROPOSAL_DECIDE,
    _T_PROPOSAL_DECIDE_NOTE,
    _T_PROPOSAL_DECIDE_HEADER,
    _T_PROPOSAL_UNKNOWN,
    _T_PROPOSAL_UNKNOWN_NONE,
    _T_PROPOSAL_COMMAND,
    _T_PROPOSAL_APPLY,
    _T_PROPOSAL_APPLY_TEXT,
    _T_WHO_PACKAGE,
    _T_WHO_YOU,
    _T_WHO_APPROVAL,
    _T_NO_FINDINGS,
    _T_ABSENCE,
)
_BANNED_WORD = ("cl" + "ean").lower()


def check_templates() -> list[str]:
    """Banned phrases (and the banned word) present in this module's fixed strings."""
    found: list[str] = []
    for template in TEMPLATES:
        lowered = template.lower()
        for phrase in BANNED_PHRASES:
            if phrase in lowered:
                found.append(phrase)
        for token in lowered.replace("`", " ").replace(".", " ").replace(",", " ").split():
            if token == _BANNED_WORD:
                found.append(_BANNED_WORD)
    return sorted(set(found))


class FleetError(Exception):
    """A fleet-level fatal condition; `main` maps it to exit 2."""


# ---------------------------------------------------------------------------
# The list
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Target:
    name: str
    url: str | None = None
    path: str | None = None
    sha: str | None = None
    branch: str | None = None

    @property
    def location(self) -> str:
        return self.url or self.path or ""


_NAME_OK = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")


def _target(raw: dict[str, Any], where: str) -> Target:
    name = str(raw.get("name") or "").strip()
    if not name or any(ch not in _NAME_OK for ch in name) or name in (".", ".."):
        raise FleetError(f"{where}: `name` must be a file-system safe identifier, got {name!r}")
    url = str(raw.get("url") or "").strip() or None
    path = str(raw.get("path") or "").strip() or None
    if bool(url) == bool(path):
        raise FleetError(f"{where}: {name}: exactly one of `url` or `path` is required")
    sha = str(raw.get("sha") or "").strip().lower() or None
    if sha is not None and not (7 <= len(sha) <= 64 and all(c in "0123456789abcdef" for c in sha)):
        raise FleetError(f"{where}: {name}: `sha` is not a commit id")
    branch = str(raw.get("branch") or "").strip() or None
    return Target(name=name, url=url, path=path, sha=sha, branch=branch)


def read_list(path: Path) -> list[Target]:
    """Targets from a YAML (`repos:` list) or CSV (`name,url|path,sha`) file."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FleetError(f"list {path.as_posix()}: {exc.strerror or exc}") from exc
    where = path.as_posix()
    suffix = path.suffix.lower()
    rows: list[dict[str, Any]]
    if suffix in (".yaml", ".yml"):
        try:
            import yaml
        except ModuleNotFoundError as exc:  # pragma: no cover - pyyaml is a dependency
            raise FleetError("pyyaml is required: pip install pyyaml") from exc
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise FleetError(f"list {where}: not valid YAML ({exc})") from exc
        repos = data.get("repos") if isinstance(data, dict) else None
        if not isinstance(repos, list) or not repos:
            raise FleetError(f"list {where}: `repos` must be a non-empty list")
        rows = [r for r in repos if isinstance(r, dict)]
        if len(rows) != len(repos):
            raise FleetError(f"list {where}: every `repos` entry must be a mapping")
    elif suffix == ".csv":
        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames or "name" not in reader.fieldnames:
            raise FleetError(f"list {where}: CSV needs a header with `name` and `url` or `path`")
        if "url" not in reader.fieldnames and "path" not in reader.fieldnames:
            raise FleetError(f"list {where}: CSV needs a `url` or `path` column")
        rows = [dict(r) for r in reader]
        if not rows:
            raise FleetError(f"list {where}: no rows")
    else:
        raise FleetError(f"list {where}: expected a .yaml/.yml or .csv file")
    targets = [_target(r, where) for r in rows]
    names = [t.name for t in targets]
    duplicates = sorted({n for n in names if names.count(n) > 1})
    if duplicates:
        raise FleetError(f"list {where}: duplicate names: {', '.join(duplicates)}")
    return targets


# ---------------------------------------------------------------------------
# One repository
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FleetOptions:
    list_path: str
    out: str = DEFAULT_OUT
    jobs: int = DEFAULT_JOBS
    per_repo_timeout: float = DEFAULT_TIMEOUT
    fail_on: str = DEFAULT_FAIL_ON
    keep_clones: bool = False
    workdir: str | None = None
    resume: bool = False
    proposal: bool = False
    fail_on_findings: bool = False
    extra_args: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "list": self.list_path.replace("\\", "/"),
            "out": self.out.replace("\\", "/"),
            "jobs": self.jobs,
            "per_repo_timeout": self.per_repo_timeout,
            "fail_on": self.fail_on,
            "keep_clones": self.keep_clones,
            "workdir": self.workdir.replace("\\", "/") if self.workdir else None,
            "resume": self.resume,
            "proposal": self.proposal,
            "fail_on_findings": self.fail_on_findings,
            "extra_args": list(self.extra_args),
        }


@dataclass
class RepoResult:
    name: str
    url: str
    sha: str | None
    status: str
    duration_s: float
    exit_code: int | None = None
    report: str | None = None
    summary: dict[str, Any] = field(default_factory=dict)
    rule_frequency: dict[str, int] = field(default_factory=dict)
    highlights: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    resumed: bool = False
    command: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "url": self.url,
            "sha": self.sha,
            "status": self.status,
            "duration_s": round(self.duration_s, 3),
            "exit_code": self.exit_code,
            "report": self.report,
            "summary": self.summary,
            "rule_frequency": self.rule_frequency,
            "highlights": self.highlights,
            "error": self.error,
            "resumed": self.resumed,
        }


def audit_argv(fail_on: str, report_path: Path, extra: Sequence[str] = ()) -> list[str]:
    """The per-repo command: this interpreter, never a launcher that could install."""
    return [
        sys.executable,
        "-m",
        "aisafe.cli",
        "audit",
        ".",
        "--format",
        "json",
        "--no-external",
        "--fail-on",
        fail_on,
        "-o",
        str(report_path),
        *extra,
    ]


def _child_env() -> dict[str, str]:
    """The child must import the same `aisafe` this process did, installed or from `src/`."""
    import aisafe

    env = dict(os.environ)
    src = str(Path(aisafe.__file__).resolve().parents[1])
    env["PYTHONPATH"] = src + os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else src
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return env


def _parse_report(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("schema") != SCHEMA_VERSION:
        return None
    if data.get("kind") != "audit":
        return None
    return data


def _names(items: Any, key: str) -> list[str]:
    out: list[str] = []
    for item in items or []:
        if isinstance(item, dict) and item.get(key):
            out.append(str(item[key]))
    return sorted(set(out))


def summarise(
    report: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, int], dict[str, Any], str | None]:
    """(summary subset, rule_frequency, inventory highlights, git_sha) from one audit report."""
    summary_in = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    by_severity = (
        summary_in.get("by_severity") if isinstance(summary_in.get("by_severity"), dict) else {}
    )
    summary = {
        "findings": int(summary_in.get("findings") or 0),
        "by_severity": {s: int(by_severity.get(s) or 0) for s in SEVERITIES},
        "by_bucket": summary_in.get("by_bucket") or {},
        "unknown_items": int(summary_in.get("unknown_items") or 0),
        "unknown_by_category": summary_in.get("unknown_by_category") or {},
        "exit_code": summary_in.get("exit_code"),
    }
    frequency: dict[str, int] = {}
    for finding in report.get("findings") or []:
        if isinstance(finding, dict) and finding.get("id"):
            display = str(finding["id"])
            frequency[display] = frequency.get(display, 0) + 1
    inventory = report.get("inventory") if isinstance(report.get("inventory"), dict) else {}
    languages = inventory.get("languages") if isinstance(inventory.get("languages"), dict) else {}
    mcp = inventory.get("mcp") if isinstance(inventory.get("mcp"), dict) else {}
    highlights = {
        "languages": sorted(k for k, v in languages.items() if isinstance(v, int) and v > 0),
        "providers": _names(inventory.get("llm_calls"), "provider"),
        "frameworks": _names(inventory.get("frameworks"), "name"),
        "tools": len(inventory.get("tools") or []),
        "mcp_servers": len(mcp.get("servers") or []),
        "hosts": _names(inventory.get("hosts"), "host"),
        "guardrails": _names(inventory.get("guardrails"), "name"),
        "evals": _names(inventory.get("evals"), "name"),
    }
    target = report.get("target") if isinstance(report.get("target"), dict) else {}
    sha = target.get("git_sha")
    return summary, dict(sorted(frequency.items())), highlights, str(sha) if sha else None


def _short_error(text: str) -> str:
    return redact(" ".join(text.split()))[-_ERROR_CHARS:] if text else ""


def _relative(path: Path, base: Path) -> str:
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def run_one(target: Target, options: FleetOptions, out_dir: Path, workdir: Path) -> RepoResult:
    """Clone (or use the path), audit in a subprocess, summarise; never raises for one repo."""
    started = time.monotonic()
    report_path = out_dir / target.name / "audit-report.json"
    result = RepoResult(
        name=target.name, url=target.location, sha=target.sha, status=STATUS_OK, duration_s=0.0
    )

    if options.resume and report_path.is_file():
        parsed = _parse_report(report_path)
        if parsed is not None:
            result.summary, result.rule_frequency, result.highlights, sha = summarise(parsed)
            result.sha = sha or target.sha
            result.exit_code = result.summary.get("exit_code")
            result.report = _relative(report_path, Path.cwd())
            result.resumed = True
            return result

    clone: Path
    cleanup = False
    if target.path:
        clone = Path(target.path)
        if not clone.is_dir():
            result.status = STATUS_CLONE_FAILED
            result.error = f"path does not exist or is not a directory: {target.path}"
            result.duration_s = time.monotonic() - started
            return result
    else:
        clone = workdir / target.name
        cleanup = not options.keep_clones
        try:
            result.sha = fetch_pinned(
                str(target.url),
                target.sha,
                clone,
                branch=target.branch,
                timeout=options.per_repo_timeout,
            )
        except GitError as exc:
            result.status = STATUS_CLONE_FAILED
            result.error = _short_error(str(exc))
            result.duration_s = time.monotonic() - started
            if cleanup:
                shutil.rmtree(clone, ignore_errors=True)
            return result

    report_path.parent.mkdir(parents=True, exist_ok=True)
    argv = audit_argv(options.fail_on, report_path.resolve(), options.extra_args)
    result.command = argv
    try:
        proc = subprocess.run(
            argv,
            cwd=str(clone),
            env=_child_env(),
            capture_output=True,
            text=True,
            timeout=options.per_repo_timeout,
        )
    except subprocess.TimeoutExpired:
        result.status = STATUS_TIMEOUT
        result.error = f"audit exceeded {options.per_repo_timeout:.0f}s"
    else:
        if proc.returncode not in (0, 1):
            result.status = STATUS_FATAL
            result.exit_code = proc.returncode
            result.error = _short_error(proc.stderr or proc.stdout)
        else:
            parsed = _parse_report(report_path)
            if parsed is None:
                result.status = STATUS_FATAL
                result.exit_code = proc.returncode
                result.error = "the audit exited normally but wrote no readable report"
            else:
                result.summary, result.rule_frequency, result.highlights, sha = summarise(parsed)
                result.sha = sha or result.sha
                result.exit_code = proc.returncode
                result.report = _relative(report_path, Path.cwd())
    finally:
        if cleanup:
            shutil.rmtree(clone, ignore_errors=True)
    result.duration_s = time.monotonic() - started
    return result


# ---------------------------------------------------------------------------
# The documents
# ---------------------------------------------------------------------------


def build_report(
    results: Sequence[RepoResult], options: FleetOptions, generated_at: str | None = None
) -> dict[str, Any]:
    ordered = sorted(results, key=lambda r: r.name)
    by_severity = {s: 0 for s in SEVERITIES}
    frequency: dict[str, int] = {}
    findings = unknown = 0
    for r in ordered:
        if r.status != STATUS_OK:
            continue
        findings += int(r.summary.get("findings") or 0)
        unknown += int(r.summary.get("unknown_items") or 0)
        for s in SEVERITIES:
            by_severity[s] += int((r.summary.get("by_severity") or {}).get(s) or 0)
        for rule, count in r.rule_frequency.items():
            frequency[rule] = frequency.get(rule, 0) + count
    completed = sum(1 for r in ordered if r.status == STATUS_OK)
    return {
        "schema": SCHEMA_VERSION,
        "kind": KIND,
        "tool": {"name": TOOL_NAME, "version": tool_version()},
        "generated_at": generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "options": options.to_dict(),
        "totals": {
            "repos": len(ordered),
            "completed": completed,
            "failed": len(ordered) - completed,
            "findings": findings,
            "by_severity": by_severity,
            "rule_frequency": dict(sorted(frequency.items())),
            "unknown_items": unknown,
            "repos_with_exit_1": sum(1 for r in ordered if r.exit_code == 1),
        },
        "disclaimer": DISCLAIMER,
        "repos": [r.to_dict() for r in ordered],
    }


def render_csv(doc: dict[str, Any]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(CSV_COLUMNS), lineterminator="\n")
    writer.writeheader()
    for repo in doc["repos"]:
        severity = (repo.get("summary") or {}).get("by_severity") or {}
        highlights = repo.get("highlights") or {}
        writer.writerow(
            {
                "name": repo["name"],
                "url": repo["url"],
                "sha": repo.get("sha") or "",
                "status": repo["status"],
                "duration_s": repo["duration_s"],
                "exit_code": "" if repo.get("exit_code") is None else repo["exit_code"],
                "findings": (repo.get("summary") or {}).get("findings", ""),
                **{s: severity.get(s, "") for s in SEVERITIES},
                "unknown_items": (repo.get("summary") or {}).get("unknown_items", ""),
                "languages": " ".join(highlights.get("languages") or []),
                "providers": " ".join(highlights.get("providers") or []),
                "frameworks": " ".join(highlights.get("frameworks") or []),
                "tools": highlights.get("tools", ""),
                "mcp_servers": highlights.get("mcp_servers", ""),
                "hosts": " ".join(highlights.get("hosts") or []),
                "report": repo.get("report") or "",
            }
        )
    return buffer.getvalue()


def _ascii(text: Any) -> str:
    return str(text).encode("ascii", "replace").decode("ascii").replace("|", "/")


def render_markdown(doc: dict[str, Any]) -> str:
    totals = doc["totals"]
    lines = [_T_MD_H1, "", f"> {doc['disclaimer']}", ""]
    lines.append(
        _T_MD_COUNTS.format(
            repos=totals["repos"], completed=totals["completed"], failed=totals["failed"]
        )
    )
    lines += ["", _T_MD_TABLE_HEADER, _T_MD_TABLE_RULE]

    def sort_key(repo: dict[str, Any]) -> tuple[int, int, str]:
        severity = (repo.get("summary") or {}).get("by_severity") or {}
        return (-int(severity.get("critical") or 0), -int(severity.get("high") or 0), repo["name"])

    for repo in sorted(doc["repos"], key=sort_key):
        summary = repo.get("summary") or {}
        severity = summary.get("by_severity") or {}
        cells = [
            _ascii(repo["name"]),
            repo["status"],
            summary.get("findings", _T_DASH),
            *(severity.get(s, _T_DASH) for s in SEVERITIES),
            summary.get("unknown_items", _T_DASH),
            _T_DASH if repo.get("exit_code") is None else repo["exit_code"],
            _ascii(repo.get("report") or _T_DASH),
        ]
        lines.append("| " + " | ".join(str(c) for c in cells) + " |")
    lines += ["", _T_MD_NOT_AUDITED, ""]
    failed = [r for r in doc["repos"] if r["status"] != STATUS_OK]
    if failed:
        for repo in failed:
            lines.append(
                f"- {_ascii(repo['name'])}: {repo['status']}: {_ascii(repo.get('error') or _T_DASH)}"
            )
    else:
        lines.append(_T_MD_NOT_AUDITED_NONE)
    lines += ["", _T_MD_RULES, "", _T_MD_RULES_HEADER, _T_MD_RULES_RULE]
    per_rule_repos: dict[str, int] = {}
    for repo in doc["repos"]:
        for rule in repo.get("rule_frequency") or {}:
            per_rule_repos[rule] = per_rule_repos.get(rule, 0) + 1
    frequency = totals.get("rule_frequency") or {}
    for rule, count in sorted(frequency.items(), key=lambda kv: (-kv[1], kv[0])):
        lines.append(f"| {rule} | {per_rule_repos.get(rule, 0)} | {count} |")
    if not frequency:
        lines.append(f"| {_T_DASH} | {_T_DASH} | {_T_DASH} |")
    lines += ["", _T_MD_NOTE, ""]
    return "\n".join(lines)


def _language_of(finding: dict[str, Any], units: list[dict[str, Any]]) -> str:
    evidence = finding.get("evidence") or []
    file = str(evidence[0].get("file") or "") if evidence and isinstance(evidence[0], dict) else ""
    suffix = PurePosixPath(file).suffix
    by_ext = LANG_BY_EXT.get(suffix) or LANG_BY_EXT.get(suffix.lower())
    if by_ext and by_ext != "config":
        return str(by_ext)
    scope = finding.get("scope") if isinstance(finding.get("scope"), dict) else {}
    unit_id = scope.get("unit")
    languages = {
        str(u.get("id")): str(u.get("language") or "unknown") for u in units if isinstance(u, dict)
    }
    if unit_id and unit_id in languages:
        return languages[unit_id]
    if scope.get("kind") == "repo":
        root = next((u for u in units if isinstance(u, dict) and u.get("root") in (".", "")), None)
        if root is not None:
            return str(root.get("language") or "unknown")
    return "unknown"


def _who(finding: dict[str, Any], language: str) -> str:
    evidence = finding.get("evidence") or []
    file = str(evidence[0].get("file") or "") if evidence and isinstance(evidence[0], dict) else ""
    if file and is_protected_path(file):
        return _T_WHO_APPROVAL
    package = (finding.get("recommendation") or {}).get("package") or {}
    if package.get("symbols") and package.get("same_control") and language == "python":
        return _T_WHO_PACKAGE
    return _T_WHO_YOU


def render_proposal(target: Target, report: dict[str, Any], command: Sequence[str]) -> str:
    """The PR body for one repository: plan and decide tables, no evidence snippet."""
    target_block = report.get("target") if isinstance(report.get("target"), dict) else {}
    sha = str(target_block.get("git_sha") or target.sha or "unknown")[:12]
    tool = report.get("tool") if isinstance(report.get("tool"), dict) else {}
    tool_text = f"{tool.get('name', 'aisafe')} {tool.get('version', '')}".strip()
    lines = [
        _T_PROPOSAL_H1.format(name=_ascii(target.name)),
        "",
        f"> {report.get('disclaimer') or DISCLAIMER}",
        "",
        _T_PROPOSAL_TARGET.format(
            location=_ascii(target.location),
            sha=sha,
            generated_at=report.get("generated_at") or _T_DASH,
            tool=_ascii(tool_text),
        ),
        "",
        _T_PROPOSAL_SEVERITY,
        "",
        _T_PROPOSAL_SEVERITY_HEADER,
        "|---|---|",
    ]
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    by_severity = summary.get("by_severity") if isinstance(summary.get("by_severity"), dict) else {}
    for s in SEVERITIES:
        lines.append(f"| {s} | {int(by_severity.get(s) or 0)} |")
    lines += ["", _T_PROPOSAL_PLAN, "", _T_PROPOSAL_PLAN_HEADER, _T_PROPOSAL_PLAN_RULE]
    inventory = report.get("inventory") if isinstance(report.get("inventory"), dict) else {}
    units = inventory.get("units") if isinstance(inventory.get("units"), list) else []
    findings = [f for f in report.get("findings") or [] if isinstance(f, dict)]
    for index, finding in enumerate(findings, start=1):
        evidence = finding.get("evidence") or []
        first = evidence[0] if evidence and isinstance(evidence[0], dict) else {}
        location = f"{first.get('file')}:{first.get('line')}" if first.get("file") else _T_ABSENCE
        package = (finding.get("recommendation") or {}).get("package") or {}
        language = _language_of(finding, units)
        lines.append(
            "| "
            + " | ".join(
                [
                    str(index),
                    _ascii(finding.get("id")),
                    _ascii(finding.get("title")),
                    _ascii(location),
                    _who(finding, language),
                    _ascii(package.get("mechanism") or "none"),
                    "yes" if package.get("same_control") else "no",
                    _ascii(package.get("leaves_open") or _T_DASH),
                ]
            )
            + " |"
        )
    if not findings:
        lines.append(f"| {_T_DASH} | {_T_NO_FINDINGS} | | | | | | |")
    lines += [
        "",
        _T_PROPOSAL_DECIDE,
        "",
        _T_PROPOSAL_DECIDE_NOTE,
        "",
        _T_PROPOSAL_DECIDE_HEADER,
        _T_PROPOSAL_DECIDE_RULE,
    ]
    for index in range(1, len(findings) + 1):
        lines.append(f"| {index} | | |")
    lines += ["", _T_PROPOSAL_UNKNOWN, ""]
    unknown = [u for u in report.get("unknown") or [] if isinstance(u, dict)]
    if unknown:
        for item in unknown:
            lines.append(
                f"- [{_ascii(item.get('category'))}] {_ascii(item.get('what'))}: {_ascii(item.get('why'))}"
            )
    else:
        lines.append(_T_PROPOSAL_UNKNOWN_NONE)
    lines += ["", _T_PROPOSAL_COMMAND, "", "    " + " ".join(_ascii(part) for part in command), ""]
    lines += [_T_PROPOSAL_APPLY, "", _T_PROPOSAL_APPLY_TEXT, ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def run_fleet(options: FleetOptions, *, echo: bool = True) -> tuple[dict[str, Any], int]:
    """Audit every target; write the three documents; return (document, exit code)."""
    targets = read_list(Path(options.list_path))
    if any(t.url for t in targets) and not git_available():
        raise FleetError("git is not on PATH and the list names remote repositories")
    out_dir = Path(options.out)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise FleetError(f"--out {options.out}: {exc.strerror or exc}") from exc
    if options.workdir:
        workdir = Path(options.workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        temp_root: str | None = None
    else:
        temp_root = tempfile.mkdtemp(prefix="aisafe-fleet-")
        workdir = Path(temp_root)

    results: list[RepoResult] = []
    try:
        if options.jobs > 1:
            with ThreadPoolExecutor(max_workers=options.jobs) as pool:
                futures = [pool.submit(run_one, t, options, out_dir, workdir) for t in targets]
                for target, future in zip(targets, futures):
                    result = future.result()
                    results.append(result)
                    if echo:
                        _echo(result)
        else:
            for target in targets:
                result = run_one(target, options, out_dir, workdir)
                results.append(result)
                if echo:
                    _echo(result)
    finally:
        if temp_root is not None and not options.keep_clones:
            shutil.rmtree(temp_root, ignore_errors=True)

    doc = build_report(results, options)
    _write(out_dir / "fleet-report.json", json.dumps(doc, indent=2, ensure_ascii=True) + "\n")
    _write(out_dir / "fleet-report.csv", render_csv(doc))
    _write(out_dir / "fleet-report.md", render_markdown(doc) + "\n")
    if options.proposal:
        by_name = {t.name: t for t in targets}
        for result in results:
            if result.status != STATUS_OK or not result.report:
                continue
            report_path = out_dir / result.name / "audit-report.json"
            parsed = _parse_report(report_path)
            if parsed is None:
                continue
            command = result.command or audit_argv(options.fail_on, report_path, options.extra_args)
            _write(
                out_dir / result.name / "proposal.md",
                render_proposal(by_name[result.name], parsed, command),
            )

    code = EXIT_OK
    if doc["totals"]["failed"]:
        code = EXIT_INCOMPLETE
    if options.fail_on_findings and doc["totals"]["repos_with_exit_1"]:
        code = EXIT_INCOMPLETE
    return doc, code


def _echo(result: RepoResult) -> None:
    summary = result.summary or {}
    if result.status == STATUS_OK:
        severity = summary.get("by_severity") or {}
        detail = (
            f"{summary.get('findings', 0)} finding(s), {severity.get('critical', 0)} critical, "
            f"{severity.get('high', 0)} high, {summary.get('unknown_items', 0)} UNKNOWN, "
            f"exit {result.exit_code}"
        )
        if result.resumed:
            detail += " (resumed)"
    else:
        detail = f"{result.status}: {result.error or ''}".rstrip(": ")
    print(f"{result.name}: {detail} [{result.duration_s:.1f}s]")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Audit every repository in LIST (YAML `repos:` or CSV `name,url,sha`), one "
            "`aisafe audit` subprocess each, and write fleet-report.{json,csv,md}. Findings in "
            "the listed repositories are the survey's content; a repository that could not be "
            "audited is its failure (exit 1)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes: 0 every repository audited, 1 at least one not audited (or, with "
            "--fail-on-findings, a repository's own audit exited 1), 2 fatal, 130 interrupted.\n"
            "The fleet clones only the URLs you list; it never searches, pushes or opens a PR."
        ),
    )
    p.add_argument("list", help="fleet.yaml (`repos:` with name, url|path, sha?, branch?) or a CSV")
    p.add_argument(
        "--out",
        default=DEFAULT_OUT,
        metavar="DIR",
        help=f"where the documents go (default: {DEFAULT_OUT})",
    )
    p.add_argument(
        "--jobs", type=int, default=DEFAULT_JOBS, metavar="N", help="parallel audits (default: 1)"
    )
    p.add_argument(
        "--per-repo-timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        metavar="S",
        help=f"wall-clock cap per repository, clone and audit each (default: {DEFAULT_TIMEOUT:.0f})",
    )
    p.add_argument(
        "--fail-on", choices=FAIL_ON_CHOICES, default=DEFAULT_FAIL_ON, help="passed to each audit"
    )
    p.add_argument(
        "--keep-clones", action="store_true", help="leave the checkouts in the work directory"
    )
    p.add_argument(
        "--workdir",
        default=None,
        metavar="DIR",
        help="where clones go (default: a temporary directory)",
    )
    p.add_argument(
        "--resume",
        action="store_true",
        help="skip a repository whose report under --out already parses",
    )
    p.add_argument(
        "--proposal", action="store_true", help="also write <out>/<name>/proposal.md, a PR body"
    )
    p.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="exit 1 when any repository's audit exited 1",
    )
    p.add_argument(
        "--extra-args",
        default="",
        metavar="ARGS",
        help="extra arguments for every `aisafe audit`, one string",
    )
    p.add_argument("--quiet", "-q", action="store_true", help="no per-repository lines on stdout")
    p.add_argument(
        "--debug", action="store_true", help="tracebacks on fatal errors; self-check the templates"
    )
    return p


def _options(args: argparse.Namespace) -> FleetOptions:
    import shlex

    if args.jobs < 1:
        raise FleetError("--jobs must be at least 1")
    if args.per_repo_timeout <= 0:
        raise FleetError("--per-repo-timeout must be positive")
    extra = tuple(shlex.split(args.extra_args)) if args.extra_args else ()
    return FleetOptions(
        list_path=args.list,
        out=args.out,
        jobs=args.jobs,
        per_repo_timeout=args.per_repo_timeout,
        fail_on=args.fail_on,
        keep_clones=args.keep_clones,
        workdir=args.workdir,
        resume=args.resume,
        proposal=args.proposal,
        fail_on_findings=args.fail_on_findings,
        extra_args=extra,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    apply_tool_config(parser, CONFIG_SECTION)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.debug:
        leaked = check_templates()
        if leaked:
            print(f"{PROG}: template self-check failed: {leaked}", file=sys.stderr)
            return EXIT_FATAL
    try:
        options = _options(args)
        doc, code = run_fleet(options, echo=not args.quiet)
    except FleetError as exc:
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
    totals = doc["totals"]
    print(
        f"{PROG}: {totals['completed']}/{totals['repos']} audited, {totals['failed']} not audited, "
        f"{totals['findings']} finding(s); documents under {Path(options.out).as_posix()}/"
    )
    return code


if __name__ == "__main__":
    sys.exit(main())
