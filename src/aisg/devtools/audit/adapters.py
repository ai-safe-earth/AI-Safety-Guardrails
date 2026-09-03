# aisg-audit: ignore-file
"""aisg/devtools/audit/adapters.py
--------------------------------
External tool adapters for `aisg audit`: gitleaks, detect-secrets, pip-audit, npm audit,
osv-scanner, mcp-scan, semgrep and promptfoo.

An adapter shells out to a scanner that is already installed, parses its JSON and folds
the result into MEASURED findings. Rules that hold:

- The audit never installs anything and never opens a socket of its own. A scanner
  that talks to a remote service declares `network = True`; the value is copied into
  its ExternalToolResult so a reader can see which rows depended on one.
- `build_argv()` is pure: no subprocess, no filesystem writes. `run()` is the only
  place a process starts, and only after `applicable()` and `locate()` said yes.
- A tool that is missing, fails or times out becomes an UnknownItem whose
  `how_to_resolve` names the install command as text. It is printed, never executed.
- Non-zero exit with parseable JSON is `ran` (scanners exit 1 on findings); no JSON is
  `failed` with the stderr tail, and never a finding.
- A tool's raw secret value never reaches a finding: snippets, titles and notes carry
  only the file, the line and the rule name the scanner reported.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from aisg.devtools.audit.model import (
    AuditContext,
    Basis,
    Bucket,
    Confidence,
    Evidence,
    EvidenceKind,
    ExternalToolResult,
    Finding,
    MatchKind,
    Recommendation,
    Scope,
    Severity,
    Status,
    Tier,
    UnknownCategory,
    UnknownItem,
    fingerprint,
    truncate_snippet,
)
from aisg.devtools.audit.patterns import MCP_CONFIG_FILES

__all__ = [
    "ADAPTERS",
    "CODE_LANGS",
    "DEFAULT_TIMEOUT",
    "DEFAULT_TOOL_NAMES",
    "FORBIDDEN_LAUNCHERS",
    "LOCKFILES",
    "NPM_LOCKFILES",
    "SEMGREP_RULES_PATH",
    "STDERR_TAIL",
    "Adapter",
    "DetectSecretsAdapter",
    "GitleaksAdapter",
    "McpScanAdapter",
    "NpmAuditAdapter",
    "OsvScannerAdapter",
    "PipAuditAdapter",
    "PromptfooAdapter",
    "RuleMeta",
    "SemgrepAdapter",
    "rule_meta",
    "run_adapters",
    "sink_rule_by_kind",
    "tool_finding",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TIMEOUT = 120
VERSION_PROBE_TIMEOUT = 15
STDERR_TAIL = 300

SEMGREP_RULES_PATH = Path(__file__).resolve().parent / "semgrep" / "aisg-sinks.yaml"

# Launchers that would install or fetch something. argv[0] is never one of these.
FORBIDDEN_LAUNCHERS = frozenset({"pip", "pip3", "uv", "uvx", "npx", "pipx"})

LOCKFILES = (
    "poetry.lock",
    "uv.lock",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "go.sum",
    "Cargo.lock",
)
NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json")
CODE_LANGS = frozenset({"python", "typescript", "go", "jvm"})

_PROMPTFOO_CONFIG_RE = re.compile(r"(?:^|/)promptfooconfig[^/]*\.(?:ya?ml|json)$")
_REQUIREMENTS_RE = re.compile(r"(?:^|/)requirements[^/]*\.txt$")
_HOST_SETTINGS_RE = re.compile(r"(?:^|/)\.(?:claude|cursor)/settings[^/]*\.json$")
_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
_CHECK_ID_RULE_RE = re.compile(r"aud[-_]?(\d{3})", re.I)
_CHECK_ID_KIND_RE = re.compile(r"aisg-sink-([a-z]+)", re.I)
_LOCAL_ONLY_REJECT_RE = re.compile(
    r"unrecognized arguments|unknown option|no such option|not recognized|invalid choice|"
    r"unexpected argument",
    re.I,
)

_BENIGN_LABELS = frozenset({"benign", "allow", "allowed", "must_survive", "helpful"})
_NEGATIVE_ASSERT = frozenset({"is-refusal"})

_SEVERITY_BY_LABEL = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}

# mcp-scan issue codes that describe transport / cross-origin problems (AUD-603)
# rather than a poisoned description (AUD-604). Anything else falls to the keywords.
_MCP_TRANSPORT_CODES = frozenset({"E003"})
_MCP_TRANSPORT_WORDS = (
    "cross-origin",
    "cross origin",
    "escalation",
    "toxic flow",
    "transport",
    "plaintext",
    "http://",
    "remote server",
)

# ---------------------------------------------------------------------------
# Rule metadata: registry first, local fallback second
# ---------------------------------------------------------------------------

_SINK_RULE_FALLBACK: dict[str, str] = {
    "shell": "AUD-401",
    "eval": "AUD-402",
    "sql": "AUD-403",
    "html": "AUD-404",
    "url": "AUD-405",
    "fs": "AUD-406",
    "file": "AUD-406",
    "filesystem": "AUD-406",
}


def sink_rule_by_kind() -> dict[str, str]:
    """kind -> AUD id for semgrep sink rules. The registry's table wins when it exists."""
    merged = dict(_SINK_RULE_FALLBACK)
    try:
        from aisg.devtools.audit.rules.sinks import SINK_RULE_BY_KIND
    except Exception:  # module absent, or the registry failed to import: fall back
        return merged
    try:
        merged.update({str(k).lower(): str(v) for k, v in dict(SINK_RULE_BY_KIND).items()})
    except (TypeError, ValueError):
        pass
    return merged


@dataclass(frozen=True)
class RuleMeta:
    """The rule-level fields an adapter finding copies from its rule."""

    id: str
    title: str
    severity: Severity
    tier: Tier
    controls: tuple[str, ...]
    recommendation: Recommendation
    related_lint_rules: tuple[str, ...] = ()
    known_failure_modes: tuple[str, ...] = ()
    priority: int = 0  # 0 -> derived from the id: AUD-4xx is P4, AUD-10xx is P10

    def __post_init__(self) -> None:
        if self.priority <= 0:
            digits = self.id.split("-", 1)[-1]
            derived = int(digits[:-2]) if digits[:-2].isdigit() else 10
            object.__setattr__(self, "priority", derived)


def _rec(tier: Tier, summary: str, *alternatives: str) -> Recommendation:
    return Recommendation(tier=tier, summary=summary, alternatives=tuple(alternatives))


_SINK_CONTROLS = ("ASI05", "LLM05", "EU:Art.15", "NIST:MEASURE-2.7")
_OUTPUT_CONTROLS = ("LLM05", "ASI02", "EU:Art.15", "NIST:MEASURE-2.7")
_SECRET_CONTROLS = ("LLM02", "ASI03", "EU:Art.15", "NIST:MEASURE-2.7")
_SUPPLY_CONTROLS = ("ASI04", "LLM03", "EU:Art.15", "NIST:MAP-4.1")
_EVAL_CONTROLS = ("LLM01", "EU:Art.9", "EU:Art.15", "NIST:MEASURE-2.5")

_FALLBACK_RULES: dict[str, RuleMeta] = {
    "AUD-401": RuleMeta(
        id="AUD-401",
        title="Model output -> shell",
        severity=Severity.CRITICAL,
        tier=Tier.T3,
        controls=_SINK_CONTROLS,
        recommendation=_rec(
            Tier.T3,
            "Never hand model output to a shell; run an allowlisted command as an argv list.",
            "subprocess.run([...], shell=False) with the command from an allowlist and the "
            "model output passed only as data",
            "aisg ToolPolicyGuard with a command allowlist and human approval for shell tools",
            "run the tool in a sandbox (container, seccomp, firejail) with no network and a "
            "read-only filesystem",
        ),
    ),
    "AUD-402": RuleMeta(
        id="AUD-402",
        title="Model output -> eval / dynamic import",
        severity=Severity.CRITICAL,
        tier=Tier.T3,
        controls=_SINK_CONTROLS,
        recommendation=_rec(
            Tier.T3,
            "Do not evaluate model output as code; interpret a declarative plan instead.",
            "replace eval/exec with a dispatch table of named operations",
            "aisg ToolPolicyGuard gating any code-execution tool behind approval",
            "execute untrusted code only in an isolated runtime (wasm, gVisor, a throwaway "
            "container)",
        ),
    ),
    "AUD-403": RuleMeta(
        id="AUD-403",
        title="Model output -> SQL",
        severity=Severity.CRITICAL,
        tier=Tier.T3,
        controls=_SINK_CONTROLS,
        recommendation=_rec(
            Tier.T3,
            "Bind model output as a query parameter, never as SQL text.",
            "parameterised queries or prepared statements through the driver or ORM",
            "aisg ToolPolicyGuard rejecting tool arguments that contain SQL keywords",
            "a read-only database role for the agent plus row-level security",
        ),
    ),
    "AUD-404": RuleMeta(
        id="AUD-404",
        title="Model output -> HTML",
        severity=Severity.HIGH,
        tier=Tier.T3,
        controls=_OUTPUT_CONTROLS,
        recommendation=_rec(
            Tier.T3,
            "Escape model output before rendering; treat it as text, not markup.",
            "render through textContent or an auto-escaping template, and a Markdown "
            "renderer that strips raw HTML",
            "aisg OutputGuard sanitising responses before they reach the UI",
            "a Content-Security-Policy without unsafe-inline plus DOMPurify on any HTML the "
            "model produces",
        ),
    ),
    "AUD-405": RuleMeta(
        id="AUD-405",
        title="Model output -> URL / request",
        severity=Severity.HIGH,
        tier=Tier.T3,
        controls=_OUTPUT_CONTROLS,
        recommendation=_rec(
            Tier.T3,
            "Resolve URLs from model output against a host allowlist before any request.",
            "host allowlist, scheme check and no redirects on the HTTP client",
            "aisg ToolPolicyGuard with a URL allowlist for fetch-style tools",
            "an egress proxy that only permits approved destinations",
        ),
    ),
    "AUD-406": RuleMeta(
        id="AUD-406",
        title="Model output -> filesystem path",
        severity=Severity.HIGH,
        tier=Tier.T3,
        controls=_OUTPUT_CONTROLS,
        recommendation=_rec(
            Tier.T3,
            "Confine file paths from model output to one directory and reject traversal.",
            "resolve the path and check it stays inside the sandbox root before open/write",
            "aisg ToolPolicyGuard with a path allowlist for file tools",
            "run the agent with a read-only filesystem and a dedicated scratch mount",
        ),
    ),
    "AUD-501": RuleMeta(
        id="AUD-501",
        title="Secret literal in source",
        severity=Severity.CRITICAL,
        tier=Tier.T1,
        controls=_SECRET_CONTROLS,
        recommendation=_rec(
            Tier.T1,
            "Rotate the secret now; load it from the environment or a secrets manager.",
            "rotate the key, then read it from the environment or a vault at runtime",
            "aisg lint as a pre-commit hook plus a detect-secrets baseline",
            "a gitleaks pre-commit hook and the hosting platform's secret scanning",
        ),
        known_failure_modes=(
            "the scanner's own false positives are reported as-is: a placeholder shaped "
            "like a key still fires",
        ),
    ),
    "AUD-502": RuleMeta(
        id="AUD-502",
        title="Secret in MCP / host config",
        severity=Severity.CRITICAL,
        tier=Tier.T1,
        controls=_SECRET_CONTROLS,
        recommendation=_rec(
            Tier.T1,
            "Reference secrets in MCP/host config as ${ENV_VAR}; rotate the leaked value.",
            "use the host's env-reference syntax and keep the value in the OS keychain or a vault",
            "aisg audit in CI so a config secret fails the build",
            "gitleaks with a custom rule scoped to MCP config files",
        ),
    ),
    "AUD-603": RuleMeta(
        id="AUD-603",
        title="Remote or plaintext MCP transport",
        severity=Severity.HIGH,
        tier=Tier.T1,
        controls=("ASI07", "LLM03", "EU:Art.15", "NIST:MAP-4.1"),
        recommendation=_rec(
            Tier.T1,
            "Use stdio or TLS to a host you control; list trusted remote hosts explicitly.",
            "pin the server to https:// with certificate validation",
            "aisg audit --trusted-mcp-hosts <host> to record the trust decision",
            "a local stdio proxy that terminates TLS and enforces a host allowlist",
        ),
    ),
    "AUD-604": RuleMeta(
        id="AUD-604",
        title="MCP tool-description poisoning",
        severity=Severity.CRITICAL,
        tier=Tier.T1,
        controls=("ASI01", "LLM01", "ASI04", "EU:Art.15", "NIST:MEASURE-2.7"),
        recommendation=_rec(
            Tier.T1,
            "Remove or quarantine the server; pin and review tool descriptions like code.",
            "pin the server version and diff tool descriptions on every update",
            "aisg PromptInjectionGuard over tool descriptions before they reach the model",
            "mcp-scan --local-only in CI with a stored tool-description baseline",
        ),
    ),
    "AUD-606": RuleMeta(
        id="AUD-606",
        title="Dependency vulnerabilities",
        severity=Severity.HIGH,
        tier=Tier.T1,
        controls=_SUPPLY_CONTROLS,
        recommendation=_rec(
            Tier.T1,
            "Upgrade to the fixed version the advisory names and pin the lockfile.",
            "upgrade, regenerate the lockfile and re-run the scanner",
            "aisg audit in CI so a new advisory blocks the merge",
            "Dependabot or Renovate with security updates enabled",
        ),
        known_failure_modes=("severity is the advisory's, not the reachability in this code",),
    ),
    "AUD-902": RuleMeta(
        id="AUD-902",
        title="Eval run has failing cases",
        severity=Severity.HIGH,
        tier=Tier.T2,
        controls=_EVAL_CONTROLS,
        recommendation=_rec(
            Tier.T2,
            "Investigate every failing eval case before shipping; a failure is a regression.",
            "block the release on eval failures in CI",
            "aisg probe or aisg measure against the deployed endpoint to reproduce",
            "promptfoo eval in CI with a stored baseline and failure thresholds",
        ),
    ),
    "AUD-904": RuleMeta(
        id="AUD-904",
        title="No benign corpus",
        severity=Severity.MEDIUM,
        tier=Tier.T2,
        controls=_EVAL_CONTROLS,
        recommendation=_rec(
            Tier.T2,
            "Add benign cases the guardrails must let through, not only attacks.",
            "add benign prompts with positive assertions to the eval config",
            "aisg measure with benign_traffic.yaml as a starting corpus",
            "promptfoo tests carrying metadata.kind: benign and an llm-rubric assertion",
        ),
        known_failure_modes=(
            "a case is counted benign from metadata.kind or from having only positive "
            "assertions; an attack case asserted with llm-rubric alone is miscounted",
        ),
    ),
}

_GENERIC_RECOMMENDATION = _rec(
    Tier.T1,
    "Review the tool's own advisory for this finding.",
    "read the scanner's report and apply the remediation it names",
    "aisg audit --format json to track the finding against a baseline",
    "the scanner's own baseline / ignore mechanism, once reviewed",
)


def _registered_rule(rule_id: str) -> Any | None:
    try:
        from aisg.devtools.audit.rules import rule_by_id
    except Exception:  # the registry may not exist yet or may fail to import
        return None
    try:
        return rule_by_id(rule_id)
    except Exception:
        return None


def rule_meta(rule_id: str) -> RuleMeta:
    """Rule-level metadata for `rule_id`: the registered rule class, else a local fallback."""
    rule = _registered_rule(rule_id)
    if rule is not None:
        try:
            return RuleMeta(
                id=str(rule.id),
                title=str(rule.title),
                severity=Severity(rule.severity),
                tier=Tier(rule.tier),
                controls=tuple(rule.controls),
                recommendation=rule.recommendation,
                related_lint_rules=tuple(getattr(rule, "related_lint_rules", ())),
                known_failure_modes=tuple(getattr(rule, "known_failure_modes", ())),
                priority=_int(getattr(rule, "priority", 0)),
            )
        except (AttributeError, TypeError, ValueError):
            pass
    meta = _FALLBACK_RULES.get(rule_id)
    if meta is not None:
        return meta
    return RuleMeta(
        id=rule_id,
        title=f"External tool finding ({rule_id})",
        severity=Severity.HIGH,
        tier=Tier.T1,
        controls=(),
        recommendation=_GENERIC_RECOMMENDATION,
    )


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _posix(path: Any) -> str:
    return str(path).replace("\\", "/")


def _relative(path: Any, root: Path | str | None) -> str:
    """`path` as a POSIX path relative to `root` when it lies inside it."""
    text = _posix(path or "")
    if root is not None:
        bases = [_posix(root)]
        try:
            bases.append(_posix(Path(root).resolve()))
        except OSError:
            pass
        for base in bases:
            base = base.rstrip("/")
            if not base:
                continue
            if text == base:
                return "."
            if text.startswith(base + "/"):
                text = text[len(base) + 1 :]
                break
    while text.startswith("./"):
        text = text[2:]
    return text or "."


def _relpaths(ctx: AuditContext) -> list[str]:
    out: list[str] = []
    for record in ctx.files:
        rel = getattr(record, "relpath", None)
        out.append(_posix(record if rel is None else rel))
    return out


def _basename(relpath: str) -> str:
    return relpath.rsplit("/", 1)[-1]


def _opt(ctx: AuditContext, name: str, default: Any = None) -> Any:
    options = ctx.options
    if options is None:
        return default
    if isinstance(options, dict):
        value = options.get(name, default)
    else:
        value = getattr(options, name, default)
    return default if value is None else value


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _tail(text: str | None, limit: int = STDERR_TAIL) -> str:
    flat = " ".join(str(text or "").split())
    return flat[-limit:] if len(flat) > limit else flat


def _load_json(text: str | None) -> Any | None:
    """Parse JSON from tool output, tolerating a banner line before the document."""
    if not text or not text.strip():
        return None
    try:
        return json.loads(text)
    except ValueError:
        pass
    starts = [i for i in (text.find("{"), text.find("[")) if i >= 0]
    if not starts:
        return None
    try:
        return json.loads(text[min(starts) :])
    except ValueError:
        return None


def _module_available(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, ValueError, AttributeError):
        return False


def _severity_from_label(label: Any) -> Severity | None:
    if not label:
        return None
    return _SEVERITY_BY_LABEL.get(str(label).strip().lower())


def _severity_from_score(score: Any) -> Severity | None:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    if value > 0.0:
        return Severity.LOW
    return None


def _at_most(severity: Severity, cap: Severity) -> Severity:
    return cap if severity.rank() > cap.rank() else severity


def _inside(root: Path, candidate: str) -> bool:
    try:
        Path(candidate).resolve().relative_to(Path(root).resolve())
    except (OSError, ValueError):
        return False
    return True


def _secret_rule_for(relpath: str) -> str:
    """AUD-502 for MCP / host config files, AUD-501 for everything else."""
    posix = _posix(relpath)
    if _HOST_SETTINGS_RE.search(posix):
        return "AUD-502"
    for _host, rx in MCP_CONFIG_FILES:
        if rx.search(posix):
            return "AUD-502"
    return "AUD-501"


def tool_finding(
    rule_id: str,
    *,
    tool: str,
    file: str,
    line: int,
    snippet: str,
    severity: Severity | None = None,
    detail: str | None = None,
    notes: str | None = None,
    sub: str | None = None,
    extra_evidence: Sequence[Evidence] = (),
) -> Finding:
    """A MEASURED finding produced by an external tool.

    Bucket, basis, evidence kind and match kind are fixed by construction; the precision
    is the literal None (UNMEASURED). Title, controls and recommendation come from the
    rule class when the registry has it, else from the local fallback table.
    """
    meta = rule_meta(rule_id)
    relpath = _posix(file) or "."
    snip = truncate_snippet(snippet)
    display_id = f"{rule_id}/{sub}" if sub else rule_id
    if relpath == ".":
        scope = Scope(kind="repo", name=".")
    else:
        scope = Scope(kind="file", name=relpath)
    evidence = [Evidence(role="tool", file=relpath, line=int(line), snippet=snip)]
    evidence.extend(extra_evidence)
    title = meta.title if not detail else f"{meta.title}: {detail}"
    return Finding(
        id=rule_id,
        sub=sub,
        fingerprint=fingerprint(display_id, relpath, snip),
        title=title,
        severity=severity or meta.severity,
        priority=meta.priority,
        bucket=Bucket.MEASURED,
        basis=Basis.MEASURED,
        confidence=Confidence(EvidenceKind.TOOL_OUTPUT, MatchKind.EXTERNAL, None),
        scope=scope,
        evidence=evidence,
        controls=meta.controls,
        recommendation=meta.recommendation,
        related_lint_rules=meta.related_lint_rules,
        known_failure_modes=meta.known_failure_modes,
        notes=notes if notes is not None else f"measured by {tool}",
    )


def _attach_file_facts(findings: Sequence[Finding], ctx: AuditContext) -> None:
    """Copy `gitignored` and the owning unit from the walk's file records."""
    records: dict[str, Any] = {}
    for record in ctx.files:
        rel = getattr(record, "relpath", None)
        if rel is not None:
            records[_posix(rel)] = record
    for finding in findings:
        file, _line = finding.location
        record = records.get(file)
        if record is None:
            continue
        if getattr(record, "gitignored", False):
            finding.gitignored = True
        unit = getattr(record, "unit", None)
        if unit and finding.scope.kind == "file" and finding.scope.unit is None:
            finding.scope = Scope(kind="file", unit=str(unit), name=finding.scope.name)


# ---------------------------------------------------------------------------
# Process plumbing
# ---------------------------------------------------------------------------


def _execute(argv: Sequence[str], root: Path, timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        list(argv),
        cwd=str(root),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def _elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _remove(path: str | None) -> None:
    if path is None:
        return
    try:
        os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Adapter base
# ---------------------------------------------------------------------------


class Adapter:
    """One external scanner.

    Subclasses set the class attributes and implement `arguments()` and `parse()`.
    `build_argv()` is `launcher() + arguments()` and is pure; `run()` swaps the launcher
    for whatever `locate()` found (a PATH entry, or `python -m <module>` for a tool that
    is importable but has no console script) and is the only method that starts a
    process.
    """

    name: str = ""
    binary: str = ""
    module: str | None = None
    network: bool = False
    needs_flag: str | None = None
    what: str = ""
    rule_ids: tuple[str, ...] = ()
    install_hint: str = ""  # text only; never executed
    version_args: tuple[str, ...] = ("--version",)
    output_to_file: bool = False

    # -- pure ---------------------------------------------------------------

    def applicable(self, ctx: AuditContext) -> bool:
        return True

    def inputs(self, ctx: AuditContext) -> tuple[str, ...]:
        """Relpaths handed to the tool; the parser uses them to place findings."""
        return ()

    def launcher(self, ctx: AuditContext) -> list[str]:
        return [self.binary]

    def network_for(self, ctx: AuditContext) -> bool:
        return bool(self.network)

    def arguments(self, ctx: AuditContext, *, timeout: float, report_path: str | None) -> list[str]:
        raise NotImplementedError

    def build_argv(
        self, ctx: AuditContext, *, timeout: float = DEFAULT_TIMEOUT, report_path: str | None = None
    ) -> list[str]:
        """The exact command line, launcher first. No subprocess, no filesystem writes."""
        return list(self.launcher(ctx)) + list(
            self.arguments(ctx, timeout=timeout, report_path=report_path)
        )

    def parse(
        self, payload: Any, *, inputs: Sequence[str] = (), root: Path | str | None = None
    ) -> list[Finding]:
        raise NotImplementedError

    def decode(self, text: str | None) -> Any | None:
        return _load_json(text)

    def rejection(self, completed: subprocess.CompletedProcess) -> str | None:
        """A tool-specific reason to call the run `failed` before looking at its JSON."""
        return None

    def precheck(self, ctx: AuditContext) -> tuple[Status, str | None, str, str] | None:
        """(status, flag, why, how_to_resolve) for an adapter-specific skip, else None."""
        return None

    def version_from(self, payload: Any) -> str | None:
        return None

    def flag_given(self, ctx: AuditContext) -> bool:
        if not self.needs_flag:
            return True
        option = self.needs_flag.lstrip("-").replace("-", "_")
        return bool(_opt(ctx, option, False))

    def unknown(self, why: str, how_to_resolve: str | None) -> UnknownItem:
        return UnknownItem(
            category=UnknownCategory.TOOLS,
            what=self.what or self.name,
            why=why,
            how_to_resolve=how_to_resolve,
            rule_ids=self.rule_ids,
        )

    # -- effects ------------------------------------------------------------

    def locate(self, ctx: AuditContext | None = None) -> list[str] | None:
        """PATH first, then `python -m <module>` for an importable tool. Never installs."""
        found = shutil.which(self.binary)
        if found:
            return [found]
        if self.module and _module_available(self.module):
            return [sys.executable, "-m", self.module]
        return None

    def probe_version(self, launcher: Sequence[str], root: Path, timeout: float) -> str | None:
        if not self.version_args:
            return None
        try:
            completed = _execute(
                [*launcher, *self.version_args], root, min(VERSION_PROBE_TIMEOUT, timeout)
            )
        except (OSError, subprocess.SubprocessError, ValueError):
            return None
        text = f"{completed.stdout or ''} {completed.stderr or ''}"
        match = _VERSION_RE.search(text)
        return match.group(0) if match else None

    def _result(self, status: Status, network: bool, **fields: Any) -> ExternalToolResult:
        return ExternalToolResult(name=self.name, status=status, network=network, **fields)

    def _read_output(self, completed: subprocess.CompletedProcess, report_path: str | None) -> str:
        if report_path is None:
            return completed.stdout or ""
        try:
            return Path(report_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def run(
        self, ctx: AuditContext, *, timeout: float = DEFAULT_TIMEOUT
    ) -> tuple[ExternalToolResult, list[Finding], list[UnknownItem]]:
        network = self.network_for(ctx)
        if not self.applicable(ctx):
            return self._result(Status.NOT_APPLICABLE, network), [], []
        if not self.flag_given(ctx):
            flag = self.needs_flag
            why = f"{self.name} runs only with {flag}"
            result = self._result(Status.SKIPPED_NEEDS_FLAG, network, flag=flag)
            return result, [], [self.unknown(why, f"aisg audit . {flag}")]
        skip = self.precheck(ctx)
        if skip is not None:
            status, flag, why, how = skip
            result = self._result(status, network, flag=flag, error=why)
            return result, [], [self.unknown(why, how)]
        launcher = self.locate(ctx)
        if launcher is None:
            why = f"{self.binary} not on PATH"
            result = self._result(Status.NOT_ON_PATH, network, error=why)
            return result, [], [self.unknown(why, f"{self.install_hint} && aisg audit .")]

        report_path: str | None = None
        if self.output_to_file:
            fd, report_path = tempfile.mkstemp(prefix=f"aisg-{self.name}-", suffix=".json")
            os.close(fd)
        head = len(self.launcher(ctx))
        argv = (
            list(launcher) + self.build_argv(ctx, timeout=timeout, report_path=report_path)[head:]
        )
        version = self.probe_version(launcher, ctx.root, timeout)
        started = time.monotonic()
        try:
            completed = _execute(argv, ctx.root, timeout)
            text = self._read_output(completed, report_path)
        except subprocess.TimeoutExpired:
            why = f"timed out after {timeout:g}s"
            result = self._result(
                Status.TIMEOUT,
                network,
                version=version,
                duration_ms=_elapsed_ms(started),
                argv=tuple(argv),
                error=why,
            )
            how = f"aisg audit . --timeout {int(timeout * 2)}"
            return result, [], [self.unknown(f"{self.name} {why}", how)]
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            why = _tail(f"{type(exc).__name__}: {exc}")
            result = self._result(
                Status.FAILED,
                network,
                version=version,
                duration_ms=_elapsed_ms(started),
                argv=tuple(argv),
                error=why,
            )
            return result, [], [self.unknown(f"{self.name} failed: {why}", self.failure_hint())]
        finally:
            _remove(report_path)
        duration = _elapsed_ms(started)

        rejected = self.rejection(completed)
        if rejected is not None:
            result = self._result(
                Status.FAILED,
                network,
                version=version,
                duration_ms=duration,
                argv=tuple(argv),
                error=rejected,
            )
            return (
                result,
                [],
                [self.unknown(f"{self.name} failed: {rejected}", self.failure_hint())],
            )

        payload = self.decode(text)
        if payload is None:
            detail = _tail(completed.stderr) or _tail(completed.stdout) or "no JSON output"
            why = f"exit {completed.returncode}: {detail}"
            result = self._result(
                Status.FAILED,
                network,
                version=version,
                duration_ms=duration,
                argv=tuple(argv),
                error=why,
            )
            return result, [], [self.unknown(f"{self.name} failed: {why}", self.failure_hint())]

        try:
            findings = self.parse(payload, inputs=self.inputs(ctx), root=ctx.root)
        except Exception as exc:  # a shape the parser did not expect is a failed run, not a crash
            why = _tail(f"could not parse {self.name} output: {type(exc).__name__}: {exc}")
            result = self._result(
                Status.FAILED,
                network,
                version=version,
                duration_ms=duration,
                argv=tuple(argv),
                error=why,
            )
            return result, [], [self.unknown(f"{self.name} failed: {why}", self.failure_hint())]
        _attach_file_facts(findings, ctx)
        result = self._result(
            Status.RAN,
            network,
            version=version or self.version_from(payload),
            duration_ms=duration,
            findings=len(findings),
            argv=tuple(argv),
        )
        return result, findings, []

    def failure_hint(self) -> str:
        return f"run `{self.binary}` by hand in the target to see its error, then aisg audit ."


# ---------------------------------------------------------------------------
# Secrets: gitleaks, detect-secrets
# ---------------------------------------------------------------------------


class GitleaksAdapter(Adapter):
    name = "gitleaks"
    binary = "gitleaks"
    network = False
    what = "secrets: regex-only"
    rule_ids = ("AUD-501", "AUD-502")
    install_hint = "install gitleaks (brew install gitleaks, or a release binary on PATH)"
    version_args = ("version",)
    output_to_file = True

    def arguments(self, ctx: AuditContext, *, timeout: float, report_path: str | None) -> list[str]:
        report = report_path or os.path.join(tempfile.gettempdir(), "aisg-gitleaks-report.json")
        return [
            "detect",
            "--no-git",
            "--source",
            ".",
            "--report-format",
            "json",
            "--report-path",
            report,
            "--exit-code",
            "0",
            "--no-banner",
        ]

    def decode(self, text: str | None) -> Any | None:
        # gitleaks leaves the report empty when nothing was found.
        if text is None or not text.strip():
            return []
        return _load_json(text)

    def parse(
        self, payload: Any, *, inputs: Sequence[str] = (), root: Path | str | None = None
    ) -> list[Finding]:
        if not isinstance(payload, list):
            return []
        out: list[Finding] = []
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            file = _relative(entry.get("File") or "", root)
            line = _int(entry.get("StartLine"))
            rule = str(entry.get("RuleID") or "unknown-rule")
            description = " ".join(str(entry.get("Description") or "").split())
            label = f"gitleaks {rule}" + (f" ({description})" if description else "")
            out.append(
                tool_finding(
                    _secret_rule_for(file),
                    tool="gitleaks",
                    file=file,
                    line=line,
                    snippet=f"{label} line {line}",
                    detail=rule,
                    notes=f"gitleaks rule {rule} at {file}:{line}",
                )
            )
        return out


class DetectSecretsAdapter(Adapter):
    name = "detect-secrets"
    binary = "detect-secrets"
    module = "detect_secrets"
    network = False
    what = "secrets: regex-only"
    rule_ids = ("AUD-501", "AUD-502")
    install_hint = "pipx install detect-secrets"

    def applicable(self, ctx: AuditContext) -> bool:
        # Only the fallback when gitleaks is absent; otherwise not applicable, no UNKNOWN.
        return GitleaksAdapter().locate(ctx) is None

    def arguments(self, ctx: AuditContext, *, timeout: float, report_path: str | None) -> list[str]:
        return ["scan", "--all-files"]

    def version_from(self, payload: Any) -> str | None:
        if isinstance(payload, dict) and payload.get("version"):
            return str(payload["version"])
        return None

    def parse(
        self, payload: Any, *, inputs: Sequence[str] = (), root: Path | str | None = None
    ) -> list[Finding]:
        if not isinstance(payload, dict):
            return []
        results = payload.get("results") or {}
        if not isinstance(results, dict):
            return []
        out: list[Finding] = []
        for raw_file, entries in results.items():
            file = _relative(raw_file, root)
            for entry in entries or []:
                if not isinstance(entry, dict):
                    continue
                line = _int(entry.get("line_number"))
                kind = str(entry.get("type") or "secret")
                out.append(
                    tool_finding(
                        _secret_rule_for(file),
                        tool="detect-secrets",
                        file=file,
                        line=line,
                        snippet=f"detect-secrets {kind} line {line}",
                        detail=kind,
                        notes=f"detect-secrets plugin {kind} at {file}:{line}",
                    )
                )
        return out


# ---------------------------------------------------------------------------
# Dependencies: pip-audit, npm audit, osv-scanner
# ---------------------------------------------------------------------------


class PipAuditAdapter(Adapter):
    """Environment mode, or `--no-deps -r <req>`. Never `-r` without `--no-deps`.

    `-r` alone resolves the target's requirements in a temporary venv, which runs
    arbitrary setup code; `--no-deps` audits the pinned lines as written.
    """

    name = "pip-audit"
    binary = "pip-audit"
    module = "pip_audit"
    network = True
    what = "dependency vulnerabilities"
    rule_ids = ("AUD-606",)
    install_hint = "pipx install pip-audit"

    _COMMON = ("--format", "json", "--progress-spinner", "off")

    def applicable(self, ctx: AuditContext) -> bool:
        if any(getattr(unit, "language", "") == "python" for unit in ctx.inventory.units):
            return True
        for rel in _relpaths(ctx):
            if _REQUIREMENTS_RE.search(rel) or _basename(rel) in ("pyproject.toml", "setup.py"):
                return True
        return False

    def mode(self, ctx: AuditContext) -> tuple[str, Any] | None:
        """("env", <python or None>) | ("req", [files]) | None when nothing can be audited."""
        env = _opt(ctx, "pip_audit_env")
        if env:
            return "env", str(env)
        if _inside(ctx.root, sys.prefix):
            return "env", None
        reqs = sorted(rel for rel in _relpaths(ctx) if _REQUIREMENTS_RE.search(rel))
        if reqs:
            return "req", reqs[:8]
        return None

    def inputs(self, ctx: AuditContext) -> tuple[str, ...]:
        mode = self.mode(ctx)
        if mode is not None and mode[0] == "req":
            return tuple(mode[1])
        return ()

    def launcher(self, ctx: AuditContext) -> list[str]:
        mode = self.mode(ctx)
        if mode is not None and mode[0] == "env" and mode[1]:
            return [mode[1], "-m", "pip_audit"]
        return [self.binary]

    def locate(self, ctx: AuditContext | None = None) -> list[str] | None:
        if ctx is not None:
            mode = self.mode(ctx)
            if mode is not None and mode[0] == "env" and mode[1]:
                python = mode[1]
                if Path(python).is_file() or shutil.which(python):
                    return [python, "-m", "pip_audit"]
                return None
        return super().locate(ctx)

    def precheck(self, ctx: AuditContext) -> tuple[Status, str | None, str, str] | None:
        if self.mode(ctx) is not None:
            return None
        why = (
            "no environment to audit: no requirements*.txt and the audit is not running "
            "inside the target's virtualenv"
        )
        return (
            Status.SKIPPED_NEEDS_FLAG,
            "--pip-audit-env",
            why,
            ("aisg audit . --pip-audit-env <path to the target's python>"),
        )

    def arguments(self, ctx: AuditContext, *, timeout: float, report_path: str | None) -> list[str]:
        mode = self.mode(ctx)
        if mode is not None and mode[0] == "req":
            args = ["--no-deps"]
            for req in mode[1]:
                args.extend(["-r", req])
            args.extend(self._COMMON)
            return args
        return list(self._COMMON)

    def parse(
        self, payload: Any, *, inputs: Sequence[str] = (), root: Path | str | None = None
    ) -> list[Finding]:
        deps: Any = payload.get("dependencies") if isinstance(payload, dict) else payload
        if not isinstance(deps, list):
            return []
        file = _relative(inputs[0], root) if inputs else "."
        out: list[Finding] = []
        for dep in deps:
            if not isinstance(dep, dict):
                continue
            name = str(dep.get("name") or "?")
            version = str(dep.get("version") or "?")
            for vuln in dep.get("vulns") or []:
                if not isinstance(vuln, dict):
                    continue
                vuln_id = str(vuln.get("id") or "unknown-id")
                fixes = [str(v) for v in vuln.get("fix_versions") or []]
                aliases = [str(a) for a in vuln.get("aliases") or []]
                description = " ".join(str(vuln.get("description") or "").split())[:200]
                fix = f"fix {', '.join(fixes)}" if fixes else "no fix version listed"
                notes = f"pip-audit: {vuln_id}"
                if aliases:
                    notes += f" ({', '.join(aliases)})"
                if description:
                    notes += f": {description}"
                out.append(
                    tool_finding(
                        "AUD-606",
                        tool="pip-audit",
                        file=file,
                        line=0,
                        snippet=f"{name} {version}: {vuln_id} ({fix})",
                        detail=f"{name} {version} ({vuln_id})",
                        notes=notes,
                    )
                )
        return out


class NpmAuditAdapter(Adapter):
    name = "npm-audit"
    binary = "npm"
    network = True
    what = "dependency vulnerabilities"
    rule_ids = ("AUD-606",)
    install_hint = "install Node.js (it bundles npm)"

    def applicable(self, ctx: AuditContext) -> bool:
        # npm audit reads the lockfile in cwd, so only a root-level one counts; when
        # osv-scanner is present it covers every lockfile and npm audit stays out.
        rels = set(_relpaths(ctx))
        if not any(name in rels for name in NPM_LOCKFILES):
            return False
        return OsvScannerAdapter().locate(ctx) is None

    def inputs(self, ctx: AuditContext) -> tuple[str, ...]:
        rels = set(_relpaths(ctx))
        return tuple(name for name in NPM_LOCKFILES if name in rels)

    def arguments(self, ctx: AuditContext, *, timeout: float, report_path: str | None) -> list[str]:
        return ["audit", "--json", "--audit-level=low"]

    def parse(
        self, payload: Any, *, inputs: Sequence[str] = (), root: Path | str | None = None
    ) -> list[Finding]:
        if not isinstance(payload, dict):
            return []
        file = _relative(inputs[0], root) if inputs else "package-lock.json"
        out: list[Finding] = []
        vulns = payload.get("vulnerabilities")
        if isinstance(vulns, dict):
            for name, entry in vulns.items():
                if not isinstance(entry, dict):
                    continue
                out.extend(self._v2_entry(str(name), entry, file))
            return out
        advisories = payload.get("advisories")
        if isinstance(advisories, dict):
            for adv in advisories.values():
                if not isinstance(adv, dict):
                    continue
                name = str(adv.get("module_name") or "?")
                title = " ".join(str(adv.get("title") or "").split())
                severity = _severity_from_label(adv.get("severity")) or Severity.HIGH
                out.append(
                    tool_finding(
                        "AUD-606",
                        tool="npm audit",
                        file=file,
                        line=0,
                        snippet=f"{name}: {title}",
                        severity=severity,
                        detail=f"{name} ({adv.get('id') or 'advisory'})",
                        notes=f"npm audit: {adv.get('url') or ''}".strip(),
                    )
                )
        return out

    @staticmethod
    def _v2_entry(name: str, entry: dict[str, Any], file: str) -> list[Finding]:
        pkg_severity = _severity_from_label(entry.get("severity"))
        affected = str(entry.get("range") or "")
        via = entry.get("via") or []
        advisories = [v for v in via if isinstance(v, dict)]
        through = [str(v) for v in via if isinstance(v, str)]
        found: list[Finding] = []
        for adv in advisories:
            title = " ".join(str(adv.get("title") or "").split())
            cvss = (
                (adv.get("cvss") or {}).get("score") if isinstance(adv.get("cvss"), dict) else None
            )
            severity = (
                _severity_from_label(adv.get("severity"))
                or pkg_severity
                or _severity_from_score(cvss)
                or Severity.HIGH
            )
            notes = f"npm audit: {adv.get('url') or 'advisory'}"
            if cvss is not None:
                notes += f"; cvss {cvss}"
            found.append(
                tool_finding(
                    "AUD-606",
                    tool="npm audit",
                    file=file,
                    line=0,
                    snippet=f"{name} {affected}: {title}",
                    severity=severity,
                    detail=f"{name} {affected}".strip(),
                    notes=notes,
                )
            )
        if not advisories:
            found.append(
                tool_finding(
                    "AUD-606",
                    tool="npm audit",
                    file=file,
                    line=0,
                    snippet=f"{name} {affected}: vulnerable via {', '.join(through) or '?'}",
                    severity=pkg_severity or Severity.HIGH,
                    detail=f"{name} {affected}".strip(),
                    notes=f"npm audit: transitive via {', '.join(through) or '?'}",
                )
            )
        return found


class OsvScannerAdapter(Adapter):
    name = "osv-scanner"
    binary = "osv-scanner"
    network = True  # unless an offline DB directory is configured
    what = "dependency vulnerabilities"
    rule_ids = ("AUD-606",)
    install_hint = (
        "install osv-scanner (a release binary on PATH, or "
        "go install github.com/google/osv-scanner/cmd/osv-scanner@v1)"
    )

    @staticmethod
    def offline() -> bool:
        return bool(os.environ.get("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"))

    def network_for(self, ctx: AuditContext) -> bool:
        return not self.offline()

    def applicable(self, ctx: AuditContext) -> bool:
        return any(_basename(rel) in LOCKFILES for rel in _relpaths(ctx))

    def inputs(self, ctx: AuditContext) -> tuple[str, ...]:
        return tuple(sorted(rel for rel in _relpaths(ctx) if _basename(rel) in LOCKFILES))

    def arguments(self, ctx: AuditContext, *, timeout: float, report_path: str | None) -> list[str]:
        args = ["--format", "json", "--recursive"]
        if self.offline():
            args.append("--offline")
        args.append(".")
        return args

    def parse(
        self, payload: Any, *, inputs: Sequence[str] = (), root: Path | str | None = None
    ) -> list[Finding]:
        if not isinstance(payload, dict):
            return []
        out: list[Finding] = []
        for res in payload.get("results") or []:
            if not isinstance(res, dict):
                continue
            source = res.get("source") or {}
            file = _relative(source.get("path") if isinstance(source, dict) else "", root)
            for pkg in res.get("packages") or []:
                if not isinstance(pkg, dict):
                    continue
                info = pkg.get("package") or {}
                name = str(info.get("name") or "?")
                version = str(info.get("version") or "?")
                ecosystem = str(info.get("ecosystem") or "?")
                max_score: dict[str, Any] = {}
                for group in pkg.get("groups") or []:
                    if isinstance(group, dict):
                        for vid in group.get("ids") or []:
                            max_score[str(vid)] = group.get("max_severity")
                for vuln in pkg.get("vulnerabilities") or []:
                    if not isinstance(vuln, dict):
                        continue
                    vuln_id = str(vuln.get("id") or "unknown-id")
                    summary = " ".join(str(vuln.get("summary") or "").split())
                    specific = vuln.get("database_specific") or {}
                    label = specific.get("severity") if isinstance(specific, dict) else None
                    severity = (
                        _severity_from_label(label)
                        or _severity_from_score(max_score.get(vuln_id))
                        or Severity.HIGH
                    )
                    aliases = [str(a) for a in vuln.get("aliases") or []]
                    notes = f"osv-scanner: {vuln_id}"
                    if aliases:
                        notes += f" ({', '.join(aliases)})"
                    out.append(
                        tool_finding(
                            "AUD-606",
                            tool="osv-scanner",
                            file=file,
                            line=0,
                            snippet=f"{name} {version} ({ecosystem}): {vuln_id} {summary}",
                            severity=severity,
                            detail=f"{name} {version} ({vuln_id})",
                            notes=notes,
                        )
                    )
        return out


# ---------------------------------------------------------------------------
# MCP: mcp-scan (always --local-only)
# ---------------------------------------------------------------------------


class McpScanAdapter(Adapter):
    """`mcp-scan scan --local-only --json <configs>`.

    mcp-scan's default mode posts the target's tool descriptions to a remote API. The
    flag is never dropped: a version that rejects it is reported as `failed`.
    """

    name = "mcp-scan"
    binary = "mcp-scan"
    module = "mcp_scan"
    network = False
    what = "MCP descriptions: regex-only"
    rule_ids = ("AUD-604", "AUD-603")
    install_hint = "pipx install mcp-scan"

    LOCAL_ONLY_REJECTED = "no local-only mode; refusing to upload tool descriptions"

    def inputs(self, ctx: AuditContext) -> tuple[str, ...]:
        files: list[str] = []
        for entry in (ctx.inventory.mcp or {}).get("configs") or []:
            file = entry.get("file") if isinstance(entry, dict) else None
            if not file:
                continue
            file = _posix(file)
            if file.startswith("~") or file.startswith("/") or re.match(r"^[A-Za-z]:/", file):
                continue
            if file not in files:
                files.append(file)
        if not files:
            for rel in _relpaths(ctx):
                if any(rx.search(rel) for _host, rx in MCP_CONFIG_FILES) and rel not in files:
                    files.append(rel)
        return tuple(sorted(files))

    def applicable(self, ctx: AuditContext) -> bool:
        return bool(self.inputs(ctx))

    def arguments(self, ctx: AuditContext, *, timeout: float, report_path: str | None) -> list[str]:
        return ["scan", "--local-only", "--json", *self.inputs(ctx)]

    def rejection(self, completed: subprocess.CompletedProcess) -> str | None:
        if completed.returncode == 0:
            return None
        text = f"{completed.stderr or ''}\n{completed.stdout or ''}"
        if "local-only" in text and _LOCAL_ONLY_REJECT_RE.search(text):
            return self.LOCAL_ONLY_REJECTED
        return None

    def failure_hint(self) -> str:
        return "upgrade mcp-scan to a release that supports --local-only, then aisg audit ."

    @staticmethod
    def _reference(servers: Any, ref: Any) -> tuple[str, str]:
        server_name, tool_name = "", ""
        if not isinstance(ref, (list, tuple)) or not isinstance(servers, list):
            return server_name, tool_name
        try:
            server = servers[int(ref[0])] if len(ref) > 0 else None
        except (IndexError, TypeError, ValueError):
            server = None
        if isinstance(server, dict):
            server_name = str(server.get("name") or "")
            tools = (server.get("signature") or {}).get("tools") or []
            try:
                tool = tools[int(ref[1])] if len(ref) > 1 else None
            except (IndexError, TypeError, ValueError):
                tool = None
            if isinstance(tool, dict):
                tool_name = str(tool.get("name") or "")
        return server_name, tool_name

    @staticmethod
    def _rule_for(code: str, label: str, message: str) -> str:
        if code.upper() in _MCP_TRANSPORT_CODES:
            return "AUD-603"
        text = f"{label} {message}".lower()
        if any(word in text for word in _MCP_TRANSPORT_WORDS):
            return "AUD-603"
        return "AUD-604"

    def parse(
        self, payload: Any, *, inputs: Sequence[str] = (), root: Path | str | None = None
    ) -> list[Finding]:
        if not isinstance(payload, dict):
            return []
        out: list[Finding] = []
        for key, report in payload.items():
            if not isinstance(report, dict):
                continue
            file = _relative(report.get("path") or key, root)
            servers = report.get("servers") or []
            for issue in report.get("issues") or []:
                if not isinstance(issue, dict):
                    continue
                code = str(issue.get("code") or "")
                message = " ".join(str(issue.get("message") or "").split())
                extra = issue.get("extra_data") or {}
                label = str(extra.get("label") or "") if isinstance(extra, dict) else ""
                server_name, tool_name = self._reference(servers, issue.get("reference"))
                where = "/".join(part for part in (server_name, tool_name) if part)
                rule_id = self._rule_for(code, label, message)
                meta = rule_meta(rule_id)
                severity = (
                    meta.severity
                    if code.upper().startswith("E")
                    else _at_most(meta.severity, Severity.HIGH)
                )
                out.append(
                    tool_finding(
                        rule_id,
                        tool="mcp-scan",
                        file=file,
                        line=0,
                        snippet=f"mcp-scan {code} {where}: {label or message}".replace("  ", " "),
                        severity=severity,
                        detail=where or None,
                        notes=f"mcp-scan {code} ({label or 'issue'}): {message}",
                    )
                )
        return out


# ---------------------------------------------------------------------------
# Sinks: semgrep with the packaged aisg-sinks.yaml
# ---------------------------------------------------------------------------


class SemgrepAdapter(Adapter):
    name = "semgrep"
    binary = "semgrep"
    module = "semgrep"
    network = False  # --metrics=off and a local config
    what = "non-Python sink taint"
    rule_ids = ("AUD-401", "AUD-402", "AUD-403", "AUD-404", "AUD-405", "AUD-406")
    install_hint = "pipx install semgrep"

    def applicable(self, ctx: AuditContext) -> bool:
        return any(getattr(record, "lang", None) in CODE_LANGS for record in ctx.files)

    def precheck(self, ctx: AuditContext) -> tuple[Status, str | None, str, str] | None:
        if SEMGREP_RULES_PATH.is_file():
            return None
        why = f"packaged rules file missing: {SEMGREP_RULES_PATH.name}"
        return Status.FAILED, None, why, "reinstall ai-safety-guardrails, then aisg audit ."

    def arguments(self, ctx: AuditContext, *, timeout: float, report_path: str | None) -> list[str]:
        return [
            "scan",
            "--config",
            str(SEMGREP_RULES_PATH),
            "--json",
            "--metrics=off",
            "--quiet",
            "--timeout",
            "30",
            ".",
        ]

    def version_from(self, payload: Any) -> str | None:
        if isinstance(payload, dict) and payload.get("version"):
            return str(payload["version"])
        return None

    @staticmethod
    def _rule_id(check_id: Any, metadata: Any, kinds: dict[str, str]) -> str | None:
        meta = metadata if isinstance(metadata, dict) else {}
        for key in ("aisg_rule_id", "aisg_rule"):
            value = meta.get(key)
            if value:
                return str(value).upper()
        kind = meta.get("kind")
        if kind and str(kind).lower() in kinds:
            return kinds[str(kind).lower()]
        text = str(check_id or "")
        match = _CHECK_ID_RULE_RE.search(text)
        if match:
            candidate = f"AUD-{match.group(1)}"
            if candidate in kinds.values():
                return candidate
        match = _CHECK_ID_KIND_RE.search(text)
        if match and match.group(1).lower() in kinds:
            return kinds[match.group(1).lower()]
        return None

    def parse(
        self, payload: Any, *, inputs: Sequence[str] = (), root: Path | str | None = None
    ) -> list[Finding]:
        if not isinstance(payload, dict):
            return []
        kinds = sink_rule_by_kind()
        out: list[Finding] = []
        for res in payload.get("results") or []:
            if not isinstance(res, dict):
                continue
            extra = res.get("extra") or {}
            check_id = str(res.get("check_id") or "")
            rule_id = self._rule_id(check_id, extra.get("metadata"), kinds)
            if rule_id is None:
                continue
            file = _relative(res.get("path") or "", root)
            start = res.get("start") or {}
            line = _int(start.get("line") if isinstance(start, dict) else None)
            lines = str(extra.get("lines") or "").strip()
            message = " ".join(str(extra.get("message") or "").split())
            out.append(
                tool_finding(
                    rule_id,
                    tool="semgrep",
                    file=file,
                    line=line,
                    snippet=lines or message or check_id,
                    notes=f"semgrep {check_id}: {message}" if message else f"semgrep {check_id}",
                )
            )
        return out


# ---------------------------------------------------------------------------
# Evals: promptfoo (only with --run-evals; it calls model providers)
# ---------------------------------------------------------------------------


class PromptfooAdapter(Adapter):
    name = "promptfoo"
    binary = "promptfoo"
    network = True
    needs_flag = "--run-evals"
    what = "eval results"
    rule_ids = ("AUD-902", "AUD-904")
    install_hint = "npm install -g promptfoo"
    output_to_file = True

    def inputs(self, ctx: AuditContext) -> tuple[str, ...]:
        return tuple(sorted(rel for rel in _relpaths(ctx) if _PROMPTFOO_CONFIG_RE.search(rel)))

    def applicable(self, ctx: AuditContext) -> bool:
        return bool(self.inputs(ctx))

    def arguments(self, ctx: AuditContext, *, timeout: float, report_path: str | None) -> list[str]:
        configs = self.inputs(ctx)
        config = configs[0] if configs else "promptfooconfig.yaml"
        output = report_path or os.path.join(tempfile.gettempdir(), "aisg-promptfoo-output.json")
        return ["eval", "-c", config, "-o", output, "--no-cache"]

    @staticmethod
    def _is_benign(case: dict[str, Any]) -> bool:
        test_case = case.get("testCase") or {}
        if not isinstance(test_case, dict):
            return False
        metadata = test_case.get("metadata") or {}
        if isinstance(metadata, dict):
            if metadata.get("benign") is True:
                return True
            for key in ("kind", "label", "category"):
                if str(metadata.get(key) or "").lower() in _BENIGN_LABELS:
                    return True
        asserts = [a for a in (test_case.get("assert") or []) if isinstance(a, dict)]
        if not asserts:
            return False
        for assertion in asserts:
            kind = str(assertion.get("type") or "").lower()
            if kind.startswith("not-") or kind in _NEGATIVE_ASSERT:
                return False
        return True

    def parse(
        self, payload: Any, *, inputs: Sequence[str] = (), root: Path | str | None = None
    ) -> list[Finding]:
        if not isinstance(payload, dict):
            return []
        body = payload.get("results") if isinstance(payload.get("results"), dict) else payload
        cases = [c for c in (body.get("results") or []) if isinstance(c, dict)]
        stats = body.get("stats") if isinstance(body.get("stats"), dict) else {}
        if stats:
            successes = _int(stats.get("successes"))
            failures = _int(stats.get("failures"))
            errors = _int(stats.get("errors"))
        else:
            errors = sum(1 for c in cases if c.get("error"))
            successes = sum(1 for c in cases if c.get("success") is True)
            failures = len(cases) - successes - errors
        total = successes + failures + errors
        config = _relative(inputs[0], root) if inputs else "promptfooconfig.yaml"
        out: list[Finding] = []
        if failures > 0 or errors > 0:
            extra: list[Evidence] = []
            for case in cases:
                if case.get("success") is True and not case.get("error"):
                    continue
                test_case = case.get("testCase") or {}
                description = str(test_case.get("description") or case.get("id") or "case")
                grading = case.get("gradingResult") or {}
                reason = str(grading.get("reason") or case.get("error") or "").strip()
                extra.append(
                    Evidence(
                        role="case",
                        file=config,
                        line=0,
                        snippet=f"{description}: {reason}" if reason else description,
                    )
                )
                if len(extra) >= 5:
                    break
            summary = (
                f"promptfoo: {successes} passed, {failures} failed, {errors} errored of {total}"
            )
            out.append(
                tool_finding(
                    "AUD-902",
                    tool="promptfoo",
                    file=config,
                    line=0,
                    snippet=summary,
                    severity=Severity.HIGH if failures > 0 else Severity.MEDIUM,
                    detail=f"promptfoo eval, {failures} failed, {errors} errored",
                    notes=f"promptfoo eval of {config}: {summary}",
                    sub="eval",
                    extra_evidence=extra,
                )
            )
        if cases and not any(self._is_benign(case) for case in cases):
            out.append(
                tool_finding(
                    "AUD-904",
                    tool="promptfoo",
                    file=config,
                    line=0,
                    snippet=(
                        f"promptfoo: {len(cases)} cases, none marked benign or asserting a "
                        "helpful answer"
                    ),
                    notes=f"promptfoo eval of {config}: no benign case among {len(cases)}",
                )
            )
        return out


# ---------------------------------------------------------------------------
# Registry and entry point
# ---------------------------------------------------------------------------

ADAPTERS: dict[str, Adapter] = {
    adapter.name: adapter
    for adapter in (
        GitleaksAdapter(),
        DetectSecretsAdapter(),
        PipAuditAdapter(),
        NpmAuditAdapter(),
        OsvScannerAdapter(),
        McpScanAdapter(),
        SemgrepAdapter(),
        PromptfooAdapter(),
    )
}

DEFAULT_TOOL_NAMES: tuple[str, ...] = tuple(ADAPTERS)


def run_adapters(
    ctx: AuditContext,
    names: Sequence[str] | None = None,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    no_external: bool = False,
) -> tuple[list[ExternalToolResult], list[Finding], list[UnknownItem]]:
    """Run the named adapters (all of them by default) and return what they produced.

    Every registered adapter gets a row: one the caller left out of `names` is
    `skipped_by_flag` (`--tools`) without an UnknownItem, since that was an explicit
    choice per tool. `no_external=True` marks every adapter `skipped_by_flag`
    (`--no-external`), starts no process, and records each as UNKNOWN: nothing was
    measured. The context is not mutated; the caller stores the results.
    """
    selected = list(DEFAULT_TOOL_NAMES) if names is None else [n.strip() for n in names if n]
    results: list[ExternalToolResult] = []
    findings: list[Finding] = []
    unknown: list[UnknownItem] = []
    for name in selected:
        if name not in ADAPTERS:
            unknown.append(
                UnknownItem(
                    category=UnknownCategory.TOOLS,
                    what=f"tool {name}",
                    why="no adapter with that name",
                    how_to_resolve=f"--tools accepts: {', '.join(DEFAULT_TOOL_NAMES)}",
                )
            )
    for name, adapter in ADAPTERS.items():
        network = adapter.network_for(ctx)
        if name not in selected:
            results.append(
                ExternalToolResult(
                    name=name, status=Status.SKIPPED_BY_FLAG, network=network, flag="--tools"
                )
            )
            continue
        if no_external:
            results.append(
                ExternalToolResult(
                    name=name, status=Status.SKIPPED_BY_FLAG, network=network, flag="--no-external"
                )
            )
            unknown.append(
                adapter.unknown(
                    f"{name} skipped by --no-external",
                    f"run without --no-external (and with {name} on PATH)",
                )
            )
            continue
        result, found, unk = adapter.run(ctx, timeout=timeout)
        results.append(result)
        findings.extend(found)
        unknown.extend(unk)
    return results, findings, unknown
