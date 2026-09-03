# aisg-audit: ignore-file
"""aisg/devtools/audit/rules/secrets_pii.py
------------------------------------------
P5 rules, AUD-501..505: secret literals in source, secrets in host / MCP config,
secrets bound into a prompt, verbatim prompt/response logging, and literal PII in
prompt templates, eval sets and committed logs.

Every snippet that reaches a Finding went through `Evidence`, which redacts; on
top of that, no rule here ever puts a matched value into a title, a note or a
sub-finding id. Grep hits from discovery are already masked at the source.
"""

from __future__ import annotations

import re
from typing import Any

from aisg.devtools.audit import patterns
from aisg.devtools.audit.model import (
    AuditContext,
    Basis,
    Evidence,
    EvidenceKind,
    Finding,
    Hit,
    MatchKind,
    Recommendation,
    Severity,
    Tier,
)
from aisg.devtools.audit.rules import AuditRule, file_text, hits_in

__all__ = [
    "RULES",
    "LiteralPii",
    "SecretInConfig",
    "SecretIntoPrompt",
    "SecretLiteral",
    "VerbatimLogging",
]

_SECRET_TABLES = ("secret", "secret_var")
_CONFIG_FILE_TABLE = list(patterns.MCP_CONFIG_FILES) + list(patterns.HOST_CONFIG_FILES)

# `env` keys in an MCP server block whose *name* says credential. Wider than
# SECRET_VAR_NAMES on purpose (`OPENAI_KEY`, `GH_TOKEN`); SECRET_VAR_EXCLUDE still vetoes.
_ENV_SECRET_NAME_RE = re.compile(r"(?i)(?:key|token|secret|passw(?:or)?d|credential|auth)")

# Inline secret sources on a prompt-assembly line: an environment read whose key
# names a credential, or a secrets-manager call.
_ENV_READ_RE = re.compile(
    r"""(?:os\.environ(?:\.get)?|getenv|os\.getenv)\s*[\[(]\s*["']([A-Za-z_][A-Za-z0-9_]*)["']"""
)
_SECRETS_MANAGER_RE = re.compile(
    r"\b(?:get_secret_value|access_secret_version|SecretClient|secretsmanager|"
    r"secretmanager|hvac\.Client|vault\.(?:read|kv)|get_secret)\b"
)
# The `{name` of an f-string / template literal placeholder, or the `+ name` of a concat.
_BRACE_NAME_RE = re.compile(r"[{$]\{?\s*([A-Za-z_][A-Za-z0-9_]*)")
_CONCAT_NAME_RE = re.compile(r"\+\s*([A-Za-z_][A-Za-z0-9_]*)\b")

# AUD-504: a logging / print call and the names that make its argument verbatim.
_LOG_CALL_RE = re.compile(
    r"(?<![\w.])(?:print|pprint|console\.(?:log|info|debug|warn|error)"
    r"|(?:self\.)?(?:logger|logging|log|LOG|_log|_logger)"
    r"\.(?:debug|info|warning|warn|error|exception|critical))\s*\((?P<arg>[^\n]*)"
)
_VERBATIM_NAMES = (
    r"(?:prompt|system_prompt|user_prompt|full_prompt|final_prompt|response|completion"
    r"|messages|chat_history|llm_output|model_output|raw_response|reply)"
)
_VERBATIM_ARG_RES = (
    # f"...{response}..." / `...${response}...`
    re.compile(r"[{$]\{?\s*" + _VERBATIM_NAMES + r"\b"),
    # print(response) / print(response.content) / console.log(completion)
    re.compile(
        r"^\s*" + _VERBATIM_NAMES + r"(?:\.(?:content|text|choices|message|output_text))*\s*[,)]"
    ),
    # "..." % response / "..." % (prompt, response)
    re.compile(r"%\s*\(?\s*" + _VERBATIM_NAMES + r"\b"),
    # logger.info("got %s", response)
    re.compile(r",\s*" + _VERBATIM_NAMES + r"\s*[,)]"),
    # "...".format(response) / logger.info("event", response=response)
    re.compile(r"(?:\bformat\(|=)\s*" + _VERBATIM_NAMES + r"\s*[,)]"),
)
_COMMENT_RE = re.compile(r"^\s*(?:#|//|\*|/\*)")
_REDACTION_RE = re.compile(
    r"(?i)\b(?:PIIDetector|PIIRestorer|presidio|redact\w*|scrub\w*|anonymi[sz]\w*"
    r"|pseudonymi[sz]\w*|mask_(?:pii|secret|sensitive|token|email|phone)\w*|pii_mask\w*)\b"
)
_LOGGING_LANGS = frozenset({"python", "typescript"})


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (
            f.evidence[0].file if f.evidence else "",
            f.evidence[0].line if f.evidence else 0,
            f.sub or "",
        ),
    )


def _record_for(ctx: AuditContext, relpath: str) -> Any | None:
    for record in ctx.files:
        if getattr(record, "relpath", None) == relpath:
            return record
    return None


def _is_config_path(relpath: str) -> bool:
    return any(rx.search(relpath) for _key, rx in _CONFIG_FILE_TABLE)


def _secret_hits(ctx: AuditContext, *, config_files: bool) -> list[Hit]:
    """One hit per (file, line): a pattern hit wins over a name-based one.

    `config_files=True` keeps only MCP / host config paths (AUD-502), False keeps
    everything else (AUD-501), so a line is reported by exactly one of the two.
    """
    chosen: dict[tuple[str, int], Hit] = {}
    for table in _SECRET_TABLES:
        for hit in hits_in(ctx, table):
            if _is_config_path(hit.file) != config_files:
                continue
            stamp = (hit.file, hit.line)
            if stamp not in chosen:
                chosen[stamp] = hit
    return [chosen[k] for k in sorted(chosen)]


def _secret_name(name: str) -> bool:
    return bool(
        patterns.SECRET_VAR_NAMES.search(name) and not patterns.SECRET_VAR_EXCLUDE.search(name)
    )


def _line_text(ctx: AuditContext, relpath: str, line: int) -> str | None:
    text = file_text(ctx, relpath)
    if text is None or line < 1:
        return None
    lines = text.split("\n")
    if line > len(lines):
        return None
    return lines[line - 1].rstrip("\r")


def _unit_ai_surface(ctx: AuditContext, unit_id: str | None) -> bool:
    if unit_id is None:
        return False
    for unit in ctx.inventory.units:
        if unit.id == unit_id:
            return bool(unit.ai_surface)
    return False


# ---------------------------------------------------------------------------
# AUD-501
# ---------------------------------------------------------------------------


class SecretLiteral(AuditRule):
    """A credential-shaped literal in a source or config file.

    Sources: the `secret` table (SECRET_PATTERNS prefixes, value masked by
    discovery) and the `secret_var` table (an assignment whose name matches
    SECRET_VAR_NAMES). Files that AUD-502 owns (MCP / host configs) are left to it.
    Gitignored `.env*` files are still reported, with `gitignored` set from the walk.
    """

    id = "AUD-501"
    title = "Secret literal in source"
    priority = 5
    severity = Severity.CRITICAL
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    tier = Tier.T1
    controls = ("ASI03", "LLM02", "EU:Art.15", "NIST:MEASURE-2.7", "NIST:GOVERN-6.1")
    related_lint_rules = ("EU-AIA-015c",)
    known_failure_modes = (
        "prefix patterns only: a random 32-char token with no vendor prefix is missed",
        "name-based hits key off the variable name; a secret bound to a neutral name is missed",
        "no gitleaks / detect-secrets corroboration in-process: bucket stays asserted",
        "an example file is recognised by suffix (.example/.sample/.template/.dist), not by content",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Move the value to the environment or a secrets manager, rotate it, and add a "
            "pre-commit secret scanner so the next one never lands."
        ),
        alternatives=(
            "gitleaks or detect-secrets as a pre-commit hook and in CI",
            "a secrets manager (AWS Secrets Manager, Vault, Doppler) read at start-up",
            "aisg audit in CI with --fail-on critical to block the merge",
            "git-filter-repo to purge the value from history after rotation",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        out: list[Finding] = []
        for hit in _secret_hits(ctx, config_files=False):
            if hit.table == "secret":
                sub, note = hit.key, f"pattern: {hit.key}"
            else:
                sub, note = "assignment", f"variable name matches SECRET_VAR_NAMES: {hit.key}"
            finding = self.finding(
                file=hit.file,
                line=hit.line,
                snippet=hit.snippet,
                sub=sub,
                notes=note,
                evidence_kind=(EvidenceKind.CONFIG if hit.lang == "config" else EvidenceKind.CODE),
            )
            record = _record_for(ctx, hit.file)
            finding.gitignored = bool(getattr(record, "gitignored", False))
            out.append(finding)
        return _sorted(out)


# ---------------------------------------------------------------------------
# AUD-502
# ---------------------------------------------------------------------------


class SecretInConfig(AuditRule):
    """A secret literal inside an MCP or host configuration file.

    Two sources: grep secret hits whose path is an MCP_CONFIG_FILES /
    HOST_CONFIG_FILES match, and `McpServer.env_literal_keys` (key names whose value
    is a literal rather than a `${...}` reference). Only key names are reported.
    """

    id = "AUD-502"
    title = "Secret in MCP / host config"
    priority = 5
    severity = Severity.CRITICAL
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CONFIG
    match_kind = MatchKind.STRUCTURED
    tier = Tier.T1
    controls = ("ASI03", "ASI04", "LLM02", "EU:Art.15", "NIST:MEASURE-2.7", "NIST:GOVERN-6.1")
    related_lint_rules = ("EU-AIA-015c",)
    known_failure_modes = (
        "env key names are classified by name; a credential under a neutral key is missed",
        "a user-level host config outside the repo is only read with --include-home",
        "no mcp-scan / gitleaks corroboration in-process: bucket stays asserted",
    )
    recommendation = Recommendation(
        tier=Tier.T1,
        summary=(
            "Reference the variable (`${VAR}`) or a keychain entry in the config and keep the "
            "value in the environment; rotate the value that was committed."
        ),
        alternatives=(
            "`${ENV_VAR}` references in .mcp.json / mcp.json (all major hosts expand them)",
            "1Password / keychain-backed `op run` or `envchain` wrappers around the host",
            "aisg audit in CI with --fail-on critical",
            "gitleaks with a custom rule for MCP config paths",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        for hit in _secret_hits(ctx, config_files=True):
            seen.add((hit.file, hit.line))
            sub = hit.key if hit.table == "secret" else "assignment"
            out.append(
                self.finding(
                    file=hit.file,
                    line=hit.line,
                    snippet=hit.snippet,
                    sub=sub,
                    notes=f"pattern: {hit.key}" if hit.table == "secret" else None,
                    match_kind=MatchKind.GREP,
                )
            )
        servers = getattr(ctx.config_facts, "servers", None) or []
        seen_keys: set[tuple[str, int, str]] = set()
        for server in servers:
            for key in getattr(server, "env_literal_keys", ()) or ():
                if not _ENV_SECRET_NAME_RE.search(key) or patterns.SECRET_VAR_EXCLUDE.search(key):
                    continue
                relpath = str(server.file).replace("\\", "/")
                line = _key_line(ctx, relpath, key) or int(server.line or 0)
                # A grep secret hit on the same line already reports it, masked.
                if (relpath, line) in seen or (relpath, line, key) in seen_keys:
                    continue
                seen_keys.add((relpath, line, key))
                out.append(
                    self.finding(
                        file=relpath,
                        line=line,
                        snippet=f'"{key}": <literal> (env of MCP server "{server.name}")',
                        sub="env",
                        notes=(
                            f"env key {key} of server {server.name} carries a literal value "
                            "rather than a ${...} reference"
                        ),
                    )
                )
        return _sorted(out)


def _key_line(ctx: AuditContext, relpath: str, key: str) -> int | None:
    text = file_text(ctx, relpath)
    if text is None:
        return None
    needle = re.compile(r"""["']?""" + re.escape(key) + r"""["']?\s*[:=]""")
    for number, line in enumerate(text.split("\n"), 1):
        if needle.search(line):
            return number
    return None


# ---------------------------------------------------------------------------
# AUD-503
# ---------------------------------------------------------------------------


class SecretIntoPrompt(AuditRule):
    """A prompt assembly whose input is a credential.

    Deep tier (`ctx.pyfacts`): `Assembly.source_names` matched against
    SECRET_VAR_NAMES minus SECRET_VAR_EXCLUDE, plus an inline `os.environ[...]` /
    `getenv(...)` read with a credential-shaped key or a secrets-manager call on the
    assembly line. Grep tier: the same name test on `prompt_assembly` hits, used for
    non-Python files and, when no deep facts exist, for Python too. A Python file is
    never reported by both tiers.
    """

    id = "AUD-503"
    title = "Secret or PII bound into a prompt"
    priority = 5
    severity = Severity.HIGH
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.AST
    requires_ai_surface = True
    tier = Tier.T2
    controls = ("ASI03", "LLM02", "LLM07", "EU:Art.10", "EU:Art.15", "NIST:MEASURE-2.7")
    related_lint_rules = ("EU-AIA-015c", "EU-GDPR-001")
    known_failure_modes = (
        "name-based: a credential bound under a neutral name is missed",
        "grep tier sees one line; an assembly split across lines is partly seen",
        "a template variable named `password` that carries a placeholder still fires",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Keep credentials out of model context: pass them to the tool at call time, "
            "never into the prompt, and tokenise PII before assembly."
        ),
        alternatives=(
            'aisg PIIDetector(action="tokenize") before assembly and PIIRestorer after',
            "Microsoft Presidio anonymizer on the assembled prompt",
            "a tool-side credential injection layer (the model sees a handle, not the value)",
            "LLM Guard Secrets scanner on the input side",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        assemblies = getattr(ctx.pyfacts, "prompt_assemblies", None) if ctx.pyfacts else None
        for assembly in assemblies or []:
            relpath = str(assembly.file).replace("\\", "/")
            names = [n for n in assembly.source_names if _secret_name(n)]
            line_text = _line_text(ctx, relpath, assembly.line) or ""
            inline = _inline_sources(line_text)
            if not names and not inline:
                continue
            stamp = (relpath, int(assembly.line))
            if stamp in seen:
                continue
            seen.add(stamp)
            out.append(
                self.finding(
                    file=relpath,
                    line=assembly.line,
                    snippet=line_text or f"{assembly.kind} assembly",
                    sub=assembly.kind,
                    notes=_notes(names, inline, system=assembly.is_system),
                )
            )
        for hit in hits_in(ctx, "prompt_assembly"):
            if ctx.pyfacts is not None and hit.lang == "python":
                continue
            stamp = (hit.file, hit.line)
            if stamp in seen:
                continue
            line_text = _line_text(ctx, hit.file, hit.line) or hit.snippet
            names = sorted({n for n in _placeholder_names(line_text) if _secret_name(n)})
            inline = _inline_sources(line_text)
            if not names and not inline:
                continue
            seen.add(stamp)
            out.append(
                self.finding(
                    file=hit.file,
                    line=hit.line,
                    snippet=line_text,
                    sub=hit.key,
                    notes=_notes(names, inline, system=hit.key == "system_role"),
                    match_kind=MatchKind.GREP,
                )
            )
        return _sorted(out)


def _placeholder_names(line: str) -> list[str]:
    names = [m.group(1) for m in _BRACE_NAME_RE.finditer(line)]
    names.extend(m.group(1) for m in _CONCAT_NAME_RE.finditer(line))
    return names


def _inline_sources(line: str) -> list[str]:
    """Environment reads with a credential-shaped key, and secrets-manager calls."""
    found: list[str] = []
    for match in _ENV_READ_RE.finditer(line):
        if _secret_name(match.group(1)):
            found.append(f"environment read of {match.group(1)}")
    if _SECRETS_MANAGER_RE.search(line):
        found.append("secrets-manager call")
    return found


def _notes(names: list[str], inline: list[str], *, system: bool) -> str:
    parts: list[str] = []
    if names:
        parts.append("credential-shaped names bound: " + ", ".join(names))
    parts.extend(inline)
    if system:
        parts.append("assembled into the system prompt")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# AUD-504
# ---------------------------------------------------------------------------


class VerbatimLogging(AuditRule):
    """A logging or print call whose argument is the raw prompt, messages or response.

    Grep over the Python / TypeScript files of AI-surface units; a line is a hit
    when a logging call's argument names a prompt / response variable directly,
    in a placeholder, or as a format argument. A redaction symbol anywhere in the
    same file, or a Presidio guardrail hit in the same unit, suppresses the file.
    """

    id = "AUD-504"
    title = "Verbatim prompt/response logging"
    priority = 5
    severity = Severity.MEDIUM
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    requires_ai_surface = True
    tier = Tier.T2
    controls = ("LLM02", "EU:Art.10", "EU:Art.12", "NIST:MEASURE-2.10", "NIST:GOVERN-1.6")
    related_lint_rules = ("EU-AIA-012a", "EU-GDPR-001")
    known_failure_modes = (
        "name-based: a response held in a variable called `r` is missed",
        "a redaction symbol in the file suppresses every call in it, applied or not",
        "structured logging (`logger.info(event, response=...)`) is only seen as a kwarg",
        "single-line only: a call whose argument sits on the next line is missed",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Log a hash, length or tokenised form; route prompts and responses through a "
            "PII redactor before any sink, and keep the raw text in a purpose-bound store."
        ),
        alternatives=(
            'aisg PIIDetector(action="redact") in front of the logger',
            "Microsoft Presidio anonymizer as a logging filter",
            "LLM observability with content redaction (Langfuse / Arize masking hooks)",
            "structlog processor that drops prompt / response keys",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        out: list[Finding] = []
        presidio_units = {
            hit.unit for hit in hits_in(ctx, "guardrail") if hit.key == "presidio" and hit.unit
        }
        for record in ctx.files:
            lang = getattr(record, "lang", None)
            relpath = getattr(record, "relpath", None)
            if lang not in _LOGGING_LANGS or relpath is None:
                continue
            unit_id = getattr(record, "unit", None)
            if not _unit_ai_surface(ctx, unit_id) or unit_id in presidio_units:
                continue
            text = file_text(ctx, relpath)
            if text is None or _REDACTION_RE.search(text):
                continue
            for number, line in enumerate(text.split("\n"), 1):
                if _COMMENT_RE.match(line):
                    continue
                match = _LOG_CALL_RE.search(line)
                if match is None:
                    continue
                name = _verbatim_name(match.group("arg"))
                if name is None:
                    continue
                out.append(
                    self.finding(
                        file=relpath,
                        line=number,
                        snippet=line.rstrip("\r"),
                        sub="print" if match.group(0).lstrip().startswith("print") else "logger",
                        notes=f"logs `{name}` with no redaction symbol in {relpath}",
                    )
                )
        return _sorted(out)


def _verbatim_name(arg: str) -> str | None:
    for rx in _VERBATIM_ARG_RES:
        match = rx.search(arg)
        if match is not None:
            inner = re.search(_VERBATIM_NAMES, match.group(0))
            return inner.group(0) if inner else match.group(0).strip()
    return None


# ---------------------------------------------------------------------------
# AUD-505
# ---------------------------------------------------------------------------


def _mask_all_pii(snippet: str) -> str:
    """Mask every PII entity in a snippet, not just the one discovery matched."""
    for entity, rx in patterns.PII_TABLE:
        try:
            snippet = rx.sub(f"<pii:{entity}>", snippet)
        except (re.error, TypeError):
            continue
    return snippet


class LiteralPii(AuditRule):
    """A PII-shaped value in a prompt template, eval set or committed log.

    Reads the `pii` table, which discovery only fills for PII_FILE_GLOBS paths and
    already masks as `<pii:ENTITY>`; placeholder values never reach it. One
    finding per (file, line, entity).
    """

    id = "AUD-505"
    title = "Literal PII in prompts / fixtures / logs"
    priority = 5
    severity = Severity.LOW
    basis = Basis.PRESENCE
    evidence_kind = EvidenceKind.CODE
    match_kind = MatchKind.GREP
    tier = Tier.T2
    controls = ("LLM02", "EU:Art.10", "NIST:MEASURE-2.10", "NIST:MAP-4.1")
    related_lint_rules = ("EU-GDPR-001", "ALIGN-007")
    known_failure_modes = (
        "regex entities only (email, phone, SSN, card, IBAN, IP, DOB); names and addresses are missed",
        "PHONE_US matches many 10-digit numbers; an id or a timestamp can fire it",
        "only PII_FILE_GLOBS paths are scanned; PII in a .py string literal is out of scope here",
        "placeholder detection is a fixed list; an unlisted synthetic value still fires",
    )
    recommendation = Recommendation(
        tier=Tier.T2,
        summary=(
            "Replace real values with documented placeholders (example.com addresses, "
            "555-01xx numbers, RFC 5737 IPs) and generate eval data synthetically."
        ),
        alternatives=(
            "aisg PIIDetector over the corpus before commit",
            "Microsoft Presidio to anonymise eval sets and log samples",
            "Faker-generated fixtures with a seed checked into the repo",
            "a pre-commit hook that rejects PII_PATTERNS matches under prompts/ and evals/",
        ),
    )

    def evaluate(self, ctx: AuditContext) -> list[Finding]:
        out: list[Finding] = []
        seen: set[tuple[str, int, str]] = set()
        for hit in hits_in(ctx, "pii"):
            entity = hit.key.lower()
            stamp = (hit.file, hit.line, entity)
            if stamp in seen:
                continue
            seen.add(stamp)
            record = _record_for(ctx, hit.file)
            # Discovery masks only the entity it matched; a second value on the
            # same line (card next to an IP) would otherwise leak through.
            snippet = _mask_all_pii(hit.snippet)
            finding = self.finding(
                file=hit.file,
                line=hit.line,
                snippet=snippet,
                sub=entity,
                notes=f"entity: {hit.key}",
                evidence=[Evidence(role="match", file=hit.file, line=hit.line, snippet=snippet)],
            )
            finding.gitignored = bool(getattr(record, "gitignored", False))
            out.append(finding)
        return _sorted(out)


RULES = [SecretLiteral, SecretInConfig, SecretIntoPrompt, VerbatimLogging, LiteralPii]
