# aisg-audit: ignore-file
"""aisg/devtools/audit/vocab.py
----------------------------
Capability classification of tools, approval/bypass symbols, MCP implied legs.

Two kinds of table live here, and consumers must treat them differently:

* ``tuple[str, ...]`` of lowercase tokens (``*_SYMBOLS``, ``INERT_KILL_SWITCH``):
  compare against ``identifier.lower()`` at AST depth, or compile as
  ``\\b(?:a|b|c)\\b`` with ``re.I`` for grep depth. Tokens, never substrings.
* compiled ``re.Pattern`` (``*_CAPABILITY``, ``APPROVAL_SYMBOLS``, ``GATE_BYPASS``,
  ``KILL_SWITCH_ENV_READS``): ``.search()`` the text; ``group(0)`` is the evidence.

The first line of this file is the audit's ignore marker so the walker never
matches the audit against its own vocabulary. Nothing here measures anything:
these lists decide what a rule *looks at*; precision stays UNMEASURED.
"""

from __future__ import annotations

import re

from aisg.modules.processing.llm_tool_filter import LLMToolFilter
from aisg.modules.processing.tool_policy import TOOL_RISK_TIERS

# --------------------------------------------------------------------------- #
# Capability regexes (applied to a tool's name + first 30 lines of body)
# --------------------------------------------------------------------------- #

# Actions with no undo. Excludes read/get/list/search/query: reads are not irreversible.
IRREVERSIBLE_CAPABILITY = re.compile(
    r"\b(?:send|email|mail|sms|post|publish|tweet|deploy|delete|drop|truncate|destroy|remove"
    r"|purge|pay|charge|refund|transfer|wire|withdraw|release|merge|force[-_ ]?push"
    r"|kubectl\s+delete|terraform\s+apply|rm\s+-rf)\b",
    re.I,
)

# Pulls untrusted content off the network. Excludes bare `get`/`load`/`read`: a
# database read is private, not untrusted, and `fetchall()` is a cursor, not the web.
FETCH_CAPABILITY = re.compile(
    r"\b(?:fetch|browse|crawl|scrape|http_get|requests\.get|httpx\.get|web_search|open_url"
    r"|navigate|playwright|puppeteer)\b",
    re.I,
)

# Runs code or a shell. Excludes `compile`/`import`/`run` alone (`re.compile`, `run(` on
# every agent object) and `evaluate` (`\beval\b` does not match it).
EXEC_CAPABILITY = re.compile(
    r"\b(?:subprocess|os\.system|os\.popen|child_process|exec\.Command|shell|bash|run_command"
    r"|execute_code|python_repl|code_interpreter|eval)\b",
    re.I,
)

# --------------------------------------------------------------------------- #
# Gate / bypass / cap / isolation vocabularies
# --------------------------------------------------------------------------- #

# A human (or a policy) sits between the tool and the action. Mixed-case entries are
# spelled exactly (no re.I). `input(` counts only when its prompt text asks for a
# confirmation: a bare `input(` matches every CLI in the unit and would silently
# mark every irreversible tool as gated.
APPROVAL_SYMBOLS = re.compile(
    r"(?:\brequire_approval\b|\bapproval_callback\b|\bhuman_in_the_loop\b|\bHumanInTheLoop\b"
    r"|\binterrupt_before\b|\binterrupt_after\b|\bconfirm\(|\bask_user\b|\brequest_confirmation\b"
    r"|\bToolPolicyGuard\b|\bneeds_approval\b|\bapprove\(|\bCommand\(\s*resume|\bHITL\b"
    r"|\bpause_for_approval\b"
    r"|\binput\(\s*f?[\"'][^\"'\n]*(?i:confirm|approve|proceed|continue|y/n|yes)[^\"'\n]*[\"'])"
)

# Literals that switch a gate off. `-y` only counts beside a destructive CLI (`rm`,
# package managers, `kubectl`, `terraform`, `gh`, `az`, `aws`, `gcloud`, `docker`):
# a bare `-y` is `npx -y`, which is supply chain (AUD-602), not gate bypass.
GATE_BYPASS = re.compile(
    r"(?:\bauto_?[aA]pprove\s*[:=]\s*[Tt]rue|\brequire_approval\s*[:=]\s*[Ff]alse"
    r"|\bhuman_in_the_loop\s*[:=]\s*[Ff]alse|\bconfirm\s*[:=]\s*[Ff]alse"
    r"|\bapproval_callback\s*[:=]\s*(?:None|null|undefined)\b|\bskip_confirmation\b|--yes\b"
    r"|\b(?:rm|apt(?:-get)?|yum|dnf|kubectl|terraform|gh|az|aws|gcloud|docker)\b[^\n|;&]*\s-y\b)"
)

# Names that bound an agent loop (AUD-102). Excludes bare counters (`i`, `n`, `count`,
# `limit`): a counter compared inside the loop body is a known miss, not a symbol.
LOOP_CAP_SYMBOLS: tuple[str, ...] = (
    "max_iter",
    "max_iterations",
    "max_steps",
    "max_turns",
    "max_rounds",
    "recursion_limit",
    "max_tool_calls",
    "budget",
    "deadline",
    "timeout",
    "step_limit",
)

# Isolation for an exec tool (AUD-104). Excludes `chroot`, `venv`, `virtualenv`, `container`
# alone: an environment is not a sandbox.
SANDBOX_SYMBOLS: tuple[str, ...] = (
    "firejail",
    "bubblewrap",
    "bwrap",
    "nsjail",
    "gvisor",
    "runsc",
    "seccomp",
    "docker",
    "e2b",
    "modal",
    "sandbox",
)

# URL / host allowlist for a fetch tool (AUD-103). Excludes `blocklist`/`denylist`/
# `blacklist`: a denylist does not bound where a fetch tool may go.
ALLOWLIST_SYMBOLS: tuple[str, ...] = (
    "allowlist",
    "allow_list",
    "allowed_domains",
    "allowed_hosts",
    "allow_hosts",
    "url_allow",
    "is_allowed_url",
    "validate_url",
)

# Prompt-injection sanitisers on the ingress-to-prompt path (AUD-302). Excludes bare
# `strip`/`clean`/`escape` and sink-specific escapes (`html.escape`, `shlex.quote`): those
# protect a sink, not the prompt, and the taint layer handles them per sink.
SANITISER_SYMBOLS: tuple[str, ...] = (
    "promptinjectionguard",
    "sanitize",
    "sanitise",
    "escape_prompt",
    "delimit",
    "spotlight",
    "llm_guard",
    "rebuff",
    "lakera",
)

# Runtime kill-switch identifiers (AUD-107); must be *read* to count. `halt` and
# `feature_flag` are deliberately absent: they match every CLI and every LaunchDarkly call.
KILL_SWITCH_SYMBOLS: tuple[str, ...] = (
    "kill_switch",
    "circuit_breaker",
    "emergency_stop",
    "pause_agent",
    "agent_disabled",
)

_KILL_SWITCH_ENV_NAMES = r"(?:AGENT_DISABLED|KILL_SWITCH|EMERGENCY_STOP|PAUSE_AGENT)"

# Kill-switch reads at runtime, one regex per idiom. None of them match a bare
# assignment (`AGENT_DISABLED = False`) or a Settings field declaration.
KILL_SWITCH_ENV_READS: tuple[re.Pattern[str], ...] = (
    # os.environ.get("AGENT_DISABLED")  /  os.environ["KILL_SWITCH"]
    re.compile(r"\bos\.environ(?:\.get)?\s*[\[(]\s*[\"']" + _KILL_SWITCH_ENV_NAMES + r"\b"),
    # os.getenv("AGENT_DISABLED")  /  getenv("KILL_SWITCH")
    re.compile(r"\bgetenv\(\s*[\"']" + _KILL_SWITCH_ENV_NAMES + r"\b"),
    # process.env.AGENT_DISABLED  /  process.env["AGENT_DISABLED"]
    re.compile(r"\bprocess\.env(?:\.|\s*\[\s*[\"'])" + _KILL_SWITCH_ENV_NAMES + r"\b"),
    # os.Getenv("AGENT_DISABLED")  (Go)
    re.compile(r"\bos\.Getenv\(\s*\"" + _KILL_SWITCH_ENV_NAMES + r"\b"),
    # settings.kill_switch  /  settings.agent_disabled  (a read; `settings.x = ...` excluded)
    re.compile(r"\bsettings\.(?:kill_switch|agent_disabled)\b(?!\s*=[^=])"),
)

# This package declares GUARDRAILS_DISABLE_ALL in `Settings` and documents it in
# `.env.example`, but nothing in `core/` or `modules/` reads it (CLAUDE.md: inert).
# A target that declares it has not got a kill switch; it gets `AUD-107/inert`.
INERT_KILL_SWITCH: tuple[str, ...] = ("GUARDRAILS_DISABLE_ALL",)

# Per-session tool budgets (AUD-105). Excludes `timeout` and `max_tokens`: a per-request
# cap is not a per-session budget.
BUDGET_SYMBOLS: tuple[str, ...] = (
    "max_tool_calls",
    "tool_budget",
    "session_budget",
    "max_calls_per_session",
    "_tool_session_counters",
    "rate_limit",
)

# --------------------------------------------------------------------------- #
# MCP servers: trifecta legs implied by package / server name (substring, lowercase)
# --------------------------------------------------------------------------- #

# Substring of the package or server name -> legs it contributes. A name matching no key
# is the consumer's call (the design says: untrusted only). Bare `git` is absent on
# purpose: it is a substring of `github`, whose legs differ. Values may overstate: a
# read-only filesystem server still gets `external_action`.
MCP_IMPLIED_LEGS: dict[str, tuple[str, ...]] = {
    "filesystem": ("private", "external_action"),
    "fetch": ("untrusted",),
    "puppeteer": ("untrusted",),
    "playwright": ("untrusted",),
    "browser": ("untrusted",),
    "search": ("untrusted",),
    "gmail": ("private", "external_action"),
    "mail": ("private", "external_action"),
    "slack": ("private", "external_action"),
    "discord": ("private", "external_action"),
    "telegram": ("private", "external_action"),
    "github": ("untrusted", "external_action"),
    "gitlab": ("untrusted", "external_action"),
    "postgres": ("private", "external_action"),
    "mysql": ("private", "external_action"),
    "sqlite": ("private", "external_action"),
    "mongodb": ("private", "external_action"),
    "redis": ("private", "external_action"),
    "supabase": ("private", "external_action"),
    "drive": ("private", "external_action"),
    "dropbox": ("private", "external_action"),
    "notion": ("private", "external_action"),
    "jira": ("private", "external_action"),
    "linear": ("private", "external_action"),
    "confluence": ("private", "external_action"),
    "calendar": ("private", "external_action"),
    "memory": ("private",),
    "sentry": ("private",),
    "shell": ("external_action",),
    "exec": ("external_action",),
    "docker": ("external_action",),
    "kubernetes": ("external_action",),
    "terraform": ("external_action",),
    "aws": ("private", "external_action"),
    "sequential-thinking": (),
    "server-time": (),
}

# --------------------------------------------------------------------------- #
# Tool names this package already treats as high risk
# --------------------------------------------------------------------------- #

# Both class attributes are read by name so a rename in llm_tool_filter.py breaks this
# import instead of silently shrinking the set.
HIGH_RISK_TOOL_NAMES: frozenset[str] = (
    frozenset(LLMToolFilter.DEFAULT_HIGH_RISK_TOOLS)
    | frozenset(LLMToolFilter.DEFAULT_HIGH_RISK_FAIL_CLOSED)
    | frozenset(name for name, tier in TOOL_RISK_TIERS.items() if tier in ("high", "critical"))
)

# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #

_CAPABILITY_LABELS: frozenset[str] = frozenset(
    {
        "external_action",
        "irreversible",
        "fetch",
        "exec",
        "private_read",
        "fs_write",
        "db_write",
        "payment",
        "deploy",
        "email",
        "chat",
        "git",
    }
)

_BODY_LINES = 30

# Domain labels, each a token regex over the raw text plus its tokenised form. Every entry
# is a whole token; `.execute(` and the SDK module names only occur in raw source. Bare
# `write`, `save`, `push`, `merge`, `transfer` are excluded: they name too many benign tools.
_LABEL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b(?:email|mail|smtp|sendmail|sendgrid|mailgun|imap|gmail)\b", re.I)),
    (
        "chat",
        re.compile(
            r"\b(?:slack|discord|telegram|whatsapp|sms|twilio|post_message|chat_post_message"
            r"|chat_postmessage)\b",
            re.I,
        ),
    ),
    (
        "payment",
        re.compile(
            r"\b(?:pay|payment|charge|refund|stripe|paypal|braintree|invoice|billing|checkout"
            r"|wire_transfer|transfer_funds|transfer_money|withdraw)\b",
            re.I,
        ),
    ),
    ("deploy", re.compile(r"\b(?:deploy|kubectl|terraform|pulumi|helm|rollout)\b", re.I)),
    ("git", re.compile(r"\b(?:git|force_push|force-push|pull_request|gh)\b", re.I)),
    (
        "db_write",
        re.compile(
            r"\b(?:insert|upsert|update|delete|drop|truncate|database_write|db_write"
            r"|insert_one|update_one|delete_one|insert_many|delete_many)\b|\.execute\(",
            re.I,
        ),
    ),
    (
        "fs_write",
        re.compile(
            r"\b(?:write_file|write_text|write_bytes|writefile|save_file|unlink|rmtree|rename"
            r"|mkdir|shutil)\b|\bfs\.write|\bos\.remove\(",
            re.I,
        ),
    ),
    (
        "private_read",
        re.compile(
            r"\b(?:read_file|read_email|read_document|database_query|sql_query|retrieve"
            r"|retrieve_document|secret|secrets|secretsmanager|credential|credentials|environ"
            r"|getenv|dotenv|vault|imaplib|psycopg2|psycopg|asyncpg|pymysql|sqlite3|sqlalchemy"
            r"|pymongo|chromadb|pinecone|weaviate|qdrant|faiss|pgvector|calendar|contacts|crm"
            r"|salesforce|hubspot)\b|\bopen\(|\.read_text\(|\.read_bytes\(",
            re.I,
        ),
    ),
)

# Domains that are an outbound side effect on their own; `fetch` and `private_read` are not.
_EXTERNAL_ACTION_LABELS = frozenset(
    {"irreversible", "exec", "email", "chat", "payment", "deploy", "git", "db_write", "fs_write"}
)

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_TOKEN_SEPARATORS = re.compile(r"[_\-./:]+")


def _tokenised(text: str) -> str:
    """`sendEmail` -> `send Email`, `send_email` -> `send email`, `os.system` -> `os system`."""
    return _TOKEN_SEPARATORS.sub(" ", _CAMEL_BOUNDARY.sub(" ", text))


def _search_text(name: str, body: str) -> str:
    """Name plus the first 30 body lines, followed by the same text split into tokens.

    Regexes run over both forms: `\\bsend\\b` needs the tokenised `send email`, while
    `os\\.system` and `rm\\s+-rf` only exist in the raw source.
    """
    raw = name + "\n" + "\n".join(body.splitlines()[:_BODY_LINES])
    return raw + "\n" + _tokenised(raw)


def classify_tool(name: str, body: str = "") -> set[str]:
    """Capability labels for a tool, from its name tokens and body symbols.

    Token matching, not substring: `send_email` is email + external_action + irreversible,
    `get_weather` is nothing, `fetch_url` is fetch, `run_shell` (or a body that calls
    `subprocess`) is exec. Only the first 30 lines of `body` are read. Labels are drawn
    from external_action, irreversible, fetch, exec, private_read, fs_write, db_write,
    payment, deploy, email, chat, git. The result is a heuristic; its precision is
    UNMEASURED.
    """
    text = _search_text(name, body)
    caps: set[str] = set()
    if IRREVERSIBLE_CAPABILITY.search(text):
        caps.add("irreversible")
    if FETCH_CAPABILITY.search(text):
        caps.add("fetch")
    if EXEC_CAPABILITY.search(text):
        caps.add("exec")
    for label, pattern in _LABEL_PATTERNS:
        if pattern.search(text):
            caps.add(label)
    if caps & _EXTERNAL_ACTION_LABELS:
        caps.add("external_action")
    return caps


def risk_tier_for(name: str) -> str:
    """Risk tier for a tool name: `critical`, `high`, `medium` or `low`.

    Order of authority: `TOOL_RISK_TIERS` (this package's shipped table), then
    `HIGH_RISK_TOOL_NAMES` (-> `high`), then `classify_tool` heuristics, else `low`.
    The heuristic step mirrors the shipped table: shell/deploy are critical; irreversible,
    payment, email, database writes and git actions are high; other side effects and
    network fetches are medium.
    """
    key = name.strip().lower()
    tier = TOOL_RISK_TIERS.get(key)
    if tier is not None:
        return tier
    if key in HIGH_RISK_TOOL_NAMES:
        return "high"
    caps = classify_tool(name)
    if caps & {"exec", "deploy"}:
        return "critical"
    if caps & {"irreversible", "payment", "email", "db_write", "git"}:
        return "high"
    if caps & {"external_action", "fs_write", "chat", "fetch"}:
        return "medium"
    return "low"
