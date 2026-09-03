"""
tests/unit/test_audit_rules_secrets_pii.py
------------------------------------------
AUD-501 (secret literal), AUD-502 (secret in MCP / host config), AUD-503
(secret bound into a prompt), AUD-504 (verbatim prompt / response logging) and
AUD-505 (literal PII in prompts / evals / logs), each against the real
discovery output of a fixture tree.

No secret-shaped or PII-shaped literal is written in this file: every value is
assembled at runtime and written into a `tmp_path` tree. Each positive test also
pins that the raw value never reaches a snippet, a title or a note.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aisg.devtools.audit.model import (
    AuditContext,
    Basis,
    Bucket,
    EvidenceKind,
    Inventory,
    MatchKind,
    Severity,
)
from aisg.devtools.audit.rules import run_rules
from aisg.devtools.audit.rules.secrets_pii import (
    RULES,
    LiteralPii,
    SecretInConfig,
    SecretIntoPrompt,
    SecretLiteral,
    VerbatimLogging,
)

ALLOWED_LINT_RULES = {
    *(f"EU-AIA-{n}" for n in "005a 005b 005c 009a 010a 010b 011a 012a 012b 013a 013b".split()),
    *(f"EU-AIA-{n}" for n in "014a 014b 015a 015b 015c 050a 050b".split()),
    "EU-GDPR-001",
    *(f"ALIGN-00{n}" for n in range(1, 9)),
}
CONTROL_TOKEN = re.compile(
    r"^(?:ASI(?:0[1-9]|10)|LLM(?:0[1-9]|10)|EU:Art\.\d+|NIST:[A-Z]+-\d+\.\d+)$"
)
BASELINE_FIXTURE = "clean_py"  # the fixture with no AI surface at all

# Runtime-assembled values; none of them appears as a literal in this file.
ANTHROPIC_KEY = "sk-ant-" + "api03-" + "x" * 40
OPENAI_KEY = "sk-proj-" + "b" * 48
NOTION_TOKEN = "ntn_" + "a" * 30
# Spaces keep this out of the `generic` SECRET_PATTERNS row, so only the
# name-based `secret_var` table sees it.
DB_PASSWORD = "hunter two " + "seven nine"
EMAIL = "jane.doe@" + "northwind-mail.io"
SSN = "219-09-" + "9999"
CARD = "4539" + "578763621486"
IP = "10.1.2." + "3"

AGENT_PY = (
    "import logging\n"
    "import os\n"
    "from openai import OpenAI\n"
    "logger = logging.getLogger(__name__)\n"
    "client = OpenAI()\n"
    "MODEL = 'gpt-4o'\n"
    "def ask(question, api_key):\n"
    "    prompt = f'Use key {api_key} to answer: {question}'\n"
    "    system_prompt = 'token ' + os.environ['SERVICE_PASSWORD']\n"
    "    response = client.chat.completions.create("
    "model=MODEL, messages=[{'role': 'user', 'content': prompt}])\n"
    "    logger.info(f'prompt was {prompt}')\n"
    "    print(response)\n"
    "    logger.debug('raw %s', response)\n"
    "    logger.info('tokens %d', response.usage.total_tokens)\n"
    "    return response\n"
)


def _write(root: Path, relpath: str, text: str) -> None:
    path = root / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _agent_tree(tmp_path: Path) -> Path:
    """A one-unit Python tree with an AI surface, used by AUD-503 / AUD-504."""
    root = tmp_path / "agent"
    _write(root, "pyproject.toml", "[project]\nname = 'agent'\n")
    _write(root, "agent.py", AGENT_PY)
    return root


def _findings(rule, ctx):
    findings, unknown = run_rules([rule], ctx)
    assert unknown == []
    return findings


def _at(findings, relpath: str, line: int):
    return [f for f in findings if f.evidence[0].file == relpath and f.evidence[0].line == line]


def _no_raw_values(findings, *values: str) -> None:
    for finding in findings:
        blob = " ".join(
            [finding.title, finding.notes or "", finding.sub or ""]
            + [ev.snippet for ev in finding.evidence]
        )
        for value in values:
            assert value not in blob


# ---------------------------------------------------------------------------
# Metadata
# ---------------------------------------------------------------------------


def test_rules_list_is_ordered_and_complete():
    assert [r.id for r in RULES] == ["AUD-501", "AUD-502", "AUD-503", "AUD-504", "AUD-505"]
    assert RULES == [SecretLiteral, SecretInConfig, SecretIntoPrompt, VerbatimLogging, LiteralPii]


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_rule_metadata(rule):
    number = rule.id.split("-", 1)[1]
    assert rule.priority == int(number[:-2]) == 5
    assert rule.controls
    for token in rule.controls:
        assert CONTROL_TOKEN.match(token), token
    assert len(rule.recommendation.alternatives) >= 3
    assert any("aisg" not in alt for alt in rule.recommendation.alternatives)
    assert rule.measured_precision is None
    assert set(rule.related_lint_rules) <= ALLOWED_LINT_RULES
    assert rule.basis is Basis.PRESENCE
    assert rule.known_failure_modes
    assert rule.title


def test_match_kinds_follow_the_evidence_source():
    assert SecretLiteral.match_kind is MatchKind.GREP
    assert SecretInConfig.match_kind is MatchKind.STRUCTURED
    assert SecretIntoPrompt.match_kind is MatchKind.AST
    assert VerbatimLogging.match_kind is MatchKind.GREP
    assert LiteralPii.match_kind is MatchKind.GREP
    assert SecretIntoPrompt.requires_ai_surface is True
    assert VerbatimLogging.requires_ai_surface is True
    assert SecretLiteral.requires_ai_surface is False
    assert LiteralPii.severity is Severity.LOW
    assert SecretLiteral.severity is Severity.CRITICAL


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_empty_context_yields_nothing(rule, tmp_path: Path):
    ctx = AuditContext(root=tmp_path, inventory=Inventory())
    assert rule().evaluate(ctx) == []


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
@pytest.mark.parametrize("deep", [True, False], ids=["deep", "grep"])
def test_baseline_fixture_yields_nothing(rule, deep, audit_fixture, audit_context):
    ctx = audit_context(audit_fixture(BASELINE_FIXTURE), deep=deep)
    assert rule().evaluate(ctx) == []


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_context_with_none_facts_does_not_raise(rule, py_agent, audit_context):
    ctx = audit_context(py_agent)
    ctx.pyfacts = None
    ctx.config_facts = None
    ctx.options = None
    rule().evaluate(ctx)  # never raises; result depends on the grep tiers only


# ---------------------------------------------------------------------------
# AUD-501 secret literal in source
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("deep", [True, False], ids=["deep", "grep"])
def test_501_py_agent_secrets_py(deep, py_agent, audit_context):
    findings = _findings(SecretLiteral, audit_context(py_agent, deep=deep))
    rows = [(f.evidence[0].file, f.evidence[0].line, f.sub) for f in findings]
    assert rows == [("secrets.py", 1, "anthropic"), ("secrets.py", 2, "aws_access_key")]
    for finding in findings:
        assert finding.id == "AUD-501"
        assert finding.severity is Severity.CRITICAL
        assert finding.bucket is Bucket.ASSERTED
        assert finding.confidence.match_kind is MatchKind.GREP
        assert finding.confidence.evidence_kind is EvidenceKind.CODE
        assert finding.gitignored is False
        assert "<redacted:" in finding.evidence[0].snippet
    _no_raw_values(findings, ANTHROPIC_KEY, "AKIA" + "Q" * 16)


def test_501_gitignored_env_file_is_reported_and_flagged(tmp_path: Path, audit_context):
    root = tmp_path / "envtree"
    _write(root, "pyproject.toml", "[project]\nname = 'x'\n")
    _write(root, ".gitignore", ".env\n")
    _write(root, ".env", f"OPENAI_API_KEY={OPENAI_KEY}\n")
    findings = _findings(SecretLiteral, audit_context(root))
    assert [(f.evidence[0].file, f.evidence[0].line) for f in findings] == [(".env", 1)]
    finding = findings[0]
    assert finding.gitignored is True
    assert finding.confidence.evidence_kind is EvidenceKind.CONFIG
    assert finding.sub == "openai_project"
    _no_raw_values(findings, OPENAI_KEY)


def test_501_name_based_assignment(tmp_path: Path, audit_context):
    root = tmp_path / "vartree"
    _write(root, "pyproject.toml", "[project]\nname = 'x'\n")
    _write(
        root,
        "settings.py",
        f'DB_PASSWORD = "{DB_PASSWORD}"\n'
        'MAX_TOKENS = "0123456789abcdef"\n'
        'API_KEY = "' + "k9" * 10 + '"\n',
    )
    findings = _findings(SecretLiteral, audit_context(root))
    rows = [(f.evidence[0].file, f.evidence[0].line, f.sub) for f in findings]
    # Line 1: name-based only. Line 2: token COUNTING, excluded. Line 3: the
    # `generic` pattern row wins over the name-based hit on the same line.
    assert rows == [("settings.py", 1, "assignment"), ("settings.py", 3, "generic")]
    assert "DB_PASSWORD" in (findings[0].notes or "")
    _no_raw_values(findings, DB_PASSWORD, "k9" * 10)


def test_501_leaves_mcp_config_paths_to_502(tmp_path: Path, audit_context):
    root = tmp_path / "cfgtree"
    _write(root, "pyproject.toml", "[project]\nname = 'x'\n")
    _write(
        root,
        ".mcp.json",
        '{"mcpServers": {"notes": {"command": "npx", "args": ["-y", "notes-mcp@1.0.0"], '
        f'"env": {{"ANTHROPIC_API_KEY": "{ANTHROPIC_KEY}"}}}}}}\n',
    )
    ctx = audit_context(root)
    assert _findings(SecretLiteral, ctx) == []
    findings = _findings(SecretInConfig, ctx)
    assert [(f.evidence[0].file, f.evidence[0].line) for f in findings] == [(".mcp.json", 1)]
    # The grep hit and the env-literal key sit on one line: reported once, masked.
    assert findings[0].confidence.match_kind is MatchKind.GREP
    assert "<redacted:" in findings[0].evidence[0].snippet
    _no_raw_values(findings, ANTHROPIC_KEY)


def test_501_example_suffix_is_not_a_secret(tmp_path: Path, audit_context):
    root = tmp_path / "exampletree"
    _write(root, "pyproject.toml", "[project]\nname = 'x'\n")
    _write(root, ".env.example", f"OPENAI_API_KEY={OPENAI_KEY}\n")
    assert _findings(SecretLiteral, audit_context(root)) == []


# ---------------------------------------------------------------------------
# AUD-502 secret in MCP / host config
# ---------------------------------------------------------------------------


def _mcp_env_tree(tmp_path: Path) -> Path:
    root = tmp_path / "mcpenv"
    _write(root, "pyproject.toml", "[project]\nname = 'x'\n")
    _write(
        root,
        ".mcp.json",
        "{\n"
        '  "mcpServers": {\n'
        '    "notion": {\n'
        '      "command": "npx",\n'
        '      "args": ["-y", "notion-mcp@1.0.0"],\n'
        '      "env": {\n'
        f'        "NOTION_API_KEY": "{NOTION_TOKEN}",\n'
        '        "NOTION_WORKSPACE": "acme",\n'
        '        "GH_TOKEN": "${GH_TOKEN}"\n'
        "      }\n"
        "    }\n"
        "  }\n"
        "}\n",
    )
    return root


@pytest.mark.parametrize("deep", [True, False], ids=["deep", "grep"])
def test_502_env_literal_key_reported_by_name_only(deep, tmp_path: Path, audit_context):
    ctx = audit_context(_mcp_env_tree(tmp_path), deep=deep)
    findings = _findings(SecretInConfig, ctx)
    rows = [(f.evidence[0].file, f.evidence[0].line, f.sub) for f in findings]
    assert rows == [(".mcp.json", 7, "env")]
    finding = findings[0]
    assert finding.id == "AUD-502"
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence.match_kind is MatchKind.STRUCTURED
    assert finding.confidence.evidence_kind is EvidenceKind.CONFIG
    assert "NOTION_API_KEY" in finding.evidence[0].snippet
    assert "notion" in finding.evidence[0].snippet
    # A `${...}` reference and a non-credential key never fire.
    assert "GH_TOKEN" not in (finding.notes or "")
    assert "NOTION_WORKSPACE" not in (finding.notes or "")
    _no_raw_values(findings, NOTION_TOKEN)


def test_502_py_agent_and_noise_carry_no_config_secret(py_agent, audit_fixture, audit_context):
    assert _findings(SecretInConfig, audit_context(py_agent)) == []
    assert _findings(SecretInConfig, audit_context(audit_fixture("noise"))) == []


def test_502_host_config_grep_hit(tmp_path: Path, audit_context):
    root = tmp_path / "hosttree"
    _write(root, "pyproject.toml", "[project]\nname = 'x'\n")
    _write(
        root, ".claude/settings.json", f'{{"env": {{"ANTHROPIC_API_KEY": "{ANTHROPIC_KEY}"}}}}\n'
    )
    ctx = audit_context(root)
    findings = _findings(SecretInConfig, ctx)
    assert [(f.evidence[0].file, f.evidence[0].line) for f in findings] == [
        (".claude/settings.json", 1)
    ]
    assert findings[0].confidence.match_kind is MatchKind.GREP
    assert _findings(SecretLiteral, ctx) == []
    _no_raw_values(findings, ANTHROPIC_KEY)


def test_502_survives_missing_config_facts(tmp_path: Path, audit_context):
    ctx = audit_context(_mcp_env_tree(tmp_path))
    ctx.config_facts = None
    assert SecretInConfig().evaluate(ctx) == []


# ---------------------------------------------------------------------------
# AUD-503 secret bound into a prompt
# ---------------------------------------------------------------------------


def test_503_deep_tier_names_and_env_reads(tmp_path: Path, audit_context):
    ctx = audit_context(_agent_tree(tmp_path))
    findings = _findings(SecretIntoPrompt, ctx)
    rows = [(f.evidence[0].file, f.evidence[0].line, f.sub) for f in findings]
    assert rows == [("agent.py", 8, "fstring"), ("agent.py", 9, "concat")]
    fstring, concat = findings
    assert fstring.confidence.match_kind is MatchKind.AST
    assert "api_key" in (fstring.notes or "")
    assert concat.confidence.match_kind is MatchKind.AST
    assert "SERVICE_PASSWORD" in (concat.notes or "")
    assert "system prompt" in (concat.notes or "")
    for finding in findings:
        assert finding.id == "AUD-503"
        assert finding.severity is Severity.HIGH


def test_503_grep_tier_when_no_deep_facts(tmp_path: Path, audit_context):
    ctx = audit_context(_agent_tree(tmp_path), deep=False)
    findings = _findings(SecretIntoPrompt, ctx)
    rows = [(f.evidence[0].file, f.evidence[0].line) for f in findings]
    assert rows == [("agent.py", 8), ("agent.py", 9)]
    for finding in findings:
        assert finding.confidence.match_kind is MatchKind.GREP


def test_503_python_line_never_reported_by_both_tiers(tmp_path: Path, audit_context):
    ctx = audit_context(_agent_tree(tmp_path))
    findings = _findings(SecretIntoPrompt, ctx)
    stamps = [(f.evidence[0].file, f.evidence[0].line) for f in findings]
    assert len(stamps) == len(set(stamps))


def test_503_neutral_names_do_not_fire(py_agent, audit_fixture, audit_context):
    # py_agent binds SYSTEM_TEMPLATE / customer / body; noise binds max_tokens / token_count.
    assert _findings(SecretIntoPrompt, audit_context(py_agent)) == []
    assert SecretIntoPrompt().evaluate(audit_context(audit_fixture("noise"))) == []


def test_503_skipped_without_ai_surface(tmp_path: Path, audit_context):
    root = tmp_path / "noai"
    _write(root, "pyproject.toml", "[project]\nname = 'x'\n")
    _write(root, "fmt.py", "def f(api_key, q):\n    return f'key {api_key}: {q}'\n")
    findings, unknown = run_rules([SecretIntoPrompt], audit_context(root))
    assert findings == [] and unknown == []


# ---------------------------------------------------------------------------
# AUD-504 verbatim prompt / response logging
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("deep", [True, False], ids=["deep", "grep"])
def test_504_logging_calls_on_prompt_and_response(deep, tmp_path: Path, audit_context):
    ctx = audit_context(_agent_tree(tmp_path), deep=deep)
    findings = _findings(VerbatimLogging, ctx)
    rows = [(f.evidence[0].file, f.evidence[0].line, f.sub) for f in findings]
    assert rows == [
        ("agent.py", 11, "logger"),
        ("agent.py", 12, "print"),
        ("agent.py", 13, "logger"),
    ]
    assert _at(findings, "agent.py", 14) == []  # `response.usage.total_tokens` is not verbatim
    for finding in findings:
        assert finding.id == "AUD-504"
        assert finding.severity is Severity.MEDIUM
        assert finding.confidence.match_kind is MatchKind.GREP
        assert "redaction" in (finding.notes or "")
    assert "prompt" in (findings[0].notes or "")
    assert "response" in (findings[1].notes or "")


def test_504_redaction_symbol_in_file_suppresses(tmp_path: Path, audit_context):
    root = _agent_tree(tmp_path)
    _write(root, "agent.py", AGENT_PY + "def redact_prompt(text):\n    return text[:8]\n")
    assert _findings(VerbatimLogging, audit_context(root)) == []


def test_504_counting_call_and_comment_do_not_fire(tmp_path: Path, audit_context):
    root = tmp_path / "count"
    _write(root, "pyproject.toml", "[project]\nname = 'x'\n")
    _write(
        root,
        "agent.py",
        "import logging\nfrom openai import OpenAI\nlogger = logging.getLogger(__name__)\n"
        "client = OpenAI()\n"
        "def ask(prompt):\n"
        "    # print(prompt)\n"
        "    logger.info('tokens %d', count_tokens(prompt))\n"
        "    logger.info('len %d', len(prompt))\n"
        "    return client.chat.completions.create(model='gpt-4o', messages=[])\n",
    )
    assert _findings(VerbatimLogging, audit_context(root)) == []


def test_504_skipped_outside_ai_surface(tmp_path: Path, audit_context):
    root = tmp_path / "noai"
    _write(root, "pyproject.toml", "[project]\nname = 'x'\n")
    _write(root, "cli.py", "def main(prompt):\n    print(prompt)\n")
    findings, unknown = run_rules([VerbatimLogging], audit_context(root))
    assert findings == [] and unknown == []


def test_504_py_agent_has_no_verbatim_logging(py_agent, audit_context):
    assert _findings(VerbatimLogging, audit_context(py_agent)) == []


# ---------------------------------------------------------------------------
# AUD-505 literal PII in prompts / evals / logs
# ---------------------------------------------------------------------------


def _pii_tree(tmp_path: Path) -> Path:
    root = tmp_path / "pii"
    _write(root, "pyproject.toml", "[project]\nname = 'x'\n")
    _write(root, "prompts/greet.prompt", f"Hello, reply to {EMAIL} about the order.\n")
    _write(root, "evals/cases.jsonl", f'{{"input": "my ssn is {SSN}", "expected": "refuse"}}\n')
    _write(root, "logs/app.log", f"2026-01-01 request from {IP} user card {CARD}\n")
    # Outside PII_FILE_GLOBS: never scanned.
    _write(root, "README.md", f"Contact {EMAIL} for access.\n")
    # Placeholders inside the globs: skipped at discovery.
    _write(root, "prompts/sample.prompt", "Write to user@example.com or call 555-0100.\n")
    return root


@pytest.mark.parametrize("deep", [True, False], ids=["deep", "grep"])
def test_505_entities_in_scoped_files_only(deep, tmp_path: Path, audit_context):
    findings = _findings(LiteralPii, audit_context(_pii_tree(tmp_path), deep=deep))
    rows = [(f.evidence[0].file, f.evidence[0].line, f.sub) for f in findings]
    assert rows == [
        ("evals/cases.jsonl", 1, "ssn"),
        ("logs/app.log", 1, "credit_card"),
        ("logs/app.log", 1, "ip_address"),
        ("prompts/greet.prompt", 1, "email"),
    ]
    for finding in findings:
        assert finding.id == "AUD-505"
        assert finding.severity is Severity.LOW
        assert finding.confidence.match_kind is MatchKind.GREP
        assert finding.gitignored is False
        assert "entity:" in (finding.notes or "")
    _no_raw_values(findings, EMAIL, SSN, CARD, IP)


def test_505_every_entity_on_the_line_is_masked(tmp_path: Path, audit_context):
    findings = _findings(LiteralPii, audit_context(_pii_tree(tmp_path)))
    for finding in _at(findings, "logs/app.log", 1):
        snippet = finding.evidence[0].snippet
        assert "<pii:IP_ADDRESS>" in snippet
        assert "<pii:CREDIT_CARD>" in snippet


def test_505_py_agent_prompt_markdown_carries_none(py_agent, audit_context):
    assert _findings(LiteralPii, audit_context(py_agent)) == []


def test_505_gitignored_flag_is_copied_from_the_file_record(tmp_path: Path, audit_context):
    # The walk drops gitignored directories, so a gitignored log is only enumerated
    # when the walk chooses to keep it; the rule copies whatever flag the record carries.
    root = tmp_path / "gilog"
    _write(root, "pyproject.toml", "[project]\nname = 'x'\n")
    _write(root, "logs/app.log", f"user {EMAIL} signed in\n")
    ctx = audit_context(root)
    for record in ctx.files:
        if record.relpath == "logs/app.log":
            record.gitignored = True
    findings = _findings(LiteralPii, ctx)
    assert [(f.evidence[0].file, f.sub, f.gitignored) for f in findings] == [
        ("logs/app.log", "email", True)
    ]
