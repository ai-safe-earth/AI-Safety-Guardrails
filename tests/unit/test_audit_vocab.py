"""
tests/unit/test_audit_vocab.py
------------------------------
Pins `aisg.devtools.audit.vocab`: capability classification is token-based (not
substring), the risk-tier order of authority, the kill-switch vocabulary's deliberate
exclusions, the env-read regexes, MCP implied legs, and the ignore marker on line 1.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aisg.devtools.audit import vocab
from aisg.devtools.audit.vocab import (
    ALLOWLIST_SYMBOLS,
    APPROVAL_SYMBOLS,
    BUDGET_SYMBOLS,
    EXEC_CAPABILITY,
    FETCH_CAPABILITY,
    GATE_BYPASS,
    HIGH_RISK_TOOL_NAMES,
    INERT_KILL_SWITCH,
    IRREVERSIBLE_CAPABILITY,
    KILL_SWITCH_ENV_READS,
    KILL_SWITCH_SYMBOLS,
    LOOP_CAP_SYMBOLS,
    MCP_IMPLIED_LEGS,
    SANDBOX_SYMBOLS,
    SANITISER_SYMBOLS,
    classify_tool,
    risk_tier_for,
)
from aisg.modules.processing.llm_tool_filter import LLMToolFilter
from aisg.modules.processing.tool_policy import TOOL_RISK_TIERS

CAPABILITY_LABELS = {
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
LEGS = {"private", "untrusted", "external_action"}


# --------------------------------------------------------------------------- #
# Self-match guard
# --------------------------------------------------------------------------- #


def test_line_one_is_the_ignore_marker():
    first = Path(vocab.__file__).read_text(encoding="utf-8").splitlines()[0]
    assert first == "# aisg-audit: ignore-file"


# --------------------------------------------------------------------------- #
# classify_tool
# --------------------------------------------------------------------------- #


def test_send_email_is_email_external_action_irreversible():
    caps = classify_tool("send_email")
    assert {"email", "external_action", "irreversible"} <= caps
    assert caps <= CAPABILITY_LABELS


def test_camel_case_name_tokenises():
    assert {"email", "external_action", "irreversible"} <= classify_tool("sendEmail")


def test_fetch_url_is_fetch_only():
    assert classify_tool("fetch_url") == {"fetch"}


def test_run_shell_is_exec():
    caps = classify_tool("run_shell")
    assert "exec" in caps
    assert "external_action" in caps


def test_body_with_subprocess_is_exec():
    caps = classify_tool("execute", "    result = subprocess.run(cmd, capture_output=True)")
    assert "exec" in caps


def test_body_only_first_thirty_lines_are_read():
    body = "\n".join(["    x = 1"] * 30 + ["    subprocess.run(cmd)"])
    assert "exec" not in classify_tool("do_thing", body)
    body = "\n".join(["    x = 1"] * 29 + ["    subprocess.run(cmd)"])
    assert "exec" in classify_tool("do_thing", body)


@pytest.mark.parametrize("name", ["get_weather", "search_docs", "calculate", "summarize"])
def test_benign_names_carry_no_action(name):
    caps = classify_tool(name)
    assert "external_action" not in caps
    assert "irreversible" not in caps
    assert "exec" not in caps


def test_get_weather_is_empty():
    assert classify_tool("get_weather") == set()


def test_benign_body_stays_benign():
    body = "    return f'what is the capital of france: {city}'"
    assert classify_tool("lookup_capital", body) == set()


def test_substring_is_not_a_token():
    # `mailbox` contains `mail`; `fetchall` contains `fetch`; `evaluate` contains `eval`.
    assert "email" not in classify_tool("count_mailbox")
    assert "fetch" not in classify_tool("rows", "    rows = cursor.fetchall()")
    assert "exec" not in classify_tool("evaluate_answer")


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("drop_table", {"db_write", "irreversible"}),
        ("deploy_service", {"deploy", "irreversible"}),
        ("charge_card", {"payment", "irreversible"}),
        ("write_file", {"fs_write"}),
        ("git_push", {"git"}),
        ("post_to_slack", {"chat", "irreversible"}),
        ("read_file", {"private_read"}),
    ],
)
def test_domain_labels(name, expected):
    caps = classify_tool(name)
    assert expected <= caps
    assert "external_action" in caps or name == "read_file"


def test_private_read_alone_is_not_an_external_action():
    assert classify_tool("read_file") == {"private_read"}


def test_every_label_is_in_the_documented_set():
    names = ["send_email", "fetch_url", "run_shell", "drop_table", "write_file", "git_push"]
    for name in names:
        assert classify_tool(name, "os.environ.get('X'); requests.post(u)") <= CAPABILITY_LABELS


# --------------------------------------------------------------------------- #
# risk_tier_for
# --------------------------------------------------------------------------- #


def test_risk_tier_table_key_wins():
    assert risk_tier_for("shell_command") == TOOL_RISK_TIERS["shell_command"] == "critical"
    assert risk_tier_for("get_weather") == TOOL_RISK_TIERS["get_weather"] == "low"
    # In the table as low even though the LLM filter screens it: the table is first.
    assert risk_tier_for("fetch_url") == "low"


def test_risk_tier_send_email_is_high():
    assert risk_tier_for("send_email") == "high"
    assert risk_tier_for("Send_Email") == "high"


def test_risk_tier_high_risk_name_not_in_table():
    assert "web_search" not in TOOL_RISK_TIERS
    assert risk_tier_for("web_search") == "high"


def test_risk_tier_heuristics_then_low():
    assert risk_tier_for("drop_table") == "high"
    assert risk_tier_for("run_shell") == "critical"
    assert risk_tier_for("write_report") == "low"
    assert risk_tier_for("calculate") == "low"


def test_risk_tier_values_are_the_four_tiers():
    for name in ["send_email", "get_weather", "run_shell", "crawl_site", "calculate", "zzz"]:
        assert risk_tier_for(name) in {"critical", "high", "medium", "low"}


# --------------------------------------------------------------------------- #
# HIGH_RISK_TOOL_NAMES: read from the shipped guards, by name
# --------------------------------------------------------------------------- #


def test_high_risk_tool_names_superset_of_both_filter_attrs():
    assert frozenset(LLMToolFilter.DEFAULT_HIGH_RISK_TOOLS) <= HIGH_RISK_TOOL_NAMES
    assert frozenset(LLMToolFilter.DEFAULT_HIGH_RISK_FAIL_CLOSED) <= HIGH_RISK_TOOL_NAMES


def test_high_risk_tool_names_superset_of_high_and_critical_tiers():
    tiered = {n for n, t in TOOL_RISK_TIERS.items() if t in ("high", "critical")}
    assert tiered <= HIGH_RISK_TOOL_NAMES
    assert "write_file" not in HIGH_RISK_TOOL_NAMES  # medium in the table, nowhere else


def test_fail_closed_class_attr_is_what_setup_uses():
    expected = {"send_email", "database_write", "payment_process", "shell_command", "deploy"}
    assert set(LLMToolFilter.DEFAULT_HIGH_RISK_FAIL_CLOSED) == expected
    guard = LLMToolFilter(judge=object())
    assert guard.high_risk_fail_closed == expected
    override = LLMToolFilter(judge=object(), high_risk_fail_closed=["deploy"])
    assert override.high_risk_fail_closed == {"deploy"}


# --------------------------------------------------------------------------- #
# Kill switch
# --------------------------------------------------------------------------- #


def test_kill_switch_symbols_exact():
    assert KILL_SWITCH_SYMBOLS == (
        "kill_switch",
        "circuit_breaker",
        "emergency_stop",
        "pause_agent",
        "agent_disabled",
    )
    assert "halt" not in KILL_SWITCH_SYMBOLS
    assert "feature_flag" not in KILL_SWITCH_SYMBOLS


def test_inert_kill_switch():
    assert "GUARDRAILS_DISABLE_ALL" in INERT_KILL_SWITCH
    assert "GUARDRAILS_DISABLE_ALL" not in KILL_SWITCH_SYMBOLS


ENV_READ_SAMPLES = [
    'disabled = os.environ.get("AGENT_DISABLED")',
    'flag = os.getenv("KILL_SWITCH")',
    "if (process.env.EMERGENCY_STOP) { return; }",
    'v := os.Getenv("PAUSE_AGENT")',
    "if settings.kill_switch:",
]


def test_each_env_read_regex_matches_its_sample():
    assert len(KILL_SWITCH_ENV_READS) == len(ENV_READ_SAMPLES)
    for pattern, sample in zip(KILL_SWITCH_ENV_READS, ENV_READ_SAMPLES):
        assert isinstance(pattern, re.Pattern)
        assert pattern.search(sample), (pattern.pattern, sample)


@pytest.mark.parametrize(
    "line",
    [
        "AGENT_DISABLED = False",
        "KILL_SWITCH: bool = False",
        "    agent_disabled: bool = False",
        "GUARDRAILS_DISABLE_ALL = True",
        "settings.kill_switch = True",
        "# set AGENT_DISABLED=1 to stop the agent",
    ],
)
def test_declarations_are_not_reads(line):
    for pattern in KILL_SWITCH_ENV_READS:
        assert not pattern.search(line), (pattern.pattern, line)


def test_more_env_read_idioms():
    assert KILL_SWITCH_ENV_READS[0].search('os.environ["AGENT_DISABLED"]')
    assert KILL_SWITCH_ENV_READS[2].search('process.env["KILL_SWITCH"]')
    assert KILL_SWITCH_ENV_READS[4].search("settings.agent_disabled == True")


# --------------------------------------------------------------------------- #
# MCP implied legs
# --------------------------------------------------------------------------- #


def test_mcp_implied_legs_are_subsets_of_the_three_legs():
    assert MCP_IMPLIED_LEGS
    for key, legs in MCP_IMPLIED_LEGS.items():
        assert key == key.lower()
        assert isinstance(legs, tuple)
        assert set(legs) <= LEGS, (key, legs)


def test_mcp_implied_legs_design_examples():
    assert set(MCP_IMPLIED_LEGS["filesystem"]) == {"private", "external_action"}
    assert set(MCP_IMPLIED_LEGS["fetch"]) == {"untrusted"}
    assert set(MCP_IMPLIED_LEGS["gmail"]) == {"private", "external_action"}
    assert set(MCP_IMPLIED_LEGS["slack"]) == {"private", "external_action"}
    assert set(MCP_IMPLIED_LEGS["github"]) == {"untrusted", "external_action"}
    assert set(MCP_IMPLIED_LEGS["postgres"]) == {"private", "external_action"}
    assert "git" not in MCP_IMPLIED_LEGS  # substring of github, whose legs differ


def test_mcp_implied_legs_substring_lookup_on_real_package_names():
    def legs_for(package: str) -> set[str]:
        out: set[str] = set()
        for key, legs in MCP_IMPLIED_LEGS.items():
            if key in package.lower():
                out.update(legs)
        return out

    assert legs_for("@modelcontextprotocol/server-gmail") == {"private", "external_action"}
    assert legs_for("@modelcontextprotocol/server-github") == {"untrusted", "external_action"}
    assert legs_for("mcp-server-fetch") == {"untrusted"}
    assert legs_for("@modelcontextprotocol/server-everything") == set()


# --------------------------------------------------------------------------- #
# Symbol tables: shape and a few documented exclusions
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "table",
    [
        LOOP_CAP_SYMBOLS,
        SANDBOX_SYMBOLS,
        ALLOWLIST_SYMBOLS,
        SANITISER_SYMBOLS,
        KILL_SWITCH_SYMBOLS,
        BUDGET_SYMBOLS,
    ],
)
def test_symbol_tables_are_tuples_of_lowercase_tokens(table):
    assert isinstance(table, tuple)
    assert table
    for token in table:
        assert isinstance(token, str)
        assert token == token.lower()
        assert re.fullmatch(r"[a-z0-9_]+", token), token


@pytest.mark.parametrize(
    "pattern",
    [IRREVERSIBLE_CAPABILITY, FETCH_CAPABILITY, EXEC_CAPABILITY, APPROVAL_SYMBOLS, GATE_BYPASS],
)
def test_regex_tables_are_compiled(pattern):
    assert isinstance(pattern, re.Pattern)


def test_loop_cap_and_budget_exclusions():
    assert "max_steps" in LOOP_CAP_SYMBOLS
    assert "count" not in LOOP_CAP_SYMBOLS
    assert "max_tool_calls" in BUDGET_SYMBOLS
    assert "timeout" not in BUDGET_SYMBOLS
    assert "max_tokens" not in BUDGET_SYMBOLS


def test_allowlist_excludes_denylists():
    assert "allowlist" in ALLOWLIST_SYMBOLS
    for bad in ("blocklist", "denylist", "blacklist"):
        assert bad not in ALLOWLIST_SYMBOLS


def test_sandbox_and_sanitiser_contents():
    assert {"firejail", "nsjail", "gvisor", "seccomp", "docker", "e2b", "sandbox"} <= set(
        SANDBOX_SYMBOLS
    )
    assert "venv" not in SANDBOX_SYMBOLS
    assert {"promptinjectionguard", "sanitize", "rebuff", "lakera"} <= set(SANITISER_SYMBOLS)
    assert "strip" not in SANITISER_SYMBOLS


def test_approval_symbols_positive_and_negative():
    assert APPROVAL_SYMBOLS.search("guard = ToolPolicyGuard(require_approval=['send_*'])")
    assert APPROVAL_SYMBOLS.search("graph.compile(interrupt_before=['tools'])")
    assert APPROVAL_SYMBOLS.search('answer = input("Proceed? [y/N] ")')
    assert not APPROVAL_SYMBOLS.search('name = input("Your name: ")')
    assert not APPROVAL_SYMBOLS.search("def send_email(to, body): ...")


def test_gate_bypass_positive_and_negative():
    assert GATE_BYPASS.search("agent = Agent(auto_approve=True)")
    assert GATE_BYPASS.search("ToolPolicyGuard(require_approval=['x'], approval_callback=None)")
    assert GATE_BYPASS.search("autoApprove: true")
    assert GATE_BYPASS.search("apt-get install -y curl")
    assert not GATE_BYPASS.search("npx -y @modelcontextprotocol/server-fetch")
    assert not GATE_BYPASS.search("ToolPolicyGuard(require_approval=['x'], approval_callback=cb)")


def test_capability_regexes_documented_exclusions():
    assert not EXEC_CAPABILITY.search("pattern = re.compile(r'x')")
    assert not EXEC_CAPABILITY.search("score = evaluate(model)")
    assert not FETCH_CAPABILITY.search("rows = cursor.fetchall()")
    assert not IRREVERSIBLE_CAPABILITY.search("def get_user(id): ...")
    assert IRREVERSIBLE_CAPABILITY.search("run('terraform apply -auto-approve')")
    assert IRREVERSIBLE_CAPABILITY.search("os.system('rm -rf /tmp/x')")
