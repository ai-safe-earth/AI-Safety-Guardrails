"""
tests/unit/test_audit_rules_package.py
--------------------------------------
The loop a `same_control=True` package promises: the finding the rule raises
is one the first symbol of its own `Recommendation.package` closes. For each
such rule a pair of scratch trees under tmp_path: one that fires, and the same
tree with that symbol wired the way the rule's `alternatives` describe. Wiring
the symbol must silence the rule, through the real walk -> discover -> pydeep
output (`audit_context` from conftest), on the AST tier and on the grep tier.

Where the wiring is a document the package writes (`aisg init`, `aisg
measure`), the wired tree holds the document the real renderer produces
(`system_card.main --defaults`, `measure.build_report`), not a hand-typed
imitation of it.

A pair is one example each way, not a precision measurement: it shows the
rule can see the control it recommends, and nothing about how often the rule
is right. `measured_precision` stays None.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest

from aisg.core.measurement import Thresholds
from aisg.devtools import system_card
from aisg.devtools.audit.rules import ALL_RULES, rule_by_id
from aisg.devtools.audit.rules.irreversible import InertGate
from aisg.devtools.measure import DEFAULT_REPORT, GuardMeasurement, build_report

# ---------------------------------------------------------------------------
# The shared tree: one Anthropic call (the AI surface), optionally three tools
# ---------------------------------------------------------------------------

PYPROJECT = '[project]\nname = "loop"\ndependencies = ["anthropic", "aisguard"]\n'

AGENT_PY = '''"""agent.py
--------
A support agent: one model call per turn.
"""

from __future__ import annotations

import anthropic

client = anthropic.Anthropic()


def run(prompt: str) -> str:
    response = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text
'''

AGENT_WITH_TOOLS_PY = '''"""agent.py
--------
A support agent: one model call per turn, tools dispatched by name.
"""

from __future__ import annotations

import anthropic

from tools import TOOL_SCHEMAS, TOOLS

client = anthropic.Anthropic()


def run(prompt: str) -> str:
    response = client.messages.create(
        model="claude-sonnet-4-5",
        max_tokens=512,
        tools=TOOL_SCHEMAS,
        messages=[{"role": "user", "content": prompt}],
    )
    for block in response.content:
        if block.type == "tool_use":
            return str(TOOLS[block.name](**block.input))
    return response.content[0].text
'''

# `send_email` is irreversible (AUD-201), `fetch_url` fetches (AUD-103), and three
# registered names are enough for AUD-105. Same shape as the shipped py_agent fixture.
TOOLS_HEAD = '''"""tools.py
--------
Tools the support agent may call.
"""

from __future__ import annotations

import smtplib
import subprocess
from email.message import EmailMessage

import requests
'''

SEND_EMAIL_UNGATED = """

def send_email(to: str, subject: str, body: str) -> str:
    msg = EmailMessage()
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP("smtp.example.com", 587) as smtp:
        smtp.send_message(msg)
    return "sent"
"""

# The gate sits on the tool's own call path: `send_email` -> `approved`, and
# `approved` is where ToolPolicyGuard is constructed with a real callback. pydeep
# joins a gate to a tool only through a function reachable from the tool body.
SEND_EMAIL_GATED = """

async def ask_operator(tool: str, args: dict, context: dict) -> bool:
    return tool in context.get("operator_allowed", ())


def approved(tool: str, args: dict) -> bool:
    guard = ToolPolicyGuard(require_approval=[tool], approval_callback=ask_operator)
    result = asyncio.run(guard.check("", {"tool_call": {"name": tool, "arguments": args}}))
    return result.passed


def send_email(to: str, subject: str, body: str) -> str:
    if not approved("send_email", {"to": to, "subject": subject}):
        return "not sent: approval withheld"
    msg = EmailMessage()
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP("smtp.example.com", 587) as smtp:
        smtp.send_message(msg)
    return "sent"
"""

TOOLS_TAIL = """

def fetch_url(url: str) -> str:
    return requests.get(url).text[:4000]


def run_shell(command: str) -> str:
    completed = subprocess.run(command, shell=True, capture_output=True, text=True)
    return completed.stdout + completed.stderr


TOOL_SCHEMAS = [
    {
        "name": "send_email",
        "description": "Send an email on behalf of the support team.",
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "fetch_url",
        "description": "Fetch the text of a web page.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "run_shell",
        "description": "Run a shell command on the support host and return its output.",
        "input_schema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
]

TOOLS = {
    "send_email": send_email,
    "fetch_url": fetch_url,
    "run_shell": run_shell,
}
"""

TOOLS_PY = TOOLS_HEAD + SEND_EMAIL_UNGATED + TOOLS_TAIL
TOOLS_GATED_PY = (
    TOOLS_HEAD.replace("import smtplib\n", "import asyncio\nimport smtplib\n").replace(
        "import requests\n", "import requests\n\nfrom aisg import ToolPolicyGuard\n"
    )
    + SEND_EMAIL_GATED
    + TOOLS_TAIL
)

# AUD-103: ToolPolicy(argument_rules=...) is the package's allowlist on a tool's arguments.
POLICY_ARGUMENT_RULES_PY = """from __future__ import annotations

from aisg import ToolPolicy, ToolPolicyGuard

FETCH_POLICY = ToolPolicy(
    allow=["fetch_url"],
    argument_rules={"fetch_url": {"url": "https://api.example.com/*"}},
)
guard = ToolPolicyGuard(policies={"user": FETCH_POLICY})
"""

# AUD-105: the per-session budget the guard keeps in the shared context dict.
POLICY_BUDGET_PY = """from __future__ import annotations

from aisg import ToolPolicyGuard

guard = ToolPolicyGuard(max_tool_calls_per_session=20, max_calls_per_tool=5)
"""

# AUD-202: the shape pydeep marks inert, and the same guard with a real callback.
GATE_INERT_PY = """from __future__ import annotations

from aisg import ToolPolicyGuard

guard = ToolPolicyGuard(require_approval=True)
"""
GATE_LIVE_PY = """from __future__ import annotations

from aisg import ToolPolicyGuard


async def ask_operator(tool: str, args: dict, context: dict) -> bool:
    return tool in context.get("operator_allowed", ())


guard = ToolPolicyGuard(require_approval=["send_email"], approval_callback=ask_operator)
"""
# The list form the guard's signature takes (`require_approval: list[str] | None`),
# with no callback: inert at runtime, since the guard answers approved when the
# callback is missing.
GATE_INERT_LIST_PY = """from __future__ import annotations

from aisg import ToolPolicyGuard

guard = ToolPolicyGuard(require_approval=["send_email"])
"""

# AUD-701: the package's tracer, constructed once and handed to the pipeline.
TELEMETRY_PY = """from __future__ import annotations

from aisg import GuardrailPipeline
from aisg.modules.observability.otel import TelemetryProvider

telemetry = TelemetryProvider(service_name="loop", exporter="otlp")
pipeline = GuardrailPipeline(telemetry_provider=telemetry)
"""

# AUD-801 / AUD-802 / AUD-903: a preset and the pipeline built from it.
PIPELINE_PY = """from __future__ import annotations

from aisg import GuardrailPipeline

pipeline = GuardrailPipeline.from_config("guardrails.yaml")
"""
PRESET_YAML = "input:\n  prompt_injection:\n    enabled: true\n"
PRESET_FAIL_OPEN_YAML = "pipeline:\n  fail_open: true\n" + PRESET_YAML
PRESET_FAIL_CLOSED_YAML = "pipeline:\n  fail_open: false\n" + PRESET_YAML
PRESET_JUDGE_MODEL_YAML = (
    "input:\n  prompt_injection:\n    enabled: true\n    llm_judge_model: claude-sonnet-4-5\n"
)

# AUD-804: an LLMJudgeBase subclass constructed with the defaults, then bounded.
JUDGE_HEAD = """from __future__ import annotations

from aisg.modules.llm_judges.base import LLMJudgeBase


class LLMJudgeVerdict(LLMJudgeBase):
    async def _call(self, prompt: str) -> str:
        return "SAFE"

"""
JUDGE_UNBOUNDED_PY = JUDGE_HEAD + "\njudge = LLMJudgeVerdict()\n"
JUDGE_BOUNDED_PY = JUDGE_HEAD + "\njudge = LLMJudgeVerdict(fail_open=False, timeout=10.0)\n"
ENV_EXAMPLE = "ANTHROPIC_API_KEY=\n"

# AUD-901: a workflow step that runs the measurement.
EVALS_WORKFLOW_YAML = """name: evals
on:
  push:
  pull_request:
jobs:
  measure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install "aisguard[devtools]"
      - run: aisg measure --config guardrails.yaml --output measure-report.json
"""

# AUD-903: a report from before the model changed. The date is fixed in the past so
# the report is always older than the freshly written model-bearing files.
STALE_REPORT = {
    "schema": "aisg/1",
    "generated_at": "2026-08-20T10:15:00+00:00",
    "models": ["claude-3-opus-20240229"],
    "config": "guardrails.yaml",
    "corpus": {"attacks": 48, "benign": 42, "timing_passes": 3},
    "guards": [{"name": "prompt_injection", "stage": "input"}],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(root: Path, files: dict[str, str]) -> Path:
    for relpath, text in files.items():
        target = root / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    return root


def _overlay(files: dict[str, str]) -> Callable[[Path], None]:
    def wire(root: Path) -> None:
        _write(root, files)

    return wire


def _wire_measure_report(root: Path) -> None:
    """The document `aisg measure` writes, for the preset in the tree, dated now."""
    measured = GuardMeasurement(
        guard_name="prompt_injection",
        stage="input",
        attacks_seen=48,
        attacks_caught=21,
        benign_seen=42,
        benign_broken=0,
        latencies_ms=[1.0] * 90,
    )
    body = build_report([measured], root / "guardrails.yaml", 48, 42, Thresholds())
    (root / DEFAULT_REPORT).write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")


def _wire_system_card(root: Path) -> None:
    """`aisg init --defaults`, through the real renderer."""
    assert system_card.main(["--defaults", "--output", str(root / "ai-system-card.yaml")]) == 0


@dataclass(frozen=True)
class Case:
    rule_id: str
    symbol: str  # the first package symbol; the wiring below adds exactly this
    fires: dict[str, str]
    wire: Callable[[Path], None]
    # The AST tier sees every pair fire; a pair whose defect is a keyword pydeep
    # resolves (AUD-202) has nothing for the grep tier to match before wiring.
    fires_on_grep: bool = True


CASES = [
    Case(
        "AUD-103",
        "ToolPolicyGuard",
        {"pyproject.toml": PYPROJECT, "agent.py": AGENT_WITH_TOOLS_PY, "tools.py": TOOLS_PY},
        _overlay({"policy.py": POLICY_ARGUMENT_RULES_PY}),
    ),
    Case(
        "AUD-105",
        "ToolPolicyGuard",
        {"pyproject.toml": PYPROJECT, "agent.py": AGENT_WITH_TOOLS_PY, "tools.py": TOOLS_PY},
        _overlay({"policy.py": POLICY_BUDGET_PY}),
    ),
    Case(
        "AUD-201",
        "ToolPolicyGuard",
        {"pyproject.toml": PYPROJECT, "agent.py": AGENT_WITH_TOOLS_PY, "tools.py": TOOLS_PY},
        _overlay({"tools.py": TOOLS_GATED_PY}),
    ),
    Case(
        "AUD-202",
        "ToolPolicyGuard",
        {"pyproject.toml": PYPROJECT, "agent.py": AGENT_PY, "policy.py": GATE_INERT_PY},
        _overlay({"policy.py": GATE_LIVE_PY}),
        fires_on_grep=False,
    ),
    Case(
        "AUD-701",
        "TelemetryProvider",
        {"pyproject.toml": PYPROJECT, "agent.py": AGENT_PY},
        _overlay({"telemetry.py": TELEMETRY_PY}),
    ),
    Case(
        "AUD-801",
        "aisg measure",
        {
            "pyproject.toml": PYPROJECT,
            "agent.py": AGENT_PY,
            "pipeline.py": PIPELINE_PY,
            "guardrails.yaml": PRESET_YAML,
        },
        _wire_measure_report,
    ),
    Case(
        "AUD-802",
        "GuardrailPipeline",
        {
            "pyproject.toml": PYPROJECT,
            "agent.py": AGENT_PY,
            "pipeline.py": PIPELINE_PY,
            "guardrails.yaml": PRESET_FAIL_OPEN_YAML,
        },
        _overlay({"guardrails.yaml": PRESET_FAIL_CLOSED_YAML}),
    ),
    Case(
        "AUD-804",
        "LLMJudgeBase",
        {"pyproject.toml": PYPROJECT, "agent.py": AGENT_PY, "judge.py": JUDGE_UNBOUNDED_PY},
        _overlay({"judge.py": JUDGE_BOUNDED_PY, ".env.example": ENV_EXAMPLE}),
    ),
    Case(
        "AUD-901",
        "aisg measure",
        {"pyproject.toml": PYPROJECT, "agent.py": AGENT_PY, "guardrails.yaml": PRESET_YAML},
        _overlay({".github/workflows/evals.yml": EVALS_WORKFLOW_YAML}),
    ),
    Case(
        "AUD-903",
        "aisg measure",
        {
            "pyproject.toml": PYPROJECT,
            "agent.py": AGENT_PY,
            "pipeline.py": PIPELINE_PY,
            "guardrails.yaml": PRESET_JUDGE_MODEL_YAML,
            DEFAULT_REPORT: json.dumps(STALE_REPORT, indent=2) + "\n",
        },
        _wire_measure_report,
    ),
    Case(
        "AUD-1001",
        "aisg init",
        {"pyproject.toml": PYPROJECT, "agent.py": AGENT_PY},
        _wire_system_card,
    ),
]
CASE_IDS = [case.rule_id for case in CASES]

# What a verb leaves in the tree: the wired tree must hold it, as a class symbol must
# appear in the wired source, so the pair is pinned to the symbol it claims to wire.
VERB_OUTPUT = {"aisg measure": DEFAULT_REPORT, "aisg init": "ai-system-card.yaml"}


def _tree_text(root: Path) -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(root.rglob("*")) if p.is_file())


def _build_pair(tmp_path: Path, case: Case) -> tuple[Path, Path]:
    before = _write(tmp_path / "before", case.fires)
    after = _write(tmp_path / "after", case.fires)
    case.wire(after)
    return before, after


# ---------------------------------------------------------------------------
# The set of pairs is the set of same_control rules
# ---------------------------------------------------------------------------


def test_every_same_control_rule_has_a_pair():
    same_control = {r.id for r in ALL_RULES if r.recommendation.package.same_control}
    assert same_control == set(CASE_IDS)
    assert len(CASE_IDS) == len(set(CASE_IDS))


@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_pair_wires_the_first_package_symbol(case: Case, tmp_path: Path):
    package = rule_by_id(case.rule_id).recommendation.package
    assert package.same_control is True
    assert package.symbols[0] == case.symbol
    _before, after = _build_pair(tmp_path, case)
    text = _tree_text(after)
    if case.symbol in VERB_OUTPUT:
        # Either the verb is run (a CI step) or what it writes is in the tree.
        assert case.symbol in text or (after / VERB_OUTPUT[case.symbol]).exists()
    else:
        assert case.symbol in text


# ---------------------------------------------------------------------------
# Fires before, silent after, on both tiers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("deep", [True, False], ids=["ast", "grep"])
@pytest.mark.parametrize("case", CASES, ids=CASE_IDS)
def test_wiring_the_symbol_silences_the_rule(case: Case, deep: bool, tmp_path, audit_context):
    rule = rule_by_id(case.rule_id)
    before, after = _build_pair(tmp_path, case)

    if deep or case.fires_on_grep:
        fired = rule().evaluate(audit_context(before, deep=deep))
        assert fired, f"{case.rule_id} did not fire on the tree built to trip it"
        assert {f.id for f in fired} == {case.rule_id}
        for finding in fired:
            assert finding.recommendation.package is rule.recommendation.package

    instance = rule()
    silent = instance.evaluate(audit_context(after, deep=deep))
    assert silent == [], [f.display_id + " " + (f.notes or "") for f in silent]
    assert instance.unknown == [], [u.what for u in instance.unknown]


def test_the_stale_report_is_older_than_anything_written_now():
    """AUD-903's before-tree relies on the fixed date staying in the past."""
    assert STALE_REPORT["generated_at"] < "2026-09-01"


# ---------------------------------------------------------------------------
# The list form the guard's signature takes
# ---------------------------------------------------------------------------


def test_inert_gate_in_the_list_form_the_guard_takes(tmp_path, audit_context):
    # `require_approval` is a list of tool names; with no `approval_callback` the guard
    # approves every one of them (tool_policy.py, `approved = True`), so the list form
    # is as inert as the literal True and AUD-202 reports it the same way.
    root = _write(
        tmp_path,
        {"pyproject.toml": PYPROJECT, "agent.py": AGENT_PY, "policy.py": GATE_INERT_LIST_PY},
    )
    fired = InertGate().evaluate(audit_context(root))
    assert [f.id for f in fired] == ["AUD-202"]
