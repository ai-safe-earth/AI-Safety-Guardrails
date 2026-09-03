"""tests/unit/test_audit_rules_sinks.py
--------------------------------------
AUD-401..AUD-406: model output reaching a shell / eval / SQL / HTML / URL / filesystem
sink, on real discovery output. Deep tier is AST taint; grep tier is co-location.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from aisg.devtools.audit.model import AuditContext, Inventory, MatchKind, Severity
from aisg.devtools.audit.pydeep import PyFacts
from aisg.devtools.audit.rules import sinks
from aisg.devtools.audit.rules.sinks import (
    RULES,
    SINK_RULE_BY_KIND,
    EvalSink,
    FsSink,
    HtmlSink,
    ShellSink,
    SqlSink,
    UrlSink,
)

ALLOWED_LINT_RULES = {
    "EU-AIA-005a",
    "EU-AIA-005b",
    "EU-AIA-005c",
    "EU-AIA-009a",
    "EU-AIA-010a",
    "EU-AIA-010b",
    "EU-AIA-011a",
    "EU-AIA-012a",
    "EU-AIA-012b",
    "EU-AIA-013a",
    "EU-AIA-013b",
    "EU-AIA-014a",
    "EU-AIA-014b",
    "EU-AIA-015a",
    "EU-AIA-015b",
    "EU-AIA-015c",
    "EU-AIA-050a",
    "EU-AIA-050b",
    "EU-GDPR-001",
} | {f"ALIGN-00{n}" for n in range(1, 9)}

# Every sink kind fed from one tainted `reply`. Line numbers are asserted below.
ALL_SINKS_PY = (
    "import subprocess\n"  # 1
    "import sqlite3\n"  # 2
    "import requests\n"  # 3
    "from markupsafe import Markup\n"  # 4
    "import anthropic\n"  # 5
    "\n"
    "client = anthropic.Anthropic()\n"  # 7
    'conn = sqlite3.connect("x.db")\n'  # 8
    "\n"
    "\n"
    "def act(prompt):\n"  # 11
    "    response = client.messages.create(\n"  # 12
    '        model="claude-3-5-sonnet-latest", max_tokens=64,\n'
    '        messages=[{"role": "user", "content": prompt}],\n'
    "    )\n"
    "    reply = response.content[0].text\n"  # 16
    "    subprocess.run(reply, shell=True)\n"  # 17
    "    eval(reply)\n"  # 18
    "    conn.cursor().execute(f\"SELECT * FROM t WHERE name = '{reply}'\")\n"  # 19
    "    page = Markup(reply)\n"  # 20
    "    requests.get(reply)\n"  # 21
    '    open(reply, "w").write("done")\n'  # 22
    "    return page\n"
)

EXPECTED_SINK_LINES = {
    "AUD-401": 17,
    "AUD-402": 18,
    "AUD-403": 19,
    "AUD-404": 20,
    "AUD-405": 21,
    "AUD-406": 22,
}

SANITISED_PY = (
    "import shlex\n"
    "import subprocess\n"
    "import anthropic\n"
    "\n"
    "client = anthropic.Anthropic()\n"
    "\n"
    "\n"
    "def sanitize(text):\n"
    "    return shlex.quote(text)\n"
    "\n"
    "\n"
    "def act(prompt):\n"
    "    response = client.messages.create(\n"
    '        model="claude-3-5-sonnet-latest", max_tokens=64,\n'
    '        messages=[{"role": "user", "content": prompt}],\n'
    "    )\n"
    "    reply = response.content[0].text\n"  # 17
    "    subprocess.run(sanitize(reply), shell=True)\n"  # 18
    "    safe = sanitize(reply)\n"
    "    subprocess.call(safe, shell=True)\n"  # 20
)


def _run(rule_cls, ctx):
    rule = rule_cls()
    return rule.evaluate(ctx), rule


def _all(ctx):
    out = {}
    for rule_cls in RULES:
        findings, rule = _run(rule_cls, ctx)
        assert rule.unknown == []
        out[rule_cls.id] = findings
    return out


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Metadata and exports
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("rule_cls", RULES)
def test_rule_metadata(rule_cls):
    assert rule_cls.id.startswith("AUD-4")
    assert rule_cls.priority == int(rule_cls.id[4]) == 4
    assert rule_cls.controls
    assert len(rule_cls.recommendation.alternatives) >= 3
    assert any("aisg" not in alt.lower() for alt in rule_cls.recommendation.alternatives)
    assert rule_cls.measured_precision is None
    assert set(rule_cls.related_lint_rules) <= ALLOWED_LINT_RULES
    assert rule_cls.known_failure_modes
    assert rule_cls.requires_ai_surface is True
    assert rule_cls.kind in SINK_RULE_BY_KIND


def test_exports():
    assert [r.id for r in RULES] == [f"AUD-40{n}" for n in range(1, 7)]
    assert SINK_RULE_BY_KIND == {
        "shell": "AUD-401",
        "eval": "AUD-402",
        "sql": "AUD-403",
        "html": "AUD-404",
        "url": "AUD-405",
        "fs": "AUD-406",
    }
    assert {r.kind: r.id for r in RULES} == SINK_RULE_BY_KIND
    assert sinks.RULES is RULES
    assert [ShellSink.severity, EvalSink.severity, SqlSink.severity] == [Severity.CRITICAL] * 3
    assert [HtmlSink.severity, UrlSink.severity, FsSink.severity] == [Severity.HIGH] * 3


# ---------------------------------------------------------------------------
# py_agent: shell sink from the AST taint path, silent otherwise
# ---------------------------------------------------------------------------


def test_shell_sink_deep_py_agent(py_agent, audit_context):
    ctx = audit_context(py_agent)
    out = _all(ctx)
    assert [f.id for f in out["AUD-401"]] == ["AUD-401"]
    f = out["AUD-401"][0]
    assert f.location == ("app.py", 61)
    assert [(e.role, e.line) for e in f.evidence] == [("source", 61), ("sink", 62)]
    assert all("\\" not in e.file for e in f.evidence)
    assert f.confidence.match_kind == MatchKind.AST
    assert f.severity == Severity.CRITICAL
    assert f.scope.kind == "function"
    assert f.scope.name == "app.py::chat"
    assert f.scope.unit == "u0"
    assert "subprocess.run" in (f.notes or "")
    for rule_id in ("AUD-402", "AUD-403", "AUD-404", "AUD-405", "AUD-406"):
        assert out[rule_id] == [], rule_id


def test_shell_sink_grep_tier_py_agent(py_agent, audit_context):
    ctx = audit_context(py_agent, deep=False)
    assert ctx.pyfacts is None
    out = _all(ctx)
    assert [f.location for f in out["AUD-401"]] == [("app.py", 61)]
    f = out["AUD-401"][0]
    assert [(e.role, e.line) for e in f.evidence] == [("source", 61), ("sink", 62)]
    assert f.confidence.match_kind == MatchKind.GREP
    assert f.scope.kind == "file"
    assert "co-located, unverified" in (f.notes or "")
    assert "data flow not verified" in (f.notes or "")
    for rule_id in ("AUD-402", "AUD-403", "AUD-404", "AUD-405", "AUD-406"):
        assert out[rule_id] == [], rule_id


def test_deep_wins_no_grep_duplicates(py_agent, audit_context):
    ctx = audit_context(py_agent)
    for findings in _all(ctx).values():
        assert all(f.confidence.match_kind == MatchKind.AST for f in findings)
        keys = [(f.location, f.id) for f in findings]
        assert len(keys) == len(set(keys))


# ---------------------------------------------------------------------------
# Other languages: grep tier only
# ---------------------------------------------------------------------------


def test_ts_agent_co_located_sinks(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("ts_agent"))
    out = _all(ctx)
    shell = out["AUD-401"]
    html = out["AUD-404"]
    assert [f.location for f in shell] == [("src/agent.ts", 14)]
    assert [f.location for f in html] == [("src/agent.ts", 14)]
    assert [(e.role, e.line) for e in shell[0].evidence] == [("source", 14), ("sink", 16)]
    assert [(e.role, e.line) for e in html[0].evidence] == [("source", 14), ("sink", 24)]
    for f in shell + html:
        assert f.confidence.match_kind == MatchKind.GREP
        assert "co-located, unverified" in (f.notes or "")
        assert "reply" in (f.notes or "")
    for rule_id in ("AUD-402", "AUD-403", "AUD-405", "AUD-406"):
        assert out[rule_id] == [], rule_id


def test_go_service_llm_call_line_is_not_its_own_source(audit_fixture, audit_context):
    ctx = audit_context(audit_fixture("go_service"))
    out = _all(ctx)
    assert out["AUD-405"] == []


# ---------------------------------------------------------------------------
# Synthetic trees: every kind, sanitisation, window and identifier rules
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("deep", [True, False])
def test_every_sink_kind_fires_once(tmp_path, audit_context, deep):
    _write(tmp_path, "agent.py", ALL_SINKS_PY)
    ctx = audit_context(tmp_path, deep=deep)
    out = _all(ctx)
    expected_kind = MatchKind.AST if deep else MatchKind.GREP
    for rule_id, sink_line in EXPECTED_SINK_LINES.items():
        findings = out[rule_id]
        assert len(findings) == 1, rule_id
        f = findings[0]
        assert [(e.role, e.line) for e in f.evidence] == [("source", 16), ("sink", sink_line)]
        assert f.confidence.match_kind == expected_kind
        assert f.evidence[0].file == "agent.py"
        if deep:
            assert f.scope.kind == "function"
            assert f.scope.name == "agent.py::act"
        else:
            assert f.scope.kind == "file"
            assert "co-located, unverified" in (f.notes or "")


def test_sanitised_path_is_silent_in_deep_and_co_located_in_grep(tmp_path, audit_context):
    _write(tmp_path, "agent.py", SANITISED_PY)
    deep = _all(audit_context(tmp_path, deep=True))
    assert deep["AUD-401"] == []
    shallow = _all(audit_context(tmp_path, deep=False))
    assert [(e.role, e.line) for f in shallow["AUD-401"] for e in f.evidence] == [
        ("source", 17),
        ("sink", 18),
    ]
    assert shallow["AUD-401"][0].confidence.match_kind == MatchKind.GREP


def test_grep_tier_needs_shared_identifier_and_window(tmp_path, audit_context):
    far = "\n".join(f"    x{n} = {n}" for n in range(70))
    _write(
        tmp_path,
        "agent.py",
        "import subprocess\n"
        "import anthropic\n"
        "\n"
        "client = anthropic.Anthropic()\n"
        "\n"
        "\n"
        "def act(prompt, command):\n"
        "    response = client.messages.create(\n"
        '        model="claude-3-5-sonnet-latest", max_tokens=64,\n'
        '        messages=[{"role": "user", "content": prompt}],\n'
        "    )\n"
        "    reply = response.content[0].text\n"
        "    subprocess.run(command, shell=True)\n"
        f"{far}\n"
        "    subprocess.run(reply, shell=True)\n"
        "    return reply\n",
    )
    out = _all(audit_context(tmp_path, deep=False))
    assert out["AUD-401"] == []


def test_grep_tier_pairs_with_llm_call_when_no_accessor(tmp_path, audit_context):
    _write(
        tmp_path,
        "agent.py",
        "import subprocess\n"
        "import anthropic\n"
        "\n"
        "client = anthropic.Anthropic()\n"
        "\n"
        "\n"
        "def act(prompt):\n"
        "    completion = client.messages.create(model=prompt)\n"  # 8
        "    subprocess.run(str(completion), shell=True)\n",  # 9
    )
    out = _all(audit_context(tmp_path, deep=False))
    assert [(e.role, e.line) for f in out["AUD-401"] for e in f.evidence] == [
        ("source", 8),
        ("sink", 9),
    ]
    assert "llm_call" in (out["AUD-401"][0].notes or "")


@pytest.mark.parametrize("name", ["clean_py", "noise", "info_only"])
@pytest.mark.parametrize("deep", [True, False])
def test_silent_on_negative_fixtures(audit_fixture, audit_context, name, deep):
    out = _all(audit_context(audit_fixture(name), deep=deep))
    assert all(findings == [] for findings in out.values()), out


@pytest.mark.parametrize("rule_cls", RULES)
def test_empty_context(tmp_path, rule_cls):
    ctx = AuditContext(root=tmp_path, inventory=Inventory())
    findings, rule = _run(rule_cls, ctx)
    assert findings == []
    assert rule.unknown == []
    ctx = AuditContext(root=tmp_path, inventory=Inventory(), pyfacts=PyFacts())
    findings, rule = _run(rule_cls, ctx)
    assert findings == []
    assert rule.unknown == []
