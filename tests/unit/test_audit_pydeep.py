"""tests/unit/test_audit_pydeep.py
-------------------------------
Python AST layer of `aisg audit`: call sites, loops, tools, gates, prompts, taint, trifecta.
"""

from __future__ import annotations

import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from aisg.devtools.audit.model import UnknownCategory  # noqa: E402
from aisg.devtools.audit.pydeep import (  # noqa: E402
    LLM_CALL_ATTRS,
    SINK_ATTRS,
    Assembly,
    CallSite,
    GateSite,
    LoopSite,
    PyFacts,
    TaintPath,
    ToolDef,
    analyse_file,
    analyse_unit,
)


@dataclass
class _Rec:
    path: Path
    relpath: str
    lang: str = "python"
    unit: str = "u"


def _src(source: str) -> str:
    """Dedent and drop the leading newline so line 1 is the first statement."""
    return textwrap.dedent(source).lstrip("\n")


def _facts(tmp_path: Path, source: str, name: str = "m.py") -> PyFacts:
    src = _src(source)
    path = tmp_path / name
    path.write_text(src, encoding="utf-8")
    return analyse_file(_Rec(path, name), src)


def _unit(tmp_path: Path, **sources: str) -> PyFacts:
    recs = []
    for name, source in sources.items():
        path = tmp_path / f"{name}.py"
        path.write_text(_src(source), encoding="utf-8")
        recs.append(_Rec(path, f"{name}.py"))
    return analyse_unit(recs)


# Lines 1-8; `reply` is model output inside `handle`, the tail goes into the same body.
ANTHROPIC_REPLY = """
    import subprocess, shlex, sqlite3, requests
    import anthropic
    from flask import render_template_string
    client = anthropic.Anthropic()

    def handle(user_text):
        response = client.messages.create(model="m", messages=[{"role": "user", "content": user_text}])
        reply = response.content[0].text
"""


# --------------------------------------------------------------------------- #
# LLM call sites
# --------------------------------------------------------------------------- #


def test_llm_call_sites_by_provider(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic, openai, litellm
        from langchain_openai import ChatOpenAI

        a = anthropic.Anthropic()
        o = openai.OpenAI()
        chain = ChatOpenAI() | (lambda x: x)

        def go():
            a.messages.create(model="m", messages=[])
            o.chat.completions.create(model="m", messages=[])
            litellm.completion(model="m", messages=[])
            chain.invoke({"q": 1})
        """,
    )
    providers = sorted((c.provider, c.line) for c in facts.llm_calls)
    assert providers == [("anthropic", 9), ("langchain", 12), ("litellm", 11), ("openai", 10)]
    assert all(
        c.function == "go" and c.loop_line is None and c.capped is None for c in facts.llm_calls
    )
    assert isinstance(facts.llm_calls[0], CallSite)


def test_run_on_non_sdk_object_is_not_a_call_site(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import subprocess

        class Job:
            def run(self):
                return 1

        def go():
            Job().run()
            subprocess.run(["ls"])
        """,
    )
    assert facts.llm_calls == []
    assert ("run",) in LLM_CALL_ATTRS


# --------------------------------------------------------------------------- #
# Loops
# --------------------------------------------------------------------------- #


def test_while_true_with_llm_call_uncapped(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic
        client = anthropic.Anthropic()

        def agent():
            while True:
                r = client.messages.create(model="m", messages=[])
                if r.stop_reason != "tool_use":
                    break
        """,
    )
    (loop,) = facts.loops
    assert isinstance(loop, LoopSite)
    assert loop.kind == "while_true" and loop.cap_symbol is None
    assert loop.contains_llm_call is True and loop.function == "agent"
    (site,) = facts.llm_calls
    assert site.loop_line == loop.line and site.capped is False


def test_while_true_capped_by_max_turns(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic
        client = anthropic.Anthropic()

        def agent(max_turns=10):
            turns = 0
            while True:
                turns += 1
                client.messages.create(model="m", messages=[])
                if turns >= max_turns:
                    break
        """,
    )
    (loop,) = facts.loops
    assert loop.cap_symbol == "max_turns"
    assert facts.llm_calls[0].capped is True


def test_counter_guard_counts_as_cap(tmp_path):
    facts = _facts(
        tmp_path,
        """
        def spin():
            n = 0
            while True:
                n += 1
                if n > 5:
                    return
        """,
    )
    assert facts.loops[0].cap_symbol == "n"


def test_huge_range_is_a_loop_site_small_range_is_not(tmp_path):
    facts = _facts(
        tmp_path,
        """
        def a():
            for i in range(10**9):
                pass

        def b():
            for i in range(5):
                pass
        """,
    )
    assert [(lp.kind, lp.function, lp.cap_symbol) for lp in facts.loops] == [
        ("for_range_huge", "a", None)
    ]


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #


def test_decorated_tool_capabilities_and_tier(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import smtplib
        from langchain_core.tools import tool

        @tool
        def send_email(to: str, body: str) -> str:
            with smtplib.SMTP("smtp.example.com") as s:
                s.sendmail("a", to, body)
            return "sent"
        """,
    )
    (t,) = facts.tools
    assert isinstance(t, ToolDef)
    assert t.name == "send_email" and t.kind == "decorator"
    assert {"email", "irreversible"} <= t.capabilities
    assert t.risk_tier in {"critical", "high"}
    assert "smtplib.SMTP" in t.calls
    assert facts.tool_gate_join == {"send_email": None}


def test_registry_and_basetool_tools(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import requests
        from langchain.tools import BaseTool

        def fetch_url(url):
            return requests.get(url).text

        TOOLS = {"fetch_url": fetch_url}

        class MyTool(BaseTool):
            name = "delete_record"
            def _run(self, record_id):
                db.delete(record_id)
        """,
    )
    by_name = {t.name: t for t in facts.tools}
    assert by_name["fetch_url"].kind == "registry" and "fetch" in by_name["fetch_url"].capabilities
    assert by_name["delete_record"].kind == "basetool"
    assert "db.delete" in by_name["delete_record"].calls


def test_from_function_tool(tmp_path):
    facts = _facts(
        tmp_path,
        """
        from langchain.tools import StructuredTool

        def lookup(q):
            return q

        t = StructuredTool.from_function(lookup, name="lookup_order")
        """,
    )
    assert [(t.name, t.kind) for t in facts.tools] == [("lookup_order", "from_function")]


# --------------------------------------------------------------------------- #
# Gates and the tool/gate join
# --------------------------------------------------------------------------- #


def test_gate_join_reaches_depth_two(tmp_path):
    facts = _facts(
        tmp_path,
        """
        from langchain_core.tools import tool

        def request_approval(what):
            return input(f"approve {what}? (y/n) ") == "y"

        def confirm_with_user(what):
            return request_approval(what)

        @tool
        def delete_everything(path: str):
            if confirm_with_user(path):
                shutil.rmtree(path)
        """,
    )
    gate = facts.tool_gate_join["delete_everything"]
    assert isinstance(gate, GateSite)
    assert gate.symbol == "input" and gate.line == 4 and gate.function == "request_approval"
    assert gate.inert_reason is None


def test_inert_gates(tmp_path):
    facts = _facts(
        tmp_path,
        """
        from langgraph.graph import StateGraph
        g = StateGraph(dict)
        a = g.compile(interrupt_before=["tools"])
        b = g.compile(interrupt_before=["tools"], checkpointer=saver)
        agent = Agent(require_approval=True)
        runner = Runner(auto_approve=True)
        """,
    )
    reasons = {(g.line, g.symbol): g.inert_reason for g in facts.gates}
    assert reasons[(3, "interrupt_before")] == "interrupt_before without checkpointer"
    assert reasons[(4, "interrupt_before")] is None
    assert reasons[(5, "require_approval")] == "require_approval=True without approval_callback"
    assert any(
        line == 6 and reason and reason.startswith("bypass:")
        for (line, _s), reason in reasons.items()
    )
    # One record per line: the Assign and the Call it wraps must not both land.
    assert len(facts.gates) == len({(g.file, g.line) for g in facts.gates})


def test_inert_gate_is_not_reported_live_through_the_join(tmp_path):
    facts = _facts(
        tmp_path,
        """
        from langchain_core.tools import tool
        from aisg import ToolPolicyGuard

        def guarded_send(to, body):
            guard = ToolPolicyGuard(require_approval=True)
            return guard.check({"to": to, "body": body})

        @tool
        def send_email(to: str, body: str):
            return guarded_send(to, body)
        """,
    )
    at_line = [g for g in facts.gates if g.line == 5]
    assert len(at_line) == 1
    assert at_line[0].inert_reason == "require_approval=True without approval_callback"
    joined = facts.tool_gate_join["send_email"]
    assert isinstance(joined, GateSite)
    assert joined.inert_reason == "require_approval=True without approval_callback"


# --------------------------------------------------------------------------- #
# Prompt assembly
# --------------------------------------------------------------------------- #


def test_prompt_from_request_body_is_untrusted(tmp_path):
    facts = _facts(
        tmp_path,
        """
        from fastapi import FastAPI, Request
        app = FastAPI()

        @app.post("/chat")
        async def chat(request: Request):
            body = await request.json()
            prompt = f"Customer says: {body['message']}"
            return prompt
        """,
    )
    (a,) = facts.prompt_assemblies
    assert isinstance(a, Assembly)
    assert a.kind == "fstring" and a.is_system is False
    assert a.untrusted_names == ("body",)


def test_system_prompt_from_env_is_system_and_trusted(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import os, anthropic
        client = anthropic.Anthropic()
        persona = os.environ["PERSONA"]

        def ask(q):
            return client.messages.create(model="m", system=f"You are {persona}.", messages=[q])
        """,
    )
    (a,) = facts.prompt_assemblies
    assert a.is_system is True and a.untrusted_names == ()
    assert a.source_names == ("persona",)


def test_system_prompt_variable_used_later_as_system(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import anthropic
        client = anthropic.Anthropic()

        def ask(name, q):
            instructions = "Be nice to " + name
            return client.messages.create(model="m", system=instructions, messages=[q])
        """,
    )
    (a,) = facts.prompt_assemblies
    assert a.kind == "concat" and a.is_system is True


def test_unrelated_fstring_is_not_an_assembly(tmp_path):
    facts = _facts(
        tmp_path,
        """
        def log(n):
            path = f"/tmp/{n}.log"
            return path
        """,
    )
    assert facts.prompt_assemblies == []


# --------------------------------------------------------------------------- #
# Taint from model output to sinks
# --------------------------------------------------------------------------- #


def _taint(tmp_path, tail: str) -> list[TaintPath]:
    """`tail` becomes the rest of `handle`'s body, starting at line 9."""
    body = textwrap.indent(textwrap.dedent(tail).strip("\n"), "        ")
    return _facts(tmp_path, ANTHROPIC_REPLY + body + "\n").taint_paths


def test_shell_sink_unsanitised(tmp_path):
    (p,) = _taint(tmp_path, "subprocess.run(reply, shell=True)")
    assert p.sink_kind == "shell" and p.sanitised is False
    assert p.source_accessor == "content_text" and p.sink_call == "subprocess.run"
    assert p.function == "handle" and p.via == (p.source_line,)


def test_shell_sink_via_shlex_quote_is_sanitised(tmp_path):
    (p,) = _taint(tmp_path, 'subprocess.run("echo " + shlex.quote(reply), shell=True)')
    assert p.sink_kind == "shell" and p.sanitised is True


def test_sql_fstring_tainted_parametrised_not(tmp_path):
    paths = _taint(
        tmp_path,
        """
        cur = sqlite3.connect("x").cursor()
        cur.execute(f"SELECT * FROM t WHERE name = '{reply}'")
        cur.execute("SELECT * FROM t WHERE name = %s", (reply,))
        """,
    )
    assert [(p.sink_kind, p.sanitised) for p in paths] == [("sql", False)]


def test_eval_url_fs_html_sinks(tmp_path):
    paths = _taint(
        tmp_path,
        """
        eval(reply)
        requests.get(reply)
        open(reply, "w")
        render_template_string(reply)
        open(reply)
        """,
    )
    assert sorted(p.sink_kind for p in paths) == ["eval", "fs", "html", "url"]
    assert all(not p.sanitised for p in paths)


def test_int_cast_kills_taint(tmp_path):
    (p,) = _taint(
        tmp_path,
        """
        n = int(reply)
        subprocess.run(f"kill {n}", shell=True)
        """,
    )
    assert p.sanitised is True


def test_taint_through_same_unit_helper(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import subprocess
        import anthropic
        client = anthropic.Anthropic()

        def handle(user_text):
            response = client.messages.create(model="m", messages=[])
            reply = response.content[0].text
            run_it(reply)

        def run_it(cmd):
            subprocess.run(cmd, shell=True)
        """,
    )
    (p,) = facts.taint_paths
    assert p.sink_kind == "shell" and p.function == "run_it"
    assert p.source_line == 7 and p.via == (7, 8) and p.sink_line == 11


def test_taint_through_json_loads_and_for_loop(tmp_path):
    (p,) = _taint(
        tmp_path,
        """
        import json
        commands = json.loads(reply)
        for cmd in commands:
            subprocess.run(cmd, shell=True)
        """,
    )
    assert p.sink_kind == "shell" and p.sanitised is False


def test_sink_table_shape():
    assert set(SINK_ATTRS) == {"shell", "eval", "sql", "html", "url", "fs"}
    assert ("subprocess", "run") in SINK_ATTRS["shell"]


# --------------------------------------------------------------------------- #
# Trifecta legs and scopes
# --------------------------------------------------------------------------- #


def test_trifecta_in_one_function_is_function_scope(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import psycopg2, smtplib
        from flask import request

        def handler():
            rows = psycopg2.connect("dsn").cursor().execute("select 1")
            payload = request.json
            smtplib.SMTP("h").sendmail("a", "b", str(rows) + str(payload))
        """,
    )
    (scope,) = facts.trifecta_scopes()
    assert scope.kind == "function" and scope.name == "m.py::handler" and scope.unit == "u"
    legs = facts.legs["func:m.py::handler"]
    assert legs["private"] and legs["untrusted"] and legs["external_action"]


def test_trifecta_split_across_functions_is_file_scope(tmp_path):
    facts = _facts(
        tmp_path,
        """
        import psycopg2, smtplib
        from flask import request

        def read():
            return psycopg2.connect("dsn")

        def ingest():
            return request.json

        def act():
            smtplib.SMTP("h")
        """,
    )
    (scope,) = facts.trifecta_scopes()
    assert scope.kind == "file" and scope.name == "m.py"


def test_trifecta_split_across_files_is_no_scope(tmp_path):
    facts = _unit(
        tmp_path,
        a="""
        import psycopg2
        from flask import request
        def f():
            return psycopg2.connect("dsn"), request.json
        """,
        b="""
        import smtplib
        def g():
            smtplib.SMTP("h")
        """,
    )
    assert facts.trifecta_scopes() == []


# --------------------------------------------------------------------------- #
# Fail-open, parse failures, merge
# --------------------------------------------------------------------------- #


def test_fail_open_guard_call_is_recorded(tmp_path):
    facts = _facts(
        tmp_path,
        """
        from aisg import PromptInjectionGuard
        guard = PromptInjectionGuard()

        async def check(x):
            try:
                await guard.check(x, {})
            except Exception:
                pass
            return x
        """,
    )
    (site,) = facts.fail_open
    assert site.symbol == "fail_open" and site.inert_reason == "exception swallowed"
    assert site.function == "check" and facts.gates == []


def test_swallowed_non_guard_call_is_not_fail_open(tmp_path):
    facts = _facts(
        tmp_path,
        """
        def f(x):
            try:
                int(x)
            except ValueError:
                pass
        """,
    )
    assert facts.fail_open == []


def test_syntax_error_becomes_unknown_item(tmp_path):
    facts = _facts(tmp_path, "def broken(:\n    pass\n")
    (item,) = facts.unknown
    assert item.category == UnknownCategory.DEEP and item.file == "m.py"
    assert "SyntaxError" in item.why
    assert facts.llm_calls == [] and facts.trifecta_scopes() == []


def test_analyse_unit_skips_non_python_and_missing_files(tmp_path):
    (tmp_path / "x.js").write_text("fetch('/')", encoding="utf-8")
    facts = analyse_unit(
        [
            _Rec(tmp_path / "x.js", "x.js", lang="javascript"),
            _Rec(tmp_path / "gone.py", "gone.py"),
        ]
    )
    (item,) = facts.unknown
    assert item.file == "gone.py" and item.category == UnknownCategory.DEEP


# --------------------------------------------------------------------------- #
# The shipped fixture
# --------------------------------------------------------------------------- #


@pytest.fixture
def py_agent_facts(audit_fixture) -> PyFacts:
    root = audit_fixture("py_agent")
    recs = [
        _Rec(root / "app.py", "app.py", unit="py_agent"),
        _Rec(root / "tools.py", "tools.py", unit="py_agent"),
    ]
    return analyse_unit(recs)


def test_fixture_py_agent(py_agent_facts):
    facts = py_agent_facts
    assert facts.unknown == []
    assert any(lp.contains_llm_call and lp.cap_symbol is None for lp in facts.loops)
    assert facts.llm_calls[0].provider == "anthropic" and facts.llm_calls[0].capped is False
    names = {t.name for t in facts.tools}
    assert {"send_email", "fetch_url", "run_shell"} <= names
    assert all(facts.tool_gate_join[n] is None for n in names)
    assert any(p.sink_kind == "shell" and not p.sanitised for p in facts.taint_paths)
    assert any(a.untrusted_names for a in facts.prompt_assemblies)
    assert any(a.is_system and a.untrusted_names for a in facts.prompt_assemblies)
    scopes = facts.trifecta_scopes()
    assert scopes and scopes[0].name == "app.py::chat"
