"""tests/unit/test_audit_discover.py
---
Grep-level discovery for `aisg audit`: what the fixtures must yield, what they
must never yield, and the honesty rules (redaction, UNKNOWN, report age).
"""

from __future__ import annotations

import json
import shutil
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest

from aisg.devtools.audit import configs, discover, patterns, walk
from aisg.devtools.audit.discover import (
    ConfigFacts,
    DiscoverOptions,
    ai_surface_units,
    config_facts,
    grep_file,
    read_measure_report,
    read_probe_report,
    read_report,
    read_system_card,
    unit_ai_surface,
)
from aisg.devtools.audit.model import INVENTORY_KEYS, Hit, Inventory, UnknownCategory
from aisg.devtools.audit.walk import FileRecord

BASELINE_FIXTURE = "clean_py"  # the fixture with no AI surface at all

ANTHROPIC_KEY = "sk-ant-" + "api03-" + "x" * 40  # assembled at runtime, never a literal
AWS_KEY = "AKIA" + "Q" * 16

# DESIGN.md section 2 entry shapes -- exact, no extras, no omissions.
MODEL_KEYS = {"id", "file", "line", "provider", "model", "pinned", "source"}
SERVER_KEYS = {
    "name",
    "file",
    "line",
    "transport",
    "command",
    "args",
    "url",
    "pinned",
    "trusted",
    "implied_legs",
    "env_secret_literals",
}
HOST_KEYS = {
    "claude": {"host", "file", "over_grants", "default_mode", "hooks"},
    "codex": {"host", "file", "approval_policy", "sandbox_mode"},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def run(root: Path, options: object = None) -> tuple[Inventory, list[Hit], ConfigFacts]:
    records, units, _unknown = walk.walk(root)
    return discover.discover(root, records, units, options)


def project(tmp_path: Path, files: dict[str, str]) -> Path:
    """A scratch project with a manifest so the root unit is python."""
    root = tmp_path / "proj"
    root.mkdir()
    (root / "pyproject.toml").write_text('[project]\nname = "proj"\n', encoding="utf-8")
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text), encoding="utf-8")
    return root


def by_table(hits: list[Hit], table: str) -> list[Hit]:
    return [h for h in hits if h.table == table]


def unknown_of(inventory: Inventory, category: UnknownCategory) -> list:
    return [u for u in inventory.unknown if u.category is category]


# ---------------------------------------------------------------------------
# py_agent: the reference fixture
# ---------------------------------------------------------------------------


class TestPyAgent:
    @pytest.fixture(autouse=True)
    def _run(self, py_agent: Path) -> None:
        self.root = py_agent
        self.inv, self.hits, self.facts = run(py_agent)
        self.doc = self.inv.to_dict()

    def test_languages(self) -> None:
        assert self.inv.languages["python"] >= 2
        assert set(self.inv.languages) == {"python", "typescript", "go", "other"}

    def test_llm_call_at_app_42_with_model_ref(self) -> None:
        calls = [c for c in self.inv.llm_calls if c["file"] == "app.py" and c["line"] == 42]
        assert calls, self.inv.llm_calls
        call = calls[0]
        assert call["provider"] == "anthropic"
        assert call["unit"] == "u0"
        ref = call["model_ref"]
        assert ref is not None
        model = next(m for m in self.inv.models if m["id"] == ref)
        assert model["model"].startswith("claude-")
        assert model["provider"] == "anthropic"
        assert isinstance(model["pinned"], bool)
        assert model["pinned"] == patterns.classify_model("anthropic", model["model"])
        assert model["source"] == "literal"

    def test_model_ids_are_numbered_and_unique(self) -> None:
        ids = [m["id"] for m in self.inv.models]
        assert ids == [f"m{i}" for i in range(1, len(ids) + 1)]

    def test_model_entries_carry_exactly_the_section_2_keys(self) -> None:
        assert self.inv.models
        for entry in self.inv.models:
            assert set(entry) == MODEL_KEYS, sorted(entry)

    def test_llm_call_falls_back_to_a_model_in_the_same_unit(self, tmp_path: Path) -> None:
        # No model id in the calling file: the ref resolves through the unit, not a
        # `unit` key on the model entry (section 2 has none).
        root = project(
            tmp_path,
            {
                "settings.py": 'MODEL = "claude-sonnet-4-5-20250929"\n',
                "worker.py": (
                    "import anthropic\n"
                    "client = anthropic.Anthropic()\n"
                    "client.messages.create(model=MODEL, messages=[])\n"
                ),
            },
        )
        inv, _hits, _facts = run(root)
        assert inv.models and all("unit" not in m for m in inv.models)
        calls = [c for c in inv.llm_calls if c["file"] == "worker.py"]
        assert calls
        ref = calls[0]["model_ref"]
        assert ref is not None
        assert next(m for m in inv.models if m["id"] == ref)["file"] == "settings.py"

    def test_tools(self) -> None:
        by_name = {t["name"]: t for t in self.inv.tools}
        assert {"send_email", "fetch_url", "run_shell"} <= set(by_name)
        email = by_name["send_email"]
        assert "irreversible" in email["capabilities"]
        assert email["gated"] is False
        assert email["gate_symbols"] == []
        assert email["file"] == "tools.py"
        assert email["unit"] == "u0"
        assert email["kind"] == "anthropic_schema"
        assert "exec" not in email["capabilities"]  # the neighbouring run_shell body is not ours
        assert "exec" in by_name["run_shell"]["capabilities"]
        assert "fetch" in by_name["fetch_url"]["capabilities"]
        assert [t["id"] for t in self.inv.tools] == [f"t{i}" for i in range(1, len(by_name) + 1)]

    def test_mcp_servers(self) -> None:
        servers = {s["name"]: s for s in self.inv.mcp["servers"]}
        assert {"gmail", "ops"} <= set(servers)
        for entry in servers.values():
            assert set(entry) == SERVER_KEYS, sorted(entry)
        gmail = servers["gmail"]
        assert gmail["pinned"] is False
        assert gmail["trusted"] is False
        assert "private" in gmail["implied_legs"]
        ops = servers["ops"]
        assert ops["transport"] in ("sse", "http", "streamable_http")
        assert ops["url"] and ops["url"].startswith("http")
        assert ops["trusted"] is False
        # The transport host / remote flag / description live on the structured record.
        records = {s.name: s for s in self.facts.servers}
        assert records["ops"].remote is True
        assert records["ops"].remote_host
        assert records["gmail"].remote is False
        assert records["gmail"].file == gmail["file"] and records["gmail"].line == gmail["line"]

    def test_mcp_remote_trusted_only_when_listed(self, py_agent: Path) -> None:
        inv, _hits, _facts = run(py_agent, DiscoverOptions(trusted_mcp_hosts=("MCP.example.com",)))
        servers = {s["name"]: s for s in inv.mcp["servers"]}
        assert servers["ops"]["trusted"] is True
        assert servers["gmail"]["trusted"] is False  # local: pinned decides, not the host list

    def test_mcp_configs(self) -> None:
        assert self.inv.mcp["configs"] == [{"file": ".mcp.json", "host": "claude"}]

    def test_hosts(self) -> None:
        assert self.inv.hosts
        claude = self.inv.hosts[0]
        assert set(claude) == HOST_KEYS["claude"], sorted(claude)
        assert claude["host"] == "claude"
        assert claude["file"] == ".claude/settings.json"
        assert "Bash(*)" in claude["over_grants"]
        assert isinstance(claude["hooks"], int)
        record = self.facts.host_records[0]
        assert record.host == "claude" and record.file == claude["file"]
        assert [g.value for g in record.over_grants] == claude["over_grants"]
        assert len(record.hooks) == claude["hooks"]
        assert record.default_mode == claude["default_mode"]

    def test_secrets_counted_and_redacted_everywhere(self) -> None:
        assert self.inv.secrets["literal_hits"] >= 1
        assert self.inv.secrets["scanner"] == "regex-only"
        secret_hits = by_table(self.hits, "secret")
        assert secret_hits
        assert any("<redacted:" in h.snippet for h in secret_hits)
        for tail in (ANTHROPIC_KEY[-12:], AWS_KEY[-12:]):
            assert all(tail not in h.snippet for h in self.hits)
            assert tail not in json.dumps(self.doc)

    def test_system_card(self) -> None:
        card = self.inv.system_card
        assert card is not None
        assert card["file"] == "ai-system-card.yaml"
        assert card["risk_tier"] == "unknown"
        assert set(card) == {"file", "risk_tier", "annex_iii_category", "incident_contact"}

    def test_units_and_surface(self) -> None:
        assert self.inv.units[0].id == "u0"
        assert self.inv.units[0].ai_surface is True
        assert unit_ai_surface(self.inv, "u0") is True
        assert unit_ai_surface(self.inv, "u99") is False
        assert "u0" in ai_surface_units(self.inv)
        assert not unknown_of(self.inv, UnknownCategory.DEEP)

    def test_loops(self) -> None:
        loops = [lp for lp in self.inv.loops if lp["file"] == "app.py"]
        assert loops
        assert loops[0]["capped"] is False
        assert loops[0]["cap_symbol"] is None
        assert loops[0]["unit"] == "u0"

    def test_legs(self) -> None:
        assert any(s["kind"] == "shell" and s["file"] == "app.py" for s in self.inv.sinks)
        assert any(i["kind"] == "http" for i in self.inv.ingress)
        assert self.inv.data_sources
        assert any(a["kind"] in ("email", "shell") for a in self.inv.external_actions)
        for leg in self.inv.sinks + self.inv.ingress + self.inv.data_sources:
            assert set(leg) == {"file", "line", "kind", "symbol", "unit"}

    def test_no_reports(self) -> None:
        assert self.inv.reports == []

    def test_target(self) -> None:
        target = self.inv.target
        assert set(target) == {
            "path",
            "git_sha",
            "dirty",
            "scanned_files",
            "skipped_files",
            "bytes",
            "duration_ms",
        }
        assert target["scanned_files"] > 0
        assert target["skipped_files"] == 0
        assert target["bytes"] > 0

    def test_hits_are_sorted_and_carry_unit(self) -> None:
        keys = [(h.file, h.line, h.col, h.table, h.key) for h in self.hits]
        assert keys == sorted(keys)
        assert all(h.unit == "u0" for h in self.hits)


# ---------------------------------------------------------------------------
# The other fixtures
# ---------------------------------------------------------------------------


def test_baseline_fixture_has_no_surface(audit_fixture) -> None:
    inv, hits, _facts = run(audit_fixture(BASELINE_FIXTURE))
    assert all(u.ai_surface is False for u in inv.units)
    assert inv.llm_calls == []
    assert inv.tools == []
    assert inv.mcp["servers"] == []
    assert inv.models == []
    assert not unknown_of(inv, UnknownCategory.DEEP)
    assert not by_table(hits, "llm_call")
    assert not by_table(hits, "tool_def")


def test_ts_agent(audit_fixture) -> None:
    inv, hits, _facts = run(audit_fixture("ts_agent"))
    assert inv.units[0].ai_surface is True
    deep = unknown_of(inv, UnknownCategory.DEEP)
    assert deep and "typescript" in deep[0].what
    assert deep[0].file == "."
    kinds = {(s["kind"], s["symbol"]) for s in inv.sinks}
    assert any(kind == "shell" and "exec" in symbol for kind, symbol in kinds)
    assert any(kind == "html" and "innerHTML" in symbol for kind, symbol in kinds)
    assert any(f["name"] == "vercel_ai" for f in inv.frameworks)
    # The Vercel AI SDK is an LLM call in its own right: the import and the call site.
    vercel = [(h.line, h.snippet) for h in by_table(hits, "llm_call") if h.key == "vercel_ai"]
    assert [line for line, _ in vercel] == [4, 9]
    assert any(c["file"] == "src/agent.ts" and c["line"] == 9 for c in inv.llm_calls)
    assert {c["provider"] for c in inv.llm_calls if c["line"] == 9} == {"multi"}


def test_go_service(audit_fixture) -> None:
    inv, hits, _facts = run(audit_fixture("go_service"))
    assert inv.units[0].ai_surface is True
    deep = unknown_of(inv, UnknownCategory.DEEP)
    assert deep and "go" in deep[0].what
    assert any(s["kind"] == "shell" and "exec.Command" in s["symbol"] for s in inv.sinks)
    assert any(h.key == "generic_http" for h in by_table(hits, "llm_call"))
    assert inv.llm_calls and inv.llm_calls[0]["file"] == "main.go"
    # CamelCase accessor: the response line is the source the shell sink is co-located with.
    accessors = [(h.line, h.key) for h in by_table(hits, "response_accessor")]
    assert accessors == [(57, "choices_message_content_go")]


def test_mcp_poison(audit_fixture) -> None:
    inv, hits, facts = run(audit_fixture("mcp_poison"))
    servers = inv.mcp["servers"]
    assert servers
    for entry in servers:
        assert set(entry) == SERVER_KEYS, sorted(entry)
    # The description is the AUD-604 input and travels on the structured record only.
    assert any("IMPORTANT" in (s.description or "") for s in facts.servers)
    assert not [h for h in by_table(hits, "mcp") if h.file == "docs/security.md"]
    assert isinstance(inv.hosts, list)


def test_hooks_curl(audit_fixture) -> None:
    inv, _hits, facts = run(audit_fixture("hosts/hooks_curl"))
    assert inv.hosts and inv.hosts[0]["hooks"] >= 1
    assert set(inv.hosts[0]) == HOST_KEYS["claude"]
    assert facts.host_records[0].hooks[0].unsafe_key == "curl_pipe_sh"


def test_codex_host_shape(audit_fixture) -> None:
    inv, _hits, facts = run(audit_fixture("hosts/codex_never"))
    codex = [h for h in inv.hosts if h["host"] == "codex"]
    assert len(codex) == 1
    assert set(codex[0]) == HOST_KEYS["codex"], sorted(codex[0])
    assert codex[0]["file"] == ".codex/config.toml"
    assert codex[0]["approval_policy"] == "never"
    assert codex[0]["sandbox_mode"] == "danger-full-access"
    # The over-grants a codex file yields are still there for the rules.
    record = next(r for r in facts.host_records if r.host == "codex")
    assert record.approval_policy == "never"
    assert {g.key for g in record.over_grants} >= {"approval_policy", "sandbox_mode"}


def test_docs_mention(audit_fixture) -> None:
    _inv, _hits, facts = run(audit_fixture("hosts/docs_mention"))
    assert len(facts.over_grant_literals) == 1
    relpath, grant = facts.over_grant_literals[0]
    assert relpath == "README.md"
    assert grant.severity == "low"
    assert grant.sub == "docs"
    assert grant.mention is True


def test_killswitch_declared_only(audit_fixture) -> None:
    _inv, hits, _facts = run(audit_fixture("killswitch_declared_only"))
    assert by_table(hits, "kill_switch_symbol") or by_table(hits, "inert_kill_switch")
    assert by_table(hits, "kill_switch_read") == []


def test_apm_only(audit_fixture) -> None:
    inv, _hits, _facts = run(audit_fixture("apm_only"))
    assert inv.observability
    assert all(o["lib"].startswith("apm:") for o in inv.observability)
    assert set(inv.observability[0]) == {"lib", "file", "line"}


@pytest.mark.parametrize(
    "name",
    [
        BASELINE_FIXTURE,
        "ts_agent",
        "go_service",
        "mcp_poison",
        "hosts/hooks_curl",
        "hosts/docs_mention",
        "killswitch_declared_only",
        "apm_only",
        "reports",
    ],
)
def test_every_fixture_serialises(audit_fixture, name: str) -> None:
    inv, _hits, _facts = run(audit_fixture(name))
    doc = inv.to_dict()
    assert all(key in doc for key in INVENTORY_KEYS)
    json.dumps(doc, ensure_ascii=True)


def test_py_agent_serialises(py_agent: Path) -> None:
    inv, _hits, _facts = run(py_agent)
    doc = inv.to_dict()
    assert all(key in doc for key in INVENTORY_KEYS)
    json.dumps(doc, ensure_ascii=True)


# ---------------------------------------------------------------------------
# Reports: asserted with an age, never measured
# ---------------------------------------------------------------------------


@pytest.fixture
def reports_root(tmp_path: Path, audit_fixture) -> Path:
    root = tmp_path / "reports"
    shutil.copytree(audit_fixture("reports"), root)
    (root / "pyproject.toml").write_text('[project]\nname = "reports"\n', encoding="utf-8")
    return root


def test_reports_are_read_with_age(reports_root: Path) -> None:
    inv, _hits, _facts = run(reports_root)
    reports = {r.file: r for r in inv.reports}
    assert set(reports) == {"measure-report.json", "measure-report-new.json", "probe-report.json"}

    old = reports["measure-report.json"]
    assert old.kind == "measure"
    assert old.generated_at is None
    assert old.age_source in ("mtime", "git")
    assert isinstance(old.age_days, int) and old.age_days >= 0
    assert old.models == []
    assert old.config_digest is None

    new = reports["measure-report-new.json"]
    body = json.loads((reports_root / "measure-report-new.json").read_text(encoding="utf-8"))
    assert new.kind == "measure"
    assert new.generated_at == body["generated_at"]
    assert new.age_source == "generated_at"
    assert new.models == body["models"]
    assert new.config_digest == body["config_digest"]

    probe = reports["probe-report.json"]
    assert probe.kind == "probe"
    assert probe.models == []
    assert probe.body["summary"]["sent"] == 10


def test_reports_are_not_eval_entries(reports_root: Path) -> None:
    # A report names the tool that wrote it ("aisg probe"); that is evidence of a past
    # run, not an eval harness. The grep hit stays; the evals[] entry does not.
    (reports_root / "promptfooconfig.yaml").write_text(
        "description: promptfoo suite\nprompts: [p.txt]\ntests:\n  - vars: {q: benign question}\n",
        encoding="utf-8",
    )
    inv, hits, _facts = run(reports_root)
    report_files = {r.file for r in inv.reports}
    assert report_files == {"measure-report.json", "measure-report-new.json", "probe-report.json"}
    assert any(h.file in report_files for h in by_table(hits, "eval_tool"))
    assert not [e for e in inv.evals if e["file"] in report_files]
    assert [e["file"] for e in inv.evals] == ["promptfooconfig.yaml"]


def test_bad_schema_is_unknown_not_a_report(reports_root: Path) -> None:
    inv, _hits, _facts = run(reports_root)
    assert "bad-schema.json" not in {r.file for r in inv.reports}
    items = [u for u in unknown_of(inv, UnknownCategory.REPORTS) if u.what == "bad-schema.json"]
    assert items and "aisg/2" in items[0].why

    report, item = read_report(reports_root / "bad-schema.json", reports_root)
    assert report is None
    assert item is not None and item.category is UnknownCategory.REPORTS
    assert "aisg/2" in item.why
    assert read_measure_report(reports_root / "bad-schema.json", reports_root) is None


def test_typed_readers(reports_root: Path) -> None:
    measure = read_measure_report(reports_root / "measure-report.json", reports_root)
    assert measure is not None and measure.kind == "measure"
    assert read_probe_report(reports_root / "measure-report.json", reports_root) is None
    probe = read_probe_report(reports_root / "probe-report.json", reports_root)
    assert probe is not None and probe.kind == "probe"
    assert read_measure_report(reports_root / "probe-report.json", reports_root) is None


def test_z_suffixed_timestamp_parses(tmp_path: Path) -> None:
    path = tmp_path / "measure-report.json"
    path.write_text(
        json.dumps({"schema": "aisg/1", "generated_at": "2026-08-20T10:15:00Z", "guards": []}),
        encoding="utf-8",
    )
    report, item = read_report(path, tmp_path)
    assert item is None and report is not None
    assert report.age_source == "generated_at"
    expected = (
        datetime.now(timezone.utc) - datetime(2026, 8, 20, 10, 15, tzinfo=timezone.utc)
    ).days
    assert report.age_days == expected
    assert report.models == []  # never inferred
    assert report.config_digest is None


def test_report_of_unknown_age_is_flagged(reports_root: Path, monkeypatch) -> None:
    monkeypatch.setattr(walk, "file_age", lambda path, root: (None, "unknown"))
    inv, _hits, _facts = run(reports_root)
    old = next(r for r in inv.reports if r.file == "measure-report.json")
    assert old.age_source == "unknown"
    assert old.age_days is None
    items = [u for u in unknown_of(inv, UnknownCategory.REPORTS) if u.what.startswith("report age")]
    assert items and items[0].file == "measure-report.json"


def test_invalid_json_report(tmp_path: Path) -> None:
    path = tmp_path / "probe-report.json"
    path.write_text("{not json", encoding="utf-8")
    report, item = read_report(path, tmp_path)
    assert report is None
    assert item is not None and item.category is UnknownCategory.REPORTS


@pytest.mark.parametrize("kind", ["audit", "audit-baseline"])
def test_own_output_is_neither_a_report_nor_an_unknown(tmp_path: Path, kind: str) -> None:
    # A committed audit-baseline.json (or a saved audit report) carries `schema: aisg/1`
    # and matches the report file glob. It is the audit's own output, not measurement
    # evidence about the system: no ReportRecord, and no "unknown report" noise either.
    path = tmp_path / "audit-report.json"
    body = {"schema": "aisg/1", "kind": kind, "generated_at": "2026-08-20T10:15:00Z"}
    if kind == "audit-baseline":
        body["fingerprints"] = ["0123456789abcdef"]
    path.write_text(json.dumps(body), encoding="utf-8")
    assert read_report(path, tmp_path) == (None, None)
    assert read_measure_report(path, tmp_path) is None
    assert read_probe_report(path, tmp_path) is None

    inv, _hits, _facts = run(tmp_path)
    assert inv.reports == []
    assert not [
        u for u in unknown_of(inv, UnknownCategory.REPORTS) if u.what == "audit-report.json"
    ]


def test_read_system_card(tmp_path: Path, audit_fixture) -> None:
    card = read_system_card(audit_fixture("py_agent") / "ai-system-card.yaml")
    assert isinstance(card, dict)
    bad = tmp_path / "ai-system-card.yaml"
    bad.write_text("- just\n- a list\n", encoding="utf-8")
    assert read_system_card(bad) is None


# ---------------------------------------------------------------------------
# Model pinning
# ---------------------------------------------------------------------------


def test_model_pinning(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "models.py": """
                import anthropic
                A = "claude-sonnet-4-5"
                B = "claude-sonnet-4-5-20250929"
                C = "gpt-4o"
                D = "gpt-4o-2024-08-06"
                E = "gemini-2.5-pro"
                F = "mistral-large-latest"
                client.chat(model="acme-llm-7b")
                """
        },
    )
    inv, _hits, _facts = run(root)
    pinned = {m["model"]: m["pinned"] for m in inv.models}
    assert pinned["claude-sonnet-4-5"] is False
    assert pinned["claude-sonnet-4-5-20250929"] is True
    assert pinned["gpt-4o"] is False
    assert pinned["gpt-4o-2024-08-06"] is True
    assert pinned["gemini-2.5-pro"] is False
    assert pinned["mistral-large-latest"] is False
    assert pinned["acme-llm-7b"] is None
    assert all(m["source"] == "literal" for m in inv.models)


def test_model_from_config_is_marked_config(tmp_path: Path) -> None:
    root = project(tmp_path, {"config.yaml": "model: gpt-4o-2024-08-06\n"})
    inv, _hits, _facts = run(root)
    assert [(m["model"], m["source"], m["pinned"]) for m in inv.models] == [
        ("gpt-4o-2024-08-06", "config", True)
    ]


# ---------------------------------------------------------------------------
# Home configs: only with the flag, labelled ~/
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_home(tmp_path: Path, monkeypatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    monkeypatch.setenv("APPDATA", str(home / "AppData" / "Roaming"))
    settings, codex, desktop = configs.home_config_paths()
    assert all(home in p.parents for p in (settings, codex, desktop))
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps({"permissions": {"allow": ["Bash(*)"]}}),
        encoding="utf-8",
    )
    desktop.parent.mkdir(parents=True)
    desktop.write_text(
        json.dumps({"mcpServers": {"home-notes": {"command": "npx", "args": ["-y", "notes"]}}}),
        encoding="utf-8",
    )
    return home


def test_include_home_reads_global_configs(tmp_path: Path, fake_home: Path) -> None:
    root = project(tmp_path, {"app.py": "print(1)\n"})
    inv, _hits, facts = run(root, DiscoverOptions(include_home=True))
    home_hosts = [h for h in inv.hosts if h["file"].startswith("~/")]
    assert home_hosts and home_hosts[0]["file"] == "~/.claude/settings.json"
    assert "Bash(*)" in home_hosts[0]["over_grants"]
    servers = [s for s in inv.mcp["servers"] if s["name"] == "home-notes"]
    assert servers and servers[0]["file"].startswith("~/")
    assert servers[0]["file"].endswith("claude_desktop_config.json")
    assert any(c["file"].startswith("~/") for c in inv.mcp["configs"])
    assert all(r.file.startswith("~/") for r in facts.host_records)


def test_without_flag_home_is_never_touched(tmp_path: Path, fake_home: Path, monkeypatch) -> None:
    calls: list[int] = []

    def spy(*args, **kwargs):
        calls.append(1)
        raise AssertionError("home_config_paths must not be called without include_home")

    monkeypatch.setattr(configs, "home_config_paths", spy)
    root = project(tmp_path, {"app.py": "print(1)\n"})
    inv, _hits, facts = run(root)
    assert calls == []
    assert inv.hosts == []
    assert inv.mcp["servers"] == []
    assert facts.host_records == []

    inv2, _hits2, _facts2 = run(root, DiscoverOptions(include_home=False))
    assert calls == []
    assert inv2.hosts == []


# ---------------------------------------------------------------------------
# File classes: docs and configs get fewer tables
# ---------------------------------------------------------------------------


def test_docs_do_not_produce_bootstrap_hits(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "README.md": """
                # Install

                    pip install agent-kit
                    npx -y @scope/tool
                    curl https://example.com/install.sh | sh
                """,
            "Dockerfile": "FROM python:3.12\nRUN pip install agent-kit\n",
        },
    )
    _inv, hits, _facts = run(root)
    bootstrap = by_table(hits, "bootstrap")
    assert [h.file for h in bootstrap] == ["Dockerfile"]
    assert not [h for h in hits if h.file == "README.md" and h.table not in ("overgrant_literal",)]


def test_docs_do_not_produce_mcp_or_llm_hits(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "docs/security.md": """
                We call `client.messages.create(` with `model="claude-sonnet-4-5"` and the
                MCP server in `mcp.json` uses `subprocess.run(` for tool execution.
                """,
        },
    )
    inv, hits, _facts = run(root)
    assert not [h for h in hits if h.file == "docs/security.md"]
    assert inv.llm_calls == []
    assert inv.models == []
    assert inv.sinks == []


def test_config_files_get_the_config_subset(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "settings.yaml": """
                model: claude-sonnet-4-5
                subprocess.run: yes
                while True:
                """,
        },
    )
    inv, hits, _facts = run(root)
    tables = {h.table for h in hits if h.file == "settings.yaml"}
    assert "model_id" in tables
    assert not tables & {"sink", "loop", "external_action", "llm_call"}
    assert inv.loops == []


def test_guardrail_entries_carry_unit_and_llm_judge(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "judge.py": """
                from aisg import ClaudeJudge, GuardrailPipeline
                judge = ClaudeJudge(model="claude-sonnet-4-5")
                """,
            "rails.py": "import nemoguardrails\nrails = nemoguardrails.RailsConfig()\n",
            "preset.yaml": """
                input:
                  prompt_injection:
                    enabled: true
                    llm_judge: true
                    fail_open: true
                """,
            "svc/pyproject.toml": '[project]\nname = "svc"\n',
            "svc/guard.py": "from aisg import PIIDetector\nd = PIIDetector()\n",
        },
    )
    inv, _hits, _facts = run(root)
    entries = {(e["file"], e["lib"]): e for e in inv.guardrails}
    assert set(entries) == {
        ("judge.py", "aisg"),
        ("rails.py", "nemoguardrails"),
        ("preset.yaml", "aisg_preset"),
        ("svc/guard.py", "aisg"),
    }
    for entry in entries.values():
        assert set(entry) == {"lib", "file", "line", "unit", "fail_open", "llm_judge"}, entry
    assert entries[("judge.py", "aisg")]["llm_judge"] is True
    assert entries[("preset.yaml", "aisg_preset")]["llm_judge"] is True
    assert entries[("preset.yaml", "aisg_preset")]["fail_open"] is True
    # Absence of the literal is not evidence of absence: None, never False.
    assert entries[("rails.py", "nemoguardrails")]["llm_judge"] is None
    assert entries[("svc/guard.py", "aisg")]["llm_judge"] is None
    assert entries[("judge.py", "aisg")]["fail_open"] is None
    units = {e["unit"] for e in entries.values()}
    assert units == {inv.units[0].id, next(u.id for u in inv.units if u.root == "svc")}
    assert entries[("svc/guard.py", "aisg")]["unit"] != entries[("judge.py", "aisg")]["unit"]


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_preset_guard_anchors_on_the_key_line_after_a_blank_line(
    tmp_path: Path, newline: str
) -> None:
    # `^\s+` would match the blank line *before* the key and anchor the evidence one
    # line too early; the fingerprint survives but the reported line is wrong. Both
    # line endings, because the text is scanned with its `\r` still attached.
    root = project(tmp_path, {})
    body = newline.join(
        [
            "input:",
            "  # A comment, then an empty line, then the first guard.",
            "",
            "  llm_tool_filter:",
            "    enabled: true",
            "",
        ]
    )
    (root / "preset.yaml").write_bytes(body.encode("utf-8"))
    inv, hits, _facts = run(root)
    entry = next(e for e in inv.guardrails if e["lib"] == "aisg_preset")
    assert entry["line"] == 4
    hit = next(h for h in by_table(hits, "guardrail") if h.file == "preset.yaml")
    assert hit.line == 4
    assert hit.snippet.strip() == "llm_tool_filter:"


def test_prompt_docs_are_scanned_for_pii(tmp_path: Path) -> None:
    # Neither value is on the SECRET_PLACEHOLDERS list (example.com and 123-45-6789 are).
    ssn = "219-09-" + "9999"
    email = "jane.doe@" + "northwind-mail.net"
    root = project(
        tmp_path,
        {
            "prompts/system.md": f"You are helpful.\nCustomer on file: {email}\n",
            "prompts/persona.txt": f"Reference SSN {ssn} when asked.\n",
            "docs/support.md": f"Escalations go to {email}.\n",
            "README.txt": f"Reference SSN {ssn}\n",
        },
    )
    _inv, hits, _facts = run(root)
    pii = by_table(hits, "pii")
    assert {(h.file, h.line, h.key) for h in pii} == {
        ("prompts/system.md", 2, "EMAIL"),
        ("prompts/persona.txt", 1, "SSN"),
    }
    # Redacted at the Hit: the value never leaves discovery.
    for hit in pii:
        assert "<pii:" in hit.snippet
        assert email not in hit.snippet and ssn not in hit.snippet
    # Docs outside PII_FILE_GLOBS keep the doc subset: no PII, no code tables.
    assert not [h for h in hits if h.file in ("docs/support.md", "README.txt")]


def test_keyword_filter_list_spanning_lines(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "filters.py": """
                BANNED_WORDS = [
                    "alpha",
                    "beta",
                ]
                blocklist = {"one", "two"}
                STOPWORDS = [
                    "the",
                ]
                """,
            "filters.ts": 'const badWords = [\n  "alpha",\n];\n',
        },
    )
    _inv, hits, _facts = run(root)
    found = {(h.file, h.line, h.col, h.key) for h in by_table(hits, "keyword_filter")}
    # The hit anchors on the name, so the line is the assignment's, not the first word's.
    assert found == {
        ("filters.py", 2, 1, "list_literal:BANNED_WORDS"),
        ("filters.py", 6, 1, "list_literal:blocklist"),
        ("filters.ts", 1, 7, "list_literal:badWords"),
    }


def test_gate_bypass_in_structured_config(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "agent.yaml": """
                agent:
                  auto_approve: true
                  require_approval: false
                """,
            "agent.json": '{"tools": {"autoApprove": true, "approval_callback": null}}\n',
            "agent.toml": "[agent]\nskip_confirmation = true\nconfirm = false\n",
            # A workflow step is a shell command, not a gate the config switches off.
            ".github/workflows/ci.yml": """
                jobs:
                  build:
                    steps:
                      - run: sudo apt-get install -y jq && gh pr merge --yes
                """,
            # Docs are never scanned for the table, even when they quote the key.
            "docs/config.md": "Set `auto_approve: true` to skip the prompt.\n",
            ".env": "AUTO_APPROVE=true\n",
        },
    )
    _inv, hits, _facts = run(root)
    bypass = by_table(hits, "gate_bypass")
    assert {(h.file, h.line) for h in bypass} == {
        ("agent.yaml", 3),
        ("agent.yaml", 4),
        ("agent.json", 1),
        ("agent.toml", 2),
        ("agent.toml", 3),
    }
    assert all(h.lang == "config" for h in bypass)
    assert {h.file for h in bypass}.isdisjoint({".github/workflows/ci.yml", "docs/config.md"})


# ---------------------------------------------------------------------------
# Mentions are not deployments: comments and docstrings
# ---------------------------------------------------------------------------

MENTION_TABLES = ("guardrail", "llm_observability", "eval_tool", "model_id")


def mention_hits(hits: list[Hit]) -> set[tuple[str, int, str, str]]:
    return {(h.file, h.line, h.table, h.key) for h in hits if h.table in MENTION_TABLES}


def test_python_comments_and_docstrings_are_not_deployments(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "agent.py": '''
                """Agent entry point.

                Wraps the model with LlamaGuard and reports traces to langfuse; run
                the promptfoo suite before deploying gpt-4o-mini.
                """
                # from aisg import GuardrailPipeline  -- disabled until the preset lands
                import os  # model: gpt-4o-mini
                from aisg import GuardrailPipeline
                from anthropic import Anthropic

                PROMPT = """You are a helper. Never mention claude-3-5-haiku-20241022."""
                client = Anthropic()
                judge = ClaudeJudge(model="claude-sonnet-4-5")  # was LlamaGuard
                trace = langfuse.trace(name="x")
                pipeline = GuardrailPipeline()
                ''',
        },
    )
    _inv, hits, _facts = run(root)
    got = mention_hits(hits)
    # The module docstring (2-6), both comment shapes (7, 8, the tail of 14) and the
    # triple-quoted prompt (12) record nothing; the live import, call and literal do.
    assert got == {
        ("agent.py", 9, "guardrail", "aisg"),
        ("agent.py", 14, "model_id", "anthropic:claude-sonnet-4-5"),
        ("agent.py", 15, "llm_observability", "langfuse"),
    }


def test_js_ts_go_comment_shapes_are_not_deployments(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "src/agent.ts": """
                // import { Langfuse } from "langfuse";
                /* The old stack used nemoguardrails and gpt-4o-mini
                 * through promptfoo; see docs.
                 */
                /**
                 * Wraps the model. LlamaGuard is not wired yet.
                 */
                import { Langfuse } from "langfuse";
                const model = "gpt-4o"; // was gpt-4o-mini
                const guard = "nemoguardrails";
                """,
            "cmd/main.go": """
                package main

                // import "github.com/langfuse/langfuse-go" -- not used
                /* model: gpt-4o-mini */
                import "fmt"

                const model = "gpt-4o"
                """,
        },
    )
    _inv, hits, _facts = run(root)
    got = mention_hits(hits)
    assert got == {
        ("src/agent.ts", 9, "llm_observability", "langfuse"),
        ("src/agent.ts", 10, "model_id", "openai:gpt-4o"),
        ("src/agent.ts", 11, "guardrail", "nemoguardrails"),
        ("cmd/main.go", 8, "model_id", "openai:gpt-4o"),
    }
    # Line 10 of agent.ts: the live literal records, the trailing-comment mention does not.
    ts_line_10 = [h.key for h in hits if h.file == "src/agent.ts" and h.line == 10]
    assert "openai:gpt-4o-mini" not in ts_line_10


def test_yaml_and_json_comments_are_not_deployments(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "config/app.yaml": """
                # model: gpt-4o-mini
                model: gpt-4o  # fallback: claude-3-5-haiku-20241022
                # evals: run promptfoo before release
                """,
            "config/app.json": '{"model": "gpt-4o"} // was gpt-4o-mini\n',
        },
    )
    _inv, hits, _facts = run(root)
    got = mention_hits(hits)
    assert got == {
        ("config/app.yaml", 3, "model_id", "openai:gpt-4o"),
        ("config/app.json", 1, "model_id", "openai:gpt-4o"),
    }


def test_mention_filter_never_touches_secrets_hooks_or_gates(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "agent.py": f"""
                # ANTHROPIC_API_KEY = "{ANTHROPIC_KEY}"
                # guard = ToolPolicyGuard(require_approval=False)
                # os.system(cmd)
                import os
                ''' fail_open: true '''
                """,
            "config/agent.yaml": """
                # auto_approve: true
                agent: {}
                """,
        },
    )
    _inv, hits, _facts = run(root)
    kept = {(h.file, h.line, h.table) for h in hits}
    assert ("agent.py", 2, "secret") in kept
    assert ("agent.py", 3, "gate_bypass") in kept
    assert ("agent.py", 4, "sink") in kept
    assert ("agent.py", 6, "fail_open") in kept
    assert ("config/agent.yaml", 2, "gate_bypass") in kept
    # Redaction still applies to the commented-out key.
    secret = next(h for h in hits if h.table == "secret" and h.line == 2)
    assert ANTHROPIC_KEY not in secret.snippet


def test_promptfoo_config_is_an_eval_by_file_name(tmp_path: Path) -> None:
    """promptfoo's own init writes the tool name only in a schema comment; the file
    name is the evidence, so the mention filter cannot make the harness vanish."""
    root = project(
        tmp_path,
        {
            "promptfooconfig.yaml": """
                # yaml-language-server: $schema=https://promptfoo.dev/config-schema.json
                description: regression suite
                prompts:
                  - "{{q}}"
                """,
            "evals/promptfooconfig.attacks.json": '{"prompts": []}\n',
            # A body mention in an unrelated file name is still the body hit it was.
            "Makefile": "evals:\n\tnpx promptfoo eval\n",
        },
    )
    inv, hits, _facts = run(root)
    evals = [h for h in hits if h.table == "eval_tool"]
    assert {(h.file, h.line, h.snippet) for h in evals} == {
        ("promptfooconfig.yaml", 1, "promptfooconfig.yaml"),
        ("evals/promptfooconfig.attacks.json", 1, "promptfooconfig.attacks.json"),
        ("Makefile", 2, "npx promptfoo eval"),
    }
    assert [e["file"] for e in inv.evals] == [
        "Makefile",
        "evals/promptfooconfig.attacks.json",
        "promptfooconfig.yaml",
    ]
    assert all(e["tool"] == "promptfoo" for e in inv.evals)


def test_llm_judge_flag_ignores_comments_and_docstrings(tmp_path: Path) -> None:
    """`guardrails[].llm_judge` is what AUD-804 keys on, so it must mean the file wires
    a judge: a judge literal that only appears in a comment or docstring leaves the
    flag at None (not shown), and a live one sets it to True."""
    root = project(
        tmp_path,
        {
            "docjudge.py": '''
                """Wraps the model call.

                Example:
                    guard = LLMInputFilter(judge=ClaudeJudge())
                """
                from aisg import PromptInjectionGuard

                guard = PromptInjectionGuard()
                ''',
            "commented.py": """
                from aisg import PromptInjectionGuard
                # judge = ClaudeJudge(model="claude-sonnet-4-5")
                use_llm_judge = False  # llm_judge: true once credentials land
                guard = PromptInjectionGuard()
                """,
            "wired.py": """
                from aisg import ClaudeJudge, LLMInputFilter
                guard = LLMInputFilter(judge=ClaudeJudge())
                """,
            "trailing.py": """
                from aisg import ClaudeJudge  # ClaudeJudge() is wired below
                judge = ClaudeJudge()
                """,
            "presets/commented.yaml": """
                input:
                  prompt_injection:
                    enabled: true
                    # llm_judge: true
                """,
            "presets/live.yaml": """
                input:
                  prompt_injection:
                    enabled: true
                    llm_judge: true  # the judge
                """,
        },
    )
    inv, _hits, _facts = run(root)
    flags = {e["file"]: e["llm_judge"] for e in inv.guardrails}
    assert flags == {
        "docjudge.py": None,
        "commented.py": None,
        "wired.py": True,
        "trailing.py": True,
        "presets/commented.yaml": None,
        "presets/live.yaml": True,
    }


def test_llm_judge_in_is_column_aware() -> None:
    text = 'x = 1  # ClaudeJudge()\njudge = ClaudeJudge()  # llm_judge: true\n"""\nLLMJudge(\n"""\n'
    spans = patterns.comment_spans(text, "python")
    assert discover._llm_judge_in(text, spans) is True
    only_mentions = 'x = 1  # ClaudeJudge()\n"""\nLLMJudge(\n"""\n'
    spans = patterns.comment_spans(only_mentions, "python")
    assert discover._llm_judge_in(only_mentions, spans) is False
    # No spans (an unknown language) filters nothing: a mention still counts.
    assert discover._llm_judge_in(only_mentions, {}) is True
    assert discover._llm_judge_in("", {}) is False


# ---------------------------------------------------------------------------
# Secrets: exclusions and redaction
# ---------------------------------------------------------------------------


def test_example_env_is_skipped_and_real_env_is_redacted(tmp_path: Path) -> None:
    key = "sk-ant-" + "api03-" + "y" * 40
    root = project(
        tmp_path,
        {
            ".env.example": f"ANTHROPIC_API_KEY={key}\n",
            ".env": f"ANTHROPIC_API_KEY={key}\n",
        },
    )
    inv, hits, _facts = run(root)
    secrets = by_table(hits, "secret")
    assert [h.file for h in secrets] == [".env"]
    assert "<redacted:" in secrets[0].snippet
    assert key[-12:] not in secrets[0].snippet
    assert inv.secrets == {"literal_hits": 0, "config_hits": 1, "scanner": "regex-only"}
    env_record = next(r for r in walk.walk(root)[0] if r.relpath == ".env")
    assert env_record.gitignored is False


def test_secret_var_assignment_and_exclusions(tmp_path: Path) -> None:
    value = "".join(chr(97 + i % 26) for i in range(24))
    root = project(
        tmp_path,
        {
            "cfg.py": f"""
                api_key = "{value}"
                max_tokens = "{value}"
                password = "${{DB_PASSWORD}}"
                """,
            "tests/fixtures/leak.py": f'api_key = "{value}"\n',
        },
    )
    _inv, hits, _facts = run(root)
    found = [(h.file, h.key) for h in by_table(hits, "secret_var")]
    assert found == [("cfg.py", "api_key")]
    assert value not in hits[0].snippet
    assert all(value not in h.snippet for h in hits)


def test_placeholder_secret_is_not_a_hit(tmp_path: Path) -> None:
    # The assignment shape is split so this file never carries one itself.
    lines = [
        "api_" + 'key = "<your-key-here-please>"',
        "auth_" + 'token = "${AUTH_TOKEN_FROM_ENV}"',
        "pass" + 'word = "changeme-changeme-changeme"',
    ]
    root = project(tmp_path, {"app.py": "\n".join(lines) + "\n"})
    _inv, hits, _facts = run(root)
    assert by_table(hits, "secret_var") == []
    assert by_table(hits, "secret") == []


# ---------------------------------------------------------------------------
# Kill switches, ingress-to-prompt, tools, loops
# ---------------------------------------------------------------------------


def test_kill_switch_read_versus_declaration(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "declared.py": "agent_disabled: bool = False\n",
            "read.py": 'import os\nif os.environ.get("AGENT_DISABLED"):\n    raise SystemExit\n',
            ".env.example": "GUARDRAILS_DISABLE_ALL=false\n",
        },
    )
    _inv, hits, _facts = run(root)
    reads = {h.file for h in by_table(hits, "kill_switch_read")}
    symbols = {h.file for h in by_table(hits, "kill_switch_symbol")}
    inert = by_table(hits, "inert_kill_switch")
    assert reads == {"read.py"}
    assert "declared.py" in symbols
    assert inert and inert[0].file == ".env.example"


def test_ingress_to_prompt_fallback(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "web.py": """
                from fastapi import FastAPI, Request

                app = FastAPI()


                @app.post("/chat")
                async def chat(request: Request):
                    payload = await request.json()
                    prompt = f"Answer this: {payload['question']}"
                    return prompt
                """,
        },
    )
    _inv, hits, _facts = run(root)
    flows = by_table(hits, "ingress_to_prompt")
    assert flows and flows[0].key == "payload"
    assert flows[0].file == "web.py"


def test_tool_gating_and_loop_cap(tmp_path: Path) -> None:
    root = project(
        tmp_path,
        {
            "agent.py": """
                MAX_TURNS = 5
                tools = [
                    {
                        "name": "delete_rows",
                        "description": "Delete rows from the database.",
                        "input_schema": {"type": "object"},
                    },
                ]


                def delete_rows(sql):
                    if not approve(sql):
                        return None
                    return db.execute(sql)


                turns = 0
                while True:
                    turns += 1
                    if turns > MAX_TURNS:
                        break
                """,
        },
    )
    inv, _hits, _facts = run(root)
    assert inv.tools and inv.tools[0]["name"] == "delete_rows"
    assert "db_write" in inv.tools[0]["capabilities"]
    assert inv.loops and inv.loops[0]["capped"] is True
    assert inv.loops[0]["cap_symbol"] is not None


# ---------------------------------------------------------------------------
# Resilience and determinism
# ---------------------------------------------------------------------------


def test_nul_and_oversized_files_are_skipped(tmp_path: Path) -> None:
    root = project(tmp_path, {"big.py": "x = 1\n" * 200})
    nul = root / "blob.py"
    nul.write_bytes(b"import os\x00\n")
    records, units, _unknown = walk.walk(root)
    assert "blob.py" not in {r.relpath for r in records}  # walk drops it itself
    records.append(
        FileRecord(path=nul, relpath="blob.py", lang="python", unit="u0", size=nul.stat().st_size)
    )
    inv, hits, _facts = discover.discover(root, records, units, None)
    assert inv.target["skipped_files"] == 1
    assert not [h for h in hits if h.file == "blob.py"]

    inv2, hits2, _facts2 = discover.discover(root, records, units, DiscoverOptions(max_size=100))
    assert inv2.target["skipped_files"] == 2
    assert not [h for h in hits2 if h.file == "big.py"]
    assert inv2.target["scanned_files"] < inv.target["scanned_files"]


def test_bad_file_becomes_runtime_unknown(tmp_path: Path, monkeypatch) -> None:
    root = project(tmp_path, {"app.py": "import anthropic\n"})

    def boom(record, text):
        raise ValueError("synthetic failure")

    monkeypatch.setattr(discover, "_matches", boom)
    inv, hits, _facts = run(root)
    assert hits == []
    items = unknown_of(inv, UnknownCategory.RUNTIME)
    assert items and items[0].what == "discover app.py"
    assert "ValueError" in items[0].why


def test_config_parse_failure_becomes_runtime_unknown(tmp_path: Path) -> None:
    root = project(tmp_path, {".mcp.json": "{not json"})
    inv, _hits, _facts = run(root)
    items = unknown_of(inv, UnknownCategory.RUNTIME)
    assert any(u.what == "config .mcp.json" for u in items)


def test_discover_is_deterministic(py_agent: Path) -> None:
    first = run(py_agent)[0].to_dict()
    second = run(py_agent)[0].to_dict()
    first["target"].pop("duration_ms")
    second["target"].pop("duration_ms")
    assert first == second


def test_grep_file_alone(tmp_path: Path) -> None:
    path = tmp_path / "app.py"
    text = "import anthropic\nclient.messages.create(model='claude-sonnet-4-5')\n"
    path.write_text(text, encoding="utf-8")
    record = FileRecord(path=path, relpath="app.py", lang="python", unit="u0", size=len(text))
    hits = grep_file(record, text)
    tables = {h.table for h in hits}
    assert "llm_call" in tables
    assert "model_id" in tables
    assert all(h.file == "app.py" and h.unit == "u0" for h in hits)
    assert grep_file(record, None) == []


def test_config_facts_alone(py_agent: Path) -> None:
    records, _units, _unknown = walk.walk(py_agent)
    facts, unknown = config_facts(py_agent, records, None)
    assert unknown == []
    assert {s.name for s in facts.servers} == {"gmail", "ops"}
    assert [r.host for r in facts.host_records] == ["claude"]


# ---------------------------------------------------------------------------
# The literal prefilter never removes a real match
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture_name", [BASELINE_FIXTURE, "ts_agent", "go_service", "killswitch_declared_only"]
)
def test_prefilter_is_a_superset(audit_fixture, fixture_name: str, monkeypatch) -> None:
    root = audit_fixture(fixture_name)
    with_filter = {(h.table, h.key, h.file, h.line) for h in run(root)[1]}
    monkeypatch.setattr(discover, "_literal_filter", lambda rx: None)
    without = {(h.table, h.key, h.file, h.line) for h in run(root)[1]}
    assert with_filter == without


def test_literal_filter_extracts_required_text() -> None:
    import re

    assert discover._literal_filter(re.compile(r"\bpromptfoo\b")) == ("promptfoo",)
    assert discover._literal_filter(re.compile(r"(?i)\b(?:simple_)?salesforce\b")) == (
        "salesforce",
    )
    assert discover._literal_filter(re.compile(r"\d{3}-\d{4}")) == ("-",)
    assert discover._literal_filter(re.compile(r"\d{3}\s\d{4}")) is None
    assert discover._literal_filter(re.compile(r"[a-z]+(?:foo)?")) is None
    lits = discover._literal_filter(re.compile(r"\bfrom\s+anthropic\s+import\b|^\s*import\s+x\b"))
    assert lits is not None and all(len(lit) >= 1 for lit in lits)


# ---------------------------------------------------------------------------
# Self-vocabulary: the modules that spell out what discovery looks for
# ---------------------------------------------------------------------------

AUDIT_PACKAGE = Path(discover.__file__).resolve().parent
# discover.py embeds `_AISG_GUARD_RE`, a literal naming every guard registry name;
# patterns.py and vocab.py are the detection tables themselves. None of the three
# may be scanned by a self-audit, or the vocabulary reads as a deployment.
SELF_VOCABULARY_SOURCES = ("discover.py", "patterns.py", "vocab.py")


@pytest.mark.parametrize("name", SELF_VOCABULARY_SOURCES)
def test_self_vocabulary_source_starts_with_ignore_marker(name: str) -> None:
    first = (AUDIT_PACKAGE / name).read_text(encoding="utf-8").splitlines()[0]
    assert first == patterns.IGNORE_MARKER


def test_walk_never_yields_the_self_vocabulary_sources() -> None:
    files, _units, _unknown = walk.walk(AUDIT_PACKAGE)
    seen = {record.relpath for record in files}
    assert seen.isdisjoint(SELF_VOCABULARY_SOURCES), seen & set(SELF_VOCABULARY_SOURCES)
    # The marker is an opt-out for the vocabulary files, not a blanket skip of the package.
    assert "walk.py" in seen and "model.py" in seen
