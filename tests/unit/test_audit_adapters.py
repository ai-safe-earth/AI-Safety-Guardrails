"""tests/unit/test_audit_adapters.py
-----------------------------------
External tool adapters for `aisg audit`: pure argv, fixture-driven parsing, and a
`run()` that never installs, never opens a socket, and reports what it could not do.
"""

from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from aisg.devtools.audit import adapters
from aisg.devtools.audit.adapters import (
    ADAPTERS,
    DEFAULT_TOOL_NAMES,
    FORBIDDEN_LAUNCHERS,
    SEMGREP_RULES_PATH,
    DetectSecretsAdapter,
    GitleaksAdapter,
    McpScanAdapter,
    NpmAuditAdapter,
    OsvScannerAdapter,
    PipAuditAdapter,
    PromptfooAdapter,
    SemgrepAdapter,
    rule_meta,
    run_adapters,
    sink_rule_by_kind,
    tool_finding,
)
from aisg.devtools.audit.model import (
    Basis,
    Bucket,
    EvidenceKind,
    MatchKind,
    Severity,
    Status,
    UnknownCategory,
)
from aisg.devtools.audit.report import BANNED_PHRASES

REPO = Path(__file__).resolve().parents[2]
TOOL_OUTPUT = REPO / "tests" / "fixtures" / "audit" / "tool_output"
ADAPTERS_SRC = REPO / "src" / "aisg" / "devtools" / "audit" / "adapters.py"

# The word the audit vocabulary bans, built from parts so this file never contains it.
_BANNED_WORD = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)

FAKE_BIN = "/fake/bin"
ALL_OPTIONS = SimpleNamespace(run_evals=True, pip_audit_env=None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def fixture_payload(name: str):
    return json.loads((TOOL_OUTPUT / f"{name}.json").read_text(encoding="utf-8"))


def fixture_text(name: str) -> str:
    return (TOOL_OUTPUT / f"{name}.json").read_text(encoding="utf-8")


def multi_tool_tree(py_agent: Path) -> Path:
    """py_agent plus a Node lockfile, a TS source file and a promptfoo config."""
    (py_agent / "package.json").write_text('{"name": "agent", "version": "1.0.0"}\n')
    (py_agent / "package-lock.json").write_text(
        '{"name": "agent", "lockfileVersion": 3, "packages": {}}\n'
    )
    (py_agent / "src").mkdir()
    (py_agent / "src" / "agent.ts").write_text(
        "import { exec } from 'child_process';\nexport const run = (r: string) => exec(r);\n"
    )
    (py_agent / "promptfooconfig.yaml").write_text("prompts: ['{{q}}']\ntests: []\n")
    return py_agent


def argv_tool(argv: list[str]) -> str:
    """Which tool a fake subprocess call is for: the launcher's basename, or the module."""
    if len(argv) >= 3 and argv[1] == "-m":
        return argv[2].replace("_", "-")
    return Path(argv[0]).stem.lower()


def is_version_probe(argv: list[str]) -> bool:
    return argv[-1] in ("--version", "version")


class FakeProcesses:
    """A `subprocess.run` stand-in that answers with fixture output and records argv."""

    def __init__(self, *, stdout_for=None, report_for=None, returncode=0, stderr=""):
        self.calls: list[list[str]] = []
        self.stdout_for = stdout_for or {}
        self.report_for = report_for or {}
        self.returncode = returncode
        self.stderr = stderr

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append(argv)
        assert kwargs.get("stdin") is subprocess.DEVNULL
        assert kwargs.get("cwd")
        assert kwargs.get("timeout")
        if is_version_probe(argv):
            return subprocess.CompletedProcess(argv, 0, "1.2.3\n", "")
        tool = argv_tool(argv)
        if tool == "gitleaks":
            report = argv[argv.index("--report-path") + 1]
            Path(report).write_text(self.report_for.get(tool, ""), encoding="utf-8")
            return subprocess.CompletedProcess(argv, self.returncode, "", self.stderr)
        if tool == "promptfoo":
            report = argv[argv.index("-o") + 1]
            Path(report).write_text(self.report_for.get(tool, ""), encoding="utf-8")
            return subprocess.CompletedProcess(argv, self.returncode, "", self.stderr)
        return subprocess.CompletedProcess(
            argv, self.returncode, self.stdout_for.get(tool, ""), self.stderr
        )


def fake_which(missing=()):
    missing = set(missing)

    def which(name, *args, **kwargs):
        if name in missing:
            return None
        return f"{FAKE_BIN}/{name}"

    return which


def full_stdout():
    return {
        "detect-secrets": json.dumps(
            {
                "version": "1.5.0",
                "results": {"secrets.py": [{"type": "Secret Keyword", "line_number": 1}]},
            }
        ),
        "pip-audit": fixture_text("pip-audit"),
        "npm": fixture_text("npm-audit"),
        "osv-scanner": fixture_text("osv"),
        "mcp-scan": fixture_text("mcp-scan"),
        "semgrep": fixture_text("semgrep"),
    }


def full_reports():
    return {"gitleaks": fixture_text("gitleaks"), "promptfoo": fixture_text("promptfoo")}


def finding_text(finding) -> str:
    parts = [finding.title, finding.notes or ""]
    parts.extend(e.snippet for e in finding.evidence)
    parts.append(json.dumps(finding.to_dict(), default=str))
    return "\n".join(parts)


@pytest.fixture
def isolate(monkeypatch):
    """Apply after the context is built (discovery itself runs `git`): no PATH, no
    importable modules, no processes, no sockets."""

    def apply() -> None:
        monkeypatch.setattr(adapters, "_module_available", lambda module: False)
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)

        def no_process(*args, **kwargs):
            raise AssertionError(f"subprocess started: {args[0] if args else kwargs}")

        def no_socket(*args, **kwargs):
            raise AssertionError("socket opened")

        monkeypatch.setattr(subprocess, "run", no_process)
        monkeypatch.setattr(socket, "socket", no_socket)

    return apply


# ---------------------------------------------------------------------------
# The packaged semgrep rules
# ---------------------------------------------------------------------------


class TestSemgrepRules:
    def test_rules_file_ships_with_metadata(self):
        assert SEMGREP_RULES_PATH.is_file()
        raw = SEMGREP_RULES_PATH.read_bytes()
        raw.decode("ascii")  # ASCII only
        doc = yaml.safe_load(raw)
        rules = doc["rules"]
        assert len(rules) >= 12
        ids = [rule["id"] for rule in rules]
        assert len(ids) == len(set(ids))
        kinds = sink_rule_by_kind()
        for rule in rules:
            meta = rule["metadata"]
            assert rule["id"].startswith("aisg-sink-")
            assert re.fullmatch(r"AUD-40[1-6]", meta["aisg_rule"])
            assert meta["aisg_rule_id"] == meta["aisg_rule"]
            assert meta["kind"] in kinds
            assert kinds[meta["kind"]] == meta["aisg_rule"]
            assert rule["mode"] == "taint"
            assert rule["pattern-sources"] and rule["pattern-sinks"]
            assert rule["severity"] in ("ERROR", "WARNING")

    def test_every_sink_kind_covered_per_language(self):
        rules = yaml.safe_load(SEMGREP_RULES_PATH.read_text(encoding="ascii"))["rules"]
        seen = {(r["metadata"]["kind"], tuple(r["languages"])) for r in rules}
        for kind in ("shell", "eval", "sql", "html", "url", "fs"):
            assert (kind, ("python",)) in seen
            assert (kind, ("javascript", "typescript")) in seen

    def test_no_pattern_mixes_jsx_into_python(self):
        rules = yaml.safe_load(SEMGREP_RULES_PATH.read_text(encoding="ascii"))["rules"]
        for rule in rules:
            if "python" not in rule["languages"]:
                continue
            for block in ("pattern-sources", "pattern-sinks"):
                for entry in rule[block]:
                    for item in entry["pattern-either"]:
                        assert "new " not in item["pattern"]
                        assert "=>" not in item["pattern"]


# ---------------------------------------------------------------------------
# Parsing, one test per fixture
# ---------------------------------------------------------------------------


class TestParse:
    def test_gitleaks(self):
        findings = GitleaksAdapter().parse(fixture_payload("gitleaks"), root=".")
        assert [(f.id, f.location) for f in findings] == [
            ("AUD-501", ("secrets.py", 1)),
            ("AUD-501", ("secrets.py", 2)),
        ]
        for finding in findings:
            assert finding.severity is Severity.CRITICAL
            assert "REDACTED-BY-FIXTURE" not in finding_text(finding)
            assert "ANTHROPIC_API_KEY" not in finding_text(finding)
        assert "generic-api-key" in findings[0].title
        assert "aws-access-token" in findings[1].notes

    def test_gitleaks_routes_config_files_to_aud_502(self):
        payload = fixture_payload("gitleaks")
        payload[0]["File"] = ".mcp.json"
        payload[1]["File"] = ".claude/settings.json"
        findings = GitleaksAdapter().parse(payload, root=".")
        assert [f.id for f in findings] == ["AUD-502", "AUD-502"]

    def test_gitleaks_relativises_absolute_paths(self, tmp_path):
        payload = fixture_payload("gitleaks")
        payload[0]["File"] = str(tmp_path / "pkg" / "secrets.py")
        findings = GitleaksAdapter().parse(payload, root=tmp_path)
        assert findings[0].location == ("pkg/secrets.py", 1)

    def test_gitleaks_empty_report_means_no_findings(self):
        adapter = GitleaksAdapter()
        assert adapter.decode("") == []
        assert adapter.parse([], root=".") == []

    def test_detect_secrets(self):
        payload = {
            "version": "1.5.0",
            "results": {
                "secrets.py": [{"type": "Secret Keyword", "line_number": 1}],
                ".cursor/mcp.json": [{"type": "Base64 High Entropy String", "line_number": 7}],
            },
        }
        adapter = DetectSecretsAdapter()
        findings = adapter.parse(payload, root=".")
        assert sorted((f.id, f.location) for f in findings) == [
            ("AUD-501", ("secrets.py", 1)),
            ("AUD-502", (".cursor/mcp.json", 7)),
        ]
        assert adapter.version_from(payload) == "1.5.0"

    def test_pip_audit(self):
        findings = PipAuditAdapter().parse(
            fixture_payload("pip-audit"), inputs=("requirements.txt",), root="."
        )
        assert len(findings) == 1
        finding = findings[0]
        assert finding.id == "AUD-606"
        assert finding.severity is Severity.HIGH
        assert finding.location == ("requirements.txt", 0)
        assert "requests" in finding.title and "GHSA-9wx4-h78v-vm56" in finding.title
        assert "2.32.0" in finding.evidence[0].snippet

    def test_npm_audit(self):
        findings = NpmAuditAdapter().parse(
            fixture_payload("npm-audit"), inputs=("package-lock.json",), root="."
        )
        assert len(findings) == 2
        assert {f.id for f in findings} == {"AUD-606"}
        assert {f.severity for f in findings} == {Severity.MEDIUM}
        assert {f.location for f in findings} == {("package-lock.json", 0)}
        titles = " ".join(f.title for f in findings)
        assert "@ai-sdk/openai" in titles and "undici" in titles
        notes = " ".join(f.notes for f in findings)
        assert "GHSA-9qxr-qj4v-4x2g" in notes

    def test_npm_audit_v1_advisories(self):
        payload = {
            "advisories": {
                "1": {
                    "id": 1,
                    "module_name": "lodash",
                    "title": "Prototype Pollution",
                    "severity": "high",
                    "url": "https://npmjs.com/advisories/1",
                }
            }
        }
        findings = NpmAuditAdapter().parse(payload, root=".")
        assert [(f.id, f.severity) for f in findings] == [("AUD-606", Severity.HIGH)]
        assert "lodash" in findings[0].title

    def test_osv_scanner(self):
        findings = OsvScannerAdapter().parse(fixture_payload("osv"), root=".")
        assert len(findings) == 1
        finding = findings[0]
        assert finding.id == "AUD-606"
        assert finding.severity is Severity.MEDIUM
        assert finding.location == ("requirements.txt", 0)
        assert "requests 2.31.0" in finding.title
        assert "CVE-2024-35195" in finding.notes

    def test_mcp_scan(self):
        findings = McpScanAdapter().parse(fixture_payload("mcp-scan"), root=".")
        assert len(findings) == 1
        finding = findings[0]
        assert finding.id == "AUD-604"
        assert finding.location == (".cursor/mcp.json", 0)
        assert finding.severity is Severity.HIGH  # W-code: capped below the rule's CRITICAL
        assert "notes/add_note" in finding.title
        assert "W001" in finding.evidence[0].snippet

    def test_mcp_scan_transport_issue_is_aud_603(self):
        payload = fixture_payload("mcp-scan")
        report = payload[".cursor/mcp.json"]
        report["issues"] = [
            {
                "code": "E003",
                "message": "Server uses plaintext http:// transport to a remote host.",
                "reference": [0, None],
                "extra_data": {},
            },
            {
                "code": "W003",
                "message": "Cross-origin escalation between two servers.",
                "reference": [0, 0],
                "extra_data": {"label": "toxic flow"},
            },
        ]
        findings = McpScanAdapter().parse(payload, root=".")
        assert [f.id for f in findings] == ["AUD-603", "AUD-603"]
        assert findings[0].severity is Severity.HIGH
        assert "notes" in findings[0].title

    def test_semgrep(self):
        adapter = SemgrepAdapter()
        payload = fixture_payload("semgrep")
        findings = adapter.parse(payload, root=".")
        assert [(f.id, f.severity, f.location) for f in findings] == [
            ("AUD-401", Severity.CRITICAL, ("src/agent.ts", 16)),
            ("AUD-404", Severity.HIGH, ("src/agent.ts", 24)),
        ]
        assert "exec(reply" in findings[0].evidence[0].snippet
        assert "innerHTML" in findings[1].evidence[0].snippet
        assert adapter.version_from(payload) == "1.90.0"

    def test_semgrep_rule_id_fallbacks(self):
        payload = fixture_payload("semgrep")
        template = payload["results"][0]

        def result(check_id, metadata):
            res = json.loads(json.dumps(template))
            res["check_id"] = check_id
            res["extra"]["metadata"] = metadata
            return res

        payload["results"] = [
            result("custom.rule", {"aisg_rule": "AUD-403"}),
            result("custom.rule", {"kind": "sql"}),
            result("x.aud-405-y", {}),
            result("aisg-sink-fs-js", {}),
            result("unrelated.rule", {"category": "security"}),
        ]
        findings = SemgrepAdapter().parse(payload, root=".")
        assert [f.id for f in findings] == ["AUD-403", "AUD-403", "AUD-405", "AUD-406"]

    def test_promptfoo(self):
        findings = PromptfooAdapter().parse(
            fixture_payload("promptfoo"), inputs=("promptfooconfig.yaml",), root="."
        )
        assert [f.display_id for f in findings] == ["AUD-902/eval"]
        finding = findings[0]
        assert finding.severity is Severity.HIGH
        assert finding.location == ("promptfooconfig.yaml", 0)
        assert "1 failed" in finding.evidence[0].snippet
        cases = [e for e in finding.evidence if e.role == "case"]
        assert len(cases) == 1
        assert "intranet.example.net" in cases[0].snippet

    def test_promptfoo_without_benign_cases_adds_aud_904(self):
        payload = fixture_payload("promptfoo")
        for case in payload["results"]["results"]:
            case["testCase"]["metadata"] = {}
            for assertion in case["testCase"].get("assert", []):
                assertion["type"] = "not-contains"
        findings = PromptfooAdapter().parse(payload, inputs=("promptfooconfig.yaml",), root=".")
        assert [f.display_id for f in findings] == ["AUD-902/eval", "AUD-904"]
        assert findings[1].severity is Severity.MEDIUM

    def test_promptfoo_all_passing_with_benign_yields_nothing(self):
        payload = fixture_payload("promptfoo")
        body = payload["results"]
        for case in body["results"]:
            case["success"] = True
        body["stats"].update({"successes": 4, "failures": 0, "errors": 0})
        assert PromptfooAdapter().parse(payload, inputs=("promptfooconfig.yaml",)) == []

    def test_every_tool_finding_is_measured_and_unmeasured_precision(self):
        collected = []
        collected += GitleaksAdapter().parse(fixture_payload("gitleaks"))
        collected += PipAuditAdapter().parse(fixture_payload("pip-audit"))
        collected += NpmAuditAdapter().parse(fixture_payload("npm-audit"))
        collected += OsvScannerAdapter().parse(fixture_payload("osv"))
        collected += McpScanAdapter().parse(fixture_payload("mcp-scan"))
        collected += SemgrepAdapter().parse(fixture_payload("semgrep"))
        collected += PromptfooAdapter().parse(fixture_payload("promptfoo"))
        assert collected
        for finding in collected:
            assert finding.bucket is Bucket.MEASURED
            assert finding.basis is Basis.MEASURED
            assert finding.confidence.evidence_kind is EvidenceKind.TOOL_OUTPUT
            assert finding.confidence.match_kind is MatchKind.EXTERNAL
            assert finding.confidence.precision is None
            assert finding.fingerprint
            assert finding.controls
            assert len(finding.recommendation.alternatives) >= 3
            assert finding.evidence[0].role == "tool"


# ---------------------------------------------------------------------------
# Rule metadata
# ---------------------------------------------------------------------------


class TestRuleMeta:
    def test_fallback_table_has_full_recommendations(self):
        for rule_id, meta in adapters._FALLBACK_RULES.items():
            assert meta.id == rule_id
            alternatives = meta.recommendation.alternatives
            assert len(alternatives) >= 3, rule_id
            assert any("aisg" not in alt.lower() for alt in alternatives), rule_id
            assert any("aisg" in alt.lower() for alt in alternatives), rule_id
            assert meta.controls
            assert meta.priority == int(rule_id.split("-")[1][:-2])

    def test_fallback_used_when_registry_lacks_the_rule(self, monkeypatch):
        monkeypatch.setattr(adapters, "_registered_rule", lambda rule_id: None)
        meta = rule_meta("AUD-401")
        assert meta is adapters._FALLBACK_RULES["AUD-401"]
        generic = rule_meta("AUD-999")
        assert generic.title == "External tool finding (AUD-999)"
        assert generic.priority == 9
        assert len(generic.recommendation.alternatives) >= 3

    def test_registry_wins_when_present(self):
        try:
            from aisg.devtools.audit.rules import rule_by_id
        except Exception:  # registry not built yet: nothing to compare against
            pytest.skip("rule registry unavailable")
        rule = rule_by_id("AUD-501")
        if rule is None:
            pytest.skip("AUD-501 not registered")
        assert rule_meta("AUD-501").title == rule.title

    def test_sink_rule_by_kind_covers_fallback_kinds(self):
        kinds = sink_rule_by_kind()
        for kind, rule_id in adapters._SINK_RULE_FALLBACK.items():
            assert kinds[kind] == rule_id

    def test_tool_finding_repo_scope_for_dot(self):
        finding = tool_finding("AUD-606", tool="x", file=".", line=0, snippet="s")
        assert finding.scope.kind == "repo"
        assert finding.notes == "measured by x"
        finding = tool_finding("AUD-606", tool="x", file="a/b.txt", line=3, snippet="s")
        assert finding.scope.kind == "file" and finding.scope.name == "a/b.txt"


# ---------------------------------------------------------------------------
# argv is pure and never installs
# ---------------------------------------------------------------------------


class TestArgv:
    def test_registry_matches_default_names(self):
        assert tuple(ADAPTERS) == DEFAULT_TOOL_NAMES
        for name, adapter in ADAPTERS.items():
            assert adapter.name == name
            assert isinstance(adapter.network, bool)
            assert adapter.binary
            assert adapter.install_hint
            assert adapter.what

    def test_no_adapter_installs_anything(self, py_agent, audit_context, isolate):
        ctx = audit_context(multi_tool_tree(py_agent), options=ALL_OPTIONS)
        isolate()  # build_argv is pure: any process start fails the test
        for adapter in ADAPTERS.values():
            argv = adapter.build_argv(ctx, timeout=120)
            assert argv, adapter.name
            assert Path(argv[0]).stem.lower() not in FORBIDDEN_LAUNCHERS, adapter.name
            assert "install" not in [token.lower() for token in argv], adapter.name
            assert not any(token.lower().startswith("install") for token in argv), adapter.name
            # The hint is text the report prints, never something the audit runs.
            assert isinstance(adapter.install_hint, str)

    def test_gitleaks_argv(self, py_agent, audit_context):
        ctx = audit_context(py_agent)
        argv = GitleaksAdapter().build_argv(ctx, report_path="/tmp/report.json")
        assert argv == [
            "gitleaks",
            "detect",
            "--no-git",
            "--source",
            ".",
            "--report-format",
            "json",
            "--report-path",
            "/tmp/report.json",
            "--exit-code",
            "0",
            "--no-banner",
        ]

    def test_mcp_scan_argv_is_local_only(self, py_agent, audit_context):
        ctx = audit_context(py_agent)
        argv = McpScanAdapter().build_argv(ctx)
        assert argv[:4] == ["mcp-scan", "scan", "--local-only", "--json"]
        assert ".mcp.json" in argv
        assert "--local-only" in argv

    def test_pip_audit_requirements_mode_never_resolves(self, py_agent, audit_context):
        ctx = audit_context(py_agent, options=ALL_OPTIONS)
        argv = PipAuditAdapter().build_argv(ctx)
        assert argv[0] == "pip-audit"
        assert "-r" in argv and "--no-deps" in argv
        assert argv.index("--no-deps") < argv.index("-r")
        assert argv[argv.index("-r") + 1] == "requirements.txt"
        assert argv[-4:] == ["--format", "json", "--progress-spinner", "off"]

    def test_pip_audit_env_mode_uses_the_named_interpreter(self, py_agent, audit_context):
        options = SimpleNamespace(run_evals=False, pip_audit_env=sys.executable)
        ctx = audit_context(py_agent, options=options)
        adapter = PipAuditAdapter()
        argv = adapter.build_argv(ctx)
        assert argv[:3] == [sys.executable, "-m", "pip_audit"]
        assert "-r" not in argv
        assert argv[3:] == ["--format", "json", "--progress-spinner", "off"]
        assert adapter.locate(ctx) == [sys.executable, "-m", "pip_audit"]

    def test_pip_audit_without_environment_needs_a_flag(self, tmp_path, audit_context):
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0"\n')
        (tmp_path / "app.py").write_text("print('hi')\n")
        ctx = audit_context(tmp_path)
        result, findings, unknown = PipAuditAdapter().run(ctx)
        assert result.status is Status.SKIPPED_NEEDS_FLAG
        assert result.flag == "--pip-audit-env"
        assert findings == []
        assert len(unknown) == 1 and "--pip-audit-env" in unknown[0].how_to_resolve

    def test_osv_scanner_offline_when_local_db_configured(
        self, py_agent, audit_context, monkeypatch
    ):
        (py_agent / "uv.lock").write_text("version = 1\n")
        ctx = audit_context(py_agent)
        adapter = OsvScannerAdapter()
        monkeypatch.delenv("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", raising=False)
        assert adapter.build_argv(ctx) == ["osv-scanner", "--format", "json", "--recursive", "."]
        assert adapter.network_for(ctx) is True
        monkeypatch.setenv("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY", str(py_agent / "db"))
        argv = adapter.build_argv(ctx)
        assert "--offline" in argv and argv[-1] == "."
        assert adapter.network_for(ctx) is False

    def test_semgrep_argv_uses_packaged_rules_and_no_metrics(self, py_agent, audit_context):
        ctx = audit_context(py_agent)
        argv = SemgrepAdapter().build_argv(ctx)
        assert argv[:3] == ["semgrep", "scan", "--config"]
        assert Path(argv[3]) == SEMGREP_RULES_PATH
        assert "--metrics=off" in argv and "--json" in argv and argv[-1] == "."

    def test_promptfoo_argv(self, py_agent, audit_context):
        (py_agent / "promptfooconfig.yaml").write_text("prompts: []\n")
        ctx = audit_context(py_agent, options=ALL_OPTIONS)
        argv = PromptfooAdapter().build_argv(ctx, report_path="/tmp/out.json")
        assert argv == [
            "promptfoo",
            "eval",
            "-c",
            "promptfooconfig.yaml",
            "-o",
            "/tmp/out.json",
            "--no-cache",
        ]


# ---------------------------------------------------------------------------
# run(): resolution, statuses, and the fixtures end to end
# ---------------------------------------------------------------------------


class TestRun:
    def test_everything_on_path_runs_from_fixture_output(
        self, py_agent, audit_context, monkeypatch
    ):
        ctx = audit_context(multi_tool_tree(py_agent), options=ALL_OPTIONS)
        monkeypatch.setattr(adapters, "_module_available", lambda module: False)
        monkeypatch.setattr(shutil, "which", fake_which(missing={"osv-scanner"}))
        fake = FakeProcesses(stdout_for=full_stdout(), report_for=full_reports())
        monkeypatch.setattr(subprocess, "run", fake)

        results, findings, unknown = run_adapters(ctx, timeout=60)
        by_name = {r.name: r for r in results}
        assert list(by_name) == list(DEFAULT_TOOL_NAMES)

        expected = {
            "gitleaks": (Status.RAN, 2),
            "detect-secrets": (Status.NOT_APPLICABLE, 0),
            "pip-audit": (Status.RAN, 1),
            "npm-audit": (Status.RAN, 2),
            "osv-scanner": (Status.NOT_ON_PATH, 0),
            "mcp-scan": (Status.RAN, 1),
            "semgrep": (Status.RAN, 2),
            "promptfoo": (Status.RAN, 1),
        }
        for name, (status, count) in expected.items():
            row = by_name[name]
            assert row.status is status, name
            assert row.findings == count, name
            assert row.network == ADAPTERS[name].network_for(ctx), name
            if status is Status.RAN:
                assert row.version == "1.2.3", name
                assert row.argv[0].startswith(FAKE_BIN), name
                assert row.duration_ms is not None
        assert len(findings) == sum(count for _, count in expected.values())
        assert "--local-only" in by_name["mcp-scan"].argv
        assert by_name["mcp-scan"].network is False
        assert by_name["pip-audit"].network is True
        assert [u for u in unknown if u.category is UnknownCategory.TOOLS] == unknown
        assert len(unknown) == 1 and "osv-scanner" in unknown[0].why
        assert "aisg audit" in unknown[0].how_to_resolve

        for argv in fake.calls:
            assert Path(argv[0]).stem.lower() not in FORBIDDEN_LAUNCHERS
            assert "install" not in [t.lower() for t in argv]
        # unit facts come from the walk's file records, not from the tool
        walked = {record.relpath for record in ctx.files}
        located = [f for f in findings if f.scope.kind == "file" and f.scope.name in walked]
        assert located and all(f.scope.unit == "u0" for f in located)
        # run_adapters is pure with respect to the context
        assert ctx.external == []

    def test_detect_secrets_runs_only_without_gitleaks(self, py_agent, audit_context, monkeypatch):
        ctx = audit_context(py_agent, options=ALL_OPTIONS)
        monkeypatch.setattr(adapters, "_module_available", lambda module: False)
        monkeypatch.setattr(shutil, "which", fake_which(missing={"gitleaks"}))
        fake = FakeProcesses(stdout_for=full_stdout(), report_for=full_reports())
        monkeypatch.setattr(subprocess, "run", fake)
        results, findings, unknown = run_adapters(ctx, ["gitleaks", "detect-secrets"])
        by_name = {r.name: r for r in results}
        assert by_name["gitleaks"].status is Status.NOT_ON_PATH
        assert by_name["detect-secrets"].status is Status.RAN
        assert by_name["detect-secrets"].findings == 1
        assert findings[0].id == "AUD-501" and findings[0].location == ("secrets.py", 1)
        assert by_name["pip-audit"].status is Status.SKIPPED_BY_FLAG
        assert by_name["pip-audit"].flag == "--tools"
        assert [u.what for u in unknown] == ["secrets: regex-only"]

    def test_python_module_fallback_launches_the_interpreter(
        self, py_agent, audit_context, monkeypatch
    ):
        ctx = audit_context(py_agent, options=ALL_OPTIONS)
        monkeypatch.setattr(adapters, "_module_available", lambda module: module == "pip_audit")
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
        fake = FakeProcesses(stdout_for=full_stdout())
        monkeypatch.setattr(subprocess, "run", fake)
        result, findings, unknown = PipAuditAdapter().run(ctx)
        assert result.status is Status.RAN
        assert result.argv[:3] == (sys.executable, "-m", "pip_audit")
        assert "--no-deps" in result.argv
        assert len(findings) == 1

    def test_tool_secret_values_never_reach_a_finding(self, py_agent, audit_context, monkeypatch):
        secret = "sk-ant-" + "api03-" + "x" * 40
        payload = fixture_payload("gitleaks")
        payload[0]["Secret"] = secret
        payload[0]["Match"] = f'ANTHROPIC_API_KEY = "{secret}"'
        payload[0]["Line"] = payload[0]["Match"]
        ctx = audit_context(py_agent)
        monkeypatch.setattr(shutil, "which", fake_which())
        fake = FakeProcesses(report_for={"gitleaks": json.dumps(payload)})
        monkeypatch.setattr(subprocess, "run", fake)
        result, findings, unknown = GitleaksAdapter().run(ctx)
        assert result.status is Status.RAN and len(findings) == 2
        for finding in findings:
            assert secret not in finding_text(finding)
            assert "x" * 20 not in finding_text(finding)

    def test_promptfoo_needs_run_evals(self, py_agent, audit_context, isolate):
        (py_agent / "promptfooconfig.yaml").write_text("prompts: []\n")
        ctx = audit_context(py_agent, options=SimpleNamespace(run_evals=False))
        isolate()
        result, findings, unknown = PromptfooAdapter().run(ctx)
        assert result.status is Status.SKIPPED_NEEDS_FLAG
        assert result.flag == "--run-evals"
        assert result.network is True
        assert findings == []
        assert len(unknown) == 1
        assert unknown[0].category is UnknownCategory.TOOLS
        assert "--run-evals" in unknown[0].how_to_resolve

    def test_no_sockets_and_nothing_on_path(self, py_agent, audit_context, isolate):
        ctx = audit_context(multi_tool_tree(py_agent), options=ALL_OPTIONS)
        isolate()
        for name, adapter in ADAPTERS.items():
            result, findings, unknown = adapter.run(ctx, timeout=5)
            assert result.name == name
            assert findings == []
            assert result.status in (
                Status.NOT_ON_PATH,
                Status.NOT_APPLICABLE,
                Status.SKIPPED_NEEDS_FLAG,
            ), name
            if result.status is Status.NOT_ON_PATH:
                assert len(unknown) == 1, name
                assert unknown[0].category is UnknownCategory.TOOLS
                assert "aisg audit" in unknown[0].how_to_resolve
                assert adapter.install_hint in unknown[0].how_to_resolve
                assert unknown[0].rule_ids == adapter.rule_ids
            elif result.status is Status.NOT_APPLICABLE:
                assert unknown == [], name
        # everything on this tree is applicable, so every adapter reported the missing binary
        statuses = {name: ADAPTERS[name].run(ctx)[0].status for name in ADAPTERS}
        assert set(statuses.values()) == {Status.NOT_ON_PATH}

    def test_not_applicable_produces_no_unknown(self, tmp_path, audit_context, isolate):
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\nversion = "0"\n')
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "pkg.py").write_text("VALUE = 1\n")
        ctx = audit_context(tmp_path, options=ALL_OPTIONS)
        isolate()
        for name in ("npm-audit", "osv-scanner", "mcp-scan", "promptfoo"):
            result, findings, unknown = ADAPTERS[name].run(ctx)
            assert result.status is Status.NOT_APPLICABLE, name
            assert findings == [] and unknown == [], name

    def test_no_external_skips_everything_without_a_process(self, py_agent, audit_context, isolate):
        ctx = audit_context(multi_tool_tree(py_agent), options=ALL_OPTIONS)
        isolate()
        results, findings, unknown = run_adapters(ctx, no_external=True)
        assert len(results) == len(DEFAULT_TOOL_NAMES)
        assert {r.status for r in results} == {Status.SKIPPED_BY_FLAG}
        assert {r.flag for r in results} == {"--no-external"}
        assert findings == []
        assert len(unknown) == len(DEFAULT_TOOL_NAMES)
        assert {u.category for u in unknown} == {UnknownCategory.TOOLS}

    def test_tools_selection_rows_and_unknown_names(self, py_agent, audit_context, isolate):
        ctx = audit_context(py_agent, options=ALL_OPTIONS)
        isolate()
        results, findings, unknown = run_adapters(ctx, ["semgrep", "nonesuch"])
        by_name = {r.name: r for r in results}
        assert by_name["semgrep"].status is Status.NOT_ON_PATH
        skipped = [r for r in results if r.name != "semgrep"]
        assert {r.status for r in skipped} == {Status.SKIPPED_BY_FLAG}
        assert {r.flag for r in skipped} == {"--tools"}
        bad = [u for u in unknown if "nonesuch" in u.what]
        assert len(bad) == 1 and "--tools accepts" in bad[0].how_to_resolve
        assert len(unknown) == 2  # semgrep missing + the unknown name

    def test_timeout(self, py_agent, audit_context, monkeypatch):
        ctx = audit_context(py_agent)
        monkeypatch.setattr(shutil, "which", fake_which())

        def slow(argv, **kwargs):
            if is_version_probe(list(argv)):
                return subprocess.CompletedProcess(argv, 0, "1.2.3", "")
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"])

        monkeypatch.setattr(subprocess, "run", slow)
        result, findings, unknown = SemgrepAdapter().run(ctx, timeout=7)
        assert result.status is Status.TIMEOUT
        assert result.version == "1.2.3"
        assert findings == []
        assert len(unknown) == 1
        assert "--timeout 14" in unknown[0].how_to_resolve

    def test_crash_is_failed_with_stderr_tail(self, py_agent, audit_context, monkeypatch):
        ctx = audit_context(py_agent)
        monkeypatch.setattr(shutil, "which", fake_which())
        fake = FakeProcesses(returncode=2, stderr="fatal: cannot read config\n" + "x" * 500)
        monkeypatch.setattr(subprocess, "run", fake)
        result, findings, unknown = SemgrepAdapter().run(ctx)
        assert result.status is Status.FAILED
        assert "exit 2" in result.error
        assert "x" * 100 in result.error and "cannot read config" not in result.error
        assert len(result.error) < 400
        assert findings == []
        assert len(unknown) == 1 and unknown[0].category is UnknownCategory.TOOLS

    def test_launch_error_is_failed(self, py_agent, audit_context, monkeypatch):
        ctx = audit_context(py_agent)
        monkeypatch.setattr(shutil, "which", fake_which())

        def broken(argv, **kwargs):
            raise OSError("exec format error")

        monkeypatch.setattr(subprocess, "run", broken)
        result, findings, unknown = GitleaksAdapter().run(ctx)
        assert result.status is Status.FAILED
        assert "exec format error" in result.error
        assert findings == [] and len(unknown) == 1

    def test_nonzero_exit_with_json_is_ran(self, py_agent, audit_context, monkeypatch):
        ctx = audit_context(py_agent, options=ALL_OPTIONS)
        monkeypatch.setattr(shutil, "which", fake_which())
        fake = FakeProcesses(stdout_for=full_stdout(), returncode=1)
        monkeypatch.setattr(subprocess, "run", fake)
        result, findings, unknown = PipAuditAdapter().run(ctx)
        assert result.status is Status.RAN
        assert result.findings == 1 and len(findings) == 1
        assert unknown == []

    def test_mcp_scan_refuses_to_run_without_local_only(self, py_agent, audit_context, monkeypatch):
        ctx = audit_context(py_agent)
        monkeypatch.setattr(shutil, "which", fake_which())
        fake = FakeProcesses(
            returncode=2,
            stderr="usage: mcp-scan [-h] ...\nmcp-scan: error: unrecognized arguments: --local-only",
        )
        monkeypatch.setattr(subprocess, "run", fake)
        result, findings, unknown = McpScanAdapter().run(ctx)
        assert result.status is Status.FAILED
        assert result.error == "no local-only mode; refusing to upload tool descriptions"
        assert findings == []
        assert len(unknown) == 1 and "--local-only" in unknown[0].how_to_resolve
        assert all("--local-only" in argv for argv in fake.calls if not is_version_probe(argv))

    def test_unparseable_payload_shape_is_failed_not_a_crash(
        self, py_agent, audit_context, monkeypatch
    ):
        ctx = audit_context(py_agent)
        monkeypatch.setattr(shutil, "which", fake_which())
        monkeypatch.setattr(
            McpScanAdapter,
            "parse",
            lambda self, payload, **kw: (_ for _ in ()).throw(KeyError("x")),
        )
        fake = FakeProcesses(stdout_for={"mcp-scan": "{}"})
        monkeypatch.setattr(subprocess, "run", fake)
        result, findings, unknown = McpScanAdapter().run(ctx)
        assert result.status is Status.FAILED
        assert "KeyError" in result.error
        assert findings == [] and len(unknown) == 1


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


class TestVocabulary:
    @pytest.mark.parametrize(
        "path", [ADAPTERS_SRC, SEMGREP_RULES_PATH, Path(__file__)], ids=lambda p: p.name
    )
    def test_no_verdict_language(self, path):
        text = path.read_text(encoding="utf-8")
        text.encode("ascii")
        lowered = text.lower()
        for phrase in BANNED_PHRASES:
            assert phrase.lower() not in lowered, phrase
        assert not _BANNED_WORD.search(text)

    def test_unknown_items_name_commands_as_text(self):
        for adapter in ADAPTERS.values():
            item = adapter.unknown("why", f"{adapter.install_hint} && aisg audit .")
            assert item.category is UnknownCategory.TOOLS
            assert item.how_to_resolve.endswith("aisg audit .")
            assert item.rule_ids == adapter.rule_ids
