"""
tests/unit/test_audit_cli.py
----------------------------
End-to-end pins for `aisg audit` run in-process: exit codes, flag handling,
the document shape, baseline round-trip, pyproject defaults, and the two
properties that must never regress -- no socket is ever opened, and no output
carries verdict language. Most tests call `aisg.devtools.audit.main.main`
directly; the ones named `..._console_entry_...` (and the baseline and
pyproject-override pins) go through `aisg.cli.main` so the console script's
REMAINDER pass-through is on the path too.
"""

from __future__ import annotations

import importlib
import json
import re
import shutil
import socket
from pathlib import Path

import pytest

from aisg import cli
from aisg.devtools._config import find_pyproject
from aisg.devtools.audit import adapters, walk
from aisg.devtools.audit.main import (
    EXIT_FATAL,
    EXIT_FINDINGS,
    EXIT_INTERRUPTED,
    EXIT_OK,
    UNKNOWN_CATEGORIES,
    AuditOptions,
    build_parser,
    main,
    run_audit,
)
from aisg.devtools.audit.model import SCHEMA_VERSION, TRIFECTA_RULE_ID
from aisg.devtools.audit.report import BANNED_PHRASES, FORMATS
from aisg.devtools.audit.rules import rule_by_id

# The package's PEP 562 hook rebinds `aisg.devtools.audit.main` to the function,
# so the module object has to come from the import system directly.
audit_main = importlib.import_module("aisg.devtools.audit.main")

# Assembled at runtime so this file never spells the banned word itself.
BANNED_WORD = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)

LOW_RULE = "AUD-703"  # fires on py_agent at severity low


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """The audit must never talk to the network; any socket is a test failure."""

    def refuse(*args, **kwargs):
        raise AssertionError("aisg audit opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture(autouse=True)
def neutral_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Run from a directory without a pyproject so the repo's [tool.aisg-audit] stays out."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    assert find_pyproject() is None, "a pyproject.toml above the temp dir would leak defaults"
    return cwd


@pytest.fixture
def no_adapter_binaries(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every external tool is absent: not on PATH and not importable."""
    monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
    monkeypatch.setattr(adapters, "_module_available", lambda module: False)


@pytest.fixture
def no_adapters(monkeypatch: pytest.MonkeyPatch) -> None:
    """Adapters produce nothing at all, so only walk/discover/pydeep UNKNOWN items remain."""

    def nothing(ctx, names=None, *, timeout=120, no_external=False):
        return [], [], []

    monkeypatch.setattr(adapters, "run_adapters", nothing)


def _json_run(args: list[str], out: Path) -> tuple[int, dict]:
    code = main([*args, "--format", "json", "-o", str(out)])
    return code, json.loads(out.read_text(encoding="utf-8"))


def _assert_no_verdict_language(text: str) -> None:
    assert text.isascii(), "output must be ASCII"
    lowered = text.lower()
    for phrase in BANNED_PHRASES:
        assert phrase not in lowered, phrase
    assert not BANNED_WORD.search(text)


# ---------------------------------------------------------------------------
# Parser and options
# ---------------------------------------------------------------------------


def test_parser_defaults_match_the_design() -> None:
    parser = build_parser()
    assert parser.prog == "aisg audit"
    ns = parser.parse_args([])
    assert ns.path == "."
    assert ns.format == "terminal"
    assert ns.fail_on == "low"
    assert ns.fail_on_unknown is None
    assert ns.deep == "python"
    assert ns.timeout == 120
    assert ns.trusted_mcp_hosts == "localhost,127.0.0.1,::1"
    assert ns.redact is True
    assert ns.exclude is None
    options = AuditOptions.from_namespace(ns)
    assert options.trusted_mcp_hosts == ("localhost", "127.0.0.1", "::1")
    assert options.exclude == ()
    assert options.tools is None
    assert options.rules is None
    assert options.fail_on_unknown is None
    # adapters and discovery read these by name
    for name in ("run_evals", "pip_audit_env", "tools", "no_external", "timeout"):
        assert hasattr(options, name)
    for name in ("include_home", "trusted_mcp_hosts"):
        assert hasattr(options, name)


def test_parser_csv_flags_and_bare_fail_on_unknown() -> None:
    parser = build_parser()
    ns = parser.parse_args(
        [
            "--exclude",
            "a,b",
            "--exclude",
            "c",
            "--tools",
            "gitleaks, semgrep",
            "--rules",
            "AUD-301,AUD-101",
            "--fail-on-unknown",
        ]
    )
    options = AuditOptions.from_namespace(ns)
    assert options.exclude == ("a", "b", "c")
    assert options.tools == ("gitleaks", "semgrep")
    assert options.rules == ("AUD-301", "AUD-101")
    assert options.fail_on_unknown == frozenset(UNKNOWN_CATEGORIES)
    scoped = AuditOptions.from_namespace(parser.parse_args(["--fail-on-unknown", "tools,reports"]))
    assert scoped.fail_on_unknown == frozenset({"tools", "reports"})


def test_parser_rejects_bad_unknown_category() -> None:
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--fail-on-unknown", "bogus"])
    assert exc.value.code == EXIT_FATAL


def test_exit_constants() -> None:
    assert (EXIT_OK, EXIT_FINDINGS, EXIT_FATAL, EXIT_INTERRUPTED) == (0, 1, 2, 130)


# ---------------------------------------------------------------------------
# Reference run on py_agent
# ---------------------------------------------------------------------------


def test_json_run_on_py_agent(py_agent: Path, tmp_path: Path, capsys) -> None:
    out = tmp_path / "out.json"
    code, doc = _json_run([str(py_agent), "--no-external"], out)
    assert code == EXIT_FINDINGS
    assert list(doc)[0] == "schema"
    assert doc["schema"] == SCHEMA_VERSION
    assert doc["kind"] == "audit"
    assert doc["findings"], "py_agent must produce findings"
    assert doc["findings"][0]["rule_id"] == TRIFECTA_RULE_ID
    assert doc["findings"][0]["scope"]["kind"] == "function"
    assert doc["summary"]["exit_code"] == EXIT_FINDINGS
    for row in doc["external_tools"]:
        assert row["status"] == "skipped_by_flag", row
        assert row["flag"] == "--no-external"
    assert doc["measured"] == []
    assert len(doc["external_tools"]) == len(adapters.ADAPTERS)
    # -o with a machine format still prints the terminal summary
    captured = capsys.readouterr()
    assert "finding" in captured.out
    assert "written to" in captured.err
    _assert_no_verdict_language(captured.out)


def test_deep_none_widens_trifecta_scope_to_unit(py_agent: Path, tmp_path: Path) -> None:
    code, doc = _json_run([str(py_agent), "--no-external", "--deep", "none"], tmp_path / "o.json")
    assert code == EXIT_FINDINGS
    first = doc["findings"][0]
    assert first["rule_id"] == TRIFECTA_RULE_ID
    assert first["scope"]["kind"] == "unit"


def test_every_rule_is_unmeasured_in_the_document(py_agent: Path, tmp_path: Path) -> None:
    _, doc = _json_run([str(py_agent), "--no-external"], tmp_path / "o.json")
    assert doc["rules"], "catalogue must be present"
    assert all(entry["measured_precision"] is None for entry in doc["rules"])
    assert all(entry["ran"] for entry in doc["rules"])
    assert all(f["confidence"]["precision"] is None for f in doc["findings"])


@pytest.mark.parametrize("fmt", FORMATS)
def test_every_format_is_free_of_verdict_language(py_agent: Path, capsys, fmt: str) -> None:
    code = main([str(py_agent), "--no-external", "--format", fmt])
    assert code == EXIT_FINDINGS
    captured = capsys.readouterr()
    assert captured.out.strip()
    _assert_no_verdict_language(captured.out)
    _assert_no_verdict_language(captured.err)


def test_quiet_terminal_keeps_summary_and_unknown(py_agent: Path, capsys) -> None:
    main([str(py_agent), "--no-external", "-q"])
    quiet = capsys.readouterr().out
    main([str(py_agent), "--no-external"])
    full = capsys.readouterr().out
    assert "UNKNOWN" in quiet
    assert "skipped by --no-external" in quiet
    assert TRIFECTA_RULE_ID not in quiet
    assert TRIFECTA_RULE_ID in full
    assert len(quiet) < len(full)
    _assert_no_verdict_language(quiet)


def test_run_audit_accepts_audit_options_directly(py_agent: Path, tmp_path: Path) -> None:
    out = tmp_path / "direct.json"
    options = AuditOptions(path=str(py_agent), no_external=True, format="json", output=str(out))
    assert run_audit(options) == EXIT_FINDINGS
    assert json.loads(out.read_text(encoding="utf-8"))["schema"] == SCHEMA_VERSION


def test_console_entry_every_renderer_is_free_of_verdict_language(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    """
    The end-to-end pin from the carry-forward: through the `aisg audit` console
    entry, on the reference fixture, none of the five renderings (json, sarif,
    markdown, terminal full, terminal quiet) carries a banned phrase or the
    banned word -- and neither does anything printed to stdout or stderr on the way.
    """
    base = ["audit", str(py_agent), "--no-external"]
    rendered: dict[str, str] = {}
    for fmt in ("json", "sarif", "markdown"):
        out = tmp_path / f"report.{fmt}"
        assert cli.main([*base, "--format", fmt, "-o", str(out)]) == EXIT_FINDINGS
        captured = capsys.readouterr()
        rendered[fmt] = out.read_text(encoding="utf-8")
        rendered[f"{fmt}:stdout"] = captured.out
        rendered[f"{fmt}:stderr"] = captured.err
    assert cli.main(base) == EXIT_FINDINGS
    rendered["terminal"] = capsys.readouterr().out
    assert cli.main([*base, "-q"]) == EXIT_FINDINGS
    rendered["terminal:quiet"] = capsys.readouterr().out

    for fmt in ("json", "sarif", "markdown", "terminal", "terminal:quiet"):
        assert rendered[fmt].strip(), f"{fmt} rendering is empty"
    assert json.loads(rendered["json"])["findings"]
    assert json.loads(rendered["sarif"])["runs"][0]["results"]
    assert TRIFECTA_RULE_ID in rendered["terminal"]
    assert TRIFECTA_RULE_ID not in rendered["terminal:quiet"]
    for name, text in rendered.items():
        _assert_no_verdict_language(text)
        for phrase in BANNED_PHRASES:
            assert phrase not in text.lower(), (name, phrase)
        assert not BANNED_WORD.search(text), name


# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------


def test_reference_fixture_without_findings_exits_zero(audit_fixture, capsys) -> None:
    code = main([str(audit_fixture("clean_py")), "--no-external", "--fail-on", "high"])
    assert code == EXIT_OK
    _assert_no_verdict_language(capsys.readouterr().out)


def test_fail_on_never_disables_findings_but_not_unknown(py_agent: Path) -> None:
    assert main([str(py_agent), "--no-external", "--fail-on", "never"]) == EXIT_OK
    assert (
        main([str(py_agent), "--no-external", "--fail-on", "never", "--fail-on-unknown"])
        == EXIT_FINDINGS
    )


def test_fail_on_unknown_tools_when_no_adapter_is_installed(
    py_agent: Path, tmp_path: Path, no_adapter_binaries
) -> None:
    base = [str(py_agent), "--fail-on", "never"]
    assert main(base) == EXIT_OK
    code, doc = _json_run([*base, "--fail-on-unknown", "tools"], tmp_path / "o.json")
    assert code == EXIT_FINDINGS
    assert doc["summary"]["exit_code"] == EXIT_FINDINGS
    assert {row["status"] for row in doc["external_tools"]} <= {"not_on_path", "not_applicable"}
    assert any(item["category"] == "tools" for item in doc["unknown"])


def test_fail_on_unknown_scoped_ignores_other_categories(
    audit_fixture, tmp_path: Path, no_adapters
) -> None:
    # ts_agent has a TypeScript AI surface and no deep layer: a `deep` item only.
    base = [str(audit_fixture("ts_agent")), "--fail-on", "never"]
    code, doc = _json_run([*base, "--fail-on-unknown", "tools,reports"], tmp_path / "a.json")
    assert code == EXIT_OK
    assert {item["category"] for item in doc["unknown"]} == {"deep"}
    assert main([*base, "--fail-on-unknown", "deep"]) == EXIT_FINDINGS
    assert main([*base, "--fail-on-unknown"]) == EXIT_FINDINGS


def test_no_redact_is_refused(py_agent: Path, capsys) -> None:
    assert main([str(py_agent), "--no-redact"]) == EXIT_FATAL
    captured = capsys.readouterr()
    assert "redaction is not optional" in captured.err
    assert captured.out == ""


def test_missing_path_is_fatal(tmp_path: Path, capsys) -> None:
    assert main([str(tmp_path / "does-not-exist")]) == EXIT_FATAL
    assert "does not exist" in capsys.readouterr().err


def test_file_path_is_fatal(py_agent: Path, capsys) -> None:
    assert main([str(py_agent / "app.py")]) == EXIT_FATAL
    assert "not a directory" in capsys.readouterr().err


def test_keyboard_interrupt_maps_to_130(py_agent: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(walk, "walk", interrupt)
    assert main([str(py_agent), "--no-external"]) == EXIT_INTERRUPTED


def test_unexpected_exception_is_exit_2_with_one_line(
    py_agent: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    def explode(*args, **kwargs):
        raise RuntimeError("walker fell over")

    monkeypatch.setattr(walk, "walk", explode)
    assert main([str(py_agent), "--no-external"]) == EXIT_FATAL
    err = capsys.readouterr().err
    assert "RuntimeError: walker fell over" in err
    assert "Traceback" not in err
    assert main([str(py_agent), "--no-external", "--debug"]) == EXIT_FATAL
    assert "Traceback" in capsys.readouterr().err


def test_debug_template_self_check_is_fatal(
    py_agent: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    assert main([str(py_agent), "--no-external", "--debug", "--fail-on", "never"]) == EXIT_OK
    capsys.readouterr()
    monkeypatch.setattr(audit_main, "check_templates", lambda: ["placeholder phrase"])
    assert main([str(py_agent), "--no-external", "--debug"]) == EXIT_FATAL
    assert "placeholder phrase" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# Rules, listing, inventory
# ---------------------------------------------------------------------------


def test_list_rules(capsys) -> None:
    assert main(["--list-rules"]) == EXIT_OK
    out = capsys.readouterr().out
    assert TRIFECTA_RULE_ID in out
    assert "UNMEASURED" in out
    assert "measured_precision" in out
    _assert_no_verdict_language(out)


def test_rules_narrows_the_run_and_notes_unknown_ids(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    code, doc = _json_run(
        [str(py_agent), "--no-external", "--rules", f"{LOW_RULE},AUD-9999"], tmp_path / "o.json"
    )
    assert code == EXIT_FINDINGS
    assert {f["rule_id"] for f in doc["findings"]} == {LOW_RULE}
    ran = {entry["id"] for entry in doc["rules"] if entry["ran"]}
    assert ran == {LOW_RULE}
    assert "unknown rule id AUD-9999" in capsys.readouterr().err


def test_naming_a_demoted_rule_runs_it_with_a_note(
    py_agent: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    rule = rule_by_id(LOW_RULE)
    assert rule is not None
    # A measured value below MIN_PRECISION demotes the rule. Only a test may set one.
    monkeypatch.setattr(rule, "measured_precision", 0.1)
    assert main([str(py_agent), "--no-external", "--rules", LOW_RULE]) == EXIT_FINDINGS
    err = capsys.readouterr().err
    assert f"rule {LOW_RULE} is below MIN_PRECISION" in err
    code, doc = _json_run([str(py_agent), "--no-external"], tmp_path / "o.json")
    entry = next(e for e in doc["rules"] if e["id"] == LOW_RULE)
    assert entry["experimental"] is True
    assert entry["ran"] is False
    code, doc = _json_run([str(py_agent), "--no-external", "--experimental"], tmp_path / "e.json")
    entry = next(e for e in doc["rules"] if e["id"] == LOW_RULE)
    assert entry["ran"] is True


def test_inventory_only(py_agent: Path, capsys) -> None:
    assert main([str(py_agent), "--inventory-only"]) == EXIT_OK
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert list(doc)[:2] == ["schema", "kind"]
    assert doc["schema"] == SCHEMA_VERSION
    assert doc["kind"] == "inventory"
    assert doc["units"]
    assert "findings" not in doc
    _assert_no_verdict_language(out)


# ---------------------------------------------------------------------------
# Walk flags
# ---------------------------------------------------------------------------


def _tree_with_ignored_secret(tmp_path: Path) -> Path:
    """An AI surface at the root and a secret-shaped literal under a gitignored directory."""
    root = tmp_path / "ignored_tree"
    root.mkdir()
    (root / ".gitignore").write_text("local/\n", encoding="utf-8")
    (root / "app.py").write_text(
        "import anthropic\n\nclient = anthropic.Anthropic()\n"
        "resp = client.messages.create(model='claude-3', messages=[])\n",
        encoding="utf-8",
    )
    ignored = root / "local"
    ignored.mkdir()
    key = "AKIA" + "Q" * 16
    (ignored / "config.py").write_text(f'AWS_ACCESS_KEY_ID = "{key}"\n', encoding="utf-8")
    return root


def _evidence_files(doc: dict) -> set[str]:
    return {ev["file"] for finding in doc["findings"] for ev in finding["evidence"]}


def test_include_ignored_walks_gitignored_files(tmp_path: Path) -> None:
    root = _tree_with_ignored_secret(tmp_path)
    _, doc = _json_run([str(root), "--no-external", "--fail-on", "never"], tmp_path / "a.json")
    assert "local/config.py" not in _evidence_files(doc)
    _, doc = _json_run(
        [str(root), "--no-external", "--fail-on", "never", "--include-ignored"], tmp_path / "b.json"
    )
    assert "local/config.py" in _evidence_files(doc)
    flagged = [
        f for f in doc["findings"] if "local/config.py" in _evidence_files({"findings": [f]})
    ]
    assert all(f["gitignored"] is True for f in flagged)


def test_exclude_prunes_the_walk(py_agent: Path, tmp_path: Path) -> None:
    _, full = _json_run([str(py_agent), "--no-external"], tmp_path / "a.json")
    _, pruned = _json_run(
        [str(py_agent), "--no-external", "--exclude", "tools.py,secrets.py"], tmp_path / "b.json"
    )
    touched = {ev["file"] for f in pruned["findings"] for ev in f["evidence"]}
    assert "tools.py" not in touched
    assert "secrets.py" not in touched
    assert len(pruned["findings"]) < len(full["findings"])


# ---------------------------------------------------------------------------
# Baseline
# ---------------------------------------------------------------------------


def test_baseline_round_trip(py_agent: Path, tmp_path: Path, capsys) -> None:
    baseline = tmp_path / "baseline.json"
    assert main([str(py_agent), "--no-external", "--write-baseline", str(baseline)]) == EXIT_OK
    assert baseline.is_file()
    assert "baseline written" in capsys.readouterr().err
    code, doc = _json_run(
        [str(py_agent), "--no-external", "--baseline", str(baseline)], tmp_path / "o.json"
    )
    assert code == EXIT_OK
    assert doc["findings"]
    assert all(f["baseline_status"] == "unchanged" for f in doc["findings"])
    assert doc["baseline"]["new"] == 0
    assert doc["baseline"]["unchanged"] == len(doc["findings"])


def test_write_then_read_baseline_on_the_same_tree_exits_zero_at_fail_on_low(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    """
    `--write-baseline` then `--baseline` on an unchanged tree: nothing is new, so
    even the strictest counted level exits 0, and the terminal summary says so.
    """
    baseline = tmp_path / "baseline.json"
    assert (
        cli.main(["audit", str(py_agent), "--no-external", "--write-baseline", str(baseline)])
        == EXIT_OK
    )
    capsys.readouterr()
    read = [
        "audit",
        str(py_agent),
        "--no-external",
        "--baseline",
        str(baseline),
        "--fail-on",
        "low",
    ]
    assert cli.main(read) == EXIT_OK
    out = capsys.readouterr().out
    summary_line = next(ln for ln in out.splitlines() if ln.lower().startswith("baseline"))
    assert re.search(r"\b0 new\b", summary_line), summary_line
    assert "unchanged" in summary_line
    assert "[baseline: unchanged]" in out
    _assert_no_verdict_language(out)
    # the machine-readable summary carries the same counts
    code = cli.main([*read, "--format", "json", "-o", str(tmp_path / "read.json")])
    assert code == EXIT_OK
    doc = json.loads((tmp_path / "read.json").read_text(encoding="utf-8"))
    assert doc["baseline"]["new"] == 0
    assert doc["baseline"]["fixed"] == 0
    assert doc["baseline"]["unchanged"] == len(doc["findings"]) > 0


def test_full_report_serves_as_a_baseline(py_agent: Path, tmp_path: Path) -> None:
    code, _ = _json_run([str(py_agent), "--no-external"], tmp_path / "report.json")
    assert code == EXIT_FINDINGS
    code, doc = _json_run(
        [str(py_agent), "--no-external", "--baseline", str(tmp_path / "report.json")],
        tmp_path / "second.json",
    )
    assert code == EXIT_OK
    assert all(f["baseline_status"] == "unchanged" for f in doc["findings"])


def test_new_finding_against_baseline_counts(py_agent: Path, tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    main([str(py_agent), "--no-external", "--write-baseline", str(baseline)])
    key = "AKIA" + "R" * 16
    (py_agent / "extra.py").write_text(f'AWS_SECRET = "{key}"\n', encoding="utf-8")
    code, doc = _json_run(
        [str(py_agent), "--no-external", "--baseline", str(baseline)], tmp_path / "o.json"
    )
    assert code == EXIT_FINDINGS
    assert any(f["baseline_status"] == "new" for f in doc["findings"])
    assert doc["baseline"]["new"] >= 1


def test_bad_baseline_file_is_fatal(py_agent: Path, tmp_path: Path, capsys) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"kind": "something-else"}\n', encoding="utf-8")
    assert main([str(py_agent), "--no-external", "--baseline", str(bad)]) == EXIT_FATAL
    assert "baseline" in capsys.readouterr().err
    assert (
        main([str(py_agent), "--no-external", "--baseline", str(tmp_path / "nope")]) == EXIT_FATAL
    )


# ---------------------------------------------------------------------------
# pyproject defaults
# ---------------------------------------------------------------------------


def test_pyproject_section_is_honoured(py_agent: Path, neutral_cwd: Path) -> None:
    (neutral_cwd / "pyproject.toml").write_text(
        f'[tool.aisg-audit]\nfail-on = "high"\nrules = ["{LOW_RULE}"]\n', encoding="utf-8"
    )
    assert main([str(py_agent), "--no-external"]) == EXIT_OK
    assert main([str(py_agent), "--no-external", "--fail-on", "low"]) == EXIT_FINDINGS


def test_explicit_fail_on_overrides_pyproject_high(
    audit_fixture, neutral_cwd: Path, capsys
) -> None:
    """
    A cwd whose pyproject sets `fail-on = "high"` (the repo's own self-audit
    setting) is only a default: on `info_only`, the section leaves the single
    info finding uncounted, and `--fail-on info` on the command line counts it.
    """
    (neutral_cwd / "pyproject.toml").write_text(
        '[tool.aisg-audit]\nfail-on = "high"\n', encoding="utf-8"
    )
    target = str(audit_fixture("info_only"))
    assert cli.main(["audit", target, "--no-external"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "1 below --fail-on high" in out
    assert cli.main(["audit", target, "--no-external", "--fail-on", "info"]) == EXIT_FINDINGS
    out = capsys.readouterr().out
    assert "0 below --fail-on info" in out
    _assert_no_verdict_language(out)


def test_pyproject_list_values_become_csv(
    py_agent: Path, neutral_cwd: Path, tmp_path: Path
) -> None:
    (neutral_cwd / "pyproject.toml").write_text(
        '[tool.aisg-audit]\nfail-on = "never"\nfail-on-unknown = ["reports"]\n'
        'exclude = ["tools.py", "secrets.py"]\ntrusted-mcp-hosts = ["localhost", "mcp.internal"]\n',
        encoding="utf-8",
    )
    code, doc = _json_run([str(py_agent), "--no-external"], tmp_path / "o.json")
    assert code == EXIT_OK
    touched = {ev["file"] for f in doc["findings"] for ev in f["evidence"]}
    assert "tools.py" not in touched and "secrets.py" not in touched
    # an explicit flag wins, and a bare --fail-on-unknown means all four categories
    assert main([str(py_agent), "--no-external", "--fail-on-unknown"]) == EXIT_FINDINGS


def test_pyproject_boolean_fail_on_unknown(py_agent: Path, neutral_cwd: Path) -> None:
    (neutral_cwd / "pyproject.toml").write_text(
        '[tool.aisg-audit]\nfail-on = "never"\nfail-on-unknown = true\n', encoding="utf-8"
    )
    assert main([str(py_agent), "--no-external"]) == EXIT_FINDINGS


def test_repo_pyproject_carries_the_section() -> None:
    from aisg.devtools._config import load_tool_config

    repo_root = Path(__file__).resolve().parents[2]
    config = load_tool_config("aisg-audit", start=repo_root)
    assert config["fail_on"] == "high"
    assert config["exclude"] == "tests,src/aisg/probes"
