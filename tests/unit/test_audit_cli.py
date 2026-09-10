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
from aisg.devtools.audit.baseline import read_baseline
from aisg.devtools.audit.html import _T_BANNER_NO_RULES
from aisg.devtools.audit.main import (
    EXIT_FATAL,
    EXIT_FINDINGS,
    EXIT_INTERRUPTED,
    EXIT_OK,
    NOT_CONFIGURABLE,
    UNKNOWN_CATEGORIES,
    AuditOptions,
    build_parser,
    main,
    run_audit,
)
from aisg.devtools.audit.model import SCHEMA_VERSION, TRIFECTA_RULE_ID
from aisg.devtools.audit.patterns import OWN_HTML_MARKER_LINE
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
    assert ns.write_baseline is None
    assert ns.amend_baseline is None
    assert ns.accept is None
    options = AuditOptions.from_namespace(ns)
    assert options.trusted_mcp_hosts == ("localhost", "127.0.0.1", "::1")
    assert options.exclude == ()
    assert options.tools is None
    assert options.rules is None
    assert options.fail_on_unknown is None
    assert options.amend_baseline is None
    assert options.accept == ()
    repeated = AuditOptions.from_namespace(
        parser.parse_args(["--amend-baseline", "b.json", "--accept", "a=x", "--accept", "b=y"])
    )
    assert repeated.amend_baseline == "b.json"
    assert repeated.accept == ("a=x", "b=y")
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


def test_keyboard_interrupt_in_amend_baseline_maps_to_130(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
) -> None:
    """The amend path runs no scan, but it is inside the same interrupt mapping."""

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(audit_main, "amend_baseline", interrupt)
    args = ["audit", "--amend-baseline", str(tmp_path / "b.json"), "--accept", "0123abcd=a reason"]
    assert cli.main(args) == EXIT_INTERRUPTED
    assert "interrupted" in capsys.readouterr().err


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


def test_inventory_only_json_keeps_the_inventory_document(py_agent: Path, tmp_path: Path) -> None:
    out = tmp_path / "inv.json"
    code = main([str(py_agent), "--inventory-only", "--format", "json", "-o", str(out)])
    assert code == EXIT_OK
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert list(doc)[:2] == ["schema", "kind"]
    assert doc["kind"] == "inventory"
    assert "findings" not in doc


def test_inventory_only_html_renders_the_page_with_no_rule_ran(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    """`--format html` gets a page, not the inventory JSON: the no-rules banner over the inventory."""
    out = tmp_path / "inv.html"
    code = main([str(py_agent), "--inventory-only", "--format", "html", "-o", str(out)])
    assert code == EXIT_OK
    assert "inventory written to" in capsys.readouterr().err
    text = out.read_text(encoding="utf-8")
    assert text.splitlines()[0] == OWN_HTML_MARKER_LINE == "<!-- # aisg-audit: ignore-file -->"
    assert _T_BANNER_NO_RULES in text
    assert "0 of" in text and "rules ran" in text
    # the same counts the inventory document carries are on the page
    _, doc = _json_run([str(py_agent), "--inventory-only"], tmp_path / "inv.json")
    assert doc["units"]
    assert f"units: {len(doc['units'])}" in text
    assert f"llm_calls: {len(doc['llm_calls'])}" in text
    _assert_no_verdict_language(text)


@pytest.mark.parametrize("flag", ["--baseline", "--write-baseline"])
def test_inventory_only_refuses_a_baseline_flag(
    py_agent: Path, tmp_path: Path, capsys, flag: str
) -> None:
    """No rule runs under --inventory-only, so the flag would be silently ignored."""
    target = tmp_path / "b.json"
    assert main([str(py_agent), "--inventory-only", flag, str(target)]) == EXIT_FATAL
    captured = capsys.readouterr()
    assert flag in captured.err and "--inventory-only" in captured.err
    assert captured.out == ""
    assert not target.exists()


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
    # The report says what was not walked: two documents made from different working
    # directories (and so different `[tool.aisg-audit]` excludes) show the mismatch.
    assert full["target"]["exclude"] == []
    assert pruned["target"]["exclude"] == ["tools.py", "secrets.py"]


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
    assert doc["baseline"]["no_longer_reported"] == []
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
    # A report carries no reasons; the block says which kind of document was compared
    # so a renderer can say "the baseline was a report" instead of "none recorded".
    assert doc["baseline"]["kind"] == "audit"
    assert doc["baseline"]["accepted"] == []


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


def test_output_and_write_baseline_together_write_both_and_exit_zero(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    """`--write-baseline` no longer returns early: the report renders, both files land."""
    report = tmp_path / "report.json"
    baseline = tmp_path / "baseline.json"
    code = cli.main(
        [
            "audit",
            str(py_agent),
            "--no-external",
            "--format",
            "json",
            "-o",
            str(report),
            "--write-baseline",
            str(baseline),
        ]
    )
    assert code == EXIT_OK
    assert report.is_file() and baseline.is_file()
    captured = capsys.readouterr()
    assert "json report written to" in captured.err
    assert "baseline written to" in captured.err
    assert captured.err.index("report written") < captured.err.index("baseline written")
    assert "finding" in captured.out  # the quiet terminal summary still prints with -o
    doc = json.loads(report.read_text(encoding="utf-8"))
    assert doc["kind"] == "audit"
    # the rendered document keeps the judged code; only the process exit is 0
    assert doc["summary"]["exit_code"] == EXIT_FINDINGS
    written = json.loads(baseline.read_text(encoding="utf-8"))
    assert list(written) == [key for key in BASELINE_KEYS if key != "accepted"]
    assert written["kind"] == "audit-baseline"
    assert sorted(written["index"]) == written["fingerprints"]
    assert {f["fingerprint"] for f in doc["findings"]} == set(written["fingerprints"])
    _assert_no_verdict_language(captured.out)
    _assert_no_verdict_language(captured.err)


def test_write_baseline_without_output_still_renders_the_report(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    baseline = tmp_path / "baseline.json"
    assert main([str(py_agent), "--no-external", "--write-baseline", str(baseline)]) == EXIT_OK
    captured = capsys.readouterr()
    assert TRIFECTA_RULE_ID in captured.out
    assert "baseline written to" in captured.err
    _assert_no_verdict_language(captured.out)


def test_write_baseline_creates_the_target_directory(
    py_agent: Path, neutral_cwd: Path, capsys
) -> None:
    """
    `.aisg-audit/` usually does not exist on the first run. The write comes after the
    scan and the render, so a missing directory used to surface as a raw fatal error
    once all the work was done; the parent is created like `-o` does.
    """
    target = neutral_cwd / "sub" / "dir" / "b.json"
    assert not target.parent.exists()
    code = main([str(py_agent), "--no-external", "--write-baseline", "sub/dir/b.json"])
    assert code == EXIT_OK
    captured = capsys.readouterr()
    assert TRIFECTA_RULE_ID in captured.out
    assert "baseline written to sub/dir/b.json" in captured.err
    assert "fatal" not in captured.err
    document = read_baseline(target)
    assert document.kind == "audit-baseline" and document.fingerprints


def test_output_and_write_baseline_at_one_path_is_refused_before_the_scan(
    py_agent: Path, neutral_cwd: Path, tmp_path: Path, capsys, monkeypatch
) -> None:
    """
    The baseline is written after the report: one path would hold the baseline while
    stderr said both were written. Refused up front, so nothing is scanned or written.
    """

    def no_scan(*args, **kwargs):
        raise AssertionError("a refused run must not scan")

    build_context = audit_main._build_context
    monkeypatch.setattr(audit_main, "_build_context", no_scan)
    absolute = tmp_path / "same.json"
    relative = neutral_cwd / "same.json"
    # The same file spelled twice the same way, then once relative to the cwd: the check
    # resolves both sides rather than comparing the strings.
    for output, write_baseline, target in (
        (str(absolute), str(absolute), absolute),
        ("same.json", str(relative), relative),
    ):
        args = [str(py_agent), "--no-external", "-o", output, "--write-baseline", write_baseline]
        assert main(args) == EXIT_FATAL
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "--output" in captured.err and "--write-baseline" in captured.err
        assert "different paths" in captured.err
        assert "report written to" not in captured.err
        assert "baseline written to" not in captured.err
        assert not target.exists()
        _assert_no_verdict_language(captured.err)
    # Two different files are fine, and both land.
    monkeypatch.setattr(audit_main, "_build_context", build_context)
    report = tmp_path / "report.json"
    baseline = tmp_path / "baseline.json"
    args = [str(py_agent), "--no-external", "--format", "json", "-o", str(report)]
    assert main([*args, "--write-baseline", str(baseline)]) == EXIT_OK
    assert json.loads(report.read_text(encoding="utf-8"))["kind"] == "audit"
    assert read_baseline(baseline).kind == "audit-baseline"


# ---------------------------------------------------------------------------
# --amend-baseline / --accept
# ---------------------------------------------------------------------------

BASELINE_KEYS = ["schema", "kind", "generated_at", "tool", "fingerprints", "accepted", "index"]
REASON = "third-party sandbox owns the shell; tracked in ticket 42"


def _baseline_for(py_agent: Path, tmp_path: Path) -> tuple[Path, dict]:
    """Write a baseline for the fixture and return its path with the parsed document."""
    baseline = tmp_path / "baseline.json"
    assert main([str(py_agent), "--no-external", "--write-baseline", str(baseline)]) == EXIT_OK
    return baseline, json.loads(baseline.read_text(encoding="utf-8"))


def _amend(baseline: Path, *accepts: str) -> int:
    args = ["--amend-baseline", str(baseline)]
    for item in accepts:
        args += ["--accept", item]
    return main(args)


def test_amend_baseline_records_a_reason_with_rule_and_file_from_the_index(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    baseline, before = _baseline_for(py_agent, tmp_path)
    capsys.readouterr()
    fingerprint = before["fingerprints"][0]

    assert _amend(baseline, f"{fingerprint}={REASON}") == EXIT_OK

    captured = capsys.readouterr()
    assert "amended" in captured.err and "1 reason" in captured.err
    assert "no scan ran" in captured.err
    assert captured.out == ""  # no render
    _assert_no_verdict_language(captured.err)
    after = json.loads(baseline.read_text(encoding="utf-8"))
    assert list(after) == BASELINE_KEYS
    assert after["fingerprints"] == before["fingerprints"]
    assert after["index"] == before["index"]
    assert after["accepted"] == [
        {
            "fingerprint": fingerprint,
            "rule": before["index"][fingerprint]["rule"],
            "file": before["index"][fingerprint]["file"],
            "reason": REASON,
        }
    ]


def test_amend_baseline_replaces_the_reason_on_repeat_and_keeps_others(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    baseline, before = _baseline_for(py_agent, tmp_path)
    first, second = before["fingerprints"][:2]
    assert _amend(baseline, f"{first}=first reason", f"{second}=second reason") == EXIT_OK
    assert "2 reasons" in capsys.readouterr().err

    assert _amend(baseline, f"{first}=revised reason") == EXIT_OK

    after = json.loads(baseline.read_text(encoding="utf-8"))
    assert [(e["fingerprint"], e["reason"]) for e in after["accepted"]] == [
        (first, "revised reason"),
        (second, "second reason"),
    ]
    assert list(after) == BASELINE_KEYS


def test_amend_baseline_accepts_a_reason_containing_an_equals_sign(
    py_agent: Path, tmp_path: Path
) -> None:
    baseline, before = _baseline_for(py_agent, tmp_path)
    fingerprint = before["fingerprints"][0]
    assert _amend(baseline, f"{fingerprint}=x = y; see ticket") == EXIT_OK
    after = json.loads(baseline.read_text(encoding="utf-8"))
    assert after["accepted"][0]["reason"] == "x = y; see ticket"


def _refused_reasons() -> list[tuple[str, str]]:
    banned_word = "cl" + "ean"
    secret = "sk-ant-" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4"
    cases = [
        ("empty", ""),
        ("whitespace", "   "),
        ("non-ascii", "caf" + chr(0xE9) + " review"),
        ("newline", "sandbox owns the shell\nsee ticket 42"),
        ("carriage-return", "sandbox owns the shell\rsee ticket 42"),
        ("tab", "sandbox owns the shell\tsee ticket 42"),
        ("escape", "sandbox owns the shell \x1b[0m see ticket 42"),
        ("delete", "sandbox owns the shell \x7f see ticket 42"),
        ("banned-word", f"the target is {banned_word} now"),
        ("secret-shaped", f"token {secret} is a test key"),
    ]
    for i, phrase in enumerate(BANNED_PHRASES):
        cases.append((f"banned-phrase-{i}", f"reviewed: it {phrase}"))
    return cases


@pytest.mark.parametrize(("label", "reason"), _refused_reasons())
def test_amend_baseline_refuses_a_reason_it_cannot_record(
    py_agent: Path, tmp_path: Path, capsys, label: str, reason: str
) -> None:
    baseline, before = _baseline_for(py_agent, tmp_path)
    capsys.readouterr()
    fingerprint = before["fingerprints"][0]

    assert _amend(baseline, f"{fingerprint}={reason}") == EXIT_FATAL

    err = capsys.readouterr().err
    assert "baseline error:" in err
    assert fingerprint in err
    assert reason.strip() == "" or reason not in err, "a refused reason is never echoed"
    _assert_no_verdict_language(err)
    assert json.loads(baseline.read_text(encoding="utf-8")) == before


def test_amend_baseline_refuses_a_multi_line_reason_by_name(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    """
    A newline is ASCII, so the ASCII check let it through, and the reason is rendered as
    one `accepted: <reason>` line in terminal and markdown (a newline breaks out of the
    markdown list item). The refusal says what shape a reason must have.
    """
    baseline, before = _baseline_for(py_agent, tmp_path)
    capsys.readouterr()
    fingerprint = before["fingerprints"][0]

    assert _amend(baseline, f"{fingerprint}=first line\n- second line") == EXIT_FATAL

    err = capsys.readouterr().err
    assert "baseline error:" in err and fingerprint in err
    assert "single line of printable ASCII" in err
    assert "second line" not in err
    assert json.loads(baseline.read_text(encoding="utf-8")) == before


def test_amend_baseline_refuses_an_unknown_fingerprint_and_writes_nothing(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    baseline, before = _baseline_for(py_agent, tmp_path)
    known = before["fingerprints"][0]
    capsys.readouterr()

    code = _amend(baseline, f"{known}={REASON}", "0123456789abcdef=not in this baseline")

    assert code == EXIT_FATAL
    err = capsys.readouterr().err
    assert "baseline error:" in err and "0123456789abcdef" in err
    assert "--write-baseline" in err
    # the valid accept before the bad one was not written either
    assert json.loads(baseline.read_text(encoding="utf-8")) == before


def test_amend_baseline_refuses_a_report(py_agent: Path, tmp_path: Path, capsys) -> None:
    report = tmp_path / "report.json"
    code, doc = _json_run([str(py_agent), "--no-external"], report)
    assert code == EXIT_FINDINGS
    fingerprint = doc["findings"][0]["fingerprint"]
    capsys.readouterr()

    assert _amend(report, f"{fingerprint}={REASON}") == EXIT_FATAL

    err = capsys.readouterr().err
    assert "baseline error:" in err and "audit-baseline" in err
    assert json.loads(report.read_text(encoding="utf-8")) == doc


def test_amend_baseline_refuses_a_malformed_accept(py_agent: Path, tmp_path: Path, capsys) -> None:
    baseline, before = _baseline_for(py_agent, tmp_path)
    capsys.readouterr()
    assert _amend(baseline, "no-equals-sign-here") == EXIT_FATAL
    err = capsys.readouterr().err
    assert "baseline error:" in err and "FINGERPRINT=REASON" in err
    assert json.loads(baseline.read_text(encoding="utf-8")) == before


def test_accept_without_amend_baseline_is_fatal(py_agent: Path, capsys) -> None:
    code = main([str(py_agent), "--no-external", "--accept", f"0123456789abcdef={REASON}"])
    assert code == EXIT_FATAL
    captured = capsys.readouterr()
    assert "--amend-baseline" in captured.err
    assert captured.out == ""  # no scan ran


def test_amend_baseline_without_accept_is_fatal(py_agent: Path, tmp_path: Path, capsys) -> None:
    baseline, before = _baseline_for(py_agent, tmp_path)
    capsys.readouterr()
    assert main(["--amend-baseline", str(baseline)]) == EXIT_FATAL
    captured = capsys.readouterr()
    assert "--accept" in captured.err
    assert captured.out == ""
    assert json.loads(baseline.read_text(encoding="utf-8")) == before


def test_amend_baseline_missing_file_is_fatal(tmp_path: Path, capsys) -> None:
    assert _amend(tmp_path / "absent.json", f"0123456789abcdef={REASON}") == EXIT_FATAL
    assert "baseline error:" in capsys.readouterr().err


def test_amend_baseline_runs_no_scan(py_agent: Path, tmp_path: Path, monkeypatch) -> None:
    baseline, before = _baseline_for(py_agent, tmp_path)

    def no_walk(*args, **kwargs):
        raise AssertionError("--amend-baseline must not scan")

    monkeypatch.setattr(walk, "walk", no_walk)
    monkeypatch.setattr(audit_main, "_build_context", no_walk)
    assert _amend(baseline, f"{before['fingerprints'][0]}={REASON}") == EXIT_OK


def test_baseline_run_on_an_amended_baseline_stamps_the_reason(
    py_agent: Path, tmp_path: Path
) -> None:
    baseline, before = _baseline_for(py_agent, tmp_path)
    fingerprint = before["fingerprints"][0]
    assert _amend(baseline, f"{fingerprint}={REASON}") == EXIT_OK

    code, doc = _json_run(
        [str(py_agent), "--no-external", "--baseline", str(baseline)], tmp_path / "o.json"
    )

    assert code == EXIT_OK
    stamped = [f for f in doc["findings"] if f["fingerprint"] == fingerprint]
    assert len(stamped) == 1
    assert stamped[0]["accepted_reason"] == REASON
    keys = list(stamped[0])
    assert keys[keys.index("baseline_status") + 1] == "accepted_reason"
    assert all("accepted_reason" not in f for f in doc["findings"] if f is not stamped[0])
    block = doc["baseline"]
    assert list(block) == [
        "file",
        "kind",
        "new",
        "unchanged",
        "accepted",
        "generated_at",
        "no_longer_reported",
    ]
    assert block["kind"] == "audit-baseline"
    assert block["accepted"] == [
        {
            "fingerprint": fingerprint,
            "rule": before["index"][fingerprint]["rule"],
            "file": before["index"][fingerprint]["file"],
            "reason": REASON,
        }
    ]
    assert block["generated_at"] == before["generated_at"]
    assert block["no_longer_reported"] == []


def test_no_longer_reported_names_rule_file_and_title(py_agent: Path, tmp_path: Path) -> None:
    baseline, before = _baseline_for(py_agent, tmp_path)
    gone = [fp for fp, entry in before["index"].items() if entry["file"].startswith("secrets.py")]
    assert gone, "the secret-shaped literals in secrets.py must be in the baseline"
    (py_agent / "secrets.py").unlink()

    code, doc = _json_run(
        [str(py_agent), "--no-external", "--baseline", str(baseline)], tmp_path / "o.json"
    )

    assert code == EXIT_OK
    block = doc["baseline"]
    assert "fixed" not in block  # the list is the count; nothing calls the absence a fix
    assert len(block["no_longer_reported"]) >= len(gone)
    for entry in block["no_longer_reported"]:
        assert list(entry) == ["fingerprint", "rule", "file", "title"]
        assert entry == {
            "fingerprint": entry["fingerprint"],
            **before["index"][entry["fingerprint"]],
        }
    assert {e["fingerprint"] for e in block["no_longer_reported"]} >= set(gone)


def test_baseline_without_an_index_lists_only_the_fingerprint(
    py_agent: Path, tmp_path: Path
) -> None:
    """An older baseline (no `index`) still diffs; `no_longer_reported` then has no names."""
    baseline, before = _baseline_for(py_agent, tmp_path)
    old = {k: v for k, v in before.items() if k != "index"}
    baseline.write_text(json.dumps(old, indent=2) + "\n", encoding="utf-8")
    (py_agent / "secrets.py").unlink()

    code, doc = _json_run(
        [str(py_agent), "--no-external", "--baseline", str(baseline)], tmp_path / "o.json"
    )

    assert code == EXIT_OK
    assert len(doc["baseline"]["no_longer_reported"]) >= 1
    assert all(list(e) == ["fingerprint"] for e in doc["baseline"]["no_longer_reported"])


# ---------------------------------------------------------------------------
# --write-baseline carries reasons over
# ---------------------------------------------------------------------------


def _refresh(py_agent: Path, compared: Path, target: Path) -> int:
    return main(
        [
            str(py_agent),
            "--no-external",
            "--baseline",
            str(compared),
            "--write-baseline",
            str(target),
        ]
    )


def test_write_baseline_refresh_keeps_the_amended_reason(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    """write, accept, write again onto the same file: the reason survives the refresh."""
    baseline, before = _baseline_for(py_agent, tmp_path)
    fingerprint = before["fingerprints"][0]
    assert _amend(baseline, f"{fingerprint}={REASON}") == EXIT_OK
    capsys.readouterr()

    assert _refresh(py_agent, baseline, baseline) == EXIT_OK

    captured = capsys.readouterr()
    assert "baseline written to" in captured.err
    assert "1 reason carried over" in captured.err
    assert "not carried" not in captured.err
    document = read_baseline(baseline)
    assert document.accepted == {fingerprint: REASON}
    assert document.fingerprints == set(before["fingerprints"])
    after = json.loads(baseline.read_text(encoding="utf-8"))
    assert list(after) == BASELINE_KEYS
    assert after["accepted"][0]["rule"] == before["index"][fingerprint]["rule"]
    _assert_no_verdict_language(captured.err)


def test_write_baseline_to_a_new_path_carries_reasons_from_the_compared_baseline(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    old, before = _baseline_for(py_agent, tmp_path)
    fingerprint = before["fingerprints"][0]
    assert _amend(old, f"{fingerprint}={REASON}") == EXIT_OK
    new = tmp_path / "new.json"
    assert not new.exists()

    assert _refresh(py_agent, old, new) == EXIT_OK

    assert read_baseline(new).accepted == {fingerprint: REASON}
    assert read_baseline(old).accepted == {fingerprint: REASON}  # the compared file is untouched
    assert "1 reason carried over" in capsys.readouterr().err


def test_write_baseline_without_reasons_to_carry_writes_no_accepted_key(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    baseline, _before = _baseline_for(py_agent, tmp_path)
    assert _refresh(py_agent, baseline, baseline) == EXIT_OK
    assert "0 reasons carried over" in capsys.readouterr().err
    assert "accepted" not in json.loads(baseline.read_text(encoding="utf-8"))


def test_write_baseline_drops_a_reason_whose_fingerprint_is_no_longer_reported(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    baseline, before = _baseline_for(py_agent, tmp_path)
    kept = next(fp for fp, e in before["index"].items() if not e["file"].startswith("secrets.py"))
    gone = next(fp for fp, e in before["index"].items() if e["file"].startswith("secrets.py"))
    code = _amend(baseline, f"{kept}={REASON}", f"{gone}=fixture key assembled at runtime")
    assert code == EXIT_OK
    (py_agent / "secrets.py").unlink()
    capsys.readouterr()

    assert _refresh(py_agent, baseline, baseline) == EXIT_OK

    err = capsys.readouterr().err
    assert "1 reason carried over" in err
    assert "1 not carried" in err and "no longer reported" in err
    document = read_baseline(baseline)
    assert document.accepted == {kept: REASON}
    assert gone not in document.fingerprints
    _assert_no_verdict_language(err)


def test_write_baseline_onto_a_file_that_is_not_a_baseline_is_refused(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    target = tmp_path / "notes.json"
    target.write_text('{"x": 1}\n', encoding="utf-8")

    code = main([str(py_agent), "--no-external", "--write-baseline", str(target)])

    assert code == EXIT_FATAL
    captured = capsys.readouterr()
    assert "notes.json" in captured.err and "not an audit-baseline" in captured.err
    assert "pick another path" in captured.err
    assert "\n" not in captured.err.strip()
    assert captured.out == ""  # refused before the scan, nothing rendered
    assert target.read_text(encoding="utf-8") == '{"x": 1}\n'


def test_write_baseline_onto_a_full_report_is_refused(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    """A report is another kind of document; overwriting it with a baseline loses the report."""
    report = tmp_path / "report.json"
    code, doc = _json_run([str(py_agent), "--no-external"], report)
    assert code == EXIT_FINDINGS
    capsys.readouterr()
    assert main([str(py_agent), "--no-external", "--write-baseline", str(report)]) == EXIT_FATAL
    assert "not an audit-baseline" in capsys.readouterr().err
    assert json.loads(report.read_text(encoding="utf-8")) == doc


def test_write_baseline_compared_against_a_report_carries_no_reasons(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    """A report used as --baseline has no reasons to carry; the refresh must not trip on it."""
    report = tmp_path / "report.json"
    code, _ = _json_run([str(py_agent), "--no-external"], report)
    assert code == EXIT_FINDINGS
    new = tmp_path / "new.json"

    assert _refresh(py_agent, report, new) == EXIT_OK

    assert "0 reasons carried over" in capsys.readouterr().err
    document = read_baseline(new)
    assert document.kind == "audit-baseline" and document.accepted == {}
    assert "accepted" not in json.loads(new.read_text(encoding="utf-8"))


def test_write_baseline_prefers_the_compared_reason_over_the_refreshed_one(
    py_agent: Path, tmp_path: Path
) -> None:
    """Both files carry a reason for one fingerprint: the document named by --baseline wins."""
    compared, before = _baseline_for(py_agent, tmp_path)
    fingerprint = before["fingerprints"][0]
    assert _amend(compared, f"{fingerprint}=the compared reason") == EXIT_OK
    target = tmp_path / "target.json"
    assert main([str(py_agent), "--no-external", "--write-baseline", str(target)]) == EXIT_OK
    assert _amend(target, f"{fingerprint}=the refreshed reason") == EXIT_OK

    assert _refresh(py_agent, compared, target) == EXIT_OK

    assert read_baseline(target).accepted == {fingerprint: "the compared reason"}


# ---------------------------------------------------------------------------
# The double run: the audit's own output inside the tree is not audited again
# ---------------------------------------------------------------------------


def _double_run(py_agent: Path, fmt: str, out_name: str) -> dict:
    own = py_agent / ".aisg-audit"
    report = own / out_name
    baseline = own / "baseline.json"
    first = [
        str(py_agent),
        "--no-external",
        "--fail-on",
        "high",
        "--format",
        fmt,
        "-o",
        str(report),
        "--write-baseline",
        str(baseline),
    ]
    assert main(first) == EXIT_OK
    assert report.is_file() and baseline.is_file()
    code, doc = _json_run(
        [str(py_agent), "--no-external", "--fail-on", "high", "--baseline", str(baseline)],
        py_agent.parent / "second.json",
    )
    assert code == EXIT_OK
    return doc


def test_double_run_json_report_is_skipped_as_own_output(py_agent: Path) -> None:
    doc = _double_run(py_agent, "json", "report.json")
    assert doc["summary"]["baseline_new"] == 0
    assert doc["baseline"]["new"] == 0
    assert doc["inventory"]["own_output_skipped"] == [".aisg-audit/report.json"]
    touched = {ev["file"] for f in doc["findings"] for ev in f["evidence"]}
    assert not any(path.startswith(".aisg-audit/") for path in touched)


def test_html_output_starts_with_the_marker_line_lf_only_and_no_bom(
    py_agent: Path, tmp_path: Path
) -> None:
    """`_write_output` writes with newline="\\n": a Windows run yields the same bytes as CI."""
    out = tmp_path / "out.html"
    code = main([str(py_agent), "--no-external", "--format", "html", "-o", str(out)])
    assert code == EXIT_FINDINGS
    raw = out.read_bytes()
    assert raw.startswith(b"<!-- # aisg-audit: ignore-file -->\n")
    assert b"\r" not in raw
    assert not raw.startswith(b"\xef\xbb\xbf")


@pytest.mark.skipif("html" not in FORMATS, reason="html renderer not shipped yet")
def test_double_run_html_report_is_skipped_by_its_marker(py_agent: Path) -> None:
    doc = _double_run(py_agent, "html", "report.html")
    assert doc["summary"]["baseline_new"] == 0
    # The html carries the ignore marker on line 1. `walk.is_own_html` recognises that
    # exact line and lists the page as own output, like the JSON report: the skip is
    # visible in the inventory, not a silent ignore-file skip.
    assert doc["inventory"]["own_output_skipped"] == [".aisg-audit/report.html"]
    touched = {ev["file"] for f in doc["findings"] for ev in f["evidence"]}
    assert not any(path.startswith(".aisg-audit/") for path in touched)


def test_oversize_files_are_counted_and_listed_under_unknown(
    py_agent: Path, tmp_path: Path, capsys
) -> None:
    """
    A file over the size limit is never opened, so nothing in it was audited. The
    walk hands the paths to `main`, which records the count on the inventory next to
    `skipped_files`; the walk's own UNKNOWN row names the file. A run with nothing over
    the limit prints 0, not "not recorded": the count was taken.
    """
    code, doc = _json_run([str(py_agent), "--no-external"], tmp_path / "small.json")
    assert code == EXIT_FINDINGS
    assert doc["inventory"]["target"]["oversize_files"] == 0
    assert not [u for u in doc["unknown"] if u["what"] == "oversize files skipped"]
    main([str(py_agent), "--no-external"])
    assert "oversize files skipped: 0" in capsys.readouterr().out

    (py_agent / "big.py").write_bytes(b"#" * (walk.DEFAULT_MAX_SIZE + 1))
    code, doc = _json_run([str(py_agent), "--no-external"], tmp_path / "big.json")
    assert code == EXIT_FINDINGS
    assert doc["inventory"]["target"]["oversize_files"] == 1
    rows = [u for u in doc["unknown"] if u["what"] == "oversize files skipped"]
    assert len(rows) == 1 and rows[0]["category"] == "runtime"
    assert "big.py" in rows[0]["why"]
    main([str(py_agent), "--no-external"])
    assert "oversize files skipped: 1" in capsys.readouterr().out


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


def test_not_configurable_names_every_per_invocation_action() -> None:
    """
    The five dests a pyproject may never set. `write-baseline` would make every run
    rewrite a file and exit 0; `inventory-only` and `list-rules` would make every run
    skip the rules, and a `true` boolean there has no flag to switch it back off.
    """
    assert NOT_CONFIGURABLE == {
        "amend_baseline",
        "accept",
        "write_baseline",
        "inventory_only",
        "list_rules",
    }
    actions = {action.dest: action for action in build_parser()._actions}
    assert NOT_CONFIGURABLE <= set(actions)
    # `--accept` says "with --amend-baseline" instead; the other four say so themselves.
    for dest in ("write_baseline", "amend_baseline", "inventory_only", "list_rules"):
        assert "(not settable from pyproject)" in str(actions[dest].help), dest


def _pyproject_lines(baseline: Path, fingerprint: str, target: Path) -> dict[str, str]:
    """One `[tool.aisg-audit]` line per key a pyproject must not be able to set."""
    posix = str(baseline).replace("\\", "/")
    target_posix = str(target).replace("\\", "/")
    return {
        "amend-baseline": f'amend-baseline = "{posix}"',
        "accept": f'accept = ["{fingerprint}={REASON}"]',
        "write-baseline": f'write-baseline = "{target_posix}"',
        "inventory-only": "inventory-only = true",
        "list-rules": "list-rules = true",
    }


@pytest.mark.parametrize(
    "keys",
    [
        ("amend-baseline", "accept"),
        ("write-baseline",),
        ("inventory-only",),
        ("list-rules",),
        ("amend-baseline", "accept", "write-baseline", "inventory-only", "list-rules"),
    ],
    ids=lambda keys: "+".join(keys),
)
def test_pyproject_cannot_set_a_per_invocation_action(
    py_agent: Path, neutral_cwd: Path, tmp_path: Path, capsys, keys: tuple[str, ...]
) -> None:
    """
    Recording a reason, writing a baseline, skipping the rules or printing the catalogue
    are actions, not defaults: each key is ignored from pyproject and the run is the same
    as without it -- exit 1 on the fixture, findings printed, nothing written.
    """
    baseline, before = _baseline_for(py_agent, tmp_path)
    fingerprint = before["fingerprints"][0]
    target = tmp_path / "from-pyproject.json"
    lines = _pyproject_lines(baseline, fingerprint, target)
    (neutral_cwd / "pyproject.toml").write_text(
        "[tool.aisg-audit]\n" + "\n".join(lines[key] for key in keys) + "\n", encoding="utf-8"
    )
    capsys.readouterr()

    assert main([str(py_agent), "--no-external"]) == EXIT_FINDINGS  # a scan ran and counted

    captured = capsys.readouterr()
    assert TRIFECTA_RULE_ID in captured.out  # findings, not the inventory or the catalogue
    assert "rules. measured_precision" not in captured.out  # --list-rules footer
    assert not captured.out.lstrip().startswith("{")  # --inventory-only document
    assert "amended" not in captured.err
    assert "baseline written" not in captured.err
    assert not target.exists()
    assert json.loads(baseline.read_text(encoding="utf-8")) == before
    assert "accepted" not in before


def test_repo_pyproject_carries_the_section() -> None:
    from aisg.devtools._config import load_tool_config

    repo_root = Path(__file__).resolve().parents[2]
    config = load_tool_config("aisg-audit", start=repo_root)
    assert config["fail_on"] == "high"
    assert config["exclude"] == "tests,src/aisg/probes"
