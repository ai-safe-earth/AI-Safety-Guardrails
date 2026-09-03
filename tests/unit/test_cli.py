"""tests/unit/test_cli.py
----------------------
Pins for the `aisg` console script: every subcommand is registered and listed,
`--help` reaches each tool's own parser through the REMAINDER pass-through,
`audit` and `skill` are imported only when invoked, and the exit codes of the
wrapped tools come back unchanged.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from aisg import __version__, cli
from aisg.devtools._config import find_pyproject

EXPECTED_COMMANDS = ("lint", "misalign", "init", "probe", "measure", "audit", "skill")

# The subcommand parsers keep their own prog names; `--help` output starts with it.
PROG_BY_COMMAND = {
    "lint": "euaiact-lint",
    "misalign": "misalignment-check",
    "init": "aisg init",
    "probe": "aisg probe",
    "measure": "aisg measure",
    "audit": "aisg audit",
    "skill": "aisg skill",
}

SRC_DIR = Path(__file__).resolve().parents[2] / "src"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """Nothing driven from these tests may open a socket."""

    def refuse(*args, **kwargs):
        raise AssertionError("the aisg console script opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def neutral_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A cwd with no pyproject above it, so the repo's [tool.aisg-audit] stays out."""
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    assert find_pyproject() is None, "a pyproject.toml above the temp dir would leak defaults"
    return cwd


# ---------------------------------------------------------------------------
# Registry and help
# ---------------------------------------------------------------------------


def test_every_command_is_registered_and_documented() -> None:
    assert set(cli.COMMANDS) == set(EXPECTED_COMMANDS)
    for name in EXPECTED_COMMANDS:
        assert callable(cli.COMMANDS[name])
        assert any(line.strip().startswith(name + " ") for line in cli._EPILOG.splitlines()), (
            f"{name} missing from the Commands block of _EPILOG"
        )
    assert "audit" in cli.COMMANDS and "skill" in cli.COMMANDS
    assert cli._audit is cli.COMMANDS["audit"]
    assert cli._skill is cli.COMMANDS["skill"]


def test_parser_choices_track_the_registry() -> None:
    parser = cli.build_parser()
    command_action = next(a for a in parser._actions if a.dest == "command")
    assert list(command_action.choices) == sorted(cli.COMMANDS)


def test_no_arguments_prints_the_epilog_and_exits_2(capsys) -> None:
    assert cli.main([]) == 2
    out = capsys.readouterr().out
    assert "Commands:" in out
    for name in EXPECTED_COMMANDS:
        assert f"  {name} " in out, name
    assert "aisg audit ." in out
    assert "aisg skill install" in out


def test_version_flag() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0


def test_unknown_command_is_a_usage_error(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["frobnicate"])
    assert exc.value.code == 2
    assert "usage: aisg" in capsys.readouterr().err


@pytest.mark.parametrize("name", EXPECTED_COMMANDS)
def test_subcommand_help_reaches_the_tools_own_parser(name: str, capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main([name, "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert out.startswith(f"usage: {PROG_BY_COMMAND[name]}"), out.splitlines()[0]


def test_audit_help_lists_its_own_flags(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["audit", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for flag in ("--fail-on", "--baseline", "--write-baseline", "--no-external", "--format"):
        assert flag in out, flag


def test_skill_help_lists_its_verbs(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["skill", "--help"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    for verb in ("install", "path", "list", "diff"):
        assert verb in out, verb


# ---------------------------------------------------------------------------
# Lazy imports
# ---------------------------------------------------------------------------


def test_importing_the_cli_does_not_load_the_devtools() -> None:
    """`aisg lint` must not pay the audit engine's import cost; check in a fresh interpreter."""
    code = (
        "import sys, aisg.cli\n"
        "loaded = sorted(m for m in sys.modules if m.startswith('aisg.devtools'))\n"
        "print(','.join(loaded))\n"
    )
    env = dict(os.environ, PYTHONPATH=str(SRC_DIR), PYTHONIOENCODING="utf-8")
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=120
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "", proc.stdout


# ---------------------------------------------------------------------------
# skill
# ---------------------------------------------------------------------------


def test_skill_list_prints_the_host_table(capsys) -> None:
    assert cli.main(["skill", "list"]) == 0
    out = capsys.readouterr().out
    header, *rows = [line for line in out.splitlines() if line.strip()]
    assert header.split("|")[0].strip() == "name"
    assert "verified" in header
    names = {row.split("|")[0].strip() for row in rows}
    assert {"claude", "agents", "cursor", "gemini", "codex"} <= names
    assert out.isascii()


def test_skill_without_a_verb_prints_help_and_exits_2(capsys) -> None:
    assert cli.main(["skill"]) == 2
    assert "usage: aisg skill" in capsys.readouterr().out


def test_skill_path_points_at_the_packaged_skill(capsys) -> None:
    assert cli.main(["skill", "path"]) == 0
    printed = Path(capsys.readouterr().out.strip())
    assert (printed / "SKILL.md").is_file()


# ---------------------------------------------------------------------------
# audit
# ---------------------------------------------------------------------------


def test_audit_unrecognised_flag_is_a_usage_error(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["audit", "--no-such-flag"])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "usage: aisg audit" in err
    assert "unrecognized arguments" in err


def test_audit_without_a_path_audits_the_cwd(neutral_cwd: Path, capsys) -> None:
    """DESIGN 7: `path` defaults to `.`; an empty cwd yields no finding and exit 0."""
    assert cli.main(["audit", "--no-external", "-q"]) == 0
    out = capsys.readouterr().out
    assert "0 findings" in out
    assert "UNKNOWN" in out


def test_audit_py_agent_json_through_the_console_entry(
    py_agent: Path, neutral_cwd: Path, tmp_path: Path, capsys
) -> None:
    out = tmp_path / "audit.json"
    code = cli.main(["audit", str(py_agent), "--no-external", "--format", "json", "-o", str(out)])
    assert code == 1
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert list(doc)[0] == "schema"
    assert doc["schema"] == "aisg/1"
    assert doc["kind"] == "audit"
    assert doc["findings"]
    assert doc["summary"]["exit_code"] == 1
    captured = capsys.readouterr()
    assert "written to" in captured.err


def test_audit_reference_fixture_without_findings_exits_zero(
    audit_fixture, neutral_cwd: Path, capsys
) -> None:
    assert cli.main(["audit", str(audit_fixture("clean_py")), "--no-external"]) == 0
    out = capsys.readouterr().out
    assert "0 findings" in out
    assert "Not an assessment of compliance with any regulation" in out


def test_audit_exit_codes_pass_through_unchanged(py_agent: Path, neutral_cwd: Path) -> None:
    from aisg.devtools.audit.main import EXIT_FATAL, EXIT_FINDINGS, EXIT_OK

    assert cli.main(["audit", str(py_agent), "--no-external", "--fail-on", "never"]) == EXIT_OK
    assert cli.main(["audit", str(py_agent), "--no-external"]) == EXIT_FINDINGS
    assert cli.main(["audit", str(py_agent / "does-not-exist"), "--no-external"]) == EXIT_FATAL


def test_version_string_matches_the_package() -> None:
    parser = cli.build_parser()
    version_action = next(a for a in parser._actions if a.dest == "version")
    assert version_action.version == f"aisg {__version__}"
