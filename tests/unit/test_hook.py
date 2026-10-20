"""tests/unit/test_hook.py
------------------------
`aisafe hook`: the adapter between an agent host's command hooks and the audit. Payloads
come from `tests/fixtures/hooks/<host>/*.json` (one per host and event, `{root}` is
substituted); the tree is a copy of the py_agent fixture.

Properties pinned here: every policy decision reaches the host in its own envelope; the
hook fails OPEN on its own errors and records them; it never opens a socket, never
imports a model SDK, never spawns an installer and writes only under `.aisafe-audit/`
during `run`; `install` prints the diff and writes only with `--yes`.
"""

from __future__ import annotations

import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from aisafe.devtools import hook
from aisafe.devtools._config import find_pyproject
from aisafe.devtools.audit import patterns
from aisafe.devtools.audit.main import main as audit_main
from aisafe.devtools.hook import (
    ALL_POLICIES,
    DEFAULT_POLICIES,
    STATE_FILE,
    HookConfig,
    State,
    UnverifiedHostError,
    merged_config,
    normalise,
)
from aisafe.devtools.hosts import HOSTS

REPO = Path(__file__).resolve().parents[2]
PY_AGENT = REPO / "tests" / "fixtures" / "audit" / "py_agent"
FIXTURES = REPO / "tests" / "fixtures" / "hooks"
HOOK_SOURCE = REPO / "src" / "aisafe" / "devtools" / "hook.py"
SH = shutil.which("sh")
PS = shutil.which("pwsh") or shutil.which("powershell")


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args, **kwargs):
        raise AssertionError("aisafe hook opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A copy of the py_agent fixture, cwd set to a neutral directory beside it."""
    root = tmp_path / "tree"
    shutil.copytree(PY_AGENT, root)
    neutral = tmp_path / "cwd"
    neutral.mkdir()
    monkeypatch.chdir(neutral)
    assert find_pyproject() is None
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(hook, "home_dir", lambda: home)
    return root


def payload(name: str, root: Path) -> dict:
    text = (FIXTURES / name).read_text(encoding="utf-8")
    return json.loads(text.replace("{root}", root.as_posix()))


def run(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    root: Path,
    host: str,
    event: str,
    body: dict | str,
    *extra: str,
) -> tuple[int, str, dict | None]:
    text = body if isinstance(body, str) else json.dumps(body)
    monkeypatch.setattr(sys, "stdin", io.StringIO(text))
    rc = hook.main(["run", "--host", host, "--event", event, "--root", str(root), *extra])
    out = capsys.readouterr().out
    parsed: dict | None = None
    if out.strip():
        try:
            parsed = json.loads(out)
        except json.JSONDecodeError:
            parsed = None
    return rc, out, parsed


def state_of(root: Path) -> dict:
    return json.loads((root / STATE_FILE).read_text(encoding="utf-8"))


def write_baseline(root: Path, monkeypatch: pytest.MonkeyPatch, capsys=None) -> str:
    """Write the audit report and baseline under `.aisafe-audit/`; drains captured stdout,
    because the audit prints its terminal summary when `-o` is given."""
    monkeypatch.chdir(root)
    rc = audit_main(
        [
            ".",
            "--no-external",
            "--format",
            "json",
            "-o",
            ".aisafe-audit/audit-report.json",
            "--write-baseline",
            ".aisafe-audit/audit-baseline.json",
        ]
    )
    assert rc == 0
    monkeypatch.chdir(root.parent / "cwd")
    if capsys is not None:
        capsys.readouterr()
    return ".aisafe-audit/audit-baseline.json"


def snapshot(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}


# ---------------------------------------------------------------------------
# Normalisers
# ---------------------------------------------------------------------------


class TestNormalise:
    def test_claude_write_is_an_edit_with_relative_path_and_content(self, tree):
        ev = normalise(
            "claude", "PreToolUse", payload("claude/PreToolUse-write-secret.json", tree), tree
        )
        assert ev.kind == "pre_tool" and ev.tool == "Write"
        assert ev.file_paths == ("new_settings.py",)
        assert ev.content and "ANTHROPIC_KEY" in ev.content
        assert ev.command is None and ev.session_id == "sess-claude-1"

    def test_claude_multiedit_joins_new_strings(self, tree):
        ev = normalise(
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-multiedit-example-file.json", tree),
            tree,
        )
        assert ev.file_paths == (".env.example",)
        assert ev.content and "ANTHROPIC_API_KEY=" in ev.content

    def test_claude_notebook_edit_uses_notebook_path_and_new_source(self, tree):
        ev = normalise(
            "claude", "PreToolUse", payload("claude/PreToolUse-notebook.json", tree), tree
        )
        assert ev.file_paths == ("analysis.ipynb",)
        assert ev.content and "Anthropic(" in ev.content

    def test_claude_bash_carries_the_command(self, tree):
        ev = normalise(
            "claude", "PreToolUse", payload("claude/PreToolUse-bash-curl-pipe.json", tree), tree
        )
        assert ev.command and ev.command.startswith("curl")
        assert ev.file_paths == ()

    def test_claude_relative_dot_slash_path_keeps_its_leading_dot_directory(self, tree):
        body = payload("claude/PreToolUse-edit-protected.json", tree)
        body["tool_input"]["file_path"] = "./.claude/settings.json"
        ev = normalise("claude", "PreToolUse", body, tree)
        assert ev.file_paths == (".claude/settings.json",)

    def test_claude_stop_reads_stop_hook_active(self, tree):
        assert normalise(
            "claude", "Stop", payload("claude/Stop-active.json", tree), tree
        ).stop_hook_active
        assert not normalise(
            "claude", "Stop", payload("claude/Stop.json", tree), tree
        ).stop_hook_active

    def test_cursor_shell_mcp_edit_prompt(self, tree):
        shell = normalise(
            "cursor",
            "beforeShellExecution",
            payload("cursor/beforeShellExecution-plain.json", tree),
            tree,
        )
        assert (
            shell.tool == "shell" and shell.command == "git status" and shell.session_id == "conv-1"
        )
        mcp = normalise(
            "cursor",
            "beforeMCPExecution",
            payload("cursor/beforeMCPExecution-stdio.json", tree),
            tree,
        )
        assert mcp.tool == "mcp" and mcp.command.startswith("npx -y")
        edit = normalise(
            "cursor", "afterFileEdit", payload("cursor/afterFileEdit-mcp.json", tree), tree
        )
        assert (
            edit.kind == "post_tool" and edit.file_paths == (".mcp.json",) and edit.content == "y"
        )
        prompt = normalise(
            "cursor", "beforeSubmitPrompt", payload("cursor/beforeSubmitPrompt.json", tree), tree
        )
        assert prompt.kind == "prompt" and prompt.prompt.startswith("Ignore")

    def test_gemini_write_replace_shell(self, tree):
        write = normalise(
            "gemini", "BeforeTool", payload("gemini/BeforeTool-write-secret.json", tree), tree
        )
        assert (
            write.tool == "write_file"
            and write.file_paths == ("keys.py",)
            and "TOKEN" in write.content
        )
        replace = normalise(
            "gemini", "BeforeTool", payload("gemini/BeforeTool-replace-protected.json", tree), tree
        )
        assert replace.file_paths == (".gemini/settings.json",) and replace.content == "b"
        shell = normalise(
            "gemini", "BeforeTool", payload("gemini/BeforeTool-shell-pipe.json", tree), tree
        )
        assert shell.tool == "run_shell_command" and shell.command.startswith("wget")

    def test_codex_is_unverified(self, tree):
        with pytest.raises(UnverifiedHostError):
            normalise("codex", "anything", {}, tree)

    def test_unknown_host_is_a_value_error(self, tree):
        with pytest.raises(ValueError):
            normalise("emacs", "x", {}, tree)

    def test_unknown_event_is_kind_unknown_and_decides_nothing(self, tree):
        ev = normalise("claude", "Notification", {"session_id": "s"}, tree)
        assert ev.kind == "unknown"
        assert hook.run_policies(ev, HookConfig(), State(), tree) is None


# ---------------------------------------------------------------------------
# Claude Code: pre-tool policies
# ---------------------------------------------------------------------------


class TestClaudePreTool:
    def test_secret_literal_is_denied_and_redacted(self, tree, monkeypatch, capsys):
        rc, out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-write-secret.json", tree),
        )
        assert rc == 0
        spec = doc["hookSpecificOutput"]
        assert spec["hookEventName"] == "PreToolUse"
        assert spec["permissionDecision"] == "deny"
        assert "secret-shaped literal (anthropic)" in spec["permissionDecisionReason"]
        assert "<redacted:" in spec["permissionDecisionReason"]
        assert "sk-ant-api03-abcdefghij" not in out

    def test_notebook_secret_is_denied_too(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-notebook.json", tree),
        )
        assert doc["hookSpecificOutput"]["permissionDecision"] == "deny"

    def test_secret_named_variable_asks_instead_of_denying(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-write-secret-var.json", tree),
        )
        assert doc["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert "secret-named variable" in doc["hookSpecificOutput"]["permissionDecisionReason"]

    def test_protected_path_asks(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-edit-protected.json", tree),
        )
        assert doc["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert ".claude/settings.json" in doc["hookSpecificOutput"]["permissionDecisionReason"]

    def test_bypass_literal_in_a_workflow_asks(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-edit-bypass-in-workflow.json", tree),
        )
        assert doc["hookSpecificOutput"]["permissionDecision"] == "ask"

    def test_example_file_is_not_a_secret_but_is_protected(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-multiedit-example-file.json", tree),
        )
        assert doc["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert "protected path" in doc["hookSpecificOutput"]["permissionDecisionReason"]

    def test_plain_write_is_silent(self, tree, monkeypatch, capsys):
        rc, out, _doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-write-plain.json", tree),
        )
        assert rc == 0 and out == ""

    def test_curl_pipe_sh_is_denied(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-bash-curl-pipe.json", tree),
        )
        assert doc["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert "curl_pipe_sh" in doc["hookSpecificOutput"]["permissionDecisionReason"]

    def test_npx_y_asks(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-bash-npx-y.json", tree),
        )
        assert doc["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert "npx_y" in doc["hookSpecificOutput"]["permissionDecisionReason"]

    def test_permission_bypass_in_a_command_asks(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-bash-bypass.json", tree),
        )
        assert doc["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert "permission bypass" in doc["hookSpecificOutput"]["permissionDecisionReason"]

    def test_shell_write_to_a_protected_path_asks(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-bash-protected-write.json", tree),
        )
        assert doc["hookSpecificOutput"]["permissionDecision"] == "ask"
        assert ".claude/settings.json" in doc["hookSpecificOutput"]["permissionDecisionReason"]

    def test_running_the_hook_installer_itself_asks(self, tree, monkeypatch, capsys):
        body = payload("claude/PreToolUse-bash-plain.json", tree)
        for command in (
            "aisafe hook install --host claude --yes",
            "python -m aisafe.cli hook uninstall --host cursor",
        ):
            body["tool_input"]["command"] = command
            _rc, _out, doc = run(monkeypatch, capsys, tree, "claude", "PreToolUse", body)
            assert doc["hookSpecificOutput"]["permissionDecision"] == "ask", command
            assert (
                "installs or removes agent hooks"
                in doc["hookSpecificOutput"]["permissionDecisionReason"]
            )

    def test_plain_command_is_silent(self, tree, monkeypatch, capsys):
        rc, out, _doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-bash-plain.json", tree),
        )
        assert rc == 0 and out == ""

    def test_a_disabled_policy_does_not_fire(self, tree, monkeypatch, capsys):
        (tree / "pyproject.toml").write_text(
            '[tool.aisafe-hook]\npolicies = ["protected_path"]\n', encoding="utf-8"
        )
        rc, out, _doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-bash-curl-pipe.json", tree),
        )
        assert rc == 0 and out == ""


# ---------------------------------------------------------------------------
# Claude Code: post-tool recheck, session start, stop gate, prompt
# ---------------------------------------------------------------------------


class TestClaudeRecheck:
    def test_edit_with_a_new_file_local_finding_adds_context(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PostToolUse",
            payload("claude/PostToolUse-edit-mcp.json", tree),
        )
        ctx = doc["hookSpecificOutput"]["additionalContext"]
        assert doc["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert "AUD-602" in ctx and ".mcp.json" in ctx
        assert "run the ai-safety-audit skill to plan the control" in ctx
        assert state_of(tree)["sessions"]["sess-claude-1"]["touched"] == [".mcp.json"]

    def test_edit_without_file_local_findings_is_silent_but_touched(
        self, tree, monkeypatch, capsys
    ):
        rc, out, _doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PostToolUse",
            payload("claude/PostToolUse-edit-app.json", tree),
        )
        assert rc == 0 and out == ""
        assert state_of(tree)["sessions"]["sess-claude-1"]["touched"] == ["app.py"]

    def test_debounce_silences_an_immediate_repeat(self, tree, monkeypatch, capsys):
        body = payload("claude/PostToolUse-edit-mcp.json", tree)
        _rc, first, _doc = run(monkeypatch, capsys, tree, "claude", "PostToolUse", body)
        _rc, second, _doc = run(monkeypatch, capsys, tree, "claude", "PostToolUse", body)
        assert first and second == ""

    def test_recheck_runs_the_full_audit_when_the_last_one_was_fast(
        self, tree, monkeypatch, capsys
    ):
        baseline = write_baseline(tree, monkeypatch, capsys)
        state = State()
        state.last_full_audit = {
            "at": "2026-01-01T00:00:00Z",
            "seconds": 0.5,
            "files": 8,
            "exit_code": 1,
            "event": "Stop",
        }
        state.save(tree)
        run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PostToolUse",
            payload("claude/PostToolUse-edit-app.json", tree),
        )
        after = state_of(tree)["last_full_audit"]
        assert after["event"] == "PostToolUse" and after["files"] and after["seconds"] > 0
        assert (tree / baseline).is_file()

    def test_recheck_output_is_the_audits_own_output_and_skipped_by_a_later_walk(
        self, tree, monkeypatch, capsys
    ):
        run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PostToolUse",
            payload("claude/PostToolUse-edit-mcp.json", tree),
        )
        recheck = tree / hook.RECHECK_FILE
        assert recheck.is_file()
        from aisafe.devtools.audit import walk

        skipped: list[str] = []
        walk.walk(tree, walk.WalkOptions(), own_output_skipped=skipped)
        assert hook.RECHECK_FILE in skipped


class TestClaudeSessionStart:
    def test_without_a_report_one_plain_line(self, tree, monkeypatch, capsys):
        rc, out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "SessionStart",
            payload("claude/SessionStart.json", tree),
        )
        assert rc == 0 and doc is None
        assert out.startswith("no .aisafe-audit/audit-report.json; run the ai-safety-audit skill")
        assert "absence of a report is not evidence of safety" in out

    def test_with_a_report_the_posture_lines(self, tree, monkeypatch, capsys):
        write_baseline(tree, monkeypatch, capsys)
        rc, out, _doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "SessionStart",
            payload("claude/SessionStart.json", tree),
        )
        assert rc == 0
        lines = out.splitlines()
        assert (
            lines[0].startswith("aisafe audit report .aisafe-audit/audit-report.json, ")
            and "old" in lines[0]
        )
        assert lines[1].startswith("findings: critical ")
        assert lines[2].startswith("top: AUD-")
        assert any(line.startswith("UNKNOWN items: ") and "never a pass" in line for line in lines)
        assert any(line == "baseline: .aisafe-audit/audit-baseline.json" for line in lines)
        assert len(out) <= hook.CONTEXT_CAP + 1

    def test_hook_errors_since_the_last_start_are_surfaced(self, tree, monkeypatch, capsys):
        run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "SessionStart",
            payload("claude/SessionStart.json", tree),
        )
        run(monkeypatch, capsys, tree, "claude", "PreToolUse", "this is not json")
        _rc, out, _doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "SessionStart",
            payload("claude/SessionStart.json", tree),
        )
        assert re.search(
            r"aisafe hook: 1 error\(s\) since the last session start; see .aisafe-audit/hook-state.json",
            out,
        )

    def test_config_problems_are_surfaced(self, tree, monkeypatch, capsys):
        (tree / "pyproject.toml").write_text(
            '[tool.aisafe-hook]\nfail-on = "sometimes"\n', encoding="utf-8"
        )
        _rc, out, _doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "SessionStart",
            payload("claude/SessionStart.json", tree),
        )
        assert "aisafe hook config: fail-on 'sometimes' is not a severity" in out


class TestClaudeStopGate:
    def test_without_a_baseline_the_gate_is_silent(self, tree, monkeypatch, capsys):
        run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PostToolUse",
            payload("claude/PostToolUse-edit-mcp.json", tree),
        )
        rc, out, _doc = run(
            monkeypatch, capsys, tree, "claude", "Stop", payload("claude/Stop.json", tree)
        )
        assert rc == 0 and out == ""

    def test_blocks_once_on_a_new_high_finding_then_lets_go(self, tree, monkeypatch, capsys):
        write_baseline(tree, monkeypatch, capsys)
        leak = payload("claude/PostToolUse-write-leak.json", tree)
        (tree / "leak.py").write_text(leak["tool_input"]["content"], encoding="utf-8")
        _rc, _out, doc = run(monkeypatch, capsys, tree, "claude", "PostToolUse", leak)
        assert "AUD-501" in doc["hookSpecificOutput"]["additionalContext"]

        rc, _out, doc = run(
            monkeypatch, capsys, tree, "claude", "Stop", payload("claude/Stop.json", tree)
        )
        assert rc == 0
        assert doc["decision"] == "block"
        assert "new finding(s) at or above high since the baseline" in doc["reason"]
        assert "AUD-501" in doc["reason"] and "leak.py" in doc["reason"]
        assert "--amend-baseline .aisafe-audit/audit-baseline.json --accept" in doc["reason"]
        assert "sk-ant-api03-abcdefghij" not in json.dumps(doc)
        session = state_of(tree)["sessions"]["sess-claude-1"]
        assert session["blocked_at"] and session["touched"] == []

        rc, out, _doc = run(
            monkeypatch, capsys, tree, "claude", "Stop", payload("claude/Stop.json", tree)
        )
        assert rc == 0 and out == "", "never twice in a row for the same session"

    def test_stop_hook_active_never_blocks(self, tree, monkeypatch, capsys):
        write_baseline(tree, monkeypatch, capsys)
        (tree / "leak.py").write_text(
            payload("claude/PostToolUse-write-leak.json", tree)["tool_input"]["content"],
            encoding="utf-8",
        )
        run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PostToolUse",
            payload("claude/PostToolUse-write-leak.json", tree),
        )
        rc, out, _doc = run(
            monkeypatch, capsys, tree, "claude", "Stop", payload("claude/Stop-active.json", tree)
        )
        assert rc == 0 and out == ""

    def test_nothing_touched_and_no_git_means_no_gate(self, tree, monkeypatch, capsys):
        write_baseline(tree, monkeypatch, capsys)
        rc, out, _doc = run(
            monkeypatch, capsys, tree, "claude", "Stop", payload("claude/Stop.json", tree)
        )
        assert rc == 0 and out == ""

    def test_no_new_counted_finding_means_no_block(self, tree, monkeypatch, capsys):
        write_baseline(tree, monkeypatch, capsys)
        run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PostToolUse",
            payload("claude/PostToolUse-edit-app.json", tree),
        )
        rc, out, _doc = run(
            monkeypatch, capsys, tree, "claude", "Stop", payload("claude/Stop.json", tree)
        )
        assert rc == 0 and out == ""
        assert state_of(tree)["last_full_audit"]["event"] == "Stop"

    def test_a_slow_last_audit_skips_the_gate_with_context(self, tree, monkeypatch, capsys):
        write_baseline(tree, monkeypatch, capsys)
        state = State.load(tree)
        state.last_full_audit = {
            "at": "2026-01-01T00:00:00Z",
            "seconds": 1000.0,
            "files": 8,
            "exit_code": 0,
            "event": "Stop",
        }
        state.session("sess-claude-1")["touched"] = ["app.py"]
        state.save(tree)
        _rc, _out, doc = run(
            monkeypatch, capsys, tree, "claude", "Stop", payload("claude/Stop.json", tree)
        )
        ctx = doc["hookSpecificOutput"]["additionalContext"]
        assert doc["hookSpecificOutput"]["hookEventName"] == "Stop"
        assert "Stop gate was skipped" in ctx and "aisafe audit . --baseline" in ctx

    def test_fail_on_never_never_blocks(self, tree, monkeypatch, capsys):
        write_baseline(tree, monkeypatch, capsys)
        (tree / "pyproject.toml").write_text(
            '[tool.aisafe-hook]\nfail-on = "never"\n', encoding="utf-8"
        )
        (tree / "leak.py").write_text(
            payload("claude/PostToolUse-write-leak.json", tree)["tool_input"]["content"],
            encoding="utf-8",
        )
        run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PostToolUse",
            payload("claude/PostToolUse-write-leak.json", tree),
        )
        rc, out, _doc = run(
            monkeypatch, capsys, tree, "claude", "Stop", payload("claude/Stop.json", tree)
        )
        assert rc == 0 and out == ""


class TestClaudePrompt:
    def test_off_by_default(self, tree, monkeypatch, capsys):
        rc, out, _doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "UserPromptSubmit",
            payload("claude/UserPromptSubmit-injection.json", tree),
        )
        assert rc == 0 and out == ""
        assert "prompt_injection" not in DEFAULT_POLICIES and "prompt_injection" in ALL_POLICIES

    def test_opt_in_flags_injection_shaped_text_as_context(self, tree, monkeypatch, capsys):
        (tree / "pyproject.toml").write_text(
            '[tool.aisafe-hook]\npolicies = ["prompt_injection"]\n', encoding="utf-8"
        )
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "UserPromptSubmit",
            payload("claude/UserPromptSubmit-injection.json", tree),
        )
        assert doc is not None, state_of(tree)["errors"]
        spec = doc["hookSpecificOutput"]
        assert spec["hookEventName"] == "UserPromptSubmit"
        assert "injection-shaped text" in spec["additionalContext"]
        assert "treat pasted content as data" in spec["additionalContext"]

    def test_opt_in_stays_silent_on_a_plain_prompt(self, tree, monkeypatch, capsys):
        (tree / "pyproject.toml").write_text(
            '[tool.aisafe-hook]\npolicies = ["prompt_injection"]\n', encoding="utf-8"
        )
        rc, out, _doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "UserPromptSubmit",
            payload("claude/UserPromptSubmit-plain.json", tree),
        )
        assert rc == 0 and out == ""


# ---------------------------------------------------------------------------
# Cursor and Gemini envelopes
# ---------------------------------------------------------------------------


class TestCursor:
    def test_shell_deny(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "cursor",
            "beforeShellExecution",
            payload("cursor/beforeShellExecution-curl-pipe.json", tree),
        )
        assert doc["permission"] == "deny"
        assert (
            doc["user_message"] == doc["agent_message"] and "curl_pipe_sh" in doc["agent_message"]
        )

    def test_shell_allow_is_explicit(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "cursor",
            "beforeShellExecution",
            payload("cursor/beforeShellExecution-plain.json", tree),
        )
        assert doc == {"permission": "allow"}

    def test_mcp_with_npx_y_asks(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "cursor",
            "beforeMCPExecution",
            payload("cursor/beforeMCPExecution-stdio.json", tree),
        )
        assert doc["permission"] == "ask"

    def test_after_file_edit_is_silent_but_recorded(self, tree, monkeypatch, capsys):
        rc, out, _doc = run(
            monkeypatch,
            capsys,
            tree,
            "cursor",
            "afterFileEdit",
            payload("cursor/afterFileEdit-mcp.json", tree),
        )
        assert rc == 0 and out == ""
        assert state_of(tree)["sessions"]["conv-1"]["touched"] == [".mcp.json"]

    def test_prompt_continues(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "cursor",
            "beforeSubmitPrompt",
            payload("cursor/beforeSubmitPrompt.json", tree),
        )
        assert doc == {"continue": True}

    def test_stop_without_baseline_is_silent(self, tree, monkeypatch, capsys):
        rc, out, _doc = run(
            monkeypatch, capsys, tree, "cursor", "stop", payload("cursor/stop.json", tree)
        )
        assert rc == 0 and out == ""

    def test_stop_with_a_new_finding_is_a_followup_message(self, tree, monkeypatch, capsys):
        write_baseline(tree, monkeypatch, capsys)
        (tree / "leak.py").write_text(
            payload("claude/PostToolUse-write-leak.json", tree)["tool_input"]["content"],
            encoding="utf-8",
        )
        edit = payload("cursor/afterFileEdit-mcp.json", tree)
        edit["file_path"] = (tree / "leak.py").as_posix()
        run(monkeypatch, capsys, tree, "cursor", "afterFileEdit", edit)
        _rc, _out, doc = run(
            monkeypatch, capsys, tree, "cursor", "stop", payload("cursor/stop.json", tree)
        )
        assert "followup_message" in doc and "AUD-501" in doc["followup_message"]


class TestGemini:
    def test_secret_deny_is_a_decision_object(self, tree, monkeypatch, capsys):
        rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "gemini",
            "BeforeTool",
            payload("gemini/BeforeTool-write-secret.json", tree),
        )
        assert rc == 0
        assert doc["decision"] == "deny" and "<redacted:" in doc["reason"]

    def test_shell_pipe_deny(self, tree, monkeypatch, capsys):
        _rc, _out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "gemini",
            "BeforeTool",
            payload("gemini/BeforeTool-shell-pipe.json", tree),
        )
        assert doc["decision"] == "deny" and "wget_pipe_sh" in doc["reason"]

    def test_allow_is_silence(self, tree, monkeypatch, capsys):
        rc, out, _doc = run(
            monkeypatch,
            capsys,
            tree,
            "gemini",
            "BeforeTool",
            payload("gemini/BeforeTool-shell-plain.json", tree),
        )
        assert rc == 0 and out == ""

    def test_ask_falls_back_to_allow_by_default_and_to_deny_when_configured(
        self, tree, monkeypatch, capsys
    ):
        body = payload("gemini/BeforeTool-replace-protected.json", tree)
        rc, out, _doc = run(monkeypatch, capsys, tree, "gemini", "BeforeTool", body)
        assert rc == 0 and out == ""
        (tree / "pyproject.toml").write_text(
            '[tool.aisafe-hook]\nask-fallback = "deny"\n', encoding="utf-8"
        )
        _rc, _out, doc = run(monkeypatch, capsys, tree, "gemini", "BeforeTool", body)
        assert doc["decision"] == "deny" and "protected path" in doc["reason"]

    def test_after_tool_context_is_one_json_object(self, tree, monkeypatch, capsys):
        _rc, out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "gemini",
            "AfterTool",
            payload("gemini/AfterTool-write-mcp.json", tree),
        )
        assert out.count("\n") == 1
        assert "AUD-602" in doc["hookSpecificOutput"]["additionalContext"]

    def test_session_start_is_json_never_prose(self, tree, monkeypatch, capsys):
        _rc, out, doc = run(
            monkeypatch,
            capsys,
            tree,
            "gemini",
            "SessionStart",
            payload("gemini/SessionStart.json", tree),
        )
        assert doc is not None and "additionalContext" in doc["hookSpecificOutput"]
        assert not out.startswith("no ")


# ---------------------------------------------------------------------------
# Fail open, state, guarantees
# ---------------------------------------------------------------------------


class TestFailOpen:
    def test_bad_payload_exits_0_silent_and_recorded(self, tree, monkeypatch, capsys):
        rc, out, _doc = run(monkeypatch, capsys, tree, "claude", "PreToolUse", "{not json")
        assert rc == 0 and out == ""
        errors = state_of(tree)["errors"]
        assert (
            len(errors) == 1
            and errors[0]["event"] == "PreToolUse"
            and "JSONDecodeError" in errors[0]["error"]
        )

    def test_cursor_permission_hook_gets_an_explicit_allow_on_error(
        self, tree, monkeypatch, capsys
    ):
        _rc, _out, doc = run(monkeypatch, capsys, tree, "cursor", "beforeShellExecution", "[1, 2")
        assert doc == {"permission": "allow"}

    def test_codex_emits_nothing_and_records(self, tree, monkeypatch, capsys):
        rc, out, _doc = run(
            monkeypatch, capsys, tree, "codex", "anything", {"cwd": tree.as_posix()}
        )
        assert rc == 0 and out == ""
        assert any("codex" in e["error"] for e in state_of(tree)["errors"])

    def test_an_audit_exception_fails_open(self, tree, monkeypatch, capsys):
        def boom(args):
            raise RuntimeError("audit exploded")

        monkeypatch.setattr(hook, "_run_audit", boom)
        rc, out, _doc = run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PostToolUse",
            payload("claude/PostToolUse-edit-mcp.json", tree),
        )
        assert rc == 0 and out == ""
        assert any("audit exploded" in e["error"] for e in state_of(tree)["errors"])

    def test_payload_event_name_wins_and_the_mismatch_is_recorded(self, tree, monkeypatch, capsys):
        body = payload("claude/PreToolUse-bash-curl-pipe.json", tree)
        _rc, _out, doc = run(monkeypatch, capsys, tree, "claude", "PostToolUse", body)
        assert doc["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert any("payload says PreToolUse" in e["error"] for e in state_of(tree)["errors"])


class TestState:
    def test_document_shape(self, tree, monkeypatch, capsys):
        run(
            monkeypatch,
            capsys,
            tree,
            "claude",
            "PreToolUse",
            payload("claude/PreToolUse-bash-plain.json", tree),
            "--origin",
            "path:/usr/bin/aisafe",
            "--expect-version",
            "9.9.9",
        )
        raw = (tree / STATE_FILE).read_text(encoding="utf-8")
        assert raw.isascii() and "\r" not in raw
        doc = json.loads(raw)
        assert (
            list(doc)[:2] == ["schema", "kind"]
            and doc["schema"] == "aisg/1"
            and doc["kind"] == "hook-state"
        )
        assert doc["origin"] == "path:/usr/bin/aisafe" and doc["expected_version"] == "9.9.9"
        assert doc["version_mismatch"] is True
        assert not (tree / STATE_FILE).with_suffix(".json.tmp").exists()

    def test_errors_and_sessions_are_capped(self, tree):
        state = State()
        for i in range(30):
            state.record_error("E", f"error {i}")
            state.session(f"s{i}")
        state.save(tree)
        doc = state_of(tree)
        assert len(doc["errors"]) == hook.ERRORS_KEPT and doc["errors"][-1]["error"] == "error 29"
        assert len(doc["sessions"]) == hook.SESSIONS_KEPT

    def test_a_corrupt_state_file_is_started_over(self, tree):
        (tree / STATE_FILE).parent.mkdir(parents=True)
        (tree / STATE_FILE).write_text("{corrupt", encoding="utf-8")
        assert State.load(tree).errors == []

    def test_everything_stored_is_redacted(self, tree):
        state = State()
        state.record_error("X", "leaked sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD here")
        state.save(tree)
        raw = (tree / STATE_FILE).read_text(encoding="utf-8")
        assert "sk-ant-api03-abcdefghij" not in raw and "<redacted:" in raw


class TestConfig:
    def test_defaults(self, tree):
        cfg = HookConfig.load(tree)
        assert cfg.fail_on == "high" and cfg.policies == DEFAULT_POLICIES
        assert cfg.ask_fallback == "allow" and cfg.problems == ()

    def test_fail_on_falls_back_to_the_audit_section(self, tree):
        (tree / "pyproject.toml").write_text(
            '[tool.aisafe-audit]\nfail-on = "medium"\n', encoding="utf-8"
        )
        assert HookConfig.load(tree).fail_on == "medium"

    def test_values_and_problems(self, tree):
        (tree / "pyproject.toml").write_text(
            "[tool.aisafe-hook]\n"
            'fail-on = "critical"\n'
            'policies = ["recheck", "nope"]\n'
            "max-audit-seconds = 3\n"
            "debounce-seconds = -1\n"
            'ask-fallback = "maybe"\n'
            'baseline = "custom-baseline.json"\n',
            encoding="utf-8",
        )
        cfg = HookConfig.load(tree)
        assert cfg.fail_on == "critical" and cfg.policies == ("recheck",)
        assert cfg.max_audit_seconds == 3.0 and cfg.debounce_seconds == 2.0
        assert cfg.ask_fallback == "allow"
        assert cfg.baseline == "custom-baseline.json" and cfg.resolve_baseline(tree) is None
        assert len(cfg.problems) == 3

    def test_baseline_resolution_prefers_aisafe_audit_then_root(self, tree):
        cfg = HookConfig.load(tree)
        assert cfg.resolve_baseline(tree) is None
        (tree / "audit-baseline.json").write_text("{}", encoding="utf-8")
        assert cfg.resolve_baseline(tree) == "audit-baseline.json"
        (tree / ".aisafe-audit").mkdir()
        (tree / ".aisafe-audit" / "audit-baseline.json").write_text("{}", encoding="utf-8")
        assert cfg.resolve_baseline(tree) == ".aisafe-audit/audit-baseline.json"

    def test_baseline_under_the_pre_rename_directory_is_still_found(self, tree):
        # Before 2026-10-20 the skill kept its baseline under `.aisg-audit/`. Without it the
        # stop gate would go quiet and every accepted finding would recheck as new.
        cfg = HookConfig.load(tree)
        (tree / "audit-baseline.json").write_text("{}", encoding="utf-8")
        (tree / ".aisg-audit").mkdir()
        (tree / ".aisg-audit" / "audit-baseline.json").write_text("{}", encoding="utf-8")
        assert cfg.resolve_baseline(tree) == ".aisg-audit/audit-baseline.json"
        (tree / ".aisafe-audit").mkdir()
        (tree / ".aisafe-audit" / "audit-baseline.json").write_text("{}", encoding="utf-8")
        assert cfg.resolve_baseline(tree) == ".aisafe-audit/audit-baseline.json"


class TestGuarantees:
    def test_run_writes_only_under_aisafe_audit(self, tree, monkeypatch, capsys):
        before = snapshot(tree)
        for name in (
            "claude/PreToolUse-write-secret.json",
            "claude/PostToolUse-edit-mcp.json",
            "claude/SessionStart.json",
            "claude/Stop.json",
        ):
            run(
                monkeypatch,
                capsys,
                tree,
                "claude",
                name.split("/")[1].split("-")[0].replace(".json", ""),
                payload(name, tree),
            )
        after = snapshot(tree)
        changed = {k for k in set(before) | set(after) if before.get(k) != after.get(k)}
        assert changed and all(k.startswith(".aisafe-audit/") for k in changed), changed

    def test_module_imports_no_model_sdk_and_spawns_no_installer(self):
        source = HOOK_SOURCE.read_text(encoding="utf-8")
        assert not re.search(
            r"^\s*(?:import|from)\s+(?:anthropic|openai|httpx|requests|groq)\b", source, re.M
        )
        assert "subprocess" not in source, "the only subprocess is walk._git"
        for launcher in (
            patterns.FORBIDDEN_LAUNCHERS
            if hasattr(patterns, "FORBIDDEN_LAUNCHERS")
            else ("pip", "uvx", "npx", "pipx")
        ):
            assert not re.search(rf"\[\s*[\"']{launcher}[\"']", source)

    def test_decisions_are_ascii_and_capped(self):
        long = "x" * 5000 + " sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD é"
        text = hook._ascii(long, hook.REASON_CAP)
        assert len(text) <= hook.REASON_CAP and text.isascii()
        assert "sk-ant-api03-abcdefghij" not in hook._ascii(
            "k=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCD", 400
        )


# ---------------------------------------------------------------------------
# install / uninstall / list
# ---------------------------------------------------------------------------


def _settings(tree: Path, rel: str = ".claude/settings.json") -> dict:
    return json.loads((tree / rel).read_text(encoding="utf-8"))


class TestInstallClaude:
    def test_dry_run_prints_the_diff_and_writes_nothing(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        before = snapshot(tree)
        rc = hook.main(["install", "--host", "claude", "--dry-run"])
        out = capsys.readouterr().out
        assert rc == 0 and snapshot(tree) == before
        assert "+++ b/" in out and ".claude/settings.json" in out
        assert "${CLAUDE_PROJECT_DIR}/.claude/hooks/aisafe-hook.sh" in out
        assert "run --host claude --event PreToolUse" in out
        assert "copy packaged scripts/hook.sh" in out

    def test_refused_without_yes_when_stdin_is_not_a_tty(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        before = snapshot(tree)
        rc = hook.main(["install", "--host", "claude"])
        err = capsys.readouterr().err
        assert rc == 1 and snapshot(tree) == before
        assert "refused:" in err and "protected path" in err and "--yes" in err

    def test_yes_writes_entries_scripts_and_keeps_user_hooks(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        existing = _settings(tree)
        existing["hooks"] = {
            "PreToolUse": [
                {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo mine"}]}
            ]
        }
        (tree / ".claude" / "settings.json").write_text(
            json.dumps(existing, indent=2), encoding="utf-8"
        )
        rc = hook.main(["install", "--host", "claude", "--yes"])
        assert rc == 0
        doc = _settings(tree)
        assert doc["permissions"] == existing["permissions"], "untouched keys survive"
        pre = doc["hooks"]["PreToolUse"]
        assert pre[0]["hooks"][0]["command"] == "echo mine"
        ours = [h for entry in pre[1:] for h in entry["hooks"]]
        assert len(ours) == 2 and all("aisafe-hook.sh" in h["command"] for h in ours)
        assert {e["matcher"] for e in pre[1:]} == {"Edit|Write|MultiEdit|NotebookEdit", "Bash"}
        assert set(doc["hooks"]) == {"PreToolUse", "PostToolUse", "SessionStart", "Stop"}
        assert doc["hooks"]["Stop"][0]["hooks"][0]["timeout"] == 120
        for name in ("aisafe-hook.sh", "aisafe-hook.ps1"):
            copied = tree / ".claude" / "hooks" / name
            assert copied.is_file() and b"aisafe-audit: ignore-file" in copied.read_bytes()
        raw = (tree / ".claude" / "settings.json").read_text(encoding="utf-8")
        assert "\r" not in raw and raw.endswith("\n")

    def test_install_is_idempotent(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        assert hook.main(["install", "--host", "claude", "--yes"]) == 0
        capsys.readouterr()
        assert hook.main(["install", "--host", "claude", "--yes"]) == 0
        assert "unchanged" in capsys.readouterr().out
        assert len(_settings(tree)["hooks"]["Stop"]) == 1

    def test_install_replaces_the_entries_an_aisg_install_wrote(self, tree, monkeypatch, capsys):
        # Before the rename the bootstrap was `aisg-hook.sh`. Those entries are ours, so a
        # new install replaces them instead of running the audit twice per event.
        monkeypatch.chdir(tree)
        existing = _settings(tree)
        old = 'sh "${CLAUDE_PROJECT_DIR}/.claude/hooks/aisg-hook.sh" run --host claude'
        existing["hooks"] = {"Stop": [{"hooks": [{"type": "command", "command": old}]}]}
        (tree / ".claude" / "settings.json").write_text(
            json.dumps(existing, indent=2), encoding="utf-8"
        )
        assert hook.main(["install", "--host", "claude", "--yes"]) == 0
        stop = _settings(tree)["hooks"]["Stop"]
        commands = [h["command"] for entry in stop for h in entry["hooks"]]
        assert len(commands) == 1 and "aisafe-hook.sh" in commands[0]

    def test_prompt_policy_adds_the_prompt_event(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        assert (
            hook.main(["install", "--host", "claude", "--yes", "--policies", "prompt_injection"])
            == 0
        )
        assert "UserPromptSubmit" in _settings(tree)["hooks"]

    def test_unknown_policy_is_fatal(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        assert hook.main(["install", "--host", "claude", "--yes", "--policies", "telepathy"]) == 2

    def test_powershell_shell_writes_the_ps1_command(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        assert hook.main(["install", "--host", "claude", "--yes", "--shell", "powershell"]) == 0
        command = _settings(tree)["hooks"]["Stop"][0]["hooks"][0]["command"]
        assert (
            command.startswith("powershell -NoProfile -ExecutionPolicy Bypass -File")
            and "aisafe-hook.ps1" in command
        )

    def test_global_writes_the_interpreter_into_the_home_config(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        home = hook.home_dir()
        assert hook.main(["install", "--host", "claude", "--global", "--yes"]) == 0
        doc = json.loads((home / ".claude" / "settings.json").read_text(encoding="utf-8"))
        command = doc["hooks"]["Stop"][0]["hooks"][0]["command"]
        assert Path(sys.executable).as_posix() in command and "-m aisafe.cli hook run" in command
        assert "--origin interpreter:" in command
        assert not (tree / ".claude" / "hooks").exists(), (
            "no bootstrap copy for a machine-local config"
        )

    def test_local_writes_settings_local(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        assert hook.main(["install", "--host", "claude", "--local", "--yes"]) == 0
        assert (tree / ".claude" / "settings.local.json").is_file()
        assert "hooks" not in _settings(tree)

    def test_python_override_writes_that_interpreter(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        assert (
            hook.main(["install", "--host", "claude", "--yes", "--python", "/opt/venv/bin/python"])
            == 0
        )
        command = _settings(tree)["hooks"]["Stop"][0]["hooks"][0]["command"]
        assert command.startswith('"/opt/venv/bin/python" -m aisafe.cli hook run')

    def test_unparsable_existing_config_is_fatal_and_untouched(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        (tree / ".claude" / "settings.json").write_text("{broken", encoding="utf-8")
        assert hook.main(["install", "--host", "claude", "--yes"]) == 2
        assert (tree / ".claude" / "settings.json").read_text(encoding="utf-8") == "{broken"

    def test_uninstall_removes_only_ours(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        existing = _settings(tree)
        existing["hooks"] = {"Stop": [{"hooks": [{"type": "command", "command": "echo bye"}]}]}
        (tree / ".claude" / "settings.json").write_text(json.dumps(existing), encoding="utf-8")
        assert hook.main(["install", "--host", "claude", "--yes"]) == 0
        assert hook.main(["uninstall", "--host", "claude", "--yes"]) == 0
        doc = _settings(tree)
        assert doc["hooks"]["Stop"] == [{"hooks": [{"type": "command", "command": "echo bye"}]}]
        assert doc["hooks"]["PreToolUse"] == [] and "SessionStart" in doc["hooks"]
        assert not (tree / ".claude" / "hooks" / "aisafe-hook.sh").exists()
        capsys.readouterr()
        assert hook.main(["uninstall", "--host", "claude", "--yes"]) == 0
        assert "unchanged" in capsys.readouterr().out


class TestInstallOtherHosts:
    def test_cursor_writes_version_1_and_its_events(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        assert hook.main(["install", "--host", "cursor", "--yes"]) == 0
        doc = _settings(tree, ".cursor/hooks.json")
        assert list(doc)[0] == "version" and doc["version"] == 1
        assert set(doc["hooks"]) == {
            "beforeShellExecution",
            "beforeMCPExecution",
            "afterFileEdit",
            "stop",
        }
        assert (
            doc["hooks"]["stop"][0]["command"]
            == 'sh ".cursor/hooks/aisafe-hook.sh" run --host cursor --event stop'
        )
        assert (tree / ".cursor" / "hooks" / "aisafe-hook.sh").is_file()
        assert "advisory" in capsys.readouterr().err

    def test_gemini_writes_matchers_and_millisecond_timeouts(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        assert hook.main(["install", "--host", "gemini", "--yes"]) == 0
        doc = _settings(tree, ".gemini/settings.json")
        assert set(doc["hooks"]) == {"BeforeTool", "AfterTool", "SessionStart"}
        before = doc["hooks"]["BeforeTool"][0]
        assert before["matcher"] == "write_file|replace|run_shell_command"
        assert before["hooks"][0]["timeout"] == 20000
        assert "ask-fallback" in capsys.readouterr().err

    def test_codex_writes_nothing_and_exits_1(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        before = snapshot(tree)
        assert hook.main(["install", "--host", "codex", "--yes"]) == 1
        assert snapshot(tree) == before
        assert "not documented" in capsys.readouterr().err

    def test_unknown_host_is_fatal(self, tree, monkeypatch, capsys):
        monkeypatch.chdir(tree)
        assert hook.main(["install", "--host", "emacs", "--yes"]) == 2
        assert hook.main(["uninstall", "--host", "emacs", "--yes"]) == 2


class TestMergedConfig:
    def test_only_hooks_is_touched_and_ours_are_replaced(self):
        host = HOSTS["claude"]
        existing = {
            "permissions": {"allow": ["Read"]},
            "hooks": {
                "Stop": [
                    {"hooks": [{"type": "command", "command": "echo mine"}]},
                    {
                        "hooks": [
                            {
                                "type": "command",
                                "command": 'sh "x/aisafe-hook.sh" run --host claude --event Stop',
                            }
                        ]
                    },
                ]
            },
        }
        merged = merged_config(
            host,
            existing,
            {"Stop": [{"hooks": [{"type": "command", "command": "aisafe hook run new"}]}]},
        )
        assert merged["permissions"] == {"allow": ["Read"]}
        assert [h["command"] for e in merged["hooks"]["Stop"] for h in e["hooks"]] == [
            "echo mine",
            "aisafe hook run new",
        ]
        removed = merged_config(host, existing, None)
        assert [h["command"] for e in removed["hooks"]["Stop"] for h in e["hooks"]] == ["echo mine"]

    def test_cursor_flat_entries(self):
        host = HOSTS["cursor"]
        existing = {
            "version": 1,
            "hooks": {
                "stop": [
                    {"command": "./mine.sh"},
                    {"command": "sh aisafe-hook.sh run --host cursor --event stop"},
                ]
            },
        }
        merged = merged_config(host, existing, None)
        assert merged["hooks"]["stop"] == [{"command": "./mine.sh"}]


class TestList:
    def test_list_prints_identity_hosts_and_policies(self, capsys):
        assert hook.main(["list"]) == 0
        out = capsys.readouterr().out
        assert out.startswith("aisafe-hook: aisafe ")
        for name in ("claude", "cursor", "gemini", "codex"):
            assert f"\n{name} " in out
        assert "policies (default):" in out and "prompt_injection" in out

    def test_no_verb_prints_help_and_exits_2(self, capsys):
        assert hook.main([]) == 2


@pytest.mark.skipif(SH is None, reason="sh not on PATH")
class TestBootstrapScript:
    def test_without_aisafe_the_bootstrap_fails_open(self, tmp_path):
        script = REPO / "src" / "aisafe" / "skills" / "ai-safety-audit" / "scripts" / "hook.sh"
        env = {"PATH": str(tmp_path / "empty-bin")}
        (tmp_path / "empty-bin").mkdir()
        for host, expected in (("claude", ""), ("cursor", '{"permission":"allow"}\n')):
            proc = subprocess.run(
                [SH, str(script), "run", "--host", host, "--event", "x"],
                input="{}",
                capture_output=True,
                text=True,
                env=env,
                timeout=60,
                check=False,
            )
            assert proc.returncode == 0, proc.stderr
            assert proc.stdout == expected
            assert "hook skipped" in proc.stderr

    def test_a_foreign_aisafe_on_path_fails_open(self, tmp_path):
        # PyPI's `aisafeguard` also installs an `aisafe` command. Given `hook run` it exits 2
        # with a usage error, which Claude Code reads as a block; the bootstrap must not.
        script = REPO / "src" / "aisafe" / "skills" / "ai-safety-audit" / "scripts" / "hook.sh"
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "aisafe"
        fake.write_bytes(b"#!/bin/sh\necho \"Error: No such command 'hook'.\" >&2\nexit 2\n")
        fake.chmod(0o755)
        env = {"PATH": str(bin_dir)}
        for host, expected in (("claude", ""), ("cursor", '{"permission":"allow"}\n')):
            proc = subprocess.run(
                [SH, str(script), "run", "--host", host, "--event", "x"],
                input="{}",
                capture_output=True,
                text=True,
                env=env,
                timeout=60,
                check=False,
            )
            assert proc.returncode == 0, proc.stderr
            assert proc.stdout == expected
            assert "exited 2" in proc.stderr and "hook skipped" in proc.stderr

    def _fake_uvx(self, tmp_path, rc):
        # Records its argv, prints one line on stdout and exits `rc`, the way uvx does when the
        # pinned release resolves (0) or cannot be fetched (1: offline, index down).
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "uvx"
        fake.write_bytes(
            b'#!/bin/sh\necho "$@" > "${0%/*}/argv"\necho from-uvx\n'
            + f"echo 'error: no solution found' >&2\nexit {rc}\n".encode()
        )
        fake.chmod(0o755)
        return bin_dir

    def test_a_uvx_that_cannot_fetch_the_pin_fails_open(self, tmp_path):
        # uvx exits 1 when it cannot resolve `aisafe==<pin>`. Claude Code reads a non-zero
        # exit as an error and Cursor an empty answer as a block; the bootstrap must not.
        script = REPO / "src" / "aisafe" / "skills" / "ai-safety-audit" / "scripts" / "hook.sh"
        bin_dir = self._fake_uvx(tmp_path, 1)
        for host, expected in (
            ("claude", "from-uvx\n"),
            ("cursor", 'from-uvx\n{"permission":"allow"}\n'),
        ):
            proc = subprocess.run(
                [SH, str(script), "run", "--host", host, "--event", "x"],
                input="{}",
                capture_output=True,
                text=True,
                env={"PATH": str(bin_dir)},
                timeout=60,
                check=False,
            )
            assert proc.returncode == 0, proc.stderr
            assert proc.stdout == expected
            assert "uvx exited 1" in proc.stderr and "hook skipped" in proc.stderr

    def test_a_working_uvx_runs_the_pinned_release_and_passes_its_answer_through(self, tmp_path):
        script = REPO / "src" / "aisafe" / "skills" / "ai-safety-audit" / "scripts" / "hook.sh"
        bin_dir = self._fake_uvx(tmp_path, 0)
        proc = subprocess.run(
            [SH, str(script), "run", "--host", "cursor", "--event", "x"],
            input="{}",
            capture_output=True,
            text=True,
            env={"PATH": str(bin_dir)},
            timeout=60,
            check=False,
        )
        assert proc.returncode == 0 and proc.stdout == "from-uvx\n"
        assert "hook skipped" not in proc.stderr
        pin = re.search(r'^AISAFE_VERSION="([^"]+)"', script.read_text(), re.M).group(1)
        argv = (bin_dir / "argv").read_text().split()
        assert argv[:4] == ["--from", f"aisafe=={pin}", "aisafe", "hook"]
        assert argv[-4:] == ["--origin", "uvx", "--expect-version", pin]

    def test_only_run_fails_open_other_verbs_keep_their_status(self, tmp_path):
        # `hook install` refusing is an answer for the person at the terminal, not a gate.
        script = REPO / "src" / "aisafe" / "skills" / "ai-safety-audit" / "scripts" / "hook.sh"
        bin_dir = self._fake_uvx(tmp_path, 1)
        proc = subprocess.run(
            [SH, str(script), "install", "--host", "claude"],
            capture_output=True,
            text=True,
            env={"PATH": str(bin_dir)},
            timeout=60,
            check=False,
        )
        assert proc.returncode == 1 and "hook skipped" not in proc.stderr


@pytest.mark.skipif(PS is None, reason="no PowerShell on PATH")
class TestBootstrapScriptPowerShell:
    SCRIPT = REPO / "src" / "aisafe" / "skills" / "ai-safety-audit" / "scripts" / "hook.ps1"

    def _run(self, bin_dir, *args):
        env = dict(os.environ, PATH=str(bin_dir))
        return subprocess.run(
            [PS, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(self.SCRIPT), *args],
            input="{}",
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
            check=False,
        )

    def _fake(self, tmp_path, name, rc):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        if os.name == "nt":
            body = f"@echo off\r\necho error: no solution found 1>&2\r\nexit /b {rc}\r\n"
            (bin_dir / f"{name}.cmd").write_text(body)
        else:
            fake = bin_dir / name
            fake.write_text(f"#!/bin/sh\necho 'error: no solution found' >&2\nexit {rc}\n")
            fake.chmod(0o755)
        return bin_dir

    def test_without_aisafe_the_bootstrap_fails_open(self, tmp_path):
        bin_dir = tmp_path / "empty-bin"
        bin_dir.mkdir()
        for host, expected in (("claude", ""), ("cursor", '{"permission":"allow"}\n')):
            proc = self._run(bin_dir, "run", "--host", host, "--event", "x")
            assert proc.returncode == 0, proc.stderr
            assert proc.stdout == expected
            assert "hook skipped" in proc.stderr

    @pytest.mark.parametrize("launcher", ["uvx", "aisafe"])
    def test_a_launcher_that_fails_fails_open(self, tmp_path, launcher):
        # uvx exits 1 when it cannot fetch the pin; a foreign `aisafe` exits 2 on `hook run`.
        bin_dir = self._fake(tmp_path, launcher, 2 if launcher == "aisafe" else 1)
        for host, expected in (("claude", ""), ("cursor", '{"permission":"allow"}\n')):
            proc = self._run(bin_dir, "run", "--host", host, "--event", "x")
            assert proc.returncode == 0, proc.stderr
            assert proc.stdout == expected
            assert "exited" in proc.stderr and "hook skipped" in proc.stderr

    def test_only_run_fails_open_other_verbs_keep_their_status(self, tmp_path):
        bin_dir = self._fake(tmp_path, "uvx", 1)
        proc = self._run(bin_dir, "install", "--host", "claude")
        assert proc.returncode == 1 and "hook skipped" not in proc.stderr
