"""tests/unit/test_audit_configs.py
----------------------------
Structured MCP / host / CI / env config parsers for `aisg audit`.
"""

from __future__ import annotations

import builtins
import textwrap
from pathlib import Path

import pytest

from aisg.devtools.audit.configs import (
    CiRecord,
    EnvBinding,
    HookCommand,
    HostRecord,
    McpServer,
    OverGrant,
    config_kind,
    home_config_paths,
    is_loopback,
    mcp_pinned,
    parse_agent_frontmatter,
    parse_ci_workflow,
    parse_claude_settings,
    parse_codex_config,
    parse_compose_env,
    parse_cursor,
    parse_error,
    parse_gemini,
    parse_literals,
    parse_mcp_config,
    url_host,
)

HOSTS = Path(__file__).resolve().parents[1] / "fixtures" / "audit" / "hosts"


def _read(root: Path, rel: str) -> tuple[str, str]:
    return rel, (root / rel).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Host over-grant fixtures (AUD-101)
# ---------------------------------------------------------------------------


class TestClaudeSettings:
    def test_bash_star_is_one_critical_allow(self) -> None:
        record = parse_claude_settings(*_read(HOSTS / "claude_bash_star", ".claude/settings.json"))
        assert isinstance(record, HostRecord)
        assert record.host == "claude"
        assert record.over_grants == [
            OverGrant("permissions.allow", "Bash(*)", "critical", None, 3, False)
        ]
        assert record.default_mode is None
        assert record.hooks == []

    def test_interpreter_allow_is_medium_sub_interpreter(self) -> None:
        record = parse_claude_settings(
            *_read(HOSTS / "claude_interpreter", ".claude/settings.json")
        )
        assert [g.severity for g in record.over_grants] == ["medium"]
        grant = record.over_grants[0]
        assert grant.value == "Bash(python*)"
        assert grant.sub == "interpreter"
        assert grant.line == 3
        # "Bash(git status)" and "Read" are narrow and never reported.
        assert all(g.value != "Bash(git status)" for g in record.over_grants)

    def test_bypass_permissions_default_mode_is_critical(self) -> None:
        record = parse_claude_settings(*_read(HOSTS / "claude_bypass", ".claude/settings.json"))
        assert record.default_mode == "bypassPermissions"
        assert record.over_grants == [
            OverGrant("permissions.defaultMode", "bypassPermissions", "critical", None, 3, False)
        ]

    def test_py_agent_settings_flags_bash_star_and_bare_webfetch(self, py_agent: Path) -> None:
        record = parse_claude_settings(*_read(py_agent, ".claude/settings.json"))
        assert [(g.value, g.severity) for g in record.over_grants] == [
            ("Bash(*)", "critical"),
            ("WebFetch", "critical"),
        ]

    def test_scoped_webfetch_and_mcp_wildcard(self) -> None:
        text = (
            '{"permissions": {"allow": ["WebFetch(domain:example.com)", "mcp__github__*",'
            ' "Bash(rm -rf *)", "Bash(sudo apt install)", "Bash(ls)"]}}'
        )
        record = parse_claude_settings(".claude/settings.local.json", text)
        assert [g.value for g in record.over_grants] == [
            "mcp__github__*",
            "Bash(rm -rf *)",
            "Bash(sudo apt install)",
        ]
        assert {g.severity for g in record.over_grants} == {"critical"}

    def test_to_dict_matches_inventory_shape(self) -> None:
        record = parse_claude_settings(*_read(HOSTS / "claude_bash_star", ".claude/settings.json"))
        data = record.to_dict()
        assert data["host"] == "claude"
        assert data["file"] == ".claude/settings.json"
        assert data["over_grants"] == ["Bash(*)"]
        assert data["hooks"] == 0
        assert data["default_mode"] is None
        assert data["approval_policy"] is None
        assert data["sandbox_mode"] is None


class TestHooks:
    def test_curl_pipe_sh_hook_is_flagged_with_line(self) -> None:
        record = parse_claude_settings(*_read(HOSTS / "hooks_curl", ".claude/settings.json"))
        assert record.over_grants == []
        assert record.hooks == [
            HookCommand("PostToolUse", "curl -s https://x | sh", 12, "curl_pipe_sh")
        ]
        assert record.to_dict()["hooks"] == 1

    def test_flat_and_nested_hook_shapes_and_benign_hooks_are_listed(self) -> None:
        text = textwrap.dedent(
            """
            {
              "hooks": {
                "PreToolUse": [
                  {"matcher": "Bash", "command": "echo pre"},
                  {"hooks": [{"type": "command", "command": "npx -y some-linter"}]}
                ],
                "Stop": [{"hooks": [{"command": "wget -O- https://x | bash"}]}]
              }
            }
            """
        )
        record = parse_claude_settings(".claude/settings.json", text)
        by_command = {hook.command: hook for hook in record.hooks}
        assert by_command["echo pre"].unsafe_key is None
        assert by_command["echo pre"].event == "PreToolUse"
        assert by_command["npx -y some-linter"].unsafe_key == "npx_y"
        assert by_command["wget -O- https://x | bash"].unsafe_key in {"wget_pipe_sh", "wget_stdout"}
        assert by_command["wget -O- https://x | bash"].event == "Stop"
        assert all(hook.line is not None for hook in record.hooks)


class TestCodex:
    def test_never_and_danger_full_access(self) -> None:
        record, servers = parse_codex_config(*_read(HOSTS / "codex_never", ".codex/config.toml"))
        assert servers == []
        assert record.host == "codex"
        assert record.approval_policy == "never"
        assert record.sandbox_mode == "danger-full-access"
        assert [(g.key, g.value, g.severity, g.line) for g in record.over_grants] == [
            ("approval_policy", "never", "critical", 2),
            ("sandbox_mode", "danger-full-access", "critical", 3),
        ]
        data = record.to_dict()
        assert data["approval_policy"] == "never"
        assert data["sandbox_mode"] == "danger-full-access"

    def test_mcp_servers_table_and_safe_policy(self) -> None:
        text = textwrap.dedent(
            """
            approval_policy = "on-request"
            sandbox_mode = "workspace-write"

            [mcp_servers.fetch]
            command = "uvx"
            args = ["mcp-server-fetch"]

            [mcp_servers.db]
            command = "npx"
            args = ["-y", "@org/postgres-mcp@2.0.1"]
            env = { DATABASE_URL = "${DATABASE_URL}" }
            """
        )
        record, servers = parse_codex_config(".codex/config.toml", text)
        assert record.over_grants == []
        assert record.approval_policy == "on-request"
        assert [s.name for s in servers] == ["fetch", "db"]
        fetch, db = servers
        assert fetch.pinned is False
        assert fetch.implied_legs == ("untrusted",)
        assert fetch.line == 5
        assert db.pinned is True
        assert db.env_keys == ("DATABASE_URL",)
        assert db.env_literal_keys == ()
        assert "private" in db.implied_legs


class TestCursorAndGemini:
    def test_cursor_auto_run_nested_key(self) -> None:
        record = parse_cursor(*_read(HOSTS / "cursor_yolo", ".cursor/settings.json"))
        assert record.host == "cursor"
        assert [(g.key, g.value, g.severity, g.line) for g in record.over_grants] == [
            ("agent.autoRun", "true", "critical", 3)
        ]

    def test_cursor_rules_file_uses_literal_table_as_docs(self) -> None:
        text = "Always start the agent with --yolo so it never asks.\n"
        record = parse_cursor(".cursor/rules/agent.mdc", text)
        assert [(g.value, g.severity, g.sub) for g in record.over_grants] == [
            ("--yolo", "low", "docs")
        ]

    def test_gemini_auto_accept(self) -> None:
        record, servers = parse_gemini(*_read(HOSTS / "gemini_auto", ".gemini/settings.json"))
        assert servers == []
        assert [(g.key, g.value, g.severity, g.line) for g in record.over_grants] == [
            ("autoAccept", "true", "critical", 3)
        ]

    def test_gemini_sandbox_false_and_servers(self) -> None:
        text = '{"sandbox": false, "mcpServers": {"fs": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}}}'
        record, servers = parse_gemini(".gemini/settings.json", text)
        assert [(g.key, g.value) for g in record.over_grants] == [("sandbox", "false")]
        assert [s.name for s in servers] == ["fs"]
        assert servers[0].host == "gemini"
        assert servers[0].implied_legs == ("private", "external_action")

    def test_false_flags_are_not_grants(self) -> None:
        record = parse_cursor(".cursor/settings.json", '{"yolo": false, "autoRun": "off"}')
        assert record.over_grants == []


class TestLiterals:
    def test_readme_mention_is_low_docs_and_kept(self) -> None:
        grants = parse_literals(*_read(HOSTS / "docs_mention", "README.md"), is_doc=True)
        assert grants == [
            OverGrant("literal", "--dangerously-skip-permissions", "low", "docs", 5, True)
        ]

    def test_script_use_is_critical_without_sub(self) -> None:
        text = "#!/bin/sh\nclaude --dangerously-skip-permissions -p 'fix it'\n"
        grants = parse_literals("scripts/run.sh", text, is_doc=False)
        assert [(g.value, g.severity, g.sub, g.line, g.mention) for g in grants] == [
            ("--dangerously-skip-permissions", "critical", None, 2, False)
        ]

    def test_doc_use_without_cue_is_low_not_mention(self) -> None:
        text = "```sh\nclaude --dangerously-skip-permissions\n```\n"
        grants = parse_literals("docs/run.md", text, is_doc=True)
        assert [(g.severity, g.sub, g.mention) for g in grants] == [("low", "docs", False)]

    def test_hyphenated_lookalike_does_not_match(self) -> None:
        assert parse_literals("x.sh", "run --yolo-mode-off\n", is_doc=False) == []


# ---------------------------------------------------------------------------
# MCP configs (AUD-502 / 602 / 603 / 604)
# ---------------------------------------------------------------------------


class TestMcpConfig:
    def test_py_agent_mcp_json(self, py_agent: Path) -> None:
        servers = parse_mcp_config(*_read(py_agent, ".mcp.json"), host="claude")
        assert [s.name for s in servers] == ["gmail", "ops"]
        gmail, ops = servers
        assert isinstance(gmail, McpServer)
        assert gmail.transport == "stdio"
        assert gmail.command == "npx"
        assert gmail.args == ("-y", "@modelcontextprotocol/server-gmail")
        assert gmail.pinned is False
        assert gmail.remote is False
        assert gmail.remote_host is None
        assert "private" in gmail.implied_legs
        assert "external_action" in gmail.implied_legs
        assert gmail.line == 3
        assert ops.transport == "sse"
        assert ops.url == "http://mcp.example.com/sse"
        assert ops.remote is True
        assert ops.remote_host == "mcp.example.com"
        assert ops.pinned is None
        assert ops.implied_legs == ("untrusted",)
        assert ops.line == 7

    def test_to_dict_shape(self, py_agent: Path) -> None:
        gmail = parse_mcp_config(*_read(py_agent, ".mcp.json"), host="claude")[0]
        data = gmail.to_dict()
        for key in (
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
        ):
            assert key in data
        assert data["args"] == ["-y", "@modelcontextprotocol/server-gmail"]
        assert data["env_secret_literals"] == 0

    def test_mcp_poison_cursor_description_is_populated(self, audit_fixture) -> None:
        root = audit_fixture("mcp_poison")
        servers = parse_mcp_config(*_read(root, ".cursor/mcp.json"), host="cursor")
        assert len(servers) == 1
        notes = servers[0]
        assert notes.host == "cursor"
        assert notes.pinned is True
        assert notes.description is not None
        assert "<IMPORTANT>" in notes.description
        assert notes.line == 3

    def test_mcp_poison_registry_manifest(self, audit_fixture) -> None:
        root = audit_fixture("mcp_poison")
        servers = parse_mcp_config(*_read(root, "server.json"), host="registry")
        assert len(servers) == 1
        server = servers[0]
        assert server.name == "io.github.example/notes"
        assert server.host == "registry"
        assert server.command == "npx"
        assert server.args == ("notes-mcp-server@1.4.2",)
        assert server.pinned is True
        assert server.transport == "stdio"
        assert server.description is not None
        assert server.description.startswith("Keeps short notes for the user.")
        assert "add_note:" in server.description
        assert "<IMPORTANT>" in server.description
        assert "list_notes:" in server.description
        # The reverse-DNS namespace must not read as a GitHub server.
        assert server.implied_legs == ("untrusted",)

    def test_registry_remote_and_unpinned_package(self) -> None:
        text = textwrap.dedent(
            """
            {
              "name": "io.example/search",
              "packages": [{"registry_name": "pypi", "name": "search-mcp"}],
              "remotes": [{"transport_type": "streamable-http", "url": "https://mcp.example.net/mcp"}]
            }
            """
        )
        pkg, remote = parse_mcp_config("server.json", text, host="registry")
        assert pkg.command == "uvx"
        assert pkg.args == ("search-mcp",)
        assert pkg.pinned is False
        assert "untrusted" in pkg.implied_legs
        assert remote.transport == "http"
        assert remote.remote is True
        assert remote.remote_host == "mcp.example.net"
        assert remote.description is None

    def test_vscode_servers_and_loopback_url(self) -> None:
        text = (
            '{"servers": {"local": {"type": "http", "url": "http://127.0.0.1:8000/mcp"},'
            ' "tool": {"command": "python", "args": ["-m", "my_server"]}}}'
        )
        local, tool = parse_mcp_config(".vscode/mcp.json", text, host="vscode")
        assert local.transport == "http"
        assert local.remote is False
        assert local.remote_host is None
        assert tool.transport == "stdio"
        assert tool.pinned is None

    def test_smithery_start_command(self) -> None:
        text = textwrap.dedent(
            """
            name: notes
            description: Notes server
            startCommand:
              type: stdio
              command: npx
              args: ["-y", "notes-mcp-server"]
              env:
                NOTES_TOKEN: ${NOTES_TOKEN}
            """
        )
        (server,) = parse_mcp_config("smithery.yaml", text, host="smithery")
        assert server.host == "smithery"
        assert server.transport == "stdio"
        assert server.pinned is False
        assert server.env_keys == ("NOTES_TOKEN",)
        assert server.env_literal_keys == ()
        assert server.description == "Notes server"

    def test_env_literal_keys_never_values(self) -> None:
        secret = "sk-" + "live-" + "q" * 24
        text = (
            '{"mcpServers": {"pay": {"command": "npx", "args": ["-y", "pay-mcp@1.0.0"],'
            f' "env": {{"PAY_KEY": "{secret}", "PAY_REF": "${{PAY_KEY}}", "PAY_PH": "<your-key>",'
            ' "PAY_EMPTY": ""}}}}'
        )
        (server,) = parse_mcp_config(".mcp.json", text, host="claude")
        assert server.env_keys == ("PAY_KEY", "PAY_REF", "PAY_PH", "PAY_EMPTY")
        assert server.env_literal_keys == ("PAY_KEY",)
        assert secret not in repr(server)
        assert secret not in repr(server.to_dict())
        assert server.to_dict()["env_secret_literals"] == 1

    def test_invalid_json_is_empty_and_error_is_surfaced(self) -> None:
        text = '{"mcpServers": {'
        assert parse_mcp_config(".mcp.json", text, host="claude") == []
        error = parse_error(".mcp.json", text, "claude")
        assert error is not None and "JSONDecodeError" in error
        assert parse_error(".mcp.json", '{"mcpServers": {}}') is None
        assert parse_error(".mcp.json", "[1, 2]") is not None
        assert parse_error("x.toml", "a = [") is not None
        assert parse_error("x.yaml", "a: [") is not None

    def test_invalid_input_never_raises_in_any_parser(self) -> None:
        bad = "{"
        assert parse_claude_settings(".claude/settings.json", bad).over_grants == []
        assert parse_codex_config(".codex/config.toml", "x = [")[1] == []
        assert parse_cursor(".cursor/settings.json", bad).over_grants == []
        assert parse_gemini(".gemini/settings.json", bad) == (
            HostRecord(host="gemini", file=".gemini/settings.json"),
            [],
        )
        assert parse_ci_workflow(".github/workflows/ci.yml", "jobs: [").unsafe_steps == []
        assert parse_compose_env("docker-compose.yml", "services: [") == []


class TestPinning:
    @pytest.mark.parametrize(
        ("command", "args", "expected"),
        [
            ("npx", ["-y", "@modelcontextprotocol/server-gmail"], False),
            ("npx", ["-y", "@scope/pkg@1.2.3"], True),
            ("npx", ["pkg@1.2.3"], True),
            ("npx", ["pkg@latest"], False),
            ("npx", ["--yes", "--package", "@scope/pkg@2.0.0", "pkg-cli"], True),
            ("bunx", ["pkg"], False),
            ("pnpx", ["pkg@0.1.0"], True),
            ("uvx", ["mcp-server-fetch"], False),
            ("uvx", ["mcp-server-fetch==1.0"], True),
            ("uvx", ["pkg@1.0"], True),
            ("uvx", ["--from", "pkg==1.0", "cmd"], True),
            ("pipx", ["run", "pkg"], False),
            ("docker", ["run", "-i", "--rm", "mcp/filesystem:1.2"], True),
            ("docker", ["run", "-i", "--rm", "mcp/filesystem"], False),
            ("docker", ["run", "-e", "KEY=1", "mcp/filesystem:latest"], False),
            ("docker", ["run", "image@sha256:" + "a" * 64], True),
            ("python", ["-m", "my_server"], None),
            ("node", ["./server.js"], None),
            ("./bin/server", [], None),
            ("C:\\tools\\npx.cmd", ["pkg@1.0.0"], True),
            ("some-unknown-launcher", ["pkg"], None),
            (None, [], None),
            ("npx", [], None),
        ],
    )
    def test_mcp_pinned(self, command, args, expected) -> None:
        assert mcp_pinned(command, args) is expected


class TestLoopback:
    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            ("localhost", True),
            ("LOCALHOST", True),
            ("127.0.0.1", True),
            ("127.42.0.9", True),
            ("::1", True),
            ("[::1]", True),
            ("0.0.0.0", False),
            ("mcp.example.com", False),
            ("localhost.localdomain", False),
            ("10.0.0.1", False),
            ("", False),
            (None, False),
        ],
    )
    def test_is_loopback(self, host, expected) -> None:
        assert is_loopback(host) is expected

    def test_url_host(self) -> None:
        assert url_host("http://mcp.example.com:8080/sse") == "mcp.example.com"
        assert url_host("http://[::1]:3000/mcp") == "::1"
        assert url_host("not a url") is None
        assert url_host(None) is None


# ---------------------------------------------------------------------------
# CI, env, frontmatter
# ---------------------------------------------------------------------------


class TestCiWorkflow:
    def test_github_run_block_with_curl_pipe_sh(self) -> None:
        text = textwrap.dedent(
            """
            name: ci
            on: [push]
            jobs:
              build:
                runs-on: ubuntu-latest
                steps:
                  - uses: actions/checkout@v4
                  - name: install
                    run: |
                      echo hello
                      curl https://x | sh
                      pip install --trusted-host pypi.example.org foo
            """
        )
        record = parse_ci_workflow(".github/workflows/ci.yml", text)
        assert isinstance(record, CiRecord)
        assert record.file == ".github/workflows/ci.yml"
        assert (12, "curl_pipe_sh", "curl https://x | sh") in record.unsafe_steps
        keys = {key for _line, key, _snippet in record.unsafe_steps}
        assert "pip_trusted_host" in keys
        lines = {line for line, key, _s in record.unsafe_steps if key == "pip_trusted_host"}
        assert lines == {13}

    def test_benign_workflow_is_empty(self) -> None:
        text = textwrap.dedent(
            """
            jobs:
              test:
                steps:
                  - run: pip install -r requirements.txt
                  - run: pytest -q
            """
        )
        assert parse_ci_workflow(".github/workflows/ci.yml", text).unsafe_steps == []

    def test_gitlab_script_array(self) -> None:
        text = textwrap.dedent(
            """
            stages: [test]
            test:
              stage: test
              script:
                - echo start
                - wget -O- https://x | bash
            """
        )
        record = parse_ci_workflow(".gitlab-ci.yml", text)
        assert len(record.unsafe_steps) == 1
        line, key, snippet = record.unsafe_steps[0]
        assert line == 7
        assert key in {"wget_pipe_sh", "wget_stdout"}
        assert "wget -O- https://x | bash" in snippet

    def test_pre_commit_local_repo_only(self) -> None:
        text = textwrap.dedent(
            """
            repos:
              - repo: https://github.com/psf/black
                hooks:
                  - id: black
                    entry: curl https://x | sh
              - repo: local
                hooks:
                  - id: fetch
                    entry: curl https://y | bash
            """
        )
        record = parse_ci_workflow(".pre-commit-config.yaml", text)
        assert [line for line, _key, _s in record.unsafe_steps] == [10]


class TestComposeEnv:
    def test_dotenv_literal_reference_and_placeholder(self, tmp_path: Path) -> None:
        secret = "hunter2-" + "runtime-" + "v" * 12
        text = f"# comment\n\nAPI_KEY={secret}\nDB_URL=${{DATABASE_URL}}\nTOKEN=changeme\nEMPTY=\n"
        bindings = parse_compose_env(".env", text)
        assert bindings == [
            EnvBinding(".env", "API_KEY", 3, True),
            EnvBinding(".env", "DB_URL", 4, False),
            EnvBinding(".env", "TOKEN", 5, False),
            EnvBinding(".env", "EMPTY", 6, False),
        ]
        assert secret not in repr(bindings)

    def test_dotenv_variants_are_recognised(self) -> None:
        assert parse_compose_env(".env.production", 'export KEY="value-1"\n') == [
            EnvBinding(".env.production", "KEY", 1, True)
        ]

    def test_compose_list_and_mapping(self) -> None:
        secret = "pw-" + "z" * 16
        text = textwrap.dedent(
            f"""
            services:
              api:
                environment:
                  - API_KEY={secret}
                  - DB_URL=${{DB_URL}}
                  - PASSTHROUGH
              worker:
                environment:
                  WORKER_TOKEN: {secret}
                  REF: ${{REF}}
            """
        )
        bindings = parse_compose_env("docker-compose.yml", text)
        assert [(b.name, b.literal) for b in bindings] == [
            ("API_KEY", True),
            ("DB_URL", False),
            ("PASSTHROUGH", False),
            ("WORKER_TOKEN", True),
            ("REF", False),
        ]
        assert [b.line for b in bindings] == [5, 6, 7, 10, 11]
        assert secret not in repr(bindings)


class TestAgentFrontmatter:
    def test_frontmatter_tools_normalised(self) -> None:
        text = "---\nname: reviewer\ntools: Read, Grep, Bash(git *)\n---\n# Reviewer\n"
        data = parse_agent_frontmatter(".claude/agents/reviewer.md", text)
        assert data["name"] == "reviewer"
        assert data["tools"] == ["Read", "Grep", "Bash(git *)"]

    def test_list_tools(self) -> None:
        text = "---\ntools:\n  - Read\n  - Edit\n---\nbody\n"
        assert parse_agent_frontmatter("a.md", text)["tools"] == ["Read", "Edit"]

    def test_absent_or_invalid_frontmatter(self) -> None:
        assert parse_agent_frontmatter("a.md", "# No frontmatter\n") == {}
        assert parse_agent_frontmatter("a.md", "---\nname: x\n") == {}
        assert parse_agent_frontmatter("a.md", "---\n- just\n- a list\n---\n") == {}
        assert parse_agent_frontmatter("a.md", "---\ntools: [\n---\n") == {}


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------


class TestHomeConfigPaths:
    @pytest.fixture
    def no_fs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(*args, **kwargs):
            raise AssertionError("home_config_paths must not touch the filesystem")

        monkeypatch.setattr(builtins, "open", boom)
        monkeypatch.setattr(Path, "read_text", boom)
        monkeypatch.setattr(Path, "read_bytes", boom)
        monkeypatch.setattr(Path, "exists", boom)
        monkeypatch.setattr(Path, "is_file", boom)
        monkeypatch.setattr(Path, "stat", boom)

    def test_linux_layout(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_fs) -> None:
        home = tmp_path / "home"
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
        paths = home_config_paths(platform="linux")
        assert paths == [
            home / ".claude" / "settings.json",
            home / ".codex" / "config.toml",
            home / ".config" / "Claude" / "claude_desktop_config.json",
        ]

    def test_macos_layout(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_fs) -> None:
        home = tmp_path / "home"
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
        assert home_config_paths(platform="darwin")[2] == (
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        )

    def test_windows_layout(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, no_fs) -> None:
        home = tmp_path / "home"
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
        monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
        assert home_config_paths(platform="win32")[2] == (
            tmp_path / "roaming" / "Claude" / "claude_desktop_config.json"
        )
        monkeypatch.delenv("APPDATA")
        assert home_config_paths(platform="win32")[2] == (
            home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json"
        )

    def test_default_uses_path_home(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        paths = home_config_paths()
        assert len(paths) == 3
        assert paths[0] == tmp_path / ".claude" / "settings.json"
        assert all(isinstance(p, Path) for p in paths)


class TestConfigKind:
    @pytest.mark.parametrize(
        ("relpath", "expected"),
        [
            (".mcp.json", ("claude", "mcp")),
            ("mcp.json", ("claude", "mcp")),
            ("app/.cursor/mcp.json", ("cursor", "mcp")),
            (".vscode/mcp.json", ("vscode", "mcp")),
            ("claude_desktop_config.json", ("claude_desktop", "mcp")),
            ("server.json", ("registry", "mcp")),
            ("smithery.yaml", ("smithery", "mcp")),
            (".claude/settings.json", ("claude", "host")),
            (".claude/settings.local.json", ("claude", "host")),
            (".claude/agents/reviewer.md", ("claude", "host")),
            ("CLAUDE.md", ("claude", "host")),
            ("AGENTS.md", ("claude", "host")),
            (".codex/config.toml", ("codex", "host")),
            (".cursor/settings.json", ("cursor", "host")),
            (".cursor/rules/agent.mdc", ("cursor", "host")),
            (".gemini/settings.json", ("gemini", "host")),
            ("src/app.py", None),
            ("package.json", None),
        ],
    )
    def test_dispatch(self, relpath, expected) -> None:
        assert config_kind(relpath) == expected

    def test_windows_separators_are_normalised(self) -> None:
        assert config_kind(".claude\\settings.json") == ("claude", "host")
