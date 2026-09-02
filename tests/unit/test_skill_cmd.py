"""
tests/unit/test_skill_cmd.py
----------------------------
Tests for `aisg skill install|path|list|diff`.

Every test but the last runs against a fake packaged tree built in tmp_path,
with `skill_root` / `iter_skill_files` / `home_dir` monkeypatched on the
command module, so nothing here reads the real package or the real home
directory. The last test uses the real package and skips when it is absent.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aisg.devtools import skill as skillcmd
from aisg.devtools.skill import (
    ALWAYS_HOSTS,
    HOSTS,
    Host,
    SkillInstallError,
    diff_installed,
    install,
    main,
    resolve_hosts,
)

SKILL = "ai-safety-audit"

FAKE_FILES = {
    "SKILL.md": b"---\nname: ai-safety-audit\ndescription: fake skill for tests\n---\n# fake\n",
    "scripts/audit.sh": b"#!/bin/sh\necho audit\n",
    "references/x.md": b"# x\n",
}


@pytest.fixture
def packaged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake packaged skill tree, wired into the command module."""
    src = tmp_path / "packaged" / SKILL
    for rel, content in FAKE_FILES.items():
        path = src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    monkeypatch.setattr(skillcmd, "skill_root", lambda: src)
    monkeypatch.setattr(skillcmd, "iter_skill_files", lambda: iter(sorted(FAKE_FILES.items())))
    return src


@pytest.fixture
def root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty project root, made the cwd so `main()` targets it."""
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    return Path.cwd()


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A fake home directory; `home_dir()` never reaches the real one."""
    fake = tmp_path / "home"
    fake.mkdir()
    monkeypatch.setattr(skillcmd, "home_dir", lambda: fake)
    return fake


def _assert_identical(dest: Path) -> None:
    for rel, content in FAKE_FILES.items():
        assert (dest / rel).read_bytes() == content, rel


# ---------------------------------------------------------------------------
# HOSTS table
# ---------------------------------------------------------------------------


class TestHosts:
    def test_every_verified_host_has_a_source_url(self):
        for host in HOSTS.values():
            if host.verified:
                assert host.source.startswith("https://"), host.name

    def test_verified_without_source_is_rejected(self):
        with pytest.raises(ValueError):
            Host(
                name="x", project_dir=".x/skills", global_dir=".x/skills", verified=True, source=""
            )

    def test_codex_is_an_alias_of_agents_sharing_the_project_dir(self):
        codex, agents = HOSTS["codex"], HOSTS["agents"]
        assert codex.alias_of == "agents"
        assert codex.project_dir == agents.project_dir == ".agents/skills"
        assert codex.global_dir == ".codex/skills"

    def test_unverified_hosts_carry_a_note(self):
        for host in HOSTS.values():
            if not host.verified:
                assert host.note, host.name

    def test_expected_hosts_present(self):
        assert set(HOSTS) == {"claude", "agents", "codex", "cursor", "gemini", "antigravity"}
        assert set(ALWAYS_HOSTS) == {"claude", "agents"}


# ---------------------------------------------------------------------------
# resolve_hosts
# ---------------------------------------------------------------------------


class TestResolveHosts:
    def test_single_name(self, tmp_path: Path):
        assert resolve_hosts("cursor", tmp_path, tmp_path) == [HOSTS["cursor"]]

    def test_unknown_name_raises(self, tmp_path: Path):
        with pytest.raises(ValueError, match="unknown host"):
            resolve_hosts("emacs", tmp_path, tmp_path)

    def test_all_is_claude_and_agents_when_no_host_dir_exists(self, tmp_path: Path):
        names = [h.name for h in resolve_hosts("all", tmp_path, tmp_path)]
        assert names == ["claude", "agents"]

    def test_all_includes_hosts_whose_dir_exists(self, tmp_path: Path):
        (tmp_path / ".cursor").mkdir()
        names = [h.name for h in resolve_hosts("all", tmp_path, tmp_path)]
        assert names == ["claude", "agents", "cursor"]

    def test_all_global_looks_in_home(self, tmp_path: Path):
        root = tmp_path / "root"
        home = tmp_path / "home"
        (home / ".gemini").mkdir(parents=True)
        (root / ".cursor").mkdir(parents=True)
        names = [h.name for h in resolve_hosts("all", root, home, global_=True)]
        assert names == ["claude", "agents", "gemini"]

    def test_force_all_is_every_non_alias_host(self, tmp_path: Path):
        names = [h.name for h in resolve_hosts("all", tmp_path, tmp_path, force_all=True)]
        assert names == ["claude", "agents", "cursor", "gemini", "antigravity"]
        assert "codex" not in names


# ---------------------------------------------------------------------------
# install / diff_installed (library surface)
# ---------------------------------------------------------------------------


class TestInstall:
    def test_installs_every_host_byte_identical(self, packaged: Path, tmp_path: Path):
        for host in HOSTS.values():
            dest = install(host, tmp_path)
            assert dest == tmp_path / host.project_dir / SKILL
            _assert_identical(dest)

    def test_global_installs_under_home(self, packaged: Path, tmp_path: Path):
        home = tmp_path / "home"
        for host in HOSTS.values():
            dest = install(host, tmp_path, global_=True, home=home)
            assert dest == home / host.global_dir / SKILL
            _assert_identical(dest)
        assert not (tmp_path / ".claude").exists()

    def test_global_defaults_to_home_dir(self, packaged: Path, tmp_path: Path, home: Path):
        dest = install(HOSTS["claude"], tmp_path, global_=True)
        assert dest == home / ".claude/skills" / SKILL

    def test_identical_copy_is_a_noop(self, packaged: Path, tmp_path: Path):
        first = install(HOSTS["claude"], tmp_path)
        mtime = (first / "SKILL.md").stat().st_mtime_ns
        second = install(HOSTS["claude"], tmp_path)
        assert second == first
        assert (first / "SKILL.md").stat().st_mtime_ns == mtime

    def test_differing_copy_is_refused_without_force(self, packaged: Path, tmp_path: Path):
        dest = install(HOSTS["claude"], tmp_path)
        (dest / "SKILL.md").write_bytes(b"edited\n")
        with pytest.raises(SkillInstallError, match="--force"):
            install(HOSTS["claude"], tmp_path)
        assert (dest / "SKILL.md").read_bytes() == b"edited\n"

    def test_force_overwrites_and_removes_extras(self, packaged: Path, tmp_path: Path):
        dest = install(HOSTS["claude"], tmp_path)
        (dest / "SKILL.md").write_bytes(b"edited\n")
        (dest / "references" / "extra.md").write_bytes(b"mine\n")
        install(HOSTS["claude"], tmp_path, force=True)
        _assert_identical(dest)
        assert not (dest / "references" / "extra.md").exists()
        assert diff_installed(HOSTS["claude"], tmp_path) == []

    def test_dry_run_writes_nothing(self, packaged: Path, tmp_path: Path, capsys):
        dest = install(HOSTS["claude"], tmp_path, dry_run=True)
        assert not dest.exists()
        out = capsys.readouterr().out
        assert "would write" in out
        assert str(dest / "SKILL.md") in out


class TestDiffInstalled:
    def test_identical(self, packaged: Path, tmp_path: Path):
        install(HOSTS["claude"], tmp_path)
        assert diff_installed(HOSTS["claude"], tmp_path) == []

    def test_changed_missing_extra(self, packaged: Path, tmp_path: Path):
        dest = install(HOSTS["claude"], tmp_path)
        (dest / "SKILL.md").write_bytes(b"edited\n")
        (dest / "references" / "x.md").unlink()
        (dest / "scripts" / "extra.sh").write_bytes(b"\n")
        assert diff_installed(HOSTS["claude"], tmp_path) == [
            "changed: SKILL.md",
            "missing: references/x.md",
            "extra: scripts/extra.sh",
        ]

    def test_not_installed_reports_every_file_missing(self, packaged: Path, tmp_path: Path):
        lines = diff_installed(HOSTS["gemini"], tmp_path)
        assert lines == [f"missing: {rel}" for rel in sorted(FAKE_FILES)]


# ---------------------------------------------------------------------------
# main(): install
# ---------------------------------------------------------------------------


class TestMainInstall:
    def test_install_per_host(self, packaged: Path, root: Path, capsys):
        for name, host in HOSTS.items():
            assert main(["install", "--host", name]) == 0
            dest = root / host.project_dir / SKILL
            _assert_identical(dest)
            out = capsys.readouterr().out
            assert f"{name} -> {dest}" in out

    def test_default_host_is_all(self, packaged: Path, root: Path, capsys):
        (root / ".gemini").mkdir()
        assert main(["install"]) == 0
        out = capsys.readouterr().out
        assert f"installed claude -> {root / '.claude/skills' / SKILL}" in out
        assert f"installed agents -> {root / '.agents/skills' / SKILL}" in out
        assert f"installed gemini -> {root / '.gemini/skills' / SKILL}" in out
        assert "cursor" not in out
        assert not (root / ".cursor").exists()

    def test_force_all_installs_everywhere(self, packaged: Path, root: Path, capsys):
        assert main(["install", "--force-all"]) == 0
        for host in HOSTS.values():
            _assert_identical(root / host.project_dir / SKILL)
        out = capsys.readouterr().out
        assert "installed cursor" in out
        assert "installed gemini" in out

    def test_global_installs_under_home(self, packaged: Path, root: Path, home: Path, capsys):
        assert main(["install", "--host", "codex", "--global"]) == 0
        dest = home / ".codex/skills" / SKILL
        _assert_identical(dest)
        assert str(dest) in capsys.readouterr().out
        assert not (root / ".agents").exists()

    def test_second_identical_install_is_unchanged(self, packaged: Path, root: Path, capsys):
        assert main(["install", "--host", "claude"]) == 0
        capsys.readouterr()
        assert main(["install", "--host", "claude"]) == 0
        out = capsys.readouterr().out
        assert out.startswith("unchanged claude -> ")

    def test_modified_copy_refused_then_forced(self, packaged: Path, root: Path, capsys):
        assert main(["install", "--host", "claude"]) == 0
        dest = root / ".claude/skills" / SKILL
        (dest / "SKILL.md").write_bytes(b"edited\n")
        capsys.readouterr()

        assert main(["install", "--host", "claude"]) == 1
        captured = capsys.readouterr()
        assert "refused: claude" in captured.err
        assert "--force" in captured.err
        assert (dest / "SKILL.md").read_bytes() == b"edited\n"

        assert main(["install", "--host", "claude", "--force"]) == 0
        assert "installed claude" in capsys.readouterr().out
        _assert_identical(dest)

    def test_dry_run_writes_nothing_and_prints_destination(
        self, packaged: Path, root: Path, capsys
    ):
        assert main(["install", "--host", "claude", "--dry-run"]) == 0
        dest = root / ".claude/skills" / SKILL
        assert not dest.exists()
        assert not (root / ".claude").exists()
        out = capsys.readouterr().out
        assert f"would install claude -> {dest}" in out
        assert f"would write {dest / 'SKILL.md'}" in out

    def test_unverified_host_prints_note_on_stderr(self, packaged: Path, root: Path, capsys):
        assert main(["install", "--host", "antigravity"]) == 0
        captured = capsys.readouterr()
        assert (
            "note: antigravity: location not verified against vendor documentation" in captured.err
        )
        assert "installed antigravity" in captured.out

    def test_verified_host_prints_no_note(self, packaged: Path, root: Path, capsys):
        assert main(["install", "--host", "claude"]) == 0
        assert capsys.readouterr().err == ""

    def test_codex_prints_resolved_destination_on_stdout(self, packaged: Path, root: Path, capsys):
        assert main(["install", "--host", "codex"]) == 0
        dest = root / ".agents/skills" / SKILL
        captured = capsys.readouterr()
        assert f"codex: resolved destination is {dest}" in captured.out
        _assert_identical(dest)
        # Codex's global dir could not be re-verified: say so on stderr.
        assert "note: codex:" in captured.err

    def test_unknown_host_exits_2_with_message(self, packaged: Path, root: Path, capsys):
        assert main(["install", "--host", "emacs"]) == 2
        assert "unknown host 'emacs'" in capsys.readouterr().err

    def test_missing_package_exits_2(self, root: Path, monkeypatch: pytest.MonkeyPatch, capsys):
        def boom():
            raise FileNotFoundError("Packaged skill 'ai-safety-audit' not found")

        monkeypatch.setattr(skillcmd, "iter_skill_files", boom)
        assert main(["install", "--host", "claude"]) == 2
        assert "not found" in capsys.readouterr().err
        assert not (root / ".claude").exists()

    def test_never_writes_outside_the_skill_directory(self, packaged: Path, root: Path):
        (root / ".claude").mkdir()
        settings = root / ".claude" / "settings.json"
        settings.write_bytes(b"{}")
        assert main(["install", "--host", "claude", "--force"]) == 0
        assert settings.read_bytes() == b"{}"
        assert sorted(p.name for p in (root / ".claude").iterdir()) == ["settings.json", "skills"]


# ---------------------------------------------------------------------------
# main(): diff, path, list, no verb
# ---------------------------------------------------------------------------


class TestMainDiff:
    def test_identical_exits_0(self, packaged: Path, root: Path, capsys):
        assert main(["install", "--host", "claude"]) == 0
        capsys.readouterr()
        assert main(["diff", "--host", "claude"]) == 0
        assert capsys.readouterr().out.startswith("identical: claude -> ")

    def test_changed_file_exits_1(self, packaged: Path, root: Path, capsys):
        assert main(["install", "--host", "claude"]) == 0
        (root / ".claude/skills" / SKILL / "SKILL.md").write_bytes(b"edited\n")
        capsys.readouterr()
        assert main(["diff", "--host", "claude"]) == 1
        out = capsys.readouterr().out
        assert "differs: claude -> " in out
        assert "changed: SKILL.md" in out

    def test_missing_file_exits_1(self, packaged: Path, root: Path, capsys):
        assert main(["install", "--host", "claude"]) == 0
        (root / ".claude/skills" / SKILL / "references" / "x.md").unlink()
        capsys.readouterr()
        assert main(["diff", "--host", "claude"]) == 1
        assert "missing: references/x.md" in capsys.readouterr().out

    def test_not_installed_exits_1(self, packaged: Path, root: Path, capsys):
        assert main(["diff", "--host", "cursor"]) == 1
        assert capsys.readouterr().out.startswith("not installed: cursor -> ")

    def test_all_reports_each_host(self, packaged: Path, root: Path, capsys):
        assert main(["install"]) == 0
        capsys.readouterr()
        assert main(["diff"]) == 0
        out = capsys.readouterr().out
        assert "identical: claude" in out
        assert "identical: agents" in out

    def test_global_diff_uses_home(self, packaged: Path, root: Path, home: Path, capsys):
        assert main(["install", "--host", "gemini", "--global"]) == 0
        capsys.readouterr()
        assert main(["diff", "--host", "gemini", "--global"]) == 0
        assert str(home / ".gemini/skills" / SKILL) in capsys.readouterr().out

    def test_missing_package_exits_2(self, root: Path, monkeypatch: pytest.MonkeyPatch, capsys):
        def boom():
            raise FileNotFoundError("Packaged skill 'ai-safety-audit' not found")

        monkeypatch.setattr(skillcmd, "skill_root", boom)
        monkeypatch.setattr(skillcmd, "iter_skill_files", boom)
        (root / ".claude/skills" / SKILL).mkdir(parents=True)
        assert main(["diff", "--host", "claude"]) == 2
        assert "not found" in capsys.readouterr().err


class TestMainOther:
    def test_path_prints_skill_root(self, packaged: Path, capsys):
        assert main(["path"]) == 0
        assert capsys.readouterr().out.strip() == str(packaged)

    def test_path_exits_2_when_package_missing(self, monkeypatch: pytest.MonkeyPatch, capsys):
        def boom():
            raise FileNotFoundError("Packaged skill 'ai-safety-audit' not found")

        monkeypatch.setattr(skillcmd, "skill_root", boom)
        assert main(["path"]) == 2
        assert "not found" in capsys.readouterr().err

    def test_list_is_ascii_and_names_every_host(self, capsys):
        assert main(["list"]) == 0
        out = capsys.readouterr().out
        assert out.isascii()
        header = out.splitlines()[0]
        for column in ("name", "project dir", "global dir", "verified", "source"):
            assert column in header
        for host in HOSTS.values():
            assert host.name in out
            if host.source:
                assert host.source in out
        assert "~/.codex/skills/" in out

    def test_no_verb_prints_help_and_exits_2(self, capsys):
        assert main([]) == 2
        assert "aisg skill" in capsys.readouterr().out

    def test_help_text_states_the_all_rule(self):
        text = skillcmd.build_parser().format_help()
        assert "claude and agents always" in text
        assert "--force-all" in text


# ---------------------------------------------------------------------------
# Integration: the real packaged skill
# ---------------------------------------------------------------------------


def test_real_package_installs_to_tmp(tmp_path: Path):
    from aisg.skills import skill_root as real_skill_root

    try:
        real_skill_root()
    except FileNotFoundError as exc:
        pytest.skip(f"packaged skill not present in this checkout: {exc}")

    dest = install(HOSTS["claude"], tmp_path)
    assert dest == tmp_path / ".claude/skills" / SKILL
    assert (dest / "SKILL.md").exists()
    assert diff_installed(HOSTS["claude"], tmp_path) == []
