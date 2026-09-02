"""tests/unit/test_skill_package.py
--------------------------------
Pins the shipped `ai-safety-audit` skill package: the canonical tree under
`src/aisg/skills/`, its two byte-identical mirrors, the bootstrap scripts' pin and
ignore marker, the wording rules (no compliance claims, no unicode), and the dev
tool that keeps the mirrors in sync.

Every path derives from the repo root so the file runs on Windows and Linux CI alike;
shell-driven checks skip when `sh` is absent.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from aisg.skills import SKILL_NAME, iter_skill_files, skill_root

REPO = Path(__file__).resolve().parents[2]
CANONICAL = REPO / "src" / "aisg" / "skills" / SKILL_NAME
MIRRORS = (
    REPO / ".claude" / "skills" / SKILL_NAME,
    REPO / ".agents" / "skills" / SKILL_NAME,
)
SCRIPTS = ("audit.sh", "audit.ps1", "verify.sh", "verify.ps1")
SYNC_TOOL = REPO / "scripts" / "sync_skill.py"
PYPROJECT = REPO / "pyproject.toml"

IGNORE_MARKER = "# aisg-audit: ignore-file"

# The negative-phrase list. Defined once here; the report module's copy must match so the
# skill text and the renderer are held to the same rule.
BANNED_PHRASES: tuple[str, ...] = (
    "is compliant",
    "compliance verified",
    "certified",
    "meets the requirements",
    "fully compliant",
    "passes the eu",
    "nist compliant",
)

SH = shutil.which("sh")
needs_sh = pytest.mark.skipif(SH is None, reason="sh not on PATH")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def tree(root: Path) -> dict[str, bytes]:
    """`{posix relpath: bytes}` under `root`, skipping `__pycache__`."""
    files: dict[str, bytes] = {}
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if not path.is_file() or "__pycache__" in rel.parts:
            continue
        files[rel.as_posix()] = path.read_bytes()
    return files


def project_version() -> str:
    text = PYPROJECT.read_text(encoding="utf-8")
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ModuleNotFoundError:
            m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.MULTILINE)
            assert m, "pyproject.toml: [project].version not found"
            return m.group(1)
    return str(tomllib.loads(text)["project"]["version"])


def skill_md() -> str:
    return (CANONICAL / "SKILL.md").read_text(encoding="utf-8")


def frontmatter(text: str) -> dict:
    lines = text.splitlines()
    assert lines[0] == "---", "SKILL.md must start with a frontmatter fence"
    end = lines.index("---", 1)
    data = yaml.safe_load("\n".join(lines[1:end]))
    assert isinstance(data, dict)
    return data


def reference_docs() -> list[Path]:
    docs = sorted((CANONICAL / "references").rglob("*.md"))
    assert docs, "references/ holds no markdown"
    return docs


def run_script(script: Path, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    assert SH is not None
    return subprocess.run(
        [SH, str(script)],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


# ---------------------------------------------------------------------------
# Package data
# ---------------------------------------------------------------------------


class TestPackagedSkill:
    def test_skill_root_is_the_canonical_tree(self):
        root = skill_root()
        assert (root / "SKILL.md").is_file()
        assert root.resolve() == CANONICAL.resolve()
        assert CANONICAL.is_relative_to(REPO / "src" / "aisg" / "skills")

    def test_iter_skill_files_matches_the_tree(self):
        assert dict(iter_skill_files()) == tree(CANONICAL)

    def test_required_files_present(self):
        rels = set(tree(CANONICAL))
        expected = {
            "SKILL.md",
            "agents/openai.yaml",
            "references/controls.md",
            "references/hosts.md",
            "references/report-format.md",
            "references/apply/python.md",
            "references/apply/typescript.md",
            "references/apply/go.md",
            "references/apply/generic.md",
        } | {f"scripts/{name}" for name in SCRIPTS}
        assert expected <= rels, sorted(expected - rels)

    def test_every_file_is_ascii(self):
        offenders = []
        for rel, content in tree(CANONICAL).items():
            try:
                content.decode("ascii")
            except UnicodeDecodeError as exc:
                offenders.append(f"{rel}: {exc.reason} at byte {exc.start}")
        assert not offenders, offenders

    def test_scripts_use_lf_line_endings(self):
        crlf = [name for name in SCRIPTS if b"\r\n" in (CANONICAL / "scripts" / name).read_bytes()]
        assert not crlf, f"CRLF in {crlf}; .gitattributes should pin eol=lf"

    def test_gitattributes_pins_script_line_endings(self):
        text = (REPO / ".gitattributes").read_text(encoding="utf-8")
        assert re.search(r"^\*\.sh\s+text\s+eol=lf", text, re.MULTILINE)
        assert re.search(r"^\*\.ps1\s+text\s+eol=lf", text, re.MULTILINE)


# ---------------------------------------------------------------------------
# SKILL.md
# ---------------------------------------------------------------------------


class TestSkillMd:
    def test_frontmatter_has_exactly_name_and_description(self):
        data = frontmatter(skill_md())
        assert set(data) == {"name", "description"}
        assert data["name"] == SKILL_NAME
        assert isinstance(data["description"], str) and data["description"].strip()

    def test_honesty_vocabulary_present(self):
        text = skill_md()
        for needle in ("legal determination", "UNMEASURED", "UNKNOWN"):
            assert needle in text, needle

    def test_scripts_referenced_only_via_skill_placeholder(self):
        text = skill_md()
        bare = re.findall(r"(?<!<skill>/)scripts/(?:audit|verify)", text)
        assert not bare, bare
        assert "<skill>/scripts/audit" in text
        assert "<skill>/scripts/verify" in text

    def test_phase_five_report_differs_from_phase_one(self):
        outputs = re.findall(r"-o\s+(\S+\.json)", skill_md())
        assert len(outputs) >= 2, outputs
        first, last = outputs[0], outputs[-1]
        assert first != last
        assert "--write-baseline" in skill_md()
        assert "--baseline" in skill_md()


# ---------------------------------------------------------------------------
# Wording
# ---------------------------------------------------------------------------


class TestWording:
    def test_banned_phrases_match_the_report_module(self):
        try:
            from aisg.devtools.audit.report import BANNED_PHRASES as REPORT_PHRASES
        except ImportError:
            pytest.skip("aisg.devtools.audit.report not importable")
        assert tuple(REPORT_PHRASES) == BANNED_PHRASES

    @pytest.mark.parametrize(
        "path",
        [CANONICAL / "SKILL.md", *reference_docs()],
        ids=lambda p: p.relative_to(CANONICAL).as_posix(),
    )
    def test_no_compliance_claims(self, path: Path):
        lowered = path.read_text(encoding="utf-8").lower()
        found = [phrase for phrase in BANNED_PHRASES if phrase in lowered]
        assert not found, found

    def test_openai_yaml_is_a_plain_mapping(self):
        data = yaml.safe_load((CANONICAL / "agents" / "openai.yaml").read_text(encoding="utf-8"))
        assert isinstance(data, dict) and data


# ---------------------------------------------------------------------------
# Scripts
# ---------------------------------------------------------------------------


class TestScripts:
    @pytest.mark.parametrize("name", SCRIPTS)
    def test_ignore_marker_in_first_five_lines(self, name: str):
        head = (CANONICAL / "scripts" / name).read_text(encoding="utf-8").splitlines()[:5]
        assert any(IGNORE_MARKER in line for line in head), head

    @pytest.mark.parametrize("name", SCRIPTS)
    def test_version_pinned_to_pyproject(self, name: str):
        text = (CANONICAL / "scripts" / name).read_text(encoding="utf-8")
        pins = re.findall(r'^\$?AISG_VERSION\s*=\s*"([^"]*)"', text, re.MULTILINE)
        assert pins, f"{name}: no AISG_VERSION line"
        assert set(pins) == {project_version()}, pins

    @pytest.mark.parametrize("name", SCRIPTS)
    def test_every_bootstrap_argument_is_pinned(self, name: str):
        text = (CANONICAL / "scripts" / name).read_text(encoding="utf-8")
        specs = re.findall(r"(?:--from|--spec)\s+(\S+)", text)
        assert specs, f"{name}: no --from/--spec bootstrap"
        unpinned = [spec for spec in specs if "==" not in spec]
        assert not unpinned, unpinned

    @pytest.mark.parametrize("name", ["verify.sh", "verify.ps1"])
    def test_never_asserts_probe_authorization(self, name: str):
        # Saying the script never adds the flag (comment, echo) is fine; passing it to
        # `aisg probe` through the bootstrap chain is not.
        text = (CANONICAL / "scripts" / name).read_text(encoding="utf-8")
        invocations = [
            line
            for line in text.splitlines()
            if re.search(r"\b(run_aisg|Invoke-Aisg|aisg)\s+probe\b", line)
            and not line.lstrip().startswith("#")
            and not re.search(r"\b(echo|Write-Output|WriteLine)\b", line)
        ]
        assert invocations, f"{name}: no probe invocation found"
        offending = [line for line in invocations if "--i-have-authorization" in line]
        assert not offending, offending

    @needs_sh
    @pytest.mark.parametrize("name", ["audit.sh", "verify.sh"])
    def test_sh_syntax(self, name: str):
        proc = subprocess.run(
            [SH, "-n", str(CANONICAL / "scripts" / name)],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr

    @needs_sh
    def test_audit_sh_without_aisg_exits_2(self, tmp_path: Path):
        proc = run_script(CANONICAL / "scripts" / "audit.sh", tmp_path, {"PATH": ""})
        assert proc.returncode == 2, (proc.stdout, proc.stderr)
        assert "aisg not found" in proc.stderr

    @needs_sh
    def test_verify_sh_without_aisg_skips_measure(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "target"\nversion = "0.0.0"\n', encoding="utf-8"
        )
        proc = run_script(
            CANONICAL / "scripts" / "verify.sh",
            tmp_path,
            {"PATH": "", "AISG_VERIFY_RUN": "0"},
        )
        assert proc.returncode == 0, (proc.stdout, proc.stderr)
        assert "measure skipped: aisg not importable in target" in proc.stderr
        assert "pytest" in proc.stdout


# ---------------------------------------------------------------------------
# Mirrors and the sync tool
# ---------------------------------------------------------------------------


class TestMirrors:
    @pytest.mark.parametrize("mirror", MIRRORS, ids=lambda p: p.relative_to(REPO).as_posix())
    def test_mirror_is_byte_identical(self, mirror: Path):
        assert mirror.is_dir(), f"{mirror} missing; run scripts/sync_skill.py"
        canonical = tree(CANONICAL)
        copy = tree(mirror)
        assert set(copy) == set(canonical), {
            "missing": sorted(set(canonical) - set(copy)),
            "stale": sorted(set(copy) - set(canonical)),
        }
        differing = [rel for rel in canonical if canonical[rel] != copy[rel]]
        assert not differing, differing

    def test_sync_tool_check_passes(self):
        proc = subprocess.run(
            [sys.executable, str(SYNC_TOOL), "--check"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert proc.returncode == 0, (proc.stdout, proc.stderr)


# ---------------------------------------------------------------------------
# hosts.md tracks the host table
# ---------------------------------------------------------------------------


class TestHostsDoc:
    def test_hosts_md_names_every_host_and_source(self):
        try:
            from aisg.devtools.skill import ALWAYS_HOSTS, HOSTS
        except ImportError:
            pytest.skip("aisg.devtools.skill not importable")
        text = (CANONICAL / "references" / "hosts.md").read_text(encoding="utf-8")
        for name, host in HOSTS.items():
            assert f"`{name}`" in text, name
            if host.source:
                assert host.source in text, f"{name}: {host.source}"
        for name in ALWAYS_HOSTS:
            assert f"`{name}`" in text, name
        assert "aisg skill list" in text
