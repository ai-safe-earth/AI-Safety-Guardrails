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

import os
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
CONTROLS_TOOL = REPO / "scripts" / "controls_md.py"
PYPROJECT = REPO / "pyproject.toml"

IGNORE_MARKER = "# aisg-audit: ignore-file"

# The negative-phrase list. Defined once here; the report module's copy must match so the
# skill text and the renderer are held to the same rule. Assembled from fragments, as in
# test_audit_report.py, so this file carries none of them as a contiguous literal.
BANNED_PHRASES: tuple[str, ...] = (
    " ".join(("is", "compliant")),
    " ".join(("compliance", "verified")),
    "certi" + "fied",
    " ".join(("meets", "the", "requirements")),
    " ".join(("fully", "compliant")),
    " ".join(("passes", "the", "eu")),
    " ".join(("nist", "compliant")),
)
# The one word the audit bans outright; the skill text is held to it too.
BANNED_WORD = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)

# Phase-3 and document vocabulary the skill must name (design section 7). Each is a flag,
# path or JSON key another slice implements; a rename there must reach the skill text.
SKILL_MD_NEEDLES = (
    ".aisg-audit/",
    "--amend-baseline",
    "--accept",
    "--format html",
    "recommendation.package",
    "leaves_open",
    "same_control",
)
REPORT_FORMAT_NEEDLES = (
    "html",
    "accepted_reason",
    "no_longer_reported",
    "own_output_skipped",
    "recommendation.package",
    "generated_at",
    "--write-baseline",
    "--amend-baseline",
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


FAKE_LOG = "aisg-calls.log"

# A stand-in `aisg` for the verify script: appends every argv to FAKE_LOG (relative to the
# cwd, so sh on Windows needs no path translation) and, for `probe`, writes a report with
# one failed case to the `-o` path and exits 1 the way the real probe does.
_FAKE_AISG = """#!/bin/sh
printf '%s\\n' "$*" >> "$AISG_FAKE_LOG"
if [ "$1" = "probe" ]; then
  out=""
  while [ $# -gt 0 ]; do
    [ "$1" = "-o" ] && out="$2"
    shift
  done
  printf '%s\\n' '{"schema": "aisg/1", "summary": {"sent": 1, "passed": 0, "failed": 1, "errors": 0, "skipped": 0, "inconclusive": 0}}' > "$out"
  exit 1
fi
exit 0
"""


def fake_aisg_env(tmp_path: Path, **extra: str) -> dict[str, str]:
    """An env whose PATH holds `sh`'s own bin dir and a fake `aisg`, plus `extra`."""
    assert SH is not None
    bin_dir = tmp_path / "fake-bin"
    bin_dir.mkdir()
    fake = bin_dir / "aisg"
    fake.write_text(_FAKE_AISG, encoding="utf-8", newline="\n")
    fake.chmod(0o755)
    env = {
        "PATH": os.pathsep.join([str(Path(SH).parent), str(bin_dir)]),
        "AISG_FAKE_LOG": FAKE_LOG,
    }
    env.update(extra)
    return env


def write_configs(tmp_path: Path) -> None:
    """A settings-only YAML that sorts first, then one with a stage key `from_config` reads."""
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "00-settings.yaml").write_text(
        "pipeline:\n  parallel_checks: true\n", encoding="utf-8"
    )
    (tmp_path / "config" / "guardrails.yaml").write_text(
        "input:\n  pii_detector:\n    enabled: true\n", encoding="utf-8"
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

    @pytest.mark.parametrize("needle", SKILL_MD_NEEDLES)
    def test_names_the_phase_three_vocabulary(self, needle: str):
        assert needle in skill_md(), needle

    def test_five_phases_in_order(self):
        text = skill_md()
        positions = [text.find(f"## Phase {n} --") for n in range(1, 6)]
        assert all(p >= 0 for p in positions), positions
        assert positions == sorted(positions), positions

    def test_every_artefact_lives_under_aisg_audit(self):
        # Every `-o <path>` and every `--baseline`/`--write-baseline`/`--amend-baseline
        # <path>` in SKILL.md points into `.aisg-audit/`, so two documents made in one
        # session describe one scan from one working directory.
        commands = [
            line
            for line in skill_md().splitlines()
            if re.match(r"\s{4,}\S", line) and "audit" in line
        ]
        assert commands, "SKILL.md: no indented command lines"
        paths = []
        for line in commands:
            paths += re.findall(
                r"(?:\s-o|--baseline|--write-baseline|--amend-baseline)\s+(\S+)", line
            )
        assert paths
        stray = [p for p in paths if not p.startswith(".aisg-audit/")]
        assert not stray, stray

    def test_never_edits_gitignore_unasked(self):
        assert "never edits `.gitignore`" in skill_md()

    def test_re_audit_is_the_evidence(self):
        text = skill_md()
        assert "Applying a diff is not evidence" in text
        assert "audit-recheck.json" in text


# ---------------------------------------------------------------------------
# references/
# ---------------------------------------------------------------------------


class TestReferences:
    @pytest.mark.parametrize("needle", REPORT_FORMAT_NEEDLES)
    def test_report_format_documents_the_new_keys(self, needle: str):
        text = (CANONICAL / "references" / "report-format.md").read_text(encoding="utf-8")
        assert needle in text, needle

    def test_report_format_names_the_html_marker_line(self):
        text = (CANONICAL / "references" / "report-format.md").read_text(encoding="utf-8")
        assert IGNORE_MARKER in text

    def test_controls_has_a_package_column(self):
        text = (CANONICAL / "references" / "controls.md").read_text(encoding="utf-8")
        header = re.search(r"^\|\s*rule\s*\|\s*Package \(mechanism\)\s*\|.*$", text, re.MULTILINE)
        assert header, "controls.md: no Package column header"
        assert "same control?" in header.group(0)
        assert "symbols" in header.group(0)

    def test_controls_package_column_covers_every_rule(self):
        try:
            from aisg.devtools.audit.rules import ALL_RULES
        except ImportError:
            pytest.skip("aisg.devtools.audit.rules not importable")
        text = (CANONICAL / "references" / "controls.md").read_text(encoding="utf-8")
        rows = set(re.findall(r"^\|\s*(AUD-\d+)\s*\|", text, re.MULTILINE))
        expected = {rule.id for rule in ALL_RULES}
        assert rows == expected, {
            "missing": sorted(expected - rows),
            "extra": sorted(rows - expected),
        }

    def test_controls_says_a_detector_is_never_the_control(self):
        text = (CANONICAL / "references" / "controls.md").read_text(encoding="utf-8")
        flat = " ".join(text.split())
        assert "A detector is never the control for a P1-P4 finding" in flat

    def test_python_idioms_are_keyed_by_symbol(self):
        # Phase 3 jumps to the section whose heading starts with the first entry of
        # `recommendation.package.symbols`; every symbol named in controls.md must have one.
        controls = (CANONICAL / "references" / "controls.md").read_text(encoding="utf-8")
        python = (CANONICAL / "references" / "apply" / "python.md").read_text(encoding="utf-8")
        headings = re.findall(r"^##+ `([^`]+)`", python, re.MULTILINE)
        first_symbols = set()
        for row in re.findall(
            r"^\|\s*AUD-\d+\s*\|[^|]*\|[^|]*\|\s*`([^`]+)`", controls, re.MULTILINE
        ):
            first_symbols.add(row)
        assert first_symbols, "controls.md: no symbols in the Package column"
        missing = sorted(first_symbols - set(headings))
        assert not missing, missing
        assert "Leaves open" in python

    @pytest.mark.parametrize("name", ["typescript.md", "go.md", "generic.md"])
    def test_non_python_guides_say_symbols_are_python_only(self, name: str):
        text = (CANONICAL / "references" / "apply" / name).read_text(encoding="utf-8")
        assert "Python-only" in text
        assert "recommendation.package.symbols" in text

    def test_report_format_quotes_the_real_controls_line(self):
        # The renderers print `controls: <items>` (terminal and markdown) and the html
        # prints no such list; the doc used to name a label no renderer emits.
        try:
            from aisg.devtools.audit import report
        except ImportError:
            pytest.skip("aisg.devtools.audit.report not importable")
        text = (CANONICAL / "references" / "report-format.md").read_text(encoding="utf-8")
        assert f"`{report._T_CONTROLS.format(items='<items>')}`" in text
        assert "Related controls" not in text

    def test_report_format_documents_both_masking_shapes(self):
        # Secrets are masked by `model.redact()` as `<redacted:PREFIX...LAST4>`; PII hits
        # are masked at discovery as `<pii:ENTITY>`. Two mechanisms, two shapes.
        try:
            from aisg.devtools.audit.model import redact
            from aisg.devtools.audit.patterns import PII_TABLE
        except ImportError:
            pytest.skip("aisg.devtools.audit not importable")
        text = (CANONICAL / "references" / "report-format.md").read_text(encoding="utf-8")
        assert "<redacted:PREFIX...LAST4>" in text
        assert redact("sk-ant-" + "a" * 30) == "<redacted:sk-ant-...aaaa>"
        assert "<pii:ENTITY>" in text
        for entity, _rx in PII_TABLE:
            assert f"`<pii:{entity}>`" in text, entity
        assert "<redacted:email>" not in text.lower()

    def test_skill_docs_state_the_unfilled_incident_contact_wording(self):
        # A blank or TODO `incident_contact` is absent for AUD-703, but the snippet says
        # `unfilled`, not `no`, and the docs must say the same.
        rule = (
            REPO / "src" / "aisg" / "devtools" / "audit" / "rules" / "observability.py"
        ).read_text(encoding="utf-8")
        assert "unfilled" in rule and "incident_contact" in rule
        for name in ("apply/python.md", "controls.md"):
            text = (CANONICAL / "references" / name).read_text(encoding="utf-8")
            flat = " ".join(text.split())
            assert "has an unfilled incident_contact" in flat, name
            assert "treats an empty or `TODO`-prefixed value as absent" not in flat, name

    def test_python_idioms_point_at_the_json_leaves_open(self):
        # The bullets in python.md are a summary; the plan row quotes the registry text,
        # which only the JSON (and controls.md, regenerated from it) carries verbatim.
        python = (CANONICAL / "references" / "apply" / "python.md").read_text(encoding="utf-8")
        assert "recommendation.package.leaves_open" in python
        assert "summary" in python


# ---------------------------------------------------------------------------
# controls.md against the rule registry
# ---------------------------------------------------------------------------


def _rule_sections(text: str) -> dict[str, tuple[str, list[str]]]:
    """`{rule id: (heading parenthetical, bullet texts)}` for every `### AUD-` section."""
    sections: dict[str, tuple[str, list[str]]] = {}
    current: str | None = None
    bullets: list[str] = []
    paren = ""
    for line in text.split("\n"):
        head = re.match(r"^### (AUD-\d+) .+? \(([^()]*)\)\s*$", line)
        if head:
            if current is not None:
                sections[current] = (paren, bullets)
            current, paren, bullets = head.group(1), head.group(2), []
            continue
        if line.startswith("#"):
            if current is not None:
                sections[current] = (paren, bullets)
            current = None
            continue
        if current is None:
            continue
        if line.startswith("- "):
            bullets.append(line[2:])
        elif line.startswith("  ") and bullets:
            bullets[-1] += " " + line.strip()
    if current is not None:
        sections[current] = (paren, bullets)
    return {
        rule_id: (paren, [" ".join(b.split()) for b in bs])
        for rule_id, (paren, bs) in sections.items()
    }


class TestControlsMatchesRegistry:
    """
    The severity word, the `- Mapping:` line and the `Leaves open:` text in every
    controls.md section are copies of the rule class; `scripts/controls_md.py` regenerates
    them and this pins that nobody edited the copy by hand.
    """

    @pytest.fixture(scope="class")
    def rules(self):
        try:
            from aisg.devtools.audit.rules import ALL_RULES
        except ImportError:
            pytest.skip("aisg.devtools.audit.rules not importable")
        return {rule.id: rule for rule in ALL_RULES}

    @pytest.fixture(scope="class")
    def sections(self):
        text = (CANONICAL / "references" / "controls.md").read_text(encoding="utf-8")
        found = _rule_sections(text)
        assert found, "controls.md: no `### AUD-` sections"
        return found

    def test_one_section_per_rule(self, rules, sections):
        assert set(sections) == set(rules), {
            "missing": sorted(set(rules) - set(sections)),
            "extra": sorted(set(sections) - set(rules)),
        }

    def test_heading_severity_is_the_rule_severity(self, rules, sections):
        wrong = {}
        for rule_id, (paren, _) in sections.items():
            # The parenthetical opens with the severity; a qualifier may follow it after
            # `;` or `,` (`high, REPORTED`, `high; per tool`).
            word = re.split(r"[;,\s]", paren.strip(), maxsplit=1)[0]
            if word != rules[rule_id].severity.value:
                wrong[rule_id] = (word, rules[rule_id].severity.value)
        assert not wrong, wrong

    def test_mapping_line_is_the_controls_tuple(self, rules, sections):
        wrong = {}
        for rule_id, (_, bullets) in sections.items():
            found = [b for b in bullets if b.startswith("Mapping:")]
            expected = "Mapping: " + ", ".join(rules[rule_id].controls) + "."
            if found != [expected]:
                wrong[rule_id] = (found, expected)
        assert not wrong, wrong

    def test_leaves_open_is_the_registry_text(self, rules, sections):
        wrong = {}
        for rule_id, (_, bullets) in sections.items():
            package = [b for b in bullets if b.startswith("Package:")]
            assert len(package) == 1, (rule_id, package)
            _, sep, tail = package[0].partition("Leaves open:")
            found = " ".join(tail.split()) if sep else ""
            expected = " ".join(rules[rule_id].recommendation.package.leaves_open.split())
            if found != expected:
                wrong[rule_id] = (found, expected)
        assert not wrong, wrong

    def test_controls_tool_check_passes(self):
        proc = subprocess.run(
            [sys.executable, str(CONTROLS_TOOL), "--check"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert proc.returncode == 0, (proc.stdout, proc.stderr)


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

    def test_no_banned_word_in_any_skill_file(self):
        offenders = [
            rel
            for rel, content in tree(CANONICAL).items()
            if BANNED_WORD.search(content.decode("ascii", errors="replace"))
        ]
        assert not offenders, offenders

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

    @pytest.mark.parametrize("name", ["verify.sh", "verify.ps1"])
    def test_verify_reports_live_under_aisg_audit(self, name: str):
        # SKILL.md says every artefact of the flow lives under `.aisg-audit/`, and the
        # walker discovers measure and probe reports there even when gitignored. The
        # scripts used to write both to the repository root.
        text = (CANONICAL / "scripts" / name).read_text(encoding="utf-8")
        assert re.search(r'^\$?report_?[dD]ir\s*=\s*"\.aisg-audit"', text, re.MULTILINE), name
        for report in ("measure-report.json", "probe-report.json"):
            hits = [m.start() for m in re.finditer(re.escape(report), text)]
            assert hits, (name, report)
            for pos in hits:
                lead = text[max(0, pos - 12) : pos]
                assert lead.endswith(("$report_dir/", "$reportDir/")), (name, text[pos - 40 : pos])
        assert not re.search(r"-o\s+(?:measure|probe)-report\.json", text), name
        # The CLIs do not create a missing parent directory, so the script must.
        created = re.search(
            r'mkdir -p "\$report_dir"|New-Item -ItemType Directory -Force -Path \$reportDir', text
        )
        assert created, f"{name}: never creates the report directory"

    @pytest.mark.parametrize("name", ["verify.sh", "verify.ps1"])
    def test_verify_detects_a_config_by_the_stage_keys_from_config_reads(self, name: str):
        # `GuardrailPipeline.from_config` builds guards from the top-level stage keys it
        # passes to `build_guards`; `pipeline:` is optional run settings and `guards:` is
        # never read. The pre-check keys must be exactly the ones the loader reads.
        text = (CANONICAL / "scripts" / name).read_text(encoding="utf-8")
        found = re.search(r"\^\(([a-z|]+)\):", text)
        assert found, f"{name}: no top-level key pattern"
        keys = set(found.group(1).split("|"))
        loader = (REPO / "src" / "aisg" / "core" / "pipeline.py").read_text(encoding="utf-8")
        stage_keys = set(re.findall(r'build_guards\("(\w+)"\)', loader))
        assert stage_keys, "from_config: no build_guards calls found"
        assert keys == stage_keys, (keys, stage_keys)
        assert "guards):" not in text and "(pipeline|" not in text, name
        # Every shipped preset carries at least one of those keys, so the detection
        # would find a preset copied into the target.
        pattern = re.compile(r"^(?:" + "|".join(sorted(stage_keys)) + r"):", re.MULTILINE)
        for preset in sorted((REPO / "src" / "aisg" / "config").glob("*.yaml")):
            assert pattern.search(preset.read_text(encoding="utf-8")), preset.name

    @needs_sh
    def test_verify_sh_dry_run_names_the_aisg_audit_report_and_creates_nothing(
        self, tmp_path: Path
    ):
        write_configs(tmp_path)
        proc = run_script(
            CANONICAL / "scripts" / "verify.sh",
            tmp_path,
            fake_aisg_env(tmp_path, AISG_VERIFY_RUN="0", AISG_PROBE_URL="http://127.0.0.1:9/chat"),
        )
        assert proc.returncode == 0, (proc.stdout, proc.stderr)
        assert (
            "measure: aisg measure --config config/guardrails.yaml"
            " -o .aisg-audit/measure-report.json"
        ) in proc.stdout
        assert "probe: aisg probe http://127.0.0.1:9/chat -o .aisg-audit/probe-report.json" in (
            proc.stdout
        )
        assert "not run (set AISG_VERIFY_RUN=1 to run)" in proc.stdout
        assert not (tmp_path / ".aisg-audit").exists()
        assert not (tmp_path / FAKE_LOG).exists()

    @needs_sh
    def test_verify_sh_skips_a_settings_only_config(self, tmp_path: Path):
        (tmp_path / "config").mkdir()
        (tmp_path / "config" / "run.yaml").write_text(
            "pipeline:\n  parallel_checks: true\nguards:\n  - pii_detector\n", encoding="utf-8"
        )
        proc = run_script(
            CANONICAL / "scripts" / "verify.sh",
            tmp_path,
            fake_aisg_env(tmp_path, AISG_VERIFY_RUN="1"),
        )
        assert proc.returncode == 0, (proc.stdout, proc.stderr)
        assert "measure: no pipeline config found" in proc.stdout
        assert "input:, processing:, output: or policy:" in proc.stdout
        assert not (tmp_path / FAKE_LOG).exists()

    @needs_sh
    def test_verify_sh_run_writes_both_reports_under_aisg_audit(self, tmp_path: Path):
        write_configs(tmp_path)
        proc = run_script(
            CANONICAL / "scripts" / "verify.sh",
            tmp_path,
            fake_aisg_env(tmp_path, AISG_VERIFY_RUN="1", AISG_PROBE_URL="http://127.0.0.1:9/chat"),
        )
        # The fake probe exits 1 (a case got through), which the script passes on.
        assert proc.returncode == 1, (proc.stdout, proc.stderr)
        calls = (tmp_path / FAKE_LOG).read_text(encoding="utf-8").splitlines()
        assert calls == [
            "measure --config config/guardrails.yaml -o .aisg-audit/measure-report.json",
            "probe http://127.0.0.1:9/chat -o .aisg-audit/probe-report.json",
        ]
        assert (tmp_path / ".aisg-audit" / "probe-report.json").is_file()
        assert "probe passed: 0" in proc.stdout
        assert "probe failed: 1" in proc.stdout
        assert "only 'passed' means passed" in proc.stdout


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
