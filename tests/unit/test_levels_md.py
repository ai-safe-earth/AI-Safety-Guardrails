"""tests/unit/test_levels_md.py
----------------------------
`references/levels.md` is generated from the packaged criteria file, so the skill reads
exactly what `aisg attest` checks. These tests pin that the committed file equals the
generator's output, that `--check` catches drift, and that the text is ASCII and free of the
report module's banned phrases.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

from aisg.devtools.attest import CRITERION_KINDS, CRITERION_READS, load_levels
from aisg.devtools.audit.report import BANNED_PHRASES

REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "scripts" / "levels_md.py"
LEVELS_MD = REPO / "src" / "aisg" / "skills" / "ai-safety-audit" / "references" / "levels.md"
BANNED_WORD = re.compile(r"\bcl" + r"ean\b", re.IGNORECASE)


def _module():
    spec = importlib.util.spec_from_file_location("levels_md", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def generated() -> str:
    return _module().render(load_levels(), CRITERION_READS)


class TestGenerated:
    def test_committed_file_equals_the_generator_output(self, generated: str):
        assert LEVELS_MD.read_text(encoding="utf-8") == generated

    def test_every_criterion_id_and_level_name_is_in_the_text(self, generated: str):
        levels = load_levels()
        for level in levels.levels:
            assert f"## Level {level.level}: {level.name}" in generated
        for criterion in levels.criteria():
            assert f"`{criterion.id}`" in generated, criterion.id
            assert f"`{criterion.kind}`" in generated, criterion.kind

    def test_reads_table_covers_every_kind(self):
        assert set(CRITERION_READS) == set(CRITERION_KINDS)
        assert all(text.isascii() and text for text in CRITERION_READS.values())

    def test_text_is_ascii_without_banned_phrases(self, generated: str):
        assert generated.isascii()
        lowered = generated.lower()
        for phrase in BANNED_PHRASES:
            assert phrase not in lowered, phrase
        assert not BANNED_WORD.search(generated)

    def test_states_the_level_rule_and_the_dirty_tree_rule(self, generated: str):
        assert "highest N such that every criterion of levels 0..N is met" in generated
        assert "cap the result at level 2" in generated
        assert "next_review_by" in generated and "90 days" in generated
        assert "bare fingerprint is a suppression" in generated


class TestTool:
    def test_check_passes_on_the_repo(self):
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--check"],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert proc.returncode == 0, (proc.stdout, proc.stderr)
        assert proc.stdout.startswith("in sync:")

    def test_check_fails_on_drift_and_write_repairs_it(self, tmp_path: Path):
        drifted = tmp_path / "levels.md"
        drifted.write_text(
            LEVELS_MD.read_text(encoding="utf-8") + "\nstray line\n", encoding="utf-8"
        )
        check = subprocess.run(
            [sys.executable, str(TOOL), "--check", "--path", str(drifted)],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert check.returncode == 1, (check.stdout, check.stderr)
        assert "differs" in check.stdout
        write = subprocess.run(
            [sys.executable, str(TOOL), "--path", str(drifted)],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert write.returncode == 0, (write.stdout, write.stderr)
        assert drifted.read_bytes() == LEVELS_MD.read_bytes()
        assert b"\r\n" not in drifted.read_bytes()

    def test_check_reports_a_missing_file(self, tmp_path: Path):
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--check", "--path", str(tmp_path / "none.md")],
            cwd=REPO,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert proc.returncode == 1
        assert "missing" in proc.stdout
