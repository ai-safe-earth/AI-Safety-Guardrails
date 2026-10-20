"""tests/unit/test_audit_wave1_rules.py
-------------------------------------
Two corrections the decision tool forced on the audit. AUD-801 counts an eval file's
mention of a guard as "the guard is exercised" only when the file is an eval config, a
data file or a test module: prose and a tool's own source measure nothing, and this
repository's `aisafe decide` (which names every guard) was the first file to show the
hole. And an `aisg/1` price table lists model ids in order to price them, so AUD-601
does not read them as unpinned deployments.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aisafe.devtools.audit import discover
from aisafe.devtools.audit.rules import run_rules
from aisafe.devtools.audit.rules.guards import GuardUnmeasured, _eval_evidence_file

PYPROJECT = '[project]\nname = "demo"\nversion = "0.0.1"\n'
AGENT_PY = """import anthropic
from aisafe import GuardrailPipeline

client = anthropic.Anthropic()
pipeline = GuardrailPipeline.from_config("guardrails.yaml")


def ask(text: str) -> str:
    pipeline.run_input(text)
    reply = client.messages.create(
        model="claude-sonnet-4-5", messages=[{"role": "user", "content": text}]
    )
    return reply.content[0].text
"""
PRESET_YAML = "input:\n  pii_detector:\n    enabled: true\n    action: redact\n"


def _tree(tmp_path: Path, extra: dict[str, str]) -> Path:
    root = tmp_path / "tree"
    root.mkdir()
    files = {"pyproject.toml": PYPROJECT, "agent.py": AGENT_PY, "guardrails.yaml": PRESET_YAML}
    files.update(extra)
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _801_guard_findings(audit_context, root: Path):
    findings, _ = run_rules([GuardUnmeasured], audit_context(root))
    return [f for f in findings if "pii_detector" in (f.notes or "")]


class TestEvalEvidenceFiles:
    @pytest.mark.parametrize(
        "relpath, counts",
        [
            ("promptfooconfig.yaml", True),
            ("evals/cases.json", True),
            ("bench/findings.csv", True),
            ("tests/test_guards.py", True),
            ("tests/conftest.py", True),
            ("src/pkg/guards_test.py", True),
            ("evals/run_suite.py", True),
            ("README.md", False),
            ("docs/explain/measurement.html", False),
            ("notes.txt", False),
            ("src/aisafe/devtools/decide.py", False),
            ("src/aisafe/devtools/measure.py", False),
            ("app/cli.py", False),
        ],
    )
    def test_which_eval_files_count_as_evidence(self, relpath, counts):
        assert _eval_evidence_file(relpath) is counts

    def test_a_readme_naming_the_guard_does_not_silence_801(self, tmp_path, audit_context):
        readme = "# Demo\n\nRun `aisafe measure` and `promptfoo eval`; pii_detector is on.\n"
        root = _tree(tmp_path, {"README.md": readme})
        assert _801_guard_findings(audit_context, root), "the README is prose, not an eval"

    def test_a_tool_module_naming_the_guard_does_not_silence_801(self, tmp_path, audit_context):
        module = 'TOOLS = ["aisafe measure", "promptfoo"]\nGUARDS = ["pii_detector"]\n'
        root = _tree(tmp_path, {"app/report.py": module})
        assert _801_guard_findings(audit_context, root)

    def test_a_test_module_naming_the_guard_does_silence_801(self, tmp_path, audit_context):
        # The tool mention sits in code, not a comment: discover drops a commented
        # mention, so the file would not be an eval entry at all.
        test = (
            "from aisafe import PIIDetector\n\nHARNESS = 'aisafe measure'\n\n\n"
            "def test_pii_detector_redacts():\n"
            "    assert PIIDetector().name == 'pii_detector'\n"
        )
        root = _tree(tmp_path, {"tests/test_pii.py": test})
        assert not _801_guard_findings(audit_context, root)

    def test_an_eval_config_naming_the_guard_does_silence_801(self, tmp_path, audit_context):
        config = "description: pii_detector regression\nprompts: [x]\nproviders: [y]\ntests: []\n"
        root = _tree(tmp_path, {"promptfooconfig.yaml": config})
        assert not _801_guard_findings(audit_context, root)


class TestPriceTableIsNotADeployment:
    PRICES = (
        "schema: aisg/1\nkind: prices\nas_of: 2026-10-19\nsources: [https://x]\nmodels:\n"
        "  claude-haiku-5-5:\n    provider: anthropic\n    input_usd_per_mtok: 0.1\n"
        "    output_usd_per_mtok: 0.5\n  gpt-4o:\n    provider: openai\n    free: true\n"
    )

    def test_detection(self):
        assert discover._is_price_table(self.PRICES)
        assert not discover._is_price_table("schema: aisg/1\nkind: audit\n")
        assert not discover._is_price_table("model: claude-haiku-5-5\n")

    def test_price_table_yields_no_model_id_hits(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"config/prices.yaml": self.PRICES})
        ctx = audit_context(root)
        assert not [h for h in ctx.hits if h.table == "model_id" and h.file == "config/prices.yaml"]

    def test_a_plain_config_still_yields_model_id_hits(self, tmp_path, audit_context):
        root = _tree(tmp_path, {"config/models.yaml": "judge:\n  model: claude-haiku-5-5\n"})
        ctx = audit_context(root)
        assert [h for h in ctx.hits if h.table == "model_id" and h.file == "config/models.yaml"]
