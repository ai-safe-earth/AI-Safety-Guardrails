"""tests/unit/test_ci_surface.py
------------------------------
The CI files other people depend on. `release.yml` publishes the package: it must use
trusted publishing (no password, no token secret), pause on the `pypi` environment for a
reviewer, gate on the version sites and the suite, and smoke-test the published package
through `uvx`, the path the skill's bootstrap takes.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
RELEASE = REPO / ".github" / "workflows" / "release.yml"


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(doc: dict) -> dict:
    # PyYAML reads the bare key `on` as the boolean True.
    return doc.get("on") or doc.get(True) or {}


def _steps_text(job: dict) -> str:
    return "\n".join(
        str(step.get("run", "")) + " " + str(step.get("uses", "")) for step in job.get("steps", [])
    )


class TestReleaseWorkflow:
    def test_parses_and_triggers_on_version_tags(self) -> None:
        doc = _load(RELEASE)
        triggers = _triggers(doc)
        assert triggers["push"]["tags"] == ["v*"]
        assert "workflow_dispatch" in triggers
        assert set(doc["jobs"]) == {"gate", "build", "publish", "github-release", "smoke"}

    def test_default_permissions_are_read_only(self) -> None:
        doc = _load(RELEASE)
        assert doc["permissions"] == {"contents": "read"}

    def test_gate_checks_version_sites_suite_and_self_audit(self) -> None:
        gate = _load(RELEASE)["jobs"]["gate"]
        text = _steps_text(gate)
        assert "scripts/bump_version.py --check --tag" in text
        assert "scripts/sync_skill.py --check" in text
        assert "scripts/controls_md.py --check" in text
        assert "pytest -q" in text
        assert "aisg audit . --no-external --fail-on high --baseline audit-baseline.json" in text

    def test_publish_uses_trusted_publishing_behind_the_pypi_environment(self) -> None:
        publish = _load(RELEASE)["jobs"]["publish"]
        assert publish["environment"] == "pypi"
        assert publish["permissions"]["id-token"] == "write"
        assert publish["needs"] == "build"
        uses = [str(step.get("uses", "")) for step in publish["steps"]]
        assert any(u.startswith("pypa/gh-action-pypi-publish@") for u in uses)
        raw = RELEASE.read_text(encoding="utf-8")
        assert "password" not in raw
        assert "PYPI_TOKEN" not in raw and "PYPI_API_TOKEN" not in raw
        assert not re.search(r"secrets\.\w*PYPI", raw)

    def test_publish_release_and_smoke_run_only_on_a_pushed_tag(self) -> None:
        jobs = _load(RELEASE)["jobs"]
        for name in ("publish", "github-release", "smoke"):
            assert jobs[name]["if"] == "github.event_name == 'push'", name

    def test_release_notes_come_from_the_changelog(self) -> None:
        job = _load(RELEASE)["jobs"]["github-release"]
        text = _steps_text(job)
        assert "bump_version.py --changelog-section" in text
        assert "gh release create" in text
        assert job["permissions"]["contents"] == "write"

    def test_smoke_runs_the_published_package_through_uvx_with_exact_exit_codes(self) -> None:
        smoke = _load(RELEASE)["jobs"]["smoke"]
        text = _steps_text(smoke)
        assert 'uvx --from "aisguard==${V}" aisg --version' in text
        assert "clean_py" in text and "py_agent" in text
        assert '[ "$rc" -eq 0 ]' in text and '[ "$rc" -eq 1 ]' in text
        assert "mktemp -d" in text  # never from this repo's root: [tool.aisg-audit] would leak

    def test_build_pins_the_build_tool_and_checks_the_top_level_name(self) -> None:
        build = _load(RELEASE)["jobs"]["build"]
        text = _steps_text(build)
        assert "pip install build==" in text
        assert 'if pkgs != {"aisg"}' in text

    def test_every_third_party_action_is_pinned_to_a_tag(self) -> None:
        doc = _load(RELEASE)
        for job in doc["jobs"].values():
            for step in job["steps"]:
                uses = step.get("uses")
                if uses:
                    assert "@" in uses, uses
