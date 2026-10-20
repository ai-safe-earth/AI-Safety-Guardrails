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
        assert "scripts/levels_md.py --check" in text
        assert "pytest -q" in text
        assert "aisafe audit . --no-external --fail-on high --baseline audit-baseline.json" in text

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
        assert 'uvx --from "aisafe==${V}" aisafe --version' in text
        assert "clean_py" in text and "py_agent" in text
        assert '[ "$rc" -eq 0 ]' in text and '[ "$rc" -eq 1 ]' in text
        assert "mktemp -d" in text  # never from this repo's root: [tool.aisafe-audit] would leak

    def test_build_pins_the_build_tool_and_checks_the_top_level_name(self) -> None:
        build = _load(RELEASE)["jobs"]["build"]
        text = _steps_text(build)
        assert "pip install build==" in text
        assert 'if pkgs != {"aisafe"}' in text

    def test_every_third_party_action_is_pinned_to_a_tag(self) -> None:
        doc = _load(RELEASE)
        for job in doc["jobs"].values():
            for step in job["steps"]:
                uses = step.get("uses")
                if uses:
                    assert "@" in uses, uses


# ---------------------------------------------------------------------------
# The consumer-facing surface: action.yml, .pre-commit-hooks.yaml, the GitLab job and
# the dogfood job in tests.yml.
# ---------------------------------------------------------------------------

ACTION = REPO / "action.yml"
PRE_COMMIT_HOOKS = REPO / ".pre-commit-hooks.yaml"
PRE_COMMIT_CONFIG = REPO / ".pre-commit-config.yaml"
GITLAB = REPO / ".gitlab-ci-euaiact.yml"
TESTS_WORKFLOW = REPO / ".github" / "workflows" / "tests.yml"


def _project_version() -> str:
    text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    return re.search(r'^version\s*=\s*"([^"]+)"', text, re.M).group(1)


class TestCompositeAction:
    def test_parses_as_a_composite_action_with_the_expected_inputs(self) -> None:
        doc = _load(ACTION)
        assert doc["runs"]["using"] == "composite"
        assert set(doc["inputs"]) == {
            "path",
            "fail-on",
            "baseline",
            "extra-args",
            "version",
            "install-from",
            "python-version",
            "upload-sarif",
            "sarif-category",
            "step-summary",
            "pr-comment",
            "output-dir",
        }
        assert set(doc["outputs"]) == {"exit-code", "findings", "new-findings", "report"}
        assert doc["inputs"]["fail-on"]["default"] == "high"
        assert doc["inputs"]["install-from"]["default"] == "pypi"

    def test_version_default_is_pinned_to_pyproject(self) -> None:
        assert _load(ACTION)["inputs"]["version"]["default"] == _project_version()

    def test_install_pins_the_distribution_to_the_version(self) -> None:
        text = _steps_text(_load(ACTION)["runs"])
        assert 'pip install --quiet "aisafe[devtools]==${AISAFE_VERSION}"' in text
        for line in re.findall(r"pip install[^\n]*", text):
            if re.search(r"\baisafe(?:\[|==|\s|\"|$)", line):
                assert "==${AISAFE_VERSION}" in line, line
        assert '"${ACTION_PATH}[devtools]"' in text

    def test_every_audit_call_tolerates_only_exit_1_and_the_verdict_is_the_json(self) -> None:
        text = _steps_text(_load(ACTION)["runs"])
        calls = re.findall(r'^\s*(aisafe audit "[^\n]*)', text, re.M)
        assert len(calls) == 3
        for call in calls:
            assert call.rstrip().endswith("|| [ $? -eq 1 ]"), call
        assert "|| true" not in text
        assert 'report.get("kind") != "audit"' in text
        assert 'code = int(summary["exit_code"])' in text and "sys.exit(code)" in text

    def test_no_compliance_verdict_in_the_action_text(self) -> None:
        text = ACTION.read_text(encoding="utf-8").lower()
        for phrase in (
            " ".join(("is", "compliant")),
            "certi" + "fied",
            " ".join(("fully", "compliant")),
        ):
            assert phrase not in text, phrase
        assert "no compliance verdict" in text

    def test_third_party_actions_are_pinned_and_sarif_is_conditional(self) -> None:
        steps = _load(ACTION)["runs"]["steps"]
        for step in steps:
            if step.get("uses"):
                assert "@" in step["uses"], step["uses"]
        sarif = next(s for s in steps if "upload-sarif" in str(s.get("uses", "")))
        assert sarif["if"] == "inputs.upload-sarif == 'true'"
        comment = next(s for s in steps if "sticky-pull-request-comment" in str(s.get("uses", "")))
        assert "inputs.pr-comment == 'true'" in comment["if"]


class TestPreCommitHooks:
    def test_hook_ids_and_shapes(self) -> None:
        hooks = {h["id"]: h for h in _load(PRE_COMMIT_HOOKS)}
        assert set(hooks) == {"aisafe-audit", "aisafe-lint", "aisafe-misalign"}
        audit = hooks["aisafe-audit"]
        assert audit["entry"] == "aisafe audit" and audit["language"] == "python"
        assert audit["pass_filenames"] is False and audit["always_run"] is True
        assert audit["stages"] == ["pre-push"]
        assert audit["args"] == ["--no-external", "--fail-on", "high"]
        for name in ("aisafe-lint", "aisafe-misalign"):
            assert hooks[name]["types"] == ["python"] and hooks[name]["pass_filenames"] is True
            assert hooks[name]["args"] == ["--errors-only"]

    def test_our_own_config_runs_the_audit_at_push_time_against_the_baseline(self) -> None:
        doc = _load(PRE_COMMIT_CONFIG)
        local = next(r for r in doc["repos"] if r["repo"] == "local")
        audit = next(h for h in local["hooks"] if h["id"] == "aisafe-audit")
        assert audit["stages"] == ["pre-push"]
        assert audit["args"][-2:] == ["--baseline", "audit-baseline.json"]
        assert "--no-external" in audit["args"]


class TestGitLabAuditJob:
    def test_job_present_with_variables_and_exit_1_tolerance(self) -> None:
        doc = _load(GITLAB)
        job = doc["aisafe-audit"]
        assert job["extends"] == ".eu-ai-act-base"
        for key in ("AUDIT_PATH", "AUDIT_FAIL_ON", "AUDIT_BASELINE"):
            assert key in doc["variables"], key
        scripts = job["script"]
        assert all(isinstance(entry, str) for entry in scripts)
        audit_calls = [s for s in scripts if s.startswith("aisafe audit")]
        assert len(audit_calls) == 2 and all(s.endswith("|| [ $? -eq 1 ]") for s in audit_calls)
        assert any("--format sarif" in s for s in audit_calls)
        assert job["artifacts"]["reports"]["sast"] == "aisafe-audit-results.sarif"
        assert job["allow_failure"] is False


class TestDogfoodJob:
    def test_tests_workflow_runs_the_action_from_the_action_path(self) -> None:
        jobs = _load(TESTS_WORKFLOW)["jobs"]
        job = jobs["action"]
        step = next(s for s in job["steps"] if s.get("uses") == "./")
        assert step["with"]["install-from"] == "action-path"
        assert step["with"]["baseline"] == "audit-baseline.json"
        assert step["with"]["upload-sarif"] == "false"
        text = _steps_text(job)
        assert 'test "$EXIT_CODE" -eq 0' in text
