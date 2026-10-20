"""tests/unit/test_attest.py
--------------------------
`aisafe attest` evaluates the level criteria against the documents the other commands wrote
and lets a named owner sign the result. These tests pin the criteria file (shape, mirror,
every rule id and card path real), each criterion kind met and unmet against a fixed clock,
the cumulative level, the document (key order, ASCII, no banned phrase, badge colours),
the honesty rules (a bare fingerprint is not an acceptance, an absent input is recorded as
absent, a dirty tree fails only the tree criterion) and the exit codes. Nothing here opens
a socket, and git is faked: `walk.git_meta` is the only subprocess the command runs.
"""

from __future__ import annotations

import datetime as dt
import json
import socket
from pathlib import Path

import pytest
import yaml

from aisafe.config import ATTEST_LEVELS_FILE, preset_path
from aisafe.devtools import attest
from aisafe.devtools._config import find_pyproject
from aisafe.devtools.attest import (
    CRITERION_KINDS,
    DISCLAIMER,
    EXIT_FATAL,
    EXIT_NOT_MET,
    EXIT_OK,
    NOT_CONFIGURABLE,
    AttestError,
    Criterion,
    CriterionResult,
    badge,
    build_document,
    build_parser,
    check_templates,
    evaluate,
    evaluate_all,
    level_reached,
    load_inputs,
    load_levels,
    main,
    render_html,
    render_markdown,
    validate_levels,
    validate_owner,
)
from aisafe.devtools.audit import discover, walk
from aisafe.devtools.audit.patterns import OWN_HTML_MARKER_LINE
from aisafe.devtools.audit.report import BANNED_PHRASES
from aisafe.devtools.audit.rules import ALL_RULES
from aisafe.devtools.system_card import DEFAULT_CARD

REPO = Path(__file__).resolve().parents[2]
NOW = dt.datetime(2026, 10, 19, 12, 0, 0, tzinfo=dt.timezone.utc)
SHA = "a1b2c3d4" * 5
OTHER_SHA = "f" * 40
OWNER = "J. Doe <risk owner>"
FP_HIGH = "1111111111111111"
FP_LOW = "2222222222222222"
REASON = "the token is rotated by the deploy job and the file is not shipped"


def _stamp(when: dt.datetime = NOW) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def _finding(rule: str, severity: str, fingerprint: str, sub: str | None = None) -> dict:
    return {
        "id": rule if sub is None else f"{rule}/{sub}",
        "rule_id": rule,
        "sub": sub,
        "fingerprint": fingerprint,
        "title": f"{rule} title",
        "severity": severity,
        "priority": int(rule.split("-")[1][0]),
        "bucket": "asserted",
        "evidence": [{"role": "site", "file": "app.py", "line": 3, "snippet": "x = 1"}],
    }


def _report(
    *,
    findings: list[dict] | None = None,
    unknown: list[dict] | None = None,
    external: list[dict] | None = None,
    git_sha: str | None = SHA,
    generated_at: str | None = None,
    no_unknown_key: bool = False,
) -> dict:
    findings = findings if findings is not None else []
    unknown = (
        unknown
        if unknown is not None
        else [{"category": "tools", "what": "gitleaks", "why": "not on PATH"}]
    )
    by_severity: dict[str, int] = {}
    for f in findings:
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
    doc = {
        "schema": "aisg/1",
        "kind": "audit",
        "tool": {"name": "aisafe-audit", "version": "0.1.0"},
        "target": {"path": "repo", "git_sha": git_sha, "dirty": False, "exclude": []},
        "generated_at": generated_at if generated_at is not None else _stamp(),
        "disclaimer": "d",
        "summary": {
            "findings": len(findings),
            "by_severity": by_severity,
            "unknown_items": len(unknown),
        },
        "findings": findings,
        "measured": [],
        "reports": [],
        "unknown": unknown,
        "external_tools": external
        if external is not None
        else [{"name": "gitleaks", "status": "not_installed", "network": False}],
        "baseline": None,
        "inventory": {},
        "rules": [],
    }
    if no_unknown_key:
        del doc["unknown"]
    return doc


def _baseline(fingerprints: list[str], reasons: dict[str, str] | None = None) -> dict:
    reasons = reasons or {}
    return {
        "schema": "aisg/1",
        "kind": "audit-baseline",
        "generated_at": _stamp(NOW - dt.timedelta(days=2)),
        "tool": {"name": "aisafe-audit", "version": "0.1.0"},
        "fingerprints": sorted(fingerprints),
        "accepted": [
            {"fingerprint": fp, "rule": "AUD-501", "file": "app.py:3", "reason": reason}
            for fp, reason in sorted(reasons.items())
        ],
        "index": {
            fp: {"rule": "AUD-501", "file": "app.py:3", "title": "a title"} for fp in fingerprints
        },
    }


def _measure(*guards: dict, generated_at: str | None = None) -> dict:
    return {
        "schema": "aisg/1",
        "generated_at": generated_at if generated_at is not None else _stamp(),
        "measured_on": "offline",
        "guards": list(guards)
        or [{"name": "pii_detector", "unavailable": False, "threshold_failures": []}],
    }


def _probe(failed: int = 0, errors: int = 0) -> dict:
    return {
        "schema": "aisg/1",
        "kind": "probe",
        "generated_at": _stamp(),
        "summary": {
            "sent": 48,
            "passed": 48 - failed,
            "failed": failed,
            "errors": errors,
            "skipped": 0,
            "inconclusive": 0,
        },
    }


def _decision(generated_at: str | None = None) -> dict:
    return {
        "schema": "aisg/1",
        "kind": "decision",
        "generated_at": generated_at if generated_at is not None else _stamp(),
    }


def _card(**over: object) -> dict:
    card = {
        "system": {"id": "sys", "name": "Sys", "purpose": "answers support tickets"},
        "role": "deployer",
        "risk_tier": "limited",
        "affected_persons": ["customers"],
        "deployment": "production",
        "incident_contact": "security@example.test",
        "prompt_audit": {
            "reviewed_at": (NOW - dt.timedelta(days=10)).strftime("%Y-%m-%d"),
            "reviewer": "R. Roe",
            "scope": ["prompts/"],
            "notes": "",
        },
    }
    card.update(over)
    return card


def _tree(
    tmp_path: Path,
    *,
    report: dict | None = None,
    report_name: str = "audit-report-after.json",
    baseline: dict | None = None,
    measure: dict | None = None,
    probe: dict | None = None,
    decision: dict | None = None,
    card: dict | None = None,
) -> Path:
    root = tmp_path / "repo"
    out = root / ".aisafe-audit"
    out.mkdir(parents=True)
    if report is not None:
        (out / report_name).write_text(json.dumps(report), encoding="utf-8")
    if baseline is not None:
        (out / "audit-baseline.json").write_text(json.dumps(baseline), encoding="utf-8")
    if measure is not None:
        (out / "measure-report.json").write_text(json.dumps(measure), encoding="utf-8")
    if probe is not None:
        (out / "probe-report.json").write_text(json.dumps(probe), encoding="utf-8")
    if decision is not None:
        (out / "decision-report.json").write_text(json.dumps(decision), encoding="utf-8")
    if card is not None:
        (root / "ai-system-card.yaml").write_text(
            yaml.safe_dump(card, sort_keys=False), encoding="utf-8"
        )
    return root


def _full_tree(tmp_path: Path, **over: object) -> Path:
    """Everything a level-3 attestation needs."""
    args: dict[str, object] = {
        "report": _report(
            findings=[_finding("AUD-501", "high", FP_HIGH), _finding("AUD-602", "low", FP_LOW)],
            external=[{"name": "gitleaks", "status": "not_installed", "network": False}],
        ),
        "baseline": _baseline([FP_HIGH], {FP_HIGH: REASON}),
        "measure": _measure(),
        "probe": _probe(),
        "decision": _decision(),
        "card": _card(),
    }
    args.update(over)
    return _tree(tmp_path, **args)  # type: ignore[arg-type]


def _by_id(results: list[CriterionResult]) -> dict[str, CriterionResult]:
    return {r.id: r for r in results}


def _criterion(kind: str, **params: object) -> Criterion:
    return Criterion(id=f"T.{kind}", level=0, kind=kind, params=params)


@pytest.fixture(autouse=True)
def no_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args, **kwargs):
        raise AssertionError("aisafe attest opened a socket")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture(autouse=True)
def fake_git(monkeypatch: pytest.MonkeyPatch) -> dict:
    """`walk.git_meta` is the command's only subprocess; the tests set HEAD and dirtiness."""
    state = {"head": SHA, "dirty": False}
    monkeypatch.setattr(walk, "git_meta", lambda root: (state["head"], state["dirty"]))
    return state


@pytest.fixture
def neutral_cwd(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    cwd = tmp_path / "cwd"
    cwd.mkdir()
    monkeypatch.chdir(cwd)
    assert find_pyproject() is None
    return cwd


@pytest.fixture
def levels():
    return load_levels()


# ---------------------------------------------------------------------------
# The criteria file
# ---------------------------------------------------------------------------


class TestCriteriaFile:
    def test_schema_and_kind_are_the_first_body_lines(self):
        text = preset_path(ATTEST_LEVELS_FILE).read_text(encoding="utf-8")
        body = [line for line in text.splitlines() if line and not line.startswith("#")]
        assert body[0] == "schema: aisg/1" and body[1] == "kind: attest-levels"

    def test_repo_mirror_is_identical(self):
        packaged = preset_path(ATTEST_LEVELS_FILE).read_bytes()
        assert (REPO / "config" / ATTEST_LEVELS_FILE).read_bytes() == packaged

    def test_four_levels_named_and_contiguous(self, levels):
        assert [(lv.level, lv.name) for lv in levels.levels] == [
            (0, "audited"),
            (1, "triaged"),
            (2, "measured"),
            (3, "governed"),
        ]
        assert levels.review_interval_days == 90

    def test_every_kind_has_an_evaluator_and_is_used_once_at_least(self, levels):
        used = {c.kind for c in levels.criteria()}
        assert used == set(CRITERION_KINDS)
        assert set(attest._EVALUATORS) == set(CRITERION_KINDS)

    def test_rule_ids_and_card_paths_are_real(self, levels):
        rule_ids = {rule.id for rule in ALL_RULES}
        assert validate_levels(levels, rule_ids, DEFAULT_CARD) == []
        named = {str(r) for c in levels.criteria() for r in c.params.get("rules") or []}
        assert named and named <= rule_ids

    def test_criterion_ids_are_unique_and_prefixed_by_level(self, levels):
        ids = [c.id for c in levels.criteria()]
        assert len(ids) == len(set(ids))
        for c in levels.criteria():
            assert c.id.startswith(f"L{c.level}.")

    def test_validate_levels_names_an_unknown_rule_and_a_missing_card_path(self, levels):
        bad = attest.Levels(
            90,
            (
                attest.Level(
                    0,
                    "x",
                    (
                        Criterion("L0.a", 0, "rules_closed", {"rules": ["AUD-999"]}),
                        Criterion("L0.b", 0, "card_fields_set", {"fields": ["system.model"]}),
                        Criterion(
                            "L0.c",
                            0,
                            "card_section_fresh",
                            {"section": "prompt_audit", "fields": ["nope"], "date_field": "when"},
                        ),
                    ),
                ),
            ),
            "x.yaml",
        )
        problems = validate_levels(bad, {r.id for r in ALL_RULES}, DEFAULT_CARD)
        assert any("AUD-999" in p for p in problems)
        assert any("system.model" in p for p in problems)
        assert any("prompt_audit.nope" in p for p in problems)
        assert any("prompt_audit.when" in p for p in problems)

    @pytest.mark.parametrize(
        "text, fragment",
        [
            ("schema: aisg/1\nkind: other\nlevels: []\n", "kind is not attest-levels"),
            ("schema: aisg/1\nkind: attest-levels\nlevels: []\n", "non-empty list"),
            (
                "schema: aisg/1\nkind: attest-levels\nlevels:\n  - {level: 1, name: a, criteria: [{id: x, kind: tree_clean}]}\n",
                "contiguous from 0",
            ),
            (
                "schema: aisg/1\nkind: attest-levels\nlevels:\n  - {level: 0, name: a, criteria: [{id: x, kind: nope}]}\n",
                "unknown kind",
            ),
            (
                "schema: aisg/1\nkind: attest-levels\nlevels:\n  - {level: 0, name: a, criteria: [{id: x, kind: tree_clean}, {id: x, kind: tree_clean}]}\n",
                "duplicate criterion id",
            ),
            (
                "schema: aisg/1\nkind: attest-levels\nreview_interval_days: 0\nlevels: []\n",
                "positive integer",
            ),
        ],
    )
    def test_malformed_criteria_files_are_refused_with_a_reason(
        self, tmp_path: Path, text: str, fragment: str
    ):
        path = tmp_path / "levels.yaml"
        path.write_text(text, encoding="utf-8")
        with pytest.raises(AttestError, match=fragment):
            load_levels(path)


# ---------------------------------------------------------------------------
# Each criterion kind, met and unmet
# ---------------------------------------------------------------------------


class TestCriteria:
    def test_report_present_fails_when_stale_or_undated(self, tmp_path: Path):
        fresh = load_inputs(_tree(tmp_path, report=_report()))
        assert evaluate(_criterion("report_present", max_age_days=30), fresh, NOW).met
        old = load_inputs(
            _tree(tmp_path / "b", report=_report(generated_at=_stamp(NOW - dt.timedelta(days=31))))
        )
        result = evaluate(_criterion("report_present", max_age_days=30), old, NOW)
        assert not result.met and "31 day(s) old" in result.missing
        undated = load_inputs(_tree(tmp_path / "c", report=_report(generated_at="")))
        assert not evaluate(_criterion("report_present"), undated, NOW).met

    def test_report_names_head_compares_the_report_commit_with_head(
        self, tmp_path: Path, fake_git: dict
    ):
        inputs = load_inputs(_tree(tmp_path, report=_report()))
        assert evaluate(_criterion("report_names_head"), inputs, NOW).met
        fake_git["head"] = OTHER_SHA
        inputs = load_inputs(_tree(tmp_path / "b", report=_report()))
        result = evaluate(_criterion("report_names_head"), inputs, NOW)
        assert not result.met and "another commit" in result.missing
        fake_git["head"] = None
        inputs = load_inputs(_tree(tmp_path / "c", report=_report()))
        assert "HEAD is unknown" in evaluate(_criterion("report_names_head"), inputs, NOW).missing
        fake_git["head"] = SHA
        inputs = load_inputs(_tree(tmp_path / "d", report=_report(git_sha=None)))
        assert "names no commit" in evaluate(_criterion("report_names_head"), inputs, NOW).missing

    def test_unknown_listed_needs_the_list_not_its_emptiness(self, tmp_path: Path):
        empty = load_inputs(_tree(tmp_path, report=_report(unknown=[])))
        result = evaluate(_criterion("unknown_listed"), empty, NOW)
        assert result.met and "0 UNKNOWN item(s) listed" == result.evidence
        absent = load_inputs(_tree(tmp_path / "b", report=_report(no_unknown_key=True)))
        assert not evaluate(_criterion("unknown_listed"), absent, NOW).met

    def test_no_open_findings_counts_only_reasoned_acceptances(self, tmp_path: Path):
        findings = [_finding("AUD-501", "high", FP_HIGH), _finding("AUD-602", "low", FP_LOW)]
        bare = load_inputs(
            _tree(tmp_path, report=_report(findings=findings), baseline=_baseline([FP_HIGH]))
        )
        result = evaluate(_criterion("no_open_findings_at_or_above", severity="high"), bare, NOW)
        assert not result.met and "AUD-501" in result.missing
        reasoned = load_inputs(
            _tree(
                tmp_path / "b",
                report=_report(findings=findings),
                baseline=_baseline([FP_HIGH], {FP_HIGH: REASON}),
            )
        )
        result = evaluate(
            _criterion("no_open_findings_at_or_above", severity="high"), reasoned, NOW
        )
        assert result.met and "1 accepted with a reason" in result.evidence
        assert not evaluate(
            _criterion("no_open_findings_at_or_above", severity="low"), reasoned, NOW
        ).met

    def test_external_tools_attempted_fails_on_skipped_by_flag(self, tmp_path: Path):
        skipped = [
            {
                "name": "gitleaks",
                "status": "skipped_by_flag",
                "network": False,
                "flag": "--no-external",
            }
        ]
        inputs = load_inputs(_tree(tmp_path, report=_report(external=skipped)))
        result = evaluate(_criterion("external_tools_attempted"), inputs, NOW)
        assert not result.met and "gitleaks" in result.missing and "--no-external" in result.missing
        inputs = load_inputs(_tree(tmp_path / "b", report=_report()))
        assert evaluate(_criterion("external_tools_attempted"), inputs, NOW).met

    def test_accepted_reasons_present_counts_bare_fingerprints_as_suppressions(
        self, tmp_path: Path
    ):
        none = load_inputs(_tree(tmp_path, report=_report()))
        assert "no baseline" in evaluate(_criterion("accepted_reasons_present"), none, NOW).missing
        bare = load_inputs(
            _tree(
                tmp_path / "b",
                report=_report(),
                baseline=_baseline([FP_HIGH, FP_LOW], {FP_HIGH: REASON}),
            )
        )
        result = evaluate(_criterion("accepted_reasons_present"), bare, NOW)
        assert not result.met and "1 fingerprint(s) without a reason" in result.missing
        full = load_inputs(
            _tree(
                tmp_path / "c", report=_report(), baseline=_baseline([FP_HIGH], {FP_HIGH: REASON})
            )
        )
        assert evaluate(_criterion("accepted_reasons_present"), full, NOW).met

    @pytest.mark.parametrize("name", ["measure", "probe", "decision"])
    def test_document_present_is_unmet_not_fatal_when_absent(self, tmp_path: Path, name: str):
        inputs = load_inputs(_tree(tmp_path, report=_report()))
        result = evaluate(
            _criterion("document_present", document=name, max_age_days=30), inputs, NOW
        )
        assert not result.met and f"no {name} document" in result.missing

    def test_document_present_checks_freshness(self, tmp_path: Path):
        old = _measure(generated_at=_stamp(NOW - dt.timedelta(days=40)))
        inputs = load_inputs(_tree(tmp_path, report=_report(), measure=old))
        result = evaluate(
            _criterion("document_present", document="measure", max_age_days=30), inputs, NOW
        )
        assert not result.met and "40 day(s) old" in result.missing
        inputs = load_inputs(_tree(tmp_path / "b", report=_report(), measure=_measure()))
        assert evaluate(
            _criterion("document_present", document="measure", max_age_days=30), inputs, NOW
        ).met

    def test_document_present_rejects_an_unknown_document_name(self, tmp_path: Path):
        inputs = load_inputs(_tree(tmp_path, report=_report()))
        assert not evaluate(_criterion("document_present", document="badge"), inputs, NOW).met

    def test_measure_thresholds_reads_failures_and_unavailable(self, tmp_path: Path):
        over = {
            "name": "pii_detector",
            "unavailable": False,
            "threshold_failures": ["false-positive rate 0.19 > 0.05"],
        }
        off = {"name": "llm_input_filter", "unavailable": True, "threshold_failures": []}
        inputs = load_inputs(_tree(tmp_path, report=_report(), measure=_measure(over, off)))
        result = evaluate(_criterion("measure_thresholds"), inputs, NOW)
        assert not result.met
        assert "over a declared threshold: pii_detector" in result.missing
        assert "unavailable (not exercised): llm_input_filter" in result.missing
        inputs = load_inputs(_tree(tmp_path / "b", report=_report(), measure=_measure()))
        assert evaluate(_criterion("measure_thresholds"), inputs, NOW).met
        inputs = load_inputs(_tree(tmp_path / "c", report=_report()))
        assert (
            "no measure report" in evaluate(_criterion("measure_thresholds"), inputs, NOW).missing
        )

    def test_probe_passing_if_present(self, tmp_path: Path):
        absent = load_inputs(_tree(tmp_path, report=_report()))
        result = evaluate(_criterion("probe_passing_if_present"), absent, NOW)
        assert result.met and "no probe report" in result.evidence
        failed = load_inputs(_tree(tmp_path / "b", report=_report(), probe=_probe(failed=2)))
        assert not evaluate(_criterion("probe_passing_if_present"), failed, NOW).met
        errored = load_inputs(_tree(tmp_path / "c", report=_report(), probe=_probe(errors=1)))
        assert not evaluate(_criterion("probe_passing_if_present"), errored, NOW).met
        passing = load_inputs(_tree(tmp_path / "d", report=_report(), probe=_probe()))
        assert evaluate(_criterion("probe_passing_if_present"), passing, NOW).met

    def test_rules_closed_ignores_accepted_findings(self, tmp_path: Path):
        findings = [_finding("AUD-901", "medium", FP_HIGH), _finding("AUD-903", "medium", FP_LOW)]
        open_ = load_inputs(_tree(tmp_path, report=_report(findings=findings)))
        result = evaluate(_criterion("rules_closed", rules=["AUD-901", "AUD-903"]), open_, NOW)
        assert not result.met and result.missing == "open: AUD-901, AUD-903"
        accepted = load_inputs(
            _tree(
                tmp_path / "b",
                report=_report(findings=findings),
                baseline=_baseline([FP_HIGH, FP_LOW], {FP_HIGH: REASON, FP_LOW: REASON}),
            )
        )
        assert evaluate(_criterion("rules_closed", rules=["AUD-901", "AUD-903"]), accepted, NOW).met

    def test_sub_findings_match_their_rule_and_print_their_display_id_once(self, tmp_path: Path):
        # `id` is already `rule/sub`; the criteria name rules, so AUD-107/inert counts for
        # AUD-107 and is printed as `AUD-107/inert`, never `AUD-107/inert/inert`.
        findings = [_finding("AUD-107", "high", FP_HIGH, sub="inert")]
        inputs = load_inputs(_tree(tmp_path, report=_report(findings=findings)))
        closed = evaluate(_criterion("rules_closed", rules=["AUD-107"]), inputs, NOW)
        assert not closed.met and closed.missing == "open: AUD-107/inert"
        high = evaluate(_criterion("no_open_findings_at_or_above", severity="high"), inputs, NOW)
        assert not high.met and high.missing == "1 open: AUD-107/inert"
        other = evaluate(_criterion("rules_closed", rules=["AUD-108"]), inputs, NOW)
        assert other.met

    def test_card_fields_set_treats_placeholders_as_unset(self, tmp_path: Path):
        fields = [
            "system.purpose",
            "affected_persons",
            "incident_contact",
            "risk_tier",
            "deployment",
        ]
        none = load_inputs(_tree(tmp_path, report=_report()))
        assert (
            "no ai-system-card.yaml"
            in evaluate(_criterion("card_fields_set", fields=fields), none, NOW).missing
        )
        todo = load_inputs(
            _tree(
                tmp_path / "b",
                report=_report(),
                card=_card(incident_contact="TODO: name", affected_persons=[]),
            )
        )
        result = evaluate(_criterion("card_fields_set", fields=fields), todo, NOW)
        assert (
            not result.met
            and result.missing == "unset or placeholder: affected_persons, incident_contact"
        )
        full = load_inputs(_tree(tmp_path / "c", report=_report(), card=_card()))
        assert evaluate(_criterion("card_fields_set", fields=fields), full, NOW).met

    def test_card_section_fresh(self, tmp_path: Path):
        params = {
            "section": "prompt_audit",
            "fields": ["reviewed_at", "reviewer"],
            "date_field": "reviewed_at",
            "max_age_days": 180,
        }
        fresh = load_inputs(_tree(tmp_path, report=_report(), card=_card()))
        result = evaluate(_criterion("card_section_fresh", **params), fresh, NOW)
        assert result.met and "10 day(s) ago by R. Roe" in result.evidence
        stale_card = _card()
        stale_card["prompt_audit"]["reviewed_at"] = (NOW - dt.timedelta(days=200)).strftime(
            "%Y-%m-%d"
        )
        stale = load_inputs(_tree(tmp_path / "b", report=_report(), card=stale_card))
        result = evaluate(_criterion("card_section_fresh", **params), stale, NOW)
        assert not result.met and "older than 180 days" in result.missing
        unset_card = _card()
        unset_card["prompt_audit"]["reviewer"] = "TODO: who reviewed"
        unset = load_inputs(_tree(tmp_path / "c", report=_report(), card=unset_card))
        assert (
            "unset or placeholder: reviewer"
            in evaluate(_criterion("card_section_fresh", **params), unset, NOW).missing
        )
        no_block = load_inputs(
            _tree(
                tmp_path / "d",
                report=_report(),
                card={k: v for k, v in _card().items() if k != "prompt_audit"},
            )
        )
        assert (
            "no prompt_audit block"
            in evaluate(_criterion("card_section_fresh", **params), no_block, NOW).missing
        )

    def test_accepted_risks_owned_needs_an_owner_only_when_there_are_risks(self, tmp_path: Path):
        none = load_inputs(_tree(tmp_path, report=_report()))
        assert evaluate(_criterion("accepted_risks_owned"), none, NOW, owner=None).met
        some = load_inputs(
            _tree(
                tmp_path / "b", report=_report(), baseline=_baseline([FP_HIGH], {FP_HIGH: REASON})
            )
        )
        assert not evaluate(_criterion("accepted_risks_owned"), some, NOW, owner=None).met
        result = evaluate(_criterion("accepted_risks_owned"), some, NOW, owner=OWNER)
        assert result.met and OWNER in result.evidence

    def test_tree_clean(self, tmp_path: Path, fake_git: dict):
        inputs = load_inputs(_tree(tmp_path, report=_report()))
        assert evaluate(_criterion("tree_clean"), inputs, NOW).met
        fake_git["dirty"] = True
        inputs = load_inputs(_tree(tmp_path / "b", report=_report()))
        assert "uncommitted changes" in evaluate(_criterion("tree_clean"), inputs, NOW).missing
        fake_git["head"] = None
        inputs = load_inputs(_tree(tmp_path / "c", report=_report()))
        assert "not a git checkout" in evaluate(_criterion("tree_clean"), inputs, NOW).missing

    def test_evidence_and_missing_are_ascii_and_redacted(self, tmp_path: Path):
        secret = "sk-ant-api03-" + "A" * 40
        inputs = load_inputs(
            _tree(tmp_path, report=_report(), baseline=_baseline([FP_HIGH], {FP_HIGH: REASON}))
        )
        result = evaluate(_criterion("accepted_risks_owned"), inputs, NOW, owner=f"Zoë {secret}")
        assert result.evidence.isascii()
        assert secret not in result.evidence


# ---------------------------------------------------------------------------
# The level and the document
# ---------------------------------------------------------------------------


class TestLevel:
    def test_level_is_cumulative(self, levels):
        def results(**met_by_level: bool) -> list[CriterionResult]:
            return [
                CriterionResult(c.id, c.level, met_by_level.get(f"l{c.level}", True), "e", "")
                for c in levels.criteria()
            ]

        assert level_reached(levels, results()) == 3
        assert level_reached(levels, results(l3=False)) == 2
        assert level_reached(levels, results(l1=False)) == 0
        assert level_reached(levels, results(l1=False, l3=True)) == 0
        assert level_reached(levels, results(l0=False)) is None

    def test_one_unmet_criterion_in_a_level_blocks_it(self, levels):
        rows = [CriterionResult(c.id, c.level, True, "e", "") for c in levels.criteria()]
        rows[0] = CriterionResult(rows[0].id, 0, False, "e", "m")
        assert level_reached(levels, rows) is None

    def test_full_tree_reaches_level_three(self, tmp_path: Path, levels):
        inputs = load_inputs(_full_tree(tmp_path))
        results = evaluate_all(levels, inputs, NOW, OWNER)
        unmet = [r for r in results if not r.met]
        assert unmet == []
        assert level_reached(levels, results) == 3

    def test_dirty_tree_fails_only_the_tree_criterion(self, tmp_path: Path, levels, fake_git: dict):
        fake_git["dirty"] = True
        inputs = load_inputs(_full_tree(tmp_path))
        results = evaluate_all(levels, inputs, NOW, OWNER)
        assert [r.id for r in results if not r.met] == ["L3.tree"]
        assert level_reached(levels, results) == 2

    def test_bare_fingerprint_keeps_the_finding_open(self, tmp_path: Path, levels):
        inputs = load_inputs(_full_tree(tmp_path, baseline=_baseline([FP_HIGH])))
        results = _by_id(evaluate_all(levels, inputs, NOW, OWNER))
        assert not results["L1.no_open_high"].met
        assert not results["L1.reasons"].met
        assert level_reached(levels, list(results.values())) == 0

    def test_absent_inputs_are_recorded_with_nulls(self, tmp_path: Path, levels):
        inputs = load_inputs(_tree(tmp_path, report=_report()))
        doc = build_document(inputs, levels, evaluate_all(levels, inputs, NOW, OWNER), OWNER, NOW)
        rows = {row["kind"]: row for row in doc["inputs"]}
        assert set(rows) == {"audit", "baseline", "measure", "probe", "decision", "card"}
        for kind in ("baseline", "measure", "probe", "decision", "card"):
            assert rows[kind] == {
                "kind": kind,
                "file": None,
                "generated_at": None,
                "age_days": None,
            }
        assert rows["audit"]["file"] == ".aisafe-audit/audit-report-after.json"
        assert rows["audit"]["age_days"] == 0
        assert doc["level"]["reached"] == 0


class TestDocument:
    def _doc(self, tmp_path: Path, levels, **over):
        inputs = load_inputs(_full_tree(tmp_path, **over))
        return build_document(inputs, levels, evaluate_all(levels, inputs, NOW, OWNER), OWNER, NOW)

    def test_key_order_is_pinned(self, tmp_path: Path, levels):
        doc = self._doc(tmp_path, levels)
        assert list(doc) == [
            "schema",
            "kind",
            "tool",
            "target",
            "generated_at",
            "owner",
            "level",
            "inputs",
            "accepted_risks",
            "unknown",
            "residual",
            "next_review_by",
            "notes",
            "disclaimer",
        ]
        assert doc["schema"] == "aisg/1" and doc["kind"] == "attestation"
        assert doc["tool"]["name"] == "aisafe-attest"
        assert list(doc["level"]) == ["reached", "name", "statement", "criteria"]
        assert list(doc["level"]["criteria"][0]) == ["id", "level", "met", "evidence", "missing"]
        assert list(doc["inputs"][0]) == ["kind", "file", "generated_at", "age_days"]
        assert list(doc["residual"]) == ["findings_by_severity", "open", "accepted"]

    def test_statement_names_owner_path_commit_level_and_date(self, tmp_path: Path, levels):
        doc = self._doc(tmp_path, levels)
        assert doc["level"]["statement"] == (
            f"{OWNER} states that repo at commit {SHA[:7]} meets the AnyAISafe level 3 (governed) "
            "criteria on 2026-10-19."
        )
        assert doc["target"] == {
            "path": (tmp_path / "repo").resolve().as_posix(),
            "git_sha": SHA,
            "dirty": False,
        }
        assert doc["generated_at"] == "2026-10-19T12:00:00Z"
        assert doc["next_review_by"] == "2027-01-17"

    def test_statement_when_no_level_is_reached(self, tmp_path: Path, levels):
        inputs = load_inputs(_tree(tmp_path, report=_report(no_unknown_key=True)))
        doc = build_document(inputs, levels, evaluate_all(levels, inputs, NOW, OWNER), OWNER, NOW)
        assert doc["level"]["reached"] is None and doc["level"]["name"] is None
        assert "reaches no level" in doc["level"]["statement"]
        assert badge(doc) == {
            "schemaVersion": 1,
            "label": "aisafe",
            "message": "no level (2026-10-19)",
            "color": "lightgrey",
        }

    def test_accepted_risks_are_copied_from_the_baseline_and_owned(self, tmp_path: Path, levels):
        doc = self._doc(tmp_path, levels)
        assert doc["accepted_risks"] == [
            {
                "fingerprint": FP_HIGH,
                "rule": "AUD-501",
                "file": "app.py:3",
                "reason": REASON,
                "owner": OWNER,
            }
        ]
        assert doc["residual"] == {
            "findings_by_severity": {"high": 1, "low": 1},
            "open": 1,
            "accepted": 1,
        }
        assert doc["unknown"] == [{"category": "tools", "what": "gitleaks", "why": "not on PATH"}]

    def test_disclaimer_extends_the_audit_disclaimer(self, tmp_path: Path, levels):
        from aisafe.devtools.audit.model import DISCLAIMER as AUDIT

        doc = self._doc(tmp_path, levels)
        assert doc["disclaimer"] == DISCLAIMER
        assert DISCLAIMER.startswith(AUDIT)
        assert "statement by the named owner" in DISCLAIMER

    def test_badge_is_informational_above_zero_and_grey_at_zero(self, tmp_path: Path, levels):
        doc = self._doc(tmp_path, levels)
        assert badge(doc) == {
            "schemaVersion": 1,
            "label": "aisafe",
            "message": "level 3 (2026-10-19)",
            "color": "informational",
        }
        doc["level"]["reached"] = 0
        assert (
            badge(doc)["color"] == "lightgrey" and badge(doc)["message"] == "level 0 (2026-10-19)"
        )
        for level in (None, 0, 1, 2, 3):
            doc["level"]["reached"] = level
            assert badge(doc)["color"] not in {"green", "brightgreen", "red", "success", "critical"}

    def test_renderers_are_ascii_and_carry_no_banned_phrase(self, tmp_path: Path, levels):
        doc = self._doc(tmp_path, levels)
        rendered = [json.dumps(doc, ensure_ascii=True), render_markdown(doc), render_html(doc)]
        for text in rendered:
            assert text.isascii()
            lowered = text.lower()
            for phrase in BANNED_PHRASES:
                assert phrase not in lowered, phrase
            assert "cl" + "ean" not in lowered
        assert check_templates() == []

    def test_markdown_has_the_sections_and_the_disclaimer_first(self, tmp_path: Path, levels):
        md = render_markdown(self._doc(tmp_path, levels))
        lines = md.splitlines()
        assert lines[0] == "# aisafe attest"
        assert lines[2].startswith("> ") and "named owner" in lines[2]
        for heading in (
            "## Criteria",
            "## Inputs",
            "## Accepted risks",
            "## Residual",
            "## UNKNOWN",
        ):
            assert heading in lines
        assert "| L3.tree | 3 | yes |" in md
        assert "level reached: 3 (governed)" in lines
        assert "next review by: 2027-01-17" in lines

    def test_html_first_line_is_the_own_output_marker(self, tmp_path: Path, levels):
        html = render_html(self._doc(tmp_path, levels))
        assert html.splitlines()[0] == OWN_HTML_MARKER_LINE
        assert "<title>aisafe attest:" in html
        assert "<h1>Attestation</h1>" in html

    def test_attestation_is_the_toolchain_own_output(self, tmp_path: Path, levels):
        doc = self._doc(tmp_path, levels)
        root = tmp_path / "scan"
        root.mkdir()
        attest.write_outputs(doc, root / ".aisafe-audit", html=True)
        (root / "app.py").write_text("x = 1\n", encoding="utf-8")
        skipped: list[str] = []
        records, _, _ = walk.walk(root, own_output_skipped=skipped)
        rels = sorted(r.relpath for r in records)
        assert ".aisafe-audit/attestation.json" not in rels
        assert ".aisafe-audit/attestation.html" not in rels
        assert ".aisafe-audit/attestation.md" in rels and ".aisafe-audit/badge.json" in rels
        assert set(skipped) == {".aisafe-audit/attestation.json", ".aisafe-audit/attestation.html"}
        assert "attestation" in discover._OWN_OUTPUT_KINDS
        record, unknown = discover.read_report(root / ".aisafe-audit" / "attestation.json", root)
        assert record is None and unknown is None


# ---------------------------------------------------------------------------
# Owner and inputs
# ---------------------------------------------------------------------------


class TestOwnerAndInputs:
    @pytest.mark.parametrize("bad", ["", "   ", None, "Zoë Doe", "J. Doe\x07", "x" * 201])
    def test_owner_must_be_printable_ascii_and_non_empty(self, bad):
        with pytest.raises(AttestError):
            validate_owner(bad)

    def test_owner_is_stripped(self):
        assert validate_owner("  J. Doe <risk owner>  ") == OWNER

    def test_missing_report_is_fatal_with_the_command_to_run(self, tmp_path: Path):
        root = tmp_path / "repo"
        root.mkdir()
        with pytest.raises(AttestError, match="aisafe audit"):
            load_inputs(root)

    def test_default_report_falls_back_to_the_survey_report_with_a_note(self, tmp_path: Path):
        inputs = load_inputs(_tree(tmp_path, report=_report(), report_name="audit-report.json"))
        assert inputs.report.path == ".aisafe-audit/audit-report.json"
        assert inputs.notes == [
            "no .aisafe-audit/audit-report-after.json; using the survey report .aisafe-audit/audit-report.json"
        ]

    def test_wrong_kind_or_schema_is_fatal(self, tmp_path: Path):
        bad = _report()
        bad["kind"] = "inventory"
        with pytest.raises(AttestError, match="kind is not audit"):
            load_inputs(_tree(tmp_path, report=bad))
        bad = _decision()
        bad["schema"] = "other/9"
        with pytest.raises(AttestError, match="schema is not aisg/1"):
            load_inputs(_tree(tmp_path / "b", report=_report(), decision=bad))

    def test_invalid_baseline_is_fatal_not_ignored(self, tmp_path: Path):
        root = _tree(tmp_path, report=_report())
        (root / ".aisafe-audit" / "audit-baseline.json").write_text(
            '{"schema": "aisg/1", "kind": "nope"}', encoding="utf-8"
        )
        with pytest.raises(AttestError, match="baseline"):
            load_inputs(root)

    def test_unreadable_json_is_fatal(self, tmp_path: Path):
        root = _tree(tmp_path, report=_report())
        (root / ".aisafe-audit" / "measure-report.json").write_text("{not json", encoding="utf-8")
        with pytest.raises(AttestError, match="not valid JSON"):
            load_inputs(root)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCli:
    def test_help_starts_with_the_prog_name(self, capsys):
        with pytest.raises(SystemExit) as exc:
            build_parser().parse_args(["--help"])
        assert exc.value.code == 0
        assert capsys.readouterr().out.startswith("usage: aisafe attest")

    def test_not_configurable_is_owner_and_check(self):
        assert NOT_CONFIGURABLE == frozenset({"owner", "check"})

    def test_writes_four_documents_and_exits_zero(self, tmp_path: Path, neutral_cwd: Path, capsys):
        root = _full_tree(tmp_path)
        code = main([str(root), "--owner", OWNER, "--html"])
        out = capsys.readouterr().out
        assert code == EXIT_OK
        names = sorted(p.name for p in (root / ".aisafe-audit").iterdir())
        assert {"attestation.json", "attestation.md", "attestation.html", "badge.json"} <= set(
            names
        )
        doc = json.loads((root / ".aisafe-audit" / "attestation.json").read_text(encoding="utf-8"))
        assert doc["level"]["reached"] == 3 and doc["owner"] == OWNER
        assert out.splitlines()[0] == "level reached: 3 (governed)"
        assert "written: " in out
        badge_doc = json.loads((root / ".aisafe-audit" / "badge.json").read_text(encoding="utf-8"))
        assert badge_doc["color"] == "informational"

    def test_without_html_flag_no_html_is_written(self, tmp_path: Path, neutral_cwd: Path):
        root = _full_tree(tmp_path)
        assert main([str(root), "--owner", OWNER]) == EXIT_OK
        assert not (root / ".aisafe-audit" / "attestation.html").exists()

    def test_owner_is_required_to_write(self, tmp_path: Path, neutral_cwd: Path, capsys):
        root = _full_tree(tmp_path)
        assert main([str(root)]) == EXIT_FATAL
        assert "--owner is required" in capsys.readouterr().err
        assert not (root / ".aisafe-audit" / "attestation.json").exists()

    @pytest.mark.parametrize("owner", ["", "Zoë", "a\x01b"])
    def test_bad_owner_is_fatal(self, tmp_path: Path, neutral_cwd: Path, owner: str):
        root = _full_tree(tmp_path)
        assert main([str(root), "--owner", owner]) == EXIT_FATAL

    def test_check_writes_nothing_and_prints_every_criterion(
        self, tmp_path: Path, neutral_cwd: Path, capsys
    ):
        root = _full_tree(tmp_path)
        before = sorted(p.name for p in (root / ".aisafe-audit").iterdir())
        assert main([str(root), "--check"]) == EXIT_OK
        out = capsys.readouterr().out
        assert sorted(p.name for p in (root / ".aisafe-audit").iterdir()) == before
        assert (
            out.splitlines()[0] == "level reached: 2 (measured)"
        )  # unsigned: L3.owner needs an owner
        assert "L3.owner" in out and "missing:" in out

    def test_check_with_owner_reaches_level_three(self, tmp_path: Path, neutral_cwd: Path, capsys):
        root = _full_tree(tmp_path)
        assert main([str(root), "--check", "--owner", OWNER, "--require-level", "3"]) == EXIT_OK
        assert capsys.readouterr().out.splitlines()[0] == "level reached: 3 (governed)"

    def test_require_level_not_reached_exits_one(self, tmp_path: Path, neutral_cwd: Path, capsys):
        root = _full_tree(tmp_path, measure=None)
        assert main([str(root), "--check", "--require-level", "2"]) == EXIT_NOT_MET
        err = capsys.readouterr().err
        assert "level 2 not reached" in err

    def test_missing_report_exits_two(self, tmp_path: Path, neutral_cwd: Path, capsys):
        root = tmp_path / "repo"
        root.mkdir()
        assert main([str(root), "--owner", OWNER]) == EXIT_FATAL
        assert "no audit report" in capsys.readouterr().err

    def test_path_that_is_not_a_directory_exits_two(self, tmp_path: Path, neutral_cwd: Path):
        assert main([str(tmp_path / "nope"), "--owner", OWNER]) == EXIT_FATAL

    def test_invalid_criteria_file_exits_two(self, tmp_path: Path, neutral_cwd: Path, capsys):
        root = _full_tree(tmp_path)
        bad = tmp_path / "levels.yaml"
        bad.write_text(
            "schema: aisg/1\nkind: attest-levels\nlevels:\n"
            "  - {level: 0, name: a, criteria: [{id: x, kind: rules_closed, rules: [AUD-999]}]}\n",
            encoding="utf-8",
        )
        assert main([str(root), "--owner", OWNER, "--level-criteria", str(bad)]) == EXIT_FATAL
        assert "AUD-999" in capsys.readouterr().err

    def test_fallback_report_note_goes_to_stderr(self, tmp_path: Path, neutral_cwd: Path, capsys):
        root = _tree(tmp_path, report=_report(), report_name="audit-report.json")
        assert main([str(root), "--check"]) == EXIT_OK
        assert "using the survey report" in capsys.readouterr().err

    def test_pyproject_defaults_apply_except_owner_and_check(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        root = _full_tree(tmp_path)
        (root / "pyproject.toml").write_text(
            '[tool.aisafe-attest]\nowner = "Config Owner"\ncheck = true\nhtml = true\nout-dir = "signed"\n',
            encoding="utf-8",
        )
        monkeypatch.chdir(root)
        # owner from pyproject is ignored: without --owner the command refuses to write
        assert main(["."]) == EXIT_FATAL
        assert "--owner is required" in capsys.readouterr().err
        # check from pyproject is ignored: with --owner the command writes, into out-dir, with html
        assert main([".", "--owner", OWNER]) == EXIT_OK
        assert (root / "signed" / "attestation.html").exists()
        assert not (root / ".aisafe-audit" / "attestation.json").exists()

    def test_debug_self_checks_the_templates(
        self, tmp_path: Path, neutral_cwd: Path, monkeypatch: pytest.MonkeyPatch, capsys
    ):
        root = _full_tree(tmp_path)
        monkeypatch.setattr(attest, "check_templates", lambda: ["a banned phrase"])
        assert main([str(root), "--check", "--debug"]) == EXIT_FATAL
        assert "template self-check failed" in capsys.readouterr().err

    def test_console_script_routes_attest(self):
        from aisafe import cli

        assert "attest" in cli.COMMANDS
        assert "aisafe attest ." in cli._EPILOG
