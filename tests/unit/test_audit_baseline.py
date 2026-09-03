"""tests/unit/test_audit_baseline.py
---------------------------------
Pins for the fingerprint baseline: write/load round trip, a full audit report read as a
baseline yields the same set, anything else is a `BaselineError`, and `diff` marks
new/unchanged in place so the exit code counts only what is new.

The `accepted` list: `write_baseline(..., reasons=...)` fills it from the findings,
`load_baseline` validates it (a reason per entry, every entry also in `fingerprints`), and
the committed `audit-baseline.json` is held to that shape -- plus one more: scanning the
baseline file itself must not reproduce the findings it accepts.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from aisg.devtools.audit.baseline import (
    BaselineDiff,
    BaselineError,
    diff,
    load_accepted,
    load_baseline,
    write_baseline,
)
from aisg.devtools.audit.model import (
    AuditContext,
    Basis,
    Bucket,
    Confidence,
    Evidence,
    EvidenceKind,
    Finding,
    Inventory,
    MatchKind,
    Recommendation,
    Scope,
    Severity,
    Tier,
)
from aisg.devtools.audit.report import build_report, compute_exit_code, render, tool_version

REPO_ROOT = Path(__file__).resolve().parents[2]
COMMITTED_BASELINE = REPO_ROOT / "audit-baseline.json"


def make_finding(
    rule_id: str,
    file: str,
    snippet: str,
    severity: Severity = Severity.HIGH,
    sub: str | None = None,
) -> Finding:
    return Finding(
        id=rule_id,
        title=f"title for {rule_id}",
        severity=severity,
        priority=4,
        bucket=Bucket.ASSERTED,
        basis=Basis.PRESENCE,
        confidence=Confidence(EvidenceKind.CODE, MatchKind.GREP),
        scope=Scope(kind="file", name=file),
        evidence=[Evidence(role="match", file=file, line=3, snippet=snippet)],
        recommendation=Recommendation(tier=Tier.T1, summary="fix", alternatives=("a", "b", "c")),
        sub=sub,
    )


def make_absence_finding(rule_id: str, unit_root: str) -> Finding:
    """An absence finding carries no evidence; its location is the scope name."""
    return Finding(
        id=rule_id,
        title=f"title for {rule_id}",
        severity=Severity.MEDIUM,
        priority=1,
        bucket=Bucket.ASSERTED,
        basis=Basis.ABSENCE,
        confidence=Confidence(EvidenceKind.ABSENCE, MatchKind.STRUCTURED),
        scope=Scope(kind="unit", unit="u0", name=unit_root),
        evidence=[],
        recommendation=Recommendation(tier=Tier.T1, summary="add", alternatives=("a", "b", "c")),
    )


def three() -> list[Finding]:
    return [
        make_finding("AUD-401", "a.py", "subprocess.run(cmd, shell=True)"),
        make_finding("AUD-402", "b.py", "eval(reply)"),
        make_finding("AUD-501", "c.py", "token = <redacted:...abcd>", Severity.CRITICAL),
    ]


def make_report(findings: list[Finding]):
    ctx = AuditContext(root=Path("target"), inventory=Inventory(target={"path": "target"}))
    code = compute_exit_code(findings, [], fail_on="low")
    return build_report(ctx, findings, [], [], [], None, rules=[], fail_on="low", exit_code=code)


# ---------------------------------------------------------------------------
# write / load
# ---------------------------------------------------------------------------


def test_write_then_load_round_trip(tmp_path: Path):
    findings = three()
    path = tmp_path / "audit-baseline.json"
    write_baseline(findings, path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert list(doc) == ["schema", "kind", "generated_at", "tool", "fingerprints"]
    assert doc["schema"] == "aisg/1" and doc["kind"] == "audit-baseline"
    assert doc["tool"] == {"name": "aisg-audit", "version": tool_version()}
    assert doc["fingerprints"] == sorted(doc["fingerprints"])
    assert len(doc["fingerprints"]) == len(set(doc["fingerprints"])) == 3
    assert load_baseline(path) == {f.fingerprint for f in findings}


def test_write_baseline_dedups_and_accepts_a_report(tmp_path: Path):
    findings = three() + three()
    report = make_report(findings)
    path = tmp_path / "b.json"
    write_baseline(report, path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert len(doc["fingerprints"]) == 3
    assert doc["tool"] == report.tool


def test_load_baseline_reads_a_full_audit_report_identically(tmp_path: Path):
    findings = three()
    report_path = tmp_path / "audit-report.json"
    report_path.write_text(render(make_report(findings), "json"), encoding="utf-8")
    baseline_path = tmp_path / "audit-baseline.json"
    write_baseline(findings, baseline_path)
    assert load_baseline(report_path) == load_baseline(baseline_path)
    assert load_baseline(report_path) == {f.fingerprint for f in findings}


def test_load_baseline_empty_report_yields_empty_set(tmp_path: Path):
    report_path = tmp_path / "audit-report.json"
    report_path.write_text(render(make_report([]), "json"), encoding="utf-8")
    assert load_baseline(report_path) == set()


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ('{"schema": "aisg/1", "kind": "probe", "summary": {}}', "kind"),
        ('{"schema": "aisg/2", "kind": "audit-baseline", "fingerprints": []}', "schema"),
        ('{"kind": "audit-baseline", "fingerprints": []}', "schema"),
        ('{"schema": "aisg/1", "kind": "audit-baseline", "fingerprints": "abc"}', "fingerprints"),
        ('{"schema": "aisg/1", "kind": "audit-baseline", "fingerprints": [1, 2]}', "fingerprint"),
        ('{"schema": "aisg/1", "kind": "audit", "findings": {}}', "findings"),
        ("[]", "object"),
        ("{not json", "JSON"),
    ],
)
def test_load_baseline_rejects_anything_else(tmp_path: Path, text: str, reason: str):
    path = tmp_path / "x.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    message = str(info.value)
    assert "\n" not in message
    assert reason in message
    assert "x.json" in message


def test_load_baseline_missing_file(tmp_path: Path):
    with pytest.raises(BaselineError) as info:
        load_baseline(tmp_path / "absent.json")
    assert "absent.json" in str(info.value)


# ---------------------------------------------------------------------------
# accepted: reasons per fingerprint
# ---------------------------------------------------------------------------


def _baseline_doc(fingerprints: list[str], accepted: object) -> str:
    return json.dumps(
        {
            "schema": "aisg/1",
            "kind": "audit-baseline",
            "fingerprints": fingerprints,
            "accepted": accepted,
        }
    )


def test_write_baseline_with_reasons_fills_accepted_from_the_findings(tmp_path: Path):
    findings = three()
    findings[1] = make_finding("AUD-402", "b.py", "eval(reply)", sub="eval")
    reasons = {
        findings[2].fingerprint: "test fixture token, assembled at runtime",
        findings[1].fingerprint: "eval on a literal, not on model output",
    }
    path = tmp_path / "audit-baseline.json"
    write_baseline(findings, path, reasons=reasons)
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert list(doc) == ["schema", "kind", "generated_at", "tool", "fingerprints", "accepted"]
    assert len(doc["fingerprints"]) == 3
    # Entries follow the findings' order, not the reasons' order; `rule` is the display id
    # (id + sub) and `file` the first evidence location.
    assert doc["accepted"] == [
        {
            "fingerprint": findings[1].fingerprint,
            "rule": "AUD-402/eval",
            "file": "b.py:3",
            "reason": "eval on a literal, not on model output",
        },
        {
            "fingerprint": findings[2].fingerprint,
            "rule": "AUD-501",
            "file": "c.py:3",
            "reason": "test fixture token, assembled at runtime",
        },
    ]
    assert load_baseline(path) == {f.fingerprint for f in findings}
    assert load_accepted(path) == reasons


def test_write_baseline_accepted_uses_the_scope_name_for_an_absence_finding(tmp_path: Path):
    absent = make_absence_finding("AUD-1001", ".")
    path = tmp_path / "b.json"
    write_baseline([absent], path, reasons={absent.fingerprint: "a library, not a system"})
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["accepted"] == [
        {
            "fingerprint": absent.fingerprint,
            "rule": "AUD-1001",
            "file": ".",
            "reason": "a library, not a system",
        }
    ]


def test_write_baseline_without_reasons_has_no_accepted_key(tmp_path: Path):
    path = tmp_path / "b.json"
    write_baseline(three(), path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert "accepted" not in doc
    assert load_accepted(path) == {}


def test_write_baseline_accepts_a_report_with_reasons(tmp_path: Path):
    findings = three()
    report = make_report(findings)
    path = tmp_path / "b.json"
    write_baseline(report, path, reasons={findings[0].fingerprint: "shell=True on a constant"})
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert [e["rule"] for e in doc["accepted"]] == ["AUD-401"]
    assert doc["tool"] == report.tool


def test_write_baseline_rejects_a_reason_that_matches_no_finding(tmp_path: Path):
    findings = three()
    path = tmp_path / "b.json"
    with pytest.raises(BaselineError) as info:
        write_baseline(findings, path, reasons={"ffffffffffffffff": "stale"})
    assert "ffffffffffffffff" in str(info.value)
    assert not path.exists()


@pytest.mark.parametrize("reason", ["", "   ", None])
def test_write_baseline_rejects_an_empty_reason(tmp_path: Path, reason: object):
    findings = three()
    path = tmp_path / "b.json"
    with pytest.raises(BaselineError) as info:
        write_baseline(findings, path, reasons={findings[0].fingerprint: reason})  # type: ignore[dict-item]
    assert findings[0].fingerprint in str(info.value)
    assert "reason" in str(info.value)
    assert not path.exists()


def test_load_baseline_rejects_an_accepted_entry_without_a_reason(tmp_path: Path):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(_baseline_doc([fp], [{"fingerprint": fp, "rule": "AUD-401", "file": "a.py:3"}]))
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    message = str(info.value)
    assert fp in message and "reason" in message and "b.json" in message
    assert "\n" not in message


def test_load_baseline_rejects_an_accepted_entry_with_a_blank_reason(tmp_path: Path):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(_baseline_doc([fp], [{"fingerprint": fp, "reason": "  "}]))
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    assert fp in str(info.value)


def test_load_baseline_rejects_an_accepted_fingerprint_not_in_fingerprints(tmp_path: Path):
    listed, stray = three()[0].fingerprint, three()[1].fingerprint
    path = tmp_path / "b.json"
    path.write_text(_baseline_doc([listed], [{"fingerprint": stray, "reason": "looked at it"}]))
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    message = str(info.value)
    assert stray in message and "fingerprints" in message
    assert listed not in message


@pytest.mark.parametrize(
    ("accepted", "reason"),
    [
        ({"fingerprint": "x"}, "not a list"),
        (["abc"], "not an object"),
        ([{"reason": "no fingerprint here"}], "no fingerprint"),
        ([{"fingerprint": "", "reason": "empty fingerprint"}], "no fingerprint"),
    ],
)
def test_load_baseline_rejects_a_malformed_accepted_list(
    tmp_path: Path, accepted: object, reason: str
):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(_baseline_doc([fp], accepted))
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    assert reason in str(info.value)


def test_load_baseline_tolerates_an_absent_or_empty_accepted_list(tmp_path: Path):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(_baseline_doc([fp], []))
    assert load_baseline(path) == {fp}
    assert load_accepted(path) == {}
    path.write_text(
        json.dumps({"schema": "aisg/1", "kind": "audit-baseline", "fingerprints": [fp]})
    )
    assert load_baseline(path) == {fp}
    assert load_accepted(path) == {}


def test_load_accepted_on_a_full_report_is_empty(tmp_path: Path):
    report_path = tmp_path / "audit-report.json"
    report_path.write_text(render(make_report(three()), "json"), encoding="utf-8")
    assert load_accepted(report_path) == {}
    assert len(load_baseline(report_path)) == 3


def test_fingerprints_are_line_ending_independent(tmp_path: Path):
    """CI checks out with LF on Linux; a Windows checkout has CRLF. Same baseline either way."""
    crlf = make_finding("AUD-401", "a.py", "subprocess.run(\r\n    cmd, shell=True)\r\n")
    lf = make_finding("AUD-401", "a.py", "subprocess.run(\n    cmd, shell=True)\n")
    assert crlf.fingerprint == lf.fingerprint
    path = tmp_path / "b.json"
    write_baseline([crlf], path, reasons={crlf.fingerprint: "constant argv"})
    result = diff([lf], load_baseline(path), file=path.name)
    assert result.to_dict() == {"file": "b.json", "new": 0, "fixed": 0, "unchanged": 1}


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


def test_diff_marks_new_and_unchanged_in_place_and_counts_fixed():
    old = three()
    baseline = {old[0].fingerprint, old[1].fingerprint, "ffffffffffffffff"}
    current = three()
    result = diff(current, baseline, file="audit-baseline.json")
    assert isinstance(result, BaselineDiff)
    assert [f.id for f in result.unchanged] == ["AUD-401", "AUD-402"]
    assert [f.id for f in result.new] == ["AUD-501"]
    assert result.fixed == ["ffffffffffffffff"]
    assert result.file == "audit-baseline.json"
    assert [f.baseline_status for f in current] == ["unchanged", "unchanged", "new"]
    assert result.to_dict() == {
        "file": "audit-baseline.json",
        "new": 1,
        "fixed": 1,
        "unchanged": 2,
    }


def test_diff_normalises_windows_paths_in_file():
    assert diff([], set(), file="out\\audit-baseline.json").file == "out/audit-baseline.json"


def test_exit_code_counts_only_new_after_diff(tmp_path: Path):
    findings = three()
    path = tmp_path / "audit-baseline.json"
    write_baseline(findings, path)
    baseline = load_baseline(path)

    same = three()
    result = diff(same, baseline, file=path.name)
    assert result.to_dict()["new"] == 0
    assert compute_exit_code(same, [], fail_on="low") == 0

    same.append(make_finding("AUD-403", "d.py", "cursor.execute(f'select {q}')"))
    result = diff(same, baseline, file=path.name)
    assert [f.id for f in result.new] == ["AUD-403"]
    assert compute_exit_code(same, [], fail_on="low") == 1
    assert compute_exit_code(same, [], fail_on="critical") == 0


def test_report_carries_the_diff(tmp_path: Path):
    findings = three()
    baseline = {findings[0].fingerprint}
    result = diff(findings, baseline, file="audit-baseline.json")
    ctx = AuditContext(root=Path("target"), inventory=Inventory(target={"path": "target"}))
    code = compute_exit_code(findings, [], fail_on="low")
    report = build_report(
        ctx, findings, [], [], [], result, rules=[], fail_on="low", exit_code=code
    )
    doc = json.loads(render(report, "json"))
    assert doc["baseline"] == {"file": "audit-baseline.json", "new": 2, "fixed": 0, "unchanged": 1}
    assert doc["summary"]["baseline_new"] == 2
    assert doc["summary"]["exit_code"] == 1
    statuses = {f["id"]: f["baseline_status"] for f in doc["findings"]}
    assert statuses == {"AUD-401": "unchanged", "AUD-402": "new", "AUD-501": "new"}


# ---------------------------------------------------------------------------
# the committed audit-baseline.json
# ---------------------------------------------------------------------------


def test_committed_baseline_has_a_reason_for_every_fingerprint():
    """
    The repo's own baseline is the strict shape: an `accepted` entry, with a reason, for
    every fingerprint. A bare fingerprint would be a suppression nobody signed.
    """
    assert COMMITTED_BASELINE.is_file(), COMMITTED_BASELINE
    fingerprints = load_baseline(COMMITTED_BASELINE)
    reasons = load_accepted(COMMITTED_BASELINE)
    assert fingerprints, "the self-audit has findings; an empty baseline is a stale one"
    assert set(reasons) == fingerprints
    doc = json.loads(COMMITTED_BASELINE.read_text(encoding="utf-8"))
    assert list(doc) == ["schema", "kind", "generated_at", "tool", "fingerprints", "accepted"]
    for entry in doc["accepted"]:
        assert entry["rule"].startswith("AUD-"), entry
        assert entry["file"], entry
        assert len(entry["reason"].split()) >= 6, entry  # a sentence, not a tag
    text = COMMITTED_BASELINE.read_text(encoding="utf-8")
    assert text.isascii()
    assert text.endswith("}\n")


def test_committed_baseline_does_not_reproduce_the_findings_it_accepts(
    tmp_path: Path, audit_context
):
    """
    `[tool.aisg-audit] exclude` does not list the baseline, so the self-audit scans it.
    A reason that quotes the literal it accepts (an over-grant flag, a kill-switch name,
    a floating model id) re-creates the finding from the baseline itself, and the gate
    reports it as new. Reasons describe; they do not quote.
    """
    from aisg.devtools.audit.rules import ALL_RULES, run_rules

    shutil.copy(COMMITTED_BASELINE, tmp_path / COMMITTED_BASELINE.name)
    ctx = audit_context(tmp_path)
    findings, _unknown = run_rules(ALL_RULES, ctx)
    offending = [
        (f.display_id, e.line, e.snippet)
        for f in findings
        for e in f.evidence
        if e.file == COMMITTED_BASELINE.name
    ]
    assert offending == []
