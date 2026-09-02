"""tests/unit/test_audit_baseline.py
---------------------------------
Pins for the fingerprint baseline: write/load round trip, a full audit report read as a
baseline yields the same set, anything else is a `BaselineError`, and `diff` marks
new/unchanged in place so the exit code counts only what is new.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aisg.devtools.audit.baseline import (
    BaselineDiff,
    BaselineError,
    diff,
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


def make_finding(
    rule_id: str, file: str, snippet: str, severity: Severity = Severity.HIGH
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
