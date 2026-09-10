"""tests/unit/test_audit_baseline.py
---------------------------------
Pins for the fingerprint baseline: write/load round trip, a full audit report read as a
baseline yields the same set, anything else is a `BaselineError`, and `diff` marks
new/unchanged in place so the exit code counts only what is new.

The `accepted` list: `write_baseline(..., reasons=...)` fills it from the findings,
`load_baseline` validates it (a reason per entry, every entry also in `fingerprints`), and
the committed `audit-baseline.json` is held to that shape -- plus one more: scanning the
baseline file itself must not reproduce the findings it accepts.

The `index` block names every fingerprint (rule, file, title) so a later diff can say what
a fingerprint that is no longer reported was, and `amend_baseline` records a reason without
a re-scan; it refuses a reason that is empty, non-ASCII, not a single printable line,
verdict-shaped or secret-shaped, and never writes on a refusal. `read_baseline` applies the same reason check, so a
hand-edited file cannot carry what `--accept` would have refused.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from aisg.devtools.audit.baseline import (
    BaselineDiff,
    BaselineError,
    amend_baseline,
    diff,
    load_accepted,
    load_baseline,
    load_generated_at,
    load_index,
    parse_accept,
    read_baseline,
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
    assert list(doc) == ["schema", "kind", "generated_at", "tool", "fingerprints", "index"]
    assert doc["schema"] == "aisg/1" and doc["kind"] == "audit-baseline"
    assert doc["tool"] == {"name": "aisg-audit", "version": tool_version()}
    assert doc["fingerprints"] == sorted(doc["fingerprints"])
    assert len(doc["fingerprints"]) == len(set(doc["fingerprints"])) == 3
    assert load_baseline(path) == {f.fingerprint for f in findings}


def test_write_baseline_index_names_every_fingerprint(tmp_path: Path):
    findings = three()
    findings[1] = make_finding("AUD-402", "b.py", "eval(reply)", sub="eval")
    path = tmp_path / "audit-baseline.json"
    write_baseline(findings, path)
    doc = json.loads(path.read_text(encoding="utf-8"))
    # Same order as `fingerprints`; rule is the display id, file the first evidence.
    assert list(doc["index"]) == doc["fingerprints"]
    assert doc["index"][findings[1].fingerprint] == {
        "rule": "AUD-402/eval",
        "file": "b.py:3",
        "title": "title for AUD-402",
    }
    assert load_index(path) == doc["index"]
    assert load_generated_at(path) == doc["generated_at"]
    assert path.read_text(encoding="utf-8").isascii()


def test_write_baseline_index_uses_the_scope_name_for_an_absence_finding(tmp_path: Path):
    absent = make_absence_finding("AUD-1001", ".")
    path = tmp_path / "b.json"
    write_baseline([absent], path)
    assert load_index(path)[absent.fingerprint]["file"] == "."


def test_load_index_and_generated_at_tolerate_an_old_baseline_and_a_report(tmp_path: Path):
    fp = three()[0].fingerprint
    old = tmp_path / "old.json"
    old.write_text(json.dumps({"schema": "aisg/1", "kind": "audit-baseline", "fingerprints": [fp]}))
    assert load_baseline(old) == {fp}
    assert load_index(old) == {}
    assert load_generated_at(old) is None
    report_path = tmp_path / "audit-report.json"
    report_path.write_text(render(make_report(three()), "json"), encoding="utf-8")
    assert load_index(report_path) == {}
    assert isinstance(load_generated_at(report_path), str)
    document = read_baseline(report_path)
    assert document.kind == "audit" and len(document.fingerprints) == 3
    assert document.accepted == {} and document.index == {}


@pytest.mark.parametrize(
    ("index", "reason"),
    [
        (["not", "a", "dict"], "not an object"),
        ({"abc": "not an object"}, "not an object"),
        ({"": {"rule": "AUD-401"}}, "not a fingerprint"),
    ],
)
def test_load_baseline_rejects_a_malformed_index(tmp_path: Path, index: object, reason: str):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(
        json.dumps(
            {"schema": "aisg/1", "kind": "audit-baseline", "fingerprints": [fp], "index": index}
        )
    )
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    assert reason in str(info.value) and "b.json" in str(info.value)


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


def test_load_baseline_on_a_non_utf8_file_is_a_baseline_error(tmp_path: Path):
    """A file in another encoding is refused by name, not as a raw UnicodeDecodeError."""
    path = tmp_path / "utf16.json"
    fp = three()[0].fingerprint
    text = json.dumps({"schema": "aisg/1", "kind": "audit-baseline", "fingerprints": [fp]})
    path.write_bytes(text.encode("utf-16"))
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    message = str(info.value)
    assert "utf16.json" in message and "UTF-8" in message
    assert "\n" not in message


def test_write_baseline_uses_lf_on_every_platform(tmp_path: Path):
    """A baseline is committed; a Windows write must not carry CRLF."""
    path = tmp_path / "b.json"
    findings = three()
    write_baseline(findings, path, reasons={findings[0].fingerprint: "constant argv"})
    raw = path.read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"}\n")
    amend_baseline(path, {findings[1].fingerprint: "eval on a literal"})
    assert b"\r" not in path.read_bytes()


def test_write_baseline_creates_the_parent_directory(tmp_path: Path):
    """
    `.aisg-audit/` usually does not exist on the first `--write-baseline`, and the write
    comes after the scan and the render: the parent is created, like `-o` does.
    """
    path = tmp_path / "sub" / "dir" / "b.json"
    assert not path.parent.exists()
    findings = three()
    write_baseline(findings, path, reasons={findings[0].fingerprint: "constant argv"})
    assert path.parent.is_dir()
    assert load_baseline(path) == {f.fingerprint for f in findings}
    assert load_accepted(path) == {findings[0].fingerprint: "constant argv"}


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
    assert list(doc) == [
        "schema",
        "kind",
        "generated_at",
        "tool",
        "fingerprints",
        "accepted",
        "index",
    ]
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


def _unrecordable_reasons() -> list[tuple[str, str]]:
    """Reasons `amend_baseline` refuses; a hand-edited file is held to the same bar."""
    from aisg.devtools.audit.report import BANNED_PHRASES

    banned_word = "cl" + "ean"
    secret = "sk-ant-" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4"
    cases = [
        ("caf" + chr(0xE9) + " fixture, not a live key", "ASCII"),
        # ASCII, but not one printable line: JSON carries these as escapes, so a hand
        # edit can put them in a file, and the renderers print the reason as one line.
        ("fixture key\nassembled at runtime", "single line"),
        ("fixture key\r\nassembled at runtime", "single line"),
        ("fixture key\tassembled at runtime", "single line"),
        ("fixture key \x00 assembled at runtime", "single line"),
        ("fixture key \x7f assembled at runtime", "single line"),
        (f"reviewed; the target is {banned_word}", "verdict"),
        (f"the token {secret} is a fixture", "secret"),
    ]
    cases.extend((f"reviewed and it {phrase} now", "verdict") for phrase in BANNED_PHRASES)
    return cases


@pytest.mark.parametrize(("reason", "why"), _unrecordable_reasons())
def test_load_baseline_rejects_an_accepted_reason_amend_would_refuse(
    tmp_path: Path, reason: str, why: str
):
    fp = three()[0].fingerprint
    path = tmp_path / "b.json"
    path.write_text(_baseline_doc([fp], [{"fingerprint": fp, "reason": reason}]), encoding="utf-8")
    with pytest.raises(BaselineError) as info:
        load_baseline(path)
    message = str(info.value)
    assert why in message and fp in message and "b.json" in message
    assert "\n" not in message
    # The refusal names the fingerprint, never the text it refused.
    assert reason not in message


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
    assert result.to_dict() == {
        "file": "b.json",
        "kind": None,
        "new": 0,
        "unchanged": 1,
        "accepted": [],
        "generated_at": None,
        "no_longer_reported": [],
    }


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------


def test_diff_marks_new_and_unchanged_in_place_and_lists_gone():
    """A gone fingerprint is listed under `no_longer_reported`; the block carries no count."""
    old = three()
    baseline = {old[0].fingerprint, old[1].fingerprint, "ffffffffffffffff"}
    current = three()
    result = diff(current, baseline, file="audit-baseline.json")
    assert isinstance(result, BaselineDiff)
    assert [f.id for f in result.unchanged] == ["AUD-401", "AUD-402"]
    assert [f.id for f in result.new] == ["AUD-501"]
    assert result.gone == ["ffffffffffffffff"]
    assert result.file == "audit-baseline.json"
    assert [f.baseline_status for f in current] == ["unchanged", "unchanged", "new"]
    assert [f.accepted_reason for f in current] == [None, None, None]
    assert result.to_dict() == {
        "file": "audit-baseline.json",
        "kind": None,
        "new": 1,
        "unchanged": 2,
        "accepted": [],
        "generated_at": None,
        "no_longer_reported": [{"fingerprint": "ffffffffffffffff"}],
    }
    assert list(result.to_dict()) == [
        "file",
        "kind",
        "new",
        "unchanged",
        "accepted",
        "generated_at",
        "no_longer_reported",
    ]
    assert "fixed" not in result.to_dict()


def test_diff_normalises_windows_paths_in_file():
    assert diff([], set(), file="out\\audit-baseline.json").file == "out/audit-baseline.json"


def test_diff_stamps_accepted_reason_and_lists_the_accepted_entries(tmp_path: Path):
    old = three()
    old[1] = make_finding("AUD-402", "b.py", "eval(reply)", sub="eval")
    path = tmp_path / "audit-baseline.json"
    write_baseline(old, path, reasons={old[1].fingerprint: "eval on a literal, never on output"})
    document = read_baseline(path)
    current = three()
    current[1] = make_finding("AUD-402", "b.py", "eval(reply)", sub="eval")
    current[1].evidence = [Evidence(role="match", file="b.py", line=30, snippet="eval(reply)")]
    # Same fingerprint at a new line: the finding is unchanged, the reason still applies,
    # and the accepted entry keeps the location the baseline recorded so a renderer can
    # say where it moved from.
    assert current[1].fingerprint == old[1].fingerprint
    assert current[1].location == ("b.py", 30)
    result = diff(
        current,
        document.fingerprints,
        file=path.name,
        accepted=document.accepted,
        index=document.index,
        generated_at=document.generated_at,
        kind=document.kind,
    )
    assert [f.accepted_reason for f in current] == [
        None,
        "eval on a literal, never on output",
        None,
    ]
    assert [f.baseline_status for f in current] == ["unchanged", "unchanged", "unchanged"]
    block = result.to_dict()
    assert block["kind"] == "audit-baseline"
    assert block["accepted"] == [
        {
            "fingerprint": old[1].fingerprint,
            "rule": "AUD-402/eval",
            "file": "b.py:3",
            "reason": "eval on a literal, never on output",
        }
    ]
    assert block["generated_at"] == document.generated_at
    assert block["no_longer_reported"] == []


def test_diff_accepted_entry_falls_back_to_the_finding_without_an_index():
    findings = three()
    reasons = {findings[0].fingerprint: "constant argv, no user input reaches it"}
    result = diff(findings, {findings[0].fingerprint}, file="b.json", accepted=reasons)
    assert result.to_dict()["accepted"] == [
        {
            "fingerprint": findings[0].fingerprint,
            "rule": "AUD-401",
            "file": "a.py:3",
            "reason": "constant argv, no user input reaches it",
        }
    ]
    assert findings[0].accepted_reason == reasons[findings[0].fingerprint]


def test_diff_names_no_longer_reported_from_the_index(tmp_path: Path):
    old = three()
    path = tmp_path / "audit-baseline.json"
    write_baseline(old, path)
    document = read_baseline(path)
    current = three()[:2]  # AUD-501 is gone
    result = diff(
        current,
        document.fingerprints,
        file=path.name,
        index=document.index,
        generated_at=document.generated_at,
    )
    assert result.gone == [old[2].fingerprint]
    assert result.to_dict()["no_longer_reported"] == [
        {
            "fingerprint": old[2].fingerprint,
            "rule": "AUD-501",
            "file": "c.py:3",
            "title": "title for AUD-501",
        }
    ]
    # A finding with a reason is accepted; one without stays a bare unchanged finding.
    assert result.to_dict()["accepted"] == []


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
    assert doc["baseline"] == {
        "file": "audit-baseline.json",
        "kind": None,
        "new": 2,
        "unchanged": 1,
        "accepted": [],
        "generated_at": None,
        "no_longer_reported": [],
    }
    assert doc["summary"]["baseline_new"] == 2
    assert doc["summary"]["exit_code"] == 1
    statuses = {f["id"]: f["baseline_status"] for f in doc["findings"]}
    assert statuses == {"AUD-401": "unchanged", "AUD-402": "new", "AUD-501": "new"}


# ---------------------------------------------------------------------------
# amend: record a reason without a re-scan
# ---------------------------------------------------------------------------

BASELINE_KEYS = ["schema", "kind", "generated_at", "tool", "fingerprints", "accepted", "index"]


def _written(tmp_path: Path, reasons: dict[int, str] | None = None) -> tuple[Path, list[Finding]]:
    """A three-finding baseline on disk; `reasons` is keyed by finding index."""
    findings = three()
    findings[1] = make_finding("AUD-402", "b.py", "eval(reply)", sub="eval")
    path = tmp_path / "audit-baseline.json"
    by_fingerprint = None
    if reasons is not None:
        by_fingerprint = {findings[i].fingerprint: reason for i, reason in reasons.items()}
    write_baseline(findings, path, reasons=by_fingerprint)
    return path, findings


def test_parse_accept_splits_on_the_first_equals():
    assert parse_accept("abc=a reason") == ("abc", "a reason")
    assert parse_accept(" abc = x=y=z ") == ("abc", "x=y=z")
    for bad in ("abc", "=reason", " =reason", ""):
        with pytest.raises(BaselineError) as info:
            parse_accept(bad)
        assert "FINGERPRINT=REASON" in str(info.value)


def test_amend_baseline_records_a_reason_with_rule_and_file_from_the_index(tmp_path: Path):
    path, findings = _written(tmp_path)
    before = json.loads(path.read_text(encoding="utf-8"))
    count = amend_baseline(
        path, {findings[1].fingerprint: "eval on a literal the model never sees"}
    )
    assert count == 1
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert list(doc) == BASELINE_KEYS
    assert doc["accepted"] == [
        {
            "fingerprint": findings[1].fingerprint,
            "rule": "AUD-402/eval",
            "file": "b.py:3",
            "reason": "eval on a literal the model never sees",
        }
    ]
    # Nothing else moved: the fingerprints, the scan time, the tool and the index stay.
    for key in ("generated_at", "tool", "fingerprints", "index"):
        assert doc[key] == before[key]
    assert load_accepted(path) == {
        findings[1].fingerprint: "eval on a literal the model never sees"
    }
    assert path.read_text(encoding="utf-8").endswith("}\n")


def test_amend_baseline_replaces_the_reason_for_a_repeated_fingerprint(tmp_path: Path):
    path, findings = _written(tmp_path, reasons={0: "first look, argv is constant"})
    amend_baseline(path, {findings[0].fingerprint: "second look, argv is a tuple literal"})
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert [e["reason"] for e in doc["accepted"]] == ["second look, argv is a tuple literal"]
    assert doc["accepted"][0]["rule"] == "AUD-401" and doc["accepted"][0]["file"] == "a.py:3"
    # Appended entries follow the ones already on file, in the order given.
    amend_baseline(
        path,
        {
            findings[2].fingerprint: "fixture token assembled at runtime",
            findings[1].fingerprint: "eval on a literal the model never sees",
        },
    )
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert [e["fingerprint"] for e in doc["accepted"]] == [
        findings[0].fingerprint,
        findings[2].fingerprint,
        findings[1].fingerprint,
    ]
    assert list(doc) == BASELINE_KEYS


def test_amend_baseline_on_an_old_file_without_an_index_leaves_rule_and_file_null(
    tmp_path: Path,
):
    fp = three()[0].fingerprint
    path = tmp_path / "old.json"
    path.write_text(
        json.dumps(
            {
                "schema": "aisg/1",
                "kind": "audit-baseline",
                "generated_at": "2026-01-01T00:00:00+00:00",
                "tool": {"name": "aisg-audit", "version": "0.0.0"},
                "fingerprints": [fp],
            }
        )
    )
    amend_baseline(path, {fp: "constant argv, nothing user-controlled reaches it"})
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert list(doc) == BASELINE_KEYS[:-1]
    assert doc["accepted"] == [
        {
            "fingerprint": fp,
            "rule": None,
            "file": None,
            "reason": "constant argv, nothing user-controlled reaches it",
        }
    ]
    assert doc["generated_at"] == "2026-01-01T00:00:00+00:00"
    assert load_accepted(path) == {fp: "constant argv, nothing user-controlled reaches it"}


def _banned_word() -> str:
    return "cl" + "ean"


def _secret_shaped() -> str:
    return "sk-ant-" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4"


def _refusals() -> list[tuple[str, str]]:
    from aisg.devtools.audit.report import BANNED_PHRASES

    cases = [
        ("", "empty"),
        ("   ", "empty"),
        ("caf" + chr(0xE9) + " fixture, not a live key", "ASCII"),
        ("constant argv\nsee the ticket", "single line"),
        ("constant argv\rsee the ticket", "single line"),
        ("constant argv\tsee the ticket", "single line"),
        ("constant argv \x1b[0m see the ticket", "single line"),
        ("constant argv \x7f see the ticket", "single line"),
        (f"this path is {_banned_word()} after review", "verdict"),
        (f"reviewed; {_banned_word().upper()}", "verdict"),
        (f"the token is {_secret_shaped()} and it is a fixture", "secret"),
        ("api_key = 'abcdefghijklmnop' is a fixture", "secret"),
    ]
    cases.extend((f"reviewed and it {phrase} now", "verdict") for phrase in BANNED_PHRASES)
    cases.extend((f"reviewed: {phrase.upper()}", "verdict") for phrase in BANNED_PHRASES)
    return cases


@pytest.mark.parametrize(("reason", "why"), _refusals())
def test_amend_baseline_refuses_a_reason_it_cannot_record(tmp_path: Path, reason: str, why: str):
    path, findings = _written(tmp_path)
    before = path.read_text(encoding="utf-8")
    with pytest.raises(BaselineError) as info:
        amend_baseline(path, {findings[0].fingerprint: reason})
    message = str(info.value)
    assert why in message and findings[0].fingerprint in message
    assert "\n" not in message
    # The refusal names the fingerprint, never the text it refused.
    if reason.strip():
        assert reason.strip() not in message
    assert path.read_text(encoding="utf-8") == before


def test_amend_baseline_refuses_a_fingerprint_the_file_does_not_list(tmp_path: Path):
    path, _findings = _written(tmp_path)
    before = path.read_text(encoding="utf-8")
    with pytest.raises(BaselineError) as info:
        amend_baseline(path, {"ffffffffffffffff": "never scanned, so never listed"})
    assert "ffffffffffffffff" in str(info.value) and "fingerprints" in str(info.value)
    assert path.read_text(encoding="utf-8") == before


def test_amend_baseline_checks_every_accept_before_writing_any(tmp_path: Path):
    path, findings = _written(tmp_path)
    before = path.read_text(encoding="utf-8")
    with pytest.raises(BaselineError):
        amend_baseline(
            path,
            {
                findings[0].fingerprint: "constant argv, a fine reason",
                findings[1].fingerprint: "",
            },
        )
    assert path.read_text(encoding="utf-8") == before


def test_amend_baseline_refuses_a_report_and_an_empty_accept_map(tmp_path: Path):
    findings = three()
    report_path = tmp_path / "audit-report.json"
    report_path.write_text(render(make_report(findings), "json"), encoding="utf-8")
    before = report_path.read_text(encoding="utf-8")
    with pytest.raises(BaselineError) as info:
        amend_baseline(report_path, {findings[0].fingerprint: "a report is not a baseline"})
    assert "audit-baseline" in str(info.value) and "audit-report.json" in str(info.value)
    assert report_path.read_text(encoding="utf-8") == before
    path, _ = _written(tmp_path)
    with pytest.raises(BaselineError) as info:
        amend_baseline(path, {})
    assert "nothing to accept" in str(info.value)


def test_amended_baseline_diffs_with_the_reason_stamped(tmp_path: Path):
    path, findings = _written(tmp_path)
    amend_baseline(path, {findings[2].fingerprint: "fixture token assembled at runtime"})
    document = read_baseline(path)
    current = three()
    current[1] = make_finding("AUD-402", "b.py", "eval(reply)", sub="eval")
    result = diff(
        current,
        document.fingerprints,
        file=path.name,
        accepted=document.accepted,
        index=document.index,
        generated_at=document.generated_at,
    )
    assert current[2].accepted_reason == "fixture token assembled at runtime"
    assert result.to_dict()["accepted"][0]["rule"] == "AUD-501"
    report = make_report(current)
    doc = json.loads(render(report, "json"))
    stamped = [f for f in doc["findings"] if f.get("accepted_reason")]
    assert [f["id"] for f in stamped] == ["AUD-501"]
    assert (
        list(stamped[0]).index("accepted_reason") == list(stamped[0]).index("baseline_status") + 1
    )


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
    # A file regenerated by this version also carries the trailing `index`; one written
    # before it does not. Either way the order in front of it is pinned.
    assert list(doc) in (BASELINE_KEYS, BASELINE_KEYS[:-1])
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
