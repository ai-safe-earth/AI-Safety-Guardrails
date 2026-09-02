"""tests/unit/test_audit_model.py
------------------------------
Pins for the audit data model: enum ranks, fingerprint stability, redaction, sorting,
serialisation key order and the UNMEASURED default.

Every secret-shaped sample below is assembled at runtime so no committed file carries a
key-shaped string.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from aisg.devtools.audit.model import (
    DEFAULT_REPORT,
    DISCLAIMER,
    FINDING_KEYS,
    INVENTORY_KEYS,
    REDACT_PATTERNS,
    REPORT_KEYS,
    SCHEMA_VERSION,
    SEVERITY_ORDER,
    TRIFECTA_RULE_ID,
    AuditContext,
    Basis,
    Bucket,
    Confidence,
    Evidence,
    EvidenceKind,
    ExternalToolResult,
    Finding,
    Hit,
    Inventory,
    MatchKind,
    Recommendation,
    Report,
    ReportRecord,
    Scope,
    Severity,
    Status,
    Tier,
    Unit,
    UnknownCategory,
    UnknownItem,
    fingerprint,
    now_iso,
    redact,
    sort_findings,
    truncate_snippet,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def make_finding(
    rule_id: str = "AUD-401",
    *,
    priority: int = 4,
    severity: Severity | str = Severity.HIGH,
    file: str = "app.py",
    line: int = 10,
    snippet: str = "subprocess.run(cmd, shell=True)",
    sub: str | None = None,
    evidence: list[Evidence] | None = None,
    **extra,
) -> Finding:
    if evidence is None:
        evidence = [Evidence(role="sink", file=file, line=line, snippet=snippet)]
    return Finding(
        id=rule_id,
        title=f"title for {rule_id}",
        severity=severity,
        priority=priority,
        bucket=Bucket.ASSERTED,
        basis=Basis.PRESENCE,
        confidence=Confidence(EvidenceKind.CODE, MatchKind.GREP),
        scope=Scope("unit", "u1", "services/agent"),
        evidence=evidence,
        controls=("ASI01",),
        recommendation=Recommendation(Tier.T1, "do the thing", ("aisg", "nemo", "manual")),
        related_lint_rules=("EU-AIA-012a",),
        known_failure_modes=("grep depth",),
        sub=sub,
        **extra,
    )


def roundtrip(obj) -> dict:
    """JSON round trip proves serialisability and preserves key order."""
    return json.loads(json.dumps(obj.to_dict()))


# ---------------------------------------------------------------------------
# constants and enums
# ---------------------------------------------------------------------------


def test_constants():
    assert SCHEMA_VERSION == "aisg/1"
    assert DEFAULT_REPORT == "audit-report.json"
    assert TRIFECTA_RULE_ID == "AUD-301"
    assert "Not an assessment of compliance with any regulation" in DISCLAIMER
    assert "legal determination" in DISCLAIMER
    assert "UNMEASURED" in DISCLAIMER


def test_severity_ranks_descend_from_critical():
    ranks = [s.rank() for s in SEVERITY_ORDER]
    assert ranks == sorted(ranks, reverse=True)
    assert Severity.CRITICAL.rank() > Severity.HIGH.rank() > Severity.MEDIUM.rank()
    assert Severity.MEDIUM.rank() > Severity.LOW.rank() > Severity.INFO.rank()
    assert Severity.INFO.rank() == 0
    assert set(SEVERITY_ORDER) == set(Severity)
    assert Severity("high") is Severity.HIGH
    assert Severity.HIGH == "high"


def test_enum_values_are_the_wire_strings():
    assert {b.value for b in Bucket} == {"measured", "asserted", "unknown"}
    assert {b.value for b in Basis} == {"presence", "absence", "measured"}
    assert {e.value for e in EvidenceKind} == {"code", "config", "absence", "tool_output", "report"}
    assert {m.value for m in MatchKind} == {"grep", "structured", "ast", "external"}
    assert {t.value for t in Tier} == {"T1", "T2", "T3"}
    assert {s.value for s in Status} == {
        "ran",
        "not_on_path",
        "not_applicable",
        "failed",
        "timeout",
        "skipped_by_flag",
        "skipped_needs_flag",
    }
    assert {c.value for c in UnknownCategory} == {"tools", "deep", "reports", "runtime"}


# ---------------------------------------------------------------------------
# fingerprint
# ---------------------------------------------------------------------------


def test_fingerprint_shape():
    fp = fingerprint("AUD-401", "app.py", "x = 1")
    assert re.fullmatch(r"[0-9a-f]{16}", fp)
    assert fp == fingerprint("AUD-401", "app.py", "x = 1")


def test_fingerprint_stable_under_whitespace_and_identifier_renumbering():
    base = fingerprint("AUD-401", "svc/app.py", "result1 = run_step2(payload)")
    assert base == fingerprint("AUD-401", "svc/app.py", "result2 = run_step3(payload)")
    assert base == fingerprint("AUD-401", "svc/app.py", "  result1   =\trun_step2(payload)  ")
    # line numbers are not part of the hash at all
    assert base == fingerprint("AUD-401", "svc/app.py", "result9 = run_step9(payload)")


def test_fingerprint_keeps_pure_numbers_and_short_identifiers():
    assert fingerprint("AUD-1", "f.py", "max_tokens = 4096") != fingerprint(
        "AUD-1", "f.py", "max_tokens = 2048"
    )
    # a two-character identifier keeps its digit (u1 vs u2 are different units)
    assert fingerprint("AUD-1", "f.py", "u1") != fingerprint("AUD-1", "f.py", "u2")


def test_fingerprint_differs_by_rule_id_and_path():
    snippet = "subprocess.run(cmd)"
    assert fingerprint("AUD-401", "app.py", snippet) != fingerprint("AUD-402", "app.py", snippet)
    assert fingerprint("AUD-401", "app.py", snippet) != fingerprint("AUD-401", "other.py", snippet)


def test_fingerprint_normalises_path_separators():
    win = str(Path("services") / "agent" / "app.py")
    assert fingerprint("AUD-401", win, "x") == fingerprint("AUD-401", "services/agent/app.py", "x")
    assert fingerprint("AUD-401", "services\\agent\\app.py", "x") == fingerprint(
        "AUD-401", "services/agent/app.py", "x"
    )


# ---------------------------------------------------------------------------
# redaction
# ---------------------------------------------------------------------------


def secret_samples() -> list[tuple[str, str]]:
    """(expected prefix, literal) pairs, every literal built at runtime."""
    return [
        ("sk-ant-", "sk-ant-" + "api03-" + "x" * 40),
        ("sk-", "sk-" + "proj-" + "A" * 30 + "1234"),
        ("ghp_", "ghp_" + "a" * 32 + "wxyz"),
        ("gho_", "gho_" + "b" * 36),
        ("github_pat_", "github_pat_" + "c" * 22 + "_" + "d" * 36 + "ef12"),
        ("AKIA", "AKIA" + "Q" * 12 + "ABCD"),
        ("xoxb-", "xoxb-" + "1234567890-" + "abcdef" * 4),
        ("xoxp-", "xoxp-" + "0987654321-" + "zyxwvu" * 4),
        ("AIza", "AIza" + "Sy" + "z" * 29 + "9999"),
    ]


@pytest.mark.parametrize("prefix,literal", secret_samples())
def test_redact_prefixed_tokens(prefix: str, literal: str):
    line = f'client = Client(api_key="{literal}")'
    out = redact(line)
    assert literal not in out
    assert "<redacted:" in out
    assert f"<redacted:{prefix}...{literal[-4:]}>" in out
    # the surrounding code survives
    assert out.startswith('client = Client(api_key="')
    assert out.endswith('")')


def test_redact_table_covers_every_listed_prefix():
    names = {name for name, _ in REDACT_PATTERNS}
    assert {"anthropic", "openai", "github_pat", "github", "aws", "slack", "google"} <= names
    for _name, pattern in REDACT_PATTERNS:
        assert pattern.groups >= 1


def test_redact_key_value_forms():
    key = "pass" + "word"
    value = "hunter2" + "hunter2"
    for sep in ("=", " = ", ": "):
        for quote in ('"', "'", ""):
            line = f"{key}{sep}{quote}{value}{quote}"
            out = redact(line)
            assert value not in out, line
            assert f"<redacted:...{value[-4:]}>" in out, line
            assert out.startswith(key), line
    json_line = '{"api_' + 'key": "' + "Z" * 20 + "9876" + '"}'
    out = redact(json_line)
    assert "Z" * 20 not in out
    assert "<redacted:...9876>" in out


def test_redact_bearer_and_adjacent_hex_runs():
    token = "eyJ" + "a" * 30 + "b1c2"
    out = redact("Authorization: Bearer " + token)
    assert token not in out
    assert "Bearer <redacted:...b1c2>" in out

    hexrun = "0123456789abcdef" * 2
    out = redact('("secret", "' + hexrun + '")')
    assert hexrun not in out
    assert "<redacted:...cdef>" in out


@pytest.mark.parametrize(
    "benign",
    [
        "max_tokens=4096",
        "token_count = 12345678",
        "tokenizer = AutoTokenizer.from_pretrained(name)",
        'secret_key = os.environ["SECRET_KEY"]',
        "api_key=settings.anthropic_api_key",
        "what is the capital of france",
        "sha = hashlib.sha256(data).hexdigest()",
        "",
    ],
)
def test_redact_leaves_benign_lines_alone(benign: str):
    assert redact(benign) == benign


def test_redact_is_idempotent():
    literal = "sk-ant-" + "api03-" + "y" * 40
    line = f'api_key = "{literal}"'
    once = redact(line)
    assert redact(once) == once
    kv = redact(("pass" + "word") + "=" + "abcdefgh1234")
    assert redact(kv) == kv


def test_truncate_snippet_normalises_redacts_and_caps():
    literal = "ghp_" + "q" * 36
    raw = "   token =\t'" + literal + "'   " + "x" * 300
    out = truncate_snippet(raw)
    assert len(out) <= 160
    assert literal not in out
    assert "<redacted:ghp_" in out
    assert "\t" not in out and "  " not in out
    assert out.endswith("...")
    short = truncate_snippet("  a   b  ")
    assert short == "a b"
    assert truncate_snippet("x" * 160) == "x" * 160


def test_truncate_redacts_before_cutting():
    # A secret that straddles the limit must be redacted as a whole, not cut into a
    # fragment short enough to slip past the prefix patterns.
    literal = "sk-ant-" + "api03-" + "w" * 60
    raw = "k" * 150 + " " + literal
    out = truncate_snippet(raw)
    assert "sk-ant-api03" not in out
    assert "w" * 8 not in out


# ---------------------------------------------------------------------------
# value objects
# ---------------------------------------------------------------------------


def test_confidence_label_unmeasured_when_precision_none():
    c = Confidence(EvidenceKind.CODE, MatchKind.AST)
    assert c.precision is None
    assert c.label == "UNMEASURED"
    assert Confidence("code", "ast", 0.5).label == "MEASURED"
    d = roundtrip(c)
    assert d == {
        "evidence_kind": "code",
        "match_kind": "ast",
        "precision": None,
        "label": "UNMEASURED",
    }


def test_evidence_snippet_is_always_redacted_and_short():
    literal = "AKIA" + "Z" * 16
    e = Evidence(role="secret", file="cfg\\prod.env", line=3, snippet="  KEY=" + literal + "  ")
    assert literal not in e.snippet
    assert e.snippet.startswith("KEY=<redacted:AKIA...ZZZZ>")
    assert e.file == "cfg/prod.env"
    assert len(Evidence("r", "f", 1, "z" * 500).snippet) <= 160


def test_scope_rejects_unknown_kind():
    Scope("repo")
    Scope("function", "u1", "app.py::main")
    with pytest.raises(ValueError):
        Scope("module")


def test_hit_and_recommendation_shapes():
    h = Hit(file="a.py", line=1, col=0, snippet="x", table="SINK", key="shell")
    assert h.unit is None and h.lang is None
    r = Recommendation("T2", "gate it", ["aisg", "other"])
    assert r.tier is Tier.T2
    assert r.alternatives == ("aisg", "other")
    assert roundtrip(r) == {"tier": "T2", "summary": "gate it", "alternatives": ["aisg", "other"]}


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------


def test_finding_defaults_and_coercion():
    f = make_finding(severity="high")
    assert f.gitignored is False
    assert f.suppressed is False
    assert f.sub is None and f.report is None and f.baseline_status is None and f.notes is None
    assert f.severity is Severity.HIGH
    assert f.fingerprint == fingerprint("AUD-401", "app.py", "subprocess.run(cmd, shell=True)")
    assert f.location == ("app.py", 10)


def test_finding_to_dict_key_order_and_ids():
    f = make_finding()
    d = roundtrip(f)
    assert list(d) == list(FINDING_KEYS)
    assert list(d)[:4] == ["id", "rule_id", "sub", "fingerprint"]
    assert d["id"] == "AUD-401" and d["rule_id"] == "AUD-401" and d["sub"] is None
    assert d["severity"] == "high" and d["bucket"] == "asserted" and d["basis"] == "presence"
    assert d["confidence"]["label"] == "UNMEASURED"
    assert d["scope"] == {"kind": "unit", "unit": "u1", "name": "services/agent"}
    assert d["evidence"][0]["file"] == "app.py"
    assert d["recommendation"]["tier"] == "T1"
    assert d["controls"] == ["ASI01"]
    assert "report" not in d and "baseline_status" not in d and "notes" not in d


def test_finding_optional_blocks_emitted_when_set():
    rec = ReportRecord("measure", "measure-report.json", "aisg/1", None, "mtime", 41)
    f = make_finding("AUD-803", report=rec.finding_report(), baseline_status="new", notes="n")
    d = roundtrip(f)
    assert list(d)[-3:] == ["report", "baseline_status", "notes"]
    assert d["report"] == {
        "file": "measure-report.json",
        "schema": "aisg/1",
        "generated_at": None,
        "age_source": "mtime",
        "age_days": 41,
    }


def test_sub_finding_has_distinct_display_id_and_fingerprint():
    parent = make_finding("AUD-107", snippet="GUARDRAILS_DISABLE_ALL = True")
    inert = make_finding("AUD-107", snippet="GUARDRAILS_DISABLE_ALL = True", sub="inert")
    assert parent.display_id == "AUD-107"
    assert inert.display_id == "AUD-107/inert"
    assert parent.fingerprint != inert.fingerprint
    assert inert.fingerprint == fingerprint(
        "AUD-107/inert", "app.py", "GUARDRAILS_DISABLE_ALL = True"
    )
    d = inert.to_dict()
    assert d["id"] == "AUD-107/inert" and d["rule_id"] == "AUD-107" and d["sub"] == "inert"


def test_absence_finding_fingerprint_uses_scope():
    a = make_finding("AUD-701", evidence=[])
    assert a.location == ("", 0)
    assert a.fingerprint == fingerprint("AUD-701", "services/agent", "")


def test_explicit_fingerprint_is_kept():
    f = make_finding(fingerprint="deadbeefdeadbeef")
    assert f.fingerprint == "deadbeefdeadbeef"


# ---------------------------------------------------------------------------
# sorting
# ---------------------------------------------------------------------------


def test_sort_findings_pins_trifecta_first():
    findings = [
        make_finding("AUD-401", priority=4, severity=Severity.HIGH, file="b.py", line=5),
        make_finding("AUD-101", priority=1, severity=Severity.CRITICAL, file="a.py", line=1),
        make_finding("AUD-301", priority=3, severity=Severity.CRITICAL, file="z.py", line=99),
        make_finding("AUD-102", priority=1, severity=Severity.HIGH, file="a.py", line=2),
    ]
    ordered = sort_findings(findings)
    assert ordered[0].id == "AUD-301"
    assert [f.id for f in ordered] == ["AUD-301", "AUD-101", "AUD-102", "AUD-401"]
    # input untouched
    assert [f.id for f in findings] == ["AUD-401", "AUD-101", "AUD-301", "AUD-102"]


def test_sort_findings_orders_by_priority_severity_file_line():
    findings = [
        make_finding("AUD-402", priority=4, severity=Severity.MEDIUM, file="a.py", line=30),
        make_finding("AUD-401", priority=4, severity=Severity.HIGH, file="b.py", line=1),
        make_finding("AUD-401", priority=4, severity=Severity.HIGH, file="a.py", line=20),
        make_finding("AUD-401", priority=4, severity=Severity.HIGH, file="a.py", line=10),
        make_finding("AUD-501", priority=5, severity=Severity.CRITICAL, file="a.py", line=1),
    ]
    ordered = sort_findings(findings)
    assert [(f.id, f.location) for f in ordered] == [
        ("AUD-401", ("a.py", 10)),
        ("AUD-401", ("a.py", 20)),
        ("AUD-401", ("b.py", 1)),
        ("AUD-402", ("a.py", 30)),
        ("AUD-501", ("a.py", 1)),
    ]


# ---------------------------------------------------------------------------
# unknown items and external tools
# ---------------------------------------------------------------------------


def test_unknown_item_category_and_dict():
    u = UnknownItem("tools", "dependency vulnerabilities", "pip-audit not on PATH")
    assert u.category is UnknownCategory.TOOLS
    assert roundtrip(u) == {
        "category": "tools",
        "what": "dependency vulnerabilities",
        "why": "pip-audit not on PATH",
    }
    full = UnknownItem(
        UnknownCategory.REPORTS,
        "report age unknown",
        "no generated_at",
        how_to_resolve="re-run aisg measure",
        file="old\\probe-report.json",
        rule_ids=["AUD-903"],
    )
    d = roundtrip(full)
    assert d["file"] == "old/probe-report.json"
    assert d["rule_ids"] == ["AUD-903"]
    assert d["how_to_resolve"] == "re-run aisg measure"
    with pytest.raises(ValueError):
        UnknownItem("other", "x", "y")


def test_external_tool_result_dict_keeps_network_and_omits_none():
    r = ExternalToolResult("pip-audit", "not_on_path", True)
    d = roundtrip(r)
    assert list(d)[:3] == ["name", "status", "network"]
    assert d["network"] is True
    assert "version" not in d and "flag" not in d and "error" not in d
    ran = ExternalToolResult(
        "mcp-scan",
        Status.RAN,
        False,
        version="0.3",
        duration_ms=12,
        findings=1,
        argv=["mcp-scan", "scan", "--local-only"],
    )
    d = roundtrip(ran)
    assert d["status"] == "ran" and d["network"] is False
    assert d["argv"] == ["mcp-scan", "scan", "--local-only"]
    assert d["findings"] == 1 and d["duration_ms"] == 12 and d["version"] == "0.3"
    skipped = ExternalToolResult("promptfoo", "skipped_needs_flag", True, flag="--run-evals")
    assert roundtrip(skipped)["flag"] == "--run-evals"


# ---------------------------------------------------------------------------
# inventory, report records, report
# ---------------------------------------------------------------------------


def test_unit_and_report_record():
    u = Unit("u1", "services\\agent", "services\\agent\\pyproject.toml", "python", True)
    assert roundtrip(u) == {
        "id": "u1",
        "root": "services/agent",
        "manifest": "services/agent/pyproject.toml",
        "language": "python",
        "ai_surface": True,
    }
    rec = ReportRecord("probe", "probe-report.json", "aisg/1", body={"summary": {"sent": 48}})
    d = roundtrip(rec)
    assert list(d) == [
        "kind",
        "file",
        "schema",
        "generated_at",
        "age_source",
        "age_days",
        "models",
        "config_digest",
    ]
    assert "body" not in d
    assert rec.models == [] and rec.age_source == "unknown"


def test_inventory_to_dict_schema_first_and_section_2_order():
    inv = Inventory(
        target={"path": "/abs/repo", "git_sha": None, "dirty": False},
        units=[Unit("u1", "services/agent", "services/agent/pyproject.toml", "python", True)],
        languages={"python": 3},
        reports=[ReportRecord("measure", "measure-report.json", "aisg/1", None, "mtime", 41)],
        unknown=[UnknownItem("deep", "deep analysis of 1 file", "SyntaxError", file="x.py")],
    )
    d = roundtrip(inv)
    assert list(d)[0] == "schema" and d["schema"] == "aisg/1"
    assert list(d)[1] == "kind" and d["kind"] == "inventory"
    assert list(d) == list(INVENTORY_KEYS)
    assert d["units"][0]["ai_surface"] is True
    assert d["reports"][0]["age_days"] == 41
    assert d["unknown"][0]["category"] == "deep"
    assert d["mcp"] == {"configs": [], "servers": []}
    assert d["system_card"] is None
    assert list(roundtrip(Inventory()))[0] == "schema"


def test_report_to_dict_key_order_matches_section_3_2():
    report = Report(
        tool={"name": "aisg-audit", "version": "unknown"},
        target={"path": "/abs/repo", "git_sha": "abc", "dirty": False},
        summary={"findings": 1},
        findings=[make_finding("AUD-301", priority=3, severity="critical")],
        measured=[{"source": "gitleaks", "status": "ran", "network": False}],
        reports=[{"source": "measure-report.json"}],
        unknown=[UnknownItem("tools", "x", "y")],
        external_tools=[ExternalToolResult("gitleaks", "ran", False)],
        baseline={"file": "audit-baseline.json", "new": 0, "fixed": 0, "unchanged": 1},
        inventory=Inventory(),
        rules=[{"id": "AUD-301", "measured_precision": None, "ran": True, "experimental": False}],
    )
    d = roundtrip(report)
    assert list(d) == list(REPORT_KEYS)
    assert list(d)[0] == "schema" and d["schema"] == "aisg/1"
    assert d["kind"] == "audit"
    assert d["disclaimer"] == DISCLAIMER
    assert d["findings"][0]["id"] == "AUD-301"
    assert d["findings"][0]["confidence"]["label"] == "UNMEASURED"
    assert d["external_tools"] == [
        {"name": "gitleaks", "status": "ran", "network": False, "findings": 0, "argv": []}
    ]
    assert d["unknown"] == [{"category": "tools", "what": "x", "why": "y"}]
    assert d["inventory"]["schema"] == "aisg/1"
    assert d["rules"][0]["measured_precision"] is None
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", d["generated_at"])


def test_empty_report_serialises():
    d = roundtrip(Report())
    assert list(d) == list(REPORT_KEYS)
    assert d["inventory"] == {} and d["baseline"] is None and d["findings"] == []


def test_audit_context_is_a_plain_container(tmp_path: Path):
    ctx = AuditContext(root=tmp_path, inventory=Inventory())
    assert ctx.pyfacts is None and ctx.options is None
    assert ctx.hits == [] and ctx.unknown == [] and ctx.external == []
    assert ctx.files == [] and ctx.reports == []
    ctx.hits.append(Hit("a.py", 1, 0, "x", "T", "k"))
    assert len(ctx.hits) == 1


def test_now_iso_format():
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", now_iso())


def test_model_text_has_no_compliance_claims():
    src = Path(__file__).resolve().parents[2] / "src" / "aisg" / "devtools" / "audit" / "model.py"
    text = src.read_text(encoding="utf-8").lower()
    for phrase in ("is compliant", "compliance verified", "certified", "meets the requirements"):
        assert phrase not in text
    assert text.isascii()
