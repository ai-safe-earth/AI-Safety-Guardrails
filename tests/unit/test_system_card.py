"""
tests/unit/test_system_card.py
------------------------------
Tests for `aisg init`.

The card records operator assertions. These tests pin the two things that must
not drift: the file is valid YAML with the agreed keys, and it keeps saying out
loud that risk classification is a legal determination rather than a tool
output.
"""

from __future__ import annotations

import uuid

import pytest
import yaml

from aisg.devtools.system_card import (
    ANNEX_III,
    DEFAULT_CARD,
    DEPLOYMENTS,
    RISK_TIERS,
    ROLES,
    _yaml_scalar,
    build_parser,
    main,
    render_card,
)


def _card(**overrides):
    card = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULT_CARD.items()}
    card["system"]["id"] = str(uuid.uuid4())
    card.update(overrides)
    return card


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


class TestRenderCard:
    def test_renders_valid_yaml(self):
        data = yaml.safe_load(render_card(_card()))
        assert data["schema"] == "aisg/1"
        assert set(data["system"]) == {"id", "name", "purpose"}
        assert data["role"] in ROLES
        assert data["deployment"] in DEPLOYMENTS

    def test_all_required_top_level_keys_present(self):
        data = yaml.safe_load(render_card(_card()))
        for key in (
            "schema",
            "system",
            "role",
            "risk_tier",
            "annex_iii_category",
            "affected_persons",
            "deployment",
            "incident_contact",
        ):
            assert key in data, f"missing {key}"

    def test_incident_contact_round_trips(self):
        data = yaml.safe_load(render_card(_card(incident_contact="oncall@example.test")))
        assert data["incident_contact"] == "oncall@example.test"

    def test_default_incident_contact_is_a_todo_placeholder(self):
        """
        `aisg audit` (AUD-703, AUD-1001) reads this key and treats a value
        that still starts with TODO as no contact at all -- the placeholder
        must never pass for a real one.
        """
        assert DEFAULT_CARD["incident_contact"].startswith("TODO")
        data = yaml.safe_load(render_card(_card()))
        assert data["incident_contact"].startswith("TODO")

    def test_incident_contact_carries_a_comment_saying_who(self):
        lines = render_card(_card()).splitlines()
        idx = next(i for i, ln in enumerate(lines) if ln.startswith("incident_contact:"))
        assert lines[idx - 1].startswith("#")
        assert "misbehaves" in lines[idx - 1]

    def test_card_is_ascii(self):
        assert render_card(_card()).isascii()

    def test_legal_determination_caveat_sits_above_risk_tier(self):
        """The caveat is the point of the file; it must precede risk_tier."""
        text = render_card(_card())
        lines = text.splitlines()
        idx = next(i for i, ln in enumerate(lines) if ln.startswith("risk_tier:"))
        preceding = "\n".join(lines[max(0, idx - 5) : idx]).lower()
        assert "legal determination" in preceding
        assert "not a tool output" in preceding

    def test_annex_iii_rendered_when_high_risk(self):
        card = _card(risk_tier="high", annex_iii_category="biometrics")
        data = yaml.safe_load(render_card(card))
        assert data["risk_tier"] == "high"
        assert data["annex_iii_category"] == "biometrics"

    def test_annex_iii_null_when_not_high(self):
        data = yaml.safe_load(render_card(_card(risk_tier="minimal")))
        assert data["annex_iii_category"] is None

    def test_every_annex_iii_value_round_trips(self):
        for category in ANNEX_III:
            card = _card(risk_tier="high", annex_iii_category=category)
            assert yaml.safe_load(render_card(card))["annex_iii_category"] == category

    def test_every_risk_tier_round_trips(self):
        for tier in RISK_TIERS:
            assert yaml.safe_load(render_card(_card(risk_tier=tier)))["risk_tier"] == tier

    def test_purpose_with_colon_survives(self):
        """A colon in free text is the classic way to emit invalid YAML."""
        card = _card()
        card["system"]["purpose"] = "Triage: routes tickets to a human"
        data = yaml.safe_load(render_card(card))
        assert data["system"]["purpose"] == "Triage: routes tickets to a human"

    def test_free_text_with_quotes_survives(self):
        card = _card(affected_persons='Users who said "yes" to terms')
        data = yaml.safe_load(render_card(card))
        assert data["affected_persons"] == 'Users who said "yes" to terms'

    def test_free_text_with_hash_survives(self):
        card = _card(affected_persons="Cohort #4 and #5")
        assert yaml.safe_load(render_card(card))["affected_persons"] == "Cohort #4 and #5"


class TestYamlScalar:
    @pytest.mark.parametrize(
        "value",
        ["plain", "Triage: routes", 'has "quotes"', "#leading-hash", "true", "null", "", "a: b: c"],
    )
    def test_scalar_round_trips(self, value):
        assert yaml.safe_load(f"k: {_yaml_scalar(value)}")["k"] == (value if value else None or "")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestInitCLI:
    def test_defaults_writes_card(self, tmp_path):
        dest = tmp_path / "ai-system-card.yaml"
        assert main(["--defaults", "-o", str(dest)]) == 0
        assert dest.is_file()
        data = yaml.safe_load(dest.read_text(encoding="utf-8"))
        assert data["schema"] == "aisg/1"
        assert data["incident_contact"].startswith("TODO")

    def test_interactive_prompts_for_incident_contact(self, tmp_path, monkeypatch):
        """Every prompt takes its default except the contact, which we answer."""
        monkeypatch.setattr("sys.stdin.isatty", lambda: True)
        answers = iter(["", "", "", "", "", "", "", "pager@example.test"])
        monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
        dest = tmp_path / "c.yaml"
        assert main(["-o", str(dest)]) == 0
        data = yaml.safe_load(dest.read_text(encoding="utf-8"))
        assert data["incident_contact"] == "pager@example.test"
        assert data["risk_tier"] == "unknown"

    def test_defaults_generates_unique_ids(self, tmp_path):
        ids = []
        for i in range(3):
            dest = tmp_path / f"card{i}.yaml"
            main(["--defaults", "-o", str(dest)])
            ids.append(yaml.safe_load(dest.read_text(encoding="utf-8"))["system"]["id"])
        assert len(set(ids)) == 3, "system.id must not be a fixed placeholder"

    def test_id_is_a_uuid(self, tmp_path):
        dest = tmp_path / "c.yaml"
        main(["--defaults", "-o", str(dest)])
        uuid.UUID(yaml.safe_load(dest.read_text(encoding="utf-8"))["system"]["id"])

    def test_refuses_to_overwrite(self, tmp_path):
        dest = tmp_path / "c.yaml"
        assert main(["--defaults", "-o", str(dest)]) == 0
        first = dest.read_text(encoding="utf-8")
        assert main(["--defaults", "-o", str(dest)]) == 2
        assert dest.read_text(encoding="utf-8") == first, "must not clobber without --force"

    def test_force_overwrites(self, tmp_path):
        dest = tmp_path / "c.yaml"
        main(["--defaults", "-o", str(dest)])
        before = yaml.safe_load(dest.read_text(encoding="utf-8"))["system"]["id"]
        assert main(["--defaults", "--force", "-o", str(dest)]) == 0
        after = yaml.safe_load(dest.read_text(encoding="utf-8"))["system"]["id"]
        assert before != after

    def test_non_interactive_without_defaults_errors(self, tmp_path, monkeypatch, capsys):
        """Under CI, stdin is not a tty -- prompting would hang."""
        monkeypatch.setattr("sys.stdin.isatty", lambda: False)
        assert main(["-o", str(tmp_path / "c.yaml")]) == 2
        assert "--defaults" in capsys.readouterr().err

    def test_reports_the_caveat_on_stdout(self, tmp_path, capsys):
        main(["--defaults", "-o", str(tmp_path / "c.yaml")])
        out = capsys.readouterr().out.lower()
        assert "legal determination" in out
        assert "did not classify" in out

    def test_parser_exposes_defaults_flag(self):
        args = build_parser().parse_args(["--defaults"])
        assert args.defaults is True
