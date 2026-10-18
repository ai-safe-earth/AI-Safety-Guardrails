"""tests/unit/test_prices.py
--------------------------
The price table is dated data, never a fetched or guessed figure. These tests pin the
shipped file (schema, kind, date, sources, every entry priced or free or local), its
repo-root mirror, the resolution order, staleness, and the per-call arithmetic.
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest

from aisg.config import PRICES_FILE, preset_path
from aisg.devtools import prices as prices_module
from aisg.devtools.prices import (
    Price,
    PricesError,
    load_prices,
    parse_prices,
    price_call,
    resolve_prices_path,
    usd_label,
)

REPO = Path(__file__).resolve().parents[2]


class TestShippedTable:
    def test_loads_with_schema_kind_date_and_sources(self):
        table = load_prices()
        text = preset_path(PRICES_FILE).read_text(encoding="utf-8")
        body = [line for line in text.splitlines() if line and not line.startswith("#")]
        assert body[0] == "schema: aisg/1" and body[1] == "kind: prices"
        assert isinstance(table.as_of, dt.date)
        assert table.sources and all(s.startswith("https://") for s in table.sources)
        assert table.stale_after_days == 90
        assert table.models

    def test_repo_mirror_is_identical(self):
        packaged = preset_path(PRICES_FILE).read_bytes()
        assert (REPO / "config" / "prices.yaml").read_bytes() == packaged

    def test_every_entry_is_priced_free_or_local(self):
        for price in load_prices().models.values():
            assert price.priced, price.model
            assert price.provider

    def test_the_shipped_default_judge_models_are_covered_or_named_as_missing(self):
        """Every model id a shipped guard or judge defaults to is either in the table
        or explicitly discussed in the file: nothing silently unpriced."""
        from aisg.modules.input.prompt_injection import PromptInjectionGuard
        from aisg.modules.llm_judges.claude_judge import ClaudeJudge
        from aisg.modules.llm_judges.llamaguard import _DEFAULT_MODELS
        from aisg.modules.llm_judges.openai_mod import OpenAIModerationJudge
        from aisg.modules.output.toxicity import ToxicityFilter

        defaults = {
            PromptInjectionGuard().llm_judge_model,
            ToxicityFilter().llm_judge_model,
            ClaudeJudge(api_key="k").model,
            OpenAIModerationJudge(api_key="k").model,
            *_DEFAULT_MODELS.values(),
        }
        table = load_prices()
        text = preset_path(PRICES_FILE).read_text(encoding="utf-8")
        for model in defaults:
            assert table.get(model) is not None or model in text, model

    def test_aliases_resolve_exactly_and_never_fuzzily(self):
        table = load_prices()
        assert table.get("claude-haiku-4-5") is table.get("claude-haiku-4-5-20251001")
        assert table.get("claude-haiku") is None
        assert table.get("CLAUDE-HAIKU-4-5-20251001") is None


class TestParsing:
    GOOD = (
        "schema: aisg/1\nkind: prices\nas_of: 2026-01-02\nstale_after_days: 30\n"
        "sources: [https://x]\nmodels:\n  m:\n    provider: p\n"
        "    input_usd_per_mtok: 1.0\n    output_usd_per_mtok: 2.0\n"
    )

    def test_wrong_schema_or_kind_is_refused(self):
        with pytest.raises(PricesError):
            parse_prices(self.GOOD.replace("kind: prices", "kind: audit"))
        with pytest.raises(PricesError):
            parse_prices(self.GOOD.replace("aisg/1", "aisg/2"))

    def test_half_priced_entry_is_refused(self):
        with pytest.raises(PricesError, match="needs input_usd_per_mtok"):
            parse_prices(self.GOOD.replace("    output_usd_per_mtok: 2.0\n", ""))

    def test_negative_or_non_numeric_price_is_refused(self):
        with pytest.raises(PricesError):
            parse_prices(self.GOOD.replace("1.0", "-1.0"))
        with pytest.raises(PricesError):
            parse_prices(self.GOOD.replace("1.0", '"cheap"'))

    def test_bad_date_and_empty_models_are_refused(self):
        with pytest.raises(PricesError, match="as_of"):
            parse_prices(self.GOOD.replace("2026-01-02", "soon"))
        with pytest.raises(PricesError, match="models"):
            parse_prices(self.GOOD.split("models:")[0] + "models: {}\n")

    def test_staleness_is_relative_to_today(self):
        table = parse_prices(self.GOOD)
        assert not table.is_stale(dt.date(2026, 1, 20))
        assert table.age_days(dt.date(2026, 1, 20)) == 18
        assert table.is_stale(dt.date(2026, 3, 1))


class TestResolution:
    def test_order_is_flag_env_pyproject_packaged(self, tmp_path, monkeypatch):
        monkeypatch.delenv(prices_module.PRICES_ENV, raising=False)
        packaged = resolve_prices_path(start=tmp_path)
        assert packaged.name == PRICES_FILE
        project = tmp_path / "pyproject.toml"
        project.write_text('[tool.aisg-decide]\nprices = "my-prices.yaml"\n', encoding="utf-8")
        assert resolve_prices_path(start=tmp_path) == Path("my-prices.yaml")
        monkeypatch.setenv(prices_module.PRICES_ENV, "env-prices.yaml")
        assert resolve_prices_path(start=tmp_path) == Path("env-prices.yaml")
        assert resolve_prices_path("flag.yaml", start=tmp_path) == Path("flag.yaml")

    def test_missing_file_is_a_prices_error(self, tmp_path):
        with pytest.raises(PricesError, match="not readable"):
            load_prices(tmp_path / "nope.yaml")

    def test_module_never_imports_a_network_library(self):
        import re

        source = (REPO / "src/aisg/devtools/prices.py").read_text(encoding="utf-8")
        pattern = re.compile(
            r"^\s*(?:import|from)\s+(socket|urllib|requests|aiohttp|httpx)\b", re.M
        )
        assert pattern.search(source) is None


class TestArithmetic:
    def test_price_call_prices_per_million(self):
        p = Price("m", "p", input_usd_per_mtok=3.0, output_usd_per_mtok=15.0)
        assert price_call(p, 1_000_000, 0) == pytest.approx(3.0)
        assert price_call(p, 1000, 100) == pytest.approx(0.0045)

    def test_free_and_local_are_zero_and_unknown_tokens_are_none(self):
        assert price_call(Price("m", "openai", free=True), None, None) == 0.0
        assert price_call(Price("m", "ollama", local=True), 5, 5) == 0.0
        assert (
            price_call(Price("m", "p", input_usd_per_mtok=1.0, output_usd_per_mtok=1.0), None, 1)
            is None
        )
        assert price_call(None, 1, 1) is None

    def test_usd_labels(self):
        priced = Price("m", "p", input_usd_per_mtok=1.0, output_usd_per_mtok=1.0)
        assert usd_label("measured", priced, False) == "measured"
        assert usd_label("estimated", priced, True) == "estimated, stale"
        assert usd_label("unavailable", priced, False) == "unavailable"
        assert usd_label("measured", None, False) == "unavailable"
        assert usd_label("measured", Price("m", "openai", free=True), True) == "free"
        assert usd_label("estimated", Price("m", "ollama", local=True), False) == "local"
        assert usd_label("none", priced, False) == "none"
