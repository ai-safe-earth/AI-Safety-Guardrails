"""
src/aisafe/devtools/prices.py
---------------------------
The price table `aisafe decide` joins token counts with, and the rules that keep the
join honest.

Prices are DATA, not knowledge: a YAML file (`prices.yaml`, shipped as package data
and mirrored at the repo-root `config/`) that names the day its figures were copied
from the provider pricing pages (`as_of`), the pages they came from (`sources`) and
how long they are good for (`stale_after_days`). Nothing here fetches a price: the
audit and the decision never open a socket, and a figure typed in by a person on a
known day is a figure that can be rechecked. A model that is not in the table
renders `unavailable` and names itself; it is never guessed.

Resolution order for the file: an explicit path, the `AISAFE_PRICES` environment
variable (or its pre-rename name `AISG_PRICES`), `[tool.aisafe-decide] prices` in pyproject.toml, then the packaged file.
"""

from __future__ import annotations

import datetime as _dt
import math
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from aisafe.core.measurement import COST_BASIS

__all__ = [
    "PRICES_FILE",
    "PRICES_ENV",
    "SCHEMA_VERSION",
    "KIND",
    "Price",
    "PriceTable",
    "PricesError",
    "load_prices",
    "resolve_prices_path",
    "price_call",
    "usd_label",
]

PRICES_FILE = "prices.yaml"
PRICES_ENV = "AISAFE_PRICES"
# Read when `PRICES_ENV` is unset: the variable's name before the rename (2026-10-20).
LEGACY_PRICES_ENV = "AISG_PRICES"
SCHEMA_VERSION = "aisg/1"
KIND = "prices"
DEFAULT_STALE_AFTER_DAYS = 90

_MTOK = 1_000_000.0


class PricesError(ValueError):
    """The price table is missing, malformed or not a price table."""


@dataclass(frozen=True)
class Price:
    """One model's list price, in USD per million tokens. `free` is a hosted model
    that charges nothing (a moderation endpoint); `local` runs on the operator's own
    hardware, which this table does not price. Both cost 0.0 here and say so."""

    model: str
    provider: str
    input_usd_per_mtok: float | None = None
    output_usd_per_mtok: float | None = None
    cached_input_usd_per_mtok: float | None = None
    free: bool = False
    local: bool = False
    aliases: tuple[str, ...] = ()

    @property
    def priced(self) -> bool:
        return (
            self.free
            or self.local
            or (self.input_usd_per_mtok is not None and self.output_usd_per_mtok is not None)
        )

    @property
    def kind(self) -> str:
        if self.free:
            return "free"
        if self.local:
            return "local"
        return "priced"


@dataclass(frozen=True)
class PriceTable:
    as_of: _dt.date
    stale_after_days: int
    sources: tuple[str, ...]
    models: dict[str, Price]
    path: str = ""
    currency: str = "USD"
    unit: str = "usd_per_million_tokens"
    _aliases: dict[str, str] = field(default_factory=dict, repr=False, compare=False)

    def age_days(self, today: _dt.date | None = None) -> int:
        return ((today or _dt.date.today()) - self.as_of).days

    def is_stale(self, today: _dt.date | None = None) -> bool:
        return self.age_days(today) > self.stale_after_days

    def get(self, model: str) -> Price | None:
        """Exact id, or an exact alias. No fuzzy matching: a near miss is a different model."""
        if model in self.models:
            return self.models[model]
        canonical = self._aliases.get(model)
        return self.models.get(canonical) if canonical else None


def _as_float(value: Any, where: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise PricesError(f"{where}: expected a number, got {value!r}")
    if value < 0 or math.isnan(float(value)):
        raise PricesError(f"{where}: a price cannot be {value!r}")
    return float(value)


def parse_prices(text: str, path: str = "") -> PriceTable:
    """Parse and validate a price table document."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PricesError(f"{path or 'prices'}: not valid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise PricesError(f"{path or 'prices'}: not a mapping")
    if doc.get("schema") != SCHEMA_VERSION or doc.get("kind") != KIND:
        raise PricesError(
            f"{path or 'prices'}: expected schema {SCHEMA_VERSION!r} and kind {KIND!r}, "
            f"got {doc.get('schema')!r} / {doc.get('kind')!r}"
        )
    raw_as_of = doc.get("as_of")
    if isinstance(raw_as_of, _dt.datetime):
        as_of = raw_as_of.date()
    elif isinstance(raw_as_of, _dt.date):
        as_of = raw_as_of
    else:
        try:
            as_of = _dt.date.fromisoformat(str(raw_as_of))
        except ValueError as exc:
            raise PricesError(f"{path or 'prices'}: as_of must be a YYYY-MM-DD date") from exc
    stale_after = doc.get("stale_after_days", DEFAULT_STALE_AFTER_DAYS)
    if not isinstance(stale_after, int) or isinstance(stale_after, bool) or stale_after < 1:
        raise PricesError(f"{path or 'prices'}: stale_after_days must be a positive integer")
    sources = doc.get("sources") or []
    if not isinstance(sources, list) or not all(isinstance(s, str) for s in sources):
        raise PricesError(f"{path or 'prices'}: sources must be a list of URLs")
    raw_models = doc.get("models")
    if not isinstance(raw_models, dict) or not raw_models:
        raise PricesError(f"{path or 'prices'}: models must be a non-empty mapping")

    models: dict[str, Price] = {}
    aliases: dict[str, str] = {}
    for model, entry in raw_models.items():
        if not isinstance(model, str) or not isinstance(entry, dict):
            raise PricesError(f"{path or 'prices'}: models.{model!r} must be a mapping")
        where = f"models.{model}"
        provider = entry.get("provider")
        if not isinstance(provider, str) or not provider:
            raise PricesError(f"{where}: provider is required")
        raw_aliases = entry.get("aliases") or []
        if not isinstance(raw_aliases, list) or not all(isinstance(a, str) for a in raw_aliases):
            raise PricesError(f"{where}: aliases must be a list of model ids")
        price = Price(
            model=model,
            provider=provider,
            input_usd_per_mtok=_as_float(entry.get("input_usd_per_mtok"), where),
            output_usd_per_mtok=_as_float(entry.get("output_usd_per_mtok"), where),
            cached_input_usd_per_mtok=_as_float(entry.get("cached_input_usd_per_mtok"), where),
            free=bool(entry.get("free", False)),
            local=bool(entry.get("local", False)),
            aliases=tuple(raw_aliases),
        )
        if not price.priced:
            raise PricesError(
                f"{where}: needs input_usd_per_mtok and output_usd_per_mtok, or free: true, "
                "or local: true"
            )
        models[model] = price
        for alias in price.aliases:
            aliases[alias] = model
    return PriceTable(
        as_of=as_of,
        stale_after_days=stale_after,
        sources=tuple(sources),
        models=models,
        path=path,
        currency=str(doc.get("currency", "USD")),
        unit=str(doc.get("unit", "usd_per_million_tokens")),
        _aliases=aliases,
    )


def _pyproject_prices(start: Path | None) -> str | None:
    """`[tool.aisafe-decide] prices`, resolved from the CWD like every other tool section."""
    try:
        from aisafe.devtools._config import load_tool_config

        config = load_tool_config("aisafe-decide", start=start)
    except Exception:  # a broken pyproject is the audit's business, not ours
        return None
    value = (config or {}).get("prices") if isinstance(config, dict) else None
    return value if isinstance(value, str) and value else None


def resolve_prices_path(explicit: str | Path | None = None, start: Path | None = None) -> Path:
    """Where the price table comes from, in resolution order; the packaged file last."""
    if explicit:
        return Path(explicit)
    env = os.environ.get(PRICES_ENV) or os.environ.get(LEGACY_PRICES_ENV)
    if env:
        return Path(env)
    configured = _pyproject_prices(start)
    if configured:
        return Path(configured)
    from aisafe.config import preset_path

    return preset_path(PRICES_FILE)


def load_prices(explicit: str | Path | None = None, start: Path | None = None) -> PriceTable:
    path = resolve_prices_path(explicit, start)
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise PricesError(f"price table not readable: {path}: {exc}") from exc
    return parse_prices(text, str(path))


def price_call(
    price: Price | None, tokens_in: float | None, tokens_out: float | None
) -> float | None:
    """
    USD for one call: tokens priced per million. None when the model is unpriced or a
    token figure is unknown; 0.0 for a free or local model whatever the tokens.
    """
    if price is None:
        return None
    if price.free or price.local:
        return 0.0
    if tokens_in is None or tokens_out is None:
        return None
    assert price.input_usd_per_mtok is not None and price.output_usd_per_mtok is not None
    return (tokens_in * price.input_usd_per_mtok + tokens_out * price.output_usd_per_mtok) / _MTOK


def usd_label(cost_basis: str, price: Price | None, stale: bool) -> str:
    """
    The label printed next to every dollar figure: how the tokens were obtained
    (`measured` / `estimated` / `unavailable`), or `free` / `local` for a model that
    costs nothing here, or `unavailable` for a model the table does not know; with
    `, stale` appended when the table is past its shelf life.
    """
    if price is None:
        label = "unavailable"
    elif price.free:
        label = "free"
    elif price.local:
        label = "local"
    elif cost_basis in ("measured", "estimated"):
        label = cost_basis
    elif cost_basis == "none":
        label = "none"
    else:
        label = "unavailable"
    if cost_basis not in COST_BASIS and price is not None and not (price.free or price.local):
        label = "unavailable"
    return f"{label}, stale" if stale and label not in ("free", "local") else label
