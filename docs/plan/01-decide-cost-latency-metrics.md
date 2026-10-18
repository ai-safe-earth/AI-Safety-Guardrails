# Design 01: `aisg decide` and the cost/latency/metrics layer

Produced 2026-10-18 by a read-only design pass over the repository. Consolidated in
`docs/PLAN.md` (wave 1). Where this file and `docs/PLAN.md` disagree, the plan wins; the
one known difference is recorded there (decision 8: card blocks are `traffic:` and
`budgets:`, `deployment` stays a scalar, which matches D14 below).

## 0. Decisions made (one line each)

| # | Decision | Why |
|---|---|---|
| D1 | Usage lives in one nested key `CheckResult.metadata["llm_usage"]` (dict), not new dataclass fields | Zero collision with the existing `judge`/`latency_ms`/`tool` keys the filters set; one place for the pipeline/logger/otel to read; `CheckResult` stays source-compatible. |
| D2 | `JudgeVerdict` gets one new field `usage: LLMUsage | None = None` | Dataclass default keeps every `JudgeVerdict(safe=...)` construction in `test_judges.py` valid. |
| D3 | `cost_basis` vocabulary is four values: `measured`, `estimated`, `unavailable`, `none` | `none` = no provider call happened (regex path, cache hit: cost is exactly 0); `unavailable` = a call happened and usage was not returned (HF, exception). Collapsing the two would call a known zero "unknown". |
| D4 | The runtime records tokens, never dollars | Prices change; a USD metric freezes a price into telemetry. Pricing is an offline join in `decide`. |
| D5 | `aisg measure` defaults to offline (no provider call); `--allow-provider-calls` opts in | It may cost money and today without credentials costs ~5.7 s per case. Offline runs still produce latency for the non-judge path and `estimated` tokens. |
| D6 | Offline mode never fakes a verdict as evidence: a judge guard's catch rate is UNMEASURED (`llm_exercised: false`), not 0% | A stubbed judge returning "safe" is not a measurement. |
| D7 | `Thresholds` gains the two per-call fields (`max_usd_per_request`, `max_human_rate`); deployment-level figures go in a sibling frozen `Budget` | A Profile alone can be judged against per-call caps; `usd/month` and `human capacity/day` need traffic, which a Profile does not know. `Budget.thresholds()` derives the per-call caps. |
| D8 | `failures()` judges `usd_per_call` only when `cost_basis == "measured"` | Demotion is a runtime decision from evidence; an estimate is not evidence. `decide` still reports estimated overruns (as `defer`/`apply with`). |
| D9 | html: `aisg audit --format html --decision PATH` adds a "Trade table" section; `decide` renders terminal/json/markdown only | The audit page already holds the plan rows the trade table annotates; one page, one numbering; the decision JSON remains authoritative and the page names it. |
| D10 | The decision JSON (`kind: decision`) is discovered by the audit as a report (like measure/probe), not as own-output | AUD-806 reads it as `REPORTED <age>` evidence. |
| D11 | One new rule, AUD-806 "Reported guard over the declared budget", with subs `/latency`, `/cost`, `/human`, `/benign`; plus sub-finding AUD-801/cost on the existing rule | AUD-803 analogue (reads a report from disk). The "judge never exercised" fact is an unmeasured fact, so it belongs under 801 with 801's package (`aisg measure`). |
| D12 | Policy-stage guards measured only behind `--include-policy` | `eu_ai_act.check_prohibited` may block adversarially benign cases; flipping it on by default would change the CI ratchet (`aisg measure --max-p99-ms 25`) in the same change. |
| D13 | Symbol -> guard mapping is derived from `REGISTRY` (`{cls.__name__: name}`), with a small hand map only for non-guard symbols | The registry is the truth; the audit's `_GUARD_CLASSES` is pinned against it by a new test. |
| D14 | Card block names are `traffic:` and `budgets:` (not `deployment:`) | `deployment` is already a pinned scalar (`eu|non_eu|unknown`, `test_renders_valid_yaml`). |
| D15 | Estimator = `ceil(chars/4)` over the real prompt constants imported from the judge modules | Judge prompts are JSON/markup heavy where `words*1.3` undercounts; importing the constants makes the estimate track the code. |
| D16 | Month = 30 days, stated in every renderer | Deterministic, labelled. |

## 1. Component list

### New files
| Path | Purpose | ~lines |
|---|---|---|
| `src/aisg/modules/llm_judges/estimate.py` | Offline token estimator per call site, importing the real prompt constants | 170 |
| `src/aisg/config/prices.yaml` + mirror `config/prices.yaml` | Price table (package data; already covered by the `"aisg.config" = ["*.yaml", ...]` glob in pyproject) | 70 |
| `src/aisg/devtools/prices.py` | Loader, override resolution, staleness, `price_call`, labels | 220 |
| `src/aisg/devtools/decide.py` | `aisg decide`: inputs, rows, recommendation function, totals, renderers, exit codes | 900 |
| `tests/unit/test_decide.py`, `tests/unit/test_prices.py`, `tests/unit/test_estimate.py` | see section 9 | 600 / 150 / 130 |
| `tests/fixtures/decide/{audit-report.json, measure-report.json, measure-report-no-llm.json, ai-system-card.yaml, prices.yaml}` | decide fixtures (new measure shape; the old `tests/fixtures/audit/reports/measure-report.json` stays as the backward-compat input) | data |

### Modified files
| Path | Change |
|---|---|
| `src/aisg/core/measurement.py` | `COST_BASIS`, `LLMUsage`, `weakest_basis()`, `Budget`; `Profile` + `Thresholds` fields; docstring fix on `false_positive_rate` |
| `src/aisg/core/base.py` | `GuardrailBase.__call__` sets `metadata.setdefault("guard_name", self.name)`; `PipelineResult.llm_usage` property |
| `src/aisg/core/pipeline.py` | opt-in `thresholds=` (constructor + `pipeline.thresholds` YAML block); `self.demoted` |
| `src/aisg/modules/llm_judges/base.py` | `JudgeVerdict.usage`; `usage_from_anthropic/_openai_compatible/_ollama`, `_int_or_none` |
| `src/aisg/modules/llm_judges/claude_judge.py`, `llamaguard.py`, `openai_mod.py`, `cache.py` | record usage; cache hit usage; cache copy also carries `reason` (existing drop) |
| `src/aisg/modules/input/prompt_injection.py` | hoist inline prompt to `_JUDGE_PROMPT`, `JUDGE_CONTENT_CAP = 2000`, `JUDGE_MAX_TOKENS = 100`; `_llm_judge_check` returns `(Finding | None, LLMUsage)`; metadata `llm_usage`, `judge_error` |
| `src/aisg/modules/output/toxicity.py` | same hoisting (`_JUDGE_PROMPT`, cap 3000, max 200); `llm_judge_model` config key (default `claude-sonnet-4-20250514`) replaces the hard-coded id; metadata |
| `src/aisg/modules/input/llm_input_filter.py`, `output/llm_output_filter.py`, `processing/llm_tool_filter.py` | add `"llm_usage": verdict.usage.as_metadata()` on every return path |
| `src/aisg/integrations/nemo_rails.py` | usage via `rails.explain()` (try/except), metadata |
| `src/aisg/modules/observability/otel.py` | 3 instruments + span attrs |
| `src/aisg/modules/observability/audit_logger.py` | `checks_run[].guard` = guard name; `check_id`, token keys; record totals |
| `src/aisg/devtools/measure.py` | flags, offline judge, new per-guard keys, `measured_on`, `pipeline` block, policy guards, `describe_measurement(..., provider_calls=)` |
| `src/aisg/devtools/system_card.py` | `traffic:` / `budgets:` blocks, prompts, defaults |
| `src/aisg/cli.py` | `decide` in `COMMANDS` + `_EPILOG` |
| `pyproject.toml` | `[tool.aisg-decide]` section (empty, commented) |
| `src/aisg/devtools/audit/discover.py` | `_report_kind` -> `"decision"`, `_REPORT_NAME_RE` adds `decision` |
| `src/aisg/devtools/audit/report.py` | `_report_entry` kind `decision` -> `_decision_extract` |
| `src/aisg/devtools/audit/rules/guards.py` | AUD-806 class; AUD-801/cost sub-finding; `RULES` |
| `src/aisg/devtools/audit/rules/__init__.py` | `SUBSYSTEM_OF_RULE["AUD-806"] = "guardrails"` |
| `src/aisg/devtools/audit/main.py`, `html.py` | `--decision PATH`; `_trade_table` section; `TEMPLATES` |
| `src/aisg/skills/ai-safety-audit/{SKILL.md, references/report-format.md, references/apply/python.md, references/controls.md}` + mirrors via `scripts/sync_skill.py` | see section 10 |
| `README.md`, `CLAUDE.md`, `docs/explain/measurement-first-guardrails.html` | see section 10 |

## 2. Data shapes (keys in order)

### 2.1 `LLMUsage` (core/measurement.py, frozen dataclass) and `metadata["llm_usage"]`
```
LLMUsage(tokens_in: int|None, tokens_out: int|None, model: str, provider: str,
         cost_basis: str, cache_hit: bool = False, calls: int = 1)
COST_BASIS = ("measured", "estimated", "unavailable", "none")
as_metadata() -> {"calls", "tokens_in", "tokens_out", "model", "provider", "cost_basis", "cache_hit"}
LLMUsage.none(model="", provider="") -> calls=0, tokens 0, basis "none"
LLMUsage.cache_hit(model, provider) -> calls=0, tokens 0, basis "none", cache_hit True
weakest_basis(iterable) -> order none < measured < estimated < unavailable
```
`PipelineResult.llm_usage` (property, dict): `{"calls", "tokens_in", "tokens_out", "cost_basis", "models": sorted unique}`; tokens sum only `int` values; if any contributing check is `unavailable` the sum is still emitted and `cost_basis` says `unavailable`.

### 2.2 `JudgeVerdict`
Existing fields unchanged, append `usage: LLMUsage | None = None`. `failed` unchanged.

### 2.3 `AuditRecord` (audit_logger.py; `to_json` uses `sort_keys=True`, so JSON order is alphabetical regardless)
New record fields: `llm_calls: int = 0`, `tokens_in: int | None = None`, `tokens_out: int | None = None`, `cost_basis: str = "none"`.
`checks_run[]` entry: `{"guard": <guard name>, "check_id": c.check_id, "passed", "action", "latency_ms", "findings", "llm_calls", "tokens_in", "tokens_out", "model", "cost_basis"}`. Guard name resolution: `c.metadata.get("guard_name") or (c.findings[0].guard_name if c.findings else "unknown")`, never the check-id prefix.

### 2.4 Price table (`prices.yaml`)
```yaml
schema: aisg/1
kind: prices
as_of: 2026-10-18            # the day the figures were copied from the pricing pages
currency: USD
unit: usd_per_million_tokens
stale_after_days: 90
sources:                     # one URL per provider pricing page consulted
  - https://...anthropic pricing...
  - https://...openai pricing...
  - https://...groq pricing...
  - https://...together pricing...
models:
  claude-sonnet-4-20250514:   {provider: anthropic, input_usd_per_mtok: <fill>, output_usd_per_mtok: <fill>, cached_input_usd_per_mtok: <fill>}
  claude-haiku-4-5-20251001:  {provider: anthropic, input_usd_per_mtok: <fill>, output_usd_per_mtok: <fill>, cached_input_usd_per_mtok: <fill>}
  omni-moderation-latest:     {provider: openai, free: true}
  llama-guard-3-8b:           {provider: groq, input_usd_per_mtok: <fill>, output_usd_per_mtok: <fill>}
  Meta-Llama/Llama-Guard-3-8B: {provider: together, input_usd_per_mtok: <fill>, output_usd_per_mtok: <fill>}
  llama-guard3:               {provider: ollama, local: true}
  meta-llama/Llama-Guard-3-8B: {provider: huggingface, local: true}
```
The model ids are exactly the defaults in `claude_judge.py:124`, `llm_judges/__init__.py:70`, `llamaguard._DEFAULT_MODELS`, `openai_mod.py:83`, `prompt_injection.llm_judge_model` default and `toxicity.py:153`. The engineer fills `<fill>` from the provider pricing pages on the day and sets `as_of` to that day; the tool never invents a figure (the honesty mechanism is `as_of` + `sources` + staleness, not accuracy claims). Optional `aliases: [..]` per entry for exact-string alternates; no fuzzy matching.

Loader (`devtools/prices.py`): `PriceTable{as_of: date, stale_after_days, sources, models: dict[str, Price]}`, `Price{provider, input_usd_per_mtok, output_usd_per_mtok, cached_input_usd_per_mtok, free, local}`; `load_prices(path=None)` resolution: explicit path > `AISG_PRICES` env > `[tool.aisg-decide] prices` > `aisg.config.preset_path("prices.yaml")` (works from a wheel; add `PRICES_FILE = "prices.yaml"` constant to `aisg/config/__init__.py`, do not add it to `PRESETS`, which `test_measure` iterates as pipeline presets). Schema/kind mismatch -> `PricesError` (decide maps to exit 2). `PriceTable.is_stale(today)`, `age_days(today)`. `price_call(price, tokens_in, tokens_out) -> float | None` (None when either token figure is None and the model is not free/local; 0.0 for free/local). `usd_label(tokens_basis, price, stale) -> "measured" | "estimated" | "unavailable" | "free" | "local"` plus `", stale"` suffix when stale.

### 2.5 Measure report (new keys; the two pinned prefixes `["schema","generated_at"]` hold)
Top level, in order: `schema, generated_at, measured_on, models, config_digest, config, pipeline, corpus, thresholds, disclaimer, guards`
- `measured_on`: the `describe_measurement()` string, now ending with `"; provider calls allowed"` or `"; offline (judge calls estimated, not made)"`.
- `pipeline`: `{"parallel_checks": bool, "fail_open": bool, "request_timeout": float|null}` read from the config (decide needs `parallel_checks` for sum-vs-max).
- `corpus`: unchanged + `"provider_calls": bool`, `"policy_guards_included": bool`.

Per guard, existing keys unchanged and in place (`name ... errors`), then appended:
```
"llm_configured": bool, "llm_exercised": bool, "llm_site": str|null,
"model": str|null, "provider": str|null,
"llm_calls_per_case": float|null, "llm_calls_per_attack": float|null, "llm_calls_per_benign": float|null,
"tokens_in_per_call": int|null, "tokens_out_per_call": int|null, "tokens_out_cap": int|null,
"prompt_overhead_tokens": int|null, "content_cap_chars": int|null,
"cost_basis": "measured"|"estimated"|"unavailable"|"none",
"cache_hit_rate": float|null,
"human_rate": float|null, "fail_mode": "open"|"closed"|"mixed"|"n/a",
"benign_modified_rate": float|null,
"notes": [str]
```
Site ids (the `llm_site` vocabulary, also the estimator's dispatch keys): `prompt_injection:inline`, `toxicity_output:inline`, `claude_judge:injection|toxicity|general`, `llamaguard:groq|together|openai|ollama|huggingface`, `openai_mod`, `nemo_rails`.

### 2.6 Decision document (`kind: decision`), keys in order
```
schema, kind, tool{name, version}, generated_at, disclaimer,
inputs{audit{file, generated_at, findings}, measure{file, generated_at, measured_on, age_days, provider_calls}|null,
       prices{file, as_of, age_days, stale, stale_after_days}, card{file}|null},
traffic{requests_per_day, avg_input_tokens, avg_output_tokens, source: "flags"|"card"|"defaults"},
budgets{p99_ms, monthly_usd, max_usd_per_request, human_review_capacity_per_day, max_human_rate, source},
controls[ row ],
selected[ control names ], totals{...}, unmeasured[ {control, why, how_to_resolve} ],
exit_code
```
Row (`controls[]`), keys in order:
```
control, symbol, kind ("guard"|"config"|"record"|"action"), stage|null,
rules[{id, same_control, mechanism}], mechanisms[sorted],
catch_rate, catch_rate_relevant{family: rate}, catch_rate_meaningful,
benign_broken_rate, benign_modified_rate, human_rate,
p50_ms, p99_ms, llm_calls_per_request, tokens_in_per_request, tokens_out_per_request,
usd_per_request, usd_per_month, usd_basis ("measured"|"estimated"|"unavailable"|"free"|"local", "+stale"),
fail_mode, provenance ("MEASURED <YYYY-MM-DD>"|"ESTIMATED <YYYY-MM-DD>"|"UNMEASURED"),
over_budget[ "p99"|"usd/request"|"usd/month"|"human"|"benign" ],
recommendation{verdict, reasons[], config_changes[]}
```
`totals`: `{mode: "sequential"|"parallel", p50_ms, p99_ms_upper_bound, usd_per_request, usd_per_month, human_per_day, human_capacity_per_day, over_budget[], excluded_unmeasured[]}`.

### 2.7 System card additions (`aisg init`)
```yaml
# What you EXPECT this system to carry. `aisg decide` reads these and compares
# measured guard figures against them; it does not verify them. Blank = unknown.
traffic:
  requests_per_day: null
  avg_input_tokens: null
  avg_output_tokens: null
budgets:
  p99_ms: null
  monthly_usd: null
  max_usd_per_request: null
  human_review_capacity_per_day: null
  max_human_rate: null
```
`DEFAULT_CARD` gains both dicts (the existing copy comprehension handles nested dicts); `collect_interactive()` asks each as an optional number ("Enter for unknown"), `_prompt_number()` helper re-asks on a non-number; `render_card` emits the block after `incident_contact`. The caveat above `risk_tier` is untouched.

## 3. Runtime token accounting

### 3.1 Readers (`llm_judges/base.py`)
```python
def _int_or_none(v) -> int | None   # int and not bool, else None  (MagicMock-safe: tests stub anthropic with MagicMock)
def usage_from_anthropic(response, model) -> LLMUsage   # getattr(response,"usage",None); .input_tokens/.output_tokens; basis measured iff both ints else unavailable
def usage_from_openai_compatible(data: dict, model, provider) -> LLMUsage  # data.get("usage",{}) prompt_tokens/completion_tokens
def usage_from_ollama(data: dict, model) -> LLMUsage   # prompt_eval_count / eval_count
```
Why MagicMock-safety matters: `test_judges.py::_make_anthropic_response` returns a `MagicMock` whose `.usage.input_tokens` is a `MagicMock`; without the `isinstance(int)` guard the reader would record a mock object.

### 3.2 Call sites
| Site | Change |
|---|---|
| `claude_judge.ClaudeJudge._call` (137-159) | `verdict = self._parse(raw); verdict.usage = usage_from_anthropic(response, self.model)`. Also pass `timeout=self.timeout` to `anthropic.AsyncAnthropic(...)`, the stored-but-never-passed timeout; one line, bounded. |
| `llamaguard._call_openai_compatible` / `_call_ollama` / `_call_huggingface` (269-365) | return `(raw, usage)`; `_call` sets `verdict.usage`. HF: `LLMUsage(None, None, model, "huggingface", "unavailable")`. |
| `openai_mod._call` | `verdict.usage = LLMUsage(None, None, self.model, "openai", "unavailable")` (the endpoint returns no usage; the price table marks it `free`). |
| `cache.CachedJudge._call` (98-106, 121-129) | both copies carry `reason=` (existing drop) and `usage=`; the hit copy gets `LLMUsage.cache_hit(inner.model, inner.provider)` where model/provider come from `getattr(self._judge, "model", "")`/`("provider", "")`. |
| `prompt_injection._llm_judge_check` (348-383) | hoist the literal to `_JUDGE_PROMPT` (format with `content=`), `JUDGE_CONTENT_CAP = 2000`, `JUDGE_MAX_TOKENS = 100`; returns `(finding, usage)`; on exception `usage = LLMUsage(None, None, model, "anthropic", "unavailable")` and `metadata["judge_error"] = f"{type(exc).__name__}: {exc}"`. `check()` writes `metadata["llm_usage"]` when the judge ran; when `llm_judge` is on but regex matched, writes `LLMUsage.none(model, "anthropic").as_metadata()` so "configured but not called" is visible (`calls: 0`). Behaviour (fail-open swallow) is not changed here; it is recorded. |
| `toxicity._llm_judge` (141-172) | identical treatment; new `setup(..., llm_judge_model="claude-sonnet-4-20250514")` replaces the hard-coded id so the price table can apply. `MODEL_KEYS` in measure already includes `llm_judge_model`, so `config_models()` picks it up. |
| `LLMInputFilter/LLMOutputFilter/LLMToolFilter` | every `CheckResult(...)` return adds `"llm_usage": (verdict.usage or LLMUsage(None,None,"", "", "unavailable")).as_metadata()`; the failed-judge branch too. The early `ALLOW` in `LLMToolFilter.check` (no tool call) adds nothing (no call was made; `measure` derives `calls_per_case` from presence of the key). |
| `nemo_rails.NemoRailsGuard.check` | after `generate_async`, `usage = _nemo_usage(rails)`: `info = rails.explain()` inside try/except; sum `prompt_tokens`/`completion_tokens` over `info.llm_calls`, `calls=len(info.llm_calls)`, model from the first `llm_model_name`, provider `"nemo"`, basis measured iff any int else unavailable; on any exception `unavailable`. Metadata key `llm_usage` on all three returns. |

### 3.3 Guard identity (`core/base.py:229-245`)
In `__call__`, after timing: `result.metadata.setdefault("guard_name", self.name)`. This is the key `otel._blocked_by` and `audit_logger._build_record` already fall back to (`test_otel.py:212` pins `metadata["guard_name"]` -> `"meta_guard"`), so it fixes the `checks_run[].guard` bug without a new dataclass field. `measure_guard` calls `guard(...)` directly, so it benefits too.

### 3.4 Telemetry (`otel.py`)
New instruments in `_init_instruments`:
- `guardrail.guard.llm_calls` counter (`{call}`), attrs `guardrail.guard.name`, `guardrail.stage`, `guardrail.llm.model`, `guardrail.llm.provider`, `guardrail.llm.cache_hit`
- `guardrail.guard.tokens` counter (`{token}`), attrs as above + `guardrail.llm.direction` (`in`|`out`) + `guardrail.llm.cost_basis`
- `guardrail.guard.tokens_per_call` histogram (`{token}`), attrs name/stage/direction
`record_check_result` reads `result.metadata.get("llm_usage")`; records only when `calls >= 1` or `cache_hit`; span attrs `guardrail.llm.tokens_in/out/model/cost_basis`. `__init__` adds the three `None` slots; `test_otel.py::_make_otel_test_provider` needs no change (`_init_instruments` assigns them) but add the three `None` lines there for symmetry.

### 3.5 Pipeline aggregation
`PipelineResult.llm_usage` property (section 2.1). No dataclass field; `_run_stage` unchanged.

## 4. Offline estimator (`modules/llm_judges/estimate.py`)

```python
CHARS_PER_TOKEN = 4
def estimate_tokens(text: str) -> int: return max(1, ceil(len(text) / CHARS_PER_TOKEN)) if text else 0

@dataclass(frozen=True)
class CallSite: id, model, provider, content_cap: int|None, max_tokens: int|None,
                prompt: Callable[[str, list|None], str], safe_reply: str

def site_for(guard) -> CallSite | None      # dispatch, unwraps CachedJudge._judge
def estimate_call(site, content, history=None) -> LLMUsage(cost_basis="estimated")
def prompt_overhead_tokens(site) -> int     # estimate_tokens(site.prompt("", None))
```
Sites and the real constants they import:
| site id | prompt | truncation | out cap | safe reply literal (output estimate = its chars/4) |
|---|---|---|---|---|
| `prompt_injection:inline` | `prompt_injection._JUDGE_PROMPT` (hoisted) | `JUDGE_CONTENT_CAP=2000` | `JUDGE_MAX_TOKENS=100` | `"SAFE"` (the literal the code compares against at line 372) |
| `toxicity_output:inline` | `toxicity._JUDGE_PROMPT` (hoisted) | 3000 | 200 | the `{"score": 0.0, "categories": [], "reason": ""}` literal from the prompt |
| `claude_judge:injection` | `claude_judge._INJECTION_PROMPT` | 3000 | 256 | the safe JSON literal in the prompt's last line |
| `claude_judge:toxicity` | `_TOXICITY_PROMPT` | 3000 | 256 | `{"safe": true, "score": 0.0, "categories": [], "confidence": 1.0, "reason": ""}` built from the prompt's declared shape |
| `claude_judge:general` | `_GENERAL_PROMPT` + `history[-6:]` x 500 chars (`_build_prompt`) | 3000 | 256 | `{"safe": true, "categories": [], "confidence": 1.0, "reason": ""}` |
| `llamaguard:<provider>` | `llamaguard._build_prompt(content, role, history)` (includes `_SAFETY_POLICY`, full content, full history) | none | 20 | `"safe"` |
| `openai_mod` | content itself | none | 0 | `""` |
| `nemo_rails` | unknown (NeMo's own flows) | - | - | returns `LLMUsage(None, None, "", "nemo", "unavailable")` |

Every result is labelled `estimated`; the estimator never opens a socket or imports a provider SDK (the judge modules import `anthropic`/`aiohttp` lazily inside `_call`, so importing their prompt constants is dependency-free; pin with a test that `sys.modules` gains no `anthropic`/`aiohttp` on `import aisg.modules.llm_judges.estimate`).

## 5. `aisg measure` extension

Flags added: `--allow-provider-calls` (default off), `--include-policy` (default off). Existing flags and exit codes unchanged.

Per guard, `measure_guard(guard, cases, timing_passes, *, provider_calls: bool)`:
1. `site = estimate.site_for(guard)`; `llm_configured = site is not None`.
2. Offline (`not provider_calls`) and `llm_configured`:
   - `PromptInjectionGuard` / `ToxicityFilter`: set `guard.llm_judge = False` / `guard.use_llm_judge = False` for the run (restore in `finally`); per case `would_call = result.action == Action.ALLOW` (the judge runs only when nothing else matched: `prompt_injection.py:315`, `toxicity.py:118`); `usage = estimate_call(site, case.payload)` when `would_call`; latency is the regex path's. `llm_exercised = False`; note `"judge not exercised: offline run; latency excludes the judge call; tokens estimated"`.
   - `LLM*Filter`: swap `guard._judge` for `_OfflineJudge(site, inner)` (an `LLMJudgeBase` whose `_call` returns `JudgeVerdict(safe=True, usage=estimate_call(...), judge_name=inner.name)`); restore after. `catch_rate_meaningful = False`, `llm_exercised = False`, note `"judge not exercised: verdicts are not measured; run with --allow-provider-calls"`. The per-case `calls` come from `metadata["llm_usage"]["calls"]`.
   - `NemoRailsGuard`: `unavailable = "offline: NeMo needs a live model; pass --allow-provider-calls"`, skipped.
3. Provider calls allowed: run as today; read `metadata["llm_usage"]` per case; `cost_basis` = `weakest_basis` over calls; a judge failure shows as `unavailable` plus `metadata["judge_error"]` into `errors`. Before each timing pass call `clear()` on any `CachedJudge` reachable from the guard, otherwise passes t1/t2 are cache hits and the median latency measures the cache, not the judge (note added when a cache was found).
4. `llm_calls_per_case = calls / cases_with_verdict` (and per attack/benign); `tokens_in_per_call` / `tokens_out_per_call` = median over calls with int tokens; `tokens_out_cap = site.max_tokens`; `prompt_overhead_tokens`, `content_cap_chars` from the site.
5. `human_rate = HUMAN verdicts / cases`; note when `tool_policy` has `require_approval` and no `approval_callback`: `"approval gate auto-approves without a callback; human_rate is not exercised"` (tool_policy.py:388-394).
6. `fail_mode`: `PromptInjectionGuard`/`ToxicityFilter` with judge -> `open` (exception swallowed); `LLM*Filter` -> `_judge.fail_open` -> `open`/`closed`, `LLMToolFilter` with a non-empty `high_risk_fail_closed` and `fail_open` -> `mixed`; `NemoRailsGuard._fail_open`; others `n/a`.
7. `benign_modified_rate = benign_modified / benign_seen`.
8. Policy guards: `collect_guards(pipeline, include_policy)` adds `pipeline.policy_guards`; `_context_for` sets `ctx["guardrail_stage"] = "input"` (what `run_input` does via `_run_stage`), always; harmless for other guards and required for `eu_ai_act`/`nist_ai_rmf`.

`build_report` writes `measured_on`, `pipeline`, the corpus flags and the new per-guard keys (section 2.5). `describe_measurement(attacks, benign, *, provider_calls=False)` keeps its 2-positional signature. `GuardMeasurement.to_profile()` additionally fills `tokens_in_per_call`, `tokens_out_per_call`, `cost_basis`, `human_rate`, `benign_modified_rate`; still never `precision`, never `usd_per_call` (measure has no prices).

FPR disagreement resolution: `false_positive_rate` keeps today's definition (blocked or `must_survive` lost) so the CI ratchet is untouched; `benign_modified_rate` is added beside it; `Profile.false_positive_rate` docstring is corrected to "wrongly blocked, or stripped of text that had to survive; modifications that keep the required text are `benign_modified_rate`". Terminal table gains columns `modified`, `llm calls/case`, `tok in/out`, `basis`.

## 6. `aisg decide`

### 6.1 CLI
```
aisg decide [--audit PATH] [--measure PATH] [--prices PATH] [--card PATH]
            [--requests-per-day N] [--avg-input-tokens N] [--avg-output-tokens N]
            [--p99-budget-ms MS] [--monthly-budget-usd USD] [--max-usd-per-request USD]
            [--human-review-capacity-per-day N] [--max-human-rate R]
            [--select CSV] [--format terminal|json|markdown] [-o PATH] [--quiet]
```
Defaults: `--audit .aisg-audit/audit-report.json` (required to exist: exit 2 with "run `aisg audit . --format json -o .aisg-audit/audit-report.json` first"), `--measure .aisg-audit/measure-report.json` (optional; absent -> every guard row UNMEASURED, exit 0 unless a budget check fails on a measured row), `--card ai-system-card.yaml` (optional). Flag > card > default (`traffic.source` says which). `[tool.aisg-decide]` via `apply_tool_config(parser, "aisg-decide", exclude=NOT_CONFIGURABLE)` with `NOT_CONFIGURABLE = frozenset({"select"})` (a selection is a per-decision act; a pyproject default would make every run compute totals and the exit code for a subset the operator did not choose this time; help text says "(not settable from pyproject)"). `prices` is configurable there. Exit codes: `EXIT_OK=0` rendered, `EXIT_OVER_BUDGET=1` any selected row or the totals exceed a hard budget, `EXIT_FATAL=2` missing/unreadable/wrong-schema input or bad flag; `KeyboardInterrupt` -> 130 (mirror audit).

### 6.2 Candidate rows
For each finding in the audit JSON with `recommendation.package.mechanism != "none"`: for each symbol -> one row per distinct symbol (rules aggregated into `rules[]`). Classification:
- `symbol_guard_name(symbol)`: inverse `REGISTRY` lookup (`import aisg` populates it; `import aisg.integrations.nemo_rails` in a try/except registers `nemo_rails`) -> `kind: guard`, `control` = registry name.
- `NON_GUARD_SYMBOLS = {"AuditLogger": "record", "TelemetryProvider": "record", "LLMJudgeBase": "config", "ToolPolicy": "config", "GuardrailPipeline": "config"}`.
- `^aisg [a-z]+$` -> `kind: action`.
Join guard rows with the measure report's `guards[]` by `name`. `GUARD_FAMILIES` (hand map, pinned against `REGISTRY` and `probe.available_families()`): `prompt_injection -> (prompt_injection, system_prompt_extraction, encoding_bypass)`, `pii_detector -> (pii_echo,)`, `tool_policy`, `llm_tool_filter -> (tool_abuse,)`, `toxicity_output`, `llm_output_filter -> (toxicity_elicitation,)`, `llm_input_filter -> (prompt_injection, toxicity_elicitation, encoding_bypass)`, `rate_limiter`, `pii_restorer`, `nemo_rails -> ()`.

### 6.3 Cost per request (the traffic join)
```
content_tokens = min(avg_tokens_for_stage, content_cap_chars/4 if cap else inf)   # input stage: avg_input_tokens; output stage: avg_output_tokens
tokens_in_per_request  = llm_calls_per_case * (prompt_overhead_tokens + content_tokens)   # when avg tokens given
                       = llm_calls_per_case * tokens_in_per_call                            # otherwise ("at corpus content length", stated)
tokens_out_per_request = llm_calls_per_case * tokens_out_per_call
usd_per_request = price_call(price, tokens_in_per_request, tokens_out_per_request)
usd_per_month   = usd_per_request * requests_per_day * 30
usd_basis       = usd_label(cost_basis, price, stale)   # "unavailable" when model not in table (row says "model <id> not in prices.yaml as_of <date>")
provenance      = "MEASURED <date>" if measure row present and (not llm_configured or llm_exercised)
                  "ESTIMATED <date>" if llm_configured and not llm_exercised and cost_basis == estimated
                  "UNMEASURED" otherwise
```

### 6.4 Recommendation (pure function `recommend(row, budgets, thresholds) -> (verdict, reasons, config_changes)`)
1. `kind != guard` -> `apply` with reason `"not a pipeline guard; aisg measure does not time it"` (listed under unmeasured too).
2. No measure row, or `llm_configured and not llm_exercised and the rule's control is the judge` (symbols `LLMToolFilter`, `LLMOutputFilter`, `LLMInputFilter`, or `prompt_injection` when the finding's rule is AUD-804) -> `unmeasured (run aisg measure first)`; hint `--allow-provider-calls` when `llm_configured`.
3. `over = []`: `p99_ms > budgets.p99_ms` -> `p99`; `usd_per_request > thresholds.max_usd_per_request` -> `usd/request`; `usd_per_month > budgets.monthly_usd` -> `usd/month`; `human_rate > thresholds.max_human_rate` or `requests_per_day*human_rate > capacity` -> `human`; report `threshold_failures` non-empty or `benign_broken_rate > Thresholds().max_false_positive_rate` -> `benign`. Unknown figures (`None`) never count as over; they are printed as `UNMEASURED`.
4. `over == []` -> `apply`.
5. Deterministic `config_changes` table:
   - `p99`/`usd*` and site `prompt_injection:inline` -> `"prompt_injection: llm_judge: false (re-measure: the report measured the judge path)"`; site `toxicity_output:inline` -> `use_llm_judge: false`.
   - `usd*` and an `LLM*Filter` -> `"wrap the judge: CachedJudge(judge, max_size=512, ttl=3600): saving scales with the repeat rate of your traffic, which this report does not know"`.
   - `p99` and `pipeline.parallel_checks == false` and a judge guard -> `"order the stage so regex guards (<names from the report>) run before <guard>: sequential mode short-circuits on the first BLOCK (core/pipeline.py:293)"`.
   - `benign` and `prompt_injection` -> `"sensitivity: low"` / `"allow_security_discussion: true"`; other guards -> `"action: flag"` (routes instead of rejecting).
   - `human` -> `"narrow require_approval to the irreversible tools, or raise human_review_capacity_per_day in the card"`.
   -> `apply with <change>` when any change applies, else `defer (over budget: <which>)`. Every `apply with` carries the reason `"the change is a hypothesis until aisg measure is re-run on the new config"`.

### 6.5 Totals
Selected = `--select` or rows whose verdict starts with `apply`. Latency: per stage, `parallel_checks` -> `max`, else `sum`; `processing` always `sum`; stages add. `p99` total is labelled `p99_ms_upper_bound` ("the sum of per-guard p99s bounds the pipeline p99; it is not the pipeline p99"). Cost sums; `human_per_day = requests_per_day * sum(human_rate)` (upper bound) vs capacity. Rows with any `None` in a summed figure are excluded and listed in `excluded_unmeasured`, printed in every format.

### 6.6 Renderers
Own `TEMPLATES` tuple of fixed strings and `check_templates()` scanning them against `report.BANNED_PHRASES` (import from `aisg.devtools.audit.report`); `--debug` turns a hit into exit 2 (mirror audit). Terminal: ASCII table (own `_table(header, rows)` modelled on `measure.render_table`), then totals block, then `UNMEASURED:` list, then the disclaimer and `"Month = 30 days. Prices as of <as_of>[, STALE]."`. Markdown: same table as a pipe table + the same three blocks, for PR bodies. JSON: section 2.6, `ensure_ascii=True`. Disclaimer text: "Figures are measured against the shipped corpora or estimated offline, as each row's label says, and compared with figures you declared. Not an assessment of compliance with any regulation."

## 7. `Thresholds` / `Profile` / `Budget` / pipeline opt-in

`core/measurement.py`:
- `Profile` += `tokens_in_per_call: int|None`, `tokens_out_per_call: int|None`, `usd_per_call: float|None`, `cost_basis: str|None`, `prices_as_of: str|None`, `human_rate: float|None`, `benign_modified_rate: float|None` (all default None; `as_source` tuple extended; `is_measured` also true when `usd_per_call` or `human_rate` is set).
- `Thresholds` += `max_usd_per_request: float|None = None`, `max_human_rate: float|None = None`. `failures()` adds `"usd/call {x:.4f} > {cap:.4f}"` only when `profile.cost_basis == "measured"` (D8) and `"human-routing rate {x:.3f} > {cap:.2f}"`. Unmeasured still cannot fail.
- `Budget(frozen)`: `requests_per_day, avg_input_tokens, avg_output_tokens, p99_ms, monthly_usd, max_usd_per_request, human_review_capacity_per_day, max_human_rate` (all `None`); `thresholds(base=DEFAULT_THRESHOLDS) -> Thresholds` with `max_p99_latency_ms=p99_ms`, `max_usd_per_request = max_usd_per_request or (monthly_usd / (requests_per_day*30) if both)`, `max_human_rate = max_human_rate or (capacity/requests_per_day if both)`; `Budget.from_card(dict)`, `Budget.merged(flags)`.

`core/pipeline.py` (bounded): `GuardrailPipeline(..., thresholds: Thresholds | None = None)`; in `__init__` compute `self.demoted = [(g.name, g.demotion_reasons(thresholds)) for g in all guards if thresholds and not g.fires_by_default(thresholds)]` and print one stderr line per demoted guard; `_run_stage` filters `enabled_guards` by `g.enabled and (thresholds is None or g.fires_by_default(thresholds))`. `from_config` reads `pipeline.thresholds: {min_precision, max_false_positive_rate, max_p99_latency_ms, max_usd_per_request, max_human_rate}`. Default `None` = today's behaviour; all shipped guards carry `Profile()`, so nothing demotes until a Profile is pasted from `aisg measure`.

## 8. Audit integration

- `discover._report_kind`: `body.get("kind") == "decision" and isinstance(body.get("controls"), list)` -> `"decision"` (checked before the measure test); `_REPORT_NAME_RE` -> `^(?:measure|probe|decision)[-_]?report.*\.json$`; `read_decision_report()` typed reader like `read_measure_report`. Not added to `_OWN_OUTPUT_KINDS`/walk `_OWN_KIND_RE` (D10).
- `report._report_entry`: kind `decision` -> `entry["controls"] = _decision_extract(body)` = `{control: {provenance, over_budget, recommendation.verdict}}` for rows with `over_budget` non-empty.
- `rules/guards.py`:
  - `GuardUnmeasured.evaluate`: after the existing groups, for each enabled wired guard present in a measure report with `llm_configured is True and llm_exercised is False` -> group `(unit, "cost", name)` emitting sub `cost` (display id `AUD-801/cost`), notes `"guard <name> wires an LLM judge; the measure report <file> did not exercise it (offline run): catch rate and tokens are estimates"`, `report=record.finding_report()`, `evidence_kind=REPORT`. Same package as the parent (`aisg measure`, `same_control=True`) by construction (`AuditRule.finding` copies the class recommendation; `test_sub_findings_inherit_the_parent_package` holds).
  - New `GuardReportedOverBudget` AUD-806 "Reported guard over the declared budget": `priority 8, severity HIGH, basis MEASURED, evidence_kind REPORT, match_kind STRUCTURED, tier T1, measured_precision None`, `controls = ("ASI01", "LLM10", "EU:Art.15", "NIST:MEASURE-2.7", "NIST:MANAGE-1.3")`, `related_lint_rules = ("ALIGN-004",)`, 4 `known_failure_modes` (budgets are the operator's declarations; estimates vs measured; stale prices; the report describes the config at decide time), `recommendation` with 3+ alternatives (one without "aisg"), `package=Package(mechanism="measurement", symbols=("aisg decide", "aisg measure"), same_control=False, leaves_open="The budgets come from the operator's card and traffic profile; the tool compares, it does not set them. A changed config needs a new measure run and a new decide run before the figures describe it.")`. `evaluate`: for each `ReportRecord(kind="decision")`, for each `controls[]` row with `over_budget`, one finding per (row, budget) with `sub` in `latency|cost|human|benign` mapped from `p99 -> latency`, `usd/* -> cost`, `human -> human`, `benign -> benign`; evidence `[Evidence("report", file, 0, f"{control}: {budget} {figure} > {cap}")]`, `report=record.finding_report()`, skipped when the control's guard is wired `enabled: false` (reuse `_guard_sites`). `RULES` appends it; `SUBSYSTEM_OF_RULE["AUD-806"] = "guardrails"`.
- `main.py`: `--decision PATH` (default None; html only; validated `schema aisg/1` + `kind decision`, else exit 2 `_DECISION_REFUSED`). `html.py`: `_numbering(doc2, ran_any, trade)` inserts `"trade"` after `"plan"`; `_trade_table(decision, numbers)` renders `_T_TRADE = "Trade table"`, headers `("control", "rules", "catch", "benign broken", "human", "p50/p99 ms", "tokens in/out", "usd/request", "usd/month", "fail mode", "provenance", "recommendation")`, totals paragraph, `UNMEASURED` list, caption `_T_TRADE_FROM = "from {file}, generated {generated_at}; prices as of {as_of}{stale}; the decision JSON is authoritative"`; all strings added to `TEMPLATES`. Without `--decision` the page is byte-identical to today (numbering unchanged).
- `cli.COMMANDS["decide"]` satisfies `test_package_symbols_are_only_verbs_or_class_names` for the new verb.
- `controls.md`: add the `### AUD-806 Reported guard over the declared budget (high)` section by hand (the generator rewrites only severity/Mapping/Leaves open of existing sections), then `python scripts/controls_md.py` and `python scripts/sync_skill.py`.

## 9. Tests

### New files
`tests/unit/test_prices.py`
- `test_packaged_prices_load_and_have_schema_kind_as_of_sources` (schema first key, kind `prices`, `as_of` parses, `sources` non-empty, every model has `provider`, and either both `*_usd_per_mtok` or `free`/`local`)
- `test_repo_and_packaged_prices_agree` (`config/prices.yaml` == `preset_path("prices.yaml")`)
- `test_default_judge_model_ids_are_priced` (ids from `claude_judge`, `llm_judges.build_judge`, `llamaguard._DEFAULT_MODELS`, `openai_mod`, `PromptInjectionGuard().llm_judge_model`, `ToxicityFilter().llm_judge_model`)
- `test_stale_after_days_labels_stale`, `test_fresh_table_is_not_stale` (frozen `today`)
- `test_override_order_flag_env_pyproject_packaged` (monkeypatch `AISG_PRICES`, tmp pyproject with `[tool.aisg-decide] prices`)
- `test_price_call_free_and_local_are_zero`, `test_price_call_unknown_tokens_is_none`, `test_wrong_schema_or_kind_raises_prices_error`, `test_no_network_import` (no `socket`/`urllib` use: grep source)

`tests/unit/test_estimate.py`
- `test_estimate_tokens_is_chars_over_four_ceil_and_deterministic`
- `test_every_site_is_labelled_estimated`
- `test_llamaguard_estimate_includes_the_safety_policy` (>= `estimate_tokens(_SAFETY_POLICY)`)
- `test_prompt_injection_estimate_uses_the_hoisted_constant_and_cap` (content of 10,000 chars -> capped at 2000)
- `test_claude_general_history_window_is_six_messages_of_500_chars`
- `test_site_for_unwraps_cached_judge`, `test_site_for_regex_only_guard_is_none`, `test_nemo_site_is_unavailable`
- `test_import_pulls_no_provider_sdk` (`anthropic`/`aiohttp` not newly imported)

`tests/unit/test_decide.py` (fixtures in `tests/fixtures/decide/`; all run from a `neutral_cwd` tmp dir like `test_audit_cli.py:74`)
- `test_json_first_two_keys_are_schema_and_kind`, `test_json_key_order_is_pinned` (top level and a row)
- `test_rows_derive_from_package_symbols_one_per_symbol` (fixture audit report: AUD-302 PromptInjectionGuard, AUD-804 LLMJudgeBase, AUD-201 ToolPolicyGuard, AUD-702 AuditLogger, AUD-801 `aisg measure`)
- `test_symbol_guard_names_match_the_registry` (every `_GUARD_CLASSES` item: `REGISTRY[name].__name__ == klass`; and every `CLASS_SYMBOLS` entry resolves to a guard or `NON_GUARD_SYMBOLS`)
- `test_guard_families_are_registry_names_and_corpus_families`
- `test_measured_row_shows_measured_date_and_numbers`, `test_estimated_row_labels_cost_est`
- `test_unmeasured_without_measure_report` (every guard row `UNMEASURED`, verdict `unmeasured (run aisg measure first)`, exit 0)
- `test_judge_not_exercised_is_unmeasured_not_zero` (`llm_exercised: false` -> no `0%`)
- `test_over_p99_budget_defers_or_suggests_change_and_exits_1`, `test_monthly_budget_uses_30_days`, `test_human_capacity_check`
- `test_recommendation_is_deterministic` (same inputs twice -> identical JSON minus `generated_at`)
- `test_config_change_for_inline_judge_is_llm_judge_false`, `test_sequential_pipeline_suggests_ordering`, `test_parallel_totals_take_max_sequential_sum`
- `test_unmeasured_rows_are_excluded_from_totals_and_listed`
- `test_model_not_in_price_table_is_unavailable_and_named`, `test_stale_prices_mark_every_usd_cell`
- `test_card_traffic_and_budgets_are_read_and_flags_win`
- `test_missing_audit_report_exits_2_with_hint`, `test_bad_schema_exits_2`
- `test_terminal_and_markdown_are_ascii`, `test_no_banned_phrase_in_decide_source_or_templates` (reuse `BANNED_PHRASES`; `check_templates()` empty), `test_disclaimer_present_in_every_format`
- `test_not_configurable_excludes_select`, `test_pyproject_prices_default_is_honoured`
- `test_registered_in_cli_and_epilog`

### Modified test files
- `test_measure.py`: update `test_existing_keys_keep_their_order` (filter list adds `measured_on`, `pipeline`); add `test_measured_on_is_in_the_json_and_names_the_mode`, `test_offline_is_default_and_makes_no_provider_call` (a guard whose judge raises on any call measures with no error), `test_judge_guard_offline_has_estimated_tokens_and_is_not_exercised`, `test_prompt_injection_calls_per_case_is_the_allow_fraction`, `test_allow_provider_calls_reads_measured_usage` (mocked judge returning `usage` measured), `test_cached_judge_is_cleared_between_passes`, `test_human_rate_and_fail_mode`, `test_benign_modified_rate_beside_fpr`, `test_policy_guards_only_with_include_policy_and_stage_is_set`, `test_pipeline_block_reflects_config`, `test_per_guard_new_keys_follow_errors`.
- `test_judges.py`: usage recorded for Claude (mock with int usage), for OpenAI-compatible (`usage` dict), Ollama (`prompt_eval_count`), HF unavailable, moderation unavailable; MagicMock usage -> `unavailable` not a mock; `CachedJudge` hit -> `cache_hit True, calls 0, basis none` and `reason` preserved; `timeout` passed to `AsyncAnthropic`.
- `test_guardrails.py`/filter tests: `llm_usage` present in `metadata` on all paths; `guard_name` set by `__call__`; prompt_injection with `llm_judge=True` and regex hit -> `calls 0`; judge exception -> `judge_error` + `unavailable`.
- `test_otel.py`: `test_token_instruments_registered`, `test_tokens_recorded_with_direction_attrs`, `test_cache_hit_counts_call_zero`; `_make_otel_test_provider` adds the three `None` slots.
- `test_improvements.py` (AuditLogger): `test_checks_run_guard_is_the_guard_name_not_the_check_id`, `test_record_totals_tokens`.
- `test_system_card.py`: `test_traffic_and_budgets_blocks_render_null_by_default`, `test_numbers_round_trip`, `test_caveat_still_above_risk_tier`, interactive prompt test for one number.
- `test_cli.py`: `EXPECTED_COMMANDS` += `"decide"`, `PROG_BY_COMMAND["decide"] = "aisg decide"`.
- `test_audit_rules_registry.py`: `EXPECTED_IDS` range `801..806`.
- `test_audit_rules_guards.py`: `test_rules_list_is_ordered_and_complete` adds AUD-806; new `test_806_fires_per_over_budget_row_with_report_age`, `test_806_silent_without_a_decision_report`, `test_806_skips_a_guard_disabled_in_the_preset`, `test_801_cost_sub_finding_when_judge_not_exercised`, `test_801_cost_silent_when_exercised_or_no_judge`; `test_empty_context_yields_nothing` covers 806 via parametrize.
- `test_audit_discover.py`: `test_decision_report_is_read_with_kind_decision`, `test_decision_report_yields_no_guardrail_entries` (mirror of `test_reports_are_not_eval_entries`).
- `test_audit_html.py`: `test_trade_table_only_with_decision_flag_and_numbering_shifts`, `test_page_without_decision_is_unchanged`, `test_trade_table_names_the_decision_file_and_price_date`.
- `test_audit_cli.py`: `--decision` with a non-decision file exits 2.
- `test_skill_package.py`: `SKILL_MD_NEEDLES` += `"aisg decide"`, `REPORT_FORMAT_NEEDLES` += `"decision"`; `controls.md` coverage test picks AUD-806 up automatically.

## 10. Docs

- `README.md`: new `### aisg decide -- what each control costs, and whether it fits the budget` after the measure section (inputs, the traffic flags, the three labels, exit codes, "prices.yaml is a file you keep current; `as_of` is printed on every figure"); measure section gains `--allow-provider-calls`/`--include-policy`; "Metrics emitted" table gains the three instruments; Audit logging snippet shows `checks_run[].guard` as a name and the token keys.
- `CLAUDE.md`: in "Measurement" add: offline default and `--allow-provider-calls`; `llm_exercised: false` means UNMEASURED catch rate, never 0; `measured_on` in the JSON; `benign_modified_rate` beside the ratchet's FPR; policy guards behind `--include-policy`. New section "`aisg decide`": the four `cost_basis` values; tokens in the runtime, dollars only offline; prices file with `as_of`/staleness and never fetched; the decision JSON is a report, not own-output; `--decision` adds the Trade table to the html; `NOT_CONFIGURABLE = {"select"}`; `Budget` vs `Thresholds` split and D8. Update the rule count / AUD-806 / the card's fields line ("...`incident_contact`, and the optional `traffic`/`budgets` blocks `aisg decide` reads"). Add the `CachedJudge` timing-pass note.
- Skill: `SKILL.md` phase 5 gains an optional step after measure: `aisg decide --format markdown -o .aisg-audit/decision.md` and `--format json -o .aisg-audit/decision-report.json`, then `--format html --decision` for document 2 ("with approval; needs the traffic figures from the card"); `references/report-format.md` new section "The decision document (`kind: decision`)" with the key order and labels; `references/apply/python.md` new `## aisg decide (AUD-806; phase 5 only)` with the config-change idioms the recommendation names (`llm_judge: false`, `use_llm_judge: false`, `CachedJudge(...)`, stage ordering under `parallel_checks: false`, `sensitivity: low`, `action: flag`, `GuardrailPipeline(thresholds=...)`), and `## GuardrailPipeline` gains the `thresholds=` line; `controls.md` AUD-806 section; `python scripts/sync_skill.py`. (The consolidated plan moves decide to its own phase 3; the phase-5 placement here is superseded.)
- `docs/explain/measurement-first-guardrails.html`: one paragraph in section 6 ("What comes next") pointing at `aisg decide` as the consumer of the measure report; a full explain doc is a follow-up via the `explain-doc` skill.

## 11. Ordered implementation steps (with dependencies)

1. `core/measurement.py`: `COST_BASIS`, `LLMUsage`, `weakest_basis`, `Budget`, Profile/Thresholds fields, docstring fix. Tests in `test_measure.py::TestProfile`.
2. `llm_judges/base.py` readers + `JudgeVerdict.usage`; `claude_judge`/`llamaguard`/`openai_mod`/`cache` record usage. Tests. Depends on 1.
3. `core/base.py` `guard_name` + `PipelineResult.llm_usage`; filters, `prompt_injection` (hoist constants), `toxicity` (hoist + `llm_judge_model`), `nemo_rails`. Tests. Depends on 1-2.
4. `otel.py` + `audit_logger.py`. Tests. Depends on 3.
5. `estimate.py`. Tests. Depends on 3 (hoisted constants).
6. `prices.yaml` + mirror + `prices.py` + `aisg.config.PRICES_FILE`. Tests. Independent of 2-5.
7. `measure.py` extension; update the pinned key-order test; run `aisg measure` locally to confirm the ratchet still exits 0 on `default.yaml`. Depends on 3, 5.
8. `system_card.py` blocks. Tests. Independent.
9. `decide.py`, `cli.py`, `pyproject [tool.aisg-decide]`, fixtures. Tests. Depends on 1, 5, 6, 7 (shape), 8.
10. Audit: `discover`/`report` decision kind, AUD-806 + AUD-801/cost, `SUBSYSTEM_OF_RULE`, `--decision` + html section, `controls.md` section, `controls_md.py`, `sync_skill.py`. Tests. Depends on 9 (decision shape).
11. `pipeline.py` `thresholds=` opt-in. Tests. Depends on 1.
12. Docs (README, CLAUDE.md, skill refs, explain mention). Depends on 9-11.
13. Verify gate: `pytest`, `ruff check`/`format` on changed files, `aisg lint src examples`, `aisg misalign src`, `aisg audit . --no-external --fail-on high --baseline audit-baseline.json` (the hoisted judge prompts and `prices.yaml` may surface new AUD findings; check and baseline with a reason if needed), `python scripts/controls_md.py --check`, `python scripts/sync_skill.py --check`.

## 12. Pinned tests that must change
- `tests/unit/test_measure.py::TestReportProvenance::test_existing_keys_keep_their_order` (add `measured_on`, `pipeline` to the filtered list).
- `tests/unit/test_cli.py::EXPECTED_COMMANDS` / `PROG_BY_COMMAND` (add `decide`).
- `tests/unit/test_audit_rules_registry.py::EXPECTED_IDS` (`range(801, 807)`).
- `tests/unit/test_audit_rules_guards.py::test_rules_list_is_ordered_and_complete` (AUD-806).
- `tests/unit/test_skill_package.py::SKILL_MD_NEEDLES` / `REPORT_FORMAT_NEEDLES` (add the decide vocabulary), additive.
- `tests/unit/test_otel.py::_make_otel_test_provider` (three new `None` slots; optional but keeps the helper honest).
- `tests/unit/test_audit_discover.py::test_own_output_is_neither_a_report_nor_an_unknown` is not changed (decision is a report, D10); add the two new discover tests instead.
Unchanged and relied upon: `list(report)[:2] == ["schema","generated_at"]` (measure), `REPORT_KEYS` (audit JSON gets no new key), `test_document_two_sections_only_with_a_baseline` (numbering shifts only with `--decision`), `test_renders_valid_yaml` (`deployment` scalar untouched).

## 13. Risks and open questions
1. Price figures must be copied by hand from the provider pages with the date; the plan deliberately gives none. If the engineer cannot verify a provider, leave the entry out: an absent model renders `unavailable` and names itself, which is honest; a guessed figure is not.
2. MagicMock usage in existing tests: covered by `_int_or_none`; any reader that does `response.usage.input_tokens` without the guard would record mocks.
3. Offline default changes `eu_high_risk.yaml` measurement (judge guards no longer attempt calls): strictly faster and labelled; CI measures `default.yaml` (no judges) so the ratchet is unaffected.
4. `CachedJudge` + timing passes: without `clear()` between passes the median latency and tokens describe the cache. Handled in step 7; note printed.
5. Decision JSON scanned by the walker: the file contains guard class names; verify with `test_decision_report_yields_no_guardrail_entries` that `GUARDRAIL_LIBS` does not produce `guardrails[]` entries from JSON (the measure fixture already shows reports are not eval entries, so this is expected to hold).
6. `human_rate` is ~0 in measurement because `ToolPolicyGuard` auto-approves without a callback; the per-guard `notes` say so and `decide` prints it rather than a reassuring 0.
7. NeMo usage depends on `rails.explain()` availability across nemoguardrails versions; wrapped in try/except -> `unavailable`.
8. Self-audit: `prices.yaml` carries model ids and URLs; `AUD-601` (floating model id) should not fire on pinned ids, but run the gate and baseline with a reason if a rule does.
9. Open: should `decide` also accept a config YAML to estimate a not-yet-measured config entirely offline (latency unknown, tokens estimated)? Proposed answer: no in this change; a row without a measure report is `UNMEASURED`, and the hint is to run `aisg measure`; estimating latency would invent a figure.
10. Open: `toxicity_output` gains `llm_judge_model`; the four presets need no edit (default keeps today's id), but `eu_high_risk.yaml` has `use_llm_judge: true` and will now show `ESTIMATED` cost rows, which is desirable.

## 14. Size estimate
Source: ~2,600 lines (decide 900, measure +200, prices 220 + yaml 2x70, estimate 170, audit +380 across discover/report/guards/html/main, runtime +330 across measurement/base/pipeline/judges/filters/nemo/otel/logger, system_card +60, cli/pyproject +15). Tests: ~1,800 lines, roughly 150-170 new test functions plus 8 edits. Docs/skill: ~300 lines.

Critical files: `src/aisg/devtools/measure.py`, `src/aisg/core/measurement.py`, `src/aisg/modules/llm_judges/base.py`, `src/aisg/devtools/audit/rules/guards.py`, `src/aisg/devtools/audit/html.py`. New: `src/aisg/devtools/decide.py`, `src/aisg/devtools/prices.py`, `src/aisg/modules/llm_judges/estimate.py`, `src/aisg/config/prices.yaml` + `config/prices.yaml`.
