# AI Safety Guardrails

> Production-ready, modular AI safety guardrails for any LLM-powered application.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![EU AI Act Ready](https://img.shields.io/badge/EU%20AI%20Act-2024%2F1689-green.svg)](#eu-ai-act-compliance)
[![NIST AI RMF](https://img.shields.io/badge/NIST-AI%20RMF%201.0-blue.svg)](#nist-ai-rmf-compliance)

---

## Overview

This library provides a layered, async-first guardrail system that slots into any LLM pipeline. Every check runs at the right moment:

```
User Input
    │
    ▼
[INPUT GUARDRAILS]          ← PII detection, prompt injection, LLM judge
    │
    ▼
LLM + Tool Calls
    │
    ▼
[PROCESSING GUARDRAILS]     ← Tool policies, indirect injection detection
    │
    ▼
LLM Response
    │
    ▼
[OUTPUT GUARDRAILS]         ← Toxicity filter, LLM judge on responses
    │
    ▼
[POLICY GUARDRAILS]         ← EU AI Act, NIST AI RMF, NeMo Rails
    │
    ▼
Safe Response to User
```

**What's implemented today:**

| Layer | Module | What it does |
|---|---|---|
| Input | `PIIDetector` | Detects & redacts emails, phones, SSNs, credit cards, IPs |
| Input | `PromptInjectionGuard` | Blocks jailbreaks, system-prompt extraction, encoded payloads |
| Input | `LLMInputFilter` | LlamaGuard / OpenAI Mod / Claude judge on user messages |
| Processing | `ToolPolicyGuard` | Allow/deny tool calls by user role |
| Processing | `LLMToolFilter` | LLM judge on tool arguments and returned results (indirect injection) |
| Output | `ToxicityFilter` | Pattern + optional API-based output toxicity detection |
| Output | `LLMOutputFilter` | LLM judge on model responses before they reach the user |
| Policy | `EUAIActCompliance` | Regulation (EU) 2024/1689 — Art. 5, 9, 12, 13, 14, 15, 50 |
| Policy | `NISTAIRMFCompliance` | NIST AI RMF 1.0 — GOVERN, MAP, MEASURE, MANAGE functions |
| Policy | `NemoRailsGuard` | NVIDIA NeMo Guardrails dialog-level safety at policy stage |
| Observability | `AuditLogger` | Structured JSONL audit trail for every pipeline run |

---

## Repository Structure

```
ai-safety-guardrails/
│
├── core/
│   ├── base.py                  # GuardrailBase, CheckResult, PipelineResult, Severity, Action
│   ├── pipeline.py              # GuardrailPipeline — async orchestrator
│   ├── exceptions.py            # GuardrailBlockedError, GuardrailConfigError, PolicyViolationError
│   └── registry.py              # REGISTRY dict + @register_guard decorator
│
├── modules/
│   ├── input/
│   │   ├── pii_detector.py
│   │   ├── prompt_injection.py
│   │   ├── advanced_injection_detectors.py   # Unicode bypass, encoding, token smuggling
│   │   └── llm_input_filter.py
│   │
│   ├── processing/
│   │   ├── tool_policy.py
│   │   └── llm_tool_filter.py
│   │
│   ├── output/
│   │   ├── toxicity.py
│   │   └── llm_output_filter.py
│   │
│   ├── policy/
│   │   ├── eu_ai_act.py
│   │   ├── nist_ai_rmf.py
│   │   └── code_analyzer/       # Static EU AI Act linter (used by devtools)
│   │
│   ├── llm_judges/
│   │   ├── base.py              # LLMJudgeBase, JudgeVerdict, category_to_severity()
│   │   ├── llamaguard.py        # LlamaGuard 3 — Groq / Together / Ollama / HuggingFace
│   │   ├── openai_mod.py        # OpenAI Moderation API
│   │   └── claude_judge.py      # Claude safety judge (injection / toxicity / general)
│   │
│   ├── analysis/
│   │   └── data_flow_analyzer.py
│   │
│   └── observability/
│       └── audit_logger.py
│
├── integrations/
│   ├── fastapi_middleware.py    # Starlette/FastAPI middleware
│   ├── anthropic_middleware.py  # Drop-in Anthropic client wrapper
│   ├── langchain_callback.py    # LangChain callback handler
│   └── nemo_rails.py            # NVIDIA NeMo Guardrails (guard + middleware)
│
├── config/
│   ├── settings.py              # Pydantic Settings — reads .env file
│   ├── default.yaml             # Default pipeline config
│   ├── eu_high_risk.yaml        # Strict config for EU high-risk systems
│   └── nemo_rails/
│       ├── config.yml           # NeMo model + rail declarations
│       └── rails.co             # Colang dialog flows
│
├── devtools/
│   ├── euaiact_lint.py          # CLI: static EU AI Act compliance linter
│   └── misalignment_check.py    # CLI: AI alignment static analysis
│
├── tests/
│   ├── test_advanced_injection.py
│   └── unit/
│       ├── test_guardrails.py
│       ├── test_nemo_rails.py
│       ├── test_nist_ai_rmf.py
│       └── test_settings.py
│
├── .env.example                 # All environment variables documented
├── pyproject.toml
└── README.md
```

---

## Installation

**Minimum (core + YAML config, no external deps):**
```bash
pip install pyyaml aiohttp
```

**Recommended for most projects:**
```bash
pip install pyyaml aiohttp pydantic-settings
```

**Install optional extras as needed:**
```bash
# LLM judge providers
pip install "ai-safety-guardrails[settings]"      # .env file support (pydantic-settings)
pip install "ai-safety-guardrails[anthropic]"     # Claude judge
pip install "ai-safety-guardrails[llamaguard]"    # LlamaGuard local (HuggingFace)

# Integrations
pip install "ai-safety-guardrails[fastapi]"       # FastAPI middleware
pip install "ai-safety-guardrails[langchain]"     # LangChain callback
pip install "ai-safety-guardrails[nemo]"          # NVIDIA NeMo Guardrails

# Observability
pip install "ai-safety-guardrails[otel]"          # OpenTelemetry
pip install "ai-safety-guardrails[metrics]"       # Prometheus

# Everything
pip install "ai-safety-guardrails[all]"
```

> **Note:** LlamaGuard via Groq or Together AI only needs `aiohttp` (already a core dep) — no extra package required. Only local HuggingFace inference needs the `llamaguard` extra.

---

## Quick Start

### 1. Basic pipeline (no API keys needed)

```python
import asyncio
from core.pipeline import GuardrailPipeline
from modules.input.pii_detector import PIIDetector
from modules.input.prompt_injection import PromptInjectionGuard
from modules.output.toxicity import ToxicityFilter
from modules.policy.eu_ai_act import EUAIActCompliance

pipeline = GuardrailPipeline(
    input_guards=[
        PIIDetector(action="redact"),
        PromptInjectionGuard(sensitivity="medium"),
    ],
    output_guards=[
        ToxicityFilter(threshold=0.7),
    ],
    policy_guards=[
        EUAIActCompliance(risk_tier="limited"),
    ],
)

async def handle_request(user_message: str) -> str:
    # Check input
    input_result = await pipeline.run_input(user_message)
    if input_result.blocked:
        return input_result.rejection_message

    # Call your LLM with the sanitized input
    llm_response = await your_llm(input_result.sanitized_output)

    # Check output
    output_result = await pipeline.run_output(llm_response)
    return output_result.sanitized_output
```

### 2. Load pipeline from YAML config

```python
from core.pipeline import GuardrailPipeline

pipeline = GuardrailPipeline.from_config("config/default.yaml")
```

See `config/default.yaml` for all available options.

### 3. Full pipeline in one call

```python
async def my_llm(prompt: str) -> str:
    # your LLM call here
    return response

result = await pipeline.run_full(
    user_input=user_message,
    llm_callable=my_llm,
    context={"user_id": "u42", "session_id": "s1"},
)
print(result.sanitized_output)
```

`run_full` raises `GuardrailBlockedError` if input or output is blocked.

---

## LLM Judges

LLM judges add a second layer of semantic safety on top of pattern-based checks. Three judges are available and share a common interface.

### Available judges

| Judge | Class | Providers | Best for |
|---|---|---|---|
| LlamaGuard 3 | `LlamaGuardJudge` | Groq, Together, Ollama, OpenAI-compat, HuggingFace | General safety, 13 harm categories |
| OpenAI Moderation | `OpenAIModerationJudge` | OpenAI (free endpoint) | Fast output moderation |
| Claude | `ClaudeJudge` | Anthropic | Injection detection, nuanced toxicity |

### Using a judge directly

```python
from modules.llm_judges import build_judge

# LlamaGuard 3 via Groq (fastest, ~100 ms)
judge = build_judge(
    judge_type="llamaguard",
    judge_provider="groq",
    api_key="gsk_...",
)

verdict = await judge.judge("Is this safe content?")
print(verdict.safe)           # True / False
print(verdict.categories)     # e.g. ["S1", "S9"]
print(verdict.latency_ms)

# Quick boolean check
safe = await judge.is_safe("Hello, how are you?")
```

### LlamaGuard via Ollama (no API key)

```bash
ollama pull llama-guard3
```

```python
judge = build_judge(
    judge_type="llamaguard",
    judge_provider="ollama",   # uses http://localhost:11434 by default
)
```

### Injecting a judge into a pipeline guard

```python
from modules.llm_judges import build_judge
from modules.input.llm_input_filter import LLMInputFilter
from modules.output.llm_output_filter import LLMOutputFilter

judge = build_judge(judge_type="llamaguard", judge_provider="groq", api_key="gsk_...")

pipeline = GuardrailPipeline(
    input_guards=[LLMInputFilter(judge=judge)],
    output_guards=[LLMOutputFilter(judge=judge)],
)
```

Or pass judge config directly (no pre-built judge object needed):

```python
LLMInputFilter(
    judge_type="llamaguard",
    judge_provider="groq",
    judge_api_key="gsk_...",
    block_on_unsafe=True,
)
```

### LLMToolFilter — indirect injection detection

```python
from modules.processing.llm_tool_filter import LLMToolFilter

# Checks tool arguments before execution
tool_filter = LLMToolFilter(judge=judge, scan_tool_arguments=True)

# Checks tool results before feeding back to LLM
tool_filter = LLMToolFilter(judge=judge, scan_tool_results=True)

pipeline = GuardrailPipeline(processing_guards=[tool_filter])

# Pass tool result in context
result = await pipeline.run_processing(
    content="tool output text",
    context={"tool_result": "fetched web content here"},
)
```

---

## Environment Variables & Settings

Copy `.env.example` to `.env` and fill in your keys:

```bash
cp .env.example .env
```

Key variables:

```bash
# Environment
GUARDRAILS_ENV=development          # development | staging | production | test
GUARDRAILS_FAIL_OPEN=false          # never true in production
GUARDRAILS_LOG_LEVEL=INFO

# API keys (only needed for the providers you use)
GROQ_API_KEY=gsk_...
ANTHROPIC_API_KEY=sk-ant-...
TOGETHER_API_KEY=...
OPENAI_API_KEY=sk-...

# Default judge
DEFAULT_JUDGE_TYPE=llamaguard       # llamaguard | openai_mod | claude
DEFAULT_JUDGE_PROVIDER=groq         # groq | together | ollama | openai | huggingface
DEFAULT_JUDGE_TIMEOUT=10.0

# EU AI Act
EU_AI_ACT_RISK_TIER=limited
EU_AI_ACT_SYSTEM_ID=my-ai-system

# NIST AI RMF
NIST_IMPACT_LEVEL=moderate
```

### Using settings in code

```python
from config.settings import settings

print(settings.groq_api_key)
print(settings.is_production)       # True / False

# Build a judge directly from settings
from modules.llm_judges import build_judge
judge = build_judge(**settings.judge_kwargs())
```

---

## Policy Compliance

### EU AI Act (Regulation 2024/1689)

```python
from modules.policy.eu_ai_act import EUAIActCompliance, RiskTier

eu_guard = EUAIActCompliance(
    risk_tier=RiskTier.HIGH,
    system_id="my-ai-system-v1",
    provider_name="Acme Corp",
    enable_audit_log=True,                    # Article 12 — tamper-evident log
    human_oversight_callback=notify_team,     # Article 14 — human-in-the-loop
    check_prohibited=True,                    # Article 5 — unacceptable risk uses
    strict_mode=True,
)
```

**Checks performed automatically:**

| Article | Check |
|---|---|
| Art. 5 | Blocks social scoring, real-time biometric surveillance, subliminal manipulation |
| Art. 9 | Risk management hooks |
| Art. 12 | Tamper-evident JSONL audit log |
| Art. 13 | Transparency — AI disclosure enforcement |
| Art. 14 | Human oversight gate for high-severity findings |
| Art. 15 | Accuracy and robustness metric collection |
| Art. 50 | Synthetic content and AI-generated labelling |

### NIST AI RMF 1.0

```python
from modules.policy.nist_ai_rmf import NISTAIRMFCompliance, ImpactLevel

nist_guard = NISTAIRMFCompliance(
    impact_level=ImpactLevel.HIGH,
    system_name="my-ai-system",
    operator_name="Acme Corp",
    enable_audit_log=True,
    human_oversight_callback=notify_team,
    check_deception=True,       # GOVERN 1 — AI transparency
    check_high_harm=True,       # MAP 1 — high-harm domain detection
    check_bias=True,            # MEASURE 2 — bias & fairness
    check_opacity=True,         # MANAGE 1 — explainability
)
```

**Checks performed:**

| RMF Function | Check |
|---|---|
| GOVERN 1 | Blocks AI impersonation and deception |
| MAP 1 | Flags high-harm domains: medical, legal, financial, criminal justice, critical infrastructure |
| MEASURE 2 | Flags use of protected attributes and disparate impact patterns |
| MANAGE 1 | Flags fully automated high-stakes decisions without human review |
| MANAGE 2.4 | Structured monitoring log (JSONL) |

---

## NVIDIA NeMo Guardrails

Two integration modes are available.

### Mode 1: NemoRailsGuard (NeMo as a policy guard)

Add NeMo as a guard inside your existing `GuardrailPipeline`:

```python
from nemoguardrails import LLMRails, RailsConfig
from integrations.nemo_rails import NemoRailsGuard

rails_cfg = RailsConfig.from_path("config/nemo_rails")
rails = LLMRails(rails_cfg)

pipeline = GuardrailPipeline(
    input_guards=[PIIDetector(), PromptInjectionGuard()],
    policy_guards=[NemoRailsGuard(rails=rails, block_on_refuse=True)],
)
```

Or load from a config path lazily:

```python
NemoRailsGuard(rails_config_path="config/nemo_rails", fail_open=True)
```

### Mode 2: NemoRailsMiddleware (NeMo as the LLM)

Use NeMo as the LLM callable, with your pipeline handling input/output guardrails around it:

```python
from integrations.nemo_rails import NemoRailsMiddleware

middleware = NemoRailsMiddleware(
    pipeline=pipeline,
    rails_config_path="config/nemo_rails",
    fail_open=True,
)

result = await middleware.generate(
    user_input="Hello, what can you help me with?",
    context={"user_id": "u42"},
    conversation_history=[
        {"role": "user", "content": "previous message"},
        {"role": "assistant", "content": "previous reply"},
    ],
)

if result.blocked:
    print(result.rejection_message)
else:
    print(result.sanitized_output)
```

### Customising the Colang flows

Edit `config/nemo_rails/rails.co` to define your own dialog rails. The file ships with ready-made flows for jailbreak detection, off-topic blocking, harmful content, AI identity transparency, and output toxicity. See the [NeMo Guardrails docs](https://docs.nvidia.com/nemo/guardrails/) for the full Colang reference.

---

## Integrations

### FastAPI middleware

```python
from fastapi import FastAPI
from integrations.fastapi_middleware import FastAPIGuardrailMiddleware

app = FastAPI()
app.add_middleware(
    FastAPIGuardrailMiddleware,
    pipeline=pipeline,
    input_body_key="message",    # JSON key containing user input
    output_body_key="response",  # JSON key containing LLM response
)
```

The middleware automatically skips `/health`, `/ready`, `/metrics`, and `/docs`.

### Anthropic middleware

```python
from integrations.anthropic_middleware import AnthropicGuardrailMiddleware
import anthropic

client = anthropic.Anthropic(api_key="sk-ant-...")
middleware = AnthropicGuardrailMiddleware(client=client, pipeline=pipeline)

response = await middleware.messages.create(
    model="claude-opus-4-6",
    max_tokens=1024,
    messages=[{"role": "user", "content": user_message}],
)
```

### LangChain callback

```python
from integrations.langchain_callback import LangChainGuardrailCallback
from langchain_openai import ChatOpenAI

callback = LangChainGuardrailCallback(pipeline=pipeline)
llm = ChatOpenAI(callbacks=[callback])
```

---

## DevTools

Two CLI tools ship with the library for pre-commit and CI use.

### euaiact-lint — static EU AI Act compliance linter

Scans Python source files for EU AI Act compliance issues without running any code:

```bash
# Scan a directory
python devtools/euaiact_lint.py modules/

# List all rules
python devtools/euaiact_lint.py --list-rules

# SARIF output for GitHub Code Scanning
python devtools/euaiact_lint.py src/ --format sarif --output results.sarif

# Errors only (non-zero exit on Art. 5 / security violations)
python devtools/euaiact_lint.py src/ --errors-only
```

### misalignment-check — AI alignment static analysis

Scans for alignment anti-patterns: deceptive system prompts, missing human oversight hooks, goal misspecification:

```bash
python devtools/misalignment_check.py modules/

# Strict mode (non-zero exit on any warning)
python devtools/misalignment_check.py src/ --fail-on-warnings
```

### Pre-commit hooks

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: euaiact-lint
        name: EU AI Act compliance lint
        entry: python devtools/euaiact_lint.py
        args: [--errors-only]
        language: python
        types: [python]

      - id: misalignment-check
        name: AI alignment check
        entry: python devtools/misalignment_check.py
        language: python
        types: [python]
```

---

## Observability

### Audit logging

```python
from modules.observability.audit_logger import AuditLogger

logger = AuditLogger(log_path="audit/pipeline.jsonl")
pipeline = GuardrailPipeline(..., audit_logger=logger)
```

Each pipeline run writes a structured JSON record with stage, latency, findings, action taken, and a run ID for correlation.

### OpenTelemetry

Set `OTEL_EXPORTER_OTLP_ENDPOINT` in your `.env` to enable automatic trace export to Jaeger, Grafana Tempo, or any OTLP-compatible backend.

### Prometheus

```bash
PROMETHEUS_ENABLED=true
PROMETHEUS_PORT=9090
```

---

## Writing a Custom Guard

Any class that extends `GuardrailBase` and implements `check()` is a valid guard:

```python
from core.base import GuardrailBase, GuardrailStage, CheckResult, Action, Severity, Finding
from core.registry import register_guard

@register_guard("my_guard")
class MyCustomGuard(GuardrailBase):
    name = "my_guard"
    stage = GuardrailStage.INPUT

    def setup(self, keyword: str = "forbidden", **kwargs):
        self.keyword = keyword

    async def check(self, content: str, context: dict) -> CheckResult:
        if self.keyword in content.lower():
            return CheckResult(
                passed=False,
                action=Action.BLOCK,
                findings=[
                    Finding(
                        guard_name=self.name,
                        severity=Severity.HIGH,
                        category="custom_block",
                        description=f"Keyword '{self.keyword}' detected.",
                    )
                ],
                rejection_message="Your request contains blocked content.",
            )
        return CheckResult(passed=True, action=Action.ALLOW)
```

Use it directly or load it from YAML once registered:

```python
pipeline = GuardrailPipeline(input_guards=[MyCustomGuard(keyword="drop table")])
```

```yaml
# config/default.yaml
input:
  my_guard:
    enabled: true
    keyword: "drop table"
```

---

## Running Tests

```bash
pip install pytest pytest-asyncio
pytest                        # run all 194 tests
pytest tests/unit/            # unit tests only
pytest -v -k "nemo"           # filter by name
```

Tests do not require any API keys. All LLM calls are mocked.

---

## License

MIT — see [LICENSE](LICENSE).
