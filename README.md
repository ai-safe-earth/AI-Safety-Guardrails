# 🛡️ AI Safety Guardrails

> Production-ready, modular AI safety guardrails for any LLM-powered application.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![EU AI Act Ready](https://img.shields.io/badge/EU%20AI%20Act-Ready-green.svg)](#policy-compliance)

## Overview

This repository provides a production-ready, framework-agnostic AI safety guardrail system you can plug into any LLM pipeline. Modules are organized around the **three critical intervention points**:

```
User Input → [INPUT GUARDRAILS] → LLM + Tools → [PROCESSING GUARDRAILS] → Response → [OUTPUT GUARDRAILS] → User
```

### Key Features

- 🔌 **Drop-in integration** — works with OpenAI, Anthropic, Bedrock, LangChain, LlamaIndex, and raw HTTP
- 🧩 **Modular by design** — use only what you need; every module is independently importable
- ⚖️ **EU AI Act compliance** — built-in policy module aligned with Regulation (EU) 2024/1689
- 🔍 **Full observability** — structured audit logging, metrics, and OpenTelemetry support
- ⚡ **Low latency** — async-first, supports parallel check execution and smart caching
- 🛠️ **Extensible** — add custom validators with a single class definition

---

## Module Architecture

```
ai-safety-guardrails/
│
├── core/                        # Core abstractions & pipeline engine
│   ├── base.py                  # GuardrailBase, CheckResult, Severity
│   ├── pipeline.py              # GuardrailPipeline — the main orchestrator
│   ├── exceptions.py            # GuardrailException hierarchy
│   └── registry.py              # Dynamic module registry
│
├── modules/
│   ├── input/                   # ① INPUT GUARDRAILS (pre-LLM)
│   │   ├── pii_detector.py      # PII detection & redaction
│   │   ├── prompt_injection.py  # Injection & jailbreak detection
│   │   ├── topic_classifier.py  # Off-topic / relevance filter
│   │   ├── toxicity.py          # Hate speech, harassment, violence
│   │   └── rate_limiter.py      # Per-user/org rate limiting
│   │
│   ├── processing/              # ② PROCESSING GUARDRAILS (tool & context control)
│   │   ├── tool_policy.py       # Tool allow/deny policies per role
│   │   ├── context_control.py   # RAG result filtering & scoping
│   │   ├── iam_binding.py       # Identity-aware least-privilege enforcement
│   │   └── memory_hygiene.py    # Long-term memory TTL & scope controls
│   │
│   ├── output/                  # ③ OUTPUT GUARDRAILS (post-LLM)
│   │   ├── hallucination.py     # Groundedness & citation checks
│   │   ├── pii_redactor.py      # Output PII scrubbing
│   │   ├── toxicity.py          # Output toxicity filter
│   │   ├── schema_validator.py  # JSON/structured output validation
│   │   └── content_policy.py    # Brand, legal, topic restrictions
│   │
│   ├── policy/                  # ④ POLICY COMPLIANCE
│   │   ├── eu_ai_act.py         # EU AI Act (2024/1689) compliance checks
│   │   ├── gdpr.py              # GDPR data processing obligations
│   │   └── risk_classifier.py   # Risk-tier classification (unacceptable / high / limited)
│   │
│   └── observability/           # ⑤ OBSERVABILITY & AUDIT
│       ├── audit_logger.py      # Tamper-evident structured audit logs
│       ├── metrics.py           # Prometheus-compatible metrics
│       └── otel.py              # OpenTelemetry tracing
│
├── integrations/                # Ready-made adapters
│   ├── openai_middleware.py
│   ├── anthropic_middleware.py
│   ├── langchain_callback.py
│   └── fastapi_middleware.py
│
├── config/
│   ├── default.yaml             # Sane defaults for all modules
│   └── eu_high_risk.yaml        # Strict config for EU high-risk AI systems
│
└── examples/
    ├── quickstart.py
    ├── chatbot_pipeline.py
    └── agentic_tool_use.py
```

---

## Quick Start

```bash
pip install ai-safety-guardrails
```

```python
from guardrails import GuardrailPipeline
from guardrails.modules.input import PIIDetector, PromptInjectionGuard, TopicClassifier
from guardrails.modules.output import ToxicityFilter, PIIRedactor
from guardrails.modules.policy import EUAIActCompliance

# Build a pipeline
pipeline = GuardrailPipeline(
    input_guards=[
        PIIDetector(action="redact"),
        PromptInjectionGuard(sensitivity="medium"),
        TopicClassifier(allowed_topics=["customer_support", "billing"]),
    ],
    output_guards=[
        ToxicityFilter(threshold=0.7),
        PIIRedactor(),
    ],
    policy_guards=[
        EUAIActCompliance(risk_tier="limited"),
    ],
)

# Use in your app
result = await pipeline.run_input(user_message)
if result.blocked:
    return result.rejection_message

llm_response = await your_llm_call(result.sanitized_input)

final = await pipeline.run_output(llm_response, context={"user_id": user_id})
return final.sanitized_output
```

---

## Module Reference

### Input Guardrails

| Module | Purpose | Key Config |
|---|---|---|
| `PIIDetector` | Detect & redact emails, SSNs, credit cards, phone numbers | `action: redact\|block\|flag`, `entities` |
| `PromptInjectionGuard` | Block jailbreaks, system prompt extraction, indirect injection | `sensitivity: low\|medium\|high` |
| `TopicClassifier` | Enforce topic boundaries for your application | `allowed_topics`, `fallback_message` |
| `ToxicityFilter` | Hate speech, harassment, violent content | `threshold`, `categories` |
| `RateLimiter` | Per-user and per-org request limits | `requests_per_minute`, `tokens_per_day` |

### Processing Guardrails

| Module | Purpose | Key Config |
|---|---|---|
| `ToolPolicy` | Allow/deny specific tool calls per user role | `policies: Dict[role, List[tool]]` |
| `ContextControl` | Limit RAG results by user permissions | `max_results`, `allowed_collections` |
| `IAMBinding` | Enforce least-privilege on tool/data access | `policy_engine: opa\|inline` |
| `MemoryHygiene` | TTL and scope on agent memory | `ttl_seconds`, `persist_fields` |

### Output Guardrails

| Module | Purpose | Key Config |
|---|---|---|
| `HallucinationDetector` | Groundedness check against source context | `threshold`, `citation_required` |
| `PIIRedactor` | Remove PII from LLM responses | `entities`, `replacement_style` |
| `ToxicityFilter` | Filter unsafe model outputs | `threshold`, `action: block\|warn` |
| `SchemaValidator` | Validate structured outputs against JSON Schema | `schema`, `strict` |
| `ContentPolicy` | Brand safety, legal disclaimers, off-topic content | `rules: List[PolicyRule]` |

### Policy Compliance

| Module | Purpose |
|---|---|
| `EUAIActCompliance` | Checks against Regulation (EU) 2024/1689 obligations |
| `GDPRGuard` | Data minimization, consent, and processing purpose checks |
| `RiskClassifier` | Classifies your AI system into EU risk tiers |

---

## Policy Compliance — EU AI Act

The `eu_ai_act` module maps directly to the obligations in **Regulation (EU) 2024/1689** (in force August 2024, GPAI rules effective August 2025, High-Risk rules August 2026):

```python
from guardrails.modules.policy import EUAIActCompliance, RiskTier

eu_guard = EUAIActCompliance(
    risk_tier=RiskTier.HIGH,          # unacceptable | high | limited | minimal
    system_id="my-ai-system-v1",
    provider_name="Acme Corp",
    enable_audit_log=True,            # Article 12 — automatic logging
    human_oversight_callback=notify_human,  # Article 14
)
```

**Checks performed automatically:**

| EU AI Act Article | What is checked |
|---|---|
| Art. 5 | Prohibits unacceptable-risk uses (social scoring, real-time biometrics) |
| Art. 9 | Risk management system hooks |
| Art. 10 | Data governance flags for training/inference data quality |
| Art. 12 | Automatic event logging with tamper-evident audit trail |
| Art. 13 | Transparency — AI interaction disclosure enforcement |
| Art. 14 | Human oversight gate — configurable intervention thresholds |
| Art. 15 | Accuracy, robustness, and cybersecurity metric collection |
| Art. 50 | Synthetic content disclosure & AI-generated labeling |

---

## Integrations

### FastAPI Middleware

```python
from fastapi import FastAPI
from guardrails.integrations import FastAPIGuardrailMiddleware

app = FastAPI()
app.add_middleware(FastAPIGuardrailMiddleware, pipeline=pipeline)
```

### LangChain Callback

```python
from guardrails.integrations import LangChainGuardrailCallback

llm = ChatOpenAI(callbacks=[LangChainGuardrailCallback(pipeline=pipeline)])
```

### Anthropic / OpenAI

```python
from guardrails.integrations import AnthropicGuardrail

client = AnthropicGuardrail(pipeline=pipeline)  # drop-in replacement
response = await client.messages.create(...)
```

---

## Configuration

All modules support YAML-based configuration for reproducible deployments:

```yaml
# config/production.yaml
pipeline:
  mode: async
  fail_open: false           # block on guardrail errors (safe default)
  parallel_checks: true

input:
  pii_detector:
    action: redact
    entities: [EMAIL, PHONE, SSN, CREDIT_CARD, IP_ADDRESS]
  prompt_injection:
    sensitivity: high
    log_attempts: true

output:
  toxicity:
    threshold: 0.75
    categories: [hate, violence, sexual, self_harm]
  pii_redactor:
    enabled: true

policy:
  eu_ai_act:
    enabled: true
    risk_tier: high
    audit_retention_days: 365
```

Load with:
```python
pipeline = GuardrailPipeline.from_config("config/production.yaml")
```

---

## Observability

Every check emits:
- **Structured audit logs** (JSON, compatible with ELK/Splunk/Datadog)
- **Prometheus metrics** — `guardrail_checks_total`, `guardrail_latency_seconds`, `guardrail_blocks_total`
- **OpenTelemetry spans** — full trace from input → guardrail → LLM → output guardrail

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). To add a custom guardrail:

```python
from guardrails.core import GuardrailBase, CheckResult, Severity

class MyCustomGuard(GuardrailBase):
    async def check(self, content: str, context: dict) -> CheckResult:
        # your logic here
        return CheckResult(passed=True)
```

---

## License

MIT — see [LICENSE](LICENSE).
