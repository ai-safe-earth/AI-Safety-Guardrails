# Repository Structure

```
ai-safety-guardrails/
│
│   ── Root
├── __init__.py                         Public API surface (clean imports)
├── pyproject.toml                      Package metadata, dependencies, CLI entry point
├── README.md                           Full documentation
├── .pre-commit-config.yaml             Pre-commit hooks (euaiact-lint + secret scan)
├── .gitlab-ci-euaiact.yml              GitLab CI/CD pipeline include
│
│   ── CI/CD
└── .github/
    └── workflows/
        └── eu-ai-act-compliance.yml    GitHub Actions: PR check + SARIF upload + PR comment
│
│   ── Core engine (framework internals)
├── core/
│   ├── base.py                         GuardrailBase, CheckResult, PipelineResult, Severity
│   ├── pipeline.py                     GuardrailPipeline — main orchestrator
│   ├── exceptions.py                   GuardrailBlockedError, PolicyViolationError, ...
│   └── registry.py                     @register_guard decorator + module registry
│
│   ── Guardrail modules (plug-in, mix-and-match)
├── modules/
│   │
│   ├── input/                          ① INPUT GUARDRAILS  (run before the LLM)
│   │   ├── pii_detector.py             Detect & redact PII (email, SSN, card, phone, IBAN…)
│   │   └── prompt_injection.py         Injection, jailbreak, base64 obfuscation, DAN patterns
│   │   # planned:
│   │   # ├── topic_classifier.py       Enforce allowed topic boundaries
│   │   # ├── toxicity.py               Input hate/harassment/violence filter
│   │   # └── rate_limiter.py           Per-user / per-org request throttle
│   │
│   ├── processing/                     ② PROCESSING GUARDRAILS  (tool & agent control)
│   │   └── tool_policy.py              Role-based tool allow/deny + human approval gate
│   │   # planned:
│   │   # ├── context_control.py        RAG result scoping & access control
│   │   # ├── iam_binding.py            Least-privilege identity enforcement
│   │   # └── memory_hygiene.py         Agent memory TTL & scope limits
│   │
│   ├── output/                         ③ OUTPUT GUARDRAILS  (run after the LLM)
│   │   └── toxicity.py                 Harmful content filter (rule-based + LLM judge)
│   │   # planned:
│   │   # ├── pii_redactor.py           Scrub PII from LLM responses
│   │   # ├── hallucination.py          Groundedness / citation check
│   │   # ├── schema_validator.py       JSON schema enforcement for structured outputs
│   │   # └── content_policy.py         Brand safety, legal disclaimers, topic rules
│   │
│   ├── policy/                         ④ POLICY COMPLIANCE
│   │   ├── eu_ai_act.py                Runtime EU AI Act guardrail (Art. 5/9/12/13/14/15/50)
│   │   │   # planned:
│   │   │   # ├── gdpr.py               GDPR data processing obligation checks
│   │   │   # └── risk_classifier.py    Risk-tier auto-classification
│   │   │
│   │   └── code_analyzer/              ④b EU AI ACT STATIC CODE ANALYZER (dev-time)
│   │       ├── analyzer.py             Engine: AST + regex scanner, ScanReport, BaseRule
│   │       ├── rules/
│   │       │   └── __init__.py         20 rules mapped to Articles 5/9/10/11/12/13/14/15/50
│   │       └── reporters/
│   │           └── __init__.py         Terminal, JSON, SARIF 2.1.0, Markdown reporters
│   │
│   └── observability/                  ⑤ OBSERVABILITY & AUDIT
│       └── audit_logger.py             Structured JSON audit logs (Art. 12 compliant)
│       # planned:
│       # ├── metrics.py                Prometheus-compatible metrics
│       # └── otel.py                   OpenTelemetry tracing
│
│   ── Framework integrations
├── integrations/
│   ├── anthropic_middleware.py         Drop-in AsyncAnthropic wrapper with guardrails
│   ├── fastapi_middleware.py           Starlette/FastAPI middleware (auto-wraps all routes)
│   └── langchain_callback.py           LangChain BaseCallbackHandler (LLM + tool hooks)
│   # planned:
│   # ├── openai_middleware.py          Drop-in AsyncOpenAI wrapper
│   # └── llamaindex_callback.py        LlamaIndex query/synthesis hooks
│
│   ── Configuration presets
├── config/
│   ├── default.yaml                    Sane defaults for all modules (limited-risk tier)
│   └── eu_high_risk.yaml               Strict preset for EU AI Act high-risk systems
│
│   ── CLI tool
├── scripts/
│   └── euaiact_lint.py                 euaiact-lint CLI (scan / diff / staged / CI modes)
│
│   ── Usage examples
├── examples/
│   ├── quickstart.py                   Minimal pipeline in 20 lines
│   ├── chatbot_customer_support.py     Customer support bot with full guardrail stack
│   ├── agentic_tool_use.py             Agent with role-based tool policies
│   ├── eu_ai_act_high_risk.py          Loan assistant — HIGH RISK compliance demo
│   ├── fastapi_service.py              Production FastAPI service with middleware
│   ├── config_driven_pipeline.py       YAML-driven pipeline (no code changes per env)
│   └── custom_guardrail.py             Writing your own guard in ~20 lines
│
│   ── Tests
└── tests/
    ├── unit/
    │   └── test_guardrails.py          Unit tests for all core modules
    ├── fixtures/
    │   └── noncompliant_sample.py      Intentionally bad code (tests all 20 lint rules)
    # planned:
    # ├── integration/
    # │   └── test_pipeline_e2e.py      End-to-end pipeline tests with mock LLM
    # └── compliance/
    #     └── test_eu_ai_act_rules.py   Per-article compliance rule test suite
```

---

## Data flow

```
                        ┌─────────────────────────────────────────┐
  User message ──────►  │  ① INPUT GUARDRAILS                     │
                        │     PIIDetector       (redact)           │
                        │     PromptInjection   (block/flag)       │
                        │     TopicClassifier   (block)            │
                        │     ToxicityFilter    (block)            │
                        └──────────────┬──────────────────────────┘
                                       │ sanitized input
                        ┌──────────────▼──────────────────────────┐
                        │  ④ POLICY GUARDRAILS (parallel)         │
                        │     EUAIActCompliance  (Art.5 block,     │
                        │                        Art.12 log,       │
                        │                        Art.14 oversight) │
                        └──────────────┬──────────────────────────┘
                                       │ cleared input
                        ┌──────────────▼──────────────────────────┐
                        │  ② PROCESSING GUARDRAILS                │
                        │     ToolPolicyGuard   (role-based ACL)   │
                        │     ContextControl    (RAG scoping)      │
                        │     IAMBinding        (least-privilege)  │
                        └──────────────┬──────────────────────────┘
                                       │ authorized request
                              ┌────────▼────────┐
                              │    LLM / Agent  │
                              └────────┬────────┘
                                       │ raw response
                        ┌──────────────▼──────────────────────────┐
                        │  ③ OUTPUT GUARDRAILS                    │
                        │     ToxicityFilter    (block/redact)     │
                        │     PIIRedactor       (redact)           │
                        │     HallucinationCheck(flag/block)       │
                        │     SchemaValidator   (enforce)          │
                        └──────────────┬──────────────────────────┘
                                       │ safe response
                              ┌────────▼────────┐
                              │      User       │
                              └─────────────────┘

  ⑤ OBSERVABILITY runs at every stage:
     AuditLogger → structured JSONL  (Art. 12 tamper-evident log)
     Metrics     → Prometheus counters/histograms
     OTel spans  → trace from input → guardrail → LLM → output
```

---

## Dev-time compliance (static analysis)

```
  git commit / git push / PR
         │
         ▼
  ┌─────────────────────────────────────────┐
  │  .pre-commit-config.yaml                │
  │    euaiact-lint --staged --errors-only  │  ← blocks commit on Art.5 / security errors
  │    detect-secrets                       │  ← blocks hardcoded API keys
  └──────────────┬──────────────────────────┘
                 │
                 ▼  (on PR)
  ┌─────────────────────────────────────────┐
  │  GitHub Actions / GitLab CI             │
  │    euaiact-lint src/ --format sarif     │  → Security tab (Code Scanning)
  │    euaiact-lint src/ --format markdown  │  → PR comment with findings
  │    euaiact-lint src/ --format json      │  → 90-day artifact (Art.12 retention)
  └─────────────────────────────────────────┘

  20 lint rules across:
    Art. 5   — prohibited practices in code
    Art. 9   — risk management hooks missing
    Art. 10  — hardcoded datasets, no bias checks
    Art. 11  — undocumented AI components
    Art. 12  — LLM calls without audit logging
    Art. 13  — no AI disclosure in response functions
    Art. 14  — automated decisions without human oversight
    Art. 15  — no input validation, pickle loads, hardcoded secrets
    Art. 50  — generated content without labels, deepfakes without disclosure
    GDPR     — PII flowing into LLM prompts
```

---

## Quick install

```bash
# Runtime guardrails only
pip install ai-safety-guardrails

# With specific integrations
pip install "ai-safety-guardrails[anthropic,fastapi]"

# Full install (all integrations + Presidio PII)
pip install "ai-safety-guardrails[all]"

# CLI linter (works standalone in any Python project)
pip install ai-safety-guardrails
euaiact-lint src/ --format terminal
```
