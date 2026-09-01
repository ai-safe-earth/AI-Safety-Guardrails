"""
src/aisg/probes/__init__.py
---------------------------
Attack corpus for `aisg probe`, one YAML file per family.

The payloads are seeded from the detection patterns this package already
ships -- INJECTION_PATTERNS, PII_PATTERNS, TOXICITY_PATTERNS,
AdvancedInjectionDetectors and LLMToolFilter.high_risk_fail_closed -- so the
corpus exercises the guards that exist rather than a parallel invention. Each
case records the `seed_pattern` it came from.

Loaded via importlib.resources, so it works from a wheel as well as a checkout.
"""
