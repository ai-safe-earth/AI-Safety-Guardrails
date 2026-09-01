"""
config/settings.py
-------------------
Centralised settings for the AI Safety Guardrails library.

Reads values from environment variables and an optional `.env` file using
pydantic-settings. All settings have sensible defaults so the library works
out of the box without a `.env` file; only API keys need to be provided for
features that call external services.

Install:
    pip install pydantic-settings
    # or
    pip install "ai-safety-guardrails[settings]"

Usage:
    from config.settings import settings

    # Access any setting
    print(settings.groq_api_key)
    print(settings.default_judge_type)
    print(settings.eu_ai_act_risk_tier)

    # Override at runtime (useful in tests)
    settings2 = Settings(groq_api_key="test-key", guardrails_env="test")

.env file (optional, loaded from project root):
    GROQ_API_KEY=gsk_...
    ANTHROPIC_API_KEY=sk-ant-...
    GUARDRAILS_ENV=production

Environment variables override .env values; .env values override defaults.
All variable names are case-insensitive.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

try:
    from pydantic import Field, field_validator, model_validator
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError as _e:
    raise ImportError(
        "pydantic-settings is required for config.settings.\n"
        "Install with:  pip install pydantic-settings\n"
        "or:            pip install 'ai-safety-guardrails[settings]'"
    ) from _e


# Resolve .env path relative to the project root (two levels up from this file)
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_FILE = _PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    """
    AI Safety Guardrails — application settings.

    Grouped into:
        1. Runtime environment
        2. API keys (LLM providers)
        3. LLM judge defaults
        4. Policy modules (EU AI Act, NIST AI RMF)
        5. Audit & observability
        6. External integrations
        7. Development / test helpers
    """

    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # ignore unknown env vars
        populate_by_name=True,
    )

    # -----------------------------------------------------------------------
    # 1. Runtime environment
    # -----------------------------------------------------------------------

    guardrails_env: Literal["development", "staging", "production", "test"] = Field(
        default="development",
        description="Active environment. Controls defaults for fail_open, log level, etc.",
    )

    guardrails_config_path: str = Field(
        default="config/default.yaml",
        description="Path to the active pipeline YAML config file.",
    )

    guardrails_fail_open: bool = Field(
        default=False,
        description=(
            "Global fail-open flag. When True, guardrail errors allow traffic through. "
            "Safe for development; NOT recommended for production."
        ),
    )

    guardrails_log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Log level for guardrail internals.",
    )

    # -----------------------------------------------------------------------
    # 2. API keys — LLM providers
    # -----------------------------------------------------------------------

    anthropic_api_key: str = Field(
        default="",
        description="Anthropic API key. Used by ClaudeJudge and the optional LLM-as-judge in guards.",
    )

    groq_api_key: str = Field(
        default="",
        description="Groq API key. Used by LlamaGuardJudge(provider='groq').",
    )

    together_api_key: str = Field(
        default="",
        description="Together AI API key. Used by LlamaGuardJudge(provider='together').",
    )

    openai_api_key: str = Field(
        default="",
        description="OpenAI API key. Used by OpenAIModerationJudge.",
    )

    perspective_api_key: str = Field(
        default="",
        description="Google Perspective API key. Used by ToxicityFilter when use_perspective=True.",
    )

    azure_content_safety_key: str = Field(
        default="",
        description="Azure Content Safety API key.",
    )

    azure_content_safety_endpoint: str = Field(
        default="",
        description="Azure Content Safety endpoint URL (e.g. https://<name>.cognitiveservices.azure.com/).",
    )

    # -----------------------------------------------------------------------
    # 3. LLM judge defaults
    # -----------------------------------------------------------------------

    default_judge_type: Literal["llamaguard", "openai_mod", "claude"] = Field(
        default="llamaguard",
        description="Default judge type used when LLMInputFilter/LLMOutputFilter/LLMToolFilter "
        "are loaded from YAML config without an explicit judge_type.",
    )

    default_judge_provider: Literal["groq", "together", "ollama", "openai", "huggingface"] = Field(
        default="groq",
        description="Default LlamaGuard provider.",
    )

    default_judge_timeout: float = Field(
        default=10.0,
        gt=0,
        description="Default timeout (seconds) for LLM judge API calls.",
    )

    default_judge_fail_open: bool = Field(
        default=True,
        description="Whether judge API failures allow traffic through (fail-open). "
        "True = fail open (safe for prod latency); False = fail closed (strict).",
    )

    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Base URL for a local Ollama server. Used by LlamaGuardJudge(provider='ollama').",
    )

    # -----------------------------------------------------------------------
    # 4. Policy modules
    # -----------------------------------------------------------------------

    # EU AI Act
    eu_ai_act_system_id: str = Field(
        default="ai-system",
        description="Unique identifier for your AI system (used in audit logs and transparency disclosures).",
    )

    eu_ai_act_provider_name: str = Field(
        default="Provider",
        description="Your organisation name, shown in EU AI Act transparency disclosures (Art. 13/50).",
    )

    eu_ai_act_risk_tier: Literal["unacceptable", "high", "limited", "minimal"] = Field(
        default="limited",
        description="EU AI Act risk tier for this deployment.",
    )

    eu_ai_act_audit_log_path: str = Field(
        default="audit/eu_ai_act.jsonl",
        description="Path for EU AI Act Art. 12 audit log.",
    )

    eu_ai_act_audit_retention_days: int = Field(
        default=365,
        gt=0,
        description="Audit log retention period in days (minimum 1 year for high-risk systems).",
    )

    # NIST AI RMF
    nist_system_name: str = Field(
        default="ai-system",
        description="System name used in NIST AI RMF audit logs.",
    )

    nist_operator_name: str = Field(
        default="Operator",
        description="Operator / organisation name for NIST AI RMF compliance records.",
    )

    nist_impact_level: Literal["critical", "high", "moderate", "low"] = Field(
        default="moderate",
        description="NIST AI RMF impact level for this deployment.",
    )

    nist_audit_log_path: str = Field(
        default="audit/nist_ai_rmf.jsonl",
        description="Path for NIST AI RMF MANAGE 2.4 monitoring log.",
    )

    # -----------------------------------------------------------------------
    # 5. Audit & observability
    # -----------------------------------------------------------------------

    guardrails_audit_log_dir: str = Field(
        default="audit",
        description="Base directory for all audit log files.",
    )

    otel_exporter_otlp_endpoint: str = Field(
        default="",
        description="OpenTelemetry OTLP exporter endpoint (e.g. http://localhost:4317). "
        "Leave empty to disable OpenTelemetry export.",
    )

    otel_service_name: str = Field(
        default="ai-safety-guardrails",
        description="Service name reported in OpenTelemetry traces and metrics.",
    )

    prometheus_enabled: bool = Field(
        default=False,
        description="Enable Prometheus metrics endpoint.",
    )

    prometheus_port: int = Field(
        default=9090,
        gt=0,
        lt=65536,
        description="Port for the Prometheus metrics HTTP server.",
    )

    # -----------------------------------------------------------------------
    # 6. External integrations
    # -----------------------------------------------------------------------

    langchain_enabled: bool = Field(
        default=False,
        description="Enable LangChain callback handler integration.",
    )

    fastapi_enabled: bool = Field(
        default=False,
        description="Enable FastAPI middleware integration.",
    )

    # -----------------------------------------------------------------------
    # 7. Development / test helpers
    # -----------------------------------------------------------------------

    guardrails_disable_all: bool = Field(
        default=False,
        description="Disable all guardrails globally. For local development only. "
        "Never set True in production.",
    )

    guardrails_mock_judges: bool = Field(
        default=False,
        description="Return safe=True for all LLM judge calls. "
        "Useful in unit tests to avoid API calls.",
    )

    # -----------------------------------------------------------------------
    # Derived / computed helpers
    # -----------------------------------------------------------------------

    @field_validator("guardrails_log_level", mode="before")
    @classmethod
    def _upper_log_level(cls, v: str) -> str:
        return v.upper()

    @model_validator(mode="after")
    def _warn_production_unsafe(self) -> "Settings":
        """Warn if unsafe settings are active in production."""
        import warnings

        if self.guardrails_env == "production":
            if self.guardrails_fail_open:
                warnings.warn(
                    "GUARDRAILS_FAIL_OPEN=true is set in a production environment. "
                    "This allows guardrail errors to pass traffic through unfiltered.",
                    stacklevel=2,
                )
            if self.guardrails_disable_all:
                warnings.warn(
                    "GUARDRAILS_DISABLE_ALL=true is set in a production environment. "
                    "All safety guardrails are inactive.",
                    stacklevel=2,
                )
        return self

    @property
    def is_production(self) -> bool:
        return self.guardrails_env == "production"

    @property
    def is_development(self) -> bool:
        return self.guardrails_env in ("development", "test")

    def judge_kwargs(self) -> dict:
        """
        Return keyword arguments for build_judge() based on current settings.
        Merges defaults with the active API key for the chosen provider.

        Usage:
            from modules.llm_judges import build_judge
            judge = build_judge(**settings.judge_kwargs())
        """
        api_key_map = {
            "groq": self.groq_api_key,
            "together": self.together_api_key,
            "openai": self.openai_api_key,
            "ollama": "",
            "huggingface": "",
        }
        return {
            "judge_type": self.default_judge_type,
            "judge_provider": self.default_judge_provider,
            "api_key": api_key_map.get(self.default_judge_provider, ""),
            "fail_open": self.default_judge_fail_open,
            "timeout": self.default_judge_timeout,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

settings = Settings()
