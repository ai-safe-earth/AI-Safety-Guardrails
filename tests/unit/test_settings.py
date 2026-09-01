"""
tests/unit/test_settings.py
-----------------------------
Unit tests for config/settings.py (Pydantic Settings).

All tests instantiate Settings() directly with keyword arguments to avoid
reading from any real .env file or ambient environment variables.
The monkeypatch fixture is used when testing environment variable resolution.
"""

import os
import sys
import warnings

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from config.settings import Settings

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make(**kwargs) -> Settings:
    """Construct Settings with env_file disabled so only kwargs + env vars apply."""
    return Settings(_env_file=None, **kwargs)


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_env_defaults_to_development(self):
        s = make()
        assert s.guardrails_env == "development"

    def test_config_path_default(self):
        s = make()
        assert s.guardrails_config_path == "config/default.yaml"

    def test_fail_open_defaults_false(self):
        s = make()
        assert s.guardrails_fail_open is False

    def test_log_level_defaults_info(self):
        s = make()
        assert s.guardrails_log_level == "INFO"

    def test_judge_type_defaults_llamaguard(self):
        s = make()
        assert s.default_judge_type == "llamaguard"

    def test_judge_provider_defaults_groq(self):
        s = make()
        assert s.default_judge_provider == "groq"

    def test_judge_timeout_default(self):
        s = make()
        assert s.default_judge_timeout == 10.0

    def test_judge_fail_open_defaults_true(self):
        s = make()
        assert s.default_judge_fail_open is True

    def test_ollama_url_default(self):
        s = make()
        assert s.ollama_base_url == "http://localhost:11434"

    def test_api_keys_default_empty(self, monkeypatch):
        # Clear any ambient API keys set in the shell environment
        for var in (
            "ANTHROPIC_API_KEY",
            "GROQ_API_KEY",
            "TOGETHER_API_KEY",
            "OPENAI_API_KEY",
            "PERSPECTIVE_API_KEY",
            "AZURE_CONTENT_SAFETY_KEY",
            "AZURE_CONTENT_SAFETY_ENDPOINT",
        ):
            monkeypatch.delenv(var, raising=False)
        s = make()
        assert s.anthropic_api_key == ""
        assert s.groq_api_key == ""
        assert s.together_api_key == ""
        assert s.openai_api_key == ""
        assert s.perspective_api_key == ""
        assert s.azure_content_safety_key == ""
        assert s.azure_content_safety_endpoint == ""

    def test_eu_ai_act_defaults(self):
        s = make()
        assert s.eu_ai_act_system_id == "ai-system"
        assert s.eu_ai_act_provider_name == "Provider"
        assert s.eu_ai_act_risk_tier == "limited"
        assert s.eu_ai_act_audit_retention_days == 365

    def test_nist_defaults(self):
        s = make()
        assert s.nist_system_name == "ai-system"
        assert s.nist_operator_name == "Operator"
        assert s.nist_impact_level == "moderate"

    def test_observability_defaults(self):
        s = make()
        assert s.otel_exporter_otlp_endpoint == ""
        assert s.otel_service_name == "ai-safety-guardrails"
        assert s.prometheus_enabled is False
        assert s.prometheus_port == 9090

    def test_dev_helpers_default_false(self):
        s = make()
        assert s.guardrails_disable_all is False
        assert s.guardrails_mock_judges is False


# ---------------------------------------------------------------------------
# Overrides via keyword arguments
# ---------------------------------------------------------------------------


class TestOverrides:
    def test_set_env(self):
        s = make(guardrails_env="production")
        assert s.guardrails_env == "production"

    def test_set_api_keys(self):
        s = make(groq_api_key="gsk_test", anthropic_api_key="sk-ant-test")
        assert s.groq_api_key == "gsk_test"
        assert s.anthropic_api_key == "sk-ant-test"

    def test_set_judge_type(self):
        s = make(default_judge_type="claude")
        assert s.default_judge_type == "claude"

    def test_set_judge_provider(self):
        s = make(default_judge_provider="ollama")
        assert s.default_judge_provider == "ollama"

    def test_set_judge_timeout(self):
        s = make(default_judge_timeout=30.0)
        assert s.default_judge_timeout == 30.0

    def test_set_eu_ai_act_fields(self):
        s = make(
            eu_ai_act_system_id="system-x",
            eu_ai_act_provider_name="Acme Corp",
            eu_ai_act_risk_tier="high",
            eu_ai_act_audit_retention_days=730,
        )
        assert s.eu_ai_act_system_id == "system-x"
        assert s.eu_ai_act_provider_name == "Acme Corp"
        assert s.eu_ai_act_risk_tier == "high"
        assert s.eu_ai_act_audit_retention_days == 730

    def test_set_nist_fields(self):
        s = make(nist_impact_level="critical", nist_system_name="sys-y")
        assert s.nist_impact_level == "critical"
        assert s.nist_system_name == "sys-y"

    def test_set_ollama_base_url(self):
        s = make(ollama_base_url="http://192.168.1.10:11434")
        assert s.ollama_base_url == "http://192.168.1.10:11434"

    def test_set_fail_open_true(self):
        s = make(guardrails_fail_open=True)
        assert s.guardrails_fail_open is True


# ---------------------------------------------------------------------------
# Environment variable resolution
# ---------------------------------------------------------------------------


class TestEnvVarResolution:
    def test_groq_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "gsk_from_env")
        s = make()
        assert s.groq_api_key == "gsk_from_env"

    def test_anthropic_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-from-env")
        s = make()
        assert s.anthropic_api_key == "sk-ant-from-env"

    def test_guardrails_env_from_env(self, monkeypatch):
        monkeypatch.setenv("GUARDRAILS_ENV", "staging")
        s = make()
        assert s.guardrails_env == "staging"

    def test_env_var_case_insensitive(self, monkeypatch):
        monkeypatch.setenv("groq_api_key", "gsk_lower")
        s = make()
        assert s.groq_api_key == "gsk_lower"

    def test_kwarg_takes_precedence_over_env(self, monkeypatch):
        monkeypatch.setenv("GROQ_API_KEY", "gsk_from_env")
        s = make(groq_api_key="gsk_explicit")
        assert s.groq_api_key == "gsk_explicit"

    def test_together_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("TOGETHER_API_KEY", "together_key")
        s = make()
        assert s.together_api_key == "together_key"

    def test_openai_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai")
        s = make()
        assert s.openai_api_key == "sk-openai"


# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------


class TestValidators:
    def test_log_level_lowercased_input_normalised(self):
        s = make(guardrails_log_level="debug")
        assert s.guardrails_log_level == "DEBUG"

    def test_log_level_mixed_case_normalised(self):
        s = make(guardrails_log_level="Warning")
        assert s.guardrails_log_level == "WARNING"

    def test_invalid_env_raises(self):
        with pytest.raises(Exception):
            make(guardrails_env="invalid_env")

    def test_invalid_judge_type_raises(self):
        with pytest.raises(Exception):
            make(default_judge_type="unknown_judge")

    def test_invalid_judge_provider_raises(self):
        with pytest.raises(Exception):
            make(default_judge_provider="aws_bedrock_not_supported")

    def test_invalid_eu_risk_tier_raises(self):
        with pytest.raises(Exception):
            make(eu_ai_act_risk_tier="medium")

    def test_invalid_nist_impact_level_raises(self):
        with pytest.raises(Exception):
            make(nist_impact_level="extreme")

    def test_invalid_log_level_raises(self):
        with pytest.raises(Exception):
            make(guardrails_log_level="VERBOSE")

    def test_judge_timeout_must_be_positive(self):
        with pytest.raises(Exception):
            make(default_judge_timeout=0)

    def test_prometheus_port_must_be_valid(self):
        with pytest.raises(Exception):
            make(prometheus_port=99999)


# ---------------------------------------------------------------------------
# Properties
# ---------------------------------------------------------------------------


class TestProperties:
    def test_is_production_true(self):
        s = make(guardrails_env="production")
        assert s.is_production is True

    def test_is_production_false_for_development(self):
        s = make(guardrails_env="development")
        assert s.is_production is False

    def test_is_development_true_for_development(self):
        s = make(guardrails_env="development")
        assert s.is_development is True

    def test_is_development_true_for_test(self):
        s = make(guardrails_env="test")
        assert s.is_development is True

    def test_is_development_false_for_production(self):
        s = make(guardrails_env="production")
        assert s.is_development is False

    def test_is_development_false_for_staging(self):
        s = make(guardrails_env="staging")
        assert s.is_development is False


# ---------------------------------------------------------------------------
# judge_kwargs()
# ---------------------------------------------------------------------------


class TestJudgeKwargs:
    def test_returns_dict_with_required_keys(self):
        s = make()
        kw = s.judge_kwargs()
        assert "judge_type" in kw
        assert "judge_provider" in kw
        assert "api_key" in kw
        assert "fail_open" in kw
        assert "timeout" in kw

    def test_judge_type_matches_setting(self):
        s = make(default_judge_type="openai_mod")
        assert s.judge_kwargs()["judge_type"] == "openai_mod"

    def test_judge_provider_matches_setting(self):
        s = make(default_judge_provider="together")
        assert s.judge_kwargs()["judge_provider"] == "together"

    def test_api_key_resolved_for_groq(self):
        s = make(default_judge_provider="groq", groq_api_key="gsk_xyz")
        assert s.judge_kwargs()["api_key"] == "gsk_xyz"

    def test_api_key_resolved_for_together(self):
        s = make(default_judge_provider="together", together_api_key="together_xyz")
        assert s.judge_kwargs()["api_key"] == "together_xyz"

    def test_api_key_resolved_for_openai(self):
        s = make(default_judge_provider="openai", openai_api_key="sk-openai-xyz")
        assert s.judge_kwargs()["api_key"] == "sk-openai-xyz"

    def test_api_key_empty_for_ollama(self):
        s = make(default_judge_provider="ollama")
        assert s.judge_kwargs()["api_key"] == ""

    def test_fail_open_matches_setting(self):
        s = make(default_judge_fail_open=False)
        assert s.judge_kwargs()["fail_open"] is False

    def test_timeout_matches_setting(self):
        s = make(default_judge_timeout=25.0)
        assert s.judge_kwargs()["timeout"] == 25.0

    def test_judge_kwargs_feeds_build_judge(self):
        """judge_kwargs() output is accepted by build_judge() without error."""
        from modules.llm_judges import build_judge

        s = make(default_judge_type="llamaguard", default_judge_provider="groq")
        judge = build_judge(**s.judge_kwargs())
        assert judge.name == "llamaguard3_groq"

    def test_judge_kwargs_claude(self):
        from modules.llm_judges import build_judge

        s = make(default_judge_type="claude")
        judge = build_judge(**s.judge_kwargs())
        assert "claude" in judge.name


# ---------------------------------------------------------------------------
# Production safety warnings
# ---------------------------------------------------------------------------


class TestProductionWarnings:
    def test_fail_open_in_production_warns(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            make(guardrails_env="production", guardrails_fail_open=True)
        messages = [str(w.message) for w in caught]
        assert any("GUARDRAILS_FAIL_OPEN" in m for m in messages)

    def test_disable_all_in_production_warns(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            make(guardrails_env="production", guardrails_disable_all=True)
        messages = [str(w.message) for w in caught]
        assert any("GUARDRAILS_DISABLE_ALL" in m for m in messages)

    def test_no_warning_in_development(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            make(guardrails_env="development", guardrails_fail_open=True)
        guardrail_warnings = [w for w in caught if "GUARDRAILS_FAIL_OPEN" in str(w.message)]
        assert len(guardrail_warnings) == 0

    def test_no_warning_when_safe_in_production(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            make(guardrails_env="production")
        guardrail_warnings = [
            w
            for w in caught
            if "GUARDRAILS_FAIL_OPEN" in str(w.message)
            or "GUARDRAILS_DISABLE_ALL" in str(w.message)
        ]
        assert len(guardrail_warnings) == 0


# ---------------------------------------------------------------------------
# .env file loading
# ---------------------------------------------------------------------------


class TestDotEnvLoading:
    def test_env_file_values_loaded(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text(
            "GROQ_API_KEY=gsk_from_file\nGUARDRAILS_ENV=staging\nDEFAULT_JUDGE_TIMEOUT=20.0\n"
        )
        s = Settings(_env_file=str(env_file))
        assert s.groq_api_key == "gsk_from_file"
        assert s.guardrails_env == "staging"
        assert s.default_judge_timeout == 20.0

    def test_multiple_keys_from_env_file(self, tmp_path, monkeypatch):
        # Ensure ambient env vars don't override the file values we're testing
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        env_file = tmp_path / ".env"
        env_file.write_text(
            "ANTHROPIC_API_KEY=sk-ant-file\n"
            "OPENAI_API_KEY=sk-openai-file\n"
            "EU_AI_ACT_RISK_TIER=high\n"
            "NIST_IMPACT_LEVEL=critical\n"
        )
        s = Settings(_env_file=str(env_file))
        assert s.anthropic_api_key == "sk-ant-file"
        assert s.openai_api_key == "sk-openai-file"
        assert s.eu_ai_act_risk_tier == "high"
        assert s.nist_impact_level == "critical"

    def test_kwarg_overrides_env_file(self, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("GROQ_API_KEY=gsk_from_file\n")
        s = Settings(_env_file=str(env_file), groq_api_key="gsk_explicit")
        assert s.groq_api_key == "gsk_explicit"

    def test_missing_env_file_uses_defaults(self, tmp_path):
        missing = tmp_path / "nonexistent.env"
        s = Settings(_env_file=str(missing))
        assert s.guardrails_env == "development"
        assert s.groq_api_key == ""

    def test_env_file_comments_ignored(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("GROQ_API_KEY", raising=False)
        env_file = tmp_path / ".env"
        env_file.write_text(
            "# This is a comment\nGROQ_API_KEY=gsk_real\n# ANTHROPIC_API_KEY=should_be_ignored\n"
        )
        s = Settings(_env_file=str(env_file))
        assert s.groq_api_key == "gsk_real"
        assert s.anthropic_api_key == ""
