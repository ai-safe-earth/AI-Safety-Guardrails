"""
modules/analysis/data_flow_rules.py
------------------------------------
EU AI Act Compliance Rules Based on Data Flow Analysis

Rules that use data flow analysis to detect:
  - Art. 10: Data governance violations (unvalidated training data)
  - Art. 15: Cybersecurity violations (unvalidated input to models)
  - GDPR Art. 5: Purpose limitation (PII to LLM without documented purpose)
  - GDPR Art. 25: Data minimization (excessive data collection)

These rules integrate with the static code analyzer framework.
"""

from __future__ import annotations

import ast
from typing import Iterator

from aisg.modules.analysis.data_flow_analyzer import DataFlowAnalyzer, SensitivityLevel
from aisg.modules.policy.code_analyzer.analyzer import BaseRule, CodeFinding, Severity

# ---------------------------------------------------------------------------
# Rule: Unvalidated User Input to LLM
# ---------------------------------------------------------------------------


class UnvalidatedLLMInputRule(BaseRule):
    """
    Detects user input flowing directly to LLM calls without validation.

    EU AI Act Article 15: Accuracy, robustness and cybersecurity
    - High-risk AI systems must be resilient against errors and adversarial attacks
    - Input validation is essential for cybersecurity

    Example violation:
        user_message = request.json.get('message')
        response = openai.ChatCompletion.create(messages=[{"content": user_message}])
    """

    rule_id = "EU-AIA-DFA-001"
    article = "Art. 15 (Cybersecurity)"
    severity = Severity.ERROR
    title = "Unvalidated user input to LLM"
    description = (
        "User input flows directly to LLM API call without validation or sanitization. "
        "This creates vulnerability to prompt injection and adversarial attacks."
    )
    suggestion = (
        "Add input validation before LLM calls: "
        "1) Validate input format and length, "
        "2) Check for injection patterns, "
        "3) Apply content filtering, "
        "4) Use guardrails framework"
    )

    def check_ast(
        self,
        tree: ast.AST,
        source_lines: list[str],
        filename: str,
    ) -> Iterator[CodeFinding]:
        """Use data flow analysis to detect unvalidated input to LLMs."""
        analyzer = DataFlowAnalyzer()
        analyzer.current_file = filename

        # Analyze the AST
        analyzer.visit(tree)

        # Filter for LLM-related findings
        for finding in analyzer.findings:
            if finding.sink_type == "llm_call" and finding.severity == "high":
                yield self._finding(
                    filename=filename,
                    line=finding.sink_line,
                    snippet=self._snippet(source_lines, finding.sink_line),
                    description=f"{self.description}\n  Source: {finding.source_type} at line {finding.source_line}\n  Flow: {' -> '.join(finding.flow_path)}",
                    suggestion=self.suggestion,
                )


# ---------------------------------------------------------------------------
# Rule: PII in Logs
# ---------------------------------------------------------------------------


class PIIInLogsRule(BaseRule):
    """
    Detects PII flowing to logging statements without redaction.

    GDPR Article 5(1)(f): Integrity and confidentiality
    - Personal data must be processed securely
    - Logging PII without redaction violates confidentiality

    Example violation:
        email = request.json.get('email')
        logger.info(f"Processing request for {email}")
    """

    rule_id = "EU-AIA-DFA-002"
    article = "GDPR Art. 5(1)(f)"
    severity = Severity.ERROR
    title = "PII logged without redaction"
    description = (
        "Personally Identifiable Information flows to logging statements without redaction. "
        "This creates data leakage risk and GDPR compliance issues."
    )
    suggestion = (
        "Redact PII before logging: "
        "1) Use structured logging with automatic PII masking, "
        "2) Hash or pseudonymize identifiers, "
        "3) Only log necessary non-PII metadata"
    )

    def check_ast(
        self,
        tree: ast.AST,
        source_lines: list[str],
        filename: str,
    ) -> Iterator[CodeFinding]:
        """Detect PII flowing to logs."""
        analyzer = DataFlowAnalyzer()
        analyzer.current_file = filename
        analyzer.visit(tree)

        for finding in analyzer.findings:
            if finding.sink_type == "logging" and finding.sensitivity == SensitivityLevel.PII:
                yield self._finding(
                    filename=filename,
                    line=finding.sink_line,
                    snippet=self._snippet(source_lines, finding.sink_line),
                    description=f"{self.description}\n  PII categories: {', '.join(c.value for c in finding.data_categories)}\n  Source: line {finding.source_line}",
                    suggestion=self.suggestion,
                )


# ---------------------------------------------------------------------------
# Rule: Secrets in Model Artifacts
# ---------------------------------------------------------------------------


class SecretsInModelRule(BaseRule):
    """
    Detects secrets (API keys, credentials) embedded in model artifacts.

    EU AI Act Article 15: Cybersecurity
    - AI systems must protect against unauthorized access
    - Embedding secrets in models creates security vulnerability

    Example violation:
        api_key = os.getenv('OPENAI_API_KEY')
        model_config = {'api_key': api_key}
        torch.save(model_config, 'model.pth')
    """

    rule_id = "EU-AIA-DFA-003"
    article = "Art. 15 (Cybersecurity)"
    severity = Severity.ERROR
    title = "Secrets embedded in model artifacts"
    description = (
        "API keys, credentials, or other secrets are embedded in model artifacts. "
        "This creates severe security risk if models are shared or leaked."
    )
    suggestion = (
        "Never embed secrets in models: "
        "1) Use external secure storage (vault, environment variables), "
        "2) Separate model weights from configuration, "
        "3) Use secret management systems"
    )

    def check_ast(
        self,
        tree: ast.AST,
        source_lines: list[str],
        filename: str,
    ) -> Iterator[CodeFinding]:
        """Detect secrets in model serialization."""
        analyzer = DataFlowAnalyzer()
        analyzer.current_file = filename
        analyzer.visit(tree)

        for finding in analyzer.findings:
            if (
                finding.sink_type == "model_serialization"
                and finding.sensitivity == SensitivityLevel.SECRET
            ):
                yield self._finding(
                    filename=filename,
                    line=finding.sink_line,
                    snippet=self._snippet(source_lines, finding.sink_line),
                    description=self.description,
                    suggestion=self.suggestion,
                    severity=Severity.ERROR,
                )


# ---------------------------------------------------------------------------
# Rule: Unencrypted Sensitive Storage
# ---------------------------------------------------------------------------


class UnencryptedStorageRule(BaseRule):
    """
    Detects sensitive data written to files without encryption.

    GDPR Article 32: Security of processing
    - Appropriate technical measures including encryption
    - Sensitive data at rest must be encrypted

    Example violation:
        user_data = request.json
        with open('user_data.json', 'w') as f:
            json.dump(user_data, f)
    """

    rule_id = "EU-AIA-DFA-004"
    article = "GDPR Art. 32 (Security)"
    severity = Severity.ERROR
    title = "Sensitive data stored without encryption"
    description = (
        "Sensitive or PII data is written to files without encryption. "
        "This violates GDPR security requirements."
    )
    suggestion = (
        "Encrypt sensitive data at rest: "
        "1) Use file-level encryption (e.g., Fernet), "
        "2) Use encrypted file systems, "
        "3) Apply field-level encryption for PII"
    )

    def check_ast(
        self,
        tree: ast.AST,
        source_lines: list[str],
        filename: str,
    ) -> Iterator[CodeFinding]:
        """Detect unencrypted storage of sensitive data."""
        analyzer = DataFlowAnalyzer()
        analyzer.current_file = filename
        analyzer.visit(tree)

        for finding in analyzer.findings:
            if finding.sink_type == "file_write" and finding.sensitivity in [
                SensitivityLevel.PII,
                SensitivityLevel.SECRET,
                SensitivityLevel.CONFIDENTIAL,
            ]:
                yield self._finding(
                    filename=filename,
                    line=finding.sink_line,
                    snippet=self._snippet(source_lines, finding.sink_line),
                    description=f"{self.description}\n  Sensitivity: {finding.sensitivity.value}",
                    suggestion=self.suggestion,
                )


# ---------------------------------------------------------------------------
# Rule: PII to External API
# ---------------------------------------------------------------------------


class PIIExfiltrationRule(BaseRule):
    """
    Detects PII transmitted to external APIs without explicit consent handling.

    GDPR Article 6: Lawfulness of processing
    - Personal data processing requires legal basis
    - Transmitting PII to third parties requires consent/contract

    EU AI Act Article 10: Data governance
    - Appropriate data governance measures for training/validation data

    Example violation:
        user_email = request.json.get('email')
        requests.post('https://analytics.example.com', json={'email': user_email})
    """

    rule_id = "EU-AIA-DFA-005"
    article = "GDPR Art. 6 + EU-AIA Art. 10"
    severity = Severity.ERROR
    title = "PII transmitted to external API"
    description = (
        "Personally Identifiable Information is transmitted to external APIs. "
        "This requires documented legal basis and appropriate safeguards."
    )
    suggestion = (
        "For PII transmission: "
        "1) Verify legal basis (consent, contract, legitimate interest), "
        "2) Implement data processing agreements with third parties, "
        "3) Use HTTPS and encrypt payloads, "
        "4) Document data flows in privacy policy"
    )

    def check_ast(
        self,
        tree: ast.AST,
        source_lines: list[str],
        filename: str,
    ) -> Iterator[CodeFinding]:
        """Detect PII exfiltration via HTTP requests."""
        analyzer = DataFlowAnalyzer()
        analyzer.current_file = filename
        analyzer.visit(tree)

        for finding in analyzer.findings:
            if finding.sink_type == "http_request" and finding.sensitivity == SensitivityLevel.PII:
                yield self._finding(
                    filename=filename,
                    line=finding.sink_line,
                    snippet=self._snippet(source_lines, finding.sink_line),
                    description=f"{self.description}\n  PII categories: {', '.join(c.value for c in finding.data_categories)}",
                    suggestion=self.suggestion,
                )


# ---------------------------------------------------------------------------
# Rule: Training Data Without Validation
# ---------------------------------------------------------------------------


class UnvalidatedTrainingDataRule(BaseRule):
    """
    Detects training data loaded without validation or bias checks.

    EU AI Act Article 10: Data and data governance
    - Training datasets must be relevant, representative, free of errors
    - Data quality must be ensured through appropriate governance measures

    Example violation:
        train_data = pd.read_csv('user_data.csv')
        model.fit(train_data)  # No validation or bias checks
    """

    rule_id = "EU-AIA-DFA-006"
    article = "Art. 10 (Data Governance)"
    severity = Severity.WARNING
    title = "Training data loaded without validation"
    description = (
        "Training data is loaded and used without validation, quality checks, or bias assessment. "
        "Article 10 requires appropriate data governance measures."
    )
    suggestion = (
        "Validate training data: "
        "1) Check for data quality issues (missing values, outliers), "
        "2) Assess for bias across protected attributes, "
        "3) Verify data representativeness, "
        "4) Document data provenance and quality metrics"
    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        """Detect training data flows without validation."""
        import re

        # Look for data loading followed by model training without validation
        data_load_pattern = re.compile(
            r"(pd\.read_csv|load_dataset|pd\.read_json|pd\.read_excel)\s*\([^)]+\)", re.I
        )
        model_fit_pattern = re.compile(
            r"(model\.fit|model\.train|\.fit\(|trainer\.train)\s*\(", re.I
        )

        lines = source.splitlines()

        for i, line in enumerate(lines, 1):
            if data_load_pattern.search(line):
                # Check next 10 lines for model.fit without validation keywords
                window = "\n".join(lines[i : min(i + 10, len(lines))])

                if model_fit_pattern.search(window):
                    # Check if validation keywords are present
                    validation_keywords = [
                        "validate",
                        "check",
                        "quality",
                        "bias",
                        "clean",
                        "preprocess",
                        "verify",
                        "assert",
                    ]

                    if not any(kw in window.lower() for kw in validation_keywords):
                        yield self._finding(
                            filename=filename,
                            line=i,
                            snippet=line.strip(),
                            description=self.description,
                            suggestion=self.suggestion,
                        )


# ---------------------------------------------------------------------------
# Export All Rules
# ---------------------------------------------------------------------------

DATA_FLOW_RULES = [
    UnvalidatedLLMInputRule(),
    PIIInLogsRule(),
    SecretsInModelRule(),
    UnencryptedStorageRule(),
    PIIExfiltrationRule(),
    UnvalidatedTrainingDataRule(),
]
