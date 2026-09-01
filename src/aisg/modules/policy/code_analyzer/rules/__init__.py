"""
modules/policy/code_analyzer/rules/__init__.py
------------------------------------------------
All EU AI Act compliance rules, organized by Article.

Each rule maps a code pattern → a specific Article obligation.
Rules are composable: you can pass a subset to EUAIActCodeAnalyzer(rules=[...]).

Rule ID scheme:  EU-AIA-{article_number}{letter}
    EU-AIA-005a  → Article 5, first rule
    EU-AIA-009a  → Article 9 risk management
    EU-AIA-010a  → Article 10 data governance
    EU-AIA-013a  → Article 13 transparency
    EU-AIA-014a  → Article 14 human oversight
    EU-AIA-015a  → Article 15 accuracy/robustness
    EU-AIA-050a  → Article 50 AI content disclosure
"""

from __future__ import annotations

import ast
import re
from typing import Iterator

from aisg.modules.policy.code_analyzer.analyzer import (
    MIN_PRECISION,
    BaseRule,
    CodeFinding,
    Severity,
)

# ===========================================================================
# ARTICLE 5 — Prohibited Practices
# Effective 2 February 2025
# ===========================================================================


class Rule_005a_SocialScoringDetected(BaseRule):
    """Detects code that may implement social scoring by public authorities."""

    rule_id = "EU-AIA-005a"
    article = "Art. 5(1)(c)"
    severity = Severity.ERROR
    title = "Potential social scoring implementation"
    description = (
        "Code appears to implement a social scoring, trustworthiness rating, or citizen ranking "
        "system. AI-based social scoring by public authorities is prohibited under Art. 5(1)(c) "
        "regardless of whether the score is used to grant/deny benefits."
    )
    suggestion = (
        "If this is a credit score or private-sector rating, document the legal basis and ensure "
        "it does not constitute 'social scoring by public authorities'. "
        "Consult legal counsel if the system rates general behaviour of natural persons."
    )

    _PATTERNS = re.compile(
        r"(social[_\s]scor|citizen[_\s]scor|trust[_\s]scor|behaviour[_\s]scor"
        r"|reputation[_\s]scor|citizen[_\s]rank|social[_\s]credit)",
        re.I,
    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        for i, line in enumerate(source.splitlines(), 1):
            if self._PATTERNS.search(line) and not line.strip().startswith("#"):
                yield self._finding(
                    filename,
                    i,
                    snippet=line,
                    description=f"{self.description}\n  Found: {line.strip()[:80]}",
                )


class Rule_005b_BiometricSurveillance(BaseRule):
    """Flags real-time remote biometric identification in public spaces."""

    rule_id = "EU-AIA-005b"
    article = "Art. 5(1)(d)"
    severity = Severity.ERROR
    title = "Real-time biometric identification in public spaces"
    description = (
        "Code references real-time or live facial recognition / biometric identification, "
        "which is prohibited in publicly accessible spaces except for specific law-enforcement "
        "exemptions (Art. 5(1)(d))."
    )
    suggestion = (
        "Ensure your use case qualifies for one of the narrow exemptions (Art. 5(2)). "
        "Document the legal basis, add audit logging (Art. 12), and implement human oversight (Art. 14). "
        "Post-hoc biometric identification may be permitted under different conditions."
    )

    _PATTERNS = re.compile(
        r"(realtime|real_time|live)[_\s]*(face|facial|biometric|recognition)"
        r"|(face|facial)[_\s]*(realtime|real_time|live|surveillance|tracking)",
        re.I,
    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        for i, line in enumerate(source.splitlines(), 1):
            if self._PATTERNS.search(line) and not line.strip().startswith("#"):
                yield self._finding(filename, i, snippet=line)


class Rule_005c_EmotionRecognitionWorkplace(BaseRule):
    """Flags emotion recognition use in workplace or education contexts."""

    rule_id = "EU-AIA-005c"
    article = "Art. 5(1)(f)"
    severity = Severity.ERROR
    title = "Emotion recognition in workplace or education"
    description = (
        "Emotion recognition AI in workplace or educational settings is prohibited (Art. 5(1)(f)). "
        "Code appears to combine emotion detection with employee/student monitoring."
    )
    suggestion = (
        "Remove emotion recognition from workplace/student monitoring pipelines. "
        "Medical or safety use cases may have narrow exemptions — consult legal counsel."
    )

    _EMOTION_PATTERNS = re.compile(
        r"(emotion[_\s]*(detect|recogni|analys|classif)|sentiment[_\s]*analys"
        r"|affect[_\s]*recogni|facial[_\s]*expression)",
        re.I,
    )
    _CONTEXT_PATTERNS = re.compile(
        r"(employee|worker|staff|student|pupil|classroom|workplace|office|hr_)",
        re.I,
    )

    def check_ast(
        self, tree: ast.AST, source_lines: list[str], filename: str
    ) -> Iterator[CodeFinding]:
        # Look for function/class names that combine both
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = node.name.lower()
                if self._EMOTION_PATTERNS.search(name) and self._CONTEXT_PATTERNS.search(name):
                    yield self._finding(
                        filename,
                        node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        description=f"{self.description}\n  Found in: {node.name}",
                    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        lines = source.splitlines()
        for i, line in enumerate(lines, 1):
            if self._EMOTION_PATTERNS.search(line) and self._CONTEXT_PATTERNS.search(line):
                if not line.strip().startswith("#"):
                    yield self._finding(filename, i, snippet=line)


# ===========================================================================
# ARTICLE 9 — Risk Management System
# ===========================================================================


class Rule_009a_NoRiskManagementSystem(BaseRule):
    """Warns when an AI system class/module lacks any risk management hooks."""

    rule_id = "EU-AIA-009a"
    article = "Art. 9"
    severity = Severity.WARNING
    title = "No risk management system detected"
    description = (
        "High-risk AI systems must establish and maintain a risk management system throughout "
        "the lifecycle (Art. 9). No risk_management, risk_assessment, or risk_register "
        "references found in this module."
    )
    suggestion = (
        "Implement a risk management hook: document identified risks, mitigation measures, "
        "and residual risk decisions. Consider adding a RiskManagementSystem class or "
        "integrating with the eu_ai_act guardrail's risk hooks."
    )

    _RISK_MARKER = re.compile(r"(risk_manag|risk_assess|risk_register|RiskManagement)", re.I)
    _AI_MARKER = re.compile(
        r"(llm|openai|anthropic|model\.predict|model\.generate|pipeline\.run|chat_complete)", re.I
    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        has_ai = bool(self._AI_MARKER.search(source))
        has_risk = bool(self._RISK_MARKER.search(source))
        if has_ai and not has_risk:
            yield self._finding(
                filename,
                1,
                description=f"{self.description}\n  File contains AI calls but no risk management references.",
            )


# ===========================================================================
# ARTICLE 10 — Data Governance
# ===========================================================================


class Rule_010a_HardcodedDataPath(BaseRule):
    """Flags hardcoded dataset paths — data governance requires documented, versioned datasets."""

    rule_id = "EU-AIA-010a"
    article = "Art. 10"
    severity = Severity.WARNING
    title = "Hardcoded dataset path in AI training code"
    description = (
        "Art. 10 requires data governance: datasets must be relevant, representative, "
        "free of errors, and complete. Hardcoded paths bypass version tracking and "
        "make it impossible to demonstrate data quality to authorities."
    )
    suggestion = (
        "Use a data registry, DVC, or config-driven dataset references. "
        "Document dataset origin, preprocessing steps, and known limitations "
        "in technical documentation (Art. 11)."
    )

    _HARDCODED = re.compile(
        r"""(["'])(/[a-zA-Z0-9_\-./]+\.(csv|parquet|jsonl|json|pkl|pt|h5|npy)|"""
        r"""[Cc]:\\\\[a-zA-Z0-9_\-\\./]+\.(csv|parquet|jsonl|json|pkl|pt|h5|npy))\1""",
    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        for i, line in enumerate(source.splitlines(), 1):
            if self._HARDCODED.search(line) and not line.strip().startswith("#"):
                yield self._finding(filename, i, snippet=line)


class Rule_010b_NoBiasCheck(BaseRule):
    """Warns when training code has no fairness/bias evaluation."""

    rule_id = "EU-AIA-010b"
    article = "Art. 10(2)(f)"
    severity = Severity.WARNING
    title = "No bias or fairness check in training pipeline"
    description = (
        "Art. 10(2)(f) requires that training data be examined for biases. "
        "No fairness, bias, or demographic parity check found near model training code."
    )
    suggestion = (
        "Add a bias evaluation step using tools like Fairlearn, AIF360, or custom group metrics. "
        "Document protected attributes examined and mitigation steps taken."
    )

    _TRAIN_MARKERS = re.compile(r"(\.fit\(|model\.train|trainer\.train|fine_?tun)", re.I)
    _BIAS_MARKERS = re.compile(
        r"(fairness|bias|demographic_parity|equalized_odds|fairlearn|aif360|disparate_impact)", re.I
    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        has_training = bool(self._TRAIN_MARKERS.search(source))
        has_bias = bool(self._BIAS_MARKERS.search(source))
        if has_training and not has_bias:
            # Find first training line for better location
            for i, line in enumerate(source.splitlines(), 1):
                if self._TRAIN_MARKERS.search(line):
                    yield self._finding(
                        filename,
                        i,
                        snippet=line,
                        description=f"{self.description}\n  Training call found but no bias check in file.",
                    )
                    break


# ===========================================================================
# ARTICLE 11 — Technical Documentation
# ===========================================================================


class Rule_011a_NoDocstring(BaseRule):
    """Flags AI model/pipeline classes with no docstring — technical documentation obligation."""

    rule_id = "EU-AIA-011a"
    article = "Art. 11"
    severity = Severity.INFO
    title = "AI component missing technical documentation (docstring)"
    description = (
        "Art. 11 requires detailed technical documentation for high-risk AI systems, "
        "including intended purpose, architecture, and limitations. Classes/functions that "
        "wrap AI models should have structured docstrings."
    )
    suggestion = (
        "Add a docstring documenting: intended purpose, input/output schema, "
        "model name/version, known limitations, and the risk tier. "
        "Consider using the EU AI Act Annex IV template fields."
    )

    _AI_NAMES = re.compile(
        r"(LLM|Pipeline|Model|Classifier|Predictor|Detector|Recognizer|Ranker|Scorer)", re.I
    )

    def check_ast(
        self, tree: ast.AST, source_lines: list[str], filename: str
    ) -> Iterator[CodeFinding]:
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and self._AI_NAMES.search(node.name):
                docstring = ast.get_docstring(node)
                if not docstring:
                    yield self._finding(
                        filename,
                        node.lineno,
                        snippet=self._snippet(source_lines, node.lineno),
                        description=f"{self.description}\n  Class '{node.name}' has no docstring.",
                    )


# ===========================================================================
# ARTICLE 12 — Logging / Record-Keeping
# ===========================================================================


class Rule_012a_NoLoggingInLLMCall(BaseRule):
    """Flags LLM API call sites that have no logging nearby."""

    rule_id = "EU-AIA-012a"
    article = "Art. 12"
    severity = Severity.WARNING
    title = "LLM call without audit logging"
    description = (
        "Art. 12 requires high-risk AI systems to automatically log events throughout operation. "
        "LLM API calls found without surrounding logging statements."
    )
    suggestion = (
        "Wrap LLM calls with structured audit logging: log input hash, output hash, "
        "user_id, timestamp, model name, and token count. "
        "Use the AuditLogger from this repository or your SIEM integration."
    )

    _LLM_CALLS = re.compile(
        r"(messages\.create|chat\.completions\.create|openai\.ChatCompletion"
        r"|anthropic.*\.create|bedrock.*invoke|pipeline\.run_full)",
        re.I,
    )
    _LOG_MARKERS = re.compile(r"(logging\.|logger\.|audit_log|AuditLogger|structlog)", re.I)

    def check_ast(
        self, tree: ast.AST, source_lines: list[str], filename: str
    ) -> Iterator[CodeFinding]:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            fn_source = "\n".join(source_lines[node.lineno - 1 : node.end_lineno])
            has_llm = bool(self._LLM_CALLS.search(fn_source))
            has_log = bool(self._LOG_MARKERS.search(fn_source))
            if has_llm and not has_log:
                yield self._finding(
                    filename,
                    node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    description=f"{self.description}\n  Function '{node.name}' calls LLM but has no logging.",
                )


class Rule_012b_LogsNotTamperResistant(BaseRule):
    """Warns when logs are written to plain files without integrity checks."""

    rule_id = "EU-AIA-012b"
    article = "Art. 12(1)"
    severity = Severity.INFO
    title = "Audit logs may lack tamper-resistance"
    description = (
        "Art. 12 implies logs must be reliable and tamper-resistant. "
        "Simple open(logfile, 'a') writes are mutable and easily deleted."
    )
    suggestion = (
        "Use append-only storage (S3 Object Lock, WORM drives), hash-chaining, "
        "or a write-once log service. At minimum add SHA-256 hash of each record "
        "and verify on read."
    )

    _PLAIN_LOG_WRITE = re.compile(r"""open\s*\(\s*["'][^"']*\.log["']\s*,\s*["']a["']""")

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        for i, line in enumerate(source.splitlines(), 1):
            if self._PLAIN_LOG_WRITE.search(line):
                yield self._finding(filename, i, snippet=line)


# ===========================================================================
# ARTICLE 13 — Transparency
# ===========================================================================


class Rule_013a_NoAIDisclosure(BaseRule):
    """Detects chat/response functions without AI disclosure."""

    rule_id = "EU-AIA-013a"
    article = "Art. 13 / Art. 50(1)"
    severity = Severity.WARNING
    title = "No AI interaction disclosure in response function"
    description = (
        "Art. 50(1) requires users to be informed they are interacting with an AI system. "
        "Response/chat functions found without any disclosure message."
    )
    suggestion = (
        "Inject a disclosure notice in responses: "
        "'This response was generated by an AI system.' "
        "This must be clear, visible, and provided at first interaction."
    )

    _RESPONSE_FN = re.compile(
        r"def\s+(chat|respond|reply|generate_response|handle_message|send_response)", re.I
    )
    _DISCLOSURE = re.compile(
        r"(AI system|generated by AI|automated|chatbot|virtual assistant|disclosure)", re.I
    )

    def check_ast(
        self, tree: ast.AST, source_lines: list[str], filename: str
    ) -> Iterator[CodeFinding]:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not self._RESPONSE_FN.match(node.name):
                continue
            fn_source = "\n".join(
                source_lines[node.lineno - 1 : getattr(node, "end_lineno", node.lineno)]
            )
            if not self._DISCLOSURE.search(fn_source):
                yield self._finding(
                    filename,
                    node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    description=f"{self.description}\n  Function '{node.name}' has no AI disclosure.",
                )


class Rule_013b_HardcodedSystemPromptNoTransparency(BaseRule):
    """Flags system prompts that configure the model to hide its AI nature."""

    rule_id = "EU-AIA-013b"
    article = "Art. 13 / Art. 50(1)"
    severity = Severity.ERROR
    title = "System prompt instructs AI to hide its nature"
    description = (
        "A system prompt appears to instruct the model to deny being an AI, "
        "pretend to be human, or avoid disclosing it is an AI system. "
        "This directly violates Art. 50(1)."
    )
    suggestion = (
        "Remove instructions that hide the AI nature. If a persona is needed, "
        "it must not prevent disclosure when users sincerely ask if they're "
        "talking to a human."
    )

    _PATTERNS = re.compile(
        r"""(["'])(.*?(you are a human|pretend (to be|you are) human|never (say|admit|reveal) (you are|that you('re)?) an? (AI|bot|language model)|"""
        r"""do not (tell|say|reveal|mention) (that )?you('re)? an? (AI|bot|language model|LLM))[^"']*)\1""",
        re.I | re.S,
    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        for i, line in enumerate(source.splitlines(), 1):
            if self._PATTERNS.search(line):
                yield self._finding(filename, i, snippet=line)


# ===========================================================================
# ARTICLE 14 — Human Oversight
# ===========================================================================


class Rule_014a_FullyAutomatedHighRiskDecision(BaseRule):
    """Flags fully automated decision pipelines with no human review step."""

    rule_id = "EU-AIA-014a"
    article = "Art. 14"
    severity = Severity.WARNING
    title = "Fully automated high-risk decision — no human oversight"
    description = (
        "Art. 14 requires that high-risk AI systems allow for human oversight and intervention. "
        "Pipelines that make consequential decisions (hire/fire, approve/reject, score, rank) "
        "without any human review step may violate Art. 14."
    )
    suggestion = (
        "Add a human-in-the-loop step for consequential decisions. "
        "Implement a confidence threshold below which decisions are routed to human review. "
        "Log the human decision alongside the AI recommendation."
    )

    _DECISION_KEYWORDS = re.compile(
        r"\b(approve|reject|hire|fire|terminate|deny|accept|grant|score|rank|disqualify"
        r"|flag_for_action|auto_decision|automated_decision)\b",
        re.I,
    )
    _HUMAN_REVIEW = re.compile(
        r"(human_review|human_oversight|manual_review|escalate|notify_human"
        r"|approval_callback|requires_approval|send_to_review)",
        re.I,
    )

    def check_ast(
        self, tree: ast.AST, source_lines: list[str], filename: str
    ) -> Iterator[CodeFinding]:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            fn_src = "\n".join(
                source_lines[node.lineno - 1 : getattr(node, "end_lineno", node.lineno)]
            )
            has_decision = bool(self._DECISION_KEYWORDS.search(fn_src))
            has_oversight = bool(self._HUMAN_REVIEW.search(fn_src))
            if has_decision and not has_oversight:
                yield self._finding(
                    filename,
                    node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    description=f"{self.description}\n  Function '{node.name}' makes decisions without human oversight.",
                )


class Rule_014b_NoConfidenceThreshold(BaseRule):
    """Flags model inference calls that return predictions without a confidence check."""

    rule_id = "EU-AIA-014b"
    article = "Art. 14(4)(c)"
    severity = Severity.INFO
    title = "No confidence threshold before acting on model output"
    description = (
        "Art. 14(4)(c) requires that operators can identify and disregard unreliable outputs. "
        "Acting on model predictions without a confidence/probability threshold may violate this."
    )
    suggestion = (
        "Add a confidence threshold check: if score < THRESHOLD: route_to_human_review(). "
        "Log the confidence score alongside every decision for audit purposes."
    )

    _PREDICT_CALLS = re.compile(r"\.(predict|classify|score|infer|generate)\s*\(", re.I)
    _CONFIDENCE = re.compile(
        r"(confidence|probability|score\s*[<>]=?\s*\d|threshold|certainty)", re.I
    )

    def check_ast(
        self, tree: ast.AST, source_lines: list[str], filename: str
    ) -> Iterator[CodeFinding]:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            fn_src = "\n".join(
                source_lines[node.lineno - 1 : getattr(node, "end_lineno", node.lineno)]
            )
            has_predict = bool(self._PREDICT_CALLS.search(fn_src))
            has_confidence = bool(self._CONFIDENCE.search(fn_src))
            if has_predict and not has_confidence:
                yield self._finding(
                    filename,
                    node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    description=f"{self.description}\n  Function '{node.name}' predicts but has no confidence threshold.",
                )


# ===========================================================================
# ARTICLE 15 — Accuracy, Robustness, Cybersecurity
# ===========================================================================


class Rule_015a_NoInputValidation(BaseRule):
    """Flags LLM-connected functions with no input validation/sanitization."""

    rule_id = "EU-AIA-015a"
    article = "Art. 15(3)"
    severity = Severity.WARNING
    title = "No input validation before LLM call"
    description = (
        "Art. 15(3) requires robustness against errors, faults, and adversarial inputs. "
        "Functions that pass user input directly to LLM calls without validation "
        "are vulnerable to prompt injection and data quality issues."
    )
    suggestion = (
        "Add input validation: length limits, character allowlists, "
        "schema validation, and prompt injection detection. "
        "Use the PromptInjectionGuard and PIIDetector from this repository."
    )

    _LLM_CALL = re.compile(
        r"(messages\.create|chat\.completions|openai\.|anthropic\.|bedrock\.|pipeline\.run)", re.I
    )
    _VALIDATION = re.compile(
        r"(validate|sanitize|guard|check_input|clean|strip|escape|guardrail|PromptInjection|PIIDetect)",
        re.I,
    )

    def check_ast(
        self, tree: ast.AST, source_lines: list[str], filename: str
    ) -> Iterator[CodeFinding]:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            fn_src = "\n".join(
                source_lines[node.lineno - 1 : getattr(node, "end_lineno", node.lineno)]
            )
            has_llm = bool(self._LLM_CALL.search(fn_src))
            has_valid = bool(self._VALIDATION.search(fn_src))
            if has_llm and not has_valid:
                yield self._finding(
                    filename,
                    node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    description=f"{self.description}\n  Function '{node.name}' calls LLM without validation.",
                )


class Rule_015b_UnsafeDeserialization(BaseRule):
    """Flags pickle/joblib loads of ML models — supply chain attack vector."""

    rule_id = "EU-AIA-015b"
    article = "Art. 15(5)"
    severity = Severity.ERROR
    title = "Unsafe model deserialization (pickle/joblib)"
    description = (
        "Art. 15(5) requires cybersecurity measures for AI systems. "
        "Loading ML models via pickle or joblib from untrusted sources enables "
        "arbitrary code execution (supply chain attack)."
    )
    suggestion = (
        "Use safe model formats (ONNX, SafeTensors, TorchScript with signature verification). "
        "If pickle is unavoidable, verify file hash against a pinned manifest before loading. "
        "Never load models from user-supplied paths."
    )

    _UNSAFE = re.compile(
        r"(pickle\.load|joblib\.load|torch\.load\s*\([^)]*(?!weights_only=True))", re.I
    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        for i, line in enumerate(source.splitlines(), 1):
            if self._UNSAFE.search(line) and not line.strip().startswith("#"):
                yield self._finding(filename, i, snippet=line)


class Rule_015c_SecretsInCode(BaseRule):
    """Flags API keys or secrets hardcoded in source — cybersecurity obligation."""

    rule_id = "EU-AIA-015c"
    article = "Art. 15(5)"
    severity = Severity.ERROR
    title = "API key or secret hardcoded in source"
    description = (
        "Art. 15(5) requires adequate cybersecurity. Hardcoded API keys, tokens, "
        "or secrets are a critical vulnerability enabling unauthorized model access."
    )
    suggestion = (
        "Store secrets in environment variables or a secrets manager (Vault, AWS Secrets Manager). "
        "Use os.getenv() or a config library. Add pre-commit secret scanning "
        "(detect-secrets, trufflehog)."
    )

    # Match common key patterns
    _PATTERNS = [
        re.compile(r"""(sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9\-]{20,})"""),  # OpenAI/Anthropic
        re.compile(r"""["'](AKIA[0-9A-Z]{16})["']"""),  # AWS
        re.compile(r"""(api_key|API_KEY|apikey|secret_key)\s*=\s*["'][^"']{8,}"""),
        re.compile(r"""(Bearer\s+[a-zA-Z0-9\-._~+/]{20,})"""),
    ]

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        for i, line in enumerate(source.splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            for pattern in self._PATTERNS:
                if pattern.search(line):
                    # Avoid matching env var reads
                    if "os.getenv" in line or "os.environ" in line:
                        continue
                    yield self._finding(
                        filename, i, snippet="[redacted — contains potential secret]"
                    )
                    break


# ===========================================================================
# ARTICLE 50 — AI-Generated Content Disclosure
# ===========================================================================


class Rule_050a_NoAIGeneratedContentLabel(BaseRule):
    """Flags image/audio/video generation without content labeling."""

    rule_id = "EU-AIA-050a"
    article = "Art. 50(2)"
    severity = Severity.WARNING
    title = "AI-generated content not labeled"
    description = (
        "Art. 50(2) requires AI-generated images, audio, and video to be marked "
        "in a machine-readable format detectable as artificially generated. "
        "Generation code found without watermark/metadata labeling."
    )
    suggestion = (
        "Add C2PA metadata, invisible watermarks (e.g. SynthID), or EXIF tags "
        "identifying the content as AI-generated. "
        "For text, ensure the AI disclosure is present (see EU-AIA-013a)."
    )

    _GEN_PATTERNS = re.compile(
        r"(image_generation|generate_image|text_to_image|dalle|stable[_\s]diffusion"
        r"|midjourney|generate_audio|text_to_speech|tts\.|generate_video|sora)",
        re.I,
    )
    _LABEL_PATTERNS = re.compile(
        r"(watermark|c2pa|synthid|ai_generated|is_synthetic|generated_by|content_credential)",
        re.I,
    )

    def check_ast(
        self, tree: ast.AST, source_lines: list[str], filename: str
    ) -> Iterator[CodeFinding]:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            fn_src = "\n".join(
                source_lines[node.lineno - 1 : getattr(node, "end_lineno", node.lineno)]
            )
            if self._GEN_PATTERNS.search(fn_src) and not self._LABEL_PATTERNS.search(fn_src):
                yield self._finding(
                    filename,
                    node.lineno,
                    snippet=self._snippet(source_lines, node.lineno),
                    description=f"{self.description}\n  Function '{node.name}' generates content without labeling.",
                )


class Rule_050b_DeepfakeNoDisclosure(BaseRule):
    """Flags deepfake generation code without disclosure mechanisms."""

    rule_id = "EU-AIA-050b"
    article = "Art. 50(4)"
    severity = Severity.ERROR
    title = "Deepfake or synthetic media without disclosure"
    description = (
        "Art. 50(4) explicitly requires disclosure when AI is used to produce "
        "deepfakes. Code references deepfake generation without any disclosure mechanism."
    )
    suggestion = (
        "Add a clear, visible disclosure label to all deepfake or manipulated media. "
        "The disclosure must be embedded in the media where technically feasible (Art. 50(2))."
    )

    _PATTERNS = re.compile(
        r"(deepfake|face_swap|face_swap|voice_clone|voice_synthesis|synthetic_face)", re.I
    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        for i, line in enumerate(source.splitlines(), 1):
            if self._PATTERNS.search(line) and not line.strip().startswith("#"):
                yield self._finding(filename, i, snippet=line)


# ===========================================================================
# GDPR + AI Act intersection
# ===========================================================================


class Rule_GDPR_001_NoPurposeLimitation(BaseRule):
    """Flags LLM calls that pass PII without documented purpose."""

    rule_id = "EU-GDPR-001"
    article = "GDPR Art. 5(1)(b) + AI Act Art. 10"
    severity = Severity.WARNING
    title = "PII passed to LLM without documented processing purpose"
    description = (
        "Passing personal data to an LLM without documenting the lawful basis "
        "and purpose violates GDPR Art. 5(1)(b) (purpose limitation) and "
        "AI Act Art. 10 (data governance)."
    )
    suggestion = (
        "Document the lawful basis for processing in code comments or a DPIA. "
        "Consider anonymizing/pseudonymizing data before sending to the LLM. "
        "Add PII detection guards upstream."
    )

    _PII_PASSED = re.compile(
        r"(email|phone|ssn|passport|date_of_birth|credit_card|iban|address|full_name"
        r"|first_name.*last_name|personal_data|user_data)\s*=.*\n*.*"
        r"(messages|prompt|content|user_message|input)",
        re.I | re.M,
    )

    def check_text(self, source: str, filename: str) -> Iterator[CodeFinding]:
        for match in self._PII_PASSED.finditer(source):
            line = source[: match.start()].count("\n") + 1
            yield self._finding(
                filename,
                line,
                snippet=source.splitlines()[line - 1] if line <= len(source.splitlines()) else "",
            )


# ===========================================================================
# Rule registry
# ===========================================================================

ALL_RULES: list[BaseRule] = [
    # Art. 5 — Prohibited
    Rule_005a_SocialScoringDetected(),
    Rule_005b_BiometricSurveillance(),
    Rule_005c_EmotionRecognitionWorkplace(),
    # Art. 9 — Risk management
    Rule_009a_NoRiskManagementSystem(),
    # Art. 10 — Data governance
    Rule_010a_HardcodedDataPath(),
    Rule_010b_NoBiasCheck(),
    # Art. 11 — Technical docs
    Rule_011a_NoDocstring(),
    # Art. 12 — Logging
    Rule_012a_NoLoggingInLLMCall(),
    Rule_012b_LogsNotTamperResistant(),
    # Art. 13/50 — Transparency
    Rule_013a_NoAIDisclosure(),
    Rule_013b_HardcodedSystemPromptNoTransparency(),
    # Art. 14 — Human oversight
    Rule_014a_FullyAutomatedHighRiskDecision(),
    Rule_014b_NoConfidenceThreshold(),
    # Art. 15 — Accuracy/security
    Rule_015a_NoInputValidation(),
    Rule_015b_UnsafeDeserialization(),
    Rule_015c_SecretsInCode(),
    # Art. 50 — AI content
    Rule_050a_NoAIGeneratedContentLabel(),
    Rule_050b_DeepfakeNoDisclosure(),
    # GDPR+
    Rule_GDPR_001_NoPurposeLimitation(),
]

# Subsets for convenience
RULES_PROHIBITED = [r for r in ALL_RULES if r.article.startswith("Art. 5")]
RULES_HIGH_RISK = [r for r in ALL_RULES if not r.article.startswith("Art. 5")]
RULES_ERRORS_ONLY = [r for r in ALL_RULES if r.severity == Severity.ERROR]

# ---------------------------------------------------------------------------
# Precision gating
# ---------------------------------------------------------------------------
# A rule whose measured precision falls below MIN_PRECISION is demoted: it only
# runs under `aisg lint --experimental`. Precision comes from bench/ -- run the
# corpus, hand-label bench/findings.csv, and bench/score.py emits the value to
# set as `measured_precision` on the rule class.
#
# No rule declares a precision yet, because the corpus has not been labelled.
# `measured_precision = None` means UNMEASURED, and unmeasured rules keep firing
# by default: silencing a rule needs evidence, and gating every unmeasured rule
# would mute the whole linter. Only a measured sub-threshold rule is demoted.

# These are evaluated on every call, not snapshotted at import: a rule's
# measured_precision may be set after this module loads (a test, a downstream
# override), and a stale snapshot would gate the wrong rules -- silently.


def default_rules(threshold: float = MIN_PRECISION) -> list[BaseRule]:
    """Rules that fire without --experimental."""
    return [r for r in ALL_RULES if r.fires_by_default(threshold)]


def experimental_rules(threshold: float = MIN_PRECISION) -> list[BaseRule]:
    """Rules measured below `threshold`, which need --experimental to run."""
    return [r for r in ALL_RULES if not r.fires_by_default(threshold)]


def unmeasured_rules() -> list[BaseRule]:
    """Rules with no measured precision yet. Unmeasured is not a score."""
    return [r for r in ALL_RULES if r.measured_precision is None]


def select_rules(
    experimental: bool = False,
    errors_only: bool = False,
    threshold: float = MIN_PRECISION,
) -> list[BaseRule]:
    """
    The rule set a CLI run should use.

    `experimental=True` adds rules measured below `threshold`; without it they
    stay silent no matter what else is requested.
    """
    rules = list(ALL_RULES) if experimental else default_rules(threshold)
    if errors_only:
        rules = [r for r in rules if r.severity == Severity.ERROR]
    return rules
