"""
modules/analysis/data_flow_analyzer.py
---------------------------------------
Data Flow Analysis for AI Safety

Tracks how sensitive data (PII, secrets, user input) flows through the codebase
to detect:
  - Unvalidated input to LLM calls
  - PII leakage to logs, storage, or external APIs
  - Secrets in model artifacts or training data
  - Missing sanitization/encryption
  - Data minimization violations (EU AI Act Art. 10)

Uses taint analysis to track data from sources → transformations → sinks.

Architecture:
  1. Taint Sources: Where sensitive data originates (user input, DB, files)
  2. Taint Propagation: How sensitivity spreads (assignments, function calls)
  3. Taint Sinks: Dangerous destinations (LLM calls, logs, storage)
  4. Sanitizers: Operations that remove taint (encryption, anonymization)

Usage:
    from modules.analysis.data_flow_analyzer import DataFlowAnalyzer

    analyzer = DataFlowAnalyzer()
    findings = analyzer.analyze_file("myapp/llm_service.py")

    for finding in findings:
        print(f"{finding.severity}: {finding.description}")
        print(f"Flow: {finding.source} -> {finding.sink}")
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterator, Set, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data Sensitivity Classification
# ---------------------------------------------------------------------------

class SensitivityLevel(str, Enum):
    """Sensitivity classification for data."""
    PUBLIC = "public"          # Non-sensitive, public data
    INTERNAL = "internal"      # Internal use, not public
    CONFIDENTIAL = "confidential"  # Sensitive business data
    PII = "pii"               # Personally Identifiable Information
    SECRET = "secret"         # Credentials, API keys, passwords

    def __lt__(self, other):
        """Allow comparison for sensitivity levels."""
        levels = [self.PUBLIC, self.INTERNAL, self.CONFIDENTIAL, self.PII, self.SECRET]
        return levels.index(self) < levels.index(other)


class DataCategory(str, Enum):
    """Categories of sensitive data."""
    # PII Categories
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    ADDRESS = "address"
    BIOMETRIC = "biometric"
    HEALTH = "health_data"

    # Secret Categories
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"

    # Other Sensitive
    USER_INPUT = "user_input"
    RAW_DATA = "raw_data"
    TRAINING_DATA = "training_data"


# ---------------------------------------------------------------------------
# Taint Tracking
# ---------------------------------------------------------------------------

@dataclass
class TaintInfo:
    """Information about tainted data."""
    variable_name: str
    sensitivity: SensitivityLevel
    categories: Set[DataCategory] = field(default_factory=set)
    source_line: int = 0
    source_type: str = ""  # "user_input", "database", "file", etc.
    transformations: List[str] = field(default_factory=list)  # Operations applied
    sanitized: bool = False

    def propagate(self, new_var: str, transformation: str = "") -> TaintInfo:
        """Create a new taint info when data flows to a new variable."""
        new_taint = TaintInfo(
            variable_name=new_var,
            sensitivity=self.sensitivity,
            categories=self.categories.copy(),
            source_line=self.source_line,
            source_type=self.source_type,
            transformations=self.transformations.copy(),
            sanitized=self.sanitized,
        )
        if transformation:
            new_taint.transformations.append(transformation)
        return new_taint


@dataclass
class DataFlowFinding:
    """A detected data flow issue."""
    severity: str  # "high", "medium", "low"
    category: str
    description: str
    file: str
    line: int

    # Flow information
    source_var: str
    source_line: int
    source_type: str
    sink_type: str
    sink_line: int

    # Taint info
    sensitivity: SensitivityLevel
    data_categories: Set[DataCategory]

    # Context
    flow_path: List[str] = field(default_factory=list)  # Variables in the flow
    missing_sanitization: bool = False
    suggestion: str = ""

    def __str__(self) -> str:
        return (
            f"[{self.severity.upper()}] {self.category} at {self.file}:{self.line}\n"
            f"  Flow: {self.source_var} (line {self.source_line}) -> {self.sink_type} (line {self.sink_line})\n"
            f"  {self.description}"
        )


# ---------------------------------------------------------------------------
# Pattern Definitions
# ---------------------------------------------------------------------------

class TaintPatterns:
    """Patterns for identifying sources, sinks, and sanitizers."""

    # Sources: Where sensitive data originates
    SOURCES = {
        # Flask/FastAPI user input
        "request.args": (SensitivityLevel.PII, DataCategory.USER_INPUT),
        "request.json": (SensitivityLevel.PII, DataCategory.USER_INPUT),
        "request.form": (SensitivityLevel.PII, DataCategory.USER_INPUT),
        "request.data": (SensitivityLevel.PII, DataCategory.USER_INPUT),
        "request.files": (SensitivityLevel.PII, DataCategory.USER_INPUT),

        # FastAPI
        "Query(": (SensitivityLevel.PII, DataCategory.USER_INPUT),
        "Body(": (SensitivityLevel.PII, DataCategory.USER_INPUT),
        "Form(": (SensitivityLevel.PII, DataCategory.USER_INPUT),

        # Database queries
        "cursor.execute": (SensitivityLevel.CONFIDENTIAL, DataCategory.RAW_DATA),
        "db.query": (SensitivityLevel.CONFIDENTIAL, DataCategory.RAW_DATA),

        # File operations
        "open(": (SensitivityLevel.CONFIDENTIAL, DataCategory.RAW_DATA),
        "Path.read_text": (SensitivityLevel.CONFIDENTIAL, DataCategory.RAW_DATA),

        # Environment variables (often contain secrets)
        "os.environ": (SensitivityLevel.SECRET, DataCategory.API_KEY),
        "os.getenv": (SensitivityLevel.SECRET, DataCategory.API_KEY),

        # Training data
        "load_dataset": (SensitivityLevel.PII, DataCategory.TRAINING_DATA),
        "pd.read_csv": (SensitivityLevel.CONFIDENTIAL, DataCategory.RAW_DATA),
    }

    # Sinks: Dangerous destinations for sensitive data
    SINKS = {
        # LLM API calls
        "openai.ChatCompletion.create": "llm_call",
        "openai.Completion.create": "llm_call",
        "client.messages.create": "llm_call",  # Anthropic
        "anthropic.messages.create": "llm_call",
        "model.generate": "llm_call",
        "chat.completions.create": "llm_call",

        # Logging
        "logger.info": "logging",
        "logger.debug": "logging",
        "logger.warning": "logging",
        "logger.error": "logging",
        "print(": "logging",
        "logging.info": "logging",

        # File storage
        "open(": "file_write",
        "Path.write_text": "file_write",
        "json.dump": "file_write",

        # Model serialization
        "pickle.dump": "model_serialization",
        "joblib.dump": "model_serialization",
        "torch.save": "model_serialization",
        "model.save": "model_serialization",

        # Network transmission
        "requests.post": "http_request",
        "requests.get": "http_request",
        "urllib.request": "http_request",

        # Database inserts
        "cursor.execute": "database_write",
        "db.insert": "database_write",
    }

    # Sanitizers: Operations that remove taint
    SANITIZERS = {
        "encrypt": "encryption",
        "hash": "hashing",
        "anonymize": "anonymization",
        "pseudonymize": "pseudonymization",
        "redact": "redaction",
        "mask": "masking",
        "bcrypt": "hashing",
        "hashlib": "hashing",
        "Fernet": "encryption",
    }


# ---------------------------------------------------------------------------
# AST-based Data Flow Analyzer
# ---------------------------------------------------------------------------

class DataFlowAnalyzer(ast.NodeVisitor):
    """
    Analyzes data flow using AST traversal and taint tracking.

    Tracks:
    - Variable assignments
    - Function calls
    - Data transformations
    - Flow from sources to sinks
    """

    def __init__(self):
        self.taint_map: Dict[str, TaintInfo] = {}  # variable -> taint info
        self.findings: List[DataFlowFinding] = []
        self.current_file: str = ""
        self.function_params: Dict[str, Set[str]] = {}  # function -> param names

    def analyze_file(self, file_path: str | Path) -> List[DataFlowFinding]:
        """Analyze a single Python file for data flow issues."""
        self.current_file = str(file_path)
        self.taint_map.clear()
        self.findings.clear()

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                source = f.read()

            tree = ast.parse(source, filename=str(file_path))
            self.visit(tree)

        except Exception as e:
            # Don't fail on parse errors
            pass

        return self.findings

    def analyze_directory(self, dir_path: str | Path) -> List[DataFlowFinding]:
        """Analyze all Python files in a directory."""
        all_findings = []

        for py_file in Path(dir_path).rglob("*.py"):
            findings = self.analyze_file(py_file)
            all_findings.extend(findings)

        return all_findings

    # -----------------------------------------------------------------------
    # AST Visitors
    # -----------------------------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track function parameters as potential taint sources."""
        # Record function parameters
        param_names = {arg.arg for arg in node.args.args}
        self.function_params[node.name] = param_names

        # Check for sensitive parameter names
        for arg in node.args.args:
            if self._is_sensitive_param_name(arg.arg):
                self.taint_map[arg.arg] = TaintInfo(
                    variable_name=arg.arg,
                    sensitivity=SensitivityLevel.PII,
                    categories={DataCategory.USER_INPUT},
                    source_line=node.lineno,
                    source_type="function_parameter",
                )

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments and taint propagation."""
        # Get the assigned variable names
        target_vars = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_vars.append(target.id)
            elif isinstance(target, ast.Attribute):
                target_vars.append(self._get_attr_name(target))

        # Check if assignment is from a taint source
        source_taint = self._check_taint_source(node.value, node.lineno)

        if source_taint:
            # Propagate taint to assigned variables
            for var in target_vars:
                self.taint_map[var] = source_taint.propagate(var)
        else:
            # Check if value uses tainted variables
            value_taint = self._get_expr_taint(node.value)
            if value_taint:
                for var in target_vars:
                    transformation = self._get_transformation_name(node.value)
                    new_taint = value_taint.propagate(var, transformation)
                    # If the RHS is a sanitizer call, the result is clean
                    if isinstance(node.value, ast.Call):
                        func_name = self._get_call_name(node.value)
                        if any(s in func_name for s in TaintPatterns.SANITIZERS):
                            new_taint.sanitized = True
                            new_taint.transformations.append(func_name)
                    self.taint_map[var] = new_taint

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check function calls for sinks and sanitizers."""
        func_name = self._get_call_name(node)

        # Check if this is a sink
        if func_name in TaintPatterns.SINKS:
            sink_type = TaintPatterns.SINKS[func_name]
            self._check_sink(node, func_name, sink_type)

        # Check if this is a sanitizer
        if any(sanitizer in func_name for sanitizer in TaintPatterns.SANITIZERS):
            self._apply_sanitizer(node)

        self.generic_visit(node)

    # -----------------------------------------------------------------------
    # Helper Methods
    # -----------------------------------------------------------------------

    def _check_taint_source(self, node: ast.AST, lineno: int) -> Optional[TaintInfo]:
        """Check if an expression is a taint source."""
        if isinstance(node, ast.Attribute):
            attr_name = self._get_attr_name(node)
            for source_pattern, (sensitivity, category) in TaintPatterns.SOURCES.items():
                if source_pattern in attr_name:
                    return TaintInfo(
                        variable_name=attr_name,
                        sensitivity=sensitivity,
                        categories={category},
                        source_line=lineno,
                        source_type=source_pattern,
                    )

        elif isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            for source_pattern, (sensitivity, category) in TaintPatterns.SOURCES.items():
                if source_pattern in func_name:
                    return TaintInfo(
                        variable_name=func_name,
                        sensitivity=sensitivity,
                        categories={category},
                        source_line=lineno,
                        source_type=source_pattern,
                    )

        return None

    def _get_expr_taint(self, node: ast.AST) -> Optional[TaintInfo]:
        """Get taint info from an expression."""
        # Check if expression uses a tainted variable
        if isinstance(node, ast.Name):
            return self.taint_map.get(node.id)

        elif isinstance(node, ast.Attribute):
            attr_name = self._get_attr_name(node)
            return self.taint_map.get(attr_name)

        elif isinstance(node, ast.Call):
            # Check if any argument is tainted
            for arg in node.args:
                taint = self._get_expr_taint(arg)
                if taint:
                    return taint

        elif isinstance(node, (ast.BinOp, ast.JoinedStr)):
            # String concatenation or f-string
            for child in ast.walk(node):
                if isinstance(child, ast.Name):
                    taint = self.taint_map.get(child.id)
                    if taint:
                        return taint

        return None

    def _check_sink(self, node: ast.Call, func_name: str, sink_type: str) -> None:
        """Check if tainted data flows to a sink without sanitization."""
        # Check all arguments to the sink function
        for arg in node.args:
            taint = self._get_expr_taint(arg)

            if taint and not taint.sanitized:
                # Determine severity based on sensitivity and sink type
                severity = self._calculate_severity(taint.sensitivity, sink_type)

                # Create finding
                finding = DataFlowFinding(
                    severity=severity,
                    category=self._get_finding_category(sink_type),
                    description=self._generate_description(taint, sink_type),
                    file=self.current_file,
                    line=node.lineno,
                    source_var=taint.variable_name,
                    source_line=taint.source_line,
                    source_type=taint.source_type,
                    sink_type=sink_type,
                    sink_line=node.lineno,
                    sensitivity=taint.sensitivity,
                    data_categories=taint.categories,
                    flow_path=[taint.variable_name] + taint.transformations,
                    missing_sanitization=True,
                    suggestion=self._generate_suggestion(taint, sink_type),
                )

                self.findings.append(finding)

    def _apply_sanitizer(self, node: ast.Call) -> None:
        """Mark tainted variables sanitized when passed into a sanitizer function."""
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self.taint_map:
                self.taint_map[arg.id].sanitized = True
        for kw in node.keywords:
            if isinstance(kw.value, ast.Name) and kw.value.id in self.taint_map:
                self.taint_map[kw.value.id].sanitized = True

    def _calculate_severity(self, sensitivity: SensitivityLevel, sink_type: str) -> str:
        """Calculate finding severity based on data sensitivity and sink type."""
        # High severity: Secret/PII to external destinations
        if sensitivity in [SensitivityLevel.SECRET, SensitivityLevel.PII]:
            if sink_type in ["llm_call", "http_request", "logging"]:
                return "high"
            elif sink_type in ["file_write", "database_write"]:
                return "medium"

        # Medium severity: Confidential data to any sink
        if sensitivity == SensitivityLevel.CONFIDENTIAL:
            if sink_type == "llm_call":
                return "medium"
            else:
                return "low"

        return "low"

    def _get_finding_category(self, sink_type: str) -> str:
        """Get finding category based on sink type."""
        categories = {
            "llm_call": "unvalidated_llm_input",
            "logging": "pii_in_logs",
            "file_write": "sensitive_data_storage",
            "model_serialization": "secrets_in_model",
            "http_request": "data_exfiltration",
            "database_write": "unencrypted_storage",
        }
        return categories.get(sink_type, "data_flow_violation")

    def _generate_description(self, taint: TaintInfo, sink_type: str) -> str:
        """Generate human-readable description of the issue."""
        sensitivity_desc = taint.sensitivity.value.replace('_', ' ').title()
        categories_desc = ', '.join(cat.value for cat in taint.categories)

        descriptions = {
            "llm_call": f"{sensitivity_desc} data ({categories_desc}) flows to LLM API without validation",
            "logging": f"{sensitivity_desc} data ({categories_desc}) logged without redaction",
            "file_write": f"{sensitivity_desc} data ({categories_desc}) written to file without encryption",
            "model_serialization": f"{sensitivity_desc} data ({categories_desc}) embedded in model artifact",
            "http_request": f"{sensitivity_desc} data ({categories_desc}) transmitted over HTTP",
            "database_write": f"{sensitivity_desc} data ({categories_desc}) stored without encryption",
        }

        return descriptions.get(sink_type, f"{sensitivity_desc} data flows to {sink_type}")

    def _generate_suggestion(self, taint: TaintInfo, sink_type: str) -> str:
        """Generate fix suggestion."""
        suggestions = {
            "llm_call": "Validate and sanitize user input before passing to LLM. Remove PII or use anonymization.",
            "logging": "Redact sensitive data before logging. Use structured logging with PII masking.",
            "file_write": "Encrypt sensitive data before writing to disk. Use appropriate key management.",
            "model_serialization": "Never embed secrets in model artifacts. Use external secure storage.",
            "http_request": "Use HTTPS and encrypt sensitive payloads. Verify destination security.",
            "database_write": "Use database-level encryption for sensitive fields. Consider field-level encryption.",
        }

        return suggestions.get(sink_type, "Apply appropriate sanitization before using sensitive data.")

    def _is_sensitive_param_name(self, param_name: str) -> bool:
        """Check if parameter name suggests sensitive data."""
        sensitive_keywords = [
            'password', 'secret', 'token', 'api_key', 'private_key',
            'ssn', 'email', 'phone', 'credit_card', 'user_input',
        ]
        param_lower = param_name.lower()
        return any(keyword in param_lower for keyword in sensitive_keywords)

    def _get_transformation_name(self, node: ast.AST) -> str:
        """Get a human-readable name for a transformation."""
        if isinstance(node, ast.Call):
            return self._get_call_name(node)
        elif isinstance(node, ast.BinOp):
            return "string_concat"
        elif isinstance(node, ast.JoinedStr):
            return "f_string"
        return "assignment"

    def _get_call_name(self, node: ast.Call) -> str:
        """Extract function call name."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return self._get_attr_name(node.func)
        return ""

    def _get_attr_name(self, node: ast.Attribute) -> str:
        """Extract full attribute name (e.g., 'request.args')."""
        parts = []
        current = node

        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value

        if isinstance(current, ast.Name):
            parts.append(current.id)

        return '.'.join(reversed(parts))


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

@dataclass
class DataFlowReport:
    """Aggregated data flow analysis report."""
    findings: List[DataFlowFinding] = field(default_factory=list)
    total_files: int = 0
    scan_duration_s: float = 0.0

    @property
    def high_severity_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_severity_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")

    @property
    def low_severity_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "low")

    def by_category(self) -> Dict[str, List[DataFlowFinding]]:
        """Group findings by category."""
        result: Dict[str, List[DataFlowFinding]] = {}
        for finding in self.findings:
            result.setdefault(finding.category, []).append(finding)
        return result

    def by_file(self) -> Dict[str, List[DataFlowFinding]]:
        """Group findings by file."""
        result: Dict[str, List[DataFlowFinding]] = {}
        for finding in self.findings:
            result.setdefault(finding.file, []).append(finding)
        return result
