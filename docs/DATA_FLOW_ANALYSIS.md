# Data Flow Analysis for AI Safety

## Overview

The Data Flow Analysis module tracks how sensitive data (PII, secrets, user input) flows through your AI codebase to detect security and compliance violations before they reach production.

## What is Taint Analysis?

**Taint analysis** is a program analysis technique that tracks "tainted" (sensitive/untrusted) data from sources through the program to sinks (dangerous destinations).

```
[SOURCE] → [TRANSFORMATIONS] → [SINK]
   ↓              ↓                ↓
User Input    Variables        LLM API Call
   ↓          Assignments           ↓
Database      Functions        Logging
   ↓        String Ops            ↓
Secrets      f-strings         File Storage
```

### Key Concepts

1. **Sources**: Where sensitive data originates
   - User input (Flask/FastAPI request objects)
   - Database queries
   - File reads
   - Environment variables (secrets)
   - Training datasets

2. **Sinks**: Dangerous destinations for sensitive data
   - LLM API calls (prompt injection risk)
   - Logging statements (data leakage)
   - File writes (unencrypted storage)
   - HTTP requests (exfiltration)
   - Model serialization (embedded secrets)

3. **Sanitizers**: Operations that remove taint
   - Encryption
   - Hashing
   - Anonymization
   - Redaction
   - Validation

4. **Taint Propagation**: How taint spreads
   - Variable assignments: `b = a` (if `a` is tainted, so is `b`)
   - String operations: `f"Hello {user_input}"` (taint propagates)
   - Function calls: Taint flows through parameters

---

## Sensitivity Levels

Data is classified into 5 sensitivity levels:

| Level | Description | Examples |
|-------|-------------|----------|
| **SECRET** | Credentials, API keys | `os.getenv('API_KEY')`, passwords |
| **PII** | Personally Identifiable Information | Email, phone, SSN, health data |
| **CONFIDENTIAL** | Sensitive business data | Internal reports, customer data |
| **INTERNAL** | Internal-use only | Employee IDs, internal docs |
| **PUBLIC** | Non-sensitive | Public documentation |

---

## Detection Capabilities

### 1. Unvalidated Input to LLM

**What it detects**: User input flowing directly to LLM APIs without validation.

**Violation Example**:
```python
from flask import request
import openai

def process_message():
    # VIOLATION: No validation
    user_message = request.json.get('message')

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_message}]
    )
```

**Why it matters**:
- **EU AI Act Art. 15**: Systems must be resilient against adversarial attacks
- **Security risk**: Prompt injection, jailbreaking
- **Data risk**: Uncontrolled data to third-party APIs

**How to fix**:
```python
def process_message():
    user_message = request.json.get('message', '')

    # Validate length
    if len(user_message) > 1000:
        raise ValueError("Message too long")

    # Check for injection patterns
    from modules.input.prompt_injection import PromptInjectionGuard
    guard = PromptInjectionGuard()
    result = await guard.check(user_message, {})

    if not result.passed:
        raise ValueError("Invalid input")

    # Now safe
    response = openai.ChatCompletion.create(...)
```

---

### 2. PII in Logs

**What it detects**: Personal data logged without redaction.

**Violation Example**:
```python
import logging
from flask import request

logger = logging.getLogger(__name__)

def register_user():
    # VIOLATION: Email logged in plaintext
    email = request.json.get('email')
    logger.info(f"New registration: {email}")
```

**Why it matters**:
- **GDPR Art. 5(1)(f)**: Integrity and confidentiality
- **Privacy risk**: PII exposed in log aggregation systems
- **Compliance**: Logs may be retained longer than data retention policies allow

**How to fix**:
```python
import hashlib

def register_user():
    email = request.json.get('email')

    # Hash email for logging
    email_hash = hashlib.sha256(email.encode()).hexdigest()[:8]
    logger.info(f"New registration: email_hash={email_hash}")
```

---

### 3. Secrets in Model Artifacts

**What it detects**: API keys or credentials embedded in saved models.

**Violation Example**:
```python
import torch
import os

def save_model():
    # VIOLATION: API key embedded in model
    api_key = os.getenv('OPENAI_API_KEY')

    model_config = {'api_key': api_key}
    torch.save(model_config, 'model.pth')
```

**Why it matters**:
- **EU AI Act Art. 15**: Cybersecurity
- **Security risk**: Models may be shared, leaked, or stolen
- **Impact**: Complete compromise of API access

**How to fix**:
```python
def save_model():
    # Only save model weights, not secrets
    torch.save(model.state_dict(), 'model.pth')

    # Secrets stay in secure storage
    # At runtime, load from environment variables
```

---

### 4. Unencrypted Sensitive Storage

**What it detects**: Sensitive data written to files without encryption.

**Violation Example**:
```python
import json
from flask import request

def save_user_data():
    # VIOLATION: PII written in plaintext
    user_data = request.json

    with open('user_data.json', 'w') as f:
        json.dump(user_data, f)
```

**Why it matters**:
- **GDPR Art. 32**: Security of processing requires encryption
- **Risk**: Data at rest is vulnerable to theft
- **Compliance**: Breach notification requirements if leaked

**How to fix**:
```python
from cryptography.fernet import Fernet

def save_user_data():
    user_data = request.json

    # Encrypt before writing
    key = Fernet.generate_key()  # Store key securely!
    cipher = Fernet(key)
    encrypted = cipher.encrypt(json.dumps(user_data).encode())

    with open('user_data.bin', 'wb') as f:
        f.write(encrypted)
```

---

### 5. PII to External APIs

**What it detects**: Personal data transmitted to third-party services.

**Violation Example**:
```python
import requests
from flask import request

def track_user():
    # VIOLATION: Email sent to analytics
    email = request.json.get('email')

    requests.post(
        'https://analytics.example.com/track',
        json={'email': email}
    )
```

**Why it matters**:
- **GDPR Art. 6**: Requires legal basis for processing
- **GDPR Art. 44**: International transfers need safeguards
- **EU AI Act Art. 10**: Data governance requirements

**How to fix**:
```python
def track_user():
    email = request.json.get('email')

    # Hash email before transmission
    email_hash = hashlib.sha256(email.encode()).hexdigest()

    requests.post(
        'https://analytics.example.com/track',
        json={'email_hash': email_hash}  # Anonymized
    )
```

---

### 6. Unvalidated Training Data

**What it detects**: Training data loaded without quality checks or bias assessment.

**Violation Example**:
```python
import pandas as pd
from sklearn.linear_model import LogisticRegression

def train_model():
    # VIOLATION: No validation
    train_data = pd.read_csv('user_data.csv')

    X = train_data.drop('target', axis=1)
    y = train_data['target']

    model = LogisticRegression()
    model.fit(X, y)  # No bias checks!
```

**Why it matters**:
- **EU AI Act Art. 10**: Data governance and quality requirements
- **Bias risk**: Unvalidated data may contain biases
- **Quality risk**: Errors in training data degrade model performance

**How to fix**:
```python
def train_model():
    train_data = pd.read_csv('user_data.csv')

    # Validate data quality
    assert not train_data.isnull().any().any(), "Missing values detected"
    assert len(train_data) >= 1000, "Insufficient training data"

    # Check for bias
    from fairlearn.metrics import demographic_parity_ratio
    # ... perform bias assessment ...

    # Document data provenance
    metadata = {
        'source': 'user_data.csv',
        'rows': len(train_data),
        'bias_score': bias_score,
        'quality_checks_passed': True
    }

    # Now safe to train
    model.fit(X, y)
```

---

## Usage

### Basic Analysis

```python
from modules.analysis.data_flow_analyzer import DataFlowAnalyzer

analyzer = DataFlowAnalyzer()

# Analyze a single file
findings = analyzer.analyze_file("myapp/llm_service.py")

for finding in findings:
    print(f"{finding.severity}: {finding.category}")
    print(f"Line {finding.sink_line}: {finding.description}")
    print(f"Flow: {finding.source_var} -> {finding.sink_type}")
```

### Analyze Entire Project

```python
# Analyze directory
findings = analyzer.analyze_directory("myapp/")

# Group by severity
high_severity = [f for f in findings if f.severity == "high"]
print(f"Critical issues: {len(high_severity)}")
```

### Integration with CI/CD

Add to your pipeline:

```bash
# Scan for data flow violations
python -m modules.analysis.data_flow_analyzer src/ --fail-on-high

# Generate report
python -m modules.analysis.data_flow_analyzer src/ --format json > dataflow-report.json
```

---

## Configuration

### Source Patterns

Add custom taint sources:

```python
from modules.analysis.data_flow_analyzer import TaintPatterns, SensitivityLevel, DataCategory

# Add your custom source
TaintPatterns.SOURCES["my_custom_input"] = (SensitivityLevel.PII, DataCategory.USER_INPUT)
```

### Sink Patterns

Add custom sinks:

```python
# Add custom sink
TaintPatterns.SINKS["my_api_call"] = "external_api"
```

### Sanitizer Patterns

Register sanitizers:

```python
# Mark functions as sanitizers
TaintPatterns.SANITIZERS["my_sanitize_func"] = "sanitization"
```

---

## Limitations

### Current Limitations

1. **Interprocedural Analysis**: Limited tracking across function boundaries
2. **Aliasing**: May not track all variable aliases
3. **Dynamic Dispatch**: Cannot analyze runtime polymorphism
4. **External Libraries**: Limited visibility into library internals

### False Negatives (Missed Vulnerabilities)

- Complex control flow (nested conditionals)
- Indirect taint propagation through containers
- Dynamically constructed variable names

### False Positives (Incorrect Warnings)

- Data that was sanitized but analyzer didn't recognize
- Context-specific safety (e.g., internal-only APIs)
- Overly conservative assumptions

**Recommendation**: Use data flow analysis as one layer in defense-in-depth:
1. Static analysis (data flow)
2. Runtime guardrails
3. Manual code review
4. Penetration testing

---

## Performance

### Benchmarks

| Codebase Size | Analysis Time | Memory Usage |
|---------------|---------------|--------------|
| Small (100 files) | ~2s | ~50MB |
| Medium (1000 files) | ~20s | ~200MB |
| Large (10000 files) | ~3min | ~1GB |

### Optimization Tips

1. **Incremental Analysis**: Only analyze changed files in CI
2. **Parallel Processing**: Use multiprocessing for large codebases
3. **Caching**: Cache results between runs
4. **Selective Scanning**: Focus on high-risk modules first

---

## EU AI Act Compliance

Data flow analysis supports compliance with:

| Article | Requirement | How Data Flow Helps |
|---------|-------------|---------------------|
| **Art. 10** | Data governance | Detect unvalidated training data |
| **Art. 15** | Cybersecurity | Detect unvalidated input to models |
| **GDPR Art. 5** | Purpose limitation | Detect PII misuse |
| **GDPR Art. 25** | Data minimization | Detect excessive data collection |
| **GDPR Art. 32** | Security | Detect unencrypted storage |

---

## Test Results

From our demonstration (`examples/test_data_flow.py`):

```
Total findings: 3/7 files
Detection rate: 42.9%

By Severity:
  HIGH: 2
  MEDIUM: 1

By Category:
  pii_in_logs: 2
  sensitive_data_storage: 1
```

**Note**: Detection rate will improve with enhanced inter procedural analysis in future versions.

---

## Future Enhancements

Planned improvements:
- [ ] Interprocedural taint tracking (cross-function flows)
- [ ] Container tracking (lists, dicts)
- [ ] Path-sensitive analysis (different branches)
- [ ] LLM-assisted taint source identification
- [ ] Integration with runtime monitoring
- [ ] Visual flow graphs
- [ ] Custom rule DSL

---

## References

- [Taint Analysis Overview](https://en.wikipedia.org/wiki/Taint_checking)
- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
- [EU AI Act - Data Governance (Art. 10)](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689)
- [GDPR Security Requirements (Art. 32)](https://gdpr-info.eu/art-32-gdpr/)

---

## Support

For questions or issues:
- Review examples: `/examples/test_data_flow.py`
- Check source: `/modules/analysis/data_flow_analyzer.py`
- File issues: GitHub Issues
