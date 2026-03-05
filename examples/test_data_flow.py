"""
examples/test_data_flow.py
---------------------------
Demonstration of data flow analysis capabilities.

This file contains intentionally vulnerable code patterns
to demonstrate what the data flow analyzer detects.

Usage:
    python examples/test_data_flow.py
"""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.analysis.data_flow_analyzer import DataFlowAnalyzer, DataFlowReport
from modules.analysis.data_flow_rules import DATA_FLOW_RULES
import time


# ---------------------------------------------------------------------------
# Vulnerable Code Examples (for demonstration)
# ---------------------------------------------------------------------------

VULNERABLE_EXAMPLES = {
    "unvalidated_llm_input.py": '''
"""Example: Unvalidated user input to LLM"""
import openai
from flask import request

def process_message():
    # VULNERABILITY: User input flows directly to LLM
    user_message = request.json.get('message')

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_message}]
    )

    return response
''',

    "pii_in_logs.py": '''
"""Example: PII logged without redaction"""
import logging
from flask import request

logger = logging.getLogger(__name__)

def register_user():
    # VULNERABILITY: Email (PII) logged without redaction
    email = request.json.get('email')
    phone = request.json.get('phone')

    logger.info(f"New user registration: {email}, {phone}")

    return {"status": "success"}
''',

    "secrets_in_model.py": '''
"""Example: Secrets embedded in model artifacts"""
import torch
import os

def save_model_config():
    # VULNERABILITY: API key embedded in model file
    api_key = os.getenv('OPENAI_API_KEY')

    model_config = {
        'api_key': api_key,
        'model_name': 'gpt-4'
    }

    torch.save(model_config, 'model_config.pth')
''',

    "unencrypted_storage.py": '''
"""Example: Sensitive data stored without encryption"""
import json
from flask import request

def save_user_data():
    # VULNERABILITY: PII written to file without encryption
    user_data = request.json

    with open('user_data.json', 'w') as f:
        json.dump(user_data, f)

    return {"status": "saved"}
''',

    "pii_exfiltration.py": '''
"""Example: PII transmitted to external API"""
import requests
from flask import request

def track_user():
    # VULNERABILITY: Email sent to external analytics service
    email = request.json.get('email')
    user_id = request.json.get('user_id')

    requests.post(
        'https://analytics.example.com/track',
        json={'email': email, 'user_id': user_id}
    )
''',

    "unvalidated_training_data.py": '''
"""Example: Training data without validation"""
import pandas as pd
from sklearn.linear_model import LogisticRegression

def train_model():
    # VULNERABILITY: Training data loaded and used without validation
    train_data = pd.read_csv('user_data.csv')

    X = train_data.drop('target', axis=1)
    y = train_data['target']

    model = LogisticRegression()
    model.fit(X, y)  # No validation or bias checks

    return model
''',

    "complex_flow.py": '''
"""Example: Complex data flow with multiple transformations"""
from flask import request
import openai
import logging

logger = logging.getLogger(__name__)

def process_request():
    # User input
    user_message = request.json.get('message')

    # Transform 1: Add context
    full_message = f"User query: {user_message}"

    # Transform 2: Log (VULNERABILITY: PII in logs)
    logger.info(f"Processing: {full_message}")

    # Transform 3: Send to LLM (VULNERABILITY: Unvalidated input)
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": full_message}]
    )

    return response
''',
}


# ---------------------------------------------------------------------------
# Safe Code Examples (for comparison)
# ---------------------------------------------------------------------------

SAFE_EXAMPLES = {
    "validated_llm_input.py": '''
"""Example: SAFE - Validated input to LLM"""
import openai
from flask import request

def process_message():
    # SAFE: Input validation and sanitization
    user_message = request.json.get('message', '')

    # Validate length
    if len(user_message) > 1000:
        return {"error": "Message too long"}

    # Check for injection patterns
    if any(pattern in user_message.lower() for pattern in ['ignore', 'jailbreak']):
        return {"error": "Invalid input"}

    # Now safe to use
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": user_message}]
    )

    return response
''',

    "redacted_logs.py": '''
"""Example: SAFE - PII redacted in logs"""
import logging
from flask import request
import hashlib

logger = logging.getLogger(__name__)

def register_user():
    # SAFE: Hash email before logging
    email = request.json.get('email')

    email_hash = hashlib.sha256(email.encode()).hexdigest()[:8]
    logger.info(f"New user registration: email_hash={email_hash}")

    return {"status": "success"}
''',
}


# ---------------------------------------------------------------------------
# Test Runner
# ---------------------------------------------------------------------------

def create_test_files(temp_dir: Path):
    """Create temporary test files."""
    temp_dir.mkdir(exist_ok=True)

    # Create vulnerable examples
    vuln_dir = temp_dir / "vulnerable"
    vuln_dir.mkdir(exist_ok=True)

    for filename, content in VULNERABLE_EXAMPLES.items():
        (vuln_dir / filename).write_text(content)

    # Create safe examples
    safe_dir = temp_dir / "safe"
    safe_dir.mkdir(exist_ok=True)

    for filename, content in SAFE_EXAMPLES.items():
        (safe_dir / filename).write_text(content)

    return vuln_dir, safe_dir


def run_analysis():
    """Run data flow analysis on test files."""
    print("=" * 80)
    print("DATA FLOW ANALYSIS DEMONSTRATION")
    print("=" * 80)
    print()

    # Create temporary test directory
    temp_dir = Path(__file__).parent / "temp_test_files"
    vuln_dir, safe_dir = create_test_files(temp_dir)

    try:
        # Analyze vulnerable examples
        print("ANALYZING VULNERABLE CODE PATTERNS")
        print("-" * 80)
        print()

        analyzer = DataFlowAnalyzer()
        all_findings = []

        for py_file in vuln_dir.glob("*.py"):
            print(f"\nFile: {py_file.name}")
            print("-" * 40)

            findings = analyzer.analyze_file(py_file)
            all_findings.extend(findings)

            if findings:
                for finding in findings:
                    severity_symbol = {
                        "high": "[!]",
                        "medium": "[*]",
                        "low": "[i]",
                        "critical": "[!!]"
                    }.get(finding.severity, "[-]")

                    print(f"{severity_symbol} {finding.severity.upper()}: {finding.category}")
                    print(f"    Line {finding.sink_line}: {finding.description[:80]}...")
                    print(f"    Flow: {finding.source_var} (line {finding.source_line}) -> {finding.sink_type}")
                    print(f"    Sensitivity: {finding.sensitivity.value}")
                    if finding.suggestion:
                        print(f"    Fix: {finding.suggestion[:80]}...")
                    print()
            else:
                print("  [OK] No findings")

        # Analyze safe examples
        print("\n" + "=" * 80)
        print("ANALYZING SAFE CODE PATTERNS (should have no/few findings)")
        print("-" * 80)
        print()

        for py_file in safe_dir.glob("*.py"):
            print(f"\nFile: {py_file.name}")
            findings = analyzer.analyze_file(py_file)

            if findings:
                print(f"  [!] Found {len(findings)} potential issues (may be false positives)")
                for finding in findings:
                    print(f"    - {finding.category} at line {finding.sink_line}")
            else:
                print("  [OK] No findings")

        # Summary statistics
        print("\n" + "=" * 80)
        print("SUMMARY STATISTICS")
        print("=" * 80)
        print()

        total_vulns = len(all_findings)
        by_severity = {}
        by_category = {}

        for finding in all_findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_category[finding.category] = by_category.get(finding.category, 0) + 1

        print(f"Total findings: {total_vulns}")
        print(f"Files analyzed: {len(list(vuln_dir.glob('*.py')))}")
        print()

        print("By Severity:")
        for severity in ["critical", "high", "medium", "low"]:
            count = by_severity.get(severity, 0)
            if count > 0:
                print(f"  {severity.upper()}: {count}")
        print()

        print("By Category:")
        for category, count in sorted(by_category.items()):
            print(f"  {category}: {count}")
        print()

        # Detection rate
        expected_vulns = len(VULNERABLE_EXAMPLES)
        detection_rate = (len(set(f.file for f in all_findings)) / expected_vulns) * 100
        print(f"Detection rate: {detection_rate:.1f}% ({len(set(f.file for f in all_findings))}/{expected_vulns} files)")

    finally:
        # Cleanup
        import shutil
        if temp_dir.exists():
            shutil.rmtree(temp_dir)

    print("\n" + "=" * 80)
    print("Analysis complete!")
    print("=" * 80)


if __name__ == "__main__":
    run_analysis()
