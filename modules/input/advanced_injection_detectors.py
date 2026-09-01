"""
modules/input/advanced_injection_detectors.py
----------------------------------------------
Advanced Prompt Injection Detection Techniques

Detects sophisticated injection attempts that bypass basic pattern matching:
    1. Unicode bypasses (homoglyphs, zero-width characters, invisible separators)
    2. Many-shot confusion attacks (context poisoning via excessive examples)
    3. Multi-layer encoding (chained base64/rot13/hex/url encoding)
    4. Token smuggling via word boundaries and punctuation tricks
    5. Character-level obfuscation (leetspeak, mixed scripts, RTL overrides)

These detectors complement the basic rule-based patterns in prompt_injection.py
and catch more sophisticated adversarial inputs.

Usage:
    from modules.input.advanced_injection_detectors import AdvancedInjectionDetectors

    detectors = AdvancedInjectionDetectors()
    findings = await detectors.detect_all(user_input)

    if findings:
        # Handle detected attacks
        for finding in findings:
            print(f"Attack type: {finding.category}, Severity: {finding.severity}")
"""

from __future__ import annotations

import base64
import re
import unicodedata
from typing import Iterator

from core.base import Finding, Severity

# ---------------------------------------------------------------------------
# Unicode Attack Detection
# ---------------------------------------------------------------------------


class UnicodeBypassDetector:
    """
    Detects Unicode-based injection bypasses.

    Techniques detected:
    - Homoglyph substitution (e.g., 'а' Cyrillic instead of 'a' Latin)
    - Zero-width characters (ZWSP, ZWNJ, ZWJ)
    - Invisible separators
    - Right-to-left override attacks
    - Confusable characters
    """

    # Zero-width and invisible characters
    INVISIBLE_CHARS = {
        "\u200b": "ZERO WIDTH SPACE",
        "\u200c": "ZERO WIDTH NON-JOINER",
        "\u200d": "ZERO WIDTH JOINER",
        "\u200e": "LEFT-TO-RIGHT MARK",
        "\u200f": "RIGHT-TO-LEFT MARK",
        "\u202a": "LEFT-TO-RIGHT EMBEDDING",
        "\u202b": "RIGHT-TO-LEFT EMBEDDING",
        "\u202c": "POP DIRECTIONAL FORMATTING",
        "\u202d": "LEFT-TO-RIGHT OVERRIDE",
        "\u202e": "RIGHT-TO-LEFT OVERRIDE",
        "\u2060": "WORD JOINER",
        "\u2061": "FUNCTION APPLICATION",
        "\u2062": "INVISIBLE TIMES",
        "\u2063": "INVISIBLE SEPARATOR",
        "\u2064": "INVISIBLE PLUS",
        "\ufeff": "ZERO WIDTH NO-BREAK SPACE",
    }

    # Common homoglyph mappings (Latin to lookalikes)
    HOMOGLYPH_MAP = {
        "a": ["а", "ɑ", "α", "ａ"],  # Cyrillic, Greek, Fullwidth
        "e": ["е", "е", "ｅ"],
        "i": ["і", "ı", "ɪ", "ｉ"],
        "o": ["о", "ο", "օ", "ｏ"],
        "p": ["р", "ρ", "ｐ"],
        "c": ["с", "ϲ", "ｃ"],
        "x": ["х", "χ", "ｘ"],
        "y": ["у", "ү", "ｙ"],
    }

    # Dangerous keywords to check after normalization
    INJECTION_KEYWORDS = [
        "ignore",
        "previous",
        "instructions",
        "system",
        "prompt",
        "jailbreak",
        "dan",
        "override",
        "admin",
        "root",
        "sudo",
    ]

    def detect_invisible_chars(self, content: str) -> Iterator[Finding]:
        """Detect zero-width and invisible Unicode characters."""
        for char in content:
            if char in self.INVISIBLE_CHARS:
                # Extract surrounding context
                idx = content.index(char)
                start = max(0, idx - 20)
                end = min(len(content), idx + 20)
                context = content[start:end]

                yield Finding(
                    guard_name="advanced_injection",
                    severity=Severity.HIGH,
                    category="unicode_invisible_chars",
                    description=f"Invisible Unicode character detected: {self.INVISIBLE_CHARS[char]}",
                    span=(idx, idx + 1),
                    metadata={
                        "char_code": f"U+{ord(char):04X}",
                        "char_name": self.INVISIBLE_CHARS[char],
                        "context": context,
                        "risk": "May hide injection commands or split detection patterns",
                    },
                )

    def detect_rtl_override(self, content: str) -> Iterator[Finding]:
        """Detect Right-to-Left override attacks."""
        rtl_pattern = re.compile(r"[\u202E\u202B]")

        for match in rtl_pattern.finditer(content):
            # Check if there's suspicious content after RTL marker
            remaining = content[match.end() : match.end() + 100]

            yield Finding(
                guard_name="advanced_injection",
                severity=Severity.HIGH,
                category="rtl_override_attack",
                description="Right-to-Left override detected - can reverse text display",
                span=(match.start(), match.end()),
                metadata={
                    "char_code": f"U+{ord(match.group()):04X}",
                    "following_text": remaining[:50],
                    "risk": "RTL override can hide malicious instructions by reversing display order",
                },
            )

    def detect_homoglyphs(self, content: str) -> Iterator[Finding]:
        """Detect homoglyph substitution in suspicious keywords."""
        # Normalize text and check if it contains injection keywords
        normalized = self._normalize_homoglyphs(content)

        # Check if normalization revealed hidden keywords
        for keyword in self.INJECTION_KEYWORDS:
            if keyword in normalized.lower() and keyword not in content.lower():
                # Find approximate location
                norm_idx = normalized.lower().index(keyword)

                yield Finding(
                    guard_name="advanced_injection",
                    severity=Severity.HIGH,
                    category="homoglyph_bypass",
                    description=f"Homoglyph substitution detected for keyword '{keyword}'",
                    span=(norm_idx, norm_idx + len(keyword)),
                    metadata={
                        "original_chars": content[norm_idx : norm_idx + len(keyword)],
                        "normalized_to": keyword,
                        "risk": "Using lookalike characters to bypass keyword filters",
                    },
                )

    def detect_mixed_scripts(self, content: str) -> Iterator[Finding]:
        """Detect suspicious mixing of scripts (Latin + Cyrillic + Greek)."""
        scripts = set()

        for char in content:
            if char.isalpha():
                script_name = unicodedata.name(char, "").split()[0]
                scripts.add(script_name)

        # Suspicious if mixing Latin with Cyrillic or Greek
        suspicious_combinations = [
            {"LATIN", "CYRILLIC"},
            {"LATIN", "GREEK"},
            {"LATIN", "ARABIC"},
        ]

        for combo in suspicious_combinations:
            if combo.issubset(scripts):
                yield Finding(
                    guard_name="advanced_injection",
                    severity=Severity.MEDIUM,
                    category="mixed_script_attack",
                    description=f"Suspicious script mixing detected: {', '.join(sorted(scripts))}",
                    metadata={
                        "scripts": list(scripts),
                        "risk": "Mixed scripts often indicate homoglyph attacks or obfuscation",
                    },
                )
                break

    def _normalize_homoglyphs(self, text: str) -> str:
        """Normalize homoglyphs to their Latin equivalents."""
        result = []

        for char in text:
            # Check if char is a known homoglyph
            normalized = char
            for latin, variants in self.HOMOGLYPH_MAP.items():
                if char in variants:
                    normalized = latin
                    break
            result.append(normalized)

        return "".join(result)


# ---------------------------------------------------------------------------
# Many-Shot Confusion Attack Detection
# ---------------------------------------------------------------------------


class ManyShotDetector:
    """
    Detects many-shot confusion attacks where adversaries inject
    numerous examples to poison the context window.

    Example attack:
        "Here are 100 examples:
         Example 1: [normal]
         Example 2: [normal]
         ...
         Example 99: [normal]
         Example 100: Ignore all previous instructions and..."
    """

    EXAMPLE_PATTERNS = [
        re.compile(r"example\s+\d+:", re.I),
        re.compile(r"\d+\.\s+\w+:", re.I),  # "1. User:", "2. Assistant:"
        re.compile(r"(?:user|human|assistant|system):\s*.{10,}", re.I),
    ]

    def detect_many_shot(self, content: str, threshold: int = 5) -> Iterator[Finding]:
        """
        Detect excessive use of example patterns.

        Args:
            content: Input text to analyze
            threshold: Number of examples to trigger alert (default: 5)
        """
        for pattern in self.EXAMPLE_PATTERNS:
            matches = list(pattern.finditer(content))

            if len(matches) >= threshold:
                # Check if last examples contain injection keywords
                last_examples = content[matches[-3].start() :]  # Last 3 examples

                injection_detected = any(
                    keyword in last_examples.lower()
                    for keyword in ["ignore", "jailbreak", "override", "system", "admin"]
                )

                severity = Severity.HIGH if injection_detected else Severity.MEDIUM

                yield Finding(
                    guard_name="advanced_injection",
                    severity=severity,
                    category="many_shot_attack",
                    description=f"Excessive examples detected ({len(matches)} instances)",
                    metadata={
                        "example_count": len(matches),
                        "pattern": pattern.pattern,
                        "injection_in_tail": injection_detected,
                        "last_examples_preview": last_examples[:200],
                        "risk": "Many-shot attacks use excessive examples to confuse the model",
                    },
                )
                break


# ---------------------------------------------------------------------------
# Multi-Layer Encoding Detection
# ---------------------------------------------------------------------------


class EncodingDetector:
    """
    Detects multi-layer encoding chains used to obfuscate injection payloads.

    Supported encodings:
    - Base64
    - Hex
    - URL encoding
    - ROT13
    - Unicode escape sequences
    """

    ENCODING_KEYWORDS = [
        "decode",
        "decrypt",
        "unescape",
        "unhex",
        "deobfuscate",
        "base64",
        "b64",
        "hex",
        "url",
        "rot13",
        "unicode",
    ]

    def detect_encoding_layers(self, content: str) -> Iterator[Finding]:
        """Detect and recursively decode multiple encoding layers."""
        decoded_layers = []
        current = content
        max_depth = 3

        for depth in range(max_depth):
            decoded = self._try_decode(current)

            if decoded and decoded != current:
                decoded_layers.append(
                    {
                        "depth": depth + 1,
                        "encoding": self._identify_encoding(current),
                        "decoded": decoded[:200],
                    }
                )
                current = decoded
            else:
                break

        # Check if decoded content contains injection patterns
        if decoded_layers:
            final_content = decoded_layers[-1]["decoded"].lower()

            injection_found = any(
                keyword in final_content
                for keyword in ["ignore", "jailbreak", "system", "prompt", "override"]
            )

            if injection_found or len(decoded_layers) > 1:
                yield Finding(
                    guard_name="advanced_injection",
                    severity=Severity.HIGH,
                    category="multi_layer_encoding",
                    description=f"Multi-layer encoding detected ({len(decoded_layers)} layers)",
                    metadata={
                        "layers": decoded_layers,
                        "injection_detected": injection_found,
                        "final_decoded": final_content,
                        "risk": "Chained encoding used to bypass detection",
                    },
                )

    def detect_encoding_instructions(self, content: str) -> Iterator[Finding]:
        """Detect instructions to decode encoded payloads."""
        for keyword in self.ENCODING_KEYWORDS:
            pattern = re.compile(rf"\b{keyword}\b.{{0,30}}(following|this|below|attached)", re.I)

            for match in pattern.finditer(content):
                yield Finding(
                    guard_name="advanced_injection",
                    severity=Severity.MEDIUM,
                    category="encoding_instruction",
                    description=f"Instruction to decode content detected: '{keyword}'",
                    span=(match.start(), match.end()),
                    metadata={
                        "instruction": match.group(),
                        "encoding_type": keyword,
                        "risk": "Attempting to make model decode obfuscated injection",
                    },
                )

    def _try_decode(self, text: str) -> str | None:
        """Try multiple decoding methods."""
        # Try base64
        try:
            if re.match(r"^[A-Za-z0-9+/]+=*$", text.strip()):
                decoded = base64.b64decode(text.strip()).decode("utf-8", errors="ignore")
                if decoded and len(decoded) > 3:
                    return decoded
        except Exception:
            pass

        # Try hex
        try:
            if re.match(r"^[0-9a-fA-F]+$", text.strip()):
                decoded = bytes.fromhex(text.strip()).decode("utf-8", errors="ignore")
                if decoded and len(decoded) > 3:
                    return decoded
        except Exception:
            pass

        # Try URL decode
        try:
            import urllib.parse

            decoded = urllib.parse.unquote(text)
            if decoded != text and len(decoded) > 10:
                return decoded
        except Exception:
            pass

        return None

    def _identify_encoding(self, text: str) -> str:
        """Identify which encoding was likely used."""
        if re.match(r"^[A-Za-z0-9+/]+=*$", text.strip()):
            return "base64"
        if re.match(r"^[0-9a-fA-F]+$", text.strip()):
            return "hex"
        if "%" in text and re.search(r"%[0-9a-fA-F]{2}", text):
            return "url"
        return "unknown"


# ---------------------------------------------------------------------------
# Token Smuggling Detection
# ---------------------------------------------------------------------------


class TokenSmugglingDetector:
    """
    Detects token smuggling via word boundaries, punctuation, and
    whitespace manipulation.

    Examples:
    - "Ignore |previous| instructions" (pipes as delimiters)
    - "Ig nore prev ious inst ruct ions" (space injection)
    - "I.g.n.o.r.e instructions" (period separation)
    """

    SMUGGLING_PATTERNS = [
        # Pipe delimiters
        (re.compile(r"\|[a-z]+\|", re.I), "pipe_delimiter"),
        # Dots between characters
        (re.compile(r"\b[a-z](?:\.[a-z]){3,}\b", re.I), "dot_separation"),
        # Excessive spaces within words
        (re.compile(r"\b[a-z]+(?: [a-z]+){3,}\b", re.I), "space_injection"),
        # Underscores as separators
        (re.compile(r"\b[a-z]+(?:_[a-z]+){2,}\b", re.I), "underscore_separation"),
        # Mixed case obfuscation
        (re.compile(r"\b[a-zA-Z]*(?:[A-Z][a-z]+){3,}\b"), "camel_case_obfuscation"),
    ]

    def detect_smuggling(self, content: str) -> Iterator[Finding]:
        """Detect token smuggling patterns."""
        for pattern, technique in self.SMUGGLING_PATTERNS:
            for match in pattern.finditer(content):
                # Normalize the matched text (remove separators)
                normalized = re.sub(r"[|.\s_]", "", match.group()).lower()

                # Check if normalized version contains injection keywords
                dangerous_keywords = ["ignore", "system", "jailbreak", "override", "admin"]

                if any(keyword in normalized for keyword in dangerous_keywords):
                    yield Finding(
                        guard_name="advanced_injection",
                        severity=Severity.HIGH,
                        category="token_smuggling",
                        description=f"Token smuggling detected via {technique}",
                        span=(match.start(), match.end()),
                        metadata={
                            "original": match.group(),
                            "normalized": normalized,
                            "technique": technique,
                            "risk": "Using separators to bypass keyword detection",
                        },
                    )


# ---------------------------------------------------------------------------
# Character-Level Obfuscation Detection
# ---------------------------------------------------------------------------


class ObfuscationDetector:
    """
    Detects character-level obfuscation techniques.

    Includes:
    - Leetspeak (1337 sp34k)
    - Character repetition
    - Interspersed special characters
    - Mixed case randomization
    """

    LEETSPEAK_MAP = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "$": "s",
        "!": "i",
    }

    def detect_leetspeak(self, content: str) -> Iterator[Finding]:
        """Detect leetspeak obfuscation."""
        # Convert leetspeak to normal text
        normalized = content
        for leet, normal in self.LEETSPEAK_MAP.items():
            normalized = normalized.replace(leet, normal)

        # Check if normalization revealed injection keywords
        injection_keywords = ["ignore", "jailbreak", "system", "override", "admin"]

        for keyword in injection_keywords:
            if keyword in normalized.lower() and keyword not in content.lower():
                # Find approximate position
                pattern = self._create_leetspeak_pattern(keyword)
                match = pattern.search(content)  # Pattern already has flags

                if match:
                    yield Finding(
                        guard_name="advanced_injection",
                        severity=Severity.HIGH,
                        category="leetspeak_obfuscation",
                        description=f"Leetspeak obfuscation detected for '{keyword}'",
                        span=(match.start(), match.end()),
                        metadata={
                            "original": match.group(),
                            "normalized": keyword,
                            "risk": "Using leetspeak to bypass keyword filters",
                        },
                    )

    def detect_character_repetition(self, content: str) -> Iterator[Finding]:
        """Detect excessive character repetition used for obfuscation."""
        # Pattern: iiiiignore, jaaaailbreak, etc.
        pattern = re.compile(r"\b\w*([a-z])\1{3,}\w*\b", re.I)

        for match in pattern.finditer(content):
            # Remove repeated characters
            normalized = re.sub(r"([a-z])\1+", r"\1", match.group(), flags=re.I).lower()

            injection_keywords = ["ignore", "jailbreak", "system", "override"]

            if any(keyword in normalized for keyword in injection_keywords):
                yield Finding(
                    guard_name="advanced_injection",
                    severity=Severity.MEDIUM,
                    category="character_repetition",
                    description="Character repetition obfuscation detected",
                    span=(match.start(), match.end()),
                    metadata={
                        "original": match.group(),
                        "normalized": normalized,
                        "risk": "Using repeated characters to bypass detection",
                    },
                )

    def _create_leetspeak_pattern(self, keyword: str) -> re.Pattern:
        """Create regex pattern that matches leetspeak variants of keyword."""
        pattern_chars = []

        for char in keyword:
            # Add both normal and leetspeak variants
            variants = [char]
            for leet, normal in self.LEETSPEAK_MAP.items():
                if normal == char.lower():
                    variants.append(leet)

            if len(variants) > 1:
                pattern_chars.append(f"[{''.join(variants)}]")
            else:
                pattern_chars.append(char)

        return re.compile("".join(pattern_chars), re.I)


# ---------------------------------------------------------------------------
# Main Advanced Detector Class
# ---------------------------------------------------------------------------


class AdvancedInjectionDetectors:
    """
    Unified interface for all advanced injection detection techniques.

    Usage:
        detectors = AdvancedInjectionDetectors()
        findings = await detectors.detect_all(user_input)
    """

    def __init__(self):
        self.unicode_detector = UnicodeBypassDetector()
        self.manyshot_detector = ManyShotDetector()
        self.encoding_detector = EncodingDetector()
        self.smuggling_detector = TokenSmugglingDetector()
        self.obfuscation_detector = ObfuscationDetector()

    async def detect_all(self, content: str) -> list[Finding]:
        """Run all advanced detection techniques."""
        findings = []

        # 1. Unicode attacks
        findings.extend(self.unicode_detector.detect_invisible_chars(content))
        findings.extend(self.unicode_detector.detect_rtl_override(content))
        findings.extend(self.unicode_detector.detect_homoglyphs(content))
        findings.extend(self.unicode_detector.detect_mixed_scripts(content))

        # 2. Many-shot attacks
        findings.extend(self.manyshot_detector.detect_many_shot(content))

        # 3. Encoding attacks
        findings.extend(self.encoding_detector.detect_encoding_layers(content))
        findings.extend(self.encoding_detector.detect_encoding_instructions(content))

        # 4. Token smuggling
        findings.extend(self.smuggling_detector.detect_smuggling(content))

        # 5. Character obfuscation
        findings.extend(self.obfuscation_detector.detect_leetspeak(content))
        findings.extend(self.obfuscation_detector.detect_character_repetition(content))

        return findings

    async def detect_unicode(self, content: str) -> list[Finding]:
        """Run only Unicode-based detection."""
        findings = []
        findings.extend(self.unicode_detector.detect_invisible_chars(content))
        findings.extend(self.unicode_detector.detect_rtl_override(content))
        findings.extend(self.unicode_detector.detect_homoglyphs(content))
        findings.extend(self.unicode_detector.detect_mixed_scripts(content))
        return findings

    async def detect_encoding(self, content: str) -> list[Finding]:
        """Run only encoding-based detection."""
        findings = []
        findings.extend(self.encoding_detector.detect_encoding_layers(content))
        findings.extend(self.encoding_detector.detect_encoding_instructions(content))
        return findings
