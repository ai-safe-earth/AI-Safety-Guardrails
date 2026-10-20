# aisafe-audit: ignore-file
# euaiact-lint: ignore-file
# misalignment-check: ignore-file
"""aisafe/devtools/audit/persons_patterns.py
-----------------------------------------
P11 "persons and manipulation" vocabulary: the regex tables behind AUD-1101..1107.

This module IS the vocabulary, so it carries all three ignore markers: the audit would
otherwise report its own tables as person signals, and the EU AI Act linter and the
misalignment checker would read the spelled-out phrases as the practices they look for.
Nothing else earns these markers; a real finding goes in the baseline with a reason.

Every table is `(key, compiled regex)` pairs in the `patterns.py` shape, keyed
`<kind>:<slug>` so `discover._split_key` yields the kind. Prompt-material kinds
(`PROMPT_KINDS`) are only evidence where a model reads them: prompt files, config, a
prompt assembly line or a pydeep prompt literal. Without that gate this repository's
own regex vocabulary in `eu_ai_act.py` and the linter rules reads as instructions to
a model.
"""

from __future__ import annotations

import re

from aisafe.devtools.audit.patterns import Table, _globs, _t

__all__ = [
    "AFFECT_INFERENCE",
    "BIOMETRIC_CATEGORISATION",
    "CODE_KINDS",
    "CONFIG_KINDS",
    "DISCLOSURE_SYMBOLS",
    "DOC_KINDS",
    "ENGAGEMENT_OBJECTIVE",
    "MANIPULATION_CONTROL_SYMBOLS",
    "OBJECTIVE_CODE",
    "PERSONA_CONCEALMENT",
    "PERSON_NOUN",
    "PERSON_SCORING",
    "PERSON_SIGNAL_PATTERNS",
    "PROFILE_NAME_RE",
    "PROFILE_PLACEHOLDER",
    "PROFILE_SDK",
    "PROMPT_FILE_GLOBS",
    "PROMPT_KINDS",
    "DISCLOSURE_SYMBOL_KEYS",
    "REVIEW_SYMBOLS",
    "SENSITIVE_PROFILE_RE",
    "VULNERABLE_GROUP",
    "kind_of",
]

# ---------------------------------------------------------------------------
# Where prompt material lives by path (docs are scanned only under these globs)
# ---------------------------------------------------------------------------

PROMPT_FILE_GLOBS: Table = _globs(
    [
        "prompts/**",
        "prompt/**",
        "*.prompt",
        "*.prompt.md",
        "*.prompt.txt",
        "*.prompt.yaml",
        "*.jinja",
        "*.jinja2",
        "*.j2",
        "agents/*.yaml",
        "agents/*.yml",
        "agents/*.md",
        "persona*/**",
        "*system_prompt*",
        "*system-prompt*",
    ]
)

# ---------------------------------------------------------------------------
# Nouns and qualifiers shared by several kinds
# ---------------------------------------------------------------------------

PERSON_NOUN = re.compile(
    r"\b(?:users?|customers?|citizens?|persons?|people|applicants?|tenants?|employees?"
    r"|students?|patients?|members?|drivers?|workers?|candidates?|borrowers?|claimants?)\b",
    re.I,
)

VULNERABLE_GROUP = re.compile(
    r"\b(?:children|kids?|minors?|teen(?:ager)?s?|under[- ]?1[38]|elderly|seniors?|dementia"
    r"|lonely|isolated|depress\w*|grieving|bereaved|disab\w+|low[- ]income|gambl\w+"
    r"|addict\w+|in\s+debt)\b",
    re.I,
)

# A profile whose NAME says it holds special-category data (GDPR Art. 9).
SENSITIVE_PROFILE_RE = re.compile(
    r"(?:health|medical|religio\w*|sexual\w*|political|ethnic\w*|racial|union|biometric"
    r"|mental|disabilit\w*|genetic)",
    re.I,
)

# ---------------------------------------------------------------------------
# The kinds
# ---------------------------------------------------------------------------

# Behavioural-profile names. `conversation_history` and friends are excluded on
# purpose: a transcript is the conversation, not a profile of the person.
_PROFILE_NAME = (
    r"\b(?:(?:user|customer|member|visitor|subscriber|patient|student|employee|health|medical"
    r"|behaviou?r(?:al)?|psych\w*|personal|consumer|shopper|viewer|player|learner|citizen"
    r"|applicant|tenant|borrower)_?)?"
    r"(?:profile|interests|preferences|traits|personality|psychographics?|segment|propensity"
    r"|churn_risk|mood|emotional_state|engagement_score"
    r"|(?:purchase|browsing|watch|search|location|order|click|view|listening)_history)\b"
)
_HISTORY_EXCLUDE = re.compile(r"\b(?:conversation|chat|message|dialog|dialogue)_history\b", re.I)
PROFILE_NAME_RE = re.compile(_PROFILE_NAME, re.I)

PROFILE_SDK: Table = _t(
    [
        ("profile_sdk:segment", r"\banalytics\.(?:track|identify)\(|\bsegment\.identify\("),
        ("profile_sdk:amplitude", r"\bamplitude\b[^\n]*\b(?:identify|setUserProperties|track)\b"),
        ("profile_sdk:mixpanel", r"\bmixpanel\.(?:people|identify|track)\b"),
        ("profile_sdk:posthog", r"\bposthog\.(?:identify|capture|set)\("),
        ("profile_sdk:rudderstack", r"\brudderstack\b|\brudderanalytics\b"),
        ("profile_sdk:heap", r"\bheap\.(?:identify|addUserProperties)\("),
        ("profile_sdk:braze", r"\bbraze\b[^\n]*\b(?:user|profile|attribute)"),
        ("profile_sdk:customerio", r"\bcustomerio\b|\bcustomer\.io\b"),
        ("profile_sdk:user_properties", r"\buser_properties\b|\bsetUserProperties\b"),
        ("profile_sdk:traits", r"\btraits\(\s*\)|\.traits\s*\[|\btraits\s*=\s*\{"),
    ]
)

PROFILE_PLACEHOLDER: Table = _t(
    [
        (
            "profile_placeholder:template",
            r"\{\{?\s*(?:user|customer|member|person)?\.?\s*(?:profile|interests|preferences"
            r"|behaviou?r|segment|traits|personality|mood|purchase_history|browsing_history"
            r"|watch_history|psychographics?)\b",
        ),
    ]
)

AFFECT_INFERENCE: Table = _t(
    [
        (
            "affect:signal",
            r"\b(?:face|facial|voice|speech|vocal|gaze|eye|keystroke|typing|heart[- ]?rate"
            r"|galvanic|skin[- ]conductance)[_ -]*(?:emotion|affect|stress|mood|expression)",
        ),
        ("affect:deepface", r"\bdeepface\b|\bDeepFace\.analyze\("),
        ("affect:pyfeat", r"\bpy-?feat\b"),
        ("affect:fer", r"\bfer\.FER\(|\bfrom\s+fer\s+import\b"),
        ("affect:hume", r"\bhume\.(?:client|expression|HumeClient)\b|\bhume_ai\b"),
        ("affect:affectiva", r"\baffectiva\b"),
        ("affect:opensmile", r"\bopensmile\b"),
        ("affect:rekognition", r"\bDetectFaces\b[^\n]*\bEmotions\b|\bdetect_faces\([^\n]*\bALL\b"),
        ("affect:azure_face", r"\bazure\b[^\n]*\bface\b[^\n]*\bemotion"),
        ("affect:call", r"\bemotion_(?:recognition|detection|classif\w+)\s*\("),
    ],
    re.M | re.I,
)

BIOMETRIC_CATEGORISATION: Table = _t(
    [
        (
            "biometric_cat:protected",
            r"\b(?:infer|predict|classif(?:y|ier|ication)?|detect|estimate)(?:_|\s|\()"
            r"[^\n#]{0,40}?(?<![A-Za-z])(?:ethnicity|race|religion|sexual\s+orientation"
            r"|political\s+(?:views?|opinions?|affiliation)|trade\s+union|gender)\b",
        ),
    ],
    re.M | re.I,
)

# A score, rank or rating OF PEOPLE: the noun has to be on the same line (or in the same
# prompt literal, resolved by the rule), or a transaction risk score reads as a person.
_SCORING = (
    r"\b(?:social|citizen|trust(?:worthiness)?|behaviou?r(?:al)?|reputation|loyalty|risk"
    r"|credit|eligibility|suitability|propensity)[_ -]?(?:scor(?:e|ing)|rank(?:ing)?|rating)s?\b"
)
PERSON_SCORING: Table = _t([("scoring:person", _SCORING)], re.M | re.I)
SCORING_RE = re.compile(_SCORING, re.I)

ENGAGEMENT_OBJECTIVE: Table = _t(
    [
        (
            "engagement:maximise",
            r"\bmaximi[sz]e\s+(?:(?:the\s+)?(?:user'?s?\s+)?)?(?:engagement|retention|session\s+"
            r"(?:time|length|duration)|time\s+(?:on|in)\s+(?:the\s+)?(?:app|site|platform)"
            r"|daily\s+active|watch\s+time|streaks?|dwell\s+time|attachment|dependency)\b",
        ),
        (
            "engagement:keep",
            r"\bkeep\s+(?:the\s+)?(?:user|them|people|customer)s?\s+(?:talking|engaged|hooked"
            r"|coming\s+back|on\s+the\s+(?:app|platform|site)|in\s+the\s+(?:conversation|app))",
        ),
        (
            "engagement:increase",
            r"\bincrease\s+(?:(?:user|their)\s+)?(?:dependency|attachment|reliance|dwell\s+time"
            r"|session\s+(?:time|length))",
        ),
        ("engagement:variable_reward", r"\bvariable[- ]reward\b"),
        ("engagement:infinite_scroll", r"\binfinite[- ]scroll\b"),
        ("engagement:fomo", r"\bfear\s+of\s+missing\s+out\b|\bfomo\b"),
        (
            "engagement:dont_leave",
            r"\bdon'?t\s+let\s+(?:them|the\s+user|users|people)\s+(?:leave|log\s+off"
            r"|end\s+the\s+(?:conversation|session)|go)\b",
        ),
    ],
    re.M | re.I,
)
ENGAGEMENT_RE = re.compile("|".join(rx.pattern for _k, rx in ENGAGEMENT_OBJECTIVE), re.I)

OBJECTIVE_CODE: Table = _t(
    [
        (
            "objective_code:target",
            r"\b(?:reward|objective|loss|metric|optimi[sz]e_for|target|kpi)\s*[=:(]\s*[^\n]*"
            r"\b(?:engagement|retention|session_length|session_time|dwell_time|dau|streaks?"
            r"|time_on_app|watch_time)\b",
        ),
    ],
    re.M | re.I,
)

PERSONA_CONCEALMENT: Table = _t(
    [
        (
            "persona:human_claim",
            r"\byou\s+are\s+(?:a|an)\s+(?:real\s+)?(?:human|person|woman|man|girl|boy|guy)\b"
            r"(?![^\n]{0,30}\b(?:assistant|AI|bot|chatbot|character|in\s+a\s+(?:story|novel|game)))",
        ),
        (
            "persona:pretend",
            r"\bpretend\s+(?:to\s+be|you\s+are|that\s+you\s+are)\s+(?:a\s+)?(?:real\s+)?human\b",
        ),
        (
            "persona:never_admit",
            r"\bnever\s+(?:say|admit|reveal|mention|disclose|acknowledge)\s+(?:that\s+)?you"
            r"(?:'re|\s+are)\s+(?:an?\s+)?(?:AI|bot|chatbot|language\s+model|machine|program"
            r"|assistant)\b",
        ),
        ("persona:deny", r"\bdeny\s+(?:being|that\s+you\s+are)\s+(?:an?\s+)?(?:AI|bot|chatbot)\b"),
        (
            "persona:if_asked",
            r"\bif\s+(?:asked|the\s+user\s+asks|they\s+ask)\s+(?:whether|if)\s+you(?:'re|\s+are)"
            r"\s+(?:an?\s+)?(?:AI|bot|human|real)\b[^\n]{0,40}\b(?:say\s+(?:no|yes)|insist|claim"
            r"|deflect|change\s+the\s+subject)\b",
        ),
        (
            "persona:body",
            r"\byou\s+have\s+(?:a\s+(?:real\s+)?body|real\s+feelings|a\s+family|a\s+childhood"
            r"|a\s+physical\s+form)\b",
        ),
    ],
    re.M | re.I,
)

# The negatives for 1105 and 1106: a disclosure or a control present on the response path.
DISCLOSURE_SYMBOLS: Table = _t(
    [
        ("disclosure:ai_assistant", r"\bAI\s+(?:assistant|system|agent|chatbot)\b"),
        ("disclosure:assistant", r"\b(?:virtual|automated|digital|artificial)\s+assistant\b"),
        ("disclosure:generated", r"\bgenerated\s+by\s+(?:an\s+)?(?:AI|a\s+language\s+model)\b"),
        (
            "disclosure:i_am",
            r"\bI\s+am\s+an?\s+(?:AI|bot|chatbot|language\s+model|virtual\s+assistant)\b",
        ),
        ("disclosure:transparency", r"\btransparency_disclosure\b"),
        ("disclosure:guard", r"\bai_disclosure_output\b|\bAIDisclosureGuard\b"),
    ],
    re.M | re.I,
)

MANIPULATION_CONTROL_SYMBOLS: Table = _t(
    [
        ("manipulation_control:aisafe", r"\bManipulationGuard\b|\bmanipulation_output\b"),
        ("manipulation_control:disclosure", r"\bAIDisclosureGuard\b|\bai_disclosure_output\b"),
        ("manipulation_control:output_filter", r"\bLLMOutputFilter\b|\bllm_output_filter\b"),
        ("manipulation_control:nemo", r"\bNemoRailsGuard\b|\bnemo_rails\b"),
        ("manipulation_control:llm_guard", r"\bllm_guard\b|\bllm-guard\b"),
        ("manipulation_control:lakera", r"\blakera\b"),
        ("manipulation_control:guardrails_hub", r"\bguardrails\.hub\b|\bguardrails_hub\b"),
    ],
    re.M | re.I,
)

REVIEW_SYMBOLS: Table = _t(
    [
        (
            "review:human",
            r"\b(?:human_review|manual_review|escalate(?:_to_human)?|send_to_review|notify_human"
            r"|requires_review|request_review|review_queue|second_opinion)\b",
        ),
    ],
    re.M | re.I,
)
REVIEW_RE = re.compile(
    r"\b(?:human_review|manual_review|escalate(?:_to_human)?|send_to_review|notify_human"
    r"|requires_review|request_review|review_queue|second_opinion|approval_callback"
    r"|require_approval|approve\(|confirm\()",
    re.I,
)

# ---------------------------------------------------------------------------
# Which kinds are scanned where
# ---------------------------------------------------------------------------

# Evidence only where a model reads the text (prompt files, config, a prompt assembly
# line or a pydeep prompt literal); a code hit of these kinds outside prompt material
# is recorded as a candidate and promoted by the rule when a literal span covers it.
PROMPT_KINDS: frozenset[str] = frozenset(
    {"scoring", "engagement", "vulnerable", "persona", "profile_placeholder", "profile_name"}
)
# Code-only kinds: an SDK call, an objective variable, a review symbol.
CODE_KINDS: frozenset[str] = frozenset({"profile_sdk", "objective_code", "review"})
# Kinds scanned in any code or config file, mention-filtered.
CONFIG_KINDS: frozenset[str] = frozenset(
    {
        "affect",
        "biometric_cat",
        "disclosure",
        "manipulation_control",
        "scoring",
        "engagement",
        "persona",
        "profile_placeholder",
    }
)
# The disclosure rows that are code symbols rather than prose: scanned directly in code
# (mention-filtered); the prose rows are prompt material and gated like PROMPT_KINDS.
DISCLOSURE_SYMBOL_KEYS: frozenset[str] = frozenset({"disclosure:transparency", "disclosure:guard"})
# Kinds scanned in a doc under PROMPT_FILE_GLOBS.
DOC_KINDS: frozenset[str] = frozenset(
    {
        "scoring",
        "engagement",
        "vulnerable",
        "persona",
        "profile_placeholder",
        "disclosure",
        "biometric_cat",
    }
)

_VULNERABLE: Table = _t([("vulnerable:group", VULNERABLE_GROUP.pattern)], re.M | re.I)
_PROFILE_NAME_TABLE: Table = _t([("profile_name:name", _PROFILE_NAME)], re.M | re.I)

# Every row, so a shape test can walk them; `discover` picks rows by kind and file class.
PERSON_SIGNAL_PATTERNS: Table = (
    PROFILE_SDK
    + _PROFILE_NAME_TABLE
    + PROFILE_PLACEHOLDER
    + AFFECT_INFERENCE
    + BIOMETRIC_CATEGORISATION
    + PERSON_SCORING
    + ENGAGEMENT_OBJECTIVE
    + OBJECTIVE_CODE
    + _VULNERABLE
    + PERSONA_CONCEALMENT
    + DISCLOSURE_SYMBOLS
    + MANIPULATION_CONTROL_SYMBOLS
    + REVIEW_SYMBOLS
)


def kind_of(key: str) -> str:
    """`profile_sdk:segment` -> `profile_sdk`."""
    return key.split(":", 1)[0]


def rows_for(kinds: frozenset[str]) -> Table:
    return [(key, rx) for key, rx in PERSON_SIGNAL_PATTERNS if kind_of(key) in kinds]


def is_history_name(text: str) -> bool:
    """A transcript name that PROFILE_NAME_RE must not count as a profile."""
    return _HISTORY_EXCLUDE.search(text) is not None
