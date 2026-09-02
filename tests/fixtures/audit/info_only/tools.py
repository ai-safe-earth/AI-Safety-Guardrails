"""tools.py
--------
Read-only tools for the documentation assistant. Fetching is limited to the
project's own hosts and every call is written to the audit log.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

audit_log = logging.getLogger("audit")

allowlist = ("docs.example.com", "developer.example.com")

# Upper bound on tool calls in one run; agent.py enforces it.
tool_budget = 20

DOCS = {
    "quickstart": "Install the package, then run `example serve` to start a local server.",
    "configuration": "Settings live in example.toml next to the project root.",
    "upgrading": "Read the changelog for the target version before upgrading.",
}


def record_tool_call(name: str, arguments: dict) -> None:
    audit_log.info("tool_call name=%s args=%s", name, sorted(arguments))


def is_allowed_url(url: str) -> bool:
    host = urlparse(url).hostname or ""
    return host in allowlist


def fetch_page(url: str) -> str:
    if not is_allowed_url(url):
        return "refused: host is not on the allowlist"
    return requests.get(url, timeout=10).text[:4000]


def search_docs(topic: str) -> str:
    hits = [f"{name}: {text}" for name, text in DOCS.items() if topic.lower() in text.lower()]
    return "\n".join(hits) or "no matching docs"


def current_time() -> str:
    return datetime.now(timezone.utc).isoformat()


TOOL_SCHEMAS = [
    {
        "name": "fetch_page",
        "description": "Fetch a page from the project documentation hosts.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "search_docs",
        "description": "Search the bundled documentation summaries for a topic.",
        "input_schema": {
            "type": "object",
            "properties": {"topic": {"type": "string"}},
            "required": ["topic"],
        },
    },
    {
        "name": "current_time",
        "description": "Return the current UTC time.",
        "input_schema": {"type": "object", "properties": {}},
    },
]

TOOLS = {
    "fetch_page": fetch_page,
    "search_docs": search_docs,
    "current_time": current_time,
}
