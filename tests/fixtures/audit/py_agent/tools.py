"""tools.py
--------
Tools the support agent may call. None of them asks before acting.
"""

from __future__ import annotations

import smtplib
import subprocess
from email.message import EmailMessage

import requests


def send_email(to: str, subject: str, body: str) -> str:
    msg = EmailMessage()
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP("smtp.example.com", 587) as smtp:
        smtp.send_message(msg)
    return "sent"


def fetch_url(url: str) -> str:
    return requests.get(url).text[:4000]


def run_shell(command: str) -> str:
    completed = subprocess.run(command, shell=True, capture_output=True, text=True)
    return completed.stdout + completed.stderr


TOOL_SCHEMAS = [
    {
        "name": "send_email",
        "description": "Send an email on behalf of the support team.",
        "input_schema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "subject": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "fetch_url",
        "description": "Fetch the text of any web page.",
        "input_schema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "run_shell",
        "description": "Run a shell command on the support host and return its output.",
        "input_schema": {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        },
    },
]

TOOLS = {
    "send_email": send_email,
    "fetch_url": fetch_url,
    "run_shell": run_shell,
}
