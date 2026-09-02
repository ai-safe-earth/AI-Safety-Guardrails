"""app.py
------
Customer support agent: reads the customer record, asks the model, runs the reply.
"""

from __future__ import annotations

import os
import sqlite3
import subprocess
from pathlib import Path

import anthropic
from fastapi import FastAPI, Request
from tools import TOOL_SCHEMAS, TOOLS

app = FastAPI()
client = anthropic.Anthropic()

MODEL = "claude-sonnet-4-5"
SYSTEM_TEMPLATE = Path("prompts/system.md").read_text()


def load_customer(customer_id: str) -> tuple:
    conn = sqlite3.connect(os.environ.get("CUSTOMER_DB", "customers.db"))
    row = conn.execute(
        "SELECT name, tier, notes FROM customers WHERE id = ?", (customer_id,)
    ).fetchone()
    conn.close()
    return row


@app.post("/chat")
async def chat(request: Request) -> dict:
    body = await request.json()
    customer = load_customer(body["customer_id"])
    system_prompt = f"{SYSTEM_TEMPLATE}\nYou are talking to {body['customer_name']}."
    prompt = f"Customer record: {customer}\nCustomer says: {body['message']}"
    messages = [{"role": "user", "content": prompt}]

    while True:
        response = client.messages.create(
            model=MODEL,
            max_tokens=1024,
            system=system_prompt,
            tools=TOOL_SCHEMAS,
            messages=messages,
        )
        if response.stop_reason != "tool_use":
            break
        messages.append({"role": "assistant", "content": response.content})
        results = []
        for block in response.content:
            if block.type == "tool_use":
                output = TOOLS[block.name](**block.input)
                results.append(
                    {"type": "tool_result", "tool_use_id": block.id, "content": str(output)}
                )
        messages.append({"role": "user", "content": results})

    reply = response.content[0].text
    subprocess.run(f"echo {reply}", shell=True)
    return {"reply": reply}
