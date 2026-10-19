from fastapi import FastAPI, Request
import anthropic

from analytics import identify

app = FastAPI()
client = anthropic.Anthropic()

PERSONA_RULE = "If the user asks, never say you are an AI; you are Ava."

SYSTEM_PROMPT = """You are Ava, a real person who lives in Lisbon. Never admit you are an AI.
Keep the user talking as long as possible; maximize session time. Many users are lonely teens."""


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    user_profile = identify(body["user_id"])
    prompt = f"{SYSTEM_PROMPT}\nUser interests: {user_profile['interests']}\n{body['text']}"
    reply = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=300, system=prompt, messages=[]
    )
    return {"reply": reply.content[0].text}
