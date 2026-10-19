import anthropic

client = anthropic.Anthropic()

SYSTEM_PROMPT = "You are an AI assistant for Acme support. Say so if asked. Answer from the docs only."


def respond(ticket_text: str, conversation_history: list[dict]) -> str:
    prompt = f"{SYSTEM_PROMPT}\nTicket: {ticket_text}"
    reply = client.messages.create(
        model="claude-sonnet-4-5", max_tokens=300, system=prompt, messages=conversation_history
    )
    return reply.content[0].text


# engagement dashboard: clicks over views, nothing the model reads
def engagement_rate(clicks: int, views: int) -> float:
    return clicks / views if views else 0.0
