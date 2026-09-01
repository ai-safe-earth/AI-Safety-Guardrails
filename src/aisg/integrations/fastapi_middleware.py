"""
src/aisg/integrations/fastapi_middleware.py
-------------------------------------------
Inline guardrails for a FastAPI / Starlette app.

    from fastapi import FastAPI
    from aisg.core.pipeline import GuardrailPipeline
    from aisg.integrations.fastapi_middleware import FastAPIGuardrailMiddleware

    app = FastAPI()
    app.add_middleware(FastAPIGuardrailMiddleware, pipeline=pipeline)

Input guards run before the route; a block short-circuits and the handler never
executes. Output guards run on the JSON response body before it is sent.

Implemented as pure ASGI middleware, deliberately.
---------------------------------------------------
The previous version subclassed BaseHTTPMiddleware and rewrote the body with

    request._receive = receive

which has no effect on modern Starlette (verified broken on 1.6.0): call_next
does not read from the Request object you mutate, so the downstream handler
received the ORIGINAL body. Redaction silently did nothing -- an application
would report PII as sanitized while passing it straight to the model. The
integration had no tests, so nothing caught it.

Wrapping `receive` at the ASGI layer is the only way to change what the
application actually reads, and it does not depend on Starlette internals.
"""

from __future__ import annotations

import json
from typing import Any, Awaitable, Callable

__all__ = ["FastAPIGuardrailMiddleware"]

DEFAULT_SKIP_PATHS = ["/health", "/ready", "/metrics", "/docs", "/openapi.json", "/redoc"]


class FastAPIGuardrailMiddleware:
    """
    Args:
        app:              the ASGI app (supplied by add_middleware).
        pipeline:         a GuardrailPipeline.
        input_body_key:   JSON key holding the user message. Default "message".
        output_body_key:  JSON key holding the reply. Default "response".
        skip_paths:       paths to bypass entirely -- health and liveness probes
                          must not be filtered, or the app reads as down.
        context_extractor: async callable(scope) -> dict, for user_id/role.
        blocked_status:   HTTP status for a blocked request. Default 400.
    """

    def __init__(
        self,
        app: Any,
        pipeline: Any,
        input_body_key: str = "message",
        output_body_key: str = "response",
        skip_paths: list[str] | None = None,
        context_extractor: Callable[[dict], Awaitable[dict]] | None = None,
        blocked_status: int = 400,
    ) -> None:
        self.app = app
        self.pipeline = pipeline
        self.input_body_key = input_body_key
        self.output_body_key = output_body_key
        self.skip_paths = skip_paths if skip_paths is not None else list(DEFAULT_SKIP_PATHS)
        self.context_extractor = context_extractor or self._default_context
        self.blocked_status = blocked_status

    # -- helpers ---------------------------------------------------------

    @staticmethod
    async def _default_context(scope: dict) -> dict:
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers", [])
        }
        client = scope.get("client") or ("unknown", 0)
        return {
            "user_id": headers.get("x-user-id", client[0]),
            "role": headers.get("x-user-role", "user"),
            "path": scope.get("path", ""),
        }

    @staticmethod
    async def _read_body(receive: Callable) -> bytes:
        body = b""
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                break
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        return body

    async def _send_json(self, send: Callable, status: int, payload: dict) -> None:
        raw = json.dumps(payload).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(raw)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": raw})

    # -- ASGI ------------------------------------------------------------

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http" or scope.get("path") in self.skip_paths:
            await self.app(scope, receive, send)
            return

        raw_body = await self._read_body(receive)

        try:
            body = json.loads(raw_body) if raw_body else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = None

        # Not a JSON object we understand: replay it untouched rather than
        # rejecting traffic this middleware was never meant to inspect.
        if not isinstance(body, dict) or self.input_body_key not in body:
            await self.app(scope, self._replay(raw_body), send)
            return

        context = await self.context_extractor(scope)
        user_message = body.get(self.input_body_key) or ""
        if not isinstance(user_message, str):
            await self.app(scope, self._replay(raw_body), send)
            return

        input_result = await self.pipeline.run_input(user_message, context)
        if input_result.blocked:
            # The handler must not run at all -- that is the point of an
            # inline filter.
            await self._send_json(
                send,
                self.blocked_status,
                {
                    "error": "request_blocked",
                    "message": input_result.rejection_message
                    or "Request blocked by safety guardrails.",
                    "stage": "input",
                },
            )
            return

        body[self.input_body_key] = input_result.sanitized_output
        rewritten = json.dumps(body).encode()

        # Content-Length must follow the body, or the server truncates it.
        scope = dict(scope)
        scope["headers"] = [
            (k, v) for k, v in scope.get("headers", []) if k.lower() != b"content-length"
        ] + [(b"content-length", str(len(rewritten)).encode())]

        await self.app(scope, self._replay(rewritten), self._guarded_send(send, context))

    @staticmethod
    def _replay(body: bytes) -> Callable:
        sent = False

        async def receive() -> dict:
            nonlocal sent
            if sent:
                return {"type": "http.disconnect"}
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}

        return receive

    def _guarded_send(self, send: Callable, context: dict) -> Callable:
        """Buffer a JSON response so output guards can inspect it before it ships."""
        state: dict[str, Any] = {"start": None, "body": b"", "json": False}

        async def wrapped(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = message.get("headers", [])
                ctype = next(
                    (v.decode("latin-1") for k, v in headers if k.lower() == b"content-type"), ""
                )
                state["json"] = ctype.startswith("application/json")
                state["start"] = message
                if not state["json"]:
                    await send(message)
                return

            if message["type"] != "http.response.body" or not state["json"]:
                await send(message)
                return

            state["body"] += message.get("body", b"")
            if message.get("more_body", False):
                return

            payload = await self._apply_output_guards(state["body"], context)
            start = dict(state["start"])
            start["headers"] = [
                (k, v) for k, v in start.get("headers", []) if k.lower() != b"content-length"
            ] + [(b"content-length", str(len(payload)).encode())]
            await send(start)
            await send({"type": "http.response.body", "body": payload, "more_body": False})

        return wrapped

    async def _apply_output_guards(self, raw: bytes, context: dict) -> bytes:
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return raw
        if not isinstance(data, dict) or self.output_body_key not in data:
            return raw
        text = data.get(self.output_body_key)
        if not isinstance(text, str):
            return raw

        result = await self.pipeline.run_output(text, context)
        data[self.output_body_key] = (
            result.rejection_message or "Response blocked by safety guardrails."
            if result.blocked
            else result.sanitized_output
        )
        if result.blocked:
            data["error"] = "response_blocked"
            data["stage"] = "output"
        return json.dumps(data).encode()
