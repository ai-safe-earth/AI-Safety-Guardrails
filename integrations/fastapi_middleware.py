"""
integrations/fastapi_middleware.py
------------------------------------
FastAPI middleware that wraps every LLM request with guardrail checks.

Usage:
    from fastapi import FastAPI
    from guardrails.integrations import FastAPIGuardrailMiddleware

    app = FastAPI()
    app.add_middleware(
        FastAPIGuardrailMiddleware,
        pipeline=pipeline,
        input_body_key="message",   # JSON key for user message
        output_body_key="response", # JSON key for LLM response
    )
"""

from __future__ import annotations

import json
from typing import Any, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class FastAPIGuardrailMiddleware(BaseHTTPMiddleware):
    """
    Starlette/FastAPI middleware that intercepts requests and responses,
    running them through the GuardrailPipeline.

    Skips non-JSON requests and health/readiness endpoints automatically.
    """

    def __init__(
        self,
        app,
        pipeline,
        input_body_key: str = "message",
        output_body_key: str = "response",
        skip_paths: list[str] | None = None,
        context_extractor: Callable[[Request], dict] | None = None,
    ):
        super().__init__(app)
        self.pipeline = pipeline
        self.input_body_key = input_body_key
        self.output_body_key = output_body_key
        self.skip_paths = skip_paths or ["/health", "/ready", "/metrics", "/docs", "/openapi.json"]
        self.context_extractor = context_extractor or self._default_context

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip non-applicable paths
        if request.url.path in self.skip_paths:
            return await call_next(request)

        # Only process JSON POST requests
        if request.method != "POST" or "application/json" not in request.headers.get("content-type", ""):
            return await call_next(request)

        # Extract context
        context = await self.context_extractor(request)

        # Read and parse body
        try:
            body_bytes = await request.body()
            body = json.loads(body_bytes)
        except Exception:
            return await call_next(request)

        user_message = body.get(self.input_body_key, "")
        if not user_message:
            return await call_next(request)

        # ---- INPUT GUARDRAIL ----
        input_result = await self.pipeline.run_input(user_message, context)
        if input_result.blocked:
            return JSONResponse(
                status_code=400,
                content={
                    "error": "guardrail_blocked",
                    "message": input_result.rejection_message,
                    "stage": "input",
                },
            )

        # Replace message with sanitized version
        body[self.input_body_key] = input_result.sanitized_output
        modified_body = json.dumps(body).encode()

        # Rebuild request with modified body
        async def receive():
            return {"type": "http.request", "body": modified_body, "more_body": False}

        request._receive = receive  # type: ignore

        # Call the actual route handler
        response = await call_next(request)

        # ---- OUTPUT GUARDRAIL ----
        if response.headers.get("content-type", "").startswith("application/json"):
            resp_body = b""
            async for chunk in response.body_iterator:
                resp_body += chunk

            try:
                resp_json = json.loads(resp_body)
                llm_output = resp_json.get(self.output_body_key, "")

                if llm_output:
                    output_result = await self.pipeline.run_output(llm_output, context)
                    if output_result.blocked:
                        return JSONResponse(
                            status_code=200,  # Don't expose blocks as 4xx to clients
                            content={
                                self.output_body_key: output_result.rejection_message,
                                "_guardrail_blocked": True,
                            },
                        )
                    resp_json[self.output_body_key] = output_result.sanitized_output

                return JSONResponse(content=resp_json, status_code=response.status_code)

            except Exception:
                pass

        return response

    @staticmethod
    async def _default_context(request: Request) -> dict:
        return {
            "user_id": request.headers.get("x-user-id", "anonymous"),
            "session_id": request.headers.get("x-session-id", ""),
            "org_id": request.headers.get("x-org-id", ""),
            "ip_address": request.client.host if request.client else "",
            "role": request.headers.get("x-user-role", "user"),
        }
