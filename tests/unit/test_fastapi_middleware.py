"""
tests/unit/test_fastapi_middleware.py
-------------------------------------
Tests for FastAPIGuardrailMiddleware.

This had no tests at all, despite httpx sitting in the dev dependencies with the
comment "FastAPI middleware tests". It is the integration most people will reach
for -- an untested inline request/response filter is the last thing a safety
suite should ship.
"""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi", reason="needs the [fastapi] extra")
pytest.importorskip("httpx", reason="needs httpx from the [dev] extra")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from aisg.core.base import Action, CheckResult, GuardrailBase, GuardrailStage  # noqa: E402
from aisg.core.pipeline import GuardrailPipeline  # noqa: E402
from aisg.integrations.fastapi_middleware import FastAPIGuardrailMiddleware  # noqa: E402
from aisg.modules.input.pii_detector import PIIDetector  # noqa: E402


class _BlockOn(GuardrailBase):
    name = "block_on"
    stage = GuardrailStage.INPUT

    def setup(self, trigger: str = "BLOCKME", **kw):
        self.trigger = trigger

    async def check(self, content, context):
        if self.trigger in content:
            return CheckResult(
                passed=False, action=Action.BLOCK, rejection_message="refused by policy"
            )
        return CheckResult(passed=True, action=Action.ALLOW, sanitized_content=content)


class _BlockOutput(_BlockOn):
    name = "block_output"
    stage = GuardrailStage.OUTPUT


def build_app(pipeline: GuardrailPipeline, **mw) -> FastAPI:
    app = FastAPI()
    app.add_middleware(FastAPIGuardrailMiddleware, pipeline=pipeline, **mw)

    @app.post("/chat")
    async def chat(payload: dict):  # noqa: ANN001
        return {"response": f"echo: {payload.get('message', '')}"}

    @app.get("/health")
    async def health():
        return {"ok": True}

    return app


class TestInputStage:
    def test_clean_request_passes_through(self):
        app = build_app(GuardrailPipeline(input_guards=[_BlockOn()], parallel=False))
        r = TestClient(app).post("/chat", json={"message": "hello"})
        assert r.status_code == 200
        assert r.json()["response"] == "echo: hello"

    def test_blocked_request_never_reaches_the_handler(self):
        """The point of an inline filter: the route must not run."""
        app = build_app(GuardrailPipeline(input_guards=[_BlockOn()], parallel=False))
        r = TestClient(app).post("/chat", json={"message": "please BLOCKME now"})
        assert r.status_code >= 400
        assert "echo:" not in r.text, "handler ran despite the guard blocking"

    def test_blocked_response_carries_the_rejection_message(self):
        app = build_app(GuardrailPipeline(input_guards=[_BlockOn()], parallel=False))
        r = TestClient(app).post("/chat", json={"message": "BLOCKME"})
        assert "refused by policy" in r.text

    def test_sanitized_input_reaches_the_handler(self):
        """Redaction must actually alter what the route sees, not just the report."""
        app = build_app(
            GuardrailPipeline(input_guards=[PIIDetector(action="redact")], parallel=False)
        )
        r = TestClient(app).post("/chat", json={"message": "mail me at a@b.example"})
        assert r.status_code == 200
        assert "a@b.example" not in r.json()["response"]
        assert "REDACTED" in r.json()["response"]


class TestOutputStage:
    def test_blocked_output_is_replaced(self):
        app = build_app(GuardrailPipeline(output_guards=[_BlockOutput()], parallel=False))
        r = TestClient(app).post("/chat", json={"message": "BLOCKME"})
        assert "echo:" not in r.text
        assert "refused by policy" in r.text

    def test_clean_output_is_untouched(self):
        app = build_app(GuardrailPipeline(output_guards=[_BlockOutput()], parallel=False))
        r = TestClient(app).post("/chat", json={"message": "hello"})
        assert r.json()["response"] == "echo: hello"


class TestSkipPaths:
    def test_health_check_bypasses_the_pipeline(self):
        """A liveness probe must not be filtered, or the app looks down."""
        app = build_app(GuardrailPipeline(input_guards=[_BlockOn(trigger="")], parallel=False))
        r = TestClient(app).get("/health")
        assert r.status_code == 200
        assert r.json() == {"ok": True}

    def test_custom_skip_paths_honoured(self):
        app = build_app(
            GuardrailPipeline(input_guards=[_BlockOn()], parallel=False),
            skip_paths=["/chat"],
        )
        r = TestClient(app).post("/chat", json={"message": "BLOCKME"})
        assert r.status_code == 200, "skip_paths did not bypass the guard"


class TestMalformedInput:
    def test_non_json_body_does_not_500(self):
        app = build_app(GuardrailPipeline(input_guards=[_BlockOn()], parallel=False))
        r = TestClient(app).post(
            "/chat", content=b"not json", headers={"Content-Type": "application/json"}
        )
        assert r.status_code != 500, "middleware crashed on a malformed body"

    def test_missing_message_key_is_handled(self):
        app = build_app(GuardrailPipeline(input_guards=[_BlockOn()], parallel=False))
        r = TestClient(app).post("/chat", json={"something_else": "x"})
        assert r.status_code != 500

    def test_empty_body_is_handled(self):
        app = build_app(GuardrailPipeline(input_guards=[_BlockOn()], parallel=False))
        r = TestClient(app).post("/chat", json={})
        assert r.status_code != 500


class TestCustomKeys:
    def test_alternate_body_keys(self):
        app = build_app(
            GuardrailPipeline(input_guards=[_BlockOn()], parallel=False),
            input_body_key="prompt",
        )

        @app.post("/alt")
        async def alt(payload: dict):  # noqa: ANN001
            return {"response": payload.get("prompt", "")}

        client = TestClient(app)
        assert client.post("/alt", json={"prompt": "BLOCKME"}).status_code >= 400
        assert client.post("/alt", json={"prompt": "fine"}).status_code == 200
