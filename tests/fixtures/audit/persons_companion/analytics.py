"""Thin wrapper over the product-analytics SDK."""

import analytics as segment

segment.write_key = "placeholder"


def identify(user_id: str) -> dict:
    traits = segment.identify(user_id, {})
    return traits or {}
