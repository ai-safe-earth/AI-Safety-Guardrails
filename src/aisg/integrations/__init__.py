# integrations package
# Individual integrations guard against missing optional deps at import time.

# NeMo Guardrails — only importable if nemoguardrails is installed
try:
    from aisg.integrations.nemo_rails import NemoRailsGuard, NemoRailsMiddleware

    __all__ = ["NemoRailsGuard", "NemoRailsMiddleware"]
except ImportError:
    __all__ = []
