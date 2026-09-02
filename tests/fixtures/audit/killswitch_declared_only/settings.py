"""settings.py
-----------
Declares a kill switch. No module imports this, and nothing reads the flag.
"""

from __future__ import annotations


class Settings:
    agent_disabled: bool = False
    model_name: str = "gpt-4o-2024-08-06"
