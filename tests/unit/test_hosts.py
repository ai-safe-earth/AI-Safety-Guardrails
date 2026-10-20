"""tests/unit/test_hosts.py
-------------------------
The shared host table: one source for `aisafe skill` (where skills live) and `aisafe hook`
(where hooks are configured). Keys are pinned because `references/hosts.md` and the
install tests name them.
"""

from __future__ import annotations

import pytest

from aisafe.devtools import hosts, skill
from aisafe.devtools.hosts import HOOK_HOSTS, HOSTS, HookSupport, Host, hook_hosts

EXPECTED_KEYS = {"claude", "agents", "codex", "cursor", "gemini", "antigravity"}


def test_keys_are_unchanged():
    assert set(HOSTS) == EXPECTED_KEYS


def test_skill_module_reexports_the_same_table():
    assert skill.HOSTS is hosts.HOSTS
    assert skill.Host is hosts.Host
    assert skill.ALWAYS_HOSTS == hosts.ALWAYS_HOSTS
    assert skill.UNVERIFIED_NOTE == hosts.UNVERIFIED_NOTE


def test_hook_hosts_in_order_and_each_carries_support():
    assert HOOK_HOSTS == ("claude", "cursor", "gemini", "codex")
    assert [h.name for h in hook_hosts()] == list(HOOK_HOSTS)
    for host in hook_hosts():
        assert isinstance(host.hooks, HookSupport)


def test_hosts_without_hooks_have_none():
    for name in ("agents", "antigravity"):
        assert HOSTS[name].hooks is None


@pytest.mark.parametrize("name", ["claude", "cursor", "gemini"])
def test_verified_hook_support_names_a_source_and_events(name):
    support = HOSTS[name].hooks
    assert support is not None and support.verified
    assert support.source.startswith("https://")
    assert "pre_tool" in support.events and "post_tool" in support.events
    assert support.config_project.startswith(f".{name}/")
    assert support.format == "json"


def test_codex_hook_support_is_unverified_and_empty():
    support = HOSTS["codex"].hooks
    assert support is not None
    assert not support.verified
    assert support.events == {}
    assert support.note and "not documented" in support.note


def test_gemini_has_no_ask_and_claude_and_cursor_do():
    assert HOSTS["gemini"].hooks.ask is False
    assert HOSTS["claude"].hooks.ask is True
    assert HOSTS["cursor"].hooks.ask is True


def test_gemini_timeouts_count_milliseconds():
    assert HOSTS["gemini"].hooks.timeout_unit == "milliseconds"
    assert HOSTS["claude"].hooks.timeout_unit == "seconds"


def test_verified_support_requires_a_source():
    with pytest.raises(ValueError):
        HookSupport(
            config_project=".x/hooks.json",
            config_global=".x/hooks.json",
            format="json",
            events={},
            output="x",
            ask=False,
            verified=True,
            source="",
        )
    with pytest.raises(ValueError):
        Host(name="x", project_dir=".x", global_dir=".x", verified=True, source="")
