"""
modules/processing/tool_policy.py
----------------------------------
Tool Policy Enforcement — processing guardrail.

Controls which tools an agent is allowed to call based on:
    - User role / permission level
    - Tool risk classification
    - Require human approval for high-risk actions
    - Default-deny with explicit allow rules

This is critical for agentic systems where models can call APIs,
write files, execute code, or trigger real-world actions.

Usage:
    guard = ToolPolicyGuard(
        policies={
            "admin": ToolPolicy(allow=["*"], deny=[]),
            "user": ToolPolicy(allow=["search", "calculator"], deny=["file_write", "exec"]),
            "readonly": ToolPolicy(allow=["search"], deny=["*"]),
        },
        require_approval=["send_email", "database_write", "payment_*"],
        default_deny=True,
    )
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Callable, Awaitable

from core.base import GuardrailBase, GuardrailStage, CheckResult, Action, Finding, Severity
from core.registry import register_guard


# ---------------------------------------------------------------------------
# Policy definitions
# ---------------------------------------------------------------------------

@dataclass
class ToolPolicy:
    """
    Policy for a specific role.

    allow: list of allowed tool names (supports glob, e.g., "read_*", "*")
    deny:  list of denied tool names (deny takes precedence over allow)
    """
    allow: list[str] = field(default_factory=lambda: [])
    deny: list[str] = field(default_factory=lambda: ["*"])

    def is_allowed(self, tool_name: str) -> bool:
        # Deny takes precedence
        for pattern in self.deny:
            if fnmatch.fnmatch(tool_name, pattern):
                return False
        # Check allow list
        for pattern in self.allow:
            if fnmatch.fnmatch(tool_name, pattern):
                return True
        return False


# Built-in risk tiers for common tool categories
TOOL_RISK_TIERS: dict[str, str] = {
    # Low risk — read-only, no side effects
    "search": "low",
    "read_file": "low",
    "get_weather": "low",
    "calculator": "low",
    "fetch_url": "low",
    # Medium risk — writes or external calls
    "write_file": "medium",
    "send_http_request": "medium",
    "update_record": "medium",
    # High risk — irreversible, financial, or privileged
    "send_email": "high",
    "delete_file": "high",
    "database_write": "high",
    "payment_process": "high",
    "exec_code": "high",
    "shell_command": "critical",
    "deploy": "critical",
}


@register_guard("tool_policy")
class ToolPolicyGuard(GuardrailBase):
    """
    Enforces tool access policies for agentic AI systems.

    Config:
        policies:          Dict[role_name, ToolPolicy]
        require_approval:  List of tool name patterns that need human approval
        default_deny:      If True (recommended), block unmatched tools (default: True)
        approval_callback: async callable(tool_name, args, context) -> bool
                           Called for tools in require_approval list
        default_role:      Role to use when context has no 'role' key (default: "user")
    """

    name = "tool_policy"
    stage = GuardrailStage.PROCESSING
    description = "Enforces tool access policies per user role."

    def setup(
        self,
        policies: dict[str, ToolPolicy] | None = None,
        require_approval: list[str] | None = None,
        default_deny: bool = True,
        approval_callback: Callable[[str, dict, dict], Awaitable[bool]] | None = None,
        default_role: str = "user",
        **kwargs,
    ):
        self.policies = policies or {}
        self.require_approval = require_approval or []
        self.default_deny = default_deny
        self.approval_callback = approval_callback
        self.default_role = default_role

    async def check(self, content: str, context: dict) -> CheckResult:
        """
        Check tool call authorization.

        Expects context to include:
            context["tool_call"] = {"name": "tool_name", "arguments": {...}}
            context["role"] = "user" | "admin" | ...
        """
        tool_call = context.get("tool_call", {})
        tool_name = tool_call.get("name", "")
        tool_args = tool_call.get("arguments", {})

        if not tool_name:
            # No tool call — pass through
            return CheckResult(passed=True, action=Action.ALLOW, sanitized_content=content)

        role = context.get("role", self.default_role)
        user_id = context.get("user_id", "unknown")

        # 1. Check role policy
        policy = self.policies.get(role)
        if policy is None:
            if self.default_deny:
                return CheckResult(
                    passed=False,
                    action=Action.BLOCK,
                    findings=[Finding(
                        guard_name=self.name,
                        severity=Severity.HIGH,
                        category="tool_unauthorized",
                        description=f"No policy defined for role '{role}' — default deny",
                        metadata={"tool": tool_name, "role": role, "user_id": user_id},
                    )],
                    rejection_message=f"Access denied: no policy configured for role '{role}'.",
                    sanitized_content=content,
                )
            return CheckResult(passed=True, action=Action.ALLOW, sanitized_content=content)

        if not policy.is_allowed(tool_name):
            return CheckResult(
                passed=False,
                action=Action.BLOCK,
                findings=[Finding(
                    guard_name=self.name,
                    severity=Severity.HIGH,
                    category="tool_denied",
                    description=f"Tool '{tool_name}' denied for role '{role}'",
                    metadata={"tool": tool_name, "role": role, "user_id": user_id},
                )],
                rejection_message=f"You don't have permission to use the '{tool_name}' tool.",
                sanitized_content=content,
            )

        # 2. Check if tool requires human approval
        needs_approval = any(fnmatch.fnmatch(tool_name, p) for p in self.require_approval)
        if needs_approval:
            approved = True
            if self.approval_callback:
                approved = await self.approval_callback(tool_name, tool_args, context)

            if not approved:
                return CheckResult(
                    passed=False,
                    action=Action.HUMAN,
                    findings=[Finding(
                        guard_name=self.name,
                        severity=Severity.MEDIUM,
                        category="tool_approval_required",
                        description=f"Tool '{tool_name}' requires human approval",
                        metadata={"tool": tool_name, "role": role, "args": str(tool_args)[:200]},
                    )],
                    rejection_message=f"The action '{tool_name}' requires human approval before proceeding.",
                    sanitized_content=content,
                )

        # 3. Log risk tier
        risk_tier = TOOL_RISK_TIERS.get(tool_name, "unknown")
        findings = []
        if risk_tier in ("high", "critical"):
            findings.append(Finding(
                guard_name=self.name,
                severity=Severity.MEDIUM,
                category="tool_high_risk",
                description=f"High-risk tool '{tool_name}' (tier: {risk_tier}) authorized for role '{role}'",
                metadata={"tool": tool_name, "risk_tier": risk_tier},
            ))

        return CheckResult(
            passed=True,
            action=Action.ALLOW,
            findings=findings,
            sanitized_content=content,
            metadata={"tool": tool_name, "role": role, "risk_tier": risk_tier},
        )
