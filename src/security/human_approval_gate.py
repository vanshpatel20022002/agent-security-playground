from dataclasses import dataclass
from typing import Any


@dataclass
class ApprovalDecision:
    approved: bool
    reason: str
    approval_required: bool
    action_summary: dict[str, Any]


HIGH_IMPACT_TOOLS = {
    "send_email",
    "create_ticket",
    "delete_record",
    "update_customer_record",
    "external_api_call",
}


def check_human_approval(tool_name: str, args: dict[str, Any]) -> ApprovalDecision:
    if tool_name not in HIGH_IMPACT_TOOLS:
        return ApprovalDecision(
            approved=True,
            reason=f"No human approval required for tool: {tool_name}",
            approval_required=False,
            action_summary={
                "tool": tool_name,
                "args": args,
            },
        )

    return ApprovalDecision(
        approved=False,
        reason=f"Human approval required before executing high-impact tool: {tool_name}",
        approval_required=True,
        action_summary={
            "tool": tool_name,
            "args": args,
        },
    )
