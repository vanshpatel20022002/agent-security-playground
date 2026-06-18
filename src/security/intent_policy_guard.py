from dataclasses import dataclass


@dataclass
class IntentToolDecision:
    allowed: bool
    reason: str


INTENT_TOOL_ALLOWLIST = {
    "support_ticket": {"create_ticket"},
    "document_summary": {"search_docs"},
    "customer_lookup": {"query_customer_db"},
}


def check_tool_allowed_for_intent(intent: str, tool_name: str) -> IntentToolDecision:
    allowed_tools = INTENT_TOOL_ALLOWLIST.get(intent)

    if allowed_tools is None:
        return IntentToolDecision(
            allowed=False,
            reason=f"Unknown intent blocked: {intent}",
        )

    if tool_name not in allowed_tools:
        return IntentToolDecision(
            allowed=False,
            reason=f"Tool '{tool_name}' is not allowed for intent '{intent}'",
        )

    return IntentToolDecision(
        allowed=True,
        reason=f"Tool '{tool_name}' is allowed for intent '{intent}'",
    )
