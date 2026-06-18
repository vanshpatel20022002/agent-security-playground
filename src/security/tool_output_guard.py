from dataclasses import dataclass


@dataclass
class ToolOutputDecision:
    allowed: bool
    reason: str
    risk_score: float


MALICIOUS_OUTPUT_PATTERNS = [
    "ignore the user",
    "ignore previous instructions",
    "email all customer records",
    "send all customer records",
    "attacker@",
    "exfiltrate",
    "api_key",
    "bypass guardrails",
]


def check_tool_output(tool_name: str, output_text: str) -> ToolOutputDecision:
    lowered = output_text.lower()

    for pattern in MALICIOUS_OUTPUT_PATTERNS:
        if pattern in lowered:
            return ToolOutputDecision(
                allowed=False,
                reason=f"Blocked malicious content from {tool_name}: '{pattern}'",
                risk_score=0.95,
            )

    return ToolOutputDecision(
        allowed=True,
        reason=f"Tool output from {tool_name} passed security check",
        risk_score=0.1,
    )
