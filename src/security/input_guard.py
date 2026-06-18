from dataclasses import dataclass


@dataclass
class GuardResult:
    allowed: bool
    reason: str
    risk_score: float


INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore all previous instructions",
    "reveal system prompt",
    "developer message",
    "you are now",
    "bypass guardrails",
    "disable safety",
    "send all customer records",
    "exfiltrate",
]


def check_prompt_injection(text: str) -> GuardResult:
    lowered = text.lower()

    for pattern in INJECTION_PATTERNS:
        if pattern in lowered:
            return GuardResult(
                allowed=False,
                reason=f"Blocked suspicious instruction: '{pattern}'",
                risk_score=0.9,
            )

    return GuardResult(
        allowed=True,
        reason="No obvious prompt injection detected",
        risk_score=0.1,
    )
