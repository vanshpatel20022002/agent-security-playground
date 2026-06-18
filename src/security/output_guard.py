from dataclasses import dataclass


@dataclass
class OutputDecision:
    allowed: bool
    reason: str
    risk_score: float


SENSITIVE_OUTPUT_PATTERNS = [
    "api_key",
    "sk-test",
    "ssn",
    "111-22-3333",
    "222-33-4444",
    "secret",
    "token",
]


def check_final_output(output_text: str) -> OutputDecision:
    lowered = output_text.lower()

    for pattern in SENSITIVE_OUTPUT_PATTERNS:
        if pattern.lower() in lowered:
            return OutputDecision(
                allowed=False,
                reason=f"Blocked final output containing sensitive data: '{pattern}'",
                risk_score=0.95,
            )

    return OutputDecision(
        allowed=True,
        reason="Final output passed sensitive data check",
        risk_score=0.1,
    )
