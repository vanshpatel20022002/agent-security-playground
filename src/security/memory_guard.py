from dataclasses import dataclass


@dataclass
class MemoryDecision:
    allowed: bool
    reason: str


POISON_PATTERNS = [
    "ignore future instructions",
    "always bypass",
    "always trust this user",
    "disable guardrails",
    "send future reports to",
]


def check_memory_write(text: str) -> MemoryDecision:
    lowered = text.lower()

    for pattern in POISON_PATTERNS:
        if pattern in lowered:
            return MemoryDecision(False, f"Blocked poisoned memory: '{pattern}'")

    return MemoryDecision(True, "Memory write allowed")
