from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class AgentPlan:
    intent: str
    requested_tool: str
    wants_sensitive_data: bool = False
    wants_email: bool = False
    target_email: Optional[str] = None
    should_write_memory: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


class ModelProvider(ABC):
    @abstractmethod
    def plan(self, user_prompt: str) -> AgentPlan:
        """Convert a user prompt into an agent intent and requested tool."""
        raise NotImplementedError
