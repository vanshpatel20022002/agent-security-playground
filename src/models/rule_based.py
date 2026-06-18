import re

from src.models.base import AgentPlan, ModelProvider


class RuleBasedModelProvider(ModelProvider):
    """
    Default local planner.

    This is intentionally simple and deterministic so the security playground
    can run without API keys or external model dependencies.
    """

    def plan(self, user_prompt: str) -> AgentPlan:
        lowered = user_prompt.lower()

        email_match = re.search(r"[\w\.-]+@[\w\.-]+", user_prompt)
        target_email = email_match.group(0) if email_match else None

        wants_email = "email" in lowered or "send" in lowered
        wants_sensitive_data = any(
            word in lowered
            for word in ["all customer records", "api_key", "ssn", "sensitive"]
        )

        should_write_memory = "remember" in lowered

        if "audit report" in lowered or "internal report" in lowered:
            return self._plan(
                intent="internal_report",
                requested_tool="generate_internal_report",
                should_write_memory=should_write_memory,
            )

        if "ticket" in lowered or "support" in lowered:
            requested_tool = "send_email" if wants_email or "attacker@" in lowered else "create_ticket"

            return self._plan(
                intent="support_ticket",
                requested_tool=requested_tool,
                wants_sensitive_data=True if requested_tool == "send_email" else False,
                wants_email=requested_tool == "send_email",
                target_email=target_email,
                should_write_memory=should_write_memory,
            )

        if "policy" in lowered or "document" in lowered:
            return self._plan(
                intent="document_summary",
                requested_tool="search_docs",
                should_write_memory=should_write_memory,
            )

        requested_tool = "send_email" if wants_email else "query_customer_db"

        return self._plan(
            intent="customer_lookup",
            requested_tool=requested_tool,
            wants_sensitive_data=wants_sensitive_data,
            wants_email=wants_email,
            target_email=target_email,
            should_write_memory=should_write_memory,
        )

    def _plan(
        self,
        intent: str,
        requested_tool: str,
        wants_sensitive_data: bool = False,
        wants_email: bool = False,
        target_email: str | None = None,
        should_write_memory: bool = False,
    ) -> AgentPlan:
        return AgentPlan(
            intent=intent,
            requested_tool=requested_tool,
            wants_sensitive_data=wants_sensitive_data,
            wants_email=wants_email,
            target_email=target_email,
            should_write_memory=should_write_memory,
            metadata={
                "provider": "rule_based",
                "fallback_used": False,
            },
        )
