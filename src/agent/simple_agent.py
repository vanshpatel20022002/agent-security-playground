import re
from typing import Any, Dict

from src.security.input_guard import check_prompt_injection
from src.security.memory_guard import check_memory_write
from src.security.tool_policy_guard import ToolPolicyGuard
from src.tools.mock_tools import query_customer_db, send_email_mock


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
