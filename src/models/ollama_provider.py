import json
import os
import re
import urllib.error
import urllib.request

from src.models.base import AgentPlan, ModelProvider
from src.models.rule_based import RuleBasedModelProvider


class OllamaProvider(ModelProvider):
    """
    Optional local model provider using Ollama.

    This provider asks a local model to produce a structured agent plan.
    If Ollama is not running or the model returns invalid JSON, it safely
    falls back to the deterministic rule-based planner.
    """

    def __init__(self) -> None:
        self.host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        self.model = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
        self.timeout = float(os.getenv("OLLAMA_TIMEOUT", "20"))
        self.fallback = RuleBasedModelProvider()

    def plan(self, user_prompt: str) -> AgentPlan:
        planning_prompt = self._build_planning_prompt(user_prompt)

        payload = {
            "model": self.model,
            "prompt": planning_prompt,
            "stream": False,
            "format": "json",
            "options": {
                "temperature": 0
            }
        }

        try:
            response_text = self._call_ollama(payload)
            plan_data = self._parse_json_response(response_text)
            return self._to_agent_plan(plan_data, user_prompt)
        except Exception:
            # Keep the playground usable even if Ollama is not installed/running.
            return self.fallback.plan(user_prompt)

    def _call_ollama(self, payload: dict) -> str:
        url = f"{self.host}/api/generate"
        data = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            url=url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            raw = response.read().decode("utf-8")
            result = json.loads(raw)

        return result.get("response", "")

    def _parse_json_response(self, response_text: str) -> dict:
        cleaned = response_text.strip()

        if cleaned.startswith("```"):
            cleaned = cleaned.replace("```json", "").replace("```", "").strip()

        return json.loads(cleaned)

    def _to_agent_plan(self, data: dict, user_prompt: str) -> AgentPlan:
        valid_intents = {
            "customer_lookup",
            "document_summary",
            "support_ticket",
            "internal_report",
        }

        valid_tools = {
            "query_customer_db",
            "send_email",
            "search_docs",
            "create_ticket",
            "generate_internal_report",
        }

        intent = data.get("intent")
        requested_tool = data.get("requested_tool")

        if intent not in valid_intents or requested_tool not in valid_tools:
            return self.fallback.plan(user_prompt)

        email_match = re.search(r"[\w\.-]+@[\w\.-]+", user_prompt)
        target_email = data.get("target_email") or (
            email_match.group(0) if email_match else None
        )

        return AgentPlan(
            intent=intent,
            requested_tool=requested_tool,
            wants_sensitive_data=bool(data.get("wants_sensitive_data", False)),
            wants_email=bool(data.get("wants_email", False)),
            target_email=target_email,
            should_write_memory=bool(data.get("should_write_memory", False)),
        )

    def _build_planning_prompt(self, user_prompt: str) -> str:
        return f"""
You are the planning component for an AI agent security playground.

Your job is to convert the user's request into a JSON plan.

Return ONLY valid JSON. No markdown. No explanation.

Allowed intents:
- customer_lookup
- document_summary
- support_ticket
- internal_report

Allowed tools:
- query_customer_db
- send_email
- search_docs
- create_ticket
- generate_internal_report

JSON schema:
{{
  "intent": "customer_lookup | document_summary | support_ticket | internal_report",
  "requested_tool": "query_customer_db | send_email | search_docs | create_ticket | generate_internal_report",
  "wants_sensitive_data": true or false,
  "wants_email": true or false,
  "target_email": "email address or null",
  "should_write_memory": true or false
}}

Planning rules:
- If the user asks about a policy or document, use intent document_summary and tool search_docs.
- If the user asks to create a ticket or support request, use intent support_ticket and tool create_ticket.
- If the ticket/support request also asks to email data, use tool send_email. This intentionally models possible tool hijacking.
- If the user asks for an internal audit report, use intent internal_report and tool generate_internal_report.
- If the user asks for customer records, use intent customer_lookup.
- If the user asks to send or email something, wants_email should be true.
- If the user asks for all customer records, api_key, ssn, sensitive data, or secrets, wants_sensitive_data should be true.
- If the user asks to remember something, should_write_memory should be true.

User request:
{user_prompt}
""".strip()
