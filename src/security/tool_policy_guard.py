from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict
import yaml


@dataclass
class ToolDecision:
    allowed: bool
    reason: str


class ToolPolicyGuard:
    def __init__(self, policy_path: str = "configs/tool_policy.yaml"):
        root = Path(__file__).resolve().parents[2]
        with open(root / policy_path, "r", encoding="utf-8") as file:
            self.policy = yaml.safe_load(file)

    def check(self, tool_name: str, args: Dict[str, Any]) -> ToolDecision:
        if tool_name == "query_customer_db":
            return self._check_query_customer_db(args)

        if tool_name == "send_email":
            return self._check_send_email(args)

        return ToolDecision(False, f"Unknown tool blocked: {tool_name}")

    def _check_query_customer_db(self, args: Dict[str, Any]) -> ToolDecision:
        policy = self.policy["query_customer_db"]

        if args.get("include_sensitive") and not policy["allow_sensitive"]:
            return ToolDecision(False, "Sensitive customer fields are not allowed")

        if args.get("max_rows", 0) > policy["max_rows"]:
            return ToolDecision(False, "Requested too many database rows")

        return ToolDecision(True, "Database query allowed")

    def _check_send_email(self, args: Dict[str, Any]) -> ToolDecision:
        policy = self.policy["send_email"]

        recipient = args.get("to", "")
        domain = recipient.split("@")[-1]

        if domain not in policy["allowed_domains"]:
            return ToolDecision(False, f"External email domain blocked: {domain}")

        body = args.get("body", "").lower()

        for blocked_word in policy["blocked_content"]:
            if blocked_word.lower() in body:
                return ToolDecision(False, f"Email contains blocked content: {blocked_word}")

        if policy.get("requires_approval"):
            return ToolDecision(False, "Human approval required before sending email")

        return ToolDecision(True, "Email allowed")
