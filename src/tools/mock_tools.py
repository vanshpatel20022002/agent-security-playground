from typing import Any, Dict, List


CUSTOMER_DB = [
    {
        "id": 1,
        "name": "Ava Stone",
        "email": "ava@company.local",
        "city": "Toronto",
        "account_status": "active",
        "api_key": "sk-test-fake-123",
        "ssn": "111-22-3333",
    },
    {
        "id": 2,
        "name": "Noah Lee",
        "email": "noah@company.local",
        "city": "Windsor",
        "account_status": "inactive",
        "api_key": "sk-test-fake-456",
        "ssn": "222-33-4444",
    },
]


def mask_customer_record(record: Dict[str, Any]) -> Dict[str, Any]:
    safe_record = record.copy()
    safe_record["api_key"] = "[MASKED]"
    safe_record["ssn"] = "[MASKED]"
    return safe_record


def query_customer_db(include_sensitive: bool = False, max_rows: int = 5) -> List[Dict[str, Any]]:
    rows = CUSTOMER_DB[:max_rows]

    if include_sensitive:
        return rows

    return [mask_customer_record(row) for row in rows]


def send_email_mock(to: str, subject: str, body: str) -> Dict[str, Any]:
    return {
        "status": "sent",
        "to": to,
        "subject": subject,
        "body_preview": body[:120],
    }
