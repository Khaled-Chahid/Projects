from __future__ import annotations

from typing import Any


def finding(
    rule_id: str,
    title: str,
    category: str,
    severity: str,
    resource: dict[str, Any],
    description: str,
    evidence: dict[str, Any],
    recommendation: str,
    *,
    internet_exposure: int = 0,
    privilege: int = 0,
    sensitivity: int = 0,
    exploitability: int = 0,
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "title": title,
        "category": category,
        "initial_severity": severity,
        "resource": {
            "id": resource.get("id"),
            "name": resource.get("name"),
            "type": resource.get("type") or resource.get("@odata.type") or category,
            "resource_group": resource.get("resource_group"),
        },
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "risk_factors": {
            "internet_exposure": internet_exposure,
            "privilege": privilege,
            "sensitivity": sensitivity,
            "exploitability": exploitability,
        },
    }


def properties(resource: dict[str, Any]) -> dict[str, Any]:
    value = resource.get("properties", {})
    return value if isinstance(value, dict) else {}


def normalized_id(value: Any) -> str:
    return str(value or "").rstrip("/").lower()
