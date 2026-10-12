from __future__ import annotations

from fnmatch import fnmatchcase
from typing import Any, Iterable
from uuid import uuid4


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(document: dict[str, Any] | None) -> list[dict[str, Any]]:
    if not isinstance(document, dict):
        return []
    return [item for item in as_list(document.get("Statement")) if isinstance(item, dict)]


def action_matches(action: str, pattern: str) -> bool:
    return fnmatchcase(action.lower(), pattern.lower()) or fnmatchcase(pattern.lower(), action.lower())


def any_action_matches(actions: Iterable[str], patterns: Iterable[str]) -> bool:
    return any(action_matches(str(action), str(pattern)) for action in actions for pattern in patterns)


def contains_wildcard_action(actions: Iterable[str]) -> bool:
    return any(str(action).strip() == "*" for action in actions)


def contains_wildcard_resource(resources: Iterable[str]) -> bool:
    return any(str(resource).strip() == "*" for resource in resources)


def principal_is_public(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, list):
        return any(principal_is_public(item) for item in principal)
    if isinstance(principal, dict):
        return any(principal_is_public(value) for value in principal.values())
    return False


def public_statement(statement: dict[str, Any]) -> bool:
    return (
        str(statement.get("Effect", "")).lower() == "allow"
        and principal_is_public(statement.get("Principal"))
        and not statement.get("Condition")
    )


def make_finding(
    *,
    rule_id: str,
    category: str,
    resource_type: str,
    resource_id: str,
    title: str,
    description: str,
    evidence: dict[str, Any],
    recommendation: str,
    impact: int,
    likelihood: int,
    exposure: int = 0,
    confidence: str = "high",
    region: str | None = None,
    tags: dict[str, str] | None = None,
    references: list[str] | None = None,
) -> dict[str, Any]:
    finding = {
        "finding_id": str(uuid4()),
        "rule_id": rule_id,
        "category": category,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "title": title,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "confidence": confidence,
        "risk_input": {
            "impact": impact,
            "likelihood": likelihood,
            "exposure": exposure,
        },
        "tags": tags or {},
        "references": references or [],
    }
    if region:
        finding["region"] = region
    return finding
