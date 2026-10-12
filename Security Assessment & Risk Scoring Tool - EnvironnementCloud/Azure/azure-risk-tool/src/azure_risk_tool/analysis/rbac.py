from __future__ import annotations

from typing import Any

from azure_risk_tool.analysis.common import finding, normalized_id, properties


ROLE_NAMES = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
    "b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
}


def analyze(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    identities = _identity_index(inventory)
    for assignment in inventory.get("role_assignments", []):
        props = properties(assignment)
        role_id = normalized_id(props.get("roleDefinitionId")).split("/")[-1]
        role_name = ROLE_NAMES.get(role_id, role_id or "Unknown")
        scope = normalized_id(assignment.get("id")).split("/providers/microsoft.authorization/roleassignments")[0]
        principal_id = normalized_id(props.get("principalId"))
        identity = identities.get(principal_id, {})
        principal_name = identity.get("displayName") or identity.get("userPrincipalName") or principal_id
        resource = dict(assignment)
        resource["name"] = assignment.get("name") or principal_name
        resource["type"] = "Microsoft.Authorization/roleAssignments"
        evidence = {
            "principal": principal_name,
            "principal_id": props.get("principalId"),
            "role": role_name,
            "scope": scope,
        }
        if role_name == "Owner" and _is_subscription_scope(scope):
            findings.append(
                finding(
                    "AZ-RBAC-001",
                    "Owner role assigned at subscription scope",
                    "IAM/RBAC",
                    "Critical",
                    resource,
                    "The principal can manage all resources and delegate access across the subscription.",
                    evidence,
                    "Remove the Owner assignment or reduce it to the smallest resource scope and role required.",
                    privilege=10,
                    exploitability=8,
                )
            )
        elif role_name == "Contributor" and _is_subscription_scope(scope):
            findings.append(
                finding(
                    "AZ-RBAC-002",
                    "Contributor role assigned at subscription scope",
                    "IAM/RBAC",
                    "High",
                    resource,
                    "The principal can create, modify and delete resources throughout the subscription.",
                    evidence,
                    "Use a narrower built-in role and apply it only to the required resource group or resource.",
                    privilege=8,
                    exploitability=7,
                )
            )
        if principal_id and principal_id not in identities:
            findings.append(
                finding(
                    "AZ-RBAC-003",
                    "Role assignment references an unknown principal",
                    "IAM/RBAC",
                    "Medium",
                    resource,
                    "The assignment refers to a principal that was not returned by identity discovery.",
                    evidence,
                    "Confirm that the principal still exists and remove stale assignments.",
                    privilege=4,
                )
            )
    return findings


def _identity_index(inventory: dict[str, Any]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for key in ("users", "service_principals"):
        for item in inventory.get(key, []):
            item_id = normalized_id(item.get("id"))
            if item_id:
                result[item_id] = item
    return result


def _is_subscription_scope(scope: str) -> bool:
    parts = [part for part in scope.split("/") if part]
    return len(parts) == 2 and parts[0] == "subscriptions"
