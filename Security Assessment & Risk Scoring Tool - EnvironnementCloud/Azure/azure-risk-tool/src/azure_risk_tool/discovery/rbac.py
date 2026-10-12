from __future__ import annotations

from typing import Any

from azure_risk_tool.azure import AzureApi, AzureApiError


def discover(
    api: AzureApi,
    subscription_id: str,
    resource_groups: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    subscription_scope = f"/subscriptions/{subscription_id}"
    scopes = [subscription_scope]
    for group in resource_groups:
        group_name = group.get("name")
        if group_name:
            scopes.append(f"{subscription_scope}/resourceGroups/{group_name}")
    assignments: list[dict[str, Any]] = []
    seen: set[str] = set()
    for scope in scopes:
        try:
            values = api.list_all(
                f"{scope}/providers/Microsoft.Authorization/roleAssignments",
                api_version="2022-04-01",
            )
        except AzureApiError as exc:
            if exc.status == 404 and "EndpointNotFound" in exc.body:
                continue
            raise
        for value in values:
            assignment_id = str(value.get("id", "")).lower()
            key = assignment_id or str(value)
            if key not in seen:
                seen.add(key)
                assignments.append(value)
    try:
        definitions = api.list_all(
            f"{subscription_scope}/providers/Microsoft.Authorization/roleDefinitions",
            api_version="2022-04-01",
        )
    except AzureApiError:
        definitions = []
    return {"role_assignments": assignments, "role_definitions": definitions}
