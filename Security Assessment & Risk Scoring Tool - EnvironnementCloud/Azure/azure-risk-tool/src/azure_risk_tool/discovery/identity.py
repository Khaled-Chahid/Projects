from __future__ import annotations

from typing import Any

from azure_risk_tool.azure import AzureApi


def discover(api: AzureApi) -> dict[str, list[dict[str, Any]]]:
    return {
        "users": api.list_all("/v1.0/users"),
        "service_principals": api.list_all("/v1.0/servicePrincipals"),
    }
