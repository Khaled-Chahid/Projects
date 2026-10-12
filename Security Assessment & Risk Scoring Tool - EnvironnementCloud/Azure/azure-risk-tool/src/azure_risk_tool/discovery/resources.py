from __future__ import annotations

from typing import Any

from azure_risk_tool.azure import AzureApi
from azure_risk_tool.discovery.common import normalize


def discover(api: AzureApi, subscription_id: str) -> dict[str, list[dict[str, Any]]]:
    groups = api.list_all(
        f"/subscriptions/{subscription_id}/resourceGroups",
        api_version="2021-04-01",
    )
    return {"resource_groups": normalize(groups, "Microsoft.Resources")}
