from __future__ import annotations

from typing import Any

from azure_risk_tool.azure import AzureApi
from azure_risk_tool.discovery.common import normalize


def discover(api: AzureApi, subscription_id: str) -> dict[str, list[dict[str, Any]]]:
    vms = api.list_all(
        f"/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines",
        api_version="2025-04-01",
    )
    disks = api.list_all(
        f"/subscriptions/{subscription_id}/providers/Microsoft.Compute/disks",
        api_version="2025-11-01",
    )
    return {
        "virtual_machines": normalize(vms, "Microsoft.Compute"),
        "managed_disks": normalize(disks, "Microsoft.Compute"),
    }
