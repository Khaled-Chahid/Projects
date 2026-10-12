from __future__ import annotations

from typing import Any

from azure_risk_tool.azure import AzureApi
from azure_risk_tool.discovery.common import normalize


def discover(api: AzureApi, subscription_id: str) -> dict[str, list[dict[str, Any]]]:
    base = f"/subscriptions/{subscription_id}/providers/Microsoft.Network"
    version = "2024-03-01"
    return {
        "virtual_networks": normalize(api.list_all(f"{base}/virtualNetworks", api_version=version), "Microsoft.Network"),
        "network_security_groups": normalize(api.list_all(f"{base}/networkSecurityGroups", api_version=version), "Microsoft.Network"),
        "network_interfaces": normalize(api.list_all(f"{base}/networkInterfaces", api_version=version), "Microsoft.Network"),
        "public_ip_addresses": normalize(api.list_all(f"{base}/publicIPAddresses", api_version=version), "Microsoft.Network"),
    }
