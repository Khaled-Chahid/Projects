from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from azure_risk_tool.azure import AzureApi
from azure_risk_tool.config import Settings
from azure_risk_tool.discovery import compute, identity, network, rbac, resources, storage


class DiscoveryManager:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def run(self) -> dict[str, Any]:
        api = AzureApi(self.settings)
        try:
            api.wait_until_ready(attempts=10, delay=1)
            inventory: dict[str, Any] = {
                "metadata": {
                    "provider": "azure-topaz",
                    "subscription_id": self.settings.subscription_id,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "endpoint": self.settings.endpoint,
                }
            }
            inventory.update(identity.discover(api))
            inventory.update(resources.discover(api, self.settings.subscription_id))
            inventory.update(
                rbac.discover(
                    api,
                    self.settings.subscription_id,
                    inventory.get("resource_groups", []),
                )
            )
            inventory.update(storage.discover(api, self.settings.subscription_id))
            inventory.update(compute.discover(api, self.settings.subscription_id))
            inventory.update(network.discover(api, self.settings.subscription_id))
            inventory["metadata"]["resource_counts"] = {
                key: len(value)
                for key, value in inventory.items()
                if isinstance(value, list) and not key.endswith("_errors")
            }
            return inventory
        finally:
            api.close()
