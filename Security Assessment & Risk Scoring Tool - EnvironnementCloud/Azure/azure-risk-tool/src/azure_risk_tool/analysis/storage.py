from __future__ import annotations

from typing import Any

from azure_risk_tool.analysis.common import finding, properties


def analyze(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    accounts = {item.get("name"): item for item in inventory.get("storage_accounts", [])}
    for account in accounts.values():
        props = properties(account)
        if props.get("allowBlobPublicAccess") is True:
            findings.append(
                finding(
                    "AZ-STG-001",
                    "Storage account permits public Blob access",
                    "Storage",
                    "Medium",
                    account,
                    "The storage account allows containers to be configured for anonymous access.",
                    {
                        "allowBlobPublicAccess": True,
                        "publicNetworkAccess": props.get("publicNetworkAccess"),
                    },
                    "Disable allowBlobPublicAccess unless anonymous access is explicitly required.",
                    internet_exposure=4,
                    sensitivity=_sensitivity(account),
                    exploitability=4,
                )
            )
    for container in inventory.get("blob_containers", []):
        public_access = str(container.get("public_access", "private")).lower()
        if public_access in {"blob", "container"}:
            account = accounts.get(container.get("storage_account"), {})
            resource = dict(container)
            resource["type"] = "Microsoft.Storage/storageAccounts/blobServices/containers"
            findings.append(
                finding(
                    "AZ-STG-002",
                    "Blob container is exposed to anonymous access",
                    "Storage",
                    "High",
                    resource,
                    "Anonymous users can read data from the Blob container according to its access level.",
                    {
                        "storage_account": container.get("storage_account"),
                        "container": container.get("name"),
                        "public_access": public_access,
                    },
                    "Set the container access level to private and provide access through identities or short-lived SAS tokens.",
                    internet_exposure=10,
                    sensitivity=_sensitivity(account),
                    exploitability=8,
                )
            )
    return findings


def _sensitivity(resource: dict[str, Any]) -> int:
    tags = resource.get("tags", {})
    value = str(tags.get("data_classification", "")).lower() if isinstance(tags, dict) else ""
    return 8 if value in {"confidential", "restricted", "sensitive"} else 3
