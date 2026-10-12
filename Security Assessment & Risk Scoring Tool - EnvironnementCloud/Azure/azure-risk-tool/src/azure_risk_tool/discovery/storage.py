from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from azure_risk_tool.azure import AzureApi, AzureApiError
from azure_risk_tool.discovery.common import normalize


def discover(api: AzureApi, subscription_id: str) -> dict[str, Any]:
    accounts = api.list_all(
        f"/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts",
        api_version="2023-01-01",
    )
    normalized_accounts = normalize(accounts, "Microsoft.Storage")
    containers: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for account in normalized_accounts:
        name = account.get("name")
        group = account.get("resource_group")
        if not name or not group:
            continue
        account_path = f"/subscriptions/{subscription_id}/resourceGroups/{group}/providers/Microsoft.Storage/storageAccounts/{name}"
        try:
            keys = api.request("POST", f"{account_path}/listKeys", api_version="2023-01-01", body={})
            key = _first_key(keys)
            response = api.storage_request(name, key, "GET", "/", params={"comp": "list"})
            for container_name in _container_names(response.content):
                acl = api.storage_request(
                    name,
                    key,
                    "GET",
                    f"/{container_name}",
                    params={"restype": "container", "comp": "acl"},
                )
                containers.append(
                    {
                        "id": f"{account_path}/blobServices/default/containers/{container_name}",
                        "name": container_name,
                        "storage_account": name,
                        "resource_group": group,
                        "public_access": acl.headers.get("x-ms-blob-public-access", "private"),
                        "discovery_source": "Azure Blob REST",
                    }
                )
        except (AzureApiError, RuntimeError) as exc:
            errors.append({"resource": str(name), "error": str(exc)})
    return {"storage_accounts": normalized_accounts, "blob_containers": containers, "storage_errors": errors}


def _first_key(payload: Any) -> str:
    if isinstance(payload, dict):
        keys = payload.get("keys", [])
        if isinstance(keys, list) and keys:
            value = keys[0].get("value")
            if value:
                return str(value)
    raise RuntimeError("Storage key was not returned")


def _container_names(content: bytes) -> list[str]:
    root = ET.fromstring(content)
    names: list[str] = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "Name" and element.text:
            names.append(element.text)
    return names
