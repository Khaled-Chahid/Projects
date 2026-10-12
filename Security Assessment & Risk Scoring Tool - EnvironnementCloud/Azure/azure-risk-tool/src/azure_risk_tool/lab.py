from __future__ import annotations

from pathlib import Path
from typing import Any

from azure_risk_tool.azure import AzureApi
from azure_risk_tool.config import Settings
from azure_risk_tool.serialization import write_json


OWNER_ROLE = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
CONTRIBUTOR_ROLE = "b24988ac-6180-42a0-ab88-20f7382dd24c"
READER_ROLE = "acdd72a7-3385-48ef-bd42-f606fba81ae7"


def resource_id(subscription_id: str, resource_group: str, provider: str, kind: str, name: str) -> str:
    return f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/{provider}/{kind}/{name}"


class LabBuilder:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.api = AzureApi(settings)
        self.subscription = settings.subscription_id
        self.location = settings.location
        self.created: dict[str, list[dict[str, Any]]] = {
            "identities": [],
            "role_assignments": [],
            "storage": [],
            "compute": [],
            "network": [],
        }

    def close(self) -> None:
        self.api.close()

    def build(self) -> dict[str, Any]:
        self.api.wait_until_ready()
        self._resource_groups()
        identities = self._identities()
        self._role_assignments(identities)
        self._storage()
        self._network_and_compute()
        manifest = {
            "provider": "Topaz",
            "subscription_id": self.subscription,
            "location": self.location,
            "created": self.created,
            "expected_findings": [
                "Owner assigned at subscription scope",
                "Contributor assigned at subscription scope",
                "Blob container exposed to public access",
                "Storage account permits public Blob access",
                "RDP and SSH exposed from the Internet",
                "Unattached managed disk",
                "Unattached network interface",
                "Unattached public IP address",
            ],
        }
        write_json(Path("output/lab-manifest.json"), manifest)
        return manifest

    def _resource_groups(self) -> None:
        for name, purpose in (("rg-production", "production"), ("rg-operations", "operations")):
            self.api.request(
                "PUT",
                f"/subscriptions/{self.subscription}/resourceGroups/{name}",
                api_version="2021-04-01",
                body={"location": self.location, "tags": {"environment": purpose, "owner": "cloud-team"}},
            )

    def _identities(self) -> dict[str, dict[str, Any]]:
        users = {
            item.get("userPrincipalName"): item
            for item in self.api.list_all("/v1.0/users")
        }
        principals = {
            item.get("displayName"): item
            for item in self.api.list_all("/v1.0/servicePrincipals")
        }
        user_specs = [
            ("alice.admin@topaz.local.dev", "Alice Admin", "alice.admin"),
            ("bob.reader@topaz.local.dev", "Bob Reader", "bob.reader"),
        ]
        result: dict[str, dict[str, Any]] = {}
        for upn, display_name, nickname in user_specs:
            item = users.get(upn)
            if item is None:
                item = self.api.request(
                    "POST",
                    "/v1.0/users",
                    body={
                        "accountEnabled": True,
                        "displayName": display_name,
                        "mailNickname": nickname,
                        "userPrincipalName": upn,
                        "passwordProfile": {
                            "forceChangePasswordNextSignIn": False,
                            "password": "RiskLab-Passw0rd!",
                        },
                    },
                    expected=(200, 201),
                )
            result[nickname] = item
            self.created["identities"].append({"type": "user", "name": upn, "id": item.get("id")})
        service_specs = [
            ("sp-deployment", "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
            ("sp-monitoring", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"),
        ]
        for name, app_id in service_specs:
            item = principals.get(name)
            if item is None:
                item = self.api.request(
                    "POST",
                    "/v1.0/servicePrincipals",
                    body={"accountEnabled": True, "appId": app_id, "displayName": name},
                    expected=(200, 201),
                )
            result[name] = item
            self.created["identities"].append({"type": "servicePrincipal", "name": name, "id": item.get("id")})
        return result

    def _role_assignments(self, identities: dict[str, dict[str, Any]]) -> None:
        subscription_scope = f"/subscriptions/{self.subscription}"
        rg_scope = f"{subscription_scope}/resourceGroups/rg-production"
        specs = [
            (
                subscription_scope,
                "10000000-0000-0000-0000-000000000001",
                identities["alice.admin"].get("id"),
                OWNER_ROLE,
                "User",
                "Alice Admin receives Owner on the subscription",
            ),
            (
                subscription_scope,
                "10000000-0000-0000-0000-000000000002",
                identities["sp-deployment"].get("id"),
                CONTRIBUTOR_ROLE,
                "ServicePrincipal",
                "Deployment service principal receives Contributor on the subscription",
            ),
            (
                rg_scope,
                "10000000-0000-0000-0000-000000000003",
                identities["bob.reader"].get("id"),
                READER_ROLE,
                "User",
                "Bob Reader receives Reader on the production resource group",
            ),
            (
                rg_scope,
                "10000000-0000-0000-0000-000000000004",
                identities["sp-monitoring"].get("id"),
                READER_ROLE,
                "ServicePrincipal",
                "Monitoring service principal receives Reader on the production resource group",
            ),
        ]
        for scope, assignment_id, principal_id, role_id, principal_type, description in specs:
            if not principal_id:
                raise RuntimeError(f"Identity creation did not return an id: {description}")
            path = f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment_id}"
            self.api.request(
                "PUT",
                path,
                api_version="2022-04-01",
                body={
                    "properties": {
                        "principalId": principal_id,
                        "principalType": principal_type,
                        "roleDefinitionId": f"/subscriptions/{self.subscription}/providers/Microsoft.Authorization/roleDefinitions/{role_id}",
                    }
                },
            )
            self.created["role_assignments"].append(
                {"scope": scope, "principal_id": principal_id, "role_id": role_id, "description": description}
            )

    def _storage(self) -> None:
        accounts = [
            (
                "stpublicdata",
                True,
                "Enabled",
                "public-data",
                "container",
                b"customer_id,email\n1001,example@example.invalid\n",
            ),
            (
                "stprivatebackups",
                False,
                "Enabled",
                "private-backups",
                None,
                b"encrypted-backup-placeholder",
            ),
        ]
        for name, allow_public, network_access, container, public_access, content in accounts:
            path = f"/subscriptions/{self.subscription}/resourceGroups/rg-production/providers/Microsoft.Storage/storageAccounts/{name}"
            self.api.request(
                "PUT",
                path,
                api_version="2023-01-01",
                body={
                    "location": self.location,
                    "kind": "StorageV2",
                    "sku": {"name": "Standard_LRS"},
                    "tags": {"environment": "production", "data_classification": "confidential"},
                    "properties": {
                        "allowBlobPublicAccess": allow_public,
                        "minimumTlsVersion": "TLS1_2",
                        "supportsHttpsTrafficOnly": True,
                        "publicNetworkAccess": network_access,
                    },
                },
            )
            keys = self.api.request("POST", f"{path}/listKeys", api_version="2023-01-01", body={})
            key = self._first_storage_key(keys)
            self.api.storage_request(
                name,
                key,
                "PUT",
                f"/{container}",
                params={"restype": "container"},
                expected=(201, 202, 409),
            )
            if public_access:
                self.api.storage_request(
                    name,
                    key,
                    "PUT",
                    f"/{container}",
                    params={"restype": "container", "comp": "acl"},
                    headers={"x-ms-blob-public-access": public_access},
                )
            blob_name = "customers.csv" if allow_public else "backup.dat"
            self.api.storage_request(
                name,
                key,
                "PUT",
                f"/{container}/{blob_name}",
                headers={"x-ms-blob-type": "BlockBlob", "Content-Type": "application/octet-stream"},
                data=content,
                expected=(201, 202),
            )
            self.created["storage"].append(
                {
                    "account": name,
                    "container": container,
                    "public_access": public_access or "private",
                    "allow_blob_public_access": allow_public,
                }
            )

    def _first_storage_key(self, payload: Any) -> str:
        if isinstance(payload, dict):
            keys = payload.get("keys", [])
            if isinstance(keys, list) and keys:
                value = keys[0].get("value")
                if value:
                    return str(value)
        raise RuntimeError("Topaz did not return a storage account key")

    def _network_and_compute(self) -> None:
        rg = "rg-production"
        sub = self.subscription
        vnet_id = resource_id(sub, rg, "Microsoft.Network", "virtualNetworks", "vnet-production")
        subnet_id = f"{vnet_id}/subnets/default"
        nsg_public_id = resource_id(sub, rg, "Microsoft.Network", "networkSecurityGroups", "nsg-public-admin")
        nsg_safe_id = resource_id(sub, rg, "Microsoft.Network", "networkSecurityGroups", "nsg-internal")
        pip_vm_id = resource_id(sub, rg, "Microsoft.Network", "publicIPAddresses", "pip-web-01")
        pip_orphan_id = resource_id(sub, rg, "Microsoft.Network", "publicIPAddresses", "pip-unused")
        nic_vm_id = resource_id(sub, rg, "Microsoft.Network", "networkInterfaces", "nic-web-01")
        nic_orphan_id = resource_id(sub, rg, "Microsoft.Network", "networkInterfaces", "nic-unused")
        disk_data_id = resource_id(sub, rg, "Microsoft.Compute", "disks", "disk-web-data")
        disk_orphan_id = resource_id(sub, rg, "Microsoft.Compute", "disks", "disk-old-backup")
        vm_id = resource_id(sub, rg, "Microsoft.Compute", "virtualMachines", "vm-web-01")

        self.api.request(
            "PUT",
            vnet_id,
            api_version="2024-03-01",
            body={
                "location": self.location,
                "tags": {"environment": "production"},
                "properties": {
                    "addressSpace": {"addressPrefixes": ["10.20.0.0/16"]},
                    "subnets": [{"name": "default", "properties": {"addressPrefix": "10.20.1.0/24"}}],
                },
            },
        )
        self.api.request(
            "PUT",
            nsg_public_id,
            api_version="2024-03-01",
            body={
                "location": self.location,
                "tags": {"environment": "production"},
                "properties": {
                    "securityRules": [
                        {
                            "name": "Allow-RDP-Internet",
                            "properties": {
                                "priority": 100,
                                "direction": "Inbound",
                                "access": "Allow",
                                "protocol": "Tcp",
                                "sourcePortRange": "*",
                                "destinationPortRange": "3389",
                                "sourceAddressPrefix": "Internet",
                                "destinationAddressPrefix": "*",
                            },
                        },
                        {
                            "name": "Allow-SSH-Internet",
                            "properties": {
                                "priority": 110,
                                "direction": "Inbound",
                                "access": "Allow",
                                "protocol": "Tcp",
                                "sourcePortRange": "*",
                                "destinationPortRange": "22",
                                "sourceAddressPrefix": "0.0.0.0/0",
                                "destinationAddressPrefix": "*",
                            },
                        },
                    ]
                },
            },
        )
        self.api.request(
            "PUT",
            nsg_safe_id,
            api_version="2024-03-01",
            body={
                "location": self.location,
                "tags": {"environment": "operations"},
                "properties": {
                    "securityRules": [
                        {
                            "name": "Allow-HTTPS-Internal",
                            "properties": {
                                "priority": 100,
                                "direction": "Inbound",
                                "access": "Allow",
                                "protocol": "Tcp",
                                "sourcePortRange": "*",
                                "destinationPortRange": "443",
                                "sourceAddressPrefix": "10.20.0.0/16",
                                "destinationAddressPrefix": "*",
                            },
                        }
                    ]
                },
            },
        )
        for public_id, allocation in ((pip_vm_id, "Static"), (pip_orphan_id, "Dynamic")):
            self.api.request(
                "PUT",
                public_id,
                api_version="2024-03-01",
                body={
                    "location": self.location,
                    "sku": {"name": "Standard"},
                    "tags": {"environment": "production"},
                    "properties": {"publicIPAllocationMethod": allocation},
                },
            )
        self.api.request(
            "PUT",
            nic_vm_id,
            api_version="2024-03-01",
            body={
                "location": self.location,
                "tags": {"environment": "production"},
                "properties": {
                    "networkSecurityGroup": {"id": nsg_public_id},
                    "ipConfigurations": [
                        {
                            "name": "ipconfig1",
                            "properties": {
                                "privateIPAllocationMethod": "Dynamic",
                                "subnet": {"id": subnet_id},
                                "publicIPAddress": {"id": pip_vm_id},
                            },
                        }
                    ],
                },
            },
        )
        self.api.request(
            "PUT",
            nic_orphan_id,
            api_version="2024-03-01",
            body={
                "location": self.location,
                "tags": {"environment": "operations"},
                "properties": {
                    "networkSecurityGroup": {"id": nsg_safe_id},
                    "ipConfigurations": [
                        {
                            "name": "ipconfig1",
                            "properties": {
                                "privateIPAllocationMethod": "Dynamic",
                                "subnet": {"id": subnet_id},
                            },
                        }
                    ],
                },
            },
        )
        for disk_id, size, classification in (
            (disk_data_id, 64, "internal"),
            (disk_orphan_id, 256, "confidential"),
        ):
            self.api.request(
                "PUT",
                disk_id,
                api_version="2025-11-01",
                body={
                    "location": self.location,
                    "sku": {"name": "Standard_LRS"},
                    "tags": {"environment": "production", "data_classification": classification},
                    "properties": {
                        "creationData": {"createOption": "Empty"},
                        "diskSizeGB": size,
                    },
                },
            )
        self.api.request(
            "PUT",
            vm_id,
            api_version="2025-04-01",
            body={
                "location": self.location,
                "tags": {"environment": "production", "owner": "web-team"},
                "properties": {
                    "hardwareProfile": {"vmSize": "Standard_B2s"},
                    "storageProfile": {
                        "imageReference": {
                            "publisher": "Canonical",
                            "offer": "0001-com-ubuntu-server-jammy",
                            "sku": "22_04-lts-gen2",
                            "version": "latest",
                        },
                        "osDisk": {
                            "name": "vm-web-01-osdisk",
                            "createOption": "FromImage",
                            "managedDisk": {"storageAccountType": "Standard_LRS"},
                        },
                        "dataDisks": [
                            {
                                "name": "disk-web-data",
                                "lun": 0,
                                "createOption": "Attach",
                                "managedDisk": {"id": disk_data_id},
                            }
                        ],
                    },
                    "osProfile": {
                        "computerName": "vm-web-01",
                        "adminUsername": "azureuser",
                        "adminPassword": "RiskLab-Passw0rd!",
                    },
                    "networkProfile": {"networkInterfaces": [{"id": nic_vm_id, "properties": {"primary": True}}]},
                },
            },
        )
        self.created["network"].extend(
            [
                {"type": "nsg", "name": "nsg-public-admin", "id": nsg_public_id},
                {"type": "nsg", "name": "nsg-internal", "id": nsg_safe_id},
                {"type": "public_ip", "name": "pip-web-01", "id": pip_vm_id},
                {"type": "public_ip", "name": "pip-unused", "id": pip_orphan_id},
                {"type": "nic", "name": "nic-web-01", "id": nic_vm_id},
                {"type": "nic", "name": "nic-unused", "id": nic_orphan_id},
            ]
        )
        self.created["compute"].extend(
            [
                {"type": "virtual_machine", "name": "vm-web-01", "id": vm_id},
                {"type": "disk", "name": "disk-web-data", "id": disk_data_id},
                {"type": "disk", "name": "disk-old-backup", "id": disk_orphan_id},
            ]
        )


def print_manifest(manifest: dict[str, Any]) -> None:
    print("\nAzure lab created in Topaz")
    print(f"Subscription: {manifest['subscription_id']}")
    for category, values in manifest["created"].items():
        print(f"{category}: {len(values)}")
    print("Expected security cases:")
    for item in manifest["expected_findings"]:
        print(f"  - {item}")
    print("Lab details: output/lab-manifest.json\n")


def main() -> None:
    settings = Settings()
    builder = LabBuilder(settings)
    try:
        manifest = builder.build()
        print_manifest(manifest)
    finally:
        builder.close()
