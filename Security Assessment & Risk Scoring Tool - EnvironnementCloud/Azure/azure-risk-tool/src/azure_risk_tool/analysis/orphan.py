from __future__ import annotations

from typing import Any

from azure_risk_tool.analysis.common import finding, normalized_id, properties


def analyze(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    attached_disks: set[str] = set()
    attached_disk_names: set[str] = set()
    attached_nics: set[str] = set()
    attached_public_ips: set[str] = set()
    for vm in inventory.get("virtual_machines", []):
        vm_props = properties(vm)
        storage = vm_props.get("storageProfile", {})
        if isinstance(storage, dict):
            os_disk = storage.get("osDisk", {})
            if isinstance(os_disk, dict):
                disk_name = normalized_id(os_disk.get("name"))
                if disk_name:
                    attached_disk_names.add(disk_name)
                managed = os_disk.get("managedDisk", {})
                if isinstance(managed, dict):
                    disk_id = normalized_id(managed.get("id"))
                    if disk_id:
                        attached_disks.add(disk_id)
            for disk in storage.get("dataDisks", []) or []:
                if not isinstance(disk, dict):
                    continue
                disk_name = normalized_id(disk.get("name"))
                if disk_name:
                    attached_disk_names.add(disk_name)
                managed = disk.get("managedDisk", {})
                if isinstance(managed, dict):
                    disk_id = normalized_id(managed.get("id"))
                    if disk_id:
                        attached_disks.add(disk_id)
        network = vm_props.get("networkProfile", {})
        if isinstance(network, dict):
            for nic in network.get("networkInterfaces", []) or []:
                if isinstance(nic, dict):
                    attached_nics.add(normalized_id(nic.get("id")))
    for nic in inventory.get("network_interfaces", []):
        nic_id = normalized_id(nic.get("id"))
        if nic_id in attached_nics:
            for configuration in properties(nic).get("ipConfigurations", []) or []:
                if not isinstance(configuration, dict):
                    continue
                public_ip = properties(configuration).get("publicIPAddress", {})
                if isinstance(public_ip, dict):
                    attached_public_ips.add(normalized_id(public_ip.get("id")))
    for disk in inventory.get("managed_disks", []):
        disk_id = normalized_id(disk.get("id"))
        disk_name = normalized_id(disk.get("name"))
        managed_by = normalized_id(disk.get("managedBy"))
        if (
            disk_id
            and disk_id not in attached_disks
            and disk_name not in attached_disk_names
            and not managed_by
        ):
            findings.append(
                finding(
                    "AZ-ORPH-001",
                    "Managed disk is not attached to a virtual machine",
                    "Orphaned Asset",
                    "Medium",
                    disk,
                    "The managed disk is not referenced by any discovered virtual machine.",
                    {"disk_id": disk.get("id"), "disk_size_gb": properties(disk).get("diskSizeGB")},
                    "Validate whether the disk is still needed, snapshot required data and delete unused disks.",
                    sensitivity=_sensitivity(disk),
                )
            )
    for nic in inventory.get("network_interfaces", []):
        nic_id = normalized_id(nic.get("id"))
        virtual_machine = properties(nic).get("virtualMachine")
        if nic_id and nic_id not in attached_nics and not virtual_machine:
            findings.append(
                finding(
                    "AZ-ORPH-002",
                    "Network interface is not attached to a virtual machine",
                    "Orphaned Asset",
                    "Low",
                    nic,
                    "The network interface is not referenced by any discovered virtual machine.",
                    {"network_interface_id": nic.get("id")},
                    "Confirm that the interface is unused and remove it to simplify the environment.",
                )
            )
    for public_ip in inventory.get("public_ip_addresses", []):
        public_id = normalized_id(public_ip.get("id"))
        ip_configuration = properties(public_ip).get("ipConfiguration")
        if public_id and public_id not in attached_public_ips and not ip_configuration:
            findings.append(
                finding(
                    "AZ-ORPH-003",
                    "Public IP address is not attached to a resource",
                    "Orphaned Asset",
                    "Low",
                    public_ip,
                    "The public IP address is not referenced by an attached network interface.",
                    {"public_ip_id": public_ip.get("id"), "ip_address": properties(public_ip).get("ipAddress")},
                    "Release the public IP if no active service requires it.",
                    internet_exposure=2,
                )
            )
    return findings


def _sensitivity(resource: dict[str, Any]) -> int:
    tags = resource.get("tags", {})
    value = str(tags.get("data_classification", "")).lower() if isinstance(tags, dict) else ""
    return 8 if value in {"confidential", "restricted", "sensitive"} else 3
