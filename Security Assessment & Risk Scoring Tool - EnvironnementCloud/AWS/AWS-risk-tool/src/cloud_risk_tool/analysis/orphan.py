from __future__ import annotations

from typing import Any

from cloud_risk_tool.analysis.common import make_finding


class OrphanAnalyzer:
    def analyze(self, data: dict[str, Any]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for region, resources in data.get("regions", {}).items():
            findings.extend(self._volumes(resources.get("volumes", []), region))
            findings.extend(self._elastic_ips(resources.get("elastic_ips", []), region))
            findings.extend(self._network_interfaces(resources.get("network_interfaces", []), region))
        return findings

    @staticmethod
    def _volumes(volumes: list[dict[str, Any]], region: str) -> list[dict[str, Any]]:
        findings = []
        for volume in volumes:
            if volume.get("state") == "available" and not volume.get("attachments"):
                findings.append(
                    make_finding(
                        rule_id="ORPHAN-001",
                        category="Orphaned Asset",
                        resource_type="EBSVolume",
                        resource_id=volume.get("volume_id"),
                        title="Potentially orphaned EBS volume",
                        description="The EBS volume is available and has no instance attachment.",
                        evidence={
                            "state": volume.get("state"),
                            "attachments": volume.get("attachments", []),
                            "size_gib": volume.get("size_gib"),
                            "volume_type": volume.get("volume_type"),
                        },
                        recommendation="Confirm that the volume is no longer required, snapshot it if necessary, then remove it through an approved process.",
                        impact=2,
                        likelihood=3,
                        region=region,
                        tags=volume.get("tags", {}),
                    )
                )
        return findings

    @staticmethod
    def _elastic_ips(addresses: list[dict[str, Any]], region: str) -> list[dict[str, Any]]:
        findings = []
        for address in addresses:
            associated = any(
                address.get(key)
                for key in ("association_id", "instance_id", "network_interface_id")
            )
            if not associated:
                findings.append(
                    make_finding(
                        rule_id="ORPHAN-002",
                        category="Orphaned Asset",
                        resource_type="ElasticIP",
                        resource_id=address.get("allocation_id") or address.get("public_ip"),
                        title="Unassociated Elastic IP address",
                        description="The allocated Elastic IP is not associated with an instance or network interface.",
                        evidence={"public_ip": address.get("public_ip"), "association_id": address.get("association_id")},
                        recommendation="Release the address if it is not reserved for a documented future use.",
                        impact=1,
                        likelihood=3,
                        region=region,
                        tags=address.get("tags", {}),
                    )
                )
        return findings

    @staticmethod
    def _network_interfaces(interfaces: list[dict[str, Any]], region: str) -> list[dict[str, Any]]:
        findings = []
        for interface in interfaces:
            if interface.get("requester_managed"):
                continue
            if interface.get("interface_type") not in {None, "interface"}:
                continue
            if interface.get("status") == "available" and not interface.get("attachment"):
                findings.append(
                    make_finding(
                        rule_id="ORPHAN-003",
                        category="Orphaned Asset",
                        resource_type="NetworkInterface",
                        resource_id=interface.get("network_interface_id"),
                        title="Detached network interface",
                        description="The customer-managed network interface is available and has no attachment.",
                        evidence={
                            "status": interface.get("status"),
                            "attachment": interface.get("attachment"),
                            "description": interface.get("description"),
                        },
                        recommendation="Verify dependencies and delete the interface if it is no longer needed.",
                        impact=1,
                        likelihood=2,
                        region=region,
                        tags=interface.get("tags", {}),
                    )
                )
        return findings
