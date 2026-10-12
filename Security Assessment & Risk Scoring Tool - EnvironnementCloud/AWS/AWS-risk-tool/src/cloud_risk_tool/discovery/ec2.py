from __future__ import annotations

from typing import Any

from cloud_risk_tool.aws import AWSClientFactory, error_record


class EC2Discovery:
    def __init__(self, factory: AWSClientFactory, regions: list[str]) -> None:
        self.factory = factory
        self.regions = regions
        self.errors: list[dict[str, Any]] = []

    def discover(self) -> dict[str, Any]:
        by_region: dict[str, Any] = {}
        for region in self.regions:
            client = self.factory.client("ec2", region_name=region)
            by_region[region] = {
                "instances": self._instances(client, region),
                "volumes": self._volumes(client, region),
                "elastic_ips": self._elastic_ips(client, region),
                "network_interfaces": self._network_interfaces(client, region),
            }
        return {"regions": by_region, "errors": self.errors}

    def _instances(self, client: Any, region: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        try:
            paginator = client.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        items.append(
                            {
                                "instance_id": instance.get("InstanceId"),
                                "state": (instance.get("State") or {}).get("Name"),
                                "instance_type": instance.get("InstanceType"),
                                "vpc_id": instance.get("VpcId"),
                                "subnet_id": instance.get("SubnetId"),
                                "launch_time": instance.get("LaunchTime"),
                                "tags": self._tags(instance.get("Tags", [])),
                            }
                        )
        except Exception as exc:
            self.errors.append(error_record("ec2", "DescribeInstances", exc, region))
        return items

    def _volumes(self, client: Any, region: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        try:
            paginator = client.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page.get("Volumes", []):
                    items.append(
                        {
                            "volume_id": volume.get("VolumeId"),
                            "state": volume.get("State"),
                            "size_gib": volume.get("Size"),
                            "volume_type": volume.get("VolumeType"),
                            "availability_zone": volume.get("AvailabilityZone"),
                            "create_time": volume.get("CreateTime"),
                            "encrypted": volume.get("Encrypted"),
                            "attachments": volume.get("Attachments", []),
                            "tags": self._tags(volume.get("Tags", [])),
                        }
                    )
        except Exception as exc:
            self.errors.append(error_record("ec2", "DescribeVolumes", exc, region))
        return items

    def _elastic_ips(self, client: Any, region: str) -> list[dict[str, Any]]:
        try:
            addresses = client.describe_addresses().get("Addresses", [])
        except Exception as exc:
            self.errors.append(error_record("ec2", "DescribeAddresses", exc, region))
            return []
        return [
            {
                "allocation_id": item.get("AllocationId"),
                "association_id": item.get("AssociationId"),
                "public_ip": item.get("PublicIp"),
                "instance_id": item.get("InstanceId"),
                "network_interface_id": item.get("NetworkInterfaceId"),
                "private_ip_address": item.get("PrivateIpAddress"),
                "domain": item.get("Domain"),
                "tags": self._tags(item.get("Tags", [])),
            }
            for item in addresses
        ]

    def _network_interfaces(self, client: Any, region: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        try:
            paginator = client.get_paginator("describe_network_interfaces")
            for page in paginator.paginate():
                for eni in page.get("NetworkInterfaces", []):
                    items.append(
                        {
                            "network_interface_id": eni.get("NetworkInterfaceId"),
                            "status": eni.get("Status"),
                            "interface_type": eni.get("InterfaceType"),
                            "requester_managed": eni.get("RequesterManaged", False),
                            "description": eni.get("Description"),
                            "vpc_id": eni.get("VpcId"),
                            "subnet_id": eni.get("SubnetId"),
                            "attachment": eni.get("Attachment"),
                            "tags": self._tags(eni.get("TagSet", [])),
                        }
                    )
        except Exception as exc:
            self.errors.append(error_record("ec2", "DescribeNetworkInterfaces", exc, region))
        return items

    @staticmethod
    def _tags(items: list[dict[str, Any]]) -> dict[str, str]:
        return {item.get("Key"): item.get("Value") for item in items if item.get("Key")}
