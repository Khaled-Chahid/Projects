from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from cloud_risk_tool.aws import AWSClientFactory, error_record
from cloud_risk_tool.config import Settings
from cloud_risk_tool.discovery.ec2 import EC2Discovery
from cloud_risk_tool.discovery.iam import IAMDiscovery
from cloud_risk_tool.discovery.s3 import S3Discovery


class DiscoveryManager:
    def __init__(self, settings: Settings, factory: AWSClientFactory) -> None:
        self.settings = settings
        self.factory = factory

    def run(self) -> dict[str, Any]:
        started = datetime.now(timezone.utc)
        identity: dict[str, Any] = {}
        root_errors: list[dict[str, Any]] = []
        try:
            identity = self.factory.identity()
        except Exception as exc:
            root_errors.append(error_record("sts", "GetCallerIdentity", exc))

        account_id = identity.get("Account")
        regions = self._resolve_regions(root_errors)
        iam = IAMDiscovery(self.factory).discover()
        s3 = S3Discovery(self.factory, account_id).discover()
        ec2 = EC2Discovery(self.factory, regions).discover()
        finished = datetime.now(timezone.utc)

        inventory = {
            "metadata": {
                "scan_id": str(uuid4()),
                "started_at": started,
                "finished_at": finished,
                "duration_seconds": round((finished - started).total_seconds(), 3),
                "target": self.settings.target,
                "region": self.settings.region,
                "regions": regions,
                "endpoint_url": self.settings.endpoint_url,
                "account_id": account_id,
                "caller_arn": identity.get("Arn"),
            },
            "iam": iam,
            "s3": s3,
            "ec2": ec2,
            "errors": root_errors + iam.get("errors", []) + s3.get("errors", []) + ec2.get("errors", []),
        }
        inventory["summary"] = self._summary(inventory)
        return inventory

    def _resolve_regions(self, errors: list[dict[str, Any]]) -> list[str]:
        if self.settings.target == "localstack":
            return list(self.settings.regions or (self.settings.region,))
        if self.settings.regions:
            return list(self.settings.regions)
        if not self.settings.all_regions:
            return [self.settings.region]
        try:
            client = self.factory.client("ec2", region_name=self.settings.region)
            response = client.describe_regions(AllRegions=False)
            return sorted(item["RegionName"] for item in response.get("Regions", []))
        except Exception as exc:
            errors.append(error_record("ec2", "DescribeRegions", exc))
            return [self.settings.region]

    @staticmethod
    def _summary(inventory: dict[str, Any]) -> dict[str, int]:
        ec2_regions = inventory.get("ec2", {}).get("regions", {})
        return {
            "iam_users": len(inventory.get("iam", {}).get("users", [])),
            "iam_roles": len(inventory.get("iam", {}).get("roles", [])),
            "iam_groups": len(inventory.get("iam", {}).get("groups", [])),
            "s3_buckets": len(inventory.get("s3", {}).get("buckets", [])),
            "ec2_instances": sum(len(data.get("instances", [])) for data in ec2_regions.values()),
            "ebs_volumes": sum(len(data.get("volumes", [])) for data in ec2_regions.values()),
            "elastic_ips": sum(len(data.get("elastic_ips", [])) for data in ec2_regions.values()),
            "network_interfaces": sum(len(data.get("network_interfaces", [])) for data in ec2_regions.values()),
            "discovery_errors": len(inventory.get("errors", [])),
        }
