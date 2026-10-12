from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cloud_risk_tool.analysis.iam import IAMAnalyzer
from cloud_risk_tool.analysis.orphan import OrphanAnalyzer
from cloud_risk_tool.analysis.s3 import S3Analyzer


class AnalysisManager:
    def __init__(self, *, access_key_max_age_days: int = 90) -> None:
        self.iam = IAMAnalyzer(access_key_max_age_days=access_key_max_age_days)
        self.s3 = S3Analyzer()
        self.orphan = OrphanAnalyzer()

    def run(self, inventory: dict[str, Any]) -> dict[str, Any]:
        findings = []
        findings.extend(self.iam.analyze(inventory.get("iam", {})))
        findings.extend(self.s3.analyze(inventory.get("s3", {})))
        findings.extend(self.orphan.analyze(inventory.get("ec2", {})))
        findings.sort(key=lambda item: (item["category"], item["rule_id"], item["resource_id"] or ""))
        return {
            "metadata": {
                "scan_id": inventory.get("metadata", {}).get("scan_id"),
                "analyzed_at": datetime.now(timezone.utc),
                "finding_count": len(findings),
            },
            "findings": findings,
            "summary": self._summary(findings),
        }

    @staticmethod
    def _summary(findings: list[dict[str, Any]]) -> dict[str, int]:
        summary: dict[str, int] = {"total": len(findings)}
        for finding in findings:
            category = finding.get("category", "Unknown")
            summary[category] = summary.get(category, 0) + 1
        return summary
