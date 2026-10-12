from __future__ import annotations

from typing import Any

from azure_risk_tool.analysis import network, orphan, rbac, storage


class AnalysisManager:
    def run(self, inventory: dict[str, Any]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        for analyzer in (rbac.analyze, storage.analyze, network.analyze, orphan.analyze):
            findings.extend(analyzer(inventory))
        return {
            "findings": findings,
            "finding_count": len(findings),
            "rules_executed": [
                "AZ-RBAC-001",
                "AZ-RBAC-002",
                "AZ-RBAC-003",
                "AZ-STG-001",
                "AZ-STG-002",
                "AZ-NET-001",
                "AZ-NET-002",
                "AZ-ORPH-001",
                "AZ-ORPH-002",
                "AZ-ORPH-003",
            ],
        }
