from __future__ import annotations

from collections import Counter
from typing import Any


BASE = {"low": 15, "medium": 40, "high": 65, "critical": 85}


class ScoringEngine:
    def score(self, analysis_result: dict[str, Any]) -> dict[str, Any]:
        scored: list[dict[str, Any]] = []
        for item in analysis_result.get("findings", []):
            finding = dict(item)
            initial = str(finding.get("initial_severity", "Low")).lower()
            factors = finding.get("risk_factors", {})
            factor_score = sum(max(0, min(10, int(value))) for value in factors.values())
            score = min(100, BASE.get(initial, 15) + factor_score)
            severity = self._severity(score)
            finding["risk_score"] = score
            finding["severity"] = severity
            scored.append(finding)
        scored.sort(key=lambda value: value.get("risk_score", 0), reverse=True)
        counts = Counter(item["severity"] for item in scored)
        return {
            "findings": scored,
            "finding_count": len(scored),
            "severity_counts": {
                "Critical": counts.get("Critical", 0),
                "High": counts.get("High", 0),
                "Medium": counts.get("Medium", 0),
                "Low": counts.get("Low", 0),
            },
            "maximum_score": max((item["risk_score"] for item in scored), default=0),
        }

    def _severity(self, score: int) -> str:
        if score >= 85:
            return "Critical"
        if score >= 60:
            return "High"
        if score >= 30:
            return "Medium"
        return "Low"
