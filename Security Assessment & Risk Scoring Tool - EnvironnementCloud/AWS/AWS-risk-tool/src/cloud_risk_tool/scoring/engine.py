from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from typing import Any


class RiskScoringEngine:
    SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

    def run(self, analysis_result: dict[str, Any]) -> dict[str, Any]:
        scored = [self.score_finding(item) for item in analysis_result.get("findings", [])]
        scored.sort(
            key=lambda item: (
                -self.SEVERITY_ORDER[item["severity"]],
                -item["score"],
                item["rule_id"],
                item.get("resource_id") or "",
            )
        )
        return {
            "metadata": {
                "scan_id": analysis_result.get("metadata", {}).get("scan_id"),
                "scored_at": datetime.now(timezone.utc),
                "finding_count": len(scored),
                "scoring_model": "weighted-impact-likelihood-v1",
            },
            "findings": scored,
            "summary": self._summary(scored),
        }

    def score_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        result = deepcopy(finding)
        risk = result.get("risk_input", {})
        impact = self._clamp(int(risk.get("impact", 1)), 1, 5)
        likelihood = self._clamp(int(risk.get("likelihood", 1)), 1, 5)
        exposure = self._clamp(int(risk.get("exposure", 0)), 0, 1)

        base = (((impact * 0.6) + (likelihood * 0.4)) / 5.0) * 9.0
        exposure_bonus = float(exposure)
        tag_bonus, tag_reasons = self._tag_modifier(result.get("tags", {}))
        score = round(min(10.0, max(0.0, base + exposure_bonus + tag_bonus)), 1)
        severity = self._severity(score)

        result["score"] = score
        result["severity"] = severity
        result["score_breakdown"] = {
            "impact": impact,
            "likelihood": likelihood,
            "exposure_bonus": exposure_bonus,
            "tag_bonus": tag_bonus,
            "tag_reasons": tag_reasons,
            "formula": "(((impact*0.6)+(likelihood*0.4))/5)*9 + exposure + tag_bonus",
        }
        return result

    @staticmethod
    def _tag_modifier(tags: dict[str, str]) -> tuple[float, list[str]]:
        normalized = {str(key).lower(): str(value).lower() for key, value in (tags or {}).items()}
        bonus = 0.0
        reasons: list[str] = []
        if normalized.get("criticality") in {"high", "critical"}:
            bonus += 0.7
            reasons.append("Criticality tag is high/critical")
        if normalized.get("dataclassification") in {"confidential", "restricted", "secret"}:
            bonus += 0.8
            reasons.append("DataClassification tag indicates sensitive data")
        if normalized.get("environment") in {"prod", "production"}:
            bonus += 0.4
            reasons.append("Environment tag indicates production")
        return round(min(1.5, bonus), 1), reasons

    @staticmethod
    def _severity(score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Medium"
        return "Low"

    @staticmethod
    def _clamp(value: int, minimum: int, maximum: int) -> int:
        return min(maximum, max(minimum, value))

    @staticmethod
    def _summary(findings: list[dict[str, Any]]) -> dict[str, int]:
        summary = {"total": len(findings), "Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for finding in findings:
            severity = finding["severity"]
            summary[severity] += 1
        return summary
