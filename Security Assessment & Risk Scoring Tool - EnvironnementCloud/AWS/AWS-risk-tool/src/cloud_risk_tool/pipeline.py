from __future__ import annotations

from pathlib import Path
from typing import Any

from cloud_risk_tool.analysis import AnalysisManager
from cloud_risk_tool.aws import AWSClientFactory
from cloud_risk_tool.config import Settings
from cloud_risk_tool.discovery import DiscoveryManager
from cloud_risk_tool.reporting import ReportGenerator
from cloud_risk_tool.scoring import RiskScoringEngine


class ScanPipeline:
    def __init__(self, settings: Settings) -> None:
        settings.validate()
        self.settings = settings
        self.factory = AWSClientFactory(settings)
        self.discovery = DiscoveryManager(settings, self.factory)
        self.analysis = AnalysisManager(access_key_max_age_days=settings.access_key_max_age_days)
        self.scoring = RiskScoringEngine()
        self.reporting = ReportGenerator()

    def run(self) -> dict[str, Any]:
        inventory = self.discovery.run()
        analysis_result = self.analysis.run(inventory)
        scored_result = self.scoring.run(analysis_result)
        paths = self.reporting.generate(
            inventory,
            analysis_result,
            scored_result,
            Path(self.settings.output_dir),
        )
        return {
            "inventory": inventory,
            "analysis": analysis_result,
            "scored": scored_result,
            "paths": paths,
        }
