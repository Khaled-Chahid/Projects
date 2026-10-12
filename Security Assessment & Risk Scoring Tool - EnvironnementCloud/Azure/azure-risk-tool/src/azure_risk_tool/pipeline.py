from __future__ import annotations

from pathlib import Path
from typing import Any

from azure_risk_tool.analysis.manager import AnalysisManager
from azure_risk_tool.config import Settings
from azure_risk_tool.discovery.manager import DiscoveryManager
from azure_risk_tool.reporting.generator import ReportGenerator
from azure_risk_tool.scoring.engine import ScoringEngine


class Pipeline:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def run(self, output_dir: Path | None = None) -> dict[str, Any]:
        inventory = DiscoveryManager(self.settings).run()
        analysis = AnalysisManager().run(inventory)
        scored = ScoringEngine().score(analysis)
        paths = ReportGenerator().generate(
            inventory,
            analysis,
            scored,
            output_dir or self.settings.output_dir,
        )
        return {"inventory": inventory, "analysis": analysis, "scored": scored, "paths": paths}
