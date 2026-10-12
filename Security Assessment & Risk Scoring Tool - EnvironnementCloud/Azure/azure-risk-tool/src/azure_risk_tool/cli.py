from __future__ import annotations

import argparse
import sys
from pathlib import Path

from azure_risk_tool.config import Settings
from azure_risk_tool.lab import LabBuilder, print_manifest
from azure_risk_tool.pipeline import Pipeline
from azure_risk_tool.serialization import read_json


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="azure-risk-tool")
    commands = root.add_subparsers(dest="command")
    scan = commands.add_parser("scan")
    scan.add_argument("--output", type=Path, default=Path("output"))
    commands.add_parser("create-lab")
    commands.add_parser("lab-info")
    return root


def main() -> None:
    args = parser().parse_args()
    command = args.command or "scan"
    try:
        if command == "create-lab":
            builder = LabBuilder(Settings())
            try:
                print_manifest(builder.build())
            finally:
                builder.close()
            return
        if command == "lab-info":
            manifest = read_json(Path("output/lab-manifest.json"))
            print_manifest(manifest)
            return
        result = Pipeline(Settings()).run(args.output)
        counts = result["scored"]["severity_counts"]
        print("\nAzure scan completed")
        print(f"Resources: {sum(result['inventory']['metadata']['resource_counts'].values())}")
        print(f"Findings: {result['scored']['finding_count']}")
        print(
            "Severity: "
            + ", ".join(f"{name}={counts.get(name, 0)}" for name in ("Critical", "High", "Medium", "Low"))
        )
        for name, path in result["paths"].items():
            print(f"{name}: {path}")
        print()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
