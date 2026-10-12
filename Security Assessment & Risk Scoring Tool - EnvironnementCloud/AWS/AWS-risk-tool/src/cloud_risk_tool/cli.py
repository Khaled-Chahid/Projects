from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cloud_risk_tool.config import Settings
from cloud_risk_tool.pipeline import ScanPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-risk-tool",
        description="Discover AWS resources, detect misconfigurations, score risks, and generate reports.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="Run the complete discovery-to-reporting pipeline")
    scan.add_argument("--target", choices=("localstack", "aws"), default=None)
    scan.add_argument("--region", default=None, help="Primary AWS region")
    scan.add_argument("--regions", default=None, help="Comma-separated EC2 regions")
    scan.add_argument("--all-regions", action="store_true", help="Scan all enabled AWS regions (real AWS only)")
    scan.add_argument("--endpoint-url", default=None, help="Custom AWS-compatible endpoint URL")
    scan.add_argument("--profile", default=None, help="AWS profile for real AWS")
    scan.add_argument("--output-dir", default=None, help="Report output directory")
    scan.add_argument("--access-key-max-age-days", type=int, default=None)
    scan.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="none",
        help="Return exit code 2 when a finding meets or exceeds this severity",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "scan":
        return 1

    settings = Settings.from_env().with_overrides(
        target=args.target,
        region=args.region,
        regions=(part.strip() for part in args.regions.split(",") if part.strip()) if args.regions else None,
        all_regions=True if args.all_regions else None,
        endpoint_url=args.endpoint_url,
        profile=args.profile,
        output_dir=args.output_dir,
        access_key_max_age_days=args.access_key_max_age_days,
    )

    try:
        result = ScanPipeline(settings).run()
    except KeyboardInterrupt:
        print("Scan interrupted.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Scan failed: {exc}", file=sys.stderr)
        return 1

    summary = result["scored"]["summary"]
    print("\nCloud Risk Tool scan completed")
    print(f"  Target:   {settings.target}")
    print(f"  Findings: {summary['total']}")
    print(
        "  Severity: "
        f"Critical={summary['Critical']} High={summary['High']} "
        f"Medium={summary['Medium']} Low={summary['Low']}"
    )
    print("  Reports:")
    for name, path in result["paths"].items():
        print(f"    {name:12} {Path(path).resolve()}")

    threshold = args.fail_on.capitalize()
    if args.fail_on != "none":
        order = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        if any(order[item["severity"]] >= order[threshold] for item in result["scored"]["findings"]):
            return 2
    return 0
