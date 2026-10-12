from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from cloud_risk_tool.serialization import write_json


class ReportGenerator:
    def generate(
        self,
        inventory: dict[str, Any],
        analysis_result: dict[str, Any],
        scored_result: dict[str, Any],
        output_dir: Path,
    ) -> dict[str, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)

        inventory_path = output_dir / "inventory.json"
        findings_path = output_dir / "findings.json"
        report_json_path = output_dir / "report.json"
        report_html_path = output_dir / "report.html"

        write_json(inventory_path, inventory)
        write_json(findings_path, analysis_result)

        report = self._report_payload(inventory, scored_result)

        write_json(report_json_path, report)
        report_html_path.write_text(
            self._html(report),
            encoding="utf-8",
        )

        return {
            "inventory": inventory_path,
            "findings": findings_path,
            "report_json": report_json_path,
            "report_html": report_html_path,
        }

    @staticmethod
    def _report_payload(
        inventory: dict[str, Any],
        scored_result: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "metadata": {
                **inventory.get("metadata", {}),
                "generated_at": datetime.now(timezone.utc),
                "tool": "cloud-risk-tool",
                "version": "0.1.0",
            },
            "inventory_summary": inventory.get("summary", {}),
            "risk_summary": scored_result.get("summary", {}),
            "findings": scored_result.get("findings", []),
            "scan_errors": inventory.get("errors", []),
        }

    @staticmethod
    def _pretty_name(value: Any) -> str:
        return str(value).replace("_", " ").strip().title()

    @staticmethod
    def _format_value(value: Any) -> str:
        if value is None:
            return "-"

        if isinstance(value, bool):
            return "Yes" if value else "No"

        if isinstance(value, (dict, list, tuple)):
            return json.dumps(
                value,
                ensure_ascii=False,
                default=str,
                indent=2,
            )

        return str(value)

    @staticmethod
    def _is_fake_account(value: Any) -> bool:
        """
        Hide LocalStack placeholder account IDs such as:
        000000000000

        A real AWS account ID will still be displayed.
        """
        account = str(value or "").strip()

        if not account:
            return True

        return account and set(account) == {"0"}

    def _metadata_html(self, metadata: dict[str, Any]) -> str:
        rows: list[str] = []

        ignored = {
            "generated_at",
            "tool",
            "version",
        }

        for key, value in metadata.items():
            normalized_key = str(key).lower()

            if normalized_key in ignored:
                continue

            if normalized_key in {
                "account",
                "account_id",
                "aws_account",
                "aws_account_id",
            } and self._is_fake_account(value):
                continue

            if value in (None, "", [], {}):
                continue

            rows.append(
                "<div class='info-item'>"
                f"<span>{escape(self._pretty_name(key))}</span>"
                f"<strong>{escape(self._format_value(value))}</strong>"
                "</div>"
            )

        generated = metadata.get("generated_at")

        if generated:
            rows.append(
                "<div class='info-item'>"
                "<span>Generated At</span>"
                f"<strong>{escape(str(generated))}</strong>"
                "</div>"
            )

        return "".join(rows)

    def _inventory_html(self, inventory: dict[str, Any]) -> str:
        if not inventory:
            return """
            <div class="empty-state">
                No inventory information available.
            </div>
            """

        rows = []

        for key, value in inventory.items():
            rows.append(
                "<tr>"
                f"<th>{escape(self._pretty_name(key))}</th>"
                f"<td>{escape(self._format_value(value))}</td>"
                "</tr>"
            )

        return (
            '<table class="inventory-table">'
            "<tbody>"
            + "".join(rows)
            + "</tbody>"
            "</table>"
        )

    def _evidence_html(self, evidence: Any) -> str:
        if evidence in (None, "", {}, []):
            return '<span class="muted">No additional evidence.</span>'

        if isinstance(evidence, dict):
            rows = []

            for key, value in evidence.items():
                formatted = self._format_value(value)

                if isinstance(value, (dict, list, tuple)):
                    rendered_value = (
                        f"<pre>{escape(formatted)}</pre>"
                    )
                else:
                    rendered_value = escape(formatted)

                rows.append(
                    "<div class='evidence-row'>"
                    f"<span>{escape(self._pretty_name(key))}</span>"
                    f"<div>{rendered_value}</div>"
                    "</div>"
                )

            return "".join(rows)

        if isinstance(evidence, (list, tuple)):
            items = "".join(
                f"<li>{escape(self._format_value(item))}</li>"
                for item in evidence
            )
            return f"<ul class='evidence-list'>{items}</ul>"

        return f"<pre>{escape(str(evidence))}</pre>"

    def _finding_card(
        self,
        item: dict[str, Any],
        number: int,
    ) -> str:
        severity = str(item.get("severity", "Low")).strip() or "Low"
        severity_class = severity.lower()

        title = escape(str(item.get("title", "Unnamed finding")))
        description = escape(str(item.get("description", "")).strip())

        score = item.get("score")
        rule_id = item.get("rule_id")
        resource_id = item.get("resource_id")
        region = item.get("region")
        recommendation = item.get("recommendation", "")
        evidence = item.get("evidence", {})

        metadata_parts = []

        if score not in (None, ""):
            metadata_parts.append(
                "<div class='finding-meta-item'>"
                "<span>Score</span>"
                f"<strong>{escape(str(score))}</strong>"
                "</div>"
            )

        if rule_id not in (None, ""):
            metadata_parts.append(
                "<div class='finding-meta-item'>"
                "<span>Rule</span>"
                f"<strong>{escape(str(rule_id))}</strong>"
                "</div>"
            )

        if resource_id not in (None, ""):
            resource_text = escape(str(resource_id))

            if region:
                resource_text += (
                    f"<small>Region: {escape(str(region))}</small>"
                )

            metadata_parts.append(
                "<div class='finding-meta-item resource-item'>"
                "<span>Resource</span>"
                f"<strong>{resource_text}</strong>"
                "</div>"
            )

        description_html = ""

        if description:
            description_html = (
                "<div class='finding-section'>"
                "<h4>Description</h4>"
                f"<p>{description}</p>"
                "</div>"
            )

        recommendation_html = ""

        if recommendation:
            recommendation_html = (
                "<div class='finding-section recommendation'>"
                "<h4>Recommendation</h4>"
                f"<p>{escape(str(recommendation))}</p>"
                "</div>"
            )

        return f"""
        <article class="finding-card severity-{escape(severity_class)}">
            <div class="finding-header">
                <div>
                    <div class="finding-number">
                        Finding #{number}
                    </div>

                    <h3>{title}</h3>
                </div>

                <span class="severity-badge severity-{escape(severity_class)}">
                    {escape(severity)}
                </span>
            </div>

            <div class="finding-metadata">
                {''.join(metadata_parts)}
            </div>

            {description_html}

            <div class="finding-section">
                <h4>Evidence</h4>

                <div class="evidence-box">
                    {self._evidence_html(evidence)}
                </div>
            </div>

            {recommendation_html}
        </article>
        """

    def _findings_html(
        self,
        findings: list[dict[str, Any]],
    ) -> str:
        if not findings:
            return """
            <div class="empty-state success-state">
                No security findings were detected.
            </div>
            """

        return "".join(
            self._finding_card(item, index)
            for index, item in enumerate(findings, start=1)
        )

    def _errors_html(
        self,
        errors: list[dict[str, Any]],
    ) -> str:
        if not errors:
            return ""

        rows = []

        for item in errors:
            rows.append(
                "<tr>"
                f"<td>{escape(str(item.get('component', '')))}</td>"
                f"<td>{escape(str(item.get('operation', '')))}</td>"
                f"<td>{escape(str(item.get('code', '')))}</td>"
                f"<td>{escape(str(item.get('resource', '')))}</td>"
                f"<td>{escape(str(item.get('message', '')))}</td>"
                "</tr>"
            )

        return f"""
        <section class="section">
            <div class="section-header">
                <div>
                    <span class="section-label">Scan health</span>
                    <h2>Discovery Errors</h2>
                </div>

                <span class="count-badge">{len(errors)}</span>
            </div>

            <div class="table-wrapper">
                <table class="errors-table">
                    <thead>
                        <tr>
                            <th>Component</th>
                            <th>Operation</th>
                            <th>Code</th>
                            <th>Resource</th>
                            <th>Message</th>
                        </tr>
                    </thead>

                    <tbody>
                        {''.join(rows)}
                    </tbody>
                </table>
            </div>
        </section>
        """

    def _html(self, report: dict[str, Any]) -> str:
        metadata = report.get("metadata", {})
        summary = report.get("risk_summary", {})
        findings = report.get("findings", [])
        inventory = report.get("inventory_summary", {})
        errors = report.get("scan_errors", [])

        severity_names = (
            "Critical",
            "High",
            "Medium",
            "Low",
        )

        severity_cards = "".join(
            f"""
            <div class="metric-card metric-{name.lower()}">
                <span>{escape(name)}</span>
                <strong>{escape(str(summary.get(name, 0)))}</strong>
            </div>
            """
            for name in severity_names
        )

        total_findings = len(findings)

        overall_score = (
            summary.get("overall_score")
            or summary.get("risk_score")
            or summary.get("total_score")
        )

        score_card = ""

        if overall_score is not None:
            score_card = f"""
            <div class="summary-extra">
                <span>Overall Risk Score</span>
                <strong>{escape(str(overall_score))}</strong>
            </div>
            """

        metadata_html = self._metadata_html(metadata)
        inventory_html = self._inventory_html(inventory)
        findings_html = self._findings_html(findings)
        errors_html = self._errors_html(errors)

        return f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <title>Cloud Risk Assessment Report</title>

    <style>
        * {{
            box-sizing: border-box;
        }}

        :root {{
            --background: #f4f6f8;
            --surface: #ffffff;
            --surface-soft: #f8fafc;

            --text: #17202a;
            --muted: #667085;

            --border: #e4e7ec;

            --critical: #7f1d1d;
            --critical-soft: #fef2f2;

            --high: #b42318;
            --high-soft: #fff4ed;

            --medium: #b54708;
            --medium-soft: #fffaeb;

            --low: #175cd3;
            --low-soft: #eff8ff;

            --success: #027a48;
            --success-soft: #ecfdf3;

            --shadow:
                0 1px 2px rgba(16, 24, 40, 0.04),
                0 4px 12px rgba(16, 24, 40, 0.05);
        }}

        body {{
            margin: 0;
            background: var(--background);
            color: var(--text);
            font-family:
                Inter,
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                Roboto,
                Arial,
                sans-serif;

            font-size: 14px;
            line-height: 1.6;
        }}

        .container {{
            width: min(1180px, calc(100% - 40px));
            margin: 40px auto 80px;
        }}

        .report-header {{
            padding: 32px;
            margin-bottom: 24px;

            background: #101828;
            color: white;

            border-radius: 14px;
            box-shadow: var(--shadow);
        }}

        .report-header .eyebrow {{
            margin: 0 0 6px;

            color: #98a2b3;

            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }}

        .report-header h1 {{
            margin: 0;
            font-size: 30px;
            line-height: 1.2;
        }}

        .report-header p {{
            margin: 10px 0 0;
            color: #d0d5dd;
        }}

        .metadata-grid {{
            display: grid;

            grid-template-columns:
                repeat(auto-fit, minmax(220px, 1fr));

            gap: 12px;

            margin-top: 24px;
        }}

        .info-item {{
            padding: 12px 14px;

            background: rgba(255, 255, 255, 0.06);

            border:
                1px solid
                rgba(255, 255, 255, 0.09);

            border-radius: 8px;
        }}

        .info-item span {{
            display: block;

            margin-bottom: 2px;

            color: #98a2b3;

            font-size: 11px;
            font-weight: 700;

            text-transform: uppercase;
        }}

        .info-item strong {{
            display: block;
            overflow-wrap: anywhere;

            color: white;
            font-size: 13px;
            font-weight: 600;
        }}

        .section {{
            padding: 26px;
            margin-top: 24px;

            background: var(--surface);

            border: 1px solid var(--border);
            border-radius: 12px;

            box-shadow: var(--shadow);
        }}

        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;

            gap: 20px;
            margin-bottom: 20px;
        }}

        .section-label {{
            display: block;

            margin-bottom: 3px;

            color: var(--muted);

            font-size: 11px;
            font-weight: 700;

            letter-spacing: 0.06em;
            text-transform: uppercase;
        }}

        h2 {{
            margin: 0;

            font-size: 21px;
            line-height: 1.3;
        }}

        .count-badge {{
            min-width: 38px;
            padding: 4px 10px;

            text-align: center;

            background: #f2f4f7;
            color: #344054;

            border-radius: 999px;

            font-size: 13px;
            font-weight: 700;
        }}

        .metrics-grid {{
            display: grid;

            grid-template-columns:
                repeat(4, minmax(120px, 1fr));

            gap: 14px;
        }}

        .metric-card {{
            padding: 18px;

            border: 1px solid var(--border);
            border-radius: 10px;
        }}

        .metric-card span {{
            display: block;

            margin-bottom: 7px;

            font-size: 12px;
            font-weight: 700;

            text-transform: uppercase;
        }}

        .metric-card strong {{
            font-size: 30px;
            line-height: 1;
        }}

        .metric-critical {{
            color: var(--critical);
            background: var(--critical-soft);
        }}

        .metric-high {{
            color: var(--high);
            background: var(--high-soft);
        }}

        .metric-medium {{
            color: var(--medium);
            background: var(--medium-soft);
        }}

        .metric-low {{
            color: var(--low);
            background: var(--low-soft);
        }}

        .summary-footer {{
            display: flex;
            flex-wrap: wrap;

            gap: 12px;

            margin-top: 16px;
        }}

        .summary-extra {{
            padding: 10px 14px;

            background: var(--surface-soft);

            border: 1px solid var(--border);
            border-radius: 8px;
        }}

        .summary-extra span {{
            margin-right: 8px;
            color: var(--muted);
        }}

        .summary-extra strong {{
            color: var(--text);
        }}

        .inventory-table,
        .errors-table {{
            width: 100%;

            border-collapse: collapse;

            background: white;
        }}

        .inventory-table th,
        .inventory-table td,
        .errors-table th,
        .errors-table td {{
            padding: 12px 14px;

            text-align: left;
            vertical-align: top;

            border-bottom: 1px solid var(--border);
        }}

        .inventory-table tr:last-child th,
        .inventory-table tr:last-child td,
        .errors-table tbody tr:last-child td {{
            border-bottom: none;
        }}

        .inventory-table th {{
            width: 38%;

            color: #475467;

            font-weight: 600;
        }}

        .inventory-table td {{
            font-weight: 600;
        }}

        .errors-table th {{
            background: var(--surface-soft);

            color: #475467;

            font-size: 12px;
        }}

        .table-wrapper {{
            overflow-x: auto;

            border: 1px solid var(--border);
            border-radius: 8px;
        }}

        .findings-container {{
            display: flex;
            flex-direction: column;

            gap: 18px;
        }}

        .finding-card {{
            position: relative;

            padding: 22px;

            overflow: hidden;

            background: var(--surface);

            border: 1px solid var(--border);
            border-left: 5px solid #98a2b3;
            border-radius: 10px;

            box-shadow: var(--shadow);
        }}

        .finding-card.severity-critical {{
            border-left-color: var(--critical);
        }}

        .finding-card.severity-high {{
            border-left-color: var(--high);
        }}

        .finding-card.severity-medium {{
            border-left-color: var(--medium);
        }}

        .finding-card.severity-low {{
            border-left-color: var(--low);
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;

            gap: 18px;

            padding-bottom: 16px;

            border-bottom: 1px solid var(--border);
        }}

        .finding-number {{
            margin-bottom: 4px;

            color: var(--muted);

            font-size: 11px;
            font-weight: 700;

            letter-spacing: 0.04em;
            text-transform: uppercase;
        }}

        .finding-header h3 {{
            margin: 0;

            font-size: 18px;
            line-height: 1.4;
        }}

        .severity-badge {{
            display: inline-flex;
            align-items: center;

            padding: 5px 10px;

            border-radius: 999px;

            font-size: 11px;
            font-weight: 800;

            letter-spacing: 0.03em;
            text-transform: uppercase;
        }}

        .severity-badge.severity-critical {{
            color: var(--critical);
            background: var(--critical-soft);
        }}

        .severity-badge.severity-high {{
            color: var(--high);
            background: var(--high-soft);
        }}

        .severity-badge.severity-medium {{
            color: var(--medium);
            background: var(--medium-soft);
        }}

        .severity-badge.severity-low {{
            color: var(--low);
            background: var(--low-soft);
        }}

        .finding-metadata {{
            display: grid;

            grid-template-columns:
                repeat(auto-fit, minmax(150px, 1fr));

            gap: 10px;

            margin-top: 16px;
        }}

        .finding-meta-item {{
            padding: 10px 12px;

            background: var(--surface-soft);

            border: 1px solid var(--border);
            border-radius: 7px;
        }}

        .finding-meta-item span {{
            display: block;

            margin-bottom: 2px;

            color: var(--muted);

            font-size: 10px;
            font-weight: 700;

            text-transform: uppercase;
        }}

        .finding-meta-item strong {{
            display: block;

            overflow-wrap: anywhere;

            color: #344054;

            font-size: 13px;
            font-weight: 600;
        }}

        .finding-meta-item small {{
            display: block;

            margin-top: 3px;

            color: var(--muted);

            font-size: 11px;
            font-weight: 400;
        }}

        .resource-item {{
            grid-column: span 2;
        }}

        .finding-section {{
            margin-top: 18px;
        }}

        .finding-section h4 {{
            margin: 0 0 7px;

            color: #344054;

            font-size: 13px;
        }}

        .finding-section p {{
            margin: 0;

            color: #475467;

            white-space: pre-wrap;
        }}

        .evidence-box {{
            padding: 14px;

            background: var(--surface-soft);

            border: 1px solid var(--border);
            border-radius: 8px;
        }}

        .evidence-row {{
            display: grid;

            grid-template-columns: minmax(150px, 28%) 1fr;

            gap: 12px;

            padding: 8px 0;

            border-bottom: 1px solid var(--border);
        }}

        .evidence-row:last-child {{
            border-bottom: none;
        }}

        .evidence-row > span {{
            color: var(--muted);

            font-size: 12px;
            font-weight: 600;
        }}

        .evidence-row > div {{
            overflow-wrap: anywhere;

            color: #344054;
            font-size: 12px;
        }}

        .evidence-list {{
            margin: 0;
            padding-left: 20px;
        }}

        pre {{
            max-width: 100%;

            padding: 12px;
            margin: 5px 0 0;

            overflow-x: auto;

            background: #101828;
            color: #eaecf0;

            border-radius: 6px;

            font-family:
                "Cascadia Code",
                Consolas,
                monospace;

            font-size: 11px;
            line-height: 1.55;

            white-space: pre-wrap;
            overflow-wrap: anywhere;
        }}

        .recommendation {{
            padding: 14px;

            background: #f0f9ff;

            border: 1px solid #b9e6fe;
            border-radius: 8px;
        }}

        .recommendation h4 {{
            color: #026aa2;
        }}

        .empty-state {{
            padding: 28px;

            text-align: center;

            background: var(--surface-soft);
            color: var(--muted);

            border: 1px dashed #d0d5dd;
            border-radius: 8px;
        }}

        .success-state {{
            color: var(--success);
            background: var(--success-soft);
            border-color: #abefc6;

            font-weight: 600;
        }}

        .muted {{
            color: var(--muted);
        }}

        footer {{
            margin-top: 28px;

            text-align: center;

            color: var(--muted);

            font-size: 11px;
        }}

        @media (max-width: 800px) {{
            .container {{
                width: min(100% - 24px, 1180px);
                margin-top: 20px;
            }}

            .report-header,
            .section {{
                padding: 20px;
            }}

            .metrics-grid {{
                grid-template-columns:
                    repeat(2, minmax(120px, 1fr));
            }}

            .resource-item {{
                grid-column: auto;
            }}

            .finding-header {{
                flex-direction: column;
            }}

            .evidence-row {{
                grid-template-columns: 1fr;
                gap: 3px;
            }}
        }}

        @media print {{
            body {{
                background: white;
            }}

            .container {{
                width: 100%;
                margin: 0;
            }}

            .report-header,
            .section,
            .finding-card {{
                box-shadow: none;
            }}

            .finding-card {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>

<body>
    <main class="container">

        <header class="report-header">
            <p class="eyebrow">
                Cloud Security Assessment
            </p>

            <h1>
                Cloud Risk Assessment Report
            </h1>

            <p>
                Security findings, discovered resources,
                risk levels and remediation recommendations.
            </p>

            <div class="metadata-grid">
                {metadata_html}
            </div>
        </header>


        <section class="section">
            <div class="section-header">
                <div>
                    <span class="section-label">
                        Risk overview
                    </span>

                    <h2>
                        Security Summary
                    </h2>
                </div>

                <span class="count-badge">
                    {total_findings}
                </span>
            </div>

            <div class="metrics-grid">
                {severity_cards}
            </div>

            <div class="summary-footer">

                <div class="summary-extra">
                    <span>Total Findings</span>
                    <strong>{total_findings}</strong>
                </div>

                {score_card}

            </div>
        </section>


        <section class="section">
            <div class="section-header">
                <div>
                    <span class="section-label">
                        Discovery
                    </span>

                    <h2>
                        Inventory Summary
                    </h2>
                </div>
            </div>

            {inventory_html}
        </section>


        <section class="section">
            <div class="section-header">
                <div>
                    <span class="section-label">
                        Security analysis
                    </span>

                    <h2>
                        Security Findings
                    </h2>
                </div>

                <span class="count-badge">
                    {total_findings}
                </span>
            </div>

            <div class="findings-container">
                {findings_html}
            </div>
        </section>


        {errors_html}


        <footer>
            Generated by cloud-risk-tool
        </footer>

    </main>
</body>
</html>
"""