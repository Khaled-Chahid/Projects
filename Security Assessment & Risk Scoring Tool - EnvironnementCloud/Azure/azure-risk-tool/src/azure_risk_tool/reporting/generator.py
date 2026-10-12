from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

from azure_risk_tool.serialization import write_json


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

        report = self._report_payload(
            inventory,
            scored_result,
        )

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

    def _report_payload(
        self,
        inventory: dict[str, Any],
        scored: dict[str, Any],
    ) -> dict[str, Any]:
        metadata = inventory.get("metadata", {})

        return {
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
            "provider": metadata.get("provider"),
            "subscription_id": metadata.get(
                "subscription_id"
            ),
            "resource_counts": metadata.get(
                "resource_counts",
                {},
            ),
            "summary": {
                "finding_count": scored.get(
                    "finding_count",
                    0,
                ),
                "severity_counts": scored.get(
                    "severity_counts",
                    {},
                ),
                "maximum_score": scored.get(
                    "maximum_score",
                    0,
                ),
            },
            "findings": scored.get(
                "findings",
                [],
            ),
        }

    @staticmethod
    def _pretty_name(value: Any) -> str:
        return (
            str(value)
            .replace("_", " ")
            .strip()
            .title()
        )

    @staticmethod
    def _format_value(value: Any) -> str:
        if value is None:
            return "-"

        if isinstance(value, bool):
            return "Yes" if value else "No"

        if isinstance(
            value,
            (dict, list, tuple),
        ):
            return json.dumps(
                value,
                ensure_ascii=False,
                default=str,
                indent=2,
            )

        return str(value)

    @staticmethod
    def _is_fake_subscription(
        subscription_id: Any,
    ) -> bool:
        """
        Hide the placeholder subscription used by
        the local Azure laboratory.

        A real subscription ID can still be displayed
        automatically in the future.
        """

        value = str(
            subscription_id or ""
        ).strip().lower()

        fake_values = {
            "11111111-1111-1111-1111-111111111111",
            "00000000-0000-0000-0000-000000000000",
        }

        return (
            not value
            or value in fake_values
        )

    def _resource_counts_html(
        self,
        resource_counts: dict[str, Any],
    ) -> str:
        if not resource_counts:
            return """
            <div class="empty-state">
                No discovered resource information available.
            </div>
            """

        cards = []

        for name, value in sorted(
            resource_counts.items()
        ):
            cards.append(
                f"""
                <div class="resource-card">
                    <span>
                        {escape(self._pretty_name(name))}
                    </span>

                    <strong>
                        {escape(str(value))}
                    </strong>
                </div>
                """
            )

        return "".join(cards)

    def _evidence_html(
        self,
        evidence: Any,
    ) -> str:
        if evidence in (
            None,
            "",
            {},
            [],
        ):
            return (
                '<span class="muted">'
                "No additional evidence."
                "</span>"
            )

        if isinstance(evidence, dict):
            rows = []

            for key, value in evidence.items():
                formatted = self._format_value(
                    value
                )

                if isinstance(
                    value,
                    (dict, list, tuple),
                ):
                    rendered_value = (
                        "<pre>"
                        f"{escape(formatted)}"
                        "</pre>"
                    )
                else:
                    rendered_value = escape(
                        formatted
                    )

                rows.append(
                    """
                    <div class="evidence-row">
                    """
                    f"""
                        <span>
                            {escape(self._pretty_name(key))}
                        </span>
                    """
                    f"""
                        <div>
                            {rendered_value}
                        </div>
                    """
                    """
                    </div>
                    """
                )

            return "".join(rows)

        if isinstance(
            evidence,
            (list, tuple),
        ):
            items = "".join(
                f"<li>{escape(self._format_value(item))}</li>"
                for item in evidence
            )

            return (
                f'<ul class="evidence-list">{items}</ul>'
            )

        return (
            "<pre>"
            f"{escape(str(evidence))}"
            "</pre>"
        )

    @staticmethod
    def _resource_information(
        item: dict[str, Any],
    ) -> tuple[str, str]:
        """
        Supports several possible Azure finding formats
        without requiring changes elsewhere in the project.
        """

        resource = item.get(
            "resource",
            {},
        )

        resource_name = ""
        resource_type = ""

        if isinstance(resource, dict):
            resource_name = str(
                resource.get("name")
                or resource.get("id")
                or resource.get("resource_id")
                or resource.get("resource_name")
                or ""
            )

            resource_type = str(
                resource.get("type")
                or resource.get("resource_type")
                or ""
            )

        elif resource:
            resource_name = str(resource)

        if not resource_name:
            resource_name = str(
                item.get("resource_id")
                or item.get("resource_name")
                or ""
            )

        if not resource_type:
            resource_type = str(
                item.get("resource_type")
                or ""
            )

        return (
            resource_name,
            resource_type,
        )

    def _finding_card(
        self,
        item: dict[str, Any],
        number: int,
    ) -> str:
        severity = str(
            item.get(
                "severity",
                "Low",
            )
        ).strip() or "Low"

        severity_class = (
            severity.lower()
        )

        title = escape(
            str(
                item.get(
                    "title",
                    "Unnamed finding",
                )
            )
        )

        description = str(
            item.get(
                "description",
                "",
            )
        ).strip()

        recommendation = str(
            item.get(
                "recommendation",
                "",
            )
        ).strip()

        score = item.get("score")

        rule_id = (
            item.get("rule_id")
            or item.get("rule")
            or item.get("id")
        )

        evidence = item.get(
            "evidence",
            {},
        )

        resource_name, resource_type = (
            self._resource_information(
                item
            )
        )

        region = (
            item.get("region")
            or item.get("location")
        )

        metadata_parts = []

        if score not in (
            None,
            "",
        ):
            metadata_parts.append(
                f"""
                <div class="finding-meta-item">
                    <span>Score</span>
                    <strong>
                        {escape(str(score))}
                    </strong>
                </div>
                """
            )

        if rule_id not in (
            None,
            "",
        ):
            metadata_parts.append(
                f"""
                <div class="finding-meta-item">
                    <span>Rule</span>
                    <strong>
                        {escape(str(rule_id))}
                    </strong>
                </div>
                """
            )

        if resource_name:
            extra_lines = ""

            if resource_type:
                extra_lines += (
                    "<small>"
                    "Type: "
                    f"{escape(resource_type)}"
                    "</small>"
                )

            if region:
                extra_lines += (
                    "<small>"
                    "Location: "
                    f"{escape(str(region))}"
                    "</small>"
                )

            metadata_parts.append(
                f"""
                <div class="finding-meta-item resource-item">
                    <span>Resource</span>

                    <strong>
                        {escape(resource_name)}
                    </strong>

                    {extra_lines}
                </div>
                """
            )

        description_html = ""

        if description:
            description_html = (
                """
                <div class="finding-section">
                    <h4>Description</h4>
                """
                f"""
                    <p>
                        {escape(description)}
                    </p>
                """
                """
                </div>
                """
            )

        recommendation_html = ""

        if recommendation:
            recommendation_html = (
                """
                <div class="finding-section recommendation">
                    <h4>Recommendation</h4>
                """
                f"""
                    <p>
                        {escape(recommendation)}
                    </p>
                """
                """
                </div>
                """
            )

        return f"""
        <article
            class="
                finding-card
                severity-{escape(severity_class)}
            "
        >
            <div class="finding-header">

                <div>
                    <div class="finding-number">
                        Finding #{number}
                    </div>

                    <h3>
                        {title}
                    </h3>
                </div>

                <span
                    class="
                        severity-badge
                        severity-{escape(severity_class)}
                    "
                >
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
            self._finding_card(
                finding,
                index,
            )
            for index, finding in enumerate(
                findings,
                start=1,
            )
        )

    def _html(
        self,
        report: dict[str, Any],
    ) -> str:
        summary = report.get(
            "summary",
            {},
        )

        counts = summary.get(
            "severity_counts",
            {},
        )

        findings = report.get(
            "findings",
            [],
        )

        resource_counts = report.get(
            "resource_counts",
            {},
        )

        provider = report.get(
            "provider",
            "",
        )

        subscription_id = report.get(
            "subscription_id",
            "",
        )

        generated_at = report.get(
            "generated_at",
            "",
        )

        finding_count = summary.get(
            "finding_count",
            len(findings),
        )

        maximum_score = summary.get(
            "maximum_score",
            0,
        )

        severity_levels = (
            "Critical",
            "High",
            "Medium",
            "Low",
        )

        severity_cards = "".join(
            f"""
            <div class="metric-card metric-{level.lower()}">

                <span>
                    {escape(level)}
                </span>

                <strong>
                    {escape(str(counts.get(level, 0)))}
                </strong>

            </div>
            """
            for level in severity_levels
        )

        subscription_html = ""

        if not self._is_fake_subscription(
            subscription_id
        ):
            subscription_html = f"""
            <div class="info-item">
                <span>Subscription</span>

                <strong>
                    {escape(str(subscription_id))}
                </strong>
            </div>
            """

        provider_html = ""

        if provider:
            provider_html = f"""
            <div class="info-item">
                <span>Provider</span>

                <strong>
                    {escape(str(provider))}
                </strong>
            </div>
            """

        generated_html = ""

        if generated_at:
            generated_html = f"""
            <div class="info-item">
                <span>Generated At</span>

                <strong>
                    {escape(str(generated_at))}
                </strong>
            </div>
            """

        resources_html = (
            self._resource_counts_html(
                resource_counts
            )
        )

        findings_html = (
            self._findings_html(
                findings
            )
        )

        return f"""<!doctype html>

<html lang="en">

<head>

    <meta charset="utf-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1"
    >

    <title>
        Azure Cloud Risk Assessment Report
    </title>

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

            --azure: #0078d4;
            --azure-soft: #eff8ff;

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
            width:
                min(
                    1180px,
                    calc(100% - 40px)
                );

            margin:
                40px auto 80px;
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
                repeat(
                    auto-fit,
                    minmax(220px, 1fr)
                );

            gap: 12px;

            margin-top: 24px;
        }}

        .info-item {{
            padding: 12px 14px;

            background:
                rgba(
                    255,
                    255,
                    255,
                    0.06
                );

            border:
                1px solid
                rgba(
                    255,
                    255,
                    255,
                    0.09
                );

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

            border:
                1px solid
                var(--border);

            border-radius: 12px;

            box-shadow: var(--shadow);
        }}

        .section-header {{
            display: flex;

            justify-content:
                space-between;

            align-items:
                flex-start;

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
                repeat(
                    4,
                    minmax(120px, 1fr)
                );

            gap: 14px;
        }}

        .metric-card {{
            padding: 18px;

            border:
                1px solid
                var(--border);

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

            border:
                1px solid
                var(--border);

            border-radius: 8px;
        }}

        .summary-extra span {{
            margin-right: 8px;

            color: var(--muted);
        }}

        .summary-extra strong {{
            color: var(--text);
        }}

        .resources-grid {{
            display: grid;

            grid-template-columns:
                repeat(
                    auto-fit,
                    minmax(180px, 1fr)
                );

            gap: 12px;
        }}

        .resource-card {{
            display: flex;

            justify-content:
                space-between;

            align-items: center;

            gap: 12px;

            padding: 15px;

            background:
                var(--surface-soft);

            border:
                1px solid
                var(--border);

            border-radius: 9px;
        }}

        .resource-card span {{
            color: #475467;

            font-size: 13px;
            font-weight: 600;
        }}

        .resource-card strong {{
            color: var(--azure);

            font-size: 20px;
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

            border:
                1px solid
                var(--border);

            border-left:
                5px solid
                #98a2b3;

            border-radius: 10px;

            box-shadow: var(--shadow);
        }}

        .finding-card.severity-critical {{
            border-left-color:
                var(--critical);
        }}

        .finding-card.severity-high {{
            border-left-color:
                var(--high);
        }}

        .finding-card.severity-medium {{
            border-left-color:
                var(--medium);
        }}

        .finding-card.severity-low {{
            border-left-color:
                var(--low);
        }}

        .finding-header {{
            display: flex;

            justify-content:
                space-between;

            align-items:
                flex-start;

            gap: 18px;

            padding-bottom: 16px;

            border-bottom:
                1px solid
                var(--border);
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
                repeat(
                    auto-fit,
                    minmax(150px, 1fr)
                );

            gap: 10px;

            margin-top: 16px;
        }}

        .finding-meta-item {{
            padding: 10px 12px;

            background:
                var(--surface-soft);

            border:
                1px solid
                var(--border);

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

            background:
                var(--surface-soft);

            border:
                1px solid
                var(--border);

            border-radius: 8px;
        }}

        .evidence-row {{
            display: grid;

            grid-template-columns:
                minmax(150px, 28%)
                1fr;

            gap: 12px;

            padding: 8px 0;

            border-bottom:
                1px solid
                var(--border);
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

            border:
                1px solid
                #b9e6fe;

            border-radius: 8px;
        }}

        .recommendation h4 {{
            color: #026aa2;
        }}

        .empty-state {{
            padding: 28px;

            text-align: center;

            background:
                var(--surface-soft);

            color: var(--muted);

            border:
                1px dashed
                #d0d5dd;

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
                width:
                    min(
                        100% - 24px,
                        1180px
                    );

                margin-top: 20px;
            }}

            .report-header,
            .section {{
                padding: 20px;
            }}

            .metrics-grid {{
                grid-template-columns:
                    repeat(
                        2,
                        minmax(120px, 1fr)
                    );
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
            Azure Cloud Security Assessment
        </p>

        <h1>
            Cloud Risk Assessment Report
        </h1>

        <p>
            Security findings, discovered Azure resources,
            risk levels and remediation recommendations.
        </p>

        <div class="metadata-grid">

            {provider_html}

            {subscription_html}

            {generated_html}

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
                {escape(str(finding_count))}
            </span>

        </div>


        <div class="metrics-grid">
            {severity_cards}
        </div>


        <div class="summary-footer">

            <div class="summary-extra">

                <span>
                    Total Findings
                </span>

                <strong>
                    {escape(str(finding_count))}
                </strong>

            </div>


            <div class="summary-extra">

                <span>
                    Maximum Score
                </span>

                <strong>
                    {escape(str(maximum_score))}
                </strong>

            </div>

        </div>

    </section>


    <section class="section">

        <div class="section-header">

            <div>

                <span class="section-label">
                    Discovery
                </span>

                <h2>
                    Resource Summary
                </h2>

            </div>

        </div>


        <div class="resources-grid">
            {resources_html}
        </div>

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
                {escape(str(finding_count))}
            </span>

        </div>


        <div class="findings-container">
            {findings_html}
        </div>

    </section>


    <footer>
        Generated by azure-risk-tool
    </footer>

</main>

</body>

</html>
"""