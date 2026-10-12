"""Console, JSON, and standalone HTML views of the same result model."""

from collections import Counter
from html import escape
import json
import os
from pathlib import Path

from core import clean


def summary(findings):
    counts = Counter(x["status"] for x in findings)
    return {"total_checks": len(findings),
            **{s: counts[s] for s in ("detected", "not_detected", "inconclusive", "skipped")},
            "policy_violations": sum(x["assessment"] == "policy_violation" for x in findings)}


def render_html(report):
    def e(value):
        return escape(clean(value, 30000), quote=True)

    count = report["summary"]
    cards = "".join(f'<div class="metric"><strong>{count[k]}</strong><span>{label}</span></div>' for k, label in (
        ("policy_violations", "Policy violations"), ("not_detected", "Not observed"),
        ("inconclusive", "Inconclusive"), ("skipped", "Skipped")))
    inventory = "".join(
        f'<tr><td>{e(p["service"].upper())}</td><td>{p["port"]}/{e(p["transport"])}</td>'
        f'<td>{e(p["state"])}</td><td>{e(json.dumps(p["fingerprint"]))}<small>{e(p["note"])}</small></td></tr>'
        for p in report["inventory"])
    sections = []
    for f in report["findings"]:
        sections.append(f'''<article class="finding {e(f['status'])}">
<div class="finding-top"><span class="id">{e(f['check_id'])} · {e(f['service'].upper())}:{f['port']}</span>
<span class="badge">{e(f['status'].replace('_', ' ').upper())} / {e(f['severity'].upper())}</span></div>
<h3>{e(f['title'])}</h3><p class="assessment">{e(f['assessment'].replace('_', ' '))}</p>
<dl><dt>Impact</dt><dd>{e(f['impact'])}</dd><dt>Recommendation</dt><dd>{e(f['remediation'])}</dd>
<dt>Limitations</dt><dd>{e(f['limitations'])}</dd></dl>
<details><summary>Evidence · {e(f['observed_at'])}</summary><pre>{e(json.dumps(f['evidence'], indent=2, ensure_ascii=True))}</pre></details>
</article>''')
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Network Services Misconfiguration Scanner — {e(report['target'])}</title>
<style>
:root{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#203047;background:#f4f6f8;line-height:1.55}}
*{{box-sizing:border-box}}body{{margin:0}}header{{background:#10283e;color:#fff;padding:44px max(24px,calc((100vw - 1080px)/2))}}
header p{{color:#c5d6e4}}h1{{font-size:clamp(26px,4vw,38px);line-height:1.2;max-width:850px;margin:12px 0}}
.eyebrow{{letter-spacing:.13em;font-size:12px;font-weight:700;color:#82d5c4}}main{{max-width:1128px;margin:auto;padding:28px 24px 48px}}
.meta{{font-size:14px}}.metrics{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}}
.metric{{background:#fff;border:1px solid #dce3ea;border-radius:10px;padding:20px}}.metric strong{{font-size:34px;display:block;line-height:1.2}}.metric span{{font-size:13px}}
.note{{background:#e8f2f3;border-left:4px solid #288574;padding:16px 20px;border-radius:4px}}
h2{{font-size:21px;margin-top:34px}}h3{{font-size:19px;margin:10px 0 2px}}.table-wrap{{overflow:auto}}table{{border-collapse:collapse;width:100%;background:white;font-size:14px}}
th,td{{text-align:left;padding:12px;border-bottom:1px solid #e1e7ec;vertical-align:top}}th{{color:#516779;background:#ebf0f5}}small{{display:block;color:#627487;margin-top:5px}}
.finding{{background:white;border:1px solid #dce3ea;border-left:4px solid #7b8ea0;padding:22px;border-radius:8px;margin:16px 0}}
.finding.detected{{border-left-color:#c38220}}.finding.not_detected{{border-left-color:#37816f}}.finding.inconclusive{{border-left-color:#6572ac}}
.finding-top{{display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}}.id{{font-size:12px;font-weight:700;color:#526a7e}}.badge{{font-size:11px;font-weight:700;background:#edf1f5;padding:3px 8px;border-radius:4px}}
.assessment{{color:#67788b;font-size:13px;margin:3px 0 16px}}dl{{display:grid;grid-template-columns:130px 1fr;gap:8px;font-size:14px}}dt{{font-weight:650}}dd{{margin:0}}
details{{border-top:1px solid #e4e9ed;padding-top:12px;font-size:13px}}summary{{cursor:pointer;font-weight:650}}pre{{background:#f2f5f8;padding:16px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}}
footer{{font-size:12px;color:#67788b;padding-top:26px}}@media(max-width:640px){{.metrics{{grid-template-columns:repeat(2,1fr)}}dl{{grid-template-columns:1fr}}dd{{margin-bottom:8px}}}}
@media print{{header{{background:white;color:#10283e;padding:16px}}header p{{color:#203047}}.finding{{break-inside:avoid}}main{{padding:16px}}details{{display:block}}}}
</style></head><body>
<header><div class="eyebrow">NETWORK SECURITY · CONFIGURATION REVIEW</div><h1>Network Services<br>Misconfiguration Scanner</h1>
<p>Evidence from a defined set of remote checks.</p><div class="meta">Target: {e(report['target'])} · Version {e(report['scanner_version'])}<br>
{e(report['started_at'])} → {e(report['finished_at'])}</div></header>
<main><p class="note"><strong>{e(report.get('report_kind', 'Live scan'))}</strong><br>
Policy: {e(report['policy']['name'])}. A negative check is limited to its stated scope. Missing evidence, connection errors, and untested services do not establish security.</p>
<div class="metrics">{cards}</div><p>{count['total_checks']} check results · {count['detected']} observed behaviors. Intentional exceptions appear as review items, not policy violations.</p>
<h2>Scope and discovery</h2><p>Single IPv4 address; selected service ports only. SNMP is checked separately over UDP.</p>
<div class="table-wrap"><table><thead><tr><th>Service</th><th>Endpoint</th><th>State</th><th>Fingerprint / context</th></tr></thead><tbody>{inventory}</tbody></table></div>
<h2>Check results</h2>{''.join(sections)}
<h2>Run settings</h2><pre>{e(json.dumps(report['settings'], indent=2))}</pre>
<footer>Network Services Misconfiguration Scanner · No overall security certification or CVE exploitation claim. Reports may contain internal names; review before publishing.</footer>
</main></body></html>'''


def save_report(report, folder):
    """Create a new private run directory; never replace an existing report."""
    path = Path(folder).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=False, mode=0o700)
    for name, data in (("report.json", json.dumps(report, indent=2, ensure_ascii=True) + "\n"),
                       ("report.html", render_html(report))):
        fd = os.open(path / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(data)
    return path


def print_results(report):
    for f in report["findings"]:
        print(f"[{f['status'].upper():13}] {f['check_id']:8} {f['title']}")
    s = report["summary"]
    print(f"\n{s['total_checks']} results | {s['policy_violations']} policy violations | "
          f"{s['inconclusive']} inconclusive | {s['skipped']} skipped")
