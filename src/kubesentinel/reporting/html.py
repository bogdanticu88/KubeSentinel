"""Renders a scan result as a single self-contained HTML file.

No template engine, no external CSS or JS, everything is inlined so the
file opens correctly straight from disk with nothing else installed. Every
piece of dynamic text is escaped, a CVE's title or description comes from
an external vulnerability database and is not something KubeSentinel
controls the content of.
"""

from html import escape as esc

from kubesentinel.models.finding import Finding
from kubesentinel.models.scan import ScanResult

_RISK_ORDER = ["critical", "high", "medium", "low"]
_RISK_COLOR = {"critical": "#b91c1c", "high": "#c2410c", "medium": "#a16207", "low": "#4b5563"}

_STYLE = """
body { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; margin: 2rem;
       color: #111; max-width: 1000px; }
h1 { margin-bottom: 0; }
.subtitle { color: #666; margin-top: 0.25rem; }
.score { font-size: 2.5rem; font-weight: 700; margin: 1rem 0 0.25rem; }
table { border-collapse: collapse; width: 100%; margin-top: 0.5rem; }
th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #ddd;
         font-size: 0.9rem; }
th { background: #f5f5f5; }
.badge { color: white; padding: 0.15rem 0.6rem; border-radius: 3px; font-size: 0.8rem;
         font-weight: 600; }
.dimensions td, .dimensions th { text-align: center; }
.warnings { color: #92400e; }
"""


def render_html(result: ScanResult) -> str:
    score_text = str(result.score.overall) if result.score.overall is not None else "n/a"
    cluster_name = esc(result.cluster.name)
    scanned_at = esc(result.scanned_at.isoformat())
    dimension_headers = "".join(
        f"<th>{esc(d.name.replace('_', ' ').title())}</th>" for d in result.score.dimensions
    )
    dimension_values = "".join(
        f"<td>{d.score if d.score is not None else 'n/a'}</td>" for d in result.score.dimensions
    )

    ranked = sorted(result.findings, key=lambda f: _RISK_ORDER.index(f.risk))
    finding_rows = "\n".join(_finding_row(f) for f in ranked)
    warnings_section = _warnings_section(result)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>KubeSentinel report: {cluster_name}</title>
<style>{_STYLE}</style>
</head>
<body>
<h1>KubeSentinel Security Scan</h1>
<p class="subtitle">Cluster: {cluster_name} &middot; scanned {scanned_at}</p>
<p class="score">{score_text}/100</p>

<table class="dimensions">
<tr>{dimension_headers}</tr>
<tr>{dimension_values}</tr>
</table>

<h2>Findings ({len(result.findings)})</h2>
<table>
<tr><th>Risk</th><th>Category</th><th>Resource</th><th>Title</th></tr>
{finding_rows}
</table>
{warnings_section}
</body>
</html>
"""


def _finding_row(finding: Finding) -> str:
    color = _RISK_COLOR.get(finding.risk, "#4b5563")
    resource = f"{finding.namespace}/{finding.resource}" if finding.namespace else finding.resource
    risk_text = esc(finding.risk.upper())
    risk_badge = f'<span class="badge" style="background:{color}">{risk_text}</span>'
    return (
        "<tr>"
        f"<td>{risk_badge}</td>"
        f"<td>{esc(finding.category)}</td>"
        f"<td>{esc(finding.resource_kind)} {esc(resource)}</td>"
        f"<td>{esc(finding.title)}</td>"
        "</tr>"
    )


def _warnings_section(result: ScanResult) -> str:
    if not result.warnings:
        return ""
    items = "\n".join(f"<li>{esc(w.resource_kind)}: {esc(w.message)}</li>" for w in result.warnings)
    return f'<h2 class="warnings">Warnings</h2>\n<ul class="warnings">{items}</ul>'
