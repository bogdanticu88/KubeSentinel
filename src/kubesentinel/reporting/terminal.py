"""Terminal rendering of a scan result and a drift report."""

from rich.console import Console

from kubesentinel.models.drift import DriftReport
from kubesentinel.models.scan import ScanResult

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def render(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    console.print()
    console.print("[bold]KubeSentinel Security Scan[/bold]")
    console.print()
    console.print(f"Cluster: {result.cluster.name}")
    if result.cluster.kubernetes_version:
        console.print(f"Kubernetes: {result.cluster.kubernetes_version}")
    console.print()

    counts = result.counts
    console.print(f"Workloads:        {counts.workloads}")
    console.print(f"Services:         {counts.services}")
    console.print(f"ServiceAccounts:  {counts.service_accounts}")
    console.print(f"Roles:            {counts.roles}")
    console.print(f"ClusterRoles:     {counts.cluster_roles}")
    console.print(f"NetworkPolicies:  {counts.network_policies}")
    console.print()

    # Counted and ranked by risk, not raw severity, a critical CVE the
    # correlation engine downgraded to HIGH belongs in the HIGH bucket.
    risk_counts = {risk: 0 for risk in SEVERITY_ORDER}
    for finding in result.findings:
        risk_counts[finding.risk] += 1

    console.print("[bold]Findings[/bold]")
    console.print("-" * 32)
    for risk in SEVERITY_ORDER:
        console.print(f"{risk.upper():<10} {risk_counts[risk]}")
    console.print()

    top_risks = sorted(result.findings, key=lambda f: SEVERITY_ORDER.index(f.risk))[:5]
    if top_risks:
        console.print("[bold]Top risks[/bold]")
        console.print()
        for finding in top_risks:
            location = finding.resource
            if finding.namespace:
                location = f"{finding.namespace}/{finding.resource}"
            console.print(f"[{finding.risk.upper()}] {location}")
            console.print(f"  {finding.title}")
            if finding.risk != finding.severity and finding.risk_reasons:
                console.print(f"  {finding.risk_reasons[0]}")
        console.print()

    console.print("[bold]Security posture[/bold]")
    for dimension in result.score.dimensions:
        label = dimension.name.replace("_", " ").capitalize()
        value = "n/a" if dimension.score is None else str(dimension.score)
        console.print(f"  {label:<15} {value}")
    console.print()

    if result.score.overall is not None:
        console.print(f"[bold]Security Score: {result.score.overall}/100[/bold]")
    else:
        console.print("[bold]Security Score: not available[/bold]")

    if result.warnings:
        console.print()
        console.print("[yellow]Warnings[/yellow]")
        for warning in result.warnings:
            console.print(f"  {warning.resource_kind}: {warning.message}")
    console.print()


def render_drift(report: DriftReport, console: Console | None = None) -> None:
    console = console or Console()

    console.print()
    console.print("[bold]KubeSentinel Drift Report[/bold]")
    console.print()
    console.print(f"Cluster:   {report.baseline_cluster}")
    console.print(f"Baseline:  {report.baseline_taken_at.isoformat(timespec='minutes')}")
    console.print(f"Current:   {report.current_taken_at.isoformat(timespec='minutes')}")
    console.print()

    if report.score_before is not None and report.score_after is not None:
        delta = report.score_after - report.score_before
        delta_text = "unchanged" if delta == 0 else f"{delta:+d}"
        score_line = (
            f"Security score: {report.score_before} -> {report.score_after}  ({delta_text})"
        )
        console.print(score_line)
    else:
        console.print("Security score: not available for one of the two snapshots being compared")
    console.print()

    console.print(f"New findings:       {len(report.new_findings)}")
    console.print(f"Resolved findings:  {len(report.resolved_findings)}")
    console.print()

    if report.new_findings:
        console.print("[bold]New[/bold]")
        ranked = sorted(report.new_findings, key=lambda f: SEVERITY_ORDER.index(f.risk))
        for finding in ranked[:10]:
            location = _location(finding.namespace, finding.resource)
            console.print(f"  [{finding.risk.upper()}] {location}: {finding.title}")
        if len(ranked) > 10:
            console.print(f"  ... and {len(ranked) - 10} more")
        console.print()

    if report.resolved_findings:
        console.print("[bold]Resolved[/bold]")
        for finding in report.resolved_findings[:10]:
            console.print(f"  {_location(finding.namespace, finding.resource)}: {finding.title}")
        if len(report.resolved_findings) > 10:
            console.print(f"  ... and {len(report.resolved_findings) - 10} more")
        console.print()

    if report.resource_changes:
        console.print("[bold]Resource changes[/bold]")
        for change in report.resource_changes:
            location = _location(change.namespace, change.name)
            console.print(f"  {change.change_type.upper():<8} {change.kind} {location}")
            for field_change in change.field_changes:
                before = _short(field_change.before)
                after = _short(field_change.after)
                severity = field_change.severity.upper()
                console.print(f"    {field_change.field}: {before} -> {after}  [{severity}]")
        console.print()


def _location(namespace: str | None, name: str) -> str:
    return f"{namespace}/{name}" if namespace else name


def _short(value: object, limit: int = 60) -> str:
    text = "(not set)" if value is None else str(value)
    return text if len(text) <= limit else text[: limit - 3] + "..."
