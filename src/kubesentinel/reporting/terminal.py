"""Terminal rendering of a scan result."""

from rich.console import Console

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

    severity_counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in result.findings:
        severity_counts[finding.severity] += 1

    console.print("[bold]Findings[/bold]")
    console.print("-" * 32)
    for severity in SEVERITY_ORDER:
        console.print(f"{severity.upper():<10} {severity_counts[severity]}")
    console.print()

    top_risks = sorted(result.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))[:5]
    if top_risks:
        console.print("[bold]Top risks[/bold]")
        console.print()
        for finding in top_risks:
            location = finding.resource
            if finding.namespace:
                location = f"{finding.namespace}/{finding.resource}"
            console.print(f"[{finding.severity.upper()}] {location}")
            console.print(f"  {finding.title}")
        console.print()

    console.print("[bold]Security posture[/bold]")
    for dimension in result.score.dimensions:
        label = dimension.name.capitalize()
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
