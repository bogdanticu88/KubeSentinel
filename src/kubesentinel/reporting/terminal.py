"""Terminal rendering of a scan result, a drift report, attack paths, and an audit."""

from rich.console import Console

from kubesentinel.gitops import GitOpsStatus
from kubesentinel.models.attackpath import AttackPath
from kubesentinel.models.audit import AuditReport
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


def render_attack_paths(paths: list[AttackPath], console: Console | None = None) -> None:
    console = console or Console()

    console.print()
    console.print("[bold]KubeSentinel Attack Paths[/bold]")
    console.print()

    if not paths:
        console.print("No attack path found from the internet to a sensitive target.")
        console.print()
        return

    plural = "s" if len(paths) != 1 else ""
    console.print(f"Found {len(paths)} path{plural}.")
    console.print()

    shown = paths[:10]
    for path in shown:
        console.print(f"[bold]ATTACK PATH {path.id}[/bold]")
        console.print()
        console.print(f"Entry point: {path.entry_point}")
        console.print(f"Target:      {path.target}")
        console.print()
        console.print("Path:")
        for node in path.nodes:
            console.print(f"  {node.kind}: {node.identifier}")
        console.print()
        console.print(f"Risk:       {path.risk.upper()}")
        console.print(f"Confidence: {path.confidence.upper()}")
        console.print()

    if len(paths) > len(shown):
        remaining = len(paths) - len(shown)
        console.print(f"... and {remaining} more, use --output json for the full list")
        console.print()


def render_audit(report: AuditReport, console: Console | None = None) -> None:
    console = console or Console()

    console.print()
    console.print(f"[bold]Kubernetes Security Audit #{report.number}[/bold]")
    console.print()
    console.print(f"Cluster: {report.cluster}")
    console.print()

    for severity in SEVERITY_ORDER:
        console.print(f"{severity.upper():<10} {report.findings_by_severity.get(severity, 0)}")
    console.print()

    if report.drift is not None:
        new_count = len(report.drift.new_findings)
        resolved_count = len(report.drift.resolved_findings)
        drift_count = len(report.drift.resource_changes)
        console.print(f"New findings          {new_count}")
        console.print(f"Resolved findings      {resolved_count}")
        console.print(f"Drift events           {drift_count}")
    else:
        console.print("No previous audit or baseline yet, this is this cluster's first audit.")

    path_delta = report.new_attack_paths - report.previous_attack_paths
    delta_text = "unchanged" if path_delta == 0 else f"{path_delta:+d}"
    console.print(f"Attack paths           {report.new_attack_paths} ({delta_text})")
    console.print()

    score_text = f"{report.score}/100" if report.score is not None else "not available"
    console.print(f"Security Score         {score_text}")
    if report.drift is not None and report.drift.score_before is not None:
        console.print(f"Previous Score         {report.drift.score_before}/100")
    console.print()

    if report.security_debt.total_open:
        console.print("[bold]Security debt[/bold]")
        for category in report.security_debt.by_category[:10]:
            console.print(f"  {category.category:<20} {category.count}")
        console.print(f"  Trend: {report.security_debt.trend}")
        console.print()


def render_gitops(statuses: list[GitOpsStatus], console: Console | None = None) -> None:
    console = console or Console()

    console.print()
    console.print("[bold]KubeSentinel GitOps Management[/bold]")
    console.print()

    if not statuses:
        console.print("No workloads found.")
        console.print()
        return

    by_tool: dict[str, list[GitOpsStatus]] = {}
    unmanaged = []
    for status in statuses:
        if status.source is None:
            unmanaged.append(status)
        else:
            by_tool.setdefault(status.source.tool, []).append(status)

    managed_count = len(statuses) - len(unmanaged)
    console.print(f"{managed_count}/{len(statuses)} workloads are managed through GitOps.")
    console.print()

    for tool in sorted(by_tool):
        entries = by_tool[tool]
        console.print(f"[bold]{tool}[/bold] ({len(entries)})")
        for status in entries:
            assert status.source is not None
            location = _location(status.namespace, status.name)
            console.print(f"  {location}  <- {status.source.name}")
        console.print()

    if unmanaged:
        console.print(f"[bold]Not GitOps-managed[/bold] ({len(unmanaged)})")
        for status in unmanaged:
            console.print(f"  {_location(status.namespace, status.name)}")
        console.print()
