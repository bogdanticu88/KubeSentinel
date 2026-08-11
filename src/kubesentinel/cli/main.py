"""KubeSentinel command line interface."""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import typer
from pydantic import TypeAdapter
from rich.console import Console

from kubesentinel import gitops as gitops_module
from kubesentinel.cli.duration import DurationParseError, parse_duration
from kubesentinel.collector.client import current_context_name
from kubesentinel.collector.errors import CollectorError
from kubesentinel.engines.attackpath.graph import build_graph
from kubesentinel.engines.attackpath.paths import find_attack_paths
from kubesentinel.engines.audit.report import build_audit_report
from kubesentinel.engines.drift.diff import compare as compare_snapshots
from kubesentinel.engines.misconfiguration.loader import RuleLoadError
from kubesentinel.integrations.azuredevops import AzureDevOpsTicketer
from kubesentinel.integrations.github import GitHubTicketer
from kubesentinel.integrations.jira import JiraTicketer
from kubesentinel.integrations.servicenow import ServiceNowTicketer
from kubesentinel.integrations.ticketer import Ticketer, TicketError
from kubesentinel.models.attackpath import AttackPath
from kubesentinel.models.scan import Snapshot
from kubesentinel.pipeline import PipelineResult, run_scan
from kubesentinel.reporting import terminal
from kubesentinel.reporting.html import render_html
from kubesentinel.reporting.sarif import render_sarif
from kubesentinel.storage import db
from kubesentinel.storage import snapshots as snapshot_store
from kubesentinel.storage import tickets as ticket_store
from kubesentinel.storage.db import StorageError

_REPORT_DEFAULT_NAMES = {
    "html": "kubesentinel-report.html",
    "sarif": "kubesentinel-report.sarif",
    "json": "kubesentinel-report.json",
}

_ATTACK_PATHS_ADAPTER = TypeAdapter(list[AttackPath])
_GITOPS_ADAPTER = TypeAdapter(list[gitops_module.GitOpsStatus])

_TICKETERS: dict[str, type[Ticketer]] = {
    "github": GitHubTicketer,
    "jira": JiraTicketer,
    "servicenow": ServiceNowTicketer,
    "azuredevops": AzureDevOpsTicketer,
}
_RISK_ORDER = ["low", "medium", "high", "critical"]

app = typer.Typer(add_completion=False, no_args_is_help=True)
baseline_app = typer.Typer(help="Manage the baseline snapshot drift is measured against.")
app.add_typer(baseline_app, name="baseline")
console = Console()


@app.callback()
def main() -> None:
    """KubeSentinel: continuous Kubernetes security assurance."""


@contextmanager
def _storage() -> Iterator[sqlite3.Connection]:
    try:
        connection = db.connect()
    except StorageError as error:
        console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(code=1) from error
    try:
        yield connection
    except StorageError as error:
        # A safety net for the read calls that don't already have their own
        # try/except with a more specific message, that inner one always
        # fires first, this only catches what would otherwise be an
        # uncaught traceback (a locked database, a corrupted row).
        console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(code=1) from error
    finally:
        connection.close()


def _run_pipeline(
    context: str | None, namespace: str | None, with_vulnerabilities: bool
) -> PipelineResult:
    try:
        return run_scan(context, namespace, with_vulnerabilities)
    except CollectorError as error:
        console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(code=1) from error
    except RuleLoadError as error:
        console.print(f"[red]Error loading rules:[/red] {error}")
        raise typer.Exit(code=1) from error


def _print_score(score: int | None) -> None:
    if score is None:
        console.print("Security Score: not available")
    else:
        console.print(f"Security Score: {score}/100")


def _to_snapshot(pipeline_result: PipelineResult) -> Snapshot:
    result = pipeline_result.scan_result
    return Snapshot(
        cluster=result.cluster.name,
        taken_at=result.scanned_at,
        kubernetes_version=result.cluster.kubernetes_version,
        node_count=result.cluster.node_count,
        resources=pipeline_result.resources,
        findings=result.findings,
        score=result.score,
        counts=result.counts,
        warnings=result.warnings,
    )


@app.command()
def scan(
    context: str = typer.Option(None, "--context", help="kubeconfig context to scan"),
    namespace: str = typer.Option(None, "--namespace", help="limit the scan to a single namespace"),
    output: str = typer.Option("terminal", "--output", "-o", help="terminal or json"),
    with_vulnerabilities: bool = typer.Option(
        False,
        "--with-vulnerabilities",
        help="also scan workload images for known CVEs using Trivy, requires trivy on PATH",
    ),
) -> None:
    """Scan a cluster's current security posture and print a scored report."""
    result = _run_pipeline(context, namespace, with_vulnerabilities).scan_result
    if output == "json":
        print(result.model_dump_json(indent=2))
    else:
        terminal.render(result, console)


@app.command()
def report(
    context: str = typer.Option(None, "--context", help="kubeconfig context to scan"),
    namespace: str = typer.Option(None, "--namespace", help="limit the scan to a single namespace"),
    with_vulnerabilities: bool = typer.Option(
        False, "--with-vulnerabilities", help="also scan workload images for known CVEs using Trivy"
    ),
    report_format: str = typer.Option("html", "--format", "-f", help="html, sarif, or json"),
    output: str = typer.Option(
        None, "--output", "-o", help="file to write, defaults by format, use - for stdout"
    ),
) -> None:
    """Scan a cluster and write a report file (HTML, SARIF, or JSON)."""
    if report_format not in _REPORT_DEFAULT_NAMES:
        console.print(
            f"[red]Error:[/red] unknown format {report_format!r}, use html, sarif, or json"
        )
        raise typer.Exit(code=1)

    result = _run_pipeline(context, namespace, with_vulnerabilities).scan_result

    if report_format == "html":
        content = render_html(result)
    elif report_format == "sarif":
        content = json.dumps(render_sarif(result.findings), indent=2)
    else:
        content = result.model_dump_json(indent=2)

    if output == "-":
        print(content)
        return

    path = Path(output) if output else Path(_REPORT_DEFAULT_NAMES[report_format])
    try:
        path.write_text(content, encoding="utf-8")
    except OSError as error:
        console.print(f"[red]Error writing report:[/red] {error}")
        raise typer.Exit(code=1) from error
    console.print(f"Report written to {path}")


@app.command()
def snapshot(
    context: str = typer.Option(None, "--context", help="kubeconfig context to scan"),
    namespace: str = typer.Option(None, "--namespace", help="limit the scan to a single namespace"),
    with_vulnerabilities: bool = typer.Option(
        False, "--with-vulnerabilities", help="also scan workload images for known CVEs using Trivy"
    ),
) -> None:
    """Scan a cluster and save the result so drift can compare against it later."""
    pipeline_result = _run_pipeline(context, namespace, with_vulnerabilities)
    new_snapshot = _to_snapshot(pipeline_result)

    with _storage() as connection:
        try:
            snapshot_id = snapshot_store.save(connection, new_snapshot)
        except StorageError as error:
            console.print(f"[red]Error saving snapshot:[/red] {error}")
            raise typer.Exit(code=1) from error

    console.print(f"Snapshot #{snapshot_id} saved for cluster {new_snapshot.cluster}.")
    _print_score(new_snapshot.score.overall)


@baseline_app.command("create")
def baseline_create(
    context: str = typer.Option(None, "--context", help="kubeconfig context to scan"),
    namespace: str = typer.Option(None, "--namespace", help="limit the scan to a single namespace"),
    with_vulnerabilities: bool = typer.Option(
        False, "--with-vulnerabilities", help="also scan workload images for known CVEs using Trivy"
    ),
) -> None:
    """Scan a cluster now and set the result as its baseline."""
    pipeline_result = _run_pipeline(context, namespace, with_vulnerabilities)
    new_snapshot = _to_snapshot(pipeline_result)

    with _storage() as connection:
        try:
            snapshot_id = snapshot_store.save(connection, new_snapshot)
            snapshot_store.set_baseline(connection, snapshot_id)
        except StorageError as error:
            console.print(f"[red]Error setting baseline:[/red] {error}")
            raise typer.Exit(code=1) from error

    console.print(f"Baseline set to snapshot #{snapshot_id} for cluster {new_snapshot.cluster}.")


@baseline_app.command("show")
def baseline_show(
    context: str = typer.Option(None, "--context", help="kubeconfig context to look up"),
) -> None:
    """Show the current baseline snapshot for a cluster."""
    cluster_name = current_context_name(context)
    with _storage() as connection:
        baseline = snapshot_store.get_baseline(connection, cluster_name)

    if baseline is None:
        console.print(
            f"No baseline set for {cluster_name}. Run 'kubesentinel baseline create' first."
        )
        raise typer.Exit(code=1)

    console.print(f"Baseline for {cluster_name}: snapshot #{baseline.id}")
    console.print(f"Taken: {baseline.taken_at.isoformat()}")
    _print_score(baseline.score.overall)
    console.print(f"Findings: {len(baseline.findings)}")


@app.command()
def drift(
    context: str = typer.Option(None, "--context", help="kubeconfig context to scan"),
    namespace: str = typer.Option(None, "--namespace", help="limit the scan to a single namespace"),
    with_vulnerabilities: bool = typer.Option(
        False, "--with-vulnerabilities", help="also scan workload images for known CVEs using Trivy"
    ),
    since: str = typer.Option(
        None,
        "--since",
        help="compare against a snapshot from this far back (7d, 24h, 30m) instead of the baseline",
    ),
    output: str = typer.Option("terminal", "--output", "-o", help="terminal or json"),
) -> None:
    """Scan a cluster now and compare it against its baseline or a past snapshot."""
    pipeline_result = _run_pipeline(context, namespace, with_vulnerabilities)
    current_snapshot = _to_snapshot(pipeline_result)
    cluster_name = current_snapshot.cluster

    with _storage() as connection:
        if since:
            try:
                since_delta = parse_duration(since)
            except DurationParseError as error:
                console.print(f"[red]Error:[/red] {error}")
                raise typer.Exit(code=1) from error
            reference = snapshot_store.get_nearest_before(
                connection, cluster_name, current_snapshot.taken_at - since_delta
            )
            if reference is None:
                console.print(f"No snapshot found for {cluster_name} from {since} or earlier.")
                raise typer.Exit(code=1)
        else:
            reference = snapshot_store.get_baseline(connection, cluster_name)
            if reference is None:
                console.print(
                    f"No baseline set for {cluster_name}. "
                    "Run 'kubesentinel baseline create' first, or pass --since."
                )
                raise typer.Exit(code=1)

    drift_report = compare_snapshots(reference, current_snapshot)
    if output == "json":
        print(drift_report.model_dump_json(indent=2))
    else:
        terminal.render_drift(drift_report, console)


@app.command("attack-paths")
def attack_paths(
    context: str = typer.Option(None, "--context", help="kubeconfig context to scan"),
    namespace: str = typer.Option(None, "--namespace", help="limit the scan to a single namespace"),
    with_vulnerabilities: bool = typer.Option(
        False, "--with-vulnerabilities", help="also scan workload images for known CVEs using Trivy"
    ),
    output: str = typer.Option("terminal", "--output", "-o", help="terminal or json"),
) -> None:
    """Find paths from the internet to secrets, cluster-admin, or a node."""
    pipeline_result = _run_pipeline(context, namespace, with_vulnerabilities)
    graph = build_graph(pipeline_result.resources)
    paths = find_attack_paths(graph, pipeline_result.scan_result.findings)

    if output == "json":
        print(_ATTACK_PATHS_ADAPTER.dump_json(paths, indent=2).decode())
    else:
        terminal.render_attack_paths(paths, console)


@app.command()
def audit(
    context: str = typer.Option(None, "--context", help="kubeconfig context to scan"),
    namespace: str = typer.Option(None, "--namespace", help="limit the scan to a single namespace"),
    with_vulnerabilities: bool = typer.Option(
        False, "--with-vulnerabilities", help="also scan workload images for known CVEs using Trivy"
    ),
    output: str = typer.Option("terminal", "--output", "-o", help="terminal or json"),
) -> None:
    """Run a numbered security audit and compare it against the previous one."""
    pipeline_result = _run_pipeline(context, namespace, with_vulnerabilities)
    current_snapshot = _to_snapshot(pipeline_result).model_copy(update={"is_audit": True})
    cluster_name = current_snapshot.cluster

    with _storage() as connection:
        try:
            snapshot_id = snapshot_store.save(connection, current_snapshot)
        except StorageError as error:
            console.print(f"[red]Error saving audit snapshot:[/red] {error}")
            raise typer.Exit(code=1) from error

        current_snapshot = current_snapshot.model_copy(update={"id": snapshot_id})
        history = list(reversed(snapshot_store.list_snapshots(connection, cluster_name)))
        previous_audits = [
            snap for snap in snapshot_store.list_audits(connection, cluster_name)
            if snap.id != snapshot_id
        ]
        reference = (
            previous_audits[0]
            if previous_audits
            else snapshot_store.get_baseline(connection, cluster_name)
        )

    audit_report = build_audit_report(
        len(previous_audits) + 1, current_snapshot, reference, history
    )

    if output == "json":
        print(audit_report.model_dump_json(indent=2))
    else:
        terminal.render_audit(audit_report, console)


@app.command()
def compare(
    baseline_id: int = typer.Argument(..., help="snapshot id, the earlier side of the comparison"),
    current_id: int = typer.Argument(..., help="snapshot id, the later side of the comparison"),
    output: str = typer.Option("terminal", "--output", "-o", help="terminal or json"),
) -> None:
    """Compare two previously saved snapshots by id."""
    with _storage() as connection:
        reference = snapshot_store.get(connection, baseline_id)
        current_snapshot = snapshot_store.get(connection, current_id)

    if reference is None:
        console.print(f"[red]Error:[/red] no snapshot with id {baseline_id}")
        raise typer.Exit(code=1)
    if current_snapshot is None:
        console.print(f"[red]Error:[/red] no snapshot with id {current_id}")
        raise typer.Exit(code=1)

    drift_report = compare_snapshots(reference, current_snapshot)
    if output == "json":
        print(drift_report.model_dump_json(indent=2))
    else:
        terminal.render_drift(drift_report, console)


@app.command()
def gitops(
    context: str = typer.Option(None, "--context", help="kubeconfig context to scan"),
    namespace: str = typer.Option(None, "--namespace", help="limit the scan to a single namespace"),
    output: str = typer.Option("terminal", "--output", "-o", help="terminal or json"),
) -> None:
    """Show which workloads are managed by ArgoCD or Flux, and which are not."""
    pipeline_result = _run_pipeline(context, namespace, with_vulnerabilities=False)
    statuses = gitops_module.detect_all(pipeline_result.resources)

    if output == "json":
        print(_GITOPS_ADAPTER.dump_json(statuses, indent=2).decode())
    else:
        terminal.render_gitops(statuses, console)


def _build_ticketer(to: str, repo: str | None) -> Ticketer:
    if to == "github":
        return GitHubTicketer(repo=repo)
    return _TICKETERS[to]()


@app.command()
def ticket(
    context: str = typer.Option(None, "--context", help="kubeconfig context to scan"),
    namespace: str = typer.Option(None, "--namespace", help="limit the scan to a single namespace"),
    with_vulnerabilities: bool = typer.Option(
        False, "--with-vulnerabilities", help="also scan workload images for known CVEs using Trivy"
    ),
    to: str = typer.Option(..., "--to", help="github, jira, servicenow, or azuredevops"),
    min_risk: str = typer.Option(
        "high",
        "--min-risk",
        help="file findings at or above this risk: low, medium, high, critical",
    ),
    repo: str = typer.Option(None, "--repo", help="GitHub repo as owner/name, github only"),
    limit: int = typer.Option(20, "--limit", help="maximum tickets to file in one run"),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="show what would be filed without filing anything"
    ),
) -> None:
    """File open findings as tickets in an external tracker.

    Skips a finding already filed against the same tracker on a previous
    run, tracked locally by the finding's own deterministic id, so running
    this on a schedule does not refile the same thing every time.
    """
    if to not in _TICKETERS:
        console.print(
            f"[red]Error:[/red] unknown ticketer {to!r}, "
            "use github, jira, servicenow, or azuredevops"
        )
        raise typer.Exit(code=1)
    if min_risk not in _RISK_ORDER:
        console.print(
            f"[red]Error:[/red] unknown risk level {min_risk!r}, use low, medium, high, or critical"
        )
        raise typer.Exit(code=1)

    ticketer_instance = _build_ticketer(to, repo)
    if not ticketer_instance.is_configured():
        console.print(
            f"[red]Error:[/red] {to} is not configured, see the README for what it needs."
        )
        raise typer.Exit(code=1)

    pipeline_result = _run_pipeline(context, namespace, with_vulnerabilities)
    threshold = _RISK_ORDER.index(min_risk)
    candidates = [
        finding
        for finding in pipeline_result.scan_result.findings
        if _RISK_ORDER.index(finding.risk) >= threshold
    ]
    candidates.sort(key=lambda finding: _RISK_ORDER.index(finding.risk), reverse=True)

    filed = skipped = failed = 0
    storage_error: StorageError | None = None
    with _storage() as connection:
        for finding in candidates:
            if filed >= limit:
                break

            try:
                already = ticket_store.already_filed(connection, finding.id, ticketer_instance.name)
            except StorageError as error:
                storage_error = error
                break
            if already:
                skipped += 1
                continue

            gitops_source = gitops_module.find_source(
                finding.resource_kind,
                finding.resource,
                finding.namespace,
                pipeline_result.resources,
            )

            if dry_run:
                console.print(f"[dim]Would file:[/dim] [{finding.risk.upper()}] {finding.title}")
                filed += 1
                continue

            try:
                ticket_result = ticketer_instance.file_finding(finding, gitops_source)
            except TicketError as error:
                console.print(f"[red]Failed to file[/red] {finding.title}: {error}")
                failed += 1
                continue

            filed += 1
            try:
                ticket_store.record(
                    connection,
                    finding.id,
                    ticketer_instance.name,
                    ticket_result.key,
                    ticket_result.url,
                    datetime.now(UTC),
                )
            except StorageError as error:
                # The ticket was already created on the tracker's side, that
                # cannot be undone here, so this stays a warning rather than
                # a failure, but a later run will not know about it and may
                # file a duplicate, the URL is printed so it is not lost.
                console.print(
                    f"[yellow]Filed {ticket_result.url or ticket_result.key} but could not "
                    f"record it locally, a later run may refile it: {error}[/yellow]"
                )
                storage_error = error
                break

            console.print(f"Filed {ticket_result.url or ticket_result.key}: {finding.title}")

    console.print()
    verb = "Would file" if dry_run else "Filed"
    console.print(f"{verb} {filed}, skipped {skipped} already filed, {failed} failed.")
    if storage_error is not None:
        console.print(f"[red]Stopped early due to a storage error:[/red] {storage_error}")
    if failed or storage_error is not None:
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
