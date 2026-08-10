"""KubeSentinel command line interface."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager

import typer
from rich.console import Console

from kubesentinel.cli.duration import DurationParseError, parse_duration
from kubesentinel.collector.client import current_context_name
from kubesentinel.collector.errors import CollectorError
from kubesentinel.engines.drift.diff import compare as compare_snapshots
from kubesentinel.engines.misconfiguration.loader import RuleLoadError
from kubesentinel.models.scan import Snapshot
from kubesentinel.pipeline import PipelineResult, run_scan
from kubesentinel.reporting import terminal
from kubesentinel.storage import db
from kubesentinel.storage import snapshots as snapshot_store
from kubesentinel.storage.db import StorageError

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

    report = compare_snapshots(reference, current_snapshot)
    if output == "json":
        print(report.model_dump_json(indent=2))
    else:
        terminal.render_drift(report, console)


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

    report = compare_snapshots(reference, current_snapshot)
    if output == "json":
        print(report.model_dump_json(indent=2))
    else:
        terminal.render_drift(report, console)


if __name__ == "__main__":
    app()
