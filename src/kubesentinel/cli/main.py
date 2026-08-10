"""KubeSentinel command line interface."""

from datetime import UTC, datetime

import typer
from rich.console import Console

from kubesentinel.collector.client import build_client, current_context_name, verify_connectivity
from kubesentinel.collector.collector import collect
from kubesentinel.collector.errors import CollectorError
from kubesentinel.engines.misconfiguration.evaluator import evaluate
from kubesentinel.engines.misconfiguration.loader import RuleLoadError, load_rules
from kubesentinel.engines.risk.scoring import score
from kubesentinel.models.scan import ClusterInfo, ScanResult
from kubesentinel.reporting import terminal

app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()


@app.callback()
def main() -> None:
    """KubeSentinel: continuous Kubernetes security assurance."""


@app.command()
def scan(
    context: str = typer.Option(None, "--context", help="kubeconfig context to scan"),
    namespace: str = typer.Option(None, "--namespace", help="limit the scan to a single namespace"),
    output: str = typer.Option("terminal", "--output", "-o", help="terminal or json"),
) -> None:
    """Scan a cluster's current security posture and print a scored report."""
    try:
        api_client = build_client(context)
        kubernetes_version = verify_connectivity(api_client)
        collection = collect(api_client, namespace=namespace)
        rules = load_rules()
    except CollectorError as error:
        console.print(f"[red]Error:[/red] {error}")
        raise typer.Exit(code=1) from error
    except RuleLoadError as error:
        console.print(f"[red]Error loading rules:[/red] {error}")
        raise typer.Exit(code=1) from error

    cluster_name = current_context_name(context)
    findings = evaluate(collection.resources, rules, cluster_name)
    score_result = score(findings, rules)

    result = ScanResult(
        cluster=ClusterInfo(
            name=cluster_name,
            kubernetes_version=kubernetes_version,
            node_count=collection.node_count,
        ),
        scanned_at=datetime.now(UTC),
        counts=collection.counts,
        findings=findings,
        score=score_result,
        warnings=collection.warnings,
    )

    if output == "json":
        print(result.model_dump_json(indent=2))
    else:
        terminal.render(result, console)


if __name__ == "__main__":
    app()
