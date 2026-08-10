"""KubeSentinel command line interface."""

from datetime import UTC, datetime

import typer
from rich.console import Console

from kubesentinel.collector.client import build_client, current_context_name, verify_connectivity
from kubesentinel.collector.collector import collect
from kubesentinel.collector.errors import CollectorError
from kubesentinel.engines.misconfiguration.evaluator import evaluate
from kubesentinel.engines.misconfiguration.loader import RuleLoadError, load_rules
from kubesentinel.engines.risk.correlation import correlate
from kubesentinel.engines.risk.scoring import score
from kubesentinel.engines.vulnerability.adapter import TrivyAdapter
from kubesentinel.engines.vulnerability.scan import scan_vulnerabilities
from kubesentinel.models.scan import ClusterInfo, CollectionWarning, ScanResult
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
    with_vulnerabilities: bool = typer.Option(
        False,
        "--with-vulnerabilities",
        help="also scan workload images for known CVEs using Trivy, requires trivy on PATH",
    ),
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
    warnings = list(collection.warnings)
    covered_dimensions: set[str] = set()

    if with_vulnerabilities:
        adapter = TrivyAdapter()
        if adapter.is_available():
            vulnerability_findings, vulnerability_warnings = scan_vulnerabilities(
                collection.resources, adapter, cluster_name
            )
            findings.extend(vulnerability_findings)
            warnings.extend(vulnerability_warnings)
            covered_dimensions.add("supply_chain")
        else:
            warnings.append(
                CollectionWarning(
                    resource_kind="Vulnerability",
                    message="trivy is not installed or not on PATH, vulnerability scanning skipped",
                )
            )

    # Correlation always runs, it is local and deterministic, no reason to
    # gate it behind the same flag that gates talking to an external scanner.
    findings = correlate(findings, collection.resources)
    score_result = score(findings, rules, extra_covered_dimensions=covered_dimensions)

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
        warnings=warnings,
    )

    if output == "json":
        print(result.model_dump_json(indent=2))
    else:
        terminal.render(result, console)


if __name__ == "__main__":
    app()
