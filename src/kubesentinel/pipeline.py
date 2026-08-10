"""Runs the full scan pipeline: collect, evaluate, optionally check images
for known vulnerabilities, correlate risk, and score.

`scan` and `snapshot` are the same work, one prints the result and moves
on, the other also writes it to local storage, so this is the one place
that orchestration lives rather than duplicated between the two commands.
"""

from dataclasses import dataclass
from datetime import UTC, datetime

from kubesentinel.collector.client import build_client, current_context_name, verify_connectivity
from kubesentinel.collector.collector import collect
from kubesentinel.engines.misconfiguration.evaluator import evaluate
from kubesentinel.engines.misconfiguration.loader import load_rules
from kubesentinel.engines.risk.correlation import correlate
from kubesentinel.engines.risk.scoring import score
from kubesentinel.engines.vulnerability.adapter import TrivyAdapter
from kubesentinel.engines.vulnerability.scan import scan_vulnerabilities
from kubesentinel.models.resource import CollectedResource
from kubesentinel.models.scan import ClusterInfo, CollectionWarning, ScanResult


@dataclass
class PipelineResult:
    scan_result: ScanResult
    resources: list[CollectedResource]


def run_scan(
    context: str | None,
    namespace: str | None,
    with_vulnerabilities: bool,
) -> PipelineResult:
    """Run collection through scoring against a live cluster.

    Raises CollectorError or RuleLoadError on failure, callers decide how
    to present those, this function only does the work.
    """
    api_client = build_client(context)
    kubernetes_version = verify_connectivity(api_client)
    collection = collect(api_client, namespace=namespace)
    rules = load_rules()

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

    scan_result = ScanResult(
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
    return PipelineResult(scan_result=scan_result, resources=collection.resources)
