"""Finds attack paths through the graph and scores their risk.

A path's confidence is capped by its weakest edge: reachable requires every
edge to be a verified structural relationship, possible means at least one
edge needs the attacker to actively use a granted capability rather than
just follow something that already routes there, theoretical means the
mechanism itself is unconfirmed. If the entry workload already has an open
critical or high finding, confidence moves up one level, a workload with a
known way in makes an otherwise hypothetical path a lot more concrete than
one where nothing is actually known to be wrong with it yet.
"""

import networkx as nx

from kubesentinel.collector.normalize import WORKLOAD_KINDS
from kubesentinel.engines.attackpath.graph import INTERNET
from kubesentinel.models.attackpath import AttackPath, Confidence, PathNode
from kubesentinel.models.finding import Finding
from kubesentinel.models.rule import Severity

# nx.all_simple_paths counts cutoff in edges, not nodes. The deepest real
# chain is six edges (Internet, Ingress, Service, Workload, ServiceAccount,
# Role, target is seven nodes), seven edges leaves one hop of headroom. The
# graph is a strict DAG by construction, so this is a sanity bound, not
# something that would otherwise be needed to keep the search tractable.
_MAX_PATH_LENGTH = 7

_CONFIDENCE_RANK: dict[Confidence, int] = {
    "theoretical": 1,
    "possible": 2,
    "reachable": 3,
    "high_confidence": 4,
}
_RANK_TO_CONFIDENCE = {rank: confidence for confidence, rank in _CONFIDENCE_RANK.items()}

_TARGET_BASE_RISK: dict[str, Severity] = {
    "Secrets": "high",
    "ClusterAdmin": "critical",
    "Node": "critical",
}

_RISK_RANK: dict[Severity, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_RISK = {rank: risk for risk, rank in _RISK_RANK.items()}


def find_attack_paths(graph: nx.DiGraph, findings: list[Finding] | None = None) -> list[AttackPath]:
    workloads_with_findings = _workloads_with_open_high_severity_findings(findings or [])

    targets = [
        node
        for node, data in graph.nodes(data=True)
        if data.get("kind") in ("Secrets", "ClusterAdmin", "Node")
    ]

    attack_paths = []
    for target in targets:
        for raw_path in nx.all_simple_paths(graph, INTERNET, target, cutoff=_MAX_PATH_LENGTH):
            attack_paths.append(_build_attack_path(graph, raw_path, workloads_with_findings))

    attack_paths.sort(key=lambda p: (-_RISK_RANK[p.risk], -_CONFIDENCE_RANK[p.confidence]))
    for index, path in enumerate(attack_paths, start=1):
        path.id = f"AP-{index}"
    return attack_paths


def _build_attack_path(
    graph: nx.DiGraph,
    raw_path: list[str],
    workloads_with_findings: set[tuple[str | None, str, str]],
) -> AttackPath:
    edge_confidences = [
        graph.edges[source, dest]["confidence"]
        for source, dest in zip(raw_path, raw_path[1:], strict=False)
    ]
    weakest_rank = min(_CONFIDENCE_RANK[confidence] for confidence in edge_confidences)

    entry_workload = _entry_workload(graph, raw_path)
    if entry_workload is not None and entry_workload in workloads_with_findings:
        weakest_rank = min(weakest_rank + 1, _CONFIDENCE_RANK["high_confidence"])
    confidence = _RANK_TO_CONFIDENCE[weakest_rank]

    target_data = graph.nodes[raw_path[-1]]
    target_kind = target_data["kind"]
    base_risk_rank = _RISK_RANK[_TARGET_BASE_RISK.get(target_kind, "medium")]
    if confidence in ("theoretical", "possible"):
        risk_rank = max(1, base_risk_rank - 1)
    elif confidence == "high_confidence":
        risk_rank = min(4, base_risk_rank + 1)
    else:
        risk_rank = base_risk_rank
    risk = _RANK_TO_RISK[risk_rank]

    nodes = [
        PathNode(kind=graph.nodes[n]["kind"], identifier=graph.nodes[n]["identifier"])
        for n in raw_path
    ]
    chain = " -> ".join(f"{node.kind}({node.identifier})" for node in nodes)

    return AttackPath(
        target_kind=target_kind,
        target=target_data["identifier"],
        nodes=nodes,
        confidence=confidence,
        risk=risk,
        summary=f"{chain} [{confidence}, {risk} risk]",
    )


def _entry_workload(graph: nx.DiGraph, raw_path: list[str]) -> tuple[str | None, str, str] | None:
    for node_id in raw_path:
        data = graph.nodes[node_id]
        if data.get("kind") not in WORKLOAD_KINDS:
            continue
        namespace, name = data["identifier"].split("/", 1)
        return (namespace, data["kind"], name)
    return None


def _workloads_with_open_high_severity_findings(
    findings: list[Finding],
) -> set[tuple[str | None, str, str]]:
    return {
        (finding.namespace, finding.resource_kind, finding.resource)
        for finding in findings
        if finding.status == "open" and finding.risk in ("critical", "high")
    }
