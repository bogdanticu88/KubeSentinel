"""Builds a numbered audit report: current findings, what changed since
the previous audit (or the baseline, if this is the first one), how
attack paths moved, and the security debt trend across every stored
snapshot for the cluster.
"""

from kubesentinel.engines.attackpath.graph import build_graph
from kubesentinel.engines.attackpath.paths import find_attack_paths
from kubesentinel.engines.audit.debt import compute_security_debt
from kubesentinel.engines.drift.diff import compare as compare_snapshots
from kubesentinel.models.audit import AuditReport
from kubesentinel.models.scan import Snapshot

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def build_audit_report(
    number: int,
    current: Snapshot,
    reference: Snapshot | None,
    history: list[Snapshot],
) -> AuditReport:
    """`history` is every stored snapshot for this cluster, oldest to
    newest, with `current` already the last entry, security debt needs the
    full history to know how long a finding has been open."""
    findings_by_severity = {
        severity: sum(1 for finding in current.findings if finding.risk == severity)
        for severity in _SEVERITY_ORDER
    }

    drift = compare_snapshots(reference, current) if reference is not None else None

    current_paths = find_attack_paths(build_graph(current.resources), current.findings)
    previous_paths = (
        find_attack_paths(build_graph(reference.resources), reference.findings)
        if reference is not None
        else []
    )

    return AuditReport(
        number=number,
        cluster=current.cluster,
        taken_at=current.taken_at,
        findings_by_severity=findings_by_severity,
        score=current.score.overall,
        drift=drift,
        new_attack_paths=len(current_paths),
        previous_attack_paths=len(previous_paths),
        security_debt=compute_security_debt(history),
    )
