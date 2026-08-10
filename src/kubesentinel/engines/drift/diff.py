"""Diffs two snapshots: new findings, resolved findings, score movement,
and structural changes to the resources themselves.

Resource diffing works against CollectedResource.data, the already
normalized security-relevant view every rule reads, not the full raw API
object. A replica count or an image digest bumped by a mutating webhook
never lands in data, so every field difference found here is already
something a rule could plausibly care about, there is no separate
significance table needed to filter noise back out, only a table for how
much a given field matters when it does change.
"""

from kubesentinel.models.drift import DriftReport, FieldChange, ResourceChange
from kubesentinel.models.finding import Finding
from kubesentinel.models.resource import CollectedResource
from kubesentinel.models.rule import Severity
from kubesentinel.models.scan import Snapshot

# Not every changed field is equally worth an operator's attention. A
# dropped ServiceAccount or a container going privileged matters far more
# than an extra label. Anything not listed here defaults to low, visible in
# the report but not raising an alarm.
_FIELD_SEVERITY: dict[str, Severity] = {
    "serviceAccountName": "high",
    "hostNetwork": "critical",
    "hostPID": "critical",
    "hostIPC": "critical",
    "automountServiceAccountToken": "medium",
    "securityContext": "high",
    "containers": "high",
    "volumes": "medium",
    "type": "high",  # a Service moving between ClusterIP, NodePort, LoadBalancer
    "selector": "medium",
    "rules": "high",  # Role or ClusterRole permissions
    "subjects": "high",  # who a RoleBinding or ClusterRoleBinding applies to
    "roleRef": "high",
}
_DEFAULT_FIELD_SEVERITY: Severity = "low"


def compare(baseline: Snapshot, current: Snapshot) -> DriftReport:
    new_findings, resolved_findings = diff_findings(baseline.findings, current.findings)
    return DriftReport(
        baseline_cluster=baseline.cluster,
        baseline_taken_at=baseline.taken_at,
        current_taken_at=current.taken_at,
        score_before=baseline.score.overall,
        score_after=current.score.overall,
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        resource_changes=diff_resources(baseline.resources, current.resources),
    )


def diff_findings(
    baseline: list[Finding], current: list[Finding]
) -> tuple[list[Finding], list[Finding]]:
    baseline_ids = {finding.id for finding in baseline}
    current_ids = {finding.id for finding in current}
    new_findings = [finding for finding in current if finding.id not in baseline_ids]
    resolved_findings = [finding for finding in baseline if finding.id not in current_ids]
    return new_findings, resolved_findings


def diff_resources(
    baseline: list[CollectedResource], current: list[CollectedResource]
) -> list[ResourceChange]:
    baseline_by_key = {(r.kind, r.namespace, r.name): r for r in baseline}
    current_by_key = {(r.kind, r.namespace, r.name): r for r in current}

    changes = []
    for kind, namespace, name in current_by_key.keys() - baseline_by_key.keys():
        changes.append(
            ResourceChange(kind=kind, namespace=namespace, name=name, change_type="added")
        )

    for kind, namespace, name in baseline_by_key.keys() - current_by_key.keys():
        changes.append(
            ResourceChange(kind=kind, namespace=namespace, name=name, change_type="removed")
        )

    for key in baseline_by_key.keys() & current_by_key.keys():
        field_changes = _diff_fields(baseline_by_key[key].data, current_by_key[key].data)
        if not field_changes:
            continue
        kind, namespace, name = key
        changes.append(
            ResourceChange(
                kind=kind,
                namespace=namespace,
                name=name,
                change_type="changed",
                field_changes=field_changes,
            )
        )

    changes.sort(key=lambda change: (change.kind, change.namespace or "", change.name))
    return changes


def _diff_fields(before: dict, after: dict) -> list[FieldChange]:
    field_changes = []
    for field in sorted(before.keys() | after.keys()):
        before_value = before.get(field)
        after_value = after.get(field)
        if before_value == after_value:
            continue
        field_changes.append(
            FieldChange(
                field=field,
                before=before_value,
                after=after_value,
                severity=_FIELD_SEVERITY.get(field, _DEFAULT_FIELD_SEVERITY),
            )
        )
    return field_changes
