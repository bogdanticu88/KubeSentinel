"""Adjusts a finding's risk based on the workload's exposure and RBAC context.

Severity is a rule's or a CVE's own intrinsic rating and never changes. Risk
is what this module produces: the same finding read differently depending
on whether its workload is reachable from outside the cluster and whether
its ServiceAccount can read Secrets, escalate privileges, or holds wildcard
permissions. This is a single-hop read of the same relationships the
attack-path graph walks multi-hop, see relationships.py.

Only findings scoped to a workload (Pod, Deployment, StatefulSet, DaemonSet,
Job, CronJob) get touched, a finding on a Role or a Service itself is not
tied to one running instance the way this join needs, so it keeps risk
equal to severity.
"""

from kubesentinel.collector.normalize import WORKLOAD_KINDS
from kubesentinel.models.finding import Finding
from kubesentinel.models.resource import CollectedResource
from kubesentinel.models.rule import Severity
from kubesentinel.relationships import (
    RoleRules,
    bound_roles,
    exposed_selectors,
    grants_escalation,
    grants_secret_read,
    has_wildcard,
    is_exposed,
    role_rules,
)

_RISK_RANK: dict[Severity, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_RISK: dict[int, Severity] = {rank: risk for risk, rank in _RISK_RANK.items()}


def correlate(findings: list[Finding], resources: list[CollectedResource]) -> list[Finding]:
    selectors = exposed_selectors(resources)
    rules = role_rules(resources)
    bindings = [r for r in resources if r.kind in ("RoleBinding", "ClusterRoleBinding")]
    workloads_by_key = {
        (r.namespace, r.kind, r.name): r for r in resources if r.kind in WORKLOAD_KINDS
    }

    correlated = []
    for finding in findings:
        key = (finding.namespace, finding.resource_kind, finding.resource)
        workload = workloads_by_key.get(key)
        if workload is None:
            correlated.append(finding)
            continue
        correlated.append(_correlate_finding(finding, workload, selectors, rules, bindings))
    return correlated


def _correlate_finding(
    finding: Finding,
    workload: CollectedResource,
    selectors: list[tuple[str | None, dict]],
    rules: RoleRules,
    bindings: list[CollectedResource],
) -> Finding:
    exposed = is_exposed(workload, selectors)
    excessive_rbac, secret_access, privilege_escalation = _service_account_context(
        workload, rules, bindings
    )

    context_score = sum([exposed, excessive_rbac, secret_access, privilege_escalation])
    severity_rank = _RISK_RANK[finding.severity]

    if context_score == 0:
        risk_rank = max(1, severity_rank - 1)
    elif context_score == 1:
        risk_rank = severity_rank
    elif context_score == 4:
        risk_rank = 4
    else:
        risk_rank = min(4, severity_rank + 1)

    risk = _RANK_TO_RISK[risk_rank]
    reasons = _explain(
        finding.severity, risk, exposed, excessive_rbac, secret_access, privilege_escalation
    )
    return finding.model_copy(update={"risk": risk, "risk_reasons": reasons})


def _service_account_context(
    workload: CollectedResource,
    rules: RoleRules,
    bindings: list[CollectedResource],
) -> tuple[bool, bool, bool]:
    sa_name = workload.data.get("serviceAccountName") or "default"
    matched_rules = [
        rule
        for key in bound_roles(workload.namespace, sa_name, bindings, rules)
        for rule in rules[key]
    ]

    excessive_rbac = any(has_wildcard(rule) for rule in matched_rules)
    secret_access = any(grants_secret_read(rule) for rule in matched_rules)
    privilege_escalation = any(grants_escalation(rule) for rule in matched_rules)
    return excessive_rbac, secret_access, privilege_escalation


def _explain(
    severity: Severity,
    risk: Severity,
    exposed: bool,
    excessive_rbac: bool,
    secret_access: bool,
    privilege_escalation: bool,
) -> list[str]:
    if risk == severity:
        return []

    exposure_note = (
        "its workload is reachable from outside the cluster"
        if exposed
        else "its workload is not exposed outside the cluster"
    )
    factors = [exposure_note]
    if excessive_rbac:
        factors.append("its ServiceAccount holds wildcard RBAC permissions")
    if secret_access:
        factors.append("its ServiceAccount can read Secrets")
    if privilege_escalation:
        factors.append("its ServiceAccount can escalate privileges")

    direction = "escalated" if _RISK_RANK[risk] > _RISK_RANK[severity] else "downgraded"
    summary = f"Risk {direction} from {severity.upper()} to {risk.upper()}: {', '.join(factors)}."
    return [summary]
