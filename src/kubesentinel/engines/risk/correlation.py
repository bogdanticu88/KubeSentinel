"""Adjusts a finding's risk based on the workload's exposure and RBAC context.

Severity is a rule's or a CVE's own intrinsic rating and never changes. Risk
is what this module produces: the same finding read differently depending
on whether its workload is reachable from outside the cluster and whether
its ServiceAccount can read Secrets, escalate privileges, or holds wildcard
permissions. This is a single-hop join (Service selector to workload
labels, ServiceAccount to a bound Role through a Binding), not the general
attack-path graph, that is a later phase.

Only findings scoped to a workload (Pod, Deployment, StatefulSet, DaemonSet,
Job, CronJob) get touched, a finding on a Role or a Service itself is not
tied to one running instance the way this join needs, so it keeps risk
equal to severity.
"""

from kubesentinel.collector.normalize import WORKLOAD_KINDS
from kubesentinel.models.finding import Finding
from kubesentinel.models.resource import CollectedResource
from kubesentinel.models.rule import Severity

_RISK_RANK: dict[Severity, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}
_RANK_TO_RISK: dict[int, Severity] = {rank: risk for risk, rank in _RISK_RANK.items()}

# (namespace, kind, name) identifies a Role or ClusterRole, namespace is
# None for a ClusterRole since it has none.
RoleKey = tuple[str | None, str, str]
RoleRules = dict[RoleKey, list[dict]]

_SECRET_READ_VERBS = {"get", "list", "watch", "*"}
_ESCALATION_VERBS = {"escalate", "bind", "impersonate"}


def correlate(findings: list[Finding], resources: list[CollectedResource]) -> list[Finding]:
    exposed_selectors = _exposed_selectors(resources)
    role_rules = _role_rules(resources)
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
        correlated.append(
            _correlate_finding(finding, workload, exposed_selectors, role_rules, bindings)
        )
    return correlated


def _correlate_finding(
    finding: Finding,
    workload: CollectedResource,
    exposed_selectors: list[tuple[str | None, dict]],
    role_rules: RoleRules,
    bindings: list[CollectedResource],
) -> Finding:
    exposed = _is_exposed(workload, exposed_selectors)
    excessive_rbac, secret_access, privilege_escalation = _service_account_context(
        workload, role_rules, bindings
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


def _exposed_selectors(resources: list[CollectedResource]) -> list[tuple[str | None, dict]]:
    ingress_backends: dict[str | None, set[str]] = {}
    for resource in resources:
        if resource.kind != "Ingress":
            continue
        names = ingress_backends.setdefault(resource.namespace, set())
        names.update(_ingress_backend_service_names(resource.data))

    selectors = []
    for resource in resources:
        if resource.kind != "Service":
            continue
        selector = resource.data.get("selector") or {}
        if not selector:
            continue
        exposed_type = resource.data.get("type") in ("LoadBalancer", "NodePort")
        exposed_via_ingress = resource.name in ingress_backends.get(resource.namespace, set())
        if exposed_type or exposed_via_ingress:
            selectors.append((resource.namespace, selector))
    return selectors


def _ingress_backend_service_names(ingress_data: dict) -> set[str]:
    names: set[str] = set()
    default_backend = (ingress_data.get("defaultBackend") or {}).get("service") or {}
    if default_backend.get("name"):
        names.add(default_backend["name"])
    for rule in ingress_data.get("rules") or []:
        for path in (rule.get("http") or {}).get("paths") or []:
            backend_service = (path.get("backend") or {}).get("service") or {}
            if backend_service.get("name"):
                names.add(backend_service["name"])
    return names


def _is_exposed(
    workload: CollectedResource, exposed_selectors: list[tuple[str | None, dict]]
) -> bool:
    labels = _pod_template_labels(workload)
    for namespace, selector in exposed_selectors:
        if namespace == workload.namespace and selector.items() <= labels.items():
            return True
    return False


def _pod_template_labels(workload: CollectedResource) -> dict[str, str]:
    # A Service selector matches a pod's own labels, not its owning
    # Deployment's labels, those are frequently different. A bare Pod's own
    # metadata.labels already are those labels, everything else nests its
    # pod template somewhere under spec, one level deeper for CronJob.
    if workload.kind == "Pod":
        return workload.labels
    spec = workload.raw.get("spec") or {}
    if workload.kind == "CronJob":
        spec = ((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}
    else:
        spec = spec.get("template") or {}
    return (spec.get("metadata") or {}).get("labels") or {}


def _role_rules(resources: list[CollectedResource]) -> RoleRules:
    rules: RoleRules = {}
    for resource in resources:
        if resource.kind not in ("Role", "ClusterRole"):
            continue
        namespace = resource.namespace if resource.kind == "Role" else None
        rules[(namespace, resource.kind, resource.name)] = resource.data.get("rules") or []
    return rules


def _service_account_context(
    workload: CollectedResource,
    role_rules: RoleRules,
    bindings: list[CollectedResource],
) -> tuple[bool, bool, bool]:
    sa_name = workload.data.get("serviceAccountName") or "default"
    sa_namespace = workload.namespace

    matched_rules: list[dict] = []
    for binding in bindings:
        if not _binding_targets_service_account(binding, sa_namespace, sa_name):
            continue
        role_ref = binding.data.get("roleRef") or {}
        role_kind, role_name = role_ref.get("kind"), role_ref.get("name")
        if not role_kind or not role_name:
            continue
        role_namespace = binding.namespace if role_kind == "Role" else None
        matched_rules.extend(role_rules.get((role_namespace, role_kind, role_name), []))

    excessive_rbac = any(_has_wildcard(rule) for rule in matched_rules)
    secret_access = any(_grants_secret_read(rule) for rule in matched_rules)
    privilege_escalation = any(_grants_escalation(rule) for rule in matched_rules)
    return excessive_rbac, secret_access, privilege_escalation


def _binding_targets_service_account(
    binding: CollectedResource, sa_namespace: str | None, sa_name: str
) -> bool:
    for subject in binding.data.get("subjects") or []:
        if subject.get("kind") != "ServiceAccount" or subject.get("name") != sa_name:
            continue
        subject_namespace = subject.get("namespace") or binding.namespace
        if subject_namespace == sa_namespace:
            return True
    return False


def _has_wildcard(rule: dict) -> bool:
    return "*" in (rule.get("resources") or []) or "*" in (rule.get("verbs") or [])


def _grants_secret_read(rule: dict) -> bool:
    resources = rule.get("resources") or []
    verbs = set(rule.get("verbs") or [])
    return ("secrets" in resources or "*" in resources) and bool(verbs & _SECRET_READ_VERBS)


def _grants_escalation(rule: dict) -> bool:
    return bool(set(rule.get("verbs") or []) & _ESCALATION_VERBS)


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
