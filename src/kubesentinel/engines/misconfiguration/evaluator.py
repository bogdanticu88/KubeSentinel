"""Evaluates loaded rules against collected resources to produce findings."""

import hashlib
from datetime import UTC, datetime

from kubesentinel.engines.misconfiguration.paths import evaluate_condition, resolve
from kubesentinel.models.finding import Evidence, Finding
from kubesentinel.models.resource import CollectedResource
from kubesentinel.models.rule import Rule

# Kubernetes stamps every RBAC object it ships by default (admin, edit, view,
# the various system:* aggregation roles) with this label. Those objects are
# not something a cluster operator configured, they exist on every cluster
# the same way, so flagging them is not actionable and just buries findings
# on RBAC an operator actually wrote. Confirmed against a real kind cluster,
# a fixture-only test suite would not have caught this.
_BOOTSTRAPPED_RBAC_LABEL_KEY = "kubernetes.io/bootstrapping"
_BOOTSTRAPPED_RBAC_LABEL_VALUE = "rbac-defaults"


def _is_kubernetes_bootstrapped(resource: CollectedResource) -> bool:
    return resource.labels.get(_BOOTSTRAPPED_RBAC_LABEL_KEY) == _BOOTSTRAPPED_RBAC_LABEL_VALUE


def evaluate(
    resources: list[CollectedResource],
    rules: list[Rule],
    cluster_name: str,
) -> list[Finding]:
    now = datetime.now(UTC)
    findings: list[Finding] = []

    for rule in rules:
        if rule.type == "resource_match":
            findings.extend(_evaluate_resource_match(rule, resources, cluster_name, now))
        elif rule.type == "namespace_missing_resource":
            findings.extend(_evaluate_namespace_missing(rule, resources, cluster_name, now))
        else:
            raise ValueError(f"unknown rule type: {rule.type!r}")

    return findings


def _evaluate_resource_match(
    rule: Rule,
    resources: list[CollectedResource],
    cluster_name: str,
    now: datetime,
) -> list[Finding]:
    if not rule.selector or not rule.conditions:
        return []

    kinds = set(rule.selector.kinds)
    match_labels = rule.selector.match_labels
    findings = []
    for resource in resources:
        if resource.kind not in kinds:
            continue
        if _is_kubernetes_bootstrapped(resource):
            continue
        if match_labels and not match_labels.items() <= resource.labels.items():
            continue
        if all(evaluate_condition(resource.data, condition) for condition in rule.conditions):
            matched_fields = {
                condition.field: resolve(resource.data, condition.field)
                for condition in rule.conditions
            }
            findings.append(
                _finding(
                    rule,
                    cluster_name,
                    now,
                    namespace=resource.namespace,
                    resource_name=resource.name,
                    resource_kind=resource.kind,
                    matched_fields=matched_fields,
                )
            )
    return findings


def _evaluate_namespace_missing(
    rule: Rule,
    resources: list[CollectedResource],
    cluster_name: str,
    now: datetime,
) -> list[Finding]:
    if not rule.require_absent_kind:
        return []

    namespaces = sorted({r.name for r in resources if r.kind == "Namespace"})
    namespaces_with_kind = {r.namespace for r in resources if r.kind == rule.require_absent_kind}

    findings = []
    for namespace in namespaces:
        if namespace in rule.exclude_namespaces:
            continue
        if namespace in namespaces_with_kind:
            continue
        findings.append(
            _finding(
                rule,
                cluster_name,
                now,
                namespace=namespace,
                resource_name=namespace,
                resource_kind="Namespace",
                matched_fields={"missing_kind": rule.require_absent_kind},
            )
        )
    return findings


def _finding(
    rule: Rule,
    cluster_name: str,
    now: datetime,
    *,
    namespace: str | None,
    resource_name: str,
    resource_kind: str,
    matched_fields: dict,
) -> Finding:
    return Finding(
        id=_finding_id(rule.id, resource_kind, namespace, resource_name),
        rule_id=rule.id,
        category=rule.category,
        dimension=rule.dimension,
        severity=rule.severity,
        cluster=cluster_name,
        namespace=namespace,
        resource=resource_name,
        resource_kind=resource_kind,
        title=rule.name,
        description=rule.description,
        risk_rationale=rule.risk_rationale,
        remediation=rule.remediation,
        references=rule.references,
        evidence=Evidence(
            resource_kind=resource_kind,
            resource_name=resource_name,
            namespace=namespace,
            matched_fields=matched_fields,
        ),
        first_seen=now,
        last_seen=now,
    )


def _finding_id(rule_id: str, kind: str, namespace: str | None, name: str) -> str:
    # Deterministic rather than sequential: the same misconfiguration on the
    # same resource produces the same id on every run, which matters once
    # drift detection needs to recognize "this is still the same finding"
    # without a database to look it up in yet.
    digest = hashlib.sha256(f"{rule_id}|{kind}|{namespace}|{name}".encode()).hexdigest()
    return f"KS-{digest[:12]}"
