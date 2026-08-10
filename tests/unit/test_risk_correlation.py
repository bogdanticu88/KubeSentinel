from datetime import UTC, datetime

from kubesentinel.engines.risk.correlation import correlate
from kubesentinel.models.finding import Evidence, Finding
from tests.fixtures import builders


def _finding(resource, severity: str = "critical") -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id=f"KS-test-{resource.name}",
        rule_id="KS-TEST-001",
        category="test",
        dimension="supply_chain",
        severity=severity,
        risk=severity,
        cluster="test",
        namespace=resource.namespace,
        resource=resource.name,
        resource_kind=resource.kind,
        title="test finding",
        description="test",
        risk_rationale="test",
        remediation="test",
        evidence=Evidence(resource_kind=resource.kind, resource_name=resource.name, namespace=resource.namespace),
        first_seen=now,
        last_seen=now,
    )


def _wildcard_rbac(namespace: str, service_account_name: str):
    role = builders.role(
        name="wildcard-role", namespace=namespace, rules=[{"resources": ["*"], "verbs": ["*"]}]
    )
    binding = builders.role_binding(
        namespace=namespace,
        subjects=[{"kind": "ServiceAccount", "name": service_account_name, "namespace": namespace}],
        role_ref_kind="Role",
        role_ref_name="wildcard-role",
    )
    return [role, binding]


def test_isolated_critical_finding_downgrades_to_high():
    # The spec's own "Finding A": critical CVE, internal workload, no
    # secret access, no privileged RBAC. Expected risk: HIGH.
    pod = builders.pod(name="internal-worker", service_account_name="internal-worker")
    finding = _finding(pod, severity="critical")

    result = correlate([finding], [pod])

    assert result[0].risk == "high"
    assert result[0].risk_reasons


def test_fully_exposed_medium_finding_escalates_to_critical():
    # The spec's own "Finding B": medium CVE, internet-facing workload,
    # cluster-wide RBAC, secret access, privilege escalation possible.
    # Expected risk: CRITICAL.
    pod = builders.pod(
        name="payments-api",
        namespace="payments",
        labels={"app": "payments-api"},
        service_account_name="payments-sa",
    )
    exposing_service = builders.service(
        name="payments-svc",
        namespace="payments",
        service_type="LoadBalancer",
        selector={"app": "payments-api"},
    )
    broad_role = builders.role(
        name="payments-role",
        namespace="payments",
        kind="ClusterRole",
        rules=[{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*", "escalate", "bind"]}],
    )
    binding = builders.role_binding(
        name="payments-binding",
        namespace="payments",
        subjects=[{"kind": "ServiceAccount", "name": "payments-sa", "namespace": "payments"}],
        role_ref_kind="ClusterRole",
        role_ref_name="payments-role",
    )
    finding = _finding(pod, severity="medium")

    result = correlate([finding], [pod, exposing_service, broad_role, binding])

    assert result[0].risk == "critical"
    assert "escalated" in result[0].risk_reasons[0]


def test_a_single_contributing_factor_does_not_move_risk_on_its_own():
    # Only full isolation (zero factors) or compounding factors (two or
    # more) change anything, one signal alone is not enough, otherwise a
    # merely-exposed-but-otherwise-unremarkable workload gets over-flagged.
    pod = builders.pod(name="web", labels={"app": "web"})
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})
    finding = _finding(pod, severity="medium")

    result = correlate([finding], [pod, service])

    assert result[0].risk == "medium"
    assert result[0].risk_reasons == []


def test_service_selector_must_match_namespace_too():
    pod = builders.pod(name="web", namespace="ns-a", labels={"app": "web"})
    # Same selector, but the exposing Service is in a different namespace,
    # Kubernetes Services never select pods across namespaces.
    service = builders.service(namespace="ns-b", service_type="LoadBalancer", selector={"app": "web"})
    finding = _finding(pod, severity="critical")

    result = correlate([finding], [pod, service])

    assert result[0].risk == "high"  # treated as not exposed, so this is the isolated case


def test_ingress_backend_exposes_a_clusterip_service():
    pod = builders.pod(name="web", labels={"app": "web"}, service_account_name="web-sa")
    internal_service = builders.service(name="web-svc", service_type="ClusterIP", selector={"app": "web"})
    ingress = builders.ingress(
        rules=[{"http": {"paths": [{"backend": {"service": {"name": "web-svc"}}}]}}]
    )
    role, binding = _wildcard_rbac("default", "web-sa")
    finding = _finding(pod, severity="medium")

    result = correlate([finding], [pod, internal_service, ingress, role, binding])

    # exposed via the Ingress backend, plus wildcard RBAC (excessive + secret
    # access, two factors from one rule) = three factors total, escalate one.
    assert result[0].risk == "high"


def test_deployment_exposure_uses_the_pod_template_labels_not_the_deployment_labels():
    deployment = builders.deployment(name="api", pod_labels={"app": "api"}, service_account_name="api-sa")
    service = builders.service(service_type="LoadBalancer", selector={"app": "api"})
    role, binding = _wildcard_rbac("default", "api-sa")
    finding = _finding(deployment, severity="medium")

    result = correlate([finding], [deployment, service, role, binding])

    assert result[0].risk == "high"


def test_service_account_default_is_used_when_none_is_set_explicitly():
    pod = builders.pod(name="quiet")  # no service_account_name given, defaults to "default"
    role, binding = _wildcard_rbac("default", "default")
    finding = _finding(pod, severity="high")

    result = correlate([finding], [pod, role, binding])

    assert result[0].risk == "critical"


def test_findings_on_non_workload_resources_are_left_untouched():
    role = builders.role(name="broad-role", rules=[{"resources": ["*"]}])
    finding = _finding(role, severity="high")

    result = correlate([finding], [role])

    assert result[0].risk == "high"
    assert result[0].risk_reasons == []


def test_a_rolebinding_can_reference_a_clusterrole_but_stays_namespace_scoped():
    # The Role/ClusterRole join has to follow roleRef.kind, not assume every
    # binding points at a namespaced Role, and a secrets-only grant (no
    # wildcard) still has to be recognized as secret access specifically.
    pod = builders.pod(name="app", namespace="team-a", labels={"app": "app"}, service_account_name="app-sa")
    service = builders.service(namespace="team-a", service_type="LoadBalancer", selector={"app": "app"})
    cluster_role = builders.role(
        name="cluster-wide-secrets",
        kind="ClusterRole",
        rules=[{"resources": ["secrets"], "verbs": ["get", "list"]}],
    )
    binding = builders.role_binding(
        namespace="team-a",
        subjects=[{"kind": "ServiceAccount", "name": "app-sa", "namespace": "team-a"}],
        role_ref_kind="ClusterRole",
        role_ref_name="cluster-wide-secrets",
    )
    finding = _finding(pod, severity="medium")

    result = correlate([finding], [pod, service, cluster_role, binding])

    assert result[0].risk == "high"  # exposed + secret access, no wildcard = two factors, escalate one
