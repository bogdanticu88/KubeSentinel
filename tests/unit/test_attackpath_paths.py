from datetime import UTC, datetime

from kubesentinel.engines.attackpath.graph import build_graph
from kubesentinel.engines.attackpath.paths import find_attack_paths
from kubesentinel.models.finding import Evidence, Finding
from tests.fixtures import builders


def _finding(resource: str, namespace: str, resource_kind: str, risk: str = "critical") -> Finding:
    now = datetime.now(UTC)
    return Finding(
        id=f"KS-test-{resource}",
        rule_id="KS-TEST-001",
        category="test",
        dimension="workloads",
        severity=risk,
        risk=risk,
        cluster="test",
        namespace=namespace,
        resource=resource,
        resource_kind=resource_kind,
        title="test finding",
        description="test",
        risk_rationale="test",
        remediation="test",
        evidence=Evidence(resource_kind=resource_kind, resource_name=resource, namespace=namespace),
        first_seen=now,
        last_seen=now,
    )


def _exposed_wildcard_cluster():
    pod = builders.pod(
        name="payments-api",
        namespace="payments",
        labels={"app": "payments-api"},
        service_account_name="payments-sa",
    )
    service = builders.service(
        namespace="payments", service_type="LoadBalancer", selector={"app": "payments-api"}
    )
    role = builders.role(
        name="broad", namespace="payments", kind="ClusterRole",
        rules=[{"resources": ["*"], "verbs": ["*"]}],
    )
    binding = builders.role_binding(
        namespace="payments",
        subjects=[{"kind": "ServiceAccount", "name": "payments-sa", "namespace": "payments"}],
        role_ref_kind="ClusterRole",
        role_ref_name="broad",
    )
    return [pod, service, role, binding], pod


def test_exposed_wildcard_workload_finds_reachable_paths_to_secrets_and_admin():
    resources, _ = _exposed_wildcard_cluster()
    graph = build_graph(resources)

    paths = find_attack_paths(graph)

    targets = {p.target_kind for p in paths}
    assert "Secrets" in targets
    assert "ClusterAdmin" in targets
    assert all(p.confidence == "reachable" for p in paths)


def test_isolated_workload_with_the_same_rbac_finds_no_paths():
    pod = builders.pod(name="internal", namespace="payments", service_account_name="payments-sa")
    role = builders.role(
        name="broad", namespace="payments", kind="ClusterRole",
        rules=[{"resources": ["*"], "verbs": ["*"]}],
    )
    binding = builders.role_binding(
        namespace="payments",
        subjects=[{"kind": "ServiceAccount", "name": "payments-sa", "namespace": "payments"}],
        role_ref_kind="ClusterRole",
        role_ref_name="broad",
    )
    # no Service at all, this workload is never reachable from the internet

    graph = build_graph([pod, role, binding])
    paths = find_attack_paths(graph)

    assert paths == []


def test_paths_are_sorted_by_risk_then_confidence():
    resources, _ = _exposed_wildcard_cluster()
    graph = build_graph(resources)

    paths = find_attack_paths(graph)

    risk_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    ranks = [risk_rank[p.risk] for p in paths]
    assert ranks == sorted(ranks, reverse=True)
    assert paths[0].id == "AP-1"


def test_an_open_critical_finding_on_the_entry_workload_escalates_confidence():
    pod = builders.pod(
        name="app", labels={"app": "web"}, service_account_name="app-sa",
        containers=[{"name": "app", "securityContext": {"privileged": True}}],
        volumes=[{"name": "root", "hostPath": {"path": "/"}}],
    )
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})

    without_findings = find_attack_paths(build_graph([pod, service]))
    node_path = next(p for p in without_findings if p.target_kind == "Node")
    assert node_path.confidence == "theoretical"

    finding = _finding(pod.name, pod.namespace, pod.kind, risk="critical")
    with_findings = find_attack_paths(build_graph([pod, service]), findings=[finding])
    node_path_escalated = next(p for p in with_findings if p.target_kind == "Node")
    assert node_path_escalated.confidence == "possible"


def test_a_low_severity_finding_does_not_escalate_confidence():
    # Only a critical or high finding makes a path meaningfully more
    # concrete, a low severity note on the entry workload should not move
    # the needle the way an actual exploitable issue would.
    pod = builders.pod(
        name="app", labels={"app": "web"},
        containers=[{"name": "app", "securityContext": {"privileged": True}}],
        volumes=[{"name": "root", "hostPath": {"path": "/"}}],
    )
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})

    finding = _finding(pod.name, pod.namespace, pod.kind, risk="low")
    paths = find_attack_paths(build_graph([pod, service]), findings=[finding])
    node_path = next(p for p in paths if p.target_kind == "Node")
    assert node_path.confidence == "theoretical"


def test_secrets_target_risk_is_high_and_cluster_admin_is_critical_when_reachable():
    resources, _ = _exposed_wildcard_cluster()
    paths = find_attack_paths(build_graph(resources))

    secrets_path = next(p for p in paths if p.target_kind == "Secrets")
    admin_path = next(p for p in paths if p.target_kind == "ClusterAdmin")

    assert secrets_path.risk == "high"
    assert admin_path.risk == "critical"


def test_theoretical_confidence_downgrades_target_risk():
    pod = builders.pod(
        name="app", labels={"app": "web"},
        containers=[{"name": "app", "securityContext": {"privileged": True}}],
        volumes=[{"name": "root", "hostPath": {"path": "/"}}],
    )
    service = builders.service(service_type="LoadBalancer", selector={"app": "web"})

    paths = find_attack_paths(build_graph([pod, service]))
    node_path = next(p for p in paths if p.target_kind == "Node")

    # Node's base risk is critical, theoretical confidence knocks it down one level
    assert node_path.risk == "high"
