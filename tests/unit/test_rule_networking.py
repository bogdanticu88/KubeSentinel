from kubesentinel.engines.misconfiguration.evaluator import evaluate
from kubesentinel.engines.misconfiguration.loader import load_rules
from tests.fixtures import builders

RULES = load_rules()


def _fires(rule_id: str, resource) -> bool:
    rule = next(r for r in RULES if r.id == rule_id)
    findings = evaluate([resource], [rule], cluster_name="test")
    return len(findings) == 1


def test_loadbalancer_exposure():
    assert _fires("KS-NET-002", builders.service(service_type="LoadBalancer"))
    assert not _fires("KS-NET-002", builders.service(service_type="ClusterIP"))


def test_nodeport_exposure():
    assert _fires("KS-NET-003", builders.service(service_type="NodePort"))
    assert not _fires("KS-NET-003", builders.service(service_type="ClusterIP"))


def test_ingress_without_tls():
    assert _fires("KS-NET-004", builders.ingress(tls=None))
    assert not _fires("KS-NET-004", builders.ingress(tls=[{"hosts": ["example.com"]}]))


def test_namespace_missing_networkpolicy():
    rule = next(r for r in RULES if r.id == "KS-NET-001")

    resources_without_policy = [builders.namespace("payments")]
    findings = evaluate(resources_without_policy, [rule], cluster_name="test")
    assert len(findings) == 1
    assert findings[0].namespace == "payments"

    resources_with_policy = [
        builders.namespace("payments"),
        builders.network_policy(namespace="payments"),
    ]
    assert evaluate(resources_with_policy, [rule], cluster_name="test") == []


def test_namespace_missing_networkpolicy_excludes_system_namespaces():
    rule = next(r for r in RULES if r.id == "KS-NET-001")
    resources = [builders.namespace("kube-system")]
    assert evaluate(resources, [rule], cluster_name="test") == []
