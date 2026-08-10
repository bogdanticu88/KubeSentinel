from kubesentinel.engines.misconfiguration.evaluator import evaluate
from kubesentinel.engines.misconfiguration.loader import load_rules
from tests.fixtures import builders

RULES = load_rules()


def _fires(rule_id: str, resource) -> bool:
    rule = next(r for r in RULES if r.id == rule_id)
    findings = evaluate([resource], [rule], cluster_name="test")
    return len(findings) == 1


def test_wildcard_resources():
    bad = builders.role(rules=[{"resources": ["*"], "verbs": ["get"]}])
    good = builders.role(rules=[{"resources": ["pods"], "verbs": ["get"]}])
    assert _fires("KS-RBAC-001", bad)
    assert not _fires("KS-RBAC-001", good)
    assert _fires("KS-RBAC-001", builders.role(rules=[{"resources": ["*"]}], kind="ClusterRole"))


def test_wildcard_verbs():
    bad = builders.role(rules=[{"resources": ["pods"], "verbs": ["*"]}])
    good = builders.role(rules=[{"resources": ["pods"], "verbs": ["get", "list"]}])
    assert _fires("KS-RBAC-002", bad)
    assert not _fires("KS-RBAC-002", good)


def test_wildcard_apigroups():
    bad = builders.role(rules=[{"apiGroups": ["*"], "resources": ["pods"]}])
    good = builders.role(rules=[{"apiGroups": ["apps"], "resources": ["deployments"]}])
    assert _fires("KS-RBAC-003", bad)
    assert not _fires("KS-RBAC-003", good)


def test_escalation_verbs():
    bad = builders.role(rules=[{"resources": ["roles"], "verbs": ["escalate"]}])
    also_bad = builders.role(rules=[{"resources": ["clusterroles"], "verbs": ["bind", "get"]}])
    good = builders.role(rules=[{"resources": ["pods"], "verbs": ["get", "list", "watch"]}])
    assert _fires("KS-RBAC-004", bad)
    assert _fires("KS-RBAC-004", also_bad)
    assert not _fires("KS-RBAC-004", good)


def test_default_serviceaccount_bound():
    bad = builders.role_binding(subjects=[{"kind": "ServiceAccount", "name": "default"}])
    good = builders.role_binding(subjects=[{"kind": "ServiceAccount", "name": "payments-api"}])
    assert _fires("KS-RBAC-005", bad)
    assert not _fires("KS-RBAC-005", good)
    assert _fires(
        "KS-RBAC-005",
        builders.role_binding(subjects=[{"kind": "ServiceAccount", "name": "default"}], kind="ClusterRoleBinding"),
    )
